//! In-flight uring operation state: the slab entry and single-shot op
//! futures.
//!
//! The `user_data` of every async SQE is the op's key in a thread-local
//! slab, so CQE dispatch is one slab lookup — no bit-encoded metadata.
//! One slab serves both thread-local rings (the per-queue ring and the
//! control ring): keys are unique per thread, and each [`Op`] remembers
//! which ring it was submitted on so cancellation reaches the right ring.
//!
//! # Keyspace contract
//!
//! Every async *and* sync submission owns a slab entry, so the ring's
//! `user_data` space has a single owner. Async entries hold a waker and
//! resolve a future; sync entries instead carry the handler-facing word
//! (the legacy tag-encoded `user_data`, see
//! `UblkIOCtx::build_user_data`) that the queue's sync event loop
//! delivers to its IO closure. Either reaper safely classifies any CQE
//! through its entry — a queue still should not mix the two dispatch
//! models, but misrouting degrades to a missed dispatch, never to
//! corrupted accounting. `user_data` values at or above
//! [`RESERVED_USER_DATA_MIN`] are sentinels that carry no op state; the
//! reapers pass them through to their callers.
//!
//! # Cancellation contract
//!
//! Dropping an [`Op`] before completion orphans the slab entry (its
//! resources stay alive until the terminal CQE) and issues a best-effort
//! ASYNC_CANCEL, so owned-buffer ops are safe to drop at any time.
//! Raw-pointer ops require the caller to keep the memory valid until the
//! op completes or the queue is torn down — see the per-function safety
//! docs in [`crate::ops`].

use crate::UblkError;
use io_uring::{cqueue, opcode, squeue, IoUring};
use slab::Slab;
use std::cell::RefCell;
use std::task::{Context, Poll, Waker};

/// Bottom of the reserved `user_data` range: values at or above this are
/// never slab keys. [`ublk_reap_and_wake`] passes their CQEs through to
/// `per_cqe` without touching the slab, so modules owning a sentinel
/// (e.g. `runtime::CTRL_POLL_DATA`) must pick it from this range.
pub(crate) const RESERVED_USER_DATA_MIN: u64 = u64::MAX - 15;

/// `user_data` sentinel for SQEs whose CQE carries no op state
/// (e.g. ASYNC_CANCEL issued on orphaning).
pub(crate) const IGNORE_USER_DATA: u64 = u64::MAX - 1;

/// Who owns the op behind one CQE's `user_data`.
pub(crate) enum CqeOwner {
    /// A slab key: the op layer owns this completion.
    Op(usize),
    /// An SQE pushed straight onto the ring with a target-bit
    /// `user_data` — the batch transport's multishot fetches cannot ride
    /// a single-shot slab entry. The target owns the completion and the
    /// word is delivered to it untouched.
    Target,
    /// A reserved sentinel; carries no op state.
    Sentinel,
}

/// Classify one CQE's `user_data`. A slab key is the only value that is
/// below [`RESERVED_USER_DATA_MIN`], clear of the target bit, and
/// representable as a `usize`; everything else belongs to the target or
/// to nobody and must never index the slab.
///
/// Both reapers classify here so they cannot drift apart: the sync loop
/// ([`crate::io::UblkQueue::flush_and_wake_io_tasks`]) and the reactor
/// ([`ublk_reap_and_wake`]) share one keyspace.
#[inline]
pub(crate) fn classify_user_data(user_data: u64) -> CqeOwner {
    if user_data >= RESERVED_USER_DATA_MIN {
        return CqeOwner::Sentinel;
    }
    if user_data & (crate::UblkUringData::Target as u64) != 0 {
        return CqeOwner::Target;
    }
    match usize::try_from(user_data) {
        Ok(key) => CqeOwner::Op(key),
        // Unreachable on 64-bit, and on 32-bit a word this large is not
        // a key the slab ever handed out -- never truncate it into one.
        Err(_) => CqeOwner::Sentinel,
    }
}

/// Resources owned by the slab entry while the kernel may still reference
/// them. They are released (or handed back to the caller) only once the
/// terminal CQE has been reaped.
pub(crate) enum Resources {
    /// Op references no caller memory (ublk commands, fsync, accept, ...)
    /// or caller-guaranteed memory (raw ops).
    None,
    /// One owned data buffer (read/write/recv/send).
    Buffer(Box<[u8]>),
    /// Timespec referenced by a TIMEOUT SQE.
    Timespec(#[allow(dead_code)] Box<io_uring::types::Timespec>),
    /// Op references no caller memory, but a successful CQE result is a
    /// fresh file descriptor the consumer owns (accept). If nobody
    /// consumes the completion, the reaper must close it.
    ResultFd,
}

impl Resources {
    pub(crate) fn into_buffer(self) -> Box<[u8]> {
        match self {
            Resources::Buffer(b) => b,
            _ => unreachable!("op resources are not a buffer"),
        }
    }
}

/// Per-op slab entry. Owns everything the kernel may still look at.
pub(crate) struct OpEntry {
    result: Option<i32>,
    /// Results beyond `result` for multi-CQE ops (`IORING_CQE_F_MORE`
    /// chains); an empty `Vec` never allocates, so single-shot ops pay
    /// nothing.
    extra_results: Vec<i32>,
    /// The terminal CQE (no `IORING_CQE_F_MORE`) has been reaped; no
    /// more completions are coming for this entry.
    terminated: bool,
    waker: Option<Waker>,
    /// The owning future was dropped; the reaper frees the entry on the
    /// terminal CQE.
    orphaned: bool,
    /// This op is a ublk io command (FETCH_REQ/COMMIT_AND_FETCH_REQ/...)
    /// whose completion the queue-state accounting must observe.
    is_io_cmd: bool,
    /// `Some` marks a sync-mode entry: no future is attached, and the
    /// stored word (legacy tag-encoded `user_data`) is delivered to the
    /// sync event loop's handler in place of the on-ring slab key.
    sync_data: Option<u64>,
    resources: Resources,
}

impl OpEntry {
    /// Release a completion nobody will consume. A discarded successful
    /// accept result is a live connection fd: dropping the value would
    /// leak it permanently (fd-table exhaustion under `select!`-style
    /// accept cancellation), so close it here.
    fn discard_result(&self, result: i32) {
        if matches!(self.resources, Resources::ResultFd) && result >= 0 {
            // SAFETY: the fd arrived in this op's own CQE and no
            // consumer exists; this close is its only owner's.
            unsafe { libc::close(result) };
        }
    }

    #[inline]
    fn push_result(&mut self, result: i32) {
        if self.result.is_none() && self.extra_results.is_empty() {
            self.result = Some(result);
        } else {
            self.extra_results.push(result);
        }
    }

    #[inline]
    fn pop_result(&mut self) -> Option<i32> {
        let result = self.result.take()?;
        if !self.extra_results.is_empty() {
            self.result = Some(self.extra_results.remove(0));
        }
        Some(result)
    }
}

/// The op slab, wrapped so thread exit cannot free memory the kernel
/// may still be using.
struct OpSlab(Slab<OpEntry>);

impl std::ops::Deref for OpSlab {
    type Target = Slab<OpEntry>;
    fn deref(&self) -> &Slab<OpEntry> {
        &self.0
    }
}

impl std::ops::DerefMut for OpSlab {
    fn deref_mut(&mut self) -> &mut Slab<OpEntry> {
        &mut self.0
    }
}

impl Drop for OpSlab {
    fn drop(&mut self) {
        // Thread exit with ops still in flight: TLS destructor order
        // between this slab and the ring cells is unspecified, and even
        // closing the ring fd first tears the ring down asynchronously
        // (io_ring_exit_work) — the kernel can still complete a request
        // into an op-owned buffer after this destructor runs. Freeing
        // the entries here would be a use-after-free reachable from
        // safe code (drop a pending recv's future, return from
        // block_on, let the thread exit). Leak them instead: bounded by
        // what was genuinely in flight, and sound.
        if !self.0.is_empty() {
            log::warn!(
                "thread exiting with {} ops in flight: leaking their buffers",
                self.0.len()
            );
            std::mem::forget(std::mem::take(&mut self.0));
        }
    }
}

std::thread_local! {
    static OP_SLAB: RefCell<OpSlab> = const { RefCell::new(OpSlab(Slab::new())) };
}

/// Whether any op is still in flight on this thread (park-loop guard).
#[inline]
pub(crate) fn has_pending_ops() -> bool {
    OP_SLAB.with(|slab| !slab.borrow().is_empty())
}

/// Which thread-local ring an op was submitted on.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum OpRing {
    Queue,
    Ctrl,
}

/// Push `sqe` to `r`, flushing once if the SQ ring is full.
#[inline]
fn push_sqe<S: squeue::EntryMarker>(r: &mut IoUring<S>, sqe: &S) -> Result<(), UblkError> {
    // SAFETY: every pointer carried by the SQE refers to memory owned
    // by the corresponding slab entry (or caller-guaranteed memory for
    // raw ops), which outlives the op by construction.
    if unsafe { r.submission().push(sqe) }.is_ok() {
        return Ok(());
    }
    r.submit()?;
    // SAFETY: as above.
    unsafe { r.submission().push(sqe) }.map_err(|_| UblkError::OtherError(-libc::EBUSY))
}

#[inline]
fn push_queue_sqe(sqe: &squeue::Entry) -> Result<(), UblkError> {
    crate::io::with_queue_ring_mut_internal!(|r: &mut IoUring<squeue::Entry>| push_sqe(r, sqe))
}

fn push_ctrl_sqe(sqe: &squeue::Entry128) -> Result<(), UblkError> {
    crate::ctrl::with_ctrl_ring_mut_internal!(|r: &mut IoUring<squeue::Entry128>| push_sqe(r, sqe))
}

#[inline]
fn insert_entry(resources: Resources, is_io_cmd: bool, sync_data: Option<u64>) -> usize {
    OP_SLAB.with(|slab| {
        slab.borrow_mut().insert(OpEntry {
            result: None,
            extra_results: Vec::new(),
            terminated: false,
            waker: None,
            orphaned: false,
            is_io_cmd,
            sync_data,
            resources,
        })
    })
}

/// Submit a sync-mode SQE on the queue ring: the slab entry carries
/// `sync_data` (the handler-facing word) instead of a future, and is
/// reclaimed by [`take_sync_entry`] when the queue's sync event loop
/// drains the CQE. Any memory the SQE references must stay valid until
/// then — sync targets use queue-slot buffers, which satisfy this by
/// construction.
pub(crate) fn submit_sync(
    build: impl FnOnce(u64) -> squeue::Entry,
    sync_data: u64,
    is_io_cmd: bool,
) -> Result<(), UblkError> {
    let key = insert_entry(Resources::None, is_io_cmd, Some(sync_data));
    if let Err(e) = push_queue_sqe(&build(key as u64)) {
        OP_SLAB.with(|slab| slab.borrow_mut().remove(key));
        return Err(e);
    }
    Ok(())
}

/// Resolve one CQE for the sync event loop: `(handler_word, is_io_cmd)`.
/// The handler word is `Some` only for sync-mode entries, which are
/// removed here; op-future entries are completed and woken exactly as
/// [`ublk_reap_and_wake`] would, so a stray async op in a sync-driven
/// queue is delivered to its future rather than corrupting state.
///
/// `is_io_cmd` reports the entry's accounting flag for EVERY entry the
/// key resolves — sync, async and orphaned alike. The async submit path
/// incremented `cmd_inflight` just like the sync one, so the sync
/// loop's batch accounting must observe the completion either way, or
/// the count leaks and the queue never reaches `is_idle()`. The third
/// flag marks orphaned entries, whose result (e.g. a stale ABORT from
/// a previous queue on this thread) must be counted but must not drive
/// current-queue state.
#[inline]
pub(crate) fn take_sync_entry(key: usize, result: i32, more: bool) -> (Option<u64>, bool, bool) {
    let (ret, waker) = OP_SLAB.with(|slab| {
        let mut slab = slab.borrow_mut();
        let Some(entry) = slab.get_mut(key) else {
            debug_assert!(false, "CQE for unknown op {}", key);
            return ((None, false, false), None);
        };
        let is_io_cmd = entry.is_io_cmd;
        if entry.sync_data.is_none() {
            if entry.orphaned {
                if !more {
                    slab.remove(key).discard_result(result);
                }
                return ((None, is_io_cmd, true), None);
            }
            entry.terminated = !more;
            entry.push_result(result);
            return ((None, is_io_cmd, false), entry.waker.take());
        }
        let entry = slab.remove(key);
        ((Some(entry.sync_data.unwrap()), is_io_cmd, false), None)
    });
    // Wake outside the slab borrow: an inline waker may drop a future
    // whose Op re-enters the slab (orphan_entry).
    if let Some(waker) = waker {
        waker.wake();
    }
    ret
}

/// Handle to one submitted single-shot operation.
///
/// Dropping it before completion orphans the slab entry and issues a
/// best-effort ASYNC_CANCEL on the ring it was submitted on.
pub(crate) struct Op {
    ring: OpRing,
    key: usize,
    done: bool,
}

impl Op {
    /// Reserve a slab entry, then build-and-push the SQE with the entry's
    /// key as `user_data`; the entry is reclaimed if the push fails.
    #[inline]
    fn submit_on(
        ring: OpRing,
        resources: Resources,
        is_io_cmd: bool,
        build_and_push: impl FnOnce(u64) -> Result<(), UblkError>,
    ) -> Result<Op, UblkError> {
        let key = insert_entry(resources, is_io_cmd, None);
        if let Err(e) = build_and_push(key as u64) {
            OP_SLAB.with(|slab| slab.borrow_mut().remove(key));
            return Err(e);
        }
        Ok(Op {
            ring,
            key,
            done: false,
        })
    }

    /// Submit an SQE built by `build` (which receives the `user_data` key)
    /// on the queue ring, with `resources` kept alive in the slab entry.
    #[inline]
    pub(crate) fn submit(
        build: impl FnOnce(u64) -> squeue::Entry,
        resources: Resources,
    ) -> Result<Op, UblkError> {
        Self::submit_on(OpRing::Queue, resources, false, |key| {
            push_queue_sqe(&build(key))
        })
    }

    /// As [`Op::submit`], marking the op as a ublk io command whose
    /// completion the queue-state accounting must observe.
    #[inline]
    pub(crate) fn submit_io_cmd(
        build: impl FnOnce(u64) -> squeue::Entry,
        resources: Resources,
    ) -> Result<Op, UblkError> {
        Self::submit_on(OpRing::Queue, resources, true, |key| {
            push_queue_sqe(&build(key))
        })
    }

    /// As [`Op::submit`], on the control ring (128-byte SQEs).
    #[inline]
    pub(crate) fn submit_ctrl(
        build: impl FnOnce(u64) -> squeue::Entry128,
        resources: Resources,
    ) -> Result<Op, UblkError> {
        Self::submit_on(OpRing::Ctrl, resources, false, |key| {
            push_ctrl_sqe(&build(key))
        })
    }

    /// Non-blocking completion check for a synchronously driven op: the
    /// CQE result once it has been reaped, consuming the op. Used by the
    /// blocking control-command path, which drives the ring itself
    /// instead of parking an executor.
    pub(crate) fn try_take_result(&mut self) -> Option<i32> {
        assert!(!self.done, "op polled after completion");
        OP_SLAB.with(|slab| {
            let mut slab = slab.borrow_mut();
            let entry = slab.get_mut(self.key).expect("op entry vanished");
            entry.result?;
            // Control commands are all single-completion uring_cmds, so
            // unlike poll_single this path needs no multi-CQE fallback.
            debug_assert!(entry.terminated, "multi-CQE ctrl cmd");
            let entry = slab.remove(self.key);
            self.done = true;
            entry.result
        })
    }

    /// Poll for the single completion, handing back the kept resources.
    #[inline]
    pub(crate) fn poll_single(&mut self, cx: &mut Context<'_>) -> Poll<(i32, Resources)> {
        assert!(!self.done, "op polled after completion");
        OP_SLAB.with(|slab| {
            let mut slab = slab.borrow_mut();
            let entry = slab.get_mut(self.key).expect("op entry vanished");
            match entry.result {
                None => {
                    // Only clone the waker when the stored one would not
                    // wake this task (repeated polls are common under
                    // join!/select!).
                    if entry
                        .waker
                        .as_ref()
                        .map_or(true, |w| !w.will_wake(cx.waker()))
                    {
                        entry.waker = Some(cx.waker().clone());
                    }
                    Poll::Pending
                }
                Some(result) => {
                    self.done = true;
                    if entry.terminated {
                        let entry = slab.remove(self.key);
                        Poll::Ready((result, entry.resources))
                    } else {
                        // A multi-CQE SQE (send_zc, multishot) was
                        // submitted through the single-shot path — a
                        // contract violation of `ops::submit_sqe`. More
                        // CQEs carrying this key are in flight: freeing
                        // the key now would let the slab recycle it and
                        // deliver those CQEs into an unrelated op. Park
                        // the entry as orphaned instead — the reaper
                        // reclaims it (and drops its resources) on the
                        // terminal CQE.
                        debug_assert!(false, "multi-CQE sqe awaited through single-shot Op");
                        log::error!(
                            "op {}: multi-CQE sqe awaited through single-shot Op; \
                             later completions are dropped",
                            self.key
                        );
                        entry.orphaned = true;
                        entry.waker = None;
                        Poll::Ready((result, Resources::None))
                    }
                }
            }
        })
    }
}

impl Drop for Op {
    fn drop(&mut self) {
        if !self.done {
            orphan_entry(self.ring, self.key);
        }
    }
}

/// Orphan a dropped op's slab entry (reclaimed by the reaper on its
/// terminal CQE) and issue a best-effort ASYNC_CANCEL; reclaims the
/// entry directly when its terminal CQE has already been reaped.
fn orphan_entry(ring: OpRing, key: usize) {
    let completed = OP_SLAB.with(|slab| {
        let mut slab = slab.borrow_mut();
        let Some(entry) = slab.get_mut(key) else {
            return true;
        };
        if entry.terminated {
            // Result already reaped but never consumed (future dropped
            // after completion, before its final poll).
            let entry = slab.remove(key);
            if let Some(result) = entry.result {
                entry.discard_result(result);
            }
            return true;
        }
        entry.orphaned = true;
        entry.waker = None;
        false
    });
    if completed {
        return;
    }
    // Best effort: if the SQ is wedged, the eventual completion (or
    // queue teardown) still reclaims the entry.
    let cancel = opcode::AsyncCancel::new(key as u64)
        .build()
        .user_data(IGNORE_USER_DATA);
    let _ = match ring {
        OpRing::Queue => push_queue_sqe(&cancel),
        OpRing::Ctrl => push_ctrl_sqe(&cancel.into()),
    };
}

/// Handle to a submitted operation that completes with one or more CQEs
/// (`IORING_CQE_F_MORE` chains: zero-copy sends, multishot ops).
///
/// [`poll_next`](MultiOp::poll_next) yields each CQE result in arrival
/// order and `None` once the terminal CQE has been consumed. Dropping
/// the handle mid-chain orphans the entry like a single-shot [`Op`].
pub(crate) struct MultiOp {
    key: usize,
    done: bool,
}

impl MultiOp {
    /// Reserve a slab entry and push the SQE built by `build` (which
    /// receives the `user_data` key) on the queue ring, as [`Op::submit`]
    /// does for single-shot ops.
    pub(crate) fn submit(build: impl FnOnce(u64) -> squeue::Entry) -> Result<MultiOp, UblkError> {
        let key = insert_entry(Resources::None, false, None);
        if let Err(e) = push_queue_sqe(&build(key as u64)) {
            OP_SLAB.with(|slab| slab.borrow_mut().remove(key));
            return Err(e);
        }
        Ok(MultiOp { key, done: false })
    }

    /// Poll for the next completion; `Ready(None)` after the terminal
    /// CQE has been consumed.
    pub(crate) fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<i32>> {
        if self.done {
            return Poll::Ready(None);
        }
        OP_SLAB.with(|slab| {
            let mut slab = slab.borrow_mut();
            let entry = slab.get_mut(self.key).expect("op entry vanished");
            if let Some(result) = entry.pop_result() {
                if entry.terminated && entry.result.is_none() {
                    slab.remove(self.key);
                    self.done = true;
                }
                return Poll::Ready(Some(result));
            }
            if entry.terminated {
                slab.remove(self.key);
                self.done = true;
                return Poll::Ready(None);
            }
            if entry
                .waker
                .as_ref()
                .map_or(true, |w| !w.will_wake(cx.waker()))
            {
                entry.waker = Some(cx.waker().clone());
            }
            Poll::Pending
        })
    }
}

impl Drop for MultiOp {
    fn drop(&mut self) {
        if !self.done {
            orphan_entry(OpRing::Queue, self.key);
        }
    }
}

/// Drain `ring`'s completion queue, collecting the waker of the future
/// behind each CQE. `per_cqe` runs for every CQE with two flags:
/// whether it completed a ublk io command (for the queue-state
/// accounting) and whether the entry was orphaned (counted, but its
/// result — e.g. a stale ABORT — must not drive current-queue state). Returns the number of CQEs drained and the wakers to
/// invoke — the caller MUST wake them, and only after releasing its
/// ring borrow (see the comment on `wakers` below). Reserved sentinels,
/// orphans and not-yet-polled futures drain without producing a waker,
/// and an executor park hook must not treat them as runnable work. The
/// slab and the completion queue are borrowed once for the whole batch;
/// CQEs posted mid-drain are picked up by the caller's next pass.
pub(crate) fn ublk_reap_and_wake<S, F>(ring: &mut IoUring<S>, mut per_cqe: F) -> (usize, Vec<Waker>)
where
    S: squeue::EntryMarker,
    F: FnMut(&cqueue::Entry, bool, bool),
{
    OP_SLAB.with(|slab| {
        let mut slab = slab.borrow_mut();
        let cq = ring.completion();
        let mut n = 0;
        // Collected, not woken here: a waker may run arbitrary code
        // inline (a bring-your-own executor can drop a task's future,
        // whose Op re-enters the slab and pushes a cancel SQE), so
        // waking under the slab — or the caller's ring — RefCell borrow
        // would panic with a double borrow. The caller wakes these
        // after releasing its ring borrow.
        let mut wakers: Vec<Waker> = Vec::new();
        for cqe in cq {
            n += 1;
            let key = match classify_user_data(cqe.user_data()) {
                CqeOwner::Op(key) => key,
                // Sentinels and target-owned CQEs (the batch transport
                // pushes its own target-bit user_data) carry no op
                // state: hand them to the caller untouched.
                CqeOwner::Sentinel | CqeOwner::Target => {
                    per_cqe(&cqe, false, false);
                    continue;
                }
            };
            let Some(entry) = slab.get_mut(key) else {
                debug_assert!(false, "CQE for unknown op {}", key);
                per_cqe(&cqe, false, false);
                continue;
            };
            // The third flag marks orphaned entries: their completion
            // must still be counted (the submit incremented the
            // inflight count), but nobody is serving the command any
            // more — in particular a stale ABORT from a command of a
            // previously dropped queue on this thread must not flip a
            // freshly registered queue into stopping.
            per_cqe(&cqe, entry.is_io_cmd, entry.orphaned);
            let more = cqueue::more(cqe.flags());
            if entry.orphaned || entry.sync_data.is_some() {
                // Orphaned future, or a sync-mode entry drained by the
                // runtime reaper (a queue should not mix the models; the
                // sync handler is not available here, so the entry is
                // only reclaimed and accounted) -- reclaimed on the
                // terminal CQE only, so a multi-CQE chain cannot land on
                // a recycled key.
                if !more {
                    slab.remove(key).discard_result(cqe.result());
                }
                continue;
            }
            entry.terminated = !more;
            entry.push_result(cqe.result());
            if let Some(waker) = entry.waker.take() {
                wakers.push(waker);
            }
        }
        (n, wakers)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both reapers route CQEs through [`classify_user_data`], so a
    /// target-owned word must never be mistaken for a slab key: the
    /// batch transport pushes its own target-bit `user_data` on the same
    /// ring the op slab uses.
    #[test]
    fn classify_user_data_separates_the_three_keyspaces() {
        let target_bit = crate::UblkUringData::Target as u64;

        assert!(matches!(classify_user_data(0), CqeOwner::Op(0)));
        assert!(matches!(classify_user_data(66), CqeOwner::Op(66)));

        // The batch transport's encoding: target bit plus its own fields.
        assert!(matches!(
            classify_user_data(target_bit | 0x42),
            CqeOwner::Target
        ));
        assert!(matches!(classify_user_data(target_bit), CqeOwner::Target));

        assert!(matches!(
            classify_user_data(IGNORE_USER_DATA),
            CqeOwner::Sentinel
        ));
        assert!(matches!(
            classify_user_data(RESERVED_USER_DATA_MIN),
            CqeOwner::Sentinel
        ));
        assert!(matches!(classify_user_data(u64::MAX), CqeOwner::Sentinel));
    }

    /// Classification must never lose bits: a word that does not fit in
    /// a `usize` has to be rejected rather than truncated into a live
    /// key (on 32-bit, `0x8000_0000_0000_0042 as usize` would be 66).
    #[test]
    fn classify_user_data_never_truncates_into_a_key() {
        let cases = [
            0,
            66,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            0x1_0000_0042,
            (crate::UblkUringData::Target as u64) | 0x42,
            RESERVED_USER_DATA_MIN - 1,
        ];
        for data in cases {
            if let CqeOwner::Op(key) = classify_user_data(data) {
                assert_eq!(
                    key as u64, data,
                    "user_data {:#x} was truncated into key {:#x}",
                    data, key
                );
            }
        }
    }
}
