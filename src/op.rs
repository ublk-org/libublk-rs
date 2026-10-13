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
use std::cell::{Cell, RefCell};
use std::task::{Context, Poll, Waker};
use std::thread::LocalKey;

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

/// The entry's inline completion storage: two 32-bit values and a tag
/// byte. A single-shot op queues up to two results in order (`tag`
/// counts them); a multi-CQE op's [`InlineFold`] uses all three as it
/// likes.
#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub(crate) struct Slots {
    pub(crate) v: [i32; 2],
    pub(crate) tag: u8,
}

/// [`InlineFold::on_cqe`] of one fold type, stored in the entry.
pub(crate) type FoldFn = fn(&mut Slots, i32, u32, bool) -> bool;

/// How a multi-CQE op keeps its CQEs: folded into the entry's inline
/// [`Slots`], the way [`crate::ops::SendZcOp`] keeps its send result and
/// notification. A multishot SQE can post any number of CQEs before its
/// consumer runs, so an op's fold must keep a bounded summary -- OR poll
/// events into a mask, count timeout ticks -- rather than queue them;
/// the op's typed handle then reads the slots through
/// [`MultiOp::poll_with`]. No allocation, no dynamic dispatch: the entry
/// stores a plain function pointer chosen at submit.
pub(crate) trait InlineFold {
    /// Fold one CQE into `slots`. Runs inside the reaper, under the op
    /// slab borrow: it must not call back into the op layer.
    /// `orphaned`: the consumer is gone (its handle was dropped); release
    /// anything the CQE carries instead of keeping it. Returns whether
    /// the consumer should be woken (the terminal CQE always wakes it).
    fn on_cqe(slots: &mut Slots, res: i32, flags: u32, orphaned: bool) -> bool;
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
///
/// Exactly one cache line: an async IO touches its entries at insert,
/// reap and poll, and an entry straddling two lines costs two misses
/// where one would do.
#[repr(align(64))]
pub(crate) struct OpEntry {
    waker: Option<Waker>,
    resources: Resources,
    /// Inline completion storage: a single-shot op's pending results, or
    /// whatever a multi-CQE op's [`InlineFold`] keeps.
    slots: Slots,
    /// A multi-CQE op's [`InlineFold`]: its CQEs are folded into
    /// `slots` instead of queued there.
    fold: Option<FoldFn>,
    /// The entry's state bits ([`Self::LIVE`] and friends), packed so a
    /// vacant entry is told apart in the line itself and the flags are
    /// one store at insert.
    flags: u8,
}

impl OpEntry {
    /// The entry is held by an op (or a sync submission); a clear bit is
    /// a vacant entry on the slab's free list.
    const LIVE: u8 = 1 << 0;
    /// The terminal CQE (no `IORING_CQE_F_MORE`) has been reaped; no
    /// more completions are coming for this entry.
    const TERMINATED: u8 = 1 << 1;
    /// The owning future was dropped; the reaper frees the entry on the
    /// terminal CQE.
    const ORPHANED: u8 = 1 << 2;
    /// This op is a ublk io command (FETCH_REQ/COMMIT_AND_FETCH_REQ/...)
    /// whose completion the queue-state accounting must observe.
    const IS_IO_CMD: u8 = 1 << 3;
    /// A sync-mode entry: no future is attached, and the handler word
    /// (legacy tag-encoded `user_data`, see [`Self::sync_data`]) is
    /// delivered to the sync event loop's handler in place of the
    /// on-ring slab key. The word lives in `slots`, which a sync entry
    /// never uses for results, so it costs no extra bytes.
    const IS_SYNC: u8 = 1 << 4;

    /// A vacant entry: nothing to drop, every flag clear.
    const fn vacant() -> Self {
        OpEntry {
            waker: None,
            resources: Resources::None,
            slots: Slots { v: [0; 2], tag: 0 },
            fold: None,
            flags: 0,
        }
    }

    #[inline(always)]
    fn is_live(&self) -> bool {
        self.flags & Self::LIVE != 0
    }

    #[inline(always)]
    fn terminated(&self) -> bool {
        self.flags & Self::TERMINATED != 0
    }

    #[inline(always)]
    fn orphaned(&self) -> bool {
        self.flags & Self::ORPHANED != 0
    }

    #[inline(always)]
    fn is_io_cmd(&self) -> bool {
        self.flags & Self::IS_IO_CMD != 0
    }

    #[inline(always)]
    fn is_sync(&self) -> bool {
        self.flags & Self::IS_SYNC != 0
    }

    #[inline(always)]
    fn set_orphaned(&mut self) {
        self.flags |= Self::ORPHANED;
    }

    /// Take a vacant entry for an op: it is written in place, field by
    /// field, rather than built on the stack and copied in. The copy
    /// was the daemon's top user-space stall: the fresh entry's narrow
    /// stores were re-read by the slab's 16-byte copy loads before they
    /// had retired (a store-forwarding stall on every submit).
    /// [`OpSlab::reclaim`] leaves a vacant entry clean (no waker, no
    /// resources, no fold, flags clear), so only what this op sets is
    /// stored. The result slots are the exception: they are reset whole
    /// here, whatever the previous op left in them, because a fold
    /// ([`TimeoutFold`], [`PollFold`]) reads a value slot before it
    /// looks at the tag.
    #[inline(always)]
    fn init(&mut self, resources: Resources, is_io_cmd: bool) {
        debug_assert!(!self.is_live());
        debug_assert!(self.waker.is_none() && self.fold.is_none());
        debug_assert!(matches!(self.resources, Resources::None));
        // A vacant entry already holds `Resources::None`, and the ublk
        // command and raw-op submitters pass that literal: matching on
        // it lets the inlined path drop the write altogether. Assigning
        // unconditionally made LLVM materialize the 24-byte enum on the
        // stack and copy it in with 16-byte loads, which re-created the
        // store-forwarding stall this in-place init exists to remove.
        if !matches!(resources, Resources::None) {
            self.resources = resources;
        }
        self.slots = Slots::default();
        self.flags = Self::LIVE | if is_io_cmd { Self::IS_IO_CMD } else { 0 };
    }

    /// As [`Self::init`] for a sync-mode entry: the handler word rides
    /// in the result slots, which such an entry never uses otherwise,
    /// so a sync submission costs no more than an async one and the
    /// entry stays one cache line.
    #[inline(always)]
    fn init_sync(&mut self, sync_data: u64, is_io_cmd: bool) {
        self.init(Resources::None, is_io_cmd);
        self.flags |= Self::IS_SYNC;
        self.slots.v = [sync_data as i32, (sync_data >> 32) as i32];
    }

    #[cfg(test)]
    fn new(resources: Resources, is_io_cmd: bool) -> Self {
        let mut entry = Self::vacant();
        entry.init(resources, is_io_cmd);
        entry
    }

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

    /// Discard every pending result nobody will consume (see
    /// [`Self::discard_result`]). A fold's slots hold folded values, not
    /// queued results, and are left alone.
    fn discard_pending(&mut self) {
        if self.fold.is_some() {
            return;
        }
        while let Some(result) = self.pop_result() {
            self.discard_result(result);
        }
    }

    /// The handler word of a sync-mode entry (see [`Self::init_sync`]),
    /// `None` for an op future's entry.
    #[inline]
    fn sync_data(&self) -> Option<u64> {
        self.is_sync()
            .then(|| (self.slots.v[0] as u32 as u64) | ((self.slots.v[1] as u32 as u64) << 32))
    }

    /// The oldest pending result, without consuming it.
    #[inline]
    fn first_result(&self) -> Option<i32> {
        (self.slots.tag > 0).then_some(self.slots.v[0])
    }

    /// Queue a CQE result in the inline slots, in arrival order.
    #[inline]
    fn push_result(&mut self, result: i32) {
        if (self.slots.tag as usize) < self.slots.v.len() {
            self.slots.v[self.slots.tag as usize] = result;
            self.slots.tag += 1;
        } else {
            // A multishot SQE pushed through a single-shot path, against
            // the documented contract: there is nowhere to keep the
            // result, so release it like any unconsumed one.
            debug_assert!(false, "third pending CQE for an op without a fold");
            self.discard_result(result);
        }
    }

    #[inline]
    fn pop_result(&mut self) -> Option<i32> {
        let result = self.first_result()?;
        self.slots.v[0] = self.slots.v[1];
        self.slots.tag -= 1;
        Some(result)
    }

    /// Hand one CQE to a live entry: a multi-CQE op's fold absorbs it,
    /// any other op queues its result. Returns whether the consumer
    /// should be woken.
    #[inline]
    fn deliver(&mut self, res: i32, flags: u32) -> bool {
        let terminated = !cqueue::more(flags);
        if terminated {
            self.flags |= Self::TERMINATED;
        }
        match self.fold {
            Some(fold) => fold(&mut self.slots, res, flags, false) || terminated,
            None => {
                self.push_result(res);
                true
            }
        }
    }

    /// One CQE for an orphaned entry, whose consumer is gone. A fold
    /// still sees it (flagged orphaned) so it can release what the CQE
    /// carries; any other op's terminal result is discarded.
    /// Returns true on the terminal CQE: the caller must then
    /// [`Self::discard_pending`] the entry and reclaim it.
    #[inline]
    fn absorb_orphaned(&mut self, res: i32, flags: u32) -> bool {
        let terminal = !cqueue::more(flags);
        match self.fold {
            Some(fold) => {
                fold(&mut self.slots, res, flags, true);
            }
            None if terminal => self.discard_result(res),
            None => {}
        }
        terminal
    }
}

/// The op slab: a table of [`OpEntry`] indexed by key, with a stack of
/// vacant keys. Insert and release never move an entry: an op takes a
/// vacant entry and writes it in place ([`OpEntry::init`]), and
/// [`Self::reclaim`] cleans it in place and pushes its key, so no entry
/// is ever built on the stack and copied in. The table itself does move:
/// it only grows (to the thread's peak in-flight ops), and growing
/// reallocates every entry, so nothing may keep a pointer into an entry
/// -- anything an SQE references ([`Resources`]) is boxed. Thread exit
/// must not free memory the kernel may still be using (see `Drop`).
struct OpSlab {
    entries: Vec<OpEntry>,
    /// Vacant keys, most recently freed on top: the next insert reuses
    /// the line that was just touched.
    free: Vec<u32>,
    /// Live entries.
    len: usize,
}

/// What one op-slab CQE amounts to for the reaper that drained it.
struct OpCqe {
    /// A sync-mode entry's handler word (legacy tag-encoded `user_data`),
    /// for the sync event loop's handler; `None` for an op future's
    /// entry.
    sync_data: Option<u64>,
    /// The entry's accounting flag, reported for sync, async and orphaned
    /// entries alike: the submit incremented `cmd_inflight` either way,
    /// so the completion must be counted or the queue never reaches
    /// `is_idle()`.
    is_io_cmd: bool,
    /// Nobody is serving the entry any more: its completion is counted,
    /// but its result (e.g. a stale ABORT from a command of a previously
    /// dropped queue on this thread) must not drive current-queue state.
    orphaned: bool,
    /// The consumer to wake, if the CQE gave it something to see. Wake it
    /// outside the slab borrow: an inline waker may drop a future whose
    /// Op re-enters the slab (orphan_entry).
    waker: Option<Waker>,
}

impl OpSlab {
    const fn new() -> Self {
        OpSlab {
            entries: Vec::new(),
            free: Vec::new(),
            len: 0,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[cfg(test)]
    fn contains(&self, key: usize) -> bool {
        self.entries.get(key).is_some_and(OpEntry::is_live)
    }

    /// The live entry under `key`, `None` for a key nobody holds.
    #[inline]
    fn get_mut(&mut self, key: usize) -> Option<&mut OpEntry> {
        self.entries.get_mut(key).filter(|e| e.is_live())
    }

    /// Keys are minted here only, and must fit the free list's `u32` and
    /// the handle's key field ([`Op::KEY_MASK`]): more live ops than
    /// that on one thread is not a case to recover from, so growth past
    /// the limit panics.
    const MAX_KEY: usize = u32::MAX as usize;

    /// Take a vacant entry (clean, see [`Self::reclaim`]) for the caller
    /// to [`OpEntry::init`] in place; its key is the SQE's `user_data`.
    #[inline(always)]
    fn alloc(&mut self) -> (usize, &mut OpEntry) {
        self.len += 1;
        let key = match self.free.pop() {
            Some(key) => key as usize,
            None => {
                let key = self.entries.len();
                assert!(key <= Self::MAX_KEY, "op slab key space exhausted");
                self.entries.push(OpEntry::vacant());
                key
            }
        };
        let entry = &mut self.entries[key];
        debug_assert!(!entry.is_live());
        (key, entry)
    }

    /// Release the live entry under `key`, handing back its resources.
    /// The entry is left clean for its next [`OpEntry::init`]: no waker,
    /// no resources, no fold, flags clear. The result slots are not
    /// touched: `init` rewrites them whole, and nothing reads a vacant
    /// entry's slots ([`Self::get_mut`] filters on `LIVE`).
    #[inline(always)]
    fn reclaim(&mut self, key: usize) -> Resources {
        let entry = &mut self.entries[key];
        debug_assert!(entry.is_live());
        entry.waker = None;
        entry.fold = None;
        entry.flags = 0;
        let resources = std::mem::replace(&mut entry.resources, Resources::None);
        self.free.push(key as u32);
        self.len -= 1;
        resources
    }

    /// Hand one CQE to the entry under `key`: a sync-mode entry yields
    /// its handler word; a live op entry takes it ([`OpEntry::deliver`]);
    /// an orphaned one absorbs it. Both a sync-mode and an orphaned entry
    /// are reclaimed on their terminal CQE only, so a multi-CQE chain
    /// (multishot, SEND_ZC) cannot land on a recycled key -- for a sync
    /// entry the handler's next submission would otherwise reuse it and
    /// the remaining CQEs would resolve to the wrong entry. `None` for a
    /// key nobody holds.
    #[inline]
    fn complete(&mut self, key: usize, res: i32, flags: u32) -> Option<OpCqe> {
        let Some(entry) = self.get_mut(key) else {
            debug_assert!(false, "CQE for unknown op {}", key);
            return None;
        };
        let is_io_cmd = entry.is_io_cmd();
        if let Some(data) = entry.sync_data() {
            if !cqueue::more(flags) {
                self.reclaim(key);
            }
            return Some(OpCqe {
                sync_data: Some(data),
                is_io_cmd,
                orphaned: false,
                waker: None,
            });
        }
        if entry.orphaned() {
            if entry.absorb_orphaned(res, flags) {
                entry.discard_pending();
                self.reclaim(key);
            }
            return Some(OpCqe {
                sync_data: None,
                is_io_cmd,
                orphaned: true,
                waker: None,
            });
        }
        let waker = if entry.deliver(res, flags) {
            entry.waker.take()
        } else {
            None
        };
        Some(OpCqe {
            sync_data: None,
            is_io_cmd,
            orphaned: false,
            waker,
        })
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
        if !self.is_empty() {
            log::warn!(
                "thread exiting with {} ops in flight: leaking their buffers",
                self.len()
            );
            std::mem::forget(std::mem::take(&mut self.entries));
        }
    }
}

std::thread_local! {
    static OP_SLAB: RefCell<OpSlab> = const { RefCell::new(OpSlab::new()) };
}

/// Run `f` on this thread's value of `key`.
///
/// `LocalKey::with` is instantiated once per closure and LLVM leaves the
/// larger instantiations out of line, so each submit and poll paid a
/// call, a prologue and an indirect call to the TLS accessor. Fetching
/// only the address through `with` keeps the access itself inlined.
/// `with` still runs on every access, so lazy init and the
/// use-after-destruction panic are unchanged, and the reference cannot
/// leave `f`.
#[inline(always)]
pub(crate) fn with_local<T: 'static, R>(key: &'static LocalKey<T>, f: impl FnOnce(&T) -> R) -> R {
    let value = key.with(|value| value as *const T);
    // SAFETY: `with` returned, so the value is alive (it panics once the
    // value is destroyed), and thread-local destructors only run after
    // the thread's code has returned, so none can start while `f` runs.
    f(unsafe { &*value })
}

/// Run `f` on this thread's op slab.
#[inline(always)]
fn with_slab<R>(f: impl FnOnce(&RefCell<OpSlab>) -> R) -> R {
    with_local(&OP_SLAB, f)
}

/// Whether any op is still in flight on this thread (park-loop guard).
#[inline]
pub(crate) fn has_pending_ops() -> bool {
    with_slab(|slab| !slab.borrow().is_empty())
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

/// Take an entry for an op and write it in place. Kept `inline(always)`
/// up through [`Op::submit_on`], so that once the `#[inline]` submitters
/// above it are inlined into their caller (which the hot paths are) the
/// `Resources::None` literal folds into a discriminant store instead of
/// a 24-byte enum copied through the stack.
#[inline(always)]
fn insert_entry(resources: Resources, is_io_cmd: bool) -> usize {
    with_slab(|slab| {
        let mut slab = slab.borrow_mut();
        let (key, entry) = slab.alloc();
        entry.init(resources, is_io_cmd);
        key
    })
}

#[inline(always)]
fn insert_sync(sync_data: u64, is_io_cmd: bool) -> usize {
    with_slab(|slab| {
        let mut slab = slab.borrow_mut();
        let (key, entry) = slab.alloc();
        entry.init_sync(sync_data, is_io_cmd);
        key
    })
}

/// Submit a sync-mode SQE on the queue ring: the slab entry carries
/// `sync_data` (the handler-facing word) instead of a future, and is
/// reclaimed by [`take_sync_entry`] when the queue's sync event loop
/// drains its terminal CQE. Any memory the SQE references must stay valid until
/// then — sync targets use queue-slot buffers, which satisfy this by
/// construction.
pub(crate) fn submit_sync(
    build: impl FnOnce(u64) -> squeue::Entry,
    sync_data: u64,
    is_io_cmd: bool,
) -> Result<(), UblkError> {
    let key = insert_sync(sync_data, is_io_cmd);
    if let Err(e) = push_queue_sqe(&build(key as u64)) {
        with_slab(|slab| slab.borrow_mut().reclaim(key));
        return Err(e);
    }
    Ok(())
}

/// Resolve one CQE for the sync event loop: `(handler_word, is_io_cmd,
/// orphaned)`, the fields of [`OpCqe`]. The handler word is `Some` only
/// for sync-mode entries; op-future entries are completed and woken
/// exactly as [`ublk_reap_and_wake`] would (both go through
/// [`OpSlab::complete`]), so a stray async op in a sync-driven queue is
/// delivered to its future rather than corrupting state.
#[inline]
pub(crate) fn take_sync_entry(key: usize, result: i32, flags: u32) -> (Option<u64>, bool, bool) {
    let Some(cqe) = with_slab(|slab| slab.borrow_mut().complete(key, result, flags)) else {
        return (None, false, false);
    };
    if let Some(waker) = cqe.waker {
        waker.wake();
    }
    (cqe.sync_data, cqe.is_io_cmd, cqe.orphaned)
}

/// Handle to one submitted single-shot operation.
///
/// Dropping it before completion orphans the slab entry and issues a
/// best-effort ASYNC_CANCEL on the ring it was submitted on.
pub(crate) struct Op {
    /// `key | ring << 32 | done << 33`: one word, so an op is returned
    /// in a register and any copy of it is a single load. As three
    /// fields it was written with narrow stores and then moved into the
    /// awaiting frame with one 16-byte load, a store-forwarding stall on
    /// every submit that was the io task's hottest instruction.
    bits: u64,
    _local: ThreadLocalOp,
}

/// Keeps op handles on the thread that submitted them (neither `Send` nor
/// `Sync`). The op's entry lives in that thread's slab and its SQE in that
/// thread's ring: polled elsewhere, a handle would read whatever entry
/// another thread keeps under the same key, and dropped elsewhere it could
/// not cancel its SQE, leaving the op running and its entry leaked.
type ThreadLocalOp = std::marker::PhantomData<*const ()>;

impl Op {
    const KEY_MASK: u64 = u32::MAX as u64;
    const RING_CTRL: u64 = 1 << 32;
    const DONE: u64 = 1 << 33;

    /// `key` was minted by [`OpSlab::alloc`], which guarantees it fits
    /// [`Self::KEY_MASK`].
    #[inline(always)]
    fn new(ring: OpRing, key: usize) -> Self {
        let ring = match ring {
            OpRing::Queue => 0,
            OpRing::Ctrl => Self::RING_CTRL,
        };
        Op {
            bits: key as u64 | ring,
            _local: std::marker::PhantomData,
        }
    }

    #[inline(always)]
    fn key(&self) -> usize {
        (self.bits & Self::KEY_MASK) as usize
    }

    #[inline(always)]
    fn ring(&self) -> OpRing {
        if self.bits & Self::RING_CTRL != 0 {
            OpRing::Ctrl
        } else {
            OpRing::Queue
        }
    }

    #[inline(always)]
    fn done(&self) -> bool {
        self.bits & Self::DONE != 0
    }

    #[inline(always)]
    fn set_done(&mut self) {
        self.bits |= Self::DONE;
    }

    /// Reserve a slab entry, then build-and-push the SQE with the entry's
    /// key as `user_data`; the entry is reclaimed if the push fails.
    #[inline(always)]
    fn submit_on(
        ring: OpRing,
        resources: Resources,
        is_io_cmd: bool,
        build_and_push: impl FnOnce(u64) -> Result<(), UblkError>,
    ) -> Result<Op, UblkError> {
        let key = insert_entry(resources, is_io_cmd);
        if let Err(e) = build_and_push(key as u64) {
            with_slab(|slab| slab.borrow_mut().reclaim(key));
            return Err(e);
        }
        Ok(Op::new(ring, key))
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
        assert!(!self.done(), "op polled after completion");
        with_slab(|slab| {
            let mut slab = slab.borrow_mut();
            let entry = slab.get_mut(self.key()).expect("op entry vanished");
            entry.first_result()?;
            // Control commands are all single-completion uring_cmds, so
            // unlike poll_single this path needs no multi-CQE fallback.
            debug_assert!(entry.terminated(), "multi-CQE ctrl cmd");
            let result = entry.first_result();
            slab.reclaim(self.key());
            self.set_done();
            result
        })
    }

    /// Poll for the single completion, handing back the kept resources.
    #[inline]
    pub(crate) fn poll_single(&mut self, cx: &mut Context<'_>) -> Poll<(i32, Resources)> {
        assert!(!self.done(), "op polled after completion");
        with_slab(|slab| {
            let mut slab = slab.borrow_mut();
            let entry = slab.get_mut(self.key()).expect("op entry vanished");
            match entry.first_result() {
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
                    self.set_done();
                    if entry.terminated() {
                        Poll::Ready((result, slab.reclaim(self.key())))
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
                            self.key()
                        );
                        // The consumer owns `result` now: take it out of the
                        // entry, or reclaiming the entry would discard it
                        // again (closing a delivered fd).
                        entry.pop_result();
                        entry.set_orphaned();
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
        if !self.done() {
            orphan_entry(self.ring(), self.key());
        }
    }
}

/// Orphan a dropped op's slab entry (reclaimed by the reaper on its
/// terminal CQE) and issue a best-effort ASYNC_CANCEL; reclaims the
/// entry directly when its terminal CQE has already been reaped.
fn orphan_entry(ring: OpRing, key: usize) {
    let completed = with_slab(|slab| {
        let mut slab = slab.borrow_mut();
        let Some(entry) = slab.get_mut(key) else {
            return true;
        };
        if entry.terminated() {
            // Result already reaped but never consumed (future dropped
            // after completion, before its final poll).
            entry.discard_pending();
            slab.reclaim(key);
            return true;
        }
        entry.set_orphaned();
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

/// Handle to a submitted op that completes with one or more CQEs
/// (`IORING_CQE_F_MORE` chains: zero-copy sends, multishot ops), each
/// folded into the entry's [`Slots`] by `F`.
///
/// Typed handles are built on [`Self::poll_with`]: it lends the consumer
/// the slots, registers the waker when there is nothing to hand out yet,
/// and reclaims the entry once the stream has ended. Dropping
/// the handle before that orphans the entry and cancels the SQE; `F`
/// keeps seeing the CQEs (as orphaned) until the terminal one.
pub(crate) struct MultiOp<F> {
    key: usize,
    done: bool,
    _fold: std::marker::PhantomData<fn() -> F>,
    _local: ThreadLocalOp,
}

impl<F: InlineFold> MultiOp<F> {
    /// Reserve an entry and push the SQE built by `build` (which receives
    /// the `user_data` key) on the queue ring.
    pub(crate) fn submit(build: impl FnOnce(u64) -> squeue::Entry) -> Result<Self, UblkError> {
        Self::submit_inner(None, |key, _| build(key))
    }

    /// As [`Self::submit`] for a timeout SQE: `ts` is kept with the entry
    /// until it is reclaimed, and `build` gets a reference to it.
    pub(crate) fn submit_timeout(
        ts: io_uring::types::Timespec,
        build: impl FnOnce(u64, &io_uring::types::Timespec) -> squeue::Entry,
    ) -> Result<Self, UblkError> {
        Self::submit_inner(Some(Box::new(ts)), |key, ts| {
            build(key, ts.expect("timeout without its timespec"))
        })
    }

    fn submit_inner(
        ts: Option<Box<io_uring::types::Timespec>>,
        build: impl FnOnce(u64, Option<&io_uring::types::Timespec>) -> squeue::Entry,
    ) -> Result<Self, UblkError> {
        let resources = ts.map_or(Resources::None, Resources::Timespec);
        let (key, ts_ptr) = with_slab(|slab| {
            let mut slab = slab.borrow_mut();
            let (key, entry) = slab.alloc();
            entry.init(resources, false);
            entry.fold = Some(F::on_cqe);
            let ts_ptr = match &entry.resources {
                Resources::Timespec(ts) => Some(&**ts as *const io_uring::types::Timespec),
                _ => None,
            };
            (key, ts_ptr)
        });
        // SAFETY: the timespec's box lives in the entry, which stays in
        // the slab (and the box at its heap address) until reclaimed after
        // the terminal CQE -- long after this SQE is built and submitted;
        // the kernel reads it when it prepares the SQE.
        let sqe = build(key as u64, ts_ptr.map(|ts| unsafe { &*ts }));
        if let Err(e) = push_queue_sqe(&sqe) {
            with_slab(|slab| slab.borrow_mut().reclaim(key));
            return Err(e);
        }
        Ok(MultiOp {
            key,
            done: false,
            _fold: std::marker::PhantomData,
            _local: std::marker::PhantomData,
        })
    }

    /// Let `take` lift an item out of what the fold kept: `Some` hands it
    /// out. `None` with the terminal CQE reaped ends the stream and
    /// reclaims the entry; `None` before that registers the waker for
    /// the next CQE.
    pub(crate) fn poll_with<T>(
        &mut self,
        cx: &mut Context<'_>,
        take: impl FnOnce(&mut Slots) -> Option<T>,
    ) -> Poll<Option<T>> {
        if self.done {
            return Poll::Ready(None);
        }
        with_slab(|slab| {
            let mut slab = slab.borrow_mut();
            let entry = slab.get_mut(self.key).expect("op entry vanished");
            if let Some(item) = take(&mut entry.slots) {
                return Poll::Ready(Some(item));
            }
            if entry.terminated() {
                slab.reclaim(self.key);
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

impl<F> Drop for MultiOp<F> {
    fn drop(&mut self) {
        if !self.done {
            orphan_entry(OpRing::Queue, self.key);
        }
    }
}

std::thread_local! {
    /// The buffer of the last [`WakerBatch`] on this thread, kept so the
    /// next reap does not allocate (and regrow) one of its own.
    static WAKER_BUF: Cell<Vec<Waker>> = const { Cell::new(Vec::new()) };
}

/// The wakers one reap collected, to be woken by its caller.
pub(crate) struct WakerBatch(Vec<Waker>);

impl WakerBatch {
    /// Takes the thread's spare buffer. A reap nested inside a waker
    /// finds none and simply allocates.
    fn new() -> Self {
        WakerBatch(WAKER_BUF.with(|buf| buf.take()))
    }

    /// A batch for a caller that had no ring to reap.
    pub(crate) fn empty() -> Self {
        WakerBatch(Vec::new())
    }

    #[inline]
    fn push(&mut self, waker: Waker) {
        self.0.push(waker);
    }

    /// Wake every collected waker, returning how many there were. Call
    /// with no slab or ring borrow held: a waker may run inline.
    pub(crate) fn wake_all(mut self) -> usize {
        let n = self.0.len();
        for waker in self.0.drain(..) {
            waker.wake();
        }
        n
    }
}

impl Drop for WakerBatch {
    fn drop(&mut self) {
        if self.0.capacity() == 0 {
            return;
        }
        self.0.clear();
        // try_with: a batch may be dropped during thread teardown.
        let _ = WAKER_BUF.try_with(|buf| buf.set(std::mem::take(&mut self.0)));
    }
}

/// Drain `ring`'s completion queue, collecting the waker of the future
/// behind each CQE. `per_cqe` runs for every CQE with two flags:
/// whether it completed a ublk io command (for the queue-state
/// accounting) and whether the entry was orphaned (counted, but its
/// result — e.g. a stale ABORT — must not drive current-queue state).
/// Returns the number of CQEs drained and the wakers to invoke — the
/// caller MUST [`WakerBatch::wake_all`] them, and only after releasing
/// its ring borrow (see the comment on `wakers` below). Reserved
/// sentinels, orphans and not-yet-polled futures drain without producing
/// a waker, and an executor park hook must not treat them as runnable
/// work. The slab and the completion queue are borrowed once for the
/// whole batch; CQEs posted mid-drain are picked up by the caller's next
/// pass.
pub(crate) fn ublk_reap_and_wake<S, F>(ring: &mut IoUring<S>, mut per_cqe: F) -> (usize, WakerBatch)
where
    S: squeue::EntryMarker,
    F: FnMut(&cqueue::Entry, bool, bool),
{
    with_slab(|slab| {
        let mut slab = slab.borrow_mut();
        let cq = ring.completion();
        let mut n = 0;
        // Collected, not woken here: a waker may run arbitrary code
        // inline (a bring-your-own executor can drop a task's future,
        // whose Op re-enters the slab and pushes a cancel SQE), so
        // waking under the slab — or the caller's ring — RefCell borrow
        // would panic with a double borrow. The caller wakes these
        // after releasing its ring borrow.
        let mut wakers = WakerBatch::new();
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
            let Some(done) = slab.complete(key, cqe.result(), cqe.flags()) else {
                per_cqe(&cqe, false, false);
                continue;
            };
            // The third flag marks orphaned entries: their completion
            // must still be counted, but in particular a stale ABORT
            // from a command of a previously dropped queue on this
            // thread must not flip a freshly registered queue into
            // stopping. A sync-mode entry's handler word has no consumer
            // here (a queue should not mix the models): the entry is
            // only reclaimed and accounted.
            per_cqe(&cqe, done.is_io_cmd, done.orphaned);
            if let Some(waker) = done.waker {
                wakers.push(waker);
            }
        }
        (n, wakers)
    })
}

/// Device-free test plumbing: a plain ring stands in for the queue ring.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use io_uring::types::{SubmitArgs, Timespec};

    pub(crate) fn install_ring(cq_entries: u32) {
        let ring = IoUring::builder()
            .setup_cqsize(cq_entries)
            .build(16)
            .unwrap();
        crate::io::QUEUE_RING.with(|cell| {
            assert!(cell.set(RefCell::new(ring)).is_ok());
        });
    }

    /// Wait until `want` CQEs are ready (each wait bounded at 1 s, so a
    /// kernel that posts fewer cannot hang a test), then reap and wake.
    /// Returns how many CQEs were reaped.
    pub(crate) fn reap(want: usize) -> usize {
        let bound = Timespec::new().sec(1);
        let args = SubmitArgs::new().timespec(&bound);
        let (n, wakers) =
            crate::io::with_queue_ring_mut_internal!(|r: &mut IoUring<squeue::Entry>| {
                // Wait for all of them at once (with `1`, a CQE already
                // queued satisfies the wait at once: a busy loop), and stop
                // when a bounded wait brings nothing new -- the kernel
                // reports a timed-out wait as success when some CQEs are
                // queued, so the error alone does not end the loop.
                loop {
                    let ready = r.completion().len();
                    if ready >= want
                        || r.submitter().submit_with_args(want, &args).is_err()
                        || r.completion().len() == ready
                    {
                        break;
                    }
                }
                ublk_reap_and_wake(r, |_, _, _| {})
            });
        wakers.wake_all();
        n
    }

    pub(crate) fn noop_waker() -> Waker {
        struct Noop;
        impl std::task::Wake for Noop {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        Waker::from(std::sync::Arc::new(Noop))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// uapi IORING_CQE_F_MORE: more CQEs follow for this SQE.
    const MORE: u32 = 1 << 1;

    /// A reap runs for every batch of completions, so collecting its
    /// wakers must not allocate each time: the buffer a batch grew is
    /// handed to the next one on the same thread.
    #[test]
    fn waker_batch_wakes_all_and_recycles_its_buffer() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct Count(AtomicUsize);
        impl std::task::Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let count = Arc::new(Count(AtomicUsize::new(0)));

        let mut batch = WakerBatch::new();
        for _ in 0..100 {
            batch.push(Waker::from(count.clone()));
        }
        let buf = batch.0.as_ptr();
        assert_eq!(batch.wake_all(), 100);
        assert_eq!(count.0.load(Ordering::Relaxed), 100);

        let next = WakerBatch::new();
        assert!(next.0.is_empty());
        assert_eq!(next.0.as_ptr(), buf, "buffer was not recycled");
    }

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

    /// An SQE submitted through the sync path may post several CQEs
    /// (multishot poll/timeout, SEND_ZC's notification). The key has to
    /// stay reserved until the terminal one: freed early, the slab hands
    /// it to the handler's next io command and the remaining CQEs are
    /// mistaken for that command's completion.
    #[test]
    fn sync_entry_stays_reserved_until_the_terminal_cqe() {
        let word = (crate::UblkUringData::Target as u64) | 0x42;
        let key = insert_sync(word, false);

        // Intermediate CQE (IORING_CQE_F_MORE): delivered, entry kept.
        assert_eq!(take_sync_entry(key, 4096, MORE), (Some(word), false, false));
        let next = insert_sync(0x5, true);
        assert_ne!(next, key, "key reused while its SQE still has CQEs due");

        // Terminal CQE: delivered once more, entry reclaimed.
        assert_eq!(take_sync_entry(key, 0, 0), (Some(word), false, false));
        assert!(OP_SLAB.with(|slab| !slab.borrow().contains(key)));

        assert_eq!(take_sync_entry(next, 0, 0), (Some(0x5), true, false));
    }

    fn blank_entry() -> OpEntry {
        OpEntry::new(Resources::None, false)
    }

    /// Each op-slab entry is touched several times per IO (insert, reap,
    /// poll); at 64 bytes and 64-byte aligned it is exactly one cache
    /// line, and the slab's enum wrapper must not add a word that would
    /// push it to two.
    #[test]
    fn op_entry_is_one_cache_line() {
        assert_eq!(std::mem::size_of::<OpEntry>(), 64);
        assert_eq!(std::mem::align_of::<OpEntry>(), 64);
        let mut slab = OpSlab::new();
        let (a, _) = slab.alloc();
        let (b, _) = slab.alloc();
        let stride = (&slab.entries[b] as *const OpEntry as usize)
            - (&slab.entries[a] as *const OpEntry as usize);
        assert_eq!(stride, 64);
        assert_eq!(&slab.entries[a] as *const OpEntry as usize % 64, 0);
    }

    /// The two inline result slots hand results back in arrival order,
    /// across interleaved pushes and pops.
    #[test]
    fn op_entry_results_keep_arrival_order() {
        let mut e = blank_entry();
        assert_eq!(e.pop_result(), None);
        e.push_result(1);
        e.push_result(2);
        assert_eq!(e.pop_result(), Some(1));
        e.push_result(3);
        assert_eq!([e.pop_result(), e.pop_result()], [Some(2), Some(3)]);
        assert_eq!(e.pop_result(), None);
        e.push_result(4);
        assert_eq!(e.pop_result(), Some(4));
        assert_eq!(e.pop_result(), None);
    }

    /// An entry released with results nobody consumed must discard all
    /// of them, not just the first: for an op owning its result fds,
    /// the second would otherwise leak. (A multishot op's state releases
    /// what it holds itself, when it is dropped.)
    #[test]
    fn op_entry_discards_every_pending_result() {
        let open_fd = || {
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
            assert!(fd >= 0);
            fd
        };
        let is_open = |fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;

        let mut e = OpEntry::new(Resources::ResultFd, false);
        let fds = [open_fd(), open_fd()];
        for fd in fds {
            e.push_result(fd);
        }
        e.discard_pending();
        assert_eq!(e.first_result(), None);
        for fd in fds {
            assert!(!is_open(fd), "fd {} leaked", fd);
        }
    }

    /// The test helper's wait is bounded even when fewer CQEs than asked
    /// for ever arrive (one already queued must not turn the wait into
    /// a busy loop), so a kernel that posts fewer cannot hang a test.
    #[test]
    fn testing_reap_gives_up_on_missing_cqes() {
        testing::install_ring(16);
        let _op = crate::ops::nop().unwrap();
        let start = std::time::Instant::now();
        assert_eq!(testing::reap(3), 1);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    /// A multi-CQE SQE awaited through the single-shot path (a contract
    /// violation) hands its first result to the consumer and orphans the
    /// entry; when the terminal CQE later reclaims it, that first result
    /// must not be discarded again -- for an fd result, that would close
    /// an fd the consumer now owns. (Debug builds assert on the misuse
    /// itself, so this runs in release builds.)
    #[test]
    #[cfg(not(debug_assertions))]
    fn misused_single_shot_does_not_discard_a_delivered_result() {
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(fd >= 0);
        let key = insert_entry(Resources::ResultFd, false);
        with_slab(|slab| slab.borrow_mut().get_mut(key).unwrap().push_result(fd));
        let mut op = Op::new(OpRing::Queue, key);
        let waker = testing::noop_waker();
        let mut cx = Context::from_waker(&waker);
        match op.poll_single(&mut cx) {
            Poll::Ready((res, _)) => assert_eq!(res, fd),
            Poll::Pending => panic!("first result not delivered"),
        }
        // The terminal CQE (no IORING_CQE_F_MORE) reclaims the entry.
        take_sync_entry(key, -libc::ECANCELED, 0);
        assert!(with_slab(|slab| !slab.borrow().contains(key)));
        assert!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0,
            "delivered fd was closed"
        );
        unsafe { libc::close(fd) };
    }

    /// A fold's slots hold folded values, not queued results: releasing
    /// the entry must leave them alone.
    #[test]
    fn discarding_a_fold_entry_leaves_its_slots_alone() {
        let mut e = blank_entry();
        e.fold = Some(RecordFold::on_cqe);
        e.slots = Slots { v: [5, 6], tag: 3 };
        e.discard_pending();
        assert_eq!(e.slots, Slots { v: [5, 6], tag: 3 });
    }

    /// Up to two pending results (every single-shot op, and a zero-copy
    /// send's result plus notification) are held inline.
    #[test]
    fn op_entry_two_results_stay_inline() {
        let mut e = blank_entry();
        e.push_result(7);
        e.push_result(8);
        assert_eq!(e.first_result(), Some(7));
        assert_eq!(e.pop_result(), Some(7));
        e.push_result(9);
        assert_eq!([e.pop_result(), e.pop_result()], [Some(8), Some(9)]);
        assert_eq!(e.first_result(), None);
    }

    /// Only an op with an InlineFold can absorb more than two results; a
    /// third pending result on any other op is a contract violation (a
    /// multishot SQE pushed through a single-shot path), which debug
    /// builds catch.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "op without a fold")]
    fn op_entry_third_result_needs_a_fold() {
        let mut e = blank_entry();
        for r in 0..3 {
            e.push_result(r);
        }
    }

    std::thread_local! {
        /// Every CQE RecordFold saw on this test thread: (res, orphaned).
        static SEEN: RefCell<Vec<(i32, bool)>> = const { RefCell::new(Vec::new()) };
    }

    /// Records every CQE handed to it.
    struct RecordFold;

    impl InlineFold for RecordFold {
        fn on_cqe(slots: &mut Slots, res: i32, _flags: u32, orphaned: bool) -> bool {
            SEEN.with(|seen| seen.borrow_mut().push((res, orphaned)));
            slots.tag = slots.tag.wrapping_add(1);
            true
        }
    }

    fn recording_timeout(count: u32) -> MultiOp<RecordFold> {
        let ts = io_uring::types::Timespec::new().nsec(100_000);
        MultiOp::submit_timeout(ts, |key, ts| {
            opcode::Timeout::new(ts)
                .count(count)
                .flags(io_uring::types::TimeoutFlags::MULTISHOT)
                .build()
                .user_data(key)
        })
        .unwrap()
    }

    /// A consumer that takes nothing: it only sees the stream end.
    fn take_nothing(_: &mut Slots) -> Option<()> {
        None
    }

    /// Every CQE of a multi-CQE op reaches its fold, with nothing queued
    /// in the entry however many arrive before the consumer runs; the
    /// consumer sees the end once the terminal CQE is in, and the entry
    /// is reclaimed.
    #[test]
    fn fold_gets_every_cqe() {
        testing::install_ring(64);
        let mut op = recording_timeout(6);
        let waker = testing::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(op.poll_with(&mut cx, take_nothing).is_pending());
        testing::reap(6);
        loop {
            match op.poll_with(&mut cx, take_nothing) {
                Poll::Ready(None) => break,
                Poll::Ready(Some(())) => unreachable!(),
                Poll::Pending => assert!(testing::reap(1) > 0, "op never ended"),
            }
        }
        let seen = SEEN.with(|s| s.borrow().clone());
        if seen == [(-libc::EINVAL, false)] {
            return; // no IORING_TIMEOUT_MULTISHOT before Linux 6.4
        }
        assert_eq!(seen, vec![(-libc::ETIME, false); 6]);
        drop(op);
        assert!(!has_pending_ops());
    }

    /// A multi-CQE op dropped mid-stream is orphaned and cancelled; the
    /// CQEs that follow still reach its fold, flagged as orphaned (so it
    /// can release what they carry), and the terminal one reclaims the
    /// entry.
    #[test]
    fn orphaned_fold_sees_the_rest() {
        testing::install_ring(64);
        let mut op = recording_timeout(0);
        let waker = testing::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(op.poll_with(&mut cx, take_nothing).is_pending());
        testing::reap(1);
        if SEEN.with(|s| s.borrow().clone()) == [(-libc::EINVAL, false)] {
            return; // no IORING_TIMEOUT_MULTISHOT before Linux 6.4
        }
        let live = SEEN.with(|s| s.borrow().len());
        drop(op);
        for _ in 0..100 {
            if !has_pending_ops() {
                break;
            }
            testing::reap(1);
        }
        assert!(!has_pending_ops(), "orphaned op never ended");
        let seen = SEEN.with(|s| s.borrow().clone());
        assert!(seen[..live].iter().all(|&(_, orphaned)| !orphaned));
        assert!(seen[live..].iter().all(|&(_, orphaned)| orphaned));
        assert_eq!(seen.last(), Some(&(-libc::ECANCELED, true)));
    }
}
