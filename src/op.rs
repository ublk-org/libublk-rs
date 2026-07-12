//! In-flight uring operation state: the slab entry and single-shot op
//! futures.
//!
//! The `user_data` of every async SQE is the op's key in a thread-local
//! slab, so CQE dispatch is one slab lookup — no bit-encoded metadata.
//! One slab serves both thread-local rings (the per-queue ring and the
//! control ring): keys are unique per thread, and each [`Op`] remembers
//! which ring it was submitted on so cancellation reaches the right ring.
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

/// `user_data` of the PollAdd SQE bridging the control ring into the
/// queue ring — see `runtime.rs`, which arms and re-arms it.
pub(crate) const CTRL_POLL_DATA: u64 = u64::MAX;

/// `user_data` sentinel for SQEs whose CQE carries no op state
/// (e.g. ASYNC_CANCEL issued on orphaning).
pub(crate) const IGNORE_USER_DATA: u64 = u64::MAX - 1;

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
    waker: Option<Waker>,
    /// The owning future was dropped; the reaper frees the entry on the
    /// terminal CQE.
    orphaned: bool,
    /// This op is a ublk io command (FETCH_REQ/COMMIT_AND_FETCH_REQ/...)
    /// whose completion the queue-state accounting must observe.
    is_io_cmd: bool,
    resources: Resources,
}

std::thread_local! {
    static OP_SLAB: RefCell<Slab<OpEntry>> = RefCell::new(Slab::new());
}

/// Whether any op is still in flight on this thread (park-loop guard).
pub(crate) fn has_pending_ops() -> bool {
    OP_SLAB.with(|slab| !slab.borrow().is_empty())
}

/// Which thread-local ring an op was submitted on.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum OpRing {
    Queue,
    Ctrl,
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

/// Push `sqe` to the thread-local queue ring, flushing once if the SQ
/// ring is full.
fn push_queue_sqe(sqe: &squeue::Entry) -> Result<(), UblkError> {
    crate::with_queue_ring_mut_internal!(|r: &mut IoUring<squeue::Entry>| {
        // SAFETY: every pointer carried by the SQE refers to memory owned
        // by the corresponding slab entry (or caller-guaranteed memory for
        // raw ops), which outlives the op by construction.
        if unsafe { r.submission().push(sqe) }.is_ok() {
            return Ok(());
        }
        r.submit()?;
        // SAFETY: as above.
        unsafe { r.submission().push(sqe) }
            .map_err(|_| UblkError::OtherError(-libc::EBUSY))
    })
}

/// Push `sqe` to the thread-local control ring, flushing once if full.
fn push_ctrl_sqe(sqe: &squeue::Entry128) -> Result<(), UblkError> {
    crate::with_ctrl_ring_mut_internal!(|r: &mut IoUring<squeue::Entry128>| {
        // SAFETY: as in `push_queue_sqe`.
        if unsafe { r.submission().push(sqe) }.is_ok() {
            return Ok(());
        }
        r.submit()?;
        // SAFETY: as above.
        unsafe { r.submission().push(sqe) }
            .map_err(|_| UblkError::OtherError(-libc::EBUSY))
    })
}

fn insert_entry(resources: Resources, is_io_cmd: bool) -> usize {
    OP_SLAB.with(|slab| {
        slab.borrow_mut().insert(OpEntry {
            result: None,
            waker: None,
            orphaned: false,
            is_io_cmd,
            resources,
        })
    })
}

impl Op {
    /// Submit an SQE built by `build` (which receives the `user_data` key)
    /// on the queue ring, with `resources` kept alive in the slab entry.
    /// `is_io_cmd` marks ublk io commands for the queue-state accounting.
    pub(crate) fn submit(
        build: impl FnOnce(u64) -> squeue::Entry,
        resources: Resources,
        is_io_cmd: bool,
    ) -> Result<Op, UblkError> {
        let key = insert_entry(resources, is_io_cmd);
        let sqe = build(key as u64);
        if let Err(e) = push_queue_sqe(&sqe) {
            OP_SLAB.with(|slab| slab.borrow_mut().remove(key));
            return Err(e);
        }
        Ok(Op {
            ring: OpRing::Queue,
            key,
            done: false,
        })
    }

    /// As [`Op::submit`], on the control ring (128-byte SQEs).
    pub(crate) fn submit_ctrl(
        build: impl FnOnce(u64) -> squeue::Entry128,
        resources: Resources,
    ) -> Result<Op, UblkError> {
        let key = insert_entry(resources, false);
        let sqe = build(key as u64);
        if let Err(e) = push_ctrl_sqe(&sqe) {
            OP_SLAB.with(|slab| slab.borrow_mut().remove(key));
            return Err(e);
        }
        Ok(Op {
            ring: OpRing::Ctrl,
            key,
            done: false,
        })
    }

    /// Poll for the single completion, handing back the kept resources.
    pub(crate) fn poll_single(&mut self, cx: &mut Context<'_>) -> Poll<(i32, Resources)> {
        assert!(!self.done, "op polled after completion");
        OP_SLAB.with(|slab| {
            let mut slab = slab.borrow_mut();
            let entry = slab.get_mut(self.key).expect("op entry vanished");
            match entry.result {
                None => {
                    entry.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
                Some(result) => {
                    let entry = slab.remove(self.key);
                    self.done = true;
                    Poll::Ready((result, entry.resources))
                }
            }
        })
    }
}

impl Drop for Op {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let completed = OP_SLAB.with(|slab| {
            let mut slab = slab.borrow_mut();
            let Some(entry) = slab.get_mut(self.key) else {
                return true;
            };
            if entry.result.is_some() {
                slab.remove(self.key);
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
        let cancel = opcode::AsyncCancel::new(self.key as u64)
            .build()
            .user_data(IGNORE_USER_DATA);
        let _ = match self.ring {
            OpRing::Queue => push_queue_sqe(&cancel),
            OpRing::Ctrl => push_ctrl_sqe(&cancel.into()),
        };
    }
}

/// Drain `ring`'s completion queue, waking the future behind each CQE.
/// `per_cqe` runs for every CQE with a flag telling whether it completed
/// a ublk io command (for the queue-state accounting). Returns the number
/// of CQEs drained. The slab is borrowed once for the whole batch.
pub(crate) fn ublk_reap_and_wake<S, F>(ring: &mut IoUring<S>, mut per_cqe: F) -> usize
where
    S: squeue::EntryMarker,
    F: FnMut(&cqueue::Entry, bool),
{
    OP_SLAB.with(|slab| {
        let mut slab = slab.borrow_mut();
        let mut n = 0;
        while let Some(cqe) = ring.completion().next() {
            n += 1;
            let data = cqe.user_data();
            if data >= IGNORE_USER_DATA {
                per_cqe(&cqe, false);
                continue;
            }
            let key = data as usize;
            let Some(entry) = slab.get_mut(key) else {
                debug_assert!(false, "CQE for unknown op {}", key);
                per_cqe(&cqe, false);
                continue;
            };
            per_cqe(&cqe, entry.is_io_cmd);
            if entry.orphaned {
                slab.remove(key);
                continue;
            }
            entry.result = Some(cqe.result());
            if let Some(waker) = entry.waker.take() {
                waker.wake();
            }
        }
        n
    })
}
