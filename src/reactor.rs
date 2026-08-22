//! Executor-agnostic driving of the thread-local ublk io_urings.
//!
//! The op futures in [`crate::ops`] (and the async `UblkQueue`/`UblkCtrl`
//! methods built on them) are plain futures: they need *some* code to
//! flush SQEs, wait for CQEs, and wake them. This module is that code,
//! independent of any executor:
//!
//! - [`reap_events`] — non-blocking: drain both thread-local rings and
//!   wake the futures their CQEs complete.
//! - [`wait_and_reap_events`] — blocking: park the thread inside
//!   `io_uring_enter` until at least one future has been woken (or no
//!   ops remain in flight). Its [`ParkOutcome`] says which happened.
//! - [`has_pending_ops`] — whether any op is still in flight.
//!
//! # Integrating an executor
//!
//! Run tasks until none is runnable, then call [`wait_and_reap_events`];
//! the woken futures make their tasks runnable again. With an executor
//! exposing an idle/park hook, call it from the hook — that is exactly
//! what the built-in `UblkRuntime` (the `tokio` feature) does with
//! Tokio's `on_thread_park`. With a hand-rolled loop:
//!
//! ```no_run
//! use libublk::reactor::{wait_and_reap_events, ParkOutcome};
//! # fn executor_has_runnable_tasks() -> bool { false }
//! # fn run_runnable_tasks() {}
//! # fn all_tasks_finished() -> bool { true }
//! # fn park_on_own_primitive() {}
//! while !all_tasks_finished() {
//!     while executor_has_runnable_tasks() {
//!         run_runnable_tasks();
//!     }
//!     match wait_and_reap_events() {
//!         // Futures were woken, or the safety timeout expired while ops
//!         // are still in flight: loop back into the scheduler, since
//!         // this call is the only CQE consumer.
//!         ParkOutcome::Woken | ParkOutcome::SafetyTimeout => {}
//!         // No CQE can arrive; sleeping on another primitive is safe.
//!         ParkOutcome::NoPendingOps => park_on_own_primitive(),
//!         _ => {}
//!     }
//! }
//! ```
//!
//! A thread may own the per-queue ring, the control ring, or both. With
//! both, the queue ring is the single park primitive and the control
//! ring is bridged into it with a `PollAdd` on the control ring fd, so
//! control-command completions wake the parked thread promptly.

use crate::op::{ublk_reap_and_wake, RESERVED_USER_DATA_MIN};
use io_uring::{opcode, types};
use std::cell::Cell;
use std::os::fd::AsRawFd;

/// user_data of the PollAdd SQE bridging the control ring into the queue
/// ring: [`wait_for_cqe`] arms it, [`reap_queue_ring`] recognizes it to
/// re-arm. It lies in the op slab's reserved range, so the reaper passes
/// its CQE through without a slab lookup.
const CTRL_POLL_DATA: u64 = u64::MAX;
// Guards future edits of either constant.
#[allow(clippy::absurd_extreme_comparisons)]
const _: () = assert!(CTRL_POLL_DATA >= RESERVED_USER_DATA_MIN);

/// Backstop wait inside [`wait_and_reap_events`]: bounds the damage of
/// any missed wakeup without ever being the intended wake mechanism
/// (CQEs wake the park long before this).
const PARK_SAFETY_SECS: u64 = 1;

std::thread_local! {
    /// Whether the control-ring PollAdd bridge is currently armed in the
    /// queue ring.
    static CTRL_POLL_ARMED: Cell<bool> = const { Cell::new(false) };
}

/// Whether any op is still in flight on this thread. When `false`, a
/// [`wait_and_reap_events`] call would return immediately: there is
/// nothing a CQE could wake.
pub fn has_pending_ops() -> bool {
    crate::op::has_pending_ops()
}

/// Drain both thread-local rings once, waking the future behind each
/// CQE. Non-blocking. Returns the number of CQEs handled.
pub fn reap_events() -> usize {
    let (q, _) = reap_queue_ring();
    let (c, _) = reap_ctrl_ring();
    q + c
}

/// As [`reap_events`], also reporting how many wakers were woken:
/// sentinel and orphan CQEs drain without making any task runnable, and
/// the park path must not mistake them for progress.
fn reap_events_counting_wakes() -> (usize, usize) {
    let (qn, qw) = reap_queue_ring();
    let (cn, cw) = reap_ctrl_ring();
    (qn + cn, qw + cw)
}

/// What a [`wait_and_reap_events`] pass ended with; tells the executor
/// whether it must keep its scheduler loop alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "the outcome decides whether the executor may park on its \
              own primitive; ignoring SafetyTimeout can deadlock"]
#[non_exhaustive]
pub enum ParkOutcome {
    /// At least one waker was woken; the executor has work.
    Woken,
    /// No op is in flight: a CQE cannot occur, so the executor may park
    /// on its own primitive (cross-thread wakes still reach it there).
    NoPendingOps,
    /// The park-safety timeout expired with ops still in flight and no
    /// waker woken. The executor MUST NOT park on a primitive that CQEs
    /// cannot reach: it may hold deferred runnable work, and the next
    /// pass of this function is the only CQE consumer.
    SafetyTimeout,
}

/// Park the thread until at least one op future has been woken, or
/// until the park-safety timeout expires: reap both rings, and if
/// nothing was woken while ops remain in flight, flush pending SQEs and
/// sleep in `io_uring_enter` for at most one safety period (1s).
///
/// Returns immediately when no ops are in flight, so an executor may
/// call this unconditionally from its idle hook.
///
/// Cross-thread wake latency: while ops ARE in flight — for a ublk
/// queue thread that is always, its FETCH commands stay armed — the
/// thread sleeps inside `io_uring_enter`, which a cross-thread wake
/// (channel send, join-handle completion) cannot interrupt. Such a
/// wake is observed at the next CQE or, at the latest, when the 1s
/// safety timeout fires; nothing is lost, but anything signalling a
/// busy-idle queue thread from outside pays up to one safety period
/// of latency per round-trip. Latency-sensitive cross-thread
/// signalling should go through the ring instead (e.g. poll an
/// eventfd via [`crate::ops::poll_add`] and write it to wake).
///
/// The safety-timeout path also returns, without any woken waker: the
/// executor may have parked while still holding runnable (deferred)
/// work, and only returning lets that work -- which may be what
/// generates the next CQE -- run. An executor whose idle loop simply
/// calls this function again is naturally live. One that would instead
/// fall back to a park primitive CQEs cannot wake (as Tokio's condvar
/// parker does) must inspect the returned [`ParkOutcome`] and re-enter
/// its scheduler loop on [`ParkOutcome::SafetyTimeout`] --
/// `UblkRuntime` (the `tokio` feature) does this by waking a no-op
/// task.
pub fn wait_and_reap_events() -> ParkOutcome {
    loop {
        let (_, woken) = reap_events_counting_wakes();
        if woken > 0 {
            return ParkOutcome::Woken;
        }
        if !has_pending_ops() {
            // Nothing a CQE could wake: let the executor park normally
            // so cross-thread wakes (e.g. join handles) still work.
            return ParkOutcome::NoPendingOps;
        }
        if !wait_for_cqe() {
            return ParkOutcome::SafetyTimeout;
        }
    }
}

/// Drain the queue ring's completion queue, waking the future behind each
/// CQE and doing the io-command accounting the explicit event loops used
/// to do. Returns the number of CQEs handled and of wakers woken.
fn reap_queue_ring() -> (usize, usize) {
    let (n, wakers, cmd_cnt, aborted) = crate::io::QUEUE_RING.with(|cell| {
        let Some(ring_cell) = cell.get() else {
            return (0, Vec::new(), 0, false);
        };
        let mut ring = ring_cell.borrow_mut();
        let mut cmd_cnt = 0u32;
        let mut aborted = false;
        let (n, wakers) = ublk_reap_and_wake(&mut ring, |cqe, is_io_cmd, orphaned| {
            if cqe.user_data() == CTRL_POLL_DATA {
                CTRL_POLL_ARMED.with(|armed| armed.set(false));
            } else if is_io_cmd {
                cmd_cnt += 1;
                // An orphaned command's ABORT is stale — possibly from
                // a queue already dropped on this thread — and must not
                // flip the currently registered queue into stopping.
                if !orphaned && cqe.result() == crate::sys::UBLK_IO_RES_ABORT {
                    aborted = true;
                }
            }
        });
        (n, wakers, cmd_cnt, aborted)
    });
    if cmd_cnt > 0 {
        crate::io::update_queue_state(cmd_cnt, aborted);
    }
    // Wake with every RefCell borrow released: an inline waker may drop
    // an op future, which re-borrows the slab and the ring.
    let woken = wakers.len();
    for waker in wakers {
        waker.wake();
    }
    (n, woken)
}

/// Drain the control ring's completion queue, waking the future behind
/// each CQE. Returns the number of CQEs handled and of wakers woken.
fn reap_ctrl_ring() -> (usize, usize) {
    let (n, wakers) = crate::ctrl::CTRL_URING.with(|cell| {
        let mut guard = cell.borrow_mut();
        let Some(ring) = guard.as_mut() else {
            return (0, Vec::new());
        };
        ublk_reap_and_wake(ring, |_, _, _| {})
    });
    let woken = wakers.len();
    for waker in wakers {
        waker.wake();
    }
    (n, woken)
}

/// Flush pending SQEs and sleep in `io_uring_enter` until a CQE arrives
/// (or the safety timeout fires). Returns `false` when the thread has no
/// ring to wait on.
fn wait_for_cqe() -> bool {
    let has_queue = crate::io::QUEUE_RING.with(|cell| cell.get().is_some());
    let has_ctrl = crate::ctrl::CTRL_URING.with(|cell| cell.borrow().is_some());

    if has_ctrl {
        // Flush control SQEs; when parking on the queue ring, also bridge
        // control completions into it so they wake the sleep below.
        let ctrl_fd = crate::ctrl::CTRL_URING.with(|cell| {
            let mut guard = cell.borrow_mut();
            let ring = guard.as_mut().unwrap();
            let _ = ring.submit();
            ring.as_raw_fd()
        });
        if has_queue && !CTRL_POLL_ARMED.with(|armed| armed.get()) {
            let sqe = opcode::PollAdd::new(types::Fd(ctrl_fd), libc::POLLIN as _)
                .build()
                .user_data(CTRL_POLL_DATA);
            let pushed = crate::io::QUEUE_RING.with(|cell| {
                let ring_cell = cell.get().unwrap();
                let mut ring = ring_cell.borrow_mut();
                // SAFETY: the SQE references no user memory.
                let pushed = unsafe { ring.submission().push(&sqe).is_ok() };
                pushed
            });
            // If the SQ is full the safety timeout still bounds the wait.
            CTRL_POLL_ARMED.with(|armed| armed.set(pushed));
        }
    }

    let timeout = types::Timespec::new().sec(PARK_SAFETY_SECS);
    let args = types::SubmitArgs::new().timespec(&timeout);
    let res = if has_queue {
        crate::io::QUEUE_RING.with(|cell| {
            let ring_cell = cell.get().unwrap();
            let ring = ring_cell.borrow_mut();
            ring.submitter().submit_with_args(1, &args)
        })
    } else if has_ctrl {
        crate::ctrl::CTRL_URING.with(|cell| {
            let mut guard = cell.borrow_mut();
            let ring = guard.as_mut().unwrap();
            ring.submitter().submit_with_args(1, &args)
        })
    } else {
        // No ring on this thread: nothing a CQE wait could wake.
        return false;
    };

    match res {
        Ok(_) => true,
        // Safety timeout: hand control back to the executor instead of
        // re-arming the wait. The executor may have parked while still
        // holding runnable (deferred) work whose progress is the only
        // way the awaited CQEs can ever be generated; bouncing out once
        // per safety period keeps that case live instead of deadlocking.
        Err(ref err) if err.raw_os_error() == Some(libc::ETIME) => false,
        Err(ref err) if matches!(err.raw_os_error(), Some(libc::EINTR | libc::EBUSY)) => true,
        Err(err) => {
            log::error!("ublk reactor: io_uring_enter failed: {}", err);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The executor's park hook must return within the park-safety bound
    /// when no CQE arrives, instead of re-arming the wait forever.
    ///
    /// The executor may park while it still has runnable (deferred) work
    /// -- Tokio's current-thread scheduler does exactly that at a
    /// `LocalSet` tick boundary, parking after polling only part of the
    /// spawned tasks. If the hook keeps waiting for a CQE that only those
    /// unpolled tasks can cause, startup deadlocks (observed with one
    /// spawned task per tag on a 128-deep queue: the FETCH completions
    /// the hook waits for cannot arrive before every task has submitted
    /// its FETCH and the device has started).
    #[test]
    fn test_wait_and_reap_events_bounded_without_cqe() {
        crate::io::ublk_init_task_ring(|cell| {
            if cell.get().is_none() {
                let ring = io_uring::IoUring::builder()
                    .build(64)
                    .map_err(crate::UblkError::IOError)?;
                cell.set(std::cell::RefCell::new(ring))
                    .map_err(|_| crate::UblkError::OtherError(-libc::EEXIST))?;
            }
            Ok(())
        })
        .unwrap();

        // One in-flight op whose CQE arrives long after the safety bound
        let _op = crate::ops::sleep(std::time::Duration::from_secs(5)).unwrap();

        let start = std::time::Instant::now();
        let outcome = wait_and_reap_events();
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "park hook blocked past the safety timeout while the executor may hold runnable work"
        );
        // The op is still in flight and nothing was woken, so the
        // executor must be told to re-enter its scheduler loop.
        assert_eq!(outcome, ParkOutcome::SafetyTimeout);
    }
}
