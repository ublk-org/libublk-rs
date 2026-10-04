//! Multishot ops: one SQE, a stream of CQEs.
//!
//! Each op folds its CQEs into the entry's inline slots with an
//! [`InlineFold`] and reads them back through a typed handle built on
//! [`MultiOp::poll_with`] -- the same shape as [`crate::ops::SendZcOp`].
//! A burst that outruns the consumer is folded, not queued, so nothing
//! grows and nothing is allocated per CQE:
//!
//! * [`TimeoutMulti`] counts ticks: `next()` yields how many fired since
//!   the last call.
//! * [`PollMulti`] ORs event masks: `next()` yields every event seen
//!   since the last call.

use crate::op::{InlineFold, MultiOp, Slots};
use crate::UblkError;
use io_uring::{opcode, types};
use std::os::fd::RawFd;
use std::task::{Context, Poll};
use std::time::Duration;

/// What a stream item reports: a folded value, or the errno the op ended
/// with (e.g. `-ECANCELED`).
pub(crate) type Item = Result<u32, i32>;

/// Slot layout shared by the folds here: slot 0 holds the folded value
/// (present while `tag & VALUE`), slot 1 the first error (while
/// `tag & ERROR`).
const VALUE: u8 = 1;
const ERROR: u8 = 2;

fn keep_error(slots: &mut Slots, res: i32) {
    if slots.tag & ERROR == 0 {
        slots.v[1] = res;
        slots.tag |= ERROR;
    }
}

/// Hand out the folded value if there is one, else the op's error;
/// `None` once both are spent, so [`MultiOp::poll_with`] ends the stream
/// or waits for the next CQE.
fn take_folded(slots: &mut Slots) -> Option<Item> {
    if slots.tag & VALUE != 0 {
        slots.tag &= !VALUE;
        Some(Ok(std::mem::take(&mut slots.v[0]) as u32))
    } else if slots.tag & ERROR != 0 {
        slots.tag &= !ERROR;
        Some(Err(slots.v[1]))
    } else {
        None
    }
}

/// Counts timeout expiries.
pub(crate) struct TimeoutFold;

impl InlineFold for TimeoutFold {
    fn on_cqe(slots: &mut Slots, res: i32, _flags: u32, orphaned: bool) -> bool {
        if orphaned {
            return false; // nothing to release
        }
        // Every expiry, the last one included, completes with -ETIME;
        // anything else ends the op (e.g. -ECANCELED, or -EINVAL from a
        // kernel without IORING_TIMEOUT_MULTISHOT).
        if res == -libc::ETIME {
            slots.v[0] = slots.v[0].saturating_add(1);
            slots.tag |= VALUE;
        } else if res < 0 {
            keep_error(slots, res);
        }
        true
    }
}

/// A repeating timer (`IORING_TIMEOUT_MULTISHOT`): fires every
/// `interval`, `count` times (0: until dropped).
pub(crate) struct TimeoutMulti(MultiOp<TimeoutFold>);

impl TimeoutMulti {
    pub(crate) fn new(interval: Duration, count: u32) -> Result<Self, UblkError> {
        let op = MultiOp::submit_timeout(types::Timespec::from(interval), |key, ts| {
            opcode::Timeout::new(ts)
                .count(count)
                .flags(types::TimeoutFlags::MULTISHOT)
                .build()
                .user_data(key)
        })?;
        Ok(TimeoutMulti(op))
    }

    /// Ticks fired since the last call (`Ok(n)`, n > 0), the error the
    /// timer ended with, or `None` once it is done.
    pub(crate) fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Item>> {
        self.0.poll_with(cx, take_folded)
    }

    pub(crate) async fn next(&mut self) -> Option<Item> {
        std::future::poll_fn(|cx| self.poll_next(cx)).await
    }
}

/// ORs poll event masks.
pub(crate) struct PollFold;

impl InlineFold for PollFold {
    fn on_cqe(slots: &mut Slots, res: i32, _flags: u32, orphaned: bool) -> bool {
        if orphaned {
            return false; // nothing to release
        }
        if res >= 0 {
            slots.v[0] |= res;
            slots.tag |= VALUE;
        } else {
            keep_error(slots, res);
        }
        true
    }
}

/// Repeated readiness notifications for one fd (multishot
/// `IORING_OP_POLL_ADD`), until dropped or the kernel ends it.
pub(crate) struct PollMulti(MultiOp<PollFold>);

impl PollMulti {
    pub(crate) fn new(fd: RawFd, mask: u32) -> Result<Self, UblkError> {
        let op = MultiOp::submit(|key| {
            opcode::PollAdd::new(types::Fd(fd), mask)
                .multi(true)
                .build()
                .user_data(key)
        })?;
        Ok(PollMulti(op))
    }

    /// Every event seen since the last call (`Ok(mask)`), the error the
    /// poll ended with, or `None` once it is done.
    pub(crate) fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Item>> {
        self.0.poll_with(cx, take_folded)
    }

    pub(crate) async fn next(&mut self) -> Option<Item> {
        std::future::poll_fn(|cx| self.poll_next(cx)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::testing;
    use std::task::{Context, Poll};
    use std::time::Duration;

    /// A burst of 64 timeout ticks reaped before the consumer runs folds
    /// into one count: the op keeps a counter, not a queue, however far
    /// the kernel gets ahead.
    #[test]
    fn timeout_ticks_fold_into_a_count() {
        testing::install_ring(128);
        let mut t = TimeoutMulti::new(Duration::from_micros(100), 64).unwrap();
        let waker = testing::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(t.poll_next(&mut cx).is_pending());

        std::thread::sleep(Duration::from_millis(30));
        testing::reap(64);
        let first = t.poll_next(&mut cx);
        if first == Poll::Ready(Some(Err(-libc::EINVAL))) {
            return; // no IORING_TIMEOUT_MULTISHOT before Linux 6.4
        }
        assert_eq!(first, Poll::Ready(Some(Ok(64))));
        assert_eq!(t.poll_next(&mut cx), Poll::Ready(None));
        drop(t);
        assert!(!crate::op::has_pending_ops());
    }

    /// Run `fut` to completion on this thread, reaping the ring whenever
    /// it is pending: a minimal stand-in for the runtime's park hook.
    fn block_on_reaping<F: std::future::Future>(fut: F) -> F::Output {
        let waker = testing::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
            assert!(testing::reap(1) > 0, "future pending with nothing to reap");
        }
    }

    /// The async handles: awaiting `next()` until the end yields every
    /// tick exactly once, however they are folded along the way, and an
    /// awaited poll stream reports the event it was woken for.
    #[test]
    fn handles_await_through_next() {
        testing::install_ring(64);
        let mut t = TimeoutMulti::new(Duration::from_micros(200), 5).unwrap();
        let ticks = block_on_reaping(async {
            let mut total = 0;
            while let Some(item) = t.next().await {
                match item {
                    Ok(n) => total += n,
                    Err(e) => return Err(e),
                }
            }
            Ok(total)
        });
        if ticks == Err(-libc::EINVAL) {
            return; // no IORING_TIMEOUT_MULTISHOT before Linux 6.4
        }
        assert_eq!(ticks, Ok(5));
        drop(t);

        let efd = unsafe { libc::eventfd(1, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        assert!(efd >= 0);
        let mut p = PollMulti::new(efd, libc::POLLIN as u32).unwrap();
        let first = block_on_reaping(p.next());
        assert!(matches!(first, Some(Ok(m)) if m & libc::POLLIN as u32 != 0));
        drop(p);
        while crate::op::has_pending_ops() {
            testing::reap(1);
        }
        unsafe { libc::close(efd) };
    }

    /// Several wakeups of a polled fd between two consumer runs fold into
    /// one event mask; dropping the op cancels it and reclaims the entry.
    #[test]
    fn poll_events_fold_into_a_mask() {
        testing::install_ring(64);
        let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        assert!(efd >= 0);
        let mut p = PollMulti::new(efd, libc::POLLIN as u32).unwrap();
        let waker = testing::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(p.poll_next(&mut cx).is_pending());

        let one: u64 = 1;
        for _ in 0..3 {
            let n = unsafe { libc::write(efd, &one as *const u64 as *const _, 8) };
            assert_eq!(n, 8);
            testing::reap(1);
        }
        match p.poll_next(&mut cx) {
            Poll::Ready(Some(Ok(mask))) => assert_ne!(mask & libc::POLLIN as u32, 0),
            other => panic!("expected a folded POLLIN mask, got {:?}", other),
        }
        assert!(p.poll_next(&mut cx).is_pending(), "events not folded");

        drop(p);
        for _ in 0..100 {
            if !crate::op::has_pending_ops() {
                break;
            }
            testing::reap(1);
        }
        assert!(!crate::op::has_pending_ops(), "cancelled poll never ended");
        unsafe { libc::close(efd) };
    }
}
