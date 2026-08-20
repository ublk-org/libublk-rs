//! Executor-integration contract.
//!
//! libublk drives IO through per-thread io_urings (see [`crate::reactor`]).
//! Any async executor can host libublk futures if its idle path parks on
//! the reactor. This module defines the pieces an integration implements
//! ([`UblkExecutor`], [`UblkSpawner`], [`UblkTask`]) plus the
//! runtime-agnostic pieces target code uses ([`TaskHandle`],
//! [`spawn_local`]).
//!
//! # Liveness contract for `block_on` implementations
//!
//! - While the future is pending and this thread may hold in-flight ring
//!   ops, park ONLY via [`crate::reactor::wait_and_reap_events`] (or poll
//!   [`crate::reactor::reap_events`] non-blockingly).
//! - If the executor's own park primitive cannot be woken by a CQE (e.g.
//!   a condvar), it must re-enter its scheduler loop when the reactor
//!   returns [`crate::reactor::ParkOutcome::SafetyTimeout`], instead of
//!   sleeping on that primitive.
//! - `block_on` must install the ambient spawner (via
//!   [`with_ambient_spawner`]) for its full dynamic extent, so
//!   [`spawn_local`] works from any task it runs.

use crate::UblkError;
use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Object-safe spawning half of an executor integration. The ambient
/// slot installed by [`with_ambient_spawner`] stores a `&dyn UblkSpawner`.
pub trait UblkSpawner {
    /// Spawn a boxed task on this thread's executor.
    fn spawn_boxed(&self, fut: Pin<Box<dyn Future<Output = ()>>>) -> TaskHandle;
}

/// Implemented by executor integrations for their native join handles.
///
/// Contract: dropping the implementor must DETACH — the task stays
/// scheduled, it is not cancelled. Executors whose native handle
/// cancels on drop (smol's `Task`) must detach in their `Drop`.
/// [`UblkTask::cancel`] requests cancellation.
///
/// Detached is not immortal: a detached task lives only as long as its
/// executor. One still pending when the enclosing
/// [`UblkExecutor::block_on`] returns is destroyed without completing.
pub trait UblkTask: Future<Output = ()> + Unpin {
    /// Request cancellation (fire-and-forget), consuming the handle.
    fn cancel(self: Box<Self>);
}

/// Runtime-agnostic join handle returned by [`spawn_local`] /
/// [`UblkSpawner::spawn_boxed`]. Awaiting it resolves `()` once the
/// task is finished *for any reason* — completion, cancellation and a
/// panic are deliberately indistinguishable here (integrations log
/// panics). A task whose outcome matters must report it through its own
/// channel or shared state.
///
/// Dropping the handle detaches the task: it stays scheduled, but only
/// for as long as the executor runs — a detached task still pending
/// when [`UblkExecutor::block_on`] returns is destroyed without
/// completing. Await the handle (or such state) before the root future
/// returns when the task must finish (e.g. a final flush).
pub struct TaskHandle(Option<Box<dyn UblkTask>>);

impl TaskHandle {
    /// Wrap an executor's native handle.
    pub fn new(inner: Box<dyn UblkTask>) -> TaskHandle {
        TaskHandle(Some(inner))
    }

    /// Request cancellation of the task (fire-and-forget). Tokio maps
    /// this to `JoinHandle::abort`; smol drops the `Task`.
    pub fn cancel(mut self) {
        if let Some(t) = self.0.take() {
            t.cancel();
        }
    }
}

impl Future for TaskHandle {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match self.0.as_mut() {
            Some(t) => {
                let r = Pin::new(&mut **t).poll(cx);
                if r.is_ready() {
                    // Fuse: never poll the native handle again after it
                    // resolves (tokio's JoinHandle panics on that), and
                    // make later polls of this handle cheap Ready(()).
                    self.0 = None;
                }
                r
            }
            None => Poll::Ready(()),
        }
    }
}

std::thread_local! {
    /// Ambient spawner for the innermost `with_ambient_spawner` extent.
    static CURRENT_SPAWNER: Cell<Option<NonNull<dyn UblkSpawner>>> =
        const { Cell::new(None) };
}

/// Install `spawner` as this thread's ambient spawner for the duration
/// of `f`, restoring the previous one afterwards (panic-safe). Executor
/// implementations call this inside `block_on`.
///
/// Installation only routes [`spawn_local`] calls to `spawner`; whether
/// a spawn then *works* is the spawner's own precondition. For
/// `UblkRuntime` (the `tokio` feature) that means an active `block_on`
/// — installing
/// its spawner without one makes [`spawn_local`] fail with Tokio's own
/// panic message rather than this module's.
pub fn with_ambient_spawner<R>(spawner: &dyn UblkSpawner, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<NonNull<dyn UblkSpawner>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CURRENT_SPAWNER.with(|c| c.set(self.0));
        }
    }

    let ptr: NonNull<dyn UblkSpawner> =
        // SAFETY: lifetime erasure only. The pointer is removed from the
        // TLS slot by `Restore` before this function returns, so no
        // access outlives `spawner`'s borrow.
        unsafe { std::mem::transmute::<NonNull<dyn UblkSpawner + '_>, _>(NonNull::from(spawner)) };
    let prev = CURRENT_SPAWNER.with(|c| c.replace(Some(ptr)));
    let _restore = Restore(prev);
    f()
}

/// Spawn a task on the ambient runtime installed by the innermost
/// [`UblkExecutor::block_on`].
///
/// The ambient spawner stays installed for `block_on`'s full extent,
/// which is slightly wider than the window in which spawning is
/// effective: a call made while the executor is already tearing down —
/// e.g. from a `Drop` impl of a task destroyed after the root future
/// returned — may hand back a [`TaskHandle`] for a task that is
/// discarded without ever running. Do not spawn from destructors;
/// schedule cleanup before the root future returns instead.
///
/// # Panics
///
/// Panics when called outside a `block_on` extent.
pub fn spawn_local(fut: impl Future<Output = ()> + 'static) -> TaskHandle {
    CURRENT_SPAWNER.with(|c| {
        let ptr = c
            .get()
            .expect("libublk::spawn_local called outside UblkExecutor::block_on");
        // SAFETY: valid for the with_ambient_spawner extent we are inside.
        let spawner = unsafe { ptr.as_ref() };
        spawner.spawn_boxed(Box::pin(fut))
    })
}

/// Executor integration contract; see the module docs for the liveness
/// rules `block_on` must follow.
pub trait UblkExecutor: UblkSpawner + Sized {
    /// Build the executor on the current thread.
    fn new() -> Result<Self, UblkError>;

    /// Run `future` to completion on this thread, installing `self` as
    /// the ambient spawner and parking on [`crate::reactor`] when idle.
    fn block_on<F: Future>(&self, future: F) -> F::Output;

    /// Create queue `qid` of `dev` on the current thread, spawn one
    /// `io_task(q, tag)` per tag, and run until every task completes.
    /// Task errors other than [`UblkError::QueueIsDown`] are logged.
    fn run_io_tasks<F, Fut>(
        dev: &Arc<crate::io::UblkDev>,
        qid: u16,
        io_task: F,
    ) -> Result<(), UblkError>
    where
        F: Fn(Rc<crate::io::UblkQueue>, u16) -> Fut + 'static,
        Fut: Future<Output = Result<(), UblkError>> + 'static,
    {
        let rt = Self::new()?;
        let dev = dev.clone();
        rt.block_on(async move {
            let q = Rc::new(crate::io::UblkQueue::new(qid, &dev)?);
            let handles: Vec<TaskHandle> = (0..dev.dev_info.queue_depth)
                .map(|tag| {
                    let task = io_task(q.clone(), tag);
                    spawn_local(async move {
                        match task.await {
                            Err(UblkError::QueueIsDown) | Ok(_) => {}
                            Err(e) => log::error!("io task failed for tag {}: {}", tag, e),
                        }
                    })
                })
                .collect();
            for h in handles {
                h.await;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal UblkTask for exercising TaskHandle without an executor.
    struct DummyTask {
        done: bool,
        cancelled: Rc<Cell<bool>>,
        detached: Rc<Cell<bool>>,
    }
    impl Future for DummyTask {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            if self.done {
                Poll::Ready(())
            } else {
                self.done = true;
                Poll::Pending
            }
        }
    }
    impl UblkTask for DummyTask {
        fn cancel(self: Box<Self>) {
            self.cancelled.set(true);
        }
    }
    impl Drop for DummyTask {
        fn drop(&mut self) {
            self.detached.set(true);
        }
    }

    fn dummy(cancelled: &Rc<Cell<bool>>, detached: &Rc<Cell<bool>>) -> TaskHandle {
        TaskHandle::new(Box::new(DummyTask {
            done: false,
            cancelled: cancelled.clone(),
            detached: detached.clone(),
        }))
    }

    fn poll_once(h: &mut TaskHandle) -> Poll<()> {
        // A raw no-op waker; MSRV 1.80 has no Waker::noop().
        use std::task::{RawWaker, RawWakerVTable, Waker};
        fn no(_: *const ()) {}
        fn cl(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VT)
        }
        static VT: RawWakerVTable = RawWakerVTable::new(cl, no, no, no);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VT)) };
        let mut cx = Context::from_waker(&waker);
        Pin::new(h).poll(&mut cx)
    }

    #[test]
    fn task_handle_polls_through_and_is_ready_after() {
        let (c, d) = (Rc::new(Cell::new(false)), Rc::new(Cell::new(false)));
        let mut h = dummy(&c, &d);
        assert_eq!(poll_once(&mut h), Poll::Pending);
        assert_eq!(poll_once(&mut h), Poll::Ready(()));
        // Handle stays Ready once resolved.
        assert_eq!(poll_once(&mut h), Poll::Ready(()));
        assert!(!c.get());
        drop(h);
        assert!(d.get());
        assert!(!c.get());
    }

    #[test]
    fn task_handle_cancel_calls_cancel() {
        let (c, d) = (Rc::new(Cell::new(false)), Rc::new(Cell::new(false)));
        dummy(&c, &d).cancel();
        assert!(c.get());
    }

    #[test]
    fn spawn_local_outside_block_on_panics() {
        let r = std::panic::catch_unwind(|| {
            let _ = spawn_local(async {});
        });
        assert!(r.is_err());
    }

    struct RecordingSpawner(Rc<Cell<u32>>);
    impl UblkSpawner for RecordingSpawner {
        fn spawn_boxed(&self, _fut: Pin<Box<dyn Future<Output = ()>>>) -> TaskHandle {
            self.0.set(self.0.get() + 1);
            TaskHandle(None) // already-resolved handle
        }
    }

    #[test]
    fn ambient_spawner_installs_and_restores() {
        let count = Rc::new(Cell::new(0));
        let s = RecordingSpawner(count.clone());
        with_ambient_spawner(&s, || {
            let _ = spawn_local(async {});
            let _ = spawn_local(async {});
        });
        assert_eq!(count.get(), 2);
        // Restored: spawning outside panics again.
        assert!(std::panic::catch_unwind(|| {
            let _ = spawn_local(async {});
        })
        .is_err());
    }
}
