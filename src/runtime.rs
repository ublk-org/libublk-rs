//! Tokio current-thread runtime glued to the thread-local ublk io_urings
//! (the built-in executor integration, behind the default `tokio`
//! feature).
//!
//! The thread's io_uring is the park primitive: Tokio's `on_thread_park`
//! hook runs only when no task is runnable, and the hook is
//! [`crate::reactor::wait_and_reap_events`] — it flushes pending SQEs and
//! waits for CQEs inside `io_uring_enter`, then wakes the futures those
//! CQEs complete. Submission is therefore batched and the steady-state
//! syscall count approaches zero under load.
//!
//! To use a different executor, disable the `tokio` feature and drive
//! [`crate::reactor`] from that executor's idle hook — this module is
//! nothing more than that pattern applied to Tokio. Alternatively,
//! implement [`crate::executor::UblkExecutor`] (see that module's docs
//! for the liveness contract).

use crate::UblkError;
use std::cell::RefCell;
use std::future::Future;
use std::task::Waker;

std::thread_local! {
    /// Waker of this thread's `block_on` root future, woken by the park
    /// hook when the reactor's safety timeout fires so the scheduler
    /// re-runs (and re-enters the hook) instead of parking on its
    /// condvar, which a CQE could never wake. It must be the root
    /// (scheduler-native) waker: waking a `LocalSet` task from its own
    /// thread only enqueues it without notifying the parker.
    static PARK_KICK_WAKER: RefCell<Option<Waker>> = const { RefCell::new(None) };
}

fn park_hook() {
    if matches!(
        crate::reactor::wait_and_reap_events(),
        crate::reactor::ParkOutcome::SafetyTimeout
    ) {
        // No waker was woken, but ops are still in flight and the
        // executor may hold deferred runnable work. Wake the block_on
        // root so the scheduler loops (running any such work) and parks
        // into this hook again, rather than on its condvar where the
        // next CQE could never reach it.
        PARK_KICK_WAKER.with(|w| {
            if let Some(waker) = w.borrow().as_ref() {
                waker.wake_by_ref();
            }
        });
    }
}

/// One thread's runtime: a Tokio current-thread scheduler whose park
/// primitive is the thread's io_uring(s).
///
/// Create it on the thread that will run it, then call
/// [`block_on`](UblkRuntime::block_on); tasks may use
/// `tokio::task::spawn_local` or the executor-agnostic
/// [`crate::executor::spawn_local`], which works under any
/// [`crate::executor::UblkExecutor`]. Tokio's IO and time drivers are
/// absent: all IO on this thread goes through the ring.
pub struct UblkRuntime {
    rt: tokio::runtime::Runtime,
    /// The runtime's own task set. Spawns via the executor contract
    /// land here — never on whatever `LocalSet` happens to be running —
    /// so tasks belong to *this* runtime and survive across its
    /// `block_on` calls, dying only when the runtime is dropped.
    local: tokio::task::LocalSet,
}

impl UblkRuntime {
    /// Build the runtime on the current thread.
    pub fn new() -> Result<Self, UblkError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .on_thread_park(park_hook)
            .build()
            .map_err(UblkError::IOError)?;
        Ok(UblkRuntime {
            rt,
            local: tokio::task::LocalSet::new(),
        })
    }

    /// Run a future to completion inside the runtime's `LocalSet`,
    /// driving the thread-local ublk uring(s) while the future is
    /// pending.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        crate::executor::with_ambient_spawner(self, || {
            self.rt.block_on(self.local.run_until(async move {
                let mut future = std::pin::pin!(future);
                std::future::poll_fn(move |cx| {
                    // (Re-)register the root waker for the park hook's kick.
                    PARK_KICK_WAKER.with(|w| {
                        let mut slot = w.borrow_mut();
                        if !slot
                            .as_ref()
                            .is_some_and(|existing| existing.will_wake(cx.waker()))
                        {
                            *slot = Some(cx.waker().clone());
                        }
                    });
                    future.as_mut().poll(cx)
                })
                .await
            }))
        })
    }

    /// Inherent delegator to the one implementation,
    /// [`UblkExecutor::run_io_tasks`](crate::executor::UblkExecutor::run_io_tasks)
    /// -- see it for the contract. Kept inherent so an executor alias
    /// (`type Rt = UblkRuntime;` vs a custom integration) resolves
    /// `Rt::run_io_tasks(...)` without a trait import, which would be an
    /// unused import under the other alias arm.
    pub fn run_io_tasks<F, Fut>(
        dev: &std::sync::Arc<crate::io::UblkDev>,
        qid: u16,
        io_task: F,
    ) -> Result<(), UblkError>
    where
        F: Fn(std::rc::Rc<crate::io::UblkQueue>, u16) -> Fut + 'static,
        Fut: Future<Output = Result<(), UblkError>> + 'static,
    {
        <Self as crate::executor::UblkExecutor>::run_io_tasks(dev, qid, io_task)
    }
}

/// Tokio's JoinHandle adapted to the executor contract. JoinHandle
/// already detaches on drop; cancel maps to abort. A JoinError resolves
/// the handle to `()` like completion does (panics are logged first),
/// per the [`crate::executor::TaskHandle`] outcome-erasure contract.
struct TokioTask(tokio::task::JoinHandle<()>);

impl Future for TokioTask {
    type Output = ();
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        match std::pin::Pin::new(&mut self.0).poll(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(()),
            std::task::Poll::Ready(Err(e)) => {
                if e.is_panic() {
                    log::error!("spawned task panicked: {}", e);
                }
                std::task::Poll::Ready(())
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl crate::executor::UblkTask for TokioTask {
    fn cancel(self: Box<Self>) {
        self.0.abort();
    }
}

/// Spawning targets the runtime's own `LocalSet` (`self.local`), never
/// the free `tokio::task::spawn_local` — the free form lands the task
/// on the *innermost currently-running* `LocalSet`, so a nested
/// `LocalSet::run_until` in target code would capture (and on return
/// destroy) library-spawned tasks. Spawning on the handle also works
/// before/between [`UblkRuntime::block_on`] calls: the task starts once
/// `block_on` next runs. (Target code calling tokio's free
/// `spawn_local` directly still gets the innermost-set semantics.)
impl crate::executor::UblkSpawner for UblkRuntime {
    fn spawn_boxed(
        &self,
        fut: std::pin::Pin<Box<dyn Future<Output = ()>>>,
    ) -> crate::executor::TaskHandle {
        crate::executor::TaskHandle::new(Box::new(TokioTask(self.local.spawn_local(fut))))
    }
}

impl crate::executor::UblkExecutor for UblkRuntime {
    fn new() -> Result<Self, UblkError> {
        UblkRuntime::new()
    }
    fn block_on<F: Future>(&self, future: F) -> F::Output {
        UblkRuntime::block_on(self, future)
    }
    // LocalSet::spawn_local is itself generic: skip the spawn_boxed box.
    fn spawn<F: Future<Output = ()> + 'static>(&self, fut: F) -> crate::executor::TaskHandle {
        crate::executor::TaskHandle::new(Box::new(TokioTask(self.local.spawn_local(fut))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An io task failing before it registers its buffer must fail
    /// run_target with an error instead of hanging both the main
    /// thread (buffer-registration condvar) and the queue thread
    /// (sibling tasks parked on the registration semaphore forever).
    /// Requires a real ublk device.
    #[test]
    fn run_target_fails_fast_when_io_tasks_error() {
        use crate::ctrl::{UblkCtrl, UblkCtrlBuilder};
        use crate::io::UblkDev;
        use crate::{UblkError, UblkFlags};
        use std::sync::Arc;

        let ctrl = UblkCtrlBuilder::default()
            .name("fail_fast")
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap();
        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(1_u64 << 30);
            Ok(())
        };
        let q_fn = move |qid: u16, dev: &Arc<UblkDev>| {
            let res = UblkRuntime::run_io_tasks(dev, qid, |_q, _tag| async move {
                Err::<(), UblkError>(UblkError::OtherError(-libc::EINVAL))
            });
            assert!(res.is_err());
        };
        let res = ctrl.run_target(tgt_init, q_fn, |_ctrl: &UblkCtrl| {});
        assert!(res.is_err());
    }

    /// The executor contract promises `spawn` needs only the executor
    /// itself, no running `block_on`: a task spawned before (or
    /// between) `block_on` calls starts once one runs. Under the old
    /// free-`tokio::task::spawn_local` implementation this panicked.
    #[test]
    fn spawn_outside_block_on_runs_on_next_block_on() {
        use crate::executor::UblkExecutor;
        use std::cell::Cell;
        use std::rc::Rc;

        let rt = <UblkRuntime as UblkExecutor>::new().unwrap();
        let ran = Rc::new(Cell::new(false));
        let r = ran.clone();
        let h = rt.spawn(async move {
            r.set(true);
        });
        assert!(!ran.get());
        rt.block_on(h);
        assert!(ran.get());
    }

    #[test]
    fn trait_impl_spawn_cancel_detach() {
        use crate::executor::{spawn_local, UblkExecutor};
        use std::cell::Cell;
        use std::rc::Rc;

        // Yield once so spawned tasks interleave with the root future.
        struct YieldNow(bool);
        impl std::future::Future for YieldNow {
            type Output = ();
            fn poll(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<()> {
                if self.0 {
                    std::task::Poll::Ready(())
                } else {
                    self.0 = true;
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            }
        }

        let rt = <UblkRuntime as UblkExecutor>::new().unwrap();
        let ran = Rc::new(Cell::new(0u32));
        let (r1, r2) = (ran.clone(), ran.clone());
        rt.block_on(async move {
            // awaited task runs
            let h = spawn_local(async move {
                r1.set(r1.get() + 1);
            });
            h.await;
            // detached task (handle dropped) still runs
            drop(spawn_local(async move {
                r2.set(r2.get() + 1);
            }));
            // cancelled pending task never runs its body end
            let h = spawn_local(async {
                std::future::pending::<()>().await;
            });
            h.cancel();
            YieldNow(false).await;
            YieldNow(false).await;
        });
        assert_eq!(ran.get(), 2);
    }
}
