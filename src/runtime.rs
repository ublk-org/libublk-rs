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
//! nothing more than that pattern applied to Tokio.

use crate::UblkError;
use std::future::Future;

/// One thread's runtime: a Tokio current-thread scheduler whose park
/// primitive is the thread's io_uring(s).
///
/// Create it on the thread that will run it, then call
/// [`block_on`](UblkRuntime::block_on); tasks may use
/// `tokio::task::spawn_local`. Tokio's IO and time drivers are absent:
/// all IO on this thread goes through the ring.
pub struct UblkRuntime {
    rt: tokio::runtime::Runtime,
}

impl UblkRuntime {
    /// Build the runtime on the current thread.
    pub fn new() -> Result<Self, UblkError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .on_thread_park(crate::reactor::wait_and_reap_events)
            .build()
            .map_err(UblkError::IOError)?;
        Ok(UblkRuntime { rt })
    }

    /// Run a future to completion inside a fresh `LocalSet`, driving the
    /// thread-local ublk uring(s) while the future is pending.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        let local = tokio::task::LocalSet::new();
        self.rt.block_on(local.run_until(future))
    }

    /// Create queue `qid` of `dev` on the current thread, spawn one
    /// `io_task(q, tag)` per tag, and run until every task completes
    /// (normally when the queue is torn down). Task errors other than
    /// [`UblkError::QueueIsDown`] are logged.
    ///
    /// This is the standard body of a `run_target()` queue handler; use
    /// [`UblkRuntime::new`] + [`block_on`](UblkRuntime::block_on) directly
    /// when the thread also runs non-io tasks (e.g. control commands).
    pub fn run_io_tasks<F, Fut>(
        dev: &std::sync::Arc<crate::io::UblkDev>,
        qid: u16,
        io_task: F,
    ) -> Result<(), UblkError>
    where
        F: Fn(std::rc::Rc<crate::io::UblkQueue>, u16) -> Fut + 'static,
        Fut: Future<Output = Result<(), UblkError>> + 'static,
    {
        let rt = UblkRuntime::new()?;
        let dev = dev.clone();
        rt.block_on(async move {
            let q = std::rc::Rc::new(crate::io::UblkQueue::new(qid, &dev)?);
            let handles: Vec<_> = (0..dev.dev_info.queue_depth)
                .map(|tag| {
                    let task = io_task(q.clone(), tag);
                    tokio::task::spawn_local(async move {
                        match task.await {
                            Err(UblkError::QueueIsDown) | Ok(_) => {}
                            Err(e) => log::error!("io task failed for tag {}: {}", tag, e),
                        }
                    })
                })
                .collect();
            for handle in handles {
                let _ = handle.await;
            }
            Ok(())
        })
    }
}
