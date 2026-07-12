//! Tokio current-thread runtime glued to the thread-local ublk io_urings.
//!
//! The thread's io_uring is the park primitive: Tokio's `on_thread_park`
//! hook runs only when no task is runnable, and the hook flushes pending
//! SQEs and waits for CQEs inside `io_uring_enter`, then wakes the futures
//! those CQEs complete. Submission is therefore batched and the
//! steady-state syscall count approaches zero under load.
//!
//! A thread may own the per-queue ring (`QUEUE_RING`), the control ring
//! (`CTRL_URING`), or both. With both, the queue ring is the single park
//! primitive and the control ring is bridged into it with a `PollAdd` on
//! the control ring fd, so control-command completions wake the parked
//! thread promptly.

use crate::op::{has_pending_ops, ublk_reap_and_wake, CTRL_POLL_DATA};
use crate::UblkError;
use io_uring::{opcode, types};
use std::cell::Cell;
use std::future::Future;
use std::os::fd::AsRawFd;

/// Backstop wait inside the park loop: bounds the damage of any missed
/// wakeup without ever being the intended wake mechanism (CQEs wake the
/// park long before this).
const PARK_SAFETY_SECS: u64 = 1;

std::thread_local! {
    /// Whether the control-ring PollAdd bridge is currently armed in the
    /// queue ring.
    static CTRL_POLL_ARMED: Cell<bool> = const { Cell::new(false) };
}

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
            .on_thread_park(park)
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

/// `on_thread_park` hook: reap CQEs and wake futures, sleeping in
/// `io_uring_enter` until at least one future can make progress.
fn park() {
    loop {
        if reap_queue_ring() + reap_ctrl_ring() > 0 {
            return;
        }
        if !has_pending_ops() {
            // Nothing a CQE could wake: let Tokio park normally so
            // cross-thread wakes (e.g. join handles) still work.
            return;
        }
        if !wait_for_cqe() {
            return;
        }
    }
}

/// Drain the queue ring's completion queue, waking the future behind each
/// CQE and doing the io-command accounting the explicit event loops used
/// to do. Returns the number of CQEs handled.
fn reap_queue_ring() -> usize {
    let (n, cmd_cnt, aborted) = crate::io::QUEUE_RING.with(|cell| {
        let Some(ring_cell) = cell.get() else {
            return (0, 0, false);
        };
        let mut ring = ring_cell.borrow_mut();
        let mut cmd_cnt = 0u32;
        let mut aborted = false;
        let n = ublk_reap_and_wake(&mut ring, |cqe, is_io_cmd| {
            if cqe.user_data() == CTRL_POLL_DATA {
                CTRL_POLL_ARMED.with(|armed| armed.set(false));
            } else if is_io_cmd {
                cmd_cnt += 1;
                if cqe.result() == crate::sys::UBLK_IO_RES_ABORT {
                    aborted = true;
                }
            }
        });
        (n, cmd_cnt, aborted)
    });
    if cmd_cnt > 0 {
        crate::io::update_queue_state(cmd_cnt, aborted);
    }
    n
}

/// Drain the control ring's completion queue, waking the future behind
/// each CQE. Returns the number of CQEs handled.
fn reap_ctrl_ring() -> usize {
    crate::ctrl::CTRL_URING.with(|cell| {
        let mut guard = cell.borrow_mut();
        let Some(ring) = guard.as_mut() else {
            return 0;
        };
        ublk_reap_and_wake(ring, |_, _| {})
    })
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
        Err(ref err)
            if matches!(
                err.raw_os_error(),
                Some(libc::ETIME | libc::EINTR | libc::EBUSY)
            ) =>
        {
            true
        }
        Err(err) => {
            log::error!("UblkRuntime park: io_uring_enter failed: {}", err);
            false
        }
    }
}
