use crate::io::UblkQueue;
use crate::UblkError;
use crate::UblkUringData;
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use slab::Slab;
use std::cell::RefCell;
use std::os::fd::AsRawFd;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

struct FutureData {
    waker: Option<Waker>,
    result: Option<i32>,
}

std::thread_local! {
    static MY_SLAB: RefCell<Slab<FutureData>> = RefCell::new(Slab::new());
}

/// User code creates one future with user_data used for submitting
/// uring OP, then future.await returns this uring OP's result.
pub struct UblkUringOpFuture {
    pub user_data: u64,
}

impl UblkUringOpFuture {
    pub fn new(tgt_io: u64) -> Self {
        MY_SLAB.with(|refcell| {
            let mut map = refcell.borrow_mut();

            let key = map.insert(FutureData {
                waker: None,
                result: None,
            });
            let user_data = ((key as u32) << 16) as u64 | tgt_io;
            log::trace!("uring: new future {:x}", user_data);
            UblkUringOpFuture { user_data }
        })
    }
}

impl Future for UblkUringOpFuture {
    type Output = i32;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        MY_SLAB.with(|refcell| {
            let mut map = refcell.borrow_mut();
            let key = ((self.user_data & !(UblkUringData::Target as u64)) >> 16) as usize;
            match map.get_mut(key) {
                None => {
                    log::trace!("uring: null slab {:x}", self.user_data);
                    Poll::Pending
                }
                Some(fd) => match fd.result {
                    Some(result) => {
                        map.remove(key);
                        log::trace!("uring: uring io ready userdata {:x} ready", self.user_data);
                        Poll::Ready(result)
                    }
                    None => {
                        fd.waker = Some(cx.waker().clone());
                        log::trace!("uring: uring io pending userdata {:x}", self.user_data);
                        Poll::Pending
                    }
                },
            }
        })
    }
}

/// Wakeup the pending task, which will be marked as runnable
/// by smol, and the task's future poll() will be run by smol
/// executor's try_tick()
#[inline]
pub fn ublk_wake_task(data: u64, cqe: &cqueue::Entry) {
    MY_SLAB.with(|refcell| {
        let mut map = refcell.borrow_mut();

        log::trace!(
            "ublk_wake_task: data {:x} user_data {:x} result {}",
            data,
            cqe.user_data(),
            cqe.result()
        );
        let data = ((data & !(UblkUringData::Target as u64)) >> 16) as usize;
        if let Some(fd) = map.get_mut(data) {
            fd.result = Some(cqe.result());
            if let Some(w) = &fd.waker {
                w.wake_by_ref();
            }
        }
    })
}

fn ublk_try_reap_cqe<S: squeue::EntryMarker>(
    ring: &mut IoUring<S>,
    nr_waits: usize,
) -> Option<cqueue::Entry> {
    match ring.submit_and_wait(nr_waits) {
        Err(_) => None,
        _ => ring.completion().next(),
    }
}

fn ublk_process_queue_io(
    exe: &smol::LocalExecutor,
    q: &UblkQueue,
    nr_waits: usize,
) -> Result<i32, UblkError> {
    let res = if !q.is_stopping() {
        q.flush_and_wake_io_tasks(|data, cqe, _| ublk_wake_task(data, cqe), nr_waits)
    } else {
        crate::io::with_queue_ring_mut_internal!(|r: &mut IoUring<squeue::Entry>| {
            match ublk_try_reap_cqe(r, nr_waits) {
                Some(cqe) => {
                    let user_data = cqe.user_data();
                    ublk_wake_task(user_data, &cqe);
                    Ok(1)
                }
                None => Ok(0),
            }
        })
    };
    while exe.try_tick() {}

    res
}

/// Run one task in this local Executor until the task is finished
pub fn ublk_run_task<T, F>(
    exe: &smol::LocalExecutor,
    task: &smol::Task<T>,
    handler: F,
) -> Result<(), UblkError>
where
    F: Fn(&smol::LocalExecutor) -> Result<(), UblkError>,
{
    // make sure the spawned task is started by `try_tick()`
    while exe.try_tick() {}
    while !task.is_finished() {
        handler(exe)?;
    }
    Ok(())
}

/// Run one IO task in this local Executor until the task is finished
pub fn ublk_run_io_task<T>(
    exe: &smol::LocalExecutor,
    task: &smol::Task<T>,
    q: &UblkQueue,
    nr_waits: usize,
) -> Result<(), UblkError> {
    let handler = move |exe: &smol::LocalExecutor| -> Result<(), UblkError> {
        let _ = ublk_process_queue_io(exe, q, nr_waits)?;
        Ok(())
    };

    ublk_run_task(exe, task, handler)
}

/// Run one control task in this local Executor until the task is finished,
/// control task is queued in the thread_local io_uring CTRL_URING.
///
/// The current queue is passed in because some control command depends on
/// IO command, such as START command, so ublk_run_ctrl_task() has to drive
/// both data and control urings.
///
/// Rust isn't friendly for using native poll or epoll, so use one dedicated
/// uring for polling data and control urings.
pub fn ublk_run_ctrl_task<T>(
    exe: &smol::LocalExecutor,
    q: &UblkQueue,
    task: &smol::Task<T>,
) -> Result<(), UblkError> {
    let mut pr: IoUring<squeue::Entry, cqueue::Entry> = IoUring::builder().build(4)?;
    let ctrl_fd =
        crate::ctrl::with_ctrl_ring_internal!(|ring: &IoUring<squeue::Entry128>| ring.as_raw_fd());
    let q_fd = q.as_raw_fd();
    let mut poll_q = true;
    let mut poll_ctrl = true;

    while exe.try_tick() {}
    while !task.is_finished() {
        log::debug!(
            "poll ring: submit and wait, ctrl_fd {} q_fd {}",
            ctrl_fd,
            q_fd
        );

        if poll_q {
            let q_e = opcode::PollAdd::new(types::Fd(q_fd), (libc::POLLIN | libc::POLLOUT) as _);
            let _ = unsafe { pr.submission().push(&q_e.build().user_data(0x01)) };
            poll_q = false;
        }
        if poll_ctrl {
            let ctrl_e =
                opcode::PollAdd::new(types::Fd(ctrl_fd), (libc::POLLIN | libc::POLLOUT) as _);
            let _ = unsafe { pr.submission().push(&ctrl_e.build().user_data(0x02)) };
            poll_ctrl = false;
        }

        pr.submit_and_wait(1)?;
        let cqes: Vec<cqueue::Entry> = pr.completion().map(Into::into).collect();
        for cqe in cqes {
            if cqe.user_data() == 0x1 {
                poll_q = true;
            }
            if cqe.user_data() == 0x2 {
                poll_ctrl = true;
            }
        }

        ublk_process_queue_io(exe, q, 0)?;
        let entry =
            crate::ctrl::with_ctrl_ring_mut_internal!(|ring: &mut IoUring<squeue::Entry128>| {
                ublk_try_reap_cqe(ring, 0)
            });
        if let Some(cqe) = entry {
            ublk_wake_task(cqe.user_data(), &cqe);
            while exe.try_tick() {}
        }
    }
    //PollAdd will be canceled automatically

    Ok(())
}

/// Abstract uring task runner that doesn't depend on specific async executor
///
/// # Arguments:
///
/// * `q`: UblkQueue instance
/// * `run_ops`: Closure to run executor operations (replaces `while exe.try_tick() {}`)
/// * `is_done`: Closure to check if all tasks are finished (replaces task checking)
/// * `poll_uring`: Async closure for uring polling logic - returns bool indicating timeout
/// * `reap_event_ops`: Closure to handle CQE reaping operations - receives timeout bool
///
/// This API abstracts the common uring event handling pattern from handle_uring_events(),
/// making it executor-agnostic and more flexible for different use cases.
///
/// # Examples:
///
/// ```no_run
/// use libublk::{run_uring_tasks, UblkError, ublk_reap_events_with_handler};
/// use libublk::uring_async::ublk_wake_task;
/// use libublk::io::with_queue_ring_mut;
///
/// async fn example_usage(q: &libublk::io::UblkQueue<'_>, exe: &smol::LocalExecutor<'_>, tasks: Vec<smol::Task<()>>) -> Result<(), UblkError> {
///     // Basic usage with smol executor
///     let run_ops = || {
///         while exe.try_tick() {}
///     };
///     let is_done = || tasks.iter().all(|task| task.is_finished());
///     let poll_uring = || async { Ok(false) }; // Simplified for example - no timeout
///     let reap_event_ops = |poll_timeout| {
///         with_queue_ring_mut(q, |r| {
///             ublk_reap_events_with_handler(r, |cqe| {
///                 ublk_wake_task(cqe.user_data(), cqe);
///             })
///         })
///     };
///
///     run_uring_tasks(poll_uring, reap_event_ops, run_ops, is_done).await?;
///     Ok(())
/// }
///
/// async fn example_custom_polling(q: &libublk::io::UblkQueue<'_>) -> Result<(), UblkError> {
///     // Alternative: Custom polling with async file
///     let run_ops = || {};
///     let is_done = || true; // Example condition
///     let poll_uring = || async {
///         libublk::io::with_queue_ring_mut(q, |r| r.submit_and_wait(0))?;
///         Ok(false) // Return false for no timeout
///     };
///     let reap_event_ops = |poll_timeout| {
///         with_queue_ring_mut(q, |r| {
///             ublk_reap_events_with_handler(r, |cqe| {
///                 ublk_wake_task(cqe.user_data(), cqe);
///             })
///         })
///     };
///     run_uring_tasks(poll_uring, reap_event_ops, run_ops, is_done).await?;
///     Ok(())
/// }
/// ```
pub async fn run_uring_tasks<R, I, P, F, W>(
    mut poll_uring: P,
    reap_event_ops: W,
    run_ops: R,
    is_done: I,
) -> Result<(), UblkError>
where
    R: Fn(),
    I: Fn() -> bool,
    P: FnMut() -> F,
    F: std::future::Future<Output = Result<bool, UblkError>>,
    W: Fn(bool) -> Result<bool, UblkError>,
{
    run_ops();
    loop {
        let (poll_timeout, failed) = match poll_uring().await {
            Ok(t) => (t, false),
            _ => (false, true),
        };

        let aborted = reap_event_ops(poll_timeout)?;
        run_ops();

        if (aborted || failed) && is_done() {
            break;
        }
    }
    Ok(())
}

/// Reap completion queue entries and handle them with a custom closure
pub fn ublk_reap_events_with_handler<T, F>(
    ring: &mut io_uring::IoUring<T>,
    mut cqe_handler: F,
) -> Result<bool, UblkError>
where
    T: io_uring::squeue::EntryMarker,
    F: FnMut(&io_uring::cqueue::Entry),
{
    let mut aborted = false;
    loop {
        match ring.completion().next() {
            Some(cqe) => {
                cqe_handler(&cqe);
                if cqe.result() == crate::sys::UBLK_IO_RES_ABORT {
                    aborted = true;
                }
            }
            _ => break,
        };
    }
    Ok(aborted)
}

pub fn ublk_reap_io_events<F>(waker_ops: F) -> Result<bool, UblkError>
where
    F: FnMut(&io_uring::cqueue::Entry),
{
    crate::io::with_queue_ring_mut_internal!(|r: &mut IoUring<squeue::Entry>| {
        ublk_reap_events_with_handler(r, waker_ops)
    })
}

/// Reap completion queue entries with queue state update and idle management
///
/// This function combines the basic functionality of `ublk_reap_io_events()` with
/// queue state management similar to what `flush_and_wake_io_tasks()` does.
/// It processes completion queue entries and updates the queue state by:
/// - Counting IO commands completed
/// - Detecting abort conditions
/// - Managing queue idle state based on poll timeout and timeout CQEs
/// - Calling the provided waker_ops closure for each completion
///
/// # Arguments
///
/// * `q`: UblkQueue instance
/// * `poll_timeout`: Boolean indicating if polling timeout occurred
/// * `timeout_data`: Optional timeout user_data to check for timeout CQEs
/// * `waker_ops`: Closure called for each completion queue entry
///
/// # Returns
///
/// Returns `Ok(aborted)` where `aborted` indicates if any IO command was aborted,
/// or an error if the operation failed.
pub fn ublk_reap_io_events_with_update_queue<F>(
    q: &UblkQueue<'_>,
    poll_timeout: bool,
    timeout_data: Option<u64>,
    mut waker_ops: F,
) -> Result<bool, UblkError>
where
    F: FnMut(&io_uring::cqueue::Entry),
{
    crate::io::with_queue_ring_mut_internal!(|ring: &mut IoUring<squeue::Entry>| {
        let mut cmd_cnt = 0u32;
        let mut aborted = false;
        let mut has_timeout = poll_timeout;

        // Builtin closure for counting commands and detecting aborts and timeouts
        let builtin_closure = |cqe: &io_uring::cqueue::Entry| {
            let user_data = cqe.user_data();

            // Check if this is a timeout CQE
            if let Some(timeout_user_data) = timeout_data {
                log::debug!("Timeout CQE received, result: {}", cqe.result());
                if user_data == timeout_user_data && cqe.result() == -libc::ETIME {
                    has_timeout = true;
                } else {
                    has_timeout = false;
                }
            } else {
                has_timeout = false;
            }

            // Count IO commands and check for abort
            if crate::io::UblkIOCtx::is_io_command(user_data) {
                cmd_cnt += 1;
                if cqe.result() == crate::sys::UBLK_IO_RES_ABORT {
                    aborted = true;
                }
            }

            // Call the passed waker_ops closure for non-timeout events
            waker_ops(cqe);
        };

        // Reap events with our combined handler
        let result = ublk_reap_events_with_handler(ring, builtin_closure);
        // Handle queue idle state based on CQE types received
        if has_timeout {
            if ring.submission().is_empty() {
                q.enter_queue_idle();
            }
        } else {
            q.exit_queue_idle();
        }

        // Update queue state if we processed any IO commands
        if cmd_cnt > 0 {
            q.update_state_batch(cmd_cnt, aborted);
        }

        result
    })
}

/// Wait and handle I/O events for a ublk queue with customizable polling and completion callbacks
///
/// This function provides a high-level interface for handling I/O events on a ublk queue.
/// It uses the underlying `run_uring_tasks` infrastructure with default uring polling via
/// `with_queue_ring_mut()` and `uring_poll_fn()`.
///
/// # Parameters
/// * `q` - The UblkQueue to handle events for
/// * `idle_secs` - Timeout in seconds for uring polling (None for no timeout)
/// * `run_ops` - Closure called periodically to run operations (e.g., executor tick)
/// * `is_done` - Closure that returns true when event handling should stop
///
/// # Returns
/// Returns `Ok(())` when `is_done()` returns true, or an error if I/O operations fail.
///
/// # Example
/// ```rust,no_run
/// use libublk::uring_async::wait_and_handle_io_events;
/// use libublk::io::UblkQueue;
/// use libublk::UblkError;
///
/// async fn handle_events(q: &UblkQueue<'_>) -> Result<(), UblkError> {
///     let run_ops = || {
///         // Run executor or other periodic operations
///     };
///     let is_done = || {
///         // Check if we should stop handling events
///         false
///     };
///
///     wait_and_handle_io_events(q, Some(20), run_ops, is_done).await
/// }
/// ```
pub async fn wait_and_handle_io_events<R, I>(
    q: &UblkQueue<'_>,
    idle_secs: Option<u64>,
    run_ops: R,
    is_done: I,
) -> Result<(), UblkError>
where
    R: Fn(),
    I: Fn() -> bool,
{
    // Use default uring polling (no smol::Async)
    let poll_uring = || async {
        let timeout = idle_secs.map(|secs| io_uring::types::Timespec::new().sec(secs));
        uring_poll_io_fn::<io_uring::squeue::Entry>(q, timeout, 1)
    };

    let reap_event = |poll_timeout| {
        ublk_reap_io_events_with_update_queue(q, poll_timeout, None, |cqe| {
            ublk_wake_task(cqe.user_data(), cqe)
        })
    };

    run_uring_tasks(poll_uring, reap_event, run_ops, is_done).await
}

pub fn uring_poll_fn<T>(
    r: &mut io_uring::IoUring<T>,
    timeout: Option<io_uring::types::Timespec>,
    to_wait: usize,
) -> Result<bool, UblkError>
where
    T: io_uring::squeue::EntryMarker,
{
    let ret = if let Some(ts) = timeout {
        let args = io_uring::types::SubmitArgs::new().timespec(&ts);
        r.submitter().submit_with_args(to_wait, &args)
    } else {
        r.submit_and_wait(to_wait)
    };

    match ret {
        Err(ref err) if err.raw_os_error() == Some(libc::ETIME) => Ok(true),
        Err(err) => Err(UblkError::IOError(err)),
        Ok(_) => Ok(false),
    }
}

pub fn uring_poll_io_fn<T>(
    q: &UblkQueue,
    timeout: Option<io_uring::types::Timespec>,
    to_wait: usize,
) -> Result<bool, UblkError>
where
    T: io_uring::squeue::EntryMarker,
{
    crate::io::with_queue_ring_mut_internal!(|r: &mut IoUring<squeue::Entry>| {
        let stopping = q.is_stopping();
        let res = uring_poll_fn(r, timeout, if stopping { 0 } else { to_wait });
        if stopping {
            Err(UblkError::QueueIsDown)
        } else {
            res
        }
    })
}

/// Wait and handle incoming IO command
///
/// # Arguments:
///
/// * `q`: UblkQueue instance
/// * `exe`: Local async Executor
///
/// Called in queue context. won't return unless error is observed.
/// Wait and handle any incoming cqe until queue is down.
///
/// This should be the only foreground thing done in queue thread.
pub fn ublk_wait_and_handle_ios(exe: &smol::LocalExecutor, q: &UblkQueue) {
    loop {
        while exe.try_tick() {}
        if q.flush_and_wake_io_tasks(|data, cqe, _| ublk_wake_task(data, cqe), 1)
            .is_err()
        {
            break;
        }
    }
    q.unregister_io_bufs();
}
