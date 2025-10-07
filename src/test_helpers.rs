#![cfg(test)]

//! Shared test utilities for async device testing
//!
//! This module provides common async test functions that can be shared
//! between different test modules, particularly for testing ublk device
//! creation and I/O operations.

use crate::ctrl::UblkCtrlBuilder;
use crate::io::{UblkDev, UblkQueue};
use crate::uring_async::{ublk_reap_events_with_handler, ublk_wake_task};
use crate::{UblkError, UblkFlags};
use io_uring::{squeue, IoUring};
use std::rc::Rc;

#[ctor::ctor]
fn init_logger() {
    let _ = env_logger::builder()
        .format_target(false)
        .format_timestamp(None)
        .is_test(true)
        .try_init();
}

/// Async I/O function for testing null device operations
///
/// This function simulates the I/O operations of a null device,
/// accepting all writes and returning zeros for reads.
pub(crate) async fn io_async_fn(tag: u16, q: &UblkQueue<'_>) -> Result<(), UblkError> {
    use crate::helpers::IoBuf;
    use crate::BufDesc;

    let buf = IoBuf::<u8>::new(q.dev.dev_info.max_io_buf_bytes as usize);
    let _buf = Some(buf);
    let iod = q.get_iod(tag);
    let buf_desc = BufDesc::Slice(_buf.as_ref().unwrap().as_slice());

    // Submit initial prep command and handle any errors (including queue down)
    // The IoBuf is automatically registered
    q.submit_io_prep_cmd(tag, buf_desc.clone(), 0, _buf.as_ref())
        .await?;

    loop {
        let res = (iod.nr_sectors << 9) as i32;
        // Any error (including QueueIsDown) will break the loop
        q.submit_io_commit_cmd(tag, buf_desc.clone(), res).await?;
    }
}

/// Queue async function for spawning I/O tasks
///
/// This function creates async tasks for each tag in the queue depth,
/// simulating concurrent I/O operations.
pub(crate) fn q_async_fn<'a>(
    exe: &smol::LocalExecutor<'a>,
    q_rc: &Rc<UblkQueue<'a>>,
    depth: u16,
    f_vec: &mut Vec<smol::Task<()>>,
) {
    for tag in 0..depth as u16 {
        let q = q_rc.clone();
        f_vec.push(exe.spawn(async move {
            if let Err(e) = io_async_fn(tag, &q).await {
                match e {
                    UblkError::QueueIsDown => {
                        // Queue down is expected during shutdown, don't log as error
                    }
                    _ => {
                        log::debug!("io_async_fn failed for tag {}: {}", tag, e);
                    }
                }
            }
        }));
    }
}

/// Device handler for async testing
///
/// Creates and manages a test ublk device with the specified flags.
/// This is useful for testing different device configurations.
pub(crate) async fn device_handler_async(dev_flags: UblkFlags) -> Result<(), UblkError> {
    let ctrl = UblkCtrlBuilder::default()
        .name("test_async")
        .dev_flags(dev_flags)
        .depth(8)
        .build_async()
        .await
        .unwrap();

    let tgt_init = |dev: &mut UblkDev| {
        dev.set_default_params(250_u64 << 30);
        Ok(())
    };
    // Use the new async method directly
    let dev_arc = &std::sync::Arc::new(UblkDev::new_async(ctrl.get_name(), tgt_init, &ctrl)?);
    let dev = dev_arc.clone();
    let dev_id = dev.dev_info.dev_id;
    assert!(dev_arc.dev_info.nr_hw_queues == 1);

    // Todo: support to handle multiple queues in one thread context
    let qh = std::thread::spawn(move || {
        let q_rc = Rc::new(UblkQueue::new(0 as u16, &dev).unwrap());
        let q = q_rc.clone();
        let exe_rc = Rc::new(smol::LocalExecutor::new());
        let exe = exe_rc.clone();
        let mut f_vec: Vec<smol::Task<()>> = Vec::new();

        if dev_flags.contains(UblkFlags::UBLK_DEV_F_MLOCK_IO_BUFFER) {
            q.mark_mlock_failed();
        }

        q_async_fn(&exe, &q, dev.dev_info.queue_depth as u16, &mut f_vec);

        smol::block_on(exe_rc.run(async move {
            let run_ops = || while exe.try_tick() {};
            let done = || f_vec.iter().all(|task| task.is_finished());

            if let Err(e) = crate::wait_and_handle_io_events(&q_rc, Some(20), run_ops, done).await {
                log::error!("handle_uring_events failed: {}", e);
            }
        }));
    });

    // Avoid to leak device
    if let Err(_) = ctrl.start_dev_async(dev_arc).await {
        log::warn!("device_handler_async: fail to start device(async)");
    }

    ctrl.dump_async().await?;
    ctrl.kill_dev_async().await?;

    // async/await needs to delete device by itself, otherwise we
    // may hang in Drop() of UblkCtrlInner.
    ctrl.del_dev_async_await().await?;

    if let Err(e) = smol::unblock(move || qh.join()).await {
        eprintln!("dev-{} join queue thread failed {:?}", dev_id, e);
    }
    Ok(())
}

/// Block on all tasks in the executor until they are finished
///
/// Utility function for managing task execution in tests.
/// Implemented using run_uring_tasks(), ublk_reap_events_with_handler() and uring_poll_fn().
pub(crate) fn ublk_join_tasks<T>(
    exe: &smol::LocalExecutor,
    tasks: Vec<smol::Task<T>>,
) -> Result<(), UblkError> {
    //support 64 devices
    crate::ctrl::init_ctrl_task_ring_default(64 * 2).unwrap();

    smol::block_on(async {
        let poll_uring = || async {
            crate::ctrl::with_ctrl_ring_mut_internal!(|r: &mut IoUring<squeue::Entry128>| {
                crate::uring_async::uring_poll_fn(r, None, 0)
            })
        };
        let reap_event = |_poll_timeout| {
            crate::ctrl::with_ctrl_ring_mut_internal!(|r: &mut IoUring<squeue::Entry128>| {
                ublk_reap_events_with_handler(r, |cqe| {
                    ublk_wake_task(cqe.user_data(), cqe);
                })
            })?;
            Ok(true)
        };
        let run_ops = || while exe.try_tick() {};
        let is_done = || tasks.iter().all(|task| task.is_finished());

        crate::uring_async::run_uring_tasks(poll_uring, reap_event, run_ops, is_done).await
    })
}

/// Block on all I/O tasks in the executor until they are finished
///
/// Similar to ublk_join_tasks() but uses QUEUE_RING for I/O operations
/// instead of control ring operations.
pub(crate) fn ublk_join_io_tasks<T>(
    exe: &smol::LocalExecutor,
    tasks: Vec<smol::Task<T>>,
) -> Result<(), UblkError> {
    // Initialize task ring for I/O operations
    crate::io::init_task_ring_default(64, 64)?;

    smol::block_on(async {
        let poll_uring = || async {
            crate::io::with_queue_ring_mut_internal!(|r: &mut IoUring<squeue::Entry>| {
                crate::uring_async::uring_poll_fn(r, None, 0)
            })
        };
        let reap_event = |_poll_timeout| {
            crate::io::with_queue_ring_mut_internal!(|r: &mut IoUring<squeue::Entry>| {
                ublk_reap_events_with_handler(r, |cqe| {
                    ublk_wake_task(cqe.user_data(), cqe);
                })
            })?;
            Ok(true)
        };
        let run_ops = || while exe.try_tick() {};
        let is_done = || tasks.iter().all(|task| task.is_finished());

        crate::uring_async::run_uring_tasks(poll_uring, reap_event, run_ops, is_done).await
    })
}
