#![cfg(test)]

//! Shared test utilities for async device testing
//!
//! This module provides common async test functions that can be shared
//! between different test modules, particularly for testing ublk device
//! creation and I/O operations.

use crate::ctrl::UblkCtrlBuilder;
use crate::io::{UblkDev, UblkQueue};
use crate::runtime::UblkRuntime;
use crate::{UblkError, UblkFlags};
use std::future::Future;
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
pub(crate) async fn io_async_fn(tag: u16, q: &UblkQueue) -> Result<(), UblkError> {
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

/// Spawn one I/O task per tag on the current `LocalSet`.
pub(crate) fn q_async_fn(q_rc: &Rc<UblkQueue>, depth: u16) -> Vec<tokio::task::JoinHandle<()>> {
    (0..depth)
        .map(|tag| {
            let q = q_rc.clone();
            tokio::task::spawn_local(async move {
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
            })
        })
        .collect()
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
        let rt = UblkRuntime::new().unwrap();
        rt.block_on(async move {
            let q_rc = Rc::new(UblkQueue::new(0_u16, &dev).unwrap());

            if dev_flags.contains(UblkFlags::UBLK_DEV_F_MLOCK_IO_BUFFER) {
                q_rc.mark_mlock_failed();
            }

            for handle in q_async_fn(&q_rc, dev.dev_info.queue_depth) {
                let _ = handle.await;
            }
        });
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

    if let Err(e) = tokio::task::spawn_blocking(move || qh.join())
        .await
        .unwrap()
    {
        eprintln!("dev-{} join queue thread failed {:?}", dev_id, e);
    }
    Ok(())
}

/// Run a control-plane future to completion on a fresh `UblkRuntime`,
/// with the thread-local control ring initialized first.
pub(crate) fn ublk_block_on_ctrl<F: Future>(fut: F) -> F::Output {
    //support 64 devices
    crate::ctrl::init_ctrl_task_ring_default(64 * 2).unwrap();
    UblkRuntime::new().unwrap().block_on(fut)
}
