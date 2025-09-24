use io_uring::IoUring;
use libublk::ctrl::UblkCtrl;
use libublk::ctrl_async::UblkCtrlAsync;
///! # Example of ramdisk
///
/// Serves for covering recovery test[`test_ublk_ramdisk_recovery`],
///
/// Build ramdisk target in single-thread conext, and the same technique
/// will be extended to create multiple devices in single thread
///
use libublk::helpers::IoBuf;
use libublk::io::{UblkDev, UblkQueue};
use libublk::uring_async::{run_uring_tasks, ublk_reap_events_with_handler, ublk_wake_task};
use libublk::{BufDesc, UblkError, UblkFlags};
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd};
use std::rc::Rc;
use std::sync::Arc;

/// Handle I/O operations using safe slice-based memory operations.
///
/// This function demonstrates how slice operations provide memory safety
/// benefits over raw pointer manipulation:
/// - Automatic bounds checking prevents buffer overflows
/// - Compile-time lifetime verification ensures memory safety
/// - No unsafe pointer arithmetic required
/// - Rust's ownership system prevents use-after-free errors
fn handle_io(q: &UblkQueue, tag: u16, io_buf: &mut [u8], ramdisk_storage: &mut [u8]) -> i32 {
    let iod = q.get_iod(tag);
    let off = (iod.start_sector << 9) as usize; // Convert to usize for slice indexing
    let bytes = (iod.nr_sectors << 9) as usize; // Convert to usize for slice operations
    let op = iod.op_flags & 0xff;

    // Bounds checking: Ensure the operation doesn't exceed storage bounds
    // This slice-based approach automatically prevents buffer overflows
    // that could occur with raw pointer arithmetic and libc::memcpy
    if off.saturating_add(bytes) > ramdisk_storage.len() {
        return -libc::EINVAL;
    }

    // Ensure I/O buffer has sufficient capacity for the operation
    // Slice bounds checking prevents reading/writing beyond buffer limits
    if bytes > io_buf.len() {
        return -libc::EINVAL;
    }

    match op {
        libublk::sys::UBLK_IO_OP_READ => {
            // Safe slice-to-slice copy operation replaces unsafe libc::memcpy
            // copy_from_slice() automatically:
            // - Verifies source and destination have compatible lengths
            // - Performs bounds checking on both slices
            // - Prevents buffer overflows through compile-time guarantees
            let src = &ramdisk_storage[off..off + bytes];
            let dst = &mut io_buf[..bytes];
            dst.copy_from_slice(src);
        }
        libublk::sys::UBLK_IO_OP_WRITE => {
            // Safe slice-to-slice copy operation replaces unsafe libc::memcpy
            // This approach eliminates common memory safety issues:
            // - No risk of writing beyond storage boundaries
            // - Automatic length verification prevents partial writes to invalid memory
            // - Slice bounds are verified at compile-time and runtime
            let src = &io_buf[..bytes];
            let dst = &mut ramdisk_storage[off..off + bytes];
            dst.copy_from_slice(src);
        }
        libublk::sys::UBLK_IO_OP_FLUSH => {
            // Flush operation requires no memory copying
        }
        _ => {
            return -libc::EINVAL;
        }
    }

    bytes as i32
}

async fn io_task(q: &UblkQueue<'_>, tag: u16, ramdisk_storage: &mut [u8]) -> Result<(), UblkError> {
    let buf_size = q.dev.dev_info.max_io_buf_bytes as usize;

    // Use IoBuf for safe I/O buffer management with automatic memory alignment
    // IoBuf provides slice-based access through Deref/DerefMut traits
    let mut buffer = IoBuf::<u8>::new(buf_size);

    // Submit initial prep command - any error will exit the function
    // The IoBuf is automatically registered
    q.submit_io_prep_cmd(tag, BufDesc::Slice(buffer.as_slice()), 0, Some(&buffer))
        .await?;

    loop {
        // Use safe slice access for memory operations
        // IoBuf's as_mut_slice() provides bounds-checked access
        // This eliminates the need for unsafe pointer operations
        let io_slice = buffer.as_mut_slice();
        let res = handle_io(&q, tag, io_slice, ramdisk_storage);

        // Any error (including QueueIsDown) will break the loop by exiting the function
        q.submit_io_commit_cmd(tag, BufDesc::Slice(buffer.as_slice()), res)
            .await?;
    }
}

fn write_dev_id(ctrl: &UblkCtrlAsync, efd: i32) -> Result<i32, Error> {
    // Can't write 0 to eventfd file, otherwise the read() side may
    // not be waken up
    let dev_id = ctrl.dev_info().dev_id as u64 + 1;
    let bytes = dev_id.to_le_bytes();

    nix::unistd::write(efd, &bytes)?;
    Ok(0)
}

fn read_dev_id(efd: i32) -> Result<i32, Error> {
    let mut buffer = [0; 8];

    let bytes_read = nix::unistd::read(efd, &mut buffer)?;
    if bytes_read == 0 {
        return Err(Error::new(ErrorKind::InvalidInput, "invalid device id"));
    }
    return Ok((i64::from_le_bytes(buffer) - 1) as i32);
}

/// Poll and handle both QUEUE_RING and CTRL_URING concurrently
async fn poll_and_handle_rings<R, I>(
    run_ops: R,
    is_done: I,
    check_done: bool,
) -> Result<(), UblkError>
where
    R: Fn(),
    I: Fn() -> bool,
{
    // Helper to create async wrapper for file descriptor
    let create_async_wrapper = |fd: i32| -> Result<smol::Async<File>, UblkError> {
        let file = unsafe { File::from_raw_fd(fd) };
        smol::Async::new(file).map_err(|_| UblkError::OtherError(-libc::EINVAL))
    };

    // Get file descriptors and create async wrappers
    let queue_fd = libublk::io::with_task_io_ring(|ring| ring.as_raw_fd());
    let ctrl_fd = libublk::ctrl::with_ctrl_ring(|ring| ring.as_raw_fd());
    let async_queue = create_async_wrapper(queue_fd)?;
    let async_ctrl = create_async_wrapper(ctrl_fd)?;

    // Polling function for both rings
    let poll_both_rings = || async {
        // Submit and wait on both rings
        libublk::io::with_task_io_ring_mut(|ring| ring.submit_and_wait(0))?;
        libublk::ctrl::with_ctrl_ring_mut(|ring| ring.submit_and_wait(0))?;

        // Wait for either ring to become readable
        smol::future::race(async_queue.readable(), async_ctrl.readable())
            .await
            .map(|_| false) // No timeout
            .map_err(UblkError::IOError)
    };

    // Helper to handle events from a ring
    let handle_ring_events = |cqe: &io_uring::cqueue::Entry| {
        ublk_wake_task(cqe.user_data(), cqe);
        cqe.result() == libublk::sys::UBLK_IO_RES_ABORT
    };

    // Event reaping function for both rings
    let reap_events = |_poll_timeout| {
        let mut aborted = check_done;

        // Reap events from both rings
        let queue_result = libublk::io::with_task_io_ring_mut(|ring| {
            ublk_reap_events_with_handler(ring, |cqe| {
                if handle_ring_events(cqe) {
                    aborted = true;
                }
            })
        });

        let ctrl_result = libublk::ctrl::with_ctrl_ring_mut(|ring| {
            ublk_reap_events_with_handler(ring, |cqe| {
                if handle_ring_events(cqe) {
                    aborted = true;
                }
            })
        });

        queue_result.and(ctrl_result).map(|_| aborted)
    };

    run_uring_tasks(poll_both_rings, reap_events, run_ops, is_done).await?;

    // Prevent file descriptors from being closed when async wrappers are dropped
    let _ = async_queue.into_inner().map(|f| {
        use std::os::fd::IntoRawFd;
        f.into_raw_fd()
    });
    let _ = async_ctrl.into_inner().map(|f| {
        use std::os::fd::IntoRawFd;
        f.into_raw_fd()
    });

    Ok(())
}

/// Create UblkCtrl using UblkCtrlBuilder::build_async() with smol executor
///
/// This function demonstrates how to create a UblkCtrl device using the async builder
/// pattern with a smol::LocalExecutor. It uses the poll_and_handle_rings pattern
/// to handle both control and I/O operations asynchronously.
///
/// # Arguments
/// * `executor` - Reference to smol::LocalExecutor for task execution
/// * `dev_id` - Device ID to assign (-1 for auto-allocation)
/// * `dev_flags` - Device flags to configure the device
///
/// # Returns
/// Result containing the created UblkCtrlAsync instance or an error
fn create_ublk_ctrl_async(
    exe_rc: Rc<smol::LocalExecutor>,
    dev_id: i32,
    dev_flags: UblkFlags,
) -> Result<UblkCtrlAsync, UblkError> {
    let ctrl_done = Rc::new(std::cell::RefCell::new(false));
    let ctrl_done_clone = ctrl_done.clone();
    let exe = exe_rc.clone();

    let ctrl_task = exe.spawn(async move {
        let result = libublk::ctrl::UblkCtrlBuilder::default()
            .name("async_ramdisk")
            .id(dev_id)
            .nr_queues(1_u16)
            .depth(128_u16)
            .dev_flags(dev_flags)
            .ctrl_flags(libublk::sys::UBLK_F_USER_RECOVERY as u64)
            .build_async()
            .await;
        *ctrl_done_clone.borrow_mut() = true;
        result
    });

    let exe2 = exe_rc.clone();
    let event_task = exe.spawn(async move {
        let run_ops = || {
            while exe2.try_tick() {}
        };
        let is_done = || *ctrl_done.borrow();
        poll_and_handle_rings(run_ops, is_done, true).await
    });

    smol::block_on(exe_rc.run(async {
        let (ctrl_result, _) = futures::join!(ctrl_task, event_task);
        ctrl_result
    }))
}

///run this ramdisk ublk daemon completely in single context with
///async control command, no need Rust async any more
fn rd_add_dev(dev_id: i32, ramdisk_storage: &mut [u8], size: u64, for_add: bool, efd: i32) {
    let dev_flags = if for_add {
        UblkFlags::UBLK_DEV_F_ADD_DEV
    } else {
        UblkFlags::UBLK_DEV_F_RECOVER_DEV
    };

    let _ = libublk::io::ublk_init_task_ring(|cell| {
        use std::cell::RefCell;
        if cell.get().is_none() {
            let ring = IoUring::<io_uring::squeue::Entry, io_uring::cqueue::Entry>::builder()
                .setup_cqsize(128)
                .setup_coop_taskrun()
                .build(128)
                .map_err(UblkError::IOError)?;

            cell.set(RefCell::new(ring))
                .map_err(|_| UblkError::OtherError(-libc::EEXIST))?;
        }
        Ok(())
    });

    // Create executor temporarily for control creation
    let exec_rc = Rc::new(smol::LocalExecutor::new());
    let ctrl = Rc::new(create_ublk_ctrl_async(exec_rc, dev_id, dev_flags).unwrap());

    log::info!("device is created:: {:?}", &ctrl.dev_info());

    let tgt_init = |dev: &mut UblkDev| {
        dev.set_default_params(size);
        Ok(())
    };
    let dev_rc = Arc::new(UblkDev::new_async(ctrl.get_name(), tgt_init, &ctrl).unwrap());
    let dev_clone = dev_rc.clone();
    let q_rc = Rc::new(UblkQueue::new(0, &dev_clone).unwrap());
    let exec_rc = Rc::new(smol::LocalExecutor::new());
    let exec = exec_rc.clone();

    // spawn async io tasks
    let mut f_vec = Vec::new();

    // Extract raw pointer and length for sharing across async tasks
    // This is the minimal unsafe code needed for async context sharing
    let storage_ptr = ramdisk_storage.as_mut_ptr();
    let storage_len = ramdisk_storage.len();

    for tag in 0..ctrl.dev_info().queue_depth as u16 {
        let q_clone = q_rc.clone();

        f_vec.push(exec.spawn(async move {
            // Reconstruct slice from raw pointer for each async task
            // This is safe because:
            // 1. The original ramdisk_storage buffer outlives all async tasks
            // 2. Each task operates on different regions controlled by I/O offset bounds
            // 3. The slice provides bounds checking for all operations within io_task
            let storage_slice = unsafe { std::slice::from_raw_parts_mut(storage_ptr, storage_len) };
            match io_task(&q_clone, tag, storage_slice).await {
                Err(UblkError::QueueIsDown) | Ok(_) => {}
                Err(e) => log::error!("io_task failed for tag {}: {}", tag, e),
            }
        }));
    }

    let ctrl_clone = ctrl.clone();
    let dev_clone = dev_rc.clone();
    f_vec.push(exec.spawn(async move {
        let r = ctrl_clone
            .configure_queue_async(&dev_clone, 0, unsafe { libc::gettid() })
            .await
            .unwrap();
        if r >= 0 {
            ctrl_clone.start_dev_async(&dev_clone).await.unwrap();
            write_dev_id(&ctrl_clone, efd).expect("Failed to write dev_id");
        }
    }));
    smol::block_on(exec_rc.run(async move {
        let run_ops = || while exec.try_tick() {};
        let done = || f_vec.iter().all(|task| task.is_finished());

        if let Err(e) = poll_and_handle_rings(run_ops, done, false).await {
            log::error!("poll_and_handle_rings failed: {}", e);
        }
    }));
}

fn rd_get_device_size(ctrl: &UblkCtrl) -> u64 {
    if let Ok(tgt) = ctrl.get_target_from_json() {
        tgt.dev_size
    } else {
        0
    }
}

fn test_add(recover: usize) {
    let dev_id: i32 = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "-1".to_string())
        .parse::<i32>()
        .unwrap();
    let s = std::env::args().nth(3).unwrap_or_else(|| "32".to_string());
    let mb = s.parse::<u64>().unwrap();
    let efd = nix::sys::eventfd::eventfd(0, nix::sys::eventfd::EfdFlags::empty()).unwrap();

    let daemonize = daemonize::Daemonize::new()
        .stdout(daemonize::Stdio::devnull())
        .stderr(daemonize::Stdio::devnull());
    match daemonize.execute() {
        daemonize::Outcome::Child(Ok(_)) => {
            let mut size = (mb << 20) as u64;

            if recover > 0 {
                assert!(dev_id >= 0);
                let ctrl = UblkCtrl::new_simple(dev_id).unwrap();
                size = rd_get_device_size(&ctrl);

                ctrl.start_user_recover().unwrap();
            }

            // Create ramdisk storage using IoBuf for proper alignment and memory management
            // IoBuf provides safe slice access while maintaining required memory alignment
            let mut ramdisk_buf = libublk::helpers::IoBuf::<u8>::new(size as usize);

            // Zero-initialize the ramdisk storage for consistent behavior
            // Using safe slice operations instead of unsafe memory manipulation
            ramdisk_buf.zero_buf();

            // Get mutable slice for safe operations within rd_add_dev
            let storage_slice = ramdisk_buf.as_mut_slice();
            rd_add_dev(dev_id, storage_slice, size, recover == 0, efd);
        }
        daemonize::Outcome::Parent(Ok(_)) => match read_dev_id(efd) {
            Ok(id) => UblkCtrl::new_simple(id).unwrap().dump(),
            _ => eprintln!("Failed to add ublk device"),
        },
        _ => panic!(),
    }
}

fn test_del(async_del: bool) {
    let s = std::env::args().nth(2).unwrap_or_else(|| "0".to_string());
    let dev_id = s.parse::<i32>().unwrap();
    let ctrl = UblkCtrl::new_simple(dev_id as i32).unwrap();

    if !async_del {
        ctrl.del_dev().expect("fail to del_dev_async");
    } else {
        ctrl.del_dev_async().expect("fail to del_dev_async");
    }
}

fn main() {
    env_logger::builder()
        .format_target(false)
        .format_timestamp(None)
        .init();
    if let Some(cmd) = std::env::args().nth(1) {
        match cmd.as_str() {
            "add" => test_add(0),
            "recover" => test_add(1),
            "del" => test_del(false),
            "del_async" => test_del(true),
            _ => todo!(),
        }
    }
}
