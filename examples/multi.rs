use async_lock::{Mutex, Semaphore};
use clap::{Arg, ArgAction, Command};
use libublk::helpers::IoBuf;
use libublk::io::{UblkDev, UblkQueue};
use libublk::multi_queue::MultiQueueManager;
use libublk::uring_async::{ublk_block_on_ctrl_tasks, ublk_handle_ios_in_current_thread};
use libublk::{ctrl::UblkCtrl, ctrl::UblkCtrlBuilder, BufDesc, UblkError, UblkFlags};
use std::rc::Rc;
use std::sync::Arc;

/// Structure to hold shared data for device handler operations
struct DeviceHandlerContext {
    device_index: u16,
    nr_queues: u16,
    nr_devices: u16,
    depth: u16,
    zero_copy: bool,
    devices: Arc<Mutex<Vec<Arc<UblkDev>>>>,
    thread_infos: Arc<Mutex<Option<Vec<(u16, libc::pthread_t, i32)>>>>,
    semaphore_ready: Arc<Semaphore>,
    semaphore_done: Arc<Semaphore>,
    eventfd: i32,
}

#[inline]
async fn __handle_queue_tag_async_null(q: Rc<UblkQueue<'_>>, tag: u16, buf: Option<&IoBuf<u8>>) {
    let mut cmd_op = libublk::sys::UBLK_U_IO_FETCH_REQ;
    let mut res = 0;
    let auto_buf_reg = libublk::sys::ublk_auto_buf_reg {
        index: q.translate_buffer_index(tag),
        flags: libublk::sys::UBLK_AUTO_BUF_REG_FALLBACK as u8,
        ..Default::default()
    };
    let buf_desc = match buf {
        Some(io_buf) => {
            q.register_io_buf(tag, &io_buf);
            BufDesc::Slice(io_buf.as_slice())
        }
        _ => BufDesc::AutoReg(auto_buf_reg),
    };
    let iod = q.get_iod(tag);

    loop {
        let cmd_res = q
            .submit_io_cmd_unified(tag, cmd_op, buf_desc.clone(), res)
            .unwrap()
            .await;
        if cmd_res == libublk::sys::UBLK_IO_RES_ABORT {
            break;
        }

        res = (iod.nr_sectors << 9) as i32;
        cmd_op = libublk::sys::UBLK_U_IO_COMMIT_AND_FETCH_REQ;
    }
}

async fn handle_queue_tag_async_null(q: Rc<UblkQueue<'_>>, tag: u16) {
    if q.support_auto_buf_zc() {
        __handle_queue_tag_async_null(q, tag, None).await
    } else {
        let buf = Some(IoBuf::<u8>::new(q.dev.dev_info.max_io_buf_bytes as usize));
        __handle_queue_tag_async_null(q, tag, buf.as_ref()).await
    }
}

fn q_async_fn<'a>(
    exe: &smol::LocalExecutor<'a>,
    q_rc: &Rc<UblkQueue<'a>>,
    depth: u16,
    f_vec: &mut Vec<smol::Task<()>>,
) {
    for tag in 0..depth as u16 {
        let q = q_rc.clone();
        f_vec.push(exe.spawn(async move {
            handle_queue_tag_async_null(q, tag).await;
        }));
    }
}

/// Create a new ublk device with the given parameters
async fn create_device(ctx: &DeviceHandlerContext) -> Result<(UblkCtrl, Arc<UblkDev>), UblkError> {
    log::info!(
        "Creating device {} with zero_copy: {}",
        ctx.device_index,
        ctx.zero_copy
    );
    let device_name = format!("test_async_{}", ctx.device_index);
    let ctrl = UblkCtrlBuilder::default()
        .name(&device_name)
        .ctrl_flags(if ctx.zero_copy {
            (libublk::sys::UBLK_F_AUTO_BUF_REG | libublk::sys::UBLK_F_SUPPORT_ZERO_COPY) as u64
        } else {
            0
        })
        .dev_flags(
            UblkFlags::UBLK_DEV_F_ADD_DEV
                | UblkFlags::UBLK_CTRL_ASYNC_AWAIT
                | UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY,
        )
        .depth(ctx.depth)
        .nr_queues(ctx.nr_queues)
        .build_async()
        .await
        .unwrap();

    let tgt_init = |dev: &mut UblkDev| {
        dev.set_default_params(250_u64 << 30);
        Ok(())
    };
    let dev_arc = Arc::new(UblkDev::new(ctrl.get_name(), tgt_init, &ctrl)?);

    Ok((ctrl, dev_arc))
}

/// Add device to shared storage and check if this is the main task
async fn register_device_and_check_main_task(
    device_index: u16,
    nr_devices: u16,
    dev_arc: Arc<UblkDev>,
    devices: Arc<Mutex<Vec<Arc<UblkDev>>>>,
) -> bool {
    let mut devices_guard = devices.lock().await;
    devices_guard.push(dev_arc);
    let device_count = devices_guard.len();
    log::info!(
        "Device {} added to shared storage, total devices: {}",
        device_index,
        device_count
    );

    device_count == nr_devices as usize
}

/// Queue thread function that handles all queues with the same qid across all devices
fn queue_thread_fn(
    qid: u16,
    devices: Arc<Mutex<Vec<Arc<UblkDev>>>>,
    tx: std::sync::mpsc::Sender<(u16, libc::pthread_t, i32)>,
) {
    log::info!("Queue thread {} starting", qid);

    // Wait briefly for all devices to be ready
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Get devices and keep them alive for the entire thread duration
    let devices_and_depth = smol::block_on(async {
        loop {
            let devices_guard = devices.lock().await;
            if devices_guard.len() > 0 {
                let devices = devices_guard.clone();
                let depth = devices[0].dev_info.queue_depth;
                return (devices, depth);
            }
            drop(devices_guard);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });

    let (devices_vec, queue_depth) = devices_and_depth;

    // Create queue manager for this thread
    let mut manager = MultiQueueManager::new();
    let exe = smol::LocalExecutor::new();
    let mut f_vec: Vec<smol::Task<()>> = Vec::new();

    for (dev_idx, device) in devices_vec.iter().enumerate() {
        log::info!("Creating queue {} for device {}", qid, dev_idx);
        if let Err(e) = manager.create_queue(qid, device) {
            log::error!(
                "Failed to create queue {} for device {}: {:?}",
                qid,
                dev_idx,
                e
            );
        }
    }

    // Register resources
    if let Err(e) = manager.register_resources() {
        log::error!("Failed to register resources for queue {}: {:?}", qid, e);
        return;
    }

    // Initialize thread and send info back
    let (pthread_handle, tid) = UblkCtrl::init_queue_thread();
    if let Err(e) = tx.send((qid, pthread_handle, tid)) {
        log::error!("Failed to send queue thread info for queue {}: {}", qid, e);
        return;
    }

    // Add io tasks for all queues
    for q_rc in manager.values() {
        let q = q_rc.clone();
        q_async_fn(&exe, &q, queue_depth as u16, &mut f_vec);
    }

    log::info!("Queue thread {} starting IO handling", qid);
    ublk_handle_ios_in_current_thread(&manager, &exe, |_, _, _| {});
    smol::block_on(async { futures::future::join_all(f_vec).await });
    log::info!("Queue thread {} finished", qid);
}

fn setup_ring(nr_dev: u16, depth: u16) -> Result<(), UblkError> {
    let qd = depth * nr_dev;
    libublk::io::ublk_init_task_ring(|cell| {
        if cell.get().is_none() {
            let ring = io_uring::IoUring::builder()
                    .setup_cqsize(qd.into())  // Custom completion queue size
                    .setup_coop_taskrun()  // Enable cooperative task running
                    .build(qd.into())?; // Custom submission queue size
            cell.set(std::cell::RefCell::new(ring))
                .map_err(|_| libublk::UblkError::OtherError(-libc::EEXIST))?;
        }
        Ok(())
    })
}

/// Create and manage all queue threads for the main task
async fn create_and_manage_queue_threads(
    context: &DeviceHandlerContext,
) -> Result<Vec<std::thread::JoinHandle<()>>, UblkError> {
    log::info!("Main task: creating {} queue threads", context.nr_queues);

    let mut queue_thread_handles = Vec::new();
    let mut queue_channels = Vec::new();
    let nr_dev = context.nr_devices;
    let depth = context.depth;

    // Create queue threads
    for qid in 0..context.nr_queues {
        let (tx, rx) = std::sync::mpsc::channel();
        queue_channels.push(rx);

        let devices_clone = context.devices.clone();
        let handle = std::thread::spawn(move || {
            let _ = setup_ring(nr_dev, depth);
            queue_thread_fn(qid, devices_clone, tx);
        });

        queue_thread_handles.push(handle);
    }

    // Collect thread information and store in context
    let mut thread_infos = Vec::new();
    for (qid, rx) in queue_channels.into_iter().enumerate() {
        match rx.recv() {
            Ok((received_qid, pthread_handle, tid)) => {
                assert_eq!(qid as u16, received_qid);
                thread_infos.push((received_qid, pthread_handle, tid));
                log::info!("Collected thread info for queue {}", received_qid);
            }
            Err(e) => {
                log::error!("Failed to receive thread info for queue {}: {}", qid, e);
                return Err(UblkError::OtherError(-libc::EINVAL));
            }
        }
    }

    // Store thread infos in context for other tasks to use
    {
        let mut shared_thread_infos = context.thread_infos.lock().await;
        *shared_thread_infos = Some(thread_infos);
    }

    Ok(queue_thread_handles)
}

/// Set thread affinity for all queue threads
async fn set_queue_thread_affinity(ctrl: &UblkCtrl, context: &DeviceHandlerContext) {
    let thread_infos = {
        let shared_thread_infos = context.thread_infos.lock().await;
        shared_thread_infos.as_ref().unwrap().clone()
    };

    for (qid, pthread_handle, _) in &thread_infos {
        ctrl.set_thread_affinity_async(*qid, *pthread_handle).await;
        log::info!("Set affinity for queue thread {}", qid);
    }
}

/// Configure device queues and start the device
async fn configure_and_start_device(
    ctrl: &UblkCtrl,
    dev_arc: &Arc<UblkDev>,
    context: &DeviceHandlerContext,
) -> Result<(), UblkError> {
    let id = dev_arc.dev_info.dev_id;
    let thread_infos = {
        let shared_thread_infos = context.thread_infos.lock().await;
        shared_thread_infos.as_ref().unwrap().clone()
    };

    for (qid, _, tid) in &thread_infos {
        log::info!("Configure dev {} queue {} (tid: {})", id, qid, tid);
        if let Err(e) = ctrl.configure_queue_async(dev_arc, *qid, *tid).await {
            log::warn!("Configure queue failed for {}-{}: {:?}", id, qid, e);
        }
    }

    log::info!("Start device {}", id);
    ctrl.start_dev_async(dev_arc).await?;
    ctrl.dump_async().await?;

    Ok(())
}

/// Handle main task logic: create queue threads, configure device, and manage lifecycle
async fn handle_main_task(
    ctrl: &UblkCtrl,
    dev_arc: Arc<UblkDev>,
    context: &DeviceHandlerContext,
) -> Result<(), UblkError> {
    // Create and manage queue threads
    let queue_thread_handles = create_and_manage_queue_threads(context).await?;
    let eventfd = context.eventfd;

    // Set thread affinity
    set_queue_thread_affinity(&ctrl, context).await;

    // Signal that queue threads are ready
    context
        .semaphore_ready
        .add_permits(context.nr_devices as usize - 1);
    log::info!("Main task: signaled queue threads ready");

    // Configure and start device
    configure_and_start_device(&ctrl, &dev_arc, context).await?;

    // Wait for all queue threads to complete using smol::unblock()
    // we have to wakeup control ring by eventfd because smol::unblock()
    // is run from remote task
    log::info!("Main task: waiting for queue threads to join");
    smol::unblock(move || {
        for handle in queue_thread_handles {
            if let Err(_) = handle.join() {
                log::error!("Queue thread panicked");
            }
        }
        let _ = UblkCtrl::wakeup_control_ring(eventfd);
    })
    .await;

    // Signal completion
    context
        .semaphore_done
        .add_permits(context.nr_devices as usize - 1);
    log::info!("Main task: completed");

    Ok(())
}

/// Handle minor task logic: wait for synchronization and configure device
async fn handle_minor_task(
    ctrl: &UblkCtrl,
    dev_arc: Arc<UblkDev>,
    context: &DeviceHandlerContext,
) -> Result<(), UblkError> {
    log::info!(
        "Minor task {}: waiting for queue threads to be ready",
        context.device_index
    );

    // Wait for queue threads to be ready
    context.semaphore_ready.acquire().await;
    log::info!(
        "Minor task {}: queue threads ready, configuring device",
        context.device_index
    );

    // Set thread affinity for this device's ctrl instance
    set_queue_thread_affinity(&ctrl, context).await;

    // Configure and start device
    configure_and_start_device(&ctrl, &dev_arc, context).await?;

    // Wait for queue threads to complete
    log::info!(
        "Minor task {}: waiting for completion signal",
        context.device_index
    );
    context.semaphore_done.acquire().await;
    log::info!("Minor task {}: completed", context.device_index);

    Ok(())
}

/// Main device handler function that implements per-thread queue architecture
///
/// This function handles the creation and management of ublk devices in a multi-device,
/// per-thread queue setup where each thread handles queue `i` across all devices.
///
/// # Arguments
/// * `depth` - Queue depth for each queue
/// * `context` - Device handler context containing shared data
///
/// # Architecture
/// - Main task (last device): Creates queue threads, manages synchronization
/// - Minor tasks (other devices): Wait for synchronization and configure devices
/// - Each queue thread handles queue `i` across all devices
async fn device_handler_async(context: &DeviceHandlerContext) -> Result<(), UblkError> {
    log::info!("device handler entry for device {}", context.device_index);

    // Create device
    let (ctrl, dev_arc) = create_device(context).await?;

    // Register device and determine if this is the main task
    let is_main_task = register_device_and_check_main_task(
        context.device_index,
        context.nr_devices,
        dev_arc.clone(),
        context.devices.clone(),
    )
    .await;

    if is_main_task {
        handle_main_task(&ctrl, dev_arc, context).await?;
    } else {
        handle_minor_task(&ctrl, dev_arc, context).await?;
    }
    let _ = ctrl.stop_dev();
    Ok(())
}

fn main() {
    env_logger::builder()
        .format_target(false)
        .format_timestamp(None)
        .init();

    let matches = Command::new("ublk-multi-dev-example")
        .about("Multi-device ublk null target example using MultiQueueManager")
        .arg(
            Arg::new("nr-dev")
                .long("nr-dev")
                .default_value("2")
                .help("Number of devices to create")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("nr-queue")
                .long("nr-queue")
                .default_value("2")
                .help("Number of queues per device")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("depth")
                .long("depth")
                .default_value("128")
                .help("Queue depth: max in-flight io commands")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("zero-copy")
                .short('z')
                .long("zero-copy")
                .help("Enable zero-copy mode with UBLK_F_AUTO_BUF_REG")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let nr_dev: u16 = matches
        .get_one::<String>("nr-dev")
        .unwrap()
        .parse()
        .unwrap_or(2);
    let nr_queue: u16 = matches
        .get_one::<String>("nr-queue")
        .unwrap()
        .parse()
        .unwrap_or(2);
    let depth: u16 = matches
        .get_one::<String>("depth")
        .unwrap()
        .parse()
        .unwrap_or(64);
    let zero_copy: bool = matches.get_flag("zero-copy");

    println!(
        "Multi-device example: {} devices, {} queues/device, depth {}, zero-copy: {}",
        nr_dev, nr_queue, depth, zero_copy
    );

    let exe_rc = Rc::new(smol::LocalExecutor::new());
    let exe = exe_rc.clone();
    let mut fvec = Vec::new();

    log::info!("init control ring");
    //support 64 devices
    libublk::ctrl::ublk_init_ctrl_task_ring(|cell| {
        if cell.get().is_none() {
            let ring = io_uring::IoUring::<io_uring::squeue::Entry128>::builder()
                .build((nr_dev * 2) as u32)
                .map_err(UblkError::IOError)?;

            cell.set(std::cell::RefCell::new(ring))
                .map_err(|_| UblkError::OtherError(-libc::EEXIST))?;
        }
        Ok(())
    })
    .unwrap();

    log::info!("prepare control tasks");

    // Create shared data structures
    let devices = Arc::new(Mutex::new(Vec::new()));
    let thread_infos = Arc::new(Mutex::new(None));
    let semaphore_ready = Arc::new(Semaphore::new(0));
    let semaphore_done = Arc::new(Semaphore::new(0));
    let eventfd = nix::sys::eventfd::eventfd(0, nix::sys::eventfd::EfdFlags::empty()).unwrap();

    for device_index in 0..nr_dev {
        let context = DeviceHandlerContext {
            device_index,
            nr_queues: nr_queue,
            nr_devices: nr_dev,
            depth,
            zero_copy,
            devices: devices.clone(),
            thread_infos: thread_infos.clone(),
            semaphore_ready: semaphore_ready.clone(),
            semaphore_done: semaphore_done.clone(),
            eventfd,
        };

        fvec.push(exe_rc.spawn(async move {
            device_handler_async(&context).await.unwrap();
            let _ = UblkCtrl::wakeup_control_ring(context.eventfd);
        }));
    }

    log::info!("block on control tasks");
    smol::block_on(exe_rc.run(async move {
        let _ = ublk_block_on_ctrl_tasks(&exe, fvec, Some(eventfd));
    }));
}
