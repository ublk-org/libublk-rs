use bitflags::bitflags;
use clap::{Arg, ArgAction, Command};
use libublk::helpers::IoBuf;
use libublk::io::{
    with_queue_ring, with_queue_ring_mut, BufDescList, UblkDev, UblkIOCtx, UblkQueue,
};
use libublk::uring_async::{ublk_reap_io_events, ublk_wake_task};
use libublk::{ctrl::UblkCtrl, BufDesc, UblkError, UblkFlags, UblkIORes};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::rc::Rc;

bitflags! {
    #[derive(Default)]
    struct NullFlags: u32 {
        const ASYNC = 0b00000001;
        const FOREGROUND = 0b00000010;
        const ONESHOT = 0b00000100;
        const ZERO_COPY = 0b00001000;
        const USE_READABLE = 0b010000;
    }
}

#[inline]
fn get_io_cmd_result(q: &UblkQueue, tag: u16) -> i32 {
    let iod = q.get_iod(tag);
    let bytes = (iod.nr_sectors << 9) as i32;

    bytes
}

#[inline]
fn handle_io_cmd(q: &UblkQueue, tag: u16, io_slice: Option<&[u8]>) {
    let bytes = get_io_cmd_result(q, tag);

    // Use unified buffer API - choose appropriate buffer descriptor based on mode
    let buf_desc = if let Some(slice) = io_slice {
        BufDesc::Slice(slice)
    } else {
        // For user_copy mode, create an empty slice since no buffer is needed
        BufDesc::Slice(&[])
    };

    q.complete_io_cmd_unified(tag, buf_desc, Ok(UblkIORes::Result(bytes)))
        .unwrap();
}

fn q_sync_zc_fn(qid: u16, dev: &UblkDev) {
    let auto_buf_reg_list_rc = Rc::new(
        (0..dev.dev_info.queue_depth)
            .map(|tag| libublk::sys::ublk_auto_buf_reg {
                index: tag,
                flags: libublk::sys::UBLK_AUTO_BUF_REG_FALLBACK as u8,
                ..Default::default()
            })
            .collect::<Vec<_>>(),
    );

    let auto_buf_reg_list = auto_buf_reg_list_rc.clone();
    let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
        let bytes = get_io_cmd_result(q, tag);
        let buf_desc = BufDesc::AutoReg(auto_buf_reg_list[tag as usize]);
        q.complete_io_cmd_unified(tag, buf_desc, Ok(UblkIORes::Result(bytes)))
            .unwrap();
    };

    let queue = match UblkQueue::new(qid, dev)
        .unwrap()
        .submit_fetch_commands_unified(BufDescList::AutoRegs(&auto_buf_reg_list_rc))
    {
        Ok(q) => q,
        Err(e) => {
            log::error!("submit_fetch_commands_unified failed: {}", e);
            return;
        }
    };

    queue.wait_and_handle_io(io_handler);
}

fn q_sync_fn(qid: u16, dev: &UblkDev, user_copy: bool) {
    let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
    let bufs = bufs_rc.clone();

    // logic for io handling using safe slice-based operations
    let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
        // Use safe slice access instead of raw pointer manipulation
        // This leverages IoBuf's Deref/DerefMut traits for memory safety
        let io_slice = if user_copy {
            None // No buffer slice for user_copy mode
        } else {
            // Safe slice creation using IoBuf's as_mut_slice() method
            // Benefits: bounds checking, lifetime verification, no unsafe code
            Some(bufs[tag as usize].as_slice())
        };
        handle_io_cmd(q, tag, io_slice);
    };

    let queue = match UblkQueue::new(qid, dev)
        .unwrap()
        .submit_fetch_commands_unified(BufDescList::Slices(if user_copy {
            None
        } else {
            Some(&bufs_rc)
        })) {
        Ok(q) => q,
        Err(e) => {
            log::error!("submit_fetch_commands_unified failed: {}", e);
            return;
        }
    };

    queue.wait_and_handle_io(io_handler);
}

async fn __null_io_task(
    q: &UblkQueue<'_>,
    tag: u16,
    buf: Option<&IoBuf<u8>>,
    user_copy: bool,
) -> Result<(), UblkError> {
    let auto_buf_reg = libublk::sys::ublk_auto_buf_reg {
        index: tag,
        flags: libublk::sys::UBLK_AUTO_BUF_REG_FALLBACK as u8,
        ..Default::default()
    };

    let buf_desc = match buf {
        Some(io_buf) => {
            // Note: submit_io_prep_cmd will automatically register the buffer
            BufDesc::Slice(io_buf.as_slice())
        }
        None if user_copy => BufDesc::Slice(&[]),
        _ => BufDesc::AutoReg(auto_buf_reg),
    };

    // Submit initial prep command - any error will exit the function
    q.submit_io_prep_cmd(tag, buf_desc.clone(), 0, buf).await?;

    loop {
        let res = get_io_cmd_result(&q, tag);
        // Any error (including QueueIsDown) will break the loop by exiting the function
        q.submit_io_commit_cmd(tag, buf_desc.clone(), res).await?;
    }
}

async fn null_io_task(
    q: &UblkQueue<'_>,
    tag: u16,
    user_copy: bool,
    zero_copy: bool,
) -> Result<(), UblkError> {
    if zero_copy && q.support_auto_buf_zc() {
        __null_io_task(q, tag, None, user_copy).await
    } else {
        let buf = if user_copy {
            None
        } else {
            Some(IoBuf::<u8>::new(q.dev.dev_info.max_io_buf_bytes as usize))
        };
        __null_io_task(q, tag, buf.as_ref(), user_copy).await
    }
}

async fn poll_events(
    q: &UblkQueue<'_>,
    async_uring: &Option<smol::Async<std::fs::File>>,
) -> Result<(), UblkError> {
    log::info!("before readable tid {}", unsafe { libc::gettid() });

    match async_uring {
        Some(async_file) => {
            with_queue_ring_mut(q, |r| r.submit_and_wait(0))?;
            async_file
                .readable()
                .await
                .map_err(|_| UblkError::OtherError(-libc::EIO))?;
        }
        None => {
            with_queue_ring_mut(q, |r| r.submit_and_wait(1))?;
        }
    }
    log::info!("after readable {}", unsafe { libc::gettid() });
    Ok(())
}

async fn handle_uring_events<T>(
    exe: &smol::LocalExecutor<'_>,
    q: &UblkQueue<'_>,
    tasks: Vec<smol::Task<T>>,
    smol_readable: bool,
) -> Result<(), UblkError> {
    let uring_fd = with_queue_ring(q, |ring| ring.as_raw_fd());
    let async_uring = if smol_readable {
        let file = unsafe { File::from_raw_fd(uring_fd) };
        Some(smol::Async::new(file).map_err(|_e| UblkError::OtherError(-libc::EINVAL))?)
    } else {
        None
    };

    smol::future::yield_now().await;

    // Use the new run_uring_tasks API
    let poll_uring = || async { poll_events(q, &async_uring).await };
    let reap_event = || ublk_reap_io_events(q, |cqe| ublk_wake_task(cqe.user_data(), cqe));
    let run_ops = || while exe.try_tick() {};
    let is_done = || tasks.iter().all(|task| task.is_finished());
    libublk::run_uring_tasks(poll_uring, reap_event, run_ops, is_done).await?;

    // Prevent the File wrapper from closing the fd when dropped
    // since the original io_uring instance still owns it
    if let Some(async_file) = async_uring {
        let _ = async_file.into_inner().map(|f| {
            use std::os::fd::IntoRawFd;
            f.into_raw_fd()
        });
    }

    Ok(())
}

fn q_async_fn(qid: u16, dev: &UblkDev, user_copy: bool, zero_copy: bool, readable: bool) {
    let q_rc = Rc::new(UblkQueue::new(qid as u16, &dev).unwrap());
    let exe_rc = Rc::new(smol::LocalExecutor::new());
    let exe = exe_rc.clone();
    let mut f_vec = Vec::new();

    for tag in 0..dev.dev_info.queue_depth as u16 {
        let q = q_rc.clone();

        f_vec.push(exe.spawn(async move {
            match null_io_task(&q, tag, user_copy, zero_copy).await {
                Err(UblkError::QueueIsDown) | Ok(_) => {}
                Err(e) => log::error!("null_io_task failed for tag {}: {}", tag, e),
            }
        }));
    }

    let q = q_rc.clone();
    let exe2 = exe_rc.clone();
    let real_exe = exe.spawn(async move {
        if let Err(e) = handle_uring_events(&exe2, &q, f_vec, readable).await {
            log::error!("handle_uring_events failed: {}", e);
        }
    });

    smol::block_on(exe_rc.run(async move { real_exe.await }));
}

fn __null_add(
    id: i32,
    nr_queues: u32,
    depth: u32,
    mut ctrl_flags: u64,
    buf_size: u32,
    flags: NullFlags,
) {
    let aio = flags.intersects(NullFlags::ASYNC);
    let oneshot = flags.intersects(NullFlags::ONESHOT);
    let zero_copy = flags.intersects(NullFlags::ZERO_COPY);
    let use_readable = flags.intersects(NullFlags::USE_READABLE);

    // Add AUTO_BUF_REG flag if zero copy is enabled
    if zero_copy {
        ctrl_flags |= libublk::sys::UBLK_F_AUTO_BUF_REG as u64;
    }

    let ctrl = libublk::ctrl::UblkCtrlBuilder::default()
        .name("example_null")
        .id(id)
        .depth(depth.try_into().unwrap())
        .nr_queues(nr_queues.try_into().unwrap())
        .io_buf_bytes(buf_size)
        .ctrl_flags(ctrl_flags)
        .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV | UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY)
        .build()
        .unwrap();
    let tgt_init = |dev: &mut UblkDev| {
        dev.set_default_params(250_u64 << 30);
        Ok(())
    };
    let user_copy = (ctrl.dev_info().flags & libublk::sys::UBLK_F_USER_COPY as u64) != 0;
    let wh = move |d_ctrl: &UblkCtrl| {
        d_ctrl.dump();
        if oneshot {
            d_ctrl.kill_dev().unwrap();
        }
    };

    // Now start this ublk target
    if aio {
        let q_async_handler =
            move |qid, dev: &_| q_async_fn(qid, dev, user_copy, zero_copy, use_readable);
        ctrl.run_target(tgt_init, q_async_handler, wh).unwrap();
    } else {
        if zero_copy {
            let q_sync_handler = move |qid, dev: &_| q_sync_zc_fn(qid, dev);
            ctrl.run_target(tgt_init, q_sync_handler, wh).unwrap();
        } else {
            let q_sync_handler = move |qid, dev: &_| q_sync_fn(qid, dev, user_copy);
            ctrl.run_target(tgt_init, q_sync_handler, wh).unwrap();
        }
    }
}

fn null_add(id: i32, nr_queues: u32, depth: u32, ctrl_flags: u64, buf_size: u32, flags: NullFlags) {
    if flags.intersects(NullFlags::FOREGROUND) {
        __null_add(id, nr_queues, depth, ctrl_flags, buf_size, flags);
    } else {
        let daemonize = daemonize::Daemonize::new()
            .stdout(daemonize::Stdio::keep())
            .stderr(daemonize::Stdio::keep());

        match daemonize.start() {
            Ok(_) => __null_add(id, nr_queues, depth, ctrl_flags, buf_size, flags),
            _ => panic!(),
        }
    }
}

fn main() {
    env_logger::builder()
        .format_target(false)
        .format_timestamp(None)
        .init();
    let matches = Command::new("ublk-null-example")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("add")
                .about("Add ublk device")
                .arg(
                    Arg::new("number")
                        .short('n')
                        .long("number")
                        .default_value("-1")
                        .allow_hyphen_values(true)
                        .help("device id, -1: auto-allocation")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("queues")
                        .long("queues")
                        .short('q')
                        .default_value("1")
                        .help("nr_hw_queues")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("depth")
                        .long("depth")
                        .short('d')
                        .default_value("128")
                        .help("queue depth: max in-flight io commands")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("buf_size")
                        .long("buf_size")
                        .short('b')
                        .default_value("524288")
                        .help("io buffer size")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("user_copy")
                        .long("user_copy")
                        .short('u')
                        .action(ArgAction::SetTrue)
                        .help("enable UBLK_F_USER_COPY"),
                )
                .arg(
                    Arg::new("unprivileged")
                        .long("unprivileged")
                        .short('p')
                        .action(ArgAction::SetTrue)
                        .help("enable UBLK_F_UN_PRIVILEGED_DEV"),
                )
                .arg(
                    Arg::new("foreground")
                        .long("foreground")
                        .action(ArgAction::SetTrue)
                        .help("run in foreground mode"),
                )
                .arg(
                    Arg::new("oneshot")
                        .long("oneshot")
                        .action(ArgAction::SetTrue)
                        .help("create, dump and remove device automatically"),
                )
                .arg(
                    Arg::new("async")
                        .long("async")
                        .short('a')
                        .action(ArgAction::SetTrue)
                        .help("use async/await to handle IO command"),
                )
                .arg(
                    Arg::new("zero_copy")
                        .long("zero-copy")
                        .short('z')
                        .action(ArgAction::SetTrue)
                        .help("enable zero copy via UBLK_F_AUTO_BUF_REG"),
                )
                .arg(
                    Arg::new("use_readable")
                        .long("use_readable")
                        .action(ArgAction::SetTrue)
                        .help("use readable polling and drain all tasks from f_vec"),
                ),
        )
        .subcommand(
            Command::new("del").about("Delete ublk device").arg(
                Arg::new("number")
                    .short('n')
                    .long("number")
                    .required(true)
                    .help("device id")
                    .action(ArgAction::Set),
            ),
        )
        .subcommand(
            Command::new("list").about("List ublk device").arg(
                Arg::new("number")
                    .short('n')
                    .long("number")
                    .default_value("-1")
                    .help("device id")
                    .action(ArgAction::Set),
            ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("add", add_matches)) => {
            let id = add_matches
                .get_one::<String>("number")
                .unwrap()
                .parse::<i32>()
                .unwrap_or(-1);
            let nr_queues = add_matches
                .get_one::<String>("queues")
                .unwrap()
                .parse::<u32>()
                .unwrap_or(1);
            let depth = add_matches
                .get_one::<String>("depth")
                .unwrap()
                .parse::<u32>()
                .unwrap_or(128);
            let buf_size = add_matches
                .get_one::<String>("buf_size")
                .unwrap()
                .parse::<u32>()
                .unwrap_or(52288);
            let mut flags: NullFlags = Default::default();

            if add_matches.get_flag("async") {
                flags |= NullFlags::ASYNC;
            };
            if add_matches.get_flag("foreground") {
                flags |= NullFlags::FOREGROUND;
            };
            if add_matches.get_flag("oneshot") {
                flags |= NullFlags::ONESHOT;
            };
            if add_matches.get_flag("zero_copy") {
                flags |= NullFlags::ZERO_COPY;
            };
            if add_matches.get_flag("use_readable") {
                flags |= NullFlags::USE_READABLE;
            };
            let ctrl_flags: u64 = if add_matches.get_flag("user_copy") {
                libublk::sys::UBLK_F_USER_COPY as u64
            } else {
                0
            } | if add_matches.get_flag("unprivileged") {
                libublk::sys::UBLK_F_UNPRIVILEGED_DEV as u64
            } else {
                0
            };

            null_add(id, nr_queues, depth, ctrl_flags, buf_size, flags);
        }
        Some(("del", add_matches)) => {
            let id = add_matches
                .get_one::<String>("number")
                .unwrap()
                .parse::<i32>()
                .unwrap_or(-1);
            UblkCtrl::new_simple(id).unwrap().del_dev().unwrap();
        }
        Some(("list", add_matches)) => {
            let dev_id = add_matches
                .get_one::<String>("number")
                .unwrap()
                .parse::<i32>()
                .unwrap_or(-1);
            if dev_id >= 0 {
                UblkCtrl::new_simple(dev_id as i32).unwrap().dump();
            } else {
                UblkCtrl::for_each_dev_id(|dev_id| {
                    UblkCtrl::new_simple(dev_id as i32).unwrap().dump();
                });
            }
        }
        _ => {
            println!("unsupported command");
        }
    };
}
