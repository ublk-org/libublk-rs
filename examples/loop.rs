use anyhow::Result;
use bitflags::bitflags;
use clap::{Arg, ArgAction, Command};
use ilog::IntLog;
use io_uring::{opcode, squeue, types};
use libublk::helpers::IoBuf;
use libublk::io::{BufDescList, UblkDev, UblkIOCtx, UblkQueue};
use libublk::uring_async::ublk_wait_and_handle_ios;
use libublk::{ctrl::UblkCtrl, BufDesc, UblkError, UblkFlags, UblkIORes};
use serde::Serialize;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::rc::Rc;

#[derive(Debug, Serialize)]
struct LoJson {
    back_file_path: String,
    direct_io: i32,
}

struct LoopTgt {
    back_file_path: String,
    back_file: std::fs::File,
    direct_io: i32,
}

bitflags! {
    #[derive(Default)]
    struct LoFlags: u32 {
        const ASYNC = 0b00000001;
        const FOREGROUND = 0b00000010;
        const ONESHOT = 0b00001000;
        const MLOCK = 0b00010000;
    }
}

// Generate ioctl function
const BLK_IOCTL_TYPE: u8 = 0x12; // Defined in linux/fs.h
const BLKGETSIZE64_NR: u8 = 114;
const BLKSSZGET_NR: u8 = 104;
const BLKPBSZGET_NR: u8 = 123;

nix::ioctl_read!(ioctl_blkgetsize64, BLK_IOCTL_TYPE, BLKGETSIZE64_NR, u64);
nix::ioctl_read_bad!(
    ioctl_blksszget,
    nix::request_code_none!(BLK_IOCTL_TYPE, BLKSSZGET_NR),
    i32
);
nix::ioctl_read_bad!(
    ioctl_blkpbszget,
    nix::request_code_none!(BLK_IOCTL_TYPE, BLKPBSZGET_NR),
    u32
);
fn lo_file_size(f: &std::fs::File) -> Result<(u64, u8, u8)> {
    if let Ok(meta) = f.metadata() {
        if meta.file_type().is_block_device() {
            let fd = f.as_raw_fd();
            let mut cap = 0_u64;
            let mut ssz = 0_i32;
            let mut pbsz = 0_u32;

            unsafe {
                let cap_ptr = &mut cap as *mut u64;
                let ssz_ptr = &mut ssz as *mut i32;
                let pbsz_ptr = &mut pbsz as *mut u32;

                ioctl_blkgetsize64(fd, cap_ptr).unwrap();
                ioctl_blksszget(fd, ssz_ptr).unwrap();
                ioctl_blkpbszget(fd, pbsz_ptr).unwrap();
            }

            Ok((cap, ssz.log2() as u8, pbsz.log2() as u8))
        } else if meta.file_type().is_file() {
            Ok((f.metadata().unwrap().len(), 9, 12))
        } else {
            Err(anyhow::anyhow!("unsupported file"))
        }
    } else {
        Err(anyhow::anyhow!("no file meta got"))
    }
}

// setup loop target
fn lo_init_tgt(dev: &mut UblkDev, lo: &LoopTgt) -> Result<(), UblkError> {
    log::info!("loop: init_tgt {}", dev.dev_info.dev_id);
    if lo.direct_io != 0 {
        unsafe {
            libc::fcntl(lo.back_file.as_raw_fd(), libc::F_SETFL, libc::O_DIRECT);
        }
    }

    let tgt = &mut dev.tgt;
    let nr_fds = tgt.nr_fds;
    tgt.fds[nr_fds as usize] = lo.back_file.as_raw_fd();
    tgt.nr_fds = nr_fds + 1;

    let sz = { lo_file_size(&lo.back_file).unwrap() };
    tgt.dev_size = sz.0;
    //todo: figure out correct block size
    tgt.params = libublk::sys::ublk_params {
        types: libublk::sys::UBLK_PARAM_TYPE_BASIC,
        basic: libublk::sys::ublk_param_basic {
            logical_bs_shift: sz.1,
            physical_bs_shift: sz.2,
            io_opt_shift: 12,
            io_min_shift: 9,
            max_sectors: dev.dev_info.max_io_buf_bytes >> 9,
            dev_sectors: tgt.dev_size >> 9,
            ..Default::default()
        },
        ..Default::default()
    };
    let val = serde_json::json!({"loop": LoJson { back_file_path: lo.back_file_path.clone(), direct_io: 1 } });
    dev.set_target_json(val);

    Ok(())
}

#[inline]
fn __lo_prep_submit_io_cmd(iod: &libublk::sys::ublksrv_io_desc) -> i32 {
    let op = iod.op_flags & 0xff;

    match op {
        libublk::sys::UBLK_IO_OP_FLUSH
        | libublk::sys::UBLK_IO_OP_READ
        | libublk::sys::UBLK_IO_OP_WRITE => return 0,
        _ => return -libc::EINVAL,
    };
}

#[inline]
fn __lo_make_io_sqe(op: u32, off: u64, bytes: u32, buf_addr: *mut u8) -> io_uring::squeue::Entry {
    match op {
        libublk::sys::UBLK_IO_OP_FLUSH => opcode::SyncFileRange::new(types::Fixed(1), bytes)
            .offset(off)
            .build()
            .flags(squeue::Flags::FIXED_FILE),
        libublk::sys::UBLK_IO_OP_READ => opcode::Read::new(types::Fixed(1), buf_addr, bytes)
            .offset(off)
            .build()
            .flags(squeue::Flags::FIXED_FILE),
        libublk::sys::UBLK_IO_OP_WRITE => opcode::Write::new(types::Fixed(1), buf_addr, bytes)
            .offset(off)
            .build()
            .flags(squeue::Flags::FIXED_FILE),
        _ => panic!(),
    }
}

/// Handle I/O operations asynchronously using slice-based buffer management.
///
/// This function demonstrates slice-based async I/O patterns for educational purposes:
/// - Uses safe slice access instead of raw pointer manipulation  
/// - Leverages IoBuf's slice methods for memory safety
/// - Shows when slice-to-pointer conversion is necessary for libublk API calls
/// - Maintains async/await patterns for high-performance I/O
async fn lo_handle_io_cmd_async(q: &UblkQueue<'_>, tag: u16, io_slice: &mut [u8]) -> i32 {
    let iod = q.get_iod(tag);
    let res = __lo_prep_submit_io_cmd(iod);
    if res < 0 {
        return res;
    }

    for _ in 0..4 {
        let op = iod.op_flags & 0xff;
        // either start to handle or retry
        let off = (iod.start_sector << 9) as u64;
        let bytes = (iod.nr_sectors << 9) as u32;

        // Convert slice to pointer only when required by libublk API
        // This conversion is necessary because io_uring operations require raw pointers
        // for kernel interface compatibility. The slice ensures we have valid bounds.
        let buf_addr = io_slice.as_mut_ptr();
        let sqe = __lo_make_io_sqe(op, off, bytes, buf_addr);
        let res = q.ublk_submit_sqe(sqe).await;
        if res != -(libc::EAGAIN) {
            return res;
        }
    }

    return -libc::EAGAIN;
}

/// Handle I/O operations synchronously (for comparison with async slice patterns).
///
/// Note: This sync handler still uses raw pointers as it follows the traditional
/// synchronous I/O pattern. The async handler above demonstrates the preferred
/// slice-based approach for new implementations.
fn lo_handle_io_cmd_sync(q: &UblkQueue<'_>, tag: u16, i: &UblkIOCtx, io_slice: &[u8]) {
    let iod = q.get_iod(tag);
    let op = iod.op_flags & 0xff;
    let data = UblkIOCtx::build_user_data(tag as u16, op, 0, true);
    if i.is_tgt_io() {
        let user_data = i.user_data();
        let res = i.result();
        let cqe_tag = UblkIOCtx::user_data_to_tag(user_data);

        assert!(cqe_tag == tag as u32);

        if res != -(libc::EAGAIN) {
            q.complete_io_cmd_unified(tag, BufDesc::Slice(io_slice), Ok(UblkIORes::Result(res)))
                .unwrap();
            return;
        }
    }

    let res = __lo_prep_submit_io_cmd(iod);
    if res < 0 {
        q.complete_io_cmd_unified(tag, BufDesc::Slice(io_slice), Ok(UblkIORes::Result(res)))
            .unwrap();
    } else {
        let op = iod.op_flags & 0xff;
        // either start to handle or retry
        let off = (iod.start_sector << 9) as u64;
        let bytes = (iod.nr_sectors << 9) as u32;
        let sqe = __lo_make_io_sqe(op, off, bytes, io_slice.as_ptr() as *mut u8).user_data(data);
        q.ublk_submit_sqe_sync(sqe).unwrap();
    }
}

fn q_fn(qid: u16, dev: &UblkDev) {
    let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
    let bufs = bufs_rc.clone();

    // Synchronous I/O handler demonstrating slice access patterns
    let lo_io_handler = move |q: &UblkQueue, tag: u16, io: &UblkIOCtx| {
        let bufs = bufs_rc.clone();

        // Note: For educational purposes, this shows how slice access can be used
        // even in sync handlers. The slice provides safe bounds-checked access.
        let io_slice = bufs[tag as usize].as_slice();

        // Convert to raw pointer only when required by legacy sync handler API
        // This demonstrates the pattern: use slices for safety, convert to pointers
        // only when absolutely necessary for API compatibility
        lo_handle_io_cmd_sync(q, tag, io, &io_slice);
    };

    let queue = match UblkQueue::new(qid, dev)
        .unwrap()
        .submit_fetch_commands_unified(BufDescList::Slices(Some(&bufs)))
    {
        Ok(q) => q,
        Err(e) => {
            log::error!("submit_fetch_commands_unified failed: {}", e);
            return;
        }
    };

    queue.wait_and_handle_io(lo_io_handler);
}

async fn lo_io_task(q: &UblkQueue<'_>, tag: u16) -> Result<(), UblkError> {
    // Use IoBuf for safe I/O buffer management with automatic memory alignment
    let mut buf = IoBuf::<u8>::new(q.dev.dev_info.max_io_buf_bytes as usize);

    // Submit initial prep command - any error will exit the function
    // The IoBuf is automatically registered
    q.submit_io_prep_cmd(tag, BufDesc::Slice(buf.as_slice()), 0, Some(&buf))
        .await?;

    loop {
        // Use safe slice access for I/O operations
        // IoBuf's as_mut_slice() provides bounds-checked access eliminating
        // the need for unsafe pointer operations in the I/O handler
        let io_slice = buf.as_mut_slice();
        let res = lo_handle_io_cmd_async(&q, tag, io_slice).await;

        // Any error (including QueueIsDown) will break the loop by exiting the function
        q.submit_io_commit_cmd(tag, BufDesc::Slice(buf.as_slice()), res)
            .await?;
    }
}

fn q_a_fn(qid: u16, dev: &UblkDev, depth: u16) {
    let q_rc = Rc::new(UblkQueue::new(qid as u16, &dev).unwrap());
    let exe = smol::LocalExecutor::new();
    let mut f_vec = Vec::new();

    for tag in 0..depth {
        let q = q_rc.clone();

        f_vec.push(exe.spawn(async move {
            match lo_io_task(&q, tag).await {
                Err(UblkError::QueueIsDown) | Ok(_) => {}
                Err(e) => log::error!("lo_io_task failed for tag {}: {}", tag, e),
            }
        }));
    }
    ublk_wait_and_handle_ios(&exe, &q_rc);
    smol::block_on(exe.run(async { futures::future::join_all(f_vec).await }));
}

fn __loop_add(
    id: i32,
    nr_queues: u32,
    depth: u16,
    buf_sz: u32,
    backing_file: &String,
    ctrl_flags: u64,
    lo_flags: LoFlags,
) {
    let aio = lo_flags.intersects(LoFlags::ASYNC);
    let oneshot = lo_flags.intersects(LoFlags::ONESHOT);
    // LooTgt has to live in the whole device lifetime
    let lo = LoopTgt {
        back_file: std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&backing_file)
            .unwrap(),
        direct_io: 1,
        back_file_path: backing_file.clone(),
    };
    let dev_flags = UblkFlags::UBLK_DEV_F_ADD_DEV
        | if lo_flags.intersects(LoFlags::MLOCK) {
            UblkFlags::UBLK_DEV_F_MLOCK_IO_BUFFER
        } else {
            UblkFlags::empty()
        };
    let ctrl = libublk::ctrl::UblkCtrlBuilder::default()
        .name("example_loop")
        .id(id)
        .ctrl_flags(ctrl_flags)
        .nr_queues(nr_queues.try_into().unwrap())
        .depth(depth)
        .io_buf_bytes(buf_sz)
        .dev_flags(dev_flags)
        .build()
        .unwrap();
    let tgt_init = |dev: &mut UblkDev| lo_init_tgt(dev, &lo);
    let wh = move |d_ctrl: &UblkCtrl| {
        d_ctrl.dump();
        if oneshot {
            d_ctrl.kill_dev().unwrap();
        }
    };

    if aio {
        ctrl.run_target(tgt_init, move |qid, dev: &_| q_a_fn(qid, dev, depth), wh)
            .unwrap();
    } else {
        ctrl.run_target(tgt_init, move |qid, dev: &_| q_fn(qid, dev), wh)
            .unwrap();
    }
}

fn loop_add(
    id: i32,
    nr_queues: u32,
    depth: u16,
    buf_sz: u32,
    backing_file: &String,
    ctrl_flags: u64,
    lo_flags: LoFlags,
) {
    if lo_flags.intersects(LoFlags::FOREGROUND) {
        __loop_add(
            id,
            nr_queues,
            depth,
            buf_sz,
            backing_file,
            ctrl_flags,
            lo_flags,
        );
    } else {
        let daemonize = daemonize::Daemonize::new()
            .stdout(daemonize::Stdio::keep())
            .stderr(daemonize::Stdio::keep());

        match daemonize.start() {
            Ok(_) => __loop_add(
                id,
                nr_queues,
                depth,
                buf_sz,
                backing_file,
                ctrl_flags,
                lo_flags,
            ),
            Err(_) => panic!(),
        }
    }
}

fn main() {
    env_logger::builder()
        .format_target(false)
        .format_timestamp(None)
        .init();
    let matches = Command::new("ublk-loop-example")
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
                        .default_value("64")
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
                    Arg::new("backing_file")
                        .long("backing_file")
                        .short('f')
                        .required(true)
                        .help("backing file")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("async")
                        .long("async")
                        .short('a')
                        .action(ArgAction::SetTrue)
                        .help("use async/await to handle IO command"),
                )
                .arg(
                    Arg::new("oneshot")
                        .long("oneshot")
                        .action(ArgAction::SetTrue)
                        .help("create, dump and remove device automatically"),
                )
                .arg(
                    Arg::new("mlock_io_buffer")
                        .long("mlock-io-buffer")
                        .short('m')
                        .action(ArgAction::SetTrue)
                        .help("enable UBLK_DEV_F_MLOCK_IO_BUFFER to lock IO buffers in memory"),
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
        .subcommand(Command::new("list").about("List ublk device"))
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
                .unwrap_or(64);
            let buf_size = add_matches
                .get_one::<String>("buf_size")
                .unwrap()
                .parse::<u32>()
                .unwrap_or(52288);
            let backing_file = add_matches.get_one::<String>("backing_file").unwrap();
            let mut lo_flags: LoFlags = Default::default();

            if add_matches.get_flag("async") {
                lo_flags |= LoFlags::ASYNC;
            };
            if add_matches.get_flag("foreground") {
                lo_flags |= LoFlags::FOREGROUND;
            };
            if add_matches.get_flag("oneshot") {
                lo_flags |= LoFlags::ONESHOT;
            };
            if add_matches.get_flag("mlock_io_buffer") {
                lo_flags |= LoFlags::MLOCK;
            }
            let ctrl_flags: u64 = if add_matches.get_flag("unprivileged") {
                libublk::sys::UBLK_F_UNPRIVILEGED_DEV as u64
            } else {
                0
            };
            loop_add(
                id,
                nr_queues,
                depth.try_into().unwrap(),
                buf_size,
                backing_file,
                ctrl_flags,
                lo_flags,
            );
        }
        Some(("del", add_matches)) => {
            let id = add_matches
                .get_one::<String>("number")
                .unwrap()
                .parse::<i32>()
                .unwrap_or(-1);
            UblkCtrl::new_simple(id).unwrap().del_dev().unwrap();
        }
        Some(("list", _add_matches)) => UblkCtrl::for_each_dev_id(|dev_id| {
            UblkCtrl::new_simple(dev_id as i32).unwrap().dump();
        }),
        _ => {
            println!("unsupported command");
        }
    };
}
