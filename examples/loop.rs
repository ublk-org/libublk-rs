use anyhow::Result;
use clap::{Arg, ArgAction, Command};
use ilog::IntLog;
use io_uring::{opcode, squeue, types};
use libublk::dev_flags::*;
use libublk::io::{UblkDev, UblkIOCtx, UblkQueue};
use libublk::{
    ctrl::UblkCtrl, exe::Executor, exe::UringOpFuture, sys, UblkError, UblkIORes, UblkSession,
};
use log::trace;
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
fn lo_init_tgt(dev: &mut UblkDev, lo: &LoopTgt, split: bool) -> Result<i32, UblkError> {
    trace!("loop: init_tgt {}", dev.dev_info.dev_id);
    if lo.direct_io != 0 {
        unsafe {
            libc::fcntl(lo.back_file.as_raw_fd(), libc::F_SETFL, libc::O_DIRECT);
        }
    }

    let tgt = &mut dev.tgt;
    let nr_fds = tgt.nr_fds;
    tgt.fds[nr_fds as usize] = lo.back_file.as_raw_fd();
    tgt.nr_fds = nr_fds + 1;

    let depth = dev.dev_info.queue_depth;
    tgt.sq_depth = if split { depth * 2 } else { depth };
    tgt.cq_depth = if split { depth * 2 } else { depth };

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

    Ok(0)
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
fn __lo_submit_io_cmd(
    q: &UblkQueue<'_>,
    op: u32,
    off: u64,
    bytes: u32,
    buf_addr: *mut u8,
    data: u64,
) {
    match op {
        libublk::sys::UBLK_IO_OP_FLUSH => {
            let sqe = &opcode::SyncFileRange::new(types::Fixed(1), bytes)
                .offset(off)
                .build()
                .flags(squeue::Flags::FIXED_FILE)
                .user_data(data);
            unsafe {
                q.q_ring
                    .borrow_mut()
                    .submission()
                    .push(sqe)
                    .expect("submission fail");
            }
        }
        libublk::sys::UBLK_IO_OP_READ => {
            let sqe = &opcode::Read::new(types::Fixed(1), buf_addr, bytes)
                .offset(off)
                .build()
                .flags(squeue::Flags::FIXED_FILE)
                .user_data(data);
            unsafe {
                q.q_ring
                    .borrow_mut()
                    .submission()
                    .push(sqe)
                    .expect("submission fail");
            }
        }
        libublk::sys::UBLK_IO_OP_WRITE => {
            let sqe = &opcode::Write::new(types::Fixed(1), buf_addr, bytes)
                .offset(off)
                .build()
                .flags(squeue::Flags::FIXED_FILE)
                .user_data(data);
            unsafe {
                q.q_ring
                    .borrow_mut()
                    .submission()
                    .push(sqe)
                    .expect("submission fail");
            }
        }
        _ => {}
    };
}

async fn lo_handle_io_cmd_async(q: &UblkQueue<'_>, tag: u16) -> i32 {
    let iod = q.get_iod(tag);
    let res = __lo_prep_submit_io_cmd(iod);
    if res < 0 {
        return res;
    }

    for _ in 0..4 {
        let op = iod.op_flags & 0xff;
        let user_data = UblkIOCtx::build_user_data_async(tag as u16, op, 0);
        // either start to handle or retry
        let off = (iod.start_sector << 9) as u64;
        let bytes = (iod.nr_sectors << 9) as u32;
        let buf_addr = q.get_io_buf_addr(tag);

        __lo_submit_io_cmd(q, op, off, bytes, buf_addr, user_data);
        let res = UringOpFuture { user_data }.await;
        if res != -(libc::EAGAIN) {
            return res;
        }
    }

    return -libc::EAGAIN;
}

async fn lo_handle_io_cmd_async_split(q: &UblkQueue<'_>, tag: u16) -> i32 {
    let iod = q.get_iod(tag);
    let res = __lo_prep_submit_io_cmd(iod);
    if res < 0 {
        return res;
    }

    let op = iod.op_flags & 0xff;
    let user_data = UblkIOCtx::build_user_data_async(tag as u16, op, 0);
    let off = (iod.start_sector << 9) as u64;
    let bytes = (iod.nr_sectors << 9) as u32;
    let buf_addr = q.get_io_buf_addr(tag);

    if bytes > 4096 {
        __lo_submit_io_cmd(q, op, off, 4096, buf_addr, user_data);
        let user_data2 = UblkIOCtx::build_user_data_async(tag as u16, op, 1);
        __lo_submit_io_cmd(
            q,
            op,
            off + 4096,
            bytes - 4096,
            ((buf_addr as u64) + 4096) as *mut u8,
            user_data2,
        );

        let f = UringOpFuture { user_data };
        let f2 = UringOpFuture {
            user_data: user_data2,
        };
        let (res, res2) = futures::join!(f, f2);

        res + res2
    } else {
        __lo_submit_io_cmd(q, op, off, bytes, buf_addr, user_data);
        let res = UringOpFuture { user_data };

        res.await
    }
}

fn lo_handle_io_cmd_sync(q: &UblkQueue<'_>, tag: u16, i: &UblkIOCtx) {
    let iod = q.get_iod(tag);
    let op = iod.op_flags & 0xff;
    let data = UblkIOCtx::build_user_data(tag as u16, op, 0, true);
    if i.is_tgt_io() {
        let user_data = i.user_data();
        let res = i.result();
        let cqe_tag = UblkIOCtx::user_data_to_tag(user_data);

        assert!(cqe_tag == tag as u32);

        if res != -(libc::EAGAIN) {
            q.complete_io_cmd(tag, Ok(UblkIORes::Result(res)));
            return;
        }
    }

    let res = __lo_prep_submit_io_cmd(iod);
    if res < 0 {
        q.complete_io_cmd(tag, Ok(UblkIORes::Result(res)));
    } else {
        let op = iod.op_flags & 0xff;
        // either start to handle or retry
        let off = (iod.start_sector << 9) as u64;
        let bytes = (iod.nr_sectors << 9) as u32;
        let buf_addr = q.get_io_buf_addr(tag);
        __lo_submit_io_cmd(q, op, off, bytes, buf_addr, data);
    }
}

fn test_add(
    id: i32,
    nr_queues: u32,
    depth: u32,
    buf_sz: u32,
    backing_file: &String,
    ctrl_flags: u64,
    fg: bool,
    aio: bool,
    split: bool,
) {
    let _pid = if !fg { unsafe { libc::fork() } } else { 0 };
    if _pid == 0 {
        __test_add(
            id,
            nr_queues,
            depth,
            buf_sz,
            backing_file,
            ctrl_flags,
            aio,
            split,
        );
    }
}

fn __test_add(
    id: i32,
    nr_queues: u32,
    depth: u32,
    buf_sz: u32,
    backing_file: &String,
    ctrl_flags: u64,
    aio: bool,
    split: bool,
) {
    {
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
        let sess = libublk::UblkSessionBuilder::default()
            .name("example_loop")
            .id(id)
            .ctrl_flags(ctrl_flags)
            .nr_queues(nr_queues)
            .depth(depth)
            .io_buf_bytes(buf_sz)
            .dev_flags(UBLK_DEV_F_ADD_DEV | if aio { UBLK_DEV_F_ASYNC } else { 0 })
            .build()
            .unwrap();

        let tgt_init = |dev: &mut UblkDev| lo_init_tgt(dev, &lo, split);
        let (mut ctrl, dev) = sess.create_devices(tgt_init).unwrap();
        let q_async_fn = move |qid: u16, dev: &UblkDev| {
            let q_rc = Rc::new(UblkQueue::new(qid as u16, &dev).unwrap());
            let exe = Executor::new(dev.get_nr_ios());

            for tag in 0..depth as u16 {
                let q = q_rc.clone();

                exe.spawn(tag as u16, async move {
                    let buf_addr = q.get_io_buf_addr(tag);
                    let mut cmd_op = sys::UBLK_IO_FETCH_REQ;
                    let mut res = 0;
                    loop {
                        let cmd_res = q.submit_io_cmd(tag, cmd_op, buf_addr, res).await;
                        if cmd_res == sys::UBLK_IO_RES_ABORT {
                            break;
                        }

                        res = if !split {
                            lo_handle_io_cmd_async(&q, tag).await
                        } else {
                            lo_handle_io_cmd_async_split(&q, tag).await
                        };
                        cmd_op = sys::UBLK_IO_COMMIT_AND_FETCH_REQ;
                    }
                });
            }
            q_rc.wait_and_wake_io_tasks(&exe);
        };

        let q_sync_fn = move |qid: u16, _dev: &UblkDev| {
            let lo_io_handler =
                move |q: &UblkQueue, tag: u16, io: &UblkIOCtx| lo_handle_io_cmd_sync(q, tag, io);

            UblkQueue::new(qid, _dev)
                .unwrap()
                .wait_and_handle_io(lo_io_handler);
        };

        if aio {
            sess.run_target(&mut ctrl, &dev, q_async_fn, |dev_id| {
                let mut d_ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();
                d_ctrl.dump();
            })
            .unwrap();
        } else {
            sess.run_target(&mut ctrl, &dev, q_sync_fn, |dev_id| {
                let mut d_ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();
                d_ctrl.dump();
            })
            .unwrap();
        }
    }
}

fn main() {
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
                    Arg::new("forground")
                        .long("forground")
                        .action(ArgAction::SetTrue)
                        .help("run in forground mode"),
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
                    Arg::new("split")
                        .long("split")
                        .short('s')
                        .action(ArgAction::SetTrue)
                        .help("Split big IO into two small IOs, only for --async"),
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

            let aio = if add_matches.get_flag("async") {
                true
            } else {
                false
            };
            let split = if aio {
                if add_matches.get_flag("split") {
                    true
                } else {
                    false
                }
            } else {
                false
            };
            let fg = if add_matches.get_flag("forground") {
                true
            } else {
                false
            };
            let ctrl_flags: u64 = if add_matches.get_flag("unprivileged") {
                libublk::sys::UBLK_F_UNPRIVILEGED_DEV as u64
            } else {
                0
            };
            test_add(
                id,
                nr_queues,
                depth,
                buf_size,
                backing_file,
                ctrl_flags,
                fg,
                aio,
                split,
            );
        }
        Some(("del", add_matches)) => {
            let id = add_matches
                .get_one::<String>("number")
                .unwrap()
                .parse::<i32>()
                .unwrap_or(-1);
            UblkCtrl::new_simple(id, 0).unwrap().del_dev().unwrap();
        }
        Some(("list", _add_matches)) => UblkSession::for_each_dev_id(|dev_id| {
            UblkCtrl::new_simple(dev_id as i32, 0).unwrap().dump();
        }),
        _ => {
            println!("unsupported command");
        }
    };
}
