use bitflags::bitflags;
use clap::{Arg, ArgAction, Command};
use libublk::dev_flags::*;
use libublk::helpers::IoBuf;
use libublk::io::{UblkDev, UblkIOCtx, UblkQueue};
use libublk::uring_async::ublk_wait_and_handle_ios;
use libublk::{ctrl::UblkCtrl, UblkIORes, UblkSession};
use std::rc::Rc;

bitflags! {
    #[derive(Default)]
    struct NullFlags: u32 {
        const ASYNC = 0b00000001;
        const FOREGROUND = 0b00000010;
        const ONESHOT = 0b00000100;
    }
}

#[inline]
fn get_io_cmd_result(q: &UblkQueue, tag: u16) -> i32 {
    let iod = q.get_iod(tag);
    let bytes = (iod.nr_sectors << 9) as i32;

    bytes
}

#[inline]
fn handle_io_cmd(q: &UblkQueue, tag: u16, buf_addr: *mut u8) {
    let bytes = get_io_cmd_result(q, tag);

    q.complete_io_cmd(tag, buf_addr, Ok(UblkIORes::Result(bytes)));
}

fn test_add(id: i32, nr_queues: u32, depth: u32, ctrl_flags: u64, buf_size: u32, flags: NullFlags) {
    if flags.intersects(NullFlags::FOREGROUND) {
        __test_add(id, nr_queues, depth, ctrl_flags, buf_size, flags);
    } else {
        let daemonize = daemonize::Daemonize::new()
            .stdout(daemonize::Stdio::keep())
            .stderr(daemonize::Stdio::keep());

        match daemonize.start() {
            Ok(_) => __test_add(id, nr_queues, depth, ctrl_flags, buf_size, flags),
            _ => panic!(),
        }
    }
}

fn __test_add(
    id: i32,
    nr_queues: u32,
    depth: u32,
    ctrl_flags: u64,
    buf_size: u32,
    flags: NullFlags,
) {
    let aio = flags.intersects(NullFlags::ASYNC);
    let oneshot = flags.intersects(NullFlags::ONESHOT);
    {
        let sess = libublk::UblkSessionBuilder::default()
            .name("example_null")
            .id(id)
            .depth(depth)
            .nr_queues(nr_queues)
            .io_buf_bytes(buf_size)
            .ctrl_flags(ctrl_flags)
            .dev_flags(UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap();
        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            Ok(0)
        };
        let ctrl = sess.create_ctrl_dev().unwrap();
        let user_copy = (ctrl.dev_info().flags & libublk::sys::UBLK_F_USER_COPY as u64) != 0;
        // queue level logic
        let q_sync_handler = move |qid: u16, dev: &UblkDev| {
            let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
            let bufs = bufs_rc.clone();

            // logic for io handling
            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let buf_addr = if user_copy {
                    std::ptr::null_mut()
                } else {
                    let bufs = bufs_rc.clone();
                    bufs[tag as usize].as_mut_ptr()
                };
                handle_io_cmd(q, tag, buf_addr);
            };

            UblkQueue::new(qid, dev)
                .unwrap()
                .regiser_io_bufs(if user_copy { None } else { Some(&bufs) })
                .submit_fetch_commands(if user_copy { None } else { Some(&bufs) })
                .wait_and_handle_io(io_handler);
        };
        let q_async_handler = move |qid: u16, dev: &UblkDev| {
            let q_rc = Rc::new(UblkQueue::new(qid as u16, &dev).unwrap());
            let exe = smol::LocalExecutor::new();
            let mut f_vec = Vec::new();

            for tag in 0..depth as u16 {
                let q = q_rc.clone();

                f_vec.push(exe.spawn(async move {
                    let buf = IoBuf::<u8>::new(q.dev.dev_info.max_io_buf_bytes as usize);
                    let mut cmd_op = libublk::sys::UBLK_IO_FETCH_REQ;
                    let mut res = 0;
                    let buf_addr = if user_copy {
                        std::ptr::null_mut()
                    } else {
                        buf.as_mut_ptr()
                    };

                    q.register_io_buf(tag, &buf);
                    loop {
                        let cmd_res = q.submit_io_cmd(tag, cmd_op, buf_addr, res).await;
                        if cmd_res == libublk::sys::UBLK_IO_RES_ABORT {
                            break;
                        }

                        res = get_io_cmd_result(&q, tag);
                        cmd_op = libublk::sys::UBLK_IO_COMMIT_AND_FETCH_REQ;
                    }
                }));
            }
            ublk_wait_and_handle_ios(&q_rc, &exe);
            smol::block_on(async { futures::future::join_all(f_vec).await });
        };

        let wh = move |d_ctrl: &UblkCtrl| {
            d_ctrl.dump();
            if oneshot {
                d_ctrl.kill_dev().unwrap();
            }
        };

        // Now start this ublk target
        if aio {
            sess.run_target(&ctrl, tgt_init, q_async_handler, wh)
                .unwrap();
        } else {
            sess.run_target(&ctrl, tgt_init, q_sync_handler, wh)
                .unwrap();
        }
    }
}

fn main() {
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
            let ctrl_flags: u64 = if add_matches.get_flag("user_copy") {
                libublk::sys::UBLK_F_USER_COPY as u64
            } else {
                0
            } | if add_matches.get_flag("unprivileged") {
                libublk::sys::UBLK_F_UNPRIVILEGED_DEV as u64
            } else {
                0
            };

            test_add(id, nr_queues, depth, ctrl_flags, buf_size, flags);
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
