use clap::{Arg, ArgAction, Command};
use libublk::dev_flags::*;
use libublk::io::{UblkDev, UblkIOCtx, UblkQueue};
use libublk::{ctrl::UblkCtrl, exe::Executor, UblkIORes, UblkSession};
use std::rc::Rc;

#[inline]
fn get_io_cmd_result(q: &UblkQueue, tag: u16) -> i32 {
    let iod = q.get_iod(tag);
    let bytes = (iod.nr_sectors << 9) as i32;

    bytes
}

#[inline]
fn handle_io_cmd(q: &UblkQueue, tag: u16) {
    let bytes = get_io_cmd_result(q, tag);
    q.complete_io_cmd(tag, Ok(UblkIORes::Result(bytes)));
}

fn test_add(
    id: i32,
    nr_queues: u32,
    depth: u32,
    ctrl_flags: u64,
    buf_size: u32,
    fg: bool,
    aio: bool,
) {
    let _pid = if !fg { unsafe { libc::fork() } } else { 0 };

    if _pid == 0 {
        __test_add(id, nr_queues, depth, ctrl_flags, buf_size, aio);
    }
}

fn __test_add(id: i32, nr_queues: u32, depth: u32, ctrl_flags: u64, buf_size: u32, aio: bool) {
    {
        let sess = libublk::UblkSessionBuilder::default()
            .name("example_null")
            .id(id)
            .depth(depth)
            .nr_queues(nr_queues)
            .io_buf_bytes(buf_size)
            .ctrl_flags(ctrl_flags)
            .dev_flags(
                UBLK_DEV_F_ADD_DEV
                    | if aio { UBLK_DEV_F_ASYNC } else { 0 }
                    | if (ctrl_flags & libublk::sys::UBLK_F_USER_COPY as u64) != 0 {
                        UBLK_DEV_F_DONT_ALLOC_BUF
                    } else {
                        0
                    },
            )
            .build()
            .unwrap();
        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            Ok(0)
        };
        let (mut ctrl, dev) = sess.create_devices(tgt_init).unwrap();
        // queue level logic
        let q_sync_handler = move |qid: u16, dev: &UblkDev| {
            // logic for io handling
            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                handle_io_cmd(q, tag);
            };

            UblkQueue::new(qid, dev)
                .unwrap()
                .wait_and_handle_io(io_handler);
        };
        let q_async_handler = move |qid: u16, dev: &UblkDev| {
            let q_rc = Rc::new(UblkQueue::new(qid as u16, &dev).unwrap());
            let exe = Executor::new(dev.get_nr_ios());

            for tag in 0..depth as u16 {
                let q = q_rc.clone();

                exe.spawn(tag as u16, async move {
                    let buf_addr = q.get_io_buf_addr(tag);
                    let mut cmd_op = libublk::sys::UBLK_IO_FETCH_REQ;
                    let mut res = 0;
                    loop {
                        let cmd_res = q.submit_io_cmd(tag, cmd_op, buf_addr, res).await;
                        if cmd_res == libublk::sys::UBLK_IO_RES_ABORT {
                            break;
                        }

                        res = get_io_cmd_result(&q, tag);
                        cmd_op = libublk::sys::UBLK_IO_COMMIT_AND_FETCH_REQ;
                    }
                });
            }
            q_rc.wait_and_wake_io_tasks(&exe);
        };

        if aio {
            // Now start this ublk target
            sess.run_target(&mut ctrl, &dev, q_async_handler, |dev_id| {
                let mut d_ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();
                d_ctrl.dump();
            })
            .unwrap();
        } else {
            sess.run_target(&mut ctrl, &dev, q_sync_handler, |dev_id| {
                let mut d_ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();
                d_ctrl.dump();
            })
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
                    Arg::new("forground")
                        .long("forground")
                        .action(ArgAction::SetTrue)
                        .help("run in forground mode"),
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

            let aio = if add_matches.get_flag("async") {
                true
            } else {
                false
            };
            let fg = if add_matches.get_flag("forground") {
                true
            } else {
                false
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

            test_add(id, nr_queues, depth, ctrl_flags, buf_size, fg, aio);
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
