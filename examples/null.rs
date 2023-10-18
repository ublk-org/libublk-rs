use clap::{Arg, ArgAction, Command};
use libublk::dev_flags::*;
use libublk::io::{UblkDev, UblkIOCtx, UblkQueue};
use libublk::{ctrl::UblkCtrl, UblkIORes, UblkSession};

fn test_add(id: i32, nr_queues: u32, depth: u32, ctrl_flags: u64, buf_size: u32, fg: bool) {
    let _pid = if !fg { unsafe { libc::fork() } } else { 0 };

    if _pid == 0 {
        __test_add(id, nr_queues, depth, ctrl_flags, buf_size);
    }
}

fn __test_add(id: i32, nr_queues: u32, depth: u32, ctrl_flags: u64, buf_size: u32) {
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
            Ok(serde_json::json!({}))
        };
        let wh = {
            let (mut ctrl, dev) = sess.create_devices(tgt_init).unwrap();
            // queue level logic
            let q_handler = move |qid: u16, _dev: &UblkDev| {
                // logic for io handling
                let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                    let iod = q.get_iod(tag);
                    let bytes = unsafe { (*iod).nr_sectors << 9 } as i32;

                    q.complete_io_cmd(tag, Ok(UblkIORes::Result(bytes)));
                };

                UblkQueue::new(qid, _dev)
                    .unwrap()
                    .wait_and_handle_io(io_handler);
            };

            // Now start this ublk target
            sess.run_target(&mut ctrl, &dev, q_handler, |dev_id| {
                let mut d_ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();
                d_ctrl.dump();
            })
            .unwrap()
        };
        wh.join().unwrap();
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

            test_add(id, nr_queues, depth, ctrl_flags, buf_size, fg);
        }
        Some(("del", add_matches)) => {
            let id = add_matches
                .get_one::<String>("number")
                .unwrap()
                .parse::<i32>()
                .unwrap_or(-1);
            UblkCtrl::new_simple(id, 0).unwrap().del().unwrap();
        }
        Some(("list", _add_matches)) => UblkSession::for_each_dev_id(|dev_id| {
            UblkCtrl::new_simple(dev_id as i32, 0).unwrap().dump();
        }),
        _ => {
            println!("unsupported command");
        }
    };
}
