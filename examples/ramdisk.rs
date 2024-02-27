use libublk::ctrl::UblkCtrl;
///! # Example of ramdisk
///
/// Serves for covering recovery test[`test_ublk_ramdisk_recovery`],
/// UblkCtrl::start_dev_in_queue() and low level interface example.
///
use libublk::dev_flags::*;
use libublk::helpers::IoBuf;
use libublk::io::{UblkDev, UblkQueue};
use libublk::uring_async::ublk_run_ctrl_task;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

fn handle_io(q: &UblkQueue, tag: u16, buf_addr: *mut u8, start: *mut u8) -> i32 {
    let iod = q.get_iod(tag);
    let off = (iod.start_sector << 9) as u64;
    let bytes = (iod.nr_sectors << 9) as i32;
    let op = iod.op_flags & 0xff;

    match op {
        libublk::sys::UBLK_IO_OP_READ => unsafe {
            libc::memcpy(
                buf_addr as *mut libc::c_void,
                start.wrapping_add(off.try_into().unwrap()) as *mut libc::c_void,
                bytes as usize,
            );
        },
        libublk::sys::UBLK_IO_OP_WRITE => unsafe {
            libc::memcpy(
                start.wrapping_add(off.try_into().unwrap()) as *mut libc::c_void,
                buf_addr as *mut libc::c_void,
                bytes as usize,
            );
        },
        _ => {
            return -libc::EINVAL;
        }
    }

    bytes
}

fn queue_fn<'a>(
    dev: &'a UblkDev,
    dev_buf_addr: *mut u8,
) -> (
    Rc<UblkQueue<'a>>,
    smol::LocalExecutor<'a>,
    Vec<smol::Task<()>>,
) {
    let q_rc = Rc::new(UblkQueue::new(0, &dev).unwrap());
    let exe = smol::LocalExecutor::new();
    let buf_size = q_rc.dev.dev_info.max_io_buf_bytes as usize;
    let depth = q_rc.dev.dev_info.queue_depth;
    let mut f_vec = Vec::new();

    for tag in 0..depth as u16 {
        let q = q_rc.clone();

        f_vec.push(exe.spawn(async move {
            let buffer = IoBuf::<u8>::new(buf_size);
            let addr = buffer.as_mut_ptr();
            let mut cmd_op = libublk::sys::UBLK_IO_FETCH_REQ;
            let mut res = 0;

            loop {
                let cmd_res = q.submit_io_cmd(tag, cmd_op, addr, res).await;
                if cmd_res == libublk::sys::UBLK_IO_RES_ABORT {
                    break;
                }

                res = handle_io(&q, tag, addr, dev_buf_addr);
                cmd_op = libublk::sys::UBLK_IO_COMMIT_AND_FETCH_REQ;
            }
        }));
        exe.try_tick();
    }

    (q_rc, exe, f_vec)
}

fn start_dev_fn(
    ctrl_rc: &Rc<UblkCtrl>,
    dev_arc: &Arc<UblkDev>,
    ctrl_exe: &smol::LocalExecutor,
    q_rc: &Rc<UblkQueue>,
    q_exe: &smol::LocalExecutor,
) -> i32 {
    let res = Rc::new(Mutex::new(0));
    let ctrl_clone = ctrl_rc.clone();
    let dev_clone = dev_arc.clone();
    let res_clone = res.clone();

    // Start device in one dedicated io task
    let task = ctrl_exe.spawn(async move {
        ctrl_clone
            .configure_queue(&dev_clone, 0, unsafe { libc::gettid() })
            .unwrap();

        let r = ctrl_clone.start_dev_async(&dev_clone).await;

        let mut guard = res_clone.lock().unwrap();
        *guard = r.unwrap();
    });
    ublk_run_ctrl_task(&ctrl_exe, &q_rc, &q_exe, &task).unwrap();

    let r = *res.lock().unwrap();

    r
}

///run this ramdisk ublk daemon completely in single context with
///async control command, no need Rust async any more
fn rd_add_dev(dev_id: i32, buf_addr: *mut u8, size: u64, for_add: bool) {
    let dev_flags = if for_add {
        UBLK_DEV_F_ADD_DEV
    } else {
        UBLK_DEV_F_RECOVER_DEV
    };

    let ctrl = Rc::new(
        libublk::ctrl::UblkCtrlBuilder::default()
            .name("example_ramdisk")
            .id(dev_id)
            .nr_queues(1_u16)
            .depth(128_u16)
            .dev_flags(dev_flags)
            .ctrl_flags(libublk::sys::UBLK_F_USER_RECOVERY as u64)
            .build()
            .unwrap(),
    );

    let tgt_init = |dev: &mut UblkDev| {
        dev.set_default_params(size);
        Ok(0)
    };
    let dev = Arc::new(UblkDev::new(ctrl.get_name(), tgt_init, &ctrl).unwrap());
    let ctrl_exe = smol::LocalExecutor::new();

    // spawn async io tasks, and return io task array
    let (q_rc, exe, f_vec) = queue_fn(&dev, buf_addr);

    // start device by running one async control task
    let res = start_dev_fn(&ctrl, &dev, &ctrl_exe, &q_rc, &exe);

    if res >= 0 {
        ctrl.dump();
        libublk::uring_async::ublk_wait_and_handle_ios(&q_rc, &exe);
        smol::block_on(async { futures::future::join_all(f_vec).await });
    } else {
        eprintln!("device can't be started");
    }
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

    let daemonize = daemonize::Daemonize::new()
        .stdout(daemonize::Stdio::keep())
        .stderr(daemonize::Stdio::keep());
    match daemonize.start() {
        Ok(_) => {
            let mut size = (mb << 20) as u64;

            if recover > 0 {
                assert!(dev_id >= 0);
                let ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();
                size = rd_get_device_size(&ctrl);

                ctrl.start_user_recover().unwrap();
            }

            let buf = libublk::helpers::IoBuf::<u8>::new(size as usize);
            rd_add_dev(dev_id, buf.as_mut_ptr(), size, recover == 0);
        }
        Err(_) => panic!(),
    }
}

fn test_del() {
    let s = std::env::args().nth(2).unwrap_or_else(|| "0".to_string());
    let dev_id = s.parse::<i32>().unwrap();
    let ctrl = UblkCtrl::new_simple(dev_id as i32, 0).unwrap();

    ctrl.del_dev().unwrap();
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
            "del" => test_del(),
            _ => todo!(),
        }
    }
}
