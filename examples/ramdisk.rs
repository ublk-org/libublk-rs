///! # Example of ramdisk
///
/// Serves for covering recovery test[`test_ublk_ramdisk_recovery`],
/// UblkCtrl::start_dev_in_queue() and low level interface example.
///
use libublk::dev_flags::*;
use libublk::io::{UblkDev, UblkQueue};
use libublk::{ctrl::UblkCtrl, exe::Executor, UblkError};
use std::rc::Rc;

fn handle_io(q: &UblkQueue, tag: u16, start: u64) -> i32 {
    let iod = q.get_iod(tag);
    let off = (iod.start_sector << 9) as u64;
    let bytes = (iod.nr_sectors << 9) as i32;
    let op = iod.op_flags & 0xff;
    let buf_addr = q.get_io_buf_addr(tag);

    match op {
        libublk::sys::UBLK_IO_OP_READ => unsafe {
            libc::memcpy(
                buf_addr as *mut libc::c_void,
                (start + off) as *mut libc::c_void,
                bytes as usize,
            );
        },
        libublk::sys::UBLK_IO_OP_WRITE => unsafe {
            libc::memcpy(
                (start + off) as *mut libc::c_void,
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

///run this ramdisk ublk daemon completely in single context with
///async control command, no need Rust async any more
fn rd_add_dev(dev_id: i32, buf_addr: u64, size: u64, for_add: bool) {
    let dev_flags = if for_add {
        UBLK_DEV_F_ADD_DEV
    } else {
        UBLK_DEV_F_RECOVER_DEV
    } | UBLK_DEV_F_ASYNC;

    let depth = 128_u16;
    let sess = libublk::UblkSessionBuilder::default()
        .name("example_ramdisk")
        .id(dev_id)
        .nr_queues(1_u16)
        .depth(depth)
        .dev_flags(dev_flags)
        .ctrl_flags(libublk::sys::UBLK_F_USER_RECOVERY as u64)
        .build()
        .unwrap();

    let tgt_init = |dev: &mut UblkDev| {
        dev.set_default_params(size);
        Ok(0)
    };
    let (mut ctrl, dev) = sess.create_devices(tgt_init).unwrap();

    let exe = Executor::new(dev.get_nr_ios());
    let q_rc = Rc::new(UblkQueue::new(0, &dev).unwrap());

    for tag in 0..depth as u16 {
        let q = q_rc.clone();
        exe.spawn(tag as u16, async move {
            let addr = q.get_io_buf_addr(tag);
            let mut cmd_op = libublk::sys::UBLK_IO_FETCH_REQ;
            let mut res = 0;
            loop {
                let cmd_res = q.submit_io_cmd(tag, cmd_op, addr as u64, res).await;
                if cmd_res == libublk::sys::UBLK_IO_RES_ABORT {
                    break;
                }

                res = handle_io(&q, tag, buf_addr);
                cmd_op = libublk::sys::UBLK_IO_COMMIT_AND_FETCH_REQ;
            }
        });
    }
    ctrl.configure_queue(&dev, 0, unsafe { libc::gettid() })
        .unwrap();

    let (token, buf) = ctrl.submit_start_dev(&dev).unwrap();
    let res = loop {
        let _ = q_rc.flush_and_wake_io_tasks(&exe, 0);
        let _res = ctrl.poll_start_dev(token);
        match _res {
            Ok(res) => break Ok(res),
            Err(UblkError::UringIOError(res)) => {
                if res != -libc::EAGAIN {
                    break Err(UblkError::UringIOError(res));
                }
            }
            Err(r) => break Err(r),
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    libublk::ublk_dealloc_buf(buf.0, buf.1, buf.2);

    match res {
        Ok(res) if res >= 0 => {
            ctrl.dump();
            q_rc.wait_and_wake_io_tasks(&exe);
        }
        _ => {}
    };
    //device may be deleted from another context, so it is normal
    //to see -ENOENT failure here
    let _ = ctrl.stop_dev(&dev);
}

fn rd_get_device_size(ctrl: &mut UblkCtrl) -> u64 {
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

    let _pid = unsafe { libc::fork() };
    if _pid == 0 {
        let mut size = (mb << 20) as u64;

        if recover > 0 {
            assert!(dev_id >= 0);
            let mut ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();
            size = rd_get_device_size(&mut ctrl);

            ctrl.start_user_recover().unwrap();
        }
        let buf = libublk::ublk_alloc_buf(size as usize, 4096);

        rd_add_dev(dev_id, buf as u64, size, recover == 0);

        libublk::ublk_dealloc_buf(buf, size as usize, 4096);
    }
}

fn test_del() {
    let s = std::env::args().nth(2).unwrap_or_else(|| "0".to_string());
    let dev_id = s.parse::<i32>().unwrap();
    let mut ctrl = UblkCtrl::new_simple(dev_id as i32, 0).unwrap();

    ctrl.del_dev().unwrap();
}

fn main() {
    if let Some(cmd) = std::env::args().nth(1) {
        match cmd.as_str() {
            "add" => test_add(0),
            "recover" => test_add(1),
            "del" => test_del(),
            _ => todo!(),
        }
    }
}
