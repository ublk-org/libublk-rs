use libublk::io::{UblkDev, UblkIOCtx, UblkQueue};
use libublk::{ctrl::UblkCtrl, UblkError, UblkIORes};

fn handle_io(
    io: &mut UblkIOCtx,
    iod: &libublk::sys::ublksrv_io_desc,
    start: u64,
) -> Result<UblkIORes, UblkError> {
    let off = (iod.start_sector << 9) as u64;
    let bytes = (iod.nr_sectors << 9) as u32;
    let op = iod.op_flags & 0xff;
    let buf_addr = io.io_buf_addr();

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
        _ => return Err(UblkError::OtherError(-libc::EINVAL)),
    }

    io.complete_io(bytes as i32);
    Ok(UblkIORes::Result(0))
}

///run this ramdisk ublk daemon completely in single context with
///async control command, no need Rust async any more
fn rd_add_dev(dev_id: i32, buf_addr: u64, size: u64, for_add: bool) {
    let depth = 128;
    let nr_queues = 1;
    let mut ctrl = UblkCtrl::new(
        dev_id,
        nr_queues,
        depth,
        512 << 10,
        libublk::sys::UBLK_F_USER_RECOVERY as u64,
        if for_add {
            libublk::UBLK_DEV_F_ADD_DEV
        } else {
            libublk::UBLK_DEV_F_RECOVER_DEV
        },
    )
    .unwrap();
    let ublk_dev = UblkDev::new(
        "ramdisk".to_string(),
        |dev: &mut UblkDev| {
            dev.set_default_params(size);
            Ok(serde_json::json!({}))
        },
        &mut ctrl,
    )
    .unwrap();

    let mut queue = UblkQueue::new(0, &ublk_dev).unwrap();
    let ctx = queue.make_queue_ctx();
    let qc = move |i: &mut UblkIOCtx| {
        let _iod = ctx.get_iod(i.get_tag());
        let iod = unsafe { &*_iod };

        handle_io(i, iod, buf_addr)
    };
    ctrl.configure_queue(&ublk_dev, 0, unsafe { libc::gettid() })
        .unwrap();

    ctrl.start_dev_in_queue(&ublk_dev, &mut queue, &qc).unwrap();
    ctrl.dump();
    queue.wait_and_handle_io(&qc);
    ctrl.stop_dev(&ublk_dev).unwrap();
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

    ctrl.del().unwrap();
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
