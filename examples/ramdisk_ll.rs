use core::any::Any;
use libublk::io::{UblkCQE, UblkDev, UblkIO, UblkQueue, UblkQueueCtx, UblkQueueImpl, UblkTgtImpl};
use libublk::{ctrl::UblkCtrl, UblkError};
use std::sync::{Arc, Mutex};

struct RamdiskTgt {
    size: u64,
}

struct RamdiskQueue {
    start: u64,
}

// setup ramdisk target
impl UblkTgtImpl for RamdiskTgt {
    fn init_tgt(&self, dev: &UblkDev) -> Result<serde_json::Value, UblkError> {
        dev.set_default_params(self.size);
        Ok(serde_json::json!({}))
    }
    fn tgt_type(&self) -> &'static str {
        "ramdisk"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// implement io logic, and it is the main job for writing new ublk target
impl UblkQueueImpl for RamdiskQueue {
    fn handle_io(
        &self,
        ctx: &UblkQueueCtx,
        io: &mut UblkIO,
        e: &UblkCQE,
    ) -> Result<i32, UblkError> {
        let tag = e.get_tag();
        let _iod = ctx.get_iod(tag);
        let iod = unsafe { &*_iod };
        let off = (iod.start_sector << 9) as u64;
        let bytes = (iod.nr_sectors << 9) as u32;
        let op = iod.op_flags & 0xff;
        let start = self.start;
        let buf_addr = io.get_buf_addr();

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

        io.complete(bytes as i32);
        Ok(0)
    }
}

///run this ramdisk ublk daemon completely in single context with
///async control command, no need Rust async any more
fn rd_add_dev2(dev_id: i32, buf_addr: u64, size: u64) {
    let depth = 128;
    let nr_queues = 1;
    let mut ctrl = UblkCtrl::new(dev_id, nr_queues, depth, 512 << 10, 0, true).unwrap();
    let ublk_dev = UblkDev::new(Box::new(RamdiskTgt { size }), &mut ctrl).unwrap();

    let ops = RamdiskQueue { start: buf_addr };
    let mut queue = UblkQueue::new(0, &ublk_dev).unwrap();
    ctrl.configure_queue(&ublk_dev, 0, unsafe { libc::gettid() }, unsafe {
        libc::pthread_self()
    });

    ctrl.start_dev(&ublk_dev, Some(&mut queue), Some(&ops))
        .unwrap();
    ctrl.dump();
    loop {
        match queue.process_io(&ops, 1) {
            Err(_) => break,
            _ => continue,
        }
    }
    ctrl.stop_dev(&ublk_dev).unwrap();
}

fn rd_add_dev(dev_id: i32, buf_addr: u64, size: u64) {
    let _qid = 0;
    let depth = 128;
    let nr_queues = 1;
    let ctrl_arc = Arc::new(Mutex::new(
        UblkCtrl::new(dev_id, nr_queues, depth, 512 << 10, 0, true).unwrap(),
    ));
    let ctrl_clone = Arc::clone(&ctrl_arc);

    let ublk_dev = {
        let mut ctrl = ctrl_clone.lock().unwrap();

        Arc::new(UblkDev::new(Box::new(RamdiskTgt { size }), &mut ctrl).unwrap())
    };

    // Still need one temp pthread for starting device
    let _dev = Arc::clone(&ublk_dev);
    let _ctrl = Arc::clone(&ctrl_arc);

    let f_ctrl = async_std::task::spawn(async move {
        let mut ctrl = _ctrl.lock().unwrap();
        ctrl.start_dev(&_dev, None, None).unwrap();

        let dev_id = ctrl.dev_info.dev_id;
        let dev_path = format!("{}{}", libublk::BDEV_PATH, dev_id);
        assert!(std::path::Path::new(&dev_path).exists() == true);

        ctrl.dump();
    });

    let _dev1 = Arc::clone(&ublk_dev);
    let f_queue = async_std::task::spawn_local(async move {
        let ops = RamdiskQueue { start: buf_addr };
        let mut queue = UblkQueue::new(_qid, &_dev1).unwrap();

        loop {
            match queue.process_io(&ops, 1) {
                Err(_) => break,
                _ => continue,
            }
        }
    });

    async_std::task::block_on(async {
        f_ctrl.await;
        f_queue.await;
    });

    {
        let mut ctrl = ctrl_clone.lock().unwrap();
        ctrl.stop_dev(&ublk_dev).unwrap();
    }
}

fn test_add(no: usize) {
    let dev_id: i32 = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "-1".to_string())
        .parse::<i32>()
        .unwrap();
    let s = std::env::args().nth(3).unwrap_or_else(|| "32".to_string());
    let mb = s.parse::<u64>().unwrap();

    let _pid = unsafe { libc::fork() };
    if _pid == 0 {
        let size = (mb << 20) as u64;
        let buf = libublk::ublk_alloc_buf(size as usize, 4096);

        if no == 0 {
            rd_add_dev(dev_id, buf as u64, size);
        } else {
            rd_add_dev2(dev_id, buf as u64, size);
        }

        libublk::ublk_dealloc_buf(buf, size as usize, 4096);
    }
}

fn test_del() {
    let s = std::env::args().nth(2).unwrap_or_else(|| "0".to_string());
    let dev_id = s.parse::<i32>().unwrap();
    let mut ctrl = UblkCtrl::new(dev_id as i32, 0, 0, 0, 0, false).unwrap();

    ctrl.del().unwrap();
}

fn main() {
    if let Some(cmd) = std::env::args().nth(1) {
        match cmd.as_str() {
            "add" => test_add(1),
            "add2" => test_add(0),
            "del" => test_del(),
            _ => todo!(),
        }
    }
}
