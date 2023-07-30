use core::any::Any;
use libublk::io::{UblkCQE, UblkDev, UblkQueue, UblkQueueCtx, UblkQueueImpl, UblkTgt, UblkTgtImpl};
use libublk::{ctrl::UblkCtrl, UblkError};

struct RamdiskTgt {
    size: u64,
    start: u64,
}

struct RamdiskQueue {}

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
        q: &mut UblkQueue,
        ctx: &UblkQueueCtx,
        e: &UblkCQE,
    ) -> Result<i32, UblkError> {
        let tag = e.get_tag();
        let _iod = ctx.get_iod(tag);
        let iod = unsafe { &*_iod };
        let off = (iod.start_sector << 9) as u64;
        let bytes = (iod.nr_sectors << 9) as u32;
        let op = iod.op_flags & 0xff;
        let tgt = q.dev.ublk_tgt_data_from_queue::<RamdiskTgt>().unwrap();
        let start = tgt.start;
        let buf_addr = q.get_buf_addr(tag);

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

        q.complete_io(tag as u16, bytes as i32);
        Ok(0)
    }
}

fn rd_get_device_size(ctrl: &mut UblkCtrl) -> u64 {
    ctrl.reload_json().unwrap();

    let tgt_val = &ctrl.json["target"];
    let tgt: Result<UblkTgt, _> = serde_json::from_value(tgt_val.clone());
    if let Ok(p) = tgt {
        p.dev_size
    } else {
        0
    }
}

fn test_add(_r: i32) {
    let dev_id: i32 = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "-1".to_string())
        .parse::<i32>()
        .unwrap();
    let s = std::env::args().nth(3).unwrap_or_else(|| "32".to_string());
    let mb = s.parse::<u64>().unwrap();
    let recover_flag = libublk::sys::UBLK_F_USER_RECOVERY as u64;

    //println!("dev_id is {}, recover {}", dev_id, _r);

    let _pid = unsafe { libc::fork() };
    if _pid == 0 {
        let mut size = (mb << 20) as u64;
        if _r > 0 {
            let mut ctrl = UblkCtrl::new(dev_id, 0, 0, 0, 0, false).unwrap();
            size = rd_get_device_size(&mut ctrl);

            ctrl.start_user_recover().unwrap();
        }

        let buf = libublk::ublk_alloc_buf(size as usize, 4096);
        let buf_addr = buf as u64;

        libublk::ublk_tgt_worker(
            dev_id,
            1,
            64,
            512_u32 * 1024,
            recover_flag,
            _r <= 0,
            |_| {
                Box::new(RamdiskTgt {
                    size,
                    start: buf_addr,
                })
            },
            |_| Box::new(RamdiskQueue {}) as Box<dyn UblkQueueImpl>,
            |dev_id| {
                let mut ctrl = UblkCtrl::new(dev_id, 0, 0, 0, 0, false).unwrap();

                ctrl.dump();
            },
        )
        .unwrap()
        .join()
        .unwrap();

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
            "add" => test_add(0),
            "recover" => test_add(1),
            "del" => test_del(),
            _ => todo!(),
        }
    }
}
