use core::any::Any;
use libublk::io::{UblkDev, UblkQueue, UblkQueueImpl, UblkTgtImpl};
use libublk::{ctrl::UblkCtrl, UblkError};

pub struct NullTgt {}
pub struct NullQueue {}

// setup null target
impl UblkTgtImpl for NullTgt {
    fn init_tgt(&self, dev: &UblkDev) -> Result<serde_json::Value, UblkError> {
        let info = dev.dev_info;
        let dev_size = 250_u64 << 30;

        let mut tgt = dev.tgt.borrow_mut();

        tgt.dev_size = dev_size;
        tgt.params = libublk::sys::ublk_params {
            types: libublk::sys::UBLK_PARAM_TYPE_BASIC,
            basic: libublk::sys::ublk_param_basic {
                logical_bs_shift: 9,
                physical_bs_shift: 12,
                io_opt_shift: 12,
                io_min_shift: 9,
                max_sectors: info.max_io_buf_bytes >> 9,
                dev_sectors: dev_size >> 9,
                ..Default::default()
            },
            ..Default::default()
        };

        Ok(serde_json::json!({}))
    }
    fn tgt_type(&self) -> &'static str {
        "null"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// implement io logic, and it is the main job for writing new ublk target
impl libublk::io::UblkQueueImpl for NullQueue {
    fn queue_io(&self, q: &mut UblkQueue, tag: u32) -> Result<i32, UblkError> {
        let iod = q.get_iod(tag);
        let bytes = unsafe { (*iod).nr_sectors << 9 } as i32;

        q.complete_io(tag as u16, bytes);
        Ok(0)
    }
}

fn test_add() {
    let s = std::env::args().nth(2).unwrap_or_else(|| "-1".to_string());
    let dev_id = s.parse::<i32>().unwrap();
    let _pid = unsafe { libc::fork() };
    if _pid == 0 {
        libublk::ublk_tgt_worker(
            dev_id,
            2,
            64,
            512_u32 * 1024,
            0,
            true,
            |_| Box::new(NullTgt {}),
            |_| Box::new(NullQueue {}) as Box<dyn UblkQueueImpl>,
            |dev_id| {
                let mut ctrl = UblkCtrl::new(dev_id, 0, 0, 0, 0, false).unwrap();

                ctrl.dump();
            },
        )
        .unwrap()
        .join()
        .unwrap();
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
            "add" => test_add(),
            "del" => test_del(),
            _ => todo!(),
        }
    }
}
