use libublk::io::{UblkDev, UblkIOCtx};
use libublk::{ctrl::UblkCtrl, UblkError};

fn handle_io(io: UblkIOCtx) -> Result<i32, UblkError> {
    let tag = io.3.get_tag();
    let iod = io.1.get_iod(tag);
    let bytes = unsafe { (*iod).nr_sectors << 9 } as i32;

    io.2.complete(bytes);
    Ok(0)
}

fn test_add() {
    let s = std::env::args().nth(2).unwrap_or_else(|| "-1".to_string());
    let dev_id = s.parse::<i32>().unwrap();
    let _pid = unsafe { libc::fork() };
    if _pid == 0 {
        libublk::ublk_tgt_worker(
            "null".to_string(),
            dev_id,
            2,
            64,
            512_u32 * 1024,
            0,
            true,
            |dev: &mut UblkDev| {
                dev.set_default_params(250_u64 << 30);
                Ok(serde_json::json!({}))
            },
            handle_io,
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
