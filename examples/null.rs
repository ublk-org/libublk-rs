use libublk::io::{UblkDev, UblkIOCtx, UblkQueueCtx};
#[cfg(feature = "fat_complete")]
use libublk::UblkFatRes;
use libublk::{ctrl::UblkCtrl, UblkError, UblkIORes};

fn null_add(dev_id: i32, comp_batch: bool) {
    let dflags = if comp_batch {
        libublk::UBLK_DEV_F_COMP_BATCH
    } else {
        0
    };
    println!("IO complete batch {}", comp_batch);
    let sess = libublk::UblkSessionBuilder::default()
        .name("null")
        .depth(64_u32)
        .nr_queues(2_u32)
        .id(dev_id)
        .dev_flags(dflags | libublk::UBLK_DEV_F_ADD_DEV)
        .build()
        .unwrap();

    let tgt_init = |dev: &mut UblkDev| {
        dev.set_default_params(250_u64 << 30);
        Ok(serde_json::json!({}))
    };

    let wh = {
        let (mut ctrl, dev) = sess.create_devices(tgt_init).unwrap();
        #[cfg(feature = "fat_complete")]
        let handle_io_batch =
            move |ctx: &UblkQueueCtx, io: &mut UblkIOCtx| -> Result<UblkIORes, UblkError> {
                let iod = ctx.get_iod(io.get_tag());
                let bytes = unsafe { (*iod).nr_sectors << 9 } as i32;

                Ok(UblkIORes::FatRes(UblkFatRes::BatchRes(vec![(
                    io.get_tag() as u16,
                    bytes,
                )])))
            };

        let handle_io =
            move |ctx: &UblkQueueCtx, io: &mut UblkIOCtx| -> Result<UblkIORes, UblkError> {
                let iod = ctx.get_iod(io.get_tag());
                let bytes = unsafe { (*iod).nr_sectors << 9 } as i32;

                Ok(UblkIORes::Result(bytes))
            };
        #[cfg(not(feature = "fat_complete"))]
        let handle_io_batch = handle_io;

        sess.run(
            &mut ctrl,
            &dev,
            if comp_batch {
                handle_io_batch
            } else {
                handle_io
            },
            |dev_id| {
                let mut d_ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();
                d_ctrl.dump();
            },
        )
        .unwrap()
    };
    wh.join().unwrap();
}

fn null_del() {
    let s = std::env::args().nth(2).unwrap_or_else(|| "0".to_string());
    let dev_id = s.parse::<i32>().unwrap();
    let mut ctrl = UblkCtrl::new_simple(dev_id as i32, 0).unwrap();

    ctrl.del_dev().unwrap();
}

fn main() {
    if let Some(cmd) = std::env::args().nth(1) {
        match cmd.as_str() {
            "add" => {
                let s2 = std::env::args().nth(2).unwrap_or_else(|| "-1".to_string());
                let dev_id = s2.parse::<i32>().unwrap();
                let s3 = std::env::args().nth(3).unwrap_or_else(|| "0".to_string());
                let batch = s3.parse::<i32>().unwrap();

                let _pid = unsafe { libc::fork() };
                if _pid == 0 {
                    null_add(dev_id, batch != 0);
                }
            }
            "del" => null_del(),
            _ => todo!(),
        }
    }
}
