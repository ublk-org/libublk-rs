use libublk::io::{UblkDev, UblkIOCtx, UblkQueue, UblkQueueCtx};
use libublk::{ctrl::UblkCtrl, UblkError};
use std::sync::Arc;

fn null_handle_io(ctx: &UblkQueueCtx, io: &mut UblkIOCtx, park: bool) -> Result<i32, UblkError> {
    let iod = ctx.get_iod(io.get_tag());
    let bytes = unsafe { (*iod).nr_sectors << 9 } as i32;

    if !park {
        io.complete_io(bytes);
        Ok(0)
    } else {
        io.add_to_comp_batch(io.get_tag() as u16, bytes);
        Ok(libublk::io::UBLK_IO_S_COMP_BATCH)
    }
}
fn test_add(dev_id: i32) {
    let s = std::env::args().nth(3).unwrap_or_else(|| "0".to_string());
    let park = s.parse::<i32>().unwrap();
    let nr_queues = 2; //two queues
                       //io depth: 64, max buf size: 512KB
    let dflags = if park != 0 {
        libublk::UBLK_DEV_F_COMP_BATCH
    } else {
        0
    };
    let mut ctrl = UblkCtrl::new(
        dev_id,
        nr_queues,
        64,
        512 << 10,
        0,
        libublk::UBLK_DEV_F_ADD_DEV | dflags,
    )
    .unwrap();

    //target specific initialization is done in this closure
    let tgt_init = |dev: &mut UblkDev| {
        dev.set_default_params(250_u64 << 30);
        Ok(serde_json::json!({}))
    };
    let ublk_dev =
        std::sync::Arc::new(UblkDev::new("null".to_string(), tgt_init, &mut ctrl).unwrap());
    let mut threads = Vec::new();

    println!("park completed IO {}", park);

    for q in 0..nr_queues {
        let dev = Arc::clone(&ublk_dev);
        threads.push(std::thread::spawn(move || {
            let mut queue = UblkQueue::new(q as u16, &dev).unwrap();
            let ctx = queue.make_queue_ctx();

            //IO handling closure(FnMut), we are driven by io_uring CQE, and
            //this closure is called for every incoming CQE(io command or
            //target io completion)
            let io_handler = move |io: &mut UblkIOCtx| null_handle_io(&ctx, io, park != 0);
            queue.wait_and_handle_io(io_handler);
        }));
    }
    ctrl.start_dev(&ublk_dev).unwrap();
    ctrl.dump();
    for qh in threads {
        qh.join().unwrap();
    }
    ctrl.stop_dev(&ublk_dev).unwrap();
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
            "add" => {
                let s = std::env::args().nth(2).unwrap_or_else(|| "-1".to_string());
                let dev_id = s.parse::<i32>().unwrap();
                let _pid = unsafe { libc::fork() };
                if _pid == 0 {
                    test_add(dev_id);
                }
            }
            "del" => test_del(),
            _ => todo!(),
        }
    }
}
