use anyhow::Result;
use io_uring::{opcode, squeue, types};
use libublk::{ublksrv_io_desc, UblkCtrl, UblkDev, UblkIO, UblkQueue, UblkQueueImpl};
use log::trace;
use serde::Serialize;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

#[derive(Debug, Serialize)]
struct LoJson {
    back_file_path: String,
    direct_io: i32,
}

struct LoopTgt {
    back_file_path: String,
    back_file: std::fs::File,
    direct_io: i32,
}
struct LoopQueue {}

fn lo_file_size(f: &std::fs::File) -> Result<u64> {
    if let Ok(meta) = f.metadata() {
        if meta.file_type().is_file() {
            Ok(f.metadata().unwrap().len())
        } else {
            Err(anyhow::anyhow!("unsupported file"))
        }
    } else {
        Err(anyhow::anyhow!("no file meta got"))
    }
}

// setup loop target
impl libublk::UblkTgtImpl for LoopTgt {
    fn init_tgt(&self, dev: &UblkDev) -> Result<serde_json::Value> {
        trace!("loop: init_tgt {}", dev.dev_info.dev_id);
        let info = dev.dev_info;

        if self.direct_io != 0 {
            unsafe {
                libc::fcntl(self.back_file.as_raw_fd(), libc::F_SETFL, libc::O_DIRECT);
            }
        }

        let mut td = dev.tdata.borrow_mut();
        let nr_fds = td.nr_fds;
        td.fds[nr_fds as usize] = self.back_file.as_raw_fd();
        td.nr_fds = nr_fds + 1;

        let mut tgt = dev.tgt.borrow_mut();
        tgt.dev_size = lo_file_size(&self.back_file).unwrap();

        //todo: figure out correct block size
        tgt.params = libublk::ublk_params {
            types: libublk::UBLK_PARAM_TYPE_BASIC,
            basic: libublk::ublk_param_basic {
                logical_bs_shift: 9,
                physical_bs_shift: 12,
                io_opt_shift: 12,
                io_min_shift: 9,
                max_sectors: info.max_io_buf_bytes >> 9,
                dev_sectors: tgt.dev_size >> 9,
                ..Default::default()
            },
            ..Default::default()
        };

        Ok(
            serde_json::json!({"loop": LoJson { back_file_path: self.back_file_path.clone(), direct_io: 1 } }),
        )
    }
    fn deinit_tgt(&self, dev: &UblkDev) {
        trace!("loop: deinit_tgt {}", dev.dev_info.dev_id);
    }
}

fn loop_queue_tgt_io(
    q: &UblkQueue,
    io: &mut UblkIO,
    tag: u32,
    iod: &ublksrv_io_desc,
) -> Result<i32> {
    let off = (iod.start_sector << 9) as u64;
    let bytes = (iod.nr_sectors << 9) as u32;
    let op = iod.op_flags & 0xff;
    let data = libublk::build_user_data(tag as u16, op, 0, true);
    let mut r = q.q_ring.borrow_mut();

    if op == libublk::UBLK_IO_OP_WRITE_ZEROES || op == libublk::UBLK_IO_OP_DISCARD {
        return Err(anyhow::anyhow!("unexpected discard"));
    }

    match op {
        libublk::UBLK_IO_OP_FLUSH => {
            let sqe = &opcode::SyncFileRange::new(types::Fixed(1), bytes)
                .offset(off)
                .build()
                .flags(squeue::Flags::FIXED_FILE)
                .user_data(data);
            unsafe {
                r.submission().push(sqe).expect("submission fail");
            }
        }
        libublk::UBLK_IO_OP_READ => {
            let sqe = &opcode::Read::new(types::Fixed(1), io.buf_addr, bytes)
                .offset(off)
                .build()
                .flags(squeue::Flags::FIXED_FILE)
                .user_data(data);
            unsafe {
                r.submission().push(sqe).expect("submission fail");
            }
        }
        libublk::UBLK_IO_OP_WRITE => {
            let sqe = &opcode::Write::new(types::Fixed(1), io.buf_addr, bytes)
                .offset(off)
                .build()
                .flags(squeue::Flags::FIXED_FILE)
                .user_data(data);
            unsafe {
                r.submission().push(sqe).expect("submission fail");
            }
        }
        _ => return Err(anyhow::anyhow!("unexpected op")),
    }

    Ok(1)
}

// implement loop IO logic, and it is the main job for writing new ublk target
impl libublk::UblkQueueImpl for LoopQueue {
    fn queue_io(&self, q: &UblkQueue, io: &mut UblkIO, tag: u32) -> Result<i32> {
        let _iod = q.get_iod(tag);
        let iod = unsafe { &*_iod };

        loop_queue_tgt_io(q, io, tag, iod)
    }

    fn tgt_io_done(&self, q: &UblkQueue, io: &mut UblkIO, tag: u32, res: i32, user_data: u64) {
        let cqe_tag = libublk::user_data_to_tag(user_data);

        assert!(cqe_tag == tag);

        if res != -(libc::EAGAIN) {
            q.complete_io(io, tag as u16, res);
        } else {
            let _iod = q.get_iod(tag);
            let iod = unsafe { &*_iod };

            loop_queue_tgt_io(q, io, tag, iod).unwrap();
        }
    }
}

// All following functions are just boilerplate code

fn __test_ublk_loop(back_file: String) {
    let mut ctrl = UblkCtrl::new(-1, 1, 128, 512_u32 * 1024, 0, true).unwrap();
    let tgt_type = "loop".to_string();
    let ublk_dev = Arc::new(
        UblkDev::new(
            Box::new(LoopTgt {
                back_file: std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&back_file)
                    .unwrap(),
                direct_io: 1,
                back_file_path: back_file,
            }),
            &mut ctrl,
            &tgt_type,
        )
        .unwrap(),
    );
    let depth = ublk_dev.dev_info.queue_depth as u32;

    let (threads, _) = ctrl.create_queue_handler(
        &ublk_dev,
        depth,
        depth,
        0,
        Arc::new(|| Box::new(LoopQueue {}) as Box<dyn UblkQueueImpl>),
    );

    ctrl.start_dev(&ublk_dev).unwrap();
    ctrl.dump();

    //wait queue threads are done
    for qh in threads {
        qh.join().unwrap();
    }
    ctrl.stop_dev(&ublk_dev).unwrap();
}

fn test_add() {
    let s = std::env::args().nth(2).unwrap();
    let _pid = unsafe { libc::fork() };

    if _pid == 0 {
        __test_ublk_loop(s);
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
