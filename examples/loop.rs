use anyhow::Result;
use core::any::Any;
use io_uring::{opcode, squeue, types};
use libublk::io::{UblkDev, UblkQueue, UblkQueueImpl, UblkTgtImpl};
use libublk::{ctrl::UblkCtrl, UblkError};
use log::trace;
use serde::Serialize;
use std::os::unix::io::AsRawFd;

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
impl UblkTgtImpl for LoopTgt {
    fn init_tgt(&self, dev: &UblkDev) -> Result<serde_json::Value, UblkError> {
        trace!("loop: init_tgt {}", dev.dev_info.dev_id);
        let info = dev.dev_info;

        if self.direct_io != 0 {
            unsafe {
                libc::fcntl(self.back_file.as_raw_fd(), libc::F_SETFL, libc::O_DIRECT);
            }
        }

        let mut tgt = dev.tgt.borrow_mut();
        let nr_fds = tgt.nr_fds;

        tgt.fds[nr_fds as usize] = self.back_file.as_raw_fd();
        tgt.nr_fds = nr_fds + 1;

        tgt.dev_size = lo_file_size(&self.back_file).unwrap();

        //todo: figure out correct block size
        tgt.params = libublk::sys::ublk_params {
            types: libublk::sys::UBLK_PARAM_TYPE_BASIC,
            basic: libublk::sys::ublk_param_basic {
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
    fn tgt_type(&self) -> &'static str {
        "loop"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn loop_queue_tgt_io(
    q: &mut UblkQueue,
    tag: u32,
    iod: &libublk::sys::ublksrv_io_desc,
) -> Result<i32, UblkError> {
    let off = (iod.start_sector << 9) as u64;
    let bytes = (iod.nr_sectors << 9) as u32;
    let op = iod.op_flags & 0xff;
    let data = libublk::io::build_user_data(tag as u16, op, 0, true);
    let buf_addr = q.get_buf_addr(tag);

    if op == libublk::sys::UBLK_IO_OP_WRITE_ZEROES || op == libublk::sys::UBLK_IO_OP_DISCARD {
        return Err(UblkError::OtherError(-libc::EINVAL));
    }

    match op {
        libublk::sys::UBLK_IO_OP_FLUSH => {
            let sqe = &opcode::SyncFileRange::new(types::Fixed(1), bytes)
                .offset(off)
                .build()
                .flags(squeue::Flags::FIXED_FILE)
                .user_data(data);
            unsafe {
                q.q_ring.submission().push(sqe).expect("submission fail");
            }
        }
        libublk::sys::UBLK_IO_OP_READ => {
            let sqe = &opcode::Read::new(types::Fixed(1), buf_addr, bytes)
                .offset(off)
                .build()
                .flags(squeue::Flags::FIXED_FILE)
                .user_data(data);
            unsafe {
                q.q_ring.submission().push(sqe).expect("submission fail");
            }
        }
        libublk::sys::UBLK_IO_OP_WRITE => {
            let sqe = &opcode::Write::new(types::Fixed(1), buf_addr, bytes)
                .offset(off)
                .build()
                .flags(squeue::Flags::FIXED_FILE)
                .user_data(data);
            unsafe {
                q.q_ring.submission().push(sqe).expect("submission fail");
            }
        }
        _ => return Err(UblkError::OtherError(-libc::EINVAL)),
    }

    Ok(1)
}

// implement loop IO logic, and it is the main job for writing new ublk target
impl UblkQueueImpl for LoopQueue {
    fn handle_io_cmd(&self, q: &mut UblkQueue, tag: u32) -> Result<i32, UblkError> {
        let _iod = q.get_iod(tag);
        let iod = unsafe { &*_iod };

        loop_queue_tgt_io(q, tag, iod)
    }

    fn tgt_io_done(&self, q: &mut UblkQueue, tag: u32, res: i32, user_data: u64) {
        let cqe_tag = libublk::io::user_data_to_tag(user_data);

        assert!(cqe_tag == tag);

        if res != -(libc::EAGAIN) {
            q.complete_io(tag as u16, res);
        } else {
            let _iod = q.get_iod(tag);
            let iod = unsafe { &*_iod };

            loop_queue_tgt_io(q, tag, iod).unwrap();
        }
    }
}

fn test_add() {
    let back_file = std::env::args().nth(2).unwrap();
    let _pid = unsafe { libc::fork() };

    if _pid == 0 {
        libublk::ublk_tgt_worker(
            -1,
            1,
            64,
            512_u32 * 1024,
            0,
            true,
            |_| {
                Box::new(LoopTgt {
                    back_file: std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&back_file)
                        .unwrap(),
                    direct_io: 1,
                    back_file_path: back_file.clone(),
                })
            },
            |_| Box::new(LoopQueue {}) as Box<dyn UblkQueueImpl>,
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
