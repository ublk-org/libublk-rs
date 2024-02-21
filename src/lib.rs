//! # libublk
//!
//! A library for building linux ublk block device in userspace, see related
//! docs in `<https://github.com/ming1/ubdsrv/blob/master/doc/external_links.rst>`
//! and introduction doc in
//! `<https://github.com/ming1/ubdsrv/blob/master/doc/ublk_intro.pdf>`

use log::error;
use std::alloc::{alloc, dealloc, Layout};
use std::sync::Arc;

pub mod ctrl;
pub mod helpers;
pub mod io;
pub mod sys;
pub mod uring_async;

pub mod dev_flags {
    /// feature: support IO batch completion from single IO tag, typical
    /// usecase is to complete IOs from eventfd CQE handler
    pub const UBLK_DEV_F_COMP_BATCH: u32 = 1u32 << 0;

    /// tell UblkCtrl that we are adding one new device
    pub const UBLK_DEV_F_ADD_DEV: u32 = 1u32 << 1;

    /// tell UblkCtrl that we are recovering one old device
    pub const UBLK_DEV_F_RECOVER_DEV: u32 = 1u32 << 2;

    pub const UBLK_DEV_F_ALL: u32 =
        UBLK_DEV_F_COMP_BATCH | UBLK_DEV_F_ADD_DEV | UBLK_DEV_F_RECOVER_DEV;
}

/// Ublk Fat completion result
pub enum UblkFatRes {
    /// Batch completion
    ///
    /// Vector is returned, and each element(`tag`, `result`) describes one
    /// io command completion result.
    BatchRes(Vec<(u16, i32)>),

    /// Zoned Append completion result
    ///
    /// (`result`, `returned lba`) is included in this result.
    ZonedAppendRes((i32, u64)),
}

/// Ublk IO completion result
///
/// Ok() part of io command completion result `Result<UblkIORes, UblkError>`
pub enum UblkIORes {
    /// normal result
    ///
    /// Completion result of this io command
    Result(i32),

    /// Fat completion result
    #[cfg(feature = "fat_complete")]
    FatRes(UblkFatRes),
}

#[derive(thiserror::Error, Debug)]
pub enum UblkError {
    #[error("failed to read the key file")]
    UringSubmissionError(#[source] std::io::Error),

    #[error("uring submission timeout")]
    UringSubmissionTimeout(i32),

    #[error("failed to push SQE to uring")]
    UringPushError(#[from] io_uring::squeue::PushError),

    #[error("io_uring IO failure")]
    UringIOError(i32),

    #[error("json failure")]
    JsonError(#[from] serde_json::Error),

    #[error("mmap failure")]
    MmapError(i32),

    #[error("queue down failure")]
    QueueIsDown(i32),

    #[error("other IO failure")]
    OtherIOError(#[source] std::io::Error),

    #[error("IO Queued")]
    IoQueued(i32),

    #[error("other failure")]
    OtherError(i32),
}

pub fn ublk_alloc_buf(size: usize, align: usize) -> *mut u8 {
    let layout = match Layout::from_size_align(size, align) {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut(),
    };
    unsafe { alloc(layout) }
}

pub fn ublk_dealloc_buf(ptr: *mut u8, size: usize, align: usize) {
    let layout = match Layout::from_size_align(size, align) {
        Ok(r) => r,
        Err(_) => return,
    };
    unsafe { dealloc(ptr as *mut u8, layout) };
}

#[macro_use]
extern crate derive_builder;

/// UblkSession: build one new ublk control device or recover the old one.
///
/// High level API.
///
/// One limit is that IO handling closure doesn't support FnMut, and low
/// level API doesn't have such limit.
///
#[derive(Default, Builder, Debug)]
#[builder(setter(into))]
#[allow(dead_code)]
pub struct UblkSession {
    /// target type, such as null, loop, ramdisk, or nbd,...
    name: String,

    /// device id: -1 can only be used for adding one new device,
    /// and ublk driver will allocate one new ID for the created device;
    /// otherwise, we are asking driver to create or recover or list
    /// one device with specified ID
    #[builder(default = "-1")]
    id: i32,

    /// how many queues
    #[builder(default = "1_u32")]
    nr_queues: u32,

    /// each queue's IO depth
    #[builder(default = "64_u32")]
    depth: u32,

    /// max size of each IO buffer size, which will be converted to
    /// block layer's queue limit of max hw sectors
    #[builder(default = "524288_u32")]
    io_buf_bytes: u32,

    /// passed to ublk driver via `sys::ublksrv_ctrl_dev_info.flags`,
    /// usually for adding or recovering device
    #[builder(default = "0")]
    ctrl_flags: u64,

    /// store target flags in `sys::ublksrv_ctrl_dev_info.ublksrv_flags`,
    /// which is immutable in the whole device lifetime
    #[builder(default = "0")]
    ctrl_target_flags: u64,

    /// libublk feature flags: UBLK_DEV_F_*
    #[builder(default = "0")]
    dev_flags: u32,
}

impl UblkSession {
    // iterator over each ublk device ID
    pub fn for_each_dev_id<T>(ops: T)
    where
        T: Fn(u32) + Clone + 'static,
    {
        if let Ok(entries) = std::fs::read_dir(ctrl::UblkCtrl::run_dir()) {
            for entry in entries.flatten() {
                let f = entry.path();
                if f.is_file() {
                    if let Some(file_stem) = f.file_stem() {
                        if let Some(stem) = file_stem.to_str() {
                            if let Ok(num) = stem.parse::<u32>() {
                                ops(num);
                            }
                        }
                    }
                }
            }
        }
    }

    /// create one pair of ublk devices, the 1st one is control device(`UblkCtrl`),
    /// and the 2nd one is data device(`UblkDev`)
    pub fn create_devices<T>(
        &self,
        tgt_fn: T,
    ) -> Result<(ctrl::UblkCtrl, Arc<io::UblkDev>), UblkError>
    where
        T: FnOnce(&mut io::UblkDev) -> Result<i32, UblkError>,
    {
        let mut ctrl = ctrl::UblkCtrl::new(
            self.id,
            self.nr_queues,
            self.depth,
            self.io_buf_bytes,
            self.ctrl_flags,
            self.ctrl_target_flags,
            self.dev_flags,
        )?;

        let dev = Arc::new(io::UblkDev::new(self.name.clone(), tgt_fn, &mut ctrl)?);

        Ok((ctrl, dev))
    }

    fn create_queue_handlers<Q>(
        &self,
        ctrl: &mut ctrl::UblkCtrl,
        dev: &Arc<io::UblkDev>,
        q_fn: Q,
    ) -> Vec<std::thread::JoinHandle<()>>
    where
        Q: FnOnce(u16, &io::UblkDev) + Send + Sync + Clone + 'static,
    {
        use std::sync::mpsc;

        let mut q_threads = Vec::new();
        let nr_queues = dev.dev_info.nr_hw_queues;

        let (tx, rx) = mpsc::channel();

        for q in 0..nr_queues {
            let _dev = Arc::clone(dev);
            let _tx = tx.clone();

            let mut affinity = ctrl::UblkQueueAffinity::new();
            ctrl.get_queue_affinity(q as u32, &mut affinity).unwrap();
            let mut _q_fn = q_fn.clone();

            q_threads.push(std::thread::spawn(move || {
                //setup pthread affinity first, so that any allocation may
                //be affine to cpu/memory
                unsafe {
                    libc::pthread_setaffinity_np(
                        libc::pthread_self(),
                        affinity.buf_len(),
                        affinity.addr() as *const libc::cpu_set_t,
                    );
                }
                _tx.send((q, unsafe { libc::gettid() })).unwrap();

                unsafe {
                    const PR_SET_IO_FLUSHER: i32 = 57; //include/uapi/linux/prctl.h
                    libc::prctl(PR_SET_IO_FLUSHER, 0, 0, 0, 0);
                };

                _q_fn(q, &_dev);
            }));
        }

        for _q in 0..nr_queues {
            let (qid, tid) = rx.recv().unwrap();
            if ctrl.configure_queue(dev, qid, tid).is_err() {
                println!(
                    "create_queue_handler: configure queue failed for {}-{}",
                    dev.dev_info.dev_id, qid
                );
            }
        }

        q_threads
    }

    /// Run ublk daemon and kick off the ublk device, and `/dev/ublkbN` will be
    /// created and visible to userspace.
    ///
    /// # Arguments:
    ///
    /// * `ctrl`: UblkCtrl device reference
    /// * `dev`: UblkDev device reference
    /// * `q_fn`: queue handler for setting up the queue and its handler
    /// * `device_fn`: handler called after device is started, run in current
    ///     context
    ///
    /// This one is the preferred interface for creating ublk daemon, and
    /// is friendly for user, such as, user can customize queue setup and
    /// io handler, such as setup async/await for handling io command.
    pub fn run_target<Q, W>(
        &self,
        ctrl: &mut ctrl::UblkCtrl,
        dev: &Arc<io::UblkDev>,
        q_fn: Q,
        device_fn: W,
    ) -> Result<i32, UblkError>
    where
        Q: FnOnce(u16, &io::UblkDev) + Send + Sync + Clone + 'static,
        W: FnOnce(i32) + Send + Sync + 'static,
    {
        let handles = self.create_queue_handlers(ctrl, dev, q_fn);
        let dev_id = dev.dev_info.dev_id as i32;

        ctrl.start_dev(dev)?;

        device_fn(dev_id);

        for qh in handles {
            qh.join().unwrap_or_else(|_| {
                eprintln!("dev-{} join queue thread failed", dev.dev_info.dev_id)
            });
        }

        //device may be deleted from another context, so it is normal
        //to see -ENOENT failure here
        let _ = ctrl.stop_dev(dev);

        Ok(0)
    }
}

#[cfg(test)]
mod libublk {
    use crate::dev_flags::*;
    use crate::io::{UblkDev, UblkIOCtx, UblkQueue};
    use crate::{ctrl::UblkCtrl, UblkError, UblkIORes};
    use crate::{UblkSession, UblkSessionBuilder};
    use std::cell::Cell;
    use std::path::Path;
    use std::rc::Rc;

    #[cfg(not(feature = "fat_complete"))]
    #[test]
    fn test_feature_fat_complete() {
        let sz = core::mem::size_of::<Result<UblkIORes, UblkError>>();
        assert!(sz == 16);
    }

    #[cfg(feature = "fat_complete")]
    #[test]
    fn test_feature_fat_complete() {
        let sz = core::mem::size_of::<Result<UblkIORes, UblkError>>();
        assert!(sz == 32);
    }

    fn __test_ublk_session<T>(w_fn: T) -> String
    where
        T: Fn(i32) + Send + Sync + Clone + 'static,
    {
        let sess = UblkSessionBuilder::default()
            .name("null")
            .depth(16_u32)
            .nr_queues(2_u32)
            .dev_flags(UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap();

        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            dev.set_target_json(serde_json::json!({"null": "test_data" }));
            Ok(0)
        };
        let (mut ctrl, dev) = sess.create_devices(tgt_init).unwrap();
        let q_fn = move |qid: u16, dev: &UblkDev| {
            let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
            let bufs = bufs_rc.clone();

            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let iod = q.get_iod(tag);
                let bytes = (iod.nr_sectors << 9) as i32;
                let bufs = bufs_rc.clone();
                let buf_addr = bufs[tag as usize].as_mut_ptr();

                q.complete_io_cmd(tag, buf_addr, Ok(UblkIORes::Result(bytes)));
            };

            UblkQueue::new(qid, dev)
                .unwrap()
                .regiser_io_bufs(Some(&bufs))
                .submit_fetch_commands(Some(&bufs))
                .wait_and_handle_io(io_handler);
        };

        sess.run_target(&mut ctrl, &dev, q_fn, move |dev_id| {
            w_fn(dev_id);
        })
        .unwrap();

        // could be too strict because of udev
        let bdev = ctrl.get_bdev_path();
        assert!(Path::new(&bdev).exists() == false);

        ctrl.get_cdev_path()
    }

    /// Covers basic ublk device creation and destroying by UblkSession
    /// APIs
    #[test]
    fn test_ublk_session() {
        let cdev = __test_ublk_session(|dev_id| {
            let mut ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();

            assert!(ctrl.get_target_data_from_json().is_some());
            ctrl.kill_dev().unwrap();
        });

        // could be too strict because of udev
        assert!(Path::new(&cdev).exists() == false);
    }

    /// test for_each_dev_id
    #[test]
    fn test_ublk_for_each_dev_id() {
        // Create one ublk device
        let handle = std::thread::spawn(|| {
            let cdev = __test_ublk_session(|dev_id| {
                std::thread::sleep(std::time::Duration::from_millis(1000));
                UblkCtrl::new_simple(dev_id, 0).unwrap().kill_dev().unwrap();
            });
            // could be too strict because of udev
            assert!(Path::new(&cdev).exists() == false);
        });

        std::thread::sleep(std::time::Duration::from_millis(400));
        let cnt_arc = Rc::new(Cell::new(0));
        let cnt = cnt_arc.clone();

        //count all existed ublk devices
        UblkSession::for_each_dev_id(move |dev_id| {
            let ctrl = UblkCtrl::new_simple(dev_id as i32, 0).unwrap();
            cnt.set(cnt.get() + 1);

            let dev_path = ctrl.get_cdev_path();
            assert!(Path::new(&dev_path).exists() == true);
        });

        // we created one
        assert!(cnt_arc.get() > 0);

        handle.join().unwrap();
    }
}
