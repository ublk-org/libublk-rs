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
pub mod io;
pub mod sys;

/// feature: support IO batch completion from single IO tag, typical
/// usecase is to complete IOs from eventfd CQE handler
pub const UBLK_DEV_F_COMP_BATCH: u32 = 1u32 << 0;

/// tell UblkCtrl that we are adding one new device
pub const UBLK_DEV_F_ADD_DEV: u32 = 1u32 << 1;

/// tell UblkCtrl that we are recovering one old device
pub const UBLK_DEV_F_RECOVER_DEV: u32 = 1u32 << 2;

const UBLK_DEV_F_ALL: u32 = UBLK_DEV_F_COMP_BATCH | UBLK_DEV_F_ADD_DEV | UBLK_DEV_F_RECOVER_DEV;

pub enum UblkIORes {
    Result(i32),
}

#[derive(thiserror::Error, Debug)]
pub enum UblkError {
    #[error("failed to read the key file")]
    UringSubmissionError(#[source] std::io::Error),

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

    #[error("other failure")]
    OtherError(i32),
}

pub const CDEV_PATH: &str = "/dev/ublkc";
pub const BDEV_PATH: &str = "/dev/ublkb";

pub fn ublk_alloc_buf(size: usize, align: usize) -> *mut u8 {
    let layout = match Layout::from_size_align(size, align) {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut() as *mut u8,
    };
    unsafe { alloc(layout) as *mut u8 }
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

    /// libublk feature flags: UBLK_DEV_F_*
    #[builder(default = "0")]
    dev_flags: u32,
}

impl UblkSession {
    /// create one pair of ublk devices, the 1st one is control device(`UblkCtrl`),
    /// and the 2nd one is data device(`UblkDev`)
    pub fn create_devices<T>(
        &self,
        tgt_fn: T,
    ) -> Result<(ctrl::UblkCtrl, Arc<io::UblkDev>), UblkError>
    where
        T: FnOnce(&mut io::UblkDev) -> Result<serde_json::Value, UblkError>,
    {
        let mut ctrl = ctrl::UblkCtrl::new(
            self.id,
            self.nr_queues,
            self.depth,
            self.io_buf_bytes,
            self.ctrl_flags,
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
        Q: Fn(&io::UblkQueueCtx, &mut io::UblkIOCtx) -> Result<UblkIORes, UblkError>
            + Send
            + Sync
            + Clone
            + 'static,
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
            let _q_fn = q_fn.clone();

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

                let mut queue = io::UblkQueue::new(q, &_dev).unwrap();
                let queue_closure = {
                    let ctx = queue.make_queue_ctx();
                    move |io_ctx: &mut io::UblkIOCtx| _q_fn(&ctx, io_ctx)
                };
                queue.wait_and_handle_io(queue_closure);
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

    /// Kick off the ublk device, and `/dev/ublkbN` will be created and visible
    /// to userspace.
    ///
    /// So far, IO handling closure doesn't support FnMut, and please switch to
    /// low level APIs if your IO handling closure needs to be FnMut.
    ///
    /// This function won't return until the device is removed.
    pub fn run<Q, W>(
        &self,
        ctrl: &mut ctrl::UblkCtrl,
        dev: &Arc<io::UblkDev>,
        io_closure: Q,
        worker_fn: W,
    ) -> Result<std::thread::JoinHandle<()>, UblkError>
    where
        Q: Fn(&io::UblkQueueCtx, &mut io::UblkIOCtx) -> Result<UblkIORes, UblkError>
            + Send
            + Sync
            + Clone
            + 'static,
        W: Fn(i32) + Send + Sync + 'static,
    {
        let handles = self.create_queue_handlers(ctrl, dev, io_closure);

        ctrl.start_dev(dev)?;

        let dev_id = dev.dev_info.dev_id as i32;
        let worker_qh = std::thread::spawn(move || {
            worker_fn(dev_id);
        });

        for qh in handles {
            qh.join().unwrap_or_else(|_| {
                eprintln!("dev-{} join queue thread failed", dev.dev_info.dev_id)
            });
        }

        ctrl.stop_dev(dev)?;

        Ok(worker_qh)
    }
}
