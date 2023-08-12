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

type QueueFn = fn(&io::UblkQueueCtx, &mut io::UblkIOCtx) -> Result<i32, UblkError>;

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
    MmapError(String),

    #[error("queue down failure")]
    QueueIsDown(String),

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

/// Create queue thread handler(high level)
///
/// # Arguments:
///
/// * `ctrl`: UblkCtrl mut reference
/// * `dev`: UblkDev reference, which is required for creating queue
/// *  `q_fn`: callback for handling io command
///
/// # Return: Vectors for holding each queue thread JoinHandler and tid
///
/// Note: This API is supposed to be used for test code only, and we don't
/// suggest to use it in production project.
pub fn create_queue_handler(
    ctrl: &mut ctrl::UblkCtrl,
    dev: &Arc<io::UblkDev>,
    q_fn: QueueFn,
) -> Vec<std::thread::JoinHandle<()>> {
    use std::sync::mpsc;

    let mut q_threads = Vec::new();
    let nr_queues = dev.dev_info.nr_hw_queues;

    let (tx, rx) = mpsc::channel();

    for q in 0..nr_queues {
        let _dev = Arc::clone(dev);
        let _tx = tx.clone();

        let mut affinity = ctrl::UblkQueueAffinity::new();
        ctrl.get_queue_affinity(q as u32, &mut affinity).unwrap();

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
            let ctx = queue.make_queue_ctx();
            let queue_closure = move |io_ctx: &mut io::UblkIOCtx| q_fn(&ctx, io_ctx);

            queue.wait_and_handle_io(queue_closure);
        }));
    }

    for _q in 0..nr_queues {
        let (qid, tid) = rx.recv().unwrap();
        if let Err(_) = ctrl.configure_queue(dev, qid, tid) {
            println!(
                "create_queue_handler: configure queue failed for {}-{}",
                dev.dev_info.dev_id, qid
            );
        }
    }

    q_threads
}

/// create ublk target device (high level)
///
/// # Arguments:
///
/// * `name`: target type name, such as loop, null, nbd,...
/// * `id`: device id, or let driver allocate one if -1 is passed
/// * `nr_queues`: how many hw queues allocated for this device
/// * `depth`: each hw queue's depth
/// * `io_buf_bytes`: max buf size for each IO
/// * `ctrl_flags`: flags for adding ublk device, which is passed to
///     ublk driver via `sys::ublksrv_ctrl_dev_info.flags`
/// * `for_add`: for adding device or not, false is often for recovering
///     ublk device
/// * `dev_flags`: flags for constructing UblkDev instance
/// * `tgt_fn`: closure for allocating Target Trait object
/// * `q_fn`: closure for allocating Target Queue Trait object
/// * `worker_fn`: closure for running workerload
///
/// # Return: JoinHandle of thread for running workload
///
/// Note: This API is supposed to be used for test code only, and we don't
/// suggest to use it in production project.
#[allow(clippy::too_many_arguments)]
pub fn ublk_tgt_worker<T, W>(
    name: String,
    id: i32,
    nr_queues: u32,
    depth: u32,
    io_buf_bytes: u32,
    ctrl_flags: u64,
    for_add: bool,
    dev_flags: u32,
    tgt_fn: T,
    q_fn: QueueFn,
    worker_fn: W,
) -> Result<std::thread::JoinHandle<()>, UblkError>
where
    T: FnOnce(&mut io::UblkDev) -> Result<serde_json::Value, UblkError>,
    W: Fn(i32) + Send + Sync + 'static,
{
    let mut ctrl =
        ctrl::UblkCtrl::new(id, nr_queues, depth, io_buf_bytes, ctrl_flags, for_add).unwrap();
    let ublk_dev = Arc::new(io::UblkDev::new(name, tgt_fn, &mut ctrl, dev_flags).unwrap());
    let threads = create_queue_handler(&mut ctrl, &ublk_dev, q_fn);

    ctrl.start_dev(&ublk_dev).unwrap();

    let dev_id = ublk_dev.dev_info.dev_id as i32;
    let worker_qh = std::thread::spawn(move || {
        worker_fn(dev_id);
    });

    for qh in threads {
        qh.join().unwrap_or_else(|_| {
            eprintln!("dev-{} join queue thread failed", ublk_dev.dev_info.dev_id)
        });
    }

    ctrl.stop_dev(&ublk_dev).unwrap();

    Ok(worker_qh)
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

    /// true is for adding new device, false is for recovering old one,
    /// need UBLK_F_USER_RECOVERY to be set in `ctrl_flags`
    #[builder(default = "true")]
    for_add: bool,

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
            self.for_add,
        )?;

        let dev = Arc::new(io::UblkDev::new(
            self.name.clone(),
            tgt_fn,
            &mut ctrl,
            self.dev_flags,
        )?);

        Ok((ctrl, dev))
    }

    fn create_queue_handlers<Q>(
        &self,
        ctrl: &mut ctrl::UblkCtrl,
        dev: &Arc<io::UblkDev>,
        q_fn: Q,
    ) -> Vec<std::thread::JoinHandle<()>>
    where
        Q: Fn(&io::UblkQueueCtx, &mut io::UblkIOCtx) -> Result<i32, UblkError>
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
        Q: Fn(&io::UblkQueueCtx, &mut io::UblkIOCtx) -> Result<i32, UblkError>
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
