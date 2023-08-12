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
