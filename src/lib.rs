use log::error;
use std::alloc::{alloc, dealloc, Layout};
use std::sync::{Arc, Condvar, Mutex};

pub mod ctrl;
pub mod io;
pub mod sys;

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
    let layout = Layout::from_size_align(size, align).unwrap();
    unsafe { alloc(layout) as *mut u8 }
}

pub fn ublk_dealloc_buf(ptr: *mut u8, size: usize, align: usize) {
    let layout = Layout::from_size_align(size, align).unwrap();
    unsafe { dealloc(ptr as *mut u8, layout) };
}

/// Create queue thread handler(high level)
///
/// # Arguments:
///
/// * `ctrl`: UblkCtrl mut reference
/// * `dev`: UblkDev reference, which is required for creating queue
/// * `sq_depth`: uring submission queue depth
/// * `cq_depth`: uring completion queue depth
/// * `ring_flags`: uring flags
/// *  `f`: closure for allocating queue trait object, and Arc() is
/// required since the closure is called for multiple threads
///
/// # Return: Vectors for holding each queue thread JoinHandler and tid
///
/// Note: This method is one high level API, and handles each queue in
/// one dedicated thread. If your target won't take this approach, please
/// don't use this API.
pub fn create_queue_handler<F>(
    ctrl: &mut ctrl::UblkCtrl,
    dev: &Arc<io::UblkDev>,
    sq_depth: u32,
    cq_depth: u32,
    ring_flags: u64,
    f: F,
) -> Vec<std::thread::JoinHandle<()>>
where
    F: Fn() -> Box<dyn io::UblkQueueImpl> + Send + Sync + 'static,
{
    let mut q_threads = Vec::new();
    let mut q_affi = Vec::new();
    let mut q_tids = Vec::new();
    let nr_queues = dev.dev_info.nr_hw_queues;
    let mut tids = Vec::<Arc<(Mutex<i32>, Condvar)>>::with_capacity(nr_queues as usize);
    let arc_fn = Arc::new(f);

    for q in 0..nr_queues {
        let mut affinity = ctrl::UblkQueueAffinity::new();
        ctrl.get_queue_affinity(q as u32, &mut affinity).unwrap();

        let _dev = Arc::clone(dev);
        let _q_id = q;
        let tid = Arc::new((Mutex::new(0_i32), Condvar::new()));
        let _tid = Arc::clone(&tid);
        let _fn = arc_fn.clone();
        let _affinity = affinity;

        q_threads.push(std::thread::spawn(move || {
            let (lock, cvar) = &*_tid;
            unsafe {
                let mut guard = lock.lock().unwrap();
                *guard = libc::gettid();
                cvar.notify_one();
            }
            unsafe {
                libc::pthread_setaffinity_np(
                    libc::pthread_self(),
                    _affinity.buf_len(),
                    _affinity.addr() as *const libc::cpu_set_t,
                );
            }
            let ops: &'static dyn io::UblkQueueImpl = &*Box::leak(_fn());
            io::UblkQueue::new(_q_id, &_dev, sq_depth, cq_depth, ring_flags)
                .unwrap()
                .handler(ops);
        }));
        tids.push(tid);
        q_affi.push(affinity);
    }
    for q in 0..nr_queues {
        let (lock, cvar) = &*tids[q as usize];

        let mut guard = lock.lock().unwrap();
        while *guard == 0 {
            guard = cvar.wait(guard).unwrap();
        }
        q_tids.push(*guard);
    }

    //Now we are up, and build & export json
    ctrl.build_json(dev, q_affi, q_tids);

    q_threads
}

/// create ublk target device (high level)
///
/// # Arguments:
///
/// * `id`: device id, or let driver allocate one if -1 is passed
/// * `nr_queues`: how many hw queues allocated for this device
/// * `depth`: each hw queue's depth
/// * `io_buf_bytes`: max buf size for each IO
/// * `flags`: flags for setting ublk device
/// * `tgt_fn`: closure for allocating Target Trait object
/// * `q_fn`: closure for allocating Target Queue Trait object
/// * `worker_fn`: closure for running workerload
///
/// # Return: JoinHandle of thread for running workload
///
/// Note: This method is one high level API, and handles each queue in
/// one dedicated thread. If your target won't take this approach, please
/// don't use this API.
#[allow(clippy::too_many_arguments)]
pub fn ublk_tgt_worker<T, Q, W>(
    id: i32,
    nr_queues: u32,
    depth: u32,
    io_buf_bytes: u32,
    flags: u64,
    for_add: bool,
    tgt_fn: T,
    q_fn: Q,
    worker_fn: W,
) -> Result<std::thread::JoinHandle<()>, UblkError>
where
    T: Fn() -> Box<dyn io::UblkTgtImpl> + Send + Sync,
    Q: Fn() -> Box<dyn io::UblkQueueImpl> + Send + Sync + 'static,
    W: Fn(i32) + Send + Sync + 'static,
{
    let mut ctrl = ctrl::UblkCtrl::new(id, nr_queues, depth, io_buf_bytes, flags, for_add).unwrap();
    let ublk_dev = Arc::new(io::UblkDev::new(tgt_fn(), &mut ctrl).unwrap());
    let depth = ublk_dev.dev_info.queue_depth as u32;

    let threads = create_queue_handler(&mut ctrl, &ublk_dev, depth, depth, 0, q_fn);

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
