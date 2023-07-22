use io_uring::{cqueue, opcode, squeue, types, IoUring};
use log::{error, info, trace};
use serde::{Deserialize, Serialize};
use std::alloc::{alloc, dealloc, Layout};
use std::any::Any;
use std::cell::RefCell;
use std::fs;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

pub mod ctrl;
pub mod sys;

#[derive(thiserror::Error, Debug)]
pub enum UblkError {
    #[error("failed to read the key file")]
    UringSubmissionError(#[source] std::io::Error),

    #[error("failed to push SQE to uring")]
    UringPushError(#[from] squeue::PushError),

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

#[inline(always)]
fn round_up(val: u32, rnd: u32) -> u32 {
    (val + rnd - 1) & !(rnd - 1)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UblkTgt {
    pub tgt_type: String,
    pub dev_size: u64,
    //const struct ublk_tgt_ops *ops;
    pub params: sys::ublk_params,
}

pub struct UblkTgtData {
    pub fds: [i32; 32],
    pub nr_fds: i32,
}

pub struct UblkDev {
    pub dev_info: sys::ublksrv_ctrl_dev_info,

    // not like C's ops, here ops actually points to one object which
    // implements the trait of UblkTgtImpl
    ops: Box<dyn UblkTgtImpl>,

    //fds[0] points to /dev/ublkcN
    cdev_file: fs::File,

    pub tgt: RefCell<UblkTgt>,
    pub tdata: RefCell<UblkTgtData>,
}

unsafe impl Send for UblkDev {}
unsafe impl Sync for UblkDev {}

impl UblkDev {
    /// New one ublk device
    ///
    /// # Arguments:
    ///
    /// * `ops`: target operation functions
    /// * `ctrl`: control device reference
    /// * `tgt_type`: target type, such as 'loop', 'null', ...
    ///
    /// ublk device is abstraction for target, and prepare for setting
    /// up target. Any target private data can be defined in the data
    /// structure which implements UblkTgtImpl.
    pub fn new(ops: Box<dyn UblkTgtImpl>, ctrl: &mut ctrl::UblkCtrl) -> Result<UblkDev, UblkError> {
        let tgt = UblkTgt {
            tgt_type: ops.tgt_type().to_string(),
            ..Default::default()
        };
        let mut data = UblkTgtData {
            fds: [0_i32; 32],
            nr_fds: 0,
        };

        let info = ctrl.dev_info;
        let cdev_path = format!("{}{}", CDEV_PATH, info.dev_id);
        let cdev_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(cdev_path)
            .map_err(UblkError::OtherIOError)?;

        data.fds[0] = cdev_file.as_raw_fd();
        data.nr_fds = 1;

        let dev = UblkDev {
            ops,
            dev_info: info,
            cdev_file,
            tgt: RefCell::new(tgt),
            tdata: RefCell::new(data),
        };

        ctrl.json = dev.ops.init_tgt(&dev)?;
        info!("dev {} initialized", dev.dev_info.dev_id);

        Ok(dev)
    }

    //private method for drop
    fn deinit_cdev(&mut self) {
        let id = self.dev_info.dev_id;

        self.ops.deinit_tgt(self);
        info!("dev {} deinitialized", id);
    }
}

///
/// Return the target concrete object from UblkTgtImpl trait object
///
/// # parameters
///
/// * `dev`: UblkDev instance
/// * `T`: The concrete target data type
///
/// Use as_any()/Downcast trick for doing this job, see `\[`downcast_trait_object`\]`
/// `<https://bennett.dev/rust/downcast-trait-object/>`
///
#[inline(always)]
pub fn ublk_tgt_data_from_queue<T: 'static>(dev: &UblkDev) -> Result<&T, UblkError> {
    let a = dev.ops.as_any();

    match a.downcast_ref::<T>() {
        Some(b) => Ok(b),
        _ => Err(UblkError::OtherError(-libc::ENOENT)),
    }
}

impl Drop for UblkDev {
    fn drop(&mut self) {
        self.deinit_cdev();
    }
}

pub trait UblkQueueImpl {
    fn queue_io(&self, q: &mut UblkQueue, tag: u32) -> Result<i32, UblkError>;
    #[inline(always)]
    fn tgt_io_done(&self, _q: &mut UblkQueue, _tag: u32, _res: i32, _user_data: u64) {}
    #[inline(always)]
    fn handle_io_background(&self, _q: &UblkQueue, _nr_queued: usize) {}
}

pub trait UblkTgtImpl {
    /// Init this target
    ///
    /// Initialize this target, dev_data is usually built from command line, so
    /// it is produced and consumed by target code.
    fn init_tgt(&self, dev: &UblkDev) -> Result<serde_json::Value, UblkError>;

    /// Deinit this target
    ///
    /// Release target specific resource.
    fn deinit_tgt(&self, dev: &UblkDev) {
        trace!("{}: deinit_tgt {}", self.tgt_type(), dev.dev_info.dev_id);
    }

    fn tgt_type(&self) -> &'static str;

    fn as_any(&self) -> &dyn Any;
}

union IOCmd {
    cmd: sys::ublksrv_io_cmd,
    buf: [u8; 16],
}

#[inline(always)]
#[allow(arithmetic_overflow)]
pub fn ublk_user_copy_pos(q_id: u16, tag: u16, offset: u32) -> u64 {
    assert!((offset & !sys::UBLK_IO_BUF_BITS_MASK) == 0);

    sys::UBLKSRV_IO_BUF_OFFSET as u64
        + ((((q_id as u64) << sys::UBLK_QID_OFF) as u64)
            | ((tag as u64) << sys::UBLK_TAG_OFF) as u64
            | offset as u64)
}

#[inline(always)]
#[allow(arithmetic_overflow)]
pub fn build_user_data(tag: u16, op: u32, tgt_data: u32, is_target_io: bool) -> u64 {
    assert!((op >> 8) == 0 && (tgt_data >> 16) == 0);

    tag as u64 | (op << 16) as u64 | (tgt_data << 24) as u64 | ((is_target_io as u64) << 63)
}

#[inline(always)]
pub fn is_target_io(user_data: u64) -> bool {
    (user_data & (1_u64 << 63)) != 0
}

#[inline(always)]
pub fn user_data_to_tag(user_data: u64) -> u32 {
    (user_data & 0xffff) as u32
}

#[inline(always)]
pub fn user_data_to_op(user_data: u64) -> u32 {
    ((user_data >> 16) & 0xff) as u32
}

const UBLK_IO_NEED_FETCH_RQ: u32 = 1_u32 << 0;
const UBLK_IO_NEED_COMMIT_RQ_COMP: u32 = 1_u32 << 1;
const UBLK_IO_FREE: u32 = 1u32 << 2;

struct UblkIO {
    buf_addr: *mut u8,
    flags: u32,
    result: i32,
}

const UBLK_QUEUE_STOPPING: u32 = 1_u32 << 0;
const UBLK_QUEUE_IDLE: u32 = 1_u32 << 1;

/// UBLK queue abstraction
///
/// Responsible for handling ublk IO from ublk driver.
///
/// So far, each queue is handled by one single io_uring.
///
pub struct UblkQueue<'a> {
    pub q_id: u16,
    pub q_depth: u32,
    io_cmd_buf: u64,
    //ops: Box<dyn UblkQueueImpl>,
    pub dev: &'a UblkDev,
    cmd_inflight: u32,
    q_state: u32,
    ios: Vec<UblkIO>,
    pub q_ring: IoUring<squeue::Entry>,
}

impl Drop for UblkQueue<'_> {
    fn drop(&mut self) {
        let dev = self.dev;
        trace!("dev {} queue {} dropped", dev.dev_info.dev_id, self.q_id);

        if let Err(r) = self.q_ring.submitter().unregister_files() {
            error!("unregister fixed files failed {}", r);
        }

        let depth = dev.dev_info.queue_depth as u32;
        let cmd_buf_sz = UblkQueue::cmd_buf_sz(depth) as usize;

        //unmap, otherwise our cdev won't be released
        unsafe {
            libc::munmap(self.io_cmd_buf as *mut libc::c_void, cmd_buf_sz);
        }

        for i in 0..depth {
            let io = &self.ios[i as usize];
            ublk_dealloc_buf(
                io.buf_addr,
                dev.dev_info.max_io_buf_bytes as usize,
                unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() },
            );
        }
    }
}

impl UblkQueue<'_> {
    #[inline(always)]
    fn cmd_buf_sz(depth: u32) -> u32 {
        let size = depth * core::mem::size_of::<sys::ublksrv_io_desc>() as u32;
        let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;

        round_up(size, page_sz)
    }

    /// New one ublk queue
    ///
    /// # Arguments:
    ///
    /// * `q_id`: queue id, [0, nr_queues)
    /// * `dev`: ublk device reference
    /// * `sq_depth`: io_uring sq depth
    /// * `cq_depth`: io_uring cq depth
    /// * `_ring_flags`: io uring flags for setup this qeuue's uring
    ///
    ///ublk queue is handling IO from driver, so far we use dedicated
    ///io_uring for handling both IO command and IO
    #[allow(clippy::uninit_vec)]
    pub fn new(
        q_id: u16,
        dev: &UblkDev,
        sq_depth: u32,
        cq_depth: u32,
        _ring_flags: u64,
    ) -> Result<UblkQueue, UblkError> {
        let td = dev.tdata.borrow();
        let ring = IoUring::<squeue::Entry, cqueue::Entry>::builder()
            .setup_cqsize(cq_depth)
            .setup_coop_taskrun()
            .build(sq_depth)
            .map_err(UblkError::OtherIOError)?;
        let depth = dev.dev_info.queue_depth as u32;
        let cdev_fd = dev.cdev_file.as_raw_fd();
        let cmd_buf_sz = UblkQueue::cmd_buf_sz(depth) as usize;

        ring.submitter()
            .register_files(&td.fds[0..td.nr_fds as usize])
            .map_err(UblkError::OtherIOError)?;

        let off = sys::UBLKSRV_CMD_BUF_OFFSET as i64
            + q_id as i64
                * ((sys::UBLK_MAX_QUEUE_DEPTH as usize
                    * core::mem::size_of::<sys::ublksrv_io_desc>()) as i64);
        let io_cmd_buf = unsafe {
            libc::mmap(
                std::ptr::null_mut::<libc::c_void>(),
                cmd_buf_sz,
                libc::PROT_READ,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                cdev_fd,
                off as i64,
            )
        };
        if io_cmd_buf == libc::MAP_FAILED {
            return Err(UblkError::MmapError(
                "io cmd buffer mmap failed".to_string(),
            ));
        }

        let mut ios = Vec::<UblkIO>::with_capacity(depth as usize);
        unsafe {
            ios.set_len(depth as usize);
        }
        for io in &mut ios {
            io.buf_addr = ublk_alloc_buf(dev.dev_info.max_io_buf_bytes as usize, unsafe {
                libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap()
            });
            io.flags = UBLK_IO_NEED_FETCH_RQ | UBLK_IO_FREE;
            io.result = -1;
        }

        let q = UblkQueue {
            q_id,
            q_depth: depth,
            io_cmd_buf: io_cmd_buf as u64,
            dev,
            cmd_inflight: 0,
            q_state: 0,
            q_ring: ring,
            ios,
        };

        trace!("dev {} queue {} started", dev.dev_info.dev_id, q_id);

        Ok(q)
    }

    #[inline(always)]
    pub fn get_buf_addr(&self, tag: u32) -> *mut u8 {
        self.ios[tag as usize].buf_addr
    }

    #[inline(always)]
    fn mark_io_done(&mut self, tag: u16, res: i32) {
        self.ios[tag as usize].flags |= UBLK_IO_NEED_COMMIT_RQ_COMP | UBLK_IO_FREE;
        self.ios[tag as usize].result = res;
    }

    #[inline(always)]
    pub fn get_iod(&self, idx: u32) -> *const sys::ublksrv_io_desc {
        (self.io_cmd_buf + idx as u64 * 24) as *const sys::ublksrv_io_desc
    }

    #[inline(always)]
    #[allow(unused_assignments)]
    fn __queue_io_cmd(&mut self, tag: u16) -> i32 {
        let mut cmd_op = 0_u32;
        let io = &self.ios[tag as usize];

        if (io.flags & UBLK_IO_FREE) == 0 {
            return 0;
        }

        if (io.flags & UBLK_IO_NEED_COMMIT_RQ_COMP) != 0 {
            cmd_op = sys::UBLK_IO_COMMIT_AND_FETCH_REQ;
        } else if (io.flags & UBLK_IO_NEED_FETCH_RQ) != 0 {
            cmd_op = sys::UBLK_IO_FETCH_REQ;
        } else {
            return 0;
        }

        let io_cmd = IOCmd {
            cmd: sys::ublksrv_io_cmd {
                tag,
                addr: io.buf_addr as u64,
                q_id: self.q_id,
                result: io.result,
            },
        };
        let data = build_user_data(tag, cmd_op, 0, false);

        let sqe = opcode::UringCmd16::new(types::Fixed(0), cmd_op)
            .cmd(unsafe { io_cmd.buf })
            .build()
            .user_data(data);

        unsafe {
            self.q_ring
                .submission()
                .push(&sqe)
                .expect("submission fail");
        }

        trace!(
            "{}: (qid {} tag {} cmd_op {}) iof {} stopping {}",
            "queue_io_cmd",
            self.q_id,
            tag,
            cmd_op,
            io.flags,
            (self.q_state & UBLK_QUEUE_STOPPING) != 0
        );

        1
    }

    #[inline(always)]
    fn queue_io_cmd(&mut self, tag: u16) -> i32 {
        let res = self.__queue_io_cmd(tag);

        if res > 0 {
            self.cmd_inflight += 1;
            self.ios[tag as usize].flags = 0;
        }

        res
    }

    #[inline(always)]
    pub fn submit_fetch_commands(&mut self) {
        for i in 0..self.q_depth {
            self.queue_io_cmd(i as u16);
        }
    }

    #[inline(always)]
    fn queue_is_idle(&self) -> bool {
        self.cmd_inflight == 0
    }

    #[inline(always)]
    fn queue_is_done(&self) -> bool {
        (self.q_state & UBLK_QUEUE_STOPPING) != 0 && self.queue_is_idle()
    }

    #[inline(always)]
    pub fn complete_io(&mut self, tag: u16, res: i32) {
        self.mark_io_done(tag, res);
        self.queue_io_cmd(tag as u16);
    }

    #[inline(always)]
    fn handle_tgt_cqe(&mut self, ops: &dyn UblkQueueImpl, res: i32, data: u64) {
        let tag = user_data_to_tag(data);

        if res < 0 && res != -(libc::EAGAIN) {
            error!(
                "{}: failed tgt io: res {} qid {} tag {}, cmd_op {}\n",
                "handle_tgt_cqe",
                res,
                self.q_id,
                user_data_to_tag(data),
                user_data_to_op(data)
            );
        }
        ops.tgt_io_done(self, tag, res, data);
    }

    #[inline(always)]
    #[allow(unused_assignments)]
    fn handle_cqe(&mut self, ops: &dyn UblkQueueImpl, e: &cqueue::Entry) {
        let data = e.user_data();
        let res = e.result();
        let tag = user_data_to_tag(data);
        let cmd_op = user_data_to_op(data);

        trace!(
            "{}: res {} (qid {} tag {} cmd_op {} target {}) state {}",
            "handle_cqe",
            res,
            self.q_id,
            tag,
            cmd_op,
            is_target_io(data),
            self.q_state,
        );

        /* Don't retrieve io in case of target io */
        if is_target_io(data) {
            self.handle_tgt_cqe(ops, res, data);
            return;
        }

        self.cmd_inflight -= 1;

        if res == sys::UBLK_IO_RES_ABORT || ((self.q_state & UBLK_QUEUE_STOPPING) != 0) {
            self.q_state |= UBLK_QUEUE_STOPPING;
            self.ios[tag as usize].flags &= !UBLK_IO_NEED_FETCH_RQ;
        }

        if res == sys::UBLK_IO_RES_OK as i32 {
            assert!(tag < self.q_depth);
            ops.queue_io(self, tag).unwrap();
        } else {
            /*
             * COMMIT_REQ will be completed immediately since no fetching
             * piggyback is required.
             *
             * Marking IO_FREE only, then this io won't be issued since
             * we only issue io with (UBLKSRV_IO_FREE | UBLKSRV_NEED_*)
             *
             * */
            self.ios[tag as usize].flags = UBLK_IO_FREE;
        }
    }

    #[inline(always)]
    fn get_cqes(&mut self) -> Vec<cqueue::Entry> {
        self.q_ring.completion().map(Into::into).collect()
    }

    #[inline(always)]
    fn reap_events_uring(&mut self, ops: &dyn UblkQueueImpl) -> usize {
        let cqes = self.get_cqes();
        let count = cqes.len();

        for cqe in cqes {
            self.handle_cqe(ops, &cqe);
        }

        count
    }

    #[inline(always)]
    pub fn process_io(&mut self, ops: &dyn UblkQueueImpl) -> Result<i32, UblkError> {
        info!(
            "dev{}-q{}: to_submit {} inflight cmd {} stopping {}",
            self.dev.dev_info.dev_id,
            self.q_id,
            0,
            self.cmd_inflight,
            (self.q_state & UBLK_QUEUE_STOPPING)
        );

        if self.queue_is_done() && self.q_ring.submission().is_empty() {
            return Err(UblkError::QueueIsDown("queue is done".to_string()));
        }

        let ret = self
            .q_ring
            .submit_and_wait(1)
            .map_err(UblkError::UringSubmissionError)?;
        let reapped = self.reap_events_uring(ops);

        {
            let nr_queued = self.q_ring.submission().len();
            ops.handle_io_background(self, nr_queued);
        }
        info!(
            "submit result {}, reapped {} stop {} idle {}",
            ret,
            reapped,
            (self.q_state & UBLK_QUEUE_STOPPING),
            (self.q_state & UBLK_QUEUE_IDLE)
        );
        Ok(reapped as i32)
    }

    pub fn handler(&mut self, ops: &dyn UblkQueueImpl) {
        self.submit_fetch_commands();
        loop {
            match self.process_io(ops) {
                Err(_) => break,
                _ => continue,
            }
        }
    }
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
    q_fn: Arc<Q>,
    worker_fn: W,
) -> Result<std::thread::JoinHandle<()>, UblkError>
where
    T: Fn() -> Box<dyn UblkTgtImpl> + Send + Sync,
    Q: Fn() -> Box<dyn UblkQueueImpl> + Send + Sync + 'static,
    W: Fn(i32) + Send + Sync + 'static,
{
    let mut ctrl = ctrl::UblkCtrl::new(id, nr_queues, depth, io_buf_bytes, flags, for_add).unwrap();
    let ublk_dev = Arc::new(UblkDev::new(tgt_fn(), &mut ctrl).unwrap());
    let depth = ublk_dev.dev_info.queue_depth as u32;

    let threads = ctrl.create_queue_handler(&ublk_dev, depth, depth, 0, q_fn);

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
