use super::{ctrl::UblkCtrl, sys, UblkError};
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use log::{error, info, trace};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::io::AsRawFd;

pub struct UblkIOCtx<'a, 'b, 'd>(
    &'a mut io_uring::IoUring<io_uring::squeue::Entry>,
    &'b mut UblkIO,
    &'d UblkCQE<'d>,
);

/// Check if this userdata is from target IO
#[inline(always)]
fn is_target_io(user_data: u64) -> bool {
    (user_data & (1_u64 << 63)) != 0
}

impl<'a, 'b, 'd> UblkIOCtx<'a, 'b, 'd> {
    #[inline(always)]
    pub fn get_ring(&mut self) -> &mut io_uring::IoUring<io_uring::squeue::Entry> {
        self.0
    }

    #[inline(always)]
    pub fn result(&self) -> i32 {
        self.2.result()
    }

    #[inline(always)]
    pub fn get_tag(&self) -> u32 {
        self.2.get_tag()
    }

    #[inline(always)]
    pub fn user_data(&self) -> u64 {
        self.2.user_data()
    }

    #[inline(always)]
    pub fn is_tgt_io(&self) -> bool {
        self.2.is_tgt_io()
    }

    #[inline(always)]
    pub fn flags(&self) -> u32 {
        self.2.flags()
    }
    #[inline(always)]
    pub fn io_buf_addr(&self) -> *mut u8 {
        self.1.get_buf_addr()
    }

    #[inline(always)]
    pub fn complete_io(&mut self, res: i32) {
        self.1.complete(res);
    }

    /// Build offset for read from or write to per-io-cmd buffer
    ///
    /// # Arguments:
    ///
    /// * `q_id`: queue id
    /// * `tag`: io command tag
    /// * `offset`: offset to this io-cmd buffer
    ///
    /// The built offset is passed to pread() or pwrite() on device of
    /// /dev/ublkcN for reading data from io command buffer, or writing
    /// data to io command buffer.
    ///
    /// Available if UBLK_F_USER_COPY is enabled.
    ///
    #[inline(always)]
    #[allow(arithmetic_overflow)]
    pub fn ublk_user_copy_pos(q_id: u16, tag: u16, offset: u32) -> u64 {
        assert!((offset & !sys::UBLK_IO_BUF_BITS_MASK) == 0);

        sys::UBLKSRV_IO_BUF_OFFSET as u64
            + ((((q_id as u64) << sys::UBLK_QID_OFF) as u64)
                | ((tag as u64) << sys::UBLK_TAG_OFF) as u64
                | offset as u64)
    }

    /// Build userdata for submitting io via io_uring
    ///
    /// # Arguments:
    ///
    /// * `tag`: io tag, length is 16bit
    /// * `op`: io operation code, length is 8bit
    /// * `tgt_data`: target specific data, at most 39bit (64 - 16 - 8 - 1)
    /// * `is_target_io`: if this userdata is for handling target io, false if
    ///         if it is only for ublk io command
    ///
    /// The built userdata is passed to io_uring for parsing io result
    ///
    #[inline(always)]
    #[allow(arithmetic_overflow)]
    pub fn build_user_data(tag: u16, op: u32, tgt_data: u32, is_target_io: bool) -> u64 {
        assert!((op >> 8) == 0 && (tgt_data >> 16) == 0);

        tag as u64 | (op << 16) as u64 | (tgt_data << 24) as u64 | ((is_target_io as u64) << 63)
    }

    /// Extract tag from userdata
    #[inline(always)]
    pub fn user_data_to_tag(user_data: u64) -> u32 {
        (user_data & 0xffff) as u32
    }

    /// Extract operation code from userdata
    #[inline(always)]
    pub fn user_data_to_op(user_data: u64) -> u32 {
        ((user_data >> 16) & 0xff) as u32
    }
}

struct UblkCQE<'d>(&'d cqueue::Entry, u32);

impl<'a> UblkCQE<'a> {
    #[inline(always)]
    fn result(&self) -> i32 {
        self.0.result()
    }
    #[inline(always)]
    fn user_data(&self) -> u64 {
        self.0.user_data()
    }

    #[inline(always)]
    fn get_tag(&self) -> u32 {
        UblkIOCtx::user_data_to_tag(self.0.user_data())
    }

    #[inline(always)]
    fn is_tgt_io(&self) -> bool {
        is_target_io(self.0.user_data())
    }
    #[inline(always)]
    fn flags(&self) -> u32 {
        self.1
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UblkTgt {
    /// target type
    pub tgt_type: String,

    /// target device size, will be the actual size of /dev/ublkbN
    pub dev_size: u64,

    /// target specific io_ring flags, default is 0
    pub ring_flags: u64,

    /// uring SQ depth, default is queue depth
    pub sq_depth: u16,

    /// uring CQ depth, default is queue depth
    pub cq_depth: u16,

    /// extra io slots, usually for meta data handling or eventfd,
    /// default is 0
    pub extra_ios: u16,

    //const struct ublk_tgt_ops *ops;
    pub fds: [i32; 32],
    pub nr_fds: i32,

    /// could become bigger, is it one issue?
    pub params: sys::ublk_params,
}

pub struct UblkDev {
    pub dev_info: sys::ublksrv_ctrl_dev_info,

    /// reserved for supporting new features
    pub flags: u32,

    //fds[0] points to /dev/ublkcN
    cdev_file: fs::File,

    pub tgt: UblkTgt,
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
    pub fn new<F>(
        tgt_name: String,
        ops: F,
        ctrl: &mut UblkCtrl,
        flags: u32,
    ) -> Result<UblkDev, UblkError>
    where
        F: FnOnce(&mut UblkDev) -> Result<serde_json::Value, UblkError>,
    {
        let info = ctrl.dev_info;
        let mut tgt = UblkTgt {
            tgt_type: tgt_name,
            sq_depth: info.queue_depth,
            cq_depth: info.queue_depth,
            fds: [0_i32; 32],
            ring_flags: 0,
            ..Default::default()
        };

        if flags != 0 {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

        let cdev_path = format!("{}{}", super::CDEV_PATH, info.dev_id);
        let cdev_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(cdev_path)
            .map_err(UblkError::OtherIOError)?;

        tgt.fds[0] = cdev_file.as_raw_fd();
        tgt.nr_fds = 1;

        let mut dev = UblkDev {
            dev_info: info,
            cdev_file,
            tgt,
            flags,
        };

        ctrl.json = ops(&mut dev)?;
        info!("dev {} initialized", dev.dev_info.dev_id);

        Ok(dev)
    }

    //private method for drop
    fn deinit_cdev(&mut self) {
        let id = self.dev_info.dev_id;

        info!("dev {} deinitialized", id);
    }

    pub fn set_default_params(&mut self, dev_size: u64) {
        let info = self.dev_info;

        self.tgt.dev_size = dev_size;
        self.tgt.params = super::sys::ublk_params {
            types: super::sys::UBLK_PARAM_TYPE_BASIC,
            basic: super::sys::ublk_param_basic {
                logical_bs_shift: 9,
                physical_bs_shift: 12,
                io_opt_shift: 12,
                io_min_shift: 12,
                max_sectors: info.max_io_buf_bytes >> 9,
                dev_sectors: dev_size >> 9,
                ..Default::default()
            },
            ..Default::default()
        };
    }
}

impl Drop for UblkDev {
    fn drop(&mut self) {
        self.deinit_cdev();
    }
}

union IOCmd {
    cmd: sys::ublksrv_io_cmd,
    buf: [u8; 16],
}

const UBLK_IO_NEED_FETCH_RQ: u32 = 1_u32 << 0;
const UBLK_IO_NEED_COMMIT_RQ_COMP: u32 = 1_u32 << 1;
const UBLK_IO_FREE: u32 = 1u32 << 2;
const UBLK_IO_TO_QUEUE: u32 = 1u32 << 3;

pub const UBLK_IO_F_FIRST: u32 = 1u32 << 16;
pub const UBLK_IO_F_LAST: u32 = 1u32 << 17;

struct UblkIO {
    buf_addr: *mut u8,
    flags: u32,
    result: i32,
}

impl UblkIO {
    #[inline(always)]
    fn get_buf_addr(&self) -> *mut u8 {
        self.buf_addr
    }

    /// Complete this io command
    ///
    /// # Arguments:
    ///
    /// * `res`: result of handling this io command
    ///
    /// Called from specific target code for completing this io command,
    /// so ublk driver gets notified and complete IO request on
    /// /dev/ublkbN
    ///
    #[inline(always)]
    fn complete(&mut self, res: i32) {
        self.flags |= UBLK_IO_NEED_COMMIT_RQ_COMP | UBLK_IO_FREE | UBLK_IO_TO_QUEUE;
        self.result = res;
    }
}

/// UblkQueue Context info
///
///
/// Can only hold read-only info for UblkQueue, so it is safe to
/// mark it as Copy
#[derive(Copy, Clone)]
pub struct UblkQueueCtx {
    pub depth: u16,
    pub q_id: u16,

    /// io command buffer start address of this queue
    buf_addr: u64,
}

impl UblkQueueCtx {
    /// Return IO command description info represented by `ublksrv_io_desc`
    ///
    /// # Arguments:
    ///
    /// * `tag`: io tag
    ///
    /// Returned `ublksrv_io_desc` data is readonly, and filled by ublk kernel
    /// driver
    ///
    #[inline(always)]
    pub fn get_iod(&self, tag: u32) -> *const sys::ublksrv_io_desc {
        assert!(tag < self.depth as u32);
        (self.buf_addr + tag as u64 * 24) as *const sys::ublksrv_io_desc
    }
}

const UBLK_QUEUE_STOPPING: u32 = 1_u32 << 0;
const UBLK_QUEUE_IDLE: u32 = 1_u32 << 1;
const UBLK_QUEUE_POLL: u32 = 1_u32 << 2;

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
    cqes_idx: usize,
    cqes_cnt: usize,
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
            super::ublk_dealloc_buf(
                io.buf_addr,
                dev.dev_info.max_io_buf_bytes as usize,
                unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() },
            );
        }
    }
}

#[inline(always)]
fn round_up(val: u32, rnd: u32) -> u32 {
    (val + rnd - 1) & !(rnd - 1)
}

impl UblkQueue<'_> {
    #[inline(always)]
    fn cmd_buf_sz(depth: u32) -> u32 {
        let size = depth * core::mem::size_of::<sys::ublksrv_io_desc>() as u32;
        let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;

        round_up(size, page_sz)
    }

    #[inline(always)]
    pub fn make_queue_ctx(&self) -> UblkQueueCtx {
        UblkQueueCtx {
            buf_addr: self.io_cmd_buf,
            depth: self.q_depth.try_into().unwrap(),
            q_id: self.q_id,
        }
    }

    /// New one ublk queue
    ///
    /// # Arguments:
    ///
    /// * `q_id`: queue id, [0, nr_queues)
    /// * `dev`: ublk device reference
    ///
    ///ublk queue is handling IO from driver, so far we use dedicated
    ///io_uring for handling both IO command and IO
    #[allow(clippy::uninit_vec)]
    pub fn new(q_id: u16, dev: &UblkDev) -> Result<UblkQueue, UblkError> {
        let tgt = &dev.tgt;
        let sq_depth = tgt.sq_depth;
        let cq_depth = tgt.cq_depth;

        let ring = IoUring::<squeue::Entry, cqueue::Entry>::builder()
            .setup_cqsize(cq_depth as u32)
            .setup_coop_taskrun()
            .build(sq_depth as u32)
            .map_err(UblkError::OtherIOError)?;

        //todo: apply io_uring flags from tgt.ring_flags

        let depth = dev.dev_info.queue_depth as u32;
        let cdev_fd = dev.cdev_file.as_raw_fd();
        let cmd_buf_sz = UblkQueue::cmd_buf_sz(depth) as usize;

        ring.submitter()
            .register_files(&tgt.fds[0..tgt.nr_fds as usize])
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

        let nr_ios = depth + tgt.extra_ios as u32;
        let mut ios = Vec::<UblkIO>::with_capacity(nr_ios as usize);
        unsafe {
            ios.set_len(nr_ios as usize);
        }

        for i in 0..nr_ios {
            let mut io = &mut ios[i as usize];

            // extra io slot needn't to allocate buffer
            if i < depth {
                io.buf_addr =
                    super::ublk_alloc_buf(dev.dev_info.max_io_buf_bytes as usize, unsafe {
                        libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap()
                    });
                io.flags = UBLK_IO_NEED_FETCH_RQ | UBLK_IO_FREE;
            } else {
                io.buf_addr = std::ptr::null_mut();
                io.flags = 0;
            }
            io.result = -1;
        }

        let mut q = UblkQueue {
            q_id,
            q_depth: depth,
            io_cmd_buf: io_cmd_buf as u64,
            dev,
            cmd_inflight: 0,
            q_state: 0,
            q_ring: ring,
            ios,
            cqes_idx: 0,
            cqes_cnt: 0,
        };
        q.submit_fetch_commands();

        trace!("dev {} queue {} started", dev.dev_info.dev_id, q_id);

        Ok(q)
    }

    pub fn set_poll(&mut self, val: bool) {
        if val {
            self.q_state |= UBLK_QUEUE_POLL;
        } else {
            self.q_state &= !UBLK_QUEUE_POLL;
        }
    }

    pub fn get_poll(&mut self) -> bool {
        self.q_state & UBLK_QUEUE_POLL != 0
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
        let data = UblkIOCtx::build_user_data(tag, cmd_op, 0, false);

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

    /// Submit all commands for fetching IO
    ///
    /// Only called during queue initialization. After queue is setup,
    /// COMMIT_AND_FETCH_REQ command is used for both committing io command
    /// result and fetching new incoming IO
    fn submit_fetch_commands(&mut self) {
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
    #[allow(unused_assignments)]
    fn handle_cqe<F>(&mut self, mut ops: F, e: &UblkCQE)
    where
        F: FnMut(&mut UblkIOCtx) -> Result<i32, UblkError>,
    {
        let data = e.user_data();
        let res = e.result();
        let tag = UblkIOCtx::user_data_to_tag(data);
        let cmd_op = UblkIOCtx::user_data_to_op(data);

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

        if is_target_io(data) {
            let res = e.result();

            if res < 0 && res != -(libc::EAGAIN) {
                let data = e.user_data();
                error!(
                    "{}: failed tgt io: res {} qid {} tag {}, cmd_op {}\n",
                    "handle_tgt_cqe",
                    res,
                    self.q_id,
                    UblkIOCtx::user_data_to_tag(data),
                    UblkIOCtx::user_data_to_op(data)
                );
            }
            ops(&mut UblkIOCtx(
                &mut self.q_ring,
                &mut self.ios[tag as usize],
                e,
            ))
            .unwrap();
            return;
        }

        self.cmd_inflight -= 1;

        if res == sys::UBLK_IO_RES_ABORT || ((self.q_state & UBLK_QUEUE_STOPPING) != 0) {
            self.q_state |= UBLK_QUEUE_STOPPING;
            self.ios[tag as usize].flags &= !UBLK_IO_NEED_FETCH_RQ;
        }

        if res == sys::UBLK_IO_RES_OK as i32 {
            assert!(tag < self.q_depth);
            ops(&mut UblkIOCtx(
                &mut self.q_ring,
                &mut self.ios[tag as usize],
                e,
            ))
            .unwrap();
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
    fn reap_one_event<F>(&mut self, ops: F) -> usize
    where
        F: FnMut(&mut UblkIOCtx) -> Result<i32, UblkError>,
    {
        let idx = self.cqes_idx;
        if idx >= self.cqes_cnt {
            return 0;
        }

        let cqe = self.q_ring.completion().next().unwrap();
        let ublk_cqe = UblkCQE(
            &cqe,
            &if idx == 0 { UBLK_IO_F_FIRST } else { 0 }
                | if idx + 1 == self.cqes_cnt {
                    UBLK_IO_F_LAST
                } else {
                    0
                },
        );
        self.handle_cqe(ops, &ublk_cqe);

        let tag = ublk_cqe.get_tag() as usize;
        if self.ios[tag].flags & UBLK_IO_TO_QUEUE != 0 {
            self.ios[tag].flags &= !UBLK_IO_TO_QUEUE;
            self.queue_io_cmd(tag.try_into().unwrap());
        }

        self.cqes_idx += 1;

        1
    }

    #[inline(always)]
    fn prep_reap_events(&mut self) -> usize {
        self.cqes_cnt = self.q_ring.completion().len();
        self.cqes_idx = 0;

        self.cqes_cnt
    }

    /// Process the incoming IO from io_uring
    ///
    /// # Arguments:
    ///
    /// * `ops`: UblkQueueImpl trait object
    ///
    /// When either io command or target io is coming, we are called for handling
    /// both.
    ///
    /// Note: Return Error in case that queue is down.
    ///
    /// # Arguments of io handling closure:
    ///
    /// * `qctx`: this queue's context info for retrieving iod and so on
    /// * `io`: IO slot, which represents the io command from ublk driver
    /// * `e`: the arrived io_uring cqe, which may represent IO command,
    ///    or any target io_uring IO issued for handling this io command
    ///
    /// Called when one io command is retrieved from ublk kernel driver side,
    /// and target code implements this method for handling io command,
    /// when e.is_target_io() returns false. After io command is done, it
    /// needs to complete by calling UblkIOCtx::complete_io().
    ///
    /// Or called when target IO is completed by io_uring, when e.is_target_io()
    /// returns true.
    ///
    /// In short, this method handles both io cmd and target io. IO command comes
    /// when its CQE is done from ublk driver, and target IO is done when its CQE
    /// is done from io_uring normal operations(FS, network, ...). Both share
    /// same IO tag.
    ///
    /// Note: io command is stored to shared mmap area(`UblkQueue`.`io_cmd_buf`) by
    /// ublk kernel driver, and is indexed by tag. IO command is readonly for
    /// ublk userspace.

    pub fn process_io<F>(&mut self, ops: F) -> Result<i32, UblkError>
    where
        F: FnMut(&mut UblkIOCtx) -> Result<i32, UblkError>,
    {
        let to_wait = if self.get_poll() { 0 } else { 1 };

        info!(
            "dev{}-q{}: to_submit {} inflight cmd {} stopping {}",
            self.dev.dev_info.dev_id,
            self.q_id,
            0,
            self.cmd_inflight,
            (self.q_state & UBLK_QUEUE_STOPPING)
        );

        if self.reap_one_event(ops) > 0 {
            return Ok(0);
        }

        if self.queue_is_done() && self.q_ring.submission().is_empty() {
            return Err(UblkError::QueueIsDown("queue is done".to_string()));
        }

        let ret = self
            .q_ring
            .submit_and_wait(to_wait)
            .map_err(UblkError::UringSubmissionError)?;
        let reapped = self.prep_reap_events();

        info!(
            "submit result {}, reapped {} stop {} idle {}",
            ret,
            reapped,
            (self.q_state & UBLK_QUEUE_STOPPING),
            (self.q_state & UBLK_QUEUE_IDLE)
        );
        Ok(reapped as i32)
    }

    /// Queue IO handler(high level interface)
    ///
    /// # Arguments:
    ///
    /// * `ops`: IO handling closure
    ///
    /// Called in queue context. Won't return unless error is observed.
    ///
    #[inline(always)]
    pub fn handler<F>(&mut self, mut ops: F)
    where
        F: FnMut(&mut UblkIOCtx) -> Result<i32, UblkError>,
    {
        loop {
            match self.process_io(&mut ops) {
                Err(_) => break,
                _ => continue,
            }
        }
    }
}
