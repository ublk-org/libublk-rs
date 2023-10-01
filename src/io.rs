#[cfg(feature = "fat_complete")]
use super::UblkFatRes;
use super::{ctrl::UblkCtrl, sys, UblkError, UblkIORes};
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use log::{error, info, trace};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::io::AsRawFd;

/// UblkIOCtx
///
/// When any io_uring CQE is received, libublk lets the target code handle
/// it by IO handling closure. This CQE may represents IO command from
/// /dev/ublkbN, or plain io_uring IO submitted from ublk target code, still
/// in the same IO handling closure.
///
/// If target won't use io_uring to handle IO, eventfd needs to be sent from
/// the real handler context to wakeup ublk queue/io_uring context for
/// driving the machinery. Eventfd gets minimized support with
/// `libublk::UBLK_DEV_F_COMP_BATCH`, and native & generic IO offloading will
/// be added soon.
///
/// UblkIOCtx & UblkQueueCtx provide enough information for target code to
/// handle this CQE and implement target IO handling logic.
///
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
    /// Set LBA for UBLK_IO_ZONE_APPEND
    #[inline(always)]
    pub fn set_zone_append_lab(&mut self, lba: u64) {
        self.1.set_buf_addr(lba)
    }

    /// Return io_uring instance which is shared in queue wide.
    ///
    /// Target IO often needs to handle IO command by io_uring further,
    /// so io_uring instance has to be exposed.
    #[inline(always)]
    pub fn get_ring(&mut self) -> &mut io_uring::IoUring<io_uring::squeue::Entry> {
        self.0
    }

    /// Return CQE's request of this IO, and used for handling target IO by
    /// io_uring. When the target IO is completed, its CQE is coming and we
    /// parse the IO result with result().
    #[inline(always)]
    pub fn result(&self) -> i32 {
        self.2.result()
    }

    /// Get this IO's tag.
    ///
    /// tag is one core concept in libublk.
    ///
    /// Each IO command has its unique tag, which is in [0, depth), and the tag
    /// is originated from ublk driver actually.
    ///
    /// When target IO uses io_uring for handling IO, this tag should be inherited
    /// by passing `tag` via `Self::build_user_data()`
    #[inline(always)]
    pub fn get_tag(&self) -> u32 {
        self.2.get_tag()
    }

    /// Get this CQE's userdata
    ///
    #[inline(always)]
    pub fn user_data(&self) -> u64 {
        self.2.user_data()
    }

    /// Return false if it is one IO command from ublk driver, otherwise
    /// it is one target IO submitted from IO closure
    #[inline(always)]
    pub fn is_tgt_io(&self) -> bool {
        self.2.is_tgt_io()
    }

    /// if this IO represented by CQE is the last one in current batch
    #[inline(always)]
    pub fn is_last_cqe(&self) -> bool {
        (self.2.flags() & UBLK_IO_F_LAST) != 0
    }

    /// if this IO represented by CQE is the first one in current batch
    #[inline(always)]
    pub fn is_first_cqe(&self) -> bool {
        (self.2.flags() & UBLK_IO_F_FIRST) != 0
    }

    /// Return pre-allocated io buffer for this tag.
    ///
    /// Don't use it in case of UBLK_F_USER_COPY, which needs target code
    /// to manage io buffer.
    #[inline(always)]
    pub fn io_buf_addr(&self) -> *mut u8 {
        self.1.get_buf_addr()
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

const UBLK_IO_F_FIRST: u32 = 1u32 << 16;
const UBLK_IO_F_LAST: u32 = 1u32 << 17;

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

/// For supporting ublk device IO path, and one thin layer of device
/// abstract in handling IO level. Ublk device supports multiple queue(MQ),
/// and each queue has its IO depth.
///
/// The `tgt` field provides target code for customizing ublk device, such
/// as defining target specific parameters, exporting its own json output,
/// and so on.
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
    pub fn new<F>(tgt_name: String, ops: F, ctrl: &mut UblkCtrl) -> Result<UblkDev, UblkError>
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
            flags: ctrl.get_dev_flags(),
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

const UBLK_IO_NEED_FETCH_RQ: u16 = 1_u16 << 0;
const UBLK_IO_NEED_COMMIT_RQ_COMP: u16 = 1_u16 << 1;
const UBLK_IO_FREE: u16 = 1u16 << 2;

struct UblkIO {
    // for holding the allocated buffer
    __buf_addr: *mut u8,

    //for sending as io command
    buf_addr: u64,
}

impl UblkIO {
    #[inline(always)]
    fn get_buf_addr(&self) -> *mut u8 {
        self.__buf_addr
    }

    /// for zoned append command only
    /// zoned support is started from linux kernel v6.6
    #[inline(always)]
    fn set_buf_addr(&mut self, addr: u64) {
        self.buf_addr = addr;
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
/// UblkQueue is the core part of the whole stack, which communicates with
/// ublk driver via `io_uring cmd`. When any io command representing one
/// block IO request originating from /dev/ublkbN comes, one uring_cmd CQE
/// is received in ublk userspace side. Basically the whole stack is driven
/// by io_uring CQE(uring_cmd or plain io_uring IO submitted from target
/// code). Here target means the specific ublk device implementation, such
/// as ublk-loop, ublk-zoned, ublk-nbd, ublk-qcow2, ...
///
/// So far, each queue is handled by one its own io_uring.
///
#[allow(dead_code)]
pub struct UblkQueue<'a> {
    flags: u32,
    q_id: u16,
    q_depth: u32,
    io_cmd_buf: u64,
    //ops: Box<dyn UblkQueueImpl>,
    pub dev: &'a UblkDev,
    cmd_inflight: u32,
    q_state: u32,
    cqes_idx: usize,
    cqes_cnt: usize,
    ios: Vec<UblkIO>,
    q_ring: IoUring<squeue::Entry>,
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
                io.__buf_addr,
                dev.dev_info.max_io_buf_bytes as usize,
                unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize },
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
            depth: self.q_depth as u16,
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
            return Err(UblkError::MmapError(unsafe { *libc::__errno_location() }));
        }

        let nr_ios = depth + tgt.extra_ios as u32;
        let mut ios = Vec::<UblkIO>::with_capacity(nr_ios as usize);
        unsafe {
            ios.set_len(nr_ios as usize);
        }

        for i in 0..nr_ios {
            let io = &mut ios[i as usize];

            // extra io slot needn't to allocate buffer
            if i < depth {
                if (dev.dev_info.flags & (super::sys::UBLK_F_USER_COPY as u64)) == 0 {
                    io.__buf_addr =
                        super::ublk_alloc_buf(dev.dev_info.max_io_buf_bytes as usize, unsafe {
                            libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap()
                        });
                } else {
                    io.__buf_addr = std::ptr::null_mut();
                }
            } else {
                io.__buf_addr = std::ptr::null_mut();
            }
            io.buf_addr = io.__buf_addr as u64;
        }

        let mut q = UblkQueue {
            flags: dev.flags,
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

    #[cfg(feature = "fat_complete")]
    fn support_comp_batch(&self) -> bool {
        self.flags & super::UBLK_DEV_F_COMP_BATCH != 0
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
    fn __queue_io_cmd(&mut self, tag: u16, flags: u16, res: i32) -> i32 {
        let mut cmd_op = 0_u32;
        let io = &self.ios[tag as usize];

        if (self.q_state & UBLK_QUEUE_STOPPING) != 0 {
            return 0;
        }

        if (flags & UBLK_IO_FREE) == 0 {
            return 0;
        }

        if (flags & UBLK_IO_NEED_COMMIT_RQ_COMP) != 0 {
            cmd_op = sys::UBLK_IO_COMMIT_AND_FETCH_REQ;
        } else if (flags & UBLK_IO_NEED_FETCH_RQ) != 0 {
            cmd_op = sys::UBLK_IO_FETCH_REQ;
        } else {
            return 0;
        }

        let io_cmd = sys::ublksrv_io_cmd {
            tag,
            addr: io.buf_addr as u64,
            q_id: self.q_id,
            result: res,
        };
        let data = UblkIOCtx::build_user_data(tag, cmd_op, 0, false);

        let sqe = opcode::UringCmd16::new(types::Fixed(0), cmd_op)
            .cmd(unsafe { core::mem::transmute::<sys::ublksrv_io_cmd, [u8; 16]>(io_cmd) })
            .build()
            .user_data(data);

        unsafe {
            self.q_ring
                .submission()
                .push(&sqe)
                .expect("submission fail");
        }

        trace!(
            "{}: (qid {} tag {} cmd_op {}) stopping {}",
            "queue_io_cmd",
            self.q_id,
            tag,
            cmd_op,
            (self.q_state & UBLK_QUEUE_STOPPING) != 0
        );

        1
    }

    #[inline(always)]
    fn queue_io_cmd(&mut self, tag: u16, flags: u16, io_cmd_result: i32) -> i32 {
        let res = self.__queue_io_cmd(tag, flags, io_cmd_result);

        if res > 0 {
            self.cmd_inflight += 1;
        }

        res
    }

    #[inline(always)]
    fn check_and_queue_io_cmd(&mut self, tag: u16, io_cmd_result: i32) {
        let flags = UBLK_IO_NEED_COMMIT_RQ_COMP | UBLK_IO_FREE;
        self.queue_io_cmd(tag, flags, io_cmd_result);
    }

    /// Submit all commands for fetching IO
    ///
    /// Only called during queue initialization. After queue is setup,
    /// COMMIT_AND_FETCH_REQ command is used for both committing io command
    /// result and fetching new incoming IO
    fn submit_fetch_commands(&mut self) {
        for i in 0..self.q_depth {
            let flags = UBLK_IO_NEED_FETCH_RQ | UBLK_IO_FREE;
            self.queue_io_cmd(i as u16, flags, -1);
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
    #[cfg(feature = "fat_complete")]
    fn complete_ios(&mut self, tag: usize, res: Result<UblkIORes, UblkError>) {
        match res {
            Ok(UblkIORes::Result(res))
            | Err(UblkError::OtherError(res))
            | Err(UblkError::UringIOError(res)) => {
                self.check_and_queue_io_cmd(tag as u16, res);
            }
            Err(UblkError::IoQueued(_)) => {}
            Ok(UblkIORes::FatRes(fat)) => match fat {
                UblkFatRes::BatchRes(ios) => {
                    assert!(self.support_comp_batch());
                    for item in ios {
                        let tag = item.0;
                        self.check_and_queue_io_cmd(tag, item.1);
                    }
                }
            },
            _ => {}
        };
    }

    #[inline(always)]
    #[cfg(not(feature = "fat_complete"))]
    fn complete_ios(&mut self, tag: usize, res: Result<UblkIORes, UblkError>) {
        match res {
            Ok(UblkIORes::Result(res))
            | Err(UblkError::OtherError(res))
            | Err(UblkError::UringIOError(res)) => {
                self.check_and_queue_io_cmd(tag as u16, res);
            }
            Err(UblkError::IoQueued(_)) => {}
            _ => {}
        };
    }

    #[inline(always)]
    fn call_io_closure<F>(&mut self, mut ops: F, tag: u32, e: &UblkCQE)
    where
        F: FnMut(&mut UblkIOCtx) -> Result<UblkIORes, UblkError>,
    {
        let mut ctx = UblkIOCtx(&mut self.q_ring, &mut self.ios[tag as usize], e);

        let res = ops(&mut ctx);
        self.complete_ios(tag as usize, res);
    }

    #[inline(always)]
    #[allow(unused_assignments)]
    fn handle_cqe<F>(&mut self, ops: F, e: &UblkCQE)
    where
        F: FnMut(&mut UblkIOCtx) -> Result<UblkIORes, UblkError>,
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
            self.call_io_closure(ops, tag, e);
            return;
        }

        self.cmd_inflight -= 1;

        if res == sys::UBLK_IO_RES_ABORT {
            self.q_state |= UBLK_QUEUE_STOPPING;
        }

        if res == sys::UBLK_IO_RES_OK as i32 {
            assert!(tag < self.q_depth);
            self.call_io_closure(ops, tag, e);
        }
    }

    #[inline(always)]
    fn reap_one_event<F>(&mut self, ops: F) -> usize
    where
        F: FnMut(&mut UblkIOCtx) -> Result<UblkIORes, UblkError>,
    {
        let idx = self.cqes_idx;
        if idx >= self.cqes_cnt {
            return 0;
        }

        let cqe = match self.q_ring.completion().next() {
            None => return 0,
            Some(r) => r,
        };

        let ublk_cqe = UblkCQE(
            &cqe,
            if idx == 0 { UBLK_IO_F_FIRST } else { 0 }
                | if idx + 1 == self.cqes_cnt {
                    UBLK_IO_F_LAST
                } else {
                    0
                },
        );
        self.handle_cqe(ops, &ublk_cqe);

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
    /// * `ops`: IO handling Closure
    ///
    /// When either io command or target io is coming, we are called for
    /// handling both. Basically the IO handling closure is called for
    /// every incoming io_uring CQE.
    ///
    /// About IO handling Closure
    ///
    /// Target IO handling needs target code to implement the IO handling
    /// closure.
    ///
    /// If IO is super fast to complete, such as ramdisk, this request can
    /// be handled directly in the closure, and return `Ok(UblkIORes::Result)`
    /// to complete the IO command originated from ublk driver. Another
    /// example is null target(null.rs).
    ///
    /// Most of times, IO is slow, so it needs to be handled asynchronously.
    /// The preferred way is to submit target IO by io_uring in IO handling
    /// closure by using the same IO slot(represented by `tag`). After this
    /// target IO is completed, one io_uring CQE will be received, and the
    /// same IO closure is called for handling this target IO, which can be
    /// checked by `UblkIOCtx::is_tgt_io()` method. Finally if the coming
    /// target IO completion means the original IO command is done,
    /// `Ok(UblkIORes::Result)` is returned for moving on, otherwise UblkError::IoQueued(_)
    /// can be returned and the IO handling closure can continue to submit IO
    /// or whatever for driving its IO logic.
    ///
    /// Not all target IO logics can be done by io_uring, such as some
    /// handling needs extra computation, which often require to offload IO
    /// in another context. However, when target IO is done in remote offload
    /// context, `Ok(UblkIORes::Result)` has to be returned from the queue/
    /// io_uring context. One approach is to use eventfd to wakeup & notify
    /// ublk queue/io_uring. Here, eventfd can be thought as one special target
    /// IO. Inside IO closure, eventfd is queued by io_uring opcode::PollAdd.
    /// Once target IO handling is done, write(eventfd) can wakeup/notify ublk
    /// queue & io_uring, then IO closure can get chance to handle all completed
    /// IOs. Unfortunately, each IO command(originated from ublk driver) can
    /// only use its own `UblkIOCtx` to complete itself. But one eventfd is
    /// often reused for the whole queue, so normally multiple IOs are completed
    /// when handling single eventfd CQE. Here IO completion batch feature is
    /// provided, and target code can return UblkFatRes::BatchRes(batch) to
    /// cover each completed IO(tag, result) in io closure. Then, all these
    /// added IOs will be completed automatically.
    pub fn process_io<F>(&mut self, ops: F) -> Result<i32, UblkError>
    where
        F: FnMut(&mut UblkIOCtx) -> Result<UblkIORes, UblkError>,
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
            return Err(UblkError::QueueIsDown(-libc::ENODEV));
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

    /// Wait and handle incoming IO
    ///
    /// # Arguments:
    ///
    /// * `ops`: IO handling closure
    ///
    /// Called in queue context. won't return unless error is observed.
    /// Wait and handle any incoming cqe until queue is down.
    ///
    #[inline(always)]
    pub fn wait_and_handle_io<F>(&mut self, mut ops: F)
    where
        F: FnMut(&mut UblkIOCtx) -> Result<UblkIORes, UblkError>,
    {
        loop {
            match self.process_io(&mut ops) {
                Err(_) => break,
                _ => continue,
            }
        }
    }
}
