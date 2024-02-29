use super::uring_async::UblkUringOpFuture;
#[cfg(feature = "fat_complete")]
use super::UblkFatRes;
use super::{ctrl::UblkCtrl, sys, UblkError, UblkFlags, UblkIORes};
use crate::helpers::IoBuf;
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fs;
use std::os::unix::io::{AsRawFd, RawFd};

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
/// `dev_flags::UBLK_DEV_F_COMP_BATCH`, and native & generic IO offloading will
/// be added soon.
///
/// UblkIOCtx & UblkQueue provide enough information for target code to
/// handle this CQE and implement target IO handling logic.
///
pub struct UblkIOCtx<'a>(&'a cqueue::Entry, u32);

impl<'a> UblkIOCtx<'a> {
    const UBLK_IO_F_FIRST: u32 = 1u32 << 16;
    const UBLK_IO_F_LAST: u32 = 1u32 << 17;

    /// Return CQE's request of this IO, and used for handling target IO by
    /// io_uring. When the target IO is completed, its CQE is coming and we
    /// parse the IO result with result().
    #[inline(always)]
    pub fn result(&self) -> i32 {
        self.0.result()
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
        UblkIOCtx::user_data_to_tag(self.0.user_data())
    }

    /// Get this CQE's userdata
    ///
    #[inline(always)]
    pub fn user_data(&self) -> u64 {
        self.0.user_data()
    }

    /// Return false if it is one IO command from ublk driver, otherwise
    /// it is one target IO submitted from IO closure
    #[inline(always)]
    pub fn is_tgt_io(&self) -> bool {
        Self::is_target_io(self.0.user_data())
    }

    /// if this IO represented by CQE is the last one in current batch
    #[inline(always)]
    pub fn is_last_cqe(&self) -> bool {
        (self.1 & Self::UBLK_IO_F_LAST) != 0
    }

    /// if this IO represented by CQE is the first one in current batch
    #[inline(always)]
    pub fn is_first_cqe(&self) -> bool {
        (self.1 & Self::UBLK_IO_F_FIRST) != 0
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
        assert!((tgt_data >> 16) == 0);

        let op = op & 0xff;
        tag as u64 | (op << 16) as u64 | (tgt_data << 24) as u64 | ((is_target_io as u64) << 63)
    }

    /// Build userdata for async io_uring OP
    ///
    /// # Arguments:
    /// * `tag`: io tag, length is 16bit
    /// * `op`: io operation code, length is 8bit
    /// * `op_id`: unique id in io task
    ///
    /// The built userdata has to be unique in this io task, so that
    /// our executor can figure out the exact submitted OP with
    /// completed cqe
    #[inline(always)]
    pub fn build_user_data_async(tag: u16, op: u32, op_id: u32) -> u64 {
        Self::build_user_data(tag, op, op_id, true)
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

    /// Check if this userdata is from target IO
    #[inline(always)]
    fn is_target_io(user_data: u64) -> bool {
        (user_data & (1_u64 << 63)) != 0
    }

    /// Check if this userdata is from IO command which is from
    /// ublk driver
    #[inline(always)]
    fn is_io_command(user_data: u64) -> bool {
        (user_data & (1_u64 << 63)) == 0
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
    pub flags: UblkFlags,

    //fds[0] points to /dev/ublkcN
    cdev_file: fs::File,

    pub tgt: UblkTgt,
    tgt_json: Option<serde_json::Value>,
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
    pub fn new<F>(tgt_name: String, ops: F, ctrl: &UblkCtrl) -> Result<UblkDev, UblkError>
    where
        F: FnOnce(&mut UblkDev) -> Result<i32, UblkError>,
    {
        let info = ctrl.dev_info();
        let mut tgt = UblkTgt {
            tgt_type: tgt_name,
            sq_depth: info.queue_depth,
            cq_depth: info.queue_depth,
            fds: [0_i32; 32],
            ring_flags: 0,
            ..Default::default()
        };
        let mut cnt = 0;
        let cdev_path = ctrl.get_cdev_path();

        // ublk char device setup(udev event handling, ...) may not be done
        // successfully, so wait a while. And the timeout is set as 3sec now.
        let cdev_file = loop {
            let f_result = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&cdev_path);

            if let Ok(f) = f_result {
                break f;
            }

            cnt += 1;
            std::thread::sleep(std::time::Duration::from_millis(10));
            if cnt >= 300 {
                return Err(UblkError::OtherError(-libc::EACCES));
            }
        };

        tgt.fds[0] = cdev_file.as_raw_fd();
        tgt.nr_fds = 1;

        let mut dev = UblkDev {
            dev_info: info,
            cdev_file,
            tgt,
            flags: ctrl.get_dev_flags(),
            tgt_json: None,
        };

        ops(&mut dev)?;
        log::info!("dev {} initialized", dev.dev_info.dev_id);

        Ok(dev)
    }

    //private method for drop
    fn deinit_cdev(&mut self) {
        let id = self.dev_info.dev_id;

        log::info!("dev {} deinitialized", id);
    }

    /// Allocate IoBufs for one queue
    pub fn alloc_queue_io_bufs(&self) -> Vec<IoBuf<u8>> {
        let depth = self.dev_info.queue_depth;
        let bytes = self.dev_info.max_io_buf_bytes as usize;
        let mut bvec = Vec::with_capacity(depth as usize);

        for _ in 0..depth {
            bvec.push(IoBuf::<u8>::new(bytes));
        }

        bvec
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

    // Store target specific json data, json["target_data"]
    pub fn set_target_json(&mut self, val: serde_json::Value) {
        self.tgt_json = Some(val);
    }

    // Retrieve target specific json data
    pub fn get_target_json(&self) -> Option<&serde_json::Value> {
        match self.tgt_json.as_ref() {
            None => None,
            Some(val) => Some(val),
        }
    }

    /// Return how many io slots, which is usually same with executor's
    /// nr_tasks.
    #[inline]
    pub fn get_nr_ios(&self) -> u16 {
        self.dev_info.queue_depth + self.tgt.extra_ios as u16
    }
}

impl Drop for UblkDev {
    fn drop(&mut self) {
        self.deinit_cdev();
    }
}

#[derive(Debug, Clone, Default)]
struct UblkQueueState {
    cmd_inflight: u32,
    state: u32,
}

impl UblkQueueState {
    const UBLK_QUEUE_STOPPING: u32 = 1_u32 << 0;
    const UBLK_QUEUE_IDLE: u32 = 1_u32 << 1;

    #[inline(always)]
    fn queue_is_quiesced(&self) -> bool {
        self.cmd_inflight == 0
    }

    #[inline(always)]
    fn queue_is_done(&self) -> bool {
        self.is_stopping() && self.queue_is_quiesced()
    }

    #[inline(always)]
    fn get_nr_cmd_inflight(&self) -> u32 {
        self.cmd_inflight
    }

    #[inline(always)]
    fn is_stopping(&self) -> bool {
        (self.state & Self::UBLK_QUEUE_STOPPING) != 0
    }

    #[inline(always)]
    fn is_idle(&self) -> bool {
        (self.state & Self::UBLK_QUEUE_IDLE) != 0
    }

    #[inline(always)]
    fn inc_cmd_inflight(&mut self) {
        self.cmd_inflight += 1;
    }

    #[inline(always)]
    fn dec_cmd_inflight(&mut self) {
        self.cmd_inflight -= 1;
    }

    fn mark_stopping(&mut self) {
        self.state |= Self::UBLK_QUEUE_STOPPING;
    }

    fn set_idle(&mut self, val: bool) {
        if val {
            self.state |= Self::UBLK_QUEUE_IDLE;
        } else {
            self.state &= !Self::UBLK_QUEUE_IDLE;
        }
    }
}

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
    flags: UblkFlags,
    q_id: u16,
    q_depth: u32,
    io_cmd_buf: u64,
    //ops: Box<dyn UblkQueueImpl>,
    pub dev: &'a UblkDev,
    bufs: RefCell<Vec<*mut u8>>,
    state: RefCell<UblkQueueState>,

    /// uring is shared for handling target IO, so has to be
    /// public
    pub q_ring: RefCell<IoUring<squeue::Entry>>,
}

impl AsRawFd for UblkQueue<'_> {
    fn as_raw_fd(&self) -> RawFd {
        self.q_ring.borrow().as_raw_fd()
    }
}

impl Drop for UblkQueue<'_> {
    fn drop(&mut self) {
        let dev = self.dev;
        log::trace!("dev {} queue {} dropped", dev.dev_info.dev_id, self.q_id);

        if let Err(r) = self.q_ring.borrow_mut().submitter().unregister_files() {
            log::error!("unregister fixed files failed {}", r);
        }

        let depth = dev.dev_info.queue_depth as u32;
        let cmd_buf_sz = UblkQueue::cmd_buf_sz(depth) as usize;

        //unmap, otherwise our cdev won't be released
        unsafe {
            libc::munmap(self.io_cmd_buf as *mut libc::c_void, cmd_buf_sz);
        }
    }
}

#[inline(always)]
fn round_up(val: u32, rnd: u32) -> u32 {
    (val + rnd - 1) & !(rnd - 1)
}

impl UblkQueue<'_> {
    const UBLK_QUEUE_IDLE_SECS: u32 = 20;
    const UBLK_QUEUE_IOCTL_ENCODE: UblkFlags = UblkFlags::UBLK_DEV_F_INTERNAL_0;

    #[inline(always)]
    fn cmd_buf_sz(depth: u32) -> u32 {
        let size = depth * core::mem::size_of::<sys::ublksrv_io_desc>() as u32;
        let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;

        round_up(size, page_sz)
    }

    #[inline(always)]
    fn is_ioctl_encode(&self) -> bool {
        self.flags.intersects(Self::UBLK_QUEUE_IOCTL_ENCODE)
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
        let mut bufs = Vec::<*mut u8>::with_capacity(nr_ios as usize);
        unsafe {
            bufs.set_len(nr_ios as usize);
        }

        for i in 0..nr_ios {
            bufs[i as usize] = std::ptr::null_mut();
        }

        assert!(!dev.flags.intersects(Self::UBLK_QUEUE_IOCTL_ENCODE));

        let q = UblkQueue {
            flags: dev.flags
                | if (dev.dev_info.flags & (sys::UBLK_F_CMD_IOCTL_ENCODE as u64)) != 0 {
                    Self::UBLK_QUEUE_IOCTL_ENCODE
                } else {
                    UblkFlags::empty()
                },
            q_id,
            q_depth: depth,
            io_cmd_buf: io_cmd_buf as u64,
            dev,
            state: RefCell::new(UblkQueueState {
                cmd_inflight: 0,
                state: 0,
            }),
            q_ring: RefCell::new(ring),
            bufs: RefCell::new(bufs),
        };

        log::info!("dev {} queue {} started", dev.dev_info.dev_id, q_id);

        Ok(q)
    }

    /// Return queue depth
    ///
    /// Queue depth decides the max count of inflight io command
    #[inline(always)]
    pub fn get_depth(&self) -> u32 {
        self.q_depth
    }

    /// Return queue id
    ///
    /// Queue id is aligned with blk-mq's queue_num
    #[inline(always)]
    pub fn get_qid(&self) -> u16 {
        self.q_id
    }

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
    pub fn get_iod(&self, tag: u16) -> &sys::ublksrv_io_desc {
        assert!((tag as u32) < self.q_depth);
        let iod = (self.io_cmd_buf + tag as u64 * 24) as *const sys::ublksrv_io_desc;
        unsafe { &*iod }
    }

    #[inline(always)]
    pub fn get_io_buf_addr(&self, tag: u16) -> *mut u8 {
        self.bufs.borrow()[tag as usize]
    }

    /// Register IO buffer, so that pages in this buffer can
    /// be discarded in case queue becomes idle
    pub fn register_io_buf(&self, tag: u16, buf: &IoBuf<u8>) {
        self.bufs.borrow_mut()[tag as usize] = buf.as_mut_ptr();
    }

    /// Register IO buffer, so that pages in this buffer can
    /// be discarded in case queue becomes idle
    pub fn unregister_io_buf(&self, tag: u16) {
        self.bufs.borrow_mut()[tag as usize] = std::ptr::null_mut();
    }

    /// unregister all io buffers
    pub(crate) fn unregister_io_bufs(&self) {
        for tag in 0..self.q_depth {
            self.unregister_io_buf(tag.try_into().unwrap());
        }
    }

    /// Register Io buffers
    pub fn regiser_io_bufs(self, bufs: Option<&Vec<IoBuf<u8>>>) -> Self {
        if let Some(b) = bufs {
            for tag in 0..self.q_depth {
                self.register_io_buf(tag.try_into().unwrap(), &b[tag as usize]);
            }
        }

        self
    }

    #[inline(always)]
    #[cfg(feature = "fat_complete")]
    fn support_comp_batch(&self) -> bool {
        self.flags.intersects(UblkFlags::UBLK_DEV_F_COMP_BATCH)
    }

    #[inline(always)]
    #[allow(unused_assignments)]
    fn __queue_io_cmd(
        &self,
        r: &mut IoUring<squeue::Entry>,
        tag: u16,
        cmd_op: u32,
        buf_addr: u64,
        user_data: u64,
        res: i32,
    ) -> i32 {
        let mut state = self.state.borrow_mut();
        if state.is_stopping() {
            return 0;
        }

        let io_cmd = sys::ublksrv_io_cmd {
            tag,
            addr: buf_addr,
            q_id: self.q_id,
            result: res,
        };

        let cmd_op = if !self.is_ioctl_encode() {
            cmd_op & 0xff
        } else {
            cmd_op
        };

        let sqe = opcode::UringCmd16::new(types::Fixed(0), cmd_op)
            .cmd(unsafe { core::mem::transmute::<sys::ublksrv_io_cmd, [u8; 16]>(io_cmd) })
            .build()
            .user_data(user_data);

        loop {
            let res = unsafe { r.submission().push(&sqe) };

            match res {
                Ok(_) => break,
                Err(_) => {
                    log::debug!("__queue_io_cmd: flush submission and retry");
                    r.submit_and_wait(0).unwrap();
                }
            }
        }

        state.inc_cmd_inflight();

        log::trace!(
            "{}: (qid {} flags {:x} tag {} cmd_op {}) stopping {}",
            "queue_io_cmd",
            self.q_id,
            self.flags,
            tag,
            cmd_op,
            state.is_stopping(),
        );

        1
    }

    #[inline(always)]
    fn queue_io_cmd(
        &self,
        r: &mut IoUring<squeue::Entry>,
        tag: u16,
        cmd_op: u32,
        buf_addr: u64,
        res: i32,
    ) -> i32 {
        let data = UblkIOCtx::build_user_data(tag, cmd_op, 0, false);
        self.__queue_io_cmd(r, tag, cmd_op, buf_addr, data, res)
    }

    #[inline(always)]
    fn commit_and_queue_io_cmd(
        &self,
        r: &mut IoUring<squeue::Entry>,
        tag: u16,
        buf_addr: u64,
        io_cmd_result: i32,
    ) {
        self.queue_io_cmd(
            r,
            tag,
            sys::UBLK_U_IO_COMMIT_AND_FETCH_REQ,
            buf_addr,
            io_cmd_result,
        );
    }

    /// Submit one io command.
    ///
    /// When it is called 1st time on this tag, the `cmd_op` has to be
    /// UBLK_U_IO_FETCH_REQ, otherwise it is UBLK_U_IO_COMMIT_AND_FETCH_REQ.
    ///
    /// UblkUringOpFuture is one Future object, so this function is actually
    /// one async function, and user can get result by submit_io_cmd().await
    ///
    /// Once result is returned, it means this command is completed and
    /// one ublk IO command is coming from ublk driver.
    ///
    /// In case of zoned, `buf_addr` can be the returned LBA for zone append
    /// command.
    #[inline]
    pub fn submit_io_cmd(
        &self,
        tag: u16,
        cmd_op: u32,
        buf_addr: *mut u8,
        result: i32,
    ) -> UblkUringOpFuture {
        let f = UblkUringOpFuture::new(0);
        let user_data = f.user_data | (tag as u64);
        let mut r = self.q_ring.borrow_mut();
        self.__queue_io_cmd(&mut r, tag, cmd_op, buf_addr as u64, user_data, result);

        f
    }

    #[inline]
    pub fn ublk_submit_sqe(&self, sqe: io_uring::squeue::Entry) -> UblkUringOpFuture {
        let f = UblkUringOpFuture::new(1_u64 << 63);
        let sqe = sqe.user_data(f.user_data);

        loop {
            let res = unsafe { self.q_ring.borrow_mut().submission().push(&sqe) };

            match res {
                Ok(_) => break,
                Err(_) => {
                    log::debug!("ublk_submit_sqe: flush and retry");
                    self.q_ring.borrow().submit_and_wait(0).unwrap();
                }
            }
        }

        f
    }

    /// Submit all commands for fetching IO
    ///
    /// Only called during queue initialization. After queue is setup,
    /// COMMIT_AND_FETCH_REQ command is used for both committing io command
    /// result and fetching new incoming IO
    pub fn submit_fetch_commands(self, bufs: Option<&Vec<IoBuf<u8>>>) -> Self {
        for i in 0..self.q_depth {
            let buf_addr = match bufs {
                Some(b) => b[i as usize].as_mut_ptr(),
                None => std::ptr::null_mut(),
            };

            assert!(
                ((self.dev.dev_info.flags & (crate::sys::UBLK_F_USER_COPY as u64)) != 0)
                    == bufs.is_none()
            );
            self.queue_io_cmd(
                &mut self.q_ring.borrow_mut(),
                i as u16,
                sys::UBLK_U_IO_FETCH_REQ,
                buf_addr as u64,
                -1,
            );
        }
        self
    }
    fn __submit_fetch_commands(&self) {
        for i in 0..self.q_depth {
            let buf_addr = self.get_io_buf_addr(i as u16) as u64;
            self.queue_io_cmd(
                &mut self.q_ring.borrow_mut(),
                i as u16,
                sys::UBLK_U_IO_FETCH_REQ,
                buf_addr,
                -1,
            );
        }
    }

    /// Complete one io command
    ///
    /// # Arguments:
    ///
    /// * `tag`: io command tag
    /// * `res`: io command result
    ///
    /// When calling this API, target code has to make sure that q_ring
    /// won't be borrowed.
    #[inline]
    pub fn complete_io_cmd(&self, tag: u16, buf_addr: *mut u8, res: Result<UblkIORes, UblkError>) {
        let r = &mut self.q_ring.borrow_mut();

        match res {
            Ok(UblkIORes::Result(res))
            | Err(UblkError::OtherError(res))
            | Err(UblkError::UringIOError(res)) => {
                self.commit_and_queue_io_cmd(r, tag, buf_addr as u64, res);
            }
            Err(UblkError::IoQueued(_)) => {}
            #[cfg(feature = "fat_complete")]
            Ok(UblkIORes::FatRes(fat)) => match fat {
                UblkFatRes::BatchRes(ios) => {
                    assert!(self.support_comp_batch());
                    for item in ios {
                        let tag = item.0;
                        self.commit_and_queue_io_cmd(r, tag, buf_addr as u64, item.1);
                    }
                }
                UblkFatRes::ZonedAppendRes((res, lba)) => {
                    self.commit_and_queue_io_cmd(r, tag, lba, res);
                }
            },
            _ => {}
        };
    }

    #[inline(always)]
    fn update_state(&self, cqe: &cqueue::Entry) {
        if !UblkIOCtx::is_target_io(cqe.user_data()) {
            let mut state = self.state.borrow_mut();

            state.dec_cmd_inflight();
            if cqe.result() == sys::UBLK_IO_RES_ABORT {
                state.mark_stopping();
            }
        }
    }

    #[inline(always)]
    #[allow(unused_assignments)]
    fn handle_cqe<F>(&self, mut ops: F, e: &UblkIOCtx)
    where
        F: FnMut(&UblkQueue, u16, &UblkIOCtx),
    {
        let data = e.user_data();
        let res = e.result();
        let tag = UblkIOCtx::user_data_to_tag(data);
        let cmd_op = UblkIOCtx::user_data_to_op(data);

        {
            log::trace!(
                "{}: res {} (qid {} tag {} cmd_op {} target {}) state {:?}",
                "handle_cqe",
                res,
                self.q_id,
                tag,
                cmd_op,
                UblkIOCtx::is_target_io(data),
                self.state.borrow(),
            );
        }

        if UblkIOCtx::is_target_io(data) {
            let res = e.result();

            if res < 0 && res != -(libc::EAGAIN) {
                let data = e.user_data();
                log::error!(
                    "{}: failed tgt io: res {} qid {} tag {}, cmd_op {}\n",
                    "handle_tgt_cqe",
                    res,
                    self.q_id,
                    UblkIOCtx::user_data_to_tag(data),
                    UblkIOCtx::user_data_to_op(data)
                );
            }
            ops(self, tag as u16, e);
            return;
        }

        self.update_state(e.0);

        if res == sys::UBLK_IO_RES_OK as i32 {
            assert!(tag < self.q_depth);
            ops(self, tag as u16, e);
        }
    }

    #[inline(always)]
    fn reap_one_event<F>(&self, ops: F, idx: i32, cnt: i32) -> usize
    where
        F: FnMut(&UblkQueue, u16, &UblkIOCtx),
    {
        if idx >= cnt {
            return 0;
        }

        let cqe = {
            match self.q_ring.borrow_mut().completion().next() {
                None => return 0,
                Some(r) => r,
            }
        };

        let ctx = UblkIOCtx(
            &cqe,
            if idx == 0 {
                UblkIOCtx::UBLK_IO_F_FIRST
            } else {
                0
            } | if idx + 1 == cnt {
                UblkIOCtx::UBLK_IO_F_LAST
            } else {
                0
            },
        );
        self.handle_cqe(ops, &ctx);

        1
    }

    fn discard_io_pages(&self) {
        let depth = self.q_depth;
        let buf_size = self.dev.dev_info.max_io_buf_bytes as usize;
        for i in 0..depth {
            let buf_addr = self.get_io_buf_addr(i as u16);
            unsafe { libc::madvise(buf_addr as *mut libc::c_void, buf_size, libc::MADV_DONTNEED) };
        }
    }

    fn enter_queue_idle(&self) {
        let mut state = self.state.borrow_mut();
        let empty = self.q_ring.borrow_mut().submission().is_empty();

        if empty && state.get_nr_cmd_inflight() == self.q_depth && !state.is_idle() {
            log::trace!(
                "dev {} queue {} becomes idle",
                self.dev.dev_info.dev_id,
                self.q_id
            );
            state.set_idle(true);
            self.discard_io_pages();
        }
    }

    #[inline]
    fn exit_queue_idle(&self) {
        let idle = { self.state.borrow().is_idle() };

        if idle {
            log::trace!(
                "dev {} queue {} becomes busy",
                self.dev.dev_info.dev_id,
                self.q_id
            );
            self.state.borrow_mut().set_idle(false);
        }
    }

    /// Return inflight IOs being handled by target code
    #[inline]
    pub fn get_inflight_nr_io(&self) -> u32 {
        self.q_depth - self.state.borrow().get_nr_cmd_inflight()
    }

    #[inline]
    fn __wait_ios(&self, to_wait: usize) -> Result<i32, UblkError> {
        let ts = types::Timespec::new().sec(Self::UBLK_QUEUE_IDLE_SECS as u64);
        let args = types::SubmitArgs::new().timespec(&ts);

        let state = self.state.borrow();
        log::trace!(
            "dev{}-q{}: to_submit {} inflight cmd {} stopping {}",
            self.dev.dev_info.dev_id,
            self.q_id,
            0,
            state.get_nr_cmd_inflight(),
            state.is_stopping(),
        );

        #[allow(clippy::collapsible_if)]
        if state.queue_is_done() {
            if self.q_ring.borrow_mut().submission().is_empty() {
                return Err(UblkError::QueueIsDown(-libc::ENODEV));
            }
        }

        let mut r = self.q_ring.borrow_mut();
        let ret = r.submitter().submit_with_args(to_wait, &args);
        match ret {
            Err(ref err) if err.raw_os_error() == Some(libc::ETIME) => {
                return Err(UblkError::UringSubmissionTimeout(-libc::ETIME));
            }
            Err(err) => return Err(UblkError::UringSubmissionError(err)),
            Ok(_) => {}
        };

        let nr_cqes = r.completion().len() as i32;
        log::trace!(
            "nr_cqes {} stop {} idle {}",
            nr_cqes,
            state.is_stopping(),
            state.is_idle(),
        );
        Ok(nr_cqes)
    }

    #[inline]
    fn wait_ios(&self, to_wait: usize) -> Result<i32, UblkError> {
        match self.__wait_ios(to_wait) {
            Ok(nr_cqes) => {
                if nr_cqes > 0 {
                    self.exit_queue_idle();
                }
                Ok(nr_cqes)
            }
            Err(UblkError::UringSubmissionTimeout(_)) => {
                self.enter_queue_idle();
                Ok(0)
            }
            Err(err) => Err(err),
        }
    }

    /// Process the incoming IOs(io commands & target IOs) from io_uring
    ///
    /// # Arguments:
    ///
    /// * `ops`: IO handling Closure
    ///
    /// * `to_wait`: passed to io_uring_enter(), wait until how many events are
    /// available
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
    pub(crate) fn process_ios<F>(&self, mut ops: F, to_wait: usize) -> Result<i32, UblkError>
    where
        F: FnMut(&UblkQueue, u16, &UblkIOCtx),
    {
        match self.wait_ios(to_wait) {
            Err(r) => Err(r),
            Ok(done) => {
                for idx in 0..done {
                    self.reap_one_event(&mut ops, idx, done);
                }
                Ok(0)
            }
        }
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
    pub fn wait_and_handle_io<F>(&self, mut ops: F)
    where
        F: FnMut(&UblkQueue, u16, &UblkIOCtx),
    {
        loop {
            match self.process_ios(&mut ops, 1) {
                Err(_) => break,
                _ => continue,
            }
        }

        self.unregister_io_bufs();
    }

    /// Flush queued SQEs to io_uring, then wait and wake up io tasks
    ///
    /// # Arguments:
    ///
    /// * `exe`: async executor
    ///
    /// * `to_wait`: passed to io_uring_enter(), wait until `to_wait` events
    /// are available. It won't block in waiting for events if `to_wait` is
    /// zero.
    ///
    /// Returns how many CQEs handled in this batch.
    ///
    /// This API is useful if user needs target specific batch handling.
    pub fn flush_and_wake_io_tasks<F>(
        &self,
        wake_handler: F,
        to_wait: usize,
    ) -> Result<i32, UblkError>
    where
        F: Fn(u64, &cqueue::Entry, bool),
    {
        match self.wait_ios(to_wait) {
            Err(r) => Err(r),
            Ok(done) => {
                for i in 0..done {
                    let cqe = {
                        match self.q_ring.borrow_mut().completion().next() {
                            None => return Err(UblkError::OtherError(-libc::EINVAL)),
                            Some(r) => r,
                        }
                    };
                    let user_data = cqe.user_data();
                    if UblkIOCtx::is_io_command(user_data) {
                        self.update_state(&cqe);
                    }
                    wake_handler(user_data, &cqe, i == done - 1);
                }
                Ok(done)
            }
        }
    }
}
