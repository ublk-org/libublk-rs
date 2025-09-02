use super::uring_async::UblkUringOpFuture;
#[cfg(feature = "fat_complete")]
use super::UblkFatRes;
use super::{ctrl::UblkCtrl, sys, UblkError, UblkFlags, UblkIORes};
use crate::bindings;
use crate::helpers::IoBuf;
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fs;
use std::os::unix::io::{AsRawFd, RawFd};

/// Unified buffer descriptor supporting both copy and zero-copy operations
#[derive(Debug, Clone)]
pub enum BufDesc<'a> {
    /// Buffer slice for copy-based operations
    ///
    /// Contains a reference to a buffer slice in userspace memory. Data is copied
    /// between this buffer and kernel buffers. Compatible with devices that have
    /// `UBLK_F_USER_COPY` enabled or devices without auto buffer registration.
    Slice(&'a [u8]),

    /// Auto buffer registration for zero-copy operations
    ///
    /// Contains auto buffer registration data that allows the kernel to directly
    /// access userspace buffers without copying. Requires devices with
    /// `UBLK_F_AUTO_BUF_REG` enabled for optimal performance.
    AutoReg(sys::ublk_auto_buf_reg),
}

impl<'a> BufDesc<'a> {
    /// Validate buffer descriptor compatibility with device capabilities
    ///
    /// # Arguments
    ///
    /// * `device_flags`: Device flags from `dev_info.flags`
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the buffer descriptor is compatible with device capabilities
    /// * `Err(UblkError::OtherError(-libc::ENOTSUP))` if the buffer type is not supported
    /// * `Err(UblkError::OtherError(-libc::EINVAL))` if the configuration is invalid
    ///
    /// # Validation Rules
    ///
    /// * `BufDesc::Slice` requires either no special flags or `UBLK_F_USER_COPY`
    /// * `BufDesc::AutoReg` requires `UBLK_F_AUTO_BUF_REG` to be enabled
    /// * `UBLK_F_AUTO_BUF_REG` and `UBLK_F_USER_COPY` cannot be used together
    #[inline]
    pub fn validate_compatibility(&self, device_flags: u64) -> Result<(), UblkError> {
        let has_auto_buf_reg = (device_flags & sys::UBLK_F_AUTO_BUF_REG as u64) != 0;
        let has_user_copy = (device_flags & sys::UBLK_F_USER_COPY as u64) != 0;

        // Check for invalid flag combination
        if has_auto_buf_reg && has_user_copy {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

        match self {
            BufDesc::Slice(_) => {
                // Slice operations are compatible with:
                // 1. No special flags (traditional buffer management)
                // 2. UBLK_F_USER_COPY (kernel handles copying)
                // They are NOT compatible with UBLK_F_AUTO_BUF_REG alone
                if has_auto_buf_reg && !has_user_copy {
                    Err(UblkError::OtherError(-libc::ENOTSUP))
                } else {
                    Ok(())
                }
            }
            BufDesc::AutoReg(_) => {
                // AutoReg operations require UBLK_F_AUTO_BUF_REG
                if has_auto_buf_reg {
                    Ok(())
                } else {
                    Err(UblkError::OtherError(-libc::ENOTSUP))
                }
            }
        }
    }

    /// Create a BufDesc from an IoBuf for migration compatibility
    ///
    /// # Arguments
    ///
    /// * `io_buf`: Reference to an IoBuf instance
    ///
    /// # Returns
    ///
    /// A `BufDesc::Slice` containing a reference to the IoBuf's data
    ///
    /// This helper method facilitates migration from existing IoBuf-based code
    /// to the new unified buffer descriptor system while maintaining zero-cost
    /// abstraction principles.
    #[inline]
    pub fn from_io_buf(io_buf: &'a IoBuf<u8>) -> Self {
        BufDesc::Slice(io_buf.as_slice())
    }

}

#[derive(Debug)]
pub enum BufDescList<'a> {
    /// List of IoBuf for traditional buffer management
    ///
    /// Contains an optional reference to a vector of `IoBuf<u8>` instances.
    /// Used with submit_fetch_commands for copy-based operations where data
    /// is explicitly transferred between userspace and kernel buffers.
    ///
    /// # When to Use
    /// - Device has traditional buffer management capabilities
    /// - `UBLK_F_USER_COPY` is enabled (when `None` is used)
    /// - Performance requirements allow for copying overhead
    /// - Simpler memory management is preferred
    ///
    /// The `Option` wrapper allows for `None` when `UBLK_F_USER_COPY` is enabled,
    /// indicating that no userspace buffers are needed because the kernel will
    /// handle buffer management through the user copy mechanism.
    Slices(Option<&'a Vec<IoBuf<u8>>>),

    /// List of auto buffer registration data for zero-copy operations
    ///
    /// Contains a slice of `sys::ublk_auto_buf_reg` structures that define
    /// buffer registration parameters for high-performance zero-copy I/O.
    /// Used with submit_fetch_commands_with_auto_buf_reg for direct kernel
    /// access to userspace buffers.
    ///
    /// # When to Use
    /// - Device supports `UBLK_F_AUTO_BUF_REG` capability
    /// - High-performance I/O is required
    /// - Memory copying overhead must be minimized
    /// - Application can handle more complex buffer management
    ///
    /// # Requirements
    /// - The slice length must be at least equal to the queue depth
    /// - Each registration entry must be properly initialized
    /// - Buffer indices must be unique and valid
    AutoRegs(&'a [sys::ublk_auto_buf_reg]),
}

/// A struct with the same memory layout as `io_uring_sys::io_uring_sqe`.
/// The definition must match the one in `io-uring-sys` crate.
/// This is a simplified version for demonstration.
#[repr(C)]
pub struct RawSqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    pub addr: u64,
    pub len: u32,
    pub rw_flags: u32,
    user_data: u64,
    pub buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    __pad2: u32,
}

#[macro_export]
macro_rules! override_sqe {
    ($entry:expr, $field:ident, $value:expr) => {
        unsafe {
            let sqe: &mut $crate::io::RawSqe = std::mem::transmute($entry);
            sqe.$field = $value;
        }
    };
    ($entry:expr, $field:ident, |=, $value:expr) => {
        unsafe {
            let sqe: &mut $crate::io::RawSqe = std::mem::transmute($entry);
            sqe.$field |= $value;
        }
    };
}

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
        F: FnOnce(&mut UblkDev) -> Result<(), UblkError>,
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

        let use_mlock = self.flags.intersects(UblkFlags::UBLK_DEV_F_MLOCK_IO_BUFFER);

        for _ in 0..depth {
            if use_mlock {
                bvec.push(IoBuf::<u8>::new_with_mlock(bytes));
            } else {
                bvec.push(IoBuf::<u8>::new(bytes));
            }
        }

        bvec
    }

    pub fn set_default_params(&mut self, dev_size: u64) {
        let info = self.dev_info;

        self.tgt.dev_size = dev_size;
        self.tgt.params = super::sys::ublk_params {
            types: super::sys::UBLK_PARAM_TYPE_BASIC,
            basic: super::sys::ublk_param_basic {
                attrs: super::sys::UBLK_ATTR_VOLATILE_CACHE,
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
        self.dev_info.queue_depth + self.tgt.extra_ios
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
pub struct UblkQueue<'a> {
    flags: UblkFlags,
    q_id: u16,
    q_depth: u32,
    io_cmd_buf: u64,
    //ops: Box<dyn UblkQueueImpl>,
    pub dev: &'a UblkDev,
    bufs: RefCell<Vec<*mut u8>>,
    state: RefCell<UblkQueueState>,

    // call uring_op() and uring_op_mut() for manipulating
    // q_ring, and in future it is likely to change to
    // thread_local variable
    pub(crate) q_ring: RefCell<IoUring<squeue::Entry>>,
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
    const UBLK_QUEUE_AUTO_BUF_REG: UblkFlags = UblkFlags::UBLK_DEV_F_INTERNAL_1;

    #[inline(always)]
    fn cmd_buf_sz(depth: u32) -> u32 {
        let size = depth * core::mem::size_of::<sys::ublksrv_io_desc>() as u32;
        let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;

        round_up(size, page_sz)
    }

    #[inline(always)]
    pub fn support_auto_buf_zc(&self) -> bool {
        self.flags.intersects(Self::UBLK_QUEUE_AUTO_BUF_REG)
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
    pub fn new(q_id: u16, dev: &UblkDev) -> Result<UblkQueue<'_>, UblkError> {
        let tgt = &dev.tgt;
        let sq_depth = tgt.sq_depth;
        let cq_depth = tgt.cq_depth;

        if (dev.dev_info.flags & sys::UBLK_F_AUTO_BUF_REG as u64) != 0
            && (dev.dev_info.flags & sys::UBLK_F_USER_COPY as u64) != 0
        {
            return Err(UblkError::InvalidVal);
        }

        let ring = IoUring::<squeue::Entry, cqueue::Entry>::builder()
            .setup_cqsize(cq_depth as u32)
            .setup_coop_taskrun()
            .build(sq_depth as u32)?;

        //todo: apply io_uring flags from tgt.ring_flags

        let depth = dev.dev_info.queue_depth as u32;
        let cdev_fd = dev.cdev_file.as_raw_fd();
        let cmd_buf_sz = UblkQueue::cmd_buf_sz(depth) as usize;
        let max_cmd_buf_sz = UblkQueue::cmd_buf_sz(sys::UBLK_MAX_QUEUE_DEPTH) as libc::off_t;

        ring.submitter()
            .register_files(&tgt.fds[0..tgt.nr_fds as usize])?;

        if (dev.dev_info.flags & sys::UBLK_F_AUTO_BUF_REG as u64) != 0 {
            ring.submitter().register_buffers_sparse(depth)?;
        }

        let off =
            sys::UBLKSRV_CMD_BUF_OFFSET as libc::off_t + (q_id as libc::off_t) * max_cmd_buf_sz;
        let io_cmd_buf = unsafe {
            libc::mmap(
                std::ptr::null_mut::<libc::c_void>(),
                cmd_buf_sz,
                libc::PROT_READ,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                cdev_fd,
                off,
            )
        };
        if io_cmd_buf == libc::MAP_FAILED {
            return Err(UblkError::IOError(std::io::Error::last_os_error()));
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
                }
                | if (dev.dev_info.flags & (sys::UBLK_F_AUTO_BUF_REG as u64)) != 0 {
                    Self::UBLK_QUEUE_AUTO_BUF_REG
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

    // Return if queue is idle
    pub fn is_idle(&self) -> bool {
        self.state.borrow().is_idle()
    }

    // Return if queue is stopping
    pub fn is_stopping(&self) -> bool {
        self.state.borrow().is_stopping()
    }

    // Manipulate immutable queue uring
    pub fn uring_op<R, H>(&self, op_handler: H) -> Result<R, UblkError>
    where
        H: Fn(&IoUring<squeue::Entry>) -> Result<R, UblkError>,
    {
        let uring = self.q_ring.borrow();

        op_handler(&uring)
    }

    // Manipulate mutable queue uring
    pub fn uring_op_mut<R, H>(&self, op_handler: H) -> Result<R, UblkError>
    where
        H: Fn(&mut IoUring<squeue::Entry>) -> Result<R, UblkError>,
    {
        let mut uring = self.q_ring.borrow_mut();

        op_handler(&mut uring)
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

    fn get_io_buf_addr(&self, tag: u16) -> *mut u8 {
        self.bufs.borrow()[tag as usize]
    }

    /// Register IO buffer, so that pages in this buffer can
    /// be discarded in case queue becomes idle
    pub fn register_io_buf(&self, tag: u16, buf: &IoBuf<u8>) {
        if self.support_auto_buf_zc() {
            return;
        }
        self.bufs.borrow_mut()[tag as usize] = buf.as_mut_ptr();
    }

    /// Register IO buffer, so that pages in this buffer can
    /// be discarded in case queue becomes idle
    pub fn unregister_io_buf(&self, tag: u16) {
        if self.support_auto_buf_zc() {
            return;
        }
        self.bufs.borrow_mut()[tag as usize] = std::ptr::null_mut();
    }

    /// unregister all io buffers
    pub(crate) fn unregister_io_bufs(&self) {
        if self.support_auto_buf_zc() {
            return;
        }
        for tag in 0..self.q_depth {
            self.unregister_io_buf(tag.try_into().unwrap());
        }
    }

    /// Register Io buffers
    pub fn regiser_io_bufs(self, bufs: Option<&Vec<IoBuf<u8>>>) -> Self {
        if !self.support_auto_buf_zc() {
            if let Some(b) = bufs {
                for tag in 0..self.q_depth {
                    self.register_io_buf(tag.try_into().unwrap(), &b[tag as usize]);
                }
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
    fn __queue_io_cmd(
        &self,
        r: &mut IoUring<squeue::Entry>,
        tag: u16,
        cmd_op: u32,
        buf_addr: u64,
        sqe_addr: Option<u64>,
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

        let mut sqe = opcode::UringCmd16::new(types::Fixed(0), cmd_op)
            .cmd(unsafe { core::mem::transmute::<sys::ublksrv_io_cmd, [u8; 16]>(io_cmd) })
            .build()
            .user_data(user_data);
        if let Some(auto_buf_addr) = sqe_addr {
            assert!(self.support_auto_buf_zc());
            override_sqe!(&mut sqe, addr, auto_buf_addr);
        }

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
            "{}: (qid {} flags {:x} tag {} cmd_op {}) stopping {} buf_addr {:x}/{:x}",
            "queue_io_cmd",
            self.q_id,
            self.flags,
            tag,
            cmd_op,
            state.is_stopping(),
            io_cmd.addr,
            buf_addr,
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
        self.__queue_io_cmd(r, tag, cmd_op, buf_addr, None, data, res)
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
        self.__queue_io_cmd(
            &mut r,
            tag,
            cmd_op,
            buf_addr as u64,
            None,
            user_data,
            result,
        );

        f
    }

    /// Submit io command with auto buffer registration support
    ///
    /// For UBLK_F_AUTO_BUF_REG, the buffer index and flags are passed via buf_reg_data.
    /// When auto buffer registration is enabled, buf_addr should be set to the encoded
    /// auto buffer registration data instead of the actual buffer address.
    #[inline]
    pub fn submit_io_cmd_with_auto_buf_reg(
        &self,
        tag: u16,
        cmd_op: u32,
        buf_reg_data: &sys::ublk_auto_buf_reg,
        result: i32,
    ) -> UblkUringOpFuture {
        let auto_buf_addr = Some(bindings::ublk_auto_buf_reg_to_sqe_addr(buf_reg_data));

        let f = UblkUringOpFuture::new(0);
        let user_data = f.user_data | (tag as u64);
        let mut r = self.q_ring.borrow_mut();
        self.__queue_io_cmd(&mut r, tag, cmd_op, 0, auto_buf_addr, user_data, result);

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

    #[inline]
    pub fn ublk_submit_sqe_sync(&self, sqe: io_uring::squeue::Entry) -> Result<(), UblkError> {
        loop {
            let res = unsafe { self.q_ring.borrow_mut().submission().push(&sqe) };

            match res {
                Ok(_) => break,
                Err(_) => {
                    log::debug!("ublk_submit_sqe: flush and retry");
                    self.q_ring.borrow().submit_and_wait(0)?;
                }
            }
        }

        Ok(())
    }

    fn submit_reg_unreg_io_buf(&self, op: u32, tag: u16, buf_index: u16) -> UblkUringOpFuture {
        let f = UblkUringOpFuture::new(0);
        let user_data = f.user_data | (tag as u64);
        let mut r = self.q_ring.borrow_mut();

        let io_cmd = sys::ublksrv_io_cmd {
            tag,
            addr: buf_index as u64,
            q_id: self.q_id,
            result: 0,
        };

        let cmd_op = if !self.is_ioctl_encode() {
            op & 0xff
        } else {
            op
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
                    log::debug!("submit_register_io_buf: flush and retry");
                    r.submit_and_wait(0).unwrap();
                }
            }
        }

        f
    }
    /// Submit manual buffer registration command
    ///
    /// Used when UBLK_F_AUTO_BUF_REG is enabled but auto registration fails
    /// and UBLK_AUTO_BUF_REG_FALLBACK was used.
    #[inline]
    pub fn submit_register_io_buf(&self, tag: u16, buf_index: u16) -> UblkUringOpFuture {
        self.submit_reg_unreg_io_buf(sys::UBLK_U_IO_REGISTER_IO_BUF, tag, buf_index)
    }

    /// Submit manual buffer unregistration command
    ///
    /// Used when UBLK_F_AUTO_BUF_REG is enabled to manually unregister buffers.
    #[inline]
    pub fn submit_unregister_io_buf(&self, tag: u16, buf_index: u16) -> UblkUringOpFuture {
        self.submit_reg_unreg_io_buf(sys::UBLK_U_IO_UNREGISTER_IO_BUF, tag, buf_index)
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

    /// Submit all commands for fetching IO with auto buffer registration
    ///
    /// # Arguments:
    ///
    /// * `buf_reg_data_list`: Array of auto buffer registration data for each tag
    ///
    /// This method supports zero-copy operations when UBLK_F_AUTO_BUF_REG is enabled.
    /// Each buffer is automatically registered using the provided registration data.
    /// Only called during queue initialization. After queue is setup,
    /// COMMIT_AND_FETCH_REQ command is used for both committing io command
    /// result and fetching new incoming IO.
    pub fn submit_fetch_commands_with_auto_buf_reg(
        self,
        buf_reg_data_list: &[sys::ublk_auto_buf_reg],
    ) -> Self {
        assert!(
            self.support_auto_buf_zc(),
            "Auto buffer registration not supported"
        );
        assert!(
            buf_reg_data_list.len() >= self.q_depth as usize,
            "Buffer registration data list too short"
        );

        for i in 0..self.q_depth {
            let buf_reg_data = &buf_reg_data_list[i as usize];
            let auto_buf_addr = bindings::ublk_auto_buf_reg_to_sqe_addr(buf_reg_data);
            let data = UblkIOCtx::build_user_data(i as u16, sys::UBLK_U_IO_FETCH_REQ, 0, false);

            self.__queue_io_cmd(
                &mut self.q_ring.borrow_mut(),
                i as u16,
                sys::UBLK_U_IO_FETCH_REQ,
                0,
                Some(auto_buf_addr),
                data,
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
            Err(UblkError::UringIoQueued) => {}
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
    fn commit_and_queue_io_cmd_with_auto_buf_reg(
        &self,
        r: &mut IoUring<squeue::Entry>,
        tag: u16,
        buf_reg_data: &sys::ublk_auto_buf_reg,
        io_cmd_result: i32,
    ) {
        let auto_buf_addr = bindings::ublk_auto_buf_reg_to_sqe_addr(buf_reg_data);
        let data = UblkIOCtx::build_user_data(tag, sys::UBLK_U_IO_COMMIT_AND_FETCH_REQ, 0, false);
        self.__queue_io_cmd(
            r,
            tag,
            sys::UBLK_U_IO_COMMIT_AND_FETCH_REQ,
            0,
            Some(auto_buf_addr),
            data,
            io_cmd_result,
        );
    }

    /// Complete one io command with auto buffer registration
    ///
    /// # Arguments:
    ///
    /// * `tag`: io command tag
    /// * `buf_reg_data`: auto buffer registration data containing buffer index and flags
    /// * `res`: io command result
    ///
    /// This method supports zero-copy operations when UBLK_F_AUTO_BUF_REG is enabled.
    /// The buffer is automatically registered using the provided registration data.
    /// When calling this API, target code has to make sure that q_ring won't be borrowed.
    #[inline]
    pub fn complete_io_cmd_with_auto_buf_reg(
        &self,
        tag: u16,
        buf_reg_data: &sys::ublk_auto_buf_reg,
        res: Result<UblkIORes, UblkError>,
    ) {
        let r = &mut self.q_ring.borrow_mut();

        match res {
            Ok(UblkIORes::Result(res))
            | Err(UblkError::OtherError(res))
            | Err(UblkError::UringIOError(res)) => {
                self.commit_and_queue_io_cmd_with_auto_buf_reg(r, tag, buf_reg_data, res);
            }
            Err(UblkError::UringIoQueued) => {}
            #[cfg(feature = "fat_complete")]
            Ok(UblkIORes::FatRes(fat)) => match fat {
                UblkFatRes::BatchRes(ios) => {
                    assert!(self.support_comp_batch());
                    for item in ios {
                        let tag = item.0;
                        self.commit_and_queue_io_cmd_with_auto_buf_reg(
                            r,
                            tag,
                            buf_reg_data,
                            item.1,
                        );
                    }
                }
                UblkFatRes::ZonedAppendRes((res, lba)) => {
                    let mut buf_reg_data_for_zoned = *buf_reg_data;
                    buf_reg_data_for_zoned.index = (lba & 0xffff) as u16;
                    self.commit_and_queue_io_cmd_with_auto_buf_reg(
                        r,
                        tag,
                        &buf_reg_data_for_zoned,
                        res,
                    );
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

        // don't enter idle if mlock buffers is enabled
        if !self
            .dev
            .flags
            .intersects(UblkFlags::UBLK_DEV_F_MLOCK_IO_BUFFER)
            && empty
            && state.get_nr_cmd_inflight() == self.q_depth
            && !state.is_idle()
        {
            log::debug!(
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
            log::debug!(
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
                return Err(UblkError::QueueIsDown);
            }
        }

        let mut r = self.q_ring.borrow_mut();
        let ret = r.submitter().submit_with_args(to_wait, &args);
        match ret {
            Err(ref err) if err.raw_os_error() == Some(libc::ETIME) => {
                return Err(UblkError::UringTimeout);
            }
            Err(err) => return Err(UblkError::IOError(err)),
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
            Err(UblkError::UringTimeout) => {
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
    /// `Ok(UblkIORes::Result)` is returned for moving on, otherwise UblkError::IoQueued
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
    /// * `wake_handler`: handler for wakeup io tasks pending on this uring
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

#[cfg(test)]
mod tests {
    use crate::ctrl::UblkCtrlBuilder;
    use crate::io::{BufDesc, UblkDev, UblkQueue};
    use crate::{sys, UblkError, UblkFlags};
    use io_uring::IoUring;

    fn __submit_uring_nop(ring: &mut IoUring<io_uring::squeue::Entry>) -> Result<usize, UblkError> {
        let nop_e = io_uring::opcode::Nop::new().build().user_data(0x42).into();

        unsafe {
            let mut queue = ring.submission();
            queue.push(&nop_e).expect("queue is full");
        }

        ring.submit_and_wait(1).map_err(UblkError::IOError)
    }

    #[test]
    fn test_queue_uring_op() {
        let ctrl = UblkCtrlBuilder::default()
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap();

        let tgt_init = |dev: &mut _| {
            let q = UblkQueue::new(0, dev)?;

            q.uring_op(|ring: &_| {
                ring.submitter().unregister_files()?;
                ring.submitter()
                    .register_files(&dev.tgt.fds)
                    .map_err(UblkError::IOError)
            })?;
            q.uring_op_mut(|ring: &mut _| -> Result<usize, UblkError> {
                __submit_uring_nop(ring)
            })?;

            Ok(())
        };

        UblkDev::new(ctrl.get_name(), tgt_init, &ctrl).unwrap();
    }

    #[test]
    fn test_buf_desc_validation() {
        let buffer = [0u8; 1024];
        let slice_desc = BufDesc::Slice(&buffer);
        let auto_reg_desc = BufDesc::AutoReg(sys::ublk_auto_buf_reg {
            index: 0,
            flags: 0,
            reserved0: 0,
            reserved1: 0,
        });

        // Test with no special flags (traditional buffer management)
        let no_flags = 0u64;
        assert!(slice_desc.validate_compatibility(no_flags).is_ok());
        assert!(auto_reg_desc.validate_compatibility(no_flags).is_err());

        // Test with UBLK_F_USER_COPY
        let user_copy_flags = sys::UBLK_F_USER_COPY as u64;
        assert!(slice_desc.validate_compatibility(user_copy_flags).is_ok());
        assert!(auto_reg_desc.validate_compatibility(user_copy_flags).is_err());

        // Test with UBLK_F_AUTO_BUF_REG
        let auto_buf_reg_flags = sys::UBLK_F_AUTO_BUF_REG as u64;
        assert!(slice_desc.validate_compatibility(auto_buf_reg_flags).is_err());
        assert!(auto_reg_desc.validate_compatibility(auto_buf_reg_flags).is_ok());

        // Test invalid combination of both flags
        let invalid_flags = (sys::UBLK_F_AUTO_BUF_REG | sys::UBLK_F_USER_COPY) as u64;
        assert!(slice_desc.validate_compatibility(invalid_flags).is_err());
        assert!(auto_reg_desc.validate_compatibility(invalid_flags).is_err());

        // Verify specific error codes
        match slice_desc.validate_compatibility(auto_buf_reg_flags) {
            Err(UblkError::OtherError(code)) => assert_eq!(code, -libc::ENOTSUP),
            _ => panic!("Expected ENOTSUP error"),
        }

        match slice_desc.validate_compatibility(invalid_flags) {
            Err(UblkError::OtherError(code)) => assert_eq!(code, -libc::EINVAL),
            _ => panic!("Expected EINVAL error"),
        }
    }

    #[test]
    fn test_buf_desc_helpers() {
        use crate::helpers::IoBuf;

        let buffer = [0u8; 1024];
        let _slice_desc = BufDesc::Slice(&buffer);

        // Test AutoReg variant
        let _auto_reg_desc = BufDesc::AutoReg(sys::ublk_auto_buf_reg {
            index: 0,
            flags: 0,
            reserved0: 0,
            reserved1: 0,
        });

        // Test from_io_buf helper
        let io_buf = IoBuf::<u8>::new(512);
        let _desc_from_io_buf = BufDesc::from_io_buf(&io_buf);
    }
}
