use super::io::{UblkDev, UblkTgt};
use super::uring_async::UblkUringOpFuture;
use super::{sys, UblkError, UblkFlags};
use bitmaps::Bitmap;
use derive_setters::*;
use io_uring::{opcode, squeue, types, IoUring};
use log::{error, trace};
use serde::Deserialize;
use std::cell::RefCell;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, RwLock};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

const CTRL_PATH: &str = "/dev/ublk-control";

const MAX_BUF_SZ: u32 = 32_u32 << 20;

// per-thread control uring - thread_local! is already lazy
//
std::thread_local! {
    pub(crate) static CTRL_URING: RefCell<Option<IoUring::<squeue::Entry128>>> =
        RefCell::new(None);
}

// Internal macro versions for backwards compatibility within the crate
#[macro_export]
macro_rules! with_ctrl_ring_internal {
    ($closure:expr) => {
        $crate::ctrl::CTRL_URING.with(|cell| {
            let ring_ref = cell.borrow();
            if let Some(ref ring) = *ring_ref {
                $closure(ring)
            } else {
                panic!("Control ring not initialized. Call ublk_init_ctrl_task_ring() first or use UblkCtrl constructor.")
            }
        })
    };
}

#[macro_export]
macro_rules! with_ctrl_ring_mut_internal {
    ($closure:expr) => {
        $crate::ctrl::CTRL_URING.with(|cell| {
            let mut ring_ref = cell.borrow_mut();
            if let Some(ref mut ring) = *ring_ref {
                $closure(ring)
            } else {
                panic!("Control ring not initialized. Call ublk_init_ctrl_task_ring() first or use UblkCtrl constructor.")
            }
        })
    };
}

// Make internal macros available within the crate
pub(crate) use with_ctrl_ring_internal;
pub(crate) use with_ctrl_ring_mut_internal;

/// Initialize the thread-local control ring using a custom closure
///
/// This API allows users to customize the io_uring initialization for control operations.
/// The closure receives a mutable reference to the Option and can conditionally initialize
/// it if not already set. If the thread-local variable is already initialized, the closure
/// does nothing.
///
/// # Arguments
/// * `init_fn` - Closure that receives &mut Option<IoUring<squeue::Entry128>> and returns
///               Result<(), UblkError>. Should set the Option to Some(ring) to initialize.
///
/// # Examples
///
/// ## Basic custom initialization:
/// ```no_run
/// use libublk::ublk_init_ctrl_task_ring;
/// use io_uring::IoUring;
///
/// fn example() -> Result<(), Box<dyn std::error::Error>> {
///     // Custom initialization before creating UblkCtrl
///     ublk_init_ctrl_task_ring(|ring_opt| {
///         if ring_opt.is_none() {
///             let ring = IoUring::builder()
///                 .setup_cqsize(256)  // Custom completion queue size
///                 .setup_coop_taskrun()  // Enable cooperative task running
///                 .build(128)?;  // Custom submission queue size
///             *ring_opt = Some(ring);
///         }
///         Ok(())
///     })?;
///     
///     // Now create UblkCtrl - it will use the pre-initialized ring
///     println!("Control ring initialized!");
///     Ok(())
/// }
/// ```
///
/// ## Advanced initialization with custom flags and size:
/// ```no_run
/// use libublk::ublk_init_ctrl_task_ring;
/// use io_uring::IoUring;
///
/// fn advanced_example() -> Result<(), Box<dyn std::error::Error>> {
///     ublk_init_ctrl_task_ring(|ring_opt| {
///         if ring_opt.is_none() {
///             let ring = IoUring::builder()
///                 .setup_cqsize(512)
///                 .setup_sqpoll(1000)  // Enable SQPOLL mode
///                 .setup_iopoll()      // Enable IOPOLL for high performance
///                 .build(256)?;
///             *ring_opt = Some(ring);
///         }
///         Ok(())
///     })?;
///     println!("Advanced control ring initialized!");
///     Ok(())
/// }
/// ```
pub fn ublk_init_ctrl_task_ring<F>(init_fn: F) -> Result<(), UblkError>
where
    F: FnOnce(&mut Option<IoUring<squeue::Entry128>>) -> Result<(), UblkError>,
{
    CTRL_URING.with(|cell| {
        let mut ring_ref = cell.borrow_mut();
        init_fn(&mut *ring_ref)
    })
}

/// Internal function to initialize the control ring with default parameters
///
/// This is called by UblkCtrlInner::new()/new_async() when the ring hasn't been
/// initialized yet. Uses default values similar to the original approach.
pub(crate) fn init_ctrl_task_ring_default(depth: u32) -> Result<(), UblkError> {
    ublk_init_ctrl_task_ring(|ring_opt| {
        if ring_opt.is_none() {
            let ring = IoUring::<squeue::Entry128>::builder()
                .build(depth)
                .map_err(UblkError::IOError)?;
            *ring_opt = Some(ring);
        }
        Ok(())
    })
}

/// Ublk per-queue CPU affinity
///
/// Responsible for setting ublk queue pthread's affinity.
///
#[derive(Debug, Default, Copy, Clone)]
pub struct UblkQueueAffinity {
    affinity: Bitmap<1024>,
}

impl UblkQueueAffinity {
    pub fn new() -> UblkQueueAffinity {
        UblkQueueAffinity {
            affinity: Bitmap::new(),
        }
    }

    pub fn buf_len(&self) -> usize {
        1024 / 8
    }

    pub fn addr(&self) -> *const u8 {
        self.affinity.as_bytes().as_ptr()
    }

    fn addr_mut(&mut self) -> *mut u8 {
        self.affinity.as_bytes().as_ptr() as *mut u8
    }

    pub fn to_bits_vec(&self) -> Vec<usize> {
        self.affinity.into_iter().collect()
    }

    /// Get a random CPU from the affinity set
    fn get_random_cpu(&self) -> Option<usize> {
        let cpus: Vec<usize> = self.affinity.into_iter().collect();
        if cpus.is_empty() {
            return None;
        }

        // Simple pseudo-random selection using current time and thread ID
        let mut seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as usize;

        unsafe {
            seed = seed.wrapping_add(libc::gettid() as usize);
        }

        Some(cpus[seed % cpus.len()])
    }

    /// Create a new affinity with only the specified CPU
    pub fn from_single_cpu(cpu: usize) -> UblkQueueAffinity {
        let mut affinity = UblkQueueAffinity::new();
        affinity.affinity.set(cpu, true);
        affinity
    }

    /// Set a specific CPU in the affinity
    pub fn set_cpu(&mut self, cpu: usize) {
        self.affinity.set(cpu, true);
    }

    /// Clear all CPUs and set only the specified one
    pub fn set_only_cpu(&mut self, cpu: usize) {
        self.affinity = Bitmap::new();
        self.affinity.set(cpu, true);
    }

    /// Check if affinity contains any CPUs
    pub fn is_empty(&self) -> bool {
        self.to_bits_vec().is_empty()
    }

    /// Check if affinity contains only one CPU
    pub fn is_single_cpu(&self) -> bool {
        self.to_bits_vec().len() == 1
    }

    /// Get the first (or only) CPU from the affinity set
    pub fn get_first_cpu(&self) -> Option<usize> {
        self.to_bits_vec().first().copied()
    }
}

#[repr(C)]
union CtrlCmd {
    ctrl_cmd: sys::ublksrv_ctrl_cmd,
    buf: [u8; 80],
}

/// the max supported length of char device path, which
/// is one implementation limit, and can be increased
/// without breaking anything.
const CTRL_UBLKC_PATH_MAX: usize = 32;
const CTRL_CMD_HAS_DATA: u32 = 1;
const CTRL_CMD_HAS_BUF: u32 = 2;
/// this command need to read data back from device
const CTRL_CMD_BUF_READ: u32 = 8;
/// this command needn't to attach char device path for audit in
/// case of unprivileged ublk, such as get_features(), add_dev().
const CTRL_CMD_NO_NEED_DEV_PATH: u32 = 16;

#[derive(Debug, Default, Copy, Clone)]
struct UblkCtrlCmdData {
    cmd_op: u32,
    flags: u32,
    data: u64,
    dev_path_len: u16,
    _pad: u16,
    _reserved: u32,

    addr: u64,
    len: u32,
}

impl UblkCtrlCmdData {
    /// Create a simple command with no data or buffer
    fn new_simple_cmd(cmd_op: u32) -> Self {
        Self {
            cmd_op,
            ..Default::default()
        }
    }

    /// Create a command with data only
    fn new_data_cmd(cmd_op: u32, data: u64) -> Self {
        Self {
            cmd_op,
            flags: CTRL_CMD_HAS_DATA,
            data,
            ..Default::default()
        }
    }

    /// Create a command with buffer for reading
    fn new_read_buffer_cmd(cmd_op: u32, addr: u64, len: u32, no_dev_path: bool) -> Self {
        let mut flags = CTRL_CMD_HAS_BUF | CTRL_CMD_BUF_READ;
        if no_dev_path {
            flags |= CTRL_CMD_NO_NEED_DEV_PATH;
        }
        Self {
            cmd_op,
            flags,
            addr,
            len,
            ..Default::default()
        }
    }

    /// Create a command with buffer for writing
    fn new_write_buffer_cmd(cmd_op: u32, addr: u64, len: u32, no_dev_path: bool) -> Self {
        let mut flags = CTRL_CMD_HAS_BUF;
        if no_dev_path {
            flags |= CTRL_CMD_NO_NEED_DEV_PATH;
        }
        Self {
            cmd_op,
            flags,
            addr,
            len,
            ..Default::default()
        }
    }

    /// Create a command with both data and buffer
    fn new_data_buffer_cmd(cmd_op: u32, data: u64, addr: u64, len: u32, read_buffer: bool) -> Self {
        let mut flags = CTRL_CMD_HAS_BUF | CTRL_CMD_HAS_DATA;
        if read_buffer {
            flags |= CTRL_CMD_BUF_READ;
        }
        Self {
            cmd_op,
            flags,
            data,
            addr,
            len,
            ..Default::default()
        }
    }

    fn prep_un_privileged_dev_path(&mut self, dev: &UblkCtrlInner) -> (u64, Option<Vec<u8>>) {
        // handle GET_DEV_INFO2 always with dev_path attached
        let cmd_op = self.cmd_op & 0xff;

        if cmd_op != sys::UBLK_CMD_GET_DEV_INFO2
            && (!dev.is_unprivileged() || (self.flags & CTRL_CMD_NO_NEED_DEV_PATH) != 0)
        {
            return (0, None);
        }

        let (buf, new_buf) = {
            let size = {
                if self.flags & CTRL_CMD_HAS_BUF != 0 {
                    self.len as usize + CTRL_UBLKC_PATH_MAX
                } else {
                    CTRL_UBLKC_PATH_MAX
                }
            };
            let mut v = vec![0_u8; size];

            (v.as_mut_ptr(), v)
        };

        let path_str = dev.get_cdev_path().to_string();
        assert!(path_str.len() <= CTRL_UBLKC_PATH_MAX);

        unsafe {
            libc::memset(buf as *mut libc::c_void, 0, CTRL_UBLKC_PATH_MAX);
            libc::memcpy(
                buf as *mut libc::c_void,
                path_str.as_ptr() as *const libc::c_void,
                path_str.len(),
            );

            if self.flags & CTRL_CMD_HAS_BUF != 0 {
                libc::memcpy(
                    (buf as u64 + CTRL_UBLKC_PATH_MAX as u64) as *mut libc::c_void,
                    self.addr as *const libc::c_void,
                    self.len as usize,
                );
            }
        }

        self.flags |= CTRL_CMD_HAS_BUF | CTRL_CMD_HAS_DATA;
        self.len += CTRL_UBLKC_PATH_MAX as u32;
        self.dev_path_len = CTRL_UBLKC_PATH_MAX as u16;
        let addr = self.addr;
        self.addr = buf as u64;
        (addr, Some(new_buf))
    }

    fn unprep_un_privileged_dev_path(&mut self, dev: &UblkCtrlInner, buf: u64) {
        let cmd_op = self.cmd_op & 0xff;

        if cmd_op != sys::UBLK_CMD_GET_DEV_INFO2
            && (!dev.is_unprivileged() || (self.flags & CTRL_CMD_NO_NEED_DEV_PATH) != 0)
        {
            return;
        }

        let addr = self.addr + CTRL_UBLKC_PATH_MAX as u64;
        let len = self.len - CTRL_UBLKC_PATH_MAX as u32;
        if self.flags & CTRL_CMD_BUF_READ != 0 {
            unsafe {
                libc::memcpy(
                    buf as *mut libc::c_void,
                    addr as *const libc::c_void,
                    len as usize,
                );
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct QueueAffinityJson {
    affinity: Vec<u32>,
    qid: u32,
    tid: u32,
}

/// JSON management for ublk device persistence
///
/// Handles all JSON serialization/deserialization, file I/O, and persistence
/// operations for ublk devices. This includes device information, queue data,
/// target configuration, and runtime state management.
#[derive(Debug)]
pub(crate) struct UblkJsonManager {
    /// Device ID for JSON file naming
    dev_id: u32,
    /// Current JSON data
    json: serde_json::Value,
}

impl UblkJsonManager {
    /// Create a new JSON manager for the specified device
    pub fn new(dev_id: u32) -> Self {
        Self {
            dev_id,
            json: serde_json::json!({}),
        }
    }

    /// Get the JSON file path for this device
    pub fn get_json_path(&self) -> String {
        format!("{}/{:04}.json", UblkCtrl::run_dir(), self.dev_id)
    }

    /// Get reference to the JSON data
    pub fn get_json(&self) -> &serde_json::Value {
        &self.json
    }

    /// Get mutable reference to the JSON data
    pub fn get_json_mut(&mut self) -> &mut serde_json::Value {
        &mut self.json
    }

    /// Set file permissions for the JSON file
    fn set_path_permission(path: &Path, mode: u32) -> Result<(), std::io::Error> {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, permissions)
    }

    /// Flush JSON data to file
    pub fn flush_json(&mut self) -> Result<i32, UblkError> {
        if self.json == serde_json::json!({}) {
            return Ok(0);
        }

        // Flushing json should only be done in case of adding new device
        let run_path = self.get_json_path();

        let json_path = Path::new(&run_path);

        if let Some(parent_dir) = json_path.parent() {
            if !parent_dir.exists() {
                std::fs::create_dir_all(parent_dir)?;
                // Set directory permissions to 777 for exported running json
                Self::set_path_permission(parent_dir, 0o777)?;
            }
        }

        let mut run_file = fs::File::create(json_path)?;

        // Each exported json file is only visible for the device owner
        Self::set_path_permission(json_path, 0o700)?;

        run_file.write_all(self.json.to_string().as_bytes())?;
        Ok(0)
    }

    /// Reload JSON data from file
    pub fn reload_json(&mut self) -> Result<i32, UblkError> {
        let mut file = fs::File::open(self.get_json_path())?;
        let mut json_str = String::new();
        file.read_to_string(&mut json_str)?;
        self.json = serde_json::from_str(&json_str).map_err(UblkError::JsonError)?;
        Ok(0)
    }

    /// Set the JSON data (called from UblkCtrlInner::build_json)
    pub fn set_json(&mut self, json: serde_json::Value) {
        self.json = json;
    }

    /// Update the device ID (called after device is added and real ID is allocated)
    pub fn update_dev_id(&mut self, new_dev_id: u32) {
        self.dev_id = new_dev_id;
    }

    /// Dump JSON content to console
    pub fn dump_json(&self) {
        if !Path::new(&self.get_json_path()).exists() {
            return;
        }

        let Ok(mut file) = fs::File::open(self.get_json_path()) else {
            eprintln!("Warning: Failed to open JSON file for dumping");
            return;
        };

        let mut json_str = String::new();
        if file.read_to_string(&mut json_str).is_err() {
            eprintln!("Warning: Failed to read JSON file content");
            return;
        }

        let Ok(json_value): Result<serde_json::Value, _> = serde_json::from_str(&json_str) else {
            eprintln!("Warning: Failed to parse JSON content");
            return;
        };

        let queues = &json_value["queues"];

        for i in 0..16 {
            // Max queues for display
            if let Some(queue) = queues.get(&i.to_string()) {
                let this_queue: Result<QueueAffinityJson, _> =
                    serde_json::from_value(queue.clone());

                if let Ok(p) = this_queue {
                    println!(
                        "\tqueue {} tid: {} affinity({})",
                        p.qid,
                        p.tid,
                        p.affinity
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<String>>()
                            .join(" ")
                    );
                }
            }
        }
        let tgt_val = &json_value["target"];
        let tgt: Result<UblkTgt, _> = serde_json::from_value(tgt_val.clone());
        if let Ok(p) = tgt {
            println!(
                "\ttarget {{\"dev_size\":{},\"name\":\"{}\",\"type\":0}}",
                p.dev_size, p.tgt_type
            );
        }
        println!("\ttarget_data {}", &json_value["target_data"]);
    }

    /// Get queue pthread ID from JSON
    pub fn get_queue_tid_from_json(&self, qid: u16) -> Result<i32, UblkError> {
        let queues = &self.json["queues"];
        let queue = &queues[qid.to_string()];
        let this_queue: Result<QueueAffinityJson, _> = serde_json::from_value(queue.clone());

        if let Ok(p) = this_queue {
            Ok(p.tid as i32)
        } else {
            Err(UblkError::OtherError(-libc::EEXIST))
        }
    }

    /// Get target flags from JSON
    pub fn get_target_flags_from_json(&self) -> Result<u32, UblkError> {
        let __tgt_flags = &self.json["target_flags"];
        let tgt_flags: Result<u32, _> = serde_json::from_value(__tgt_flags.clone());
        if let Ok(t) = tgt_flags {
            Ok(t)
        } else {
            Err(UblkError::OtherError(-libc::EINVAL))
        }
    }

    /// Get target configuration from JSON
    pub fn get_target_from_json(&self) -> Result<super::io::UblkTgt, UblkError> {
        let tgt_val = &self.json["target"];
        let tgt: Result<super::io::UblkTgt, _> = serde_json::from_value(tgt_val.clone());
        if let Ok(t) = tgt {
            Ok(t)
        } else {
            Err(UblkError::OtherError(-libc::EINVAL))
        }
    }

    /// Get target data from JSON
    pub fn get_target_data_from_json(&self) -> Option<serde_json::Value> {
        let val = &self.json["target_data"];
        if !val.is_null() {
            Some(val.clone())
        } else {
            None
        }
    }

    /// Get target type from JSON
    pub fn get_target_type_from_json(&self) -> Result<String, UblkError> {
        if let Ok(tgt) = self.get_target_from_json() {
            Ok(tgt.tgt_type)
        } else {
            Err(UblkError::OtherError(-libc::EINVAL))
        }
    }
}

/// Configuration for creating UblkCtrlInner
#[derive(Debug, Clone)]
struct UblkCtrlConfig {
    name: Option<String>,
    id: i32,
    nr_queues: u32,
    depth: u32,
    io_buf_bytes: u32,
    flags: u64,
    tgt_flags: u64,
    dev_flags: UblkFlags,
}

impl UblkCtrlConfig {
    fn new(
        name: Option<String>,
        id: i32,
        nr_queues: u32,
        depth: u32,
        io_buf_bytes: u32,
        flags: u64,
        tgt_flags: u64,
        dev_flags: UblkFlags,
    ) -> Self {
        Self {
            name,
            id,
            nr_queues,
            depth,
            io_buf_bytes,
            flags,
            tgt_flags,
            dev_flags,
        }
    }
}

/// UblkSession: build one new ublk control device or recover the old one.
///
/// High level API.
///
/// One limit is that IO handling closure doesn't support FnMut, and low
/// level API doesn't have such limit.
///
#[derive(Setters, Debug, PartialEq, Eq)]
pub struct UblkCtrlBuilder<'a> {
    /// target type, such as null, loop, ramdisk, or nbd,...
    name: &'a str,

    /// device id: -1 can only be used for adding one new device,
    /// and ublk driver will allocate one new ID for the created device;
    /// otherwise, we are asking driver to create or recover or list
    /// one device with specified ID
    id: i32,

    /// how many queues
    nr_queues: u16,

    /// each queue's IO depth
    depth: u16,

    /// max size of each IO buffer size, which will be converted to
    /// block layer's queue limit of max hw sectors
    io_buf_bytes: u32,

    /// passed to ublk driver via `sys::ublksrv_ctrl_dev_info.flags`,
    /// usually for adding or recovering device
    ctrl_flags: u64,

    /// store target flags in `sys::ublksrv_ctrl_dev_info.ublksrv_flags`,
    /// which is immutable in the whole device lifetime
    ctrl_target_flags: u64,

    /// libublk feature flags: UBLK_DEV_F_*
    dev_flags: UblkFlags,
}

impl Default for UblkCtrlBuilder<'_> {
    fn default() -> Self {
        UblkCtrlBuilder {
            name: "none",
            id: -1,
            nr_queues: 1,
            depth: 64,
            io_buf_bytes: 524288,
            ctrl_flags: 0,
            ctrl_target_flags: 0,
            dev_flags: UblkFlags::empty(),
        }
    }
}

impl UblkCtrlBuilder<'_> {
    /// create one pair of ublk devices, the 1st one is control device(`UblkCtrl`),
    /// and the 2nd one is data device(`UblkDev`)
    pub fn build(self) -> Result<UblkCtrl, UblkError> {
        UblkCtrl::new(
            Some(self.name.to_string()),
            self.id,
            self.nr_queues.into(),
            self.depth.into(),
            self.io_buf_bytes,
            self.ctrl_flags,
            self.ctrl_target_flags,
            self.dev_flags,
        )
    }
    pub async fn build_async(self) -> Result<super::ctrl_async::UblkCtrlAsync, UblkError> {
        super::ctrl_async::UblkCtrlAsync::new_async(
            Some(self.name.to_string()),
            self.id,
            self.nr_queues.into(),
            self.depth.into(),
            self.io_buf_bytes,
            self.ctrl_flags,
            self.ctrl_target_flags,
            self.dev_flags,
        )
        .await
    }
}

/// ublk control device
///
/// Responsible for controlling ublk device:
///
/// 1) adding and removing ublk char device(/dev/ublkcN)
///
/// 2) send all kinds of control commands(recover, list, set/get parameter,
/// get queue affinity, ...)
///
/// 3) exporting device as json file
pub struct UblkCtrl {
    inner: RwLock<UblkCtrlInner>,
}

pub(crate) struct UblkCtrlInner {
    pub(crate) name: Option<String>,
    file: fs::File,
    pub(crate) dev_info: sys::ublksrv_ctrl_dev_info,
    pub(crate) json_manager: UblkJsonManager,
    pub(crate) features: Option<u64>,

    /// global flags, shared with UblkDev and UblkQueue
    pub(crate) dev_flags: UblkFlags,
    // only set when running start_dev_async() which is enabled before
    // adding UBLK_CTRL_ASYNC_AWAIT
    pub(crate) force_async: bool,

    //only used in Drop()
    force_sync: bool,
    cmd_token: i32,
    queue_tids: Vec<i32>,
    queue_selected_cpus: Vec<usize>,
    pub(crate) nr_queues_configured: u16,
}

/// Affinity management helpers
impl UblkCtrlInner {
    /// enable async/await API enforcement: when set, only async/await control
    /// APIs can be used; when not set, only synchronous control APIs can be used
    pub(crate) const UBLK_CTRL_ASYNC_AWAIT: UblkFlags = UblkFlags::UBLK_DEV_F_INTERNAL_3;

    async fn get_queue_affinity_effective_async(
        &mut self,
        qid: u16,
    ) -> Result<UblkQueueAffinity, UblkError> {
        let mut kernel_affinity = UblkQueueAffinity::new();
        self.get_queue_affinity_async(qid as u32, &mut kernel_affinity)
            .await?;

        if self
            .dev_flags
            .contains(UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY)
        {
            // Select single CPU from available CPUs
            let selected_cpu = self.queue_selected_cpus[qid as usize];
            Ok(UblkQueueAffinity::from_single_cpu(selected_cpu))
        } else {
            Ok(kernel_affinity)
        }
    }
    /// Get queue affinity from kernel and optionally transform for single CPU mode
    fn get_queue_affinity_effective(&mut self, qid: u16) -> Result<UblkQueueAffinity, UblkError> {
        let mut kernel_affinity = UblkQueueAffinity::new();
        self.get_queue_affinity(qid as u32, &mut kernel_affinity)?;

        if self
            .dev_flags
            .contains(UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY)
        {
            // Select single CPU from available CPUs
            let selected_cpu = self.queue_selected_cpus[qid as usize];
            Ok(UblkQueueAffinity::from_single_cpu(selected_cpu))
        } else {
            Ok(kernel_affinity)
        }
    }

    /// Select and store single CPU for queue (used during device setup)
    async fn select_single_cpu_for_queue_async(
        &mut self,
        qid: u16,
        cpu: Option<usize>,
    ) -> Result<usize, UblkError> {
        let mut kernel_affinity = UblkQueueAffinity::new();
        self.get_queue_affinity_async(qid as u32, &mut kernel_affinity)
            .await?;

        let selected_cpu = if let Some(cpu) = cpu {
            // Validate that the specified CPU is in the affinity mask
            let available_cpus = kernel_affinity.to_bits_vec();
            if available_cpus.contains(&cpu) {
                cpu
            } else {
                return Err(UblkError::OtherError(-libc::EINVAL));
            }
        } else {
            // Select a random CPU from the affinity mask
            kernel_affinity.get_random_cpu().unwrap_or(0)
        };

        // Store the selected CPU
        if (qid as usize) < self.queue_selected_cpus.len() {
            self.queue_selected_cpus[qid as usize] = selected_cpu;
            Ok(selected_cpu)
        } else {
            Err(UblkError::OtherError(-libc::EINVAL))
        }
    }
    /// Select and store single CPU for queue (used during device setup)
    fn select_single_cpu_for_queue(
        &mut self,
        qid: u16,
        cpu: Option<usize>,
    ) -> Result<usize, UblkError> {
        let mut kernel_affinity = UblkQueueAffinity::new();
        self.get_queue_affinity(qid as u32, &mut kernel_affinity)?;

        let selected_cpu = if let Some(cpu) = cpu {
            // Validate that the specified CPU is in the affinity mask
            let available_cpus = kernel_affinity.to_bits_vec();
            if available_cpus.contains(&cpu) {
                cpu
            } else {
                return Err(UblkError::OtherError(-libc::EINVAL));
            }
        } else {
            // Select a random CPU from the affinity mask
            kernel_affinity.get_random_cpu().unwrap_or(0)
        };

        // Store the selected CPU
        if (qid as usize) < self.queue_selected_cpus.len() {
            self.queue_selected_cpus[qid as usize] = selected_cpu;
            Ok(selected_cpu)
        } else {
            Err(UblkError::OtherError(-libc::EINVAL))
        }
    }

    /// Create appropriate affinity for queue thread setup
    fn create_thread_affinity(&mut self, qid: u16) -> Result<UblkQueueAffinity, UblkError> {
        if self
            .dev_flags
            .contains(UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY)
        {
            // For single CPU mode, select and store the CPU first
            let selected_cpu = self.select_single_cpu_for_queue(qid, None)?;
            Ok(UblkQueueAffinity::from_single_cpu(selected_cpu))
        } else {
            // For multi-CPU mode, use kernel's full affinity
            let mut kernel_affinity = UblkQueueAffinity::new();
            self.get_queue_affinity(qid as u32, &mut kernel_affinity)?;
            Ok(kernel_affinity)
        }
    }

    /// Create appropriate affinity for queue thread setup
    pub(crate) async fn create_thread_affinity_async(
        &mut self,
        qid: u16,
    ) -> Result<UblkQueueAffinity, UblkError> {
        if self
            .dev_flags
            .contains(UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY)
        {
            // For single CPU mode, select and store the CPU first
            let selected_cpu = self.select_single_cpu_for_queue_async(qid, None).await?;
            Ok(UblkQueueAffinity::from_single_cpu(selected_cpu))
        } else {
            // For multi-CPU mode, use kernel's full affinity
            let mut kernel_affinity = UblkQueueAffinity::new();
            self.get_queue_affinity_async(qid as u32, &mut kernel_affinity)
                .await?;
            Ok(kernel_affinity)
        }
    }
}

impl Drop for UblkCtrlInner {
    fn drop(&mut self) {
        let id = self.dev_info.dev_id;
        trace!("ctrl: device {} dropped", id);
        if self.for_add_dev() {
            self.force_sync = true;
            if let Err(r) = self.del() {
                //Maybe deleted from other utilities, so no warn or error:w
                trace!("Delete char device {} failed {}", self.dev_info.dev_id, r);
            }
        }
    }
}

impl UblkCtrlInner {
    /// char device and block device name may change according to system policy,
    /// such udev may rename it in its own namespaces.
    const CDEV_PATH: &'static str = "/dev/ublkc";
    pub(crate) const BDEV_PATH: &'static str = "/dev/ublkb";

    const UBLK_CTRL_DEV_DELETED: UblkFlags = UblkFlags::UBLK_DEV_F_INTERNAL_2;
    const UBLK_DRV_F_ALL: u64 = (sys::UBLK_F_SUPPORT_ZERO_COPY
        | sys::UBLK_F_URING_CMD_COMP_IN_TASK
        | sys::UBLK_F_NEED_GET_DATA
        | sys::UBLK_F_USER_RECOVERY
        | sys::UBLK_F_USER_RECOVERY_REISSUE
        | sys::UBLK_F_UNPRIVILEGED_DEV
        | sys::UBLK_F_CMD_IOCTL_ENCODE
        | sys::UBLK_F_USER_COPY
        | sys::UBLK_F_ZONED
        | sys::UBLK_F_AUTO_BUF_REG) as u64;

    /// Create device info structure from parameters
    fn create_device_info(
        id: i32,
        nr_queues: u32,
        depth: u32,
        io_buf_bytes: u32,
        flags: u64,
        tgt_flags: u64,
    ) -> sys::ublksrv_ctrl_dev_info {
        sys::ublksrv_ctrl_dev_info {
            nr_hw_queues: nr_queues as u16,
            queue_depth: depth as u16,
            max_io_buf_bytes: io_buf_bytes,
            dev_id: id as u32,
            ublksrv_pid: unsafe { libc::getpid() } as i32,
            flags,
            ublksrv_flags: tgt_flags,
            ..Default::default()
        }
    }

    /// Open control device file
    fn open_control_device() -> Result<fs::File, UblkError> {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(CTRL_PATH)
            .map_err(UblkError::from)
    }

    /// Initialize queue data structures
    fn init_queue_data(nr_queues: u32) -> (Vec<i32>, Vec<usize>) {
        let queue_tids = {
            let mut tids = Vec::<i32>::with_capacity(nr_queues as usize);
            unsafe {
                tids.set_len(nr_queues as usize);
            }
            tids
        };
        let queue_selected_cpus = vec![0; nr_queues as usize];
        (queue_tids, queue_selected_cpus)
    }

    /// Handle device lifecycle (add new device or recover existing)
    fn handle_device_lifecycle(&mut self, id: i32) -> Result<(), UblkError> {
        if self.for_add_dev() {
            self.add()?;
            // Update JSON manager with the actual allocated device ID
            self.json_manager.update_dev_id(self.dev_info.dev_id);
        } else if id >= 0 {
            if let Err(_) = self.reload_json() {
                eprintln!("device reload json failed");
            }
            self.read_dev_info()?;
        }
        Ok(())
    }

    /// Handle device lifecycle asynchronously (add new device or recover existing)
    async fn handle_device_lifecycle_async(&mut self, id: i32) -> Result<(), UblkError> {
        if self.for_add_dev() {
            self.add_async().await?;
            // Update JSON manager with the actual allocated device ID
            self.json_manager.update_dev_id(self.dev_info.dev_id);
        } else if id >= 0 {
            if let Err(_) = self.reload_json() {
                eprintln!("device reload json failed");
            }
            self.read_dev_info_async().await?;
        }
        Ok(())
    }

    fn is_deleted(&self) -> bool {
        self.dev_flags.intersects(Self::UBLK_CTRL_DEV_DELETED)
    }

    fn mark_deleted(&mut self) {
        self.dev_flags |= Self::UBLK_CTRL_DEV_DELETED;
    }

    /// Detect and store driver features
    fn detect_features(&mut self) {
        self.features = match self.__get_features() {
            Ok(f) => Some(f),
            _ => None,
        };
    }

    /// Detect and store driver features asynchronously
    async fn detect_features_async(&mut self) {
        self.features = match self.__get_features_async().await {
            Ok(f) => Some(f),
            _ => None,
        };
    }

    fn new(config: UblkCtrlConfig) -> Result<UblkCtrlInner, UblkError> {
        let dev_info = Self::create_device_info(
            config.id,
            config.nr_queues,
            config.depth,
            config.io_buf_bytes,
            config.flags,
            config.tgt_flags,
        );
        let file = Self::open_control_device()?;
        let (queue_tids, queue_selected_cpus) = Self::init_queue_data(config.nr_queues);

        // Initialize control ring with default parameters
        init_ctrl_task_ring_default(16)?;

        let mut dev = UblkCtrlInner {
            name: config.name,
            file,
            dev_info,
            json_manager: UblkJsonManager::new(dev_info.dev_id),
            cmd_token: 0,
            queue_tids,
            queue_selected_cpus,
            nr_queues_configured: 0,
            dev_flags: config.dev_flags,
            force_async: false,
            force_sync: false,
            features: None,
        };

        dev.detect_features();
        dev.handle_device_lifecycle(config.id)?;

        log::info!(
            "ctrl: device {} flags {:x} created",
            dev.dev_info.dev_id,
            dev.dev_flags
        );

        Ok(dev)
    }

    async fn new_async(config: UblkCtrlConfig) -> Result<UblkCtrlInner, UblkError> {
        let dev_info = Self::create_device_info(
            config.id,
            config.nr_queues,
            config.depth,
            config.io_buf_bytes,
            config.flags,
            config.tgt_flags,
        );
        let file = Self::open_control_device()?;
        let (queue_tids, queue_selected_cpus) = Self::init_queue_data(config.nr_queues);

        // Initialize control ring with default parameters
        init_ctrl_task_ring_default(16)?;

        let mut dev = UblkCtrlInner {
            name: config.name,
            file,
            dev_info,
            json_manager: UblkJsonManager::new(dev_info.dev_id),
            cmd_token: 0,
            queue_tids,
            queue_selected_cpus,
            nr_queues_configured: 0,
            dev_flags: config.dev_flags,
            force_async: false,
            force_sync: false,
            features: None,
        };

        dev.detect_features_async().await;
        dev.handle_device_lifecycle_async(config.id).await?;

        log::info!(
            "ctrl/async: device {} flags {:x} created",
            dev.dev_info.dev_id,
            dev.dev_flags
        );

        Ok(dev)
    }

    /// Legacy constructor wrapper for backward compatibility
    #[allow(clippy::too_many_arguments)]
    fn new_with_params(
        name: Option<String>,
        id: i32,
        nr_queues: u32,
        depth: u32,
        io_buf_bytes: u32,
        flags: u64,
        tgt_flags: u64,
        dev_flags: UblkFlags,
    ) -> Result<UblkCtrlInner, UblkError> {
        let config = UblkCtrlConfig::new(
            name,
            id,
            nr_queues,
            depth,
            io_buf_bytes,
            flags,
            tgt_flags,
            dev_flags,
        );
        Self::new(config)
    }

    /// Async legacy constructor wrapper for backward compatibility
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new_with_params_async(
        name: Option<String>,
        id: i32,
        nr_queues: u32,
        depth: u32,
        io_buf_bytes: u32,
        flags: u64,
        tgt_flags: u64,
        dev_flags: UblkFlags,
    ) -> Result<UblkCtrlInner, UblkError> {
        let config = UblkCtrlConfig::new(
            name,
            id,
            nr_queues,
            depth,
            io_buf_bytes,
            flags,
            tgt_flags,
            dev_flags,
        );
        Self::new_async(config).await
    }

    fn is_unprivileged(&self) -> bool {
        (self.dev_info.flags & (super::sys::UBLK_F_UNPRIVILEGED_DEV as u64)) != 0
    }

    pub(crate) fn get_cdev_path(&self) -> String {
        format!("{}{}", UblkCtrlInner::CDEV_PATH, self.dev_info.dev_id)
    }

    pub(crate) fn for_add_dev(&self) -> bool {
        self.dev_flags.intersects(UblkFlags::UBLK_DEV_F_ADD_DEV)
    }

    fn for_recover_dev(&self) -> bool {
        self.dev_flags.intersects(UblkFlags::UBLK_DEV_F_RECOVER_DEV)
    }

    fn dev_state_desc(&self) -> String {
        match self.dev_info.state as u32 {
            sys::UBLK_S_DEV_DEAD => "DEAD".to_string(),
            sys::UBLK_S_DEV_LIVE => "LIVE".to_string(),
            sys::UBLK_S_DEV_QUIESCED => "QUIESCED".to_string(),
            _ => "UNKNOWN".to_string(),
        }
    }

    pub(crate) fn store_queue_tid(&mut self, qid: u16, tid: i32) {
        self.queue_tids[qid as usize] = tid;
    }

    pub(crate) fn dump_from_json(&self) {
        self.json_manager.dump_json();
    }

    /// Returned path of this device's exported json file
    ///
    pub(crate) fn run_path(&self) -> String {
        self.json_manager.get_json_path()
    }

    fn ublk_ctrl_prep_cmd(
        &mut self,
        fd: i32,
        dev_id: u32,
        data: &UblkCtrlCmdData,
        token: u64,
    ) -> squeue::Entry128 {
        let cmd = sys::ublksrv_ctrl_cmd {
            addr: if (data.flags & CTRL_CMD_HAS_BUF) != 0 {
                data.addr
            } else {
                0
            },
            len: if (data.flags & CTRL_CMD_HAS_BUF) != 0 {
                data.len as u16
            } else {
                0
            },
            data: if (data.flags & CTRL_CMD_HAS_DATA) != 0 {
                [data.data]
            } else {
                [0]
            },
            dev_id,
            queue_id: u16::MAX,
            dev_path_len: data.dev_path_len,
            ..Default::default()
        };
        let c_cmd = CtrlCmd { ctrl_cmd: cmd };

        opcode::UringCmd80::new(types::Fd(fd), data.cmd_op)
            .cmd(unsafe { c_cmd.buf })
            .build()
            .user_data(token)
    }

    fn ublk_submit_cmd_async(&mut self, data: &UblkCtrlCmdData) -> UblkUringOpFuture {
        let fd = self.file.as_raw_fd();
        let dev_id = self.dev_info.dev_id;
        let f = UblkUringOpFuture::new(0);
        let sqe = self.ublk_ctrl_prep_cmd(fd, dev_id, data, f.user_data);

        unsafe {
            with_ctrl_ring_mut_internal!(|ring: &mut IoUring<squeue::Entry128>| {
                if let Err(e) = ring.submission().push(&sqe) {
                    eprintln!("Warning: Failed to push SQE to submission queue: {:?}", e);
                }
            })
        }
        f
    }

    fn ublk_submit_cmd(
        &mut self,
        data: &UblkCtrlCmdData,
        to_wait: usize,
    ) -> Result<u64, UblkError> {
        let fd = self.file.as_raw_fd();
        let dev_id = self.dev_info.dev_id;

        // token is generated uniquely because '&mut self' is
        // passed in
        let token = {
            self.cmd_token += 1;
            self.cmd_token
        } as u64;
        let sqe = self.ublk_ctrl_prep_cmd(fd, dev_id, data, token);

        with_ctrl_ring_mut_internal!(|r: &mut IoUring<squeue::Entry128>| {
            unsafe {
                if let Err(e) = r.submission().push(&sqe) {
                    eprintln!("Warning: Failed to push SQE to submission queue: {:?}", e);
                    return;
                }
            };
            let _ = r.submit_and_wait(to_wait);
        });
        Ok(token)
    }

    /// check one control command and see if it is completed
    ///
    fn poll_cmd(&mut self, token: u64) -> i32 {
        with_ctrl_ring_mut_internal!(|r: &mut IoUring<squeue::Entry128>| {
            let res = match r.completion().next() {
                Some(cqe) => {
                    if cqe.user_data() != token {
                        -libc::EAGAIN
                    } else {
                        cqe.result()
                    }
                }
                None => -libc::EAGAIN,
            };

            res
        })
    }

    fn ublk_ctrl_need_retry(
        new_data: &mut UblkCtrlCmdData,
        data: &UblkCtrlCmdData,
        res: i32,
    ) -> bool {
        let legacy_op = data.cmd_op & 0xff;

        // Needn't to retry:
        //
        // 1) command is completed successfully
        //
        // 2) this is new command which has been issued via ioctl encoding
        // already
        if res >= 0 || res == -libc::EBUSY || (legacy_op > sys::UBLK_CMD_GET_DEV_INFO2) {
            false
        } else {
            *new_data = *data;
            new_data.cmd_op = legacy_op;
            true
        }
    }

    /// Convert uring result to UblkError
    fn ublk_err_to_result(res: i32) -> Result<i32, UblkError> {
        if res >= 0 || res == -libc::EBUSY {
            Ok(res)
        } else {
            Err(UblkError::UringIOError(res))
        }
    }

    async fn ublk_ctrl_cmd_async(&mut self, data: &UblkCtrlCmdData) -> Result<i32, UblkError> {
        // Enforce async/await API usage: async methods can only be used when UBLK_CTRL_ASYNC_AWAIT is set
        if !self.force_async
            && !self
                .dev_flags
                .contains(UblkCtrlInner::UBLK_CTRL_ASYNC_AWAIT)
        {
            log::warn!("Warn: async cmd {:x} is run from sync context", data.cmd_op);
            return Err(UblkError::OtherError(-libc::EPERM));
        }

        let mut new_data = *data;
        let mut res: i32 = 0;

        for _ in 0..2 {
            let (old_buf, _new) = new_data.prep_un_privileged_dev_path(self);
            res = self.ublk_submit_cmd_async(&new_data).await;
            new_data.unprep_un_privileged_dev_path(self, old_buf);

            trace!("ublk_ctrl_cmd_async: cmd {:x} res {}", data.cmd_op, res);
            if !Self::ublk_ctrl_need_retry(&mut new_data, data, res) {
                break;
            }
        }

        Self::ublk_err_to_result(res)
    }

    fn ublk_ctrl_cmd(&mut self, data: &UblkCtrlCmdData) -> Result<i32, UblkError> {
        // Enforce non-async API usage: sync methods can only be used when UBLK_CTRL_ASYNC_AWAIT is NOT set
        if !self.force_sync
            && self
                .dev_flags
                .contains(UblkCtrlInner::UBLK_CTRL_ASYNC_AWAIT)
        {
            log::warn!("Warn: sync cmd {:x} is run from async context", data.cmd_op);
            return Err(UblkError::OtherError(-libc::EPERM));
        }

        let mut new_data = *data;
        let mut res: i32 = 0;

        for _ in 0..2 {
            let (old_buf, _new) = new_data.prep_un_privileged_dev_path(self);
            let token = self.ublk_submit_cmd(&new_data, 1)?;
            res = self.poll_cmd(token);
            new_data.unprep_un_privileged_dev_path(self, old_buf);

            trace!("ublk_ctrl_cmd: cmd {:x} res {}", data.cmd_op, res);
            if !Self::ublk_ctrl_need_retry(&mut new_data, data, res) {
                break;
            }
        }

        Self::ublk_err_to_result(res)
    }

    /// Prepare ADD_DEV command data
    fn prepare_add_cmd(&self) -> UblkCtrlCmdData {
        UblkCtrlCmdData::new_write_buffer_cmd(
            sys::UBLK_U_CMD_ADD_DEV,
            std::ptr::addr_of!(self.dev_info) as u64,
            core::mem::size_of::<sys::ublksrv_ctrl_dev_info>() as u32,
            true, // no_dev_path
        )
    }

    fn add(&mut self) -> Result<i32, UblkError> {
        let data = self.prepare_add_cmd();
        self.ublk_ctrl_cmd(&data)
    }

    /// Add this device asynchronously
    ///
    async fn add_async(&mut self) -> Result<i32, UblkError> {
        let data = self.prepare_add_cmd();
        self.ublk_ctrl_cmd_async(&data).await
    }

    /// Prepare DEL_DEV command data  
    fn prepare_del_cmd(&self, force_async: bool) -> UblkCtrlCmdData {
        let cmd_op = if force_async
            || self
                .dev_flags
                .intersects(UblkFlags::UBLK_DEV_F_DEL_DEV_ASYNC)
        {
            sys::UBLK_U_CMD_DEL_DEV_ASYNC
        } else {
            sys::UBLK_U_CMD_DEL_DEV
        };
        UblkCtrlCmdData::new_simple_cmd(cmd_op)
    }

    /// Remove this device
    ///
    fn del(&mut self) -> Result<i32, UblkError> {
        if self.is_deleted() {
            return Ok(0);
        }

        let data = self.prepare_del_cmd(false);
        let res = self.ublk_ctrl_cmd(&data)?;
        self.mark_deleted();
        Ok(res)
    }

    /// Remove this device
    ///
    fn del_async(&mut self) -> Result<i32, UblkError> {
        if self.is_deleted() {
            return Ok(0);
        }

        let data = self.prepare_del_cmd(true);
        let res = self.ublk_ctrl_cmd(&data)?;
        self.mark_deleted();
        Ok(res)
    }

    /// Delete this device using proper async/await pattern
    ///
    /// This method provides the same functionality as del() but uses the
    /// async uring infrastructure. It follows the same command selection
    /// logic as the synchronous version, choosing between DEL_DEV_ASYNC
    /// and DEL_DEV commands based on device flags.
    ///
    pub(crate) async fn del_async_await(&mut self) -> Result<i32, UblkError> {
        if self.is_deleted() {
            return Ok(0);
        }

        let data = self.prepare_del_cmd(true);
        let res = self.ublk_ctrl_cmd_async(&data).await?;
        self.mark_deleted();
        Ok(res)
    }

    /// Prepare GET_FEATURES command data
    fn prepare_get_features_cmd(features_ptr: u64) -> UblkCtrlCmdData {
        UblkCtrlCmdData::new_read_buffer_cmd(
            sys::UBLK_U_CMD_GET_FEATURES,
            features_ptr,
            core::mem::size_of::<u64>() as u32,
            true, // no_dev_path
        )
    }

    fn __get_features(&mut self) -> Result<u64, UblkError> {
        let features = 0_u64;
        let data = Self::prepare_get_features_cmd(std::ptr::addr_of!(features) as u64);
        self.ublk_ctrl_cmd(&data)?;
        Ok(features)
    }

    async fn __get_features_async(&mut self) -> Result<u64, UblkError> {
        let features = 0_u64;
        let data = Self::prepare_get_features_cmd(std::ptr::addr_of!(features) as u64);
        self.ublk_ctrl_cmd_async(&data).await?;
        Ok(features)
    }

    /// Prepare read device info command data
    fn prepare_read_dev_info_cmd(&self, cmd_op: u32) -> UblkCtrlCmdData {
        UblkCtrlCmdData::new_read_buffer_cmd(
            cmd_op,
            std::ptr::addr_of!(self.dev_info) as u64,
            core::mem::size_of::<sys::ublksrv_ctrl_dev_info>() as u32,
            false, // need dev_path
        )
    }

    fn __read_dev_info(&mut self) -> Result<i32, UblkError> {
        let data = self.prepare_read_dev_info_cmd(sys::UBLK_U_CMD_GET_DEV_INFO);
        self.ublk_ctrl_cmd(&data)
    }

    fn __read_dev_info2(&mut self) -> Result<i32, UblkError> {
        let data = self.prepare_read_dev_info_cmd(sys::UBLK_U_CMD_GET_DEV_INFO2);
        self.ublk_ctrl_cmd(&data)
    }

    fn read_dev_info(&mut self) -> Result<i32, UblkError> {
        self.__read_dev_info2().or_else(|_| self.__read_dev_info())
    }

    /// Async version of read_dev_info() - retrieve device info from ublk driver
    ///
    pub(crate) async fn read_dev_info_async(&mut self) -> Result<i32, UblkError> {
        match self.__read_dev_info2_async().await {
            Ok(result) => Ok(result),
            Err(_) => self.__read_dev_info_async().await,
        }
    }

    async fn __read_dev_info_async(&mut self) -> Result<i32, UblkError> {
        let data = self.prepare_read_dev_info_cmd(sys::UBLK_U_CMD_GET_DEV_INFO);
        self.ublk_ctrl_cmd_async(&data).await
    }

    async fn __read_dev_info2_async(&mut self) -> Result<i32, UblkError> {
        let data = self.prepare_read_dev_info_cmd(sys::UBLK_U_CMD_GET_DEV_INFO2);
        self.ublk_ctrl_cmd_async(&data).await
    }

    /// Prepare START_DEV command data
    fn prepare_start_cmd(pid: i32) -> UblkCtrlCmdData {
        UblkCtrlCmdData::new_data_cmd(sys::UBLK_U_CMD_START_DEV, pid as u64)
    }

    /// Start this device by sending command to ublk driver
    ///
    fn start(&mut self, pid: i32) -> Result<i32, UblkError> {
        let data = Self::prepare_start_cmd(pid);
        self.ublk_ctrl_cmd(&data)
    }

    /// Start this device by sending command to ublk driver
    ///
    async fn start_async(&mut self, pid: i32) -> Result<i32, UblkError> {
        let data = Self::prepare_start_cmd(pid);
        self.ublk_ctrl_cmd_async(&data).await
    }

    /// Prepare STOP_DEV command data
    fn prepare_stop_cmd() -> UblkCtrlCmdData {
        UblkCtrlCmdData::new_simple_cmd(sys::UBLK_U_CMD_STOP_DEV)
    }

    /// Stop this device by sending command to ublk driver
    ///
    fn stop(&mut self) -> Result<i32, UblkError> {
        let data = Self::prepare_stop_cmd();
        self.ublk_ctrl_cmd(&data)
    }

    /// Stop this device by sending command to ublk driver asynchronously
    ///
    pub(crate) async fn stop_async(&mut self) -> Result<i32, UblkError> {
        let data = Self::prepare_stop_cmd();
        self.ublk_ctrl_cmd_async(&data).await
    }

    /// Prepare GET_PARAMS command data
    fn prepare_get_params_cmd(params: &mut sys::ublk_params) -> UblkCtrlCmdData {
        params.len = core::mem::size_of::<sys::ublk_params>() as u32;
        UblkCtrlCmdData::new_read_buffer_cmd(
            sys::UBLK_U_CMD_GET_PARAMS,
            params as *const sys::ublk_params as u64,
            params.len,
            false, // need dev_path
        )
    }

    /// Retrieve this device's parameter from ublk driver by
    /// sending command
    ///
    /// Can't pass params by reference(&mut), why?
    fn get_params(&mut self, params: &mut sys::ublk_params) -> Result<i32, UblkError> {
        let data = Self::prepare_get_params_cmd(params);
        self.ublk_ctrl_cmd(&data)
    }

    /// Retrieve this device's parameter from ublk driver by
    /// sending command in async/.await
    pub(crate) async fn get_params_async(
        &mut self,
        params: &mut sys::ublk_params,
    ) -> Result<i32, UblkError> {
        let data = Self::prepare_get_params_cmd(params);
        self.ublk_ctrl_cmd_async(&data).await
    }

    /// Send this device's parameter to ublk driver
    ///
    /// Note: device parameter has to send to driver before starting
    /// this device
    fn set_params(&mut self, params: &sys::ublk_params) -> Result<i32, UblkError> {
        let mut p = *params;

        p.len = core::mem::size_of::<sys::ublk_params>() as u32;
        let data = UblkCtrlCmdData::new_write_buffer_cmd(
            sys::UBLK_U_CMD_SET_PARAMS,
            std::ptr::addr_of!(p) as u64,
            p.len,
            false, // need dev_path
        );

        self.ublk_ctrl_cmd(&data)
    }

    /// Send this device's parameter to ublk driver asynchronously
    ///
    /// Note: device parameter has to send to driver before starting
    /// this device
    pub(crate) async fn set_params_async(
        &mut self,
        params: &sys::ublk_params,
    ) -> Result<i32, UblkError> {
        let mut p = *params;

        p.len = core::mem::size_of::<sys::ublk_params>() as u32;
        let data = UblkCtrlCmdData::new_write_buffer_cmd(
            sys::UBLK_U_CMD_SET_PARAMS,
            std::ptr::addr_of!(p) as u64,
            p.len,
            false, // need dev_path
        );
        self.ublk_ctrl_cmd_async(&data).await
    }

    /// Prepare GET_QUEUE_AFFINITY command data
    fn prepare_get_queue_affinity_cmd(q: u32, bm: &mut UblkQueueAffinity) -> UblkCtrlCmdData {
        UblkCtrlCmdData::new_data_buffer_cmd(
            sys::UBLK_U_CMD_GET_QUEUE_AFFINITY,
            q as u64,
            bm.addr() as u64,
            bm.buf_len() as u32,
            true, // read_buffer
        )
    }

    fn get_queue_affinity(&mut self, q: u32, bm: &mut UblkQueueAffinity) -> Result<i32, UblkError> {
        let data = Self::prepare_get_queue_affinity_cmd(q, bm);
        self.ublk_ctrl_cmd(&data)
    }

    /// Retrieving the specified queue's affinity from ublk driver in async/.await
    ///
    pub(crate) async fn get_queue_affinity_async(
        &mut self,
        q: u32,
        bm: &mut UblkQueueAffinity,
    ) -> Result<i32, UblkError> {
        let data = Self::prepare_get_queue_affinity_cmd(q, bm);
        self.ublk_ctrl_cmd_async(&data).await
    }

    /// Prepare START_USER_RECOVERY command data
    fn prepare_start_user_recover_cmd() -> UblkCtrlCmdData {
        UblkCtrlCmdData::new_simple_cmd(sys::UBLK_U_CMD_START_USER_RECOVERY)
    }

    fn __start_user_recover(&mut self) -> Result<i32, UblkError> {
        let data = Self::prepare_start_user_recover_cmd();
        self.ublk_ctrl_cmd(&data)
    }

    pub(crate) async fn __start_user_recover_async(&mut self) -> Result<i32, UblkError> {
        let data = Self::prepare_start_user_recover_cmd();
        self.ublk_ctrl_cmd_async(&data).await
    }

    /// Prepare END_USER_RECOVERY command data
    fn prepare_end_user_recover_cmd(pid: i32) -> UblkCtrlCmdData {
        UblkCtrlCmdData::new_data_cmd(sys::UBLK_U_CMD_END_USER_RECOVERY, pid as u64)
    }

    /// End user recover for this device, do similar thing done in start_dev()
    ///
    fn end_user_recover(&mut self, pid: i32) -> Result<i32, UblkError> {
        let data = Self::prepare_end_user_recover_cmd(pid);
        self.ublk_ctrl_cmd(&data)
    }

    /// End user recover for this device, do similar thing done in start_dev()
    ///
    async fn end_user_recover_async(&mut self, pid: i32) -> Result<i32, UblkError> {
        let data = Self::prepare_end_user_recover_cmd(pid);
        self.ublk_ctrl_cmd_async(&data).await
    }

    fn prep_start_dev(&mut self, dev: &UblkDev) -> Result<i32, UblkError> {
        self.read_dev_info()?;
        if self.dev_info.state == sys::UBLK_S_DEV_LIVE as u16 {
            return Ok(0);
        }

        if self.dev_info.state != sys::UBLK_S_DEV_QUIESCED as u16 {
            self.set_params(&dev.tgt.params)?;
            self.flush_json()?;
        } else if self.for_recover_dev() {
            self.flush_json()?;
        } else {
            return Err(UblkError::OtherError(-libc::EINVAL));
        };

        Ok(0)
    }

    /// Prepare to start device asynchronously - async version of prep_start_dev
    async fn prep_start_dev_async(&mut self, dev: &UblkDev) -> Result<i32, UblkError> {
        self.read_dev_info_async().await?;
        if self.dev_info.state == sys::UBLK_S_DEV_LIVE as u16 {
            return Ok(0);
        }

        if self.dev_info.state != sys::UBLK_S_DEV_QUIESCED as u16 {
            self.set_params_async(&dev.tgt.params).await?;
            self.flush_json()?;
        } else if self.for_recover_dev() {
            self.flush_json()?;
        } else {
            return Err(UblkError::OtherError(-libc::EINVAL));
        };

        Ok(0)
    }

    pub(crate) async fn start_dev_async(&mut self, dev: &UblkDev) -> Result<i32, UblkError> {
        self.prep_start_dev_async(dev).await?;

        if self.dev_info.state != sys::UBLK_S_DEV_QUIESCED as u16 {
            self.start_async(unsafe { libc::getpid() as i32 }).await
        } else if self.for_recover_dev() {
            self.end_user_recover_async(unsafe { libc::getpid() as i32 })
                .await
        } else {
            Err(crate::UblkError::OtherError(-libc::EINVAL))
        }
    }

    /// Flush this device's json info as file
    fn flush_json(&mut self) -> Result<i32, UblkError> {
        // flushing json should only be done in case of adding new device
        // or recovering old device
        if !self.for_add_dev() && !self.for_recover_dev() {
            return Ok(0);
        }

        self.json_manager.flush_json()
    }

    /// Build json info for this device
    ///
    /// # Arguments:
    ///
    /// * `dev`: this device's UblkDev instance
    /// * `affi`: queue affinity vector, in which each item stores the queue's affinity
    /// * `tids`: queue pthread tid vector, in which each item stores the queue's
    /// pthread tid
    ///
    /// Build JSON data with provided queue affinities
    fn build_json_with_affinities(
        &self,
        dev: &UblkDev,
        queue_affinities: &[UblkQueueAffinity],
    ) -> serde_json::Value {
        let tgt_data = dev.get_target_json();
        let mut map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

        for qid in 0..dev.dev_info.nr_hw_queues {
            let affinity = &queue_affinities[qid as usize];

            map.insert(
                format!("{}", qid),
                serde_json::json!({
                    "qid": qid,
                    "tid": self.queue_tids[qid as usize],
                    "affinity": affinity.to_bits_vec(),
                }),
            );
        }

        let mut json = serde_json::json!({
            "dev_info": dev.dev_info,
            "target": dev.tgt,
            "target_flags": dev.flags.bits(),
        });

        if let Some(val) = tgt_data {
            json["target_data"] = val.clone()
        }

        json["queues"] = serde_json::Value::Object(map);
        json
    }

    /// Build JSON data for device
    fn build_json_internal(&mut self, dev: &UblkDev) -> Result<serde_json::Value, UblkError> {
        let mut queue_affinities = Vec::with_capacity(dev.dev_info.nr_hw_queues as usize);

        for qid in 0..dev.dev_info.nr_hw_queues {
            let affinity = self.get_queue_affinity_effective(qid)?;
            queue_affinities.push(affinity);
        }

        Ok(self.build_json_with_affinities(dev, &queue_affinities))
    }

    /// Build JSON data for device (async)
    async fn build_json_internal_async(
        &mut self,
        dev: &UblkDev,
    ) -> Result<serde_json::Value, UblkError> {
        let mut queue_affinities = Vec::with_capacity(dev.dev_info.nr_hw_queues as usize);

        for qid in 0..dev.dev_info.nr_hw_queues {
            let affinity = self.get_queue_affinity_effective_async(qid).await?;
            queue_affinities.push(affinity);
        }

        Ok(self.build_json_with_affinities(dev, &queue_affinities))
    }

    /// Update existing JSON with queue thread IDs
    fn update_json_queue_tids(&mut self, dev: &UblkDev) -> bool {
        if !self.json_manager.get_json().is_null()
            && self.json_manager.get_json().is_object()
            && !self.json_manager.get_json().as_object().unwrap().is_empty()
        {
            if let Some(queues) = self.json_manager.get_json_mut().get_mut("queues") {
                for qid in 0..dev.dev_info.nr_hw_queues {
                    if let Some(queue) = queues.get_mut(&qid.to_string()) {
                        if let Some(tid) = queue.get_mut("tid") {
                            *tid = serde_json::json!(self.queue_tids[qid as usize]);
                        }
                    }
                }
            }
            true
        } else {
            false
        }
    }

    fn build_json(&mut self, dev: &UblkDev) -> Result<i32, UblkError> {
        // Update queue thread IDs if JSON already exists
        if self.update_json_queue_tids(dev) {
            return Ok(0);
        }

        let json = self.build_json_internal(dev)?;
        self.json_manager.set_json(json);
        Ok(0)
    }

    pub(crate) async fn build_json_async(&mut self, dev: &UblkDev) -> Result<i32, UblkError> {
        // Update queue thread IDs if JSON already exists
        if self.update_json_queue_tids(dev) {
            return Ok(0);
        }

        let json = self.build_json_internal_async(dev).await?;
        self.json_manager.set_json(json);
        Ok(0)
    }

    /// Reload json info for this device
    ///
    fn reload_json(&mut self) -> Result<i32, UblkError> {
        self.json_manager.reload_json()
    }

    /// Dump this device info
    ///
    /// The 1st part is from UblkCtrl.dev_info, and the 2nd part is
    /// retrieved from device's exported json file
    /// Print device info after data has been collected
    pub(crate) fn dump_device_info(&self, p: &sys::ublk_params) {
        let info = &self.dev_info;
        println!(
            "\ndev id {}: nr_hw_queues {} queue_depth {} block size {} dev_capacity {}",
            info.dev_id,
            info.nr_hw_queues,
            info.queue_depth,
            1 << p.basic.logical_bs_shift,
            p.basic.dev_sectors
        );
        println!(
            "\tmax rq size {} daemon pid {} flags 0x{:x} state {}",
            info.max_io_buf_bytes,
            info.ublksrv_pid,
            info.flags,
            self.dev_state_desc()
        );
        println!(
            "\tublkc: {}:{} ublkb: {}:{} owner: {}:{}",
            p.devt.char_major,
            p.devt.char_minor,
            p.devt.disk_major,
            p.devt.disk_minor,
            info.owner_uid,
            info.owner_gid
        );
    }

    /// Validate input parameter and return InvalidVal error if condition fails
    fn validate_param(condition: bool) -> Result<(), UblkError> {
        if condition {
            Ok(())
        } else {
            Err(UblkError::InvalidVal)
        }
    }

    /// New one ublk control device
    ///
    /// # Arguments:
    ///
    /// * `id`: device id, or let driver allocate one if -1 is passed
    /// * `nr_queues`: how many hw queues allocated for this device
    /// * `depth`: each hw queue's depth
    /// * `io_buf_bytes`: max buf size for each IO
    /// * `flags`: flags for setting ublk device
    /// * `for_add`: is for adding new device
    /// * `dev_flags`: global flags as userspace side feature, will be
    ///     shared with UblkDev and UblkQueue
    ///
    /// ublk control device is for sending command to driver, and maintain
    /// device exported json file, dump, or any misc management task.
    ///
    #[allow(clippy::too_many_arguments)]
    /// Validate parameters for new UblkCtrl creation
    pub(crate) fn validate_new_params(
        flags: u64,
        dev_flags: UblkFlags,
        id: i32,
        nr_queues: u32,
        depth: u32,
        io_buf_bytes: u32,
    ) -> Result<(), UblkError> {
        Self::validate_param((flags & !Self::UBLK_DRV_F_ALL) == 0)?;

        Self::validate_param(!dev_flags.intersects(crate::ublk_internal_flags_all!()))?;

        if !Path::new(CTRL_PATH).exists() {
            eprintln!("Please run `modprobe ublk_drv` first");
            return Err(UblkError::OtherError(-libc::ENOENT));
        }

        // Check mlock feature compatibility
        if dev_flags.intersects(UblkFlags::UBLK_DEV_F_MLOCK_IO_BUFFER) {
            // mlock feature is incompatible with certain other features
            Self::validate_param(
                (flags & sys::UBLK_F_USER_COPY as u64) == 0
                    && (flags & sys::UBLK_F_AUTO_BUF_REG as u64) == 0
                    && (flags & sys::UBLK_F_SUPPORT_ZERO_COPY as u64) == 0,
            )?;
        }

        Self::validate_param(id >= -1)?;
        Self::validate_param(nr_queues <= sys::UBLK_MAX_NR_QUEUES)?;
        Self::validate_param(depth <= sys::UBLK_MAX_QUEUE_DEPTH)?;

        let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;
        Self::validate_param(io_buf_bytes <= MAX_BUF_SZ && (io_buf_bytes & (page_sz - 1)) == 0)?;

        Ok(())
    }

    /// Consolidated error handling helpers

    /// Convert system call result to UblkError::OtherError
    fn sys_result_to_error(res: i32) -> Result<i32, UblkError> {
        if res >= 0 {
            Ok(res)
        } else {
            Err(UblkError::OtherError(res))
        }
    }

    /// Validate queue ID bounds
    fn validate_queue_id(qid: u16, max_queues: u16) -> Result<(), UblkError> {
        if (qid as usize) < (max_queues as usize) {
            Ok(())
        } else {
            Err(UblkError::OtherError(-libc::EINVAL))
        }
    }

    /// Check if thread ID is valid (non-zero)
    fn validate_thread_id(tid: i32) -> Result<(), UblkError> {
        if tid != 0 {
            Ok(())
        } else {
            Err(UblkError::OtherError(-libc::ESRCH))
        }
    }
}

impl UblkCtrl {
    fn get_inner(&self) -> std::sync::RwLockReadGuard<'_, UblkCtrlInner> {
        self.inner.read().unwrap_or_else(|poisoned| {
            eprintln!("Warning: RwLock poisoned, recovering");
            poisoned.into_inner()
        })
    }

    fn get_inner_mut(&self) -> std::sync::RwLockWriteGuard<'_, UblkCtrlInner> {
        self.inner.write().unwrap_or_else(|poisoned| {
            eprintln!("Warning: RwLock poisoned, recovering");
            poisoned.into_inner()
        })
    }

    pub fn get_name(&self) -> String {
        let inner = self.get_inner();

        match &inner.name {
            Some(name) => name.clone(),
            None => "none".to_string(),
        }
    }

    pub(crate) fn get_dev_flags(&self) -> UblkFlags {
        self.get_inner().dev_flags
    }

    pub fn new(
        name: Option<String>,
        id: i32,
        nr_queues: u32,
        depth: u32,
        io_buf_bytes: u32,
        flags: u64,
        tgt_flags: u64,
        dev_flags: UblkFlags,
    ) -> Result<UblkCtrl, UblkError> {
        if dev_flags.intersects(UblkCtrlInner::UBLK_CTRL_ASYNC_AWAIT) {
            return Err(UblkError::InvalidVal);
        }

        UblkCtrlInner::validate_new_params(flags, dev_flags, id, nr_queues, depth, io_buf_bytes)?;

        let inner = RwLock::new(UblkCtrlInner::new_with_params(
            name,
            id,
            nr_queues,
            depth,
            io_buf_bytes,
            flags,
            tgt_flags,
            dev_flags,
        )?);

        Ok(UblkCtrl { inner })
    }

    /// Allocate one simple UblkCtrl device for delelting, listing, recovering,..,
    /// and it can't be done for adding device
    pub fn new_simple(id: i32) -> Result<UblkCtrl, UblkError> {
        assert!(id >= 0);
        Self::new(None, id, 0, 0, 0, 0, 0, UblkFlags::empty())
    }

    /// Return current device info
    pub fn dev_info(&self) -> sys::ublksrv_ctrl_dev_info {
        self.get_inner().dev_info
    }

    /// Return ublk_driver's features
    ///
    /// Target code may need to query driver features runtime, so
    /// cache it inside device
    pub fn get_driver_features(&self) -> Option<u64> {
        self.get_inner().features
    }

    /// Return ublk char device path
    pub fn get_cdev_path(&self) -> String {
        self.get_inner().get_cdev_path()
    }

    /// Return ublk block device path
    pub fn get_bdev_path(&self) -> String {
        format!(
            "{}{}",
            UblkCtrlInner::BDEV_PATH,
            self.get_inner().dev_info.dev_id
        )
    }

    /// Get queue's pthread id from exported json file for this device
    ///
    /// # Arguments:
    ///
    /// * `qid`: queue id
    ///
    pub fn get_queue_tid(&self, qid: u32) -> Result<i32, UblkError> {
        let ctrl = self.get_inner();
        ctrl.json_manager.get_queue_tid_from_json(qid as u16)
    }

    /// Get target flags from exported json file for this device
    ///
    pub fn get_target_flags_from_json(&self) -> Result<u32, UblkError> {
        let ctrl = self.get_inner();
        ctrl.json_manager.get_target_flags_from_json()
    }

    /// Get target from exported json file for this device
    ///
    pub fn get_target_from_json(&self) -> Result<super::io::UblkTgt, UblkError> {
        let ctrl = self.get_inner();
        ctrl.json_manager.get_target_from_json()
    }

    /// Return target json data
    ///
    /// Should only be called after device is started, otherwise target data
    /// won't be serialized out, and this API returns None
    pub fn get_target_data_from_json(&self) -> Option<serde_json::Value> {
        let ctrl = self.get_inner();
        ctrl.json_manager.get_target_data_from_json()
    }

    /// Get target type from exported json file for this device
    ///
    pub fn get_target_type_from_json(&self) -> Result<String, UblkError> {
        let ctrl = self.get_inner();
        ctrl.json_manager.get_target_type_from_json()
    }

    /// Configure queue affinity and record queue tid
    ///
    /// # Arguments:
    ///
    /// * `qid`: queue id
    /// * `tid`: tid of the queue's pthread context
    /// * `pthread_id`: pthread handle for setting affinity
    ///
    /// Note: this method has to be called in queue daemon context
    pub fn configure_queue(&self, dev: &UblkDev, qid: u16, tid: i32) -> Result<i32, UblkError> {
        let mut ctrl = self.get_inner_mut();

        ctrl.store_queue_tid(qid, tid);

        ctrl.nr_queues_configured += 1;

        if ctrl.nr_queues_configured == ctrl.dev_info.nr_hw_queues {
            ctrl.build_json(dev)?;
        }

        Ok(0)
    }

    pub fn dump(&self) {
        let mut ctrl = self.get_inner_mut();
        let mut p = sys::ublk_params {
            ..Default::default()
        };

        if ctrl.read_dev_info().is_err() {
            error!("Dump dev {} failed\n", ctrl.dev_info.dev_id);
            return;
        }

        if ctrl.get_params(&mut p).is_err() {
            error!("Dump dev {} failed\n", ctrl.dev_info.dev_id);
            return;
        }

        ctrl.dump_device_info(&p);
        ctrl.dump_from_json();
        println!("\tublksrv_flags: 0x{:x}", ctrl.dev_info.ublksrv_flags);
    }

    pub fn run_dir() -> String {
        String::from("/run/ublksrvd")
    }

    /// Returned path of this device's exported json file
    ///
    pub fn run_path(&self) -> String {
        self.get_inner().run_path()
    }

    /// Retrieving supported UBLK FEATURES from ublk driver
    ///
    /// Supported since linux kernel v6.5
    pub fn get_features() -> Option<u64> {
        match Self::new(None, -1, 0, 0, 0, 0, 0, UblkFlags::empty()) {
            Ok(ctrl) => ctrl.get_driver_features(),
            _ => None,
        }
    }

    /// Retrieving device info from ublk driver
    ///
    pub fn read_dev_info(&self) -> Result<i32, UblkError> {
        self.get_inner_mut().read_dev_info()
    }

    /// Retrieve this device's parameter from ublk driver by
    /// sending command
    ///
    /// Can't pass params by reference(&mut), why?
    pub fn get_params(&self, params: &mut sys::ublk_params) -> Result<i32, UblkError> {
        self.get_inner_mut().get_params(params)
    }

    /// Send this device's parameter to ublk driver
    ///
    /// Note: device parameter has to send to driver before starting
    /// this device
    pub fn set_params(&self, params: &sys::ublk_params) -> Result<i32, UblkError> {
        self.get_inner_mut().set_params(params)
    }

    /// Retrieving the specified queue's affinity from ublk driver
    ///
    pub fn get_queue_affinity(&self, q: u32, bm: &mut UblkQueueAffinity) -> Result<i32, UblkError> {
        self.get_inner_mut().get_queue_affinity(q, bm)
    }

    /// Set single CPU affinity for a specific queue
    ///
    /// This method selects a single CPU from the queue's affinity mask and stores it
    /// for later use in build_json. If no CPU is specified, it selects a random CPU
    /// from the queue's current affinity mask.
    ///
    /// # Arguments
    /// * `qid` - Queue ID (0-based)
    /// * `cpu` - Optional specific CPU to use. If None, selects randomly from affinity mask
    ///
    /// # Returns
    /// The selected CPU ID on success
    pub fn set_queue_single_affinity(
        &self,
        qid: u16,
        cpu: Option<usize>,
    ) -> Result<usize, UblkError> {
        self.get_inner_mut().select_single_cpu_for_queue(qid, cpu)
    }

    /// Get the effective affinity for a specific queue thread
    ///
    /// This method retrieves the actual CPU affinity of the running queue thread
    /// using sched_getaffinity syscall with the stored thread ID (TID).
    ///
    /// # Arguments
    /// * `qid` - Queue ID (0-based)
    /// * `affinity` - UblkQueueAffinity to store the result
    ///
    /// # Returns
    /// 0 on success, or error code on failure
    pub fn get_queue_effective_affinity(
        &self,
        qid: u16,
        affinity: &mut UblkQueueAffinity,
    ) -> Result<i32, UblkError> {
        let inner = self.get_inner();

        // Validate queue ID
        UblkCtrlInner::validate_queue_id(qid, inner.queue_tids.len() as u16)?;

        let tid = inner.queue_tids[qid as usize];

        // Check if the thread has been configured (tid != 0)
        UblkCtrlInner::validate_thread_id(tid)?;

        // Use sched_getaffinity to get the actual thread affinity
        let result = unsafe {
            libc::sched_getaffinity(
                tid,
                affinity.buf_len(),
                affinity.addr_mut() as *mut libc::cpu_set_t,
            )
        };

        if result == 0 {
            Ok(0)
        } else {
            UblkCtrlInner::sys_result_to_error(-unsafe { *libc::__errno_location() })
        }
    }

    /// Start user recover for this device
    ///
    pub fn start_user_recover(&self) -> Result<i32, UblkError> {
        let mut count = 0u32;
        let unit = 100_u32;

        loop {
            let res = self.get_inner_mut().__start_user_recover();
            if let Ok(r) = res {
                if r == -libc::EBUSY {
                    std::thread::sleep(std::time::Duration::from_millis(unit as u64));
                    count += unit;
                    if count < 30000 {
                        continue;
                    }
                }
            }
            return res;
        }
    }

    /// Start ublk device
    ///
    /// # Arguments:
    ///
    /// * `dev`: ublk device
    ///
    /// Send parameter to driver, and flush json to storage, finally
    /// send START command
    ///
    /// Waits for all queue buffer registrations to complete before starting.
    /// If any queue fails mlock, this method will fail immediately.
    ///
    pub fn start_dev(&self, dev: &UblkDev) -> Result<i32, UblkError> {
        let mut ctrl = self.get_inner_mut();
        ctrl.prep_start_dev(dev)?;

        // Wait for all queue buffer registrations to complete
        dev.wait_for_buffer_registration(ctrl.dev_info.nr_hw_queues as usize)?;

        if ctrl.dev_info.state != sys::UBLK_S_DEV_QUIESCED as u16 {
            ctrl.start(unsafe { libc::getpid() as i32 })
        } else if ctrl.for_recover_dev() {
            ctrl.end_user_recover(unsafe { libc::getpid() as i32 })
        } else {
            Err(crate::UblkError::OtherError(-libc::EINVAL))
        }
    }

    /// Start ublk device in async/.await
    ///
    /// # Arguments:
    ///
    /// * `dev`: ublk device
    ///
    /// Send parameter to driver, and flush json to storage, finally
    /// send START command
    ///
    /// Waits for all queue buffer registrations to complete before starting.
    /// If any queue fails mlock, this method will fail immediately.
    ///
    /// This is the only one async API allowed without UBLK_CTRL_ASYNC_AWAIT
    ///
    pub async fn start_dev_async(&self, dev: &UblkDev) -> Result<i32, UblkError> {
        let mut ctrl = self.get_inner_mut();

        ctrl.force_async = true;

        // Wait for all queue buffer registrations to complete
        dev.wait_for_buffer_registration(ctrl.dev_info.nr_hw_queues as usize)?;

        let res = ctrl.start_dev_async(dev).await;
        ctrl.force_async = false;
        res
    }

    /// Stop ublk device
    ///
    /// Remove json export, and send stop command to control device
    ///
    pub fn stop_dev(&self) -> Result<i32, UblkError> {
        let mut ctrl = self.get_inner_mut();
        let rp = ctrl.run_path();

        if ctrl.for_add_dev() && Path::new(&rp).exists() {
            fs::remove_file(rp)?;
        }
        ctrl.stop()
    }

    /// Kill this device
    ///
    /// Preferred method for target code to stop & delete device,
    /// which is safe and can avoid deadlock.
    ///
    /// But device may not be really removed yet, and the device ID
    /// can still be in-use after kill_dev() returns.
    ///
    pub fn kill_dev(&self) -> Result<i32, UblkError> {
        self.get_inner_mut().stop()
    }

    /// Remove this device and its exported json file
    ///
    /// Called when the user wants to remove one device really
    ///
    /// Be careful, this interface may cause deadlock if the
    /// for-add control device is live, and it is always safe
    /// to kill device via .kill_dev().
    ///
    pub fn del_dev(&self) -> Result<i32, UblkError> {
        let mut ctrl = self.get_inner_mut();

        ctrl.del()?;
        if Path::new(&ctrl.run_path()).exists() {
            fs::remove_file(ctrl.run_path())?;
        }
        Ok(0)
    }

    /// Remove this device and its exported json file in async
    /// way
    pub fn del_dev_async(&self) -> Result<i32, UblkError> {
        let mut ctrl = self.get_inner_mut();

        ctrl.del_async()?;
        if Path::new(&ctrl.run_path()).exists() {
            fs::remove_file(ctrl.run_path())?;
        }
        Ok(0)
    }

    /// Calculate queue affinity based on device settings
    ///
    /// This function calculates the appropriate CPU affinity for a queue,
    /// considering single CPU affinity optimization if enabled.
    fn calculate_queue_affinity(&self, queue_id: u16) -> UblkQueueAffinity {
        self.get_inner_mut()
            .create_thread_affinity(queue_id)
            .unwrap_or_else(|_| {
                // Fallback to kernel affinity if thread affinity creation fails
                let mut affinity = UblkQueueAffinity::new();
                self.get_queue_affinity(queue_id as u32, &mut affinity)
                    .unwrap_or_default();
                affinity
            })
    }

    /// Set queue thread affinity using thread ID
    ///
    /// This function sets CPU affinity for the specified thread ID.
    /// It should be called from the main thread context after receiving
    /// the thread ID from the queue thread.
    pub fn set_thread_affinity(&self, qid: u16, tid: libc::pid_t) {
        // Calculate and set affinity using the thread ID
        let affinity = self.calculate_queue_affinity(qid);

        unsafe {
            libc::sched_setaffinity(
                tid,
                affinity.buf_len(),
                affinity.addr() as *const libc::cpu_set_t,
            );
        }
    }

    /// Initialize queue thread and return tid
    ///
    /// This function sets up the basic thread properties and returns
    /// the thread ID for external affinity configuration.
    pub fn init_queue_thread() -> libc::pid_t {
        let tid = unsafe { libc::gettid() };

        // Set IO flusher property for the queue thread
        unsafe {
            const PR_SET_IO_FLUSHER: i32 = 57; // include/uapi/linux/prctl.h
            libc::prctl(PR_SET_IO_FLUSHER, 0, 0, 0, 0);
        }

        tid
    }

    fn create_queue_handlers<Q>(
        &self,
        dev: &Arc<UblkDev>,
        q_fn: Q,
    ) -> Vec<std::thread::JoinHandle<()>>
    where
        Q: FnOnce(u16, &UblkDev) + Send + Sync + Clone + 'static,
    {
        use std::sync::mpsc;

        let mut q_threads = Vec::new();
        let nr_queues = dev.dev_info.nr_hw_queues;

        let (tx, rx) = mpsc::channel();

        for q in 0..nr_queues {
            let _dev = Arc::clone(dev);
            let _tx = tx.clone();
            let mut _q_fn = q_fn.clone();

            q_threads.push(std::thread::spawn(move || {
                let tid = Self::init_queue_thread();
                if let Err(e) = _tx.send((q, tid)) {
                    eprintln!("Warning: Failed to send queue thread info: {}", e);
                    return;
                }
                _q_fn(q, &_dev);
            }));
        }

        // Set affinity from main thread context using thread IDs
        for _q in 0..nr_queues {
            let (qid, tid) = match rx.recv() {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Warning: Failed to receive queue thread info: {}", e);
                    continue;
                }
            };

            self.set_thread_affinity(qid, tid);
            if let Err(e) = self.configure_queue(dev, qid, tid) {
                eprintln!(
                    "Warning: configure queue failed for {}-{}: {:?}",
                    dev.dev_info.dev_id, qid, e
                );
            }
        }

        q_threads
    }

    /// Run ublk daemon and kick off the ublk device, and `/dev/ublkbN` will be
    /// created and exposed to userspace.
    ///
    /// # Arguments:
    ///
    /// * `tgt_fn`: target initialization handler
    /// * `q_fn`: queue handler for setting up the queue and its handler,
    ///     all IO logical is implemented in queue handler
    /// * `device_fn`: called after device is started, run in current
    ///     context
    ///
    /// This one is the preferred interface for creating ublk daemon, and
    /// is friendly for user, such as, user can customize queue setup and
    /// io handler, such as setup async/await for handling io command.
    pub fn run_target<T, Q, W>(&self, tgt_fn: T, q_fn: Q, device_fn: W) -> Result<i32, UblkError>
    where
        T: FnOnce(&mut UblkDev) -> Result<(), UblkError>,
        Q: FnOnce(u16, &UblkDev) + Send + Sync + Clone + 'static,
        W: FnOnce(&UblkCtrl) + Send + Sync + 'static,
    {
        let dev = &Arc::new(UblkDev::new(self.get_name(), tgt_fn, self)?);
        let handles = self.create_queue_handlers(dev, q_fn);

        self.start_dev(dev)?;

        device_fn(self);

        for qh in handles {
            qh.join().unwrap_or_else(|_| {
                eprintln!("dev-{} join queue thread failed", dev.dev_info.dev_id)
            });
        }

        //device may be deleted from another context, so it is normal
        //to see -ENOENT failure here
        let _ = self.stop_dev();

        Ok(0)
    }

    /// Iterator over each ublk device ID
    pub fn for_each_dev_id<T>(ops: T)
    where
        T: Fn(u32) + Clone + 'static,
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/ublk-char") {
            for entry in entries.flatten() {
                let f = entry.path();
                if let Some(file_name) = f.file_name() {
                    if let Some(name) = file_name.to_str() {
                        // Extract device ID from ublkcN format
                        if name.starts_with("ublkc") {
                            if let Ok(dev_id) = name[5..].parse::<u32>() {
                                ops(dev_id);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ctrl::{UblkCtrlBuilder, UblkQueueAffinity};
    use crate::io::{UblkDev, UblkIOCtx, UblkQueue};
    use crate::UblkError;
    use crate::{ctrl::UblkCtrl, UblkFlags, UblkIORes};
    use std::cell::Cell;
    use std::path::Path;
    use std::rc::Rc;

    #[test]
    fn test_ublk_get_features() {
        match UblkCtrl::get_features() {
            Some(f) => eprintln!("features is {:04x}", f),
            None => eprintln!("not support GET_FEATURES, require linux v6.5"),
        }
    }

    fn __test_add_ctrl_dev(del_async: bool) {
        let ctrl = UblkCtrl::new(
            None,
            -1,
            1,
            64,
            512_u32 * 1024,
            0,
            0,
            if del_async {
                UblkFlags::UBLK_DEV_F_DEL_DEV_ASYNC
            } else {
                UblkFlags::empty()
            } | UblkFlags::UBLK_DEV_F_ADD_DEV,
        )
        .unwrap();
        let dev_path = ctrl.get_cdev_path();

        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(Path::new(&dev_path).exists() == true);
    }
    #[test]
    fn test_add_ctrl_dev_del_sync() {
        __test_add_ctrl_dev(false);
    }

    #[test]
    fn test_add_ctrl_dev_del_async() {
        __test_add_ctrl_dev(true);
    }

    #[test]
    fn test_add_ctrl_dev_del_async2() {
        let ctrl = UblkCtrl::new(
            None,
            -1,
            1,
            64,
            512_u32 * 1024,
            0,
            0,
            UblkFlags::UBLK_DEV_F_ADD_DEV,
        )
        .unwrap();

        match ctrl.del_dev_async() {
            Ok(_res) => {}
            Err(UblkError::UringIOError(res)) => {
                /* -ENOSUPP */
                assert!(res == -524 || res == -libc::EOPNOTSUPP);
            }
            _ => assert!(false),
        }
    }

    /// minimized unprivileged ublk test, may just run in root privilege
    #[test]
    fn test_add_un_privileted_ublk() {
        let ctrl = UblkCtrl::new(
            None,
            -1,
            1,
            64,
            512_u32 * 1024,
            0,
            crate::sys::UBLK_F_UNPRIVILEGED_DEV as u64,
            UblkFlags::UBLK_DEV_F_ADD_DEV,
        )
        .unwrap();
        let dev_path = ctrl.get_cdev_path();

        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(Path::new(&dev_path).exists() == true);
    }

    #[test]
    fn test_set_queue_single_affinity() {
        let ctrl = UblkCtrlBuilder::default()
            .name("null")
            .nr_queues(2_u16)
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap();

        // Test invalid queue ID (should fail regardless of device state)
        let invalid_queue = ctrl.set_queue_single_affinity(100, None);
        assert!(invalid_queue.is_err());

        // Test that the method exists and has correct signature by checking queue_selected_cpus initialization
        let inner = ctrl.get_inner();
        assert_eq!(inner.queue_selected_cpus.len(), 2);
        assert_eq!(inner.queue_selected_cpus[0], 0); // Should be initialized to 0
        assert_eq!(inner.queue_selected_cpus[1], 0); // Should be initialized to 0
    }

    #[test]
    fn test_get_queue_effective_affinity() {
        let ctrl = UblkCtrlBuilder::default()
            .name("null")
            .nr_queues(2_u16)
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap();

        let mut affinity = UblkQueueAffinity::new();

        // Test invalid queue ID
        let invalid_queue_result = ctrl.get_queue_effective_affinity(100, &mut affinity);
        assert!(invalid_queue_result.is_err());

        // Test unconfigured queue (tid == 0)
        let unconfigured_result = ctrl.get_queue_effective_affinity(0, &mut affinity);
        assert!(unconfigured_result.is_err());
        // Should return ESRCH error for unconfigured thread
        if let Err(UblkError::OtherError(err)) = unconfigured_result {
            assert_eq!(err, -libc::ESRCH);
        }

        // Test that the method signature is correct and compiles
        // Actual functionality testing would require a running queue thread
        assert!(true); // Method compiles and basic validation works
    }

    #[test]
    fn test_ublk_target_json() {
        let ctrl = UblkCtrlBuilder::default()
            .name("null")
            .ctrl_target_flags(0xbeef as u64)
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap();

        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            dev.set_target_json(serde_json::json!({"null": "test_data" }));
            Ok(())
        };
        let dev = UblkDev::new(ctrl.get_name(), tgt_init, &ctrl).unwrap();

        //not built & flushed out yet
        assert!(ctrl.get_target_data_from_json().is_none());
        assert!(dev.get_target_json().is_some());
        assert!(dev.dev_info.ublksrv_flags == 0xbeef as u64);
        assert!(ctrl.dev_info().ublksrv_flags == 0xbeef as u64);
    }

    fn __test_ublk_session<T>(mut w_fn: T) -> String
    where
        T: FnMut(&UblkCtrl) + Send + Sync + Clone + 'static,
    {
        let ctrl = UblkCtrlBuilder::default()
            .name("null")
            .depth(16_u16)
            .nr_queues(2_u16)
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap();

        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            dev.set_target_json(serde_json::json!({"null": "test_data" }));
            Ok(())
        };
        let q_fn = move |qid: u16, dev: &UblkDev| {
            use crate::BufDescList;
            let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
            let bufs = bufs_rc.clone();

            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let iod = q.get_iod(tag);
                let bytes = (iod.nr_sectors << 9) as i32;
                let bufs = bufs_rc.clone();
                let buf_addr = bufs[tag as usize].as_mut_ptr();

                #[allow(deprecated)]
                q.complete_io_cmd(tag, buf_addr, Ok(UblkIORes::Result(bytes)));
            };

            let queue = match UblkQueue::new(qid, dev)
                .unwrap()
                .submit_fetch_commands_unified(BufDescList::Slices(Some(&bufs)))
            {
                Ok(q) => q,
                Err(e) => {
                    log::error!("submit_fetch_commands_unified failed: {}", e);
                    return;
                }
            };

            queue.wait_and_handle_io(io_handler);
        };

        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            w_fn(ctrl);
        })
        .unwrap();

        // could be too strict because of udev
        let bdev = ctrl.get_bdev_path();
        assert!(Path::new(&bdev).exists() == false);

        let cpath = ctrl.get_cdev_path();

        cpath
    }

    /// Covers basic ublk device creation and destroying by UblkSession
    /// APIs
    #[test]
    fn test_ublk_session() {
        let cdev = __test_ublk_session(|ctrl: &UblkCtrl| {
            assert!(ctrl.get_target_data_from_json().is_some());
            ctrl.kill_dev().unwrap();
        });

        // could be too strict because of udev
        assert!(Path::new(&cdev).exists() == false);
    }
    /// test for_each_dev_id
    #[test]
    fn test_ublk_for_each_dev_id() {
        use std::sync::{atomic::AtomicI32, atomic::Ordering, Arc};

        // Create one ublk device and capture its device ID
        let created_dev_id = Arc::new(AtomicI32::new(-1));
        let created_dev_id_clone = created_dev_id.clone();

        let handle = std::thread::spawn(move || {
            let cdev = __test_ublk_session(move |ctrl: &UblkCtrl| {
                // Capture the device ID of the device we created
                created_dev_id_clone.store(ctrl.dev_info().dev_id as i32, Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(1000));
                ctrl.kill_dev().unwrap();
            });
            // could be too strict because of udev
            assert!(Path::new(&cdev).exists() == false);
        });

        std::thread::sleep(std::time::Duration::from_millis(400));
        let cnt_arc = Rc::new(Cell::new(0));
        let cnt = cnt_arc.clone();

        // Only count the device we created in this test
        UblkCtrl::for_each_dev_id(move |dev_id| {
            let target_dev_id = created_dev_id.load(Ordering::Relaxed);
            if target_dev_id >= 0 && dev_id == target_dev_id as u32 {
                let ctrl = UblkCtrl::new_simple(dev_id as i32).unwrap();
                cnt.set(cnt.get() + 1);

                let dev_path = ctrl.get_cdev_path();
                assert!(Path::new(&dev_path).exists() == true);
            }
        });

        // we should have found exactly one device (the one we created)
        assert_eq!(cnt_arc.get(), 1);

        handle.join().unwrap();
    }

    /// Test UBLK_DEV_F_SINGLE_CPU_AFFINITY feature
    #[test]
    fn test_single_cpu_affinity() {
        // Test 1: Verify the flag is properly defined and can be used
        let single_cpu_flags =
            UblkFlags::UBLK_DEV_F_ADD_DEV | UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY;
        let normal_flags = UblkFlags::UBLK_DEV_F_ADD_DEV;

        assert!(single_cpu_flags.contains(UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY));
        assert!(!normal_flags.contains(UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY));

        // Test 2: Create control devices with and without the flag
        let ctrl_with_flag = UblkCtrlBuilder::default()
            .name("test_single_cpu")
            .depth(16_u16)
            .nr_queues(2_u16)
            .dev_flags(single_cpu_flags)
            .build()
            .unwrap();

        let ctrl_without_flag = UblkCtrlBuilder::default()
            .name("test_normal")
            .depth(16_u16)
            .nr_queues(2_u16)
            .dev_flags(normal_flags)
            .build()
            .unwrap();

        // Test 3: Verify flag is stored correctly in the control device
        assert!(ctrl_with_flag
            .get_dev_flags()
            .contains(UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY));
        assert!(!ctrl_without_flag
            .get_dev_flags()
            .contains(UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY));

        // Test 4: Test UblkQueueAffinity helper methods
        let test_affinity = UblkQueueAffinity::from_single_cpu(3);
        let bits = test_affinity.to_bits_vec();
        assert_eq!(
            bits.len(),
            1,
            "Single CPU affinity should contain exactly one CPU"
        );
        assert_eq!(bits[0], 3, "Single CPU affinity should contain CPU 3");

        // Test 5: Test random CPU selection (create an affinity with multiple CPUs and verify selection)
        let mut multi_cpu_affinity = UblkQueueAffinity::new();
        multi_cpu_affinity.set_cpu(1);
        multi_cpu_affinity.set_cpu(3);
        multi_cpu_affinity.set_cpu(5);

        let selected_cpu = multi_cpu_affinity.get_random_cpu();
        assert!(
            selected_cpu.is_some(),
            "Should be able to select a CPU from multi-CPU affinity"
        );

        let cpu = selected_cpu.unwrap();
        assert!(
            cpu == 1 || cpu == 3 || cpu == 5,
            "Selected CPU should be one of the available CPUs (1, 3, or 5), got {}",
            cpu
        );

        println!("✓ Single CPU affinity feature tests passed");
        println!("  - Flag definition and usage: PASS");
        println!("  - Control device flag storage: PASS");
        println!("  - Single CPU affinity creation: PASS");
        println!("  - Random CPU selection: PASS (selected CPU {})", cpu);
    }
}
