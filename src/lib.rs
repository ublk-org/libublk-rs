#![allow(dead_code)]
#![allow(non_snake_case, non_camel_case_types)]
include!(concat!(env!("OUT_DIR"), "/ublk_cmd.rs"));

use anyhow::Result as AnyRes;
use bitmaps::Bitmap;
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use log::{error, info, trace};
use std::alloc::{alloc, dealloc, Layout};
use std::any::Any;
use std::cell::RefCell;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Condvar, Mutex};
use std::{env, fs};

//todo: fix bindgen to cover the following definition
const UBLK_IO_RES_ABORT: i32 = -libc::ENODEV;

const CTRL_PATH: &str = "/dev/ublk-control";
const CDEV_PATH: &str = "/dev/ublkc";
const BDEV_PATH: &str = "/dev/ublkb";

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
    pub fn to_bits_vec(&self) -> Vec<usize> {
        self.affinity.into_iter().collect()
    }
}

union CtrlCmd {
    ctrl_cmd: ublksrv_ctrl_cmd,
    buf: [u8; 80],
}

const CTRL_CMD_HAS_DATA: u32 = 1;
const CTRL_CMD_HAS_BUF: u32 = 2;

#[derive(Debug, Default, Copy, Clone)]
struct UblkCtrlCmdData {
    cmd_op: u32,
    flags: u32,
    data: [u64; 2],
    addr: u64,
    len: u32,
}

fn ublk_ctrl_prep_cmd(fd: i32, dev_id: u32, data: &UblkCtrlCmdData) -> squeue::Entry128 {
    let cmd = ublksrv_ctrl_cmd {
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
            [data.data[0] as u64]
        } else {
            [0]
        },
        dev_id: dev_id,
        queue_id: u16::MAX,
        ..Default::default()
    };
    let c_cmd = CtrlCmd { ctrl_cmd: cmd };

    opcode::UringCmd80::new(types::Fd(fd), data.cmd_op)
        .cmd(unsafe { c_cmd.buf })
        .build()
}

fn ublk_ctrl_cmd(ctrl: &mut UblkCtrl, data: &UblkCtrlCmdData) -> AnyRes<i32> {
    let sqe = ublk_ctrl_prep_cmd(ctrl.file.as_raw_fd(), ctrl.dev_info.dev_id, data);

    unsafe {
        ctrl.ring.submission().push(&sqe).expect("submission fail");
    }
    ctrl.ring.submit_and_wait(1)?;

    let cqe = ctrl.ring.completion().next().expect("cqueue is empty");
    match cqe.result() {
        0 => Ok(0),
        e => Err(anyhow::anyhow!(e)),
    }
}

#[derive(Debug, Deserialize)]
struct queue_affinity_json {
    affinity: Vec<u32>,
    qid: u32,
    tid: u32,
}

/// UBLK controller
///
/// Responsible for:
///
/// 1) adding and removing ublk char device(/dev/ublkcN)
///
/// 2) send all kinds of control commands
///
/// 3) exporting device as json file
pub struct UblkCtrl {
    file: fs::File,
    pub dev_info: ublksrv_ctrl_dev_info,
    pub json: serde_json::Value,
    for_add: bool,
    ring: IoUring<squeue::Entry128>,
}

impl Drop for UblkCtrl {
    fn drop(&mut self) {
        let id = self.dev_info.dev_id;
        trace!("ctrl: device {} dropped", id);
        if self.for_add {
            if let Err(r) = self.del() {
                //Maybe deleted from other utilities, so no warn or error:w
                trace!("Delete char device {} failed {}", self.dev_info.dev_id, r);
            }
        }
    }
}

impl UblkCtrl {
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
    ///
    /// ublk control device is for sending command to driver, and maintain
    /// device exported json file, dump, or any misc management task.
    ///
    pub fn new(
        id: i32,
        nr_queues: u32,
        depth: u32,
        io_buf_bytes: u32,
        flags: u64,
        for_add: bool,
    ) -> AnyRes<UblkCtrl> {
        let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder().build(16)?;
        let info = ublksrv_ctrl_dev_info {
            nr_hw_queues: nr_queues as u16,
            queue_depth: depth as u16,
            max_io_buf_bytes: io_buf_bytes,
            dev_id: id as u32,
            ublksrv_pid: unsafe { libc::getpid() } as i32,
            flags: flags,
            ..Default::default()
        };
        let fd = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(CTRL_PATH)?;

        let mut dev = UblkCtrl {
            file: fd,
            dev_info: info,
            json: serde_json::json!({}),
            ring: ring,
            for_add: for_add,
        };

        //add cdev if the device is for adding device
        if dev.for_add {
            dev.add()?;
        }
        trace!("ctrl: device {} created", dev.dev_info.dev_id);

        Ok(dev)
    }

    fn dev_state_desc(&self) -> String {
        match self.dev_info.state as u32 {
            UBLK_S_DEV_DEAD => "DEAD".to_string(),
            UBLK_S_DEV_LIVE => "LIVE".to_string(),
            _ => "UNKNOWN".to_string(),
        }
    }

    pub fn dump_from_json(&self) {
        if std::path::Path::new(&self.run_path()).exists() == false {
            return;
        }
        let mut file = fs::File::open(self.run_path()).expect("Failed to open file");
        let mut json_str = String::new();

        file.read_to_string(&mut json_str)
            .expect("Failed to read file");

        let json_value: serde_json::Value =
            serde_json::from_str(&json_str).expect("Failed to parse JSON");
        let queues = &json_value["queues"];

        for i in 0..self.dev_info.nr_hw_queues {
            let queue = &queues[i.to_string()];
            let this_queue: Result<queue_affinity_json, _> = serde_json::from_value(queue.clone());

            match this_queue {
                Ok(p) => println!(
                    "\tqueue {} tid: {} affinity({})",
                    i,
                    p.tid,
                    p.affinity
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<String>>()
                        .join(" ")
                ),
                Err(_) => {}
            }
        }
        let tgt_val = &json_value["target"];
        let tgt: Result<UblkTgt, _> = serde_json::from_value(tgt_val.clone());
        match tgt {
            Ok(p) => println!(
                "\ttarget {{\"dev_size\":{},\"name\":\"{}\",\"type\":0}}",
                p.dev_size, p.tgt_type
            ),
            Err(_) => {}
        }
    }
    pub fn dump(&mut self) {
        let mut p = ublk_params {
            ..Default::default()
        };

        if let Err(_) = self.get_info() {
            error!("Dump dev {} failed\n", self.dev_info.dev_id);
            return;
        }

        match self.get_params(p) {
            Ok(r) => p = r,
            Err(_) => {
                error!("Dump dev {} failed\n", self.dev_info.dev_id);
                return;
            }
        }

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

        self.dump_from_json();
    }

    pub fn run_dir() -> String {
        format!("{}/ublk", std::env::temp_dir().display())
    }

    fn run_path(&self) -> String {
        format!("{}/{:04}.json", UblkCtrl::run_dir(), self.dev_info.dev_id)
    }

    fn add(&mut self) -> AnyRes<i32> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: UBLK_CMD_ADD_DEV,
            flags: CTRL_CMD_HAS_BUF,
            addr: std::ptr::addr_of!(self.dev_info) as u64,
            len: core::mem::size_of::<ublksrv_ctrl_dev_info>() as u32,
            data: [0, 0],
        };

        ublk_ctrl_cmd(self, &data)
    }

    pub fn del(&mut self) -> AnyRes<i32> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: UBLK_CMD_DEL_DEV,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    pub fn get_info(&mut self) -> AnyRes<i32> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: UBLK_CMD_GET_DEV_INFO,
            flags: CTRL_CMD_HAS_BUF,
            addr: std::ptr::addr_of!(self.dev_info) as u64,
            len: core::mem::size_of::<ublksrv_ctrl_dev_info>() as u32,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    pub fn start(&mut self, pid: i32) -> AnyRes<i32> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: UBLK_CMD_START_DEV,
            flags: CTRL_CMD_HAS_DATA,
            data: [pid as u64, 0],
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    pub fn stop(&mut self) -> AnyRes<i32> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: UBLK_CMD_STOP_DEV,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    /// Can't pass params by reference(&mut), why?
    pub fn get_params(&mut self, mut params: ublk_params) -> AnyRes<ublk_params> {
        params.len = core::mem::size_of::<ublk_params>() as u32;
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: UBLK_CMD_GET_PARAMS,
            flags: CTRL_CMD_HAS_BUF,
            addr: std::ptr::addr_of!(params) as u64,
            len: params.len,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)?;
        Ok(params)
    }

    pub fn set_params(&mut self, params: &ublk_params) -> AnyRes<i32> {
        let mut p = params.clone();

        p.len = core::mem::size_of::<ublk_params>() as u32;
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: UBLK_CMD_SET_PARAMS,
            flags: CTRL_CMD_HAS_BUF,
            addr: std::ptr::addr_of!(p) as u64,
            len: p.len,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    pub fn get_queue_affinity(&mut self, q: u32, bm: &mut UblkQueueAffinity) -> AnyRes<i32> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: UBLK_CMD_GET_QUEUE_AFFINITY,
            flags: CTRL_CMD_HAS_BUF | CTRL_CMD_HAS_DATA,
            addr: bm.addr() as u64,
            data: [q as u64, 0],
            len: bm.buf_len() as u32,
            ..Default::default()
        };
        ublk_ctrl_cmd(self, &data)
    }

    /// Start ublk device
    ///
    /// # Arguments:
    ///
    /// * `_dev`: ublk device
    ///
    /// Send parameter to driver, and flush json to storage, finally
    /// send START command
    ///
    pub fn start_dev(&mut self, dev: &UblkDev) -> AnyRes<i32> {
        let params = dev.tgt.borrow();

        self.set_params(&params.params)?;
        self.flush_json()?;
        self.start(unsafe { libc::getpid() as i32 })?;

        Ok(0)
    }

    /// Stop ublk device
    ///
    /// # Arguments:
    ///
    /// * `_dev`: ublk device
    ///
    /// Remove json export, and send stop command to control device
    ///
    pub fn stop_dev(&mut self, _dev: &UblkDev) -> AnyRes<i32> {
        if self.for_add && std::path::Path::new(&self.run_path()).exists() == true {
            fs::remove_file(self.run_path())?;
        }
        self.stop()
    }

    pub fn flush_json(&mut self) -> AnyRes<i32> {
        let run_path = self.run_path();

        if let Some(parent_dir) = std::path::Path::new(&run_path).parent() {
            fs::create_dir_all(parent_dir)?;
        }
        let mut run_file = fs::File::create(&run_path)?;

        run_file.write_all(self.json.to_string().as_bytes())?;
        Ok(0)
    }

    pub fn build_json(&mut self, dev: &UblkDev, affi: Vec<UblkQueueAffinity>, tids: Vec<i32>) {
        let tgt_data = self.json["target_data"].clone();
        let mut map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

        for qid in 0..dev.dev_info.nr_hw_queues {
            map.insert(
                format!("{}", qid),
                serde_json::json!({
                    "qid": qid,
                    "tid": tids[qid as usize],
                    "affinity": affi[qid as usize].to_bits_vec(),
                }),
            );
        }

        let mut json = serde_json::json!({
                    "dev_info": dev.dev_info,
                    "target": dev.tgt,
        });

        json["target_data"] = tgt_data;
        json["queues"] = serde_json::Value::Object(map);

        self.json = json;
    }
    /// Create queue thread handler(high level)
    ///
    /// # Arguments:
    ///
    /// * `_dev`: UblkDev reference, which is required for creating queue
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
    pub fn create_queue_handler<F: Fn() -> Box<dyn UblkQueueImpl> + Send + Sync + 'static>(
        &mut self,
        dev: &Arc<UblkDev>,
        sq_depth: u32,
        cq_depth: u32,
        ring_flags: u64,
        f: Arc<F>,
    ) -> Vec<std::thread::JoinHandle<()>> {
        let mut q_threads = Vec::new();
        let mut q_affi = Vec::new();
        let mut q_tids = Vec::new();
        let nr_queues = dev.dev_info.nr_hw_queues;
        let mut tids = Vec::<Arc<(Mutex<i32>, Condvar)>>::with_capacity(nr_queues as usize);

        for q in 0..nr_queues {
            let mut affinity = UblkQueueAffinity::new();
            self.get_queue_affinity(q as u32, &mut affinity).unwrap();

            let _dev = Arc::clone(dev);
            let _q_id = q.clone();
            let tid = Arc::new((Mutex::new(0_i32), Condvar::new()));
            let _tid = Arc::clone(&tid);
            let _fn = f.clone();
            let _affinity = affinity.clone();

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
                let ops: &'static dyn UblkQueueImpl = &*Box::leak(_fn());
                UblkQueue::new(_q_id, &_dev, sq_depth, cq_depth, ring_flags)
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
        self.build_json(&dev, q_affi, q_tids);

        q_threads
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UblkTgt {
    pub tgt_type: String,
    pub dev_size: u64,
    //const struct ublk_tgt_ops *ops;
    pub params: ublk_params,
}

pub struct UblkTgtData {
    pub fds: [i32; 32],
    pub nr_fds: i32,
}

pub struct UblkDev {
    pub dev_info: ublksrv_ctrl_dev_info,

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
    pub fn new(ops: Box<dyn UblkTgtImpl>, ctrl: &mut UblkCtrl) -> AnyRes<UblkDev> {
        let tgt = UblkTgt {
            tgt_type: ops.tgt_type().to_string(),
            ..Default::default()
        };
        let mut data = UblkTgtData {
            fds: [0_i32; 32],
            nr_fds: 0,
        };

        let info = ctrl.dev_info.clone();
        let cdev_path = format!("{}{}", CDEV_PATH, info.dev_id);
        let cdev_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(cdev_path)?;

        data.fds[0] = cdev_file.as_raw_fd();
        data.nr_fds = 1;

        let dev = UblkDev {
            ops: ops,
            dev_info: info,
            cdev_file: cdev_file,
            tgt: RefCell::new(tgt),
            tdata: RefCell::new(data),
        };

        ctrl.json = dev.ops.init_tgt(&dev)?;
        info!("dev {} initialized", dev.dev_info.dev_id);

        Ok(dev)
    }

    //private method for drop
    fn deinit_cdev(&mut self) -> AnyRes<i32> {
        let id = self.dev_info.dev_id;

        self.ops.deinit_tgt(self);
        info!("dev {} deinitialized", id);
        Ok(0)
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
/// Use as_any()/Downcast trick for doing this job, see [downcast_trait_object]
/// (https://bennett.dev/rust/downcast-trait-object/)
///
#[inline(always)]
pub fn ublk_tgt_data_from_queue<T: 'static>(dev: &UblkDev) -> AnyRes<&T> {
    let a = dev.ops.as_any();

    let tgt: &T = match a.downcast_ref::<T>() {
        Some(b) => b,
        _ => return Err(anyhow::anyhow!("downcast failed")),
    };

    Ok(tgt)
}

impl Drop for UblkDev {
    fn drop(&mut self) {
        if let Err(err) = self.deinit_cdev() {
            error!("deinit cdev {} failed {}", self.dev_info.dev_id, err);
        }
    }
}

pub trait UblkQueueImpl {
    fn queue_io(&self, q: &mut UblkQueue, tag: u32) -> AnyRes<i32>;
    #[inline(always)]
    fn tgt_io_done(&self, _q: &mut UblkQueue, _tag: u32, _res: i32, _user_data: u64) {}
    fn setup_queue(&mut self, _q: &UblkQueue, _dev: &UblkDev) -> AnyRes<i32> {
        Ok(0)
    }
}

pub trait UblkTgtImpl {
    /// Init this target
    ///
    /// Initialize this target, dev_data is usually built from command line, so
    /// it is produced and consumed by target code.
    fn init_tgt(&self, dev: &UblkDev) -> AnyRes<serde_json::Value>;

    /// Deinit this target
    ///
    /// Release target specific resource.
    fn deinit_tgt(&self, dev: &UblkDev);

    fn tgt_type(&self) -> &'static str;

    fn as_any(&self) -> &dyn Any;
}

#[repr(C, align(512))]
struct ublk_dio_buf([u8; 512]);

union IOCmd {
    cmd: ublksrv_io_cmd,
    buf: [u8; 16],
}

#[inline(always)]
#[allow(arithmetic_overflow)]
pub fn build_user_data(tag: u16, op: u32, tgt_data: u32, is_target_io: bool) -> u64 {
    assert!((op >> 8) == 0 && (tgt_data >> 16) == 0);

    match is_target_io {
        true => tag as u64 | (op << 16) as u64 | (tgt_data << 24) as u64 | (1_u64 << 63),
        false => tag as u64 | (op << 16) as u64 | (tgt_data << 24) as u64,
    }
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
pub struct UblkIO {
    pub buf_addr: *mut u8,
    flags: u32,
    result: i32,
}

impl UblkIO {
    fn is_done(&self) -> bool {
        self.flags & (UBLK_IO_NEED_COMMIT_RQ_COMP | UBLK_IO_FREE) != 0
    }
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
            ublk_dealloc_buf(io.buf_addr, dev.dev_info.max_io_buf_bytes as usize, 512);
        }
    }
}

impl UblkQueue<'_> {
    #[inline(always)]
    fn cmd_buf_sz(depth: u32) -> u32 {
        let size = depth * core::mem::size_of::<ublksrv_io_desc>() as u32;
        let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;

        return round_up(size, page_sz);
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
    pub fn new(
        q_id: u16,
        dev: &UblkDev,
        sq_depth: u32,
        cq_depth: u32,
        _ring_flags: u64,
    ) -> AnyRes<UblkQueue> {
        let td = dev.tdata.borrow();
        let ring = IoUring::<squeue::Entry, cqueue::Entry>::builder()
            .setup_cqsize(cq_depth)
            .setup_coop_taskrun()
            .build(sq_depth)?;
        let depth = dev.dev_info.queue_depth as u32;
        let cdev_fd = dev.cdev_file.as_raw_fd();
        let cmd_buf_sz = UblkQueue::cmd_buf_sz(depth) as usize;

        ring.submitter()
            .register_files(&td.fds[0..td.nr_fds as usize])?;

        let off = UBLKSRV_CMD_BUF_OFFSET as i64
            + q_id as i64
                * ((UBLK_MAX_QUEUE_DEPTH as usize * core::mem::size_of::<ublksrv_io_desc>())
                    as i64);
        let io_cmd_buf = unsafe {
            libc::mmap(
                0 as *mut libc::c_void,
                cmd_buf_sz,
                libc::PROT_READ,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                cdev_fd,
                off as i64,
            )
        };
        if io_cmd_buf == libc::MAP_FAILED {
            return Err(anyhow::anyhow!("io command buf mapping failed"));
        }

        let mut ios = Vec::<UblkIO>::with_capacity(depth as usize);
        unsafe {
            ios.set_len(depth as usize);
        }
        for io in &mut ios {
            io.buf_addr = ublk_alloc_buf(dev.dev_info.max_io_buf_bytes as usize, 512);
            io.flags = UBLK_IO_NEED_FETCH_RQ | UBLK_IO_FREE;
            io.result = -1;
        }

        let q = UblkQueue {
            q_id: q_id,
            q_depth: depth,
            io_cmd_buf: io_cmd_buf as u64,
            dev: dev,
            cmd_inflight: 0,
            q_state: 0,
            q_ring: ring,
            ios: ios,
        };

        trace!("dev {} queue {} started", dev.dev_info.dev_id, q_id);

        Ok(q)
    }

    #[inline(always)]
    pub fn get_buf_addr(&self, tag: u32) -> *mut u8 {
        return self.ios[tag as usize].buf_addr;
    }

    #[inline(always)]
    fn mark_io_done(&mut self, tag: u16, res: i32) {
        self.ios[tag as usize].flags |= UBLK_IO_NEED_COMMIT_RQ_COMP | UBLK_IO_FREE;
        self.ios[tag as usize].result = res;
    }

    #[inline(always)]
    pub fn get_iod(&self, idx: u32) -> *const ublksrv_io_desc {
        (self.io_cmd_buf + idx as u64 * 24) as *const ublksrv_io_desc
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
            cmd_op = UBLK_IO_COMMIT_AND_FETCH_REQ;
        } else if (io.flags & UBLK_IO_NEED_FETCH_RQ) != 0 {
            cmd_op = UBLK_IO_FETCH_REQ;
        } else {
            return 0;
        }

        let io_cmd = IOCmd {
            cmd: ublksrv_io_cmd {
                tag: tag,
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

        if res == UBLK_IO_RES_ABORT || ((self.q_state & UBLK_QUEUE_STOPPING) != 0) {
            self.q_state |= UBLK_QUEUE_STOPPING;
            self.ios[tag as usize].flags &= !UBLK_IO_NEED_FETCH_RQ;
        }

        if res == UBLK_IO_RES_OK as i32 {
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
    pub fn process_io(&mut self, ops: &dyn UblkQueueImpl) -> AnyRes<i32> {
        info!(
            "dev{}-q{}: to_submit {} inflight cmd {} stopping {}",
            self.dev.dev_info.dev_id,
            self.q_id,
            0,
            self.cmd_inflight,
            (self.q_state & UBLK_QUEUE_STOPPING)
        );

        if self.queue_is_done() {
            if self.q_ring.submission().is_empty() {
                return Err(anyhow::anyhow!("queue is down"));
            }
        }

        let ret = self.q_ring.submit_and_wait(1)?;
        let reapped = self.reap_events_uring(ops);

        info!(
            "submit result {}, reapped {} stop {} idle {}",
            ret,
            reapped,
            (self.q_state & UBLK_QUEUE_STOPPING),
            (self.q_state & UBLK_QUEUE_IDLE)
        );
        return Ok(reapped as i32);
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
pub fn ublk_tgt_worker<T, Q, W>(
    id: i32,
    nr_queues: u32,
    depth: u32,
    io_buf_bytes: u32,
    flags: u64,
    tgt_fn: T,
    q_fn: Arc<Q>,
    worker_fn: W,
) -> AnyRes<std::thread::JoinHandle<()>>
where
    T: Fn() -> Box<dyn UblkTgtImpl> + Send + Sync,
    Q: Fn() -> Box<dyn UblkQueueImpl> + Send + Sync + 'static,
    W: Fn(i32) + Send + Sync + 'static,
{
    let mut ctrl = UblkCtrl::new(id, nr_queues, depth, io_buf_bytes, flags, true).unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Arc;

    #[test]
    fn add_ctrl_dev() {
        let ctrl = UblkCtrl::new(-1, 1, 64, 512_u32 * 1024, 0, true).unwrap();
        let dev_path = format!("{}{}", CDEV_PATH, ctrl.dev_info.dev_id);

        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(Path::new(&dev_path).exists() == true);
    }

    struct NullTgt {}
    struct NullQueue {}

    // setup null target
    impl UblkTgtImpl for NullTgt {
        fn init_tgt(&self, dev: &UblkDev) -> AnyRes<serde_json::Value> {
            let info = dev.dev_info;
            let dev_size = 250_u64 << 30;

            let mut tgt = dev.tgt.borrow_mut();

            tgt.dev_size = dev_size;
            tgt.params = ublk_params {
                types: UBLK_PARAM_TYPE_BASIC,
                basic: ublk_param_basic {
                    logical_bs_shift: 9,
                    physical_bs_shift: 12,
                    io_opt_shift: 12,
                    io_min_shift: 9,
                    max_sectors: info.max_io_buf_bytes >> 9,
                    dev_sectors: dev_size >> 9,
                    ..Default::default()
                },
                ..Default::default()
            };

            Ok(serde_json::json!({}))
        }
        fn deinit_tgt(&self, _dev: &UblkDev) {}
        fn tgt_type(&self) -> &'static str {
            "null"
        }
        #[inline(always)]
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    // implement io logic, and it is the main job for writing new ublk target
    impl UblkQueueImpl for NullQueue {
        fn queue_io(&self, q: &mut UblkQueue, tag: u32) -> AnyRes<i32> {
            let iod = q.get_iod(tag);
            let bytes = unsafe { (*iod).nr_sectors << 9 } as i32;

            q.complete_io(tag as u16, bytes);
            Ok(0)
        }
    }

    /// make one ublk-null and test if /dev/ublkbN can be created successfully
    #[test]
    fn test_ublk_null() {
        ublk_tgt_worker(
            -1,
            2,
            64,
            512_u32 * 1024,
            0,
            || Box::new(NullTgt {}),
            Arc::new(|| Box::new(NullQueue {}) as Box<dyn UblkQueueImpl>),
            |dev_id| {
                let mut ctrl = UblkCtrl::new(dev_id, 0, 0, 0, 0, false).unwrap();
                let dev_path = format!("{}{}", BDEV_PATH, dev_id);

                std::thread::sleep(std::time::Duration::from_millis(500));

                //ublk block device should be observed now
                assert!(Path::new(&dev_path).exists() == true);

                //ublk exported json file should be observed
                assert!(Path::new(&ctrl.run_path()).exists() == true);

                ctrl.del().unwrap();
            },
        )
        .unwrap()
        .join()
        .unwrap();
    }

    struct RamdiskTgt {
        size: u64,
        start: u64,
    }

    struct RamdiskQueue {}

    // setup ramdisk target
    impl UblkTgtImpl for RamdiskTgt {
        fn init_tgt(&self, dev: &UblkDev) -> AnyRes<serde_json::Value> {
            let info = dev.dev_info;
            let dev_size = self.size;

            let mut tgt = dev.tgt.borrow_mut();

            tgt.dev_size = dev_size;
            tgt.params = ublk_params {
                types: UBLK_PARAM_TYPE_BASIC,
                basic: ublk_param_basic {
                    logical_bs_shift: 12,
                    physical_bs_shift: 12,
                    io_opt_shift: 12,
                    io_min_shift: 12,
                    max_sectors: info.max_io_buf_bytes >> 9,
                    dev_sectors: dev_size >> 9,
                    ..Default::default()
                },
                ..Default::default()
            };

            Ok(serde_json::json!({}))
        }
        fn deinit_tgt(&self, _dev: &UblkDev) {}
        fn tgt_type(&self) -> &'static str {
            "ramdisk"
        }
        #[inline(always)]
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    // implement io logic, and it is the main job for writing new ublk target
    impl UblkQueueImpl for RamdiskQueue {
        fn queue_io(&self, q: &mut UblkQueue, tag: u32) -> AnyRes<i32> {
            let _iod = q.get_iod(tag);
            let iod = unsafe { &*_iod };
            let off = (iod.start_sector << 9) as u64;
            let bytes = (iod.nr_sectors << 9) as u32;
            let op = iod.op_flags & 0xff;
            let tgt = ublk_tgt_data_from_queue::<RamdiskTgt>(q.dev).unwrap();
            let start = tgt.start;
            let buf_addr = q.get_buf_addr(tag);

            match op {
                UBLK_IO_OP_FLUSH => {}
                UBLK_IO_OP_READ => unsafe {
                    libc::memcpy(
                        buf_addr as *mut libc::c_void,
                        (start + off) as *mut libc::c_void,
                        bytes as usize,
                    );
                },
                UBLK_IO_OP_WRITE => unsafe {
                    libc::memcpy(
                        (start + off) as *mut libc::c_void,
                        buf_addr as *mut libc::c_void,
                        bytes as usize,
                    );
                },
                _ => return Err(anyhow::anyhow!("unexpected op")),
            }

            q.complete_io(tag as u16, bytes as i32);
            Ok(0)
        }
    }

    /// make one ublk-null and test if /dev/ublkbN can be created successfully
    #[test]
    fn test_ublk_ramdisk() {
        let size = 32_u64 << 20;
        let buf = ublk_alloc_buf(size as usize, 4096);
        let buf_addr = buf as u64;

        ublk_tgt_worker(
            -1,
            1,
            64,
            512_u32 * 1024,
            0,
            || {
                Box::new(RamdiskTgt {
                    size: size,
                    start: buf_addr,
                })
            },
            Arc::new(|| Box::new(RamdiskQueue {}) as Box<dyn UblkQueueImpl>),
            |dev_id| {
                let mut ctrl = UblkCtrl::new(dev_id, 0, 0, 0, 0, false).unwrap();
                let dev_path = format!("{}{}", BDEV_PATH, dev_id);

                std::thread::sleep(std::time::Duration::from_millis(500));

                //ublk block device should be observed now
                assert!(Path::new(&dev_path).exists() == true);

                //ublk exported json file should be observed
                assert!(Path::new(&ctrl.run_path()).exists() == true);

                //format as ext4 test over the ramdisk
                {
                    let ext4_options = block_utils::Filesystem::Ext4 {
                        inode_size: 512,
                        stride: Some(2),
                        stripe_width: None,
                        reserved_blocks_percentage: 10,
                    };
                    block_utils::format_block_device(&Path::new(&dev_path), &ext4_options).unwrap();

                    let tmp_dir = tempfile::TempDir::new().unwrap();
                    let bdev = block_utils::get_device_info(Path::new(&dev_path)).unwrap();

                    block_utils::mount_device(&bdev, tmp_dir.path()).unwrap();
                    block_utils::unmount_device(tmp_dir.path()).unwrap();
                }
                ctrl.del().unwrap();
            },
        )
        .unwrap()
        .join()
        .unwrap();
        ublk_dealloc_buf(buf, size as usize, 4096);
    }
}
