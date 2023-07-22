use super::io::{UblkDev, UblkQueue, UblkQueueImpl, UblkTgt};
use super::{sys, UblkError};
use bitmaps::Bitmap;
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use log::{error, trace};
use serde::Deserialize;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Condvar, Mutex};

const CTRL_PATH: &str = "/dev/ublk-control";

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
    ctrl_cmd: sys::ublksrv_ctrl_cmd,
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
            [data.data[0] as u64]
        } else {
            [0]
        },
        dev_id,
        queue_id: u16::MAX,
        ..Default::default()
    };
    let c_cmd = CtrlCmd { ctrl_cmd: cmd };

    opcode::UringCmd80::new(types::Fd(fd), data.cmd_op)
        .cmd(unsafe { c_cmd.buf })
        .build()
}

fn ublk_ctrl_cmd(ctrl: &mut UblkCtrl, data: &UblkCtrlCmdData) -> Result<i32, UblkError> {
    let sqe = ublk_ctrl_prep_cmd(ctrl.file.as_raw_fd(), ctrl.dev_info.dev_id, data);

    unsafe {
        ctrl.ring
            .submission()
            .push(&sqe)
            .map_err(UblkError::UringPushError)?;
    }
    ctrl.ring
        .submit_and_wait(1)
        .map_err(UblkError::UringSubmissionError)?;

    let cqe = ctrl.ring.completion().next().expect("cqueue is empty");
    let res: i32 = cqe.result();
    if res == 0 || res == -libc::EBUSY {
        Ok(res)
    } else {
        Err(UblkError::UringIOError(res))
    }
}

#[derive(Debug, Deserialize)]
struct QueueAffinityJson {
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
    pub dev_info: sys::ublksrv_ctrl_dev_info,
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
    ) -> Result<UblkCtrl, UblkError> {
        let ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(16)
            .map_err(UblkError::OtherIOError)?;
        let info = sys::ublksrv_ctrl_dev_info {
            nr_hw_queues: nr_queues as u16,
            queue_depth: depth as u16,
            max_io_buf_bytes: io_buf_bytes,
            dev_id: id as u32,
            ublksrv_pid: unsafe { libc::getpid() } as i32,
            flags,
            ..Default::default()
        };
        let fd = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(CTRL_PATH)
            .map_err(UblkError::OtherIOError)?;

        let mut dev = UblkCtrl {
            file: fd,
            dev_info: info,
            json: serde_json::json!({}),
            ring,
            for_add,
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
            sys::UBLK_S_DEV_DEAD => "DEAD".to_string(),
            sys::UBLK_S_DEV_LIVE => "LIVE".to_string(),
            sys::UBLK_S_DEV_QUIESCED => "QUIESCED".to_string(),
            _ => "UNKNOWN".to_string(),
        }
    }

    pub fn get_queue_tid(&self, qid: u32) -> Result<i32, UblkError> {
        let queues = &self.json["queues"];
        let queue = &queues[qid.to_string()];
        let this_queue: Result<QueueAffinityJson, _> = serde_json::from_value(queue.clone());

        if let Ok(p) = this_queue {
            Ok(p.tid.try_into().unwrap())
        } else {
            Err(UblkError::OtherError(-libc::EEXIST))
        }
    }

    pub fn dump_from_json(&self) {
        if !std::path::Path::new(&self.run_path()).exists() {
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
            let this_queue: Result<QueueAffinityJson, _> = serde_json::from_value(queue.clone());

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
    pub fn dump(&mut self) {
        let mut p = sys::ublk_params {
            ..Default::default()
        };

        if self.get_info().is_err() {
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

    pub fn run_path(&self) -> String {
        format!("{}/{:04}.json", UblkCtrl::run_dir(), self.dev_info.dev_id)
    }

    fn add(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_ADD_DEV,
            flags: CTRL_CMD_HAS_BUF,
            addr: std::ptr::addr_of!(self.dev_info) as u64,
            len: core::mem::size_of::<sys::ublksrv_ctrl_dev_info>() as u32,
            data: [0, 0],
        };

        ublk_ctrl_cmd(self, &data)
    }

    pub fn del(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_DEL_DEV,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    /// Remove one device
    ///
    ///
    /// Called when the user wants to remove one device really
    ///
    pub fn del_dev(&mut self) -> Result<i32, UblkError> {
        self.del()?;
        if std::path::Path::new(&self.run_path()).exists() {
            fs::remove_file(self.run_path()).map_err(UblkError::OtherIOError)?;
        }
        Ok(0)
    }

    pub fn get_info(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_GET_DEV_INFO,
            flags: CTRL_CMD_HAS_BUF,
            addr: std::ptr::addr_of!(self.dev_info) as u64,
            len: core::mem::size_of::<sys::ublksrv_ctrl_dev_info>() as u32,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    pub fn start(&mut self, pid: i32) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_START_DEV,
            flags: CTRL_CMD_HAS_DATA,
            data: [pid as u64, 0],
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    pub fn stop(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_STOP_DEV,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    /// Can't pass params by reference(&mut), why?
    pub fn get_params(
        &mut self,
        mut params: sys::ublk_params,
    ) -> Result<sys::ublk_params, UblkError> {
        params.len = core::mem::size_of::<sys::ublk_params>() as u32;
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_GET_PARAMS,
            flags: CTRL_CMD_HAS_BUF,
            addr: std::ptr::addr_of!(params) as u64,
            len: params.len,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)?;
        Ok(params)
    }

    pub fn set_params(&mut self, params: &sys::ublk_params) -> Result<i32, UblkError> {
        let mut p = *params;

        p.len = core::mem::size_of::<sys::ublk_params>() as u32;
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_SET_PARAMS,
            flags: CTRL_CMD_HAS_BUF,
            addr: std::ptr::addr_of!(p) as u64,
            len: p.len,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    pub fn get_queue_affinity(
        &mut self,
        q: u32,
        bm: &mut UblkQueueAffinity,
    ) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_GET_QUEUE_AFFINITY,
            flags: CTRL_CMD_HAS_BUF | CTRL_CMD_HAS_DATA,
            addr: bm.addr() as u64,
            data: [q as u64, 0],
            len: bm.buf_len() as u32,
        };
        ublk_ctrl_cmd(self, &data)
    }

    pub fn __start_user_recover(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_START_USER_RECOVERY,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    pub fn start_user_recover(&mut self) -> Result<i32, UblkError> {
        let mut count = 0u32;
        let unit = 100_u32;

        loop {
            let res = self.__start_user_recover();
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

    pub fn end_user_recover(&mut self, pid: i32) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_END_USER_RECOVERY,
            flags: CTRL_CMD_HAS_DATA,
            data: [pid as u64, 0],
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
    pub fn start_dev(&mut self, dev: &UblkDev) -> Result<i32, UblkError> {
        let params = dev.tgt.borrow();

        self.get_info()?;
        if self.dev_info.state != sys::UBLK_S_DEV_QUIESCED as u16 {
            self.set_params(&params.params)?;
            self.flush_json()?;
            self.start(unsafe { libc::getpid() as i32 })?;
        } else {
            self.end_user_recover(unsafe { libc::getpid() as i32 })?;
        }

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
    pub fn stop_dev(&mut self, _dev: &UblkDev) -> Result<i32, UblkError> {
        if self.for_add && std::path::Path::new(&self.run_path()).exists() {
            fs::remove_file(self.run_path()).map_err(UblkError::OtherIOError)?;
        }
        self.stop()
    }

    pub fn flush_json(&mut self) -> Result<i32, UblkError> {
        let run_path = self.run_path();

        if let Some(parent_dir) = std::path::Path::new(&run_path).parent() {
            fs::create_dir_all(parent_dir).map_err(UblkError::OtherIOError)?;
        }
        let mut run_file = fs::File::create(&run_path).map_err(UblkError::OtherIOError)?;

        run_file
            .write_all(self.json.to_string().as_bytes())
            .map_err(UblkError::OtherIOError)?;
        Ok(0)
    }

    pub fn build_json(&mut self, dev: &UblkDev, affi: Vec<UblkQueueAffinity>, tids: Vec<i32>) {
        let tgt_data = self.json.clone();
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

    pub fn reload_json(&mut self) -> Result<i32, UblkError> {
        let mut file = fs::File::open(self.run_path()).map_err(UblkError::OtherIOError)?;
        let mut json_str = String::new();

        file.read_to_string(&mut json_str)
            .map_err(UblkError::OtherIOError)?;
        self.json = serde_json::from_str(&json_str).map_err(UblkError::JsonError)?;

        Ok(0)
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
            let _q_id = q;
            let tid = Arc::new((Mutex::new(0_i32), Condvar::new()));
            let _tid = Arc::clone(&tid);
            let _fn = f.clone();
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
        self.build_json(dev, q_affi, q_tids);

        q_threads
    }
}
