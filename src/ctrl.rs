use super::io::{UblkDev, UblkTgt};
use super::{sys, UblkError};
use bitmaps::Bitmap;
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use log::{error, trace};
use serde::Deserialize;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

const CTRL_PATH: &str = "/dev/ublk-control";

const MAX_BUF_SZ: u32 = 32_u32 << 20;

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
    pub fn to_bits_vec(&self) -> Vec<usize> {
        self.affinity.into_iter().collect()
    }
}

#[repr(C)]
union CtrlCmd {
    ctrl_cmd: sys::ublksrv_ctrl_cmd,
    buf: [u8; 80],
}

const CTRL_CMD_HAS_DATA: u32 = 1;
const CTRL_CMD_HAS_BUF: u32 = 2;
const CTRL_CMD_ASYNC: u32 = 4;

#[derive(Debug, Default, Copy, Clone)]
struct UblkCtrlCmdData {
    cmd_op: u32,
    flags: u32,
    data: [u64; 2],
    addr: u64,
    len: u32,
}

fn ublk_ctrl_prep_cmd(
    ctrl: &mut UblkCtrl,
    fd: i32,
    dev_id: u32,
    data: &UblkCtrlCmdData,
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
        .user_data({
            ctrl.cmd_token += 1;
            ctrl.cmd_token as u64
        })
}

fn ublk_ctrl_cmd(ctrl: &mut UblkCtrl, data: &UblkCtrlCmdData) -> Result<i32, UblkError> {
    let sqe = ublk_ctrl_prep_cmd(ctrl, ctrl.file.as_raw_fd(), ctrl.dev_info.dev_id, data);
    let to_wait = if data.flags & CTRL_CMD_ASYNC != 0 {
        0
    } else {
        1
    };

    unsafe {
        ctrl.ring
            .submission()
            .push(&sqe)
            .map_err(UblkError::UringPushError)?;
    }
    ctrl.ring
        .submit_and_wait(to_wait)
        .map_err(UblkError::UringSubmissionError)?;

    if to_wait == 0 {
        return Ok(ctrl.cmd_token);
    }

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
    file: fs::File,
    pub dev_info: sys::ublksrv_ctrl_dev_info,
    pub json: serde_json::Value,
    for_add: bool,
    cmd_token: i32,
    queue_tids: Vec<i32>,
    nr_queues_configured: u16,
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
    #[allow(clippy::uninit_vec)]
    pub fn new(
        id: i32,
        nr_queues: u32,
        depth: u32,
        io_buf_bytes: u32,
        flags: u64,
        for_add: bool,
    ) -> Result<UblkCtrl, UblkError> {
        if id < 0 && id != -1 {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

        if nr_queues > sys::UBLK_MAX_NR_QUEUES {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

        if depth > sys::UBLK_MAX_QUEUE_DEPTH {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

        if io_buf_bytes > MAX_BUF_SZ {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

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
            cmd_token: 0,
            queue_tids: {
                let mut tids = Vec::<i32>::with_capacity(nr_queues as usize);
                unsafe {
                    tids.set_len(nr_queues as usize);
                }
                tids
            },
            nr_queues_configured: 0,
        };

        //add cdev if the device is for adding device
        if dev.for_add {
            dev.add()?;
        } else {
            let res = dev.reload_json();
            if res.is_err() {
                eprintln!("device reload json failed");
            }
            dev.get_info()?;
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

    /// Get queue's pthread id from exported json file for this device
    ///
    /// # Arguments:
    ///
    /// * `qid`: queue id
    ///
    pub fn get_queue_tid(&self, qid: u32) -> Result<i32, UblkError> {
        let queues = &self.json["queues"];
        let queue = &queues[qid.to_string()];
        let this_queue: Result<QueueAffinityJson, _> = serde_json::from_value(queue.clone());

        if let Ok(p) = this_queue {
            Ok(p.tid as i32)
        } else {
            Err(UblkError::OtherError(-libc::EEXIST))
        }
    }

    /// Get target flags from exported json file for this device
    ///
    pub fn get_target_flags_from_json(&self) -> Result<u32, UblkError> {
        let __tgt_flags = &self.json["target_flags"];
        let tgt_flags: Result<u32, _> = serde_json::from_value(__tgt_flags.clone());

        if let Ok(flags) = tgt_flags {
            Ok(flags)
        } else {
            Err(UblkError::OtherError(-libc::EINVAL))
        }
    }

    /// Get target from exported json file for this device
    ///
    pub fn get_target_from_json(&self) -> Result<super::io::UblkTgt, UblkError> {
        let tgt_val = &self.json["target"];
        let tgt: Result<super::io::UblkTgt, _> = serde_json::from_value(tgt_val.clone());
        if let Ok(p) = tgt {
            Ok(p)
        } else {
            Err(UblkError::OtherError(-libc::EINVAL))
        }
    }

    /// Get target type from exported json file for this device
    ///
    pub fn get_target_type_from_json(&self) -> Result<String, UblkError> {
        if let Ok(tgt) = self.get_target_from_json() {
            Ok(tgt.tgt_type)
        } else {
            Err(UblkError::OtherError(-libc::EINVAL))
        }
    }

    fn store_queue_tid(&mut self, qid: u16, tid: i32) {
        self.queue_tids[qid as usize] = tid;
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
    pub fn configure_queue(&mut self, dev: &UblkDev, qid: u16, tid: i32) -> Result<i32, UblkError> {
        self.store_queue_tid(qid, tid);

        self.nr_queues_configured += 1;

        if self.nr_queues_configured == self.dev_info.nr_hw_queues {
            self.build_json(dev)?;
        }

        Ok(0)
    }

    pub fn queues_configured(&self) -> bool {
        self.nr_queues_configured == self.dev_info.nr_hw_queues
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

    /// Dump this device info
    ///
    /// The 1st part is from UblkCtrl.dev_info, and the 2nd part is
    /// retrieved from device's exported json file
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

    /// Returned path of this device's exported json file
    ///
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

    /// Poll one control command until it is completed
    ///
    /// Note: so far, we only support to poll at most one-inflight
    /// command, and the use case is for supporting to run start_dev
    /// in queue io handling context
    pub fn poll_cmd(&mut self, token: i32) -> Result<i32, UblkError> {
        if self.ring.completion().is_empty() {
            return Err(UblkError::UringIOError(-libc::EAGAIN));
        }

        let cqe = self.ring.completion().next().expect("cqueue is empty");
        let res: i32 = cqe.result();
        if res == 0 && cqe.user_data() == token as u64 {
            Ok(res)
        } else {
            Err(UblkError::UringIOError(res))
        }
    }

    /// Remove this device
    ///
    pub fn del(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_DEL_DEV,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    /// Remove this device and its exported json file
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

    /// Retrieving device info from ublk driver
    ///
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

    /// Start this device by sending command to ublk driver
    ///
    pub fn start(&mut self, pid: i32, async_cmd: bool) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_START_DEV,
            flags: CTRL_CMD_HAS_DATA | if async_cmd { CTRL_CMD_ASYNC } else { 0 },
            data: [pid as u64, 0],
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    /// Stop this device by sending command to ublk driver
    ///
    pub fn stop(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_STOP_DEV,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    /// Retrieve this device's parameter from ublk driver by
    /// sending command
    ///
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

    /// Send this device's parameter to ublk driver
    ///
    /// Note: device parameter has to send to driver before starting
    /// this device
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

    /// Retrieving the specified queue's affinity from ublk driver
    ///
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

    fn __start_user_recover(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_START_USER_RECOVERY,
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    /// Start user recover for this device
    ///
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

    /// End user recover for this device
    ///
    pub fn end_user_recover(&mut self, pid: i32, async_cmd: bool) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_CMD_END_USER_RECOVERY,
            flags: CTRL_CMD_HAS_DATA | if async_cmd { CTRL_CMD_ASYNC } else { 0 },
            data: [pid as u64, 0],
            ..Default::default()
        };

        ublk_ctrl_cmd(self, &data)
    }

    fn __start_dev(&mut self, dev: &UblkDev, async_cmd: bool) -> Result<i32, UblkError> {
        self.get_info()?;
        if self.dev_info.state == sys::UBLK_S_DEV_LIVE as u16 {
            return Ok(0);
        }

        let token = if self.dev_info.state != sys::UBLK_S_DEV_QUIESCED as u16 {
            self.set_params(&dev.tgt.params)?;
            self.flush_json()?;
            self.start(unsafe { libc::getpid() as i32 }, async_cmd)?
        } else {
            self.end_user_recover(unsafe { libc::getpid() as i32 }, async_cmd)?
        };

        Ok(token)
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
    pub fn start_dev(&mut self, dev: &UblkDev) -> Result<i32, UblkError> {
        self.__start_dev(dev, false)
    }

    /// Start ublk device from queue daemon context
    ///
    /// # Arguments:
    ///
    /// * `dev`: ublk device
    /// * `queue`: ublk queue, if both `queue` and `ops`  isn't none, we
    ///     start device in queue daemon context
    /// * `ops`: ublk queue trait
    ///
    /// Send parameter to driver, and flush json to storage, finally
    /// send START command
    ///
    /// When ublk driver handles START_DEV, ublk IO starts to come from
    /// this kernel code path, such as, reading partition table, so we
    /// have make io handler working before sending START_DEV to kernel
    ///
    pub fn start_dev_in_queue<F>(
        &mut self,
        dev: &UblkDev,
        q: &mut super::io::UblkQueue,
        mut ops: F,
    ) -> Result<i32, UblkError>
    where
        F: FnMut(&mut super::io::UblkIOCtx) -> Result<i32, UblkError>,
    {
        let mut started = false;
        let token = self.__start_dev(dev, true)?;

        q.set_poll(true);
        while !started {
            std::thread::sleep(std::time::Duration::from_millis(10));
            if let Ok(res) = self.poll_cmd(token) {
                started = true;
                if res == 0 {
                    continue;
                } else {
                    return Err(UblkError::UringIOError(res));
                }
            }
            match q.process_io(&mut ops) {
                Err(r) => return Err(r),
                _ => continue,
            }
        }
        q.set_poll(false);

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

    /// Flush this device's json info as file
    pub fn flush_json(&mut self) -> Result<i32, UblkError> {
        if self.json == serde_json::json!({}) {
            return Ok(0);
        }

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

    /// Build json info for this device
    ///
    /// # Arguments:
    ///
    /// * `dev`: this device's UblkDev instance
    /// * `affi`: queue affinity vector, in which each item stores the queue's affinity
    /// * `tids`: queue pthread tid vector, in which each item stores the queue's
    /// pthread tid
    ///
    fn build_json(&mut self, dev: &UblkDev) -> Result<i32, UblkError> {
        let tgt_data = self.json.clone();
        let mut map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

        for qid in 0..dev.dev_info.nr_hw_queues {
            let mut affinity = self::UblkQueueAffinity::new();
            self.get_queue_affinity(qid as u32, &mut affinity)?;

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
                    "target_flags": dev.flags,
        });

        json["target_data"] = tgt_data;
        json["queues"] = serde_json::Value::Object(map);

        self.json = json;
        Ok(0)
    }

    /// Reload json info for this device
    ///
    pub fn reload_json(&mut self) -> Result<i32, UblkError> {
        let mut file = fs::File::open(self.run_path()).map_err(UblkError::OtherIOError)?;
        let mut json_str = String::new();

        file.read_to_string(&mut json_str)
            .map_err(UblkError::OtherIOError)?;
        self.json = serde_json::from_str(&json_str).map_err(UblkError::JsonError)?;

        Ok(0)
    }
}
