use super::io::{UblkDev, UblkTgt};
use super::uring_async::UblkUringOpFuture;
use super::{dev_flags, sys, UblkError};
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

std::thread_local! {
    pub(crate) static CTRL_URING: RefCell<IoUring::<squeue::Entry128>> =
        RefCell::new(IoUring::<squeue::Entry128>::builder()
            .build(16).unwrap());
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
    pub fn to_bits_vec(&self) -> Vec<usize> {
        self.affinity.into_iter().collect()
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

#[allow(dead_code)]
#[derive(Debug, Default, Copy, Clone)]
struct UblkCtrlCmdData {
    cmd_op: u32,
    flags: u32,
    data: u64,
    dev_path_len: u16,
    pad: u16,
    reserved: u32,

    addr: u64,
    len: u32,
}

impl UblkCtrlCmdData {
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
    dev_flags: u32,
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
            dev_flags: 0,
        }
    }
}

impl UblkCtrlBuilder<'_> {
    /// create one pair of ublk devices, the 1st one is control device(`UblkCtrl`),
    /// and the 2nd one is data device(`UblkDev`)
    pub fn build(self) -> Result<UblkCtrl, UblkError> {
        Ok(UblkCtrl::new(
            Some(self.name.to_string()),
            self.id,
            self.nr_queues.into(),
            self.depth.into(),
            self.io_buf_bytes,
            self.ctrl_flags,
            self.ctrl_target_flags,
            self.dev_flags,
        )?)
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

struct UblkCtrlInner {
    name: Option<String>,
    file: fs::File,
    dev_info: sys::ublksrv_ctrl_dev_info,
    json: serde_json::Value,
    features: Option<u64>,

    /// global flags, shared with UblkDev and UblkQueue
    dev_flags: u32,
    cmd_token: i32,
    queue_tids: Vec<i32>,
    nr_queues_configured: u16,
}

impl Drop for UblkCtrlInner {
    fn drop(&mut self) {
        let id = self.dev_info.dev_id;
        trace!("ctrl: device {} dropped", id);
        if self.for_add_dev() {
            if let Err(r) = self.del() {
                //Maybe deleted from other utilities, so no warn or error:w
                trace!("Delete char device {} failed {}", self.dev_info.dev_id, r);
            }
        }
    }
}

impl UblkCtrlInner {
    #[allow(clippy::uninit_vec)]
    fn new(
        name: Option<String>,
        id: i32,
        nr_queues: u32,
        depth: u32,
        io_buf_bytes: u32,
        flags: u64,
        tgt_flags: u64,
        dev_flags: u32,
    ) -> Result<UblkCtrlInner, UblkError> {
        if !Path::new(CTRL_PATH).exists() {
            eprintln!("Please run `modprobe ublk_drv` first");
            return Err(UblkError::OtherError(-libc::ENOENT));
        }

        if (dev_flags & !dev_flags::UBLK_DEV_F_ALL) != 0 {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

        if id < 0 && id != -1 {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

        if nr_queues > sys::UBLK_MAX_NR_QUEUES {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

        if depth > sys::UBLK_MAX_QUEUE_DEPTH {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

        let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;
        if io_buf_bytes > MAX_BUF_SZ || io_buf_bytes & (page_sz - 1) != 0 {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

        let info = sys::ublksrv_ctrl_dev_info {
            nr_hw_queues: nr_queues as u16,
            queue_depth: depth as u16,
            max_io_buf_bytes: io_buf_bytes,
            dev_id: id as u32,
            ublksrv_pid: unsafe { libc::getpid() } as i32,
            flags,
            ublksrv_flags: tgt_flags,
            ..Default::default()
        };
        let fd = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(CTRL_PATH)
            .map_err(UblkError::OtherIOError)?;

        let mut dev = UblkCtrlInner {
            name,
            file: fd,
            dev_info: info,
            json: serde_json::json!({}),
            cmd_token: 0,
            queue_tids: {
                let mut tids = Vec::<i32>::with_capacity(nr_queues as usize);
                unsafe {
                    tids.set_len(nr_queues as usize);
                }
                tids
            },
            nr_queues_configured: 0,
            dev_flags,
            features: None,
        };

        let features = match dev.__get_features() {
            Ok(f) => Some(f),
            _ => None,
        };
        dev.features = features;

        //add cdev if the device is for adding device
        if dev.for_add_dev() {
            dev.add()?;
        } else if id >= 0 {
            let res = dev.reload_json();
            if res.is_err() {
                eprintln!("device reload json failed");
            }
            dev.read_dev_info()?;
        }

        trace!(
            "ctrl: device {} flags {:x} created",
            dev.dev_info.dev_id,
            dev.dev_flags
        );

        Ok(dev)
    }

    fn is_unprivileged(&self) -> bool {
        (self.dev_info.flags & (super::sys::UBLK_F_UNPRIVILEGED_DEV as u64)) != 0
    }

    fn get_cdev_path(&self) -> String {
        format!("{}{}", UblkCtrl::CDEV_PATH, self.dev_info.dev_id)
    }

    fn for_add_dev(&self) -> bool {
        (self.dev_flags & dev_flags::UBLK_DEV_F_ADD_DEV) != 0
    }

    fn for_recover_dev(&self) -> bool {
        (self.dev_flags & dev_flags::UBLK_DEV_F_RECOVER_DEV) != 0
    }

    fn dev_state_desc(&self) -> String {
        match self.dev_info.state as u32 {
            sys::UBLK_S_DEV_DEAD => "DEAD".to_string(),
            sys::UBLK_S_DEV_LIVE => "LIVE".to_string(),
            sys::UBLK_S_DEV_QUIESCED => "QUIESCED".to_string(),
            _ => "UNKNOWN".to_string(),
        }
    }

    fn store_queue_tid(&mut self, qid: u16, tid: i32) {
        self.queue_tids[qid as usize] = tid;
    }

    fn dump_from_json(&self) {
        if !Path::new(&self.run_path()).exists() {
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

    /// Returned path of this device's exported json file
    ///
    fn run_path(&self) -> String {
        format!("{}/{:04}.json", UblkCtrl::run_dir(), self.dev_info.dev_id)
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
            CTRL_URING.with(|refcell| {
                refcell.borrow_mut().submission().push(&sqe).unwrap();
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

        CTRL_URING.with(|refcell| {
            let mut r = refcell.borrow_mut();

            loop {
                let res = unsafe { r.submission().push(&sqe) };
                match res {
                    Ok(_) => break,
                    Err(_) => {
                        log::debug!("ublk_submit_cmd: flush and retry");
                        r.submit_and_wait(0).unwrap();
                    }
                }
            }
            r.submit_and_wait(to_wait).unwrap();
        });
        Ok(token)
    }

    /// check one control command and see if it is completed
    ///
    fn poll_cmd(&mut self, token: u64) -> i32 {
        CTRL_URING.with(|refcell| {
            let mut r = refcell.borrow_mut();

            if r.completion().is_empty() {
                //Err(UblkError::UringIOError(-libc::EAGAIN))
                -libc::EAGAIN
            } else {
                let cqe = r.completion().next().expect("cqueue is empty");
                if cqe.user_data() != token {
                    //Err(UblkError::UringIOError(-libc::EAGAIN))
                    -libc::EAGAIN
                } else {
                    let res: i32 = cqe.result();
                    if res == 0 || res == -libc::EBUSY {
                        res
                    } else {
                        //Err(UblkError::UringIOError(res))
                        res
                    }
                }
            }
        })
    }

    async fn __ublk_ctrl_cmd_async(&mut self, data: &UblkCtrlCmdData) -> i32 {
        let mut data = *data;

        let (old_buf, _new) = data.prep_un_privileged_dev_path(self);
        let res = self.ublk_submit_cmd_async(&mut data).await;

        data.unprep_un_privileged_dev_path(self, old_buf);

        res
    }

    async fn ublk_ctrl_cmd_async(&mut self, data: &UblkCtrlCmdData) -> Result<i32, UblkError> {
        let res = self.__ublk_ctrl_cmd_async(data).await;

        if res >= 0 || res == -libc::EBUSY {
            Ok(res)
        } else {
            let legacy_op = data.cmd_op & 0xff;

            // new commands have to be issued via ioctl encoding
            if legacy_op > sys::UBLK_CMD_GET_DEV_INFO2 {
                Err(UblkError::UringIOError(res))
            } else {
                let mut new_data = *data;

                // retry one more time with legacy encoding
                new_data.cmd_op = legacy_op;
                let res = self.__ublk_ctrl_cmd_async(&new_data).await;
                if res >= 0 || res == -libc::EBUSY {
                    Ok(res)
                } else {
                    Err(UblkError::UringIOError(res))
                }
            }
        }
    }

    fn __ublk_ctrl_cmd(&mut self, data: &UblkCtrlCmdData) -> i32 {
        let mut data = *data;
        let to_wait = 1;

        let (old_buf, _new) = data.prep_un_privileged_dev_path(self);
        let token = self.ublk_submit_cmd(&data, to_wait).unwrap();
        let res = self.poll_cmd(token);

        data.unprep_un_privileged_dev_path(self, old_buf);

        res
    }

    fn ublk_ctrl_cmd(&mut self, data: &UblkCtrlCmdData) -> Result<i32, UblkError> {
        let res = self.__ublk_ctrl_cmd(data);

        if res >= 0 || res == -libc::EBUSY {
            Ok(res)
        } else {
            let legacy_op = data.cmd_op & 0xff;

            // new commands have to be issued via ioctl encoding
            if legacy_op > sys::UBLK_CMD_GET_DEV_INFO2 {
                Err(UblkError::UringIOError(res))
            } else {
                let mut new_data = *data;

                // retry one more time with legacy encoding for
                // old kernel without ioctl encoding support
                new_data.cmd_op = legacy_op;
                let res = self.__ublk_ctrl_cmd(&new_data);
                if res >= 0 || res == -libc::EBUSY {
                    Ok(res)
                } else {
                    Err(UblkError::UringIOError(res))
                }
            }
        }
    }

    fn add(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_ADD_DEV,
            flags: CTRL_CMD_HAS_BUF | CTRL_CMD_NO_NEED_DEV_PATH,
            addr: std::ptr::addr_of!(self.dev_info) as u64,
            len: core::mem::size_of::<sys::ublksrv_ctrl_dev_info>() as u32,
            ..Default::default()
        };

        self.ublk_ctrl_cmd(&data)
    }

    /// Remove this device
    ///
    fn del(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_DEL_DEV,
            ..Default::default()
        };

        self.ublk_ctrl_cmd(&data)
    }

    fn __get_features(&mut self) -> Result<u64, UblkError> {
        let features = 0_u64;
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_GET_FEATURES,
            flags: CTRL_CMD_HAS_BUF | CTRL_CMD_BUF_READ | CTRL_CMD_NO_NEED_DEV_PATH,
            addr: std::ptr::addr_of!(features) as u64,
            len: core::mem::size_of::<u64>() as u32,
            ..Default::default()
        };

        self.ublk_ctrl_cmd(&data)?;

        Ok(features)
    }

    fn __read_dev_info(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_GET_DEV_INFO,
            flags: CTRL_CMD_HAS_BUF | CTRL_CMD_BUF_READ,
            addr: std::ptr::addr_of!(self.dev_info) as u64,
            len: core::mem::size_of::<sys::ublksrv_ctrl_dev_info>() as u32,
            ..Default::default()
        };

        self.ublk_ctrl_cmd(&data)
    }

    fn __read_dev_info2(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_GET_DEV_INFO2,
            flags: CTRL_CMD_HAS_BUF | CTRL_CMD_BUF_READ,
            addr: std::ptr::addr_of!(self.dev_info) as u64,
            len: core::mem::size_of::<sys::ublksrv_ctrl_dev_info>() as u32,
            ..Default::default()
        };

        self.ublk_ctrl_cmd(&data)
    }

    fn read_dev_info(&mut self) -> Result<i32, UblkError> {
        let res = self.__read_dev_info2();

        if res.is_err() {
            self.__read_dev_info()
        } else {
            res
        }
    }

    /// Start this device by sending command to ublk driver
    ///
    fn start(&mut self, pid: i32) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_START_DEV,
            flags: CTRL_CMD_HAS_DATA,
            data: pid as u64,
            ..Default::default()
        };

        self.ublk_ctrl_cmd(&data)
    }

    /// Start this device by sending command to ublk driver
    ///
    async fn start_async(&mut self, pid: i32) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_START_DEV,
            flags: CTRL_CMD_HAS_DATA,
            data: pid as u64,
            ..Default::default()
        };

        self.ublk_ctrl_cmd_async(&data).await
    }

    /// Stop this device by sending command to ublk driver
    ///
    fn stop(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_STOP_DEV,
            ..Default::default()
        };

        self.ublk_ctrl_cmd(&data)
    }

    /// Retrieve this device's parameter from ublk driver by
    /// sending command
    ///
    /// Can't pass params by reference(&mut), why?
    fn get_params(&mut self, params: &mut sys::ublk_params) -> Result<i32, UblkError> {
        params.len = core::mem::size_of::<sys::ublk_params>() as u32;
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_GET_PARAMS,
            flags: CTRL_CMD_HAS_BUF | CTRL_CMD_BUF_READ,
            addr: params as *const sys::ublk_params as u64,
            len: params.len,
            ..Default::default()
        };

        self.ublk_ctrl_cmd(&data)
    }

    /// Send this device's parameter to ublk driver
    ///
    /// Note: device parameter has to send to driver before starting
    /// this device
    fn set_params(&mut self, params: &sys::ublk_params) -> Result<i32, UblkError> {
        let mut p = *params;

        p.len = core::mem::size_of::<sys::ublk_params>() as u32;
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_SET_PARAMS,
            flags: CTRL_CMD_HAS_BUF,
            addr: std::ptr::addr_of!(p) as u64,
            len: p.len,
            ..Default::default()
        };

        self.ublk_ctrl_cmd(&data)
    }

    fn get_queue_affinity(&mut self, q: u32, bm: &mut UblkQueueAffinity) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_GET_QUEUE_AFFINITY,
            flags: CTRL_CMD_HAS_BUF | CTRL_CMD_HAS_DATA | CTRL_CMD_BUF_READ,
            addr: bm.addr() as u64,
            data: q as u64,
            len: bm.buf_len() as u32,
            ..Default::default()
        };
        self.ublk_ctrl_cmd(&data)
    }

    fn __start_user_recover(&mut self) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_START_USER_RECOVERY,
            ..Default::default()
        };

        self.ublk_ctrl_cmd(&data)
    }

    /// End user recover for this device, do similar thing done in start_dev()
    ///
    fn end_user_recover(&mut self, pid: i32) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_END_USER_RECOVERY,
            flags: CTRL_CMD_HAS_DATA,
            data: pid as u64,
            ..Default::default()
        };

        self.ublk_ctrl_cmd(&data)
    }

    /// End user recover for this device, do similar thing done in start_dev()
    ///
    async fn end_user_recover_async(&mut self, pid: i32) -> Result<i32, UblkError> {
        let data: UblkCtrlCmdData = UblkCtrlCmdData {
            cmd_op: sys::UBLK_U_CMD_END_USER_RECOVERY,
            flags: CTRL_CMD_HAS_DATA,
            data: pid as u64,
            ..Default::default()
        };

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
            return Err(crate::UblkError::OtherError(-libc::EINVAL));
        };

        Ok(0)
    }

    fn set_path_permission(path: &Path, mode: u32) -> Result<i32, UblkError> {
        use std::os::unix::fs::PermissionsExt;

        let metadata = fs::metadata(path).map_err(UblkError::OtherIOError)?;
        let mut permissions = metadata.permissions();

        permissions.set_mode(mode);
        fs::set_permissions(path, permissions).map_err(UblkError::OtherIOError)?;

        Ok(0)
    }

    /// Flush this device's json info as file
    fn flush_json(&mut self) -> Result<i32, UblkError> {
        if self.json == serde_json::json!({}) {
            return Ok(0);
        }

        // flushing json should only be done in case of adding new device
        // or recovering old device
        if !self.for_add_dev() && !self.for_recover_dev() {
            return Ok(0);
        }

        let run_path = self.run_path();
        let json_path = Path::new(&run_path);

        if let Some(parent_dir) = json_path.parent() {
            if !Path::new(&parent_dir).exists() {
                fs::create_dir_all(parent_dir).map_err(UblkError::OtherIOError)?;

                // It is just fine to expose the running parent directory as
                // 777, and we will make sure every exported running json
                // file as 700.
                Self::set_path_permission(parent_dir, 0o777)?;
            }
        }
        let mut run_file = fs::File::create(json_path).map_err(UblkError::OtherIOError)?;

        // Each exported json file is only visible for the device owner.
        // In future, it can be relaxed, such as allowing group to access,
        // according to ublk use policy
        Self::set_path_permission(json_path, 0o700)?;

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
        // keep everything not changed except for queue tid
        if dev.dev_info.state == sys::UBLK_S_DEV_QUIESCED as u16 {
            if let Some(queues) = self.json.get_mut("queues") {
                for qid in 0..dev.dev_info.nr_hw_queues {
                    let t = format!("{}", qid);
                    if let Some(q) = queues.get_mut(t) {
                        if let Some(tid) = q.get_mut("tid") {
                            *tid = serde_json::json!(self.queue_tids[qid as usize]);
                        }
                    }
                }
            }
            return Ok(0);
        }

        let tgt_data = dev.get_target_json();
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

        if let Some(val) = tgt_data {
            json["target_data"] = val.clone()
        }

        json["queues"] = serde_json::Value::Object(map);

        self.json = json;
        Ok(0)
    }

    /// Reload json info for this device
    ///
    fn reload_json(&mut self) -> Result<i32, UblkError> {
        let mut file = fs::File::open(self.run_path()).map_err(UblkError::OtherIOError)?;
        let mut json_str = String::new();

        file.read_to_string(&mut json_str)
            .map_err(UblkError::OtherIOError)?;
        self.json = serde_json::from_str(&json_str).map_err(UblkError::JsonError)?;

        Ok(0)
    }
}

impl UblkCtrl {
    /// char device and block device name may change according to system policy,
    /// such udev may rename it in its own namespaces.
    const CDEV_PATH: &'static str = "/dev/ublkc";
    const BDEV_PATH: &'static str = "/dev/ublkb";

    fn get_inner(&self) -> std::sync::RwLockReadGuard<UblkCtrlInner> {
        self.inner.read().unwrap()
    }

    fn get_inner_mut(&self) -> std::sync::RwLockWriteGuard<UblkCtrlInner> {
        self.inner.write().unwrap()
    }

    pub fn get_name(&self) -> String {
        let inner = self.get_inner();

        match &inner.name {
            Some(name) => name.clone(),
            None => "none".to_string(),
        }
    }

    pub(crate) fn get_dev_flags(&self) -> u32 {
        self.get_inner().dev_flags
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
    pub fn new(
        name: Option<String>,
        id: i32,
        nr_queues: u32,
        depth: u32,
        io_buf_bytes: u32,
        flags: u64,
        tgt_flags: u64,
        dev_flags: u32,
    ) -> Result<UblkCtrl, UblkError> {
        let inner = RwLock::new(UblkCtrlInner::new(
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
    pub fn new_simple(id: i32, dev_flags: u32) -> Result<UblkCtrl, UblkError> {
        assert!((dev_flags & dev_flags::UBLK_DEV_F_ADD_DEV) == 0);
        assert!(id >= 0);
        Self::new(None, id, 0, 0, 0, 0, 0, dev_flags)
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
        format!("{}{}", Self::BDEV_PATH, self.get_inner().dev_info.dev_id)
    }

    /// Get queue's pthread id from exported json file for this device
    ///
    /// # Arguments:
    ///
    /// * `qid`: queue id
    ///
    pub fn get_queue_tid(&self, qid: u32) -> Result<i32, UblkError> {
        let ctrl = self.get_inner_mut();
        let queues = &ctrl.json["queues"];
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
        let ctrl = self.get_inner_mut();
        let __tgt_flags = &ctrl.json["target_flags"];
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
        let tgt_val = &self.get_inner().json["target"];
        let tgt: Result<super::io::UblkTgt, _> = serde_json::from_value(tgt_val.clone());
        if let Ok(p) = tgt {
            Ok(p)
        } else {
            Err(UblkError::OtherError(-libc::EINVAL))
        }
    }

    /// Return target json data
    ///
    /// Should only be called after device is started, otherwise target data
    /// won't be serialized out, and this API returns None
    pub fn get_target_data_from_json(&self) -> Option<serde_json::Value> {
        let val = &self.get_inner().json["target_data"];
        if !val.is_null() {
            Some(val.clone())
        } else {
            None
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

    /// Dump this device info
    ///
    /// The 1st part is from UblkCtrl.dev_info, and the 2nd part is
    /// retrieved from device's exported json file
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

        let info = &ctrl.dev_info;
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
            ctrl.dev_state_desc()
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

        ctrl.dump_from_json();
    }

    pub fn run_dir() -> String {
        format!("{}/ublk", std::env::temp_dir().display())
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
        match Self::new(None, -1, 0, 0, 0, 0, 0, 0) {
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
    pub fn start_dev(&self, dev: &UblkDev) -> Result<i32, UblkError> {
        let mut ctrl = self.get_inner_mut();
        ctrl.prep_start_dev(dev)?;

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
    pub async fn start_dev_async(&self, dev: &UblkDev) -> Result<i32, UblkError> {
        let mut ctrl = self.get_inner_mut();
        ctrl.prep_start_dev(dev)?;

        if ctrl.dev_info.state != sys::UBLK_S_DEV_QUIESCED as u16 {
            ctrl.start_async(unsafe { libc::getpid() as i32 }).await
        } else if ctrl.for_recover_dev() {
            ctrl.end_user_recover_async(unsafe { libc::getpid() as i32 })
                .await
        } else {
            Err(crate::UblkError::OtherError(-libc::EINVAL))
        }
    }

    /// Stop ublk device
    ///
    /// Remove json export, and send stop command to control device
    ///
    pub fn stop_dev(&self) -> Result<i32, UblkError> {
        let mut ctrl = self.get_inner_mut();
        let rp = ctrl.run_path();

        if ctrl.for_add_dev() && Path::new(&rp).exists() {
            fs::remove_file(rp).map_err(UblkError::OtherIOError)?;
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
            fs::remove_file(ctrl.run_path()).map_err(UblkError::OtherIOError)?;
        }
        Ok(0)
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

            let mut affinity = UblkQueueAffinity::new();
            self.get_queue_affinity(q as u32, &mut affinity).unwrap();
            let mut _q_fn = q_fn.clone();

            q_threads.push(std::thread::spawn(move || {
                //setup pthread affinity first, so that any allocation may
                //be affine to cpu/memory
                unsafe {
                    libc::pthread_setaffinity_np(
                        libc::pthread_self(),
                        affinity.buf_len(),
                        affinity.addr() as *const libc::cpu_set_t,
                    );
                }
                _tx.send((q, unsafe { libc::gettid() })).unwrap();

                unsafe {
                    const PR_SET_IO_FLUSHER: i32 = 57; //include/uapi/linux/prctl.h
                    libc::prctl(PR_SET_IO_FLUSHER, 0, 0, 0, 0);
                };

                _q_fn(q, &_dev);
            }));
        }

        for _q in 0..nr_queues {
            let (qid, tid) = rx.recv().unwrap();
            if self.configure_queue(dev, qid, tid).is_err() {
                println!(
                    "create_queue_handler: configure queue failed for {}-{}",
                    dev.dev_info.dev_id, qid
                );
            }
        }

        q_threads
    }

    /// Run ublk daemon and kick off the ublk device, and `/dev/ublkbN` will be
    /// created and visible to userspace.
    ///
    /// # Arguments:
    ///
    /// * `tgt_fn`: target initialization handler
    /// * `q_fn`: queue handler for setting up the queue and its handler
    /// * `device_fn`: handler called after device is started, run in current
    ///     context
    ///
    /// This one is the preferred interface for creating ublk daemon, and
    /// is friendly for user, such as, user can customize queue setup and
    /// io handler, such as setup async/await for handling io command.
    pub fn run_target<T, Q, W>(&self, tgt_fn: T, q_fn: Q, device_fn: W) -> Result<i32, UblkError>
    where
        T: FnOnce(&mut UblkDev) -> Result<i32, UblkError>,
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
        if let Ok(entries) = std::fs::read_dir(UblkCtrl::run_dir()) {
            for entry in entries.flatten() {
                let f = entry.path();
                if f.is_file() {
                    if let Some(file_stem) = f.file_stem() {
                        if let Some(stem) = file_stem.to_str() {
                            if let Ok(num) = stem.parse::<u32>() {
                                ops(num);
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
    use super::dev_flags::*;
    use crate::ctrl::UblkCtrlBuilder;
    use crate::io::{UblkDev, UblkIOCtx, UblkQueue};
    use crate::{ctrl::UblkCtrl, UblkIORes};
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

    #[test]
    fn test_add_ctrl_dev() {
        let ctrl =
            UblkCtrl::new(None, -1, 1, 64, 512_u32 * 1024, 0, 0, UBLK_DEV_F_ADD_DEV).unwrap();
        let dev_path = ctrl.get_cdev_path();

        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(Path::new(&dev_path).exists() == true);
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
            UBLK_DEV_F_ADD_DEV,
        )
        .unwrap();
        let dev_path = ctrl.get_cdev_path();

        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(Path::new(&dev_path).exists() == true);
    }

    #[test]
    fn test_ublk_target_json() {
        let ctrl = UblkCtrlBuilder::default()
            .name("null")
            .ctrl_target_flags(0xbeef as u64)
            .dev_flags(UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap();

        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            dev.set_target_json(serde_json::json!({"null": "test_data" }));
            Ok(0)
        };
        let dev = UblkDev::new(ctrl.get_name(), tgt_init, &ctrl).unwrap();

        //not built & flushed out yet
        assert!(ctrl.get_target_data_from_json().is_none());
        assert!(dev.get_target_json().is_some());
        assert!(dev.dev_info.ublksrv_flags == 0xbeef as u64);
        assert!(ctrl.dev_info().ublksrv_flags == 0xbeef as u64);
    }

    fn __test_ublk_session<T>(w_fn: T) -> String
    where
        T: Fn(&UblkCtrl) + Send + Sync + Clone + 'static,
    {
        let ctrl = UblkCtrlBuilder::default()
            .name("null")
            .depth(16_u16)
            .nr_queues(2_u16)
            .dev_flags(UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap();

        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            dev.set_target_json(serde_json::json!({"null": "test_data" }));
            Ok(0)
        };
        let q_fn = move |qid: u16, dev: &UblkDev| {
            let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
            let bufs = bufs_rc.clone();

            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let iod = q.get_iod(tag);
                let bytes = (iod.nr_sectors << 9) as i32;
                let bufs = bufs_rc.clone();
                let buf_addr = bufs[tag as usize].as_mut_ptr();

                q.complete_io_cmd(tag, buf_addr, Ok(UblkIORes::Result(bytes)));
            };

            UblkQueue::new(qid, dev)
                .unwrap()
                .regiser_io_bufs(Some(&bufs))
                .submit_fetch_commands(Some(&bufs))
                .wait_and_handle_io(io_handler);
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
        // Create one ublk device
        let handle = std::thread::spawn(|| {
            let cdev = __test_ublk_session(|ctrl: &UblkCtrl| {
                std::thread::sleep(std::time::Duration::from_millis(1000));
                ctrl.kill_dev().unwrap();
            });
            // could be too strict because of udev
            assert!(Path::new(&cdev).exists() == false);
        });

        std::thread::sleep(std::time::Duration::from_millis(400));
        let cnt_arc = Rc::new(Cell::new(0));
        let cnt = cnt_arc.clone();

        //count all existed ublk devices
        UblkCtrl::for_each_dev_id(move |dev_id| {
            let ctrl = UblkCtrl::new_simple(dev_id as i32, 0).unwrap();
            cnt.set(cnt.get() + 1);

            let dev_path = ctrl.get_cdev_path();
            assert!(Path::new(&dev_path).exists() == true);
        });

        // we created one
        assert!(cnt_arc.get() > 0);

        handle.join().unwrap();
    }
}
