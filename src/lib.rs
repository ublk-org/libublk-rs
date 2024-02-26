//! # libublk
//!
//! A library for building linux ublk block device in userspace, see related
//! docs in `<https://github.com/ming1/ubdsrv/blob/master/doc/external_links.rst>`
//! and introduction doc in
//! `<https://github.com/ming1/ubdsrv/blob/master/doc/ublk_intro.pdf>`

use log::error;
use std::alloc::{alloc, dealloc, Layout};

pub mod ctrl;
pub mod helpers;
pub mod io;
pub mod sys;
pub mod uring_async;

pub mod dev_flags {
    /// feature: support IO batch completion from single IO tag, typical
    /// usecase is to complete IOs from eventfd CQE handler
    pub const UBLK_DEV_F_COMP_BATCH: u32 = 1u32 << 0;

    /// tell UblkCtrl that we are adding one new device
    pub const UBLK_DEV_F_ADD_DEV: u32 = 1u32 << 1;

    /// tell UblkCtrl that we are recovering one old device
    pub const UBLK_DEV_F_RECOVER_DEV: u32 = 1u32 << 2;

    pub const UBLK_DEV_F_ALL: u32 =
        UBLK_DEV_F_COMP_BATCH | UBLK_DEV_F_ADD_DEV | UBLK_DEV_F_RECOVER_DEV;
}

/// Ublk Fat completion result
pub enum UblkFatRes {
    /// Batch completion
    ///
    /// Vector is returned, and each element(`tag`, `result`) describes one
    /// io command completion result.
    BatchRes(Vec<(u16, i32)>),

    /// Zoned Append completion result
    ///
    /// (`result`, `returned lba`) is included in this result.
    ZonedAppendRes((i32, u64)),
}

/// Ublk IO completion result
///
/// Ok() part of io command completion result `Result<UblkIORes, UblkError>`
pub enum UblkIORes {
    /// normal result
    ///
    /// Completion result of this io command
    Result(i32),

    /// Fat completion result
    #[cfg(feature = "fat_complete")]
    FatRes(UblkFatRes),
}

#[derive(thiserror::Error, Debug)]
pub enum UblkError {
    #[error("failed to read the key file")]
    UringSubmissionError(#[source] std::io::Error),

    #[error("uring submission timeout")]
    UringSubmissionTimeout(i32),

    #[error("failed to push SQE to uring")]
    UringPushError(#[from] io_uring::squeue::PushError),

    #[error("io_uring IO failure")]
    UringIOError(i32),

    #[error("json failure")]
    JsonError(#[from] serde_json::Error),

    #[error("mmap failure")]
    MmapError(i32),

    #[error("queue down failure")]
    QueueIsDown(i32),

    #[error("other IO failure")]
    OtherIOError(#[source] std::io::Error),

    #[error("IO Queued")]
    IoQueued(i32),

    #[error("other failure")]
    OtherError(i32),
}

pub fn ublk_alloc_buf(size: usize, align: usize) -> *mut u8 {
    let layout = match Layout::from_size_align(size, align) {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut(),
    };
    unsafe { alloc(layout) }
}

pub fn ublk_dealloc_buf(ptr: *mut u8, size: usize, align: usize) {
    let layout = match Layout::from_size_align(size, align) {
        Ok(r) => r,
        Err(_) => return,
    };
    unsafe { dealloc(ptr as *mut u8, layout) };
}

#[macro_use]
extern crate derive_builder;

/// UblkSession: build one new ublk control device or recover the old one.
///
/// High level API.
///
/// One limit is that IO handling closure doesn't support FnMut, and low
/// level API doesn't have such limit.
///
#[derive(Default, Builder, Debug)]
#[builder(setter(into))]
#[allow(dead_code)]
pub struct UblkSession {
    /// target type, such as null, loop, ramdisk, or nbd,...
    name: String,

    /// device id: -1 can only be used for adding one new device,
    /// and ublk driver will allocate one new ID for the created device;
    /// otherwise, we are asking driver to create or recover or list
    /// one device with specified ID
    #[builder(default = "-1")]
    id: i32,

    /// how many queues
    #[builder(default = "1_u32")]
    nr_queues: u32,

    /// each queue's IO depth
    #[builder(default = "64_u32")]
    depth: u32,

    /// max size of each IO buffer size, which will be converted to
    /// block layer's queue limit of max hw sectors
    #[builder(default = "524288_u32")]
    io_buf_bytes: u32,

    /// passed to ublk driver via `sys::ublksrv_ctrl_dev_info.flags`,
    /// usually for adding or recovering device
    #[builder(default = "0")]
    ctrl_flags: u64,

    /// store target flags in `sys::ublksrv_ctrl_dev_info.ublksrv_flags`,
    /// which is immutable in the whole device lifetime
    #[builder(default = "0")]
    ctrl_target_flags: u64,

    /// libublk feature flags: UBLK_DEV_F_*
    #[builder(default = "0")]
    dev_flags: u32,
}

impl UblkSession {
    pub fn name(&self) -> String {
        self.name.clone()
    }
    /// create one pair of ublk devices, the 1st one is control device(`UblkCtrl`),
    /// and the 2nd one is data device(`UblkDev`)
    pub fn create_ctrl_dev(&self) -> Result<ctrl::UblkCtrl, UblkError> {
        Ok(ctrl::UblkCtrl::new(
            Some(self.name.clone()),
            self.id,
            self.nr_queues,
            self.depth,
            self.io_buf_bytes,
            self.ctrl_flags,
            self.ctrl_target_flags,
            self.dev_flags,
        )?)
    }
}

#[cfg(test)]
mod libublk {
    use crate::{UblkError, UblkIORes};

    #[cfg(not(feature = "fat_complete"))]
    #[test]
    fn test_feature_fat_complete() {
        let sz = core::mem::size_of::<Result<UblkIORes, UblkError>>();
        assert!(sz == 16);
    }

    #[cfg(feature = "fat_complete")]
    #[test]
    fn test_feature_fat_complete() {
        let sz = core::mem::size_of::<Result<UblkIORes, UblkError>>();
        assert!(sz == 32);
    }
}
