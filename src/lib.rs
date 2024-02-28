//! # libublk
//!
//! A library for building linux ublk block device in userspace, see related
//! docs in `<https://github.com/ming1/ubdsrv/blob/master/doc/external_links.rst>`
//! and introduction doc in
//! `<https://github.com/ming1/ubdsrv/blob/master/doc/ublk_intro.pdf>`

use log::error;

pub mod ctrl;
pub mod helpers;
pub mod io;
pub mod sys;
pub mod uring_async;

/// Don't use the top 8 bits, which are reserved for internal uses
pub mod dev_flags {
    /// feature: support IO batch completion from single IO tag, typical
    /// usecase is to complete IOs from eventfd CQE handler
    pub const UBLK_DEV_F_COMP_BATCH: u32 = 1u32 << 0;

    /// tell UblkCtrl that we are adding one new device
    pub const UBLK_DEV_F_ADD_DEV: u32 = 1u32 << 1;

    /// tell UblkCtrl that we are recovering one old device
    pub const UBLK_DEV_F_RECOVER_DEV: u32 = 1u32 << 2;

    pub(crate) const UBLK_DEV_F_INTERNAL_0: u32 = 1u32 << 31;

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
