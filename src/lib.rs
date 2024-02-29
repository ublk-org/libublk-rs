//! # libublk
//!
//! A library for building linux ublk block device in userspace, see related
//! docs in `<https://github.com/ming1/ubdsrv/blob/master/doc/external_links.rst>`
//! and introduction doc in
//! `<https://github.com/ming1/ubdsrv/blob/master/doc/ublk_intro.pdf>`

use bitflags::bitflags;

pub mod ctrl;
pub mod helpers;
pub mod io;
pub mod sys;
pub mod uring_async;

bitflags! {
    #[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
    /// UblkFlags: top 8bits are reserved for internal use
    pub struct UblkFlags: u32 {
        /// feature: support IO batch completion from single IO tag, typical
        /// usecase is to complete IOs from eventfd CQE handler
        const UBLK_DEV_F_COMP_BATCH = 0b00000001;

        /// tell UblkCtrl that we are adding one new device
        const UBLK_DEV_F_ADD_DEV = 0b00000010;

        /// tell UblkCtrl that we are recovering one old device
        const UBLK_DEV_F_RECOVER_DEV = 0b00000100;

        const UBLK_DEV_F_INTERNAL_0 = 1_u32 << 31;
    }
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
    #[error("uring submission timeout")]
    UringTimeout,

    #[error("IO Queued")]
    UringIoQueued,

    #[error("io_uring IO failure")]
    UringIOError(i32),

    #[error("json failure")]
    JsonError(#[from] serde_json::Error),

    #[error("queue down failure")]
    QueueIsDown,

    #[error("other IO failure")]
    IOError(#[from] std::io::Error),

    #[error("Invalid input")]
    InvalidVal,

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
