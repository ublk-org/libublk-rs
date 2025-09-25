//! # libublk
//!
//! A library for building linux ublk block device in userspace, see related
//! docs in `<https://github.com/ming1/ubdsrv/blob/master/doc/external_links.rst>`
//! and introduction doc in
//! `<https://github.com/ming1/ubdsrv/blob/master/doc/ublk_intro.pdf>`

use bitflags::bitflags;

mod bindings;
pub mod ctrl;
pub mod ctrl_async;
pub mod helpers;
pub mod io;
pub mod sys;
#[cfg(test)]
pub mod test_helpers;
pub mod uring_async;

// Re-export important types for unified buffer management
#[allow(deprecated)]
pub use io::{
    ublk_init_task_ring, with_queue_ring, with_queue_ring_mut, with_task_io_ring,
    with_task_io_ring_mut, BufDesc, BufDescList,
};

// Re-export control ring initialization and access
pub use ctrl::{ublk_init_ctrl_task_ring, with_ctrl_ring, with_ctrl_ring_mut};

// Re-export async utilities
pub use uring_async::{
    run_uring_tasks, ublk_reap_events_with_handler, ublk_reap_io_events, wait_and_handle_io_events,
};

/// Ublk io_uring user_data constants
#[repr(u64)]
pub enum UblkUringData {
    /// Target IO bit flag - indicates user_data is from target IO
    Target = 1_u64 << 63,
    /// Non-async IO bit flag - indicates it is from one non-async IO in
    /// async/.await code path, should only be used in async/.await
    NonAsync = 1_u64 << 62,
}

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

        /// tell UblkCtrl that we are deleted in async
        const UBLK_DEV_F_DEL_DEV_ASYNC = 0b00001000;

        /// enable single CPU affinity optimization: select one random CPU
        /// from queue's affinity instead of setting all CPUs
        const UBLK_DEV_F_SINGLE_CPU_AFFINITY = 0b00010000;

        /// enable mlock for io buffers: lock user IO buffer pages in memory
        /// to prevent swapping. Requires CAP_IPC_LOCK capability.
        /// It is required for ublk to be used as swap disk
        const UBLK_DEV_F_MLOCK_IO_BUFFER = 0b00100000;

        const UBLK_DEV_F_INTERNAL_0 = 1_u32 << 31;
        const UBLK_DEV_F_INTERNAL_1 = 1_u32 << 30;
        const UBLK_DEV_F_INTERNAL_2 = 1_u32 << 29;
        const UBLK_DEV_F_INTERNAL_3 = 1_u32 << 28;
    }
}

macro_rules! ublk_internal_flags_all {
    () => {
        UblkFlags::UBLK_DEV_F_INTERNAL_0
            | UblkFlags::UBLK_DEV_F_INTERNAL_1
            | UblkFlags::UBLK_DEV_F_INTERNAL_2
            | UblkFlags::UBLK_DEV_F_INTERNAL_3
    };
}

pub(crate) use ublk_internal_flags_all;

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
