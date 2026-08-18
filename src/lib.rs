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
mod op;
pub mod ops;
pub mod reactor;
#[cfg(feature = "tokio")]
pub mod runtime;
pub mod sys;
// The shared test helpers drive devices through UblkRuntime; the
// reactor-only build tests the reactor directly instead.
#[cfg(all(test, feature = "tokio"))]
pub mod test_helpers;

// Re-export io_uring: `squeue::Entry` and `cqueue::Entry` appear in this
// crate's public API (`ops::submit_sqe`, `UblkQueue::ublk_submit_sqe`,
// the `flush_and_wake_io_tasks` handler, the ring accessors), so a
// target must build those values from the *same* io-uring version the
// library was compiled against. Name it as `libublk::io_uring` instead
// of declaring a separate dependency that has to be kept in lockstep.
pub use io_uring;

// Re-export tokio so targets use the same runtime version as the library
// (tasks are spawned with `tokio::task::spawn_local` inside
// `UblkRuntime::block_on`).
#[cfg(feature = "tokio")]
pub use tokio;

#[cfg(feature = "tokio")]
pub use runtime::UblkRuntime;

// Re-export important types for unified buffer management
#[allow(deprecated)]
pub use io::{
    ublk_init_task_ring, with_task_io_ring, with_task_io_ring_mut, BufDesc, BufDescList,
    UblkBatchBuffers, UblkBatchCompletion, UblkBatchConfig, UblkBatchQueue,
};

// Re-export control ring initialization and access
pub use ctrl::{ublk_init_ctrl_task_ring, with_ctrl_ring, with_ctrl_ring_mut};

/// Ublk io_uring user_data constants, used by the legacy sync event
/// loop's tag-encoded `user_data` (async ops are slab-keyed and carry no
/// bit-encoded metadata)
///
/// Non-exhaustive: the reserved `user_data` bits are a wire format
/// shared with the kernel, and further bits may be spoken for later.
#[repr(u64)]
#[non_exhaustive]
pub enum UblkUringData {
    /// Target IO bit flag - indicates user_data is from target IO
    Target = 1_u64 << 63,
}

bitflags! {
    #[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
    /// UblkFlags: top 8bits are reserved for internal use
    pub struct UblkFlags: u32 {
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

        /// Reserved for libublk's own use; targets must not set the
        /// top 8 bits.
        const UBLK_DEV_F_INTERNAL_0 = 1_u32 << 31;
        /// Reserved for libublk's own use.
        const UBLK_DEV_F_INTERNAL_1 = 1_u32 << 30;
        /// Reserved for libublk's own use.
        const UBLK_DEV_F_INTERNAL_2 = 1_u32 << 29;
        /// Reserved for libublk's own use.
        const UBLK_DEV_F_INTERNAL_3 = 1_u32 << 28;
        /// Reserved for libublk's own use.
        const UBLK_DEV_F_INTERNAL_4 = 1_u32 << 27;
    }
}

macro_rules! ublk_internal_flags_all {
    () => {
        UblkFlags::UBLK_DEV_F_INTERNAL_0
            | UblkFlags::UBLK_DEV_F_INTERNAL_1
            | UblkFlags::UBLK_DEV_F_INTERNAL_2
            | UblkFlags::UBLK_DEV_F_INTERNAL_3
            | UblkFlags::UBLK_DEV_F_INTERNAL_4
    };
}

pub(crate) use ublk_internal_flags_all;

/// Every fallible libublk operation reports this error.
///
/// Use [`UblkError::errno`] to turn one into the negative errno a ublk
/// server completes a failed io command with. The enum is
/// `#[non_exhaustive]`: match with a `_` arm.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum UblkError {
    /// An io_uring operation completed with a negative errno, carried
    /// verbatim as the CQE reported it.
    #[error("io_uring IO failure")]
    UringIOError(i32),

    /// Device parameters or the recovery JSON failed to (de)serialize.
    #[error("json failure")]
    JsonError(#[from] serde_json::Error),

    /// The queue is being torn down and accepts no further io. Queue
    /// handlers normally treat this as the signal to return cleanly.
    #[error("queue down failure")]
    QueueIsDown,

    /// A syscall or `/dev/ublk-control` operation failed; wraps the
    /// underlying [`std::io::Error`].
    #[error("other IO failure")]
    IOError(#[from] std::io::Error),

    /// An argument was rejected before anything was submitted: a buffer
    /// descriptor incompatible with the device flags, an out-of-range
    /// length, a bad configuration.
    #[error("Invalid input")]
    InvalidVal,

    /// A failure with no more specific variant, as a negative errno.
    #[error("other failure")]
    OtherError(i32),
}

impl UblkError {
    /// Map this error to a negative errno, the form a ublk server uses
    /// to complete a failed io command (and the form io_uring CQEs
    /// report), so target code can propagate any [`UblkError`] into an
    /// io completion.
    pub fn errno(&self) -> i32 {
        let e = match self {
            UblkError::UringIOError(res) | UblkError::OtherError(res) => *res,
            UblkError::IOError(err) => -err.raw_os_error().unwrap_or(libc::EIO),
            UblkError::JsonError(_) => -libc::EINVAL,
            UblkError::InvalidVal => -libc::EINVAL,
            UblkError::QueueIsDown => -libc::ENODEV,
        };
        if e > 0 {
            -e
        } else if e == 0 {
            -libc::EIO
        } else {
            e
        }
    }
}

#[cfg(test)]
mod libublk {
    use crate::UblkError;

    #[test]
    fn test_io_res_size() {
        let sz = core::mem::size_of::<Result<i32, UblkError>>();
        assert!(sz == 16);
    }
}
