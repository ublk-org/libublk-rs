//! Async io_uring operation constructors and their futures.
//!
//! Every function submits one SQE on the thread-local queue ring and
//! returns a future resolving to the CQE result — the OP-based analog of
//! hand-building SQEs and bit-encoding `user_data`. Owned-buffer ops move
//! a `Box<[u8]>` into the op for its lifetime and hand it back on
//! completion, so they are safe under arbitrary future cancellation. Raw
//! ops carry only a pointer and are the hot-path variants for queue-slot
//! buffers; see their safety contracts.
//!
//! The catalog covers the target-side IO a ublk server needs: file-backed
//! storage (read/write/fsync/fallocate/sync_file_range), sockets for
//! network targets like nbd or nvme-tcp (accept/recv/send), ring timers
//! ([`sleep`]), fd readiness ([`poll_add`]), and an escape hatch for any
//! other opcode ([`submit_sqe`]).

use std::future::Future;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use io_uring::{opcode, squeue, types};

use crate::op::{Op, Resources};
use crate::UblkError;

/// A target IO's file: a raw fd, or an index into the queue ring's
/// registered fixed-file table (index 0 is the ublk char device; targets
/// typically register their backing file at index 1).
#[derive(Clone, Copy)]
pub enum TgtFd {
    /// A plain (non-registered) file descriptor.
    Raw(RawFd),
    /// An index into the ring's registered fixed-file table.
    Fixed(u16),
}

/// Build one opcode against either fd form.
macro_rules! with_tgt_fd {
    ($file:expr, |$fd:ident| $build:expr) => {
        match $file {
            TgtFd::Raw(raw) => {
                let $fd = types::Fd(raw);
                $build
            }
            TgtFd::Fixed(idx) => {
                let $fd = types::Fixed(idx.into());
                $build
            }
        }
    };
}

fn buf_len(buf: &[u8]) -> Result<u32, UblkError> {
    u32::try_from(buf.len()).map_err(|_| UblkError::InvalidVal)
}

/// Future of an op that owns one buffer; resolves to the CQE result plus
/// the buffer handed back.
pub struct BufOp {
    op: Op,
}

impl Future for BufOp {
    type Output = (i32, Box<[u8]>);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (result, resources) = ready!(self.op.poll_single(cx));
        Poll::Ready((result, resources.into_buffer()))
    }
}

/// Future of an op without owned resources; resolves to the CQE result
/// (negative errno on failure, as io_uring reports it).
pub struct RawOp {
    op: Op,
}

impl RawOp {
    pub(crate) fn new(op: Op) -> Self {
        RawOp { op }
    }
}

impl Future for RawOp {
    type Output = i32;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (result, _) = ready!(self.op.poll_single(cx));
        Poll::Ready(result)
    }
}

/// Read from `file` at `offset` into an owned buffer.
pub fn read_at(file: TgtFd, mut buf: Box<[u8]>, offset: u64) -> Result<BufOp, UblkError> {
    let len = buf_len(&buf)?;
    let ptr = buf.as_mut_ptr();
    let op = Op::submit(
        |key| {
            with_tgt_fd!(file, |fd| opcode::Read::new(fd, ptr, len)
                .offset(offset)
                .build()
                .user_data(key))
        },
        Resources::Buffer(buf),
        false,
    )?;
    Ok(BufOp { op })
}

/// Write `buf` to `file` at `offset`.
pub fn write_at(file: TgtFd, buf: Box<[u8]>, offset: u64) -> Result<BufOp, UblkError> {
    let len = buf_len(&buf)?;
    let ptr = buf.as_ptr();
    let op = Op::submit(
        |key| {
            with_tgt_fd!(file, |fd| opcode::Write::new(fd, ptr, len)
                .offset(offset)
                .build()
                .user_data(key))
        },
        Resources::Buffer(buf),
        false,
    )?;
    Ok(BufOp { op })
}

/// Positional read into caller-managed memory (queue-slot buffers).
///
/// # Safety
///
/// `ptr..ptr+len` must remain valid and unaliased for writes until this
/// op's CQE has been reaped — which, if the returned future is dropped
/// before completion, is *later* than the drop: the caller must keep the
/// memory alive until queue teardown confirms no ops are pending.
pub unsafe fn read_at_raw(
    file: TgtFd,
    ptr: *mut u8,
    len: u32,
    offset: u64,
) -> Result<RawOp, UblkError> {
    let op = Op::submit(
        |key| {
            with_tgt_fd!(file, |fd| opcode::Read::new(fd, ptr, len)
                .offset(offset)
                .build()
                .user_data(key))
        },
        Resources::None,
        false,
    )?;
    Ok(RawOp { op })
}

/// Positional write from caller-managed memory.
///
/// # Safety
///
/// Same contract as [`read_at_raw`] (reads the buffer only).
pub unsafe fn write_at_raw(
    file: TgtFd,
    ptr: *const u8,
    len: u32,
    offset: u64,
) -> Result<RawOp, UblkError> {
    let op = Op::submit(
        |key| {
            with_tgt_fd!(file, |fd| opcode::Write::new(fd, ptr, len)
                .offset(offset)
                .build()
                .user_data(key))
        },
        Resources::None,
        false,
    )?;
    Ok(RawOp { op })
}

/// `fsync(2)` / `fdatasync(2)` via the ring.
pub fn fsync(file: TgtFd, datasync: bool) -> Result<RawOp, UblkError> {
    let flags = if datasync {
        types::FsyncFlags::DATASYNC
    } else {
        types::FsyncFlags::empty()
    };
    let op = Op::submit(
        |key| {
            with_tgt_fd!(file, |fd| opcode::Fsync::new(fd)
                .flags(flags)
                .build()
                .user_data(key))
        },
        Resources::None,
        false,
    )?;
    Ok(RawOp { op })
}

/// `sync_file_range(2)` via the ring (`flags` is the `SYNC_FILE_RANGE_*`
/// bitset; 0 requests write-and-wait on most kernels' flush paths).
pub fn sync_file_range(
    file: TgtFd,
    offset: u64,
    len: u32,
    flags: u32,
) -> Result<RawOp, UblkError> {
    let op = Op::submit(
        |key| {
            with_tgt_fd!(file, |fd| opcode::SyncFileRange::new(fd, len)
                .offset(offset)
                .flags(flags)
                .build()
                .user_data(key))
        },
        Resources::None,
        false,
    )?;
    Ok(RawOp { op })
}

/// `fallocate(2)` via the ring (`FALLOC_FL_*` modes: punch-hole,
/// zero-range, ... — the file target's discard/write-zeroes primitive).
pub fn fallocate(file: TgtFd, mode: i32, offset: u64, len: u64) -> Result<RawOp, UblkError> {
    let op = Op::submit(
        |key| {
            with_tgt_fd!(file, |fd| opcode::Fallocate::new(fd, len)
                .offset(offset)
                .mode(mode)
                .build()
                .user_data(key))
        },
        Resources::None,
        false,
    )?;
    Ok(RawOp { op })
}

/// Future of a ring timer.
pub struct Sleep {
    op: Op,
}

impl Future for Sleep {
    type Output = Result<(), UblkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (result, _) = ready!(self.op.poll_single(cx));
        match result {
            // -ETIME is the normal "timer fired" completion.
            0 => Poll::Ready(Ok(())),
            err if err == -libc::ETIME => Poll::Ready(Ok(())),
            err => Poll::Ready(Err(UblkError::OtherError(err))),
        }
    }
}

/// Sleep via `IORING_OP_TIMEOUT` — the timer primitive on queue threads
/// (Tokio's time driver is disabled there).
pub fn sleep(duration: Duration) -> Result<Sleep, UblkError> {
    let timespec = Box::new(
        types::Timespec::new()
            .sec(duration.as_secs())
            .nsec(duration.subsec_nanos()),
    );
    let timespec_ptr: *const types::Timespec = &*timespec;
    let op = Op::submit(
        |key| opcode::Timeout::new(timespec_ptr).build().user_data(key),
        Resources::Timespec(timespec),
        false,
    )?;
    Ok(Sleep { op })
}

/// Wait for `fd` to become ready for the given `poll(2)` event mask
/// (e.g. `libc::POLLIN`) via one-shot `IORING_OP_POLL_ADD`; completes
/// with the returned events mask. Re-issue to wait again.
pub fn poll_add(fd: RawFd, events: u32) -> Result<RawOp, UblkError> {
    let op = Op::submit(
        |key| {
            opcode::PollAdd::new(types::Fd(fd), events)
                .build()
                .user_data(key)
        },
        Resources::None,
        false,
    )?;
    Ok(RawOp { op })
}

/// Future resolving to one accepted connection.
pub struct Accept {
    op: Op,
}

impl Future for Accept {
    type Output = Result<OwnedFd, UblkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (result, _) = ready!(self.op.poll_single(cx));
        if result < 0 {
            return Poll::Ready(Err(UblkError::OtherError(result)));
        }
        // SAFETY: a successful accept CQE carries a fresh fd owned by us.
        Poll::Ready(Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) }))
    }
}

/// Accept one connection on a listening socket.
pub fn accept(fd: RawFd) -> Result<Accept, UblkError> {
    let op = Op::submit(
        |key| {
            opcode::Accept::new(types::Fd(fd), std::ptr::null_mut(), std::ptr::null_mut())
                .build()
                .user_data(key)
        },
        Resources::None,
        false,
    )?;
    Ok(Accept { op })
}

/// Receive from a socket into an owned buffer.
pub fn recv(fd: RawFd, mut buf: Box<[u8]>) -> Result<BufOp, UblkError> {
    let len = buf_len(&buf)?;
    let ptr = buf.as_mut_ptr();
    let op = Op::submit(
        |key| {
            opcode::Recv::new(types::Fd(fd), ptr, len)
                .build()
                .user_data(key)
        },
        Resources::Buffer(buf),
        false,
    )?;
    Ok(BufOp { op })
}

/// Send an owned buffer on a socket.
pub fn send(fd: RawFd, buf: Box<[u8]>) -> Result<BufOp, UblkError> {
    let len = buf_len(&buf)?;
    let ptr = buf.as_ptr();
    let op = Op::submit(
        |key| {
            opcode::Send::new(types::Fd(fd), ptr, len)
                .build()
                .user_data(key)
        },
        Resources::Buffer(buf),
        false,
    )?;
    Ok(BufOp { op })
}

/// Receive into caller-managed memory (queue-slot buffers).
///
/// # Safety
///
/// Same contract as [`read_at_raw`].
pub unsafe fn recv_raw(fd: RawFd, ptr: *mut u8, len: u32) -> Result<RawOp, UblkError> {
    let op = Op::submit(
        |key| {
            opcode::Recv::new(types::Fd(fd), ptr, len)
                .build()
                .user_data(key)
        },
        Resources::None,
        false,
    )?;
    Ok(RawOp { op })
}

/// Send from caller-managed memory.
///
/// # Safety
///
/// Same contract as [`read_at_raw`] (reads the buffer only).
pub unsafe fn send_raw(fd: RawFd, ptr: *const u8, len: u32) -> Result<RawOp, UblkError> {
    let op = Op::submit(
        |key| {
            opcode::Send::new(types::Fd(fd), ptr, len)
                .build()
                .user_data(key)
        },
        Resources::None,
        false,
    )?;
    Ok(RawOp { op })
}

/// Submit an arbitrary SQE on the queue ring — the escape hatch for
/// opcodes without a dedicated constructor. The entry's `user_data` is
/// overwritten with the op key.
///
/// # Safety
///
/// Every pointer the SQE carries must remain valid until this op's CQE
/// has been reaped — same contract as [`read_at_raw`].
pub unsafe fn submit_sqe(sqe: squeue::Entry) -> Result<RawOp, UblkError> {
    let op = Op::submit(|key| sqe.user_data(key), Resources::None, false)?;
    Ok(RawOp { op })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::UblkRuntime;
    use crate::UblkError;
    use io_uring::opcode;
    use std::time::{Duration, Instant};

    fn test_runtime() -> Result<UblkRuntime, UblkError> {
        crate::io::init_task_ring_default(64, 64)?;
        UblkRuntime::new()
    }

    /// Test submit_sqe with NOP operation
    #[test]
    fn test_ops_submit_sqe_nop() -> Result<(), UblkError> {
        let rt = test_runtime()?;
        rt.block_on(async {
            let nop_sqe = opcode::Nop::new().build();
            // SAFETY: NOP references no memory.
            let result = unsafe { submit_sqe(nop_sqe) }?.await;
            assert_eq!(result, 0); // NOP should return 0
            Ok(())
        })
    }

    /// Test the ring timer
    #[test]
    fn test_ops_sleep() -> Result<(), UblkError> {
        let rt = test_runtime()?;
        rt.block_on(async {
            let start = Instant::now();
            sleep(Duration::from_millis(100))?.await?;
            let elapsed = start.elapsed();

            // Timer should fire in approximately 100ms
            assert!(elapsed >= Duration::from_millis(90));
            assert!(elapsed <= Duration::from_millis(200));
            Ok(())
        })
    }

    /// Test multiple concurrent operations
    #[test]
    fn test_ops_concurrent() -> Result<(), UblkError> {
        let rt = test_runtime()?;
        rt.block_on(async {
            let tasks: Vec<_> = (0..5)
                .map(|_| {
                    tokio::task::spawn_local(async {
                        let nop_sqe = opcode::Nop::new().build();
                        // SAFETY: NOP references no memory.
                        let result = unsafe { submit_sqe(nop_sqe) }.unwrap().await;
                        assert_eq!(result, 0);
                    })
                })
                .collect();
            for task in tasks {
                task.await.unwrap();
            }
        });
        Ok(())
    }

    /// Test error handling with an invalid operation
    #[test]
    fn test_ops_error_handling() -> Result<(), UblkError> {
        let rt = test_runtime()?;
        rt.block_on(async {
            use io_uring::types::Fd;

            let close_sqe = opcode::Close::new(Fd(-1)).build();
            // SAFETY: CLOSE references no memory.
            let result = unsafe { submit_sqe(close_sqe) }?.await;
            // Close with invalid fd should return -EBADF (-9)
            assert_eq!(result, -9);
            Ok(())
        })
    }

    /// Test that read_at/write_at hand the buffer back
    #[test]
    fn test_ops_file_read_write() -> Result<(), UblkError> {
        let rt = test_runtime()?;
        let file = tempfile::NamedTempFile::new().map_err(UblkError::IOError)?;
        let fd = {
            use std::os::fd::AsRawFd;
            file.as_file().as_raw_fd()
        };
        rt.block_on(async move {
            let data = vec![0x5au8; 4096].into_boxed_slice();
            let (res, _buf) = write_at(TgtFd::Raw(fd), data, 0)?.await;
            assert_eq!(res, 4096);

            let (res, buf) = read_at(TgtFd::Raw(fd), vec![0u8; 4096].into_boxed_slice(), 0)?.await;
            assert_eq!(res, 4096);
            assert!(buf.iter().all(|b| *b == 0x5a));

            let res = fsync(TgtFd::Raw(fd), false)?.await;
            assert_eq!(res, 0);
            Ok(())
        })
    }
}
