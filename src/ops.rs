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
//!
//! # Completion-type convention
//!
//! Catalog ops resolve to the raw CQE result (`i32`, negative errno on
//! failure): a ublk server usually completes the incoming io with that
//! value verbatim, so [`RawOp`] and [`BufOp`] do not translate it.
//! Dedicated future types translate to `Result` only where the raw value
//! is not what the caller wants: [`Sleep`] folds the timer's `-ETIME`
//! into success, and [`Accept`] wraps the returned descriptor in an
//! [`OwnedFd`].

use std::future::Future;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use io_uring::{opcode, squeue, types};

use crate::op::{MultiOp, Op, Resources};
use crate::UblkError;

/// A target IO's file: a raw fd, or an index into the queue ring's
/// registered fixed-file table (index 0 is the ublk char device; targets
/// typically register their backing file at index 1).
#[derive(Clone, Copy)]
#[non_exhaustive]
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

    #[inline]
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

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (result, _) = ready!(self.op.poll_single(cx));
        Poll::Ready(result)
    }
}

/// Submit a resource-free SQE; its `user_data` is overwritten with the
/// op key.
#[inline]
fn submit_raw(sqe: squeue::Entry) -> Result<RawOp, UblkError> {
    let op = Op::submit(|key| sqe.user_data(key), Resources::None)?;
    Ok(RawOp::new(op))
}

/// Submit an SQE referencing `buf`, keeping the buffer alive in the op
/// until the CQE hands it back; `user_data` is overwritten with the op
/// key.
#[inline]
fn submit_buf(sqe: squeue::Entry, buf: Box<[u8]>) -> Result<BufOp, UblkError> {
    let op = Op::submit(|key| sqe.user_data(key), Resources::Buffer(buf))?;
    Ok(BufOp { op })
}

/// Read from `file` at `offset` into an owned buffer.
pub fn read_at(file: TgtFd, mut buf: Box<[u8]>, offset: u64) -> Result<BufOp, UblkError> {
    let len = buf_len(&buf)?;
    let ptr = buf.as_mut_ptr();
    let sqe = with_tgt_fd!(file, |fd| opcode::Read::new(fd, ptr, len)
        .offset(offset)
        .build());
    submit_buf(sqe, buf)
}

/// Write `buf` to `file` at `offset`.
pub fn write_at(file: TgtFd, buf: Box<[u8]>, offset: u64) -> Result<BufOp, UblkError> {
    let len = buf_len(&buf)?;
    let ptr = buf.as_ptr();
    let sqe = with_tgt_fd!(file, |fd| opcode::Write::new(fd, ptr, len)
        .offset(offset)
        .build());
    submit_buf(sqe, buf)
}

/// Positional read into caller-managed memory (queue-slot buffers).
///
/// # Safety
///
/// `ptr..ptr+len` must remain valid and unaliased for writes until this
/// op's CQE has been reaped — which, if the returned future is dropped
/// before completion, is *later* than the drop: the caller must keep the
/// memory alive until queue teardown confirms no ops are pending.
#[inline]
pub unsafe fn read_at_raw(
    file: TgtFd,
    ptr: *mut u8,
    len: u32,
    offset: u64,
) -> Result<RawOp, UblkError> {
    submit_raw(with_tgt_fd!(file, |fd| opcode::Read::new(fd, ptr, len)
        .offset(offset)
        .build()))
}

/// Positional write from caller-managed memory.
///
/// # Safety
///
/// Same contract as [`read_at_raw`] (reads the buffer only).
#[inline]
pub unsafe fn write_at_raw(
    file: TgtFd,
    ptr: *const u8,
    len: u32,
    offset: u64,
) -> Result<RawOp, UblkError> {
    submit_raw(with_tgt_fd!(file, |fd| opcode::Write::new(fd, ptr, len)
        .offset(offset)
        .build()))
}

/// Read from `file` at `offset` into the ring-registered fixed buffer
/// `buf_index` (`IORING_OP_READ_FIXED`).
///
/// # Safety
///
/// The fixed-buffer slot must stay registered, and any memory it maps
/// valid, until this op's CQE has been reaped. `ptr` addresses into the
/// registered buffer; ublk `UBLK_F_AUTO_BUF_REG` slots take a null
/// pointer.
#[inline]
pub unsafe fn read_at_fixed(
    file: TgtFd,
    buf_index: u16,
    ptr: *mut u8,
    len: u32,
    offset: u64,
) -> Result<RawOp, UblkError> {
    submit_raw(with_tgt_fd!(file, |fd| opcode::ReadFixed::new(
        fd, ptr, len, buf_index
    )
    .offset(offset)
    .build()))
}

/// Write to `file` at `offset` from the ring-registered fixed buffer
/// `buf_index` (`IORING_OP_WRITE_FIXED`).
///
/// # Safety
///
/// As for [`read_at_fixed`].
#[inline]
pub unsafe fn write_at_fixed(
    file: TgtFd,
    buf_index: u16,
    ptr: *const u8,
    len: u32,
    offset: u64,
) -> Result<RawOp, UblkError> {
    submit_raw(with_tgt_fd!(file, |fd| opcode::WriteFixed::new(
        fd, ptr, len, buf_index
    )
    .offset(offset)
    .build()))
}

/// `fsync(2)` / `fdatasync(2)` via the ring.
#[inline]
pub fn fsync(file: TgtFd, datasync: bool) -> Result<RawOp, UblkError> {
    let flags = if datasync {
        types::FsyncFlags::DATASYNC
    } else {
        types::FsyncFlags::empty()
    };
    submit_raw(with_tgt_fd!(file, |fd| opcode::Fsync::new(fd)
        .flags(flags)
        .build()))
}

/// `sync_file_range(2)` via the ring (`flags` is the `SYNC_FILE_RANGE_*`
/// bitset, passed through verbatim).
#[inline]
pub fn sync_file_range(file: TgtFd, offset: u64, len: u32, flags: u32) -> Result<RawOp, UblkError> {
    submit_raw(with_tgt_fd!(file, |fd| opcode::SyncFileRange::new(fd, len)
        .offset(offset)
        .flags(flags)
        .build()))
}

/// `fallocate(2)` via the ring (`FALLOC_FL_*` modes: punch-hole,
/// zero-range, ... — the file target's discard/write-zeroes primitive).
#[inline]
pub fn fallocate(file: TgtFd, mode: i32, offset: u64, len: u64) -> Result<RawOp, UblkError> {
    submit_raw(with_tgt_fd!(file, |fd| opcode::Fallocate::new(fd, len)
        .offset(offset)
        .mode(mode)
        .build()))
}

/// Future of a ring timer.
pub struct Sleep {
    op: RawOp,
}

impl Future for Sleep {
    type Output = Result<(), UblkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = ready!(Pin::new(&mut self.op).poll(cx));
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
    )?;
    Ok(Sleep { op: RawOp::new(op) })
}

/// No-op via the ring (`IORING_OP_NOP`): completes immediately with 0 —
/// an instant "target IO" for tests and benchmarks.
#[inline]
pub fn nop() -> Result<RawOp, UblkError> {
    submit_raw(opcode::Nop::new().build())
}

/// Wait for `fd` to become ready for the given `poll(2)` event mask
/// (e.g. `libc::POLLIN`) via one-shot `IORING_OP_POLL_ADD`; completes
/// with the returned events mask. Re-issue to wait again.
pub fn poll_add(fd: RawFd, events: u32) -> Result<RawOp, UblkError> {
    submit_raw(opcode::PollAdd::new(types::Fd(fd), events).build())
}

/// Future resolving to one accepted connection.
pub struct Accept {
    op: RawOp,
}

impl Future for Accept {
    type Output = Result<OwnedFd, UblkError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = ready!(Pin::new(&mut self.op).poll(cx));
        if result < 0 {
            return Poll::Ready(Err(UblkError::OtherError(result)));
        }
        // SAFETY: a successful accept CQE carries a fresh fd owned by us.
        Poll::Ready(Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) }))
    }
}

/// Accept one connection on a listening socket.
pub fn accept(fd: RawFd) -> Result<Accept, UblkError> {
    let op = submit_raw(
        opcode::Accept::new(types::Fd(fd), std::ptr::null_mut(), std::ptr::null_mut()).build(),
    )?;
    Ok(Accept { op })
}

/// Receive from a socket into an owned buffer. `flags` is the
/// `recv(2)` `MSG_*` bitset (e.g. `libc::MSG_WAITALL` for a
/// full-length receive), passed through verbatim.
pub fn recv(fd: TgtFd, mut buf: Box<[u8]>, flags: i32) -> Result<BufOp, UblkError> {
    let len = buf_len(&buf)?;
    let ptr = buf.as_mut_ptr();
    submit_buf(
        with_tgt_fd!(fd, |f| opcode::Recv::new(f, ptr, len).flags(flags).build()),
        buf,
    )
}

/// Send an owned buffer on a socket; `flags` as for [`recv`].
pub fn send(fd: TgtFd, buf: Box<[u8]>, flags: i32) -> Result<BufOp, UblkError> {
    let len = buf_len(&buf)?;
    let ptr = buf.as_ptr();
    submit_buf(
        with_tgt_fd!(fd, |f| opcode::Send::new(f, ptr, len).flags(flags).build()),
        buf,
    )
}

/// Receive into caller-managed memory (queue-slot buffers); `flags` as
/// for [`recv`].
///
/// # Safety
///
/// Same contract as [`read_at_raw`].
#[inline]
pub unsafe fn recv_raw(fd: TgtFd, ptr: *mut u8, len: u32, flags: i32) -> Result<RawOp, UblkError> {
    submit_raw(with_tgt_fd!(fd, |f| opcode::Recv::new(f, ptr, len)
        .flags(flags)
        .build()))
}

/// Receive into the ring-registered fixed buffer `buf_index`. `addr`
/// follows the fixed-buffer convention of the registration type: an
/// address inside a user-registered buffer, or the plain byte offset
/// for kernel-registered buffers (ublk `UBLK_F_AUTO_BUF_REG` request
/// buffers, which have no userspace mapping) -- resuming a partial
/// receive continues at the consumed byte count. `flags` as for
/// [`recv`].
///
/// # Safety
///
/// As for [`read_at_fixed`]: the fixed-buffer slot must stay registered
/// until this op's CQE has been reaped.
pub unsafe fn recv_fixed(
    fd: TgtFd,
    buf_index: u16,
    addr: u64,
    len: u32,
    flags: i32,
) -> Result<RawOp, UblkError> {
    let mut sqe = with_tgt_fd!(fd, |f| opcode::Recv::new(f, addr as *mut u8, len)
        .flags(flags)
        .build());
    crate::override_sqe!(&mut sqe, ioprio, |=, IORING_RECVSEND_FIXED_BUF);
    crate::override_sqe!(&mut sqe, buf_index, buf_index);
    submit_raw(sqe)
}

/// Send from caller-managed memory; `flags` as for [`recv`].
///
/// # Safety
///
/// Same contract as [`read_at_raw`] (reads the buffer only).
#[inline]
pub unsafe fn send_raw(
    fd: TgtFd,
    ptr: *const u8,
    len: u32,
    flags: i32,
) -> Result<RawOp, UblkError> {
    submit_raw(with_tgt_fd!(fd, |f| opcode::Send::new(f, ptr, len)
        .flags(flags)
        .build()))
}

/// `IORING_RECVSEND_FIXED_BUF` (SQE ioprio bit): `addr`/`len` describe a
/// range inside the registered buffer `buf_index`. Not in the io-uring
/// crate's public API for plain send/recv.
const IORING_RECVSEND_FIXED_BUF: u16 = 1 << 2;
/// `IORING_SEND_ZC_REPORT_USAGE`: the notification CQE reports whether
/// the kernel copied (bit 31 of its result) instead of sending
/// zero-copy.
const SEND_ZC_REPORT_USAGE: u16 = 1 << 3;
/// Notification-CQE result bit set when a "zero-copy" send actually
/// copied (loopback always copies). Not an errno.
const NOTIF_ZC_COPIED: i32 = 1 << 31;

/// Handle to an in-flight zero-copy send.
///
/// ZC sends complete in two CQEs: the send result first (awaited via
/// [`SendZcOp::sent`]), then a notification once the kernel drops its
/// last reference to the pages ([`SendZcOp::into_notif`]). The notif
/// future must be awaited (or the handle deliberately dropped, orphaning
/// the op) before any referenced memory is reused.
pub struct SendZcOp {
    op: MultiOp,
}

impl SendZcOp {
    /// Await the send CQE: bytes accepted into the socket, or a negative
    /// errno. Call once, before [`Self::into_notif`].
    pub async fn sent(&mut self) -> i32 {
        std::future::poll_fn(|cx| self.op.poll_next(cx))
            .await
            // The result CQE always precedes termination; a bare
            // termination means the op was cancelled under teardown.
            .unwrap_or(-libc::ECANCELED)
    }

    /// The notification future gating buffer reuse. Take it even when
    /// the send failed: an errored ZC send may still have pinned pages
    /// and post a notification; if it did not, the future resolves
    /// immediately.
    pub fn into_notif(self) -> ZcNotif {
        ZcNotif { op: self.op }
    }
}

/// Future of a ZC send's notification CQE; resolves to `true` when the
/// kernel reports it copied the data rather than sending zero-copy
/// (always the case on loopback).
pub struct ZcNotif {
    op: MultiOp,
}

impl Future for ZcNotif {
    type Output = bool;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut copied = false;
        while let Some(result) = ready!(self.op.poll_next(cx)) {
            copied = result & NOTIF_ZC_COPIED != 0;
        }
        Poll::Ready(copied)
    }
}

/// Zero-copy send from caller-managed memory (`IORING_OP_SEND_ZC`);
/// completes in two CQEs -- see [`SendZcOp`]. With `buf_index` the data
/// is sent from the ring-registered fixed buffer of that index (`ptr` is
/// then the offset within it, as for [`recv_fixed`]) and the kernel
/// reuses that registration instead of pinning pages per send. `flags`
/// as for [`recv`].
///
/// # Safety
///
/// The memory (or the fixed-buffer slot) must stay valid until the
/// **terminal** CQE -- the notification -- has been reaped, not merely
/// until [`SendZcOp::sent`] resolves.
pub unsafe fn send_zc(
    fd: TgtFd,
    ptr: *const u8,
    len: u32,
    flags: i32,
    buf_index: Option<u16>,
) -> Result<SendZcOp, UblkError> {
    let op = MultiOp::submit(|key| {
        with_tgt_fd!(fd, |f| opcode::SendZc::new(f, ptr, len)
            .buf_index(buf_index)
            .flags(flags)
            .zc_flags(SEND_ZC_REPORT_USAGE)
            .build())
        .user_data(key)
    })?;
    Ok(SendZcOp { op })
}

/// Build an `IORING_OP_URING_CMD` SQE with a 16-byte inline payload
/// (64-byte SQE, queue ring format).
#[inline]
pub(crate) fn uring_cmd16_sqe(file: TgtFd, cmd_op: u32, cmd: [u8; 16]) -> squeue::Entry {
    with_tgt_fd!(file, |fd| opcode::UringCmd16::new(fd, cmd_op)
        .cmd(cmd)
        .build())
}

/// Build an `IORING_OP_URING_CMD` SQE with an 80-byte inline payload
/// (128-byte SQE, control ring format).
pub(crate) fn uring_cmd80_sqe(fd: RawFd, cmd_op: u32, cmd: [u8; 80]) -> squeue::Entry128 {
    opcode::UringCmd80::new(types::Fd(fd), cmd_op)
        .cmd(cmd)
        .build()
}

/// `IORING_OP_URING_CMD` with a 16-byte inline payload on the queue ring
/// — the driver-command primitive for char devices (ublk io commands,
/// nvme passthrough, ...).
///
/// # Safety
///
/// Any memory the command payload references (embedded pointers the
/// driver dereferences) must remain valid until this op's CQE has been
/// reaped — same contract as [`read_at_raw`].
pub unsafe fn uring_cmd16(file: TgtFd, cmd_op: u32, cmd: [u8; 16]) -> Result<RawOp, UblkError> {
    submit_raw(uring_cmd16_sqe(file, cmd_op, cmd))
}

/// `IORING_OP_URING_CMD` with an 80-byte inline payload on the
/// thread-local control ring (128-byte SQEs) — the ublk control-command
/// primitive.
///
/// # Safety
///
/// Same contract as [`uring_cmd16`].
pub unsafe fn uring_cmd80(fd: RawFd, cmd_op: u32, cmd: [u8; 80]) -> Result<RawOp, UblkError> {
    let op = Op::submit_ctrl(
        |key| uring_cmd80_sqe(fd, cmd_op, cmd).user_data(key),
        Resources::None,
    )?;
    Ok(RawOp::new(op))
}

/// As [`uring_cmd80`], with `buf` owned by the op while the command is
/// in flight and handed back on completion — for commands whose payload
/// references caller memory (e.g. the unprivileged-mode dev-path
/// buffer), making them safe under future cancellation.
///
/// # Safety
///
/// Every pointer the command payload references must point into `buf`
/// (whose liveness the op guarantees) or stay valid until the CQE is
/// reaped, as for [`uring_cmd16`].
pub unsafe fn uring_cmd80_buf(
    fd: RawFd,
    cmd_op: u32,
    cmd: [u8; 80],
    buf: Box<[u8]>,
) -> Result<BufOp, UblkError> {
    let op = Op::submit_ctrl(
        |key| uring_cmd80_sqe(fd, cmd_op, cmd).user_data(key),
        Resources::Buffer(buf),
    )?;
    Ok(BufOp { op })
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
    submit_raw(sqe)
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

    /// A connected TCP loopback pair (SEND_ZC does not support AF_UNIX).
    fn socketpair() -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let a = std::net::TcpStream::connect(addr).unwrap();
        let (b, _) = listener.accept().unwrap();
        (a, b)
    }

    /// Zero-copy send: both CQEs (send result + notification) must be
    /// consumed through the two-phase SendZcOp, and the payload must
    /// arrive intact.
    #[test]
    fn test_ops_send_zc() -> Result<(), UblkError> {
        use std::os::fd::AsRawFd;

        let rt = test_runtime()?;
        let (a, b) = socketpair();
        rt.block_on(async {
            let payload = b"zero copy payload".to_vec().into_boxed_slice();
            // SAFETY: `payload` outlives the notification await below.
            let mut op = unsafe {
                send_zc(
                    TgtFd::Raw(a.as_raw_fd()),
                    payload.as_ptr(),
                    payload.len() as u32,
                    0,
                    None,
                )
            }?;
            let sent = op.sent().await;
            assert_eq!(sent as usize, payload.len());
            // AF_UNIX sends always copy; just consume the notification.
            let _copied = op.into_notif().await;

            let (res, rbuf) = recv(
                TgtFd::Raw(b.as_raw_fd()),
                vec![0u8; 64].into_boxed_slice(),
                0,
            )?
            .await;
            assert_eq!(res as usize, payload.len());
            assert_eq!(&rbuf[..res as usize], &payload[..]);
            Ok(())
        })
    }

    /// recv_fixed must land the data in the ring-registered buffer at
    /// the requested offset.
    #[test]
    fn test_ops_recv_fixed() -> Result<(), UblkError> {
        use std::os::fd::AsRawFd;

        let rt = test_runtime()?;
        let (a, b) = socketpair();

        // Register one 4k buffer with the task ring
        let buf = crate::helpers::IoBuf::<u8>::new(4096);
        let iovec = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: 4096,
        };
        crate::io::with_task_io_ring_mut(|ring| {
            // SAFETY: `buf` outlives the ring usage in this test.
            unsafe { ring.submitter().register_buffers(&[iovec]) }.map_err(UblkError::IOError)
        })?;

        rt.block_on(async {
            let msg = b"fixed landing";
            let sent = send(
                TgtFd::Raw(a.as_raw_fd()),
                msg.to_vec().into_boxed_slice(),
                0,
            )?
            .await;
            assert_eq!(sent.0 as usize, msg.len());

            // SAFETY: buffer 0 stays registered until after the await.
            let res = unsafe {
                recv_fixed(
                    TgtFd::Raw(b.as_raw_fd()),
                    0,
                    buf.as_mut_ptr() as u64 + 128,
                    msg.len() as u32,
                    libc::MSG_WAITALL,
                )
            }?
            .await;
            if res == -libc::EINVAL {
                // Registered-buffer recv needs a recent kernel
                println!("skipping recv_fixed test: kernel does not support it");
                return Ok(());
            }
            assert_eq!(res as usize, msg.len());
            assert_eq!(&buf.as_slice()[128..128 + msg.len()], &msg[..]);
            Ok(())
        })
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
