use crate::with_queue_ring_internal;
use crate::with_queue_ring_mut_internal;
use crate::UblkError;
use io_uring::{cqueue, squeue, IoUring};
use slab::Slab;
use std::cell::RefCell;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

struct FutureData {
    waker: Option<Waker>,
    result: Option<i32>,
}

std::thread_local! {
    static MY_SLAB: RefCell<Slab<FutureData>> = RefCell::new(Slab::new());
}

/// User code creates one future with user_data used for submitting
/// uring OP, then future.await returns this uring OP's result.
pub struct UblkUringOpFuture {
    pub user_data: u64,
}

impl UblkUringOpFuture {
    fn get_key(data: u64) -> usize {
        ((data >> 16) & 0xffffffff) as usize
    }
    pub fn new(tgt_io: u64) -> Self {
        MY_SLAB.with(|refcell| {
            let mut map = refcell.borrow_mut();

            let key = map.insert(FutureData {
                waker: None,
                result: None,
            });
            let user_data = ((key as u32) << 16) as u64 | tgt_io;
            log::trace!("uring: new future data {:x}/{:x}", user_data, key);
            UblkUringOpFuture { user_data }
        })
    }

    pub fn new_validate(data: u64) -> Result<Self, UblkError> {
        if Self::get_key(data) != 0 {
            return Err(UblkError::InvalidVal);
        }

        Ok(Self::new(data))
    }
}

impl Future for UblkUringOpFuture {
    type Output = i32;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        MY_SLAB.with(|refcell| {
            let mut map = refcell.borrow_mut();
            let key = Self::get_key(self.user_data);
            match map.get_mut(key) {
                None => {
                    log::trace!("uring: null slab data {:x}/{:x}", self.user_data, key);
                    Poll::Pending
                }
                Some(fd) => match fd.result {
                    Some(result) => {
                        map.remove(key);
                        log::trace!(
                            "uring: uring io ready data {:x}/{:x} ready",
                            self.user_data,
                            key
                        );
                        Poll::Ready(result)
                    }
                    None => {
                        fd.waker = Some(cx.waker().clone());
                        log::trace!(
                            "uring: uring io pending data {:x}/{:x}",
                            self.user_data,
                            key
                        );
                        Poll::Pending
                    }
                },
            }
        })
    }
}

/// Whether any uring op future is still pending on this thread.
pub(crate) fn has_pending_futures() -> bool {
    MY_SLAB.with(|refcell| !refcell.borrow().is_empty())
}

/// Drain `ring`'s completion queue, waking the future behind each CQE.
/// `per_cqe` runs first for every CQE (classification, bookkeeping).
/// Returns the number of CQEs drained. The future slab is borrowed once
/// for the whole batch rather than per CQE.
pub(crate) fn ublk_reap_and_wake<S, F>(ring: &mut IoUring<S>, mut per_cqe: F) -> usize
where
    S: squeue::EntryMarker,
    F: FnMut(&cqueue::Entry),
{
    MY_SLAB.with(|refcell| {
        let mut map = refcell.borrow_mut();
        let mut n = 0;
        while let Some(cqe) = ring.completion().next() {
            per_cqe(&cqe);
            let key = UblkUringOpFuture::get_key(cqe.user_data());
            if let Some(fd) = map.get_mut(key) {
                fd.result = Some(cqe.result());
                if let Some(w) = &fd.waker {
                    w.wake_by_ref();
                }
            }
            n += 1;
        }
        n
    })
}

/// Wakeup the pending task, which will be marked as runnable
/// by the executor, and the task's future poll() will be run
#[inline]
pub fn ublk_wake_task(data: u64, cqe: &cqueue::Entry) {
    MY_SLAB.with(|refcell| {
        let mut map = refcell.borrow_mut();

        log::trace!(
            "ublk_wake_task: data {:x} user_data {:x} result {}",
            data,
            cqe.user_data(),
            cqe.result()
        );
        let key = UblkUringOpFuture::get_key(data);
        if let Some(fd) = map.get_mut(key) {
            fd.result = Some(cqe.result());
            if let Some(w) = &fd.waker {
                w.wake_by_ref();
            }
        }
    })
}

#[inline]
pub(crate) fn __ublk_submit_sqe_async(
    sqe: io_uring::squeue::Entry,
    user_data: u64,
) -> Result<UblkUringOpFuture, UblkError> {
    let f = UblkUringOpFuture::new_validate(user_data)?;
    let sqe = sqe.user_data(f.user_data);

    loop {
        let res = with_queue_ring_mut_internal!(|r: &mut IoUring<squeue::Entry>| unsafe {
            r.submission().push(&sqe)
        });

        let _ = match res {
            Ok(_) => break,
            Err(_) => {
                log::debug!("ublk_submit_sqe: flush and retry");
                with_queue_ring_internal!(|r: &IoUring<squeue::Entry>| r.submit_and_wait(0))
            }
        };
    }

    Ok(f)
}

/// Submit an io_uring submission queue entry asynchronously
///
/// This function submits an io_uring SQE and returns a future that completes
/// when the operation finishes.
///
/// # Arguments
///
/// * `sqe` - The io_uring submission queue entry to submit
/// * `user_data` - User data to associate with this operation. This value is used
///   to identify the operation when the completion queue entry is received.
///
/// # Important: Marking Target I/O Operations
///
/// **When issuing ublk uring_cmd operations in the same io_uring context as the queue's
/// thread-local ring, you MUST set the `UblkUringData::Target` bit in the `user_data` parameter.**
///
/// This is critical for proper operation classification:
/// - `UblkUringData::Target` bit set: Indicates this is a target I/O operation
/// - `UblkUringData::Target` bit NOT set: Indicates this is a ublk I/O command from the driver
///
/// The library uses this bit to distinguish between:
/// 1. **IO commands from ublk driver** - Commands originating from `/dev/ublkbN` that need to be
///    handled by the target implementation
/// 2. **Target IO operations** - IO operations submitted by the target code itself (e.g., reads/writes
///    to backing storage, uring_cmd operations for ublk communication)
///
/// # Example
///
/// ```no_run
/// use libublk::uring_async::ublk_submit_sqe_async;
/// use libublk::UblkUringData;
/// use io_uring::opcode;
///
/// async fn example() -> Result<(), libublk::UblkError> {
///     // When submitting a ublk uring_cmd in the same io_uring context,
///     // mark it as target I/O by setting the Target bit
///     let sqe = opcode::Nop::new().build();
///     let result = ublk_submit_sqe_async(sqe, UblkUringData::Target as u64).await?;
///
///     println!("Operation completed with result: {}", result);
///     Ok(())
/// }
/// ```
///
/// # Returns
///
/// Returns `Ok(i32)` with the operation result on success, or `Err(UblkError)` on failure.
///
/// # Errors
///
/// This function can return errors if:
/// - The io_uring submission queue is full and cannot accept new entries
/// - The user_data validation fails (see `UblkUringOpFuture::new_validate`)
pub async fn ublk_submit_sqe_async(
    sqe: io_uring::squeue::Entry,
    user_data: u64,
) -> Result<i32, UblkError> {
    let f = __ublk_submit_sqe_async(sqe, user_data)?;

    Ok(f.await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::UblkRuntime;
    use io_uring::opcode;
    use std::time::{Duration, Instant};

    fn test_runtime() -> Result<UblkRuntime, UblkError> {
        crate::io::init_task_ring_default(64, 64)?;
        UblkRuntime::new()
    }

    /// Test ublk_submit_sqe_async with NOP operation
    #[test]
    fn test_ublk_submit_sqe_async_nop() -> Result<(), UblkError> {
        let rt = test_runtime()?;
        rt.block_on(async {
            let nop_sqe = opcode::Nop::new().build();
            let result = ublk_submit_sqe_async(nop_sqe, 12345).await?;
            assert_eq!(result, 0); // NOP should return 0
            Ok(())
        })
    }

    /// Test ublk_submit_sqe_async with timeout operation
    #[test]
    fn test_ublk_submit_sqe_async_timeout() -> Result<(), UblkError> {
        let rt = test_runtime()?;
        rt.block_on(async {
            let timeout_spec = io_uring::types::Timespec::new().sec(0).nsec(100_000_000); // 100ms
            let timeout_sqe = opcode::Timeout::new(&timeout_spec as *const _).build();

            let start = Instant::now();
            let result = ublk_submit_sqe_async(timeout_sqe, 54321).await?;
            let elapsed = start.elapsed();

            // Timeout should complete in approximately 100ms
            assert!(elapsed >= Duration::from_millis(90));
            assert!(elapsed <= Duration::from_millis(200));
            assert_eq!(result, -62); // -ETIME
            Ok(())
        })
    }

    /// Test ublk_submit_sqe_async with multiple concurrent operations
    #[test]
    fn test_ublk_submit_sqe_async_concurrent() -> Result<(), UblkError> {
        let rt = test_runtime()?;
        rt.block_on(async {
            let tasks: Vec<_> = (0..5)
                .map(|i| {
                    tokio::task::spawn_local(async move {
                        let user_data = 1000 + i;
                        let nop_sqe = opcode::Nop::new().build();
                        let result = ublk_submit_sqe_async(nop_sqe, user_data).await.unwrap();
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

    /// Test ublk_submit_sqe_async error handling with invalid operation
    #[test]
    fn test_ublk_submit_sqe_async_error_handling() -> Result<(), UblkError> {
        let rt = test_runtime()?;
        rt.block_on(async {
            use io_uring::types::Fd;

            let close_sqe = opcode::Close::new(Fd(-1)).build();
            let result = ublk_submit_sqe_async(close_sqe, 9999).await?;
            // Close with invalid fd should return -EBADF (-9)
            assert_eq!(result, -9);
            Ok(())
        })
    }
}
