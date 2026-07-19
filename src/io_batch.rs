//! Queue-level transport for Linux `UBLK_F_BATCH_IO`.
//!
//! This module owns the generic kernel communication needed by batch ublk
//! queues: preparing IO tags and buffers, maintaining a multishot fetch,
//! recycling provided buffers, and committing groups of results. Target
//! implementations remain responsible for interpreting each fetched tag and
//! performing the actual backend IO.
//!
//! The current transport supports the normal userspace-buffer copy path. It
//! intentionally rejects `UBLK_F_USER_COPY`, `UBLK_F_SUPPORT_ZERO_COPY`,
//! `UBLK_F_AUTO_BUF_REG`, and `UBLK_F_ZONED`; those modes require different
//! batch element layouts and buffer lifetimes.

use std::cell::RefCell;
use std::collections::HashSet;
use std::mem::{size_of, transmute};

use io_uring::{cqueue, opcode, squeue, types};

use crate::helpers::IoBuf;
use crate::io::{with_task_io_ring_mut, RawSqe, UblkIOCtx, UblkQueue};
use crate::{sys, UblkError};

const IORING_URING_CMD_MULTISHOT: u32 = 1 << 1;
const BATCH_USER_DATA_MAGIC: u32 = 0x424b;
const BATCH_FETCH_OP: u32 = 0xf0;
const BATCH_COMMIT_OP: u32 = 0xf1;
const BATCH_PROVIDE_OP: u32 = 0xf2;
const BATCH_PREP_OP: u32 = 0xf3;
const BATCH_SETUP_PROVIDE_OP: u32 = 0xf4;
const BATCH_REMOVE_OP: u32 = 0xf5;
const UNSUPPORTED_BATCH_FLAGS: u64 = sys::UBLK_F_USER_COPY as u64
    | sys::UBLK_F_SUPPORT_ZERO_COPY as u64
    | sys::UBLK_F_AUTO_BUF_REG as u64
    | sys::UBLK_F_ZONED as u64;

std::thread_local! {
    static BATCH_BUFFER_GROUPS: RefCell<HashSet<u16>> = RefCell::new(HashSet::new());
}

/// Configuration for the multishot batch fetch buffer pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkBatchConfig {
    /// Number of provided buffers kept available to the multishot fetch.
    pub fetch_buffer_count: u16,
    /// Maximum number of IO tags returned in one provided buffer.
    pub tags_per_fetch_buffer: u16,
    /// io_uring provided-buffer group used by the batch fetch.
    ///
    /// This group must be used exclusively by this batch queue on its
    /// thread-local io_uring. Target-specific operations must not provide
    /// buffers to the same group while the batch queue exists.
    pub buffer_group: u16,
}

impl Default for UblkBatchConfig {
    fn default() -> Self {
        Self {
            fetch_buffer_count: 8,
            tags_per_fetch_buffer: 128,
            buffer_group: 0x7000,
        }
    }
}

/// Result for one completed ublk request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkBatchCompletion {
    /// Queue-wide IO tag returned by [`UblkBatchEvent::Requests`].
    pub tag: u16,
    /// Number of bytes completed or a negative errno.
    pub result: i32,
}

impl UblkBatchCompletion {
    /// Construct a completion for the normal userspace-buffer path.
    pub fn new(tag: u16, result: i32) -> Self {
        Self { tag, result }
    }
}

/// A CQE consumed by [`UblkBatchQueue::handle_cqe`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UblkBatchEvent {
    /// Newly fetched request tags ready for target-specific processing.
    Requests(Vec<u16>),
    /// Every element from the last submitted completion batch was committed.
    CommitComplete { completions: usize },
    /// A fetch command failed and was automatically rearmed.
    FetchError { result: i32 },
    /// The multishot fetch terminated with the supplied result.
    FetchStopped { result: i32 },
    /// An internal provided-buffer completion requiring no target action.
    Internal,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BatchElement {
    tag: u16,
    buffer_index: u16,
    result: i32,
    buffer_address: u64,
}

struct InflightCommit {
    elements: Box<[BatchElement]>,
    offset: usize,
}

impl InflightCommit {
    fn remaining(&self) -> &[BatchElement] {
        &self.elements[self.offset..]
    }

    fn advance(&mut self, result: i32) -> Result<bool, UblkError> {
        let element_bytes = size_of::<BatchElement>();
        if result <= 0 || result as usize % element_bytes != 0 {
            return Err(UblkError::OtherError(if result < 0 {
                result
            } else {
                -libc::EIO
            }));
        }

        let completed = result as usize / element_bytes;
        if completed > self.elements.len() - self.offset {
            return Err(UblkError::OtherError(-libc::EIO));
        }
        self.offset += completed;
        Ok(self.offset == self.elements.len())
    }
}

struct BufferRegistrationGuard<'queue, 'dev> {
    queue: &'queue UblkQueue<'dev>,
    completed: bool,
}

impl BufferRegistrationGuard<'_, '_> {
    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for BufferRegistrationGuard<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.queue.dev.notify_buffer_registration_complete(true);
        }
    }
}

struct BufferGroupRegistration {
    group: u16,
    release_on_drop: bool,
}

impl BufferGroupRegistration {
    fn claim(group: u16) -> Result<Self, UblkError> {
        let claimed = BATCH_BUFFER_GROUPS.with(|groups| groups.borrow_mut().insert(group));
        if !claimed {
            return Err(UblkError::OtherError(-libc::EADDRINUSE));
        }
        Ok(Self {
            group,
            release_on_drop: true,
        })
    }

    fn retain_until_queue_shutdown(&mut self) {
        self.release_on_drop = false;
    }
}

impl Drop for BufferGroupRegistration {
    fn drop(&mut self) {
        if self.release_on_drop {
            release_buffer_group(self.group);
        }
    }
}

/// Generic transport state for one `UBLK_F_BATCH_IO` queue.
///
/// Create the [`UblkQueue`] first, then construct this transport with the
/// queue's IO buffers. The target can continue using
/// [`UblkQueue::flush_and_wake_io_tasks`] and pass every CQE to
/// [`handle_cqe`](Self::handle_cqe). A `None` return means that the CQE does
/// not belong to this transport and must be handled by the target.
///
/// Before dropping the transport, stop the ublk queue, wait for the fetch to
/// terminate, and complete [`begin_shutdown`](Self::begin_shutdown). Dropping
/// it earlier deliberately retains allocations that the kernel may still
/// reference.
///
/// # Example
///
/// ```no_run
/// use libublk::io::{
///     UblkBatchCompletion, UblkBatchConfig, UblkBatchEvent, UblkBatchQueue,
///     UblkDev, UblkQueue,
/// };
/// use libublk::UblkError;
///
/// fn handle_queue(qid: u16, dev: &UblkDev) -> Result<(), UblkError> {
///     let queue = UblkQueue::new(qid, dev)?;
///     let buffers = dev.alloc_queue_io_bufs();
///     let mut batch = UblkBatchQueue::new(&queue, buffers, UblkBatchConfig::default())?;
///     let mut pending = Vec::new();
///
///     loop {
///         let mut batch_error = None;
///         queue.flush_and_wake_io_tasks(
///             |_user_data, cqe, _is_last| match batch.handle_cqe(cqe) {
///                 Ok(Some(UblkBatchEvent::Requests(tags))) => {
///                     pending.extend(tags.into_iter().map(|tag| {
///                         let iod = queue.get_iod(tag);
///                         let bytes = (iod.nr_sectors << 9) as i32;
///                         let result = match iod.op_flags & 0xff {
///                             libublk::sys::UBLK_IO_OP_READ => {
///                                 batch.get_io_buf_mut(tag).unwrap().zero_buf();
///                                 bytes
///                             }
///                             libublk::sys::UBLK_IO_OP_WRITE => bytes,
///                             libublk::sys::UBLK_IO_OP_FLUSH => 0,
///                             _ => -libc::EOPNOTSUPP,
///                         };
///                         UblkBatchCompletion::new(tag, result)
///                     }));
///                 }
///                 Ok(Some(_)) => {}
///                 Ok(None) => {
///                     // Handle target-specific CQEs here.
///                 }
///                 Err(error) => batch_error = Some(error),
///             },
///             1,
///         )?;
///         if let Some(error) = batch_error {
///             return Err(error);
///         }
///         if !batch.has_inflight_commit() && !pending.is_empty() {
///             batch.submit_io_completions(pending.drain(..))?;
///         }
///         if batch.is_fetch_stopped() && !batch.has_inflight_commit() && pending.is_empty() {
///             break;
///         }
///     }
///     batch.begin_shutdown()?;
///     while !batch.is_shutdown_complete() {
///         let mut batch_error = None;
///         queue.flush_and_wake_io_tasks(
///             |_user_data, cqe, _is_last| {
///                 if let Err(error) = batch.handle_cqe(cqe) {
///                     batch_error = Some(error);
///                 }
///             },
///             1,
///         )?;
///         if let Some(error) = batch_error {
///             return Err(error);
///         }
///     }
///     Ok(())
/// }
/// ```
pub struct UblkBatchQueue<'queue, 'dev> {
    queue: &'queue UblkQueue<'dev>,
    buffers: Vec<IoBuf<u8>>,
    fetch_buffers: Vec<Box<[u16]>>,
    config: UblkBatchConfig,
    inflight_commit: Option<InflightCommit>,
    owned_tags: Vec<bool>,
    fetch_stopped: bool,
    remove_remaining: u16,
    shutdown_started: bool,
    shutdown_complete: bool,
}

impl<'queue, 'dev> UblkBatchQueue<'queue, 'dev> {
    /// Prepare all queue tags and start one multishot batch fetch.
    ///
    /// The batch queue owns `buffers` because their addresses are supplied to
    /// the kernel and must remain valid while batch IO is active.
    ///
    /// # Arguments:
    ///
    /// * `queue`: ublk queue created for a device with `UBLK_F_BATCH_IO`
    /// * `buffers`: one userspace IO buffer for every queue tag
    /// * `config`: multishot fetch buffer pool configuration
    ///
    /// # Returns:
    ///
    /// The initialized batch queue, or [`UblkError`] if validation or kernel
    /// setup fails.
    ///
    /// # Errors:
    ///
    /// Returns `EOPNOTSUPP` if batch IO is disabled or the device uses an IO
    /// buffer layout not supported by this transport. Returns
    /// [`UblkError::InvalidVal`] if the buffer count does not match the queue
    /// depth, an IO buffer is smaller than `max_io_buf_bytes`, or the fetch
    /// buffer configuration is empty. Returns `EADDRINUSE` if another batch
    /// queue on the same thread-local io_uring already owns
    /// `config.buffer_group`.
    pub fn new(
        queue: &'queue UblkQueue<'dev>,
        buffers: Vec<IoBuf<u8>>,
        config: UblkBatchConfig,
    ) -> Result<Self, UblkError> {
        if queue.dev.dev_info.flags & sys::UBLK_F_BATCH_IO as u64 == 0 {
            return Err(UblkError::OtherError(-libc::EOPNOTSUPP));
        }
        let mut registration = BufferRegistrationGuard {
            queue,
            completed: false,
        };
        Self::validate(queue, &buffers, config)?;
        let mut group_registration = BufferGroupRegistration::claim(config.buffer_group)?;

        Self::prepare_tags(queue, &buffers)?;
        for (tag, buffer) in buffers.iter().enumerate() {
            queue.register_io_buf_internal(tag as u16, buffer);
        }

        let mut fetch_buffers = (0..config.fetch_buffer_count)
            .map(|_| vec![0_u16; config.tags_per_fetch_buffer as usize].into_boxed_slice())
            .collect::<Vec<_>>();
        for (buffer_id, buffer) in fetch_buffers.iter_mut().enumerate() {
            if let Err(error) = Self::provide_fetch_buffer_sync(
                queue,
                config.buffer_group,
                buffer_id as u16,
                buffer,
            ) {
                std::mem::forget(buffers);
                std::mem::forget(fetch_buffers);
                return Err(error);
            }
            if buffer_id == 0 {
                // From this point the ring may retain this group even if
                // construction subsequently fails. Do not permit a new batch
                // queue to reuse it until the ring itself is torn down.
                group_registration.retain_until_queue_shutdown();
            }
        }
        if let Err(error) = Self::submit_fetch(queue, config) {
            std::mem::forget(buffers);
            std::mem::forget(fetch_buffers);
            return Err(error);
        }
        queue
            .dev
            .notify_buffer_registration_complete(queue.is_mlock_failed());
        registration.complete();

        Ok(Self {
            queue,
            buffers,
            fetch_buffers,
            config,
            inflight_commit: None,
            owned_tags: vec![false; queue.get_depth() as usize],
            fetch_stopped: false,
            remove_remaining: config.fetch_buffer_count,
            shutdown_started: false,
            shutdown_complete: false,
        })
    }

    /// Return the underlying ublk queue.
    #[inline(always)]
    pub fn get_queue(&self) -> &UblkQueue<'dev> {
        self.queue
    }

    /// Return the userspace IO buffer for a currently fetched `tag`.
    #[inline(always)]
    pub fn get_io_buf(&self, tag: u16) -> Option<&IoBuf<u8>> {
        self.owned_tags
            .get(tag as usize)
            .copied()
            .filter(|owned| *owned)
            .and_then(|_| self.buffers.get(tag as usize))
    }

    /// Return the mutable userspace IO buffer for a currently fetched `tag`.
    ///
    /// Target code can use this method to fill the buffer before completing a
    /// READ request.
    #[inline(always)]
    pub fn get_io_buf_mut(&mut self, tag: u16) -> Option<&mut IoBuf<u8>> {
        self.owned_tags
            .get(tag as usize)
            .copied()
            .filter(|owned| *owned)
            .and_then(|_| self.buffers.get_mut(tag as usize))
    }

    /// Return whether a completion batch is awaiting kernel acknowledgement.
    #[inline(always)]
    pub fn has_inflight_commit(&self) -> bool {
        self.inflight_commit.is_some()
    }

    /// Return whether fetching permanently stopped with `UBLK_IO_RES_ABORT`.
    #[inline(always)]
    pub fn is_fetch_stopped(&self) -> bool {
        self.fetch_stopped
    }

    /// Start removing the provided-buffer group from io_uring.
    ///
    /// Call this after the multishot fetch has stopped and all completion
    /// batches have finished. Continue passing CQEs to
    /// [`handle_cqe`](Self::handle_cqe) until
    /// [`is_shutdown_complete`](Self::is_shutdown_complete) returns true.
    ///
    /// # Returns:
    ///
    /// `Ok(())` when buffer removal is queued or was already completed.
    ///
    /// # Errors:
    ///
    /// Returns `EBUSY` until the driver has aborted the fetch during queue
    /// shutdown, or while a completion batch is still active.
    pub fn begin_shutdown(&mut self) -> Result<(), UblkError> {
        if self.shutdown_complete || self.shutdown_started {
            return Ok(());
        }
        if !self.fetch_stopped || !self.queue.is_stopping() || self.inflight_commit.is_some() {
            return Err(UblkError::OtherError(-libc::EBUSY));
        }
        self.shutdown_started = true;
        if let Err(error) = self.submit_remove_buffers() {
            self.shutdown_started = false;
            return Err(error);
        }
        Ok(())
    }

    /// Return whether all kernel references to the owned buffers were removed.
    #[inline(always)]
    pub fn is_shutdown_complete(&self) -> bool {
        self.shutdown_complete
    }

    /// Submit a group of target results to the kernel.
    ///
    /// Only one completion group may be in flight. Partial kernel commits are
    /// resubmitted automatically by [`handle_cqe`](Self::handle_cqe).
    ///
    /// # Arguments:
    ///
    /// * `completions`: target IO results to commit to the ublk driver
    ///
    /// # Returns:
    ///
    /// `Ok(())` when the completion command is queued successfully.
    ///
    /// # Errors:
    ///
    /// Returns `EBUSY` while another completion batch is in flight. Returns
    /// [`UblkError::InvalidVal`] for a tag that was not fetched, a duplicate
    /// tag, or an oversized group.
    pub fn submit_io_completions<I>(&mut self, completions: I) -> Result<(), UblkError>
    where
        I: IntoIterator<Item = UblkBatchCompletion>,
    {
        if self.inflight_commit.is_some() {
            return Err(UblkError::OtherError(-libc::EBUSY));
        }

        let mut elements = Vec::new();
        let mut seen = vec![false; self.buffers.len()];
        for completion in completions {
            let tag = completion.tag as usize;
            if !self.owned_tags.get(tag).copied().unwrap_or(false) || seen[tag] {
                return Err(UblkError::InvalidVal);
            }
            let buffer = self.buffers.get(tag).ok_or(UblkError::InvalidVal)?;
            seen[tag] = true;
            elements.push(BatchElement {
                tag: completion.tag,
                buffer_index: 0,
                result: completion.result,
                buffer_address: buffer.as_ptr() as u64,
            });
        }
        if elements.is_empty() {
            return Ok(());
        }
        if elements.len() > u16::MAX as usize {
            return Err(UblkError::InvalidVal);
        }
        for element in &elements {
            self.owned_tags[element.tag as usize] = false;
        }

        self.inflight_commit = Some(InflightCommit {
            elements: elements.into_boxed_slice(),
            offset: 0,
        });
        if let Err(error) = self.submit_inflight_commit() {
            if let Some(commit) = self.inflight_commit.as_ref() {
                for element in commit.elements.iter() {
                    self.owned_tags[element.tag as usize] = true;
                }
            }
            self.inflight_commit = None;
            return Err(error);
        }
        Ok(())
    }

    /// Consume one CQE if it belongs to the batch transport.
    ///
    /// Every CQE reaped from [`UblkQueue::flush_and_wake_io_tasks`] should be
    /// passed to this method before target-specific handling. Fetch buffers are
    /// recycled and non-terminal multishot fetches are rearmed automatically.
    ///
    /// # Arguments:
    ///
    /// * `cqe`: completion queue entry reaped from the queue's io_uring
    ///
    /// # Returns:
    ///
    /// Returns one [`UblkBatchEvent`] for a consumed batch CQE. Returns
    /// `Ok(None)` when the CQE belongs to target-specific IO and has not been
    /// consumed.
    ///
    /// # Errors:
    ///
    /// Returns an error for malformed kernel results or if recycling a fetch
    /// buffer, rearming a fetch, or resubmitting a partial commit fails.
    pub fn handle_cqe(&mut self, cqe: &cqueue::Entry) -> Result<Option<UblkBatchEvent>, UblkError> {
        let qid = self.queue.get_qid();
        match cqe.user_data() {
            value if value == batch_user_data(BATCH_FETCH_OP, qid) => {
                self.handle_fetch_cqe(cqe).map(Some)
            }
            value if value == batch_user_data(BATCH_COMMIT_OP, qid) => {
                self.handle_commit_cqe(cqe.result()).map(Some)
            }
            value if value == batch_user_data(BATCH_PROVIDE_OP, qid) => {
                check_zero_result(cqe.result())?;
                Ok(Some(UblkBatchEvent::Internal))
            }
            value if value == batch_user_data(BATCH_REMOVE_OP, qid) => {
                self.handle_remove_cqe(cqe.result()).map(Some)
            }
            _ => Ok(None),
        }
    }

    fn validate(
        queue: &UblkQueue<'_>,
        buffers: &[IoBuf<u8>],
        config: UblkBatchConfig,
    ) -> Result<(), UblkError> {
        let flags = queue.dev.dev_info.flags;
        if flags & UNSUPPORTED_BATCH_FLAGS != 0 {
            return Err(UblkError::OtherError(-libc::EOPNOTSUPP));
        }
        if buffers.len() != queue.get_depth() as usize
            || config.fetch_buffer_count == 0
            || config.tags_per_fetch_buffer == 0
        {
            return Err(UblkError::InvalidVal);
        }
        let required_bytes = queue.dev.dev_info.max_io_buf_bytes as usize;
        if buffers
            .iter()
            .any(|buffer| buffer.as_ptr().is_null() || buffer.len() < required_bytes)
        {
            return Err(UblkError::InvalidVal);
        }
        Ok(())
    }

    fn prepare_tags(queue: &UblkQueue<'_>, buffers: &[IoBuf<u8>]) -> Result<(), UblkError> {
        let elements = buffers
            .iter()
            .enumerate()
            .map(|(tag, buffer)| BatchElement {
                tag: tag as u16,
                buffer_address: buffer.as_ptr() as u64,
                ..Default::default()
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let entry = batch_command(
            sys::UBLK_U_IO_PREP_IO_CMDS,
            batch_header(queue.get_qid(), elements.len()),
            elements.as_ptr() as u64,
            batch_user_data(BATCH_PREP_OP, queue.get_qid()),
        );
        let result = submit_and_wait(
            queue,
            entry,
            batch_user_data(BATCH_PREP_OP, queue.get_qid()),
        )?;
        check_zero_result(result)
    }

    fn submit_inflight_commit(&self) -> Result<(), UblkError> {
        let commit = self.inflight_commit.as_ref().ok_or(UblkError::InvalidVal)?;
        let remaining = commit.remaining();
        let entry = batch_command(
            sys::UBLK_U_IO_COMMIT_IO_CMDS,
            batch_header(self.queue.get_qid(), remaining.len()),
            remaining.as_ptr() as u64,
            batch_user_data(BATCH_COMMIT_OP, self.queue.get_qid()),
        );
        self.queue.ublk_submit_sqe_sync(entry)
    }

    fn handle_commit_cqe(&mut self, result: i32) -> Result<UblkBatchEvent, UblkError> {
        let commit = self.inflight_commit.as_mut().ok_or(UblkError::InvalidVal)?;
        let total = commit.elements.len();
        if commit.advance(result)? {
            self.inflight_commit = None;
            Ok(UblkBatchEvent::CommitComplete { completions: total })
        } else {
            self.submit_inflight_commit()?;
            Ok(UblkBatchEvent::Internal)
        }
    }

    fn handle_fetch_cqe(&mut self, cqe: &cqueue::Entry) -> Result<UblkBatchEvent, UblkError> {
        let result = cqe.result();
        let flags = cqe.flags();
        if result < 0 {
            if result == sys::UBLK_IO_RES_ABORT {
                log::debug!(
                    "batch queue {} fetch stopped with {}",
                    self.queue.get_qid(),
                    result
                );
                self.fetch_stopped = true;
                self.queue.mark_stopping();
                return Ok(UblkBatchEvent::FetchStopped { result });
            }

            log::debug!(
                "batch queue {} fetch failed with {}, rearming",
                self.queue.get_qid(),
                result
            );
            Self::submit_fetch(self.queue, self.config)?;
            return Ok(UblkBatchEvent::FetchError { result });
        }

        let buffer_id = cqueue::buffer_select(flags).ok_or(UblkError::InvalidVal)?;
        let buffer = self
            .fetch_buffers
            .get_mut(buffer_id as usize)
            .ok_or(UblkError::InvalidVal)?;
        let bytes = result as usize;
        if bytes > buffer.len() * size_of::<u16>() || bytes % size_of::<u16>() != 0 {
            return Err(UblkError::OtherError(-libc::EIO));
        }
        let tags = buffer[..bytes / size_of::<u16>()].to_vec();
        claim_tags(&mut self.owned_tags, &tags)?;
        Self::provide_fetch_buffer(self.queue, self.config.buffer_group, buffer_id, buffer)?;

        if !cqueue::more(flags) {
            Self::submit_fetch(self.queue, self.config)?;
        }
        Ok(UblkBatchEvent::Requests(tags))
    }

    fn submit_remove_buffers(&self) -> Result<(), UblkError> {
        if self.remove_remaining == 0 {
            return Ok(());
        }
        let entry = opcode::RemoveBuffers::new(self.remove_remaining, self.config.buffer_group)
            .build()
            .user_data(batch_user_data(BATCH_REMOVE_OP, self.queue.get_qid()));
        self.queue.ublk_submit_sqe_sync(entry)
    }

    fn handle_remove_cqe(&mut self, result: i32) -> Result<UblkBatchEvent, UblkError> {
        if !self.shutdown_started || result <= 0 || result as u32 > self.remove_remaining as u32 {
            return Err(UblkError::OtherError(if result < 0 {
                result
            } else {
                -libc::EIO
            }));
        }
        self.remove_remaining -= result as u16;
        if self.remove_remaining == 0 {
            self.shutdown_complete = true;
        } else if let Err(error) = self.submit_remove_buffers() {
            self.shutdown_started = false;
            return Err(error);
        }
        Ok(UblkBatchEvent::Internal)
    }

    fn submit_fetch(queue: &UblkQueue<'_>, config: UblkBatchConfig) -> Result<(), UblkError> {
        let header = batch_fetch_header(queue.get_qid());
        let mut entry = batch_command(
            sys::UBLK_U_IO_FETCH_IO_CMDS,
            header,
            0,
            batch_user_data(BATCH_FETCH_OP, queue.get_qid()),
        )
        .flags(squeue::Flags::BUFFER_SELECT);
        unsafe {
            let raw: &mut RawSqe = transmute(&mut entry);
            raw.rw_flags |= IORING_URING_CMD_MULTISHOT;
            raw.buf_index = config.buffer_group;
        }
        queue.ublk_submit_sqe_sync(entry)
    }

    fn provide_fetch_buffer_sync(
        queue: &UblkQueue<'_>,
        group: u16,
        buffer_id: u16,
        buffer: &mut [u16],
    ) -> Result<(), UblkError> {
        let result = submit_and_wait(
            queue,
            provide_buffer_entry(
                group,
                buffer_id,
                buffer,
                batch_user_data(BATCH_SETUP_PROVIDE_OP, queue.get_qid()),
            ),
            batch_user_data(BATCH_SETUP_PROVIDE_OP, queue.get_qid()),
        )?;
        check_zero_result(result)
    }

    fn provide_fetch_buffer(
        queue: &UblkQueue<'_>,
        group: u16,
        buffer_id: u16,
        buffer: &mut [u16],
    ) -> Result<(), UblkError> {
        queue.ublk_submit_sqe_sync(provide_buffer_entry(
            group,
            buffer_id,
            buffer,
            batch_user_data(BATCH_PROVIDE_OP, queue.get_qid()),
        ))
    }
}

impl Drop for UblkBatchQueue<'_, '_> {
    fn drop(&mut self) {
        if self.shutdown_complete {
            release_buffer_group(self.config.buffer_group);
            return;
        }

        log::warn!(
            "batch queue {} dropped before shutdown completed; retaining kernel-referenced buffers",
            self.queue.get_qid()
        );
        std::mem::forget(std::mem::take(&mut self.buffers));
        std::mem::forget(std::mem::take(&mut self.fetch_buffers));
        if let Some(commit) = self.inflight_commit.take() {
            std::mem::forget(commit);
        }
    }
}

fn batch_header(qid: u16, elements: usize) -> sys::ublk_batch_io {
    sys::ublk_batch_io {
        q_id: qid,
        flags: sys::UBLK_BATCH_F_HAS_BUF_ADDR as u16,
        nr_elem: elements as u16,
        elem_bytes: size_of::<BatchElement>() as u8,
        reserved: 0,
        reserved2: 0,
    }
}

fn batch_fetch_header(qid: u16) -> sys::ublk_batch_io {
    sys::ublk_batch_io {
        q_id: qid,
        flags: 0,
        nr_elem: 0,
        elem_bytes: size_of::<u16>() as u8,
        reserved: 0,
        reserved2: 0,
    }
}

fn batch_user_data(operation: u32, qid: u16) -> u64 {
    UblkIOCtx::build_user_data(qid, operation, BATCH_USER_DATA_MAGIC, true)
}

fn release_buffer_group(group: u16) {
    BATCH_BUFFER_GROUPS.with(|groups| {
        groups.borrow_mut().remove(&group);
    });
}

fn batch_command(
    command: u32,
    header: sys::ublk_batch_io,
    address: u64,
    user_data: u64,
) -> squeue::Entry {
    opcode::UringCmd16::new(types::Fixed(0), command)
        .cmd(unsafe { transmute::<sys::ublk_batch_io, [u8; 16]>(header) })
        .addr(Some(address))
        .build()
        .user_data(user_data)
}

fn provide_buffer_entry(
    group: u16,
    buffer_id: u16,
    buffer: &mut [u16],
    user_data: u64,
) -> squeue::Entry {
    opcode::ProvideBuffers::new(
        buffer.as_mut_ptr().cast::<u8>(),
        size_of_val(buffer) as i32,
        1,
        group,
        buffer_id,
    )
    .build()
    .user_data(user_data)
}

fn check_zero_result(result: i32) -> Result<(), UblkError> {
    match result {
        0 => Ok(()),
        result if result < 0 => Err(UblkError::OtherError(result)),
        _ => Err(UblkError::OtherError(-libc::EIO)),
    }
}

fn claim_tags(owned_tags: &mut [bool], tags: &[u16]) -> Result<(), UblkError> {
    let mut seen = vec![false; owned_tags.len()];
    for tag in tags {
        let tag = *tag as usize;
        if owned_tags.get(tag).copied().unwrap_or(true) || seen[tag] {
            return Err(UblkError::OtherError(-libc::EIO));
        }
        seen[tag] = true;
    }
    for tag in tags {
        owned_tags[*tag as usize] = true;
    }
    Ok(())
}

fn submit_and_wait(
    queue: &UblkQueue<'_>,
    entry: squeue::Entry,
    expected_user_data: u64,
) -> Result<i32, UblkError> {
    let ring_is_clean = with_task_io_ring_mut(|ring| {
        let submission_is_empty = ring.submission().is_empty();
        let completion_is_empty = ring.completion().is_empty();
        submission_is_empty && completion_is_empty
    });
    if !ring_is_clean {
        return Err(UblkError::OtherError(-libc::EBUSY));
    }
    queue.ublk_submit_sqe_sync(entry)?;
    with_task_io_ring_mut(|ring| {
        ring.submit_and_wait(1).map_err(UblkError::IOError)?;
        ring.completion()
            .next()
            .ok_or(UblkError::InvalidVal)
            .and_then(|cqe| {
                if cqe.user_data() == expected_user_data {
                    Ok(cqe.result())
                } else {
                    Err(UblkError::OtherError(-libc::EIO))
                }
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_element_matches_uapi_layout() {
        assert_eq!(size_of::<BatchElement>(), 16);
        assert_eq!(std::mem::align_of::<BatchElement>(), 8);
        assert_eq!(std::mem::offset_of!(BatchElement, result), 4);
        assert_eq!(std::mem::offset_of!(BatchElement, buffer_address), 8);
    }

    #[test]
    fn batch_header_describes_buffer_address_elements() {
        let header = batch_header(7, 32);
        assert_eq!(header.q_id, 7);
        assert_eq!(header.nr_elem, 32);
        assert_eq!(header.elem_bytes as usize, size_of::<BatchElement>());
        assert_eq!(header.flags, sys::UBLK_BATCH_F_HAS_BUF_ADDR as u16);
    }

    #[test]
    fn fetch_header_describes_u16_tags() {
        let header = batch_fetch_header(5);
        assert_eq!(header.q_id, 5);
        assert_eq!(header.nr_elem, 0);
        assert_eq!(header.flags, 0);
        assert_eq!(header.elem_bytes as usize, size_of::<u16>());
    }

    #[test]
    fn partial_commit_advances_by_element_bytes() {
        let mut commit = InflightCommit {
            elements: vec![BatchElement::default(); 3].into_boxed_slice(),
            offset: 0,
        };
        assert!(!commit.advance(size_of::<BatchElement>() as i32).unwrap());
        assert_eq!(commit.remaining().len(), 2);
        assert!(commit
            .advance((2 * size_of::<BatchElement>()) as i32)
            .unwrap());
    }

    #[test]
    fn partial_commit_rejects_invalid_byte_count() {
        let mut commit = InflightCommit {
            elements: vec![BatchElement::default()].into_boxed_slice(),
            offset: 0,
        };
        assert!(commit.advance(1).is_err());
        assert!(commit
            .advance((2 * size_of::<BatchElement>()) as i32)
            .is_err());
    }

    #[test]
    fn batch_user_data_values_are_target_operations_and_distinct() {
        let target = crate::UblkUringData::Target as u64;
        let fetch = batch_user_data(BATCH_FETCH_OP, 3);
        let commit = batch_user_data(BATCH_COMMIT_OP, 3);
        let provide = batch_user_data(BATCH_PROVIDE_OP, 3);
        assert_ne!(fetch & target, 0);
        assert_ne!(commit & target, 0);
        assert_ne!(provide & target, 0);
        assert_ne!(fetch, commit);
        assert_ne!(commit, provide);
        assert_ne!(fetch, batch_user_data(BATCH_FETCH_OP, 4));
        assert_eq!(UblkIOCtx::user_data_to_tag(fetch), 3);
        assert_eq!(UblkIOCtx::user_data_to_op(fetch), BATCH_FETCH_OP);
    }

    #[test]
    fn buffer_groups_are_exclusive_within_a_thread_ring() {
        let group = 0x7ffe;
        let first = BufferGroupRegistration::claim(group).unwrap();
        assert!(BufferGroupRegistration::claim(group).is_err());
        drop(first);
        assert!(BufferGroupRegistration::claim(group).is_ok());
    }

    #[test]
    fn claim_tags_does_not_partially_update_on_error() {
        let mut owned_tags = vec![false; 4];
        assert!(claim_tags(&mut owned_tags, &[1, 1]).is_err());
        assert_eq!(owned_tags, vec![false; 4]);

        assert!(claim_tags(&mut owned_tags, &[2, 4]).is_err());
        assert_eq!(owned_tags, vec![false; 4]);

        claim_tags(&mut owned_tags, &[1, 3]).unwrap();
        assert_eq!(owned_tags, vec![false, true, false, true]);
    }

    #[test]
    fn zero_result_check_rejects_errors_and_unexpected_counts() {
        assert!(check_zero_result(0).is_ok());
        assert!(check_zero_result(-libc::ENOBUFS).is_err());
        assert!(check_zero_result(1).is_err());
    }

    #[test]
    fn unsupported_buffer_layouts_are_rejected() {
        assert_ne!(UNSUPPORTED_BATCH_FLAGS & sys::UBLK_F_USER_COPY as u64, 0);
        assert_ne!(
            UNSUPPORTED_BATCH_FLAGS & sys::UBLK_F_SUPPORT_ZERO_COPY as u64,
            0
        );
        assert_ne!(UNSUPPORTED_BATCH_FLAGS & sys::UBLK_F_AUTO_BUF_REG as u64, 0);
        assert_ne!(UNSUPPORTED_BATCH_FLAGS & sys::UBLK_F_ZONED as u64, 0);
    }
}
