//! Queue-level transport for Linux `UBLK_F_BATCH_IO`.
//!
//! This module owns the generic kernel communication needed by batch ublk
//! queues: preparing IO tags and buffers, maintaining a multishot fetch,
//! recycling provided buffers, and committing groups of results. Target
//! implementations remain responsible for interpreting each fetched tag and
//! performing the actual backend IO.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::mem::{size_of, size_of_val, transmute};

use io_uring::{cqueue, opcode, squeue, types};

use crate::helpers::IoBuf;
use crate::io::{defer_queue_cqe, with_task_io_ring_mut, RawSqe, UblkIOCtx, UblkQueue};
use crate::{sys, UblkError};

const IORING_URING_CMD_MULTISHOT: u32 = 1 << 1;
// This user_data encoding is local to the batch transport and is not
// coordinated library-wide. Other users on the same ring must avoid it.
const BATCH_USER_DATA_MAGIC: u64 = 0x424b;
const BATCH_USER_DATA_ID_SHIFT: u32 = 24;
const BATCH_USER_DATA_MAGIC_SHIFT: u32 = 40;
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

/// Configuration for the multishot batch fetch and commit pools.
///
/// The default keeps eight provided fetch buffers, two fetch commands, and two
/// commit batches in flight, with space for 128 tags per fetch buffer. Counts
/// must be nonzero, and the fetch-command count cannot exceed the fetch-buffer
/// count. [`UblkBatchQueue::new`] validates these relationships.
///
/// The default fetch buffer group is `0x7000`, an arbitrary high-numbered group
/// rather than an io_uring-reserved value. A batch queue must own its group
/// exclusively on the thread-local io_uring, so callers must choose a different
/// group when target-specific operations on the same ring already use it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkBatchConfig {
    fetch_buffer_count: u16,
    fetch_command_count: u16,
    max_inflight_commits: u16,
    tags_per_fetch_buffer: u16,
    fetch_buffer_group: u16,
}

impl UblkBatchConfig {
    /// Construct the default batch queue configuration.
    pub const fn new() -> Self {
        Self {
            fetch_buffer_count: 8,
            fetch_command_count: 2,
            max_inflight_commits: 2,
            tags_per_fetch_buffer: 128,
            fetch_buffer_group: 0x7000,
        }
    }

    /// Set the nonzero number of provided fetch buffers.
    #[must_use]
    pub const fn with_fetch_buffer_count(mut self, count: u16) -> Self {
        self.fetch_buffer_count = count;
        self
    }

    /// Set the nonzero number of multishot fetch commands kept in flight.
    ///
    /// This cannot exceed [`fetch_buffer_count`](Self::fetch_buffer_count).
    #[must_use]
    pub const fn with_fetch_command_count(mut self, count: u16) -> Self {
        self.fetch_command_count = count;
        self
    }

    /// Set the nonzero maximum number of completion batches kept in flight.
    #[must_use]
    pub const fn with_max_inflight_commits(mut self, count: u16) -> Self {
        self.max_inflight_commits = count;
        self
    }

    /// Set the nonzero maximum number of tags returned in one fetch buffer.
    #[must_use]
    pub const fn with_tags_per_fetch_buffer(mut self, count: u16) -> Self {
        self.tags_per_fetch_buffer = count;
        self
    }

    /// Set the io_uring provided-buffer group used by batch fetches.
    #[must_use]
    pub const fn with_fetch_buffer_group(mut self, group: u16) -> Self {
        self.fetch_buffer_group = group;
        self
    }

    /// Return the number of provided fetch buffers.
    pub const fn fetch_buffer_count(&self) -> u16 {
        self.fetch_buffer_count
    }

    /// Return the number of multishot fetch commands kept in flight.
    pub const fn fetch_command_count(&self) -> u16 {
        self.fetch_command_count
    }

    /// Return the maximum number of completion batches kept in flight.
    pub const fn max_inflight_commits(&self) -> u16 {
        self.max_inflight_commits
    }

    /// Return the maximum number of tags returned in one fetch buffer.
    pub const fn tags_per_fetch_buffer(&self) -> u16 {
        self.tags_per_fetch_buffer
    }

    /// Return the io_uring provided-buffer group used by batch fetches.
    pub const fn fetch_buffer_group(&self) -> u16 {
        self.fetch_buffer_group
    }
}

impl Default for UblkBatchConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Buffer strategy used by a batch queue.
#[non_exhaustive]
#[derive(Debug)]
pub enum UblkBatchBuffers {
    /// One userspace IO buffer for every queue tag.
    IoBufs(Vec<IoBuf<u8>>),
}

/// Result for one completed ublk request.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UblkBatchCompletion {
    /// Queue-wide IO tag passed to [`UblkBatchQueue::handle_cqe`]'s request
    /// callback.
    pub tag: u16,
    /// Number of bytes completed or a negative errno.
    pub result: i32,
}

impl UblkBatchCompletion {
    /// Construct a completion.
    pub const fn new(tag: u16, result: i32) -> Self {
        Self { tag, result }
    }
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
    elements: Vec<BatchElement>,
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
            self.queue.dev.notify_queue_setup_failed();
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

    fn release_after_cleanup(&mut self) {
        self.release_on_drop = true;
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
/// [`handle_cqe`](Self::handle_cqe). An `Ok(false)` return means that the CQE
/// does not belong to this transport and must be handled by the target.
///
/// Before dropping the transport, stop the ublk queue and keep handling CQEs
/// until [`try_begin_shutdown`](Self::try_begin_shutdown) starts cleanup and
/// [`is_shutdown_complete`](Self::is_shutdown_complete) returns true. Dropping
/// it earlier deliberately retains allocations that the kernel may still
/// reference.
///
/// # Limitations
///
/// - Only the normal userspace-buffer copy path is supported. Construction
///   rejects `UBLK_F_USER_COPY`, `UBLK_F_SUPPORT_ZERO_COPY`,
///   `UBLK_F_AUTO_BUF_REG`, and `UBLK_F_ZONED` because those modes require
///   different batch element layouts and buffer lifetimes.
/// - Batch queues must use [`UblkQueue::flush_and_wake_io_tasks`]. Synchronous
///   setup preserves unrelated queue CQEs for that loop, but the generic async
///   event-loop helpers do not consume those deferred CQEs.
/// - Batch CQE `user_data` reserves the target bit, queue ID in bits `0..=15`,
///   operations `0xf0..=0xf5` in bits `16..=23`, command ID in bits `24..=39`,
///   and marker `0x424b` in bits `40..=55`. Target-specific operations on the
///   same ring must not use that encoding.
///
/// # Example
///
/// ```no_run
/// use libublk::io::{
///     UblkBatchBuffers, UblkBatchCompletion, UblkBatchConfig, UblkBatchQueue, UblkDev,
///     UblkQueue,
/// };
/// use libublk::UblkError;
///
/// fn handle_queue(qid: u16, dev: &UblkDev) -> Result<(), UblkError> {
///     let queue = UblkQueue::new(qid, dev)?;
///     let buffers = dev.alloc_queue_io_bufs();
///     let mut batch = UblkBatchQueue::new(
///         &queue,
///         UblkBatchBuffers::IoBufs(buffers),
///         UblkBatchConfig::default(),
///     )?;
///     let mut pending = Vec::new();
///
///     loop {
///         let mut batch_error = None;
///         queue.flush_and_wake_io_tasks(
///             |_user_data, cqe, _is_last| match batch.handle_cqe(cqe, |batch, tags| {
///                 for &tag in tags {
///                     let iod = queue.get_iod(tag);
///                     let bytes = (iod.nr_sectors << 9) as i32;
///                     let result = match iod.op_flags & 0xff {
///                         libublk::sys::UBLK_IO_OP_READ => {
///                             batch.io_buf_mut(tag).unwrap().zero_buf();
///                             bytes
///                         }
///                         libublk::sys::UBLK_IO_OP_WRITE => bytes,
///                         libublk::sys::UBLK_IO_OP_FLUSH => 0,
///                         _ => -libc::EOPNOTSUPP,
///                     };
///                     pending.push(UblkBatchCompletion::new(tag, result));
///                 }
///                 Ok(())
///             }) {
///                 Ok(true) => {}
///                 Ok(false) => {
///                     // Handle target-specific CQEs here.
///                 }
///                 Err(error) => batch_error = Some(error),
///             },
///             1,
///         )?;
///         if let Some(error) = batch_error {
///             return Err(error);
///         }
///         if !pending.is_empty() && batch.try_submit_completions(&pending)? {
///             pending.clear();
///         }
///         if batch.try_begin_shutdown()? && batch.is_shutdown_complete() {
///             break;
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
    inflight_commits: HashMap<u16, InflightCommit>,
    commit_pool: Vec<Vec<BatchElement>>,
    next_commit_id: u16,
    owned_tags: Vec<bool>,
    tag_scratch: Vec<bool>,
    request_scratch: Vec<u16>,
    commit_failed: bool,
    inflight_fetches: HashSet<u16>,
    fetch_stopped: bool,
    provide_inflight: HashSet<u16>,
    remove_remaining: u16,
    shutdown_started: bool,
    shutdown_complete: bool,
}

impl<'queue, 'dev> UblkBatchQueue<'queue, 'dev> {
    /// Prepare all queue tags and start the configured multishot batch fetches.
    ///
    /// The batch queue owns `buffers` because their addresses are supplied to
    /// the kernel and must remain valid while batch IO is active.
    ///
    /// # Arguments:
    ///
    /// * `queue`: ublk queue created for a device with `UBLK_F_BATCH_IO`
    /// * `buffers`: buffer strategy and resources used by the batch queue
    /// * `config`: multishot fetch and commit pool configuration
    ///
    /// # Returns:
    ///
    /// The initialized batch queue.
    ///
    /// # Errors:
    ///
    /// Returns `EOPNOTSUPP` if batch IO is disabled or the device uses an IO
    /// buffer layout not supported by this transport. Returns
    /// [`UblkError::InvalidVal`] if the buffer count does not match the queue
    /// depth, an IO buffer is smaller than `max_io_buf_bytes`, a configured
    /// count is zero, the fetch-command count exceeds the fetch-buffer count,
    /// or the initial fetches cannot fit in the thread-local io_uring submission
    /// queue. Returns `EADDRINUSE` if another batch queue on that ring already
    /// owns the configured fetch buffer group.
    pub fn new(
        queue: &'queue UblkQueue<'dev>,
        buffers: UblkBatchBuffers,
        config: UblkBatchConfig,
    ) -> Result<Self, UblkError> {
        let UblkBatchBuffers::IoBufs(buffers) = buffers;
        let mut registration = BufferRegistrationGuard {
            queue,
            completed: false,
        };
        if queue.dev.dev_info.flags & sys::UBLK_F_BATCH_IO as u64 == 0 {
            return Err(UblkError::OtherError(-libc::EOPNOTSUPP));
        }
        Self::validate(queue, &buffers, config)?;
        let submission_capacity = with_task_io_ring_mut(|ring| ring.submission().capacity());
        validate_initial_fetch_capacity(config.fetch_command_count, submission_capacity)?;
        let mut group_registration = BufferGroupRegistration::claim(config.fetch_buffer_group)?;

        let mut fetch_buffers = (0..config.fetch_buffer_count)
            .map(|_| vec![0_u16; config.tags_per_fetch_buffer as usize].into_boxed_slice())
            .collect::<Vec<_>>();
        let mut provided_buffers = 0;
        for (buffer_id, buffer) in fetch_buffers.iter_mut().enumerate() {
            if let Err(error) = Self::provide_fetch_buffer_sync(
                queue,
                config.fetch_buffer_group,
                buffer_id as u16,
                buffer,
            ) {
                if let Err(cleanup_error) = Self::remove_fetch_buffers_sync(
                    queue,
                    config.fetch_buffer_group,
                    provided_buffers,
                ) {
                    log::error!(
                        "failed to clean batch buffer group {} after setup error: {}",
                        config.fetch_buffer_group,
                        cleanup_error
                    );
                    std::mem::forget(fetch_buffers);
                } else {
                    group_registration.release_after_cleanup();
                }
                return Err(error);
            }
            provided_buffers += 1;
            if provided_buffers == 1 {
                // From this point the ring may retain this group even if
                // construction subsequently fails. Do not permit a new batch
                // queue to reuse it until the ring itself is torn down.
                group_registration.retain_until_queue_shutdown();
            }
        }

        if let Err(error) = Self::prepare_tags(queue, &buffers) {
            if let Err(cleanup_error) =
                Self::remove_fetch_buffers_sync(queue, config.fetch_buffer_group, provided_buffers)
            {
                log::error!(
                    "failed to clean batch buffer group {} after tag preparation error: {}",
                    config.fetch_buffer_group,
                    cleanup_error
                );
                std::mem::forget(fetch_buffers);
            } else {
                group_registration.release_after_cleanup();
            }
            return Err(error);
        }
        for (tag, buffer) in buffers.iter().enumerate() {
            queue.register_io_buf_internal(tag as u16, buffer);
        }

        let mut inflight_fetches = preallocated_id_set(config.fetch_command_count);
        inflight_fetches.extend(0..config.fetch_command_count);
        Self::enqueue_initial_fetches(queue, config);
        queue
            .dev
            .notify_buffer_registration_complete(queue.is_mlock_failed());
        registration.complete();

        Ok(Self {
            queue,
            buffers,
            fetch_buffers,
            config,
            inflight_commits: preallocated_commit_map(config.max_inflight_commits),
            commit_pool: (0..config.max_inflight_commits)
                .map(|_| Vec::with_capacity(queue.get_depth() as usize))
                .collect(),
            next_commit_id: 0,
            owned_tags: vec![false; queue.get_depth() as usize],
            tag_scratch: vec![false; queue.get_depth() as usize],
            request_scratch: Vec::with_capacity(config.tags_per_fetch_buffer as usize),
            commit_failed: false,
            inflight_fetches,
            fetch_stopped: false,
            provide_inflight: preallocated_id_set(config.fetch_buffer_count),
            remove_remaining: config.fetch_buffer_count,
            shutdown_started: false,
            shutdown_complete: false,
        })
    }

    /// Return the underlying ublk queue.
    #[inline(always)]
    pub fn queue(&self) -> &UblkQueue<'dev> {
        self.queue
    }

    /// Return the userspace IO buffer for a currently fetched `tag`.
    #[inline(always)]
    pub fn io_buf(&self, tag: u16) -> Option<&IoBuf<u8>> {
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
    pub fn io_buf_mut(&mut self, tag: u16) -> Option<&mut IoBuf<u8>> {
        self.owned_tags
            .get(tag as usize)
            .copied()
            .filter(|owned| *owned)
            .and_then(|_| self.buffers.get_mut(tag as usize))
    }

    /// Return the number of completion batches awaiting kernel acknowledgement.
    #[inline(always)]
    pub fn inflight_commit_count(&self) -> usize {
        self.inflight_commits.len()
    }

    /// Return whether all fetch commands stopped with `UBLK_IO_RES_ABORT`.
    #[inline(always)]
    pub fn all_fetches_stopped(&self) -> bool {
        self.fetch_stopped
    }

    /// Try to start removing the provided-buffer group from io_uring.
    ///
    /// Call this while draining a stopped queue. Continue passing CQEs to
    /// [`handle_cqe`](Self::handle_cqe) until
    /// [`is_shutdown_complete`](Self::is_shutdown_complete) returns true.
    ///
    /// # Returns:
    ///
    /// `Ok(false)` until the multishot fetch and all completion and
    /// buffer-provide operations have finished. `Ok(true)` means buffer removal
    /// has started or already completed.
    ///
    /// # Errors:
    ///
    /// Returns an error if queuing the provided-buffer removal fails.
    pub fn try_begin_shutdown(&mut self) -> Result<bool, UblkError> {
        if self.shutdown_complete || self.shutdown_started {
            return Ok(true);
        }
        if !shutdown_ready(
            self.fetch_stopped,
            self.queue.is_stopping(),
            self.inflight_commits.len(),
            self.provide_inflight.len(),
        ) {
            return Ok(false);
        }
        self.shutdown_started = true;
        if self.remove_remaining == 0 {
            self.shutdown_complete = true;
            return Ok(true);
        }
        if let Err(error) = self.submit_remove_buffers() {
            self.shutdown_started = false;
            return Err(error);
        }
        Ok(true)
    }

    /// Return whether all kernel references to the owned buffers were removed.
    #[inline(always)]
    pub fn is_shutdown_complete(&self) -> bool {
        self.shutdown_complete
    }

    /// Try to submit a group of target results to the kernel.
    ///
    /// Multiple completion groups may be in flight. Each group receives an
    /// internal command ID, and partial kernel commits are resubmitted
    /// automatically by [`handle_cqe`](Self::handle_cqe).
    ///
    /// # Arguments:
    ///
    /// * `completions`: results for fetched tags that are ready to be committed
    ///
    /// # Returns:
    ///
    /// `Ok(true)` when the completion command is queued successfully or the
    /// input is empty. `Ok(false)` means all configured commit slots are in
    /// flight; the caller retains the input and can retry after handling CQEs.
    ///
    /// # Errors:
    ///
    /// Returns `EIO` after a previous non-empty completion command failed.
    /// Returns [`UblkError::InvalidVal`] for a tag that was not fetched, a
    /// duplicate tag, or an oversized group. The input slice is never modified.
    pub fn try_submit_completions(
        &mut self,
        completions: &[UblkBatchCompletion],
    ) -> Result<bool, UblkError> {
        if completions.is_empty() {
            return Ok(true);
        }
        if self.commit_failed {
            return Err(UblkError::OtherError(-libc::EIO));
        }
        let Some(mut elements) = acquire_commit_buffer(&mut self.commit_pool) else {
            return Ok(false);
        };
        elements.clear();
        self.tag_scratch.fill(false);
        for completion in completions {
            let tag = completion.tag as usize;
            if !completion_tag_is_valid(&self.owned_tags, &mut self.tag_scratch, tag) {
                self.commit_pool.push(elements);
                return Err(UblkError::InvalidVal);
            }
            let Some(buffer) = self.buffers.get(tag) else {
                self.commit_pool.push(elements);
                return Err(UblkError::InvalidVal);
            };
            elements.push(BatchElement {
                tag: completion.tag,
                buffer_index: 0,
                result: completion.result,
                buffer_address: buffer.as_ptr() as u64,
            });
        }
        if elements.len() > u16::MAX as usize {
            elements.clear();
            self.commit_pool.push(elements);
            return Err(UblkError::InvalidVal);
        }
        let commit_id = match self.allocate_commit_id() {
            Ok(commit_id) => commit_id,
            Err(error) => {
                elements.clear();
                self.commit_pool.push(elements);
                return Err(error);
            }
        };
        for element in &elements {
            self.owned_tags[element.tag as usize] = false;
        }

        self.inflight_commits.insert(
            commit_id,
            InflightCommit {
                elements,
                offset: 0,
            },
        );
        if let Err(error) = self.submit_inflight_commit(commit_id) {
            if let Some(mut commit) = self.inflight_commits.remove(&commit_id) {
                for element in commit.elements.iter() {
                    self.owned_tags[element.tag as usize] = true;
                }
                commit.elements.clear();
                self.commit_pool.push(commit.elements);
            }
            return Err(error);
        }
        Ok(true)
    }

    /// Consume one CQE if it belongs to the batch transport.
    ///
    /// Every CQE reaped from [`UblkQueue::flush_and_wake_io_tasks`] should be
    /// passed to this method before target-specific handling. Fetched request
    /// tags are passed to `requests` using reusable transport storage. Fetch
    /// buffers are recycled and non-terminal multishot fetches are rearmed
    /// automatically.
    ///
    /// # Arguments:
    ///
    /// * `cqe`: completion queue entry reaped from the queue's io_uring
    /// * `requests`: callback that processes each fetched group of request tags
    ///
    /// # Returns:
    ///
    /// Returns `Ok(true)` when the CQE was consumed by the batch transport and
    /// `Ok(false)` when it belongs to target-specific IO. The `requests`
    /// callback receives each fetched tag batch without allocating.
    ///
    /// # Errors:
    ///
    /// Returns an error for malformed kernel results or if recycling a fetch
    /// buffer, rearming a fetch, or resubmitting a partial commit fails.
    pub fn handle_cqe<F>(&mut self, cqe: &cqueue::Entry, mut requests: F) -> Result<bool, UblkError>
    where
        F: FnMut(&mut Self, &[u16]) -> Result<(), UblkError>,
    {
        let qid = self.queue.get_qid();
        let Some((operation, command_id)) = parse_batch_user_data(cqe.user_data(), qid) else {
            return Ok(false);
        };
        match operation {
            BATCH_FETCH_OP => self
                .handle_fetch_cqe(command_id, cqe, &mut requests)
                .map(|()| true),
            BATCH_COMMIT_OP => self
                .handle_commit_cqe(command_id, cqe.result())
                .map(|()| true),
            BATCH_PROVIDE_OP => {
                if !self.provide_inflight.remove(&command_id) {
                    return Err(UblkError::InvalidVal);
                }
                let result = check_zero_result(cqe.result()).and_then(|()| {
                    restore_provided_buffer(
                        &mut self.remove_remaining,
                        self.config.fetch_buffer_count,
                    )
                });
                self.mark_queue_stopping_if_batch_drained();
                result?;
                Ok(true)
            }
            BATCH_REMOVE_OP if command_id == 0 => {
                self.handle_remove_cqe(cqe.result()).map(|()| true)
            }
            _ => Ok(false),
        }
    }

    fn validate(
        queue: &UblkQueue<'_>,
        buffers: &[IoBuf<u8>],
        config: UblkBatchConfig,
    ) -> Result<(), UblkError> {
        validate_batch_flags(queue.dev.dev_info.flags)?;
        validate_batch_config(config)?;
        validate_io_buffers(
            buffers,
            queue.get_depth() as usize,
            queue.dev.dev_info.max_io_buf_bytes as usize,
        )
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
            batch_user_data(BATCH_PREP_OP, queue.get_qid(), 0),
        );
        let result = submit_and_wait(
            queue,
            entry,
            batch_user_data(BATCH_PREP_OP, queue.get_qid(), 0),
        )?;
        check_zero_result(result)
    }

    fn allocate_commit_id(&mut self) -> Result<u16, UblkError> {
        allocate_command_id(&self.inflight_commits, &mut self.next_commit_id)
    }

    fn recycle_commit(&mut self, commit_id: u16) {
        recycle_commit_buffer(&mut self.inflight_commits, &mut self.commit_pool, commit_id);
    }

    fn submit_inflight_commit(&self, commit_id: u16) -> Result<(), UblkError> {
        let commit = self
            .inflight_commits
            .get(&commit_id)
            .ok_or(UblkError::InvalidVal)?;
        let remaining = commit.remaining();
        let entry = batch_command(
            sys::UBLK_U_IO_COMMIT_IO_CMDS,
            batch_header(self.queue.get_qid(), remaining.len()),
            remaining.as_ptr() as u64,
            batch_user_data(BATCH_COMMIT_OP, self.queue.get_qid(), commit_id),
        );
        self.queue.ublk_submit_sqe_sync(entry)
    }

    fn handle_commit_cqe(&mut self, commit_id: u16, result: i32) -> Result<(), UblkError> {
        let advance = {
            let commit = self
                .inflight_commits
                .get_mut(&commit_id)
                .ok_or(UblkError::InvalidVal)?;
            commit.advance(result)
        };
        let complete = match advance {
            Ok(value) => value,
            Err(error) => {
                self.recycle_commit(commit_id);
                self.commit_failed = true;
                self.mark_queue_stopping_if_batch_drained();
                return Err(error);
            }
        };
        if complete {
            self.recycle_commit(commit_id);
            self.mark_queue_stopping_if_batch_drained();
            Ok(())
        } else {
            if let Err(error) = self.submit_inflight_commit(commit_id) {
                self.recycle_commit(commit_id);
                self.commit_failed = true;
                self.mark_queue_stopping_if_batch_drained();
                return Err(error);
            }
            Ok(())
        }
    }

    fn handle_fetch_cqe<F>(
        &mut self,
        fetch_id: u16,
        cqe: &cqueue::Entry,
        requests: &mut F,
    ) -> Result<(), UblkError>
    where
        F: FnMut(&mut Self, &[u16]) -> Result<(), UblkError>,
    {
        if !self.inflight_fetches.contains(&fetch_id) {
            return Err(UblkError::InvalidVal);
        }
        let result = cqe.result();
        let flags = cqe.flags();
        let terminal = match classify_fetch_cqe(result, flags) {
            FetchCqeAction::Stop => {
                self.inflight_fetches.remove(&fetch_id);
                log::debug!(
                    "batch queue {} fetch stopped with {}",
                    self.queue.get_qid(),
                    result
                );
                self.fetch_stopped = self.inflight_fetches.is_empty();
                self.mark_queue_stopping_if_batch_drained();
                return Ok(());
            }
            FetchCqeAction::RearmError => {
                self.inflight_fetches.remove(&fetch_id);
                log::debug!(
                    "batch queue {} fetch failed with {}, rearming",
                    self.queue.get_qid(),
                    result
                );
                Self::submit_fetch(self.queue, self.config, fetch_id)?;
                self.inflight_fetches.insert(fetch_id);
                return Ok(());
            }
            FetchCqeAction::Requests { terminal } => terminal,
        };
        if terminal {
            self.inflight_fetches.remove(&fetch_id);
        }

        let buffer_id = cqueue::buffer_select(flags).ok_or(UblkError::InvalidVal)?;
        consume_provided_buffer(&mut self.remove_remaining)?;
        let mut tags = std::mem::take(&mut self.request_scratch);
        tags.clear();
        let handled = (|| {
            {
                let buffer = self
                    .fetch_buffers
                    .get(buffer_id as usize)
                    .ok_or(UblkError::InvalidVal)?;
                copy_fetched_tags(&mut tags, buffer, result as usize)?;
            }
            claim_tags(&mut self.owned_tags, &tags, &mut self.tag_scratch)?;
            if !self.provide_inflight.insert(buffer_id) {
                return Err(UblkError::InvalidVal);
            }
            let provide_result = {
                let buffer = self
                    .fetch_buffers
                    .get_mut(buffer_id as usize)
                    .ok_or(UblkError::InvalidVal)?;
                Self::provide_fetch_buffer(
                    self.queue,
                    self.config.fetch_buffer_group,
                    buffer_id,
                    buffer,
                )
            };
            if let Err(error) = provide_result {
                self.provide_inflight.remove(&buffer_id);
                return Err(error);
            }

            if terminal {
                Self::submit_fetch(self.queue, self.config, fetch_id)?;
                self.inflight_fetches.insert(fetch_id);
            }
            requests(self, &tags)?;
            Ok(())
        })();
        tags.clear();
        self.request_scratch = tags;
        handled
    }

    fn submit_remove_buffers(&self) -> Result<(), UblkError> {
        if self.remove_remaining == 0 {
            return Ok(());
        }
        let entry = remove_buffers_entry(
            self.remove_remaining,
            self.config.fetch_buffer_group,
            batch_user_data(BATCH_REMOVE_OP, self.queue.get_qid(), 0),
        );
        self.queue.ublk_submit_sqe_sync(entry)
    }

    fn handle_remove_cqe(&mut self, result: i32) -> Result<(), UblkError> {
        if !self.shutdown_started {
            return Err(UblkError::InvalidVal);
        }
        apply_removed_buffers(&mut self.remove_remaining, result)?;
        if self.remove_remaining == 0 {
            self.shutdown_complete = true;
        } else if let Err(error) = self.submit_remove_buffers() {
            self.shutdown_started = false;
            return Err(error);
        }
        Ok(())
    }

    fn submit_fetch(
        queue: &UblkQueue<'_>,
        config: UblkBatchConfig,
        fetch_id: u16,
    ) -> Result<(), UblkError> {
        queue.ublk_submit_sqe_sync(fetch_entry(queue, config, fetch_id))
    }

    fn enqueue_initial_fetches(queue: &UblkQueue<'_>, config: UblkBatchConfig) {
        with_task_io_ring_mut(|ring| {
            let mut submission = ring.submission();
            let available = submission.capacity().saturating_sub(submission.len());
            assert!(available >= config.fetch_command_count as usize);
            for fetch_id in 0..config.fetch_command_count {
                let entry = fetch_entry(queue, config, fetch_id);
                unsafe {
                    submission
                        .push(&entry)
                        .expect("initial batch fetch capacity was prevalidated");
                }
            }
        });
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
                batch_user_data(BATCH_SETUP_PROVIDE_OP, queue.get_qid(), buffer_id),
            ),
            batch_user_data(BATCH_SETUP_PROVIDE_OP, queue.get_qid(), buffer_id),
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
            batch_user_data(BATCH_PROVIDE_OP, queue.get_qid(), buffer_id),
        ))
    }

    fn remove_fetch_buffers_sync(
        queue: &UblkQueue<'_>,
        group: u16,
        count: u16,
    ) -> Result<(), UblkError> {
        let user_data = batch_user_data(BATCH_REMOVE_OP, queue.get_qid(), 0);
        let mut remaining = count;
        while remaining != 0 {
            let result = submit_and_wait(
                queue,
                remove_buffers_entry(remaining, group, user_data),
                user_data,
            )?;
            apply_removed_buffers(&mut remaining, result)?;
        }
        Ok(())
    }

    fn mark_queue_stopping_if_batch_drained(&self) {
        if batch_activity_drained(
            self.fetch_stopped,
            self.inflight_commits.len(),
            self.provide_inflight.len(),
        ) {
            self.queue.mark_stopping();
        }
    }
}

impl Drop for UblkBatchQueue<'_, '_> {
    fn drop(&mut self) {
        if self.shutdown_complete {
            release_buffer_group(self.config.fetch_buffer_group);
            return;
        }

        log::warn!(
            "batch queue {} dropped before shutdown completed; retaining kernel-referenced buffers",
            self.queue.get_qid()
        );
        std::mem::forget(std::mem::take(&mut self.buffers));
        std::mem::forget(std::mem::take(&mut self.fetch_buffers));
        std::mem::forget(std::mem::take(&mut self.inflight_commits));
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

fn batch_user_data(operation: u32, qid: u16, command_id: u16) -> u64 {
    crate::UblkUringData::Target as u64
        | qid as u64
        | ((operation & 0xff) as u64) << 16
        | (command_id as u64) << BATCH_USER_DATA_ID_SHIFT
        | BATCH_USER_DATA_MAGIC << BATCH_USER_DATA_MAGIC_SHIFT
}

fn parse_batch_user_data(user_data: u64, qid: u16) -> Option<(u32, u16)> {
    let target = crate::UblkUringData::Target as u64;
    let reserved = 0x7f_u64 << 56;
    if user_data & target == 0
        || user_data & reserved != 0
        || UblkIOCtx::user_data_to_tag(user_data) != qid as u32
        || (user_data >> BATCH_USER_DATA_MAGIC_SHIFT) & 0xffff != BATCH_USER_DATA_MAGIC
    {
        return None;
    }
    Some((
        UblkIOCtx::user_data_to_op(user_data),
        ((user_data >> BATCH_USER_DATA_ID_SHIFT) & 0xffff) as u16,
    ))
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

fn remove_buffers_entry(count: u16, group: u16, user_data: u64) -> squeue::Entry {
    opcode::RemoveBuffers::new(count, group)
        .build()
        .user_data(user_data)
}

fn fetch_entry(queue: &UblkQueue<'_>, config: UblkBatchConfig, fetch_id: u16) -> squeue::Entry {
    let header = batch_fetch_header(queue.get_qid());
    let mut entry = batch_command(
        sys::UBLK_U_IO_FETCH_IO_CMDS,
        header,
        0,
        batch_user_data(BATCH_FETCH_OP, queue.get_qid(), fetch_id),
    )
    .flags(squeue::Flags::BUFFER_SELECT);
    unsafe {
        let raw: &mut RawSqe = transmute(&mut entry);
        raw.rw_flags |= IORING_URING_CMD_MULTISHOT;
        raw.buf_index = config.fetch_buffer_group;
    }
    entry
}

fn validate_batch_flags(flags: u64) -> Result<(), UblkError> {
    if flags & UNSUPPORTED_BATCH_FLAGS != 0 {
        Err(UblkError::OtherError(-libc::EOPNOTSUPP))
    } else {
        Ok(())
    }
}

fn validate_batch_config(config: UblkBatchConfig) -> Result<(), UblkError> {
    if config.fetch_buffer_count == 0
        || config.fetch_command_count == 0
        || config.fetch_command_count > config.fetch_buffer_count
        || config.max_inflight_commits == 0
        || config.tags_per_fetch_buffer == 0
    {
        Err(UblkError::InvalidVal)
    } else {
        Ok(())
    }
}

fn validate_initial_fetch_capacity(fetch_commands: u16, capacity: usize) -> Result<(), UblkError> {
    if fetch_commands as usize > capacity {
        Err(UblkError::InvalidVal)
    } else {
        Ok(())
    }
}

fn validate_io_buffers(
    buffers: &[IoBuf<u8>],
    queue_depth: usize,
    required_bytes: usize,
) -> Result<(), UblkError> {
    if buffers.len() != queue_depth
        || buffers
            .iter()
            .any(|buffer| buffer.as_ptr().is_null() || buffer.len() < required_bytes)
    {
        Err(UblkError::InvalidVal)
    } else {
        Ok(())
    }
}

fn shutdown_ready(
    fetch_stopped: bool,
    queue_stopping: bool,
    inflight_commits: usize,
    inflight_provides: usize,
) -> bool {
    queue_stopping && batch_activity_drained(fetch_stopped, inflight_commits, inflight_provides)
}

fn batch_activity_drained(
    fetch_stopped: bool,
    inflight_commits: usize,
    inflight_provides: usize,
) -> bool {
    fetch_stopped && inflight_commits == 0 && inflight_provides == 0
}

fn completion_tag_is_valid(owned_tags: &[bool], seen: &mut [bool], tag: usize) -> bool {
    if !owned_tags.get(tag).copied().unwrap_or(false) || seen.get(tag).copied().unwrap_or(true) {
        return false;
    }
    seen[tag] = true;
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FetchCqeAction {
    Stop,
    RearmError,
    Requests { terminal: bool },
}

fn classify_fetch_cqe(result: i32, flags: u32) -> FetchCqeAction {
    if result == sys::UBLK_IO_RES_ABORT {
        FetchCqeAction::Stop
    } else if result < 0 {
        FetchCqeAction::RearmError
    } else {
        FetchCqeAction::Requests {
            terminal: !cqueue::more(flags),
        }
    }
}

fn copy_fetched_tags(
    scratch: &mut Vec<u16>,
    buffer: &[u16],
    bytes: usize,
) -> Result<(), UblkError> {
    if bytes > size_of_val(buffer) || bytes % size_of::<u16>() != 0 {
        return Err(UblkError::OtherError(-libc::EIO));
    }
    scratch.clear();
    scratch.extend_from_slice(&buffer[..bytes / size_of::<u16>()]);
    Ok(())
}

fn check_zero_result(result: i32) -> Result<(), UblkError> {
    match result {
        0 => Ok(()),
        result if result < 0 => Err(UblkError::OtherError(result)),
        _ => Err(UblkError::OtherError(-libc::EIO)),
    }
}

fn consume_provided_buffer(available: &mut u16) -> Result<(), UblkError> {
    *available = available.checked_sub(1).ok_or(UblkError::InvalidVal)?;
    Ok(())
}

fn restore_provided_buffer(available: &mut u16, capacity: u16) -> Result<(), UblkError> {
    if *available >= capacity {
        return Err(UblkError::InvalidVal);
    }
    *available += 1;
    Ok(())
}

fn apply_removed_buffers(remaining: &mut u16, result: i32) -> Result<(), UblkError> {
    if result <= 0 || result as u32 > *remaining as u32 {
        return Err(UblkError::OtherError(if result < 0 {
            result
        } else {
            -libc::EIO
        }));
    }
    *remaining -= result as u16;
    Ok(())
}

fn preallocated_commit_map(capacity: u16) -> HashMap<u16, InflightCommit> {
    HashMap::with_capacity(capacity as usize)
}

fn preallocated_id_set(capacity: u16) -> HashSet<u16> {
    HashSet::with_capacity(capacity as usize)
}

fn allocate_command_id<T>(inflight: &HashMap<u16, T>, next_id: &mut u16) -> Result<u16, UblkError> {
    for _ in 0..=u16::MAX {
        let command_id = *next_id;
        *next_id = next_id.wrapping_add(1);
        if !inflight.contains_key(&command_id) {
            return Ok(command_id);
        }
    }
    Err(UblkError::OtherError(-libc::EBUSY))
}

fn acquire_commit_buffer(pool: &mut Vec<Vec<BatchElement>>) -> Option<Vec<BatchElement>> {
    pool.pop()
}

fn recycle_commit_buffer(
    inflight: &mut HashMap<u16, InflightCommit>,
    pool: &mut Vec<Vec<BatchElement>>,
    commit_id: u16,
) -> bool {
    let Some(mut commit) = inflight.remove(&commit_id) else {
        return false;
    };
    commit.elements.clear();
    pool.push(commit.elements);
    true
}

fn claim_tags(owned_tags: &mut [bool], tags: &[u16], seen: &mut [bool]) -> Result<(), UblkError> {
    if seen.len() != owned_tags.len() {
        return Err(UblkError::InvalidVal);
    }
    seen.fill(false);
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
    queue.ublk_submit_sqe_sync(entry)?;
    loop {
        let cqe = with_task_io_ring_mut(|ring| {
            ring.submit_and_wait(1).map_err(UblkError::IOError)?;
            ring.completion().next().ok_or(UblkError::InvalidVal)
        })?;
        if cqe.user_data() == expected_user_data {
            return Ok(cqe.result());
        }
        defer_queue_cqe(cqe);
    }
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
            elements: vec![BatchElement::default(); 3],
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
            elements: vec![BatchElement::default()],
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
        let fetch = batch_user_data(BATCH_FETCH_OP, 3, 7);
        let commit = batch_user_data(BATCH_COMMIT_OP, 3, 7);
        let next_commit = batch_user_data(BATCH_COMMIT_OP, 3, 8);
        let provide = batch_user_data(BATCH_PROVIDE_OP, 3, 7);
        assert_ne!(fetch & target, 0);
        assert_ne!(commit & target, 0);
        assert_ne!(provide & target, 0);
        assert_ne!(fetch, commit);
        assert_ne!(commit, provide);
        assert_ne!(commit, next_commit);
        assert_ne!(fetch, batch_user_data(BATCH_FETCH_OP, 4, 7));
        assert_eq!(UblkIOCtx::user_data_to_tag(fetch), 3);
        assert_eq!(UblkIOCtx::user_data_to_op(fetch), BATCH_FETCH_OP);
        assert_eq!(fetch, 0x8042_4b00_07f0_0003);
        assert_eq!(parse_batch_user_data(fetch, 3), Some((BATCH_FETCH_OP, 7)));
        assert_eq!(parse_batch_user_data(fetch, 4), None);
        assert_eq!(parse_batch_user_data(fetch & !target, 3), None);
        assert_eq!(
            parse_batch_user_data(UblkIOCtx::build_user_data(3, BATCH_FETCH_OP, 7, true), 3,),
            None
        );
    }

    #[test]
    fn concurrent_command_ids_skip_ids_that_are_in_flight() {
        let inflight = HashMap::from([(0, ()), (1, ()), (u16::MAX, ())]);
        let mut next_id = 0;
        assert_eq!(allocate_command_id(&inflight, &mut next_id).unwrap(), 2);
        assert_eq!(next_id, 3);

        next_id = u16::MAX;
        assert_eq!(allocate_command_id(&inflight, &mut next_id).unwrap(), 2);
        assert_eq!(next_id, 3);
    }

    #[test]
    fn default_config_enables_multiple_fetch_commands() {
        let config = UblkBatchConfig::default();
        assert!(config.fetch_command_count() > 1);
        assert!(config.fetch_command_count() <= config.fetch_buffer_count());
        assert!(config.max_inflight_commits() > 1);
    }

    #[test]
    fn config_builder_exposes_each_batch_limit() {
        let config = UblkBatchConfig::new()
            .with_fetch_buffer_count(4)
            .with_fetch_command_count(3)
            .with_max_inflight_commits(5)
            .with_tags_per_fetch_buffer(64)
            .with_fetch_buffer_group(0x1234);

        assert_eq!(config.fetch_buffer_count(), 4);
        assert_eq!(config.fetch_command_count(), 3);
        assert_eq!(config.max_inflight_commits(), 5);
        assert_eq!(config.tags_per_fetch_buffer(), 64);
        assert_eq!(config.fetch_buffer_group(), 0x1234);
    }

    #[test]
    fn invalid_batch_configurations_are_rejected() {
        let valid = UblkBatchConfig::default();
        assert!(validate_batch_config(valid).is_ok());

        for invalid in [
            valid.with_fetch_buffer_count(0),
            valid.with_fetch_command_count(0),
            valid.with_fetch_command_count(valid.fetch_buffer_count() + 1),
            valid.with_max_inflight_commits(0),
            valid.with_tags_per_fetch_buffer(0),
        ] {
            assert!(validate_batch_config(invalid).is_err());
        }
    }

    #[test]
    fn initial_fetches_must_fit_in_submission_queue() {
        assert!(validate_initial_fetch_capacity(4, 4).is_ok());
        assert!(validate_initial_fetch_capacity(5, 4).is_err());
    }

    #[test]
    fn invalid_io_buffer_counts_and_sizes_are_rejected() {
        let buffers = vec![IoBuf::<u8>::new(8), IoBuf::<u8>::new(8)];
        assert!(validate_io_buffers(&buffers, 2, 8).is_ok());
        assert!(validate_io_buffers(&buffers, 1, 8).is_err());
        assert!(validate_io_buffers(&buffers, 2, 9).is_err());
    }

    #[test]
    fn unowned_and_duplicate_completion_tags_are_rejected() {
        let owned = [true, false];
        let mut seen = [false; 2];
        assert!(completion_tag_is_valid(&owned, &mut seen, 0));
        assert!(!completion_tag_is_valid(&owned, &mut seen, 0));

        seen.fill(false);
        assert!(!completion_tag_is_valid(&owned, &mut seen, 1));
        assert!(!completion_tag_is_valid(&owned, &mut seen, 2));
    }

    #[test]
    fn shutdown_requires_all_batch_activity_to_finish() {
        assert!(shutdown_ready(true, true, 0, 0));
        assert!(!shutdown_ready(false, true, 0, 0));
        assert!(!shutdown_ready(true, false, 0, 0));
        assert!(!shutdown_ready(true, true, 1, 0));
        assert!(!shutdown_ready(true, true, 0, 1));
    }

    #[test]
    fn queue_stopping_waits_for_all_batch_activity() {
        assert!(batch_activity_drained(true, 0, 0));
        assert!(!batch_activity_drained(false, 0, 0));
        assert!(!batch_activity_drained(true, 1, 0));
        assert!(!batch_activity_drained(true, 0, 1));
        assert!(!batch_activity_drained(false, 1, 1));
    }

    #[test]
    fn fetch_cqe_errors_stop_or_rearm_as_required() {
        assert_eq!(
            classify_fetch_cqe(sys::UBLK_IO_RES_ABORT, 0),
            FetchCqeAction::Stop
        );
        assert_eq!(
            classify_fetch_cqe(-libc::ENOBUFS, 0),
            FetchCqeAction::RearmError
        );
        assert_eq!(
            classify_fetch_cqe(0, 1 << 1),
            FetchCqeAction::Requests { terminal: false }
        );
        assert_eq!(
            classify_fetch_cqe(0, 0),
            FetchCqeAction::Requests { terminal: true }
        );
    }

    #[test]
    fn request_scratch_reuses_its_allocation() {
        let mut scratch = Vec::with_capacity(4);
        let allocation = scratch.as_ptr();
        copy_fetched_tags(&mut scratch, &[1, 2, 3, 4], 4).unwrap();
        assert_eq!(scratch, [1, 2]);
        assert_eq!(scratch.as_ptr(), allocation);

        copy_fetched_tags(&mut scratch, &[3, 4, 5, 6], 8).unwrap();
        assert_eq!(scratch, [3, 4, 5, 6]);
        assert_eq!(scratch.as_ptr(), allocation);
        assert!(copy_fetched_tags(&mut scratch, &[1], 1).is_err());
        assert!(copy_fetched_tags(&mut scratch, &[1], 4).is_err());
    }

    #[test]
    fn completed_commit_buffer_returns_to_pool_without_reallocation() {
        let mut elements = Vec::with_capacity(4);
        elements.push(BatchElement::default());
        let allocation = elements.as_ptr();
        let mut inflight = HashMap::from([(
            7,
            InflightCommit {
                elements,
                offset: 0,
            },
        )]);
        let mut pool = Vec::new();

        assert!(recycle_commit_buffer(&mut inflight, &mut pool, 7));
        assert!(inflight.is_empty());
        assert_eq!(pool.len(), 1);
        assert!(pool[0].is_empty());
        assert_eq!(pool[0].as_ptr(), allocation);
        assert!(!recycle_commit_buffer(&mut inflight, &mut pool, 7));
    }

    #[test]
    fn commit_backpressure_preserves_caller_completions() {
        let completions = vec![UblkBatchCompletion::new(7, 4096)];
        let mut pool = Vec::new();

        assert!(acquire_commit_buffer(&mut pool).is_none());
        assert_eq!(completions, [UblkBatchCompletion::new(7, 4096)]);
    }

    #[test]
    fn inflight_tracking_is_preallocated_to_configured_limits() {
        let commits = preallocated_commit_map(3);
        let fetches = preallocated_id_set(4);
        let provides = preallocated_id_set(8);

        assert!(commits.capacity() >= 3);
        assert!(fetches.capacity() >= 4);
        assert!(provides.capacity() >= 8);
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
    fn cleaned_setup_releases_retained_buffer_group() {
        let group = 0x7ffd;
        let mut registration = BufferGroupRegistration::claim(group).unwrap();
        registration.retain_until_queue_shutdown();
        assert!(BufferGroupRegistration::claim(group).is_err());

        registration.release_after_cleanup();
        drop(registration);
        assert!(BufferGroupRegistration::claim(group).is_ok());
    }

    #[test]
    fn claim_tags_does_not_partially_update_on_error() {
        let mut owned_tags = vec![false; 4];
        let mut seen = vec![false; 4];
        assert!(claim_tags(&mut owned_tags, &[1, 1], &mut seen).is_err());
        assert_eq!(owned_tags, vec![false; 4]);

        assert!(claim_tags(&mut owned_tags, &[2, 4], &mut seen).is_err());
        assert_eq!(owned_tags, vec![false; 4]);

        claim_tags(&mut owned_tags, &[1, 3], &mut seen).unwrap();
        assert_eq!(owned_tags, vec![false, true, false, true]);
    }

    #[test]
    fn zero_result_check_rejects_errors_and_unexpected_counts() {
        assert!(check_zero_result(0).is_ok());
        assert!(check_zero_result(-libc::ENOBUFS).is_err());
        assert!(check_zero_result(1).is_err());
    }

    #[test]
    fn provided_buffer_accounting_tracks_consumption_and_restore() {
        let mut available = 2;
        consume_provided_buffer(&mut available).unwrap();
        assert_eq!(available, 1);
        restore_provided_buffer(&mut available, 2).unwrap();
        assert_eq!(available, 2);

        assert!(restore_provided_buffer(&mut available, 2).is_err());
        available = 0;
        assert!(consume_provided_buffer(&mut available).is_err());
    }

    #[test]
    fn setup_cleanup_accepts_partial_removals_and_rejects_bad_counts() {
        let mut remaining = 4;
        apply_removed_buffers(&mut remaining, 2).unwrap();
        assert_eq!(remaining, 2);
        apply_removed_buffers(&mut remaining, 2).unwrap();
        assert_eq!(remaining, 0);

        let mut remaining = 2;
        assert!(apply_removed_buffers(&mut remaining, 0).is_err());
        assert!(apply_removed_buffers(&mut remaining, 3).is_err());
        assert!(apply_removed_buffers(&mut remaining, -libc::EIO).is_err());
        assert_eq!(remaining, 2);
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
        assert!(validate_batch_flags(0).is_ok());
        for flag in [
            sys::UBLK_F_USER_COPY,
            sys::UBLK_F_SUPPORT_ZERO_COPY,
            sys::UBLK_F_AUTO_BUF_REG,
            sys::UBLK_F_ZONED,
        ] {
            assert!(validate_batch_flags(flag as u64).is_err());
        }
    }
}
