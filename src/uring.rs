//! # Unified io_uring and Resource Management Module
//!
//! This module provides a unified structure for managing both io_uring instances
//! and their associated resource registrations in a thread-local context.

use super::UblkError;
use io_uring::{squeue, IoUring};
use std::cell::{OnceCell, RefCell};
use std::os::unix::io::RawFd;

/// Queue resource range tracking for multi-queue scenarios
#[derive(Debug, Clone)]
pub struct QueueResourceRange {
    /// Queue's slab key for identification
    pub queue_slab_key: u16,
    /// Starting index in the global file table
    pub file_start_index: u16,
    /// Number of files owned by this queue
    pub file_count: u16,
    /// Starting index in the global buffer table (for auto buffer registration)
    pub buffer_start_index: u16,
    /// Number of buffers owned by this queue
    pub buffer_count: u16,
}

/// Centralized resource manager for io_uring resource registration across multiple queues
#[derive(Debug)]
pub struct UringResourceManager {
    /// All files to be registered with io_uring (accumulated from all queues)
    pub files: Vec<RawFd>,
    /// Resource ranges for each queue
    pub queue_ranges: Vec<QueueResourceRange>,
    /// Whether resources have been registered with io_uring
    pub registered: bool,
    /// Total buffer count needed for sparse buffer registration
    pub total_buffer_count: u32,
}

impl UringResourceManager {
    fn new() -> Self {
        Self {
            files: Vec::new(),
            queue_ranges: Vec::new(),
            registered: false,
            total_buffer_count: 0,
        }
    }

    /// Add files and buffer requirements for a queue
    pub fn add_queue_resources(
        &mut self,
        queue_slab_key: u16,
        files: &[RawFd],
        buffer_count: u32,
    ) -> QueueResourceRange {
        if self.registered {
            panic!("Cannot add resources after registration");
        }

        let file_start_index = self.files.len() as u16;
        let buffer_start_index = self.total_buffer_count as u16;

        // Add files to the global table
        self.files.extend_from_slice(files);

        // Create range record for this queue
        let range = QueueResourceRange {
            queue_slab_key,
            file_start_index,
            file_count: files.len() as u16,
            buffer_start_index,
            buffer_count: buffer_count as u16,
        };

        self.queue_ranges.push(range.clone());
        self.total_buffer_count += buffer_count;

        range
    }

    /// Perform batch registration of all accumulated files and buffers
    pub fn register_resources_with_ring(
        &mut self,
        ring: &mut IoUring<squeue::Entry>,
    ) -> Result<(), UblkError> {
        if self.registered {
            return Ok(()); // Already registered
        }

        // Register all files
        if !self.files.is_empty() {
            ring.submitter()
                .register_files(&self.files)
                .map_err(UblkError::IOError)?;
        }

        // Register sparse buffers if needed
        if self.total_buffer_count > 0 {
            ring.submitter()
                .register_buffers_sparse(self.total_buffer_count)
                .map_err(UblkError::IOError)?;
        }

        self.registered = true;
        log::debug!(
            "Registered {} files and {} buffers for {} queues",
            self.files.len(),
            self.total_buffer_count,
            self.queue_ranges.len()
        );
        Ok(())
    }

    /// Get resource range for a specific queue
    pub fn get_queue_range(&self, queue_slab_key: u16) -> Option<&QueueResourceRange> {
        self.queue_ranges
            .iter()
            .find(|range| range.queue_slab_key == queue_slab_key)
    }

    /// Unregister resources when all queues are dropped
    pub fn unregister_resources(
        &mut self,
        ring: &mut IoUring<squeue::Entry>,
    ) -> Result<(), UblkError> {
        if !self.registered {
            return Ok(()); // Nothing to unregister
        }

        // Unregister files if any were registered
        if !self.files.is_empty() {
            if let Err(e) = ring.submitter().unregister_files() {
                log::error!("Failed to unregister files in multi-queue mode: {}", e);
                return Err(UblkError::IOError(e));
            }
        }

        // Unregister sparse buffers if any were registered
        if self.total_buffer_count > 0 {
            if let Err(e) = ring.submitter().unregister_buffers() {
                log::error!("Failed to unregister buffers in multi-queue mode: {}", e);
                return Err(UblkError::IOError(e));
            }
        }

        self.registered = false;
        log::debug!(
            "Unregistered {} files and {} buffers for {} queues",
            self.files.len(),
            self.total_buffer_count,
            self.queue_ranges.len()
        );
        Ok(())
    }
}

impl Drop for UringResourceManager {
    fn drop(&mut self) {
        // We can't access the ring here safely, so just log if there are resources
        if self.registered {
            log::warn!("UringResourceManager dropped while resources were still registered");
        }
    }
}

/// Unified io_uring and resource management structure
///
/// This structure encapsulates both the io_uring instance and its resource manager
/// to ensure proper initialization order and cleanup dependencies.
pub struct UblkUring {
    /// The io_uring instance
    ring: OnceCell<RefCell<IoUring<squeue::Entry>>>,
    /// Resource manager for multi-queue scenarios
    resource_manager: RefCell<Option<UringResourceManager>>,
}

impl UblkUring {
    pub fn new() -> Self {
        Self {
            ring: OnceCell::new(),
            resource_manager: RefCell::new(None),
        }
    }

    /// Access the ring with immutable reference
    pub fn with_ring<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&IoUring<squeue::Entry>) -> R,
    {
        if let Some(ring_cell) = self.ring.get() {
            let ring = ring_cell.borrow();
            f(&*ring)
        } else {
            panic!("Queue ring not initialized. Call ublk_init_task_ring() first or create a UblkQueue.")
        }
    }

    /// Access the ring with mutable reference
    pub fn with_ring_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut IoUring<squeue::Entry>) -> R,
    {
        if let Some(ring_cell) = self.ring.get() {
            let mut ring = ring_cell.borrow_mut();
            f(&mut *ring)
        } else {
            panic!("Queue ring not initialized. Call ublk_init_task_ring() first or create a UblkQueue.")
        }
    }

    /// Access the resource manager
    pub fn with_resource_manager<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut UringResourceManager) -> R,
    {
        let mut manager_opt = self.resource_manager.borrow_mut();
        if manager_opt.is_none() {
            *manager_opt = Some(UringResourceManager::new());
        }
        f(manager_opt.as_mut().unwrap())
    }

    /// Initialize the ring using a custom closure
    pub fn init_ring<F>(&self, init_fn: F) -> Result<(), UblkError>
    where
        F: FnOnce(&OnceCell<RefCell<IoUring<squeue::Entry>>>) -> Result<(), UblkError>,
    {
        init_fn(&self.ring)
    }

    /// Remove a queue from the resource manager and cleanup if it was the last one
    pub fn remove_queue_from_resource_manager(&self, queue_slab_key: u16) -> Result<(), UblkError> {
        let mut manager_opt = self.resource_manager.borrow_mut();
        if let Some(manager) = manager_opt.as_mut() {
            // Remove the queue from the ranges
            manager
                .queue_ranges
                .retain(|range| range.queue_slab_key != queue_slab_key);

            // If this was the last queue, clean up the manager
            if manager.queue_ranges.is_empty() {
                log::debug!("Last queue removed, cleaning up io_uring resource manager");
                // Move the manager out of the Option to trigger cleanup
                let mut cleanup_manager = manager_opt.take().unwrap();
                // Explicitly call unregister_resources with the ring before drop
                self.with_ring_mut(|ring| cleanup_manager.unregister_resources(ring))?;
            }
        }
        Ok(())
    }
}

impl Drop for UblkUring {
    fn drop(&mut self) {
        // Ensure resource manager is cleaned up before ring
        if let Some(mut manager) = self.resource_manager.borrow_mut().take() {
            if let Some(ring_cell) = self.ring.get() {
                if let Ok(mut ring) = ring_cell.try_borrow_mut() {
                    let _ = manager.unregister_resources(&mut *ring);
                }
            }
        }
    }
}

impl Default for UblkUring {
    fn default() -> Self {
        Self::new()
    }
}

// Thread-local unified uring instance
std::thread_local! {
    pub(crate) static UBLK_URING: UblkUring = UblkUring::new();
}
