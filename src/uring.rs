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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctrl::UblkCtrlBuilder;
    use crate::io::{with_uring_resource_manager, UblkDev, UblkQueue};
    use crate::multi_queue::MultiQueueManager;
    use crate::UblkFlags;

    #[test]
    fn test_multi_queue_resource_manager_integration() {
        // Test comprehensive multi-queue resource management integration
        // This is adapted from the examples/multi_queue.rs example

        let nr_queues = 4;

        // Create a ublk controller with multiple queues for testing
        let ctrl = UblkCtrlBuilder::default()
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .name("test-multi-queue-resource-mgr")
            .nr_queues(nr_queues)
            .build()
            .expect("Failed to create ublk controller");

        // Test target initialization with multi-queue resource management
        let tgt_init = |dev: &mut UblkDev| {
            // Create a multi-queue manager
            let mut manager = MultiQueueManager::new();
            let mut queues: Vec<UblkQueue<'_>> = Vec::new();

            // Verify initial state
            assert_eq!(manager.queue_count(), 0);
            assert!(!manager.are_resources_registered());

            // Create multiple queues with automatic resource management
            for q_id in 0..nr_queues {
                // Create queue - this will automatically add its resources to the manager
                let queue = UblkQueue::new_multi(q_id, dev, &mut manager)?;

                // Verify queue was created with proper slab key
                let slab_key = queue.get_slab_key();
                assert_ne!(slab_key, crate::multi_queue::slab_key::UNUSE_KEY);
                assert!(slab_key <= crate::multi_queue::slab_key::MAX_QUEUE_KEY);

                let range = queue
                    .get_resource_range()
                    .expect("resources are not added after creating queues");

                // Check resource range for multi-queue scenarios
                assert_eq!(range.queue_slab_key, slab_key);
                assert_eq!(range.file_count, 1); // Each queue should have 1 file (cdev)

                // Verify resource ranges don't overlap
                for existing_queue in &queues {
                    if let Some(existing_range) = existing_queue.get_resource_range() {
                        // File ranges should not overlap
                        assert!(
                            range.file_start_index
                                >= existing_range.file_start_index + existing_range.file_count
                                || existing_range.file_start_index
                                    >= range.file_start_index + range.file_count,
                            "File ranges overlap between queues"
                        );

                        // Buffer ranges should not overlap (if both have buffers)
                        if range.buffer_count > 0 && existing_range.buffer_count > 0 {
                            assert!(
                                range.buffer_start_index
                                    >= existing_range.buffer_start_index
                                        + existing_range.buffer_count
                                    || existing_range.buffer_start_index
                                        >= range.buffer_start_index + range.buffer_count,
                                "Buffer ranges overlap between queues"
                            );
                        }
                    }
                }

                queues.push(queue);
            }

            // Verify manager state after queue creation
            assert_eq!(manager.queue_count(), nr_queues as usize);
            assert!(!manager.are_resources_registered());

            // Test resource registration
            manager.register_resources()?;
            assert!(manager.are_resources_registered());

            // Test that double registration is safe
            let result = manager.register_resources();
            assert!(result.is_ok(), "Double registration should be safe");

            // Test index translation functionality
            if let Some(queue) = queues.first() {
                // Test file index translation
                let global_file_idx = queue.translate_file_index(0);
                if let Some(range) = queue.get_resource_range() {
                    assert_eq!(global_file_idx, range.file_start_index);
                } else {
                    assert_eq!(global_file_idx, 0); // Single queue mode
                }

                // Test buffer index translation (if buffers are used)
                if queue
                    .get_resource_range()
                    .map(|r| r.buffer_count > 0)
                    .unwrap_or(false)
                {
                    let global_buffer_idx = queue.translate_buffer_index(0);
                    if let Some(range) = queue.get_resource_range() {
                        assert_eq!(global_buffer_idx, range.buffer_start_index);
                    }
                }
            }

            // Verify resource manager state through UBLK_URING
            UBLK_URING.with(|ublk_uring| {
                ublk_uring.with_resource_manager(|resource_mgr| {
                    assert_eq!(resource_mgr.queue_ranges.len(), nr_queues as usize);
                    assert_eq!(resource_mgr.files.len(), nr_queues as usize); // One file per queue
                    assert!(resource_mgr.registered);

                    // Verify each queue has its range properly registered
                    for queue in &queues {
                        let slab_key = queue.get_slab_key();
                        let range = resource_mgr.get_queue_range(slab_key);
                        assert!(range.is_some(), "Queue range should be registered");

                        if let Some(range) = range {
                            assert_eq!(range.queue_slab_key, slab_key);
                        }
                    }
                });
            });

            // Test queue lookup functionality
            for queue in &queues {
                let slab_key = queue.get_slab_key();
                let retrieved_range = crate::io::get_queue_resource_range(slab_key);
                assert!(
                    retrieved_range.is_some(),
                    "Should be able to retrieve queue range"
                );

                if let Some(range) = retrieved_range {
                    assert_eq!(range.queue_slab_key, slab_key);
                }
            }

            Ok(())
        };

        // Create the ublk device with our multi-queue initialization
        let _dev =
            UblkDev::new(ctrl.get_name(), tgt_init, &ctrl).expect("Failed to create ublk device");
    }

    #[test]
    fn test_uring_resource_manager_lifecycle() {
        // Test the basic lifecycle of UringResourceManager

        // Test initial state
        UBLK_URING.with(|ublk_uring| {
            ublk_uring.with_resource_manager(|manager| {
                assert_eq!(manager.files.len(), 0);
                assert_eq!(manager.queue_ranges.len(), 0);
                assert!(!manager.registered);
                assert_eq!(manager.total_buffer_count, 0);
            });
        });

        // Test adding resources
        let test_files = [42, 43, 44]; // Mock file descriptors
        let range1 =
            with_uring_resource_manager(|manager| manager.add_queue_resources(1, &test_files, 64));

        assert_eq!(range1.queue_slab_key, 1);
        assert_eq!(range1.file_start_index, 0);
        assert_eq!(range1.file_count, 3);
        assert_eq!(range1.buffer_start_index, 0);
        assert_eq!(range1.buffer_count, 64);

        // Add another queue's resources
        let test_files2 = [45];
        let range2 =
            with_uring_resource_manager(|manager| manager.add_queue_resources(2, &test_files2, 32));

        assert_eq!(range2.queue_slab_key, 2);
        assert_eq!(range2.file_start_index, 3); // After first queue's 3 files
        assert_eq!(range2.file_count, 1);
        assert_eq!(range2.buffer_start_index, 64); // After first queue's 64 buffers
        assert_eq!(range2.buffer_count, 32);

        // Verify accumulated state
        UBLK_URING.with(|ublk_uring| {
            ublk_uring.with_resource_manager(|manager| {
                assert_eq!(manager.files.len(), 4); // 3 + 1 files
                assert_eq!(manager.queue_ranges.len(), 2);
                assert!(!manager.registered);
                assert_eq!(manager.total_buffer_count, 96); // 64 + 32 buffers
            });
        });

        // Test range lookup
        let retrieved_range1 = UBLK_URING.with(|ublk_uring| {
            ublk_uring.with_resource_manager(|manager| manager.get_queue_range(1).cloned())
        });
        assert!(retrieved_range1.is_some());
        assert_eq!(retrieved_range1.unwrap().queue_slab_key, 1);

        // Test queue removal
        let removal_result =
            UBLK_URING.with(|ublk_uring| ublk_uring.remove_queue_from_resource_manager(1));
        assert!(removal_result.is_ok());

        // Verify queue was removed
        UBLK_URING.with(|ublk_uring| {
            ublk_uring.with_resource_manager(|manager| {
                assert_eq!(manager.queue_ranges.len(), 1);
                assert!(manager.get_queue_range(1).is_none());
                assert!(manager.get_queue_range(2).is_some());
            });
        });
    }

    #[test]
    fn test_ublk_uring_drop_ordering() {
        // This test verifies that the Drop implementation works correctly
        // We can't directly test Drop, but we can verify the cleanup methods work

        // Initialize the ring first since cleanup may need it
        use crate::io::ublk_init_task_ring;
        use io_uring::IoUring;
        use std::cell::RefCell;

        ublk_init_task_ring(|cell| {
            if cell.get().is_none() {
                let ring = IoUring::builder()
                    .setup_cqsize(64)
                    .build(32)
                    .map_err(crate::UblkError::IOError)?;
                cell.set(RefCell::new(ring))
                    .map_err(|_| crate::UblkError::OtherError(-libc::EEXIST))?;
            }
            Ok(())
        })
        .expect("Failed to initialize ring for test");

        // Add some test resources
        with_uring_resource_manager(|manager| {
            manager.add_queue_resources(99, &[999], 10);
        });

        // Test manual cleanup
        let cleanup_result =
            UBLK_URING.with(|ublk_uring| ublk_uring.remove_queue_from_resource_manager(99));
        assert!(cleanup_result.is_ok());

        // Verify cleanup worked
        UBLK_URING.with(|ublk_uring| {
            ublk_uring.with_resource_manager(|manager| {
                assert!(manager.get_queue_range(99).is_none());
            });
        });
    }
}
