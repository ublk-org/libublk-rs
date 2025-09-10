//! # Unified io_uring and Resource Management Module
//!
//! This module provides a unified structure for managing both io_uring instances
//! and their associated resource registrations in a thread-local context.

use super::UblkError;
use io_uring::{squeue, IoUring};
use std::cell::RefCell;
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
    pub fn new() -> Self {
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

/// Helper functions for thread-local io_uring instance management

/// Access the ring with immutable reference
pub fn with_ring<F, R>(f: F) -> R
where
    F: FnOnce(&IoUring<squeue::Entry>) -> R,
{
    UBLK_URING.with(|ring_cell| {
        let ring_ref = ring_cell.borrow();
        if let Some(ref ring) = *ring_ref {
            f(ring)
        } else {
            panic!("Queue ring not initialized. Call ublk_init_task_ring() first or create a UblkQueue.")
        }
    })
}

/// Access the ring with mutable reference
pub fn with_ring_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut IoUring<squeue::Entry>) -> R,
{
    UBLK_URING.with(|ring_cell| {
        let mut ring_ref = ring_cell.borrow_mut();
        if let Some(ref mut ring) = *ring_ref {
            f(ring)
        } else {
            panic!("Queue ring not initialized. Call ublk_init_task_ring() first or create a UblkQueue.")
        }
    })
}

/// Initialize the ring with a custom one (only when None)
pub fn set_ring(new_ring: IoUring<squeue::Entry>) -> Option<IoUring<squeue::Entry>> {
    UBLK_URING.with(|ring_cell| {
        ring_cell.replace(Some(new_ring))
    })
}

// Thread-local unified uring instance - direct RefCell<Option<IoUring<squeue::Entry>>>
std::thread_local! {
    pub(crate) static UBLK_URING: RefCell<Option<IoUring<squeue::Entry>>> = RefCell::new(None);
}

#[cfg(test)]
mod tests {
    use crate::ctrl::UblkCtrlBuilder;
    use crate::io::{UblkDev, UblkQueue};
    use crate::multi_queue::MultiQueueManager;
    use crate::UblkFlags;

    /// Verify that a queue was created correctly with proper slab key and resource allocation
    fn verify_queue_creation(
        queue: &UblkQueue,
        queue_key: usize,
        _q_id: u16,
        expected_buffer_start: u16,
    ) -> crate::uring::QueueResourceRange {
        let slab_key = queue.get_slab_key();
        assert_ne!(slab_key, crate::multi_queue::slab_key::UNUSE_KEY);
        assert!(slab_key <= crate::multi_queue::slab_key::MAX_QUEUE_KEY);
        assert_eq!(slab_key, queue_key as u16);

        let range = queue
            .get_resource_range()
            .expect("resources are not added after creating queues");

        // Check resource range for multi-queue scenarios
        assert_eq!(range.queue_slab_key, slab_key);
        assert_eq!(range.file_count, 1); // Each queue should have 1 file (cdev)
        assert_eq!(
            range.buffer_count, 64,
            "Each queue should have 64 buffers (queue_depth)"
        );
        assert_eq!(
            range.buffer_start_index, expected_buffer_start,
            "Buffer start index should be queue_id * queue_depth"
        );

        range.clone()
    }

    /// Check that resource ranges don't overlap between queues
    fn verify_no_resource_overlap(
        manager: &MultiQueueManager,
        current_range: &crate::uring::QueueResourceRange,
        current_slab_key: u16,
    ) {
        for (key, existing_queue) in manager.iter() {
            // Skip comparing with self
            if key == current_slab_key {
                continue;
            }

            if let Some(existing_range) = existing_queue.get_resource_range() {
                // File ranges should not overlap
                assert!(
                    current_range.file_start_index
                        >= existing_range.file_start_index + existing_range.file_count
                        || existing_range.file_start_index
                            >= current_range.file_start_index + current_range.file_count,
                    "File ranges overlap between queues"
                );

                // Buffer ranges should not overlap
                assert!(
                    current_range.buffer_start_index
                        >= existing_range.buffer_start_index + existing_range.buffer_count
                        || existing_range.buffer_start_index
                            >= current_range.buffer_start_index + current_range.buffer_count,
                    "Buffer ranges overlap between queues"
                );
            }
        }
    }

    /// Test index translation functionality for files and buffers
    fn verify_index_translation(manager: &MultiQueueManager) {
        if let Some((_, queue)) = manager.iter().next() {
            // Test file index translation
            let global_file_idx = queue.translate_file_index(0);
            if let Some(range) = queue.get_resource_range() {
                assert_eq!(global_file_idx, range.file_start_index);
            } else {
                assert_eq!(global_file_idx, 0); // Single queue mode
            }

            // Test buffer index translation (should always have buffers with UBLK_F_AUTO_BUF_REG)
            if let Some(range) = queue.get_resource_range() {
                assert!(
                    range.buffer_count > 0,
                    "Should have buffers with UBLK_F_AUTO_BUF_REG"
                );

                // Test buffer index translation
                let global_buffer_idx_0 = queue.translate_buffer_index(0);
                let global_buffer_idx_10 = queue.translate_buffer_index(10);
                let global_buffer_idx_63 = queue.translate_buffer_index(63);

                assert_eq!(global_buffer_idx_0, range.buffer_start_index);
                assert_eq!(global_buffer_idx_10, range.buffer_start_index + 10);
                assert_eq!(global_buffer_idx_63, range.buffer_start_index + 63);

                println!("Queue 0 buffer translations: local 0->global {}, local 10->global {}, local 63->global {}",
                        global_buffer_idx_0, global_buffer_idx_10, global_buffer_idx_63);
            }
        }
    }

    /// Verify the resource manager state through manager's embedded resource manager
    fn verify_resource_manager_state(manager: &MultiQueueManager, nr_queues: u16) {
        assert_eq!(manager.get_queue_ranges_count(), nr_queues as usize);
        assert_eq!(manager.get_files_count(), nr_queues as usize); // One file per queue
        assert!(manager.is_registered());

        // Verify total buffer count is correct (nr_queues * 64 buffers each)
        let expected_total_buffers = (nr_queues * 64) as u32;
        assert_eq!(
            manager.get_total_buffer_count(),
            expected_total_buffers,
            "Total buffer count should be nr_queues * queue_depth"
        );

        // Verify each queue has its range properly registered
        for (idx, (slab_key, _queue)) in manager.iter().enumerate() {
            let range = manager.get_queue_resource_range(slab_key);
            assert!(range.is_some(), "Queue range should be registered");

            if let Some(range) = range {
                assert_eq!(range.queue_slab_key, slab_key);
                assert_eq!(range.buffer_count, 64, "Each queue should have 64 buffers");
                assert_eq!(
                    range.buffer_start_index,
                    (idx as u16) * 64,
                    "Buffer start index should be sequential"
                );
            }
        }
    }

    /// Test queue lookup functionality through manager
    fn verify_queue_lookup(manager: &MultiQueueManager) {
        for (slab_key, _queue) in manager.iter() {
            let retrieved_range = manager.get_queue_resource_range(slab_key);
            assert!(
                retrieved_range.is_some(),
                "Should be able to retrieve queue range"
            );

            if let Some(range) = retrieved_range {
                assert_eq!(range.queue_slab_key, slab_key);
            }
        }
    }

    #[test]
    fn test_multi_queue_resource_manager_integration() {
        // Test comprehensive multi-queue resource management integration
        // This is adapted from the examples/multi_queue.rs example
        // NOTE: This test requires kernel ublk support and appropriate permissions

        let nr_queues = 4;

        // Create a ublk controller with multiple queues for testing
        // Include UBLK_F_AUTO_BUF_REG to test buffer resource registration
        let ctrl = UblkCtrlBuilder::default()
            .ctrl_flags(crate::sys::UBLK_F_AUTO_BUF_REG as u64)
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .name("test-multi-queue-resource-mgr")
            .nr_queues(nr_queues)
            .depth(64_u16) // Set queue depth for buffer testing
            .build()
            .expect("Failed to create ublk controller");

        // Test target initialization with multi-queue resource management
        let tgt_init = |dev: &mut UblkDev| {
            // Create a multi-queue manager and verify initial state
            let mut manager = MultiQueueManager::new();
            assert_eq!(manager.queue_count(), 0);
            assert!(!manager.are_resources_registered());

            // Create and verify multiple queues with automatic resource management
            for q_id in 0..nr_queues {
                let queue_key = manager.create_queue(q_id, dev)?;
                let queue = manager
                    .get_queue_by_key(queue_key)
                    .expect("Queue should exist");
                let expected_buffer_start = (q_id as u16) * 64;

                // Verify queue creation and get resource range
                let range = verify_queue_creation(queue, queue_key, q_id, expected_buffer_start);

                // Verify no resource overlap with other queues
                verify_no_resource_overlap(&manager, &range, queue.get_slab_key());
            }

            // Verify manager state and register resources
            assert_eq!(manager.queue_count(), nr_queues as usize);
            assert!(!manager.are_resources_registered());

            manager.register_resources()?;
            assert!(manager.are_resources_registered());

            // Test that double registration is safe
            let result = manager.register_resources();
            assert!(result.is_ok(), "Double registration should be safe");

            // Run comprehensive verification tests
            verify_index_translation(&manager);
            verify_resource_manager_state(&manager, nr_queues);
            verify_queue_lookup(&manager);

            Ok(())
        };

        // Create the ublk device with our multi-queue initialization
        let _dev =
            UblkDev::new(ctrl.get_name(), tgt_init, &ctrl).expect("Failed to create ublk device");
    }

    #[test]
    fn test_multi_queue_manager_resource_lifecycle() {
        // Test the basic lifecycle of MultiQueueManager's embedded resource manager
        let mut manager = MultiQueueManager::new();

        // Test initial state
        assert_eq!(manager.get_files_count(), 0);
        assert_eq!(manager.get_queue_ranges_count(), 0);
        assert!(!manager.is_registered());
        assert_eq!(manager.get_total_buffer_count(), 0);

        // Test adding resources
        let test_files = [42, 43, 44]; // Mock file descriptors
        let range1 = manager
            .add_queue_files_and_buffers(1, &test_files, 64)
            .unwrap();

        assert_eq!(range1.queue_slab_key, 1);
        assert_eq!(range1.file_start_index, 0);
        assert_eq!(range1.file_count, 3);
        assert_eq!(range1.buffer_start_index, 0);
        assert_eq!(range1.buffer_count, 64);

        // Add another queue's resources
        let test_files2 = [45];
        let range2 = manager
            .add_queue_files_and_buffers(2, &test_files2, 32)
            .unwrap();

        assert_eq!(range2.queue_slab_key, 2);
        assert_eq!(range2.file_start_index, 3); // After first queue's 3 files
        assert_eq!(range2.file_count, 1);
        assert_eq!(range2.buffer_start_index, 64); // After first queue's 64 buffers
        assert_eq!(range2.buffer_count, 32);

        // Verify accumulated state
        assert_eq!(manager.get_files_count(), 4); // 3 + 1 files
        assert_eq!(manager.get_queue_ranges_count(), 2);
        assert!(!manager.is_registered());
        assert_eq!(manager.get_total_buffer_count(), 96); // 64 + 32 buffers

        // Test range lookup
        let retrieved_range1 = manager.get_queue_resource_range(1);
        assert!(retrieved_range1.is_some());
        assert_eq!(retrieved_range1.unwrap().queue_slab_key, 1);

        let retrieved_range2 = manager.get_queue_resource_range(2);
        assert!(retrieved_range2.is_some());
        assert_eq!(retrieved_range2.unwrap().queue_slab_key, 2);

        // Test that non-existent queue returns None
        let nonexistent_range = manager.get_queue_resource_range(999);
        assert!(nonexistent_range.is_none());
    }

    #[test]
    fn test_multi_queue_manager_drop_ordering() {
        // This test verifies that the MultiQueueManager Drop implementation works correctly
        // and properly manages embedded resource lifecycle

        // Initialize the ring first since resource registration may need it
        use crate::io::ublk_init_task_ring;
        use crate::multi_queue::MultiQueueManager;
        use io_uring::IoUring;

        ublk_init_task_ring(|| {
            let ring = IoUring::builder()
                .setup_cqsize(64)
                .build(32)
                .map_err(crate::UblkError::IOError)?;
            Ok(ring)
        })
        .expect("Failed to initialize ring for test");

        // Test resource management lifecycle through MultiQueueManager
        {
            let mut manager = MultiQueueManager::new();

            // Add some test resources
            let range = manager.add_queue_files_and_buffers(99, &[999], 10).unwrap();
            assert_eq!(range.queue_slab_key, 99);
            assert_eq!(range.file_count, 1);
            assert_eq!(range.buffer_count, 10);

            // Verify resources are tracked
            assert_eq!(manager.get_files_count(), 1);
            assert_eq!(manager.get_total_buffer_count(), 10);
            assert!(!manager.is_registered());

            // Test resource lookup
            let retrieved_range = manager.get_queue_resource_range(99);
            assert!(retrieved_range.is_some());
            assert_eq!(retrieved_range.unwrap().queue_slab_key, 99);

            // Test that non-existent queue returns None
            let nonexistent_range = manager.get_queue_resource_range(999);
            assert!(nonexistent_range.is_none());

            // MultiQueueManager should clean up resources when dropped
        } // manager is dropped here, testing Drop implementation

        // After drop, resources should be cleaned up (verified through Drop implementation)
        // The Drop implementation logs warnings if resources are still registered
    }
}
