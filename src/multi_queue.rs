//! Multi-Queue Support Module
//!
//! This module provides multi-queue functionality for handling multiple ublk queues
//! within a single thread context. It uses a slab-based approach for efficient queue
//! lookup and routing.
//!
//! ## Key Components
//!
//! - **Slab Key Management**: Constants and utilities for managing 10-bit slab keys
//! - **Queue Storage**: Thread-local slab for storing queue references
//! - **MultiQueueManager**: Automatic lifecycle management for multiple queues
//!
//! ## Basic Usage
//!
//! ```no_run
//! use libublk::multi_queue::{MultiQueueManager};
//! use libublk::io::{UblkQueue, UblkDev};
//!
//! fn example(dev: &UblkDev) -> Result<(), libublk::UblkError> {
//!     let mut manager = MultiQueueManager::new();
//!
//!     // Create queues with automatic registration
//!     for q_id in 0..4 {
//!         let queue_key = manager.create_queue(q_id, dev)?;
//!         // Access queue via manager.get_queue_by_key(queue_key)
//!     }
//!
//!     println!("Managing {} queues", manager.queue_count());
//!     Ok(())
//! }
//! ```

use crate::io::{register_all_uring_resources, UblkDev, UblkQueue};
use crate::uring::QueueResourceRange;
use crate::UblkError;
use slab::Slab;
use std::rc::Rc;

/// Multi-queue slab key constants
#[allow(dead_code)]
pub(crate) mod slab_key {
    /// Maximum valid queue slab key (0-1021 are valid)
    pub const MAX_QUEUE_KEY: u16 = 1020;

    /// Reserved slab key for future use
    pub const RESERVED: u16 = 1021;

    /// Special slab key indicating control command
    pub const CONTROL_CMD: u16 = 1022;

    /// Special slab key indicating we are not using slab key
    pub const UNUSE_KEY: u16 = 1023;

    /// Total number of possible slab keys (10-bit = 1024)
    pub const TOTAL_KEYS: u16 = 1024;

    /// Check if a slab key is valid for queue registration
    #[inline]
    pub fn is_valid_queue_key(key: u16) -> bool {
        key <= MAX_QUEUE_KEY
    }

    /// Check if a slab key indicates a control command
    #[inline]
    pub fn is_control_cmd(key: u16) -> bool {
        key == CONTROL_CMD
    }
}

/// Multi-queue manager for coordinating multiple queues
///
/// This manager handles automatic allocation and cleanup of queues for
/// multi-queue operations. Queues created with `manager.create_queue()` are
/// automatically stored and managed, and will be cleaned up when the manager is dropped.
/// Uses a Slab for stable queue keys that don't change when other queues are removed.
pub struct MultiQueueManager<'a> {
    resources_registered: bool,
    /// Managed queue storage - manager owns all queues with stable slab keys
    queue_registry: Slab<Rc<UblkQueue<'a>>>,
}

impl<'a> MultiQueueManager<'a> {
    /// Create a new multi-queue manager
    pub fn new() -> Self {
        Self {
            resources_registered: false,
            queue_registry: Slab::new(),
        }
    }

    /// Create a new queue and add it to the manager
    ///
    /// Creates a new UblkQueue using UblkQueue::new_multi() and stores it in the
    /// manager's queue registry. Returns the stable slab key that can be used to reference
    /// the queue via get_queue_by_key(). The slab key remains valid until the queue is
    /// explicitly removed, even if other queues are removed.
    ///
    /// # Arguments
    /// * `q_id`: Queue ID
    /// * `dev`: UblkDev reference
    ///
    /// # Returns
    /// Stable slab key of the created queue in the registry, or error on failure
    pub fn create_queue<'b>(&mut self, q_id: u16, dev: &'b UblkDev) -> Result<usize, UblkError>
    where
        'b: 'a, // dev must outlive the manager's lifetime
    {
        // Insert into slab to get a stable key, then create queue with that key
        let slab_key = self.queue_registry.vacant_entry().key();
        let mut queue = UblkQueue::new_multi(q_id, dev, slab_key as u16)?;

        queue.add_resources(self, slab_key.try_into().unwrap())?;

        let inserted_key = self.queue_registry.insert(Rc::new(queue));
        assert_eq!(slab_key, inserted_key); // Verify the key matches
        Ok(slab_key)
    }

    /// Remove a queue from the manager by slab key
    ///
    /// # Arguments
    /// * `slab_key`: The stable slab key of the queue to remove
    ///
    /// # Returns
    /// Ok(()) if the queue was successfully removed, or error if the key is invalid
    pub fn remove_queue(&mut self, slab_key: u16) -> Result<(), UblkError> {
        let key = slab_key as usize;
        if self.queue_registry.contains(key) {
            self.queue_registry.remove(key);
            Ok(())
        } else {
            Err(UblkError::OtherError(-libc::ENOENT))
        }
    }

    /// Get all managed queue keys (stable slab keys as u16)
    pub fn get_queue_keys(&self) -> Vec<u16> {
        self.queue_registry
            .iter()
            .map(|(key, _)| key as u16)
            .collect()
    }

    /// Get the number of managed queues
    pub fn queue_count(&self) -> usize {
        self.queue_registry.len()
    }

    /// Add queue resources to the centralized io_uring resource manager
    ///
    /// This method accumulates files and buffer requirements from a queue
    /// into the thread-local io_uring resource manager. Resources are not actually
    /// registered with io_uring until `register_resources()` is called.
    ///
    /// # Arguments
    /// * `queue_slab_key`: The slab key of the queue
    /// * `files`: File descriptors that this queue needs registered
    /// * `buffer_count`: Number of buffers this queue needs for auto buffer registration
    ///
    /// # Returns
    /// The resource range allocated to this queue
    pub fn add_queue_files_and_buffers(
        &mut self,
        queue_slab_key: u16,
        files: &[std::os::unix::io::RawFd],
        buffer_count: u32,
    ) -> Result<QueueResourceRange, UblkError> {
        if self.resources_registered {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

        let range = crate::uring::with_uring_resource_manager(|manager| {
            manager.add_queue_resources(queue_slab_key, files, buffer_count)
        });
        Ok(range)
    }

    /// Register all accumulated resources with the io_uring instance
    ///
    /// This method performs the batch registration of all files and buffers
    /// that have been accumulated via `add_queue_files_and_buffers()` calls.
    /// It must be called after all queues have been created and before any
    /// queue operations begin.
    ///
    /// # Returns
    /// * `Ok(())` - Resources successfully registered
    /// * `Err(UblkError)` - Registration failed (e.g., io_uring not initialized)
    pub fn register_resources(&mut self) -> Result<(), UblkError> {
        if self.resources_registered {
            return Ok(()); // Already registered
        }

        register_all_uring_resources()?;
        self.resources_registered = true;
        log::debug!(
            "MultiQueueManager: Resources registered for {} queues",
            self.queue_registry.len()
        );
        Ok(())
    }

    /// Check if resources have been registered
    pub fn are_resources_registered(&self) -> bool {
        self.resources_registered
    }

    /// Get a queue reference by slab key from this manager
    ///
    /// # Arguments
    /// * `slab_key`: The stable slab key of the queue in the registry
    ///
    /// # Returns
    /// Reference to the queue if found, None otherwise
    pub fn get_queue_by_key(&self, slab_key: usize) -> Option<&Rc<UblkQueue>> {
        self.queue_registry.get(slab_key)
    }

    /// Get the number of registered queues
    pub fn get_registered_queue_count(&self) -> usize {
        self.queue_registry.len()
    }
}

impl<'a> Drop for MultiQueueManager<'a> {
    /// Automatically clean up all managed queues when the manager is dropped
    fn drop(&mut self) {
        let queue_count = self.queue_registry.len();
        self.queue_registry.clear();
        log::debug!(
            "MultiQueueManager dropped, cleaned up {} queues",
            queue_count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::slab_key;
    use crate::io::UblkIOCtx;
    use crate::multi_queue::MultiQueueManager;

    #[test]
    fn test_multi_queue_slab_operations() {
        // Test basic slab operations
        let manager = MultiQueueManager::new();

        // Initially no queues should be registered
        assert_eq!(manager.queue_count(), 0);

        // Test user_data encoding/decoding with 10-bit slab keys
        let tag = 42u16;
        let tgt_data = 0x34u32; // 16-bit value that fits in the field
        let slab_key = 123u16; // 10-bit value (valid queue key)
        let is_target = true;

        // Build user_data with direct encoding (same as UblkUringOpFuture::new)
        let user_data = tag as u64
            | (tgt_data << 16) as u64
            | ((slab_key as u64) << 48)
            | ((is_target as u64) << 63);

        // Verify encoding/decoding
        assert_eq!(UblkIOCtx::user_data_to_tag(user_data), tag as u32);
        assert_eq!(UblkIOCtx::user_data_to_slab_key(user_data), slab_key);

        // Test the is_target_io flag by checking both values
        let non_target_data =
            tag as u64 | (tgt_data << 16) as u64 | ((slab_key as u64) << 48) | (0u64 << 63); // false = 0
        let target_data =
            tag as u64 | (tgt_data << 16) as u64 | ((slab_key as u64) << 48) | (1u64 << 63); // true = 1

        // Both should decode to the same values except for the target flag
        assert_eq!(UblkIOCtx::user_data_to_slab_key(non_target_data), slab_key);
        assert_eq!(UblkIOCtx::user_data_to_slab_key(target_data), slab_key);

        // Verify target flag differences
        assert_ne!(non_target_data & (1u64 << 63), target_data & (1u64 << 63));

        // Test slab key constants and validation
        assert!(slab_key::is_valid_queue_key(0));
        assert!(slab_key::is_valid_queue_key(slab_key::MAX_QUEUE_KEY));
        assert!(!slab_key::is_valid_queue_key(slab_key::RESERVED));
        assert!(!slab_key::is_valid_queue_key(slab_key::CONTROL_CMD));
        assert!(slab_key::is_control_cmd(slab_key::CONTROL_CMD));
        assert!(!slab_key::is_control_cmd(123));

        // Test with control command slab key
        let control_data = tag as u64
            | (tgt_data << 16) as u64
            | ((slab_key::CONTROL_CMD as u64) << 48)
            | ((is_target as u64) << 63);
        assert_eq!(
            UblkIOCtx::user_data_to_slab_key(control_data),
            slab_key::CONTROL_CMD
        );
    }
}
