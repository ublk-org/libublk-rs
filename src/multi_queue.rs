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
//!     let mut queues = Vec::new();
//!
//!     // Create queues with automatic registration
//!     for q_id in 0..4 {
//!         let queue = UblkQueue::new_multi(q_id, dev, &mut manager)?;
//!         queues.push(queue);
//!     }
//!
//!     println!("Managing {} queues", manager.queue_count());
//!     Ok(())
//! }
//! ```

use crate::io::UblkQueue;
use crate::UblkError;
use std::cell::RefCell;

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

// Thread-local slab for storing queue references in multi-queue scenarios
// Uses raw pointers to allow non-static lifetimes within a controlled scope
std::thread_local! {
    static QUEUE_SLAB: RefCell<slab::Slab<*const ()>> =
        RefCell::new(slab::Slab::new());
}

/// Multi-queue manager for coordinating multiple queues
///
/// This manager handles automatic allocation and cleanup of slab entries for
/// multi-queue operations. Queues created with `UblkQueue::new_multi()` are
/// automatically registered and will be unregistered when the manager is dropped.
#[derive(Debug, Default)]
pub struct MultiQueueManager {
    queue_keys: Vec<u16>,
}

impl MultiQueueManager {
    /// Create a new multi-queue manager
    pub fn new() -> Self {
        Self {
            queue_keys: Vec::new(),
        }
    }

    /// Remove a queue from the manager
    pub fn remove_queue(&mut self, slab_key: u16) -> Result<(), UblkError> {
        Self::unregister_queue(slab_key)?;
        self.queue_keys.retain(|&key| key != slab_key);
        Ok(())
    }

    /// Remove the queue slot from the manager
    pub(crate) fn remove_queue_slot(&mut self, slab_key: u16) -> Result<(), UblkError> {
        self.remove_queue(slab_key)
    }

    /// Allocate a queue slot efficiently using vacant_entry()
    ///
    /// This method is used internally by `UblkQueue::new_multi()` to pre-allocate
    /// a slab entry before queue creation.
    pub(crate) fn allocate_queue_slot(&mut self) -> Result<u16, UblkError> {
        QUEUE_SLAB.with(|slab_cell| {
            let mut slab = slab_cell.borrow_mut();

            if slab.len() >= slab_key::MAX_QUEUE_KEY as usize {
                return Err(UblkError::OtherError(-libc::ENOSPC));
            }

            let entry = slab.vacant_entry();
            let key = entry.key();

            if key > slab_key::MAX_QUEUE_KEY as usize {
                return Err(UblkError::OtherError(-libc::ENOSPC));
            }

            // Reserve the slot with a placeholder
            entry.insert(std::ptr::null());

            Ok(key as u16)
        })
    }

    /// Register a queue at the pre-allocated slot
    ///
    /// This method is used internally by `UblkQueue::new_multi()` to register
    /// the queue after it has been created.
    pub(crate) fn register_queue_at_slot(
        &mut self,
        queue: &UblkQueue,
        slab_key: u16,
    ) -> Result<(), UblkError> {
        QUEUE_SLAB.with(|slab_cell| {
            let mut slab = slab_cell.borrow_mut();

            // Update the placeholder with the actual queue pointer
            if let Some(slot) = slab.get_mut(slab_key as usize) {
                *slot = queue as *const UblkQueue as *const ();
                self.queue_keys.push(slab_key);
                Ok(())
            } else {
                Err(UblkError::OtherError(-libc::ENOENT))
            }
        })
    }

    /// Get all managed queue keys
    pub fn get_queue_keys(&self) -> &[u16] {
        &self.queue_keys
    }

    /// Get the number of managed queues
    pub fn queue_count(&self) -> usize {
        self.queue_keys.len()
    }

    /// Unregister a queue from multi-queue handling (internal function)
    fn unregister_queue(slab_key: u16) -> Result<(), UblkError> {
        if !slab_key::is_valid_queue_key(slab_key) {
            return Err(UblkError::OtherError(-libc::EINVAL));
        }

        QUEUE_SLAB.with(|slab_cell| {
            let mut slab = slab_cell.borrow_mut();

            match slab.try_remove(slab_key as usize) {
                Some(_) => Ok(()),
                None => Err(UblkError::OtherError(-libc::ENOENT)),
            }
        })
    }

    /// Get a queue reference by slab key
    ///
    /// # Arguments
    /// * `slab_key`: The slab key for the queue
    ///
    /// # Returns
    /// Reference to the queue if found, None otherwise
    pub fn get_queue_by_key(slab_key: u16) -> Option<&'static UblkQueue<'static>> {
        if !slab_key::is_valid_queue_key(slab_key) {
            return None;
        }

        QUEUE_SLAB.with(|slab_cell| {
            let slab = slab_cell.borrow();
            slab.get(slab_key as usize).map(|queue_ptr| {
                // SAFETY: The pointer is valid as long as the caller ensures proper usage
                unsafe { &*(*queue_ptr as *const UblkQueue) }
            })
        })
    }

    /// Get the number of registered queues
    pub fn get_registered_queue_count() -> usize {
        QUEUE_SLAB.with(|slab_cell| {
            let slab = slab_cell.borrow();
            slab.len()
        })
    }
}

impl Drop for MultiQueueManager {
    /// Automatically unregister all managed queues when the manager is dropped
    fn drop(&mut self) {
        for &slab_key in &self.queue_keys {
            if let Err(e) = Self::unregister_queue(slab_key) {
                log::warn!(
                    "Failed to unregister queue with slab key {}: {:?}",
                    slab_key,
                    e
                );
            }
        }
        self.queue_keys.clear();
        log::debug!(
            "MultiQueueManager dropped, unregistered {} queues",
            self.queue_keys.len()
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

        // Initially no queues should be registered
        assert_eq!(MultiQueueManager::get_registered_queue_count(), 0);

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
