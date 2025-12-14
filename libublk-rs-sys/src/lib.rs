//! # libublk-rs-sys
//!
//! Low-level FFI bindings for the Linux ublk (userspace block device) kernel interface.
//!
//! This crate provides raw, unsafe bindings to the ublk kernel API. These bindings are
//! automatically generated from the kernel headers using bindgen.
//!
//! ## Usage
//!
//! This is a `-sys` crate, which means it provides low-level FFI bindings without safe
//! wrappers. If you're looking for a safe, high-level API, consider using the `libublk`
//! crate instead.
//!
//! These bindings allow you to:
//! - Issue ublk control commands to create/delete/manage ublk devices
//! - Handle I/O operations on ublk queues
//! - Configure device parameters
//! - Use your own io_uring instance for handling ublk operations
//!
//! ## Example
//!
//! ```rust,no_run
//! use libublk_rs_sys::*;
//! use std::os::fd::AsRawFd;
//!
//! // Open the ublk control device
//! let ctrl_fd = unsafe {
//!     libc::open(
//!         b"/dev/ublk-control\0".as_ptr() as *const i8,
//!         libc::O_RDWR,
//!     )
//! };
//!
//! // Use the raw bindings with your own io_uring instance...
//! ```
//!
//! ## Safety
//!
//! All functions and types in this crate are unsafe to use and require careful attention
//! to the ublk kernel API documentation. Improper use can lead to undefined behavior,
//! kernel panics, or data corruption.
//!
//! See the [Linux kernel documentation](https://docs.kernel.org/block/ublk.html) and
//! the ublk header file for more information.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/ublk_cmd.rs"));

/// Convert a packed u64 sqe address to an `ublk_auto_buf_reg` structure.
///
/// This function unpacks the automatic buffer registration data from the format
/// used in io_uring sqe->addr field.
///
/// # Format
/// - bits 0-15: buffer index
/// - bits 16-23: flags
/// - bits 24-31: reserved0
/// - bits 32-63: reserved1
#[inline(always)]
pub fn ublk_sqe_addr_to_auto_buf_reg(sqe_addr: u64) -> ublk_auto_buf_reg {
    ublk_auto_buf_reg {
        index: sqe_addr as u16,
        flags: (sqe_addr >> 16) as u8,
        ..Default::default()
    }
}

/// Convert an `ublk_auto_buf_reg` structure to a packed u64 sqe address.
///
/// This function packs automatic buffer registration data into the format
/// used in io_uring sqe->addr field for `UBLK_F_AUTO_BUF_REG`.
///
/// # Format
/// - bits 0-15: buffer index
/// - bits 16-23: flags
/// - bits 24-31: reserved0
/// - bits 32-63: reserved1
#[inline(always)]
pub fn ublk_auto_buf_reg_to_sqe_addr(buf: &ublk_auto_buf_reg) -> u64 {
    buf.index as u64
        | (buf.flags as u64) << 16
        | (buf.reserved0 as u64) << 24
        | (buf.reserved1 as u64) << 32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_buf_reg_conversion() {
        // Test round-trip conversion
        let orig = ublk_auto_buf_reg {
            index: 0x1234,
            flags: 0xAB,
            reserved0: 0xCD,
            reserved1: 0xDEADBEEF,
        };

        let packed = ublk_auto_buf_reg_to_sqe_addr(&orig);
        let unpacked = ublk_sqe_addr_to_auto_buf_reg(packed);

        assert_eq!(unpacked.index, orig.index);
        assert_eq!(unpacked.flags, orig.flags);
        // Note: reserved fields are not preserved in the unpacking from sqe_addr
        // as the current implementation uses Default::default() for them
    }

    #[test]
    fn test_sqe_addr_packing() {
        let buf = ublk_auto_buf_reg {
            index: 0x00FF,
            flags: 0x12,
            reserved0: 0x34,
            reserved1: 0x56789ABC,
        };

        let packed = ublk_auto_buf_reg_to_sqe_addr(&buf);

        // Verify bit layout:
        // bits 0-15: index (0x00FF)
        // bits 16-23: flags (0x12)
        // bits 24-31: reserved0 (0x34)
        // bits 32-63: reserved1 (0x56789ABC)
        assert_eq!(packed & 0xFFFF, 0x00FF);
        assert_eq!((packed >> 16) & 0xFF, 0x12);
        assert_eq!((packed >> 24) & 0xFF, 0x34);
        assert_eq!((packed >> 32) & 0xFFFFFFFF, 0x56789ABC);
    }
}
