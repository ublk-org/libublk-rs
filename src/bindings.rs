// Re-export helper functions from sys crate for backward compatibility
#[allow(unused_imports)]
pub use crate::sys::{ublk_auto_buf_reg_to_sqe_addr, ublk_sqe_addr_to_auto_buf_reg};
