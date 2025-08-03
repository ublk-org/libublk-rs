use crate::sys;

#[inline(always)]
#[allow(dead_code)]
pub fn ublk_sqe_addr_to_auto_buf_reg(sqe_addr: u64) -> sys::ublk_auto_buf_reg {
    sys::ublk_auto_buf_reg {
        index: sqe_addr as u16,
        flags: (sqe_addr >> 16) as u8,
        ..Default::default()
    }
}

#[inline(always)]
pub fn ublk_auto_buf_reg_to_sqe_addr(buf: &sys::ublk_auto_buf_reg) -> u64 {
    buf.index as u64
        | (buf.flags as u64) << 16
        | (buf.reserved0 as u64) << 24
        | (buf.reserved1 as u64) << 32
}
