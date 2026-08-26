//! Shared-memory zero copy (`UBLK_F_SHMEM_ZC`).
//!
//! With this feature a ublk server registers page-aligned shared mappings
//! (hugetlbfs files, memfds, …) with the driver. Whenever an application
//! issues a block request whose pages all live inside one registered buffer,
//! the driver hands the request over with `UBLK_IO_F_SHMEM_ZC` set in
//! `ublksrv_io_desc.op_flags` and, instead of a buffer address, an encoded
//! `(buffer index, byte offset)` in `ublksrv_io_desc.addr`. The kernel copies
//! nothing for such a request in either direction: the server reads or
//! writes the data through its *own* mapping of the same memory.
//!
//! The match is opportunistic and per request. Requests whose pages are not
//! in a registered buffer take the ordinary path, so a server still provides
//! its usual per-tag buffers through [`BufDesc`](crate::BufDesc); nothing in
//! the FETCH/COMMIT protocol changes.
//!
//! This module provides the pieces a target needs:
//!
//! * [`ShmemZcAddr`] decodes the encoded `addr` of a matched request.
//! * [`ShmemBuf`] owns one shared mapping the server can register.

use std::os::fd::BorrowedFd;
use std::path::Path;

use crate::{sys, UblkError};

/// The decoded `ublksrv_io_desc.addr` of a request that carries
/// `UBLK_IO_F_SHMEM_ZC`.
///
/// The wire format is `bits [0:31] = byte offset`, `bits [32:47] = buffer
/// index`, `bits [48:63] = reserved` (`UBLK_SHMEM_ZC_*` in `ublk_cmd.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShmemZcAddr {
    /// Index the driver assigned when the buffer was registered.
    pub index: u16,
    /// Byte offset of the request's data inside that buffer.
    pub offset: u32,
}

impl ShmemZcAddr {
    /// Pack `index` and `offset` the way the driver does.
    pub const fn encode(self) -> u64 {
        ((self.index as u64) << sys::UBLK_SHMEM_ZC_IDX_OFF) | self.offset as u64
    }

    /// Unpack a driver-encoded address. Reserved bits are ignored.
    pub const fn decode(addr: u64) -> Self {
        Self {
            index: ((addr >> sys::UBLK_SHMEM_ZC_IDX_OFF) & sys::UBLK_SHMEM_ZC_IDX_MASK as u64)
                as u16,
            offset: (addr & sys::UBLK_SHMEM_ZC_OFF_MASK as u64) as u32,
        }
    }

    /// Decode the address of `iod` if the driver matched the request to a
    /// registered shared buffer.
    ///
    /// Returns `None` for an ordinary request, whose `addr` is the buffer
    /// address the server itself passed in FETCH/COMMIT (or zero in user-copy
    /// mode) and must not be interpreted as an index/offset pair.
    #[inline]
    pub fn from_iod(iod: &sys::ublksrv_io_desc) -> Option<Self> {
        if iod.op_flags & sys::UBLK_IO_F_SHMEM_ZC != 0 {
            Some(Self::decode(iod.addr))
        } else {
            None
        }
    }
}

fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// One `MAP_SHARED` mapping of a shared-memory object, owned by the server.
///
/// This is what gets registered with the driver: the backing object is
/// whatever the applications that want zero copy also map — a hugetlbfs
/// file, a memfd handed over a socket, and so on. The whole object is mapped
/// from offset zero, populated up front, and unmapped on drop.
///
/// The driver requires the address and length to be page aligned, and caps
/// one buffer at 4 GiB; a length that is not a page multiple is rejected
/// here so the mistake surfaces before any registration.
#[derive(Debug)]
pub struct ShmemBuf {
    base: *mut u8,
    len: usize,
    read_only: bool,
}

// The mapping is shared with other processes and the kernel by design; the
// struct itself holds no Rust-side state a thread could observe torn.
unsafe impl Send for ShmemBuf {}
unsafe impl Sync for ShmemBuf {}

impl ShmemBuf {
    /// Map `len` bytes of `fd` from offset zero.
    ///
    /// `len == 0` maps the whole object as reported by `fstat(2)`, which is
    /// the usual case for a hugetlbfs file or a memfd that was
    /// `ftruncate(2)`d by its creator. A read-only mapping (`PROT_READ`)
    /// pairs with registering the buffer as `UBLK_SHMEM_BUF_READ_ONLY`, so
    /// the driver will only ever match WRITE requests to it.
    ///
    /// # Errors
    ///
    /// [`UblkError::InvalidVal`] if the resulting length is zero or not a
    /// page multiple; [`UblkError::IOError`] from `fstat(2)`/`mmap(2)`.
    pub fn from_fd(fd: BorrowedFd<'_>, len: usize, read_only: bool) -> Result<Self, UblkError> {
        use std::os::fd::AsRawFd;

        let raw_fd = fd.as_raw_fd();
        let len = if len == 0 {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: `st` is a valid, writable stat buffer.
            if unsafe { libc::fstat(raw_fd, &mut st) } < 0 {
                return Err(UblkError::IOError(std::io::Error::last_os_error()));
            }
            st.st_size as usize
        } else {
            len
        };
        if len == 0 || len % page_size() != 0 {
            return Err(UblkError::InvalidVal);
        }

        let prot = if read_only {
            libc::PROT_READ
        } else {
            libc::PROT_READ | libc::PROT_WRITE
        };
        // SAFETY: plain mmap of a caller-provided fd; the result is checked.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                prot,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                raw_fd,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(UblkError::IOError(std::io::Error::last_os_error()));
        }

        Ok(Self {
            base: base as *mut u8,
            len,
            read_only,
        })
    }

    /// Open `path` and map the whole object, see [`Self::from_fd`].
    ///
    /// Opens `O_RDONLY` when `read_only`, `O_RDWR` otherwise.
    pub fn open(path: &Path, read_only: bool) -> Result<Self, UblkError> {
        use std::os::fd::AsFd;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(path)?;
        Self::from_fd(file.as_fd(), 0, read_only)
    }

    /// Start of the mapping. Page aligned.
    ///
    /// The memory behind it is shared with applications and the kernel, so
    /// no `&mut [u8]` is derived from it here; targets hand the pointer to
    /// raw io_uring ops.
    #[inline]
    pub fn as_ptr(&self) -> *mut u8 {
        self.base
    }

    /// Length of the mapping in bytes. A page multiple.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// A mapping is never empty; provided for clippy's `len_without_is_empty`.
    #[inline]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether this was mapped `PROT_READ` only.
    #[inline]
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }
}

impl Drop for ShmemBuf {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` came from a successful mmap in `from_fd`.
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};

    fn memfd(size: usize) -> OwnedFd {
        let name = c"libublk-shmem-test";
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
        assert_eq!(unsafe { libc::ftruncate(fd, size as libc::off_t) }, 0);
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    #[test]
    fn zc_addr_round_trips() {
        let a = ShmemZcAddr {
            index: 0x1234,
            offset: 0xdead_b000,
        };
        assert_eq!(a.encode(), 0x1234_dead_b000);
        assert_eq!(ShmemZcAddr::decode(a.encode()), a);
    }

    #[test]
    fn zc_addr_decode_ignores_reserved_bits() {
        let a = ShmemZcAddr {
            index: 7,
            offset: 4096,
        };
        assert_eq!(ShmemZcAddr::decode(a.encode() | (0xffff << 48)), a);
    }

    #[test]
    fn zc_addr_from_iod_requires_the_flag() {
        let mut iod = sys::ublksrv_io_desc {
            op_flags: sys::UBLK_IO_OP_READ,
            addr: ShmemZcAddr {
                index: 3,
                offset: 8192,
            }
            .encode(),
            ..Default::default()
        };
        assert_eq!(ShmemZcAddr::from_iod(&iod), None);

        iod.op_flags |= sys::UBLK_IO_F_SHMEM_ZC;
        assert_eq!(
            ShmemZcAddr::from_iod(&iod),
            Some(ShmemZcAddr {
                index: 3,
                offset: 8192
            })
        );
    }

    #[test]
    fn shmem_buf_maps_whole_memfd_shared() {
        let page = page_size();
        let fd = memfd(2 * page);
        let buf = ShmemBuf::from_fd(fd.as_fd(), 0, false).unwrap();

        assert_eq!(buf.len(), 2 * page);
        assert!(!buf.is_empty());
        assert_eq!(buf.as_ptr() as usize % page, 0);
        assert!(!buf.is_read_only());

        // Written through the mapping, visible through the fd: MAP_SHARED.
        unsafe { std::ptr::write_bytes(buf.as_ptr().add(page), 0xa5, 16) };
        let mut back = [0u8; 16];
        use std::os::fd::AsRawFd;
        let n = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                back.as_mut_ptr() as *mut libc::c_void,
                16,
                page as libc::off_t,
            )
        };
        assert_eq!(n, 16);
        assert_eq!(back, [0xa5; 16]);
    }

    #[test]
    fn shmem_buf_explicit_len_and_read_only() {
        let page = page_size();
        let fd = memfd(4 * page);
        let buf = ShmemBuf::from_fd(fd.as_fd(), page, true).unwrap();
        assert_eq!(buf.len(), page);
        assert!(buf.is_read_only());
    }

    #[test]
    fn shmem_buf_rejects_unaligned_or_empty_len() {
        let page = page_size();
        let fd = memfd(page);
        assert!(matches!(
            ShmemBuf::from_fd(fd.as_fd(), page + 1, false),
            Err(UblkError::InvalidVal)
        ));

        let empty = memfd(0);
        assert!(matches!(
            ShmemBuf::from_fd(empty.as_fd(), 0, false),
            Err(UblkError::InvalidVal)
        ));
    }

    #[test]
    fn shmem_buf_open_path() {
        let page = page_size();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shmem");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(page as u64)
            .unwrap();

        let buf = ShmemBuf::open(&path, false).unwrap();
        assert_eq!(buf.len(), page);
        assert!(ShmemBuf::open(&dir.path().join("missing"), false).is_err());
    }
}
