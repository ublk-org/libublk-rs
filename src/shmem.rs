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
//! * [`ShmemBufs`] keeps the registered mappings by driver index and turns a
//!   matched request into a pointer into the right one.

use std::os::fd::BorrowedFd;
use std::path::Path;
use std::sync::{Mutex, RwLock};

use crate::ctrl::UblkCtrl;
use crate::ctrl_async::UblkCtrlAsync;
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

/// The shared buffers one device has registered, by driver index.
///
/// Queue handlers on every queue thread resolve matched requests against
/// this table, while registration happens from whoever drives the control
/// device -- before `START_DEV`, or later at runtime when an application
/// hands over a new memfd. A `RwLock` keeps both correct; the per-request
/// read lock is uncontended in practice.
///
/// Indexes are assigned by the driver (lowest free, so they stay small) and
/// the table grows to fit. It never unregisters on drop: a mapping that is
/// still registered when this goes away is a caller error, and the driver
/// releases everything on device removal anyway.
///
/// Registering and unregistering are serialized against each other by a
/// control-side lock, separate from the table lock: the driver recycles a
/// freed index immediately, so an unregister racing a register could file
/// the newcomer under the slot being emptied. The table lock itself is
/// never held across a driver command, because the queue freeze inside
/// that command waits for queue threads which need [`Self::resolve`].
#[derive(Debug, Default)]
pub struct ShmemBufs {
    bufs: RwLock<Vec<Option<ShmemBuf>>>,
    ctl: Mutex<()>,
}

/// Keeps a mapping alive if the future registering it is dropped mid-flight.
///
/// REG_BUF runs on io-wq after submission returns, so a cancelled
/// registration may still be pinning the mapping's pages -- or, had the
/// range been unmapped and reused, somebody else's. Leaking the mapping
/// (bounded by its size, until the process exits) is the safe outcome.
struct KeepOnCancel(Option<ShmemBuf>);

impl KeepOnCancel {
    fn take(mut self) -> ShmemBuf {
        self.0.take().expect("mapping taken once")
    }
}

impl Drop for KeepOnCancel {
    fn drop(&mut self) {
        if let Some(buf) = self.0.take() {
            std::mem::forget(buf);
        }
    }
}

impl ShmemBufs {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `buf` with the device behind `ctrl` and take ownership of
    /// the mapping under the index the driver assigned.
    ///
    /// See [`UblkCtrl::register_shmem_buf`] for the driver-side semantics,
    /// errors, and the queue freeze this implies on a live device.
    pub fn register(&self, ctrl: &UblkCtrl, buf: ShmemBuf) -> Result<u16, UblkError> {
        let _ctl = self.ctl.lock().unwrap_or_else(|e| e.into_inner());
        let index = ctrl.register_shmem_buf(&buf)?;
        self.insert(index, buf);
        Ok(index)
    }

    /// Async counterpart of [`Self::register`].
    ///
    /// Dropping the returned future before it completes leaks `buf`'s
    /// mapping rather than unmapping it: the driver may still be pinning
    /// those pages (see [`UblkCtrlAsync::register_shmem_buf_async`]).
    // The control lock is held across the await on purpose: it only
    // serializes register/unregister against each other, and the awaited
    // command is the very thing that needs serializing.
    #[allow(clippy::await_holding_lock)]
    pub async fn register_async(
        &self,
        ctrl: &UblkCtrlAsync,
        buf: ShmemBuf,
    ) -> Result<u16, UblkError> {
        let _ctl = self.ctl.lock().unwrap_or_else(|e| e.into_inner());
        let keep = KeepOnCancel(Some(buf));
        let res = ctrl
            .register_shmem_buf_async(keep.0.as_ref().unwrap())
            .await;
        // completed (either way): the mapping is ours to drop again
        let buf = keep.take();
        let index = res?;
        self.insert(index, buf);
        Ok(index)
    }

    /// Unregister `index` from the device and hand its mapping back.
    ///
    /// Only indexes this table registered are accepted; anything else is
    /// `ENOENT` without touching the driver. Nothing in flight references
    /// the returned mapping any more (see
    /// [`UblkCtrl::unregister_shmem_buf`]), so it may simply be dropped.
    pub fn unregister(&self, ctrl: &UblkCtrl, index: u16) -> Result<ShmemBuf, UblkError> {
        let _ctl = self.ctl.lock().unwrap_or_else(|e| e.into_inner());
        self.check_registered(index)?;
        ctrl.unregister_shmem_buf(index)?;
        self.take(index).ok_or(UblkError::OtherError(-libc::ENOENT))
    }

    /// Async counterpart of [`Self::unregister`].
    #[allow(clippy::await_holding_lock)] // see register_async
    pub async fn unregister_async(
        &self,
        ctrl: &UblkCtrlAsync,
        index: u16,
    ) -> Result<ShmemBuf, UblkError> {
        let _ctl = self.ctl.lock().unwrap_or_else(|e| e.into_inner());
        self.check_registered(index)?;
        ctrl.unregister_shmem_buf_async(index).await?;
        self.take(index).ok_or(UblkError::OtherError(-libc::ENOENT))
    }

    /// File `buf` under `index` without talking to the driver.
    ///
    /// Registrations belong to the device, not to the process that made
    /// them, so they survive a ublk server restart: a server recovering a
    /// device with `UBLK_F_USER_RECOVERY` maps the same shared object again
    /// and adopts it under the index it recorded before, and requests keep
    /// matching without any REG_BUF/UNREG_BUF round trip (which could not
    /// be issued anyway: the driver freezes the queue for those, and a
    /// quiesced queue full of requeued requests never drains).
    ///
    /// `buf` must map the very same pages the driver pinned under `index`;
    /// adopting anything else serves wrong data. A mapping already held
    /// under `index` is replaced and returned.
    pub fn adopt(&self, index: u16, buf: ShmemBuf) -> Option<ShmemBuf> {
        let mut bufs = self.bufs.write().unwrap();
        let slot = index as usize;
        if bufs.len() <= slot {
            bufs.resize_with(slot + 1, || None);
        }
        bufs[slot].replace(buf)
    }

    /// Number of registered buffers.
    pub fn len(&self) -> usize {
        self.bufs
            .read()
            .unwrap()
            .iter()
            .filter(|b| b.is_some())
            .count()
    }

    /// Whether nothing is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The data pointer for a request the driver matched to one of these
    /// buffers.
    ///
    /// Returns `None` for an ordinary request (no `UBLK_IO_F_SHMEM_ZC`), for
    /// an index this table does not hold, and when
    /// `offset + nr_sectors * 512` runs past the end of the mapping, so a
    /// handler can treat every `None` on a flagged request as `EINVAL`.
    ///
    /// The pointer stays valid for as long as the mapping is registered
    /// here; the memory behind it is shared with the application that
    /// issued the request.
    #[inline]
    pub fn resolve(&self, iod: &sys::ublksrv_io_desc) -> Option<*mut u8> {
        let zc = ShmemZcAddr::from_iod(iod)?;
        let bytes = (iod.nr_sectors as usize) << 9;
        let bufs = self.bufs.read().unwrap();
        let buf = bufs.get(zc.index as usize)?.as_ref()?;
        let end = (zc.offset as usize).checked_add(bytes)?;
        if end > buf.len() {
            return None;
        }
        // SAFETY: offset + bytes <= len, checked above.
        Some(unsafe { buf.as_ptr().add(zc.offset as usize) })
    }

    fn insert(&self, index: u16, buf: ShmemBuf) {
        let replaced = self.adopt(index, buf);
        debug_assert!(replaced.is_none(), "driver handed out a live index");
    }

    fn take(&self, index: u16) -> Option<ShmemBuf> {
        self.bufs.write().unwrap().get_mut(index as usize)?.take()
    }

    fn check_registered(&self, index: u16) -> Result<(), UblkError> {
        match self.bufs.read().unwrap().get(index as usize) {
            Some(Some(_)) => Ok(()),
            _ => Err(UblkError::OtherError(-libc::ENOENT)),
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

    fn zc_iod(index: u16, offset: u32, bytes: u32) -> sys::ublksrv_io_desc {
        sys::ublksrv_io_desc {
            op_flags: sys::UBLK_IO_OP_WRITE | sys::UBLK_IO_F_SHMEM_ZC,
            nr_sectors: bytes >> 9,
            addr: ShmemZcAddr { index, offset }.encode(),
            ..Default::default()
        }
    }

    #[test]
    fn shmem_bufs_resolve_points_into_the_right_mapping() {
        let page = page_size();
        let fd0 = memfd(2 * page);
        let fd3 = memfd(page);
        let table = ShmemBufs::new();
        assert!(table.is_empty());

        // Driver indexes need not be dense: the table grows to fit.
        table.insert(0, ShmemBuf::from_fd(fd0.as_fd(), 0, false).unwrap());
        table.insert(3, ShmemBuf::from_fd(fd3.as_fd(), 0, false).unwrap());
        assert_eq!(table.len(), 2);

        let base0 = table.bufs.read().unwrap()[0].as_ref().unwrap().as_ptr();
        let base3 = table.bufs.read().unwrap()[3].as_ref().unwrap().as_ptr();

        assert_eq!(
            table.resolve(&zc_iod(0, page as u32, 4096)),
            Some(unsafe { base0.add(page) })
        );
        assert_eq!(table.resolve(&zc_iod(3, 0, page as u32)), Some(base3));
    }

    #[test]
    fn shmem_bufs_resolve_rejects_what_it_cannot_serve() {
        let page = page_size();
        let fd = memfd(page);
        let table = ShmemBufs::new();
        table.insert(1, ShmemBuf::from_fd(fd.as_fd(), 0, false).unwrap());

        // ordinary request: not for this table, whatever addr holds
        let mut plain = zc_iod(1, 0, 4096);
        plain.op_flags &= !sys::UBLK_IO_F_SHMEM_ZC;
        assert_eq!(table.resolve(&plain), None);

        // unknown indexes, inside and beyond the table's length
        assert_eq!(table.resolve(&zc_iod(0, 0, 4096)), None);
        assert_eq!(table.resolve(&zc_iod(9, 0, 4096)), None);

        // the last sector fits, one more does not, and offsets past the end
        // or overflowing usize are refused
        assert!(table
            .resolve(&zc_iod(1, (page - 512) as u32, 512))
            .is_some());
        assert_eq!(table.resolve(&zc_iod(1, (page - 512) as u32, 1024)), None);
        assert_eq!(table.resolve(&zc_iod(1, page as u32, 512)), None);
        assert_eq!(table.resolve(&zc_iod(1, u32::MAX, 512)), None);

        // adopt() publishes without the driver and hands back what it displaces
        let other = ShmemBuf::from_fd(memfd(page).as_fd(), 0, false).unwrap();
        let other_ptr = other.as_ptr();
        let displaced = table.adopt(1, other).unwrap();
        assert_ne!(displaced.as_ptr(), other_ptr);
        assert_eq!(table.resolve(&zc_iod(1, 0, 512)), Some(other_ptr));
        drop(displaced);

        // gone after take(): a stale index resolves to nothing
        assert!(table.take(1).is_some());
        assert!(table.take(1).is_none());
        assert_eq!(table.resolve(&zc_iod(1, 0, 512)), None);
        assert!(matches!(
            table.check_registered(1),
            Err(UblkError::OtherError(e)) if e == -libc::ENOENT
        ));
    }

    #[test]
    fn keep_on_cancel_leaks_instead_of_unmapping() {
        let page = page_size();
        let fd = memfd(page);
        let buf = ShmemBuf::from_fd(fd.as_fd(), 0, false).unwrap();
        let ptr = buf.as_ptr();
        unsafe { *ptr = 0x5a };

        // dropped like a cancelled future: the mapping must survive
        drop(KeepOnCancel(Some(buf)));
        assert_eq!(unsafe { *ptr }, 0x5a);

        // taken after completion: an ordinary, droppable mapping again
        let buf = ShmemBuf::from_fd(fd.as_fd(), 0, false).unwrap();
        let keep = KeepOnCancel(Some(buf));
        let buf = keep.take();
        assert_eq!(buf.len(), page);
        drop(buf);
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
