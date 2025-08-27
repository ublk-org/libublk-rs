use std::ops::{Deref, DerefMut};

pub fn type_of_this<T>(_: &T) -> String {
    std::any::type_name::<T>().to_string()
}

/// Slice like buffer, which address is aligned with 4096.
///
pub struct IoBuf<T> {
    ptr: *mut T,
    size: usize,
    mlocked: bool,
}

// Users of IoBuf has to deal with Send & Sync
unsafe impl<T> Send for IoBuf<T> {}
unsafe impl<T> Sync for IoBuf<T> {}

impl<T> IoBuf<T> {
    pub fn new(size: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc(layout) } as *mut T;

        assert!(size != 0);

        IoBuf {
            ptr,
            size,
            mlocked: false,
        }
    }

    pub fn new_with_mlock(size: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc(layout) } as *mut T;

        assert!(size != 0);

        let mut buf = IoBuf {
            ptr,
            size,
            mlocked: false,
        };

        // Attempt to mlock the buffer
        let mlock_result = unsafe { libc::mlock(ptr as *const libc::c_void, size) };

        if mlock_result == 0 {
            buf.mlocked = true;
        }
        // Note: We don't fail if mlock fails, as it might be due to permissions
        // or system limits. The caller can check with is_mlocked().

        buf
    }

    /// Check if the buffer is currently locked in memory
    pub fn is_mlocked(&self) -> bool {
        self.mlocked
    }

    /// how many elements in this buffer
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        let elem_size = core::mem::size_of::<T>();
        self.size / elem_size
    }

    /// Return raw address of this buffer
    pub fn as_ptr(&self) -> *const T {
        self.ptr
    }

    /// Return mutable raw address of this buffer
    pub fn as_mut_ptr(&self) -> *mut T {
        self.ptr
    }

    /// fill zero for every bits of this buffer
    pub fn zero_buf(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.as_mut_ptr(), 0, self.len());
        }
    }
}

impl<T> std::fmt::Debug for IoBuf<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ptr {:?} size {} element type {}",
            self.ptr,
            self.size,
            type_of_this(unsafe { &*self.ptr })
        )
    }
}

/// Slice reference of this buffer
impl<T> Deref for IoBuf<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        let elem_size = core::mem::size_of::<T>();
        unsafe { std::slice::from_raw_parts(self.ptr, self.size / elem_size) }
    }
}

/// Mutable slice reference of this buffer
impl<T> DerefMut for IoBuf<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        let elem_size = core::mem::size_of::<T>();
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size / elem_size) }
    }
}

/// Free buffer with same alloc layout
impl<T> Drop for IoBuf<T> {
    fn drop(&mut self) {
        // munlock the buffer if it was mlocked
        if self.mlocked {
            unsafe {
                libc::munlock(self.ptr as *const libc::c_void, self.size);
            }
        }

        let layout = std::alloc::Layout::from_size_align(self.size, 4096).unwrap();
        unsafe { std::alloc::dealloc(self.ptr as *mut u8, layout) };
    }
}

#[macro_export]
macro_rules! zero_io_buf {
    ($buffer:expr) => {{
        unsafe {
            std::ptr::write_bytes($buffer.as_mut_ptr(), 0, $buffer.len());
        }
    }};
}
