//! Userspace Pointer Abstraction
//! TODO: All these pointer operations must be aware of the differences between
//! kernel and user spaces and between VTL0 and VTL1 for
//! additional sanity checks and extra mode switches (e.g., SMAP/SMEP)

use litebox::platform::{RawConstPointer, RawMutPointer};

/// Represent a user space pointer to a read-only object
#[repr(C)]
#[derive(Clone)]
pub struct UserConstPtr<T> {
    pub inner: *const T,
}

impl<T: Clone> core::fmt::Debug for UserConstPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("UserConstPtr").field(&self.inner).finish()
    }
}

unsafe fn read_at_offset<'a, T: Clone>(
    ptr: *const T,
    count: isize,
) -> Option<alloc::borrow::Cow<'a, T>> {
    if ptr.is_null() {
        return None;
    }
    if ptr.is_aligned() {
        Some(alloc::borrow::Cow::Borrowed(unsafe { &*ptr.offset(count) }))
    } else {
        // TODO: consider whether we should use `litebox_platform_linux_kernel`'s `memcpy_fallible`.
        // `litebox_platform_lvbs` currently preallocates all memory, so there would be no page fault.
        let mut buffer = core::mem::MaybeUninit::<T>::uninit();
        let buffer = unsafe {
            core::ptr::copy_nonoverlapping(
                ptr.offset(count).cast::<u8>(),
                buffer.as_mut_ptr().cast::<u8>(),
                core::mem::size_of::<T>(),
            );
            buffer.assume_init()
        };
        Some(alloc::borrow::Cow::Owned(buffer))
    }
}

unsafe fn to_cow_slice<'a, T: Clone>(
    ptr: *const T,
    len: usize,
) -> Option<alloc::borrow::Cow<'a, [T]>> {
    if ptr.is_null() {
        return None;
    }
    if len == 0 {
        return Some(alloc::borrow::Cow::Owned(alloc::vec::Vec::new()));
    }
    if ptr.is_aligned() {
        Some(alloc::borrow::Cow::Borrowed(unsafe {
            core::slice::from_raw_parts(ptr, len)
        }))
    } else {
        // TODO: consider whether we should need `litebox_platform_linux_kernel`'s `memcpy_fallible`.
        // `litebox_platform_lvbs` currently preallocates all memory, so there would be no page fault.
        let mut buffer = alloc::vec::Vec::<T>::with_capacity(len);
        unsafe {
            core::ptr::copy_nonoverlapping(
                ptr.cast::<u8>(),
                buffer.as_mut_ptr().cast::<u8>(),
                len * core::mem::size_of::<T>(),
            );
            buffer.set_len(len);
        }
        Some(alloc::borrow::Cow::Owned(buffer))
    }
}

impl<T: Clone> Copy for UserConstPtr<T> {}
impl<T: Clone> RawConstPointer<T> for UserConstPtr<T> {
    unsafe fn read_at_offset<'a>(self, count: isize) -> Option<alloc::borrow::Cow<'a, T>> {
        unsafe { read_at_offset(self.inner, count) }
    }

    unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
        unsafe { to_cow_slice(self.inner, len) }
    }

    fn as_usize(&self) -> usize {
        self.inner.expose_provenance()
    }
    fn from_usize(addr: usize) -> Self {
        Self {
            inner: core::ptr::with_exposed_provenance(addr),
        }
    }
}

impl<T: Clone> UserConstPtr<T> {
    /// Check if it is null
    pub fn is_null(self) -> bool {
        self.inner.is_null()
    }

    /// Read from user space at the `off` offset
    pub fn from_user_at_offset(self, off: isize) -> Option<T> {
        unsafe { Some(self.read_at_offset(off)?.into_owned()) }
    }
}

/// Represent a user space pointer to a mutable object
#[repr(C)]
#[derive(Clone)]
pub struct UserMutPtr<T> {
    pub inner: *mut T,
}

impl<T: Clone> core::fmt::Debug for UserMutPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("UserMutPtr").field(&self.inner).finish()
    }
}

impl<T: Clone> Copy for UserMutPtr<T> {}
impl<T: Clone> RawConstPointer<T> for UserMutPtr<T> {
    unsafe fn read_at_offset<'a>(self, count: isize) -> Option<alloc::borrow::Cow<'a, T>> {
        unsafe { read_at_offset(self.inner, count) }
    }

    unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
        unsafe { to_cow_slice(self.inner, len) }
    }

    fn as_usize(&self) -> usize {
        self.inner.expose_provenance()
    }
    fn from_usize(addr: usize) -> Self {
        Self {
            inner: core::ptr::with_exposed_provenance_mut(addr),
        }
    }
}

impl<T: Clone> RawMutPointer<T> for UserMutPtr<T> {
    unsafe fn write_at_offset(self, count: isize, value: T) -> Option<()> {
        if self.inner.is_null() {
            return None;
        }
        if self.inner.is_aligned() {
            unsafe {
                *self.inner.offset(count) = value;
            }
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (&raw const value).cast::<u8>(),
                    self.inner.offset(count).cast::<u8>(),
                    core::mem::size_of::<T>(),
                );
            }
        }
        Some(())
    }

    fn mutate_subslice_with<R>(
        self,
        range: impl core::ops::RangeBounds<isize>,
        f: impl FnOnce(&mut [T]) -> R,
    ) -> Option<R> {
        if self.inner.is_null() || !self.inner.is_aligned() {
            return None;
        }
        let start = match range.start_bound() {
            core::ops::Bound::Included(&x) => x,
            core::ops::Bound::Excluded(_) => unreachable!(),
            core::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            core::ops::Bound::Included(&x) => x.checked_add(1)?,
            core::ops::Bound::Excluded(&x) => x,
            core::ops::Bound::Unbounded => {
                return None;
            }
        };
        let len = if start <= end {
            start.abs_diff(end)
        } else {
            return None;
        };
        let _ = start.checked_mul(size_of::<T>().try_into().ok()?)?;
        let data = unsafe { self.inner.offset(start) };
        let _ = isize::try_from(len.checked_mul(size_of::<T>())?).ok()?;
        let slice = unsafe { core::slice::from_raw_parts_mut(data, len) };
        Some(f(slice))
    }
}

impl<T: Clone> UserMutPtr<T> {
    /// Check if it is null
    pub fn is_null(self) -> bool {
        self.inner.is_null()
    }

    /// Write to user space at the `off` offset
    pub fn to_user_at_offset(self, off: isize, value: T) -> Option<()> {
        unsafe { self.write_at_offset(off, value) }
    }

    /// Cast to a pointer with different underlying type
    pub fn cast<U>(self) -> UserMutPtr<U> {
        UserMutPtr {
            inner: self.inner.cast(),
        }
    }
}
