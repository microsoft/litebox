//! Userspace Pointer Abstraction

use litebox::platform::{RawConstPointer, RawMutPointer};

/// Represent a user space pointer to a read-only object
#[repr(C)]
#[derive(Clone)]
pub struct UserConstPtr<T> {
    pub inner: *const T,
}

impl<T: Clone> Copy for UserConstPtr<T> {}
impl<T: Clone> RawConstPointer<T> for UserConstPtr<T> {
    unsafe fn read_at_offset<'a>(self, _count: isize) -> Option<alloc::borrow::Cow<'a, T>> {
        todo!()
    }

    unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
        // todo!()
        if self.inner.is_null() || !self.inner.is_aligned() {
            return None;
        }
        Some(alloc::borrow::Cow::Borrowed(unsafe {
            core::slice::from_raw_parts(self.inner, len)
        }))
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
    /// Check if it's null
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

impl<T: Clone> Copy for UserMutPtr<T> {}
impl<T: Clone> RawConstPointer<T> for UserMutPtr<T> {
    unsafe fn read_at_offset<'a>(self, _count: isize) -> Option<alloc::borrow::Cow<'a, T>> {
        todo!()
    }

    unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
        // todo!()
        if self.inner.is_null() || !self.inner.is_aligned() {
            return None;
        }
        Some(alloc::borrow::Cow::Borrowed(unsafe {
            core::slice::from_raw_parts(self.inner, len)
        }))
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
        // todo!()
        if self.inner.is_null() || !self.inner.is_aligned() {
            return None;
        }
        unsafe {
            *self.inner.offset(count) = value;
        }
        Some(())
    }

    fn mutate_subslice_with<R>(
        self,
        range: impl core::ops::RangeBounds<isize>,
        f: impl FnOnce(&mut [T]) -> R,
    ) -> Option<R> {
        // todo!()
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
    /// Check if it's null
    pub fn is_null(self) -> bool {
        self.inner.is_null()
    }

    /// Write to user space at the `off` offset
    pub fn to_user_at_offset(self, off: isize, value: T) -> Option<()> {
        unsafe { self.write_at_offset(off, value) }
    }
}
