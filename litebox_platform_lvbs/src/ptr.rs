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

    unsafe fn to_cow_slice<'a>(self, _len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
        todo!()
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

    unsafe fn to_cow_slice<'a>(self, _len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
        todo!()
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
    unsafe fn write_at_offset(self, _count: isize, _value: T) -> Option<()> {
        todo!()
    }

    fn mutate_subslice_with<R>(
        self,
        _range: impl core::ops::RangeBounds<isize>,
        _f: impl FnOnce(&mut [T]) -> R,
    ) -> Option<R> {
        todo!()
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
