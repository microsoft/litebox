//! Userspace Pointer Abstraction with Fallible Memory Access
//!
//! This module implements fallible userspace pointers that can safely handle invalid
//! memory accesses from userspace. The pointers use [`__lb_memcpy_fallible`] internally,
//! which relies on an exception table mechanism to recover from memory faults.
//!
//! ## Exception Handling Mechanism
//!
//! **IMPORTANT**: For these pointers to behave as truly fallible (returning `None`
//! on invalid access), the platform **must** implement and register appropriate
//! exception handlers. Without proper exception handling setup, invalid memory
//! accesses will still crash the program.
//!
//! When accessing userspace memory through these pointers:
//!
//! 1. **With Exception Handling** (Required for fallible behavior): The platform
//!    must set up exception handlers (e.g., SIGSEGV signal handlers on Linux userland)
//!    that can catch memory access failures such as page faults or segmentation violations.
//!    The handler must use [`crate::mm::exception_table::search_exception_tables`] to
//!    look up the faulting instruction and redirect execution to a recovery point,
//!    allowing the operation to return `None` gracefully instead of crashing.
//!
//! 2. **Without Exception Handling** (Fallback behavior): If no exception handlers
//!    are configured, these pointers behave like slightly more expensive
//!    [`crate::platform::trivial_providers::TransparentConstPtr`] and
//!    [`crate::platform::trivial_providers::TransparentMutPtr`]. Invalid memory
//!    accesses will still cause the program to crash (e.g., with SIGSEGV), but
//!    with the additional overhead of the fallible copy mechanism.

use crate::mm::exception_table::__lb_memcpy_fallible;
use crate::platform::{RawConstPointer, RawMutPointer};

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

/// Read from user space at the `off` offset, in a fallible manner.
///
/// Note that this is fallible only if recovering from exceptions (e.g., page fault or SIGSEGV)
/// is supported.
unsafe fn read_at_offset<'a, T: Clone>(
    ptr: *const T,
    count: isize,
) -> Option<alloc::borrow::Cow<'a, T>> {
    let src = unsafe { ptr.add(usize::try_from(count).ok()?) };
    let mut data = core::mem::MaybeUninit::<T>::uninit();
    let failed_bytes = unsafe {
        __lb_memcpy_fallible(
            data.as_mut_ptr().cast(),
            src.cast(),
            core::mem::size_of::<T>(),
        )
    };
    if failed_bytes == 0 {
        let val = unsafe { data.assume_init() };
        Some(alloc::borrow::Cow::Owned(val))
    } else {
        None
    }
}

unsafe fn to_cow_slice<'a, T: Clone>(
    ptr: *const T,
    len: usize,
) -> Option<alloc::borrow::Cow<'a, [T]>> {
    if len == 0 {
        return Some(alloc::borrow::Cow::Owned(alloc::vec::Vec::new()));
    }
    let mut data = alloc::vec::Vec::<T>::with_capacity(len);
    let failed_bytes = unsafe {
        __lb_memcpy_fallible(
            data.as_mut_ptr().cast(),
            ptr.cast(),
            len * core::mem::size_of::<T>(),
        )
    };
    if failed_bytes == 0 {
        unsafe { data.set_len(len) };
        Some(alloc::borrow::Cow::Owned(data))
    } else {
        None
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
        unsafe { read_at_offset(self.inner.cast_const(), count) }
    }

    unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
        unsafe { to_cow_slice(self.inner.cast_const(), len) }
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
        let dst = unsafe { self.inner.add(usize::try_from(count).ok()?) };
        let failed_bytes = unsafe {
            __lb_memcpy_fallible(
                dst.cast(),
                (&raw const value).cast(),
                core::mem::size_of::<T>(),
            )
        };
        if failed_bytes == 0 { Some(()) } else { None }
    }

    fn mutate_subslice_with<R>(
        self,
        _range: impl core::ops::RangeBounds<isize>,
        _f: impl FnOnce(&mut [T]) -> R,
    ) -> Option<R> {
        unimplemented!("use write_slice_at_offset instead")
    }

    fn copy_from_slice(self, start_offset: usize, buf: &[T]) -> Option<()>
    where
        T: Copy,
    {
        if buf.is_empty() {
            return Some(());
        }
        let dst = unsafe { self.inner.add(start_offset) };
        let failed_bytes = unsafe {
            __lb_memcpy_fallible(dst.cast(), buf.as_ptr().cast(), core::mem::size_of_val(buf))
        };
        if failed_bytes == 0 { Some(()) } else { None }
    }
}
