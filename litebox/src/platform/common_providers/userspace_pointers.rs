// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Userspace Pointer Abstraction with Fallible Memory Access
//!
//! This module implements fallible userspace pointers that can safely handle invalid
//! memory accesses from userspace. The pointers use fallible memory access routines
//! internally, which relies on an exception table mechanism to recover from memory
//! faults.
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

use crate::mm::exception_table::memcpy_fallible;
use crate::platform::{RawConstPointer, RawMutPointer};

/// Trait to validate that a pointer is a userspace pointer.
///
/// Succeeding these operations does not guarantee that the pointer is valid to
/// access, just that it is in the userspace address range and won't be used to
/// access kernel memory.
pub trait ValidateAccess {
    /// Validate that the given pointer is a valid userspace pointer.
    ///
    /// Returns `Some(ptr)` if valid. If the pointer is not valid, returns
    /// `None` or `Some(invalid)` where `invalid` is adjusted to a valid
    /// userspace address but will deterministically cause a fault on
    /// access.
    fn validate<T>(ptr: *mut T) -> Option<*mut T>;
    /// Validate that the given slice pointer is a valid userspace pointer.
    ///
    /// Returns as in `validate`. Note that only the starting pointer is
    /// returned.
    fn validate_slice<T>(ptr: *mut [T]) -> Option<*mut T>;
}

/// An implementiation of [`ValidateAccess`] that performs no validation. This
/// might be appropriate for purely-userland contexts.
pub struct NoValidation;

impl ValidateAccess for NoValidation {
    fn validate<T>(ptr: *mut T) -> Option<*mut T> {
        Some(ptr)
    }
    fn validate_slice<T>(ptr: *mut [T]) -> Option<*mut T> {
        Some(ptr.cast())
    }
}

/// Represent a user space pointer to a read-only object
#[repr(C)]
pub struct UserConstPtr<V, T> {
    inner: *const T,
    _validator: core::marker::PhantomData<V>,
}

impl<V: ValidateAccess, T: Clone> UserConstPtr<V, T> {
    pub fn from_ptr(ptr: *const T) -> Self {
        Self {
            inner: ptr,
            _validator: core::marker::PhantomData,
        }
    }
}

impl<V, T> Clone for UserConstPtr<V, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V, T> Copy for UserConstPtr<V, T> {}

impl<V, T: Clone> core::fmt::Debug for UserConstPtr<V, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("UserConstPtr").field(&self.inner).finish()
    }
}

/// Read from user space at the `off` offset, in a fallible manner.
///
/// Note that this is fallible only if recovering from exceptions (e.g., page fault or SIGSEGV)
/// is supported.
unsafe fn read_at_offset<'a, V: ValidateAccess, T: Clone>(
    ptr: *const T,
    count: isize,
) -> Option<alloc::borrow::Cow<'a, T>> {
    let src = unsafe { ptr.add(usize::try_from(count).ok()?) };
    let src = V::validate(src.cast_mut())?.cast_const();
    // Match on the size of `T` to use the appropriate fallible read function to
    // ensure that small aligned reads are atomic (and faster than a full
    // memcpy). This match will be evaluated at compile time, so there is no
    // runtime overhead.
    let val = unsafe {
        match size_of::<T>() {
            1 => core::mem::transmute_copy(
                &crate::mm::exception_table::read_u8_fallible(src.cast()).ok()?,
            ),
            2 => core::mem::transmute_copy(
                &crate::mm::exception_table::read_u16_fallible(src.cast()).ok()?,
            ),
            4 => core::mem::transmute_copy(
                &crate::mm::exception_table::read_u32_fallible(src.cast()).ok()?,
            ),
            #[cfg(target_pointer_width = "64")]
            8 => core::mem::transmute_copy(
                &crate::mm::exception_table::read_u64_fallible(src.cast()).ok()?,
            ),
            _ => {
                let mut data = core::mem::MaybeUninit::<T>::uninit();
                memcpy_fallible(
                    data.as_mut_ptr().cast(),
                    src.cast(),
                    core::mem::size_of::<T>(),
                )
                .ok()?;

                data.assume_init()
            }
        }
    };
    Some(alloc::borrow::Cow::Owned(val))
}

unsafe fn to_cow_slice<'a, V: ValidateAccess, T: Clone>(
    ptr: *const T,
    len: usize,
) -> Option<alloc::borrow::Cow<'a, [T]>> {
    if len == 0 {
        return Some(alloc::borrow::Cow::Owned(alloc::vec::Vec::new()));
    }
    let ptr = V::validate_slice(core::ptr::slice_from_raw_parts(ptr, len).cast_mut())?.cast_const();
    let mut data = alloc::vec::Vec::<T>::with_capacity(len);
    unsafe {
        memcpy_fallible(
            data.as_mut_ptr().cast(),
            ptr.cast(),
            len * core::mem::size_of::<T>(),
        )
        .ok()?;
        data.set_len(len);
    }
    Some(alloc::borrow::Cow::Owned(data))
}

impl<V: ValidateAccess, T: Clone> RawConstPointer<T> for UserConstPtr<V, T> {
    unsafe fn read_at_offset<'a>(self, count: isize) -> Option<alloc::borrow::Cow<'a, T>> {
        unsafe { read_at_offset::<V, T>(self.inner, count) }
    }

    unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
        unsafe { to_cow_slice::<V, T>(self.inner, len) }
    }

    fn as_usize(&self) -> usize {
        self.inner.expose_provenance()
    }
    fn from_usize(addr: usize) -> Self {
        Self {
            inner: core::ptr::with_exposed_provenance(addr),
            _validator: core::marker::PhantomData,
        }
    }
}

/// Represent a user space pointer to a mutable object
#[repr(C)]
pub struct UserMutPtr<V, T> {
    inner: *mut T,
    _validator: core::marker::PhantomData<V>,
}

impl<V: ValidateAccess, T: Clone> UserMutPtr<V, T> {
    pub fn from_ptr(ptr: *mut T) -> Self {
        Self {
            inner: ptr,
            _validator: core::marker::PhantomData,
        }
    }
}

impl<V, T: Clone> core::fmt::Debug for UserMutPtr<V, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("UserMutPtr").field(&self.inner).finish()
    }
}

impl<V, T> Clone for UserMutPtr<V, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V, T> Copy for UserMutPtr<V, T> {}

impl<V: ValidateAccess, T: Clone> RawConstPointer<T> for UserMutPtr<V, T> {
    unsafe fn read_at_offset<'a>(self, count: isize) -> Option<alloc::borrow::Cow<'a, T>> {
        unsafe { read_at_offset::<V, T>(self.inner.cast_const(), count) }
    }

    unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
        unsafe { to_cow_slice::<V, T>(self.inner.cast_const(), len) }
    }

    fn as_usize(&self) -> usize {
        self.inner.expose_provenance()
    }
    fn from_usize(addr: usize) -> Self {
        Self::from_ptr(core::ptr::with_exposed_provenance_mut(addr))
    }
}

impl<V: ValidateAccess, T: Clone> RawMutPointer<T> for UserMutPtr<V, T> {
    unsafe fn write_at_offset(self, count: isize, value: T) -> Option<()> {
        let dst = unsafe { self.inner.add(usize::try_from(count).ok()?) };
        let dst = V::validate(dst)?;
        // Match on the size of `T` to use the appropriate fallible write function to
        // ensure that small aligned writes are atomic (and faster than a full
        // memcpy). This match will be evaluated at compile time, so there is no
        // runtime overhead.
        unsafe {
            match size_of::<T>() {
                1 => crate::mm::exception_table::write_u8_fallible(
                    dst.cast(),
                    core::mem::transmute_copy(&value),
                ),
                2 => crate::mm::exception_table::write_u16_fallible(
                    dst.cast(),
                    core::mem::transmute_copy(&value),
                ),
                4 => crate::mm::exception_table::write_u32_fallible(
                    dst.cast(),
                    core::mem::transmute_copy(&value),
                ),
                #[cfg(target_pointer_width = "64")]
                8 => crate::mm::exception_table::write_u64_fallible(
                    dst.cast(),
                    core::mem::transmute_copy(&value),
                ),
                _ => memcpy_fallible(
                    dst.cast(),
                    (&raw const value).cast(),
                    core::mem::size_of::<T>(),
                ),
            }
        }
        .ok()
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
        let dst = V::validate_slice(core::ptr::slice_from_raw_parts_mut(dst, buf.len()))?;
        unsafe { memcpy_fallible(dst.cast(), buf.as_ptr().cast(), size_of_val(buf)).ok() }
    }
}
