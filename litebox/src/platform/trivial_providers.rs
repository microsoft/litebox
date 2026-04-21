// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementations of trivial providers.
//!
//! Most users of LiteBox may possibly need more featureful providers, provided by other crates;
//! however, some users might find these sufficient for their use case.

use super::{RawConstPointer, RawMutPointer, TimerHandle};

use zerocopy::{FromBytes, IntoBytes};

/// A [`TimerHandle`] for [`super::TimerProvider`].
pub enum UnsupportedTimerHandle {}

impl TimerHandle for UnsupportedTimerHandle {
    fn set_timer(&self, _duration: core::time::Duration) {
        unreachable!("TimerProvider is not supported for this platform");
    }
}

/// A trivial [`RawConstPointer`] that is literally just `*const T`.
///
/// Useful for purely-userland contexts.
// NOTE: We explicitly write the `T: Sized` bound to explicitly document that
// these need to be "thin" pointers, and that "fat" pointers (i.e., pointers to
// DSTs) are unsupported.
#[derive(FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct TransparentConstPtr<T: Sized> {
    /// An exposed-provenance address of the pointer. See [`Self::as_ptr`] for
    /// more details.
    inner: usize,
    _phantom_ptr: core::marker::PhantomData<*const T>,
}

impl<T> TransparentConstPtr<T> {
    /// Explicitly-private function.  See
    /// [`super::common_providers::userspace_pointers::UserConstPtr::as_ptr`]
    /// for more details.
    fn as_ptr(&self) -> *const T {
        core::ptr::with_exposed_provenance(self.inner)
    }
}
impl<T> Clone for TransparentConstPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for TransparentConstPtr<T> {}
impl<T> core::fmt::Debug for TransparentConstPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("ConstPtr").field(&self.inner).finish()
    }
}
impl<T: FromBytes> RawConstPointer<T> for TransparentConstPtr<T> {
    fn read_at_offset(self, count: isize) -> Option<T> {
        let ptr = self.as_ptr();
        if ptr.is_null() || !ptr.is_aligned() {
            return None;
        }
        let p = ptr.wrapping_offset(count);
        // SAFETY: We checked the pointer is non-null and aligned. The FromBytes bound
        // on T guarantees that any byte pattern is valid for T, so reading from valid
        // memory is safe.
        Some(match size_of::<T>() {
            // Try to ensure a single access for primitive types. The use of
            // volatile here is dubious--this should really use inline asm or
            // perhaps atomic loads.
            1 | 2 | 4 | 8 => unsafe { p.read_volatile() },
            _ => unsafe { p.read() },
        })
    }
    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        let ptr = self.as_ptr();
        if ptr.is_null() || !ptr.is_aligned() {
            return None;
        }
        // SAFETY: We checked the pointer is non-null and aligned. The FromBytes bound
        // on T guarantees that any byte pattern is valid for T.
        let mut boxed = alloc::boxed::Box::<[T]>::new_uninit_slice(len);
        unsafe {
            core::ptr::copy_nonoverlapping(ptr, boxed.as_mut_ptr().cast(), len);
            Some(boxed.assume_init())
        }
    }

    fn as_usize(&self) -> usize {
        self.inner
    }
    fn from_usize(addr: usize) -> Self {
        Self {
            inner: addr,
            _phantom_ptr: core::marker::PhantomData,
        }
    }
}

/// A trivial [`RawMutPointer`] that is literally just `*mut T`.
///
/// Useful for purely-userland contexts.
// NOTE: We explicitly write the `T: Sized` bound to explicitly document that
// these need to be "thin" pointers, and that "fat" pointers (i.e., pointers to
// DSTs) are unsupported.
#[derive(FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct TransparentMutPtr<T: Sized> {
    /// An exposed-provenance address of the pointer. See [`Self::as_ptr`] for
    /// more details.
    inner: usize,
    _phantom_ptr: core::marker::PhantomData<*mut T>,
}

impl<T> TransparentMutPtr<T> {
    /// Explicitly-private function.  See
    /// [`super::common_providers::userspace_pointers::UserConstPtr::as_ptr`]
    /// for more details.
    fn as_ptr(&self) -> *mut T {
        core::ptr::with_exposed_provenance_mut(self.inner)
    }
}
impl<T> Clone for TransparentMutPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for TransparentMutPtr<T> {}
impl<T> core::fmt::Debug for TransparentMutPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("MutPtr").field(&self.inner).finish()
    }
}
impl<T: FromBytes> RawConstPointer<T> for TransparentMutPtr<T> {
    fn read_at_offset(self, count: isize) -> Option<T> {
        let ptr = self.as_ptr();
        if ptr.is_null() || !ptr.is_aligned() {
            return None;
        }
        // SAFETY: We checked the pointer is non-null and aligned. The FromBytes bound
        // on T guarantees that any byte pattern is valid for T, so reading from valid
        // memory is safe.
        Some(match size_of::<T>() {
            // Try to ensure a single access for primitive types. The use of
            // volatile here is dubious--this should really use inline asm or
            // perhaps atomic loads.
            1 | 2 | 4 | 8 => unsafe { ptr.offset(count).read_volatile() },
            _ => unsafe { ptr.offset(count).read() },
        })
    }
    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        let ptr = self.as_ptr();
        if ptr.is_null() || !ptr.is_aligned() {
            return None;
        }
        // SAFETY: We checked the pointer is non-null and aligned. The FromBytes bound
        // on T guarantees that any byte pattern is valid for T.
        let mut boxed = alloc::boxed::Box::<[T]>::new_uninit_slice(len);
        unsafe {
            core::ptr::copy_nonoverlapping(ptr, boxed.as_mut_ptr().cast(), len);
            Some(boxed.assume_init())
        }
    }

    fn as_usize(&self) -> usize {
        self.inner
    }
    fn from_usize(addr: usize) -> Self {
        Self {
            inner: addr,
            _phantom_ptr: core::marker::PhantomData,
        }
    }
}
impl<T: FromBytes + IntoBytes> RawMutPointer<T> for TransparentMutPtr<T> {
    fn write_at_offset(self, count: isize, value: T) -> Option<()> {
        let ptr = self.as_ptr();
        if ptr.is_null() || !ptr.is_aligned() {
            return None;
        }
        let p = ptr.wrapping_offset(count);
        // SAFETY: We checked the pointer is non-null and aligned. The IntoBytes bound
        // on T guarantees that T can be safely written as bytes.
        unsafe {
            *p = value;
        }
        Some(())
    }
    fn mutate_subslice_with<R>(
        self,
        range: impl core::ops::RangeBounds<isize>,
        f: impl FnOnce(&mut [T]) -> R,
    ) -> Option<R> {
        let ptr = self.as_ptr();
        if ptr.is_null() || !ptr.is_aligned() {
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
        let data = ptr.wrapping_offset(start);
        let _ = isize::try_from(len.checked_mul(size_of::<T>())?).ok()?;
        let slice = unsafe { core::slice::from_raw_parts_mut(data, len) };
        Some(f(slice))
    }
}
