// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementations of trivial providers.
//!
//! Most users of LiteBox may possibly need more featureful providers, provided by other crates;
//! however, some users might find these sufficient for their use case.

use super::{
    Punchthrough, PunchthroughError, PunchthroughProvider, PunchthroughToken, RawConstPointer,
    RawMutPointer,
};
use zerocopy::{FromBytes, IntoBytes};

/// A trivial provider, useful when no punchthrough is necessary.
pub struct ImpossiblePunchthroughProvider {}
impl PunchthroughProvider for ImpossiblePunchthroughProvider {
    type PunchthroughToken<'a> = ImpossiblePunchthroughToken;
    fn get_punchthrough_token_for<'a>(
        &self,
        _punchthrough: <Self::PunchthroughToken<'a> as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'a>> {
        // Since `ImpossiblePunchthrough` is an empty enum, it is impossible to actually invoke
        // `execute` upon it, meaning that the implementation here is irrelevant, since anything
        // within it is provably unreachable.
        unreachable!()
    }
}
/// A [`Punchthrough`] for [`ImpossiblePunchthroughProvider`]
pub enum ImpossiblePunchthrough {}
impl Punchthrough for ImpossiblePunchthrough {
    // Infallible has the same role as the never type (`!`) which will _eventually_ be stabilized in
    // Rust. Since `Infallible` has no variant, a value of this type can never actually exist.
    type ReturnSuccess = core::convert::Infallible;
    type ReturnFailure = core::convert::Infallible;
}
/// A [`PunchthroughToken`] for [`ImpossiblePunchthrough`]
pub enum ImpossiblePunchthroughToken {}
impl PunchthroughToken for ImpossiblePunchthroughToken {
    type Punchthrough = ImpossiblePunchthrough;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as Punchthrough>::ReturnSuccess,
        PunchthroughError<<Self::Punchthrough as Punchthrough>::ReturnFailure>,
    > {
        // Since `ImpossiblePunchthroughToken` is an empty enum, it is impossible to actually invoke
        // `execute` upon it, meaning that the implementation here is irrelevant, since anything
        // within it is provably unreachable.
        unreachable!()
    }
}

/// A trivial provider, useful when punchthroughs are be necessary, but might prefer to be
/// simply caught as "unimplemented" temporarily, while more infrastructure is set up.
pub struct IgnoredPunchthroughProvider {}
impl PunchthroughProvider for IgnoredPunchthroughProvider {
    type PunchthroughToken<'a> = IgnoredPunchthroughToken;
    fn get_punchthrough_token_for<'a>(
        &self,
        punchthrough: <Self::PunchthroughToken<'a> as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'a>> {
        Some(IgnoredPunchthroughToken { punchthrough })
    }
}
/// A [`Punchthrough`] for [`IgnoredPunchthroughProvider`]
pub struct IgnoredPunchthrough {
    data: &'static str,
}
impl Punchthrough for IgnoredPunchthrough {
    type ReturnSuccess = Underspecified;
    type ReturnFailure = Underspecified;
}
/// A [`PunchthroughToken`] for [`IgnoredPunchthrough`]
pub struct IgnoredPunchthroughToken {
    punchthrough: IgnoredPunchthrough,
}
impl PunchthroughToken for IgnoredPunchthroughToken {
    type Punchthrough = IgnoredPunchthrough;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as Punchthrough>::ReturnSuccess,
        PunchthroughError<<Self::Punchthrough as Punchthrough>::ReturnFailure>,
    > {
        Err(PunchthroughError::Unimplemented(self.punchthrough.data))
    }
}

/// An under-specified type that cannot be "inspected" or created; used for [`IgnoredPunchthrough`]
#[doc(hidden)]
pub struct Underspecified {
    // Explicitly private field, to prevent destructuring or creation outside this module.
    __private: (),
}
impl core::fmt::Debug for Underspecified {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        unreachable!("Underspecified is never constructed")
    }
}
impl core::fmt::Display for Underspecified {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        unreachable!("Underspecified is never constructed")
    }
}
impl core::error::Error for Underspecified {}

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
