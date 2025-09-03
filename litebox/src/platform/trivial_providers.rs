//! Implementations of trivial providers.
//!
//! Most users of LiteBox may possibly need more featureful providers, provided by other crates;
//! however, some users might find these sufficient for their use case.

use super::{
    Punchthrough, PunchthroughError, PunchthroughProvider, PunchthroughToken, RawConstPointer,
    RawMutPointer,
};

/// A trivial provider, useful when no punchthrough is necessary.
pub struct ImpossiblePunchthroughProvider {}
impl PunchthroughProvider for ImpossiblePunchthroughProvider {
    type PunchthroughToken = ImpossiblePunchthroughToken;
    fn get_punchthrough_token_for(
        &self,
        _punchthrough: <Self::PunchthroughToken as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
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
    type PunchthroughToken = IgnoredPunchthroughToken;
    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
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
#[repr(C)]
#[derive(Clone)]
pub struct TransparentConstPtr<T> {
    pub inner: *const T,
}
impl<T: Clone> core::fmt::Debug for TransparentConstPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("ConstPtr").field(&self.inner).finish()
    }
}
impl<T: Clone> Copy for TransparentConstPtr<T> {}
impl<T: Clone> RawConstPointer<T> for TransparentConstPtr<T> {
    unsafe fn read_at_offset<'a>(self, count: isize) -> Option<alloc::borrow::Cow<'a, T>> {
        if self.inner.is_null() || !self.inner.is_aligned() {
            return None;
        }
        Some(alloc::borrow::Cow::Borrowed(unsafe {
            &*self.inner.offset(count)
        }))
    }
    unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
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

/// A trivial [`RawMutPointer`] that is literally just `*mut T`.
///
/// Useful for purely-userland contexts.
#[repr(C)]
#[derive(Clone)]
pub struct TransparentMutPtr<T> {
    pub inner: *mut T,
}
impl<T: Clone> core::fmt::Debug for TransparentMutPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("MutPtr").field(&self.inner).finish()
    }
}
impl<T: Clone> Copy for TransparentMutPtr<T> {}
impl<T: Clone> RawConstPointer<T> for TransparentMutPtr<T> {
    unsafe fn read_at_offset<'a>(self, count: isize) -> Option<alloc::borrow::Cow<'a, T>> {
        if self.inner.is_null() || !self.inner.is_aligned() {
            return None;
        }
        Some(alloc::borrow::Cow::Borrowed(unsafe {
            &*self.inner.offset(count)
        }))
    }
    unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
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
impl<T: Clone> RawMutPointer<T> for TransparentMutPtr<T> {
    unsafe fn write_at_offset(self, count: isize, value: T) -> Option<()> {
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
