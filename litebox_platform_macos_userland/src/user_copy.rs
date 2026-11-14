// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! User pointers whose failed fallible accesses are retried once after the
//! thread's registered supplier ([`litebox_common_macos::UserCopyFaults`])
//! supplies the accessed range.

use core::mem::ManuallyDrop;
use core::ops::Range;
use std::cell::Cell;

use litebox::platform::common_providers::userspace_pointers::{self, NoValidation};
use litebox::platform::{RawConstPointer, RawMutPointer};
use litebox_common_macos::UserCopyFaults;
use zerocopy::{FromBytes, IntoBytes};

use crate::MacosUserlandWithPageSize;

/// The supplier registered by `with_user_copy_supplier`, as a pointer to its
/// `&dyn Fn(Range<usize>) -> bool` on that call's stack; null when none is
/// registered and while it runs.
type Supplier = *const ();

thread_local! {
    static SUPPLIER: Cell<Supplier> = const { Cell::new(core::ptr::null()) };
}

/// Restores the slot on drop, including during unwinding.
struct Restore(Supplier);

impl Drop for Restore {
    fn drop(&mut self) {
        SUPPLIER.set(self.0);
    }
}

impl<const PAGE_SIZE: usize> UserCopyFaults for MacosUserlandWithPageSize<PAGE_SIZE> {
    fn with_user_copy_supplier<R>(
        &self,
        supply: &dyn Fn(Range<usize>) -> bool,
        f: impl FnOnce() -> R,
    ) -> R {
        // `_restore` removes the pointer to `supply` from the slot before
        // this frame ends.
        let _restore = Restore(SUPPLIER.replace((&raw const supply).cast()));
        f()
    }
}

/// Run `access`; if it fails, let the supplier supply `range` and retry once.
fn retry<R>(range: Option<Range<usize>>, access: impl Fn() -> Option<R>) -> Option<R> {
    if let Some(result) = access() {
        return Some(result);
    }
    let range = range?;
    let supply = SUPPLIER.replace(core::ptr::null());
    if supply.is_null() {
        return None;
    }
    let supplied = {
        let _restore = Restore(supply);
        // SAFETY: a non-null slot points to the `&dyn Fn` argument of a
        // `with_user_copy_supplier` frame of this thread that is still live:
        // the frame restores the previous slot value before it returns.
        unsafe { (*supply.cast::<&dyn Fn(Range<usize>) -> bool>())(range) }
    };
    if supplied { access() } else { None }
}

/// Bytes of `count` values of `T` starting `offset` values past `base`.
fn span<T>(base: usize, offset: isize, count: usize) -> Option<Range<usize>> {
    let start = usize::try_from(offset)
        .ok()?
        .checked_mul(size_of::<T>())
        .and_then(|bytes| base.checked_add(bytes))?;
    let end = count
        .checked_mul(size_of::<T>())
        .and_then(|bytes| start.checked_add(bytes))?;
    (start < end).then_some(start..end)
}

/// The platform's user pointer, for both [`RawConstPointer`] and
/// [`RawMutPointer`].
#[derive(FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct UserPtr<T: Sized>(userspace_pointers::UserMutPtr<NoValidation, T>);

impl<T> Clone for UserPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for UserPtr<T> {}

impl<T> core::fmt::Debug for UserPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: FromBytes> RawConstPointer<T> for UserPtr<T> {
    fn as_usize(&self) -> usize {
        self.0.as_usize()
    }

    fn from_usize(addr: usize) -> Self {
        Self(RawConstPointer::from_usize(addr))
    }

    fn read_at_offset(self, count: isize) -> Option<T> {
        retry(span::<T>(self.as_usize(), count, 1), || {
            self.0.read_at_offset(count)
        })
    }

    fn to_owned_slice(self, len: usize) -> Option<Box<[T]>> {
        retry(span::<T>(self.as_usize(), 0, len), || {
            self.0.to_owned_slice(len)
        })
    }

    unsafe fn copy_to_raw(self, offset: usize, dst: *mut T, len: usize) -> Option<()> {
        let range = isize::try_from(offset)
            .ok()
            .and_then(|offset| span::<T>(self.as_usize(), offset, len));
        // SAFETY: the caller upholds the contract for every attempt.
        retry(range, || unsafe { self.0.copy_to_raw(offset, dst, len) })
    }
}

impl<T: FromBytes + IntoBytes> RawMutPointer<T> for UserPtr<T> {
    fn write_at_offset(self, count: isize, value: T) -> Option<()> {
        // Each attempt writes a bitwise copy of `value` through the same
        // address as `ManuallyDrop<T>` (same layout, so the same scalar or
        // byte write), so only `value` itself is ever dropped.
        let ptr = userspace_pointers::UserMutPtr::<NoValidation, ManuallyDrop<T>>::from_usize(
            self.as_usize(),
        );
        retry(span::<T>(self.as_usize(), count, 1), || {
            // SAFETY: `value` is live for the read and the copy is never
            // dropped.
            ptr.write_at_offset(
                count,
                ManuallyDrop::new(unsafe { core::ptr::read(&raw const value) }),
            )
        })
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
        let range = isize::try_from(start_offset)
            .ok()
            .and_then(|offset| span::<T>(self.as_usize(), offset, buf.len()));
        retry(range, || self.0.copy_from_slice(start_offset, buf))
    }

    unsafe fn copy_from_raw(self, offset: usize, src: *const T, len: usize) -> Option<()> {
        let range = isize::try_from(offset)
            .ok()
            .and_then(|offset| span::<T>(self.as_usize(), offset, len));
        // SAFETY: the caller upholds the contract for every attempt.
        retry(range, || unsafe { self.0.copy_from_raw(offset, src, len) })
    }
}
