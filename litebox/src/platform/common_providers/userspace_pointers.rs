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
use zerocopy::{FromBytes, IntoBytes};

/// Trait to validate that a pointer is a userspace pointer and temporarily enable
/// kernel-mode access to it.
///
/// Succeeding these operations does not guarantee that the pointer is valid to
/// access, just that it is in the userspace address range and won't be used to
/// access kernel memory.
///
/// Platforms may provide a security feature to prevent the kernel from accessing
/// userspace memory, such as x86_64's Supervisor Mode Access Prevention (SMAP) or
/// Arm's Privileged Access Never (PAN). This trait provides an interface to
/// temporarily disable such protections around supervisor-mode access to the
/// userspace pointer.
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

    /// Execute `f` while temporarily allowing supervisor-mode access to userspace
    /// memory.
    ///
    /// Platforms with hardware protections such as SMAP or PAN should override this
    /// to disable the protection before calling `f` and re-enable it afterwards.
    /// The default implementation simply calls `f()`, which is appropriate for
    /// platforms without such protection.
    #[inline]
    fn with_user_memory_access<R>(f: impl FnOnce() -> R) -> R {
        f()
    }
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
// NOTE: We explicitly write the `T: Sized` bound to explicitly document that
// these need to be "thin" pointers, and that "fat" pointers (i.e., pointers to
// DSTs) are unsupported.
#[derive(FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct UserConstPtr<V, T: Sized> {
    /// An exposed-provenance address of the pointer. See [`Self::as_ptr`] for
    /// more details.
    inner: usize,
    _phantom_ptr: core::marker::PhantomData<*const T>,
    _validator: core::marker::PhantomData<V>,
}

impl<V: ValidateAccess, T> UserConstPtr<V, T> {
    pub fn from_ptr(ptr: *const T) -> Self {
        Self {
            inner: ptr.expose_provenance(),
            _phantom_ptr: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }

    /// Explicitly-private function.  This particular function exists because we
    /// store the `*const T` that would be stored in this struct instead as a
    /// `usize`.  We store `inner` as a `usize` to support
    /// `zerocopy::{FromBytes, IntoBytes}`.  Both of these _are_ sound to
    /// implement on `*const T`, but `zerocopy` currently chooses not to
    /// implement these, due to potential provenance footguns (see
    /// <https://github.com/google/zerocopy/blob/dce155c9b6004af2bdfeefc547abbcae3661909e/src/impls.rs#L955-L958>,
    /// or for a lot more details, see
    /// <https://github.com/google/zerocopy/issues/170>).  Our usage of these
    /// pointers is always through exposed provenance (see more details on
    /// [`RawConstPointer`]), and thus our provenance story is intimately linked
    /// to the design of that trait.  We are thus opting into the sound (but
    /// footgun-controlled) approach of storing a `usize` and converting it over
    /// here.
    fn as_ptr(&self) -> *const T {
        core::ptr::with_exposed_provenance(self.inner)
    }
}

impl<V, T> Clone for UserConstPtr<V, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V, T> Copy for UserConstPtr<V, T> {}

impl<V, T> core::fmt::Debug for UserConstPtr<V, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("UserConstPtr").field(&self.inner).finish()
    }
}

/// Read from user space at the `off` offset, in a fallible manner.
///
/// Note that this is fallible only if recovering from exceptions (e.g., page fault or SIGSEGV)
/// is supported.
fn read_at_offset<V: ValidateAccess, T: FromBytes>(ptr: *const T, count: isize) -> Option<T> {
    let src = ptr.wrapping_add(usize::try_from(count).ok()?);
    let src = V::validate(src.cast_mut())?.cast_const();
    // Match on the size of `T` to use the appropriate fallible read function to
    // ensure that small aligned reads are atomic (and faster than a full
    // memcpy). This match will be evaluated at compile time, so there is no
    // runtime overhead.
    //
    // SAFETY: The FromBytes bound on T guarantees that any byte pattern is valid for T,
    // so transmute_copy is safe. The memory access itself is fallible and returns None
    // on invalid memory access.
    V::with_user_memory_access(|| {
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
        Some(val)
    })
}

fn to_owned_slice<V: ValidateAccess, T: FromBytes>(
    ptr: *const T,
    len: usize,
) -> Option<alloc::boxed::Box<[T]>> {
    if len == 0 {
        return Some(alloc::boxed::Box::new([]));
    }
    let ptr = V::validate_slice(core::ptr::slice_from_raw_parts(ptr, len).cast_mut())?.cast_const();
    let mut data = alloc::boxed::Box::<[T]>::new_uninit_slice(len);
    // SAFETY: The FromBytes bound on T guarantees that any byte pattern is valid for T.
    // The memcpy_fallible operation returns None on invalid memory access.
    V::with_user_memory_access(|| unsafe {
        memcpy_fallible(
            data.as_mut_ptr().cast(),
            ptr.cast(),
            len * core::mem::size_of::<T>(),
        )
    })
    .ok()?;
    Some(unsafe { data.assume_init() })
}

impl<V: ValidateAccess, T: FromBytes> RawConstPointer<T> for UserConstPtr<V, T> {
    fn read_at_offset(self, count: isize) -> Option<T> {
        read_at_offset::<V, T>(self.as_ptr(), count)
    }

    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        to_owned_slice::<V, T>(self.as_ptr(), len)
    }

    fn as_usize(&self) -> usize {
        self.inner
    }
    fn from_usize(addr: usize) -> Self {
        Self {
            inner: addr,
            _phantom_ptr: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }
}

/// Represent a user space pointer to a mutable object
// NOTE: We explicitly write the `T: Sized` bound to explicitly document that
// these need to be "thin" pointers, and that "fat" pointers (i.e., pointers to
// DSTs) are unsupported.
#[derive(FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct UserMutPtr<V, T: Sized> {
    /// An exposed-provenance address of the pointer. See [`Self::as_ptr`] for
    /// more details.
    inner: usize,
    _phantom_ptr: core::marker::PhantomData<*mut T>,
    _validator: core::marker::PhantomData<V>,
}

impl<V: ValidateAccess, T> UserMutPtr<V, T> {
    pub fn from_ptr(ptr: *mut T) -> Self {
        Self {
            inner: ptr.expose_provenance(),
            _phantom_ptr: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }

    /// Explicitly-private function.  See equivalent [`UserConstPtr::as_ptr`]
    /// for more details.
    fn as_ptr(&self) -> *mut T {
        core::ptr::with_exposed_provenance_mut(self.inner)
    }
}

impl<V, T> core::fmt::Debug for UserMutPtr<V, T> {
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

impl<V: ValidateAccess, T: FromBytes> RawConstPointer<T> for UserMutPtr<V, T> {
    fn read_at_offset(self, count: isize) -> Option<T> {
        read_at_offset::<V, T>(self.as_ptr().cast_const(), count)
    }

    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        to_owned_slice::<V, T>(self.as_ptr().cast_const(), len)
    }

    fn as_usize(&self) -> usize {
        self.inner
    }
    fn from_usize(addr: usize) -> Self {
        Self {
            inner: addr,
            _phantom_ptr: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }
}

impl<V: ValidateAccess, T: FromBytes + IntoBytes> RawMutPointer<T> for UserMutPtr<V, T> {
    fn write_at_offset(self, count: isize, value: T) -> Option<()> {
        let dst = self.as_ptr().wrapping_add(usize::try_from(count).ok()?);
        let dst = V::validate(dst)?;
        // Match on the size of `T` to use the appropriate fallible write function to
        // ensure that small aligned writes are atomic (and faster than a full
        // memcpy). This match will be evaluated at compile time, so there is no
        // runtime overhead.
        //
        // SAFETY: The IntoBytes bound on T guarantees that T can be safely written as bytes.
        // The transmute_copy is safe because T implements IntoBytes. The memory access
        // itself is fallible and returns None on invalid memory access.
        V::with_user_memory_access(|| unsafe {
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
        })
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
        let dst = self.as_ptr().wrapping_add(start_offset);
        let dst = V::validate_slice(core::ptr::slice_from_raw_parts_mut(dst, buf.len()))?;
        V::with_user_memory_access(|| unsafe {
            memcpy_fallible(dst.cast(), buf.as_ptr().cast(), size_of_val(buf))
        })
        .ok()
    }
}
