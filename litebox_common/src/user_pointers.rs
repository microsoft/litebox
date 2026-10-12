// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Address-only user pointer types.
//!
//! These wrap a bare `usize` address and, unlike
//! [`litebox::platform::RawConstPointer`]/[`litebox::platform::RawMutPointer`],
//! carry no [`RawPointerProvider`] (`Platform`) parameter. This keeps `Platform`
//! from being viral across every type that merely *stores* a user pointer value.
//! Memory is accessed by converting back to the platform pointer type via
//! [`UserPtr::to_platform_ptr`]/[`UserPtrMut::to_platform_ptr`] (or the
//! convenience access methods), which take the platform as an explicit witness
//! `P`.

use litebox::platform::{RawConstPointer, RawMutPointer, RawPointerProvider};
use zerocopy::{FromBytes, IntoBytes};

/// A user-space const pointer represented purely as an address (`usize`).
///
/// Unlike [`litebox::platform::RawConstPointer`], this type carries no
/// [`RawPointerProvider`] (`Platform`) parameter: it only *stores* the address
/// of a user pointer. Memory is accessed by converting back to the platform
/// pointer type via the [`Self::read_at_offset`]/[`Self::to_owned_slice`]
/// methods, which take the platform as an explicit witness `P`.
///
/// This keeps `Platform` from being viral across every type that merely holds a
/// user pointer value.
// NOTE: We explicitly write the `T: Sized` bound to document that these need to
// be "thin" pointers; "fat" pointers (i.e., pointers to DSTs) are unsupported.
#[derive(FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct UserPtr<T: Sized> {
    /// An exposed-provenance address of the pointer.
    addr: usize,
    /// Note: This keeps user pointers `!Send + !Sync`; see
    /// <https://github.com/microsoft/litebox/issues/431>.
    _phantom: core::marker::PhantomData<*const T>,
}

impl<T> UserPtr<T> {
    /// Create a pointer from a raw address.
    pub fn from_usize(addr: usize) -> Self {
        Self {
            addr,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Create a pointer from a native `*const T`, exposing its provenance.
    pub fn from_ptr(ptr: *const T) -> Self {
        Self::from_usize(ptr.expose_provenance())
    }

    /// Get the address of the pointer as a `usize`.
    pub fn as_usize(&self) -> usize {
        self.addr
    }

    /// Whether this pointer's address is null (zero).
    pub fn is_null(&self) -> bool {
        self.addr == 0
    }

    /// Reinterpret this pointer as pointing to a different type `U`.
    pub fn cast<U>(self) -> UserPtr<U> {
        UserPtr::from_usize(self.addr)
    }
}

impl<T> Clone for UserPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for UserPtr<T> {}
impl<T> core::fmt::Debug for UserPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("UserPtr").field(&self.addr).finish()
    }
}

impl<T: FromBytes> UserPtr<T> {
    /// Convert platform `P`'s const pointer type into an address-only pointer.
    pub fn from_platform_ptr<P: RawPointerProvider>(ptr: P::RawConstPointer<T>) -> Self {
        Self::from_usize(ptr.as_usize())
    }

    /// Convert this address-only pointer into platform `P`'s const pointer type,
    /// through which memory can actually be accessed.
    pub fn to_platform_ptr<P: RawPointerProvider>(self) -> P::RawConstPointer<T> {
        <P::RawConstPointer<T> as RawConstPointer<T>>::from_usize(self.addr)
    }

    /// See [`RawConstPointer::read_at_offset`].
    pub fn read_at_offset<P: RawPointerProvider>(self, count: isize) -> Option<T> {
        self.to_platform_ptr::<P>().read_at_offset(count)
    }

    /// See [`RawConstPointer::to_owned_slice`].
    pub fn to_owned_slice<P: RawPointerProvider>(
        self,
        len: usize,
    ) -> Option<alloc::boxed::Box<[T]>> {
        self.to_platform_ptr::<P>().to_owned_slice(len)
    }
}

impl UserPtr<core::ffi::c_char> {
    /// See [`RawConstPointer::to_cstring`].
    pub fn to_cstring<P: RawPointerProvider>(self) -> Option<alloc::ffi::CString> {
        self.to_platform_ptr::<P>().to_cstring()
    }
}

/// A user-space mutable pointer represented purely as an address (`usize`).
///
/// The mutable counterpart of [`UserPtr`]. See [`UserPtr`] for the rationale.
// NOTE: We explicitly write the `T: Sized` bound to document that these need to
// be "thin" pointers; "fat" pointers (i.e., pointers to DSTs) are unsupported.
#[derive(FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct UserPtrMut<T: Sized> {
    /// An exposed-provenance address of the pointer.
    addr: usize,
    /// Note: This keeps user pointers `!Send + !Sync`; see
    /// <https://github.com/microsoft/litebox/issues/431>.
    _phantom: core::marker::PhantomData<*mut T>,
}

impl<T> UserPtrMut<T> {
    /// Create a pointer from a raw address.
    pub fn from_usize(addr: usize) -> Self {
        Self {
            addr,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Create a pointer from a native `*mut T`, exposing its provenance.
    pub fn from_ptr(ptr: *mut T) -> Self {
        Self::from_usize(ptr.expose_provenance())
    }

    /// Get the address of the pointer as a `usize`.
    pub fn as_usize(&self) -> usize {
        self.addr
    }

    /// Whether this pointer's address is null (zero).
    pub fn is_null(&self) -> bool {
        self.addr == 0
    }

    /// Reinterpret this pointer as pointing to a different type `U`.
    pub fn cast<U>(self) -> UserPtrMut<U> {
        UserPtrMut::from_usize(self.addr)
    }
}

impl<T> Clone for UserPtrMut<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for UserPtrMut<T> {}
impl<T> core::fmt::Debug for UserPtrMut<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("UserPtrMut").field(&self.addr).finish()
    }
}

impl<T: FromBytes + IntoBytes> UserPtrMut<T> {
    /// Convert platform `P`'s mutable pointer type into an address-only pointer.
    pub fn from_platform_ptr<P: RawPointerProvider>(ptr: P::RawMutPointer<T>) -> Self {
        Self::from_usize(ptr.as_usize())
    }

    /// Convert this address-only pointer into platform `P`'s mutable pointer type,
    /// through which memory can actually be accessed.
    pub fn to_platform_ptr<P: RawPointerProvider>(self) -> P::RawMutPointer<T> {
        <P::RawMutPointer<T> as RawConstPointer<T>>::from_usize(self.addr)
    }

    /// See [`RawConstPointer::read_at_offset`].
    pub fn read_at_offset<P: RawPointerProvider>(self, count: isize) -> Option<T> {
        self.to_platform_ptr::<P>().read_at_offset(count)
    }

    /// See [`RawConstPointer::to_owned_slice`].
    pub fn to_owned_slice<P: RawPointerProvider>(
        self,
        len: usize,
    ) -> Option<alloc::boxed::Box<[T]>> {
        self.to_platform_ptr::<P>().to_owned_slice(len)
    }

    /// See [`RawMutPointer::write_at_offset`].
    #[must_use]
    pub fn write_at_offset<P: RawPointerProvider>(self, count: isize, value: T) -> Option<()> {
        self.to_platform_ptr::<P>().write_at_offset(count, value)
    }

    /// See [`RawMutPointer::write_slice_at_offset`].
    #[must_use]
    pub fn write_slice_at_offset<P: RawPointerProvider>(
        self,
        count: isize,
        values: &[T],
    ) -> Option<()>
    where
        T: Clone,
    {
        self.to_platform_ptr::<P>()
            .write_slice_at_offset(count, values)
    }

    /// See [`RawMutPointer::copy_from_slice`].
    #[must_use]
    pub fn copy_from_slice<P: RawPointerProvider>(
        self,
        start_offset: usize,
        buf: &[T],
    ) -> Option<()>
    where
        T: Copy,
    {
        self.to_platform_ptr::<P>()
            .copy_from_slice(start_offset, buf)
    }
}
