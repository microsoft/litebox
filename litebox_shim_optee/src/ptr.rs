//! Placeholders for specifying remote pointer access (e.g., reading data from
//! VTL0 physical memory)
//! TODO: Improve these and move these to the litebox crate later

use litebox::platform::{RawConstPointer, RawMutPointer};

// TODO: use the one from the litebox crate
pub trait ValidateAccess {}

/// Trait to access a pointer to remote memory
/// For now, we only consider copying the entire value before acccessing it.
/// We do not consider byte-level access or unaligned access.
pub trait RemoteMemoryAccess {
    fn read_at_offset<T>(ptr: *mut T, count: isize) -> Option<T>;

    fn write_at_offset<T>(ptr: *mut T, count: isize, value: T) -> Option<()>;

    fn slice_from<T>(ptr: *mut T, len: usize) -> Option<alloc::boxed::Box<[T]>>;

    fn copy_from_slice<T>(start_offset: usize, buf: &[T]) -> Option<()>;
}

#[repr(C)]
pub struct RemoteConstPtr<V, A, T> {
    inner: *const T,
    _access: core::marker::PhantomData<A>,
    _validator: core::marker::PhantomData<V>,
}

impl<V: ValidateAccess, A: RemoteMemoryAccess, T: Clone> RemoteConstPtr<V, A, T> {
    pub fn from_ptr(ptr: *const T) -> Self {
        Self {
            inner: ptr,
            _access: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }
}

impl<V, A, T> Clone for RemoteConstPtr<V, A, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V, A, T> Copy for RemoteConstPtr<V, A, T> {}

impl<V, A, T: Clone> core::fmt::Debug for RemoteConstPtr<V, A, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("RemoteConstPtr").field(&self.inner).finish()
    }
}

impl<V: ValidateAccess, A: RemoteMemoryAccess, T: Clone> RawConstPointer<T>
    for RemoteConstPtr<V, A, T>
{
    unsafe fn read_at_offset<'a>(self, count: isize) -> Option<alloc::borrow::Cow<'a, T>> {
        let val = A::read_at_offset(self.inner.cast_mut(), count)?;
        Some(alloc::borrow::Cow::Owned(val))
    }

    unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
        // TODO: read data from the remote side
        if len == 0 {
            return Some(alloc::borrow::Cow::Owned(alloc::vec::Vec::new()));
        }
        let mut data = alloc::vec::Vec::new();
        data.reserve_exact(len);
        unsafe { data.set_len(len) };
        Some(alloc::borrow::Cow::Owned(data))
    }

    fn as_usize(&self) -> usize {
        self.inner.expose_provenance()
    }

    fn from_usize(addr: usize) -> Self {
        Self {
            inner: core::ptr::with_exposed_provenance(addr),
            _access: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }
}

#[repr(C)]
pub struct RemoteMutPtr<V, A, T> {
    inner: *mut T,
    _access: core::marker::PhantomData<A>,
    _validator: core::marker::PhantomData<V>,
}

impl<V: ValidateAccess, A: RemoteMemoryAccess, T: Clone> RemoteMutPtr<V, A, T> {
    pub fn from_ptr(ptr: *mut T) -> Self {
        Self {
            inner: ptr,
            _access: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }
}

impl<V, A, T> Clone for RemoteMutPtr<V, A, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V, A, T> Copy for RemoteMutPtr<V, A, T> {}

impl<V, A, T: Clone> core::fmt::Debug for RemoteMutPtr<V, A, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("RemoteMutPtr").field(&self.inner).finish()
    }
}

impl<V: ValidateAccess, A: RemoteMemoryAccess, T: Clone> RawConstPointer<T>
    for RemoteMutPtr<V, A, T>
{
    unsafe fn read_at_offset<'a>(self, count: isize) -> Option<alloc::borrow::Cow<'a, T>> {
        let val = A::read_at_offset(self.inner, count)?;
        Some(alloc::borrow::Cow::Owned(val))
    }

    unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<alloc::borrow::Cow<'a, [T]>> {
        // TODO: read data from the remote side
        if len == 0 {
            return Some(alloc::borrow::Cow::Owned(alloc::vec::Vec::new()));
        }
        let data = A::slice_from(self.inner, len)?;
        Some(alloc::borrow::Cow::Owned(data.into()))
    }

    fn as_usize(&self) -> usize {
        self.inner.expose_provenance()
    }

    fn from_usize(addr: usize) -> Self {
        Self::from_ptr(core::ptr::with_exposed_provenance_mut(addr))
    }
}

impl<V: ValidateAccess, A: RemoteMemoryAccess, T: Clone> RawMutPointer<T>
    for RemoteMutPtr<V, A, T>
{
    unsafe fn write_at_offset<'a>(self, count: isize, value: T) -> Option<()> {
        A::write_at_offset(self.inner, count, value)
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
        A::copy_from_slice(start_offset, buf)
    }
}

// TODO: implement a validation mechanism for VTL0 physical addresses (e.g., ensure this physical
// address does not belong to VTL1)
pub struct Novalidation;
impl ValidateAccess for Novalidation {}

pub struct Vtl0PhysMemoryAccess;
impl RemoteMemoryAccess for Vtl0PhysMemoryAccess {
    fn read_at_offset<T>(_ptr: *mut T, _count: isize) -> Option<T> {
        // TODO: read a value from VTL0 physical memory
        let val: T = unsafe { core::mem::zeroed() };
        Some(val)
    }

    fn write_at_offset<T>(_ptr: *mut T, _count: isize, _value: T) -> Option<()> {
        // TODO: write a value to VTL0 physical memory
        Some(())
    }

    fn slice_from<T>(_ptr: *mut T, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        // TODO: read a slice from VTL0 physical memory
        let mut data: alloc::vec::Vec<T> = alloc::vec::Vec::new();
        data.reserve_exact(len);
        unsafe { data.set_len(len) };
        Some(data.into_boxed_slice())
    }

    fn copy_from_slice<T>(_start_offset: usize, _buf: &[T]) -> Option<()> {
        // TODO: write a slice to VTL0 physical memory
        Some(())
    }
}

/// Normal world const pointer type. For now, we only consider VTL0 physical memory but it can be
/// something else like TrustZone normal world, other VMPL or TD partition, or other processes.
pub type NormalWorldConstPtr<T> = RemoteConstPtr<Novalidation, Vtl0PhysMemoryAccess, T>;

/// Normal world mutable pointer type. For now, we only consider VTL0 physical memory but it can be
/// something else like TrustZone normal world, other VMPL or TD partition, or other processes.
pub type NormalWorldMutPtr<T> = RemoteMutPtr<Novalidation, Vtl0PhysMemoryAccess, T>;
