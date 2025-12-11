//! Placeholders for implementing remote pointer access (e.g., reading from VTL0 physical memory)
//! TODO: Improve these and move these to the litebox crate later

use litebox::platform::{RawConstPointer, RawMutPointer};

pub trait ValidateAccess {}
pub trait RemotePtrKind {}

#[repr(C)]
pub struct RemoteConstPtr<V, K, T> {
    inner: *const T,
    _kind: core::marker::PhantomData<K>,
    _validator: core::marker::PhantomData<V>,
}

impl<V: ValidateAccess, K: RemotePtrKind, T: Clone> RemoteConstPtr<V, K, T> {
    pub fn from_ptr(ptr: *const T) -> Self {
        Self {
            inner: ptr,
            _kind: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }
}

impl<V, K, T> Clone for RemoteConstPtr<V, K, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V, K, T> Copy for RemoteConstPtr<V, K, T> {}

impl<V, K, T: Clone> core::fmt::Debug for RemoteConstPtr<V, K, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("RemoteConstPtr").field(&self.inner).finish()
    }
}

impl<V: ValidateAccess, K: RemotePtrKind, T: Clone> RawConstPointer<T> for RemoteConstPtr<V, K, T> {
    unsafe fn read_at_offset<'a>(self, _count: isize) -> Option<alloc::borrow::Cow<'a, T>> {
        // TODO: read data from the remote side
        let val: T = unsafe { core::mem::zeroed() };
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
            _kind: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }
}

#[repr(C)]
pub struct RemoteMutPtr<V, K, T> {
    inner: *mut T,
    _kind: core::marker::PhantomData<K>,
    _validator: core::marker::PhantomData<V>,
}

impl<V: ValidateAccess, K: RemotePtrKind, T: Clone> RemoteMutPtr<V, K, T> {
    pub fn from_ptr(ptr: *mut T) -> Self {
        Self {
            inner: ptr,
            _kind: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }
}

impl<V, K, T> Clone for RemoteMutPtr<V, K, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V, K, T> Copy for RemoteMutPtr<V, K, T> {}

impl<V, K, T: Clone> core::fmt::Debug for RemoteMutPtr<V, K, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("RemoteMutPtr").field(&self.inner).finish()
    }
}

impl<V: ValidateAccess, K: RemotePtrKind, T: Clone> RawConstPointer<T> for RemoteMutPtr<V, K, T> {
    unsafe fn read_at_offset<'a>(self, _count: isize) -> Option<alloc::borrow::Cow<'a, T>> {
        // TODO: read data from the remote side
        let val: T = unsafe { core::mem::zeroed() };
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
        Self::from_ptr(core::ptr::with_exposed_provenance_mut(addr))
    }
}

impl<V: ValidateAccess, K: RemotePtrKind, T: Clone> RawMutPointer<T> for RemoteMutPtr<V, K, T> {
    unsafe fn write_at_offset<'a>(self, _count: isize, _value: T) -> Option<()> {
        Some(())
    }

    fn mutate_subslice_with<R>(
        self,
        _range: impl core::ops::RangeBounds<isize>,
        _f: impl FnOnce(&mut [T]) -> R,
    ) -> Option<R> {
        unimplemented!("use write_slice_at_offset instead")
    }

    fn copy_from_slice(self, _start_offset: usize, _buf: &[T]) -> Option<()>
    where
        T: Copy,
    {
        Some(())
    }
}
