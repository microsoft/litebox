//! Physical Pointer Abstraction with On-demand Mapping
//!
//! This module implements types and traits to support accessing physical addresses
//! (e.g., VTL0 or normal-world physical memory) from LiteBox with on-demand mapping.
//! In the context of LVBS and OP-TEE, accessing physical memory is necessary
//! because VTL0 and VTL1 as well as normal world and secure world do not share
//! the same virtual address space, but they still have to share data through memory.
//! VTL1 and secure world receive physical addresses from VTL0 and normal world,
//! respectively, and they need to read from or write to those addresses.
//!
//! To simplify all these, we could persistently map the entire VTL0/normal-world
//! physical memory into VTL1/secure-world address space at once and just access them
//! through corresponding virtual addresses. Also, we could define some APIs to let
//! LiteBox (shim) map/unmap arbitrary physical addresses (i.e., implementing and
//! exposing APIs like Linux kernel's `vmap()` and `vunmap()`). However, this module
//! does not take these approaches due to scalability (e.g., how to deal with a system
//! with terabytes of physical memory?) and security concerns (e.g., data corruption or
//! information leakage due to concurrent and persistent access).
//!
//! Instead, the approach this module takes is to map the required physical memory
//! region on-demand when accessing them while using a buffer to copy data to/from
//! those regions. This way, this module can ensure that data must be copied into
//! LiteBox-managed memory before being used while avoiding any unknown side effects
//! due to persistent memory mapping.
//!
//! Considerations:
//!
//! Ideally, this module should be able to validate whether a given physical address
//! is okay to access or even exists in the first place. For example, accessing
//! LiteBox's own memory with this physical pointer abstraction must be prohibited to
//! prevent the Boomerang attack. Also, some device memory is mapped to certain
//! physical address ranges and LiteBox should not touch them without in-depth
//! knowledge. However, this is a bit tricky because, in many cases, LiteBox does
//! not directly interact with the underlying hardware or BIOS/UEFI. In the case of
//! LVBS, LiteBox obtains the physical memory information from VTL0 including the
//! total physical memory size and the memory range assigned to VTL1/LiteBox.
//! Thus, this module can at least confirm a given physical address does not belong
//! to VTL1's physical memory.
//!
//! This module should allow byte-level access while transparently handling page
//! mapping and data access across page boundaries. This could become complicated
//! when we consider multiple page sizes (e.g., 4 KiB, 2 MiB, 1 GiB).  Also,
//! unaligned access is matter to be considered.
//!
//! In addition, often times, this physical pointer abstraction is involved with
//! a list of physical addresses (i.e., scatter-gather list). For example, in
//! the worse case, a two-byte value can span across two non-contiguous physical
//! pages. Thus, to enhance the performance, we may need to consider mapping
//! multiple pages at once, copy data from/to them, and unmap them later. Currently,
//! our implementation (in `litebox_platform_lvbs`) does not implement this
//! functionality yet and it just maps/unmaps one page at a time (this works but is
//! inefficient).
//!
//! When this module needs to access data across physical page boundaries, it assumes
//! that those physical pages are virtually contiguous in VTL0 or normal-world address
//! space. Otherwise, this module could end up with accessing incorrect data. This is
//! best-effort assumption and ensuring this is the caller's responsibility (e.g., even
//! if this module always requires a list of physical addresses, the caller can provide
//! a wrong list by mistake or intentionally).

use litebox::platform::{RawConstPointer, RawMutPointer};
use thiserror::Error;

/// Trait to validate that a physical pointer does not belong to LiteBox-managed memory
/// (including both kernel and userspace memory).
///
/// This validation is mainly to deal with the Boomerang attack where a normal-world client
/// tricks the secure-world kernel (i.e., LiteBox) to access the secure-world memory.
/// However, even if there is no such threat (e.g., no normal/secure world separation),
/// this validation is still beneficial to ensure the memory safety.
///
/// Succeeding these operations does not guarantee that the physical pointer is valid to
/// access, just that it is outside of LiteBox-managed memory and won't be used to access
/// it as an unmanaged channel.
pub trait ValidateAccess {
    /// Validate that the given physical pointer does not belong to LiteBox-managed memory.
    ///
    /// Here, we do not use `*const T` or `*mut T` because this is a physical pointer which
    /// must not be dereferenced directly.
    ///
    /// Returns `Some(pa)` if valid. If the pointer is not valid, returns `None`.
    fn validate<T>(pa: usize) -> Result<usize, PhysPointerError>;
}

/// Trait to access a pointer to physical memory
/// For now, we only consider copying the entire value before accessing it.
/// We do not consider byte-level access or unaligned access.
pub trait RemoteMemoryAccess {
    fn read_at_offset<T>(ptr: *mut T, count: isize) -> Option<T>;

    fn write_at_offset<T>(ptr: *mut T, count: isize, value: T) -> Option<()>;

    fn slice_from<T>(ptr: *mut T, len: usize) -> Option<alloc::boxed::Box<[T]>>;

    fn copy_from_slice<T>(start_offset: usize, buf: &[T]) -> Option<()>;
}

/// Data structure for an array of physical pages. These physical pages should be
/// virtually contiguous in the source address space.
#[derive(Clone)]
pub struct PhysPageArray<const ALIGN: usize>(alloc::boxed::Box<[usize]>);

impl PhysPageArray<4096> {
    /// Create a new `PhysPageArray` from the given slice of physical addresses.
    pub fn try_from_slice(addrs: &[usize]) -> Result<Self, PhysPointerError> {
        for addr in addrs {
            if !addr.is_multiple_of(4096) {
                return Err(PhysPointerError::UnalignedPhysicalAddress(*addr, 4096));
            }
        }
        Ok(Self(addrs.into()))
    }
}

/// Data structure to maintain the mapping information returned by `vmap()`.
/// `base` is the virtual address of the mapped region which is page aligned.
/// `size` is the size of the mapped region in bytes.
#[derive(Clone)]
pub struct PhysPageMapInfo<const ALIGN: usize> {
    pub base: *mut u8,
    pub size: usize,
}

bitflags::bitflags! {
    /// Physical page map permissions which is a restricted version of
    /// [`litebox::platform::page_mgmt::MemoryRegionPermissions`].
    ///
    /// This module only supports READ and WRITE permissions. Both EXECUTE and SHARED
    /// permissions are explicitly prohibited.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PhysPageMapPermissions: u8 {
        /// Readable
        const READ = 1 << 0;
        /// Writable
        const WRITE = 1 << 1;
    }
}

/// Trait to map and unmap physical pages into virtually contiguous address space.
///
/// The implementation of this trait is platform-specific because it depends on how
/// the underlying platform manages page tables and memory regions.
pub trait PhysPageMapper {
    /// Map the given [`PhysPageArray`] into virtually contiguous address space with the given
    /// [`PhysPageMapPermissions`] while returning [`PhysPageMapInfo`].
    /// This function is analogous to Linux kernel's `vmap()`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `pages` are not in active use. LiteBox itself cannot fully guarantee this
    /// and it needs some helps from the caller, hypervisor, or hardware.
    unsafe fn vmap<const ALIGN: usize>(
        pages: PhysPageArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<PhysPageMapInfo<ALIGN>, PhysPointerError>;
    /// Unmap the previously mapped virtually contiguous address space ([`PhysPageMapInfo`]).
    /// This function is analogous to Linux kernel's `vunmap()`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the virtual addresses belonging to `vmap_info` are not in active use.
    /// Like `vmap()`, LiteBox itself cannot fully guarantee this and it needs some helps from other parties.
    unsafe fn vunmap<const ALIGN: usize>(
        vmap_info: PhysPageMapInfo<ALIGN>,
    ) -> Result<(), PhysPointerError>;
}

/// Represent a physical pointer to a read-only object.
/// - `pages`: An array of page-aligned physical addresses ([`PhysPageArray`]). Physical addresses in
///   this array should be virtually contiguous.
/// - `offset`: The offset within `pages[0]` where the object starts. It should be smaller than `ALIGN`.
/// - `T`: The type of the object being pointed to. `pages` with respect to `offset` should cover enough
///   memory for an object of type `T`.
/// - `V`: The validator type implementing [`ValidateAccess`] trait to validate the physical addresses
#[derive(Clone)]
#[repr(C)]
pub struct PhysConstPtr<V, M, T, const ALIGN: usize> {
    pages: PhysPageArray<ALIGN>,
    offset: usize,
    map_info: Option<PhysPageMapInfo<ALIGN>>,
    _type: core::marker::PhantomData<T>,
    _mapper: core::marker::PhantomData<M>,
    _validator: core::marker::PhantomData<V>,
}

impl<V: ValidateAccess, M: PhysPageMapper, T: Clone, const ALIGN: usize>
    PhysConstPtr<V, M, T, ALIGN>
{
    /// Create a new `PhysConstPtr` from the given physical page array and offset.
    pub fn try_from_page_array(
        pages: PhysPageArray<ALIGN>,
        offset: usize,
    ) -> Result<Self, PhysPointerError> {
        if offset >= ALIGN {
            return Err(PhysPointerError::InvalidBaseOffset(offset, ALIGN));
        }
        let size = if pages.0.is_empty() {
            0
        } else {
            ALIGN - offset + (pages.0.len() - 1) * ALIGN
        };
        if size < core::mem::size_of::<T>() {
            return Err(PhysPointerError::InsufficientPhysicalPages(
                size,
                core::mem::size_of::<T>(),
            ));
        }
        for pa in &pages.0 {
            V::validate::<T>(*pa)?;
        }
        Ok(Self {
            pages,
            offset,
            map_info: None,
            _type: core::marker::PhantomData,
            _mapper: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        })
    }
    /// Create a new `PhysConstPtr` from the given contiguous physical address and length.
    /// The caller must ensure that `pa`, ..., `pa+len` are both physically and virtually contiguous.
    pub fn try_from_contiguous_pages(pa: usize, len: usize) -> Result<Self, PhysPointerError> {
        if len < core::mem::size_of::<T>() {
            return Err(PhysPointerError::InsufficientPhysicalPages(
                len,
                core::mem::size_of::<T>(),
            ));
        }
        let start_page = pa - (pa % ALIGN);
        let end_page = pa + len;
        let end_page_aligned = if end_page.is_multiple_of(ALIGN) {
            end_page
        } else {
            end_page + (ALIGN - (end_page % ALIGN))
        };
        let mut pages = alloc::vec::Vec::new();
        let mut current_page = start_page;
        while current_page < end_page_aligned {
            V::validate::<T>(current_page)?;
            pages.push(current_page);
            current_page += ALIGN;
        }
        Self::try_from_page_array(PhysPageArray(pages.into()), pa - start_page)
    }
    /// Map the physical pages if not already mapped.
    fn map(&mut self) -> Result<(), PhysPointerError> {
        if self.map_info.is_none() {
            unsafe {
                self.map_info = Some(M::vmap(self.pages.clone(), PhysPageMapPermissions::READ)?);
            }
        }
        Ok(())
    }
    /// Unmap the physical pages if mapped.
    fn unmap(&mut self) -> Result<(), PhysPointerError> {
        if let Some(map_info) = self.map_info.take() {
            unsafe {
                M::vunmap(map_info)?;
            }
            self.map_info = None;
        }
        Ok(())
    }
    pub fn as_usize(&mut self) -> Result<usize, PhysPointerError> {
        todo!()
    }
    pub fn from_usize(&mut self, addr: usize) -> Result<(), PhysPointerError> {
        todo!()
    }
}

impl<V, M, T: Clone, const ALIGN: usize> core::fmt::Debug for PhysConstPtr<V, M, T, ALIGN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhysConstPtr")
            .field("pages", &self.pages.0)
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
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

// TODO: Sample no-op implementations to be removed. Implement a validation mechanism for
// VTL0 physical addresses (e.g., ensure this physical address does not belong to VTL1)
pub struct Novalidation;
impl ValidateAccess for Novalidation {
    fn validate<T>(pa: usize) -> Result<usize, PhysPointerError> {
        Ok(pa)
    }
}

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

/// Possible errors for physical page access
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum PhysPointerError {
    #[error("Physical address {0:#x} is invalid to access")]
    InvalidPhysicalAddress(usize),
    #[error("Physical address {0:#x} is not aligned to {1} bytes")]
    UnalignedPhysicalAddress(usize, usize),
    #[error("Offset {0:#x} is not aligned to {1} bytes")]
    UnalignedOffset(usize, usize),
    #[error("Base offset {0:#x} is greater than or equal to alignment ({1} bytes)")]
    InvalidBaseOffset(usize, usize),
    #[error(
        "The total size of the given pages ({0} bytes) is insufficient for the requested type ({1} bytes)"
    )]
    InsufficientPhysicalPages(usize, usize),
}

/// Normal world const pointer type. For now, we only consider VTL0 physical memory but it can be
/// something else like TrustZone normal world, other VMPL or TD partition, or other processes.
pub type NormalWorldConstPtr<T> = RemoteConstPtr<Novalidation, Vtl0PhysMemoryAccess, T>;

/// Normal world mutable pointer type. For now, we only consider VTL0 physical memory but it can be
/// something else like TrustZone normal world, other VMPL or TD partition, or other processes.
pub type NormalWorldMutPtr<T> = RemoteMutPtr<Novalidation, Vtl0PhysMemoryAccess, T>;
