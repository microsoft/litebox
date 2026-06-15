// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Physical Pointer Abstraction with On-demand Mapping
//!
//! This module adds supports for accessing physical addresses (e.g., VTL0
//! or normal-world physical memory) from LiteBox with on-demand mapping.
//! In the context of LVBS and OP-TEE, accessing physical memory is
//! necessary because VTL0 and VTL1 as well as normal world and secure
//! world exchange data using physical addresses.
//!
//! The safe read/write APIs in this module follow the same safety model as
//! safe wrappers around DMA buffers or shared physical memory. The
//! physical memory is external to Rust's ordinary ownership model and may
//! be changed by hardware or another privilege level. These APIs remain
//! safe because they do not create Rust references into that external
//! memory; they only perform bounded copies between a temporary mapping
//! and memory owned by LiteBox. Cooperating LiteBox mappings are
//! serialized by the platform's access reservation policy so safe
//! callers cannot create conflicting mappings through this abstraction.
//!
//! The safe APIs should validate whether a given physical address is okay
//! to access. For example, accessing LiteBox's own memory through this
//! physical pointer abstraction is prohibited to avoid confused-deputy
//! attacks and to ensure Rust memory safety. In the case of LVBS, LiteBox
//! obtains the physical memory information from VTL0 like the total
//! physical memory range assigned to VTL1/LiteBox. Thus, this module can
//! confirm a given physical address does not belong to VTL1's physical
//! memory.

use crate::vmap::{
    GlobalVmapManager, PhysPageAddr, PhysPageMapInfo, PhysPageMapPermissions, PhysPointerError,
    VmapManager,
};
use core::marker::PhantomData;
use zerocopy::{FromBytes, IntoBytes};

/// The concrete [`PhysPageMapInfo`] produced by the `VmapManager` behind a [`GlobalVmapManager`].
type MapInfoOf<V, const ALIGN: usize> =
    <<V as GlobalVmapManager<ALIGN>>::Manager as VmapManager<ALIGN>>::MapInfo;

/// Allocate a zeroed `Box<T>` on the heap.
///
/// # Panics
///
/// Panics if `T` is a zero-sized type, since `alloc_zeroed` with a zero-sized
/// layout is undefined behavior.
fn box_new_zeroed<T: FromBytes>() -> alloc::boxed::Box<T> {
    assert!(
        core::mem::size_of::<T>() > 0,
        "box_new_zeroed does not support zero-sized types"
    );
    let layout = core::alloc::Layout::new::<T>();
    // Safety: layout has a non-zero size and correct alignment for T.
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) }.cast::<T>();
    if ptr.is_null() {
        alloc::alloc::handle_alloc_error(layout);
    }
    // Safety: ptr is a valid, zeroed, properly aligned heap allocation for T.
    // T: FromBytes guarantees all-zero is a valid bit pattern.
    unsafe { alloc::boxed::Box::from_raw(ptr) }
}

#[inline]
fn align_down(address: usize, align: usize) -> usize {
    address & !(align - 1)
}

#[inline]
fn align_up(len: usize, align: usize) -> usize {
    len.next_multiple_of(align)
}

/// Represent a physical pointer to an object with on-demand mapping.
///
/// Safe methods on this type copy to or from a temporary mapping. They never expose
/// references or slices into the mapped physical memory.
///
/// Read methods require `T: FromBytes` because external memory may contain any bit pattern.
/// Write methods require `T: IntoBytes` because values are written by copying their byte
/// representation.
///
/// - `pages`: An array of page-aligned physical addresses. We expect physical addresses in this array are
///   virtually contiguous.
/// - `offset`: The offset within `pages[0]` where the object starts. It should be smaller than `ALIGN`.
/// - `count`: The number of objects of type `T` that can be accessed from this pointer.
/// - `T`: The type of the object being pointed to. `pages` with respect to `offset` should cover enough
///   memory for an object of type `T`.
#[repr(C)]
pub struct PhysMutPtr<T: Clone, const ALIGN: usize, V: GlobalVmapManager<ALIGN>> {
    pages: alloc::boxed::Box<[PhysPageAddr<ALIGN>]>,
    offset: usize,
    count: usize,
    _type: PhantomData<T>,
    _vmap: PhantomData<V>,
}

impl<T: Clone, const ALIGN: usize, V> PhysMutPtr<T, ALIGN, V>
where
    V: GlobalVmapManager<ALIGN>,
{
    /// Create a new `PhysMutPtr` from the given physical page array and offset.
    ///
    /// All addresses in `pages` should be valid and aligned to `ALIGN`, and `offset` should be
    /// smaller than `ALIGN`. Also, `pages` should contain enough pages to cover at least one
    /// object of type `T` starting from `offset`. If these conditions are not met, this function
    /// returns `Err(PhysPointerError)`.
    pub fn new(pages: &[PhysPageAddr<ALIGN>], offset: usize) -> Result<Self, PhysPointerError> {
        if core::mem::size_of::<T>() == 0 {
            return Err(PhysPointerError::UnsupportedZeroSizedType);
        }
        if offset >= ALIGN {
            return Err(PhysPointerError::InvalidBaseOffset(offset, ALIGN));
        }
        let size = if pages.is_empty() {
            0
        } else {
            pages
                .len()
                .checked_mul(ALIGN)
                .ok_or(PhysPointerError::Overflow)?
                - offset
        };
        if size < core::mem::size_of::<T>() {
            return Err(PhysPointerError::InsufficientPhysicalPages(
                size,
                core::mem::size_of::<T>(),
            ));
        }
        V::manager().validate_unowned(pages)?;
        Ok(Self {
            pages: pages.into(),
            offset,
            count: size / core::mem::size_of::<T>(),
            _type: PhantomData,
            _vmap: PhantomData,
        })
    }

    /// Create a new `PhysMutPtr` from the given contiguous physical address and length.
    ///
    /// This is a shortcut for
    /// `PhysMutPtr::new([align_down(pa), align_down(pa) + ALIGN, ..., align_up(pa + bytes) - ALIGN], pa % ALIGN)`.
    /// This function assumes that `pa`, ..., `pa+bytes` are both physically and virtually contiguous. If not,
    /// later accesses through `PhysMutPtr` may read/write data in a wrong order.
    pub fn with_contiguous_pages(pa: usize, bytes: usize) -> Result<Self, PhysPointerError> {
        if bytes < core::mem::size_of::<T>() {
            return Err(PhysPointerError::InsufficientPhysicalPages(
                bytes,
                core::mem::size_of::<T>(),
            ));
        }
        let start_page = align_down(pa, ALIGN);
        let end_page = align_up(
            pa.checked_add(bytes).ok_or(PhysPointerError::Overflow)?,
            ALIGN,
        );
        let mut pages = alloc::vec::Vec::with_capacity((end_page - start_page) / ALIGN);
        let mut current_page = start_page;
        while current_page < end_page {
            pages.push(
                PhysPageAddr::<ALIGN>::new(current_page)
                    .ok_or(PhysPointerError::InvalidPhysicalAddress(current_page))?,
            );
            current_page += ALIGN;
        }
        Self::new(&pages, pa - start_page)
    }

    /// Create a new `PhysMutPtr` from the given physical address for a single object.
    ///
    /// This is a shortcut for `PhysMutPtr::with_contiguous_pages(pa, size_of::<T>())`.
    ///
    /// Note: This module doesn't provide `as_usize` because LiteBox should not dereference physical addresses directly.
    pub fn with_usize(pa: usize) -> Result<Self, PhysPointerError> {
        Self::with_contiguous_pages(pa, core::mem::size_of::<T>())
    }

    /// Read the value at the given offset from the physical pointer.
    ///
    /// Returns an owned copy of the value read from physical memory.
    pub fn read_at_offset(&self, count: usize) -> Result<alloc::boxed::Box<T>, PhysPointerError>
    where
        T: FromBytes,
    {
        if count >= self.count {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        let guard = unsafe {
            self.map_and_get_ptr_guard(
                count,
                core::mem::size_of::<T>(),
                PhysPageMapPermissions::READ,
            )?
        };
        let mut boxed = box_new_zeroed::<T>();
        // Fallible: another core may unmap this page concurrently.
        let result = unsafe {
            litebox::mm::exception_table::memcpy_fallible(
                core::ptr::from_mut::<T>(boxed.as_mut()).cast::<u8>(),
                guard.ptr.cast::<u8>(),
                guard.size,
            )
        };
        debug_assert!(result.is_ok(), "fault reading from mapped physical page");
        result.map_err(|_| PhysPointerError::CopyFailed)?;
        Ok(boxed)
    }

    /// Read a slice of values at the given offset from the physical pointer.
    ///
    /// Copies values from physical memory into the caller-provided slice.
    pub fn read_slice_at_offset(
        &self,
        count: usize,
        values: &mut [T],
    ) -> Result<(), PhysPointerError>
    where
        T: FromBytes,
    {
        if values.is_empty() {
            return Ok(());
        }
        if count
            .checked_add(values.len())
            .is_none_or(|end| end > self.count)
        {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        let guard = unsafe {
            self.map_and_get_ptr_guard(
                count,
                core::mem::size_of_val(values),
                PhysPageMapPermissions::READ,
            )?
        };
        // Fallible: another core may unmap this page concurrently.
        let result = unsafe {
            litebox::mm::exception_table::memcpy_fallible(
                values.as_mut_ptr().cast::<u8>(),
                guard.ptr.cast::<u8>(),
                guard.size,
            )
        };
        debug_assert!(result.is_ok(), "fault reading from mapped physical page");
        result.map_err(|_| PhysPointerError::CopyFailed)?;
        Ok(())
    }

    /// Write the value at the given offset to the physical pointer.
    pub fn write_at_offset(&self, count: usize, value: T) -> Result<(), PhysPointerError>
    where
        T: IntoBytes,
    {
        if count >= self.count {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        let guard = unsafe {
            self.map_and_get_ptr_guard(
                count,
                core::mem::size_of::<T>(),
                PhysPageMapPermissions::READ | PhysPageMapPermissions::WRITE,
            )?
        };
        // Fallible: another core may unmap this page concurrently.
        let result = unsafe {
            litebox::mm::exception_table::memcpy_fallible(
                guard.ptr.cast::<u8>(),
                core::ptr::from_ref(&value).cast::<u8>(),
                guard.size,
            )
        };
        debug_assert!(result.is_ok(), "fault writing to mapped physical page");
        result.map_err(|_| PhysPointerError::CopyFailed)?;
        Ok(())
    }

    /// Write a slice of values at the given offset to the physical pointer.
    pub fn write_slice_at_offset(&self, count: usize, values: &[T]) -> Result<(), PhysPointerError>
    where
        T: IntoBytes,
    {
        if values.is_empty() {
            return Ok(());
        }
        if count
            .checked_add(values.len())
            .is_none_or(|end| end > self.count)
        {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        let guard = unsafe {
            self.map_and_get_ptr_guard(
                count,
                core::mem::size_of_val(values),
                PhysPageMapPermissions::READ | PhysPageMapPermissions::WRITE,
            )?
        };
        // Fallible: another core may unmap this page concurrently.
        let result = unsafe {
            litebox::mm::exception_table::memcpy_fallible(
                guard.ptr.cast::<u8>(),
                values.as_ptr().cast::<u8>(),
                guard.size,
            )
        };
        debug_assert!(result.is_ok(), "fault writing to mapped physical page");
        result.map_err(|_| PhysPointerError::CopyFailed)?;
        Ok(())
    }

    /// This function maps physical pages for the requested data element at a given
    /// index and returns a guard that unmaps on drop.
    ///
    /// It bridges element-level access (used by `read_at_offset`, `write_at_offset`, etc.)
    /// with page-level mapping. It determines which physical pages contain the requested
    /// element, maps them into virtual memory, and returns a pointer adjusted for
    /// the element's position.
    ///
    /// - `count`: Element index (0-based) within this physical pointer's range.
    /// - `size`: Total byte size to map (must cover the data being accessed).
    /// - `perms`: Required page permissions (read, write).
    ///
    /// # Safety
    ///
    /// Same as [`Self::map_range`]. The returned guard is tied to `self`'s lifetime
    /// and releases the mapping when it goes out of scope.
    unsafe fn map_and_get_ptr_guard(
        &self,
        count: usize,
        size: usize,
        perms: PhysPageMapPermissions,
    ) -> Result<MappedGuard<'_, T, ALIGN, V>, PhysPointerError> {
        let skip = self
            .offset
            .checked_add(
                count
                    .checked_mul(core::mem::size_of::<T>())
                    .ok_or(PhysPointerError::Overflow)?,
            )
            .ok_or(PhysPointerError::Overflow)?;
        let start = skip / ALIGN;
        let end = (skip + size).div_ceil(ALIGN);
        let map_info = unsafe { self.map_range(start, end, perms)? };
        let ptr = map_info.base().wrapping_add(skip % ALIGN).cast::<T>();
        Ok(MappedGuard {
            map_info: Some(map_info),
            ptr,
            size,
            _owner: PhantomData,
        })
    }

    /// Map the physical pages from `start` to `end` indexes.
    ///
    /// # Safety
    ///
    /// This function assumes that the underlying platform safely handles concurrent mapping/unmapping
    /// requests for the same physical pages.
    unsafe fn map_range(
        &self,
        start: usize,
        end: usize,
        perms: PhysPageMapPermissions,
    ) -> Result<MapInfoOf<V, ALIGN>, PhysPointerError> {
        if start >= end || end > self.pages.len() {
            return Err(PhysPointerError::IndexOutOfBounds(end, self.pages.len()));
        }
        let accept_perms = PhysPageMapPermissions::READ | PhysPageMapPermissions::WRITE;
        if perms.bits() & !accept_perms.bits() != 0 {
            return Err(PhysPointerError::UnsupportedPermissions(perms.bits()));
        }
        let sub_pages = &self.pages[start..end];
        unsafe { V::manager().vmap(sub_pages, perms) }
    }
}

/// RAII guard that unmaps physical pages when dropped.
///
/// Created by `map_and_get_ptr_guard`. Its lifetime is tied to the parent
/// `PhysMutPtr`, and it owns the map info for the duration of the temporary mapping.
struct MappedGuard<'a, T: Clone, const ALIGN: usize, V: GlobalVmapManager<ALIGN>> {
    map_info: Option<MapInfoOf<V, ALIGN>>,
    ptr: *mut T,
    size: usize,
    _owner: PhantomData<&'a PhysMutPtr<T, ALIGN, V>>,
}

impl<T: Clone, const ALIGN: usize, V: GlobalVmapManager<ALIGN>> Drop
    for MappedGuard<'_, T, ALIGN, V>
{
    fn drop(&mut self) {
        // SAFETY: The platform is expected to handle unmapping safely. Drop cannot
        // report errors. If unmapping fails, drop the returned private map_info;
        // platform-specific resources that cannot be reclaimed are handled by the
        // platform `vunmap` implementation.
        if let Some(map_info) = self.map_info.take() {
            let _ = unsafe { V::manager().vunmap(map_info) };
        }
    }
}

impl<T: Clone, const ALIGN: usize, V: GlobalVmapManager<ALIGN>> core::fmt::Debug
    for PhysMutPtr<T, ALIGN, V>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhysMutPtr")
            .field("pages[0]", &self.pages.first().map_or(0, |p| p.as_usize()))
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

/// Represent a physical pointer to a read-only object. This wraps around [`PhysMutPtr`] and
/// exposes only copy-out access.
#[repr(C)]
pub struct PhysConstPtr<T: Clone, const ALIGN: usize, V: GlobalVmapManager<ALIGN>> {
    inner: PhysMutPtr<T, ALIGN, V>,
}

impl<T: Clone + FromBytes, const ALIGN: usize, V> PhysConstPtr<T, ALIGN, V>
where
    V: GlobalVmapManager<ALIGN>,
{
    /// Create a new `PhysConstPtr` from the given physical page array and offset.
    ///
    /// All addresses in `pages` should be valid and aligned to `ALIGN`, and `offset` should be smaller
    /// than `ALIGN`. Also, `pages` should contain enough pages to cover at least one object of
    /// type `T` starting from `offset`. If these conditions are not met, this function returns
    /// `Err(PhysPointerError)`.
    pub fn new(pages: &[PhysPageAddr<ALIGN>], offset: usize) -> Result<Self, PhysPointerError> {
        Ok(Self {
            inner: PhysMutPtr::new(pages, offset)?,
        })
    }

    /// Create a new `PhysConstPtr` from the given contiguous physical address and length.
    ///
    /// This is a shortcut for
    /// `PhysConstPtr::new([align_down(pa), align_down(pa) + ALIGN, ..., align_up(pa + bytes) - ALIGN], pa % ALIGN)`.
    /// This function assumes that `pa`, ..., `pa+bytes` are both physically and virtually contiguous. If not,
    /// later accesses through `PhysConstPtr` may read data in a wrong order.
    pub fn with_contiguous_pages(pa: usize, bytes: usize) -> Result<Self, PhysPointerError> {
        Ok(Self {
            inner: PhysMutPtr::with_contiguous_pages(pa, bytes)?,
        })
    }

    /// Create a new `PhysConstPtr` from the given physical address for a single object.
    ///
    /// This is a shortcut for `PhysConstPtr::with_contiguous_pages(pa, size_of::<T>())`.
    ///
    /// Note: This module doesn't provide `as_usize` because LiteBox should not dereference physical addresses directly.
    pub fn with_usize(pa: usize) -> Result<Self, PhysPointerError> {
        Ok(Self {
            inner: PhysMutPtr::with_usize(pa)?,
        })
    }

    /// Read the value at the given offset from the physical pointer.
    ///
    /// Returns an owned copy of the value read from physical memory.
    pub fn read_at_offset(&mut self, count: usize) -> Result<alloc::boxed::Box<T>, PhysPointerError>
    where
        T: FromBytes,
    {
        self.inner.read_at_offset(count)
    }

    /// Read a slice of values at the given offset from the physical pointer.
    ///
    /// Copies values from physical memory into the caller-provided slice.
    pub fn read_slice_at_offset(
        &mut self,
        count: usize,
        values: &mut [T],
    ) -> Result<(), PhysPointerError>
    where
        T: FromBytes,
    {
        self.inner.read_slice_at_offset(count, values)
    }
}

impl<T: Clone, const ALIGN: usize, V: GlobalVmapManager<ALIGN>> core::fmt::Debug
    for PhysConstPtr<T, ALIGN, V>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhysConstPtr")
            .field(
                "pages[0]",
                &self.inner.pages.first().map_or(0, |p| p.as_usize()),
            )
            .field("offset", &self.inner.offset)
            .finish_non_exhaustive()
    }
}
