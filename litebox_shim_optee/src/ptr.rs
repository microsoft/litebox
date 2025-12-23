// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Physical Pointer Abstraction with On-demand Mapping
//!
//! This module adds supports for accessing physical addresses (e.g., VTL0 or
//! normal-world physical memory) from LiteBox with on-demand mapping.
//! In the context of LVBS and OP-TEE, accessing physical memory is necessary
//! because VTL0 and VTL1 as well as normal world and secure world do not share
//! the same virtual address space, but they still have to share data through memory.
//! VTL1 and secure world receive physical addresses from VTL0 and normal world,
//! respectively, and they need to read from or write to those addresses.
//!
//! To simplify all these, we could persistently map the entire VTL0/normal-world
//! physical memory into VTL1/secure-world address space at once and just access them
//! through corresponding virtual addresses. However, this module does not take these
//! approaches due to scalability (e.g., how to deal with a system with terabytes of
//! physical memory?) and security concerns (e.g., data corruption or information
//! leakage due to concurrent or persistent access).
//!
//! Instead, the approach this module takes is to map the required physical memory
//! region on-demand when accessing them while using a LiteBox-managed buffer to copy
//! data to/from those regions. This way, this module can ensure that data must be
//! copied into LiteBox-managed memory before being used while avoiding any unknown
//! side effects due to persistent memory mapping.
//!
//! Considerations:
//!
//! Ideally, this module should be able to validate whether a given physical address
//! is okay to access or even exists in the first place. For example, accessing
//! LiteBox's own memory with this physical pointer abstraction must be prohibited to
//! prevent the Boomerang attack and any other undefined memory access. Also, some
//! device memory is mapped to certain physical address ranges and LiteBox should not
//! touch them without in-depth knowledge. However, this is a bit tricky because, in
//! many cases, LiteBox does not directly interact with the underlying hardware or
//! BIOS/UEFI such that it does not have complete knowledge of the physical memory
//! layout. In the case of LVBS, LiteBox obtains the physical memory information
//! from VTL0 including the total physical memory size and the memory range assigned
//! to VTL1/LiteBox. Thus, this module can at least confirm a given physical address
//! does not belong to VTL1's physical memory.
//!
//! This module should allow byte-level access while transparently handling page
//! mapping and data access across page boundaries. This could become complicated
//! when we consider multiple page sizes (e.g., 4 KiB, 2 MiB, 1 GiB). Also,
//! unaligned access is matter to be considered.
//!
//! In addition, often times, this physical pointer abstraction is involved with
//! a list of physical addresses (i.e., scatter-gather list). For example, in
//! the worse case, a two-byte value can span across two non-contiguous physical
//! pages (the last byte of the first page and the first byte of the second page).
//! Thus, to enhance the performance, we may need to consider mapping multiple pages
//! at once, copy data from/to them, and unmap them later.
//!
//! When this module needs to access data across physical page boundaries, it assumes
//! that those physical pages are virtually contiguous in VTL0 or normal-world address
//! space. Otherwise, this module could end up with accessing unrelated data. This is
//! best-effort assumption and ensuring this is the caller's responsibility (e.g., even
//! if this module always requires a list of physical addresses, the caller might
//! provide a wrong list by mistake or intentionally).

// TODO: Since the below `PhysMutPtr` and `PhysConstPtr` are not OP-TEE specific,
// we can move them to a different crate (e.g., `litebox`) if needed.

use core::ops::Deref;
use litebox::platform::vmap::{
    PhysPageArray, PhysPageMapInfo, PhysPageMapPermissions, PhysPointerError, VmapProvider,
};
use litebox_platform_multiplex::{Platform, platform};

#[inline]
fn align_down(address: usize, align: usize) -> usize {
    address & !(align - 1)
}

#[inline]
fn align_up(len: usize, align: usize) -> usize {
    len.next_multiple_of(align)
}

/// Represent a physical pointer to an object with on-demand mapping.
/// - `pages`: An array of page-aligned physical addresses ([`PhysPageArray`]). Physical addresses in
///   this array should be virtually contiguous.
/// - `offset`: The offset within `pages[0]` where the object starts. It should be smaller than `ALIGN`.
/// - `count`: The number of objects of type `T` that can be accessed from this pointer.
/// - `map_info`: The mapping information of the currently mapped physical pages, if any.
/// - `T`: The type of the object being pointed to. `pages` with respect to `offset` should cover enough
///   memory for an object of type `T`.
#[derive(Clone)]
#[repr(C)]
pub struct PhysMutPtr<T, const ALIGN: usize> {
    pages: PhysPageArray<ALIGN>,
    offset: usize,
    count: usize,
    map_info: Option<PhysPageMapInfo<ALIGN>>,
    _type: core::marker::PhantomData<T>,
}

impl<T: Clone, const ALIGN: usize> PhysMutPtr<T, ALIGN> {
    /// Create a new `PhysMutPtr` from the given physical page array and offset.
    ///
    /// All addresses in `pages` must be valid and aligned to `ALIGN`, and `offset` must be smaller than `ALIGN`.
    /// Also, `pages` must contain enough pages to cover at least one object of type `T` starting from `offset`.
    pub fn try_from_page_array(
        pages: PhysPageArray<ALIGN>,
        offset: usize,
    ) -> Result<Self, PhysPointerError> {
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
        for pa in pages.iter() {
            <Platform as VmapProvider<ALIGN>>::validate::<T>(platform(), *pa)?;
        }
        Ok(Self {
            pages,
            offset,
            count: size / core::mem::size_of::<T>(),
            map_info: None,
            _type: core::marker::PhantomData,
        })
    }
    /// Create a new `PhysMutPtr` from the given contiguous physical address and length.
    ///
    /// This is a shortcut for `try_from_page_array([align_down(pa), ..., align_up(align_down(pa) + bytes)], pa % ALIGN)`.
    /// The caller must ensure that `pa`, ..., `pa+bytes` are both physically and virtually contiguous.
    pub fn try_from_contiguous_pages(pa: usize, bytes: usize) -> Result<Self, PhysPointerError> {
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
            <Platform as VmapProvider<ALIGN>>::validate::<T>(platform(), current_page)?;
            pages.push(current_page);
            current_page += ALIGN;
        }
        Self::try_from_page_array(PhysPageArray::try_from_slice(&pages)?, pa - start_page)
    }
    /// Create a new `PhysMutPtr` from the given physical address for a single object.
    ///
    /// This is a shortcut for `try_from_contiguous_pages(pa, size_of::<T>())`.
    ///
    /// Note: This module doesn't provide `as_usize` because LiteBox should not dereference physical addresses directly.
    pub fn try_from_usize(pa: usize) -> Result<Self, PhysPointerError> {
        Self::try_from_contiguous_pages(pa, core::mem::size_of::<T>())
    }
    /// Read the value at the given offset from the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently accessed by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware). That it, it might read corrupt data.
    pub unsafe fn read_at_offset(
        &mut self,
        count: usize,
    ) -> Result<alloc::boxed::Box<T>, PhysPointerError> {
        if count >= self.count {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        let skip = self
            .offset
            .checked_add(
                count
                    .checked_mul(core::mem::size_of::<T>())
                    .ok_or(PhysPointerError::Overflow)?,
            )
            .ok_or(PhysPointerError::Overflow)?;
        let start = skip / ALIGN;
        let end = (skip + core::mem::size_of::<T>()).div_ceil(ALIGN);
        unsafe {
            self.map_range(start, end, PhysPageMapPermissions::READ)?;
        }
        // Don't forget to call unmap() before returning to the caller
        let Some(map_info) = &self.map_info else {
            unsafe {
                self.unmap()?;
            }
            return Err(PhysPointerError::NoMappingInfo);
        };
        let addr = unsafe { map_info.base.add(self.offset) }
            .cast::<T>()
            .wrapping_add(count);
        let val = {
            let mut buffer = core::mem::MaybeUninit::<T>::uninit();
            if (addr as usize).is_multiple_of(core::mem::align_of::<T>()) {
                unsafe {
                    core::ptr::copy_nonoverlapping(addr, buffer.as_mut_ptr(), 1);
                }
            } else {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        addr.cast::<u8>(),
                        buffer.as_mut_ptr().cast::<u8>(),
                        core::mem::size_of::<T>(),
                    );
                }
            }
            unsafe { buffer.assume_init() }
        };
        unsafe {
            self.unmap()?;
        }
        Ok(alloc::boxed::Box::new(val))
    }
    /// Read a slice of values at the given offset from the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently accessed by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware). That is, it might read corrupt data.
    pub unsafe fn read_slice_at_offset(
        &mut self,
        count: usize,
        values: &mut [T],
    ) -> Result<(), PhysPointerError> {
        if count
            .checked_add(values.len())
            .is_none_or(|end| end > self.count)
        {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        let skip = self
            .offset
            .checked_add(
                count
                    .checked_mul(core::mem::size_of::<T>())
                    .ok_or(PhysPointerError::Overflow)?,
            )
            .ok_or(PhysPointerError::Overflow)?;
        let start = skip / ALIGN;
        let end = (skip + core::mem::size_of_val(values)).div_ceil(ALIGN);
        unsafe {
            self.map_range(start, end, PhysPageMapPermissions::READ)?;
        }
        // Don't forget to call unmap() before returning to the caller
        let Some(map_info) = &self.map_info else {
            unsafe {
                self.unmap()?;
            }
            return Err(PhysPointerError::NoMappingInfo);
        };
        let addr = unsafe { map_info.base.add(self.offset) }
            .cast::<T>()
            .wrapping_add(count);
        if (addr as usize).is_multiple_of(core::mem::align_of::<T>()) {
            unsafe {
                core::ptr::copy_nonoverlapping(addr, values.as_mut_ptr(), values.len());
            }
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    addr.cast::<u8>(),
                    values.as_mut_ptr().cast::<u8>(),
                    core::mem::size_of_val(values),
                );
            }
        }
        unsafe {
            self.unmap()?;
        }
        Ok(())
    }
    /// Write the value at the given offset to the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently accessed by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware). That is, data it writes might be overwritten.
    pub unsafe fn write_at_offset(
        &mut self,
        count: usize,
        value: T,
    ) -> Result<(), PhysPointerError> {
        if count >= self.count {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        let skip = self
            .offset
            .checked_add(
                count
                    .checked_mul(core::mem::size_of::<T>())
                    .ok_or(PhysPointerError::Overflow)?,
            )
            .ok_or(PhysPointerError::Overflow)?;
        let start = skip / ALIGN;
        let end = (skip + core::mem::size_of::<T>()).div_ceil(ALIGN);
        unsafe {
            self.map_range(
                start,
                end,
                PhysPageMapPermissions::READ | PhysPageMapPermissions::WRITE,
            )?;
        }
        // Don't forget to call unmap() before returning to the caller
        let Some(map_info) = &self.map_info else {
            unsafe {
                self.unmap()?;
            }
            return Err(PhysPointerError::NoMappingInfo);
        };
        let addr = unsafe { map_info.base.add(self.offset) }
            .cast::<T>()
            .wrapping_add(count);
        if (addr as usize).is_multiple_of(core::mem::align_of::<T>()) {
            unsafe { core::ptr::write(addr, value) };
        } else {
            unsafe { core::ptr::write_unaligned(addr, value) };
        }
        unsafe {
            self.unmap()?;
        }
        Ok(())
    }
    /// Write a slice of values at the given offset to the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently accessed by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware). That is, data it writes might be overwritten.
    pub unsafe fn write_slice_at_offset(
        &mut self,
        count: usize,
        values: &[T],
    ) -> Result<(), PhysPointerError> {
        if count
            .checked_add(values.len())
            .is_none_or(|end| end > self.count)
        {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        let skip = self
            .offset
            .checked_add(
                count
                    .checked_mul(core::mem::size_of::<T>())
                    .ok_or(PhysPointerError::Overflow)?,
            )
            .ok_or(PhysPointerError::Overflow)?;
        let start = skip / ALIGN;
        let end = (skip + core::mem::size_of_val(values)).div_ceil(ALIGN);
        unsafe {
            self.map_range(
                start,
                end,
                PhysPageMapPermissions::READ | PhysPageMapPermissions::WRITE,
            )?;
        }
        // Don't forget to call unmap() before returning to the caller
        let Some(map_info) = &self.map_info else {
            unsafe {
                self.unmap()?;
            }
            return Err(PhysPointerError::NoMappingInfo);
        };
        let addr = unsafe { map_info.base.add(self.offset) }
            .cast::<T>()
            .wrapping_add(count);
        if (addr as usize).is_multiple_of(core::mem::align_of::<T>()) {
            unsafe {
                core::ptr::copy_nonoverlapping(values.as_ptr(), addr, values.len());
            }
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    values.as_ptr().cast::<u8>(),
                    addr.cast::<u8>(),
                    core::mem::size_of_val(values),
                );
            }
        }
        unsafe {
            self.unmap()?;
        }
        Ok(())
    }
    /// Map the physical pages from `start` to `end` indexes.
    ///
    /// # Safety
    ///
    /// This function assumes that the underlying platform safely handles concurrent mapping/unmapping
    /// requests for the same physical pages.
    unsafe fn map_range(
        &mut self,
        start: usize,
        end: usize,
        perms: PhysPageMapPermissions,
    ) -> Result<(), PhysPointerError> {
        if start >= end || end > self.pages.len() {
            return Err(PhysPointerError::IndexOutOfBounds(end, self.pages.len()));
        }
        if self.map_info.is_none() {
            let sub_pages = PhysPageArray::try_from_slice(&self.pages.deref()[start..end])?;
            unsafe {
                self.map_info = Some(platform().vmap(sub_pages, perms)?);
            }
            Ok(())
        } else {
            Err(PhysPointerError::AlreadyMapped(
                self.pages.first().unwrap_or(0),
            ))
        }
    }
    /// Unmap the physical pages if mapped.
    ///
    /// # Safety
    ///
    /// This function assumes that the underlying platform safely handles concurrent mapping/unmapping
    /// requests for the same physical pages.
    unsafe fn unmap(&mut self) -> Result<(), PhysPointerError> {
        if let Some(map_info) = self.map_info.take() {
            unsafe {
                platform().vunmap(map_info)?;
            }
            self.map_info = None;
            Ok(())
        } else {
            Err(PhysPointerError::Unmapped(self.pages.first().unwrap_or(0)))
        }
    }
}

impl<T: Clone, const ALIGN: usize> core::fmt::Debug for PhysMutPtr<T, ALIGN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhysMutPtr")
            .field("pages[0]", &self.pages.first().unwrap_or(0))
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

/// Represent a physical pointer to a read-only object. This wraps around [`PhysMutPtr`] and
/// exposes only read access.
#[derive(Clone)]
#[repr(C)]
pub struct PhysConstPtr<T, const ALIGN: usize> {
    inner: PhysMutPtr<T, ALIGN>,
}
impl<T: Clone, const ALIGN: usize> PhysConstPtr<T, ALIGN> {
    /// Create a new `PhysMutPtr` from the given physical page array and offset.
    ///
    /// All addresses in `pages` must be valid and aligned to `ALIGN`, and `offset` must be smaller than `ALIGN`.
    /// Also, `pages` must contain enough pages to cover at least one object of type `T` starting from `offset`.
    pub fn try_from_page_array(
        pages: PhysPageArray<ALIGN>,
        offset: usize,
    ) -> Result<Self, PhysPointerError> {
        Ok(Self {
            inner: PhysMutPtr::try_from_page_array(pages, offset)?,
        })
    }
    /// Create a new `PhysMutPtr` from the given contiguous physical address and length.
    ///
    /// This is a shortcut for `try_from_page_array([align_down(pa), ..., align_up(align_down(pa) + bytes)], pa % ALIGN)`.
    /// The caller must ensure that `pa`, ..., `pa+bytes` are both physically and virtually contiguous.
    pub fn try_from_contiguous_pages(pa: usize, bytes: usize) -> Result<Self, PhysPointerError> {
        Ok(Self {
            inner: PhysMutPtr::try_from_contiguous_pages(pa, bytes)?,
        })
    }
    /// Create a new `PhysMutPtr` from the given physical address for a single object.
    ///
    /// This is a shortcut for `try_from_contiguous_pages(pa, size_of::<T>())`.
    ///
    /// Note: This module doesn't provide `as_usize` because LiteBox should not dereference physical addresses directly.
    pub fn try_from_usize(pa: usize) -> Result<Self, PhysPointerError> {
        Ok(Self {
            inner: PhysMutPtr::try_from_usize(pa)?,
        })
    }
    /// Read the value at the given offset from the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently accessed by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware). That is, it might read corrupt data.
    pub unsafe fn read_at_offset(
        &mut self,
        count: usize,
    ) -> Result<alloc::boxed::Box<T>, PhysPointerError> {
        unsafe { self.inner.read_at_offset(count) }
    }
    /// Read a slice of values at the given offset from the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently accessed by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware). That is, it might read corrupt data.
    pub unsafe fn read_slice_at_offset(
        &mut self,
        count: usize,
        values: &mut [T],
    ) -> Result<(), PhysPointerError> {
        unsafe { self.inner.read_slice_at_offset(count, values) }
    }
}

impl<T: Clone, const ALIGN: usize> core::fmt::Debug for PhysConstPtr<T, ALIGN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhysConstPtr")
            .field("pages[0]", &self.inner.pages.first().unwrap_or(0))
            .field("offset", &self.inner.offset)
            .finish_non_exhaustive()
    }
}
