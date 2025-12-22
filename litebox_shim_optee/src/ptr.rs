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

use litebox::platform::page_mgmt::MemoryRegionPermissions;
use thiserror::Error;

#[inline]
fn align_down(address: usize, align: usize) -> usize {
    address & !(align - 1)
}

#[inline]
fn align_up(len: usize, align: usize) -> usize {
    len.next_multiple_of(align)
}

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

/// Data structure for an array of physical pages. These physical pages should be
/// virtually contiguous in the source address space.
#[derive(Clone)]
pub struct PhysPageArray<const ALIGN: usize> {
    inner: alloc::boxed::Box<[usize]>,
}
impl<const ALIGN: usize> PhysPageArray<ALIGN> {
    /// Create a new `PhysPageArray` from the given slice of physical addresses.
    pub fn try_from_slice(addrs: &[usize]) -> Result<Self, PhysPointerError> {
        for addr in addrs {
            if !addr.is_multiple_of(ALIGN) {
                return Err(PhysPointerError::UnalignedPhysicalAddress(*addr, ALIGN));
            }
        }
        Ok(Self {
            inner: alloc::boxed::Box::from(addrs),
        })
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn iter(&self) -> impl Iterator<Item = &usize> {
        self.inner.iter()
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
impl From<MemoryRegionPermissions> for PhysPageMapPermissions {
    fn from(perms: MemoryRegionPermissions) -> Self {
        let mut phys_perms = PhysPageMapPermissions::empty();
        if perms.contains(MemoryRegionPermissions::READ) {
            phys_perms |= PhysPageMapPermissions::READ;
        }
        if perms.contains(MemoryRegionPermissions::WRITE) {
            phys_perms |= PhysPageMapPermissions::WRITE;
        }
        phys_perms
    }
}
impl From<PhysPageMapPermissions> for MemoryRegionPermissions {
    fn from(perms: PhysPageMapPermissions) -> Self {
        let mut mem_perms = MemoryRegionPermissions::empty();
        if perms.contains(PhysPageMapPermissions::READ) {
            mem_perms |= MemoryRegionPermissions::READ;
        }
        if perms.contains(PhysPageMapPermissions::WRITE) {
            mem_perms |= MemoryRegionPermissions::WRITE;
        }
        mem_perms
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

/// Represent a physical pointer to an object with on-demand mapping.
/// - `pages`: An array of page-aligned physical addresses ([`PhysPageArray`]). Physical addresses in
///   this array should be virtually contiguous.
/// - `offset`: The offset within `pages[0]` where the object starts. It should be smaller than `ALIGN`.
/// - `count`: The number of objects of type `T` that can be accessed from this pointer.
/// - `T`: The type of the object being pointed to. `pages` with respect to `offset` should cover enough
///   memory for an object of type `T`.
/// - `V`: The validator type implementing [`ValidateAccess`] trait to validate the physical addresses
#[derive(Clone)]
#[repr(C)]
pub struct PhysMutPtr<V, M, T, const ALIGN: usize> {
    pages: PhysPageArray<ALIGN>,
    offset: usize,
    count: usize,
    map_info: Option<PhysPageMapInfo<ALIGN>>,
    _type: core::marker::PhantomData<T>,
    _mapper: core::marker::PhantomData<M>,
    _validator: core::marker::PhantomData<V>,
}

impl<V: ValidateAccess, M: PhysPageMapper, T: Clone, const ALIGN: usize>
    PhysMutPtr<V, M, T, ALIGN>
{
    /// Create a new `PhysMutPtr` from the given physical page array and offset.
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
            V::validate::<T>(*pa)?;
        }
        Ok(Self {
            pages,
            offset,
            count: size / core::mem::size_of::<T>(),
            map_info: None,
            _type: core::marker::PhantomData,
            _mapper: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        })
    }
    /// Create a new `PhysMutPtr` from the given contiguous physical address and length.
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
            V::validate::<T>(current_page)?;
            pages.push(current_page);
            current_page += ALIGN;
        }
        Self::try_from_page_array(PhysPageArray::try_from_slice(&pages)?, pa - start_page)
    }
    /// Create a new `PhysMutPtr` from the given physical address for a single object.
    /// This is a shortcut for `try_from_contiguous_pages(pa, size_of::<T>())`.
    pub fn try_from_usize(pa: usize) -> Result<Self, PhysPointerError> {
        Self::try_from_contiguous_pages(pa, core::mem::size_of::<T>())
    }
    /// Read the value at the given offset from the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently accessed by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware).
    pub unsafe fn read_at_offset(
        &mut self,
        count: usize,
    ) -> Result<alloc::boxed::Box<T>, PhysPointerError> {
        if count >= self.count {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        self.map_all(PhysPageMapPermissions::READ)?;
        let Some(map_info) = &self.map_info else {
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
        self.unmap()?;
        Ok(alloc::boxed::Box::new(val))
    }
    /// Read a slice of values at the given offset from the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently accessed by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware).
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
        self.map_all(PhysPageMapPermissions::READ)?;
        let Some(map_info) = &self.map_info else {
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
        self.unmap()?;
        Ok(())
    }
    /// Write the value at the given offset to the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently accessed by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware).
    pub unsafe fn write_at_offset(
        &mut self,
        count: usize,
        value: T,
    ) -> Result<(), PhysPointerError> {
        if count >= self.count {
            return Err(PhysPointerError::IndexOutOfBounds(count, self.count));
        }
        self.map_all(PhysPageMapPermissions::READ | PhysPageMapPermissions::WRITE)?;
        let Some(map_info) = &self.map_info else {
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
        self.unmap()?;
        Ok(())
    }
    /// Write a slice of values at the given offset to the physical pointer.
    ///
    /// # Safety
    ///
    /// The caller should be aware that the given physical address might be concurrently accessed by
    /// other entities (e.g., the normal world kernel) if there is no extra security mechanism
    /// in place (e.g., by the hypervisor or hardware).
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
        self.map_all(PhysPageMapPermissions::READ | PhysPageMapPermissions::WRITE)?;
        let Some(map_info) = &self.map_info else {
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
        self.unmap()?;
        Ok(())
    }
    /// Map the physical pages if not already mapped.
    fn map_all(&mut self, perms: PhysPageMapPermissions) -> Result<(), PhysPointerError> {
        if self.map_info.is_none() {
            unsafe {
                self.map_info = Some(M::vmap(self.pages.clone(), perms)?);
            }
            Ok(())
        } else {
            Err(PhysPointerError::AlreadyMapped(
                self.pages.iter().next().copied().unwrap_or(0),
            ))
        }
    }
    /// Unmap the physical pages if mapped.
    fn unmap(&mut self) -> Result<(), PhysPointerError> {
        if let Some(map_info) = self.map_info.take() {
            unsafe {
                M::vunmap(map_info)?;
            }
            self.map_info = None;
            Ok(())
        } else {
            Err(PhysPointerError::Unmapped(
                self.pages.iter().next().copied().unwrap_or(0),
            ))
        }
    }
}

impl<V, M, T: Clone, const ALIGN: usize> core::fmt::Debug for PhysMutPtr<V, M, T, ALIGN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhysMutPtr")
            .field("pages[0]", &self.pages.iter().next().copied().unwrap_or(0))
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

/// Represent a physical pointer to a read-only object. This wraps around [`PhysMutPtr`] and
/// exposes only read access.
#[derive(Clone)]
#[repr(C)]
pub struct PhysConstPtr<V, M, T, const ALIGN: usize> {
    inner: PhysMutPtr<V, M, T, ALIGN>,
}
impl<V: ValidateAccess, M: PhysPageMapper, T: Clone, const ALIGN: usize>
    PhysConstPtr<V, M, T, ALIGN>
{
    /// Create a new `PhysConstPtr` from the given physical page array and offset.
    pub fn try_from_page_array(
        pages: PhysPageArray<ALIGN>,
        offset: usize,
    ) -> Result<Self, PhysPointerError> {
        Ok(Self {
            inner: PhysMutPtr::try_from_page_array(pages, offset)?,
        })
    }
    /// Create a new `PhysConstPtr` from the given contiguous physical address and length.
    /// The caller must ensure that `pa`, ..., `pa+bytes` are both physically and virtually contiguous.
    pub fn try_from_contiguous_pages(pa: usize, bytes: usize) -> Result<Self, PhysPointerError> {
        Ok(Self {
            inner: PhysMutPtr::try_from_contiguous_pages(pa, bytes)?,
        })
    }
    /// Create a new `PhysConstPtr` from the given physical address for a single object.
    /// This is a shortcut for `try_from_contiguous_pages(pa, size_of::<T>())`.
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
    /// in place (e.g., by the hypervisor or hardware).
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
    /// in place (e.g., by the hypervisor or hardware).
    pub unsafe fn read_slice_at_offset(
        &mut self,
        count: usize,
        values: &mut [T],
    ) -> Result<(), PhysPointerError> {
        unsafe { self.inner.read_slice_at_offset(count, values) }
    }
}

impl<V, M, T: Clone, const ALIGN: usize> core::fmt::Debug for PhysConstPtr<V, M, T, ALIGN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhysConstPtr")
            .field(
                "pages[0]",
                &self.inner.pages.iter().next().copied().unwrap_or(0),
            )
            .field("offset", &self.inner.offset)
            .finish_non_exhaustive()
    }
}

// TODO: Sample no-op implementations to be removed. Implement a validation mechanism for
// VTL0 physical addresses (e.g., ensure this physical address does not belong to VTL1)
pub struct NoValidation;
impl ValidateAccess for NoValidation {
    fn validate<T>(pa: usize) -> Result<usize, PhysPointerError> {
        Ok(pa)
    }
}

pub struct MockPhysMemoryMapper;
impl PhysPageMapper for MockPhysMemoryMapper {
    unsafe fn vmap<const ALIGN: usize>(
        pages: PhysPageArray<ALIGN>,
        _perms: PhysPageMapPermissions,
    ) -> Result<PhysPageMapInfo<ALIGN>, PhysPointerError> {
        Ok(PhysPageMapInfo {
            base: core::ptr::null_mut(),
            size: pages.iter().count() * ALIGN,
        })
    }
    unsafe fn vunmap<const ALIGN: usize>(
        _vmap_info: PhysPageMapInfo<ALIGN>,
    ) -> Result<(), PhysPointerError> {
        Ok(())
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
    #[error("Index {0} is out of bounds (count: {1})")]
    IndexOutOfBounds(usize, usize),
    #[error("Physical address {0:#x} is already mapped")]
    AlreadyMapped(usize),
    #[error("Physical address {0:#x} is unmapped")]
    Unmapped(usize),
    #[error("No mapping information available")]
    NoMappingInfo,
    #[error("Overflow occurred during calculation")]
    Overflow,
}

/// Normal world constant pointer type using MockPhysMemoryMapper for testing purposes.
pub type NormalWorldConstPtr<T, const ALIGN: usize> =
    PhysConstPtr<NoValidation, MockPhysMemoryMapper, T, ALIGN>;

/// Normal world mutable pointer type using MockPhysMemoryMapper for testing purposes.
pub type NormalWorldMutPtr<T, const ALIGN: usize> =
    PhysMutPtr<NoValidation, MockPhysMemoryMapper, T, ALIGN>;
