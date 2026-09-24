// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Memory management related functionality

pub mod allocator;
pub mod exception_table;
pub mod linux;
mod vmem;
pub mod windows;

#[cfg(test)]
mod tests;

use core::ops::Range;

use alloc::vec::Vec;

use vmem::Vmem;
pub use vmem::{
    CreatePagesFlags, DEFAULT_RESERVED_SPACE_SIZE, MappingError, NonZeroAddress, NonZeroPageSize,
    PAGE_SIZE, PageFaultError, PageRange, VmFlags, VmemMoveError, VmemPageFaultHandler,
    VmemProtectError, VmemResetError, VmemUnmapError,
};

use crate::{
    LiteBox,
    platform::{
        PageManagementProvider, RawConstPointer, RawPointerProvider,
        page_mgmt::{
            MemoryRegionPermissions, ReleaseTargetOf, ReservationOf, ReservationStore,
            TrackedReservations,
        },
    },
    sync::{RawSyncPrimitivesProvider, RwLock},
};

/// Linux-style automatic mapping policy.
pub enum Linux {}

/// Windows-style explicit reservation policy.
pub enum Windows {}

/// A page-manager style supported by a provider's reservation representation.
#[doc(hidden)]
pub trait PageManagerStyleFor<Platform, const ALIGN: usize>
where
    Platform: PageManagementProvider<ALIGN>,
{
    type Reservations: ReservationStore<
            Reservation = ReservationOf<Platform, ALIGN>,
            ReleaseTarget: Into<ReleaseTargetOf<Platform, ALIGN>>,
        >;
}

impl<Platform, const ALIGN: usize> PageManagerStyleFor<Platform, ALIGN> for Linux
where
    Platform: PageManagementProvider<ALIGN>,
{
    type Reservations = Platform::Reservations;
}

impl<Platform, const ALIGN: usize> PageManagerStyleFor<Platform, ALIGN> for Windows
where
    Platform: PageManagementProvider<ALIGN>,
{
    type Reservations = TrackedReservations<ReservationOf<Platform, ALIGN>>;
}

/// An owning manager for Linux-style automatic mappings.
///
/// Explicit Windows reservation operations are unavailable on this type.
///
/// ```compile_fail,E0599
/// use litebox::{mm::LinuxPageManager, platform::{PageManagementProvider, RawPointerProvider}, sync::RawSyncPrimitivesProvider};
/// fn release<Platform: RawSyncPrimitivesProvider + RawPointerProvider + PageManagementProvider<4096>>(
///     manager: &LinuxPageManager<Platform, 4096>, pointer: Platform::RawMutPointer<u8>,
/// ) {
///     unsafe { manager.remove_pages(pointer, 4096) }.unwrap();
/// }
/// ```
pub type LinuxPageManager<Platform, const ALIGN: usize> = PageManager<Platform, ALIGN, Linux>;

/// An owning manager for Windows-style explicit reservations.
///
/// Linux mapping operations are unavailable on this type.
///
/// ```compile_fail,E0599
/// use litebox::{mm::WindowsPageManager, platform::{PageManagementProvider, RawPointerProvider}, sync::RawSyncPrimitivesProvider};
/// fn unmap<Platform: RawSyncPrimitivesProvider + RawPointerProvider + PageManagementProvider<4096>>(
///     manager: &WindowsPageManager<Platform, 4096>, pointer: Platform::RawMutPointer<u8>,
/// ) {
///     unsafe { manager.unmap_pages(pointer, 4096) }.unwrap();
/// }
/// ```
///
/// ```compile_fail,E0599
/// use litebox::{mm::WindowsPageManager, platform::{PageManagementProvider, RawPointerProvider}, sync::RawSyncPrimitivesProvider};
/// fn reset<Platform: RawSyncPrimitivesProvider + RawPointerProvider + PageManagementProvider<4096>>(
///     manager: &WindowsPageManager<Platform, 4096>, pointer: Platform::RawMutPointer<u8>,
/// ) {
///     unsafe { manager.reset_pages(pointer, 4096, true) }.unwrap();
/// }
/// ```
///
/// The two families are distinct owning types, not interchangeable views.
///
/// ```compile_fail,E0308
/// use litebox::{mm::{LinuxPageManager, WindowsPageManager}, platform::{PageManagementProvider, RawPointerProvider}, sync::RawSyncPrimitivesProvider};
/// fn switch<Platform: RawSyncPrimitivesProvider + RawPointerProvider + PageManagementProvider<4096>>(
///     manager: WindowsPageManager<Platform, 4096>,
/// ) -> LinuxPageManager<Platform, 4096> {
///     manager
/// }
/// ```
pub type WindowsPageManager<Platform, const ALIGN: usize> = PageManager<Platform, ALIGN, Windows>;

/// Shared memory ownership, mapping metadata, and protection operations.
///
/// Construct a [`LinuxPageManager`] or [`WindowsPageManager`] for the guest's API family.
/// The style is fixed for the manager's lifetime; neither family provides a conversion to the other.
/// Linux-style managers use the provider's selected reservation representation. Windows-style
/// managers always track the provider's opaque reservation handles:
///
/// ```
/// use litebox::{LiteBox, mm::{LinuxPageManager, WindowsPageManager}, platform::{PageManagementProvider, RawPointerProvider}, sync::RawSyncPrimitivesProvider};
/// fn managers<Platform>(
///     litebox: &LiteBox<Platform>,
/// ) -> (LinuxPageManager<Platform, 4096>, WindowsPageManager<Platform, 4096>)
/// where
///     Platform: RawSyncPrimitivesProvider
///         + RawPointerProvider
///         + PageManagementProvider<4096>,
/// {
///     let linux = LinuxPageManager::new(litebox);
///     let windows = WindowsPageManager::new(litebox);
///     assert_eq!(linux.reservations(), windows.reservations());
///     (linux, windows)
/// }
/// ```
pub struct PageManager<Platform, const ALIGN: usize, Style>
where
    Platform: RawSyncPrimitivesProvider + RawPointerProvider + PageManagementProvider<ALIGN>,
    Style: PageManagerStyleFor<Platform, ALIGN>,
{
    vmem: RwLock<Platform, Vmem<Platform, ALIGN, Style>>,
}

impl<Platform, const ALIGN: usize, Style> PageManager<Platform, ALIGN, Style>
where
    Platform: RawSyncPrimitivesProvider + RawPointerProvider + PageManagementProvider<ALIGN>,
    Style: PageManagerStyleFor<Platform, ALIGN>,
{
    /// Create a new `PageManager` instance.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        let vmem = RwLock::new(Vmem::new(litebox.x.platform));
        Self { vmem }
    }

    /// Remove all mappings, release all owned reservations, and reset the program break.
    ///
    /// Every mapping is treated as owned memory, regardless of its flags or origin.
    /// Ordinary decommit does not release reservations; Linux unmap reclaims only touched empty ones.
    ///
    /// # Safety
    ///
    /// The caller must ensure that all mappings are owned, valid for provider teardown, and no
    /// longer used. The caller relinquishes all reservations, including uncommitted ranges.
    pub unsafe fn release_memory(&self) -> Result<(), VmemUnmapError> {
        let mut vmem = self.vmem.write();
        // SAFETY: The caller excludes all users and relinquishes all owned backing.
        unsafe { vmem.release_memory() };
        Ok(())
    }

    /// Change permissions of committed pages without changing their contents or commitment.
    ///
    /// The entire range is validated before mutation and may span reservations. Unchanged
    /// permissions require no provider call. Recoverable failure leaves permissions unchanged.
    ///
    /// # Safety
    ///
    /// The caller must exclude accesses conflicting with the requested permissions, including
    /// concurrent execution when granting write access.
    pub unsafe fn protect_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::from_start_len(start, len).ok_or(VmemProtectError::InvalidRange(
            start..start.saturating_add(len),
        ))?;
        // SAFETY: The caller excludes conflicting accesses; the manager validates committed coverage.
        unsafe { vmem.protect_mapping(range, new_permissions) }
    }

    /// Make pages readable and writable.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `execute` access to the memory region.
    pub unsafe fn make_pages_writable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: The caller excludes execution while granting write access.
        unsafe {
            self.protect_pages(
                ptr,
                len,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )
        }
    }

    /// Make pages readable and executable.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `write` access to the memory region.
    pub unsafe fn make_pages_executable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: The caller excludes writes while granting execute access.
        unsafe {
            self.protect_pages(
                ptr,
                len,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
            )
        }
    }

    /// Make pages readable only.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `write/execute` access to the memory region.
    pub unsafe fn make_pages_readable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: The caller excludes writes and execution while making these pages read-only.
        unsafe { self.protect_pages(ptr, len, MemoryRegionPermissions::READ) }
    }

    /// Make pages inaccessible.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent access to the memory region.
    pub unsafe fn make_pages_inaccessible(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: The caller excludes all accesses while removing permissions.
        unsafe { self.protect_pages(ptr, len, MemoryRegionPermissions::empty()) }
    }

    /// Make pages readable, writable and executable.
    ///
    /// # Safety
    ///
    /// This operation is inherently dangerous and should be used with extreme caution.
    /// Allowing pages to be both writable and executable can lead to severe security vulnerabilities,
    /// such as code injection attacks or exploitation of memory corruption bugs.
    ///
    /// The caller must ensure the following:
    /// 1. The memory region is only used for legitimate purposes, such as JIT compilation,
    ///    where writable and executable permissions are strictly necessary.
    /// 2. The memory region is properly sanitized and does not contain malicious or unintended code.
    ///
    /// It is highly recommended to minimize the use of this function and to prefer safer alternatives
    /// whenever possible. If this function must be used, ensure that the memory region is locked down
    /// and access is strictly controlled.
    pub unsafe fn make_pages_rwx(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: The caller guarantees controlled accesses to this writable executable mapping.
        unsafe {
            self.protect_pages(
                ptr,
                len,
                MemoryRegionPermissions::READ
                    | MemoryRegionPermissions::WRITE
                    | MemoryRegionPermissions::EXEC,
            )
        }
    }

    /// Returns committed guest mappings, including no-access pages.
    pub fn mappings(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.vmem
            .read()
            .iter()
            .map(|(r, vma)| (r.start..r.end, vma.flags()))
            .collect()
    }

    /// Returns all explicitly tracked reservation ranges, whether committed or uncommitted.
    ///
    /// Reservations retain their allocation boundaries when committed mappings split or merge.
    /// Managers using a handle-free reservation store return an empty list; use
    /// [`Self::mappings`] to inspect their committed address-space ownership.
    pub fn reservations(&self) -> Vec<Range<usize>> {
        self.vmem.read().reservations().collect()
    }

    /// Returns whether every byte in `range` is mapped with `required` permissions.
    pub fn range_has_permissions(
        &self,
        range: Range<usize>,
        required: MemoryRegionPermissions,
    ) -> bool {
        if range.start > range.end {
            return false;
        }
        self.range_prefix_with_permissions(range.clone(), required) == range.len()
    }

    /// Returns the length of the contiguous prefix of `range` mapped with `required` permissions.
    pub fn range_prefix_with_permissions(
        &self,
        range: Range<usize>,
        required: MemoryRegionPermissions,
    ) -> usize {
        if range.start >= range.end {
            return 0;
        }
        let vmem = self.vmem.read();
        let mut covered_until = range.start;
        while covered_until < range.end {
            let Some((mapped, area)) = vmem
                .vmas
                .overlapping(covered_until..Platform::TASK_ADDR_MAX)
                .next()
            else {
                break;
            };
            let area_permissions = MemoryRegionPermissions::from(area.flags());
            if mapped.start > covered_until {
                let fault_addr = covered_until & !(ALIGN - 1);
                let stack_can_grow = (Platform::TASK_ADDR_MIN..Platform::TASK_ADDR_MAX)
                    .contains(&fault_addr)
                    && area.flags().contains(VmFlags::VM_GROWSDOWN)
                    && area_permissions.contains(required)
                    && vmem
                        .vmas
                        .overlapping(Platform::TASK_ADDR_MIN..fault_addr)
                        .next_back()
                        .is_none_or(|(previous_range, previous_area)| {
                            (previous_area.flags().contains(VmFlags::VM_GROWSDOWN)
                                && !(previous_area.flags() & VmFlags::VM_ACCESS_FLAGS).is_empty())
                                || fault_addr - previous_range.end
                                    >= Vmem::<Platform, ALIGN, Style>::STACK_GUARD_GAP
                        });
                if !stack_can_grow {
                    break;
                }
            } else if !area_permissions.contains(required) {
                break;
            }
            covered_until = covered_until.max(mapped.end);
        }
        covered_until.saturating_sub(range.start).min(range.len())
    }

    /// Get the memory permissions of a given address range.
    ///
    /// `ptr` specifies the start address of the memory range.
    /// `len` specifies the length of the memory range.
    /// This function returns `MemoryRegionPermissions` only if the range is valid.
    /// A memory range is invalid if it contains:
    /// - Unmapped pages
    /// - Memory pages with different permissions
    pub fn get_memory_permissions(
        &self,
        ptr: NonZeroAddress<ALIGN>,
        len: NonZeroPageSize<ALIGN>,
    ) -> Option<MemoryRegionPermissions> {
        let vmem = self.vmem.read();
        let start = ptr.as_usize();
        let page_range = PageRange::<ALIGN>::from_start_len(start, len.as_usize())?;
        vmem.get_memory_permissions(page_range)
    }
}
