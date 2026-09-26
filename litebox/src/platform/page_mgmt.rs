// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Page-management related types and traits

use alloc::vec::Vec;

use crate::platform::{RawConstPointer as _, RawMutPointer as _};

use super::RawPointerProvider;
use core::ops::Range;
use thiserror::Error;

/// Exclusive ownership of a reserved virtual-address extent.
pub trait PageReservation {
    /// Return the owned address range.
    fn range(&self) -> Range<usize>;
}

/// Storage for reservations indexed by their starting address.
pub trait ReservationStore {
    /// Reservation value retained by the store.
    type Reservation: PageReservation;

    /// Insert a reservation at `base`.
    fn insert(&mut self, base: usize, reservation: Self::Reservation) -> Option<Self::Reservation>;

    /// Iterate over reservation bases and values in ascending address order.
    fn iter(&self) -> impl DoubleEndedIterator<Item = (&usize, &Self::Reservation)>;

    /// Iterate over every reservation overlapping `range` in ascending address order.
    fn overlapping(
        &self,
        range: Range<usize>,
    ) -> impl DoubleEndedIterator<Item = (usize, &Self::Reservation)>;

    /// Remove and return every reservation overlapping `range` in ascending address order.
    fn take_overlapping(&mut self, range: Range<usize>) -> Vec<Self::Reservation>;
}

bitflags::bitflags! {
    /// Permissions for a memory region
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MemoryRegionPermissions: u8 {
        /// Readable
        const READ = 1 << 0;
        /// Writable
        const WRITE = 1 << 1;
        /// Executable
        const EXEC = 1 << 2;
        /// Sharable between processes
        const SHARED = 1 << 3;
    }
}

/// A provider for managing memory pages
///
/// NOTE: Due to insufficient support for associated constants in current Stable Rust, we have
/// `ALIGN` as a parameter. In the future, this may be changed to an associated constant, since each
/// platform has only one canonical alignment.
pub trait PageManagementProvider<const ALIGN: usize>: RawPointerProvider {
    /// The lower bound (inclusive) for virtual addresses that can be allocated for task memory.
    ///
    /// Note it must be aligned to `ALIGN`.
    const TASK_ADDR_MIN: usize;
    /// The upper bound (exclusive) for virtual addresses that can be allocated for task memory.
    ///
    /// Note it must be aligned to `ALIGN`.
    const TASK_ADDR_MAX: usize;

    /// Allocates new memory pages at the specified `suggested_range` with the given `initial_permissions`.
    ///
    /// # Parameters
    ///
    /// - `suggested_range`: A suggested address range for the allocation.
    /// - `initial_permissions`: The permissions to apply to the allocated memory region.
    /// - `can_grow_down`: If `true`, the region is allowed to grow downward (towards zero) upon
    ///   a page fault.
    /// - `populate_pages_immediately`: If `true`, the pages are populated immediately; otherwise,
    ///   they are populated lazily.
    /// - `fixed_address_behavior`: Specifies the required semantics of `suggested_range`.
    ///
    /// # Returns
    ///
    /// On success, returns a raw mutable pointer to the start of the allocated memory region.
    ///
    /// # Errors
    ///
    /// Returns an [`AllocationError`] if the allocation fails.
    fn allocate_pages(
        &self,
        suggested_range: Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError>;

    /// Allocates an alias of a stable shared backing object.
    ///
    /// Every call carrying the same `backing_identity` and overlapping
    /// `backing_offset` range must expose the same bytes immediately, even when
    /// the returned virtual addresses differ. Platforms without a native shared
    /// backing implementation retain the ordinary allocation behavior by
    /// default; their shims may still provide sharing through an address-space
    /// handoff, but simultaneous aliases will not be coherent until the platform
    /// overrides this method.
    #[expect(unused_variables, reason = "default body ignores backing metadata")]
    #[allow(
        clippy::too_many_arguments,
        reason = "each parameter is independently required by the platform allocation contract"
    )]
    fn allocate_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        suggested_range: Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        self.allocate_pages(
            suggested_range,
            initial_permissions,
            can_grow_down,
            populate_pages_immediately,
            fixed_address_behavior,
        )
    }

    /// Initializes portions of a shared backing object that have not been initialized before.
    ///
    /// `initialize` receives ranges relative to `backing_offset`; an implementation with a
    /// canonical shared-page store calls it only for gaps that have never been initialized. The
    /// callback runs while that store's initialization state is serialized, so two simultaneous
    /// first mappings cannot overwrite one another with stale file bytes. The default calls it for
    /// the complete range because a platform without canonical aliases allocates independent pages.
    fn initialize_shared_pages<E>(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        length: usize,
        mut initialize: impl FnMut(Range<usize>) -> Result<(), E>,
    ) -> Result<(), E> {
        let _ = (backing_identity, backing_offset);
        initialize(0..length)
    }

    /// Overlays bytes currently held by a canonical shared backing onto `data`.
    ///
    /// Bytes for which the platform has no initialized canonical storage are left unchanged. The
    /// default is a no-op for platforms whose shared mappings are managed outside this provider.
    fn read_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        data: &mut [u8],
    ) -> Result<(), SharedPageIoError> {
        let _ = (backing_identity, backing_offset, data);
        Ok(())
    }

    /// Propagates a file write into any canonical shared backing storage that already exists.
    ///
    /// A range that has never been mapped need not allocate storage; its eventual first mapping is
    /// initialized from the file itself. The default is a no-op.
    fn write_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        data: &[u8],
    ) -> Result<(), SharedPageIoError> {
        let _ = (backing_identity, backing_offset, data);
        Ok(())
    }

    /// Zeroes any canonical shared storage intersecting `backing_range` after file truncation.
    ///
    /// This operates only on storage that already exists; future mappings obtain zero-filled bytes
    /// from the resized file. The default is a no-op.
    fn zero_shared_pages(
        &self,
        backing_identity: usize,
        backing_range: Range<usize>,
    ) -> Result<(), SharedPageIoError> {
        let _ = (backing_identity, backing_range);
        Ok(())
    }

    /// De-allocated all pages in the given `range`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that these pages are not in active use.
    unsafe fn deallocate_pages(&self, range: Range<usize>) -> Result<(), DeallocationError>;

    /// Remap pages from `old_range` to `new_range`.
    ///
    /// ## Returns
    ///
    /// On success it returns a pointer to the new virtual memory area. That need not be
    /// `new_range.start`: `new_range` is where the caller would like the pages, and a platform may
    /// place them elsewhere (with the same length) when the host already occupies that range.
    ///
    /// # Safety
    ///
    /// The caller must ensure that it is safe to move the `old_range` (i.e., these pages are not in
    /// active use).
    ///
    /// The `new_range` must be larger than `old_range`, and must not overlap with `old_range`.
    ///
    /// Both ranges must be aligned to `ALIGN`.
    unsafe fn remap_pages(
        &self,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, RemapError> {
        debug_assert!(old_range.start.is_multiple_of(ALIGN));
        debug_assert!(new_range.start.is_multiple_of(ALIGN));
        debug_assert!(old_range.len().is_multiple_of(ALIGN));
        debug_assert!(new_range.len().is_multiple_of(ALIGN));
        debug_assert!(new_range.len() > old_range.len());
        debug_assert!(old_range.start.max(new_range.start) >= old_range.end.min(new_range.end));
        // Default implementation: allocate new pages, copy data, deallocate old pages
        let temp_permissions = permissions | MemoryRegionPermissions::WRITE;
        let allocate = |behavior| {
            self.allocate_pages(new_range.clone(), temp_permissions, false, true, behavior)
        };
        let new_ptr = match allocate(FixedAddressBehavior::NoReplace) {
            // `new_range` is free only as far as the caller's bookkeeping knows. A hosted
            // platform can already hold part of it for the host (on Windows, even the unusable
            // tail of a host allocation's 64 KiB granule), and failing the move over that would
            // turn a guest `mremap(MREMAP_MAYMOVE)` into `EFAULT`. Let the platform place the
            // pages elsewhere instead, as Linux's own `mremap` without `MREMAP_FIXED` does; the
            // caller records the address returned below.
            Err(AllocationError::AddressInUse | AllocationError::AddressInUseByPlatform) => {
                allocate(FixedAddressBehavior::Hint)
            }
            result => result,
        }
        .map_err(|e| match e {
            AllocationError::OutOfMemory => RemapError::OutOfMemory,
            AllocationError::AddressInUse | AllocationError::AddressInUseByPlatform => {
                RemapError::AlreadyAllocated
            }
            AllocationError::Unaligned
            | AllocationError::BelowMinAddress
            | AllocationError::AboveMaxAddress
            | AllocationError::AddressPartiallyInUse => unreachable!(),
        })?;
        let new_range = new_ptr.as_usize()..new_ptr.as_usize() + new_range.len();

        // Copy memory from old range to new range
        if !permissions.contains(MemoryRegionPermissions::READ) {
            (unsafe {
                self.update_permissions(
                    old_range.clone(),
                    permissions | MemoryRegionPermissions::READ,
                )
            })
            .expect("failed to update permissions on old range for copying");
        }
        // Copy in chunks of ALIGN bytes to handle very large memory regions
        let total_len = old_range.len();
        let mut offset = 0;
        while offset < total_len {
            let chunk_len = (total_len - offset).min(ALIGN);
            let old_ptr =
                <Self as RawPointerProvider>::RawConstPointer::from_usize(old_range.start + offset);
            new_ptr
                .write_slice_at_offset(
                    isize::try_from(offset).unwrap(),
                    &old_ptr.to_owned_slice(chunk_len).unwrap(),
                )
                .unwrap();
            offset += ALIGN;
        }

        if temp_permissions != permissions {
            (unsafe { self.update_permissions(new_range.clone(), permissions) })
                .expect("failed to restore permissions on new range");
        }

        (unsafe { self.deallocate_pages(old_range) }).expect("failed to deallocate old range");

        Ok(new_ptr)
    }

    /// Moves a stable shared backing alias while preserving its backing offset.
    ///
    /// Platforms that expose canonical shared pages override this so the destination aliases the
    /// same physical storage rather than receiving a private byte copy. Other platforms retain the
    /// ordinary remap behavior.
    ///
    /// # Safety
    ///
    /// Same contract as [`Self::remap_pages`], which the default body forwards to: the caller
    /// must ensure it is safe to move `old_range` (not in active use), `new_range` must be larger
    /// than `old_range` and must not overlap it, and both ranges must be aligned to `ALIGN`.
    unsafe fn remap_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, RemapError> {
        let _ = (backing_identity, backing_offset);
        // SAFETY: this method has the same safety contract as `remap_pages` and forwards it.
        unsafe { self.remap_pages(old_range, new_range, permissions) }
    }

    /// Whether one [`Self::update_permissions`] call may span adjacent tracked
    /// mappings while retaining all-or-fail semantics.
    ///
    /// Returning `true` promises that `Err` means no part of the range changed,
    /// and that any failure after publication terminates rather than unwinds or
    /// returns. Providers whose native operation has reservation/backing
    /// boundaries must retain the default and receive one region at a time.
    fn has_transactional_permission_updates(&self) -> bool {
        false
    }

    /// Update the permissions on pages in `range` to `new_permissions`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the permissions do not conflict with any currently active usage
    /// of these pages.
    unsafe fn update_permissions(
        &self,
        range: Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError>;

    /// Return reserved pages that are not available for allocation.
    ///
    /// Note that the returned ranges should be `ALIGN`-aligned.
    fn reserved_pages(&self) -> impl Iterator<Item = &Range<usize>>;

    /// Attempt to allocate pages with copy-on-write semantics backed by static data.
    ///
    /// This method allows platforms that support it to create CoW mappings instead of performing
    /// expensive page-by-page memory copies. This is particularly useful when mapping pre-loaded
    /// file data that was mmap'd by the host.
    ///
    /// The default implementation returns unsupported CoW. Platforms that DO support COW should
    /// override this method to unlock better performance.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn try_allocate_cow_pages(
        &self,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, CowAllocationError> {
        Err(CowAllocationError::UnsupportedByPlatform)
    }

    /// Toggle this thread's write access to code pages whose writability is
    /// gated *per thread* by the platform, on top of ordinary page permissions.
    ///
    /// Darwin's `MAP_JIT` is the motivating case: an executable mapping there
    /// is writable *or* executable per thread, never both at once, switched by
    /// `pthread_jit_write_protect_np`. Any code that writes into a mapping
    /// that is (or has ever been) executable — loading guest segments,
    /// patching syscall sites in place, writing trampoline stubs — must
    /// bracket the write between `jit_write_protect(false)` and
    /// `jit_write_protect(true)`, in addition to whatever `update_permissions`
    /// calls it makes. Platforms without per-thread code write protection keep
    /// this default no-op, so callers may bracket unconditionally.
    ///
    /// # Safety
    ///
    /// While write access is enabled (`executable == false`), no code may be
    /// executed from any per-thread-protected code mapping on this thread; the
    /// caller must restore `executable == true` before returning to any such
    /// code (including guest code).
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    unsafe fn jit_write_protect(&self, executable: bool) {}
}

/// Behavior when allocating pages at a fixed address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedAddressBehavior {
    /// The address is just a hint, and the platform may choose a different
    /// address if the hint is not available.
    Hint,
    /// Allocate the pages at the specified address, replacing any existing
    /// mappings.
    Replace,
    /// Allocate the pages at the specified address, failing if any part of the
    /// range is already in use.
    NoReplace,
}

/// Possible errors for [`PageManagementProvider::allocate_pages`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum AllocationError {
    #[error("provided range is not page-aligned")]
    Unaligned,
    #[error("provided address is below the minimum allowed address")]
    BelowMinAddress,
    #[error("provided address is above the maximum allowed address")]
    AboveMaxAddress,
    #[error("out of memory")]
    OutOfMemory,
    #[error("provided fixed address range is in use")]
    AddressInUse,
    #[error("provided fixed address range is in use by the platform")]
    AddressInUseByPlatform,
    #[error("provided fixed address range partially overlaps existing mappings")]
    AddressPartiallyInUse,
}

/// Possible errors for [`PageManagementProvider::deallocate_pages`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DeallocationError {
    #[error("provided range is not page-aligned")]
    Unaligned,
    #[error("provided range contains unallocated pages")]
    AlreadyUnallocated,
}

/// Possible errors for [`PageManagementProvider::remap_pages`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum RemapError {
    #[error("at least one of the provided ranges was not page-aligned")]
    Unaligned,
    #[error("provided old range contains unallocated pages")]
    AlreadyUnallocated,
    #[error("provided ranges were overlapping")]
    Overlapping,
    #[error("provided new range is already allocated")]
    AlreadyAllocated,
    #[error("out of memory")]
    OutOfMemory,
}

/// Possible errors for [`PageManagementProvider::update_permissions`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum PermissionUpdateError {
    #[error("provided range is not page-aligned")]
    Unaligned,
    #[error("provided range contains unallocated pages")]
    Unallocated,
}

/// Failure while synchronizing a canonical shared backing with file-descriptor I/O.
#[derive(Error, Debug)]
pub enum SharedPageIoError {
    #[error("shared backing range overflow")]
    OutOfRange,
    #[error("host shared backing I/O failed")]
    Io,
}

/// Possible errors for [`PageManagementProvider::try_allocate_cow_pages`]
///
/// ```text
///  ____________________
/// ( Maybe the grass is )
/// ( greener on the     )
/// ( other side?        )
///  --------------------
///         o   ^__^
///          o  (oo)\_______
///             (__)\       )\/\
///                 ||----w |
///                 ||     ||
/// ```
#[derive(Error, Debug)]
pub enum CowAllocationError {
    #[error("copy-on-write page allocation is not supported for this particular platform")]
    UnsupportedByPlatform,
    #[error("source region is not copy-on-writable")]
    UnsupportedSourceRegion,
    #[error("unaligned request")]
    Unaligned,
    #[error("internal failure in creating CoW pages")]
    InternalFailure,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::trivial_providers::{TransparentConstPtr, TransparentMutPtr};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    const PAGE: usize = 0x1000;

    /// Backs the default [`PageManagementProvider::remap_pages`] with real memory, and plays a host
    /// that already owns `occupied` (when set): a `NoReplace` claim there fails the way a hosted
    /// platform reports a range it holds outside the caller's bookkeeping, and `Hint` then places
    /// the pages at `fallback`.
    struct HostBackend {
        occupied: Option<usize>,
        fallback: usize,
        allocations: RefCell<Vec<(usize, FixedAddressBehavior)>>,
        permission_updates: RefCell<Vec<(Range<usize>, MemoryRegionPermissions)>>,
        deallocations: RefCell<Vec<Range<usize>>>,
    }

    impl RawPointerProvider for HostBackend {
        type RawConstPointer<T: zerocopy::FromBytes> = TransparentConstPtr<T>;
        type RawMutPointer<T: zerocopy::FromBytes + zerocopy::IntoBytes> = TransparentMutPtr<T>;
    }

    impl PageManagementProvider<PAGE> for HostBackend {
        const TASK_ADDR_MIN: usize = PAGE;
        const TASK_ADDR_MAX: usize = usize::MAX - (PAGE - 1);

        fn allocate_pages(
            &self,
            suggested_range: Range<usize>,
            _initial_permissions: MemoryRegionPermissions,
            _can_grow_down: bool,
            _populate_pages_immediately: bool,
            fixed_address_behavior: FixedAddressBehavior,
        ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
            self.allocations
                .borrow_mut()
                .push((suggested_range.start, fixed_address_behavior));
            if self.occupied != Some(suggested_range.start) {
                return Ok(TransparentMutPtr::from_usize(suggested_range.start));
            }
            match fixed_address_behavior {
                FixedAddressBehavior::Hint => Ok(TransparentMutPtr::from_usize(self.fallback)),
                FixedAddressBehavior::NoReplace => Err(AllocationError::AddressInUseByPlatform),
                FixedAddressBehavior::Replace => unreachable!("remap never replaces"),
            }
        }

        unsafe fn deallocate_pages(&self, range: Range<usize>) -> Result<(), DeallocationError> {
            self.deallocations.borrow_mut().push(range);
            Ok(())
        }

        unsafe fn update_permissions(
            &self,
            range: Range<usize>,
            new_permissions: MemoryRegionPermissions,
        ) -> Result<(), PermissionUpdateError> {
            self.permission_updates
                .borrow_mut()
                .push((range, new_permissions));
            Ok(())
        }

        fn reserved_pages(&self) -> impl Iterator<Item = &Range<usize>> {
            core::iter::empty()
        }
    }

    /// Moves one page filled with `0xA5` to a two-page range and returns the arena, the arena
    /// offset of its first page, the backend and the pointer `remap_pages` returned. The arena's
    /// pages are: the old page, the two requested pages, and the two fallback pages.
    fn remap_one_page(
        host_owns_requested: bool,
    ) -> (Vec<u8>, usize, HostBackend, TransparentMutPtr<u8>) {
        let mut arena = vec![0u8; 6 * PAGE];
        let offset = (arena.as_ptr() as usize).next_multiple_of(PAGE) - arena.as_ptr() as usize;
        arena[offset..offset + PAGE].fill(0xA5);
        let base = arena.as_ptr() as usize + offset;
        let requested = base + PAGE;
        let backend = HostBackend {
            occupied: host_owns_requested.then_some(requested),
            fallback: base + 3 * PAGE,
            allocations: RefCell::new(Vec::new()),
            permission_updates: RefCell::new(Vec::new()),
            deallocations: RefCell::new(Vec::new()),
        };
        // SAFETY: every range lies inside `arena`, which outlives the call, and nothing else
        // uses the old page.
        let new_ptr = unsafe {
            backend.remap_pages(
                base..base + PAGE,
                requested..requested + 2 * PAGE,
                MemoryRegionPermissions::READ,
            )
        }
        .unwrap();
        (arena, offset, backend, new_ptr)
    }

    #[test]
    fn remap_pages_claims_the_requested_range_when_it_is_free() {
        let (arena, offset, backend, new_ptr) = remap_one_page(false);
        let base = arena.as_ptr() as usize + offset;
        let requested = base + PAGE;

        assert_eq!(new_ptr.as_usize(), requested);
        assert_eq!(
            *backend.allocations.borrow(),
            [(requested, FixedAddressBehavior::NoReplace)]
        );
        assert!(
            arena[offset + PAGE..offset + 2 * PAGE]
                .iter()
                .all(|&b| b == 0xA5)
        );
        assert_eq!(
            *backend.permission_updates.borrow(),
            [(
                requested..requested + 2 * PAGE,
                MemoryRegionPermissions::READ
            )]
        );
        assert_eq!(backend.deallocations.borrow().len(), 1);
        assert_eq!(backend.deallocations.borrow()[0], base..base + PAGE);
    }

    #[test]
    fn remap_pages_falls_back_when_the_host_owns_the_requested_range() {
        let (arena, offset, backend, new_ptr) = remap_one_page(true);
        let base = arena.as_ptr() as usize + offset;
        let requested = base + PAGE;
        let fallback = base + 3 * PAGE;

        assert_eq!(new_ptr.as_usize(), fallback);
        assert_eq!(
            *backend.allocations.borrow(),
            [
                (requested, FixedAddressBehavior::NoReplace),
                (requested, FixedAddressBehavior::Hint),
            ]
        );
        // The data and the final permissions both follow the pages to where they landed.
        assert!(
            arena[offset + 3 * PAGE..offset + 4 * PAGE]
                .iter()
                .all(|&b| b == 0xA5)
        );
        assert!(
            arena[offset + PAGE..offset + 3 * PAGE]
                .iter()
                .all(|&b| b == 0)
        );
        assert_eq!(
            *backend.permission_updates.borrow(),
            [(fallback..fallback + 2 * PAGE, MemoryRegionPermissions::READ)]
        );
        assert_eq!(backend.deallocations.borrow().len(), 1);
        assert_eq!(backend.deallocations.borrow()[0], base..base + PAGE);
    }
}
