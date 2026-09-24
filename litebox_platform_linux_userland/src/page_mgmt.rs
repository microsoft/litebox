// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;

fn prot_flags(flags: MemoryRegionPermissions) -> ProtFlags {
    let mut res = ProtFlags::PROT_NONE;
    res.set(
        ProtFlags::PROT_READ,
        flags.contains(MemoryRegionPermissions::READ),
    );
    res.set(
        ProtFlags::PROT_WRITE,
        flags.contains(MemoryRegionPermissions::WRITE),
    );
    res.set(
        ProtFlags::PROT_EXEC,
        flags.contains(MemoryRegionPermissions::EXEC),
    );
    if flags.contains(MemoryRegionPermissions::SHARED) {
        unimplemented!()
    }
    res
}

#[cfg(target_arch = "aarch64")]
pub(super) fn cache_sync_permissions(
    permissions: MemoryRegionPermissions,
) -> MemoryRegionPermissions {
    (permissions | MemoryRegionPermissions::READ) & !MemoryRegionPermissions::EXEC
}

litebox::define_page_reservation!(LinuxUserlandReservation);

impl<const ALIGN: usize> From<LinuxUserlandReservation<ALIGN>> for core::ops::Range<usize> {
    fn from(reservation: LinuxUserlandReservation<ALIGN>) -> Self {
        reservation.range()
    }
}

impl LinuxUserland {
    pub(super) fn mmap_anonymous(
        suggested_range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<UserMutPtr<u8>, litebox::platform::page_mgmt::AllocationError> {
        let flags = MapFlags::MAP_PRIVATE
            | MapFlags::MAP_ANONYMOUS
            | match behavior {
                FixedAddressBehavior::Hint => MapFlags::empty(),
                FixedAddressBehavior::Replace => MapFlags::MAP_FIXED,
                FixedAddressBehavior::NoReplace => MapFlags::MAP_FIXED_NOREPLACE,
            }
            | if can_grow_down {
                MapFlags::MAP_GROWSDOWN
            } else {
                MapFlags::empty()
            }
            | if populate {
                MapFlags::MAP_POPULATE
            } else {
                MapFlags::empty()
            };
        // SAFETY: Non-replacing modes acquire fresh memory; replacement callers authorize the supplied range.
        let pointer = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::mmap,
                suggested_range.start,
                suggested_range.len(),
                prot_flags(permissions).bits().reinterpret_as_unsigned() as usize,
                flags.bits().reinterpret_as_unsigned() as usize,
                usize::MAX,
                0,
            )
        }
        .map_err(|error| match error {
            syscalls::Errno::ENOMEM => litebox::platform::page_mgmt::AllocationError::OutOfMemory,
            syscalls::Errno::EEXIST => {
                assert_eq!(behavior, FixedAddressBehavior::NoReplace);
                litebox::platform::page_mgmt::AllocationError::AddressInUse
            }
            other => panic!("unhandled mmap error {other}"),
        })?;
        Ok(UserMutPtr::from_usize(pointer))
    }

    unsafe fn protect_native_pages(
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PageStateUpdateError> {
        let map_error = |error| match error {
            syscalls::Errno::ENOMEM => {
                litebox::platform::page_mgmt::PageStateUpdateError::OutOfMemory
            }
            other => panic!("unhandled mprotect error {other}"),
        };
        #[cfg(target_arch = "x86_64")]
        // SAFETY: The caller owns the mapped range and excludes accesses conflicting with the new permissions.
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::mprotect,
                range.start,
                range.len(),
                prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
            )
        }
        .map_err(map_error)?;

        #[cfg(target_arch = "aarch64")]
        {
            let syncing = new_permissions.contains(MemoryRegionPermissions::EXEC);
            let mapped_permissions = if syncing {
                cache_sync_permissions(new_permissions)
            } else {
                new_permissions
            };
            // SAFETY: The owned range must be readable and non-executable during instruction-cache maintenance.
            unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::mprotect,
                    range.start,
                    range.len(),
                    prot_flags(mapped_permissions)
                        .bits()
                        .reinterpret_as_unsigned() as usize,
                )
            }
            .map_err(map_error)?;
            if syncing {
                sync_instruction_stream(range.clone());
                if mapped_permissions != new_permissions {
                    // SAFETY: Cache maintenance is complete and the caller excludes conflicting accesses.
                    unsafe {
                        syscalls::syscall3(
                            syscalls::Sysno::mprotect,
                            range.start,
                            range.len(),
                            prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
                        )
                    }
                    .map_err(map_error)?;
                }
            }
        }
        Ok(())
    }
}

impl LinuxUserland {
    unsafe fn allocate_owned_pages<const ALIGN: usize, Reservations>(
        replaced_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        mapping_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, litebox::platform::page_mgmt::AllocationError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
        use litebox::platform::page_mgmt::AllocationError;
        if range.start >= range.end
            || !range.start.is_multiple_of(ALIGN)
            || !range.end.is_multiple_of(ALIGN)
        {
            return Err(AllocationError::Unaligned);
        }
        let minimum = <Self as PageManagementProvider<ALIGN>>::TASK_ADDR_MIN;
        let maximum = <Self as PageManagementProvider<ALIGN>>::TASK_ADDR_MAX;
        if range.start < minimum && !(range.start == 0 && behavior == FixedAddressBehavior::Hint) {
            return Err(AllocationError::BelowMinAddress);
        }
        if range.end > maximum {
            return Err(AllocationError::AboveMaxAddress);
        }
        let pointer = match Self::mmap_anonymous(
            range.clone(),
            mapping_permissions,
            can_grow_down,
            populate,
            behavior,
        ) {
            Ok(pointer) => pointer,
            Err(error) => {
                assert_ne!(
                    behavior,
                    FixedAddressBehavior::Replace,
                    "failed MAP_FIXED may have changed existing mappings: {error}"
                );
                return Err(error);
            }
        };
        let actual = pointer.as_usize()..pointer.as_usize() + range.len();
        debug_assert!(behavior == FixedAddressBehavior::Hint || actual == range);
        debug_assert!(actual.start >= minimum && actual.end <= maximum);
        debug_assert!(actual.start.is_multiple_of(ALIGN));
        if behavior == FixedAddressBehavior::Replace {
            replaced_reservations().for_each(drop);
        }
        // SAFETY: mmap acquired this extent and all overlapping handles have been consumed.
        Ok(unsafe { LinuxUserlandReservation::new(actual) })
    }
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for LinuxUserland {
    type Reservations = NoReservations<ALIGN, LinuxUserlandReservation<ALIGN>>;

    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux config
    #[cfg(target_arch = "x86_64")]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    /// Assumes the host kernel is configured for a 48-bit user virtual address
    /// space. AArch64 Linux is also built with 39, 42 and 47 bits, and on those
    /// hosts this hands out addresses the kernel then refuses to map.
    ///
    /// Naming the smallest configuration instead is not an option today: the
    /// allocator in `litebox::mm` searches downwards from the highest existing
    /// mapping, and the runtime's own mappings sit above any limit smaller than
    /// the host's real one, leaving it unable to place anything at all.
    ///
    /// TODO: probe the host's limit -- this is an associated const, so that
    /// needs `PageManagementProvider` to express a runtime bound -- and teach
    /// the allocator to place into a region holding no existing mapping.
    #[cfg(target_arch = "aarch64")]
    const TASK_ADDR_MAX: usize = 0x0000_FFFF_FFFF_F000; // (1 << 48) - PAGE_SIZE;

    unsafe fn reserve_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        can_grow_down: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, litebox::platform::page_mgmt::AllocationError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
        // SAFETY: The caller supplies exclusive ownership and replacement authorization.
        unsafe {
            Self::allocate_owned_pages(
                replaced_reservations,
                range,
                MemoryRegionPermissions::empty(),
                can_grow_down,
                false,
                behavior,
            )
        }
    }

    unsafe fn reserve_and_commit_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, litebox::platform::page_mgmt::ReserveAndCommitError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
        // SAFETY: The caller supplies exclusive ownership and replacement authorization.
        unsafe {
            Self::allocate_owned_pages(
                replaced_reservations,
                range,
                permissions,
                can_grow_down,
                populate,
                behavior,
            )
        }
        .map_err(litebox::platform::page_mgmt::ReserveAndCommitError::Allocation)
    }

    unsafe fn commit_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        populate: bool,
    ) -> Result<(), litebox::platform::page_mgmt::PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>,
    {
        // SAFETY: The caller owns these mapped pages and excludes conflicting accesses; existing contents are preserved.
        unsafe { Self::protect_native_pages(range.clone(), permissions) }
            .expect("mprotect failed with potentially partial permission changes");
        if populate {
            // SAFETY: The advisory request covers live owned memory and cannot change its contents.
            let _ = unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::madvise,
                    range.start,
                    range.len(),
                    libc::MADV_WILLNEED as usize,
                )
            };
        }
        Ok(())
    }

    unsafe fn protect_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>,
    {
        // SAFETY: The caller supplies committed pages and excludes conflicting accesses; mprotect preserves contents.
        unsafe { Self::protect_native_pages(range, permissions) }
            .expect("mprotect failed with potentially partial permission changes");
        Ok(())
    }

    unsafe fn release_pages(&self, range: core::ops::Range<usize>) {
        assert!(range.start < range.end);
        assert!(range.start.is_multiple_of(ALIGN) && range.end.is_multiple_of(ALIGN));
        // SAFETY: The caller transfers all ownership in this range and keeps holes unmapped without concurrent users.
        unsafe { syscalls::syscall2(syscalls::Sysno::munmap, range.start, range.len()) }
            .expect("munmap failed");
    }

    unsafe fn try_remap_pages<Reservations>(
        &self,
        source_reservations: impl FnOnce() -> Reservations,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
        _permissions: MemoryRegionPermissions,
    ) -> Result<ReservationOf<Self, ALIGN>, litebox::platform::page_mgmt::RemapError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
        debug_assert!(new_range.len() > old_range.len());
        // SAFETY: The caller owns the committed source and excludes users. MAYMOVE preserves
        // other mappings and performs source cleanup itself, including possible in-place growth.
        let address = unsafe {
            syscalls::syscall5(
                syscalls::Sysno::mremap,
                old_range.start,
                old_range.len(),
                new_range.len(),
                MRemapFlags::MREMAP_MAYMOVE.bits() as usize,
                new_range.start,
            )
        }
        .map_err(|error| match error {
            syscalls::Errno::ENOMEM => litebox::platform::page_mgmt::RemapError::OutOfMemory,
            syscalls::Errno::EFAULT => litebox::platform::page_mgmt::RemapError::AlreadyUnallocated,
            syscalls::Errno::EINVAL => litebox::platform::page_mgmt::RemapError::Unaligned,
            other => panic!("unexpected mremap failure: {other}"),
        })?;
        source_reservations().for_each(drop);
        let destination = address..address + new_range.len();
        // SAFETY: Successful mremap transfers this extent; replaced source ownership was consumed.
        let reservation = unsafe { LinuxUserlandReservation::new(destination.clone()) };
        Ok(reservation)
    }

    unsafe fn decommit_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>,
    {
        // SAFETY: The caller owns the mapped range and excludes all accesses while it is inaccessible.
        unsafe { Self::protect_native_pages(range.clone(), MemoryRegionPermissions::empty()) }
            .expect("mprotect failed with potentially partial permission changes");
        // SAFETY: The caller relinquishes private anonymous contents; the range is now inaccessible.
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::madvise,
                range.start,
                range.len(),
                libc::MADV_DONTNEED as usize,
            )
        }
        .expect("madvise failed with potentially partial content discard");
        Ok(())
    }

    unsafe fn try_allocate_cow_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, CowAllocationError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
        if source_data.is_empty()
            || !source_data.len().is_multiple_of(ALIGN)
            || !suggested_start.is_multiple_of(ALIGN)
        {
            return Err(CowAllocationError::Unaligned);
        }
        let minimum = <Self as PageManagementProvider<ALIGN>>::TASK_ADDR_MIN;
        let maximum = <Self as PageManagementProvider<ALIGN>>::TASK_ADDR_MAX;
        if (suggested_start < minimum
            && !(suggested_start == 0 && fixed_address_behavior == FixedAddressBehavior::Hint))
            || suggested_start
                .checked_add(source_data.len())
                .is_none_or(|end| end > maximum)
        {
            return Err(CowAllocationError::InternalFailure);
        }
        let Some((file_path, file_offset)) = self.lookup_cow_region(source_data) else {
            return Err(CowAllocationError::UnsupportedSourceRegion);
        };
        if !file_offset.is_multiple_of(ALIGN) {
            return Err(CowAllocationError::Unaligned);
        }
        let file_path_cstr =
            std::ffi::CString::new(file_path.as_os_str().as_encoded_bytes()).unwrap();
        // TODO(jb): We should likely be storing pre-opened FDs, right?
        #[cfg(target_arch = "x86_64")]
        let fd = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::open,
                file_path_cstr.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        #[cfg(target_arch = "aarch64")]
        let fd = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::openat,
                AT_FDCWD,
                file_path_cstr.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        let fd = fd.expect("file should remain unchanged on host");

        let mut flags = MapFlags::MAP_PRIVATE;
        match fixed_address_behavior {
            FixedAddressBehavior::Hint => {}
            FixedAddressBehavior::Replace => flags |= MapFlags::MAP_FIXED,
            FixedAddressBehavior::NoReplace => flags |= MapFlags::MAP_FIXED_NOREPLACE,
        }

        let result = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::mmap,
                suggested_start,
                source_data.len(),
                prot_flags(permissions).bits().reinterpret_as_unsigned() as usize,
                flags.bits().reinterpret_as_unsigned() as usize,
                fd,
                file_offset,
            )
        };

        let _ = unsafe { syscalls::syscall1(syscalls::Sysno::close, fd) };

        let address = match result {
            Ok(address) => address,
            Err(error) => {
                assert_ne!(
                    fixed_address_behavior,
                    FixedAddressBehavior::Replace,
                    "failed CoW MAP_FIXED may have changed existing mappings: {error}"
                );
                return Err(CowAllocationError::InternalFailure);
            }
        };
        let actual = address..address + source_data.len();
        assert!(fixed_address_behavior == FixedAddressBehavior::Hint || address == suggested_start);
        assert!(address >= minimum && actual.end <= maximum && address.is_multiple_of(ALIGN));
        if fixed_address_behavior == FixedAddressBehavior::Replace {
            replaced_reservations().for_each(drop);
        }
        // SAFETY: mmap acquired this committed extent and all overlapping handle ownership was consumed.
        Ok(unsafe { LinuxUserlandReservation::new(actual) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::RawMutPointer as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn cache_sync_permissions_are_readable_and_non_executable() {
        use litebox::platform::page_mgmt::MemoryRegionPermissions;

        let final_permissions = MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC;
        let sync_permissions = super::cache_sync_permissions(final_permissions);

        assert!(sync_permissions.contains(MemoryRegionPermissions::READ));
        assert!(!sync_permissions.contains(MemoryRegionPermissions::EXEC));
        assert!(final_permissions.contains(MemoryRegionPermissions::EXEC));
    }

    unsafe fn release_reservations<const ALIGN: usize>(
        platform: &LinuxUserland,
        reservations: Vec<ReservationOf<LinuxUserland, ALIGN>>,
    ) {
        for reservation in reservations {
            // SAFETY: The fixture relinquishes this exact owned extent without remaining users.
            unsafe {
                <LinuxUserland as PageManagementProvider<ALIGN>>::release_pages(
                    platform,
                    reservation.into(),
                );
            }
        }
    }

    fn take_contained_reservations<const ALIGN: usize>(
        reservations: &mut Vec<ReservationOf<LinuxUserland, ALIGN>>,
        range: core::ops::Range<usize>,
    ) -> impl Iterator<Item = ReservationOf<LinuxUserland, ALIGN>> + '_ {
        core::mem::take(reservations)
            .into_iter()
            .map(move |reservation| {
                let extent = reservation.range();
                let (prefix, selected, suffix) =
                    reservation.split(extent.start.max(range.start)..extent.end.min(range.end));
                reservations.extend(prefix);
                reservations.extend(suffix);
                selected
            })
    }

    fn reserve_backing(
        platform: &LinuxUserland,
        range: core::ops::Range<usize>,
        behavior: FixedAddressBehavior,
        grow: bool,
    ) -> Result<ReservationOf<LinuxUserland, 4096>, litebox::platform::page_mgmt::AllocationError>
    {
        assert_ne!(behavior, FixedAddressBehavior::Replace);
        // SAFETY: This fixture acquires fresh inaccessible pages without replacing any mapping.
        unsafe {
            <LinuxUserland as PageManagementProvider<4096>>::reserve_pages(
                platform,
                || -> core::iter::Empty<_> {
                    panic!("non-replacing reserve must not request reservations")
                },
                range.clone(),
                grow,
                behavior,
            )
        }
    }

    #[test]
    fn test_native_reserve_and_commit_preserves_ownership() {
        use litebox::platform::page_mgmt::{
            AllocationError, PageReservation, ReserveAndCommitError,
        };

        const PAGE_SIZE: usize = 4096;
        let platform = LinuxUserland::new();
        let writable = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        // SAFETY: The test owns every acquired extent and ends all accesses before release.
        unsafe {
            let reservation =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                    platform,
                    || -> core::iter::Empty<_> {
                        panic!("hint allocation must not request reservations")
                    },
                    0..4 * PAGE_SIZE,
                    writable,
                    false,
                    true,
                    FixedAddressBehavior::Hint,
                )
                .unwrap();
            let extent = reservation.range();
            assert_eq!(extent.len(), 4 * PAGE_SIZE);
            assert!(extent.start.is_multiple_of(PAGE_SIZE));
            assert!(
                core::slice::from_raw_parts(extent.start as *const u8, extent.len())
                    .iter()
                    .all(|byte| *byte == 0)
            );
            (extent.start as *mut u8).write(0x5a);
            ((extent.end - 1) as *mut u8).write(0xa5);
            let collision =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                    platform,
                    || -> core::iter::Empty<_> {
                        panic!("no-replace allocation must not request reservations")
                    },
                    extent.clone(),
                    writable,
                    false,
                    false,
                    FixedAddressBehavior::NoReplace,
                )
                .unwrap_err();
            assert!(matches!(collision, ReserveAndCommitError::Allocation(_)));
            let mut existing = vec![reservation];
            let unaligned =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                    platform,
                    || -> core::iter::Empty<_> {
                        panic!("invalid allocation must not request reservations")
                    },
                    extent.start + 1..extent.end,
                    writable,
                    false,
                    false,
                    FixedAddressBehavior::Replace,
                )
                .unwrap_err();
            assert!(matches!(
                unaligned,
                ReserveAndCommitError::Allocation(AllocationError::Unaligned)
            ));
            assert_eq!(existing.len(), 1);
            assert_eq!(existing[0].range(), extent);
            let relocated =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                    platform,
                    || -> core::iter::Empty<_> {
                        panic!("hint allocation must not request reservations")
                    },
                    extent.clone(),
                    MemoryRegionPermissions::READ,
                    false,
                    false,
                    FixedAddressBehavior::Hint,
                )
                .unwrap();
            let relocated_extent = relocated.range();
            assert_eq!(relocated_extent.len(), extent.len());
            assert!(relocated_extent.end <= extent.start || extent.end <= relocated_extent.start);
            assert_eq!((relocated_extent.start as *const u8).read(), 0);
            assert_eq!((extent.start as *const u8).read(), 0x5a);
            assert_eq!(((extent.end - 1) as *const u8).read(), 0xa5);
            release_reservations::<PAGE_SIZE>(platform, vec![relocated]);
            let relocated =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                    platform,
                    || -> core::iter::Empty<_> {
                        panic!("no-replace allocation must not request reservations")
                    },
                    relocated_extent.clone(),
                    MemoryRegionPermissions::READ,
                    false,
                    false,
                    FixedAddressBehavior::NoReplace,
                )
                .unwrap();
            assert_eq!(relocated.range(), relocated_extent);
            let replaced = extent.start + PAGE_SIZE..extent.end - PAGE_SIZE;
            core::ptr::write_bytes(replaced.start as *mut u8, 0xff, replaced.len());
            let replacement =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                    platform,
                    || {
                        assert_eq!((replaced.start as *const u8).read(), 0);
                        take_contained_reservations(&mut existing, replaced.clone())
                    },
                    replaced.clone(),
                    MemoryRegionPermissions::READ,
                    false,
                    true,
                    FixedAddressBehavior::Replace,
                )
                .unwrap();
            assert_eq!(replacement.range(), replaced);
            assert_eq!(
                existing
                    .iter()
                    .map(PageReservation::range)
                    .collect::<Vec<_>>(),
                [extent.start..replaced.start, replaced.end..extent.end]
            );
            assert!(
                core::slice::from_raw_parts(replaced.start as *const u8, replaced.len())
                    .iter()
                    .all(|byte| *byte == 0)
            );
            assert_eq!((extent.start as *const u8).read(), 0x5a);
            assert_eq!(((extent.end - 1) as *const u8).read(), 0xa5);
            existing.extend([replacement, relocated]);
            release_reservations::<PAGE_SIZE>(platform, existing);
        }
    }

    #[test]
    fn test_batched_protection_and_release_preserve_gaps() {
        const PAGE_SIZE: usize = 4096;
        let platform = LinuxUserland::new();
        let reservation = reserve_backing(
            platform,
            0..6 * PAGE_SIZE,
            FixedAddressBehavior::Hint,
            false,
        )
        .unwrap();
        let base = reservation.range().start;
        let (_, first, rest) = reservation.split(base..base + 2 * PAGE_SIZE);
        let (_, second, rest) = rest
            .unwrap()
            .split(base + 2 * PAGE_SIZE..base + 4 * PAGE_SIZE);
        let (_, retained, tail) = rest
            .unwrap()
            .split(base + 4 * PAGE_SIZE..base + 5 * PAGE_SIZE);
        let tail = tail.unwrap();
        let writable = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        // SAFETY: The test owns all extents and ends accesses before release; mincore only queries mapping state.
        unsafe {
            for reservation in [&first, &second, &retained, &tail] {
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                    platform,
                    || core::iter::once(reservation),
                    reservation.range(),
                    writable,
                    false,
                )
                .unwrap();
            }
            for offset in (0..6 * PAGE_SIZE).step_by(PAGE_SIZE) {
                ((base + offset) as *mut u8).write(0x5a);
            }
            let protected = base + PAGE_SIZE..base + 3 * PAGE_SIZE;
            for permissions in [
                MemoryRegionPermissions::empty(),
                MemoryRegionPermissions::READ,
            ] {
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::protect_pages(
                    platform,
                    || -> core::iter::Empty<&ReservationOf<LinuxUserland, PAGE_SIZE>> {
                        panic!("range protection must not request reservations")
                    },
                    protected.clone(),
                    permissions,
                )
                .unwrap();
            }
            assert_eq!((protected.start as *const u8).read(), 0x5a);
            assert_eq!(((base + 2 * PAGE_SIZE) as *const u8).read(), 0x5a);
            (base as *mut u8).write(0xa5);
            (protected.end as *mut u8).write(0xa5);
            release_reservations::<PAGE_SIZE>(platform, vec![first, second, tail]);
            release_reservations::<PAGE_SIZE>(platform, Vec::new());
            for offset in (0..6 * PAGE_SIZE).step_by(PAGE_SIZE) {
                let mut residency = 0u8;
                let result =
                    libc::mincore((base + offset) as *mut _, PAGE_SIZE, &raw mut residency);
                if offset == 4 * PAGE_SIZE {
                    assert_eq!(result, 0);
                    assert_eq!(((base + offset) as *const u8).read(), 0x5a);
                    ((base + offset) as *mut u8).write(0xa5);
                } else {
                    assert_eq!(result, -1);
                    assert_eq!(
                        std::io::Error::last_os_error().raw_os_error(),
                        Some(libc::ENOMEM)
                    );
                }
            }
            release_reservations::<PAGE_SIZE>(platform, vec![retained]);
        }
    }

    #[test]
    fn test_release_preserves_survivors() {
        const PAGE_SIZE: usize = 4096;
        let platform = LinuxUserland::new();
        let reservation = reserve_backing(
            platform,
            0..5 * PAGE_SIZE,
            FixedAddressBehavior::Hint,
            false,
        )
        .unwrap();
        let base = reservation.range().start;
        let range = base + PAGE_SIZE..base + 4 * PAGE_SIZE;
        // SAFETY: The fixture exclusively owns all five pages and stops accessing released pages.
        unsafe {
            <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                reservation.range(),
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                false,
            )
            .unwrap();
            (base as *mut u8).write(0x5a);
            ((base + 4 * PAGE_SIZE) as *mut u8).write(0xa5);
            let (prefix, middle, suffix) = reservation.split(range.clone());
            let (_, first, rest) = middle.split(base + PAGE_SIZE..base + 2 * PAGE_SIZE);
            let (_, hole, last) = rest
                .unwrap()
                .split(base + 2 * PAGE_SIZE..base + 3 * PAGE_SIZE);
            release_reservations::<PAGE_SIZE>(platform, vec![first, hole, last.unwrap()]);
            for offset in (0..5 * PAGE_SIZE).step_by(PAGE_SIZE) {
                let mut residency = 0u8;
                let result =
                    libc::mincore((base + offset) as *mut _, PAGE_SIZE, &raw mut residency);
                if offset == 0 || offset == 4 * PAGE_SIZE {
                    assert_eq!(result, 0);
                } else {
                    assert_eq!(result, -1);
                    assert_eq!(
                        std::io::Error::last_os_error().raw_os_error(),
                        Some(libc::ENOMEM)
                    );
                }
            }
            assert_eq!((base as *const u8).read(), 0x5a);
            assert_eq!(((base + 4 * PAGE_SIZE) as *const u8).read(), 0xa5);
            release_reservations::<PAGE_SIZE>(platform, vec![prefix.unwrap(), suffix.unwrap()]);
        }
    }

    #[test]
    fn test_direct_reserved_mapping_lifecycle() {
        use litebox::mm::{
            WindowsPageManager,
            linux::{CreatePagesFlags, NonZeroPageSize},
        };

        const PAGE_SIZE: usize = 4096;

        let platform = LinuxUserland::new();
        let manager = WindowsPageManager::<_, PAGE_SIZE>::new(&litebox::LiteBox::new(platform));
        let initial_mappings = manager.mappings();
        let initial_reservations = manager.reservations();
        // SAFETY: No fixed address is requested; the reservation has no concurrent users.
        let ptr = unsafe {
            manager.create_reserved_pages(
                None,
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                PAGE_SIZE,
                CreatePagesFlags::empty(),
            )
        }
        .unwrap();
        let is_committed = || {
            manager
                .mappings()
                .into_iter()
                .any(|(range, _)| range.contains(&ptr.as_usize()))
        };
        assert!(!is_committed());
        assert!(
            manager
                .reservations()
                .contains(&(ptr.as_usize()..ptr.as_usize() + PAGE_SIZE))
        );
        assert_eq!(manager.reservations().len(), initial_reservations.len() + 1);

        // SAFETY: The page is exclusively owned; commitment may retain no-access permissions.
        unsafe { manager.commit_pages(ptr, PAGE_SIZE, MemoryRegionPermissions::empty()) }.unwrap();
        assert!(is_committed());
        // SAFETY: The committed page has no concurrent users.
        unsafe {
            manager.commit_pages(
                ptr,
                PAGE_SIZE,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )
        }
        .unwrap();
        ptr.write_at_offset(0, 0xa5).unwrap();

        // SAFETY: The test no longer accesses the committed page before recommitting it.
        unsafe { manager.decommit_pages(ptr, PAGE_SIZE) }.unwrap();
        assert!(!is_committed());
        // SAFETY: The page remains owned by the manager after decommit.
        unsafe { manager.commit_pages(ptr, PAGE_SIZE, MemoryRegionPermissions::READ) }.unwrap();
        assert_eq!(ptr.read_at_offset(0).unwrap(), 0);
        // SAFETY: The mapping is no longer accessed after removal.
        unsafe { manager.remove_pages(ptr, PAGE_SIZE) }.unwrap();
        assert_eq!(manager.reservations(), initial_reservations);
        assert_eq!(manager.mappings(), initial_mappings);

        let reservation = reserve_backing(
            platform,
            0..2 * PAGE_SIZE,
            FixedAddressBehavior::Hint,
            false,
        )
        .unwrap();
        let extent = reservation.range();
        // SAFETY: The test exclusively owns this reservation and ends all accesses before release.
        unsafe {
            <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                extent.start..extent.start + PAGE_SIZE,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                false,
            )
            .unwrap();
            (extent.start as *mut u8).write(0x5a);
            <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                extent.start + PAGE_SIZE..extent.end,
                MemoryRegionPermissions::READ,
                true,
            )
            .unwrap();
            <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::protect_pages(
                platform,
                || core::iter::once(&reservation),
                extent.clone(),
                MemoryRegionPermissions::READ,
            )
            .unwrap();
            assert_eq!((extent.start as *const u8).read(), 0x5a);
            assert_eq!(((extent.start + PAGE_SIZE) as *const u8).read(), 0);
            <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::protect_pages(
                platform,
                || core::iter::once(&reservation),
                extent.clone(),
                MemoryRegionPermissions::empty(),
            )
            .unwrap();
            <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::protect_pages(
                platform,
                || core::iter::once(&reservation),
                extent.clone(),
                MemoryRegionPermissions::READ,
            )
            .unwrap();
            assert_eq!((reservation.range().start as *const u8).read(), 0x5a);
            <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
                platform,
                || core::iter::once(&reservation),
                extent,
            )
            .unwrap();
            release_reservations::<PAGE_SIZE>(platform, vec![reservation]);
        }
    }

    #[test]
    fn test_reset_and_decommit_preserve_neighbors_and_permissions() {
        use crate::UserMutPtr;
        use litebox::mm::{
            CreatePagesFlags, LinuxPageManager, NonZeroPageSize, WindowsPageManager,
        };

        const PAGE_SIZE: usize = 4096;
        let next_page = isize::try_from(PAGE_SIZE).unwrap();
        let platform = LinuxUserland::new();
        let litebox = litebox::LiteBox::new(platform);
        let manager = LinuxPageManager::<_, PAGE_SIZE>::new(&litebox);
        let initial_reservations = manager.reservations();
        // SAFETY: The test exclusively owns these anonymous mappings and releases them after use.
        unsafe {
            let pointer = manager
                .create_writable_pages(
                    None,
                    NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
                    CreatePagesFlags::empty(),
                    |_| Ok(0),
                )
                .unwrap();
            pointer.write_at_offset(0, 0x5a).unwrap();
            pointer.write_at_offset(next_page, 0xa5).unwrap();
            pointer.write_at_offset(2 * next_page, 0x7f).unwrap();
            let middle = UserMutPtr::<u8>::from_usize(pointer.as_usize() + PAGE_SIZE);
            manager.make_pages_inaccessible(middle, PAGE_SIZE).unwrap();
            let mappings = manager.mappings();
            manager.reset_pages(middle, PAGE_SIZE, true).unwrap();
            assert_eq!(
                manager
                    .reservations()
                    .into_iter()
                    .filter(|range| !initial_reservations.contains(range))
                    .collect::<Vec<_>>(),
                (0..3)
                    .map(|index| {
                        let start = pointer.as_usize() + index * PAGE_SIZE;
                        start..start + PAGE_SIZE
                    })
                    .collect::<Vec<_>>()
            );
            assert_eq!(manager.mappings(), mappings);
            manager.make_pages_readable(middle, PAGE_SIZE).unwrap();
            assert_eq!(middle.read_at_offset(0), Some(0));
            let mappings = manager.mappings();
            manager.reset_pages(middle, PAGE_SIZE, true).unwrap();
            assert_eq!(manager.mappings(), mappings);
            assert_eq!(middle.read_at_offset(0), Some(0));
            assert_eq!(pointer.read_at_offset(0), Some(0x5a));
            assert_eq!(pointer.read_at_offset(2 * next_page), Some(0x7f));
            manager.unmap_pages(pointer, 3 * PAGE_SIZE).unwrap();
            assert_eq!(manager.reservations(), initial_reservations);

            let manager = WindowsPageManager::<_, PAGE_SIZE>::new(&litebox);
            let pointer = manager
                .create_reserved_and_committed_pages(
                    None,
                    NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
                    PAGE_SIZE,
                    CreatePagesFlags::empty(),
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                )
                .unwrap();
            pointer.write_at_offset(0, 0x5a).unwrap();
            pointer.write_at_offset(next_page, 0xa5).unwrap();
            pointer.write_at_offset(2 * next_page, 0x7f).unwrap();
            let middle = UserMutPtr::<u8>::from_usize(pointer.as_usize() + PAGE_SIZE);
            let reservations = manager.reservations();
            manager.decommit_pages(middle, PAGE_SIZE).unwrap();
            manager.decommit_pages(middle, PAGE_SIZE).unwrap();
            manager
                .commit_pages(pointer, 3 * PAGE_SIZE, MemoryRegionPermissions::READ)
                .unwrap();
            assert_eq!(manager.reservations(), reservations);
            assert_eq!(pointer.read_at_offset(0), Some(0x5a));
            assert_eq!(middle.read_at_offset(0), Some(0));
            assert_eq!(pointer.read_at_offset(2 * next_page), Some(0x7f));
            manager.remove_pages(pointer, 3 * PAGE_SIZE).unwrap();
        }
    }

    #[test]
    fn test_automatic_mappings_share_reservation_lifecycle() {
        use litebox::mm::{
            LinuxPageManager,
            linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize},
        };
        const PAGE_SIZE: usize = 4096;
        let platform = LinuxUserland::new();
        let manager = LinuxPageManager::<_, PAGE_SIZE>::new(&litebox::LiteBox::new(platform));
        let initial_mappings = manager.mappings();
        let initial_reservations = manager.reservations();
        // SAFETY: These mappings are private to the test, which stops accessing them before release.
        unsafe {
            let stack = manager
                .create_stack_pages(
                    None,
                    NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
                    CreatePagesFlags::empty(),
                )
                .unwrap();
            let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
            let stack_header = format!("{:x}-", stack.as_usize());
            let native_flags = smaps
                .lines()
                .skip_while(|line| !line.starts_with(&stack_header))
                .find_map(|line| line.strip_prefix("VmFlags:"))
                .expect("the committed stack must have a native VMA");
            assert!(native_flags.split_whitespace().any(|flag| flag == "gd"));
            let mapped = manager
                .create_writable_pages(
                    None,
                    NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
                    CreatePagesFlags::empty(),
                    |_| Ok(0),
                )
                .unwrap();
            assert_eq!(manager.reservations().len(), initial_reservations.len() + 2);
            let stack_backing = manager
                .reservations()
                .into_iter()
                .find(|range| range.contains(&stack.as_usize()))
                .unwrap();
            assert_eq!(
                stack_backing,
                stack.as_usize()..stack.as_usize() + 3 * PAGE_SIZE
            );
            assert!(
                manager.reservations().iter().any(|range| {
                    range == &(mapped.as_usize()..mapped.as_usize() + 3 * PAGE_SIZE)
                })
            );
            for pointer in [stack, mapped] {
                pointer.write_at_offset(0, 0x5a).unwrap();
            }
            let next_page = isize::try_from(PAGE_SIZE).unwrap();
            stack.write_at_offset(next_page, 0xa5).unwrap();
            manager.make_pages_inaccessible(stack, PAGE_SIZE).unwrap();
            manager.make_pages_readable(stack, PAGE_SIZE).unwrap();
            assert_eq!(stack.read_at_offset(0), Some(0x5a));
            manager.unmap_pages(stack, PAGE_SIZE).unwrap();
            assert!(
                manager
                    .reservations()
                    .iter()
                    .any(|range| range.contains(&stack.as_usize()))
            );
            let mut residency = 0u8;
            assert_eq!(
                libc::mincore(stack.as_usize() as *mut _, PAGE_SIZE, &raw mut residency),
                0
            );
            assert_eq!(stack.read_at_offset(next_page), Some(0xa5));
            manager
                .create_inaccessible_pages(
                    NonZeroAddress::new(stack.as_usize()),
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                    |_| Ok(0),
                )
                .unwrap();
            assert!(
                manager
                    .mappings()
                    .iter()
                    .any(|(range, _)| range.contains(&stack.as_usize()))
            );
            manager.make_pages_readable(stack, PAGE_SIZE).unwrap();
            assert_eq!(stack.read_at_offset(0), Some(0));
            assert_eq!(stack.read_at_offset(next_page), Some(0xa5));
            let reservations = manager.reservations();
            assert_eq!(reservations.len(), initial_reservations.len() + 2);
            let middle = crate::UserMutPtr::<u8>::from_usize(mapped.as_usize() + PAGE_SIZE);
            manager.make_pages_readable(middle, PAGE_SIZE).unwrap();
            assert_eq!(manager.reservations().len(), initial_reservations.len() + 2);
            manager.unmap_pages(stack, PAGE_SIZE).unwrap();
            assert_eq!(manager.reservations().len(), initial_reservations.len() + 2);
            assert!(
                !manager
                    .mappings()
                    .iter()
                    .any(|(range, _)| { range.contains(&stack.as_usize()) })
            );
            manager
                .create_readable_pages(
                    NonZeroAddress::new(stack.as_usize()),
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                    |_| Ok(0),
                )
                .unwrap();
            assert_eq!(stack.read_at_offset(0), Some(0));
            assert_eq!(stack.read_at_offset(next_page), Some(0xa5));
            assert_eq!(manager.reservations(), reservations);
            manager.release_memory().unwrap();
            assert_eq!(manager.reservations(), initial_reservations);
            assert_eq!(manager.mappings(), initial_mappings);
            for pointer in [stack, mapped] {
                assert_eq!(
                    syscalls::syscall3(
                        syscalls::Sysno::mprotect,
                        pointer.as_usize(),
                        3 * PAGE_SIZE,
                        libc::PROT_READ as usize,
                    ),
                    Err(syscalls::Errno::ENOMEM)
                );
            }
        }
    }

    #[test]
    fn test_native_remap_preserves_manager_ownership() {
        use litebox::mm::{
            LinuxPageManager,
            linux::{CreatePagesFlags, NonZeroPageSize},
        };
        const PAGE_SIZE: usize = 4096;
        let platform = LinuxUserland::new();
        let manager = LinuxPageManager::<_, PAGE_SIZE>::new(&litebox::LiteBox::new(platform));
        let initial_mappings = manager.mappings();
        let initial_reservations = manager.reservations();
        // SAFETY: All allocations are exclusive to this fixture; accesses stop before cleanup.
        unsafe {
            let source = manager
                .create_writable_pages(
                    None,
                    NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
                    CreatePagesFlags::empty(),
                    |_| Ok(0),
                )
                .unwrap();
            let base = source.as_usize();
            source.write_at_offset(0, 0x5a).unwrap();
            source
                .write_at_offset(isize::try_from(2 * PAGE_SIZE).unwrap(), 0xa5)
                .unwrap();
            manager
                .make_pages_inaccessible(source, 3 * PAGE_SIZE)
                .unwrap();
            assert!(matches!(
                manager.remap_pages(source, 2 * PAGE_SIZE, 4 * PAGE_SIZE, false),
                Err(litebox::platform::page_mgmt::RemapError::OutOfMemory)
            ));
            let moved = manager
                .remap_pages(source, 2 * PAGE_SIZE, 4 * PAGE_SIZE, true)
                .unwrap();
            assert_ne!(moved.as_usize(), base);
            let suffix = crate::UserMutPtr::<u8>::from_usize(base + 2 * PAGE_SIZE);
            let actual = manager.reservations();
            let mut expected = vec![
                base + 2 * PAGE_SIZE..base + 3 * PAGE_SIZE,
                moved.as_usize()..moved.as_usize() + 4 * PAGE_SIZE,
            ];
            expected.extend(initial_reservations.iter().cloned());
            expected.sort_by_key(|range| range.start);
            assert_eq!(actual, expected);
            manager.make_pages_readable(moved, 4 * PAGE_SIZE).unwrap();
            manager.make_pages_readable(suffix, PAGE_SIZE).unwrap();
            assert_eq!(moved.read_at_offset(0), Some(0x5a));
            assert_eq!(
                moved.read_at_offset(isize::try_from(4 * PAGE_SIZE - 1).unwrap()),
                Some(0)
            );
            assert_eq!(suffix.read_at_offset(0), Some(0xa5));
            assert_eq!(
                syscalls::syscall3(
                    syscalls::Sysno::mprotect,
                    base,
                    2 * PAGE_SIZE,
                    libc::PROT_READ as usize
                ),
                Err(syscalls::Errno::ENOMEM),
            );
            manager.unmap_pages(moved, 4 * PAGE_SIZE).unwrap();
            manager.unmap_pages(suffix, PAGE_SIZE).unwrap();
            assert_eq!(manager.reservations(), initial_reservations);
            assert_eq!(manager.mappings(), initial_mappings);

            let permissions = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
            let source = <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
                platform,
                || -> core::iter::Empty<_> { panic!("hint reserve must not request reservations") },
                0..4 * PAGE_SIZE,
                false,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
            let neighbor = <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
                platform,
                || -> core::iter::Empty<_> { panic!("hint reserve must not request reservations") },
                0..4 * PAGE_SIZE,
                false,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
            for reservation in [&source, &neighbor] {
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                    platform,
                    || core::iter::once(reservation),
                    reservation.range(),
                    permissions,
                    true,
                )
                .unwrap();
            }
            let source_range = source.range();
            let source_pointer = crate::UserMutPtr::<u8>::from_usize(source_range.start);
            let neighbor_pointer = crate::UserMutPtr::<u8>::from_usize(neighbor.range().start);
            source_pointer.write_at_offset(0, 0x7f).unwrap();
            source_pointer
                .write_at_offset(isize::try_from(PAGE_SIZE).unwrap(), 0x5a)
                .unwrap();
            source_pointer
                .write_at_offset(isize::try_from(3 * PAGE_SIZE).unwrap(), 0xa5)
                .unwrap();
            neighbor_pointer.write_at_offset(0, 0x3c).unwrap();
            let old_range = source_range.start + PAGE_SIZE..source_range.end - PAGE_SIZE;
            let (prefix, first, second) =
                source.split(source_range.start..source_range.start + 2 * PAGE_SIZE);
            assert!(prefix.is_none());
            let mut reservations = vec![first, second.unwrap()];
            let acquired = <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::try_remap_pages(
                platform,
                || take_contained_reservations(&mut reservations, old_range.clone()),
                old_range.clone(),
                0..4 * PAGE_SIZE,
                permissions,
            )
            .unwrap();
            let actual = acquired.range();
            reservations.push(acquired);
            reservations.sort_unstable_by_key(|reservation| reservation.range().start);
            let mut expected = vec![
                source_range.start..source_range.start + PAGE_SIZE,
                source_range.end - PAGE_SIZE..source_range.end,
                actual.clone(),
            ];
            expected.sort_unstable_by_key(|range| range.start);
            assert_eq!(
                reservations
                    .iter()
                    .map(litebox::platform::page_mgmt::PageReservation::range)
                    .collect::<Vec<_>>(),
                expected
            );
            let moved = crate::UserMutPtr::<u8>::from_usize(actual.start);
            assert_eq!(moved.read_at_offset(0), Some(0x5a));
            assert_eq!(
                moved.read_at_offset(isize::try_from(actual.len() - 1).unwrap()),
                Some(0)
            );
            assert_eq!(neighbor_pointer.read_at_offset(0), Some(0x3c));
            assert_eq!(source_pointer.read_at_offset(0), Some(0x7f));
            assert_eq!(
                source_pointer.read_at_offset(isize::try_from(3 * PAGE_SIZE).unwrap()),
                Some(0xa5)
            );
            reservations.push(neighbor);
            release_reservations::<PAGE_SIZE>(platform, reservations);
        }
    }

    #[test]
    fn test_cow_mapping_registers_native_backing() {
        use litebox::mm::LinuxPageManager;
        const PAGE_SIZE: usize = 4096;
        let content: &'static [u8; PAGE_SIZE] = &[0x5a; PAGE_SIZE];
        let platform = LinuxUserland::new();
        let manager = LinuxPageManager::<_, PAGE_SIZE>::new(&litebox::LiteBox::new(platform));
        let initial_mappings = manager.mappings();
        let initial_reservations = manager.reservations();
        let permissions = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        let path = std::env::temp_dir().join(format!("litebox-cow-{}", std::process::id()));
        std::fs::write(&path, content).unwrap();
        // SAFETY: The test exclusively owns all requested mappings and relinquishes them before cleanup.
        unsafe {
            assert!(
                manager
                    .try_create_cow_pages(
                        0,
                        content,
                        permissions,
                        FixedAddressBehavior::Hint,
                        false,
                    )
                    .is_err()
            );
            assert_eq!(manager.mappings(), initial_mappings);
            assert_eq!(manager.reservations(), initial_reservations);
            platform.register_cow_region(content, &path);
            let mapped = manager
                .try_create_cow_pages(0, content, permissions, FixedAddressBehavior::Hint, false)
                .unwrap();
            let address = mapped.as_usize();
            let reservations = manager.reservations();
            assert_eq!(reservations.len(), initial_reservations.len() + 1);
            assert!(reservations.contains(&(address..address + PAGE_SIZE)));
            assert_eq!(mapped.as_usize(), address);
            assert_eq!(mapped.read_at_offset(0), Some(0x5a));
            mapped.write_at_offset(0, 0xa5).unwrap();
            assert_eq!(std::fs::read(&path).unwrap()[0], 0x5a);
            assert_eq!(manager.reservations(), reservations);
            assert!(
                manager
                    .mappings()
                    .iter()
                    .any(|(range, _)| { range == &(address..address + PAGE_SIZE) })
            );
            assert!(
                manager
                    .try_create_cow_pages(
                        address,
                        content,
                        permissions,
                        FixedAddressBehavior::NoReplace,
                        false,
                    )
                    .is_err()
            );
            assert_eq!(mapped.read_at_offset(0), Some(0xa5));
            manager.unmap_pages(mapped, PAGE_SIZE).unwrap();
            assert_eq!(manager.mappings(), initial_mappings);
            assert_eq!(manager.reservations(), initial_reservations);
            let remapped = manager
                .try_create_cow_pages(
                    address,
                    content,
                    permissions,
                    FixedAddressBehavior::NoReplace,
                    false,
                )
                .unwrap();
            assert_eq!(remapped.as_usize(), address);
            assert_eq!(remapped.read_at_offset(0), Some(0x5a));
            let mappings = manager.mappings();
            let reservations = manager.reservations();
            assert!(
                manager
                    .try_create_cow_pages(
                        address,
                        &[0x3c; PAGE_SIZE],
                        permissions,
                        FixedAddressBehavior::Replace,
                        false,
                    )
                    .is_err()
            );
            assert_eq!(manager.mappings(), mappings);
            assert_eq!(manager.reservations(), reservations);
            remapped.write_at_offset(0, 0xa5).unwrap();
            let replaced = manager
                .try_create_cow_pages(
                    address,
                    content,
                    permissions,
                    FixedAddressBehavior::Replace,
                    false,
                )
                .unwrap();
            assert_eq!(replaced.as_usize(), address);
            assert_eq!(replaced.read_at_offset(0), Some(0x5a));
            assert_eq!(manager.reservations(), reservations);
            manager.release_memory().unwrap();
            assert_eq!(manager.reservations(), initial_reservations);
            assert_eq!(manager.mappings(), initial_mappings);
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_cow_replacement_transfers_reservation_ownership() {
        use litebox::platform::page_mgmt::{CowAllocationError, PageReservation};

        const PAGE_SIZE: usize = 4096;
        let content: &'static [u8; 2 * PAGE_SIZE] = &[0x5a; 2 * PAGE_SIZE];
        let platform = LinuxUserland::new();
        let permissions = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        let path = std::env::temp_dir().join(format!("litebox-cow-tokens-{}", std::process::id()));
        std::fs::write(&path, content).unwrap();
        // SAFETY: All mappings belong exclusively to the test; replacement is authorized and release ends all accesses.
        unsafe {
            let reservation = <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
                platform,
                core::iter::empty,
                0..4 * PAGE_SIZE,
                false,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
            <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                reservation.range(),
                permissions,
                false,
            )
            .unwrap();
            let base = reservation.range().start;
            for offset in (0..4 * PAGE_SIZE).step_by(PAGE_SIZE) {
                ((base + offset) as *mut u8).write(0xa5);
            }
            let (_, first, second) = reservation.split(base..base + 2 * PAGE_SIZE);
            let mut tokens = vec![first, second.unwrap()];
            let original_ranges = tokens
                .iter()
                .map(PageReservation::range)
                .collect::<Vec<_>>();
            let error =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::try_allocate_cow_pages(
                    platform,
                    || -> core::iter::Empty<_> {
                        panic!("unsupported CoW must not request reservations")
                    },
                    base + PAGE_SIZE,
                    content,
                    permissions,
                    FixedAddressBehavior::Replace,
                )
                .unwrap_err();
            assert!(matches!(error, CowAllocationError::UnsupportedSourceRegion));
            assert_eq!(
                tokens
                    .iter()
                    .map(PageReservation::range)
                    .collect::<Vec<_>>(),
                vec![
                    base..base + 2 * PAGE_SIZE,
                    base + 2 * PAGE_SIZE..base + 4 * PAGE_SIZE,
                ]
            );
            for offset in (0..4 * PAGE_SIZE).step_by(PAGE_SIZE) {
                assert_eq!(((base + offset) as *const u8).read(), 0xa5);
            }
            platform.register_cow_region(content, &path);
            let error =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::try_allocate_cow_pages(
                    platform,
                    || -> core::iter::Empty<_> {
                        panic!("invalid CoW must not request reservations")
                    },
                    base + PAGE_SIZE + 1,
                    content,
                    permissions,
                    FixedAddressBehavior::Replace,
                )
                .unwrap_err();
            assert!(matches!(error, CowAllocationError::Unaligned));
            assert_eq!(
                tokens
                    .iter()
                    .map(PageReservation::range)
                    .collect::<Vec<_>>(),
                original_ranges
            );
            let relocated =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::try_allocate_cow_pages(
                    platform,
                    || -> core::iter::Empty<_> { panic!("hint CoW must not request reservations") },
                    base + PAGE_SIZE,
                    content,
                    permissions,
                    FixedAddressBehavior::Hint,
                )
                .unwrap();
            let relocated_range = relocated.range();
            assert!(relocated_range.end <= base || relocated_range.start >= base + 4 * PAGE_SIZE);
            assert_eq!((relocated_range.start as *const u8).read(), 0x5a);
            release_reservations::<PAGE_SIZE>(platform, vec![relocated]);
            let fresh =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::try_allocate_cow_pages(
                    platform,
                    || -> core::iter::Empty<_> {
                        panic!("no-replace CoW must not request reservations")
                    },
                    relocated_range.start,
                    content,
                    permissions,
                    FixedAddressBehavior::NoReplace,
                )
                .unwrap();
            assert_eq!(fresh.range(), relocated_range);
            assert_eq!((relocated_range.start as *const u8).read(), 0x5a);
            release_reservations::<PAGE_SIZE>(platform, vec![fresh]);
            let mapped =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::try_allocate_cow_pages(
                    platform,
                    || {
                        take_contained_reservations(
                            &mut tokens,
                            base + PAGE_SIZE..base + 3 * PAGE_SIZE,
                        )
                    },
                    base + PAGE_SIZE,
                    content,
                    permissions,
                    FixedAddressBehavior::Replace,
                )
                .unwrap();
            assert_eq!(mapped.range(), base + PAGE_SIZE..base + 3 * PAGE_SIZE);
            assert_eq!(
                tokens
                    .iter()
                    .map(PageReservation::range)
                    .collect::<Vec<_>>(),
                vec![
                    base..base + PAGE_SIZE,
                    base + 3 * PAGE_SIZE..base + 4 * PAGE_SIZE,
                ]
            );
            assert_eq!((base as *const u8).read(), 0xa5);
            assert_eq!(((base + 3 * PAGE_SIZE) as *const u8).read(), 0xa5);
            assert_eq!(((base + PAGE_SIZE) as *const u8).read(), 0x5a);
            assert_eq!(((base + 2 * PAGE_SIZE) as *const u8).read(), 0x5a);
            ((base + PAGE_SIZE) as *mut u8).write(0x3c);
            assert_eq!(std::fs::read(&path).unwrap()[0], 0x5a);
            let error =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::try_allocate_cow_pages(
                    platform,
                    || -> core::iter::Empty<_> {
                        panic!("no-replace CoW must not request reservations")
                    },
                    base + PAGE_SIZE,
                    content,
                    permissions,
                    FixedAddressBehavior::NoReplace,
                )
                .unwrap_err();
            assert!(matches!(error, CowAllocationError::InternalFailure));
            assert_eq!(((base + PAGE_SIZE) as *const u8).read(), 0x3c);
            tokens.insert(1, mapped);
            release_reservations::<PAGE_SIZE>(platform, tokens);
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_decommit_preserves_mapping_ownership() {
        use litebox::platform::page_mgmt::PageReservation;

        let platform = LinuxUserland::new();
        let permissions = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        // SAFETY: Hint acquisition returns a fresh mapping; this test ends all accesses before releasing its handles.
        unsafe {
            let reservation = <LinuxUserland as PageManagementProvider<4096>>::reserve_pages(
                platform,
                || -> core::iter::Empty<_> { panic!("hint reserve must not request reservations") },
                0..12288,
                false,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
            let base = reservation.range().start;
            let pointer = crate::UserMutPtr::<u8>::from_usize(base);
            assert_eq!(pointer.read_at_offset(0), None);
            assert_eq!(pointer.read_at_offset(8192), None);
            assert!(pointer.to_owned_slice(12288).is_none());
            <LinuxUserland as PageManagementProvider<4096>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                reservation.range(),
                permissions,
                false,
            )
            .unwrap();
            pointer.write_at_offset(0, 0x5a).unwrap();
            pointer.write_at_offset(4096, 0xa5).unwrap();
            pointer.write_at_offset(8192, 0x7e).unwrap();
            let middle = base + 4096..base + 8192;
            <LinuxUserland as PageManagementProvider<4096>>::decommit_pages(
                platform,
                || -> core::iter::Once<&ReservationOf<LinuxUserland, 4096>> {
                    panic!("range-based decommit must not request reservations")
                },
                middle.clone(),
            )
            .unwrap();
            assert_eq!(reservation.range(), base..base + 12288);
            assert_eq!(pointer.read_at_offset(0), Some(0x5a));
            assert_eq!(pointer.read_at_offset(4096), None);
            assert_eq!(pointer.read_at_offset(8192), Some(0x7e));
            assert!(pointer.to_owned_slice(12288).is_none());
            for permissions in [
                MemoryRegionPermissions::empty(),
                MemoryRegionPermissions::READ,
            ] {
                <LinuxUserland as PageManagementProvider<4096>>::commit_pages(
                    platform,
                    || core::iter::once(&reservation),
                    reservation.range(),
                    permissions,
                    false,
                )
                .unwrap();
            }
            assert_eq!(pointer.read_at_offset(0), Some(0x5a));
            assert_eq!(pointer.read_at_offset(4096), Some(0));
            assert_eq!(pointer.read_at_offset(8192), Some(0x7e));
            let copied = pointer.to_owned_slice(12288).unwrap();
            assert_eq!(copied[0], 0x5a);
            assert_eq!(copied[8192], 0x7e);
            assert!(copied[4096..8192].iter().all(|&byte| byte == 0));
            <LinuxUserland as PageManagementProvider<4096>>::commit_pages(
                platform,
                || core::iter::once(&reservation),
                middle.clone(),
                MemoryRegionPermissions::READ,
                false,
            )
            .unwrap();
            assert_eq!(pointer.read_at_offset(4096), Some(0));
            let (prefix, released, suffix) = reservation.split(middle);
            release_reservations::<4096>(platform, vec![released]);
            assert_eq!(pointer.read_at_offset(0), Some(0x5a));
            assert_eq!(pointer.read_at_offset(8192), Some(0x7e));
            release_reservations::<4096>(platform, vec![prefix.unwrap(), suffix.unwrap()]);
        }
    }

    #[test]
    fn test_batched_commit_and_decommit_skip_reservation_lookup() {
        use litebox::platform::page_mgmt::PageReservation;

        const PAGE_SIZE: usize = 4096;
        let platform = LinuxUserland::new();
        let permissions = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        // SAFETY: The fixture exclusively owns these private anonymous pages and excludes users during state changes and release.
        unsafe {
            let reservation =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                    platform,
                    || -> core::iter::Empty<_> {
                        panic!("hint allocation must not request reservations")
                    },
                    0..4 * PAGE_SIZE,
                    permissions,
                    false,
                    false,
                    FixedAddressBehavior::Hint,
                )
                .unwrap();
            let base = reservation.range().start;
            core::ptr::write_bytes(base as *mut u8, 0xa5, 4 * PAGE_SIZE);
            let (_, prefix, suffix) = reservation.split(base..base + 2 * PAGE_SIZE);
            let reservations = vec![prefix, suffix.unwrap()];
            let pointer = crate::UserMutPtr::<u8>::from_usize(base);
            let page_offset = isize::try_from(PAGE_SIZE).unwrap();
            let middle = base + PAGE_SIZE..base + 3 * PAGE_SIZE;
            for _ in 0..2 {
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::decommit_pages(
                    platform,
                    || -> core::slice::Iter<'_, ReservationOf<LinuxUserland, PAGE_SIZE>> {
                        panic!("range-based decommit must not request reservations")
                    },
                    middle.clone(),
                )
                .unwrap();
                assert_eq!(pointer.read_at_offset(0), Some(0xa5));
                assert_eq!(pointer.read_at_offset(page_offset), None);
                assert_eq!(pointer.read_at_offset(2 * page_offset), None);
                assert_eq!(pointer.read_at_offset(3 * page_offset), Some(0xa5));
            }
            for (index, reservation) in reservations.iter().enumerate() {
                assert_eq!(
                    reservation.range(),
                    base + index * 2 * PAGE_SIZE..base + (index + 1) * 2 * PAGE_SIZE,
                );
            }
            for permissions in [
                MemoryRegionPermissions::empty(),
                MemoryRegionPermissions::READ,
            ] {
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                    platform,
                    || -> core::slice::Iter<'_, ReservationOf<LinuxUserland, PAGE_SIZE>> {
                        panic!("range-based commit must not request reservations")
                    },
                    base..base + 4 * PAGE_SIZE,
                    permissions,
                    true,
                )
                .unwrap();
            }
            let contents = pointer.to_owned_slice(4 * PAGE_SIZE).unwrap();
            assert!(contents[..PAGE_SIZE].iter().all(|&byte| byte == 0xa5));
            assert!(
                contents[PAGE_SIZE..3 * PAGE_SIZE]
                    .iter()
                    .all(|&byte| byte == 0)
            );
            assert!(contents[3 * PAGE_SIZE..].iter().all(|&byte| byte == 0xa5));
            release_reservations::<PAGE_SIZE>(platform, reservations);
        }
    }

    #[test]
    fn test_reserve_replacement_transfers_ownership() {
        use litebox::platform::page_mgmt::{AllocationError, PageReservation};
        const PAGE_SIZE: usize = 4096;
        let platform = LinuxUserland::new();
        let release = release_reservations::<PAGE_SIZE>;
        let permissions = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        // SAFETY: The fixture exclusively owns all mappings, including the replacement range;
        // all reads and writes finish before the corresponding handles are released.
        unsafe {
            let original = <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
                platform,
                || -> core::iter::Empty<_> { panic!("hint reserve must not request reservations") },
                0..6 * PAGE_SIZE,
                false,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
            <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::commit_pages(
                platform,
                || core::iter::once(&original),
                original.range(),
                permissions,
                false,
            )
            .unwrap();
            let base = original.range().start;
            for (index, marker) in [0x51u8, 0x52, 0x53, 0x54, 0x55, 0x56]
                .into_iter()
                .enumerate()
            {
                ((base + index * PAGE_SIZE) as *mut u8).write(marker);
            }
            let (_, first, tail) = original.split(base..base + 2 * PAGE_SIZE);
            let (gap, second, _) = tail
                .unwrap()
                .split(base + 3 * PAGE_SIZE..base + 6 * PAGE_SIZE);
            release(platform, vec![gap.unwrap()]);
            let original_ranges = vec![first.range(), second.range()];
            let requested = base + PAGE_SIZE..base + 5 * PAGE_SIZE;
            let mut existing = vec![first, second];
            let error = <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
                platform,
                || -> core::iter::Empty<_> {
                    panic!("invalid reserve must not request reservations")
                },
                requested.start..requested.end + 1,
                false,
                FixedAddressBehavior::Replace,
            )
            .unwrap_err();
            assert!(matches!(error, AllocationError::Unaligned));
            assert_eq!(
                existing
                    .iter()
                    .map(PageReservation::range)
                    .collect::<Vec<_>>(),
                original_ranges
            );
            assert_eq!((requested.start as *const u8).read(), 0x52);
            assert_eq!(((requested.end - PAGE_SIZE) as *const u8).read(), 0x55);
            let error = <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
                platform,
                || -> core::iter::Empty<_> {
                    panic!("no-replace reserve must not request reservations")
                },
                requested.clone(),
                false,
                FixedAddressBehavior::NoReplace,
            )
            .unwrap_err();
            assert!(matches!(error, AllocationError::AddressInUse));
            let relocated = <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_pages(
                platform,
                || -> core::iter::Empty<_> { panic!("hint reserve must not request reservations") },
                requested.clone(),
                false,
                FixedAddressBehavior::Hint,
            )
            .unwrap();
            assert_ne!(relocated.range().start, requested.start);
            assert_eq!(relocated.range().len(), requested.len());
            release(platform, vec![relocated]);
            let replacement =
                <LinuxUserland as PageManagementProvider<PAGE_SIZE>>::reserve_and_commit_pages(
                    platform,
                    || take_contained_reservations(&mut existing, requested.clone()),
                    requested.clone(),
                    permissions,
                    false,
                    false,
                    FixedAddressBehavior::Replace,
                )
                .unwrap();
            assert_eq!(replacement.range(), requested);
            assert_eq!(
                existing
                    .iter()
                    .map(PageReservation::range)
                    .collect::<Vec<_>>(),
                vec![
                    base..base + PAGE_SIZE,
                    base + 5 * PAGE_SIZE..base + 6 * PAGE_SIZE
                ]
            );
            for address in requested.clone().step_by(PAGE_SIZE) {
                assert_eq!((address as *const u8).read(), 0);
            }
            assert_eq!((base as *const u8).read(), 0x51);
            assert_eq!(((base + 5 * PAGE_SIZE) as *const u8).read(), 0x56);
            release(platform, vec![replacement]);
            for reservation in existing {
                release(platform, vec![reservation]);
            }
            assert_eq!(
                syscalls::syscall3(
                    syscalls::Sysno::mprotect,
                    base,
                    6 * PAGE_SIZE,
                    libc::PROT_READ as usize
                ),
                Err(syscalls::Errno::ENOMEM)
            );
        }
    }

    #[test]
    fn test_direct_mapping_preserves_native_replacement_modes() {
        use litebox::mm::{
            LinuxPageManager,
            linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize},
        };
        use litebox::platform::page_mgmt::AllocationError;

        const PAGE_SIZE: usize = 4096;
        let platform = LinuxUserland::new();
        let foreign = LinuxUserland::mmap_anonymous(
            0..2 * PAGE_SIZE,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            false,
            false,
            FixedAddressBehavior::Hint,
        )
        .unwrap();
        let range = foreign.as_usize()..foreign.as_usize() + PAGE_SIZE;
        foreign.write_at_offset(0, 0xa5).unwrap();
        let manager = LinuxPageManager::<_, PAGE_SIZE>::new(&litebox::LiteBox::new(platform));
        let initial_mappings = manager.mappings();
        let initial_reservations = manager.reservations();
        // SAFETY: NoReplace preserves the existing native mapping, which has no concurrent users.
        assert!(
            unsafe {
                manager.create_writable_pages(
                    Some(NonZeroAddress::new(range.start).unwrap()),
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                    |_| Ok(0),
                )
            }
            .is_err()
        );
        assert_eq!(manager.mappings(), initial_mappings);
        assert!(matches!(
            reserve_backing(
                platform,
                range.clone(),
                FixedAddressBehavior::NoReplace,
                false,
            ),
            Err(AllocationError::AddressInUse)
        ));
        let relocated =
            reserve_backing(platform, range.clone(), FixedAddressBehavior::Hint, false).unwrap();
        assert_ne!(relocated.range().start, range.start);
        assert_eq!(foreign.read_at_offset(0).unwrap(), 0xa5);
        // SAFETY: The test owns the relocated reservation and both adjacent mapped pages;
        // the second is replaced through the manager first, then both are replaced without concurrent users.
        unsafe {
            release_reservations::<PAGE_SIZE>(platform, vec![relocated]);
            let owned = manager
                .create_writable_pages(
                    NonZeroAddress::new(range.end),
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    CreatePagesFlags::FIXED_ADDR,
                    |_| Ok(0),
                )
                .unwrap();
            owned.write_at_offset(0, 0x5a).unwrap();
            let mappings = manager.mappings();
            let reservations = manager.reservations();
            assert!(
                manager
                    .create_writable_pages(
                        NonZeroAddress::new(range.start),
                        NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
                        CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                        |_| Ok(0)
                    )
                    .is_err()
            );
            assert_eq!(manager.mappings(), mappings);
            assert_eq!(manager.reservations(), reservations);
            assert_eq!(foreign.read_at_offset(0), Some(0xa5));
            assert_eq!(owned.read_at_offset(0), Some(0x5a));

            let replacement = manager
                .create_writable_pages(
                    NonZeroAddress::new(range.start),
                    NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
                    CreatePagesFlags::FIXED_ADDR,
                    |pointer| {
                        assert_eq!(pointer.read_at_offset(0), Some(0));
                        assert_eq!(
                            pointer.read_at_offset(isize::try_from(PAGE_SIZE).unwrap()),
                            Some(0)
                        );
                        Ok(0)
                    },
                )
                .unwrap();
            assert_eq!(replacement.as_usize(), range.start);
            assert_eq!(
                manager
                    .reservations()
                    .into_iter()
                    .filter(|range| !initial_reservations.contains(range))
                    .collect::<Vec<_>>(),
                core::slice::from_ref(&(range.start..range.end + PAGE_SIZE))
            );
            manager.unmap_pages(replacement, 2 * PAGE_SIZE).unwrap();
            assert_eq!(manager.reservations(), initial_reservations);
            assert_eq!(manager.mappings(), initial_mappings);
        }
    }

    #[test]
    fn test_direct_mapping_releases_file_backed_subrange() {
        use litebox::mm::{
            LinuxPageManager,
            linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize},
        };

        const PAGE_SIZE: usize = 4096;
        let platform = LinuxUserland::new();
        let manager = LinuxPageManager::<_, PAGE_SIZE>::new(&litebox::LiteBox::new(platform));
        let length = NonZeroPageSize::new(PAGE_SIZE).unwrap();
        // SAFETY: No fixed address is requested and the mapping has no concurrent users.
        let allocation = unsafe {
            manager
                .create_writable_pages(
                    None,
                    NonZeroPageSize::new(PAGE_SIZE * 3).unwrap(),
                    CreatePagesFlags::empty(),
                    |_| Ok(0),
                )
                .unwrap()
        };
        allocation.write_at_offset(0, 0x12).unwrap();
        allocation
            .write_at_offset(isize::try_from(PAGE_SIZE * 2).unwrap(), 0x34)
            .unwrap();
        let pointer = super::UserMutPtr::<u8>::from_usize(allocation.as_usize() + PAGE_SIZE);
        let range = pointer.as_usize()..pointer.as_usize() + PAGE_SIZE;
        let _cleanup = litebox::utils::defer(|| {
            // SAFETY: Only the test's allocation is removed; startup mappings are untouched.
            unsafe { manager.unmap_pages(allocation, PAGE_SIZE * 3) }.unwrap();
        });
        // SAFETY: The name is a valid C string; the returned descriptor is checked and owned below.
        let descriptor =
            unsafe { libc::memfd_create(c"reservation-backing".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(descriptor >= 0);
        // SAFETY: The descriptor was just created and has no other owner.
        let backing = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let contents: &'static [u8; PAGE_SIZE] = &[0xa5_u8; PAGE_SIZE];
        // SAFETY: The descriptor is live and contents is readable for its full length.
        assert_eq!(
            unsafe {
                libc::pwrite(
                    backing.as_raw_fd(),
                    contents.as_ptr().cast(),
                    contents.len(),
                    0,
                )
            },
            isize::try_from(PAGE_SIZE).unwrap()
        );
        platform.register_cow_region(
            contents,
            std::path::PathBuf::from(format!("/proc/self/fd/{}", backing.as_raw_fd())),
        );
        // SAFETY: The test exclusively owns this page and permits replacement with committed CoW backing.
        let mapped = unsafe {
            manager.try_create_cow_pages(
                range.start,
                contents,
                MemoryRegionPermissions::READ,
                FixedAddressBehavior::Replace,
                false,
            )
        }
        .unwrap();
        assert_eq!(mapped.as_usize(), range.start);
        assert_eq!(pointer.read_at_offset(0).unwrap(), 0xa5);
        // SAFETY: The file-backed guest mapping has no concurrent users.
        unsafe { manager.unmap_pages(pointer, PAGE_SIZE) }.unwrap();
        assert_eq!(allocation.read_at_offset(0).unwrap(), 0x12);
        assert_eq!(
            allocation
                .read_at_offset(isize::try_from(PAGE_SIZE * 2).unwrap())
                .unwrap(),
            0x34
        );
        let released = reserve_backing(
            platform,
            range.clone(),
            FixedAddressBehavior::NoReplace,
            false,
        )
        .unwrap();
        assert_eq!(released.range().start, range.start);
        // SAFETY: This independently acquired reservation is exclusively owned and unused.
        unsafe {
            release_reservations::<PAGE_SIZE>(platform, vec![released]);
        }
        // SAFETY: This address has no guest mapping; NoReplace prevents overwriting host mappings.
        let reused = unsafe {
            manager
                .create_writable_pages(
                    Some(NonZeroAddress::new(range.start).unwrap()),
                    length,
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                    |_| Ok(0),
                )
                .unwrap()
        };
        assert_eq!(reused.as_usize(), range.start);
        assert_eq!(reused.read_at_offset(0).unwrap(), 0);
        // SAFETY: The test's allocation has no concurrent users; startup mappings are untouched.
        unsafe { manager.unmap_pages(allocation, PAGE_SIZE * 3) }.unwrap();
        let released = reserve_backing(
            platform,
            range.clone(),
            FixedAddressBehavior::NoReplace,
            false,
        )
        .unwrap();
        assert_eq!(released.range().start, range.start);
        // SAFETY: The complete reacquired reservation is exclusively owned and unused.
        unsafe {
            release_reservations::<PAGE_SIZE>(platform, vec![released]);
        }
    }
}
