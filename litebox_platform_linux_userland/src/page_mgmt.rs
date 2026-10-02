// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use litebox::platform::page_mgmt::{AllocationDirection, HintPlacementBehavior};

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

litebox::define_page_reservation!(LinuxUserlandReservation);

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for LinuxUserland {
    type Reservations = litebox::platform::common_providers::reservations::NoTrackedReservations<
        ALIGN,
        LinuxUserlandReservation<ALIGN>,
    >;

    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux config
    #[cfg(target_arch = "x86_64")]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    const HINT_PLACEMENT_BEHAVIOR: HintPlacementBehavior =
        HintPlacementBehavior::Directional(AllocationDirection::TopDown);

    unsafe fn commit_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        populate_pages_immediately: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError>
    where
        Reservations: Iterator<Item = &'reservation LinuxUserlandReservation<ALIGN>>,
        LinuxUserlandReservation<ALIGN>: 'reservation,
    {
        // SAFETY: The caller owns the mapping and excludes conflicting access to these pages.
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::mprotect,
                range.start,
                range.len(),
                prot_flags(permissions).bits().reinterpret_as_unsigned() as usize,
            )
        }
        .expect("mprotect failed while committing pages");
        if populate_pages_immediately {
            // TODO: MADV_WILLNEED only reads ahead file or swap pages; anonymous pages still fault lazily.
            // SAFETY: This advice covers the live owned mapping and does not change its contents.
            let _ = unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::madvise,
                    range.start,
                    range.len(),
                    libc::MADV_WILLNEED as usize,
                )
            };
        }
        Ok(UserMutPtr::from_ptr(range.start as *mut u8))
    }

    unsafe fn reserve_and_commit_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<
        litebox::platform::page_mgmt::ReservationOf<Self, ALIGN>,
        litebox::platform::page_mgmt::AllocationError,
    >
    where
        Reservations: Iterator<Item = litebox::platform::page_mgmt::ReservationOf<Self, ALIGN>>,
    {
        debug_assert!(!suggested_range.is_empty());
        debug_assert!(
            suggested_range.start
                >= <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MIN
                || (suggested_range.start == 0
                    && matches!(fixed_address_behavior, FixedAddressBehavior::Hint(_)))
        );
        debug_assert!(
            suggested_range.end
                <= <Self as litebox::platform::PageManagementProvider<ALIGN>>::TASK_ADDR_MAX
        );
        debug_assert!(!matches!(
            fixed_address_behavior,
            FixedAddressBehavior::Hint(AllocationDirection::BottomUp)
        ));
        let flags = MapFlags::MAP_PRIVATE
            | MapFlags::MAP_ANONYMOUS
            | match fixed_address_behavior {
                FixedAddressBehavior::Hint(_) => MapFlags::empty(),
                FixedAddressBehavior::Replace => MapFlags::MAP_FIXED,
                FixedAddressBehavior::NoReplace => MapFlags::MAP_FIXED_NOREPLACE,
            }
            | if can_grow_down {
                MapFlags::MAP_GROWSDOWN
            } else {
                MapFlags::empty()
            }
            | if populate_pages_immediately {
                MapFlags::MAP_POPULATE
            } else {
                MapFlags::empty()
            };
        let r = unsafe {
            syscalls::syscall6(
                {
                    #[cfg(target_arch = "x86_64")]
                    {
                        syscalls::Sysno::mmap
                    }
                },
                suggested_range.start,
                suggested_range.len(),
                prot_flags(initial_permissions)
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                flags.bits().reinterpret_as_unsigned() as usize,
                usize::MAX,
                0,
            )
        };
        let ptr = r.map_err(|err| match err {
            syscalls::Errno::ENOMEM => litebox::platform::page_mgmt::AllocationError::OutOfMemory,
            syscalls::Errno::EEXIST => {
                assert!(matches!(
                    fixed_address_behavior,
                    FixedAddressBehavior::NoReplace
                ));
                litebox::platform::page_mgmt::AllocationError::AddressInUse
            }
            _ => panic!("unhandled mmap error {err}"),
        })?;
        if fixed_address_behavior == FixedAddressBehavior::Replace {
            replaced_reservations().for_each(drop);
        }
        // SAFETY: mmap returned exclusive ownership of this exact aligned extent.
        Ok(unsafe { LinuxUserlandReservation::new(ptr..ptr + suggested_range.len()) })
    }

    unsafe fn decommit_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError>
    where
        Reservations: Iterator<Item = &'reservation LinuxUserlandReservation<ALIGN>>,
        LinuxUserlandReservation<ALIGN>: 'reservation,
    {
        // SAFETY: The caller owns these pages and excludes all users of the decommitted range.
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::mprotect,
                range.start,
                range.len(),
                ProtFlags::PROT_NONE.bits().reinterpret_as_unsigned() as usize,
            )
        }
        .expect("mprotect failed while decommitting pages");
        // TODO: MADV_DONTNEED restores file contents for private file mappings instead of zeroing;
        // decommit is currently only used by the Windows shim, which lacks native file mappings.
        // SAFETY: The range is owned and inaccessible; discard its backing.
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::madvise,
                range.start,
                range.len(),
                libc::MADV_DONTNEED as usize,
            )
        }
        .expect("madvise failed while decommitting pages");
        Ok(())
    }

    unsafe fn release_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let _ = unsafe { syscalls::syscall2(syscalls::Sysno::munmap, range.start, range.len()) }
            .expect("munmap failed");
        Ok(())
    }

    unsafe fn try_remap_pages<Reservations>(
        &self,
        source_reservations: impl FnOnce() -> Reservations,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
        _permissions: MemoryRegionPermissions,
    ) -> Result<
        litebox::platform::page_mgmt::ReservationOf<Self, ALIGN>,
        litebox::platform::page_mgmt::RemapError,
    >
    where
        Reservations: Iterator<Item = litebox::platform::page_mgmt::ReservationOf<Self, ALIGN>>,
    {
        let res = unsafe {
            syscalls::syscall5(
                syscalls::Sysno::mremap,
                old_range.start,
                old_range.len(),
                new_range.len(),
                MRemapFlags::MREMAP_MAYMOVE.bits() as usize,
                new_range.start,
            )
            .expect("mremap failed")
        };
        source_reservations().for_each(drop);
        // SAFETY: Successful mremap transferred ownership to this destination extent.
        Ok(unsafe { LinuxUserlandReservation::new(res..res + new_range.len()) })
    }

    unsafe fn protect_pages<'reservation, Reservations>(
        &self,
        _covering_reservations: impl FnOnce() -> Reservations,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError>
    where
        Reservations:
            Iterator<Item = &'reservation litebox::platform::page_mgmt::ReservationOf<Self, ALIGN>>,
        litebox::platform::page_mgmt::ReservationOf<Self, ALIGN>: 'reservation,
    {
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::mprotect,
                range.start,
                range.len(),
                prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
            )
        }
        .expect("mprotect failed");
        Ok(())
    }

    unsafe fn try_allocate_cow_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<litebox::platform::page_mgmt::ReservationOf<Self, ALIGN>, CowAllocationError>
    where
        Reservations: Iterator<Item = litebox::platform::page_mgmt::ReservationOf<Self, ALIGN>>,
    {
        let Some((file_path, file_offset)) = self.lookup_cow_region(source_data) else {
            return Err(CowAllocationError::UnsupportedSourceRegion);
        };
        if !file_offset.is_multiple_of(ALIGN) {
            return Err(CowAllocationError::Unaligned);
        }

        let file_path_cstr =
            std::ffi::CString::new(file_path.as_os_str().as_encoded_bytes()).unwrap();
        // TODO(jb): We should likely be storing pre-opened FDs, right?
        let fd = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::open,
                file_path_cstr.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        let fd = fd.expect("file should remain unchanged on host");

        let mut flags = MapFlags::MAP_PRIVATE;
        match fixed_address_behavior {
            FixedAddressBehavior::Hint(_) => {}
            FixedAddressBehavior::Replace => flags |= MapFlags::MAP_FIXED,
            FixedAddressBehavior::NoReplace => flags |= MapFlags::MAP_FIXED_NOREPLACE,
        }

        let result = unsafe {
            syscalls::syscall6(
                {
                    #[cfg(target_arch = "x86_64")]
                    {
                        syscalls::Sysno::mmap
                    }
                },
                suggested_start,
                source_data.len(),
                prot_flags(permissions).bits().reinterpret_as_unsigned() as usize,
                flags.bits().reinterpret_as_unsigned() as usize,
                fd,
                {
                    #[cfg(target_arch = "x86_64")]
                    {
                        file_offset
                    }
                },
            )
        };

        let _ = unsafe { syscalls::syscall1(syscalls::Sysno::close, fd) };

        match result {
            Ok(address) => {
                if fixed_address_behavior == FixedAddressBehavior::Replace {
                    replaced_reservations().for_each(drop);
                }
                // SAFETY: mmap returned exclusive ownership of this CoW mapping.
                Ok(unsafe { LinuxUserlandReservation::new(address..address + source_data.len()) })
            }
            Err(_) => Err(CowAllocationError::InternalFailure),
        }
    }
}
