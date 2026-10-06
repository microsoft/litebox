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

#[cfg(target_arch = "aarch64")]
fn cache_sync_permissions(permissions: MemoryRegionPermissions) -> MemoryRegionPermissions {
    (permissions | MemoryRegionPermissions::READ) & !MemoryRegionPermissions::EXEC
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
    /// With ASLR disabled the host's top-down mmap area begins just below
    /// `0x7FFF_F800_0000`; with ASLR enabled it is randomized by at most 1 TiB
    /// below that. Placing guest memory under this limit keeps it out of the
    /// host's way, so `fork` can restore the guest at the parent's addresses
    /// in a fresh runner without colliding with that runner's host mappings.
    #[cfg(target_arch = "x86_64")]
    const PLACEMENT_ADDR_MAX: usize = 0x7000_0000_0000;
    /// As on x86-64, keeps guest memory below host mappings so `fork` can restore it in a fresh
    /// runner. On 47- and 48-bit hosts, all host mappings lie above 64 TiB; on smaller ones,
    /// this limit has no effect.
    #[cfg(target_arch = "aarch64")]
    const PLACEMENT_ADDR_MAX: usize = 0x4000_0000_0000;
    /// The kernel may place a rejected hint anywhere, including inside the
    /// host's mmap area, so vmem must pick exact addresses itself.
    #[cfg(target_arch = "x86_64")]
    const HINT_PLACEMENT_BEHAVIOR: HintPlacementBehavior = HintPlacementBehavior::Unspecified;
    /// Exact `MAP_FIXED_NOREPLACE` placement would fail on hosts with fewer
    /// than 48 VA bits; see the `TASK_ADDR_MAX` note above.
    #[cfg(target_arch = "aarch64")]
    const HINT_PLACEMENT_BEHAVIOR: HintPlacementBehavior =
        HintPlacementBehavior::Directional(AllocationDirection::TopDown);

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
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
                syscalls::Sysno::mmap,
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
        Ok(UserMutPtr::from_usize(ptr))
    }

    unsafe fn release_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let _ = unsafe { syscalls::syscall2(syscalls::Sysno::munmap, range.start, range.len()) }
            .expect("munmap failed");
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        // Without `MREMAP_FIXED` the kernel ignores `new_range` and may move the pages into the
        // host's mmap area. `MREMAP_FIXED` replaces whatever is mapped at the destination, and the
        // host may hold mappings vmem does not know about, so claim the destination first.
        //
        // The claim also provides the grown tail, so only the old pages move: growing them would
        // extend pages that a fork restore mapped from its process image into the image's
        // following bytes instead of fresh zeroed pages.
        let (flags, moved_len) = {
            <Self as litebox::platform::PageManagementProvider<ALIGN>>::allocate_pages(
                self,
                new_range.clone(),
                // Shared anonymous memory is private on the host, as in `allocate_pages`.
                permissions - MemoryRegionPermissions::SHARED,
                false,
                false,
                FixedAddressBehavior::NoReplace,
            )
            .map_err(|error| match error {
                // A host mapping vmem does not know about holds the destination; the caller's
                // copy places the pages elsewhere instead.
                litebox::platform::page_mgmt::AllocationError::AddressInUse => {
                    litebox::platform::page_mgmt::RemapError::UnsupportedByPlatform
                }
                // Hosts with fewer than 48 VA bits may refuse vmem's destination; copy instead.
                #[cfg(target_arch = "aarch64")]
                litebox::platform::page_mgmt::AllocationError::OutOfMemory => {
                    litebox::platform::page_mgmt::RemapError::UnsupportedByPlatform
                }
                _ => litebox::platform::page_mgmt::RemapError::OutOfMemory,
            })?;
            (
                MRemapFlags::MREMAP_MAYMOVE | MRemapFlags::MREMAP_FIXED,
                old_range.len(),
            )
        };
        let res = unsafe {
            syscalls::syscall5(
                syscalls::Sysno::mremap,
                old_range.start,
                old_range.len(),
                moved_len,
                flags.bits() as usize,
                new_range.start,
            )
        };
        // A moved range's pages and its claimed tail stay separate host mappings, and kernels
        // before 6.17 cannot move more than one mapping at once. Release the claim, which the
        // kernel may already have unmapped, and let the caller copy instead. Later kernels can
        // move several mappings but may stop partway when the host runs out of memory or
        // mappings; the moved pages are then released with the claim, and the caller's copy
        // panics on the missing source.
        let res = res.map_err(|_| {
            // SAFETY: vmem reserved `new_range` for this move, so only the claim made above and
            // any source pages a partial move placed in it can be unmapped.
            let _ = unsafe {
                syscalls::syscall2(syscalls::Sysno::munmap, new_range.start, new_range.len())
            }
            .expect("munmap failed");
            litebox::platform::page_mgmt::RemapError::UnsupportedByPlatform
        })?;
        Ok(UserMutPtr::from_usize(res))
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::mprotect,
                range.start,
                range.len(),
                prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
            )
        }
        .expect("mprotect failed");

        #[cfg(target_arch = "aarch64")]
        {
            // Cache maintenance needs read permission. Keep execute disabled until
            // the new instructions are visible to the fetch path.
            //
            // TODO: only a W->X transition needs this; `update_permissions` is not
            // told the old permissions, so every transition to X pays for it.
            // Revisit when the trait passes the old permissions.
            let syncing = new_permissions.contains(MemoryRegionPermissions::EXEC);
            let mapped_permissions = if syncing {
                cache_sync_permissions(new_permissions)
            } else {
                new_permissions
            };

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
            .expect("mprotect failed");
            if syncing {
                sync_instruction_stream(range.clone());
                if mapped_permissions != new_permissions {
                    unsafe {
                        syscalls::syscall3(
                            syscalls::Sysno::mprotect,
                            range.start,
                            range.len(),
                            prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
                        )
                    }
                    .expect("mprotect failed");
                }
            }
        }
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.reserved_pages.iter()
    }

    /// Asks the host to back `range` with transparent huge pages, each of which takes one
    /// fault and one clear instead of one per base page. This is best-effort: the host may
    /// have them disabled, or another thread may have unmapped the range.
    fn advise_fill(&self, range: core::ops::Range<usize>) {
        // SAFETY: `MADV_HUGEPAGE` changes how the host backs `range`, never what it contains.
        let _ = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::madvise,
                range.start,
                range.len(),
                libc::MADV_HUGEPAGE.reinterpret_as_unsigned() as usize,
            )
        };
    }

    fn try_allocate_cow_pages(
        &self,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, CowAllocationError> {
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
            FixedAddressBehavior::Hint(_) => {}
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

        match result {
            Ok(ptr) => Ok(UserMutPtr::from_usize(ptr)),
            Err(_) => Err(CowAllocationError::InternalFailure),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::PageManagementProvider;

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn cache_sync_permissions_are_readable_and_non_executable() {
        let final_permissions = MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC;
        let sync_permissions = cache_sync_permissions(final_permissions);

        assert!(sync_permissions.contains(MemoryRegionPermissions::READ));
        assert!(!sync_permissions.contains(MemoryRegionPermissions::EXEC));
        assert!(final_permissions.contains(MemoryRegionPermissions::EXEC));
    }

    #[test]
    fn test_reserved_pages() {
        let platform = LinuxUserland::new();
        let reserved_pages: Vec<_> =
            <LinuxUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

        // Check that the reserved pages are in order and non-overlapping
        let mut prev = 0;
        for page in reserved_pages {
            assert!(page.start >= prev);
            assert!(page.end > page.start);
            prev = page.end;
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn moving_growth_of_file_pages_adds_zeroed_pages() {
        const PAGE: usize = 4096;
        let platform = LinuxUserland::new();
        let read_write = libc::PROT_READ | libc::PROT_WRITE;
        // SAFETY: The name is a valid C string.
        let fd = unsafe { libc::memfd_create(c"remap".as_ptr(), 0) };
        assert!(fd >= 0);
        let contents: Vec<u8> = [0xa5; PAGE].into_iter().chain([0x5a; PAGE]).collect();
        // SAFETY: `contents` is valid for its length.
        let written = unsafe { libc::write(fd, contents.as_ptr().cast(), contents.len()) };
        assert_eq!(written, isize::try_from(contents.len()).unwrap());
        // SAFETY: A private mapping of the descriptor's first page replaces nothing.
        let old = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                PAGE,
                read_write,
                libc::MAP_PRIVATE,
                fd,
                0,
            )
        };
        assert_ne!(old, libc::MAP_FAILED);
        // Find a free destination by mapping and releasing it.
        // SAFETY: Anonymous mappings replace nothing, and nothing uses the released one.
        let new = unsafe {
            let new = libc::mmap(
                core::ptr::null_mut(),
                2 * PAGE,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(new, libc::MAP_FAILED);
            assert_eq!(libc::munmap(new, 2 * PAGE), 0);
            new as usize
        };
        let old = old as usize;

        // SAFETY: Nothing else uses the old page, and the destination is free.
        let moved = unsafe {
            <LinuxUserland as PageManagementProvider<PAGE>>::remap_pages(
                platform,
                old..old + PAGE,
                new..new + 2 * PAGE,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )
        }
        .unwrap();

        assert_eq!(moved.as_usize(), new);
        // SAFETY: The remap left both pages mapped readable and writable.
        let pages = unsafe { core::slice::from_raw_parts_mut(new as *mut u8, 2 * PAGE) };
        assert!(pages[..PAGE].iter().all(|&byte| byte == 0xa5));
        assert!(pages[PAGE..].iter().all(|&byte| byte == 0));
        pages[PAGE] = 1;
        // SAFETY: Nothing uses the pages or the descriptor anymore.
        unsafe {
            assert_eq!(libc::munmap(new as *mut libc::c_void, 2 * PAGE), 0);
            assert_eq!(libc::close(fd), 0);
        }
    }
}
