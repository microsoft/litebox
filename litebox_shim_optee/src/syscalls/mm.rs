// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.

use litebox::mm::linux::{MappingError, PAGE_SIZE, VmFlags};
use litebox::platform::page_mgmt::PageManagementProvider;
use litebox_common_linux::{MapFlags, ProtFlags, errno::Errno, user_pointers::UserPtrMut};

use crate::{Platform, Task, UserMutPtr};

// Keep bottom-up placement consistent with LiteBox's private Vmem stack policy.
const STACK_GUARD_GAP: usize = 256 << 12;

#[inline]
fn align_up(addr: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two());
    addr.checked_next_multiple_of(align)
}

impl Task {
    /// Finds the first address-space gap from low to high.
    ///
    /// OP-TEE chooses user VAs bottom-up. Matching that order matters because
    /// `ldelf`'s sequential segment allocations with padding rely on it, while
    /// LiteBox's `get_unmmaped_area` searches for free VAs top-down by default.
    fn find_bottom_up_gap(&self, len: usize) -> Option<usize> {
        debug_assert!(len.is_multiple_of(PAGE_SIZE));
        let task_addr_min = <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN;
        let task_addr_max = <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX;
        let mut candidate = task_addr_min..task_addr_min.checked_add(len)?;
        if candidate.end > task_addr_max {
            return None;
        }
        // `PageManager::mappings()` returns mappings ordered by ascending start address.
        for (range, flags) in self.global.pm.mappings() {
            let protected_range = if flags.contains(VmFlags::VM_GROWSDOWN) {
                range.start.saturating_sub(STACK_GUARD_GAP << 1)
            } else {
                range.start
            }..range.end;
            if candidate.end <= protected_range.start {
                return Some(candidate.start);
            }
            if candidate.start < protected_range.end {
                candidate = protected_range.end..protected_range.end.checked_add(len)?;
                if candidate.end > task_addr_max {
                    return None;
                }
            }
        }
        Some(candidate.start)
    }

    #[inline]
    fn do_mmap_anonymous(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<UserMutPtr<u8>, MappingError> {
        let op = |_| Ok(0);
        litebox_common_linux::mm::do_mmap(
            &self.global.pm,
            suggested_addr,
            len,
            prot,
            flags,
            false,
            op,
        )
        .map(UserPtrMut::to_platform_ptr::<Platform>)
    }

    /// Handle syscall `mmap`
    pub(crate) fn sys_mmap(
        &self,
        addr: usize,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        _fd: i32,
        offset: usize,
    ) -> Result<UserMutPtr<u8>, Errno> {
        // check alignment
        if !offset.is_multiple_of(PAGE_SIZE) || !addr.is_multiple_of(PAGE_SIZE) || len == 0 {
            return Err(Errno::EINVAL);
        }
        if flags.intersects(
            MapFlags::MAP_SHARED
                | MapFlags::MAP_32BIT
                | MapFlags::MAP_GROWSDOWN
                | MapFlags::MAP_LOCKED
                | MapFlags::MAP_NONBLOCK
                | MapFlags::MAP_SYNC
                | MapFlags::MAP_HUGETLB
                | MapFlags::MAP_HUGE_2MB
                | MapFlags::MAP_HUGE_1GB,
        ) {
            #[cfg(debug_assertions)]
            todo!("Unsupported flags {:?}", flags);
            #[cfg(not(debug_assertions))]
            return Err(Errno::EINVAL);
        }

        let aligned_len = align_up(len, PAGE_SIZE).ok_or(Errno::ENOMEM)?;
        if aligned_len == 0 {
            return Err(Errno::ENOMEM);
        }
        if offset.checked_add(aligned_len).is_none() {
            return Err(Errno::EOVERFLOW);
        }

        let (suggested_addr, flags) = if addr == 0
            && !flags.intersects(MapFlags::MAP_FIXED | MapFlags::MAP_FIXED_NOREPLACE)
        {
            debug_assert_ne!(
                <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN,
                0,
                "sys_mmap treats address zero as no hint"
            );
            // The mapping snapshot and fixed-address claim are separate operations.
            // Since OP-TEE OS doesn't support multithreading and we serialize each TA
            // instance's execution, this address space cannot change between them.
            // We can use a bounded retry loop for the search and claim on EEXIST
            // if we need to consider multithreaded TAs in the future.
            (
                Some(self.find_bottom_up_gap(aligned_len).ok_or(Errno::ENOMEM)?),
                flags | MapFlags::MAP_FIXED_NOREPLACE,
            )
        } else if addr == 0 {
            (None, flags)
        } else {
            (Some(addr), flags)
        };
        let result = if flags.contains(MapFlags::MAP_ANONYMOUS) {
            self.do_mmap_anonymous(suggested_addr, aligned_len, prot, flags)
        } else {
            #[cfg(debug_assertions)]
            {
                panic!("we don't support file-backed mmap");
            }

            #[cfg(not(debug_assertions))]
            return Err(Errno::EINVAL);
        };
        result.map_err(Errno::from)
    }

    /// Handle syscall `munmap`
    pub(crate) fn sys_munmap(&self, addr: UserMutPtr<u8>, len: usize) -> Result<(), Errno> {
        let pm = &self.global.pm;
        litebox_common_linux::mm::sys_munmap(
            pm,
            UserPtrMut::from_platform_ptr::<Platform>(addr),
            len,
        )
    }

    /// Handle syscall `mprotect`
    #[inline]
    pub(crate) fn sys_mprotect(
        &self,
        addr: UserMutPtr<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        let pm = &self.global.pm;
        litebox_common_linux::mm::sys_mprotect(
            pm,
            UserPtrMut::from_platform_ptr::<Platform>(addr),
            len,
            prot,
        )
    }
}
