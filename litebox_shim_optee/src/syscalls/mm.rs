// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.

use litebox::mm::linux::{MappingError, PAGE_SIZE};
use litebox::platform::RawConstPointer;
use litebox_common_linux::{MapFlags, ProtFlags, errno::Errno, user_pointers::UserPtrMut};

use crate::{Task, UserMutPtr};

/// Bridge a platform mutable pointer to the address-only `UserPtrMut` used by
/// the shared `litebox_common_linux::mm` helpers.
fn to_local(ptr: UserMutPtr<u8>) -> UserPtrMut<u8> {
    UserPtrMut::from_usize(ptr.as_usize())
}

/// Bridge an address-only `UserPtrMut` back to a platform mutable pointer.
fn from_local(ptr: UserPtrMut<u8>) -> UserMutPtr<u8> {
    <UserMutPtr<u8> as RawConstPointer<u8>>::from_usize(ptr.as_usize())
}

#[inline]
fn align_up(addr: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two());
    addr.checked_next_multiple_of(align)
}

impl Task {
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
        .map(from_local)
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

        let suggested_addr = if addr == 0 { None } else { Some(addr) };
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
        litebox_common_linux::mm::sys_munmap(pm, to_local(addr), len)
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
        litebox_common_linux::mm::sys_mprotect(pm, to_local(addr), len, prot)
    }
}
