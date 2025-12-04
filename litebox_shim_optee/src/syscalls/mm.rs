//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.

use litebox::mm::linux::{MappingError, PAGE_SIZE};
use litebox_common_linux::{MapFlags, ProtFlags, errno::Errno};

use crate::{UserMutPtr, litebox_page_manager};

// `litebox_shim_optee` memory management
// OP-TEE OS does have `ldelf_*` syscalls for memory management, but they are for LDELF (an ELF loader) not TAs.
// These syscalls are not exposed to TAs. Further, LiteBox uses its own ELF loader.
// To this end, we don't need to implement `ldelf_*` syscalls for memory management and, instead, can use
// existing Linux kernel-style `mmap*` syscalls (or kernel functions because they are not exposed to the user space).
// For now, `litebox_shim_optee` only needs `mmap`, `munmap`, and `mprotect` syscalls.

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

#[inline]
fn do_mmap_anonymous(
    suggested_addr: Option<usize>,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
) -> Result<UserMutPtr<u8>, MappingError> {
    let op = |_| Ok(0);
    litebox_common_linux::mm::do_mmap(
        litebox_page_manager(),
        suggested_addr,
        len,
        prot,
        flags,
        false,
        op,
    )
}

/// Handle syscall `mmap`
pub(crate) fn sys_mmap(
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
            | MapFlags::MAP_HUGE_1GB
            | MapFlags::MAP_FIXED_NOREPLACE,
    ) {
        todo!("Unsupported flags {:?}", flags);
    }

    let aligned_len = align_up(len, PAGE_SIZE);
    if aligned_len == 0 {
        return Err(Errno::ENOMEM);
    }
    if offset.checked_add(aligned_len).is_none() {
        return Err(Errno::EOVERFLOW);
    }

    let suggested_addr = if addr == 0 { None } else { Some(addr) };
    if flags.contains(MapFlags::MAP_ANONYMOUS) {
        do_mmap_anonymous(suggested_addr, aligned_len, prot, flags)
    } else {
        panic!("we don't support file-backed mmap");
    }
    .map_err(Errno::from)
}

/// Handle syscall `munmap`
#[allow(dead_code)]
pub(crate) fn sys_munmap(addr: UserMutPtr<u8>, len: usize) -> Result<(), Errno> {
    let pm = litebox_page_manager();
    litebox_common_linux::mm::sys_munmap(pm, addr, len)
}

/// Handle syscall `mprotect`
#[inline]
pub(crate) fn sys_mprotect(addr: UserMutPtr<u8>, len: usize, prot: ProtFlags) -> Result<(), Errno> {
    let pm = litebox_page_manager();
    litebox_common_linux::mm::sys_mprotect(pm, addr, len, prot)
}
