//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.

use litebox::{
    mm::linux::{
        CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, PAGE_SIZE, VmemUnmapError,
    },
    platform::{RawConstPointer, RawMutPointer, page_mgmt::DeallocationError},
};
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, errno::Errno};

use crate::{MutPtr, litebox_page_manager};

/// `litebox_shim_optee` memory management
/// OP-TEE OS does have `ldelf_*` syscalls for memory management, but they are for LDELF (an ELF loader) not TAs.
/// These syscalls are not exposed to TAs. Further, LiteBox uses its own ELF loader.
/// To this end, we don't need to implement `ldelf_*` syscalls for memory management and, instead, can use
/// existing Linux kernel-style `mmap*` syscalls (or kernel functions because they are not exposed to the user space).
/// For now, `litebox_shim_optee` only needs `mmap`, `munmap`, and `mprotect` syscalls.

const PAGE_MASK: usize = !(PAGE_SIZE - 1);

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

fn do_mmap(
    suggested_addr: Option<usize>,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
    ensure_space_after: bool,
    op: impl FnOnce(MutPtr<u8>) -> Result<usize, MappingError>,
) -> Result<MutPtr<u8>, MappingError> {
    let flags = {
        let mut create_flags = CreatePagesFlags::empty();
        create_flags.set(
            CreatePagesFlags::FIXED_ADDR,
            flags.contains(MapFlags::MAP_FIXED),
        );
        create_flags.set(
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            flags.contains(MapFlags::MAP_POPULATE),
        );
        create_flags.set(CreatePagesFlags::ENSURE_SPACE_AFTER, ensure_space_after);
        create_flags.set(
            CreatePagesFlags::MAP_FILE,
            !flags.contains(MapFlags::MAP_ANONYMOUS),
        );
        create_flags
    };
    let suggested_addr = match suggested_addr {
        Some(addr) => Some(NonZeroAddress::new(addr).ok_or(MappingError::UnAligned)?),
        None => None,
    };
    let length = NonZeroPageSize::new(len).ok_or(MappingError::UnAligned)?;
    let pm = litebox_page_manager();
    match prot {
        ProtFlags::PROT_READ_EXEC => unsafe {
            pm.create_executable_pages(suggested_addr, length, flags, op)
        },
        ProtFlags::PROT_READ_WRITE => unsafe {
            pm.create_writable_pages(suggested_addr, length, flags, op)
        },
        ProtFlags::PROT_READ => unsafe {
            pm.create_readable_pages(suggested_addr, length, flags, op)
        },
        ProtFlags::PROT_NONE => unsafe {
            pm.create_inaccessible_pages(suggested_addr, length, flags, op)
        },
        _ => todo!("Unsupported prot flags {:?}", prot),
    }
}

fn do_mmap_anonymous(
    suggested_addr: Option<usize>,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
) -> Result<MutPtr<u8>, MappingError> {
    let op = |_| Ok(0);
    do_mmap(suggested_addr, len, prot, flags, false, op)
}

/// Handle syscall `mmap`
pub(crate) fn sys_mmap(
    addr: usize,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
    fd: i32,
    offset: usize,
) -> Result<MutPtr<u8>, Errno> {
    // check alignment
    if offset & !PAGE_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if addr & !PAGE_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
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
#[expect(dead_code)]
pub(crate) fn sys_munmap(addr: crate::MutPtr<u8>, len: usize) -> Result<(), Errno> {
    if addr.as_usize() & !PAGE_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Err(Errno::EINVAL);
    }
    let aligned_len = align_up(len, PAGE_SIZE);
    if addr.as_usize().checked_add(aligned_len).is_none() {
        return Err(Errno::EINVAL);
    }

    let pm = litebox_page_manager();
    match unsafe { pm.remove_pages(addr, aligned_len) } {
        Err(VmemUnmapError::UnAligned) => Err(Errno::EINVAL),
        Err(VmemUnmapError::UnmapError(e)) => match e {
            DeallocationError::Unaligned => Err(Errno::EINVAL),
            // It is not an error if the indicated range does not contain any mapped pages.
            DeallocationError::AlreadyUnallocated => Ok(()),
            _ => unimplemented!(),
        },
        Ok(()) => Ok(()),
    }
}

/// Handle syscall `mprotect`
pub(crate) fn sys_mprotect(
    addr: crate::MutPtr<u8>,
    len: usize,
    prot: ProtFlags,
) -> Result<(), Errno> {
    if addr.as_usize() & !PAGE_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(());
    }

    let pm = litebox_page_manager();
    match prot {
        ProtFlags::PROT_READ_EXEC => unsafe { pm.make_pages_executable(addr, len) },
        ProtFlags::PROT_READ_WRITE => unsafe { pm.make_pages_writable(addr, len) },
        ProtFlags::PROT_READ => unsafe { pm.make_pages_readable(addr, len) },
        ProtFlags::PROT_NONE => unsafe { pm.make_pages_inaccessible(addr, len) },
        ProtFlags::PROT_READ_WRITE_EXEC => unsafe { pm.make_pages_rwx(addr, len) },
        _ => todo!("Unsupported prot flags {:?}", prot),
    }
    .map_err(Errno::from)
}
