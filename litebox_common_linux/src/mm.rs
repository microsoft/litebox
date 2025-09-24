//! Common implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.

use litebox::{
    mm::linux::{
        CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, PAGE_SIZE, VmemUnmapError,
    },
    platform::{RawConstPointer, page_mgmt::DeallocationError},
};

use crate::{MRemapFlags, MapFlags, ProtFlags, errno::Errno};

const PAGE_MASK: usize = !(PAGE_SIZE - 1);

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

pub fn do_mmap<
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<{ litebox::mm::linux::PAGE_SIZE }>,
>(
    pm: &litebox::mm::PageManager<Platform, { litebox::mm::linux::PAGE_SIZE }>,
    suggested_addr: Option<usize>,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
    ensure_space_after: bool,
    op: impl FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, litebox::mm::linux::MappingError>,
) -> Result<Platform::RawMutPointer<u8>, litebox::mm::linux::MappingError> {
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

/// Handle syscall `munmap`
pub fn sys_munmap<
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<{ litebox::mm::linux::PAGE_SIZE }>,
>(
    pm: &litebox::mm::PageManager<Platform, { litebox::mm::linux::PAGE_SIZE }>,
    addr: Platform::RawMutPointer<u8>,
    len: usize,
) -> Result<(), Errno> {
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
pub fn sys_mprotect<
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<{ litebox::mm::linux::PAGE_SIZE }>,
>(
    pm: &litebox::mm::PageManager<Platform, { litebox::mm::linux::PAGE_SIZE }>,
    addr: Platform::RawMutPointer<u8>,
    len: usize,
    prot: ProtFlags,
) -> Result<(), Errno> {
    if addr.as_usize() & !PAGE_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(());
    }

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

/// Handle syscall `mremap`
pub fn sys_mremap<
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<{ litebox::mm::linux::PAGE_SIZE }>,
>(
    pm: &litebox::mm::PageManager<Platform, { litebox::mm::linux::PAGE_SIZE }>,
    old_addr: Platform::RawMutPointer<u8>,
    old_size: usize,
    new_size: usize,
    flags: MRemapFlags,
    _new_addr: usize,
) -> Result<Platform::RawMutPointer<u8>, Errno> {
    if flags.intersects(
        (MRemapFlags::MREMAP_FIXED | MRemapFlags::MREMAP_MAYMOVE | MRemapFlags::MREMAP_DONTUNMAP)
            .complement(),
    ) {
        return Err(Errno::EINVAL);
    }
    if flags.contains(MRemapFlags::MREMAP_FIXED) && !flags.contains(MRemapFlags::MREMAP_MAYMOVE) {
        return Err(Errno::EINVAL);
    }
    /*
     * MREMAP_DONTUNMAP is always a move and it does not allow resizing
     * in the process.
     */
    if flags.contains(MRemapFlags::MREMAP_DONTUNMAP)
        && (!flags.contains(MRemapFlags::MREMAP_MAYMOVE) || old_size != new_size)
    {
        return Err(Errno::EINVAL);
    }
    if old_addr.as_usize() & !PAGE_MASK != 0 {
        return Err(Errno::EINVAL);
    }

    let old_size = align_down(old_size, PAGE_SIZE);
    let new_size = align_down(new_size, PAGE_SIZE);
    if new_size == 0 {
        return Err(Errno::EINVAL);
    }

    if flags.intersects(MRemapFlags::MREMAP_FIXED | MRemapFlags::MREMAP_DONTUNMAP) {
        todo!("Unsupported flags {:?}", flags);
    }

    unsafe {
        pm.remap_pages(
            old_addr,
            old_size,
            new_size,
            flags.contains(MRemapFlags::MREMAP_MAYMOVE),
        )
    }
    .map_err(Errno::from)
}

pub fn sys_brk<
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<{ litebox::mm::linux::PAGE_SIZE }>,
>(
    pm: &litebox::mm::PageManager<Platform, { litebox::mm::linux::PAGE_SIZE }>,
    addr: Platform::RawMutPointer<u8>,
) -> Result<usize, Errno> {
    unsafe { pm.brk(addr.as_usize()) }.map_err(Errno::from)
}

pub fn sys_madvise<
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<{ litebox::mm::linux::PAGE_SIZE }>,
>(
    pm: &litebox::mm::PageManager<Platform, { litebox::mm::linux::PAGE_SIZE }>,
    addr: Platform::RawMutPointer<u8>,
    len: usize,
    advice: crate::MadviseBehavior,
) -> Result<(), Errno> {
    if addr.as_usize() & !PAGE_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(());
    }
    let aligned_len = len.next_multiple_of(PAGE_SIZE);
    if aligned_len == 0 {
        // overflow
        return Err(Errno::EINVAL);
    }
    let Some(_end) = addr.as_usize().checked_add(aligned_len) else {
        return Err(Errno::EINVAL);
    };

    match advice {
        crate::MadviseBehavior::Normal
        | crate::MadviseBehavior::DontFork
        | crate::MadviseBehavior::DoFork => {
            // No-op for now, as we don't support fork yet.
            Ok(())
        }
        crate::MadviseBehavior::DontNeed => {
            // After a successful MADV_DONTNEED operation, the semantics of memory access in the specified region are changed:
            // subsequent accesses of pages in the range will succeed, but will result in either repopulating the memory contents
            // from the up-to-date contents of the underlying mapped file (for shared file mappings, shared anonymous mappings,
            // and shmem-based techniques such as System V shared memory segments) or zero-fill-on-demand pages for anonymous private mappings.
            //
            // Note we do not support shared memory yet, so this is just to discard the pages without removing the mapping.
            unsafe { pm.reset_pages(addr, aligned_len, false) }.map_err(Errno::from)
        }
        crate::MadviseBehavior::Free => {
            unsafe { pm.reset_pages(addr, aligned_len, true) }.map_err(Errno::from)
        }
        _ => unimplemented!("Unsupported madvise behavior {:?}", advice),
    }
}
