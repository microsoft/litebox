//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.

use litebox::{
    mm::linux::{
        CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, PAGE_SIZE, VmemUnmapError,
    },
    platform::{RawConstPointer, RawMutPointer, page_mgmt::DeallocationError},
};
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, errno::Errno};

use crate::{MutPtr, litebox_page_manager};

const PAGE_MASK: usize = !(PAGE_SIZE - 1);
const PAGE_SHIFT: usize = PAGE_SIZE.trailing_zeros() as usize;

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

fn do_mmap_file(
    suggested_addr: Option<usize>,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
    fd: i32,
    offset: usize,
) -> Result<MutPtr<u8>, MappingError> {
    let op = |ptr: MutPtr<u8>| -> Result<usize, MappingError> {
        // Note a malicious user may unmap ptr while we are reading.
        // `sys_read` does not handle page faults, so we need to use a
        // temporary buffer to read the data from fs (without worrying page
        // faults) and write it to the user buffer with page fault handling.
        let mut file_offset = offset;
        let mut buffer = [0; PAGE_SIZE];
        let mut copied = 0;
        while copied < len {
            let size = crate::syscalls::file::sys_read(fd, &mut buffer, Some(file_offset))
                .map_err(|e| match e {
                    Errno::EBADF => MappingError::BadFD(fd),
                    Errno::EISDIR => MappingError::NotAFile,
                    Errno::EACCES => MappingError::NotForReading,
                    _ => unimplemented!(),
                })?;
            if size == 0 {
                break;
            }
            // TODO: implement [`memcpy`](https://elixir.bootlin.com/linux/v5.19.17/source/arch/x86/lib/memcpy_64.S#L30)
            // to return EFAULT if the user buffer is not valid
            ptr.copy_from_slice(copied, &buffer[..size]).unwrap();
            copied += size;
            file_offset += size;
        }
        Ok(copied)
    };
    let fixed_addr = flags.contains(MapFlags::MAP_FIXED);
    do_mmap(
        suggested_addr,
        len,
        prot,
        flags,
        // Note we need to ensure that the space after the mapping is available
        // so that we could load trampoline code right after the mapping.
        offset == 0 && !fixed_addr,
        op,
    )
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
        do_mmap_file(suggested_addr, aligned_len, prot, flags, fd, offset)
    }
    .map_err(Errno::from)
}

/// Handle syscall `munmap`
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

pub(crate) fn sys_mremap(
    old_addr: crate::MutPtr<u8>,
    old_size: usize,
    new_size: usize,
    flags: MRemapFlags,
    new_addr: usize,
) -> Result<crate::MutPtr<u8>, Errno> {
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

    let pm = litebox_page_manager();
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

/// Handle syscall `brk`
pub(crate) fn sys_brk(addr: MutPtr<u8>) -> Result<usize, Errno> {
    let pm = litebox_page_manager();
    unsafe { pm.brk(addr.as_usize()) }.map_err(Errno::from)
}

/// Handle syscall `madvise`
pub(crate) fn sys_madvise(
    addr: MutPtr<u8>,
    len: usize,
    advice: litebox_common_linux::MadviseBehavior,
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
    let Some(end) = addr.as_usize().checked_add(aligned_len) else {
        return Err(Errno::EINVAL);
    };

    match advice {
        litebox_common_linux::MadviseBehavior::Normal
        | litebox_common_linux::MadviseBehavior::DontFork
        | litebox_common_linux::MadviseBehavior::DoFork => {
            // No-op for now, as we don't support fork yet.
            Ok(())
        }
        litebox_common_linux::MadviseBehavior::DontNeed => {
            // After a successful MADV_DONTNEED operation, the semantics of memory access in the specified region are changed:
            // subsequent accesses of pages in the range will succeed, but will result in either repopulating the memory contents
            // from the up-to-date contents of the underlying mapped file (for shared file mappings, shared anonymous mappings,
            // and shmem-based techniques such as System V shared memory segments) or zero-fill-on-demand pages for anonymous private mappings.
            //
            // Note we do not support shared memory yet, so this is just to discard the pages without removing the mapping.
            unsafe { litebox_page_manager().reset_pages(addr, len) }.map_err(Errno::from)
        }
        _ => unimplemented!("unsupported madvise behavior"),
    }
}

#[cfg(test)]
mod tests {
    use litebox::{
        fs::{Mode, OFlags},
        platform::{RawConstPointer, RawMutPointer},
    };
    use litebox_common_linux::{MapFlags, ProtFlags};

    use crate::syscalls::{
        file::{sys_close, sys_open, sys_write},
        mm::sys_munmap,
        tests::init_platform,
    };

    use super::{sys_madvise, sys_mmap};

    #[test]
    fn test_anonymous_mmap() {
        init_platform(None);

        let addr = sys_mmap(
            0,
            0x2000,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
            -1,
            0,
        )
        .unwrap();
        unsafe {
            addr.mutate_subslice_with(..0x2000, |buf| {
                buf.fill(0xff);
            })
            .unwrap();
        };
        assert_eq!(
            unsafe { addr.read_at_offset(0x1000) }.unwrap().into_owned(),
            0xff,
        );
        sys_munmap(addr, 0x2000).unwrap();
    }

    #[test]
    fn test_file_backed_mmap() {
        init_platform(None);

        let content = b"Hello, world!";
        let fd = sys_open("test.txt", OFlags::RDWR | OFlags::CREAT, Mode::RWXU).unwrap();
        let fd = i32::try_from(fd).unwrap();
        assert_eq!(sys_write(fd, content, None).unwrap(), content.len());
        let addr = sys_mmap(
            0,
            0x1000,
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE,
            fd,
            0,
        )
        .unwrap();
        assert_eq!(
            unsafe { addr.to_cow_slice(content.len()).unwrap() },
            content.as_slice(),
        );
        sys_munmap(addr, 0x1000).unwrap();
        sys_close(fd).unwrap();
    }

    // `mremap` is not implemented for freebsd yet.
    #[cfg(not(feature = "platform_freebsd_userland"))]
    #[test]
    fn test_mremap() {
        init_platform(None);

        let addr = sys_mmap(
            0,
            0x2000,
            ProtFlags::PROT_READ,
            MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
            -1,
            0,
        )
        .unwrap();

        assert!(matches!(
            super::sys_mremap(
                addr,
                0x1000,
                0x2000,
                litebox_common_linux::MRemapFlags::empty(),
                0
            ),
            Err(litebox_common_linux::errno::Errno::ENOMEM)
        ),);
        let new_addr = super::sys_mremap(
            addr,
            0x1000,
            0x2000,
            litebox_common_linux::MRemapFlags::MREMAP_MAYMOVE,
            0,
        )
        .unwrap();
        sys_munmap(addr, 0x2000).unwrap();
        sys_munmap(new_addr, 0x2000).unwrap();
    }

    #[test]
    fn test_madvise() {
        init_platform(None);

        let addr = sys_mmap(
            0,
            0x2000,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
            -1,
            0,
        )
        .unwrap();

        addr.mutate_subslice_with(..0x10, |buf| {
            buf.fill(0xff);
        })
        .unwrap();

        // Test MADV_NORMAL
        assert!(sys_madvise(addr, 0x2000, litebox_common_linux::MadviseBehavior::Normal).is_ok());

        // Test MADV_DONTNEED
        assert!(
            sys_madvise(
                addr,
                0x2000,
                litebox_common_linux::MadviseBehavior::DontNeed
            )
            .is_ok()
        );

        unsafe {
            addr.to_cow_slice(0x10).unwrap().iter().for_each(|&x| {
                assert_eq!(x, 0); // Should be zeroed after MADV_DONTNEED
            });
        }

        sys_munmap(addr, 0x2000).unwrap();
    }
}
