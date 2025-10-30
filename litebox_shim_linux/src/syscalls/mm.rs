//! Implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.
//! Most of these syscalls which are not backed by files are implemented in [`litebox_common_linux::mm`].

use litebox::{
    mm::linux::{MappingError, PAGE_SIZE},
    platform::RawMutPointer,
};
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, errno::Errno};

use crate::{MutPtr, litebox_page_manager};

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

#[inline]
fn do_mmap(
    suggested_addr: Option<usize>,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
    ensure_space_after: bool,
    op: impl FnOnce(MutPtr<u8>) -> Result<usize, MappingError>,
) -> Result<MutPtr<u8>, MappingError> {
    litebox_common_linux::mm::do_mmap(
        litebox_page_manager(),
        suggested_addr,
        len,
        prot,
        flags,
        ensure_space_after,
        op,
    )
}

#[inline]
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
        do_mmap_file(suggested_addr, aligned_len, prot, flags, fd, offset)
    }
    .map_err(Errno::from)
}

/// Handle syscall `munmap`
#[inline]
pub(crate) fn sys_munmap(addr: crate::MutPtr<u8>, len: usize) -> Result<(), Errno> {
    litebox_common_linux::mm::sys_munmap(litebox_page_manager(), addr, len)
}

/// Handle syscall `mprotect`
#[inline]
pub(crate) fn sys_mprotect(
    addr: crate::MutPtr<u8>,
    len: usize,
    prot: ProtFlags,
) -> Result<(), Errno> {
    litebox_common_linux::mm::sys_mprotect(litebox_page_manager(), addr, len, prot)
}

#[inline]
pub(crate) fn sys_mremap(
    old_addr: crate::MutPtr<u8>,
    old_size: usize,
    new_size: usize,
    flags: MRemapFlags,
    new_addr: usize,
) -> Result<crate::MutPtr<u8>, Errno> {
    litebox_common_linux::mm::sys_mremap(
        litebox_page_manager(),
        old_addr,
        old_size,
        new_size,
        flags,
        new_addr,
    )
}

/// Handle syscall `brk`
#[inline]
pub(crate) fn sys_brk(addr: MutPtr<u8>) -> Result<usize, Errno> {
    litebox_common_linux::mm::sys_brk(litebox_page_manager(), addr)
}

/// Handle syscall `madvise`
#[inline]
pub(crate) fn sys_madvise(
    addr: MutPtr<u8>,
    len: usize,
    advice: litebox_common_linux::MadviseBehavior,
) -> Result<(), Errno> {
    litebox_common_linux::mm::sys_madvise(litebox_page_manager(), addr, len, advice)
}

#[cfg(test)]
mod tests {
    use litebox::{
        fs::{Mode, OFlags},
        platform::{PageManagementProvider, RawConstPointer, RawMutPointer},
    };
    use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, errno::Errno};

    use crate::syscalls::{
        file::{sys_close, sys_open, sys_write},
        mm::{sys_mremap, sys_munmap},
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

    // `mremap` is not implemented for windows yet.
    #[cfg(not(any(feature = "platform_windows_userland")))]
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
    fn test_collision_with_global_allocator() {
        init_platform(None);
        let platform = litebox_platform_multiplex::platform();
        let mut data = alloc::vec::Vec::new();
        // Find an address that is allocated to the global allocator but not in reserved regions.
        // LiteBox's page manager is not aware of the global allocator's allocations.
        let addr = loop {
            let buf = alloc::vec::Vec::<u8>::with_capacity(0x10_0000);
            let addr = buf.as_ptr() as usize;
            data.push(buf);

            let mut included = false;
            for r in <litebox_platform_multiplex::Platform as PageManagementProvider<4096>>::reserved_pages(platform) {
                if r.contains(&addr) {
                    included = true;
                    break;
                }
            }

            if !included {
                // Also ensure that [addr - 0x1000, addr) is available, which is needed in the test below.
                if let Ok(ptr) = sys_mmap(
                    addr - 0x1000,
                    0x1000,
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
                    -1,
                    0,
                ) {
                    if ptr.as_usize() != addr - 0x1000 {
                        sys_munmap(ptr, 0x1000).unwrap();
                        continue;
                    }
                    break addr;
                }
            }
        };

        // mmap with the found address should still succeed but not at the exact address.
        let res = sys_mmap(
            addr,
            0x1000,
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
            -1,
            0,
        )
        .unwrap();
        assert_ne!(res.as_usize(), 0);
        assert_ne!(res.as_usize(), addr);

        // grow the mapping without MREMAP_MAYMOVE should fail as the new region collides with the global allocator
        let err = sys_mremap(
            crate::MutPtr::from_usize(addr - 0x1000),
            0x1000,
            0x2000,
            MRemapFlags::empty(),
            addr - 0x1000,
        )
        .unwrap_err();
        assert_eq!(err, Errno::ENOMEM);
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
