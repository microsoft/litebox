use litebox::{
    mm::linux::{MappingError, PAGE_SIZE},
    platform::RawMutPointer,
};
use litebox_common_linux::{MapFlags, ProtFlags, errno::Errno};

use crate::{MutPtr, litebox_page_manager};

const PAGE_MASK: usize = !(PAGE_SIZE - 1);
const PAGE_SHIFT: usize = PAGE_SIZE.trailing_zeros() as usize;

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

fn do_mmap(
    addr: Option<usize>,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
    op: impl FnOnce(MutPtr<u8>) -> Result<usize, MappingError>,
) -> Result<MutPtr<u8>, MappingError> {
    let fixed_addr = flags.contains(MapFlags::MAP_FIXED);
    let suggested_addr = addr.unwrap_or(0);
    let pm = litebox_page_manager();
    match prot {
        ProtFlags::PROT_READ_EXEC => unsafe {
            pm.create_executable_pages(suggested_addr, len, fixed_addr, op)
        },
        ProtFlags::PROT_READ_WRITE => unsafe {
            pm.create_writable_pages(suggested_addr, len, fixed_addr, op)
        },
        ProtFlags::PROT_READ => unsafe {
            pm.create_readable_pages(suggested_addr, len, fixed_addr, op)
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
    do_mmap(suggested_addr, len, prot, flags, op)
}

fn do_mmap_file(
    suggested_addr: Option<usize>,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
    fd: i32,
    offset: usize,
) -> Result<MutPtr<u8>, MappingError> {
    let fixed_addr = flags.contains(MapFlags::MAP_FIXED);
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
            let start = isize::try_from(copied).unwrap();
            ptr.mutate_subslice_with(
                start..start.checked_add_unsigned(size).unwrap(),
                |user_buf| {
                    // TODO: implement [`memcpy`](https://elixir.bootlin.com/linux/v5.19.17/source/arch/x86/lib/memcpy_64.S#L30)
                    // to return EFAULT if the user buffer is not valid
                    user_buf.copy_from_slice(&buffer[..size]);
                },
            )
            .unwrap();
            copied += size;
            file_offset += size;
        }
        Ok(copied)
    };
    do_mmap(suggested_addr, len, prot, flags, op)
}

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
            | MapFlags::MAP_NORESERVE
            | MapFlags::MAP_POPULATE
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
