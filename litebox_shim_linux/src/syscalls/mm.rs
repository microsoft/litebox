use litebox::{
    mm::linux::{MappingError, PAGE_SIZE},
    platform::RawMutPointer,
};
use litebox_common_linux::errno::Errno;

use crate::{MutPtr, litebox_page_manager};

const PAGE_MASK: usize = !(PAGE_SIZE - 1);
const PAGE_SHIFT: usize = PAGE_SIZE.trailing_zeros() as usize;

bitflags::bitflags! {
    /// Desired memory protection of a memory mapping.
    #[derive(PartialEq, Debug)]
    struct ProtFlags: core::ffi::c_int {
        /// Pages cannot be accessed.
        const PROT_NONE = 0;
        /// Pages can be read.
        const PROT_READ = 1 << 0;
        /// Pages can be written.
        const PROT_WRITE = 1 << 1;
        /// Pages can be executed
        const PROT_EXEC = 1 << 2;

        const PROT_READ_EXEC = Self::PROT_READ.bits() | Self::PROT_EXEC.bits();
        const PROT_READ_WRITE = Self::PROT_READ.bits() | Self::PROT_WRITE.bits();
    }
}

bitflags::bitflags! {
    #[non_exhaustive]
    #[derive(Debug)]
    struct MapFlags: core::ffi::c_int {
        /// Changes are private
        const MAP_PRIVATE = 1 << 1;
        /// Interpret addr exactly
        const MAP_FIXED = 1 << 4;
        /// don't use a file
        const MAP_ANONYMOUS = 1 << 5;
    }
}

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
        // FIXME: ptr may be unmaped
        ptr.mutate_subslice_with(..isize::try_from(len).unwrap(), |user_buf| {
            // Loader code always runs before the program starts, so we can ensure
            // user_buf is valid (e.g., won't be unmapped).
            crate::syscalls::file::sys_read(fd, user_buf, Some(offset)).map_err(|e| match e {
                Errno::EBADF => MappingError::BadFD(fd),
                Errno::EISDIR => MappingError::NotAFile,
                Errno::EACCES => MappingError::NotForReading,
                _ => unimplemented!(),
            })
        })
        .unwrap()
    };
    do_mmap(suggested_addr, len, prot, flags, op)
}

pub(crate) fn sys_mmap(
    addr: usize,
    len: usize,
    prot: i32,
    flags: i32,
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

    let prot = ProtFlags::from_bits_truncate(prot);
    let flags = MapFlags::from_bits(flags).expect("Unsupported flags");
    let aligned_len = align_up(len, PAGE_SIZE);
    if aligned_len == 0 {
        // overflow
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
