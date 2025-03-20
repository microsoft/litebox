use litebox::{
    mm::linux::{MappingError, PAGE_SIZE},
    platform::RawMutPointer,
};

use crate::{MutPtr, litebox_vmm};

use super::read::sys_read;

const PAGE_MASK: usize = !(PAGE_SIZE - 1);
const PAGE_SHIFT: usize = PAGE_SIZE.trailing_zeros() as usize;

bitflags::bitflags! {
    /// Desired memory protection of a memory mapping.
    #[derive(PartialEq)]
    pub struct ProtFlags: u32 {
        /// Pages cannot be accessed.
        const PROT_NONE = 0;
        /// Pages can be read.
        const PROT_READ = 1 << 0;
        /// Pages can be written.
        const PROT_WRITE = 1 << 1;
        /// Pages can be executed
        const PROT_EXEC = 1 << 2;
    }
}

bitflags::bitflags! {
    #[non_exhaustive]
    struct MmapFlags: u32 {
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

fn do_mmap_common(
    addr: Option<usize>,
    len: usize,
    prot: ProtFlags,
    flags: MmapFlags,
    op: impl FnOnce(MutPtr<u8>) -> Result<usize, MappingError>,
) -> Result<MutPtr<u8>, MappingError> {
    let fixed_addr = flags.contains(MmapFlags::MAP_FIXED);
    let suggested_addr = addr.unwrap_or(0);
    let vmm = litebox_vmm();
    match prot {
        ProtFlags::PROT_EXEC => unsafe {
            vmm.create_executable_pages(suggested_addr, len, fixed_addr, op)
        },
        ProtFlags::PROT_WRITE => unsafe {
            vmm.create_writable_pages(suggested_addr, len, fixed_addr, op)
        },
        ProtFlags::PROT_READ => unsafe {
            vmm.create_readable_pages(suggested_addr, len, fixed_addr, op)
        },
        _ => todo!(),
    }
}

fn do_mmap_anonymous(
    suggested_addr: Option<usize>,
    len: usize,
    prot: ProtFlags,
    flags: MmapFlags,
) -> Result<MutPtr<u8>, MappingError> {
    let op = |_| Ok(0);
    do_mmap_common(suggested_addr, len, prot, flags, op)
}

fn do_mmap_file(
    suggested_addr: Option<usize>,
    len: usize,
    prot: ProtFlags,
    flags: MmapFlags,
    fd: i32,
    offset: usize,
) -> Result<MutPtr<u8>, MappingError> {
    let fixed_addr = flags.contains(MmapFlags::MAP_FIXED);
    let op = |ptr: MutPtr<u8>| -> Result<usize, MappingError> {
        // FIXME: ptr may be unmaped
        ptr.mutate_subslice_with(..len as isize, |user_buf| {
            sys_read(fd, user_buf, Some(offset))
        })
        .unwrap()
        .map_err(MappingError::ReadError)
    };
    do_mmap_common(suggested_addr, len, prot, flags, op)
}

fn sys_mmap(
    addr: usize,
    len: usize,
    prot: u32,
    flags: u32,
    fd: i32,
    offset: usize,
) -> Result<MutPtr<u8>, MappingError> {
    // check alignment
    if offset & !PAGE_MASK != 0 {
        return Err(MappingError::MisAligned);
    }
    if addr & !PAGE_MASK != 0 {
        return Err(MappingError::MisAligned);
    }
    if len == 0 {
        return Err(MappingError::MisAligned);
    }

    let prot = ProtFlags::from_bits_truncate(prot);
    let flags = MmapFlags::from_bits(flags).expect("Unsupported flags");
    let aligned_len = align_up(len, PAGE_SIZE);
    if aligned_len == 0 {
        // overflow
        return Err(MappingError::OutOfMemory);
    }
    if offset.checked_add(aligned_len).is_none() {
        return Err(MappingError::OutOfMemory);
    }

    let suggested_addr = if addr == 0 { None } else { Some(addr) };
    if flags.contains(MmapFlags::MAP_ANONYMOUS) {
        do_mmap_anonymous(suggested_addr, aligned_len, prot, flags)
    } else {
        do_mmap_file(suggested_addr, aligned_len, prot, flags, fd, offset)
    }
}
