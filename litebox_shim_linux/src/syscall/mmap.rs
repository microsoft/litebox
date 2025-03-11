use litebox::{
    fd::FileFd,
    fs::FileSystem,
    mm::mapping::{MappingError, MappingProvider},
    platform::RawMutPointer,
};

use crate::{
    MutPtr,
    errno::{
        AsErrno,
        constants::{EBADF, EINVAL, ENOMEM, EOVERFLOW},
    },
    file_descriptors, litebox_fs, litebox_vmm,
};

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = !(PAGE_SIZE - 1);
const PAGE_SHIFT: usize = PAGE_SIZE.trailing_zeros() as usize;

impl AsErrno for MappingError {
    fn as_errno(&self) -> i32 {
        match self {
            MappingError::OutOfMemory => ENOMEM,
            MappingError::ReadError(_) => EINVAL,
            _ => todo!(),
        }
    }
}

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

fn do_mmap(
    addr: usize,
    len: usize,
    prot: ProtFlags,
    flags: MmapFlags,
) -> Result<usize, MappingError> {
    todo!()
}

fn do_mmap_file<P: MappingProvider<MutPtr<u8>>>(
    addr: usize,
    len: usize,
    prot: ProtFlags,
    flags: MmapFlags,
    file: &FileFd,
    pgoff: usize,
    mm: &mut P,
) -> Result<usize, MappingError> {
    let suggested_addr = if addr == 0 { None } else { Some(addr) };
    let fixed_addr = flags.contains(MmapFlags::MAP_FIXED);
    let op = |ptr: MutPtr<u8>| -> Result<usize, MappingError> {
        let file_offset = pgoff << PAGE_SHIFT;
        // FIXME: ptr may be unmaped
        ptr.mutate_subslice_with(..len as isize, |user_buf| {
            litebox_fs().read(file, user_buf, Some(file_offset))
        })
        .unwrap()
        .map_err(MappingError::ReadError)
    };
    let mut vmm = litebox_vmm().write();
    match prot {
        ProtFlags::PROT_READ => vmm.create_readable_page(suggested_addr, len, fixed_addr, op),
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE => {
            vmm.create_writable_page(suggested_addr, len, fixed_addr, op)
        }
        ProtFlags::PROT_READ | ProtFlags::PROT_EXEC => {
            vmm.create_executable_page(suggested_addr, len, fixed_addr, op)
        }
        _ => todo!(),
    }
}

fn sys_mmap<P: MappingProvider<MutPtr<u8>>>(
    addr: usize,
    len: usize,
    prot: u32,
    flags: u32,
    fd: i32,
    offset: usize,
    mm: &mut P,
) -> isize {
    // check alignment
    if offset & !PAGE_MASK != 0 {
        return -EINVAL as _;
    }
    if addr & !PAGE_MASK != 0 {
        return -EINVAL as _;
    }
    if len == 0 {
        return -EINVAL as _;
    }

    let prot = ProtFlags::from_bits_truncate(prot);
    let flags = MmapFlags::from_bits(flags).expect("Unsupported flags");
    let aligned_len = align_up(len, PAGE_SIZE);
    if aligned_len == 0 {
        // overflow
        return -ENOMEM as _;
    }
    let count = offset >> PAGE_SHIFT;
    if count.checked_add(aligned_len >> PAGE_SHIFT).is_none() {
        return -EOVERFLOW as _;
    }

    let res = if flags.contains(MmapFlags::MAP_ANONYMOUS) {
        do_mmap(addr, aligned_len, prot, flags)
    } else {
        // TODO: return EACCESS if fd is valid but does not refer to a regular file
        match file_descriptors().read().get_file_fd(fd as u32) {
            Some(file) => do_mmap_file(addr, aligned_len, prot, flags, file, count, mm),
            None => return -EBADF as _,
        }
    };

    match res {
        Ok(addr) => addr as isize,
        Err(err) => -err.as_errno() as isize,
    }
}
