use core::ffi::c_int;
use core::ptr::NonNull;

use alloc::string::ToString;
use elf_loader::mmap::{MapFlags, ProtFlags};
use litebox::{
    fs::FileSystem,
    mm::mapping::{MappingError, MappingProvider},
    platform::RawMutPointer,
};

use crate::{MutPtr, file_descriptors, litebox_fs, litebox_vmm};

pub(super) struct ElfLoaderMmap;

impl ElfLoaderMmap {
    const PROT_EXECUTABLE: c_int = ProtFlags::PROT_READ.bits() | ProtFlags::PROT_EXEC.bits();
    const PROT_WRITABLE: c_int = ProtFlags::PROT_READ.bits() | ProtFlags::PROT_WRITE.bits();
    const PROT_READABLE: c_int = ProtFlags::PROT_READ.bits();

    fn do_mmap_file(
        addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        file: &litebox::fd::FileFd,
        offset: usize,
    ) -> elf_loader::Result<usize> {
        let fixed_addr = flags.contains(MapFlags::MAP_FIXED);
        let op = |ptr: MutPtr<u8>| -> Result<usize, MappingError> {
            ptr.mutate_subslice_with(..len as isize, |user_buf| {
                // Loader code always runs before the program starts, so we can ensure
                // user_buf is valid (e.g., won't be unmapped).
                litebox_fs().read(file, user_buf, Some(offset))
            })
            .unwrap()
            .map_err(MappingError::ReadError)
        };
        let mut vmm = litebox_vmm().write();
        match prot.bits() {
            Self::PROT_EXECUTABLE => vmm.create_executable_page(addr, len, fixed_addr, op),
            Self::PROT_WRITABLE => vmm.create_writable_page(addr, len, fixed_addr, op),
            Self::PROT_READABLE => vmm.create_readable_page(addr, len, fixed_addr, op),
            _ => todo!(),
        }
        .map_err(|e| elf_loader::Error::MmapError { msg: e.to_string() })
    }

    fn do_mmap_anonymous(
        addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> elf_loader::Result<usize> {
        let fixed_addr = flags.contains(MapFlags::MAP_FIXED);
        let mut vmm = litebox_vmm().write();
        let op = |ptr: MutPtr<u8>| Ok(0);
        match prot.bits() {
            Self::PROT_EXECUTABLE => vmm.create_executable_page(addr, len, fixed_addr, op),
            Self::PROT_WRITABLE => vmm.create_writable_page(addr, len, fixed_addr, op),
            Self::PROT_READABLE => vmm.create_readable_page(addr, len, fixed_addr, op),
            _ => todo!(),
        }
        .map_err(|e| elf_loader::Error::MmapError { msg: e.to_string() })
    }
}

impl elf_loader::mmap::Mmap for ElfLoaderMmap {
    unsafe fn mmap(
        addr: Option<usize>,
        len: usize,
        prot: elf_loader::mmap::ProtFlags,
        flags: elf_loader::mmap::MapFlags,
        offset: usize,
        fd: Option<i32>,
        need_copy: &mut bool,
    ) -> elf_loader::Result<NonNull<core::ffi::c_void>> {
        let ptr = if let Some(fd) = fd {
            match file_descriptors().read().get_file_fd(fd as _) {
                Some(file) => Self::do_mmap_file(addr, len, prot, flags, file, offset)?,
                None => {
                    return Err(elf_loader::Error::MmapError {
                        msg: "Invalid file descriptor".to_string(),
                    });
                }
            }
        } else {
            *need_copy = true;
            Self::do_mmap_anonymous(addr, len, prot, flags)?
        };
        Ok(unsafe { NonNull::new_unchecked(ptr as _) })
    }

    unsafe fn mmap_anonymous(
        addr: usize,
        len: usize,
        prot: elf_loader::mmap::ProtFlags,
        flags: elf_loader::mmap::MapFlags,
    ) -> elf_loader::Result<NonNull<core::ffi::c_void>> {
        let addr = if addr == 0 { None } else { Some(addr) };
        let ptr = Self::do_mmap_anonymous(addr, len, prot, flags)?;
        Ok(unsafe { NonNull::new_unchecked(ptr as _) })
    }

    unsafe fn munmap(addr: NonNull<core::ffi::c_void>, len: usize) -> elf_loader::Result<()> {
        todo!()
    }

    unsafe fn mprotect(
        addr: NonNull<core::ffi::c_void>,
        len: usize,
        prot: elf_loader::mmap::ProtFlags,
    ) -> elf_loader::Result<()> {
        todo!()
    }
}
