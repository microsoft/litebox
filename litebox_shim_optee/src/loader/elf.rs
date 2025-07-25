//! ELF loader for LiteBox

use core::{
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::{ffi::CString, string::ToString, vec::Vec};
use elf_loader::{
    Elf, Loader,
    arch::ElfPhdr,
    mmap::{MapFlags, Mmap, ProtFlags},
    object::ElfObject,
};
use litebox::{
    fs::{Mode, OFlags},
    mm::linux::{CreatePagesFlags, MappingError, PAGE_SIZE},
    platform::{RawConstPointer as _, SystemInfoProvider as _},
    utils::TruncateExt,
};
use litebox_common_linux::errno::Errno;
use thiserror::Error;

use crate::litebox_page_manager;

use super::stack::UserStack;

// An opened elf file
struct ElfFileInMemory {
    addr: usize,
    len: usize,
    name: CString, // dummy name
    fd: i32,       // dummy fd
}

impl ElfFileInMemory {
    #[allow(clippy::unnecessary_wraps)]
    fn new(addr: usize, len: usize) -> Result<Self, Errno> {
        let name = CString::new("/DUMMY").unwrap();
        let fd = 0;
        Ok(Self {
            addr,
            len,
            name,
            fd,
        })
    }
}

impl ElfObject for ElfFileInMemory {
    fn file_name(&self) -> &core::ffi::CStr {
        &self.name
    }

    fn read(&mut self, mut buf: &mut [u8], mut offset: usize) -> elf_loader::Result<()> {
        todo!()
    }

    fn as_fd(&self) -> Option<i32> {
        Some(self.fd)
    }
}

/// [`elf_loader::mmap::Mmap`] implementation for ELF loader
struct ElfLoaderMmap;

impl ElfLoaderMmap {
    fn do_mmap_anonymous(
        addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> elf_loader::Result<usize> {
        match crate::syscalls::mm::sys_mmap(
            addr.unwrap_or(0),
            len,
            litebox_common_linux::ProtFlags::from_bits_truncate(prot.bits()),
            litebox_common_linux::MapFlags::from_bits(
                flags.bits() | MapFlags::MAP_ANONYMOUS.bits(),
            )
            .expect("unsupported flags"),
            -1,
            0,
        ) {
            Ok(addr) => Ok(addr.as_usize()),
            Err(e) => Err(elf_loader::Error::MmapError { msg: e.to_string() }),
        }
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
        #[cfg(debug_assertions)]
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "ElfLoaderMmap::mmap(addr: {:x?}, len: {}, prot: {:x?}, flags: {:x?}, offset: {}, fd: {:?})",
            addr,
            len,
            prot.bits(),
            flags.bits(),
            offset,
            fd
        );
        let ptr = if let Some(fd) = fd {
            todo!()
        } else {
            // No file provided because it is a blob.
            // Set `need_copy` so that the loader will copy the memory
            // to the new address space.
            *need_copy = true;
            Self::do_mmap_anonymous(addr, len, prot, flags)?
        };
        Ok(NonNull::new(ptr as _).expect("null pointer"))
    }

    unsafe fn mmap_anonymous(
        addr: usize,
        len: usize,
        prot: elf_loader::mmap::ProtFlags,
        flags: elf_loader::mmap::MapFlags,
    ) -> elf_loader::Result<NonNull<core::ffi::c_void>> {
        let addr = if addr == 0 { None } else { Some(addr) };
        let ptr = Self::do_mmap_anonymous(addr, len, prot, flags)?;
        Ok(NonNull::new(ptr as _).expect("null pointer"))
    }

    unsafe fn munmap(_addr: NonNull<core::ffi::c_void>, _len: usize) -> elf_loader::Result<()> {
        // This is called when dropping the loader. We will unmap the memory when the program exits instead.
        Ok(())
    }

    unsafe fn mprotect(
        _addr: NonNull<core::ffi::c_void>,
        _len: usize,
        _prot: elf_loader::mmap::ProtFlags,
    ) -> elf_loader::Result<()> {
        todo!()
    }
}

/// Struct to hold the information needed to start the program
/// (entry point and user stack top).
pub struct ElfLoadInfo {
    pub entry_point: usize,
    pub user_stack_top: usize,
}

#[cfg(target_arch = "x86_64")]
type Ehdr = elf::file::Elf64_Ehdr;
#[cfg(target_arch = "x86")]
type Ehdr = elf::file::Elf32_Ehdr;
#[cfg(target_arch = "x86_64")]
type Shdr = elf::section::Elf64_Shdr;
#[cfg(target_arch = "x86")]
type Shdr = elf::section::Elf32_Shdr;

/// Loader for ELF files
pub(super) struct ElfLoader;

impl ElfLoader {
    /// Load an ELF file and prepare the stack for the new process.
    #[allow(clippy::too_many_lines)]
    pub(super) fn load(path: &str, argv: Vec<CString>) -> Result<ElfLoadInfo, ElfLoaderError> {
        let mut loader = Loader::<ElfLoaderMmap>::new();

        todo!()
    }
}

#[derive(Error, Debug)]
pub enum ElfLoaderError {
    #[error("failed to open the ELF file: {0}")]
    OpenError(#[from] Errno),
    #[error("failed to load the ELF file: {0}")]
    LoaderError(#[from] elf_loader::Error),
    #[error("invalid stack")]
    InvalidStackAddr,
    #[error("failed to mmap: {0}")]
    MappingError(#[from] MappingError),
}

impl From<ElfLoaderError> for litebox_common_linux::errno::Errno {
    fn from(value: ElfLoaderError) -> Self {
        match value {
            ElfLoaderError::OpenError(e) => e,
            ElfLoaderError::LoaderError(_) => litebox_common_linux::errno::Errno::EINVAL,
            ElfLoaderError::InvalidStackAddr | ElfLoaderError::MappingError(_) => {
                litebox_common_linux::errno::Errno::ENOMEM
            }
        }
    }
}
