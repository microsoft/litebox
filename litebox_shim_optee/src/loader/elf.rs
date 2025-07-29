//! ELF loader for LiteBox

use core::ptr::NonNull;

use alloc::{ffi::CString, string::ToString, vec, vec::Vec};
use bitflags::Flags;
use elf_loader::{
    Loader,
    mmap::{MapFlags, ProtFlags},
    object::ElfObject,
};
use hashbrown::HashMap;
use litebox::{
    mm::linux::{CreatePagesFlags, MappingError},
    platform::RawConstPointer as _,
};
use litebox_common_linux::errno::Errno;
use once_cell::race::OnceBox;
use thiserror::Error;

use crate::{MutPtr, litebox_page_manager};

use super::stack::UserStack;

struct FdElfMap {
    inner: spin::mutex::SpinMutex<HashMap<i32, ElfFileInMemory>>,
}

impl FdElfMap {
    fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    // FIX: this function does redundant memory copying.
    fn get(&self, fd: i32) -> Option<ElfFileInMemory> {
        self.inner.lock().get(&fd).cloned()
    }

    fn remove(&self, fd: i32) -> Option<ElfFileInMemory> {
        self.inner.lock().remove(&fd)
    }

    fn new_elf(&self, elf_buf: &[u8]) -> Result<i32, Errno> {
        let mut inner = self.inner.lock();
        let name = CString::new("/DUMMY").unwrap();
        let fd = match inner.keys().max() {
            Some(&id) => id.checked_add(1).ok_or(Errno::ENOMEM)?,
            None => 1,
        };
        inner.insert(fd, ElfFileInMemory::new(elf_buf, fd)?);
        Ok(fd)
    }
}

fn fd_elf_map() -> &'static FdElfMap {
    static FD_ELF_MAP: OnceBox<FdElfMap> = OnceBox::new();
    FD_ELF_MAP.get_or_init(|| alloc::boxed::Box::new(FdElfMap::new()))
}

#[derive(Clone)]
// An opened elf file
struct ElfFileInMemory {
    buffer: alloc::vec::Vec<u8>,
    name: CString,
    fd: i32,
}

impl ElfFileInMemory {
    #[allow(clippy::unnecessary_wraps)]
    fn new(elf_buf: &[u8], fd: i32) -> Result<Self, Errno> {
        let name = CString::new("/DUMMY").unwrap();
        Ok(Self {
            buffer: elf_buf.to_vec(),
            name,
            fd,
        })
    }
}

impl ElfObject for ElfFileInMemory {
    fn file_name(&self) -> &core::ffi::CStr {
        &self.name
    }

    fn read(&mut self, buf: &mut [u8], offset: usize) -> elf_loader::Result<()> {
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "buflen {} offset {}",
            buf.len(),
            offset
        );
        buf.copy_from_slice(&self.buffer[offset..offset + buf.len()]);
        Ok(())
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
            // the below imitates Self::do_mmap_file(addr, len, prot, flags, fd, offset) by preloading the file content into memory
            let mut temp_prot = elf_loader::mmap::ProtFlags::empty();
            temp_prot.set(elf_loader::mmap::ProtFlags::PROT_READ, true);
            temp_prot.set(elf_loader::mmap::ProtFlags::PROT_WRITE, true);

            let mapped_addr = Self::do_mmap_anonymous(addr, len, temp_prot, flags)?;

            let fd_elf_map = fd_elf_map();
            let mut object = fd_elf_map
                .get(fd)
                .expect("fd_elf_map.get(fd) should return Some(ElfFileInMemory)");

            let mut buf = vec![0u8; len];
            let _ = object.read(&mut buf, offset);

            unsafe {
                litebox::log_println!(
                    litebox_platform_multiplex::platform(),
                    "memcpy: src = {:x?}, dst = {:x?}, len = {}",
                    buf.as_ptr(),
                    mapped_addr,
                    len
                );
                core::ptr::copy_nonoverlapping(buf.as_ptr(), mapped_addr as *mut u8, len);
            }
            crate::syscalls::mm::sys_mprotect(
                MutPtr::from_usize(mapped_addr),
                len,
                litebox_common_linux::ProtFlags::from_bits_truncate(prot.bits()),
            )
            .expect("sys_mprotect failed");

            mapped_addr
        } else {
            // No file provided because it is a blob.
            // Set `need_copy` so that the loader will copy the memory
            // to the new address space.
            *need_copy = true;
            Self::do_mmap_anonymous(addr, len, prot, flags)?
        };
        #[cfg(debug_assertions)]
        litebox::log_println!(litebox_platform_multiplex::platform(), "ptr = {:x?}", ptr);
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
    // Load an ELF file and prepare the stack for the new process.
    pub(super) fn load_buffer(
        elf_buf: &[u8],
        argv: Vec<CString>,
    ) -> Result<ElfLoadInfo, ElfLoaderError> {
        let mut loader = Loader::<ElfLoaderMmap>::new();

        let fd_elf_map = fd_elf_map();
        let fd = fd_elf_map
            .new_elf(elf_buf)
            .map_err(ElfLoaderError::OpenError)?;
        let object = fd_elf_map
            .get(fd)
            .ok_or(ElfLoaderError::OpenError(Errno::ENOENT))?;

        let elf = loader
            .easy_load(object)
            .map_err(ElfLoaderError::LoaderError)?;

        fd_elf_map
            .remove(fd)
            .expect("fd_elf_map.remove(fd) should return Some(ElfFileInMemory)");

        let entry = elf.entry();
        let base = elf.base();

        #[cfg(debug_assertions)]
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "entry = {:#x}, base = {:#x}",
            entry,
            base
        );

        let sp = unsafe {
            let length = litebox::mm::linux::NonZeroPageSize::new(super::DEFAULT_STACK_SIZE)
                .expect("DEFAULT_STACK_SIZE is not page-aligned");
            litebox_page_manager()
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(ElfLoaderError::MappingError)?
        };
        let mut stack = UserStack::new(sp, super::DEFAULT_STACK_SIZE)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;
        stack.init(argv).ok_or(ElfLoaderError::InvalidStackAddr)?;

        Ok(ElfLoadInfo {
            entry_point: entry,
            user_stack_top: stack.get_cur_stack_top(),
        })
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
