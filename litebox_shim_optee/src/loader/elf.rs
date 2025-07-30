//! ELF loader for LiteBox

use alloc::{ffi::CString, string::ToString};
use core::ptr::NonNull;
use elf::{ElfBytes, endian::AnyEndian};
use elf_loader::{
    Loader,
    arch::ElfPhdr,
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

/// Data structure to maintain a mapping of fd to in-memory TA ELF files.
/// This is needed because [`elf_loader`] uses file- or fd-backed `mmap` to load ELF files
/// but `litebox_shim_optee` does not have a fd-based filesystem.
struct FdElfMap {
    inner: spin::mutex::SpinMutex<HashMap<i32, ElfFileInMemory>>,
}

impl FdElfMap {
    fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    /// This function returns a copy of the ELF file in memory
    fn get(&self, fd: i32) -> Option<ElfFileInMemory> {
        self.inner.lock().get(&fd).cloned()
    }

    /// Ths function finds the ELF file in memory by its fd and reads the content
    /// into the provided buffer from the specified offset.
    fn read(&self, buf: &mut [u8], offset: usize, fd: i32) -> Result<(), Errno> {
        let mut inner = self.inner.lock();
        if let Some(object) = inner.get_mut(&fd) {
            object.read(buf, offset).map_err(|_| Errno::EIO)
        } else {
            Err(Errno::ENOENT)
        }
    }

    /// This function removes the ELF file from the map by its fd and returns it.
    fn remove(&self, fd: i32) -> Option<ElfFileInMemory> {
        self.inner.lock().remove(&fd)
    }

    /// This function registers a new ELF file in memory with the given buffer and returns its fd.
    fn register_elf(&self, elf_buf: &[u8]) -> Result<i32, Errno> {
        let mut inner = self.inner.lock();
        let fd = match inner.keys().max() {
            Some(&id) => id.checked_add(1).ok_or(Errno::ENOMEM)?,
            None => 3, // 0, 1, 2 have special meanings (stdin, stdout, stderr)
        };
        inner.insert(fd, ElfFileInMemory::new(elf_buf, fd)?);
        Ok(fd)
    }
}

fn fd_elf_map() -> &'static FdElfMap {
    static FD_ELF_MAP: OnceBox<FdElfMap> = OnceBox::new();
    FD_ELF_MAP.get_or_init(|| alloc::boxed::Box::new(FdElfMap::new()))
}

// An ELF file loaded in memory
#[derive(Clone)]
struct ElfFileInMemory {
    buffer: alloc::vec::Vec<u8>,
    name: CString,
    fd: i32,
}

impl ElfFileInMemory {
    #[allow(clippy::unnecessary_wraps)]
    fn new(elf_buf: &[u8], fd: i32) -> Result<Self, Errno> {
        let name = CString::new("/DUMMY").unwrap(); // TODO: use TA's uuid as name
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
        #[cfg(debug_assertions)]
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "ElfObject::read(buflen: {}, offset: {})",
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
            // the below imitates do_mmap_file(addr, len, prot, flags, fd, offset)
            // by preloading the file content into memory
            let mut temp_prot = elf_loader::mmap::ProtFlags::empty();
            temp_prot.set(elf_loader::mmap::ProtFlags::PROT_READ, true);
            temp_prot.set(elf_loader::mmap::ProtFlags::PROT_WRITE, true);

            let mapped_addr = Self::do_mmap_anonymous(addr, len, temp_prot, flags)?;
            let mapped_slice: &mut [u8] =
                unsafe { core::slice::from_raw_parts_mut(mapped_addr as *mut u8, len) };
            let fd_elf_map = fd_elf_map();
            fd_elf_map
                .read(mapped_slice, offset, fd)
                .expect("fd_elf_map.read failed");

            crate::syscalls::mm::sys_mprotect(
                MutPtr::from_usize(mapped_addr),
                len,
                litebox_common_linux::ProtFlags::from_bits_truncate(prot.bits()),
            )
            .expect("sys_mprotect failed");

            *need_copy = false;
            mapped_addr
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

// `dl_phdr_info` from optee_os/lib/libutee/include/link.h
// Note: the `libc` crate defines it but we can't use `libc` with `litebox_runner_lvbs` due to `no_std` issues.
#[allow(clippy::struct_field_names)]
#[derive(Debug)]
#[repr(C)]
struct DlPhdrInfo {
    pub dlpi_addr: u64,
    pub dlpi_name: *const i8,
    pub dlpi_phdr: *const ElfPhdr,
    pub dlpi_phnum: u16,
    pub dlpi_adds: u64,
    pub dlpi_subs: u64,
    pub dlpi_tls_modid: usize,
    pub dlpi_tls_data: *mut u8,
}

impl DlPhdrInfo {
    pub fn new() -> Self {
        Self {
            dlpi_addr: 0,
            dlpi_name: core::ptr::null(),
            dlpi_phdr: core::ptr::null(),
            dlpi_phnum: 0,
            dlpi_adds: 0,
            dlpi_subs: 0,
            dlpi_tls_modid: 0,
            dlpi_tls_data: core::ptr::null_mut(),
        }
    }
}

/// `elf_phdr_info` from optee_os/lib/libutee/include/user_ta_header.h
#[derive(Debug)]
#[repr(C)]
struct ElfPhdrInfo {
    pub reserved: u32,
    pub count: u16,
    pub reserved2: u8,
    pub zero: i8,
    pub dlpi: *mut DlPhdrInfo,
}

impl ElfPhdrInfo {
    pub fn new(dlpi: *mut DlPhdrInfo, count: u16) -> Self {
        Self {
            reserved: 0,
            reserved2: 0,
            zero: 0,
            dlpi,
            count,
        }
    }
}

/// This function populates the `__elf_phdr_info` section of a TA ELF loaded in memory.
/// We should call this function once the ELF file is loaded into memory because it require
/// the base address of the loaded ELF file.
/// `__elf_phdr_info` is an OP-TEE-specific section that contains the `DlPhdrInfo` structure.
/// Since this is a custom section, [`elf_loader`] does not handle it.
/// For now, this population is mostly with minimal data just for enabling loading.
/// This function can be extended later if needed.
///
/// # Safety
/// This function is unsafe because it directly modifies the memory content of a loaded ELF file.
unsafe fn ta_elf_set_elf_phdr_info(elf_buf: &[u8], base: usize) {
    let elf = ElfBytes::<AnyEndian>::minimal_parse(elf_buf).expect("Failed to parse ELF data");
    let Ok(Some((symtab, sym_strtab))) = elf.symbol_table() else {
        panic!("ELF file does not contain a symbol table");
    };

    let mut elf_phdr_info_addr: Option<usize> = None;
    for s in symtab {
        if s.st_bind() == elf::abi::STB_GLOBAL
            && s.st_symtype() == elf::abi::STT_OBJECT
            && let Ok(sym_name) = sym_strtab.get(s.st_name as usize)
            && sym_name == "__elf_phdr_info"
        {
            elf_phdr_info_addr =
                base.checked_add(usize::try_from(s.st_value).expect("st_value overflow"));
            break;
        }
    }

    if let Some(elf_phdr_info_addr) = elf_phdr_info_addr {
        #[cfg(debug_assertions)]
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "elf_phdr_info_addr = {:#x}",
            elf_phdr_info_addr
        );

        // TODO: unmap this page once the TA exits
        let ptr = crate::syscalls::mm::sys_mmap(
            0,
            core::mem::size_of::<ElfPhdrInfo>(),
            litebox_common_linux::ProtFlags::PROT_READ
                | litebox_common_linux::ProtFlags::PROT_WRITE,
            litebox_common_linux::MapFlags::MAP_ANONYMOUS
                | litebox_common_linux::MapFlags::MAP_PRIVATE,
            -1,
            0,
        )
        .expect("sys_mmap failed");
        let dl_phdr_info = unsafe { &mut *(ptr.as_usize() as *mut DlPhdrInfo) };
        *dl_phdr_info = DlPhdrInfo::new();

        let elf_phdr_info = unsafe { &mut *(elf_phdr_info_addr as *mut ElfPhdrInfo) };
        *elf_phdr_info = ElfPhdrInfo::new(core::ptr::from_mut::<DlPhdrInfo>(dl_phdr_info), 1);

        dl_phdr_info.dlpi_addr = u64::try_from(base).expect("base address overflow");
        dl_phdr_info.dlpi_name = elf_phdr_info.zero as *const i8;
        dl_phdr_info.dlpi_adds = 1;
    }
}

/// Loader for ELF files
pub(super) struct ElfLoader;

impl ElfLoader {
    // Load an ELF file and prepare the stack for the new process.
    pub(super) fn load_buffer(elf_buf: &[u8]) -> Result<ElfLoadInfo, ElfLoaderError> {
        let mut loader = Loader::<ElfLoaderMmap>::new();

        let fd_elf_map = fd_elf_map();
        let fd = fd_elf_map
            .register_elf(elf_buf)
            .map_err(ElfLoaderError::OpenError)?;
        let object = fd_elf_map
            .get(fd)
            .ok_or(ElfLoaderError::OpenError(Errno::ENOENT))?;

        let elf = loader
            .easy_load(object)
            .map_err(ElfLoaderError::LoaderError)?;

        let entry = elf.entry();
        let base = elf.base();

        unsafe { ta_elf_set_elf_phdr_info(elf_buf, base) };

        fd_elf_map
            .remove(fd)
            .expect("fd_elf_map.remove(fd) should return Some(ElfFileInMemory)");

        let sp = unsafe {
            let length = litebox::mm::linux::NonZeroPageSize::new(super::DEFAULT_STACK_SIZE)
                .expect("DEFAULT_STACK_SIZE is not page-aligned");
            litebox_page_manager()
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(ElfLoaderError::MappingError)?
        };
        let mut stack = UserStack::new(sp, super::DEFAULT_STACK_SIZE)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;
        stack.init().ok_or(ElfLoaderError::InvalidStackAddr)?;

        #[cfg(debug_assertions)]
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "entry = {:#x}, base = {:#x}, stack = {:#x}",
            entry,
            base,
            stack.get_cur_stack_top(),
        );

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
