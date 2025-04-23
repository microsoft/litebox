//! ELF loader for LiteBox

use core::ptr::NonNull;

use alloc::{collections::btree_map::BTreeMap, ffi::CString, string::ToString, vec::Vec};
use elf_loader::{
    Elf, Loader,
    arch::ElfPhdr,
    mmap::{MapFlags, ProtFlags},
    object::ElfObject,
};
use litebox::{
    fs::{Mode, OFlags},
    mm::linux::{MappingError, PAGE_SIZE},
    platform::RawConstPointer,
};
use litebox_common_linux::errno::Errno;
use thiserror::Error;

use crate::litebox_page_manager;

use super::stack::{AuxKey, UserStack};

// An opened elf file
struct ElfFile {
    name: CString,
    fd: i32,
}

impl ElfFile {
    fn new(path: &str) -> Result<Self, Errno> {
        let name = CString::new(path).unwrap();
        let fd = crate::syscalls::file::sys_open(path, OFlags::RDONLY, Mode::empty())?;
        let Ok(fd) = i32::try_from(fd) else {
            unreachable!("fd should be a valid i32");
        };

        Ok(Self { name, fd })
    }
}

impl ElfObject for ElfFile {
    fn file_name(&self) -> &core::ffi::CStr {
        &self.name
    }

    fn read(&mut self, mut buf: &mut [u8], mut offset: usize) -> elf_loader::Result<()> {
        loop {
            if buf.is_empty() {
                return Ok(());
            }
            // Try to read the remaining bytes
            match crate::syscalls::file::sys_read(self.fd, buf, Some(offset)) {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        // reached the end of the file
                        return Err(elf_loader::Error::IOError {
                            msg: "failed to fill buffer".to_string(),
                        });
                    } else {
                        // Successfully read some bytes
                        buf = &mut buf[bytes_read..];
                        offset += bytes_read;
                    }
                }
                Err(_) => {
                    // Error occurred
                    return Err(elf_loader::Error::IOError {
                        msg: "failed to read from file".to_string(),
                    });
                }
            }
        }
    }

    fn as_fd(&self) -> Option<i32> {
        Some(self.fd)
    }
}

/// [`elf_loader::mmap::Mmap`] implementation for ELF loader
struct ElfLoaderMmap;

impl ElfLoaderMmap {
    fn do_mmap_file(
        addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        fd: i32,
        offset: usize,
    ) -> elf_loader::Result<usize> {
        // TODO: we copy the file to the memory to support file-backed mmap.
        // Loader may rely on `mmap` instead of `mprotect` to change the memory protection,
        // in which case the file is copied multiple times. To reduce the overhead, we
        // could convert some `mmap` calls to `mprotect` calls whenever possible.
        match crate::syscalls::mm::sys_mmap(
            addr.unwrap_or(0),
            len,
            litebox_common_linux::ProtFlags::from_bits_truncate(prot.bits()),
            litebox_common_linux::MapFlags::from_bits(flags.bits()).expect("unsupported flags"),
            fd,
            offset,
        ) {
            Ok(addr) => Ok(addr.as_usize()),
            Err(e) => Err(elf_loader::Error::MmapError { msg: e.to_string() }),
        }
    }

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
        let ptr = if let Some(fd) = fd {
            Self::do_mmap_file(addr, len, prot, flags, fd, offset)?
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

/// Loader for ELF files
pub(super) struct ElfLoader;

impl ElfLoader {
    // TODO: set a guard page for the stack
    const DEFAULT_STACK_SIZE: usize = 2048 * PAGE_SIZE; // 8MB

    fn init_auxvec(elf: &Elf) -> BTreeMap<AuxKey, usize> {
        let mut aux = BTreeMap::new();
        let phdrs = elf.phdrs();
        aux.insert(AuxKey::AT_PAGESZ, PAGE_SIZE);
        aux.insert(
            AuxKey::AT_PHDR,
            if phdrs.is_empty() {
                0
            } else {
                phdrs.as_ptr() as usize
            },
        );
        aux.insert(AuxKey::AT_PHENT, core::mem::size_of::<ElfPhdr>());
        aux.insert(AuxKey::AT_PHNUM, phdrs.len());
        aux.insert(AuxKey::AT_ENTRY, elf.entry());
        aux
    }

    /// Load an ELF file and prepare the stack for the new process.
    pub(super) fn load(
        path: &str,
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<ElfLoadInfo, ElfLoaderError> {
        let elf = {
            let mut loader = Loader::<ElfLoaderMmap>::new();
            loader
                .easy_load(ElfFile::new(path).map_err(ElfLoaderError::OpenError)?)
                .map_err(ElfLoaderError::LoaderError)?
        };
        let interp: Option<Elf> = if let Some(interp_name) = elf.interp() {
            // e.g., /lib64/ld-linux-x86-64.so.2
            let mut loader = Loader::<ElfLoaderMmap>::new();
            Some(
                loader
                    .easy_load(ElfFile::new(interp_name).map_err(ElfLoaderError::OpenError)?)
                    .map_err(ElfLoaderError::LoaderError)?,
            )
        } else {
            None
        };

        let mut aux = Self::init_auxvec(&elf);
        let entry = if let Some(ld) = interp {
            aux.insert(AuxKey::AT_BASE, ld.base());
            ld.entry()
        } else {
            elf.entry()
        };

        let sp = unsafe {
            litebox_page_manager()
                .create_stack_pages(0, Self::DEFAULT_STACK_SIZE, false)
                .map_err(ElfLoaderError::MappingError)?
        };
        let mut stack =
            UserStack::new(sp, Self::DEFAULT_STACK_SIZE).ok_or(ElfLoaderError::InvalidStackAddr)?;
        stack
            .init(argv, envp, aux)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;

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
