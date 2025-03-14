//! ELF loader for LiteBox

use core::{ffi::c_int, ptr::NonNull, str::FromStr};

use alloc::{collections::btree_map::BTreeMap, ffi::CString, string::ToString, vec::Vec};
use elf_loader::{
    Elf, Loader,
    arch::ElfPhdr,
    mmap::{MapFlags, ProtFlags},
    object::ElfObject,
};
use litebox::{
    fs::{FileSystem, Mode, OFlags, errors::OpenError},
    mm::linux::{MappingError, PAGE_SIZE},
    platform::{RawConstPointer, RawMutPointer},
};
use thiserror::Error;

use crate::{MutPtr, file_descriptors, litebox_fs, litebox_vmm};

use super::stack::{AuxKey, UserStack};

// An opened elf file
struct ElfFile {
    name: CString,
    fd: u32,
}

impl ElfFile {
    pub(super) fn from_path(path: &str) -> Result<Self, OpenError> {
        let file = litebox_fs().open(path, OFlags::RDWR, Mode::empty())?;
        let fd = file_descriptors()
            .write()
            .insert(crate::Descriptor::File(file));

        Ok(Self {
            name: CString::from_str(path).unwrap(),
            fd,
        })
    }
}

impl ElfObject for ElfFile {
    fn file_name(&self) -> &core::ffi::CStr {
        &self.name
    }

    fn read(&mut self, buf: &mut [u8], offset: usize) -> elf_loader::Result<()> {
        if let Some(file) = file_descriptors().read().get_file_fd(self.fd) {
            match litebox_fs().read(file, buf, Some(offset)) {
                Ok(_) => Ok(()),
                Err(_) => Err(elf_loader::Error::IOError {
                    msg: "failed to read from file".to_string(),
                }),
            }
        } else {
            Err(elf_loader::Error::IOError {
                msg: "failed to get file descriptor".to_string(),
            })
        }
    }

    fn as_fd(&self) -> Option<i32> {
        Some(self.fd.try_into().unwrap())
    }
}

/// [`elf_loader::mmap::Mmap`] implementation for ELF loader
/// using [`litebox::mm::mapping::MappingProvider`].
struct ElfLoaderMmap;

impl ElfLoaderMmap {
    const PROT_EXECUTABLE: c_int = ProtFlags::PROT_READ.bits() | ProtFlags::PROT_EXEC.bits();
    const PROT_WRITABLE: c_int = ProtFlags::PROT_READ.bits() | ProtFlags::PROT_WRITE.bits();
    const PROT_READABLE: c_int = ProtFlags::PROT_READ.bits();

    fn do_mmap_common(
        addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        op: impl FnOnce(MutPtr<u8>) -> Result<usize, MappingError>,
    ) -> elf_loader::Result<usize> {
        let fixed_addr = flags.contains(MapFlags::MAP_FIXED);
        let suggested_addr = addr.unwrap_or(0);
        let vmm = litebox_vmm();
        let res = match prot.bits() {
            Self::PROT_EXECUTABLE => unsafe {
                vmm.create_executable_pages(suggested_addr, len, fixed_addr, op)
            },
            Self::PROT_WRITABLE => unsafe {
                vmm.create_writable_pages(suggested_addr, len, fixed_addr, op)
            },
            Self::PROT_READABLE => unsafe {
                vmm.create_readable_pages(suggested_addr, len, fixed_addr, op)
            },
            _ => todo!(),
        };
        match res {
            Ok(addr) => Ok(addr.as_usize()),
            Err(e) => Err(elf_loader::Error::MmapError { msg: e.to_string() }),
        }
    }

    fn do_mmap_file(
        addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        file: &litebox::fd::FileFd,
        offset: usize,
    ) -> elf_loader::Result<usize> {
        // TODO: we copy the file to the memory to support file-backed mmap.
        // Loader may rely on `mmap`` instead of `mprotect` to change the memory protection,
        // in which case the file is copied multiple times. To reduce the overhead, we
        // could convert some `mmap` calls to `mprotect` calls whenever possible.
        let op = |ptr: MutPtr<u8>| -> Result<usize, MappingError> {
            ptr.mutate_subslice_with(..isize::try_from(len).unwrap(), |user_buf| {
                // Loader code always runs before the program starts, so we can ensure
                // user_buf is valid (e.g., won't be unmapped).
                litebox_fs().read(file, user_buf, Some(offset))
            })
            .unwrap()
            .map_err(MappingError::ReadError)
        };
        Self::do_mmap_common(addr, len, prot, flags, op)
    }

    fn do_mmap_anonymous(
        addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> elf_loader::Result<usize> {
        let op = |_| Ok(0);
        Self::do_mmap_common(addr, len, prot, flags, op)
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
            match file_descriptors()
                .read()
                .get_file_fd(fd.try_into().unwrap())
            {
                Some(file) => Self::do_mmap_file(addr, len, prot, flags, file, offset)?,
                None => {
                    return Err(elf_loader::Error::MmapError {
                        msg: "Invalid file descriptor".to_string(),
                    });
                }
            }
        } else {
            // No file provided because it is a blob.
            // Set `need_copy` so that the loader will copy the memory
            // to the new address space.
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
struct ElfLoadInfo {
    entry_point: usize,
    user_stack_top: usize,
}

/// Loader for ELF files
struct ElfLoader;

impl ElfLoader {
    const DEFAULT_STACK_SIZE: usize = 2 * PAGE_SIZE;

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
    fn load(
        path: &str,
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<ElfLoadInfo, ElfLoaderError> {
        let elf = {
            let mut loader = Loader::<ElfLoaderMmap>::new();
            loader
                .easy_load(ElfFile::from_path(path).map_err(ElfLoaderError::OpenError)?)
                .map_err(ElfLoaderError::LoaderError)?
        };
        let interp: Option<Elf> = if let Some(interp_name) = elf.interp() {
            // e.g., /lib64/ld-linux-x86-64.so.2
            let mut loader = Loader::<ElfLoaderMmap>::new();
            Some(
                loader
                    .easy_load(ElfFile::from_path(interp_name).map_err(ElfLoaderError::OpenError)?)
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
            litebox_vmm()
                .create_stack_pages(0, Self::DEFAULT_STACK_SIZE, false)
                .unwrap()
        };
        let mut stack = UserStack::new(sp, Self::DEFAULT_STACK_SIZE).unwrap();
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
enum ElfLoaderError {
    #[error("failed to open the ELF file: {0}")]
    OpenError(#[from] OpenError),
    #[error("failed to load the ELF file: {0}")]
    LoaderError(#[from] elf_loader::Error),
    #[error("invalid stack")]
    InvalidStackAddr,
}

#[cfg(test)]
mod tests {
    use super::ElfLoader;
    use crate::litebox_fs;
    use alloc::ffi::CString;
    use alloc::vec;
    use core::arch::global_asm;
    use litebox::{
        fs::{FileSystem, Mode, OFlags},
        platform::trivial_providers::ImpossiblePunchthroughProvider,
    };
    use litebox_platform_multiplex::{Platform, set_platform};

    extern crate std;

    global_asm!(
        "
        .text
        .align	4
        .globl	trampoline
        .type	trampoline,@function
    trampoline:
        xor rdx, rdx
        mov	rsp, rsi
        jmp	rdi
        /* Should not reach. */
        hlt"
    );

    fn init_platform() {
        static ONCE: spin::Once = spin::Once::new();
        ONCE.call_once(|| {
            let platform = unsafe { Platform::new_for_test(ImpossiblePunchthroughProvider {}) };
            set_platform(platform);
        });
    }

    fn compile(path: &std::path::Path) {
        // Compile the hello.c file to an executable
        let output = std::process::Command::new("gcc")
            .arg("-o")
            .arg(path.to_str().unwrap())
            .arg("./src/loader/hello.c")
            .arg("-static")
            .output()
            .expect("Failed to compile hello.c");
        assert!(output.status.success(), "failed to compile hello.c");
    }

    fn install_file(path: &std::path::PathBuf, out: &str) {
        let fd = litebox_fs()
            .open(
                out,
                OFlags::CREAT | OFlags::WRONLY,
                Mode::XGRP | Mode::XOTH | Mode::XUSR | Mode::RGRP | Mode::ROTH | Mode::RUSR,
            )
            .unwrap();
        let contents = std::fs::read(path).unwrap();
        litebox_fs().write(&fd, &contents, None).unwrap();
        litebox_fs().close(fd).unwrap();
    }

    #[test]
    fn test_load_exec() {
        unsafe extern "C" {
            fn trampoline(entry: usize, sp: usize) -> !;
        }

        init_platform();

        // no std::env::var("OUT_DIR").unwrap()??
        let path = std::path::Path::new("../target/debug").join("hello");
        compile(&path);

        let executable_path = "/hello";
        install_file(&path, executable_path);

        let argv = vec![
            CString::new("./hello").unwrap(),
            CString::new("hello").unwrap(),
        ];
        let envp = vec![CString::new("PATH=/bin").unwrap()];
        let info = ElfLoader::load(executable_path, argv, envp).expect("failed to load executable");

        unsafe { trampoline(info.entry_point, info.user_stack_top) };
    }
}
