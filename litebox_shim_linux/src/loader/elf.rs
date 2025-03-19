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
    fs::{Mode, OFlags, errors::OpenError},
    mm::linux::{MappingError, PAGE_SIZE},
    platform::{RawConstPointer, RawMutPointer},
};
use thiserror::Error;

use crate::{MutPtr, litebox_vmm, sys_open, syscalls::read::sys_read};

use super::stack::{AuxKey, UserStack};

// An opened elf file
struct ElfFile {
    name: CString,
    fd: i32,
}

impl ElfFile {
    fn from_path(path: &str) -> Result<Self, OpenError> {
        let fd = sys_open(path, OFlags::RDONLY, Mode::empty())?;

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
        match sys_read(self.fd, buf, Some(offset)) {
            Ok(_) => Ok(()),
            Err(_) => Err(elf_loader::Error::IOError {
                msg: "failed to read from file".to_string(),
            }),
        }
    }

    fn as_fd(&self) -> Option<i32> {
        Some(self.fd)
    }
}

/// [`elf_loader::mmap::Mmap`] implementation for ELF loader
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
        fd: i32,
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
                sys_read(fd, user_buf, Some(offset))
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
            Self::do_mmap_file(addr, len, prot, flags, fd, offset)?
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
enum ElfLoaderError {
    #[error("failed to open the ELF file: {0}")]
    OpenError(#[from] OpenError),
    #[error("failed to load the ELF file: {0}")]
    LoaderError(#[from] elf_loader::Error),
    #[error("invalid stack")]
    InvalidStackAddr,
    #[error("failed to mmap: {0}")]
    MappingError(#[from] MappingError),
}

#[cfg(test)]
mod tests {
    use core::{arch::global_asm, str::FromStr as _};

    use alloc::{ffi::CString, vec};
    use litebox::{
        fs::{FileSystem as _, Mode, OFlags},
        platform::trivial_providers::ImpossiblePunchthroughProvider,
    };
    use litebox_platform_multiplex::{Platform, set_platform};

    use crate::{litebox_fs, set_fs};

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

    unsafe extern "C" {
        fn trampoline(entry: usize, sp: usize) -> !;
    }

    fn init_platform() {
        static ONCE: spin::Once = spin::Once::new();
        ONCE.call_once(|| {
            let platform = unsafe { Platform::new_for_test(ImpossiblePunchthroughProvider {}) };
            set_platform(platform);

            let mut in_mem_fs =
                litebox::fs::in_mem::FileSystem::new(litebox_platform_multiplex::platform());
            in_mem_fs.with_root_privileges(|fs| {
                fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                    .expect("Failed to set permissions on root");
            });
            set_fs(in_mem_fs);

            install_dir("/lib64");
        });
    }

    fn compile(output: &std::path::Path, exec_or_lib: bool) {
        // Compile the hello.c file to an executable
        let mut args = vec!["-o", output.to_str().unwrap(), "./tests/hello.c"];
        if exec_or_lib {
            args.push("-static");
        }
        let output = std::process::Command::new("gcc")
            .args(args)
            .output()
            .expect("Failed to compile hello.c");
        assert!(
            output.status.success(),
            "failed to compile hello.c {:?}",
            output.stderr
        );
    }

    fn install_dir(path: &str) {
        litebox_fs()
            .mkdir(path, Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to create directory");
    }

    fn install_file(path: &std::path::PathBuf, out: &str) {
        let fd = litebox_fs()
            .open(
                out,
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXG | Mode::RWXO | Mode::RWXU,
            )
            .unwrap();
        let contents = std::fs::read(path).unwrap();
        litebox_fs().write(&fd, &contents, None).unwrap();
        litebox_fs().close(fd).unwrap();
    }

    fn test_load_exec_common(executable_path: &str) {
        let argv = vec![
            CString::new(executable_path).unwrap(),
            CString::new("hello").unwrap(),
        ];
        let envp = vec![CString::new("PATH=/bin").unwrap()];
        let info = super::ElfLoader::load(executable_path, argv, envp).unwrap();

        unsafe { trampoline(info.entry_point, info.user_stack_top) };
    }

    #[test]
    fn test_load_exec_dynamic() {
        init_platform();

        let path =
            std::path::Path::new(std::env::var("OUT_DIR").unwrap().as_str()).join("hello_dylib");
        compile(&path, false);

        let executable_path = "/hello_dylib";
        install_file(&path, executable_path);
        install_file(
            &std::path::PathBuf::from_str("/lib64/ld-linux-x86-64.so.2").unwrap(),
            "/lib64/ld-linux-x86-64.so.2",
        );

        test_load_exec_common(executable_path);
    }

    #[test]
    fn test_load_exec_static() {
        init_platform();

        let path =
            std::path::Path::new(std::env::var("OUT_DIR").unwrap().as_str()).join("hello_exec");
        compile(&path, true);

        let executable_path = "/hello_exec";
        install_file(&path, executable_path);

        test_load_exec_common(executable_path);
    }
}
