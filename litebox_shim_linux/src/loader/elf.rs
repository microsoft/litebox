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
    mm::mapping::{MappingError, MappingProvider},
    platform::RawMutPointer,
};

use crate::{MutPtr, file_descriptors, litebox_fs, litebox_vmm};

use super::stack::{AuxKey, UserStack};

struct ElfFile {
    name: CString,
    fd: i32,
}

impl ElfFile {
    pub(super) fn from_path(path: &str) -> Result<Self, OpenError> {
        let file = litebox_fs().open(path, OFlags::RDWR, Mode::empty())?;
        let fd = file_descriptors()
            .write()
            .insert(crate::Descriptor::File(file))
            .try_into()
            .unwrap();

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
        if let Some(file) = file_descriptors().read().get_file_fd(self.fd as u32) {
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
        Some(self.fd)
    }
}

struct ElfLoaderMmap;

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
        // This is called when dropping the loader. We need to unmap the memory when the program exits.
        Ok(())
    }

    unsafe fn mprotect(
        addr: NonNull<core::ffi::c_void>,
        len: usize,
        prot: elf_loader::mmap::ProtFlags,
    ) -> elf_loader::Result<()> {
        todo!()
    }
}

struct ElfLoadInfo {
    entry_point: usize,
    user_stack_top: usize,
}

struct ElfLoader;

impl ElfLoader {
    fn init_auxvec(elf: &Elf) -> BTreeMap<AuxKey, usize> {
        let mut aux = BTreeMap::new();
        let phdrs = elf.phdrs();
        // TODO: where should we get this value?
        aux.insert(AuxKey::AT_PAGESZ, 0x1000);
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

    fn load(
        path: &str,
        argv: Vec<CString>,
        envp: Vec<CString>,
        stack_top_vaddr: usize,
    ) -> Result<ElfLoadInfo, ()> {
        let elf = {
            let mut loader = Loader::<ElfLoaderMmap>::new();
            loader.easy_load(ElfFile::from_path(path).unwrap()).unwrap()
        };
        let interp: Option<Elf> = if let Some(interp_name) = elf.interp() {
            // e.g., /lib64/ld-linux-x86-64.so.2
            let mut loader = Loader::<ElfLoaderMmap>::new();
            loader
                .easy_load(ElfFile::from_path(interp_name).unwrap())
                .ok()
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

        let stack = UserStack::new(stack_top_vaddr);
        let pos = stack.init(argv, envp, aux).unwrap();

        Ok(ElfLoadInfo {
            entry_point: entry,
            user_stack_top: stack_top_vaddr.checked_add_signed(pos).unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ElfLoader;
    use crate::{litebox_fs, set_vmm};
    use alloc::vec;
    use alloc::{ffi::CString, string::String};
    use core::arch::global_asm;
    use litebox::{
        fs::{FileSystem, Mode, OFlags},
        platform::trivial_providers::ImpossiblePunchthroughProvider,
    };
    use litebox_platform_multiplex::{Platform, VMem, set_platform};

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

    #[repr(align(4096))]
    struct Stack([u8; 8192]);
    static mut TEST_EXEC_STACK: Stack = Stack([0; 8192]);

    fn init_platform() {
        static ONCE: spin::Once = spin::Once::new();
        ONCE.call_once(|| {
            let platform = Platform::new("tun0", ImpossiblePunchthroughProvider {}, true);
            set_platform(platform);

            let vmm = VMem::new();
            set_vmm(vmm);
        });
    }

    fn compile(path: &std::path::PathBuf) {
        // Compile the hello.c file to an executable
        let output = std::process::Command::new("gcc")
            .arg("-o")
            .arg(path.to_str().unwrap())
            .arg("./src/loader/hello.c")
            .arg("-static")
            .output()
            .expect("Failed to compile hello.c");
        if !output.status.success() {
            panic!(
                "Failed to compile hello.c: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
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
        init_platform();

        // no std::env::var("OUT_DIR").unwrap()??
        let path = std::path::PathBuf::from("../target/debug").join("hello");
        compile(&path);

        let executable_path = "/hello";
        install_file(&path, executable_path);

        #[allow(static_mut_refs)]
        let sp: *mut u8 = unsafe { TEST_EXEC_STACK.0.as_mut_ptr().add(TEST_EXEC_STACK.0.len()) };
        let argv = vec![
            CString::new("./hello").unwrap(),
            CString::new("hello").unwrap(),
        ];
        let envp = vec![CString::new("PATH=/bin").unwrap()];

        let info = ElfLoader::load(executable_path, argv, envp, sp as usize)
            .expect("failed to load executable");
        unsafe extern "C" {
            fn trampoline(entry: usize, sp: usize) -> !;
        }

        unsafe { trampoline(info.entry_point, info.user_stack_top) };
    }
}
