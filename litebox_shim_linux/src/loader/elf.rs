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

use crate::{
    litebox_page_manager,
    loader::auxv::{AuxKey, AuxVec},
};

use super::stack::UserStack;
use crate::Task;
use crate::with_current_task;

// An opened elf file
struct ElfFile<'a> {
    task: &'a Task,
    name: CString,
    fd: i32,
}

impl<'a> ElfFile<'a> {
    fn new(task: &'a Task, path: &str) -> Result<Self, Errno> {
        let name = CString::new(path).unwrap();
        let fd = task.sys_open(path, OFlags::RDONLY, Mode::empty())?;
        let Ok(fd) = i32::try_from(fd) else {
            unreachable!("fd should be a valid i32");
        };

        Ok(Self { task, name, fd })
    }
}

impl ElfObject for ElfFile<'_> {
    fn file_name(&self) -> &core::ffi::CStr {
        &self.name
    }

    fn read(&mut self, mut buf: &mut [u8], mut offset: usize) -> elf_loader::Result<()> {
        loop {
            if buf.is_empty() {
                return Ok(());
            }
            // Try to read the remaining bytes
            match self.task.sys_read(self.fd, buf, Some(offset)) {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        // reached the end of the file
                        return Err(elf_loader::Error::MmapError {
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
                    return Err(elf_loader::Error::MmapError {
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
struct ElfLoaderMmap<'a>(&'a Task);

impl ElfLoaderMmap<'_> {
    fn do_mmap_file(
        &self,
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
        match self.0.sys_mmap(
            addr.unwrap_or(super::DEFAULT_LOW_ADDR),
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
        &self,
        addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> elf_loader::Result<usize> {
        match self.0.sys_mmap(
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

impl elf_loader::mmap::Mmap for ElfLoaderMmap<'_> {
    unsafe fn mmap(
        addr: Option<usize>,
        len: usize,
        prot: elf_loader::mmap::ProtFlags,
        flags: elf_loader::mmap::MapFlags,
        offset: usize,
        fd: Option<i32>,
        need_copy: &mut bool,
    ) -> elf_loader::Result<NonNull<core::ffi::c_void>> {
        // TODO: fix upstream elf_loader to add &self parameter to avoid using TLS here.
        with_current_task(|task| {
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
                ElfLoaderMmap(task).do_mmap_file(addr, len, prot, flags, fd, offset)?
            } else {
                // No file provided because it is a blob.
                // Set `need_copy` so that the loader will copy the memory
                // to the new address space.
                *need_copy = true;
                ElfLoaderMmap(task).do_mmap_anonymous(addr, len, prot, flags)?
            };
            Ok(NonNull::new(ptr as _).expect("null pointer"))
        })
    }

    unsafe fn mmap_anonymous(
        addr: usize,
        len: usize,
        prot: elf_loader::mmap::ProtFlags,
        flags: elf_loader::mmap::MapFlags,
    ) -> elf_loader::Result<NonNull<core::ffi::c_void>> {
        with_current_task(|task| {
            let addr = if addr == 0 { None } else { Some(addr) };
            let ptr = ElfLoaderMmap(task).do_mmap_anonymous(addr, len, prot, flags)?;
            Ok(NonNull::new(ptr as _).expect("null pointer"))
        })
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

#[repr(C, packed)]
struct TrampolineSection {
    magic_number: u64,
    trampoline_addr: u64,
    trampoline_size: u64,
}

#[derive(Debug)]
struct TrampolineHdr {
    /// The virtual memory of the trampoline code.
    vaddr: usize,
    /// The file offset of the trampoline code in the ELF file.
    file_offset: usize,
    /// Size of the trampoline code in the ELF file.
    size: usize,
}

/// Get the trampoline header from the ELF file.
fn get_trampoline_hdr(task: &Task, object: &mut ElfFile) -> Option<TrampolineHdr> {
    let mut buf: [u8; size_of::<Ehdr>()] = [0; size_of::<Ehdr>()];
    object.read(&mut buf, 0).unwrap();
    let elfhdr: &Ehdr = unsafe { &*(buf.as_ptr().cast()) };

    // read section headers
    let shdrs_size = usize::from(elfhdr.e_shentsize) * usize::from(elfhdr.e_shnum.checked_sub(1)?);
    let mut buf: [u8; size_of::<Shdr>()] = [0; size_of::<Shdr>()];
    // Read the last section header because our syscall rewriter adds a trampoline section at the end.
    object
        .read(
            &mut buf,
            usize::try_from(elfhdr.e_shoff).unwrap() + shdrs_size,
        )
        .unwrap();
    let trampoline_shdr: &Shdr = unsafe { &*(buf.as_ptr().cast()) };
    let trampoline_shdr_flags: u32 = trampoline_shdr.sh_flags.truncate();
    if trampoline_shdr.sh_type != elf::abi::SHT_PROGBITS
        || trampoline_shdr_flags != elf::abi::SHF_ALLOC
    {
        return None;
    }

    if trampoline_shdr.sh_size < size_of::<TrampolineSection>().try_into().unwrap() {
        return None;
    }
    let mut buf: [u8; size_of::<TrampolineSection>()] = [0; size_of::<TrampolineSection>()];
    object
        .read(
            &mut buf,
            usize::try_from(trampoline_shdr.sh_offset).unwrap(),
        )
        .ok()?;
    let trampoline: TrampolineSection = unsafe { core::mem::transmute(buf) };
    // TODO: check section name instead of magic number
    if trampoline.magic_number != super::REWRITER_MAGIC_NUMBER {
        return None;
    }
    // The trampoline code is placed at the end of the file.
    let file_size = task
        .sys_fstat(object.as_fd().unwrap())
        .expect("failed to get file stat")
        .st_size;
    Some(TrampolineHdr {
        vaddr: usize::try_from(trampoline.trampoline_addr).ok()?,
        file_offset: file_size - usize::try_from(trampoline.trampoline_size).unwrap(),
        size: usize::try_from(trampoline.trampoline_size).unwrap(),
    })
}

fn load_trampoline(trampoline: TrampolineHdr, relo_off: usize, fd: i32) -> usize {
    // Our rewriter ensures that both `trampoline.vaddr` and `trampoline.file_offset` are page-aligned.
    // Otherwise, `ElfLoaderMmap::mmap` will fail and panic.
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "Loading trampoline {:?}",
        trampoline
    );
    assert!(
        trampoline.vaddr.is_multiple_of(PAGE_SIZE),
        "trampoline address must be page-aligned"
    );
    assert!(
        trampoline.file_offset.is_multiple_of(PAGE_SIZE),
        "trampoline file offset must be page-aligned"
    );
    let start_addr = relo_off + trampoline.vaddr;
    let end_addr = (start_addr + trampoline.size).next_multiple_of(0x1000);
    let mut need_copy = false;
    let ret = unsafe {
        ElfLoaderMmap::mmap(
            Some(start_addr),
            end_addr - start_addr,
            elf_loader::mmap::ProtFlags::PROT_READ | elf_loader::mmap::ProtFlags::PROT_WRITE,
            elf_loader::mmap::MapFlags::MAP_PRIVATE,
            trampoline.file_offset,
            Some(fd),
            &mut need_copy,
        )
    }
    .expect("failed to mmap trampoline section");
    assert_eq!(
        start_addr,
        ret.as_ptr() as usize,
        "trampoline mapping address is taken"
    );
    // The first 8 bytes of the data is the magic number,
    let version_number = start_addr as *const u64;
    assert_eq!(
        unsafe { version_number.read() },
        super::REWRITER_VERSION_NUMBER,
        "trampoline section version number mismatch"
    );
    let placeholder = (start_addr + 8) as *mut usize;
    unsafe {
        placeholder.write(litebox_platform_multiplex::platform().get_syscall_entry_point());
    }
    let ptr = crate::MutPtr::from_usize(start_addr);
    let pm = litebox_page_manager();
    unsafe { pm.make_pages_executable(ptr, end_addr - start_addr) }
        .expect("failed to make pages executable");
    end_addr
}

const KEY_BRK: u8 = 0x01;

/// Loader for ELF files
pub(super) struct ElfLoader;

impl ElfLoader {
    fn init_auxvec_with_elf(aux: &mut AuxVec, elf: &Elf) {
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
    }

    /// Load an ELF file and prepare the stack for the new process.
    pub(super) fn load(
        task: &Task,
        path: &str,
        argv: Vec<CString>,
        envp: Vec<CString>,
        mut aux: AuxVec,
    ) -> Result<ElfLoadInfo, ElfLoaderError> {
        let elf = {
            let mut loader = Loader::<ElfLoaderMmap>::new();
            // Set a hook to get the brk address (i.e., the end of the program's data segment) from the ELF file.
            loader.set_hook(alloc::boxed::Box::new(|_name, phdr, _segment, data| {
                let end: usize = usize::try_from(phdr.p_vaddr + phdr.p_memsz).unwrap();
                if let Some(elf_brk) = data.get(KEY_BRK) {
                    let elf_brk = elf_brk.downcast_ref::<AtomicUsize>().unwrap();
                    if elf_brk.load(Ordering::Relaxed) < end {
                        // Update the brk to the end of the segment
                        elf_brk.store(end, Ordering::Relaxed);
                    }
                } else {
                    // Create a new brk for the segment
                    data.insert(KEY_BRK, alloc::boxed::Box::new(AtomicUsize::new(end)));
                }
                Ok(())
            }));
            let mut object = ElfFile::new(task, path).map_err(ElfLoaderError::OpenError)?;
            let file_fd = object.as_fd().unwrap();
            // Check if the file is modified by our syscall rewriter. If so, we need to update
            // the syscall callback pointer.
            let trampoline = get_trampoline_hdr(task, &mut object);
            let elf = loader
                .easy_load(object)
                .map_err(ElfLoaderError::LoaderError)?;

            let end_of_trampoline = if let Some(trampoline) = trampoline {
                load_trampoline(trampoline, elf.base(), file_fd)
            } else {
                0
            };
            let base = elf.base();
            let brk = elf
                .user_data()
                .get(KEY_BRK)
                .unwrap()
                .downcast_ref::<AtomicUsize>()
                .unwrap()
                .load(Ordering::Relaxed);
            let init_brk =
                core::cmp::max((base + brk).next_multiple_of(PAGE_SIZE), end_of_trampoline);
            unsafe { litebox_page_manager().brk(init_brk) }.expect("failed to set brk");
            task.sys_close(file_fd).expect("failed to close fd");
            elf
        };
        let interp: Option<Elf> = if let Some(interp_name) = elf.interp() {
            // e.g., /lib64/ld-linux-x86-64.so.2
            let mut loader = Loader::<ElfLoaderMmap>::new();
            let mut object = ElfFile::new(task, interp_name).map_err(ElfLoaderError::OpenError)?;
            let trampoline = get_trampoline_hdr(task, &mut object);
            let file_fd = object.as_fd().unwrap();
            let interp = loader
                .easy_load(object)
                .map_err(ElfLoaderError::LoaderError)?;

            if let Some(trampoline) = trampoline {
                load_trampoline(trampoline, interp.base(), file_fd);
            }
            task.sys_close(file_fd).expect("failed to close fd");
            Some(interp)
        } else {
            None
        };

        Self::init_auxvec_with_elf(&mut aux, &elf);
        let entry = if let Some(ld) = interp {
            aux.insert(AuxKey::AT_BASE, ld.base());
            ld.entry()
        } else {
            elf.entry()
        };

        let sp = unsafe {
            let length = litebox::mm::linux::NonZeroPageSize::new(super::DEFAULT_STACK_SIZE)
                .expect("DEFAULT_STACK_SIZE is not page-aligned");
            litebox_page_manager()
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(ElfLoaderError::MappingError)?
        };
        let mut stack = UserStack::new(sp, super::DEFAULT_STACK_SIZE)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;
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
