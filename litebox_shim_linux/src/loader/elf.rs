//! ELF loader for LiteBox

use core::{
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::{collections::btree_map::BTreeMap, ffi::CString, string::ToString, vec::Vec};
use elf_loader::{
    Elf, Loader,
    arch::ElfPhdr,
    mmap::{MapFlags, Mmap, ProtFlags},
    object::ElfObject,
};
use litebox::{
    fs::{Mode, OFlags},
    mm::linux::{CreatePagesFlags, MappingError, PAGE_SIZE},
    platform::{RawConstPointer as _, SystemInfoProvider as _, ThreadLocalStorageProvider as _},
    utils::TruncateExt,
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
            // A default low address is used for the binary (which grows upwards) to avoid
            // conflicts with the kernel's memory mappings (which grows downwards).
            addr.unwrap_or(0x1000_0000),
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

struct TrampolineHdr {
    /// The virtual memory of the trampoline code.
    vaddr: usize,
    /// The file offset of the trampoline code in the ELF file.
    file_offset: usize,
    /// Size of the trampoline code in the ELF file.
    size: usize,
}

/// Get the trampoline header from the ELF file.
fn get_trampoline_hdr(object: &mut ElfFile) -> Option<TrampolineHdr> {
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
        || trampoline_shdr_flags != elf::abi::SHF_ALLOC | elf::abi::SHF_EXECINSTR
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
    let file_size = crate::syscalls::file::sys_fstat(object.as_fd().unwrap())
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
    assert!(
        trampoline.vaddr % PAGE_SIZE == 0,
        "trampoline address must be page-aligned"
    );
    assert!(
        trampoline.file_offset % PAGE_SIZE == 0,
        "trampoline file offset must be page-aligned"
    );
    let start_addr = relo_off + trampoline.vaddr;
    let end_addr = (start_addr + trampoline.size).next_multiple_of(0x1000);
    let mut need_copy = false;
    unsafe {
        ElfLoaderMmap::mmap(
            Some(start_addr),
            end_addr - start_addr,
            elf_loader::mmap::ProtFlags::PROT_READ | elf_loader::mmap::ProtFlags::PROT_WRITE,
            elf_loader::mmap::MapFlags::MAP_PRIVATE | elf_loader::mmap::MapFlags::MAP_FIXED,
            trampoline.file_offset,
            Some(fd),
            &mut need_copy,
        )
    }
    .expect("failed to mmap trampoline section");
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
    #[allow(clippy::too_many_lines)]
    pub(super) fn load(
        path: &str,
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<ElfLoadInfo, ElfLoaderError> {
        let elf = {
            let mut loader = Loader::<ElfLoaderMmap>::new();
            // Set a hook to get the brk address (i.e., the end of the program's data segment) from the ELF file.
            loader.set_hook(alloc::boxed::Box::new(|name, phdr, segment, data| {
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
            let mut object = ElfFile::new(path).map_err(ElfLoaderError::OpenError)?;
            let file_fd = object.as_fd().unwrap();
            // Check if the file is modified by our syscall rewriter. If so, we need to update
            // the syscall callback pointer.
            let trampoline = get_trampoline_hdr(&mut object);
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
            elf
        };
        let interp: Option<Elf> = if let Some(interp_name) = elf.interp() {
            // e.g., /lib64/ld-linux-x86-64.so.2
            let mut loader = Loader::<ElfLoaderMmap>::new();
            let mut object = ElfFile::new(interp_name).map_err(ElfLoaderError::OpenError)?;
            let trampoline = get_trampoline_hdr(&mut object);
            let file_fd = object.as_fd().unwrap();
            let interp = loader
                .easy_load(object)
                .map_err(ElfLoaderError::LoaderError)?;

            if let Some(trampoline) = trampoline {
                load_trampoline(trampoline, interp.base(), file_fd);
            }
            Some(interp)
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

        let user_info = litebox_platform_multiplex::platform()
            .with_thread_local_storage_mut(|tls| (*tls.current_task.credentials).clone());
        aux.insert(AuxKey::AT_UID, user_info.uid);
        aux.insert(AuxKey::AT_EUID, user_info.euid);
        aux.insert(AuxKey::AT_GID, user_info.gid);
        aux.insert(AuxKey::AT_EGID, user_info.egid);

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
