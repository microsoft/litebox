//! ELF loader for LiteBox

use alloc::{ffi::CString, string::ToString};
use core::ptr::NonNull;
use elf_loader::{
    Loader,
    mmap::{MapFlags, ProtFlags},
    object::ElfObject,
};
use hashbrown::HashMap;
use litebox::platform::{PunchthroughProvider, PunchthroughToken};
use litebox::{
    mm::linux::{MappingError, PAGE_SIZE},
    platform::RawConstPointer as _,
};
use litebox_common_linux::errno::Errno;
use once_cell::race::OnceBox;
use thiserror::Error;

use super::ElfLoadInfo;
use crate::UserMutPtr;

#[cfg(feature = "platform_linux_userland")]
use crate::litebox_page_manager;
#[cfg(feature = "platform_linux_userland")]
use elf_loader::mmap::Mmap;
#[cfg(feature = "platform_linux_userland")]
use litebox::platform::SystemInfoProvider;
#[cfg(feature = "platform_linux_userland")]
use litebox::utils::TruncateExt;

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

    /// This function finds the ELF file in memory by its fd and reads the content
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

    #[allow(dead_code)]
    fn size(&self) -> usize {
        self.buffer.len()
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
        let src_slice = &self.buffer[offset..];
        let copy_len = src_slice.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&src_slice[..copy_len]);
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
            litebox_common_linux::ProtFlags::from_bits(prot.bits()).ok_or(
                elf_loader::Error::MmapError {
                    msg: "unsupported prot flags".to_string(),
                },
            )?,
            litebox_common_linux::MapFlags::from_bits(
                flags.bits() | MapFlags::MAP_ANONYMOUS.bits(),
            )
            .ok_or(elf_loader::Error::MmapError {
                msg: "unsupported map flags".to_string(),
            })?,
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
            let mapped_addr = Self::do_mmap_anonymous(
                addr.or(Some(DEFAULT_ELF_LOAD_BASE)),
                len,
                temp_prot,
                flags,
            )?;
            let mapped_slice: &mut [u8] =
                unsafe { core::slice::from_raw_parts_mut(mapped_addr as *mut u8, len) };
            let fd_elf_map = fd_elf_map();
            fd_elf_map
                .read(mapped_slice, offset, fd)
                .expect("fd_elf_map.read failed");

            crate::syscalls::mm::sys_mprotect(
                UserMutPtr::from_usize(mapped_addr),
                len,
                litebox_common_linux::ProtFlags::from_bits(prot.bits()).ok_or(
                    elf_loader::Error::MmapError {
                        msg: "unsupported prot flags".to_string(),
                    },
                )?,
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

#[cfg(feature = "platform_linux_userland")]
#[cfg(target_arch = "x86_64")]
type Ehdr = elf::file::Elf64_Ehdr;
#[cfg(feature = "platform_linux_userland")]
#[cfg(target_arch = "x86")]
type Ehdr = elf::file::Elf32_Ehdr;
#[cfg(feature = "platform_linux_userland")]
#[cfg(target_arch = "x86_64")]
type Shdr = elf::section::Elf64_Shdr;
#[cfg(feature = "platform_linux_userland")]
#[cfg(target_arch = "x86")]
type Shdr = elf::section::Elf32_Shdr;

#[cfg(feature = "platform_linux_userland")]
#[repr(C, packed)]
struct TrampolineSection {
    magic_number: u64,
    trampoline_addr: u64,
    trampoline_size: u64,
}

#[cfg(feature = "platform_linux_userland")]
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
#[cfg(feature = "platform_linux_userland")]
fn get_trampoline_hdr(object: &mut ElfFileInMemory) -> Option<TrampolineHdr> {
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
    let trampoline = unsafe { &*buf.as_ptr().cast::<TrampolineSection>() };
    // TODO: check section name instead of magic number
    if trampoline.magic_number != super::REWRITER_MAGIC_NUMBER {
        return None;
    }
    // The trampoline code is placed at the end of the file.
    let file_size = object.size();
    Some(TrampolineHdr {
        vaddr: usize::try_from(trampoline.trampoline_addr).ok()?,
        file_offset: file_size - usize::try_from(trampoline.trampoline_size).unwrap(),
        size: usize::try_from(trampoline.trampoline_size).unwrap(),
    })
}

#[cfg(feature = "platform_linux_userland")]
fn load_trampoline(trampoline: TrampolineHdr, relo_off: usize, fd: i32) -> usize {
    // Our rewriter ensures that both `trampoline.vaddr` and `trampoline.file_offset` are page-aligned.
    // Otherwise, `ElfLoaderMmap::mmap` will fail and panic.
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "Loading trampoline {:?} with relo_off {:#x}",
        trampoline,
        relo_off,
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
    let end_addr = (start_addr + trampoline.size).next_multiple_of(PAGE_SIZE);
    let mut need_copy = false;
    // TODO: For now, we unmap `ldelf`'s memory area to load the trampoline.
    // TAs might interact with `ldelf` to use its critical syscalls, so we might need to
    // figure out how to deal with this potential memory area overlap.
    let _ =
        crate::syscalls::mm::sys_munmap(UserMutPtr::from_usize(start_addr), end_addr - start_addr);
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
    let ptr = UserMutPtr::from_usize(start_addr);
    let pm = litebox_page_manager();
    unsafe { pm.make_pages_executable(ptr, end_addr - start_addr) }
        .expect("failed to make pages executable");
    end_addr
}

/// Allocate the guest TLS for an OP-TEE TA.
/// This function is required to overcome the compatibility issue coming from
/// system and build toolchain differences. OP-TEE OS only supports a single thread and
/// thus does not explicitly set up the TLS area. In contrast, we do use an x86 toolchain to
/// compile OP-TEE TAs and this toolchain assumes there is a valid TLS areas for various purposes
/// including stack protection. To this end, the toolchain generates binaries using
/// the `FS` register for TLS access.
/// This function allocates a TLS area on behalf of the TA to satisfy the toolchain's assumption.
/// Instead of using this function, we could change the flags of the toolchain to not use TLS
/// (e.g., `-fno-stack-protector`), but this might be insecure. Also, the toolchain might have
/// other features relying on TLS.
#[cfg(target_arch = "x86_64")]
pub(super) fn allocate_guest_tls(
    tls_size: Option<usize>,
) -> Result<(), litebox_common_linux::errno::Errno> {
    let tls_size = tls_size.unwrap_or(PAGE_SIZE).next_multiple_of(PAGE_SIZE);
    let addr = crate::syscalls::mm::sys_mmap(
        0,
        tls_size,
        litebox_common_linux::ProtFlags::PROT_READ | litebox_common_linux::ProtFlags::PROT_WRITE,
        litebox_common_linux::MapFlags::MAP_PRIVATE
            | litebox_common_linux::MapFlags::MAP_ANONYMOUS
            | litebox_common_linux::MapFlags::MAP_POPULATE,
        -1,
        0,
    )?;
    let punchthrough = litebox_common_linux::PunchthroughSyscall::SetFsBase {
        addr: addr.as_usize(),
    };
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(punchthrough)
        .expect("Failed to get punchthrough token for SET_FS");
    let _ = token.execute().map(|_| ()).map_err(|e| match e {
        litebox::platform::PunchthroughError::Failure(errno) => errno,
        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
    });
    Ok(())
}

const DEFAULT_ELF_LOAD_BASE: usize = (1 << 46) - PAGE_SIZE;

/// Loader for ELF files
pub(super) struct ElfLoader;

impl ElfLoader {
    // Load an ELF file for the new process.
    pub(super) fn load_buffer(elf_buf: &[u8]) -> Result<ElfLoadInfo, ElfLoaderError> {
        let mut loader = Loader::<ElfLoaderMmap>::new();

        let fd_elf_map = fd_elf_map();
        let fd = fd_elf_map
            .register_elf(elf_buf)
            .map_err(ElfLoaderError::OpenError)?;
        #[allow(unused_mut)]
        let mut object = fd_elf_map
            .get(fd)
            .ok_or(ElfLoaderError::OpenError(Errno::ENOENT))?;

        #[cfg(feature = "platform_linux_userland")]
        let trampoline = get_trampoline_hdr(&mut object);

        let elf = loader
            .easy_load(object)
            .map_err(ElfLoaderError::LoaderError)?;

        let entry = elf.entry();
        let base = elf.base();

        #[cfg(feature = "platform_linux_userland")]
        if let Some(trampoline) = trampoline {
            load_trampoline(trampoline, base, fd);
        }

        fd_elf_map
            .remove(fd)
            .expect("fd_elf_map.remove(fd) should return Some(ElfFileInMemory)");

        let stack = crate::loader::ta_stack::allocate_stack(None).unwrap_or_else(|| {
            panic!("Failed to allocate stack");
        });

        #[cfg(debug_assertions)]
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "entry = {:#x}, base = {:#x}, stack_base = {:#x}, params_address = {:#x}",
            entry,
            base,
            stack.get_stack_base(),
            stack.get_params_address()
        );

        Ok(ElfLoadInfo {
            entry_point: entry,
            stack_base: stack.get_stack_base(),
            params_address: stack.get_params_address(),
            ldelf_arg_address: Some(stack.get_ldelf_arg_address()),
        })
    }

    #[cfg(feature = "platform_linux_userland")]
    pub(super) fn load_trampoline(elf_buf: &[u8], base: usize) -> Result<(), ElfLoaderError> {
        let fd_elf_map = fd_elf_map();
        let fd = fd_elf_map
            .register_elf(elf_buf)
            .map_err(ElfLoaderError::OpenError)?;
        #[allow(unused_mut)]
        let mut object = fd_elf_map
            .get(fd)
            .ok_or(ElfLoaderError::OpenError(Errno::ENOENT))?;

        let trampoline = get_trampoline_hdr(&mut object);

        if let Some(trampoline) = trampoline {
            load_trampoline(trampoline, base, fd);
        }

        fd_elf_map
            .remove(fd)
            .expect("fd_elf_map.remove(fd) should return Some(ElfFileInMemory)");

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum ElfLoaderError {
    #[error("failed to open the ELF file: {0}")]
    OpenError(#[from] Errno),
    #[error("failed to load the ELF file: {0}")]
    LoaderError(#[from] elf_loader::Error),
    #[error("failed to mmap: {0}")]
    MappingError(#[from] MappingError),
}

impl From<ElfLoaderError> for litebox_common_linux::errno::Errno {
    fn from(value: ElfLoaderError) -> Self {
        match value {
            ElfLoaderError::OpenError(e) => e,
            ElfLoaderError::LoaderError(_) => litebox_common_linux::errno::Errno::EINVAL,
            ElfLoaderError::MappingError(_) => litebox_common_linux::errno::Errno::ENOMEM,
        }
    }
}
