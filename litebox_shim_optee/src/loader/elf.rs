//! ELF loader for LiteBox

use litebox::platform::{PunchthroughProvider, PunchthroughToken, RawMutPointer as _};
use litebox::{mm::linux::PAGE_SIZE, platform::RawConstPointer as _};
use litebox_common_linux::errno::Errno;
use litebox_common_linux::loader::ElfParsedFile;
use thiserror::Error;

use super::ElfLoadInfo;
use crate::MutPtr;

// An ELF file loaded in memory
#[derive(Clone)]
struct ElfFileInMemory<'a> {
    buffer: &'a [u8],
}

impl<'a> ElfFileInMemory<'a> {
    fn new(elf_buf: &'a [u8]) -> Self {
        Self { buffer: elf_buf }
    }
}

impl litebox_common_linux::loader::ReadAt for ElfFileInMemory<'_> {
    type Error = Errno;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        #[cfg(debug_assertions)]
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "ElfFileInMemory::read(buflen: {}, offset: {})",
            buf.len(),
            offset
        );
        let offset: usize = offset.try_into().map_err(|_| Errno::EINVAL)?;
        let src_slice = self
            .buffer
            .get(offset..)
            .ok_or(Errno::EINVAL)?
            .get(..buf.len())
            .ok_or(Errno::EINVAL)?;
        buf.copy_from_slice(src_slice);
        Ok(())
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        Ok(self.buffer.len() as u64)
    }
}

impl litebox_common_linux::loader::MapMemory for ElfFileInMemory<'_> {
    type Error = Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        let mapping_len = len + (align.max(PAGE_SIZE) - PAGE_SIZE);
        let mapping_ptr = crate::syscalls::mm::sys_mmap(
            DEFAULT_ELF_LOAD_BASE,
            mapping_len,
            litebox_common_linux::ProtFlags::PROT_NONE,
            litebox_common_linux::MapFlags::MAP_ANONYMOUS
                | litebox_common_linux::MapFlags::MAP_PRIVATE,
            -1,
            0,
        )?
        .as_usize();

        let ptr = mapping_ptr.next_multiple_of(align);
        let end = ptr + len;
        let mapping_end = mapping_ptr + mapping_len;
        if ptr != mapping_ptr {
            crate::syscalls::mm::sys_munmap(MutPtr::from_usize(mapping_ptr), ptr - mapping_ptr)?;
        }
        if end != mapping_end {
            crate::syscalls::mm::sys_munmap(MutPtr::from_usize(end), mapping_end - end)?;
        }
        Ok(ptr)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        #[cfg(debug_assertions)]
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "ElfLoaderMmap::mmap(addr: {:#x?}, len: {}, prot: {:?}, offset: {:#x}, buffer_len: {:#x})",
            address,
            len,
            prot,
            offset,
            self.buffer.len(),
        );

        // The other inputs are validated by `map_zero`.
        if !offset.is_multiple_of(PAGE_SIZE as u64) {
            return Err(Errno::EINVAL);
        }

        // Map the region as writable first.
        self.map_zero(
            address,
            len,
            &litebox_common_linux::loader::Protection {
                read: true,
                write: true,
                execute: false,
            },
        )?;
        // Write the data from the ELF file. Treat mapping beyond the file size as zeros.
        let data = if let Ok(offset) = offset.try_into() {
            self.buffer.get(offset..).unwrap_or(&[])
        } else {
            &[]
        };
        MutPtr::from_usize(address)
            .copy_from_slice(0, &data[..len.min(data.len())])
            .ok_or(Errno::EFAULT)?;
        // Set the final protections.
        self.protect(address, len, prot)?;
        Ok(())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        crate::syscalls::mm::sys_mmap(
            address,
            len,
            prot.flags(),
            litebox_common_linux::MapFlags::MAP_ANONYMOUS
                | litebox_common_linux::MapFlags::MAP_PRIVATE
                | litebox_common_linux::MapFlags::MAP_FIXED,
            -1,
            0,
        )?;
        Ok(())
    }

    fn protect(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        crate::syscalls::mm::sys_mprotect(MutPtr::from_usize(address), len, prot.flags())
    }
}

const DEFAULT_ELF_LOAD_BASE: usize = (1 << 46) - PAGE_SIZE;

/// Loader for ELF files
pub(super) struct ElfLoader;

impl ElfLoader {
    // Load an ELF file for the new process.
    pub(super) fn load_buffer(elf_buf: &[u8]) -> Result<ElfLoadInfo, ElfLoaderError> {
        let platform = litebox_platform_multiplex::platform();
        let mut file = ElfFileInMemory::new(elf_buf);

        #[cfg_attr(not(feature = "platform_linux_userland"), expect(unused_mut))]
        let mut parsed = ElfParsedFile::parse(&mut file)?;

        #[cfg(feature = "platform_linux_userland")]
        parsed.parse_trampoline(
            &mut file,
            litebox::platform::SystemInfoProvider::get_syscall_entry_point(platform),
        )?;

        // Since LiteBox does not use ldelf or libc for OP-TEE TAs, it should relocate the TA ELF's symbols.
        let info = parsed.load_and_relocate(&mut file, &mut &*platform)?;
        let entry = info.entry_point;
        let base = info.base_addr;

        // Initialize the guest TLS for an OP-TEE TA.
        // Typically, the loader (e.g., OP-TEE's ldelf) or libc initializes the guest TLS before
        // calling the main function. However, currently, LiteBox does not use ldelf or libc for
        // OP-TEE TAs such that no guest code attempts to initialize the guest TLS.
        // To avoid this problem, `litebox_shim_optee` initializes the guest TLS by
        // allocating a guest page and programming the FS base to point to the allocated page.
        // Note that we use `PunchthroughSyscall::SetFsBase` for this purpose not to deal with
        // the underlying platform behaviors.
        // Two alternatives:
        // 1) Initialize the guest TLS at the runner.
        // 2) Write a minimal ldelf and bundle it with each OP-TEE TA.
        let addr = crate::syscalls::mm::sys_mmap(
            0,
            PAGE_SIZE,
            litebox_common_linux::ProtFlags::PROT_READ
                | litebox_common_linux::ProtFlags::PROT_WRITE,
            litebox_common_linux::MapFlags::MAP_PRIVATE
                | litebox_common_linux::MapFlags::MAP_ANONYMOUS
                | litebox_common_linux::MapFlags::MAP_FIXED
                | litebox_common_linux::MapFlags::MAP_POPULATE,
            -1,
            0,
        );
        let punchthrough = litebox_common_linux::PunchthroughSyscall::SetFsBase {
            addr: addr.unwrap().as_usize(),
        };
        let token = litebox_platform_multiplex::platform()
            .get_punchthrough_token_for(punchthrough)
            .expect("Failed to get punchthrough token for SET_FS");
        let _ = token.execute().map(|_| ()).map_err(|e| match e {
            litebox::platform::PunchthroughError::Failure(errno) => errno,
            _ => unimplemented!("Unsupported punchthrough error {:?}", e),
        });

        let stack = crate::loader::ta_stack::allocate_stack(None).unwrap_or_else(|| {
            panic!("Failed to allocate stack");
        });

        #[cfg(debug_assertions)]
        litebox::log_println!(
            platform,
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
        })
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum ElfLoaderError {
    #[error("failed to open the ELF file: {0}")]
    OpenError(#[from] Errno),
    #[error("failed to load the ELF file: {0}")]
    ParseError(#[from] litebox_common_linux::loader::ElfParseError<Errno>),
    #[error("failed to map the ELF file: {0}")]
    LoadError(#[from] litebox_common_linux::loader::ElfLoadError<Errno>),
}

impl From<ElfLoaderError> for litebox_common_linux::errno::Errno {
    fn from(value: ElfLoaderError) -> Self {
        match value {
            ElfLoaderError::OpenError(e) => e,
            ElfLoaderError::ParseError(e) => e.into(),
            ElfLoaderError::LoadError(e) => e.into(),
        }
    }
}
