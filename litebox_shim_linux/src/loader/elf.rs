// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ELF loader for LiteBox

use alloc::{ffi::CString, vec::Vec};
use litebox::{
    fs::{Mode, OFlags},
    mm::linux::{CreatePagesFlags, MappingError, PAGE_SIZE},
    utils::{ReinterpretSignedExt, TruncateExt},
};
use litebox_common_linux::{MapFlags, errno::Errno, loader::ElfParsedFile};
use thiserror::Error;

use crate::{
    UserPtrMut,
    loader::auxv::{AuxKey, AuxVec},
};

use super::stack::UserStack;
use crate::{ShimPlatform, Task};

// An opened elf file
struct ElfFile<'a, Platform: ShimPlatform> {
    task: &'a Task<Platform>,
    fd: i32,
    load_high: bool,
}

impl<'a, Platform: ShimPlatform> ElfFile<'a, Platform> {
    fn new(task: &'a Task<Platform>, path: impl litebox::path::Arg) -> Result<Self, Errno> {
        let fd = task
            .sys_open(path, OFlags::RDONLY, Mode::empty())?
            .reinterpret_as_signed();
        Ok(ElfFile {
            task,
            fd,
            load_high: false,
        })
    }
}

impl<Platform: ShimPlatform> Drop for ElfFile<'_, Platform> {
    fn drop(&mut self) {
        self.task.sys_close(self.fd).expect("failed to close fd");
    }
}

impl<Platform: ShimPlatform> litebox_common_linux::loader::ReadAt for &'_ ElfFile<'_, Platform> {
    type Error = Errno;

    fn read_at(&mut self, mut offset: u64, mut buf: &mut [u8]) -> Result<(), Self::Error> {
        loop {
            if buf.is_empty() {
                return Ok(());
            }
            // Try to read the remaining bytes
            let bytes_read = self.task.sys_read(self.fd, buf, Some(offset.trunc()))?;
            if bytes_read == 0 {
                // reached the end of the file
                return Err(Errno::ENODATA);
            } else {
                // Successfully read some bytes
                buf = &mut buf[bytes_read..];
                offset += bytes_read as u64;
            }
        }
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        #[cfg(target_arch = "x86_64")]
        {
            Ok(self.task.sys_fstat(self.fd)?.st_size as u64)
        }
        #[cfg(target_arch = "aarch64")]
        {
            // The asm-generic ABI uses signed `st_size`; reject negative sizes.
            u64::try_from(self.task.sys_fstat(self.fd)?.st_size).map_err(|_| Errno::EINVAL)
        }
    }
}

impl<Platform: ShimPlatform> litebox_common_linux::loader::MapMemory for ElfFile<'_, Platform> {
    type Error = Errno;

    // TODO: move AArch64 gate finalization into the common loader, then remove
    // this architecture-specific trampoline ownership split.
    const POPULATES_TRAMPOLINE: bool = cfg!(target_arch = "aarch64");

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        // Allocate a mapping large enough that even if it's maximally misaligned we can
        // still fit `len` bytes.
        let mapping_len = len + (align.max(PAGE_SIZE) - PAGE_SIZE);
        let hint = if self.load_high {
            // Reserve the interpreter top-down by passing no hint: LiteBox's
            // `get_unmmaped_area` then runs its top-down search and returns
            // the highest free slot (see `litebox/src/mm/linux.rs`), which is
            // where we want `ld.so` so the low ET_EXEC brk heap below stays
            // uncapped. This needs no explicit `TASK_ADDR_MAX` arithmetic and
            // no reserve-once bookkeeping, and it does not rely on any
            // platform honoring an out-of-range hint.
            0
        } else {
            super::DEFAULT_LOW_ADDR
        };
        let mapping_ptr = self
            .task
            .sys_mmap(
                hint,
                mapping_len,
                litebox_common_linux::ProtFlags::PROT_NONE,
                litebox_common_linux::MapFlags::MAP_ANONYMOUS
                    | litebox_common_linux::MapFlags::MAP_PRIVATE,
                -1,
                0,
            )?
            .as_usize();

        // See `compute_reserved_regions` for why the trim regions must be
        // computed in page units: `len` (an ELF's `max_vaddr - min_vaddr`
        // span) is in general not page-aligned, and `munmap` rejects
        // non-page-aligned start addresses with EINVAL.
        let regions = litebox_common_linux::loader::compute_reserved_regions(
            mapping_ptr,
            mapping_len,
            len,
            align,
        );
        if let Some((addr, size)) = regions.head_unmap {
            self.task.sys_munmap(UserPtrMut::from_usize(addr), size)?;
        }
        if let Some((addr, size)) = regions.tail_unmap {
            self.task.sys_munmap(UserPtrMut::from_usize(addr), size)?;
        }
        Ok(regions.aligned_ptr)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.task.sys_mmap(
            address,
            len,
            prot.flags(),
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            self.fd,
            offset.trunc(),
        )?;
        Ok(())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.task.sys_mmap(
            address,
            len,
            prot.flags(),
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
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
        let addr = UserPtrMut::<u8>::from_usize(address);
        self.task.sys_mprotect(addr, len, prot.flags())
    }
}

/// Struct to hold the information needed to start the program
/// (entry point and user stack top).
pub struct ElfLoadInfo {
    pub entry_point: usize,
    pub user_stack_top: usize,
}

/// Loader for ELF files
pub(crate) struct ElfLoader<'a, Platform: ShimPlatform> {
    path: &'a str,
    main: FileAndParsed<'a, Platform>,
    interp: Option<FileAndParsed<'a, Platform>>,
}

struct FileAndParsed<'a, Platform: ShimPlatform> {
    file: ElfFile<'a, Platform>,
    parsed: ElfParsedFile,
}

impl<'a, Platform: ShimPlatform> FileAndParsed<'a, Platform> {
    fn new(
        task: &'a Task<Platform>,
        path: impl litebox::path::Arg,
    ) -> Result<Self, ElfLoaderError> {
        let file = ElfFile::new(task, path).map_err(ElfLoaderError::OpenError)?;
        let mut parsed = litebox_common_linux::loader::ElfParsedFile::parse(&mut &file)
            .map_err(ElfLoaderError::ParseError)?;

        let syscall_entry_point = task.global.platform.get_syscall_entry_point();
        #[cfg(target_arch = "aarch64")]
        let parse_entry_point = {
            // TODO: split trampoline detection from x86 callback-slot setup in
            // the common parser. AArch64 has no callback slot to initialize.
            const AARCH64_UNUSED_ENTRY_POINT: usize = 1;
            syscall_entry_point.max(AARCH64_UNUSED_ENTRY_POINT)
        };
        #[cfg(target_arch = "x86_64")]
        let parse_entry_point = syscall_entry_point;

        // Try to parse an embedded trampoline. For pre-patched binaries this
        // succeeds and load_trampoline() will map it. For unpatched binaries
        // (UnpatchedBinary error), the runtime patching during mmap will patch
        // code segments as they are mapped.
        if parse_entry_point != 0 {
            match parsed.parse_trampoline(&mut &file, parse_entry_point) {
                Ok(()) | Err(litebox_common_linux::loader::ElfParseError::UnpatchedBinary) => {
                    // Ok: pre-patched trampoline found, or unpatched binary
                    // that the runtime mmap hook will handle.
                }
                Err(e) => return Err(ElfLoaderError::ParseError(e)),
            }
        }

        Ok(Self { file, parsed })
    }

    /// Load the ELF into guest memory.
    fn load_mapped(
        &mut self,
        platform: &(impl litebox::platform::RawPointerProvider + litebox::platform::SystemInfoProvider),
    ) -> Result<litebox_common_linux::loader::MappingInfo, ElfLoaderError> {
        let syscall_entry_point = self.file.task.global.platform.get_syscall_entry_point();
        // When the platform requires syscall rewriting but the binary has no
        // embedded trampoline, reserve space so that brk starts past the
        // runtime trampoline region.
        let reserve = if syscall_entry_point != 0 && !self.parsed.has_trampoline() {
            Some(litebox::mm::linux::DEFAULT_RESERVED_SPACE_SIZE)
        } else {
            None
        };
        let result = self.parsed.load(&mut self.file, &mut &*platform, reserve)?;
        #[cfg(target_arch = "aarch64")]
        if self.parsed.has_trampoline()
            && !self
                .file
                .task
                .global
                .elf_patch_cache
                .lock()
                .get(&self.file.fd)
                .is_some_and(crate::syscalls::mm::ElfPatchState::trampoline_is_populated)
        {
            litebox_util_log::error!(fd:? = self.file.fd; "AArch64 trampoline was not populated while loading the ELF");
            return Err(ElfLoaderError::LoadError(
                litebox_common_linux::loader::ElfLoadError::InvalidProgramHeader,
            ));
        }
        Ok(result)
    }
}

impl<'a, Platform: ShimPlatform> ElfLoader<'a, Platform> {
    /// Parses an ELF file from the given path.
    pub fn new(task: &'a Task<Platform>, path: &'a str) -> Result<Self, ElfLoaderError> {
        // Parse the main ELF file.
        let main = FileAndParsed::new(task, path)?;

        // Parse the interpreter ELF file, if any.
        let interp = if let Some(interp_name) = main.parsed.interp(&mut &main.file)? {
            // e.g., /lib64/ld-linux-x86-64.so.2
            let mut interp = FileAndParsed::new(task, interp_name)?;
            // Linux places the ET_EXEC interpreter high so brk can grow above
            // the fixed-address main image without hitting ld.so.
            interp.file.load_high = true;
            Some(interp)
        } else {
            None
        };

        Ok(Self { path, main, interp })
    }

    /// Load an ELF file and prepare the stack for the new process.
    pub fn load(
        &mut self,
        argv: Vec<CString>,
        envp: Vec<CString>,
        mut aux: AuxVec,
    ) -> Result<ElfLoadInfo, ElfLoaderError> {
        let global = &self.main.file.task.global;

        // Load the main ELF file first so that it gets privileged addresses.
        let info = self.main.load_mapped(global.platform)?;

        // Load the interpreter ELF file, if any.
        let interp = if let Some(interp) = &mut self.interp {
            Some(interp.load_mapped(global.platform)?)
        } else {
            None
        };

        global.pm.set_initial_brk(info.brk);
        aux.insert(AuxKey::AT_PAGESZ, PAGE_SIZE);
        aux.insert(AuxKey::AT_PHDR, info.phdrs_addr);
        aux.insert(AuxKey::AT_PHENT, info.phent_size());
        aux.insert(AuxKey::AT_PHNUM, info.num_phdrs);
        aux.insert(AuxKey::AT_ENTRY, info.entry_point);
        let entry = if let Some(interp) = &interp {
            aux.insert(AuxKey::AT_BASE, interp.base_addr);
            interp.entry_point
        } else {
            info.entry_point
        };

        let sp = unsafe {
            let length = litebox::mm::linux::NonZeroPageSize::new(super::DEFAULT_STACK_SIZE)
                .expect("DEFAULT_STACK_SIZE is not page-aligned");
            global
                .pm
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(ElfLoaderError::MappingError)?
        };
        let mut stack = UserStack::<Platform>::new(
            UserPtrMut::from_platform_ptr::<Platform>(sp),
            super::DEFAULT_STACK_SIZE,
        )
        .ok_or(ElfLoaderError::InvalidStackAddr)?;
        stack
            .init(argv, envp, aux)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;

        Ok(ElfLoadInfo {
            entry_point: entry,
            user_stack_top: stack.get_cur_stack_top(),
        })
    }

    /// Returns the command name from the ELF path.
    pub fn comm(&self) -> &[u8] {
        self.path.rsplit('/').next().unwrap_or("unknown").as_bytes()
    }
}

#[derive(Error, Debug)]
pub enum ElfLoaderError {
    #[error("failed to open the ELF file")]
    OpenError(#[from] Errno),
    #[error("failed to parse the ELF file")]
    ParseError(#[from] litebox_common_linux::loader::ElfParseError<Errno>),
    #[error("failed to load the ELF file")]
    LoadError(#[from] litebox_common_linux::loader::ElfLoadError<Errno>),
    #[error("invalid stack")]
    InvalidStackAddr,
    #[error("failed to mmap")]
    MappingError(#[from] MappingError),
}

impl From<ElfLoaderError> for litebox_common_linux::errno::Errno {
    fn from(value: ElfLoaderError) -> Self {
        match value {
            ElfLoaderError::OpenError(e) => e,
            ElfLoaderError::ParseError(e) => e.into(),
            ElfLoaderError::InvalidStackAddr | ElfLoaderError::MappingError(_) => {
                litebox_common_linux::errno::Errno::ENOMEM
            }
            ElfLoaderError::LoadError(e) => e.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::syscalls::tests::TestPlatform;
    use litebox::platform::PageManagementProvider;
    use litebox_common_linux::loader::MapMemory as _;

    use super::*;

    #[test]
    fn interpreter_reservation_is_top_down_above_low_heap() {
        let task = crate::syscalls::tests::init_platform();
        let mut interpreter = ElfFile {
            task: &task,
            fd: 0,
            load_high: true,
        };
        let address = interpreter
            .reserve(PAGE_SIZE, PAGE_SIZE)
            .expect("the interpreter reservation should succeed");

        let addr_max = <TestPlatform as PageManagementProvider<{ PAGE_SIZE }>>::TASK_ADDR_MAX;
        assert!(
            address >= addr_max / 2,
            "interpreter reserved at {address:#x}, near the low-heap region {:#x} rather than top-down high (>= {:#x})",
            crate::loader::DEFAULT_LOW_ADDR,
            addr_max / 2,
        );
        task.sys_munmap(UserPtrMut::from_usize(address), PAGE_SIZE)
            .expect("the test reservation should unmap");
    }
}
