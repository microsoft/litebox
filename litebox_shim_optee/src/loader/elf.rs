// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ELF loader for LiteBox customized for loading and running `ldelf` and
//! eventually the target OP-TEE TA.
//!
//! Unlike the ELF loader for Linux Shim, this loader does not load the main
//! ELF. This is because OP-TEE's `ldelf` has several non-standard features
//! to load TA ELF and we decide not to implement them. Instead, this loader
//! loads and runs a `ldelf` binary which in turn makes several ldelf syscalls
//! loads the target TA. Then, this loader collects the necessary information
//! to start the loaded TA (e.g., entry point). Note that we run `ldelf` in
//! the user mode. That is, it is not in our TCB.
//!
//! Since OP-TEE Shim does not support file-backed mapping, this module uses
//! anonymous mappings and manually loads the ELF segments into memory, which
//! result in unnecessary data copies and higher memory usage. To avoid this,
//! we need to implement file-backed mapping, demand paging, and/or shared
//! mapping in the future.
use crate::{MutPtr, Task, ThreadInitState, UserMutPtr};
use litebox::{
    platform::{RawConstPointer as _, RawMutPointer as _},
    utils::TruncateExt,
};
use litebox_common_linux::{
    MapFlags, ProtFlags,
    errno::Errno,
    loader::{ElfParseError, ElfParsedFile},
    vmem::MappingError,
};
use litebox_common_optee::{LdelfArg, PAGE_SIZE};
use thiserror::Error;

/// An ELF file loaded in memory
struct ElfFileInMemory<'a, Platform: crate::OpteeShimPlatform> {
    task: &'a Task<Platform>,
    buffer: &'a [u8],
}

impl<Platform: crate::OpteeShimPlatform> litebox_common_linux::loader::ReadAt
    for &'_ ElfFileInMemory<'_, Platform>
{
    type Error = Errno;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        if buf.is_empty() {
            return Ok(());
        }
        let start: usize = offset.trunc();
        let end = start.checked_add(buf.len()).ok_or(Errno::ENODATA)?;
        let src = self.buffer.get(start..end).ok_or(Errno::ENODATA)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        Ok(self.buffer.len() as u64)
    }
}

impl<Platform: crate::OpteeShimPlatform> litebox_common_linux::loader::MapMemory
    for ElfFileInMemory<'_, Platform>
{
    type Error = Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        // Allocate a mapping large enough that even if it's maximally misaligned we can
        // still fit `len` bytes.
        let mapping_len = len
            .checked_add(align.max(PAGE_SIZE) - PAGE_SIZE)
            .ok_or(Errno::ENOMEM)?;
        let mapping_ptr = self
            .task
            .sys_mmap(
                super::DEFAULT_LOW_ADDR,
                mapping_len,
                ProtFlags::PROT_NONE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
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
            self.task
                .sys_munmap(MutPtr::<Platform, _>::from_usize(addr), size)?;
        }
        if let Some((addr, size)) = regions.tail_unmap {
            self.task
                .sys_munmap(MutPtr::<Platform, _>::from_usize(addr), size)?;
        }
        Ok(regions.aligned_ptr)
    }

    /// This function imitates file-based mapping by using the in-memory ELF file.
    ///
    /// TODO: Optimize this function to avoid unnecessary copies with demand paging.
    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        let mapped_addr = self
            .task
            .sys_mmap(
                address,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANONYMOUS
                    | MapFlags::MAP_PRIVATE
                    | MapFlags::MAP_FIXED
                    // Pre-populate: ELF loading runs before run_thread_arch sets up
                    // the kernel-mode demand paging infrastructure.
                    | MapFlags::MAP_POPULATE,
                -1,
                offset.trunc(),
            )?
            .as_usize();

        // Copy ELF data directly to user memory without intermediate buffer.
        // MAP_ANONYMOUS ensures remaining bytes are zero if src is shorter than len.
        let offset: usize = offset.trunc();
        if len > 0 && offset < self.buffer.len() {
            let available = self.buffer.len() - offset;
            let end = offset + core::cmp::min(len, available);
            let src = &self.buffer[offset..end];
            let user_ptr = UserMutPtr::<Platform, u8>::from_usize(mapped_addr);
            user_ptr
                .copy_from_slice(0, src)
                .ok_or(ElfLoaderError::MappingError(MappingError::OutOfMemory))?;
        }

        self.task
            .sys_mprotect(
                UserMutPtr::<Platform, _>::from_usize(mapped_addr),
                len,
                prot.flags(),
            )
            .map_err(ElfLoaderError::ProtectError)?;
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
            MapFlags::MAP_ANONYMOUS
                | MapFlags::MAP_PRIVATE
                | MapFlags::MAP_FIXED
                // Pre-populate: ELF loading runs before run_thread_arch sets up
                // the kernel-mode demand paging infrastructure.
                | MapFlags::MAP_POPULATE,
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
        let addr = crate::MutPtr::<Platform, u8>::from_usize(address);
        self.task.sys_mprotect(addr, len, prot.flags())
    }
}

/// Loader for ELF files
pub(crate) struct ElfLoader<'a, Platform: crate::OpteeShimPlatform> {
    file: ElfFileInMemory<'a, Platform>,
    parsed: ElfParsedFile,
}

impl<'a, Platform: crate::OpteeShimPlatform> ElfLoader<'a, Platform> {
    /// Parse a given ELF binary in memory.
    pub fn new(task: &'a Task<Platform>, elf: &'a [u8]) -> Result<Self, ElfLoaderError> {
        let file = ElfFileInMemory { task, buffer: elf };
        let mut parsed = ElfParsedFile::parse(&mut &file).map_err(ElfLoaderError::ParseError)?;
        match parsed.parse_trampoline(&mut &file, task.global.platform.get_syscall_entry_point()) {
            Ok(()) | Err(ElfParseError::UnpatchedBinary) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(Self { file, parsed })
    }

    /// The pages the TA's trampoline occupies, relative to the TA's load
    /// address, or `None` if the TA has no trampoline.
    ///
    /// Callers anchor the result at the address `ldelf` maps the first segment
    /// at, whereas [`Self::load_ta_trampoline`] anchors at
    /// `entry_point - e_entry`. The two agree as long as the first `PT_LOAD`
    /// starts at vaddr 0, which `ldelf` assumes too.
    pub(crate) fn trampoline_relative_page_range(&self) -> Option<core::ops::Range<usize>> {
        self.parsed.trampoline_page_range(0)
    }

    /// Load `ldelf` and prepare the stack and CPU context for it with the given TA UUID.
    pub fn load_ldelf(&mut self, ldelf_arg: &LdelfArg) -> Result<ThreadInitState, ElfLoaderError> {
        let task = self.file.task;
        let global = &task.global;
        let ldelf_info = self
            .parsed
            .load(&mut self.file, &mut &*global.platform, None)?;

        let mut ta_stack = crate::loader::ta_stack::allocate_stack(task, None).ok_or(
            ElfLoaderError::MappingError(litebox_common_linux::vmem::MappingError::OutOfMemory),
        )?;
        ta_stack
            .init_with_ldelf_arg(ldelf_arg)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;
        task.set_ta_stack_base_addr(ta_stack.get_stack_base());

        Ok(ThreadInitState::Ldelf {
            ldelf_arg_address: ta_stack.get_ldelf_arg_address(),
            entry_point: ldelf_info.entry_point,
            stack_top: ta_stack.get_cur_stack_top(),
        })
    }

    /// Load the TA trampoline.
    ///
    /// This function is for the OP-TEE shim which uses an external `ldelf` program to load the target TA.
    /// Since `ldelf` is not aware of the LiteBox trampoline, we should call this function after `ldelf` has
    /// loaded the TA into memory whose base address is different from that of `ldelf`.
    pub fn load_ta_trampoline(&mut self, ta_entry_point: usize) -> Result<(), ElfLoaderError> {
        let task = self.file.task;
        let global = &task.global;

        self.parsed
            .load_secondary_trampoline(&mut self.file, &mut &*global.platform, ta_entry_point)
            .map_err(|_| {
                ElfLoaderError::MappingError(litebox_common_linux::vmem::MappingError::OutOfMemory)
            })
    }
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ElfLoaderError {
    #[error("failed to open the ELF file")]
    OpenError(#[from] Errno),
    #[error("failed to parse the ELF file")]
    ParseError(#[from] litebox_common_linux::loader::ElfParseError<Errno>),
    #[error("failed to load the ELF file")]
    LoadError(#[from] litebox_common_linux::loader::ElfLoadError<Errno>),
    #[error("invalid stack")]
    InvalidStackAddr,
    #[error("failed to set memory protection")]
    ProtectError(Errno),
    #[error("failed to mmap")]
    MappingError(#[from] MappingError),
    #[error("dynamic TA failed signature or UUID verification")]
    UnverifiedTa,
}

impl From<ElfLoaderError> for litebox_common_linux::errno::Errno {
    fn from(value: ElfLoaderError) -> Self {
        match value {
            ElfLoaderError::OpenError(e) | ElfLoaderError::ProtectError(e) => e,
            ElfLoaderError::ParseError(e) => e.into(),
            ElfLoaderError::InvalidStackAddr | ElfLoaderError::MappingError(_) => {
                litebox_common_linux::errno::Errno::ENOMEM
            }
            ElfLoaderError::LoadError(e) => e.into(),
            ElfLoaderError::UnverifiedTa => litebox_common_linux::errno::Errno::EACCES,
        }
    }
}
