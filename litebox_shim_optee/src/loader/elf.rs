// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ELF loader for LiteBox customized for loading and running `ldelf` and
//! eventially the target OP-TEE TA.
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
//! result in uncessary data copies and higher memory usage. To avoid this,
//! we need to implement file-backed mapping, demand paging, and/or shared
//! mapping in the future.
use crate::{MutPtr, Task, ThreadInitState, UserMutPtr};
use litebox::{
    mm::linux::{MappingError, PAGE_SIZE},
    platform::{RawConstPointer as _, RawMutPointer as _, SystemInfoProvider as _},
    utils::TruncateExt,
};
use litebox_common_linux::{MapFlags, ProtFlags, errno::Errno, loader::ElfParsedFile};
use litebox_common_optee::LdelfArg;
use thiserror::Error;

/// An ELF file loaded in memory
struct ElfFileInMemory<'a> {
    task: &'a Task,
    buffer: alloc::boxed::Box<[u8]>,
}

fn read_at(elf: &ElfFileInMemory, offset: u64, buf: &mut [u8]) -> Result<(), Errno> {
    if buf.is_empty() {
        return Ok(());
    }
    let offset = offset.truncate();
    if offset >= elf.buffer.len() {
        return Err(Errno::ENODATA);
    }
    let end = core::cmp::min(offset + buf.len(), elf.buffer.len());
    let len = end - offset;
    buf[..len].copy_from_slice(&elf.buffer[offset..end]);
    Ok(())
}

impl<'a> ElfFileInMemory<'a> {
    fn new(task: &'a Task, elf_buf: &[u8]) -> Self {
        Self {
            task,
            buffer: elf_buf.into(),
        }
    }
}

impl litebox_common_linux::loader::ReadAt for &'_ ElfFileInMemory<'_> {
    type Error = Errno;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        read_at(self, offset, buf)
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        Ok(self.buffer.len() as u64)
    }
}

impl litebox_common_linux::loader::MapMemory for ElfFileInMemory<'_> {
    type Error = Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        // Allocate a mapping large enough that even if it's maximally misaligned we can
        // still fit `len` bytes.
        let mapping_len = len + (align.max(PAGE_SIZE) - PAGE_SIZE);
        let mapping_ptr = self
            .task
            .sys_mmap(
                super::DEFAULT_LOW_ADDR,
                mapping_len,
                ProtFlags::PROT_NONE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_POPULATE,
                -1,
                0,
            )?
            .as_usize();

        let ptr = mapping_ptr.next_multiple_of(align);
        let end = ptr + len;
        let mapping_end = mapping_ptr + mapping_len;
        if ptr != mapping_ptr {
            self.task
                .sys_munmap(MutPtr::from_usize(mapping_ptr), ptr - mapping_ptr)?;
        }
        if end != mapping_end {
            self.task
                .sys_munmap(MutPtr::from_usize(end), mapping_end - end)?;
        }
        Ok(ptr)
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
                    | MapFlags::MAP_POPULATE,
                -1,
                offset.truncate(),
            )?
            .as_usize();

        // Copy ELF data directly to user memory without intermediate buffer.
        // MAP_ANONYMOUS ensures remaining bytes are zero if src is shorter than len.
        let offset: usize = offset.truncate();
        if len > 0 && offset < self.buffer.len() {
            let end = core::cmp::min(offset + len, self.buffer.len());
            let src = &self.buffer[offset..end];
            let user_ptr = UserMutPtr::<u8>::from_usize(mapped_addr);
            user_ptr
                .copy_from_slice(0, src)
                .ok_or(ElfLoaderError::MappingError(MappingError::OutOfMemory))?;
        }

        self.task
            .sys_mprotect(UserMutPtr::from_usize(mapped_addr), len, prot.flags())
            .expect("sys_mprotect failed");
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
        let addr = crate::MutPtr::<u8>::from_usize(address);
        self.task.sys_mprotect(addr, len, prot.flags())
    }
}

/// Loader for ELF files
pub(crate) struct ElfLoader<'a> {
    main: FileAndParsed<'a>,
    is_ldelf: bool,
}

struct FileAndParsed<'a> {
    file: ElfFileInMemory<'a>,
    parsed: ElfParsedFile,
}

impl<'a> FileAndParsed<'a> {
    fn new(task: &'a Task, elf_buf: &[u8]) -> Result<Self, ElfLoaderError> {
        let file = ElfFileInMemory::new(task, elf_buf);
        let mut parsed = litebox_common_linux::loader::ElfParsedFile::parse(&mut &file)
            .map_err(ElfLoaderError::ParseError)?;
        parsed.parse_trampoline(&mut &file, task.global.platform.get_syscall_entry_point())?;
        Ok(Self { file, parsed })
    }
}

impl<'a> ElfLoader<'a> {
    /// Parse a given ELF binary in memory.
    pub fn new(task: &'a Task, elf_bin: &[u8], is_ldelf: bool) -> Result<Self, ElfLoaderError> {
        let main = FileAndParsed::new(task, elf_bin)?;
        Ok(Self { main, is_ldelf })
    }

    /// Load `ldelf` and prepare the stack and CPU context for it with the given TA UUID.
    pub fn load_ldelf(&mut self, ldelf_arg: &LdelfArg) -> Result<ThreadInitState, ElfLoaderError> {
        if !self.is_ldelf {
            return Err(ElfLoaderError::OpenError(Errno::ENOENT));
        }
        let task = self.main.file.task;
        let global = &task.global;
        let ldelf_info = self
            .main
            .parsed
            .load(&mut self.main.file, &mut &*global.platform)?;

        let mut ta_stack = crate::loader::ta_stack::allocate_stack(task, None).ok_or(
            ElfLoaderError::MappingError(litebox::mm::linux::MappingError::OutOfMemory),
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
        if self.is_ldelf {
            return Err(ElfLoaderError::OpenError(Errno::ENOENT));
        }
        let task = self.main.file.task;
        let global = &task.global;

        self.main
            .parsed
            .load_secondary_trampoline(&mut self.main.file, &mut &*global.platform, ta_entry_point)
            .map_err(|_| {
                ElfLoaderError::MappingError(litebox::mm::linux::MappingError::OutOfMemory)
            })
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
    #[error("TA binary UUID does not match expected UUID")]
    InvalidUuid,
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
            ElfLoaderError::InvalidUuid => litebox_common_linux::errno::Errno::EINVAL,
        }
    }
}
