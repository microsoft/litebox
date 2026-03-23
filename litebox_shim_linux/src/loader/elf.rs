// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ELF loader for LiteBox

use alloc::{ffi::CString, vec::Vec};
use litebox::{
    fs::{Mode, OFlags},
    mm::linux::{CreatePagesFlags, MappingError, PAGE_SIZE},
    platform::{RawConstPointer as _, RawMutPointer as _, SystemInfoProvider as _},
    utils::{ReinterpretSignedExt, TruncateExt},
};
use litebox_common_linux::{
    MapFlags,
    errno::Errno,
    loader::{ElfParsedFile, ReadAt as _},
};
use thiserror::Error;

use crate::{
    MutPtr,
    loader::auxv::{AuxKey, AuxVec},
};

use super::stack::UserStack;
use crate::{ShimFS, Task};

// An opened elf file
struct ElfFile<'a, FS: ShimFS> {
    task: &'a Task<FS>,
    fd: i32,
}

impl<'a, FS: ShimFS> ElfFile<'a, FS> {
    fn new(task: &'a Task<FS>, path: impl litebox::path::Arg) -> Result<Self, Errno> {
        let fd = task
            .sys_open(path, OFlags::RDONLY, Mode::empty())?
            .reinterpret_as_signed();
        Ok(ElfFile { task, fd })
    }
}

impl<FS: ShimFS> Drop for ElfFile<'_, FS> {
    fn drop(&mut self) {
        self.task.sys_close(self.fd).expect("failed to close fd");
    }
}

impl<FS: ShimFS> litebox_common_linux::loader::ReadAt for &'_ ElfFile<'_, FS> {
    type Error = Errno;

    fn read_at(&mut self, mut offset: u64, mut buf: &mut [u8]) -> Result<(), Self::Error> {
        loop {
            if buf.is_empty() {
                return Ok(());
            }
            // Try to read the remaining bytes
            let bytes_read = self.task.sys_read(self.fd, buf, Some(offset.truncate()))?;
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
        Ok(self.task.sys_fstat(self.fd)?.st_size as u64)
    }
}

impl<FS: ShimFS> litebox_common_linux::loader::MapMemory for ElfFile<'_, FS> {
    type Error = Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        // Start PIE binaries at a fixed offset into the partition so that the
        // low addresses remain unmapped (NULL-dereference guard region).
        let hint = self.task.process_state.borrow().pm.addr_min() + super::PIE_LOAD_OFFSET;

        // Allocate a mapping large enough that even if it's maximally misaligned we can
        // still fit `len` bytes.
        let mapping_len = len + (align.max(PAGE_SIZE) - PAGE_SIZE);
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
            offset.truncate(),
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
        let addr = crate::MutPtr::<u8>::from_usize(address);
        self.task.sys_mprotect(addr, len, prot.flags())
    }
}

/// A [`MapMemory`] wrapper that reads file-backed data from an in-memory buffer
/// instead of from a file descriptor. Used when the loader has patched the ELF
/// binary on the fly (e.g. syscall rewriting of the dynamic linker).
///
/// `reserve`, `map_zero`, and `protect` are delegated to the underlying
/// [`ElfFile`]; `map_file` is replaced by `map_zero` + a memory copy from the
/// patched buffer.
struct PatchedMapper<'a, 'b, FS: ShimFS> {
    inner: &'b mut ElfFile<'a, FS>,
    data: &'b [u8],
}

impl<FS: ShimFS> litebox_common_linux::loader::MapMemory for PatchedMapper<'_, '_, FS> {
    type Error = Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        self.inner.reserve(len, align)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        // Allocate anonymous pages, copy from the in-memory buffer, then apply
        // the requested protection.
        self.inner.map_zero(
            address,
            len,
            &litebox_common_linux::loader::Protection {
                read: true,
                write: true,
                execute: false,
            },
        )?;

        let offset: usize = offset.truncate();
        if offset < self.data.len() {
            let end = core::cmp::min(offset + len, self.data.len());
            let src = &self.data[offset..end];
            let dest = MutPtr::<u8>::from_usize(address);
            dest.copy_from_slice(0, src).ok_or(Errno::EFAULT)?;
        }

        // Set final permissions if different from the writable mapping above.
        if !prot.write || prot.execute {
            self.inner.protect(address, len, prot)?;
        }
        Ok(())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.inner.map_zero(address, len, prot)
    }

    fn protect(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.inner.protect(address, len, prot)
    }
}

/// Struct to hold the information needed to start the program
/// (entry point and user stack top).
pub struct ElfLoadInfo {
    pub entry_point: usize,
    pub user_stack_top: usize,
}

/// Loader for ELF files
pub(crate) struct ElfLoader<'a, FS: ShimFS> {
    path: &'a str,
    main: FileAndParsed<'a, FS>,
    interp: Option<FileAndParsed<'a, FS>>,
}

struct FileAndParsed<'a, FS: ShimFS> {
    file: ElfFile<'a, FS>,
    parsed: ElfParsedFile,
    /// When the rewriter backend is active and the binary was not pre-patched,
    /// the loader patches it on the fly and loads from this in-memory copy.
    patched_data: Option<Vec<u8>>,
}

impl<'a, FS: ShimFS> FileAndParsed<'a, FS> {
    fn new(task: &'a Task<FS>, path: impl litebox::path::Arg) -> Result<Self, ElfLoaderError> {
        let file = ElfFile::new(task, path).map_err(ElfLoaderError::OpenError)?;
        let mut parsed = litebox_common_linux::loader::ElfParsedFile::parse(&mut &file)
            .map_err(ElfLoaderError::ParseError)?;

        let syscall_entry_point = task.global.platform.get_syscall_entry_point();
        let trampoline_result = parsed.parse_trampoline(&mut &file, syscall_entry_point);

        // If the rewriter backend is active (syscall_entry_point != 0) and the
        // binary lacks a trampoline, patch it on the fly so that both the main
        // program and the dynamic linker are covered.
        let patched_data = if syscall_entry_point != 0 && trampoline_result.is_err() {
            let size: usize = (&mut &file)
                .size()
                .map_err(ElfLoaderError::OpenError)?
                .truncate();
            let mut buf = alloc::vec![0u8; size];
            (&mut &file)
                .read_at(0, &mut buf)
                .map_err(ElfLoaderError::OpenError)?;

            match litebox_syscall_rewriter::hook_syscalls_in_elf(&buf, None) {
                Ok(patched) => {
                    // Re-parse the patched binary and extract its trampoline.
                    parsed =
                        litebox_common_linux::loader::ElfParsedFile::parse(&mut patched.as_slice())
                            .map_err(ElfLoaderError::ParseError)?;
                    parsed
                        .parse_trampoline(&mut patched.as_slice(), syscall_entry_point)
                        .map_err(ElfLoaderError::ParseError)?;
                    Some(patched)
                }
                Err(_) => {
                    // Patching failed (e.g. ET_REL, no .text). Proceed without
                    // a trampoline — the binary may simply have no syscalls.
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            file,
            parsed,
            patched_data,
        })
    }

    /// Load the ELF into guest memory, choosing the right mapper depending on
    /// whether the binary was patched in memory.
    fn load_mapped(
        &mut self,
        platform: &(impl litebox::platform::RawPointerProvider + litebox::platform::SystemInfoProvider),
    ) -> Result<litebox_common_linux::loader::MappingInfo, ElfLoaderError> {
        if let Some(ref data) = self.patched_data {
            let mut mapper = PatchedMapper {
                inner: &mut self.file,
                data,
            };
            Ok(self.parsed.load(&mut mapper, &mut &*platform)?)
        } else {
            Ok(self.parsed.load(&mut self.file, &mut &*platform)?)
        }
    }
}

impl<'a, FS: ShimFS> ElfLoader<'a, FS> {
    /// Parses an ELF file from the given path.
    pub fn new(task: &'a Task<FS>, path: &'a str) -> Result<Self, ElfLoaderError> {
        // Parse the main ELF file.
        let main = FileAndParsed::new(task, path)?;

        // Parse the interpreter ELF file, if any.
        let interp = if let Some(interp_name) = main.parsed.interp(&mut &main.file)? {
            Some(FileAndParsed::new(task, interp_name)?)
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
        exec_filename: Option<&CString>,
    ) -> Result<ElfLoadInfo, ElfLoaderError> {
        let global = &self.main.file.task.global;
        let process_state = self.main.file.task.process_state.borrow();

        // Reject ET_EXEC binaries whose fixed load addresses fall outside the
        // process's VA partition (e.g., a child process in a higher slot).
        if let Some(fixed_range) = self.main.parsed.fixed_load_range() {
            let pm_min = process_state.pm.addr_min();
            let pm_max = process_state.pm.addr_max();
            if fixed_range.start < pm_min || fixed_range.end > pm_max {
                return Err(ElfLoaderError::OutOfRange);
            }
        }

        // Load the main ELF file first so that it gets privileged addresses.
        let info = self.main.load_mapped(global.platform)?;

        // Load the interpreter ELF file, if any.
        let interp = if let Some(interp) = &mut self.interp {
            Some(interp.load_mapped(global.platform)?)
        } else {
            None
        };

        process_state.pm.set_initial_brk(info.brk);
        process_state
            .main_bss_start
            .store(info.bss_start, core::sync::atomic::Ordering::Relaxed);
        process_state
            .main_bss_end
            .store(info.bss_end, core::sync::atomic::Ordering::Relaxed);
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
            process_state
                .pm
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(ElfLoaderError::MappingError)?
        };
        let mut stack = UserStack::new(sp, super::DEFAULT_STACK_SIZE)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;
        stack
            .init(argv, envp, aux, exec_filename)
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
    #[error("ET_EXEC load addresses outside process VA range")]
    OutOfRange,
}

impl From<ElfLoaderError> for litebox_common_linux::errno::Errno {
    fn from(value: ElfLoaderError) -> Self {
        match value {
            ElfLoaderError::OpenError(e) => e,
            // Non-ELF files that also lack a #! shebang (handled earlier in
            // sys_execve) reach here. Map to ENOENT to prevent glibc from
            // retrying execution via /bin/sh for opaque binaries.
            ElfLoaderError::ParseError(_) => litebox_common_linux::errno::Errno::ENOENT,
            ElfLoaderError::InvalidStackAddr | ElfLoaderError::MappingError(_) => {
                litebox_common_linux::errno::Errno::ENOMEM
            }
            ElfLoaderError::LoadError(e) => e.into(),
            // OutOfRange means the binary's load address doesn't fit in the
            // current VA partition (e.g. non-PIE at 0x400000 in a child slot).
            ElfLoaderError::OutOfRange => litebox_common_linux::errno::Errno::ENOMEM,
        }
    }
}
