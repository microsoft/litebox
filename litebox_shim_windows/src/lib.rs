// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A placeholder Windows NT shim for LiteBox.
//!
//! This crate intentionally only exposes the runner-facing skeleton for now.
//! The actual NT syscall, PE loading, and Windows process environment support
//! will be filled in piece by piece.

#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use litebox::fd::TypedFd;
use litebox::fs::{Mode, OFlags};
use litebox::mm::PageManager;
use litebox::mm::linux::{
    CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, VmemProtectError,
};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::{LiteBox, platform::RawPointerProvider};
use litebox_common_windows::loader::{
    AccessMemory, Fault, MapMemory, PAGE_SIZE, PeLoadError, PeParseError, PeParsedFile, Protection,
    ReadAt, page_align_down,
};
use litebox_platform_multiplex::Platform;
use thiserror::Error;

const INITIAL_STACK_SIZE: usize = 1024 * 1024;
const PLACEHOLDER_EXIT_CODE: i32 = 1;
const ZERO_CHUNK: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
const FILE_CHUNK_BYTES: usize = 64 * 1024;

type WindowsPageManager = PageManager<Platform, PAGE_SIZE>;

pub type DefaultFS = WindowsFS;

pub(crate) type WindowsFS = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;

/// A trait required for file systems to be used by the Windows shim.
pub trait ShimFS: litebox::fs::FileSystem + Send + Sync + 'static {}
impl<T: litebox::fs::FileSystem + Send + Sync + 'static> ShimFS for T {}

/// Builds a Windows NT shim instance.
pub struct WindowsShimBuilder {
    litebox: LiteBox<Platform>,
}

impl Default for WindowsShimBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsShimBuilder {
    #[must_use]
    pub fn new() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            litebox: LiteBox::new(platform),
        }
    }

    #[must_use]
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    /// Build a default layered file system with the given in-memory and tar read-only layers.
    #[must_use]
    pub fn default_fs(
        &self,
        in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
        tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
    ) -> DefaultFS {
        default_fs(&self.litebox, in_mem_fs, tar_ro_fs)
    }

    #[must_use]
    pub fn build<FS: ShimFS>(self) -> WindowsShim<FS> {
        let page_manager = Arc::new(PageManager::new(&self.litebox));
        WindowsShim {
            litebox: Arc::new(self.litebox),
            page_manager,
            _fs: PhantomData,
        }
    }
}

/// A placeholder Windows shim.
pub struct WindowsShim<FS: ShimFS> {
    litebox: Arc<LiteBox<Platform>>,
    page_manager: Arc<WindowsPageManager>,
    _fs: PhantomData<FS>,
}

impl<FS: ShimFS> WindowsShim<FS> {
    /// Loads the program at `path` as the shim's initial task.
    ///
    /// TODO: PEB/TEB setup and initial handle table state are not yet implemented.
    pub fn load_program(
        &self,
        fs: Arc<FS>,
        path: &str,
        _argv: Vec<alloc::ffi::CString>,
        _envp: Vec<alloc::ffi::CString>,
    ) -> Result<LoadedProgram<FS>, WindowsLoadError> {
        let file = PeImageFile::open(fs, path)?;
        let parsed = PeParsedFile::parse(&mut &file).map_err(|e| match e {
            PeParseError::Io(io) => WindowsLoadError::Access(io),
            other => WindowsLoadError::Parse(other),
        })?;
        let mut mapper = PeImageMapper {
            file: &file,
            page_manager: &self.page_manager,
            chunk: alloc::vec![0u8; FILE_CHUNK_BYTES],
        };
        let mut memory = PeImageMemory;
        let mapping = parsed.load(&mut mapper, &mut memory).map_err(|e| match e {
            PeLoadError::Map(access) => WindowsLoadError::Access(access),
            other => WindowsLoadError::Load(other),
        })?;
        let entry_point = mapping.entry_point;

        let length =
            NonZeroPageSize::new(INITIAL_STACK_SIZE).ok_or(PeImageAccessError::AddressOverflow)?;
        // SAFETY: `suggested_address` is `None` and `CreatePagesFlags::empty()` does not set
        // `fixed_addr`, so the kernel picks a free range — no existing mapping can be displaced.
        let stack_base = unsafe {
            self.page_manager
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(PeImageAccessError::Mapping)?
        };
        let stack_top = stack_base
            .as_usize()
            .checked_add(INITIAL_STACK_SIZE)
            .ok_or(PeImageAccessError::AddressOverflow)?;

        Ok(LoadedProgram {
            entrypoints: WindowsShimEntrypoints {
                entry_point,
                stack_top,
                _fs: PhantomData,
            },
            process: WindowsShimProcess,
        })
    }

    #[must_use]
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }
}

/// The shim entrypoint object passed to the platform.
pub struct WindowsShimEntrypoints<FS: ShimFS> {
    entry_point: usize,
    stack_top: usize,
    _fs: PhantomData<FS>,
}

impl<FS: ShimFS> EnterShim for WindowsShimEntrypoints<FS> {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        ctx.rip = self.entry_point;
        ctx.rsp = self.stack_top;
        ctx.eflags = 0x202;
        litebox_util_log::debug!(
            entry_point:% = format_args!("{:#x}", self.entry_point),
            stack_top:% = format_args!("{:#x}", self.stack_top);
            "Starting initial Windows guest thread"
        );
        ContinueOperation::Resume
    }

    fn syscall(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        // TODO: Decode and dispatch NT syscalls.
        ContinueOperation::Terminate
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &ExceptionInfo,
    ) -> ContinueOperation {
        litebox_util_log::debug!(
            exception:? = info.exception,
            rip:% = format_args!("{:#x}", ctx.rip),
            cr2:% = format_args!("{:#x}", info.cr2);
            "Windows guest exception"
        );
        // TODO: Translate hardware exceptions into Windows SEH where appropriate.
        ContinueOperation::Terminate
    }

    fn interrupt(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        // TODO: Handle host interrupts for Windows guest waits/APCs.
        ContinueOperation::Terminate
    }
}

/// A loaded Windows program and the process handle used to wait for it.
pub struct LoadedProgram<FS: ShimFS> {
    /// The initial-thread entrypoint state passed to the platform's `run_thread`.
    pub entrypoints: WindowsShimEntrypoints<FS>,
    /// Handle used to wait for the loaded program to exit.
    pub process: WindowsShimProcess,
}

/// A placeholder handle to a process loaded via [`WindowsShim::load_program`].
pub struct WindowsShimProcess;

impl WindowsShimProcess {
    /// Wait for the process to exit, returning its exit code.
    ///
    /// Currently a placeholder that returns a fixed exit code immediately.
    /// Once NT process lifecycle exists, this will actually block.
    #[must_use]
    pub fn wait(&self) -> i32 {
        PLACEHOLDER_EXIT_CODE
    }
}

/// Errors that can occur while opening, parsing, and mapping a Windows PE image.
#[derive(Debug, Error)]
pub enum WindowsLoadError {
    /// PE parsing failed.
    #[error("failed to parse PE image")]
    Parse(#[source] PeParseError<PeImageAccessError>),
    /// PE image mapping failed.
    #[error("failed to load PE image")]
    Load(#[source] PeLoadError<PeImageAccessError>),
    /// Opening the PE image failed.
    #[error(transparent)]
    Access(#[from] PeImageAccessError),
}

/// Errors from the shim-side PE image backing file and memory mapper.
#[derive(Debug, Error)]
pub enum PeImageAccessError {
    /// Opening the executable failed.
    #[error("failed to open PE image")]
    Open(#[from] litebox::fs::errors::OpenError),
    /// Reading the executable failed.
    #[error("failed to read PE image")]
    Read(#[from] litebox::fs::errors::ReadError),
    /// Reading file metadata failed.
    #[error("failed to read PE image metadata")]
    FileStatus(#[from] litebox::fs::errors::FileStatusError),
    /// The backing file ended before the requested range was read.
    #[error("short read from PE image")]
    ShortRead,
    /// A PE file offset or image address overflowed this host representation.
    #[error("PE image address overflow")]
    AddressOverflow,
    /// A memory mapping operation failed.
    #[error(transparent)]
    Mapping(#[from] MappingError),
    /// A memory protection operation failed.
    #[error(transparent)]
    Protect(#[from] VmemProtectError),
    /// A mapped memory access failed.
    #[error("mapped PE image memory access failed")]
    MemoryAccess,
}

struct PeImageFile<FS: ShimFS> {
    fs: Arc<FS>,
    fd: TypedFd<FS>,
}

impl<FS: ShimFS> PeImageFile<FS> {
    fn open(fs: Arc<FS>, path: &str) -> Result<Self, PeImageAccessError> {
        let fd = fs.open(path, OFlags::RDONLY, Mode::empty())?;
        Ok(Self { fs, fd })
    }

    fn read_exact_at(
        &self,
        mut offset: usize,
        mut buf: &mut [u8],
    ) -> Result<(), PeImageAccessError> {
        while !buf.is_empty() {
            let bytes_read = self.fs.read(&self.fd, buf, Some(offset))?;
            if bytes_read == 0 {
                return Err(PeImageAccessError::ShortRead);
            }
            offset = offset
                .checked_add(bytes_read)
                .ok_or(PeImageAccessError::AddressOverflow)?;
            buf = &mut buf[bytes_read..];
        }
        Ok(())
    }
}

impl<FS: ShimFS> Drop for PeImageFile<FS> {
    fn drop(&mut self) {
        if let Err(e) = self.fs.close(&self.fd) {
            litebox_util_log::warn!(error:? = e; "failed to close PE image file");
        }
    }
}

impl<FS: ShimFS> ReadAt for &'_ PeImageFile<FS> {
    type Error = PeImageAccessError;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.read_exact_at(
            offset
                .try_into()
                .map_err(|_| PeImageAccessError::AddressOverflow)?,
            buf,
        )
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        self.fs
            .fd_file_status(&self.fd)?
            .size
            .try_into()
            .map_err(|_| PeImageAccessError::AddressOverflow)
    }
}

struct PeImageMapper<'a, FS: ShimFS> {
    file: &'a PeImageFile<FS>,
    page_manager: &'a WindowsPageManager,
    /// Reusable per-call I/O staging buffer for [`MapMemory::map_file`].
    chunk: Vec<u8>,
}

impl<FS: ShimFS> MapMemory for PeImageMapper<'_, FS> {
    type Error = PeImageAccessError;

    fn reserve(
        &mut self,
        preferred_base: usize,
        len: usize,
        _align: usize,
    ) -> Result<usize, Self::Error> {
        let length = NonZeroPageSize::new(len).ok_or(PeImageAccessError::AddressOverflow)?;
        let suggested_address = if preferred_base == 0 {
            None
        } else {
            Some(NonZeroAddress::new(preferred_base).ok_or(PeImageAccessError::AddressOverflow)?)
        };

        // SAFETY: `CreatePagesFlags::empty()` does not set `fixed_addr`, so the kernel
        // treats `suggested_address` as a hint and never silently unmaps an existing
        // mapping; the documented overlap precondition therefore does not apply.
        let ptr = unsafe {
            self.page_manager.create_inaccessible_pages(
                suggested_address,
                length,
                CreatePagesFlags::empty(),
                |_| Ok(0),
            )?
        };
        Ok(ptr.as_usize())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        make_pages_writable(self.page_manager, address, len)?;
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(address);
        let mut written = 0;
        while written < len {
            let chunk = (len - written).min(ZERO_CHUNK.len());
            ptr.copy_from_slice(written, &ZERO_CHUNK[..chunk])
                .ok_or(PeImageAccessError::MemoryAccess)?;
            written += chunk;
        }
        protect_pages(self.page_manager, address, len, *prot)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        make_pages_writable(self.page_manager, address, len)?;
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(address);
        let file_offset: usize = offset
            .try_into()
            .map_err(|_| PeImageAccessError::AddressOverflow)?;
        let mut read = 0;
        while read < len {
            let remaining = len - read;
            let n = remaining.min(self.chunk.len());
            self.file.read_exact_at(
                file_offset
                    .checked_add(read)
                    .ok_or(PeImageAccessError::AddressOverflow)?,
                &mut self.chunk[..n],
            )?;
            ptr.copy_from_slice(read, &self.chunk[..n])
                .ok_or(PeImageAccessError::MemoryAccess)?;
            read += n;
        }
        protect_pages(self.page_manager, address, len, *prot)
    }

    fn protect(
        &mut self,
        address: usize,
        len: usize,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        protect_pages(self.page_manager, address, len, *prot)
    }
}

struct PeImageMemory;

impl AccessMemory for PeImageMemory {
    fn read(&mut self, address: usize, buf: &mut [u8]) -> Result<(), Fault> {
        let ptr = <Platform as RawPointerProvider>::RawConstPointer::<u8>::from_usize(address);
        buf.copy_from_slice(&ptr.to_owned_slice(buf.len()).ok_or(Fault)?);
        Ok(())
    }

    fn write(&mut self, address: usize, data: &[u8]) -> Result<(), Fault> {
        let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(address);
        ptr.copy_from_slice(0, data).ok_or(Fault)
    }
}

fn make_pages_writable(
    page_manager: &WindowsPageManager,
    address: usize,
    len: usize,
) -> Result<(), PeImageAccessError> {
    let (start, len) = page_range(address, len)?;
    if len == 0 {
        return Ok(());
    }
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(start);
    // SAFETY: Loading happens before the initial guest thread is allowed to execute.
    unsafe { page_manager.make_pages_writable(ptr, len)? };
    Ok(())
}

fn protect_pages(
    page_manager: &WindowsPageManager,
    address: usize,
    len: usize,
    prot: Protection,
) -> Result<(), PeImageAccessError> {
    let (start, len) = page_range(address, len)?;
    if len == 0 {
        return Ok(());
    }
    let ptr = <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(start);
    // SAFETY: All `make_pages_*` calls happen during PE load, before the initial
    // guest thread starts, so there is no concurrent read/write/execute on these
    // pages. The RWX arm is only reached when a section's COFF characteristics
    // demand WRITE|EXECUTE; the bytes copied into the section come from the
    // attacker-controlled PE file and are not executed until protections are set,
    // so this is no looser than running the same PE under the real Windows loader.
    match (prot.read, prot.write, prot.execute) {
        (_, true, true) => unsafe { page_manager.make_pages_rwx(ptr, len)? },
        (_, true, false) => unsafe { page_manager.make_pages_writable(ptr, len)? },
        (_, false, true) => unsafe { page_manager.make_pages_executable(ptr, len)? },
        (true, false, false) => unsafe { page_manager.make_pages_readable(ptr, len)? },
        (false, false, false) => unsafe { page_manager.make_pages_inaccessible(ptr, len)? },
    }
    Ok(())
}

fn page_range(address: usize, len: usize) -> Result<(usize, usize), PeImageAccessError> {
    if len == 0 {
        return Ok((address, 0));
    }
    let start = page_align_down(address);
    let end = address
        .checked_add(len)
        .and_then(|v| v.checked_next_multiple_of(PAGE_SIZE))
        .ok_or(PeImageAccessError::AddressOverflow)?;
    Ok((start, end - start))
}

fn default_fs(
    litebox: &LiteBox<Platform>,
    in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
    tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
) -> WindowsFS {
    let dev_stdio = litebox::fs::devices::FileSystem::new(litebox);
    litebox::fs::layered::FileSystem::new(
        litebox,
        in_mem_fs,
        litebox::fs::layered::FileSystem::new(
            litebox,
            dev_stdio,
            tar_ro_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    )
}
