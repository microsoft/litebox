// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{sync::Arc, vec::Vec};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, SystemInfoProvider as _};
use litebox::{
    fs::{Mode, OFlags},
    mm::linux::{
        CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, VmemProtectError,
    },
    platform::RawPointerProvider,
};
use litebox_common_windows::loader::{
    AccessMemory, Fault, MapMemory, MappingInfo, PAGE_SIZE, PeLoadError, PeParseError,
    PeParsedFile, Protection, ReadAt, page_align_down,
};
use litebox_platform_multiplex::Platform;
use thiserror::Error;

use crate::ShimFS;

const NTDLL_WRITABLE_SECTIONS: &[&[u8]] = &[b".mrdata"];
const NTDLL_PATHS: &[&str] = &["/Windows/System32/ntdll.dll", "/windows/system32/ntdll.dll"];
const ZERO_CHUNK: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
const FILE_CHUNK_BYTES: usize = 64 * 1024;
const INITIAL_STACK_SIZE: usize = 1024 * 1024;

/// Struct to hold the information needed to start the program.
pub(crate) struct PeLoadInfo {
    pub(crate) entry_point: usize,
    pub(crate) stack_top: usize,
    pub(crate) ntdll_mapping: Option<MappingInfo>,
}

/// Loader for Windows PE files.
pub(crate) struct PeLoader<'a, FS: ShimFS> {
    fs: Arc<FS>,
    page_manager: &'a crate::WindowsPageManager,
}

impl<'a, FS: ShimFS> PeLoader<'a, FS> {
    pub(crate) fn new(fs: Arc<FS>, page_manager: &'a crate::WindowsPageManager) -> Self {
        Self { fs, page_manager }
    }

    pub(crate) fn load(&self, path: &str) -> Result<PeLoadInfo, WindowsLoadError> {
        let image = load_image(self.fs.clone(), path, self.page_manager)?;
        let application_entry_point = image.mapping.entry_point;
        let ntdll = load_ntdll(self.fs.clone(), self.page_manager, NTDLL_PATHS)?;

        let length =
            NonZeroPageSize::new(INITIAL_STACK_SIZE).ok_or(PeImageAccessError::AddressOverflow)?;
        let stack_base = unsafe {
            self.page_manager
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(PeImageAccessError::Mapping)?
        };
        let stack_top = stack_base
            .as_usize()
            .checked_add(INITIAL_STACK_SIZE)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let stack_top = if stack_top.is_multiple_of(16) {
            stack_top - core::mem::size_of::<usize>()
        } else {
            stack_top
        };

        Ok(PeLoadInfo {
            entry_point: application_entry_point,
            stack_top,
            ntdll_mapping: ntdll.map(|image| image.mapping),
        })
    }
}

struct LoadedImage {
    mapping: MappingInfo,
}

fn load_ntdll<FS: crate::ShimFS>(
    fs: Arc<FS>,
    page_manager: &crate::WindowsPageManager,
    ntdll_paths: &[&str],
) -> Result<Option<LoadedImage>, WindowsLoadError> {
    for path in ntdll_paths {
        match load_image_with_writable_sections(
            fs.clone(),
            path,
            page_manager,
            NTDLL_WRITABLE_SECTIONS,
        ) {
            Ok(image) => {
                litebox_util_log::debug!(path:% = path; "Loaded guest ntdll.dll");
                return Ok(Some(image));
            }
            Err(error) if is_missing_file_error(&error) => {}
            Err(error) => return Err(error),
        }
    }

    litebox_util_log::debug!("Guest ntdll.dll was not found in the initial filesystem");
    Ok(None)
}

fn load_image<FS: ShimFS>(
    fs: Arc<FS>,
    path: &str,
    page_manager: &crate::WindowsPageManager,
) -> Result<LoadedImage, WindowsLoadError> {
    load_image_with_writable_sections(fs, path, page_manager, &[])
}

fn load_image_with_writable_sections<FS: ShimFS>(
    fs: Arc<FS>,
    path: &str,
    page_manager: &crate::WindowsPageManager,
    writable_section_names: &[&[u8]],
) -> Result<LoadedImage, WindowsLoadError> {
    let file = PeImageFile::open(fs, path)?;
    let mut parsed = PeParsedFile::parse(&mut &file).map_err(WindowsLoadError::Parse)?;
    parsed
        .parse_trampoline(
            &mut &file,
            litebox_platform_multiplex::platform().get_syscall_entry_point(),
        )
        .map_err(WindowsLoadError::Parse)?;
    let mut mapper = PeImageMapper {
        file: &file,
        page_manager,
        chunk: alloc::vec![0u8; FILE_CHUNK_BYTES],
    };
    let mut memory = PeImageMemory;
    let mapping = parsed
        .load_with_writable_sections(&mut mapper, &mut memory, writable_section_names)
        .map_err(WindowsLoadError::Load)?;
    Ok(LoadedImage { mapping })
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
    /// Guest ntdll.dll does not export LdrInitializeThunk.
    #[error("guest ntdll.dll does not export LdrInitializeThunk")]
    MissingNtDllLoaderEntrypoint,
    /// Guest ntdll.dll does not export RtlUserThreadStart.
    #[error("guest ntdll.dll does not export RtlUserThreadStart")]
    MissingNtDllThreadEntrypoint,
    /// Guest ntdll.dll has not been rewritten for LiteBox syscall/GS handling.
    #[error("guest ntdll.dll must be rewritten for LiteBox before entering its loader")]
    UnrewrittenNtDll,
}

fn is_missing_file_error(error: &WindowsLoadError) -> bool {
    let WindowsLoadError::Access(PeImageAccessError::Open(error)) = error else {
        return false;
    };

    matches!(
        error,
        litebox::fs::errors::OpenError::PathError(
            litebox::fs::errors::PathError::NoSuchFileOrDirectory
                | litebox::fs::errors::PathError::MissingComponent
        )
    )
}

struct PeImageFile<FS: ShimFS> {
    fs: Arc<FS>,
    fd: litebox::fd::TypedFd<FS>,
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
    page_manager: &'a crate::WindowsPageManager,
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
    page_manager: &crate::WindowsPageManager,
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
    page_manager: &crate::WindowsPageManager,
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
