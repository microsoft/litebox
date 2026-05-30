// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::TruncateExt as _;
use litebox::{
    fs::{Mode, OFlags},
    mm::linux::{
        CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, VmemProtectError,
    },
    platform::RawPointerProvider,
};
use litebox_common_windows::loader::{
    AccessMemory, Fault, KiUserInvertedFunctionTableEntry, KiUserInvertedFunctionTableHeader,
    MAXIMUM_INVERTED_FUNCTION_TABLE_SIZE, MapMemory, MappingInfo, PAGE_SIZE, PeExportError,
    PeLoadError, PeParseError, PeParsedFile, Protection, ReadAt, page_align_down,
};
use thiserror::Error;

use crate::ShimFS;

const NTDLL_WRITABLE_SECTIONS: &[&[u8]] = &[b".mrdata"];
const NTDLL_PATHS: &[&str] = &["/Windows/System32/ntdll.dll", "/windows/system32/ntdll.dll"];
const RUNTIME_FUNCTION_ENTRY_SIZE: usize = 12;
const ZERO_CHUNK: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
const FILE_CHUNK_BYTES: usize = 64 * 1024;
const INITIAL_STACK_SIZE: usize = 1024 * 1024;

pub(crate) struct PeLoadInfo {
    pub(crate) entry_point: usize,
    pub(crate) stack_top: usize,
    pub(crate) ntdll_mapping: Option<MappingInfo>,
}

pub(crate) struct PeLoader<'a, Platform: crate::ShimPlatform, FS: ShimFS> {
    platform: &'static Platform,
    fs: Arc<FS>,
    page_manager: &'a crate::WindowsPageManager<Platform>,
}

impl<'a, Platform: crate::ShimPlatform, FS: ShimFS> PeLoader<'a, Platform, FS> {
    pub(crate) fn new(
        platform: &'static Platform,
        fs: Arc<FS>,
        page_manager: &'a crate::WindowsPageManager<Platform>,
    ) -> Self {
        Self {
            platform,
            fs,
            page_manager,
        }
    }

    pub(crate) fn load(&self, path: &str) -> Result<PeLoadInfo, WindowsLoadError> {
        let image = load_image(self.platform, self.fs.clone(), path, self.page_manager)?;
        let application_entry_point = image.mapping.entry_point;
        let ntdll = load_ntdll(
            self.platform,
            self.fs.clone(),
            self.page_manager,
            NTDLL_PATHS,
        )?;

        if let Some(ntdll) = &ntdll {
            if !ntdll.image.parsed.has_trampoline() {
                return Err(WindowsLoadError::UnrewrittenNtDll);
            }
            Self::initialize_ki_user_inverted_function_table(&image, ntdll)?;
        }

        let length =
            NonZeroPageSize::new(INITIAL_STACK_SIZE).ok_or(PeImageAccessError::AddressOverflow)?;
        // SAFETY: `suggested_address` is `None` and `CreatePagesFlags::empty()` does not set
        // `fixed_addr`, so the page manager picks an unused region — there is no overlapping-
        // mapping precondition for the caller to uphold.
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
            ntdll_mapping: ntdll.map(|ntdll| ntdll.image.mapping),
        })
    }

    fn initialize_ki_user_inverted_function_table(
        application: &LoadedImage,
        ntdll: &LoadedNtDll,
    ) -> Result<(), WindowsLoadError> {
        let table_address = ntdll.exports.ki_user_inverted_function_table;

        let mut entries = Vec::new();
        for image in [&ntdll.image, application] {
            if let Some(entry) = image.inverted_function_table_entry()? {
                entries.push(entry);
            }
        }

        let header = KiUserInvertedFunctionTableHeader {
            current_size: entries.len().trunc(),
            maximum_size: MAXIMUM_INVERTED_FUNCTION_TABLE_SIZE,
            epoch: 0,
            overflow: 0,
            padding_0: [0; 3],
        };

        // `KI_USER_INVERTED_FUNCTION_TABLE` lives in ntdll's writable `.mrdata` section.
        crate::write_value::<Platform, _>(table_address, header)
            .ok_or(PeImageAccessError::MemoryAccess)?;
        let entries_address = table_address
            .checked_add(core::mem::size_of::<KiUserInvertedFunctionTableHeader>())
            .ok_or(PeImageAccessError::AddressOverflow)?;
        crate::write_slice::<Platform, _>(entries_address, &entries)
            .ok_or(PeImageAccessError::MemoryAccess)?;

        litebox_util_log::debug!(
            table:% = format_args!("{table_address:#x}");
            "Initialized ntdll!KiUserInvertedFunctionTable"
        );

        Ok(())
    }
}

struct LoadedImage {
    mapping: MappingInfo,
    parsed: PeParsedFile,
}

impl LoadedImage {
    fn inverted_function_table_entry(
        &self,
    ) -> Result<Option<KiUserInvertedFunctionTableEntry>, WindowsLoadError> {
        let Some(exception_directory) = self.parsed.exception_directory() else {
            return Ok(None);
        };
        if !exception_directory
            .size
            .is_multiple_of(RUNTIME_FUNCTION_ENTRY_SIZE)
        {
            return Err(WindowsLoadError::InvalidNtDllExceptionDirectory);
        }

        let exception_directory_address = self
            .mapping
            .base_addr
            .checked_add(exception_directory.rva)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let size_of_image = u32::try_from(self.parsed.image_size())
            .map_err(|_| PeImageAccessError::AddressOverflow)?;

        Ok(Some(KiUserInvertedFunctionTableEntry {
            exception_directory_address,
            image_base: self.mapping.base_addr,
            image_size: size_of_image,
            size_of_table: u32::try_from(exception_directory.size)
                .map_err(|_| PeImageAccessError::AddressOverflow)?,
        }))
    }
}

struct LoadedNtDll {
    image: LoadedImage,
    exports: NtDllExports,
}

#[derive(Clone, Copy, Debug)]
struct NtDllExports {
    ki_user_inverted_function_table: usize,
}

fn load_ntdll<Platform: crate::ShimPlatform, FS: crate::ShimFS>(
    platform: &'static Platform,
    fs: Arc<FS>,
    page_manager: &crate::WindowsPageManager<Platform>,
    ntdll_paths: &[&str],
) -> Result<Option<LoadedNtDll>, WindowsLoadError> {
    for path in ntdll_paths {
        match load_image_with_writable_sections(
            fs.clone(),
            path,
            platform,
            page_manager,
            NTDLL_WRITABLE_SECTIONS,
        ) {
            Ok(image) => {
                let exports = ntdll_exports::<Platform>(&image)?;
                litebox_util_log::debug!(path:% = path; "Loaded guest ntdll.dll");
                return Ok(Some(LoadedNtDll { image, exports }));
            }
            Err(error) if is_missing_file_error(&error) => {}
            Err(error) => return Err(error),
        }
    }

    litebox_util_log::debug!("Guest ntdll.dll was not found in the initial filesystem");
    Ok(None)
}

fn load_image<Platform: crate::ShimPlatform, FS: ShimFS>(
    platform: &'static Platform,
    fs: Arc<FS>,
    path: &str,
    page_manager: &crate::WindowsPageManager<Platform>,
) -> Result<LoadedImage, WindowsLoadError> {
    load_image_with_writable_sections(fs, path, platform, page_manager, &[])
}

fn load_image_with_writable_sections<Platform: crate::ShimPlatform, FS: ShimFS>(
    fs: Arc<FS>,
    path: &str,
    platform: &'static Platform,
    page_manager: &crate::WindowsPageManager<Platform>,
    writable_section_names: &[&[u8]],
) -> Result<LoadedImage, WindowsLoadError> {
    let file = PeImageFile::open(fs, path)?;
    let mut parsed = PeParsedFile::parse(&mut &file).map_err(WindowsLoadError::Parse)?;
    parsed
        .parse_trampoline(&mut &file, platform.get_syscall_entry_point())
        .map_err(WindowsLoadError::Parse)?;
    let mut mapper = PeImageMapper {
        file: &file,
        page_manager,
        chunk: alloc::vec![0u8; FILE_CHUNK_BYTES],
    };
    let mut memory = PeImageMemory::<Platform>(PhantomData);
    let mapping = parsed
        .load_with_writable_sections(&mut mapper, &mut memory, writable_section_names)
        .map_err(WindowsLoadError::Load)?;
    Ok(LoadedImage { mapping, parsed })
}

fn ntdll_exports<Platform: RawPointerProvider>(
    image: &LoadedImage,
) -> Result<NtDllExports, WindowsLoadError> {
    let export_names = [
        "LdrInitializeThunk",
        "RtlUserThreadStart",
        "KiUserInvertedFunctionTable",
    ];
    let mut memory = PeImageMemory::<Platform>(PhantomData);
    let addresses = image
        .parsed
        .find_export_addresses(image.mapping.base_addr, &mut memory, &export_names)
        .map_err(WindowsLoadError::Export)?;
    let [
        ldr_initialize_thunk,
        rtl_user_thread_start,
        ki_user_inverted_function_table,
    ]: [Option<usize>; 3] = addresses
        .try_into()
        .map_err(|_| WindowsLoadError::MissingNtDllInvertedFunctionTable)?;

    ldr_initialize_thunk.ok_or(WindowsLoadError::MissingNtDllLoaderEntrypoint)?;
    rtl_user_thread_start.ok_or(WindowsLoadError::MissingNtDllThreadEntrypoint)?;
    let ki_user_inverted_function_table = ki_user_inverted_function_table
        .ok_or(WindowsLoadError::MissingNtDllInvertedFunctionTable)?;

    Ok(NtDllExports {
        ki_user_inverted_function_table,
    })
}

/// Errors that can occur while opening, parsing, and mapping a Windows PE image.
#[derive(Debug, Error)]
pub enum WindowsLoadError {
    #[error("failed to parse PE image")]
    Parse(#[source] PeParseError<PeImageAccessError>),
    #[error("failed to load PE image")]
    Load(#[source] PeLoadError<PeImageAccessError>),
    #[error("failed to parse PE export table")]
    Export(#[source] PeExportError),
    /// Accessing the PE backing file or its mapped memory failed.
    #[error(transparent)]
    Access(#[from] PeImageAccessError),
    /// Guest ntdll.dll does not export LdrInitializeThunk.
    #[error("guest ntdll.dll does not export LdrInitializeThunk")]
    MissingNtDllLoaderEntrypoint,
    /// Guest ntdll.dll does not export RtlUserThreadStart.
    #[error("guest ntdll.dll does not export RtlUserThreadStart")]
    MissingNtDllThreadEntrypoint,
    /// Guest ntdll.dll does not export KiUserInvertedFunctionTable.
    #[error("guest ntdll.dll does not export KiUserInvertedFunctionTable")]
    MissingNtDllInvertedFunctionTable,
    /// Guest ntdll.dll has an invalid exception directory.
    #[error("guest ntdll.dll has an invalid exception directory")]
    InvalidNtDllExceptionDirectory,
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

struct PeImageMapper<'a, Platform: crate::ShimPlatform, FS: ShimFS> {
    file: &'a PeImageFile<FS>,
    page_manager: &'a crate::WindowsPageManager<Platform>,
    /// Reusable per-call I/O staging buffer for [`MapMemory::map_file`].
    chunk: Vec<u8>,
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> MapMemory for PeImageMapper<'_, Platform, FS> {
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
    #[error("failed to open PE image")]
    Open(#[from] litebox::fs::errors::OpenError),
    #[error("failed to read PE image")]
    Read(#[from] litebox::fs::errors::ReadError),
    #[error("failed to read PE image metadata")]
    FileStatus(#[from] litebox::fs::errors::FileStatusError),
    /// The backing file ended before the requested range was filled.
    #[error("short read from PE image")]
    ShortRead,
    /// A PE file offset or image address overflowed the host's `usize`.
    #[error("PE image address overflow")]
    AddressOverflow,
    #[error(transparent)]
    Mapping(#[from] MappingError),
    #[error(transparent)]
    Protect(#[from] VmemProtectError),
    #[error("mapped PE image memory access failed")]
    MemoryAccess,
}

struct PeImageMemory<Platform>(PhantomData<Platform>);

impl<Platform: RawPointerProvider> AccessMemory for PeImageMemory<Platform> {
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

fn make_pages_writable<Platform: crate::ShimPlatform>(
    page_manager: &crate::WindowsPageManager<Platform>,
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

fn protect_pages<Platform: crate::ShimPlatform>(
    page_manager: &crate::WindowsPageManager<Platform>,
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

#[cfg(all(test, target_os = "windows", target_arch = "x86_64"))]
mod tests {
    extern crate std;

    use alloc::{string::String, vec, vec::Vec};

    use super::*;

    #[allow(non_snake_case)]
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleW(lp_module_name: *const u16) -> *mut core::ffi::c_void;
        fn GetProcAddress(
            h_module: *mut core::ffi::c_void,
            lp_proc_name: *const core::ffi::c_char,
        ) -> *mut core::ffi::c_void;
        fn GetModuleFileNameW(
            h_module: *mut core::ffi::c_void,
            lp_filename: *mut u16,
            n_size: u32,
        ) -> u32;
    }

    #[test]
    fn ntdll_exports_finds_ki_user_inverted_function_table() {
        let ntdll = ntdll_module_base();
        let loaded_ntdll = loaded_module_image(ntdll);

        let exports = ntdll_exports::<crate::tests::TestPlatform>(&loaded_ntdll)
            .expect("failed to parse ntdll exports");
        let expected_table = own_inverted_function_table() as usize;

        assert_eq!(
            exports.ki_user_inverted_function_table, expected_table,
            "ntdll export lookup returned the wrong KiUserInvertedFunctionTable address"
        );
    }

    #[test]
    fn dumps_own_inverted_function_table() {
        assert_eq!(
            core::mem::size_of::<KiUserInvertedFunctionTableHeader>(),
            16
        );
        assert_eq!(core::mem::size_of::<KiUserInvertedFunctionTableEntry>(), 24);

        let table = own_inverted_function_table();
        // SAFETY: `own_inverted_function_table` resolves a live data export from the
        // current process's already-loaded ntdll. The header is copied immediately.
        let header = unsafe { read_table_value::<KiUserInvertedFunctionTableHeader>(table) };

        std::println!(
            "ntdll!KiUserInvertedFunctionTable @ {:#x}: current_size={} maximum_size={} epoch={} overflow={}",
            table as usize,
            header.current_size,
            header.maximum_size,
            header.epoch,
            header.overflow
        );

        assert!(header.maximum_size > 0);
        assert!(header.maximum_size <= MAXIMUM_INVERTED_FUNCTION_TABLE_SIZE);
        assert!(header.current_size <= header.maximum_size);
        assert!(header.current_size > 0);

        let entries = read_inverted_function_table_entries(table, header.current_size);
        for (index, entry) in entries.iter().enumerate() {
            let binary_name = module_name_from_base(entry.image_base);
            std::println!(
                "  [{index}] binary=\"{}\" exception_directory={:#x} image_base={:#x} image_size={:#x} size_of_table={:#x}",
                binary_name,
                entry.exception_directory_address,
                entry.image_base,
                entry.image_size,
                entry.size_of_table
            );
        }

        assert_table_contains_entry(
            &entries,
            "ntdll.dll",
            module_inverted_function_table_entry(ntdll_module_base()),
        );
        assert_table_contains_entry(
            &entries,
            "the test executable",
            module_inverted_function_table_entry(application_module_base()),
        );
    }

    fn own_inverted_function_table() -> *const u8 {
        let ntdll = ntdll_module_base();

        // SAFETY: The module handle was returned by `GetModuleHandleW`, and the
        // symbol name is a valid NUL-terminated C string literal.
        let table = unsafe { GetProcAddress(ntdll, c"KiUserInvertedFunctionTable".as_ptr()) };
        assert!(
            !table.is_null(),
            "ntdll.dll does not export KiUserInvertedFunctionTable"
        );

        table.cast::<u8>()
    }

    fn ntdll_module_base() -> *mut core::ffi::c_void {
        module_base(Some("ntdll.dll"))
    }

    fn application_module_base() -> *mut core::ffi::c_void {
        module_base(None)
    }

    fn module_base(name: Option<&str>) -> *mut core::ffi::c_void {
        let module_name: Option<Vec<u16>> = name.map(|name| {
            let mut name: Vec<u16> = name.encode_utf16().collect();
            name.push(0);
            name
        });
        let module_name_ptr = module_name.as_ref().map_or(core::ptr::null(), Vec::as_ptr);
        // SAFETY: The string is NUL-terminated and points to a process-owned buffer
        // that remains alive for the duration of the call. A null pointer asks for
        // the current process's executable module.
        let module = unsafe { GetModuleHandleW(module_name_ptr) };
        assert!(!module.is_null(), "module is not loaded in this process");

        module
    }

    fn module_inverted_function_table_entry(
        module: *mut core::ffi::c_void,
    ) -> KiUserInvertedFunctionTableEntry {
        loaded_module_image(module)
            .inverted_function_table_entry()
            .expect("failed to build inverted function table entry")
            .expect("loaded PE image has no exception directory")
    }

    fn loaded_module_image(module: *mut core::ffi::c_void) -> LoadedImage {
        let base_addr = module as usize;
        let mut module_memory = ModuleMemory {
            base: base_addr as *const u8,
        };
        let parsed = PeParsedFile::parse(&mut module_memory)
            .expect("failed to parse loaded PE image from memory");
        LoadedImage {
            mapping: MappingInfo {
                base_addr,
                image_size: parsed.image_size(),
                entry_point: base_addr,
            },
            parsed,
        }
    }

    fn module_name_from_base(image_base: usize) -> String {
        let module = image_base as *mut core::ffi::c_void;
        let mut buffer = vec![0u16; 260];
        loop {
            // SAFETY: `module` is the image base reported by ntdll's table, which is
            // also the HMODULE for the loaded image. `buffer` is valid for `len` UTF-16
            // code units and remains alive for the duration of the call.
            let len = unsafe {
                GetModuleFileNameW(
                    module,
                    buffer.as_mut_ptr(),
                    u32::try_from(buffer.len()).unwrap(),
                )
            } as usize;
            if len == 0 {
                return String::from("<unknown>");
            }
            if len < buffer.len() {
                return String::from_utf16_lossy(&buffer[..len]);
            }
            buffer.resize(buffer.len() * 2, 0);
        }
    }

    fn read_inverted_function_table_entries(
        table: *const u8,
        current_size: u32,
    ) -> Vec<KiUserInvertedFunctionTableEntry> {
        let entries = table.wrapping_add(core::mem::size_of::<KiUserInvertedFunctionTableHeader>());
        let entry_size = core::mem::size_of::<KiUserInvertedFunctionTableEntry>();
        (0..current_size as usize)
            .map(|index| {
                let entry_address = entries.wrapping_add(index * entry_size);
                // SAFETY: The header just read from ntdll says `current_size` entries are
                // initialized immediately after the header in this same exported table.
                unsafe { read_table_value::<KiUserInvertedFunctionTableEntry>(entry_address) }
            })
            .collect()
    }

    fn assert_table_contains_entry(
        entries: &[KiUserInvertedFunctionTableEntry],
        name: &str,
        expected: KiUserInvertedFunctionTableEntry,
    ) {
        let actual = entries
            .iter()
            .find(|entry| entry.image_base == expected.image_base)
            .unwrap_or_else(|| {
                panic!("{name} was not present in the host inverted function table")
            });

        assert_eq!(
            actual.exception_directory_address,
            expected.exception_directory_address
        );
        assert_eq!(actual.image_size, expected.image_size);
        assert_eq!(actual.size_of_table, expected.size_of_table);
    }

    unsafe fn read_table_value<T: zerocopy::FromBytes>(address: *const u8) -> T {
        // SAFETY: The caller guarantees that `address` points to at least
        // `size_of::<T>()` readable bytes.
        let bytes = unsafe { core::slice::from_raw_parts(address, core::mem::size_of::<T>()) };
        T::read_from_bytes(bytes).expect("failed to read table value")
    }

    struct ModuleMemory {
        base: *const u8,
    }

    impl ReadAt for ModuleMemory {
        type Error = core::convert::Infallible;

        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
            let offset: usize = offset.try_into().unwrap();
            // SAFETY: The test only constructs `ModuleMemory` from live module image
            // bases returned by `GetModuleHandleW`. `PeParsedFile::parse` reads PE
            // headers and section headers, which remain mapped in loaded images.
            unsafe {
                core::ptr::copy_nonoverlapping(self.base.add(offset), buf.as_mut_ptr(), buf.len());
            }
            Ok(())
        }

        fn size(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::MAX)
        }
    }
}
