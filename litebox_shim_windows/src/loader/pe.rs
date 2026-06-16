// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::btree_map::BTreeMap;
use alloc::{ffi::CString, string::String, sync::Arc, vec::Vec};
use core::{
    marker::PhantomData,
    mem::{align_of, size_of},
};
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
    PeLoadError, PeParseError, PeParsedFile, Protection, ReadAt, build_api_set_namespace,
    page_align_down,
};
use rangemap::RangeMap;
use thiserror::Error;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

use crate::nt_types::{
    ClientId, PebBitField, ProcessEnvironmentBlock, RtlUserProcFlags, RtlUserProcessParameters,
    ThreadEnvironmentBlock, UnicodeString, X64Context,
};
use crate::syscalls::mm::{MemoryType, PageProtection};
use crate::{MutPtr, ShimFS};

const NTDLL_WRITABLE_SECTIONS: &[&[u8]] = &[b".mrdata"];
const NTDLL_PATHS: &[&str] = &["/Windows/System32/ntdll.dll", "/windows/system32/ntdll.dll"];
const RUNTIME_FUNCTION_ENTRY_SIZE: usize = 12;
const ZERO_CHUNK: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
const FILE_CHUNK_BYTES: usize = 64 * 1024;
const INITIAL_STACK_SIZE: usize = 1024 * 1024;
const WINDOWS_SHARED_SECTION_SIZE: usize = 0x1_0000;
const CSR_SERVER_DLL_MAX: usize = 4;
const BASESRV_SERVERDLL_INDEX: usize = 1;
const WINDOWS_DIRECTORY: &str = r"C:\Windows";
const WINDOWS_SYSTEM_DIRECTORY: &str = r"C:\Windows\System32";
const WINDOWS_NAMED_OBJECT_DIRECTORY: &str = r"\BaseNamedObjects";
const WINDOWS_OS_MAJOR_VERSION: u16 = 10;
const WINDOWS_OS_MINOR_VERSION: u16 = 0;
const WINDOWS_OS_BUILD_NUMBER: u16 = 19041;
const WINDOWS_OS_PLATFORM_WIN32_NT: u32 = 2;
const WINDOWS_TIME_ZONE_ID_INVALID: u32 = u32::MAX;
const WINDOWS_CRITICAL_SECTION_TIMEOUT_100NS: i64 = -150 * 10_000_000;
const WINDOWS_HEAP_SEGMENT_RESERVE: u64 = 1024 * 1024;
const WINDOWS_HEAP_SEGMENT_COMMIT: u64 = 2 * PAGE_SIZE as u64;
const WINDOWS_HEAP_DECOMMIT_TOTAL_FREE_THRESHOLD: u64 = 64 * 1024;
const WINDOWS_HEAP_DECOMMIT_FREE_BLOCK_THRESHOLD: u64 = PAGE_SIZE as u64;
const WINDOWS_NT_TIB_VERSION: usize = 30 << 8;
const INITIAL_PROCESS_ID: usize = 1;
const INITIAL_THREAD_ID: usize = 1;

macro_rules! write_static_server_data_field {
    ($platform:ty, $base:expr, $field:ident, $value:expr $(,)?) => {
        write_guest_field_at_offset::<$platform, _, _>(
            $base,
            core::mem::offset_of!(BaseStaticServerData, $field),
            $value,
        )
    };
}

pub(crate) struct WindowsProcessEnvironment {
    pub(crate) peb: usize,
    pub(crate) teb: usize,
    pub(crate) context: usize,
}

pub(crate) struct PeLoadInfo<Platform: crate::ShimPlatform> {
    pub(crate) entry_point: usize,
    pub(crate) stack_top: usize,
    pub(crate) ntdll_mapping: Option<MappingInfo>,
    pub(crate) virtual_allocations: crate::WindowsVirtualAllocations<Platform>,
    pub(crate) environment: WindowsProcessEnvironment,
}

struct ProcessEnvironmentInput<'a> {
    image: &'a PeParsedFile,
    image_base_address: usize,
    image_path: &'a str,
    argv: &'a [CString],
    envp: &'a [CString],
    stack_base: usize,
    stack_allocation_top: usize,
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

    pub(crate) fn load(
        &self,
        path: &str,
        argv: &[CString],
        envp: &[CString],
    ) -> Result<PeLoadInfo<Platform>, WindowsLoadError> {
        let image = load_image(self.platform, self.fs.clone(), path, self.page_manager)?;
        let application_entry_point = image.mapping.entry_point;
        let ntdll = load_ntdll(self.platform, self.fs.clone(), self.page_manager)?;

        let entry_point = if let Some(ntdll) = &ntdll {
            if !ntdll.image.parsed.has_trampoline() {
                return Err(WindowsLoadError::UnrewrittenNtDll);
            }
            Self::initialize_ki_user_inverted_function_table(&image, ntdll)?;
            ntdll.exports.ldr_initialize_thunk
        } else {
            application_entry_point
        };

        let length =
            NonZeroPageSize::new(INITIAL_STACK_SIZE).ok_or(PeImageAccessError::AddressOverflow)?;
        // SAFETY: `suggested_address` is `None` and `CreatePagesFlags::empty()` does not set
        // `fixed_addr`, so the page manager picks an unused region and cannot replace a mapping.
        let stack_base = unsafe {
            self.page_manager
                .create_stack_pages(None, length, CreatePagesFlags::empty())
        }
        .map_err(PeImageAccessError::Mapping)?;
        let stack_allocation_top = stack_base
            .as_usize()
            .checked_add(INITIAL_STACK_SIZE)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let stack_top = if stack_allocation_top.is_multiple_of(16) {
            stack_allocation_top - core::mem::size_of::<usize>()
        } else {
            stack_allocation_top
        };

        let environment = self.create_process_environment(ProcessEnvironmentInput {
            image: &image.parsed,
            image_base_address: image.mapping.base_addr,
            image_path: path,
            argv,
            envp,
            stack_base: stack_base.as_usize(),
            stack_allocation_top,
        })?;
        if let Some(ntdll) = &ntdll {
            let context = X64Context::initial_thread_context(
                ntdll.exports.rtl_user_thread_start,
                application_entry_point,
                stack_top,
                environment.peb,
            );
            write_guest_slice::<Platform, _>(environment.context, context.as_bytes())?;
        }

        let virtual_allocations =
            crate::WindowsVirtualAllocations::<Platform>::new(BTreeMap::new());
        register_image_virtual_allocation(&virtual_allocations, image.mapping, image.pages);
        let ntdll_mapping = if let Some(ntdll) = ntdll {
            let mapping = ntdll.image.mapping;
            register_image_virtual_allocation(&virtual_allocations, mapping, ntdll.image.pages);
            Some(mapping)
        } else {
            None
        };

        Ok(PeLoadInfo {
            entry_point,
            stack_top,
            ntdll_mapping,
            virtual_allocations,
            environment,
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
        write_guest_value::<Platform, _>(table_address, header)?;
        let entries_address = table_address
            .checked_add(core::mem::size_of::<KiUserInvertedFunctionTableHeader>())
            .ok_or(PeImageAccessError::AddressOverflow)?;
        write_guest_slice::<Platform, _>(entries_address, &entries)?;

        litebox_util_log::debug!(
            table:% = format_args!("{table_address:#x}");
            "Initialized ntdll!KiUserInvertedFunctionTable"
        );

        Ok(())
    }

    fn create_process_environment(
        &self,
        input: ProcessEnvironmentInput<'_>,
    ) -> Result<WindowsProcessEnvironment, WindowsLoadError> {
        let create_pages = |size: usize| -> Result<usize, PeImageAccessError> {
            let aligned_length = size.next_multiple_of(PAGE_SIZE);
            let length =
                NonZeroPageSize::new(aligned_length).ok_or(PeImageAccessError::AddressOverflow)?;
            // SAFETY: `suggested_address` is `None` and `CreatePagesFlags::empty()` leaves address
            // selection to the page manager, so this cannot replace an existing mapping.
            let ptr = unsafe {
                self.page_manager.create_writable_pages(
                    None,
                    length,
                    CreatePagesFlags::empty(),
                    |_| Ok(0),
                )
            }?;
            Ok(ptr.as_usize())
        };
        let teb_ptr = create_pages(size_of::<ThreadEnvironmentBlock>())?;
        let peb_ptr = create_pages(size_of::<ProcessEnvironmentBlock>())?;
        let api_set_map = build_api_set_namespace(API_SET_MAPPINGS)
            .map_err(|_| PeImageAccessError::AddressOverflow)?;
        let api_set_map_ptr = create_pages(api_set_map.len())?;
        write_guest_slice::<Platform, _>(api_set_map_ptr, &api_set_map)?;
        let ctx_ptr = create_pages(size_of::<X64Context>())?;

        let win32_image_path = win32_image_path(input.image_path);
        let dos_image_path = dos_image_path(input.image_path);
        let current_directory_path = Utf16StringBuffer::new(r"C:\")?;
        let dll_path = Utf16StringBuffer::new(r"C:\Windows\System32;C:\")?;
        let image_path_name = Utf16StringBuffer::new(&dos_image_path)?;
        let command_line =
            Utf16StringBuffer::new(&windows_command_line(&win32_image_path, input.argv))?;
        let window_title = Utf16StringBuffer::new(&dos_image_path)?;
        let desktop_info = Utf16StringBuffer::new("")?;
        let shell_info = Utf16StringBuffer::new("")?;
        let runtime_data = Utf16StringBuffer::new("")?;
        let redirection_dll_name = Utf16StringBuffer::new("")?;
        let environment_block = windows_environment_block(input.envp);
        let environment_size = checked_mul(environment_block.len(), size_of::<u16>())?;
        let environment_ptr = create_pages(environment_size)?;
        write_guest_slice::<Platform, _>(environment_ptr, &environment_block)?;
        let process_parameter_strings = [
            &current_directory_path,
            &dll_path,
            &image_path_name,
            &command_line,
            &window_title,
            &desktop_info,
            &shell_info,
            &runtime_data,
            &redirection_dll_name,
        ];
        let process_parameters_length = process_parameter_strings.iter().try_fold(
            size_of::<RtlUserProcessParameters>(),
            |length, string| {
                length
                    .checked_add(usize::from(string.maximum_length))
                    .ok_or(PeImageAccessError::AddressOverflow)
            },
        )?;
        let process_parameters_allocation_length =
            process_parameters_length.next_multiple_of(PAGE_SIZE);
        let process_parameters_ptr = create_pages(process_parameters_length)?;

        let mut process_parameters = RtlUserProcessParameters::new_zeroed();
        process_parameters.maximum_length = to_u32(process_parameters_allocation_length)?;
        process_parameters.length = to_u32(process_parameters_length)?;
        process_parameters.flags = RtlUserProcFlags::NORMALIZED.bits();
        process_parameters.environment = environment_ptr;
        process_parameters.environment_size =
            u64::try_from(environment_size).map_err(|_| PeImageAccessError::AddressOverflow)?;
        let mut process_parameters_allocation =
            GuestMemoryAllocator::new(process_parameters_ptr, process_parameters_length)?;
        let guest_process_parameters =
            process_parameters_allocation.allocate::<Platform, RtlUserProcessParameters>()?;
        process_parameters.current_directory.dos_path = allocate_guest_unicode_string::<Platform>(
            &mut process_parameters_allocation,
            &current_directory_path,
        )?;
        process_parameters.dll_path = allocate_guest_unicode_string::<Platform>(
            &mut process_parameters_allocation,
            &dll_path,
        )?;
        process_parameters.image_path_name = allocate_guest_unicode_string::<Platform>(
            &mut process_parameters_allocation,
            &image_path_name,
        )?;
        process_parameters.command_line = allocate_guest_unicode_string::<Platform>(
            &mut process_parameters_allocation,
            &command_line,
        )?;
        process_parameters.window_title = allocate_guest_unicode_string::<Platform>(
            &mut process_parameters_allocation,
            &window_title,
        )?;
        process_parameters.desktop_info = allocate_guest_unicode_string::<Platform>(
            &mut process_parameters_allocation,
            &desktop_info,
        )?;
        process_parameters.shell_info = allocate_guest_unicode_string::<Platform>(
            &mut process_parameters_allocation,
            &shell_info,
        )?;
        process_parameters.runtime_data = allocate_guest_unicode_string::<Platform>(
            &mut process_parameters_allocation,
            &runtime_data,
        )?;
        process_parameters.redirection_dll_name = allocate_guest_unicode_string::<Platform>(
            &mut process_parameters_allocation,
            &redirection_dll_name,
        )?;
        guest_process_parameters
            .write_at_offset(0, process_parameters)
            .ok_or(PeImageAccessError::MemoryAccess)?;

        let read_only_shared_memory_base = create_pages(WINDOWS_SHARED_SECTION_SIZE)?;
        let mut shared_heap =
            GuestMemoryAllocator::new(read_only_shared_memory_base, WINDOWS_SHARED_SECTION_SIZE)?;
        let read_only_static_server_data =
            initialize_windows_static_server_data::<Platform>(&mut shared_heap)?;
        let mut peb = ProcessEnvironmentBlock::new_zeroed();
        peb.image_base_address = input.image_base_address;
        if input.image_base_address != input.image.image_base() || input.image.has_dynamic_base() {
            peb.bit_field = PebBitField::IS_IMAGE_DYNAMICALLY_RELOCATED.bits();
        }
        let process_heaps = initial_process_heaps_array(peb_ptr)?;
        let fast_peb_lock = create_pages(size_of::<RtlCriticalSection>())?;
        write_guest_value::<Platform, _>(fast_peb_lock, RtlCriticalSection::initialized(0))?;
        let loader_lock = create_pages(size_of::<RtlCriticalSection>())?;
        write_guest_value::<Platform, _>(loader_lock, RtlCriticalSection::initialized(0))?;

        peb.api_set_map = api_set_map_ptr;
        peb.process_parameters = process_parameters_ptr;
        peb.fast_peb_lock = fast_peb_lock;
        peb.shared_data = read_only_shared_memory_base;
        peb.number_of_processors = 1;
        peb.critical_section_timeout = WINDOWS_CRITICAL_SECTION_TIMEOUT_100NS;
        peb.heap_segment_reserve = WINDOWS_HEAP_SEGMENT_RESERVE;
        peb.heap_segment_commit = WINDOWS_HEAP_SEGMENT_COMMIT;
        peb.heap_de_commit_total_free_threshold = WINDOWS_HEAP_DECOMMIT_TOTAL_FREE_THRESHOLD;
        peb.heap_de_commit_free_block_threshold = WINDOWS_HEAP_DECOMMIT_FREE_BLOCK_THRESHOLD;
        peb.maximum_number_of_heaps = process_heaps.maximum_number_of_heaps;
        peb.process_heaps = process_heaps.address;
        peb.loader_lock = loader_lock;
        peb.active_process_affinity_mask = 1;
        peb.os_major_version = u32::from(WINDOWS_OS_MAJOR_VERSION);
        peb.os_minor_version = u32::from(WINDOWS_OS_MINOR_VERSION);
        peb.os_build_number = WINDOWS_OS_BUILD_NUMBER;
        peb.os_platform_id = WINDOWS_OS_PLATFORM_WIN32_NT;
        peb.image_subsystem = u32::from(input.image.subsystem());
        peb.image_subsystem_major_version = u32::from(input.image.major_subsystem_version());
        peb.image_subsystem_minor_version = u32::from(input.image.minor_subsystem_version());
        peb.read_only_shared_memory_base = read_only_shared_memory_base;
        peb.read_only_static_server_data = read_only_static_server_data;
        peb.csr_server_read_only_shared_memory_base = read_only_shared_memory_base as u64;
        write_guest_value::<Platform, _>(peb_ptr, peb)?;

        let mut teb = ThreadEnvironmentBlock::new_zeroed();
        teb.nt_tib.exception_list = 0;
        teb.nt_tib.stack_base = input.stack_allocation_top;
        teb.nt_tib.stack_limit = input.stack_base;
        teb.nt_tib.fiber_data_or_version = WINDOWS_NT_TIB_VERSION;
        teb.nt_tib.self_pointer = teb_ptr;
        // TODO: set real ID
        teb.client_id = ClientId {
            unique_process: INITIAL_PROCESS_ID,
            unique_thread: INITIAL_THREAD_ID,
        };
        teb.thread_local_storage_pointer =
            teb_ptr + core::mem::offset_of!(ThreadEnvironmentBlock, tls_slots);
        teb.process_environment_block = peb_ptr;
        teb.real_client_id = teb.client_id;
        teb.activation_context_stack_pointer =
            teb_ptr + core::mem::offset_of!(ThreadEnvironmentBlock, activation_stack);
        teb.static_unicode_string =
            initial_teb_static_unicode_string(teb_ptr, &teb.static_unicode_buffer)?;
        teb.deallocation_stack = input.stack_base;
        write_guest_value::<Platform, _>(teb_ptr, teb)?;
        Ok(WindowsProcessEnvironment {
            peb: peb_ptr,
            teb: teb_ptr,
            context: ctx_ptr,
        })
    }
}

fn initialize_windows_static_server_data<Platform: RawPointerProvider>(
    shared_heap: &mut GuestMemoryAllocator,
) -> Result<usize, PeImageAccessError> {
    let read_only_static_server_data =
        shared_heap.allocate_array::<Platform, usize>(CSR_SERVER_DLL_MAX)?;
    let client_base_static_server_data =
        shared_heap.allocate::<Platform, BaseStaticServerData>()?;
    initialize_static_server_data::<Platform>(shared_heap, client_base_static_server_data)?;

    read_only_static_server_data
        .write_at_offset(
            BASESRV_SERVERDLL_INDEX.cast_signed(),
            client_base_static_server_data.as_usize(),
        )
        .ok_or(PeImageAccessError::MemoryAccess)?;
    Ok(read_only_static_server_data.as_usize())
}

fn initialize_static_server_data<Platform: RawPointerProvider>(
    shared_heap: &mut GuestMemoryAllocator,
    base_static_server_data: MutPtr<Platform, BaseStaticServerData>,
) -> Result<(), PeImageAccessError> {
    let windows_directory =
        allocate_guest_unicode_string_from_str::<Platform>(shared_heap, WINDOWS_DIRECTORY)?;
    write_static_server_data_field!(
        Platform,
        base_static_server_data,
        windows_directory,
        windows_directory,
    )?;
    let windows_system_directory =
        allocate_guest_unicode_string_from_str::<Platform>(shared_heap, WINDOWS_SYSTEM_DIRECTORY)?;
    write_static_server_data_field!(
        Platform,
        base_static_server_data,
        windows_system_directory,
        windows_system_directory,
    )?;
    let named_object_directory = allocate_guest_unicode_string_from_str::<Platform>(
        shared_heap,
        WINDOWS_NAMED_OBJECT_DIRECTORY,
    )?;
    write_static_server_data_field!(
        Platform,
        base_static_server_data,
        named_object_directory,
        named_object_directory,
    )?;
    write_static_server_data_field!(
        Platform,
        base_static_server_data,
        windows_major_version,
        WINDOWS_OS_MAJOR_VERSION,
    )?;
    write_static_server_data_field!(
        Platform,
        base_static_server_data,
        windows_minor_version,
        WINDOWS_OS_MINOR_VERSION,
    )?;
    write_static_server_data_field!(
        Platform,
        base_static_server_data,
        build_number,
        WINDOWS_OS_BUILD_NUMBER,
    )?;

    let ini_file_mapping = shared_heap
        .allocate::<Platform, IniFileMapping>()?
        .as_usize();
    write_static_server_data_field!(
        Platform,
        base_static_server_data,
        ini_file_mapping,
        ini_file_mapping,
    )?;
    write_static_server_data_field!(
        Platform,
        base_static_server_data,
        termsrv_client_time_zone_id,
        WINDOWS_TIME_ZONE_ID_INVALID,
    )?;
    Ok(())
}

fn register_image_virtual_allocation<Platform: crate::ShimPlatform>(
    virtual_allocations: &crate::WindowsVirtualAllocations<Platform>,
    mapping: MappingInfo,
    pages: RangeMap<usize, PageProtection>,
) {
    virtual_allocations.write().insert(
        mapping.base_addr,
        crate::WindowsVirtualAllocation {
            base: mapping.base_addr,
            size: mapping.mapping_size,
            allocation_protect: PageProtection::PAGE_EXECUTE_WRITECOPY,
            type_: MemoryType::MEM_IMAGE,
            pages,
        },
    );
}

struct LoadedImage {
    mapping: MappingInfo,
    pages: RangeMap<usize, PageProtection>,
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

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct RtlCriticalSection {
    debug_info: usize,
    lock_count: i32,
    recursion_count: u32,
    owning_thread: usize,
    lock_semaphore: usize,
    spin_count: usize,
}

impl RtlCriticalSection {
    const fn initialized(spin_count: usize) -> Self {
        Self {
            debug_info: usize::MAX,
            lock_count: -1,
            recursion_count: 0,
            owning_thread: 0,
            lock_semaphore: 0,
            spin_count,
        }
    }
}

struct GuestMemoryAllocator {
    cursor: usize,
    end: usize,
}

impl GuestMemoryAllocator {
    fn new(base: usize, size: usize) -> Result<Self, PeImageAccessError> {
        let cursor = base;
        let end = checked_add(base, size)?;
        if cursor > end {
            return Err(PeImageAccessError::AddressOverflow);
        }
        Ok(Self { cursor, end })
    }

    fn allocate<Platform, T>(&mut self) -> Result<MutPtr<Platform, T>, PeImageAccessError>
    where
        Platform: RawPointerProvider,
        T: FromBytes + IntoBytes,
    {
        self.allocate_array::<Platform, T>(1)
    }

    fn allocate_array<Platform, T>(
        &mut self,
        count: usize,
    ) -> Result<MutPtr<Platform, T>, PeImageAccessError>
    where
        Platform: RawPointerProvider,
        T: FromBytes + IntoBytes,
    {
        let address = self.allocate_bytes(checked_mul(size_of::<T>(), count)?, align_of::<T>())?;
        Ok(MutPtr::<Platform, T>::from_usize(address))
    }

    fn allocate_bytes(
        &mut self,
        size: usize,
        alignment: usize,
    ) -> Result<usize, PeImageAccessError> {
        debug_assert!(alignment.is_power_of_two());
        let address = self
            .cursor
            .checked_next_multiple_of(alignment)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        let cursor = checked_add(address, size)?;
        if cursor > self.end {
            return Err(PeImageAccessError::AddressOverflow);
        }
        self.cursor = cursor;
        Ok(address)
    }
}

// Reference layout from ReactOS `sdk/include/reactos/subsys/win/base.h`.
#[repr(C)]
#[derive(FromBytes, IntoBytes)]
struct BaseStaticServerData {
    windows_directory: UnicodeString,
    windows_system_directory: UnicodeString,
    named_object_directory: UnicodeString,
    windows_major_version: u16,
    windows_minor_version: u16,
    build_number: u16,
    csd_number: u16,
    rc_number: u16,
    csd_version: [u16; 128],
    padding_0: [u8; 6],
    sys_info: SystemBasicInformation,
    time_of_day: SystemTimeOfDayInformation,
    ini_file_mapping: usize,
    nls_user_info: NlsUserInfo,
    default_separate_vdm: u8,
    is_wow_task_ready: u8,
    padding_1: [u8; 6],
    windows_sys32_x86_directory: UnicodeString,
    f_termsrv_app_install_mode: u8,
    padding_2: [u8; 3],
    tzi_termsrv_client_time_zone: TimeZoneInformation,
    kt_termsrv_client_bias: KSystemTime,
    termsrv_client_time_zone_id: u32,
    luid_device_maps_enabled: u8,
    padding_3: [u8; 3],
    termsrv_client_time_zone_change_num: u32,
}

#[allow(clippy::struct_field_names)]
#[repr(C)]
#[derive(FromBytes, IntoBytes)]
struct IniFileMapping {
    file_names: usize,
    default_file_name_mapping: usize,
    win_ini_file_mapping: usize,
    reserved: u32,
    padding: [u8; 4],
}

#[repr(C)]
#[derive(FromBytes, IntoBytes)]
struct SystemBasicInformation {
    reserved: u32,
    timer_resolution: u32,
    page_size: u32,
    number_of_physical_pages: u32,
    lowest_physical_page_number: u32,
    highest_physical_page_number: u32,
    allocation_granularity: u32,
    padding_0: [u8; 4],
    minimum_user_mode_address: usize,
    maximum_user_mode_address: usize,
    active_processors_affinity_mask: usize,
    number_of_processors: u8,
    padding_1: [u8; 7],
}

#[repr(C)]
#[derive(FromBytes, IntoBytes)]
struct SystemTimeOfDayInformation {
    boot_time: i64,
    current_time: i64,
    time_zone_bias: i64,
    time_zone_id: u32,
    reserved: u32,
    boot_time_bias: u64,
    sleep_time_bias: u64,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes)]
struct NlsUserInfo {
    s_language: [u16; 80],
    i_country: [u16; 80],
    s_country: [u16; 80],
    s_list: [u16; 80],
    i_measure: [u16; 80],
    i_paper_size: [u16; 80],
    s_decimal: [u16; 80],
    s_thousand: [u16; 80],
    s_grouping: [u16; 80],
    i_digits: [u16; 80],
    i_l_zero: [u16; 80],
    i_neg_number: [u16; 80],
    s_native_digits: [u16; 80],
    num_shape: [u16; 80],
    s_currency: [u16; 80],
    s_mon_dec_sep: [u16; 80],
    s_mon_thou_sep: [u16; 80],
    s_mon_grouping: [u16; 80],
    i_curr_digits: [u16; 80],
    i_currency: [u16; 80],
    i_neg_curr: [u16; 80],
    s_positive_sign: [u16; 80],
    s_negative_sign: [u16; 80],
    s_time_format: [u16; 80],
    s_time: [u16; 80],
    i_time: [u16; 80],
    i_tl_zero: [u16; 80],
    i_time_prefix: [u16; 80],
    s_1159: [u16; 80],
    s_2359: [u16; 80],
    s_short_date: [u16; 80],
    s_date: [u16; 80],
    i_date: [u16; 80],
    s_year_month: [u16; 80],
    s_long_date: [u16; 80],
    i_cal_type: [u16; 80],
    i_first_day_of_week: [u16; 80],
    i_first_week_of_year: [u16; 80],
    locale: [u16; 80],
    user_locale_id: u32,
    interactive_user_luid: Luid,
    ul_cache_update_count: u32,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes)]
struct Luid {
    low_part: u32,
    high_part: i32,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes)]
struct TimeZoneInformation {
    bias: i32,
    standard_name: [u16; 32],
    standard_date: SystemTime,
    standard_bias: i32,
    daylight_name: [u16; 32],
    daylight_date: SystemTime,
    daylight_bias: i32,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes)]
struct SystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes)]
struct KSystemTime {
    low_part: u32,
    high_1_time: i32,
    high_2_time: i32,
}

const API_SET_MAPPINGS: &[(&str, &str)] = &[
    ("api-ms-win-core-apiquery-l1-1-0", "ntdll.dll"),
    ("api-ms-win-core-apiquery-l1-1-2", "ntdll.dll"),
    ("api-ms-win-core-apiquery-l2-1-1", "kernelbase.dll"),
    ("api-ms-win-core-appcompat-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-appcompat-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-appinit-l1-1-0", "kernel32.dll"),
    ("api-ms-win-core-atoms-l1-1-0", "kernel32.dll"),
    ("api-ms-win-core-backgroundtask-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-calendar-l1-1-0", "kernel32.dll"),
    ("api-ms-win-core-comm-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-comm-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-commandlinetoargv-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-console-ansi-l2-1-0", "kernel32.dll"),
    ("api-ms-win-core-console-internal-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l1-2-1", "kernelbase.dll"),
    ("api-ms-win-core-console-l1-2-2", "kernelbase.dll"),
    ("api-ms-win-core-console-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l2-2-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l3-1-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l3-2-0", "kernelbase.dll"),
    ("api-ms-win-core-crt-l1-1-0", "ntdll.dll"),
    ("api-ms-win-core-crt-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-datetime-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-datetime-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-datetime-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-debug-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-debug-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-debug-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-delayload-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-delayload-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-downlevel-shlwapi-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-errorhandling-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-errorhandling-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-errorhandling-l1-1-3", "kernelbase.dll"),
    ("api-ms-win-core-fibers-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-fibers-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-fibers-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-fibers-l2-1-1", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-2-1", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-2-2", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-2-3", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-2-5", "kernelbase.dll"),
    ("api-ms-win-core-file-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-file-l2-1-1", "kernelbase.dll"),
    ("api-ms-win-core-file-l2-1-2", "kernelbase.dll"),
    ("api-ms-win-core-file-l2-1-3", "kernelbase.dll"),
    ("api-ms-win-core-file-l2-1-4", "kernelbase.dll"),
    ("api-ms-win-core-handle-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-heap-obsolete-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-heap-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-heap-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-heap-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-interlocked-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-io-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-io-l1-1-1", "kernel32.dll"),
    ("api-ms-win-core-job-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-largeinteger-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l1-2-1", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l1-2-2", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l1-2-3", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-localization-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-localization-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-localization-l1-2-4", "kernelbase.dll"),
    ("api-ms-win-core-localization-l2-1-0", "kernelbase.dll"),
    (
        "api-ms-win-core-localization-private-l1-1-0",
        "kernelbase.dll",
    ),
    ("api-ms-win-core-localregistry-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-memory-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-memory-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-memory-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-memory-l1-1-9", "kernelbase.dll"),
    ("api-ms-win-core-misc-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-namedpipe-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-namedpipe-l1-2-1", "kernelbase.dll"),
    ("api-ms-win-core-namedpipe-l1-2-2", "kernelbase.dll"),
    ("api-ms-win-core-namespace-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-normalization-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-path-l1-1-0", "kernelbase.dll"),
    (
        "api-ms-win-core-processenvironment-l1-1-0",
        "kernelbase.dll",
    ),
    (
        "api-ms-win-core-processenvironment-l1-1-1",
        "kernelbase.dll",
    ),
    (
        "api-ms-win-core-processenvironment-l1-2-0",
        "kernelbase.dll",
    ),
    ("api-ms-win-core-processsnapshot-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-processthreads-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-processthreads-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-processthreads-l1-1-2", "kernelbase.dll"),
    ("api-ms-win-core-processthreads-l1-1-3", "kernelbase.dll"),
    ("api-ms-win-core-processthreads-l1-1-8", "kernel32.dll"),
    ("api-ms-win-core-processtopology-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-profile-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-pcw-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-psapi-ansi-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-psapi-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-realtime-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-registry-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-rtlsupport-l1-1-0", "ntdll.dll"),
    ("api-ms-win-core-rtlsupport-l1-1-1", "ntdll.dll"),
    ("api-ms-win-core-rtlsupport-l1-2-2", "ntdll.dll"),
    ("api-ms-win-core-sidebyside-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-string-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-string-l2-1-1", "kernelbase.dll"),
    ("api-ms-win-core-synch-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-synch-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-synch-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-synch-l1-2-1", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-2-1", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-2-3", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-2-8", "kernelbase.dll"),
    ("api-ms-win-core-systemtopology-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-systemtopology-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-threadpool-legacy-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-threadpool-l1-2-0", "kernelbase.dll"),
    (
        "api-ms-win-core-threadpool-private-l1-1-0",
        "kernelbase.dll",
    ),
    ("api-ms-win-core-timezone-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-util-l1-1-0", "kernelbase.dll"),
    (
        "api-ms-win-core-windowserrorreporting-l1-1-0",
        "kernelbase.dll",
    ),
    (
        "api-ms-win-core-windowserrorreporting-l1-1-1",
        "kernelbase.dll",
    ),
    (
        "api-ms-win-core-windowserrorreporting-l1-1-2",
        "kernelbase.dll",
    ),
    (
        "api-ms-win-core-windowserrorreporting-l1-1-3",
        "kernelbase.dll",
    ),
    ("api-ms-win-core-wow64-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-wow64-l1-1-1", "kernelbase.dll"),
    ("api-ms-win-core-wow64-l1-1-3", "kernelbase.dll"),
    ("api-ms-win-core-xstate-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-xstate-l2-1-1", "kernelbase.dll"),
    ("api-ms-win-core-xstate-l2-1-2", "kernelbase.dll"),
    ("api-ms-win-eventing-consumer-l1-1-0", "sechost.dll"),
    ("api-ms-win-eventing-consumer-l1-1-1", "sechost.dll"),
    ("api-ms-win-eventing-controller-l1-1-0", "sechost.dll"),
    ("api-ms-win-eventing-provider-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-security-audit-l1-1-0", "sechost.dll"),
    ("api-ms-win-security-audit-l1-1-1", "sechost.dll"),
    ("api-ms-win-security-appcontainer-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-security-base-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-security-base-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-security-base-private-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-security-lsalookup-l1-1-0", "sechost.dll"),
    ("api-ms-win-security-sddl-l1-1-0", "sechost.dll"),
    ("api-ms-win-service-core-l1-1-0", "sechost.dll"),
    ("api-ms-win-service-core-l1-1-1", "sechost.dll"),
    ("api-ms-win-service-core-l1-1-2", "sechost.dll"),
    ("api-ms-win-service-management-l1-1-0", "sechost.dll"),
    ("api-ms-win-service-management-l2-1-0", "sechost.dll"),
    ("api-ms-win-service-private-l1-1-0", "sechost.dll"),
    ("api-ms-win-service-private-l1-1-2", "sechost.dll"),
    ("api-ms-win-service-private-l1-1-3", "sechost.dll"),
    ("api-ms-win-service-winsvc-l1-1-0", "sechost.dll"),
    ("ext-ms-win-appcompat-apphelp-l1-1-2", "apphelp.dll"),
    ("ext-ms-win-authz-context-l1-1-0", "authz.dll"),
    ("ext-ms-win-core-winrt-remote-l1-1-0", ""),
    ("ext-ms-win-oobe-query-l1-1-0", ""),
    (
        "ext-ms-win-packagevirtualizationcontext-l1-1-0",
        "daxexec.dll",
    ),
    ("ext-ms-win-rpc-ssl-l1-1-0", "rpcrtremote.dll"),
];

fn checked_add(left: usize, right: usize) -> Result<usize, PeImageAccessError> {
    left.checked_add(right)
        .ok_or(PeImageAccessError::AddressOverflow)
}

fn checked_mul(left: usize, right: usize) -> Result<usize, PeImageAccessError> {
    left.checked_mul(right)
        .ok_or(PeImageAccessError::AddressOverflow)
}

fn to_u32(value: usize) -> Result<u32, PeImageAccessError> {
    u32::try_from(value).map_err(|_| PeImageAccessError::AddressOverflow)
}

fn write_guest_value<Platform, T>(address: usize, value: T) -> Result<(), PeImageAccessError>
where
    Platform: RawPointerProvider,
    T: FromBytes + IntoBytes,
{
    crate::write_value::<Platform, T>(address, value).ok_or(PeImageAccessError::MemoryAccess)
}

fn write_guest_field_at_offset<Platform, Struct, Field>(
    base: MutPtr<Platform, Struct>,
    field_offset: usize,
    value: Field,
) -> Result<(), PeImageAccessError>
where
    Platform: RawPointerProvider,
    Struct: FromBytes + IntoBytes,
    Field: FromBytes + IntoBytes,
{
    crate::write_field_at_offset::<Platform, Struct, Field>(base, field_offset, value)
        .ok_or(PeImageAccessError::MemoryAccess)
}

fn write_guest_slice<Platform, T>(address: usize, values: &[T]) -> Result<(), PeImageAccessError>
where
    Platform: RawPointerProvider,
    T: Copy + FromBytes + IntoBytes,
{
    crate::write_slice::<Platform, T>(address, values).ok_or(PeImageAccessError::MemoryAccess)
}

struct LoadedNtDll {
    image: LoadedImage,
    exports: NtDllExports,
}

#[derive(Clone, Copy, Debug)]
struct NtDllExports {
    /// `LdrInitializeThunk`
    ldr_initialize_thunk: usize,
    /// `RtlUserThreadStart`
    rtl_user_thread_start: usize,
    /// `KiUserInvertedFunctionTable`
    ki_user_inverted_function_table: usize,
}

fn load_ntdll<Platform: crate::ShimPlatform, FS: crate::ShimFS>(
    platform: &'static Platform,
    fs: Arc<FS>,
    page_manager: &crate::WindowsPageManager<Platform>,
) -> Result<Option<LoadedNtDll>, WindowsLoadError> {
    for path in NTDLL_PATHS {
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
        pages: RangeMap::new(),
    };
    let mut memory = PeImageMemory::<Platform>(PhantomData);
    let mapping = parsed
        .load_with_writable_sections(&mut mapper, &mut memory, writable_section_names)
        .map_err(WindowsLoadError::Load)?;
    Ok(LoadedImage {
        mapping,
        pages: mapper.pages,
        parsed,
    })
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

    let ldr_initialize_thunk =
        ldr_initialize_thunk.ok_or(WindowsLoadError::MissingNtDllLoaderEntrypoint)?;
    let rtl_user_thread_start =
        rtl_user_thread_start.ok_or(WindowsLoadError::MissingNtDllThreadEntrypoint)?;
    let ki_user_inverted_function_table = ki_user_inverted_function_table
        .ok_or(WindowsLoadError::MissingNtDllInvertedFunctionTable)?;

    Ok(NtDllExports {
        ldr_initialize_thunk,
        rtl_user_thread_start,
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
    pages: RangeMap<usize, PageProtection>,
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> PeImageMapper<'_, Platform, FS> {
    fn record_pages(
        &mut self,
        address: usize,
        len: usize,
        protect: PageProtection,
    ) -> Result<(), PeImageAccessError> {
        let (start, len) = page_range(address, len)?;
        if len == 0 {
            return Ok(());
        }
        let end = start
            .checked_add(len)
            .ok_or(PeImageAccessError::AddressOverflow)?;
        self.pages.insert(start..end, protect);
        Ok(())
    }

    fn protect_and_record_pages(
        &mut self,
        address: usize,
        len: usize,
        prot: Protection,
    ) -> Result<(), PeImageAccessError> {
        protect_pages(self.page_manager, address, len, prot)?;
        self.record_pages(address, len, page_protection_from_loader_protection(prot))
    }
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
        let base = ptr.as_usize();
        self.record_pages(base, len, PageProtection::PAGE_NOACCESS)?;
        Ok(base)
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
        self.protect_and_record_pages(address, len, *prot)
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
        self.protect_and_record_pages(address, len, *prot)
    }

    fn protect(
        &mut self,
        address: usize,
        len: usize,
        prot: &Protection,
    ) -> Result<(), Self::Error> {
        self.protect_and_record_pages(address, len, *prot)
    }
}

fn page_protection_from_loader_protection(protect: Protection) -> PageProtection {
    match (protect.read, protect.write, protect.execute) {
        (_, true, true) => PageProtection::PAGE_EXECUTE_READWRITE,
        (_, true, false) => PageProtection::PAGE_READWRITE,
        (true, false, true) => PageProtection::PAGE_EXECUTE_READ,
        (false, false, true) => PageProtection::PAGE_EXECUTE,
        (true, false, false) => PageProtection::PAGE_READONLY,
        (false, false, false) => PageProtection::PAGE_NOACCESS,
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

fn win32_image_path(path: &str) -> String {
    let mut win32_path = String::from("C:");
    if !path.starts_with('/') && !path.starts_with('\\') {
        win32_path.push('\\');
    }
    for ch in path.chars() {
        win32_path.push(if ch == '/' { '\\' } else { ch });
    }
    win32_path
}

fn dos_image_path(path: &str) -> String {
    let mut dos_path = String::from(r"\??\");
    dos_path.push_str(&win32_image_path(path));
    dos_path
}

fn windows_command_line(image_path: &str, argv: &[CString]) -> String {
    let mut command_line = String::new();
    if let Some(arg0) = argv.first() {
        push_windows_quoted_arg(&mut command_line, &cstring_to_string(arg0));
    } else {
        push_windows_quoted_arg(&mut command_line, image_path);
    }
    for arg in argv.iter().skip(1) {
        command_line.push(' ');
        push_windows_quoted_arg(&mut command_line, &cstring_to_string(arg));
    }
    command_line
}

fn push_windows_quoted_arg(command_line: &mut String, arg: &str) {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        command_line.push_str(arg);
        return;
    }

    command_line.push('"');
    let mut backslashes = 0;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..=backslashes * 2 {
                command_line.push('\\');
            }
            command_line.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                command_line.push('\\');
            }
            command_line.push(ch);
            backslashes = 0;
        }
    }
    for _ in 0..backslashes * 2 {
        command_line.push('\\');
    }
    command_line.push('"');
}

fn windows_environment_block(envp: &[CString]) -> Vec<u16> {
    let mut variables = envp.iter().map(cstring_to_string).collect::<Vec<_>>();
    variables.sort_by(|left, right| {
        left.bytes()
            .map(|byte| byte.to_ascii_uppercase())
            .cmp(right.bytes().map(|byte| byte.to_ascii_uppercase()))
    });

    let mut block = Vec::new();
    for variable in variables {
        block.extend(variable.encode_utf16());
        block.push(0);
    }
    block.push(0);
    if envp.is_empty() {
        block.push(0);
    }
    block
}

fn cstring_to_string(value: &CString) -> String {
    match core::str::from_utf8(value.as_bytes()) {
        Ok(value) => String::from(value),
        Err(_) => String::from_utf8_lossy(value.as_bytes()).into_owned(),
    }
}

struct InitialProcessHeaps {
    address: usize,
    maximum_number_of_heaps: u32,
}

fn initial_process_heaps_array(peb_ptr: usize) -> Result<InitialProcessHeaps, PeImageAccessError> {
    let peb_size = core::mem::size_of::<ProcessEnvironmentBlock>();
    let address = peb_ptr
        .checked_add(peb_size)
        .ok_or(PeImageAccessError::AddressOverflow)?;
    let maximum_number_of_heaps =
        (peb_size.next_multiple_of(PAGE_SIZE) - peb_size) / core::mem::size_of::<usize>();
    Ok(InitialProcessHeaps {
        address,
        maximum_number_of_heaps: maximum_number_of_heaps.trunc(),
    })
}

fn allocate_guest_unicode_string_from_str<Platform: RawPointerProvider>(
    shared_heap: &mut GuestMemoryAllocator,
    value: &str,
) -> Result<UnicodeString, PeImageAccessError> {
    let string = Utf16StringBuffer::new(value)?;
    allocate_guest_unicode_string::<Platform>(shared_heap, &string)
}

fn allocate_guest_unicode_string<Platform: RawPointerProvider>(
    allocation: &mut GuestMemoryAllocator,
    string: &Utf16StringBuffer,
) -> Result<UnicodeString, PeImageAccessError> {
    let buffer = allocation.allocate_array::<Platform, u16>(string.units.len())?;
    buffer
        .write_slice_at_offset(0, &string.units)
        .ok_or(PeImageAccessError::MemoryAccess)?;
    Ok(UnicodeString {
        length: string.length,
        maximum_length: string.maximum_length,
        padding_0: [0; 4],
        buffer: buffer.as_usize(),
    })
}

fn initial_teb_static_unicode_string(
    teb_ptr: usize,
    static_unicode_buffer: &[u16],
) -> Result<UnicodeString, PeImageAccessError> {
    let buffer = teb_ptr
        .checked_add(core::mem::offset_of!(
            ThreadEnvironmentBlock,
            static_unicode_buffer
        ))
        .ok_or(PeImageAccessError::AddressOverflow)?;
    Ok(UnicodeString {
        length: 0,
        maximum_length: u16::try_from(core::mem::size_of_val(static_unicode_buffer))
            .map_err(|_| PeImageAccessError::AddressOverflow)?,
        padding_0: [0; 4],
        buffer,
    })
}

struct Utf16StringBuffer {
    length: u16,
    maximum_length: u16,
    units: Vec<u16>,
}

impl Utf16StringBuffer {
    fn new(value: &str) -> Result<Self, PeImageAccessError> {
        let mut units: Vec<u16> = value.encode_utf16().collect();
        let length = utf16_byte_len(units.len())?;
        units.push(0);
        let maximum_length = utf16_byte_len(units.len())?;
        Ok(Self {
            length,
            maximum_length,
            units,
        })
    }
}

fn utf16_byte_len(units: usize) -> Result<u16, PeImageAccessError> {
    units
        .checked_mul(core::mem::size_of::<u16>())
        .and_then(|bytes| u16::try_from(bytes).ok())
        .ok_or(PeImageAccessError::AddressOverflow)
}

#[cfg(all(test, target_os = "windows", target_arch = "x86_64"))]
mod tests {
    extern crate std;

    use alloc::{string::String, vec, vec::Vec};
    use litebox::platform::{RawConstPointer as _, RawPointerProvider};
    use litebox_common_windows::loader::{
        ApiSetHashEntry, ApiSetNamespace, ApiSetNamespaceEntry, ApiSetValueEntry,
        MAX_API_SET_NAMESPACE_SIZE, api_set_hash_prefix,
    };

    use super::*;
    use crate::nt_types::{ProcessEnvironmentBlock, ThreadEnvironmentBlock, UnicodeString};

    const TEST_STACK_BASE: usize = 0x7000_0000;
    const TEST_STACK_TOP: usize = TEST_STACK_BASE + 0x100000;

    #[allow(non_snake_case)]
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcessId() -> u32;
        fn GetCurrentThreadId() -> u32;
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
        fn RtlGetCurrentPeb() -> *const ProcessEnvironmentBlock;
    }

    macro_rules! print_diff_fields {
        ($prefix:literal, $synthetic:expr, $host:expr, [$($field:ident),+ $(,)?]) => {
            $(
                print_diff_field!($prefix, $synthetic, $host, $field);
            )+
        };
    }

    macro_rules! print_diff_field {
        ($prefix:literal, $synthetic:expr, $host:expr, csd_version) => {
            print_unicode_string_diff(
                concat!($prefix, ".", stringify!(csd_version)),
                ($synthetic).csd_version,
                ($host).csd_version,
            );
        };

        ($prefix:literal, $synthetic:expr, $host:expr, static_unicode_string) => {
            print_unicode_string_diff(
                concat!($prefix, ".", stringify!(static_unicode_string)),
                ($synthetic).static_unicode_string,
                ($host).static_unicode_string,
            );
        };
        ($prefix:literal, $synthetic:expr, $host:expr, $field:ident) => {
            print_field_diff(
                concat!($prefix, ".", stringify!($field)),
                ($synthetic).$field,
                ($host).$field,
            );
        };
    }

    fn table_offset(base: u32, index: u32, entry_size: usize) -> Option<usize> {
        (base as usize).checked_add((index as usize).checked_mul(entry_size)?)
    }

    fn read_utf16_string(bytes: &[u8], offset: u32, len: u32) -> Option<String> {
        let offset = offset as usize;
        let len = len as usize;
        let end = offset.checked_add(len)?;
        let bytes = bytes.get(offset..end)?;
        let mut chunks = bytes.chunks_exact(size_of::<u16>());
        if !chunks.remainder().is_empty() {
            return None;
        }
        let units = chunks
            .by_ref()
            .map(|chunk| u16::from_le_bytes(chunk.try_into().expect("u16 byte chunk")))
            .collect::<Vec<_>>();
        Some(String::from_utf16_lossy(&units))
    }

    fn parse_api_set_value_entry(bytes: &[u8], offset: usize) -> Option<ApiSetValueEntry> {
        Some(
            ApiSetValueEntry::read_from_prefix(bytes.get(offset..)?)
                .ok()?
                .0,
        )
    }

    fn api_set_value_entry_value(entry: ApiSetValueEntry, bytes: &[u8]) -> Option<String> {
        read_utf16_string(bytes, entry.value_offset, entry.value_length)
    }

    fn api_set_value_entry_name(entry: ApiSetValueEntry, bytes: &[u8]) -> Option<String> {
        read_utf16_string(bytes, entry.name_offset, entry.name_length)
    }

    fn parse_api_set_hash_entry(bytes: &[u8], offset: usize) -> Option<ApiSetHashEntry> {
        Some(
            ApiSetHashEntry::read_from_prefix(bytes.get(offset..)?)
                .ok()?
                .0,
        )
    }

    fn parse_api_set_namespace_entry(bytes: &[u8], offset: usize) -> Option<ApiSetNamespaceEntry> {
        Some(
            ApiSetNamespaceEntry::read_from_prefix(bytes.get(offset..)?)
                .ok()?
                .0,
        )
    }

    fn api_set_namespace_entry_name(entry: ApiSetNamespaceEntry, bytes: &[u8]) -> Option<String> {
        read_utf16_string(bytes, entry.name_offset, entry.name_length)
    }

    fn api_set_namespace_entry_value(
        entry: ApiSetNamespaceEntry,
        bytes: &[u8],
        index: u32,
    ) -> Option<ApiSetValueEntry> {
        if index >= entry.value_count {
            return None;
        }
        parse_api_set_value_entry(
            bytes,
            table_offset(entry.value_offset, index, size_of::<ApiSetValueEntry>())?,
        )
    }

    fn parse_api_set_namespace(bytes: &[u8]) -> Option<ApiSetNamespace> {
        let namespace = ApiSetNamespace::read_from_prefix(bytes).ok()?.0;
        let size = namespace.size as usize;
        if size != bytes.len()
            || !(size_of::<ApiSetNamespace>()..=MAX_API_SET_NAMESPACE_SIZE).contains(&size)
        {
            return None;
        }
        if table_offset(
            namespace.entry_offset,
            namespace.count,
            size_of::<ApiSetNamespaceEntry>(),
        )? > size
        {
            return None;
        }
        if table_offset(
            namespace.hash_offset,
            namespace.count,
            size_of::<ApiSetHashEntry>(),
        )? > size
        {
            return None;
        }
        Some(namespace)
    }

    fn api_set_namespace_entry(
        namespace: ApiSetNamespace,
        bytes: &[u8],
        index: u32,
    ) -> Option<ApiSetNamespaceEntry> {
        if index >= namespace.count {
            return None;
        }
        parse_api_set_namespace_entry(
            bytes,
            table_offset(
                namespace.entry_offset,
                index,
                size_of::<ApiSetNamespaceEntry>(),
            )?,
        )
    }

    fn api_set_namespace_hash_entry(
        namespace: ApiSetNamespace,
        bytes: &[u8],
        index: u32,
    ) -> Option<ApiSetHashEntry> {
        if index >= namespace.count {
            return None;
        }
        parse_api_set_hash_entry(
            bytes,
            table_offset(namespace.hash_offset, index, size_of::<ApiSetHashEntry>())?,
        )
    }

    fn host_api_set_namespace_bytes() -> Vec<u8> {
        let peb = unsafe {
            // SAFETY: `RtlGetCurrentPeb` returns the current process PEB pointer on Windows.
            RtlGetCurrentPeb().as_ref()
        }
        .expect("host PEB");
        let namespace_ptr = peb.api_set_map as *const ApiSetNamespace;
        let namespace = unsafe {
            // SAFETY: `ApiSetMap` points at the host process API_SET_NAMESPACE while the
            // process is alive; we read only the fixed header first to learn its size.
            namespace_ptr.as_ref()
        }
        .expect("host API_SET_NAMESPACE header");
        let size = namespace.size as usize;
        assert!(
            (size_of::<ApiSetNamespace>()..=MAX_API_SET_NAMESPACE_SIZE).contains(&size),
            "host API_SET_NAMESPACE has unexpected size {size:#x}"
        );
        let bytes = unsafe {
            // SAFETY: The size was read from the validated namespace header above, and the
            // host API-set namespace is immutable process-wide data owned by ntdll.
            core::slice::from_raw_parts(peb.api_set_map as *const u8, size)
        };
        bytes.to_vec()
    }

    fn api_set_default_value(bytes: &[u8], contract: &str) -> Option<String> {
        let namespace = parse_api_set_namespace(bytes)?;
        for index in 0..namespace.count {
            let entry = api_set_namespace_entry(namespace, bytes, index)?;
            if api_set_namespace_entry_name(entry, bytes)?.eq_ignore_ascii_case(contract) {
                let value = api_set_namespace_entry_value(entry, bytes, 0)?;
                return api_set_value_entry_value(value, bytes);
            }
        }
        None
    }

    fn assert_api_set_hash_table(bytes: &[u8]) {
        let namespace = parse_api_set_namespace(bytes).expect("valid API_SET_NAMESPACE");
        let mut previous = None;
        for hash_index in 0..namespace.count {
            let hash_entry =
                api_set_namespace_hash_entry(namespace, bytes, hash_index).expect("hash entry");
            let entry = api_set_namespace_entry(namespace, bytes, hash_entry.index)
                .expect("hash entry target");
            let name = api_set_namespace_entry_name(entry, bytes).expect("hash entry target name");
            let expected_hash = api_set_hash_with_hashed_length(&name, entry.hashed_length)
                .expect("valid API-set hashed length");
            assert_eq!(hash_entry.hash, expected_hash, "hash for {name}");
            if let Some((previous_hash, previous_index)) = previous {
                assert!(
                    (previous_hash, previous_index) <= (hash_entry.hash, hash_entry.index),
                    "API-set hash table is not sorted"
                );
            }
            previous = Some((hash_entry.hash, hash_entry.index));
        }
    }

    fn api_set_hash_with_hashed_length(name: &str, hashed_length: u32) -> Option<u32> {
        let code_unit_bytes = u32::try_from(size_of::<u16>()).ok()?;
        if !name.is_ascii() || !hashed_length.is_multiple_of(code_unit_bytes) {
            return None;
        }
        let hashed_units = usize::try_from(hashed_length / code_unit_bytes).ok()?;
        let prefix = name.get(..hashed_units)?;
        Some(api_set_hash_prefix(prefix))
    }

    fn dump_api_set_entries(bytes: &[u8], namespace: ApiSetNamespace) {
        std::println!("entries:");
        for index in 0..namespace.count {
            let entry = api_set_namespace_entry(namespace, bytes, index).expect("namespace entry");
            std::println!(
                "  {index:04} name={} flags={:#x} hashed_len={} values={}",
                api_set_namespace_entry_name(entry, bytes)
                    .unwrap_or_else(|| String::from("<invalid>")),
                entry.flags,
                entry.hashed_length,
                entry.value_count
            );
            for value_index in 0..entry.value_count {
                let value = api_set_namespace_entry_value(entry, bytes, value_index)
                    .expect("namespace value");
                let name = api_set_value_entry_name(value, bytes).unwrap_or_default();
                let value_name = api_set_value_entry_value(value, bytes)
                    .unwrap_or_else(|| String::from("<invalid>"));
                std::println!(
                    "       [{value_index}] name={} value={} flags={:#x}",
                    if name.is_empty() { "<default>" } else { &name },
                    value_name,
                    value.flags
                );
            }
        }
    }

    fn dump_api_set_hash_entries(bytes: &[u8], namespace: ApiSetNamespace) {
        std::println!("hash entries:");
        for index in 0..namespace.count {
            let entry = api_set_namespace_hash_entry(namespace, bytes, index).expect("hash entry");
            std::println!(
                "  {index:04} hash={:#010x} index={}",
                entry.hash,
                entry.index
            );
        }
    }

    fn dump_api_set_namespace(api_set_map: ApiSetNamespace, bytes: &[u8], label: &str) {
        std::println!("{label}");
        std::println!("API_SET_NAMESPACE len={:#x}", bytes.len(),);
        std::println!("     version: {:#010x}", api_set_map.version);
        std::println!("        size: {:#010x}", api_set_map.size);
        std::println!("       flags: {:#010x}", api_set_map.flags);
        std::println!("       count: {:#010x}", api_set_map.count);
        std::println!("entry_offset: {:#010x}", api_set_map.entry_offset);
        std::println!(" hash_offset: {:#010x}", api_set_map.hash_offset);
        std::println!(" hash_factor: {:#010x}", api_set_map.hash_factor);
        std::println!();
        dump_api_set_entries(bytes, api_set_map);
        std::println!();
        dump_api_set_hash_entries(bytes, api_set_map);
        std::println!();
    }

    #[test]
    fn dump_host_api_set_namespace() {
        let host_bytes = host_api_set_namespace_bytes();
        let host = parse_api_set_namespace(&host_bytes).expect("valid host API_SET_NAMESPACE");
        dump_api_set_namespace(host, &host_bytes, "host");
    }

    #[test]
    fn api_set_namespace_matches_host_invariants() {
        let host_bytes = host_api_set_namespace_bytes();
        let host = parse_api_set_namespace(&host_bytes).expect("valid host API_SET_NAMESPACE");
        let synthetic_bytes =
            build_api_set_namespace(API_SET_MAPPINGS).expect("LiteBox API_SET_NAMESPACE builds");
        let synthetic =
            parse_api_set_namespace(&synthetic_bytes).expect("valid synthetic API_SET_NAMESPACE");

        assert_eq!(synthetic.version, host.version);
        assert_eq!(synthetic.hash_factor, host.hash_factor);
        assert_eq!(synthetic.flags, 0);
        assert_api_set_hash_table(&host_bytes);
        assert_api_set_hash_table(&synthetic_bytes);

        let mut host_checked = 0;
        let mut host_mismatches = Vec::new();
        for &(contract, expected_host) in API_SET_MAPPINGS {
            let synthetic_host = api_set_default_value(&synthetic_bytes, contract);
            assert_eq!(
                synthetic_host.as_deref(),
                Some(expected_host),
                "synthetic mapping for {contract}"
            );
            if let Some(host_value) = api_set_default_value(&host_bytes, contract) {
                if !host_value.eq_ignore_ascii_case(expected_host) {
                    host_mismatches.push(std::format!(
                        "{contract}: expected {expected_host}, got {host_value}"
                    ));
                }
                host_checked += 1;
            }
        }
        assert!(
            host_mismatches.is_empty(),
            "host API-set mapping mismatches:\n{}",
            host_mismatches.join("\n")
        );
        assert!(
            host_checked >= 3,
            "expected at least three synthetic API-set contracts on the host, found {host_checked}"
        );

        for (contract, expected_host) in [
            ("api-ms-win-core-rtlsupport-l1-1-0", "ntdll.dll"),
            ("api-ms-win-core-file-l1-2-3", "kernelbase.dll"),
            ("api-ms-win-eventing-consumer-l1-1-0", "sechost.dll"),
        ] {
            assert_eq!(
                api_set_default_value(&synthetic_bytes, contract).as_deref(),
                Some(expected_host),
                "synthetic mapping for {contract}"
            );
        }
    }

    #[test]
    fn prints_created_teb_host_diff() {
        let synthetic = created_process_environment_snapshot();
        let current_teb = host_teb_snapshot();
        let teb_self = host_teb_address();
        let peb_address = host_peb_address();

        assert_eq!(synthetic.teb.nt_tib.self_pointer, synthetic.environment.teb);
        assert_eq!(current_teb.nt_tib.self_pointer, teb_self);
        assert_eq!(
            synthetic.teb.process_environment_block,
            synthetic.environment.peb
        );
        assert_eq!(current_teb.process_environment_block, peb_address);
        assert_eq!(current_teb.client_id, host_client_id());

        print_diff_header("synthetic TEB vs host TEB");
        print_diff_fields!(
            "TEB.NtTib",
            synthetic.teb.nt_tib,
            current_teb.nt_tib,
            [
                exception_list,
                stack_base,
                stack_limit,
                sub_system_tib,
                fiber_data_or_version,
                arbitrary_user_pointer,
                self_pointer,
            ]
        );
        print_diff_fields!(
            "TEB",
            synthetic.teb,
            current_teb,
            [
                environment_pointer,
                client_id,
                active_rpc_handle,
                thread_local_storage_pointer,
                process_environment_block,
                last_error_value,
                count_of_owned_critical_sections,
                csr_client_thread,
                win_32_thread_info,
                user_32_reserved,
                user_reserved,
                padding_user_reserved,
                wow_32_reserved,
                current_locale,
                fp_software_status_register,
                reserved_for_debugger_instrumentation,
                system_reserved_1,
                heap_fls_data,
                rng_state,
                placeholder_compatibility_mode,
                placeholder_hydration_always_explicit,
                placeholder_reserved,
                proxied_process_id,
                activation_stack,
                working_on_behalf_ticket,
                exception_code,
                padding_0,
                activation_context_stack_pointer,
                instrumentation_callback_sp,
                instrumentation_callback_previous_pc,
                instrumentation_callback_previous_sp,
                tx_fs_context,
                instrumentation_callback_disabled,
                unaligned_load_store_exceptions,
                padding_1,
                gdi_teb_batch,
                real_client_id,
                gdi_cached_process_handle,
                gdi_client_pid,
                gdi_client_tid,
                gdi_thread_local_info,
                win_32_client_info,
                gl_dispatch_table,
                gl_reserved_1,
                gl_reserved_2,
                gl_section_info,
                gl_section,
                gl_table,
                gl_current_rc,
                gl_context,
                last_status_value,
                padding_2,
                static_unicode_string,
                static_unicode_buffer,
                padding_3,
                deallocation_stack,
                tls_slots,
                tls_links,
                vdm,
                reserved_for_nt_rpc,
                dbg_ss_reserved,
                hard_error_mode,
                padding_4,
                instrumentation,
                activity_id,
                sub_process_tag,
                perflib_data,
                etw_trace_data,
                win_sock_data,
                gdi_batch_count,
                ideal_processor_value,
                guaranteed_stack_bytes,
                padding_5,
                reserved_for_perf,
                reserved_for_ole,
                waiting_on_loader_lock,
                padding_6,
                saved_priority_state,
                reserved_for_code_coverage,
                thread_pool_data,
                tls_expansion_slots,
                chpe_v_2_cpu_area_info,
                unused,
                mui_generation,
                is_impersonating,
                nls_cache,
                p_shim_data,
                heap_data,
                padding_7,
                current_transaction_handle,
                active_frame,
                fls_data,
                preferred_languages,
                user_pref_languages,
                merged_pref_languages,
                mui_impersonation,
                cross_teb_flags,
                same_teb_flags,
                txn_scope_enter_callback,
                txn_scope_exit_callback,
                txn_scope_context,
                lock_count,
                wow_teb_offset,
                resource_ret_value,
                reserved_for_wdf,
                reserved_for_crt,
                effective_container_id,
                last_sleep_counter,
                spin_call_count,
                padding_8,
                extended_feature_disable_mask,
                scheduler_shared_data_slot,
                heap_walk_context,
                primary_group_affinity,
                rcu,
            ]
        );
    }

    #[test]
    fn prints_created_peb_host_diff() {
        let created = created_process_environment_snapshot();
        let host_peb = host_peb_snapshot();

        assert_eq!(created.peb.image_base_address, created.image_base_address);
        assert_ne!(host_peb.image_base_address, 0);

        print_diff_header("synthetic PEB vs host PEB");
        print_diff_fields!(
            "PEB",
            created.peb,
            host_peb,
            [
                inherited_address_space,
                read_image_file_exec_options,
                being_debugged,
            ]
        );
        print_peb_bit_field_diff(
            "PEB.bit_field",
            crate::nt_types::PebBitField::from_bits_retain(created.peb.bit_field),
            crate::nt_types::PebBitField::from_bits_retain(host_peb.bit_field),
        );
        print_diff_fields!(
            "PEB",
            created.peb,
            host_peb,
            [
                padding_0,
                mutant,
                image_base_address,
                ldr,
                process_parameters,
                sub_system_data,
                process_heap,
                fast_peb_lock,
                atl_thunk_s_list_ptr,
                ifeo_key,
                cross_process_flags,
                padding_1,
                kernel_callback_table,
                system_reserved,
                atl_thunk_s_list_ptr_32,
                api_set_map,
                tls_expansion_counter,
                padding_2,
                tls_bitmap,
                tls_bitmap_bits,
                read_only_shared_memory_base,
                shared_data,
                read_only_static_server_data,
                ansi_code_page_data,
                oem_code_page_data,
                unicode_case_table_data,
                number_of_processors,
                nt_global_flag,
                critical_section_timeout,
                heap_segment_reserve,
                heap_segment_commit,
                heap_de_commit_total_free_threshold,
                heap_de_commit_free_block_threshold,
                number_of_heaps,
                maximum_number_of_heaps,
                process_heaps,
                gdi_shared_handle_table,
                process_starter_helper,
                gdi_dc_attribute_list,
                padding_3,
                loader_lock,
                os_major_version,
                os_minor_version,
                os_build_number,
                os_csd_version,
                os_platform_id,
                image_subsystem,
                image_subsystem_major_version,
                image_subsystem_minor_version,
                padding_4,
                active_process_affinity_mask,
                gdi_handle_buffer,
                post_process_init_routine,
                tls_expansion_bitmap,
                tls_expansion_bitmap_bits,
                session_id,
                padding_5,
                app_compat_flags,
                app_compat_flags_user,
                p_shim_data,
                app_compat_info,
                csd_version,
                activation_context_data,
                process_assembly_storage_map,
                system_default_activation_context_data,
                system_assembly_storage_map,
                minimum_stack_commit,
                spare_pointers,
                patch_loader_data,
                chpe_v2_process_info,
                app_model_feature_state,
                spare_ulongs,
                active_code_page,
                oem_code_page,
                use_case_mapping,
                unused_nls_field,
                padding_6a,
                wer_registration_data,
                wer_ship_assert_ptr,
                ec_code_bit_map,
                p_image_header_hash,
                tracing_flags,
                padding_6,
                csr_server_read_only_shared_memory_base,
                tpp_workerp_list_lock,
                tpp_workerp_list,
                wait_on_address_hash_table,
                telemetry_coverage_header,
                cloud_file_flags,
                cloud_file_diag_flags,
                placeholder_compatibility_mode,
                placeholder_compatibility_mode_reserved,
                leap_second_data,
                leap_second_flags,
                nt_global_flag_2,
                extended_feature_disable_mask,
            ]
        );
    }

    #[test]
    fn process_parameters_include_argv_and_environment() {
        let created = created_process_environment_snapshot();

        // `RTL_USER_PROCESS_PARAMETERS.CommandLine` stores the original command line for
        // `CommandLineToArgvW`, and the environment is a sorted UTF-16 `name=value\0...\0\0`
        // block as documented for `GetEnvironmentStringsW`.
        assert_eq!(
            decode_guest_unicode_string(created.process_parameters.command_line),
            "test.exe \"arg with space\" \"quote\\\"arg\""
        );
        assert_ne!(created.process_parameters.environment, 0);
        assert_eq!(
            read_guest_utf16_units(
                created.process_parameters.environment,
                usize::try_from(created.process_parameters.environment_size)
                    .expect("environment size fits usize")
                    / size_of::<u16>(),
            ),
            utf16_environment_units(&["a=one", "B=two", "c=three"])
        );
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

    struct CreatedProcessEnvironmentSnapshot {
        environment: WindowsProcessEnvironment,
        peb: ProcessEnvironmentBlock,
        teb: ThreadEnvironmentBlock,
        process_parameters: RtlUserProcessParameters,
        image_base_address: usize,
    }

    fn created_process_environment_snapshot() -> CreatedProcessEnvironmentSnapshot {
        let platform = crate::tests::test_platform();
        let litebox = litebox::LiteBox::new(platform);
        let page_manager = crate::WindowsPageManager::<crate::tests::TestPlatform>::new(&litebox);
        let fs = Arc::new(litebox::fs::in_mem::FileSystem::new(&litebox));
        let loader = PeLoader::new(platform, fs, &page_manager);
        let image = loaded_module_image(application_module_base());

        let image_base_address = image.mapping.base_addr;
        let argv = [
            CString::new("test.exe").expect("valid argv[0]"),
            CString::new("arg with space").expect("valid argv[1]"),
            CString::new("quote\"arg").expect("valid argv[2]"),
        ];
        let envp = [
            CString::new("c=three").expect("valid envp[0]"),
            CString::new("B=two").expect("valid envp[1]"),
            CString::new("a=one").expect("valid envp[2]"),
        ];
        let environment = loader
            .create_process_environment(ProcessEnvironmentInput {
                image: &image.parsed,
                image_base_address,
                image_path: "test.exe",
                argv: &argv,
                envp: &envp,
                stack_base: TEST_STACK_BASE,
                stack_allocation_top: TEST_STACK_TOP,
            })
            .expect("failed to create synthetic Windows process environment");
        let peb = read_guest_value::<ProcessEnvironmentBlock>(environment.peb);

        CreatedProcessEnvironmentSnapshot {
            process_parameters: read_guest_value(peb.process_parameters),
            peb,
            teb: read_guest_value(environment.teb),
            environment,
            image_base_address,
        }
    }

    fn read_guest_utf16_units(address: usize, units: usize) -> Vec<u16> {
        let ptr =
            <crate::tests::TestPlatform as RawPointerProvider>::RawConstPointer::<u16>::from_usize(
                address,
            );
        ptr.to_owned_slice(units)
            .expect("guest UTF-16 block is readable")
            .to_vec()
    }

    fn utf16_environment_units(vars: &[&str]) -> Vec<u16> {
        let mut units = Vec::new();
        for var in vars {
            units.extend(var.encode_utf16());
            units.push(0);
        }
        units.push(0);
        units
    }

    fn print_field_diff<T>(field: &str, synthetic: T, host: T)
    where
        T: core::fmt::Debug + IntoBytes + zerocopy::Immutable,
    {
        let status = if synthetic.as_bytes() == host.as_bytes() {
            "✓"
        } else {
            "X"
        };
        let synthetic = format_field_value(&synthetic);
        let host = format_field_value(&host);
        std::println!("{status:<2} {field:<48} {synthetic} | {host}");
    }

    fn print_peb_bit_field_diff(
        field: &str,
        synthetic: crate::nt_types::PebBitField,
        host: crate::nt_types::PebBitField,
    ) {
        let status = if synthetic.bits() == host.bits() {
            "✓"
        } else {
            "X"
        };
        let synthetic = format_field_value(&synthetic);
        let host = format_field_value(&host);
        std::println!("{status:<2} {field:<48} {synthetic} | {host}");
    }

    fn print_unicode_string_diff(field: &str, synthetic: UnicodeString, host: UnicodeString) {
        let synthetic = decode_guest_unicode_string(synthetic);
        let host = decode_host_unicode_string(host);
        let status = if synthetic == host { "✓" } else { "X" };
        let synthetic = format_field_value(&synthetic);
        let host = format_field_value(&host);
        std::println!("{status:<2} {field:<48} {synthetic} | {host}");
    }

    fn decode_guest_unicode_string(value: UnicodeString) -> String {
        let Some(chars) = unicode_string_chars(value) else {
            return std::format!("<invalid length {:#x}>", value.length);
        };
        if chars == 0 {
            return String::new();
        }
        if value.buffer == 0 {
            return String::from("<null buffer>");
        }

        let ptr =
            <crate::tests::TestPlatform as RawPointerProvider>::RawConstPointer::<u16>::from_usize(
                value.buffer,
            );
        let Some(units) = ptr.to_owned_slice(chars) else {
            return String::from("<unreadable buffer>");
        };
        String::from_utf16_lossy(&units)
    }

    fn decode_host_unicode_string(value: UnicodeString) -> String {
        let Some(chars) = unicode_string_chars(value) else {
            return std::format!("<invalid length {:#x}>", value.length);
        };
        if chars == 0 {
            return String::new();
        }
        if value.buffer == 0 {
            return String::from("<null buffer>");
        }

        // SAFETY: Host PEB/TEB snapshots contain pointers owned by the current
        // process; the `UNICODE_STRING.Length` field bounds the UTF-16 slice.
        let units = unsafe { core::slice::from_raw_parts(value.buffer as *const u16, chars) };
        String::from_utf16_lossy(units)
    }

    fn unicode_string_chars(value: UnicodeString) -> Option<usize> {
        if value.length.is_multiple_of(2) {
            Some(usize::from(value.length / 2))
        } else {
            None
        }
    }

    fn format_field_value<T: core::fmt::Debug>(value: &T) -> String {
        const MAX_VALUE_LEN: usize = 96;

        let mut value = std::format!("{value:x?}");
        if value.len() <= MAX_VALUE_LEN {
            return value;
        }

        let mut end = MAX_VALUE_LEN;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
        value.push_str("...");
        value
    }

    fn print_diff_header(title: &str) {
        std::println!("{title}");
        std::println!("   {:<48} synthetic | host", "field");
        std::println!("   {:<48} ----------------", "-----");
    }

    fn read_guest_value<T>(address: usize) -> T
    where
        T: Copy + zerocopy::FromBytes,
    {
        let ptr =
            <crate::tests::TestPlatform as RawPointerProvider>::RawConstPointer::<T>::from_usize(
                address,
            );
        ptr.read_at_offset(0)
            .expect("failed to read synthetic guest process environment value")
    }

    fn host_teb_snapshot() -> ThreadEnvironmentBlock {
        // SAFETY: `host_teb_address` returns the current thread's live host TEB pointer.
        unsafe { read_host_value(host_teb_address() as *const ThreadEnvironmentBlock) }
    }

    fn host_peb_snapshot() -> ProcessEnvironmentBlock {
        // SAFETY: `host_peb_address` returns the current process's live host PEB pointer.
        unsafe { read_host_value(host_peb_address() as *const ProcessEnvironmentBlock) }
    }

    fn host_teb_address() -> usize {
        let teb: usize;
        // SAFETY: On x86_64 Windows, GS:[0x30] is the current thread's TEB pointer.
        unsafe {
            core::arch::asm!(
                "mov {}, gs:[0x30]",
                out(reg) teb,
                options(nostack, preserves_flags, readonly),
            );
        }
        teb
    }

    fn host_peb_address() -> usize {
        let peb: usize;
        // SAFETY: On x86_64 Windows, GS:[0x60] is the current process's PEB pointer.
        unsafe {
            core::arch::asm!(
                "mov {}, gs:[0x60]",
                out(reg) peb,
                options(nostack, preserves_flags, readonly),
            );
        }
        peb
    }

    fn host_client_id() -> ClientId {
        // SAFETY: These kernel32 calls take no pointers and return IDs for the current process/thread.
        let unique_process = unsafe { GetCurrentProcessId() };
        // SAFETY: These kernel32 calls take no pointers and return IDs for the current process/thread.
        let unique_thread = unsafe { GetCurrentThreadId() };
        ClientId {
            unique_process: usize::try_from(unique_process).unwrap(),
            unique_thread: usize::try_from(unique_thread).unwrap(),
        }
    }

    unsafe fn read_host_value<T: Copy>(address: *const T) -> T {
        // SAFETY: The caller guarantees `address` points into live host loader/PEB/TEB state.
        unsafe { core::ptr::read_volatile(address) }
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
                mapping_size: parsed.image_size(),
                entry_point: base_addr
                    .checked_add(parsed.entry_point_rva())
                    .expect("module entry point address fits usize"),
            },
            pages: RangeMap::new(),
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
