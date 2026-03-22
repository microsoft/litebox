// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Stub DLL catalog.
//!
//! Generates ntdll.dll, kernel32.dll, advapi32.dll, and ws2_32.dll stubs
//! with the correct export lists for the NT shim. Each export is a tiny
//! syscall stub or a user-mode function that the shim intercepts.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::NtSyscallId;
use crate::pe_builder::{
    CALLBACK_PTR_RVA, GS_TABLE_PTR_RVA, REVERSE_GS_TABLE_PTR_RVA, StubExport, build_stub_dll,
};

/// Default preferred base addresses for stub DLLs.
/// Each DLL gets a distinct base to avoid collisions.
pub const NTDLL_IMAGE_BASE: u64 = 0x0000_7FFE_0000_0000;
pub const KERNEL32_IMAGE_BASE: u64 = 0x0000_7FFE_0001_0000;

/// Default preferred base for advapi32.dll stub.
pub const ADVAPI32_IMAGE_BASE: u64 = 0x0000_7FFE_0002_0000;

/// Default preferred base for ws2_32.dll stub.
pub const WS2_32_IMAGE_BASE: u64 = 0x0000_7FFE_0003_0000;

/// Default preferred bases for additional stub DLLs needed by node.exe.
pub const CRYPT32_IMAGE_BASE: u64 = 0x0000_7FFE_0004_0000;
pub const IPHLPAPI_IMAGE_BASE: u64 = 0x0000_7FFE_0005_0000;
pub const SHELL32_IMAGE_BASE: u64 = 0x0000_7FFE_0006_0000;
pub const USER32_IMAGE_BASE: u64 = 0x0000_7FFE_0007_0000;
pub const USERENV_IMAGE_BASE: u64 = 0x0000_7FFE_0008_0000;
pub const WINMM_IMAGE_BASE: u64 = 0x0000_7FFE_0009_0000;
pub const DBGHELP_IMAGE_BASE: u64 = 0x0000_7FFE_000A_0000;
pub const OLE32_IMAGE_BASE: u64 = 0x0000_7FFE_000B_0000;

/// Base address for the fallback "unimplemented" stub DLL.
pub const FALLBACK_IMAGE_BASE: u64 = 0x0000_7FFE_000F_0000;

/// Build a tiny DLL with a single `__fallback_stub` export that returns 0.
/// The returned DLL's export VA can be used as a fallback for unresolved
/// imports so that calling an unimplemented function returns 0 instead of
/// crashing.
pub fn build_fallback_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    let exports = vec![StubExport::return_status("__fallback_stub", 0)];
    let mut bytes = build_stub_dll("__fallback.dll", &exports, image_base);
    patch_text_header(
        &mut bytes,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    );
    bytes
}

/// Generate the ntdll.dll stub bytes with a specific load base and callback.
///
/// `image_base` should match the VA where the DLL will be loaded, so that
/// no rebasing is needed (the .text section stays RX).
///
/// `syscall_entry` is the address of the platform's `syscall_callback`.
/// `gs_table_ptr` is the address of the host-owned GS lookup table.
pub fn build_ntdll_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    let exports = ntdll_exports();
    let mut bytes = build_stub_dll("ntdll.dll", &exports, image_base);
    patch_text_header(
        &mut bytes,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    );
    bytes
}

/// Generate the kernel32.dll stub bytes with a specific load base and callback.
pub fn build_kernel32_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    let exports = kernel32_exports();
    let mut bytes = build_stub_dll("kernel32.dll", &exports, image_base);
    patch_text_header(
        &mut bytes,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    );
    bytes
}

/// Generate the advapi32.dll stub bytes with a specific load base and callback.
pub fn build_advapi32_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    let exports = advapi32_exports();
    let mut bytes = build_stub_dll("advapi32.dll", &exports, image_base);
    patch_text_header(
        &mut bytes,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    );
    bytes
}

/// Generate the ws2_32.dll stub bytes with a specific load base and callback.
pub fn build_ws2_32_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    let exports = ws2_32_exports();
    let mut bytes = build_stub_dll("ws2_32.dll", &exports, image_base);
    patch_text_header(
        &mut bytes,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    );
    bytes
}

/// Generate the ntdll.dll stub bytes with the default base (for tests).
pub fn build_ntdll() -> Vec<u8> {
    let exports = ntdll_exports();
    build_stub_dll("ntdll.dll", &exports, NTDLL_IMAGE_BASE)
}

/// Generate the kernel32.dll stub bytes with the default base (for tests).
pub fn build_kernel32() -> Vec<u8> {
    let exports = kernel32_exports();
    build_stub_dll("kernel32.dll", &exports, KERNEL32_IMAGE_BASE)
}

/// Generate the ws2_32.dll stub bytes with the default base (for tests).
pub fn build_ws2_32() -> Vec<u8> {
    let exports = ws2_32_exports();
    build_stub_dll("ws2_32.dll", &exports, WS2_32_IMAGE_BASE)
}

// ========================================================================
// Additional stub DLLs required by node.exe
// ========================================================================

/// Generate a generic stub DLL with a specific load base and callback.
fn build_generic_stub(
    dll_name: &str,
    exports: &[StubExport],
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    let mut bytes = build_stub_dll(dll_name, exports, image_base);
    patch_text_header(
        &mut bytes,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    );
    bytes
}

pub fn build_crypt32_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    build_generic_stub(
        "crypt32.dll",
        &crypt32_exports(),
        image_base,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    )
}

pub fn build_iphlpapi_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    build_generic_stub(
        "iphlpapi.dll",
        &iphlpapi_exports(),
        image_base,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    )
}

pub fn build_shell32_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    build_generic_stub(
        "shell32.dll",
        &shell32_exports(),
        image_base,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    )
}

pub fn build_user32_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    build_generic_stub(
        "user32.dll",
        &user32_exports(),
        image_base,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    )
}

pub fn build_userenv_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    build_generic_stub(
        "userenv.dll",
        &userenv_exports(),
        image_base,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    )
}

pub fn build_winmm_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    build_generic_stub(
        "winmm.dll",
        &winmm_exports(),
        image_base,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    )
}

pub fn build_dbghelp_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    build_generic_stub(
        "dbghelp.dll",
        &dbghelp_exports(),
        image_base,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    )
}

pub fn build_ole32_for(
    image_base: u64,
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) -> Vec<u8> {
    build_generic_stub(
        "ole32.dll",
        &ole32_exports(),
        image_base,
        syscall_entry,
        gs_table_ptr,
        reverse_gs_table_ptr,
    )
}

/// Write the callback pointer, forward GS table pointer, and reverse GS table
/// pointer into the raw DLL bytes at the file offsets corresponding to their RVAs.
fn patch_text_header(
    bytes: &mut [u8],
    syscall_entry: u64,
    gs_table_ptr: u64,
    reverse_gs_table_ptr: u64,
) {
    use crate::pe_parser::PeParsedFile;
    let parsed = PeParsedFile::parse(bytes).expect("stub DLL should be valid PE");

    let cb_off = parsed
        .rva_to_file_offset(CALLBACK_PTR_RVA)
        .expect("callback pointer RVA must be in .text section");
    bytes[cb_off..cb_off + 8].copy_from_slice(&syscall_entry.to_le_bytes());

    let gs_off = parsed
        .rva_to_file_offset(GS_TABLE_PTR_RVA)
        .expect("GS table pointer RVA must be in .text section");
    bytes[gs_off..gs_off + 8].copy_from_slice(&gs_table_ptr.to_le_bytes());

    let rev_gs_off = parsed
        .rva_to_file_offset(REVERSE_GS_TABLE_PTR_RVA)
        .expect("reverse GS table pointer RVA must be in .text section");
    bytes[rev_gs_off..rev_gs_off + 8].copy_from_slice(&reverse_gs_table_ptr.to_le_bytes());
}

/// Ntdll exports: one syscall stub per NT syscall number.
fn ntdll_exports() -> Vec<StubExport> {
    vec![
        // Phase 1: Minimal boot
        StubExport::syscall_stub("NtWriteFile", NtSyscallId::NtWriteFile as u32),
        StubExport::syscall_stub(
            "NtAllocateVirtualMemory",
            NtSyscallId::NtAllocateVirtualMemory as u32,
        ),
        StubExport::syscall_stub(
            "NtFreeVirtualMemory",
            NtSyscallId::NtFreeVirtualMemory as u32,
        ),
        StubExport::syscall_stub(
            "NtProtectVirtualMemory",
            NtSyscallId::NtProtectVirtualMemory as u32,
        ),
        StubExport::syscall_stub(
            "NtQueryVirtualMemory",
            NtSyscallId::NtQueryVirtualMemory as u32,
        ),
        StubExport::syscall_stub("NtClose", NtSyscallId::NtClose as u32),
        StubExport::syscall_stub("NtTerminateProcess", NtSyscallId::NtTerminateProcess as u32),
        // Phase 2: File I/O
        StubExport::syscall_stub("NtCreateFile", NtSyscallId::NtCreateFile as u32),
        StubExport::syscall_stub("NtReadFile", NtSyscallId::NtReadFile as u32),
        StubExport::syscall_stub(
            "NtQueryInformationFile",
            NtSyscallId::NtQueryInformationFile as u32,
        ),
        StubExport::syscall_stub(
            "NtSetInformationFile",
            NtSyscallId::NtSetInformationFile as u32,
        ),
        StubExport::syscall_stub(
            "NtQueryVolumeInformationFile",
            NtSyscallId::NtQueryVolumeInformationFile as u32,
        ),
        StubExport::syscall_stub(
            "NtQueryAttributesFile",
            NtSyscallId::NtQueryAttributesFile as u32,
        ),
        StubExport::syscall_stub(
            "NtQueryDirectoryFile",
            NtSyscallId::NtQueryDirectoryFile as u32,
        ),
        StubExport::syscall_stub(
            "NtQuerySystemInformation",
            NtSyscallId::NtQuerySystemInformation as u32,
        ),
        StubExport::syscall_stub(
            "NtQueryPerformanceCounter",
            NtSyscallId::NtQueryPerformanceCounter as u32,
        ),
        StubExport::syscall_stub("NtQuerySystemTime", NtSyscallId::NtQuerySystemTime as u32),
        StubExport::syscall_stub(
            "NtQueryInformationProcess",
            NtSyscallId::NtQueryInformationProcess as u32,
        ),
        // Phase 3: Threading & sync
        StubExport::syscall_stub("NtDelayExecution", NtSyscallId::NtDelayExecution as u32),
        StubExport::syscall_stub(
            "NtSetInformationThread",
            NtSyscallId::NtSetInformationThread as u32,
        ),
        StubExport::syscall_stub("NtCreateThreadEx", NtSyscallId::NtCreateThreadEx as u32),
        StubExport::syscall_stub("NtTerminateThread", NtSyscallId::NtTerminateThread as u32),
        StubExport::syscall_stub("NtOpenKey", NtSyscallId::NtOpenKey as u32),
        StubExport::syscall_stub("NtQueryValueKey", NtSyscallId::NtQueryValueKey as u32),
        StubExport::syscall_stub("NtCreateEvent", NtSyscallId::NtCreateEvent as u32),
        StubExport::syscall_stub("NtSetEvent", NtSyscallId::NtSetEvent as u32),
        StubExport::syscall_stub("NtResetEvent", NtSyscallId::NtResetEvent as u32),
        StubExport::syscall_stub("NtClearEvent", NtSyscallId::NtClearEvent as u32),
        StubExport::syscall_stub(
            "NtWaitForSingleObject",
            NtSyscallId::NtWaitForSingleObject as u32,
        ),
        StubExport::syscall_stub(
            "NtWaitForMultipleObjects",
            NtSyscallId::NtWaitForMultipleObjects as u32,
        ),
        StubExport::syscall_stub("NtCreateSemaphore", NtSyscallId::NtCreateSemaphore as u32),
        StubExport::syscall_stub("NtReleaseSemaphore", NtSyscallId::NtReleaseSemaphore as u32),
        StubExport::syscall_stub("NtCreateKeyedEvent", NtSyscallId::NtCreateKeyedEvent as u32),
        StubExport::syscall_stub(
            "NtWaitForKeyedEvent",
            NtSyscallId::NtWaitForKeyedEvent as u32,
        ),
        StubExport::syscall_stub(
            "NtReleaseKeyedEvent",
            NtSyscallId::NtReleaseKeyedEvent as u32,
        ),
        StubExport::syscall_stub("NtDuplicateObject", NtSyscallId::NtDuplicateObject as u32),
        // Rtl* user-mode functions.
        StubExport::return_status("RtlNtStatusToDosError", 0),
        StubExport::return_status("RtlInitUnicodeString", 0),
        StubExport::return_status("RtlInitAnsiString", 0),
        StubExport::return_status("RtlUnicodeToMultiByteSize", 0),
        StubExport::return_status("RtlUnicodeToMultiByteN", 0),
    ]
}

/// Kernel32 exports: high-level Win32 API wrappers.
///
/// These are implemented as syscall stubs that the shim intercepts,
/// using syscall numbers in a reserved kernel32 range (0x1000+).
/// The shim can distinguish kernel32 calls from ntdll calls by the
/// syscall number range.
///
/// For Phase 1, most are simple stubs that return success/zero.
fn kernel32_exports() -> Vec<StubExport> {
    vec![
        // --- Console I/O & Process Control (Phase 1) ---
        StubExport::syscall_stub("GetStdHandle", K32_GET_STD_HANDLE),
        StubExport::syscall_stub("WriteConsoleW", K32_WRITE_CONSOLE_W),
        StubExport::syscall_stub("WriteConsoleA", K32_WRITE_CONSOLE_A),
        StubExport::syscall_stub("ReadConsoleW", K32_READ_CONSOLE_W),
        StubExport::syscall_stub("ExitProcess", K32_EXIT_PROCESS),
        StubExport::syscall_stub("GetCommandLineW", K32_GET_COMMAND_LINE_W),
        StubExport::syscall_stub("GetCommandLineA", K32_GET_COMMAND_LINE_A),
        StubExport::syscall_stub("GetModuleHandleW", K32_GET_MODULE_HANDLE_W),
        // GetLastError / SetLastError: pure user-mode TEB access.
        StubExport::get_last_error(),
        StubExport::set_last_error(),
        // --- Process & Thread identity ---
        StubExport::return_status("GetCurrentProcessId", 1),
        StubExport::syscall_stub("GetCurrentThreadId", K32_GET_CURRENT_THREAD_ID),
        // GetCurrentProcess returns the pseudo-handle -1 (0xFFFFFFFF).
        StubExport::return_status("GetCurrentProcess", -1),
        // GetCurrentThread returns the pseudo-handle -2 (0xFFFFFFFE).
        StubExport::return_status("GetCurrentThread", -2i32),
        // --- Heap functions (Phase 2) ---
        StubExport::syscall_stub("GetProcessHeap", K32_GET_PROCESS_HEAP),
        StubExport::syscall_stub("HeapAlloc", K32_HEAP_ALLOC),
        StubExport::syscall_stub("HeapFree", K32_HEAP_FREE),
        StubExport::syscall_stub("HeapReAlloc", K32_HEAP_REALLOC),
        StubExport::syscall_stub("HeapSize", K32_HEAP_SIZE),
        // --- Virtual memory (kernel32 wrappers around Nt*) ---
        StubExport::syscall_stub("VirtualAlloc", K32_VIRTUAL_ALLOC),
        StubExport::syscall_stub("VirtualFree", K32_VIRTUAL_FREE),
        StubExport::syscall_stub("VirtualProtect", K32_VIRTUAL_PROTECT),
        StubExport::syscall_stub("VirtualQuery", K32_VIRTUAL_QUERY),
        // --- System info ---
        StubExport::syscall_stub("GetSystemInfo", K32_GET_SYSTEM_INFO),
        StubExport::syscall_stub("GetNativeSystemInfo", K32_GET_SYSTEM_INFO),
        StubExport::syscall_stub("IsProcessorFeaturePresent", K32_IS_PROCESSOR_FEATURE),
        StubExport::syscall_stub("GetSystemTimeAsFileTime", K32_GET_SYSTEM_TIME_AS_FT),
        StubExport::syscall_stub("QueryPerformanceCounter", K32_QUERY_PERF_COUNTER),
        StubExport::syscall_stub("QueryPerformanceFrequency", K32_QUERY_PERF_FREQUENCY),
        // --- Synchronization stubs (single-threaded for Phase 2) ---
        // --- Synchronization (Phase 3B: real critical sections) ---
        StubExport::syscall_stub("InitializeCriticalSection", K32_INIT_CRITICAL_SECTION),
        StubExport::syscall_stub("InitializeCriticalSectionEx", K32_INIT_CRITICAL_SECTION_EX),
        StubExport::syscall_stub(
            "InitializeCriticalSectionAndSpinCount",
            K32_INIT_CRITICAL_SECTION_AND_SPIN_COUNT,
        ),
        StubExport::syscall_stub("EnterCriticalSection", K32_ENTER_CRITICAL_SECTION),
        StubExport::syscall_stub("TryEnterCriticalSection", K32_TRY_ENTER_CRITICAL_SECTION),
        StubExport::syscall_stub("LeaveCriticalSection", K32_LEAVE_CRITICAL_SECTION),
        StubExport::syscall_stub("DeleteCriticalSection", K32_DELETE_CRITICAL_SECTION),
        StubExport::return_status("InitializeSListHead", 0),
        // --- TLS (Phase 2: simple stubs; Phase 3: real impl) ---
        StubExport::syscall_stub("TlsAlloc", K32_TLS_ALLOC),
        StubExport::syscall_stub("TlsGetValue", K32_TLS_GET_VALUE),
        StubExport::syscall_stub("TlsSetValue", K32_TLS_SET_VALUE),
        StubExport::syscall_stub("TlsFree", K32_TLS_FREE),
        // --- FLS (fiber-local storage — treated same as TLS for now) ---
        StubExport::syscall_stub("FlsAlloc", K32_FLS_ALLOC),
        StubExport::syscall_stub("FlsGetValue", K32_FLS_GET_VALUE),
        StubExport::syscall_stub("FlsSetValue", K32_FLS_SET_VALUE),
        StubExport::syscall_stub("FlsFree", K32_FLS_FREE),
        // --- Pointer encoding (identity — no obfuscation in sandbox) ---
        // EncodePointer: mov rax, rcx; ret
        StubExport::raw("EncodePointer", vec![0x48, 0x89, 0xC8, 0xC3]),
        StubExport::raw("DecodePointer", vec![0x48, 0x89, 0xC8, 0xC3]),
        // --- Debugging ---
        StubExport::return_status("IsDebuggerPresent", 0),
        // --- Exception handling ---
        StubExport::syscall_stub(
            "SetUnhandledExceptionFilter",
            K32_SET_UNHANDLED_EXCEPTION_FILTER,
        ),
        StubExport::syscall_stub("UnhandledExceptionFilter", K32_UNHANDLED_EXCEPTION_FILTER),
        // --- Locale / codepage ---
        StubExport::return_status("GetACP", 65001), // UTF-8
        StubExport::return_status("GetOEMCP", 437), // OEM US
        StubExport::return_status("AreFileApisANSI", 1), // TRUE
        StubExport::return_status("IsValidCodePage", 1), // TRUE
        StubExport::syscall_stub("GetCPInfo", K32_GET_CP_INFO),
        StubExport::syscall_stub("MultiByteToWideChar", K32_MULTI_BYTE_TO_WIDE_CHAR),
        StubExport::syscall_stub("WideCharToMultiByte", K32_WIDE_CHAR_TO_MULTI_BYTE),
        StubExport::syscall_stub("GetStringTypeW", K32_GET_STRING_TYPE_W),
        StubExport::syscall_stub("LCMapStringW", K32_LC_MAP_STRING_W),
        StubExport::syscall_stub("CompareStringW", K32_COMPARE_STRING_W),
        // --- Environment ---
        StubExport::syscall_stub("GetEnvironmentStringsW", K32_GET_ENVIRONMENT_STRINGS_W),
        StubExport::syscall_stub("FreeEnvironmentStringsW", K32_FREE_ENVIRONMENT_STRINGS_W),
        StubExport::syscall_stub("GetEnvironmentVariableW", K32_GET_ENVIRONMENT_VARIABLE_W),
        // --- Module ---
        StubExport::syscall_stub("GetModuleHandleExW", K32_GET_MODULE_HANDLE_W),
        StubExport::syscall_stub("GetModuleFileNameW", K32_GET_MODULE_FILE_NAME_W),
        // --- Misc ---
        StubExport::return_status("GetStartupInfoW", 0), // stub
        StubExport::return_status("SetHandleCount", 0),
        StubExport::syscall_stub("GetFileType", K32_GET_FILE_TYPE),
        // --- File I/O wrappers ---
        StubExport::syscall_stub("CreateFileW", K32_CREATE_FILE_W),
        StubExport::syscall_stub("ReadFile", K32_READ_FILE),
        StubExport::syscall_stub("WriteFile", K32_WRITE_FILE),
        StubExport::syscall_stub("CloseHandle", K32_CLOSE_HANDLE),
        StubExport::syscall_stub("GetFileSizeEx", K32_GET_FILE_SIZE_EX),
        StubExport::syscall_stub("SetFilePointerEx", K32_SET_FILE_POINTER_EX),
        StubExport::return_status("FlushFileBuffers", 1), // TRUE
        StubExport::syscall_stub("SetEndOfFile", K32_SET_END_OF_FILE),
        // --- Console mode ---
        StubExport::syscall_stub("GetConsoleMode", K32_GET_CONSOLE_MODE),
        StubExport::syscall_stub("SetConsoleMode", K32_SET_CONSOLE_MODE),
        StubExport::return_status("GetConsoleOutputCP", 65001), // UTF-8
        StubExport::return_status("GetConsoleCP", 65001),       // UTF-8
        // --- Version info ---
        StubExport::syscall_stub("GetVersionExW", K32_GET_VERSION_EX_W),
        // --- Module loading ---
        StubExport::syscall_stub("GetProcAddress", K32_GET_PROC_ADDRESS),
        StubExport::syscall_stub("LoadLibraryExW", K32_LOAD_LIBRARY_EX_W),
        StubExport::return_status("FreeLibrary", 1), // TRUE
        // --- Debug output ---
        StubExport::syscall_stub("OutputDebugStringA", K32_OUTPUT_DEBUG_STRING_A),
        StubExport::syscall_stub("OutputDebugStringW", K32_OUTPUT_DEBUG_STRING_W),
        // --- Exception ---
        StubExport::syscall_stub("RaiseException", K32_RAISE_EXCEPTION),
        // --- Heap (additional) ---
        StubExport::syscall_stub("HeapCreate", K32_HEAP_CREATE),
        StubExport::syscall_stub("HeapDestroy", K32_HEAP_DESTROY),
        // --- Path / directory ---
        StubExport::syscall_stub("GetFullPathNameW", K32_GET_FULL_PATH_NAME_W),
        StubExport::syscall_stub("GetTempPathW", K32_GET_TEMP_PATH_W),
        StubExport::syscall_stub("GetCurrentDirectoryW", K32_GET_CURRENT_DIRECTORY_W),
        StubExport::syscall_stub("SetCurrentDirectoryW", K32_SET_CURRENT_DIRECTORY_W),
        // --- Waits ---
        StubExport::syscall_stub("WaitForSingleObject", K32_WAIT_FOR_SINGLE_OBJECT),
        StubExport::syscall_stub("WaitForSingleObjectEx", K32_WAIT_FOR_SINGLE_OBJECT_EX),
        StubExport::syscall_stub("Sleep", K32_SLEEP),
        StubExport::syscall_stub("SleepEx", K32_SLEEP_EX),
        // --- Handle duplication ---
        StubExport::syscall_stub("DuplicateHandle", K32_DUPLICATE_HANDLE),
        // --- SetFileInformationByHandle ---
        StubExport::return_status("SetFileInformationByHandle", 1),
        // --- TerminateProcess (Win32 wrapper around NtTerminateProcess) ---
        StubExport::syscall_stub("TerminateProcess", K32_EXIT_PROCESS), // same as ExitProcess
        // --- Environment (additional) ---
        StubExport::syscall_stub("SetEnvironmentVariableW", K32_SET_ENVIRONMENT_VARIABLE_W),
        // --- Console handle ---
        StubExport::syscall_stub("SetStdHandle", K32_SET_STD_HANDLE),
        // --- File search (FindFirst/FindNext/FindClose) ---
        StubExport::syscall_stub("FindFirstFileExW", K32_FIND_FIRST_FILE_EX_W),
        StubExport::syscall_stub("FindNextFileW", K32_FIND_NEXT_FILE_W),
        StubExport::syscall_stub("FindClose", K32_FIND_CLOSE),
        // --- Registry (api-ms-win-core-registry-l1-1 maps here) ---
        StubExport::syscall_stub("RegOpenKeyExW", K32_REG_OPEN_KEY_EX_W),
        StubExport::syscall_stub("RegQueryValueExW", K32_REG_QUERY_VALUE_EX_W),
        StubExport::syscall_stub("RegCloseKey", K32_REG_CLOSE_KEY),
        StubExport::syscall_stub("RegOpenKeyExA", K32_REG_OPEN_KEY_EX_W),
        StubExport::syscall_stub("RegQueryValueExA", K32_REG_QUERY_VALUE_EX_W),
        // --- SEH / unwinding (kernel32 re-exports from ntdll) ---
        StubExport::syscall_stub("RtlCaptureContext", K32_RTL_CAPTURE_CONTEXT),
        StubExport::syscall_stub("RtlLookupFunctionEntry", K32_RTL_LOOKUP_FUNCTION_ENTRY),
        StubExport::syscall_stub("RtlVirtualUnwind", K32_RTL_VIRTUAL_UNWIND),
        StubExport::syscall_stub("RtlUnwindEx", K32_RTL_UNWIND_EX),
        StubExport::syscall_stub("RtlPcToFileHeader", K32_RTL_PC_TO_FILE_HEADER),
    ]
}

/// advapi32.dll exports — registry and security stubs.
///
/// Node.js / UCRT may import directly from advapi32. The registry functions
/// use the same K32 pseudo-syscall numbers as kernel32 (since the API-set
/// mapper routes `api-ms-win-core-registry-l1-1` to kernel32).
fn advapi32_exports() -> Vec<StubExport> {
    vec![
        // --- Registry ---
        StubExport::syscall_stub("RegOpenKeyExW", K32_REG_OPEN_KEY_EX_W),
        StubExport::syscall_stub("RegQueryValueExW", K32_REG_QUERY_VALUE_EX_W),
        StubExport::syscall_stub("RegCloseKey", K32_REG_CLOSE_KEY),
        // --- Security stubs ---
        // OpenProcessToken: returns FALSE, LastError = ERROR_NO_TOKEN (1008).
        StubExport::return_status_with_last_error("OpenProcessToken", 0, 1008),
        // GetTokenInformation: returns FALSE, LastError = ERROR_NO_TOKEN (1008).
        StubExport::return_status_with_last_error("GetTokenInformation", 0, 1008),
        // RegOpenKeyExA (ANSI variant): same handler.
        StubExport::syscall_stub("RegOpenKeyExA", K32_REG_OPEN_KEY_EX_W),
        StubExport::syscall_stub("RegQueryValueExA", K32_REG_QUERY_VALUE_EX_W),
    ]
}

/// ws2_32.dll exports — WinSock trampolines and byte-order helpers.
fn ws2_32_exports() -> Vec<StubExport> {
    let mut wsa_get_last_error = StubExport::get_last_error();
    wsa_get_last_error.name = String::from("WSAGetLastError");

    let mut wsa_set_last_error = StubExport::set_last_error();
    wsa_set_last_error.name = String::from("WSASetLastError");

    vec![
        StubExport::syscall_stub("WSAStartup", WS2_STARTUP),
        StubExport::syscall_stub("WSACleanup", WS2_CLEANUP),
        StubExport::syscall_stub("socket", WS2_SOCKET),
        StubExport::syscall_stub("closesocket", WS2_CLOSESOCKET),
        StubExport::syscall_stub("connect", WS2_CONNECT),
        StubExport::syscall_stub("bind", WS2_BIND),
        StubExport::syscall_stub("listen", WS2_LISTEN),
        StubExport::syscall_stub("accept", WS2_ACCEPT),
        StubExport::syscall_stub("send", WS2_SEND),
        StubExport::syscall_stub("recv", WS2_RECV),
        StubExport::syscall_stub("sendto", WS2_SENDTO),
        StubExport::syscall_stub("recvfrom", WS2_RECVFROM),
        StubExport::syscall_stub("shutdown", WS2_SHUTDOWN),
        StubExport::syscall_stub("setsockopt", WS2_SETSOCKOPT),
        StubExport::syscall_stub("getsockopt", WS2_GETSOCKOPT),
        StubExport::syscall_stub("ioctlsocket", WS2_IOCTLSOCKET),
        StubExport::syscall_stub("select", WS2_SELECT),
        StubExport::syscall_stub("getsockname", WS2_GETSOCKNAME),
        StubExport::syscall_stub("getpeername", WS2_GETPEERNAME),
        StubExport::syscall_stub("getaddrinfo", WS2_GETADDRINFO),
        StubExport::syscall_stub("freeaddrinfo", WS2_FREEADDRINFO),
        wsa_get_last_error,
        wsa_set_last_error,
        StubExport::raw(
            "htons",
            vec![0x66, 0x8B, 0xC1, 0x86, 0xE0, 0x0F, 0xB7, 0xC0, 0xC3],
        ),
        StubExport::raw("htonl", vec![0x8B, 0xC1, 0x0F, 0xC8, 0xC3]),
        StubExport::raw(
            "ntohs",
            vec![0x66, 0x8B, 0xC1, 0x86, 0xE0, 0x0F, 0xB7, 0xC0, 0xC3],
        ),
        StubExport::raw("ntohl", vec![0x8B, 0xC1, 0x0F, 0xC8, 0xC3]),
        StubExport::syscall_stub("inet_pton", WS2_INET_PTON),
    ]
}

// ========================================================================
// Additional stub DLL export lists for node.exe dependencies
// ========================================================================

/// crypt32.dll — certificate store stubs. All return 0/NULL (failure).
fn crypt32_exports() -> Vec<StubExport> {
    vec![
        StubExport::return_status("CertCloseStore", 1), // TRUE (always succeeds)
        StubExport::return_status("CertDuplicateCertificateContext", 0), // NULL
        StubExport::return_status("CertEnumCertificatesInStore", 0), // NULL (no certs)
        StubExport::return_status("CertFindCertificateInStore", 0), // NULL (not found)
        StubExport::return_status("CertFreeCertificateContext", 1), // TRUE
        StubExport::return_status("CertGetCertificateContextProperty", 0), // FALSE
        StubExport::return_status("CertGetEnhancedKeyUsage", 0), // FALSE
        StubExport::return_status("CertOpenStore", 0),  // NULL
        StubExport::return_status("CertOpenSystemStoreW", 0), // NULL
    ]
}

/// iphlpapi.dll — network adapter/route stubs. Return ERROR_NO_DATA (232)
/// or 0 where appropriate.
fn iphlpapi_exports() -> Vec<StubExport> {
    vec![
        StubExport::return_status("CancelMibChangeNotify2", 0), // NO_ERROR
        StubExport::return_status("ConvertInterfaceIndexToLuid", 0), // NO_ERROR
        StubExport::return_status("ConvertInterfaceLuidToNameW", 0), // NO_ERROR
        StubExport::return_status("GetAdaptersAddresses", 232), // ERROR_NO_DATA
        StubExport::return_status("GetBestRoute2", 232),        // ERROR_NO_DATA
        StubExport::return_status("NotifyIpInterfaceChange", 0), // NO_ERROR (stub)
        StubExport::return_status("if_indextoname", 0),         // NULL (failure)
        StubExport::return_status("if_nametoindex", 0),         // 0 (not found)
    ]
}

/// shell32.dll — shell folder stubs.
fn shell32_exports() -> Vec<StubExport> {
    // SHGetKnownFolderPath returns HRESULT; E_NOTIMPL = 0x80004001.
    vec![StubExport::return_status(
        "SHGetKnownFolderPath",
        0x80004001_u32 as i32, // E_NOTIMPL
    )]
}

/// user32.dll — UI stubs. Most return 0 (failure/no-op).
fn user32_exports() -> Vec<StubExport> {
    vec![
        StubExport::return_status("CharUpperA", 0),
        StubExport::return_status("DispatchMessageA", 0),
        StubExport::return_status("GetMessageA", -1), // -1 = error
        StubExport::return_status("GetProcessWindowStation", 0), // NULL
        StubExport::return_status("GetSystemMetrics", 0),
        StubExport::return_status("GetUserObjectInformationW", 0), // FALSE
        StubExport::return_status("MapVirtualKeyW", 0),
        StubExport::return_status("MessageBoxW", 0), // 0 = failure
        StubExport::return_status("TranslateMessage", 0), // FALSE
    ]
}

/// userenv.dll — user profile stubs.
fn userenv_exports() -> Vec<StubExport> {
    vec![StubExport::return_status_with_last_error(
        "GetUserProfileDirectoryW",
        0,   // FALSE
        232, // ERROR_NO_DATA
    )]
}

/// winmm.dll — multimedia timer stubs.
fn winmm_exports() -> Vec<StubExport> {
    vec![StubExport::return_status("timeGetTime", 0)]
}

/// dbghelp.dll — debug helper stubs. All return 0/FALSE (no debug info).
fn dbghelp_exports() -> Vec<StubExport> {
    vec![
        StubExport::return_status("MiniDumpWriteDump", 0), // FALSE
        StubExport::return_status("StackWalk64", 0),       // FALSE
        StubExport::return_status("SymCleanup", 1),        // TRUE (always succeeds)
        StubExport::return_status("SymFromAddr", 0),       // FALSE
        StubExport::return_status("SymFunctionTableAccess64", 0), // NULL
        StubExport::return_status("SymGetLineFromAddr64", 0), // FALSE
        StubExport::return_status("SymGetModuleBase64", 0), // 0 (not found)
        StubExport::return_status("SymGetOptions", 0),     // 0
        StubExport::return_status("SymGetSearchPathW", 0), // FALSE
        StubExport::return_status("SymInitialize", 1),     // TRUE
        StubExport::return_status("SymSetOptions", 0),     // prev options = 0
        StubExport::return_status("SymSetSearchPathW", 1), // TRUE
        StubExport::return_status("UnDecorateSymbolName", 0), // 0 (failure)
    ]
}

/// ole32.dll — COM stubs.
fn ole32_exports() -> Vec<StubExport> {
    // CoTaskMemFree is void(void*), returning 0 is harmless.
    vec![StubExport::return_status("CoTaskMemFree", 0)]
}

// Reserved syscall numbers for kernel32 functions (0x1000+ range).
pub const K32_GET_STD_HANDLE: u32 = 0x1001;
pub const K32_WRITE_CONSOLE_W: u32 = 0x1002;
pub const K32_WRITE_CONSOLE_A: u32 = 0x1003;
pub const K32_READ_CONSOLE_W: u32 = 0x1093;
pub const K32_EXIT_PROCESS: u32 = 0x1004;
pub const K32_GET_COMMAND_LINE_W: u32 = 0x1005;
pub const K32_GET_COMMAND_LINE_A: u32 = 0x1006;
pub const K32_GET_MODULE_HANDLE_W: u32 = 0x1007;
// Phase 2: Heap
pub const K32_GET_PROCESS_HEAP: u32 = 0x1008;
pub const K32_HEAP_ALLOC: u32 = 0x1009;
pub const K32_HEAP_FREE: u32 = 0x100A;
pub const K32_HEAP_REALLOC: u32 = 0x100B;
pub const K32_HEAP_SIZE: u32 = 0x100C;
// Phase 2: Virtual memory wrappers
pub const K32_VIRTUAL_ALLOC: u32 = 0x1010;
pub const K32_VIRTUAL_FREE: u32 = 0x1011;
pub const K32_VIRTUAL_PROTECT: u32 = 0x1012;
pub const K32_VIRTUAL_QUERY: u32 = 0x1013;
// Phase 2: System info
pub const K32_GET_SYSTEM_INFO: u32 = 0x1020;
pub const K32_IS_PROCESSOR_FEATURE: u32 = 0x1021;
pub const K32_GET_SYSTEM_TIME_AS_FT: u32 = 0x1022;
pub const K32_QUERY_PERF_COUNTER: u32 = 0x1023;
pub const K32_QUERY_PERF_FREQUENCY: u32 = 0x1024;
// Phase 2: TLS
pub const K32_TLS_ALLOC: u32 = 0x1030;
pub const K32_TLS_GET_VALUE: u32 = 0x1031;
pub const K32_TLS_SET_VALUE: u32 = 0x1032;
pub const K32_TLS_FREE: u32 = 0x1033;
// Phase 2: FLS
pub const K32_FLS_ALLOC: u32 = 0x1038;
pub const K32_FLS_GET_VALUE: u32 = 0x1039;
pub const K32_FLS_SET_VALUE: u32 = 0x103A;
pub const K32_FLS_FREE: u32 = 0x103B;
// Phase 2: Exception handling
pub const K32_SET_UNHANDLED_EXCEPTION_FILTER: u32 = 0x1040;
// Phase 2: Environment
pub const K32_GET_ENVIRONMENT_STRINGS_W: u32 = 0x1050;
pub const K32_GET_ENVIRONMENT_VARIABLE_W: u32 = 0x1051;
// Phase 2: Module
pub const K32_GET_MODULE_FILE_NAME_W: u32 = 0x1060;
// Phase 2: Locale/string conversion
pub const K32_MULTI_BYTE_TO_WIDE_CHAR: u32 = 0x1070;
pub const K32_WIDE_CHAR_TO_MULTI_BYTE: u32 = 0x1071;
pub const K32_GET_CP_INFO: u32 = 0x1072;
pub const K32_GET_STRING_TYPE_W: u32 = 0x1073;
pub const K32_LC_MAP_STRING_W: u32 = 0x1074;
pub const K32_COMPARE_STRING_W: u32 = 0x1075;
// Phase 2: File I/O wrappers (kernel32 → ntdll)
pub const K32_CREATE_FILE_W: u32 = 0x1080;
pub const K32_READ_FILE: u32 = 0x1081;
pub const K32_WRITE_FILE: u32 = 0x1082;
pub const K32_CLOSE_HANDLE: u32 = 0x1083;
pub const K32_GET_FILE_TYPE: u32 = 0x1084;
pub const K32_GET_FILE_SIZE_EX: u32 = 0x1085;
pub const K32_SET_FILE_POINTER_EX: u32 = 0x1086;
pub const K32_SET_END_OF_FILE: u32 = 0x108A;
// Phase 2: Console mode
pub const K32_GET_CONSOLE_MODE: u32 = 0x1090;
pub const K32_SET_CONSOLE_MODE: u32 = 0x1091;
// Phase 2: Version info
pub const K32_GET_VERSION_EX_W: u32 = 0x10A0;
// Phase 2: Module loading
pub const K32_GET_PROC_ADDRESS: u32 = 0x10B0;
pub const K32_LOAD_LIBRARY_EX_W: u32 = 0x10B1;
// Phase 2: Debug output
pub const K32_OUTPUT_DEBUG_STRING_A: u32 = 0x10C0;
pub const K32_OUTPUT_DEBUG_STRING_W: u32 = 0x10C1;
// Phase 2: Heap (additional)
pub const K32_HEAP_CREATE: u32 = 0x100D;
pub const K32_HEAP_DESTROY: u32 = 0x100E;
// Phase 2: Path / directory
pub const K32_GET_FULL_PATH_NAME_W: u32 = 0x10D0;
pub const K32_GET_TEMP_PATH_W: u32 = 0x10D1;
pub const K32_GET_CURRENT_DIRECTORY_W: u32 = 0x10D2;
pub const K32_SET_CURRENT_DIRECTORY_W: u32 = 0x10D3;
// Phase 2: Handle duplication
pub const K32_DUPLICATE_HANDLE: u32 = 0x10E0;
// Phase 2: Environment (additional)
pub const K32_SET_ENVIRONMENT_VARIABLE_W: u32 = 0x1052;
pub const K32_FREE_ENVIRONMENT_STRINGS_W: u32 = 0x1053;
// Phase 2: Console handle
pub const K32_SET_STD_HANDLE: u32 = 0x1092;
// Phase 2: File search
pub const K32_FIND_FIRST_FILE_EX_W: u32 = 0x1087;
pub const K32_FIND_NEXT_FILE_W: u32 = 0x1088;
pub const K32_FIND_CLOSE: u32 = 0x1089;
// Phase 2: SEH / unwinding
pub const K32_RTL_CAPTURE_CONTEXT: u32 = 0x10F0;
pub const K32_RTL_LOOKUP_FUNCTION_ENTRY: u32 = 0x10F1;
pub const K32_RTL_VIRTUAL_UNWIND: u32 = 0x10F2;
pub const K32_RTL_UNWIND_EX: u32 = 0x10F3;
pub const K32_RTL_PC_TO_FILE_HEADER: u32 = 0x10F4;
pub const K32_RAISE_EXCEPTION: u32 = 0x10F5;
pub const K32_UNHANDLED_EXCEPTION_FILTER: u32 = 0x10F6;
// Phase 3B: Sleep
pub const K32_SLEEP: u32 = 0x1100;
pub const K32_SLEEP_EX: u32 = 0x1101;
// Phase 3B: Critical sections
pub const K32_INIT_CRITICAL_SECTION: u32 = 0x1110;
pub const K32_INIT_CRITICAL_SECTION_EX: u32 = 0x1111;
pub const K32_INIT_CRITICAL_SECTION_AND_SPIN_COUNT: u32 = 0x1112;
pub const K32_ENTER_CRITICAL_SECTION: u32 = 0x1113;
pub const K32_LEAVE_CRITICAL_SECTION: u32 = 0x1114;
pub const K32_DELETE_CRITICAL_SECTION: u32 = 0x1115;
pub const K32_TRY_ENTER_CRITICAL_SECTION: u32 = 0x1116;
// Phase 3B: Wait APIs
pub const K32_WAIT_FOR_SINGLE_OBJECT: u32 = 0x1120;
pub const K32_WAIT_FOR_SINGLE_OBJECT_EX: u32 = 0x1121;
pub const K32_GET_CURRENT_THREAD_ID: u32 = 0x1130;

pub const K32_REG_OPEN_KEY_EX_W: u32 = 0x1140;
pub const K32_REG_QUERY_VALUE_EX_W: u32 = 0x1141;
pub const K32_REG_CLOSE_KEY: u32 = 0x1142;

// Phase 4: WinSock (ws2_32.dll)
pub const WS2_STARTUP: u32 = 0x1200;
pub const WS2_CLEANUP: u32 = 0x1201;
pub const WS2_SOCKET: u32 = 0x1202;
pub const WS2_CLOSESOCKET: u32 = 0x1203;
pub const WS2_CONNECT: u32 = 0x1204;
pub const WS2_BIND: u32 = 0x1205;
pub const WS2_LISTEN: u32 = 0x1206;
pub const WS2_ACCEPT: u32 = 0x1207;
pub const WS2_SEND: u32 = 0x1208;
pub const WS2_RECV: u32 = 0x1209;
pub const WS2_SENDTO: u32 = 0x120A;
pub const WS2_RECVFROM: u32 = 0x120B;
pub const WS2_SHUTDOWN: u32 = 0x120C;
pub const WS2_SETSOCKOPT: u32 = 0x120D;
pub const WS2_GETSOCKOPT: u32 = 0x120E;
pub const WS2_IOCTLSOCKET: u32 = 0x120F;
pub const WS2_SELECT: u32 = 0x1210;
pub const WS2_GETSOCKNAME: u32 = 0x1211;
pub const WS2_GETPEERNAME: u32 = 0x1212;
pub const WS2_GETADDRINFO: u32 = 0x1213;
pub const WS2_FREEADDRINFO: u32 = 0x1214;
pub const WS2_HTONS: u32 = 0x1215;
pub const WS2_HTONL: u32 = 0x1216;
pub const WS2_NTOHS: u32 = 0x1217;
pub const WS2_NTOHL: u32 = 0x1218;
pub const WS2_INET_PTON: u32 = 0x1219;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_parser::PeParsedFile;

    #[test]
    fn ntdll_stub_is_valid_pe() {
        let bytes = build_ntdll();
        let parsed = PeParsedFile::parse(&bytes).expect("ntdll stub should be valid PE");
        assert!(parsed.is_dll);
        assert_eq!(parsed.image_base, NTDLL_IMAGE_BASE);

        let exports = parsed.exports(&bytes);
        // Should have all ntdll exports.
        let names: Vec<_> = exports.iter().filter_map(|e| e.name).collect();
        assert!(names.contains(&"NtWriteFile"));
        assert!(names.contains(&"NtClose"));
        assert!(names.contains(&"NtTerminateProcess"));
        assert!(names.contains(&"RtlNtStatusToDosError"));
    }

    #[test]
    fn kernel32_stub_is_valid_pe() {
        let bytes = build_kernel32();
        let parsed = PeParsedFile::parse(&bytes).expect("kernel32 stub should be valid PE");
        assert!(parsed.is_dll);
        assert_eq!(parsed.image_base, KERNEL32_IMAGE_BASE);

        let exports = parsed.exports(&bytes);
        let names: Vec<_> = exports.iter().filter_map(|e| e.name).collect();
        assert!(names.contains(&"GetStdHandle"));
        assert!(names.contains(&"WriteConsoleW"));
        assert!(names.contains(&"ExitProcess"));
        assert!(names.contains(&"GetCommandLineW"));
        // Phase 2 additions
        assert!(names.contains(&"HeapAlloc"));
        assert!(names.contains(&"VirtualAlloc"));
        assert!(names.contains(&"EncodePointer"));
        assert!(names.contains(&"TlsAlloc"));
    }

    #[test]
    fn ws2_32_stub_is_valid_pe() {
        let bytes = build_ws2_32();
        let parsed = PeParsedFile::parse(&bytes).expect("ws2_32 stub should be valid PE");
        assert!(parsed.is_dll);
        assert_eq!(parsed.image_base, WS2_32_IMAGE_BASE);

        let exports = parsed.exports(&bytes);
        let names: Vec<_> = exports.iter().filter_map(|e| e.name).collect();
        assert!(names.contains(&"WSAStartup"));
        assert!(names.contains(&"socket"));
        assert!(names.contains(&"WSAGetLastError"));
        assert!(names.contains(&"htons"));
        assert!(names.contains(&"inet_pton"));
    }

    #[test]
    fn ntdll_and_kernel32_have_distinct_bases() {
        let ntdll = build_ntdll();
        let kernel32 = build_kernel32();
        let p1 = PeParsedFile::parse(&ntdll).unwrap();
        let p2 = PeParsedFile::parse(&kernel32).unwrap();
        assert_ne!(p1.image_base, p2.image_base);
    }
}
