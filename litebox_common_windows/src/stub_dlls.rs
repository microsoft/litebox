// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Stub DLL catalog.
//!
//! Generates ntdll.dll and kernel32.dll stubs with the correct export lists
//! for the NT shim. Each export is a tiny syscall stub or a user-mode function
//! that the shim intercepts.

use alloc::vec;
use alloc::vec::Vec;

use crate::NtSyscallNumber;
use crate::pe_builder::{CALLBACK_PTR_RVA, GS_TABLE_PTR_RVA, StubExport, build_stub_dll};

/// Default preferred base addresses for stub DLLs.
/// Each DLL gets a distinct base to avoid collisions.
pub const NTDLL_IMAGE_BASE: u64 = 0x0000_7FFE_0000_0000;
pub const KERNEL32_IMAGE_BASE: u64 = 0x0000_7FFE_0001_0000;

/// Generate the ntdll.dll stub bytes with a specific load base and callback.
///
/// `image_base` should match the VA where the DLL will be loaded, so that
/// no rebasing is needed (the .text section stays RX).
///
/// `syscall_entry` is the address of the platform's `syscall_callback`.
/// `gs_table_ptr` is the address of the host-owned GS lookup table.
pub fn build_ntdll_for(image_base: u64, syscall_entry: u64, gs_table_ptr: u64) -> Vec<u8> {
    let exports = ntdll_exports();
    let mut bytes = build_stub_dll("ntdll.dll", &exports, image_base);
    patch_text_header(&mut bytes, syscall_entry, gs_table_ptr);
    bytes
}

/// Generate the kernel32.dll stub bytes with a specific load base and callback.
pub fn build_kernel32_for(image_base: u64, syscall_entry: u64, gs_table_ptr: u64) -> Vec<u8> {
    let exports = kernel32_exports();
    let mut bytes = build_stub_dll("kernel32.dll", &exports, image_base);
    patch_text_header(&mut bytes, syscall_entry, gs_table_ptr);
    bytes
}

/// Default preferred base for advapi32.dll stub.
pub const ADVAPI32_IMAGE_BASE: u64 = 0x0000_7FFE_0002_0000;

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

/// Generate the advapi32.dll stub bytes with a specific load base and callback.
pub fn build_advapi32_for(image_base: u64, syscall_entry: u64, gs_table_ptr: u64) -> Vec<u8> {
    let exports = advapi32_exports();
    let mut bytes = build_stub_dll("advapi32.dll", &exports, image_base);
    patch_text_header(&mut bytes, syscall_entry, gs_table_ptr);
    bytes
}

/// Write the callback pointer and GS table pointer into the raw DLL bytes
/// at the file offsets corresponding to their RVAs.
fn patch_text_header(bytes: &mut [u8], syscall_entry: u64, gs_table_ptr: u64) {
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
}

/// Ntdll exports: one syscall stub per NT syscall number.
fn ntdll_exports() -> Vec<StubExport> {
    vec![
        // Phase 1: Minimal boot
        StubExport::syscall_stub("NtWriteFile", NtSyscallNumber::NtWriteFile as u32),
        StubExport::syscall_stub(
            "NtAllocateVirtualMemory",
            NtSyscallNumber::NtAllocateVirtualMemory as u32,
        ),
        StubExport::syscall_stub(
            "NtFreeVirtualMemory",
            NtSyscallNumber::NtFreeVirtualMemory as u32,
        ),
        StubExport::syscall_stub(
            "NtProtectVirtualMemory",
            NtSyscallNumber::NtProtectVirtualMemory as u32,
        ),
        StubExport::syscall_stub(
            "NtQueryVirtualMemory",
            NtSyscallNumber::NtQueryVirtualMemory as u32,
        ),
        StubExport::syscall_stub("NtClose", NtSyscallNumber::NtClose as u32),
        StubExport::syscall_stub(
            "NtTerminateProcess",
            NtSyscallNumber::NtTerminateProcess as u32,
        ),
        // Phase 2: File I/O
        StubExport::syscall_stub("NtCreateFile", NtSyscallNumber::NtCreateFile as u32),
        StubExport::syscall_stub("NtReadFile", NtSyscallNumber::NtReadFile as u32),
        StubExport::syscall_stub(
            "NtQueryInformationFile",
            NtSyscallNumber::NtQueryInformationFile as u32,
        ),
        StubExport::syscall_stub(
            "NtSetInformationFile",
            NtSyscallNumber::NtSetInformationFile as u32,
        ),
        StubExport::syscall_stub(
            "NtQueryVolumeInformationFile",
            NtSyscallNumber::NtQueryVolumeInformationFile as u32,
        ),
        StubExport::syscall_stub(
            "NtQueryAttributesFile",
            NtSyscallNumber::NtQueryAttributesFile as u32,
        ),
        StubExport::syscall_stub(
            "NtQueryDirectoryFile",
            NtSyscallNumber::NtQueryDirectoryFile as u32,
        ),
        StubExport::syscall_stub(
            "NtQuerySystemInformation",
            NtSyscallNumber::NtQuerySystemInformation as u32,
        ),
        StubExport::syscall_stub(
            "NtQueryPerformanceCounter",
            NtSyscallNumber::NtQueryPerformanceCounter as u32,
        ),
        StubExport::syscall_stub(
            "NtQuerySystemTime",
            NtSyscallNumber::NtQuerySystemTime as u32,
        ),
        StubExport::syscall_stub(
            "NtQueryInformationProcess",
            NtSyscallNumber::NtQueryInformationProcess as u32,
        ),
        // Phase 3: Threading & sync
        StubExport::syscall_stub("NtDelayExecution", NtSyscallNumber::NtDelayExecution as u32),
        StubExport::syscall_stub(
            "NtSetInformationThread",
            NtSyscallNumber::NtSetInformationThread as u32,
        ),
        StubExport::syscall_stub("NtCreateThreadEx", NtSyscallNumber::NtCreateThreadEx as u32),
        StubExport::syscall_stub(
            "NtTerminateThread",
            NtSyscallNumber::NtTerminateThread as u32,
        ),
        StubExport::syscall_stub("NtOpenKey", NtSyscallNumber::NtOpenKey as u32),
        StubExport::syscall_stub("NtQueryValueKey", NtSyscallNumber::NtQueryValueKey as u32),
        StubExport::syscall_stub("NtCreateEvent", NtSyscallNumber::NtCreateEvent as u32),
        StubExport::syscall_stub("NtSetEvent", NtSyscallNumber::NtSetEvent as u32),
        StubExport::syscall_stub("NtResetEvent", NtSyscallNumber::NtResetEvent as u32),
        StubExport::syscall_stub("NtClearEvent", NtSyscallNumber::NtClearEvent as u32),
        StubExport::syscall_stub(
            "NtWaitForSingleObject",
            NtSyscallNumber::NtWaitForSingleObject as u32,
        ),
        StubExport::syscall_stub(
            "NtWaitForMultipleObjects",
            NtSyscallNumber::NtWaitForMultipleObjects as u32,
        ),
        StubExport::syscall_stub(
            "NtCreateSemaphore",
            NtSyscallNumber::NtCreateSemaphore as u32,
        ),
        StubExport::syscall_stub(
            "NtReleaseSemaphore",
            NtSyscallNumber::NtReleaseSemaphore as u32,
        ),
        StubExport::syscall_stub(
            "NtCreateKeyedEvent",
            NtSyscallNumber::NtCreateKeyedEvent as u32,
        ),
        StubExport::syscall_stub(
            "NtWaitForKeyedEvent",
            NtSyscallNumber::NtWaitForKeyedEvent as u32,
        ),
        StubExport::syscall_stub(
            "NtReleaseKeyedEvent",
            NtSyscallNumber::NtReleaseKeyedEvent as u32,
        ),
        StubExport::syscall_stub(
            "NtDuplicateObject",
            NtSyscallNumber::NtDuplicateObject as u32,
        ),
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

// Reserved syscall numbers for kernel32 functions (0x1000+ range).
pub const K32_GET_STD_HANDLE: u32 = 0x1001;
pub const K32_WRITE_CONSOLE_W: u32 = 0x1002;
pub const K32_WRITE_CONSOLE_A: u32 = 0x1003;
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
    fn ntdll_and_kernel32_have_distinct_bases() {
        let ntdll = build_ntdll();
        let kernel32 = build_kernel32();
        let p1 = PeParsedFile::parse(&ntdll).unwrap();
        let p2 = PeParsedFile::parse(&kernel32).unwrap();
        assert_ne!(p1.image_base, p2.image_base);
    }
}
