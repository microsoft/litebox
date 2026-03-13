// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Function implementation table and trampoline linking
//!
//! This module provides the infrastructure to link DLL stub exports
//! to actual platform implementations via trampolines.

use crate::{LinuxPlatformForWindows, Result};
use litebox_shim_windows::loader::dispatch::generate_trampoline;

/// Function implementation entry
pub struct FunctionImpl {
    /// Function name (e.g., "NtCreateFile")
    pub name: &'static str,
    /// DLL name (e.g., "KERNEL32.dll", "NTDLL.dll")
    pub dll_name: &'static str,
    /// Number of parameters
    pub num_params: usize,
    /// Implementation function address
    pub impl_address: usize,
}

/// Get the table of all function implementations
///
/// This table maps Windows API functions to their Linux platform implementations.
/// Each entry specifies:
/// - The function name
/// - The DLL it belongs to
/// - The number of parameters (for trampoline generation)
/// - The address of the implementation function
///
/// The implementation functions are external C functions defined in the
/// MSVCRT module and platform layer.
pub fn get_function_table() -> Vec<FunctionImpl> {
    vec![
        // MSVCRT.dll functions - these are defined in msvcrt.rs
        FunctionImpl {
            name: "malloc",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_malloc as *const () as usize,
        },
        FunctionImpl {
            name: "free",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_free as *const () as usize,
        },
        FunctionImpl {
            name: "calloc",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_calloc as *const () as usize,
        },
        FunctionImpl {
            name: "memcpy",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_memcpy as *const () as usize,
        },
        FunctionImpl {
            name: "memmove",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_memmove as *const () as usize,
        },
        FunctionImpl {
            name: "memset",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_memset as *const () as usize,
        },
        FunctionImpl {
            name: "memcmp",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_memcmp as *const () as usize,
        },
        FunctionImpl {
            name: "strlen",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_strlen as *const () as usize,
        },
        FunctionImpl {
            name: "strncmp",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_strncmp as *const () as usize,
        },
        FunctionImpl {
            name: "printf",
            dll_name: "MSVCRT.dll",
            num_params: 8, // Variadic; translate up to 8 params (format + 7 args)
            impl_address: crate::msvcrt::msvcrt_printf as *const () as usize,
        },
        FunctionImpl {
            name: "fprintf",
            dll_name: "MSVCRT.dll",
            num_params: 8, // Variadic; translate up to 8 params (stream + format + 6 args)
            impl_address: crate::msvcrt::msvcrt_fprintf as *const () as usize,
        },
        FunctionImpl {
            name: "fwrite",
            dll_name: "MSVCRT.dll",
            num_params: 4,
            impl_address: crate::msvcrt::msvcrt_fwrite as *const () as usize,
        },
        FunctionImpl {
            name: "__getmainargs",
            dll_name: "MSVCRT.dll",
            num_params: 5,
            impl_address: crate::msvcrt::msvcrt___getmainargs as *const () as usize,
        },
        FunctionImpl {
            name: "__set_app_type",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt___set_app_type as *const () as usize,
        },
        FunctionImpl {
            name: "_initterm",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__initterm as *const () as usize,
        },
        FunctionImpl {
            name: "signal",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_signal as *const () as usize,
        },
        FunctionImpl {
            name: "abort",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt_abort as *const () as usize,
        },
        FunctionImpl {
            name: "exit",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_exit as *const () as usize,
        },
        FunctionImpl {
            name: "__iob_func",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt___iob_func as *const () as usize,
        },
        FunctionImpl {
            name: "vfprintf",
            dll_name: "MSVCRT.dll",
            num_params: 3, // Takes FILE*, const char*, va_list
            impl_address: crate::msvcrt::msvcrt_vfprintf as *const () as usize,
        },
        FunctionImpl {
            name: "vprintf",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_vprintf as *const () as usize,
        },
        FunctionImpl {
            name: "vsprintf",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_vsprintf as *const () as usize,
        },
        FunctionImpl {
            name: "vsnprintf",
            dll_name: "MSVCRT.dll",
            num_params: 4,
            impl_address: crate::msvcrt::msvcrt_vsnprintf as *const () as usize,
        },
        FunctionImpl {
            name: "vswprintf",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_vswprintf as *const () as usize,
        },
        FunctionImpl {
            name: "fwprintf",
            dll_name: "MSVCRT.dll",
            num_params: 8, // variadic: stream + format + up to 6 args via trampoline
            impl_address: crate::msvcrt::msvcrt_fwprintf as *const () as usize,
        },
        FunctionImpl {
            name: "vfwprintf",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_vfwprintf as *const () as usize,
        },
        FunctionImpl {
            name: "_onexit",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__onexit as *const () as usize,
        },
        FunctionImpl {
            name: "_amsg_exit",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__amsg_exit as *const () as usize,
        },
        FunctionImpl {
            name: "_cexit",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt__cexit as *const () as usize,
        },
        FunctionImpl {
            name: "_fpreset",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt__fpreset as *const () as usize,
        },
        FunctionImpl {
            name: "__setusermatherr",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt___setusermatherr as *const () as usize,
        },
        // Additional CRT functions needed by C++ MinGW programs (winsock_test, etc.)
        FunctionImpl {
            name: "strerror",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_strerror as *const () as usize,
        },
        FunctionImpl {
            name: "wcslen",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_wcslen as *const () as usize,
        },
        FunctionImpl {
            name: "wcscmp",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_wcscmp as *const () as usize,
        },
        FunctionImpl {
            name: "wcsstr",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_wcsstr as *const () as usize,
        },
        FunctionImpl {
            name: "fputc",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_fputc as *const () as usize,
        },
        FunctionImpl {
            name: "fputs",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_fputs as *const () as usize,
        },
        FunctionImpl {
            name: "puts",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_puts as *const () as usize,
        },
        FunctionImpl {
            name: "_read",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__read as *const () as usize,
        },
        FunctionImpl {
            name: "_write",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__write as *const () as usize,
        },
        FunctionImpl {
            name: "getchar",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt_getchar as *const () as usize,
        },
        FunctionImpl {
            name: "putchar",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_putchar as *const () as usize,
        },
        FunctionImpl {
            name: "realloc",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_realloc as *const () as usize,
        },
        FunctionImpl {
            name: "localeconv",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt_localeconv as *const () as usize,
        },
        FunctionImpl {
            name: "___lc_codepage_func",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt____lc_codepage_func as *const () as usize,
        },
        FunctionImpl {
            name: "___mb_cur_max_func",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt____mb_cur_max_func as *const () as usize,
        },
        // KERNEL32.dll functions - these are defined in kernel32.rs
        FunctionImpl {
            name: "Sleep",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_Sleep as *const () as usize,
        },
        FunctionImpl {
            name: "GetCurrentThreadId",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetCurrentThreadId as *const () as usize,
        },
        FunctionImpl {
            name: "GetThreadId",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetThreadId as *const () as usize,
        },
        FunctionImpl {
            name: "GetCurrentProcessId",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetCurrentProcessId as *const () as usize,
        },
        FunctionImpl {
            name: "TlsAlloc",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_TlsAlloc as *const () as usize,
        },
        FunctionImpl {
            name: "TlsFree",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_TlsFree as *const () as usize,
        },
        FunctionImpl {
            name: "TlsGetValue",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_TlsGetValue as *const () as usize,
        },
        FunctionImpl {
            name: "TlsSetValue",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_TlsSetValue as *const () as usize,
        },
        // Phase 8: Exception Handling (stubs for CRT compatibility)
        FunctionImpl {
            name: "__C_specific_handler",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32___C_specific_handler as *const () as usize,
        },
        FunctionImpl {
            name: "SetUnhandledExceptionFilter",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SetUnhandledExceptionFilter as *const ()
                as usize,
        },
        FunctionImpl {
            name: "UnhandledExceptionFilter",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_UnhandledExceptionFilter as *const () as usize,
        },
        FunctionImpl {
            name: "InitializeSListHead",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_InitializeSListHead as *const () as usize,
        },
        FunctionImpl {
            name: "RaiseException",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_RaiseException as *const () as usize,
        },
        FunctionImpl {
            name: "RtlCaptureContext",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_RtlCaptureContext as *const () as usize,
        },
        FunctionImpl {
            name: "RtlLookupFunctionEntry",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_RtlLookupFunctionEntry as *const () as usize,
        },
        FunctionImpl {
            name: "RtlUnwindEx",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_RtlUnwindEx as *const () as usize,
        },
        FunctionImpl {
            name: "RtlVirtualUnwind",
            dll_name: "KERNEL32.dll",
            num_params: 8,
            impl_address: crate::kernel32::kernel32_RtlVirtualUnwind as *const () as usize,
        },
        FunctionImpl {
            name: "RtlPcToFileHeader",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_RtlPcToFileHeader as *const () as usize,
        },
        FunctionImpl {
            name: "AddVectoredExceptionHandler",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_AddVectoredExceptionHandler as *const ()
                as usize,
        },
        FunctionImpl {
            name: "RemoveVectoredExceptionHandler",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_RemoveVectoredExceptionHandler as *const ()
                as usize,
        },
        // Phase 8.2: Critical Sections
        FunctionImpl {
            name: "InitializeCriticalSection",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_InitializeCriticalSection as *const () as usize,
        },
        FunctionImpl {
            name: "EnterCriticalSection",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_EnterCriticalSection as *const () as usize,
        },
        FunctionImpl {
            name: "LeaveCriticalSection",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_LeaveCriticalSection as *const () as usize,
        },
        FunctionImpl {
            name: "TryEnterCriticalSection",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_TryEnterCriticalSection as *const () as usize,
        },
        FunctionImpl {
            name: "DeleteCriticalSection",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_DeleteCriticalSection as *const () as usize,
        },
        // Phase 8.3: String Operations
        FunctionImpl {
            name: "MultiByteToWideChar",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_MultiByteToWideChar as *const () as usize,
        },
        FunctionImpl {
            name: "WideCharToMultiByte",
            dll_name: "KERNEL32.dll",
            num_params: 8,
            impl_address: crate::kernel32::kernel32_WideCharToMultiByte as *const () as usize,
        },
        FunctionImpl {
            name: "lstrlenW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_lstrlenW as *const () as usize,
        },
        FunctionImpl {
            name: "CompareStringOrdinal",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_CompareStringOrdinal as *const () as usize,
        },
        // Phase 8.4: Performance Counters
        FunctionImpl {
            name: "QueryPerformanceCounter",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_QueryPerformanceCounter as *const () as usize,
        },
        FunctionImpl {
            name: "QueryPerformanceFrequency",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_QueryPerformanceFrequency as *const () as usize,
        },
        FunctionImpl {
            name: "GetSystemTimePreciseAsFileTime",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetSystemTimePreciseAsFileTime as *const ()
                as usize,
        },
        FunctionImpl {
            name: "GetSystemTimeAsFileTime",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetSystemTimeAsFileTime as *const () as usize,
        },
        // Phase 8.5: File I/O Trampolines
        FunctionImpl {
            name: "CreateFileW",
            dll_name: "KERNEL32.dll",
            num_params: 7,
            impl_address: crate::kernel32::kernel32_CreateFileW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateFileA",
            dll_name: "KERNEL32.dll",
            num_params: 7,
            impl_address: crate::kernel32::kernel32_CreateFileA as *const () as usize,
        },
        FunctionImpl {
            name: "ReadFile",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_ReadFile as *const () as usize,
        },
        FunctionImpl {
            name: "WriteFile",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_WriteFile as *const () as usize,
        },
        FunctionImpl {
            name: "CloseHandle",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_CloseHandle as *const () as usize,
        },
        // Phase 8.6: Heap Management Trampolines
        FunctionImpl {
            name: "GetProcessHeap",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetProcessHeap as *const () as usize,
        },
        FunctionImpl {
            name: "HeapAlloc",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_HeapAlloc as *const () as usize,
        },
        FunctionImpl {
            name: "HeapFree",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_HeapFree as *const () as usize,
        },
        FunctionImpl {
            name: "HeapReAlloc",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_HeapReAlloc as *const () as usize,
        },
        // Phase 8.7: Additional startup and CRT functions
        FunctionImpl {
            name: "GetStartupInfoA",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetStartupInfoA as *const () as usize,
        },
        FunctionImpl {
            name: "GetStartupInfoW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetStartupInfoW as *const () as usize,
        },
        FunctionImpl {
            name: "_acmdln",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt__acmdln as *const () as usize,
        },
        FunctionImpl {
            name: "_ismbblead",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__ismbblead as *const () as usize,
        },
        FunctionImpl {
            name: "__C_specific_handler",
            dll_name: "MSVCRT.dll",
            num_params: 4,
            impl_address: crate::msvcrt::msvcrt___C_specific_handler as *const () as usize,
        },
        // Phase 9: CRT helper functions for global data access
        FunctionImpl {
            name: "__p__fmode",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt___p__fmode as *const () as usize,
        },
        FunctionImpl {
            name: "__p__commode",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt___p__commode as *const () as usize,
        },
        FunctionImpl {
            name: "_setargv",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt__setargv as *const () as usize,
        },
        FunctionImpl {
            name: "_set_invalid_parameter_handler",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__set_invalid_parameter_handler as *const ()
                as usize,
        },
        FunctionImpl {
            name: "_pei386_runtime_relocator",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt__pei386_runtime_relocator as *const () as usize,
        },
        // Additional KERNEL32 stub functions
        FunctionImpl {
            name: "CancelIo",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_CancelIo as *const () as usize,
        },
        FunctionImpl {
            name: "CopyFileExW",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_CopyFileExW as *const () as usize,
        },
        FunctionImpl {
            name: "CopyFileW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_CopyFileW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateDirectoryW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_CreateDirectoryW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateDirectoryExW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_CreateDirectoryExW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateEventW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_CreateEventW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateFileMappingA",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_CreateFileMappingA as *const () as usize,
        },
        FunctionImpl {
            name: "CreateHardLinkW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_CreateHardLinkW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateIoCompletionPort",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_CreateIoCompletionPort as *const () as usize,
        },
        FunctionImpl {
            name: "CreatePipe",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_CreatePipe as *const () as usize,
        },
        FunctionImpl {
            name: "CreateProcessA",
            dll_name: "KERNEL32.dll",
            num_params: 10,
            impl_address: crate::kernel32::kernel32_CreateProcessA as *const () as usize,
        },
        FunctionImpl {
            name: "CreateProcessW",
            dll_name: "KERNEL32.dll",
            num_params: 10,
            impl_address: crate::kernel32::kernel32_CreateProcessW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateSymbolicLinkW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_CreateSymbolicLinkW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateThread",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_CreateThread as *const () as usize,
        },
        FunctionImpl {
            name: "CreateToolhelp32Snapshot",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_CreateToolhelp32Snapshot as *const () as usize,
        },
        FunctionImpl {
            name: "CreateWaitableTimerExW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_CreateWaitableTimerExW as *const () as usize,
        },
        FunctionImpl {
            name: "DeleteFileW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_DeleteFileW as *const () as usize,
        },
        FunctionImpl {
            name: "DeleteFileA",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_DeleteFileA as *const () as usize,
        },
        FunctionImpl {
            name: "DeleteProcThreadAttributeList",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_DeleteProcThreadAttributeList as *const ()
                as usize,
        },
        FunctionImpl {
            name: "DeviceIoControl",
            dll_name: "KERNEL32.dll",
            num_params: 8,
            impl_address: crate::kernel32::kernel32_DeviceIoControl as *const () as usize,
        },
        FunctionImpl {
            name: "DuplicateHandle",
            dll_name: "KERNEL32.dll",
            num_params: 7,
            impl_address: crate::kernel32::kernel32_DuplicateHandle as *const () as usize,
        },
        FunctionImpl {
            name: "FlushFileBuffers",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_FlushFileBuffers as *const () as usize,
        },
        FunctionImpl {
            name: "FormatMessageW",
            dll_name: "KERNEL32.dll",
            num_params: 7,
            impl_address: crate::kernel32::kernel32_FormatMessageW as *const () as usize,
        },
        FunctionImpl {
            name: "GetCurrentDirectoryW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetCurrentDirectoryW as *const () as usize,
        },
        FunctionImpl {
            name: "GetExitCodeProcess",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetExitCodeProcess as *const () as usize,
        },
        FunctionImpl {
            name: "GetFileAttributesW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetFileAttributesW as *const () as usize,
        },
        FunctionImpl {
            name: "GetFileInformationByHandle",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetFileInformationByHandle as *const ()
                as usize,
        },
        FunctionImpl {
            name: "GetFileType",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetFileType as *const () as usize,
        },
        FunctionImpl {
            name: "GetFullPathNameW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetFullPathNameW as *const () as usize,
        },
        FunctionImpl {
            name: "GetLastError",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetLastError as *const () as usize,
        },
        FunctionImpl {
            name: "GetModuleHandleW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetModuleHandleW as *const () as usize,
        },
        FunctionImpl {
            name: "GetProcAddress",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetProcAddress as *const () as usize,
        },
        FunctionImpl {
            name: "GetQueuedCompletionStatus",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_GetQueuedCompletionStatus as *const () as usize,
        },
        FunctionImpl {
            name: "GetQueuedCompletionStatusEx",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_GetQueuedCompletionStatusEx as *const ()
                as usize,
        },
        FunctionImpl {
            name: "GetStdHandle",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetStdHandle as *const () as usize,
        },
        FunctionImpl {
            name: "LoadLibraryA",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_LoadLibraryA as *const () as usize,
        },
        FunctionImpl {
            name: "LoadLibraryW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_LoadLibraryW as *const () as usize,
        },
        FunctionImpl {
            name: "SetConsoleCtrlHandler",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_SetConsoleCtrlHandler as *const () as usize,
        },
        FunctionImpl {
            name: "SetFilePointerEx",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_SetFilePointerEx as *const () as usize,
        },
        FunctionImpl {
            name: "SetLastError",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SetLastError as *const () as usize,
        },
        FunctionImpl {
            name: "WaitForSingleObject",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_WaitForSingleObject as *const () as usize,
        },
        FunctionImpl {
            name: "WaitForSingleObjectEx",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_WaitForSingleObjectEx as *const () as usize,
        },
        FunctionImpl {
            name: "WriteConsoleW",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_WriteConsoleW as *const () as usize,
        },
        FunctionImpl {
            name: "WriteConsoleA",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_WriteConsoleA as *const () as usize,
        },
        FunctionImpl {
            name: "GetFileInformationByHandleEx",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetFileInformationByHandleEx as *const ()
                as usize,
        },
        FunctionImpl {
            name: "GetFileSizeEx",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetFileSizeEx as *const () as usize,
        },
        FunctionImpl {
            name: "GetFinalPathNameByHandleW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetFinalPathNameByHandleW as *const () as usize,
        },
        FunctionImpl {
            name: "GetOverlappedResult",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetOverlappedResult as *const () as usize,
        },
        FunctionImpl {
            name: "GetProcessId",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetProcessId as *const () as usize,
        },
        FunctionImpl {
            name: "GetSystemDirectoryW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetSystemDirectoryW as *const () as usize,
        },
        FunctionImpl {
            name: "GetTempPathW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetTempPathW as *const () as usize,
        },
        FunctionImpl {
            name: "GetTempPathA",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetTempPathA as *const () as usize,
        },
        FunctionImpl {
            name: "GetWindowsDirectoryW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetWindowsDirectoryW as *const () as usize,
        },
        FunctionImpl {
            name: "InitOnceBeginInitialize",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_InitOnceBeginInitialize as *const () as usize,
        },
        FunctionImpl {
            name: "InitOnceComplete",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_InitOnceComplete as *const () as usize,
        },
        FunctionImpl {
            name: "InitializeProcThreadAttributeList",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_InitializeProcThreadAttributeList as *const ()
                as usize,
        },
        FunctionImpl {
            name: "LockFileEx",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_LockFileEx as *const () as usize,
        },
        FunctionImpl {
            name: "MapViewOfFile",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_MapViewOfFile as *const () as usize,
        },
        FunctionImpl {
            name: "Module32FirstW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_Module32FirstW as *const () as usize,
        },
        FunctionImpl {
            name: "Module32NextW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_Module32NextW as *const () as usize,
        },
        FunctionImpl {
            name: "MoveFileExW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_MoveFileExW as *const () as usize,
        },
        FunctionImpl {
            name: "ReadFileEx",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_ReadFileEx as *const () as usize,
        },
        FunctionImpl {
            name: "RemoveDirectoryW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_RemoveDirectoryW as *const () as usize,
        },
        FunctionImpl {
            name: "SetCurrentDirectoryW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SetCurrentDirectoryW as *const () as usize,
        },
        FunctionImpl {
            name: "SetFileAttributesW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_SetFileAttributesW as *const () as usize,
        },
        FunctionImpl {
            name: "SetFileInformationByHandle",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_SetFileInformationByHandle as *const ()
                as usize,
        },
        FunctionImpl {
            name: "SetFileTime",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_SetFileTime as *const () as usize,
        },
        FunctionImpl {
            name: "SetHandleInformation",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_SetHandleInformation as *const () as usize,
        },
        FunctionImpl {
            name: "UnlockFile",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_UnlockFile as *const () as usize,
        },
        FunctionImpl {
            name: "UnmapViewOfFile",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_UnmapViewOfFile as *const () as usize,
        },
        FunctionImpl {
            name: "UpdateProcThreadAttribute",
            dll_name: "KERNEL32.dll",
            num_params: 7,
            impl_address: crate::kernel32::kernel32_UpdateProcThreadAttribute as *const () as usize,
        },
        FunctionImpl {
            name: "WriteFileEx",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_WriteFileEx as *const () as usize,
        },
        FunctionImpl {
            name: "SetThreadStackGuarantee",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SetThreadStackGuarantee as *const () as usize,
        },
        FunctionImpl {
            name: "SetWaitableTimer",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_SetWaitableTimer as *const () as usize,
        },
        FunctionImpl {
            name: "SleepEx",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_SleepEx as *const () as usize,
        },
        FunctionImpl {
            name: "SwitchToThread",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_SwitchToThread as *const () as usize,
        },
        FunctionImpl {
            name: "TerminateProcess",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_TerminateProcess as *const () as usize,
        },
        FunctionImpl {
            name: "WaitForMultipleObjects",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_WaitForMultipleObjects as *const () as usize,
        },
        FunctionImpl {
            name: "GetCommandLineW",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetCommandLineW as *const () as usize,
        },
        FunctionImpl {
            name: "GetEnvironmentStringsW",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetEnvironmentStringsW as *const () as usize,
        },
        FunctionImpl {
            name: "FreeEnvironmentStringsW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_FreeEnvironmentStringsW as *const () as usize,
        },
        FunctionImpl {
            name: "ExitProcess",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_ExitProcess as *const () as usize,
        },
        FunctionImpl {
            name: "GetCurrentProcess",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetCurrentProcess as *const () as usize,
        },
        FunctionImpl {
            name: "GetCurrentThread",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetCurrentThread as *const () as usize,
        },
        FunctionImpl {
            name: "GetModuleHandleA",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetModuleHandleA as *const () as usize,
        },
        FunctionImpl {
            name: "GetModuleFileNameW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_GetModuleFileNameW as *const () as usize,
        },
        FunctionImpl {
            name: "GetSystemInfo",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetSystemInfo as *const () as usize,
        },
        FunctionImpl {
            name: "GetConsoleMode",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetConsoleMode as *const () as usize,
        },
        FunctionImpl {
            name: "GetConsoleOutputCP",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetConsoleOutputCP as *const () as usize,
        },
        FunctionImpl {
            name: "ReadConsoleW",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_ReadConsoleW as *const () as usize,
        },
        FunctionImpl {
            name: "GetEnvironmentVariableW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_GetEnvironmentVariableW as *const () as usize,
        },
        FunctionImpl {
            name: "SetEnvironmentVariableW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_SetEnvironmentVariableW as *const () as usize,
        },
        FunctionImpl {
            name: "VirtualProtect",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_VirtualProtect as *const () as usize,
        },
        FunctionImpl {
            name: "VirtualQuery",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_VirtualQuery as *const () as usize,
        },
        FunctionImpl {
            name: "FreeLibrary",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_FreeLibrary as *const () as usize,
        },
        FunctionImpl {
            name: "FindFirstFileW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_FindFirstFileW as *const () as usize,
        },
        FunctionImpl {
            name: "FindFirstFileExW",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_FindFirstFileExW as *const () as usize,
        },
        FunctionImpl {
            name: "FindNextFileW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_FindNextFileW as *const () as usize,
        },
        FunctionImpl {
            name: "FindClose",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_FindClose as *const () as usize,
        },
        FunctionImpl {
            name: "WaitOnAddress",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_WaitOnAddress as *const () as usize,
        },
        FunctionImpl {
            name: "WakeByAddressAll",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_WakeByAddressAll as *const () as usize,
        },
        FunctionImpl {
            name: "WakeByAddressSingle",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_WakeByAddressSingle as *const () as usize,
        },
        // Phase 10: Additional MSVCRT functions
        FunctionImpl {
            name: "strcmp",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_strcmp as *const () as usize,
        },
        FunctionImpl {
            name: "strcpy",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_strcpy as *const () as usize,
        },
        FunctionImpl {
            name: "strcat",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_strcat as *const () as usize,
        },
        FunctionImpl {
            name: "strchr",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_strchr as *const () as usize,
        },
        FunctionImpl {
            name: "strrchr",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_strrchr as *const () as usize,
        },
        FunctionImpl {
            name: "strstr",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_strstr as *const () as usize,
        },
        FunctionImpl {
            name: "_initterm_e",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__initterm_e as *const () as usize,
        },
        FunctionImpl {
            name: "__p___argc",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt___p___argc as *const () as usize,
        },
        FunctionImpl {
            name: "__p___argv",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt___p___argv as *const () as usize,
        },
        FunctionImpl {
            name: "_lock",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__lock as *const () as usize,
        },
        FunctionImpl {
            name: "_unlock",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__unlock as *const () as usize,
        },
        FunctionImpl {
            name: "getenv",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_getenv as *const () as usize,
        },
        FunctionImpl {
            name: "_errno",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt__errno as *const () as usize,
        },
        FunctionImpl {
            name: "__lconv_init",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt___lconv_init as *const () as usize,
        },
        FunctionImpl {
            name: "_XcptFilter",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__XcptFilter as *const () as usize,
        },
        FunctionImpl {
            name: "_controlfp",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__controlfp as *const () as usize,
        },
        // Phase 10: Additional KERNEL32 functions
        FunctionImpl {
            name: "GetACP",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetACP as *const () as usize,
        },
        FunctionImpl {
            name: "IsProcessorFeaturePresent",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_IsProcessorFeaturePresent as *const () as usize,
        },
        FunctionImpl {
            name: "IsDebuggerPresent",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_IsDebuggerPresent as *const () as usize,
        },
        FunctionImpl {
            name: "GetStringTypeW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetStringTypeW as *const () as usize,
        },
        FunctionImpl {
            name: "HeapSize",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_HeapSize as *const () as usize,
        },
        FunctionImpl {
            name: "InitializeCriticalSectionAndSpinCount",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_InitializeCriticalSectionAndSpinCount
                as *const () as usize,
        },
        FunctionImpl {
            name: "InitializeCriticalSectionEx",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_InitializeCriticalSectionEx as *const ()
                as usize,
        },
        FunctionImpl {
            name: "FlsAlloc",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_FlsAlloc as *const () as usize,
        },
        FunctionImpl {
            name: "FlsFree",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_FlsFree as *const () as usize,
        },
        FunctionImpl {
            name: "FlsGetValue",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_FlsGetValue as *const () as usize,
        },
        FunctionImpl {
            name: "FlsSetValue",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_FlsSetValue as *const () as usize,
        },
        FunctionImpl {
            name: "IsValidCodePage",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_IsValidCodePage as *const () as usize,
        },
        FunctionImpl {
            name: "GetOEMCP",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetOEMCP as *const () as usize,
        },
        FunctionImpl {
            name: "GetCPInfo",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetCPInfo as *const () as usize,
        },
        FunctionImpl {
            name: "GetLocaleInfoW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetLocaleInfoW as *const () as usize,
        },
        FunctionImpl {
            name: "LCMapStringW",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_LCMapStringW as *const () as usize,
        },
        FunctionImpl {
            name: "VirtualAlloc",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_VirtualAlloc as *const () as usize,
        },
        FunctionImpl {
            name: "VirtualFree",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_VirtualFree as *const () as usize,
        },
        FunctionImpl {
            name: "DecodePointer",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_DecodePointer as *const () as usize,
        },
        FunctionImpl {
            name: "EncodePointer",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_EncodePointer as *const () as usize,
        },
        FunctionImpl {
            name: "GetTickCount64",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetTickCount64 as *const () as usize,
        },
        FunctionImpl {
            name: "SetEvent",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SetEvent as *const () as usize,
        },
        FunctionImpl {
            name: "ResetEvent",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_ResetEvent as *const () as usize,
        },
        FunctionImpl {
            name: "IsDBCSLeadByteEx",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_IsDBCSLeadByteEx as *const () as usize,
        },
        // NTDLL.dll functions
        FunctionImpl {
            name: "NtWriteFile",
            dll_name: "NTDLL.dll",
            num_params: 9,
            impl_address: crate::ntdll_impl::ntdll_NtWriteFile as *const () as usize,
        },
        FunctionImpl {
            name: "NtReadFile",
            dll_name: "NTDLL.dll",
            num_params: 9,
            impl_address: crate::ntdll_impl::ntdll_NtReadFile as *const () as usize,
        },
        FunctionImpl {
            name: "NtCreateFile",
            dll_name: "NTDLL.dll",
            num_params: 11,
            impl_address: crate::ntdll_impl::ntdll_NtCreateFile as *const () as usize,
        },
        FunctionImpl {
            name: "NtOpenFile",
            dll_name: "NTDLL.dll",
            num_params: 6,
            impl_address: crate::ntdll_impl::ntdll_NtOpenFile as *const () as usize,
        },
        FunctionImpl {
            name: "NtClose",
            dll_name: "NTDLL.dll",
            num_params: 1,
            impl_address: crate::ntdll_impl::ntdll_NtClose as *const () as usize,
        },
        FunctionImpl {
            name: "NtAllocateVirtualMemory",
            dll_name: "NTDLL.dll",
            num_params: 6,
            impl_address: crate::ntdll_impl::ntdll_NtAllocateVirtualMemory as *const () as usize,
        },
        FunctionImpl {
            name: "NtFreeVirtualMemory",
            dll_name: "NTDLL.dll",
            num_params: 4,
            impl_address: crate::ntdll_impl::ntdll_NtFreeVirtualMemory as *const () as usize,
        },
        FunctionImpl {
            name: "NtCreateNamedPipeFile",
            dll_name: "NTDLL.dll",
            num_params: 14,
            impl_address: crate::ntdll_impl::ntdll_NtCreateNamedPipeFile as *const () as usize,
        },
        FunctionImpl {
            name: "RtlNtStatusToDosError",
            dll_name: "NTDLL.dll",
            num_params: 1,
            impl_address: crate::ntdll_impl::ntdll_RtlNtStatusToDosError as *const () as usize,
        },
        FunctionImpl {
            name: "RtlPcToFileHeader",
            dll_name: "NTDLL.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_RtlPcToFileHeader as *const () as usize,
        },
        // WS2_32.dll — Windows Sockets 2
        FunctionImpl {
            name: "WSAStartup",
            dll_name: "WS2_32.dll",
            num_params: 2,
            impl_address: crate::ws2_32::ws2_WSAStartup as *const () as usize,
        },
        FunctionImpl {
            name: "WSACleanup",
            dll_name: "WS2_32.dll",
            num_params: 0,
            impl_address: crate::ws2_32::ws2_WSACleanup as *const () as usize,
        },
        FunctionImpl {
            name: "WSAGetLastError",
            dll_name: "WS2_32.dll",
            num_params: 0,
            impl_address: crate::ws2_32::ws2_WSAGetLastError as *const () as usize,
        },
        FunctionImpl {
            name: "WSASetLastError",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_WSASetLastError as *const () as usize,
        },
        FunctionImpl {
            name: "socket",
            dll_name: "WS2_32.dll",
            num_params: 3,
            impl_address: crate::ws2_32::ws2_socket as *const () as usize,
        },
        FunctionImpl {
            name: "WSASocketW",
            dll_name: "WS2_32.dll",
            num_params: 6,
            impl_address: crate::ws2_32::ws2_WSASocketW as *const () as usize,
        },
        FunctionImpl {
            name: "closesocket",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_closesocket as *const () as usize,
        },
        FunctionImpl {
            name: "bind",
            dll_name: "WS2_32.dll",
            num_params: 3,
            impl_address: crate::ws2_32::ws2_bind as *const () as usize,
        },
        FunctionImpl {
            name: "listen",
            dll_name: "WS2_32.dll",
            num_params: 2,
            impl_address: crate::ws2_32::ws2_listen as *const () as usize,
        },
        FunctionImpl {
            name: "accept",
            dll_name: "WS2_32.dll",
            num_params: 3,
            impl_address: crate::ws2_32::ws2_accept as *const () as usize,
        },
        FunctionImpl {
            name: "connect",
            dll_name: "WS2_32.dll",
            num_params: 3,
            impl_address: crate::ws2_32::ws2_connect as *const () as usize,
        },
        FunctionImpl {
            name: "send",
            dll_name: "WS2_32.dll",
            num_params: 4,
            impl_address: crate::ws2_32::ws2_send as *const () as usize,
        },
        FunctionImpl {
            name: "recv",
            dll_name: "WS2_32.dll",
            num_params: 4,
            impl_address: crate::ws2_32::ws2_recv as *const () as usize,
        },
        FunctionImpl {
            name: "sendto",
            dll_name: "WS2_32.dll",
            num_params: 6,
            impl_address: crate::ws2_32::ws2_sendto as *const () as usize,
        },
        FunctionImpl {
            name: "recvfrom",
            dll_name: "WS2_32.dll",
            num_params: 6,
            impl_address: crate::ws2_32::ws2_recvfrom as *const () as usize,
        },
        FunctionImpl {
            name: "WSASend",
            dll_name: "WS2_32.dll",
            num_params: 7,
            impl_address: crate::ws2_32::ws2_WSASend as *const () as usize,
        },
        FunctionImpl {
            name: "WSARecv",
            dll_name: "WS2_32.dll",
            num_params: 7,
            impl_address: crate::ws2_32::ws2_WSARecv as *const () as usize,
        },
        FunctionImpl {
            name: "getsockname",
            dll_name: "WS2_32.dll",
            num_params: 3,
            impl_address: crate::ws2_32::ws2_getsockname as *const () as usize,
        },
        FunctionImpl {
            name: "getpeername",
            dll_name: "WS2_32.dll",
            num_params: 3,
            impl_address: crate::ws2_32::ws2_getpeername as *const () as usize,
        },
        FunctionImpl {
            name: "getsockopt",
            dll_name: "WS2_32.dll",
            num_params: 5,
            impl_address: crate::ws2_32::ws2_getsockopt as *const () as usize,
        },
        FunctionImpl {
            name: "setsockopt",
            dll_name: "WS2_32.dll",
            num_params: 5,
            impl_address: crate::ws2_32::ws2_setsockopt as *const () as usize,
        },
        FunctionImpl {
            name: "ioctlsocket",
            dll_name: "WS2_32.dll",
            num_params: 3,
            impl_address: crate::ws2_32::ws2_ioctlsocket as *const () as usize,
        },
        FunctionImpl {
            name: "shutdown",
            dll_name: "WS2_32.dll",
            num_params: 2,
            impl_address: crate::ws2_32::ws2_shutdown as *const () as usize,
        },
        FunctionImpl {
            name: "select",
            dll_name: "WS2_32.dll",
            num_params: 5,
            impl_address: crate::ws2_32::ws2_select as *const () as usize,
        },
        FunctionImpl {
            name: "getaddrinfo",
            dll_name: "WS2_32.dll",
            num_params: 4,
            impl_address: crate::ws2_32::ws2_getaddrinfo as *const () as usize,
        },
        FunctionImpl {
            name: "freeaddrinfo",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_freeaddrinfo as *const () as usize,
        },
        FunctionImpl {
            name: "GetHostNameW",
            dll_name: "WS2_32.dll",
            num_params: 2,
            impl_address: crate::ws2_32::ws2_GetHostNameW as *const () as usize,
        },
        FunctionImpl {
            name: "WSADuplicateSocketW",
            dll_name: "WS2_32.dll",
            num_params: 3,
            impl_address: crate::ws2_32::ws2_WSADuplicateSocketW as *const () as usize,
        },
        FunctionImpl {
            name: "htons",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_htons as *const () as usize,
        },
        FunctionImpl {
            name: "htonl",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_htonl as *const () as usize,
        },
        FunctionImpl {
            name: "ntohs",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_ntohs as *const () as usize,
        },
        FunctionImpl {
            name: "ntohl",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_ntohl as *const () as usize,
        },
        FunctionImpl {
            name: "__WSAFDIsSet",
            dll_name: "WS2_32.dll",
            num_params: 2,
            impl_address: crate::ws2_32::ws2___WSAFDIsSet as *const () as usize,
        },
        // Phase 40: WSA events and gethostbyname
        FunctionImpl {
            name: "WSACreateEvent",
            dll_name: "WS2_32.dll",
            num_params: 0,
            impl_address: crate::ws2_32::ws2_WSACreateEvent as *const () as usize,
        },
        FunctionImpl {
            name: "WSACloseEvent",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_WSACloseEvent as *const () as usize,
        },
        FunctionImpl {
            name: "WSAResetEvent",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_WSAResetEvent as *const () as usize,
        },
        FunctionImpl {
            name: "WSASetEvent",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_WSASetEvent as *const () as usize,
        },
        FunctionImpl {
            name: "WSAEventSelect",
            dll_name: "WS2_32.dll",
            num_params: 3,
            impl_address: crate::ws2_32::ws2_WSAEventSelect as *const () as usize,
        },
        FunctionImpl {
            name: "WSAEnumNetworkEvents",
            dll_name: "WS2_32.dll",
            num_params: 3,
            impl_address: crate::ws2_32::ws2_WSAEnumNetworkEvents as *const () as usize,
        },
        FunctionImpl {
            name: "WSAWaitForMultipleEvents",
            dll_name: "WS2_32.dll",
            num_params: 5,
            impl_address: crate::ws2_32::ws2_WSAWaitForMultipleEvents as *const () as usize,
        },
        FunctionImpl {
            name: "gethostbyname",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_gethostbyname as *const () as usize,
        },
        // Phase 41: WSAAsyncSelect
        FunctionImpl {
            name: "WSAAsyncSelect",
            dll_name: "WS2_32.dll",
            num_params: 4,
            impl_address: crate::ws2_32::ws2_WSAAsyncSelect as *const () as usize,
        },
        // USER32.dll — Windows GUI (headless stubs)
        FunctionImpl {
            name: "MessageBoxW",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_MessageBoxW as *const () as usize,
        },
        FunctionImpl {
            name: "RegisterClassExW",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_RegisterClassExW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateWindowExW",
            dll_name: "USER32.dll",
            num_params: 12,
            impl_address: crate::user32::user32_CreateWindowExW as *const () as usize,
        },
        FunctionImpl {
            name: "ShowWindow",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_ShowWindow as *const () as usize,
        },
        FunctionImpl {
            name: "UpdateWindow",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_UpdateWindow as *const () as usize,
        },
        FunctionImpl {
            name: "GetMessageW",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_GetMessageW as *const () as usize,
        },
        FunctionImpl {
            name: "TranslateMessage",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_TranslateMessage as *const () as usize,
        },
        FunctionImpl {
            name: "DispatchMessageW",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_DispatchMessageW as *const () as usize,
        },
        FunctionImpl {
            name: "DestroyWindow",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_DestroyWindow as *const () as usize,
        },
        FunctionImpl {
            name: "PostQuitMessage",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_PostQuitMessage as *const () as usize,
        },
        FunctionImpl {
            name: "DefWindowProcW",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_DefWindowProcW as *const () as usize,
        },
        FunctionImpl {
            name: "LoadCursorW",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_LoadCursorW as *const () as usize,
        },
        FunctionImpl {
            name: "LoadIconW",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_LoadIconW as *const () as usize,
        },
        FunctionImpl {
            name: "GetSystemMetrics",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_GetSystemMetrics as *const () as usize,
        },
        FunctionImpl {
            name: "SetWindowLongPtrW",
            dll_name: "USER32.dll",
            num_params: 3,
            impl_address: crate::user32::user32_SetWindowLongPtrW as *const () as usize,
        },
        FunctionImpl {
            name: "GetWindowLongPtrW",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_GetWindowLongPtrW as *const () as usize,
        },
        FunctionImpl {
            name: "SendMessageW",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_SendMessageW as *const () as usize,
        },
        FunctionImpl {
            name: "PostMessageW",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_PostMessageW as *const () as usize,
        },
        FunctionImpl {
            name: "PeekMessageW",
            dll_name: "USER32.dll",
            num_params: 5,
            impl_address: crate::user32::user32_PeekMessageW as *const () as usize,
        },
        FunctionImpl {
            name: "BeginPaint",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_BeginPaint as *const () as usize,
        },
        FunctionImpl {
            name: "EndPaint",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_EndPaint as *const () as usize,
        },
        FunctionImpl {
            name: "GetClientRect",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_GetClientRect as *const () as usize,
        },
        FunctionImpl {
            name: "InvalidateRect",
            dll_name: "USER32.dll",
            num_params: 3,
            impl_address: crate::user32::user32_InvalidateRect as *const () as usize,
        },
        FunctionImpl {
            name: "SetTimer",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_SetTimer as *const () as usize,
        },
        FunctionImpl {
            name: "KillTimer",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_KillTimer as *const () as usize,
        },
        FunctionImpl {
            name: "GetDC",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_GetDC as *const () as usize,
        },
        FunctionImpl {
            name: "ReleaseDC",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_ReleaseDC as *const () as usize,
        },
        // ADVAPI32.dll — Windows Registry (in-memory implementation)
        FunctionImpl {
            name: "RegOpenKeyExW",
            dll_name: "ADVAPI32.dll",
            num_params: 5,
            impl_address: crate::advapi32::advapi32_RegOpenKeyExW as *const () as usize,
        },
        FunctionImpl {
            name: "RegCreateKeyExW",
            dll_name: "ADVAPI32.dll",
            num_params: 9,
            impl_address: crate::advapi32::advapi32_RegCreateKeyExW as *const () as usize,
        },
        FunctionImpl {
            name: "RegCloseKey",
            dll_name: "ADVAPI32.dll",
            num_params: 1,
            impl_address: crate::advapi32::advapi32_RegCloseKey as *const () as usize,
        },
        FunctionImpl {
            name: "RegQueryValueExW",
            dll_name: "ADVAPI32.dll",
            num_params: 6,
            impl_address: crate::advapi32::advapi32_RegQueryValueExW as *const () as usize,
        },
        FunctionImpl {
            name: "RegSetValueExW",
            dll_name: "ADVAPI32.dll",
            num_params: 6,
            impl_address: crate::advapi32::advapi32_RegSetValueExW as *const () as usize,
        },
        FunctionImpl {
            name: "RegDeleteValueW",
            dll_name: "ADVAPI32.dll",
            num_params: 2,
            impl_address: crate::advapi32::advapi32_RegDeleteValueW as *const () as usize,
        },
        FunctionImpl {
            name: "RegEnumKeyExW",
            dll_name: "ADVAPI32.dll",
            num_params: 8,
            impl_address: crate::advapi32::advapi32_RegEnumKeyExW as *const () as usize,
        },
        FunctionImpl {
            name: "RegEnumValueW",
            dll_name: "ADVAPI32.dll",
            num_params: 8,
            impl_address: crate::advapi32::advapi32_RegEnumValueW as *const () as usize,
        },
        // ADVAPI32 — User name
        FunctionImpl {
            name: "GetUserNameW",
            dll_name: "ADVAPI32.dll",
            num_params: 2,
            impl_address: crate::advapi32::advapi32_GetUserNameW as *const () as usize,
        },
        FunctionImpl {
            name: "GetUserNameA",
            dll_name: "ADVAPI32.dll",
            num_params: 2,
            impl_address: crate::advapi32::advapi32_GetUserNameA as *const () as usize,
        },
        // GDI32.dll — Windows GDI graphics (headless stubs)
        FunctionImpl {
            name: "GetStockObject",
            dll_name: "GDI32.dll",
            num_params: 1,
            impl_address: crate::gdi32::gdi32_GetStockObject as *const () as usize,
        },
        FunctionImpl {
            name: "CreateSolidBrush",
            dll_name: "GDI32.dll",
            num_params: 1,
            impl_address: crate::gdi32::gdi32_CreateSolidBrush as *const () as usize,
        },
        FunctionImpl {
            name: "DeleteObject",
            dll_name: "GDI32.dll",
            num_params: 1,
            impl_address: crate::gdi32::gdi32_DeleteObject as *const () as usize,
        },
        FunctionImpl {
            name: "SelectObject",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_SelectObject as *const () as usize,
        },
        FunctionImpl {
            name: "CreateCompatibleDC",
            dll_name: "GDI32.dll",
            num_params: 1,
            impl_address: crate::gdi32::gdi32_CreateCompatibleDC as *const () as usize,
        },
        FunctionImpl {
            name: "DeleteDC",
            dll_name: "GDI32.dll",
            num_params: 1,
            impl_address: crate::gdi32::gdi32_DeleteDC as *const () as usize,
        },
        FunctionImpl {
            name: "SetBkColor",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_SetBkColor as *const () as usize,
        },
        FunctionImpl {
            name: "SetTextColor",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_SetTextColor as *const () as usize,
        },
        FunctionImpl {
            name: "TextOutW",
            dll_name: "GDI32.dll",
            num_params: 5,
            impl_address: crate::gdi32::gdi32_TextOutW as *const () as usize,
        },
        FunctionImpl {
            name: "Rectangle",
            dll_name: "GDI32.dll",
            num_params: 5,
            impl_address: crate::gdi32::gdi32_Rectangle as *const () as usize,
        },
        FunctionImpl {
            name: "FillRect",
            dll_name: "GDI32.dll",
            num_params: 3,
            impl_address: crate::gdi32::gdi32_FillRect as *const () as usize,
        },
        FunctionImpl {
            name: "CreateFontW",
            dll_name: "GDI32.dll",
            num_params: 14,
            impl_address: crate::gdi32::gdi32_CreateFontW as *const () as usize,
        },
        FunctionImpl {
            name: "GetTextExtentPoint32W",
            dll_name: "GDI32.dll",
            num_params: 4,
            impl_address: crate::gdi32::gdi32_GetTextExtentPoint32W as *const () as usize,
        },
        // GDI32 — Phase 45: Extended graphics primitives
        FunctionImpl {
            name: "GetDeviceCaps",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_GetDeviceCaps as *const () as usize,
        },
        FunctionImpl {
            name: "SetBkMode",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_SetBkMode as *const () as usize,
        },
        FunctionImpl {
            name: "SetMapMode",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_SetMapMode as *const () as usize,
        },
        FunctionImpl {
            name: "SetViewportOrgEx",
            dll_name: "GDI32.dll",
            num_params: 4,
            impl_address: crate::gdi32::gdi32_SetViewportOrgEx as *const () as usize,
        },
        FunctionImpl {
            name: "CreatePen",
            dll_name: "GDI32.dll",
            num_params: 3,
            impl_address: crate::gdi32::gdi32_CreatePen as *const () as usize,
        },
        FunctionImpl {
            name: "CreatePenIndirect",
            dll_name: "GDI32.dll",
            num_params: 1,
            impl_address: crate::gdi32::gdi32_CreatePenIndirect as *const () as usize,
        },
        FunctionImpl {
            name: "CreateBrushIndirect",
            dll_name: "GDI32.dll",
            num_params: 1,
            impl_address: crate::gdi32::gdi32_CreateBrushIndirect as *const () as usize,
        },
        FunctionImpl {
            name: "CreatePatternBrush",
            dll_name: "GDI32.dll",
            num_params: 1,
            impl_address: crate::gdi32::gdi32_CreatePatternBrush as *const () as usize,
        },
        FunctionImpl {
            name: "CreateHatchBrush",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_CreateHatchBrush as *const () as usize,
        },
        FunctionImpl {
            name: "CreateBitmap",
            dll_name: "GDI32.dll",
            num_params: 5,
            impl_address: crate::gdi32::gdi32_CreateBitmap as *const () as usize,
        },
        FunctionImpl {
            name: "CreateCompatibleBitmap",
            dll_name: "GDI32.dll",
            num_params: 3,
            impl_address: crate::gdi32::gdi32_CreateCompatibleBitmap as *const () as usize,
        },
        FunctionImpl {
            name: "CreateDIBSection",
            dll_name: "GDI32.dll",
            num_params: 6,
            impl_address: crate::gdi32::gdi32_CreateDIBSection as *const () as usize,
        },
        FunctionImpl {
            name: "GetDIBits",
            dll_name: "GDI32.dll",
            num_params: 7,
            impl_address: crate::gdi32::gdi32_GetDIBits as *const () as usize,
        },
        FunctionImpl {
            name: "SetDIBits",
            dll_name: "GDI32.dll",
            num_params: 7,
            impl_address: crate::gdi32::gdi32_SetDIBits as *const () as usize,
        },
        FunctionImpl {
            name: "BitBlt",
            dll_name: "GDI32.dll",
            num_params: 9,
            impl_address: crate::gdi32::gdi32_BitBlt as *const () as usize,
        },
        FunctionImpl {
            name: "StretchBlt",
            dll_name: "GDI32.dll",
            num_params: 11,
            impl_address: crate::gdi32::gdi32_StretchBlt as *const () as usize,
        },
        FunctionImpl {
            name: "PatBlt",
            dll_name: "GDI32.dll",
            num_params: 6,
            impl_address: crate::gdi32::gdi32_PatBlt as *const () as usize,
        },
        FunctionImpl {
            name: "GetPixel",
            dll_name: "GDI32.dll",
            num_params: 3,
            impl_address: crate::gdi32::gdi32_GetPixel as *const () as usize,
        },
        FunctionImpl {
            name: "SetPixel",
            dll_name: "GDI32.dll",
            num_params: 4,
            impl_address: crate::gdi32::gdi32_SetPixel as *const () as usize,
        },
        FunctionImpl {
            name: "MoveToEx",
            dll_name: "GDI32.dll",
            num_params: 4,
            impl_address: crate::gdi32::gdi32_MoveToEx as *const () as usize,
        },
        FunctionImpl {
            name: "LineTo",
            dll_name: "GDI32.dll",
            num_params: 3,
            impl_address: crate::gdi32::gdi32_LineTo as *const () as usize,
        },
        FunctionImpl {
            name: "Polyline",
            dll_name: "GDI32.dll",
            num_params: 3,
            impl_address: crate::gdi32::gdi32_Polyline as *const () as usize,
        },
        FunctionImpl {
            name: "Polygon",
            dll_name: "GDI32.dll",
            num_params: 3,
            impl_address: crate::gdi32::gdi32_Polygon as *const () as usize,
        },
        FunctionImpl {
            name: "Ellipse",
            dll_name: "GDI32.dll",
            num_params: 5,
            impl_address: crate::gdi32::gdi32_Ellipse as *const () as usize,
        },
        FunctionImpl {
            name: "Arc",
            dll_name: "GDI32.dll",
            num_params: 9,
            impl_address: crate::gdi32::gdi32_Arc as *const () as usize,
        },
        FunctionImpl {
            name: "RoundRect",
            dll_name: "GDI32.dll",
            num_params: 7,
            impl_address: crate::gdi32::gdi32_RoundRect as *const () as usize,
        },
        FunctionImpl {
            name: "GetTextMetricsW",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_GetTextMetricsW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateRectRgn",
            dll_name: "GDI32.dll",
            num_params: 4,
            impl_address: crate::gdi32::gdi32_CreateRectRgn as *const () as usize,
        },
        FunctionImpl {
            name: "SelectClipRgn",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_SelectClipRgn as *const () as usize,
        },
        FunctionImpl {
            name: "GetClipBox",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_GetClipBox as *const () as usize,
        },
        FunctionImpl {
            name: "SetStretchBltMode",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_SetStretchBltMode as *const () as usize,
        },
        FunctionImpl {
            name: "GetObjectW",
            dll_name: "GDI32.dll",
            num_params: 3,
            impl_address: crate::gdi32::gdi32_GetObjectW as *const () as usize,
        },
        FunctionImpl {
            name: "GetCurrentObject",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_GetCurrentObject as *const () as usize,
        },
        FunctionImpl {
            name: "ExcludeClipRect",
            dll_name: "GDI32.dll",
            num_params: 5,
            impl_address: crate::gdi32::gdi32_ExcludeClipRect as *const () as usize,
        },
        FunctionImpl {
            name: "IntersectClipRect",
            dll_name: "GDI32.dll",
            num_params: 5,
            impl_address: crate::gdi32::gdi32_IntersectClipRect as *const () as usize,
        },
        FunctionImpl {
            name: "SaveDC",
            dll_name: "GDI32.dll",
            num_params: 1,
            impl_address: crate::gdi32::gdi32_SaveDC as *const () as usize,
        },
        FunctionImpl {
            name: "RestoreDC",
            dll_name: "GDI32.dll",
            num_params: 2,
            impl_address: crate::gdi32::gdi32_RestoreDC as *const () as usize,
        },
        // KERNEL32 — Time APIs
        FunctionImpl {
            name: "GetSystemTime",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetSystemTime as *const () as usize,
        },
        FunctionImpl {
            name: "GetLocalTime",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetLocalTime as *const () as usize,
        },
        FunctionImpl {
            name: "SystemTimeToFileTime",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_SystemTimeToFileTime as *const () as usize,
        },
        FunctionImpl {
            name: "FileTimeToSystemTime",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_FileTimeToSystemTime as *const () as usize,
        },
        FunctionImpl {
            name: "GetTickCount",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetTickCount as *const () as usize,
        },
        // KERNEL32 — Local memory management
        FunctionImpl {
            name: "LocalAlloc",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_LocalAlloc as *const () as usize,
        },
        FunctionImpl {
            name: "LocalFree",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_LocalFree as *const () as usize,
        },
        // KERNEL32 — Interlocked atomic operations
        FunctionImpl {
            name: "InterlockedIncrement",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_InterlockedIncrement as *const () as usize,
        },
        FunctionImpl {
            name: "InterlockedDecrement",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_InterlockedDecrement as *const () as usize,
        },
        FunctionImpl {
            name: "InterlockedExchange",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_InterlockedExchange as *const () as usize,
        },
        FunctionImpl {
            name: "InterlockedExchangeAdd",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_InterlockedExchangeAdd as *const () as usize,
        },
        FunctionImpl {
            name: "InterlockedCompareExchange",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_InterlockedCompareExchange as *const ()
                as usize,
        },
        FunctionImpl {
            name: "InterlockedCompareExchange64",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_InterlockedCompareExchange64 as *const ()
                as usize,
        },
        // KERNEL32 — System info
        FunctionImpl {
            name: "IsWow64Process",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_IsWow64Process as *const () as usize,
        },
        FunctionImpl {
            name: "GetNativeSystemInfo",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetNativeSystemInfo as *const () as usize,
        },
        // KERNEL32 — Phase 26: Mutex / Semaphore
        FunctionImpl {
            name: "CreateMutexW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_CreateMutexW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateMutexA",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_CreateMutexA as *const () as usize,
        },
        FunctionImpl {
            name: "OpenMutexW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_OpenMutexW as *const () as usize,
        },
        FunctionImpl {
            name: "ReleaseMutex",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_ReleaseMutex as *const () as usize,
        },
        FunctionImpl {
            name: "CreateSemaphoreW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_CreateSemaphoreW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateSemaphoreA",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_CreateSemaphoreA as *const () as usize,
        },
        FunctionImpl {
            name: "OpenSemaphoreW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_OpenSemaphoreW as *const () as usize,
        },
        FunctionImpl {
            name: "ReleaseSemaphore",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_ReleaseSemaphore as *const () as usize,
        },
        // KERNEL32 — Phase 26: Console Extensions
        FunctionImpl {
            name: "SetConsoleMode",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_SetConsoleMode as *const () as usize,
        },
        FunctionImpl {
            name: "SetConsoleTitleW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SetConsoleTitleW as *const () as usize,
        },
        FunctionImpl {
            name: "SetConsoleTitleA",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SetConsoleTitleA as *const () as usize,
        },
        FunctionImpl {
            name: "GetConsoleTitleW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetConsoleTitleW as *const () as usize,
        },
        FunctionImpl {
            name: "AllocConsole",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_AllocConsole as *const () as usize,
        },
        FunctionImpl {
            name: "FreeConsole",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_FreeConsole as *const () as usize,
        },
        FunctionImpl {
            name: "GetConsoleWindow",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetConsoleWindow as *const () as usize,
        },
        // KERNEL32 — Phase 26: String Utilities
        FunctionImpl {
            name: "lstrlenA",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_lstrlenA as *const () as usize,
        },
        FunctionImpl {
            name: "lstrcpyW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_lstrcpyW as *const () as usize,
        },
        FunctionImpl {
            name: "lstrcpyA",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_lstrcpyA as *const () as usize,
        },
        FunctionImpl {
            name: "lstrcmpW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_lstrcmpW as *const () as usize,
        },
        FunctionImpl {
            name: "lstrcmpA",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_lstrcmpA as *const () as usize,
        },
        FunctionImpl {
            name: "lstrcmpiW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_lstrcmpiW as *const () as usize,
        },
        FunctionImpl {
            name: "lstrcmpiA",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_lstrcmpiA as *const () as usize,
        },
        FunctionImpl {
            name: "OutputDebugStringW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_OutputDebugStringW as *const () as usize,
        },
        FunctionImpl {
            name: "OutputDebugStringA",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_OutputDebugStringA as *const () as usize,
        },
        // KERNEL32 — Phase 26: Drive / Volume APIs
        FunctionImpl {
            name: "GetDriveTypeW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetDriveTypeW as *const () as usize,
        },
        FunctionImpl {
            name: "GetLogicalDrives",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetLogicalDrives as *const () as usize,
        },
        FunctionImpl {
            name: "GetLogicalDriveStringsW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetLogicalDriveStringsW as *const () as usize,
        },
        FunctionImpl {
            name: "GetDiskFreeSpaceExW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetDiskFreeSpaceExW as *const () as usize,
        },
        FunctionImpl {
            name: "GetVolumeInformationW",
            dll_name: "KERNEL32.dll",
            num_params: 8,
            impl_address: crate::kernel32::kernel32_GetVolumeInformationW as *const () as usize,
        },
        // KERNEL32 — Phase 26: Computer Name
        FunctionImpl {
            name: "GetComputerNameW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetComputerNameW as *const () as usize,
        },
        FunctionImpl {
            name: "GetComputerNameExW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_GetComputerNameExW as *const () as usize,
        },
        // SHELL32.dll functions
        FunctionImpl {
            name: "CommandLineToArgvW",
            dll_name: "SHELL32.dll",
            num_params: 2,
            impl_address: crate::shell32::shell32_CommandLineToArgvW as *const () as usize,
        },
        FunctionImpl {
            name: "SHGetFolderPathW",
            dll_name: "SHELL32.dll",
            num_params: 5,
            impl_address: crate::shell32::shell32_SHGetFolderPathW as *const () as usize,
        },
        FunctionImpl {
            name: "ShellExecuteW",
            dll_name: "SHELL32.dll",
            num_params: 6,
            impl_address: crate::shell32::shell32_ShellExecuteW as *const () as usize,
        },
        FunctionImpl {
            name: "SHCreateDirectoryExW",
            dll_name: "SHELL32.dll",
            num_params: 3,
            impl_address: crate::shell32::shell32_SHCreateDirectoryExW as *const () as usize,
        },
        // VERSION.dll functions
        FunctionImpl {
            name: "GetFileVersionInfoSizeW",
            dll_name: "VERSION.dll",
            num_params: 2,
            impl_address: crate::version::version_GetFileVersionInfoSizeW as *const () as usize,
        },
        FunctionImpl {
            name: "GetFileVersionInfoW",
            dll_name: "VERSION.dll",
            num_params: 4,
            impl_address: crate::version::version_GetFileVersionInfoW as *const () as usize,
        },
        FunctionImpl {
            name: "VerQueryValueW",
            dll_name: "VERSION.dll",
            num_params: 4,
            impl_address: crate::version::version_VerQueryValueW as *const () as usize,
        },
        // KERNEL32 — Phase 27: Thread Management
        FunctionImpl {
            name: "SetThreadPriority",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_SetThreadPriority as *const () as usize,
        },
        FunctionImpl {
            name: "GetThreadPriority",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetThreadPriority as *const () as usize,
        },
        FunctionImpl {
            name: "SuspendThread",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SuspendThread as *const () as usize,
        },
        FunctionImpl {
            name: "ResumeThread",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_ResumeThread as *const () as usize,
        },
        FunctionImpl {
            name: "OpenThread",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_OpenThread as *const () as usize,
        },
        FunctionImpl {
            name: "GetExitCodeThread",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetExitCodeThread as *const () as usize,
        },
        // KERNEL32 — Phase 27: Process Management
        FunctionImpl {
            name: "OpenProcess",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_OpenProcess as *const () as usize,
        },
        FunctionImpl {
            name: "GetProcessTimes",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_GetProcessTimes as *const () as usize,
        },
        // KERNEL32 — Phase 27: File Times
        FunctionImpl {
            name: "GetFileTime",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetFileTime as *const () as usize,
        },
        FunctionImpl {
            name: "CompareFileTime",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_CompareFileTime as *const () as usize,
        },
        FunctionImpl {
            name: "FileTimeToLocalFileTime",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_FileTimeToLocalFileTime as *const () as usize,
        },
        // KERNEL32 — Phase 27: Temp File Name
        FunctionImpl {
            name: "GetTempFileNameW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetTempFileNameW as *const () as usize,
        },
        // USER32 — Phase 27: Character Conversion
        FunctionImpl {
            name: "CharUpperW",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_CharUpperW as *const () as usize,
        },
        FunctionImpl {
            name: "CharLowerW",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_CharLowerW as *const () as usize,
        },
        FunctionImpl {
            name: "CharUpperA",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_CharUpperA as *const () as usize,
        },
        FunctionImpl {
            name: "CharLowerA",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_CharLowerA as *const () as usize,
        },
        // USER32 — Phase 27: Character Classification
        FunctionImpl {
            name: "IsCharAlphaW",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_IsCharAlphaW as *const () as usize,
        },
        FunctionImpl {
            name: "IsCharAlphaNumericW",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_IsCharAlphaNumericW as *const () as usize,
        },
        FunctionImpl {
            name: "IsCharUpperW",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_IsCharUpperW as *const () as usize,
        },
        FunctionImpl {
            name: "IsCharLowerW",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_IsCharLowerW as *const () as usize,
        },
        // USER32 — Phase 27: Window Utilities
        FunctionImpl {
            name: "IsWindow",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_IsWindow as *const () as usize,
        },
        FunctionImpl {
            name: "IsWindowEnabled",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_IsWindowEnabled as *const () as usize,
        },
        FunctionImpl {
            name: "IsWindowVisible",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_IsWindowVisible as *const () as usize,
        },
        FunctionImpl {
            name: "EnableWindow",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_EnableWindow as *const () as usize,
        },
        FunctionImpl {
            name: "GetWindowTextW",
            dll_name: "USER32.dll",
            num_params: 3,
            impl_address: crate::user32::user32_GetWindowTextW as *const () as usize,
        },
        FunctionImpl {
            name: "SetWindowTextW",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_SetWindowTextW as *const () as usize,
        },
        FunctionImpl {
            name: "GetParent",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_GetParent as *const () as usize,
        },
        // Phase 28: MSVCRT numeric conversion
        FunctionImpl {
            name: "atoi",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_atoi as *const () as usize,
        },
        FunctionImpl {
            name: "atol",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_atol as *const () as usize,
        },
        FunctionImpl {
            name: "atof",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_atof as *const () as usize,
        },
        FunctionImpl {
            name: "strtol",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_strtol as *const () as usize,
        },
        FunctionImpl {
            name: "strtoul",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_strtoul as *const () as usize,
        },
        FunctionImpl {
            name: "strtod",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_strtod as *const () as usize,
        },
        FunctionImpl {
            name: "_itoa",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__itoa as *const () as usize,
        },
        FunctionImpl {
            name: "_ltoa",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__ltoa as *const () as usize,
        },
        // Phase 28: MSVCRT string extras
        FunctionImpl {
            name: "strncpy",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_strncpy as *const () as usize,
        },
        FunctionImpl {
            name: "strncat",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_strncat as *const () as usize,
        },
        FunctionImpl {
            name: "_stricmp",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__stricmp as *const () as usize,
        },
        FunctionImpl {
            name: "_strnicmp",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__strnicmp as *const () as usize,
        },
        FunctionImpl {
            name: "_strdup",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__strdup as *const () as usize,
        },
        FunctionImpl {
            name: "strnlen",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_strnlen as *const () as usize,
        },
        // Phase 28: MSVCRT random & time
        FunctionImpl {
            name: "rand",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt_rand as *const () as usize,
        },
        FunctionImpl {
            name: "srand",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_srand as *const () as usize,
        },
        FunctionImpl {
            name: "time",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_time as *const () as usize,
        },
        FunctionImpl {
            name: "clock",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt_clock as *const () as usize,
        },
        // Phase 28: MSVCRT math
        FunctionImpl {
            name: "abs",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_abs as *const () as usize,
        },
        FunctionImpl {
            name: "labs",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_labs as *const () as usize,
        },
        FunctionImpl {
            name: "_abs64",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__abs64 as *const () as usize,
        },
        FunctionImpl {
            name: "fabs",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_fabs as *const () as usize,
        },
        FunctionImpl {
            name: "sqrt",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_sqrt as *const () as usize,
        },
        FunctionImpl {
            name: "pow",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_pow as *const () as usize,
        },
        FunctionImpl {
            name: "log",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_log as *const () as usize,
        },
        FunctionImpl {
            name: "log10",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_log10 as *const () as usize,
        },
        FunctionImpl {
            name: "exp",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_exp as *const () as usize,
        },
        FunctionImpl {
            name: "sin",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_sin as *const () as usize,
        },
        FunctionImpl {
            name: "cos",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_cos as *const () as usize,
        },
        FunctionImpl {
            name: "tan",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_tan as *const () as usize,
        },
        FunctionImpl {
            name: "atan",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_atan as *const () as usize,
        },
        FunctionImpl {
            name: "atan2",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_atan2 as *const () as usize,
        },
        FunctionImpl {
            name: "ceil",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_ceil as *const () as usize,
        },
        FunctionImpl {
            name: "floor",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_floor as *const () as usize,
        },
        FunctionImpl {
            name: "fmod",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_fmod as *const () as usize,
        },
        // Phase 28: MSVCRT wide-char extras
        FunctionImpl {
            name: "wcscpy",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_wcscpy as *const () as usize,
        },
        FunctionImpl {
            name: "wcscat",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_wcscat as *const () as usize,
        },
        FunctionImpl {
            name: "wcsncpy",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_wcsncpy as *const () as usize,
        },
        FunctionImpl {
            name: "wcschr",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_wcschr as *const () as usize,
        },
        FunctionImpl {
            name: "wcsncmp",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_wcsncmp as *const () as usize,
        },
        FunctionImpl {
            name: "_wcsicmp",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__wcsicmp as *const () as usize,
        },
        FunctionImpl {
            name: "_wcsnicmp",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__wcsnicmp as *const () as usize,
        },
        FunctionImpl {
            name: "wcstombs",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_wcstombs as *const () as usize,
        },
        FunctionImpl {
            name: "mbstowcs",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_mbstowcs as *const () as usize,
        },
        // Phase 28: KERNEL32 additions
        FunctionImpl {
            name: "GetFileSize",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetFileSize as *const () as usize,
        },
        FunctionImpl {
            name: "SetFilePointer",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_SetFilePointer as *const () as usize,
        },
        FunctionImpl {
            name: "SetEndOfFile",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SetEndOfFile as *const () as usize,
        },
        FunctionImpl {
            name: "FlushViewOfFile",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_FlushViewOfFile as *const () as usize,
        },
        FunctionImpl {
            name: "GetSystemDefaultLangID",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetSystemDefaultLangID as *const () as usize,
        },
        FunctionImpl {
            name: "GetUserDefaultLangID",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetUserDefaultLangID as *const () as usize,
        },
        FunctionImpl {
            name: "GetSystemDefaultLCID",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetSystemDefaultLCID as *const () as usize,
        },
        FunctionImpl {
            name: "GetUserDefaultLCID",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetUserDefaultLCID as *const () as usize,
        },
        // Phase 28: USER32 window utility stubs
        FunctionImpl {
            name: "FindWindowW",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_FindWindowW as *const () as usize,
        },
        FunctionImpl {
            name: "FindWindowExW",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_FindWindowExW as *const () as usize,
        },
        FunctionImpl {
            name: "GetForegroundWindow",
            dll_name: "USER32.dll",
            num_params: 0,
            impl_address: crate::user32::user32_GetForegroundWindow as *const () as usize,
        },
        FunctionImpl {
            name: "SetForegroundWindow",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_SetForegroundWindow as *const () as usize,
        },
        FunctionImpl {
            name: "BringWindowToTop",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_BringWindowToTop as *const () as usize,
        },
        FunctionImpl {
            name: "GetWindowRect",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_GetWindowRect as *const () as usize,
        },
        FunctionImpl {
            name: "SetWindowPos",
            dll_name: "USER32.dll",
            num_params: 7,
            impl_address: crate::user32::user32_SetWindowPos as *const () as usize,
        },
        FunctionImpl {
            name: "MoveWindow",
            dll_name: "USER32.dll",
            num_params: 6,
            impl_address: crate::user32::user32_MoveWindow as *const () as usize,
        },
        FunctionImpl {
            name: "GetCursorPos",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_GetCursorPos as *const () as usize,
        },
        FunctionImpl {
            name: "SetCursorPos",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_SetCursorPos as *const () as usize,
        },
        FunctionImpl {
            name: "ScreenToClient",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_ScreenToClient as *const () as usize,
        },
        FunctionImpl {
            name: "ClientToScreen",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_ClientToScreen as *const () as usize,
        },
        FunctionImpl {
            name: "ShowCursor",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_ShowCursor as *const () as usize,
        },
        FunctionImpl {
            name: "GetFocus",
            dll_name: "USER32.dll",
            num_params: 0,
            impl_address: crate::user32::user32_GetFocus as *const () as usize,
        },
        FunctionImpl {
            name: "SetFocus",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_SetFocus as *const () as usize,
        },
        // USER32 — Phase 45: Dialog, menu, clipboard, drawing, capture, misc GUI
        FunctionImpl {
            name: "RegisterClassW",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_RegisterClassW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateWindowW",
            dll_name: "USER32.dll",
            num_params: 11,
            impl_address: crate::user32::user32_CreateWindowW as *const () as usize,
        },
        FunctionImpl {
            name: "DialogBoxParamW",
            dll_name: "USER32.dll",
            num_params: 5,
            impl_address: crate::user32::user32_DialogBoxParamW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateDialogParamW",
            dll_name: "USER32.dll",
            num_params: 5,
            impl_address: crate::user32::user32_CreateDialogParamW as *const () as usize,
        },
        FunctionImpl {
            name: "EndDialog",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_EndDialog as *const () as usize,
        },
        FunctionImpl {
            name: "GetDlgItem",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_GetDlgItem as *const () as usize,
        },
        FunctionImpl {
            name: "GetDlgItemTextW",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_GetDlgItemTextW as *const () as usize,
        },
        FunctionImpl {
            name: "SetDlgItemTextW",
            dll_name: "USER32.dll",
            num_params: 3,
            impl_address: crate::user32::user32_SetDlgItemTextW as *const () as usize,
        },
        FunctionImpl {
            name: "SendDlgItemMessageW",
            dll_name: "USER32.dll",
            num_params: 5,
            impl_address: crate::user32::user32_SendDlgItemMessageW as *const () as usize,
        },
        FunctionImpl {
            name: "GetDlgItemInt",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_GetDlgItemInt as *const () as usize,
        },
        FunctionImpl {
            name: "SetDlgItemInt",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_SetDlgItemInt as *const () as usize,
        },
        FunctionImpl {
            name: "CheckDlgButton",
            dll_name: "USER32.dll",
            num_params: 3,
            impl_address: crate::user32::user32_CheckDlgButton as *const () as usize,
        },
        FunctionImpl {
            name: "IsDlgButtonChecked",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_IsDlgButtonChecked as *const () as usize,
        },
        FunctionImpl {
            name: "DrawTextW",
            dll_name: "USER32.dll",
            num_params: 5,
            impl_address: crate::user32::user32_DrawTextW as *const () as usize,
        },
        FunctionImpl {
            name: "DrawTextA",
            dll_name: "USER32.dll",
            num_params: 5,
            impl_address: crate::user32::user32_DrawTextA as *const () as usize,
        },
        FunctionImpl {
            name: "DrawTextExW",
            dll_name: "USER32.dll",
            num_params: 6,
            impl_address: crate::user32::user32_DrawTextExW as *const () as usize,
        },
        FunctionImpl {
            name: "AdjustWindowRect",
            dll_name: "USER32.dll",
            num_params: 3,
            impl_address: crate::user32::user32_AdjustWindowRect as *const () as usize,
        },
        FunctionImpl {
            name: "AdjustWindowRectEx",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_AdjustWindowRectEx as *const () as usize,
        },
        FunctionImpl {
            name: "SystemParametersInfoW",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_SystemParametersInfoW as *const () as usize,
        },
        FunctionImpl {
            name: "SystemParametersInfoA",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_SystemParametersInfoA as *const () as usize,
        },
        FunctionImpl {
            name: "CreateMenu",
            dll_name: "USER32.dll",
            num_params: 0,
            impl_address: crate::user32::user32_CreateMenu as *const () as usize,
        },
        FunctionImpl {
            name: "CreatePopupMenu",
            dll_name: "USER32.dll",
            num_params: 0,
            impl_address: crate::user32::user32_CreatePopupMenu as *const () as usize,
        },
        FunctionImpl {
            name: "DestroyMenu",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_DestroyMenu as *const () as usize,
        },
        FunctionImpl {
            name: "AppendMenuW",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_AppendMenuW as *const () as usize,
        },
        FunctionImpl {
            name: "InsertMenuItemW",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_InsertMenuItemW as *const () as usize,
        },
        FunctionImpl {
            name: "GetMenu",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_GetMenu as *const () as usize,
        },
        FunctionImpl {
            name: "SetMenu",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_SetMenu as *const () as usize,
        },
        FunctionImpl {
            name: "DrawMenuBar",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_DrawMenuBar as *const () as usize,
        },
        FunctionImpl {
            name: "TrackPopupMenu",
            dll_name: "USER32.dll",
            num_params: 7,
            impl_address: crate::user32::user32_TrackPopupMenu as *const () as usize,
        },
        FunctionImpl {
            name: "SetCapture",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_SetCapture as *const () as usize,
        },
        FunctionImpl {
            name: "ReleaseCapture",
            dll_name: "USER32.dll",
            num_params: 0,
            impl_address: crate::user32::user32_ReleaseCapture as *const () as usize,
        },
        FunctionImpl {
            name: "GetCapture",
            dll_name: "USER32.dll",
            num_params: 0,
            impl_address: crate::user32::user32_GetCapture as *const () as usize,
        },
        FunctionImpl {
            name: "TrackMouseEvent",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_TrackMouseEvent as *const () as usize,
        },
        FunctionImpl {
            name: "RedrawWindow",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_RedrawWindow as *const () as usize,
        },
        FunctionImpl {
            name: "OpenClipboard",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_OpenClipboard as *const () as usize,
        },
        FunctionImpl {
            name: "CloseClipboard",
            dll_name: "USER32.dll",
            num_params: 0,
            impl_address: crate::user32::user32_CloseClipboard as *const () as usize,
        },
        FunctionImpl {
            name: "EmptyClipboard",
            dll_name: "USER32.dll",
            num_params: 0,
            impl_address: crate::user32::user32_EmptyClipboard as *const () as usize,
        },
        FunctionImpl {
            name: "GetClipboardData",
            dll_name: "USER32.dll",
            num_params: 1,
            impl_address: crate::user32::user32_GetClipboardData as *const () as usize,
        },
        FunctionImpl {
            name: "SetClipboardData",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_SetClipboardData as *const () as usize,
        },
        FunctionImpl {
            name: "LoadStringW",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_LoadStringW as *const () as usize,
        },
        FunctionImpl {
            name: "LoadBitmapW",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_LoadBitmapW as *const () as usize,
        },
        FunctionImpl {
            name: "LoadImageW",
            dll_name: "USER32.dll",
            num_params: 6,
            impl_address: crate::user32::user32_LoadImageW as *const () as usize,
        },
        FunctionImpl {
            name: "CallWindowProcW",
            dll_name: "USER32.dll",
            num_params: 5,
            impl_address: crate::user32::user32_CallWindowProcW as *const () as usize,
        },
        FunctionImpl {
            name: "GetWindowInfo",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_GetWindowInfo as *const () as usize,
        },
        FunctionImpl {
            name: "MapWindowPoints",
            dll_name: "USER32.dll",
            num_params: 4,
            impl_address: crate::user32::user32_MapWindowPoints as *const () as usize,
        },
        FunctionImpl {
            name: "MonitorFromWindow",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_MonitorFromWindow as *const () as usize,
        },
        FunctionImpl {
            name: "MonitorFromPoint",
            dll_name: "USER32.dll",
            num_params: 3,
            impl_address: crate::user32::user32_MonitorFromPoint as *const () as usize,
        },
        FunctionImpl {
            name: "GetMonitorInfoW",
            dll_name: "USER32.dll",
            num_params: 2,
            impl_address: crate::user32::user32_GetMonitorInfoW as *const () as usize,
        },
        // vulkan-1.dll — Vulkan API stubs (Phase 45)
        FunctionImpl {
            name: "vkCreateInstance",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkCreateInstance as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroyInstance",
            dll_name: "vulkan-1.dll",
            num_params: 2,
            impl_address: crate::vulkan1::vulkan1_vkDestroyInstance as *const () as usize,
        },
        FunctionImpl {
            name: "vkEnumerateInstanceExtensionProperties",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkEnumerateInstanceExtensionProperties
                as *const () as usize,
        },
        FunctionImpl {
            name: "vkEnumerateInstanceLayerProperties",
            dll_name: "vulkan-1.dll",
            num_params: 2,
            impl_address: crate::vulkan1::vulkan1_vkEnumerateInstanceLayerProperties as *const ()
                as usize,
        },
        FunctionImpl {
            name: "vkEnumeratePhysicalDevices",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkEnumeratePhysicalDevices as *const () as usize,
        },
        FunctionImpl {
            name: "vkGetPhysicalDeviceProperties",
            dll_name: "vulkan-1.dll",
            num_params: 2,
            impl_address: crate::vulkan1::vulkan1_vkGetPhysicalDeviceProperties as *const ()
                as usize,
        },
        FunctionImpl {
            name: "vkGetPhysicalDeviceFeatures",
            dll_name: "vulkan-1.dll",
            num_params: 2,
            impl_address: crate::vulkan1::vulkan1_vkGetPhysicalDeviceFeatures as *const () as usize,
        },
        FunctionImpl {
            name: "vkGetPhysicalDeviceQueueFamilyProperties",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkGetPhysicalDeviceQueueFamilyProperties
                as *const () as usize,
        },
        FunctionImpl {
            name: "vkGetPhysicalDeviceMemoryProperties",
            dll_name: "vulkan-1.dll",
            num_params: 2,
            impl_address: crate::vulkan1::vulkan1_vkGetPhysicalDeviceMemoryProperties as *const ()
                as usize,
        },
        FunctionImpl {
            name: "vkCreateDevice",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreateDevice as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroyDevice",
            dll_name: "vulkan-1.dll",
            num_params: 2,
            impl_address: crate::vulkan1::vulkan1_vkDestroyDevice as *const () as usize,
        },
        FunctionImpl {
            name: "vkGetDeviceQueue",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkGetDeviceQueue as *const () as usize,
        },
        FunctionImpl {
            name: "vkCreateWin32SurfaceKHR",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreateWin32SurfaceKHR as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroySurfaceKHR",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroySurfaceKHR as *const () as usize,
        },
        FunctionImpl {
            name: "vkGetPhysicalDeviceSurfaceSupportKHR",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkGetPhysicalDeviceSurfaceSupportKHR as *const ()
                as usize,
        },
        FunctionImpl {
            name: "vkGetPhysicalDeviceSurfaceCapabilitiesKHR",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkGetPhysicalDeviceSurfaceCapabilitiesKHR
                as *const () as usize,
        },
        FunctionImpl {
            name: "vkGetPhysicalDeviceSurfaceFormatsKHR",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkGetPhysicalDeviceSurfaceFormatsKHR as *const ()
                as usize,
        },
        FunctionImpl {
            name: "vkGetPhysicalDeviceSurfacePresentModesKHR",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkGetPhysicalDeviceSurfacePresentModesKHR
                as *const () as usize,
        },
        FunctionImpl {
            name: "vkCreateSwapchainKHR",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreateSwapchainKHR as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroySwapchainKHR",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroySwapchainKHR as *const () as usize,
        },
        FunctionImpl {
            name: "vkGetSwapchainImagesKHR",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkGetSwapchainImagesKHR as *const () as usize,
        },
        FunctionImpl {
            name: "vkAcquireNextImageKHR",
            dll_name: "vulkan-1.dll",
            num_params: 6,
            impl_address: crate::vulkan1::vulkan1_vkAcquireNextImageKHR as *const () as usize,
        },
        FunctionImpl {
            name: "vkQueuePresentKHR",
            dll_name: "vulkan-1.dll",
            num_params: 2,
            impl_address: crate::vulkan1::vulkan1_vkQueuePresentKHR as *const () as usize,
        },
        FunctionImpl {
            name: "vkAllocateMemory",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkAllocateMemory as *const () as usize,
        },
        FunctionImpl {
            name: "vkFreeMemory",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkFreeMemory as *const () as usize,
        },
        FunctionImpl {
            name: "vkCreateBuffer",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreateBuffer as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroyBuffer",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroyBuffer as *const () as usize,
        },
        FunctionImpl {
            name: "vkCreateImage",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreateImage as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroyImage",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroyImage as *const () as usize,
        },
        FunctionImpl {
            name: "vkCreateRenderPass",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreateRenderPass as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroyRenderPass",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroyRenderPass as *const () as usize,
        },
        FunctionImpl {
            name: "vkCreateFramebuffer",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreateFramebuffer as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroyFramebuffer",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroyFramebuffer as *const () as usize,
        },
        FunctionImpl {
            name: "vkCreateGraphicsPipelines",
            dll_name: "vulkan-1.dll",
            num_params: 6,
            impl_address: crate::vulkan1::vulkan1_vkCreateGraphicsPipelines as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroyPipeline",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroyPipeline as *const () as usize,
        },
        FunctionImpl {
            name: "vkCreateShaderModule",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreateShaderModule as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroyShaderModule",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroyShaderModule as *const () as usize,
        },
        FunctionImpl {
            name: "vkCreateCommandPool",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreateCommandPool as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroyCommandPool",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroyCommandPool as *const () as usize,
        },
        FunctionImpl {
            name: "vkAllocateCommandBuffers",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkAllocateCommandBuffers as *const () as usize,
        },
        FunctionImpl {
            name: "vkFreeCommandBuffers",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkFreeCommandBuffers as *const () as usize,
        },
        FunctionImpl {
            name: "vkBeginCommandBuffer",
            dll_name: "vulkan-1.dll",
            num_params: 2,
            impl_address: crate::vulkan1::vulkan1_vkBeginCommandBuffer as *const () as usize,
        },
        FunctionImpl {
            name: "vkEndCommandBuffer",
            dll_name: "vulkan-1.dll",
            num_params: 1,
            impl_address: crate::vulkan1::vulkan1_vkEndCommandBuffer as *const () as usize,
        },
        FunctionImpl {
            name: "vkCmdBeginRenderPass",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkCmdBeginRenderPass as *const () as usize,
        },
        FunctionImpl {
            name: "vkCmdEndRenderPass",
            dll_name: "vulkan-1.dll",
            num_params: 1,
            impl_address: crate::vulkan1::vulkan1_vkCmdEndRenderPass as *const () as usize,
        },
        FunctionImpl {
            name: "vkCmdDraw",
            dll_name: "vulkan-1.dll",
            num_params: 5,
            impl_address: crate::vulkan1::vulkan1_vkCmdDraw as *const () as usize,
        },
        FunctionImpl {
            name: "vkCmdDrawIndexed",
            dll_name: "vulkan-1.dll",
            num_params: 6,
            impl_address: crate::vulkan1::vulkan1_vkCmdDrawIndexed as *const () as usize,
        },
        FunctionImpl {
            name: "vkQueueSubmit",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkQueueSubmit as *const () as usize,
        },
        FunctionImpl {
            name: "vkQueueWaitIdle",
            dll_name: "vulkan-1.dll",
            num_params: 1,
            impl_address: crate::vulkan1::vulkan1_vkQueueWaitIdle as *const () as usize,
        },
        FunctionImpl {
            name: "vkDeviceWaitIdle",
            dll_name: "vulkan-1.dll",
            num_params: 1,
            impl_address: crate::vulkan1::vulkan1_vkDeviceWaitIdle as *const () as usize,
        },
        FunctionImpl {
            name: "vkCreateFence",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreateFence as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroyFence",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroyFence as *const () as usize,
        },
        FunctionImpl {
            name: "vkWaitForFences",
            dll_name: "vulkan-1.dll",
            num_params: 5,
            impl_address: crate::vulkan1::vulkan1_vkWaitForFences as *const () as usize,
        },
        FunctionImpl {
            name: "vkResetFences",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkResetFences as *const () as usize,
        },
        FunctionImpl {
            name: "vkCreateSemaphore",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreateSemaphore as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroySemaphore",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroySemaphore as *const () as usize,
        },
        FunctionImpl {
            name: "vkCreateDescriptorSetLayout",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreateDescriptorSetLayout as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroyDescriptorSetLayout",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroyDescriptorSetLayout as *const ()
                as usize,
        },
        FunctionImpl {
            name: "vkCreatePipelineLayout",
            dll_name: "vulkan-1.dll",
            num_params: 4,
            impl_address: crate::vulkan1::vulkan1_vkCreatePipelineLayout as *const () as usize,
        },
        FunctionImpl {
            name: "vkDestroyPipelineLayout",
            dll_name: "vulkan-1.dll",
            num_params: 3,
            impl_address: crate::vulkan1::vulkan1_vkDestroyPipelineLayout as *const () as usize,
        },
        FunctionImpl {
            name: "vkGetInstanceProcAddr",
            dll_name: "vulkan-1.dll",
            num_params: 2,
            impl_address: crate::vulkan1::vulkan1_vkGetInstanceProcAddr as *const () as usize,
        },
        FunctionImpl {
            name: "vkGetDeviceProcAddr",
            dll_name: "vulkan-1.dll",
            num_params: 2,
            impl_address: crate::vulkan1::vulkan1_vkGetDeviceProcAddr as *const () as usize,
        },
        // Phase 28: SHLWAPI path utilities
        FunctionImpl {
            name: "PathFileExistsW",
            dll_name: "SHLWAPI.dll",
            num_params: 1,
            impl_address: crate::shlwapi::shlwapi_PathFileExistsW as *const () as usize,
        },
        FunctionImpl {
            name: "PathCombineW",
            dll_name: "SHLWAPI.dll",
            num_params: 3,
            impl_address: crate::shlwapi::shlwapi_PathCombineW as *const () as usize,
        },
        FunctionImpl {
            name: "PathGetFileNameW",
            dll_name: "SHLWAPI.dll",
            num_params: 1,
            impl_address: crate::shlwapi::shlwapi_PathGetFileNameW as *const () as usize,
        },
        FunctionImpl {
            name: "PathRemoveFileSpecW",
            dll_name: "SHLWAPI.dll",
            num_params: 1,
            impl_address: crate::shlwapi::shlwapi_PathRemoveFileSpecW as *const () as usize,
        },
        FunctionImpl {
            name: "PathIsRelativeW",
            dll_name: "SHLWAPI.dll",
            num_params: 1,
            impl_address: crate::shlwapi::shlwapi_PathIsRelativeW as *const () as usize,
        },
        FunctionImpl {
            name: "PathFindExtensionW",
            dll_name: "SHLWAPI.dll",
            num_params: 1,
            impl_address: crate::shlwapi::shlwapi_PathFindExtensionW as *const () as usize,
        },
        FunctionImpl {
            name: "PathStripPathW",
            dll_name: "SHLWAPI.dll",
            num_params: 1,
            impl_address: crate::shlwapi::shlwapi_PathStripPathW as *const () as usize,
        },
        FunctionImpl {
            name: "PathAddBackslashW",
            dll_name: "SHLWAPI.dll",
            num_params: 1,
            impl_address: crate::shlwapi::shlwapi_PathAddBackslashW as *const () as usize,
        },
        FunctionImpl {
            name: "StrToIntW",
            dll_name: "SHLWAPI.dll",
            num_params: 1,
            impl_address: crate::shlwapi::shlwapi_StrToIntW as *const () as usize,
        },
        FunctionImpl {
            name: "StrCmpIW",
            dll_name: "SHLWAPI.dll",
            num_params: 2,
            impl_address: crate::shlwapi::shlwapi_StrCmpIW as *const () as usize,
        },
        // C++ Exception Handling (MSVC-style)
        FunctionImpl {
            name: "_CxxThrowException",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__CxxThrowException as *const () as usize,
        },
        FunctionImpl {
            name: "__CxxFrameHandler3",
            dll_name: "MSVCRT.dll",
            num_params: 4,
            impl_address: crate::msvcrt::msvcrt___CxxFrameHandler3 as *const () as usize,
        },
        FunctionImpl {
            name: "__CxxFrameHandler4",
            dll_name: "MSVCRT.dll",
            num_params: 4,
            impl_address: crate::msvcrt::msvcrt___CxxFrameHandler4 as *const () as usize,
        },
        FunctionImpl {
            name: "__CxxRegisterExceptionObject",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt___CxxRegisterExceptionObject as *const () as usize,
        },
        FunctionImpl {
            name: "__CxxUnregisterExceptionObject",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt___CxxUnregisterExceptionObject as *const ()
                as usize,
        },
        FunctionImpl {
            name: "__DestructExceptionObject",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt___DestructExceptionObject as *const () as usize,
        },
        FunctionImpl {
            name: "__uncaught_exception",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt___uncaught_exception as *const () as usize,
        },
        FunctionImpl {
            name: "__uncaught_exceptions",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt___uncaught_exceptions as *const () as usize,
        },
        FunctionImpl {
            name: "_local_unwind",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__local_unwind as *const () as usize,
        },
        FunctionImpl {
            name: "terminate",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt_terminate as *const () as usize,
        },
        FunctionImpl {
            name: "_set_se_translator",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__set_se_translator as *const () as usize,
        },
        FunctionImpl {
            name: "_is_exception_typeof",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__is_exception_typeof as *const () as usize,
        },
        FunctionImpl {
            name: "__std_terminate",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt___std_terminate as *const () as usize,
        },
        FunctionImpl {
            name: "_CxxExceptionFilter",
            dll_name: "MSVCRT.dll",
            num_params: 4,
            impl_address: crate::msvcrt::msvcrt__CxxExceptionFilter as *const () as usize,
        },
        FunctionImpl {
            name: "__current_exception",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt___current_exception as *const () as usize,
        },
        FunctionImpl {
            name: "__current_exception_context",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt___current_exception_context as *const () as usize,
        },
        // VCRUNTIME140 / UCRT stubs for MSVC-compiled programs.
        // These DLLs are aliased to MSVCRT.dll in the DLL manager, so all
        // entries use dll_name: "MSVCRT.dll".
        FunctionImpl {
            name: "__vcrt_initialize",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::vcruntime__vcrt_initialize as *const () as usize,
        },
        FunctionImpl {
            name: "__vcrt_uninitialize",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::vcruntime__vcrt_uninitialize as *const () as usize,
        },
        FunctionImpl {
            name: "__security_init_cookie",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::vcruntime__security_init_cookie as *const () as usize,
        },
        FunctionImpl {
            name: "__security_check_cookie",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::vcruntime__security_check_cookie as *const () as usize,
        },
        FunctionImpl {
            name: "_initialize_narrow_environment",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::ucrt__initialize_narrow_environment as *const () as usize,
        },
        FunctionImpl {
            name: "_get_initial_narrow_environment",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::ucrt__get_initial_narrow_environment as *const () as usize,
        },
        FunctionImpl {
            name: "_configure_narrow_argv",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::ucrt__configure_narrow_argv as *const () as usize,
        },
        FunctionImpl {
            name: "_set_app_type",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::ucrt__set_app_type as *const () as usize,
        },
        FunctionImpl {
            name: "_exit",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::ucrt__exit as *const () as usize,
        },
        FunctionImpl {
            name: "_c_exit",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::ucrt__c_exit as *const () as usize,
        },
        FunctionImpl {
            name: "_crt_atexit",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::ucrt__crt_atexit as *const () as usize,
        },
        FunctionImpl {
            name: "_register_thread_local_exe_atexit_callback",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::ucrt__register_thread_local_exe_atexit_callback
                as *const () as usize,
        },
        FunctionImpl {
            name: "_seh_filter_exe",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::ucrt__seh_filter_exe as *const () as usize,
        },
        FunctionImpl {
            name: "_initialize_onexit_table",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::ucrt__initialize_onexit_table as *const () as usize,
        },
        FunctionImpl {
            name: "_register_onexit_function",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::ucrt__register_onexit_function as *const () as usize,
        },
        FunctionImpl {
            name: "_set_fmode",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::ucrt__set_fmode as *const () as usize,
        },
        FunctionImpl {
            name: "_set_new_mode",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::ucrt__set_new_mode as *const () as usize,
        },
        FunctionImpl {
            name: "__acrt_iob_func",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::ucrt__acrt_iob_func as *const () as usize,
        },
        FunctionImpl {
            name: "__stdio_common_vfprintf",
            dll_name: "MSVCRT.dll",
            num_params: 5,
            impl_address: crate::msvcrt::ucrt__stdio_common_vfprintf as *const () as usize,
        },
        FunctionImpl {
            name: "_configthreadlocale",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::ucrt__configthreadlocale as *const () as usize,
        },
        // MSVCRT.dll — formatted I/O
        FunctionImpl {
            name: "sprintf",
            dll_name: "MSVCRT.dll",
            num_params: 9, // Variadic; buf + format + up to 7 args
            impl_address: crate::msvcrt::msvcrt_sprintf as *const () as usize,
        },
        FunctionImpl {
            name: "snprintf",
            dll_name: "MSVCRT.dll",
            num_params: 9, // Variadic; buf + count + format + up to 6 args
            impl_address: crate::msvcrt::msvcrt_snprintf as *const () as usize,
        },
        FunctionImpl {
            name: "_snprintf_s",
            dll_name: "MSVCRT.dll",
            num_params: 10, // Variadic; buf + sizeOfBuffer + count + format + up to 6 args
            impl_address: crate::msvcrt::msvcrt_snprintf_s as *const () as usize,
        },
        FunctionImpl {
            name: "sscanf",
            dll_name: "MSVCRT.dll",
            num_params: 18, // Variadic; buf + format + up to 16 pointer args
            impl_address: crate::msvcrt::msvcrt_sscanf as *const () as usize,
        },
        FunctionImpl {
            name: "swprintf",
            dll_name: "MSVCRT.dll",
            num_params: 8, // Variadic; buf + format + up to 6 args
            impl_address: crate::msvcrt::msvcrt_swprintf as *const () as usize,
        },
        FunctionImpl {
            name: "wprintf",
            dll_name: "MSVCRT.dll",
            num_params: 8, // Variadic; format + up to 7 args
            impl_address: crate::msvcrt::msvcrt_wprintf as *const () as usize,
        },
        // MSVCRT.dll — character classification
        FunctionImpl {
            name: "isalpha",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_isalpha as *const () as usize,
        },
        FunctionImpl {
            name: "isdigit",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_isdigit as *const () as usize,
        },
        FunctionImpl {
            name: "isspace",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_isspace as *const () as usize,
        },
        FunctionImpl {
            name: "isupper",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_isupper as *const () as usize,
        },
        FunctionImpl {
            name: "islower",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_islower as *const () as usize,
        },
        FunctionImpl {
            name: "toupper",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_toupper as *const () as usize,
        },
        FunctionImpl {
            name: "tolower",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_tolower as *const () as usize,
        },
        FunctionImpl {
            name: "isxdigit",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_isxdigit as *const () as usize,
        },
        FunctionImpl {
            name: "ispunct",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_ispunct as *const () as usize,
        },
        FunctionImpl {
            name: "isprint",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_isprint as *const () as usize,
        },
        FunctionImpl {
            name: "iscntrl",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_iscntrl as *const () as usize,
        },
        FunctionImpl {
            name: "isalnum",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_isalnum as *const () as usize,
        },
        // MSVCRT.dll — sorting and searching
        FunctionImpl {
            name: "qsort",
            dll_name: "MSVCRT.dll",
            num_params: 4,
            impl_address: crate::msvcrt::msvcrt_qsort as *const () as usize,
        },
        FunctionImpl {
            name: "bsearch",
            dll_name: "MSVCRT.dll",
            num_params: 5,
            impl_address: crate::msvcrt::msvcrt_bsearch as *const () as usize,
        },
        // MSVCRT.dll — wide string numeric conversions
        FunctionImpl {
            name: "wcstol",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_wcstol as *const () as usize,
        },
        FunctionImpl {
            name: "wcstoul",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_wcstoul as *const () as usize,
        },
        FunctionImpl {
            name: "wcstod",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_wcstod as *const () as usize,
        },
        // MSVCRT.dll — file I/O
        FunctionImpl {
            name: "fopen",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_fopen as *const () as usize,
        },
        FunctionImpl {
            name: "_wfopen",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__wfopen as *const () as usize,
        },
        FunctionImpl {
            name: "fclose",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_fclose as *const () as usize,
        },
        FunctionImpl {
            name: "fread",
            dll_name: "MSVCRT.dll",
            num_params: 4,
            impl_address: crate::msvcrt::msvcrt_fread as *const () as usize,
        },
        FunctionImpl {
            name: "fgets",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_fgets as *const () as usize,
        },
        FunctionImpl {
            name: "fseek",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_fseek as *const () as usize,
        },
        FunctionImpl {
            name: "ftell",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_ftell as *const () as usize,
        },
        FunctionImpl {
            name: "feof",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_feof as *const () as usize,
        },
        FunctionImpl {
            name: "ferror",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_ferror as *const () as usize,
        },
        FunctionImpl {
            name: "clearerr",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_clearerr as *const () as usize,
        },
        FunctionImpl {
            name: "fflush",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_fflush as *const () as usize,
        },
        FunctionImpl {
            name: "rewind",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_rewind as *const () as usize,
        },
        FunctionImpl {
            name: "fgetc",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_fgetc as *const () as usize,
        },
        FunctionImpl {
            name: "fputc",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_fputc as *const () as usize,
        },
        FunctionImpl {
            name: "ungetc",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_ungetc as *const () as usize,
        },
        FunctionImpl {
            name: "fileno",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_fileno as *const () as usize,
        },
        FunctionImpl {
            name: "_fileno",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_fileno as *const () as usize,
        },
        FunctionImpl {
            name: "fdopen",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_fdopen as *const () as usize,
        },
        FunctionImpl {
            name: "_fdopen",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_fdopen as *const () as usize,
        },
        FunctionImpl {
            name: "tmpfile",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt_tmpfile as *const () as usize,
        },
        FunctionImpl {
            name: "remove",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_remove as *const () as usize,
        },
        FunctionImpl {
            name: "rename",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_rename as *const () as usize,
        },
        // OLEAUT32: COM error info and BSTR functions
        FunctionImpl {
            name: "GetErrorInfo",
            dll_name: "OLEAUT32.dll",
            num_params: 2,
            impl_address: crate::oleaut32::oleaut32_get_error_info as *const () as usize,
        },
        FunctionImpl {
            name: "SetErrorInfo",
            dll_name: "OLEAUT32.dll",
            num_params: 2,
            impl_address: crate::oleaut32::oleaut32_set_error_info as *const () as usize,
        },
        FunctionImpl {
            name: "SysFreeString",
            dll_name: "OLEAUT32.dll",
            num_params: 1,
            impl_address: crate::oleaut32::oleaut32_sys_free_string as *const () as usize,
        },
        FunctionImpl {
            name: "SysStringLen",
            dll_name: "OLEAUT32.dll",
            num_params: 1,
            impl_address: crate::oleaut32::oleaut32_sys_string_len as *const () as usize,
        },
        FunctionImpl {
            name: "SysAllocString",
            dll_name: "OLEAUT32.dll",
            num_params: 1,
            impl_address: crate::oleaut32::oleaut32_sys_alloc_string as *const () as usize,
        },
        FunctionImpl {
            name: "SysAllocStringLen",
            dll_name: "OLEAUT32.dll",
            num_params: 2,
            impl_address: crate::oleaut32::oleaut32_sys_alloc_string_len as *const () as usize,
        },
        // api-ms-win-core-winrt-error: Windows Runtime error origination
        FunctionImpl {
            name: "RoOriginateErrorW",
            dll_name: "api-ms-win-core-winrt-error-l1-1-0.dll",
            num_params: 3,
            impl_address: crate::oleaut32::winrt_ro_originate_error_w as *const () as usize,
        },
        FunctionImpl {
            name: "RoOriginateError",
            dll_name: "api-ms-win-core-winrt-error-l1-1-0.dll",
            num_params: 2,
            impl_address: crate::oleaut32::winrt_ro_originate_error as *const () as usize,
        },
        FunctionImpl {
            name: "RoGetErrorReportingFlags",
            dll_name: "api-ms-win-core-winrt-error-l1-1-0.dll",
            num_params: 1,
            impl_address: crate::oleaut32::winrt_ro_get_error_reporting_flags as *const () as usize,
        },
        // ole32.dll — COM initialization functions
        FunctionImpl {
            name: "CoInitialize",
            dll_name: "ole32.dll",
            num_params: 1,
            impl_address: crate::ole32::ole32_co_initialize as *const () as usize,
        },
        FunctionImpl {
            name: "CoInitializeEx",
            dll_name: "ole32.dll",
            num_params: 2,
            impl_address: crate::ole32::ole32_co_initialize_ex as *const () as usize,
        },
        FunctionImpl {
            name: "CoUninitialize",
            dll_name: "ole32.dll",
            num_params: 0,
            impl_address: crate::ole32::ole32_co_uninitialize as *const () as usize,
        },
        FunctionImpl {
            name: "CoCreateInstance",
            dll_name: "ole32.dll",
            num_params: 5,
            impl_address: crate::ole32::ole32_co_create_instance as *const () as usize,
        },
        FunctionImpl {
            name: "CoCreateGuid",
            dll_name: "ole32.dll",
            num_params: 1,
            impl_address: crate::ole32::ole32_co_create_guid as *const () as usize,
        },
        FunctionImpl {
            name: "StringFromGUID2",
            dll_name: "ole32.dll",
            num_params: 3,
            impl_address: crate::ole32::ole32_string_from_guid2 as *const () as usize,
        },
        FunctionImpl {
            name: "CLSIDFromString",
            dll_name: "ole32.dll",
            num_params: 2,
            impl_address: crate::ole32::ole32_clsid_from_string as *const () as usize,
        },
        FunctionImpl {
            name: "CoTaskMemAlloc",
            dll_name: "ole32.dll",
            num_params: 1,
            impl_address: crate::ole32::ole32_co_task_mem_alloc as *const () as usize,
        },
        FunctionImpl {
            name: "CoTaskMemFree",
            dll_name: "ole32.dll",
            num_params: 1,
            impl_address: crate::ole32::ole32_co_task_mem_free as *const () as usize,
        },
        FunctionImpl {
            name: "CoTaskMemRealloc",
            dll_name: "ole32.dll",
            num_params: 2,
            impl_address: crate::ole32::ole32_co_task_mem_realloc as *const () as usize,
        },
        FunctionImpl {
            name: "CoGetClassObject",
            dll_name: "ole32.dll",
            num_params: 5,
            impl_address: crate::ole32::ole32_co_get_class_object as *const () as usize,
        },
        FunctionImpl {
            name: "CoSetProxyBlanket",
            dll_name: "ole32.dll",
            num_params: 8,
            impl_address: crate::ole32::ole32_co_set_proxy_blanket as *const () as usize,
        },
        // msvcp140.dll — C++ standard library stubs
        FunctionImpl {
            name: "??2@YAPEAX_K@Z",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140_operator_new as *const () as usize,
        },
        FunctionImpl {
            name: "??3@YAXPEAX@Z",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140_operator_delete as *const () as usize,
        },
        FunctionImpl {
            name: "??_U@YAPEAX_K@Z",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140_operator_new_array as *const () as usize,
        },
        FunctionImpl {
            name: "??_V@YAXPEAX@Z",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140_operator_delete_array as *const () as usize,
        },
        FunctionImpl {
            name: "?_Xbad_alloc@std@@YAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 0,
            impl_address: crate::msvcp140::msvcp140__Xbad_alloc as *const () as usize,
        },
        FunctionImpl {
            name: "?_Xlength_error@std@@YAXPEBD@Z",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__Xlength_error as *const () as usize,
        },
        FunctionImpl {
            name: "?_Xout_of_range@std@@YAXPEBD@Z",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__Xout_of_range as *const () as usize,
        },
        FunctionImpl {
            name: "?_Xinvalid_argument@std@@YAXPEBD@Z",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__Xinvalid_argument as *const () as usize,
        },
        FunctionImpl {
            name: "?_Xruntime_error@std@@YAXPEBD@Z",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__Xruntime_error as *const () as usize,
        },
        FunctionImpl {
            name: "?_Xoverflow_error@std@@YAXPEBD@Z",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__Xoverflow_error as *const () as usize,
        },
        FunctionImpl {
            name: "?_Getctype@_Locinfo@std@@QEBAPBU_Ctypevec@@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__Getctype as *const () as usize,
        },
        FunctionImpl {
            name: "?_Getdays@_Locinfo@std@@QEBAPEBDXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__Getdays as *const () as usize,
        },
        FunctionImpl {
            name: "?_Getmonths@_Locinfo@std@@QEBAPEBDXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__Getmonths as *const () as usize,
        },
        // Phase 35: std::exception stubs
        FunctionImpl {
            name: "?what@exception@std@@UEBAPEBDXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__exception_what as *const () as usize,
        },
        FunctionImpl {
            name: "??1exception@std@@UEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__exception_dtor as *const () as usize,
        },
        FunctionImpl {
            name: "??0exception@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__exception_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??0exception@std@@QEAA@PEBD@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__exception_ctor_msg as *const () as usize,
        },
        // Phase 35: locale / lockit stubs
        FunctionImpl {
            name: "?_Getgloballocale@locale@std@@CAPEAV_Lobj@12@XZ",
            dll_name: "msvcp140.dll",
            num_params: 0,
            impl_address: crate::msvcp140::msvcp140__Getgloballocale as *const () as usize,
        },
        FunctionImpl {
            name: "??0_Lockit@std@@QEAA@H@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__Lockit_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??1_Lockit@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__Lockit_dtor as *const () as usize,
        },
        // Phase 35: ios_base::Init stubs
        FunctionImpl {
            name: "??0Init@ios_base@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__ios_base_Init_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??1Init@ios_base@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__ios_base_Init_dtor as *const () as usize,
        },
        // Phase 37: std::basic_string<char> (MSVC x64 ABI)
        FunctionImpl {
            name: "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__basic_string_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@PEBD@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__basic_string_ctor_cstr as *const () as usize,
        },
        FunctionImpl {
            name: "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@AEBV01@@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__basic_string_copy_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__basic_string_dtor as *const () as usize,
        },
        FunctionImpl {
            name: "?c_str@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBAPEBDXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__basic_string_c_str as *const () as usize,
        },
        FunctionImpl {
            name: "?size@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA_KXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__basic_string_size as *const () as usize,
        },
        FunctionImpl {
            name: "?empty@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA_NXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__basic_string_empty as *const () as usize,
        },
        FunctionImpl {
            name: "??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV01@AEBV01@@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__basic_string_assign_op as *const () as usize,
        },
        FunctionImpl {
            name: "??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV01@PEBD@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__basic_string_assign_cstr as *const () as usize,
        },
        FunctionImpl {
            name: "?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV12@PEBD@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__basic_string_append_cstr as *const () as usize,
        },
        // Phase 35: MSVCRT width-counting and wide vsnprintf
        FunctionImpl {
            name: "_vsnwprintf",
            dll_name: "MSVCRT.dll",
            num_params: 4,
            impl_address: crate::msvcrt::msvcrt__vsnwprintf as *const () as usize,
        },
        FunctionImpl {
            name: "_scprintf",
            dll_name: "MSVCRT.dll",
            num_params: 7,
            impl_address: crate::msvcrt::msvcrt__scprintf as *const () as usize,
        },
        FunctionImpl {
            name: "_vscprintf",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__vscprintf as *const () as usize,
        },
        FunctionImpl {
            name: "_scwprintf",
            dll_name: "MSVCRT.dll",
            num_params: 7,
            impl_address: crate::msvcrt::msvcrt__scwprintf as *const () as usize,
        },
        FunctionImpl {
            name: "_vscwprintf",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__vscwprintf as *const () as usize,
        },
        // Phase 35: CRT fd/Win32 handle interop
        FunctionImpl {
            name: "_get_osfhandle",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__get_osfhandle as *const () as usize,
        },
        FunctionImpl {
            name: "_open_osfhandle",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__open_osfhandle as *const () as usize,
        },
        FunctionImpl {
            name: "_wcsdup",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__wcsdup as *const () as usize,
        },
        FunctionImpl {
            name: "__stdio_common_vsscanf",
            dll_name: "MSVCRT.dll",
            num_params: 6,
            impl_address: crate::msvcrt::ucrt__stdio_common_vsscanf as *const () as usize,
        },
        FunctionImpl {
            name: "PostQueuedCompletionStatus",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_PostQueuedCompletionStatus as *const ()
                as usize,
        },
        // bcryptprimitives.dll functions
        FunctionImpl {
            name: "ProcessPrng",
            dll_name: "bcryptprimitives.dll",
            num_params: 2,
            impl_address: crate::bcrypt::bcrypt_ProcessPrng as *const () as usize,
        },
        // USERENV.dll functions
        FunctionImpl {
            name: "GetUserProfileDirectoryW",
            dll_name: "USERENV.dll",
            num_params: 3,
            impl_address: crate::userenv::userenv_GetUserProfileDirectoryW as *const () as usize,
        },
        // Phase 37: UCRT sprintf/snprintf/sprintf_s entry points
        FunctionImpl {
            name: "__stdio_common_vsprintf",
            dll_name: "MSVCRT.dll",
            num_params: 6,
            impl_address: crate::msvcrt::ucrt__stdio_common_vsprintf as *const () as usize,
        },
        FunctionImpl {
            name: "__stdio_common_vsnprintf_s",
            dll_name: "MSVCRT.dll",
            num_params: 7,
            impl_address: crate::msvcrt::ucrt__stdio_common_vsnprintf_s as *const () as usize,
        },
        FunctionImpl {
            name: "__stdio_common_vsprintf_s",
            dll_name: "MSVCRT.dll",
            num_params: 6,
            impl_address: crate::msvcrt::ucrt__stdio_common_vsprintf_s as *const () as usize,
        },
        FunctionImpl {
            name: "__stdio_common_vswprintf",
            dll_name: "MSVCRT.dll",
            num_params: 6,
            impl_address: crate::msvcrt::ucrt__stdio_common_vswprintf as *const () as usize,
        },
        // Phase 37: scanf / fscanf
        FunctionImpl {
            name: "scanf",
            dll_name: "MSVCRT.dll",
            num_params: 17, // 1 fixed (format) + 16 pointer args
            impl_address: crate::msvcrt::msvcrt_scanf as *const () as usize,
        },
        FunctionImpl {
            name: "fscanf",
            dll_name: "MSVCRT.dll",
            num_params: 18,
            impl_address: crate::msvcrt::msvcrt_fscanf as *const () as usize,
        },
        FunctionImpl {
            name: "__stdio_common_vfscanf",
            dll_name: "MSVCRT.dll",
            num_params: 5,
            impl_address: crate::msvcrt::ucrt__stdio_common_vfscanf as *const () as usize,
        },
        // Phase 37: numeric conversion helpers
        FunctionImpl {
            name: "_ultoa",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__ultoa as *const () as usize,
        },
        FunctionImpl {
            name: "_i64toa",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__i64toa as *const () as usize,
        },
        FunctionImpl {
            name: "_ui64toa",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__ui64toa as *const () as usize,
        },
        FunctionImpl {
            name: "_strtoi64",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__strtoi64 as *const () as usize,
        },
        FunctionImpl {
            name: "_strtoui64",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__strtoui64 as *const () as usize,
        },
        FunctionImpl {
            name: "_itow",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__itow as *const () as usize,
        },
        FunctionImpl {
            name: "_ltow",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__ltow as *const () as usize,
        },
        FunctionImpl {
            name: "_ultow",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__ultow as *const () as usize,
        },
        FunctionImpl {
            name: "_i64tow",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__i64tow as *const () as usize,
        },
        FunctionImpl {
            name: "_ui64tow",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__ui64tow as *const () as usize,
        },
        // Phase 38: std::basic_string<wchar_t> (MSVC x64 ABI)
        FunctionImpl {
            name: "??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__basic_wstring_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@PEB_W@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__basic_wstring_ctor_cstr as *const () as usize,
        },
        FunctionImpl {
            name: "??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@AEBV01@@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__basic_wstring_copy_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??1?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__basic_wstring_dtor as *const () as usize,
        },
        FunctionImpl {
            name: "?c_str@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBAPEB_WXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__basic_wstring_c_str as *const () as usize,
        },
        FunctionImpl {
            name: "?size@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBA_KXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__basic_wstring_size as *const () as usize,
        },
        FunctionImpl {
            name: "?empty@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBA_NXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__basic_wstring_empty as *const () as usize,
        },
        FunctionImpl {
            name: "??4?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@AEBV01@@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__basic_wstring_assign_op as *const () as usize,
        },
        FunctionImpl {
            name: "??4?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@PEB_W@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__basic_wstring_assign_cstr as *const ()
                as usize,
        },
        FunctionImpl {
            name: "?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@PEB_W@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__basic_wstring_append_cstr as *const ()
                as usize,
        },
        // Phase 38: _wfindfirst / _wfindnext / _findclose
        FunctionImpl {
            name: "_wfindfirst64i32",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__wfindfirst64i32 as *const () as usize,
        },
        FunctionImpl {
            name: "_wfindnext64i32",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__wfindnext64i32 as *const () as usize,
        },
        FunctionImpl {
            name: "_findclose",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__findclose as *const () as usize,
        },
        // Phase 38: locale-aware printf variants
        FunctionImpl {
            name: "_printf_l",
            dll_name: "MSVCRT.dll",
            num_params: 9,
            impl_address: crate::msvcrt::msvcrt__printf_l as *const () as usize,
        },
        FunctionImpl {
            name: "_fprintf_l",
            dll_name: "MSVCRT.dll",
            num_params: 9,
            impl_address: crate::msvcrt::msvcrt__fprintf_l as *const () as usize,
        },
        FunctionImpl {
            name: "_sprintf_l",
            dll_name: "MSVCRT.dll",
            num_params: 9,
            impl_address: crate::msvcrt::msvcrt__sprintf_l as *const () as usize,
        },
        FunctionImpl {
            name: "_snprintf_l",
            dll_name: "MSVCRT.dll",
            num_params: 9,
            impl_address: crate::msvcrt::msvcrt__snprintf_l as *const () as usize,
        },
        FunctionImpl {
            name: "_wprintf_l",
            dll_name: "MSVCRT.dll",
            num_params: 9,
            impl_address: crate::msvcrt::msvcrt__wprintf_l as *const () as usize,
        },
        // Phase 39: Extended Process Management
        FunctionImpl {
            name: "GetPriorityClass",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetPriorityClass as *const () as usize,
        },
        FunctionImpl {
            name: "SetPriorityClass",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_SetPriorityClass as *const () as usize,
        },
        FunctionImpl {
            name: "GetProcessAffinityMask",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_GetProcessAffinityMask as *const () as usize,
        },
        FunctionImpl {
            name: "SetProcessAffinityMask",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_SetProcessAffinityMask as *const () as usize,
        },
        FunctionImpl {
            name: "FlushInstructionCache",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_FlushInstructionCache as *const () as usize,
        },
        FunctionImpl {
            name: "ReadProcessMemory",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_ReadProcessMemory as *const () as usize,
        },
        FunctionImpl {
            name: "WriteProcessMemory",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_WriteProcessMemory as *const () as usize,
        },
        FunctionImpl {
            name: "VirtualAllocEx",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_VirtualAllocEx as *const () as usize,
        },
        FunctionImpl {
            name: "VirtualFreeEx",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_VirtualFreeEx as *const () as usize,
        },
        FunctionImpl {
            name: "CreateJobObjectW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_CreateJobObjectW as *const () as usize,
        },
        FunctionImpl {
            name: "AssignProcessToJobObject",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_AssignProcessToJobObject as *const () as usize,
        },
        FunctionImpl {
            name: "IsProcessInJob",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_IsProcessInJob as *const () as usize,
        },
        FunctionImpl {
            name: "QueryInformationJobObject",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_QueryInformationJobObject as *const () as usize,
        },
        FunctionImpl {
            name: "SetInformationJobObject",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_SetInformationJobObject as *const () as usize,
        },
        FunctionImpl {
            name: "OpenJobObjectW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_OpenJobObjectW as *const () as usize,
        },
        // Phase 39: Low-level POSIX-style file I/O (MSVCRT.dll)
        FunctionImpl {
            name: "_open",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__open as *const () as usize,
        },
        FunctionImpl {
            name: "_close",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__close as *const () as usize,
        },
        FunctionImpl {
            name: "_lseek",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__lseek as *const () as usize,
        },
        FunctionImpl {
            name: "_lseeki64",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__lseeki64 as *const () as usize,
        },
        FunctionImpl {
            name: "_tell",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__tell as *const () as usize,
        },
        FunctionImpl {
            name: "_telli64",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__telli64 as *const () as usize,
        },
        FunctionImpl {
            name: "_eof",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__eof as *const () as usize,
        },
        FunctionImpl {
            name: "_creat",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__creat as *const () as usize,
        },
        FunctionImpl {
            name: "_commit",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__commit as *const () as usize,
        },
        FunctionImpl {
            name: "_dup",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__dup as *const () as usize,
        },
        FunctionImpl {
            name: "_dup2",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__dup2 as *const () as usize,
        },
        FunctionImpl {
            name: "_chsize",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__chsize as *const () as usize,
        },
        FunctionImpl {
            name: "_chsize_s",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__chsize_s as *const () as usize,
        },
        FunctionImpl {
            name: "_filelength",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__filelength as *const () as usize,
        },
        FunctionImpl {
            name: "_filelengthi64",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__filelengthi64 as *const () as usize,
        },
        // Phase 40: stat functions and wide-path file opens
        FunctionImpl {
            name: "_stat",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__stat as *const () as usize,
        },
        FunctionImpl {
            name: "_stat64",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__stat64 as *const () as usize,
        },
        FunctionImpl {
            name: "_fstat",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__fstat as *const () as usize,
        },
        FunctionImpl {
            name: "_fstat64",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__fstat64 as *const () as usize,
        },
        FunctionImpl {
            name: "_wopen",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__wopen as *const () as usize,
        },
        FunctionImpl {
            name: "_wsopen",
            dll_name: "MSVCRT.dll",
            num_params: 4,
            impl_address: crate::msvcrt::msvcrt__wsopen as *const () as usize,
        },
        FunctionImpl {
            name: "_wstat",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__wstat as *const () as usize,
        },
        FunctionImpl {
            name: "_wstat64",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__wstat64 as *const () as usize,
        },
        // Phase 41: safe sopen variants
        FunctionImpl {
            name: "_sopen_s",
            dll_name: "MSVCRT.dll",
            num_params: 5,
            impl_address: crate::msvcrt::msvcrt__sopen_s as *const () as usize,
        },
        FunctionImpl {
            name: "_wsopen_s",
            dll_name: "MSVCRT.dll",
            num_params: 5,
            impl_address: crate::msvcrt::msvcrt__wsopen_s as *const () as usize,
        },
        // Phase 39: std::vector<char> member functions (msvcp140.dll)
        FunctionImpl {
            name: "??0?$vector@DU?$allocator@D@std@@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__vector_char_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??1?$vector@DU?$allocator@D@std@@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__vector_char_dtor as *const () as usize,
        },
        FunctionImpl {
            name: "?push_back@?$vector@DU?$allocator@D@std@@@std@@QEAAXAEBD@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__vector_char_push_back as *const () as usize,
        },
        FunctionImpl {
            name: "?size@?$vector@DU?$allocator@D@std@@@std@@QEBA_KXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__vector_char_size as *const () as usize,
        },
        FunctionImpl {
            name: "?capacity@?$vector@DU?$allocator@D@std@@@std@@QEBA_KXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__vector_char_capacity as *const () as usize,
        },
        FunctionImpl {
            name: "?clear@?$vector@DU?$allocator@D@std@@@std@@QEAAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__vector_char_clear as *const () as usize,
        },
        FunctionImpl {
            name: "?data@?$vector@DU?$allocator@D@std@@@std@@QEAAPEADXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__vector_char_data_mut as *const () as usize,
        },
        FunctionImpl {
            name: "?data@?$vector@DU?$allocator@D@std@@@std@@QEBAPEBDXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__vector_char_data_const as *const () as usize,
        },
        FunctionImpl {
            name: "?reserve@?$vector@DU?$allocator@D@std@@@std@@QEAAX_K@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__vector_char_reserve as *const () as usize,
        },
        // Phase 41: std::map<void*,void*> stubs (MSVC x64 mangled names)
        FunctionImpl {
            name: "??0?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__map_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??1?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__map_dtor as *const () as usize,
        },
        FunctionImpl {
            name: "?insert@?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAAAEAU?$pair@V?$_Tree_iterator@V?$_Tree_val@U?$_Tree_simple_types@U?$pair@$$CBPEAXPEAX@std@@@std@@@std@@@std@@_N@std@@AEBU?$pair@$$CBPEAXPEAX@2@@2@@Z",
            dll_name: "msvcp140.dll",
            num_params: 3,
            impl_address: crate::msvcp140::msvcp140__map_insert as *const () as usize,
        },
        FunctionImpl {
            name: "?find@?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAAV?$_Tree_iterator@V?$_Tree_val@U?$_Tree_simple_types@U?$pair@$$CBPEAXPEAX@std@@@std@@@std@@@2@AEBQEAX@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__map_find as *const () as usize,
        },
        FunctionImpl {
            name: "?size@?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEBA_KXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__map_size as *const () as usize,
        },
        FunctionImpl {
            name: "?clear@?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__map_clear as *const () as usize,
        },
        // Phase 41: std::ostringstream stubs (MSVC x64 mangled names)
        FunctionImpl {
            name: "??0?$basic_ostringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@H@Z",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__ostringstream_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??1?$basic_ostringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@UEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__ostringstream_dtor as *const () as usize,
        },
        FunctionImpl {
            name: "?str@?$basic_ostringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__ostringstream_str as *const () as usize,
        },
        FunctionImpl {
            name: "?write@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEBD_J@Z",
            dll_name: "msvcp140.dll",
            num_params: 3,
            impl_address: crate::msvcp140::msvcp140__ostringstream_write as *const () as usize,
        },
        FunctionImpl {
            name: "?tellp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__ostringstream_tellp as *const () as usize,
        },
        FunctionImpl {
            name: "?seekp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__ostringstream_seekp as *const () as usize,
        },
        // ── Phase 42: MSVCRT path manipulation ───────────────────────────────
        FunctionImpl {
            name: "_fullpath",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt__fullpath as *const () as usize,
        },
        FunctionImpl {
            name: "_splitpath",
            dll_name: "MSVCRT.dll",
            num_params: 5,
            impl_address: crate::msvcrt::msvcrt__splitpath as *const () as usize,
        },
        FunctionImpl {
            name: "_splitpath_s",
            dll_name: "MSVCRT.dll",
            num_params: 9,
            impl_address: crate::msvcrt::msvcrt__splitpath_s as *const () as usize,
        },
        FunctionImpl {
            name: "_makepath",
            dll_name: "MSVCRT.dll",
            num_params: 5,
            impl_address: crate::msvcrt::msvcrt__makepath as *const () as usize,
        },
        FunctionImpl {
            name: "_makepath_s",
            dll_name: "MSVCRT.dll",
            num_params: 6,
            impl_address: crate::msvcrt::msvcrt__makepath_s as *const () as usize,
        },
        // ── Phase 42: WS2_32 networking ───────────────────────────────────────
        FunctionImpl {
            name: "WSAIoctl",
            dll_name: "WS2_32.dll",
            num_params: 9,
            impl_address: crate::ws2_32::ws2_WSAIoctl as *const () as usize,
        },
        FunctionImpl {
            name: "inet_addr",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_inet_addr as *const () as usize,
        },
        FunctionImpl {
            name: "inet_pton",
            dll_name: "WS2_32.dll",
            num_params: 3,
            impl_address: crate::ws2_32::ws2_inet_pton as *const () as usize,
        },
        FunctionImpl {
            name: "inet_ntop",
            dll_name: "WS2_32.dll",
            num_params: 4,
            impl_address: crate::ws2_32::ws2_inet_ntop as *const () as usize,
        },
        FunctionImpl {
            name: "WSAPoll",
            dll_name: "WS2_32.dll",
            num_params: 3,
            impl_address: crate::ws2_32::ws2_WSAPoll as *const () as usize,
        },
        // ── Phase 42: msvcp140 std::istringstream ────────────────────────────
        FunctionImpl {
            name: "??0?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@H@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__istringstream_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??0?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@H@Z",
            dll_name: "msvcp140.dll",
            num_params: 3,
            impl_address: crate::msvcp140::msvcp140__istringstream_ctor_str as *const () as usize,
        },
        FunctionImpl {
            name: "??1?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@UEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__istringstream_dtor as *const () as usize,
        },
        FunctionImpl {
            name: "?str@?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__istringstream_str as *const () as usize,
        },
        FunctionImpl {
            name: "?str@?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAXAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__istringstream_str_set as *const () as usize,
        },
        FunctionImpl {
            name: "?read@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEAD_J@Z",
            dll_name: "msvcp140.dll",
            num_params: 3,
            impl_address: crate::msvcp140::msvcp140__istringstream_read as *const () as usize,
        },
        FunctionImpl {
            name: "?seekg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__istringstream_seekg as *const () as usize,
        },
        FunctionImpl {
            name: "?tellg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__istringstream_tellg as *const () as usize,
        },
        // Phase 43: MSVCRT directory helpers
        FunctionImpl {
            name: "_getcwd",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__getcwd as *const () as usize,
        },
        FunctionImpl {
            name: "_chdir",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__chdir as *const () as usize,
        },
        FunctionImpl {
            name: "_mkdir",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__mkdir as *const () as usize,
        },
        FunctionImpl {
            name: "_rmdir",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__rmdir as *const () as usize,
        },
        // Phase 43: KERNEL32 volume enumeration
        FunctionImpl {
            name: "FindFirstVolumeW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_FindFirstVolumeW as *const () as usize,
        },
        FunctionImpl {
            name: "FindNextVolumeW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_FindNextVolumeW as *const () as usize,
        },
        FunctionImpl {
            name: "FindVolumeClose",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_FindVolumeClose as *const () as usize,
        },
        // Phase 43: std::stringstream (basic_stringstream<char>) mangled names (MSVC x64)
        FunctionImpl {
            name: "??0?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@H@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__stringstream_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??0?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@H@Z",
            dll_name: "msvcp140.dll",
            num_params: 3,
            impl_address: crate::msvcp140::msvcp140__stringstream_ctor_str as *const () as usize,
        },
        FunctionImpl {
            name: "??1?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@UEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__stringstream_dtor as *const () as usize,
        },
        FunctionImpl {
            name: "?str@?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__stringstream_str as *const () as usize,
        },
        FunctionImpl {
            name: "?str@?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAXAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__stringstream_str_set as *const () as usize,
        },
        FunctionImpl {
            name: "?read@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEAD_J@Z",
            dll_name: "msvcp140.dll",
            num_params: 3,
            impl_address: crate::msvcp140::msvcp140__stringstream_read as *const () as usize,
        },
        FunctionImpl {
            name: "?write@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEBD_J@Z",
            dll_name: "msvcp140.dll",
            num_params: 3,
            impl_address: crate::msvcp140::msvcp140__stringstream_write as *const () as usize,
        },
        FunctionImpl {
            name: "?seekg@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__stringstream_seekg as *const () as usize,
        },
        FunctionImpl {
            name: "?tellg@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__stringstream_tellg as *const () as usize,
        },
        FunctionImpl {
            name: "?seekp@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__stringstream_seekp as *const () as usize,
        },
        FunctionImpl {
            name: "?tellp@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__stringstream_tellp as *const () as usize,
        },
        // Phase 43: std::unordered_map<void*,void*> mangled names (MSVC x64)
        FunctionImpl {
            name: "??0?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__unordered_map_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??1?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__unordered_map_dtor as *const () as usize,
        },
        FunctionImpl {
            name: "?size@?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEBA_KXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__unordered_map_size as *const () as usize,
        },
        FunctionImpl {
            name: "?clear@?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__unordered_map_clear as *const () as usize,
        },
        FunctionImpl {
            name: "?insert@?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA?AV?$pair@_K_N@2@$$QEAV?$pair@PEAXPEAX@2@@Z",
            dll_name: "msvcp140.dll",
            num_params: 3,
            impl_address: crate::msvcp140::msvcp140__unordered_map_insert as *const () as usize,
        },
        FunctionImpl {
            name: "?find@?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA?AV?$pair@_K_N@2@PEAX@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__unordered_map_find as *const () as usize,
        },
        // Phase 44: std::deque<void*>
        FunctionImpl {
            name: "??0?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__deque_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??1?$deque@PEAXV?$allocator@PEAX@std@@@std@@UEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__deque_dtor as *const () as usize,
        },
        FunctionImpl {
            name: "?push_back@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXPEAX@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__deque_push_back as *const () as usize,
        },
        FunctionImpl {
            name: "?push_front@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXPEAX@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__deque_push_front as *const () as usize,
        },
        FunctionImpl {
            name: "?pop_front@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__deque_pop_front as *const () as usize,
        },
        FunctionImpl {
            name: "?pop_back@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__deque_pop_back as *const () as usize,
        },
        FunctionImpl {
            name: "?front@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAAEAPEAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__deque_front as *const () as usize,
        },
        FunctionImpl {
            name: "?back@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAAEAPEAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__deque_back as *const () as usize,
        },
        FunctionImpl {
            name: "?size@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEBA_KXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__deque_size as *const () as usize,
        },
        FunctionImpl {
            name: "?clear@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__deque_clear as *const () as usize,
        },
        // Phase 44: std::stack<void*>
        FunctionImpl {
            name: "??0?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__stack_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??1?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@UEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__stack_dtor as *const () as usize,
        },
        FunctionImpl {
            name: "?push@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAXPEAX@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__stack_push as *const () as usize,
        },
        FunctionImpl {
            name: "?pop@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__stack_pop as *const () as usize,
        },
        FunctionImpl {
            name: "?top@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAAEAPEAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__stack_top as *const () as usize,
        },
        FunctionImpl {
            name: "?size@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEBA_KXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__stack_size as *const () as usize,
        },
        FunctionImpl {
            name: "?empty@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEBA_NXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__stack_empty as *const () as usize,
        },
        // Phase 44: std::queue<void*>
        FunctionImpl {
            name: "??0?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__queue_ctor as *const () as usize,
        },
        FunctionImpl {
            name: "??1?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@UEAA@XZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__queue_dtor as *const () as usize,
        },
        FunctionImpl {
            name: "?push@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAXPEAX@Z",
            dll_name: "msvcp140.dll",
            num_params: 2,
            impl_address: crate::msvcp140::msvcp140__queue_push as *const () as usize,
        },
        FunctionImpl {
            name: "?pop@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__queue_pop as *const () as usize,
        },
        FunctionImpl {
            name: "?front@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAAEAPEAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__queue_front as *const () as usize,
        },
        FunctionImpl {
            name: "?back@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAAEAPEAXXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__queue_back as *const () as usize,
        },
        FunctionImpl {
            name: "?size@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEBA_KXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__queue_size as *const () as usize,
        },
        FunctionImpl {
            name: "?empty@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEBA_NXZ",
            dll_name: "msvcp140.dll",
            num_params: 1,
            impl_address: crate::msvcp140::msvcp140__queue_empty as *const () as usize,
        },
        // Phase 44: MSVCRT temp functions
        FunctionImpl {
            name: "tmpnam",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_tmpnam as *const () as usize,
        },
        FunctionImpl {
            name: "_mktemp",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__mktemp as *const () as usize,
        },
        FunctionImpl {
            name: "_tempnam",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__tempnam as *const () as usize,
        },
        // Phase 44: WS2_32 service/protocol lookup
        FunctionImpl {
            name: "getservbyname",
            dll_name: "WS2_32.dll",
            num_params: 2,
            impl_address: crate::ws2_32::ws2_getservbyname as *const () as usize,
        },
        FunctionImpl {
            name: "getservbyport",
            dll_name: "WS2_32.dll",
            num_params: 2,
            impl_address: crate::ws2_32::ws2_getservbyport as *const () as usize,
        },
        FunctionImpl {
            name: "getprotobyname",
            dll_name: "WS2_32.dll",
            num_params: 1,
            impl_address: crate::ws2_32::ws2_getprotobyname as *const () as usize,
        },
        // Phase 44: KERNEL32 volume paths
        FunctionImpl {
            name: "GetVolumePathNamesForVolumeNameW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetVolumePathNamesForVolumeNameW as *const ()
                as usize,
        },
    ]
}

impl LinuxPlatformForWindows {
    /// Initialize function trampolines for all supported functions
    ///
    /// This generates trampolines that bridge the Windows x64 calling convention
    /// to the System V AMD64 calling convention used by our platform implementations.
    ///
    /// When `verbose` is `true`, logs each trampoline address to stderr as it is
    /// allocated.  Pass `false` to suppress this output.
    ///
    /// # Safety
    /// This function allocates executable memory and writes machine code to it.
    /// The generated trampolines must only be called from Windows x64 calling
    /// convention code.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub unsafe fn initialize_trampolines(&self, verbose: bool) -> Result<()> {
        let function_table = get_function_table();
        let state = self.state.lock().unwrap();

        for func in function_table {
            // Generate trampoline code
            let trampoline_code = generate_trampoline(func.num_params, func.impl_address as u64);

            // Allocate and write the trampoline
            let trampoline_addr = unsafe {
                state.trampoline_manager.allocate_trampoline(
                    format!("{}::{}", func.dll_name, func.name),
                    &trampoline_code,
                )?
            };

            if verbose {
                eprintln!(
                    "Initialized trampoline for {}::{} at 0x{:X}",
                    func.dll_name, func.name, trampoline_addr
                );
            }
        }

        Ok(())
    }

    /// Link trampolines to DLL manager
    ///
    /// This updates the DLL export addresses to use actual trampoline addresses
    /// instead of stub addresses. Must be called after `initialize_trampolines()`.
    ///
    /// When `verbose` is `true`, logs each linked address to stderr.
    /// Pass `false` to suppress this output.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn link_trampolines_to_dll_manager(&self, verbose: bool) -> Result<()> {
        let function_table = get_function_table();
        let mut state = self.state.lock().unwrap();

        for func in function_table {
            // Get the trampoline address
            if let Some(trampoline_addr) = state
                .trampoline_manager
                .get_trampoline(&format!("{}::{}", func.dll_name, func.name))
            {
                // Update the DLL manager with the real address
                state
                    .dll_manager
                    .update_export_address(func.dll_name, func.name, trampoline_addr)
                    .ok(); // Ignore errors - function may not be in DLL exports yet

                if verbose {
                    eprintln!(
                        "Linked trampoline for {}::{} at 0x{:X}",
                        func.dll_name, func.name, trampoline_addr
                    );
                }
            }
        }

        Ok(())
    }

    /// Link data exports to their actual memory addresses
    ///
    /// This updates the DLL manager to point data imports to real memory locations
    /// instead of stub addresses. Must be called after `link_trampolines_to_dll_manager()`.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    ///
    /// # Safety
    /// This function accesses mutable static variables to get their addresses.
    /// It's safe because we only take addresses, not modify the values.
    pub unsafe fn link_data_exports_to_dll_manager(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        // MSVCRT.dll data exports
        // SAFETY: We're only taking the address of the static, not modifying it.
        // These are global variables that C code expects to access directly.
        let data_exports = vec![
            (
                "MSVCRT.dll",
                "_fmode",
                core::ptr::addr_of_mut!(crate::msvcrt::msvcrt__fmode) as usize,
            ),
            (
                "MSVCRT.dll",
                "_commode",
                core::ptr::addr_of_mut!(crate::msvcrt::msvcrt__commode) as usize,
            ),
            (
                "MSVCRT.dll",
                "__initenv",
                core::ptr::addr_of_mut!(crate::msvcrt::msvcrt___initenv) as usize,
            ),
            // Stack-probe functions use a non-standard calling convention (RAX = frame
            // size; must be preserved on return).  They must NOT go through the normal
            // trampoline (which clobbers RAX), so we register them here as direct
            // function addresses.  On Linux the kernel maps stack pages on demand, so
            // a bare `ret` (empty function) is the correct implementation.
            (
                "MSVCRT.dll",
                "__chkstk",
                crate::msvcrt::msvcrt_chkstk_nop as *const () as usize,
            ),
            (
                "MSVCRT.dll",
                "___chkstk_ms",
                crate::msvcrt::msvcrt_chkstk_nop as *const () as usize,
            ),
            (
                "MSVCRT.dll",
                "_alloca_probe",
                crate::msvcrt::msvcrt_chkstk_nop as *const () as usize,
            ),
        ];

        for (dll_name, export_name, address) in data_exports {
            state
                .dll_manager
                .update_export_address(dll_name, export_name, address)
                .ok(); // Ignore errors - export may not be in DLL yet
        }

        Ok(())
    }

    /// Get the trampoline address for a specific function
    ///
    /// Returns the address of the trampoline that can be called from Windows
    /// x64 calling convention code.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn get_trampoline_address(&self, dll_name: &str, function_name: &str) -> Option<usize> {
        let state = self.state.lock().unwrap();
        state
            .trampoline_manager
            .get_trampoline(&format!("{dll_name}::{function_name}"))
    }

    /// Returns all trampoline addresses for registered DLL functions.
    ///
    /// Each element is `(dll_name, function_name, trampoline_address)`.
    /// Must be called after [`initialize_trampolines`](Self::initialize_trampolines).
    /// The returned addresses bridge Windows x64 → System V AMD64 ABI.
    ///
    /// Used by the runner to populate the dynamic-export registry so that
    /// Windows programs can call `LoadLibraryW`/`GetProcAddress` at runtime.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn export_dll_addresses(&self) -> Vec<(String, String, usize)> {
        let state = self.state.lock().unwrap();
        get_function_table()
            .into_iter()
            .filter_map(|f| {
                let key = format!("{}::{}", f.dll_name, f.name);
                let addr = state.trampoline_manager.get_trampoline(&key)?;
                Some((f.dll_name.to_string(), f.name.to_string(), addr))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_table() {
        let table = get_function_table();
        assert!(!table.is_empty());

        // Verify all entries have valid data
        for func in &table {
            assert!(!func.name.is_empty());
            assert!(!func.dll_name.is_empty());
            assert_ne!(func.impl_address, 0);
        }
    }

    #[test]
    fn test_msvc_hello_cli_compat_exports_present() {
        let table = get_function_table();
        let has = |dll: &str, name: &str| {
            table
                .iter()
                .any(|f| f.dll_name.eq_ignore_ascii_case(dll) && f.name == name)
        };

        assert!(has("KERNEL32.dll", "UnhandledExceptionFilter"));
        assert!(has("KERNEL32.dll", "InitializeSListHead"));
        assert!(has("KERNEL32.dll", "WaitForSingleObjectEx"));
        assert!(has("KERNEL32.dll", "GetSystemTimeAsFileTime"));
        assert!(has("MSVCRT.dll", "_get_initial_narrow_environment"));
        assert!(has("MSVCRT.dll", "_set_app_type"));
        assert!(has("MSVCRT.dll", "_exit"));
        assert!(has("MSVCRT.dll", "_c_exit"));
        assert!(has(
            "MSVCRT.dll",
            "_register_thread_local_exe_atexit_callback"
        ));
        assert!(has("MSVCRT.dll", "_seh_filter_exe"));
        assert!(has("MSVCRT.dll", "_initialize_onexit_table"));
        assert!(has("MSVCRT.dll", "_register_onexit_function"));
        assert!(has("MSVCRT.dll", "_set_fmode"));
        assert!(has("MSVCRT.dll", "_set_new_mode"));
    }

    #[test]
    fn test_initialize_trampolines() {
        let platform = LinuxPlatformForWindows::new();

        // SAFETY: We're testing trampoline initialization
        let result = unsafe { platform.initialize_trampolines(false) };
        assert!(result.is_ok());

        // Verify we can retrieve trampoline addresses
        let malloc_addr = platform.get_trampoline_address("MSVCRT.dll", "malloc");
        assert!(malloc_addr.is_some());
        assert_ne!(malloc_addr.unwrap(), 0);

        let free_addr = platform.get_trampoline_address("MSVCRT.dll", "free");
        assert!(free_addr.is_some());
        assert_ne!(free_addr.unwrap(), 0);

        // Addresses should be different
        assert_ne!(malloc_addr, free_addr);
    }

    #[test]
    fn test_get_nonexistent_trampoline() {
        let platform = LinuxPlatformForWindows::new();

        // SAFETY: We're testing trampoline initialization
        let _ = unsafe { platform.initialize_trampolines(false) };

        let addr = platform.get_trampoline_address("KERNEL32.dll", "NonExistentFunction");
        assert!(addr.is_none());
    }

    #[test]
    fn test_link_trampolines_to_dll_manager() {
        let platform = LinuxPlatformForWindows::new();

        // SAFETY: We're testing trampoline initialization and linking
        unsafe {
            platform.initialize_trampolines(false).unwrap();
        }
        platform.link_trampolines_to_dll_manager(false).unwrap();

        // Verify that MSVCRT exports now have trampoline addresses
        let mut state = platform.state.lock().unwrap();

        // Load MSVCRT.dll handle
        let msvcrt_handle = state.dll_manager.load_library("MSVCRT.dll").unwrap();

        // Check that malloc has a trampoline address
        let malloc_addr = state
            .dll_manager
            .get_proc_address(msvcrt_handle, "malloc")
            .unwrap();

        // The address should not be a stub address (< 0x1000 is too low for real code)
        assert!(malloc_addr > 0x1000);

        // Verify it matches the trampoline manager's address
        let trampoline_addr = state
            .trampoline_manager
            .get_trampoline("MSVCRT.dll::malloc");
        assert_eq!(Some(malloc_addr), trampoline_addr);
    }
}
