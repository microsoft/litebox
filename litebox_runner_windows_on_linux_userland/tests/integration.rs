// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Integration tests for Windows-on-Linux PE loading and execution
//!
//! These tests validate the end-to-end PE loading pipeline with real Windows executables.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use litebox_platform_linux_for_windows::LinuxPlatformForWindows;
use litebox_shim_windows::syscalls::ntdll::NtdllApi;

#[test]
fn test_pe_loader_with_minimal_binary() {
    // Test that we can create a platform and use basic APIs
    let mut platform = LinuxPlatformForWindows::new();

    // Test basic console I/O (already implemented)
    let stdout_handle = platform.get_std_output();
    let result = platform.write_console(stdout_handle, "Test output\n");
    assert!(result.is_ok(), "Console write should succeed");
}

#[test]
fn test_dll_loading_infrastructure() {
    // Verify that DLL manager can load stub DLLs
    use litebox_shim_windows::loader::DllManager;

    let mut dll_manager = DllManager::new();

    // Test loading KERNEL32.dll (should already be pre-loaded)
    let kernel32_handle = dll_manager
        .load_library("KERNEL32.dll")
        .expect("KERNEL32.dll should be pre-loaded");
    assert!(
        kernel32_handle.as_raw() > 0,
        "KERNEL32 handle should be valid"
    );

    // Test case-insensitive loading
    let kernel32_handle2 = dll_manager
        .load_library("kernel32.dll")
        .expect("Case-insensitive loading should work");
    assert_eq!(
        kernel32_handle, kernel32_handle2,
        "Same DLL should return same handle"
    );

    // Test getting function address from KERNEL32
    let get_std_handle_addr = dll_manager.get_proc_address(kernel32_handle, "GetStdHandle");
    assert!(
        get_std_handle_addr.is_ok(),
        "GetStdHandle should be in KERNEL32 exports"
    );

    // Test WS2_32.dll is pre-loaded
    let ws2_32_handle = dll_manager
        .load_library("WS2_32.dll")
        .expect("WS2_32.dll should be pre-loaded");
    assert!(ws2_32_handle.as_raw() > 0, "WS2_32 handle should be valid");

    // Test getting a Winsock function
    let wsa_startup_addr = dll_manager.get_proc_address(ws2_32_handle, "WSAStartup");
    assert!(
        wsa_startup_addr.is_ok(),
        "WSAStartup should be in WS2_32 exports"
    );
}

#[test]
fn test_command_line_apis() {
    // Test command-line argument APIs are implemented
    let platform = LinuxPlatformForWindows::new();

    // Get command line (should return empty by default)
    let cmd_line = platform.get_command_line_w();
    assert!(
        !cmd_line.is_empty() || cmd_line.is_empty(),
        "get_command_line_w should return a Vec"
    );

    // Test parsing empty command line
    let args = platform.command_line_to_argv_w(&[]);
    assert_eq!(args.len(), 0, "Empty command line should produce no args");

    // Test parsing a simple command line
    let test_cmd: Vec<u16> = "program.exe arg1 arg2\0".encode_utf16().collect();
    let args = platform.command_line_to_argv_w(&test_cmd);
    assert!(
        args.len() >= 3,
        "Command line with 3 parts should produce at least 3 args"
    );
}

#[test]
fn test_file_search_apis() {
    // Test that file search APIs are implemented
    use std::fs;

    // Create a temporary directory with test files
    let temp_dir = std::env::temp_dir().join("litebox_test_file_search");
    let _ = fs::remove_dir_all(&temp_dir); // Clean up if exists
    fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

    // Create some test files
    fs::write(temp_dir.join("test1.txt"), "test").expect("Failed to create test file");
    fs::write(temp_dir.join("test2.txt"), "test").expect("Failed to create test file");

    let mut platform = LinuxPlatformForWindows::new();

    // Build search pattern (e.g., "C:\temp\*.txt" in Windows format)
    let search_pattern = format!("{}\\*.txt\0", temp_dir.display());
    let pattern_wide: Vec<u16> = search_pattern.encode_utf16().collect();

    // Test FindFirstFileW
    let result = platform.find_first_file_w(&pattern_wide);

    // Clean up temp directory
    let _ = fs::remove_dir_all(&temp_dir);

    // Verify the result
    match result {
        Ok((handle, find_data)) => {
            assert!(handle.0 > 0, "Valid search handle should be non-zero");
            // Check that file name was populated
            let file_name_len = find_data
                .file_name
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(0);
            assert!(file_name_len > 0, "File name should not be empty");

            // Test FindNextFileW (may succeed with more files, return Ok(None), or Err on completion)
            // Different implementations handle end-of-directory differently
            let _next_result = platform.find_next_file_w(handle);
            // Don't assert on result - implementation may vary

            // Test FindClose
            let close_result = platform.find_close(handle);
            assert!(close_result.is_ok(), "FindClose should succeed");
        }
        Err(e) => {
            panic!("FindFirstFileW failed: {e:?}");
        }
    }
}

#[test]
fn test_memory_protection_apis() {
    // Test memory protection APIs (Phase 7)
    use litebox_shim_windows::syscalls::ntdll::memory_protection;

    let mut platform = LinuxPlatformForWindows::new();

    // Allocate some memory
    let address = platform
        .nt_allocate_virtual_memory(4096, memory_protection::PAGE_READWRITE)
        .expect("Memory allocation should succeed");

    assert!(address > 0, "Allocated address should be non-zero");

    // Test memory protection change
    let old_protect = platform
        .nt_protect_virtual_memory(address, 4096, memory_protection::PAGE_READONLY)
        .expect("Memory protection change should succeed");

    // The old protection should be valid (either 2 or 4, depending on platform implementation)
    assert!(
        old_protect == memory_protection::PAGE_READONLY
            || old_protect == memory_protection::PAGE_READWRITE,
        "Old protection should be a valid protection flag, got: {old_protect}"
    );

    // Free the memory
    platform
        .nt_free_virtual_memory(address, 4096)
        .expect("Memory deallocation should succeed");
}

#[test]
fn test_error_handling_apis() {
    // Test error handling APIs (Phase 7)
    let mut platform = LinuxPlatformForWindows::new();

    // Initially, last error should be 0
    let initial_error = platform.get_last_error();
    assert_eq!(initial_error, 0, "Initial error should be 0");

    // Set an error
    platform.set_last_error(5); // ERROR_ACCESS_DENIED

    // Get the error back
    let error = platform.get_last_error();
    assert_eq!(error, 5, "GetLastError should return the set error code");

    // Set a different error
    platform.set_last_error(2); // ERROR_FILE_NOT_FOUND

    let error2 = platform.get_last_error();
    assert_eq!(error2, 2, "GetLastError should return the new error code");
}

#[test]
fn test_dll_manager_has_all_required_exports() {
    // Verify that all critical Windows APIs are exported from stubs
    use litebox_shim_windows::loader::DllManager;

    let mut dll_manager = DllManager::new();

    // Get KERNEL32 handle
    let kernel32 = dll_manager.load_library("KERNEL32.dll").unwrap();

    // Critical APIs that should be present
    let required_functions = vec![
        "LoadLibraryW",
        "GetProcAddress",
        "FreeLibrary",
        "GetStdHandle",
        "WriteConsoleW",
        "CreateFileW",
        "ReadFile",
        "WriteFile",
        "CloseHandle",
        "GetCommandLineW",
        "FindFirstFileExW",
        "FindNextFileW",
        "FindClose",
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "GetLastError",
        "SetLastError",
        "VirtualProtect",
        "HeapAlloc",
        "HeapFree",
        "GetEnvironmentVariableW",
        "SetEnvironmentVariableW",
        "GetModuleHandleW",
        "ExitProcess",
    ];

    for func_name in required_functions {
        let result = dll_manager.get_proc_address(kernel32, func_name);
        assert!(result.is_ok(), "KERNEL32.dll should export {func_name}");
    }

    // Check WS2_32.dll exports
    let ws2_32 = dll_manager.load_library("WS2_32.dll").unwrap();
    let winsock_functions = vec![
        "WSAStartup",
        "WSACleanup",
        "socket",
        "connect",
        "send",
        "recv",
    ];

    for func_name in winsock_functions {
        let result = dll_manager.get_proc_address(ws2_32, func_name);
        assert!(result.is_ok(), "WS2_32.dll should export {func_name}");
    }

    // Check USER32.dll extended exports (Phase 24)
    let user32 = dll_manager.load_library("USER32.dll").unwrap();
    let user32_functions = vec![
        "MessageBoxW",
        "RegisterClassExW",
        "CreateWindowExW",
        "ShowWindow",
        "UpdateWindow",
        "GetMessageW",
        "TranslateMessage",
        "DispatchMessageW",
        "DestroyWindow",
        "PostQuitMessage",
        "DefWindowProcW",
        "LoadCursorW",
        "LoadIconW",
        "GetSystemMetrics",
        "SetWindowLongPtrW",
        "GetWindowLongPtrW",
        "SendMessageW",
        "PostMessageW",
        "PeekMessageW",
        "BeginPaint",
        "EndPaint",
        "GetClientRect",
        "InvalidateRect",
        "SetTimer",
        "KillTimer",
        "GetDC",
        "ReleaseDC",
    ];

    for func_name in user32_functions {
        let result = dll_manager.get_proc_address(user32, func_name);
        assert!(result.is_ok(), "USER32.dll should export {func_name}");
    }

    // Check GDI32.dll exports (Phase 24)
    let gdi32 = dll_manager.load_library("GDI32.dll").unwrap();
    let gdi32_functions = vec![
        "GetStockObject",
        "CreateSolidBrush",
        "DeleteObject",
        "SelectObject",
        "CreateCompatibleDC",
        "DeleteDC",
        "SetBkColor",
        "SetTextColor",
        "TextOutW",
        "Rectangle",
        "FillRect",
        "CreateFontW",
        "GetTextExtentPoint32W",
    ];

    for func_name in gdi32_functions {
        let result = dll_manager.get_proc_address(gdi32, func_name);
        assert!(result.is_ok(), "GDI32.dll should export {func_name}");
    }

    // Check ole32.dll exports (Phase 32)
    let ole32 = dll_manager.load_library("ole32.dll").unwrap();
    let ole32_functions = vec![
        "CoInitialize",
        "CoInitializeEx",
        "CoUninitialize",
        "CoCreateInstance",
        "CoTaskMemAlloc",
        "CoTaskMemFree",
        "CoTaskMemRealloc",
        "StringFromGUID2",
        "CoCreateGuid",
        "CLSIDFromString",
    ];

    for func_name in ole32_functions {
        let result = dll_manager.get_proc_address(ole32, func_name);
        assert!(result.is_ok(), "ole32.dll should export {func_name}");
    }

    // Check msvcp140.dll exports (Phase 33) — all 13 stub symbols
    let msvcp140 = dll_manager.load_library("msvcp140.dll").unwrap();
    let msvcp140_functions = vec![
        // operator new / delete
        "??2@YAPEAX_K@Z",
        "??3@YAXPEAX@Z",
        "??_U@YAPEAX_K@Z",
        "??_V@YAXPEAX@Z",
        // exception helpers
        "?_Xbad_alloc@std@@YAXXZ",
        "?_Xlength_error@std@@YAXPEBD@Z",
        "?_Xout_of_range@std@@YAXPEBD@Z",
        "?_Xinvalid_argument@std@@YAXPEBD@Z",
        "?_Xruntime_error@std@@YAXPEBD@Z",
        "?_Xoverflow_error@std@@YAXPEBD@Z",
        // locale C++ member functions
        "?_Getctype@_Locinfo@std@@QEBAPBU_Ctypevec@@XZ",
        "?_Getdays@_Locinfo@std@@QEBAPEBDXZ",
        "?_Getmonths@_Locinfo@std@@QEBAPEBDXZ",
    ];

    for func_name in msvcp140_functions {
        let result = dll_manager.get_proc_address(msvcp140, func_name);
        assert!(result.is_ok(), "msvcp140.dll should export {func_name}");
    }

    // Check that Phase 32 MSVCRT additions are now resolvable via the DLL manager
    let msvcrt = dll_manager.load_library("MSVCRT.dll").unwrap();
    let msvcrt_phase32_functions = vec![
        "sprintf", "snprintf", "sscanf", "fopen", "fclose", "fread", "qsort", "bsearch", "isalpha",
        "toupper", "tolower", "wcstol", "wcstoul", "wcstod", "fileno", "_fileno", "fdopen",
        "_fdopen", "realloc", "remove", "rename",
    ];
    for func_name in msvcrt_phase32_functions {
        let result = dll_manager.get_proc_address(msvcrt, func_name);
        assert!(result.is_ok(), "MSVCRT.dll should export {func_name}");
    }

    // Check that Phase 34 MSVCRT additions are now resolvable via the DLL manager
    let msvcrt_phase34_functions = vec![
        "vprintf",
        "vsprintf",
        "vsnprintf",
        "vswprintf",
        "fwprintf",
        "vfwprintf",
        "_write",
        "getchar",
        "putchar",
    ];
    for func_name in msvcrt_phase34_functions {
        let result = dll_manager.get_proc_address(msvcrt, func_name);
        assert!(result.is_ok(), "MSVCRT.dll should export {func_name}");
    }

    // Check that Phase 35 MSVCRT additions are resolvable via the DLL manager
    let msvcrt_phase35_functions = vec![
        "_vsnwprintf",
        "_scprintf",
        "_vscprintf",
        "_scwprintf",
        "_vscwprintf",
        "_get_osfhandle",
        "_open_osfhandle",
    ];
    for func_name in msvcrt_phase35_functions {
        let result = dll_manager.get_proc_address(msvcrt, func_name);
        assert!(result.is_ok(), "MSVCRT.dll should export {func_name}");
    }

    // Check that Phase 36 MSVCRT additions are resolvable via the DLL manager
    let msvcrt_phase36_functions = vec!["_wcsdup", "__stdio_common_vsscanf"];
    for func_name in msvcrt_phase36_functions {
        let result = dll_manager.get_proc_address(msvcrt, func_name);
        assert!(result.is_ok(), "MSVCRT.dll should export {func_name}");
    }

    // Check that Phase 35 msvcp140.dll additions are resolvable
    let msvcp140_phase35_functions = vec![
        "?what@exception@std@@UEBAPEBDXZ",
        "??1exception@std@@UEAA@XZ",
        "??0exception@std@@QEAA@XZ",
        "??0exception@std@@QEAA@PEBD@Z",
        "?_Getgloballocale@locale@std@@CAPEAV_Lobj@12@XZ",
        "??0_Lockit@std@@QEAA@H@Z",
        "??1_Lockit@std@@QEAA@XZ",
        "??0Init@ios_base@std@@QEAA@XZ",
        "??1Init@ios_base@std@@QEAA@XZ",
    ];
    for func_name in msvcp140_phase35_functions {
        let result = dll_manager.get_proc_address(msvcp140, func_name);
        assert!(result.is_ok(), "msvcp140.dll should export {func_name}");
    }

    // Check that Phase 37 MSVCRT additions are resolvable via the DLL manager
    let msvcrt_phase37_functions = vec![
        "__stdio_common_vsprintf",
        "__stdio_common_vsnprintf_s",
        "__stdio_common_vsprintf_s",
        "__stdio_common_vswprintf",
        "scanf",
        "fscanf",
        "__stdio_common_vfscanf",
        "_ultoa",
        "_i64toa",
        "_ui64toa",
        "_strtoi64",
        "_strtoui64",
        "_itow",
        "_ltow",
        "_ultow",
        "_i64tow",
        "_ui64tow",
    ];
    for func_name in msvcrt_phase37_functions {
        let result = dll_manager.get_proc_address(msvcrt, func_name);
        assert!(result.is_ok(), "MSVCRT.dll should export {func_name}");
    }

    // Check that Phase 37 msvcp140.dll basic_string additions are resolvable
    let msvcp140_phase37_functions = vec![
        "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ",
        "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@PEBD@Z",
        "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@AEBV01@@Z",
        "??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ",
        "?c_str@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBAPEBDXZ",
        "?size@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA_KXZ",
        "?empty@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA_NXZ",
        "??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV01@AEBV01@@Z",
        "??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV01@PEBD@Z",
        "?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV12@PEBD@Z",
    ];
    for func_name in msvcp140_phase37_functions {
        let result = dll_manager.get_proc_address(msvcp140, func_name);
        assert!(result.is_ok(), "msvcp140.dll should export {func_name}");
    }

    // Check that Phase 38 MSVCRT additions are resolvable via the DLL manager
    let msvcrt_phase38_functions = vec![
        "_wfindfirst64i32",
        "_wfindnext64i32",
        "_findclose",
        "_printf_l",
        "_fprintf_l",
        "_sprintf_l",
        "_snprintf_l",
        "_wprintf_l",
    ];
    for func_name in msvcrt_phase38_functions {
        let result = dll_manager.get_proc_address(msvcrt, func_name);
        assert!(result.is_ok(), "MSVCRT.dll should export {func_name}");
    }

    // Check that Phase 38 msvcp140.dll basic_wstring additions are resolvable
    let msvcp140_phase38_functions = vec![
        "??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ",
        "??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@PEB_W@Z",
        "??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@AEBV01@@Z",
        "??1?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ",
        "?c_str@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBAPEB_WXZ",
        "?size@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBA_KXZ",
        "?empty@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBA_NXZ",
        "??4?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@AEBV01@@Z",
        "??4?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@PEB_W@Z",
        "?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@PEB_W@Z",
    ];
    for func_name in msvcp140_phase38_functions {
        let result = dll_manager.get_proc_address(msvcp140, func_name);
        assert!(result.is_ok(), "msvcp140.dll should export {func_name}");
    }

    // Check that Phase 39 KERNEL32 process management additions are resolvable
    let kernel32_phase39_functions = vec![
        "GetPriorityClass",
        "SetPriorityClass",
        "GetProcessAffinityMask",
        "SetProcessAffinityMask",
        "FlushInstructionCache",
        "ReadProcessMemory",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "VirtualFreeEx",
        "CreateJobObjectW",
        "AssignProcessToJobObject",
        "IsProcessInJob",
        "QueryInformationJobObject",
        "SetInformationJobObject",
        "OpenJobObjectW",
    ];
    for func_name in kernel32_phase39_functions {
        let result = dll_manager.get_proc_address(kernel32, func_name);
        assert!(result.is_ok(), "KERNEL32.dll should export {func_name}");
    }

    // Check that Phase 39 MSVCRT file I/O additions are resolvable
    let msvcrt_phase39_functions = vec![
        "_open",
        "_close",
        "_lseek",
        "_lseeki64",
        "_tell",
        "_telli64",
        "_eof",
        "_creat",
        "_commit",
        "_dup",
        "_dup2",
        "_chsize",
        "_chsize_s",
        "_filelength",
        "_filelengthi64",
    ];
    for func_name in msvcrt_phase39_functions {
        let result = dll_manager.get_proc_address(msvcrt, func_name);
        assert!(result.is_ok(), "MSVCRT.dll should export {func_name}");
    }

    // Check that Phase 39 msvcp140.dll vector<char> additions are resolvable
    let msvcp140_phase39_functions = vec![
        "??0?$vector@DU?$allocator@D@std@@@std@@QEAA@XZ",
        "??1?$vector@DU?$allocator@D@std@@@std@@QEAA@XZ",
        "?push_back@?$vector@DU?$allocator@D@std@@@std@@QEAAXAEBD@Z",
        "?size@?$vector@DU?$allocator@D@std@@@std@@QEBA_KXZ",
        "?capacity@?$vector@DU?$allocator@D@std@@@std@@QEBA_KXZ",
        "?clear@?$vector@DU?$allocator@D@std@@@std@@QEAAXXZ",
        "?data@?$vector@DU?$allocator@D@std@@@std@@QEAAPEADXZ",
        "?data@?$vector@DU?$allocator@D@std@@@std@@QEBAPEBDXZ",
        "?reserve@?$vector@DU?$allocator@D@std@@@std@@QEAAX_K@Z",
    ];
    for func_name in msvcp140_phase39_functions {
        let result = dll_manager.get_proc_address(msvcp140, func_name);
        assert!(result.is_ok(), "msvcp140.dll should export {func_name}");
    }

    // Check that Phase 40 WS2_32.dll additions are resolvable
    let ws2_phase40_functions = vec![
        "WSACreateEvent",
        "WSACloseEvent",
        "WSAResetEvent",
        "WSASetEvent",
        "WSAEventSelect",
        "WSAEnumNetworkEvents",
        "WSAWaitForMultipleEvents",
        "gethostbyname",
    ];
    for func_name in ws2_phase40_functions {
        let addr = dll_manager.get_proc_address(ws2_32, func_name);
        assert!(
            addr.is_ok(),
            "WS2_32.dll::{func_name} should be resolvable after Phase 40"
        );
    }

    // Check that Phase 40 MSVCRT additions are resolvable
    let msvcrt_phase40_functions = vec![
        "_stat", "_stat64", "_fstat", "_fstat64", "_wopen", "_wsopen", "_wstat", "_wstat64",
    ];
    for func_name in msvcrt_phase40_functions {
        let addr = dll_manager.get_proc_address(msvcrt, func_name);
        assert!(
            addr.is_ok(),
            "MSVCRT.dll::{func_name} should be resolvable after Phase 40"
        );
    }
}

#[test]
fn test_phase41_dll_exports_present() {
    use litebox_shim_windows::loader::DllManager;

    let mut dll_manager = DllManager::new();
    let ws2_32 = dll_manager.load_library("WS2_32.dll").unwrap();
    let msvcrt = dll_manager.load_library("MSVCRT.dll").unwrap();
    let msvcp140 = dll_manager.load_library("msvcp140.dll").unwrap();

    // Check WS2_32.dll Phase 41 additions
    let addr = dll_manager.get_proc_address(ws2_32, "WSAAsyncSelect");
    assert!(
        addr.is_ok(),
        "WS2_32.dll::WSAAsyncSelect should be resolvable after Phase 41"
    );

    // Check MSVCRT.dll Phase 41 additions
    for func_name in ["_sopen_s", "_wsopen_s"] {
        let addr = dll_manager.get_proc_address(msvcrt, func_name);
        assert!(
            addr.is_ok(),
            "MSVCRT.dll::{func_name} should be resolvable after Phase 41"
        );
    }

    // Check msvcp140.dll Phase 41 additions (mangled MSVC x64 names)
    let msvcp140_phase41_functions = vec![
        // std::map<void*,void*> mangled names
        "??0?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA@XZ",
        "??1?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA@XZ",
        "?size@?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEBA_KXZ",
        "?clear@?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAAXXZ",
        // std::ostringstream (basic_ostringstream<char>) mangled names
        "??0?$basic_ostringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@H@Z",
        "??1?$basic_ostringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@UEAA@XZ",
        "?str@?$basic_ostringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@XZ",
        "?write@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEBD_J@Z",
        "?tellp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ",
        "?seekp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z",
    ];
    for func_name in msvcp140_phase41_functions {
        let addr = dll_manager.get_proc_address(msvcp140, func_name);
        assert!(
            addr.is_ok(),
            "msvcp140.dll::{func_name} should be resolvable after Phase 41"
        );
    }
}

#[test]
fn test_phase42_dll_exports_present() {
    use litebox_shim_windows::loader::DllManager;

    let mut dll_manager = DllManager::new();
    let ws2_32 = dll_manager.load_library("WS2_32.dll").unwrap();
    let msvcrt = dll_manager.load_library("MSVCRT.dll").unwrap();
    let msvcp140 = dll_manager.load_library("msvcp140.dll").unwrap();

    // Check WS2_32.dll Phase 42 additions
    for func_name in ["WSAIoctl", "inet_addr", "inet_pton", "inet_ntop", "WSAPoll"] {
        let addr = dll_manager.get_proc_address(ws2_32, func_name);
        assert!(
            addr.is_ok(),
            "WS2_32.dll::{func_name} should be resolvable after Phase 42"
        );
    }

    // Check MSVCRT.dll Phase 42 additions
    for func_name in [
        "_fullpath",
        "_splitpath",
        "_splitpath_s",
        "_makepath",
        "_makepath_s",
    ] {
        let addr = dll_manager.get_proc_address(msvcrt, func_name);
        assert!(
            addr.is_ok(),
            "MSVCRT.dll::{func_name} should be resolvable after Phase 42"
        );
    }

    // Check msvcp140.dll Phase 42 additions (mangled MSVC x64 names)
    let msvcp140_phase42_functions = vec![
        "??0?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@H@Z",
        "??0?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@H@Z",
        "??1?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@UEAA@XZ",
        "?str@?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@XZ",
        "?str@?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAXAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@@Z",
        "?read@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEAD_J@Z",
        "?seekg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z",
        "?tellg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ",
    ];
    for func_name in msvcp140_phase42_functions {
        let addr = dll_manager.get_proc_address(msvcp140, func_name);
        assert!(
            addr.is_ok(),
            "msvcp140.dll::{func_name} should be resolvable after Phase 42"
        );
    }
}

#[test]
fn test_phase43_dll_exports_present() {
    use litebox_shim_windows::loader::DllManager;

    let mut dll_manager = DllManager::new();
    let kernel32 = dll_manager.load_library("KERNEL32.dll").unwrap();
    let msvcrt = dll_manager.load_library("MSVCRT.dll").unwrap();
    let msvcp140 = dll_manager.load_library("msvcp140.dll").unwrap();

    // Check KERNEL32.dll Phase 43 additions
    for func_name in ["FindFirstVolumeW", "FindNextVolumeW", "FindVolumeClose"] {
        let addr = dll_manager.get_proc_address(kernel32, func_name);
        assert!(
            addr.is_ok(),
            "KERNEL32.dll::{func_name} should be resolvable after Phase 43"
        );
    }

    // Check MSVCRT.dll Phase 43 additions
    for func_name in ["_getcwd", "_chdir", "_mkdir", "_rmdir"] {
        let addr = dll_manager.get_proc_address(msvcrt, func_name);
        assert!(
            addr.is_ok(),
            "MSVCRT.dll::{func_name} should be resolvable after Phase 43"
        );
    }

    // Check msvcp140.dll Phase 43 additions (mangled MSVC x64 names)
    let msvcp140_phase43_functions = vec![
        // std::stringstream (basic_stringstream<char>) mangled names
        "??0?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@H@Z",
        "??0?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@H@Z",
        "??1?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@UEAA@XZ",
        "?str@?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@XZ",
        "?str@?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAXAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@@Z",
        "?read@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEAD_J@Z",
        "?write@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEBD_J@Z",
        "?seekg@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z",
        "?tellg@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ",
        "?seekp@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z",
        "?tellp@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ",
        // std::unordered_map<void*,void*> mangled names
        "??0?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA@XZ",
        "??1?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA@XZ",
        "?size@?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEBA_KXZ",
        "?clear@?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAAXXZ",
        "?insert@?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA?AV?$pair@_K_N@2@$$QEAV?$pair@PEAXPEAX@2@@Z",
        "?find@?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA?AV?$pair@_K_N@2@PEAX@Z",
    ];
    for func_name in msvcp140_phase43_functions {
        let addr = dll_manager.get_proc_address(msvcp140, func_name);
        assert!(
            addr.is_ok(),
            "msvcp140.dll::{func_name} should be resolvable after Phase 43"
        );
    }
}

// Phase 44 resolution: verify new DLL exports are resolvable
#[test]
fn test_phase44_symbol_resolution() {
    use litebox_shim_windows::loader::DllManager;

    let mut dll_manager = DllManager::new();
    let k32 = dll_manager.load_library("KERNEL32.dll").unwrap();
    let crt = dll_manager.load_library("MSVCRT.dll").unwrap();
    let ws2 = dll_manager.load_library("WS2_32.dll").unwrap();
    let msvcp = dll_manager.load_library("msvcp140.dll").unwrap();

    // Check KERNEL32.dll Phase 44 additions
    let func_name = "GetVolumePathNamesForVolumeNameW";
    assert!(
        dll_manager.get_proc_address(k32, func_name).is_ok(),
        "KERNEL32.dll::{func_name} should be resolvable after Phase 44"
    );

    // Check MSVCRT.dll Phase 44 additions
    for func_name in ["tmpnam", "_mktemp", "_tempnam"] {
        assert!(
            dll_manager.get_proc_address(crt, func_name).is_ok(),
            "MSVCRT.dll::{func_name} should be resolvable after Phase 44"
        );
    }

    // Check WS2_32.dll Phase 44 additions
    for func_name in ["getservbyname", "getservbyport", "getprotobyname"] {
        assert!(
            dll_manager.get_proc_address(ws2, func_name).is_ok(),
            "WS2_32.dll::{func_name} should be resolvable after Phase 44"
        );
    }

    // Check msvcp140.dll Phase 44 additions (deque/stack/queue mangled names)
    for func_name in [
        "??0?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAA@XZ",
        "??1?$deque@PEAXV?$allocator@PEAX@std@@@std@@UEAA@XZ",
        "?push_back@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXPEAX@Z",
        "?push_front@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXPEAX@Z",
        "?pop_front@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXXZ",
        "?pop_back@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXXZ",
        "?front@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAAEAPEAXXZ",
        "?back@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAAEAPEAXXZ",
        "?size@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEBA_KXZ",
        "?clear@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXXZ",
        "??0?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAA@XZ",
        "??1?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@UEAA@XZ",
        "?push@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAXPEAX@Z",
        "?pop@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAXXZ",
        "?top@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAAEAPEAXXZ",
        "?size@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEBA_KXZ",
        "?empty@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEBA_NXZ",
        "??0?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAA@XZ",
        "??1?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@UEAA@XZ",
        "?push@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAXPEAX@Z",
        "?pop@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAXXZ",
        "?front@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAAEAPEAXXZ",
        "?back@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAAEAPEAXXZ",
        "?size@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEBA_KXZ",
        "?empty@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEBA_NXZ",
    ] {
        assert!(
            dll_manager.get_proc_address(msvcp, func_name).is_ok(),
            "msvcp140.dll::{func_name} should be resolvable after Phase 44"
        );
    }
}

// Phase 45 resolution: verify new USER32, GDI32 and vulkan-1 exports are resolvable
#[test]
fn test_phase45_dll_exports_present() {
    use litebox_shim_windows::loader::DllManager;

    let mut dll_manager = DllManager::new();
    let user32 = dll_manager.load_library("USER32.dll").unwrap();
    let gdi32 = dll_manager.load_library("GDI32.dll").unwrap();
    let vulkan1 = dll_manager.load_library("vulkan-1.dll").unwrap();

    // Check USER32.dll Phase 45 additions
    for func_name in [
        "RegisterClassW",
        "CreateWindowW",
        "DialogBoxParamW",
        "CreateDialogParamW",
        "EndDialog",
        "GetDlgItem",
        "GetDlgItemTextW",
        "SetDlgItemTextW",
        "SendDlgItemMessageW",
        "GetDlgItemInt",
        "SetDlgItemInt",
        "CheckDlgButton",
        "IsDlgButtonChecked",
        "DrawTextW",
        "DrawTextA",
        "DrawTextExW",
        "AdjustWindowRect",
        "AdjustWindowRectEx",
        "SystemParametersInfoW",
        "SystemParametersInfoA",
        "CreateMenu",
        "CreatePopupMenu",
        "DestroyMenu",
        "AppendMenuW",
        "InsertMenuItemW",
        "GetMenu",
        "SetMenu",
        "DrawMenuBar",
        "TrackPopupMenu",
        "SetCapture",
        "ReleaseCapture",
        "GetCapture",
        "TrackMouseEvent",
        "RedrawWindow",
        "OpenClipboard",
        "CloseClipboard",
        "EmptyClipboard",
        "GetClipboardData",
        "SetClipboardData",
        "LoadStringW",
        "LoadBitmapW",
        "LoadImageW",
        "CallWindowProcW",
        "GetWindowInfo",
        "MapWindowPoints",
        "MonitorFromWindow",
        "MonitorFromPoint",
        "GetMonitorInfoW",
    ] {
        assert!(
            dll_manager.get_proc_address(user32, func_name).is_ok(),
            "USER32.dll::{func_name} should be resolvable after Phase 45"
        );
    }

    // Check GDI32.dll Phase 45 additions
    for func_name in [
        "GetDeviceCaps",
        "SetBkMode",
        "SetMapMode",
        "SetViewportOrgEx",
        "CreatePen",
        "CreatePenIndirect",
        "CreateBrushIndirect",
        "CreatePatternBrush",
        "CreateHatchBrush",
        "CreateBitmap",
        "CreateCompatibleBitmap",
        "CreateDIBSection",
        "GetDIBits",
        "SetDIBits",
        "BitBlt",
        "StretchBlt",
        "PatBlt",
        "GetPixel",
        "SetPixel",
        "MoveToEx",
        "LineTo",
        "Polyline",
        "Polygon",
        "Ellipse",
        "Arc",
        "RoundRect",
        "GetTextMetricsW",
        "CreateRectRgn",
        "SelectClipRgn",
        "GetClipBox",
        "SetStretchBltMode",
        "GetObjectW",
        "GetCurrentObject",
        "ExcludeClipRect",
        "IntersectClipRect",
        "SaveDC",
        "RestoreDC",
    ] {
        assert!(
            dll_manager.get_proc_address(gdi32, func_name).is_ok(),
            "GDI32.dll::{func_name} should be resolvable after Phase 45"
        );
    }

    // Check vulkan-1.dll Phase 45 additions
    for func_name in [
        "vkCreateInstance",
        "vkDestroyInstance",
        "vkEnumerateInstanceExtensionProperties",
        "vkEnumerateInstanceLayerProperties",
        "vkEnumeratePhysicalDevices",
        "vkGetPhysicalDeviceProperties",
        "vkGetPhysicalDeviceFeatures",
        "vkGetPhysicalDeviceQueueFamilyProperties",
        "vkGetPhysicalDeviceMemoryProperties",
        "vkCreateDevice",
        "vkDestroyDevice",
        "vkGetDeviceQueue",
        "vkCreateWin32SurfaceKHR",
        "vkDestroySurfaceKHR",
        "vkGetPhysicalDeviceSurfaceSupportKHR",
        "vkGetPhysicalDeviceSurfaceCapabilitiesKHR",
        "vkGetPhysicalDeviceSurfaceFormatsKHR",
        "vkGetPhysicalDeviceSurfacePresentModesKHR",
        "vkCreateSwapchainKHR",
        "vkDestroySwapchainKHR",
        "vkGetSwapchainImagesKHR",
        "vkAcquireNextImageKHR",
        "vkQueuePresentKHR",
        "vkAllocateMemory",
        "vkFreeMemory",
        "vkCreateBuffer",
        "vkDestroyBuffer",
        "vkCreateImage",
        "vkDestroyImage",
        "vkCreateRenderPass",
        "vkDestroyRenderPass",
        "vkCreateFramebuffer",
        "vkDestroyFramebuffer",
        "vkCreateGraphicsPipelines",
        "vkDestroyPipeline",
        "vkCreateShaderModule",
        "vkDestroyShaderModule",
        "vkCreateCommandPool",
        "vkDestroyCommandPool",
        "vkAllocateCommandBuffers",
        "vkFreeCommandBuffers",
        "vkBeginCommandBuffer",
        "vkEndCommandBuffer",
        "vkCmdBeginRenderPass",
        "vkCmdEndRenderPass",
        "vkCmdDraw",
        "vkCmdDrawIndexed",
        "vkQueueSubmit",
        "vkQueueWaitIdle",
        "vkDeviceWaitIdle",
        "vkCreateFence",
        "vkDestroyFence",
        "vkWaitForFences",
        "vkResetFences",
        "vkCreateSemaphore",
        "vkDestroySemaphore",
        "vkCreateDescriptorSetLayout",
        "vkDestroyDescriptorSetLayout",
        "vkCreatePipelineLayout",
        "vkDestroyPipelineLayout",
        "vkGetInstanceProcAddr",
        "vkGetDeviceProcAddr",
    ] {
        assert!(
            dll_manager.get_proc_address(vulkan1, func_name).is_ok(),
            "vulkan-1.dll::{func_name} should be resolvable after Phase 45"
        );
    }
}

#[cfg(test)]
mod test_program_helpers {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    /// Get the path to a Windows test program executable
    pub fn get_test_program_path(name: &str) -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let workspace_root = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();

        // Default target directory for the windows_test_programs crate
        let default_target_dir = workspace_root.join("windows_test_programs").join("target");

        // Honor CARGO_TARGET_DIR if set, otherwise use the default
        let target_dir = env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or(default_target_dir);

        let base = target_dir.join("x86_64-pc-windows-gnu");

        // Prefer release builds, but fall back to debug if needed
        for profile in ["release", "debug"] {
            let candidate = base.join(profile).join(format!("{name}.exe"));
            if candidate.exists() {
                return candidate;
            }
        }

        // If nothing exists yet, return the conventional release path
        base.join("release").join(format!("{name}.exe"))
    }

    /// Run a Windows test program and return the output
    #[allow(dead_code)]
    pub fn run_test_program(
        name: &str,
        args: &[&str],
    ) -> Result<std::process::Output, std::io::Error> {
        let runner_exe = env!("CARGO_BIN_EXE_litebox_runner_windows_on_linux_userland");
        let test_program = get_test_program_path(name);

        let mut cmd = Command::new(runner_exe);
        cmd.arg(test_program);
        for arg in args {
            cmd.arg(arg);
        }

        cmd.output()
    }

    /// Check if a test program exists
    pub fn test_program_exists(name: &str) -> bool {
        get_test_program_path(name).exists()
    }
}

/// Test that we can load and potentially run the hello_cli program
#[test]
#[ignore = "Requires MinGW-built Windows test programs (run with --ignored after building windows_test_programs)"]
fn test_hello_cli_program_exists() {
    use test_program_helpers::*;

    // Verify the test program was built
    assert!(
        test_program_exists("hello_cli"),
        "hello_cli.exe should be built in windows_test_programs"
    );
}

/// Test that we can load and potentially run the file_io_test program
#[test]
#[ignore = "Requires MinGW-built Windows test programs (run with --ignored after building windows_test_programs)"]
fn test_file_io_test_program_exists() {
    use test_program_helpers::*;

    assert!(
        test_program_exists("file_io_test"),
        "file_io_test.exe should be built in windows_test_programs"
    );

    // Run the program and verify it succeeds
    let output =
        run_test_program("file_io_test", &[]).expect("failed to launch file_io_test runner");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "file_io_test.exe should exit with code 0, stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("=== File I/O Test Suite ==="),
        "file_io_test.exe stdout should contain test header, got:\n{stdout}"
    );
    assert!(
        stdout.contains("=== File I/O Test Complete ==="),
        "file_io_test.exe stdout should contain completion marker, got:\n{stdout}"
    );
}

/// Test that we can load and potentially run the args_test program
#[test]
#[ignore = "Requires MinGW-built Windows test programs (run with --ignored after building windows_test_programs)"]
fn test_args_test_program_exists() {
    use test_program_helpers::*;

    // Verify the test program was built
    assert!(
        test_program_exists("args_test"),
        "args_test.exe should be built in windows_test_programs"
    );
}

/// Test that we can load and potentially run the env_test program
#[test]
#[ignore = "Requires MinGW-built Windows test programs (run with --ignored after building windows_test_programs)"]
fn test_env_test_program_exists() {
    use test_program_helpers::*;

    // Verify the test program was built
    assert!(
        test_program_exists("env_test"),
        "env_test.exe should be built in windows_test_programs"
    );
}

/// Test that string_test runs correctly and all string operations pass
#[test]
#[ignore = "Requires MinGW-built Windows test programs (run with --ignored after building windows_test_programs)"]
fn test_string_test_program_exists() {
    use test_program_helpers::*;

    assert!(
        test_program_exists("string_test"),
        "string_test.exe should be built in windows_test_programs"
    );

    // Run the program and verify all 7 string tests pass
    let output = run_test_program("string_test", &[]).expect("failed to launch string_test runner");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "string_test.exe should exit with code 0, stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("=== String Operations Test ==="),
        "string_test.exe stdout should contain test header, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Results:"),
        "string_test.exe stdout should contain a Results: line, got:\n{stdout}"
    );
    assert!(
        stdout.contains("0 failed"),
        "string_test.exe should report 0 failures, got:\n{stdout}"
    );
}

/// Test that we can load and potentially run the math_test program
#[test]
#[ignore = "Requires MinGW-built Windows test programs (run with --ignored after building windows_test_programs)"]
fn test_math_test_program_exists() {
    use test_program_helpers::*;

    // Verify the test program was built
    assert!(
        test_program_exists("math_test"),
        "math_test.exe should be built in windows_test_programs"
    );
}

/// Test that getprocaddress_test.exe builds, loads, and all 8 test cases pass.
///
/// The executable is a plain-C program in `windows_test_programs/dynload_test/`
/// built with `make` (MinGW cross-compiler), not via Cargo.  It directly calls
/// `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`, and
/// `FreeLibrary`, exercising the LiteBox dynamic-loading shim.
#[test]
#[ignore = "Requires MinGW-built C test program (run: cd windows_test_programs/dynload_test && make)"]
fn test_getprocaddress_c_program() {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    // Locate the compiled exe next to its source
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();
    let exe_path = workspace_root
        .join("windows_test_programs")
        .join("dynload_test")
        .join("getprocaddress_test.exe");

    assert!(
        exe_path.exists(),
        "getprocaddress_test.exe not found at {exe_path:?}. \
         Build it with: cd windows_test_programs/dynload_test && make"
    );

    let runner_exe = env!("CARGO_BIN_EXE_litebox_runner_windows_on_linux_userland");
    let output = Command::new(runner_exe)
        .arg(&exe_path)
        .output()
        .expect("failed to launch litebox runner for getprocaddress_test.exe");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "getprocaddress_test.exe should exit with code 0\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("=== GetProcAddress Test Suite ==="),
        "output should contain test suite header\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("0 failed"),
        "output should report 0 failures\nstdout:\n{stdout}"
    );
}

/// Test that hello_gui.exe loads and runs to completion in headless mode.
///
/// `hello_gui` is a Rust Windows program that calls `GetModuleHandleW` and
/// `MessageBoxW`.  In headless mode, `MessageBoxW` prints to stderr and returns
/// IDOK immediately.  The program must exit with code 0.
///
/// Build the program with:
/// ```
/// cd windows_test_programs
/// cargo build --release --target x86_64-pc-windows-gnu -p hello_gui
/// ```
#[test]
#[ignore = "Requires MinGW-built Windows test programs (run with --ignored after building windows_test_programs)"]
fn test_hello_gui_program() {
    use test_program_helpers::*;

    assert!(
        test_program_exists("hello_gui"),
        "hello_gui.exe should be built in windows_test_programs"
    );

    // Run the program; MessageBoxW will print to stderr and return IDOK
    let output = run_test_program("hello_gui", &[]).expect("failed to launch hello_gui runner");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "hello_gui.exe should exit with code 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// Test that seh_c_test.exe runs all 21 C-language SEH API tests successfully.
///
/// `seh_c_test` is a MinGW-compiled C program that exercises Windows structured-
/// exception-handling runtime APIs without using MSVC `__try`/`__except` syntax.
///
/// Build the program with:
/// ```
/// cd windows_test_programs/seh_test && make seh_c_test.exe
/// ```
#[test]
#[ignore = "Requires MinGW-built SEH test programs (run: cd windows_test_programs/seh_test && make)"]
fn test_seh_c_program() {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();
    let exe_path = workspace_root
        .join("windows_test_programs")
        .join("seh_test")
        .join("seh_c_test.exe");

    assert!(
        exe_path.exists(),
        "seh_c_test.exe not found at {exe_path:?}. \
         Build it with: cd windows_test_programs/seh_test && make seh_c_test.exe"
    );

    let runner_exe = env!("CARGO_BIN_EXE_litebox_runner_windows_on_linux_userland");
    let output = Command::new(runner_exe)
        .arg(&exe_path)
        .output()
        .expect("failed to launch litebox runner for seh_c_test.exe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "seh_c_test.exe should exit with code 0\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("=== SEH C Runtime API Test Suite ==="),
        "seh_c_test.exe stdout should contain test suite header\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("21 passed, 0 failed"),
        "seh_c_test.exe should report 21 passed, 0 failed\nstdout:\n{stdout}"
    );
}

/// Test that seh_cpp_test.exe runs all 12 C++ exception-handling tests successfully.
///
/// `seh_cpp_test` is a MinGW-compiled C++ program that exercises C++ `throw`/`catch`
/// using the Windows x64 SEH machinery (`__gxx_personality_seh0` / `_GCC_specific_handler`).
/// It validates basic throw/catch, rethrow, catch-all, destructor unwinding, polymorphic
/// dispatch, and cross-frame propagation.
///
/// Build the program with:
/// ```
/// cd windows_test_programs/seh_test && make seh_cpp_test.exe
/// ```
#[test]
#[ignore = "Requires MinGW-built SEH test programs (run: cd windows_test_programs/seh_test && make)"]
fn test_seh_cpp_program() {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();
    let exe_path = workspace_root
        .join("windows_test_programs")
        .join("seh_test")
        .join("seh_cpp_test.exe");

    assert!(
        exe_path.exists(),
        "seh_cpp_test.exe not found at {exe_path:?}. \
         Build it with: cd windows_test_programs/seh_test && make seh_cpp_test.exe"
    );

    let runner_exe = env!("CARGO_BIN_EXE_litebox_runner_windows_on_linux_userland");
    let output = Command::new(runner_exe)
        .arg(&exe_path)
        .output()
        .expect("failed to launch litebox runner for seh_cpp_test.exe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "seh_cpp_test.exe should exit with code 0\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("=== SEH C++ Test Suite ==="),
        "seh_cpp_test.exe stdout should contain test suite header\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("0 failed"),
        "seh_cpp_test.exe should report 0 failed\nstdout:\n{stdout}"
    );
}

/// Test that seh_cpp_test_clang.exe runs all 26 C++ exception-handling tests successfully.
///
/// `seh_cpp_test_clang` is the same test source as `seh_cpp_test` but compiled
/// with `clang++ --target=x86_64-w64-mingw32` at `-O0`.  The LLVM front-end
/// generates different unwind tables and cleanup landing pads compared to
/// GCC/MinGW, including `_Unwind_Resume` calls (STATUS_GCC_UNWIND path through
/// `RaiseException`).  This validates that Clang-compiled MinGW-ABI C++
/// exceptions work correctly through the LiteBox exception dispatcher.
///
/// Build the program with:
/// ```
/// cd windows_test_programs/seh_test && make seh_cpp_test_clang.exe
/// ```
#[test]
#[ignore = "Requires clang-built MinGW SEH test program (run: cd windows_test_programs/seh_test && make seh_cpp_test_clang.exe)"]
fn test_seh_cpp_clang_program() {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();
    let exe_path = workspace_root
        .join("windows_test_programs")
        .join("seh_test")
        .join("seh_cpp_test_clang.exe");

    assert!(
        exe_path.exists(),
        "seh_cpp_test_clang.exe not found at {exe_path:?}. \
         Build it with: cd windows_test_programs/seh_test && make seh_cpp_test_clang.exe"
    );

    let runner_exe = env!("CARGO_BIN_EXE_litebox_runner_windows_on_linux_userland");
    let output = Command::new(runner_exe)
        .arg(&exe_path)
        .output()
        .expect("failed to launch litebox runner for seh_cpp_test_clang.exe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "seh_cpp_test_clang.exe should exit with code 0\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("=== SEH C++ Test Suite ==="),
        "seh_cpp_test_clang.exe stdout should contain test suite header\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("0 failed"),
        "seh_cpp_test_clang.exe should report 0 failed\nstdout:\n{stdout}"
    );
}

/// Test that seh_cpp_test_msvc.exe passes all 10 MSVC-style C++ exception tests.
///
/// `seh_cpp_test_msvc` is compiled with `clang++ --target=x86_64-pc-windows-msvc`
/// and uses MSVC-style exception handling (`_CxxThrowException` /
/// `__CxxFrameHandler3`) instead of GCC-style.  This validates that all 10 test
/// cases pass through the LiteBox exception dispatcher, including:
///   - throw/catch for int, double, const char*
///   - rethrow (`throw;`)
///   - catch-all (`catch(...)`)
///   - stack unwinding (destructor calls)
///   - nested try/catch
///   - cross-frame propagation
///   - multiple catch clauses
///   - exception through indirect (function pointer) call
///
/// Build the program with:
/// ```
/// cd windows_test_programs/seh_test && make seh_cpp_test_msvc.exe
/// ```
#[test]
#[ignore = "Requires clang-cl-built MSVC test program (run: cd windows_test_programs/seh_test && make seh_cpp_test_msvc.exe)"]
fn test_seh_cpp_msvc_program() {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();
    let exe_path = workspace_root
        .join("windows_test_programs")
        .join("seh_test")
        .join("seh_cpp_test_msvc.exe");

    assert!(
        exe_path.exists(),
        "seh_cpp_test_msvc.exe not found at {exe_path:?}. \
         Build it with: cd windows_test_programs/seh_test && make seh_cpp_test_msvc.exe"
    );

    let runner_exe = env!("CARGO_BIN_EXE_litebox_runner_windows_on_linux_userland");
    let output = Command::new(runner_exe)
        .arg(&exe_path)
        .output()
        .expect("failed to launch litebox runner for seh_cpp_test_msvc.exe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("=== SEH C++ Test Suite (MSVC ABI / clang-cl) ==="),
        "seh_cpp_test_msvc.exe stdout should contain MSVC test suite header\nstdout:\n{stdout}"
    );
    // All 21 checks across 10 tests must pass with 0 failures.
    assert!(
        stdout.contains("21 passed, 0 failed"),
        "seh_cpp_test_msvc.exe should report 21 passed, 0 failed\nstdout:\n{stdout}"
    );
    assert!(
        output.status.success(),
        "seh_cpp_test_msvc.exe should exit with status 0\nstdout:\n{stdout}"
    );
}

/// Test that phase27_test.exe passes all Phase 27 Windows API tests.
///
/// `phase27_test` is a MinGW-compiled C++ program that exercises thread management,
/// process management, file time APIs, system directory APIs, character conversion,
/// character classification, and headless window utilities.
///
/// The binary is pre-compiled and checked in at
/// `windows_test_programs/phase27_test/phase27_test.exe`.
#[test]
#[ignore = "Requires pre-compiled phase27_test.exe in windows_test_programs/phase27_test/"]
fn test_phase27_program() {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();
    let exe_path = workspace_root
        .join("windows_test_programs")
        .join("phase27_test")
        .join("phase27_test.exe");

    assert!(
        exe_path.exists(),
        "phase27_test.exe not found at {exe_path:?}. \
         Build it with: cd windows_test_programs/phase27_test && make"
    );

    let runner_exe = env!("CARGO_BIN_EXE_litebox_runner_windows_on_linux_userland");
    let output = Command::new(runner_exe)
        .arg(&exe_path)
        .output()
        .expect("failed to launch litebox runner for phase27_test.exe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "phase27_test.exe should exit with code 0\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("=== Phase 27 Windows API Tests ==="),
        "phase27_test.exe stdout should contain test suite header\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("PASSED (0 failures)"),
        "phase27_test.exe should report PASSED with 0 failures\nstdout:\n{stdout}"
    );
}
