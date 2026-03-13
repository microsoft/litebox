// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! DLL loading and management
//!
//! This module provides:
//! - DLL handle management
//! - Function export lookups
//! - Stub DLL implementations for common Windows DLLs

use crate::{Result, WindowsShimError};
extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Base addresses for stub DLL function pointers
/// Each DLL gets its own address range to avoid collisions
mod stub_addresses {
    /// KERNEL32.dll function address range: 0x1000-0x1FFF
    pub const KERNEL32_BASE: usize = 0x1000;

    /// NTDLL.dll function address range: 0x2000-0x2FFF
    pub const NTDLL_BASE: usize = 0x2000;

    /// MSVCRT.dll function address range: 0x3000-0x3FFF
    pub const MSVCRT_BASE: usize = 0x3000;

    /// bcryptprimitives.dll function address range: 0x4000-0x4FFF
    pub const BCRYPT_BASE: usize = 0x4000;

    /// USERENV.dll function address range: 0x5000-0x5FFF
    pub const USERENV_BASE: usize = 0x5000;

    /// WS2_32.dll function address range: 0x6000-0x6FFF
    pub const WS2_32_BASE: usize = 0x6000;

    /// api-ms-win-core-synch-l1-2-0.dll function address range: 0x7000-0x7FFF
    pub const APIMS_SYNCH_BASE: usize = 0x7000;

    /// USER32.dll function address range: 0x8000-0x8FFF
    pub const USER32_BASE: usize = 0x8000;

    /// ADVAPI32.dll function address range: 0x9000-0x9FFF
    pub const ADVAPI32_BASE: usize = 0x9000;

    /// GDI32.dll function address range: 0xA000-0xAFFF
    pub const GDI32_BASE: usize = 0xA000;

    /// SHELL32.dll function address range: 0xB000-0xBFFF
    pub const SHELL32_BASE: usize = 0xB000;

    /// VERSION.dll function address range: 0xC000-0xCFFF
    pub const VERSION_BASE: usize = 0xC000;

    /// SHLWAPI.dll function address range: 0xD000-0xDFFF
    pub const SHLWAPI_BASE: usize = 0xD000;

    /// OLEAUT32.dll function address range: 0xE000-0xEFFF
    pub const OLEAUT32_BASE: usize = 0xE000;

    /// api-ms-win-core-winrt-error-l1-1-0.dll function address range: 0xF000-0xFFFF
    pub const WINRT_ERROR_BASE: usize = 0xF000;

    /// ole32.dll function address range: 0x10000-0x10FFF
    pub const OLE32_BASE: usize = 0x10000;

    /// msvcp140.dll function address range: 0x11000-0x11FFF
    pub const MSVCP140_BASE: usize = 0x11000;

    /// vulkan-1.dll function address range: 0x12000-0x12FFF
    pub const VULKAN1_BASE: usize = 0x12000;
}

/// Type for a DLL function pointer
pub type DllFunction = usize;

/// Type for a function implementation callback
///
/// This is called when a Windows API function needs to be executed.
/// The callback receives the function name and can dispatch to the appropriate implementation.
pub type FunctionCallback = fn(dll_name: &str, function_name: &str) -> Option<DllFunction>;

/// Handle to a loaded DLL
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DllHandle(u64);

impl DllHandle {
    /// Create a new DLL handle from a raw value
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Get the raw handle value
    pub const fn as_raw(&self) -> u64 {
        self.0
    }
}

/// Information about a single exported function
#[derive(Debug, Clone)]
pub struct ExportedFunction {
    /// Function name
    pub name: String,
    /// Function address (stub implementation)
    pub address: DllFunction,
}

/// Information about a loaded or stub DLL
#[derive(Debug, Clone)]
pub struct DllInfo {
    /// DLL name (e.g., "KERNEL32.dll")
    pub name: String,
    /// DLL handle
    pub handle: DllHandle,
    /// Exported functions
    pub exports: BTreeMap<String, DllFunction>,
}

/// DLL manager for loading and managing Windows DLLs
pub struct DllManager {
    /// Next DLL handle to allocate
    next_handle: u64,
    /// Loaded DLLs by handle
    dlls: BTreeMap<DllHandle, DllInfo>,
    /// DLL lookup by name (case-insensitive)
    dll_by_name: BTreeMap<String, DllHandle>,
}

impl DllManager {
    /// Create a new DLL manager with common stub DLLs pre-loaded
    pub fn new() -> Self {
        let mut manager = Self {
            next_handle: 1,
            dlls: BTreeMap::new(),
            dll_by_name: BTreeMap::new(),
        };

        // Pre-load common stub DLLs
        manager.load_stub_kernel32();
        manager.load_stub_ntdll();
        manager.load_stub_msvcrt();
        manager.load_stub_bcryptprimitives();
        manager.load_stub_userenv();
        manager.load_stub_ws2_32();
        manager.load_stub_apims_synch();
        manager.load_stub_user32();
        manager.load_stub_advapi32();
        manager.load_stub_gdi32();
        manager.load_stub_shell32();
        manager.load_stub_version();
        manager.load_stub_shlwapi();
        manager.load_stub_oleaut32();
        manager.load_stub_winrt_error();
        manager.load_stub_ole32();
        manager.load_stub_msvcp140();
        manager.load_stub_vulkan1();

        manager
    }

    /// Load a DLL by name (or return existing handle if already loaded)
    pub fn load_library(&mut self, name: &str) -> Result<DllHandle> {
        // Normalize name to uppercase for case-insensitive lookup
        let normalized_name = name.to_uppercase();

        // Check if already loaded
        if let Some(&handle) = self.dll_by_name.get(&normalized_name) {
            return Ok(handle);
        }

        // Handle API Set DLLs - these are forwarder DLLs that redirect to real implementations
        // API sets were introduced in Windows 7 and use the naming pattern "api-ms-win-*"
        if normalized_name.starts_with("API-MS-WIN-") || normalized_name.starts_with("EXT-MS-WIN-")
        {
            // Map API set DLLs to their real implementation DLL
            let impl_dll = map_api_set_to_implementation(&normalized_name);

            // Check if we have the implementation DLL loaded
            if let Some(&handle) = self.dll_by_name.get(&impl_dll.to_uppercase()) {
                // Alias the API set name to the same handle
                self.dll_by_name.insert(normalized_name, handle);
                return Ok(handle);
            }

            // If implementation isn't loaded, return error
            return Err(WindowsShimError::UnsupportedFeature(format!(
                "API Set DLL {name} maps to {impl_dll}, which is not loaded"
            )));
        }

        // For now, we only support stub DLLs
        // Real DLL loading would be implemented here

        // Normalize MSVC runtime DLLs to MSVCRT.dll.  Programs compiled with the
        // MSVC toolchain import from vcruntime140.dll and the Universal CRT
        // (ucrtbase.dll) instead of the older msvcrt.dll.  Our implementations live
        // under MSVCRT.dll, so we alias these names to that DLL.
        if matches!(
            normalized_name.as_str(),
            "VCRUNTIME140.DLL" | "VCRUNTIME140_1.DLL" | "UCRTBASE.DLL"
        ) && let Some(&handle) = self.dll_by_name.get("MSVCRT.DLL")
        {
            self.dll_by_name.insert(normalized_name, handle);
            return Ok(handle);
        }

        Err(WindowsShimError::UnsupportedFeature(format!(
            "DLL not found: {name}"
        )))
    }

    /// Get the address of a function in a loaded DLL
    pub fn get_proc_address(&self, handle: DllHandle, name: &str) -> Result<DllFunction> {
        let dll = self.dlls.get(&handle).ok_or_else(|| {
            WindowsShimError::InvalidParameter(format!("Invalid DLL handle: {handle:?}"))
        })?;

        dll.exports.get(name).copied().ok_or_else(|| {
            WindowsShimError::UnsupportedFeature(format!(
                "Function {name} not found in {}",
                dll.name
            ))
        })
    }

    /// Update the address of an exported function
    ///
    /// This is used to replace stub addresses with actual trampoline addresses
    /// after initialization.
    ///
    /// # Panics
    /// Panics if attempting to update a function in a DLL that doesn't exist or
    /// if the function doesn't exist in that DLL's export table.
    pub fn update_export_address(
        &mut self,
        dll_name: &str,
        function_name: &str,
        new_address: DllFunction,
    ) -> Result<()> {
        let normalized_name = dll_name.to_uppercase();
        let handle = self.dll_by_name.get(&normalized_name).ok_or_else(|| {
            WindowsShimError::UnsupportedFeature(format!("DLL not found: {dll_name}"))
        })?;

        let dll = self.dlls.get_mut(handle).ok_or_else(|| {
            WindowsShimError::InvalidParameter(format!("Invalid DLL handle: {handle:?}"))
        })?;

        if !dll.exports.contains_key(function_name) {
            return Err(WindowsShimError::UnsupportedFeature(format!(
                "Function {function_name} not found in {dll_name}"
            )));
        }

        dll.exports.insert(function_name.to_string(), new_address);
        Ok(())
    }

    /// Free a loaded DLL
    pub fn free_library(&mut self, handle: DllHandle) -> Result<()> {
        let dll = self.dlls.remove(&handle).ok_or_else(|| {
            WindowsShimError::InvalidParameter(format!("Invalid DLL handle: {handle:?}"))
        })?;

        let normalized_name = dll.name.to_uppercase();
        self.dll_by_name.remove(&normalized_name);

        Ok(())
    }

    /// Register a stub DLL with the manager
    fn register_stub_dll(&mut self, name: &str, exports: Vec<(&str, DllFunction)>) -> DllHandle {
        let handle = DllHandle::new(self.next_handle);
        self.next_handle += 1;

        let normalized_name = name.to_uppercase();

        let mut export_map: BTreeMap<String, DllFunction> = BTreeMap::new();
        for (export_name, address) in exports {
            export_map.insert(export_name.to_string(), address);
        }

        let dll_info = DllInfo {
            name: name.to_string(),
            handle,
            exports: export_map,
        };

        self.dlls.insert(handle, dll_info);
        self.dll_by_name.insert(normalized_name, handle);

        handle
    }

    /// Load stub KERNEL32.dll
    fn load_stub_kernel32(&mut self) {
        use stub_addresses::KERNEL32_BASE;

        // For now, use stub addresses (will be replaced with actual implementations)
        let exports = vec![
            ("LoadLibraryA", KERNEL32_BASE),
            ("LoadLibraryW", KERNEL32_BASE + 1),
            ("GetProcAddress", KERNEL32_BASE + 2),
            ("FreeLibrary", KERNEL32_BASE + 3),
            ("GetStdHandle", KERNEL32_BASE + 4),
            ("WriteConsoleW", KERNEL32_BASE + 5),
            ("CreateFileW", KERNEL32_BASE + 6),
            ("ReadFile", KERNEL32_BASE + 7),
            ("WriteFile", KERNEL32_BASE + 8),
            ("CloseHandle", KERNEL32_BASE + 9),
            // Synchronization functions (from API set api-ms-win-core-synch-l1-2-0.dll)
            ("WaitOnAddress", KERNEL32_BASE + 0xA),
            ("WakeByAddressAll", KERNEL32_BASE + 0xB),
            ("WakeByAddressSingle", KERNEL32_BASE + 0xC),
            // Phase 7: Command-line and file operations
            ("GetCommandLineW", KERNEL32_BASE + 0xD),
            ("FindFirstFileExW", KERNEL32_BASE + 0xE),
            ("FindNextFileW", KERNEL32_BASE + 0xF),
            ("FindClose", KERNEL32_BASE + 0x10),
            // Phase 7: Process and thread information
            ("GetCurrentProcessId", KERNEL32_BASE + 0x11),
            ("GetCurrentThreadId", KERNEL32_BASE + 0x12),
            ("GetCurrentProcess", KERNEL32_BASE + 0x13),
            ("GetCurrentThread", KERNEL32_BASE + 0x14),
            // Phase 7: Error handling
            ("GetLastError", KERNEL32_BASE + 0x15),
            ("SetLastError", KERNEL32_BASE + 0x16),
            // Phase 7: Memory operations
            ("VirtualProtect", KERNEL32_BASE + 0x17),
            ("VirtualQuery", KERNEL32_BASE + 0x18),
            ("HeapAlloc", KERNEL32_BASE + 0x19),
            ("HeapFree", KERNEL32_BASE + 0x1A),
            ("HeapReAlloc", KERNEL32_BASE + 0x1B),
            ("GetProcessHeap", KERNEL32_BASE + 0x1C),
            // Phase 7: Environment and system info
            ("GetEnvironmentVariableW", KERNEL32_BASE + 0x1D),
            ("SetEnvironmentVariableW", KERNEL32_BASE + 0x1E),
            ("GetEnvironmentStringsW", KERNEL32_BASE + 0x1F),
            ("FreeEnvironmentStringsW", KERNEL32_BASE + 0x20),
            ("GetSystemInfo", KERNEL32_BASE + 0x21),
            // Phase 7: Module handling
            ("GetModuleHandleW", KERNEL32_BASE + 0x22),
            ("GetModuleHandleA", KERNEL32_BASE + 0x23),
            ("GetModuleFileNameW", KERNEL32_BASE + 0x24),
            // Phase 7: Console
            ("GetConsoleMode", KERNEL32_BASE + 0x25),
            ("ReadConsoleW", KERNEL32_BASE + 0x26),
            ("GetConsoleOutputCP", KERNEL32_BASE + 0x27),
            // Phase 7: Threading and timing
            ("Sleep", KERNEL32_BASE + 0x28),
            // Phase 7: Exit
            ("ExitProcess", KERNEL32_BASE + 0x29),
            // Phase 7: Thread Local Storage (TLS)
            ("TlsAlloc", KERNEL32_BASE + 0x2A),
            ("TlsFree", KERNEL32_BASE + 0x2B),
            ("TlsGetValue", KERNEL32_BASE + 0x2C),
            ("TlsSetValue", KERNEL32_BASE + 0x2D),
            // Phase 8: Exception Handling (stubs for CRT compatibility)
            ("__C_specific_handler", KERNEL32_BASE + 0x2E),
            ("SetUnhandledExceptionFilter", KERNEL32_BASE + 0x2F),
            ("UnhandledExceptionFilter", KERNEL32_BASE + 0xDF),
            ("RaiseException", KERNEL32_BASE + 0x30),
            ("RtlCaptureContext", KERNEL32_BASE + 0x31),
            ("RtlLookupFunctionEntry", KERNEL32_BASE + 0x32),
            ("RtlUnwindEx", KERNEL32_BASE + 0x33),
            ("RtlVirtualUnwind", KERNEL32_BASE + 0x34),
            ("AddVectoredExceptionHandler", KERNEL32_BASE + 0x35),
            ("InitializeSListHead", KERNEL32_BASE + 0xE0),
            // Phase 8.2: Critical Sections
            ("InitializeCriticalSection", KERNEL32_BASE + 0x36),
            ("EnterCriticalSection", KERNEL32_BASE + 0x37),
            ("LeaveCriticalSection", KERNEL32_BASE + 0x38),
            ("TryEnterCriticalSection", KERNEL32_BASE + 0x39),
            ("DeleteCriticalSection", KERNEL32_BASE + 0x3A),
            // Phase 8.3: String Operations
            ("MultiByteToWideChar", KERNEL32_BASE + 0x3B),
            ("WideCharToMultiByte", KERNEL32_BASE + 0x3C),
            ("lstrlenW", KERNEL32_BASE + 0x3D),
            ("CompareStringOrdinal", KERNEL32_BASE + 0x3E),
            // Phase 8.4: Performance Counters
            ("QueryPerformanceCounter", KERNEL32_BASE + 0x3F),
            ("QueryPerformanceFrequency", KERNEL32_BASE + 0x40),
            ("GetSystemTimePreciseAsFileTime", KERNEL32_BASE + 0x41),
            ("GetSystemTimeAsFileTime", KERNEL32_BASE + 0xE1),
            // Phase 8.5 and 8.6: Note - CreateFileW, ReadFile, WriteFile, CloseHandle,
            // GetProcessHeap, HeapAlloc, HeapFree, HeapReAlloc are already in the list above
            // Phase 8.7: Additional startup functions
            ("GetStartupInfoA", KERNEL32_BASE + 0x42),
            ("GetStartupInfoW", KERNEL32_BASE + 0x43),
            // Phase 9: Additional missing APIs (stubs for Rust std compatibility)
            ("CancelIo", KERNEL32_BASE + 0x44),
            ("CopyFileExW", KERNEL32_BASE + 0x45),
            ("CreateDirectoryW", KERNEL32_BASE + 0x46),
            ("CreateEventW", KERNEL32_BASE + 0x47),
            ("CreateFileMappingA", KERNEL32_BASE + 0x48),
            ("CreateHardLinkW", KERNEL32_BASE + 0x49),
            ("CreatePipe", KERNEL32_BASE + 0x4A),
            ("CreateProcessW", KERNEL32_BASE + 0x4B),
            ("CreateSymbolicLinkW", KERNEL32_BASE + 0x4C),
            ("CreateThread", KERNEL32_BASE + 0x4D),
            ("CreateToolhelp32Snapshot", KERNEL32_BASE + 0x4E),
            ("CreateWaitableTimerExW", KERNEL32_BASE + 0x4F),
            ("DeleteFileW", KERNEL32_BASE + 0x50),
            ("DeleteProcThreadAttributeList", KERNEL32_BASE + 0x51),
            ("DeviceIoControl", KERNEL32_BASE + 0x52),
            ("DuplicateHandle", KERNEL32_BASE + 0x53),
            ("FlushFileBuffers", KERNEL32_BASE + 0x54),
            ("FormatMessageW", KERNEL32_BASE + 0x55),
            ("GetCurrentDirectoryW", KERNEL32_BASE + 0x56),
            ("GetExitCodeProcess", KERNEL32_BASE + 0x57),
            ("GetFileAttributesW", KERNEL32_BASE + 0x58),
            ("GetFileInformationByHandle", KERNEL32_BASE + 0x59),
            ("GetFileType", KERNEL32_BASE + 0x5A),
            ("GetFullPathNameW", KERNEL32_BASE + 0x5B),
            ("SetConsoleCtrlHandler", KERNEL32_BASE + 0x5C),
            ("SetFilePointerEx", KERNEL32_BASE + 0x5D),
            ("WaitForSingleObject", KERNEL32_BASE + 0x5E),
            ("WaitForSingleObjectEx", KERNEL32_BASE + 0xE2),
            ("GetFileInformationByHandleEx", KERNEL32_BASE + 0x5F),
            ("GetFileSizeEx", KERNEL32_BASE + 0x60),
            ("GetFinalPathNameByHandleW", KERNEL32_BASE + 0x61),
            ("GetOverlappedResult", KERNEL32_BASE + 0x62),
            ("GetProcessId", KERNEL32_BASE + 0x63),
            ("GetSystemDirectoryW", KERNEL32_BASE + 0x64),
            ("GetTempPathW", KERNEL32_BASE + 0x65),
            ("GetWindowsDirectoryW", KERNEL32_BASE + 0x66),
            ("InitOnceBeginInitialize", KERNEL32_BASE + 0x67),
            ("InitOnceComplete", KERNEL32_BASE + 0x68),
            ("InitializeProcThreadAttributeList", KERNEL32_BASE + 0x69),
            ("LockFileEx", KERNEL32_BASE + 0x6A),
            ("MapViewOfFile", KERNEL32_BASE + 0x6B),
            ("Module32FirstW", KERNEL32_BASE + 0x6C),
            ("Module32NextW", KERNEL32_BASE + 0x6D),
            ("MoveFileExW", KERNEL32_BASE + 0x6E),
            ("ReadFileEx", KERNEL32_BASE + 0x6F),
            ("RemoveDirectoryW", KERNEL32_BASE + 0x70),
            ("SetCurrentDirectoryW", KERNEL32_BASE + 0x71),
            ("SetFileAttributesW", KERNEL32_BASE + 0x72),
            ("SetFileInformationByHandle", KERNEL32_BASE + 0x73),
            ("SetFileTime", KERNEL32_BASE + 0x74),
            ("SetHandleInformation", KERNEL32_BASE + 0x75),
            ("UnlockFile", KERNEL32_BASE + 0x76),
            ("UnmapViewOfFile", KERNEL32_BASE + 0x77),
            ("UpdateProcThreadAttribute", KERNEL32_BASE + 0x78),
            ("WriteFileEx", KERNEL32_BASE + 0x79),
            ("SetThreadStackGuarantee", KERNEL32_BASE + 0x7A),
            ("SetWaitableTimer", KERNEL32_BASE + 0x7B),
            ("SleepEx", KERNEL32_BASE + 0x7C),
            ("SwitchToThread", KERNEL32_BASE + 0x7D),
            ("TerminateProcess", KERNEL32_BASE + 0x7E),
            ("WaitForMultipleObjects", KERNEL32_BASE + 0x7F),
            // Phase 10: Additional KERNEL32 functions
            ("GetACP", KERNEL32_BASE + 0x80),
            ("IsProcessorFeaturePresent", KERNEL32_BASE + 0x81),
            ("IsDebuggerPresent", KERNEL32_BASE + 0x82),
            ("GetStringTypeW", KERNEL32_BASE + 0x83),
            ("HeapSize", KERNEL32_BASE + 0x84),
            (
                "InitializeCriticalSectionAndSpinCount",
                KERNEL32_BASE + 0x85,
            ),
            ("InitializeCriticalSectionEx", KERNEL32_BASE + 0x86),
            ("FlsAlloc", KERNEL32_BASE + 0x87),
            ("FlsFree", KERNEL32_BASE + 0x88),
            ("FlsGetValue", KERNEL32_BASE + 0x89),
            ("FlsSetValue", KERNEL32_BASE + 0x8A),
            ("IsValidCodePage", KERNEL32_BASE + 0x8B),
            ("GetOEMCP", KERNEL32_BASE + 0x8C),
            ("GetCPInfo", KERNEL32_BASE + 0x8D),
            ("GetLocaleInfoW", KERNEL32_BASE + 0x8E),
            ("LCMapStringW", KERNEL32_BASE + 0x8F),
            ("VirtualAlloc", KERNEL32_BASE + 0x90),
            ("VirtualFree", KERNEL32_BASE + 0x91),
            ("DecodePointer", KERNEL32_BASE + 0x92),
            ("EncodePointer", KERNEL32_BASE + 0x93),
            ("GetTickCount64", KERNEL32_BASE + 0x94),
            ("SetEvent", KERNEL32_BASE + 0x95),
            ("ResetEvent", KERNEL32_BASE + 0x96),
            // Phase 12: Extended file system APIs
            ("FindFirstFileW", KERNEL32_BASE + 0x97),
            ("CopyFileW", KERNEL32_BASE + 0x98),
            ("CreateDirectoryExW", KERNEL32_BASE + 0x99),
            ("IsDBCSLeadByteEx", KERNEL32_BASE + 0x9A),
            // Phase 25: Time, local memory, interlocked, system info
            ("GetSystemTime", KERNEL32_BASE + 0x9B),
            ("GetLocalTime", KERNEL32_BASE + 0x9C),
            ("SystemTimeToFileTime", KERNEL32_BASE + 0x9D),
            ("FileTimeToSystemTime", KERNEL32_BASE + 0x9E),
            ("GetTickCount", KERNEL32_BASE + 0x9F),
            ("LocalAlloc", KERNEL32_BASE + 0xA0),
            ("LocalFree", KERNEL32_BASE + 0xA1),
            ("InterlockedIncrement", KERNEL32_BASE + 0xA2),
            ("InterlockedDecrement", KERNEL32_BASE + 0xA3),
            ("InterlockedExchange", KERNEL32_BASE + 0xA4),
            ("InterlockedExchangeAdd", KERNEL32_BASE + 0xA5),
            ("InterlockedCompareExchange", KERNEL32_BASE + 0xA6),
            ("InterlockedCompareExchange64", KERNEL32_BASE + 0xA7),
            ("IsWow64Process", KERNEL32_BASE + 0xA8),
            ("GetNativeSystemInfo", KERNEL32_BASE + 0xA9),
            // Phase 26: Mutex / Semaphore
            ("CreateMutexW", KERNEL32_BASE + 0xAA),
            ("CreateMutexA", KERNEL32_BASE + 0xAB),
            ("OpenMutexW", KERNEL32_BASE + 0xAC),
            ("ReleaseMutex", KERNEL32_BASE + 0xAD),
            ("CreateSemaphoreW", KERNEL32_BASE + 0xAE),
            ("CreateSemaphoreA", KERNEL32_BASE + 0xAF),
            ("OpenSemaphoreW", KERNEL32_BASE + 0xB0),
            ("ReleaseSemaphore", KERNEL32_BASE + 0xB1),
            // Phase 26: Console Extensions
            ("SetConsoleMode", KERNEL32_BASE + 0xB2),
            ("SetConsoleTitleW", KERNEL32_BASE + 0xB3),
            ("SetConsoleTitleA", KERNEL32_BASE + 0xB4),
            ("GetConsoleTitleW", KERNEL32_BASE + 0xB5),
            ("AllocConsole", KERNEL32_BASE + 0xB6),
            ("FreeConsole", KERNEL32_BASE + 0xB7),
            ("GetConsoleWindow", KERNEL32_BASE + 0xB8),
            // Phase 26: String Utilities
            ("lstrlenA", KERNEL32_BASE + 0xB9),
            ("lstrcpyW", KERNEL32_BASE + 0xBA),
            ("lstrcpyA", KERNEL32_BASE + 0xBB),
            ("lstrcmpW", KERNEL32_BASE + 0xBC),
            ("lstrcmpA", KERNEL32_BASE + 0xBD),
            ("lstrcmpiW", KERNEL32_BASE + 0xBE),
            ("lstrcmpiA", KERNEL32_BASE + 0xBF),
            ("OutputDebugStringW", KERNEL32_BASE + 0xC0),
            ("OutputDebugStringA", KERNEL32_BASE + 0xC1),
            // Phase 26: Drive / Volume APIs
            ("GetDriveTypeW", KERNEL32_BASE + 0xC2),
            ("GetLogicalDrives", KERNEL32_BASE + 0xC3),
            ("GetLogicalDriveStringsW", KERNEL32_BASE + 0xC4),
            ("GetDiskFreeSpaceExW", KERNEL32_BASE + 0xC5),
            ("GetVolumeInformationW", KERNEL32_BASE + 0xC6),
            // Phase 26: Computer Name
            ("GetComputerNameW", KERNEL32_BASE + 0xC7),
            ("GetComputerNameExW", KERNEL32_BASE + 0xC8),
            // Phase 27: Thread Management
            ("SetThreadPriority", KERNEL32_BASE + 0xC9),
            ("GetThreadPriority", KERNEL32_BASE + 0xCA),
            ("SuspendThread", KERNEL32_BASE + 0xCB),
            ("ResumeThread", KERNEL32_BASE + 0xCC),
            ("OpenThread", KERNEL32_BASE + 0xCD),
            ("GetExitCodeThread", KERNEL32_BASE + 0xCE),
            // Phase 27: Process Management
            ("OpenProcess", KERNEL32_BASE + 0xCF),
            ("GetProcessTimes", KERNEL32_BASE + 0xD0),
            // Phase 27: File Times
            ("GetFileTime", KERNEL32_BASE + 0xD1),
            ("CompareFileTime", KERNEL32_BASE + 0xD2),
            ("FileTimeToLocalFileTime", KERNEL32_BASE + 0xD3),
            // Phase 27: Temp File Name
            ("GetTempFileNameW", KERNEL32_BASE + 0xD4),
            // Phase 28
            ("GetFileSize", KERNEL32_BASE + 0xD5),
            ("SetFilePointer", KERNEL32_BASE + 0xD6),
            ("SetEndOfFile", KERNEL32_BASE + 0xD7),
            ("FlushViewOfFile", KERNEL32_BASE + 0xD8),
            ("GetSystemDefaultLangID", KERNEL32_BASE + 0xD9),
            ("GetUserDefaultLangID", KERNEL32_BASE + 0xDA),
            ("GetSystemDefaultLCID", KERNEL32_BASE + 0xDB),
            ("GetUserDefaultLCID", KERNEL32_BASE + 0xDC),
            ("RemoveVectoredExceptionHandler", KERNEL32_BASE + 0xDD),
            // ANSI console write (used by MSVC-ABI programs)
            ("WriteConsoleA", KERNEL32_BASE + 0xDE),
            // Async I/O / IOCP
            ("CreateIoCompletionPort", KERNEL32_BASE + 0xE3),
            ("PostQueuedCompletionStatus", KERNEL32_BASE + 0xE4),
            ("GetQueuedCompletionStatus", KERNEL32_BASE + 0xE5),
            ("GetQueuedCompletionStatusEx", KERNEL32_BASE + 0xE6),
            // ANSI file helpers used by async_io_test and similar programs
            ("CreateFileA", KERNEL32_BASE + 0xE7),
            ("GetTempPathA", KERNEL32_BASE + 0xE8),
            ("DeleteFileA", KERNEL32_BASE + 0xE9),
            // Phase 39: Extended Process Management
            ("GetPriorityClass", KERNEL32_BASE + 0xEA),
            ("SetPriorityClass", KERNEL32_BASE + 0xEB),
            ("GetProcessAffinityMask", KERNEL32_BASE + 0xEC),
            ("SetProcessAffinityMask", KERNEL32_BASE + 0xED),
            ("FlushInstructionCache", KERNEL32_BASE + 0xEE),
            ("ReadProcessMemory", KERNEL32_BASE + 0xEF),
            ("WriteProcessMemory", KERNEL32_BASE + 0xF0),
            ("VirtualAllocEx", KERNEL32_BASE + 0xF1),
            ("VirtualFreeEx", KERNEL32_BASE + 0xF2),
            ("CreateJobObjectW", KERNEL32_BASE + 0xF3),
            ("AssignProcessToJobObject", KERNEL32_BASE + 0xF4),
            ("IsProcessInJob", KERNEL32_BASE + 0xF5),
            ("QueryInformationJobObject", KERNEL32_BASE + 0xF6),
            ("SetInformationJobObject", KERNEL32_BASE + 0xF7),
            ("OpenJobObjectW", KERNEL32_BASE + 0xF8),
            ("CreateProcessA", KERNEL32_BASE + 0xF9),
            // Phase 43: Volume enumeration
            ("FindFirstVolumeW", KERNEL32_BASE + 0xFA),
            ("FindNextVolumeW", KERNEL32_BASE + 0xFB),
            ("FindVolumeClose", KERNEL32_BASE + 0xFC),
            // Phase 44: Volume path names
            ("GetVolumePathNamesForVolumeNameW", KERNEL32_BASE + 0xFD),
        ];

        self.register_stub_dll("KERNEL32.dll", exports);
    }

    /// Load stub NTDLL.dll
    fn load_stub_ntdll(&mut self) {
        use stub_addresses::NTDLL_BASE;

        let exports = vec![
            ("NtCreateFile", NTDLL_BASE),
            ("NtReadFile", NTDLL_BASE + 1),
            ("NtWriteFile", NTDLL_BASE + 2),
            ("NtClose", NTDLL_BASE + 3),
            ("NtAllocateVirtualMemory", NTDLL_BASE + 4),
            ("NtFreeVirtualMemory", NTDLL_BASE + 5),
            // Additional NTDLL functions
            ("NtOpenFile", NTDLL_BASE + 6),
            ("NtCreateNamedPipeFile", NTDLL_BASE + 7),
            ("RtlNtStatusToDosError", NTDLL_BASE + 8),
        ];

        self.register_stub_dll("NTDLL.dll", exports);
    }

    /// Load stub MSVCRT.dll
    fn load_stub_msvcrt(&mut self) {
        use stub_addresses::MSVCRT_BASE;

        let exports = vec![
            ("printf", MSVCRT_BASE),
            ("malloc", MSVCRT_BASE + 1),
            ("free", MSVCRT_BASE + 2),
            ("exit", MSVCRT_BASE + 3),
            // Additional CRT functions needed by Rust binaries
            ("calloc", MSVCRT_BASE + 4),
            ("memcmp", MSVCRT_BASE + 5),
            ("memcpy", MSVCRT_BASE + 6),
            ("memmove", MSVCRT_BASE + 7),
            ("memset", MSVCRT_BASE + 8),
            ("strlen", MSVCRT_BASE + 9),
            ("strncmp", MSVCRT_BASE + 0xA),
            ("fprintf", MSVCRT_BASE + 0xB),
            ("vfprintf", MSVCRT_BASE + 0xC),
            ("fwrite", MSVCRT_BASE + 0xD),
            ("signal", MSVCRT_BASE + 0xE),
            ("abort", MSVCRT_BASE + 0xF),
            // MinGW-specific CRT initialization functions
            ("__getmainargs", MSVCRT_BASE + 0x10),
            ("__initenv", MSVCRT_BASE + 0x11),
            ("__iob_func", MSVCRT_BASE + 0x12),
            ("__set_app_type", MSVCRT_BASE + 0x13),
            ("__setusermatherr", MSVCRT_BASE + 0x14),
            ("_amsg_exit", MSVCRT_BASE + 0x15),
            ("_cexit", MSVCRT_BASE + 0x16),
            ("_commode", MSVCRT_BASE + 0x17),
            ("_fmode", MSVCRT_BASE + 0x18),
            ("_fpreset", MSVCRT_BASE + 0x19),
            ("_initterm", MSVCRT_BASE + 0x1A),
            ("_onexit", MSVCRT_BASE + 0x1B),
            // Phase 8.7: Additional CRT functions
            ("_acmdln", MSVCRT_BASE + 0x1C),
            ("_ismbblead", MSVCRT_BASE + 0x1D),
            ("__C_specific_handler", MSVCRT_BASE + 0x1E),
            // Phase 9: CRT helper functions for global data access
            ("__p__fmode", MSVCRT_BASE + 0x1F),
            ("__p__commode", MSVCRT_BASE + 0x20),
            ("_setargv", MSVCRT_BASE + 0x21),
            ("_set_invalid_parameter_handler", MSVCRT_BASE + 0x22),
            ("_pei386_runtime_relocator", MSVCRT_BASE + 0x23),
            // Phase 10: Additional MSVCRT functions
            ("strcmp", MSVCRT_BASE + 0x24),
            ("strcpy", MSVCRT_BASE + 0x25),
            ("strcat", MSVCRT_BASE + 0x26),
            ("strchr", MSVCRT_BASE + 0x27),
            ("strrchr", MSVCRT_BASE + 0x28),
            ("strstr", MSVCRT_BASE + 0x29),
            ("_initterm_e", MSVCRT_BASE + 0x2A),
            ("__p___argc", MSVCRT_BASE + 0x2B),
            ("__p___argv", MSVCRT_BASE + 0x2C),
            ("_lock", MSVCRT_BASE + 0x2D),
            ("_unlock", MSVCRT_BASE + 0x2E),
            ("getenv", MSVCRT_BASE + 0x2F),
            ("_errno", MSVCRT_BASE + 0x30),
            ("__lconv_init", MSVCRT_BASE + 0x31),
            ("_XcptFilter", MSVCRT_BASE + 0x32),
            ("_controlfp", MSVCRT_BASE + 0x33),
            // Additional CRT functions needed by C++ MinGW programs
            ("strerror", MSVCRT_BASE + 0x34),
            ("wcslen", MSVCRT_BASE + 0x35),
            ("wcscmp", MSVCRT_BASE + 0x3A),
            ("wcsstr", MSVCRT_BASE + 0x3B),
            ("fputc", MSVCRT_BASE + 0x36),
            ("localeconv", MSVCRT_BASE + 0x37),
            ("___lc_codepage_func", MSVCRT_BASE + 0x38),
            ("___mb_cur_max_func", MSVCRT_BASE + 0x39),
            // Phase 28: numeric conversion
            ("atoi", MSVCRT_BASE + 0x3C),
            ("atol", MSVCRT_BASE + 0x3D),
            ("atof", MSVCRT_BASE + 0x3E),
            ("strtol", MSVCRT_BASE + 0x3F),
            ("strtoul", MSVCRT_BASE + 0x40),
            ("strtod", MSVCRT_BASE + 0x41),
            ("_itoa", MSVCRT_BASE + 0x42),
            ("_ltoa", MSVCRT_BASE + 0x43),
            // Phase 28: string extras
            ("strncpy", MSVCRT_BASE + 0x44),
            ("strncat", MSVCRT_BASE + 0x45),
            ("_stricmp", MSVCRT_BASE + 0x46),
            ("_strnicmp", MSVCRT_BASE + 0x47),
            ("_strdup", MSVCRT_BASE + 0x48),
            ("strnlen", MSVCRT_BASE + 0x49),
            // Phase 28: random & time
            ("rand", MSVCRT_BASE + 0x4A),
            ("srand", MSVCRT_BASE + 0x4B),
            ("time", MSVCRT_BASE + 0x4C),
            ("clock", MSVCRT_BASE + 0x4D),
            // Phase 28: math
            ("abs", MSVCRT_BASE + 0x4E),
            ("labs", MSVCRT_BASE + 0x4F),
            ("_abs64", MSVCRT_BASE + 0x50),
            ("fabs", MSVCRT_BASE + 0x51),
            ("sqrt", MSVCRT_BASE + 0x52),
            ("pow", MSVCRT_BASE + 0x53),
            ("log", MSVCRT_BASE + 0x54),
            ("log10", MSVCRT_BASE + 0x55),
            ("exp", MSVCRT_BASE + 0x56),
            ("sin", MSVCRT_BASE + 0x57),
            ("cos", MSVCRT_BASE + 0x58),
            ("tan", MSVCRT_BASE + 0x59),
            ("atan", MSVCRT_BASE + 0x5A),
            ("atan2", MSVCRT_BASE + 0x5B),
            ("ceil", MSVCRT_BASE + 0x5C),
            ("floor", MSVCRT_BASE + 0x5D),
            ("fmod", MSVCRT_BASE + 0x5E),
            // Phase 28: wide-char extras
            ("wcscpy", MSVCRT_BASE + 0x5F),
            ("wcscat", MSVCRT_BASE + 0x60),
            ("wcsncpy", MSVCRT_BASE + 0x61),
            ("wcschr", MSVCRT_BASE + 0x62),
            ("wcsncmp", MSVCRT_BASE + 0x63),
            ("_wcsicmp", MSVCRT_BASE + 0x64),
            ("_wcsnicmp", MSVCRT_BASE + 0x65),
            ("wcstombs", MSVCRT_BASE + 0x66),
            ("mbstowcs", MSVCRT_BASE + 0x67),
            // C++ Exception Handling (MSVC-style)
            ("_CxxThrowException", MSVCRT_BASE + 0x68),
            ("__CxxFrameHandler3", MSVCRT_BASE + 0x69),
            ("__CxxFrameHandler4", MSVCRT_BASE + 0x6A),
            ("terminate", MSVCRT_BASE + 0x6B),
            ("_set_se_translator", MSVCRT_BASE + 0x6C),
            ("_is_exception_typeof", MSVCRT_BASE + 0x6D),
            ("__std_terminate", MSVCRT_BASE + 0x6E),
            ("_CxxExceptionFilter", MSVCRT_BASE + 0x6F),
            ("__current_exception", MSVCRT_BASE + 0x70),
            ("__current_exception_context", MSVCRT_BASE + 0x71),
            // UCRT / VCRUNTIME140 functions needed by MSVC-compiled programs
            ("__vcrt_initialize", MSVCRT_BASE + 0x72),
            ("__vcrt_uninitialize", MSVCRT_BASE + 0x73),
            ("__security_init_cookie", MSVCRT_BASE + 0x74),
            ("__security_check_cookie", MSVCRT_BASE + 0x75),
            ("_initialize_narrow_environment", MSVCRT_BASE + 0x76),
            ("_get_initial_narrow_environment", MSVCRT_BASE + 0x7F),
            ("_configure_narrow_argv", MSVCRT_BASE + 0x77),
            ("_set_app_type", MSVCRT_BASE + 0x80),
            ("_exit", MSVCRT_BASE + 0x81),
            ("_c_exit", MSVCRT_BASE + 0x82),
            ("_crt_atexit", MSVCRT_BASE + 0x78),
            (
                "_register_thread_local_exe_atexit_callback",
                MSVCRT_BASE + 0x83,
            ),
            ("_seh_filter_exe", MSVCRT_BASE + 0x84),
            ("_initialize_onexit_table", MSVCRT_BASE + 0x85),
            ("_register_onexit_function", MSVCRT_BASE + 0x86),
            ("_set_fmode", MSVCRT_BASE + 0x87),
            ("_set_new_mode", MSVCRT_BASE + 0x88),
            ("__acrt_iob_func", MSVCRT_BASE + 0x79),
            ("__stdio_common_vfprintf", MSVCRT_BASE + 0x7A),
            ("_configthreadlocale", MSVCRT_BASE + 0x7B),
            // Stack probe functions — registered via data-export path so RAX is preserved.
            // These placeholder addresses are overwritten by link_data_exports_to_dll_manager.
            ("__chkstk", MSVCRT_BASE + 0x7C),
            ("___chkstk_ms", MSVCRT_BASE + 0x7D),
            ("_alloca_probe", MSVCRT_BASE + 0x7E),
            // Phase 29-31: additional C++ EH / UCRT functions
            ("_local_unwind", MSVCRT_BASE + 0x89),
            ("__CxxRegisterExceptionObject", MSVCRT_BASE + 0x8A),
            ("__CxxUnregisterExceptionObject", MSVCRT_BASE + 0x8B),
            ("__DestructExceptionObject", MSVCRT_BASE + 0x8C),
            ("__uncaught_exception", MSVCRT_BASE + 0x8D),
            ("__uncaught_exceptions", MSVCRT_BASE + 0x8E),
            // Phase 32: formatted I/O
            ("sprintf", MSVCRT_BASE + 0x8F),
            ("snprintf", MSVCRT_BASE + 0x90),
            ("sscanf", MSVCRT_BASE + 0x91),
            ("swprintf", MSVCRT_BASE + 0x92),
            ("wprintf", MSVCRT_BASE + 0x93),
            // Phase 32: character classification
            ("isalpha", MSVCRT_BASE + 0x94),
            ("isdigit", MSVCRT_BASE + 0x95),
            ("isspace", MSVCRT_BASE + 0x96),
            ("isupper", MSVCRT_BASE + 0x97),
            ("islower", MSVCRT_BASE + 0x98),
            ("isprint", MSVCRT_BASE + 0x99),
            ("isxdigit", MSVCRT_BASE + 0x9A),
            ("isalnum", MSVCRT_BASE + 0x9B),
            ("iscntrl", MSVCRT_BASE + 0x9C),
            ("ispunct", MSVCRT_BASE + 0x9D),
            ("toupper", MSVCRT_BASE + 0x9E),
            ("tolower", MSVCRT_BASE + 0x9F),
            // Phase 32: sorting / searching
            ("qsort", MSVCRT_BASE + 0xA0),
            ("bsearch", MSVCRT_BASE + 0xA1),
            // Phase 32: wide-string numeric conversions
            ("wcstol", MSVCRT_BASE + 0xA2),
            ("wcstoul", MSVCRT_BASE + 0xA3),
            ("wcstod", MSVCRT_BASE + 0xA4),
            // Phase 32: file I/O
            ("fopen", MSVCRT_BASE + 0xA5),
            ("fclose", MSVCRT_BASE + 0xA6),
            ("fread", MSVCRT_BASE + 0xA7),
            ("fseek", MSVCRT_BASE + 0xA8),
            ("ftell", MSVCRT_BASE + 0xA9),
            ("fflush", MSVCRT_BASE + 0xAA),
            ("fgets", MSVCRT_BASE + 0xAB),
            ("rewind", MSVCRT_BASE + 0xAC),
            ("feof", MSVCRT_BASE + 0xAD),
            ("ferror", MSVCRT_BASE + 0xAE),
            ("clearerr", MSVCRT_BASE + 0xAF),
            ("fgetc", MSVCRT_BASE + 0xB0),
            ("ungetc", MSVCRT_BASE + 0xB1),
            ("fileno", MSVCRT_BASE + 0xB2),
            ("_fileno", MSVCRT_BASE + 0xB2), // alias
            ("fdopen", MSVCRT_BASE + 0xB3),
            ("_fdopen", MSVCRT_BASE + 0xB3), // alias
            ("tmpfile", MSVCRT_BASE + 0xB4),
            ("remove", MSVCRT_BASE + 0xB5),
            ("rename", MSVCRT_BASE + 0xB6),
            // Phase 32: misc previously-missing functions
            ("fputs", MSVCRT_BASE + 0xB7),
            ("puts", MSVCRT_BASE + 0xB8),
            ("realloc", MSVCRT_BASE + 0xB9),
            ("_read", MSVCRT_BASE + 0xBA),
            (
                "_register_thread_local_exe_atexit_callback",
                MSVCRT_BASE + 0xBB,
            ),
            // Phase 33: wide-char file I/O
            ("_wfopen", MSVCRT_BASE + 0xBC),
            // Phase 34: vprintf family and basic I/O
            ("vprintf", MSVCRT_BASE + 0xBD),
            ("vsprintf", MSVCRT_BASE + 0xBE),
            ("vsnprintf", MSVCRT_BASE + 0xBF),
            ("vswprintf", MSVCRT_BASE + 0xC0),
            ("fwprintf", MSVCRT_BASE + 0xC1),
            ("vfwprintf", MSVCRT_BASE + 0xC2),
            ("_write", MSVCRT_BASE + 0xC3),
            ("getchar", MSVCRT_BASE + 0xC4),
            ("putchar", MSVCRT_BASE + 0xC5),
            // Phase 35 additions
            ("_vsnwprintf", MSVCRT_BASE + 0xC6),
            ("_scprintf", MSVCRT_BASE + 0xC7),
            ("_vscprintf", MSVCRT_BASE + 0xC8),
            ("_scwprintf", MSVCRT_BASE + 0xC9),
            ("_vscwprintf", MSVCRT_BASE + 0xCA),
            ("_get_osfhandle", MSVCRT_BASE + 0xCB),
            ("_open_osfhandle", MSVCRT_BASE + 0xCC),
            ("_wcsdup", MSVCRT_BASE + 0xCD),
            ("__stdio_common_vsscanf", MSVCRT_BASE + 0xCE),
            // Secure formatted I/O
            ("_snprintf_s", MSVCRT_BASE + 0xCF),
            // Phase 37 additions
            ("__stdio_common_vsprintf", MSVCRT_BASE + 0xD0),
            ("__stdio_common_vsnprintf_s", MSVCRT_BASE + 0xD1),
            ("__stdio_common_vsprintf_s", MSVCRT_BASE + 0xD2),
            ("__stdio_common_vswprintf", MSVCRT_BASE + 0xD3),
            ("scanf", MSVCRT_BASE + 0xD4),
            ("fscanf", MSVCRT_BASE + 0xD5),
            ("__stdio_common_vfscanf", MSVCRT_BASE + 0xD6),
            ("_ultoa", MSVCRT_BASE + 0xD7),
            ("_i64toa", MSVCRT_BASE + 0xD8),
            ("_ui64toa", MSVCRT_BASE + 0xD9),
            ("_strtoi64", MSVCRT_BASE + 0xDA),
            ("_strtoui64", MSVCRT_BASE + 0xDB),
            ("_itow", MSVCRT_BASE + 0xDC),
            ("_ltow", MSVCRT_BASE + 0xDD),
            ("_ultow", MSVCRT_BASE + 0xDE),
            ("_i64tow", MSVCRT_BASE + 0xDF),
            ("_ui64tow", MSVCRT_BASE + 0xE0),
            // Phase 38: wide file enumeration and locale printf
            ("_wfindfirst64i32", MSVCRT_BASE + 0xE1),
            ("_wfindnext64i32", MSVCRT_BASE + 0xE2),
            ("_findclose", MSVCRT_BASE + 0xE3),
            ("_printf_l", MSVCRT_BASE + 0xE4),
            ("_fprintf_l", MSVCRT_BASE + 0xE5),
            ("_sprintf_l", MSVCRT_BASE + 0xE6),
            ("_snprintf_l", MSVCRT_BASE + 0xE7),
            ("_wprintf_l", MSVCRT_BASE + 0xE8),
            // Phase 39: Low-level file I/O
            ("_open", MSVCRT_BASE + 0xE9),
            ("_close", MSVCRT_BASE + 0xEA),
            ("_lseek", MSVCRT_BASE + 0xEB),
            ("_lseeki64", MSVCRT_BASE + 0xEC),
            ("_tell", MSVCRT_BASE + 0xED),
            ("_telli64", MSVCRT_BASE + 0xEE),
            ("_eof", MSVCRT_BASE + 0xEF),
            ("_creat", MSVCRT_BASE + 0xF0),
            ("_commit", MSVCRT_BASE + 0xF1),
            ("_dup", MSVCRT_BASE + 0xF2),
            ("_dup2", MSVCRT_BASE + 0xF3),
            ("_chsize", MSVCRT_BASE + 0xF4),
            ("_chsize_s", MSVCRT_BASE + 0xF5),
            ("_filelength", MSVCRT_BASE + 0xF6),
            ("_filelengthi64", MSVCRT_BASE + 0xF7),
            // Phase 40: stat functions and wide-path file opens
            ("_stat", MSVCRT_BASE + 0xF8),
            ("_stat64", MSVCRT_BASE + 0xF9),
            ("_fstat", MSVCRT_BASE + 0xFA),
            ("_fstat64", MSVCRT_BASE + 0xFB),
            ("_wopen", MSVCRT_BASE + 0xFC),
            ("_wsopen", MSVCRT_BASE + 0xFD),
            ("_wstat", MSVCRT_BASE + 0xFE),
            ("_wstat64", MSVCRT_BASE + 0xFF),
            ("_sopen_s", MSVCRT_BASE + 0x100),
            ("_wsopen_s", MSVCRT_BASE + 0x101),
            ("_fullpath", MSVCRT_BASE + 0x102),
            ("_splitpath", MSVCRT_BASE + 0x103),
            ("_splitpath_s", MSVCRT_BASE + 0x104),
            ("_makepath", MSVCRT_BASE + 0x105),
            ("_makepath_s", MSVCRT_BASE + 0x106),
            // Phase 43: Directory navigation
            ("_getcwd", MSVCRT_BASE + 0x107),
            ("_chdir", MSVCRT_BASE + 0x108),
            ("_mkdir", MSVCRT_BASE + 0x109),
            ("_rmdir", MSVCRT_BASE + 0x10A),
            // Phase 44: temp file functions
            ("tmpnam", MSVCRT_BASE + 0x10B),
            ("_mktemp", MSVCRT_BASE + 0x10C),
            ("_tempnam", MSVCRT_BASE + 0x10D),
        ];

        self.register_stub_dll("MSVCRT.dll", exports);
    }

    /// Load stub bcryptprimitives.dll
    fn load_stub_bcryptprimitives(&mut self) {
        use stub_addresses::BCRYPT_BASE;

        let exports = vec![
            // Cryptographic PRNG function
            ("ProcessPrng", BCRYPT_BASE),
        ];

        self.register_stub_dll("bcryptprimitives.dll", exports);
    }

    /// Load stub USERENV.dll
    fn load_stub_userenv(&mut self) {
        use stub_addresses::USERENV_BASE;

        let exports = vec![
            // User profile directory function
            ("GetUserProfileDirectoryW", USERENV_BASE),
        ];

        self.register_stub_dll("USERENV.dll", exports);
    }

    /// Load stub WS2_32.dll (Windows Sockets 2)
    fn load_stub_ws2_32(&mut self) {
        use stub_addresses::WS2_32_BASE;

        let exports = vec![
            // Winsock initialization and cleanup
            ("WSAStartup", WS2_32_BASE),
            ("WSACleanup", WS2_32_BASE + 1),
            ("WSAGetLastError", WS2_32_BASE + 2),
            ("WSASetLastError", WS2_32_BASE + 0x1B),
            // Socket operations
            ("WSASocketW", WS2_32_BASE + 3),
            ("socket", WS2_32_BASE + 4),
            ("closesocket", WS2_32_BASE + 5),
            // Connection operations
            ("bind", WS2_32_BASE + 6),
            ("listen", WS2_32_BASE + 7),
            ("accept", WS2_32_BASE + 8),
            ("connect", WS2_32_BASE + 9),
            // Data transfer
            ("send", WS2_32_BASE + 0xA),
            ("recv", WS2_32_BASE + 0xB),
            ("sendto", WS2_32_BASE + 0xC),
            ("recvfrom", WS2_32_BASE + 0xD),
            ("WSASend", WS2_32_BASE + 0xE),
            ("WSARecv", WS2_32_BASE + 0xF),
            // Socket information and control
            ("getsockname", WS2_32_BASE + 0x10),
            ("getpeername", WS2_32_BASE + 0x11),
            ("getsockopt", WS2_32_BASE + 0x12),
            ("setsockopt", WS2_32_BASE + 0x13),
            ("ioctlsocket", WS2_32_BASE + 0x14),
            // Name resolution
            ("getaddrinfo", WS2_32_BASE + 0x15),
            ("freeaddrinfo", WS2_32_BASE + 0x16),
            ("GetHostNameW", WS2_32_BASE + 0x17),
            // Misc
            ("select", WS2_32_BASE + 0x18),
            ("shutdown", WS2_32_BASE + 0x19),
            ("WSADuplicateSocketW", WS2_32_BASE + 0x1A),
            // Byte-order conversion
            ("htons", WS2_32_BASE + 0x1C),
            ("htonl", WS2_32_BASE + 0x1D),
            ("ntohs", WS2_32_BASE + 0x1E),
            ("ntohl", WS2_32_BASE + 0x1F),
            // FD_ISSET helper (called by the FD_ISSET macro on Windows)
            ("__WSAFDIsSet", WS2_32_BASE + 0x20),
            // Phase 40: WSA events and gethostbyname
            ("WSACreateEvent", WS2_32_BASE + 0x21),
            ("WSACloseEvent", WS2_32_BASE + 0x22),
            ("WSAResetEvent", WS2_32_BASE + 0x23),
            ("WSASetEvent", WS2_32_BASE + 0x24),
            ("WSAEventSelect", WS2_32_BASE + 0x25),
            ("WSAEnumNetworkEvents", WS2_32_BASE + 0x26),
            ("WSAWaitForMultipleEvents", WS2_32_BASE + 0x27),
            ("gethostbyname", WS2_32_BASE + 0x28),
            ("WSAAsyncSelect", WS2_32_BASE + 0x29),
            ("WSAIoctl", WS2_32_BASE + 0x2A),
            ("inet_addr", WS2_32_BASE + 0x2B),
            ("inet_pton", WS2_32_BASE + 0x2C),
            ("inet_ntop", WS2_32_BASE + 0x2D),
            ("WSAPoll", WS2_32_BASE + 0x2E),
            // Phase 44: service/protocol lookup
            ("getservbyname", WS2_32_BASE + 0x2F),
            ("getservbyport", WS2_32_BASE + 0x30),
            ("getprotobyname", WS2_32_BASE + 0x31),
        ];

        self.register_stub_dll("WS2_32.dll", exports);
    }

    /// Load stub api-ms-win-core-synch-l1-2-0.dll
    fn load_stub_apims_synch(&mut self) {
        use stub_addresses::APIMS_SYNCH_BASE;

        let exports = vec![
            // Modern synchronization primitives
            ("WaitOnAddress", APIMS_SYNCH_BASE),
            ("WakeByAddressAll", APIMS_SYNCH_BASE + 1),
            ("WakeByAddressSingle", APIMS_SYNCH_BASE + 2),
        ];

        self.register_stub_dll("api-ms-win-core-synch-l1-2-0.dll", exports);
    }

    /// Load stub USER32.dll (Windows GUI)
    fn load_stub_user32(&mut self) {
        use stub_addresses::USER32_BASE;

        let exports = vec![
            // Message box
            ("MessageBoxW", USER32_BASE),
            // Window class / creation
            ("RegisterClassExW", USER32_BASE + 1),
            ("CreateWindowExW", USER32_BASE + 2),
            // Window visibility / updates
            ("ShowWindow", USER32_BASE + 3),
            ("UpdateWindow", USER32_BASE + 4),
            // Message loop
            ("GetMessageW", USER32_BASE + 5),
            ("TranslateMessage", USER32_BASE + 6),
            ("DispatchMessageW", USER32_BASE + 7),
            // Window destruction
            ("DestroyWindow", USER32_BASE + 8),
            // Extended window management
            ("PostQuitMessage", USER32_BASE + 9),
            ("DefWindowProcW", USER32_BASE + 10),
            ("LoadCursorW", USER32_BASE + 11),
            ("LoadIconW", USER32_BASE + 12),
            ("GetSystemMetrics", USER32_BASE + 13),
            ("SetWindowLongPtrW", USER32_BASE + 14),
            ("GetWindowLongPtrW", USER32_BASE + 15),
            ("SendMessageW", USER32_BASE + 16),
            ("PostMessageW", USER32_BASE + 17),
            ("PeekMessageW", USER32_BASE + 18),
            // Painting
            ("BeginPaint", USER32_BASE + 19),
            ("EndPaint", USER32_BASE + 20),
            ("GetClientRect", USER32_BASE + 21),
            ("InvalidateRect", USER32_BASE + 22),
            // Timer
            ("SetTimer", USER32_BASE + 23),
            ("KillTimer", USER32_BASE + 24),
            // Device context
            ("GetDC", USER32_BASE + 25),
            ("ReleaseDC", USER32_BASE + 26),
            // Phase 27: Character Conversion
            ("CharUpperW", USER32_BASE + 27),
            ("CharLowerW", USER32_BASE + 28),
            ("CharUpperA", USER32_BASE + 29),
            ("CharLowerA", USER32_BASE + 30),
            // Phase 27: Character Classification
            ("IsCharAlphaW", USER32_BASE + 31),
            ("IsCharAlphaNumericW", USER32_BASE + 32),
            ("IsCharUpperW", USER32_BASE + 33),
            ("IsCharLowerW", USER32_BASE + 34),
            // Phase 27: Window Utilities
            ("IsWindow", USER32_BASE + 35),
            ("IsWindowEnabled", USER32_BASE + 36),
            ("IsWindowVisible", USER32_BASE + 37),
            ("EnableWindow", USER32_BASE + 38),
            ("GetWindowTextW", USER32_BASE + 39),
            ("SetWindowTextW", USER32_BASE + 40),
            ("GetParent", USER32_BASE + 41),
            // Phase 28
            ("FindWindowW", USER32_BASE + 42),
            ("FindWindowExW", USER32_BASE + 43),
            ("GetForegroundWindow", USER32_BASE + 44),
            ("SetForegroundWindow", USER32_BASE + 45),
            ("BringWindowToTop", USER32_BASE + 46),
            ("GetWindowRect", USER32_BASE + 47),
            ("SetWindowPos", USER32_BASE + 48),
            ("MoveWindow", USER32_BASE + 49),
            ("GetCursorPos", USER32_BASE + 50),
            ("SetCursorPos", USER32_BASE + 51),
            ("ScreenToClient", USER32_BASE + 52),
            ("ClientToScreen", USER32_BASE + 53),
            ("ShowCursor", USER32_BASE + 54),
            ("GetFocus", USER32_BASE + 55),
            ("SetFocus", USER32_BASE + 56),
            // Phase 45: Dialog, menu, clipboard, drawing, capture, misc GUI
            ("RegisterClassW", USER32_BASE + 57),
            ("CreateWindowW", USER32_BASE + 58),
            ("DialogBoxParamW", USER32_BASE + 59),
            ("CreateDialogParamW", USER32_BASE + 60),
            ("EndDialog", USER32_BASE + 61),
            ("GetDlgItem", USER32_BASE + 62),
            ("GetDlgItemTextW", USER32_BASE + 63),
            ("SetDlgItemTextW", USER32_BASE + 64),
            ("SendDlgItemMessageW", USER32_BASE + 65),
            ("GetDlgItemInt", USER32_BASE + 66),
            ("SetDlgItemInt", USER32_BASE + 67),
            ("CheckDlgButton", USER32_BASE + 68),
            ("IsDlgButtonChecked", USER32_BASE + 69),
            ("DrawTextW", USER32_BASE + 70),
            ("DrawTextA", USER32_BASE + 71),
            ("DrawTextExW", USER32_BASE + 72),
            ("AdjustWindowRect", USER32_BASE + 73),
            ("AdjustWindowRectEx", USER32_BASE + 74),
            ("SystemParametersInfoW", USER32_BASE + 75),
            ("SystemParametersInfoA", USER32_BASE + 76),
            ("CreateMenu", USER32_BASE + 77),
            ("CreatePopupMenu", USER32_BASE + 78),
            ("DestroyMenu", USER32_BASE + 79),
            ("AppendMenuW", USER32_BASE + 80),
            ("InsertMenuItemW", USER32_BASE + 81),
            ("GetMenu", USER32_BASE + 82),
            ("SetMenu", USER32_BASE + 83),
            ("DrawMenuBar", USER32_BASE + 84),
            ("TrackPopupMenu", USER32_BASE + 85),
            ("SetCapture", USER32_BASE + 86),
            ("ReleaseCapture", USER32_BASE + 87),
            ("GetCapture", USER32_BASE + 88),
            ("TrackMouseEvent", USER32_BASE + 89),
            ("RedrawWindow", USER32_BASE + 90),
            ("OpenClipboard", USER32_BASE + 91),
            ("CloseClipboard", USER32_BASE + 92),
            ("EmptyClipboard", USER32_BASE + 93),
            ("GetClipboardData", USER32_BASE + 94),
            ("SetClipboardData", USER32_BASE + 95),
            ("LoadStringW", USER32_BASE + 96),
            ("LoadBitmapW", USER32_BASE + 97),
            ("LoadImageW", USER32_BASE + 98),
            ("CallWindowProcW", USER32_BASE + 99),
            ("GetWindowInfo", USER32_BASE + 100),
            ("MapWindowPoints", USER32_BASE + 101),
            ("MonitorFromWindow", USER32_BASE + 102),
            ("MonitorFromPoint", USER32_BASE + 103),
            ("GetMonitorInfoW", USER32_BASE + 104),
        ];

        self.register_stub_dll("USER32.dll", exports);
    }
    /// Load stub ADVAPI32.dll (Windows Registry and security APIs)
    fn load_stub_advapi32(&mut self) {
        use stub_addresses::ADVAPI32_BASE;

        let exports = vec![
            // Registry key operations
            ("RegOpenKeyExW", ADVAPI32_BASE),
            ("RegCreateKeyExW", ADVAPI32_BASE + 1),
            ("RegCloseKey", ADVAPI32_BASE + 2),
            // Registry value operations
            ("RegQueryValueExW", ADVAPI32_BASE + 3),
            ("RegSetValueExW", ADVAPI32_BASE + 4),
            ("RegDeleteValueW", ADVAPI32_BASE + 5),
            // Registry enumeration
            ("RegEnumKeyExW", ADVAPI32_BASE + 6),
            ("RegEnumValueW", ADVAPI32_BASE + 7),
            // Phase 26: User Name
            ("GetUserNameW", ADVAPI32_BASE + 8),
            ("GetUserNameA", ADVAPI32_BASE + 9),
        ];

        self.register_stub_dll("ADVAPI32.dll", exports);
    }

    /// Load stub GDI32.dll (Windows GDI graphics APIs)
    fn load_stub_gdi32(&mut self) {
        use stub_addresses::GDI32_BASE;

        let exports = vec![
            // Stock objects and brushes
            ("GetStockObject", GDI32_BASE),
            ("CreateSolidBrush", GDI32_BASE + 1),
            ("DeleteObject", GDI32_BASE + 2),
            // Device context
            ("SelectObject", GDI32_BASE + 3),
            ("CreateCompatibleDC", GDI32_BASE + 4),
            ("DeleteDC", GDI32_BASE + 5),
            // Color
            ("SetBkColor", GDI32_BASE + 6),
            ("SetTextColor", GDI32_BASE + 7),
            // Drawing
            ("TextOutW", GDI32_BASE + 8),
            ("Rectangle", GDI32_BASE + 9),
            ("FillRect", GDI32_BASE + 10),
            // Font
            ("CreateFontW", GDI32_BASE + 11),
            ("GetTextExtentPoint32W", GDI32_BASE + 12),
            // Phase 45: Extended graphics primitives
            ("GetDeviceCaps", GDI32_BASE + 13),
            ("SetBkMode", GDI32_BASE + 14),
            ("SetMapMode", GDI32_BASE + 15),
            ("SetViewportOrgEx", GDI32_BASE + 16),
            ("CreatePen", GDI32_BASE + 17),
            ("CreatePenIndirect", GDI32_BASE + 18),
            ("CreateBrushIndirect", GDI32_BASE + 19),
            ("CreatePatternBrush", GDI32_BASE + 20),
            ("CreateHatchBrush", GDI32_BASE + 21),
            ("CreateBitmap", GDI32_BASE + 22),
            ("CreateCompatibleBitmap", GDI32_BASE + 23),
            ("CreateDIBSection", GDI32_BASE + 24),
            ("GetDIBits", GDI32_BASE + 25),
            ("SetDIBits", GDI32_BASE + 26),
            ("BitBlt", GDI32_BASE + 27),
            ("StretchBlt", GDI32_BASE + 28),
            ("PatBlt", GDI32_BASE + 29),
            ("GetPixel", GDI32_BASE + 30),
            ("SetPixel", GDI32_BASE + 31),
            ("MoveToEx", GDI32_BASE + 32),
            ("LineTo", GDI32_BASE + 33),
            ("Polyline", GDI32_BASE + 34),
            ("Polygon", GDI32_BASE + 35),
            ("Ellipse", GDI32_BASE + 36),
            ("Arc", GDI32_BASE + 37),
            ("RoundRect", GDI32_BASE + 38),
            ("GetTextMetricsW", GDI32_BASE + 39),
            ("CreateRectRgn", GDI32_BASE + 40),
            ("SelectClipRgn", GDI32_BASE + 41),
            ("GetClipBox", GDI32_BASE + 42),
            ("SetStretchBltMode", GDI32_BASE + 43),
            ("GetObjectW", GDI32_BASE + 44),
            ("GetCurrentObject", GDI32_BASE + 45),
            ("ExcludeClipRect", GDI32_BASE + 46),
            ("IntersectClipRect", GDI32_BASE + 47),
            ("SaveDC", GDI32_BASE + 48),
            ("RestoreDC", GDI32_BASE + 49),
        ];

        self.register_stub_dll("GDI32.dll", exports);
    }

    fn load_stub_shell32(&mut self) {
        use stub_addresses::SHELL32_BASE;

        let exports = vec![
            ("CommandLineToArgvW", SHELL32_BASE),
            ("SHGetFolderPathW", SHELL32_BASE + 1),
            ("ShellExecuteW", SHELL32_BASE + 2),
            ("SHCreateDirectoryExW", SHELL32_BASE + 3),
        ];

        self.register_stub_dll("SHELL32.dll", exports);
    }

    fn load_stub_version(&mut self) {
        use stub_addresses::VERSION_BASE;

        let exports = vec![
            ("GetFileVersionInfoSizeW", VERSION_BASE),
            ("GetFileVersionInfoW", VERSION_BASE + 1),
            ("VerQueryValueW", VERSION_BASE + 2),
        ];

        self.register_stub_dll("VERSION.dll", exports);
    }

    /// Load stub SHLWAPI.dll (Shell Lightweight Utility APIs)
    fn load_stub_shlwapi(&mut self) {
        use stub_addresses::SHLWAPI_BASE;

        let exports = vec![
            ("PathFileExistsW", SHLWAPI_BASE),
            ("PathCombineW", SHLWAPI_BASE + 1),
            ("PathGetFileNameW", SHLWAPI_BASE + 2),
            ("PathRemoveFileSpecW", SHLWAPI_BASE + 3),
            ("PathIsRelativeW", SHLWAPI_BASE + 4),
            ("PathFindExtensionW", SHLWAPI_BASE + 5),
            ("PathStripPathW", SHLWAPI_BASE + 6),
            ("PathAddBackslashW", SHLWAPI_BASE + 7),
            ("StrToIntW", SHLWAPI_BASE + 8),
            ("StrCmpIW", SHLWAPI_BASE + 9),
        ];

        self.register_stub_dll("SHLWAPI.dll", exports);
    }

    /// Load stub OLEAUT32.dll (OLE Automation APIs)
    fn load_stub_oleaut32(&mut self) {
        use stub_addresses::OLEAUT32_BASE;

        let exports = vec![
            // COM error info
            ("GetErrorInfo", OLEAUT32_BASE),
            ("SetErrorInfo", OLEAUT32_BASE + 1),
            // BSTR (Basic String) functions
            ("SysFreeString", OLEAUT32_BASE + 2),
            ("SysStringLen", OLEAUT32_BASE + 3),
            ("SysAllocString", OLEAUT32_BASE + 4),
            ("SysAllocStringLen", OLEAUT32_BASE + 5),
        ];

        self.register_stub_dll("OLEAUT32.dll", exports);
    }

    /// Load stub api-ms-win-core-winrt-error-l1-1-0.dll (Windows Runtime error APIs)
    fn load_stub_winrt_error(&mut self) {
        use stub_addresses::WINRT_ERROR_BASE;

        let exports = vec![
            // Windows Runtime error origination
            ("RoOriginateErrorW", WINRT_ERROR_BASE),
            ("RoOriginateError", WINRT_ERROR_BASE + 1),
            ("RoGetErrorReportingFlags", WINRT_ERROR_BASE + 2),
        ];

        self.register_stub_dll("api-ms-win-core-winrt-error-l1-1-0.dll", exports);
    }

    /// Load stub ole32.dll (COM initialization and memory functions)
    fn load_stub_ole32(&mut self) {
        use stub_addresses::OLE32_BASE;

        let exports = vec![
            // COM initialization
            ("CoInitialize", OLE32_BASE),
            ("CoInitializeEx", OLE32_BASE + 1),
            ("CoUninitialize", OLE32_BASE + 2),
            // COM object creation
            ("CoCreateInstance", OLE32_BASE + 3),
            ("CoGetClassObject", OLE32_BASE + 4),
            // GUID functions
            ("CoCreateGuid", OLE32_BASE + 5),
            ("StringFromGUID2", OLE32_BASE + 6),
            ("CLSIDFromString", OLE32_BASE + 7),
            // COM task memory
            ("CoTaskMemAlloc", OLE32_BASE + 8),
            ("CoTaskMemFree", OLE32_BASE + 9),
            ("CoTaskMemRealloc", OLE32_BASE + 10),
            // Security
            ("CoSetProxyBlanket", OLE32_BASE + 11),
        ];

        self.register_stub_dll("ole32.dll", exports);
    }

    /// Load stub msvcp140.dll (Microsoft C++ Standard Library)
    ///
    /// Registers stub exports for the most commonly imported symbols from
    /// `msvcp140.dll`.  The C++ mangled names are used as export names so
    /// that the PE import resolver can match them.
    fn load_stub_msvcp140(&mut self) {
        use stub_addresses::MSVCP140_BASE;

        let exports = vec![
            // Global operator new / delete
            ("??2@YAPEAX_K@Z", MSVCP140_BASE), // operator new(size_t)
            ("??3@YAXPEAX@Z", MSVCP140_BASE + 1), // operator delete(void*)
            ("??_U@YAPEAX_K@Z", MSVCP140_BASE + 2), // operator new[](size_t)
            ("??_V@YAXPEAX@Z", MSVCP140_BASE + 3), // operator delete[](void*)
            // Standard exception helpers
            ("?_Xbad_alloc@std@@YAXXZ", MSVCP140_BASE + 4),
            ("?_Xlength_error@std@@YAXPEBD@Z", MSVCP140_BASE + 5),
            ("?_Xout_of_range@std@@YAXPEBD@Z", MSVCP140_BASE + 6),
            ("?_Xinvalid_argument@std@@YAXPEBD@Z", MSVCP140_BASE + 7),
            ("?_Xruntime_error@std@@YAXPEBD@Z", MSVCP140_BASE + 8),
            ("?_Xoverflow_error@std@@YAXPEBD@Z", MSVCP140_BASE + 9),
            // Locale helpers
            (
                "?_Getctype@_Locinfo@std@@QEBAPBU_Ctypevec@@XZ",
                MSVCP140_BASE + 10,
            ),
            ("?_Getdays@_Locinfo@std@@QEBAPEBDXZ", MSVCP140_BASE + 11),
            ("?_Getmonths@_Locinfo@std@@QEBAPEBDXZ", MSVCP140_BASE + 12),
            // Phase 35: std::exception stubs
            ("?what@exception@std@@UEBAPEBDXZ", MSVCP140_BASE + 13),
            ("??1exception@std@@UEAA@XZ", MSVCP140_BASE + 14),
            ("??0exception@std@@QEAA@XZ", MSVCP140_BASE + 15),
            ("??0exception@std@@QEAA@PEBD@Z", MSVCP140_BASE + 16),
            // Phase 35: locale / lockit stubs
            (
                "?_Getgloballocale@locale@std@@CAPEAV_Lobj@12@XZ",
                MSVCP140_BASE + 17,
            ),
            ("??0_Lockit@std@@QEAA@H@Z", MSVCP140_BASE + 18),
            ("??1_Lockit@std@@QEAA@XZ", MSVCP140_BASE + 19),
            // Phase 35: ios_base::Init stubs
            ("??0Init@ios_base@std@@QEAA@XZ", MSVCP140_BASE + 20),
            ("??1Init@ios_base@std@@QEAA@XZ", MSVCP140_BASE + 21),
            // Phase 37: std::basic_string<char> member functions
            (
                "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ",
                MSVCP140_BASE + 22,
            ),
            (
                "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@PEBD@Z",
                MSVCP140_BASE + 23,
            ),
            (
                "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@AEBV01@@Z",
                MSVCP140_BASE + 24,
            ),
            (
                "??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ",
                MSVCP140_BASE + 25,
            ),
            (
                "?c_str@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBAPEBDXZ",
                MSVCP140_BASE + 26,
            ),
            (
                "?size@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA_KXZ",
                MSVCP140_BASE + 27,
            ),
            (
                "?empty@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA_NXZ",
                MSVCP140_BASE + 28,
            ),
            (
                "??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV01@AEBV01@@Z",
                MSVCP140_BASE + 29,
            ),
            (
                "??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV01@PEBD@Z",
                MSVCP140_BASE + 30,
            ),
            (
                "?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV12@PEBD@Z",
                MSVCP140_BASE + 31,
            ),
            // Phase 38: std::basic_string<wchar_t> member functions
            (
                "??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ",
                MSVCP140_BASE + 32,
            ),
            (
                "??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@PEB_W@Z",
                MSVCP140_BASE + 33,
            ),
            (
                "??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@AEBV01@@Z",
                MSVCP140_BASE + 34,
            ),
            (
                "??1?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ",
                MSVCP140_BASE + 35,
            ),
            (
                "?c_str@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBAPEB_WXZ",
                MSVCP140_BASE + 36,
            ),
            (
                "?size@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBA_KXZ",
                MSVCP140_BASE + 37,
            ),
            (
                "?empty@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBA_NXZ",
                MSVCP140_BASE + 38,
            ),
            (
                "??4?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@AEBV01@@Z",
                MSVCP140_BASE + 39,
            ),
            (
                "??4?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV01@PEB_W@Z",
                MSVCP140_BASE + 40,
            ),
            (
                "?append@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@PEB_W@Z",
                MSVCP140_BASE + 41,
            ),
            // Phase 39: std::vector<char> member functions
            (
                "??0?$vector@DU?$allocator@D@std@@@std@@QEAA@XZ",
                MSVCP140_BASE + 42,
            ),
            (
                "??1?$vector@DU?$allocator@D@std@@@std@@QEAA@XZ",
                MSVCP140_BASE + 43,
            ),
            (
                "?push_back@?$vector@DU?$allocator@D@std@@@std@@QEAAXAEBD@Z",
                MSVCP140_BASE + 44,
            ),
            (
                "?size@?$vector@DU?$allocator@D@std@@@std@@QEBA_KXZ",
                MSVCP140_BASE + 45,
            ),
            (
                "?capacity@?$vector@DU?$allocator@D@std@@@std@@QEBA_KXZ",
                MSVCP140_BASE + 46,
            ),
            (
                "?clear@?$vector@DU?$allocator@D@std@@@std@@QEAAXXZ",
                MSVCP140_BASE + 47,
            ),
            (
                "?data@?$vector@DU?$allocator@D@std@@@std@@QEAAPEADXZ",
                MSVCP140_BASE + 48,
            ),
            (
                "?data@?$vector@DU?$allocator@D@std@@@std@@QEBAPEBDXZ",
                MSVCP140_BASE + 49,
            ),
            (
                "?reserve@?$vector@DU?$allocator@D@std@@@std@@QEAAX_K@Z",
                MSVCP140_BASE + 50,
            ),
            // std::map<void*,void*> mangled names (MSVC x64)
            (
                "??0?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA@XZ",
                MSVCP140_BASE + 51,
            ),
            (
                "??1?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA@XZ",
                MSVCP140_BASE + 52,
            ),
            (
                "?insert@?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAAAEAU?$pair@V?$_Tree_iterator@V?$_Tree_val@U?$_Tree_simple_types@U?$pair@$$CBPEAXPEAX@std@@@std@@@std@@@std@@_N@std@@AEBU?$pair@$$CBPEAXPEAX@2@@2@@Z",
                MSVCP140_BASE + 53,
            ),
            (
                "?find@?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAAV?$_Tree_iterator@V?$_Tree_val@U?$_Tree_simple_types@U?$pair@$$CBPEAXPEAX@std@@@std@@@std@@@2@AEBQEAX@Z",
                MSVCP140_BASE + 54,
            ),
            (
                "?size@?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEBA_KXZ",
                MSVCP140_BASE + 55,
            ),
            (
                "?clear@?$map@PEAXPEAXU?$less@PEAX@std@@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAAXXZ",
                MSVCP140_BASE + 56,
            ),
            // std::ostringstream (basic_ostringstream<char>) mangled names (MSVC x64)
            (
                "??0?$basic_ostringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@H@Z",
                MSVCP140_BASE + 57,
            ),
            (
                "??1?$basic_ostringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@UEAA@XZ",
                MSVCP140_BASE + 58,
            ),
            (
                "?str@?$basic_ostringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@XZ",
                MSVCP140_BASE + 59,
            ),
            (
                "?write@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEBD_J@Z",
                MSVCP140_BASE + 60,
            ),
            (
                "?tellp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ",
                MSVCP140_BASE + 61,
            ),
            (
                "?seekp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z",
                MSVCP140_BASE + 62,
            ),
            // std::istringstream (basic_istringstream<char>) mangled names (MSVC x64)
            (
                "??0?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@H@Z",
                MSVCP140_BASE + 63,
            ),
            (
                "??0?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@H@Z",
                MSVCP140_BASE + 64,
            ),
            (
                "??1?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@UEAA@XZ",
                MSVCP140_BASE + 65,
            ),
            (
                "?str@?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@XZ",
                MSVCP140_BASE + 66,
            ),
            (
                "?str@?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAXAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@@Z",
                MSVCP140_BASE + 67,
            ),
            (
                "?read@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEAD_J@Z",
                MSVCP140_BASE + 68,
            ),
            (
                "?seekg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z",
                MSVCP140_BASE + 69,
            ),
            (
                "?tellg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ",
                MSVCP140_BASE + 70,
            ),
            // Phase 43: std::stringstream (basic_stringstream<char>) mangled names
            (
                "??0?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@H@Z",
                MSVCP140_BASE + 71,
            ),
            (
                "??0?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@H@Z",
                MSVCP140_BASE + 72,
            ),
            (
                "??1?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@UEAA@XZ",
                MSVCP140_BASE + 73,
            ),
            (
                "?str@?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@XZ",
                MSVCP140_BASE + 74,
            ),
            (
                "?str@?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAXAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@@Z",
                MSVCP140_BASE + 75,
            ),
            (
                "?read@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEAD_J@Z",
                MSVCP140_BASE + 76,
            ),
            (
                "?write@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEBD_J@Z",
                MSVCP140_BASE + 77,
            ),
            (
                "?seekg@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z",
                MSVCP140_BASE + 78,
            ),
            (
                "?tellg@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ",
                MSVCP140_BASE + 79,
            ),
            (
                "?seekp@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z",
                MSVCP140_BASE + 80,
            ),
            (
                "?tellp@?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ",
                MSVCP140_BASE + 81,
            ),
            // Phase 43: std::unordered_map<void*,void*> mangled names
            (
                "??0?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA@XZ",
                MSVCP140_BASE + 82,
            ),
            (
                "??1?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA@XZ",
                MSVCP140_BASE + 83,
            ),
            (
                "?size@?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEBA_KXZ",
                MSVCP140_BASE + 84,
            ),
            (
                "?clear@?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAAXXZ",
                MSVCP140_BASE + 85,
            ),
            (
                "?insert@?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA?AV?$pair@_K_N@2@$$QEAV?$pair@PEAXPEAX@2@@Z",
                MSVCP140_BASE + 86,
            ),
            (
                "?find@?$unordered_map@PEAXPEAXU?$hash@PEAX@std@@U?$equal_to@PEAX@2@V?$allocator@U?$pair@$$CBPEAXPEAX@std@@@2@@std@@QEAA?AV?$pair@_K_N@2@PEAX@Z",
                MSVCP140_BASE + 87,
            ),
            // Phase 44: std::deque<void*>
            (
                "??0?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAA@XZ",
                MSVCP140_BASE + 88,
            ),
            (
                "??1?$deque@PEAXV?$allocator@PEAX@std@@@std@@UEAA@XZ",
                MSVCP140_BASE + 89,
            ),
            (
                "?push_back@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXPEAX@Z",
                MSVCP140_BASE + 90,
            ),
            (
                "?push_front@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXPEAX@Z",
                MSVCP140_BASE + 91,
            ),
            (
                "?pop_front@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXXZ",
                MSVCP140_BASE + 92,
            ),
            (
                "?pop_back@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXXZ",
                MSVCP140_BASE + 93,
            ),
            (
                "?front@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAAEAPEAXXZ",
                MSVCP140_BASE + 94,
            ),
            (
                "?back@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAAEAPEAXXZ",
                MSVCP140_BASE + 95,
            ),
            (
                "?size@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEBA_KXZ",
                MSVCP140_BASE + 96,
            ),
            (
                "?clear@?$deque@PEAXV?$allocator@PEAX@std@@@std@@QEAAXXZ",
                MSVCP140_BASE + 97,
            ),
            // Phase 44: std::stack<void*>
            (
                "??0?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAA@XZ",
                MSVCP140_BASE + 98,
            ),
            (
                "??1?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@UEAA@XZ",
                MSVCP140_BASE + 99,
            ),
            (
                "?push@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAXPEAX@Z",
                MSVCP140_BASE + 100,
            ),
            (
                "?pop@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAXXZ",
                MSVCP140_BASE + 101,
            ),
            (
                "?top@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAAEAPEAXXZ",
                MSVCP140_BASE + 102,
            ),
            (
                "?size@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEBA_KXZ",
                MSVCP140_BASE + 103,
            ),
            (
                "?empty@?$stack@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEBA_NXZ",
                MSVCP140_BASE + 104,
            ),
            // Phase 44: std::queue<void*>
            (
                "??0?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAA@XZ",
                MSVCP140_BASE + 105,
            ),
            (
                "??1?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@UEAA@XZ",
                MSVCP140_BASE + 106,
            ),
            (
                "?push@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAXPEAX@Z",
                MSVCP140_BASE + 107,
            ),
            (
                "?pop@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAXXZ",
                MSVCP140_BASE + 108,
            ),
            (
                "?front@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAAEAPEAXXZ",
                MSVCP140_BASE + 109,
            ),
            (
                "?back@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEAAAEAPEAXXZ",
                MSVCP140_BASE + 110,
            ),
            (
                "?size@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEBA_KXZ",
                MSVCP140_BASE + 111,
            ),
            (
                "?empty@?$queue@PEAXV?$deque@PEAXV?$allocator@PEAX@std@@@std@@@std@@QEBA_NXZ",
                MSVCP140_BASE + 112,
            ),
        ];

        self.register_stub_dll("msvcp140.dll", exports);
    }

    /// Load stub vulkan-1.dll (Vulkan API stubs, Phase 45)
    fn load_stub_vulkan1(&mut self) {
        use stub_addresses::VULKAN1_BASE;

        let exports = vec![
            // Instance management
            ("vkCreateInstance", VULKAN1_BASE),
            ("vkDestroyInstance", VULKAN1_BASE + 1),
            ("vkEnumerateInstanceExtensionProperties", VULKAN1_BASE + 2),
            ("vkEnumerateInstanceLayerProperties", VULKAN1_BASE + 3),
            // Physical device
            ("vkEnumeratePhysicalDevices", VULKAN1_BASE + 4),
            ("vkGetPhysicalDeviceProperties", VULKAN1_BASE + 5),
            ("vkGetPhysicalDeviceFeatures", VULKAN1_BASE + 6),
            ("vkGetPhysicalDeviceQueueFamilyProperties", VULKAN1_BASE + 7),
            ("vkGetPhysicalDeviceMemoryProperties", VULKAN1_BASE + 8),
            // Logical device
            ("vkCreateDevice", VULKAN1_BASE + 9),
            ("vkDestroyDevice", VULKAN1_BASE + 10),
            ("vkGetDeviceQueue", VULKAN1_BASE + 11),
            // Surface (KHR_win32_surface)
            ("vkCreateWin32SurfaceKHR", VULKAN1_BASE + 12),
            ("vkDestroySurfaceKHR", VULKAN1_BASE + 13),
            ("vkGetPhysicalDeviceSurfaceSupportKHR", VULKAN1_BASE + 14),
            (
                "vkGetPhysicalDeviceSurfaceCapabilitiesKHR",
                VULKAN1_BASE + 15,
            ),
            ("vkGetPhysicalDeviceSurfaceFormatsKHR", VULKAN1_BASE + 16),
            (
                "vkGetPhysicalDeviceSurfacePresentModesKHR",
                VULKAN1_BASE + 17,
            ),
            // Swapchain (KHR_swapchain)
            ("vkCreateSwapchainKHR", VULKAN1_BASE + 18),
            ("vkDestroySwapchainKHR", VULKAN1_BASE + 19),
            ("vkGetSwapchainImagesKHR", VULKAN1_BASE + 20),
            ("vkAcquireNextImageKHR", VULKAN1_BASE + 21),
            ("vkQueuePresentKHR", VULKAN1_BASE + 22),
            // Memory & Resources
            ("vkAllocateMemory", VULKAN1_BASE + 23),
            ("vkFreeMemory", VULKAN1_BASE + 24),
            ("vkCreateBuffer", VULKAN1_BASE + 25),
            ("vkDestroyBuffer", VULKAN1_BASE + 26),
            ("vkCreateImage", VULKAN1_BASE + 27),
            ("vkDestroyImage", VULKAN1_BASE + 28),
            // Render passes & pipelines
            ("vkCreateRenderPass", VULKAN1_BASE + 29),
            ("vkDestroyRenderPass", VULKAN1_BASE + 30),
            ("vkCreateFramebuffer", VULKAN1_BASE + 31),
            ("vkDestroyFramebuffer", VULKAN1_BASE + 32),
            ("vkCreateGraphicsPipelines", VULKAN1_BASE + 33),
            ("vkDestroyPipeline", VULKAN1_BASE + 34),
            ("vkCreateShaderModule", VULKAN1_BASE + 35),
            ("vkDestroyShaderModule", VULKAN1_BASE + 36),
            // Command pools & buffers
            ("vkCreateCommandPool", VULKAN1_BASE + 37),
            ("vkDestroyCommandPool", VULKAN1_BASE + 38),
            ("vkAllocateCommandBuffers", VULKAN1_BASE + 39),
            ("vkFreeCommandBuffers", VULKAN1_BASE + 40),
            ("vkBeginCommandBuffer", VULKAN1_BASE + 41),
            ("vkEndCommandBuffer", VULKAN1_BASE + 42),
            ("vkCmdBeginRenderPass", VULKAN1_BASE + 43),
            ("vkCmdEndRenderPass", VULKAN1_BASE + 44),
            ("vkCmdDraw", VULKAN1_BASE + 45),
            ("vkCmdDrawIndexed", VULKAN1_BASE + 46),
            ("vkQueueSubmit", VULKAN1_BASE + 47),
            ("vkQueueWaitIdle", VULKAN1_BASE + 48),
            ("vkDeviceWaitIdle", VULKAN1_BASE + 49),
            // Synchronization
            ("vkCreateFence", VULKAN1_BASE + 50),
            ("vkDestroyFence", VULKAN1_BASE + 51),
            ("vkWaitForFences", VULKAN1_BASE + 52),
            ("vkResetFences", VULKAN1_BASE + 53),
            ("vkCreateSemaphore", VULKAN1_BASE + 54),
            ("vkDestroySemaphore", VULKAN1_BASE + 55),
            // Descriptor sets & pipeline layout
            ("vkCreateDescriptorSetLayout", VULKAN1_BASE + 56),
            ("vkDestroyDescriptorSetLayout", VULKAN1_BASE + 57),
            ("vkCreatePipelineLayout", VULKAN1_BASE + 58),
            ("vkDestroyPipelineLayout", VULKAN1_BASE + 59),
            // Proc address
            ("vkGetInstanceProcAddr", VULKAN1_BASE + 60),
            ("vkGetDeviceProcAddr", VULKAN1_BASE + 61),
        ];

        self.register_stub_dll("vulkan-1.dll", exports);
    }
}

/// Map Windows API Set DLL names to their real implementation DLLs
///
/// Windows uses API Sets as a layer of indirection between applications and
/// the actual DLL implementations. This allows Microsoft to refactor their
/// implementation without breaking compatibility.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets>
fn map_api_set_to_implementation(api_set_name: &str) -> &'static str {
    let name_upper = api_set_name.to_uppercase();

    // Core Process/Thread APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-PROCESSTHREADS-") {
        return "KERNEL32.dll";
    }

    // Synchronization APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-SYNCH-") {
        return "KERNEL32.dll";
    }

    // Memory APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-MEMORY-") {
        return "KERNEL32.dll";
    }

    // File I/O APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-FILE-") {
        return "KERNEL32.dll";
    }

    // Console APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-CONSOLE-") {
        return "KERNEL32.dll";
    }

    // Handle APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-HANDLE-") {
        return "KERNEL32.dll";
    }

    // Library Loader APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-LIBRARYLOADER-") {
        return "KERNEL32.dll";
    }

    // NT DLL APIs -> NTDLL.dll
    if name_upper.starts_with("API-MS-WIN-CORE-RTLSUPPORT-") {
        return "NTDLL.dll";
    }

    // C Runtime APIs -> MSVCRT.dll (UCRT API sets forward to the same implementations)
    if name_upper.starts_with("API-MS-WIN-CRT-") {
        return "MSVCRT.dll";
    }

    // Default to KERNEL32.dll for unknown API sets
    // Most API sets forward to KERNEL32
    "KERNEL32.dll"
}

impl Default for DllManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dll_manager_creation() {
        let manager = DllManager::new();
        // Should have 18 pre-loaded stub DLLs (KERNEL32, NTDLL, MSVCRT, bcrypt, USERENV,
        // WS2_32, api-ms-win-core-synch, USER32, ADVAPI32, GDI32, SHELL32, VERSION, SHLWAPI,
        // OLEAUT32, api-ms-win-core-winrt-error-l1-1-0, ole32, msvcp140, vulkan-1)
        assert_eq!(manager.dlls.len(), 18);
    }

    #[test]
    fn test_load_library_existing() {
        let mut manager = DllManager::new();
        let handle = manager.load_library("KERNEL32.dll").unwrap();
        assert!(handle.as_raw() > 0);
    }

    #[test]
    fn test_load_library_case_insensitive() {
        let mut manager = DllManager::new();
        let handle1 = manager.load_library("kernel32.dll").unwrap();
        let handle2 = manager.load_library("KERNEL32.DLL").unwrap();
        assert_eq!(handle1, handle2);
    }

    #[test]
    fn test_get_proc_address() {
        let mut manager = DllManager::new();
        let handle = manager.load_library("KERNEL32.dll").unwrap();
        let func = manager.get_proc_address(handle, "LoadLibraryA");
        assert!(func.is_ok());
    }

    #[test]
    fn test_get_proc_address_not_found() {
        let mut manager = DllManager::new();
        let handle = manager.load_library("KERNEL32.dll").unwrap();
        let result = manager.get_proc_address(handle, "NonExistentFunction");
        assert!(result.is_err());
    }

    #[test]
    fn test_free_library() {
        let mut manager = DllManager::new();
        let handle = manager.load_library("MSVCRT.dll").unwrap();
        let result = manager.free_library(handle);
        assert!(result.is_ok());

        // Should not be able to get proc address after freeing
        let result = manager.get_proc_address(handle, "printf");
        assert!(result.is_err());
    }

    #[test]
    fn test_vcruntime140_aliased_to_msvcrt() {
        let mut manager = DllManager::new();
        // VCRUNTIME140.dll should resolve to the same handle as MSVCRT.dll
        let msvcrt = manager.load_library("MSVCRT.dll").unwrap();
        let vcruntime = manager.load_library("vcruntime140.dll").unwrap();
        assert_eq!(
            msvcrt, vcruntime,
            "vcruntime140.dll must alias to MSVCRT.dll"
        );
        // Repeated loads return the cached alias
        let vcruntime2 = manager.load_library("VCRUNTIME140.DLL").unwrap();
        assert_eq!(msvcrt, vcruntime2);
    }

    #[test]
    fn test_ucrtbase_aliased_to_msvcrt() {
        let mut manager = DllManager::new();
        let msvcrt = manager.load_library("MSVCRT.dll").unwrap();
        let ucrtbase = manager.load_library("ucrtbase.dll").unwrap();
        assert_eq!(msvcrt, ucrtbase, "ucrtbase.dll must alias to MSVCRT.dll");
    }

    #[test]
    fn test_api_ms_win_crt_redirected_to_msvcrt() {
        let mut manager = DllManager::new();
        let msvcrt = manager.load_library("MSVCRT.dll").unwrap();
        // api-ms-win-crt-* DLLs should all forward to MSVCRT.dll
        for api_set in &[
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "api-ms-win-crt-stdio-l1-1-0.dll",
            "api-ms-win-crt-math-l1-1-0.dll",
            "api-ms-win-crt-heap-l1-1-0.dll",
            "api-ms-win-crt-locale-l1-1-0.dll",
        ] {
            let handle = manager.load_library(api_set).unwrap_or_else(|e| {
                panic!("Failed to load {api_set}: {e}");
            });
            assert_eq!(msvcrt, handle, "{api_set} must alias to MSVCRT.dll");
        }
    }

    #[test]
    fn test_msvc_hello_cli_exports_present() {
        let mut manager = DllManager::new();
        let kernel32 = manager.load_library("KERNEL32.dll").unwrap();
        for name in [
            "UnhandledExceptionFilter",
            "InitializeSListHead",
            "WaitForSingleObjectEx",
            "GetSystemTimeAsFileTime",
        ] {
            assert!(
                manager.get_proc_address(kernel32, name).is_ok(),
                "expected KERNEL32 export {name}"
            );
        }

        let crt = manager
            .load_library("api-ms-win-crt-runtime-l1-1-0.dll")
            .unwrap();
        for name in [
            "_get_initial_narrow_environment",
            "_set_app_type",
            "_exit",
            "_c_exit",
            "_register_thread_local_exe_atexit_callback",
            "_seh_filter_exe",
            "_initialize_onexit_table",
            "_register_onexit_function",
        ] {
            assert!(
                manager.get_proc_address(crt, name).is_ok(),
                "expected CRT export {name}"
            );
        }
        let stdio = manager
            .load_library("api-ms-win-crt-stdio-l1-1-0.dll")
            .unwrap();
        assert!(manager.get_proc_address(stdio, "_set_fmode").is_ok());
        let heap = manager
            .load_library("api-ms-win-crt-heap-l1-1-0.dll")
            .unwrap();
        assert!(manager.get_proc_address(heap, "_set_new_mode").is_ok());
    }
}
