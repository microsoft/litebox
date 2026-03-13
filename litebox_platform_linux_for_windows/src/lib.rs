// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux platform implementation for Windows APIs
//!
//! This crate implements Windows NTDLL APIs using Linux syscalls.
//! This is the "South" platform layer that translates Windows API calls
//! to Linux syscalls.

#![feature(c_variadic)]

pub mod advapi32;
pub mod bcrypt;
pub mod function_table;
pub mod gdi32;
pub mod kernel32;
pub mod msvcp140;
pub mod msvcrt;
pub mod ntdll_impl;
pub mod ole32;
pub mod oleaut32;
pub mod shell32;
pub mod shlwapi;
pub mod trampoline;
pub mod user32;
pub mod userenv;
pub mod version;
pub mod vulkan1;
#[cfg(feature = "real_vulkan")]
pub mod vulkan_loader;
pub mod ws2_32;

pub use kernel32::register_dynamic_exports;
pub use kernel32::register_exception_table;
pub use kernel32::set_process_command_line;
pub use kernel32::set_sandbox_root;
pub use kernel32::set_volume_serial;

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use thiserror::Error;

use litebox_shim_windows::loader::DllManager;
use litebox_shim_windows::syscalls::ntdll::{
    ConsoleHandle, EventHandle, FileHandle, NtdllApi, RegKeyHandle, SearchHandle, ThreadEntryPoint,
    ThreadHandle, Win32FindDataW,
};

use trampoline::TrampolineManager;

/// Windows error codes
mod windows_errors {
    /// The system cannot find the file specified
    pub const ERROR_FILE_NOT_FOUND: u32 = 2;
    /// Access is denied
    pub const ERROR_ACCESS_DENIED: u32 = 5;
    /// The handle is invalid
    pub const ERROR_INVALID_HANDLE: u32 = 6;
    /// The file exists
    pub const ERROR_FILE_EXISTS: u32 = 80;
    /// The parameter is incorrect
    pub const ERROR_INVALID_PARAMETER: u32 = 87;
}

/// Platform errors
#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid handle: {0}")]
    InvalidHandle(u64),

    #[error("Path translation error: {0}")]
    PathTranslation(String),

    #[error("Memory error: {0}")]
    MemoryError(String),

    #[error("Thread error: {0}")]
    ThreadError(String),

    #[error("Synchronization error: {0}")]
    SyncError(String),

    #[error("Timeout")]
    Timeout,

    #[error("Registry error: {0}")]
    RegistryError(String),

    #[error("Environment error: {0}")]
    EnvironmentError(String),
}

pub type Result<T> = core::result::Result<T, PlatformError>;

/// Windows file handle (maps to Linux FD)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WinHandle(u64);

/// Thread information
struct ThreadInfo {
    join_handle: Option<JoinHandle<u32>>,
    exit_code: Arc<Mutex<Option<u32>>>,
}

/// Event object for synchronization
struct EventObject {
    manual_reset: bool,
    state: Arc<(Mutex<bool>, Condvar)>,
}

/// Registry key object
#[allow(dead_code)]
struct RegistryKey {
    path: String,
    values: HashMap<String, String>,
}

/// Directory search state
struct SearchState {
    /// Directory entries iterator
    entries: Vec<std::fs::DirEntry>,
    /// Current index in entries
    current_index: usize,
    /// Search pattern (glob)
    pattern: String,
}

/// Internal platform state (thread-safe)
struct PlatformState {
    /// Handle to file descriptor mapping
    handles: HashMap<u64, File>,
    /// Thread handle mapping
    threads: HashMap<u64, ThreadInfo>,
    /// Event handle mapping
    events: HashMap<u64, EventObject>,
    /// Registry key mapping
    registry_keys: HashMap<u64, RegistryKey>,
    /// Search handle mapping (for FindFirstFile/FindNextFile)
    searches: HashMap<u64, SearchState>,
    /// Environment variables
    environment: HashMap<String, String>,
    /// DLL manager for LoadLibrary/GetProcAddress
    dll_manager: DllManager,
    /// Command line arguments (stored as UTF-16)
    command_line: Vec<u16>,
    /// Trampoline manager for executable code generation
    trampoline_manager: TrampolineManager,
}

/// Linux platform for Windows API implementation
pub struct LinuxPlatformForWindows {
    /// Thread-safe interior state
    state: Mutex<PlatformState>,
    /// Atomic handle ID generator
    next_handle: AtomicU64,
}

impl LinuxPlatformForWindows {
    /// Create a new platform instance
    pub fn new() -> Self {
        // Initialize with some default environment variables
        let mut environment = HashMap::new();
        environment.insert("COMPUTERNAME".to_string(), "LITEBOX-HOST".to_string());
        environment.insert("OS".to_string(), "Windows_NT".to_string());
        environment.insert("PROCESSOR_ARCHITECTURE".to_string(), "AMD64".to_string());

        // Initialize command line with program name (empty for now, will be set by runner)
        let command_line = Vec::new();

        Self {
            state: Mutex::new(PlatformState {
                handles: HashMap::new(),
                threads: HashMap::new(),
                events: HashMap::new(),
                registry_keys: HashMap::new(),
                searches: HashMap::new(),
                environment,
                dll_manager: DllManager::new(),
                command_line,
                trampoline_manager: TrampolineManager::new(),
            }),
            next_handle: AtomicU64::new(0x1000), // Start at a high value to avoid conflicts
        }
    }

    /// Allocate a new handle ID (thread-safe)
    fn allocate_handle(&self) -> u64 {
        self.next_handle.fetch_add(1, Ordering::SeqCst)
    }

    /// Set the command line for the process
    ///
    /// This should be called by the runner to set the command line arguments
    /// before executing the Windows program.
    ///
    /// # Panics
    ///
    /// Panics if the state mutex is poisoned.
    pub fn set_command_line(&mut self, args: &[String]) {
        let mut state = self.state.lock().unwrap();

        // Build command line string
        let cmd_line = if args.is_empty() {
            String::new()
        } else {
            args.iter()
                .map(|arg| {
                    // Quote arguments with spaces or quotes
                    // In Windows, quotes inside quoted strings are escaped by doubling them
                    if arg.contains(' ') || arg.contains('"') {
                        format!("\"{}\"", arg.replace('"', "\"\""))
                    } else {
                        arg.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        };

        // Convert to UTF-16 with null terminator
        let mut utf16: Vec<u16> = cmd_line.encode_utf16().collect();
        utf16.push(0);
        state.command_line = utf16;
    }

    /// NtCreateFile - Create or open a file (internal implementation)
    fn nt_create_file_impl(
        &mut self,
        path: &str,
        access: u32,
        create_disposition: u32,
    ) -> Result<u64> {
        let linux_path = translate_windows_path_to_linux(path);

        let mut options = OpenOptions::new();

        // Translate access flags
        if access & 0x80000000 != 0 {
            // GENERIC_READ
            options.read(true);
        }
        if access & 0x40000000 != 0 {
            // GENERIC_WRITE
            options.write(true);
        }

        // Translate creation disposition
        // CREATE_NEW = 1: Creates a new file, fails if file already exists
        // CREATE_ALWAYS = 2: Creates a new file, always (overwrites if exists)
        // OPEN_EXISTING = 3: Opens existing file, fails if doesn't exist
        // OPEN_ALWAYS = 4: Opens file if exists, creates if doesn't exist
        // TRUNCATE_EXISTING = 5: Opens and truncates existing file, fails if doesn't exist
        match create_disposition {
            1 => {
                // CREATE_NEW
                options.create_new(true).write(true);
            }
            2 => {
                // CREATE_ALWAYS
                options.create(true).truncate(true).write(true);
            }
            3 => {
                // OPEN_EXISTING - default behavior
            }
            4 => {
                // OPEN_ALWAYS
                options.create(true).write(true);
            }
            5 => {
                // TRUNCATE_EXISTING
                options.truncate(true).write(true);
            }
            _ => {
                // Invalid disposition
                self.set_last_error_impl(windows_errors::ERROR_INVALID_PARAMETER);
                return Err(PlatformError::PathTranslation(
                    "Invalid create disposition".to_string(),
                ));
            }
        }

        // Try to open the file and set appropriate error codes on failure
        match options.open(&linux_path) {
            Ok(file) => {
                let handle = self.allocate_handle();
                self.state.lock().unwrap().handles.insert(handle, file);
                self.set_last_error_impl(0); // Success
                Ok(handle)
            }
            Err(e) => {
                // Map IO error to Windows error code
                use std::io::ErrorKind;
                let error_code = match e.kind() {
                    ErrorKind::NotFound => windows_errors::ERROR_FILE_NOT_FOUND,
                    ErrorKind::PermissionDenied => windows_errors::ERROR_ACCESS_DENIED,
                    ErrorKind::AlreadyExists => windows_errors::ERROR_FILE_EXISTS,
                    _ => windows_errors::ERROR_INVALID_PARAMETER,
                };
                self.set_last_error_impl(error_code);
                Err(PlatformError::IoError(e))
            }
        }
    }

    /// NtReadFile - Read from a file (internal implementation)
    fn nt_read_file_impl(&mut self, handle: u64, buffer: &mut [u8]) -> Result<usize> {
        let mut state = self.state.lock().unwrap();
        let Some(file) = state.handles.get_mut(&handle) else {
            drop(state);
            self.set_last_error_impl(windows_errors::ERROR_INVALID_HANDLE);
            return Err(PlatformError::InvalidHandle(handle));
        };

        let result = file.read(buffer);
        drop(state);

        match result {
            Ok(bytes_read) => {
                self.set_last_error_impl(0); // Success
                Ok(bytes_read)
            }
            Err(e) => {
                self.set_last_error_impl(windows_errors::ERROR_INVALID_PARAMETER);
                Err(PlatformError::IoError(e))
            }
        }
    }

    /// NtWriteFile - Write to a file (internal implementation)
    fn nt_write_file_impl(&mut self, handle: u64, buffer: &[u8]) -> Result<usize> {
        let mut state = self.state.lock().unwrap();
        let Some(file) = state.handles.get_mut(&handle) else {
            drop(state);
            self.set_last_error_impl(windows_errors::ERROR_INVALID_HANDLE);
            return Err(PlatformError::InvalidHandle(handle));
        };

        let result = file.write(buffer);
        drop(state);

        match result {
            Ok(bytes_written) => {
                self.set_last_error_impl(0); // Success
                Ok(bytes_written)
            }
            Err(e) => {
                self.set_last_error_impl(windows_errors::ERROR_INVALID_PARAMETER);
                Err(PlatformError::IoError(e))
            }
        }
    }

    /// NtClose - Close a handle (internal implementation)
    fn nt_close_impl(&mut self, handle: u64) -> Result<()> {
        let result = self.state.lock().unwrap().handles.remove(&handle);

        if result.is_some() {
            self.set_last_error_impl(0); // Success
            Ok(())
        } else {
            self.set_last_error_impl(windows_errors::ERROR_INVALID_HANDLE);
            Err(PlatformError::InvalidHandle(handle))
        }
    }

    /// Get standard output handle (internal implementation)
    #[allow(clippy::unused_self)]
    fn get_std_output_impl(&self) -> u64 {
        // Use a special handle value for stdout
        0xFFFF_FFFF_0001
    }

    /// Write to console (internal implementation)
    #[allow(clippy::unused_self)]
    fn write_console_impl(&mut self, handle: u64, text: &str) -> Result<usize> {
        if handle == 0xFFFF_FFFF_0001 {
            print!("{text}");
            std::io::stdout().flush()?;
            Ok(text.len())
        } else {
            Err(PlatformError::InvalidHandle(handle))
        }
    }

    /// NtAllocateVirtualMemory - Allocate virtual memory (internal implementation)
    #[allow(clippy::unused_self)]
    fn nt_allocate_virtual_memory_impl(&mut self, size: usize, protect: u32) -> Result<u64> {
        use std::ptr;

        // Translate Windows protection flags to Linux PROT_ flags
        let mut prot = 0;
        if protect & 0x04 != 0 || protect & 0x40 != 0 {
            // PAGE_READWRITE or PAGE_EXECUTE_READWRITE
            prot |= libc::PROT_READ | libc::PROT_WRITE;
        } else if protect & 0x02 != 0 || protect & 0x20 != 0 {
            // PAGE_READONLY or PAGE_EXECUTE_READ
            prot |= libc::PROT_READ;
        }
        if protect & 0x10 != 0 || protect & 0x20 != 0 || protect & 0x40 != 0 {
            // Any EXECUTE flag
            prot |= libc::PROT_EXEC;
        }

        // SAFETY: mmap is called with valid parameters
        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if addr == libc::MAP_FAILED {
            return Err(PlatformError::MemoryError("mmap failed".to_string()));
        }

        Ok(addr as u64)
    }

    /// NtFreeVirtualMemory - Free virtual memory (internal implementation)
    #[allow(clippy::unused_self)]
    fn nt_free_virtual_memory_impl(&mut self, address: u64, size: usize) -> Result<()> {
        // SAFETY: munmap is called with valid parameters
        let result = unsafe { libc::munmap(address as *mut libc::c_void, size) };

        if result != 0 {
            return Err(PlatformError::MemoryError("munmap failed".to_string()));
        }

        Ok(())
    }

    /// NtProtectVirtualMemory - Change memory protection (internal implementation)
    /// Phase 7: Real API Implementation
    #[allow(clippy::unused_self)]
    fn nt_protect_virtual_memory_impl(
        &mut self,
        address: u64,
        size: usize,
        new_protect: u32,
    ) -> Result<u32> {
        // Translate Windows protection flags to Linux PROT_ flags
        let mut prot = 0;
        if new_protect & 0x04 != 0 || new_protect & 0x40 != 0 {
            // PAGE_READWRITE or PAGE_EXECUTE_READWRITE
            prot |= libc::PROT_READ | libc::PROT_WRITE;
        } else if new_protect & 0x02 != 0 || new_protect & 0x20 != 0 {
            // PAGE_READONLY or PAGE_EXECUTE_READ
            prot |= libc::PROT_READ;
        } else if new_protect & 0x01 != 0 {
            // PAGE_NOACCESS
            prot = libc::PROT_NONE;
        }
        if new_protect & 0x10 != 0 || new_protect & 0x20 != 0 || new_protect & 0x40 != 0 {
            // Any EXECUTE flag
            prot |= libc::PROT_EXEC;
        }

        // SAFETY: mprotect is called with valid parameters
        let result = unsafe { libc::mprotect(address as *mut libc::c_void, size, prot) };

        if result != 0 {
            return Err(PlatformError::MemoryError("mprotect failed".to_string()));
        }

        // Return the old protection flags (we don't track these, so return new_protect)
        Ok(new_protect)
    }

    // Phase 4: Threading implementation

    /// NtCreateThread - Create a new thread (internal implementation)
    #[allow(clippy::unnecessary_wraps)]
    fn nt_create_thread_impl(
        &mut self,
        entry_point: ThreadEntryPoint,
        parameter: *mut core::ffi::c_void,
        _stack_size: usize,
    ) -> Result<u64> {
        let exit_code = Arc::new(Mutex::new(None));
        let exit_code_clone = Arc::clone(&exit_code);

        // Convert pointer to usize for Send across threads
        let param_addr = parameter as usize;

        // SAFETY: We're spawning a thread with a valid entry point function.
        // The caller is responsible for ensuring the parameter pointer is valid
        // for the lifetime of the thread.
        let join_handle = thread::spawn(move || {
            let param_ptr = param_addr as *mut core::ffi::c_void;
            let result = entry_point(param_ptr);
            *exit_code_clone.lock().unwrap() = Some(result);
            result
        });

        let handle = self.allocate_handle();
        self.state.lock().unwrap().threads.insert(
            handle,
            ThreadInfo {
                join_handle: Some(join_handle),
                exit_code,
            },
        );

        Ok(handle)
    }

    /// NtTerminateThread - Terminate a thread (internal implementation)
    fn nt_terminate_thread_impl(&mut self, handle: u64, exit_code: u32) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let thread_info = state
            .threads
            .get_mut(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;

        // Set the exit code
        *thread_info.exit_code.lock().unwrap() = Some(exit_code);

        // Note: Rust doesn't support forcefully terminating threads safely
        // The thread will exit when it reaches a natural exit point
        // For now, we just mark it as terminated
        Ok(())
    }

    /// NtWaitForSingleObject - Wait for a thread (internal implementation)
    fn nt_wait_for_single_object_impl(&mut self, handle: u64, timeout_ms: u32) -> Result<u32> {
        // Take the join handle from the state
        let (join_handle_opt, exit_code) = {
            let mut state = self.state.lock().unwrap();
            let thread_info = state
                .threads
                .get_mut(&handle)
                .ok_or(PlatformError::InvalidHandle(handle))?;
            (
                thread_info.join_handle.take(),
                Arc::clone(&thread_info.exit_code),
            )
        };

        if let Some(join_handle) = join_handle_opt {
            if timeout_ms == u32::MAX {
                // Infinite wait
                join_handle
                    .join()
                    .map_err(|_| PlatformError::ThreadError("Thread join failed".to_string()))?;
                Ok(0) // WAIT_OBJECT_0
            } else {
                // Timed wait - spawn a timeout checker
                use std::time::Duration;
                let start = std::time::Instant::now();
                let timeout = Duration::from_millis(u64::from(timeout_ms));

                loop {
                    if (*exit_code.lock().unwrap()).is_some() {
                        // Thread completed
                        join_handle.join().map_err(|_| {
                            PlatformError::ThreadError("Thread join failed".to_string())
                        })?;
                        return Ok(0); // WAIT_OBJECT_0
                    }

                    if start.elapsed() >= timeout {
                        // Store the join handle back for later
                        let mut state = self.state.lock().unwrap();
                        if let Some(thread_info) = state.threads.get_mut(&handle) {
                            thread_info.join_handle = Some(join_handle);
                        }
                        return Ok(0x00000102); // WAIT_TIMEOUT
                    }

                    thread::sleep(Duration::from_millis(10));
                }
            }
        } else {
            // Thread already waited on
            Ok(0) // WAIT_OBJECT_0
        }
    }

    /// NtCreateEvent - Create an event object (internal implementation)
    fn nt_create_event_impl(&mut self, manual_reset: bool, initial_state: bool) -> u64 {
        let handle = self.allocate_handle();
        let event = EventObject {
            manual_reset,
            state: Arc::new((Mutex::new(initial_state), Condvar::new())),
        };
        self.state.lock().unwrap().events.insert(handle, event);
        handle
    }

    /// NtSetEvent - Signal an event (internal implementation)
    fn nt_set_event_impl(&mut self, handle: u64) -> Result<()> {
        let event_state = {
            let state = self.state.lock().unwrap();
            let event = state
                .events
                .get(&handle)
                .ok_or(PlatformError::InvalidHandle(handle))?;
            Arc::clone(&event.state)
        };

        let (lock, cvar) = &*event_state;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
        Ok(())
    }

    /// NtResetEvent - Reset an event (internal implementation)
    fn nt_reset_event_impl(&mut self, handle: u64) -> Result<()> {
        let event_state = {
            let state = self.state.lock().unwrap();
            let event = state
                .events
                .get(&handle)
                .ok_or(PlatformError::InvalidHandle(handle))?;
            Arc::clone(&event.state)
        };

        let (lock, _cvar) = &*event_state;
        *lock.lock().unwrap() = false;
        Ok(())
    }

    /// NtWaitForEvent - Wait for an event (internal implementation)
    fn nt_wait_for_event_impl(&mut self, handle: u64, timeout_ms: u32) -> Result<u32> {
        // Get event from state (clone Arc to avoid holding lock)
        let (event_state, manual_reset) = {
            let state = self.state.lock().unwrap();
            let event = state
                .events
                .get(&handle)
                .ok_or(PlatformError::InvalidHandle(handle))?;
            (Arc::clone(&event.state), event.manual_reset)
        };

        let (lock, cvar) = &*event_state;
        let mut signaled = lock.lock().unwrap();

        if timeout_ms == u32::MAX {
            // Infinite wait
            while !*signaled {
                signaled = cvar.wait(signaled).unwrap();
            }
            // Auto-reset for non-manual reset events
            if !manual_reset {
                *signaled = false;
            }
            Ok(0) // WAIT_OBJECT_0
        } else {
            // Timed wait
            use std::time::Duration;
            let timeout = Duration::from_millis(u64::from(timeout_ms));
            let result = cvar.wait_timeout(signaled, timeout).unwrap();
            signaled = result.0;

            if *signaled {
                // Auto-reset for non-manual reset events
                if !manual_reset {
                    *signaled = false;
                }
                Ok(0) // WAIT_OBJECT_0
            } else {
                Ok(0x00000102) // WAIT_TIMEOUT
            }
        }
    }

    /// NtCloseHandle - Close thread or event handle (internal implementation)
    fn nt_close_handle_impl(&mut self, handle: u64) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        // Try to remove from threads or events
        if state.threads.remove(&handle).is_some() || state.events.remove(&handle).is_some() {
            Ok(())
        } else {
            Err(PlatformError::InvalidHandle(handle))
        }
    }

    // Phase 5: Environment Variables implementation

    /// Get environment variable (internal implementation)
    fn get_environment_variable_impl(&self, name: &str) -> Option<String> {
        let state = self.state.lock().unwrap();
        state.environment.get(name).cloned()
    }

    /// Set environment variable (internal implementation)
    #[allow(clippy::unnecessary_wraps)]
    fn set_environment_variable_impl(&mut self, name: &str, value: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state
            .environment
            .insert(name.to_string(), value.to_string());
        Ok(())
    }

    // Phase 5: Process Information implementation

    /// Get current process ID (internal implementation)
    #[allow(clippy::unused_self, clippy::cast_sign_loss)]
    fn get_current_process_id_impl(&self) -> u32 {
        // SAFETY: getpid() is safe to call
        unsafe { libc::getpid() as u32 }
    }

    /// Get current thread ID (internal implementation)
    #[allow(
        clippy::unused_self,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn get_current_thread_id_impl(&self) -> u32 {
        // SAFETY: gettid() is safe to call on Linux
        #[cfg(target_os = "linux")]
        unsafe {
            libc::syscall(libc::SYS_gettid) as u32
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Fallback for non-Linux systems (e.g., during development on macOS)
            std::thread::current().id().as_u64().get() as u32
        }
    }

    // Phase 5: Registry Emulation implementation

    /// Open registry key (internal implementation)
    #[allow(clippy::unnecessary_wraps)]
    fn reg_open_key_ex_impl(&mut self, key: &str, subkey: &str) -> Result<u64> {
        let full_path = if subkey.is_empty() {
            key.to_string()
        } else {
            format!("{key}\\{subkey}")
        };

        // Create a simple in-memory registry with some common keys
        let mut values = HashMap::new();

        // Populate with some default values based on the key
        if full_path.contains("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") {
            values.insert(
                "ProductName".to_string(),
                "Windows 10 Pro (LiteBox Emulated)".to_string(),
            );
            values.insert("CurrentVersion".to_string(), "10.0".to_string());
            values.insert("CurrentBuild".to_string(), "19045".to_string());
        }

        let handle = self.allocate_handle();
        let mut state = self.state.lock().unwrap();
        state.registry_keys.insert(
            handle,
            RegistryKey {
                path: full_path,
                values,
            },
        );

        Ok(handle)
    }

    /// Query registry value (internal implementation)
    fn reg_query_value_ex_impl(&self, handle: u64, value_name: &str) -> Option<String> {
        let state = self.state.lock().unwrap();
        state
            .registry_keys
            .get(&handle)
            .and_then(|key| key.values.get(value_name).cloned())
    }

    /// Close registry key (internal implementation)
    fn reg_close_key_impl(&mut self, handle: u64) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state
            .registry_keys
            .remove(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;
        Ok(())
    }

    // Phase 7: Error Handling

    /// Get last error (delegates to kernel32 thread-local storage)
    #[allow(clippy::unused_self)]
    fn get_last_error_impl(&self) -> u32 {
        // SAFETY: This is safe to call from Rust code
        unsafe { crate::kernel32::kernel32_GetLastError() }
    }

    /// Set last error (delegates to kernel32 thread-local storage)
    #[allow(clippy::unused_self)]
    fn set_last_error_impl(&mut self, error_code: u32) {
        // SAFETY: This is safe to call from Rust code
        unsafe { crate::kernel32::kernel32_SetLastError(error_code) }
    }

    /// Internal implementation for find_first_file_w
    fn find_first_file_w_impl(
        &mut self,
        pattern: &[u16],
    ) -> Result<(SearchHandle, Win32FindDataW)> {
        // Convert UTF-16 pattern to String
        let pattern_str = String::from_utf16_lossy(pattern);
        let pattern_str = pattern_str.trim_end_matches('\0');

        // Translate Windows path to Linux path
        let linux_pattern = translate_windows_path_to_linux(pattern_str);

        // Parse the pattern to extract directory and filename pattern
        let path = std::path::Path::new(&linux_pattern);
        let (dir_path, file_pattern) = if let Some(parent) = path.parent() {
            if parent.as_os_str().is_empty() {
                (
                    ".",
                    path.file_name().and_then(|n| n.to_str()).unwrap_or("*"),
                )
            } else {
                (
                    parent.to_str().unwrap_or("."),
                    path.file_name().and_then(|n| n.to_str()).unwrap_or("*"),
                )
            }
        } else {
            (".", path.to_str().unwrap_or("*"))
        };

        // Read directory entries
        let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(dir_path) {
            Ok(read_dir) => read_dir.filter_map(std::result::Result::ok).collect(),
            Err(e) => {
                use std::io::ErrorKind;
                let error_code = match e.kind() {
                    ErrorKind::NotFound => windows_errors::ERROR_FILE_NOT_FOUND,
                    ErrorKind::PermissionDenied => windows_errors::ERROR_ACCESS_DENIED,
                    _ => windows_errors::ERROR_INVALID_PARAMETER,
                };
                self.set_last_error_impl(error_code);
                return Err(PlatformError::IoError(e));
            }
        };

        if entries.is_empty() {
            self.set_last_error_impl(windows_errors::ERROR_FILE_NOT_FOUND);
            return Err(PlatformError::PathTranslation("No files found".to_string()));
        }

        // Create search state
        let handle = self.allocate_handle();
        let search_state = SearchState {
            entries,
            current_index: 0,
            pattern: file_pattern.to_string(),
        };

        // Get first matching entry
        let Some(first_index) = get_next_matching_entry_index(&search_state) else {
            self.set_last_error_impl(windows_errors::ERROR_FILE_NOT_FOUND);
            return Err(PlatformError::PathTranslation(
                "No matching files found".to_string(),
            ));
        };

        let find_data = entry_to_find_data(&search_state.entries[first_index])?;

        // Store search state with index advanced
        let mut state = self.state.lock().unwrap();
        state.searches.insert(
            handle,
            SearchState {
                entries: search_state.entries,
                current_index: first_index + 1,
                pattern: search_state.pattern,
            },
        );
        drop(state);

        self.set_last_error_impl(0);
        Ok((SearchHandle(handle), find_data))
    }

    /// Internal implementation for find_next_file_w
    fn find_next_file_w_impl(&mut self, handle: SearchHandle) -> Result<Option<Win32FindDataW>> {
        let mut state = self.state.lock().unwrap();
        let Some(search_state) = state.searches.get_mut(&handle.0) else {
            drop(state);
            self.set_last_error_impl(windows_errors::ERROR_INVALID_HANDLE);
            return Err(PlatformError::InvalidHandle(handle.0));
        };

        // Find next matching entry
        while search_state.current_index < search_state.entries.len() {
            let entry = &search_state.entries[search_state.current_index];
            search_state.current_index += 1;

            if matches_pattern(&entry.file_name().to_string_lossy(), &search_state.pattern) {
                let find_data = entry_to_find_data(entry)?;
                drop(state);
                self.set_last_error_impl(0);
                return Ok(Some(find_data));
            }
        }

        drop(state);
        self.set_last_error_impl(0);
        Ok(None)
    }

    /// Internal implementation for find_close
    fn find_close_impl(&mut self, handle: SearchHandle) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.searches.remove(&handle.0).is_none() {
            drop(state);
            self.set_last_error_impl(windows_errors::ERROR_INVALID_HANDLE);
            return Err(PlatformError::InvalidHandle(handle.0));
        }
        drop(state);
        self.set_last_error_impl(0);
        Ok(())
    }
}

/// Get next matching directory entry index (helper for FindFirstFile)
fn get_next_matching_entry_index(search_state: &SearchState) -> Option<usize> {
    for i in search_state.current_index..search_state.entries.len() {
        let entry = &search_state.entries[i];
        if matches_pattern(&entry.file_name().to_string_lossy(), &search_state.pattern) {
            return Some(i);
        }
    }
    None
}

impl Default for LinuxPlatformForWindows {
    fn default() -> Self {
        Self::new()
    }
}

/// Translate Windows path to Linux path
///
/// Converts Windows-style paths (C:\path\to\file.txt) to Linux paths (/path/to/file.txt)
pub(crate) fn translate_windows_path_to_linux(windows_path: &str) -> String {
    let mut path = windows_path.to_string();

    // Remove drive letter if present (C:, D:, etc.)
    if path.len() >= 2 && path.chars().nth(1) == Some(':') {
        path = path[2..].to_string();
    }

    // Replace backslashes with forward slashes
    path = path.replace('\\', "/");

    // Ensure it starts with /
    if !path.starts_with('/') {
        path = format!("/{path}");
    }

    path
}

/// Convert a directory entry to WIN32_FIND_DATAW
fn entry_to_find_data(
    entry: &std::fs::DirEntry,
) -> Result<litebox_shim_windows::syscalls::ntdll::Win32FindDataW> {
    use litebox_shim_windows::syscalls::ntdll::Win32FindDataW;

    let metadata = entry.metadata().map_err(PlatformError::IoError)?;
    let file_name = entry.file_name();
    let file_name_str = file_name.to_string_lossy();

    // Convert filename to UTF-16
    let mut file_name_utf16 = [0u16; 260];
    let encoded: Vec<u16> = file_name_str.encode_utf16().collect();
    let copy_len = encoded.len().min(259); // Leave room for null terminator
    file_name_utf16[..copy_len].copy_from_slice(&encoded[..copy_len]);
    file_name_utf16[copy_len] = 0; // Null terminator

    // Get file attributes
    let mut attributes = 0u32;
    if metadata.is_dir() {
        attributes |= 0x00000010; // FILE_ATTRIBUTE_DIRECTORY
    }
    if attributes == 0 {
        attributes = 0x00000080; // FILE_ATTRIBUTE_NORMAL
    }

    // Get file size
    let file_size = metadata.len();
    let file_size_low = (file_size & 0xFFFFFFFF) as u32;
    let file_size_high = (file_size >> 32) as u32;

    // Get file times (simplified - just use modified time for all)
    let modified = metadata
        .modified()
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let duration = modified
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    // Convert to Windows FILETIME (100-nanosecond intervals since 1601-01-01)
    // Unix epoch (1970-01-01) is 116444736000000000 * 100ns intervals after Windows epoch
    let windows_time = duration.as_nanos() / 100 + 116444736000000000;
    #[allow(clippy::cast_possible_truncation)]
    let time_low = (windows_time & 0xFFFFFFFF) as u32;
    #[allow(clippy::cast_possible_truncation)]
    let time_high = (windows_time >> 32) as u32;

    Ok(Win32FindDataW {
        file_attributes: attributes,
        creation_time_low: time_low,
        creation_time_high: time_high,
        last_access_time_low: time_low,
        last_access_time_high: time_high,
        last_write_time_low: time_low,
        last_write_time_high: time_high,
        file_size_high,
        file_size_low,
        reserved0: 0,
        reserved1: 0,
        file_name: file_name_utf16,
        alternate_file_name: [0; 14],
    })
}

/// Match a filename against a pattern (supports * and ?)
fn matches_pattern(name: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern == "*.*" {
        return true;
    }

    let mut name_chars = name.chars().peekable();
    let mut pattern_chars = pattern.chars().peekable();

    while let Some(&p) = pattern_chars.peek() {
        match p {
            '*' => {
                pattern_chars.next();
                if pattern_chars.peek().is_none() {
                    return true; // * at end matches everything
                }
                // Try to match the rest of the pattern
                while name_chars.peek().is_some() {
                    if matches_pattern(
                        &name_chars.clone().collect::<String>(),
                        &pattern_chars.clone().collect::<String>(),
                    ) {
                        return true;
                    }
                    name_chars.next();
                }
                return false;
            }
            '?' => {
                pattern_chars.next();
                if name_chars.next().is_none() {
                    return false;
                }
            }
            _ => {
                pattern_chars.next();
                let Some(n) = name_chars.next() else {
                    return false;
                };
                // Use eq_ignore_ascii_case for proper case-insensitive comparison
                if !n.eq_ignore_ascii_case(&p) {
                    return false;
                }
            }
        }
    }

    name_chars.peek().is_none()
}

/// Implement the NtdllApi trait from litebox_shim_windows
impl NtdllApi for LinuxPlatformForWindows {
    fn nt_create_file(
        &mut self,
        path: &str,
        access: u32,
        create_disposition: u32,
    ) -> litebox_shim_windows::Result<FileHandle> {
        let handle = self
            .nt_create_file_impl(path, access, create_disposition)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))?;
        Ok(FileHandle(handle))
    }

    fn nt_read_file(
        &mut self,
        handle: FileHandle,
        buffer: &mut [u8],
    ) -> litebox_shim_windows::Result<usize> {
        self.nt_read_file_impl(handle.0, buffer)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_write_file(
        &mut self,
        handle: FileHandle,
        buffer: &[u8],
    ) -> litebox_shim_windows::Result<usize> {
        self.nt_write_file_impl(handle.0, buffer)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_close(&mut self, handle: FileHandle) -> litebox_shim_windows::Result<()> {
        self.nt_close_impl(handle.0)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn get_std_output(&self) -> ConsoleHandle {
        ConsoleHandle(self.get_std_output_impl())
    }

    fn write_console(
        &mut self,
        handle: ConsoleHandle,
        text: &str,
    ) -> litebox_shim_windows::Result<usize> {
        self.write_console_impl(handle.0, text)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_allocate_virtual_memory(
        &mut self,
        size: usize,
        protect: u32,
    ) -> litebox_shim_windows::Result<u64> {
        self.nt_allocate_virtual_memory_impl(size, protect)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_free_virtual_memory(
        &mut self,
        address: u64,
        size: usize,
    ) -> litebox_shim_windows::Result<()> {
        self.nt_free_virtual_memory_impl(address, size)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_protect_virtual_memory(
        &mut self,
        address: u64,
        size: usize,
        new_protect: u32,
    ) -> litebox_shim_windows::Result<u32> {
        self.nt_protect_virtual_memory_impl(address, size, new_protect)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    // Phase 4: Threading APIs

    fn nt_create_thread(
        &mut self,
        entry_point: ThreadEntryPoint,
        parameter: *mut core::ffi::c_void,
        stack_size: usize,
    ) -> litebox_shim_windows::Result<ThreadHandle> {
        let handle = self
            .nt_create_thread_impl(entry_point, parameter, stack_size)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))?;
        Ok(ThreadHandle(handle))
    }

    fn nt_terminate_thread(
        &mut self,
        handle: ThreadHandle,
        exit_code: u32,
    ) -> litebox_shim_windows::Result<()> {
        self.nt_terminate_thread_impl(handle.0, exit_code)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_wait_for_single_object(
        &mut self,
        handle: ThreadHandle,
        timeout_ms: u32,
    ) -> litebox_shim_windows::Result<u32> {
        self.nt_wait_for_single_object_impl(handle.0, timeout_ms)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    // Phase 4: Synchronization APIs

    fn nt_create_event(
        &mut self,
        manual_reset: bool,
        initial_state: bool,
    ) -> litebox_shim_windows::Result<EventHandle> {
        let handle = self.nt_create_event_impl(manual_reset, initial_state);
        Ok(EventHandle(handle))
    }

    fn nt_set_event(&mut self, handle: EventHandle) -> litebox_shim_windows::Result<()> {
        self.nt_set_event_impl(handle.0)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_reset_event(&mut self, handle: EventHandle) -> litebox_shim_windows::Result<()> {
        self.nt_reset_event_impl(handle.0)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_wait_for_event(
        &mut self,
        handle: EventHandle,
        timeout_ms: u32,
    ) -> litebox_shim_windows::Result<u32> {
        self.nt_wait_for_event_impl(handle.0, timeout_ms)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_close_handle(&mut self, handle: u64) -> litebox_shim_windows::Result<()> {
        self.nt_close_handle_impl(handle)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    // Phase 5: Environment Variables

    fn get_environment_variable(&self, name: &str) -> Option<String> {
        self.get_environment_variable_impl(name)
    }

    fn set_environment_variable(
        &mut self,
        name: &str,
        value: &str,
    ) -> litebox_shim_windows::Result<()> {
        self.set_environment_variable_impl(name, value)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    // Phase 5: Process Information

    fn get_current_process_id(&self) -> u32 {
        self.get_current_process_id_impl()
    }

    fn get_current_thread_id(&self) -> u32 {
        self.get_current_thread_id_impl()
    }

    // Phase 5: Registry Emulation

    fn reg_open_key_ex(
        &mut self,
        key: &str,
        subkey: &str,
    ) -> litebox_shim_windows::Result<RegKeyHandle> {
        let handle = self
            .reg_open_key_ex_impl(key, subkey)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))?;
        Ok(RegKeyHandle(handle))
    }

    fn reg_query_value_ex(&self, handle: RegKeyHandle, value_name: &str) -> Option<String> {
        self.reg_query_value_ex_impl(handle.0, value_name)
    }

    fn reg_close_key(&mut self, handle: RegKeyHandle) -> litebox_shim_windows::Result<()> {
        self.reg_close_key_impl(handle.0)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    // Phase 6: DLL Loading

    fn load_library(&mut self, name: &str) -> litebox_shim_windows::Result<u64> {
        let mut state = self.state.lock().unwrap();
        state
            .dll_manager
            .load_library(name)
            .map(|handle| handle.as_raw())
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn get_proc_address(&self, dll_handle: u64, name: &str) -> litebox_shim_windows::Result<u64> {
        use litebox_shim_windows::loader::DllHandle;

        let state = self.state.lock().unwrap();
        state
            .dll_manager
            .get_proc_address(DllHandle::new(dll_handle), name)
            .map(|addr| addr as u64)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn free_library(&mut self, dll_handle: u64) -> litebox_shim_windows::Result<()> {
        use litebox_shim_windows::loader::DllHandle;

        let mut state = self.state.lock().unwrap();
        state
            .dll_manager
            .free_library(DllHandle::new(dll_handle))
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    // Phase 7: Error Handling

    fn get_last_error(&self) -> u32 {
        self.get_last_error_impl()
    }

    fn set_last_error(&mut self, error_code: u32) {
        self.set_last_error_impl(error_code);
    }

    // Phase 7: Command-Line Argument Parsing

    fn get_command_line_w(&self) -> Vec<u16> {
        let state = self.state.lock().unwrap();
        state.command_line.clone()
    }

    fn command_line_to_argv_w(&self, command_line: &[u16]) -> Vec<Vec<u16>> {
        // Convert UTF-16 to String for easier parsing
        let cmd_str = String::from_utf16_lossy(command_line);
        let cmd_str = cmd_str.trim_end_matches('\0');

        if cmd_str.is_empty() {
            return Vec::new();
        }

        let mut args = Vec::new();
        let mut current_arg = Vec::new();
        let mut in_quotes = false;
        let mut chars = cmd_str.chars().peekable();

        while let Some(ch) = chars.next() {
            match ch {
                '"' => {
                    // Handle doubled quotes inside quoted strings (Windows convention)
                    if in_quotes && chars.peek() == Some(&'"') {
                        chars.next();
                        current_arg.push('"');
                    } else {
                        in_quotes = !in_quotes;
                    }
                }
                ' ' | '\t' if !in_quotes => {
                    if !current_arg.is_empty() {
                        // Convert to UTF-16 and add null terminator
                        let mut utf16: Vec<u16> = current_arg
                            .iter()
                            .collect::<String>()
                            .encode_utf16()
                            .collect();
                        utf16.push(0);
                        args.push(utf16);
                        current_arg.clear();
                    }
                }
                '\\' => {
                    // Count consecutive backslashes
                    let mut backslash_count = 1;
                    while chars.peek() == Some(&'\\') {
                        backslash_count += 1;
                        chars.next();
                    }

                    // Check if followed by a quote
                    if chars.peek() == Some(&'"') {
                        // 2n backslashes + quote = n backslashes + end quote
                        // 2n+1 backslashes + quote = n backslashes + literal quote
                        let num_backslashes = backslash_count / 2;
                        current_arg.extend(std::iter::repeat_n('\\', num_backslashes));
                        if backslash_count % 2 == 1 {
                            // Odd number: literal quote
                            chars.next();
                            current_arg.push('"');
                        }
                        // Even number: the quote will be processed in next iteration
                    } else {
                        // Not followed by quote: backslashes are literal
                        current_arg.extend(std::iter::repeat_n('\\', backslash_count));
                    }
                }
                _ => {
                    current_arg.push(ch);
                }
            }
        }

        // Add the last argument if any
        if !current_arg.is_empty() {
            let mut utf16: Vec<u16> = current_arg
                .iter()
                .collect::<String>()
                .encode_utf16()
                .collect();
            utf16.push(0);
            args.push(utf16);
        }

        args
    }

    // Phase 7: Advanced File Operations

    fn find_first_file_w(
        &mut self,
        pattern: &[u16],
    ) -> litebox_shim_windows::Result<(SearchHandle, Win32FindDataW)> {
        self.find_first_file_w_impl(pattern)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn find_next_file_w(
        &mut self,
        handle: SearchHandle,
    ) -> litebox_shim_windows::Result<Option<Win32FindDataW>> {
        self.find_next_file_w_impl(handle)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn find_close(&mut self, handle: SearchHandle) -> litebox_shim_windows::Result<()> {
        self.find_close_impl(handle)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_translation() {
        assert_eq!(
            translate_windows_path_to_linux("C:\\test\\file.txt"),
            "/test/file.txt"
        );
        assert_eq!(
            translate_windows_path_to_linux("\\test\\file.txt"),
            "/test/file.txt"
        );
        assert_eq!(
            translate_windows_path_to_linux("/test/file.txt"),
            "/test/file.txt"
        );
    }

    #[test]
    fn test_handle_allocation() {
        let platform = LinuxPlatformForWindows::new();
        let h1 = platform.allocate_handle();
        let h2 = platform.allocate_handle();
        assert_ne!(h1, h2);
    }

    // Phase 4: Threading tests

    extern "C" fn simple_thread_func(_param: *mut core::ffi::c_void) -> u32 {
        42
    }

    #[test]
    fn test_thread_creation() {
        let mut platform = LinuxPlatformForWindows::new();

        let result =
            platform.nt_create_thread(simple_thread_func, std::ptr::null_mut(), 1024 * 1024);

        assert!(result.is_ok());
        let handle = result.unwrap();

        // Wait for thread to complete
        let wait_result = platform.nt_wait_for_single_object(handle, u32::MAX);
        assert!(wait_result.is_ok());
        assert_eq!(wait_result.unwrap(), 0); // WAIT_OBJECT_0
    }

    extern "C" fn incrementing_thread_func(param: *mut core::ffi::c_void) -> u32 {
        // SAFETY: Test code controls the pointer validity
        unsafe {
            let counter = param.cast::<u32>();
            *counter += 1;
        }
        0
    }

    #[test]
    fn test_thread_with_parameter() {
        let mut platform = LinuxPlatformForWindows::new();
        let mut counter: u32 = 0;
        let counter_ptr = (&raw mut counter).cast::<core::ffi::c_void>();

        let handle = platform
            .nt_create_thread(incrementing_thread_func, counter_ptr, 1024 * 1024)
            .unwrap();

        // Wait for thread
        platform
            .nt_wait_for_single_object(handle, u32::MAX)
            .unwrap();

        assert_eq!(counter, 1);
    }

    #[test]
    fn test_event_creation_and_signal() {
        let mut platform = LinuxPlatformForWindows::new();

        // Create an event in non-signaled state
        let event = platform.nt_create_event(false, false).unwrap();

        // Set the event
        let result = platform.nt_set_event(event);
        assert!(result.is_ok());

        // Wait should succeed immediately
        let wait_result = platform.nt_wait_for_event(event, 100);
        assert!(wait_result.is_ok());
        assert_eq!(wait_result.unwrap(), 0); // WAIT_OBJECT_0
    }

    #[test]
    fn test_event_manual_reset() {
        let mut platform = LinuxPlatformForWindows::new();

        // Create a manual reset event in signaled state
        let event = platform.nt_create_event(true, true).unwrap();

        // Wait should succeed
        platform.nt_wait_for_event(event, 100).unwrap();

        // Wait again should still succeed (manual reset stays signaled)
        platform.nt_wait_for_event(event, 100).unwrap();

        // Reset the event
        platform.nt_reset_event(event).unwrap();

        // Now wait should timeout
        let result = platform.nt_wait_for_event(event, 100).unwrap();
        assert_eq!(result, 0x00000102); // WAIT_TIMEOUT
    }

    #[test]
    fn test_event_auto_reset() {
        let mut platform = LinuxPlatformForWindows::new();

        // Create an auto-reset event in signaled state
        let event = platform.nt_create_event(false, true).unwrap();

        // First wait should succeed and auto-reset
        let result = platform.nt_wait_for_event(event, 100).unwrap();
        assert_eq!(result, 0); // WAIT_OBJECT_0

        // Second wait should timeout (auto-reset)
        let result = platform.nt_wait_for_event(event, 100).unwrap();
        assert_eq!(result, 0x00000102); // WAIT_TIMEOUT
    }

    #[test]
    fn test_close_handles() {
        let mut platform = LinuxPlatformForWindows::new();

        // Create thread handle
        let thread_handle = platform
            .nt_create_thread(simple_thread_func, std::ptr::null_mut(), 1024 * 1024)
            .unwrap();

        // Create event handle
        let event_handle = platform.nt_create_event(false, false).unwrap();

        // Close both handles
        assert!(platform.nt_close_handle(thread_handle.0).is_ok());
        assert!(platform.nt_close_handle(event_handle.0).is_ok());

        // Trying to close again should fail
        assert!(platform.nt_close_handle(thread_handle.0).is_err());
        assert!(platform.nt_close_handle(event_handle.0).is_err());
    }

    // Phase 5: Environment Variables tests

    #[test]
    fn test_environment_variables() {
        let mut platform = LinuxPlatformForWindows::new();

        // Set a new environment variable
        platform
            .set_environment_variable("TEST_VAR", "test_value")
            .unwrap();

        // Read it back
        let value = platform.get_environment_variable("TEST_VAR");
        assert_eq!(value, Some("test_value".to_string()));

        // Non-existent variable should return None
        let value = platform.get_environment_variable("NONEXISTENT");
        assert_eq!(value, None);
    }

    #[test]
    fn test_default_environment_variables() {
        let platform = LinuxPlatformForWindows::new();

        // Check default environment variables
        assert!(platform.get_environment_variable("COMPUTERNAME").is_some());
        assert!(platform.get_environment_variable("OS").is_some());
        assert_eq!(
            platform.get_environment_variable("OS"),
            Some("Windows_NT".to_string())
        );
    }

    // Phase 5: Process Information tests

    #[test]
    fn test_process_and_thread_ids() {
        let platform = LinuxPlatformForWindows::new();

        let pid = platform.get_current_process_id();
        let tid = platform.get_current_thread_id();

        // IDs should be non-zero
        assert_ne!(pid, 0);
        assert_ne!(tid, 0);

        // Calling again should return the same process ID
        assert_eq!(pid, platform.get_current_process_id());
    }

    // Phase 5: Registry Emulation tests

    #[test]
    fn test_registry_open_and_query() {
        let mut platform = LinuxPlatformForWindows::new();

        // Open a registry key
        let key_handle = platform
            .reg_open_key_ex(
                "HKEY_LOCAL_MACHINE",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            )
            .unwrap();

        // Query a value
        let product_name = platform.reg_query_value_ex(key_handle, "ProductName");
        assert!(product_name.is_some());
        assert!(product_name.unwrap().contains("Windows"));

        // Query another value
        let version = platform.reg_query_value_ex(key_handle, "CurrentVersion");
        assert_eq!(version, Some("10.0".to_string()));

        // Close the key
        assert!(platform.reg_close_key(key_handle).is_ok());
    }

    #[test]
    fn test_registry_nonexistent_value() {
        let mut platform = LinuxPlatformForWindows::new();

        let key_handle = platform
            .reg_open_key_ex("HKEY_LOCAL_MACHINE", "SOFTWARE\\Test")
            .unwrap();

        // Query non-existent value
        let value = platform.reg_query_value_ex(key_handle, "NonExistent");
        assert_eq!(value, None);

        platform.reg_close_key(key_handle).unwrap();
    }

    #[test]
    fn test_registry_close_invalid_handle() {
        let mut platform = LinuxPlatformForWindows::new();

        // Try to close an invalid registry handle
        let result = platform.reg_close_key(RegKeyHandle(0xDEADBEEF));
        assert!(result.is_err());
    }

    // Phase 6: DLL Loading Tests

    #[test]
    fn test_load_library_kernel32() {
        let mut platform = LinuxPlatformForWindows::new();

        // Load KERNEL32.dll
        let handle = platform.load_library("KERNEL32.dll").unwrap();
        assert!(handle > 0);
    }

    #[test]
    fn test_load_library_case_insensitive() {
        let mut platform = LinuxPlatformForWindows::new();

        // Load with different cases
        let handle1 = platform.load_library("kernel32.dll").unwrap();
        let handle2 = platform.load_library("KERNEL32.DLL").unwrap();
        assert_eq!(handle1, handle2);
    }

    #[test]
    fn test_get_proc_address() {
        let mut platform = LinuxPlatformForWindows::new();

        // Load KERNEL32.dll and get LoadLibraryA
        let handle = platform.load_library("KERNEL32.dll").unwrap();
        let func = platform.get_proc_address(handle, "LoadLibraryA");
        assert!(func.is_ok());
    }

    #[test]
    fn test_get_proc_address_not_found() {
        let mut platform = LinuxPlatformForWindows::new();

        // Load KERNEL32.dll and try to get a non-existent function
        let handle = platform.load_library("KERNEL32.dll").unwrap();
        let result = platform.get_proc_address(handle, "NonExistentFunction");
        assert!(result.is_err());
    }

    #[test]
    fn test_free_library() {
        let mut platform = LinuxPlatformForWindows::new();

        // Load and free MSVCRT.dll
        let handle = platform.load_library("MSVCRT.dll").unwrap();
        let result = platform.free_library(handle);
        assert!(result.is_ok());

        // Should not be able to get proc address after freeing
        let result = platform.get_proc_address(handle, "printf");
        assert!(result.is_err());
    }

    // Phase 7: Memory Protection tests

    #[test]
    fn test_memory_protection() {
        let mut platform = LinuxPlatformForWindows::new();

        // Allocate memory with read-write protection
        let size = 4096;
        let address = platform
            .nt_allocate_virtual_memory(size, 0x04) // PAGE_READWRITE
            .unwrap();
        assert_ne!(address, 0);

        // Change protection to read-only
        let result = platform.nt_protect_virtual_memory(address, size, 0x02); // PAGE_READONLY
        assert!(result.is_ok());

        // Free the memory
        let result = platform.nt_free_virtual_memory(address, size);
        assert!(result.is_ok());
    }

    #[test]
    fn test_memory_protection_execute() {
        let mut platform = LinuxPlatformForWindows::new();

        // Allocate memory with execute-read-write protection
        let size = 4096;
        let address = platform
            .nt_allocate_virtual_memory(size, 0x40) // PAGE_EXECUTE_READWRITE
            .unwrap();
        assert_ne!(address, 0);

        // Change protection to execute-read
        let result = platform.nt_protect_virtual_memory(address, size, 0x20); // PAGE_EXECUTE_READ
        assert!(result.is_ok());

        // Free the memory
        let result = platform.nt_free_virtual_memory(address, size);
        assert!(result.is_ok());
    }

    // Phase 7: Error Handling tests

    #[test]
    fn test_get_set_last_error() {
        let mut platform = LinuxPlatformForWindows::new();

        // Initially should be 0
        assert_eq!(platform.get_last_error(), 0);

        // Set an error
        platform.set_last_error(123);
        assert_eq!(platform.get_last_error(), 123);

        // Set another error
        platform.set_last_error(456);
        assert_eq!(platform.get_last_error(), 456);

        // Set back to 0
        platform.set_last_error(0);
        assert_eq!(platform.get_last_error(), 0);
    }

    #[test]
    fn test_last_error_thread_local() {
        use std::sync::Arc;
        use std::sync::Mutex;

        let platform = Arc::new(Mutex::new(LinuxPlatformForWindows::new()));

        // Set error in main thread
        platform.lock().unwrap().set_last_error(100);

        // Spawn a thread and check that it has its own error code
        let platform_clone = Arc::clone(&platform);
        let handle = std::thread::spawn(move || {
            // Should be 0 in new thread
            let error = platform_clone.lock().unwrap().get_last_error();
            assert_eq!(error, 0);

            // Set error in this thread
            platform_clone.lock().unwrap().set_last_error(200);
            let error = platform_clone.lock().unwrap().get_last_error();
            assert_eq!(error, 200);
        });

        handle.join().unwrap();

        // Main thread should still have its own error
        assert_eq!(platform.lock().unwrap().get_last_error(), 100);
    }

    // Phase 7: Enhanced File I/O tests

    #[test]
    fn test_file_io_with_error_codes() {
        let mut platform = LinuxPlatformForWindows::new();

        // Try to open a non-existent file with OPEN_EXISTING (disposition 3)
        let result = platform.nt_create_file("/tmp/nonexistent_test_file.txt", 0x80000000, 3);
        assert!(result.is_err());
        // Should set ERROR_FILE_NOT_FOUND (2)
        assert_eq!(platform.get_last_error(), 2);

        // Create a new file successfully
        let handle = platform
            .nt_create_file("/tmp/test_file_io.txt", 0xC0000000, 2) // CREATE_ALWAYS
            .unwrap();
        // Should set error code to 0 (success)
        assert_eq!(platform.get_last_error(), 0);

        // Write to the file
        let data = b"Hello, World!";
        let bytes_written = platform.nt_write_file(handle, data).unwrap();
        assert_eq!(bytes_written, data.len());
        assert_eq!(platform.get_last_error(), 0);

        // Close the file
        platform.nt_close(handle).unwrap();
        assert_eq!(platform.get_last_error(), 0);

        // Clean up
        let _ = std::fs::remove_file("/tmp/test_file_io.txt");
    }

    #[test]
    fn test_file_create_new_disposition() {
        let mut platform = LinuxPlatformForWindows::new();
        let test_path = "/tmp/test_create_new.txt";

        // Clean up any existing file
        let _ = std::fs::remove_file(test_path);

        // CREATE_NEW (1) - should succeed if file doesn't exist
        let handle = platform.nt_create_file(test_path, 0xC0000000, 1).unwrap();
        platform.nt_close(handle).unwrap();

        // CREATE_NEW again - should fail with ERROR_FILE_EXISTS (80)
        let result = platform.nt_create_file(test_path, 0xC0000000, 1);
        assert!(result.is_err());
        assert_eq!(platform.get_last_error(), 80);

        // Clean up
        let _ = std::fs::remove_file(test_path);
    }

    #[test]
    fn test_file_truncate_existing_disposition() {
        let mut platform = LinuxPlatformForWindows::new();
        let test_path = "/tmp/test_truncate.txt";

        // Clean up any existing file
        let _ = std::fs::remove_file(test_path);

        // Create a file with some content using standard file I/O
        {
            let mut file = std::fs::File::create(test_path).unwrap();
            file.write_all(b"Initial content that should be truncated")
                .unwrap();
        }

        // TRUNCATE_EXISTING (5) - should truncate the file
        let handle = platform.nt_create_file(test_path, 0xC0000000, 5).unwrap();

        // Write new content
        let data = b"New";
        platform.nt_write_file(handle, data).unwrap();
        platform.nt_close(handle).unwrap();

        // Verify the file only contains "New"
        let content = std::fs::read_to_string(test_path).unwrap();
        assert_eq!(content, "New");

        // Clean up
        let _ = std::fs::remove_file(test_path);
    }

    #[test]
    fn test_file_invalid_handle_error() {
        let mut platform = LinuxPlatformForWindows::new();

        // Try to read from an invalid handle
        let mut buffer = [0u8; 10];
        let result = platform.nt_read_file(FileHandle(0xDEADBEEF), &mut buffer);
        assert!(result.is_err());
        // Should set ERROR_INVALID_HANDLE (6)
        assert_eq!(platform.get_last_error(), 6);

        // Try to write to an invalid handle
        let result = platform.nt_write_file(FileHandle(0xDEADBEEF), b"test");
        assert!(result.is_err());
        assert_eq!(platform.get_last_error(), 6);

        // Try to close an invalid handle
        let result = platform.nt_close(FileHandle(0xDEADBEEF));
        assert!(result.is_err());
        assert_eq!(platform.get_last_error(), 6);
    }

    // Phase 7: Command-line argument parsing tests

    #[test]
    fn test_command_line_to_argv() {
        let platform = LinuxPlatformForWindows::new();

        // Test simple command line
        let cmd_line: Vec<u16> = "program.exe arg1 arg2\0".encode_utf16().collect();
        let args = platform.command_line_to_argv_w(&cmd_line);
        assert_eq!(args.len(), 3);
        assert_eq!(
            String::from_utf16_lossy(&args[0]).trim_end_matches('\0'),
            "program.exe"
        );
        assert_eq!(
            String::from_utf16_lossy(&args[1]).trim_end_matches('\0'),
            "arg1"
        );
        assert_eq!(
            String::from_utf16_lossy(&args[2]).trim_end_matches('\0'),
            "arg2"
        );

        // Test command line with quotes
        let cmd_line: Vec<u16> = "program.exe \"arg with spaces\" arg2\0"
            .encode_utf16()
            .collect();
        let args = platform.command_line_to_argv_w(&cmd_line);
        assert_eq!(args.len(), 3);
        assert_eq!(
            String::from_utf16_lossy(&args[0]).trim_end_matches('\0'),
            "program.exe"
        );
        assert_eq!(
            String::from_utf16_lossy(&args[1]).trim_end_matches('\0'),
            "arg with spaces"
        );
        assert_eq!(
            String::from_utf16_lossy(&args[2]).trim_end_matches('\0'),
            "arg2"
        );
    }

    #[test]
    fn test_set_get_command_line() {
        let mut platform = LinuxPlatformForWindows::new();

        let args = vec![
            "test.exe".to_string(),
            "arg1".to_string(),
            "arg with spaces".to_string(),
        ];
        platform.set_command_line(&args);

        let cmd_line = platform.get_command_line_w();
        let cmd_str = String::from_utf16_lossy(&cmd_line)
            .trim_end_matches('\0')
            .to_string();

        // Should contain all args, with quotes around the one with spaces
        assert!(cmd_str.contains("test.exe"));
        assert!(cmd_str.contains("arg1"));
        assert!(cmd_str.contains("\"arg with spaces\""));
    }

    #[test]
    fn test_command_line_backslash_handling() {
        let platform = LinuxPlatformForWindows::new();

        // Test: Backslashes not followed by quotes are literal
        let cmd_line = r"program.exe C:\path\to\file.txt".to_string() + "\0";
        let cmd_line_utf16: Vec<u16> = cmd_line.encode_utf16().collect();
        let args = platform.command_line_to_argv_w(&cmd_line_utf16);
        assert_eq!(args.len(), 2);
        assert_eq!(
            String::from_utf16_lossy(&args[1]).trim_end_matches('\0'),
            r"C:\path\to\file.txt"
        );

        // Test: 2 backslashes + quote = 1 backslash (quote ends the string)
        // Command line: "test\\"  -> output: test\
        let cmd_line = r#"program.exe "test\\""#.to_string() + "\0";
        let cmd_line_utf16: Vec<u16> = cmd_line.encode_utf16().collect();
        let args = platform.command_line_to_argv_w(&cmd_line_utf16);
        assert_eq!(args.len(), 2);
        assert_eq!(
            String::from_utf16_lossy(&args[1]).trim_end_matches('\0'),
            r"test\"
        );

        // Test: 3 backslashes + quote = 1 backslash + literal quote (quote doesn't end string)
        // Command line: "test\\"more"  -> output: test"more
        let cmd_line = r#"program.exe "test\"more""#.to_string() + " \0";
        let cmd_line_utf16: Vec<u16> = cmd_line.encode_utf16().collect();
        let args = platform.command_line_to_argv_w(&cmd_line_utf16);
        assert_eq!(args.len(), 2);
        assert_eq!(
            String::from_utf16_lossy(&args[1]).trim_end_matches('\0'),
            r#"test"more"#
        );

        // Test: 4 backslashes + quote = 2 backslashes (quote ends the string)
        let cmd_line = r#"program.exe "test\\\\""#.to_string() + "\0";
        let cmd_line_utf16: Vec<u16> = cmd_line.encode_utf16().collect();
        let args = platform.command_line_to_argv_w(&cmd_line_utf16);
        assert_eq!(args.len(), 2);
        assert_eq!(
            String::from_utf16_lossy(&args[1]).trim_end_matches('\0'),
            r"test\\"
        );
    }

    #[test]
    fn test_command_line_doubled_quotes() {
        let platform = LinuxPlatformForWindows::new();

        // Test: Doubled quotes inside quoted strings (Windows convention)
        let cmd_line: Vec<u16> = "program.exe \"He said \"\"Hello\"\"\"\0"
            .encode_utf16()
            .collect();
        let args = platform.command_line_to_argv_w(&cmd_line);
        assert_eq!(args.len(), 2);
        assert_eq!(
            String::from_utf16_lossy(&args[1]).trim_end_matches('\0'),
            "He said \"Hello\""
        );
    }

    #[test]
    fn test_set_command_line_with_quotes() {
        let mut platform = LinuxPlatformForWindows::new();

        // Test that quotes in arguments are doubled
        let args = vec!["test.exe".to_string(), "He said \"Hello\"".to_string()];
        platform.set_command_line(&args);

        let cmd_line = platform.get_command_line_w();
        let cmd_str = String::from_utf16_lossy(&cmd_line)
            .trim_end_matches('\0')
            .to_string();

        // Should have doubled quotes
        assert!(cmd_str.contains("\"\""));

        // Parse it back and verify
        let parsed_args = platform.command_line_to_argv_w(&cmd_line);
        assert_eq!(parsed_args.len(), 2);
        assert_eq!(
            String::from_utf16_lossy(&parsed_args[1]).trim_end_matches('\0'),
            "He said \"Hello\""
        );
    }

    // Phase 7: File pattern matching tests

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("test.txt", "*"));
        assert!(matches_pattern("test.txt", "*.txt"));
        assert!(matches_pattern("test.txt", "test.*"));
        assert!(matches_pattern("test.txt", "test.txt"));
        assert!(!matches_pattern("test.txt", "*.doc"));
        assert!(matches_pattern("test.txt", "????.txt"));
        assert!(!matches_pattern("test.txt", "?.txt"));

        // Test case insensitivity
        assert!(matches_pattern("Test.TXT", "test.txt"));
        assert!(matches_pattern("test.txt", "TEST.TXT"));
    }
}
