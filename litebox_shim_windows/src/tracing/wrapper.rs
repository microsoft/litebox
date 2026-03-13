// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tracing wrapper for NTDLL APIs
//!
//! This module provides a wrapper that intercepts NTDLL API calls
//! for tracing purposes.

use crate::Result;
use crate::syscalls::ntdll::{
    ConsoleHandle, EventHandle, FileHandle, NtdllApi, RegKeyHandle, ThreadEntryPoint, ThreadHandle,
};
use crate::tracing::{ApiCategory, TraceEvent, Tracer};
use std::sync::Arc;

/// Wrapper for NtdllApi that adds tracing
pub struct TracedNtdllApi<T: NtdllApi> {
    inner: T,
    tracer: Arc<Tracer>,
}

impl<T: NtdllApi> TracedNtdllApi<T> {
    /// Create a new traced API wrapper
    pub fn new(inner: T, tracer: Arc<Tracer>) -> Self {
        Self { inner, tracer }
    }

    /// Get a reference to the inner API implementation
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner API implementation
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: NtdllApi> NtdllApi for TracedNtdllApi<T> {
    fn nt_create_file(
        &mut self,
        path: &str,
        access: u32,
        create_disposition: u32,
    ) -> Result<FileHandle> {
        // Trace call
        if self.tracer.is_enabled() {
            let args =
                format!("path=\"{path}\", access=0x{access:08X}, disposition={create_disposition}");
            let event = TraceEvent::call("NtCreateFile", ApiCategory::FileIo).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_create_file(path, access, create_disposition);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(handle) => format!("Ok(handle=0x{:X})", handle.0),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtCreateFile", ApiCategory::FileIo)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_read_file(&mut self, handle: FileHandle, buffer: &mut [u8]) -> Result<usize> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}, buffer_size={}", handle.0, buffer.len());
            let event = TraceEvent::call("NtReadFile", ApiCategory::FileIo).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_read_file(handle, buffer);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(bytes_read) => format!("Ok(bytes_read={bytes_read})"),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtReadFile", ApiCategory::FileIo)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_write_file(&mut self, handle: FileHandle, buffer: &[u8]) -> Result<usize> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}, buffer_size={}", handle.0, buffer.len());
            let event = TraceEvent::call("NtWriteFile", ApiCategory::FileIo).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_write_file(handle, buffer);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(bytes_written) => format!("Ok(bytes_written={bytes_written})"),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtWriteFile", ApiCategory::FileIo)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_close(&mut self, handle: FileHandle) -> Result<()> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}", handle.0);
            let event = TraceEvent::call("NtClose", ApiCategory::FileIo).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_close(handle);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(()) => "Ok(())".to_string(),
                Err(e) => format!("Err({e})"),
            };
            let event =
                TraceEvent::return_event("NtClose", ApiCategory::FileIo).with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn get_std_output(&self) -> ConsoleHandle {
        // Note: get_std_output doesn't modify state, so we intentionally don't trace it
        // to reduce noise in the trace output. This is a deliberate design decision.
        self.inner.get_std_output()
    }

    fn write_console(&mut self, handle: ConsoleHandle, text: &str) -> Result<usize> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}, text=\"{}\"", handle.0, text.escape_debug());
            let event = TraceEvent::call("WriteConsole", ApiCategory::ConsoleIo).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.write_console(handle, text);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(bytes_written) => format!("Ok(bytes_written={bytes_written})"),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("WriteConsole", ApiCategory::ConsoleIo)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_allocate_virtual_memory(&mut self, size: usize, protect: u32) -> Result<u64> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("size={size}, protect=0x{protect:08X}");
            let event =
                TraceEvent::call("NtAllocateVirtualMemory", ApiCategory::Memory).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_allocate_virtual_memory(size, protect);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(addr) => format!("Ok(address=0x{addr:X})"),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtAllocateVirtualMemory", ApiCategory::Memory)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_free_virtual_memory(&mut self, address: u64, size: usize) -> Result<()> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("address=0x{address:X}, size={size}");
            let event =
                TraceEvent::call("NtFreeVirtualMemory", ApiCategory::Memory).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_free_virtual_memory(address, size);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(()) => "Ok(())".to_string(),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtFreeVirtualMemory", ApiCategory::Memory)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_protect_virtual_memory(
        &mut self,
        address: u64,
        size: usize,
        new_protect: u32,
    ) -> Result<u32> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("address=0x{address:X}, size={size}, new_protect=0x{new_protect:X}");
            let event =
                TraceEvent::call("NtProtectVirtualMemory", ApiCategory::Memory).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self
            .inner
            .nt_protect_virtual_memory(address, size, new_protect);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(old_protect) => format!("Ok(old_protect=0x{old_protect:X})"),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtProtectVirtualMemory", ApiCategory::Memory)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    // Phase 4: Threading APIs

    fn nt_create_thread(
        &mut self,
        entry_point: ThreadEntryPoint,
        parameter: *mut core::ffi::c_void,
        stack_size: usize,
    ) -> Result<ThreadHandle> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!(
                "entry_point=0x{:X}, parameter=0x{:X}, stack_size={}",
                entry_point as usize, parameter as usize, stack_size
            );
            let event = TraceEvent::call("NtCreateThread", ApiCategory::Threading).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self
            .inner
            .nt_create_thread(entry_point, parameter, stack_size);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(handle) => format!("Ok(handle=0x{:X})", handle.0),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtCreateThread", ApiCategory::Threading)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_terminate_thread(&mut self, handle: ThreadHandle, exit_code: u32) -> Result<()> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}, exit_code={}", handle.0, exit_code);
            let event =
                TraceEvent::call("NtTerminateThread", ApiCategory::Threading).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_terminate_thread(handle, exit_code);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(()) => "Ok(())".to_string(),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtTerminateThread", ApiCategory::Threading)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_wait_for_single_object(&mut self, handle: ThreadHandle, timeout_ms: u32) -> Result<u32> {
        // Trace call
        if self.tracer.is_enabled() {
            let timeout_str = if timeout_ms == u32::MAX {
                "INFINITE".to_string()
            } else {
                format!("{timeout_ms}ms")
            };
            let args = format!("handle=0x{:X}, timeout={}", handle.0, timeout_str);
            let event =
                TraceEvent::call("NtWaitForSingleObject", ApiCategory::Threading).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_wait_for_single_object(handle, timeout_ms);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(wait_result) => format!("Ok(wait_result=0x{wait_result:08X})"),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtWaitForSingleObject", ApiCategory::Threading)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    // Phase 4: Synchronization APIs

    fn nt_create_event(&mut self, manual_reset: bool, initial_state: bool) -> Result<EventHandle> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("manual_reset={manual_reset}, initial_state={initial_state}");
            let event =
                TraceEvent::call("NtCreateEvent", ApiCategory::Synchronization).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_create_event(manual_reset, initial_state);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(handle) => format!("Ok(handle=0x{:X})", handle.0),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtCreateEvent", ApiCategory::Synchronization)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_set_event(&mut self, handle: EventHandle) -> Result<()> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}", handle.0);
            let event =
                TraceEvent::call("NtSetEvent", ApiCategory::Synchronization).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_set_event(handle);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(()) => "Ok(())".to_string(),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtSetEvent", ApiCategory::Synchronization)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_reset_event(&mut self, handle: EventHandle) -> Result<()> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}", handle.0);
            let event =
                TraceEvent::call("NtResetEvent", ApiCategory::Synchronization).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_reset_event(handle);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(()) => "Ok(())".to_string(),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtResetEvent", ApiCategory::Synchronization)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_wait_for_event(&mut self, handle: EventHandle, timeout_ms: u32) -> Result<u32> {
        // Trace call
        if self.tracer.is_enabled() {
            let timeout_str = if timeout_ms == u32::MAX {
                "INFINITE".to_string()
            } else {
                format!("{timeout_ms}ms")
            };
            let args = format!("handle=0x{:X}, timeout={}", handle.0, timeout_str);
            let event =
                TraceEvent::call("NtWaitForEvent", ApiCategory::Synchronization).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_wait_for_event(handle, timeout_ms);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(wait_result) => format!("Ok(wait_result=0x{wait_result:08X})"),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtWaitForEvent", ApiCategory::Synchronization)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_close_handle(&mut self, handle: u64) -> Result<()> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{handle:X}");
            let event =
                TraceEvent::call("NtCloseHandle", ApiCategory::Synchronization).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_close_handle(handle);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(()) => "Ok(())".to_string(),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("NtCloseHandle", ApiCategory::Synchronization)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    // Phase 5: Environment Variables

    fn get_environment_variable(&self, name: &str) -> Option<String> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("name=\"{name}\"");
            let event = TraceEvent::call("GetEnvironmentVariable", ApiCategory::Environment)
                .with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.get_environment_variable(name);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Some(value) => format!("Some(\"{value}\")"),
                None => "None".to_string(),
            };
            let event =
                TraceEvent::return_event("GetEnvironmentVariable", ApiCategory::Environment)
                    .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn set_environment_variable(&mut self, name: &str, value: &str) -> Result<()> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("name=\"{name}\", value=\"{value}\"");
            let event = TraceEvent::call("SetEnvironmentVariable", ApiCategory::Environment)
                .with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.set_environment_variable(name, value);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(()) => "Ok(())".to_string(),
                Err(e) => format!("Err({e})"),
            };
            let event =
                TraceEvent::return_event("SetEnvironmentVariable", ApiCategory::Environment)
                    .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    // Phase 5: Process Information

    fn get_current_process_id(&self) -> u32 {
        // Trace call
        if self.tracer.is_enabled() {
            let event = TraceEvent::call("GetCurrentProcessId", ApiCategory::Process);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.get_current_process_id();

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = format!("{result}");
            let event = TraceEvent::return_event("GetCurrentProcessId", ApiCategory::Process)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn get_current_thread_id(&self) -> u32 {
        // Trace call
        if self.tracer.is_enabled() {
            let event = TraceEvent::call("GetCurrentThreadId", ApiCategory::Threading);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.get_current_thread_id();

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = format!("{result}");
            let event = TraceEvent::return_event("GetCurrentThreadId", ApiCategory::Threading)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    // Phase 5: Registry Emulation

    fn reg_open_key_ex(&mut self, key: &str, subkey: &str) -> Result<RegKeyHandle> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("key=\"{key}\", subkey=\"{subkey}\"");
            let event = TraceEvent::call("RegOpenKeyEx", ApiCategory::Registry).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.reg_open_key_ex(key, subkey);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(handle) => format!("Ok(handle=0x{:X})", handle.0),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("RegOpenKeyEx", ApiCategory::Registry)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn reg_query_value_ex(&self, handle: RegKeyHandle, value_name: &str) -> Option<String> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}, value_name=\"{value_name}\"", handle.0);
            let event = TraceEvent::call("RegQueryValueEx", ApiCategory::Registry).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.reg_query_value_ex(handle, value_name);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Some(value) => format!("Some(\"{value}\")"),
                None => "None".to_string(),
            };
            let event = TraceEvent::return_event("RegQueryValueEx", ApiCategory::Registry)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn reg_close_key(&mut self, handle: RegKeyHandle) -> Result<()> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}", handle.0);
            let event = TraceEvent::call("RegCloseKey", ApiCategory::Registry).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.reg_close_key(handle);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(()) => "Ok(())".to_string(),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("RegCloseKey", ApiCategory::Registry)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    // Phase 6: DLL Loading

    fn load_library(&mut self, name: &str) -> Result<u64> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("name=\"{name}\"");
            let event = TraceEvent::call("LoadLibrary", ApiCategory::Dll).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.load_library(name);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(handle) => format!("Ok(handle=0x{handle:X})"),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("LoadLibrary", ApiCategory::Dll)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn get_proc_address(&self, dll_handle: u64, name: &str) -> Result<u64> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("dll_handle=0x{dll_handle:X}, name=\"{name}\"");
            let event = TraceEvent::call("GetProcAddress", ApiCategory::Dll).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.get_proc_address(dll_handle, name);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(address) => format!("Ok(address=0x{address:X})"),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("GetProcAddress", ApiCategory::Dll)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn free_library(&mut self, dll_handle: u64) -> Result<()> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("dll_handle=0x{dll_handle:X}");
            let event = TraceEvent::call("FreeLibrary", ApiCategory::Dll).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.free_library(dll_handle);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(()) => "Ok(())".to_string(),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("FreeLibrary", ApiCategory::Dll)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    // Phase 7: Error Handling

    fn get_last_error(&self) -> u32 {
        // Note: We don't trace get_last_error to avoid noise, as it's called very frequently
        self.inner.get_last_error()
    }

    fn set_last_error(&mut self, error_code: u32) {
        // Trace call for debugging purposes
        if self.tracer.is_enabled() {
            let args = format!("error_code={error_code}");
            let event = TraceEvent::call("SetLastError", ApiCategory::Process).with_args(args);
            self.tracer.trace(event);
        }

        self.inner.set_last_error(error_code);

        // No return value to trace
    }

    // Phase 7: Command-Line Argument Parsing

    fn get_command_line_w(&self) -> Vec<u16> {
        // Don't trace to avoid noise
        self.inner.get_command_line_w()
    }

    fn command_line_to_argv_w(&self, command_line: &[u16]) -> Vec<Vec<u16>> {
        if self.tracer.is_enabled() {
            let cmd_str = String::from_utf16_lossy(command_line);
            let args = format!("command_line=\"{}\"", cmd_str.trim_end_matches('\0'));
            let event =
                TraceEvent::call("CommandLineToArgvW", ApiCategory::Process).with_args(args);
            self.tracer.trace(event);
        }

        let result = self.inner.command_line_to_argv_w(command_line);

        if self.tracer.is_enabled() {
            let ret_str = format!("argc={}", result.len());
            let event = TraceEvent::return_event("CommandLineToArgvW", ApiCategory::Process)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    // Phase 7: Advanced File Operations

    fn find_first_file_w(
        &mut self,
        pattern: &[u16],
    ) -> Result<(
        crate::syscalls::ntdll::SearchHandle,
        crate::syscalls::ntdll::Win32FindDataW,
    )> {
        if self.tracer.is_enabled() {
            let pattern_str = String::from_utf16_lossy(pattern);
            let args = format!("pattern=\"{}\"", pattern_str.trim_end_matches('\0'));
            let event = TraceEvent::call("FindFirstFileW", ApiCategory::FileIo).with_args(args);
            self.tracer.trace(event);
        }

        let result = self.inner.find_first_file_w(pattern);

        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok((handle, data)) => {
                    let file_name = String::from_utf16_lossy(&data.file_name);
                    let file_name = file_name.trim_end_matches('\0');
                    format!("Ok(handle=0x{:X}, file=\"{}\")", handle.0, file_name)
                }
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("FindFirstFileW", ApiCategory::FileIo)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn find_next_file_w(
        &mut self,
        handle: crate::syscalls::ntdll::SearchHandle,
    ) -> Result<Option<crate::syscalls::ntdll::Win32FindDataW>> {
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}", handle.0);
            let event = TraceEvent::call("FindNextFileW", ApiCategory::FileIo).with_args(args);
            self.tracer.trace(event);
        }

        let result = self.inner.find_next_file_w(handle);

        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(Some(data)) => {
                    let file_name = String::from_utf16_lossy(&data.file_name);
                    let file_name = file_name.trim_end_matches('\0');
                    format!("Ok(file=\"{file_name}\")")
                }
                Ok(None) => "Ok(None)".to_string(),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("FindNextFileW", ApiCategory::FileIo)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn find_close(&mut self, handle: crate::syscalls::ntdll::SearchHandle) -> Result<()> {
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}", handle.0);
            let event = TraceEvent::call("FindClose", ApiCategory::FileIo).with_args(args);
            self.tracer.trace(event);
        }

        let result = self.inner.find_close(handle);

        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(()) => "Ok(())".to_string(),
                Err(e) => format!("Err({e})"),
            };
            let event = TraceEvent::return_event("FindClose", ApiCategory::FileIo)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::ntdll::{create_disposition, file_access, memory_protection};
    use crate::tracing::{TraceConfig, TraceFilter};

    // Mock implementation for testing
    struct MockNtdllApi;

    impl NtdllApi for MockNtdllApi {
        fn nt_create_file(
            &mut self,
            _path: &str,
            _access: u32,
            _create_disposition: u32,
        ) -> Result<FileHandle> {
            Ok(FileHandle(42))
        }

        fn nt_read_file(&mut self, _handle: FileHandle, buffer: &mut [u8]) -> Result<usize> {
            Ok(buffer.len())
        }

        fn nt_write_file(&mut self, _handle: FileHandle, buffer: &[u8]) -> Result<usize> {
            Ok(buffer.len())
        }

        fn nt_close(&mut self, _handle: FileHandle) -> Result<()> {
            Ok(())
        }

        fn get_std_output(&self) -> ConsoleHandle {
            ConsoleHandle(1)
        }

        fn write_console(&mut self, _handle: ConsoleHandle, text: &str) -> Result<usize> {
            Ok(text.len())
        }

        fn nt_allocate_virtual_memory(&mut self, _size: usize, _protect: u32) -> Result<u64> {
            Ok(0x1000000)
        }

        fn nt_free_virtual_memory(&mut self, _address: u64, _size: usize) -> Result<()> {
            Ok(())
        }

        fn nt_create_thread(
            &mut self,
            _entry_point: ThreadEntryPoint,
            _parameter: *mut core::ffi::c_void,
            _stack_size: usize,
        ) -> Result<ThreadHandle> {
            Ok(ThreadHandle(100))
        }

        fn nt_terminate_thread(&mut self, _handle: ThreadHandle, _exit_code: u32) -> Result<()> {
            Ok(())
        }

        fn nt_wait_for_single_object(
            &mut self,
            _handle: ThreadHandle,
            _timeout_ms: u32,
        ) -> Result<u32> {
            Ok(0) // WAIT_OBJECT_0
        }

        fn nt_create_event(
            &mut self,
            _manual_reset: bool,
            _initial_state: bool,
        ) -> Result<EventHandle> {
            Ok(EventHandle(200))
        }

        fn nt_set_event(&mut self, _handle: EventHandle) -> Result<()> {
            Ok(())
        }

        fn nt_reset_event(&mut self, _handle: EventHandle) -> Result<()> {
            Ok(())
        }

        fn nt_wait_for_event(&mut self, _handle: EventHandle, _timeout_ms: u32) -> Result<u32> {
            Ok(0) // WAIT_OBJECT_0
        }

        fn nt_close_handle(&mut self, _handle: u64) -> Result<()> {
            Ok(())
        }

        // Phase 5: Environment Variables

        fn get_environment_variable(&self, _name: &str) -> Option<String> {
            Some("test_value".to_string())
        }

        fn set_environment_variable(&mut self, _name: &str, _value: &str) -> Result<()> {
            Ok(())
        }

        // Phase 5: Process Information

        fn get_current_process_id(&self) -> u32 {
            1234
        }

        fn get_current_thread_id(&self) -> u32 {
            5678
        }

        // Phase 5: Registry Emulation

        fn reg_open_key_ex(&mut self, _key: &str, _subkey: &str) -> Result<RegKeyHandle> {
            Ok(RegKeyHandle(300))
        }

        fn reg_query_value_ex(&self, _handle: RegKeyHandle, _value_name: &str) -> Option<String> {
            Some("registry_value".to_string())
        }

        fn reg_close_key(&mut self, _handle: RegKeyHandle) -> Result<()> {
            Ok(())
        }

        // Phase 6: DLL Loading

        fn load_library(&mut self, _name: &str) -> Result<u64> {
            Ok(0x10000000) // Mock DLL handle
        }

        fn get_proc_address(&self, _dll_handle: u64, _name: &str) -> Result<u64> {
            Ok(0x20000000) // Mock function address
        }

        fn free_library(&mut self, _dll_handle: u64) -> Result<()> {
            Ok(())
        }

        // Phase 7: Error Handling

        fn get_last_error(&self) -> u32 {
            0
        }

        fn set_last_error(&mut self, _error_code: u32) {
            // Mock implementation - do nothing
        }

        // Phase 7: Command-Line Argument Parsing

        fn get_command_line_w(&self) -> Vec<u16> {
            let cmd = "test.exe arg1 arg2";
            let mut utf16: Vec<u16> = cmd.encode_utf16().collect();
            utf16.push(0);
            utf16
        }

        fn command_line_to_argv_w(&self, _command_line: &[u16]) -> Vec<Vec<u16>> {
            vec![
                "test.exe\0".encode_utf16().collect(),
                "arg1\0".encode_utf16().collect(),
                "arg2\0".encode_utf16().collect(),
            ]
        }

        // Phase 7: Advanced File Operations

        fn find_first_file_w(
            &mut self,
            _pattern: &[u16],
        ) -> Result<(
            crate::syscalls::ntdll::SearchHandle,
            crate::syscalls::ntdll::Win32FindDataW,
        )> {
            Ok((
                crate::syscalls::ntdll::SearchHandle(0x5000),
                crate::syscalls::ntdll::Win32FindDataW {
                    file_attributes: 0x00000080, // FILE_ATTRIBUTE_NORMAL
                    creation_time_low: 0,
                    creation_time_high: 0,
                    last_access_time_low: 0,
                    last_access_time_high: 0,
                    last_write_time_low: 0,
                    last_write_time_high: 0,
                    file_size_high: 0,
                    file_size_low: 1024,
                    reserved0: 0,
                    reserved1: 0,
                    file_name: {
                        let mut name = [0u16; 260];
                        let test: Vec<u16> = "test.txt\0".encode_utf16().collect();
                        name[..test.len()].copy_from_slice(&test);
                        name
                    },
                    alternate_file_name: [0; 14],
                },
            ))
        }

        fn find_next_file_w(
            &mut self,
            _handle: crate::syscalls::ntdll::SearchHandle,
        ) -> Result<Option<crate::syscalls::ntdll::Win32FindDataW>> {
            Ok(None) // No more files
        }

        fn find_close(&mut self, _handle: crate::syscalls::ntdll::SearchHandle) -> Result<()> {
            Ok(())
        }

        fn nt_protect_virtual_memory(
            &mut self,
            _address: u64,
            _size: usize,
            new_protect: u32,
        ) -> Result<u32> {
            Ok(new_protect) // Return the new protection as old protection
        }
    }

    #[test]
    fn test_traced_api_disabled() {
        let mock = MockNtdllApi;
        let config = TraceConfig::default(); // disabled
        let trace_ctx = Arc::new(Tracer::new(config, TraceFilter::default()).unwrap());
        let mut traced = TracedNtdllApi::new(mock, trace_ctx);

        let result = traced.nt_create_file(
            "test.txt",
            file_access::GENERIC_READ,
            create_disposition::OPEN_EXISTING,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_traced_api_enabled() {
        let mock = MockNtdllApi;
        let config = TraceConfig::enabled();
        let trace_ctx = Arc::new(Tracer::new(config, TraceFilter::default()).unwrap());
        let mut traced = TracedNtdllApi::new(mock, trace_ctx);

        let result = traced.nt_create_file(
            "test.txt",
            file_access::GENERIC_READ,
            create_disposition::OPEN_EXISTING,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_traced_memory_operations() {
        let mock = MockNtdllApi;
        let config = TraceConfig::enabled();
        let trace_ctx = Arc::new(Tracer::new(config, TraceFilter::default()).unwrap());
        let mut traced = TracedNtdllApi::new(mock, trace_ctx);

        let alloc_result =
            traced.nt_allocate_virtual_memory(4096, memory_protection::PAGE_READWRITE);
        assert!(alloc_result.is_ok());

        let free_result = traced.nt_free_virtual_memory(0x1000000, 4096);
        assert!(free_result.is_ok());
    }
}
