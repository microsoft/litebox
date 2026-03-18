// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a Windows NT-compatible ABI via LiteBox.
//!
//! This shim intercepts `syscall` instructions issued by NT stub DLLs
//! (ntdll.dll, kernel32.dll, etc.) and dispatches them to handlers that
//! implement the NT kernel interface on top of the LiteBox core.
//!
//! ## Syscall Calling Convention
//!
//! Our ntdll stubs use the Windows x64 syscall convention:
//! ```text
//! mov r10, rcx      ; preserve arg0 (syscall clobbers rcx)
//! mov eax, <NR>     ; syscall number
//! syscall
//! ret
//! ```
//!
//! The shim reads arguments from: r10, rdx, r8, r9, then stack.

#![no_std]
#![allow(
    // Skeleton code has unused fields and stub methods.
    dead_code,
    unused_variables,
    // Cast warnings for syscall number extraction and status return
    // are inherent to the NT ABI (u32 syscall numbers, i32 NTSTATUS).
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::unused_self,
    // Phase 2 adds many match arms; some have similar structure.
    clippy::match_same_arms,
)]

extern crate alloc;

use core::cell::RefCell;
use core::sync::atomic::{AtomicI32, Ordering};

use litebox::mm::PageManager;
use litebox::shim::{ContinueOperation, ExceptionInfo};
use litebox_common_windows::NtSyscallNumber;
use litebox_common_windows::ntstatus::NtStatus;
use litebox_common_windows::stub_dlls;
use litebox_platform_multiplex::Platform;

/// Pseudo-handle value for the current process (HANDLE)-1.
const NT_CURRENT_PROCESS_HANDLE: usize = litebox_common_windows::NT_CURRENT_PROCESS;

/// Page size for the Windows userland platform (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Per-process state shared across all threads in an NT guest process.
///
/// Wraps the page manager and other process-wide resources. The runner
/// creates this once and passes a shared reference to each thread's
/// `NtShimEntrypoints`.
pub struct NtProcessState {
    /// Page manager for the guest address space.
    pub pm: PageManager<Platform, PAGE_SIZE>,
    /// Tracks allocation base → aligned size for MEM_RELEASE.
    /// MEM_RELEASE with size==0 must free the entire original allocation.
    alloc_tracker: RefCell<alloc::collections::BTreeMap<usize, usize>>,
}

impl NtProcessState {
    /// Create a new process state with the given page manager.
    pub fn new(pm: PageManager<Platform, PAGE_SIZE>) -> Self {
        Self {
            pm,
            alloc_tracker: RefCell::new(alloc::collections::BTreeMap::new()),
        }
    }

    /// Record an allocation (base address → size in bytes).
    pub fn track_alloc(&self, base: usize, size: usize) {
        self.alloc_tracker.borrow_mut().insert(base, size);
    }

    /// Look up and remove the tracked allocation size for `base`.
    /// Returns `None` if the base was never tracked.
    pub fn untrack_alloc(&self, base: usize) -> Option<usize> {
        self.alloc_tracker.borrow_mut().remove(&base)
    }
}

/// On debug builds, logs that an unimplemented syscall was attempted.
macro_rules! log_unimplemented {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!("NT shim: unimplemented: {}\n", core::format_args!($($arg)*));
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
    };
}

pub mod handle_table;
pub mod peb_teb;
pub mod syscalls;

/// The execution context type. We reuse the same `PtRegs`+`FpRegs` layout
/// from `litebox_common_linux` since the platform asm saves registers in
/// that format regardless of which shim is active.
///
/// For the NT shim, we interpret the registers using the Windows syscall
/// convention:
/// - `orig_rax` / `rax`: syscall number
/// - `r10`: arg0 (moved from rcx by the ntdll stub)
/// - `rdx`: arg1
/// - `r8`: arg2
/// - `r9`: arg3
/// - stack: arg4, arg5, ...
pub type ExecutionContext = litebox_common_linux::ExecutionContext;

/// The NT shim entrypoints, implementing the `EnterShim` trait.
///
/// Each platform thread gets its own instance. Thread-local state (e.g., the
/// current TEB address) is stored here. Process-wide state (PageManager, etc.)
/// is accessed through the shared `process_state` reference.
pub struct NtShimEntrypoints<'ps> {
    /// Exit code set by NtTerminateProcess. The runner reads this after
    /// `run_thread` returns to propagate the guest exit status.
    exit_code: AtomicI32,
    /// NT object handle table. Uses RefCell for interior mutability since
    /// EnterShim methods take `&self`. Phase 3 will switch to a Mutex.
    handles: RefCell<handle_table::HandleTable>,
    /// Pre-allocated stdio handle values for GetStdHandle dispatch.
    stdin_handle: u32,
    stdout_handle: u32,
    stderr_handle: u32,
    /// Initial thread state set by the runner before calling `run_thread`.
    /// The `init` callback reads this to set rip, rsp, and GS base.
    init_state: Option<NtInitState>,
    /// Shared process state (PageManager, etc.).
    process_state: &'ps NtProcessState,
    /// Next TLS slot index to allocate.
    tls_next: RefCell<u32>,
    /// Free TLS slot indices available for reuse.
    tls_free_list: RefCell<alloc::vec::Vec<u32>>,
    /// Next FLS slot index to allocate.
    fls_next: RefCell<u32>,
    /// Free FLS slot indices available for reuse.
    fls_free_list: RefCell<alloc::vec::Vec<u32>>,
    /// FLS slot values (fiber-local storage, treated as thread-local for Phase 2).
    fls_slots: RefCell<[usize; 128]>,
    /// Previous unhandled exception filter (for SetUnhandledExceptionFilter).
    unhandled_exception_filter: RefCell<usize>,
    /// Backing store for Get/SetEnvironmentVariableW.
    env_vars: RefCell<alloc::collections::BTreeMap<alloc::string::String, alloc::string::String>>,
    /// Pool of allocated environment blocks for GetEnvironmentStringsW.
    /// Each entry is (va, allocated_size, in_use). Only blocks with
    /// `in_use == false` are candidates for reuse. FreeEnvironmentStringsW
    /// marks a block as not in use.
    env_block_pool: RefCell<alloc::vec::Vec<(usize, usize, bool)>>,
    /// Guest current working directory (for relative path resolution).
    current_directory: RefCell<alloc::string::String>,
}

/// State set by the runner to configure the initial thread.
pub struct NtInitState {
    /// Absolute VA of the PE entry point.
    pub entry_point: usize,
    /// Top of the guest stack (rsp value on entry).
    pub stack_top: usize,
    /// Guest VA of the TEB (for GS base setup, deferred to Phase 3).
    pub teb_va: usize,
    /// Guest VA of the PEB (for GetModuleHandleW etc.).
    pub peb_va: usize,
    /// Image base address of the main executable.
    pub image_base: usize,
    /// Guest VA of the RTL_USER_PROCESS_PARAMETERS structure.
    pub process_params_va: usize,
    /// Guest VA of the ANSI command line buffer (for GetCommandLineA).
    pub cmdline_ansi_va: usize,
    /// Guest VA of the environment block (double-NUL terminated UTF-16).
    pub env_block_va: usize,
    /// Loaded module base addresses for GetModuleHandleW lookups.
    pub module_bases: alloc::vec::Vec<ModuleBase>,
    /// Guest address space VA range (start..end). Used to validate guest
    /// pointers before dereferencing them in host code.
    pub guest_va_start: usize,
    pub guest_va_end: usize,
    /// Full path of the main executable (for GetModuleFileNameW).
    pub exe_path: alloc::string::String,
}

/// A loaded module's name and base address for GetModuleHandleW.
pub struct ModuleBase {
    /// Module name (case-insensitive), e.g. "ntdll.dll".
    pub name: alloc::string::String,
    /// Full path for GetModuleFileNameW, e.g. "C:\\Windows\\System32\\ntdll.dll".
    pub path: alloc::string::String,
    /// Guest VA base address.
    pub base_address: usize,
    /// Size of the loaded image in bytes (from PE SizeOfImage).
    pub image_size: usize,
}

impl<'ps> NtShimEntrypoints<'ps> {
    /// Create a new NT shim entrypoints for the initial thread.
    #[must_use]
    pub fn new(process_state: &'ps NtProcessState) -> Self {
        let (handles, stdin, stdout, stderr) = handle_table::HandleTable::with_stdio();
        Self {
            exit_code: AtomicI32::new(0),
            handles: RefCell::new(handles),
            stdin_handle: stdin,
            stdout_handle: stdout,
            stderr_handle: stderr,
            init_state: None,
            process_state,
            tls_next: RefCell::new(0),
            tls_free_list: RefCell::new(alloc::vec::Vec::new()),
            fls_next: RefCell::new(0),
            fls_free_list: RefCell::new(alloc::vec::Vec::new()),
            fls_slots: RefCell::new([0usize; 128]),
            unhandled_exception_filter: RefCell::new(0),
            env_vars: RefCell::new(alloc::collections::BTreeMap::new()),
            env_block_pool: RefCell::new(alloc::vec::Vec::new()),
            current_directory: RefCell::new(alloc::string::String::from("C:\\")),
        }
    }

    /// Set the initial thread state. Must be called before `run_thread`.
    pub fn set_init_state(&mut self, state: NtInitState) {
        // Parse the environment block (double-NUL terminated UTF-16LE) into
        // the backing env var map so Get/SetEnvironmentVariableW work.
        if state.env_block_va != 0 {
            let mut env_map = self.env_vars.borrow_mut();
            let mut ptr = state.env_block_va;
            loop {
                // Read one UTF-16 NUL-terminated string.
                let mut chars = alloc::vec::Vec::new();
                loop {
                    let ch = unsafe { core::ptr::read(ptr as *const u16) };
                    ptr += 2;
                    if ch == 0 {
                        break;
                    }
                    chars.push(ch);
                    if chars.len() > 32768 {
                        break;
                    }
                }
                if chars.is_empty() {
                    break; // double-NUL = end of env block
                }
                let s = alloc::string::String::from_utf16_lossy(&chars);
                if let Some(eq_pos) = s.find('=') {
                    let key = &s[..eq_pos];
                    let val = &s[eq_pos + 1..];
                    if !key.is_empty() {
                        env_map.insert(
                            alloc::string::String::from(key),
                            alloc::string::String::from(val),
                        );
                    }
                }
            }
        }
        self.init_state = Some(state);
    }

    /// Returns the guest's requested exit code (set by NtTerminateProcess).
    /// Call this after `run_thread` returns to get the exit status.
    pub fn exit_code(&self) -> i32 {
        self.exit_code.load(Ordering::Acquire)
    }

    /// Returns the stdio handle values for PEB/TEB synthesis.
    pub fn stdio_handles(&self) -> (u32, u32, u32) {
        (self.stdin_handle, self.stdout_handle, self.stderr_handle)
    }

    /// Dispatch an NT syscall or kernel32 syscall.
    ///
    /// Reads the syscall number from `orig_rax` (the platform's
    /// `syscall_callback` stores the original rax there) and arguments from
    /// r10, rdx, r8, r9 (matching the Windows NT syscall convention).
    /// Returns (status, should_terminate).
    fn dispatch_syscall(&self, ctx: &mut ExecutionContext) -> (NtStatus, bool) {
        let nr = ctx.regs.orig_rax as u32;

        // First try NT syscalls (0x0001–0x0FFF range).
        if let Some(nt_nr) = NtSyscallNumber::from_raw(nr) {
            return self.dispatch_nt_syscall(nt_nr, nr, ctx);
        }

        // Then try kernel32 syscalls (0x1000+ range).
        match nr {
            stub_dlls::K32_GET_STD_HANDLE => {
                syscalls::k32_get_std_handle(
                    ctx,
                    self.stdin_handle,
                    self.stdout_handle,
                    self.stderr_handle,
                );
                // GetStdHandle returns the handle in rax (already set by the handler),
                // not an NTSTATUS. Don't overwrite rax in the caller.
                return (NtStatus::STATUS_SUCCESS, false);
            }
            stub_dlls::K32_WRITE_CONSOLE_A => {
                let status = syscalls::k32_write_console_a(ctx, &self.handles.borrow());
                return (status, false);
            }
            stub_dlls::K32_WRITE_CONSOLE_W => {
                let status = syscalls::k32_write_console_w(ctx, &self.handles.borrow());
                return (status, false);
            }
            stub_dlls::K32_EXIT_PROCESS => {
                let (status, terminate, exit_code) = syscalls::k32_exit_process(ctx);
                if terminate {
                    self.exit_code.store(exit_code, Ordering::Release);
                }
                return (status, terminate);
            }
            stub_dlls::K32_GET_COMMAND_LINE_W => {
                // GetCommandLineW returns a pointer to the UNICODE_STRING
                // buffer inside RTL_USER_PROCESS_PARAMETERS.
                if let Some(state) = &self.init_state {
                    let buf_va = state.process_params_va
                        + peb_teb::process_params_offsets::COMMAND_LINE_BUFFER;
                    // Read the Buffer pointer from the UNICODE_STRING struct.
                    // Safety: guest memory is directly accessible on userland.
                    let ptr = unsafe { *(buf_va as *const u64) };
                    ctx.regs.rax = ptr as usize;
                } else {
                    ctx.regs.rax = 0;
                }
                return (NtStatus::STATUS_SUCCESS, false);
            }
            stub_dlls::K32_GET_COMMAND_LINE_A => {
                // GetCommandLineA — return pointer to the ANSI command line
                // buffer that was built alongside the UTF-16 version in the
                // PEB/TEB region.
                if let Some(state) = &self.init_state {
                    ctx.regs.rax = state.cmdline_ansi_va;
                } else {
                    ctx.regs.rax = 0;
                }
                return (NtStatus::STATUS_SUCCESS, false);
            }
            stub_dlls::K32_GET_MODULE_HANDLE_W => {
                // GetModuleHandleW(lpModuleName).
                // NULL → image base of the main executable.
                // Non-null → case-insensitive lookup in loaded modules.
                let module_name_va = ctx.regs.r10; // arg0
                if module_name_va == 0 {
                    if let Some(state) = &self.init_state {
                        ctx.regs.rax = state.image_base;
                    } else {
                        ctx.regs.rax = 0;
                    }
                } else if let Some(state) = &self.init_state {
                    // Read the UTF-16LE module name from guest memory,
                    // validating the pointer against the guest VA range.
                    let name = read_wide_string_bounded(
                        module_name_va,
                        state.guest_va_start,
                        state.guest_va_end,
                    );
                    if let Some(name) = name {
                        // Case-insensitive match against known modules.
                        // Also strip any leading path components so both
                        // "kernel32.dll" and "C:\Windows\System32\kernel32.dll"
                        // match.
                        let name_lower = name.to_ascii_lowercase();
                        let basename = name_lower
                            .rsplit_once('\\')
                            .map_or(name_lower.as_str(), |(_, b)| b);
                        let found = state
                            .module_bases
                            .iter()
                            .find(|m| m.name.to_ascii_lowercase() == basename);
                        ctx.regs.rax = found.map_or(0, |m| m.base_address);
                        if ctx.regs.rax == 0 {
                            log_unimplemented!("GetModuleHandleW({:?}) not found", name);
                        }
                    } else {
                        // Unterminated or invalid pointer — return NULL.
                        log_unimplemented!(
                            "GetModuleHandleW: bad lpModuleName VA 0x{:X}",
                            module_name_va
                        );
                        ctx.regs.rax = 0;
                    }
                } else {
                    ctx.regs.rax = 0;
                }
                return (NtStatus::STATUS_SUCCESS, false);
            }
            // --- Phase 2: Heap ---
            stub_dlls::K32_GET_PROCESS_HEAP => {
                syscalls::heap::k32_get_process_heap(ctx);
                return (NtStatus::STATUS_SUCCESS, false);
            }
            stub_dlls::K32_HEAP_ALLOC => {
                let status = syscalls::heap::k32_heap_alloc(ctx, &self.process_state.pm);
                return (status, false);
            }
            stub_dlls::K32_HEAP_FREE => {
                let status = syscalls::heap::k32_heap_free(ctx, &self.process_state.pm);
                return (status, false);
            }
            stub_dlls::K32_HEAP_REALLOC => {
                let status = syscalls::heap::k32_heap_realloc(ctx, &self.process_state.pm);
                return (status, false);
            }
            stub_dlls::K32_HEAP_SIZE => {
                let status = syscalls::heap::k32_heap_size(ctx);
                return (status, false);
            }
            // --- Phase 2: VirtualAlloc/Free/Protect/Query ---
            stub_dlls::K32_VIRTUAL_ALLOC => {
                let status = syscalls::k32_handlers::k32_virtual_alloc(ctx, self.process_state);
                return (status, false);
            }
            stub_dlls::K32_VIRTUAL_FREE => {
                let status = syscalls::k32_handlers::k32_virtual_free(ctx, self.process_state);
                return (status, false);
            }
            stub_dlls::K32_VIRTUAL_PROTECT => {
                let status =
                    syscalls::k32_handlers::k32_virtual_protect(ctx, &self.process_state.pm);
                return (status, false);
            }
            stub_dlls::K32_VIRTUAL_QUERY => {
                let status = syscalls::k32_handlers::k32_virtual_query(ctx, &self.process_state.pm);
                return (status, false);
            }
            // --- Phase 2: System info ---
            stub_dlls::K32_GET_SYSTEM_INFO => {
                let status = syscalls::k32_handlers::k32_get_system_info(ctx);
                return (status, false);
            }
            stub_dlls::K32_IS_PROCESSOR_FEATURE => {
                let status = syscalls::k32_handlers::k32_is_processor_feature(ctx);
                return (status, false);
            }
            stub_dlls::K32_GET_SYSTEM_TIME_AS_FT => {
                let status = syscalls::k32_handlers::k32_get_system_time_as_ft(ctx);
                return (status, false);
            }
            stub_dlls::K32_QUERY_PERF_COUNTER => {
                let status = syscalls::k32_handlers::k32_query_perf_counter(ctx);
                return (status, false);
            }
            stub_dlls::K32_QUERY_PERF_FREQUENCY => {
                let status = syscalls::k32_handlers::k32_query_perf_frequency(ctx);
                return (status, false);
            }
            // --- Phase 2: TLS ---
            stub_dlls::K32_TLS_ALLOC => {
                let status = syscalls::k32_handlers::k32_tls_alloc(
                    ctx,
                    &mut self.tls_next.borrow_mut(),
                    &mut self.tls_free_list.borrow_mut(),
                );
                return (status, false);
            }
            stub_dlls::K32_TLS_GET_VALUE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_tls_get_value(ctx, teb_va);
                return (status, false);
            }
            stub_dlls::K32_TLS_SET_VALUE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status =
                    syscalls::k32_handlers::k32_tls_set_value(ctx, teb_va, self.process_state);
                return (status, false);
            }
            stub_dlls::K32_TLS_FREE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let tls_next = *self.tls_next.borrow();
                let status = syscalls::k32_handlers::k32_tls_free(
                    ctx,
                    tls_next,
                    &mut self.tls_free_list.borrow_mut(),
                    teb_va,
                );
                return (status, false);
            }
            // --- Phase 2: FLS ---
            stub_dlls::K32_FLS_ALLOC => {
                let status = syscalls::k32_handlers::k32_fls_alloc(
                    ctx,
                    &mut self.fls_next.borrow_mut(),
                    &mut self.fls_free_list.borrow_mut(),
                );
                return (status, false);
            }
            stub_dlls::K32_FLS_GET_VALUE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_fls_get_value(
                    ctx,
                    &self.fls_slots.borrow(),
                    teb_va,
                );
                return (status, false);
            }
            stub_dlls::K32_FLS_SET_VALUE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_fls_set_value(
                    ctx,
                    &mut self.fls_slots.borrow_mut(),
                    teb_va,
                );
                return (status, false);
            }
            stub_dlls::K32_FLS_FREE => {
                let fls_next = *self.fls_next.borrow();
                let status = syscalls::k32_handlers::k32_fls_free(
                    ctx,
                    fls_next,
                    &mut self.fls_free_list.borrow_mut(),
                    &mut self.fls_slots.borrow_mut(),
                );
                return (status, false);
            }
            // --- Phase 2: Exception handling ---
            stub_dlls::K32_SET_UNHANDLED_EXCEPTION_FILTER => {
                let status = syscalls::k32_handlers::k32_set_unhandled_exception_filter(
                    ctx,
                    &mut self.unhandled_exception_filter.borrow_mut(),
                );
                return (status, false);
            }
            stub_dlls::K32_RAISE_EXCEPTION => {
                let (status, terminate) = syscalls::k32_handlers::k32_raise_exception(ctx);
                if terminate {
                    self.exit_code.store(ctx.regs.rax as i32, Ordering::Release);
                }
                return (status, terminate);
            }
            stub_dlls::K32_UNHANDLED_EXCEPTION_FILTER => {
                let status = syscalls::k32_handlers::k32_unhandled_exception_filter(ctx);
                return (status, false);
            }
            // --- Phase 2: Environment ---
            stub_dlls::K32_GET_ENVIRONMENT_STRINGS_W => {
                let status = syscalls::k32_handlers::k32_get_environment_strings_w(
                    ctx,
                    &self.env_vars.borrow(),
                    self.process_state,
                    &self.env_block_pool,
                );
                return (status, false);
            }
            stub_dlls::K32_GET_ENVIRONMENT_VARIABLE_W => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_get_environment_variable_w(
                    ctx,
                    &self.env_vars.borrow(),
                    teb_va,
                );
                return (status, false);
            }
            // --- Phase 2: Module ---
            stub_dlls::K32_GET_MODULE_FILE_NAME_W => {
                let (exe_path, module_bases, image_base, teb_va) =
                    if let Some(s) = self.init_state.as_ref() {
                        (
                            s.exe_path.as_str(),
                            s.module_bases.as_slice(),
                            s.image_base,
                            s.teb_va,
                        )
                    } else {
                        ("C:\\app.exe", &[][..], 0usize, 0usize)
                    };
                let status = syscalls::k32_handlers::k32_get_module_file_name_w(
                    ctx,
                    exe_path,
                    module_bases,
                    image_base,
                    teb_va,
                );
                return (status, false);
            }

            // --- String conversion ---
            stub_dlls::K32_MULTI_BYTE_TO_WIDE_CHAR => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_multi_byte_to_wide_char(ctx, teb_va);
                return (status, false);
            }
            stub_dlls::K32_WIDE_CHAR_TO_MULTI_BYTE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_wide_char_to_multi_byte(ctx, teb_va);
                return (status, false);
            }
            stub_dlls::K32_GET_CP_INFO => {
                let status = syscalls::k32_handlers::k32_get_cp_info(ctx);
                return (status, false);
            }
            stub_dlls::K32_GET_STRING_TYPE_W => {
                let status = syscalls::k32_handlers::k32_get_string_type_w(ctx);
                return (status, false);
            }
            stub_dlls::K32_LC_MAP_STRING_W => {
                let status = syscalls::k32_handlers::k32_lc_map_string_w(ctx);
                return (status, false);
            }
            stub_dlls::K32_COMPARE_STRING_W => {
                let status = syscalls::k32_handlers::k32_compare_string_w(ctx);
                return (status, false);
            }

            // --- Kernel32 file I/O wrappers ---
            stub_dlls::K32_CREATE_FILE_W => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let cwd = self.current_directory.borrow();
                let status = syscalls::k32_handlers::k32_create_file_w(
                    ctx,
                    &mut self.handles.borrow_mut(),
                    teb_va,
                    &cwd,
                );
                return (status, false);
            }
            stub_dlls::K32_READ_FILE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_read_file(
                    ctx,
                    &mut self.handles.borrow_mut(),
                    teb_va,
                );
                return (status, false);
            }
            stub_dlls::K32_WRITE_FILE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_write_file(
                    ctx,
                    &mut self.handles.borrow_mut(),
                    teb_va,
                );
                return (status, false);
            }
            stub_dlls::K32_CLOSE_HANDLE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_close_handle(
                    ctx,
                    &mut self.handles.borrow_mut(),
                    teb_va,
                );
                return (status, false);
            }
            stub_dlls::K32_GET_FILE_TYPE => {
                let status = syscalls::k32_handlers::k32_get_file_type(ctx, &self.handles.borrow());
                return (status, false);
            }
            stub_dlls::K32_GET_FILE_SIZE_EX => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_get_file_size_ex(
                    ctx,
                    &self.handles.borrow(),
                    teb_va,
                );
                return (status, false);
            }
            stub_dlls::K32_SET_FILE_POINTER_EX => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_set_file_pointer_ex(
                    ctx,
                    &mut self.handles.borrow_mut(),
                    teb_va,
                );
                return (status, false);
            }

            // --- Console mode ---
            stub_dlls::K32_GET_CONSOLE_MODE => {
                let status = syscalls::k32_handlers::k32_get_console_mode(ctx);
                return (status, false);
            }
            stub_dlls::K32_SET_CONSOLE_MODE => {
                let status = syscalls::k32_handlers::k32_set_console_mode(ctx);
                return (status, false);
            }

            // --- Version info ---
            stub_dlls::K32_GET_VERSION_EX_W => {
                let status = syscalls::k32_handlers::k32_get_version_ex_w(ctx);
                return (status, false);
            }

            // --- Module loading ---
            stub_dlls::K32_GET_PROC_ADDRESS => {
                let (module_bases, teb_va) = if let Some(s) = self.init_state.as_ref() {
                    (s.module_bases.as_slice(), s.teb_va)
                } else {
                    (&[][..], 0usize)
                };
                let status =
                    syscalls::k32_handlers::k32_get_proc_address(ctx, module_bases, teb_va);
                return (status, false);
            }
            stub_dlls::K32_LOAD_LIBRARY_EX_W => {
                let (module_bases, teb_va) = if let Some(s) = self.init_state.as_ref() {
                    (s.module_bases.as_slice(), s.teb_va)
                } else {
                    (&[][..], 0usize)
                };
                let status =
                    syscalls::k32_handlers::k32_load_library_ex_w(ctx, module_bases, teb_va);
                return (status, false);
            }

            // --- Debug output ---
            stub_dlls::K32_OUTPUT_DEBUG_STRING_A => {
                let status = syscalls::k32_handlers::k32_output_debug_string_a(ctx);
                return (status, false);
            }
            stub_dlls::K32_OUTPUT_DEBUG_STRING_W => {
                let status = syscalls::k32_handlers::k32_output_debug_string_w(ctx);
                return (status, false);
            }

            // --- Heap (additional) ---
            stub_dlls::K32_HEAP_CREATE => {
                let status = syscalls::k32_handlers::k32_heap_create(ctx);
                return (status, false);
            }
            stub_dlls::K32_HEAP_DESTROY => {
                let status = syscalls::k32_handlers::k32_heap_destroy(ctx);
                return (status, false);
            }

            // --- Path / directory ---
            stub_dlls::K32_GET_FULL_PATH_NAME_W => {
                let cwd = self.current_directory.borrow();
                let status = syscalls::k32_handlers::k32_get_full_path_name_w(ctx, &cwd);
                return (status, false);
            }
            stub_dlls::K32_GET_TEMP_PATH_W => {
                let status = syscalls::k32_handlers::k32_get_temp_path_w(ctx);
                return (status, false);
            }
            stub_dlls::K32_GET_CURRENT_DIRECTORY_W => {
                let cwd = self.current_directory.borrow();
                let status = syscalls::k32_handlers::k32_get_current_directory_w(ctx, &cwd);
                return (status, false);
            }
            stub_dlls::K32_SET_CURRENT_DIRECTORY_W => {
                let mut cwd = self.current_directory.borrow_mut();
                let status = syscalls::k32_handlers::k32_set_current_directory_w(ctx, &mut cwd);
                return (status, false);
            }

            // --- Handle duplication ---
            stub_dlls::K32_DUPLICATE_HANDLE => {
                let status = syscalls::k32_handlers::k32_duplicate_handle(
                    ctx,
                    &mut self.handles.borrow_mut(),
                );
                return (status, false);
            }

            // --- Environment (additional) ---
            stub_dlls::K32_SET_ENVIRONMENT_VARIABLE_W => {
                let status = syscalls::k32_handlers::k32_set_environment_variable_w(
                    ctx,
                    &mut self.env_vars.borrow_mut(),
                );
                return (status, false);
            }
            stub_dlls::K32_FREE_ENVIRONMENT_STRINGS_W => {
                let status = syscalls::k32_handlers::k32_free_environment_strings_w(
                    ctx,
                    self.process_state,
                    &self.env_block_pool,
                );
                return (status, false);
            }

            // --- Console handle ---
            stub_dlls::K32_SET_STD_HANDLE => {
                let status = syscalls::k32_handlers::k32_set_std_handle(ctx);
                return (status, false);
            }

            // --- File search ---
            stub_dlls::K32_FIND_FIRST_FILE_EX_W => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_find_first_file_ex_w(
                    ctx,
                    &mut self.handles.borrow_mut(),
                    teb_va,
                );
                return (status, false);
            }
            stub_dlls::K32_FIND_NEXT_FILE_W => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_find_next_file_w(
                    ctx,
                    &mut self.handles.borrow_mut(),
                    teb_va,
                );
                return (status, false);
            }
            stub_dlls::K32_FIND_CLOSE => {
                let status =
                    syscalls::k32_handlers::k32_find_close(ctx, &mut self.handles.borrow_mut());
                return (status, false);
            }

            // --- SEH / unwinding ---
            stub_dlls::K32_RTL_CAPTURE_CONTEXT => {
                let status = syscalls::k32_handlers::k32_rtl_capture_context(ctx);
                return (status, false);
            }
            stub_dlls::K32_RTL_LOOKUP_FUNCTION_ENTRY => {
                let mods = self
                    .init_state
                    .as_ref()
                    .map(|s| s.module_bases.as_slice())
                    .unwrap_or(&[]);
                let status = syscalls::k32_handlers::k32_rtl_lookup_function_entry(ctx, mods);
                return (status, false);
            }
            stub_dlls::K32_RTL_VIRTUAL_UNWIND => {
                let mods = self
                    .init_state
                    .as_ref()
                    .map(|s| s.module_bases.as_slice())
                    .unwrap_or(&[]);
                let status = syscalls::k32_handlers::k32_rtl_virtual_unwind(ctx, mods);
                return (status, false);
            }
            stub_dlls::K32_RTL_UNWIND_EX => {
                let mods = self
                    .init_state
                    .as_ref()
                    .map(|s| s.module_bases.as_slice())
                    .unwrap_or(&[]);
                let status = syscalls::k32_handlers::k32_rtl_unwind_ex(ctx, mods);
                return (status, false);
            }
            stub_dlls::K32_RTL_PC_TO_FILE_HEADER => {
                let mods = self
                    .init_state
                    .as_ref()
                    .map(|s| s.module_bases.as_slice())
                    .unwrap_or(&[]);
                let status = syscalls::k32_handlers::k32_rtl_pc_to_file_header(ctx, mods);
                return (status, false);
            }

            _ => {}
        }

        log_unimplemented!("unknown syscall nr=0x{:04X}", nr);
        (NtStatus::STATUS_NOT_IMPLEMENTED, false)
    }

    /// Dispatch an NT-specific syscall (from ntdll stubs).
    fn dispatch_nt_syscall(
        &self,
        nt_nr: NtSyscallNumber,
        raw_nr: u32,
        ctx: &mut ExecutionContext,
    ) -> (NtStatus, bool) {
        match nt_nr {
            NtSyscallNumber::NtTerminateProcess => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let handle = args.arg0;
                let exit_status = args.arg1 as i32;

                if handle == NT_CURRENT_PROCESS_HANDLE || handle == 0 {
                    self.exit_code.store(exit_status, Ordering::Release);
                    (NtStatus::STATUS_SUCCESS, true)
                } else {
                    log_unimplemented!("NtTerminateProcess on remote handle 0x{:X}", handle);
                    (NtStatus::STATUS_NOT_IMPLEMENTED, false)
                }
            }
            NtSyscallNumber::NtWriteFile => {
                let status = syscalls::file::nt_write_file(ctx, &mut self.handles.borrow_mut());
                (status, false)
            }
            NtSyscallNumber::NtClose => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let status = syscalls::nt_close(&mut self.handles.borrow_mut(), args.arg0 as u32);
                (status, false)
            }
            // Phase 2: File I/O
            NtSyscallNumber::NtCreateFile => {
                let status = syscalls::file::nt_create_file(ctx, &mut self.handles.borrow_mut());
                (status, false)
            }
            NtSyscallNumber::NtReadFile => {
                let status = syscalls::file::nt_read_file(ctx, &mut self.handles.borrow_mut());
                (status, false)
            }
            NtSyscallNumber::NtQueryInformationFile => {
                let status = syscalls::file::nt_query_information_file(ctx, &self.handles.borrow());
                (status, false)
            }
            NtSyscallNumber::NtSetInformationFile => {
                let status =
                    syscalls::file::nt_set_information_file(ctx, &mut self.handles.borrow_mut());
                (status, false)
            }
            NtSyscallNumber::NtQueryAttributesFile => {
                let status = syscalls::file::nt_query_attributes_file(ctx);
                (status, false)
            }
            // Phase 2: Memory management
            NtSyscallNumber::NtAllocateVirtualMemory => {
                let status = syscalls::memory::nt_allocate_virtual_memory(ctx, self.process_state);
                (status, false)
            }
            NtSyscallNumber::NtFreeVirtualMemory => {
                let status = syscalls::memory::nt_free_virtual_memory(ctx, self.process_state);
                (status, false)
            }
            NtSyscallNumber::NtProtectVirtualMemory => {
                let status =
                    syscalls::memory::nt_protect_virtual_memory(ctx, &self.process_state.pm);
                (status, false)
            }
            NtSyscallNumber::NtQueryVirtualMemory => {
                let status = syscalls::memory::nt_query_virtual_memory(ctx, &self.process_state.pm);
                (status, false)
            }
            // Phase 2: System information & time
            NtSyscallNumber::NtQuerySystemInformation => {
                let status = syscalls::sysinfo::nt_query_system_information(ctx);
                (status, false)
            }
            NtSyscallNumber::NtQueryPerformanceCounter => {
                let status = syscalls::sysinfo::nt_query_performance_counter(ctx);
                (status, false)
            }
            NtSyscallNumber::NtQuerySystemTime => {
                let status = syscalls::sysinfo::nt_query_system_time(ctx);
                (status, false)
            }
            NtSyscallNumber::NtQueryInformationProcess => {
                let status =
                    syscalls::sysinfo::nt_query_information_process(ctx, self.init_state.as_ref());
                (status, false)
            }
            NtSyscallNumber::NtDelayExecution => {
                let status = syscalls::sysinfo::nt_delay_execution(ctx);
                (status, false)
            }
            NtSyscallNumber::NtSetInformationThread => {
                // Commonly called for thread name, affinity, etc.
                // Return success for now — most info classes are optional.
                (NtStatus::STATUS_SUCCESS, false)
            }
            NtSyscallNumber::NtQueryVolumeInformationFile => {
                // Stub: return basic volume information.
                let status = syscalls::file::nt_query_volume_information_file(ctx);
                (status, false)
            }
            NtSyscallNumber::NtQueryDirectoryFile => {
                let status =
                    syscalls::file::nt_query_directory_file(ctx, &mut self.handles.borrow_mut());
                (status, false)
            }
            other => {
                log_unimplemented!("syscall {:?} (nr=0x{:04X})", other, raw_nr);
                (NtStatus::STATUS_NOT_IMPLEMENTED, false)
            }
        }
    }
}

impl<'ps> litebox::shim::EnterShim for NtShimEntrypoints<'ps> {
    type ExecutionContext = ExecutionContext;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        // Set up initial thread state from the runner-provided init state.
        if let Some(state) = &self.init_state {
            ctx.regs.rip = state.entry_point;
            ctx.regs.rsp = state.stack_top;
            // Set rcx = rip so the platform uses the sysret fast path for
            // initial entry. This is important because sysret restores guest
            // GS base in naked asm. The NtContinue slow path may not preserve
            // wrgsbase across the kernel round-trip on all Windows versions.
            // The guest entry point does not use rcx as a parameter.
            ctx.regs.rcx = state.entry_point;
        }
        ContinueOperation::Resume
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        let nr = ctx.regs.orig_rax as u32;

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: syscall nr=0x{:04X} rip=0x{:X} r10=0x{:X} rdx=0x{:X}\n",
                nr,
                ctx.regs.rip,
                ctx.regs.r10,
                ctx.regs.rdx
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }

        let (status, terminate) = self.dispatch_syscall(ctx);

        // Kernel32 functions in the 0x1000+ range return values in rax
        // directly (the dispatch handler sets rax). NT syscalls in the
        // 0x0000–0x0FFF range return NTSTATUS in rax.
        let is_kernel32 = nr >= 0x1000;
        if !is_kernel32 {
            ctx.regs.rax = status.0 as u32 as usize;
        }

        if terminate {
            return ContinueOperation::Terminate;
        }

        ContinueOperation::Resume
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &ExceptionInfo,
    ) -> ContinueOperation {
        let status = exception_to_ntstatus(info);

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: EXCEPTION at rip=0x{:X} rsp=0x{:X} status=0x{:08X} info={:?}\n",
                ctx.regs.rip,
                ctx.regs.rsp,
                status.0 as u32,
                info
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }

        self.exit_code.store(status.0, Ordering::Release);
        log_unimplemented!(
            "exception {:?} at rip=0x{:X} (exit code 0x{:08X})",
            info.exception,
            ctx.regs.rip,
            status.0 as u32
        );
        ContinueOperation::Terminate
    }

    fn interrupt(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        // Note: Guest GS base is NOT restored here — interrupts are delivered
        // via the platform's VEH which runs with host GS (restored by the
        // kernel for exception delivery). The trampoline return path handles
        // guest GS restoration for the syscall path.
        ContinueOperation::Resume
    }
}

/// Map an x86 exception to the NTSTATUS that Windows uses as the process exit
/// code for an unhandled exception of that type.
fn exception_to_ntstatus(info: &ExceptionInfo) -> NtStatus {
    use litebox::shim::Exception;
    match info.exception {
        Exception::DIVIDE_ERROR => NtStatus::STATUS_INTEGER_DIVIDE_BY_ZERO,
        Exception::BREAKPOINT => NtStatus::STATUS_BREAKPOINT,
        Exception::INVALID_OPCODE => NtStatus::STATUS_ILLEGAL_INSTRUCTION,
        Exception::GENERAL_PROTECTION_FAULT => NtStatus::STATUS_ACCESS_VIOLATION,
        Exception::PAGE_FAULT => NtStatus::STATUS_ACCESS_VIOLATION,
        _ => NtStatus::STATUS_UNSUCCESSFUL,
    }
}

/// Maximum characters to read from a guest wide string. Windows MAX_PATH is
/// 260; module names are always shorter. This bound prevents unbounded walks
/// through host memory if the guest passes a bad or unterminated pointer.
const MAX_WIDE_STRING_CHARS: usize = 260;

// ---------------------------------------------------------------------------
// Minimal FFI for VirtualQuery — used to probe whether guest pages are
// committed before reading. We define the struct and extern inline to avoid
// adding a windows-sys dependency to this no_std crate.
// ---------------------------------------------------------------------------

/// Subset of MEMORY_BASIC_INFORMATION (x86_64 layout, 48 bytes).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[repr(C)]
struct MemoryBasicInformation {
    base_address: usize,
    allocation_base: usize,
    allocation_protect: u32,
    _partition_id: u16,
    _pad: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    type_: u32,
    _pad2: u32,
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe extern "system" {
    fn VirtualQuery(
        lp_address: usize,
        lp_buffer: *mut MemoryBasicInformation,
        dw_length: usize,
    ) -> usize;
}

/// Page state: committed (backed by physical storage).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const MEM_COMMIT: u32 = 0x1000;
/// Page protection: no access.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const PAGE_NOACCESS: u32 = 0x01;
/// Page protection modifier: guard page.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const PAGE_GUARD: u32 = 0x100;

/// Check whether the byte range `[va, va+len)` is backed by committed,
/// readable pages. Returns `false` for MEM_FREE, MEM_RESERVE, PAGE_NOACCESS,
/// or PAGE_GUARD regions.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn is_memory_readable(va: usize, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let end = match va.checked_add(len) {
        Some(e) => e,
        None => return false,
    };
    let mut addr = va;
    while addr < end {
        let mut mbi = core::mem::MaybeUninit::<MemoryBasicInformation>::zeroed();
        // SAFETY: mbi is a properly-sized output buffer for VirtualQuery.
        let ret = unsafe {
            VirtualQuery(
                addr,
                mbi.as_mut_ptr(),
                core::mem::size_of::<MemoryBasicInformation>(),
            )
        };
        if ret == 0 {
            return false;
        }
        // SAFETY: VirtualQuery succeeded, so mbi is fully initialized.
        let mbi = unsafe { mbi.assume_init() };
        if mbi.state != MEM_COMMIT {
            return false;
        }
        if mbi.protect == PAGE_NOACCESS || (mbi.protect & PAGE_GUARD) != 0 {
            return false;
        }
        // Advance past this region.
        let region_end = mbi.base_address + mbi.region_size;
        addr = region_end;
    }
    true
}

/// Non-Windows stub: always returns false (no guest memory access possible).
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn is_memory_readable(_va: usize, _len: usize) -> bool {
    false
}

/// Read a null-terminated UTF-16LE string from guest memory at `va`, with
/// incremental page probing.
///
/// For each u16 we need to read, we ensure the containing page(s) are
/// committed and readable via `VirtualQuery`. Probing is done lazily —
/// only pages actually touched are checked — so a short string near the
/// end of a committed region works correctly.
///
/// Returns `None` if `va` is zero, outside the guest VA partition, the
/// pages are not readable, or the string exceeds [`MAX_WIDE_STRING_CHARS`].
fn read_wide_string_bounded(
    va: usize,
    guest_va_start: usize,
    guest_va_end: usize,
) -> Option<alloc::string::String> {
    if va == 0 || va < guest_va_start {
        return None;
    }

    let mut chars = alloc::vec::Vec::new();
    let mut ptr = va;
    // Track the end of the currently-probed readable region.
    let mut probed_up_to: usize = va;

    for _ in 0..MAX_WIDE_STRING_CHARS {
        let read_end = ptr.checked_add(2)?;
        // Bounds-check against the guest partition.
        if read_end > guest_va_end {
            return None;
        }
        // If the next u16 extends past our probed window, re-probe.
        if read_end > probed_up_to {
            if !is_memory_readable(ptr, 2) {
                return None;
            }
            // VirtualQuery tells us the region extends to base + region_size.
            // Rather than re-querying for every char, probe the remainder of
            // this page so we amortise the syscall cost.
            let page_end = (ptr & !0xFFF) + 0x1000;
            probed_up_to = page_end;
        }
        // SAFETY: we just verified via VirtualQuery that [ptr, ptr+2) is
        // backed by committed readable memory within the guest partition.
        let wchar = unsafe { core::ptr::read_unaligned(ptr as *const u16) };
        if wchar == 0 {
            return Some(alloc::string::String::from_utf16_lossy(&chars));
        }
        chars.push(wchar);
        ptr = read_end;
    }
    // Unterminated string — treat as invalid rather than silently truncating.
    None
}
