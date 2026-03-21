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
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::unused_self,
    // Raw guest-memory marshaling uses explicit pointer casts and alignment assumptions.
    clippy::borrow_as_ptr,
    clippy::cast_ptr_alignment,
    clippy::ptr_as_ptr,
    // Phase 2 adds many match arms; some have similar structure.
    clippy::items_after_statements,
    clippy::match_same_arms,
    clippy::single_match_else,
    // These helpers intentionally use scratch bindings and doc-light internal APIs.
    clippy::missing_panics_doc,
    clippy::no_effect_underscore_binding,
    clippy::used_underscore_binding,
    clippy::unnecessary_cast,
    // Some syscall helpers naturally use near-identical names for paired values.
    clippy::similar_names,
    clippy::format_push_string,
    clippy::identity_op,
    clippy::new_without_default,
    clippy::too_many_arguments,
    clippy::case_sensitive_file_extension_comparisons,
)]

extern crate alloc;

use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

use litebox::event::wait::WaitState;
use litebox::mm::PageManager;
use litebox::shim::{ContinueOperation, ExceptionInfo};
use litebox_common_windows::ntstatus::NtStatus;
use litebox_common_windows::stub_dlls;
use litebox_common_windows::{NtSyscallId, NtSyscallMap};
use litebox_platform_multiplex::Platform;

/// Concrete layered filesystem type used by the NT shim.
/// Same architecture as the Linux shim: in-memory (writable) on top of
/// devices on top of tar read-only.
pub type NtFS = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;

/// Pseudo-handle value for the current process (HANDLE)-1.
const NT_CURRENT_PROCESS_HANDLE: usize = litebox_common_windows::NT_CURRENT_PROCESS;

/// Page size for the Windows userland platform (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Pre-captured NLS combined section data from the host kernel.
/// The runner captures this once and passes it to the shim so the shim
/// doesn't need to call host Win32 APIs (GetModuleHandleA, etc.).
pub struct NlsData {
    /// The combined NLS section bytes (typically ~0xD3000 = 864KB).
    pub section: alloc::vec::Vec<u8>,
    /// Default locale ID (e.g. 0x409 for en-US).
    pub locale_id: u32,
    /// Default casing table size.
    pub casing_size: i64,
}

/// Per-process state shared across all threads in an NT guest process.
///
/// Wraps the page manager and other process-wide resources. The runner
/// creates this once and passes a shared reference to each thread's
/// `NtShimEntrypoints`.
pub struct NtProcessState {
    /// Page manager for the guest address space.
    pub pm: PageManager<Platform, PAGE_SIZE>,
    /// Tracks allocation base ΓåÆ aligned size for MEM_RELEASE.
    /// MEM_RELEASE with size==0 must free the entire original allocation.
    alloc_tracker: Mutex<alloc::collections::BTreeMap<usize, usize>>,
    /// Tracks SEC_IMAGE mappings (base ΓåÆ size) for NtQueryVirtualMemory.
    /// Pages within these ranges should report `MEM_IMAGE` type instead of
    /// `MEM_PRIVATE`, matching real NT kernel behavior.
    image_mappings: Mutex<alloc::collections::BTreeMap<usize, usize>>,
}

impl NtProcessState {
    /// Create a new process state with the given page manager.
    pub fn new(pm: PageManager<Platform, PAGE_SIZE>) -> Self {
        Self {
            pm,
            alloc_tracker: Mutex::new(alloc::collections::BTreeMap::new()),
            image_mappings: Mutex::new(alloc::collections::BTreeMap::new()),
        }
    }

    /// Record an allocation (base address ΓåÆ size in bytes).
    pub fn track_alloc(&self, base: usize, size: usize) {
        self.alloc_tracker.lock().insert(base, size);
    }

    /// Look up and remove the tracked allocation size for `base`.
    /// Returns `None` if the base was never tracked.
    pub fn untrack_alloc(&self, base: usize) -> Option<usize> {
        self.alloc_tracker.lock().remove(&base)
    }

    /// Returns `true` if `addr` falls within any tracked allocation range.
    pub fn is_tracked_alloc(&self, addr: usize) -> bool {
        let tracker = self.alloc_tracker.lock();
        // Find the largest base Γëñ addr and check if addr < base + size.
        if let Some((&base, &size)) = tracker.range(..=addr).next_back() {
            addr < base + size
        } else {
            false
        }
    }

    /// Allocate a small RW region in guest VA. Returns the guest VA of the
    /// allocated block, or 0 on failure. The allocation is page-aligned and
    /// at least `size` bytes.
    pub fn alloc_rw_bytes(&self, size: usize) -> usize {
        use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
        use litebox::platform::RawConstPointer as _;
        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let Some(nz_size) = NonZeroPageSize::<PAGE_SIZE>::new(aligned) else {
            return 0;
        };
        // Safety: create_writable_pages places the pages in guest VA.
        let result = unsafe {
            self.pm
                .create_writable_pages(None, nz_size, CreatePagesFlags::empty(), |_| Ok(0))
        };
        match result {
            Ok(ptr) => ptr.as_usize(),
            Err(_) => 0,
        }
    }

    /// Record a SEC_IMAGE mapping (base ΓåÆ size) for NtQueryVirtualMemory.
    pub fn track_image_mapping(&self, base: usize, size: usize) {
        self.image_mappings.lock().insert(base, size);
    }

    /// Returns `true` if `addr` falls within a SEC_IMAGE mapping.
    pub fn is_image_mapping(&self, addr: usize) -> bool {
        let mappings = self.image_mappings.lock();
        if let Some((&base, &size)) = mappings.range(..=addr).next_back() {
            addr < base + size
        } else {
            false
        }
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
/// current TEB address) is stored here. Process-wide state is accessed through
/// the shared `shared` reference (an `Arc<NtSharedState>`).
pub struct NtShimEntrypoints {
    /// Exit code set by NtTerminateProcess. The runner reads this after
    /// `run_thread` returns to propagate the guest exit status.
    exit_code: AtomicI32,
    /// Initial thread state set by the runner before calling `run_thread`.
    /// The `init` callback reads this to set rip, rsp, and GS base.
    init_state: Option<NtInitState>,
    /// For child threads: the argument to pass in RCX on entry.
    /// None for the main thread (main thread uses sysret fast path with RCX = RIP).
    child_thread_argument: Option<usize>,
    /// FLS slot values (fiber-local storage, treated as thread-local for Phase 2).
    /// Per-thread because FLS is per-fiber/per-thread.
    fls_slots: Mutex<[usize; 128]>,
    /// The thread object for this thread. `None` for the main thread.
    /// Used to call `set_exited()` when the thread terminates.
    thread_obj: Option<alloc::sync::Arc<handle_table::ThreadObject>>,
    /// Per-thread ID. Main thread = 1, child threads get monotonically
    /// increasing IDs from `NtSharedState::next_thread_id`.
    thread_id: u32,
    /// Per-thread wait state for proper blocking waits (sleep, events, etc.).
    wait_state: WaitState<Platform>,
    /// Process-wide shared state (handles, env, CWD, etc.).
    shared: alloc::sync::Arc<NtSharedState>,
}

/// Process-wide state shared by all threads via `Arc`.
pub(crate) struct NtSharedState {
    /// NT object handle table.
    pub handles: Mutex<handle_table::HandleTable>,
    /// Pre-allocated stdio handle values for GetStdHandle dispatch.
    pub stdin_handle: u32,
    pub stdout_handle: u32,
    pub stderr_handle: u32,
    /// Shared process state (PageManager, etc.).
    pub process_state: alloc::sync::Arc<NtProcessState>,
    /// Next TLS slot index to allocate.
    pub tls_next: Mutex<u32>,
    /// Free TLS slot indices available for reuse.
    pub tls_free_list: Mutex<alloc::vec::Vec<u32>>,
    /// Next FLS slot index to allocate.
    pub fls_next: Mutex<u32>,
    /// Free FLS slot indices available for reuse.
    pub fls_free_list: Mutex<alloc::vec::Vec<u32>>,
    /// Previous unhandled exception filter (for SetUnhandledExceptionFilter).
    pub unhandled_exception_filter: Mutex<usize>,
    /// Backing store for Get/SetEnvironmentVariableW.
    pub env_vars: Mutex<alloc::collections::BTreeMap<alloc::string::String, alloc::string::String>>,
    /// Pool of allocated environment blocks for GetEnvironmentStringsW.
    pub env_block_pool: Mutex<alloc::vec::Vec<(usize, usize, bool)>>,
    /// Guest current working directory (for relative path resolution).
    pub current_directory: Mutex<alloc::string::String>,
    /// Next thread ID for NtCreateThreadEx.
    pub next_thread_id: Mutex<u32>,
    /// Optional smoltcp network stack for WinSock syscalls.
    /// Set by the runner after creating the Network instance.
    pub net: spin::Once<alloc::sync::Arc<spin::Mutex<litebox::net::Network<Platform>>>>,
    /// Socket storage: maps socket IDs ΓåÆ owned `SocketFd` handles.
    /// Socket IDs are also stored in the handle table as `NtObject::Socket { sock_id }`.
    pub sockets: Mutex<alloc::collections::BTreeMap<u32, litebox::net::SocketFd<Platform>>>,
    /// Next socket ID to allocate.
    pub next_socket_id: Mutex<u32>,
    /// Carry-over buffer for ReadConsoleW: bytes read from host stdin that
    /// have not yet been returned to the guest.  Preserves excess and
    /// incomplete UTF-8 tails across calls.
    pub console_input_pending: Mutex<alloc::vec::Vec<u8>>,
    /// Pre-captured NLS combined section data, locale ID, and casing size.
    /// Set by the runner so the shim doesn't need to call host APIs.
    pub nls_data: spin::Once<NlsData>,
    /// Litebox core VFS for file I/O.
    pub fs: spin::Once<alloc::sync::Arc<NtFS>>,
    /// Guest address space VA range (start..end) for pointer validation.
    pub guest_va_start: core::sync::atomic::AtomicUsize,
    pub guest_va_end: core::sync::atomic::AtomicUsize,
    /// Raw descriptor storage for VFS file descriptors.
    /// Maps raw integer fd indices to `TypedFd<NtFS>` handles.
    pub raw_fds: Mutex<litebox::fd::RawDescriptorStorage>,
    /// Mapping from real Windows syscall numbers to `NtSyscallId`.
    /// Populated by the ntdll rewriter; used for dispatch.
    pub syscall_map: spin::Once<NtSyscallMap>,
    /// Syscall number ΓåÆ export name for unhandled stubs (debug logging).
    pub unhandled_stubs: spin::Once<alloc::vec::Vec<(u32, alloc::string::String)>>,
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
    /// For ntdll-driven init: RCX value (CONTEXT* pointer on guest stack).
    pub initial_rcx: usize,
    /// For ntdll-driven init: RDX value (ntdll base address).
    pub initial_rdx: usize,
    /// RVA of KiUserExceptionDispatcher in ntdll, resolved from PE exports.
    pub ki_user_exception_dispatcher_rva: Option<usize>,
}

/// A loaded module's name and base address for GetModuleHandleW.
#[derive(Clone)]
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

impl NtShimEntrypoints {
    /// Create a new NT shim entrypoints for the initial thread.
    #[must_use]
    pub fn new(process_state: alloc::sync::Arc<NtProcessState>) -> Self {
        let (handles, stdin, stdout, stderr) = handle_table::HandleTable::with_stdio();
        let shared = alloc::sync::Arc::new(NtSharedState {
            handles: Mutex::new(handles),
            stdin_handle: stdin,
            stdout_handle: stdout,
            stderr_handle: stderr,
            process_state,
            tls_next: Mutex::new(0),
            tls_free_list: Mutex::new(alloc::vec::Vec::new()),
            fls_next: Mutex::new(0),
            fls_free_list: Mutex::new(alloc::vec::Vec::new()),
            unhandled_exception_filter: Mutex::new(0),
            env_vars: Mutex::new(alloc::collections::BTreeMap::new()),
            env_block_pool: Mutex::new(alloc::vec::Vec::new()),
            current_directory: Mutex::new(alloc::string::String::from("C:\\")),
            next_thread_id: Mutex::new(2), // TID 1 is the main thread
            net: spin::Once::new(),
            sockets: Mutex::new(alloc::collections::BTreeMap::new()),
            next_socket_id: Mutex::new(1),
            console_input_pending: Mutex::new(alloc::vec::Vec::new()),
            nls_data: spin::Once::new(),
            fs: spin::Once::new(),
            guest_va_start: core::sync::atomic::AtomicUsize::new(0),
            guest_va_end: core::sync::atomic::AtomicUsize::new(usize::MAX),
            raw_fds: Mutex::new(litebox::fd::RawDescriptorStorage::new()),
            syscall_map: spin::Once::new(),
            unhandled_stubs: spin::Once::new(),
        });
        Self {
            exit_code: AtomicI32::new(0),
            init_state: None,
            child_thread_argument: None,
            fls_slots: Mutex::new([0usize; 128]),
            thread_obj: None,
            thread_id: 1, // Main thread is always TID 1
            wait_state: WaitState::new(litebox_platform_multiplex::platform()),
            shared,
        }
    }

    /// Install the syscall mapping table produced by the ntdll rewriter.
    /// Must be called before entering the guest.
    pub fn set_syscall_map(&self, map: NtSyscallMap) {
        let _ = self.shared.syscall_map.call_once(|| map);
    }

    /// Install unhandled stub names for debug logging of unknown syscalls.
    pub fn set_unhandled_stubs(&self, stubs: alloc::vec::Vec<(u32, alloc::string::String)>) {
        let _ = self.shared.unhandled_stubs.call_once(|| stubs);
    }

    /// Install pre-captured NLS data so the shim doesn't call host APIs.
    pub fn set_nls_data(&self, data: NlsData) {
        let _ = self.shared.nls_data.call_once(|| data);
    }

    /// Install the litebox core VFS for file I/O.
    pub fn set_fs(&self, fs: alloc::sync::Arc<NtFS>) {
        let _ = self.shared.fs.call_once(|| fs);
    }

    /// Returns a wait context for the current thread, suitable for blocking
    /// waits (sleep, event waits, etc.). Uses the platform's blocking
    /// primitives instead of busy-spinning.
    pub(crate) fn wait_cx(&self) -> litebox::event::wait::WaitContext<'_, Platform> {
        self.wait_state.context()
    }

    /// Create a new NT shim entrypoints for a child thread.
    ///
    /// Shares all process-wide state with the parent through `Arc<NtSharedState>`.
    /// The child gets its own per-thread state (init_state, fls_slots, thread_obj).
    fn new_for_child_thread(
        shared: alloc::sync::Arc<NtSharedState>,
        thread_obj: alloc::sync::Arc<handle_table::ThreadObject>,
        thread_id: u32,
        parent_init: &NtInitState,
        child_entry: usize,
        child_stack_top: usize,
        child_teb_va: usize,
        child_argument: usize,
    ) -> Self {
        Self {
            exit_code: AtomicI32::new(0),
            init_state: Some(NtInitState {
                entry_point: child_entry,
                stack_top: child_stack_top,
                teb_va: child_teb_va,
                peb_va: parent_init.peb_va,
                image_base: parent_init.image_base,
                process_params_va: parent_init.process_params_va,
                cmdline_ansi_va: parent_init.cmdline_ansi_va,
                env_block_va: 0, // Don't re-parse env block
                module_bases: parent_init.module_bases.clone(),
                guest_va_start: parent_init.guest_va_start,
                guest_va_end: parent_init.guest_va_end,
                exe_path: parent_init.exe_path.clone(),
                initial_rcx: 0,
                initial_rdx: 0,
                ki_user_exception_dispatcher_rva: parent_init.ki_user_exception_dispatcher_rva,
            }),
            child_thread_argument: Some(child_argument),
            fls_slots: Mutex::new([0usize; 128]),
            thread_obj: Some(thread_obj),
            thread_id,
            wait_state: WaitState::new(litebox_platform_multiplex::platform()),
            shared,
        }
    }

    /// Set the initial thread state. Must be called before `run_thread`.
    pub fn set_init_state(&mut self, state: NtInitState) {
        // Parse the environment block (double-NUL terminated UTF-16LE) into
        // the backing env var map so Get/SetEnvironmentVariableW work.
        if state.env_block_va != 0 {
            let mut env_map = self.shared.env_vars.lock();
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
        self.shared
            .guest_va_start
            .store(state.guest_va_start, Ordering::Release);
        self.shared
            .guest_va_end
            .store(state.guest_va_end, Ordering::Release);
        self.init_state = Some(state);
    }

    /// Returns the guest's requested exit code (set by NtTerminateProcess).
    /// Call this after `run_thread` returns to get the exit status.
    pub fn exit_code(&self) -> i32 {
        self.exit_code.load(Ordering::Acquire)
    }

    /// Returns the stdio handle values for PEB/TEB synthesis.
    pub fn stdio_handles(&self) -> (u32, u32, u32) {
        (
            self.shared.stdin_handle,
            self.shared.stdout_handle,
            self.shared.stderr_handle,
        )
    }

    /// Attach the smoltcp network stack for WinSock syscall dispatch.
    /// Must be called before running the guest if networking is needed.
    pub fn set_network(&self, net: alloc::sync::Arc<spin::Mutex<litebox::net::Network<Platform>>>) {
        self.shared.net.call_once(|| net);
    }

    /// Dispatch an NT syscall or kernel32 syscall.
    ///
    /// Reads the syscall number from `orig_rax` (the platform's
    /// `syscall_callback` stores the original rax there) and arguments from
    /// r10, rdx, r8, r9 (matching the Windows NT syscall convention).
    /// Returns (status, should_terminate).
    fn dispatch_syscall(&self, ctx: &mut ExecutionContext) -> (NtStatus, bool) {
        let nr = ctx.regs.orig_rax as u32;

        // First try NT syscalls via the rewriter-produced mapping.
        if let Some(map) = self.shared.syscall_map.get()
            && let Some(id) = map.lookup(nr)
        {
            return self.dispatch_nt_syscall(id, nr, ctx);
        }

        // Then try kernel32 syscalls (0x1000+ range).
        match nr {
            stub_dlls::K32_GET_STD_HANDLE => {
                syscalls::k32_get_std_handle(
                    ctx,
                    self.shared.stdin_handle,
                    self.shared.stdout_handle,
                    self.shared.stderr_handle,
                );
                // GetStdHandle returns the handle in rax (already set by the handler),
                // not an NTSTATUS. Don't overwrite rax in the caller.
                return (NtStatus::STATUS_SUCCESS, false);
            }
            stub_dlls::K32_WRITE_CONSOLE_A => {
                let status = syscalls::k32_write_console_a(ctx, &self.shared.handles.lock());
                return (status, false);
            }
            stub_dlls::K32_WRITE_CONSOLE_W => {
                let status = syscalls::k32_write_console_w(ctx, &self.shared.handles.lock());
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
                // GetCommandLineA ΓÇö return pointer to the ANSI command line
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
                // NULL ΓåÆ image base of the main executable.
                // Non-null ΓåÆ case-insensitive lookup in loaded modules.
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
                    let name = read_wide_string_checked(
                        &self.shared.process_state.pm,
                        module_name_va,
                        state.guest_va_start,
                        state.guest_va_end,
                        MAX_WIDE_STRING_CHARS,
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
                        // Unterminated or invalid pointer ΓÇö return NULL.
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
                let status = syscalls::heap::k32_heap_alloc(ctx, &self.shared.process_state.pm);
                return (status, false);
            }
            stub_dlls::K32_HEAP_FREE => {
                let status = syscalls::heap::k32_heap_free(ctx, &self.shared.process_state.pm);
                return (status, false);
            }
            stub_dlls::K32_HEAP_REALLOC => {
                let status = syscalls::heap::k32_heap_realloc(ctx, &self.shared.process_state.pm);
                return (status, false);
            }
            stub_dlls::K32_HEAP_SIZE => {
                let status = syscalls::heap::k32_heap_size(ctx);
                return (status, false);
            }
            // --- Phase 2: VirtualAlloc/Free/Protect/Query ---
            stub_dlls::K32_VIRTUAL_ALLOC => {
                let status =
                    syscalls::k32_handlers::k32_virtual_alloc(ctx, &self.shared.process_state);
                return (status, false);
            }
            stub_dlls::K32_VIRTUAL_FREE => {
                let status =
                    syscalls::k32_handlers::k32_virtual_free(ctx, &self.shared.process_state);
                return (status, false);
            }
            stub_dlls::K32_VIRTUAL_PROTECT => {
                let status =
                    syscalls::k32_handlers::k32_virtual_protect(ctx, &self.shared.process_state.pm);
                return (status, false);
            }
            stub_dlls::K32_VIRTUAL_QUERY => {
                let status =
                    syscalls::k32_handlers::k32_virtual_query(ctx, &self.shared.process_state.pm);
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
                    &mut self.shared.tls_next.lock(),
                    &mut self.shared.tls_free_list.lock(),
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
                let status = syscalls::k32_handlers::k32_tls_set_value(
                    ctx,
                    teb_va,
                    &self.shared.process_state,
                );
                return (status, false);
            }
            stub_dlls::K32_TLS_FREE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let tls_next = *self.shared.tls_next.lock();
                let status = syscalls::k32_handlers::k32_tls_free(
                    ctx,
                    tls_next,
                    &mut self.shared.tls_free_list.lock(),
                    teb_va,
                );
                return (status, false);
            }
            // --- Phase 2: FLS ---
            stub_dlls::K32_FLS_ALLOC => {
                let status = syscalls::k32_handlers::k32_fls_alloc(
                    ctx,
                    &mut self.shared.fls_next.lock(),
                    &mut self.shared.fls_free_list.lock(),
                );
                return (status, false);
            }
            stub_dlls::K32_FLS_GET_VALUE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status =
                    syscalls::k32_handlers::k32_fls_get_value(ctx, &self.fls_slots.lock(), teb_va);
                return (status, false);
            }
            stub_dlls::K32_FLS_SET_VALUE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_fls_set_value(
                    ctx,
                    &mut self.fls_slots.lock(),
                    teb_va,
                );
                return (status, false);
            }
            stub_dlls::K32_FLS_FREE => {
                let fls_next = *self.shared.fls_next.lock();
                let status = syscalls::k32_handlers::k32_fls_free(
                    ctx,
                    fls_next,
                    &mut self.shared.fls_free_list.lock(),
                    &mut self.fls_slots.lock(),
                );
                return (status, false);
            }
            // --- Phase 2: Exception handling ---
            stub_dlls::K32_SET_UNHANDLED_EXCEPTION_FILTER => {
                let status = syscalls::k32_handlers::k32_set_unhandled_exception_filter(
                    ctx,
                    &mut self.shared.unhandled_exception_filter.lock(),
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
                    &self.shared.env_vars.lock(),
                    &self.shared.process_state,
                    &self.shared.env_block_pool,
                );
                return (status, false);
            }
            stub_dlls::K32_GET_ENVIRONMENT_VARIABLE_W => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_get_environment_variable_w(
                    ctx,
                    &self.shared.env_vars.lock(),
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
                let cwd = self.shared.current_directory.lock();
                let status = syscalls::k32_handlers::k32_create_file_w(
                    ctx,
                    &mut self.shared.handles.lock(),
                    teb_va,
                    &cwd,
                    &self.shared,
                );
                return (status, false);
            }
            stub_dlls::K32_READ_FILE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let h_file = args.arg0 as u32;

                // Snapshot handle info under lock, then drop lock before I/O
                // so that potentially blocking reads (UNC, pipes) don't stall
                // the global handle table.
                enum ReadTarget {
                    VfsFile {
                        raw_fd: usize,
                        position: alloc::sync::Arc<core::sync::atomic::AtomicU64>,
                    },
                    Console,
                }
                let target = {
                    let handles = self.shared.handles.lock();
                    match handles.get(h_file) {
                        Some(crate::handle_table::NtObject::File {
                            raw_fd, position, ..
                        }) => ReadTarget::VfsFile {
                            raw_fd: *raw_fd,
                            position: position.clone(),
                        },
                        Some(crate::handle_table::NtObject::ConsoleInput) => ReadTarget::Console,
                        _ => {
                            syscalls::k32_handlers::set_guest_last_error(teb_va, 6);
                            ctx.regs.rax = 0;
                            return (NtStatus::STATUS_SUCCESS, false);
                        }
                    }
                };
                // Handle lock dropped.
                let status = match target {
                    ReadTarget::VfsFile { raw_fd, position } => {
                        syscalls::k32_handlers::k32_read_file_vfs(
                            ctx,
                            raw_fd,
                            &position,
                            teb_va,
                            &self.shared,
                        )
                    }
                    ReadTarget::Console => syscalls::k32_handlers::k32_read_file_console(
                        ctx,
                        teb_va,
                        &self.shared.console_input_pending,
                    ),
                };
                return (status, false);
            }
            stub_dlls::K32_WRITE_FILE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let h_file = args.arg0 as u32;

                // Snapshot handle info under lock, drop before I/O.
                enum WriteTarget {
                    Console {
                        is_stderr: bool,
                    },
                    VfsFile {
                        raw_fd: usize,
                        position: alloc::sync::Arc<core::sync::atomic::AtomicU64>,
                    },
                }
                let target = {
                    let handles = self.shared.handles.lock();
                    match handles.get(h_file) {
                        Some(crate::handle_table::NtObject::ConsoleOutput { is_stderr }) => {
                            WriteTarget::Console {
                                is_stderr: *is_stderr,
                            }
                        }
                        Some(crate::handle_table::NtObject::File {
                            raw_fd, position, ..
                        }) => WriteTarget::VfsFile {
                            raw_fd: *raw_fd,
                            position: position.clone(),
                        },
                        _ => {
                            syscalls::k32_handlers::set_guest_last_error(teb_va, 6);
                            ctx.regs.rax = 0;
                            return (NtStatus::STATUS_SUCCESS, false);
                        }
                    }
                };
                let status = match target {
                    WriteTarget::Console { is_stderr: _ } => {
                        syscalls::k32_handlers::k32_write_file_console(ctx)
                    }
                    WriteTarget::VfsFile { raw_fd, position } => {
                        syscalls::k32_handlers::k32_write_file_vfs(
                            ctx,
                            raw_fd,
                            &position,
                            teb_va,
                            &self.shared,
                        )
                    }
                };
                return (status, false);
            }
            stub_dlls::K32_CLOSE_HANDLE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_close_handle(
                    ctx,
                    &mut self.shared.handles.lock(),
                    teb_va,
                    &self.shared,
                );
                return (status, false);
            }
            stub_dlls::K32_GET_FILE_TYPE => {
                let status =
                    syscalls::k32_handlers::k32_get_file_type(ctx, &self.shared.handles.lock());
                return (status, false);
            }
            stub_dlls::K32_GET_FILE_SIZE_EX => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_get_file_size_ex(
                    ctx,
                    &self.shared.handles.lock(),
                    teb_va,
                    &self.shared,
                );
                return (status, false);
            }
            stub_dlls::K32_SET_FILE_POINTER_EX => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_set_file_pointer_ex(
                    ctx,
                    &mut self.shared.handles.lock(),
                    teb_va,
                    &self.shared,
                );
                return (status, false);
            }
            stub_dlls::K32_SET_END_OF_FILE => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_set_end_of_file(
                    ctx,
                    &mut self.shared.handles.lock(),
                    teb_va,
                    &self.shared,
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
            stub_dlls::K32_READ_CONSOLE_W => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let handle = ctx.regs.r10 as u32;
                let is_console_input = matches!(
                    self.shared.handles.lock().get(handle),
                    Some(crate::handle_table::NtObject::ConsoleInput)
                );
                let status = if is_console_input {
                    syscalls::k32_handlers::k32_read_console_w(
                        ctx,
                        is_console_input,
                        teb_va,
                        &self.shared.console_input_pending,
                    )
                } else {
                    syscalls::k32_handlers::set_guest_last_error(teb_va, 6);
                    ctx.regs.rax = 0;
                    NtStatus::STATUS_SUCCESS
                };
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
                let cwd = self.shared.current_directory.lock();
                let status = syscalls::k32_handlers::k32_get_full_path_name_w(ctx, &cwd);
                return (status, false);
            }
            stub_dlls::K32_GET_TEMP_PATH_W => {
                let status = syscalls::k32_handlers::k32_get_temp_path_w(ctx);
                return (status, false);
            }
            stub_dlls::K32_GET_CURRENT_DIRECTORY_W => {
                let cwd = self.shared.current_directory.lock();
                let status = syscalls::k32_handlers::k32_get_current_directory_w(ctx, &cwd);
                return (status, false);
            }
            stub_dlls::K32_SET_CURRENT_DIRECTORY_W => {
                let mut cwd = self.shared.current_directory.lock();
                let status = syscalls::k32_handlers::k32_set_current_directory_w(
                    ctx,
                    &mut cwd,
                    &self.shared,
                );
                return (status, false);
            }

            // --- Handle duplication ---
            stub_dlls::K32_DUPLICATE_HANDLE => {
                let status = syscalls::k32_handlers::k32_duplicate_handle(
                    ctx,
                    &mut self.shared.handles.lock(),
                );
                return (status, false);
            }

            // --- Environment (additional) ---
            stub_dlls::K32_SET_ENVIRONMENT_VARIABLE_W => {
                let status = syscalls::k32_handlers::k32_set_environment_variable_w(
                    ctx,
                    &mut self.shared.env_vars.lock(),
                );
                return (status, false);
            }
            stub_dlls::K32_FREE_ENVIRONMENT_STRINGS_W => {
                let status = syscalls::k32_handlers::k32_free_environment_strings_w(
                    ctx,
                    &self.shared.process_state,
                    &self.shared.env_block_pool,
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
                let cwd = self.shared.current_directory.lock();
                let status = syscalls::k32_handlers::k32_find_first_file_ex_w(
                    ctx,
                    &mut self.shared.handles.lock(),
                    teb_va,
                    &cwd,
                    &self.shared,
                );
                return (status, false);
            }
            stub_dlls::K32_FIND_NEXT_FILE_W => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                let status = syscalls::k32_handlers::k32_find_next_file_w(
                    ctx,
                    &mut self.shared.handles.lock(),
                    teb_va,
                );
                return (status, false);
            }
            stub_dlls::K32_FIND_CLOSE => {
                let status = syscalls::k32_handlers::k32_find_close(
                    ctx,
                    &mut self.shared.handles.lock(),
                    &self.shared,
                );
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
                    .map_or(&[][..], |s| s.module_bases.as_slice());
                let status = syscalls::k32_handlers::k32_rtl_lookup_function_entry(ctx, mods);
                return (status, false);
            }
            stub_dlls::K32_RTL_VIRTUAL_UNWIND => {
                let mods = self
                    .init_state
                    .as_ref()
                    .map_or(&[][..], |s| s.module_bases.as_slice());
                let status = syscalls::k32_handlers::k32_rtl_virtual_unwind(ctx, mods);
                return (status, false);
            }
            stub_dlls::K32_RTL_UNWIND_EX => {
                let mods = self
                    .init_state
                    .as_ref()
                    .map_or(&[][..], |s| s.module_bases.as_slice());
                let status = syscalls::k32_handlers::k32_rtl_unwind_ex(ctx, mods);
                return (status, false);
            }
            stub_dlls::K32_RTL_PC_TO_FILE_HEADER => {
                let mods = self
                    .init_state
                    .as_ref()
                    .map_or(&[][..], |s| s.module_bases.as_slice());
                let status = syscalls::k32_handlers::k32_rtl_pc_to_file_header(ctx, mods);
                return (status, false);
            }
            // --- Phase 3B: Sleep ---
            stub_dlls::K32_SLEEP => {
                let status = syscalls::k32_handlers::k32_sleep(ctx, &self.wait_cx());
                return (status, false);
            }
            stub_dlls::K32_SLEEP_EX => {
                let status = syscalls::k32_handlers::k32_sleep_ex(ctx, &self.wait_cx());
                return (status, false);
            }
            // --- Phase 3B: Critical sections ---
            stub_dlls::K32_INIT_CRITICAL_SECTION => {
                let status = syscalls::k32_handlers::k32_init_critical_section(ctx);
                return (status, false);
            }
            stub_dlls::K32_INIT_CRITICAL_SECTION_EX => {
                let status = syscalls::k32_handlers::k32_init_critical_section_ex(ctx);
                return (status, false);
            }
            stub_dlls::K32_INIT_CRITICAL_SECTION_AND_SPIN_COUNT => {
                let status = syscalls::k32_handlers::k32_init_critical_section_and_spin_count(ctx);
                return (status, false);
            }
            stub_dlls::K32_ENTER_CRITICAL_SECTION => {
                let status =
                    syscalls::k32_handlers::k32_enter_critical_section(ctx, self.thread_id);
                return (status, false);
            }
            stub_dlls::K32_TRY_ENTER_CRITICAL_SECTION => {
                let status =
                    syscalls::k32_handlers::k32_try_enter_critical_section(ctx, self.thread_id);
                return (status, false);
            }
            stub_dlls::K32_LEAVE_CRITICAL_SECTION => {
                let status =
                    syscalls::k32_handlers::k32_leave_critical_section(ctx, self.thread_id);
                return (status, false);
            }
            stub_dlls::K32_DELETE_CRITICAL_SECTION => {
                let status = syscalls::k32_handlers::k32_delete_critical_section(ctx);
                return (status, false);
            }
            // --- Phase 3B: Wait APIs ---
            stub_dlls::K32_WAIT_FOR_SINGLE_OBJECT | stub_dlls::K32_WAIT_FOR_SINGLE_OBJECT_EX => {
                // WaitForSingleObject(hHandle, dwMilliseconds)
                // WaitForSingleObjectEx(hHandle, dwMilliseconds, bAlertable)
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let handle = args.arg0 as u32;
                let millis = args.arg1 as u32;
                let waitable = {
                    let handles = self.shared.handles.lock();
                    syscalls::sync::lookup_waitable(&handles, handle)
                };
                let timeout = if millis == 0xFFFF_FFFF {
                    None // INFINITE
                } else {
                    Some(core::time::Duration::from_millis(u64::from(millis)))
                };
                let status = match waitable {
                    Some(w) => match &w {
                        syscalls::sync::Waitable::Event(e) => {
                            syscalls::sync::wait_event_with_timeout(e, timeout, &self.wait_cx())
                        }
                        syscalls::sync::Waitable::Semaphore(s) => {
                            syscalls::sync::wait_semaphore_with_timeout(s, timeout, &self.wait_cx())
                        }
                        syscalls::sync::Waitable::Thread(t) => {
                            syscalls::sync::wait_thread_with_timeout(t, timeout, &self.wait_cx())
                        }
                    },
                    None => NtStatus::STATUS_INVALID_HANDLE,
                };
                // Return value in rax: WAIT_OBJECT_0 (0) on success, WAIT_TIMEOUT (258)
                ctx.regs.rax = match status {
                    NtStatus::STATUS_SUCCESS => 0,     // WAIT_OBJECT_0
                    NtStatus::STATUS_TIMEOUT => 0x102, // WAIT_TIMEOUT
                    _ => 0xFFFF_FFFF,                  // WAIT_FAILED
                };
                return (NtStatus::STATUS_SUCCESS, false);
            }
            // --- Thread identity ---
            stub_dlls::K32_GET_CURRENT_THREAD_ID => {
                ctx.regs.rax = self.thread_id as usize;
                return (NtStatus::STATUS_SUCCESS, false);
            }
            // --- Registry stubs ---
            stub_dlls::K32_REG_OPEN_KEY_EX_W => {
                // RegOpenKeyExW / RegOpenKeyExA ΓÇö always return ERROR_FILE_NOT_FOUND.
                // In a sandbox, no registry keys exist.
                ctx.regs.rax = 2; // ERROR_FILE_NOT_FOUND
                return (NtStatus::STATUS_SUCCESS, false);
            }
            stub_dlls::K32_REG_QUERY_VALUE_EX_W => {
                ctx.regs.rax = 2; // ERROR_FILE_NOT_FOUND
                return (NtStatus::STATUS_SUCCESS, false);
            }
            stub_dlls::K32_REG_CLOSE_KEY => {
                // RegCloseKey ΓÇö always succeeds (nothing to close).
                ctx.regs.rax = 0; // ERROR_SUCCESS
                return (NtStatus::STATUS_SUCCESS, false);
            }

            // --- WinSock (ws2_32) syscalls ---
            nr if nr >= stub_dlls::WS2_STARTUP => {
                let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                return syscalls::net::dispatch_ws2_syscall(&self.shared, nr, ctx, teb_va);
            }

            _ => {}
        }

        // Look up the name from unhandled_stubs if available.
        let name = self.shared.unhandled_stubs.get().and_then(|stubs| {
            stubs
                .iter()
                .find(|(n, _)| *n == nr)
                .map(|(_, s)| s.as_str())
        });
        if let Some(name) = name {
            log_unimplemented!("unknown syscall nr=0x{:04X} ({})", nr, name);
        } else {
            log_unimplemented!("unknown syscall nr=0x{:04X}", nr);
        }
        (NtStatus::STATUS_NOT_IMPLEMENTED, false)
    }

    /// Dispatch an NT-specific syscall (from ntdll stubs).
    ///
    /// The rewriter trampoline pops the return address into RCX before
    /// entering `syscall_callback`, so `ctx.regs.rsp` is 8 bytes higher
    /// than in the stub-DLL path (where the return address stays on stack).
    /// We temporarily subtract 8 from RSP so that all stack-arg offsets
    /// (+0x28 = arg5, +0x30 = arg6, etc.) work identically to the stub path.
    fn dispatch_nt_syscall(
        &self,
        nt_nr: NtSyscallId,
        raw_nr: u32,
        ctx: &mut ExecutionContext,
    ) -> (NtStatus, bool) {
        // Normalize RSP: the rewriter trampoline pops the return address,
        // so RSP is 8 higher than it would be with a real `syscall` instruction
        // or with the stub-DLL path.  Subtract 8 so stack arg offsets match.
        ctx.regs.rsp = ctx.regs.rsp.wrapping_sub(8);

        let result = self.dispatch_nt_syscall_inner(nt_nr, raw_nr, ctx);

        #[cfg(debug_assertions)]
        {
            // Log return status for non-SUCCESS results to aid debugging.
            let status = result.0;
            if status != NtStatus::STATUS_SUCCESS {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "NT shim: {:?} returned 0x{:08X}\n",
                    nt_nr,
                    status.0 as u32,
                ));
            }
        }

        // Restore RSP so sysret resumes the guest correctly.
        ctx.regs.rsp = ctx.regs.rsp.wrapping_add(8);

        result
    }

    /// Inner dispatch after RSP normalization.
    fn dispatch_nt_syscall_inner(
        &self,
        nt_nr: NtSyscallId,
        raw_nr: u32,
        ctx: &mut ExecutionContext,
    ) -> (NtStatus, bool) {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: {:?} (nr=0x{:04X}) r10=0x{:X} rdx=0x{:X} r8=0x{:X}\n",
                nt_nr,
                raw_nr,
                ctx.regs.r10,
                ctx.regs.rdx,
                ctx.regs.r8,
            ));
        }
        match nt_nr {
            NtSyscallId::NtTerminateProcess => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let handle = args.arg0;
                let exit_status = args.arg1 as i32;

                if handle == NT_CURRENT_PROCESS_HANDLE || handle == 0 {
                    self.exit_code.store(exit_status, Ordering::Release);
                    // Mark this thread as exited too.
                    if let Some(ref obj) = self.thread_obj {
                        obj.set_exited(exit_status);
                    }
                    (NtStatus::STATUS_SUCCESS, true)
                } else {
                    log_unimplemented!("NtTerminateProcess on remote handle 0x{:X}", handle);
                    (NtStatus::STATUS_NOT_IMPLEMENTED, false)
                }
            }
            NtSyscallId::NtWriteFile => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let file_handle = args.arg0 as u32;

                // Snapshot handle info under lock, drop before I/O.
                enum NtWriteTarget {
                    Console {
                        is_stderr: bool,
                    },
                    VfsFile {
                        raw_fd: usize,
                        position: alloc::sync::Arc<core::sync::atomic::AtomicU64>,
                    },
                    Invalid,
                }
                let target = {
                    let handles = self.shared.handles.lock();
                    match handles.get(file_handle) {
                        Some(crate::handle_table::NtObject::ConsoleOutput { is_stderr }) => {
                            NtWriteTarget::Console {
                                is_stderr: *is_stderr,
                            }
                        }
                        Some(crate::handle_table::NtObject::File {
                            raw_fd, position, ..
                        }) => NtWriteTarget::VfsFile {
                            raw_fd: *raw_fd,
                            position: position.clone(),
                        },
                        _ => NtWriteTarget::Invalid,
                    }
                };
                let status = match target {
                    NtWriteTarget::Console { is_stderr } => {
                        syscalls::file::nt_write_file_console(ctx, is_stderr)
                    }
                    NtWriteTarget::VfsFile { raw_fd, position } => {
                        syscalls::file::nt_write_file_vfs(ctx, raw_fd, &position, &self.shared)
                    }
                    NtWriteTarget::Invalid => NtStatus::STATUS_INVALID_HANDLE,
                };
                (status, false)
            }
            NtSyscallId::NtClose => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let status = syscalls::nt_close(
                    &mut self.shared.handles.lock(),
                    args.arg0 as u32,
                    &self.shared,
                );
                (status, false)
            }
            // Phase 2: File I/O
            NtSyscallId::NtCreateFile => {
                let status = syscalls::file::nt_create_file(
                    ctx,
                    &mut self.shared.handles.lock(),
                    &self.shared,
                );
                (status, false)
            }
            NtSyscallId::NtOpenFile => {
                let status = syscalls::file::nt_open_file(
                    ctx,
                    &mut self.shared.handles.lock(),
                    &self.shared,
                );
                (status, false)
            }
            NtSyscallId::NtReadFile => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let file_handle = args.arg0 as u32;

                // Snapshot handle info under lock, drop before I/O.
                enum NtReadTarget {
                    VfsFile {
                        raw_fd: usize,
                        position: alloc::sync::Arc<core::sync::atomic::AtomicU64>,
                    },
                    Console,
                    Invalid,
                }
                let target = {
                    let handles = self.shared.handles.lock();
                    match handles.get(file_handle) {
                        Some(crate::handle_table::NtObject::File {
                            raw_fd, position, ..
                        }) => NtReadTarget::VfsFile {
                            raw_fd: *raw_fd,
                            position: position.clone(),
                        },
                        Some(crate::handle_table::NtObject::ConsoleInput) => NtReadTarget::Console,
                        _ => NtReadTarget::Invalid,
                    }
                };
                let status = match target {
                    NtReadTarget::VfsFile { raw_fd, position } => {
                        syscalls::file::nt_read_file_vfs(ctx, raw_fd, &position, &self.shared)
                    }
                    NtReadTarget::Console => syscalls::file::nt_read_file_console(ctx),
                    NtReadTarget::Invalid => NtStatus::STATUS_INVALID_HANDLE,
                };
                (status, false)
            }
            NtSyscallId::NtQueryInformationFile => {
                let status = syscalls::file::nt_query_information_file(
                    ctx,
                    &self.shared.handles.lock(),
                    &self.shared,
                );
                (status, false)
            }
            NtSyscallId::NtSetInformationFile => {
                let status =
                    syscalls::file::nt_set_information_file(ctx, &mut self.shared.handles.lock());
                (status, false)
            }
            NtSyscallId::NtQueryAttributesFile => {
                let status = syscalls::file::nt_query_attributes_file(ctx, &self.shared);
                (status, false)
            }
            // Phase 2: Memory management
            NtSyscallId::NtAllocateVirtualMemory => {
                let status =
                    syscalls::memory::nt_allocate_virtual_memory(ctx, &self.shared.process_state);
                (status, false)
            }
            NtSyscallId::NtAllocateVirtualMemoryEx => {
                let status = syscalls::memory::nt_allocate_virtual_memory_ex(
                    ctx,
                    &self.shared.process_state,
                );
                (status, false)
            }
            NtSyscallId::NtFreeVirtualMemory => {
                let status =
                    syscalls::memory::nt_free_virtual_memory(ctx, &self.shared.process_state);
                (status, false)
            }
            NtSyscallId::NtProtectVirtualMemory => {
                let status =
                    syscalls::memory::nt_protect_virtual_memory(ctx, &self.shared.process_state.pm);
                (status, false)
            }
            NtSyscallId::NtQueryVirtualMemory => {
                let module_bases = self
                    .init_state
                    .as_ref()
                    .map_or(&[][..], |s| s.module_bases.as_slice());
                let status = syscalls::memory::nt_query_virtual_memory(
                    ctx,
                    &self.shared.process_state,
                    module_bases,
                );
                (status, false)
            }
            // Phase 2: System information & time
            NtSyscallId::NtQuerySystemInformation => {
                let status = syscalls::sysinfo::nt_query_system_information(ctx);
                (status, false)
            }
            NtSyscallId::NtQuerySystemInformationEx => {
                let status = syscalls::sysinfo::nt_query_system_information_ex(ctx);
                (status, false)
            }
            NtSyscallId::NtQueryPerformanceCounter => {
                let status = syscalls::sysinfo::nt_query_performance_counter(ctx);
                (status, false)
            }
            NtSyscallId::NtQuerySystemTime => {
                let status = syscalls::sysinfo::nt_query_system_time(ctx);
                (status, false)
            }
            NtSyscallId::NtQueryInformationProcess => {
                let status =
                    syscalls::sysinfo::nt_query_information_process(ctx, self.init_state.as_ref());
                (status, false)
            }
            NtSyscallId::NtDelayExecution => {
                let status = syscalls::sysinfo::nt_delay_execution(ctx, &self.wait_cx());
                (status, false)
            }
            NtSyscallId::NtSetInformationThread => {
                // Commonly called for thread name, affinity, etc.
                // Return success for now ΓÇö most info classes are optional.
                (NtStatus::STATUS_SUCCESS, false)
            }
            NtSyscallId::NtQueryVolumeInformationFile => {
                // Stub: return basic volume information.
                let status = syscalls::file::nt_query_volume_information_file(ctx);
                (status, false)
            }
            NtSyscallId::NtQueryDirectoryFile => {
                let status = syscalls::file::nt_query_directory_file(
                    ctx,
                    &mut self.shared.handles.lock(),
                    &self.shared,
                );
                (status, false)
            }
            // Phase 3: Sync primitives
            NtSyscallId::NtCreateKeyedEvent => {
                let status =
                    syscalls::sync::nt_create_keyed_event(ctx, &mut self.shared.handles.lock());
                (status, false)
            }
            NtSyscallId::NtWaitForKeyedEvent => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let keyed = {
                    let handles = self.shared.handles.lock();
                    syscalls::sync::lookup_keyed_event(&handles, args.arg0 as u32)
                };
                match keyed {
                    Some(k) => (
                        syscalls::sync::wait_for_keyed_event(ctx, &k, &self.wait_cx()),
                        false,
                    ),
                    None => (NtStatus::STATUS_INVALID_HANDLE, false),
                }
            }
            NtSyscallId::NtReleaseKeyedEvent => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let keyed = {
                    let handles = self.shared.handles.lock();
                    syscalls::sync::lookup_keyed_event(&handles, args.arg0 as u32)
                };
                match keyed {
                    Some(k) => (
                        syscalls::sync::release_keyed_event(ctx, &k, &self.wait_cx()),
                        false,
                    ),
                    None => (NtStatus::STATUS_INVALID_HANDLE, false),
                }
            }
            NtSyscallId::NtCreateEvent => {
                let status = syscalls::sync::nt_create_event(ctx, &mut self.shared.handles.lock());
                (status, false)
            }
            NtSyscallId::NtSetEvent => {
                let status = syscalls::sync::nt_set_event(ctx, &self.shared.handles.lock());
                (status, false)
            }
            NtSyscallId::NtResetEvent => {
                let status = syscalls::sync::nt_reset_event(ctx, &self.shared.handles.lock());
                (status, false)
            }
            NtSyscallId::NtClearEvent => {
                let status = syscalls::sync::nt_clear_event(ctx, &self.shared.handles.lock());
                (status, false)
            }
            NtSyscallId::NtCreateSemaphore => {
                let status =
                    syscalls::sync::nt_create_semaphore(ctx, &mut self.shared.handles.lock());
                (status, false)
            }
            NtSyscallId::NtReleaseSemaphore => {
                let status = syscalls::sync::nt_release_semaphore(ctx, &self.shared.handles.lock());
                (status, false)
            }
            NtSyscallId::NtWaitForSingleObject => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let waitable = {
                    let handles = self.shared.handles.lock();
                    syscalls::sync::lookup_waitable(&handles, args.arg0 as u32)
                };
                match waitable {
                    Some(w) => (syscalls::sync::wait_single(ctx, &w, &self.wait_cx()), false),
                    None => (NtStatus::STATUS_INVALID_HANDLE, false),
                }
            }
            NtSyscallId::NtWaitForMultipleObjects => {
                let status = syscalls::sync::nt_wait_for_multiple_objects(
                    ctx,
                    &self.shared.handles,
                    &self.wait_cx(),
                );
                (status, false)
            }
            NtSyscallId::NtDuplicateObject => {
                // NtDuplicateObject(SourceProcess, SourceHandle, TargetProcess,
                //                   TargetHandle*, DesiredAccess, Attributes, Options)
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let source_handle = args.arg1 as u32;
                let target_handle_va = args.arg3;
                let mut handles = self.shared.handles.lock();

                // Handle pseudo-handles: -1 = current process, -2 = current thread.
                let new_obj = if source_handle == 0xFFFFFFFF {
                    Some(handle_table::NtObject::CurrentProcess)
                } else if source_handle == 0xFFFFFFFE {
                    Some(handle_table::NtObject::CurrentThread)
                } else {
                    None
                };

                let result = if let Some(obj) = new_obj {
                    let h = handles.insert(obj);
                    Some(h)
                } else {
                    handles.duplicate(source_handle)
                };

                if let Some(new_handle) = result {
                    if target_handle_va != 0 {
                        unsafe {
                            core::ptr::write(target_handle_va as *mut u32, new_handle);
                        }
                    }
                    (NtStatus::STATUS_SUCCESS, false)
                } else {
                    (NtStatus::STATUS_INVALID_HANDLE, false)
                }
            }
            NtSyscallId::NtCreateThreadEx => {
                let status = syscalls::thread::nt_create_thread_ex(ctx, self);
                (status, false)
            }
            NtSyscallId::NtTerminateThread => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let handle = args.arg0 as u32;
                let exit_code = args.arg1 as i32;

                // -2 (0xFFFFFFFE) = NtCurrentThread pseudo-handle.
                let is_current = handle == 0xFFFFFFFE || handle as i32 == -2;
                if is_current {
                    self.exit_code.store(exit_code, Ordering::Release);
                    if let Some(ref obj) = self.thread_obj {
                        obj.set_exited(exit_code);
                    }
                    return (NtStatus::STATUS_SUCCESS, true);
                }

                // Look up the handle and validate it's a thread object.
                let handles = self.shared.handles.lock();
                match handles.get(handle) {
                    Some(handle_table::NtObject::Thread(t)) => {
                        if t.thread_id == self.thread_id {
                            // Handle resolves to our own thread.
                            drop(handles);
                            self.exit_code.store(exit_code, Ordering::Release);
                            if let Some(ref obj) = self.thread_obj {
                                obj.set_exited(exit_code);
                            }
                            (NtStatus::STATUS_SUCCESS, true)
                        } else {
                            log_unimplemented!(
                                "NtTerminateThread: cross-thread termination (handle=0x{:X})",
                                handle
                            );
                            (NtStatus::STATUS_NOT_IMPLEMENTED, false)
                        }
                    }
                    Some(_) => {
                        // Handle exists but is not a thread object.
                        (NtStatus::STATUS_OBJECT_TYPE_MISMATCH, false)
                    }
                    None => (NtStatus::STATUS_INVALID_HANDLE, false),
                }
            }
            // --- Registry stubs (NT level) ---
            NtSyscallId::NtOpenKey | NtSyscallId::NtOpenKeyEx => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let key_handle_ptr = args.arg0; // PHANDLE
                let _desired_access = args.arg1 as u32;
                let obj_attrs_ptr = args.arg2; // POBJECT_ATTRIBUTES

                // Read the key name from OBJECT_ATTRIBUTES.ObjectName
                let key_name = if obj_attrs_ptr != 0 {
                    // OBJECT_ATTRIBUTES layout (x64):
                    //   +0x00: ULONG Length
                    //   +0x08: HANDLE RootDirectory
                    //   +0x10: PUNICODE_STRING ObjectName
                    //   +0x18: ULONG Attributes
                    //   +0x20: PVOID SecurityDescriptor
                    //   +0x28: PVOID SecurityQualityOfService
                    let name_ptr =
                        unsafe { core::ptr::read_unaligned((obj_attrs_ptr + 0x10) as *const u64) };
                    if name_ptr != 0 {
                        // UNICODE_STRING: Length (u16) + MaxLength (u16) + Buffer (ptr)
                        let len =
                            unsafe { core::ptr::read_unaligned(name_ptr as *const u16) } as usize;
                        let buf =
                            unsafe { core::ptr::read_unaligned((name_ptr + 8) as *const u64) };
                        if buf != 0 && len > 0 {
                            let wchars =
                                unsafe { core::slice::from_raw_parts(buf as *const u16, len / 2) };
                            alloc::string::String::from_utf16_lossy(wchars)
                        } else {
                            alloc::string::String::from("<empty>")
                        }
                    } else {
                        alloc::string::String::from("<null>")
                    }
                } else {
                    alloc::string::String::from("<no-attrs>")
                };

                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    let msg = alloc::format!("NT shim: NtOpenKey(name={key_name:?})\n");
                    litebox_platform_multiplex::platform().debug_log_print(&msg);
                }

                // For critical Session Manager keys, return a dummy handle
                // so ntdll's init can proceed. NtQueryValueKey will return
                // NOT_FOUND for individual values.
                // Exclude "Segment Heap" ΓÇö we don't support segment heap,
                // and returning NOT_FOUND here forces ntdll to use the
                // traditional NT heap (RtlCreateHeap).
                let key_lower = key_name.to_ascii_lowercase();
                let is_critical_key = (key_lower.contains("session manager")
                    || key_lower.contains("knowndlls")
                    || key_lower.contains("nls")
                    || key_lower.contains("muilanguages")
                    || key_lower.contains("currentversion")
                    || key_lower.contains("\\registry\\user\\")
                    || key_lower.contains("control panel"))
                    && !key_lower.contains("segment heap");
                if is_critical_key {
                    // Dump PEB NLS fields for debugging
                    #[cfg(debug_assertions)]
                    if key_lower.contains("control panel")
                        && let Some(init) = self.init_state.as_ref()
                    {
                        let peb = init.peb_va;
                        use litebox::platform::DebugLogProvider as _;
                        let acp_id =
                            unsafe { core::ptr::read_unaligned((peb + 0x34C) as *const u16) };
                        let oemcp_id =
                            unsafe { core::ptr::read_unaligned((peb + 0x34E) as *const u16) };
                        let ansi_data =
                            unsafe { core::ptr::read_unaligned((peb + 0x350) as *const u64) };
                        let oem_data =
                            unsafe { core::ptr::read_unaligned((peb + 0x358) as *const u64) };
                        let case_data =
                            unsafe { core::ptr::read_unaligned((peb + 0x360) as *const u64) };
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: PEB NLS fields:\n  \
                                     ACP=0x{acp_id:X} OEMCP=0x{oemcp_id:X}\n  \
                                     AnsiCodePageData=0x{ansi_data:X}\n  \
                                     OemCodePageData=0x{oem_data:X}\n  \
                                     UnicodeCaseTableData=0x{case_data:X}\n",
                        ));
                        // If AnsiCodePageData is set, dump first 16 bytes
                        if ansi_data != 0 {
                            let bytes: [u8; 16] =
                                unsafe { core::ptr::read_unaligned(ansi_data as *const [u8; 16]) };
                            litebox_platform_multiplex::platform().debug_log_print(
                                &alloc::format!(
                                    "  AnsiCodePageData first 16 bytes: {bytes:02X?}\n"
                                ),
                            );
                        }
                    }
                    // Create a dummy registry key handle.
                    let handle_val = self
                        .shared
                        .handles
                        .lock()
                        .insert(handle_table::NtObject::RegistryKey);
                    if key_handle_ptr != 0 {
                        unsafe {
                            core::ptr::write(key_handle_ptr as *mut u32, handle_val);
                        }
                    }
                    (NtStatus::STATUS_SUCCESS, false)
                } else {
                    (NtStatus::STATUS_OBJECT_NAME_NOT_FOUND, false)
                }
            }
            NtSyscallId::NtEnumerateKey | NtSyscallId::NtEnumerateValueKey => {
                // Our dummy registry keys have no subkeys or values.
                // Return STATUS_NO_MORE_ENTRIES to stop enumeration loops.
                (NtStatus::STATUS_NO_MORE_ENTRIES, false)
            }
            NtSyscallId::NtQueryValueKey => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let _key_handle = args.arg0 as u32;
                let value_name_ptr = args.arg1; // PUNICODE_STRING
                let info_class = args.arg2 as u32;
                let info_ptr = args.arg3;
                let info_length = unsafe { syscalls::NtSyscallArgs::arg4(ctx) } as u32;
                let result_length_ptr = unsafe { syscalls::NtSyscallArgs::arg5(ctx) };

                // Read the value name.
                let value_name = if value_name_ptr != 0 {
                    let len =
                        unsafe { core::ptr::read_unaligned(value_name_ptr as *const u16) } as usize;
                    let buf =
                        unsafe { core::ptr::read_unaligned((value_name_ptr + 8) as *const u64) };
                    if buf != 0 && len > 0 {
                        let wchars =
                            unsafe { core::slice::from_raw_parts(buf as *const u16, len / 2) };
                        alloc::string::String::from_utf16_lossy(wchars)
                    } else {
                        alloc::string::String::new()
                    }
                } else {
                    alloc::string::String::new()
                };

                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    let msg = alloc::format!(
                        "NT shim: NtQueryValueKey(name={value_name:?}, class={info_class})\n"
                    );
                    litebox_platform_multiplex::platform().debug_log_print(&msg);
                }

                // Return hardcoded values for critical NLS registry entries.
                let name_lower = value_name.to_ascii_lowercase();
                let reg_value: Option<&str> = match name_lower.as_str() {
                    "acp" => Some("1252"),    // ANSI Code Page
                    "oemcp" => Some("437"),   // OEM Code Page
                    "maccp" => Some("10000"), // MAC Code Page
                    _ => None,
                };

                if let Some(val_str) = reg_value {
                    // Return as REG_SZ (type 1) in KeyValuePartialInformation.
                    let val_wide: alloc::vec::Vec<u16> = val_str
                        .encode_utf16()
                        .chain(core::iter::once(0u16))
                        .collect();
                    let data_bytes = val_wide.len() * 2;
                    // KEY_VALUE_PARTIAL_INFORMATION: TitleIndex(4) + Type(4) + DataLength(4) + Data
                    let total_size = 12 + data_bytes;

                    if result_length_ptr != 0 {
                        unsafe {
                            core::ptr::write(result_length_ptr as *mut u32, total_size as u32);
                        }
                    }

                    if (info_length as usize) < total_size || info_ptr == 0 {
                        (NtStatus::STATUS_BUFFER_TOO_SMALL, false)
                    } else if info_class == 2 {
                        // KeyValuePartialInformation
                        unsafe {
                            let base = info_ptr as *mut u8;
                            core::ptr::write(base.cast::<u32>(), 0); // TitleIndex
                            core::ptr::write(base.add(4).cast::<u32>(), 1); // Type = REG_SZ
                            core::ptr::write(base.add(8).cast::<u32>(), data_bytes as u32); // DataLength
                            core::ptr::copy_nonoverlapping(
                                val_wide.as_ptr() as *const u8,
                                base.add(12),
                                data_bytes,
                            );
                        }
                        (NtStatus::STATUS_SUCCESS, false)
                    } else {
                        // Other info classes ΓÇö return NOT_IMPLEMENTED for now.
                        (NtStatus::STATUS_NOT_IMPLEMENTED, false)
                    }
                } else {
                    (NtStatus::STATUS_OBJECT_NAME_NOT_FOUND, false)
                }
            }

            // --- NtContinue: restore CONTEXT and resume ---
            NtSyscallId::NtContinue => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let context_ptr = args.arg0; // RCX (saved in R10) = CONTEXT*
                // Read the CONTEXT structure from guest memory and update
                // the execution context registers so the platform resumes
                // at the new RIP/RSP/etc.
                // CONTEXT offsets (x64):
                //   0x44 = EFlags, 0x78 = Rax, 0x80 = Rcx, 0x88 = Rdx,
                //   0x90 = Rbx, 0x98 = Rsp, 0xA0 = Rbp, 0xA8 = Rsi,
                //   0xB0 = Rdi, 0xB8 = R8, 0xC0 = R9, 0xC8 = R10,
                //   0xD0 = R11, 0xD8 = R12, 0xE0 = R13, 0xE8 = R14,
                //   0xF0 = R15, 0xF8 = Rip
                unsafe {
                    let p = context_ptr as *const u8;
                    let r64 = |off: usize| {
                        u64::from_le_bytes(
                            core::slice::from_raw_parts(p.add(off), 8)
                                .try_into()
                                .unwrap(),
                        ) as usize
                    };
                    let r32 = |off: usize| {
                        u32::from_le_bytes(
                            core::slice::from_raw_parts(p.add(off), 4)
                                .try_into()
                                .unwrap(),
                        )
                    };
                    ctx.regs.rip = r64(0xF8);
                    ctx.regs.rsp = r64(0x98);
                    ctx.regs.rax = r64(0x78);
                    ctx.regs.rcx = r64(0x80);
                    ctx.regs.rdx = r64(0x88);
                    ctx.regs.rbx = r64(0x90);
                    ctx.regs.rbp = r64(0xA0);
                    ctx.regs.rsi = r64(0xA8);
                    ctx.regs.rdi = r64(0xB0);
                    ctx.regs.r8 = r64(0xB8);
                    ctx.regs.r9 = r64(0xC0);
                    ctx.regs.r10 = r64(0xC8);
                    ctx.regs.r11 = r64(0xD0);
                    ctx.regs.r12 = r64(0xD8);
                    ctx.regs.r13 = r64(0xE0);
                    ctx.regs.r14 = r64(0xE8);
                    ctx.regs.r15 = r64(0xF0);
                    // Restore EFlags (offset 0x44 in CONTEXT).
                    ctx.eflags = r32(0x44) as usize;
                    // Restore FP/XSAVE state from CONTEXT.FltSave (offset 0x100,
                    // 512-byte FXSAVE area). The platform's slow NtContinue path
                    // copies ctx.fp_regs into the host CONTEXT, so we must
                    // populate it here for the state to carry over.
                    let flt_save_offset = 0x100;
                    let fxsave_size = 512.min(ctx.fp_regs.data.len());
                    core::ptr::copy_nonoverlapping(
                        p.add(flt_save_offset),
                        ctx.fp_regs.data.as_mut_ptr(),
                        fxsave_size,
                    );
                }
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NtContinue: new RIP=0x{:X}, RSP=0x{:X}, RCX=0x{:X}, RDX=0x{:X}\n",
                        ctx.regs.rip,
                        ctx.regs.rsp,
                        ctx.regs.rcx,
                        ctx.regs.rdx
                    ));
                }
                // NtContinue does not return an NTSTATUS ΓÇö it switches context.
                // We return STATUS_SUCCESS but the dispatch loop must NOT
                // overwrite rax (it was already set from the CONTEXT).
                // Leave rcx != rip so the platform uses the slow NtContinue
                // path which correctly restores ALL registers from the context.
                (NtStatus::STATUS_SUCCESS, false)
            }

            // --- ntdll-driven init: section syscalls for DLL loading ---
            NtSyscallId::NtCreateSection => {
                let status = syscalls::section::nt_create_section(
                    ctx,
                    &mut self.shared.handles.lock(),
                    &self.shared,
                );
                (status, false)
            }
            NtSyscallId::NtMapViewOfSection => {
                let status = syscalls::section::nt_map_view_of_section(
                    ctx,
                    &self.shared.handles.lock(),
                    &self.shared.process_state,
                );
                (status, false)
            }
            NtSyscallId::NtUnmapViewOfSection => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let _unmap_base = args.arg1 as usize;
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtUnmapViewOfSection base=0x{_unmap_base:X}\n",
                    ));
                }
                (NtStatus::STATUS_SUCCESS, false)
            }

            // --- ntdll-driven init: stubs for syscalls hit during LdrpInitialize ---
            NtSyscallId::NtOpenSection => {
                // ntdll tries to open \KnownDlls\<name> as a cached section.
                // We emulate this by looking up the DLL name in our tar archive
                // and creating a Section handle directly, bypassing the
                // NtOpenFile ΓåÆ NtCreateSection path.
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let handle_out_ptr = args.arg0;
                let _desired_access = args.arg1 as u32;
                let obj_attrs_ptr = args.arg2;

                // Extract the name from OBJECT_ATTRIBUTES.
                let name = if obj_attrs_ptr != 0 {
                    let name_ptr =
                        unsafe { core::ptr::read((obj_attrs_ptr + 0x10) as *const usize) };
                    if name_ptr != 0 {
                        let len = unsafe { core::ptr::read(name_ptr as *const u16) as usize };
                        let buf = unsafe { core::ptr::read((name_ptr + 8) as *const usize) };
                        if buf != 0 && len > 0 {
                            let chars = len / 2;
                            let slice =
                                unsafe { core::slice::from_raw_parts(buf as *const u16, chars) };
                            alloc::string::String::from_utf16_lossy(slice)
                        } else {
                            alloc::string::String::new()
                        }
                    } else {
                        alloc::string::String::new()
                    }
                } else {
                    alloc::string::String::new()
                };

                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtOpenSection name=\"{name}\"\n"
                    ));
                }

                // Extract the DLL filename from paths like
                // "\KnownDlls\kernelbase.dll" or just "kernelbase.dll".
                let dll_name = name.rsplit('\\').next().unwrap_or(&name).to_lowercase();

                // Try to find this DLL in the VFS (tar_ro layer).
                let found = if dll_name.ends_with(".dll") {
                    if let Some(fs) = self.shared.fs.get() {
                        use litebox::fs::FileSystem as _;
                        // DLLs in the tar are stored at the root level.
                        let vfs_path = alloc::format!("/{dll_name}");
                        if let Ok(fd) = fs.open(
                            &vfs_path,
                            litebox::fs::OFlags::RDONLY,
                            litebox::fs::Mode::RUSR,
                        ) {
                            // Read the entire file into memory for PE parsing.
                            let size = fs.fd_file_status(&fd).map(|s| s.size as usize).unwrap_or(0);
                            let mut buf = alloc::vec![0u8; size];
                            let bytes_read = fs.read(&fd, &mut buf, None).unwrap_or(0);
                            buf.truncate(bytes_read);
                            let _ = fs.close(&fd);
                            if buf.is_empty() { None } else { Some(buf) }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(pe_data) = found {
                    // Parse PE and create a Section handle (like NtCreateSection).
                    match litebox_common_windows::pe_parser::PeParsedFile::parse(&pe_data) {
                        Ok(parsed) => {
                            let handle = self.shared.handles.lock().insert(
                                crate::handle_table::NtObject::Section {
                                    pe_data: alloc::sync::Arc::new(pe_data.clone()),
                                    image_size: parsed.size_of_image,
                                    image_base: parsed.image_base,
                                    entry_point: parsed.entry_point,
                                    section_alignment: parsed.section_alignment,
                                    is_dll: parsed.is_dll,
                                },
                            );
                            if handle_out_ptr != 0 {
                                unsafe {
                                    core::ptr::write(handle_out_ptr as *mut u32, handle);
                                }
                            }
                            #[cfg(debug_assertions)]
                            {
                                use litebox::platform::DebugLogProvider as _;
                                litebox_platform_multiplex::platform().debug_log_print(
                                    &alloc::format!(
                                        "NT shim: NtOpenSection ΓåÆ created section for '{dll_name}' (handle=0x{handle:X})\n"
                                    ),
                                );
                            }
                            (NtStatus::STATUS_SUCCESS, false)
                        }
                        Err(_) => {
                            #[cfg(debug_assertions)]
                            {
                                use litebox::platform::DebugLogProvider as _;
                                litebox_platform_multiplex::platform().debug_log_print(
                                    &alloc::format!(
                                        "NT shim: NtOpenSection PE parse failed for '{dll_name}'\n"
                                    ),
                                );
                            }
                            (NtStatus::STATUS_OBJECT_NAME_NOT_FOUND, false)
                        }
                    }
                } else {
                    #[cfg(debug_assertions)]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform()
                            .debug_log_print("NT shim: NtOpenSection returned 0xC0000034\n");
                    }
                    (NtStatus::STATUS_OBJECT_NAME_NOT_FOUND, false)
                }
            }
            NtSyscallId::NtQuerySection => {
                let status = syscalls::section::nt_query_section(ctx, &self.shared.handles.lock());
                (status, false)
            }
            NtSyscallId::NtSetInformationProcess => {
                let info_class = ctx.regs.rdx as u32;
                match info_class {
                    // ProcessMappingInformation (0x70 = 112): ntdll uses this
                    // to register the MI_MAP_INFO region with the kernel. The
                    // kernel then writes mapping entries during
                    // NtMapViewOfSection(SEC_IMAGE). We don't implement this
                    // kernel-side write, so reject the class to make ntdll
                    // fall back to a path that doesn't rely on MI_MAP_INFO.
                    0x70 => {
                        #[cfg(debug_assertions)]
                        {
                            use litebox::platform::DebugLogProvider as _;
                            litebox_platform_multiplex::platform().debug_log_print(
                                "  NtSetInformationProcess(0x70): ΓåÆ STATUS_INVALID_INFO_CLASS (disable MI_MAP_INFO)\n",
                            );
                        }
                        (NtStatus(0xC0000003_u32 as i32), false) // STATUS_INVALID_INFO_CLASS
                    }
                    _ => (NtStatus::STATUS_SUCCESS, false),
                }
            }
            NtSyscallId::NtFlushBuffersFile => (NtStatus::STATUS_SUCCESS, false),
            NtSyscallId::NtCreateMutant => {
                log_unimplemented!("NtCreateMutant");
                (NtStatus::STATUS_NOT_IMPLEMENTED, false)
            }
            NtSyscallId::NtOpenMutant => (NtStatus::STATUS_OBJECT_NAME_NOT_FOUND, false),
            NtSyscallId::NtQueryInformationThread => {
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let _thread_handle = args.arg0; // -2 = NtCurrentThread
                let info_class = args.arg1 as u32;
                let info_ptr = args.arg2;
                let info_len = args.arg3 as u32;
                let return_len_ptr = unsafe { syscalls::NtSyscallArgs::arg4(ctx) };

                match info_class {
                    0 => {
                        // ThreadBasicInformation (48 bytes):
                        //   +0x00: NTSTATUS ExitStatus (4)
                        //   +0x08: PVOID TebBaseAddress (8)
                        //   +0x10: CLIENT_ID { UniqueProcess(8), UniqueThread(8) }
                        //   +0x20: ULONG_PTR AffinityMask (8)
                        //   +0x28: LONG Priority (4)
                        //   +0x2C: LONG BasePriority (4)
                        if info_len < 48 || info_ptr == 0 {
                            (NtStatus::STATUS_INFO_LENGTH_MISMATCH, false)
                        } else {
                            let teb_va = self.init_state.as_ref().map_or(0, |s| s.teb_va);
                            unsafe {
                                let p = info_ptr as *mut u8;
                                core::ptr::write_bytes(p, 0, 48);
                                // ExitStatus = STATUS_PENDING (0x103)
                                core::ptr::write(p.add(0) as *mut u32, 0x103);
                                // TebBaseAddress
                                core::ptr::write(p.add(8) as *mut u64, teb_va as u64);
                                // ClientId.UniqueProcess
                                core::ptr::write(p.add(0x10) as *mut u64, 4);
                                // ClientId.UniqueThread
                                core::ptr::write(p.add(0x18) as *mut u64, 4);
                                // AffinityMask
                                core::ptr::write(p.add(0x20) as *mut u64, 1);
                                // Priority = 8, BasePriority = 8
                                core::ptr::write(p.add(0x28) as *mut i32, 8);
                                core::ptr::write(p.add(0x2C) as *mut i32, 8);
                            }
                            if return_len_ptr != 0 {
                                unsafe {
                                    core::ptr::write(return_len_ptr as *mut u32, 48);
                                }
                            }
                            (NtStatus::STATUS_SUCCESS, false)
                        }
                    }
                    _ => {
                        log_unimplemented!("NtQueryInformationThread class={}", info_class);
                        (NtStatus::STATUS_NOT_IMPLEMENTED, false)
                    }
                }
            }
            NtSyscallId::NtOpenProcessToken | NtSyscallId::NtOpenThreadToken => {
                // No token support in sandbox.
                (NtStatus::STATUS_NO_TOKEN, false)
            }
            NtSyscallId::NtQueryInformationToken => {
                // Pseudo-handles: -4 = CurrentProcessToken, -5 = CurrentThreadToken,
                // -6 = CurrentThreadEffectiveToken.
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let _token_handle = args.arg0; // pseudo-handle or real
                let info_class = args.arg1 as u32;
                let info_ptr = args.arg2;
                let info_len = args.arg3 as u32;
                let return_len_ptr = unsafe { syscalls::NtSyscallArgs::arg4(ctx) };

                match info_class {
                    1 => {
                        // TokenUser: return a synthetic SID.
                        // TOKEN_USER is { SID_AND_ATTRIBUTES { PSID, DWORD Attributes } }
                        // We place the SID right after the TOKEN_USER header.
                        // Minimal SID: S-1-5-21-0-0-0-1000 (generic user)
                        //   Revision=1, SubAuthorityCount=5,
                        //   IdentifierAuthority={0,0,0,0,0,5},
                        //   SubAuthorities=[21, 0, 0, 0, 1000]
                        let sid_size: u32 = 8 + 5 * 4; // 28 bytes
                        let header_size: u32 = 16; // SID_AND_ATTRIBUTES on 64-bit
                        let needed = header_size + sid_size;

                        if return_len_ptr != 0 {
                            unsafe {
                                core::ptr::write(return_len_ptr as *mut u32, needed);
                            }
                        }
                        if info_len < needed {
                            (NtStatus(0xC0000023_u32 as i32), false) // STATUS_BUFFER_TOO_SMALL
                        } else if info_ptr == 0 {
                            (NtStatus::STATUS_INVALID_PARAMETER, false)
                        } else {
                            let buf = info_ptr as *mut u8;
                            unsafe {
                                core::ptr::write_bytes(buf, 0, needed as usize);
                                // PSID pointer ΓåÆ right after header
                                let sid_va = info_ptr + header_size as usize;
                                core::ptr::write(buf as *mut u64, sid_va as u64);
                                // Attributes = 0 (already zeroed)
                                // SID body
                                let sid = sid_va as *mut u8;
                                *sid = 1; // Revision
                                *sid.add(1) = 5; // SubAuthorityCount
                                // IdentifierAuthority = {0,0,0,0,0,5}
                                *sid.add(7) = 5;
                                // SubAuthority[0] = 21
                                core::ptr::write((sid.add(8)) as *mut u32, 21);
                                // SubAuthority[1..3] = 0 (already zeroed)
                                // SubAuthority[4] = 1000
                                core::ptr::write((sid.add(24)) as *mut u32, 1000);
                            }
                            (NtStatus::STATUS_SUCCESS, false)
                        }
                    }
                    25 => {
                        // TokenElevation: DWORD = 0 (not elevated)
                        let needed: u32 = 4;
                        if return_len_ptr != 0 {
                            unsafe {
                                core::ptr::write(return_len_ptr as *mut u32, needed);
                            }
                        }
                        if info_len >= needed && info_ptr != 0 {
                            unsafe {
                                core::ptr::write(info_ptr as *mut u32, 0);
                            }
                            (NtStatus::STATUS_SUCCESS, false)
                        } else {
                            (NtStatus(0xC0000023_u32 as i32), false)
                        }
                    }
                    _ => {
                        #[cfg(debug_assertions)]
                        {
                            use litebox::platform::DebugLogProvider as _;
                            litebox_platform_multiplex::platform().debug_log_print(
                                &alloc::format!(
                                    "NT shim: NtQueryInformationToken class={info_class} unhandled\n"
                                ),
                            );
                        }
                        (NtStatus::STATUS_NOT_IMPLEMENTED, false)
                    }
                }
            }
            NtSyscallId::NtRtlExitUserThread => {
                // Thread exit. For the main thread, treat as process exit.
                if let Some(ref obj) = self.thread_obj {
                    let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                    obj.set_exited(args.arg0 as i32);
                    (NtStatus::STATUS_SUCCESS, true)
                } else {
                    // Main thread exiting.
                    let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                    self.exit_code.store(args.arg0 as i32, Ordering::Release);
                    (NtStatus::STATUS_SUCCESS, true)
                }
            }

            // --- Phase 6: Additional ntdll init syscalls ---
            NtSyscallId::NtTraceEvent => {
                // ETW tracing ΓÇö no-op in sandbox.
                (NtStatus::STATUS_SUCCESS, false)
            }
            NtSyscallId::NtManageHotPatch => {
                // Hotpatching ΓÇö not supported in sandbox.
                (NtStatus::STATUS_NOT_SUPPORTED, false)
            }
            NtSyscallId::NtRaiseHardError => {
                // ntdll raises this when DLL init fails (e.g., STATUS_DLL_INIT_FAILED).
                // Log the status and parameters, then terminate.
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let status = args.arg0 as u32;
                let num_params = args.arg1 as u32;
                let params_ptr = args.arg3; // PULONG_PTR *Parameters
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NtRaiseHardError: status=0x{status:08X} num_params={num_params}\n",
                    ));
                    if params_ptr != 0 && num_params > 0 {
                        for i in 0..num_params.min(4) {
                            let param = unsafe {
                                core::ptr::read((params_ptr + (i as usize) * 8) as *const u64)
                            };
                            litebox_platform_multiplex::platform().debug_log_print(
                                &alloc::format!("  param[{i}] = 0x{param:016X}\n"),
                            );
                        }
                    }
                    // Dump RSP, RIP, and all GPRs
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "  RSP=0x{:X} RIP=0x{:X} RBP=0x{:X}\n  \
                         RAX=0x{:X} RBX=0x{:X} RCX=0x{:X} RDX=0x{:X}\n  \
                         RSI=0x{:X} RDI=0x{:X} R8=0x{:X} R9=0x{:X}\n  \
                         R10=0x{:X} R11=0x{:X} R12=0x{:X} R13=0x{:X}\n  \
                         R14=0x{:X} R15=0x{:X}\n",
                        ctx.regs.rsp,
                        ctx.regs.rip,
                        ctx.regs.rbp,
                        ctx.regs.rax,
                        ctx.regs.rbx,
                        ctx.regs.rcx,
                        ctx.regs.rdx,
                        ctx.regs.rsi,
                        ctx.regs.rdi,
                        ctx.regs.r8,
                        ctx.regs.r9,
                        ctx.regs.r10,
                        ctx.regs.r11,
                        ctx.regs.r12,
                        ctx.regs.r13,
                        ctx.regs.r14,
                        ctx.regs.r15,
                    ));
                    // Walk the stack to find return addresses (likely ntdll code)
                    let (ntdll_base, ntdll_end) = self
                        .init_state
                        .as_ref()
                        .and_then(|s| s.module_bases.iter().find(|m| m.name == "ntdll.dll"))
                        .map_or((0, 0), |m| (m.base_address, m.base_address + m.image_size));
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "  ntdll range: 0x{ntdll_base:X}..0x{ntdll_end:X}\n",
                    ));
                    // Scan stack for all values (not just ntdll range)
                    let rsp = ctx.regs.rsp as usize;
                    litebox_platform_multiplex::platform().debug_log_print("  Full stack dump:\n");
                    for off in (0..256).step_by(8) {
                        let addr = rsp + off;
                        if addr > 0 {
                            let val = unsafe { core::ptr::read(addr as *const u64) };
                            let annotation =
                                if val as usize >= ntdll_base && (val as usize) < ntdll_end {
                                    let rva = val as usize - ntdll_base;
                                    alloc::format!(" (ntdll+0x{rva:X})")
                                } else {
                                    alloc::string::String::new()
                                };
                            litebox_platform_multiplex::platform().debug_log_print(
                                &alloc::format!(
                                    "    [RSP+0x{off:X}] = 0x{val:016X}{annotation}\n",
                                ),
                            );
                        }
                    }
                    // Read kernelbase progress marker if loaded
                    if let Some(init) = self.init_state.as_ref() {
                        for m in &init.module_bases {
                            if m.name.to_ascii_lowercase().contains("kernelbase") {
                                let marker_addr = m.base_address + 0x39C868;
                                let marker =
                                    unsafe { core::ptr::read_unaligned(marker_addr as *const u16) };
                                litebox_platform_multiplex::platform().debug_log_print(
                                    &alloc::format!(
                                        "  kernelbase progress: 0x{marker:X} (base=0x{:X})\n",
                                        m.base_address
                                    ),
                                );
                            }
                        }
                    }
                }
                self.exit_code.store(status as i32, Ordering::Release);
                (NtStatus::STATUS_SUCCESS, true)
            }
            NtSyscallId::NtQueryKey => {
                // NtQueryKey(KeyHandle, KeyInformationClass, KeyInformation,
                //            Length, ResultLength)
                // Validate the handle, then return empty/minimal results.
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let key_handle = args.arg0 as u32;
                let info_class = args.arg1 as u32;
                let _info_ptr = args.arg2;
                let info_length = args.arg3 as u32;
                let result_length_ptr =
                    unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };

                let is_valid = self
                    .shared
                    .handles
                    .lock()
                    .get(key_handle)
                    .is_some_and(|obj| matches!(obj, handle_table::NtObject::RegistryKey));
                if is_valid {
                    // Minimum fixed-header sizes per NT ABI:
                    //   KeyBasicInformation:  LARGE_INTEGER + 2*ULONG = 16 bytes (+ Name)
                    //   KeyNodeInformation:   LARGE_INTEGER + 4*ULONG = 24 bytes (+ Name)
                    //   KeyFullInformation:   LARGE_INTEGER + 9*ULONG = 44 bytes (+ Class)
                    let required: u32 = match info_class {
                        0 => 16, // KeyBasicInformation
                        1 => 24, // KeyNodeInformation
                        2 => 44, // KeyFullInformation
                        _ => return (NtStatus::STATUS_INVALID_INFO_CLASS, false),
                    };
                    if result_length_ptr != 0 {
                        unsafe {
                            core::ptr::write(result_length_ptr as *mut u32, required);
                        }
                    }
                    if info_length < required {
                        (NtStatus(0xC0000023_u32 as i32), false) // STATUS_BUFFER_TOO_SMALL
                    } else {
                        // Zero-fill the output buffer
                        if _info_ptr != 0 && info_length > 0 {
                            unsafe {
                                core::ptr::write_bytes(
                                    _info_ptr as *mut u8,
                                    0,
                                    info_length as usize,
                                );
                            }
                        }
                        (NtStatus::STATUS_SUCCESS, false)
                    }
                } else {
                    (NtStatus::STATUS_INVALID_HANDLE, false)
                }
            }

            NtSyscallId::NtInitializeNlsFiles => {
                // NtInitializeNlsFiles(OUT PVOID *BaseAddress, OUT PLCID DefaultLocaleId,
                //                      OUT PLARGE_INTEGER DefaultCasingTableSize)
                // Uses pre-captured NLS data from the runner (no host API calls).
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let base_addr_out = args.arg0;
                let locale_id_out = args.arg1;
                let casing_size_out = args.arg2;

                let Some(nls) = self.shared.nls_data.get() else {
                    #[cfg(debug_assertions)]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform()
                            .debug_log_print("NT shim: NtInitializeNlsFiles: no NLS data set\n");
                    }
                    return (NtStatus::STATUS_UNSUCCESSFUL, false);
                };

                use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
                use litebox::platform::RawConstPointer as _;

                let alloc_size = (nls.section.len() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                let nz_size =
                    NonZeroPageSize::<PAGE_SIZE>::new(alloc_size).expect("NLS alloc size");

                let data = &nls.section;
                let result = unsafe {
                    self.shared.process_state.pm.create_readable_pages(
                        None,
                        nz_size,
                        CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                        |ptr| {
                            let dest = ptr.as_usize() as *mut u8;
                            core::ptr::copy_nonoverlapping(data.as_ptr(), dest, data.len());
                            Ok(data.len())
                        },
                    )
                };

                match result {
                    Ok(addr) => {
                        let va = addr.as_usize();
                        if base_addr_out != 0 {
                            unsafe { core::ptr::write(base_addr_out as *mut u64, va as u64) }
                        }
                        if locale_id_out != 0 {
                            unsafe { core::ptr::write(locale_id_out as *mut u32, nls.locale_id) }
                        }
                        if casing_size_out != 0 {
                            unsafe {
                                core::ptr::write(casing_size_out as *mut i64, nls.casing_size);
                            }
                        }
                        #[cfg(debug_assertions)]
                        {
                            use litebox::platform::DebugLogProvider as _;
                            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                                "NT shim: NtInitializeNlsFiles mapped at 0x{va:X} ({} bytes, locale=0x{:X})\n",
                                data.len(), nls.locale_id
                            ));
                        }
                        (NtStatus::STATUS_SUCCESS, false)
                    }
                    Err(_) => (NtStatus::STATUS_NO_MEMORY, false),
                }
            }

            NtSyscallId::NtGetNlsSectionPtr => {
                // NtGetNlsSectionPtr: load NLS data from host and map into guest.
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let section_type = args.arg0 as u32;
                let section_data = args.arg1 as u32;

                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    let msg = alloc::format!(
                        "NT shim: NtGetNlsSectionPtr(type={section_type}, data=0x{section_data:X})\n"
                    );
                    litebox_platform_multiplex::platform().debug_log_print(&msg);
                }

                // Determine NLS filename based on type.
                let nls_filename = match section_type {
                    11 => alloc::format!("c_{section_data}.nls"),
                    12 => alloc::string::String::from("normnfc.nls"),
                    _ => alloc::string::String::from("l_intl.nls"),
                };

                let nls_path = alloc::format!("C:\\Windows\\System32\\{nls_filename}");

                // In no_std mode we cannot read host files. NLS data must be
                // provided by the runner via set_nls_data().  Return not-found
                // so the caller falls back to its built-in path.
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    let msg =
                        alloc::format!("NT shim: NLS file not available (no_std): {nls_path}\n");
                    litebox_platform_multiplex::platform().debug_log_print(&msg);
                }
                (NtStatus::STATUS_OBJECT_NAME_NOT_FOUND, false)
            }

            NtSyscallId::NtCreateWaitCompletionPacket => {
                // Thread pool wait completion packet ΓÇö allocate a dummy handle.
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let handle_ptr = args.arg0; // PHANDLE
                let mut handles = self.shared.handles.lock();
                let h = handles.insert(handle_table::NtObject::Stub {
                    kind: alloc::string::String::from("WaitCompletionPacket"),
                });
                unsafe {
                    *(handle_ptr as *mut u64) = h as u64;
                }
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtCreateIoCompletion => {
                // I/O completion port ΓÇö used by ntdll's thread pool (TpAllocPool).
                // Allocate a dummy handle so the pool init doesn't fail.
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let handle_ptr = args.arg0; // PHANDLE
                let mut handles = self.shared.handles.lock();
                let h = handles.insert(handle_table::NtObject::Stub {
                    kind: alloc::string::String::from("IoCompletion"),
                });
                unsafe {
                    *(handle_ptr as *mut u64) = h as u64;
                }
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtCreateWorkerFactory => {
                // Worker factory ΓÇö ntdll's thread pool creates worker threads
                // through this syscall. Allocate a dummy handle; the actual
                // thread creation won't happen but the pool init will succeed.
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let handle_ptr = args.arg0; // PHANDLE
                let mut handles = self.shared.handles.lock();
                let h = handles.insert(handle_table::NtObject::Stub {
                    kind: alloc::string::String::from("WorkerFactory"),
                });
                unsafe {
                    *(handle_ptr as *mut u64) = h as u64;
                }
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtCreateTimer2 => {
                // Timer2 ΓÇö used by the thread pool for delayed work items.
                // Allocate a dummy handle so pool init doesn't abort.
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let handle_ptr = args.arg0; // PHANDLE
                let mut handles = self.shared.handles.lock();
                let h = handles.insert(handle_table::NtObject::Stub {
                    kind: alloc::string::String::from("Timer2"),
                });
                unsafe {
                    *(handle_ptr as *mut u64) = h as u64;
                }
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtOpenDirectoryObject => {
                // ntdll opens \KnownDlls to check for pre-cached section
                // objects. Return a fake handle so the loader proceeds to
                // NtOpenSection per-DLL, where we return NOT_FOUND to force
                // file-based loading.
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let handle_ptr = args.arg0 as *mut u64;
                let mut handles = self.shared.handles.lock();
                let h = handles.insert(handle_table::NtObject::Stub {
                    kind: alloc::string::String::from("DirectoryObject"),
                });
                unsafe { core::ptr::write(handle_ptr, h as u64) };
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtRaiseException => {
                // NtRaiseException(EXCEPTION_RECORD*, CONTEXT*, FirstChance)
                //
                // On real Windows the kernel dispatches this back to user mode
                // via KiUserExceptionDispatcher. We replicate that: copy the
                // EXCEPTION_RECORD and CONTEXT onto the guest stack in the
                // layout KiUserExceptionDispatcher expects, then redirect RIP.
                //
                // Stack layout for KiUserExceptionDispatcher:
                //   [RSP+0x000]: CONTEXT         (0x4D0 bytes)
                //   [RSP+0x4F0]: EXCEPTION_RECORD (0x98 bytes)
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let exc_record_ptr = args.arg0; // EXCEPTION_RECORD*
                let context_ptr = args.arg1; // CONTEXT*

                const CONTEXT_SIZE: usize = 0x4D0;
                const EXCEPTION_RECORD_SIZE: usize = 0x98;
                const EXCEPTION_RECORD_OFFSET: usize = 0x4F0;
                // Total frame: EXCEPTION_RECORD_OFFSET + EXCEPTION_RECORD_SIZE,
                // rounded up to 16-byte alignment.
                const FRAME_SIZE: usize =
                    (EXCEPTION_RECORD_OFFSET + EXCEPTION_RECORD_SIZE + 0xF) & !0xF;

                // Find KiUserExceptionDispatcher address from ntdll base + RVA.
                let dispatcher_va = self.init_state.as_ref().and_then(|s| {
                    let base = s
                        .module_bases
                        .iter()
                        .find(|m| m.name == "ntdll.dll")
                        .map(|m| m.base_address)?;
                    let rva = s.ki_user_exception_dispatcher_rva?;
                    Some(base + rva)
                });

                if let Some(dispatcher_va) = dispatcher_va {
                    // Allocate frame on guest stack.
                    let new_rsp = (ctx.regs.rsp - FRAME_SIZE) & !0xF;

                    // Copy CONTEXT and EXCEPTION_RECORD to guest stack.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            context_ptr as *const u8,
                            new_rsp as *mut u8,
                            CONTEXT_SIZE,
                        );
                        // Zero the gap between CONTEXT end and EXCEPTION_RECORD.
                        core::ptr::write_bytes(
                            (new_rsp + CONTEXT_SIZE) as *mut u8,
                            0,
                            EXCEPTION_RECORD_OFFSET - CONTEXT_SIZE,
                        );
                        core::ptr::copy_nonoverlapping(
                            exc_record_ptr as *const u8,
                            (new_rsp + EXCEPTION_RECORD_OFFSET) as *mut u8,
                            EXCEPTION_RECORD_SIZE,
                        );
                    }

                    // Redirect guest execution to KiUserExceptionDispatcher.
                    ctx.regs.rsp = new_rsp;
                    ctx.regs.rip = dispatcher_va;
                    ctx.regs.rcx = dispatcher_va; // for sysret fast path

                    #[cfg(debug_assertions)]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        let exc_code = unsafe { *(exc_record_ptr as *const u32) };
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NtRaiseException: code=0x{exc_code:X} ΓåÆ KiUserExceptionDispatcher @ 0x{dispatcher_va:X}\n",
                        ));
                    }
                    (NtStatus::STATUS_SUCCESS, false)
                } else {
                    (NtStatus::STATUS_UNSUCCESSFUL, false)
                }
            }

            NtSyscallId::NtOpenEvent => {
                // ntdll tries to open named events (e.g. CSR connection).
                // Return NOT_FOUND ΓÇö we don't have CSRSS or named event objects.
                (NtStatus::STATUS_OBJECT_NAME_NOT_FOUND, false)
            }

            NtSyscallId::NtSetInformationWorkerFactory => {
                // Configure thread pool (min/max threads, etc.). Stub as success.
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtAssociateWaitCompletionPacket => {
                // Associates a wait packet with a completion port. Stub as success.
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtShutdownWorkerFactory => {
                // Thread pool shutdown/cleanup. Stub as success.
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtCancelWaitCompletionPacket => {
                // Cancel a pending wait completion packet. Stub as success.
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtTraceControl => {
                // ETW trace control. Stub as success.
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtSetWnfProcessNotificationEvent => {
                // WNF (Windows Notification Facility) event. Stub as success.
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtSubscribeWnfStateChange | NtSyscallId::NtUnsubscribeWnfStateChange => {
                // WNF subscribe/unsubscribe. Stub as success.
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtApphelpCacheControl => {
                // Application compatibility database lookup. Not needed.
                (NtStatus::STATUS_NOT_FOUND, false)
            }

            NtSyscallId::NtCreateSectionEx => {
                // NtCreateSectionEx is the modern (Win10+) superset of
                // NtCreateSection with an extra ExtendedParameters array.
                // We ignore the extended params and delegate to the existing
                // NtCreateSection handler which reads the first 7 arguments.
                let status = syscalls::section::nt_create_section(
                    ctx,
                    &mut self.shared.handles.lock(),
                    &self.shared,
                );
                (status, false)
            }

            NtSyscallId::NtMapViewOfSectionEx => {
                // NtMapViewOfSectionEx is the modern (Win10+) superset of
                // NtMapViewOfSection with extra parameters. Delegate to
                // existing handler which reads the standard 10 arguments.
                let status = syscalls::section::nt_map_view_of_section(
                    ctx,
                    &self.shared.handles.lock(),
                    &self.shared.process_state,
                );
                (status, false)
            }

            NtSyscallId::NtSetDefaultHardErrorPort => {
                // Registers the hard error port. Stub as success.
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtOpenSymbolicLinkObject => {
                // ntdll opens \KnownDlls\KnownDllPath to discover the system
                // directory (C:\Windows\System32). Return a fake handle so
                // NtQuerySymbolicLinkObject can return the path.
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let handle_ptr = args.arg0 as *mut u64;
                let mut handles = self.shared.handles.lock();
                let h = handles.insert(handle_table::NtObject::Stub {
                    kind: alloc::string::String::from("SymbolicLink"),
                });
                unsafe { core::ptr::write(handle_ptr, h as u64) };
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtQuerySymbolicLinkObject => {
                // Return the system directory path that the loader uses for
                // DLL search. The UNICODE_STRING at arg1 receives the target.
                //
                // UNICODE_STRING layout: { u16 Length, u16 MaximumLength, *u16 Buffer }
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let _handle = args.arg0;
                let ustr_ptr = args.arg1;

                // The path ntdll expects for KnownDllPath.
                let path: &[u16] = &[
                    b'C' as u16,
                    b':' as u16,
                    b'\\' as u16,
                    b'W' as u16,
                    b'i' as u16,
                    b'n' as u16,
                    b'd' as u16,
                    b'o' as u16,
                    b'w' as u16,
                    b's' as u16,
                    b'\\' as u16,
                    b'S' as u16,
                    b'y' as u16,
                    b's' as u16,
                    b't' as u16,
                    b'e' as u16,
                    b'm' as u16,
                    b'3' as u16,
                    b'2' as u16,
                ];
                let byte_len = (path.len() * 2) as u16;

                unsafe {
                    // Read MaximumLength from UNICODE_STRING.
                    let max_len = core::ptr::read_unaligned((ustr_ptr + 2) as *const u16);
                    if max_len < byte_len {
                        return (NtStatus::STATUS_BUFFER_TOO_SMALL, false);
                    }
                    // Write Length.
                    core::ptr::write_unaligned(ustr_ptr as *mut u16, byte_len);
                    // Copy path into Buffer.
                    let buf_ptr =
                        core::ptr::read_unaligned((ustr_ptr + 8) as *const usize) as *mut u16;
                    core::ptr::copy_nonoverlapping(path.as_ptr(), buf_ptr, path.len());
                }
                // If caller provides a return-length pointer (arg2), write it.
                let ret_len_ptr = args.arg2;
                if ret_len_ptr != 0 {
                    unsafe {
                        core::ptr::write(ret_len_ptr as *mut u32, byte_len as u32);
                    }
                }
                (NtStatus::STATUS_SUCCESS, false)
            }

            NtSyscallId::NtDeviceIoControlFile => {
                // NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext,
                //   IoStatusBlock, IoControlCode, InputBuffer, InputLen, OutputBuffer, OutputLen)
                // Args: r10=FileHandle, rdx=Event, r8=ApcRoutine, r9=ApcContext
                //   [rsp+0x28]=IoStatusBlock, [rsp+0x30]=IoControlCode
                let args = syscalls::NtSyscallArgs::from_ctx(ctx);
                let file_handle = args.arg0 as u32;
                let io_status_ptr =
                    unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
                let ioctl_code = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const u32) };

                let is_condrv = {
                    let handles = self.shared.handles.lock();
                    handles.get(file_handle).is_some_and(|obj| {
                        matches!(obj, handle_table::NtObject::Stub { kind } if kind == "ConDrv")
                    })
                };

                if is_condrv {
                    #[cfg(debug_assertions)]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtDeviceIoControlFile ConDrv ioctl=0x{ioctl_code:X} ΓåÆ stub success\n"
                        ));
                    }
                    if io_status_ptr != 0 {
                        unsafe {
                            core::ptr::write(io_status_ptr as *mut u64, 0); // Status
                            core::ptr::write((io_status_ptr + 8) as *mut u64, 0); // Information
                        }
                    }
                    (NtStatus::STATUS_SUCCESS, false)
                } else {
                    log_unimplemented!(
                        "NtDeviceIoControlFile handle=0x{:X} ioctl=0x{:X}",
                        file_handle,
                        ioctl_code
                    );
                    (NtStatus::STATUS_NOT_IMPLEMENTED, false)
                }
            }

            other => {
                log_unimplemented!("syscall {:?} (nr=0x{:04X})", other, raw_nr);
                (NtStatus::STATUS_NOT_IMPLEMENTED, false)
            }
        }
    }
}

impl litebox::shim::EnterShim for NtShimEntrypoints {
    type ExecutionContext = ExecutionContext;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        // Set up initial thread state from the runner-provided init state.
        if let Some(state) = &self.init_state {
            ctx.regs.rip = state.entry_point;
            ctx.regs.rsp = state.stack_top;

            if let Some(argument) = self.child_thread_argument {
                // Child thread: RCX = argument (first Win64 parameter).
                ctx.regs.rcx = argument;
            } else if state.initial_rcx != 0 {
                // ntdll-driven init: RCX = CONTEXT* on guest stack,
                // RDX = ntdll base address. Since RCX != RIP, the platform
                // uses the NtContinue slow path which restores all registers.
                ctx.regs.rcx = state.initial_rcx;
                ctx.regs.rdx = state.initial_rdx;
            } else {
                ctx.regs.rcx = state.entry_point;
            }
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
        // directly (the dispatch handler sets rax). NT syscalls return
        // NTSTATUS in rax.
        // Special case: NtContinue restores the full context including rax,
        // so we must not overwrite it.
        let is_kernel32 = nr >= 0x1000;
        let is_context_switch = self.shared.syscall_map.get().and_then(|m| m.lookup(nr))
            == Some(NtSyscallId::NtContinue);
        if !is_kernel32 && !is_context_switch {
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
        // A child thread returning from its start routine via `ret` pops the
        // sentinel into RIP and advances RSP to stack_top + 8 (one slot past
        // the sentinel). We verify both RIP and RSP to distinguish a legitimate
        // return from an accidental indirect call/jump to the sentinel address.
        if ctx.regs.rip == syscalls::thread::THREAD_EXIT_SENTINEL
            && self.thread_obj.is_some()
            && self
                .init_state
                .as_ref()
                .is_some_and(|s| ctx.regs.rsp == s.stack_top + 8)
        {
            let exit_code = ctx.regs.rax as i32;
            self.exit_code.store(exit_code, Ordering::Release);
            if let Some(ref obj) = self.thread_obj {
                obj.set_exited(exit_code);
            }
            return ContinueOperation::Terminate;
        }

        // Handle demand-commit page faults for reserved (inaccessible) pages.
        //
        // In the NT memory model, MEM_RESERVE creates inaccessible pages and
        // MEM_COMMIT makes them accessible. When guest code (especially ntdll's
        // heap) accesses a reserved page without an explicit MEM_COMMIT, we
        // demand-commit it here by upgrading the faulting page to read-write.
        if info.exception == litebox::shim::Exception::PAGE_FAULT {
            let fault_addr = info.cr2 & !(PAGE_SIZE - 1);
            if let (Some(addr), Some(page_size)) = (
                litebox::mm::linux::NonZeroAddress::<PAGE_SIZE>::new(fault_addr),
                litebox::mm::linux::NonZeroPageSize::<PAGE_SIZE>::new(PAGE_SIZE),
            ) && let Some(perms) = self
                .shared
                .process_state
                .pm
                .get_memory_permissions(addr, page_size)
                && perms.is_empty()
            {
                // Page is in a valid VMA but has no permissions (reserved).
                // Demand-commit: upgrade to read-write.
                use litebox::platform::{RawConstPointer as _, RawPointerProvider};
                let ptr =
                    <Platform as RawPointerProvider>::RawMutPointer::<u8>::from_usize(fault_addr);
                if unsafe {
                    self.shared
                        .process_state
                        .pm
                        .make_pages_writable(ptr, PAGE_SIZE)
                }
                .is_ok()
                {
                    #[cfg(debug_assertions)]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: demand-commit page fault at 0x{:X} \
                                         (rip=0x{:X}) ΓåÆ committed RW\n",
                            fault_addr,
                            ctx.regs.rip,
                        ));
                    }
                    return ContinueOperation::Resume;
                }
            }
        }

        let status = exception_to_ntstatus(info);

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: EXCEPTION at rip=0x{:X} rsp=0x{:X} status=0x{:08X}\n  \
                 rax=0x{:X} rcx=0x{:X} rdx=0x{:X} rbx=0x{:X}\n  \
                 rsi=0x{:X} rdi=0x{:X} rbp=0x{:X}\n  \
                 r8=0x{:X} r9=0x{:X} r10=0x{:X} r11=0x{:X}\n  \
                 r12=0x{:X} r13=0x{:X} r14=0x{:X} r15=0x{:X}\n  \
                 info={:?}\n",
                ctx.regs.rip,
                ctx.regs.rsp,
                status.0 as u32,
                ctx.regs.rax,
                ctx.regs.rcx,
                ctx.regs.rdx,
                ctx.regs.rbx,
                ctx.regs.rsi,
                ctx.regs.rdi,
                ctx.regs.rbp,
                ctx.regs.r8,
                ctx.regs.r9,
                ctx.regs.r10,
                ctx.regs.r11,
                ctx.regs.r12,
                ctx.regs.r13,
                ctx.regs.r14,
                ctx.regs.r15,
                info
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);

            // Dump stack: 8 words below RSP and 48 words above (covers rsp+0x170)
            let rsp = ctx.regs.rsp as u64;
            let mut stack_dump = alloc::string::String::from("  stack (rsp-64..rsp+384):\n");
            for offset in (-8i64..48).rev() {
                let addr = (rsp as i64 + offset * 8) as u64;
                let val = unsafe { core::ptr::read_unaligned(addr as *const u64) };
                let marker = if offset == 0 { " <-- RSP" } else { "" };
                stack_dump.push_str(&alloc::format!(
                    "    [{addr:016X}] = 0x{val:016X}{marker}\n"
                ));
            }
            litebox_platform_multiplex::platform().debug_log_print(&stack_dump);

            // Dump instruction bytes at crash RIP
            let rip = ctx.regs.rip as u64;
            let mut insn_dump = alloc::format!("  code at rip=0x{rip:X}: ");
            for i in 0u64..16 {
                let byte = unsafe { core::ptr::read((rip + i) as *const u8) };
                insn_dump.push_str(&alloc::format!("{byte:02X} "));
            }
            // Also show 8 bytes before rip for context
            insn_dump.push_str(&alloc::format!("\n  code at rip-8=0x{:X}: ", rip - 8));
            for i in 0u64..8 {
                let byte = unsafe { core::ptr::read((rip - 8 + i) as *const u8) };
                insn_dump.push_str(&alloc::format!("{byte:02X} "));
            }
            insn_dump.push('\n');
            litebox_platform_multiplex::platform().debug_log_print(&insn_dump);

            // Dump memory near R12 and R13 to understand initialized vs zero-filled regions.
            for (label, base) in [("R12", ctx.regs.r12), ("R13", ctx.regs.r13)] {
                if base != 0 {
                    let mut mem = alloc::format!("  memory at {label}=0x{base:X}:\n");
                    for off in (0usize..0xC0).step_by(8) {
                        let addr = base as usize + off;
                        let val = unsafe { core::ptr::read_unaligned(addr as *const u64) };
                        if val != 0 {
                            mem.push_str(&alloc::format!(
                                "    [{label}+0x{off:03X}] = 0x{val:016X}\n"
                            ));
                        }
                    }
                    litebox_platform_multiplex::platform().debug_log_print(&mem);
                }
            }
        }

        self.exit_code.store(status.0, Ordering::Release);
        // Mark this thread's ThreadObject as exited so waiters wake up.
        if let Some(ref obj) = self.thread_obj {
            obj.set_exited(status.0);
        }
        log_unimplemented!(
            "exception {:?} at rip=0x{:X} (exit code 0x{:08X})",
            info.exception,
            ctx.regs.rip,
            status.0 as u32
        );
        ContinueOperation::Terminate
    }

    fn interrupt(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        // Note: Guest GS base is NOT restored here ΓÇö interrupts are delivered
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

/// Check whether the page at `va` has any permissions in the PageManager.
/// Platform-agnostic replacement for VirtualQuery-based probing.
pub(crate) fn is_page_readable(pm: &PageManager<Platform, PAGE_SIZE>, va: usize) -> bool {
    let page_addr = va & !(PAGE_SIZE - 1);
    if let (Some(addr), Some(size)) = (
        litebox::mm::linux::NonZeroAddress::<PAGE_SIZE>::new(page_addr),
        litebox::mm::linux::NonZeroPageSize::<PAGE_SIZE>::new(PAGE_SIZE),
    ) {
        pm.get_memory_permissions(addr, size)
            .is_some_and(|perms| !perms.is_empty())
    } else {
        false
    }
}

/// Read a null-terminated UTF-16LE string from guest memory at `va`, with
/// incremental page probing via PageManager.
///
/// Returns `None` if `va` is zero, outside the guest VA partition, the
/// pages are not readable, or the string exceeds `max_chars`.
pub(crate) fn read_wide_string_checked(
    pm: &PageManager<Platform, PAGE_SIZE>,
    va: usize,
    guest_va_start: usize,
    guest_va_end: usize,
    max_chars: usize,
) -> Option<alloc::string::String> {
    if va == 0 || va < guest_va_start {
        return None;
    }

    let mut chars = alloc::vec::Vec::new();
    let mut ptr = va;
    // Track the end of the currently-probed readable region.
    let mut probed_up_to: usize = va;

    for _ in 0..max_chars {
        let read_end = ptr.checked_add(2)?;
        // Bounds-check against the guest partition.
        if read_end > guest_va_end {
            return None;
        }
        // If the next u16 extends past our probed window, re-probe.
        if read_end > probed_up_to {
            if !is_page_readable(pm, ptr) {
                return None;
            }
            // If the u16 straddles a page boundary, also probe the next page.
            let next_page = (ptr & !0xFFF) + 0x1000;
            if read_end > next_page && !is_page_readable(pm, next_page) {
                return None;
            }
            // Cache probe up to the end of the last verified page.
            probed_up_to = if read_end > next_page {
                next_page + 0x1000
            } else {
                next_page
            };
        }
        // SAFETY: PageManager confirmed the page is accessible.
        let wchar = unsafe { core::ptr::read_unaligned(ptr as *const u16) };
        if wchar == 0 {
            return Some(alloc::string::String::from_utf16_lossy(&chars));
        }
        chars.push(wchar);
        ptr = read_end;
    }
    // Unterminated string ΓÇö treat as invalid rather than silently truncating.
    None
}
