// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Windows.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use core::cell::Cell;
use core::panic;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::cell::RefCell;
use std::os::raw::c_void;
use std::os::windows::io::AsRawHandle as _;
use std::sync::{Arc, Mutex, OnceLock};

use litebox::platform::ImmediatelyWokenUp;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::{
    AllocationError, FixedAddressBehavior, MemoryRegionPermissions,
};
use litebox::shim::{ContinueOperation, Exception};
use litebox::utils::TruncateExt as _;
use litebox_common_linux::PunchthroughSyscall;

use windows_sys::Win32::Foundation::{self as Win32_Foundation, FILETIME};
use windows_sys::Win32::{
    Foundation::GetLastError,
    System::Diagnostics::Debug::{
        AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
        EXCEPTION_POINTERS, EXCEPTION_RECORD,
    },
    System::Memory::{
        self as Win32_Memory, PrefetchVirtualMemory, VirtualAlloc2, VirtualFree, VirtualProtect,
    },
    System::SystemInformation::{self as Win32_SysInfo, GetSystemTimePreciseAsFileTime},
    System::Threading::{self as Win32_Threading, GetCurrentProcess},
    System::WindowsProgramming::QueryUnbiasedInterruptTimePrecise,
};
use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

// Thread-local storage for FS base state
thread_local! {
    static THREAD_FS_BASE: Cell<usize> = const { Cell::new(0) };
}

/// The userland Windows platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct WindowsUserland {
    reserved_pages: alloc::vec::Vec<core::ops::Range<usize>>,
    sys_info: std::sync::RwLock<Win32_SysInfo::SYSTEM_INFO>,
}

impl core::fmt::Debug for WindowsUserland {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WindowsUserland").finish_non_exhaustive()
    }
}

// Safety: Given that SYSTEM_INFO is not Send/Sync (it contains *mut c_void), we use RwLock to
// ensure that the sys_info is only accessed in a thread-safe manner.
// Moreover, SYSTEM_INFO is only initialized once during platform creation, and it is read-only
// after that.
unsafe impl Send for WindowsUserland {}
unsafe impl Sync for WindowsUserland {}

/// Helper functions for managing per-thread FS base
impl WindowsUserland {
    /// Get the current thread's FS base state
    fn get_thread_fs_base() -> usize {
        THREAD_FS_BASE.get()
    }

    /// Set the current thread's FS base
    fn set_thread_fs_base(new_base: usize) {
        THREAD_FS_BASE.set(new_base);
        Self::restore_thread_fs_base();
    }

    /// Restore the current thread's FS base from saved state
    fn restore_thread_fs_base() {
        unsafe {
            litebox_common_linux::wrfsbase(THREAD_FS_BASE.get());
        }
    }

    /// Initialize FS base state for a new thread
    fn init_thread_fs_base() {
        Self::set_thread_fs_base(0);
    }
}

unsafe extern "system" fn vectored_exception_handler(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    let Some(tls) = get_tls_ptr() else {
        // TLS slot not initialized yet; cannot be in guest
        return EXCEPTION_CONTINUE_SEARCH;
    };
    let tls = unsafe { &*tls };
    let (info, exception_record, context);
    unsafe {
        info = *exception_info;
        exception_record = &*info.ExceptionRecord;
        context = &mut *info.ContextRecord;
    }

    if !tls.is_in_guest.get() {
        // This might be a faulting guest memory access in LiteBox code. Try to
        // recover.
        if exception_record.ExceptionCode == Win32_Foundation::EXCEPTION_ACCESS_VIOLATION
            && let Some(recover) =
                litebox::mm::exception_table::search_exception_tables(context.Rip.truncate())
        {
            // Found a matching exception table entry.
            context.Rip = recover as u64;
            return EXCEPTION_CONTINUE_EXECUTION;
        } else {
            // Not one of our exceptions; let other handlers process it.
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    tls.is_in_guest.set(false);

    let regs = unsafe { &mut *tls.guest_context_top.get().wrapping_sub(1) };
    save_guest_context(regs, context);

    // If it looks like fs base was cleared, then go through the interrupt path
    // instead of the exception path to restore the fs base and try again.
    //
    // This is done instead of just fixing up fsbase and returning here to avoid
    // missing a real interrupt that arrives while resuming the guest. Go through
    // the interrupt path to ensure that any pending interrupts are also handled.
    if exception_record.ExceptionCode == Win32_Foundation::EXCEPTION_ACCESS_VIOLATION
        && unsafe { litebox_common_linux::rdfsbase() } == 0
        && WindowsUserland::get_thread_fs_base() != 0
    {
        set_context_to_interrupt_callback(tls, context);
    } else {
        // Push the exception record onto the host stack.
        let exception_record_ptr = tls.host_sp.get().cast::<EXCEPTION_RECORD>().wrapping_sub(1);
        assert!(exception_record_ptr.is_aligned());
        unsafe { exception_record_ptr.write(*exception_record) };

        // Re-align the stack pointer.
        let rsp = exception_record_ptr as usize & !15;

        // Ensure that `run_thread_arch` is linked in so that `exception_callback` is visible.
        let _ = run_thread_arch as *const () as usize;

        // Update the thread context to jump to the exception handler.
        context.Rip = exception_callback as *const () as usize as u64;
        context.Rsp = rsp as u64;
        context.Rbp = tls.host_bp.get() as u64;
        context.Rdx = exception_record_ptr as u64;
    }

    EXCEPTION_CONTINUE_EXECUTION
}

fn save_guest_context(
    guest_context: &mut litebox_common_linux::PtRegs,
    context: &windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    let litebox_common_linux::PtRegs {
        r15,
        r14,
        r13,
        r12,
        rbp,
        rbx,
        r11,
        r10,
        r9,
        r8,
        rax,
        rcx,
        rdx,
        rsi,
        rdi,
        orig_rax,
        rip,
        cs: _,
        eflags,
        rsp,
        ss: _,
    } = guest_context;
    *r15 = context.R15.truncate();
    *r14 = context.R14.truncate();
    *r13 = context.R13.truncate();
    *r12 = context.R12.truncate();
    *rbp = context.Rbp.truncate();
    *rbx = context.Rbx.truncate();
    *r11 = context.R11.truncate();
    *r10 = context.R10.truncate();
    *r9 = context.R9.truncate();
    *r8 = context.R8.truncate();
    *rax = context.Rax.truncate();
    *rcx = context.Rcx.truncate();
    *rdx = context.Rdx.truncate();
    *rsi = context.Rsi.truncate();
    *rdi = context.Rdi.truncate();
    *orig_rax = context.Rax.truncate();
    *rip = context.Rip.truncate();
    *eflags = context.EFlags as usize;
    *rsp = context.Rsp.truncate();
}

impl WindowsUserland {
    /// Create a new userland-Windows platform for use in `LiteBox`.
    ///
    /// # Panics
    ///
    /// Panics if the TLS slot cannot be created.
    pub fn new() -> &'static Self {
        let mut sys_info = Win32_SysInfo::SYSTEM_INFO::default();
        Self::get_system_information(&mut sys_info);

        // TODO(chuqi): Currently we just print system information for
        // `TASK_ADDR_MIN` and `TASK_ADDR_MAX`.
        // Will remove these prints once we have a better way to replace
        // the current `const` values in PageManagementProvider.
        println!("System information.");
        println!(
            "=> Max user address: {:#x}",
            sys_info.lpMaximumApplicationAddress as usize
        );
        println!(
            "=> Min user address: {:#x}",
            sys_info.lpMinimumApplicationAddress as usize
        );

        let reserved_pages = Self::read_memory_maps();

        let platform = Self {
            reserved_pages,
            sys_info: std::sync::RwLock::new(sys_info),
        };

        // Initialize it's own fs-base (for the main thread)
        WindowsUserland::init_thread_fs_base();

        // Windows sets FS_BASE to 0 regularly upon scheduling; we register an exception handler
        // to set FS_BASE back to a "stored" value whenever we notice that it has become 0.
        unsafe {
            let _ = AddVectoredExceptionHandler(0, Some(vectored_exception_handler));
        }

        Box::leak(Box::new(platform))
    }

    fn read_memory_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        let mut reserved_pages = alloc::vec::Vec::new();
        let mut address = 0usize;

        loop {
            let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            let ok = unsafe {
                Win32_Memory::VirtualQuery(
                    address as *const c_void,
                    &raw mut mbi,
                    core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
                ) != 0
            };
            if !ok {
                break;
            }

            if mbi.State == Win32_Memory::MEM_RESERVE || mbi.State == Win32_Memory::MEM_COMMIT {
                reserved_pages.push(core::ops::Range {
                    start: mbi.BaseAddress as usize,
                    end: (mbi.BaseAddress as usize + mbi.RegionSize),
                });
            }

            address = mbi.BaseAddress as usize + mbi.RegionSize;
            if address == 0 {
                break;
            }
        }

        reserved_pages
    }

    /// Retrieves information about the host platform (Windows).
    fn get_system_information(sys_info: &mut Win32_SysInfo::SYSTEM_INFO) {
        unsafe {
            Win32_SysInfo::GetSystemInfo(sys_info);
        }
    }

    fn round_up_to_granu(&self, x: usize) -> usize {
        let gran = self.sys_info.read().unwrap().dwAllocationGranularity as usize;
        (x + gran - 1) & !(gran - 1)
    }

    fn round_down_to_granu(&self, x: usize) -> usize {
        let gran = self.sys_info.read().unwrap().dwAllocationGranularity as usize;
        x & !(gran - 1)
    }

    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        // TODO: Currently we are using a static thread ID and credentials (faked).
        // This is a placeholder for future implementation to use passthrough.
        litebox_common_linux::TaskParams {
            pid: 1000,
            // TODO: placeholder for actual PPID
            ppid: 0,
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
        }
    }
}

impl litebox::platform::Provider for WindowsUserland {}

/// Runs a guest thread using the provided shim and the given initial context.
///
/// This will run until the thread terminates.
///
/// # Safety
/// The context must be valid guest context.
#[expect(
    clippy::missing_panics_doc,
    reason = "the caller cannot control whether this will panic"
)]
pub unsafe fn run_thread(
    shim: impl litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
) {
    // Allocate a TLS slot for this module if not already done. This is used as
    // a place to store data across calls to the guest, since all the registers
    // are used by the guest and will be clobbered.
    //
    // We use this instead of native TLS because accesses are easier from
    // assembly. In particular, finding the module's TLS base requires extra
    // registers and/or clobbering flags, whereas we can get the value of a
    // TLS slot with only one register and no changes to flags.
    static REGISTER_KEY: std::sync::Once = const { std::sync::Once::new() };
    REGISTER_KEY.call_once(|| {
        let index = unsafe { windows_sys::Win32::System::Threading::TlsAlloc() };
        assert!(
            index < 64,
            "no non-extended TLS slots available: {index:#x}"
        );
        TLS_INDEX.store(index, Ordering::Relaxed);
    });
    run_thread_inner(&shim, ctx);
}

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
) {
    let tls_index = TLS_INDEX.load(Ordering::Relaxed);
    let tls_state = TlsState {
        host_sp: Cell::new(core::ptr::null_mut()),
        host_bp: Cell::new(core::ptr::null_mut()),
        guest_context_top: std::ptr::from_mut(ctx).wrapping_add(1).into(),
        scratch: 0.into(),
        is_in_guest: false.into(),
        interrupt: false.into(),
        continue_context: Box::default(),
    };
    unsafe {
        windows_sys::Win32::System::Threading::TlsSetValue(
            tls_index,
            core::ptr::from_ref(&tls_state).cast(),
        );
    }
    let _tls_guard = litebox::utils::defer(|| unsafe {
        windows_sys::Win32::System::Threading::TlsSetValue(tls_index, core::ptr::null());
    });
    let mut thread_ctx = ThreadContext {
        shim,
        ctx,
        tls: &tls_state,
    };
    ThreadHandle::run_with_handle(&tls_state, || unsafe {
        run_thread_arch(&mut thread_ctx, &tls_state);
    });
}

static TLS_INDEX: AtomicU32 = AtomicU32::new(u32::MAX);

struct TlsState {
    host_sp: Cell<*mut u128>,
    host_bp: Cell<*mut u128>,
    guest_context_top: Cell<*mut litebox_common_linux::PtRegs>,
    scratch: Cell<usize>,
    is_in_guest: Cell<bool>,
    interrupt: Cell<bool>,
    continue_context:
        Box<std::cell::UnsafeCell<windows_sys::Win32::System::Diagnostics::Debug::CONTEXT>>,
}

fn get_tls_ptr() -> Option<*const TlsState> {
    let tls_index = TLS_INDEX.load(Ordering::Relaxed);
    if tls_index == u32::MAX {
        return None;
    }
    Some(unsafe {
        windows_sys::Win32::System::Threading::TlsGetValue(tls_index).cast::<TlsState>()
    })
}

/// Runs the guest thread until it terminates.
///
/// This saves all non-volatile register state then switches to the guest
/// context. When the guest makes a syscall, it jumps back into the middle of
/// this routine, at `syscall_callback`. This code then updates the guest
/// context structure, switches back to the host stack, and calls the syscall
/// handler.
///
/// When the guest thread terminates, this function returns after restoring
/// non-volatile register state.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C-unwind" fn run_thread_arch(thread_ctx: &mut ThreadContext, tls_state: &TlsState) {
    core::arch::naked_asm!(
    "
    .seh_proc run_thread
    // Push all non-volatiles
    push rbp
    .seh_pushreg rbp
    mov rbp, rsp
    .seh_setframe rbp, 0
    push rbx
    .seh_pushreg rbx
    push rdi
    .seh_pushreg rdi
    push rsi
    .seh_pushreg rsi
    push r12
    .seh_pushreg r12
    push r13
    .seh_pushreg r13
    push r14
    .seh_pushreg r14
    push r15
    .seh_pushreg r15
    sub rsp, 168 // align + space for xmm6-xmm15
    .seh_stackalloc 168
    movdqa [rsp + 0*16], xmm6
    .seh_savexmm xmm6, 0*16
    movdqa [rsp + 1*16], xmm7
    .seh_savexmm xmm7, 1*16
    movdqa [rsp + 2*16], xmm8
    .seh_savexmm xmm8, 2*16
    movdqa [rsp + 3*16], xmm9
    .seh_savexmm xmm9, 3*16
    movdqa [rsp + 4*16], xmm10
    .seh_savexmm xmm10, 4*16
    movdqa [rsp + 5*16], xmm11
    .seh_savexmm xmm11, 5*16
    movdqa [rsp + 6*16], xmm12
    .seh_savexmm xmm12, 6*16
    movdqa [rsp + 7*16], xmm13
    .seh_savexmm xmm13, 7*16
    movdqa [rsp + 8*16], xmm14
    .seh_savexmm xmm14, 8*16
    movdqa [rsp + 9*16], xmm15
    .seh_savexmm xmm15, 9*16
    .seh_endprologue

    // Offset into the TEB (gs segment) where TLS slots are stored.
    .equ TEB_TLS_SLOTS_OFFSET, 5248

    push    rcx // Alignment
    push    rcx // Save thread_ctx

    // Save the host rsp and rbp into the TLS state.
    mov     QWORD PTR [rdx + {HOST_SP}], rsp
    mov     QWORD PTR [rdx + {HOST_BP}], rbp

    call {init_handler}
    jmp .Ldone

    // This entry point is called from the guest when it issues a syscall
    // instruction.
    //
    // At entry, the register context is the guest context with the
    // return address in rcx. r11 is an available scratch register (it would
    // contain rflags if the syscall instruction had actually been issued).
    .globl  syscall_callback
syscall_callback:
    // Get the TLS state from the TLS slot and clear the in-guest flag.
    mov     r11d, DWORD PTR [rip + {TLS_INDEX}]
    mov     r11, QWORD PTR gs:[r11 * 8 + TEB_TLS_SLOTS_OFFSET]
    mov     BYTE PTR [r11 + {IS_IN_GUEST}], 0
    // Set rsp to the top of the guest context.
    mov     QWORD PTR [r11 + {SCRATCH}], rsp
    mov     rsp, QWORD PTR [r11 + {GUEST_CONTEXT_TOP}]

    // TODO: save float and vector registers (xsave or fxsave)
    // Save caller-saved registers
    push    0x2b       // pt_regs->ss = __USER_DS
    push    QWORD PTR [r11 + {SCRATCH}] // pt_regs->sp
    pushfq             // pt_regs->eflags
    push    0x33       // pt_regs->cs = __USER_CS
    push    rcx        // pt_regs->ip
    push    rax        // pt_regs->orig_ax

    push    rdi         // pt_regs->di
    push    rsi         // pt_regs->si
    push    rdx         // pt_regs->dx
    push    rcx         // pt_regs->cx
    push    -38         // pt_regs->ax = ENOSYS
    push    r8          // pt_regs->r8
    push    r9          // pt_regs->r9
    push    r10         // pt_regs->r10
    push    [rsp + 88]  // pt_regs->r11 = rflags
    push    rbx         // pt_regs->bx
    push    rbp         // pt_regs->bp
    push    r12
    push    r13
    push    r14
    push    r15

    /// Reestablish the stack and frame pointers.
    mov     rsp, [r11 + {HOST_SP}]
    mov     rbp, [r11 + {HOST_BP}]

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    mov  rcx, QWORD PTR [rsp] // thread_ctx
    call {syscall_handler}
    jmp .Ldone

exception_callback:
    // Handle the exception. The stack and frame pointers are already restored,
    // and the guest context is up to date. rcx contains a pointer to the
    // guest pt_regs, and rdx contains a pointer to the exception record.
    mov  rcx, QWORD PTR [rsp] // thread_ctx
    call {exception_handler}
    jmp .Ldone

interrupt_callback:
    mov  rcx, QWORD PTR [rsp] // thread_ctx
    call {interrupt_handler}
    jmp .Ldone

.Ldone:
    // Restore non-volatile registers and return.
    lea  rsp, [rbp - (168 + 56)]
    movdqa xmm6, [rsp + 0*16]
    movdqa xmm7, [rsp + 1*16]
    movdqa xmm8, [rsp + 2*16]
    movdqa xmm9, [rsp + 3*16]
    movdqa xmm10, [rsp + 4*16]
    movdqa xmm11, [rsp + 5*16]
    movdqa xmm12, [rsp + 6*16]
    movdqa xmm13, [rsp + 7*16]
    movdqa xmm14, [rsp + 8*16]
    movdqa xmm15, [rsp + 9*16]
    add rsp, 168 // 10 * 16 + 8 (for stack alignment)
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rdi
    pop  rbx
    pop  rbp
    ret
    .seh_endproc
    ",
    init_handler = sym init_handler,
    syscall_handler = sym syscall_handler,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    TLS_INDEX = sym TLS_INDEX,
    HOST_SP = const core::mem::offset_of!(TlsState, host_sp),
    HOST_BP = const core::mem::offset_of!(TlsState, host_bp),
    GUEST_CONTEXT_TOP = const core::mem::offset_of!(TlsState, guest_context_top),
    SCRATCH = const core::mem::offset_of!(TlsState, scratch),
    IS_IN_GUEST = const core::mem::offset_of!(TlsState, is_in_guest),
    );
}

/// Switches to the provided guest context.
///
/// # Safety
/// The context must be valid guest context. This can only be called if
/// `run_thread_arch` is on the stack; after the guest exits, it will return to
/// the interior of `run_thread_arch`.
///
/// Do not call this at a point where the stack needs to be unwound to run
/// destructors.
///
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    #[unsafe(naked)]
    extern "C" fn switch_to_guest_sysret(ctx: &litebox_common_linux::PtRegs) -> ! {
        core::arch::naked_asm!(
            // Load all registers from the guest context structure.
            "switch_to_guest_start:",
            "mov rsp, rcx",
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbp",
            "pop rbx",
            "pop r11",
            "pop r10",
            "pop r9",
            "pop r8",
            "pop rax",
            "pop rcx",
            "pop rdx",
            "pop rsi",
            "pop rdi",
            "pop rcx",    // skip orig_rax
            "pop rcx",    // read rip into rcx
            "add rsp, 8", // skip cs
            "popfq",
            "pop rsp",
            "jmp rcx", // jump to the entry point of the thread
            "switch_to_guest_end:",
        );
    }

    fn switch_to_guest_ntcontinue(tls: &TlsState, ctx: &litebox_common_linux::PtRegs) -> ! {
        use litebox::utils::ReinterpretSignedExt;
        use windows_sys::Win32::System::Diagnostics::Debug::{
            CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_INTEGER_AMD64,
        };
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtContinue(
                ctx: *const CONTEXT,
                raise_alert: u8,
            ) -> windows_sys::Win32::Foundation::NTSTATUS;
        }
        let win_ctx = tls.continue_context.get();
        // SAFETY: no other code accesses `continue_context` while `is_in_guest` is false.
        unsafe {
            win_ctx.write(CONTEXT {
                ContextFlags: CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64,
                EFlags: ctx.eflags.truncate(),
                Rax: ctx.rax as u64,
                Rcx: ctx.rcx as u64,
                Rdx: ctx.rdx as u64,
                Rbx: ctx.rbx as u64,
                Rsp: ctx.rsp as u64,
                Rbp: ctx.rbp as u64,
                Rsi: ctx.rsi as u64,
                Rdi: ctx.rdi as u64,
                R8: ctx.r8 as u64,
                R9: ctx.r9 as u64,
                R10: ctx.r10 as u64,
                R11: ctx.r11 as u64,
                R12: ctx.r12 as u64,
                R13: ctx.r13 as u64,
                R14: ctx.r14 as u64,
                R15: ctx.r15 as u64,
                Rip: ctx.rip as u64,
                ..CONTEXT::default()
            });
        }
        // Ensure the context is written before we set `is_in_guest` so that
        // `ThreadHandle::interrupt` can see a consistent state.
        std::sync::atomic::compiler_fence(Ordering::Release);
        tls.is_in_guest.set(true);
        unsafe {
            let status = NtContinue(win_ctx, 0);
            panic!(
                "NtContinue failed: {}",
                std::io::Error::from_raw_os_error(
                    windows_sys::Win32::Foundation::RtlNtStatusToDosError(status)
                        .reinterpret_as_signed(),
                ),
            );
        }
    }

    let tls = unsafe { &*get_tls_ptr().expect("TLS not initialized") };
    assert!(!tls.is_in_guest.get());

    // Restore fsbase for the guest.
    WindowsUserland::restore_thread_fs_base();

    // The fast path for switching to the guest relies on rcx == rip. This is
    // the common case, because the syscall instruction sets rcx to rip at entry
    // to the kernel. When this is not the case, we use NtContinue to jump to
    // the guest with the full register state.
    //
    // This is much slower, but it is only used for things like signal handlers,
    // so it should not be on the critical path.
    if ctx.rcx == ctx.rip {
        tls.is_in_guest.set(true);
        switch_to_guest_sysret(ctx)
    } else {
        switch_to_guest_ntcontinue(tls, ctx)
    }
}

fn thread_start(
    init_thread: Box<
        dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
    >,
    mut ctx: litebox_common_linux::PtRegs,
) {
    // Allow caller to run some code before we return to the new thread.
    let shim = init_thread.init();

    run_thread_inner(shim.as_ref(), &mut ctx);
}

impl litebox::platform::ThreadProvider for WindowsUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        init_thread: Box<
            dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        let ctx = ctx.clone();
        // TODO: do we need to wait for the handle in the main thread?
        let _handle = std::thread::Builder::new().spawn(move || thread_start(init_thread, ctx))?;

        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        CURRENT_THREAD_HANDLE.with_borrow(|current| {
            current
                .clone()
                .expect("current thread is not managed by LiteBox")
        })
    }

    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        CURRENT_THREAD_HANDLE.with_borrow(|current| {
            thread.interrupt(current.as_ref());
        });
    }
}

#[derive(Clone)]
pub struct ThreadHandle(Arc<Mutex<Option<ThreadHandleInner>>>);

struct ThreadHandleInner {
    handle: std::os::windows::io::OwnedHandle,
    tls: SendConstPtr<TlsState>,
}

struct SendConstPtr<T>(*const T);
unsafe impl<T> Send for SendConstPtr<T> {}

thread_local! {
    static CURRENT_THREAD_HANDLE: RefCell<Option<ThreadHandle>> = const { RefCell::new(None) };
}

impl ThreadHandle {
    /// Runs `f`, ensuring that [`CURRENT_THREAD_HANDLE`] is set while in the call to `f`.
    fn run_with_handle<R>(tls: &TlsState, f: impl FnOnce() -> R) -> R {
        let win_handle = unsafe {
            std::os::windows::io::BorrowedHandle::borrow_raw(
                windows_sys::Win32::System::Threading::GetCurrentThread(),
            )
        };
        let handle = ThreadHandle(Arc::new(Mutex::new(Some(ThreadHandleInner {
            handle: win_handle
                .try_clone_to_owned()
                .expect("failed to clone current thread handle"),
            tls: SendConstPtr(tls),
        }))));
        CURRENT_THREAD_HANDLE.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "nested run_with_handle calls are not supported"
            );
            *current = Some(handle);
        });
        let _guard = litebox::utils::defer(|| {
            let current = CURRENT_THREAD_HANDLE.take().unwrap();
            *current.0.lock().unwrap() = None;
        });
        f()
    }

    /// Interrupt the thread represented by this handle, where `current` is the
    /// current thread's handle if it is managed by LiteBox.
    ///
    /// The basic strategy is this:
    /// 1. Suspend the target thread.
    /// 2. Access its TLS state to check if it's in the guest.
    /// 3. If it's not actually in the guest, set the interrupt flag and resume,
    ///    with some careful handling to make sure the interrupt flag is
    ///    evaluated upon return to the guest in all cases.
    /// 4. If it is in the guest, save the guest context and set the thread
    ///    context to resume at the interrupt callback.
    /// 5. Resume the target thread.
    fn interrupt(&self, current: Option<&ThreadHandle>) {
        /// Helper to lock two mutexes in address order, to prevent deadlock.
        fn lock_two<'a, T, U>(
            left: &'a Mutex<T>,
            right: &'a Mutex<U>,
        ) -> (std::sync::MutexGuard<'a, T>, std::sync::MutexGuard<'a, U>) {
            if std::ptr::from_ref(left).addr() < std::ptr::from_ref(right).addr() {
                let l = left.lock().unwrap();
                let r = right.lock().unwrap();
                (l, r)
            } else {
                let r = right.lock().unwrap();
                let l = left.lock().unwrap();
                (l, r)
            }
        }

        let (_current_guard, target) = if let Some(current) = current {
            if Arc::ptr_eq(&current.0, &self.0) {
                // Interrupting self; just set the flag.
                (unsafe { &*get_tls_ptr().unwrap() }).interrupt.set(true);
                return;
            }

            // Lock both the current and target thread handles so that this
            // thread is not suspended while holding the target thread lock.
            let (c, t) = lock_two(&current.0, &self.0);
            (Some(c), t)
        } else {
            // The current thread can't be suspended since it's not managed by LiteBox.
            (None, self.0.lock().unwrap())
        };
        let Some(inner) = target.as_ref() else {
            // The target is no longer managed by LiteBox.
            return;
        };

        // Suspend the target thread.
        unsafe {
            windows_sys::Win32::System::Threading::SuspendThread(inner.handle.as_raw_handle());
        }
        let _resume_guard = litebox::utils::defer(|| unsafe {
            windows_sys::Win32::System::Threading::ResumeThread(inner.handle.as_raw_handle());
        });

        // SAFETY: The target TLS state is accessible while the thread is
        // suspended.
        let target_tls = unsafe { &*inner.tls.0 };

        // Write the target interrupt flag.
        target_tls.interrupt.set(true);

        if !target_tls.is_in_guest.get() {
            // Not running in the guest. The interrupt flag will be checked
            // before returning to the guest, so just resume.
            return;
        }

        let guest_context = target_tls.guest_context_top.get().wrapping_sub(1);

        // Running in the guest. There are multiple possibilities:
        //
        // 1. The thread is in the middle of returning to the guest via the
        //    register pop path. Don't save context but do jump to the interrupt
        //    callback.
        // 2. The thread is in the middle of returning to the guest via the
        //    NtContinue path. Update the NtContinue context to point to the
        //    interrupt callback.
        // 3. The thread is beginning to handle an exception. Don't do anything;
        //    this path will check the interrupt flag.
        // 4. In the guest. Save the guest context and jump to the interrupt callback.

        // Get the current register context.
        let mut context = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT {
            ContextFlags: windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64
                | windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_INTEGER_AMD64,
            ..Default::default()
        };
        let r = unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::GetThreadContext(
                inner.handle.as_raw_handle(),
                &raw mut context,
            )
        };
        assert_ne!(
            r,
            0,
            "GetThreadContext failed: {}",
            std::io::Error::last_os_error()
        );

        let run_interrupt_callback = if (switch_to_guest_start as *const () as usize
            ..switch_to_guest_end as *const () as usize)
            .contains(&(context.Rip.truncate()))
        {
            // Case 1: jump to interrupt callback without saving the guest
            // context, since it's already saved.
            true
        } else if is_in_ntdll_or_this(context.Rip.truncate()) {
            // Case 2/3: we can't distinguish between them. For case 2 we don't
            // need to do anything, but for case 3 we need to update the
            // NtContinue context to point to the interrupt callback (the guest
            // context is already up to date).
            //
            // In case 2, the NtContinue context is not being used, so it is
            // safe to update it anyway.

            // SAFETY: `continue_context` is not accessed by user-mode code
            // while `is_in_guest` is true.
            let continue_context = unsafe { &mut *target_tls.continue_context.get() };
            set_context_to_interrupt_callback(target_tls, continue_context);
            false
        } else {
            // Case 4: save the guest context and jump to interrupt callback.
            save_guest_context(unsafe { &mut *guest_context }, &context);
            true
        };
        if run_interrupt_callback {
            set_context_to_interrupt_callback(target_tls, &mut context);
            unsafe {
                windows_sys::Win32::System::Diagnostics::Debug::SetThreadContext(
                    inner.handle.as_raw_handle(),
                    &raw const context,
                );
            }
        }
    }
}

/// Updates `context` to jump to the interrupt callback with the given
/// `guest_context` pointer.
fn set_context_to_interrupt_callback(
    tls: &TlsState,
    context: &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    let required_flags = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64
        | windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_INTEGER_AMD64;
    assert!(context.ContextFlags & required_flags == required_flags);
    context.Rip = interrupt_callback as *const () as usize as u64;
    context.Rsp = tls.host_sp.get().addr() as u64;
    context.Rbp = tls.host_bp.get().addr() as u64;
}

/// Returns true if the given instruction pointer is in ntdll.dll or this module.
fn is_in_ntdll_or_this(ip: usize) -> bool {
    static BOUNDS: OnceLock<[std::ops::Range<usize>; 2]> = const { OnceLock::new() };

    let bounds = BOUNDS.get_or_init(|| {
        unsafe extern "C" {
            safe static __ImageBase: c_void;
        }
        fn module_bounds(module: *const c_void) -> std::ops::Range<usize> {
            let mut module_info = windows_sys::Win32::System::ProcessStatus::MODULEINFO::default();
            let r = unsafe {
                windows_sys::Win32::System::ProcessStatus::GetModuleInformation(
                    windows_sys::Win32::System::Threading::GetCurrentProcess(),
                    module.cast_mut(),
                    &raw mut module_info,
                    size_of_val(&module_info).try_into().unwrap(),
                )
            };
            assert_ne!(
                r,
                0,
                "GetModuleInformation failed: {}",
                std::io::Error::last_os_error()
            );
            let start = module_info.lpBaseOfDll.addr();
            let end = start + module_info.SizeOfImage as usize;
            start..end
        }

        let ntdll = unsafe {
            windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(windows_sys::w!(
                "ntdll.dll"
            ))
        };
        [module_bounds(ntdll), module_bounds(&raw const __ImageBase)]
    });

    bounds.iter().any(|b| b.contains(&ip))
}

impl litebox::platform::RawMutexProvider for WindowsUserland {
    type RawMutex = RawMutex;
}

// A skeleton of a raw mutex for Windows.
pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
    inner: AtomicU32,
}

impl RawMutex {
    const fn new() -> Self {
        Self {
            inner: AtomicU32::new(0),
        }
    }

    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // We immediately wake up (without even hitting syscalls) if we can clearly see that the
        // value is different.
        if self.inner.load(Ordering::SeqCst) != val {
            return Err(ImmediatelyWokenUp);
        }

        // Compute timeout in ms
        let timeout_ms = match timeout {
            None => Win32_Threading::INFINITE, // no timeout
            Some(timeout) => {
                let ms = timeout.as_millis();
                ms.min(u128::from(Win32_Threading::INFINITE - 1)).truncate()
            }
        };

        let ok = unsafe {
            Win32_Threading::WaitOnAddress(
                (&raw const self.inner).cast::<c_void>(),
                (&raw const val).cast::<c_void>(),
                std::mem::size_of::<u32>(),
                timeout_ms,
            ) != 0
        };

        if ok {
            Ok(UnblockedOrTimedOut::Unblocked)
        } else {
            // Check why WaitOnAddress failed
            let err = unsafe { GetLastError() };
            match err {
                Win32_Foundation::ERROR_TIMEOUT => {
                    // Timed out
                    Ok(UnblockedOrTimedOut::TimedOut)
                }
                e => {
                    // Other error, possibly spurious wakeup or value changed
                    // Continue the loop to check the value again
                    panic!("Unexpected error={e} for WaitOnAddress");
                }
            }
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        assert!(n > 0, "wake_many should be called with n > 0");
        let n: u32 = n.try_into().unwrap();

        let mutex = core::ptr::from_ref(self.underlying_atomic()).cast::<c_void>();
        unsafe {
            if n == 1 {
                Win32_Threading::WakeByAddressSingle(mutex);
            } else if n >= i32::MAX as u32 {
                Win32_Threading::WakeByAddressAll(mutex);
            } else {
                // Wake up `n` threads iteratively
                for _ in 0..n {
                    Win32_Threading::WakeByAddressSingle(mutex);
                }
            }
        }

        // For windows, the OS kernel does not tell us how many threads were actually woken up,
        // so we just return `n`
        n as usize
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_or_maybe_timeout(val, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => unreachable!(),
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val, Some(timeout))
    }
}

impl litebox::platform::IPInterfaceProvider for WindowsUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        unimplemented!(
            "send_ip_packet is not implemented for Windows yet. packet length: {}",
            packet.len()
        );
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        unimplemented!(
            "receive_ip_packet is not implemented for Windows yet. packet length: {}",
            packet.len()
        );
    }
}

impl litebox::platform::TimeProvider for WindowsUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        let mut ts = 0;
        unsafe { QueryUnbiasedInterruptTimePrecise(&raw mut ts) };
        Instant(ts)
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut filetime = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        unsafe {
            GetSystemTimePreciseAsFileTime(&raw mut filetime);
        }
        let FILETIME {
            dwLowDateTime: low,
            dwHighDateTime: high,
        } = filetime;
        let filetime = (u64::from(high) << 32) | u64::from(low);
        SystemTime { filetime }
    }
}

/// 100ns units returned by `QueryUnbiasedInterruptTimePrecise`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        let diff = self.0.checked_sub(earlier.0)?;
        // Convert from 100ns intervals to nanoseconds. This won't overflow in
        // our lifetimes.
        Some(Duration::from_nanos(diff * 100))
    }

    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        let duration_100ns: u64 = (duration.as_nanos() / 100).try_into().ok()?;
        let new = self.0.checked_add(duration_100ns)?;
        Some(Instant(new))
    }
}

pub struct SystemTime {
    // 100ns intervals since Windows epoch
    filetime: u64,
}

impl litebox::platform::SystemTime for SystemTime {
    // Windows epoch: Jan 1, 1601
    // Unix epoch: Jan 1, 1970
    // Difference: 11644473600 seconds
    // Intervals: 100ns intervals
    // Seconds per interval: 10^-7
    const UNIX_EPOCH: Self = SystemTime {
        filetime: 11_644_473_600 * 10_000_000,
    };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        if self.filetime >= earlier.filetime {
            let diff_100ns = self.filetime - earlier.filetime;
            let nanos = diff_100ns * 100;
            let secs = nanos / 1_000_000_000;
            let remaining_nanos = nanos % 1_000_000_000;
            Ok(core::time::Duration::new(secs, remaining_nanos as u32))
        } else {
            let diff_100ns = earlier.filetime - self.filetime;
            let nanos = diff_100ns * 100;
            let secs = nanos / 1_000_000_000;
            let remaining_nanos = nanos % 1_000_000_000;
            Err(core::time::Duration::new(secs, remaining_nanos as u32))
        }
    }
}

pub struct PunchthroughToken<'a> {
    punchthrough: PunchthroughSyscall<'a, WindowsUserland>,
}

impl<'a> litebox::platform::PunchthroughToken for PunchthroughToken<'a> {
    type Punchthrough = PunchthroughSyscall<'a, WindowsUserland>;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<
            <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnFailure,
        >,
    > {
        match self.punchthrough {
            PunchthroughSyscall::SetFsBase { addr } => {
                // Use WindowsUserland's per-thread FS base management system
                WindowsUserland::set_thread_fs_base(addr);
                Ok(0)
            }
            PunchthroughSyscall::GetFsBase => {
                // Use the stored FS base value from our per-thread storage
                Ok(WindowsUserland::get_thread_fs_base())
            }
        }
    }
}

impl litebox::platform::PunchthroughProvider for WindowsUserland {
    type PunchthroughToken<'a> = PunchthroughToken<'a>;
    fn get_punchthrough_token_for<'a>(
        &self,
        punchthrough: <Self::PunchthroughToken<'a> as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'a>> {
        Some(PunchthroughToken { punchthrough })
    }
}

impl litebox::platform::DebugLogProvider for WindowsUserland {
    fn debug_log_print(&self, msg: &str) {
        // TODO: Implement Windows debug logging
        // For now, use standard error output
        use std::io::Write;
        let _ = std::io::stderr().write_all(msg.as_bytes());
    }
}

type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;

impl litebox::platform::RawPointerProvider for WindowsUserland {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

#[allow(
    clippy::match_same_arms,
    reason = "Iterate over all cases for prot_flags."
)]
fn prot_flags(flags: MemoryRegionPermissions) -> Win32_Memory::PAGE_PROTECTION_FLAGS {
    match (
        flags.contains(MemoryRegionPermissions::READ),
        flags.contains(MemoryRegionPermissions::WRITE),
        flags.contains(MemoryRegionPermissions::EXEC),
    ) {
        // no permissions
        (false, false, false) => Win32_Memory::PAGE_NOACCESS,
        // read-only
        (true, false, false) => Win32_Memory::PAGE_READONLY,
        // write-only (Windows doesn't have write-only, so we use r+w)
        (false, true, false) => Win32_Memory::PAGE_READWRITE,
        // read-write
        (true, true, false) => Win32_Memory::PAGE_READWRITE,
        // exeute-only (Windows doesn't have execute-only, so we use r+x)
        (false, false, true) => Win32_Memory::PAGE_EXECUTE_READ,
        // read-execute
        (true, false, true) => Win32_Memory::PAGE_EXECUTE_READ,
        // write-execute (Windows doesn't have write-execute, so we use rwx)
        (false, true, true) => Win32_Memory::PAGE_EXECUTE_READWRITE,
        // read-write-execute
        (true, true, true) => Win32_Memory::PAGE_EXECUTE_READWRITE,
    }
}

fn do_prefetch_on_range(start: usize, size: usize) {
    let ok = unsafe {
        let prefetch_entry = Win32_Memory::WIN32_MEMORY_RANGE_ENTRY {
            VirtualAddress: start as *mut c_void,
            NumberOfBytes: size,
        };
        PrefetchVirtualMemory(GetCurrentProcess(), 1, &raw const prefetch_entry, 0) != 0
    };
    assert!(ok, "PrefetchVirtualMemory failed with error: {}", unsafe {
        GetLastError()
    });
}

fn do_query_on_region(mbi: &mut Win32_Memory::MEMORY_BASIC_INFORMATION, base_addr: *mut c_void) {
    let ok = unsafe {
        Win32_Memory::VirtualQuery(
            base_addr,
            mbi,
            core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
        ) != 0
    };
    assert!(ok, "VirtualQuery addr={:p} failed: {}", base_addr, unsafe {
        GetLastError()
    });
}

/// Helper method to process a memory range by iterating through Windows memory regions.
///
/// Windows memory is managed in Virtual Address Descriptors (VADs) at the NT kernel level,
/// which means a single user-space range might span multiple regions. This helper method
/// queries each region within the specified range and applies the given operation.
///
/// # Parameters
/// - `range`: The memory range to process
/// - `operation`: A closure that takes (region_range, region_state) and returns Result<bool, E>.
///
/// # Panics
///
/// Panics if the operation returns false for any region.
fn process_memory_range_by_regions<F, E>(
    mut range: core::ops::Range<usize>,
    mut operation: F,
) -> Result<(), E>
where
    F: FnMut(core::ops::Range<usize>, Win32_Memory::VIRTUAL_ALLOCATION_TYPE) -> Result<bool, E>,
{
    while !range.is_empty() {
        let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut mbi, range.start as *mut c_void);
        debug_assert_eq!(range.start, mbi.BaseAddress as usize);
        let len = mbi.RegionSize.min(range.len());
        let success = operation(range.start..range.start + len, mbi.State)?;
        assert!(
            success,
            "operation failed on region {:p}-{:p}: {}",
            range.start as *mut c_void,
            (range.start + len) as *mut c_void,
            std::io::Error::last_os_error()
        );
        range = (range.start + len)..range.end;
    }
    Ok(())
}

macro_rules! debug_assert_alignment {
    ($r:ident, $page_size:expr) => {
        debug_assert!($r.start.is_multiple_of($page_size));
        debug_assert!($r.end.is_multiple_of($page_size));
    };
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for WindowsUserland {
    // TODO(chuqi): These are currently "magic numbers" grabbed from my Windows 11 SystemInformation.
    // The actual values should be determined by `GetSystemInfo()`.
    //
    // NOTE: make sure the values are PAGE_ALIGNED.
    const TASK_ADDR_MIN: usize = 0x1_0000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;
    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        debug_assert!(ALIGN.is_multiple_of(self.sys_info.read().unwrap().dwPageSize as usize));
        debug_assert_alignment!(suggested_range, ALIGN);

        // A helper closure to reserve and commit memory in one go.
        //
        // Note that MEM_RESERVE requires the base address to be aligned to system allocation granularity,
        // while MEM_COMMIT only requires page-aligned address.
        //
        // To ensure future MEM_COMMIT calls on sub-ranges succeed, we always reserve the entire aligned range
        // (i.e., MEM_RESERVE size is also made aligned to system allocation granularity).
        let reserve_and_commit = |r: core::ops::Range<usize>,
                                  flags: Win32_Memory::PAGE_PROTECTION_FLAGS|
         -> *mut c_void {
            let aligned_start_addr = self.round_down_to_granu(r.start);
            let aligned_end_addr = self.round_up_to_granu(r.end);
            let ptr = unsafe {
                VirtualAlloc2(
                    GetCurrentProcess(),
                    aligned_start_addr as *mut c_void,
                    aligned_end_addr - aligned_start_addr,
                    Win32_Memory::MEM_RESERVE,
                    Win32_Memory::PAGE_NOACCESS,
                    core::ptr::null_mut(),
                    0,
                )
            };
            if ptr.is_null() {
                core::ptr::null_mut()
            } else {
                unsafe {
                    VirtualAlloc2(
                        GetCurrentProcess(),
                        if r.start == 0 {
                            ptr
                        } else {
                            r.start as *mut c_void
                        },
                        r.len(),
                        Win32_Memory::MEM_COMMIT,
                        flags,
                        core::ptr::null_mut(),
                        0,
                    )
                }
            }
        };

        let mut base_addr = suggested_range.start as *mut c_void;
        let size = suggested_range.len();
        // TODO: For Windows, there is no MAP_GROWDOWN features so far.
        let _ = can_grow_down;

        if suggested_range.start != 0 {
            assert!(suggested_range.start >= <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::
                                                            TASK_ADDR_MIN);
            assert!(suggested_range.end <= <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::
                                                            TASK_ADDR_MAX);

            let has_committed_page =
                process_memory_range_by_regions(suggested_range.clone(), |_r, state| {
                    if state == Win32_Memory::MEM_COMMIT {
                        Err(())
                    } else {
                        Ok(true)
                    }
                })
                .is_err();
            if has_committed_page && fixed_address_behavior == FixedAddressBehavior::Hint {
                // If any page in the suggested range is already committed, and the caller
                // did not request a fixed address, we ask the OS to allocate a new region.
                base_addr = core::ptr::null_mut();
            } else if has_committed_page
                && fixed_address_behavior == FixedAddressBehavior::NoReplace
            {
                return Err(AllocationError::AddressInUse);
            } else {
                process_memory_range_by_regions(
                    suggested_range,
                    |r, state| -> Result<bool, std::convert::Infallible> {
                        let ok = match state {
                            // In case the region is already reserved, we just need to commit it.
                            // In case the region is already committed, decommit and recommit it.
                            Win32_Memory::MEM_RESERVE | Win32_Memory::MEM_COMMIT => {
                                if state == Win32_Memory::MEM_COMMIT {
                                    // TODO: handle this race condition properly.
                                    assert_eq!(
                                        fixed_address_behavior,
                                        FixedAddressBehavior::Replace,
                                        "raced with another memory allocator"
                                    );
                                    let decommit_ok = unsafe {
                                        VirtualFree(
                                            r.start as *mut c_void,
                                            r.len(),
                                            Win32_Memory::MEM_DECOMMIT,
                                        )
                                    } != 0;
                                    assert!(
                                        decommit_ok,
                                        "VirtualFree(DECOMMIT) failed: {}",
                                        unsafe { GetLastError() }
                                    );
                                }
                                let ptr = unsafe {
                                    VirtualAlloc2(
                                        GetCurrentProcess(),
                                        r.start as *mut c_void,
                                        r.len(),
                                        Win32_Memory::MEM_COMMIT,
                                        prot_flags(initial_permissions),
                                        core::ptr::null_mut(),
                                        0,
                                    )
                                };
                                !ptr.is_null()
                            }
                            // In case the region is free, we need to reserve and commit it.
                            Win32_Memory::MEM_FREE => {
                                let ptr =
                                    reserve_and_commit(r.clone(), prot_flags(initial_permissions));
                                !ptr.is_null()
                            }
                            _ => unimplemented!(
                                "Unexpected memory state: {:?} when allocating pages",
                                state
                            ),
                        };
                        // Prefetch the memory range if requested
                        if ok && populate_pages_immediately {
                            do_prefetch_on_range(r.start, r.len());
                        }
                        Ok(ok)
                    },
                )
                .unwrap();
                return Ok(UserMutPtr::from_ptr(base_addr.cast()));
            }
        }

        debug_assert!(base_addr.is_null());
        let ptr = reserve_and_commit(0..size, prot_flags(initial_permissions));
        assert!(
            !ptr.is_null(),
            "VirtualAlloc2(RESERVE|COMMIT size=0x{:x}) failed: {}",
            size,
            std::io::Error::last_os_error()
        );

        // Prefetch the memory range if requested
        if populate_pages_immediately {
            do_prefetch_on_range(ptr as usize, size);
        }
        Ok(UserMutPtr::from_ptr(ptr.cast::<u8>()))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        debug_assert_alignment!(range, ALIGN);
        process_memory_range_by_regions(
            range,
            |r, state| -> Result<bool, std::convert::Infallible> {
                debug_assert_ne!(
                    state,
                    Win32_Memory::MEM_FREE,
                    "Trying to deallocate a free region: {:p}-{:p}",
                    r.start as *mut c_void,
                    r.end as *mut c_void
                );
                Ok(unsafe {
                    VirtualFree(r.start as *mut c_void, r.len(), Win32_Memory::MEM_DECOMMIT)
                } != 0)
            },
        )
        .expect("deallocate_pages failed");
        Ok(())
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        debug_assert_alignment!(range, ALIGN);
        let flags = prot_flags(new_permissions);
        process_memory_range_by_regions(
            range,
            |r, state| -> Result<bool, std::convert::Infallible> {
                debug_assert_eq!(
                    state,
                    Win32_Memory::MEM_COMMIT,
                    "Trying to change permissions on a non-committed region: {:p}-{:p}",
                    r.start as *mut c_void,
                    r.end as *mut c_void
                );
                let mut old_protect: u32 = 0;
                Ok(unsafe {
                    VirtualProtect(r.start as *mut c_void, r.len(), flags, &raw mut old_protect)
                } != 0)
            },
        )
        .expect("update_permissions failed");
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &std::ops::Range<usize>> {
        self.reserved_pages.iter()
    }
}

impl litebox::platform::StdioProvider for WindowsUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        use std::io::Read as _;
        std::io::stdin().read(buf).map_err(|err| {
            if err.kind() == std::io::ErrorKind::BrokenPipe {
                litebox::platform::StdioReadError::Closed
            } else {
                panic!("unhandled error {err}")
            }
        })
    }

    fn write_to(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        use std::io::Write as _;
        match stream {
            litebox::platform::StdioOutStream::Stdout => {
                std::io::stdout().write(buf).map_err(|err| {
                    if err.kind() == std::io::ErrorKind::BrokenPipe {
                        litebox::platform::StdioWriteError::Closed
                    } else {
                        panic!("unhandled error {err}")
                    }
                })
            }
            litebox::platform::StdioOutStream::Stderr => {
                std::io::stderr().write(buf).map_err(|err| {
                    if err.kind() == std::io::ErrorKind::BrokenPipe {
                        litebox::platform::StdioWriteError::Closed
                    } else {
                        panic!("unhandled error {err}")
                    }
                })
            }
        }
    }

    fn is_a_tty(&self, stream: litebox::platform::StdioStream) -> bool {
        use litebox::platform::StdioStream;
        use std::io::IsTerminal as _;
        match stream {
            StdioStream::Stdin => std::io::stdin().is_terminal(),
            StdioStream::Stdout => std::io::stdout().is_terminal(),
            StdioStream::Stderr => std::io::stderr().is_terminal(),
        }
    }
}

#[global_allocator]
static SLAB_ALLOC: litebox::mm::allocator::SafeZoneAllocator<'static, 28, WindowsUserland> =
    litebox::mm::allocator::SafeZoneAllocator::new();

impl litebox::mm::allocator::MemoryProvider for WindowsUserland {
    fn alloc(layout: &std::alloc::Layout) -> Option<(usize, usize)> {
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            // Note `mmap` provides no guarantee of alignment, so we double the size to ensure we
            // can always find a required chunk within the returned memory region.
            core::cmp::max(layout.align(), 0x1000) << 1,
        );

        match unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                core::ptr::null_mut(),
                size,
                Win32_Memory::MEM_COMMIT | Win32_Memory::MEM_RESERVE,
                Win32_Memory::PAGE_READWRITE,
                core::ptr::null_mut(),
                0,
            )
        } {
            addr if addr.is_null() => None,
            addr => Some((addr as usize, size)),
        }
    }

    unsafe fn free(_addr: usize) {
        unimplemented!("Memory deallocation is not implemented for Windows yet.");
    }
}

unsafe extern "C" {
    // Defined in asm blocks above
    fn syscall_callback() -> isize;
    fn exception_callback() -> isize;
    fn interrupt_callback();
    fn switch_to_guest_start();
    fn switch_to_guest_end();
}

unsafe extern "C-unwind" fn init_handler(thread_ctx: &mut ThreadContext<'_>) {
    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.init(ctx));
}

unsafe extern "C-unwind" fn syscall_handler(thread_ctx: &mut ThreadContext<'_>) {
    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.syscall(ctx));
}

unsafe extern "C-unwind" fn exception_handler(
    thread_ctx: &mut ThreadContext<'_>,
    exception_record: &EXCEPTION_RECORD,
) {
    let (exception, error_code, cr2) = match exception_record.ExceptionCode {
        Win32_Foundation::EXCEPTION_ACCESS_VIOLATION => {
            let info = exception_record.ExceptionInformation;
            let read_write_flag = info[0];
            let faulting_address = info[1];
            if read_write_flag == 0 && faulting_address == !0 {
                // This is probably a #GP, not a #PF.
                (Exception::GENERAL_PROTECTION_FAULT, 0, 0)
            } else {
                let error_code = 4 | if read_write_flag == 0 { 0 } else { 1 << 1 }; // PF error code: bit 1 = write
                (Exception::PAGE_FAULT, error_code, faulting_address)
            }
        }
        Win32_Foundation::EXCEPTION_ILLEGAL_INSTRUCTION => (Exception::INVALID_OPCODE, 0, 0),
        Win32_Foundation::EXCEPTION_BREAKPOINT => (Exception::BREAKPOINT, 0, 0),
        Win32_Foundation::EXCEPTION_INT_DIVIDE_BY_ZERO => (Exception::DIVIDE_ERROR, 0, 0),
        code => panic!("Unhandled Win32 exception code: {:#x}", code),
    };

    let info = litebox::shim::ExceptionInfo {
        exception,
        error_code,
        cr2,
        kernel_mode: false,
    };

    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.exception(ctx, &info));
}

unsafe extern "C-unwind" fn interrupt_handler(thread_ctx: &mut ThreadContext<'_>) {
    thread_ctx.call_shim(|shim, ctx, interrupt| {
        if interrupt {
            shim.interrupt(ctx)
        } else {
            // We likely got here just to restore fsbase, so don't bother the
            // shim.
            ContinueOperation::Resume
        }
    });
}

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &'a mut litebox_common_linux::PtRegs,
    tls: &'a TlsState,
}

impl ThreadContext<'_> {
    /// Calls `f` in order to call into a shim entrypoint.
    fn call_shim(
        &mut self,
        f: impl FnOnce(
            &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
            &mut litebox_common_linux::PtRegs,
            bool,
        ) -> ContinueOperation,
    ) {
        // Clear the interrupt flag before calling the shim, since we've handled it
        // now (by calling into the shim), and it might be set again by the shim
        // before returning.
        let op = f(self.shim, self.ctx, self.tls.interrupt.replace(false));
        match op {
            ContinueOperation::Resume => unsafe { switch_to_guest(self.ctx) },
            ContinueOperation::Terminate => {}
        }
    }
}

impl litebox::platform::SystemInfoProvider for WindowsUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as *const () as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
        // Windows doesn't have VDSO equivalent, return None
        None
    }
}

thread_local! {
    // Use `ManuallyDrop` for more efficient TLS accesses, since this is always
    // dropped manually before the thread exits.
    static PLATFORM_TLS: Cell<*mut ()> = const { Cell::new(core::ptr::null_mut()) };
}

/// WindowsUserland platform's thread-local storage implementation.
unsafe impl litebox::platform::ThreadLocalStorageProvider for WindowsUserland {
    fn get_thread_local_storage() -> *mut () {
        PLATFORM_TLS.get()
    }

    unsafe fn replace_thread_local_storage(new_tls: *mut ()) -> *mut () {
        PLATFORM_TLS.replace(new_tls)
    }

    fn clear_guest_thread_local_storage() {
        Self::init_thread_fs_base();
    }
}

impl litebox::platform::CrngProvider for WindowsUserland {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

/// Dummy `VmemPageFaultHandler`.
///
/// Page faults are handled transparently by the host Windows kernel.
/// Provided to satisfy trait bounds for `PageManager::handle_page_fault`.
impl litebox::mm::linux::VmemPageFaultHandler for WindowsUserland {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox::mm::linux::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unreachable!("host kernel handles page faults for Windows userland")
    }

    fn access_error(_error_code: u64, _flags: litebox::mm::linux::VmFlags) -> bool {
        unreachable!("host kernel handles page faults for Windows userland")
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use std::thread::sleep;

    use crate::WindowsUserland;
    use crate::process_memory_range_by_regions;
    use litebox::platform::PageManagementProvider;
    use litebox::platform::RawConstPointer;
    use litebox::platform::RawMutex;
    use litebox::platform::page_mgmt::FixedAddressBehavior;
    use litebox::platform::page_mgmt::MemoryRegionPermissions;

    #[test]
    fn test_raw_mutex() {
        let mutex = std::sync::Arc::new(super::RawMutex {
            inner: AtomicU32::new(0),
        });

        let copied_mutex = mutex.clone();
        std::thread::spawn(move || {
            sleep(core::time::Duration::from_millis(500));
            copied_mutex
                .inner
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            copied_mutex.wake_many(10);
        });

        assert!(mutex.block(0).is_ok());
    }

    #[test]
    fn test_reserved_pages() {
        let platform = WindowsUserland::new();
        let reserved_pages: Vec<_> =
            <WindowsUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

        // Check that the reserved pages are not empty
        assert!(!reserved_pages.is_empty(), "No reserved pages found");

        // Check that the reserved pages are in order and non-overlapping
        let mut prev = 0;
        for page in reserved_pages {
            assert!(page.start >= prev);
            assert!(page.end > page.start);
            prev = page.end;
        }
    }

    #[test]
    fn test_page_provider() {
        let collect_regions = |r| {
            let mut regions = Vec::new();
            process_memory_range_by_regions(
                r,
                |region, state| -> Result<bool, core::convert::Infallible> {
                    regions.push((region, state));
                    Ok(true)
                },
            )
            .unwrap();
            regions
        };

        let platform = WindowsUserland::new();
        let system_allocation_granularity =
            platform.sys_info.read().unwrap().dwAllocationGranularity as usize;
        // Allocate some pages: it should reserve `system_allocation_granularity` bytes but only commit 0x1000 bytes
        let addr = <WindowsUserland as PageManagementProvider<4096>>::allocate_pages(
            platform,
            0..0x1000,
            MemoryRegionPermissions::WRITE,
            false,
            true,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        assert_eq!(
            collect_regions(addr..addr + system_allocation_granularity),
            vec![
                (
                    addr..addr + 0x1000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
                (
                    addr + 0x1000..addr + system_allocation_granularity,
                    windows_sys::Win32::System::Memory::MEM_RESERVE
                ),
            ]
        );

        assert!(system_allocation_granularity >= 0x1_0000);
        // We should be able to allocate [addr + 0x8000, addr + 0x1_0000)
        let addr2 = <WindowsUserland as PageManagementProvider<4096>>::allocate_pages(
            platform,
            (addr + 0x8000)..(addr + 0x1_0000),
            MemoryRegionPermissions::WRITE,
            false,
            true,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        // Even though `fixed_address` is false, we should still get the requested address if it's free.
        assert_eq!(addr2, addr + 0x8000);
        assert_eq!(
            collect_regions(addr..addr + 0x1_0000),
            vec![
                (
                    addr..addr + 0x1000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
                (
                    addr + 0x1000..addr + 0x8000,
                    windows_sys::Win32::System::Memory::MEM_RESERVE
                ),
                (
                    addr + 0x8000..addr + 0x1_0000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
            ]
        );

        // Try to allocate [addr + 0x4000, addr + 0x1_0000), which overlaps with existing committed pages.
        // OS should allocate a new region instead of the requested one (as `fixed_address` is false)
        let addr3 = <WindowsUserland as PageManagementProvider<4096>>::allocate_pages(
            platform,
            (addr + 0x4000)..(addr + 0x1_0000),
            MemoryRegionPermissions::WRITE,
            false,
            true,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        assert_ne!(addr3, addr + 0x4000);
    }
}
