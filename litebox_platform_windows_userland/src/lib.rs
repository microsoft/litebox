// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Windows.
//!

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use core::cell::{Cell, UnsafeCell};
use core::panic;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use core::time::Duration;
use std::cell::RefCell;
use std::os::raw::c_void;
use std::os::windows::io::AsRawHandle as _;
use std::sync::{Arc, Mutex, OnceLock};

use litebox::platform::page_mgmt::{
    AllocationError, FixedAddressBehavior, MemoryRegionPermissions,
};
use litebox::shim::{ContinueOperation, Exception};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_types::ThreadEnvironmentBlock;
use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
    WaitWakerProvider,
};
use litebox_platform::time::{
    Instant as InstantTrait, SystemTime as SystemTimeTrait, TimeProvider,
};

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

/// Like DynamoRIO's x64 fallback, use the last pointer-sized slot in the TEB's
/// second page, beyond the shared `ThreadEnvironmentBlock`. The size of
/// `ThreadEnvironmentBlock` is 0x1878 but its allocation is rounded up to 0x2000.
const TEB_RUNTIME_TLS_OFFSET: usize = 0x2000 - size_of::<*const c_void>();
const GUEST_TEB_SIZE: usize = size_of::<ThreadEnvironmentBlock>();
/// Set to true and rebuild to enable whole TEB swapping for debugging purposes.
/// Selective TEB swapping is faster but may miss certain internal state changes
/// that whole TEB swapping would catch.
const USE_WHOLE_TEB_SWAP: bool = false;
/// State exchanged for non-graphical guests. GDI batching and Win32/OpenGL
/// client arrays remain native; supporting guest graphics requires revisiting
/// this selection. Keep the remaining state until narrower ownership is proven.
static TEB_SWAP_RANGES: [[usize; 2]; 4] = [
    [
        0,
        core::mem::offset_of!(ThreadEnvironmentBlock, gdi_teb_batch),
    ],
    [
        core::mem::offset_of!(ThreadEnvironmentBlock, real_client_id),
        core::mem::offset_of!(ThreadEnvironmentBlock, win_32_client_info),
    ],
    [
        core::mem::offset_of!(ThreadEnvironmentBlock, last_status_value),
        GUEST_TEB_SIZE,
    ],
    [0, 0],
];
const _: () = {
    let mut index = 0;
    while index < TEB_SWAP_RANGES.len() - 1 {
        let [start, end] = TEB_SWAP_RANGES[index];
        assert!(start < end && end <= GUEST_TEB_SIZE);
        assert!(end - start >= 16);
        assert!(start.is_multiple_of(8) && end.is_multiple_of(8));
        if index > 0 {
            assert!(TEB_SWAP_RANGES[index - 1][1] <= start);
        }
        index += 1;
    }
};
/// Some pointers are relocated between the guest shadow and native TEB when
/// they point inside the source TEB.
static TEB_INTERNAL_POINTER_OFFSETS: [usize; 7] = [
    core::mem::offset_of!(ThreadEnvironmentBlock, nt_tib.self_pointer),
    core::mem::offset_of!(ThreadEnvironmentBlock, thread_local_storage_pointer),
    core::mem::offset_of!(ThreadEnvironmentBlock, activation_stack.active_frame),
    core::mem::offset_of!(
        ThreadEnvironmentBlock,
        activation_stack.frame_list_cache.flink
    ),
    core::mem::offset_of!(
        ThreadEnvironmentBlock,
        activation_stack.frame_list_cache.blink
    ),
    core::mem::offset_of!(ThreadEnvironmentBlock, activation_context_stack_pointer),
    core::mem::offset_of!(ThreadEnvironmentBlock, static_unicode_string.buffer),
];
const PF_RDWRFSGSBASE_AVAILABLE: u32 = 22;

/// Determines how the guest accesses its thread-local storage.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestTlsMode {
    /// A Linux guest uses FS as its TLS base.
    Linux = 1,
    /// A Windows guest uses native GS with exchanged host/guest TEB state.
    Windows = 2,
}

const GUEST_TLS_MODE_UNCONFIGURED: u8 = 0;
static GUEST_TLS_MODE: AtomicU8 = AtomicU8::new(GUEST_TLS_MODE_UNCONFIGURED);

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

impl WindowsUserland {
    /// Configures the process-wide guest TLS mode.
    ///
    /// # Panics
    ///
    /// Panics if a different mode has already been configured.
    pub fn set_guest_tls_mode(guest_tls_mode: GuestTlsMode) {
        let guest_tls_mode = guest_tls_mode as u8;
        if let Err(configured_mode) = GUEST_TLS_MODE.compare_exchange(
            GUEST_TLS_MODE_UNCONFIGURED,
            guest_tls_mode,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            assert_eq!(
                configured_mode, guest_tls_mode,
                "guest TLS mode is already configured",
            );
        }
    }

    fn set_guest_teb(teb: usize) {
        // SAFETY: Called on a managed thread while host TEB state is installed.
        let tls = unsafe { &*get_tls_ptr().expect("TLS not initialized") };
        tls.guest_teb.set(teb);
    }

    fn set_thread_fs_base(fs_base: usize) {
        let tls = unsafe { &*get_tls_ptr().expect("TLS not initialized") };
        tls.guest_fs_base.set(fs_base);
        Self::restore_thread_fs_base(tls);
    }

    fn restore_thread_fs_base(tls: &TlsState) {
        unsafe { litebox_common_linux::wrfsbase(tls.guest_fs_base.get()) };
    }
}

fn guest_tls_mode() -> GuestTlsMode {
    match GUEST_TLS_MODE.load(Ordering::Acquire) {
        mode if mode == GuestTlsMode::Linux as u8 => GuestTlsMode::Linux,
        mode if mode == GuestTlsMode::Windows as u8 => GuestTlsMode::Windows,
        GUEST_TLS_MODE_UNCONFIGURED => panic!("guest TLS mode is not configured"),
        _ => unreachable!("invalid guest TLS mode"),
    }
}

fn current_teb() -> *mut u8 {
    let teb: *mut u8;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
            options(nostack, preserves_flags, readonly),
        );
    }
    teb
}

fn teb_runtime_tls_slot(teb: usize) -> *mut *const TlsState {
    let address = teb + TEB_RUNTIME_TLS_OFFSET;
    debug_assert!(address.is_multiple_of(align_of::<*const TlsState>()));
    core::ptr::with_exposed_provenance_mut(address)
}

fn runtime_tls_slot() -> *mut *const TlsState {
    teb_runtime_tls_slot(current_teb().addr())
}

/// Runs the Rust handler with host FP controls
#[unsafe(naked)]
unsafe extern "system" fn vectored_exception_handler(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    core::arch::naked_asm!(
        ".seh_proc vectored_exception_entry",
        "sub rsp, 40",
        ".seh_stackalloc 40",
        ".seh_endprologue",
        "fnstcw WORD PTR [rsp + 32]",
        "stmxcsr DWORD PTR [rsp + 36]",
        // Clear the x87 exception flags and restore the host FP control state
        "fnclex",
        "fldcw WORD PTR [rip + {HOST_X87_CONTROL_WORD}]",
        "ldmxcsr DWORD PTR [rip + {HOST_MXCSR}]",
        "call {handler}",
        "fldcw WORD PTR [rsp + 32]",
        "ldmxcsr DWORD PTR [rsp + 36]",
        "add rsp, 40",
        "ret",
        ".seh_endproc",
        HOST_X87_CONTROL_WORD = sym HOST_X87_CONTROL_WORD,
        HOST_MXCSR = sym HOST_MXCSR,
        handler = sym vectored_exception_handler_inner,
    );
}

unsafe extern "system" fn vectored_exception_handler_inner(
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
                litebox::mm::exception_table::search_exception_tables(context.Rip.trunc())
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
    save_guest_context(tls, regs, context);

    // If it looks like fs base was cleared, then go through the interrupt path
    // instead of the exception path to restore the fs base and try again.
    //
    // This is done instead of just fixing up fsbase and returning here to avoid
    // missing a real interrupt that arrives while resuming the guest. Go through
    // the interrupt path to ensure that any pending interrupts are also handled.
    if exception_record.ExceptionCode == Win32_Foundation::EXCEPTION_ACCESS_VIOLATION
        && guest_tls_mode() == GuestTlsMode::Linux
        && unsafe { litebox_common_linux::rdfsbase() } == 0
        && tls.guest_fs_base.get() != 0
    {
        set_context_to_interrupt_callback(context);
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
        // `host_sp` points at the slot where `run_thread_arch` saved its
        // `ThreadContext` argument. Set it to `rcx` (i.e., the first argument) so
        // that [`exception_handler`] can access it.
        context.Rcx = unsafe { tls.host_sp.get().cast::<usize>().read() } as u64;
        context.Rdx = exception_record_ptr as u64;
    }

    EXCEPTION_CONTINUE_EXECUTION
}

fn save_guest_context(
    tls: &TlsState,
    guest_context: &mut litebox_common_linux::PtRegs,
    context: &windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        CONTEXT_FLOATING_POINT_AMD64, CONTEXT_XSTATE_AMD64, CopyContext,
    };

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
    *r15 = context.R15.trunc();
    *r14 = context.R14.trunc();
    *r13 = context.R13.trunc();
    *r12 = context.R12.trunc();
    *rbp = context.Rbp.trunc();
    *rbx = context.Rbx.trunc();
    *r11 = context.R11.trunc();
    *r10 = context.R10.trunc();
    *r9 = context.R9.trunc();
    *r8 = context.R8.trunc();
    *rax = context.Rax.trunc();
    *rcx = context.Rcx.trunc();
    *rdx = context.Rdx.trunc();
    *rsi = context.Rsi.trunc();
    *rdi = context.Rdi.trunc();
    *orig_rax = context.Rax.trunc();
    *rip = context.Rip.trunc();
    *eflags = context.EFlags as usize;
    *rsp = context.Rsp.trunc();

    // SAFETY: the current thread is outside the guest, or the target thread is
    // suspended, so no other code can access `continue_context` concurrently.
    let ok = unsafe {
        CopyContext(
            (*tls.continue_context.get()).as_ptr(),
            CONTEXT_FLOATING_POINT_AMD64 | CONTEXT_XSTATE_AMD64,
            context,
        )
    };
    assert_ne!(ok, 0, "CopyContext failed");
    tls.guest_xstate_format.set(GuestXstateFormat::Windows);
}

impl WindowsUserland {
    /// Create a new userland-Windows platform for use in `LiteBox`.
    ///
    /// # Panics
    ///
    /// Panics if Windows has not enabled user-mode FSGSBASE instructions.
    pub fn new() -> &'static Self {
        assert!(
            // SAFETY: `IsProcessorFeaturePresent` accepts any feature identifier and has no
            // pointer or lifetime requirements.
            unsafe { Win32_Threading::IsProcessorFeaturePresent(PF_RDWRFSGSBASE_AVAILABLE) != 0 },
            "Windows has not enabled user-mode FSGSBASE instructions",
        );

        let mut sys_info = Win32_SysInfo::SYSTEM_INFO::default();
        Self::get_system_information(&mut sys_info);

        // TODO(chuqi): Currently we just print system information for
        // `TASK_ADDR_MIN` and `TASK_ADDR_MAX`.
        // Will remove these prints once we have a better way to replace
        // the current `const` values in PageManagementProvider.
        #[cfg(debug_assertions)]
        {
            println!("System information.");
            println!(
                "=> Max user address: {:#x}",
                sys_info.lpMaximumApplicationAddress as usize
            );
            println!(
                "=> Min user address: {:#x}",
                sys_info.lpMinimumApplicationAddress as usize
            );
        }

        let reserved_pages = Self::read_memory_maps();

        let platform = Self {
            reserved_pages,
            sys_info: std::sync::RwLock::new(sys_info),
        };

        // Windows sets FS_BASE to 0 regularly upon scheduling; we register an exception handler
        // to set FS_BASE back to a "stored" value whenever we notice that it has become 0.
        unsafe {
            let _ = AddVectoredExceptionHandler(0, Some(vectored_exception_handler));
        }

        // Register a console control handler to receive Ctrl+C
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(
                Some(ctrl_c_handler),
                1, // TRUE — add the handler
            );
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

impl litebox::platform::SignalProvider for WindowsUserland {
    type Signal = litebox_common_linux::signal::Signal;

    fn take_pending_signals(&self, mut f: impl FnMut(Self::Signal)) {
        let bits = get_tls_ptr().map_or(0, |p| {
            unsafe { &*p }
                .pending_host_signals
                .swap(0, Ordering::SeqCst)
        });
        let sigs = litebox_common_linux::signal::SigSet::from_u64(u64::from(bits));
        for signal in sigs {
            f(signal);
        }
    }
}

/// Runs a guest thread using the provided shim and the given initial context.
///
/// This will run until the thread terminates.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread(
    shim: impl litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
) {
    run_thread_inner(&shim, ctx);
}

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
) {
    let tls_state = TlsState::new();
    tls_state
        .guest_context_top
        .set(std::ptr::from_mut(ctx).wrapping_add(1));

    let mut thread_ctx = ThreadContext {
        shim,
        ctx,
        tls: &tls_state,
    };
    ThreadHandle::run_with_handle(&tls_state, || {
        debug_assert_host_fx_control_state();
        unsafe { run_thread_arch(&mut thread_ctx, &tls_state) };
    });
}

/// Windows x64 ABI default: all x87 exceptions masked, 53-bit precision, round to nearest.
/// Unlike the guest's architectural initial value (0x037f), this selects double precision.
/// See <https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention#fpcsr>.
static HOST_X87_CONTROL_WORD: u16 = 0x027f;
static HOST_MXCSR: u32 = core::arch::x86_64::_MM_MASK_MASK;

#[inline]
fn debug_assert_host_fx_control_state() {
    #[cfg(debug_assertions)]
    {
        const HOST_MXCSR_CONTROL_MASK: u32 = 0xffc0;
        let mut x87_control_word = 0_u16;
        let mut mxcsr = 0_u32;
        unsafe {
            core::arch::asm!(
                "fnstcw WORD PTR [{x87_control_word}]",
                "stmxcsr DWORD PTR [{mxcsr}]",
                x87_control_word = in(reg) &raw mut x87_control_word,
                mxcsr = in(reg) &raw mut mxcsr,
                options(nostack, preserves_flags),
            );
        }
        debug_assert_eq!(x87_control_word, HOST_X87_CONTROL_WORD);
        debug_assert_eq!(mxcsr & HOST_MXCSR_CONTROL_MASK, HOST_MXCSR);
    }
}

const XSAVE_LEGACY_SIZE: usize =
    size_of::<windows_sys::Win32::System::Diagnostics::Debug::XSAVE_FORMAT>();
const XSAVE_HEADER_OFFSET: usize = XSAVE_LEGACY_SIZE;

#[repr(C, align(64))]
#[derive(Clone)]
struct XsaveChunk([u8; 64]);

struct XsaveLayout {
    size: usize,
    mask: u64,
    components: Vec<XsaveComponent>,
}

struct XsaveComponent {
    id: u32,
    offset: usize,
    size: usize,
}

impl XsaveLayout {
    fn get() -> &'static Self {
        static LAYOUT: OnceLock<XsaveLayout> = OnceLock::new();
        LAYOUT.get_or_init(|| {
            const CPUID_XSAVE: u32 = 1 << 26;
            const CPUID_OSXSAVE: u32 = 1 << 27;

            assert!(core::arch::x86_64::__cpuid(0).eax >= 0x0d);
            let feature_info = core::arch::x86_64::__cpuid(1);
            assert_eq!(
                feature_info.ecx & (CPUID_XSAVE | CPUID_OSXSAVE),
                CPUID_XSAVE | CPUID_OSXSAVE,
                "XSAVE must be supported and enabled by Windows",
            );
            let features = core::arch::x86_64::__cpuid_count(0x0d, 0);
            let mask = unsafe { core::arch::x86_64::_xgetbv(0) };
            assert_eq!(mask & 3, 3, "x87 and SSE state must be enabled");
            assert!(features.ebx as usize >= XSAVE_HEADER_OFFSET + 64);
            let components = (2..64)
                .filter(|id| mask & (1 << id) != 0)
                .map(|id| {
                    let component = core::arch::x86_64::__cpuid_count(0x0d, id);
                    let component = XsaveComponent {
                        id,
                        offset: component.ebx as usize,
                        size: component.eax as usize,
                    };
                    assert!(component.offset + component.size <= features.ebx as usize);
                    component
                })
                .collect();
            XsaveLayout {
                size: features.ebx as usize,
                mask,
                components,
            }
        })
    }
}

/// Represents the standard-layout XSAVE area for a guest context.
struct XsaveArea {
    storage: Box<[XsaveChunk]>,
}

impl XsaveArea {
    const GUEST_INITIAL_X87_CONTROL_WORD: u16 = 0x037f;
    const GUEST_INITIAL_MXCSR: u32 = core::arch::x86_64::_MM_MASK_MASK;

    fn initial_guest() -> Self {
        let chunk_count = XsaveLayout::get().size.div_ceil(size_of::<XsaveChunk>());
        let mut area = Self {
            storage: vec![XsaveChunk([0; 64]); chunk_count].into_boxed_slice(),
        };
        // SAFETY: The buffer owns aligned, initialized storage for the legacy area.
        // Standard XRSTOR loads MXCSR even when XSTATE_BV marks SSE as initial.
        unsafe {
            (*area
                .as_mut_ptr()
                .cast::<windows_sys::Win32::System::Diagnostics::Debug::XSAVE_FORMAT>())
            .MxCsr = Self::GUEST_INITIAL_MXCSR;
        }
        area
    }

    fn as_ptr(&self) -> *const u8 {
        self.storage.as_ptr().cast()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.storage.as_mut_ptr().cast()
    }

    fn xstate_bv(&self) -> u64 {
        unsafe {
            self.as_ptr()
                .add(XSAVE_HEADER_OFFSET)
                .cast::<u64>()
                .read_unaligned()
        }
    }

    fn restore_to_context(
        &self,
        context: &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
    ) {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            CONTEXT_XSTATE_AMD64, LocateXStateFeature, SetXStateFeaturesMask,
        };

        let legacy_state = self.legacy_state_for_context();
        context.Anonymous.FltSave = legacy_state;
        context.MxCsr = legacy_state.MxCsr;
        if context.ContextFlags & CONTEXT_XSTATE_AMD64 != CONTEXT_XSTATE_AMD64 {
            return;
        }

        let layout = XsaveLayout::get();
        let xstate_bv = self.xstate_bv();
        for component in &layout.components {
            if xstate_bv & (1 << component.id) == 0 {
                continue;
            }
            let mut length = 0;
            // SAFETY: The context has initialized XSTATE storage, checked above.
            let destination =
                unsafe { LocateXStateFeature(context, component.id, &raw mut length).cast::<u8>() };
            assert!(!destination.is_null());
            assert_eq!(length as usize, component.size);
            // SAFETY: The component fits both disjoint buffers and is marked valid.
            unsafe {
                destination
                    .copy_from_nonoverlapping(self.as_ptr().add(component.offset), component.size);
            }
        }
        // SAFETY: The context owns initialized XSTATE storage for the enabled features.
        let ok = unsafe { SetXStateFeaturesMask(context, xstate_bv & layout.mask) };
        assert_ne!(ok, 0, "SetXStateFeaturesMask failed");
    }

    fn legacy_state_for_context(
        &self,
    ) -> windows_sys::Win32::System::Diagnostics::Debug::XSAVE_FORMAT {
        use windows_sys::Win32::System::Diagnostics::Debug::XSAVE_FORMAT;

        let saved = unsafe { self.as_ptr().cast::<XSAVE_FORMAT>().read() };
        let mut state = XSAVE_FORMAT {
            ControlWord: Self::GUEST_INITIAL_X87_CONTROL_WORD,
            MxCsr: saved.MxCsr,
            MxCsr_Mask: saved.MxCsr_Mask,
            ..Default::default()
        };
        let xstate_bv = self.xstate_bv();
        if xstate_bv & 1 != 0 {
            state.ControlWord = saved.ControlWord;
            state.StatusWord = saved.StatusWord;
            state.TagWord = saved.TagWord;
            state.ErrorOpcode = saved.ErrorOpcode;
            state.ErrorOffset = saved.ErrorOffset;
            state.ErrorSelector = saved.ErrorSelector;
            state.DataOffset = saved.DataOffset;
            state.DataSelector = saved.DataSelector;
            state.FloatRegisters = saved.FloatRegisters;
        }
        if xstate_bv & 2 != 0 {
            state.XmmRegisters = saved.XmmRegisters;
        }
        state
    }
}

/// Represents an extended CPU context, including the XSAVE area.
struct ExtendedContext {
    /// Storage for the Windows context, including the XSAVE area.
    _storage: Box<[XsaveChunk]>,
    /// Pointer to the Windows context (i.e., `_storage`)
    context: *mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
}

impl ExtendedContext {
    fn new() -> Self {
        static CONTEXT_LENGTH: OnceLock<u32> = OnceLock::new();

        use windows_sys::Win32::System::Diagnostics::Debug::{
            CONTEXT_ALL_AMD64, CONTEXT_XSTATE_AMD64, InitializeContext, SetXStateFeaturesMask,
        };

        let flags = CONTEXT_ALL_AMD64 | CONTEXT_XSTATE_AMD64;
        let mut context_length = *CONTEXT_LENGTH.get_or_init(|| {
            let mut context_length = 0;
            let mut context = core::ptr::null_mut();
            let ok = unsafe {
                InitializeContext(
                    core::ptr::null_mut(),
                    flags,
                    &raw mut context,
                    &raw mut context_length,
                )
            };
            assert_eq!(ok, 0);
            assert_ne!(context_length, 0);
            context_length
        });

        let chunk_count = (context_length as usize).div_ceil(size_of::<XsaveChunk>());
        let mut storage = vec![XsaveChunk([0; 64]); chunk_count].into_boxed_slice();
        let mut context = core::ptr::null_mut();
        let ok = unsafe {
            InitializeContext(
                storage.as_mut_ptr().cast(),
                flags,
                &raw mut context,
                &raw mut context_length,
            )
        };
        assert_ne!(ok, 0, "InitializeContext failed");
        let ok = unsafe { SetXStateFeaturesMask(context, XsaveLayout::get().mask) };
        assert_ne!(ok, 0, "SetXStateFeaturesMask failed");
        Self {
            _storage: storage,
            context,
        }
    }

    fn as_ptr(&self) -> *mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT {
        self.context
    }

    fn context_mut(&mut self) -> &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT {
        unsafe { &mut *self.context }
    }

    fn prepare_for_capture(
        &mut self,
    ) -> &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            CONTEXT_ALL_AMD64, CONTEXT_XSTATE_AMD64, SetXStateFeaturesMask,
        };

        let context = self.context_mut();
        context.ContextFlags = CONTEXT_ALL_AMD64 | CONTEXT_XSTATE_AMD64;
        // SAFETY: The context retains its initialized extended storage across captures.
        let ok = unsafe { SetXStateFeaturesMask(context, XsaveLayout::get().mask) };
        assert_ne!(ok, 0, "SetXStateFeaturesMask failed");
        context
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum GuestXstateFormat {
    Native,
    Windows,
}

struct TlsState {
    host_sp: Cell<*mut u128>,
    host_bp: Cell<*mut u128>,
    guest_context_top: Cell<*mut litebox_common_linux::PtRegs>,
    scratch: Cell<usize>,
    is_in_guest: Cell<bool>,
    interrupt: Cell<bool>,
    continue_context: UnsafeCell<ExtendedContext>,
    /// Scratch storage used exclusively under the target thread-handle mutex.
    interrupt_context: UnsafeCell<ExtendedContext>,
    guest_xsave_ptr: Cell<*mut u8>,
    guest_xsave_area: UnsafeCell<XsaveArea>,
    guest_xsave_mask: u64,
    guest_xstate_format: Cell<GuestXstateFormat>,
    guest_fs_base: Cell<usize>,
    guest_teb: Cell<usize>,
    host_teb: Cell<*mut u8>,
    host_teb_shadow: Box<UnsafeCell<[usize; GUEST_TEB_SIZE / size_of::<usize>()]>>,
    /// Bitmask of pending host-originated signals for this thread.
    pending_host_signals: AtomicU32,
    /// Pointer to the `Waker` currently being waited on, or null if not
    /// waiting.
    waiting_waker: std::sync::atomic::AtomicPtr<core::task::Waker>,
}

impl TlsState {
    /// Creates a new `TlsState` with all fields zeroed / defaulted.
    fn new() -> Self {
        let mut guest_xsave_area = XsaveArea::initial_guest();
        let guest_xsave_ptr = guest_xsave_area.as_mut_ptr();
        Self {
            host_sp: Cell::new(core::ptr::null_mut()),
            host_bp: Cell::new(core::ptr::null_mut()),
            guest_context_top: core::ptr::null_mut::<litebox_common_linux::PtRegs>().into(),
            scratch: 0.into(),
            is_in_guest: false.into(),
            interrupt: false.into(),
            continue_context: UnsafeCell::new(ExtendedContext::new()),
            interrupt_context: UnsafeCell::new(ExtendedContext::new()),
            guest_xsave_ptr: Cell::new(guest_xsave_ptr),
            guest_xsave_area: UnsafeCell::new(guest_xsave_area),
            guest_xsave_mask: XsaveLayout::get().mask,
            guest_xstate_format: Cell::new(GuestXstateFormat::Native),
            guest_fs_base: Cell::new(0),
            guest_teb: Cell::new(0),
            host_teb: Cell::new(core::ptr::null_mut()),
            host_teb_shadow: Box::new(UnsafeCell::new([0; GUEST_TEB_SIZE / size_of::<usize>()])),
            pending_host_signals: AtomicU32::new(0),
            waiting_waker: std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()),
        }
    }
}

/// Saves selected host TEB fields and installs guest fields without changing GS.
/// `USE_WHOLE_TEB_SWAP` overrides the selection for both install and restore.
///
/// # Safety
///
/// `tls` must belong to this thread and have a configured, nonzero guest TEB.
/// Its TEB allocations must be live, disjoint, and writable for `GUEST_TEB_SIZE`
/// bytes. Host TEB state must be installed.
#[unsafe(naked)]
unsafe extern "C" fn install_guest_teb(tls: &TlsState) {
    core::arch::naked_asm!(
        ".if {USE_WHOLE_TEB_SWAP}",
        "jmp {install_guest_whole_teb}",
        ".endif",
        "mov r10, [rcx + {GUEST_TEB}]",
        "mov r8, [rcx + {HOST_TEB}]",
        "mov r9, [rcx + {HOST_TEB_SHADOW}]",
        "mov rcx, r10",
        "mov rdx, r8",
        "jmp .Lcopy_teb",
        ".globl restore_host_teb",
    "restore_host_teb:",
        ".if {USE_WHOLE_TEB_SWAP}",
        "jmp {restore_host_whole_teb}",
        ".endif",
        "mov r9, [rcx + {GUEST_TEB}]",
        "mov r8, [rcx + {HOST_TEB}]",
        "mov r10, [rcx + {HOST_TEB_SHADOW}]",
        "mov rcx, r8",
        "mov rdx, r9",
        ".Lcopy_teb:",
        "movq xmm3, rcx",
        "lea rax, [rip + {SWAP_RANGES}]",
    ".Lcopy_teb_range:",
        "mov r11, [rax]",
        "mov rcx, [rax + 8]",
        "cmp r11, rcx",
        "je .Lcopy_teb_done",
        "sub rcx, 16",
        "cmp r11, rcx",
        "ja .Lcopy_teb_tail",
    ".Lcopy_teb_blocks:",
        "movdqu xmm0, [r8 + r11]",
        "movdqu xmm1, [r10 + r11]",
        "movdqu [r9 + r11], xmm0",
        "movdqu [r8 + r11], xmm1",
        "add r11, 16",
        "cmp r11, rcx",
        "jbe .Lcopy_teb_blocks",
    ".Lcopy_teb_tail:",
        "add rcx, 16",
        "cmp r11, rcx",
        "je .Lcopy_teb_next",
        "movq xmm0, [r8 + r11]",
        "movq xmm1, [r10 + r11]",
        "movq [r9 + r11], xmm0",
        "movq [r8 + r11], xmm1",
    ".Lcopy_teb_next:",
        "add rax, 16",
        "jmp .Lcopy_teb_range",
        ".Lcopy_teb_done:",
        "movq r9, xmm3",
        "mov r10, rdx",
        "lea r8, [rip + {POINTER_OFFSETS}]",
        "xor r11d, r11d",
        "8:",
        "mov rdx, [r8 + r11 * 8]",
        "mov rax, [r10 + rdx]",
        "sub rax, r9",
        "cmp rax, {TEB_SIZE}",
        "jae 10f",
        "add rax, r10",
        "mov [r10 + rdx], rax",
        "10:",
        "inc r11",
        "cmp r11, {POINTER_COUNT}",
        "jb 8b",
        "ret",
        GUEST_TEB = const core::mem::offset_of!(TlsState, guest_teb),
        HOST_TEB = const core::mem::offset_of!(TlsState, host_teb),
        HOST_TEB_SHADOW = const core::mem::offset_of!(TlsState, host_teb_shadow),
        TEB_SIZE = const GUEST_TEB_SIZE,
        SWAP_RANGES = sym TEB_SWAP_RANGES,
        POINTER_OFFSETS = sym TEB_INTERNAL_POINTER_OFFSETS,
        POINTER_COUNT = const TEB_INTERNAL_POINTER_OFFSETS.len(),
        USE_WHOLE_TEB_SWAP = const USE_WHOLE_TEB_SWAP as usize,
        install_guest_whole_teb = sym install_guest_whole_teb,
        restore_host_whole_teb = sym restore_host_whole_teb,
    );
}

/// Whole-modeled-TEB fallback for diagnosing selective exchange bugs.
///
/// # Safety
///
/// The same requirements as `install_guest_teb` apply.
#[unsafe(naked)]
unsafe extern "C" fn install_guest_whole_teb(tls: &TlsState) {
    core::arch::naked_asm!(
        "mov r10, [rcx + {GUEST_TEB}]",
        "mov r8, [rcx + {HOST_TEB}]",
        "mov r9, [rcx + {HOST_TEB_SHADOW}]",
        "mov rcx, r10",
        "mov rdx, r8",
        "jmp .Lwhole_copy_teb",
        ".globl restore_host_whole_teb",
    "restore_host_whole_teb:",
        "mov r9, [rcx + {GUEST_TEB}]",
        "mov r8, [rcx + {HOST_TEB}]",
        "mov r10, [rcx + {HOST_TEB_SHADOW}]",
        "mov rcx, r8",
        "mov rdx, r9",
        ".Lwhole_copy_teb:",
        "xor r11d, r11d",
    ".Lwhole_copy_teb_blocks:",
        "movdqu xmm0, [r8 + r11]",
        "movdqu xmm1, [r8 + r11 + 16]",
        "movdqu xmm2, [r8 + r11 + 32]",
        "movdqu xmm3, [r8 + r11 + 48]",
        "movdqu [r9 + r11], xmm0",
        "movdqu [r9 + r11 + 16], xmm1",
        "movdqu [r9 + r11 + 32], xmm2",
        "movdqu [r9 + r11 + 48], xmm3",
        "movdqu xmm0, [r10 + r11]",
        "movdqu xmm1, [r10 + r11 + 16]",
        "movdqu xmm2, [r10 + r11 + 32]",
        "movdqu xmm3, [r10 + r11 + 48]",
        "movdqu [r8 + r11], xmm0",
        "movdqu [r8 + r11 + 16], xmm1",
        "movdqu [r8 + r11 + 32], xmm2",
        "movdqu [r8 + r11 + 48], xmm3",
        "add r11, 64",
        "cmp r11, {BLOCK_END}",
        "jb .Lwhole_copy_teb_blocks",
        "3:",
        "mov rax, [r8 + r11]",
        "mov [r9 + r11], rax",
        "mov rax, [r10 + r11]",
        "mov [r8 + r11], rax",
        "add r11, 8",
        "cmp r11, {TEB_SIZE}",
        "jb 3b",
        "mov r9, rcx",
        "mov r10, rdx",
        "lea r8, [rip + {POINTER_OFFSETS}]",
        "xor r11d, r11d",
        "8:",
        "mov rdx, [r8 + r11 * 8]",
        "mov rax, [r10 + rdx]",
        "sub rax, r9",
        "cmp rax, {TEB_SIZE}",
        "jae 10f",
        "add rax, r10",
        "mov [r10 + rdx], rax",
        "10:",
        "inc r11",
        "cmp r11, {POINTER_COUNT}",
        "jb 8b",
        "ret",
        GUEST_TEB = const core::mem::offset_of!(TlsState, guest_teb),
        HOST_TEB = const core::mem::offset_of!(TlsState, host_teb),
        HOST_TEB_SHADOW = const core::mem::offset_of!(TlsState, host_teb_shadow),
        TEB_SIZE = const GUEST_TEB_SIZE,
        BLOCK_END = const GUEST_TEB_SIZE / 64 * 64,
        POINTER_OFFSETS = sym TEB_INTERNAL_POINTER_OFFSETS,
        POINTER_COUNT = const TEB_INTERNAL_POINTER_OFFSETS.len(),
    );
}

/// Captures the native TEB and stores `tls` in its runtime slot.
///
/// # Safety
///
/// The caller must ensure `tls` remains valid for the duration of its use.
unsafe fn install_tls(tls: &TlsState) {
    let host_teb = current_teb();
    assert!(!host_teb.is_null(), "host TEB is not configured");
    tls.host_teb.set(host_teb);
    unsafe {
        teb_runtime_tls_slot(host_teb.addr()).write(core::ptr::from_ref(tls));
    }
}

/// Clears the current thread's post-TEB runtime slot.
fn uninstall_tls() {
    // SAFETY: Teardown runs on the owning thread after host state was restored.
    unsafe {
        runtime_tls_slot().write(core::ptr::null());
    }
}

fn get_tls_ptr() -> Option<*const TlsState> {
    let ptr = unsafe { runtime_tls_slot().read() };
    if ptr.is_null() {
        return None;
    }
    Some(ptr)
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
    mov     r11, QWORD PTR gs:[{TEB_RUNTIME_TLS_OFFSET}]
    mov     BYTE PTR [r11 + {IS_IN_GUEST}], 0
    // Set rsp to the top of the guest context.
    mov     QWORD PTR [r11 + {SCRATCH}], rsp
    mov     rsp, QWORD PTR [r11 + {GUEST_CONTEXT_TOP}]

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

    // Save guest XSTATE now that the guest GPRs are preserved.
    mov     eax, DWORD PTR [r11 + {XSAVE_MASK}]
    mov     edx, DWORD PTR [r11 + {XSAVE_MASK} + 4]
    mov     r10, QWORD PTR [r11 + {GUEST_XSAVE_PTR}]
    xsave64 [r10]
    mov     BYTE PTR [r11 + {GUEST_XSTATE_FORMAT}], 0
    // Clear the x87 exception flags and restore the Windows ABI's standard host x87 control word and mxcsr.
    fnclex
    fldcw WORD PTR [rip + {HOST_X87_CONTROL_WORD}]
    ldmxcsr DWORD PTR [rip + {HOST_MXCSR}]

    /// Reestablish the stack and frame pointers.
    mov     rsp, [r11 + {HOST_SP}]
    mov     rbp, [r11 + {HOST_BP}]
    cmp     BYTE PTR [rip + {GUEST_TLS_MODE}], {WINDOWS_TLS_MODE}
    jne     2f
    mov     rcx, r11
    sub     rsp, 32
    call    {restore_host_teb}
    add     rsp, 32
2:

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    mov  rcx, QWORD PTR [rsp] // thread_ctx
    call {syscall_handler}
    jmp .Ldone

exception_callback:
    // Clear the x87 exception flags and restore the Windows ABI's standard host x87 control word and mxcsr.
    fnclex
    fldcw WORD PTR [rip + {HOST_X87_CONTROL_WORD}]
    ldmxcsr DWORD PTR [rip + {HOST_MXCSR}]
    // Handle the exception. The stack and frame pointers are already restored,
    // and the guest context is up to date. rcx contains a pointer to the
    // guest pt_regs, and rdx contains a pointer to the exception record.
    mov  r11, QWORD PTR gs:[{TEB_RUNTIME_TLS_OFFSET}]
    cmp  BYTE PTR [rip + {GUEST_TLS_MODE}], {WINDOWS_TLS_MODE}
    jne  2f
    sub  rsp, 48
    mov  [rsp + 32], rcx
    mov  [rsp + 40], rdx
    mov  rcx, r11
    call {restore_host_teb}
    mov  rcx, [rsp + 32]
    mov  rdx, [rsp + 40]
    add  rsp, 48
2:
    call {exception_handler}
    jmp .Ldone

interrupt_callback:
    mov  r11, QWORD PTR gs:[{TEB_RUNTIME_TLS_OFFSET}]
    mov  BYTE PTR [r11 + {IS_IN_GUEST}], 0
    mov     rsp, [r11 + {HOST_SP}]
    mov     rbp, [r11 + {HOST_BP}]
    // Clear the x87 exception flags and restore the Windows ABI's standard host x87 control word and mxcsr.
    fnclex
    fldcw WORD PTR [rip + {HOST_X87_CONTROL_WORD}]
    ldmxcsr DWORD PTR [rip + {HOST_MXCSR}]
    cmp  BYTE PTR [rip + {GUEST_TLS_MODE}], {WINDOWS_TLS_MODE}
    jne  2f
    mov  rcx, r11
    sub  rsp, 32
    call {restore_host_teb}
    add  rsp, 32
2:
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
    TEB_RUNTIME_TLS_OFFSET = const TEB_RUNTIME_TLS_OFFSET,
    HOST_SP = const core::mem::offset_of!(TlsState, host_sp),
    HOST_BP = const core::mem::offset_of!(TlsState, host_bp),
    GUEST_TLS_MODE = sym GUEST_TLS_MODE,
    WINDOWS_TLS_MODE = const GuestTlsMode::Windows as u8,
    restore_host_teb = sym restore_host_teb,
    GUEST_CONTEXT_TOP = const core::mem::offset_of!(TlsState, guest_context_top),
    SCRATCH = const core::mem::offset_of!(TlsState, scratch),
    IS_IN_GUEST = const core::mem::offset_of!(TlsState, is_in_guest),
    HOST_X87_CONTROL_WORD = sym HOST_X87_CONTROL_WORD,
    HOST_MXCSR = sym HOST_MXCSR,
    GUEST_XSAVE_PTR = const core::mem::offset_of!(TlsState, guest_xsave_ptr),
    XSAVE_MASK = const core::mem::offset_of!(TlsState, guest_xsave_mask),
    GUEST_XSTATE_FORMAT = const core::mem::offset_of!(TlsState, guest_xstate_format),
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
    extern "C" fn switch_to_guest_sysret(ctx: &litebox_common_linux::PtRegs, tls: &TlsState) -> ! {
        // Set `in_guest` now, then check if there is a pending interrupt. If
        // so, jump to the interrupt handler.
        //
        // If an interrupt arrives after the check, then the signal handler will
        // see that the IP is between `switch_to_guest_start` and
        // `switch_to_guest_end` and will set the `interrupt` and jump to
        // `interrupt_callback`.
        core::arch::naked_asm!(
            "cmp BYTE PTR [rip + {GUEST_TLS_MODE}], {WINDOWS_TLS_MODE}",
            "jne 3f",
            "sub rsp, 56",
            "mov [rsp + 32], rcx",
            "mov [rsp + 40], rdx",
            "mov rcx, rdx",
            "call {install_guest_teb}",
            "mov rcx, [rsp + 32]",
            "mov rdx, [rsp + 40]",
            "add rsp, 56",
            "3:",
            "switch_to_guest_start:",
            "mov BYTE PTR [rdx + {IS_IN_GUEST}], 1",
            "cmp BYTE PTR [rdx + {INTERRUPT}], 0",
            "je 2f",
            "jmp {interrupt_callback}",
            "2:",
            "mov r10, [rdx + {GUEST_XSAVE_PTR}]",
            "mov eax, DWORD PTR [rdx + {XSAVE_MASK}]",
            "mov edx, DWORD PTR [rdx + {XSAVE_MASK} + 4]",
            "xrstor64 [r10]",
            // Load all registers from the guest context structure.
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
            IS_IN_GUEST = const core::mem::offset_of!(TlsState, is_in_guest),
            INTERRUPT = const core::mem::offset_of!(TlsState, interrupt),
            GUEST_XSAVE_PTR = const core::mem::offset_of!(TlsState, guest_xsave_ptr),
            XSAVE_MASK = const core::mem::offset_of!(TlsState, guest_xsave_mask),
            GUEST_TLS_MODE = sym GUEST_TLS_MODE,
            WINDOWS_TLS_MODE = const GuestTlsMode::Windows as u8,
            install_guest_teb = sym install_guest_teb,
            interrupt_callback = sym interrupt_callback,
        );
    }

    fn switch_to_guest_ntcontinue(tls: &TlsState, ctx: &litebox_common_linux::PtRegs) -> ! {
        use litebox::utils::ReinterpretSignedExt;
        use windows_sys::Win32::System::Diagnostics::Debug::{
            CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_FLOATING_POINT_AMD64, CONTEXT_INTEGER_AMD64,
        };
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtContinue(
                ctx: *const CONTEXT,
                raise_alert: u8,
            ) -> windows_sys::Win32::Foundation::NTSTATUS;
        }
        let win_ctx = unsafe { (*tls.continue_context.get()).as_ptr() };
        let native_xstate = tls.guest_xstate_format.get() == GuestXstateFormat::Native;
        // SAFETY: no other code accesses `continue_context` while `is_in_guest` is false.
        unsafe {
            let win_ctx = &mut *win_ctx;
            win_ctx.ContextFlags = CONTEXT_CONTROL_AMD64
                | CONTEXT_INTEGER_AMD64
                | CONTEXT_FLOATING_POINT_AMD64
                | windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_XSTATE_AMD64;
            win_ctx.EFlags = ctx.eflags.trunc();
            win_ctx.Rax = ctx.rax as u64;
            win_ctx.Rcx = ctx.rcx as u64;
            win_ctx.Rdx = ctx.rdx as u64;
            win_ctx.Rbx = ctx.rbx as u64;
            win_ctx.Rsp = ctx.rsp as u64;
            win_ctx.Rbp = ctx.rbp as u64;
            win_ctx.Rsi = ctx.rsi as u64;
            win_ctx.Rdi = ctx.rdi as u64;
            win_ctx.R8 = ctx.r8 as u64;
            win_ctx.R9 = ctx.r9 as u64;
            win_ctx.R10 = ctx.r10 as u64;
            win_ctx.R11 = ctx.r11 as u64;
            win_ctx.R12 = ctx.r12 as u64;
            win_ctx.R13 = ctx.r13 as u64;
            win_ctx.R14 = ctx.r14 as u64;
            win_ctx.R15 = ctx.r15 as u64;
            win_ctx.Rip = ctx.rip as u64;
            if native_xstate {
                (*tls.guest_xsave_area.get()).restore_to_context(win_ctx);
            }
        }
        tls.guest_xstate_format.set(GuestXstateFormat::Windows);
        // Ensure the context is written before we set `is_in_guest` so that
        // `ThreadHandle::interrupt` can see a consistent state.
        std::sync::atomic::compiler_fence(Ordering::Release);
        let windows_guest = guest_tls_mode() == GuestTlsMode::Windows;
        // SAFETY: This thread owns both TEB states. Only the transition assembly
        // and the native NtContinue stub run before control reaches the guest.
        if windows_guest {
            unsafe { install_guest_teb(tls) };
        }
        unsafe {
            core::arch::asm!(
                "mov BYTE PTR [{tls} + {IS_IN_GUEST}], 1",
                "cmp BYTE PTR [{tls} + {INTERRUPT}], 0",
                "je 2f",
                "jmp {interrupt_callback}",
                "2:",
                tls = in(reg) tls,
                IS_IN_GUEST = const core::mem::offset_of!(TlsState, is_in_guest),
                INTERRUPT = const core::mem::offset_of!(TlsState, interrupt),
                interrupt_callback = sym interrupt_callback,
            );
        }
        unsafe {
            let status = NtContinue(win_ctx, 0);
            tls.is_in_guest.set(false);
            if windows_guest {
                restore_host_teb(tls);
            }
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
    match guest_tls_mode() {
        GuestTlsMode::Linux => WindowsUserland::restore_thread_fs_base(tls),
        GuestTlsMode::Windows => {
            debug_assert_ne!(tls.guest_teb.get(), 0, "guest TEB is not configured");
        }
    }

    // The fast path for switching to the guest relies on rcx == rip. This is
    // the common case, because the syscall instruction sets rcx to rip at entry
    // to the kernel. When this is not the case, we use NtContinue to jump to
    // the guest with the full register state.
    //
    // This is much slower, but it is only used for things like signal handlers,
    // so it should not be on the critical path.
    if tls.guest_xstate_format.get() == GuestXstateFormat::Native && ctx.rcx == ctx.rip {
        switch_to_guest_sysret(ctx, tls)
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

    #[cfg(debug_assertions)]
    fn run_test_thread<R>(f: impl FnOnce() -> R) -> R {
        let tls = TlsState::new();
        ThreadHandle::run_with_handle(&tls, f)
    }
}

impl litebox::platform::TimerProvider for WindowsUserland {
    type TimerHandle = TimerHandle;
    type Signal = litebox_common_linux::signal::Signal;

    fn create_timer(
        &self,
        signal: Self::Signal,
    ) -> Result<Self::TimerHandle, litebox::platform::TimerCreationError> {
        let ctx = Box::new(TimerCallbackContext { signal });

        // Create a threadpool timer with the callback registered up-front.
        // The callback fires whenever the timer is armed via
        // `SetThreadpoolTimer` and the due time elapses.
        //
        // Safety: We pass a raw pointer to `ctx` which is heap-allocated via
        // `Box` and lives as long as the `TimerHandle`. The `Drop` impl
        // cancels and waits for all in-flight callbacks before the `Box` is
        // dropped, so the pointer remains valid for every callback invocation.
        let tp_timer = unsafe {
            Win32_Threading::CreateThreadpoolTimer(
                Some(threadpool_timer_callback),
                &raw const *ctx as *mut c_void,
                std::ptr::null(),
            )
        };
        assert!(
            tp_timer != 0,
            "CreateThreadpoolTimer failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(TimerHandle {
            tp_timer,
            _ctx: ctx,
        })
    }
}

pub struct TimerHandle {
    tp_timer: Win32_Threading::PTP_TIMER,
    /// Prevent the context from being dropped while the timer is alive.
    /// The raw pointer passed to the threadpool callback points into this box.
    _ctx: Box<TimerCallbackContext>,
}

impl Drop for TimerHandle {
    fn drop(&mut self) {
        // Cancel any pending callback, wait for in-flight callbacks to
        // complete, then close the threadpool timer.
        //
        // After this sequence completes the callback will never run again, so
        // it is safe to let `self.ctx` (the `Box`) drop normally.
        unsafe {
            Win32_Threading::SetThreadpoolTimer(self.tp_timer, std::ptr::null(), 0, 0);
            Win32_Threading::WaitForThreadpoolTimerCallbacks(self.tp_timer, 1);
            Win32_Threading::CloseThreadpoolTimer(self.tp_timer);
        }
    }
}

impl litebox::platform::TimerHandle for TimerHandle {
    fn set_timer(&self, duration: core::time::Duration) {
        if duration.is_zero() {
            // A zero duration cancels the timer without firing.
            // Passing NULL as the due-time pointer tells Windows to cancel
            // the pending callback.
            unsafe {
                Win32_Threading::SetThreadpoolTimer(self.tp_timer, std::ptr::null(), 0, 0);
            }
            return;
        }

        // Due time is in 100 ns intervals; negative means relative.
        // Pack into a FILETIME for SetThreadpoolTimer.
        let due_time_100ns: i64 = {
            let intervals = duration.as_nanos() / 100;
            -(i64::try_from(intervals).unwrap_or(i64::MAX))
        };
        let due_time = FILETIME {
            dwLowDateTime: due_time_100ns.cast_unsigned().trunc(),
            dwHighDateTime: (due_time_100ns >> 32).cast_unsigned().trunc(),
        };

        // Arm the threadpool timer. The callback registered at creation
        // time will fire after `duration` elapses.
        unsafe {
            Win32_Threading::SetThreadpoolTimer(
                self.tp_timer,
                &raw const due_time,
                0, // no repeat
                0, // no window
            );
        }
    }
}

/// Context shared between the `TimerHandle` and the threadpool timer callback.
struct TimerCallbackContext {
    signal: litebox_common_linux::signal::Signal,
}

/// Threadpool timer callback registered via `CreateThreadpoolTimer`.
///
/// Picks an arbitrary active thread and delivers the signal.
unsafe extern "system" fn threadpool_timer_callback(
    _instance: Win32_Threading::PTP_CALLBACK_INSTANCE,
    context: *mut c_void,
    _timer: Win32_Threading::PTP_TIMER,
) {
    // Safety: `context` points to the `TimerCallbackContext` owned by the
    // `TimerHandle`. The handle's `Drop` impl waits for all in-flight
    // callbacks before dropping the context, so this reference is valid.
    let ctx = unsafe { &*context.cast::<TimerCallbackContext>() };
    let thread = ACTIVE_THREADS.lock().unwrap().first().cloned();
    if let Some(thread) = thread {
        thread.deliver_signal(ctx.signal);
    }
}

/// Console control handler registered via `SetConsoleCtrlHandler`.
///
/// When the user presses Ctrl+C, this sets the SIGINT bit on every active
/// managed thread and interrupts them so the shim can deliver the signal.
unsafe extern "system" fn ctrl_c_handler(ctrl_type: u32) -> i32 {
    if ctrl_type != windows_sys::Win32::System::Console::CTRL_C_EVENT {
        return 0; // FALSE — let the next handler deal with it
    }

    // Pick one arbitrary thread to deliver the signal to.
    let thread = ACTIVE_THREADS.lock().unwrap().first().cloned();

    if let Some(thread) = thread {
        thread.deliver_signal(litebox_common_linux::signal::Signal::SIGINT);
    }

    1 // TRUE — we handled it
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

/// Global registry of all active managed thread handles.
///
/// Threads are registered in [`ThreadHandle::run_with_handle`] and
/// removed when the guard drops.
///
/// TODO: This global list only works when we support a single process. For
/// multi-process support, each process (or `WindowsUserland` instance) should
/// track its own thread list.
static ACTIVE_THREADS: Mutex<alloc::vec::Vec<ThreadHandle>> = Mutex::new(alloc::vec::Vec::new());

impl ThreadHandle {
    /// Creates a [`ThreadHandle`] referencing the calling OS thread.
    fn for_current_thread(tls: &TlsState) -> ThreadHandle {
        let win_handle = unsafe {
            std::os::windows::io::BorrowedHandle::borrow_raw(
                windows_sys::Win32::System::Threading::GetCurrentThread(),
            )
        };
        ThreadHandle(Arc::new(Mutex::new(Some(ThreadHandleInner {
            handle: win_handle
                .try_clone_to_owned()
                .expect("failed to clone current thread handle"),
            tls: SendConstPtr(tls),
        }))))
    }

    /// Runs `f`, ensuring that [`CURRENT_THREAD_HANDLE`] is set while in the call to `f`.
    fn run_with_handle<R>(tls: &TlsState, f: impl FnOnce() -> R) -> R {
        // Safety: `tls_state` lives for the duration of this call.
        unsafe { install_tls(tls) };

        let handle = Self::for_current_thread(tls);
        ACTIVE_THREADS.lock().unwrap().push(handle.clone());
        CURRENT_THREAD_HANDLE.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "thread is already registered with LiteBox",
            );
            *current = Some(handle.clone());
        });
        let _guard = litebox::utils::defer(move || {
            let current = CURRENT_THREAD_HANDLE.take().unwrap();
            // Remove from the global registry.
            ACTIVE_THREADS
                .lock()
                .unwrap()
                .retain(|h| !Arc::ptr_eq(&h.0, &current.0));
            *current.0.lock().unwrap() = None;
            uninstall_tls();
        });
        f()
    }

    /// Sets a pending signal on this thread, wakes it from any condvar wait,
    /// and interrupts it so the shim processes the signal promptly.
    fn deliver_signal(&self, signal: litebox_common_linux::signal::Signal) {
        let bit: u32 = 1 << (signal.as_i32() - 1);

        // Set the pending signal bit and wake the condvar in one lock scope.
        {
            let inner = self.0.lock().unwrap();
            if let Some(inner) = inner.as_ref() {
                // Safety: the TLS pointer is valid as long as the thread is
                // alive, and we hold the thread handle lock.
                let tls = unsafe { &*inner.tls.0 };
                tls.pending_host_signals.fetch_or(bit, Ordering::SeqCst);

                let waker = tls.waiting_waker.load(Ordering::Acquire);
                if !waker.is_null() {
                    // SAFETY: `waker` was heap-allocated via `Box::into_raw` in
                    // `update_waker`. It remains valid here because
                    // `update_waker` acquires this same `ThreadHandleInner`
                    // mutex before freeing the old pointer, and we hold that
                    // mutex now.
                    let waker = unsafe { &*waker };
                    waker.wake_by_ref();
                }
            }
        }

        self.interrupt(None);
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
        // SAFETY: The target thread-handle mutex serializes all users of this
        // scratch buffer. It is separate from the saved guest continue_context.
        let extended_context = unsafe { &mut *target_tls.interrupt_context.get() };
        let context = extended_context.prepare_for_capture();
        let r = unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::GetThreadContext(
                inner.handle.as_raw_handle(),
                context,
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
            .contains(&(context.Rip.trunc()))
        {
            // Case 1: jump to interrupt callback without saving the guest
            // context, since it's already saved.
            true
        } else if is_in_ntdll_or_this(context.Rip.trunc()) {
            // Case 2/3: we can't distinguish between them. For case 3 we don't
            // need to do anything, but for case 2 we need to update the
            // NtContinue context to point to the interrupt callback (the guest
            // context is already up to date).
            //
            // In case 3, the NtContinue context is not being used, so it is
            // safe to update it anyway.

            // SAFETY: `continue_context` is not accessed by user-mode code
            // while `is_in_guest` is true.
            let continue_context = unsafe { (*target_tls.continue_context.get()).as_ptr() };
            set_context_to_interrupt_callback(unsafe { &mut *continue_context });
            false
        } else {
            // Case 4: save the guest context and jump to interrupt callback.
            save_guest_context(target_tls, unsafe { &mut *guest_context }, context);
            true
        };
        if run_interrupt_callback {
            set_context_to_interrupt_callback(context);
            context.ContextFlags =
                windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64;
            // SAFETY: The target is suspended and only its control state is changed.
            unsafe {
                windows_sys::Win32::System::Diagnostics::Debug::SetThreadContext(
                    inner.handle.as_raw_handle(),
                    context,
                );
            }
        }
    }
}

/// Updates `context` to jump to the interrupt callback, which restores the host stack.
fn set_context_to_interrupt_callback(
    context: &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    let required_flags = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64;
    assert_eq!(context.ContextFlags & required_flags, required_flags);
    context.Rip = interrupt_callback as *const () as usize as u64;
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

impl RawMutexProvider for WindowsUserland {
    type RawMutex = RawMutex;
}

impl WaitWakerProvider for WindowsUserland {
    fn update_waker(&self, waker: Option<core::task::Waker>) {
        if let Some(tls) = get_tls_ptr().map(|p| unsafe { &*p }) {
            let waker_ptr = waker.map_or(std::ptr::null_mut(), |w| Box::into_raw(Box::new(w)));
            let old = tls.waiting_waker.swap(waker_ptr, Ordering::AcqRel);
            if !old.is_null() {
                // Synchronize with `deliver_signal`, which may be concurrently
                // reading the old waker pointer on another thread while holding
                // the `ThreadHandleInner` mutex. Acquiring the same mutex here
                // ensures that `deliver_signal` has finished using the pointer
                // before we free it.
                CURRENT_THREAD_HANDLE.with_borrow(|handle| {
                    let _guard = handle.as_ref().map(|handle| handle.0.lock().unwrap());
                    // SAFETY: old pointer was created by Box::into_raw in a previous
                    // call to update_waker. No other thread can be accessing it now
                    // because we synchronized via the ThreadHandleInner mutex above.
                    unsafe { drop(Box::from_raw(old)) };
                });
            }
        }
    }
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

    #[expect(clippy::unnecessary_wraps)]
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // Compute timeout in ms
        let timeout_ms = match timeout {
            None => Win32_Threading::INFINITE, // no timeout
            Some(timeout) => {
                let ms = timeout.as_millis();
                ms.min(u128::from(Win32_Threading::INFINITE - 1)).trunc()
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
                Win32_Foundation::ERROR_TIMEOUT => Ok(UnblockedOrTimedOut::TimedOut),
                e => panic!("Unexpected error={e} for WaitOnAddress"),
            }
        }
    }
}

impl RawMutexTrait for RawMutex {
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
        // so we return zero to indicate that the count is unknown.
        0
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

impl TimeProvider for WindowsUserland {
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

impl InstantTrait for Instant {
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

impl SystemTimeTrait for SystemTime {
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

impl litebox::platform::ArchSpecificProvider for WindowsUserland {
    fn set_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
        val: usize,
    ) -> Result<(), litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::FsBase => {
                if litebox_common_linux::arch::is_valid_user_fs_base(val) {
                    Self::set_thread_fs_base(val);
                    Ok(())
                } else {
                    Err(litebox::platform::ArchSpecificError::RegisterUnpermittedValue)
                }
            }
            litebox::platform::ArchSpecificRegister::GsBase
                if guest_tls_mode() == GuestTlsMode::Windows =>
            {
                if val != 0 && litebox_common_linux::arch::is_valid_user_fs_base(val) {
                    Self::set_guest_teb(val);
                    Ok(())
                } else {
                    Err(litebox::platform::ArchSpecificError::RegisterUnpermittedValue)
                }
            }
            litebox::platform::ArchSpecificRegister::GsBase => {
                // Windows uses GS for its own thread environment block
                // (TEB); the host platform does not expose a safe way for
                // the guest to program gs base without breaking the host.
                Err(litebox::platform::ArchSpecificError::RegisterReserved)
            }
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }

    fn get_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
    ) -> Result<usize, litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::FsBase => get_tls_ptr()
                .map(|tls| unsafe { &*tls }.guest_fs_base.get())
                .ok_or(litebox::platform::ArchSpecificError::RegisterUnsupported),
            litebox::platform::ArchSpecificRegister::GsBase
                if guest_tls_mode() == GuestTlsMode::Windows =>
            {
                get_tls_ptr()
                    .map(|tls| unsafe { &*tls }.guest_teb.get())
                    .ok_or(litebox::platform::ArchSpecificError::RegisterUnsupported)
            }
            litebox::platform::ArchSpecificRegister::GsBase => {
                // See note above: gs base is reserved by the Windows host.
                Err(litebox::platform::ArchSpecificError::RegisterReserved)
            }
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
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

    /// Writes selected guest TEB fields to its shadow and restores saved host fields.
    /// Excluded graphics fields are neither saved nor restored; see `TEB_SWAP_RANGES`.
    /// GS is unchanged. Internal guest pointers are relocated back into the shadow.
    ///
    /// # Safety
    ///
    /// `tls` must belong to this thread and have a configured, nonzero guest TEB.
    /// Its TEB allocations must be live, disjoint, and writable for `GUEST_TEB_SIZE`
    /// bytes. Guest TEB state must be installed and the host save area must contain
    /// valid state.
    #[expect(
        improper_ctypes,
        reason = "assembly entry in install_guest_teb uses Rust-computed TlsState offsets"
    )]
    fn restore_host_teb(tls: &TlsState);

    /// Restores the entire modeled host TEB and writes guest state back to its shadow.
    ///
    /// # Safety
    ///
    /// The same requirements as `restore_host_teb` apply, and the preceding
    /// install must have used `install_guest_whole_teb`.
    #[expect(
        improper_ctypes,
        reason = "assembly entry in install_guest_whole_teb uses Rust-computed TlsState offsets"
    )]
    fn restore_host_whole_teb(tls: &TlsState);
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
        code => panic!("Unhandled Win32 exception code: {code:#x}"),
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
    #[test]
    #[ignore = "microbenchmark; run in release mode with --ignored --nocapture"]
    fn benchmark_teb_exchange_selective_vs_whole() {
        #[unsafe(naked)]
        unsafe extern "C" fn round_trips<const SELECTIVE: bool>(
            _tls: &super::TlsState,
            _iterations: usize,
        ) {
            core::arch::naked_asm!(
                "push rsi",
                "push rdi",
                "sub rsp, 40",
                "mov rsi, rcx",
                "mov rdi, rdx",
                "2:",
                "mov rcx, rsi",
                ".if {SELECTIVE}",
                "call {install_selective}",
                "mov rcx, rsi",
                "call {restore_selective}",
                ".else",
                "call {install_whole}",
                "mov rcx, rsi",
                "call {restore_whole}",
                ".endif",
                "dec rdi",
                "jnz 2b",
                "add rsp, 40",
                "pop rdi",
                "pop rsi",
                "ret",
                SELECTIVE = const SELECTIVE as usize,
                install_selective = sym super::install_guest_teb,
                restore_selective = sym super::restore_host_teb,
                install_whole = sym super::install_guest_whole_teb,
                restore_whole = sym super::restore_host_whole_teb,
            );
        }

        const ITERATIONS: usize = 500_000;
        const SAMPLES: usize = 21;
        assert!(
            !std::hint::black_box(super::USE_WHOLE_TEB_SWAP),
            "disable the whole-TEB fallback before benchmarking"
        );
        let tls = super::TlsState::new();
        let mut native = Box::new([0x1111_1111_1111_1111usize; super::GUEST_TEB_SIZE / 8]);
        let mut guest = Box::new([0x2222_2222_2222_2222usize; super::GUEST_TEB_SIZE / 8]);
        let guest_base = guest.as_mut_ptr().addr();
        for offset in super::TEB_INTERNAL_POINTER_OFFSETS {
            guest[offset / 8] = guest_base + offset;
        }
        let original_native = native.clone();
        let original_guest = guest.clone();
        tls.host_teb.set(native.as_mut_ptr().cast());
        tls.guest_teb.set(guest_base);
        // SAFETY: Both implementations use the same live, disjoint synthetic TEB
        // buffers and balanced transitions; GS and the real host TEB are untouched.
        unsafe {
            round_trips::<false>(&tls, 10_000);
            round_trips::<true>(&tls, 10_000);
        }
        let mut before = [0.0f64; SAMPLES];
        let mut after = [0.0f64; SAMPLES];
        for sample in 0..SAMPLES {
            for selective in [sample % 2 != 0, sample % 2 == 0] {
                let start = std::time::Instant::now();
                // SAFETY: Same validated buffers and balanced transitions as warmup.
                unsafe {
                    if selective {
                        round_trips::<true>(&tls, ITERATIONS);
                    } else {
                        round_trips::<false>(&tls, ITERATIONS);
                    }
                }
                let elapsed = start.elapsed().as_secs_f64() * 1e9
                    / f64::from(u32::try_from(ITERATIONS).unwrap());
                if selective {
                    after[sample] = elapsed;
                } else {
                    before[sample] = elapsed;
                }
                assert_eq!(native, original_native);
                assert_eq!(guest, original_guest);
            }
        }
        before.sort_by(f64::total_cmp);
        after.sort_by(f64::total_cmp);
        let selected_bytes: usize = super::TEB_SWAP_RANGES
            .iter()
            .map(|[start, end]| end - start)
            .sum();
        println!(
            "Warm-cache synthetic TEB round trip (install + restore), {SAMPLES} samples, {ITERATIONS} iterations/sample; alternating order"
        );
        println!(
            "Whole: {} bytes; median {:.2} ns, min {:.2}, max {:.2}",
            super::GUEST_TEB_SIZE,
            before[SAMPLES / 2],
            before[0],
            before[SAMPLES - 1],
        );
        println!(
            "Selective: {selected_bytes} bytes; median {:.2} ns, min {:.2}, max {:.2}",
            after[SAMPLES / 2],
            after[0],
            after[SAMPLES - 1],
        );
        println!(
            "Reduction: {:.2} ns ({:.1}%); speedup {:.2}x",
            before[SAMPLES / 2] - after[SAMPLES / 2],
            (1.0 - after[SAMPLES / 2] / before[SAMPLES / 2]) * 100.0,
            before[SAMPLES / 2] / after[SAMPLES / 2],
        );
    }

    #[test]
    fn configured_teb_exchange_preserves_selected_state() {
        check_teb_exchange(
            super::install_guest_teb,
            super::restore_host_teb,
            super::USE_WHOLE_TEB_SWAP,
        );
    }

    #[test]
    fn whole_teb_exchange_preserves_all_state() {
        check_teb_exchange(
            super::install_guest_whole_teb,
            super::restore_host_whole_teb,
            true,
        );
    }

    fn check_teb_exchange(
        install: unsafe extern "C" fn(&super::TlsState),
        restore: unsafe extern "C" fn(&super::TlsState),
        whole: bool,
    ) {
        let tls = super::TlsState::new();
        let mut native = Box::new([0x1111_1111_1111_1111usize; super::GUEST_TEB_SIZE / 8]);
        let mut guest = Box::new([0x2222_2222_2222_2222usize; super::GUEST_TEB_SIZE / 8]);
        let native_base = native.as_mut_ptr().addr();
        let guest_base = guest.as_mut_ptr().addr();
        for offset in super::TEB_INTERNAL_POINTER_OFFSETS {
            guest[offset / 8] = guest_base + offset;
        }
        let original_native = native.clone();
        let original_guest = guest.clone();
        tls.host_teb.set(native.as_mut_ptr().cast());
        tls.guest_teb.set(guest_base);

        // SAFETY: These disjoint, initialized buffers cover the modeled TEB.
        // The helper does not access GS, so the actual native TEB stays installed.
        unsafe { install(&tls) };
        for index in 0..native.len() {
            let offset = index * 8;
            let selected = whole
                || super::TEB_SWAP_RANGES
                    .iter()
                    .any(|&[start, end]| (start..end).contains(&offset));
            let expected = if super::TEB_INTERNAL_POINTER_OFFSETS.contains(&offset) {
                assert!(selected);
                native_base + offset
            } else if selected {
                original_guest[index]
            } else {
                original_native[index]
            };
            assert_eq!(native[index], expected, "offset {offset:#x}");
            if selected && !super::TEB_INTERNAL_POINTER_OFFSETS.contains(&offset) {
                native[index] = 0x3333_3333_3333_3333;
            }
        }
        // SAFETY: The same live buffers contain balanced host/guest states.
        unsafe { restore(&tls) };
        assert_eq!(native, original_native);
        for index in 0..guest.len() {
            let offset = index * 8;
            let selected = whole
                || super::TEB_SWAP_RANGES
                    .iter()
                    .any(|&[start, end]| (start..end).contains(&offset));
            let expected = if selected && !super::TEB_INTERNAL_POINTER_OFFSETS.contains(&offset) {
                0x3333_3333_3333_3333
            } else {
                original_guest[index]
            };
            assert_eq!(guest[index], expected, "offset {offset:#x}");
        }
    }

    use core::sync::atomic::AtomicU32;
    use std::thread::sleep;

    use crate::WindowsUserland;
    use crate::process_memory_range_by_regions;
    use crate::{XsaveArea, XsaveLayout};
    use litebox::platform::PageManagementProvider;
    use litebox::platform::RawConstPointer;
    use litebox::platform::page_mgmt::FixedAddressBehavior;
    use litebox::platform::page_mgmt::MemoryRegionPermissions;
    use litebox_platform::sync::RawMutex;

    #[test]
    fn interrupt_capture_preserves_xstate_on_reuse() {
        use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
        use litebox_common_linux::PtRegs;
        use std::cell::Cell;
        use std::sync::atomic::Ordering;
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAlloc,
            VirtualFree, VirtualProtect,
        };

        const TEST_VECTOR_QWORD: u64 = 0x5a5a_5a5a_5a5a_5a5a;
        const TEST_NEXT_VECTOR_QWORD: u64 = 0x3c3c_3c3c_3c3c_3c3c;
        const TEST_MXCSR: u32 = 0x3f80;

        #[unsafe(naked)]
        unsafe extern "C" fn guest_entry() {
            core::arch::naked_asm!(
                "sub rsp, 40",
                "mov DWORD PTR [rsp + 32], {mxcsr}",
                "mov rax, {vector}",
                "mov QWORD PTR [rsp], rax",
                "mov QWORD PTR [rsp + 8], rax",
                "mov QWORD PTR [rsp + 16], rax",
                "mov QWORD PTR [rsp + 24], rax",
                "ldmxcsr [rsp + 32]",
                "movdqu xmm0, [rsp]",
                "test rsi, rsi",
                "jz 2f",
                "vmovdqu ymm0, [rsp]",
                "2:",
                "add rsp, 40",
                "jmp rbx",
                mxcsr = const TEST_MXCSR,
                vector = const TEST_VECTOR_QWORD,
            );
        }

        #[unsafe(naked)]
        unsafe extern "C" fn guest_after_interrupt() {
            core::arch::naked_asm!(
                // Change the state before reusing the interrupt capture buffer.
                "sub rsp, 32",
                "mov rax, {vector}",
                "mov QWORD PTR [rsp], rax",
                "mov QWORD PTR [rsp + 8], rax",
                "mov QWORD PTR [rsp + 16], rax",
                "mov QWORD PTR [rsp + 24], rax",
                "movdqu xmm0, [rsp]",
                "test rsi, rsi",
                "jz 2f",
                "vmovdqu ymm0, [rsp]",
                "2:",
                "add rsp, 32",
                "jmp rbx",
                vector = const TEST_NEXT_VECTOR_QWORD,
            );
        }

        #[unsafe(naked)]
        unsafe extern "C" fn guest_stop() {
            core::arch::naked_asm!(
                "jmp {syscall_callback}",
                syscall_callback = sym crate::syscall_callback,
            );
        }

        struct InterruptShim {
            count: Cell<usize>,
            avx: bool,
        }

        impl EnterShim for InterruptShim {
            type ExecutionContext = PtRegs;

            fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                ContinueOperation::Resume
            }

            fn syscall(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                ContinueOperation::Terminate
            }

            fn exception(&self, _ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
                panic!("unexpected guest exception: {info:?}");
            }

            fn interrupt(&self, ctx: &mut PtRegs) -> ContinueOperation {
                let expected = [0x5a, 0x3c][self.count.get()];
                // SAFETY: The target has returned to the host; its saved context
                // is not concurrently accessible while is_in_guest is false.
                let context = unsafe {
                    &mut *(*(*crate::get_tls_ptr().unwrap()).continue_context.get()).as_ptr()
                };
                assert_eq!(context.MxCsr, TEST_MXCSR);
                // SAFETY: GetThreadContext and CopyContext initialized FltSave.
                let legacy = unsafe { context.Anonymous.FltSave };
                assert_eq!(
                    legacy.XmmRegisters[0].Low,
                    u64::from_le_bytes([expected; 8])
                );
                assert_eq!(
                    legacy.XmmRegisters[0].High.cast_unsigned(),
                    u64::from_le_bytes([expected; 8])
                );
                if self.avx {
                    let mut length = 0;
                    // SAFETY: The saved context has initialized AVX storage.
                    let upper = unsafe {
                        windows_sys::Win32::System::Diagnostics::Debug::LocateXStateFeature(
                            context,
                            2,
                            &raw mut length,
                        )
                        .cast::<u8>()
                    };
                    assert!(!upper.is_null() && length >= 16);
                    // SAFETY: The AVX component contains at least 16 initialized bytes.
                    assert_eq!(
                        unsafe { core::slice::from_raw_parts(upper, 16) },
                        [expected; 16]
                    );
                }
                let count = self.count.get() + 1;
                self.count.set(count);
                if count == 2 {
                    return ContinueOperation::Terminate;
                }
                ctx.rip = ctx.r12;
                ContinueOperation::Resume
            }
        }

        crate::GUEST_TLS_MODE.store(
            crate::GuestTlsMode::Linux as u8,
            core::sync::atomic::Ordering::Release,
        );

        // Place the spin loop outside this module so `is_in_ntdll_or_this`
        // classifies its RIP as guest code and `interrupt` exercises case 4,
        // which captures the live guest context and XSTATE.
        // SAFETY: Allocate a private page, populate it while writable, then make
        // it executable before starting the worker. The page outlives the worker.
        let code = unsafe {
            VirtualAlloc(
                core::ptr::null(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        assert!(!code.is_null());
        let _free = litebox::utils::defer(|| {
            // SAFETY: The worker is joined before the uniquely owned page is freed.
            assert_ne!(unsafe { VirtualFree(code, 0, MEM_RELEASE) }, 0);
        });
        // mov dword ptr [rdi], 1; pause; cmp dword ptr [r14], 0; je pause; jmp r13.
        let instructions = [
            0xc7_u8, 0x07, 1, 0, 0, 0, 0xf3, 0x90, 0x41, 0x83, 0x3e, 0, 0x74, 0xf8, 0x41, 0xff,
            0xe5,
        ];
        // SAFETY: The page is writable and large enough for these instructions.
        unsafe {
            code.cast::<u8>()
                .copy_from_nonoverlapping(instructions.as_ptr(), instructions.len());
        };
        let mut old_protection = 0;
        // SAFETY: The page is exclusively owned and the worker has not started.
        assert_ne!(
            unsafe { VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &raw mut old_protection) },
            0
        );
        // SAFETY: Flush the newly populated executable page before running it.
        assert_ne!(
            unsafe {
                windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache(
                    crate::GetCurrentProcess(),
                    code,
                    instructions.len(),
                )
            },
            0
        );

        let code_address = code.addr();
        // Capture 0x5a and then 0x3c into the same interrupt scratch context.
        let ready = AtomicU32::new(0);
        let stop = AtomicU32::new(0);
        std::thread::scope(|scope| {
            let _stop_worker = litebox::utils::defer(|| stop.store(1, Ordering::Release));
            let timeout = std::time::Duration::from_secs(5);
            let deadline = std::time::Instant::now() + timeout;
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let ready_ref = &ready;
            let stop_ref = &stop;
            let worker = scope.spawn(move || {
                let shim = InterruptShim {
                    count: Cell::new(0),
                    avx: std::is_x86_feature_detected!("avx"),
                };
                let mut stack = [0_u128; 256];
                let entry = guest_entry as *const () as usize;
                let mut ctx = PtRegs {
                    rip: entry,
                    rcx: entry,
                    rbx: code_address,
                    rdi: core::ptr::from_ref(ready_ref).addr(),
                    rsi: usize::from(shim.avx),
                    r12: guest_after_interrupt as *const () as usize,
                    r13: guest_stop as *const () as usize,
                    r14: core::ptr::from_ref(stop_ref).addr(),
                    rsp: stack.as_mut_ptr().wrapping_add(stack.len()).addr(),
                    eflags: 0x202,
                    ..Default::default()
                };
                let tls = crate::TlsState::new();
                tls.guest_context_top
                    .set(core::ptr::from_mut(&mut ctx).wrapping_add(1));
                let mut thread_ctx = crate::ThreadContext {
                    shim: &shim,
                    ctx: &mut ctx,
                    tls: &tls,
                };
                crate::ThreadHandle::run_with_handle(&tls, || {
                    sender
                        .send(
                            crate::CURRENT_THREAD_HANDLE
                                .with_borrow(|handle| handle.clone().unwrap()),
                        )
                        .unwrap();
                    // SAFETY: The worker owns a live guest stack and TLS until termination.
                    unsafe { crate::run_thread_arch(&mut thread_ctx, &tls) };
                });
                shim.count.get()
            });
            let handle = receiver.recv_timeout(timeout).expect("guest did not start");
            for _ in 0..2 {
                // The trampoline publishes readiness only after the new XSTATE
                // value is live, so each capture has a deterministic expectation.
                while ready.swap(0, Ordering::Acquire) == 0 {
                    assert!(
                        !worker.is_finished(),
                        "guest exited before signaling readiness"
                    );
                    assert!(
                        std::time::Instant::now() < deadline,
                        "guest readiness timed out"
                    );
                    std::thread::yield_now();
                }
                handle.interrupt(None);
            }
            while !worker.is_finished() {
                assert!(std::time::Instant::now() < deadline, "guest exit timed out");
                std::thread::yield_now();
            }
            assert_eq!(worker.join().unwrap(), 2);
        });
    }

    #[test]
    fn xsave_syscalls_preserve_state_across_resume_paths() {
        use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
        use litebox_common_linux::PtRegs;
        use std::cell::Cell;

        const TEST_CW: u16 = 0x077e;
        const TEST_MXCSR: u32 = 0x3f80;
        const TEST_VECTOR_QWORD: u64 = 0x5a5a_5a5a_5a5a_5a5a;
        const X87_STATUS_INVALID_OPERATION: u16 = 1 << 0;
        const X87_STATUS_EXCEPTION_SUMMARY: u16 = 1 << 7;

        #[unsafe(naked)]
        unsafe extern "C" fn guest_entry() {
            core::arch::naked_asm!(
                "stmxcsr [rsi]",
                "fnstcw [rsi + 4]",
                "sub rsp, 40",
                "mov WORD PTR [rsp + 32], {control_word}",
                "mov DWORD PTR [rsp + 36], {mxcsr}",
                "mov rax, {vector}",
                "mov QWORD PTR [rsp], rax",
                "mov QWORD PTR [rsp + 8], rax",
                "mov QWORD PTR [rsp + 16], rax",
                "mov QWORD PTR [rsp + 24], rax",
                "fldcw [rsp + 32]",
                "ldmxcsr [rsp + 36]",
                "movdqu xmm0, [rsp]",
                "test rdi, rdi",
                "jz 2f",
                "vmovdqu ymm0, [rsp]",
                "2:",
                // Leave an unmasked invalid-operation exception pending.
                "fldz",
                "fldz",
                "fdivp st(1), st(0)",
                "add rsp, 40",
                "lea rcx, [rip + 3f]",
                "jmp {syscall_callback}",
                "3:",
                "lea rcx, [rip + 4f]",
                "jmp {syscall_callback}",
                "4:",
                "lea rcx, [rip + 5f]",
                "jmp {syscall_callback}",
                "5:",
                "pxor xmm0, xmm0",
                "test rdi, rdi",
                "jz 6f",
                "vzeroall",
                "6:",
                "lea rcx, [rip + 7f]",
                "jmp {syscall_callback}",
                "7:",
                "lea rcx, [rip + 8f]",
                "jmp {syscall_callback}",
                "8:",
                "lea rcx, [rip + 9f]",
                "jmp {syscall_callback}",
                "9:",
                "ud2",
                control_word = const TEST_CW,
                mxcsr = const TEST_MXCSR,
                vector = const TEST_VECTOR_QWORD,
                syscall_callback = sym crate::syscall_callback,
            );
        }

        struct StateShim {
            calls: Cell<usize>,
            avx: bool,
        }

        impl EnterShim for StateShim {
            type ExecutionContext = PtRegs;

            fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                ContinueOperation::Resume
            }

            fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
                let pending_status = X87_STATUS_INVALID_OPERATION | X87_STATUS_EXCEPTION_SUMMARY;
                let host_status: u16;
                // SAFETY: FNSTSW only reads the current thread's x87 status word.
                unsafe {
                    core::arch::asm!(
                        "fnstsw ax",
                        lateout("ax") host_status,
                        options(nomem, nostack, preserves_flags),
                    );
                }
                assert_eq!(host_status & pending_status, 0);

                let call = self.calls.get() + 1;
                self.calls.set(call);
                // SAFETY: This is the active guest's host callback; capture has finished.
                let area = unsafe { &*(*crate::get_tls_ptr().unwrap()).guest_xsave_area.get() };
                let legacy = area.legacy_state_for_context();
                assert_eq!(legacy.ControlWord, TEST_CW);
                assert_eq!(legacy.StatusWord & pending_status, pending_status);
                assert_eq!(legacy.MxCsr, TEST_MXCSR);
                let expected = if call >= 4 { 0 } else { 0x5a };
                assert_eq!(
                    legacy.XmmRegisters[0].Low,
                    u64::from_le_bytes([expected; 8])
                );
                assert_eq!(
                    legacy.XmmRegisters[0].High.cast_unsigned(),
                    u64::from_le_bytes([expected; 8])
                );
                if self.avx {
                    let component = XsaveLayout::get()
                        .components
                        .iter()
                        .find(|component| component.id == 2)
                        .unwrap();
                    if area.xstate_bv() & 4 != 0 {
                        // SAFETY: The enabled AVX component contains YMM0's upper 16 bytes.
                        let upper = unsafe {
                            core::slice::from_raw_parts(area.as_ptr().add(component.offset), 16)
                        };
                        assert_eq!(upper, [expected; 16]);
                    } else {
                        assert_eq!(expected, 0);
                    }
                }
                if call == 2 || call == 4 {
                    // Force the guest to take the slower `NtContinue` resume path.
                    ctx.rcx = 0;
                }
                if call == 6 {
                    ContinueOperation::Terminate
                } else {
                    ContinueOperation::Resume
                }
            }

            fn exception(&self, _ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
                panic!("unexpected guest exception: {info:?}");
            }

            fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                ContinueOperation::Resume
            }
        }

        crate::GUEST_TLS_MODE.store(
            crate::GuestTlsMode::Linux as u8,
            core::sync::atomic::Ordering::Release,
        );
        for fast_entry in [false, true] {
            let shim = StateShim {
                calls: Cell::new(0),
                avx: std::is_x86_feature_detected!("avx"),
            };
            let mut stack = [0_u128; 256];
            let mut initial_controls = [0_u32; 2];
            let entry = guest_entry as *const () as usize;
            let mut ctx = PtRegs {
                rip: entry,
                rcx: if fast_entry { entry } else { 0 },
                rsp: stack.as_mut_ptr().wrapping_add(stack.len()).addr(),
                rsi: initial_controls.as_mut_ptr().addr(),
                rdi: usize::from(shim.avx),
                eflags: 0x202,
                ..Default::default()
            };
            crate::run_thread_inner(&shim, &mut ctx);
            assert_eq!(shim.calls.get(), 6);
            assert_eq!(
                initial_controls,
                [
                    XsaveArea::GUEST_INITIAL_MXCSR,
                    u32::from(XsaveArea::GUEST_INITIAL_X87_CONTROL_WORD)
                ]
            );
        }
    }

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
