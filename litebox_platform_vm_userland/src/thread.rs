// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest execution on the runner's thread (e.g. a TA and `ldelf`). Switching is a
//! jump: both run in ring 3.
//!
//! Entries from the guest, all producing the same `PtRegs`:
//! - `vmu_syscall_callback`: rewritten syscalls; return address in `rcx`.
//! - `upcall_entry`: from the kernel, for unmodified syscalls and unresolved
//!   exceptions.
//!
//! Assumes a single thread: the switch state is global.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use litebox::shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo};
use litebox_common_linux::PtRegs;
use litebox_common_vm_abi::{Registers, UpcallFrame, UpcallKind};
use zerocopy::TryFromBytes as _;

/// Accessed from assembly by field offset.
#[repr(C)]
struct SwitchState {
    /// Valid while `run_thread_arch` is active.
    host_sp: AtomicUsize,
    /// Valid while `run_thread_arch` is active.
    host_bp: AtomicUsize,
    /// End of the guest `PtRegs`, which entries push below it.
    guest_context_top: AtomicUsize,
    /// Scratch for [`restore_context`].
    resume_rip: AtomicUsize,
    /// Set while guest code runs, and while `vmu_enter_guest` switches to it;
    /// decides who an upcall is for.
    in_guest: AtomicBool,
    /// An interrupt upcall arrived while the runner ran; the next guest
    /// entry handles it instead (it may be due to the guest).
    pending_interrupt: AtomicBool,
}

static STATE: SwitchState = SwitchState {
    host_sp: AtomicUsize::new(0),
    host_bp: AtomicUsize::new(0),
    guest_context_top: AtomicUsize::new(0),
    resume_rip: AtomicUsize::new(0),
    in_guest: AtomicBool::new(false),
    pending_interrupt: AtomicBool::new(false),
};

type DynShim<'a> = &'a dyn EnterShim<ExecutionContext = PtRegs>;

struct ThreadContext<'a> {
    shim: DynShim<'a>,
    ctx: *mut PtRegs,
}

impl ThreadContext<'_> {
    fn call_shim(&mut self, f: impl FnOnce(DynShim<'_>, &mut PtRegs) -> ContinueOperation) {
        // Safety: `ctx` outlives `run_thread_arch`, and no other reference
        // to it is live while the shim runs.
        let op = f(self.shim, unsafe { &mut *self.ctx });
        if let ContinueOperation::Resume = op {
            // Safety: the shim prepared a guest context.
            unsafe { switch_to_guest(self.ctx) }
        }
    }
}

/// Returns when the shim terminates the guest.
///
/// # Safety
///
/// No other `run_thread_ref`/`reenter_thread_ref` may be active.
pub unsafe fn run_thread_ref<T>(shim: &T, ctx: &mut PtRegs)
where
    T: EnterShim<ExecutionContext = PtRegs>,
{
    run_thread_inner(shim, ctx, false);
}

/// Returns when the shim terminates the guest.
///
/// # Safety
///
/// As for [`run_thread_ref`].
pub unsafe fn reenter_thread_ref<T>(shim: &T, ctx: &mut PtRegs)
where
    T: EnterShim<ExecutionContext = PtRegs>,
{
    run_thread_inner(shim, ctx, true);
}

fn run_thread_inner(shim: DynShim<'_>, ctx: &mut PtRegs, reenter: bool) {
    let ctx = core::ptr::from_mut(ctx);
    let mut thread_ctx = ThreadContext { shim, ctx };
    // Safety: `ctx` is valid for the call, which returns exactly once.
    unsafe { run_thread_arch(&mut thread_ctx, ctx, u8::from(reenter)) };
}

unsafe extern "C" fn init_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.init(ctx));
}

unsafe extern "C" fn reenter_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.reenter(ctx));
}

unsafe extern "C" fn syscall_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.syscall(ctx));
}

unsafe extern "C" fn guest_exception_handler(
    thread_ctx: &mut ThreadContext,
    vector: u64,
    error_code: u64,
    fault_address: u64,
) {
    let info = ExceptionInfo {
        exception: Exception(u8::try_from(vector).unwrap_or(u8::MAX)),
        error_code: u32::try_from(error_code).unwrap_or(u32::MAX),
        cr2: usize::try_from(fault_address).unwrap_or(usize::MAX),
        kernel_mode: false,
    };
    thread_ctx.call_shim(|shim, ctx| shim.exception(ctx, &info));
}

unsafe extern "C" fn guest_interrupt_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.interrupt(ctx));
}

/// Guest entries switch back to the host stack saved here and finish at
/// `vmu_thread_done`; the function returns once, when the guest terminates.
#[unsafe(naked)]
unsafe extern "C" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut PtRegs,
    reenter: u8,
) {
    core::arch::naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "push rdi", // `thread_ctx`; also aligns the stack
        "mov [rip + {state} + {host_sp}], rsp",
        "mov [rip + {state} + {host_bp}], rbp",
        "lea r8, [rsi + {CTX_SIZE}]",
        "mov [rip + {state} + {guest_context_top}], r8",
        "test dl, dl",
        "jnz 2f",
        "call {init_handler}",
        "jmp vmu_thread_done",
        "2:",
        "call {reenter_handler}",
        "jmp vmu_thread_done",

        // Guest registers; return address in `rcx`; `r11` is free, as after
        // a real `syscall`. Clearing `in_guest` must come first.
        ".globl vmu_syscall_callback",
        "vmu_syscall_callback:",
        "mov byte ptr [rip + {state} + {in_guest}], 0",
        "mov r11, rsp",
        "mov rsp, [rip + {state} + {guest_context_top}]",
        "push 0x2b",       // ss
        "push r11",        // rsp
        "pushfq",          // rflags
        "push 0x33",       // cs
        "push rcx",        // rip
        "push rax",        // orig_rax
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push -38",        // rax = -ENOSYS
        "push r8",
        "push r9",
        "push r10",
        "push [rsp + 88]", // r11 = rflags
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rsp, [rip + {state} + {host_sp}]",
        "mov rbp, [rip + {state} + {host_bp}]",
        "mov rdi, [rsp]",
        "cld", // the guest may have left DF set
        "call {syscall_handler}",
        "jmp vmu_thread_done",

        // From `upcall_dispatch`, guest state already in the guest context.
        ".globl vmu_guest_syscall_upcall",
        "vmu_guest_syscall_upcall:",
        "mov rsp, [rip + {state} + {host_sp}]",
        "mov rbp, [rip + {state} + {host_bp}]",
        "mov rdi, [rsp]",
        "call {syscall_handler}",
        "jmp vmu_thread_done",

        // From `upcall_dispatch`, guest state already in the guest context.
        ".globl vmu_guest_interrupt_upcall",
        "vmu_guest_interrupt_upcall:",
        "mov rsp, [rip + {state} + {host_sp}]",
        "mov rbp, [rip + {state} + {host_bp}]",
        "mov rdi, [rsp]",
        "call {guest_interrupt_handler}",
        "jmp vmu_thread_done",

        // As above; rdi = vector, rsi = error code, rdx = fault address.
        ".globl vmu_guest_exception_callback",
        "vmu_guest_exception_callback:",
        "mov rcx, rdx",
        "mov rdx, rsi",
        "mov rsi, rdi",
        "mov rsp, [rip + {state} + {host_sp}]",
        "mov rbp, [rip + {state} + {host_bp}]",
        "mov rdi, [rsp]",
        "call {guest_exception_handler}",

        "vmu_thread_done:",
        "lea rsp, [rbp - 5 * 8]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret",
        state = sym STATE,
        host_sp = const core::mem::offset_of!(SwitchState, host_sp),
        host_bp = const core::mem::offset_of!(SwitchState, host_bp),
        guest_context_top = const core::mem::offset_of!(SwitchState, guest_context_top),
        in_guest = const core::mem::offset_of!(SwitchState, in_guest),
        CTX_SIZE = const size_of::<PtRegs>(),
        init_handler = sym init_handler,
        reenter_handler = sym reenter_handler,
        syscall_handler = sym syscall_handler,
        guest_exception_handler = sym guest_exception_handler,
        guest_interrupt_handler = sym guest_interrupt_handler,
    );
}

unsafe extern "C" {
    fn vmu_syscall_callback();
    fn vmu_guest_syscall_upcall() -> !;
    fn vmu_guest_interrupt_upcall() -> !;
    fn vmu_guest_exception_callback(vector: u64, error_code: u64, fault_address: u64) -> !;
}

pub(crate) fn syscall_callback_address() -> usize {
    vmu_syscall_callback as *const () as usize
}

/// # Safety
///
/// `ctx` must be a valid guest context, and `run_thread_arch` must be active.
unsafe fn switch_to_guest(ctx: *const PtRegs) -> ! {
    // Safety: forwarded to the caller; `PtRegs` and `Registers` share a layout.
    unsafe { vmu_enter_guest(ctx.cast()) }
}

/// `PtRegs` and `Registers` share a layout, field by field.
const _: () = {
    assert!(size_of::<PtRegs>() == size_of::<Registers>());
    assert!(core::mem::offset_of!(PtRegs, r15) == core::mem::offset_of!(Registers, r15));
    assert!(core::mem::offset_of!(PtRegs, r14) == core::mem::offset_of!(Registers, r14));
    assert!(core::mem::offset_of!(PtRegs, r13) == core::mem::offset_of!(Registers, r13));
    assert!(core::mem::offset_of!(PtRegs, r12) == core::mem::offset_of!(Registers, r12));
    assert!(core::mem::offset_of!(PtRegs, rbp) == core::mem::offset_of!(Registers, rbp));
    assert!(core::mem::offset_of!(PtRegs, rbx) == core::mem::offset_of!(Registers, rbx));
    assert!(core::mem::offset_of!(PtRegs, r11) == core::mem::offset_of!(Registers, r11));
    assert!(core::mem::offset_of!(PtRegs, r10) == core::mem::offset_of!(Registers, r10));
    assert!(core::mem::offset_of!(PtRegs, r9) == core::mem::offset_of!(Registers, r9));
    assert!(core::mem::offset_of!(PtRegs, r8) == core::mem::offset_of!(Registers, r8));
    assert!(core::mem::offset_of!(PtRegs, rax) == core::mem::offset_of!(Registers, rax));
    assert!(core::mem::offset_of!(PtRegs, rcx) == core::mem::offset_of!(Registers, rcx));
    assert!(core::mem::offset_of!(PtRegs, rdx) == core::mem::offset_of!(Registers, rdx));
    assert!(core::mem::offset_of!(PtRegs, rsi) == core::mem::offset_of!(Registers, rsi));
    assert!(core::mem::offset_of!(PtRegs, rdi) == core::mem::offset_of!(Registers, rdi));
    assert!(core::mem::offset_of!(PtRegs, orig_rax) == core::mem::offset_of!(Registers, orig_rax));
    assert!(core::mem::offset_of!(PtRegs, rip) == core::mem::offset_of!(Registers, rip));
    assert!(core::mem::offset_of!(PtRegs, cs) == core::mem::offset_of!(Registers, cs));
    assert!(core::mem::offset_of!(PtRegs, eflags) == core::mem::offset_of!(Registers, rflags));
    assert!(core::mem::offset_of!(PtRegs, rsp) == core::mem::offset_of!(Registers, rsp));
    assert!(core::mem::offset_of!(PtRegs, ss) == core::mem::offset_of!(Registers, ss));
};

unsafe extern "C" {
    /// Enters the guest at `ctx` (the guest context), unless an interrupt is
    /// pending, which it handles first. From its start to `vmu_restore_end`,
    /// `in_guest` is set but the guest is not running yet: an interrupt there
    /// leaves `ctx` (still the guest's) as it was.
    fn vmu_enter_guest(ctx: *const Registers) -> !;
    /// [`restore_context`]'s final jump, to [`SwitchState::resume_rip`].
    fn vmu_restore_jmp();
    fn vmu_restore_end();
}

/// Also holds `vmu_enter_guest`, which falls into the restore.
///
/// # Safety
///
/// `regs` must be a valid ring-3 context for this process.
#[unsafe(naked)]
unsafe extern "C" fn restore_context(regs: *const Registers) -> ! {
    core::arch::naked_asm!(
        "jmp 4f",
        ".globl vmu_enter_guest",
        "vmu_enter_guest:",
        "mov byte ptr [rip + {state} + {in_guest}], 1",
        "cmp byte ptr [rip + {state} + {pending}], 0",
        "je 4f",
        "mov byte ptr [rip + {state} + {in_guest}], 0",
        "mov byte ptr [rip + {state} + {pending}], 0",
        "jmp vmu_guest_interrupt_upcall",
        "4:",
        "mov rsp, rdi",
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
        "add rsp, 8", // orig_rax
        "pop qword ptr [rip + {state} + {resume_rip}]",
        "add rsp, 8", // cs
        "popfq",
        "pop rsp",
        ".globl vmu_restore_jmp",
        "vmu_restore_jmp:",
        "jmp qword ptr [rip + {state} + {resume_rip}]",
        ".globl vmu_restore_end",
        "vmu_restore_end:",
        state = sym STATE,
        resume_rip = const core::mem::offset_of!(SwitchState, resume_rip),
        in_guest = const core::mem::offset_of!(SwitchState, in_guest),
        pending = const core::mem::offset_of!(SwitchState, pending_interrupt),
    );
}

/// `rdi`: the [`UpcallFrame`] at the top of the upcall stack. An upcall for
/// the runner itself is fatal, except for an exception-table fixup.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn upcall_entry() -> ! {
    core::arch::naked_asm!(
        "and rsp, -16",
        "cld", // the interrupted code may have left DF set
        "call {dispatch}",
        "ud2",
        dispatch = sym upcall_dispatch,
    );
}

extern "C" fn upcall_dispatch(frame: *const UpcallFrame) -> ! {
    // Safety: the kernel wrote a frame there and does not touch it again.
    let bytes =
        unsafe { core::slice::from_raw_parts(frame.cast::<u8>(), size_of::<UpcallFrame>()) };
    let frame = UpcallFrame::try_read_from_bytes(bytes).expect("malformed upcall frame");
    let rip = usize::try_from(frame.regs.rip).unwrap_or(usize::MAX);
    let entering = (vmu_enter_guest as *const () as usize..vmu_restore_end as *const () as usize)
        .contains(&rip);
    if STATE.in_guest.load(Ordering::Relaxed) && entering && frame.kind == UpcallKind::Interrupt {
        // Interrupted on the way into the guest: the guest context is intact,
        // unlike the registers, which are partly the runner's.
        STATE.in_guest.store(false, Ordering::Relaxed);
        STATE.pending_interrupt.store(false, Ordering::Relaxed);
        // Safety: `run_thread_arch` is active (the guest was being entered).
        unsafe { vmu_guest_interrupt_upcall() }
    }
    if frame.kind == UpcallKind::Interrupt && rip == vmu_syscall_callback as *const () as usize {
        // On the callback's first instruction, which clears `in_guest`: the
        // guest made its (rewritten) syscall, and must not see the callback's
        // address as its own. As for the runner's code below: after the
        // syscall, at the next guest entry.
        STATE.in_guest.store(false, Ordering::Relaxed);
    }
    if STATE.in_guest.swap(false, Ordering::Relaxed) {
        let top = STATE.guest_context_top.load(Ordering::Relaxed);
        let ctx = (top - size_of::<PtRegs>()) as *mut Registers;
        // Safety: `run_thread_arch` is active (the guest was running), so
        // `ctx` is its guest context.
        unsafe { ctx.write(frame.regs) };
        match frame.kind {
            // Safety: as above; this abandons the upcall stack.
            UpcallKind::Syscall => unsafe { vmu_guest_syscall_upcall() },
            // Safety: as above.
            UpcallKind::Exception => unsafe {
                vmu_guest_exception_callback(frame.vector, frame.error_code, frame.fault_address)
            },
            // Safety: as above.
            UpcallKind::Interrupt => unsafe { vmu_guest_interrupt_upcall() },
        }
    }
    if frame.kind == UpcallKind::Interrupt {
        // The runner's own code ran, not the guest: leave the interrupt to
        // the next guest entry, and resume exactly where it was.
        STATE.pending_interrupt.store(true, Ordering::Relaxed);
        let mut regs = frame.regs;
        if rip == vmu_restore_jmp as *const () as usize {
            // Its target is only in the scratch, which resuming overwrites.
            regs.rip = STATE.resume_rip.load(Ordering::Relaxed) as u64;
        }
        // Safety: the runner's own state at the interrupt.
        unsafe { restore_context(&raw const regs) }
    }
    if frame.kind == UpcallKind::Exception
        && let Some(fixup) = litebox::mm::exception_table::search_exception_tables(rip)
    {
        let mut regs = frame.regs;
        regs.rip = fixup as u64;
        // Safety: the runner's own state at the fault, redirected to its
        // registered fixup.
        unsafe { restore_context(&raw const regs) }
    }
    panic!(
        "unhandled {:?} upcall from the runner (vector {}, error {:#x}) at {:#x}, address {:#x}",
        frame.kind, frame.vector, frame.error_code, frame.regs.rip, frame.fault_address
    );
}
