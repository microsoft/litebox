// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! x86-64 guest/host transitions and signal-context helpers.

use std::cell::RefCell;

use litebox::utils::{ReinterpretSignedExt, ReinterpretUnsignedExt as _, TruncateExt};
use litebox_common::arch::x86_64::xstate::{XsaveArea, XsaveLayout};

use super::{
    LinuxUserland, ThreadContext, exception_handler, init_handler, interrupt_handler,
    reenter_handler, syscall_handler,
};

const RFLAGS_TF: u32 = 1 << 8;
const RFLAGS_DF: u32 = 1 << 10;
const RFLAGS_AC: u32 = 1 << 18;
const HOST_UNSAFE_RFLAGS: u32 = RFLAGS_TF | RFLAGS_DF | RFLAGS_AC;
const HOST_SAFE_RFLAGS_MASK: u32 = !HOST_UNSAFE_RFLAGS;

// Clear TF, DF, and AC in the live flags before entering host code. Callers
// must preserve the original guest flags before invoking this macro.
macro_rules! sanitize_host_rflags {
    () => {
        "
    pushfq
    and DWORD PTR [rsp], {HOST_SAFE_RFLAGS_MASK}
    popfq
"
    };
}

/// Full TLS memory operand for a `.tbss` variable in normal host context
/// (after the fs/gs swap).
///
/// Example: `tls!("pending_host_signals")` expands to
/// `"fs:pending_host_signals@tpoff"`.
macro_rules! tls {
    ($var:literal) => {
        concat!("fs:", $var, "@tpoff")
    };
}
pub(super) use tls;

/// Full TLS memory operand for a `.tbss` variable accessed via the *saved*
/// segment register (before the fs/gs swap, e.g. from a signal handler).
///
/// Example: `saved_tls!("in_guest")` expands to `"gs:in_guest@tpoff"`.
macro_rules! saved_tls {
    ($var:literal) => {
        concat!("gs:", $var, "@tpoff")
    };
}
pub(super) use saved_tls;

thread_local! {
    pub(super) static GUEST_XSTATE: RefCell<Option<XsaveArea>> = const { RefCell::new(None) };
}

pub(super) enum GuestXstateInit {
    Initial,
    Reenter,
    Inherited(XsaveArea),
}

pub(super) fn activate_xstate(init: GuestXstateInit) {
    let layout = XsaveLayout::get();
    GUEST_XSTATE.with_borrow_mut(|guest| {
        match init {
            GuestXstateInit::Initial => {
                if let Some(guest) = guest.as_mut() {
                    guest.reset_to_initial();
                }
            }
            GuestXstateInit::Reenter => {}
            GuestXstateInit::Inherited(inherited) => *guest = Some(inherited),
        }
        let guest = guest.get_or_insert_with(|| XsaveArea::initial(layout));
        // SAFETY: The buffer remains owned by this thread's TLS until thread exit.
        // No guest is running while these assembly TLS slots are initialized.
        unsafe {
            core::arch::asm!(
                "mov fs:guest_xsave@tpoff, {guest}",
                "mov fs:xsave_mask@tpoff, {mask}",
                "mov BYTE PTR fs:use_xsaveopt@tpoff, {xsaveopt}",
                guest = in(reg) guest.as_mut_ptr(),
                mask = in(reg) layout.mask,
                xsaveopt = in(reg_byte) u8::from(layout.xsaveopt),
                options(nostack, preserves_flags),
            );
        }
    });
}

core::arch::global_asm!(
    "
    .section .tbss
    .align 8
scratch:
    .quad 0
host_sp:
    .quad 0
host_bp:
    .quad 0
.globl guest_xsave
guest_xsave:
    .quad 0
.globl xsave_mask
xsave_mask:
    .quad 0
.globl use_xsaveopt
use_xsaveopt:
    .byte 0
    .align 2
host_x87_control_word:
    .word 0
    .align 4
host_mxcsr:
    .long 0
.globl guest_context_top
guest_context_top:
    .quad 0
.globl guest_fsbase
guest_fsbase:
    .quad 0
.globl in_guest
in_guest:
    .byte 0
.globl interrupt
interrupt:
    .byte 0
    .align 4
.globl pending_host_signals
pending_host_signals:
    .long 0
    .align 8
.globl wait_waker_addr
wait_waker_addr:
    .quad 0
    "
);

pub(super) fn set_guest_fsbase(value: usize) {
    unsafe {
        core::arch::asm! {
            "mov fs:guest_fsbase@tpoff, {}",
            in(reg) value,
            options(nostack, preserves_flags)
        }
    }
}

pub(super) fn get_guest_fsbase() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm! {
            "mov {}, fs:guest_fsbase@tpoff",
            out(reg) value,
            options(nostack, preserves_flags)
        }
    }
    value
}

/// Saves the guest's extended state to its TLS save area. Clobbers rax, rdx, r10, and flags.
macro_rules! save_guest_xstate {
    () => {
        "
    mov     r10, fs:guest_xsave@tpoff
    mov     eax, DWORD PTR fs:xsave_mask@tpoff
    mov     edx, DWORD PTR fs:xsave_mask@tpoff+4
    cmp     BYTE PTR fs:use_xsaveopt@tpoff, 0
    je      8f
    xsaveopt64 [r10]
    jmp     9f
8:
    xsave64 [r10]
9:
"
    };
}

/// Clears the x87 exception flags and restores the host x87 FPU and SSE control words.
macro_rules! restore_host_fp_controls {
    () => {
        "
    fnclex
    fldcw   WORD PTR fs:host_x87_control_word@tpoff
    ldmxcsr DWORD PTR fs:host_mxcsr@tpoff
"
    };
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
#[unsafe(naked)]
pub(super) unsafe extern "C-unwind" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::PtRegs,
    reenter: u8,
) {
    core::arch::naked_asm!(
    "
    .cfi_startproc
    // Push all non-volatiles.
    push rbp
    mov rbp, rsp
    .cfi_def_cfa rbp, 16
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rdi // save thread context

    // Save host rsp and rbp and guest context top in TLS.
    mov fs:host_sp@tpoff, rsp
    mov fs:host_bp@tpoff, rbp
    lea r8, [rsi + {GUEST_CONTEXT_SIZE}]
    mov fs:guest_context_top@tpoff, r8

    // Save host fs base in gs base. This will stay set for the lifetime
    // of this call stack.
    rdfsbase r8
    wrgsbase r8

    // Preserve the host FP controls required by the SysV AMD64 ABI. FP data
    // registers are caller-saved, so they do not require a host XSAVE area.
    fnstcw WORD PTR fs:host_x87_control_word@tpoff
    stmxcsr DWORD PTR fs:host_mxcsr@tpoff

    // Call init_handler or reenter_handler based on reenter flag (in dl).
    test dl, dl
    jnz 1f
    call {init_handler}
    jmp .Ldone
1:
    call {reenter_handler}
    jmp .Ldone

    // This entry point is called from the guest when it issues a syscall
    // instruction.
    //
    // At entry, the register context is the guest context with the
    // return address in rcx. r11 is an available scratch register (it would
    // contain rflags if the syscall instruction had actually been issued).
    .globl syscall_callback
syscall_callback:
    // Clear in_guest flag. This must be the first instruction to match the
    // expectations of `interrupt_signal_handler`.
    mov      BYTE PTR gs:in_guest@tpoff, 0

    // Restore host fs base.
    rdfsbase r11
    mov      gs:guest_fsbase@tpoff, r11
    rdgsbase r11
    wrfsbase r11

    // Switch to the top of the guest context.
    mov     r11, rsp
    mov     rsp, fs:guest_context_top@tpoff

    // Save caller-saved registers
    push    0x2b       // pt_regs->ss = __USER_DS
    push    r11        // pt_regs->sp
    pushfq             // pt_regs->eflags
",
    sanitize_host_rflags!(),
"
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
    push    r12         // pt_regs->r12
    push    r13         // pt_regs->r13
    push    r14         // pt_regs->r14
    push    r15         // pt_regs->r15
",
    save_guest_xstate!(),
    restore_host_fp_controls!(),
"
    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    mov rdi, [rsp] // pass thread_ctx
    call {syscall_handler}
    // This thread is done. Return.
    jmp .Ldone

.globl exception_callback
exception_callback:
    // rt_sigreturn restored the guest FP state. Save it before entering host code.
    mov     r8, rdx
",
    save_guest_xstate!(),
    restore_host_fp_controls!(),
"
    mov     rdx, r8

    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    mov rdi, [rsp] // pass thread_ctx
    call {exception_handler}
    jmp .Ldone

.globl interrupt_callback
interrupt_callback:
    // rt_sigreturn restored the guest FP state. Save it before entering host code.
",
    save_guest_xstate!(),
"
.globl interrupt_callback_no_xsave
interrupt_callback_no_xsave:
",
    restore_host_fp_controls!(),
"
    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    mov rdi, [rsp] // pass thread_ctx
    call {interrupt_handler}

.Ldone:
    // Shim handlers may leave modified FP controls when terminating the guest.
",
    restore_host_fp_controls!(),
"
    lea  rsp, [rbp - 5*8]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    .cfi_def_cfa rsp, 8
    ret
    .cfi_endproc
",
    GUEST_CONTEXT_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
    init_handler = sym init_handler,
    reenter_handler = sym reenter_handler,
    syscall_handler = sym syscall_handler,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    HOST_SAFE_RFLAGS_MASK = const HOST_SAFE_RFLAGS_MASK,
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
#[unsafe(naked)]
pub(super) unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    core::arch::naked_asm!(
        ".globl switch_to_guest_start",
        "switch_to_guest_start:",
        // Set `in_guest` now, then check if there is a pending interrupt. If an
        // interrupt arrives while `in_guest` is set, the signal handler will
        // see that the IP is between `switch_to_guest_start` and
        // `switch_to_guest_end` and will set `interrupt` and jump to
        // `interrupt_callback_no_xsave`.
        //
        // If an interrupt is already pending, clear `in_guest` and jump to
        // `interrupt_callback_no_xsave` without entering the guest. The callback
        // runs host code, and a signal arriving there with `in_guest` still set
        // would be taken for a guest interrupt and overwrite the saved guest
        // context with host registers.
        "mov BYTE PTR fs:in_guest@tpoff, 1",
        "cmp BYTE PTR fs:interrupt@tpoff, 0",
        "je 2f",
        "mov BYTE PTR fs:in_guest@tpoff, 0",
        "jmp interrupt_callback_no_xsave",
        "2:",
        "mov r10, fs:guest_xsave@tpoff",
        "mov eax, DWORD PTR fs:xsave_mask@tpoff",
        "mov edx, DWORD PTR fs:xsave_mask@tpoff+4",
        "xrstor64 [r10]",
        // Restore guest context from ctx.
        "mov rsp, rdi",
        // Switch to the guest fsbase
        "mov rdx, fs:guest_fsbase@tpoff",
        "wrfsbase rdx",
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
        "add rsp, 8",           // skip orig_rax
        "pop gs:scratch@tpoff", // read rip into scratch
        "add rsp, 8",           // skip cs
        "popfq",
        "pop rsp",
        "jmp gs:scratch@tpoff", // jump to the guest
        ".globl switch_to_guest_end",
        "switch_to_guest_end:",
    );
}

// Defined in the assembly blocks above.
unsafe extern "C" {
    pub(super) fn syscall_callback() -> isize;
    pub(super) fn exception_callback();
    pub(super) fn interrupt_callback();
    pub(super) fn interrupt_callback_no_xsave();
    pub(super) fn switch_to_guest_start();
    pub(super) fn switch_to_guest_end();
}

/// Called from signal handlers to fix up thread state after potentially running
/// in the guest.
///
/// Restores the proper host `fsbase` so that TLS can be used. Clears `in_guest`
/// and optionally sets `interrupt`. If `in_guest` was previously set, returns
/// the guest context pointer (which does not necessarily have up-to-date guest
/// register state yet).
pub(super) fn signal_handler_exit_guest(
    _context: &libc::ucontext_t,
    set_interrupt: bool,
) -> Option<*mut litebox_common_linux::PtRegs> {
    unsafe {
        let gsbase: u64;
        core::arch::asm! {
            "rdgsbase {}", out(reg) gsbase
        };
        let is_in_guest = if gsbase == 0 {
            false
        } else {
            let in_guest: u8;
            core::arch::asm! {
                "mov {in_guest}, BYTE PTR gs:in_guest@tpoff",
                "mov BYTE PTR gs:in_guest@tpoff, 0",
                in_guest = out(reg_byte) in_guest,
                options(nostack, preserves_flags)
            }
            if set_interrupt {
                core::arch::asm! {
                    "mov BYTE PTR gs:interrupt@tpoff, 1",
                    options(nostack, preserves_flags)
                };
            }
            in_guest != 0
        };
        if !is_in_guest {
            return None;
        }

        let guest_context_top: *mut litebox_common_linux::PtRegs;
        core::arch::asm! {
            "wrfsbase {gsbase}",
            "mov {guest_context_top}, fs:guest_context_top@tpoff",
            gsbase = in(reg) gsbase,
            guest_context_top = out(reg) guest_context_top,
            options(nostack, preserves_flags)
        };
        Some(guest_context_top.sub(1))
    }
}

/// Copies register state from a Linux signal context to a LiteBox PtRegs
/// structure.
pub(super) fn copy_signal_context(
    regs: &mut litebox_common_linux::PtRegs,
    context: &libc::ucontext_t,
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
    } = regs;
    for (reg, sig_reg) in [
        (r15, libc::REG_R15),
        (r14, libc::REG_R14),
        (r13, libc::REG_R13),
        (r12, libc::REG_R12),
        (rbp, libc::REG_RBP),
        (rbx, libc::REG_RBX),
        (r11, libc::REG_R11),
        (r10, libc::REG_R10),
        (r9, libc::REG_R9),
        (r8, libc::REG_R8),
        (rax, libc::REG_RAX),
        (rcx, libc::REG_RCX),
        (rdx, libc::REG_RDX),
        (rsi, libc::REG_RSI),
        (rdi, libc::REG_RDI),
        (rip, libc::REG_RIP),
        (rsp, libc::REG_RSP),
        (eflags, libc::REG_EFL),
    ] {
        *reg = context.uc_mcontext.gregs[sig_reg.reinterpret_as_unsigned() as usize]
            .reinterpret_as_unsigned()
            .trunc();
    }
    *orig_rax = *rax;
}

/// Updates a Linux signal context to return to `f` with the given arguments.
pub(super) fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize,
    p1: isize,
    p2: isize,
    p3: isize,
) {
    let sigctx = &mut context.uc_mcontext;
    sigctx.gregs[libc::REG_RIP as usize] = (f as usize).reinterpret_as_signed() as i64;
    sigctx.gregs[libc::REG_RDI as usize] = p0 as i64;
    sigctx.gregs[libc::REG_RSI as usize] = p1 as i64;
    sigctx.gregs[libc::REG_RDX as usize] = p2 as i64;
    sigctx.gregs[libc::REG_RCX as usize] = p3 as i64;
    // `rt_sigreturn` restores RFLAGS before entering the callback, which must
    // satisfy the host ABI rather than inherit guest-controlled execution flags.
    sigctx.gregs[libc::REG_EFL as usize] &= !i64::from(HOST_UNSAFE_RFLAGS);
}

impl litebox::platform::ArchSpecificProvider for LinuxUserland {
    // We swap gs and fs before and after a syscall, so while handling a guest
    // syscall the guest's fs base is stored in the gs base register; the
    // per-thread `guest_fsbase` slot holds the value that will be programmed
    // into fs base on guest re-entry.
    fn set_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
        val: usize,
    ) -> Result<(), litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::FsBase => {
                if litebox_common_linux::arch::is_valid_user_fs_base(val) {
                    set_guest_fsbase(val);
                    Ok(())
                } else {
                    Err(litebox::platform::ArchSpecificError::RegisterUnpermittedValue)
                }
            }
            litebox::platform::ArchSpecificRegister::GsBase => {
                // GS base is used internally by this platform to hold the host
                // TLS base across the guest/host fs-gs swap, so it is not
                // directly programmable by the guest.
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
            litebox::platform::ArchSpecificRegister::FsBase => Ok(get_guest_fsbase()),
            litebox::platform::ArchSpecificRegister::GsBase => {
                // See note above: gs base is reserved for host TLS on this
                // platform and is not exposed to the guest.
                Err(litebox::platform::ArchSpecificError::RegisterReserved)
            }
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::Ordering;

    use crate::LinuxUserland;

    #[test]
    fn spawned_guest_inherits_xstate() {
        use litebox::platform::ThreadProvider as _;
        use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo, InitThread};
        use litebox_common::arch::x86_64::xstate::{XsaveArea, XsaveLayout, XsaveLegacyArea};
        use litebox_common_linux::PtRegs;
        use std::sync::mpsc::{Sender, channel};

        const TEST_CW: u16 = 0x0b7f;
        const TEST_MXCSR: u32 = 0x5f80;
        // 1.0 in 80-bit floating-point format.
        const X87_ONE: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f];

        #[unsafe(naked)]
        unsafe extern "C" fn guest_entry() {
            core::arch::naked_asm!(
                "test rdi, rdi",
                "jnz 3f",
                "sub rsp, 40",
                "mov WORD PTR [rsp + 32], {control_word}",
                "mov DWORD PTR [rsp + 36], {mxcsr}",
                "mov rax, 0x5a5a5a5a5a5a5a5a",
                "mov [rsp], rax",
                "mov [rsp + 8], rax",
                "mov [rsp + 16], rax",
                "mov [rsp + 24], rax",
                "fldcw [rsp + 32]",
                "ldmxcsr [rsp + 36]",
                "fld1",
                "movdqu xmm0, [rsp]",
                "add rsp, 40",
                "lea rcx, [rip + 4f]",
                "jmp {syscall_callback}",
                "3:",
                "fxsave64 [rsi]",
                "4:",
                "lea rcx, [rip + 5f]",
                "jmp {syscall_callback}",
                "5:",
                "ud2",
                control_word = const TEST_CW,
                mxcsr = const TEST_MXCSR,
                syscall_callback = sym crate::syscall_callback,
            );
        }

        struct ChildStorage {
            _stack: Box<[u128; 256]>,
            snapshot: XsaveArea,
        }

        struct Shim {
            platform: &'static LinuxUserland,
            sender: Sender<XsaveLegacyArea>,
            child: Option<ChildStorage>,
        }

        impl InitThread for Shim {
            type ExecutionContext = PtRegs;

            fn init(self: Box<Self>) -> Box<dyn EnterShim<ExecutionContext = PtRegs>> {
                self
            }
        }

        impl EnterShim for Shim {
            type ExecutionContext = PtRegs;

            fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                ContinueOperation::Resume
            }

            fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
                if let Some(child) = &self.child {
                    self.sender.send(*child.snapshot.legacy_area()).unwrap();
                } else {
                    // SAFETY: These caller-saved registers belong to the shim;
                    // the parent's guest state has already been captured.
                    unsafe {
                        core::arch::asm!(
                            "fninit",
                            "pxor xmm0, xmm0",
                            out("xmm0") _,
                            options(nostack),
                        );
                    }
                    let mut stack = Box::new([0_u128; 256]);
                    let mut snapshot = XsaveArea::initial(XsaveLayout::get());
                    let mut child_ctx = ctx.clone();
                    child_ctx.rip = guest_entry as *const () as usize;
                    child_ctx.rsp = stack.as_mut_ptr().wrapping_add(stack.len()).addr();
                    child_ctx.rdi = 1;
                    child_ctx.rsi = snapshot.as_mut_ptr().addr();
                    let child = Box::new(Shim {
                        platform: self.platform,
                        sender: self.sender.clone(),
                        child: Some(ChildStorage {
                            _stack: stack,
                            snapshot,
                        }),
                    });
                    // SAFETY: The child owns its stack and aligned snapshot
                    // buffer, and its shim terminates after capturing state.
                    unsafe { self.platform.spawn_thread(&child_ctx, child).unwrap() };
                }
                ContinueOperation::Terminate
            }

            fn exception(&self, _ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
                panic!("unexpected guest exception: {info:?}");
            }

            fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                ContinueOperation::Resume
            }
        }

        let platform = LinuxUserland::new(None);
        let (sender, receiver) = channel();
        let shim = Shim {
            platform,
            sender,
            child: None,
        };
        let mut stack = [0_u128; 256];
        let mut ctx = PtRegs {
            rip: guest_entry as *const () as usize,
            rsp: stack.as_mut_ptr().wrapping_add(stack.len()).addr(),
            eflags: 0x202,
            ..Default::default()
        };
        // SAFETY: The parent uses a valid stack and terminates after spawning
        // the child, which retains ownership of all its guest buffers.
        unsafe { crate::run_thread_ref(&shim, &mut ctx) };
        let snapshot = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(snapshot.control_word, TEST_CW);
        assert_eq!(snapshot.mxcsr, TEST_MXCSR);
        assert_eq!(&snapshot.float_registers[0][..X87_ONE.len()], &X87_ONE);
        assert_eq!(snapshot.xmm_registers[0], [0x5a; 16]);
    }

    #[test]
    fn xsave_preserves_state_across_guest_transitions() {
        use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
        use litebox_common::arch::x86_64::xstate::{XsaveArea, XsaveLegacyArea};
        use litebox_common_linux::PtRegs;
        use std::cell::Cell;

        const TEST_CW: u16 = 0x077e;
        const TEST_MXCSR: u32 = 0x3f80;
        const HOST_CW: u16 = 0x0b7f;
        const HOST_MXCSR: u32 = 0x5f80;
        const SNAPSHOT_COUNT: usize = 5;
        const X87_STATUS_INVALID_OPERATION: u16 = 1 << 0;
        const X87_STATUS_EXCEPTION_SUMMARY: u16 = 1 << 7;
        const X87_INVALID_OPERATION_STATUS: u16 =
            X87_STATUS_INVALID_OPERATION | X87_STATUS_EXCEPTION_SUMMARY;

        #[repr(C, align(64))]
        #[derive(Clone, Copy)]
        struct Snapshot {
            legacy: XsaveLegacyArea,
            ymm_hi: [u8; 64],
        }

        impl Default for Snapshot {
            fn default() -> Self {
                Self {
                    legacy: XsaveLegacyArea::default(),
                    ymm_hi: [0; 64],
                }
            }
        }

        #[repr(C, align(64))]
        struct CaptureSet {
            snapshots: [Snapshot; SNAPSHOT_COUNT],
            host_mxcsr: u32,
            host_control: u16,
        }

        const SNAPSHOT_SIZE: usize = core::mem::size_of::<Snapshot>();

        #[unsafe(naked)]
        unsafe extern "C" fn guest_entry() {
            core::arch::naked_asm!(
                // Preserve the snapshot buffer, AVX flag, interrupt signal,
                // process ID, and thread ID in callee-saved registers.
                "mov r12, rsi",
                "mov r13, rdi",
                "mov ebx, edx",
                "mov r14, r8",
                "mov r15, r9",
                // Record the host controls observed before installing guest
                // state. The assertions below verify their exact restoration.
                "stmxcsr [r12 + {host_mxcsr_offset}]",
                "fnstcw [r12 + {host_control_offset}]",
                // Install distinctive x87, SSE, and optional AVX guest state.
                "sub rsp, 40",
                "mov WORD PTR [rsp + 32], {control_word}",
                "mov DWORD PTR [rsp + 36], {mxcsr}",
                "mov rax, 0x5a5a5a5a5a5a5a5a",
                "mov [rsp], rax",
                "mov [rsp + 8], rax",
                "mov [rsp + 16], rax",
                "mov [rsp + 24], rax",
                "fldcw [rsp + 32]",
                "ldmxcsr [rsp + 36]",
                "movdqu xmm0, [rsp]",
                "test r13, r13",  // Whether support for AVX is enabled
                "jz 2f",
                "vmovdqu ymm0, [rsp]",
                "2:",
                "fldz",
                "fldz",
                "fdivp st(1), st(0)",
                "add rsp, 40",
                // Syscall transition: the shim clobbers host FP state before
                // resuming at label 3. Capture snapshot 0 after restoration.
                "lea rcx, [rip + 3f]",
                "jmp {syscall_callback}",
                "3:",
                "fxsave64 [r12]",
                "test r13, r13",
                "jz 4f",
                "vmovdqu [r12 + 512], ymm0",
                "4:",
                // Install a state distinct from the preceding syscall so this
                // snapshot proves the exception callback saved it.
                "sub rsp, 32",
                "mov rax, 0x6b6b6b6b6b6b6b6b",
                "mov [rsp], rax",
                "mov [rsp + 8], rax",
                "mov [rsp + 16], rax",
                "mov [rsp + 24], rax",
                "movdqu xmm0, [rsp]",
                "test r13, r13",
                "jz 13f",
                "vmovdqu ymm0, [rsp]",
                "13:",
                "add rsp, 32",
                // Exception transition: UD2 enters the exception callback,
                // which advances RIP. Capture snapshot 1 after resumption.
                "ud2",
                "fxsave64 [r12 + {snapshot_size}]",
                "test r13, r13",
                "jz 5f",
                "vmovdqu [r12 + {snapshot_size} + 512], ymm0",
                "5:",
                // Install another distinct state so this snapshot proves the
                // interrupt callback saved it rather than restoring snapshot 1.
                "sub rsp, 32",
                "mov rax, 0x7c7c7c7c7c7c7c7c",
                "mov [rsp], rax",
                "mov [rsp + 8], rax",
                "mov [rsp + 16], rax",
                "mov [rsp + 24], rax",
                "movdqu xmm0, [rsp]",
                "test r13, r13",
                "jz 14f",
                "vmovdqu ymm0, [rsp]",
                "14:",
                "add rsp, 32",
                // Interrupt transition: signal this guest thread directly and
                // capture snapshot 2 after the interrupt callback resumes it.
                "mov rdi, r14",
                "mov rsi, r15",
                "mov edx, ebx",
                "mov eax, {tgkill}",
                "syscall",
                "fxsave64 [r12 + 2*{snapshot_size}]",
                "test r13, r13",  // Whether support for AVX is enabled
                "jz 6f",
                "vmovdqu [r12 + 2*{snapshot_size} + 512], ymm0",
                "6:",
                // The shim terminates on this second syscall. reenter_thread
                // resumes at label 7; snapshot 3 verifies persisted XSTATE.
                "lea rcx, [rip + 7f]",
                "jmp {syscall_callback}",
                "7:",
                "fxsave64 [r12 + 3*{snapshot_size}]",
                "test r13, r13",
                "jz 8f",
                "vmovdqu [r12 + 3*{snapshot_size} + 512], ymm0",
                "8:",
                // Replace the guest state, cross another syscall, and capture
                // snapshot 4 to prove the newly saved state supersedes it.
                "fninit",
                "pxor xmm0, xmm0",
                "test r13, r13",
                "jz 9f",
                "vzeroall",
                "9:",
                "lea rcx, [rip + 10f]",
                "jmp {syscall_callback}",
                "10:",
                "fxsave64 [r12 + 4*{snapshot_size}]",
                "test r13, r13",
                "jz 11f",
                "vmovdqu [r12 + 4*{snapshot_size} + 512], ymm0",
                "11:",
                // The fourth syscall terminates the test. UD2 is unreachable
                // and prevents accidental fallthrough if it unexpectedly resumes.
                "lea rcx, [rip + 12f]",
                "jmp {syscall_callback}",
                "12:",
                "ud2",
                snapshot_size = const SNAPSHOT_SIZE,
                host_mxcsr_offset = const core::mem::offset_of!(CaptureSet, host_mxcsr),
                host_control_offset = const core::mem::offset_of!(CaptureSet, host_control),
                control_word = const TEST_CW,
                mxcsr = const TEST_MXCSR,
                tgkill = const libc::SYS_tgkill,
                syscall_callback = sym crate::syscall_callback,
            );
        }

        struct StateShim {
            calls: Cell<usize>,
            exceptions: Cell<usize>,
            interrupts: Cell<usize>,
            avx: bool,
        }

        impl StateShim {
            fn clobber_host_state(&self) {
                let mut control = 0_u16;
                let status: u16;
                let mut mxcsr = 0_u32;
                // SAFETY: These instructions access only the current thread's FP
                // registers and valid local outputs; AVX is checked before use.
                unsafe {
                    core::arch::asm!(
                        "fnstcw [{control}]",
                        "fnstsw ax",
                        "stmxcsr [{mxcsr}]",
                        control = in(reg) &raw mut control,
                        mxcsr = in(reg) &raw mut mxcsr,
                        out("ax") status,
                        options(nostack, preserves_flags),
                    );
                }
                assert_eq!(control, HOST_CW);
                assert_eq!(status & X87_INVALID_OPERATION_STATUS, 0);
                assert_eq!(mxcsr & !0x3f, HOST_MXCSR);
                // SAFETY: The clobbers are declared and AVX support was detected.
                unsafe {
                    core::arch::asm!(
                        "fninit",
                        "pxor xmm0, xmm0",
                        out("xmm0") _,
                        options(nostack),
                    );
                    if self.avx {
                        core::arch::asm!(
                            "vpxor ymm0, ymm0, ymm0",
                            out("ymm0") _,
                            options(nostack),
                        );
                    }
                }
            }
        }

        impl EnterShim for StateShim {
            type ExecutionContext = PtRegs;

            fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                self.clobber_host_state();
                ContinueOperation::Resume
            }

            fn reenter(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                self.clobber_host_state();
                ContinueOperation::Resume
            }

            fn syscall(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                self.clobber_host_state();
                let call = self.calls.get() + 1;
                self.calls.set(call);
                if call == 2 || call == 4 {
                    ContinueOperation::Terminate
                } else {
                    ContinueOperation::Resume
                }
            }

            fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
                self.clobber_host_state();
                assert_eq!(info.exception, litebox::shim::Exception(6));
                self.exceptions.set(self.exceptions.get() + 1);
                ctx.rip += 2;
                ContinueOperation::Resume
            }

            fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                self.clobber_host_state();
                self.interrupts.set(self.interrupts.get() + 1);
                ContinueOperation::Resume
            }
        }

        let mut original_control = 0_u16;
        let mut original_mxcsr = 0_u32;
        let host_control = HOST_CW;
        let host_mxcsr = HOST_MXCSR;
        // SAFETY: Save the test thread's controls and install masked,
        // non-default rounding modes to verify exact host restoration.
        unsafe {
            core::arch::asm!(
                "fnstcw [{original_control}]",
                "stmxcsr [{original_mxcsr}]",
                "fldcw [{host_control}]",
                "ldmxcsr [{host_mxcsr}]",
                original_control = in(reg) &raw mut original_control,
                original_mxcsr = in(reg) &raw mut original_mxcsr,
                host_control = in(reg) &raw const host_control,
                host_mxcsr = in(reg) &raw const host_mxcsr,
                options(nostack, preserves_flags),
            );
        }
        let _restore_controls = litebox::utils::defer(|| unsafe {
            core::arch::asm!(
                "fnclex",
                "fldcw [{original_control}]",
                "ldmxcsr [{original_mxcsr}]",
                original_control = in(reg) &raw const original_control,
                original_mxcsr = in(reg) &raw const original_mxcsr,
                options(nostack, preserves_flags),
            );
        });

        let _platform = LinuxUserland::new(None);
        let shim = StateShim {
            calls: Cell::new(0),
            exceptions: Cell::new(0),
            interrupts: Cell::new(0),
            avx: std::is_x86_feature_detected!("avx"),
        };
        let mut stack = [0_u128; 256];
        let mut captures = CaptureSet {
            snapshots: [Snapshot::default(); SNAPSHOT_COUNT],
            host_mxcsr: 0,
            host_control: 0,
        };
        let mut ctx = PtRegs {
            rip: guest_entry as *const () as usize,
            rsp: stack.as_mut_ptr().wrapping_add(stack.len()).addr(),
            rsi: captures.snapshots.as_mut_ptr().addr(),
            rdi: usize::from(shim.avx),
            rdx: usize::try_from(crate::INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed)).unwrap(),
            // SAFETY: These calls only query the current process and thread IDs.
            r8: usize::try_from(unsafe { libc::getpid() }).unwrap(),
            r9: usize::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap(),
            eflags: 0x202,
            ..Default::default()
        };
        // SAFETY: The assembly guest uses a valid stack and output buffer and the
        // shim terminates at known points, preserving a valid reentry context.
        unsafe {
            crate::run_thread_ref(&shim, &mut ctx);
            assert_eq!(shim.calls.get(), 2);
            crate::reenter_thread(&shim, &mut ctx);
        }
        assert_eq!(shim.calls.get(), 4);
        assert_eq!(shim.exceptions.get(), 1);
        assert_eq!(shim.interrupts.get(), 1);
        for (index, snapshot) in captures.snapshots.iter().enumerate() {
            let (expected_status, expected_vector) = match index {
                0 => (X87_INVALID_OPERATION_STATUS, 0x5a),
                1 => (X87_INVALID_OPERATION_STATUS, 0x6b),
                2 | 3 => (X87_INVALID_OPERATION_STATUS, 0x7c),
                4 => (0, 0),
                _ => unreachable!(),
            };
            let expected_control = if index == 4 { 0x037f } else { TEST_CW };
            assert_eq!(snapshot.legacy.control_word, expected_control);
            assert_eq!(
                snapshot.legacy.status_word & X87_INVALID_OPERATION_STATUS,
                expected_status
            );
            assert_eq!(snapshot.legacy.mxcsr, TEST_MXCSR);
            assert_eq!(snapshot.legacy.xmm_registers[0], [expected_vector; 16]);
            if shim.avx {
                assert_eq!(&snapshot.ymm_hi[..32], &[expected_vector; 32]);
            }
        }
        assert_eq!(captures.host_mxcsr, XsaveArea::GUEST_INITIAL_MXCSR);
        assert_eq!(
            captures.host_control,
            XsaveArea::GUEST_INITIAL_X87_CONTROL_WORD
        );
    }

    /// An interrupt pending at guest entry diverts to the interrupt handler
    /// without entering the guest, so a further interrupt taken while that
    /// handler runs host code must not be treated as a guest interrupt, which
    /// would re-enter the handler.
    #[test]
    fn interrupt_in_diverted_interrupt_handler_is_not_a_guest_interrupt() {
        use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
        use litebox_common_linux::PtRegs;

        // The signal is delivered to the calling thread before `pthread_kill` returns.
        fn interrupt_current_thread() {
            let signal = crate::INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed);
            // SAFETY: `pthread_self` is a live thread with the interrupt handler installed.
            assert_eq!(
                unsafe { libc::pthread_kill(libc::pthread_self(), signal) },
                0
            );
        }

        #[derive(Default)]
        struct Shim {
            interrupts: core::cell::Cell<u32>,
        }

        impl EnterShim for Shim {
            type ExecutionContext = PtRegs;

            fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                interrupt_current_thread();
                ContinueOperation::Resume
            }

            fn syscall(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }

            fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
                unreachable!()
            }

            fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                self.interrupts.set(self.interrupts.get() + 1);
                if self.interrupts.get() == 1 {
                    interrupt_current_thread();
                }
                ContinueOperation::Terminate
            }
        }

        let _platform = LinuxUserland::new(None);
        let shim = Shim::default();
        // SAFETY: the shim terminates the thread before it enters the guest.
        unsafe { crate::run_thread_ref(&shim, &mut PtRegs::default()) };
        assert_eq!(shim.interrupts.get(), 1);
    }
}
