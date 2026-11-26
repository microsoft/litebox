// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RV64 guest/host transitions and signal recovery.
//!
//! # Register contract
//!
//! Guest code is rewritten as described in [`litebox_trampoline::riscv64`]:
//! `tp` belongs to the guest, and while the guest runs physical `gp` points to
//! this thread's [`TlsBlock`], whose prefix is the gates' [`GateTls`]. Host
//! code needs `tp` for TLS and `gp` for linker-relaxed global accesses, so
//! every transition swaps both. At every instruction, either `gp` is the
//! host `gp` (`__global_pointer$`) and `tp` already holds the host `tp`, or
//! `gp` points to the block, from which the host `tp` is derived (`gp` less
//! the block's thread-pointer offset). Entering the guest sets `gp` to the
//! block before installing the guest `tp`, leaving it installs the host `tp`
//! before restoring the host `gp`, and the `rt_sigreturn` path installs both
//! guest registers atomically. Signal entry relies on this; see
//! [`exception_entry`].
//!
//! The block is addressed through local-exec TLS relocations, which are valid
//! only in the main executable. Every `%tprel_*` sequence and every
//! `__global_pointer$` reference is assembled with `.option norelax`: GNU ld
//! would otherwise relax them into `gp`- or `tp`-relative forms that are wrong
//! whenever the other register belongs to the guest.

use super::*;
use litebox::arch::riscv64::fp::FpState;
use litebox_common_linux::PtRegs;
use litebox_trampoline::riscv64::GateTls;
pub(super) use litebox_trampoline::riscv64::recovery::GateInterruption;
use litebox_trampoline::riscv64::recovery::{self, GateSignalResult};

/// Overwrites the destination with this thread's [`TlsBlock`] address,
/// derived from the host `tp`.
macro_rules! load_tls_block_base {
    ($reg:literal) => {
        concat!(
            ".option push\n.option norelax\n",
            "lui ",
            $reg,
            ", %tprel_hi(litebox_tls_block)\n",
            "add ",
            $reg,
            ", ",
            $reg,
            ", tp, %tprel_add(litebox_tls_block)\n",
            "addi ",
            $reg,
            ", ",
            $reg,
            ", %tprel_lo(litebox_tls_block)\n",
            ".option pop\n",
        )
    };
}

/// Overwrites the destination with the [`TlsBlock`]'s offset from the host
/// `tp`, so that the host `tp` is the block address less this.
macro_rules! load_tls_block_tprel {
    ($reg:literal) => {
        concat!(
            ".option push\n.option norelax\n",
            "lui ",
            $reg,
            ", %tprel_hi(litebox_tls_block)\n",
            "addi ",
            $reg,
            ", ",
            $reg,
            ", %tprel_lo(litebox_tls_block)\n",
            ".option pop\n",
        )
    };
}

/// Overwrites the destination with the host `gp`.
macro_rules! load_host_gp {
    ($reg:literal) => {
        concat!(
            ".option push\n.option norelax\n",
            "lla ",
            $reg,
            ", __global_pointer$\n",
            ".option pop\n",
        )
    };
}

/// Layout of the RV64 TLS control block.
///
/// A layout witness only: the storage is the `.tbss` block reserved below, and
/// this type is never instantiated. Every offset the transition assembly uses
/// is derived from it with [`core::mem::offset_of`], so the two cannot drift.
#[repr(C)]
struct TlsBlock {
    /// Gates address this at physical `gp`, so it must come first.
    gate: GateTls,
    host_sp: usize,
    /// The `*mut PtRegs` that `run_thread_arch` was given.
    guest_context: usize,
    /// The continuation of the last `ecall` gate to enter the runtime, while
    /// [`switch_to_guest`] may still resume through it; zero otherwise.
    gate_continuation: usize,
    /// The guest pc after that gate's syscall.
    gate_next_pc: usize,
    in_guest: u8,
    interrupt: u8,
    is_guest_thread: u8,
    pending_host_signals: u32,
    wait_waker_addr: usize,
    /// The host `fcsr`, saved when entering the guest.
    host_fcsr: u32,
    /// The guest's floating-point state whenever the guest is not running.
    guest_fp: FpState,
    resume_frame: ResumeFrame,
}

/// Byte offsets of [`TlsBlock`]'s fields, for the transition assembly.
mod tls_offset {
    use super::{GateTls, TlsBlock};
    use core::mem::offset_of;

    const GATE: usize = offset_of!(TlsBlock, gate);
    pub(super) const GUEST_GP: usize = GATE + offset_of!(GateTls, guest_gp);
    pub(super) const SPILL: usize = GATE + offset_of!(GateTls, spill);
    pub(super) const SYSCALL_ENTRY: usize = GATE + offset_of!(GateTls, syscall_entry);
    pub(super) const HOST_SP: usize = offset_of!(TlsBlock, host_sp);
    pub(super) const GUEST_CONTEXT: usize = offset_of!(TlsBlock, guest_context);
    pub(super) const GATE_CONTINUATION: usize = offset_of!(TlsBlock, gate_continuation);
    pub(super) const GATE_NEXT_PC: usize = offset_of!(TlsBlock, gate_next_pc);
    pub(super) const IN_GUEST: usize = offset_of!(TlsBlock, in_guest);
    pub(super) const INTERRUPT: usize = offset_of!(TlsBlock, interrupt);
    pub(super) const IS_GUEST_THREAD: usize = offset_of!(TlsBlock, is_guest_thread);
    pub(super) const PENDING_HOST_SIGNALS: usize = offset_of!(TlsBlock, pending_host_signals);
    pub(super) const WAIT_WAKER_ADDR: usize = offset_of!(TlsBlock, wait_waker_addr);
    pub(super) const HOST_FCSR: usize = offset_of!(TlsBlock, host_fcsr);
    pub(super) const GUEST_FP: usize = offset_of!(TlsBlock, guest_fp);
    pub(super) const RESUME_FRAME: usize = offset_of!(TlsBlock, resume_frame);
}

// Gates address `GateTls` at `gp + 0`, and the assembly uses 12-bit offsets.
const _: () = assert!(
    tls_offset::GUEST_GP == 0
        && tls_offset::GUEST_FP + FpState::FCSR_OFFSET < 2048
        && tls_offset::HOST_FCSR < 2048
);

// The assembly addresses `PtRegs` fields at 8 times their Linux `sc_regs`
// index, with `orig_a0` after `t6`.
const _: () = {
    use core::mem::offset_of;
    assert!(
        offset_of!(PtRegs, pc) == 0
            && offset_of!(PtRegs, gp) == 3 * 8
            && offset_of!(PtRegs, tp) == 4 * 8
            && offset_of!(PtRegs, t0) == 5 * 8
            && offset_of!(PtRegs, a0) == 10 * 8
            && offset_of!(PtRegs, t6) == 31 * 8
            && offset_of!(PtRegs, orig_a0) == 32 * 8
            && size_of::<PtRegs>() == 33 * 8
    );
};

// Storage layout and alignment must exactly match `TlsBlock`.
core::arch::global_asm!(
    ".section .tbss, \"awT\", @nobits",
    ".balign {align}",
    ".globl litebox_tls_block",
    "litebox_tls_block:",
    ".zero {size}",
    ".previous",
    align = const core::mem::align_of::<TlsBlock>(),
    size = const core::mem::size_of::<TlsBlock>(),
);

/// Returns this thread's [`TlsBlock`] address. Only valid with the host `tp`.
#[inline]
fn tls_block() -> usize {
    let block: usize;
    // SAFETY: materializes an address from `tp` and link-time constants only.
    unsafe {
        core::arch::asm!(
            load_tls_block_base!("{block}"),
            block = out(reg) block,
            options(pure, nomem, nostack, preserves_flags)
        );
    }
    block
}

/// Returns the host `gp`, `__global_pointer$`.
#[inline]
fn host_gp() -> usize {
    let gp: usize;
    // SAFETY: materializes a link-time address only.
    unsafe {
        core::arch::asm!(
            load_host_gp!("{gp}"),
            gp = out(reg) gp,
            options(pure, nomem, nostack, preserves_flags)
        );
    }
    gp
}

/// A pointer to the [`TlsBlock`] field at `offset`; see [`tls_offset`].
#[inline]
fn slot<T>(offset: usize) -> *mut T {
    (tls_block() + offset) as *mut T
}

/// Verifies the block's alignment, which the Rust references into it, the
/// atomics the assembly applies to it (RISC-V faults on misaligned AMOs), and
/// the resume frame, which becomes `sp` for `rt_sigreturn` and so needs the
/// psABI's 16-byte stack alignment, all rely on.
///
/// # Panics
///
/// Panics if the TLS block is misaligned.
pub(super) fn assert_tls_block_placement() {
    let block = tls_block();
    let align = core::mem::align_of::<TlsBlock>();
    assert!(
        block.is_multiple_of(align),
        "the TLS block at {block:#x} is not {align}-byte aligned",
    );
}

/// Returns this thread's in-guest flag, which the transition assembly also
/// writes.
fn in_guest_flag() -> &'static core::sync::atomic::AtomicU8 {
    // SAFETY: an aligned byte slot of this thread's own TLS block, which lives
    // as long as the thread, and is otherwise accessed only by this thread's
    // assembly.
    unsafe { core::sync::atomic::AtomicU8::from_ptr(slot(tls_offset::IN_GUEST)) }
}

/// Returns this thread's pending-interrupt flag.
fn interrupt_flag() -> &'static core::sync::atomic::AtomicU8 {
    // SAFETY: as for `in_guest_flag`.
    unsafe { core::sync::atomic::AtomicU8::from_ptr(slot(tls_offset::INTERRUPT)) }
}

/// Returns this thread's guest-thread marker.
fn guest_thread_flag() -> &'static core::sync::atomic::AtomicU8 {
    // SAFETY: as for `in_guest_flag`.
    unsafe { core::sync::atomic::AtomicU8::from_ptr(slot(tls_offset::IS_GUEST_THREAD)) }
}

fn pending_host_signals() -> &'static AtomicU32 {
    // SAFETY: a naturally aligned `u32` of this thread's own TLS block, only
    // ever accessed atomically.
    unsafe { AtomicU32::from_ptr(slot(tls_offset::PENDING_HOST_SIGNALS)) }
}

fn wait_waker_addr() -> &'static core::sync::atomic::AtomicUsize {
    // SAFETY: as for `pending_host_signals`.
    unsafe { core::sync::atomic::AtomicUsize::from_ptr(slot(tls_offset::WAIT_WAKER_ADDR)) }
}

/// Updates the marker from host execution context.
pub(super) fn set_guest_thread_marker(value: bool) {
    guest_thread_flag().store(u8::from(value), Ordering::SeqCst);
}

/// Replaces the marker from host execution context.
pub(super) fn replace_guest_thread_marker(value: bool) -> bool {
    guest_thread_flag().swap(u8::from(value), Ordering::SeqCst) != 0
}

/// Reads the marker from a signal context or host execution context. Signal
/// entry has already installed the host `tp`.
pub(super) fn is_guest_thread_from_signal_context() -> bool {
    guest_thread_flag().load(Ordering::SeqCst) != 0
}

pub(super) fn take_pending_host_signals_bits() -> u32 {
    // `amoswap.w` is atomic against this thread's signal handlers.
    pending_host_signals().swap(0, Ordering::SeqCst)
}

pub(super) fn swap_wait_waker_addr(new_addr: usize) -> usize {
    wait_waker_addr().swap(new_addr, Ordering::SeqCst)
}

pub(super) fn clear_interrupt() {
    interrupt_flag().store(0, Ordering::SeqCst);
}

/// Records `mask` in the pending host signals and returns the waker address
/// published by [`swap_wait_waker_addr`].
///
/// # Safety
///
/// Must run with the host `tp`, which signal entry installs.
pub(super) unsafe fn record_pending_signal(mask: u32) -> usize {
    pending_host_signals().fetch_or(mask, Ordering::SeqCst);
    wait_waker_addr().load(Ordering::SeqCst)
}

/// Runs the shim's `init` or `reenter` on `thread_ctx`, and later every other
/// shim entry for the guest thread, on this host stack frame.
///
/// The frame saves every callee-saved register. The callbacks below are entered
/// with guest state, reload the host `sp` from [`TlsBlock::host_sp`] and
/// re-establish `s0` before calling Rust: the FDE's CFA is `s0`, so an unwind
/// out of a handler never reads guest memory.
#[unsafe(naked)]
pub(super) unsafe extern "C-unwind" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::PtRegs,
    reenter: u8,
) {
    core::arch::naked_asm!(
    "
    .option push
    .option norelax
    .cfi_startproc
    addi sp, sp, -208
    .cfi_def_cfa_offset 208
    sd   ra,   200(sp)
    .cfi_offset ra, -8
    sd   s0,   192(sp)
    .cfi_offset s0, -16
    sd   s1,   184(sp)
    .cfi_offset s1, -24
    sd   s2,   176(sp)
    .cfi_offset s2, -32
    sd   s3,   168(sp)
    .cfi_offset s3, -40
    sd   s4,   160(sp)
    .cfi_offset s4, -48
    sd   s5,   152(sp)
    .cfi_offset s5, -56
    sd   s6,   144(sp)
    .cfi_offset s6, -64
    sd   s7,   136(sp)
    .cfi_offset s7, -72
    sd   s8,   128(sp)
    .cfi_offset s8, -80
    sd   s9,   120(sp)
    .cfi_offset s9, -88
    sd   s10,  112(sp)
    .cfi_offset s10, -96
    sd   s11,  104(sp)
    .cfi_offset s11, -104
    fsd  fs0,  96(sp)
    .cfi_offset fs0, -112
    fsd  fs1,  88(sp)
    .cfi_offset fs1, -120
    fsd  fs2,  80(sp)
    .cfi_offset fs2, -128
    fsd  fs3,  72(sp)
    .cfi_offset fs3, -136
    fsd  fs4,  64(sp)
    .cfi_offset fs4, -144
    fsd  fs5,  56(sp)
    .cfi_offset fs5, -152
    fsd  fs6,  48(sp)
    .cfi_offset fs6, -160
    fsd  fs7,  40(sp)
    .cfi_offset fs7, -168
    fsd  fs8,  32(sp)
    .cfi_offset fs8, -176
    fsd  fs9,  24(sp)
    .cfi_offset fs9, -184
    fsd  fs10, 16(sp)
    .cfi_offset fs10, -192
    fsd  fs11, 8(sp)
    .cfi_offset fs11, -200
    // Anchor the CFA on `s0` for the whole FDE, so that the callbacks'
    // wholesale `sp` reload keeps unwinding valid. Each callback is entered
    // with a guest `s0` and re-establishes `s0 = host_sp + 224` before calling
    // Rust.
    addi s0, sp, 208
    .cfi_def_cfa s0, 0
    // `thread_ctx` for the callbacks; `host_sp` points at it.
    addi sp, sp, -16
    sd   a0, 0(sp)
    ",
    load_tls_block_base!("t1"),
    "
    sd   sp, {HOST_SP}(t1)
    sd   a1, {GUEST_CONTEXT}(t1)
    sd   zero, {GATE_CONTINUATION}(t1)
    lla  t2, syscall_callback
    sd   t2, {SYSCALL_ENTRY}(t1)
    // The psABI extends a `u8` argument to the register width.
    bnez a2, 1f
    call {init_handler}
    j    .Ldone_riscv64
1:
    call {reenter_handler}
    j    .Ldone_riscv64

    // Entered by `jalr t0, 0(t0)` from an `ecall` gate (see
    // `litebox_trampoline::riscv64`): `gp` is the TLS block, `tp` and every
    // other register except `t0` hold guest values, `t0` holds the
    // continuation, and the guest `t0` is in the block's `spill`.
    .globl syscall_callback
syscall_callback:
    // `in_syscall_callback_prologue` covers the pcs before the label below,
    // where `in_guest` is still set; keep the label right after the store.
    sb   zero, {IN_GUEST}(gp)
    .globl syscall_callback_in_guest_cleared
syscall_callback_in_guest_cleared:
    sd   t0, {GATE_CONTINUATION}(gp)
    ld   t0, {GUEST_CONTEXT}(gp)
    sd   ra, 8(t0)
    sd   sp, 16(t0)
    sd   tp, 32(t0)
    sd   t1, 48(t0)
    sd   t2, 56(t0)
    sd   s0, 64(t0)
    sd   s1, 72(t0)
    sd   a1, 88(t0)
    sd   a2, 96(t0)
    sd   a3, 104(t0)
    sd   a4, 112(t0)
    sd   a5, 120(t0)
    sd   a6, 128(t0)
    sd   a7, 136(t0)
    sd   s2, 144(t0)
    sd   s3, 152(t0)
    sd   s4, 160(t0)
    sd   s5, 168(t0)
    sd   s6, 176(t0)
    sd   s7, 184(t0)
    sd   s8, 192(t0)
    sd   s9, 200(t0)
    sd   s10, 208(t0)
    sd   s11, 216(t0)
    sd   t3, 224(t0)
    sd   t4, 232(t0)
    sd   t5, 240(t0)
    sd   t6, 248(t0)
    sd   a0, 256(t0)
    li   a0, -{ENOSYS}
    sd   a0, 80(t0)
    ld   a0, {SPILL}(gp)
    sd   a0, 40(t0)
    ld   a0, {GUEST_GP}(gp)
    sd   a0, 24(t0)
    // Provisional pc; `syscall_entry_handler` replaces it.
    ld   a0, {GATE_CONTINUATION}(gp)
    sd   a0, 0(t0)
    addi t1, gp, {GUEST_FP}
    fsd  f0, 0(t1)
    fsd  f1, 8(t1)
    fsd  f2, 16(t1)
    fsd  f3, 24(t1)
    fsd  f4, 32(t1)
    fsd  f5, 40(t1)
    fsd  f6, 48(t1)
    fsd  f7, 56(t1)
    fsd  f8, 64(t1)
    fsd  f9, 72(t1)
    fsd  f10, 80(t1)
    fsd  f11, 88(t1)
    fsd  f12, 96(t1)
    fsd  f13, 104(t1)
    fsd  f14, 112(t1)
    fsd  f15, 120(t1)
    fsd  f16, 128(t1)
    fsd  f17, 136(t1)
    fsd  f18, 144(t1)
    fsd  f19, 152(t1)
    fsd  f20, 160(t1)
    fsd  f21, 168(t1)
    fsd  f22, 176(t1)
    fsd  f23, 184(t1)
    fsd  f24, 192(t1)
    fsd  f25, 200(t1)
    fsd  f26, 208(t1)
    fsd  f27, 216(t1)
    fsd  f28, 224(t1)
    fsd  f29, 232(t1)
    fsd  f30, 240(t1)
    fsd  f31, 248(t1)
    frcsr a0
    sw   a0, {FCSR}(t1)
    lw   a0, {HOST_FCSR}(gp)
    fscsr a0
    ld   sp, {HOST_SP}(gp)
    addi s0, sp, 224
    // Host `tp` first, while `gp` still locates the block. Each of `tp` and
    // `gp` is switched by a single instruction, so that a signal never sees
    // an intermediate value in either (see `signal_entry!`).
    ",
    load_tls_block_tprel!("t1"),
    "
    sub  tp, gp, t1
    ",
    load_host_gp!("t1"),
    "
    mv   gp, t1
    ld   a0, 0(sp)
    call {syscall_entry_handler}
    j    .Ldone_riscv64

    // Entered from `exception_signal_handler` via `set_signal_return` with the
    // host `gp` and `tp`, and the host signal number, trap number, error code
    // and fault address in a0-a3. The signal number moves to a4 so that a0 can
    // hold `thread_ctx`.
    .globl exception_callback
exception_callback:
    ",
    load_tls_block_base!("t1"),
    "
    ld   sp, {HOST_SP}(t1)
    addi s0, sp, 224
    mv   a4, a0
    ld   a0, 0(sp)
    call {exception_handler}
    j    .Ldone_riscv64

    // Entered with the host `gp` and `tp`, either from `interrupt_signal_handler`
    // via `set_signal_return` or from a guest resume that found `interrupt`
    // set.
    .globl interrupt_callback
interrupt_callback:
    ",
    load_tls_block_base!("t1"),
    "
    ld   sp, {HOST_SP}(t1)
    addi s0, sp, 224
    ld   a0, 0(sp)
    call {interrupt_handler}
    j    .Ldone_riscv64

.Ldone_riscv64:
    addi sp, s0, -208
    .cfi_def_cfa sp, 208
    ld   ra,   200(sp)
    ld   s0,   192(sp)
    ld   s1,   184(sp)
    ld   s2,   176(sp)
    ld   s3,   168(sp)
    ld   s4,   160(sp)
    ld   s5,   152(sp)
    ld   s6,   144(sp)
    ld   s7,   136(sp)
    ld   s8,   128(sp)
    ld   s9,   120(sp)
    ld   s10,  112(sp)
    ld   s11,  104(sp)
    fld  fs0,  96(sp)
    fld  fs1,  88(sp)
    fld  fs2,  80(sp)
    fld  fs3,  72(sp)
    fld  fs4,  64(sp)
    fld  fs5,  56(sp)
    fld  fs6,  48(sp)
    fld  fs7,  40(sp)
    fld  fs8,  32(sp)
    fld  fs9,  24(sp)
    fld  fs10, 16(sp)
    fld  fs11, 8(sp)
    addi sp, sp, 208
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .option pop
    ",
    HOST_SP = const tls_offset::HOST_SP,
    GUEST_CONTEXT = const tls_offset::GUEST_CONTEXT,
    GATE_CONTINUATION = const tls_offset::GATE_CONTINUATION,
    SYSCALL_ENTRY = const tls_offset::SYSCALL_ENTRY,
    IN_GUEST = const tls_offset::IN_GUEST,
    SPILL = const tls_offset::SPILL,
    GUEST_GP = const tls_offset::GUEST_GP,
    GUEST_FP = const tls_offset::GUEST_FP,
    FCSR = const FpState::FCSR_OFFSET,
    HOST_FCSR = const tls_offset::HOST_FCSR,
    ENOSYS = const libc::ENOSYS,
    init_handler = sym init_handler,
    reenter_handler = sym reenter_handler,
    syscall_entry_handler = sym syscall_entry_handler,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    );
}

/// Completes the guest context `syscall_callback` saved, then handles the
/// syscall.
///
/// The gate's continuation is a host-independent fact of the gate code, so
/// the guest pc after the `ecall` site is recovered from it rather than
/// trusted. That pc and the continuation are recorded so that
/// [`switch_to_guest`] can resume through the gate. If the continuation is not
/// an intact `ecall` gate (a guest that jumps to the runtime entry itself, or
/// unreadable code), the pc stays at the continuation and nothing is
/// recorded, so the resume goes through `rt_sigreturn` with the context's
/// `t0`, which `syscall_callback` took from `spill`.
unsafe extern "C-unwind" fn syscall_entry_handler(thread_ctx: &mut ThreadContext) {
    let next = recovery::syscall_return_pc(thread_ctx.ctx.pc, read_guest);
    // SAFETY: this thread's own TLS slots.
    unsafe {
        if let Some(next) = next {
            thread_ctx.ctx.pc = next;
            slot::<usize>(tls_offset::GATE_NEXT_PC).write(next);
        } else {
            slot::<usize>(tls_offset::GATE_CONTINUATION).write(0);
        }
        syscall_handler(thread_ctx);
    }
}

/// Reads guest memory at `address` into `output`, reporting a fault instead of
/// raising it.
fn read_guest(address: usize, output: &mut [u8]) -> bool {
    // SAFETY: `output` is writable for its exact length. The source is a
    // guest-controlled address, so it may be unmapped; it is read as raw bytes
    // through the exception table, never through a Rust reference. From a
    // signal handler, reaching the fixup requires the re-entrant exception
    // handler that `SA_NODEFER` provides; recursion is bounded at one level,
    // because the nested fault lands on this copy, which the table covers.
    unsafe {
        litebox::mm::exception_table::memcpy_fallible(
            output.as_mut_ptr(),
            address as *const u8,
            output.len(),
        )
        .is_ok()
    }
}

/// Switches stacks and calls `entry(arg)`; nothing may use the calling frames
/// afterwards.
#[unsafe(naked)]
pub(super) unsafe extern "C" fn switch_stack(
    top: usize,
    arg: *mut (),
    entry: unsafe extern "C" fn(*mut ()) -> !,
) -> ! {
    core::arch::naked_asm!(
        "mv sp, a0",
        "li s0, 0",
        "li ra, 0",
        "mv a0, a1",
        "jalr a2",
        "unimp",
    );
}

/// Switches to the provided guest context.
///
/// # Safety
/// The context must be a valid guest context. This can only be called if
/// `run_thread_arch` is on the stack; after the guest exits, it will return to
/// the interior of `run_thread_arch`. Do not call this where the stack needs
/// unwinding to run destructors.
///
/// The generic resume restores the complete context through `rt_sigreturn`.
/// As an optimization, a resume at the pc recorded by the most recent syscall
/// entry jumps back into that syscall's gate instead, which reloads `t0` and
/// jumps to the pc. The record is consumed here, so it is used at most once.
pub(super) unsafe extern "C" fn switch_to_guest(ctx: &PtRegs) -> ! {
    // SAFETY: this thread's own TLS slots.
    let continuation = unsafe {
        slot::<usize>(tls_offset::GUEST_GP).write(ctx.gp);
        slot::<usize>(tls_offset::SPILL).write(ctx.t0);
        let continuation = slot::<usize>(tls_offset::GATE_CONTINUATION).replace(0);
        (continuation != 0 && ctx.pc == slot::<usize>(tls_offset::GATE_NEXT_PC).read())
            .then_some(continuation)
    };
    if let Some(continuation) = continuation {
        // SAFETY: the caller's contract; `continuation` is the reload of the
        // `ecall` gate whose return jump goes to `ctx.pc`.
        unsafe { switch_to_guest_via_gate(ctx, continuation) }
    } else {
        // SAFETY: the caller's contract; the frame is complete.
        unsafe { switch_to_guest_via_sigreturn(prepare_resume_frame(ctx)) }
    }
}

/// Resumes the guest at `continuation` with every register but `t0` from
/// `ctx`, and the guest floating-point state from the TLS block.
///
/// # Safety
/// As [`switch_to_guest`], which has set `spill` to `ctx.t0`; `continuation`
/// must reload `t0` from `spill` and continue at `ctx.pc`.
///
/// One of the ranges [`in_switch_to_guest`] tests: once `in_guest` is set, a
/// signal here returns to the host with `ctx` and the block's floating-point
/// state still authoritative.
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest_via_gate(ctx: &PtRegs, continuation: usize) -> ! {
    core::arch::naked_asm!(
    "
    .option push
    .option norelax
    // No FDE: nothing unwinds through here.
    .globl switch_to_guest_via_gate_start
switch_to_guest_via_gate_start:
    ",
    load_tls_block_base!("t1"),
    "
    frcsr t2
    sw   t2, {HOST_FCSR}(t1)
    li   t2, 1
    sb   t2, {IN_GUEST}(t1)
    lbu  t2, {INTERRUPT}(t1)
    beqz t2, 2f
    sb   zero, {IN_GUEST}(t1)
    tail interrupt_callback
2:
    addi t2, t1, {GUEST_FP}
    fld  f0, 0(t2)
    fld  f1, 8(t2)
    fld  f2, 16(t2)
    fld  f3, 24(t2)
    fld  f4, 32(t2)
    fld  f5, 40(t2)
    fld  f6, 48(t2)
    fld  f7, 56(t2)
    fld  f8, 64(t2)
    fld  f9, 72(t2)
    fld  f10, 80(t2)
    fld  f11, 88(t2)
    fld  f12, 96(t2)
    fld  f13, 104(t2)
    fld  f14, 112(t2)
    fld  f15, 120(t2)
    fld  f16, 128(t2)
    fld  f17, 136(t2)
    fld  f18, 144(t2)
    fld  f19, 152(t2)
    fld  f20, 160(t2)
    fld  f21, 168(t2)
    fld  f22, 176(t2)
    fld  f23, 184(t2)
    fld  f24, 192(t2)
    fld  f25, 200(t2)
    fld  f26, 208(t2)
    fld  f27, 216(t2)
    fld  f28, 224(t2)
    fld  f29, 232(t2)
    fld  f30, 240(t2)
    fld  f31, 248(t2)
    lw   t3, {FCSR}(t2)
    fscsr t3
    mv   t0, a1
    // `gp` before the guest `tp`; see the module docs.
    mv   gp, t1
    ld   tp, 32(a0)
    ld   ra, 8(a0)
    ld   sp, 16(a0)
    ld   t1, 48(a0)
    ld   t2, 56(a0)
    ld   s0, 64(a0)
    ld   s1, 72(a0)
    ld   a1, 88(a0)
    ld   a2, 96(a0)
    ld   a3, 104(a0)
    ld   a4, 112(a0)
    ld   a5, 120(a0)
    ld   a6, 128(a0)
    ld   a7, 136(a0)
    ld   s2, 144(a0)
    ld   s3, 152(a0)
    ld   s4, 160(a0)
    ld   s5, 168(a0)
    ld   s6, 176(a0)
    ld   s7, 184(a0)
    ld   s8, 192(a0)
    ld   s9, 200(a0)
    ld   s10, 208(a0)
    ld   s11, 216(a0)
    ld   t3, 224(a0)
    ld   t4, 232(a0)
    ld   t5, 240(a0)
    ld   t6, 248(a0)
    ld   a0, 80(a0)
    jr   t0
    .globl switch_to_guest_via_gate_end
switch_to_guest_via_gate_end:
    .option pop
    ",
    HOST_FCSR = const tls_offset::HOST_FCSR,
    IN_GUEST = const tls_offset::IN_GUEST,
    INTERRUPT = const tls_offset::INTERRUPT,
    GUEST_FP = const tls_offset::GUEST_FP,
    FCSR = const FpState::FCSR_OFFSET,
    );
}

/// The kernel's `struct rt_sigframe`, synthesized for the generic guest
/// resume. One instance per thread, in the TLS block rather than on the guest
/// stack, which would have to be writable at resume time.
#[repr(C, align(16))]
struct ResumeFrame {
    /// Ignored by `rt_sigreturn`.
    siginfo: [u8; 128],
    ucontext: libc::ucontext_t,
}

// The kernel's `rt_sigframe`: `struct ucontext` follows the 128-byte siginfo,
// with the 16-byte-aligned `sigcontext` after 1024 bits of signal mask.
const _: () = {
    use core::mem::offset_of;
    assert!(
        offset_of!(ResumeFrame, ucontext) == 128
            && offset_of!(libc::ucontext_t, uc_mcontext) == 176
            && offset_of!(libc::mcontext_t, __fpregs) == 256
    );
};

/// Fills this thread's [`ResumeFrame`] from `ctx` and the guest floating-point
/// state, and returns it.
///
/// `rt_sigreturn` restores the signal mask, here the current one, every
/// integer register including `gp` (the TLS block) and `tp`, and the D
/// extension state. It requires the extension area after the D state to start
/// with a zero reserved word and an END header, and an all-zero area is just
/// that, so the frame describes no V state. The zero `uc_stack` makes the
/// kernel's altstack restore fail harmlessly, leaving the current altstack.
fn prepare_resume_frame(ctx: &PtRegs) -> *mut ResumeFrame {
    let frame = slot::<ResumeFrame>(tls_offset::RESUME_FRAME);
    // SAFETY: this thread's own frame, which nothing else references while
    // host code runs. `pthread_sigmask` only writes the given set.
    unsafe {
        let uc = &mut (*frame).ucontext;
        uc.__uc_flags = 0;
        uc.uc_link = core::ptr::null_mut();
        uc.uc_stack = core::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, core::ptr::null(), &raw mut uc.uc_sigmask);
        let gregs = &mut uc.uc_mcontext.__gregs;
        *gregs = FromBytes::read_from_bytes(&ctx.as_bytes()[..size_of_val(gregs)]).unwrap();
        gregs[3] = tls_block() as u64;
        core::ptr::write_bytes(&raw mut uc.uc_mcontext.__fpregs, 0, 1);
        let guest = slot::<FpState>(tls_offset::GUEST_FP).read();
        uc.uc_mcontext.__fpregs.__d = libc::__riscv_mc_d_ext_state {
            __f: guest.f,
            __fcsr: guest.fcsr,
        };
    }
    frame
}

/// Restores the guest through a prepared [`ResumeFrame`], by a host
/// `rt_sigreturn` unrelated to any guest `rt_sigreturn` the shim emulates.
///
/// # Safety
/// As [`switch_to_guest`]; `frame` must be from [`prepare_resume_frame`].
///
/// The other range [`in_switch_to_guest`] tests.
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest_via_sigreturn(frame: *mut ResumeFrame) -> ! {
    core::arch::naked_asm!(
    "
    .option push
    .option norelax
    .globl switch_to_guest_via_sigreturn_start
switch_to_guest_via_sigreturn_start:
    ",
    load_tls_block_base!("t1"),
    "
    frcsr t2
    sw   t2, {HOST_FCSR}(t1)
    li   t2, 1
    sb   t2, {IN_GUEST}(t1)
    lbu  t2, {INTERRUPT}(t1)
    beqz t2, 2f
    sb   zero, {IN_GUEST}(t1)
    tail interrupt_callback
2:
    // `rt_sigreturn` takes the frame from `sp`; the frame installs the guest
    // `sp`, `gp` and `tp` at once.
    mv   sp, a0
    li   a7, {NR_RT_SIGRETURN}
    ecall
    // Unreachable: on a bad frame, Linux forces SIGSEGV.
    unimp
    .globl switch_to_guest_via_sigreturn_end
switch_to_guest_via_sigreturn_end:
    .option pop
    ",
    HOST_FCSR = const tls_offset::HOST_FCSR,
    IN_GUEST = const tls_offset::IN_GUEST,
    INTERRUPT = const tls_offset::INTERRUPT,
    NR_RT_SIGRETURN = const libc::SYS_rt_sigreturn,
    );
}

unsafe extern "C" {
    pub(super) fn syscall_callback() -> isize;
    pub(super) fn syscall_callback_in_guest_cleared();
    pub(super) fn exception_callback();
    pub(super) fn interrupt_callback();
    fn switch_to_guest_via_gate_start();
    fn switch_to_guest_via_gate_end();
    fn switch_to_guest_via_sigreturn_start();
    fn switch_to_guest_via_sigreturn_end();
}

pub(super) fn syscall_entry_point() -> usize {
    syscall_callback as *const () as usize
}

/// Moves `ctx` back to the `ecall` site, which the rewriter replaced with a
/// four-byte `jal` to its gate.
pub(super) fn rewind_syscall(ctx: &mut PtRegs) {
    ctx.pc = ctx
        .pc
        .wrapping_sub(litebox_trampoline::SYSCALL_ENTRY_INSTRUCTION_LEN);
}

pub(super) fn in_switch_to_guest(pc: usize) -> bool {
    fn body(start: unsafe extern "C" fn(), end: unsafe extern "C" fn()) -> core::ops::Range<usize> {
        start as *const () as usize..end as *const () as usize
    }

    body(switch_to_guest_via_gate_start, switch_to_guest_via_gate_end).contains(&pc)
        || body(
            switch_to_guest_via_sigreturn_start,
            switch_to_guest_via_sigreturn_end,
        )
        .contains(&pc)
}

/// Whether `pc` is in [`exception_entry`] or [`interrupt_entry`].
fn in_signal_entry(pc: usize) -> bool {
    let body = |start: usize, end: unsafe extern "C" fn()| start..end as *const () as usize;
    body(exception_entry as *const () as usize, exception_entry_end).contains(&pc)
        || body(interrupt_entry as *const () as usize, interrupt_entry_end).contains(&pc)
}

pub(super) fn in_syscall_callback_prologue(ip: usize) -> bool {
    // The label keeps the bound tied to the asm.
    let start = syscall_callback as *const () as usize;
    (start..syscall_callback_in_guest_cleared as *const () as usize).contains(&ip)
}

/// Makes code just written to `range` visible to instruction fetch on every
/// hart before it runs: RISC-V instruction fetch is not coherent with stores.
pub(super) fn sync_instruction_stream(range: core::ops::Range<usize>) {
    if range.start >= range.end {
        return;
    }
    // Flags 0 synchronizes all threads of the process. The result is ignored:
    // failure only means that no synchronization is needed or possible
    // (qemu-user, for one, tracks self-modifying code itself).
    // SAFETY: only affects instruction caches.
    let _ = unsafe {
        syscalls::syscall3(
            syscalls::Sysno::riscv_flush_icache,
            range.start,
            range.end,
            0,
        )
    };
}

/// Called from signal handlers to fix up thread state after potentially running
/// in the guest.
///
/// Optionally sets `interrupt`, and claims the interrupted guest unless
/// `context` is host code: clears `in_guest` and, if it was set, installs the
/// host `fcsr` for the handler and returns the guest context pointer (which
/// does not necessarily have up-to-date guest register state yet).
///
/// `in_guest` alone does not identify the guest: it stays set while a
/// handler that interrupted the guest runs up to this call, where another
/// signal (SIGINT and SIGALRM are not masked in exception handlers) may
/// interrupt it. Such a nested signal leaves the guest to the outer handler
/// (see [`interrupted_host_code`]), so a handler that interrupted the guest
/// must leave through the runtime, not return to the guest directly, for the
/// shim to see an interrupt the nested signal set.
pub(super) fn signal_handler_exit_guest(
    context: &libc::ucontext_t,
    set_interrupt: bool,
) -> Option<*mut PtRegs> {
    if set_interrupt {
        interrupt_flag().store(1, Ordering::SeqCst);
    }
    if interrupted_host_code(context) || in_guest_flag().swap(0, Ordering::SeqCst) == 0 {
        return None;
    }
    // SAFETY: this thread's own TLS slots; `fscsr` changes only the
    // floating-point environment, which the signal return restores.
    unsafe {
        let fcsr = slot::<u32>(tls_offset::HOST_FCSR).read();
        core::arch::asm!("fscsr {}", in(reg) fcsr, options(nomem, nostack));
        Some(slot::<*mut PtRegs>(tls_offset::GUEST_CONTEXT).read())
    }
}

/// Whether a signal interrupted host code, from its context alone.
///
/// `in_guest` is set only within [`in_switch_to_guest`], which installs the
/// block as `gp` before leaving its range. While it is set, outside that
/// range, `gp` is the block from guest code until a signal handler or
/// `syscall_callback` clears it: the guest, its gates, the first instruction
/// of `syscall_callback`, and the signal entry before it installs the host
/// `gp`. Every other context has the host `gp`.
fn interrupted_host_code(context: &libc::ucontext_t) -> bool {
    let gregs = &context.uc_mcontext.__gregs;
    let pc: usize = gregs[0].trunc();
    let gp: usize = gregs[3].trunc();
    (gp == host_gp() && !in_switch_to_guest(pc)) || in_signal_entry(pc)
}

/// Copies the guest integer context from a Linux signal context interrupted
/// in the guest, substituting the guest `gp` for the physical one and mapping
/// a pc inside a gate, or at the runtime's syscall entry, to the context it
/// stands for.
pub(super) fn copy_signal_context(
    regs: &mut PtRegs,
    context: &libc::ucontext_t,
    interruption: GateInterruption,
) {
    let mut gregs: [usize; 32] = context.uc_mcontext.__gregs.map(TruncateExt::trunc);
    let at_syscall_entry = in_syscall_callback_prologue(gregs[0]);
    // A synchronous fault at the runtime entry's first store means physical
    // `gp` is not the TLS block, just as for a gate's own access.
    if interruption == GateInterruption::Synchronous && at_syscall_entry {
        fatal_runtime_state();
    }
    // SAFETY: this thread's own TLS slots.
    let spill = unsafe {
        gregs[3] = slot::<usize>(tls_offset::GUEST_GP).read();
        slot::<usize>(tls_offset::SPILL).read()
    };
    if at_syscall_entry {
        recovery::canonicalize_syscall_entry(&mut gregs, spill, read_guest);
    } else {
        match recovery::canonicalize(&mut gregs, spill, interruption, read_guest) {
            GateSignalResult::NotGate | GateSignalResult::Canonicalized => {}
            GateSignalResult::InvalidRuntimeState => fatal_runtime_state(),
        }
    }
    regs.as_mut_bytes()[..size_of_val(&gregs)].copy_from_slice(gregs.as_bytes());
    regs.orig_a0 = regs.a0;
}

/// Terminates after transition recovery finds that physical `gp` does not
/// locate the runtime's TLS block.
pub(super) fn fatal_runtime_state() -> ! {
    // The kernel delivers the illegal-instruction fault even though SIGILL is blocked, by
    // resetting it to its default action, so the process dies by SIGILL. Exit if it does not.
    let blocked: u64 = 1 << (libc::SIGILL - 1);
    // SAFETY: `rt_sigprocmask`, `unimp` and `exit_group` are async-signal-safe, are admitted by
    // this platform's seccomp filter, and involve no TLS, formatting, allocation, locks or
    // destructors. `blocked` is a kernel signal set that outlives the call.
    unsafe {
        let _ = syscalls::syscall4(
            syscalls::Sysno::rt_sigprocmask,
            libc::SIG_BLOCK.cast_unsigned() as usize,
            (&raw const blocked) as usize,
            0,
            core::mem::size_of_val(&blocked),
        );
        core::arch::asm!(
            "unimp",
            "li a0, {status}",
            "li a7, {nr}",
            "ecall",
            status = const libc::EXIT_FAILURE,
            nr = const libc::SYS_exit_group,
            options(noreturn)
        );
    }
}

/// Updates a Linux signal context interrupted in the guest to return to `f`
/// with the given arguments and the host `gp`, `tp` and `fcsr`.
///
/// The guest floating-point registers are live in the context, so they are
/// saved to the TLS block first, except within [`in_switch_to_guest`], where the
/// block is still authoritative.
pub(super) fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize,
    p1: isize,
    p2: isize,
    p3: isize,
) {
    let mc = &mut context.uc_mcontext;
    // SAFETY: Linux fills the D extension state, the union's active member on
    // RV64GC, and the TLS slots are this thread's own.
    unsafe {
        let fp = &mut mc.__fpregs.__d;
        if !in_switch_to_guest(mc.__gregs[0].trunc()) {
            slot::<FpState>(tls_offset::GUEST_FP).write(FpState::new(fp.__f, fp.__fcsr));
        }
        fp.__fcsr = slot::<u32>(tls_offset::HOST_FCSR).read();
    }
    let (gp, tp): (usize, usize);
    // SAFETY: reads registers only; signal entry installed the host values.
    unsafe {
        core::arch::asm!(
            "mv {gp}, gp",
            "mv {tp}, tp",
            gp = out(reg) gp,
            tp = out(reg) tp,
            options(nomem, nostack, preserves_flags)
        );
    }
    mc.__gregs[0] = f as usize as u64;
    mc.__gregs[3] = gp as u64;
    mc.__gregs[4] = tp as u64;
    for (reg, value) in mc.__gregs[10..14].iter_mut().zip([p0, p1, p2, p3]) {
        *reg = value.reinterpret_as_unsigned() as u64;
    }
}

/// Recovers the `scause` exception code of a synchronous fault, which Linux
/// does not expose to userspace, from its signal.
///
/// The signal identifies an illegal instruction or breakpoint directly.
/// `BUS_ADRALN` is a misaligned load, store or AMO, as jumps cannot misalign
/// with the C extension; Linux reports the pc as its address, so the
/// instruction at the pc tells which. Any other memory fault is taken as a
/// page fault at its address: an instruction fetch faults at the pc, or at
/// the next page if the instruction at the pc is four bytes and straddles it;
/// a data access to such an address is indistinguishable and taken as a
/// fetch. Otherwise the instruction at the pc is a store or AMO, or else a
/// load. Linux reports access faults (PMP or PMA violations) of every kind as
/// `SEGV_ACCERR` at the pc, so they are taken as instruction page faults.
pub(super) fn exception_from_signal(
    signum: libc::c_int,
    code: libc::c_int,
    pc: usize,
    address: usize,
) -> litebox::shim::Exception {
    use litebox::shim::Exception;
    // RV64 Linux's base page size; protections change at its multiples only.
    const PAGE_SIZE: usize = 0x1000;
    let fetch = || {
        let straddle = pc.wrapping_add(2);
        address == pc
            || (address == straddle
                && straddle.is_multiple_of(PAGE_SIZE)
                && !is_compressed_instruction(pc))
    };
    match signum {
        libc::SIGBUS if code == libc::BUS_ADRALN => {
            if is_store(pc) {
                Exception::STORE_ADDRESS_MISALIGNED
            } else {
                Exception::LOAD_ADDRESS_MISALIGNED
            }
        }
        libc::SIGSEGV | libc::SIGBUS if fetch() => Exception::INSTRUCTION_PAGE_FAULT,
        libc::SIGSEGV | libc::SIGBUS if is_store(pc) => Exception::STORE_PAGE_FAULT,
        libc::SIGSEGV | libc::SIGBUS => Exception::LOAD_PAGE_FAULT,
        libc::SIGTRAP => Exception::BREAKPOINT,
        // SIGILL, and SIGFPE, which RISC-V never raises: it has no arithmetic
        // traps, so the signal was sent.
        _ => Exception::ILLEGAL_INSTRUCTION,
    }
}

/// Whether the instruction at `pc` is known to be two bytes. Reads fallibly.
fn is_compressed_instruction(pc: usize) -> bool {
    let mut half = [0; 2];
    read_guest(pc, &mut half) && u16::from_le_bytes(half) & 0b11 != 0b11
}

/// Whether the instruction at `pc` is a store or AMO, other than `lr`. Reads
/// fallibly and only what decides: the first halfword gives the opcode, and an
/// unreadable one is not a store; only an AMO's operation is in the second,
/// and an AMO whose second halfword is unreadable is taken as a store.
fn is_store(pc: usize) -> bool {
    let mut half = [0; 2];
    if !read_guest(pc, &mut half) {
        return false;
    }
    let low = u16::from_le_bytes(half);
    if low & 0b11 != 0b11 {
        // Compressed (C extension) stores: `c.fsd`, `c.sw` and `c.sd` in
        // quadrant 0, and their stack-pointer forms in quadrant 2.
        return matches!(low & 0b11, 0b00 | 0b10) && (5..=7).contains(&(low >> 13));
    }
    match low & 0x7f {
        // STORE and STORE-FP.
        0x23 | 0x27 => true,
        // AMO, except `lr`, which only loads.
        0x2f => {
            let mut high = [0; 2];
            !read_guest(pc.wrapping_add(2), &mut high) || u16::from_le_bytes(high) >> 11 != 0b00010
        }
        _ => false,
    }
}

impl litebox::platform::ArchSpecificProvider for LinuxUserland {
    fn get_arch_specific_register(
        &self,
        _reg: &litebox::platform::ArchSpecificRegister,
    ) -> Result<usize, litebox::platform::ArchSpecificError> {
        // `gp` and `tp` are ordinary guest registers in `PtRegs`.
        Err(litebox::platform::ArchSpecificError::RegisterUnsupported)
    }

    fn set_arch_specific_register(
        &self,
        _reg: &litebox::platform::ArchSpecificRegister,
        _val: usize,
    ) -> Result<(), litebox::platform::ArchSpecificError> {
        Err(litebox::platform::ArchSpecificError::RegisterUnsupported)
    }
}

impl litebox::platform::GuestVectorStateProvider for LinuxUserland {
    type GuestVectorState = FpState;

    fn get_guest_vector_state(&self) -> FpState {
        // SAFETY: this thread's own TLS slot.
        unsafe { slot::<FpState>(tls_offset::GUEST_FP).read() }
    }

    fn set_guest_vector_state(&self, state: &FpState) {
        // SAFETY: this thread's own TLS slot.
        unsafe { slot::<FpState>(tls_offset::GUEST_FP).write(*state) };
    }
}

/// Installs inherited guest floating-point state. Otherwise the thread keeps
/// its state, which is zero, as Linux starts threads, on a fresh thread.
pub(super) fn prepare_guest_vector_state(inherited: Option<&FpState>) {
    if let Some(state) = inherited {
        // SAFETY: this thread's own TLS slot.
        unsafe { slot::<FpState>(tls_offset::GUEST_FP).write(*state) };
    }
}

// The transition assembly swaps the guest and host `gp` and `tp`; no
// per-thread registration or fork reset is needed.
pub(crate) struct Registration;

impl Registration {
    #[inline]
    pub(crate) fn enter() -> Self {
        Self
    }
}

#[inline]
pub(crate) unsafe fn reset_after_fork() {}

/// Admits [`sync_instruction_stream`].
pub(crate) fn add_seccomp_rules(rules: &mut Vec<(i64, Vec<seccompiler::SeccompRule>)>) {
    rules.push((syscalls::Sysno::riscv_flush_icache as i64, vec![]));
}

/// Defines a naked signal entry `$name` that installs the host `gp` and `tp`
/// and tail-calls `$handler`, and the symbol `$end` just past its code.
macro_rules! signal_entry {
    ($(#[$attr:meta])* $name:ident, $end:ident, $handler:path) => {
        $(#[$attr])*
        #[unsafe(naked)]
        pub(crate) unsafe extern "C" fn $name(
            signum: libc::c_int,
            info: &mut libc::siginfo_t,
            context: &mut libc::ucontext_t,
        ) {
            /// The handler proper, with the host `gp` and `tp`.
            unsafe extern "C" fn inner(
                signum: libc::c_int,
                info: &mut libc::siginfo_t,
                context: &mut libc::ucontext_t,
            ) {
                // SAFETY: the kernel supplies the signal arguments.
                unsafe { $handler(signum, info, context) };
            }

            core::arch::naked_asm!(
                load_host_gp!("t0"),
                "beq  gp, t0, 2f",
                load_tls_block_tprel!("t1"),
                "sub  tp, gp, t1",
                "mv   gp, t0",
                "2:",
                "tail {inner}",
                concat!(".globl ", stringify!($end)),
                concat!(stringify!($end), ":"),
                inner = sym inner,
            );
        }

        unsafe extern "C" {
            fn $end();
        }
    };
}

signal_entry!(
    /// Exception signal entry. Signals can interrupt the guest, or a
    /// transition, with physical `gp` the TLS block and `tp` the guest's or
    /// the host's. Before any Rust runs, this installs the host `tp`, derived
    /// from `gp`, and then the host `gp`; see the module docs.
    exception_entry,
    exception_entry_end,
    super::exception_signal_handler
);
signal_entry!(
    /// Interrupt signal entry; see [`exception_entry`].
    interrupt_entry,
    interrupt_entry_end,
    super::interrupt_signal_handler
);

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use core::sync::atomic::{AtomicU64, AtomicUsize};
    use litebox::platform::{GuestVectorStateProvider as _, ThreadProvider as _};
    use litebox::shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo};
    use litebox_common_linux::signal::{SigSet, Signal};
    use litebox_trampoline::riscv64::gate::{self, GateKind, RD, RS1, RS2};

    const PAGE: usize = 4096;
    const GP: u32 = 3;
    const T0: u32 = 5;
    const T1: u32 = 6;
    const A0: u32 = 10;
    const A1: u32 = 11;
    const A2: u32 = 12;
    const A3: u32 = 13;
    const A4: u32 = 14;

    const fn i_type(opcode: u32, funct3: u32, rd: u32, rs1: u32, imm: i32) -> u32 {
        (imm.cast_unsigned() & 0xfff) << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | opcode
    }
    const fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
        i_type(0x13, 0, rd, rs1, imm)
    }
    const fn lb(rd: u32, rs1: u32, imm: i32) -> u32 {
        i_type(0x03, 0, rd, rs1, imm)
    }
    const fn ld(rd: u32, rs1: u32, imm: i32) -> u32 {
        i_type(0x03, 3, rd, rs1, imm)
    }
    const fn jalr(rd: u32, rs1: u32, imm: i32) -> u32 {
        i_type(0x67, 0, rd, rs1, imm)
    }
    const fn sd(rs2: u32, rs1: u32, imm: i32) -> u32 {
        let imm = imm.cast_unsigned();
        (imm >> 5 & 0x7f) << 25 | rs2 << 20 | rs1 << 15 | 3 << 12 | (imm & 31) << 7 | 0x23
    }
    const fn add(rd: u32, rs1: u32, rs2: u32) -> u32 {
        rs2 << 20 | rs1 << 15 | rd << 7 | 0x33
    }
    /// `jal x0` by `offset` bytes.
    const fn j(offset: i32) -> u32 {
        let d = offset.cast_unsigned();
        (d >> 20 & 1) << 31 | (d >> 1 & 0x3ff) << 21 | (d >> 11 & 1) << 20 | d & 0xff000 | 0x6f
    }
    const fn fmv_x_d(rd: u32, fs1: u32) -> u32 {
        0xe200_0053 | fs1 << 15 | rd << 7
    }
    const fn fmv_d_x(fd: u32, rs1: u32) -> u32 {
        0xf200_0053 | rs1 << 15 | fd << 7
    }
    const fn frcsr(rd: u32) -> u32 {
        0x0030_2073 | rd << 7
    }
    const fn fscsr(rs1: u32) -> u32 {
        0x0030_1073 | rs1 << 15
    }
    /// `amo<funct5>.w a0, rs2, (a2)`.
    const fn amo(funct5: u32, rs2: u32) -> u32 {
        funct5 << 27 | rs2 << 20 | A2 << 15 | 2 << 12 | A0 << 7 | 0x2f
    }
    const EBREAK: u32 = 0x0010_0073;
    /// `unimp`: `csrrw x0, cycle, x0`.
    const UNIMP: u32 = 0xc000_1073;

    /// Guest code under construction, with the sites the rewriter would
    /// rewrite in it. A site's original instruction is irrelevant: emission
    /// overwrites it with a jump to its gate.
    #[derive(Default)]
    struct Program {
        code: Vec<u8>,
        sites: Vec<(usize, usize, GateKind)>,
    }

    impl Program {
        /// Appends `words` and returns the offset of the first.
        fn insns(&mut self, words: &[u32]) -> usize {
            let at = self.code.len();
            for word in words {
                self.code.extend_from_slice(&word.to_le_bytes());
            }
            at
        }

        /// Appends a `len`-byte site for a `kind` gate and returns its offset.
        fn site(&mut self, len: usize, kind: GateKind) -> usize {
            let at = self.code.len();
            self.code.resize(at + len, 0);
            self.sites.push((at, len, kind));
            at
        }

        fn ecall(&mut self) -> usize {
            self.site(4, GateKind::Ecall)
        }

        /// A four-byte site for `word`, whose register operands are at `fields`.
        fn gp(&mut self, word: u32, fields: &'static [u32]) -> usize {
            self.site(4, GateKind::Gp { word, fields })
        }
    }

    /// A rewritten [`Program`] in memory, in a mapping of an inaccessible
    /// guard page, a code page, a gate page, a data page and a stack page.
    /// The guard page makes gate recovery's backward scan from the first
    /// instructions fault and recover.
    struct Guest {
        mapping: usize,
        code: usize,
    }

    impl Guest {
        /// Loads the code at the start of the readable code page, directly
        /// followed by its gates.
        fn load(program: Program) -> Self {
            Self::map(program, false)
        }

        /// Loads the code at the end of the execute-only code page, followed
        /// by its gates on the readable gate page.
        fn load_execute_only(program: Program) -> Self {
            Self::map(program, true)
        }

        fn map(program: Program, execute_only: bool) -> Self {
            // SAFETY: creates a fresh private mapping.
            let mapping = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    5 * PAGE,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED);
            let mapping = mapping.addr();
            let code_page = mapping + PAGE;
            let gate_page = code_page + PAGE;
            // SAFETY: the new mapping, which nothing else uses.
            let protected = unsafe {
                libc::mprotect(
                    code_page as *mut _,
                    4 * PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            };
            assert_eq!(protected, 0);
            let mut code = program.code;
            code.resize(code.len().next_multiple_of(4), 0);
            let base = if execute_only {
                gate_page - code.len()
            } else {
                code_page
            };
            let gates_base = base + code.len();
            let mut gates = Vec::new();
            for (at, len, kind) in program.sites {
                gate::emit(
                    &mut code[at..at + len],
                    (base + at) as u64,
                    kind,
                    gates_base as u64,
                    &mut gates,
                )
                .unwrap();
            }
            code.extend_from_slice(&gates);
            assert!(gates_base + gates.len() <= gate_page + PAGE);
            let code_protection = if execute_only {
                libc::PROT_EXEC
            } else {
                libc::PROT_READ | libc::PROT_EXEC
            };
            // SAFETY: the code and gate pages of the new mapping, which
            // nothing else uses.
            unsafe {
                core::ptr::copy_nonoverlapping(code.as_ptr(), base as *mut u8, code.len());
                assert_eq!(
                    libc::mprotect(code_page as *mut _, PAGE, code_protection),
                    0
                );
                assert_eq!(
                    libc::mprotect(gate_page as *mut _, PAGE, libc::PROT_READ | libc::PROT_EXEC),
                    0
                );
            }
            sync_instruction_stream(base..base + code.len());
            Self {
                mapping,
                code: base,
            }
        }

        fn at(&self, offset: usize) -> usize {
            self.code + offset
        }

        fn data(&self) -> *mut u64 {
            (self.mapping + 3 * PAGE) as *mut u64
        }

        fn stack_top(&self) -> usize {
            self.mapping + 5 * PAGE
        }
    }

    impl Drop for Guest {
        fn drop(&mut self) {
            // SAFETY: unmaps the mapping `map` created, which no guest runs.
            unsafe { libc::munmap(self.mapping as *mut _, 5 * PAGE) };
        }
    }

    /// A context entering `guest` at `entry` with its stack, `gp` at its
    /// data page, and a distinctive value in every other register, which is
    /// also how an interrupt or exception right at `entry` presents it.
    fn initial_context(guest: &Guest, entry: usize) -> PtRegs {
        let words: [usize; 33] = core::array::from_fn(|i| 0x6d05_7000_0000_0000 | i << 4);
        let mut regs = PtRegs::read_from_bytes(words.as_bytes()).unwrap();
        regs.pc = guest.at(entry);
        regs.sp = guest.stack_top();
        regs.gp = guest.data().addr();
        regs.orig_a0 = regs.a0;
        regs
    }

    #[track_caller]
    fn assert_regs_eq(actual: &PtRegs, expected: &PtRegs) {
        assert_eq!(format!("{actual:#x?}"), format!("{expected:#x?}"));
    }

    enum Entry {
        Init,
        Syscall,
        Exception(ExceptionInfo),
        Interrupt,
    }

    /// A shim that hands every entry to a closure.
    struct ScriptShim<F>(RefCell<F>);

    impl<F: FnMut(Entry, &mut PtRegs) -> ContinueOperation> EnterShim for ScriptShim<F> {
        type ExecutionContext = PtRegs;

        fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
            (self.0.borrow_mut())(Entry::Init, ctx)
        }

        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            (self.0.borrow_mut())(Entry::Syscall, ctx)
        }

        fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
            (self.0.borrow_mut())(Entry::Exception(*info), ctx)
        }

        fn interrupt(&self, ctx: &mut PtRegs) -> ContinueOperation {
            (self.0.borrow_mut())(Entry::Interrupt, ctx)
        }
    }

    /// Runs a guest thread whose shim is `script`, which must install a
    /// valid guest context before resuming.
    fn run(script: impl FnMut(Entry, &mut PtRegs) -> ContinueOperation) {
        LinuxUserland::new();
        let shim = ScriptShim(RefCell::new(script));
        // SAFETY: the script installs the guest context.
        unsafe { super::run_thread_ref(&shim, &mut PtRegs::default()) };
    }

    fn read_fcsr() -> u32 {
        let fcsr: usize;
        // SAFETY: reads the floating-point environment only.
        unsafe {
            core::arch::asm!("frcsr {}", out(reg) fcsr, options(nomem, nostack, preserves_flags));
        }
        fcsr.trunc()
    }

    /// Syscalls enter the shim with the architectural guest context, and
    /// resume through the gate when the pc is unchanged, and otherwise,
    /// including after `rewind_syscall`, through `rt_sigreturn`.
    #[test]
    fn gate_syscalls_resume_through_the_gate_or_sigreturn() {
        const POISON: u64 = 0x6d05_7000_dead_0000;
        let mut program = Program::default();
        let first = program.ecall();
        let second = program.ecall();
        let third = program.ecall();
        program.insns(&[EBREAK]);
        let last = program.ecall();
        let guest = Guest::load(program);
        let start = initial_context(&guest, first);
        // Only the `rt_sigreturn` resume rewrites the resume frame's pc.
        let poison_resume_frame = || {
            // SAFETY: this thread's own resume frame, unused while host code
            // runs.
            unsafe {
                let frame = slot::<ResumeFrame>(tls_offset::RESUME_FRAME);
                let pc = &raw mut (*frame).ucontext.uc_mcontext.__gregs[0];
                core::mem::replace(&mut *pc, POISON) == POISON
            }
        };

        let mut expected = start.clone();
        let mut syscalls = 0;
        let mut via_gate = false;
        run(|entry, ctx| {
            if let Entry::Init = entry {
                *ctx = start.clone();
                poison_resume_frame();
                return ContinueOperation::Resume;
            }
            assert!(matches!(entry, Entry::Syscall));
            syscalls += 1;
            assert_eq!(
                poison_resume_frame(),
                via_gate,
                "resume to syscall {syscalls}"
            );
            let site = match syscalls {
                1 => first,
                2 => second,
                3 => third,
                _ => last,
            };
            expected.pc = guest.at(site) + 4;
            expected.orig_a0 = expected.a0;
            expected.a0 = (-(libc::ENOSYS as isize)).cast_unsigned();
            assert_regs_eq(ctx, &expected);
            // SAFETY: this thread's own TLS slots.
            unsafe {
                assert_eq!(slot::<usize>(tls_offset::GATE_NEXT_PC).read(), ctx.pc);
                assert_ne!(slot::<usize>(tls_offset::GATE_CONTINUATION).read(), 0);
            }
            match syscalls {
                1 => ctx.a0 = 42,
                2 => {
                    ctx.t0 = 0x7470;
                    ctx.a2 = 0xa2;
                }
                // Skips the breakpoint.
                3 => ctx.pc = guest.at(last),
                4 => {
                    rewind_syscall(ctx);
                    ctx.a7 = 0xa7;
                }
                _ => return ContinueOperation::Terminate,
            }
            via_gate = syscalls <= 2;
            expected = ctx.clone();
            ContinueOperation::Resume
        });
        assert_eq!(syscalls, 5);
    }

    /// Gates present the guest's own gp whatever physical gp holds, and
    /// restore the scratch registers they borrow.
    #[test]
    fn gp_gates_virtualize_gp() {
        const NEW_GP: usize = 0x6d05_7000_0000_0300;
        let mut program = Program::default();
        // `c.mv a1, gp`.
        program.site(
            2,
            GateKind::Gp {
                word: add(A1, 0, GP),
                fields: &[RD, RS1, RS2],
            },
        );
        program.gp(ld(A2, GP, 0), &[RD, RS1]);
        program.gp(sd(A3, GP, 8), &[RS1, RS2]);
        program.gp(addi(GP, GP, 16), &[RD, RS1]);
        // Borrows t2, as t0 and t1 are operands.
        program.gp(add(T0, GP, T1), &[RD, RS1, RS2]);
        let auipc = program.site(4, GateKind::AuipcGp(0x1000));
        program.ecall();
        program.gp(addi(A4, GP, 0), &[RD, RS1]);
        program.ecall();
        let guest = Guest::load(program);
        let start = initial_context(&guest, 0);
        let data = guest.data();
        // SAFETY: the guest's data page.
        unsafe { data.write(0x0123_4567_89ab_cdef) };

        let mut syscalls = 0;
        run(|entry, ctx| {
            match entry {
                Entry::Init => {
                    *ctx = start.clone();
                    return ContinueOperation::Resume;
                }
                Entry::Syscall => syscalls += 1,
                _ => panic!("unexpected entry"),
            }
            if syscalls > 1 {
                assert_eq!((ctx.gp, ctx.a4), (NEW_GP, NEW_GP));
                return ContinueOperation::Terminate;
            }
            let mut expected = start.clone();
            expected.pc = ctx.pc;
            expected.a0 = ctx.a0;
            expected.a1 = start.gp;
            expected.a2 = 0x0123_4567_89ab_cdef;
            expected.t0 = start.gp + 16 + start.t1;
            expected.gp = guest.at(auipc) + 0x1000;
            assert_regs_eq(ctx, &expected);
            // SAFETY: the guest's data page.
            assert_eq!(unsafe { data.add(1).read() }, start.a3 as u64);
            ctx.gp = NEW_GP;
            ContinueOperation::Resume
        });
        assert_eq!(syscalls, 2);
    }

    /// The guest's floating-point registers and `fcsr` are in the TLS block
    /// while the host runs with its own `fcsr`, and both resumes load them.
    #[test]
    fn guest_fp_state_is_preserved_across_syscalls() {
        let mut program = Program::default();
        program.insns(&[fmv_x_d(A1, 5), frcsr(A2), fmv_d_x(6, A3), fscsr(A4)]);
        program.ecall();
        let reload = program.insns(&[fmv_x_d(A1, 7), frcsr(A2)]);
        program.ecall();
        let guest = Guest::load(program);
        let mut start = initial_context(&guest, 0);
        // Rounds down, with the inexact flag.
        start.a4 = 0x41;

        let platform = LinuxUserland::new();
        let initial = FpState::new(core::array::from_fn(|i| 0x4000 | i as u64), 0x20);
        let host_fcsr = read_fcsr();
        let mut syscalls = 0;
        run(|entry, ctx| {
            match entry {
                Entry::Init => {
                    platform.set_guest_vector_state(&initial);
                    *ctx = start.clone();
                    return ContinueOperation::Resume;
                }
                Entry::Syscall => syscalls += 1,
                _ => panic!("unexpected entry"),
            }
            assert_eq!(read_fcsr(), host_fcsr);
            let mut state = platform.get_guest_vector_state();
            match syscalls {
                1 => {
                    assert_eq!((ctx.a1, ctx.a2), (0x4005, 0x20));
                    let mut expected = initial;
                    expected.f[6] = start.a3 as u64;
                    expected.fcsr = 0x41;
                    assert_eq!(state, expected);
                    // The gate resume must load f7 from the block.
                    // SAFETY: clobbers a caller-saved register only.
                    unsafe { core::arch::asm!("fmv.d.x f7, zero", out("f7") _) };
                    state.f[7] = 0x7777;
                    state.fcsr = 0x83;
                }
                2 => {
                    assert_eq!((ctx.a1, ctx.a2), (0x7777, 0x83));
                    state.f[7] = 0x7778;
                    state.fcsr = 0x62;
                    ctx.pc = guest.at(reload);
                }
                _ => {
                    assert_eq!((ctx.a1, ctx.a2), (0x7778, 0x62));
                    return ContinueOperation::Terminate;
                }
            }
            platform.set_guest_vector_state(&state);
            ContinueOperation::Resume
        });
        assert_eq!(syscalls, 3);
        assert_eq!(read_fcsr(), host_fcsr);
    }

    /// Interrupts preempt a guest spinning through gates, which the shim
    /// sees at an instruction boundary of the original loop.
    #[test]
    fn interrupts_preempt_a_guest_in_gates() {
        const INTERRUPTS: usize = 20;
        /// Stops the interrupt sender however the guest thread ends.
        struct Stop<'a>(&'a AtomicBool);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let mut program = Program::default();
        // `c.mv a1, gp`.
        let top = program.site(
            2,
            GateKind::Gp {
                word: add(A1, 0, GP),
                fields: &[RD, RS1, RS2],
            },
        );
        // Borrows t1, as t0 is an operand.
        let store = program.gp(sd(T0, GP, 0), &[RS1, RS2]);
        let jump = program.insns(&[j(-6)]);
        let exit = program.ecall();
        assert_eq!(jump - top, 6);
        let guest = Guest::load(program);
        let start = initial_context(&guest, top);
        let mut expected = start.clone();
        expected.a1 = start.gp;
        let loop_pcs = [top, store, jump].map(|offset| guest.at(offset));

        let platform = LinuxUserland::new();
        let stop = AtomicBool::new(false);
        let handled = AtomicUsize::new(0);
        // SAFETY: the guest's data page, which outlives the scope below and
        // which only the guest's `sd t0, 0(gp)` and these atomics access.
        let stored = unsafe { AtomicU64::from_ptr(guest.data()) };
        let mut interrupts = 0;
        std::thread::scope(|scope| {
            let _stop = Stop(&stop);
            run(|entry, ctx| match entry {
                Entry::Init => {
                    let thread = platform.current_thread();
                    let (stop, handled) = (&stop, &handled);
                    // Interrupts the guest only once it has stored since the
                    // last interrupt, so each one preempts the running loop
                    // however slow the host's way back to the guest is.
                    scope.spawn(move || {
                        let mut sent = 0;
                        while !stop.load(Ordering::Relaxed) {
                            if handled.load(Ordering::Acquire) == sent
                                && stored.load(Ordering::Relaxed) != 0
                            {
                                platform.interrupt_thread(&thread);
                                sent += 1;
                            }
                            std::thread::sleep(Duration::from_micros(100));
                        }
                    });
                    *ctx = start.clone();
                    ContinueOperation::Resume
                }
                Entry::Interrupt => {
                    interrupts += 1;
                    assert!(loop_pcs.contains(&ctx.pc), "interrupted at {:#x}", ctx.pc);
                    expected.pc = ctx.pc;
                    assert_regs_eq(ctx, &expected);
                    assert_eq!(stored.swap(0, Ordering::Relaxed), start.t0 as u64);
                    if interrupts == INTERRUPTS {
                        stop.store(true, Ordering::Relaxed);
                        ctx.pc = guest.at(exit);
                    }
                    handled.fetch_add(1, Ordering::Release);
                    ContinueOperation::Resume
                }
                Entry::Syscall => {
                    assert_eq!(interrupts, INTERRUPTS);
                    ContinueOperation::Terminate
                }
                Entry::Exception(info) => panic!("unexpected exception {info:?}"),
            });
        });
    }

    /// Guest faults reach the shim as RV64 exceptions at the faulting
    /// instruction, inside a gate at its site, and resume where the shim
    /// moves the pc.
    #[test]
    fn guest_exceptions_reach_the_shim() {
        const UNMAPPED: usize = 0x1000;
        let mut program = Program::default();
        let load = program.insns(&[lb(A1, 0, 0)]);
        let store = program.insns(&[sd(A1, A2, 0)]);
        let breakpoint = program.insns(&[EBREAK]);
        let illegal = program.insns(&[UNIMP]);
        let gate_load = program.gp(ld(A3, GP, 0), &[RD, RS1]);
        let fetch = program.insns(&[jalr(0, A4, 0)]);
        let exit = program.ecall();
        let guest = Guest::load(program);
        let mut start = initial_context(&guest, load);
        start.a2 = 8;
        start.gp = 16;
        start.a4 = UNMAPPED;

        // Each fault's exception, pc and address, and where it resumes.
        let faults = [
            (Exception::LOAD_PAGE_FAULT, guest.at(load), 0, store),
            (Exception::STORE_PAGE_FAULT, guest.at(store), 8, breakpoint),
            (Exception::BREAKPOINT, guest.at(breakpoint), 0, illegal),
            (
                Exception::ILLEGAL_INSTRUCTION,
                guest.at(illegal),
                0,
                gate_load,
            ),
            (Exception::LOAD_PAGE_FAULT, guest.at(gate_load), 16, fetch),
            (Exception::INSTRUCTION_PAGE_FAULT, UNMAPPED, UNMAPPED, exit),
        ];
        let mut taken = 0;
        run(|entry, ctx| {
            let info = match entry {
                Entry::Init => {
                    *ctx = start.clone();
                    return ContinueOperation::Resume;
                }
                Entry::Exception(info) => info,
                Entry::Syscall => {
                    assert_eq!(taken, faults.len());
                    return ContinueOperation::Terminate;
                }
                Entry::Interrupt => panic!("unexpected interrupt"),
            };
            let (exception, pc, address, resume) = faults[taken];
            taken += 1;
            assert_eq!(
                (
                    info.exception,
                    info.fault_address,
                    info.kernel_mode,
                    info.bus_error
                ),
                (exception, address, false, false),
                "fault {taken}"
            );
            let mut expected = start.clone();
            expected.pc = pc;
            assert_regs_eq(ctx, &expected);
            ctx.pc = guest.at(resume);
            ContinueOperation::Resume
        });
        assert_eq!(taken, faults.len());
    }

    /// Gates recover without reading execute-only guest code: a gate faults
    /// and restarts at its site if that is readable, and otherwise at its
    /// start, and a syscall returns past, and rewinds to, its `ecall` site.
    #[test]
    fn gates_recover_with_execute_only_sites() {
        const LOADED: u64 = 0x6d05_7000_10ad_0000;
        let mut program = Program::default();
        let load = program.gp(ld(A3, GP, 0), &[RD, RS1]);
        let ecall = program.ecall();
        let guest = Guest::load_execute_only(program);
        let gate = guest.at(8);
        // `read_guest` needs the platform's fault handlers.
        LinuxUserland::new();
        let restart = if read_guest(guest.at(load), &mut [0; 4]) {
            guest.at(load)
        } else {
            gate
        };
        let mut start = initial_context(&guest, load);
        start.gp = 16;
        // SAFETY: the data page, which no guest uses yet.
        unsafe { guest.data().write(LOADED) };

        let mut expected = start.clone();
        let mut entries = 0;
        run(|entry, ctx| {
            entries += 1;
            match (entries, entry) {
                (1, Entry::Init) => {
                    *ctx = start.clone();
                    return ContinueOperation::Resume;
                }
                (2, Entry::Exception(info)) => {
                    assert_eq!(
                        (info.exception, info.fault_address),
                        (Exception::LOAD_PAGE_FAULT, 16)
                    );
                    expected.pc = restart;
                    assert_regs_eq(ctx, &expected);
                    ctx.gp = guest.data().addr();
                }
                (3 | 4, Entry::Syscall) => {
                    expected.pc = guest.at(ecall) + 4;
                    expected.a3 = LOADED.trunc();
                    expected.orig_a0 = expected.a0;
                    expected.a0 = (-(libc::ENOSYS as isize)).cast_unsigned();
                    assert_regs_eq(ctx, &expected);
                    if entries == 4 {
                        return ContinueOperation::Terminate;
                    }
                    rewind_syscall(ctx);
                    assert_eq!(ctx.pc, guest.at(ecall));
                    ctx.a7 = 0xa7;
                }
                (n, _) => panic!("unexpected entry {n}"),
            }
            expected = ctx.clone();
            ContinueOperation::Resume
        });
        assert_eq!(entries, 4);
    }

    /// Unwinds a panic out of each shim entry and through `run_thread_arch`,
    /// including its callbacks entered from the guest, and catches it.
    ///
    /// `run_thread_arch`'s CFI is hand-written and nothing else checks it:
    /// reaching the `catch_unwind` requires the unwinder to resolve the CFA
    /// rule correctly, and a bad rule aborts the process.
    #[test]
    fn test_unwind_through_run_thread_arch() {
        let mut program = Program::default();
        let syscall = program.ecall();
        let fault = program.insns(&[lb(A1, 0, 0)]);
        let guest = Guest::load(program);
        LinuxUserland::new();
        for (unwind_from, entry) in [
            ("init", syscall),
            ("syscall", syscall),
            ("exception", fault),
            ("interrupt", syscall),
        ] {
            let start = initial_context(&guest, entry);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(|entry, ctx| {
                    let name = match entry {
                        Entry::Init => {
                            *ctx = start.clone();
                            if unwind_from == "interrupt" {
                                // Delivered before `pthread_kill` returns, so
                                // the resume finds the interrupt pending.
                                let signal = INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed);
                                // SAFETY: interrupts this live thread, which
                                // has the handler installed.
                                assert_eq!(
                                    unsafe { libc::pthread_kill(libc::pthread_self(), signal) },
                                    0
                                );
                            }
                            "init"
                        }
                        Entry::Syscall => "syscall",
                        Entry::Exception(_) => "exception",
                        Entry::Interrupt => "interrupt",
                    };
                    if name == unwind_from {
                        std::panic::panic_any(name);
                    }
                    ContinueOperation::Resume
                });
            }));
            let Err(payload) = result else {
                panic!("no panic out of {unwind_from}");
            };
            assert_eq!(
                payload.downcast_ref::<&str>(),
                Some(&unwind_from),
                "unexpected panic while unwinding out of {unwind_from}"
            );
            assert!(
                !is_guest_thread_from_signal_context(),
                "unwinding must run `GuestThreadMarker`'s drop"
            );
            assert_eq!(in_guest_flag().load(Ordering::SeqCst), 0);
        }
    }

    /// Signal recovery presents the guest gp from the TLS block and maps a pc
    /// inside a gate to the context the gate stands for.
    #[test]
    fn copy_signal_context_canonicalizes_interrupted_gates() {
        const GUEST_GP: usize = 0x6d05_7000_0000_0300;
        const SPILL: usize = 0x6d05_7000_0000_0500;
        // Recovery reads the guest code fallibly, through the fault handler.
        LinuxUserland::new();
        let mut program = Program::default();
        let site = program.gp(ld(A2, GP, 0), &[RD, RS1]);
        let ecall = program.ecall();
        let guest = Guest::load(program);
        // The gates: `sd t0, SPILL(gp)`; `ld t0, GUEST_GP(gp)`; `ld a2, 0(t0)`;
        // `ld t0, SPILL(gp)`; `jal x0, next`, and `sd t0, SPILL(gp)`;
        // `ld t0, SYSCALL_ENTRY(gp)`; `jalr t0, 0(t0)`; `ld t0, SPILL(gp)`;
        // `jal x0, next`.
        let gate = guest.at(8);
        let ecall_reload = gate + 20 + 12;

        // SAFETY: this thread's own TLS slots, which no guest uses.
        unsafe {
            slot::<usize>(tls_offset::GUEST_GP).write(GUEST_GP);
            slot::<usize>(tls_offset::SPILL).write(SPILL);
        }
        // SAFETY: an all-zero context is valid.
        let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
        for (i, reg) in context.uc_mcontext.__gregs.iter_mut().enumerate() {
            *reg = 0x6d05_7000_0000_0000 | (i as u64) << 4;
        }
        let t0 = context.uc_mcontext.__gregs[5];
        let entry = syscall_callback as *const () as usize;
        for (pc, continuation, resume, spilled) in [
            (guest.at(site), None, guest.at(site), false),
            (gate + 8, None, guest.at(site), true),
            (gate + 12, None, guest.at(site) + 4, true),
            // Interrupted at the runtime's syscall entry, before the syscall.
            (entry, Some(ecall_reload), guest.at(ecall), true),
        ] {
            context.uc_mcontext.__gregs[0] = pc as u64;
            context.uc_mcontext.__gregs[5] = continuation.map_or(t0, |c| c as u64);
            let mut regs = PtRegs::default();
            copy_signal_context(&mut regs, &context, GateInterruption::Asynchronous);
            let mut expected = PtRegs::default();
            expected.as_mut_bytes()[..256].copy_from_slice(context.uc_mcontext.__gregs.as_bytes());
            expected.pc = resume;
            expected.gp = GUEST_GP;
            if spilled {
                expected.t0 = SPILL;
            }
            expected.orig_a0 = expected.a0;
            assert_regs_eq(&regs, &expected);
        }
    }

    /// A signal claims the guest only if it interrupted guest code, its
    /// syscall entry or `switch_to_guest`, not if it interrupted a handler
    /// that has yet to claim the guest itself.
    #[test]
    fn nested_signals_leave_the_guest_to_the_outer_handler() {
        LinuxUserland::new();
        // SAFETY: this thread's own TLS slot; claiming the guest installs it.
        unsafe { slot::<u32>(tls_offset::HOST_FCSR).write(read_fcsr()) };
        let (host, block) = (host_gp(), tls_block());
        let address = |f: unsafe extern "C" fn()| f as *const () as usize;
        let handler = signal_handler_exit_guest as *const () as usize;
        for (pc, gp, claims) in [
            (handler, host, false),
            (exception_entry as *const () as usize, block, false),
            (interrupt_entry as *const () as usize + 4, block, false),
            (address(switch_to_guest_via_gate_start), host, true),
            (address(switch_to_guest_via_sigreturn_start), host, true),
            (syscall_callback as *const () as usize, block, true),
            (0x6d05_7000_0000_0000, block, true),
        ] {
            // SAFETY: an all-zero context is valid.
            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
            context.uc_mcontext.__gregs[0] = pc as u64;
            context.uc_mcontext.__gregs[3] = gp as u64;
            in_guest_flag().store(1, Ordering::SeqCst);
            interrupt_flag().store(0, Ordering::SeqCst);
            let claimed = signal_handler_exit_guest(&context, true).is_some();
            assert_eq!(
                (
                    claimed,
                    in_guest_flag().load(Ordering::SeqCst),
                    interrupt_flag().load(Ordering::SeqCst)
                ),
                (claims, u8::from(!claims), 1),
                "{pc:#x}"
            );
        }
        in_guest_flag().store(0, Ordering::SeqCst);
        interrupt_flag().store(0, Ordering::SeqCst);
    }

    /// Returning from a guest signal to the host saves the guest's
    /// floating-point registers, except within `switch_to_guest`, where the
    /// TLS block holds them, and installs the host `fcsr`, `gp` and `tp`.
    #[test]
    fn set_signal_return_saves_guest_fp_outside_switch_to_guest() {
        let platform = LinuxUserland::new();
        let block = FpState::new([0x1111; 32], 0x20);
        let signal = FpState::new(core::array::from_fn(|i| 0x4000 | i as u64), 0x41);
        let (gp, tp): (u64, u64);
        // SAFETY: reads registers only; this thread's own TLS slot.
        unsafe {
            core::arch::asm!("mv {}, gp", "mv {}, tp", out(reg) gp, out(reg) tp);
            slot::<u32>(tls_offset::HOST_FCSR).write(0x60);
        }
        for (pc, saved) in [
            (0x6d05_7000_0000_0000, true),
            (switch_to_guest_via_gate_start as *const () as usize, false),
            (
                switch_to_guest_via_sigreturn_start as *const () as usize,
                false,
            ),
        ] {
            platform.set_guest_vector_state(&block);
            // SAFETY: an all-zero context is valid.
            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
            context.uc_mcontext.__gregs[0] = pc as u64;
            context.uc_mcontext.__fpregs.__d = libc::__riscv_mc_d_ext_state {
                __f: signal.f,
                __fcsr: signal.fcsr,
            };
            set_signal_return(&mut context, exception_callback, 1, 2, 3, 4);
            assert_eq!(
                platform.get_guest_vector_state(),
                if saved { signal } else { block }
            );
            let mc = &context.uc_mcontext;
            // SAFETY: the D state is the union's active member.
            assert_eq!(unsafe { mc.__fpregs.__d.__fcsr }, 0x60);
            assert_eq!(mc.__gregs[0], exception_callback as *const () as u64);
            assert_eq!(mc.__gregs[3..5], [gp, tp]);
            assert_eq!(mc.__gregs[10..14], [1, 2, 3, 4]);
        }
    }

    /// Memory faults are classified by the faulting instruction, which may
    /// be compressed, and by whether the fetch itself faulted.
    #[test]
    fn exception_from_signal_classifies_memory_faults() {
        const SEGV_MAPERR: libc::c_int = 1;
        LinuxUserland::new();
        let classify =
            |pc: usize, address| exception_from_signal(libc::SIGSEGV, SEGV_MAPERR, pc, address);
        let store = [
            Exception::STORE_PAGE_FAULT,
            Exception::STORE_ADDRESS_MISALIGNED,
        ];
        let load = [
            Exception::LOAD_PAGE_FAULT,
            Exception::LOAD_ADDRESS_MISALIGNED,
        ];
        for (code, expected) in [
            (&sd(A1, A2, 0).to_le_bytes()[..], store),
            (&(0x27 | A2 << 15 | 3 << 12 | 1 << 20).to_le_bytes(), store), // fsd
            (&amo(0b00000, A1).to_le_bytes(), store),                      // amoadd.w
            (&amo(0b00011, A1).to_le_bytes(), store),                      // sc.w
            (&amo(0b00010, 0).to_le_bytes(), load),                        // lr.w
            (&ld(A1, A2, 0).to_le_bytes(), load),
            (&0xe004u16.to_le_bytes(), store), // c.sd s1, 0(s0)
            (&0xe006u16.to_le_bytes(), store), // c.sdsp ra, 0(sp)
            (&0x6004u16.to_le_bytes(), load),  // c.ld s1, 0(s0)
        ] {
            let pc = code.as_ptr().addr();
            // Linux reports the pc as a misaligned access's address.
            let misaligned = exception_from_signal(libc::SIGBUS, libc::BUS_ADRALN, pc, pc);
            assert_eq!([classify(pc, 0x10), misaligned], expected, "{code:x?}");
        }

        // A fetch faults at the pc, or at the next page for a four-byte
        // instruction that straddles it.
        // SAFETY: a fresh private mapping, unmapped below.
        let pages = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                2 * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(pages, libc::MAP_FAILED);
        let put = |pc: usize, bytes: &[u8]| {
            // SAFETY: within the writable mapping.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), pc as *mut u8, bytes.len()) };
            pc
        };
        let pc = put(pages.addr() + PAGE - 2, &sd(A1, A2, 0).to_le_bytes());
        assert_eq!(classify(pc, pc), Exception::INSTRUCTION_PAGE_FAULT);
        assert_eq!(classify(pc, pc + 2), Exception::INSTRUCTION_PAGE_FAULT);
        assert_eq!(classify(pc, pc + 1), Exception::STORE_PAGE_FAULT);
        put(pc, &0xe004u16.to_le_bytes()); // c.sd s1, 0(s0)
        assert_eq!(classify(pc, pc + 2), Exception::STORE_PAGE_FAULT);
        let pc = put(pages.addr(), &sd(A1, A2, 0).to_le_bytes());
        assert_eq!(classify(pc, pc + 2), Exception::STORE_PAGE_FAULT);
        // SAFETY: the mapping above, which nothing references any more.
        assert_eq!(unsafe { libc::munmap(pages, 2 * PAGE) }, 0);

        // An unreadable instruction is neither a store nor known to be short.
        let unreadable = 0x1000;
        assert_eq!(classify(unreadable, 0x10), Exception::LOAD_PAGE_FAULT);
        assert_eq!(
            classify(unreadable - 2, unreadable),
            Exception::INSTRUCTION_PAGE_FAULT
        );
    }

    fn read_tls<T>(offset: usize) -> T {
        // SAFETY: this thread's own, naturally aligned slot.
        unsafe { slot::<T>(offset).read_volatile() }
    }

    #[test]
    fn test_pending_host_signals_roundtrip() {
        let _ = take_pending_host_signals();
        assert_eq!(read_tls::<u32>(tls_offset::PENDING_HOST_SIGNALS), 0);
        assert_eq!(read_tls::<usize>(tls_offset::WAIT_WAKER_ADDR), 0);

        let alarm_bit = 1u32 << (Signal::SIGALRM.as_i32() - 1);
        let interrupt_bit = 1u32 << (Signal::SIGINT.as_i32() - 1);
        // SAFETY: host code runs with the host `tp`.
        unsafe {
            record_pending_signal(alarm_bit);
            record_pending_signal(interrupt_bit);
        }
        assert_eq!(
            read_tls::<u32>(tls_offset::PENDING_HOST_SIGNALS),
            alarm_bit | interrupt_bit,
            "record_pending_signal must OR into the slot, not overwrite it"
        );

        let taken = take_pending_host_signals();
        let expected = SigSet::empty().with(Signal::SIGALRM).with(Signal::SIGINT);
        assert_eq!(taken.as_u64(), expected.as_u64());
        assert!(
            take_pending_host_signals().is_empty(),
            "take_pending_host_signals must clear the slot it read"
        );
    }

    #[test]
    fn test_update_waker_exchange() {
        let platform = LinuxUserland::new();
        assert_eq!(read_tls::<usize>(tls_offset::WAIT_WAKER_ADDR), 0);

        platform.update_waker(Some(core::task::Waker::noop().clone()));
        assert_ne!(
            read_tls::<usize>(tls_offset::WAIT_WAKER_ADDR),
            0,
            "update_waker must publish the boxed waker"
        );
        platform.update_waker(Some(core::task::Waker::noop().clone()));
        assert_ne!(read_tls::<usize>(tls_offset::WAIT_WAKER_ADDR), 0);

        platform.update_waker(None);
        assert_eq!(
            read_tls::<usize>(tls_offset::WAIT_WAKER_ADDR),
            0,
            "update_waker(None) must clear the slot"
        );
    }

    #[test]
    fn test_guest_thread_marker() {
        assert!(!is_guest_thread_from_signal_context());
        {
            let _outer = GuestThreadMarker::enter();
            assert!(is_guest_thread_from_signal_context());
            {
                let _inner = GuestThreadMarker::enter();
                assert!(is_guest_thread_from_signal_context());
            }
            assert!(
                is_guest_thread_from_signal_context(),
                "dropping a nested marker must not unmark the thread"
            );
        }
        assert!(!is_guest_thread_from_signal_context());
    }
}
