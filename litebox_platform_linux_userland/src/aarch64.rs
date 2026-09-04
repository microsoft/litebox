// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 guest/host transitions and signal recovery. `TPIDR_EL0` remains the
//! host anchor; the guest thread pointer is virtualized in memory.

use super::*;
use litebox_syscall_rewriter::aarch64::{
    GATE_ALIGNMENT, GATE_PC_CANDIDATE_COUNT, GATE_SLOT_SIZES, GateMetadata, MSR_FRAME_BYTES,
    MSR_FRAME_OFF_VALUE, MrsTpidrGateOffset, MrsTpidrValueSource, MsrTpidrFrameState,
    MsrTpidrGateOffset, RuntimeAccess, SVC_FRAME_BYTES, SVC_GATE_BYTES, SVC_SLOT_BYTES,
    SvcFrameState, SvcGateOffset,
};
#[cfg(feature = "aarch64_virtualize_x18")]
use litebox_syscall_rewriter::aarch64::{
    X18_FRAME_BYTES, X18AdrOffset, X18CompareBranchOffset, X18FrameState, X18GateOffset, X18Resume,
    X18ValueSource, x18_branch_recovery_plan,
};

/// Overwrites the destination with the TLS control-block address derived from
/// the host anchor in `TPIDR_EL0`. Callbacks entered directly from a rewritten
/// gate must use `x16`, the only scratch register provided by the gate ABI.
/// Valid only for local-exec TLS in the main executable.
macro_rules! load_tls_block_base {
    ($reg:literal) => {
        concat!(
            "mrs ",
            $reg,
            ", tpidr_el0\n",
            "add ",
            $reg,
            ", ",
            $reg,
            ", #:tprel_hi12:litebox_tls_block, lsl #12\n",
            "add ",
            $reg,
            ", ",
            $reg,
            ", #:tprel_lo12_nc:litebox_tls_block\n",
        )
    };
}
pub(super) use load_tls_block_base;

macro_rules! tprel_offset {
    ($var:ident) => {
        tprel_offset!(@sym stringify!($var))
    };
    ($var:literal) => {
        tprel_offset!(@sym $var)
    };
    (@sym $var:expr) => {{
        let offset: usize;
        // SAFETY: reads no memory; materializes a link-time constant only.
        unsafe {
            core::arch::asm!(
                concat!("movz {0}, #:tprel_g1:", $var),
                concat!("movk {0}, #:tprel_g0_nc:", $var),
                out(reg) offset,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
        offset
    }};
}

/// Guest FP/SIMD state in the kernel's `fpsimd_context` field order.
/// The 16-byte alignment permits paired Q-register loads and stores.
use litebox_common_linux::signal::aarch64::GuestVectorState;

/// Layout of the AArch64 TLS control block.
///
/// A layout witness only: the storage is the `.tbss` block reserved below, and
/// this type is never instantiated. Every offset the transition assembly uses
/// is derived from it with [`core::mem::offset_of`], so the two cannot drift.
#[repr(C)]
struct TlsBlock {
    /// Guest thread pointer — the slot rewritten guest binaries read and write
    /// in place of the hardware `TPIDR_EL0`.
    ///
    /// Also part of the `litebox_syscall_rewriter` ABI, but dynamically: the
    /// loader patches each rewritten binary's gates with this slot's measured
    /// address (see [`guest_thread_pointer_tp_offset`]).
    guest_thread_pointer: usize,
    /// Guest x18 value used when optional x18 virtualization is enabled.
    guest_x18: usize,
    host_sp: usize,
    guest_context_top: usize,
    in_guest: u8,
    interrupt: u8,
    is_guest_thread: u8,
    pending_host_signals: u32,
    wait_waker_addr: usize,
    outbound_stub: usize,
    outbound_pc: usize,
    resume_frame_initialized: u8,
    guest_vector_state: GuestVectorState,
    resume_frame: resume_frame::ResumeFrame,
}

/// Byte offsets of [`TlsBlock`]'s fields, for the transition assembly.
pub(super) mod tls_offset {
    use super::TlsBlock;
    use core::mem::offset_of;

    pub(crate) const GUEST_THREAD_POINTER: usize = offset_of!(TlsBlock, guest_thread_pointer);
    pub(super) const GUEST_X18: usize = offset_of!(TlsBlock, guest_x18);
    pub(crate) const HOST_SP: usize = offset_of!(TlsBlock, host_sp);
    pub(crate) const GUEST_CONTEXT_TOP: usize = offset_of!(TlsBlock, guest_context_top);
    pub(crate) const IN_GUEST: usize = offset_of!(TlsBlock, in_guest);
    pub(crate) const INTERRUPT: usize = offset_of!(TlsBlock, interrupt);
    pub(crate) const IS_GUEST_THREAD: usize = offset_of!(TlsBlock, is_guest_thread);
    pub(crate) const PENDING_HOST_SIGNALS: usize = offset_of!(TlsBlock, pending_host_signals);
    pub(crate) const WAIT_WAKER_ADDR: usize = offset_of!(TlsBlock, wait_waker_addr);
    pub(crate) const OUTBOUND_STUB: usize = offset_of!(TlsBlock, outbound_stub);
    pub(crate) const OUTBOUND_PC: usize = offset_of!(TlsBlock, outbound_pc);
    pub(crate) const RESUME_FRAME_INITIALIZED: usize =
        offset_of!(TlsBlock, resume_frame_initialized);
    pub(super) const GUEST_VECTOR_STATE: usize = offset_of!(TlsBlock, guest_vector_state);
    pub(crate) const RESUME_FRAME: usize = offset_of!(TlsBlock, resume_frame);
}

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

/// Byte offset of this thread's `guest_thread_pointer` slot from the thread
/// pointer (TP) — `TPIDR_EL0` — as fixed by this binary's link.
///
/// The loader patches this into every rewritten guest binary's thread-pointer
/// gates. The linker decides it per embedder, but it is the same on every
/// thread.
///
/// # Panics
///
/// Panics if the offset is not one a gate can be patched to reach.
pub(super) fn guest_thread_pointer_tp_offset() -> u16 {
    let offset = tprel_offset!(litebox_tls_block) + tls_offset::GUEST_THREAD_POINTER;
    u16::try_from(offset)
        .ok()
        .filter(|off| litebox_syscall_rewriter::aarch64::is_patchable_guest_tpidr_offset(*off))
        .expect(
            "guest_thread_pointer must sit at a thread-pointer offset a rewriter gate can reach",
        )
}

/// Verifies the resume-frame alignment and rewriter-gate reach invariants.
///
/// # Panics
///
/// Panics if either invariant is violated.
pub(super) fn assert_tls_block_placement() {
    let frame = tprel_offset!(litebox_tls_block) + tls_offset::RESUME_FRAME;
    assert!(
        frame.is_multiple_of(core::mem::align_of::<resume_frame::ResumeFrame>()),
        "the resume frame is at thread-pointer offset {frame}, which `sys_rt_sigreturn` would \
         reject, failing every asynchronous guest resume",
    );

    let _ = guest_thread_pointer_tp_offset();
    let guest_tp = tprel_offset!(litebox_tls_block) + tls_offset::GUEST_THREAD_POINTER;
    let guest_x18 = tprel_offset!(litebox_tls_block) + tls_offset::GUEST_X18;
    assert_eq!(
        guest_x18.checked_sub(guest_tp),
        Some(litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP),
    );
    assert!(guest_x18.is_multiple_of(8) && u16::try_from(guest_x18).is_ok());
    #[cfg(feature = "aarch64_virtualize_x18")]
    assert!(
        u16::try_from(guest_x18)
            .is_ok_and(litebox_syscall_rewriter::aarch64::is_patchable_guest_x18_offset)
    );
}

const _: () = assert!(
    tls_offset::GUEST_X18 - tls_offset::GUEST_THREAD_POINTER
        == litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP
);
const _: () = assert!(tls_offset::GUEST_VECTOR_STATE < (1 << 12));

#[cfg(feature = "aarch64_virtualize_x18")]
fn set_guest_x18(value: usize) {
    // SAFETY: writes this thread's own fixed TLS slot and does not modify SP.
    unsafe {
        core::arch::asm! {
            load_tls_block_base!("{tmp}"),
            "str {val}, [{tmp}, #{off}]",
            tmp = out(reg) _,
            val = in(reg) value,
            off = const tls_offset::GUEST_X18,
            options(nostack, preserves_flags)
        }
    }
}

#[cfg(feature = "aarch64_virtualize_x18")]
fn get_guest_x18() -> usize {
    let value;
    // SAFETY: reads this thread's own fixed TLS slot and does not modify SP.
    unsafe {
        core::arch::asm! {
            load_tls_block_base!("{tmp}"),
            "ldr {value}, [{tmp}, #{off}]",
            tmp = out(reg) _,
            value = out(reg) value,
            off = const tls_offset::GUEST_X18,
            options(nostack, preserves_flags, readonly)
        }
    }
    value
}

pub(super) fn set_guest_thread_pointer(value: usize) {
    // SAFETY: an own-thread [`tls_offset`] slot access.
    unsafe {
        core::arch::asm! {
            load_tls_block_base!("{tmp}"),
            "str {val}, [{tmp}, #{off}]",
            tmp = out(reg) _,
            val = in(reg) value,
            off = const tls_offset::GUEST_THREAD_POINTER,
            options(nostack, preserves_flags)
        }
    }
}

pub(super) fn set_is_guest_thread(value: bool) {
    // SAFETY: an own-thread [`tls_offset`] slot access.
    unsafe {
        core::arch::asm! {
            load_tls_block_base!("{tmp}"),
            "strb {val:w}, [{tmp}, #{off}]",
            tmp = out(reg) _,
            val = in(reg) u32::from(value),
            off = const tls_offset::IS_GUEST_THREAD,
            options(nostack, preserves_flags)
        }
    }
}

pub(super) fn is_guest_thread() -> bool {
    let value: u32;
    // SAFETY: an own-thread [`tls_offset`] slot access. Also safe from a signal
    // handler: `TPIDR_EL0` is the host anchor at all times, guest code included.
    unsafe {
        core::arch::asm! {
            load_tls_block_base!("{tmp}"),
            "ldrb {val:w}, [{tmp}, #{off}]",
            tmp = out(reg) _,
            val = out(reg) value,
            off = const tls_offset::IS_GUEST_THREAD,
            options(nostack, preserves_flags)
        }
    }
    value != 0
}

pub(super) fn get_guest_thread_pointer() -> usize {
    let value: usize;
    // SAFETY: an own-thread [`tls_offset`] slot access.
    unsafe {
        core::arch::asm! {
            load_tls_block_base!("{tmp}"),
            "ldr {val}, [{tmp}, #{off}]",
            tmp = out(reg) _,
            val = out(reg) value,
            off = const tls_offset::GUEST_THREAD_POINTER,
            options(nostack, preserves_flags)
        }
    }
    value
}

#[unsafe(naked)]
pub(super) unsafe extern "C-unwind" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::PtRegs,
    reenter: u8,
) {
    core::arch::naked_asm!(
    "
    .cfi_startproc
    // Preserve every AAPCS64 callee-saved register across guest execution.
    stp x29, x30, [sp, #-160]!
    .cfi_def_cfa_offset 160
    .cfi_offset x29, -160
    .cfi_offset x30, -152
    mov x29, sp
    // Anchor the CFA on the frame pointer so the `sub sp, sp, #16` below (and
    // the callbacks' wholesale `mov sp, host_sp`) do not invalidate unwinding
    // through the `bl`s.
    //
    // INVARIANT: this rule is in effect for the whole FDE, including the three
    // alternate entry points below. Each of them is reached with `x29` holding
    // *guest* state, so each must re-establish the host `x29` before its `bl`
    // — otherwise a panic out of a handler would make the unwinder compute
    // `CFA = guest_x29 + 160` and read a return address from guest-controlled
    // memory. `x29 == host_sp + 16` by construction (see the `sub sp, sp, #16`
    // below), so each re-establishes it from `host_sp`.
    .cfi_def_cfa x29, 160
    stp x19, x20, [sp, #16]
    .cfi_offset x19, -144
    .cfi_offset x20, -136
    stp x21, x22, [sp, #32]
    .cfi_offset x21, -128
    .cfi_offset x22, -120
    stp x23, x24, [sp, #48]
    .cfi_offset x23, -112
    .cfi_offset x24, -104
    stp x25, x26, [sp, #64]
    .cfi_offset x25, -96
    .cfi_offset x26, -88
    stp x27, x28, [sp, #80]
    .cfi_offset x27, -80
    .cfi_offset x28, -72
    stp d8,  d9,  [sp, #96]
    .cfi_offset d8, -64
    .cfi_offset d9, -56
    stp d10, d11, [sp, #112]
    .cfi_offset d10, -48
    .cfi_offset d11, -40
    stp d12, d13, [sp, #128]
    .cfi_offset d12, -32
    .cfi_offset d13, -24
    stp d14, d15, [sp, #144]
    .cfi_offset d14, -16
    .cfi_offset d15, -8

    sub sp, sp, #16
    str x0, [sp]

    ",
    load_tls_block_base!("x8"),
    "
    mov x9, sp
    str x9, [x8, #{HOST_SP}]
    add x9, x1, #{GUEST_CONTEXT_SIZE}
    str x9, [x8, #{GUEST_CONTEXT_TOP}]

    // AAPCS64 leaves the upper bits of a `u8` parameter undefined.
    tst  w2, #0xff
    b.ne 1f
    bl {init_handler}
    b .Ldone_aarch64
1:
    bl {reenter_handler}
    b .Ldone_aarch64

    // Entered by `BR X16` from a rewriter-emitted SVC slot when the
    // guest issues a syscall. State on entry (rewriter ABI, see
    // `litebox_syscall_rewriter::aarch64` module docs):
    //
    //   | Item                     | Value                                  |
    //   | ------------------------ | -------------------------------------- |
    //   | x16                      | clobbered (holds the callback address) |
    //   | [sp, #0]                 | saved guest x16                        |
    //   | [sp, #8]                 | guest resume PC (svc_site + 4)         |
    //   | [sp, #16]                | this site's outbound stub address      |
    //   | sp                       | guest SP minus 32 (gate frame is live) |
    //   | x0-x15, x17-x30, NZCV    | pristine guest values                  |
    //   | TPIDR_EL0                | host anchor                            |
    .globl syscall_callback
syscall_callback:
    // Clear `in_guest`. This takes four instructions, so a pc can sit inside
    // the prologue with `in_guest` still 1. `in_syscall_callback_prologue`
    // tests the half-open range up to the label below; keep that label
    // immediately after the `strb`.
    ",
    load_tls_block_base!("x16"),
    "
    strb wzr, [x16, #{IN_GUEST}]
    .globl syscall_callback_in_guest_cleared
syscall_callback_in_guest_cleared:

    // Literal `PtRegs` offsets below are pinned by `tests::test_ptregs_layout`.
    ldr  x16, [x16, #{GUEST_CONTEXT_TOP}]
    sub  x16, x16, #{GUEST_CONTEXT_SIZE}

    stp  x0,  x1,  [x16]
    stp  x2,  x3,  [x16, #16]
    stp  x4,  x5,  [x16, #32]
    stp  x6,  x7,  [x16, #48]
    stp  x8,  x9,  [x16, #64]
    stp  x10, x11, [x16, #80]
    stp  x12, x13, [x16, #96]
    stp  x14, x15, [x16, #112]

    // Guest x16 and the resume PC come off the gate frame. The pair load
    // spells the rewriter's two offsets implicitly, so they are asserted below.
    ldp  x0,  x1,  [sp]
    str  x0,  [x16, #128]         // regs[16] = guest x16
    str  x17, [x16, #136]
    .if {VIRTUALIZE_X18}
    ",
    load_tls_block_base!("x0"),
    "
    ldr  x0, [x0, #{GUEST_X18}]
    str  x0, [x16, #144]
    .else
    str  x18, [x16, #144]
    .endif
    stp  x19, x20, [x16, #152]
    stp  x21, x22, [x16, #168]
    stp  x23, x24, [x16, #184]
    stp  x25, x26, [x16, #200]
    stp  x27, x28, [x16, #216]
    stp  x29, x30, [x16, #232]

    add  x0,  sp,  #{SVC_FRAME_BYTES}
    str  x0,  [x16, #248]         // sp: undo the gate's frame, so `PtRegs::sp`
                                  // is the true guest SP the shim expects
    str  x1,  [x16, #256]         // pc

    // Publish these before leaving the guest stack: the gate frame lies below
    // guest SP and need not survive the shim round trip.
    ldr  x0,  [sp,  #{SVC_FRAME_OFF_STUB}]
    ",
    load_tls_block_base!("x17"),
    "
    str  x0,  [x17, #{OUTBOUND_STUB}]
    str  x1,  [x17, #{OUTBOUND_PC}]

    mrs  x0,  nzcv
    str  x0,  [x16, #264]         // pstate
    ldr  x0,  [x16]
    str  x0,  [x16, #272]         // orig_x0
    str  w8,  [x16, #280]         // syscallno
    // regs[0] = -ENOSYS, matching what Linux leaves in x0 on syscall entry.
    // The negative immediate assembles to `MOVN`, i.e. a sign-extended 64-bit
    // value rather than a zero-extended 32-bit one.
    mov  x0,  #-{ENOSYS}
    str  x0,  [x16]

    add  x0, x17, #{GUEST_VECTOR_STATE}
    stp  q0,  q1,  [x0, #0]
    stp  q2,  q3,  [x0, #32]
    stp  q4,  q5,  [x0, #64]
    stp  q6,  q7,  [x0, #96]
    stp  q8,  q9,  [x0, #128]
    stp  q10, q11, [x0, #160]
    stp  q12, q13, [x0, #192]
    stp  q14, q15, [x0, #224]
    stp  q16, q17, [x0, #256]
    stp  q18, q19, [x0, #288]
    stp  q20, q21, [x0, #320]
    stp  q22, q23, [x0, #352]
    stp  q24, q25, [x0, #384]
    stp  q26, q27, [x0, #416]
    stp  q28, q29, [x0, #448]
    stp  q30, q31, [x0, #480]
    mrs  x1, fpsr
    mrs  x2, fpcr
    add  x0, x0, #512
    stp  w1, w2, [x0]

    // `x29` still holds the guest's frame pointer at this point (it was
    // spilled to `regs[29]` above). Re-establish the host value before the
    // `bl`, or the `.cfi_def_cfa x29, 160` rule would resolve against guest
    // memory if `syscall_handler` unwinds. `host_sp` is the frame base minus
    // the 16-byte `thread_ctx` slot, so the host `x29` is `host_sp + 16`.
    ",
    load_tls_block_base!("x17"),
    "
    ldr  x17, [x17, #{HOST_SP}]
    mov  sp,  x17
    add  x29, sp,  #16
    ldr  x0,  [sp]                // thread_ctx
    bl   {syscall_handler}
    b    .Ldone_aarch64

    // Entered from `exception_signal_handler` via `set_signal_return`, which
    // parks the handler arguments in `regs[0..3]` -> x0-x3 on entry here.
    // Argument 0 is a placeholder that this stub overwrites with `thread_ctx`;
    // arguments 1-3 (the signal number standing in for a trap number, a zero
    // error code, and the fault address) are already in x1-x3 and must not be
    // clobbered, so this stub scratches only x9 and above.
    //
    // `x29` arrives holding guest state (this is a signal return out of guest
    // execution), so it is re-established before the `bl`; see the
    // `.cfi_def_cfa x29, 160` invariant above.
    .globl exception_callback
exception_callback:
    ",
    load_tls_block_base!("x9"),
    "
    ldr x9, [x9, #{HOST_SP}]
    mov sp, x9
    add x29, sp, #16
    ldr x0, [sp]                  // thread_ctx
    bl {exception_handler}
    b .Ldone_aarch64

    // Entered either from `interrupt_signal_handler` via `set_signal_return`
    // (all four arguments are placeholders) or by a direct branch from
    // `switch_to_guest` when the `interrupt` byte was already set.
    // `interrupt_handler` takes only `thread_ctx`.
    //
    // Both entry paths arrive with a guest `x29`, so it is re-established
    // before the `bl`; see the `.cfi_def_cfa x29, 160` invariant above.
    .globl interrupt_callback
interrupt_callback:
    ",
    load_tls_block_base!("x9"),
    "
    ldr x9, [x9, #{HOST_SP}]
    mov sp, x9
    add x29, sp, #16
    ldr x0, [sp]                  // thread_ctx
    bl {interrupt_handler}
    b .Ldone_aarch64

.Ldone_aarch64:
    add sp, sp, #16
    ldp x19, x20, [sp, #16]
    ldp x21, x22, [sp, #32]
    ldp x23, x24, [sp, #48]
    ldp x25, x26, [sp, #64]
    ldp x27, x28, [sp, #80]
    ldp d8,  d9,  [sp, #96]
    ldp d10, d11, [sp, #112]
    ldp d12, d13, [sp, #128]
    ldp d14, d15, [sp, #144]
    ldp x29, x30, [sp], #160
    .cfi_def_cfa sp, 0
    ret
    .cfi_endproc
",
    GUEST_CONTEXT_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
    HOST_SP = const tls_offset::HOST_SP,
    GUEST_CONTEXT_TOP = const tls_offset::GUEST_CONTEXT_TOP,
    GUEST_VECTOR_STATE = const tls_offset::GUEST_VECTOR_STATE,
    IN_GUEST = const tls_offset::IN_GUEST,
    OUTBOUND_STUB = const tls_offset::OUTBOUND_STUB,
    OUTBOUND_PC = const tls_offset::OUTBOUND_PC,
    GUEST_X18 = const tls_offset::GUEST_X18,
    VIRTUALIZE_X18 = const cfg!(feature = "aarch64_virtualize_x18") as usize,
    SVC_FRAME_BYTES = const litebox_syscall_rewriter::aarch64::SVC_FRAME_BYTES,
    SVC_FRAME_OFF_STUB = const litebox_syscall_rewriter::aarch64::SVC_FRAME_OFF_STUB,
    ENOSYS = const libc::ENOSYS,
    init_handler = sym init_handler,
    reenter_handler = sym reenter_handler,
    syscall_handler = sym syscall_handler,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    );
}

/// `ldp x0, x1, [sp]` in `syscall_callback` reads the gate frame's two fields
/// as a pair, which only works at these offsets.
const _: () = assert!(
    litebox_syscall_rewriter::aarch64::SVC_FRAME_OFF_X16 == 0
        && litebox_syscall_rewriter::aarch64::SVC_FRAME_OFF_RETADDR == 8
);

/// The kernel's `struct rt_sigframe`, synthesized by the runtime so that an
/// *asynchronous* guest resume can restore all 31 GPRs, `SP`, `PC` and
/// `PSTATE` at once.
///
/// Returning through `rt_sigreturn` spends no register as a branch target, so
/// guest `x16` survives.
///
/// One instance per guest thread, in this crate's TLS rather than on the guest
/// stack, which would have to be writable at resume time and lies at a
/// guest-controlled address. Together with [`GuestVectorState`], costs
/// about 5.2KiB of `.tbss` per thread.
///
/// The required `fpsimd_context` record is populated from the platform-owned
/// guest vector state before each resume.
pub(super) mod resume_frame {
    use litebox_common_linux::PtRegs;
    use litebox_common_linux::signal::{Siginfo, Ucontext};
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

    /// `FPSIMD_MAGIC` from `arch/arm64/include/uapi/asm/sigcontext.h`.
    const FPSIMD_MAGIC: u32 = 0x4650_8001;

    /// `__NR_rt_sigreturn` on the asm-generic syscall table AArch64 uses.
    pub(crate) const NR_RT_SIGRETURN: u32 = syscalls::Sysno::rt_sigreturn as u32;

    /// The kernel's `struct fpsimd_context`: a `struct _aarch64_ctx` header
    /// followed by the FP/SIMD register file.
    ///
    /// `fpsr`/`fpcr` sit *between* the header and `vregs`; putting them after
    /// `vregs` instead pads the record out past the size the kernel expects.
    #[repr(C)]
    #[derive(FromBytes, Immutable, IntoBytes, KnownLayout)]
    struct FpsimdContext {
        magic: u32,
        size: u32,
        fpsr: u32,
        fpcr: u32,
        vregs: [u128; 32],
    }

    /// The kernel's `struct _aarch64_ctx`, used on its own as the `END_MAGIC`
    /// terminator that closes the `__reserved` record list.
    #[repr(C)]
    #[derive(FromBytes, Immutable, IntoBytes, KnownLayout)]
    struct Aarch64Ctx {
        magic: u32,
        size: u32,
    }

    /// The kernel's `struct rt_sigframe`.
    ///
    /// `rt_sigreturn` never reads the `siginfo` back — it exists so that the
    /// address a handler is entered with points at a complete frame — so this
    /// one stays zero for the whole of the thread's life. It is a field so
    /// that this type is the kernel's type and the layout test checks the
    /// `ucontext` offset.
    #[repr(C, align(16))]
    #[derive(FromBytes)]
    pub(super) struct ResumeFrame {
        siginfo: Siginfo,
        ucontext: Ucontext,
    }

    /// Uses pre-aligned TLS storage to avoid lazy initialization on a path that
    /// must not panic.
    fn state() -> (*mut ResumeFrame, *mut u8, usize) {
        let block: usize;
        // SAFETY: materializes the base of this thread's own TLS control
        // block from `TPIDR_EL0`, which always holds the host anchor. Reads no
        // memory.
        unsafe {
            core::arch::asm!(
                load_tls_block_base!("{block}"),
                block = out(reg) block,
                options(nomem, nostack, preserves_flags)
            );
        }
        (
            (block + super::tls_offset::RESUME_FRAME) as *mut ResumeFrame,
            (block + super::tls_offset::RESUME_FRAME_INITIALIZED) as *mut u8,
            block,
        )
    }

    fn init(frame: &mut ResumeFrame) {
        let mcontext = &mut frame.ucontext.mcontext;

        let (fpsimd, rest) = FpsimdContext::mut_from_prefix(&mut mcontext.__reserved)
            .expect("__reserved is larger than both records");
        fpsimd.magic = FPSIMD_MAGIC;
        fpsimd.size = u32::try_from(size_of::<FpsimdContext>()).expect("record size fits in u32");
        let (end, _) =
            Aarch64Ctx::mut_from_prefix(rest).expect("__reserved is larger than both records");
        end.magic = 0;
        end.size = 0;

        // `uc_stack` is deliberately left zeroed. `sys_rt_sigreturn` passes it
        // to `restore_altstack`, which squashes every error, and
        // `{ss_sp: NULL, ss_flags: 0, ss_size: 0}` is rejected by
        // `do_sigaltstack` (`ss_size < MINSIGSTKSZ` gives `-ENOMEM`) before it
        // changes anything. So this thread's alternate signal stack — which
        // `with_signal_alt_stack` installed and which every host signal
        // handler runs on — is left exactly as it is. Note that zeroing is not
        // the same as writing `SS_DISABLE`, which *would* tear it down.
    }

    /// Finds the kernel FP/SIMD record in a bounded AArch64 context chain.
    fn find_fpsimd_context(records: &[u8]) -> Option<&FpsimdContext> {
        let mut records = records;
        loop {
            let (header, _) = Aarch64Ctx::ref_from_prefix(records).ok()?;
            if header.magic == 0 && header.size == 0 {
                return None;
            }
            let size = usize::try_from(header.size).ok()?;
            if size < size_of::<Aarch64Ctx>() || size > records.len() || !size.is_multiple_of(16) {
                return None;
            }
            if header.magic == FPSIMD_MAGIC {
                if size != size_of::<FpsimdContext>() {
                    return None;
                }
                return FpsimdContext::ref_from_prefix(&records[..size])
                    .ok()
                    .map(|(context, _)| context);
            }
            records = &records[size..];
        }
    }

    /// Returns this thread's platform-owned guest vector state.
    fn guest_vector_state(block: usize) -> &'static super::GuestVectorState {
        // SAFETY: `block` is this thread's TLS base. Mutations happen only in
        // transition assembly or a signal handler while guest execution is stopped.
        unsafe { &*((block + super::tls_offset::GUEST_VECTOR_STATE) as *const _) }
    }

    /// Copies kernel-saved guest FP/SIMD state from a host signal context.
    /// Returns false if the bounded extension-record chain has no valid record.
    pub(super) fn capture_signal_vector_state(context: &libc::ucontext_t, block: usize) -> bool {
        const _: () = assert!(
            size_of::<libc::mcontext_t>()
                == size_of::<litebox_common_linux::signal::aarch64::Sigcontext>()
                && align_of::<libc::mcontext_t>()
                    == align_of::<litebox_common_linux::signal::aarch64::Sigcontext>()
                && core::mem::offset_of!(libc::mcontext_t, fault_address)
                    == core::mem::offset_of!(
                        litebox_common_linux::signal::aarch64::Sigcontext,
                        fault_address
                    )
                && core::mem::offset_of!(libc::mcontext_t, regs)
                    == core::mem::offset_of!(
                        litebox_common_linux::signal::aarch64::Sigcontext,
                        regs
                    )
                && core::mem::offset_of!(libc::mcontext_t, sp)
                    == core::mem::offset_of!(litebox_common_linux::signal::aarch64::Sigcontext, sp)
                && core::mem::offset_of!(libc::mcontext_t, pc)
                    == core::mem::offset_of!(litebox_common_linux::signal::aarch64::Sigcontext, pc)
                && core::mem::offset_of!(libc::mcontext_t, pstate)
                    == core::mem::offset_of!(
                        litebox_common_linux::signal::aarch64::Sigcontext,
                        pstate
                    )
        );
        // SAFETY: the assertions above pin libc's public prefix and complete
        // size/alignment to LiteBox's kernel-compatible sigcontext definition.
        let signal_context = unsafe {
            &*core::ptr::from_ref(&context.uc_mcontext)
                .cast::<litebox_common_linux::signal::aarch64::Sigcontext>()
        };
        let Some(fpsimd) = find_fpsimd_context(&signal_context.__reserved) else {
            return false;
        };
        // SAFETY: guest execution is stopped and this signal handler has sole
        // write access to the current thread's TLS vector state.
        let state = unsafe {
            &mut *((block + super::tls_offset::GUEST_VECTOR_STATE) as *mut super::GuestVectorState)
        };
        state.registers = fpsimd.vregs;
        state.fpsr = fpsimd.fpsr;
        state.fpcr = fpsimd.fpcr;
        true
    }

    /// Fills this thread's frame in from `ctx` and returns it, ready for
    /// `rt_sigreturn`.
    pub(super) fn prepare(ctx: &PtRegs) -> *mut ResumeFrame {
        let (frame, initialized, block) = state();
        // SAFETY: own-thread [`super::tls_offset`] slot accesses. The `&mut` is
        // exclusive: this is the only function that takes one, it cannot be
        // reentered on this thread (it runs with `in_guest` clear, outside any
        // signal handler, and calls nothing that re-enters the runtime), and
        // it is dead before the frame is handed to the kernel.
        let frame = unsafe { &mut *frame };
        // SAFETY: as above. Volatile is not needed — nothing else writes this
        // byte — but the read and the write are kept adjacent to the `init`
        // they guard.
        unsafe {
            if *initialized == 0 {
                init(frame);
                *initialized = 1;
            }
        }

        // `restore_sigframe` ends by installing this mask, so it decides the
        // host mask after every asynchronous resume and has to say "no change".
        // Sampled per resume: this frame outlives a single guest lifetime, and
        // nothing stops a host thread from running another one.
        // SAFETY: `sigset_t` is a plain bit array, so all-zero is a valid value.
        let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
        // SAFETY: `set` is a live, correctly typed `sigset_t`; passing a null
        // `set` argument makes this a pure query.
        unsafe {
            libc::pthread_sigmask(libc::SIG_BLOCK, core::ptr::null(), &raw mut set);
        }
        // SAFETY: `sigset_t` is at least 8 bytes on every Linux target and its
        // first 8 bytes are the mask for signals 1..=64, which is exactly the
        // kernel's `sigset_t`. Read unaligned because `sigset_t`'s alignment is
        // not part of its public API.
        let blocked = unsafe { core::ptr::read_unaligned((&raw const set).cast::<u64>()) };
        frame.ucontext.sigmask = litebox_common_linux::signal::SigSet::from_u64(blocked);

        let (fpsimd, _) = FpsimdContext::mut_from_prefix(&mut frame.ucontext.mcontext.__reserved)
            .expect("__reserved is 4KiB");
        let vector_state = guest_vector_state(block);
        fpsimd.vregs = vector_state.registers;
        fpsimd.fpsr = vector_state.fpsr;
        fpsimd.fpcr = vector_state.fpcr;

        let mcontext = &mut frame.ucontext.mcontext;
        for (dst, src) in mcontext.regs.iter_mut().zip(ctx.regs.iter()) {
            *dst = *src as u64;
        }
        #[cfg(feature = "aarch64_virtualize_x18")]
        // SAFETY: copies physical x18 into the kernel signal frame without
        // touching memory outside `mcontext` or modifying machine state.
        unsafe {
            core::arch::asm!("mov {host_x18}, x18", host_x18 = out(reg) mcontext.regs[18], options(nomem, nostack, preserves_flags));
        }
        mcontext.sp = ctx.sp as u64;
        mcontext.pc = ctx.pc as u64;
        // `rt_sigreturn` hands the whole word to the kernel, and
        // `valid_user_regs` rejects some values rather than trimming them, so
        // mask before the kernel sees it.
        mcontext.pstate = ctx.pstate & litebox_common_linux::arch::SAFE_USER_PSTATE;

        &raw mut *frame
    }

    #[cfg(test)]
    mod tests {
        use super::{Aarch64Ctx, FpsimdContext, ResumeFrame};
        use core::mem::offset_of;
        use litebox::utils::TruncateExt;
        use litebox_common_linux::PtRegs;
        use litebox_common_linux::signal::{Siginfo, Ucontext, aarch64::Sigcontext};
        use zerocopy::FromBytes as _;

        #[repr(align(16))]
        struct AlignedRecords([u8; 4096]);

        /// The layout `rt_sigreturn` expects, pinned against the kernel's
        /// `struct rt_sigframe`. This is the whole contract with the kernel:
        /// it reads fixed offsets off a bare pointer.
        #[test]
        fn test_frame_layout_matches_the_kernel() {
            assert_eq!(size_of::<Siginfo>(), 128);
            assert_eq!(offset_of!(ResumeFrame, siginfo), 0);
            assert_eq!(offset_of!(ResumeFrame, ucontext), 128);
            assert_eq!(size_of::<ResumeFrame>(), 4688);
            assert_eq!(align_of::<ResumeFrame>(), 16);

            assert_eq!(offset_of!(Ucontext, flags), 0);
            assert_eq!(offset_of!(Ucontext, link), 8);
            assert_eq!(offset_of!(Ucontext, stack), 16);
            assert_eq!(offset_of!(Ucontext, sigmask), 40);
            assert_eq!(offset_of!(Ucontext, mcontext), 176);
            assert_eq!(size_of::<Ucontext>(), 4560);

            assert_eq!(offset_of!(Sigcontext, fault_address), 0);
            assert_eq!(offset_of!(Sigcontext, regs), 8);
            assert_eq!(offset_of!(Sigcontext, sp), 256);
            assert_eq!(offset_of!(Sigcontext, pc), 264);
            assert_eq!(offset_of!(Sigcontext, pstate), 272);
            assert_eq!(offset_of!(Sigcontext, __reserved), 288);
            assert_eq!(size_of::<Sigcontext>(), 4384);

            // The two records written into `__reserved`, which the kernel
            // walks by `size` from the start of the area.
            assert_eq!(size_of::<FpsimdContext>(), 528);
            // Size alone does not pin the field order: `fpsr` and `fpcr` are
            // both `u32` and swapping them would install a guest-controlled
            // exception word into `FPCR`, trap-enable bits and all.
            assert_eq!(offset_of!(FpsimdContext, magic), 0);
            assert_eq!(offset_of!(FpsimdContext, size), 4);
            assert_eq!(offset_of!(FpsimdContext, fpsr), 8);
            assert_eq!(offset_of!(FpsimdContext, fpcr), 12);
            assert_eq!(offset_of!(FpsimdContext, vregs), 16);
            assert_eq!(super::FPSIMD_MAGIC, 0x4650_8001);
            assert_eq!(align_of::<FpsimdContext>(), 16);
            assert_eq!(size_of::<Aarch64Ctx>(), 8);
            assert!(size_of::<FpsimdContext>() + size_of::<Aarch64Ctx>() <= 4096);
        }

        #[test]
        fn signal_vector_state_parser_accepts_reordered_records_and_rejects_malformed_ones() {
            const UNKNOWN_MAGIC: u32 = 0x1234_5678;
            let expected = [0x1122_3344_5566_7788u128; 32];
            let mut records = AlignedRecords([0; 4096]);
            let (unknown, rest) = Aarch64Ctx::mut_from_prefix(&mut records.0).unwrap();
            unknown.magic = UNKNOWN_MAGIC;
            unknown.size = 16;
            let (fpsimd, rest) = FpsimdContext::mut_from_prefix(&mut rest[8..]).unwrap();
            fpsimd.magic = super::FPSIMD_MAGIC;
            fpsimd.size = u32::try_from(size_of::<FpsimdContext>()).unwrap();
            fpsimd.vregs = expected;
            let (end, _) = Aarch64Ctx::mut_from_prefix(rest).unwrap();
            end.magic = 0;
            end.size = 0;

            let parsed = super::find_fpsimd_context(&records.0).unwrap();
            assert_eq!(parsed.vregs, expected);

            records.0[4..8].copy_from_slice(&15u32.to_ne_bytes());
            assert!(super::find_fpsimd_context(&records.0).is_none());

            records.0.fill(0);
            assert!(super::find_fpsimd_context(&records.0).is_none());
            records.0[..4].copy_from_slice(&UNKNOWN_MAGIC.to_ne_bytes());
            records.0[4..8].copy_from_slice(&4112u32.to_ne_bytes());
            assert!(super::find_fpsimd_context(&records.0).is_none());
        }

        #[test]
        fn test_prepared_frame_round_trips_x16_through_the_kernel() {
            const SENTINEL: usize = 0x1234_1234_1234_1234;
            // Derive asm offsets from Rust layout so they cannot drift.
            const MCONTEXT: usize =
                offset_of!(ResumeFrame, ucontext) + offset_of!(Ucontext, mcontext);
            const REGS: usize = MCONTEXT + offset_of!(Sigcontext, regs);

            let mut ctx: PtRegs = unsafe { core::mem::zeroed() };
            ctx.regs[16] = SENTINEL;
            ctx.pc = 0;
            ctx.sp = 0;
            ctx.pstate = u64::MAX;

            let frame = super::prepare(&ctx);

            // SAFETY: `frame` is this thread's own frame, filled in above. The
            // block writes the live `sp`, `pc` and callee-saved registers into
            // it, so `rt_sigreturn` restores exactly the state this function
            // is running with, plus the sentinel in `x16`, and resumes at the
            // `99:` label. `x8` and `x16`-`x18` are declared clobbered; every
            // other caller-saved register is restored from the frame as zero,
            // so they are declared clobbered too via `clobber_abi("C")`.
            let observed: u64;
            unsafe {
                core::arch::asm!(
                    // Use a separate base because STP cannot reach `regs[30]`
                    // directly from the frame base.
                    "add x17, {f}, #{regs}",
                    "stp x19, x20, [x17, #152]",
                    "stp x21, x22, [x17, #168]",
                    "stp x23, x24, [x17, #184]",
                    "stp x25, x26, [x17, #200]",
                    "stp x27, x28, [x17, #216]",
                    "stp x29, x30, [x17, #232]",
                    "mov x17, sp",
                    "str x17, [{f}, #{sp}]",
                    "adr x17, 99f",
                    "str x17, [{f}, #{pc}]",
                    "mov sp, {f}",
                    "mov x8, #{nr}",
                    "svc #0",
                    "brk #0",
                    "99:",
                    "mov x20, x16",
                    f = in(reg) frame,
                    lateout("x20") observed,
                    regs = const REGS,
                    sp = const MCONTEXT + 256,
                    pc = const MCONTEXT + 264,
                    nr = const super::NR_RT_SIGRETURN,
                    clobber_abi("C"),
                );
            }

            let observed: usize = observed.trunc();
            assert_eq!(
                observed, SENTINEL,
                "the kernel must restore `regs[16]` from the synthesized frame"
            );
        }

        /// `prepare` must sanitize `pstate` rather than pass a guest-derived
        /// word through to `valid_user_regs`.
        ///
        /// The consequence of not doing so is not a permissive guest, it is a
        /// host `SIGSEGV`: `PSR_MODE32_BIT` in a frame makes `rt_sigreturn`
        /// take its `badframe` path. The preceding test would catch that only
        /// by killing the test process.
        #[test]
        fn test_prepare_sanitizes_pstate() {
            let mut ctx: PtRegs = unsafe { core::mem::zeroed() };
            ctx.pstate = u64::MAX;
            let frame = super::prepare(&ctx);
            // SAFETY: `frame` is this thread's own frame and no `&mut` to it
            // is live here.
            let pstate = unsafe { (*frame).ucontext.mcontext.pstate };
            assert_eq!(pstate, litebox_common_linux::arch::SAFE_USER_PSTATE);
            assert_eq!(pstate & (1 << 4), 0, "PSR_MODE32_BIT must never be set");
        }
    }
}

/// Switches to the provided guest context.
///
/// # Safety
/// The context must be a valid guest context. This can only be called if
/// `run_thread_arch` is on the stack; after the guest exits, it will return to
/// the interior of `run_thread_arch`. Do not call this where the stack needs
/// unwinding to run destructors.
///
/// AArch64 cannot restore all 31 GPRs *and* branch, so this dispatches to
/// [`switch_to_guest_via_outbound_stub`] or [`switch_to_guest_via_sigreturn`].
/// The stub is usable exactly when [`tls_offset::OUTBOUND_STUB`] is recorded and
/// `PtRegs::pc` still equals [`tls_offset::OUTBOUND_PC`]; the pair is never
/// invalidated, so a stale record can only be selected when using it is correct.
/// The choice happens here, before `in_guest` is set, so the frame stores cannot
/// be attributed to the guest.
pub(super) unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    #[cfg(feature = "aarch64_virtualize_x18")]
    set_guest_x18(ctx.regs[18]);
    if outbound_stub_is_current(ctx) {
        // SAFETY: the caller's contract, plus the stub's own: a stub is
        // recorded and `ctx.pc` is the PC it branches to, checked above.
        unsafe { switch_to_guest_via_outbound_stub(ctx) }
    } else {
        let frame = resume_frame::prepare(ctx);
        // SAFETY: the caller's contract, plus a fully prepared frame, which
        // `resume_frame::prepare` just returned and which lives for the rest
        // of this thread's life.
        unsafe { switch_to_guest_via_sigreturn(frame) }
    }
}

pub(super) fn outbound_stub_is_current(ctx: &litebox_common_linux::PtRegs) -> bool {
    let stub: usize;
    let pc: usize;
    // SAFETY: own-thread [`tls_offset`] slot accesses. Read through `asm!`
    // rather than plain loads because the transition assembly writes these
    // slots behind the compiler's back.
    unsafe {
        core::arch::asm!(
            load_tls_block_base!("{block}"),
            "ldr {stub}, [{block}, #{stub_off}]",
            "ldr {pc}, [{block}, #{pc_off}]",
            block = out(reg) _,
            stub = out(reg) stub,
            pc = out(reg) pc,
            stub_off = const tls_offset::OUTBOUND_STUB,
            pc_off = const tls_offset::OUTBOUND_PC,
            options(nostack, preserves_flags, readonly)
        );
    }
    stub != 0 && pc == ctx.pc
}

/// Re-enters the guest through the rewriter's per-site outbound stub, for a
/// resume at the `SVC` site the guest left from.
///
/// # Safety
/// As [`switch_to_guest`], and additionally: a stub must be recorded in
/// [`tls_offset::OUTBOUND_STUB`] and `ctx.pc` must be the PC it branches to.
/// [`outbound_stub_is_current`] is the check.
///
/// `SP` is staged at `PtRegs::sp - SVC_FRAME_BYTES` because the stub pops the
/// frame, and `[SP, #0]` is re-written from `PtRegs::regs[16]` so a shim that
/// modified it is honored. That store is the only write to guest memory in any
/// transition assembly, so it carries an exception-table fixup that skips it
/// and takes the stub anyway.
///
/// The `switch_to_guest_via_outbound_stub_start`/`_end` bracket is one of the
/// two ranges [`in_switch_to_guest`] tests: from before the `in_guest` store to
/// the final branch, an interrupt must reach `interrupt_callback` rather than
/// be attributed to the guest. Do not shrink it.
#[unsafe(naked)]
pub(super) unsafe extern "C" fn switch_to_guest_via_outbound_stub(
    ctx: &litebox_common_linux::PtRegs,
) -> ! {
    core::arch::naked_asm!(
    "
// No `.cfi_startproc`/`.cfi_endproc`, so this function gets no FDE. That is
// deliberate: it is `-> !` and never returns, and the doc comment above
// forbids calling it where the stack may need unwinding, so there is no
// correct CFA to describe. Emitting a rule here would be worse than emitting
// none, because `sp` and `x29` are switched to guest values partway through.
.globl switch_to_guest_via_outbound_stub_start
switch_to_guest_via_outbound_stub_start:
    ",
    load_tls_block_base!("x17"),
    "
    mov  w16, #1
    strb w16, [x17, #{IN_GUEST}]
    ldrb w16, [x17, #{INTERRUPT}]
    // The condition is inverted around an unconditional branch on purpose; do
    // not 'simplify' this back to `cbnz w16, interrupt_callback`.
    // `interrupt_callback` lives in `run_thread_arch`'s separate `naked_asm!`
    // block, so the reference is a cross-section relocation resolved by the
    // linker, not by the assembler. A conditional branch emits
    // `R_AARCH64_CONDBR19`, which reaches only +/-1MiB and for which the
    // linker inserts no veneer -- it hard-fails with `relocation truncated to
    // fit` if CGU partitioning or LTO ever places the two functions further
    // apart. `B` emits `R_AARCH64_JUMP26`: +/-128MiB and veneer-able.
    cbz  w16, 3f
    // The guest is not entered after all, so `in_guest` must not stay set:
    // `interrupt_callback` runs host code, and a signal arriving there with
    // `in_guest` set is taken for a guest fault and overwrites the saved guest
    // context with the host register file.
    strb wzr, [x17, #{IN_GUEST}]
    b    interrupt_callback
3:

    add  x17, x17, #{GUEST_VECTOR_STATE}
    add  x17, x17, #512
    ldp  w16, w4, [x17]
    sub  x17, x17, #512
    msr  fpsr, x16
    msr  fpcr, x4
    ldp  q0,  q1,  [x17, #0]
    ldp  q2,  q3,  [x17, #32]
    ldp  q4,  q5,  [x17, #64]
    ldp  q6,  q7,  [x17, #96]
    ldp  q8,  q9,  [x17, #128]
    ldp  q10, q11, [x17, #160]
    ldp  q12, q13, [x17, #192]
    ldp  q14, q15, [x17, #224]
    ldp  q16, q17, [x17, #256]
    ldp  q18, q19, [x17, #288]
    ldp  q20, q21, [x17, #320]
    ldp  q22, q23, [x17, #352]
    ldp  q24, q25, [x17, #384]
    ldp  q26, q27, [x17, #416]
    ldp  q28, q29, [x17, #448]
    ldp  q30, q31, [x17, #480]
    sub  x17, x17, #{GUEST_VECTOR_STATE}

    // x16 carries the stub across restoration; guest x16 is staged for the
    // stub to reload.
    ldr  x16, [x17, #{OUTBOUND_STUB}]
    ldr  x4,  [x0,  #248]
    sub  x4,  x4,  #{SVC_FRAME_BYTES}
    mov  sp,  x4
    ldr  x5,  [x0,  #128]
    // The one and only write to *guest* memory in the transition assembly,
    // hence the only instruction here that a guest can make fault. It is
    // registered in the exception table below so that a fault is recovered in
    // place instead of being mistaken for a guest exception; see this
    // function's doc comment.
.globl switch_to_guest_stage_x16
switch_to_guest_stage_x16:
    str  x5,  [sp,  #{SVC_FRAME_OFF_X16}]
.globl switch_to_guest_stage_x16_fixup
switch_to_guest_stage_x16_fixup:
    // TODO: skipping the store is not a clean recovery either way. If the
    // guest stack is unmapped, the stub's own reload of `x16` faults next; if
    // it is merely read-only, that reload succeeds and returns the guest's
    // original `x16`, silently dropping any change the shim made to
    // `regs[16]`. Diverting here to the `rt_sigreturn` path would handle both,
    // since it reads its frame from runtime TLS and never touches guest
    // memory -- but it must first restore `sp` from `host_sp` and clear
    // `in_guest`, since it re-enters Rust.
    // Exception-table entry for the store above, in the format
    // `litebox::mm::exception_table` defines and searches: three self-relative
    // 32-bit deltas, [start, stop) and the fixup. Written out longhand rather
    // than through that module's `ex_table_entry!` because the macro is
    // private to it and this body is one string literal; keep the section
    // flags (`aR`: allocate, retain) identical to the ones there.
    .pushsection ex_table,\"aR\"
    .balign 4
    .long switch_to_guest_stage_x16 - .
    .long switch_to_guest_stage_x16_fixup - .
    .long switch_to_guest_stage_x16_fixup - .
    .popsection

    // `msr nzcv` writes only PSTATE 31:28. SSBS and DIT are carried in
    // `PtRegs::pstate` (see `copy_signal_context`) but are knowingly NOT
    // restored here: writing them needs `msr ssbs`/`msr dit`, which are
    // ARMv8.0 optional / ARMv8.4 respectively, so unconditionally emitting
    // them would raise this crate's hardware floor. A guest that sets SSBS or
    // DIT therefore loses them across a syscall: both are hardening hints with
    // no architectural effect on results. (The asynchronous path does restore
    // them, for free, because `rt_sigreturn` writes the whole SPSR; see
    // `resume_frame::prepare`.)
    //
    // TODO: restore SSBS/DIT for guests that set them, gated on a runtime
    // feature probe (HWCAP_SSBS / HWCAP2_DIT) so the hardware floor stays at
    // ARMv8.0. Only worth doing once a guest actually depends on them.
    ldr  x1,  [x0, #264]
    msr  nzcv, x1
    ldr  x1,  [x0, #8]
    ldp  x2,  x3,  [x0, #16]
    ldp  x4,  x5,  [x0, #32]
    ldp  x6,  x7,  [x0, #48]
    ldp  x8,  x9,  [x0, #64]
    ldp  x10, x11, [x0, #80]
    ldp  x12, x13, [x0, #96]
    ldp  x14, x15, [x0, #112]
    ldr  x17, [x0, #136]
    .if !{VIRTUALIZE_X18}
    ldr  x18, [x0, #144]
    .endif
    ldp  x19, x20, [x0, #152]
    ldp  x21, x22, [x0, #168]
    ldp  x23, x24, [x0, #184]
    ldp  x25, x26, [x0, #200]
    ldp  x27, x28, [x0, #216]
    ldp  x29, x30, [x0, #232]
    ldr  x0,  [x0, #0]
    br   x16
.globl switch_to_guest_via_outbound_stub_end
switch_to_guest_via_outbound_stub_end:
"
    ,
    IN_GUEST = const tls_offset::IN_GUEST,
    INTERRUPT = const tls_offset::INTERRUPT,
    GUEST_VECTOR_STATE = const tls_offset::GUEST_VECTOR_STATE,
    OUTBOUND_STUB = const tls_offset::OUTBOUND_STUB,
    SVC_FRAME_BYTES = const litebox_syscall_rewriter::aarch64::SVC_FRAME_BYTES,
    SVC_FRAME_OFF_X16 = const litebox_syscall_rewriter::aarch64::SVC_FRAME_OFF_X16,
    VIRTUALIZE_X18 = const cfg!(feature = "aarch64_virtualize_x18") as usize,
    );
}

/// Re-enters the guest by `rt_sigreturn`-ing into a prepared
/// [`resume_frame::ResumeFrame`], for a resume at an arbitrary PC.
///
/// # Safety
/// As [`switch_to_guest`], and additionally: `frame` must point at a frame
/// [`resume_frame::prepare`] has filled in from the context being resumed, and
/// must stay valid until the guest is entered.
///
/// A *host* `rt_sigreturn` on the host's own thread, unrelated to the guest
/// `rt_sigreturn` the shim emulates.
///
/// The second range [`in_switch_to_guest`] tests; see
/// [`switch_to_guest_via_outbound_stub`]. During the `svc` itself is fine.
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest_via_sigreturn(frame: *mut resume_frame::ResumeFrame) -> ! {
    core::arch::naked_asm!(
    "
// No FDE, for the reason given on `switch_to_guest_via_outbound_stub`.
.globl switch_to_guest_via_sigreturn_start
switch_to_guest_via_sigreturn_start:
    ",
    load_tls_block_base!("x17"),
    "
    mov  w16, #1
    strb w16, [x17, #{IN_GUEST}]
    ldrb w16, [x17, #{INTERRUPT}]
    cbz  w16, 3f
    strb wzr, [x17, #{IN_GUEST}]
    b    interrupt_callback
3:
    // `sys_rt_sigreturn` takes the frame address from `SP` and nothing else;
    // it rejects `SP & 15`, which `ResumeFrame`'s `align(16)` rules out. The
    // guest's own `SP` is in the frame and the kernel installs it.
    mov  sp,  x0
    mov  x8,  #{NR_RT_SIGRETURN}
    svc  #0
    // Unreachable: `rt_sigreturn` does not return, and a frame it rejects is
    // answered with a `SIGSEGV` rather than an error return. Trap rather than
    // fall through into whatever the linker placed next.
    brk  #0
.globl switch_to_guest_via_sigreturn_end
switch_to_guest_via_sigreturn_end:
"
    ,
    IN_GUEST = const tls_offset::IN_GUEST,
    INTERRUPT = const tls_offset::INTERRUPT,
    NR_RT_SIGRETURN = const resume_frame::NR_RT_SIGRETURN,
    );
}

impl litebox::platform::ArchSpecificProvider for LinuxUserland {
    fn set_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
        val: usize,
    ) -> Result<(), litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::TpidrEl0 => {
                if litebox_common_linux::arch::is_valid_user_tls_base(val) {
                    set_guest_thread_pointer(val);
                    Ok(())
                } else {
                    Err(litebox::platform::ArchSpecificError::RegisterUnpermittedValue)
                }
            }
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }
    fn get_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
    ) -> Result<usize, litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::TpidrEl0 => Ok(get_guest_thread_pointer()),
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }
}

impl litebox::platform::GuestVectorStateProvider for LinuxUserland {
    type GuestVectorState = GuestVectorState;

    fn get_guest_vector_state(&self) -> GuestVectorState {
        let block: usize;
        unsafe {
            core::arch::asm!(
                load_tls_block_base!("{block}"),
                block = out(reg) block,
                options(nomem, nostack, preserves_flags)
            );
            ((block + tls_offset::GUEST_VECTOR_STATE) as *const GuestVectorState).read()
        }
    }

    fn set_guest_vector_state(&self, state: &GuestVectorState) {
        let block: usize;
        unsafe {
            core::arch::asm!(
                load_tls_block_base!("{block}"),
                block = out(reg) block,
                options(nomem, nostack, preserves_flags)
            );
            ((block + tls_offset::GUEST_VECTOR_STATE) as *mut GuestVectorState)
                .write(state.clone());
        }
    }
}

unsafe extern "C" {
    /// The compiler runtime's cache-synchronization helper: cleans the data
    /// cache to the point of unification and invalidates the instruction cache
    /// over `[start, end)`.
    fn __clear_cache(start: *mut core::ffi::c_char, end: *mut core::ffi::c_char);
}

/// Make code just written to `range` visible to the instruction fetch path,
/// before that range becomes executable.
///
/// AArch64's instruction cache is not architecturally coherent with the data
/// cache. Omitting this does not fail cleanly: the fetch path may see stale
/// bytes, intermittently and machine-dependently.
pub(super) fn sync_instruction_stream(range: core::ops::Range<usize>) {
    if range.start >= range.end {
        return;
    }
    // SAFETY: `range` is a mapped range this platform is changing permissions
    // on, so both ends are valid addresses within one mapping. `__clear_cache`
    // only performs cache maintenance over it and writes no memory.
    unsafe {
        __clear_cache(
            range.start as *mut core::ffi::c_char,
            range.end as *mut core::ffi::c_char,
        );
    }
}

// The canonical context must remain stack-backed: boxing here would allocate in
// a signal handler, violating the async-signal-safe contract.
#[allow(clippy::large_enum_variant)]
pub(super) enum Aarch64GateSignalResult {
    NotGate,
    Canonicalized(litebox_common_linux::PtRegs),
    #[cfg_attr(
        not(feature = "aarch64_virtualize_x18"),
        expect(
            dead_code,
            reason = "only the x18 indirect-branch gate resumes the guest transparently"
        )
    )]
    ResumeGuest(litebox_common_linux::PtRegs),
    PreserveSavedContext,
    InvalidRuntimeState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum GateInterruption {
    /// A hardware fault attributed to the current gate instruction.
    Synchronous,
    /// A synchronous breakpoint caused by the current gate instruction.
    Breakpoint,
    /// An independently delivered signal interrupting the gate.
    Asynchronous,
}

#[derive(Clone, Copy)]
struct GateRuntimeState {
    guest_thread_pointer_addr: usize,
    expected_outbound_stub: usize,
    expected_outbound_pc: usize,
}

fn read_usize(read: &mut impl FnMut(usize, &mut [u8]) -> bool, address: usize) -> Option<usize> {
    let mut bytes = [0u8; size_of::<usize>()];
    read(address, &mut bytes).then(|| usize::from_ne_bytes(bytes))
}

#[cfg(feature = "aarch64_virtualize_x18")]
fn recover_x18_frame(
    state: X18FrameState,
    signal_sp: usize,
    read: &mut impl FnMut(usize, &mut [u8]) -> bool,
) -> Option<(usize, Option<[usize; 2]>)> {
    let (frame_sp, restore_registers, pop_frame) = match state {
        X18FrameState::Absent => return Some((signal_sp, None)),
        X18FrameState::AtSpRegistersLive => (signal_sp, false, true),
        X18FrameState::AtSpRestoreRegisters => (signal_sp, true, true),
        X18FrameState::BelowSpRestoreRegisters => {
            let frame_sp = signal_sp.wrapping_sub(usize::from(X18_FRAME_BYTES));
            (frame_sp, true, false)
        }
    };
    let restored = if restore_registers {
        let mut frame = [[0u8; size_of::<usize>()]; 2];
        if !read(frame_sp, frame.as_flattened_mut()) {
            return None;
        }
        Some(frame.map(usize::from_ne_bytes))
    } else {
        None
    };
    let final_sp = if pop_frame {
        frame_sp.wrapping_add(usize::from(X18_FRAME_BYTES))
    } else {
        signal_sp
    };
    Some((final_sp, restored))
}

#[cfg(feature = "aarch64_virtualize_x18")]
fn apply_x18_recovery(
    canonical: &mut litebox_common_linux::PtRegs,
    scratch: u8,
    anchor_scratch: u8,
    restored_registers: Option<[usize; 2]>,
    guest_sp: usize,
    guest_x18: usize,
    resume_pc: usize,
) {
    if let Some([saved_scratch, saved_anchor]) = restored_registers {
        canonical.regs[usize::from(scratch)] = saved_scratch;
        canonical.regs[usize::from(anchor_scratch)] = saved_anchor;
    }
    canonical.sp = guest_sp;
    canonical.regs[18] = guest_x18;
    canonical.pc = resume_pc;
}

#[cfg(feature = "aarch64_virtualize_x18")]
fn resolve_x18_recovery_pc(
    resume: X18Resume,
    site: usize,
    guest_x18: usize,
    conditional_target: Option<u64>,
) -> Option<usize> {
    Some(match resume {
        X18Resume::Original => site,
        X18Resume::Next => site.wrapping_add(4),
        X18Resume::TakenTarget => conditional_target?.trunc(),
        X18Resume::LogicalX18 => guest_x18,
    })
}

/// Recognizes and canonicalizes an interrupted compact gate using only bounded,
/// caller-supplied reads. The signal-handler caller supplies exception-table
/// reads; tests supply synthetic mappings.
///
/// A candidate is accepted only if its metadata word, its exact instruction
/// template, and the inbound branch at its original site all agree. That is
/// what makes a range registry unnecessary. A guest that forges all three
/// changes only its own libOS semantics under LiteBox's threat model.
#[cfg(test)]
pub(super) fn canonicalize_aarch64_gate_signal_context(
    context: &libc::ucontext_t,
    saved: &litebox_common_linux::PtRegs,
    guest_thread_pointer_addr: usize,
    expected_outbound_stub: usize,
    expected_outbound_pc: usize,
    read: impl FnMut(usize, &mut [u8]) -> bool,
) -> Aarch64GateSignalResult {
    canonicalize_aarch64_gate_signal_context_with_kind(
        context,
        saved,
        GateRuntimeState {
            guest_thread_pointer_addr,
            expected_outbound_stub,
            expected_outbound_pc,
        },
        GateInterruption::Asynchronous,
        read,
    )
}

fn canonicalize_aarch64_gate_signal_context_with_kind(
    context: &libc::ucontext_t,
    saved: &litebox_common_linux::PtRegs,
    runtime: GateRuntimeState,
    interruption: GateInterruption,
    mut read: impl FnMut(usize, &mut [u8]) -> bool,
) -> Aarch64GateSignalResult {
    // Frame and slot sizes come from the rewriter; gate-local instruction
    // boundaries below follow each emitted template.
    const SVC_FRAME: usize = SVC_FRAME_BYTES as usize;
    const MSR_FRAME: usize = MSR_FRAME_BYTES as usize;
    let pc = context.uc_mcontext.pc;
    if !pc.is_multiple_of(4) {
        return Aarch64GateSignalResult::NotGate;
    }
    let pc: usize = pc.trunc();

    let aligned = pc & !(GATE_ALIGNMENT - 1);
    let mut found = None;
    for candidate_index in 0..GATE_PC_CANDIDATE_COUNT {
        let Some(slot_start) = aligned.checked_sub(candidate_index * GATE_ALIGNMENT) else {
            continue;
        };
        for slot_size in GATE_SLOT_SIZES {
            let Some(slot_end) = slot_start.checked_add(slot_size) else {
                continue;
            };
            if pc < slot_start || pc >= slot_end {
                continue;
            }
            let mut metadata_bytes = [0u8; 4];
            if !read(slot_end - 4, &mut metadata_bytes) {
                continue;
            }
            let Some(metadata) = litebox_syscall_rewriter::aarch64::decode_gate_metadata_word(
                u32::from_le_bytes(metadata_bytes),
            ) else {
                continue;
            };
            if metadata.slot_size() != slot_size {
                continue;
            }
            let mut slot = [0u8; SVC_SLOT_BYTES];
            if !read(slot_start, &mut slot[..slot_size]) {
                continue;
            }
            // Everything up to here is a guess drawn from guest memory: the
            // metadata word lives at `slot_end - 4`, which the guest can write.
            // Failing to validate is the evidence that this candidate is not a
            // gate, so it is discarded rather than treated as a corrupt one --
            // otherwise a guest could stage a plausible metadata word, fault at
            // a PC of its choosing and take the runtime down at will. This also
            // covers a PC in a real gate's padding or metadata: that code never
            // ran the prologue, so the interrupted registers are the guest's
            // own and delivering the signal unchanged is correct.
            let Some(classified) = litebox_syscall_rewriter::aarch64::classify_copied_gate_slot(
                &slot[..slot_size],
                slot_start as u64,
                pc as u64,
            ) else {
                continue;
            };
            if found.is_some() {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            found = Some((slot_start, classified));
        }
    }
    let Some((slot_start, gate)) = found else {
        return Aarch64GateSignalResult::NotGate;
    };

    // Guest-derived provenance failures are `NotGate`. Once a gate is
    // authenticated, unreadable state required to restore it is invalid.
    let site = gate.original_site();
    if !site.is_multiple_of(4) {
        return Aarch64GateSignalResult::NotGate;
    }
    let site: usize = site.trunc();
    let mut original = [0u8; 4];
    if !read(site, &mut original) {
        return Aarch64GateSignalResult::NotGate;
    }
    let original = u32::from_le_bytes(original);
    if litebox_syscall_rewriter::aarch64::decode_branch_target(original, site as u64)
        != Some(slot_start as u64)
    {
        return Aarch64GateSignalResult::NotGate;
    }

    let metadata = gate.metadata();
    let offset = pc - slot_start;
    if matches!(metadata, GateMetadata::Svc) && offset >= SVC_GATE_BYTES {
        return if runtime.expected_outbound_stub == slot_start + SVC_GATE_BYTES
            && runtime.expected_outbound_pc == site + 4
        {
            Aarch64GateSignalResult::PreserveSavedContext
        } else {
            Aarch64GateSignalResult::NotGate
        };
    }

    let mut canonical = saved.clone();
    copy_signal_context(&mut canonical, context);
    canonical.pc = site;

    // `copy_signal_context` derived `orig_x0` from the interrupted `regs[0]`,
    // which for `mrs x0, tpidr_el0` is the *host* anchor. Whatever the arms
    // below repair, re-derive it afterwards rather than leaving a host address
    // in a guest-visible field.
    match metadata {
        GateMetadata::MrsTpidr { destination, .. } => {
            let destination = usize::from(destination);
            let Some(stage) = MrsTpidrGateOffset::from_offset(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(recovery) = stage.recovery_plan() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if recovery.runtime_access == RuntimeAccess::Memory
                && interruption == GateInterruption::Synchronous
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            match recovery.value {
                MrsTpidrValueSource::Register => {}
                MrsTpidrValueSource::Slot => {
                    let Some(guest_tp) = read_usize(&mut read, runtime.guest_thread_pointer_addr)
                    else {
                        return Aarch64GateSignalResult::InvalidRuntimeState;
                    };
                    canonical.regs[destination] = guest_tp;
                }
            }
            if recovery.completed {
                canonical.pc = site + 4;
            }
        }
        GateMetadata::MsrTpidr { source, .. } => {
            let Some(stage) = MsrTpidrGateOffset::from_offset(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(recovery) = stage.recovery_plan() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if recovery.runtime_access == RuntimeAccess::Memory
                && interruption == GateInterruption::Synchronous
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            let restored = if recovery.frame == MsrTpidrFrameState::RestoreRegisters {
                let mut frame = [[0u8; size_of::<usize>()]; 3];
                if !read(canonical.sp, frame.as_flattened_mut()) {
                    return Aarch64GateSignalResult::NotGate;
                }
                let saved_x16 = usize::from_ne_bytes(frame[0]);
                let saved_x17 = usize::from_ne_bytes(frame[1]);
                let captured = usize::from_ne_bytes(frame[2]);
                let architectural_source = match source {
                    16 => saved_x16,
                    17 => saved_x17,
                    31 => 0,
                    register => canonical.regs[usize::from(register)],
                };
                if captured != architectural_source {
                    return Aarch64GateSignalResult::NotGate;
                }
                Some([saved_x16, saved_x17])
            } else {
                // Before commit, the staged value cheaply checks consistency
                // with the interrupted frame. After LDP at +28, recovery needs
                // neither the frame nor this check.
                if recovery.validate_capture {
                    let Some(captured) = read_usize(
                        &mut read,
                        canonical.sp.wrapping_add(usize::from(MSR_FRAME_OFF_VALUE)),
                    ) else {
                        return Aarch64GateSignalResult::NotGate;
                    };
                    let architectural_source = match source {
                        31 => 0,
                        register => canonical.regs[usize::from(register)],
                    };
                    if captured != architectural_source {
                        return Aarch64GateSignalResult::NotGate;
                    }
                }
                None
            };
            let guest_sp = match recovery.frame {
                MsrTpidrFrameState::Absent => canonical.sp,
                MsrTpidrFrameState::RegistersLive | MsrTpidrFrameState::RestoreRegisters => {
                    canonical.sp.wrapping_add(MSR_FRAME)
                }
            };
            if let Some([saved_x16, saved_x17]) = restored {
                canonical.regs[16] = saved_x16;
                canonical.regs[17] = saved_x17;
            }
            canonical.sp = guest_sp;
            if recovery.completed {
                canonical.pc = site + 4;
            }
        }
        GateMetadata::Svc => {
            let Some(stage) = SvcGateOffset::from_offset(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(plan) = stage.recovery_plan() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            // SVC uses a template-fixed literal; supported MRS/MSR execution
            // uses the permanent host anchor read by the gate itself.
            if plan.runtime_access == RuntimeAccess::Memory
                && interruption == GateInterruption::Synchronous
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            let saved_x16 = match plan.frame {
                SvcFrameState::NoFrame | SvcFrameState::FrameAtSpX16Live => None,
                SvcFrameState::RestoreX16FromFrame => {
                    let Some(saved_x16) = read_usize(&mut read, canonical.sp) else {
                        return Aarch64GateSignalResult::NotGate;
                    };
                    Some(saved_x16)
                }
            };
            let guest_sp = match plan.frame {
                SvcFrameState::NoFrame => canonical.sp,
                SvcFrameState::FrameAtSpX16Live | SvcFrameState::RestoreX16FromFrame => {
                    canonical.sp.wrapping_add(SVC_FRAME)
                }
            };
            if let Some(saved_x16) = saved_x16 {
                canonical.regs[16] = saved_x16;
            }
            canonical.sp = guest_sp;
        }
        #[cfg(feature = "aarch64_virtualize_x18")]
        GateMetadata::X18 { scratch } => {
            let Some(stage) = X18GateOffset::from_offset(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(plan) = stage.recovery_plan() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if plan.runtime_access == RuntimeAccess::Memory
                && interruption == GateInterruption::Synchronous
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            let Some((guest_sp, restored_registers)) =
                recover_x18_frame(plan.frame, canonical.sp, &mut read)
            else {
                return Aarch64GateSignalResult::NotGate;
            };
            let guest_x18 = match plan.value {
                X18ValueSource::Scratch => context.uc_mcontext.regs[usize::from(scratch)].trunc(),
                X18ValueSource::Slot => {
                    let Some(value) = read_usize(
                        &mut read,
                        runtime.guest_thread_pointer_addr
                            + litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP,
                    ) else {
                        return Aarch64GateSignalResult::InvalidRuntimeState;
                    };
                    value
                }
            };
            let Some(resume_pc) = resolve_x18_recovery_pc(plan.resume, site, guest_x18, None)
            else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            apply_x18_recovery(
                &mut canonical,
                scratch,
                gate.anchor_scratch().unwrap(),
                restored_registers,
                guest_sp,
                guest_x18,
                resume_pc,
            );
        }
        #[cfg(feature = "aarch64_virtualize_x18")]
        GateMetadata::X18CompareBranch { scratch } => {
            let Some(stage) = X18CompareBranchOffset::from_offset(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(plan) = stage.recovery_plan() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if plan.runtime_access == RuntimeAccess::Memory
                && interruption == GateInterruption::Synchronous
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            let Some((guest_sp, restored_registers)) =
                recover_x18_frame(plan.frame, canonical.sp, &mut read)
            else {
                return Aarch64GateSignalResult::NotGate;
            };
            let Some(guest_x18) = read_usize(
                &mut read,
                runtime.guest_thread_pointer_addr
                    + litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP,
            ) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(resume_pc) =
                resolve_x18_recovery_pc(plan.resume, site, guest_x18, gate.conditional_target())
            else {
                return Aarch64GateSignalResult::NotGate;
            };
            apply_x18_recovery(
                &mut canonical,
                scratch,
                gate.anchor_scratch().unwrap(),
                restored_registers,
                guest_sp,
                guest_x18,
                resume_pc,
            );
        }
        #[cfg(feature = "aarch64_virtualize_x18")]
        GateMetadata::X18Adr { scratch } => {
            let Some(stage) = X18AdrOffset::from_offset(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            let Some(plan) = stage.recovery_plan() else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if plan.runtime_access == RuntimeAccess::Memory
                && interruption == GateInterruption::Synchronous
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            let Some((guest_sp, restored_registers)) =
                recover_x18_frame(plan.frame, canonical.sp, &mut read)
            else {
                return Aarch64GateSignalResult::NotGate;
            };
            let guest_x18 = match plan.value {
                X18ValueSource::Scratch => context.uc_mcontext.regs[usize::from(scratch)].trunc(),
                X18ValueSource::Slot => {
                    let Some(value) = read_usize(
                        &mut read,
                        runtime.guest_thread_pointer_addr
                            + litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP,
                    ) else {
                        return Aarch64GateSignalResult::InvalidRuntimeState;
                    };
                    value
                }
            };
            let Some(resume_pc) = resolve_x18_recovery_pc(plan.resume, site, guest_x18, None)
            else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            apply_x18_recovery(
                &mut canonical,
                scratch,
                gate.anchor_scratch().unwrap(),
                restored_registers,
                guest_sp,
                guest_x18,
                resume_pc,
            );
        }
        #[cfg(feature = "aarch64_virtualize_x18")]
        GateMetadata::X18Branch { kind } => {
            let Some(plan) = x18_branch_recovery_plan(offset) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if plan.frame != X18FrameState::Absent
                || plan.value != X18ValueSource::Slot
                || plan.resume != X18Resume::LogicalX18
                || plan.runtime_access != RuntimeAccess::NoAccess
            {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            }
            let Some(guest_x18) = read_usize(
                &mut read,
                runtime.guest_thread_pointer_addr
                    + litebox_syscall_rewriter::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP,
            ) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            canonical.regs[18] = guest_x18;
            if interruption == GateInterruption::Breakpoint {
                if kind.writes_link_register() {
                    canonical.regs[30] = site.wrapping_add(4);
                }
                let Some(resume_pc) = resolve_x18_recovery_pc(plan.resume, site, guest_x18, None)
                else {
                    return Aarch64GateSignalResult::InvalidRuntimeState;
                };
                canonical.pc = resume_pc;
                canonical.orig_x0 = canonical.regs[0];
                return Aarch64GateSignalResult::ResumeGuest(canonical);
            }
        }
        #[cfg(not(feature = "aarch64_virtualize_x18"))]
        GateMetadata::X18 { .. }
        | GateMetadata::X18CompareBranch { .. }
        | GateMetadata::X18Adr { .. }
        | GateMetadata::X18Branch { .. } => return Aarch64GateSignalResult::NotGate,
    }
    canonical.orig_x0 = canonical.regs[0];
    Aarch64GateSignalResult::Canonicalized(canonical)
}

pub(super) fn canonicalize_runtime_aarch64_gate_signal_context(
    context: &libc::ucontext_t,
    saved: &litebox_common_linux::PtRegs,
    interruption: GateInterruption,
) -> Aarch64GateSignalResult {
    let block: usize;
    let expected_outbound_stub: usize;
    let expected_outbound_pc: usize;
    // SAFETY: reads the permanent host TLS anchor without touching memory.
    unsafe {
        core::arch::asm!(
            load_tls_block_base!("{block}"),
            block = out(reg) block,
            options(nostack, nomem, preserves_flags)
        );
        core::arch::asm!(
            "ldr {stub}, [{block}, #{stub_off}]",
            "ldr {pc}, [{block}, #{pc_off}]",
            block = in(reg) block,
            stub = out(reg) expected_outbound_stub,
            pc = out(reg) expected_outbound_pc,
            stub_off = const tls_offset::OUTBOUND_STUB,
            pc_off = const tls_offset::OUTBOUND_PC,
            options(nostack, readonly, preserves_flags)
        );
    }
    canonicalize_aarch64_gate_signal_context_with_kind(
        context,
        saved,
        GateRuntimeState {
            guest_thread_pointer_addr: block + tls_offset::GUEST_THREAD_POINTER,
            expected_outbound_stub,
            expected_outbound_pc,
        },
        interruption,
        |address, output| {
            // SAFETY: `output` is writable for its exact length. The source is
            // a guest-controlled address -- a gate slot, the original site,
            // this thread's `guest_thread_pointer` slot, or the guest `SP` --
            // so it may be unmapped or may alias host memory; it is read as raw
            // bytes through the exception table, never as a live Rust
            // reference. Faulting is expected rather than exceptional, and
            // reaching the fixup requires a re-entrant handler:
            // `exception_signal_handler` runs on `SA_NODEFER` for exactly this.
            // Recursion is bounded at one level, because the nested fault lands
            // on this load, which the table covers, and that lookup reads no
            // guest memory.
            unsafe {
                litebox::mm::exception_table::memcpy_fallible(
                    output.as_mut_ptr(),
                    address as *const u8,
                    output.len(),
                )
                .is_ok()
            }
        },
    )
}

/// Terminates after AArch64 transition recovery finds invalid runtime state,
/// such as ambiguous gates, unreadable runtime TLS, or malformed vector state.
pub(super) fn fatal_aarch64_runtime_state() -> ! {
    // SAFETY: `getpid`, `gettid`, `tgkill` and `exit_group` are
    // async-signal-safe, are admitted by this platform's seccomp filter, and
    // involve no formatting, allocation, locks or destructors.
    unsafe {
        let pid = syscalls::syscall0(syscalls::Sysno::getpid).unwrap_or(0);
        let tid = syscalls::syscall0(syscalls::Sysno::gettid).unwrap_or(0);
        for signal in [libc::SIGABRT, libc::SIGKILL] {
            let _ = syscalls::syscall3(
                syscalls::Sysno::tgkill,
                pid,
                tid,
                signal.cast_unsigned() as usize,
            );
        }
        core::arch::asm!(
            "mov x0, #{status}",
            "mov x8, #{nr}",
            "svc #0",
            status = const libc::EXIT_FAILURE,
            nr = const libc::SYS_exit_group,
            options(noreturn)
        );
    }
}

/// Clears `in_guest`, optionally sets `interrupt`, and optionally captures the
/// kernel-saved vector state. Returns the published guest context only if
/// `in_guest` was set; its registers may still require copying or gate
/// canonicalization. Invalid required vector state terminates the process.
pub(super) fn signal_handler_exit_guest(
    context: &libc::ucontext_t,
    set_interrupt: bool,
    capture_vector_state: bool,
) -> Option<*mut litebox_common_linux::PtRegs> {
    let block: usize;
    // SAFETY: materializes the base of this thread's TLS control block from
    // `TPIDR_EL0`, the host anchor even when this signal interrupted guest
    // code. Reads no memory.
    unsafe {
        core::arch::asm!(
            load_tls_block_base!("{0}"),
            out(reg) block,
            options(nostack, nomem, preserves_flags)
        );
    }
    // SAFETY: own-thread [`tls_offset`] slot accesses off `block`. Volatile
    // because the transition assembly also writes them, unseen by the compiler.
    unsafe {
        let in_guest = (block + tls_offset::IN_GUEST) as *mut u8;
        let was_in_guest = in_guest.read_volatile();
        in_guest.write_volatile(0);
        if set_interrupt {
            ((block + tls_offset::INTERRUPT) as *mut u8).write_volatile(1);
        }
        if was_in_guest == 0 {
            return None;
        }
        if capture_vector_state && !resume_frame::capture_signal_vector_state(context, block) {
            fatal_aarch64_runtime_state();
        }
        let top = ((block + tls_offset::GUEST_CONTEXT_TOP) as *const usize).read_volatile();
        Some((top as *mut litebox_common_linux::PtRegs).sub(1))
    }
}

pub(super) fn copy_signal_context(
    regs: &mut litebox_common_linux::PtRegs,
    context: &libc::ucontext_t,
) {
    let m = &context.uc_mcontext;
    for (dst, src) in regs.regs.iter_mut().zip(m.regs.iter()) {
        *dst = (*src).trunc();
    }
    #[cfg(feature = "aarch64_virtualize_x18")]
    {
        regs.regs[18] = get_guest_x18();
    }
    regs.sp = m.sp.trunc();
    regs.pc = m.pc.trunc();
    // Raw `m.pstate` carries privileged bits. Mask to the bits a guest may own,
    // so the shim sees the same set of bits however the context was produced.
    regs.pstate = m.pstate & litebox_common_linux::arch::SAFE_USER_PSTATE;
    regs.orig_x0 = regs.regs[0];
    // `PtRegs` is reused across guest entries, so a stale `syscallno` would
    // tell the shim a syscall is in flight during an exception or interrupt.
    regs.syscallno = litebox_common_linux::arch::NO_SYSCALL;
}

pub(super) fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize,
    p1: isize,
    p2: isize,
    p3: isize,
) {
    let m = &mut context.uc_mcontext;
    m.pc = f as usize as u64;
    // AAPCS64: first four integer arguments in x0-x3.
    m.regs[0] = p0.reinterpret_as_unsigned() as u64;
    m.regs[1] = p1.reinterpret_as_unsigned() as u64;
    m.regs[2] = p2.reinterpret_as_unsigned() as u64;
    m.regs[3] = p3.reinterpret_as_unsigned() as u64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;
    use litebox::platform::{RawMutexProvider, SystemInfoProvider as _};
    use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
    use litebox_common_linux::PtRegs;
    use litebox_common_linux::signal::{SigSet, Signal};

    #[test]
    fn test_gate_patching_lands_in_the_runtime_tls_block() {
        const IMM12_SHIFT: u32 = 10;
        const IMM12_MASK: u32 = 0x003F_FC00;
        const ALIGN: u16 = litebox_syscall_rewriter::aarch64::GUEST_TPIDR_OFFSET_ALIGN;

        let mut code = 0xD53B_D049u32.to_le_bytes(); // MRS X9, TPIDR_EL0
        let (mut tramp, trapped) =
            litebox_syscall_rewriter::patch_code_segment(&mut code, 0x1000, 0x400000, 0).unwrap();
        assert!(trapped.is_empty());
        assert_eq!(
            litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&tramp),
            Some(16 + 4),
            "the emitted gate must be in the unpatched state, or everything below \
             passes vacuously"
        );

        let platform = LinuxUserland::new();
        let offset = platform.guest_thread_pointer_offset().expect(
            "an AArch64 platform must supply a guest thread-pointer offset; without one the \
             loader leaves every gate on the placeholder, which does not fault",
        );
        let offset = u16::try_from(offset).expect("the guest slot must sit within a gate's reach");
        assert_eq!(
            litebox_syscall_rewriter::aarch64::patch_guest_tpidr_offset(&mut tramp, offset)
                .unwrap(),
            1
        );
        assert_eq!(
            litebox_syscall_rewriter::aarch64::find_guest_tpidr_placeholder(&tramp),
            None,
            "no gate may still hold the placeholder once the loader has staged the trampoline"
        );
        let classified =
            litebox_syscall_rewriter::aarch64::classify_gate_pc(&tramp, 0x400000, 0x400010)
                .expect("finalized emitted MRS slot must validate");
        assert_eq!(classified.slot_offset(), 16);
        assert!(matches!(
            classified.metadata(),
            litebox_syscall_rewriter::aarch64::GateMetadata::MrsTpidr { destination: 9, .. }
        ));

        let patched = u32::from_le_bytes(tramp[16 + 4..16 + 8].try_into().unwrap());
        let gate_offset = ((patched & IMM12_MASK) >> IMM12_SHIFT) as usize * usize::from(ALIGN);
        let tp: usize;
        // SAFETY: reads the thread pointer; touches no memory.
        unsafe {
            core::arch::asm!(
                "mrs {tp}, tpidr_el0",
                tp = out(reg) tp,
                options(nomem, nostack, preserves_flags)
            );
        }
        let gate_target = tp + gate_offset;

        // Compared against the slot's address as the *linker* resolves it, so
        // this is an independent check of the number rather than a restatement
        // of it.
        assert_eq!(
            gate_target,
            tp + tprel_offset!(litebox_tls_block) + tls_offset::GUEST_THREAD_POINTER,
            "a patched gate must dereference this thread's own `guest_thread_pointer` slot"
        );

        let block = tp + tprel_offset!(litebox_tls_block);
        let block_end = block + core::mem::size_of::<super::TlsBlock>();
        assert!(
            (block..block_end).contains(&gate_target),
            "gate dereferences {gate_target:#x}, outside the runtime TLS control block \
             {block:#x}..{block_end:#x}"
        );
    }

    /// Pins the `PtRegs` field offsets that the AArch64 transition assembly
    /// hardcodes. A field reorder or insertion in `litebox_common_linux`
    /// would otherwise silently corrupt the guest context.
    #[test]
    fn test_ptregs_layout() {
        assert_eq!(core::mem::size_of::<PtRegs>(), 288);
        assert_eq!(core::mem::align_of::<PtRegs>(), 16);
        assert_eq!(offset_of!(PtRegs, regs) + 16 * 8, 128);
        assert_eq!(offset_of!(PtRegs, sp), 248);
        assert_eq!(offset_of!(PtRegs, pc), 256);
        assert_eq!(offset_of!(PtRegs, pstate), 264);
        assert_eq!(offset_of!(PtRegs, orig_x0), 272);
        assert_eq!(offset_of!(PtRegs, syscallno), 280);
    }

    #[test]
    fn guest_vector_state_has_kernel_fpsimd_layout_and_zero_default() {
        let state = GuestVectorState::default();
        assert_eq!(core::mem::align_of::<GuestVectorState>(), 16);
        assert_eq!(core::mem::size_of::<GuestVectorState>(), 528);
        assert_eq!(core::mem::offset_of!(GuestVectorState, registers), 0);
        assert_eq!(core::mem::offset_of!(GuestVectorState, fpsr), 512);
        assert_eq!(core::mem::offset_of!(GuestVectorState, fpcr), 516);
        assert!(state.registers.iter().all(|register| *register == 0));
        assert_eq!(state.fpsr, 0);
        assert_eq!(state.fpcr, 0);
    }

    fn gate_fixture(
        original: u32,
    ) -> (
        Vec<u8>,
        Vec<u8>,
        libc::ucontext_t,
        litebox_common_linux::PtRegs,
    ) {
        let mut code = original.to_le_bytes().to_vec();
        let (trampoline, trapped) =
            litebox_syscall_rewriter::patch_code_segment(&mut code, 0x1000, 0x400000, 0).unwrap();
        assert!(trapped.is_empty());
        let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
        for (index, reg) in context.uc_mcontext.regs.iter_mut().enumerate() {
            *reg = 0xfeed_0000_0000_0000 | index as u64;
        }
        context.uc_mcontext.sp = 0x8000;
        // NZCV, plus bits a guest must never carry out of canonicalization:
        // `M[4]` (AArch32 execution state) and all of DAIF.
        context.uc_mcontext.pstate = 0xf000_0000 | (1 << 4) | (0xf << 6);
        let mut saved = litebox_common_linux::PtRegs::default();
        for (index, reg) in saved.regs.iter_mut().enumerate() {
            *reg = 0x6000_0000_0000_0000 | index;
        }
        saved.sp = 0x9000;
        saved.pc = 0x7000;
        (code, trampoline, context, saved)
    }

    fn fixture_reader<'a>(
        code: &'a [u8],
        trampoline: &'a [u8],
        frame: &'a [u8],
        guest_tp: &'a [u8],
    ) -> impl FnMut(usize, &mut [u8]) -> bool + 'a {
        move |address, output| {
            for (base, bytes) in [
                (0x1000usize, code),
                (0x400000, trampoline),
                (0x8000, frame),
                (0x500000, guest_tp),
            ] {
                if let Some(offset) = address.checked_sub(base)
                    && let Some(source) = bytes.get(offset..offset.saturating_add(output.len()))
                {
                    output.copy_from_slice(source);
                    return true;
                }
            }
            false
        }
    }

    fn expected_signal_regs(
        saved: &litebox_common_linux::PtRegs,
        context: &libc::ucontext_t,
    ) -> litebox_common_linux::PtRegs {
        let mut expected = saved.clone();
        for (destination, source) in expected.regs.iter_mut().zip(context.uc_mcontext.regs) {
            *destination = source.trunc();
        }
        #[cfg(feature = "aarch64_virtualize_x18")]
        {
            expected.regs[18] = get_guest_x18();
        }
        expected.sp = context.uc_mcontext.sp.trunc();
        expected.pc = context.uc_mcontext.pc.trunc();
        expected.pstate = context.uc_mcontext.pstate & litebox_common_linux::arch::SAFE_USER_PSTATE;
        expected.orig_x0 = expected.regs[0];
        expected.syscallno = litebox_common_linux::arch::NO_SYSCALL;
        expected
    }

    fn assert_ptregs_eq(
        actual: &litebox_common_linux::PtRegs,
        expected: &litebox_common_linux::PtRegs,
        stage: &str,
    ) {
        assert_eq!(actual.regs, expected.regs, "{stage}: GPRs");
        assert_eq!(actual.sp, expected.sp, "{stage}: SP");
        assert_eq!(actual.pc, expected.pc, "{stage}: PC");
        assert_eq!(actual.pstate, expected.pstate, "{stage}: PSTATE");
        // Independently of `SAFE_USER_PSTATE`: only the condition flags may
        // reach the guest from this fixture. Comparing against the masking
        // expression alone would still pass if the mask were widened.
        assert_eq!(
            actual.pstate & !0xf000_0000,
            0,
            "{stage}: PSTATE outside NZCV reached the guest"
        );
        assert_eq!(actual.orig_x0, expected.orig_x0, "{stage}: orig_x0");
        assert_eq!(actual.syscallno, expected.syscallno, "{stage}: syscallno");
        assert_eq!(actual.unused2, expected.unused2, "{stage}: unused2");
    }

    fn ptregs_bytes(
        regs: &litebox_common_linux::PtRegs,
    ) -> [u8; core::mem::size_of::<litebox_common_linux::PtRegs>()] {
        let mut bytes = [0; core::mem::size_of::<litebox_common_linux::PtRegs>()];
        // SAFETY: both regions are valid for exactly `size_of::<PtRegs>()`
        // bytes; reading padding is sound here because fixtures start zeroed.
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::from_ref(regs).cast::<u8>(),
                bytes.as_mut_ptr(),
                bytes.len(),
            );
        }
        bytes
    }

    #[test]
    fn gate_canonicalization_covers_every_emitted_instruction_boundary() {
        const HOST_ANCHOR: u64 = 0xfeed_f000_0000_0010;
        const HOST_CALLBACK: u64 = 0xfeed_f000_0000_0011;
        const TRAMPOLINE_ADDRESS: u64 = 0xfeed_f000_0000_0012;
        const GUEST_X16: usize = 0x1616_1616_1616_1616;
        const GUEST_X17: usize = 0x1717_1717_1717_1717;
        const ORIGINAL_PC: usize = 0x1000;
        const POST_PC: usize = 0x1004;
        const GUEST_SP: usize = 0x8020;
        const GUEST_TP: usize = 0x1234_5678_9abc_def0;
        const UPDATED_GUEST_TP: usize = 0x2345_6789_abcd_ef01;
        let guest_tp = GUEST_TP.to_le_bytes();

        let (code, trampoline, mut context, saved) = gate_fixture(0xd53b_d049);
        for offset in [0usize, 4, 8] {
            context.uc_mcontext.pc = 0x400010 + offset as u64;
            context.uc_mcontext.regs[9] = match offset {
                0 => saved.regs[9] as u64,
                4 => HOST_ANCHOR,
                8 => UPDATED_GUEST_TP as u64,
                _ => unreachable!(),
            };
            let mut reader = fixture_reader(&code, &trampoline, &[], &guest_tp);
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                move |address, output| {
                    (address != 0x500000 || offset != 8) && reader(address, output)
                },
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("MRS +{offset} did not canonicalize");
            };
            let mut expected = expected_signal_regs(&saved, &context);
            expected.pc = if offset == 0 { ORIGINAL_PC } else { POST_PC };
            expected.regs[9] = match offset {
                0 => saved.regs[9],
                4 => GUEST_TP,
                8 => UPDATED_GUEST_TP,
                _ => unreachable!(),
            };
            assert_ptregs_eq(&regs, &expected, &format!("MRS +{offset}"));
            assert!(!regs.regs.contains(&HOST_ANCHOR.trunc()));
        }

        let (code, trampoline, mut context, saved) = gate_fixture(0xd51b_d045);
        let mut saved = saved;
        saved.regs[16] = GUEST_X16;
        saved.regs[17] = GUEST_X17;
        let mut frame = [0u8; 32];
        frame[0..8].copy_from_slice(&(saved.regs[16] as u64).to_le_bytes());
        frame[8..16].copy_from_slice(&(saved.regs[17] as u64).to_le_bytes());
        frame[16..24].copy_from_slice(&(saved.regs[5] as u64).to_le_bytes());
        for offset in (0usize..=32).step_by(4) {
            context.uc_mcontext.pc = 0x400010 + offset as u64;
            context.uc_mcontext.sp = if offset == 0 || offset >= 32 {
                0x8020
            } else {
                0x8000
            };
            context.uc_mcontext.regs[16] = if (16..28).contains(&offset) {
                HOST_ANCHOR
            } else {
                saved.regs[16] as u64
            };
            context.uc_mcontext.regs[17] = if (20..28).contains(&offset) {
                HOST_CALLBACK
            } else {
                saved.regs[17] as u64
            };
            context.uc_mcontext.regs[5] = saved.regs[5] as u64;
            let mut reader = fixture_reader(&code, &trampoline, &frame, &guest_tp);
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                move |address, output| {
                    (offset < 28 || address != 0x8000) && reader(address, output)
                },
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("MSR +{offset} did not canonicalize");
            };
            let mut expected = expected_signal_regs(&saved, &context);
            expected.pc = if offset <= 20 { ORIGINAL_PC } else { POST_PC };
            expected.sp = GUEST_SP;
            expected.regs[16] = saved.regs[16];
            expected.regs[17] = saved.regs[17];
            assert_ptregs_eq(&regs, &expected, &format!("MSR +{offset}"));
            assert!(!regs.regs.contains(&HOST_ANCHOR.trunc()));
            assert!(!regs.regs.contains(&HOST_CALLBACK.trunc()));
        }

        let (code, trampoline, mut context, saved) = gate_fixture(0xd400_0001);
        let mut saved = saved;
        saved.regs[16] = GUEST_X16;
        saved.regs[17] = GUEST_X17;
        let mut frame = [0u8; 32];
        frame[0..8].copy_from_slice(&(saved.regs[16] as u64).to_le_bytes());
        let saved_before = ptregs_bytes(&saved);
        for offset in (0usize..=44).step_by(4) {
            context.uc_mcontext.pc = 0x400010 + offset as u64;
            context.uc_mcontext.sp = if offset == 0 { 0x8020 } else { 0x8000 };
            context.uc_mcontext.regs[16] = if offset <= 8 {
                saved.regs[16] as u64
            } else if (20..28).contains(&offset) {
                TRAMPOLINE_ADDRESS
            } else if offset >= 28 {
                HOST_CALLBACK
            } else {
                0x1004
            };
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0x400010 + 36,
                0x1004,
                fixture_reader(&code, &trampoline, &frame, &guest_tp),
            );
            if offset >= 36 {
                assert!(matches!(
                    result,
                    Aarch64GateSignalResult::PreserveSavedContext
                ));
                assert_eq!(ptregs_bytes(&saved), saved_before, "SVC outbound +{offset}");
            } else {
                let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                    panic!("SVC +{offset} did not canonicalize");
                };
                let mut expected = expected_signal_regs(&saved, &context);
                expected.pc = ORIGINAL_PC;
                expected.sp = GUEST_SP;
                expected.regs[16] = saved.regs[16];
                assert_ptregs_eq(&regs, &expected, &format!("SVC +{offset}"));
                assert!(!regs.regs.contains(&HOST_CALLBACK.trunc()));
                assert!(!regs.regs.contains(&TRAMPOLINE_ADDRESS.trunc()));
            }
        }

        for offset in [36usize, 40, 44] {
            context.uc_mcontext.pc = 0x400010 + offset as u64;
            for (stub, pc) in [(0, 0x1004), (0x400010 + 36, 0), (0x400010 + 36, 0x2004)] {
                let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                    &context,
                    &saved,
                    0x500000,
                    stub,
                    pc,
                    fixture_reader(&code, &trampoline, &frame, &guest_tp),
                );
                assert!(matches!(result, Aarch64GateSignalResult::NotGate));
            }
        }
    }

    #[test]
    #[cfg(feature = "aarch64_virtualize_x18")]
    fn x18_gate_canonicalization_boundary_table() {
        const SITE: usize = 0x1000;
        const SLOT: usize = 0x400010;
        const FRAME: usize = 0x8000;
        const GUEST_SP: usize = FRAME + 16;
        const LOGICAL_BEFORE: usize = 0x1818_1818_1818_1818;
        const LOGICAL_AFTER: usize = 0x2828_2828_2828_2828;
        const SAVED_SCRATCH: usize = 0x1717_1717_1717_1717;
        const SAVED_ANCHOR: usize = 0x1616_1616_1616_1616;
        const SAVED_X30: usize = 0x3030_3030_3030_3030;
        const NZCV_BEFORE: usize = 0x4000_0000;
        const NZCV_AFTER: usize = 0x8000_0000;

        let options = litebox_syscall_rewriter::RewriteOptions::new(
            litebox_syscall_rewriter::TargetHost::Linux,
            true,
        );
        let mut code = 0xaa12_03f2u32.to_le_bytes().to_vec(); // mov x18, x18
        let (trampoline, _) = litebox_syscall_rewriter::patch_code_segment_with_options(
            &mut code,
            SITE as u64,
            0x400000,
            0,
            options,
        )
        .unwrap();

        let mut saved = PtRegs::default();
        saved.regs[16] = SAVED_ANCHOR;
        saved.regs[17] = SAVED_SCRATCH;
        saved.regs[30] = SAVED_X30;
        let mut frame = [0u8; 16];
        frame[0..8].copy_from_slice(&SAVED_SCRATCH.to_ne_bytes());
        frame[8..16].copy_from_slice(&SAVED_ANCHOR.to_ne_bytes());

        for (offset, after_transform, committed) in [
            (0, false, false),
            (4, false, false),
            (8, false, false),
            (12, false, false),
            (16, false, false),
            (20, false, false),
            (24, true, false),
            (28, true, false),
            (32, true, false),
            (36, true, true),
            (40, true, true),
        ] {
            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
            context.uc_mcontext.pc = (SLOT + offset) as u64;
            context.uc_mcontext.sp = if matches!(offset, 0 | 20 | 24 | 40) {
                GUEST_SP as u64
            } else {
                FRAME as u64
            };
            context.uc_mcontext.regs[16] = SAVED_ANCHOR as u64;
            context.uc_mcontext.regs[17] = if after_transform && offset != 40 {
                LOGICAL_AFTER as u64
            } else {
                SAVED_SCRATCH as u64
            };
            context.uc_mcontext.regs[30] = SAVED_X30 as u64;
            context.uc_mcontext.pstate = if after_transform {
                NZCV_AFTER as u64
            } else {
                NZCV_BEFORE as u64
            };
            let slot_value = if committed {
                LOGICAL_AFTER
            } else {
                LOGICAL_BEFORE
            };
            let mut slots = [0u8; 16];
            slots[8..].copy_from_slice(&slot_value.to_ne_bytes());
            let result = canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(&code, &trampoline, &frame, &slots),
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("x18 +{offset} did not canonicalize");
            };
            assert_eq!(
                regs.pc,
                if after_transform { SITE + 4 } else { SITE },
                "+{offset}: PC"
            );
            assert_eq!(regs.sp, GUEST_SP, "+{offset}: SP");
            assert_eq!(regs.regs[16], SAVED_ANCHOR, "+{offset}: anchor scratch");
            assert_eq!(regs.regs[17], SAVED_SCRATCH, "+{offset}: value scratch");
            assert_eq!(
                regs.regs[18],
                if after_transform {
                    LOGICAL_AFTER
                } else {
                    LOGICAL_BEFORE
                },
                "+{offset}: logical x18"
            );
            assert_eq!(regs.regs[30], SAVED_X30, "+{offset}: x30");
            assert_eq!(
                regs.pstate,
                if after_transform {
                    NZCV_AFTER as u64
                } else {
                    NZCV_BEFORE as u64
                },
                "+{offset}: NZCV"
            );
        }

        for (offset, signal_sp, frame_address, expected_sp) in [
            (20usize, 8usize, 8usize.wrapping_sub(16), 8usize),
            (24, 8, 8usize.wrapping_sub(16), 8),
            (
                8,
                usize::MAX.wrapping_sub(15),
                usize::MAX.wrapping_sub(15),
                0,
            ),
        ] {
            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
            context.uc_mcontext.pc = (SLOT + offset) as u64;
            context.uc_mcontext.sp = signal_sp as u64;
            context.uc_mcontext.regs[16] = SAVED_ANCHOR as u64;
            context.uc_mcontext.regs[17] = SAVED_SCRATCH as u64;
            let mut slots = [0u8; 16];
            slots[8..].copy_from_slice(&LOGICAL_BEFORE.to_ne_bytes());
            let mut reader = fixture_reader(&code, &trampoline, &[], &slots);
            let result = canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                move |address, output| {
                    if address == frame_address && output.len() == frame.len() {
                        output.copy_from_slice(&frame);
                        true
                    } else {
                        reader(address, output)
                    }
                },
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("x18 +{offset} rejected wrapped frame arithmetic");
            };
            assert_eq!(regs.sp, expected_sp, "+{offset}: SP");
            assert_eq!(regs.regs[16], SAVED_ANCHOR, "+{offset}: anchor scratch");
            assert_eq!(regs.regs[17], SAVED_SCRATCH, "+{offset}: value scratch");
        }

        for offset in [8usize, 32] {
            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
            context.uc_mcontext.pc = (SLOT + offset) as u64;
            context.uc_mcontext.sp = FRAME as u64;
            context.uc_mcontext.regs[16] = SAVED_ANCHOR as u64;
            context.uc_mcontext.regs[17] = LOGICAL_AFTER as u64;
            let result = canonicalize_aarch64_gate_signal_context_with_kind(
                &context,
                &saved,
                GateRuntimeState {
                    guest_thread_pointer_addr: 0x500000,
                    expected_outbound_stub: 0,
                    expected_outbound_pc: 0,
                },
                GateInterruption::Synchronous,
                fixture_reader(&code, &trampoline, &frame, &[0; 16]),
            );
            assert!(matches!(
                result,
                Aarch64GateSignalResult::InvalidRuntimeState
            ));
        }

        for (offset, sp, slot_value) in [
            (0usize, 8usize, LOGICAL_BEFORE),
            (40, GUEST_SP, LOGICAL_AFTER),
        ] {
            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
            context.uc_mcontext.pc = (SLOT + offset) as u64;
            context.uc_mcontext.sp = sp as u64;
            context.uc_mcontext.regs[16] = SAVED_ANCHOR as u64;
            context.uc_mcontext.regs[17] = SAVED_SCRATCH as u64;
            let mut slots = [0u8; 16];
            slots[8..].copy_from_slice(&slot_value.to_ne_bytes());
            let result = canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &slots),
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("x18 +{offset} required a nonexistent frame");
            };
            assert_eq!(regs.sp, sp);
            assert_eq!(regs.regs[18], slot_value);
        }

        let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
        context.uc_mcontext.pc = (SLOT + 12) as u64;
        context.uc_mcontext.sp = FRAME as u64;
        let result = canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            0x500000,
            0,
            0,
            fixture_reader(&code, &trampoline, &[], &[0; 16]),
        );
        assert!(matches!(result, Aarch64GateSignalResult::NotGate));
    }

    #[test]
    #[cfg(feature = "aarch64_virtualize_x18")]
    fn indirect_x18_gates_resume_with_the_expected_link_register() {
        const SITE: usize = 0x1000;
        const SLOT: usize = 0x400010;
        const LOGICAL_X18: usize = 0x1234_5678_9abc_def0;
        let options = litebox_syscall_rewriter::RewriteOptions::new(
            litebox_syscall_rewriter::TargetHost::Linux,
            true,
        );
        for (word, name, writes_link) in [
            (0xd61f_0240u32, "BR X18", false),
            (0xd63f_0240, "BLR X18", true),
            (0xd65f_0240, "RET X18", false),
        ] {
            let mut code = word.to_le_bytes().to_vec();
            let (trampoline, trapped) = litebox_syscall_rewriter::patch_code_segment_with_options(
                &mut code,
                SITE as u64,
                0x400000,
                0,
                options,
            )
            .unwrap();
            assert!(trapped.is_empty());

            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
            for (index, reg) in context.uc_mcontext.regs.iter_mut().enumerate() {
                *reg = 0xfeed_0000_0000_0000 | index as u64;
            }
            context.uc_mcontext.pc = SLOT as u64;
            context.uc_mcontext.sp = 0x8000;
            context.uc_mcontext.pstate = 0xa000_0000;
            let saved = PtRegs::default();
            let mut slots = [0u8; 16];
            slots[8..].copy_from_slice(&LOGICAL_X18.to_ne_bytes());

            let result = canonicalize_aarch64_gate_signal_context_with_kind(
                &context,
                &saved,
                GateRuntimeState {
                    guest_thread_pointer_addr: 0x500000,
                    expected_outbound_stub: 0,
                    expected_outbound_pc: 0,
                },
                GateInterruption::Breakpoint,
                fixture_reader(&code, &trampoline, &[], &slots),
            );
            let Aarch64GateSignalResult::ResumeGuest(regs) = result else {
                panic!("{name} trap gate did not request a transparent resume");
            };
            let mut expected = expected_signal_regs(&saved, &context);
            expected.pc = LOGICAL_X18;
            expected.regs[18] = LOGICAL_X18;
            if writes_link {
                expected.regs[30] = SITE + 4;
            }
            assert_ptregs_eq(&regs, &expected, name);

            let result = canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &slots),
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("asynchronous signal at {name} gate did not retry the guest branch");
            };
            assert_eq!(regs.pc, SITE);
            assert_eq!(regs.regs[18], LOGICAL_X18);
        }
    }

    #[test]
    #[cfg(feature = "aarch64_virtualize_x18")]
    fn breakpoint_at_ordinary_x18_gate_uses_normal_recovery() {
        const SITE: usize = 0x1000;
        const SLOT: usize = 0x400010;
        const LOGICAL_X18: usize = 0x1818;
        let options = litebox_syscall_rewriter::RewriteOptions::new(
            litebox_syscall_rewriter::TargetHost::Linux,
            true,
        );
        let mut code = 0xaa12_03f2u32.to_le_bytes().to_vec(); // mov x18, x18
        let (trampoline, trapped) = litebox_syscall_rewriter::patch_code_segment_with_options(
            &mut code,
            SITE as u64,
            0x400000,
            0,
            options,
        )
        .unwrap();
        assert!(trapped.is_empty());
        let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
        context.uc_mcontext.pc = SLOT as u64;
        context.uc_mcontext.sp = 0x8000;
        let saved = PtRegs::default();
        let mut slots = [0u8; 16];
        slots[8..].copy_from_slice(&LOGICAL_X18.to_ne_bytes());

        let result = canonicalize_aarch64_gate_signal_context_with_kind(
            &context,
            &saved,
            GateRuntimeState {
                guest_thread_pointer_addr: 0x500000,
                expected_outbound_stub: 0,
                expected_outbound_pc: 0,
            },
            GateInterruption::Breakpoint,
            fixture_reader(&code, &trampoline, &[], &slots),
        );
        let Aarch64GateSignalResult::Canonicalized(regs) = result else {
            panic!("breakpoint changed ordinary x18 gate recovery");
        };
        assert_eq!(regs.pc, SITE);
        assert_eq!(regs.regs[18], LOGICAL_X18);
    }

    #[test]
    #[cfg(feature = "aarch64_virtualize_x18")]
    fn cbnz_w18_gate_canonicalizes_fallthrough_and_taken_paths() {
        const SITE: usize = 0x1000;
        const SLOT: usize = 0x400010;
        const FRAME: usize = 0x8000;
        let options = litebox_syscall_rewriter::RewriteOptions::new(
            litebox_syscall_rewriter::TargetHost::Linux,
            true,
        );
        let mut code = 0x3500_0332u32.to_le_bytes().to_vec();
        let (trampoline, _) = litebox_syscall_rewriter::patch_code_segment_with_options(
            &mut code,
            SITE as u64,
            0x400000,
            0,
            options,
        )
        .unwrap();

        let mut saved = PtRegs::default();
        saved.regs[16] = 0x1616;
        saved.regs[17] = 0x1717;
        let mut frame = [0u8; 16];
        frame[..8].copy_from_slice(&saved.regs[17].to_ne_bytes());
        frame[8..].copy_from_slice(&saved.regs[16].to_ne_bytes());

        for (logical, path_offset, expected_pc) in
            [(0usize, 20usize, SITE + 4), (1usize, 32usize, SITE + 0x64)]
        {
            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
            context.uc_mcontext.pc = (SLOT + path_offset) as u64;
            context.uc_mcontext.sp = FRAME as u64;
            let mut slots = [0u8; 16];
            slots[8..].copy_from_slice(&logical.to_ne_bytes());
            let result = canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(&code, &trampoline, &frame, &slots),
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("CBNZ W18 path +{path_offset} did not canonicalize");
            };
            assert_eq!(regs.pc, expected_pc);
            assert_eq!(regs.sp, FRAME + 16);
            assert_eq!(regs.regs[16], saved.regs[16]);
            assert_eq!(regs.regs[17], saved.regs[17]);
            assert_eq!(regs.regs[18], logical);
        }

        for (logical, path_offset, sp, expected_pc) in [
            (0usize, 24usize, FRAME, SITE + 4),
            (0, 28, FRAME + 16, SITE + 4),
            (1, 36, FRAME, SITE + 0x64),
            (1, 40, FRAME + 16, SITE + 0x64),
        ] {
            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
            context.uc_mcontext.pc = (SLOT + path_offset) as u64;
            context.uc_mcontext.sp = sp as u64;
            context.uc_mcontext.regs[16] = saved.regs[16] as u64;
            context.uc_mcontext.regs[17] = saved.regs[17] as u64;
            let mut slots = [0u8; 16];
            slots[8..].copy_from_slice(&logical.to_ne_bytes());
            let result = canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &slots),
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("CBNZ W18 +{path_offset} required an already-consumed frame");
            };
            assert_eq!(regs.pc, expected_pc);
            assert_eq!(regs.sp, FRAME + 16);
            assert_eq!(regs.regs[16], saved.regs[16]);
            assert_eq!(regs.regs[17], saved.regs[17]);
            assert_eq!(regs.regs[18], logical);
        }
    }

    #[test]
    #[cfg(feature = "aarch64_virtualize_x18")]
    fn adr_x18_gate_canonicalization_boundary_table() {
        const SITE: usize = 0x1000;
        const SLOT: usize = 0x400010;
        const FRAME: usize = 0x8000;
        const GUEST_SP: usize = FRAME + 16;
        const TARGET: usize = SITE + 12;
        const GUEST_X18_BEFORE: usize = 0x1818_1818_1818_1818;

        let options = litebox_syscall_rewriter::RewriteOptions::new(
            litebox_syscall_rewriter::TargetHost::Linux,
            true,
        );
        let mut code = 0x1000_0072u32.to_le_bytes().to_vec(); // adr x18, +0xc
        let (trampoline, _) = litebox_syscall_rewriter::patch_code_segment_with_options(
            &mut code,
            SITE as u64,
            0x400000,
            0,
            options,
        )
        .unwrap();

        let mut saved = PtRegs::default();
        saved.regs[16] = 0x1616;
        saved.regs[17] = 0x1717;
        let mut frame = [0u8; 16];
        frame[..8].copy_from_slice(&saved.regs[17].to_ne_bytes());
        frame[8..].copy_from_slice(&saved.regs[16].to_ne_bytes());

        for offset in (0usize..=24).step_by(4) {
            let completed = offset >= 16;
            let frame_exists = !matches!(offset, 0 | 24);
            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
            context.uc_mcontext.pc = (SLOT + offset) as u64;
            context.uc_mcontext.sp = if frame_exists {
                FRAME as u64
            } else {
                GUEST_SP as u64
            };
            context.uc_mcontext.regs[16] = saved.regs[16] as u64;
            context.uc_mcontext.regs[17] = if offset == 16 {
                TARGET as u64
            } else {
                saved.regs[17] as u64
            };
            let mut slots = [0u8; 16];
            slots[8..].copy_from_slice(
                &(if offset >= 20 {
                    TARGET
                } else {
                    GUEST_X18_BEFORE
                })
                .to_ne_bytes(),
            );
            let result = canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(
                    &code,
                    &trampoline,
                    if frame_exists { &frame } else { &[] },
                    &slots,
                ),
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("ADR x18 +{offset} did not canonicalize");
            };
            assert_eq!(regs.pc, if completed { SITE + 4 } else { SITE });
            assert_eq!(regs.sp, GUEST_SP);
            assert_eq!(regs.regs[16], saved.regs[16]);
            assert_eq!(regs.regs[17], saved.regs[17]);
            assert_eq!(
                regs.regs[18],
                if completed { TARGET } else { GUEST_X18_BEFORE }
            );
        }
    }

    #[test]
    fn invalid_gate_runtime_state_never_mutates_saved_ptregs() {
        let (code, trampoline, mut context, saved) = gate_fixture(0xd51b_d045);
        context.uc_mcontext.pc = 0x400010 + 20;
        context.uc_mcontext.sp = 0x8000;
        context.uc_mcontext.regs[5] = saved.regs[5] as u64;
        let mut frame = [0u8; 24];
        frame[0..8].copy_from_slice(&(saved.regs[16] as u64).to_le_bytes());
        frame[8..16].copy_from_slice(&(saved.regs[17] as u64).to_le_bytes());
        frame[16..24].copy_from_slice(&(saved.regs[5] as u64).to_le_bytes());

        let before = ptregs_bytes(&saved);
        // Candidate, original-site, and guest-frame provenance failures are
        // `NotGate`. No failure may mutate the saved registers.
        for denied_address in [0x400010usize, 0x1000, 0x8000] {
            let mut reader = fixture_reader(&code, &trampoline, &frame, &[]);
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                move |address, output| address != denied_address && reader(address, output),
            );
            assert!(
                matches!(result, Aarch64GateSignalResult::NotGate),
                "denying {denied_address:#x} should be NotGate"
            );
            assert_eq!(
                ptregs_bytes(&saved),
                before,
                "denying {denied_address:#x} mutated saved PtRegs"
            );
        }

        let mut wrong_branch = code.clone();
        wrong_branch.copy_from_slice(&0x1400_0000u32.to_le_bytes());
        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            0x500000,
            0,
            0,
            fixture_reader(&wrong_branch, &trampoline, &frame, &[]),
        );
        assert!(matches!(result, Aarch64GateSignalResult::NotGate));
        assert_eq!(ptregs_bytes(&saved), before);

        let mut wrong_template = trampoline.clone();
        wrong_template[16 + 8..16 + 12].copy_from_slice(&0xd503_201fu32.to_le_bytes());
        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            0x500000,
            0,
            0,
            fixture_reader(&code, &wrong_template, &frame, &[]),
        );
        assert!(matches!(result, Aarch64GateSignalResult::NotGate));
        assert_eq!(ptregs_bytes(&saved), before);

        frame[16..24].copy_from_slice(&0xdead_beef_u64.to_le_bytes());
        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            0x500000,
            0,
            0,
            fixture_reader(&code, &trampoline, &frame, &[]),
        );
        assert!(matches!(result, Aarch64GateSignalResult::NotGate));
        assert_eq!(ptregs_bytes(&saved), before);

        context.uc_mcontext.pc = 0x400010 + 24;
        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            0x500000,
            0,
            0,
            fixture_reader(&code, &trampoline, &[], &[]),
        );
        assert!(matches!(result, Aarch64GateSignalResult::NotGate));
        assert_eq!(ptregs_bytes(&saved), before);
    }

    #[test]
    fn gate_classifier_and_provenance_negatives_are_failure_atomic() {
        let (code, trampoline, mut context, saved) = gate_fixture(0xd400_0001);
        let before = ptregs_bytes(&saved);
        let mut frame = [0u8; 32];
        frame[..8].copy_from_slice(&(saved.regs[16] as u64).to_ne_bytes());

        let assert_failure =
            |result: Aarch64GateSignalResult, expected_invalid: bool, label: &str| {
                if expected_invalid {
                    assert!(
                        matches!(result, Aarch64GateSignalResult::InvalidRuntimeState),
                        "{label}"
                    );
                } else {
                    assert!(
                        matches!(result, Aarch64GateSignalResult::NotGate),
                        "{label}"
                    );
                }
                assert_eq!(
                    ptregs_bytes(&saved),
                    before,
                    "{label}: saved PtRegs changed"
                );
            };

        for (pc, expected_invalid, label) in [
            (0x2000, false, "ordinary guest code"),
            (0x400011, false, "unaligned gate PC"),
            (0x400010 + 48, false, "SVC padding"),
            (0x400010 + 60, false, "SVC metadata"),
        ] {
            context.uc_mcontext.pc = pc;
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(&code, &trampoline, &frame, &[]),
            );
            assert_failure(result, expected_invalid, label);
        }

        // A template that does not validate is evidence the candidate is not
        // a gate, not evidence of a corrupt one: the metadata word that got it
        // this far is guest-writable, so treating a mismatch as fatal would
        // hand the guest a way to kill the runtime on demand.
        context.uc_mcontext.pc = 0x400010 + 8;
        context.uc_mcontext.sp = 0x8000;
        for (word_offset, label) in [
            (0usize, "bad first template word"),
            (28, "bad callback load"),
            (32, "bad inbound register branch"),
            (48, "bad padding word"),
        ] {
            let mut mutated = trampoline.clone();
            mutated[16 + word_offset..16 + word_offset + 4].copy_from_slice(&0u32.to_le_bytes());
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(&code, &mutated, &frame, &[]),
            );
            assert_failure(result, false, label);
        }

        let mut bad_metadata = trampoline.clone();
        bad_metadata[16 + 60] ^= 0x80;
        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            0x500000,
            0,
            0,
            fixture_reader(&code, &bad_metadata, &frame, &[]),
        );
        assert_failure(result, false, "bad metadata");

        for (branch, label) in [
            (0x940f_fc04u32, "inbound BL opcode"),
            (0xd61f_0200, "inbound BR x16 opcode/register"),
            (0x1400_0001, "inbound B wrong target"),
        ] {
            let wrong_code = branch.to_le_bytes();
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(&wrong_code, &trampoline, &frame, &[]),
            );
            assert_failure(result, false, label);
        }

        // The reader is intentionally inconsistent: it presents one valid SVC
        // slot at each of two candidate starts. Candidate uniqueness must still
        // fail closed rather than selecting either one.
        let second_start = 0x400020usize;
        let second_pc = second_start + 8;
        let (_, second_slot, _, _) = gate_fixture(0xd400_0001);
        let mut second_slot = second_slot[16..80].to_vec();
        let first_slot = trampoline[16..80].to_vec();
        let mut source = 0xd400_0001u32.to_le_bytes();
        let (relocated, trapped) = litebox_syscall_rewriter::patch_code_segment(
            &mut source,
            0x1000,
            second_start as u64 - 16,
            0,
        )
        .unwrap();
        assert!(trapped.is_empty());
        second_slot.copy_from_slice(&relocated[16..80]);
        context.uc_mcontext.pc = second_pc as u64;
        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            0x500000,
            0,
            0,
            move |address, output| {
                let source = if address == 0x400010 && output.len() == 64 {
                    Some(first_slot.as_slice())
                } else if address == second_start && output.len() == 64 {
                    Some(second_slot.as_slice())
                } else if address == 0x400010 + 60 && output.len() == 4 {
                    Some(&first_slot[60..64])
                } else if address == second_start + 60 && output.len() == 4 {
                    Some(&second_slot[60..64])
                } else {
                    None
                };
                if let Some(source) = source {
                    output.copy_from_slice(source);
                    true
                } else {
                    false
                }
            },
        );
        assert_failure(result, true, "ambiguous candidates");

        // Gate stack arithmetic wraps exactly like the AArch64 ADD/SUB pair.
        context.uc_mcontext.pc = 0x400010 + 4;
        context.uc_mcontext.sp = u64::MAX - 15;
        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            0x500000,
            0,
            0,
            fixture_reader(&code, &trampoline, &frame, &[]),
        );
        let Aarch64GateSignalResult::Canonicalized(regs) = result else {
            panic!("wrapped SP did not canonicalize");
        };
        assert_eq!(regs.sp, 16);
    }

    #[test]
    fn unreadable_mrs_guest_tp_is_failure_atomic() {
        let (code, trampoline, mut context, saved) = gate_fixture(0xd53b_d049);
        context.uc_mcontext.pc = 0x400010 + 4;
        let before = (saved.regs, saved.sp, saved.pc, saved.pstate, saved.orig_x0);
        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            0x500000,
            0,
            0,
            fixture_reader(&code, &trampoline, &[], &[]),
        );
        assert!(matches!(
            result,
            Aarch64GateSignalResult::InvalidRuntimeState
        ));
        assert_eq!(
            (saved.regs, saved.sp, saved.pc, saved.pstate, saved.orig_x0),
            before
        );
    }

    #[test]
    fn gate_stage_reads_are_required_only_at_the_consuming_boundaries() {
        const GUEST_TP: usize = 0x1234_5678_9abc_def0;
        let guest_tp = GUEST_TP.to_ne_bytes();

        let (mrs_code, mrs_slot, mut context, saved) = gate_fixture(0xd53b_d049);
        for (offset, readable, canonical) in [
            (0usize, false, true),
            (4, false, false),
            (4, true, true),
            (8, false, true),
        ] {
            context.uc_mcontext.pc = 0x400010 + offset as u64;
            context.uc_mcontext.regs[9] = if offset == 8 {
                GUEST_TP as u64
            } else {
                0xfeed_f000_0000_0010
            };
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(
                    &mrs_code,
                    &mrs_slot,
                    &[],
                    if readable { &guest_tp } else { &[] },
                ),
            );
            assert_eq!(
                matches!(result, Aarch64GateSignalResult::Canonicalized(_)),
                canonical,
                "MRS +{offset}, guest TP readable={readable}"
            );
        }

        let (msr_code, msr_slot, mut context, saved) = gate_fixture(0xd51b_d045);
        let mut msr_frame = [0u8; 24];
        msr_frame[..8].copy_from_slice(&(saved.regs[16] as u64).to_ne_bytes());
        msr_frame[8..16].copy_from_slice(&(saved.regs[17] as u64).to_ne_bytes());
        msr_frame[16..].copy_from_slice(&(saved.regs[5] as u64).to_ne_bytes());
        for offset in (0usize..=32).step_by(4) {
            context.uc_mcontext.pc = 0x400010 + offset as u64;
            context.uc_mcontext.sp = if offset == 0 || offset == 32 {
                0x8020
            } else {
                0x8000
            };
            context.uc_mcontext.regs[5] = saved.regs[5] as u64;
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(&msr_code, &msr_slot, &[], &[]),
            );
            if matches!(offset, 0 | 4 | 8 | 28 | 32) {
                assert!(
                    matches!(result, Aarch64GateSignalResult::Canonicalized(_)),
                    "MSR +{offset} should not need the frame"
                );
            } else {
                assert!(
                    matches!(result, Aarch64GateSignalResult::NotGate),
                    "MSR +{offset} should require the frame"
                );
            }
        }
        context.uc_mcontext.pc = 0x400010 + 12;
        context.uc_mcontext.sp = 0x8000;
        context.uc_mcontext.regs[5] = saved.regs[5] as u64;
        let captured = saved.regs[5].to_ne_bytes();
        let mut reader = fixture_reader(&msr_code, &msr_slot, &[], &[]);
        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            0x500000,
            0,
            0,
            move |address, output| {
                if address == 0x8010 && output.len() == captured.len() {
                    output.copy_from_slice(&captured);
                    true
                } else {
                    reader(address, output)
                }
            },
        );
        let Aarch64GateSignalResult::Canonicalized(regs) = result else {
            panic!("MSR +12 required saved x16/x17");
        };
        assert_eq!(regs.regs[16], context.uc_mcontext.regs[16].trunc());
        assert_eq!(regs.regs[17], context.uc_mcontext.regs[17].trunc());
        assert_eq!(regs.sp, 0x8020);

        // The frame value is provenance before and after commit; changing it
        // must fail rather than reconstructing from scratch registers.
        msr_frame[16..].copy_from_slice(&0xdead_beef_dead_beefu64.to_ne_bytes());
        for offset in [12usize, 20, 24] {
            context.uc_mcontext.pc = 0x400010 + offset as u64;
            context.uc_mcontext.sp = 0x8000;
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(&msr_code, &msr_slot, &msr_frame, &[]),
            );
            assert!(
                matches!(result, Aarch64GateSignalResult::NotGate),
                "MSR +{offset} accepted a mutated capture"
            );
        }

        let (svc_code, svc_slot, mut context, saved) = gate_fixture(0xd400_0001);
        for offset in (0usize..=32).step_by(4) {
            context.uc_mcontext.pc = 0x400010 + offset as u64;
            context.uc_mcontext.sp = if offset == 0 { 0x8020 } else { 0x8000 };
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(&svc_code, &svc_slot, &[], &[]),
            );
            if matches!(offset, 0 | 4 | 8) {
                assert!(
                    matches!(result, Aarch64GateSignalResult::Canonicalized(_)),
                    "SVC +{offset} should not need the frame"
                );
            } else {
                assert!(
                    matches!(result, Aarch64GateSignalResult::NotGate),
                    "SVC +{offset} should require the frame"
                );
            }
        }

        let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
        let no_frame: &[u8] = &[];
        for (code, slot, offset, frame) in [
            (&mrs_code, &mrs_slot, 4usize, no_frame),
            (&msr_code, &msr_slot, 20, msr_frame.as_slice()),
            (&svc_code, &svc_slot, 28, no_frame),
        ] {
            context.uc_mcontext.pc = 0x400010 + offset as u64;
            context.uc_mcontext.sp = 0x8000;
            let result = canonicalize_aarch64_gate_signal_context_with_kind(
                &context,
                &saved,
                GateRuntimeState {
                    guest_thread_pointer_addr: 0x500000,
                    expected_outbound_stub: 0,
                    expected_outbound_pc: 0,
                },
                GateInterruption::Synchronous,
                fixture_reader(code, slot, frame, &guest_tp),
            );
            assert!(
                matches!(result, Aarch64GateSignalResult::InvalidRuntimeState),
                "gate +{offset} synchronous runtime access"
            );
        }

        for (code, slot) in [(&svc_code, &svc_slot), (&msr_code, &msr_slot)] {
            context.uc_mcontext.pc = 0x400010 + 4;
            context.uc_mcontext.sp = usize::MAX.wrapping_sub(31) as u64;
            let result = canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(code, slot, &[], &guest_tp),
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("gate failed to restore wrapped guest SP");
            };
            assert_eq!(regs.sp, 0);
        }
    }

    #[test]
    fn canonicalizer_rejects_mrs_xzr_metadata_without_indexing_x31() {
        let (code, mut trampoline, mut context, saved) = gate_fixture(0xd53b_d049);
        trampoline[28..32].copy_from_slice(&0x1f11_b807u32.to_le_bytes());
        context.uc_mcontext.pc = 0x400010;

        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            0x500000,
            0,
            0,
            fixture_reader(&code, &trampoline, &[], &[]),
        );
        assert!(matches!(result, Aarch64GateSignalResult::NotGate));
    }

    #[test]
    fn msr_special_sources_validate_the_captured_architectural_value() {
        for (source, expected) in [(16u8, 0x1616usize), (17, 0x1717), (31, 0)] {
            let original = 0xd51b_d040 | u32::from(source);
            let (code, trampoline, mut context, mut saved) = gate_fixture(original);
            saved.regs[16] = 0x1616;
            saved.regs[17] = 0x1717;
            context.uc_mcontext.pc = 0x400010 + 20;
            context.uc_mcontext.sp = 0x8000;
            let mut frame = [0u8; 24];
            frame[0..8].copy_from_slice(&0x1616u64.to_ne_bytes());
            frame[8..16].copy_from_slice(&0x1717u64.to_ne_bytes());
            frame[16..24].copy_from_slice(&(expected as u64).to_ne_bytes());

            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                0x500000,
                0,
                0,
                fixture_reader(&code, &trampoline, &frame, &[]),
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("MSR x{source} did not canonicalize");
            };
            assert_eq!(regs.regs[16], 0x1616);
            assert_eq!(regs.regs[17], 0x1717);
        }
    }

    fn tls_block_base() -> usize {
        let tp: usize;
        // SAFETY: reads the thread pointer; touches no memory.
        unsafe {
            core::arch::asm!(
                "mrs {tp}, tpidr_el0",
                tp = out(reg) tp,
                options(nomem, nostack, preserves_flags)
            );
        }
        tp + tprel_offset!(litebox_tls_block)
    }

    macro_rules! read_tls_slot {
        ($ty:ty, $offset:expr) => {{
            // SAFETY: this thread's own, naturally aligned slot.
            unsafe { ((tls_block_base() + $offset) as *const $ty).read_volatile() }
        }};
    }

    #[test]
    fn test_pending_host_signals_roundtrip() {
        let _ = super::take_pending_host_signals();
        assert_eq!(read_tls_slot!(u32, tls_offset::PENDING_HOST_SIGNALS), 0);

        // SAFETY: on AArch64 `record_pending_signal` has no precondition
        // beyond `TPIDR_EL0` being the host anchor, which it always is. The
        // waker slot is null on this thread (asserted below), so no waker is
        // dereferenced.
        assert_eq!(read_tls_slot!(usize, tls_offset::WAIT_WAKER_ADDR), 0);
        unsafe {
            super::record_pending_signal(Signal::SIGALRM);
            super::record_pending_signal(Signal::SIGINT);
        }

        let expected_bits =
            (1u32 << (Signal::SIGALRM.as_i32() - 1)) | (1u32 << (Signal::SIGINT.as_i32() - 1));
        assert_eq!(
            read_tls_slot!(u32, tls_offset::PENDING_HOST_SIGNALS),
            expected_bits,
            "record_pending_signal must OR into the slot, not overwrite it"
        );

        let taken = super::take_pending_host_signals();
        let expected = SigSet::empty().with(Signal::SIGALRM).with(Signal::SIGINT);
        assert_eq!(taken.as_u64(), expected.as_u64());
        assert!(taken.contains(Signal::SIGALRM));
        assert!(taken.contains(Signal::SIGINT));

        assert!(
            super::take_pending_host_signals().is_empty(),
            "take_pending_host_signals must clear the slot it read"
        );
        assert_eq!(read_tls_slot!(u32, tls_offset::PENDING_HOST_SIGNALS), 0);
    }

    #[test]
    fn test_update_waker_exchange() {
        let platform = LinuxUserland::new();
        let wait_state = litebox::event::wait::WaitState::new(platform);

        assert_eq!(read_tls_slot!(usize, tls_offset::WAIT_WAKER_ADDR), 0);

        platform.update_waker(Some(wait_state.context().waker().clone()));
        let first = read_tls_slot!(usize, tls_offset::WAIT_WAKER_ADDR);
        assert_ne!(first, 0, "update_waker must publish the boxed waker");

        platform.update_waker(Some(wait_state.context().waker().clone()));
        let second = read_tls_slot!(usize, tls_offset::WAIT_WAKER_ADDR);
        assert_ne!(second, 0);

        platform.update_waker(None);
        assert_eq!(
            read_tls_slot!(usize, tls_offset::WAIT_WAKER_ADDR),
            0,
            "update_waker(None) must clear the slot"
        );
    }

    /// Unwinds a panic out of a shim handler, through `run_thread_arch`'s
    /// frame, and catches it on the other side.
    ///
    /// `run_thread_arch`'s CFI is hand-written and nothing else checks it.
    /// Reaching the `catch_unwind` requires the unwinder to resolve the CFA
    /// rule correctly; a bad rule aborts the process, so a green run is the
    /// assertion. Covers the `init_handler` entry only — the other three need
    /// real guest code.
    #[test]
    fn test_unwind_through_run_thread_arch() {
        struct PanickingShim;

        impl EnterShim for PanickingShim {
            type ExecutionContext = PtRegs;
            fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                panic!("unwind out of init_handler");
            }
            fn syscall(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }
            fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
                unreachable!()
            }
            fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }
        }

        let result = std::panic::catch_unwind(|| {
            let mut ctx = PtRegs::default();
            // SAFETY: the shim panics out of `init` before the context is ever
            // used to enter the guest, so no valid guest state is required.
            unsafe { super::run_thread(PanickingShim, &mut ctx) };
        });

        assert!(result.is_err(), "the panic must propagate to the caller");
        assert!(
            !super::is_guest_thread(),
            "unwinding must run `GuestThreadMarker`'s drop"
        );
    }

    #[test]
    fn test_guest_thread_marker() {
        assert!(!is_guest_thread(), "a plain test thread is not a guest");

        {
            let _outer = GuestThreadMarker::enter();
            assert!(is_guest_thread());
            {
                let _inner = GuestThreadMarker::enter();
                assert!(is_guest_thread());
            }
            assert!(
                is_guest_thread(),
                "dropping a nested marker must not un-mark the thread while \
                 an outer frame is still running the guest"
            );
        }
        assert!(!is_guest_thread(), "the outermost marker must restore");

        let result = std::panic::catch_unwind(|| {
            let _marker = GuestThreadMarker::enter();
            assert!(is_guest_thread());
            panic!("unwind out of guest execution");
        });
        assert!(result.is_err());
        assert!(
            !is_guest_thread(),
            "the marker must be restored when the guest frame unwinds"
        );
    }

    /// The staging store must carry an exception-table fixup, or a fault on it
    /// escapes into `exception_signal_handler` with `in_guest == 1` and is
    /// mistaken for a guest fault; see [`switch_to_guest_via_outbound_stub`].
    #[test]
    fn test_switch_to_guest_stage_x16_has_exception_fixup() {
        let stage = super::switch_to_guest_stage_x16 as *const () as usize;
        let fixup = super::switch_to_guest_stage_x16_fixup as *const () as usize;
        assert_eq!(
            litebox::mm::exception_table::search_exception_tables(stage),
            Some(fixup),
            "the guest-stack staging store must be recoverable in place"
        );
    }

    #[test]
    fn asynchronous_sigsegv_does_not_use_exception_fixup() {
        let stage = super::switch_to_guest_stage_x16 as *const () as usize;
        assert_eq!(
            super::signal_exception_fixup(libc::SIGSEGV, libc::SI_USER, stage),
            None
        );
    }

    /// A SIGSEGV on that store must not be attributed to the guest.
    ///
    /// `in_guest` is already 1 at the fault, so without the fixup and the
    /// `switch_to_guest` guard the handler would overwrite the guest `PtRegs`
    /// with the host register file. Asserts that the guest context is
    /// untouched, `in_guest` is left alone, and the context is redirected to
    /// the fixup.
    #[test]
    fn test_exception_on_guest_stack_store_does_not_leak_host_state() {
        const SEGV_MAPERR: libc::c_int = 1;

        let stage = super::switch_to_guest_stage_x16 as *const () as usize;
        let fixup = super::switch_to_guest_stage_x16_fixup as *const () as usize;

        let mut guest = std::boxed::Box::new(PtRegs::default());
        for (i, r) in guest.regs.iter_mut().enumerate() {
            *r = 0x6d05_7000_0000_0000 | i;
        }
        guest.sp = 0x6d05_7000_5000_0000;
        guest.pc = 0x6d05_7000_6000_0000;
        let before = std::format!("{guest:?}");

        let in_guest = (tls_block_base() + tls_offset::IN_GUEST) as *mut u8;
        let context_top = (tls_block_base() + tls_offset::GUEST_CONTEXT_TOP) as *mut usize;

        // SAFETY: both are this thread's own naturally aligned TLS slots, and
        // nothing else on this thread is in guest execution, so publishing a
        // synthetic context here cannot be observed by anything but the call
        // below. Both are restored before the assertions.
        unsafe {
            context_top.write_volatile((&raw mut *guest).add(1) as usize);
            in_guest.write_volatile(1);
        }

        let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
        let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
        info.si_code = SEGV_MAPERR;
        for (i, r) in context.uc_mcontext.regs.iter_mut().enumerate() {
            *r = 0xffff_0000_0000_0000 | i as u64;
        }
        context.uc_mcontext.pc = stage as u64;
        context.uc_mcontext.sp = 0xffff_0000_5000_0000;
        context.uc_mcontext.fault_address = 0xffff_0000_5000_0000;

        // SAFETY: `exception_signal_handler`'s contract is a signal number and
        // the two pointers a `SA_SIGINFO` handler receives; both are valid
        // here. It is reentrant with respect to this thread's TLS block, which
        // is the only state it touches besides the context it is handed.
        unsafe { super::exception_signal_handler(libc::SIGSEGV, &mut info, &mut context) };

        // SAFETY: as above.
        let was_in_guest = unsafe {
            let was = in_guest.read_volatile();
            in_guest.write_volatile(0);
            context_top.write_volatile(0);
            was
        };

        assert_eq!(
            std::format!("{guest:?}"),
            before,
            "a fault on the guest-stack staging store must not overwrite the guest context \
             with host register state"
        );
        assert_eq!(
            was_in_guest, 1,
            "the fault is a host fault recovered in place, so the thread is still on its way \
             into the guest and `in_guest` must stay set"
        );
        let fixed_pc: usize = context.uc_mcontext.pc.trunc();
        assert_eq!(
            fixed_pc, fixup,
            "the signal context must be redirected to the store's fixup, not to \
             `exception_callback`"
        );
    }
}
