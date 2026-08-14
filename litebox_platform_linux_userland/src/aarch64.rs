// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 guest/host transitions and signal recovery. `TPIDR_EL0` remains the
//! host anchor; the guest thread pointer is virtualized in memory.

use super::*;
use litebox_syscall_rewriter::aarch64::{
    GATE_ALIGNMENT, GateMetadata, MRS_SLOT_BYTES, MSR_FRAME_BYTES, MSR_SLOT_BYTES, SVC_FRAME_BYTES,
    SVC_GATE_BYTES, SVC_SLOT_BYTES, X18_CONDITIONAL_SLOT_BYTES, X18_PCREL_SLOT_BYTES,
    X18_SETUP_BYTES, X18_SLOT_BYTES,
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
    /// address.
    guest_thread_pointer: usize,
    guest_x18: usize,
    saved_anchor_scratch: usize,
    saved_value_scratch: usize,
    host_x18: usize,
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
    resume_frame: resume_frame::ResumeFrame,
}

/// Byte offsets of [`TlsBlock`]'s fields, for the transition assembly.
pub(super) mod tls_offset {
    use super::TlsBlock;
    use core::mem::offset_of;

    pub(crate) const GUEST_THREAD_POINTER: usize = offset_of!(TlsBlock, guest_thread_pointer);
    pub(crate) const GUEST_X18: usize = offset_of!(TlsBlock, guest_x18);
    pub(crate) const SAVED_ANCHOR_SCRATCH: usize = offset_of!(TlsBlock, saved_anchor_scratch);
    pub(crate) const SAVED_VALUE_SCRATCH: usize = offset_of!(TlsBlock, saved_value_scratch);
    pub(crate) const HOST_X18: usize = offset_of!(TlsBlock, host_x18);
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

/// Byte offset of the guest thread-pointer slot from `TPIDR_EL0`, as fixed by
/// this binary's link.
///
/// The loader patches this into every rewritten guest binary's thread-pointer
/// gates. The linker decides it per embedder, but it is the same on every
/// thread.
///
/// # Panics
///
/// Panics if the offset is not one a gate can be patched to reach.
pub(super) fn guest_thread_pointer_offset() -> usize {
    let base = tprel_offset!(litebox_tls_block);
    base + tls_offset::GUEST_THREAD_POINTER
}

pub(super) fn guest_x18_offset() -> usize {
    tprel_offset!(litebox_tls_block) + tls_offset::GUEST_X18
}

pub(super) fn x18_scratch_offsets() -> (usize, usize) {
    let base = tprel_offset!(litebox_tls_block);
    (
        base + tls_offset::SAVED_ANCHOR_SCRATCH,
        base + tls_offset::SAVED_VALUE_SCRATCH,
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

    let (saved_anchor_scratch, saved_value_scratch) = x18_scratch_offsets();
    let values = [
        guest_thread_pointer_offset(),
        guest_x18_offset(),
        saved_anchor_scratch,
        saved_value_scratch,
    ];
    assert!(values.iter().all(|offset| offset.is_multiple_of(8)));
    assert!(
        values
            .iter()
            .enumerate()
            .all(|(index, offset)| !values[..index].contains(offset))
    );
    litebox_syscall_rewriter::aarch64::Aarch64GateOffsets::new(
        u16::try_from(values[0]).expect("guest_tpidr offset is too large for a gate"),
        u16::try_from(values[1]).expect("guest_x18 offset is too large for a gate"),
        u16::try_from(values[2]).expect("saved_anchor_scratch offset is too large for a gate"),
        u16::try_from(values[3]).expect("saved_value_scratch offset is too large for a gate"),
    )
    .expect("AArch64 TLS runtime slots must be distinct, aligned, and encodable");
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

#[cfg(feature = "aarch64_virtualize_x18")]
fn virtualized_x18() -> usize {
    let value: usize;
    // SAFETY: an own-thread [`tls_offset`] slot access.
    unsafe {
        core::arch::asm! {
            load_tls_block_base!("{block}"),
            "ldr {value}, [{block}, #{value_off}]",
            block = out(reg) _,
            value = out(reg) value,
            value_off = const tls_offset::GUEST_X18,
            options(nostack, readonly, preserves_flags)
        }
    }
    value
}

#[cfg(feature = "aarch64_virtualize_x18")]
pub(super) fn publish_virtualized_x18(value: usize) {
    // SAFETY: an own-thread [`tls_offset`] slot access.
    unsafe {
        core::arch::asm! {
            load_tls_block_base!("{block}"),
            "str {value}, [{block}, #{value_off}]",
            block = out(reg) _,
            value = in(reg) value,
            value_off = const tls_offset::GUEST_X18,
            options(nostack, preserves_flags)
        }
    }
}

#[cfg(not(feature = "aarch64_virtualize_x18"))]
pub(super) fn publish_virtualized_x18(_value: usize) {}

pub(super) fn copy_ordinary_signal_context(
    regs: &mut litebox_common_linux::PtRegs,
    context: &libc::ucontext_t,
) {
    copy_signal_context(regs, context);
    #[cfg(feature = "aarch64_virtualize_x18")]
    {
        regs.regs[18] = virtualized_x18();
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
    str x18, [x8, #{HOST_X18}]

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
    // Preserve the historical physical guest x18 ABI unless this build
    // virtualizes x18. Virtualized builds expose the logical TLS slot.
    .if {VIRTUALIZE_X18}
    ",
    load_tls_block_base!("x0"),
    "
    ldr  x0,  [x0, #{GUEST_X18}]
    str  x0,  [x16, #144]
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

    .globl internal_emulation_callback
internal_emulation_callback:
    ",
    load_tls_block_base!("x9"),
    "
    ldr x9, [x9, #{HOST_SP}]
    mov sp, x9
    add x29, sp, #16
    ldr x0, [sp]
    bl {internal_emulation_handler}
    brk #0

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
    HOST_X18 = const tls_offset::HOST_X18,
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
    internal_emulation_handler = sym internal_emulation_handler,
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
/// guest-controlled address. Costs ~4.7KB of `.tbss` per thread.
///
/// The `fpsimd_context` record's `vregs` stay zero -- LiteBox saves no guest
/// FP/SIMD -- but the record cannot be omitted: `parse_user_sigframe` rejects
/// a frame without one.
pub(super) mod resume_frame {
    use litebox_common_linux::PtRegs;
    use litebox_common_linux::signal::{Siginfo, Ucontext};
    use zerocopy::{FromBytes, IntoBytes, KnownLayout};

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
    #[derive(FromBytes, IntoBytes, KnownLayout)]
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
    #[derive(FromBytes, IntoBytes, KnownLayout)]
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
    fn state() -> (*mut ResumeFrame, *mut u8) {
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

    /// Fills this thread's frame in from `ctx` and returns it, ready for
    /// `rt_sigreturn`.
    pub(super) fn prepare(ctx: &PtRegs) -> *mut ResumeFrame {
        let (frame, initialized) = state();
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

        // `restore_fpsimd_context` installs these, so a zeroed record would
        // reset the guest's rounding mode and flush-to-zero on every
        // asynchronous resume. Copying the live values instead makes the resume
        // a no-op, matching what the outbound-stub path does by not touching
        // them at all.
        //
        // `FPCR` really is the guest's: it is a mode register and nothing
        // between the guest's exit and here writes one. `FPSR` is not --- its
        // cumulative exception bits are set by ordinary arithmetic, so the host
        // code that ran in between has polluted them. Carrying them forward is
        // still the better of the two options, since zeroing would discard the
        // guest's own flags on top.
        //
        // TODO: preserve vector state across transitions. Asynchronous resume
        // currently restores zeroed `vregs`, corrupting SIMD-using guests.
        let status: u32;
        let control: u32;
        // SAFETY: reads two floating-point control registers; touches no
        // memory.
        unsafe {
            core::arch::asm!(
                "mrs {status:x}, fpsr",
                "mrs {control:x}, fpcr",
                status = out(reg) status,
                control = out(reg) control,
                options(nomem, nostack, preserves_flags)
            );
        }
        let (fpsimd, _) = FpsimdContext::mut_from_prefix(&mut frame.ucontext.mcontext.__reserved)
            .expect("__reserved is 4KiB");
        fpsimd.fpsr = status;
        fpsimd.fpcr = control;

        let mcontext = &mut frame.ucontext.mcontext;
        for (dst, src) in mcontext.regs.iter_mut().zip(ctx.regs.iter()) {
            *dst = *src as u64;
        }
        #[cfg(feature = "aarch64_virtualize_x18")]
        {
            let block: usize;
            unsafe {
                core::arch::asm!(load_tls_block_base!("{block}"), block = out(reg) block, options(nostack, preserves_flags));
            }
            mcontext.regs[18] = unsafe { *((block + super::tls_offset::HOST_X18) as *const u64) };
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
        use litebox_common_linux::PtRegs;
        use litebox_common_linux::signal::{Siginfo, Ucontext, aarch64::Sigcontext};

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

            assert_eq!(
                usize::try_from(observed).unwrap(),
                SENTINEL,
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

        #[cfg(feature = "aarch64_virtualize_x18")]
        #[test]
        fn virtualized_resume_frame_preserves_host_x18_not_logical_x18() {
            const LOGICAL_X18: usize = 0x1818_0000_0000_0033;
            const HOST_X18: usize = 0x1818_0000_0000_0055;
            let mut ctx = PtRegs::default();
            ctx.regs[18] = LOGICAL_X18;
            super::super::publish_virtualized_x18(LOGICAL_X18);
            let block: usize;
            unsafe {
                core::arch::asm!(load_tls_block_base!("{block}"), block = out(reg) block, options(nostack, preserves_flags));
                *((block + super::super::tls_offset::HOST_X18) as *mut usize) = HOST_X18;
            }

            let frame = super::prepare(&ctx);
            let physical_x18 = unsafe { (*frame).ucontext.mcontext.regs[18] };

            assert_eq!(physical_x18, HOST_X18 as u64);
            assert_ne!(physical_x18, LOGICAL_X18 as u64);
        }

        #[cfg(not(feature = "aarch64_virtualize_x18"))]
        #[test]
        fn nonvirtualized_resume_frame_restores_ptregs_x18_physically() {
            const GUEST_X18: usize = 0x1818_0000_0000_0044;
            let mut ctx = PtRegs::default();
            ctx.regs[18] = GUEST_X18;
            let frame = super::prepare(&ctx);

            assert_eq!(
                unsafe { (*frame).ucontext.mcontext.regs[18] },
                GUEST_X18 as u64
            );
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
    publish_virtualized_x18(ctx.regs[18]);
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
    .if {VIRTUALIZE_X18}
    ldr  x18, [x17, #{HOST_X18}]
    .else
    ldr  x18, [x0, #144]
    .endif
    ldr  x17, [x0, #136]
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
    OUTBOUND_STUB = const tls_offset::OUTBOUND_STUB,
    VIRTUALIZE_X18 = const cfg!(feature = "aarch64_virtualize_x18") as usize,
    HOST_X18 = const tls_offset::HOST_X18,
    SVC_FRAME_BYTES = const litebox_syscall_rewriter::aarch64::SVC_FRAME_BYTES,
    SVC_FRAME_OFF_X16 = const litebox_syscall_rewriter::aarch64::SVC_FRAME_OFF_X16,
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
    InternalEmulation(litebox_common_linux::PtRegs),
    PreserveSavedContext,
    InvalidRuntimeState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Aarch64GateInterruption {
    SynchronousException,
    AsynchronousInterrupt,
}

#[derive(Clone, Copy)]
pub(super) struct Aarch64GateRuntimeSlots {
    guest_tpidr: usize,
    guest_x18: usize,
    saved_anchor: usize,
    saved_value: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClassifiedX18SignalPc {
    pub site: litebox_syscall_rewriter::aarch64::ClassifiedGate,
    pub site_start: usize,
    pub instruction_offset: u8,
    pub setup_instruction_offset: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandidateDiscovery<T> {
    None,
    Unique(T),
    Ambiguous,
}

impl<T> CandidateDiscovery<T> {
    fn add(&mut self, candidate: T) {
        *self = match core::mem::replace(self, Self::None) {
            Self::None => Self::Unique(candidate),
            Self::Unique(_) | Self::Ambiguous => Self::Ambiguous,
        };
    }
}

fn classify_x18_signal_pc(
    context: &libc::ucontext_t,
    mut read: impl FnMut(usize, &mut [u8]) -> bool,
) -> CandidateDiscovery<ClassifiedX18SignalPc> {
    let Ok(pc) = usize::try_from(context.uc_mcontext.pc) else {
        return CandidateDiscovery::None;
    };
    if !pc.is_multiple_of(4) {
        return CandidateDiscovery::None;
    }
    let aligned = pc & !(GATE_ALIGNMENT - 1);
    let mut found = CandidateDiscovery::None;
    for index in 0..(X18_CONDITIONAL_SLOT_BYTES / GATE_ALIGNMENT) {
        let Some(start) = aligned.checked_sub(index * GATE_ALIGNMENT) else {
            continue;
        };
        let mut storage = [0u8; X18_CONDITIONAL_SLOT_BYTES];
        for slot_size in [
            X18_SLOT_BYTES,
            X18_PCREL_SLOT_BYTES,
            X18_CONDITIONAL_SLOT_BYTES,
        ] {
            let slot = &mut storage[..slot_size];
            if read(start, slot)
                && let Some(site) = litebox_syscall_rewriter::aarch64::classify_copied_gate_slot(
                    slot,
                    start as u64,
                    pc as u64,
                )
                && site.x18().is_some()
            {
                let Ok(instruction_offset) = u8::try_from(pc - start) else {
                    continue;
                };
                found.add(ClassifiedX18SignalPc {
                    site,
                    site_start: start,
                    instruction_offset,
                    setup_instruction_offset: None,
                });
            }
        }
    }

    for index in 0..(X18_SETUP_BYTES / GATE_ALIGNMENT) {
        let Some(setup_start) = aligned.checked_sub(index * GATE_ALIGNMENT) else {
            continue;
        };
        let mut setup = [0u8; X18_SETUP_BYTES];
        let Some(classified_setup) = read(setup_start, &mut setup)
            .then(|| {
                litebox_syscall_rewriter::aarch64::classify_copied_x18_setup_record(
                    &setup,
                    setup_start as u64,
                    pc as u64,
                )
            })
            .flatten()
        else {
            continue;
        };
        let Ok(link) = usize::try_from(context.uc_mcontext.regs[30]) else {
            continue;
        };
        for return_offset in GateMetadata::X18_SETUP_RETURN_OFFSETS {
            let Some(site_start) = link
                .checked_sub(return_offset)
                .filter(|start| start.is_multiple_of(GATE_ALIGNMENT))
            else {
                continue;
            };
            let mut storage = [0u8; X18_CONDITIONAL_SLOT_BYTES];
            for slot_size in [
                X18_SLOT_BYTES,
                X18_PCREL_SLOT_BYTES,
                X18_CONDITIONAL_SLOT_BYTES,
            ] {
                let slot = &mut storage[..slot_size];
                let Some(site) = read(site_start, slot)
                    .then(|| {
                        litebox_syscall_rewriter::aarch64::classify_copied_gate_slot(
                            slot,
                            site_start as u64,
                            link as u64,
                        )
                    })
                    .flatten()
                else {
                    continue;
                };
                let Some(details) = site.x18() else { continue };
                if site.metadata().x18_setup_return_offset() != Some(return_offset)
                    || details.setup_handler() != setup_start as u64
                    || site.metadata().anchor_scratch()
                        != classified_setup.metadata().anchor_scratch()
                    || site.metadata().value_scratch()
                        != classified_setup.metadata().value_scratch()
                    || details.guest_x18_offset() != classified_setup.guest_x18_offset()
                    || details.saved_anchor_scratch_offset()
                        != classified_setup.saved_anchor_scratch_offset()
                    || details.saved_value_scratch_offset()
                        != classified_setup.saved_value_scratch_offset()
                {
                    continue;
                }
                found.add(ClassifiedX18SignalPc {
                    site,
                    site_start,
                    instruction_offset: u8::try_from(
                        site.metadata()
                            .x18_setup_call_offset()
                            .expect("x18 site has a setup call"),
                    )
                    .expect("x18 setup call offset fits u8"),
                    setup_instruction_offset: Some(classified_setup.instruction_offset()),
                });
            }
        }
    }
    found
}

fn read_usize(read: &mut impl FnMut(usize, &mut [u8]) -> bool, address: usize) -> Option<usize> {
    let mut bytes = [0u8; size_of::<usize>()];
    read(address, &mut bytes).then(|| usize::from_ne_bytes(bytes))
}

fn canonicalize_x18_gate(
    context: &libc::ucontext_t,
    saved: &litebox_common_linux::PtRegs,
    classified: ClassifiedX18SignalPc,
    interruption: Aarch64GateInterruption,
    slots: Aarch64GateRuntimeSlots,
    read: &mut impl FnMut(usize, &mut [u8]) -> bool,
) -> Aarch64GateSignalResult {
    const FRAME_BYTES: usize = 32;
    let Some(details) = classified.site.x18() else {
        return Aarch64GateSignalResult::NotGate;
    };
    let (GateMetadata::X18 {
        anchor_scratch,
        value_scratch,
    }
    | GateMetadata::X18Pcrel {
        anchor_scratch,
        value_scratch,
    }
    | GateMetadata::X18Conditional {
        anchor_scratch,
        value_scratch,
    }) = classified.site.metadata()
    else {
        return Aarch64GateSignalResult::NotGate;
    };
    let conditional = matches!(
        classified.site.metadata(),
        GateMetadata::X18Conditional { .. }
    );
    let (anchor, value) = (usize::from(anchor_scratch), usize::from(value_scratch));
    let slot_matches = |address: usize, offset: u16| {
        slots
            .guest_x18
            .checked_sub(usize::from(details.guest_x18_offset()))
            .and_then(|anchor| anchor.checked_add(usize::from(offset)))
            == Some(address)
    };
    if slots.guest_x18 == 0
        || !slot_matches(slots.saved_anchor, details.saved_anchor_scratch_offset())
        || !slot_matches(slots.saved_value, details.saved_value_scratch_offset())
    {
        return Aarch64GateSignalResult::InvalidRuntimeState;
    }

    let mut canonical = saved.clone();
    copy_signal_context(&mut canonical, context);
    let Ok(site) = usize::try_from(classified.site.original_site()) else {
        return Aarch64GateSignalResult::NotGate;
    };
    let setup_offset = classified.setup_instruction_offset.map(usize::from);
    let raw_site_offset = usize::from(classified.instruction_offset);
    if !conditional && setup_offset.is_none() && raw_site_offset == 0 {
        let Some(guest_x18) = read_usize(read, slots.guest_x18) else {
            return Aarch64GateSignalResult::InvalidRuntimeState;
        };
        canonical.regs[18] = guest_x18;
        canonical.pc = site;
        canonical.orig_x0 = canonical.regs[0];
        return Aarch64GateSignalResult::Canonicalized(canonical);
    }
    // The compact ordinary/PC-relative gate removed the old SUB instruction.
    // Normalize later boundaries to the historical phase offsets used below.
    let site_offset = if !conditional && setup_offset.is_none() {
        raw_site_offset + 4
    } else {
        raw_site_offset
    };
    if interruption == Aarch64GateInterruption::SynchronousException
        && setup_offset.map_or(
            matches!(site_offset, 32 | 36 | 40 | 48 | 52 | 56),
            |offset| matches!(offset, 8 | 16 | 20),
        )
    {
        return Aarch64GateSignalResult::InvalidRuntimeState;
    }
    let frame_sp = if setup_offset.is_some() || (4..24).contains(&site_offset) {
        canonical.sp
    } else if site_offset > 24 {
        let Some(frame_sp) = canonical.sp.checked_sub(FRAME_BYTES) else {
            return Aarch64GateSignalResult::NotGate;
        };
        frame_sp
    } else {
        0
    };
    let read_frame = |read: &mut _, index: usize| {
        frame_sp
            .checked_add(index * size_of::<usize>())
            .and_then(|address| read_usize(read, address))
    };
    let read_slot = |read: &mut _, address| read_usize(read, address);

    if let Some(offset) = setup_offset {
        let Some(frame_anchor) = read_frame(read, 0) else {
            return Aarch64GateSignalResult::NotGate;
        };
        let Some(frame_value) = read_frame(read, 1) else {
            return Aarch64GateSignalResult::NotGate;
        };
        let Some(frame_x30) = read_frame(read, 2) else {
            return Aarch64GateSignalResult::NotGate;
        };
        let restored_anchor = if offset >= 12 {
            let Some(slot) = read_slot(read, slots.saved_anchor) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if slot != frame_anchor {
                return Aarch64GateSignalResult::NotGate;
            }
            slot
        } else {
            frame_anchor
        };
        let restored_value = if offset >= 20 {
            let Some(slot) = read_slot(read, slots.saved_value) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            if slot != frame_value {
                return Aarch64GateSignalResult::NotGate;
            }
            slot
        } else {
            frame_value
        };
        canonical.regs[anchor] = restored_anchor;
        canonical.regs[value] = restored_value;
        canonical.regs[30] = frame_x30;
        let Some(sp) = canonical.sp.checked_add(FRAME_BYTES) else {
            return Aarch64GateSignalResult::NotGate;
        };
        canonical.sp = sp;
        canonical.pc = site;
    } else if site_offset < 16 {
        if site_offset >= 8 {
            let Some(frame_anchor) = read_frame(read, 0) else {
                return Aarch64GateSignalResult::NotGate;
            };
            let Some(frame_value) = read_frame(read, 1) else {
                return Aarch64GateSignalResult::NotGate;
            };
            canonical.regs[anchor] = frame_anchor;
            canonical.regs[value] = frame_value;
        }
        if site_offset >= 4 {
            let Some(sp) = canonical.sp.checked_add(FRAME_BYTES) else {
                return Aarch64GateSignalResult::NotGate;
            };
            canonical.sp = sp;
        }
        canonical.pc = site;
    } else if conditional && site_offset >= 24 {
        if site_offset == 24 {
            let (Some(restored_anchor), Some(restored_value)) = (
                read_slot(read, slots.saved_anchor),
                read_slot(read, slots.saved_value),
            ) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            canonical.regs[anchor] = restored_anchor;
            canonical.regs[value] = restored_value;
            canonical.pc = site;
        } else {
            let path_start = if site_offset >= 44 { 44 } else { 28 };
            canonical.regs[anchor] = if site_offset >= path_start + 12 {
                canonical.regs[anchor]
            } else {
                let Some(restored) = read_slot(read, slots.saved_anchor) else {
                    return Aarch64GateSignalResult::InvalidRuntimeState;
                };
                restored
            };
            canonical.regs[value] = if site_offset >= path_start + 8 {
                canonical.regs[value]
            } else {
                let Some(restored) = read_slot(read, slots.saved_value) else {
                    return Aarch64GateSignalResult::InvalidRuntimeState;
                };
                restored
            };
            canonical.pc = if path_start == 44 {
                let Some(taken) = details
                    .taken()
                    .and_then(|target| usize::try_from(target).ok())
                else {
                    return Aarch64GateSignalResult::NotGate;
                };
                taken
            } else {
                let Ok(fallthrough) = usize::try_from(details.fallthrough()) else {
                    return Aarch64GateSignalResult::NotGate;
                };
                fallthrough
            };
        }
    } else {
        let pre_instruction_frame = if site_offset < 24 {
            let (Some(frame_anchor), Some(frame_value), Some(frame_x30)) = (
                read_frame(read, 0),
                read_frame(read, 1),
                read_frame(read, 2),
            ) else {
                return Aarch64GateSignalResult::NotGate;
            };
            Some((frame_anchor, frame_value, frame_x30))
        } else {
            None
        };
        let restored_anchor = if site_offset >= 44 {
            canonical.regs[anchor]
        } else {
            let Some(slot) = read_slot(read, slots.saved_anchor) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            slot
        };
        let restored_value = if site_offset >= 40 {
            canonical.regs[value]
        } else {
            let Some(slot) = read_slot(read, slots.saved_value) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            slot
        };
        canonical.regs[anchor] = restored_anchor;
        canonical.regs[value] = restored_value;
        if let Some((frame_anchor, frame_value, frame_x30)) = pre_instruction_frame {
            if restored_anchor != frame_anchor || restored_value != frame_value {
                return Aarch64GateSignalResult::NotGate;
            }
            if site_offset == 16 {
                canonical.regs[30] = frame_x30;
            } else if canonical.regs[30] != frame_x30 {
                return Aarch64GateSignalResult::NotGate;
            }
        }
        if site_offset < 24 {
            let Some(sp) = canonical.sp.checked_add(FRAME_BYTES) else {
                return Aarch64GateSignalResult::NotGate;
            };
            canonical.sp = sp;
        }
        let materialization_complete = if details.original_is_adr() {
            site_offset > 28
        } else {
            site_offset > 24
        };
        canonical.pc = if materialization_complete {
            site + 4
        } else {
            site
        };
    }
    canonical.regs[18] = if !conditional
        && setup_offset.is_none()
        && ((details.original_is_adr() && site_offset == 32)
            || (!details.original_is_adr() && matches!(site_offset, 28 | 32)))
    {
        let Ok(result) = usize::try_from(context.uc_mcontext.regs[value]) else {
            return Aarch64GateSignalResult::InvalidRuntimeState;
        };
        result
    } else {
        let Some(guest_x18) = read_slot(read, slots.guest_x18) else {
            return Aarch64GateSignalResult::InvalidRuntimeState;
        };
        guest_x18
    };
    canonical.orig_x0 = canonical.regs[0];
    Aarch64GateSignalResult::Canonicalized(canonical)
}

/// Recognizes and canonicalizes an interrupted compact gate using only bounded,
/// caller-supplied reads. The signal-handler caller supplies exception-table
/// reads; tests supply synthetic mappings.
///
/// A candidate is accepted only if its metadata word, its exact instruction
/// template, and the inbound branch at its original site all agree. That is
/// what makes a range registry unnecessary. A guest that forges all three
/// changes only its own libOS semantics under LiteBox's threat model.
fn canonicalize_aarch64_gate_signal_context_with_interruption(
    context: &libc::ucontext_t,
    saved: &litebox_common_linux::PtRegs,
    interruption: Aarch64GateInterruption,
    runtime_slots: Aarch64GateRuntimeSlots,
    expected_outbound_stub: usize,
    expected_outbound_pc: usize,
    mut read: impl FnMut(usize, &mut [u8]) -> bool,
) -> Aarch64GateSignalResult {
    // Every slot boundary and frame size below is the rewriter's, not this
    // crate's: re-deriving them here would let the two drift silently.
    const SVC_FRAME: usize = SVC_FRAME_BYTES as usize;
    const MSR_FRAME: usize = MSR_FRAME_BYTES as usize;
    // The widest slot spans this many `GATE_ALIGNMENT` steps, so the aligned PC
    // is at most one step short of this many steps past the slot start.
    const MAX_CANDIDATES: usize = SVC_SLOT_BYTES / GATE_ALIGNMENT;
    let pc = context.uc_mcontext.pc;
    let Ok(pc_usize) = usize::try_from(pc) else {
        return Aarch64GateSignalResult::NotGate;
    };
    if !pc.is_multiple_of(4) {
        return Aarch64GateSignalResult::NotGate;
    }

    let x18 = classify_x18_signal_pc(context, &mut read);

    let aligned = pc_usize & !(GATE_ALIGNMENT - 1);
    let mut found = CandidateDiscovery::None;
    for candidate_index in 0..MAX_CANDIDATES {
        let Some(slot_start) = aligned.checked_sub(candidate_index * GATE_ALIGNMENT) else {
            continue;
        };
        for slot_size in [MRS_SLOT_BYTES, MSR_SLOT_BYTES, SVC_SLOT_BYTES] {
            let Some(slot_end) = slot_start.checked_add(slot_size) else {
                continue;
            };
            if pc_usize < slot_start || pc_usize >= slot_end {
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
            let mut slot = [0u8; 64];
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
                pc,
            ) else {
                continue;
            };
            if matches!(
                classified.metadata(),
                GateMetadata::X18 { .. }
                    | GateMetadata::X18Pcrel { .. }
                    | GateMetadata::X18Conditional { .. }
            ) {
                continue;
            }
            found.add((slot_start, classified));
        }
    }

    let (slot_start, gate) = match (x18, found) {
        (CandidateDiscovery::Unique(x18), CandidateDiscovery::None) => {
            let site = x18.site.original_site();
            let Ok(site_usize) = usize::try_from(site) else {
                return Aarch64GateSignalResult::NotGate;
            };
            let mut original = [0u8; 4];
            if !read(site_usize, &mut original)
                || litebox_syscall_rewriter::aarch64::decode_branch_target(
                    u32::from_le_bytes(original),
                    site,
                ) != Some(x18.site_start as u64)
            {
                return Aarch64GateSignalResult::NotGate;
            }
            return canonicalize_x18_gate(
                context,
                saved,
                x18,
                interruption,
                runtime_slots,
                &mut read,
            );
        }
        (CandidateDiscovery::None, CandidateDiscovery::Unique(legacy)) => legacy,
        (CandidateDiscovery::None, CandidateDiscovery::None)
        | (CandidateDiscovery::Ambiguous, _)
        | (_, CandidateDiscovery::Ambiguous)
        | (CandidateDiscovery::Unique(_), CandidateDiscovery::Unique(_)) => {
            return Aarch64GateSignalResult::NotGate;
        }
    };

    // Guest-derived provenance failures are `NotGate`; only unreadable
    // runtime-owned TLS is an invalid runtime state.
    let site = gate.original_site();
    let Ok(site_usize) = usize::try_from(site) else {
        return Aarch64GateSignalResult::NotGate;
    };
    if !site.is_multiple_of(4) {
        return Aarch64GateSignalResult::NotGate;
    }
    let mut original = [0u8; 4];
    if !read(site_usize, &mut original) {
        return Aarch64GateSignalResult::NotGate;
    }
    let original = u32::from_le_bytes(original);
    if litebox_syscall_rewriter::aarch64::decode_branch_target(original, site)
        != Some(slot_start as u64)
    {
        return Aarch64GateSignalResult::NotGate;
    }

    let metadata = gate.metadata();
    let offset = pc_usize - slot_start;
    if matches!(metadata, GateMetadata::Svc) && offset >= SVC_GATE_BYTES {
        return if expected_outbound_stub == slot_start + SVC_GATE_BYTES
            && expected_outbound_pc == site_usize + 4
        {
            Aarch64GateSignalResult::PreserveSavedContext
        } else {
            Aarch64GateSignalResult::NotGate
        };
    }

    let mut canonical = saved.clone();
    copy_signal_context(&mut canonical, context);
    canonical.pc = site_usize;

    // `copy_signal_context` derived `orig_x0` from the interrupted `regs[0]`,
    // which for `mrs x0, tpidr_el0` is the *host* anchor. Whatever the arms
    // below repair, re-derive it afterwards rather than leaving a host address
    // in a guest-visible field.
    match metadata {
        GateMetadata::MrsTpidr { destination, .. } => {
            let destination = usize::from(destination);
            if offset == 4 {
                let Some(guest_tp) = read_usize(&mut read, runtime_slots.guest_tpidr) else {
                    return Aarch64GateSignalResult::InvalidRuntimeState;
                };
                canonical.regs[destination] = guest_tp;
                canonical.pc = site_usize + 4;
            } else if offset == 8 {
                canonical.pc = site_usize + 4;
            }
        }
        GateMetadata::MsrTpidr { source, .. } => {
            if offset == 4 {
                let Some(sp) = canonical.sp.checked_add(MSR_FRAME) else {
                    return Aarch64GateSignalResult::NotGate;
                };
                canonical.sp = sp;
            } else if (8..28).contains(&offset) {
                let mut frame = [[0u8; size_of::<usize>()]; 3];
                let words = if offset == 8 { 2 } else { 3 };
                if !read(canonical.sp, frame[..words].as_flattened_mut()) {
                    return Aarch64GateSignalResult::NotGate;
                }
                let saved_x16 = usize::from_ne_bytes(frame[0]);
                let saved_x17 = usize::from_ne_bytes(frame[1]);
                if offset >= 12 {
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
                }
                canonical.regs[16] = saved_x16;
                canonical.regs[17] = saved_x17;
                let Some(sp) = canonical.sp.checked_add(MSR_FRAME) else {
                    return Aarch64GateSignalResult::NotGate;
                };
                canonical.sp = sp;
            } else if offset == 28 {
                // LDP at +24 has completed, so x16/x17 are already the live
                // guest values. ADD SP at +28 has not yet completed.
                let Some(sp) = canonical.sp.checked_add(MSR_FRAME) else {
                    return Aarch64GateSignalResult::NotGate;
                };
                canonical.sp = sp;
            }
            if offset > usize::from(gate.commit_offset()) {
                canonical.pc = site_usize + 4;
            }
        }
        GateMetadata::Svc => {
            if offset == 4 {
                let Some(sp) = canonical.sp.checked_add(SVC_FRAME) else {
                    return Aarch64GateSignalResult::NotGate;
                };
                canonical.sp = sp;
            } else if offset >= 8 {
                let Some(saved_x16) = read_usize(&mut read, canonical.sp) else {
                    return Aarch64GateSignalResult::NotGate;
                };
                canonical.regs[16] = saved_x16;
                let Some(sp) = canonical.sp.checked_add(SVC_FRAME) else {
                    return Aarch64GateSignalResult::NotGate;
                };
                canonical.sp = sp;
            }
        }
        GateMetadata::X18Br => {
            let Some(guest_x18) = read_usize(&mut read, runtime_slots.guest_x18) else {
                return Aarch64GateSignalResult::InvalidRuntimeState;
            };
            canonical.regs[18] = guest_x18;
            if interruption == Aarch64GateInterruption::SynchronousException {
                canonical.pc = guest_x18;
                canonical.orig_x0 = canonical.regs[0];
                return Aarch64GateSignalResult::InternalEmulation(canonical);
            }
        }
        GateMetadata::X18 { .. }
        | GateMetadata::X18Pcrel { .. }
        | GateMetadata::X18Conditional { .. } => {
            return Aarch64GateSignalResult::PreserveSavedContext;
        }
    }
    canonical.orig_x0 = canonical.regs[0];
    Aarch64GateSignalResult::Canonicalized(canonical)
}

#[cfg(test)]
pub(super) fn canonicalize_aarch64_gate_signal_context(
    context: &libc::ucontext_t,
    saved: &litebox_common_linux::PtRegs,
    runtime_slots: Aarch64GateRuntimeSlots,
    expected_outbound_stub: usize,
    expected_outbound_pc: usize,
    read: impl FnMut(usize, &mut [u8]) -> bool,
) -> Aarch64GateSignalResult {
    canonicalize_aarch64_gate_signal_context_with_interruption(
        context,
        saved,
        Aarch64GateInterruption::AsynchronousInterrupt,
        runtime_slots,
        expected_outbound_stub,
        expected_outbound_pc,
        read,
    )
}

pub(super) fn canonicalize_runtime_aarch64_gate_signal_context(
    context: &libc::ucontext_t,
    saved: &litebox_common_linux::PtRegs,
    interruption: Aarch64GateInterruption,
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
    canonicalize_aarch64_gate_signal_context_with_interruption(
        context,
        saved,
        interruption,
        Aarch64GateRuntimeSlots {
            guest_tpidr: block + tls_offset::GUEST_THREAD_POINTER,
            guest_x18: block + tls_offset::GUEST_X18,
            saved_anchor: block + tls_offset::SAVED_ANCHOR_SCRATCH,
            saved_value: block + tls_offset::SAVED_VALUE_SCRATCH,
        },
        expected_outbound_stub,
        expected_outbound_pc,
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

/// Terminates after gate canonicalization reports unreadable or inconsistent
/// runtime-owned TLS state. Candidate discovery reads guest memory, so even
/// multiple exact forged candidates are `NotGate`, never fatal.
pub(super) fn fatal_aarch64_gate_runtime_state() -> ! {
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

/// Clears `in_guest` and optionally sets `interrupt`. Returns the published
/// guest context only if `in_guest` was set; its registers may still require
/// copying or gate canonicalization.
pub(super) fn signal_handler_exit_guest(
    // Kept for signature parity, so both call sites stay architecture-free.
    _context: &libc::ucontext_t,
    set_interrupt: bool,
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

    #[cfg(feature = "aarch64_virtualize_x18")]
    #[test]
    fn ordinary_guest_pc_uses_virtual_x18() {
        const PHYSICAL_X18: u64 = 0x1818_0000_0000_0001;
        const VIRTUAL_X18: usize = 0x1818_0000_0000_0002;
        let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
        let mut regs = PtRegs::default();
        context.uc_mcontext.pc = 0x1234;
        context.uc_mcontext.regs[18] = PHYSICAL_X18;

        publish_virtualized_x18(VIRTUAL_X18);
        copy_ordinary_signal_context(&mut regs, &context);

        assert_eq!(regs.regs[18], VIRTUAL_X18);
        assert_ne!(regs.regs[18], usize::try_from(PHYSICAL_X18).unwrap());
    }

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
        let gate_offset =
            usize::try_from((patched & IMM12_MASK) >> IMM12_SHIFT).unwrap() * usize::from(ALIGN);
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

    fn x18_gate_fixture_for(original: u32) -> (Vec<u8>, Vec<u8>, libc::ucontext_t, PtRegs) {
        let mut code = original.to_le_bytes().to_vec();
        let (mut trampoline, trapped) = litebox_syscall_rewriter::patch_code_segment_with_options(
            &mut code,
            0x1000,
            0x400000,
            0,
            litebox_syscall_rewriter::RewriteOptions::new(
                litebox_syscall_rewriter::TargetHost::Linux,
                true,
            ),
        )
        .unwrap();
        assert!(trapped.is_empty());
        litebox_syscall_rewriter::aarch64::finalize_trampoline_gates_with_offsets(
            &mut trampoline,
            litebox_syscall_rewriter::aarch64::Aarch64GateOffsets::new(96, 104, 112, 120).unwrap(),
        )
        .unwrap();
        let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
        context.uc_mcontext.sp = 0x8000;
        let saved = PtRegs::default();
        (code, trampoline, context, saved)
    }

    fn x18_gate_fixture() -> (Vec<u8>, Vec<u8>, libc::ucontext_t, PtRegs) {
        x18_gate_fixture_for(0xaa00_03f2)
    }

    #[test]
    fn br_x18_gate_distinguishes_async_rewind_from_sync_internal_emulation() {
        let (code, trampoline, mut context, saved) = x18_gate_fixture_for(0xd61f_0240);
        let slots = Aarch64GateRuntimeSlots {
            guest_tpidr: 0x500000,
            guest_x18: 0x500008,
            saved_anchor: 0x500010,
            saved_value: 0x500018,
        };
        let mut runtime = [0u8; 32];
        context.uc_mcontext.pc = 0x400010;
        context.uc_mcontext.sp = 0x8120;
        context.uc_mcontext.pstate = 0xa000_0000;
        for (index, reg) in context.uc_mcontext.regs.iter_mut().enumerate() {
            *reg = 0xfeed_0000_0000_0000 | index as u64;
        }

        let physical_x18 = context.uc_mcontext.regs[18];

        for target in [0, 0x1818_1818_1818_1818usize] {
            runtime[8..16].copy_from_slice(&target.to_ne_bytes());
            let asynchronous = canonicalize_aarch64_gate_signal_context_with_interruption(
                &context,
                &saved,
                super::classify_aarch64_gate_interruption(libc::SIGTRAP, libc::SI_USER),
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &runtime),
            );
            let Aarch64GateSignalResult::Canonicalized(asynchronous) = asynchronous else {
                panic!("async BR x18 did not rewind");
            };
            assert_eq!(asynchronous.pc, 0x1000);
            assert_eq!(asynchronous.regs[18], target);

            let synchronous = canonicalize_aarch64_gate_signal_context_with_interruption(
                &context,
                &saved,
                Aarch64GateInterruption::SynchronousException,
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &runtime),
            );
            let Aarch64GateSignalResult::InternalEmulation(emulated) = synchronous else {
                panic!("synchronous BRK was not internal emulation");
            };
            let mut expected = expected_signal_regs(&saved, &context);
            expected.regs[18] = target;
            expected.pc = target;
            assert_ptregs_eq(&emulated, &expected, "BR x18 emulation");
            assert_eq!(context.uc_mcontext.regs[18], physical_x18);
        }
    }

    #[test]
    fn x18_conditional_taken_path_canonicalizes_to_original_target() {
        const SLOT: usize = 0x400030;
        let (code, trampoline, mut context, saved) = x18_gate_fixture_for(0x3400_0092);
        let slots = Aarch64GateRuntimeSlots {
            guest_tpidr: 0x500000,
            guest_x18: 0x500008,
            saved_anchor: 0x500010,
            saved_value: 0x500018,
        };
        let mut runtime = [0u8; 32];
        runtime[8..16].copy_from_slice(&0x1818usize.to_ne_bytes());
        runtime[16..24].copy_from_slice(&0x1616usize.to_ne_bytes());
        runtime[24..32].copy_from_slice(&0x1717usize.to_ne_bytes());
        context.uc_mcontext.pc = (SLOT + 44) as u64;
        context.uc_mcontext.sp = 0x8020;
        context.uc_mcontext.regs[16] = 0x500000;
        context.uc_mcontext.regs[17] = 0;
        context.uc_mcontext.regs[30] = 0x3030;
        context.uc_mcontext.pstate = 0xa000_0000;

        let result = canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            slots,
            0,
            0,
            fixture_reader(&code, &trampoline, &[], &runtime),
        );
        let Aarch64GateSignalResult::Canonicalized(canonical) = result else {
            panic!("taken conditional path did not canonicalize");
        };
        assert_eq!(canonical.pc, 0x1010);
        assert_eq!(canonical.regs[18], 0x1818);
        assert_eq!(canonical.regs[16], 0x1616);
        assert_eq!(canonical.regs[17], 0x1717);
        assert_eq!(canonical.regs[30], 0x3030);
        assert_eq!(canonical.sp, 0x8020);
        assert_eq!(canonical.pstate, 0xa000_0000);
    }

    fn test_runtime_slots(guest_tpidr: usize) -> Aarch64GateRuntimeSlots {
        Aarch64GateRuntimeSlots {
            guest_tpidr,
            guest_x18: 0,
            saved_anchor: 0,
            saved_value: 0,
        }
    }

    #[test]
    fn x18_site_boundaries_restore_guest_state_by_completed_phase() {
        const SITE: usize = 0x400030;
        const ORIGINAL: usize = 0x1000;
        const FRAME_SP: usize = 0x8000;
        const GUEST_SP: usize = FRAME_SP + 32;
        const GUEST_XA: usize = 0xaaaa_aaaa_aaaa_aaaa;
        const GUEST_XV: usize = 0xbbbb_bbbb_bbbb_bbbb;
        const GUEST_X30: usize = 0x3030_3030_3030_3030;
        const LIVE_X30: usize = 0x3030_3030_3030_2424;
        const LIVE_SP: usize = 0x9090;
        const PRE_X18: usize = 0x1818_1818_1818_1818;
        const LIVE_RESULT_X18: usize = 0xeeee_eeee_eeee_eeee;
        const COMMITTED_X18: usize = 0xc0c0_c0c0_c0c0_c0c0;
        const PHYSICAL_X18: usize = 0xdead_dead_dead_dead;
        const HOST_ANCHOR: usize = 0xfafa_fafa_fafa_fafa;
        let (code, trampoline, mut context, saved) = x18_gate_fixture();
        let slots = Aarch64GateRuntimeSlots {
            guest_tpidr: 0x500000,
            guest_x18: 0x500008,
            saved_anchor: 0x500010,
            saved_value: 0x500018,
        };
        let mut frame = [0u8; 32];
        frame[0..8].copy_from_slice(&GUEST_XA.to_ne_bytes());
        frame[8..16].copy_from_slice(&GUEST_XV.to_ne_bytes());
        frame[16..24].copy_from_slice(&GUEST_X30.to_ne_bytes());
        let mut runtime = [0u8; 32];
        runtime[8..16].copy_from_slice(&PRE_X18.to_ne_bytes());
        runtime[16..24].copy_from_slice(&GUEST_XA.to_ne_bytes());
        runtime[24..32].copy_from_slice(&GUEST_XV.to_ne_bytes());

        for offset in (0usize..=36).step_by(4) {
            let phase = if offset == 0 { 0 } else { offset + 4 };
            context.uc_mcontext.pc = (SITE + offset) as u64;
            context.uc_mcontext.sp = if phase == 24 {
                LIVE_SP as u64
            } else if phase == 0 || phase > 24 {
                GUEST_SP as u64
            } else {
                FRAME_SP as u64
            };
            context.uc_mcontext.regs[16] = if (16..40).contains(&phase) {
                HOST_ANCHOR as u64
            } else {
                GUEST_XA as u64
            };
            context.uc_mcontext.regs[17] = if phase == 28 || phase == 32 {
                LIVE_RESULT_X18 as u64
            } else if (16..32).contains(&phase) {
                PRE_X18 as u64
            } else {
                GUEST_XV as u64
            };
            context.uc_mcontext.regs[18] = PHYSICAL_X18 as u64;
            context.uc_mcontext.regs[30] = match phase {
                16 => (SITE + 16) as u64,
                24 => LIVE_X30 as u64,
                _ => GUEST_X30 as u64,
            };
            if phase >= 36 {
                runtime[8..16].copy_from_slice(&COMMITTED_X18.to_ne_bytes());
            } else {
                runtime[8..16].copy_from_slice(&PRE_X18.to_ne_bytes());
            }

            let result = canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                slots,
                0,
                0,
                fixture_reader(
                    &code,
                    &trampoline,
                    if phase == 24 { &[] } else { &frame },
                    &runtime,
                ),
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("x18 site +{offset} did not canonicalize");
            };
            assert_eq!(regs.regs[16], GUEST_XA, "+{offset}: anchor scratch");
            assert_eq!(regs.regs[17], GUEST_XV, "+{offset}: value scratch");
            assert_eq!(
                regs.regs[30],
                if phase == 24 { LIVE_X30 } else { GUEST_X30 },
                "+{offset}: x30"
            );
            assert_eq!(
                regs.sp,
                if phase == 24 { LIVE_SP } else { GUEST_SP },
                "+{offset}: SP"
            );
            assert_eq!(
                regs.pc,
                if phase <= 24 { ORIGINAL } else { ORIGINAL + 4 },
                "+{offset}: PC"
            );
            assert_eq!(
                regs.regs[18],
                match phase {
                    0..=24 => PRE_X18,
                    28 | 32 => LIVE_RESULT_X18,
                    _ => COMMITTED_X18,
                },
                "+{offset}: x18"
            );
            assert_eq!(regs.orig_x0, regs.regs[0], "+{offset}: orig_x0");
        }
    }

    #[test]
    fn x18_setup_boundaries_restore_guest_frame_and_flags() {
        const SETUP: usize = 0x400010;
        const SITE: usize = 0x400030;
        const GUEST_XA: usize = 0xaaaa_aaaa_aaaa_aaaa;
        const GUEST_XV: usize = 0xbbbb_bbbb_bbbb_bbbb;
        const GUEST_X30: usize = 0x3030_3030_3030_3030;
        const PRE_X18: usize = 0x1818_1818_1818_1818;
        const PHYSICAL_X18: usize = 0xdead_dead_dead_dead;
        const HOST_ANCHOR: usize = 0xfafa_fafa_fafa_fafa;
        let (code, trampoline, mut context, saved) = x18_gate_fixture();
        let slots = Aarch64GateRuntimeSlots {
            guest_tpidr: 0x500000,
            guest_x18: 0x500008,
            saved_anchor: 0x500010,
            saved_value: 0x500018,
        };
        let mut frame = [0u8; 32];
        frame[0..8].copy_from_slice(&GUEST_XA.to_ne_bytes());
        frame[8..16].copy_from_slice(&GUEST_XV.to_ne_bytes());
        frame[16..24].copy_from_slice(&GUEST_X30.to_ne_bytes());
        let mut runtime = [0u8; 32];
        runtime[8..16].copy_from_slice(&PRE_X18.to_ne_bytes());
        runtime[16..24].copy_from_slice(&GUEST_XA.to_ne_bytes());
        runtime[24..32].copy_from_slice(&GUEST_XV.to_ne_bytes());

        for offset in (0usize..=24).step_by(4) {
            context.uc_mcontext.pc = (SETUP + offset) as u64;
            context.uc_mcontext.sp = 0x8000;
            context.uc_mcontext.regs[16] = if offset >= 4 {
                HOST_ANCHOR as u64
            } else {
                GUEST_XA as u64
            };
            context.uc_mcontext.regs[17] = match offset {
                8..=12 => GUEST_XA as u64,
                24 => 0x1818,
                _ => GUEST_XV as u64,
            };
            context.uc_mcontext.regs[30] = (SITE + 12) as u64;
            context.uc_mcontext.regs[18] = PHYSICAL_X18 as u64;
            context.uc_mcontext.pstate = 0xa000_0000;
            let result = canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &frame, &runtime),
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("x18 setup +{offset} did not canonicalize");
            };
            assert_eq!(regs.regs[16], GUEST_XA, "+{offset}: anchor scratch");
            assert_eq!(regs.regs[17], GUEST_XV, "+{offset}: value scratch");
            assert_eq!(regs.regs[30], GUEST_X30, "+{offset}: x30");
            assert_eq!(regs.sp, 0x8020, "+{offset}: SP");
            assert_eq!(regs.pc, 0x1000, "+{offset}: PC");
            assert_eq!(regs.regs[18], PRE_X18, "+{offset}: x18");
            assert_eq!(regs.pstate, 0xa000_0000, "+{offset}: NZCV");
        }
    }

    #[test]
    fn shared_x18_setup_provenance_accepts_each_calling_gate_kind() {
        const SETUP: usize = 0x400010;
        const SITE: usize = 0x400030;

        for (original, setup_return_offset, expected_metadata) in [
            (
                0xaa00_03f2,
                12,
                GateMetadata::X18 {
                    anchor_scratch: 16,
                    value_scratch: 17,
                },
            ),
            (
                0x1000_0092, // adr x18, +0x10
                12,
                GateMetadata::X18Pcrel {
                    anchor_scratch: 16,
                    value_scratch: 17,
                },
            ),
            (
                0xb400_0032, // cbz x18, +4
                16,
                GateMetadata::X18Conditional {
                    anchor_scratch: 16,
                    value_scratch: 17,
                },
            ),
        ] {
            let (_code, trampoline, mut context, _saved) = x18_gate_fixture_for(original);
            context.uc_mcontext.pc = (SETUP + 8) as u64;
            context.uc_mcontext.regs[30] = (SITE + setup_return_offset) as u64;

            let discovery =
                classify_x18_signal_pc(&context, fixture_reader(&[], &trampoline, &[], &[]));
            let CandidateDiscovery::Unique(classified) = discovery else {
                panic!("shared setup caller {expected_metadata:?} was not uniquely classified");
            };
            assert_eq!(classified.site_start, SITE);
            assert_eq!(classified.site.metadata(), expected_metadata);
            assert_eq!(
                classified.instruction_offset,
                u8::try_from(setup_return_offset - 4).unwrap()
            );
            assert_eq!(classified.setup_instruction_offset, Some(8));
        }
    }

    #[test]
    fn x18_gate_read_failures_follow_guest_and_runtime_ownership() {
        let (code, trampoline, mut context, saved) = x18_gate_fixture();
        let slots = Aarch64GateRuntimeSlots {
            guest_tpidr: 0x500000,
            guest_x18: 0x500008,
            saved_anchor: 0x500010,
            saved_value: 0x500018,
        };
        context.uc_mcontext.sp = 0x8000;
        context.uc_mcontext.regs[30] = 0x40003c;
        context.uc_mcontext.pc = 0x400010;
        assert!(matches!(
            canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &[]),
            ),
            Aarch64GateSignalResult::NotGate
        ));

        let mut frame = [0u8; 32];
        frame[0..8].copy_from_slice(&context.uc_mcontext.regs[16].to_ne_bytes());
        frame[8..16].copy_from_slice(&context.uc_mcontext.regs[17].to_ne_bytes());
        frame[16..24].copy_from_slice(&0x3030usize.to_ne_bytes());
        assert!(matches!(
            canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &frame, &[]),
            ),
            Aarch64GateSignalResult::InvalidRuntimeState
        ));

        context.uc_mcontext.pc = 0x400030;
        context.uc_mcontext.sp = 0x8020;
        assert!(matches!(
            canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &[]),
            ),
            Aarch64GateSignalResult::InvalidRuntimeState
        ));

        context.uc_mcontext.pc = 0x400030 + 24;
        context.uc_mcontext.sp = 0x8020;
        assert!(matches!(
            canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &[]),
            ),
            Aarch64GateSignalResult::InvalidRuntimeState
        ));

        frame[0..8].copy_from_slice(&context.uc_mcontext.regs[16].to_ne_bytes());
        frame[8..16].copy_from_slice(&context.uc_mcontext.regs[17].to_ne_bytes());
        frame[16..24].copy_from_slice(&context.uc_mcontext.regs[30].to_ne_bytes());
        assert!(matches!(
            canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &frame, &[]),
            ),
            Aarch64GateSignalResult::InvalidRuntimeState
        ));
    }

    #[test]
    fn x18_post_instruction_preserves_width_x30_and_nzcv_results() {
        const SITE: usize = 0x400030;
        const RESULT_FLAGS: u64 = 0x9000_0000;
        for (original, result_x18, result_x30, label) in [
            (0x2a00_03f2, 0x0000_0000_89ab_cdef, 0x3030, "w18 result"),
            (0xaa1e_03f2, 0x3030, 0x3030, "x30 input"),
            (0xaa12_03fe, 0x1818, 0x1818, "x30 output"),
            (0xab01_0012, 0x4242, 0x3030, "flag-setting x18 output"),
        ] {
            let (code, trampoline, mut context, saved) = x18_gate_fixture_for(original);
            let slots = Aarch64GateRuntimeSlots {
                guest_tpidr: 0x500000,
                guest_x18: 0x500008,
                saved_anchor: 0x500010,
                saved_value: 0x500018,
            };
            let mut runtime = [0u8; 32];
            runtime[16..24].copy_from_slice(&0x1616usize.to_ne_bytes());
            runtime[24..32].copy_from_slice(&0x1717usize.to_ne_bytes());
            context.uc_mcontext.pc = (SITE + 28) as u64;
            context.uc_mcontext.sp = 0x8020;
            context.uc_mcontext.regs[16] = 0xfafa;
            context.uc_mcontext.regs[17] = result_x18 as u64;
            context.uc_mcontext.regs[30] = result_x30 as u64;
            context.uc_mcontext.pstate = RESULT_FLAGS;
            context.uc_mcontext.regs[0] = 0x0101;
            let result = canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &runtime),
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!("{label} did not canonicalize");
            };
            assert_eq!(regs.regs[18], result_x18, "{label}: x18");
            assert_eq!(regs.regs[30], result_x30, "{label}: x30");
            assert_eq!(regs.pstate, RESULT_FLAGS, "{label}: NZCV");
            assert_eq!(regs.orig_x0, 0x0101, "{label}: orig_x0");
        }
    }

    #[test]
    fn x18_gate_signal_sync_and_async_runtime_boundaries_diverge() {
        const SETUP: usize = 0x400010;
        const SITE: usize = 0x400030;
        let (code, trampoline, mut context, saved) = x18_gate_fixture();
        let slots = Aarch64GateRuntimeSlots {
            guest_tpidr: 0x500000,
            guest_x18: 0x500008,
            saved_anchor: 0x500010,
            saved_value: 0x500018,
        };
        let mut runtime = [0u8; 32];
        runtime[8..16].copy_from_slice(&0x1818usize.to_ne_bytes());
        runtime[16..24].copy_from_slice(&0x1616usize.to_ne_bytes());
        runtime[24..32].copy_from_slice(&0x1717usize.to_ne_bytes());
        context.uc_mcontext.sp = 0x8020;
        context.uc_mcontext.regs[16] = 0xfafa;
        context.uc_mcontext.regs[17] = 0x2828;
        context.uc_mcontext.regs[30] = 0x3030;

        for offset in [20usize, 24, 28] {
            context.uc_mcontext.pc = (SITE + offset) as u64;
            let asynchronous = canonicalize_aarch64_gate_signal_context_with_interruption(
                &context,
                &saved,
                Aarch64GateInterruption::AsynchronousInterrupt,
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &runtime),
            );
            let Aarch64GateSignalResult::Canonicalized(asynchronous) = asynchronous else {
                panic!("async site +{offset} did not canonicalize");
            };
            assert_eq!(asynchronous.pc, if offset == 20 { 0x1000 } else { 0x1004 });
            assert_eq!(
                asynchronous.regs[18],
                if offset == 20 { 0x1818 } else { 0x2828 }
            );

            let synchronous = canonicalize_aarch64_gate_signal_context_with_interruption(
                &context,
                &saved,
                Aarch64GateInterruption::SynchronousException,
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &runtime),
            );
            if offset == 28 {
                assert!(matches!(
                    synchronous,
                    Aarch64GateSignalResult::InvalidRuntimeState
                ));
            } else {
                assert!(matches!(
                    synchronous,
                    Aarch64GateSignalResult::Canonicalized(_)
                ));
            }
        }

        for offset in [8usize, 16, 20] {
            context.uc_mcontext.pc = (SETUP + offset) as u64;
            context.uc_mcontext.regs[30] = (SITE + 12) as u64;
            assert!(matches!(
                canonicalize_aarch64_gate_signal_context_with_interruption(
                    &context,
                    &saved,
                    Aarch64GateInterruption::SynchronousException,
                    slots,
                    0,
                    0,
                    fixture_reader(&code, &trampoline, &[], &runtime),
                ),
                Aarch64GateSignalResult::InvalidRuntimeState
            ));
        }

        for offset in [32usize, 36] {
            context.uc_mcontext.pc = (SITE + offset) as u64;
            context.uc_mcontext.regs[30] = 0x3030;
            assert!(matches!(
                canonicalize_aarch64_gate_signal_context_with_interruption(
                    &context,
                    &saved,
                    Aarch64GateInterruption::SynchronousException,
                    slots,
                    0,
                    0,
                    fixture_reader(&code, &trampoline, &[], &runtime),
                ),
                Aarch64GateSignalResult::InvalidRuntimeState
            ));
        }

        context.uc_mcontext.pc = (SITE + 36) as u64;
        context.uc_mcontext.regs[16] = 0x1616;
        context.uc_mcontext.regs[17] = 0x1717;
        assert!(matches!(
            canonicalize_aarch64_gate_signal_context_with_interruption(
                &context,
                &saved,
                Aarch64GateInterruption::SynchronousException,
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &runtime),
            ),
            Aarch64GateSignalResult::InvalidRuntimeState
        ));
    }

    #[test]
    fn x18_gate_signal_guest_frame_mismatch_is_not_gate() {
        const SETUP: usize = 0x400010;
        const SITE: usize = 0x400030;
        let (code, trampoline, mut context, saved) = x18_gate_fixture();
        let slots = Aarch64GateRuntimeSlots {
            guest_tpidr: 0x500000,
            guest_x18: 0x500008,
            saved_anchor: 0x500010,
            saved_value: 0x500018,
        };
        let mut frame = [0u8; 32];
        frame[0..8].copy_from_slice(&0xaaaausize.to_ne_bytes());
        frame[8..16].copy_from_slice(&0xbbbbusize.to_ne_bytes());
        frame[16..24].copy_from_slice(&0x3030usize.to_ne_bytes());
        let mut runtime = [0u8; 32];
        runtime[8..16].copy_from_slice(&0x1818usize.to_ne_bytes());
        runtime[16..24].copy_from_slice(&0xddddusize.to_ne_bytes());
        runtime[24..32].copy_from_slice(&0xbbbbusize.to_ne_bytes());

        for pc in [SETUP + 12, SITE + 16] {
            context.uc_mcontext.pc = pc as u64;
            context.uc_mcontext.sp = 0x8000;
            context.uc_mcontext.regs[30] = if pc < SITE {
                (SITE + 12) as u64
            } else {
                0x3030
            };
            assert!(matches!(
                canonicalize_aarch64_gate_signal_context(
                    &context,
                    &saved,
                    slots,
                    0,
                    0,
                    fixture_reader(&code, &trampoline, &frame, &runtime),
                ),
                Aarch64GateSignalResult::NotGate
            ));
        }
    }

    #[test]
    fn x18_pcrel_signal_completion_is_form_aware() {
        const SITE: usize = 0x400030;
        let slots = Aarch64GateRuntimeSlots {
            guest_tpidr: 0x500000,
            guest_x18: 0x500008,
            saved_anchor: 0x500010,
            saved_value: 0x500018,
        };
        for (original, offset, expected_pc, expected_x18) in [
            (0x1000_0092, 24usize, 0x1000usize, 0x1818usize), // ADR: ADD pending
            (0x1000_0092, 28, 0x1004, 0x2828),                // ADR: ADD complete
            (0x9000_0012, 24, 0x1004, 0x2828),                // ADRP complete
        ] {
            let (code, trampoline, mut context, saved) = x18_gate_fixture_for(original);
            let mut runtime = [0u8; 32];
            runtime[8..16].copy_from_slice(&0x1818usize.to_ne_bytes());
            runtime[16..24].copy_from_slice(&0x1616usize.to_ne_bytes());
            runtime[24..32].copy_from_slice(&0x1717usize.to_ne_bytes());
            context.uc_mcontext.pc = (SITE + offset) as u64;
            context.uc_mcontext.sp = 0x8020;
            context.uc_mcontext.regs[16] = 0xfafa;
            context.uc_mcontext.regs[17] = 0x2828;
            context.uc_mcontext.regs[30] = 0x3030;

            assert!(matches!(
                classify_x18_signal_pc(&context, fixture_reader(&code, &trampoline, &[], &runtime)),
                CandidateDiscovery::Unique(_)
            ));

            let result = canonicalize_aarch64_gate_signal_context_with_interruption(
                &context,
                &saved,
                Aarch64GateInterruption::AsynchronousInterrupt,
                slots,
                0,
                0,
                fixture_reader(&code, &trampoline, &[], &runtime),
            );
            let Aarch64GateSignalResult::Canonicalized(regs) = result else {
                panic!(
                    "PC-relative gate +{offset} did not canonicalize: {}",
                    match result {
                        Aarch64GateSignalResult::NotGate => "not gate",
                        Aarch64GateSignalResult::InvalidRuntimeState => "invalid runtime state",
                        Aarch64GateSignalResult::InternalEmulation(_) => "internal emulation",
                        Aarch64GateSignalResult::PreserveSavedContext => "preserve saved context",
                        Aarch64GateSignalResult::Canonicalized(_) => unreachable!(),
                    }
                );
            };
            assert_eq!(regs.pc, expected_pc);
            assert_eq!(regs.regs[18], expected_x18);
        }
    }

    #[test]
    fn x18_site_and_setup_pcs_require_exact_site_provenance() {
        let (code, trampoline, mut context, saved) = x18_gate_fixture();
        let setup = 0x400010usize;
        let site_slot = setup + X18_SETUP_BYTES;

        for (pc, setup_offset) in [(site_slot + 20, None), (setup + 4, Some(4))] {
            context.uc_mcontext.pc = pc as u64;
            context.uc_mcontext.regs[30] = (site_slot + 12) as u64;
            let classified =
                classify_x18_signal_pc(&context, fixture_reader(&code, &trampoline, &[], &[]));
            let CandidateDiscovery::Unique(classified) = classified else {
                panic!("x18 PC {pc:#x} did not classify uniquely");
            };
            assert_eq!(classified.site.original_site(), 0x1000);
            assert_eq!(
                classified.instruction_offset,
                if setup_offset.is_some() { 8 } else { 20 }
            );
            assert_eq!(classified.setup_instruction_offset, setup_offset);
        }

        context.uc_mcontext.pc = setup as u64 + 4;
        for x30 in [0, site_slot + 8, site_slot + 16] {
            context.uc_mcontext.regs[30] = x30 as u64;
            assert!(matches!(
                canonicalize_aarch64_gate_signal_context(
                    &context,
                    &saved,
                    test_runtime_slots(0x500000),
                    0,
                    0,
                    fixture_reader(&code, &trampoline, &[], &[]),
                ),
                Aarch64GateSignalResult::NotGate
            ));
        }

        let mut wrong_inbound = code.clone();
        wrong_inbound.copy_from_slice(&0x1400_0000u32.to_le_bytes());
        context.uc_mcontext.regs[30] = (site_slot + 12) as u64;
        assert!(matches!(
            canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                test_runtime_slots(0x500000),
                0,
                0,
                fixture_reader(&wrong_inbound, &trampoline, &[], &[]),
            ),
            Aarch64GateSignalResult::NotGate
        ));
    }

    #[test]
    fn multiple_x18_site_candidates_are_ambiguous() {
        let make_slot = |start: usize| {
            let mut code = 0xaa00_03f2u32.to_le_bytes().to_vec();
            let (mut trampoline, trapped) =
                litebox_syscall_rewriter::patch_code_segment_with_options(
                    &mut code,
                    0x1000,
                    (start - 48) as u64,
                    0,
                    litebox_syscall_rewriter::RewriteOptions::new(
                        litebox_syscall_rewriter::TargetHost::Linux,
                        true,
                    ),
                )
                .unwrap();
            assert!(trapped.is_empty());
            litebox_syscall_rewriter::aarch64::finalize_trampoline_gates_with_offsets(
                &mut trampoline,
                litebox_syscall_rewriter::aarch64::Aarch64GateOffsets::new(96, 104, 112, 120)
                    .unwrap(),
            )
            .unwrap();
            trampoline[48..96].to_vec()
        };
        let first_start = 0x400010usize;
        let second_start = 0x400020usize;
        let first = make_slot(first_start);
        let second = make_slot(second_start);
        let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
        let pc = second_start + 8;
        context.uc_mcontext.pc = pc as u64;

        let discovery = classify_x18_signal_pc(&context, move |address, output| {
            let source = if address == first_start && output.len() == 48 {
                Some(first.as_slice())
            } else if address == second_start && output.len() == 48 {
                Some(second.as_slice())
            } else {
                None
            };
            source.is_some_and(|source| {
                output.copy_from_slice(source);
                true
            })
        });

        assert!(matches!(discovery, CandidateDiscovery::Ambiguous));
    }

    #[test]
    fn concurrent_multiple_x18_setup_candidates_are_ambiguous() {
        let (_code, trampoline, mut context, _saved) = x18_gate_fixture();
        let first_setup = 0x400010usize;
        let second_setup = 0x400020usize;
        let site_start = 0x500000usize;
        let setup = trampoline[16..48].to_vec();
        let pristine_site = trampoline[48..96].to_vec();
        let site_for = |target: usize| {
            let mut site = pristine_site.clone();
            let displacement =
                i64::try_from(target).unwrap() - i64::try_from(site_start + 8).unwrap();
            assert_eq!(displacement % 4, 0);
            let immediate = i32::try_from(displacement >> 2).unwrap().cast_unsigned();
            let bl = 0x9400_0000 | (immediate & 0x03ff_ffff);
            site[8..12].copy_from_slice(&bl.to_le_bytes());
            site
        };
        let first_site = site_for(first_setup);
        let second_site = site_for(second_setup);
        let mut site_reads = 0;
        context.uc_mcontext.pc = (second_setup + 4) as u64;
        context.uc_mcontext.regs[30] = (site_start + 12) as u64;

        let discovery = classify_x18_signal_pc(&context, move |address, output| {
            let source =
                if (address == first_setup || address == second_setup) && output.len() == 32 {
                    Some(setup.as_slice())
                } else if address == site_start && output.len() == 48 {
                    site_reads += 1;
                    Some(if site_reads == 1 {
                        second_site.as_slice()
                    } else {
                        first_site.as_slice()
                    })
                } else {
                    None
                };
            source.is_some_and(|source| {
                output.copy_from_slice(source);
                true
            })
        });

        assert!(matches!(discovery, CandidateDiscovery::Ambiguous));
    }

    #[test]
    fn cross_kind_candidate_ambiguity_returns_not_gate() {
        let (x18_code, x18_trampoline, mut context, saved) = x18_gate_fixture();
        let x18_slot = x18_trampoline[48..96].to_vec();
        let mut svc_code = 0xd400_0001u32.to_le_bytes();
        let (svc_trampoline, trapped) =
            litebox_syscall_rewriter::patch_code_segment(&mut svc_code, 0x2000, 0x400010, 0)
                .unwrap();
        assert!(trapped.is_empty());
        let svc_slot = svc_trampoline[16..80].to_vec();
        let pc = 0x400038usize;
        context.uc_mcontext.pc = pc as u64;

        let result = canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            test_runtime_slots(0x500000),
            0,
            0,
            move |address, output| {
                let source = if address == 0x400030 && output.len() == 48 {
                    Some(x18_slot.as_slice())
                } else if address == 0x400020 && output.len() == 64 {
                    Some(svc_slot.as_slice())
                } else if address == 0x40005c && output.len() == 4 {
                    Some(&svc_slot[60..64])
                } else if address == 0x1000 && output.len() == 4 {
                    Some(x18_code.as_slice())
                } else if address == 0x2000 && output.len() == 4 {
                    Some(svc_code.as_slice())
                } else {
                    None
                };
                source.is_some_and(|source| {
                    output.copy_from_slice(source);
                    true
                })
            },
        );

        assert!(matches!(result, Aarch64GateSignalResult::NotGate));
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
            *destination = usize::try_from(source).unwrap();
        }
        expected.sp = usize::try_from(context.uc_mcontext.sp).unwrap();
        expected.pc = usize::try_from(context.uc_mcontext.pc).unwrap();
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
                test_runtime_slots(0x500000),
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
            assert!(!regs.regs.contains(&usize::try_from(HOST_ANCHOR).unwrap()));
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
                test_runtime_slots(0x500000),
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
            assert!(!regs.regs.contains(&usize::try_from(HOST_ANCHOR).unwrap()));
            assert!(!regs.regs.contains(&usize::try_from(HOST_CALLBACK).unwrap()));
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
            context.uc_mcontext.regs[16] = if offset < 8 {
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
                test_runtime_slots(0x500000),
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
                assert!(!regs.regs.contains(&usize::try_from(HOST_CALLBACK).unwrap()));
                assert!(
                    !regs
                        .regs
                        .contains(&usize::try_from(TRAMPOLINE_ADDRESS).unwrap())
                );
            }
        }

        for offset in [36usize, 40, 44] {
            context.uc_mcontext.pc = 0x400010 + offset as u64;
            for (stub, pc) in [(0, 0x1004), (0x400010 + 36, 0), (0x400010 + 36, 0x2004)] {
                let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                    &context,
                    &saved,
                    test_runtime_slots(0x500000),
                    stub,
                    pc,
                    fixture_reader(&code, &trampoline, &frame, &guest_tp),
                );
                assert!(matches!(result, Aarch64GateSignalResult::NotGate));
            }
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
        // The slot body, the original site and the gate frame all live in guest
        // memory, so denying any of them yields `NotGate` and leaves the signal
        // with the guest; see the boundary on
        // `canonicalize_aarch64_gate_signal_context`. None of them may touch
        // the saved registers on the way out.
        for denied_address in [0x400010usize, 0x1000, 0x8000] {
            let mut reader = fixture_reader(&code, &trampoline, &frame, &[]);
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                test_runtime_slots(0x500000),
                0,
                0,
                move |address, output| address != denied_address && reader(address, output),
            );
            assert!(
                matches!(result, Aarch64GateSignalResult::NotGate),
                "denying {denied_address:#x} should leave the signal with the guest"
            );
            assert_eq!(ptregs_bytes(&saved), before);
        }

        let mut wrong_branch = code.clone();
        wrong_branch.copy_from_slice(&0x1400_0000u32.to_le_bytes());
        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            test_runtime_slots(0x500000),
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
            test_runtime_slots(0x500000),
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
            test_runtime_slots(0x500000),
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
            test_runtime_slots(0x500000),
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
                test_runtime_slots(0x500000),
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
                test_runtime_slots(0x500000),
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
            test_runtime_slots(0x500000),
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
                test_runtime_slots(0x500000),
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
            test_runtime_slots(0x500000),
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
        assert_failure(result, false, "ambiguous guest-derived candidates");

        // SP restoration arithmetic must be checked before publishing a result.
        // `sp` is a guest register, so a value that cannot be restored means
        // this is not a gate frame rather than a broken runtime.
        context.uc_mcontext.pc = 0x400010 + 4;
        context.uc_mcontext.sp = u64::MAX - 15;
        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            test_runtime_slots(0x500000),
            0,
            0,
            fixture_reader(&code, &trampoline, &frame, &[]),
        );
        assert_failure(result, false, "SP overflow");
    }

    #[test]
    fn unreadable_mrs_guest_tp_is_failure_atomic() {
        let (code, trampoline, mut context, saved) = gate_fixture(0xd53b_d049);
        context.uc_mcontext.pc = 0x400010 + 4;
        let before = (saved.regs, saved.sp, saved.pc, saved.pstate, saved.orig_x0);
        let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
            &context,
            &saved,
            test_runtime_slots(0x500000),
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
                test_runtime_slots(0x500000),
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
                test_runtime_slots(0x500000),
                0,
                0,
                fixture_reader(&msr_code, &msr_slot, &[], &[]),
            );
            assert_eq!(
                matches!(result, Aarch64GateSignalResult::Canonicalized(_)),
                matches!(offset, 0 | 4 | 28 | 32),
                "MSR +{offset} frame requirement"
            );
        }
        // The frame value is provenance before and after commit; changing it
        // must fail rather than reconstructing from scratch registers.
        msr_frame[16..].copy_from_slice(&0xdead_beef_dead_beefu64.to_ne_bytes());
        for offset in [12usize, 20, 24] {
            context.uc_mcontext.pc = 0x400010 + offset as u64;
            context.uc_mcontext.sp = 0x8000;
            let result = super::aarch64::canonicalize_aarch64_gate_signal_context(
                &context,
                &saved,
                test_runtime_slots(0x500000),
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
                test_runtime_slots(0x500000),
                0,
                0,
                fixture_reader(&svc_code, &svc_slot, &[], &[]),
            );
            // Past the staging store the frame is required, and it lives on the
            // guest's stack -- so an unreadable one leaves the signal with the
            // guest rather than killing the runtime.
            if matches!(offset, 0 | 4) {
                assert!(
                    matches!(result, Aarch64GateSignalResult::Canonicalized(_)),
                    "SVC +{offset} should not need the frame"
                );
            } else {
                assert!(
                    matches!(result, Aarch64GateSignalResult::NotGate),
                    "SVC +{offset} with an unreadable frame must stay with the guest"
                );
            }
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
            test_runtime_slots(0x500000),
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
                test_runtime_slots(0x500000),
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

    /// A SIGSEGV on that store must not be attributed to the guest.
    ///
    /// `in_guest` is already 1 at the fault, so without the fixup and the
    /// `switch_to_guest` guard the handler would overwrite the guest `PtRegs`
    /// with the host register file. Asserts that the guest context is
    /// untouched, `in_guest` is left alone, and the context is redirected to
    /// the fixup.
    #[test]
    fn test_exception_on_guest_stack_store_does_not_leak_host_state() {
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
        assert_eq!(
            usize::try_from(context.uc_mcontext.pc).unwrap(),
            fixup,
            "the signal context must be redirected to the store's fixup, not to \
             `exception_callback`"
        );
    }
}
