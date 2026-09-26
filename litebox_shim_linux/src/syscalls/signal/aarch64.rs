// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! aarch64 signal-frame construction and teardown.
//!
//! The aarch64 frame differs from the x86-64 one in three ways that matter
//! here, all dictated by `arch/arm64/kernel/signal.c`:
//!
//! * `siginfo` comes *before* `ucontext` in `struct rt_sigframe`, and the frame
//!   sits exactly at `sp` -- there is no return address pushed below it, so
//!   `rt_sigreturn` reads the frame straight off `sp`.
//! * The trampoline is handed to the handler in `x30` rather than pushed, and a
//!   `frame_record` (a saved `x29`/`x30` pair) is written just above the frame
//!   so an unwinder can chain out of the handler.
//! * AAPCS64 has no red zone, so nothing below `sp` needs to be stepped over.

use crate::ShimPlatform;
use crate::UserPtrMut;
use crate::syscalls::signal::{DeliverFault, SignalState};
use core::mem::offset_of;
use litebox::shim::{Exception, ExceptionInfo};
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{
    AARCH64_GENERAL_REGISTER_COUNT, PtRegs,
    signal::{SaFlags, SigAction, SigSet, Siginfo, Signal, Ucontext, aarch64::Sigcontext},
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// `pt_regs::syscallno` value meaning "no syscall is in flight", matching the
/// kernel's `NO_SYSCALL`.
const NO_SYSCALL: i32 = -1;

/// The kernel's `struct _aarch64_ctx`: the common header on every extension
/// record in `sigcontext.__reserved`'s chain, terminated by a record with
/// `magic == 0`.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable)]
struct Aarch64CtxHeader {
    magic: u32,
    size: u32,
}

/// The kernel's `struct fpsimd_context`
/// (`arch/arm64/include/uapi/asm/sigcontext.h`): `fpsr`/`fpcr` come *before*
/// `vregs` -- verified against the kernel header directly (fetched from
/// `torvalds/linux` `master`), not assumed from Darwin's own
/// `__darwin_arm_neon_state64` putting them in the opposite order.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable)]
struct FpsimdContext {
    head: Aarch64CtxHeader,
    fpsr: u32,
    fpcr: u32,
    vregs: [u128; 32],
}

/// `FPSIMD_MAGIC` from `arch/arm64/include/uapi/asm/sigcontext.h`.
const FPSIMD_MAGIC: u32 = 0x4650_8001;

const _: () = assert!(size_of::<FpsimdContext>() == 528);
const _: () = assert!(size_of::<FpsimdContext>() <= 4096);

/// Builds `sigcontext.__reserved`'s context-record chain holding `fp`'s state
/// as a single `fpsimd_context` record, followed by nothing but zero bytes --
/// a well-formed zero-`magic` terminator immediately after it, identical in
/// spirit to leaving the whole area zeroed (a well-formed *empty* chain).
fn fpsimd_reserved(fp: &litebox::platform::FpSimdState64) -> [u8; 4096] {
    let record = FpsimdContext {
        head: Aarch64CtxHeader {
            magic: FPSIMD_MAGIC,
            size: u32::try_from(size_of::<FpsimdContext>())
                .expect("FpsimdContext's fixed 528-byte size fits comfortably in a u32"),
        },
        fpsr: fp.fpsr,
        fpcr: fp.fpcr,
        vregs: fp.v,
    };
    let mut reserved = [0u8; 4096];
    reserved[..size_of::<FpsimdContext>()].copy_from_slice(record.as_bytes());
    reserved
}

/// Reads an `fpsimd_context` record back out of `sigcontext.__reserved`, if
/// the chain's first record is genuinely one (checked by `magic`, matching
/// how a real kernel walks this chain). A guest that never touched this area,
/// or a handler that reconstructed its own frame without one, leaves no valid
/// record here -- reporting `None` rather than faulting keeps `rt_sigreturn`
/// tolerant of both, exactly as leaving the guest's FP state alone (neither
/// restored nor cleared) would be if this platform had never modelled FP
/// state at all.
fn parse_fpsimd_reserved(reserved: &[u8; 4096]) -> Option<litebox::platform::FpSimdState64> {
    let header =
        Aarch64CtxHeader::read_from_bytes(&reserved[..size_of::<Aarch64CtxHeader>()]).ok()?;
    if header.magic != FPSIMD_MAGIC || (header.size as usize) < size_of::<FpsimdContext>() {
        return None;
    }
    let record = FpsimdContext::read_from_bytes(&reserved[..size_of::<FpsimdContext>()]).ok()?;
    Some(litebox::platform::FpSimdState64 {
        v: record.vregs,
        fpsr: record.fpsr,
        fpcr: record.fpcr,
    })
}

/// The kernel's `struct rt_sigframe` for aarch64.
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
struct SignalFrame {
    siginfo: Siginfo,
    ucontext: Ucontext,
}

/// The kernel's `struct frame_record`: the saved frame pointer and link
/// register an unwinder follows to step from the handler back into the
/// interrupted frame.
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
struct FrameRecord {
    fp: usize,
    lr: usize,
}

/// The frame is placed at a 16-byte-aligned `sp` and the frame record sits
/// immediately above it, so the frame's own size has to preserve that
/// alignment. `sys_rt_sigreturn` rejects a misaligned `sp` outright.
const _: () = assert!(size_of::<SignalFrame>().is_multiple_of(16));
const _: () = assert!(size_of::<FrameRecord>().is_multiple_of(16));

/// State recorded for a thread that has taken no exception yet.
pub(super) const NO_EXCEPTION: ExceptionInfo = ExceptionInfo {
    exception: Exception(0),
    fault_address: 0,
    esr: 0,
    kernel_mode: false,
};

/// Maps an aarch64 exception class to the signal Linux raises for it, together
/// with the address reported in the accompanying `si_addr`.
pub(super) fn exception_signal(info: &ExceptionInfo) -> (Signal, usize) {
    let signal = match info.exception {
        // A `BRK` or a hardware breakpoint is a debug trap.
        Exception::BRK64 | Exception::BREAKPOINT_LOWER_EL | Exception::BREAKPOINT_CURRENT_EL => {
            Signal::SIGTRAP
        }
        // Class 0 is "unknown reason", which is what an undefined instruction
        // raises; the kernel's `do_el0_undef` turns it into SIGILL. A trapped
        // system-register access lands in the same place.
        Exception::UNKNOWN | Exception::SYSTEM_REGISTER_TRAP => Signal::SIGILL,
        Exception::FP_EXCEPTION_A64 => Signal::SIGFPE,
        // Aborts and anything unclassified become SIGSEGV, mirroring how the
        // x86-64 path treats page faults and unknown vectors. There may be a
        // more appropriate signal in some cases (e.g., SIGBUS for an alignment
        // fault), which needs the abort's fault-status code to distinguish.
        _ => Signal::SIGSEGV,
    };
    let fault_address = match info.exception {
        Exception::DATA_ABORT_LOWER_EL
        | Exception::DATA_ABORT_CURRENT_EL
        | Exception::INSTRUCTION_ABORT_LOWER_EL
        | Exception::INSTRUCTION_ABORT_CURRENT_EL => info.fault_address,
        _ => 0,
    };
    (signal, fault_address)
}

pub(super) fn uctx_addr(ctx: &PtRegs) -> usize {
    // `sp` points at the whole frame, whose first member is the `siginfo`.
    ctx.sp.wrapping_add(offset_of!(SignalFrame, ucontext))
}

pub(super) fn sp(ctx: &PtRegs) -> usize {
    ctx.sp
}

pub(super) fn get_signal_frame(sp: usize, _action: &SigAction) -> usize {
    // Reserve the frame record at the top, then the frame below it. Both sizes
    // are 16-byte multiples (asserted above), so a 16-aligned result stays
    // aligned all the way down.
    let next_frame = sp.wrapping_sub(size_of::<FrameRecord>()) & !15;
    next_frame.wrapping_sub(size_of::<SignalFrame>())
}

/// Address of the frame record belonging to the frame at `frame_addr`.
fn frame_record_addr(frame_addr: usize) -> usize {
    frame_addr.wrapping_add(size_of::<SignalFrame>())
}

impl<Platform: ShimPlatform> SignalState<Platform> {
    pub(super) fn write_signal_frame(
        &self,
        platform: &Platform,
        frame_addr: usize,
        siginfo: &Siginfo,
        action: &SigAction,
        ctx: &mut PtRegs,
    ) -> Result<(), DeliverFault> {
        // The kernel falls back to the vDSO's `sigtramp` when the guest
        // supplies no `sa_restorer`. LiteBox exposes no vDSO to the guest, but
        // a platform can provide its own equivalent trampoline (see
        // `SystemInfoProvider::get_sigreturn_trampoline_address`'s doc
        // comment) -- fall back to that, and only refuse delivery (better
        // than entering the handler with a wild `x30`, matching the x86-64
        // path) when the platform has no trampoline to offer either.
        let restorer = if action.flags.contains(SaFlags::RESTORER) {
            action.restorer
        } else {
            platform
                .get_sigreturn_trampoline_address()
                .ok_or(DeliverFault)?
        };

        let mut regs = [0u64; AARCH64_GENERAL_REGISTER_COUNT];
        for (slot, value) in regs.iter_mut().zip(ctx.regs.iter()) {
            *slot = *value as u64;
        }

        let last_exception = self.last_exception.get();
        let frame = SignalFrame {
            siginfo: siginfo.clone(),
            ucontext: Ucontext {
                flags: 0,
                link: 0, // core::ptr::null_mut()
                stack: self.altstack.get(),
                sigmask: self.blocked.get(),
                __unused: [0; 1024 / 8 - size_of::<SigSet>()],
                __align_pad: [0; 8],
                mcontext: Sigcontext {
                    fault_address: last_exception.fault_address as u64,
                    regs,
                    sp: ctx.sp as u64,
                    pc: ctx.pc as u64,
                    pstate: ctx.pstate,
                    __reserved_pad: [0; 8],
                    // A real `fpsimd_context` record holding the guest's
                    // current vector state, followed by a well-formed
                    // zero-`magic` terminator (see `fpsimd_reserved`).
                    __reserved: fpsimd_reserved(&platform.get_fp_state()),
                },
            },
        };

        let frame_ptr = UserPtrMut::from_usize(frame_addr);
        frame_ptr
            .write_at_offset::<Platform>(0, frame)
            .ok_or(DeliverFault)?;

        let record_addr = frame_record_addr(frame_addr);
        let record_ptr = UserPtrMut::<FrameRecord>::from_usize(record_addr);
        record_ptr
            .write_at_offset::<Platform>(
                0,
                FrameRecord {
                    fp: ctx.regs[29],
                    lr: ctx.regs[30],
                },
            )
            .ok_or(DeliverFault)?;

        ctx.sp = frame_addr;
        ctx.pc = action.sigaction;
        ctx.regs[0] = siginfo.signo.reinterpret_as_unsigned() as usize;
        if action.flags.contains(SaFlags::SIGINFO) {
            ctx.regs[1] = frame_addr.wrapping_add(offset_of!(SignalFrame, siginfo));
            ctx.regs[2] = frame_addr.wrapping_add(offset_of!(SignalFrame, ucontext));
        }
        ctx.regs[29] = record_addr;
        ctx.regs[30] = restorer;
        Ok(())
    }
}

pub(super) fn restore_sigcontext<Platform: ShimPlatform>(
    platform: &Platform,
    ctx: &mut PtRegs,
    sigctx: &Sigcontext,
) -> usize {
    let Sigcontext {
        fault_address: _,
        ref regs,
        sp,
        pc,
        pstate,
        __reserved_pad: _,
        ref __reserved,
    } = *sigctx;

    // A handler may have inspected or modified its frame's vector state
    // before calling `sigreturn` (e.g. fixing up an FP exception); restore
    // whatever is genuinely there. A frame with no valid `fpsimd_context`
    // record (never written by `write_signal_frame`, or a handler that built
    // its own frame from scratch) leaves the guest's FP state untouched,
    // matching this platform's behavior before any of this was modelled.
    if let Some(fp) = parse_fpsimd_reserved(__reserved) {
        platform.set_fp_state(&fp);
    }

    for (slot, value) in ctx.regs.iter_mut().zip(regs.iter()) {
        *slot = (*value).trunc();
    }
    ctx.sp = sp.trunc();
    ctx.pc = pc.trunc();
    // Keep only the PSTATE bits a guest is allowed to own. Everything else --
    // exception level, execution state, mask bits, illegal-state, single-step --
    // is imposed by the ABI, which is what the kernel's `valid_user_regs` check
    // enforces on this path.
    ctx.pstate = pstate & litebox_common_linux::arch::SAFE_USER_PSTATE;
    // Returning from a handler leaves no syscall in flight, so no restart logic
    // should re-issue the interrupted call.
    ctx.syscallno = NO_SYSCALL;

    ctx.regs[0]
}
