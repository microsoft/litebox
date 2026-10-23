// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Partial implementation of the AArch64 Linux signal-frame ABI.
//!
//! LiteBox supplies a fallback restorer because it exposes no guest vDSO.

use crate::syscalls::signal::{DeliverFault, SignalState};
use crate::{ShimPlatform, Task, UserPtrMut};
use core::mem::offset_of;
use litebox::arch::aarch64::GENERAL_REGISTER_COUNT;
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::PAGE_SIZE;
use litebox_common_linux::{
    MapFlags, ProtFlags, PtRegs,
    signal::{
        SaFlags, SigAction, Siginfo, Ucontext,
        aarch64::{
            GuestVectorState, RESERVED_SIZE, Sigcontext, SveVectorLength, UnknownRecords,
            parse_signal_records,
        },
    },
};
use litebox_trampoline::{
    aarch64::RT_SIGRETURN_TRAMPOLINE_BYTES, aarch64::emit_rt_sigreturn_trampoline,
};
use zerocopy::{FromBytes, IntoBytes};

/// Reads vector state from the guest's `__reserved`, validating SVE against
/// `host_vl`; returns `None` for invalid records.
fn read_vector_state(
    reserved: &[u8; RESERVED_SIZE],
    host_vl: Option<SveVectorLength>,
) -> Option<GuestVectorState> {
    let records = parse_signal_records(reserved, UnknownRecords::Reject).ok()?;
    let mut state = GuestVectorState::new(host_vl);
    state.load_signal_records(&records).ok()?;
    Some(state)
}

/// Linux `rt_sigframe` followed by an unwind-link frame record. Dynamic extra
/// context is omitted.
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
struct SignalFrame {
    siginfo: Siginfo,
    ucontext: Ucontext,
    next_frame_fp: usize,
    next_frame_lr: usize,
}

pub(super) fn uctx_addr(ctx: &PtRegs) -> usize {
    ctx.sp.wrapping_add(offset_of!(SignalFrame, ucontext))
}

pub(super) fn sp(ctx: &PtRegs) -> usize {
    ctx.sp
}

pub(super) fn pc(ctx: &PtRegs) -> usize {
    ctx.pc
}

/// Length of the native `SVC` instruction.
pub(super) const NATIVE_SYSCALL_INSTRUCTION_LEN: usize = 4;

/// Moves `ctx`, a syscall's return, back to the syscall instruction with its first argument
/// restored.
pub(super) fn restart_syscall(ctx: &mut PtRegs, syscall_instruction_len: usize) {
    ctx.regs[0] = ctx.orig_x0;
    ctx.pc = ctx.pc.wrapping_sub(syscall_instruction_len);
}

/// AArch64 has no red zone below the stack pointer.
pub(super) const RED_ZONE_SIZE: usize = 0;

pub(super) fn get_signal_frame(sp: usize, _action: &SigAction) -> Option<usize> {
    let frame_addr = sp.checked_sub(core::mem::size_of::<SignalFrame>())?;
    // Linux AArch64 signal entry requires a 16-byte-aligned stack pointer.
    Some(frame_addr & !15)
}

/// Returns the SVE vector length of guest vector state, which is the host's,
/// or `None` when the platform does not manage guest SVE state.
pub(crate) fn guest_sve_vl<Platform: ShimPlatform>(platform: &Platform) -> Option<SveVectorLength> {
    platform.get_guest_vector_state().sve_vl()
}

fn requested_restorer(action: &SigAction) -> Option<usize> {
    action
        .flags
        .contains(SaFlags::RESTORER)
        .then_some(action.restorer)
}

fn handler_arguments(action: &SigAction, frame_addr: usize) -> Option<(usize, usize)> {
    action.flags.contains(SaFlags::SIGINFO).then(|| {
        (
            frame_addr.wrapping_add(offset_of!(SignalFrame, siginfo)),
            frame_addr.wrapping_add(offset_of!(SignalFrame, ucontext)),
        )
    })
}

/// Returns a cached synthetic `rt_sigreturn` guest mapping.
/// The cache is reset on `execve`; guest VM operations can invalidate it.
pub(super) fn sigreturn_trampoline<Platform: ShimPlatform>(
    task: &Task<Platform>,
    action: &SigAction,
) -> Result<usize, DeliverFault> {
    if let Some(restorer) = requested_restorer(action) {
        return Ok(restorer);
    }

    let mut cached = task.process().sigreturn_trampoline.lock();
    if let Some(addr) = *cached {
        return Ok(addr);
    }

    const { assert!(RT_SIGRETURN_TRAMPOLINE_BYTES <= PAGE_SIZE) };

    let page = task
        .do_mmap(
            None,
            PAGE_SIZE,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            |_| Ok(0),
        )
        .map_err(|_| DeliverFault)?;

    let callback = task.global.platform.get_syscall_entry_point();
    page.cast::<[u8; RT_SIGRETURN_TRAMPOLINE_BYTES]>()
        .write_at_offset::<Platform>(
            0,
            emit_rt_sigreturn_trampoline(callback).map_err(|_| DeliverFault)?,
        )
        .ok_or(DeliverFault)?;

    // Drop write before execute; the guest never needs write access.
    task.sys_mprotect_raw(page, PAGE_SIZE, ProtFlags::PROT_READ | ProtFlags::PROT_EXEC)
        .map_err(|_| DeliverFault)?;

    let addr = page.as_usize();
    *cached = Some(addr);
    Ok(addr)
}

impl<Platform: ShimPlatform> SignalState<Platform> {
    /// Like Linux, handlers retain the interrupted vector state, including live SVE.
    pub(super) fn write_signal_frame(
        &self,
        platform: &Platform,
        frame_addr: usize,
        siginfo: &Siginfo,
        action: &SigAction,
        ctx: &mut PtRegs,
        sigreturn_trampoline: usize,
    ) -> Result<(), DeliverFault> {
        let last_exception = self.last_exception.get();

        let mut regs = [0u64; GENERAL_REGISTER_COUNT];
        for (dst, src) in regs.iter_mut().zip(ctx.regs.iter()) {
            *dst = *src as u64;
        }

        let mut reserved = [0; RESERVED_SIZE];
        platform
            .get_guest_vector_state()
            .write_signal_records(&mut reserved)
            .ok_or(DeliverFault)?;
        let frame = SignalFrame {
            siginfo: siginfo.clone(),
            ucontext: Ucontext {
                flags: 0,
                link: 0, // core::ptr::null_mut(),
                stack: self.altstack.get(),
                sigmask: self.blocked.get(),
                __unused: [0; _],
                __align_pad: [0; _],
                mcontext: Sigcontext {
                    fault_address: last_exception.fault_address as u64,
                    regs,
                    sp: ctx.sp as u64,
                    pc: ctx.pc as u64,
                    pstate: ctx.pstate,
                    __reserved_pad: [0; _],
                    __reserved: reserved,
                },
            },
            next_frame_fp: ctx.regs[29],
            next_frame_lr: ctx.regs[30],
        };

        let frame_ptr = UserPtrMut::from_usize(frame_addr);
        frame_ptr
            .write_at_offset::<Platform>(0, frame)
            .ok_or(DeliverFault)?;

        ctx.sp = frame_addr;
        ctx.pc = action.sigaction;
        ctx.regs[0] = usize::try_from(siginfo.signo.reinterpret_as_unsigned())
            .expect("a u32 always fits in a 64-bit usize");
        if let Some((siginfo, ucontext)) = handler_arguments(action, frame_addr) {
            ctx.regs[1] = siginfo;
            ctx.regs[2] = ucontext;
        }
        // Link the handler's frame chain to the interrupted frame.
        ctx.regs[29] = frame_addr.wrapping_add(offset_of!(SignalFrame, next_frame_fp));
        ctx.regs[30] = sigreturn_trampoline;
        // PSTATE carries over into the handler: `setup_return` adjusts only
        // TCO and BTYPE, neither of which LiteBox models. `copy_signal_context`
        // has already masked it to the bits a guest may own.
        ctx.syscallno = litebox_common_linux::arch::NO_SYSCALL;
        Ok(())
    }
}

/// Restores scalar state before validating vector records, as Linux does;
/// returns restored X0, or `None` with vector state unchanged for invalid records.
pub(super) fn restore_sigcontext<Platform: ShimPlatform>(
    platform: &Platform,
    ctx: &mut PtRegs,
    sigctx: &Sigcontext,
) -> Option<usize> {
    let Sigcontext {
        fault_address: _,
        regs,
        sp,
        pc,
        pstate,
        __reserved_pad: _,
        __reserved: _,
    } = sigctx;

    for (dst, src) in ctx.regs.iter_mut().zip(regs.iter()) {
        *dst = src.trunc();
    }
    ctx.sp = sp.trunc();
    ctx.pc = pc.trunc();
    // The guest chose this value, so only the bits a guest may set survive.
    ctx.pstate = *pstate & litebox_common_linux::arch::SAFE_USER_PSTATE;
    ctx.syscallno = litebox_common_linux::arch::NO_SYSCALL;

    let vector_state = read_vector_state(&sigctx.__reserved, guest_sve_vl(platform))?;
    platform.set_guest_vector_state(&vector_state);
    Some(ctx.regs[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UserPtr;
    use crate::syscalls::signal::siginfo_kill;
    use crate::syscalls::tests::{TestPlatform, init_platform, test_platform};
    use alloc::vec;
    use alloc::vec::Vec;
    use litebox::platform::GuestVectorStateProvider as _;
    use litebox_common_linux::signal::{SaFlags, SigSet, Signal};

    fn action(flags: SaFlags, restorer: usize) -> SigAction {
        SigAction {
            sigaction: 0x1000,
            flags,
            __pad: 0,
            restorer,
            mask: SigSet::empty(),
        }
    }

    #[test]
    fn sa_restorer_selects_the_guest_restorer() {
        let set = action(SaFlags::RESTORER, 0x1234_5678);
        assert_eq!(requested_restorer(&set), Some(0x1234_5678));

        let unset = action(SaFlags::empty(), 0x1234_5678);
        assert_eq!(requested_restorer(&unset), None);
    }

    #[test]
    fn handler_arguments_are_only_supplied_for_sa_siginfo() {
        let plain = action(SaFlags::empty(), 0);
        assert_eq!(handler_arguments(&plain, 0x8000), None);

        let siginfo = action(SaFlags::SIGINFO, 0);
        assert_eq!(
            handler_arguments(&siginfo, 0x8000),
            Some((
                0x8000 + offset_of!(SignalFrame, siginfo),
                0x8000 + offset_of!(SignalFrame, ucontext),
            ))
        );
    }

    /// State with patterned FP/SIMD registers and room for SVE at `sve_vl`.
    fn fpsimd_state(sve_vl: Option<SveVectorLength>) -> GuestVectorState {
        let mut state = GuestVectorState::new(sve_vl);
        *state.v_registers_mut() = core::array::from_fn(|index| index as u128 * 0x101);
        state.set_fpsr(0x1234);
        state.set_fpcr(0x5678);
        state
    }

    fn live_state(vl: SveVectorLength) -> GuestVectorState {
        let registers: Vec<u8> = (0..vl.registers_size())
            .map(|i| u8::try_from(i % 253).unwrap())
            .collect();
        let mut state = fpsimd_state(Some(vl));
        state.set_sve_registers(&registers).unwrap();
        state
    }

    fn records(state: &GuestVectorState) -> [u8; RESERVED_SIZE] {
        let mut records = [0; RESERVED_SIZE];
        state.write_signal_records(&mut records).unwrap();
        records
    }

    /// Delivers a signal at the end of `stack` with `state` as the platform's
    /// guest vector state.
    fn deliver(stack: &mut [u128], state: &GuestVectorState) -> PtRegs {
        let platform = test_platform();
        platform.set_guest_vector_state(state);
        let signals = SignalState::<TestPlatform>::new_process();
        let action = action(SaFlags::SIGINFO, 0);
        let mut regs = [0; 31];
        regs[29] = 0x2929;
        regs[30] = 0x3030;
        let sp = stack.as_mut_ptr_range().end.addr();
        let mut ctx = PtRegs {
            regs,
            sp,
            pc: 0x4000,
            ..PtRegs::default()
        };
        let frame = get_signal_frame(sp, &action).unwrap();
        assert!(frame >= stack.as_ptr().addr());
        let siginfo = siginfo_kill(Signal::SIGUSR1);
        let written =
            signals.write_signal_frame(platform, frame, &siginfo, &action, &mut ctx, 0x7000);
        assert!(written.is_ok());
        ctx
    }

    fn read_ucontext(ctx: &PtRegs) -> Ucontext {
        UserPtr::<Ucontext>::from_usize(uctx_addr(ctx))
            .read_at_offset::<TestPlatform>(0)
            .unwrap()
    }

    #[test]
    fn signal_frames_round_trip_vector_state() {
        let host_vl = guest_sve_vl(test_platform());
        let mut stack = vec![0u128; 1024];
        for state in core::iter::once(fpsimd_state(host_vl)).chain(host_vl.map(live_state)) {
            let ctx = deliver(&mut stack, &state);
            let reserved = read_ucontext(&ctx).mcontext.__reserved;
            assert_eq!(read_vector_state(&reserved, host_vl), Some(state));
        }
    }

    #[test]
    fn rt_sigreturn_rejects_sve_records_the_host_cannot_restore() {
        let host = SveVectorLength::new(16).unwrap();
        let other = SveVectorLength::MAX;
        let live = records(&live_state(other));
        assert_eq!(read_vector_state(&live, Some(host)), None, "VL mismatch");
        assert_eq!(read_vector_state(&live, None), None, "no SVE on the host");

        // Linux checks the VL of header-only records too.
        let header_only = records(&fpsimd_state(Some(other)));
        assert_eq!(
            read_vector_state(&header_only, Some(host)),
            None,
            "header-only VL mismatch"
        );

        // Records without an SVE record leave SVE state inactive.
        assert_eq!(
            read_vector_state(&records(&fpsimd_state(None)), Some(host)),
            Some(fpsimd_state(Some(host)))
        );
    }

    /// Like Linux, a frame with invalid records still restores the scalar
    /// context, which the forced `SIGSEGV` then reports.
    #[test]
    fn rt_sigreturn_restores_scalar_context_before_rejecting_records() {
        let platform = test_platform();
        let host_vl = guest_sve_vl(platform);
        let mut stack = vec![0u128; 1024];
        let sp = stack.as_mut_ptr_range().end.addr();
        let mut ctx = deliver(&mut stack, &fpsimd_state(host_vl));
        let before = GuestVectorState::new(host_vl);
        platform.set_guest_vector_state(&before);
        let mut ucontext = read_ucontext(&ctx);
        // An FP/SIMD record of the wrong size is invalid.
        ucontext.mcontext.__reserved[4..8].copy_from_slice(&16u32.to_ne_bytes());
        ctx.pc = 0x7000;
        ctx.syscallno = 139;

        assert_eq!(
            restore_sigcontext(platform, &mut ctx, &ucontext.mcontext),
            None
        );
        assert_eq!((ctx.pc, ctx.sp), (0x4000, sp));
        assert_eq!((ctx.regs[29], ctx.regs[30]), (0x2929, 0x3030));
        assert_eq!(ctx.syscallno, litebox_common_linux::arch::NO_SYSCALL);
        assert_eq!(platform.get_guest_vector_state(), before);
    }

    /// Like Linux, `rt_sigreturn` rejects an unaligned SP before it installs
    /// the frame's signal mask.
    #[test]
    fn rt_sigreturn_rejects_an_unaligned_sp_before_installing_the_mask() {
        let task = init_platform();
        let mut stack = vec![0u128; 512];
        let mut ctx = PtRegs {
            sp: stack.as_mut_ptr().addr() + 8,
            ..PtRegs::default()
        };
        // Read from this SP, the frame would block every signal.
        UserPtrMut::<SigSet>::from_usize(uctx_addr(&ctx) + offset_of!(Ucontext, sigmask))
            .write_at_offset::<TestPlatform>(0, SigSet::from_u64(u64::MAX))
            .unwrap();
        let blocked = task.signals.blocked.get();
        assert_eq!(task.sys_rt_sigreturn(&mut ctx), 0);
        assert_eq!(task.signals.blocked.get(), blocked);
        assert!(task.pending_signal_set().contains(Signal::SIGSEGV));
    }
}
