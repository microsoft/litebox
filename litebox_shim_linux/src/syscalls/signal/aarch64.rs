// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Partial implementation of the AArch64 Linux signal-frame ABI.
//!
//! LiteBox supplies a fallback restorer because it exposes no guest vDSO.

use crate::syscalls::signal::{DeliverFault, SignalState};
use crate::{ShimPlatform, Task, UserPtr, UserPtrMut};
use core::mem::offset_of;
use litebox::arch::aarch64::GENERAL_REGISTER_COUNT;
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::PAGE_SIZE;
use litebox_common_linux::{
    MapFlags, ProtFlags, PtRegs,
    signal::{
        SaFlags, SigAction, Siginfo, Ucontext,
        aarch64::{Sigcontext, read_guest_vector_records, write_vector_records},
    },
};
use litebox_trampoline::{
    aarch64::RT_SIGRETURN_TRAMPOLINE_BYTES, aarch64::emit_rt_sigreturn_trampoline,
};
use zerocopy::{FromBytes, IntoBytes};

#[repr(align(16))]
struct AlignedContextRecords([u8; 4096]);

/// Linux `rt_sigframe` followed by an unwind-link frame record. Guest vector
/// lengths never need an `extra_context` record.
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

/// Returns the most stack `deliver_signal` can use, reported as `AT_MINSIGSTKSZ`.
///
/// The result is the same for every guest vector length: each offered VL's live
/// `sve_context` fits `__reserved` (`sve_context_fits_reserved`), so `SignalFrame` has a fixed
/// size.
pub(crate) fn max_signal_frame_size() -> usize {
    // Worst-case alignment in `get_signal_frame`, plus the SVC frame that the fallback restorer
    // pushes below the frame without `SA_RESTORER`.
    let padding = 15 + usize::from(litebox_trampoline::aarch64::SVC_FRAME_BYTES);
    (core::mem::size_of::<SignalFrame>() + padding).next_multiple_of(16)
}

pub(super) fn get_signal_frame(sp: usize, _action: &SigAction) -> Option<usize> {
    let frame_addr = sp.checked_sub(core::mem::size_of::<SignalFrame>())?;
    // Linux AArch64 signal entry requires a 16-byte-aligned stack pointer.
    Some(frame_addr & !15)
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

        let mut reserved = AlignedContextRecords([0; 4096]);
        write_vector_records(&mut reserved.0, &platform.get_guest_vector_state());
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
                    __reserved: reserved.0,
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

/// Restores `ctx` and the guest vector state from `sigctx`, which `rt_sigreturn` read from the
/// signal frame at `ctx.sp`.
pub(super) fn restore_sigcontext<Platform: ShimPlatform>(
    platform: &Platform,
    ctx: &mut PtRegs,
    sigctx: &Sigcontext,
) -> Option<usize> {
    let reserved_addr = uctx_addr(ctx)
        .wrapping_add(offset_of!(Ucontext, mcontext))
        .wrapping_add(offset_of!(Sigcontext, __reserved));
    let read_guest = |addr, bytes: &mut [u8]| {
        UserPtr::<u8>::from_usize(addr).copy_to_slice::<Platform>(0, bytes)
    };
    let mut vector_state = platform.get_guest_vector_state();
    read_guest_vector_records(
        &sigctx.__reserved,
        reserved_addr,
        ctx.sp,
        read_guest,
        &mut vector_state,
    )
    .ok()?;
    platform.set_guest_vector_state(&vector_state);
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

    Some(ctx.regs[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::signal::{SaFlags, SigSet};

    fn action(flags: SaFlags, restorer: usize) -> SigAction {
        SigAction {
            sigaction: 0x1000,
            flags,
            __pad: 0,
            restorer,
            mask: SigSet::empty(),
        }
    }

    /// A delivered frame carries the guest's FP/SIMD state, and its live SVE
    /// state if the platform gives guests a vector length. `rt_sigreturn`
    /// restores a handler's edit to `fpsimd_context`, which with live SVE state
    /// replaces the low 128 bits of the Z register. With or without
    /// `SA_RESTORER`, the frame fits an alternate stack of
    /// `max_signal_frame_size()` bytes.
    #[test]
    fn signal_frames_carry_and_restore_vector_state() {
        use crate::syscalls::tests::{TestPlatform, init_platform};
        use litebox::arch::aarch64::vector::VectorArea;
        use litebox::platform::{GuestVectorStateProvider as _, ThreadProvider as _};
        use litebox_common_linux::signal::{
            SigAltStack, Signal, SsFlags,
            aarch64::{fpsimd_context_mut, read_vector_records},
        };

        let task = init_platform();
        let platform = task.global.platform;
        let mut state = platform.get_guest_vector_state();
        let sve_vl = state.sve_vl();
        state.set_fpsimd(&core::array::from_fn(|index| index as u128), 0x10, 0x20);
        if let Some(vl) = sve_vl {
            let payload: alloc::vec::Vec<u8> = (0..vl.payload_size())
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect();
            assert!(state.set_sve_payload(&payload));
        }

        TestPlatform::run_test_thread(|| {
            for flags in [SaFlags::RESTORER, SaFlags::empty()] {
                platform.set_guest_vector_state(&state);
                let act = action(SaFlags::SIGINFO | SaFlags::ONSTACK | flags, 0x2000);
                task.sys_rt_sigaction(
                    Signal::SIGUSR1,
                    Some(crate::UserPtr::from_ptr(&raw const act)),
                    None,
                    size_of::<SigSet>(),
                )
                .unwrap();
                task.send_signal(
                    Signal::SIGUSR1,
                    crate::syscalls::signal::siginfo_kill(Signal::SIGUSR1),
                );
                let mut stack = alloc::vec![0u8; 4 * PAGE_SIZE];
                let stack_top = stack.as_mut_ptr() as usize + stack.len();
                // A top 15 bytes past a 16-byte boundary needs the most alignment. The size is
                // below MINSIGSTKSZ, which `sigaltstack` would reject. Delivery fails unless the
                // frame, including any prefix, stays on the alternate stack.
                let altstack_top = (stack_top - PAGE_SIZE).next_multiple_of(16) - 1;
                task.signals.altstack.set(SigAltStack {
                    sp: altstack_top - max_signal_frame_size(),
                    flags: SsFlags::empty(),
                    __pad: 0,
                    size: max_signal_frame_size(),
                });
                let mut ctx = PtRegs {
                    sp: stack_top,
                    ..PtRegs::default()
                };
                task.process_signals(&mut ctx, None);
                assert_eq!(ctx.pc, act.sigaction, "the handler must be entered");
                assert!(ctx.sp < altstack_top);

                // SAFETY: `ctx.regs[2]` addresses the frame's ucontext in `stack`.
                let reserved =
                    unsafe { &mut (*(ctx.regs[2] as *mut Ucontext)).mcontext.__reserved };
                let mut delivered = VectorArea::initial(sve_vl);
                assert_eq!(read_vector_records(reserved, &mut delivered), Ok(()));
                assert_eq!(delivered, state);

                let mut expected = state.clone();
                let mut vregs = *state.vregs();
                vregs[1] = u128::MAX;
                fpsimd_context_mut(reserved).unwrap().vregs[1] = u128::MAX;
                expected.set_fpsimd(&vregs, 0x10, 0x20);

                platform.set_guest_vector_state(&VectorArea::default());
                task.sys_rt_sigreturn(&mut ctx);
                assert_eq!(platform.get_guest_vector_state(), expected);
                assert_eq!(ctx.sp, stack_top);
            }
        });
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
}
