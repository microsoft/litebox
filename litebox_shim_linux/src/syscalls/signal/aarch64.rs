// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Partial implementation of the AArch64 Linux signal-frame ABI.
//!
//! LiteBox supplies a fallback restorer because it exposes no guest vDSO.

use crate::syscalls::signal::{DeliverFault, SignalState};
use crate::{ShimPlatform, Task, UserPtrMut};
use core::mem::offset_of;
use litebox::mm::linux::PAGE_SIZE;
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{
    AARCH64_GENERAL_REGISTER_COUNT, MapFlags, ProtFlags, PtRegs,
    signal::{
        SaFlags, SigAction, Siginfo, Ucontext,
        aarch64::{GuestVectorState, Sigcontext},
    },
};
use litebox_syscall_rewriter::aarch64::{
    RT_SIGRETURN_TRAMPOLINE_BYTES, emit_rt_sigreturn_trampoline,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

const FPSIMD_MAGIC: u32 = 0x4650_8001;

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct FpsimdContext {
    magic: u32,
    size: u32,
    fpsr: u32,
    fpcr: u32,
    vregs: [u128; 32],
}

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct Aarch64Ctx {
    magic: u32,
    size: u32,
}

fn write_vector_state(records: &mut [u8; 4096], state: &GuestVectorState) {
    let (fpsimd, rest) = FpsimdContext::mut_from_prefix(records).unwrap();
    fpsimd.magic = FPSIMD_MAGIC;
    fpsimd.size = u32::try_from(size_of::<FpsimdContext>()).unwrap();
    fpsimd.fpsr = state.fpsr;
    fpsimd.fpcr = state.fpcr;
    fpsimd.vregs = state.registers;
    let (end, _) = Aarch64Ctx::mut_from_prefix(rest).unwrap();
    end.magic = 0;
    end.size = 0;
}

fn read_vector_state(records: &[u8; 4096]) -> Option<GuestVectorState> {
    let mut records = records.as_slice();
    let mut state = None;
    loop {
        let (header, _) = Aarch64Ctx::ref_from_prefix(records).ok()?;
        if header.magic == 0 && header.size == 0 {
            return state;
        }
        let size = usize::try_from(header.size).ok()?;
        if size < size_of::<Aarch64Ctx>() || size > records.len() || !size.is_multiple_of(16) {
            return None;
        }
        if header.magic == FPSIMD_MAGIC {
            if state.is_some() || size != size_of::<FpsimdContext>() {
                return None;
            }
            let (fpsimd, _) = FpsimdContext::ref_from_prefix(&records[..size]).ok()?;
            state = Some(GuestVectorState {
                registers: fpsimd.vregs,
                fpsr: fpsimd.fpsr,
                fpcr: fpsimd.fpcr,
            });
        }
        records = &records[size..];
    }
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

pub(super) fn get_signal_frame(sp: usize, _action: &SigAction) -> usize {
    let frame_addr = sp.wrapping_sub(core::mem::size_of::<SignalFrame>());
    // Linux AArch64 signal entry requires a 16-byte-aligned stack pointer.
    frame_addr & !15
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
        .do_mmap_anonymous(
            None,
            PAGE_SIZE,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
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

        let mut regs = [0u64; AARCH64_GENERAL_REGISTER_COUNT];
        for (dst, src) in regs.iter_mut().zip(ctx.regs.iter()) {
            *dst = *src as u64;
        }

        let mut reserved = [0; 4096];
        write_vector_state(&mut reserved, &platform.get_guest_vector_state());
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

pub(super) fn restore_sigcontext<Platform: ShimPlatform>(
    platform: &Platform,
    ctx: &mut PtRegs,
    sigctx: &Sigcontext,
) -> Option<usize> {
    let vector_state = read_vector_state(&sigctx.__reserved)?;
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

    #[test]
    fn vector_state_round_trips_through_signal_records() {
        let expected = GuestVectorState {
            registers: core::array::from_fn(|index| index as u128 * 0x101),
            fpsr: 0x1234,
            fpcr: 0x5678,
        };
        let mut records = [0; 4096];
        write_vector_state(&mut records, &expected);
        assert_eq!(read_vector_state(&records), Some(expected.clone()));

        records[4..8].copy_from_slice(&15u32.to_ne_bytes());
        assert_eq!(read_vector_state(&records), None);

        write_vector_state(&mut records, &expected);
        let terminator = size_of::<FpsimdContext>();
        records[terminator..terminator + 8].fill(0xff);
        assert_eq!(read_vector_state(&records), None);
    }
}
