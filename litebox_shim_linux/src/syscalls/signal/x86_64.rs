// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::MutPtr;
use crate::syscalls::signal::{DeliverFault, SignalState};
use core::mem::offset_of;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{
    PtRegs,
    signal::{SaFlags, SigAction, Siginfo, Ucontext, x86_64::Sigcontext},
};
use zerocopy::{FromBytes, IntoBytes};

#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
struct SignalFrame {
    return_address: usize,
    ucontext: Ucontext,
    siginfo: Siginfo,
}

pub(super) fn uctx_addr(ctx: &PtRegs) -> usize {
    ctx.rsp
}

pub(super) fn sp(ctx: &PtRegs) -> usize {
    ctx.rsp
}

pub(super) fn get_signal_frame(sp: usize, _action: &SigAction) -> usize {
    let mut frame_addr = sp;

    // Skip the redzone.
    frame_addr = frame_addr.wrapping_sub(128);

    // Space for the signal frame.
    frame_addr = frame_addr.wrapping_sub(core::mem::size_of::<SignalFrame>());

    // Align the frame (offset by 8 bytes for return address)
    frame_addr &= !15;
    frame_addr = frame_addr.wrapping_sub(8);

    frame_addr
}

impl SignalState {
    pub(super) fn write_signal_frame(
        &self,
        frame_addr: usize,
        siginfo: &Siginfo,
        action: &SigAction,
        ctx: &mut PtRegs,
    ) -> Result<(), DeliverFault> {
        if !action.flags.contains(SaFlags::RESTORER) {
            return Err(DeliverFault);
        }

        let last_exception = self.last_exception.get();
        let frame = SignalFrame {
            return_address: action.restorer,
            ucontext: Ucontext {
                flags: 0,
                link: 0, // core::ptr::null_mut(),
                stack: self.altstack.get(),
                mcontext: Sigcontext {
                    r8: ctx.r8 as u64,
                    r9: ctx.r9 as u64,
                    r10: ctx.r10 as u64,
                    r11: ctx.r11 as u64,
                    r12: ctx.r12 as u64,
                    r13: ctx.r13 as u64,
                    r14: ctx.r14 as u64,
                    r15: ctx.r15 as u64,
                    rdi: ctx.rdi as u64,
                    rsi: ctx.rsi as u64,
                    rbp: ctx.rbp as u64,
                    rbx: ctx.rbx as u64,
                    rdx: ctx.rdx as u64,
                    rax: ctx.rax as u64,
                    rcx: ctx.rcx as u64,
                    rsp: ctx.rsp as u64,
                    rip: ctx.rip as u64,
                    rflags: ctx.eflags as u64,
                    cs: ctx.cs.truncate(),
                    gs: 0,
                    fs: 0,
                    ss: ctx.ss.truncate(),
                    err: last_exception.error_code.into(),
                    trapno: last_exception.exception.0.into(),
                    oldmask: self.blocked.get().as_u64(),
                    cr2: last_exception.cr2 as u64,
                    fpstate: 0, // TODO
                    reserved1: [0; 8],
                },
                sigmask: self.blocked.get(),
            },
            siginfo: siginfo.clone(),
        };

        let frame_ptr = MutPtr::from_usize(frame_addr);
        frame_ptr.write_at_offset(0, frame).ok_or(DeliverFault)?;

        ctx.rsp = frame_addr;
        ctx.rip = action.sigaction;
        ctx.rdi = siginfo.signo.reinterpret_as_unsigned() as usize;
        ctx.rsi = frame_addr.wrapping_add(offset_of!(SignalFrame, siginfo));
        ctx.rdx = frame_addr.wrapping_add(offset_of!(SignalFrame, ucontext));
        ctx.rax = 0;
        ctx.eflags &= !litebox_common_linux::EFLAGS_DF;
        Ok(())
    }
}

pub(super) fn restore_sigcontext(
    ctx: &mut PtRegs,
    sigctx: &litebox_common_linux::signal::x86_64::Sigcontext,
) -> usize {
    let litebox_common_linux::signal::x86_64::Sigcontext {
        r8,
        r9,
        r10,
        r11,
        r12,
        r13,
        r14,
        r15,
        rdi,
        rsi,
        rbp,
        rbx,
        rdx,
        rax,
        rcx,
        rsp,
        rip,
        rflags,
        cs: _,
        gs: _,
        fs: _,
        ss: _,
        err: _,
        trapno: _,
        oldmask: _,
        cr2: _,
        fpstate: _,
        reserved1: _,
    } = *sigctx;

    ctx.r8 = r8.truncate();
    ctx.r9 = r9.truncate();
    ctx.r10 = r10.truncate();
    ctx.r11 = r11.truncate();
    ctx.r12 = r12.truncate();
    ctx.r13 = r13.truncate();
    ctx.r14 = r14.truncate();
    ctx.r15 = r15.truncate();
    ctx.rdi = rdi.truncate();
    ctx.rsi = rsi.truncate();
    ctx.rbp = rbp.truncate();
    ctx.rbx = rbx.truncate();
    ctx.rdx = rdx.truncate();
    ctx.rax = rax.truncate();
    ctx.rcx = rcx.truncate();
    ctx.rsp = rsp.truncate();
    ctx.rip = rip.truncate();
    ctx.eflags = rflags.truncate();

    // TODO: restore fpstate

    ctx.rax
}
