// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux x86-64 signal frames, including standard-layout XSAVE state.
//!
//! Legacy-only and null FP-state pointers are also accepted on `rt_sigreturn`.

use crate::syscalls::signal::{DeliverFault, SignalState};
use crate::{ShimPlatform, Task, UserPtr, UserPtrMut};
use alloc::{vec, vec::Vec};
use core::mem::{offset_of, size_of_val};
use litebox::arch::x86_64::xstate::{XsaveArea, XsaveHeader, XsaveLayout, XsaveLegacyArea};
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{
    PtRegs,
    signal::{
        SaFlags, SigAction, Siginfo, Ucontext,
        x86_64::{FpState, FpxSwBytes, Sigcontext},
    },
};
use zerocopy::{FromBytes, IntoBytes};

const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
const SW_RESERVED_OFFSET: usize = offset_of!(FpState, sw_reserved);
const XSAVE_HEADER_SIZE: usize = size_of::<XsaveHeader>();
const LEGACY_SIZE: usize = size_of::<XsaveLegacyArea>();
const UC_FP_XSTATE: usize = 1;

fn signal_xstate(state: &XsaveArea, layout: &XsaveLayout) -> Option<Vec<u8>> {
    let mut bytes = state.as_bytes().to_vec();
    bytes[..LEGACY_SIZE].copy_from_slice(state.materialized_legacy_area().as_bytes());
    // Signal handlers may edit legacy registers even when XSAVE marked them
    // initial. Linux makes those edits effective without requiring header edits.
    bytes[LEGACY_SIZE..LEGACY_SIZE + 8].copy_from_slice(&(state.xstate_bv() | 3).to_ne_bytes());
    let sw = FpxSwBytes {
        magic1: FP_XSTATE_MAGIC1,
        extended_size: u32::try_from(layout.size.checked_add(size_of_val(&FP_XSTATE_MAGIC2))?)
            .ok()?,
        xfeatures: layout.mask,
        xstate_size: u32::try_from(layout.size).ok()?,
        padding: [0; 7],
    };
    bytes[SW_RESERVED_OFFSET..LEGACY_SIZE].copy_from_slice(sw.as_bytes());
    bytes.extend_from_slice(&FP_XSTATE_MAGIC2.to_ne_bytes());
    Some(bytes)
}

fn read_sigframe_state<Platform: ShimPlatform>(addr: usize) -> Option<XsaveArea> {
    let layout = XsaveLayout::get();
    if addr == 0 {
        return Some(XsaveArea::initial(layout));
    }
    if !addr.is_multiple_of(16) {
        return None;
    }
    let legacy = UserPtr::<[u8; LEGACY_SIZE]>::from_usize(addr).read_at_offset::<Platform>(0)?;
    let sw = FpxSwBytes::read_from_bytes(&legacy[SW_RESERVED_OFFSET..]).ok()?;
    let xstate_size = sw.xstate_size as usize;
    let mut extended = sw.magic1 == FP_XSTATE_MAGIC1
        && (LEGACY_SIZE + XSAVE_HEADER_SIZE..=layout.size).contains(&xstate_size)
        && xstate_size <= sw.extended_size as usize;
    if extended {
        let trailer = UserPtr::<u32>::from_usize(addr.checked_add(xstate_size)?)
            .read_at_offset::<Platform>(0)?;
        extended = trailer == FP_XSTATE_MAGIC2;
    }

    let mut bytes = vec![0; layout.size];
    if extended {
        if !addr.is_multiple_of(64) {
            return None;
        }
        let saved = UserPtr::<u8>::from_usize(addr).to_owned_slice::<Platform>(xstate_size)?;
        bytes[..xstate_size].copy_from_slice(&saved);
    } else {
        // Linux accepts a legacy-only frame when XSAVE metadata or its trailer
        // is absent. Extended components then return to architectural init state.
        bytes[..LEGACY_SIZE].copy_from_slice(&legacy);
        bytes[LEGACY_SIZE..LEGACY_SIZE + 8].copy_from_slice(&3u64.to_ne_bytes());
    }
    let mut state = XsaveArea::from_bytes(&bytes, layout)?;
    if extended {
        for component in &layout.components {
            if state.xstate_bv() & (1 << component.id) != 0
                && component.offset + component.size > xstate_size
            {
                return None;
            }
        }
        state.header_mut().xstate_bv &= sw.xfeatures;
    }
    Some(state)
}

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

pub(super) fn pc(ctx: &PtRegs) -> usize {
    ctx.rip
}

/// Length of the native `SYSCALL` instruction.
pub(super) const NATIVE_SYSCALL_INSTRUCTION_LEN: usize = 2;

/// Moves `ctx`, a syscall's return, back to the syscall instruction with its number restored.
pub(super) fn restart_syscall(ctx: &mut PtRegs, syscall_instruction_len: usize) {
    ctx.rax = ctx.orig_rax;
    ctx.rip = ctx.rip.wrapping_sub(syscall_instruction_len);
}

pub(super) fn get_signal_frame(sp: usize, _action: &SigAction) -> Option<usize> {
    let mut frame_addr = sp;

    // Skip the redzone.
    frame_addr = frame_addr.checked_sub(128)?;

    // Linux places a separately 64-byte-aligned XSAVE area above rt_sigframe.
    frame_addr = frame_addr.checked_sub(
        XsaveLayout::get()
            .size
            .checked_add(size_of_val(&FP_XSTATE_MAGIC2))?,
    )? & !63;

    // Space for the signal frame.
    frame_addr = frame_addr.checked_sub(core::mem::size_of::<SignalFrame>())?;

    // Align the frame (offset by 8 bytes for return address)
    frame_addr &= !15;
    frame_addr.checked_sub(8)
}

/// Requires the guest's own `sa_restorer`; LiteBox has no x86-64 vDSO fallback.
pub(super) fn sigreturn_trampoline<Platform: ShimPlatform>(
    _task: &Task<Platform>,
    action: &SigAction,
) -> Result<usize, DeliverFault> {
    if !action.flags.contains(SaFlags::RESTORER) {
        return Err(DeliverFault);
    }
    Ok(action.restorer)
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
        let layout = XsaveLayout::get();
        let fpstate_addr = frame_addr
            .checked_add(size_of::<SignalFrame>())
            .and_then(|addr| addr.checked_add(63))
            .ok_or(DeliverFault)?
            & !63;
        let state =
            signal_xstate(&platform.get_guest_vector_state(), layout).ok_or(DeliverFault)?;
        UserPtrMut::from_usize(fpstate_addr)
            .write_slice_at_offset::<Platform>(0, &state)
            .ok_or(DeliverFault)?;
        let frame = SignalFrame {
            return_address: sigreturn_trampoline,
            ucontext: Ucontext {
                flags: UC_FP_XSTATE,
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
                    cs: ctx.cs.trunc(),
                    gs: 0,
                    fs: 0,
                    ss: ctx.ss.trunc(),
                    err: last_exception.error_code.into(),
                    trapno: last_exception.exception.0.into(),
                    oldmask: self.blocked.get().as_u64(),
                    cr2: last_exception.cr2 as u64,
                    fpstate: fpstate_addr as u64,
                    reserved1: [0; 8],
                },
                sigmask: self.blocked.get(),
            },
            siginfo: siginfo.clone(),
        };

        let frame_ptr = UserPtrMut::from_usize(frame_addr);
        frame_ptr
            .write_at_offset::<Platform>(0, frame)
            .ok_or(DeliverFault)?;

        ctx.rsp = frame_addr;
        ctx.rip = action.sigaction;
        ctx.rdi = siginfo.signo.reinterpret_as_unsigned() as usize;
        ctx.rsi = frame_addr.wrapping_add(offset_of!(SignalFrame, siginfo));
        ctx.rdx = frame_addr.wrapping_add(offset_of!(SignalFrame, ucontext));
        ctx.rax = 0;
        let direction_flag: usize = litebox::arch::x86_64::RFlags::DF.bits().trunc();
        ctx.eflags &= !direction_flag;
        platform.set_guest_vector_state(&XsaveArea::initial(layout));
        Ok(())
    }
}

pub(super) fn restore_sigcontext<Platform: ShimPlatform>(
    platform: &Platform,
    ctx: &mut PtRegs,
    sigctx: &litebox_common_linux::signal::x86_64::Sigcontext,
) -> Option<usize> {
    let vector_state = read_sigframe_state::<Platform>(sigctx.fpstate.trunc())?;
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

    ctx.r8 = r8.trunc();
    ctx.r9 = r9.trunc();
    ctx.r10 = r10.trunc();
    ctx.r11 = r11.trunc();
    ctx.r12 = r12.trunc();
    ctx.r13 = r13.trunc();
    ctx.r14 = r14.trunc();
    ctx.r15 = r15.trunc();
    ctx.rdi = rdi.trunc();
    ctx.rsi = rsi.trunc();
    ctx.rbp = rbp.trunc();
    ctx.rbx = rbx.trunc();
    ctx.rdx = rdx.trunc();
    ctx.rax = rax.trunc();
    ctx.rcx = rcx.trunc();
    ctx.rsp = rsp.trunc();
    ctx.rip = rip.trunc();
    ctx.eflags = rflags.trunc();

    platform.set_guest_vector_state(&vector_state);

    Some(ctx.rax)
}
