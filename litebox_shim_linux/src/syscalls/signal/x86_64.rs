// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux x86-64 signal frames, including standard-layout XSAVE state.
//!
//! Legacy-only and null FP-state pointers are also accepted on `rt_sigreturn`.

use crate::syscalls::signal::{DeliverFault, SignalState};
use crate::{ShimPlatform, Task, UserPtr, UserPtrMut};
use alloc::{vec, vec::Vec};
use core::mem::offset_of;
use litebox::arch::x86_64::xstate::{
    XFeatureMask, XSAVE_HEADER_OFFSET, XSAVE_HEADER_SIZE, XSAVE_LEGACY_SIZE, XsaveArea,
    XsaveHeader, XsaveLayout, XsaveLegacyArea,
};
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{
    PtRegs,
    signal::{
        SaFlags, SigAction, Siginfo, Ucontext,
        x86_64::{
            FP_XSTATE_MAGIC1, FP_XSTATE_MAGIC2, FP_XSTATE_MAGIC2_SIZE, FpState, FpxSwBytes,
            Sigcontext, UC_FP_XSTATE, UC_SIGCONTEXT_SS, UC_STRICT_RESTORE_SS,
        },
    },
};
use zerocopy::{FromBytes, IntoBytes};

const SW_RESERVED_OFFSET: usize = offset_of!(FpState, sw_reserved);
const XSTATE_BV_OFFSET: usize = XSAVE_HEADER_OFFSET + offset_of!(XsaveHeader, xstate_bv);
const MXCSR_OFFSET: usize = offset_of!(XsaveLegacyArea, mxcsr);
/// Alignment Linux requires of XSAVE-format signal FP state.
const XSTATE_ALIGN: usize = 64;
/// Alignment Linux requires of legacy FXSAVE-format signal FP state.
const FXSTATE_ALIGN: usize = 16;

/// Stack below the interrupted SP that x86-64 code may use without moving SP.
pub(super) const RED_ZONE_SIZE: usize = 128;

/// Size of the FP state stored above a signal frame: the XSAVE area and its trailer.
fn fpstate_size(layout: &XsaveLayout) -> usize {
    layout.size + FP_XSTATE_MAGIC2_SIZE
}

/// Returns the address of the FP state stored above the signal frame at `frame_addr`.
fn fpstate_addr(frame_addr: usize) -> Option<usize> {
    frame_addr
        .checked_add(size_of::<SignalFrame>())?
        .checked_next_multiple_of(XSTATE_ALIGN)
}

/// Returns the most stack a signal frame can use, reported as `AT_MINSIGSTKSZ`.
pub(crate) fn max_signal_frame_size() -> usize {
    // Worst-case alignment of the FP state and frame in `get_signal_frame`, plus
    // the slot that offsets the frame like a return address.
    let padding = (XSTATE_ALIGN - 1) + 15 + 8;
    (size_of::<SignalFrame>() + fpstate_size(XsaveLayout::get()) + padding).next_multiple_of(16)
}

/// Writes the current guest vector state as signal-frame FP state at `addr`.
fn write_fpstate<Platform: ShimPlatform>(platform: &Platform, addr: usize) -> Option<()> {
    let layout = XsaveLayout::get();
    let mut state = platform.get_guest_vector_state();
    state.sanitize(layout);
    let sw = FpxSwBytes {
        magic1: FP_XSTATE_MAGIC1,
        extended_size: u32::try_from(fpstate_size(layout)).ok()?,
        xfeatures: layout.mask,
        xstate_size: u32::try_from(layout.size).ok()?,
        padding: [0; 7],
    };
    let ptr = UserPtrMut::<u8>::from_usize(addr);
    let bytes = state.as_bytes();
    // `sw` occupies the legacy area's tail, so copy the state around it.
    ptr.copy_from_slice::<Platform>(0, &bytes[..SW_RESERVED_OFFSET])?;
    ptr.copy_from_slice::<Platform>(SW_RESERVED_OFFSET, sw.as_bytes())?;
    ptr.copy_from_slice::<Platform>(XSAVE_LEGACY_SIZE, &bytes[XSAVE_LEGACY_SIZE..])?;
    ptr.copy_from_slice::<Platform>(layout.size, FP_XSTATE_MAGIC2.as_bytes())
}

/// Reads the FP state that `rt_sigreturn` restores from `addr`, following
/// Linux's `__fpu_restore_sig`. Returns `None` where Linux fails the restore.
fn read_fpstate<Platform: ShimPlatform>(addr: usize) -> Option<XsaveArea> {
    let layout = XsaveLayout::get();
    if addr == 0 {
        return Some(XsaveArea::initial(layout));
    }
    if !addr.is_multiple_of(FXSTATE_ALIGN) {
        return None;
    }
    let legacy =
        UserPtr::<[u8; XSAVE_LEGACY_SIZE]>::from_usize(addr).read_at_offset::<Platform>(0)?;
    let sw = FpxSwBytes::read_from_bytes(&legacy[SW_RESERVED_OFFSET..]).ok()?;
    let xstate_size = sw.xstate_size as usize;
    let mut extended = sw.magic1 == FP_XSTATE_MAGIC1
        && (XSAVE_HEADER_OFFSET + XSAVE_HEADER_SIZE..=layout.size).contains(&xstate_size)
        && xstate_size <= sw.extended_size as usize;
    if extended {
        let trailer = UserPtr::<u32>::from_usize(addr.checked_add(xstate_size)?)
            .read_at_offset::<Platform>(0)?;
        extended = trailer == FP_XSTATE_MAGIC2;
    }
    let bytes = if extended {
        read_xstate_bytes::<Platform>(addr, xstate_size, sw.xfeatures, layout)?
    } else {
        legacy_xstate_bytes(&legacy, layout)
    };
    XsaveArea::from_bytes(&bytes, layout)
}

/// Expands a legacy-only frame, which Linux accepts when XSAVE metadata or its
/// trailer is absent. Extended components return to their initial state.
fn legacy_xstate_bytes(legacy: &[u8; XSAVE_LEGACY_SIZE], layout: &XsaveLayout) -> Vec<u8> {
    let mut bytes = vec![0; layout.size];
    bytes[..XSAVE_LEGACY_SIZE].copy_from_slice(legacy);
    bytes[XSTATE_BV_OFFSET..][..8].copy_from_slice(&XFeatureMask::LEGACY.bits().to_ne_bytes());
    bytes
}

/// Reads an XSAVE-format frame of `xstate_size` bytes, restoring only the
/// components in the frame's `xfeatures`, as Linux's XRSTOR mask does.
fn read_xstate_bytes<Platform: ShimPlatform>(
    addr: usize,
    xstate_size: usize,
    xfeatures: u64,
    layout: &XsaveLayout,
) -> Option<Vec<u8>> {
    if !addr.is_multiple_of(XSTATE_ALIGN) {
        return None;
    }
    let mut bytes = UserPtr::<u8>::from_usize(addr)
        .to_owned_slice::<Platform>(xstate_size)?
        .into_vec();
    bytes.resize(layout.size, 0);
    let xstate_bv = u64::read_from_bytes(&bytes[XSTATE_BV_OFFSET..][..8]).ok()?;
    // XRSTOR faults on unsupported XSTATE_BV bits even outside its mask.
    if xstate_bv & !layout.mask != 0 {
        return None;
    }
    // Components outside `xfeatures` return to their initial state without
    // reading their saved bytes.
    let xstate_bv = xstate_bv & xfeatures;
    for component in &layout.components {
        if xstate_bv & (1 << component.id) == 0 {
            continue;
        }
        let component_end = component.offset.checked_add(component.size)?;
        if component_end > layout.size {
            return None;
        }
        if component_end > xstate_size {
            // Linux's xstate_size locates the trailer; XRSTOR still reads active
            // components at their standard offsets beyond that declared size.
            let component_addr = addr.checked_add(component.offset)?;
            let component_bytes = UserPtr::<u8>::from_usize(component_addr)
                .to_owned_slice::<Platform>(component.size)?;
            bytes
                .get_mut(component.offset..component_end)?
                .copy_from_slice(&component_bytes);
        }
    }
    bytes[XSTATE_BV_OFFSET..][..8].copy_from_slice(&xstate_bv.to_ne_bytes());
    if xfeatures & XFeatureMask::SSE.bits() == 0 {
        // XRSTOR loads MXCSR, faulting on unsupported bits, only for SSE or
        // AVX. Linux then reinitializes the SSE state omitted from `xfeatures`.
        let mxcsr = u32::read_from_bytes(&bytes[MXCSR_OFFSET..][..4]).ok()?;
        if xfeatures & XFeatureMask::AVX.bits() != 0 && mxcsr & !layout.mxcsr_mask != 0 {
            return None;
        }
        bytes[MXCSR_OFFSET..][..4].copy_from_slice(&XsaveArea::GUEST_INITIAL_MXCSR.to_ne_bytes());
    }
    Some(bytes)
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
    // Like Linux, a separately 64-byte-aligned XSAVE area sits above rt_sigframe.
    let fpstate = sp.checked_sub(fpstate_size(XsaveLayout::get()))? & !(XSTATE_ALIGN - 1);
    // Align the frame, offset by 8 bytes for the return address.
    let frame_addr = (fpstate.checked_sub(size_of::<SignalFrame>())? & !15).checked_sub(8)?;
    debug_assert_eq!(fpstate_addr(frame_addr), Some(fpstate));
    Some(frame_addr)
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
        let fpstate = fpstate_addr(frame_addr).ok_or(DeliverFault)?;
        write_fpstate(platform, fpstate).ok_or(DeliverFault)?;
        let frame = SignalFrame {
            return_address: sigreturn_trampoline,
            ucontext: Ucontext {
                flags: UC_FP_XSTATE | UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS,
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
                    fpstate: fpstate as u64,
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
        platform.set_guest_vector_state(&XsaveArea::initial(XsaveLayout::get()));
        Ok(())
    }
}

/// Restores `ctx` and the vector state from `sigctx`, returning the restored
/// RAX. Returns `None` for an invalid FP state; like Linux, the general
/// registers are then still restored and the vector state is reset.
pub(super) fn restore_sigcontext<Platform: ShimPlatform>(
    platform: &Platform,
    ctx: &mut PtRegs,
    sigctx: &Sigcontext,
) -> Option<usize> {
    let Sigcontext {
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
        fpstate,
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

    if let Some(vector_state) = read_fpstate::<Platform>(fpstate.trunc()) {
        platform.set_guest_vector_state(&vector_state);
        Some(ctx.rax)
    } else {
        platform.set_guest_vector_state(&XsaveArea::initial(XsaveLayout::get()));
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::tests::{TestPlatform, test_platform};
    use litebox::arch::x86_64::xstate::XsaveChunk;
    use litebox_common_linux::signal::SigSet;

    const XMM0_OFFSET: usize = offset_of!(XsaveLegacyArea, xmm_registers);

    /// An XSAVE-format signal FP state as `write_fpstate` lays it out.
    struct Frame {
        storage: Vec<XsaveChunk>,
        offset: usize,
    }

    impl Frame {
        fn new(offset: usize) -> Self {
            let layout = XsaveLayout::get();
            let chunks = (offset + fpstate_size(layout)).div_ceil(size_of::<XsaveChunk>());
            let mut frame = Self {
                storage: vec![XsaveChunk([0; 64]); chunks],
                offset,
            };
            let mut state = XsaveArea::initial(layout);
            state.sanitize(layout);
            frame.bytes()[..layout.size].copy_from_slice(state.as_bytes());
            frame.set_sw(|sw| {
                *sw = FpxSwBytes {
                    magic1: FP_XSTATE_MAGIC1,
                    extended_size: u32::try_from(fpstate_size(layout)).unwrap(),
                    xfeatures: layout.mask,
                    xstate_size: u32::try_from(layout.size).unwrap(),
                    padding: [0; 7],
                };
            });
            frame.set(layout.size, &FP_XSTATE_MAGIC2.to_ne_bytes());
            frame
        }

        fn bytes(&mut self) -> &mut [u8] {
            &mut self.storage.as_mut_bytes()[self.offset..]
        }

        fn set(&mut self, offset: usize, value: &[u8]) {
            self.bytes()[offset..offset + value.len()].copy_from_slice(value);
        }

        fn set_sw(&mut self, f: impl FnOnce(&mut FpxSwBytes)) {
            let bytes = &mut self.bytes()[SW_RESERVED_OFFSET..XSAVE_LEGACY_SIZE];
            let mut sw = FpxSwBytes::read_from_bytes(bytes).unwrap();
            f(&mut sw);
            bytes.copy_from_slice(sw.as_bytes());
        }

        fn set_xstate_bv(&mut self, xstate_bv: u64) {
            self.set(XSTATE_BV_OFFSET, &xstate_bv.to_ne_bytes());
        }

        fn set_mxcsr(&mut self, mxcsr: u32) {
            self.set(MXCSR_OFFSET, &mxcsr.to_ne_bytes());
        }

        fn read(&self) -> Option<XsaveArea> {
            let _ = test_platform();
            read_fpstate::<TestPlatform>(self.storage.as_ptr().addr() + self.offset)
        }
    }

    #[test]
    fn signal_frame_layout_fits_below_sp() {
        let layout = XsaveLayout::get();
        let action = SigAction {
            sigaction: 0,
            flags: SaFlags::empty(),
            __pad: 0,
            restorer: 0,
            mask: SigSet::empty(),
        };
        for sp in 0x10_0000..0x10_0000 + 2 * XSTATE_ALIGN {
            let frame = get_signal_frame(sp, &action).unwrap();
            let fpstate = fpstate_addr(frame).unwrap();
            assert_eq!((frame + 8) % 16, 0);
            assert_eq!(fpstate % XSTATE_ALIGN, 0);
            assert!(frame + size_of::<SignalFrame>() <= fpstate);
            assert!(fpstate + fpstate_size(layout) <= sp);
            assert!(sp - frame <= max_signal_frame_size());
        }
    }

    #[test]
    fn null_fpstate_restores_initial_state() {
        let _ = test_platform();
        let layout = XsaveLayout::get();
        assert_eq!(
            read_fpstate::<TestPlatform>(0),
            Some(XsaveArea::initial(layout))
        );
    }

    #[test]
    fn xsave_frame_round_trips() {
        let mut frame = Frame::new(0);
        frame.set(XMM0_OFFSET, &[0x5a; 16]);
        let state = frame.read().unwrap();
        assert_eq!(state.legacy_area().xmm_registers[0], [0x5a; 16]);
        assert_eq!(state.xstate_bv(), XFeatureMask::LEGACY.bits());
    }

    #[test]
    fn frames_without_xsave_metadata_restore_legacy_state() {
        let layout = XsaveLayout::get();
        let mut no_magic = Frame::new(0);
        no_magic.set_sw(|sw| sw.magic1 = 0);
        let mut no_trailer = Frame::new(0);
        no_trailer.set(layout.size, &[0; 4]);
        // Only XSAVE-format state requires 64-byte alignment.
        let mut misaligned = Frame::new(16);
        misaligned.set_sw(|sw| sw.magic1 = 0);
        for mut frame in [no_magic, no_trailer, misaligned] {
            frame.set(XMM0_OFFSET, &[0x3c; 16]);
            frame.set_xstate_bv(layout.mask);
            let state = frame.read().unwrap();
            assert_eq!(state.xstate_bv(), XFeatureMask::LEGACY.bits());
            assert_eq!(state.legacy_area().xmm_registers[0], [0x3c; 16]);
        }
        assert!(Frame::new(16).read().is_none());
    }

    #[test]
    fn omitted_sse_reinitializes_mxcsr() {
        let mut frame = Frame::new(0);
        frame.set_mxcsr(0x5f80);
        frame.set_sw(|sw| sw.xfeatures &= !XFeatureMask::SSE.bits());
        let state = frame.read().unwrap();
        assert_eq!(state.legacy_area().mxcsr, XsaveArea::GUEST_INITIAL_MXCSR);
        assert_eq!(state.xstate_bv() & XFeatureMask::SSE.bits(), 0);
    }

    #[test]
    fn mxcsr_is_validated_only_when_loaded() {
        let invalid = !XsaveLayout::get().mxcsr_mask;
        let mut unloaded = Frame::new(0);
        unloaded.set_mxcsr(invalid);
        unloaded.set_sw(|sw| sw.xfeatures &= !(XFeatureMask::SSE | XFeatureMask::AVX).bits());
        let state = unloaded.read().unwrap();
        assert_eq!(state.legacy_area().mxcsr, XsaveArea::GUEST_INITIAL_MXCSR);

        let mut avx_only = Frame::new(0);
        avx_only.set_mxcsr(invalid);
        avx_only.set_sw(|sw| {
            sw.xfeatures = (sw.xfeatures & !XFeatureMask::SSE.bits()) | XFeatureMask::AVX.bits();
        });
        assert!(avx_only.read().is_none());

        let mut full = Frame::new(0);
        full.set_mxcsr(invalid);
        assert!(full.read().is_none());
    }

    #[test]
    fn unsupported_xstate_bv_bits_fail_even_when_masked() {
        let mut frame = Frame::new(0);
        frame.set_xstate_bv(XFeatureMask::LEGACY.bits() | 1 << 63);
        frame.set_sw(|sw| sw.xfeatures &= !(1 << 63));
        assert!(frame.read().is_none());
    }

    #[test]
    fn short_frames_read_active_components_past_the_trailer_offset() {
        let layout = XsaveLayout::get();
        let Some(component) = layout.components.first() else {
            return;
        };
        let short_size = XSAVE_HEADER_OFFSET + XSAVE_HEADER_SIZE;
        let short = |xfeatures: u64| {
            let mut frame = Frame::new(0);
            frame.set_xstate_bv(XFeatureMask::LEGACY.bits() | 1 << component.id);
            frame.set(short_size, &FP_XSTATE_MAGIC2.to_ne_bytes());
            frame.set_sw(|sw| {
                sw.xstate_size = u32::try_from(short_size).unwrap();
                sw.xfeatures = xfeatures;
            });
            frame.read()
        };
        let state = short(layout.mask).unwrap();
        assert_ne!(state.xstate_bv() & (1 << component.id), 0);
        let state = short(layout.mask & !(1 << component.id)).unwrap();
        assert_eq!(state.xstate_bv(), XFeatureMask::LEGACY.bits());
    }
}
