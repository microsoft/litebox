// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(feature = "platform_linux_userland")]
use crate::ConstPtr;
use crate::MutPtr;
use crate::Task;
use crate::syscalls::signal::{DeliverFault, SignalState};
use core::mem::offset_of;
use litebox::platform::RawConstPointer as _;
use litebox::platform::RawMutPointer as _;
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{
    PtRegs,
    signal::{SaFlags, SigAction, Siginfo, Ucontext, x86_64::Sigcontext},
};
use zerocopy::{FromBytes, IntoBytes};

/// Size of the guest FP/SIMD save area in bytes.
const FPSTATE_SIZE: usize = litebox_common_linux::FP_STATE_SIZE;
/// Size of the legacy FXSAVE area in bytes.
#[cfg(any(feature = "platform_linux_userland", test))]
const LEGACY_FPSTATE_SIZE: usize = 512;
/// FP state area alignment.
const FPSTATE_ALIGN: usize = 64;
/// XSAVE header offset within the save area.
#[cfg(feature = "platform_linux_userland")]
const XSTATE_HEADER_OFFSET: usize = LEGACY_FPSTATE_SIZE;
/// Offset of xstate_bv within the XSAVE header.
#[cfg(feature = "platform_linux_userland")]
const XSTATE_BV_OFFSET: usize = XSTATE_HEADER_OFFSET;
/// Offset of xcomp_bv within the XSAVE header.
#[cfg(feature = "platform_linux_userland")]
const XCOMP_BV_OFFSET: usize = XSTATE_HEADER_OFFSET + 8;
/// Size of the XSAVE header in bytes.
#[cfg(feature = "platform_linux_userland")]
const XSTATE_HEADER_SIZE: usize = 64;
/// Offset of the first extended state payload (YMM upper halves today).
#[cfg(feature = "platform_linux_userland")]
const XSTATE_EXTENDED_OFFSET: usize = XSTATE_HEADER_OFFSET + XSTATE_HEADER_SIZE;
/// Offset of the software-reserved region within the legacy FXSAVE layout.
#[cfg(any(feature = "platform_linux_userland", test))]
const SW_RESERVED_OFFSET: usize = 464;
/// Size of the guest signal-frame FP buffer, including Linux's trailing magic2.
#[cfg(feature = "platform_linux_userland")]
const SIGNAL_FPSTATE_SIZE: usize = FPSTATE_SIZE + core::mem::size_of::<u32>();
/// Linux xstate signal-frame marker values from asm/sigcontext.h.
#[cfg(feature = "platform_linux_userland")]
const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
#[cfg(feature = "platform_linux_userland")]
const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
/// Guest-visible xfeatures we currently preserve end-to-end.
#[cfg(feature = "platform_linux_userland")]
const XFEATURE_FP: u64 = 1 << 0;
#[cfg(feature = "platform_linux_userland")]
const XFEATURE_SSE: u64 = 1 << 1;
#[cfg(feature = "platform_linux_userland")]
const XFEATURE_AVX: u64 = 1 << 2;
#[cfg(feature = "platform_linux_userland")]
const GUEST_XFEATURE_MASK: u64 = XFEATURE_FP | XFEATURE_SSE | XFEATURE_AVX;
/// MXCSR bits that are valid (non-reserved). Bits 16-31 are reserved.
#[cfg(feature = "platform_linux_userland")]
const MXCSR_VALID_MASK: u32 = 0x0000_FFFF;
/// Default MXCSR feature mask for CPUs that don't report one (pre-SSE2).
/// SSE1-only: no DAZ (bit 6), so bits 0-5 + 7-15 = 0xFFBF.
#[cfg(feature = "platform_linux_userland")]
const MXCSR_DEFAULT_FEATURE_MASK: u32 = 0x0000_FFBF;

/// Validates an MXCSR value against the valid mask and an optional host CPU
/// feature mask. Returns `true` if the value is safe for FXRSTOR.
#[cfg(feature = "platform_linux_userland")]
fn validate_mxcsr(mxcsr: u32, host_mxcsr_mask: u32) -> bool {
    // Reserved bits (16-31) must always be clear.
    if mxcsr & !MXCSR_VALID_MASK != 0 {
        return false;
    }
    // Use the host-reported mask, or the conservative SSE1-only default
    // if the CPU didn't report one (mxcsr_mask=0 on pre-SSE2 CPUs).
    let effective_mask = if host_mxcsr_mask != 0 {
        host_mxcsr_mask
    } else {
        MXCSR_DEFAULT_FEATURE_MASK
    };
    if mxcsr & !effective_mask != 0 {
        return false;
    }
    true
}

#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
struct SignalFrame {
    return_address: usize,
    ucontext: Ucontext,
    siginfo: Siginfo,
}

/// Guest signal-frame FP buffer: the XSAVE/FXSAVE image plus Linux's trailing
/// FP_XSTATE_MAGIC2 word when extended state is advertised.
#[cfg(feature = "platform_linux_userland")]
type SignalFpStateBuf = [u8; SIGNAL_FPSTATE_SIZE];

/// Reinitializes guest FP state with a canonical clean FXSAVE image
/// matching Linux kernel's post-execve FP state. All FP/XMM registers are
/// zeroed, x87 CW=0x037F, MXCSR=0x1F80.
///
/// Note: this zeroes `mxcsr_mask` (offset 28), but that's OK —
/// `host_mxcsr_mask` was captured at thread startup by `fxsave64` and
/// persists in `ctx.fp_regs` across the next guest→shim transition.
/// `execve` doesn't re-run `run_thread_arch`, so the mask remains valid.
pub(crate) fn reinit_guest_fp_state(fp_regs: &mut litebox_common_linux::FpRegs) {
    *fp_regs = litebox_common_linux::FpRegs::default();
}

/// Returns the MXCSR feature mask from the FXSAVE image in `ctx.fp_regs`.
///
/// The mask lives at offset 28 in the FXSAVE area and is populated by
/// `fxsave64`. If the image was never populated by a real `fxsave64` (e.g.,
/// on platforms that don't do FP save/restore), this returns 0, which
/// `validate_mxcsr` handles correctly (accepts any MXCSR value).
#[cfg(feature = "platform_linux_userland")]
fn read_host_mxcsr_mask(ctx: &litebox_common_linux::ExecutionContext) -> u32 {
    u32::from_le_bytes(ctx.fp_regs.data[28..32].try_into().unwrap())
}

#[cfg(feature = "platform_linux_userland")]
fn read_xstate_bv(fp: &[u8; FPSTATE_SIZE]) -> u64 {
    u64::from_le_bytes(
        fp[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8]
            .try_into()
            .unwrap(),
    )
}

#[cfg(feature = "platform_linux_userland")]
fn write_xstate_bv(fp: &mut [u8; FPSTATE_SIZE], xfeatures: u64) {
    fp[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8].copy_from_slice(&xfeatures.to_le_bytes());
}

#[cfg(feature = "platform_linux_userland")]
fn xsave_area_size(xfeatures: u64) -> u32 {
    if (xfeatures & XFEATURE_AVX) != 0 {
        #[allow(clippy::cast_possible_truncation)]
        {
            FPSTATE_SIZE as u32
        }
    } else {
        #[allow(clippy::cast_possible_truncation)]
        {
            XSTATE_EXTENDED_OFFSET as u32
        }
    }
}

#[cfg(feature = "platform_linux_userland")]
fn sanitize_xsave_image(fp: &mut [u8; FPSTATE_SIZE], force_fpsse: bool) -> u64 {
    let mut xfeatures = read_xstate_bv(fp) & GUEST_XFEATURE_MASK;
    if force_fpsse || (xfeatures & XFEATURE_AVX) != 0 {
        xfeatures |= XFEATURE_FP | XFEATURE_SSE;
    }
    fp[SW_RESERVED_OFFSET..LEGACY_FPSTATE_SIZE].fill(0);
    write_xstate_bv(fp, xfeatures);
    fp[XCOMP_BV_OFFSET..XSTATE_EXTENDED_OFFSET].fill(0);
    if (xfeatures & XFEATURE_AVX) == 0 {
        fp[XSTATE_EXTENDED_OFFSET..FPSTATE_SIZE].fill(0);
    }
    xfeatures
}

#[cfg(feature = "platform_linux_userland")]
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "platform_linux_userland")]
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[cfg(feature = "platform_linux_userland")]
fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "platform_linux_userland")]
fn extended_fpstate_len(legacy_fp: &[u8; LEGACY_FPSTATE_SIZE]) -> Option<usize> {
    if read_u32(legacy_fp, SW_RESERVED_OFFSET) != FP_XSTATE_MAGIC1 {
        return None;
    }

    match read_u32(legacy_fp, SW_RESERVED_OFFSET + 4) as usize {
        SIGNAL_FPSTATE_SIZE | FPSTATE_SIZE => {
            Some(read_u32(legacy_fp, SW_RESERVED_OFFSET + 4) as usize)
        }
        _ => None,
    }
}

#[cfg(feature = "platform_linux_userland")]
fn write_signal_frame_xstate_metadata(fp: &mut [u8; SIGNAL_FPSTATE_SIZE], xfeatures: u64) {
    fp[SW_RESERVED_OFFSET..LEGACY_FPSTATE_SIZE].fill(0);
    write_u32(fp, SW_RESERVED_OFFSET, FP_XSTATE_MAGIC1);
    #[allow(clippy::cast_possible_truncation)]
    write_u32(fp, SW_RESERVED_OFFSET + 4, SIGNAL_FPSTATE_SIZE as u32);
    write_u64(fp, SW_RESERVED_OFFSET + 8, xfeatures);
    write_u32(fp, SW_RESERVED_OFFSET + 16, xsave_area_size(xfeatures));
    write_u32(fp, FPSTATE_SIZE, FP_XSTATE_MAGIC2);
}

pub(super) fn uctx_addr(ctx: &PtRegs) -> usize {
    ctx.rsp
}

/// Return the restored RAX after rt_sigreturn so the caller's writeback is idempotent.
pub(super) fn sigreturn_rax(ctx: &PtRegs) -> usize {
    ctx.rax
}

pub(super) fn sp(ctx: &PtRegs) -> usize {
    ctx.rsp
}

pub(super) fn get_signal_frame(sp: usize, _action: &SigAction) -> usize {
    let mut frame_addr = sp;

    // Skip the redzone.
    frame_addr = frame_addr.wrapping_sub(128);

    // Reserve space for the guest signal-frame FP area, 64-byte aligned.
    #[cfg(feature = "platform_linux_userland")]
    let fpstate_size = SIGNAL_FPSTATE_SIZE;
    #[cfg(not(feature = "platform_linux_userland"))]
    let fpstate_size = FPSTATE_SIZE;
    frame_addr = (frame_addr.wrapping_sub(fpstate_size)) & !(FPSTATE_ALIGN - 1);

    // Space for the signal frame.
    frame_addr = frame_addr.wrapping_sub(core::mem::size_of::<SignalFrame>());

    // Align the frame (offset by 8 bytes for return address)
    frame_addr &= !15;
    frame_addr = frame_addr.wrapping_sub(8);

    frame_addr
}

/// Computes the fpstate address on the guest stack given the signal frame
/// address. The FP state area lives above the SignalFrame, 64-byte aligned.
#[cfg(any(feature = "platform_linux_userland", test))]
fn fpstate_addr_from_frame(frame_addr: usize) -> usize {
    let above_frame = frame_addr.wrapping_add(core::mem::size_of::<SignalFrame>());
    // Align up to FPSTATE_ALIGN.
    (above_frame + (FPSTATE_ALIGN - 1)) & !(FPSTATE_ALIGN - 1)
}

impl SignalState {
    pub(super) fn write_signal_frame(
        &self,
        frame_addr: usize,
        siginfo: &Siginfo,
        action: &SigAction,
        ctx: &mut litebox_common_linux::ExecutionContext,
        task: &Task<impl crate::ShimFS>,
        in_syscall: bool,
    ) -> Result<(), DeliverFault> {
        if !action.flags.contains(SaFlags::RESTORER) {
            return Err(DeliverFault);
        }

        // Compute fpstate address and write guest FP state to guest stack.
        #[cfg(feature = "platform_linux_userland")]
        let fpstate_guest_addr = {
            let addr = fpstate_addr_from_frame(frame_addr);
            let mut fp: SignalFpStateBuf = [0u8; SIGNAL_FPSTATE_SIZE];
            fp[..FPSTATE_SIZE].copy_from_slice(&ctx.fp_regs.data);
            let xfeatures = {
                let save = <&mut [u8; FPSTATE_SIZE]>::try_from(&mut fp[..FPSTATE_SIZE]).unwrap();
                sanitize_xsave_image(save, true)
            };
            write_signal_frame_xstate_metadata(&mut fp, xfeatures);
            if !task.prepare_cow_for_host_write(addr, SIGNAL_FPSTATE_SIZE) {
                return Err(DeliverFault);
            }
            let fp_ptr = MutPtr::<SignalFpStateBuf>::from_usize(addr);
            fp_ptr.write_at_offset(0, fp).ok_or(DeliverFault)?;
            addr as u64
        };
        #[cfg(not(feature = "platform_linux_userland"))]
        let fpstate_guest_addr: u64 = 0;

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
                    // In syscall context, ctx.r11 holds the internal
                    // call-site scratch address; the guest-visible R11
                    // is RFLAGS (as set by the real `syscall` instruction).
                    // In async interrupt context, ctx.r11 is the real
                    // architectural register.
                    r11: if in_syscall {
                        ctx.eflags as u64
                    } else {
                        ctx.r11 as u64
                    },
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
                    fpstate: fpstate_guest_addr,
                    reserved1: [0; 8],
                },
                sigmask: self.blocked.get(),
            },
            siginfo: siginfo.clone(),
        };

        if !task.prepare_cow_for_host_write(frame_addr, core::mem::size_of::<SignalFrame>()) {
            return Err(DeliverFault);
        }
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
    ctx: &mut litebox_common_linux::ExecutionContext,
    sigctx: &litebox_common_linux::signal::x86_64::Sigcontext,
) -> Result<usize, ()> {
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
        #[cfg(feature = "platform_linux_userland")]
        fpstate,
        #[cfg(not(feature = "platform_linux_userland"))]
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

    // Restore FP state from the signal frame if present.
    #[cfg(feature = "platform_linux_userland")]
    if fpstate != 0 {
        // This is x86_64-only code; fpstate is a u64 guest pointer.
        #[allow(clippy::cast_possible_truncation)]
        let fp_ptr = ConstPtr::<u8>::from_usize(fpstate as usize);
        let mut fp = [0u8; FPSTATE_SIZE];
        let legacy_fp = fp_ptr.to_owned_slice(LEGACY_FPSTATE_SIZE).ok_or(())?;
        fp[..LEGACY_FPSTATE_SIZE].copy_from_slice(&legacy_fp);

        if let Some(len) = extended_fpstate_len((&*legacy_fp).try_into().unwrap()) {
            // Only trust XSAVE bytes past the legacy 512-byte region when the
            // Linux xstate metadata is present. Readable bytes after a legacy
            // frame can otherwise be unrelated stack data.
            let fp_bytes = fp_ptr.to_owned_slice(len).ok_or(())?;
            let tail_len = FPSTATE_SIZE.min(len);
            if tail_len > LEGACY_FPSTATE_SIZE {
                fp[LEGACY_FPSTATE_SIZE..tail_len]
                    .copy_from_slice(&fp_bytes[LEGACY_FPSTATE_SIZE..tail_len]);
            }
        }

        // Linux sigreturn restore always treats the legacy x87/SSE region as
        // present. Force those bits on for both legacy 512-byte frames and
        // extended XSAVE frames so XRSTOR loads the saved state instead of
        // reinitializing it when xstate_bv was zeroed or absent.
        sanitize_xsave_image(&mut fp, true);

        // Validate MXCSR from guest-controlled signal frame against the
        // trusted host CPU mask to prevent fxrstor/xrstor #GP fault.
        let mxcsr = u32::from_le_bytes(fp[24..28].try_into().unwrap());
        let host_mask = read_host_mxcsr_mask(ctx);
        if !validate_mxcsr(mxcsr, host_mask) {
            return Err(());
        }

        ctx.fp_regs.data = fp;
    }

    Ok(ctx.rax)
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::signal::SigSet;

    fn dummy_action() -> SigAction {
        SigAction {
            sigaction: 0x1000,
            restorer: 0x2000,
            flags: SaFlags::RESTORER,
            mask: SigSet::empty(),
            #[cfg(target_arch = "x86_64")]
            __pad: 0,
        }
    }

    // --- Signal frame layout tests ---

    #[test]
    fn signal_frame_is_return_address_aligned() {
        // The frame address should satisfy the x86_64 ABI: 16-byte aligned
        // minus 8 (so that after the call instruction pushes the return
        // address, RSP is 16-byte aligned).
        for &sp in &[
            0x7fff_ffff_f000usize,
            0x7fff_ffff_e008,
            0x7fff_ffff_d100,
            0x1000_0000_0000,
        ] {
            let frame_addr = get_signal_frame(sp, &dummy_action());
            assert_eq!(
                frame_addr % 16,
                8,
                "frame_addr {frame_addr:#x} for sp {sp:#x} should be 16-aligned minus 8"
            );
        }
    }

    #[test]
    fn signal_frame_below_redzone() {
        let sp = 0x7fff_ffff_f000usize;
        let frame_addr = get_signal_frame(sp, &dummy_action());
        // Frame must be at least 128 (redzone) + sizeof(SignalFrame) below sp.
        assert!(
            frame_addr + core::mem::size_of::<SignalFrame>() <= sp - 128,
            "frame overlaps redzone"
        );
    }

    #[test]
    fn fpstate_area_is_64_byte_aligned() {
        for &sp in &[
            0x7fff_ffff_f000usize,
            0x7fff_ffff_e008,
            0x7fff_ffff_d123,
            0x1000_0000_0000,
        ] {
            let frame_addr = get_signal_frame(sp, &dummy_action());
            let fp_addr = fpstate_addr_from_frame(frame_addr);
            assert_eq!(
                fp_addr % FPSTATE_ALIGN,
                0,
                "fpstate {fp_addr:#x} for sp {sp:#x} not 64-byte aligned"
            );
        }
    }

    #[test]
    fn fpstate_fits_between_frame_and_redzone() {
        let sp = 0x7fff_ffff_f000usize;
        let frame_addr = get_signal_frame(sp, &dummy_action());
        let fp_addr = fpstate_addr_from_frame(frame_addr);

        // fpstate must be above the signal frame.
        assert!(
            fp_addr >= frame_addr + core::mem::size_of::<SignalFrame>(),
            "fpstate overlaps signal frame"
        );
        // fpstate area must not exceed sp - 128 (redzone boundary).
        assert!(
            fp_addr + SIGNAL_FPSTATE_SIZE <= sp - 128,
            "fpstate extends into redzone"
        );
    }

    #[test]
    fn fpstate_layout_round_trip() {
        // Verify that for various SP values, fpstate_addr_from_frame produces
        // an address that is consistent with get_signal_frame's allocation.
        for sp in (0x1000_0000..0x1000_0100).step_by(8) {
            let frame_addr = get_signal_frame(sp, &dummy_action());
            let fp_addr = fpstate_addr_from_frame(frame_addr);
            assert_eq!(fp_addr % FPSTATE_ALIGN, 0);
            assert!(fp_addr >= frame_addr + core::mem::size_of::<SignalFrame>());
            assert!(fp_addr + SIGNAL_FPSTATE_SIZE <= sp - 128);
        }
    }

    // --- MXCSR validation tests ---

    #[test]
    fn mxcsr_default_is_valid() {
        assert!(validate_mxcsr(0x1F80, 0));
        assert!(validate_mxcsr(0x1F80, 0xFFFF));
    }

    #[test]
    fn mxcsr_zero_is_valid() {
        // All exceptions unmasked — unusual but architecturally valid.
        assert!(validate_mxcsr(0x0000, 0));
        assert!(validate_mxcsr(0x0000, 0xFFFF));
    }

    #[test]
    fn mxcsr_reserved_bits_rejected() {
        // Bit 16 is reserved.
        assert!(!validate_mxcsr(0x0001_0000, 0));
        // Bit 31 is reserved.
        assert!(!validate_mxcsr(0x8000_0000, 0));
        // All reserved bits set.
        assert!(!validate_mxcsr(0xFFFF_0000, 0));
    }

    #[test]
    fn mxcsr_host_mask_rejects_unsupported_bits() {
        // Host mask says only bits 0-12 are valid (typical SSE-only CPU).
        let host_mask = 0x0000_FFBF;
        // Bit 6 (DAZ) is not in the mask — should fail.
        assert!(!validate_mxcsr(0x0040, host_mask));
        // Default 0x1F80 should pass (bits 7-12 = exception masks).
        assert!(validate_mxcsr(0x1F80, host_mask));
    }

    #[test]
    fn mxcsr_host_mask_zero_uses_conservative_default() {
        // host_mask=0 means CPU didn't report a mask (pre-SSE2).
        // Should use conservative default 0xFFBF (no DAZ bit 6).
        assert!(validate_mxcsr(0x1F80, 0)); // standard default passes
        assert!(!validate_mxcsr(0x0040, 0)); // DAZ bit rejected without host support
        assert!(!validate_mxcsr(0xFFFF, 0)); // bits outside 0xFFBF rejected
    }

    #[test]
    fn mxcsr_combined_reserved_and_host_mask() {
        // Bit 16 is reserved AND unsupported — reserved check fires first.
        assert!(!validate_mxcsr(0x0001_0040, 0xFFBF));
    }

    // --- GPR restore round-trip tests ---

    #[test]
    fn restore_sigcontext_restores_gprs() {
        let sigctx = Sigcontext {
            r8: 0x0808,
            r9: 0x0909,
            r10: 0x1010,
            r11: 0x1111,
            r12: 0x1212,
            r13: 0x1313,
            r14: 0x1414,
            r15: 0x1515,
            rdi: 0xD1,
            rsi: 0x51,
            rbp: 0xB9,
            rbx: 0xBB,
            rdx: 0xDD,
            rax: 0xAA,
            rcx: 0xCC,
            rsp: 0x5959,
            rip: 0x1919,
            rflags: 0x0202,
            cs: 0x33,
            gs: 0,
            fs: 0,
            ss: 0x2B,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
            fpstate: 0, // no FP state pointer → skip FP restore
            reserved1: [0; 8],
        };

        let mut ctx = litebox_common_linux::ExecutionContext::default();
        let result = restore_sigcontext(&mut ctx, &sigctx);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0xAA); // rax
        assert_eq!(ctx.r8, 0x0808);
        assert_eq!(ctx.r15, 0x1515);
        assert_eq!(ctx.rdi, 0xD1);
        assert_eq!(ctx.rsp, 0x5959);
        assert_eq!(ctx.rip, 0x1919);
        assert_eq!(ctx.eflags, 0x0202);
    }

    #[test]
    fn restore_sigcontext_with_zero_fpstate_succeeds() {
        // fpstate=0 means no FP state in the signal frame (legacy).
        // restore_sigcontext should succeed without touching TLS.
        let sigctx = Sigcontext {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 42,
            rcx: 0,
            rsp: 0x1000,
            rip: 0x2000,
            rflags: 0,
            cs: 0x33,
            gs: 0,
            fs: 0,
            ss: 0x2B,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
            fpstate: 0,
            reserved1: [0; 8],
        };

        let mut ctx = litebox_common_linux::ExecutionContext::default();
        assert_eq!(restore_sigcontext(&mut ctx, &sigctx), Ok(42));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn signal_fpstate_metadata_marks_extended_state() {
        let mut fp: SignalFpStateBuf = [0u8; SIGNAL_FPSTATE_SIZE];
        fp[..FPSTATE_SIZE].copy_from_slice(&litebox_common_linux::FpRegs::default().data);
        let xfeatures = {
            let save = <&mut [u8; FPSTATE_SIZE]>::try_from(&mut fp[..FPSTATE_SIZE]).unwrap();
            sanitize_xsave_image(save, true)
        };
        write_signal_frame_xstate_metadata(&mut fp, xfeatures);

        assert_eq!(
            read_xstate_bv((&fp[..FPSTATE_SIZE]).try_into().unwrap()),
            0x3
        );
        assert_eq!(
            u32::from_le_bytes(
                fp[SW_RESERVED_OFFSET..SW_RESERVED_OFFSET + 4]
                    .try_into()
                    .unwrap()
            ),
            FP_XSTATE_MAGIC1
        );
        assert_eq!(
            u32::from_le_bytes(
                fp[SW_RESERVED_OFFSET + 4..SW_RESERVED_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            SIGNAL_FPSTATE_SIZE as u32
        );
        assert_eq!(
            u64::from_le_bytes(
                fp[SW_RESERVED_OFFSET + 8..SW_RESERVED_OFFSET + 16]
                    .try_into()
                    .unwrap()
            ),
            0x3
        );
        assert_eq!(
            u32::from_le_bytes(
                fp[SW_RESERVED_OFFSET + 16..SW_RESERVED_OFFSET + 20]
                    .try_into()
                    .unwrap()
            ),
            XSTATE_EXTENDED_OFFSET as u32
        );
        assert_eq!(
            u32::from_le_bytes(fp[FPSTATE_SIZE..SIGNAL_FPSTATE_SIZE].try_into().unwrap()),
            FP_XSTATE_MAGIC2
        );
    }

    #[test]
    fn restore_sigcontext_sanitizes_xsave_header() {
        let mut fp = [0u8; SIGNAL_FPSTATE_SIZE];
        fp[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
        write_signal_frame_xstate_metadata(&mut fp, GUEST_XFEATURE_MASK);
        fp[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8].copy_from_slice(&0xFFFFu64.to_le_bytes());
        fp[XCOMP_BV_OFFSET..XCOMP_BV_OFFSET + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        fp[XCOMP_BV_OFFSET + 8..XSTATE_EXTENDED_OFFSET].fill(0xA5);
        fp[XSTATE_EXTENDED_OFFSET..FPSTATE_SIZE].fill(0x5A);

        let sigctx = Sigcontext {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 7,
            rcx: 0,
            rsp: 0x1000,
            rip: 0x2000,
            rflags: 0,
            cs: 0x33,
            gs: 0,
            fs: 0,
            ss: 0x2B,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
            fpstate: fp.as_ptr() as usize as u64,
            reserved1: [0; 8],
        };

        let mut ctx = litebox_common_linux::ExecutionContext::default();
        assert_eq!(restore_sigcontext(&mut ctx, &sigctx), Ok(7));
        assert_eq!(read_xstate_bv(&ctx.fp_regs.data), GUEST_XFEATURE_MASK);
        assert!(
            ctx.fp_regs.data[XCOMP_BV_OFFSET..XSTATE_EXTENDED_OFFSET]
                .iter()
                .all(|&b| b == 0),
            "xcomp_bv or reserved XSAVE header bytes not cleared"
        );
    }

    #[test]
    fn restore_sigcontext_legacy_fpstate_forces_fpsse() {
        let mut fp = [0u8; LEGACY_FPSTATE_SIZE];
        fp[0..2].copy_from_slice(&0x1234u16.to_le_bytes());
        fp[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());

        let sigctx = Sigcontext {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 11,
            rcx: 0,
            rsp: 0x1000,
            rip: 0x2000,
            rflags: 0,
            cs: 0x33,
            gs: 0,
            fs: 0,
            ss: 0x2B,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
            fpstate: fp.as_ptr() as usize as u64,
            reserved1: [0; 8],
        };

        let mut ctx = litebox_common_linux::ExecutionContext::default();
        assert_eq!(restore_sigcontext(&mut ctx, &sigctx), Ok(11));
        assert_eq!(
            read_xstate_bv(&ctx.fp_regs.data),
            XFEATURE_FP | XFEATURE_SSE
        );
        assert_eq!(
            u16::from_le_bytes(ctx.fp_regs.data[0..2].try_into().unwrap()),
            0x1234
        );
    }

    #[test]
    fn restore_sigcontext_ignores_readable_xsave_tail_without_metadata() {
        let mut fp = [0u8; FPSTATE_SIZE];
        fp[0..2].copy_from_slice(&0x9ABCu16.to_le_bytes());
        fp[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
        fp[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8]
            .copy_from_slice(&GUEST_XFEATURE_MASK.to_le_bytes());
        fp[XSTATE_EXTENDED_OFFSET..FPSTATE_SIZE].fill(0x5A);

        let sigctx = Sigcontext {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 12,
            rcx: 0,
            rsp: 0x1000,
            rip: 0x2000,
            rflags: 0,
            cs: 0x33,
            gs: 0,
            fs: 0,
            ss: 0x2B,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
            fpstate: fp.as_ptr() as usize as u64,
            reserved1: [0; 8],
        };

        let mut ctx = litebox_common_linux::ExecutionContext::default();
        assert_eq!(restore_sigcontext(&mut ctx, &sigctx), Ok(12));
        assert_eq!(
            read_xstate_bv(&ctx.fp_regs.data),
            XFEATURE_FP | XFEATURE_SSE
        );
        assert!(
            ctx.fp_regs.data[XSTATE_EXTENDED_OFFSET..FPSTATE_SIZE]
                .iter()
                .all(|&b| b == 0),
            "readable tail without xstate metadata should be ignored"
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn restore_sigcontext_accepts_valid_832_byte_xsave_frame() {
        let mut fp = [0u8; FPSTATE_SIZE];
        fp[0..2].copy_from_slice(&0x2468u16.to_le_bytes());
        fp[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
        write_u32(&mut fp, SW_RESERVED_OFFSET, FP_XSTATE_MAGIC1);
        write_u32(&mut fp, SW_RESERVED_OFFSET + 4, FPSTATE_SIZE as u32);
        write_u64(&mut fp, SW_RESERVED_OFFSET + 8, GUEST_XFEATURE_MASK);
        write_u32(
            &mut fp,
            SW_RESERVED_OFFSET + 16,
            xsave_area_size(GUEST_XFEATURE_MASK),
        );
        fp[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8]
            .copy_from_slice(&GUEST_XFEATURE_MASK.to_le_bytes());
        fp[XSTATE_EXTENDED_OFFSET..FPSTATE_SIZE].fill(0x5A);

        let sigctx = Sigcontext {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 12,
            rcx: 0,
            rsp: 0x1000,
            rip: 0x2000,
            rflags: 0,
            cs: 0x33,
            gs: 0,
            fs: 0,
            ss: 0x2B,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
            fpstate: fp.as_ptr() as usize as u64,
            reserved1: [0; 8],
        };

        let mut ctx = litebox_common_linux::ExecutionContext::default();
        assert_eq!(restore_sigcontext(&mut ctx, &sigctx), Ok(12));
        assert_eq!(read_xstate_bv(&ctx.fp_regs.data), GUEST_XFEATURE_MASK);
        assert_eq!(
            u16::from_le_bytes(ctx.fp_regs.data[0..2].try_into().unwrap()),
            0x2468
        );
        assert!(
            ctx.fp_regs.data[XSTATE_EXTENDED_OFFSET..FPSTATE_SIZE]
                .iter()
                .all(|&b| b == 0x5A),
            "valid 832-byte XSAVE frame should preserve AVX payload"
        );
    }

    #[test]
    fn restore_sigcontext_zero_xstate_bv_still_restores_fpsse() {
        let mut fp = [0u8; SIGNAL_FPSTATE_SIZE];
        fp[0..2].copy_from_slice(&0x5678u16.to_le_bytes());
        fp[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
        write_signal_frame_xstate_metadata(&mut fp, GUEST_XFEATURE_MASK);

        let sigctx = Sigcontext {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 13,
            rcx: 0,
            rsp: 0x1000,
            rip: 0x2000,
            rflags: 0,
            cs: 0x33,
            gs: 0,
            fs: 0,
            ss: 0x2B,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
            fpstate: fp.as_ptr() as usize as u64,
            reserved1: [0; 8],
        };

        let mut ctx = litebox_common_linux::ExecutionContext::default();
        assert_eq!(restore_sigcontext(&mut ctx, &sigctx), Ok(13));
        assert_eq!(
            read_xstate_bv(&ctx.fp_regs.data),
            XFEATURE_FP | XFEATURE_SSE
        );
        assert_eq!(
            u16::from_le_bytes(ctx.fp_regs.data[0..2].try_into().unwrap()),
            0x5678
        );
    }

    // --- FpRegs::default() test ---

    #[test]
    fn fp_regs_default_matches_linux_init_state() {
        let fp = litebox_common_linux::FpRegs::default();
        let img = &fp.data;

        // x87 control word at offset 0: 0x037F
        assert_eq!(u16::from_le_bytes(img[0..2].try_into().unwrap()), 0x037F);
        // x87 status word at offset 2: 0 (no exceptions)
        assert_eq!(u16::from_le_bytes(img[2..4].try_into().unwrap()), 0);
        // x87 tag word at offset 4: 0xFFFF (all empty)
        assert_eq!(u16::from_le_bytes(img[4..6].try_into().unwrap()), 0xFFFF);
        // MXCSR at offset 24: 0x1F80
        assert_eq!(u32::from_le_bytes(img[24..28].try_into().unwrap()), 0x1F80);
        // XMM registers at offsets 160-415 should all be zero
        assert!(
            img[160..416].iter().all(|&b| b == 0),
            "XMM registers not zeroed"
        );
        // x87 register space at offsets 32-159 should all be zero
        assert!(img[32..160].iter().all(|&b| b == 0), "x87 regs not zeroed");
    }
}
