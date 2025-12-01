use super::{DeliverFault, SignalState};
use crate::{ConstPtr, Errno, MutPtr, Task};
use core::mem::offset_of;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{
    PtRegs,
    signal::{SaFlags, SigAction, SigSet, Siginfo, Signal, Ucontext, x86::Sigcontext},
};

#[repr(C)]
#[derive(Clone)]
struct SignalFrame {
    return_address: usize,
    signal: i32,
    context: LegacyContext,
}

#[repr(C)]
#[derive(Clone)]
struct LegacyContext {
    sigcontext: Sigcontext,
    unused: [u32; 136],
    extramask: u32,
}

#[repr(C)]
#[derive(Clone)]
struct SignalFrameRt {
    return_address: usize,
    signal: i32,
    siginfo_ptr: usize,
    ucontext_ptr: usize,
    siginfo: Siginfo,
    ucontext: Ucontext,
}

impl Task {
    /// Legacy signal return syscall implementation for x86.
    pub(crate) fn sys_sigreturn(&self, ctx: &mut PtRegs) -> Result<usize, Errno> {
        let lctx_addr = ctx.esp.wrapping_sub(8);
        let lctx_ptr = ConstPtr::<LegacyContext>::from_usize(lctx_addr);
        let Some(lctx) = (unsafe { lctx_ptr.read_at_offset(0) }) else {
            self.force_signal(Signal::SIGSEGV, false);
            return Err(Errno::EFAULT);
        };
        let lctx = lctx.into_owned();

        let mask = SigSet::from_u64(
            u64::from(lctx.sigcontext.oldmask) | (u64::from(lctx.extramask) << 32),
        );
        self.signals.set_signal_mask(mask);

        Ok(restore_sigcontext(ctx, &lctx.sigcontext))
    }
}

pub(super) fn uctx_addr(ctx: &PtRegs) -> usize {
    // Skip parameters.
    ctx.esp
        .wrapping_add(offset_of!(SignalFrameRt, ucontext) - offset_of!(SignalFrameRt, signal))
}

pub(super) fn sp(ctx: &PtRegs) -> usize {
    ctx.esp
}

pub(super) fn get_signal_frame(sp: usize, action: &SigAction) -> usize {
    let mut frame_addr = sp;

    // Space for the signal frame.
    if action.flags.contains(SaFlags::SIGINFO) {
        frame_addr -= core::mem::size_of::<SignalFrameRt>();
    } else {
        frame_addr -= core::mem::size_of::<SignalFrame>();
    }

    // Align the frame (offset by 4 bytes for return address).
    frame_addr &= !15;
    frame_addr -= 4;

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
            // No restorer was provided. This is optional on x86, but if one is
            // not present then we have to provide one from the vDSO. Since we
            // don't currently have a vDSO, we can't deliver the signal.
            //
            // Fortunately, if glibc sees that there is no vDSO, it will provide
            // a restorer. musl always provides a restorer.
            //
            // FUTURE: add a vDSO with a restorer.
            return Err(DeliverFault);
        }

        let mask = self.blocked.get().as_u64();
        let oldmask = mask.truncate();
        let extramask = (mask >> 32).truncate();

        let last_exception = self.last_exception.get();
        let sigcontext = Sigcontext {
            gs: ctx.xgs.truncate(),
            fs: ctx.xfs.truncate(),
            es: ctx.xes.truncate(),
            ds: ctx.xds.truncate(),
            edi: ctx.edi.truncate(),
            esi: ctx.esi.truncate(),
            ebp: ctx.ebp.truncate(),
            esp: ctx.esp.truncate(),
            ebx: ctx.ebx.truncate(),
            edx: ctx.edx.truncate(),
            ecx: ctx.ecx.truncate(),
            eax: ctx.eax.truncate(),
            eip: ctx.eip.truncate(),
            cs: ctx.xcs.truncate(),
            eflags: ctx.eflags.truncate(),
            esp_at_signal: ctx.esp.truncate(),
            ss: ctx.xss.truncate(),
            err: last_exception.error_code,
            trapno: last_exception.exception.0.into(),
            oldmask,
            cr2: last_exception.cr2.truncate(),
            fpstate: 0, // TODO
        };

        let rt = action.flags.contains(SaFlags::SIGINFO);
        if rt {
            let frame_ptr = MutPtr::from_usize(frame_addr);
            let frame = SignalFrameRt {
                return_address: action.restorer,
                signal: siginfo.signo,
                siginfo_ptr: frame_addr + core::mem::offset_of!(SignalFrameRt, siginfo),
                ucontext_ptr: frame_addr + core::mem::offset_of!(SignalFrameRt, ucontext),
                ucontext: Ucontext {
                    flags: 0,
                    link: core::ptr::null_mut(),
                    stack: self.altstack.get(),
                    mcontext: sigcontext,
                    sigmask: self.blocked.get(),
                },
                siginfo: siginfo.clone(),
            };
            unsafe { frame_ptr.write_at_offset(0, frame).ok_or(DeliverFault)? };
        } else {
            let frame_ptr = MutPtr::from_usize(frame_addr);
            let frame = SignalFrame {
                return_address: action.restorer,
                signal: siginfo.signo,
                context: LegacyContext {
                    sigcontext,
                    unused: [0; 136],
                    extramask,
                },
            };
            unsafe { frame_ptr.write_at_offset(0, frame).ok_or(DeliverFault)? };
        }

        ctx.esp = frame_addr;
        ctx.eip = action.sigaction;
        ctx.eax = siginfo.signo.reinterpret_as_unsigned() as usize;
        if rt {
            ctx.edx = frame_addr + core::mem::offset_of!(SignalFrameRt, siginfo);
            ctx.ecx = frame_addr + core::mem::offset_of!(SignalFrameRt, ucontext);
        } else {
            ctx.edx = 0;
            ctx.ecx = 0;
        }
        ctx.eflags &= !litebox_common_linux::EFLAGS_DF;
        Ok(())
    }
}

pub(super) fn restore_sigcontext(
    ctx: &mut PtRegs,
    sigctx: &litebox_common_linux::signal::x86::Sigcontext,
) -> usize {
    let litebox_common_linux::signal::x86::Sigcontext {
        gs,
        fs,
        es,
        ds,
        edi,
        esi,
        ebp,
        esp,
        ebx,
        edx,
        ecx,
        eax,
        trapno: _,
        err: _,
        eip,
        cs,
        eflags,
        esp_at_signal: _,
        ss,
        fpstate: _,
        oldmask: _,
        cr2: _,
    } = *sigctx;

    ctx.xgs = gs as usize;
    ctx.xfs = fs as usize;
    ctx.xes = es as usize;
    ctx.xds = ds as usize;
    ctx.xcs = cs as usize;
    ctx.xss = ss as usize;
    ctx.edi = edi as usize;
    ctx.esi = esi as usize;
    ctx.ebp = ebp as usize;
    ctx.esp = esp as usize;
    ctx.ebx = ebx as usize;
    ctx.edx = edx as usize;
    ctx.ecx = ecx as usize;
    ctx.eax = eax as usize;
    ctx.eip = eip as usize;
    ctx.eflags = eflags as usize;

    // TODO: restore fpstate

    ctx.eax
}
