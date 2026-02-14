// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Signal handling syscalls and support.

#[cfg(target_arch = "x86")]
pub(crate) mod x86;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use litebox_common_linux::signal::SignalDisposition;
#[cfg(target_arch = "x86")]
use x86 as arch;
#[cfg(target_arch = "x86_64")]
use x86_64 as arch;
use zerocopy::FromZeros;

use crate::syscalls::process::ExitStatus;
use crate::{ConstPtr, MutPtr, ShimFS, Task};
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::Arc;
use core::cell::{Cell, RefCell};
use litebox::{
    platform::{RawConstPointer as _, RawMutPointer as _},
    shim::Exception,
    sync::Mutex,
    utils::ReinterpretUnsignedExt as _,
};
use litebox_common_linux::signal::{
    MINSIGSTKSZ, NSIG, SI_KERNEL, SI_USER, SIG_DFL, SIG_IGN, SaFlags, SigAction, SigAltStack,
    SigSet, Siginfo, SiginfoData, SigmaskHow, Signal, SsFlags, Ucontext,
};
use litebox_common_linux::{PtRegs, errno::Errno};
use litebox_platform_multiplex::Platform;

pub(crate) struct SignalState {
    /// Pending thread signals.
    pending: RefCell<PendingSignals>,
    /// Currently blocked signals.
    blocked: Cell<SigSet>,
    /// Signal handlers.
    handlers: RefCell<Arc<SignalHandlers>>,
    /// Alternate signal stack.
    altstack: Cell<SigAltStack>,
    /// The last exception info recorded for signal delivery.
    last_exception: Cell<litebox::shim::ExceptionInfo>,
}

impl SignalState {
    pub fn new_process() -> Self {
        Self {
            pending: RefCell::new(PendingSignals::new()),
            blocked: Cell::new(SigSet::empty()),
            handlers: RefCell::new(Arc::new(SignalHandlers::new())),
            altstack: Cell::new(SigAltStack {
                sp: 0,
                flags: SsFlags::DISABLE,
                size: 0,
                #[cfg(target_arch = "x86_64")]
                __pad: 0,
            }),
            last_exception: Cell::new(litebox::shim::ExceptionInfo {
                exception: litebox::shim::Exception(0),
                error_code: 0,
                cr2: 0,
                kernel_mode: false,
            }),
        }
    }

    pub fn clone_for_new_task(&self) -> Self {
        Self {
            // Reset pending
            pending: RefCell::new(PendingSignals::new()),
            // Preserve blocked
            blocked: Cell::new(self.blocked.get()),
            // Share handlers across tasks
            handlers: self.handlers.clone(),
            // Clear altstack
            altstack: SigAltStack {
                flags: SsFlags::DISABLE,
                sp: 0,
                size: 0,
                #[cfg(target_arch = "x86_64")]
                __pad: 0,
            }
            .into(),
            // Preserve last exception
            last_exception: self.last_exception.clone(),
        }
    }

    /// Resets signal state for an `execve` call.
    pub(crate) fn reset_for_exec(&self) {
        let mut handlers = self.handlers.borrow_mut();
        // Ensure that the signal handlers are no longer shared.
        let handlers = Arc::make_mut(&mut handlers);
        // Reset the handlers to defaults.
        for handler in &mut handlers.inner.get_mut().handlers {
            handler.action = SigAction {
                sigaction: if handler.action.sigaction == SIG_IGN {
                    SIG_IGN
                } else {
                    SIG_DFL
                },
                restorer: 0,
                flags: SaFlags::empty(),
                mask: SigSet::empty(),
                #[cfg(target_arch = "x86_64")]
                __pad: 0,
            };
        }
        self.clear_sigaltstack();
    }
}

struct SignalHandlers {
    inner: Mutex<Platform, SignalHandlersInner>,
}

#[derive(Clone)]
struct SignalHandlersInner {
    handlers: [Handler; NSIG],
}

impl SignalHandlersInner {
    /// Returns the array index for the given signal.
    fn sig_index(signal: Signal) -> usize {
        (signal.as_i32().reinterpret_as_unsigned() - 1) as usize
    }
}

impl core::ops::Index<Signal> for SignalHandlersInner {
    type Output = Handler;

    fn index(&self, signal: Signal) -> &Self::Output {
        &self.handlers[Self::sig_index(signal)]
    }
}

impl core::ops::IndexMut<Signal> for SignalHandlersInner {
    fn index_mut(&mut self, signal: Signal) -> &mut Self::Output {
        &mut self.handlers[Self::sig_index(signal)]
    }
}

#[derive(Clone)]
struct Handler {
    action: SigAction,
    /// The user cannot change this action.
    immutable: bool,
}

impl SignalHandlers {
    fn new() -> Self {
        Self {
            inner: Mutex::new(SignalHandlersInner {
                handlers: core::array::from_fn(|i| Handler {
                    action: SigAction {
                        sigaction: SIG_DFL,
                        restorer: 0,
                        flags: SaFlags::empty(),
                        mask: SigSet::empty(),
                        #[cfg(target_arch = "x86_64")]
                        __pad: 0,
                    },
                    immutable: i == SignalHandlersInner::sig_index(Signal::SIGKILL)
                        || i == SignalHandlersInner::sig_index(Signal::SIGSTOP),
                }),
            }),
        }
    }
}

impl Clone for SignalHandlers {
    fn clone(&self) -> Self {
        Self {
            inner: Mutex::new(self.inner.lock().clone()),
        }
    }
}

struct PendingSignals {
    /// The set of pending signals.
    pending: SigSet,
    /// The queue of pending siginfo structures.
    queue: VecDeque<Siginfo>,
}

impl PendingSignals {
    fn new() -> Self {
        Self {
            pending: SigSet::empty(),
            queue: VecDeque::new(),
        }
    }

    fn next(&self, blocked: SigSet) -> Option<Signal> {
        const EXCEPTION_SIGNALS: SigSet = SigSet::empty()
            .with(Signal::SIGSEGV)
            .with(Signal::SIGBUS)
            .with(Signal::SIGFPE)
            .with(Signal::SIGILL)
            .with(Signal::SIGTRAP);

        let pending = self.pending & !blocked;

        // Look for exception signals first since these must be delivered with
        // the user context at the time of the exception.
        let next = (pending & EXCEPTION_SIGNALS)
            .lowest_set()
            .or_else(|| pending.lowest_set())?;

        Some(next)
    }

    fn remove(&mut self, signal: Signal) -> Siginfo {
        // Find the entry.
        let pos = self
            .queue
            .iter()
            .position(|info| info.signo == signal.as_i32())
            .expect("removing non-pending signal");

        // If there are no more entries with this signal number, remove it from
        // the pending mask.
        let more = self
            .queue
            .iter()
            .skip(pos + 1)
            .any(|info| info.signo == signal.as_i32());
        if !more {
            self.pending.remove(signal);
        }

        self.queue.remove(pos).unwrap()
    }

    fn push(&mut self, rlimits: &super::process::ResourceLimits, signal: Signal, siginfo: Siginfo) {
        assert_eq!(signal.as_i32(), siginfo.signo);

        // Don't queue duplicates for standard signals.
        if !signal.is_rt_signal() && self.pending.contains(signal) {
            return;
        }

        // Restrict maximum queued signals via rlimits when Linux would do so.
        if signal.is_rt_signal() || (siginfo.code != SI_USER && siginfo.code != SI_KERNEL) {
            let limit = rlimits.get_rlimit_cur(litebox_common_linux::RlimitResource::SIGPENDING);
            if self.queue.len() >= limit {
                // Drop the signal.
                return;
            }
        }
        self.queue.push_back(siginfo);
        self.pending.add(signal);
    }
}

/// Returns whether `sp` is within the given signal stack.
fn is_on_stack(stack: &SigAltStack, sp: usize) -> bool {
    if stack.flags.contains(SsFlags::DISABLE) {
        return false;
    }
    let stack_start = stack.sp;
    let stack_end = stack.sp + stack.size;
    sp >= stack_start && sp < stack_end
}

/// Creates a `Siginfo` for an exception signal.
fn siginfo_exception(signal: Signal, fault_address: usize) -> Siginfo {
    Siginfo {
        signo: signal.as_i32(),
        errno: 0,
        code: SI_KERNEL,
        #[cfg(target_arch = "x86_64")]
        __pad: 0,
        data: SiginfoData::new_addr(fault_address),
    }
}

/// Creates a `Siginfo` for a signal sent by a user process via `kill()`,
/// `tkill()`, or `tgkill()`.
fn siginfo_kill(signal: Signal) -> Siginfo {
    Siginfo {
        signo: signal.as_i32(),
        errno: 0,
        code: SI_USER,
        #[cfg(target_arch = "x86_64")]
        __pad: 0,
        data: SiginfoData::new_zeroed(),
    }
}

impl SignalState {
    /// Updates the blocked signal mask.
    fn set_signal_mask(&self, mask: SigSet) {
        self.blocked.set(mask);
    }

    /// Sets the alternate signal stack.
    fn set_sigaltstack(&self, ss: SigAltStack) -> Result<(), Errno> {
        if !ss
            .flags
            .difference(SsFlags::DISABLE | SsFlags::ONSTACK | SsFlags::AUTODISARM)
            .is_empty()
        {
            Err(Errno::EINVAL)
        } else if ss.flags.contains(SsFlags::DISABLE) {
            self.clear_sigaltstack();
            Ok(())
        } else if ss.sp.checked_add(ss.size).is_none() {
            Err(Errno::EINVAL)
        } else if ss.size < MINSIGSTKSZ {
            Err(Errno::ENOMEM)
        } else {
            self.altstack.set(SigAltStack {
                sp: ss.sp,
                flags: ss.flags & SsFlags::AUTODISARM,
                size: ss.size,
                #[cfg(target_arch = "x86_64")]
                __pad: 0,
            });
            Ok(())
        }
    }

    /// Clears the alternate signal stack.
    fn clear_sigaltstack(&self) {
        self.altstack.set(SigAltStack {
            sp: 0,
            flags: SsFlags::DISABLE,
            size: 0,
            #[cfg(target_arch = "x86_64")]
            __pad: 0,
        });
    }

    fn deliver_signal(
        &self,
        signal: Signal,
        siginfo: &Siginfo,
        action: &SigAction,
        ctx: &mut PtRegs,
    ) -> Result<(), DeliverFault> {
        let sp = arch::sp(ctx);
        let on_alt_stack = is_on_stack(&self.altstack.get(), sp);
        let altstack = self.altstack.get();
        let switch_stacks = action.flags.contains(SaFlags::ONSTACK)
            && !on_alt_stack
            && !altstack.flags.contains(SsFlags::DISABLE);
        let sp = if switch_stacks {
            altstack.sp + altstack.size
        } else {
            sp
        };

        let frame_addr = arch::get_signal_frame(sp, action);

        if (switch_stacks || on_alt_stack) && !is_on_stack(&altstack, frame_addr) {
            return Err(DeliverFault);
        }

        self.write_signal_frame(frame_addr, siginfo, action, ctx)?;

        let mut mask = self.blocked.get() | action.mask;
        if !action.flags.contains(SaFlags::NODEFER) {
            mask.add(signal);
        }
        self.set_signal_mask(mask);

        if altstack.flags.contains(SsFlags::AUTODISARM) {
            self.clear_sigaltstack();
        }
        Ok(())
    }
}

/// A fault when delivering a signal.
struct DeliverFault;

impl<FS: ShimFS> Task<FS> {
    pub(crate) fn sys_rt_sigprocmask(
        &self,
        how: SigmaskHow,
        set_ptr: Option<crate::ConstPtr<SigSet>>,
        oldset_ptr: Option<crate::MutPtr<SigSet>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        let set = if let Some(set_ptr) = set_ptr {
            Some(set_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?)
        } else {
            None
        };

        if let Some(oldset_ptr) = oldset_ptr {
            let oldset = self.signals.blocked.get();
            oldset_ptr.write_at_offset(0, oldset).ok_or(Errno::EFAULT)?;
        }

        if let Some(set) = set {
            let mut blocked = self.signals.blocked.get();
            match how {
                SigmaskHow::SIG_BLOCK => {
                    blocked = blocked | set;
                }
                SigmaskHow::SIG_UNBLOCK => {
                    blocked = blocked & !set;
                }
                SigmaskHow::SIG_SETMASK => {
                    blocked = set;
                }
            }
            self.signals.set_signal_mask(blocked);
        }

        Ok(0)
    }

    pub(crate) fn sys_sigaltstack(
        &self,
        ss_ptr: Option<ConstPtr<SigAltStack>>,
        old_ss_ptr: Option<MutPtr<SigAltStack>>,
        ctx: &PtRegs,
    ) -> Result<usize, Errno> {
        let mut old_ss = self.signals.altstack.get();
        let is_on_stack = is_on_stack(&old_ss, arch::sp(ctx));
        if let Some(old_ss_ptr) = old_ss_ptr {
            if is_on_stack {
                old_ss.flags |= SsFlags::ONSTACK;
            }
            old_ss_ptr.write_at_offset(0, old_ss).ok_or(Errno::EFAULT)?;
        }
        if let Some(ss_ptr) = ss_ptr {
            if is_on_stack {
                return Err(Errno::EPERM);
            }
            let ss = ss_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            self.signals.set_sigaltstack(ss)?;
        }
        Ok(0)
    }

    pub(crate) fn sys_rt_sigreturn(&self, ctx: &mut PtRegs) -> Result<usize, Errno> {
        let uctx_addr = arch::uctx_addr(ctx);
        let uctx_ptr = ConstPtr::<Ucontext>::from_usize(uctx_addr);
        let Some(uctx) = uctx_ptr.read_at_offset(0) else {
            self.force_signal(Signal::SIGSEGV, false);
            return Err(Errno::EFAULT);
        };

        // Restore the alternate signal stack, ignoring errors.
        self.signals.set_sigaltstack(uctx.stack).ok();

        self.signals.set_signal_mask(uctx.sigmask);

        Ok(arch::restore_sigcontext(ctx, &uctx.mcontext))
    }

    pub(crate) fn sys_rt_sigaction(
        &self,
        signal: Signal,
        act_ptr: Option<ConstPtr<SigAction>>,
        oldact_ptr: Option<MutPtr<SigAction>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if signal == Signal::SIGKILL || signal == Signal::SIGSTOP {
            return Err(Errno::EINVAL);
        }
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        let act = if let Some(act_ptr) = act_ptr {
            Some(act_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?)
        } else {
            None
        };

        let handlers = self.signals.handlers.borrow();
        let old_act = {
            let mut inner = handlers.inner.lock();
            let handler = &mut inner[signal];
            if handler.immutable {
                return Err(Errno::EINVAL);
            }
            let old_act = handler.action;
            if let Some(act) = act {
                handler.action = act;
            }
            old_act
        };

        if let Some(oldact_ptr) = oldact_ptr {
            oldact_ptr
                .write_at_offset(0, old_act)
                .ok_or(Errno::EFAULT)?;
        }

        Ok(0)
    }

    pub(crate) fn sys_kill(&self, pid: i32, signal: i32) -> Result<usize, Errno> {
        self.do_kill(Some(pid), None, signal)
    }

    pub(crate) fn sys_tkill(&self, tid: i32, signal: i32) -> Result<usize, Errno> {
        self.do_kill(None, Some(tid), signal)
    }

    pub(crate) fn sys_tgkill(&self, pid: i32, tid: i32, signal: i32) -> Result<usize, Errno> {
        self.do_kill(Some(pid), Some(tid), signal)
    }

    fn do_kill(&self, pid: Option<i32>, tid: Option<i32>, signal: i32) -> Result<usize, Errno> {
        let signal = Signal::try_from(signal)?;
        if pid.is_none_or(|pid| pid == self.pid) && tid.is_none_or(|tid| tid == self.tid) {
            self.send_signal(signal, siginfo_kill(signal));
            Ok(0)
        } else {
            log_unsupported!("sys_{{t|tg}}kill with remote pid/tid");
            Err(Errno::ESRCH)
        }
    }

    /// Returns whether there are any pending signals that can be delivered.
    pub(crate) fn has_pending_signals(&self) -> bool {
        let pending = self.signals.pending.borrow().pending & !self.signals.blocked.get();
        !pending.is_empty()
    }

    /// Deliver any pending signals.
    pub(crate) fn process_signals(&self, ctx: &mut PtRegs) {
        loop {
            let mut pending = self.signals.pending.borrow_mut();
            let Some(signal) = pending.next(self.signals.blocked.get()) else {
                break;
            };
            if self.is_exiting() {
                // Don't deliver any more signals if exiting.
                return;
            }

            let siginfo: Siginfo = pending.remove(signal);
            drop(pending);
            let action = self.signals.handlers.borrow().inner.lock()[signal].action;
            #[expect(clippy::match_same_arms)]
            match action.sigaction {
                SIG_DFL => {
                    match signal.default_disposition() {
                        SignalDisposition::Terminate
                        | SignalDisposition::Core
                        | SignalDisposition::Stop => {
                            // STOP is not currently supported, so treat as
                            // terminate. Core dumps are also not currently
                            // supported.
                            litebox::log_println!(
                                self.global.platform,
                                "-- Fatal signal {:?}: terminating task {}:{}",
                                signal,
                                self.pid,
                                self.tid,
                            );
                            self.exit_group(ExitStatus::Signal(signal));
                        }
                        SignalDisposition::Ignore => {}
                        SignalDisposition::Continue => {
                            // Stop is not supported, so continue does nothing.
                        }
                    }
                }
                SIG_IGN => {}
                _ => {
                    if let Err(DeliverFault) =
                        self.signals.deliver_signal(signal, &siginfo, &action, ctx)
                    {
                        // Failed to deliver signal. Inject a SIGSEGV
                        // (terminating the process if we were trying to deliver
                        // a SIGSEGV).
                        self.force_signal(Signal::SIGSEGV, signal == Signal::SIGSEGV);
                    }
                }
            }
        }
    }

    /// Only supports sending signals to self for now.
    fn send_signal(&self, signal: Signal, siginfo: Siginfo) {
        self.signals
            .pending
            .borrow_mut()
            .push(&self.process().limits, signal, siginfo);
    }

    /// Forces a signal to be delivered on next call to `check_for_signals`.
    fn force_signal(&self, signal: Signal, force_exit: bool) {
        let siginfo = Siginfo {
            signo: signal.as_i32(),
            errno: 0,
            code: SI_KERNEL,
            #[cfg(target_arch = "x86_64")]
            __pad: 0,
            data: SiginfoData::new_zeroed(),
        };
        self.force_signal_with_info(signal, force_exit, siginfo);
    }

    fn force_signal_with_info(&self, signal: Signal, force_exit: bool, siginfo: Siginfo) {
        assert!(matches!(signal, Signal::SIGKILL | Signal::SIGSEGV));

        self.signals
            .pending
            .borrow_mut()
            .push(&self.process().limits, signal, siginfo);

        // Update the handler if necessary to ensure the signal is handled.
        let handlers = self.signals.handlers.borrow();
        let mut inner = handlers.inner.lock();
        let handler = &mut inner[signal];
        if force_exit
            || self.signals.blocked.get().contains(signal)
            || handler.action.sigaction == SIG_IGN
        {
            let mut blocked = self.signals.blocked.get();
            blocked.remove(signal);
            self.signals.set_signal_mask(blocked);
            handler.action = SigAction {
                sigaction: SIG_DFL,
                restorer: 0,
                flags: SaFlags::empty(),
                mask: SigSet::empty(),
                #[cfg(target_arch = "x86_64")]
                __pad: 0,
            };
            // Don't allow further changes to this action.
            handler.immutable = true;
        }
    }

    pub(crate) fn handle_exception_request(&self, info: &litebox::shim::ExceptionInfo) {
        let signal = match info.exception {
            Exception::DIVIDE_ERROR => Signal::SIGFPE,
            Exception::BREAKPOINT => Signal::SIGTRAP,
            Exception::INVALID_OPCODE => Signal::SIGILL,
            // Page faults and unknown exceptions map to SIGSEGV. There may be
            // more appropriate signals in some other cases (e.g., SIGBUS).
            _ => Signal::SIGSEGV,
        };
        // For page faults, provide the faulting address.
        let fault_address = if info.exception == Exception::PAGE_FAULT {
            info.cr2
        } else {
            0
        };
        self.signals.last_exception.set(*info);
        self.force_signal_with_info(signal, false, siginfo_exception(signal, fault_address));
    }
}
