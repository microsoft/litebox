// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Signal handling syscalls and support.

#[cfg(target_arch = "x86")]
pub(crate) mod x86;
#[cfg(target_arch = "x86_64")]
mod x86_64;

/// Reinitializes the guest FP/SIMD state for a fresh process image.
/// Call after `execve` resets registers but before re-entering the guest.
#[cfg(target_arch = "x86_64")]
pub(crate) fn reinit_guest_fp_state(fp_regs: &mut litebox_common_linux::FpRegs) {
    x86_64::reinit_guest_fp_state(fp_regs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigsegv_page_fault_uses_maperr_for_nonpresent_pages() {
        let siginfo = siginfo_exception(Signal::SIGSEGV, 0x1234, Some(0x6));
        assert_eq!(siginfo.code, SEGV_MAPERR);
    }

    #[test]
    fn sigsegv_page_fault_uses_accerr_for_protection_faults() {
        let siginfo = siginfo_exception(Signal::SIGSEGV, 0x1234, Some(0x7));
        assert_eq!(siginfo.code, SEGV_ACCERR);
    }

    #[test]
    fn non_page_fault_exceptions_keep_kernel_code() {
        let siginfo = siginfo_exception(Signal::SIGILL, 0, None);
        assert_eq!(siginfo.code, SI_KERNEL);
    }
}

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
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::time::Duration;
use litebox::{
    platform::{Instant as _, RawConstPointer as _, RawMutPointer as _, TimeProvider},
    process::{ProcessId, ProcessState},
    shim::Exception,
    sync::Mutex,
    utils::ReinterpretUnsignedExt as _,
};
use litebox_common_linux::signal::{
    MINSIGSTKSZ, NSIG, SEGV_ACCERR, SEGV_MAPERR, SI_KERNEL, SI_USER, SIG_DFL, SIG_IGN, SaFlags,
    SigAction, SigAltStack, SigSet, Siginfo, SiginfoData, SigmaskHow, Signal, SsFlags, Ucontext,
};
use litebox_common_linux::{PtRegs, errno::Errno};
use litebox_platform_multiplex::Platform;

pub(crate) struct SignalState {
    /// Pending thread signals.
    pending: RefCell<PendingSignals>,
    /// Pending process signals (shared across all threads).
    shared_pending: Arc<Mutex<Platform, PendingSignals>>,
    /// Currently blocked signals.
    blocked: Cell<SigSet>,
    /// Signal handlers.
    handlers: RefCell<Arc<SignalHandlers>>,
    /// Alternate signal stack.
    altstack: Cell<SigAltStack>,
    /// The last exception info recorded for signal delivery.
    last_exception: Cell<litebox::shim::ExceptionInfo>,
    /// Deferred mask restore (like Linux's TIF_RESTORE_SIGMASK).
    ///
    /// When set, `process_signals` will restore this mask after delivering
    /// pending signals. Used by `epoll_pwait` / `ppoll` to atomically
    /// unblock signals during the wait and re-block them afterwards.
    restore_mask: Cell<Option<SigSet>>,
}

impl SignalState {
    pub fn new_process() -> Self {
        Self {
            pending: RefCell::new(PendingSignals::new()),
            shared_pending: Arc::new(Mutex::new(PendingSignals::new())),
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
            restore_mask: Cell::new(None),
        }
    }

    /// Reconstruct signal state from a fork snapshot.
    ///
    /// Per POSIX/Linux fork semantics: handlers and blocked mask are inherited,
    /// pending signals are not.
    pub fn new_from_restore(
        blocked: SigSet,
        handler_snapshots: &[crate::syscalls::fork_snapshot::SignalHandlerSnapshot],
        altstack: SigAltStack,
    ) -> Self {
        let handlers = SignalHandlers::from_restore(handler_snapshots);
        Self {
            pending: RefCell::new(PendingSignals::new()),
            shared_pending: Arc::new(Mutex::new(PendingSignals::new())),
            blocked: Cell::new(blocked),
            handlers: RefCell::new(Arc::new(handlers)),
            altstack: Cell::new(altstack),
            last_exception: Cell::new(litebox::shim::ExceptionInfo {
                exception: litebox::shim::Exception(0),
                error_code: 0,
                cr2: 0,
                kernel_mode: false,
            }),
            restore_mask: Cell::new(None),
        }
    }

    /// Get the current blocked signal mask.
    pub fn get_blocked(&self) -> SigSet {
        self.blocked.get()
    }

    /// Get the current alternate signal stack.
    #[allow(dead_code)] // Used by fork snapshot capture.
    pub fn altstack(&self) -> SigAltStack {
        self.altstack.get()
    }

    /// Snapshot all signal handlers as plain data for true-fork export.
    #[allow(dead_code)] // Used by fork snapshot capture.
    pub fn snapshot_handlers(&self) -> Vec<crate::syscalls::fork_snapshot::SignalHandlerSnapshot> {
        let handlers = self.handlers.borrow();
        let inner = handlers.inner.lock();
        inner
            .handlers
            .iter()
            .map(|h| crate::syscalls::fork_snapshot::SignalHandlerSnapshot {
                sigaction: h.action.sigaction,
                restorer: h.action.restorer,
                flags: h.action.flags,
                mask: h.action.mask,
            })
            .collect()
    }

    /// Set the blocked signal mask.
    pub fn set_blocked(&self, mask: SigSet) {
        self.blocked.set(mask);
    }

    /// Schedule a deferred mask restore. The mask will be restored after the
    /// next `process_signals` call delivers any unblocked signals.
    pub fn set_restore_mask(&self, mask: SigSet) {
        self.restore_mask.set(Some(mask));
    }

    pub(crate) fn last_exception(&self) -> litebox::shim::ExceptionInfo {
        self.last_exception.get()
    }

    pub fn clone_for_new_task(&self) -> Self {
        Self {
            // Reset pending
            pending: RefCell::new(PendingSignals::new()),
            // Share process-wide pending signals
            shared_pending: self.shared_pending.clone(),
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
            restore_mask: Cell::new(None),
        }
    }

    /// Creates signal state for a forked child process.
    ///
    /// Unlike [`clone_for_new_task`](Self::clone_for_new_task) (which shares
    /// signal handlers via `Arc` for threads), fork creates a deep copy of
    /// the handlers so the child process can modify them independently.
    ///
    /// If `clear_altstack` is true, the child's alternate signal stack is
    /// disabled (standard fork behavior). If false, the parent's altstack
    /// is inherited (used with `CLONE_VM | CLONE_VFORK`).
    pub fn clone_for_fork(&self, clear_altstack: bool) -> Self {
        let altstack = if clear_altstack {
            SigAltStack {
                flags: SsFlags::DISABLE,
                sp: 0,
                size: 0,
                #[cfg(target_arch = "x86_64")]
                __pad: 0,
            }
        } else {
            self.altstack.get()
        };
        Self {
            pending: RefCell::new(PendingSignals::new()),
            blocked: Cell::new(self.blocked.get()),
            shared_pending: Arc::new(Mutex::new(PendingSignals::new())),
            // Deep-copy handlers so the child's rt_sigaction doesn't affect
            // the parent (important for vfork where both run concurrently).
            handlers: RefCell::new(Arc::new((*self.handlers.borrow()).as_ref().clone())),
            altstack: altstack.into(),
            last_exception: self.last_exception.clone(),
            restore_mask: Cell::new(None),
        }
    }

    /// Resets user-installed signal handlers to `SIG_DFL`.
    ///
    /// Signals already set to `SIG_DFL` or `SIG_IGN` are left untouched.
    /// Used by both `execve` (which also clears the altstack) and
    /// `CLONE_CLEAR_SIGHAND` (which does not touch the altstack).
    pub(crate) fn reset_caught_handlers(&self) {
        let mut handlers = self.handlers.borrow_mut();
        // Ensure that the signal handlers are no longer shared.
        let handlers = Arc::make_mut(&mut handlers);
        for handler in &mut handlers.inner.get_mut().handlers {
            if handler.action.sigaction != SIG_DFL && handler.action.sigaction != SIG_IGN {
                handler.action = SigAction {
                    sigaction: SIG_DFL,
                    restorer: 0,
                    flags: SaFlags::empty(),
                    mask: SigSet::empty(),
                    #[cfg(target_arch = "x86_64")]
                    __pad: 0,
                };
            }
        }
    }

    /// Resets signal state for an `execve` call.
    pub(crate) fn reset_for_exec(&self) {
        self.reset_caught_handlers();
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

    fn from_restore(
        handler_snapshots: &[crate::syscalls::fork_snapshot::SignalHandlerSnapshot],
    ) -> Self {
        let mut handlers: [Handler; NSIG] = core::array::from_fn(|i| Handler {
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
        });
        for (i, snap) in handler_snapshots.iter().enumerate() {
            if i < NSIG {
                // Don't override SIGKILL/SIGSTOP immutable handlers.
                if !handlers[i].immutable {
                    handlers[i].action = SigAction {
                        sigaction: snap.sigaction,
                        restorer: snap.restorer,
                        flags: snap.flags,
                        mask: snap.mask,
                        #[cfg(target_arch = "x86_64")]
                        __pad: 0,
                    };
                }
            }
        }
        Self {
            inner: Mutex::new(SignalHandlersInner { handlers }),
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

pub(crate) struct PendingSignals {
    /// The set of pending signals.
    pending: SigSet,
    /// The queue of pending siginfo structures.
    queue: VecDeque<Siginfo>,
}

impl PendingSignals {
    pub(crate) fn new() -> Self {
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

    /// Returns true if any pending signal is NOT in `blocked`.
    fn has_unblocked(&self, blocked: SigSet) -> bool {
        !(self.pending & !blocked).is_empty()
    }

    /// Returns true if `signal` is in the pending set.
    fn is_pending(&self, signal: Signal) -> bool {
        self.pending.contains(signal)
    }

    /// Returns the raw pending signal set.
    fn pending_set(&self) -> SigSet {
        self.pending
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

    pub(crate) fn push(
        &mut self,
        rlimits: &super::process::ResourceLimits,
        signal: Signal,
        siginfo: Siginfo,
    ) {
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
fn siginfo_exception(
    signal: Signal,
    fault_address: usize,
    page_fault_error_code: Option<u64>,
) -> Siginfo {
    let code = match (signal, page_fault_error_code) {
        (Signal::SIGSEGV, Some(error_code)) => {
            if (error_code & 0x1) == 0 {
                SEGV_MAPERR
            } else {
                SEGV_ACCERR
            }
        }
        _ => SI_KERNEL,
    };

    Siginfo {
        signo: signal.as_i32(),
        errno: 0,
        code,
        #[cfg(target_arch = "x86_64")]
        __pad: 0,
        data: SiginfoData::new_addr(fault_address),
    }
}

/// Creates a `Siginfo` for a signal sent by a user process via `kill()`,
/// `tkill()`, or `tgkill()`.
pub(crate) fn siginfo_kill(signal: Signal) -> Siginfo {
    Siginfo {
        signo: signal.as_i32(),
        errno: 0,
        code: SI_USER,
        #[cfg(target_arch = "x86_64")]
        __pad: 0,
        data: SiginfoData::new_zeroed(),
    }
}

/// Build a `Siginfo` for a kernel-generated signal (e.g. SIGPIPE from a
/// broken-pipe write).  Uses `SI_KERNEL` to match real Linux behaviour.
pub(crate) fn siginfo_kernel(signal: Signal) -> Siginfo {
    Siginfo {
        signo: signal.as_i32(),
        errno: 0,
        code: SI_KERNEL,
        #[cfg(target_arch = "x86_64")]
        __pad: 0,
        data: SiginfoData::new_zeroed(),
    }
}

impl SignalState {
    /// Updates the blocked signal mask.
    fn set_signal_mask(&self, mut mask: SigSet) {
        mask.remove(Signal::SIGKILL);
        mask.remove(Signal::SIGSTOP);
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
        ctx: &mut litebox_common_linux::ExecutionContext,
        task: &Task<impl ShimFS>,
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
            litebox::log_println!(
                task.global.platform,
                "[SIGNAL-DELIVER-FAULT] pid={} tid={} comm={:?} signal={:?} reason=frame-outside-altstack pre_sp={:#x} frame_addr={:#x} altstack_sp={:#x} altstack_size={:#x} altstack_flags={:#x} switch_stacks={} on_alt_stack={} handler={:#x} restorer={:#x} flags={:#x}",
                task.pid,
                task.tid,
                task.task_comm_preview(),
                signal,
                sp,
                frame_addr,
                altstack.sp,
                altstack.size,
                altstack.flags.bits(),
                switch_stacks,
                on_alt_stack,
                action.sigaction,
                action.restorer,
                action.flags.bits(),
            );
            return Err(DeliverFault);
        }

        if self
            .write_signal_frame(
                frame_addr,
                siginfo,
                action,
                ctx,
                task,
                task.in_syscall.get(),
            )
            .is_err()
        {
            litebox::log_println!(
                task.global.platform,
                "[SIGNAL-DELIVER-FAULT] pid={} tid={} comm={:?} signal={:?} reason=write-frame pre_sp={:#x} frame_addr={:#x} altstack_sp={:#x} altstack_size={:#x} altstack_flags={:#x} switch_stacks={} on_alt_stack={} handler={:#x} restorer={:#x} flags={:#x}",
                task.pid,
                task.tid,
                task.task_comm_preview(),
                signal,
                sp,
                frame_addr,
                altstack.sp,
                altstack.size,
                altstack.flags.bits(),
                switch_stacks,
                on_alt_stack,
                action.sigaction,
                action.restorer,
                action.flags.bits(),
            );
            return Err(DeliverFault);
        }

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

    pub(crate) fn sys_rt_sigreturn(
        &self,
        ctx: &mut litebox_common_linux::ExecutionContext,
    ) -> Result<usize, Errno> {
        let uctx_addr = arch::uctx_addr(ctx);
        let uctx_ptr = ConstPtr::<Ucontext>::from_usize(uctx_addr);
        let Some(uctx) = uctx_ptr.read_at_offset(0) else {
            self.force_signal(Signal::SIGSEGV, false);
            return Err(Errno::EFAULT);
        };

        // Restore the alternate signal stack, ignoring errors.
        self.signals.set_sigaltstack(uctx.stack).ok();

        self.signals.set_signal_mask(uctx.sigmask);

        arch::restore_sigcontext(ctx, &uctx.mcontext).map_err(|()| {
            // FP state validation failed (e.g., invalid MXCSR in
            // guest-controlled signal frame). Force SIGSEGV matching
            // Linux kernel behavior for malformed signal frames.
            self.force_signal(Signal::SIGSEGV, false);
            Errno::EFAULT
        })?;

        // After restoring the guest context, ctx.r11 holds the real
        // architectural R11 (not the call-site scratch). Clear in_syscall
        // so that any follow-up signal delivered before re-entering guest
        // code preserves the correct R11 in the signal frame.
        self.in_syscall.set(false);

        // Return the restored RAX so that the caller's unconditional
        // writeback (ctx.rax = return_value) is idempotent. Without this,
        // rt_sigreturn would resume with RAX=0 instead of the value from
        // the signal frame.
        Ok(arch::sigreturn_rax(ctx))
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
        // The sandbox treats default-disposition stop signals as terminate.
        // Suppress them for group/broadcast kills to avoid accidentally
        // killing targets that should only be stopped.
        let suppress_stop = signal > 0
            && Signal::try_from(signal).is_ok_and(|sig| {
                sig.default_disposition() == litebox_common_linux::signal::SignalDisposition::Stop
            });

        if pid == 0 || pid < -1 {
            // pid=0: send to caller's process group.
            // pid<-1: send to process group -pid.

            // Validate signal upfront (Linux rejects invalid signals before
            // iterating the process table).
            if signal != 0 {
                Signal::try_from(signal)?;
            }

            let target_pgid = if pid == 0 {
                litebox::process::ProcessGroupId(self.sys_getpgid(0).map_err(|_| Errno::ESRCH)?)
            } else {
                let raw = u32::try_from(pid.wrapping_neg()).map_err(|_| Errno::ESRCH)?;
                litebox::process::ProcessGroupId(raw)
            };

            let my_pgid = self.sys_getpgid(0).unwrap_or(0);
            let is_own_group = target_pgid.as_u32() == my_pgid;
            let mut delivered = false;

            // Deliver to self first (if in the target group).
            if is_own_group {
                if !suppress_stop {
                    let _ = self.do_kill(Some(self.pid), None, signal);
                }
                delivered = true;
            }

            // Deliver to all other processes in the group.
            let members = self
                .global
                .litebox
                .process_registry()
                .process_ids_in_group(target_pgid);
            for member in &members {
                // Skip self — already handled via do_kill above. Compare
                // using process_id (guest ProcessId), not pid (host TID).
                if *member == self.process_id {
                    continue;
                }
                let member_pid = i32::try_from(member.0).unwrap_or(-1);
                if member_pid > 0 {
                    if suppress_stop {
                        delivered = true;
                        continue;
                    }
                    if self
                        .do_remote_process_kill(member_pid, None, signal)
                        .is_ok()
                    {
                        delivered = true;
                    }
                }
            }

            if !delivered && members.is_empty() {
                return Err(Errno::ESRCH);
            }
            return Ok(0);
        }
        if pid == -1 {
            // pid=-1 means "send to every process the caller can signal
            // (except PID 1 and self)".
            if signal != 0 {
                Signal::try_from(signal)?;
            }
            // Suppress stop signals — the sandbox treats Stop as Terminate.
            if suppress_stop {
                return Ok(0);
            }
            let all_pids = self
                .global
                .litebox
                .process_registry()
                .all_running_except(self.process_id);
            let root_pid = self.global.litebox.process_registry().root_pid();
            let mut delivered = false;
            for target in all_pids {
                if Some(target) == root_pid {
                    continue; // skip the init process, matching Linux semantics
                }
                let target_pid = i32::try_from(target.0).unwrap_or(-1);
                if target_pid > 0
                    && self
                        .do_remote_process_kill(target_pid, None, signal)
                        .is_ok()
                {
                    delivered = true;
                }
            }
            if !delivered {
                return Err(Errno::ESRCH);
            }
            return Ok(0);
        }
        if pid > 0 && pid != self.pid {
            return self.do_remote_process_kill(pid, None, signal);
        }
        self.do_kill(Some(pid), None, signal)
    }

    pub(crate) fn sys_tkill(&self, tid: i32, signal: i32) -> Result<usize, Errno> {
        self.do_kill(None, Some(tid), signal)
    }

    pub(crate) fn sys_tgkill(&self, pid: i32, tid: i32, signal: i32) -> Result<usize, Errno> {
        self.do_kill(Some(pid), Some(tid), signal)
    }

    /// Handle syscall `rt_sigsuspend`.
    ///
    /// Atomically replaces the current signal mask with `mask`, then suspends
    /// until a signal whose action is to invoke a handler is delivered.
    /// On return, the original mask is restored and `EINTR` is returned.
    pub(crate) fn sys_rt_sigsuspend(
        &self,
        mask_ptr: crate::ConstPtr<SigSet>,
        sigsetsize: usize,
        ctx: &mut litebox_common_linux::ExecutionContext,
    ) -> Result<usize, Errno> {
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        let new_mask: SigSet = mask_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
        let old_mask = self.signals.blocked.get();

        // Set the temporary mask and schedule restoration.
        // The signal delivery path (process_signals) checks restore_mask
        // and will reset the blocked mask after delivering any pending signal.
        self.signals.blocked.set(new_mask);
        self.signals.restore_mask.set(Some(old_mask));

        // Check for pending signals once, then return EINTR immediately.
        //
        // Thread-to-thread signals (e.g. from musl's internal threads)
        // go through the host kernel and are delivered asynchronously
        // via the platform's signal handler → drain_thread_signals.
        // Blocking here is pointless and harmful: the CLI's musl runtime
        // calls sigsuspend thousands of times during startup, and even
        // a 10ms wait per call adds up to tens of seconds.
        self.drain_thread_signals();
        self.drain_cross_process_signals();
        self.process_signals(ctx);

        // sigsuspend always returns EINTR unless signal delivery terminates the task.
        Err(Errno::EINTR)
    }

    /// Handle syscall `rt_sigtimedwait`.
    ///
    /// Synchronously waits for one of the signals in `set` to become pending.
    /// The signal is dequeued and its number is returned. If `info` is not null,
    /// the signal's siginfo is written there.
    pub(crate) fn sys_rt_sigtimedwait(
        &self,
        set_ptr: crate::ConstPtr<SigSet>,
        _info: Option<crate::MutPtr<u8>>,
        timeout_ptr: Option<crate::ConstPtr<litebox_common_linux::Timespec>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        let wait_set: SigSet = set_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
        let timeout = timeout_ptr
            .map(|p| {
                let ts: litebox_common_linux::Timespec =
                    p.read_at_offset(0).ok_or(Errno::EFAULT)?;
                Duration::try_from(ts)
            })
            .transpose()?;

        // Helper: check if any signal in wait_set is pending, dequeue it.
        let try_dequeue = || -> Option<Signal> {
            let mut pending = self.signals.pending.borrow_mut();
            if let Some(sig) = (pending.pending_set() & wait_set).lowest_set() {
                let _siginfo = pending.remove(sig);
                return Some(sig);
            }
            let mut shared = self.signals.shared_pending.lock();
            if let Some(sig) = (shared.pending_set() & wait_set).lowest_set() {
                let _siginfo = shared.remove(sig);
                return Some(sig);
            }
            None
        };

        // First try without waiting.
        self.drain_thread_signals();
        self.drain_cross_process_signals();
        if let Some(sig) = try_dequeue() {
            return Ok(sig.as_i32() as usize);
        }

        // If timeout is zero, return immediately.
        if timeout.is_some_and(|t| t.is_zero()) {
            return Err(Errno::EAGAIN);
        }

        // Wait with timeout.
        let deadline = timeout.map(|t| {
            self.global
                .platform
                .now()
                .checked_add(t)
                .unwrap_or_else(|| self.global.platform.now())
        });

        loop {
            let _ = self.wait_cx().wait_until(|| {
                self.drain_thread_signals();
                self.drain_cross_process_signals();
                let pending = self.signals.pending.borrow();
                let shared = self.signals.shared_pending.lock();
                let has_match = !(pending.pending_set() & wait_set).is_empty()
                    || !(shared.pending_set() & wait_set).is_empty();
                if has_match {
                    return true;
                }
                if let Some(dl) = &deadline {
                    return self.global.platform.now() >= *dl;
                }
                false
            });

            if let Some(sig) = try_dequeue() {
                return Ok(sig.as_i32() as usize);
            }

            if let Some(dl) = &deadline {
                if self.global.platform.now() >= *dl {
                    return Err(Errno::EAGAIN);
                }
            }
        }
    }

    /// Handle syscall `rt_sigpending`.
    ///
    /// Returns the set of signals that are pending for delivery.
    pub(crate) fn sys_rt_sigpending(
        &self,
        set_ptr: crate::MutPtr<SigSet>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        self.drain_thread_signals();
        self.drain_cross_process_signals();
        let pending = self.signals.pending.borrow();
        let shared = self.signals.shared_pending.lock();
        let result = pending.pending_set() | shared.pending_set();
        set_ptr.write_at_offset(0, result).ok_or(Errno::EFAULT)?;
        Ok(0)
    }

    fn do_remote_process_kill(
        &self,
        pid: i32,
        tid: Option<i32>,
        signal: i32,
    ) -> Result<usize, Errno> {
        // After Phase K Step 3, ProcessId == guest pid by construction.
        let target = ProcessId(pid.try_into().map_err(|_| Errno::ESRCH)?);

        // Check process existence. First try the local process registry,
        // then the control plane. For signal 0 (existence check), also
        // accept any positive PID — in the sandbox, all guest processes
        // are considered alive since they can't be killed externally.
        let is_local = self
            .global
            .litebox
            .process_registry()
            .with_context(target, |ctx| matches!(ctx.state, ProcessState::Running))
            .unwrap_or(false);
        let is_remote = !is_local
            && self
                .global
                .control_plane
                .owner_of_running_process(target)
                .is_some();
        let is_fork_child = !is_local
            && !is_remote
            && self
                .global
                .fork_child_host_pids
                .read()
                .contains_key(&target.0);
        let is_child = !is_local
            && !is_remote
            && !is_fork_child
            && self
                .global
                .litebox
                .process_registry()
                .get_children(self.process_id)
                .is_some_and(|children| children.contains(&target));
        let is_running =
            is_local || is_remote || is_fork_child || is_child || (signal == 0 && pid > 0);
        if !is_running {
            return Err(Errno::ESRCH);
        }

        // If the target is running in a remote worker host (fork-restore or
        // remote exec), forward the signal to the worker host OS process
        // directly. This includes signal 0 (existence check) so we test
        // host-level liveness rather than relying on guest registry state alone.
        if let Some(&host_pid) = self.global.fork_child_host_pids.read().get(&target.0) {
            if signal == 0 {
                let ret = self.global.platform.kill_worker_host(host_pid, 0);
                return if ret < 0 {
                    Err(Errno::try_from(-ret).unwrap_or(Errno::ESRCH))
                } else {
                    Ok(0)
                };
            }
            let signal = Signal::try_from(signal)?;
            if tid.is_some() {
                log_unsupported!(
                    "tgkill for fork child pid {} (host_pid {}) not supported",
                    target.0,
                    host_pid,
                );
                return Err(Errno::EOPNOTSUPP);
            }
            if self.try_deliver_remote_signalfd(target.0, signal, &siginfo_kill(signal)) {
                return Ok(0);
            }
            let ret = self
                .global
                .platform
                .kill_worker_host(host_pid, signal.as_i32());
            if ret < 0 {
                return Err(Errno::try_from(-ret).unwrap_or(Errno::EIO));
            }
            return Ok(0);
        }

        if signal == 0 {
            return Ok(0);
        }
        let signal = Signal::try_from(signal)?;

        if let Some(owner_host) = self.global.control_plane.owner_of_running_process(target)
            && owner_host != self.global.control_plane.local_host()
        {
            log_unsupported!(
                "kill for running pid {} owned by remote host {:?}",
                target.0,
                owner_host
            );
            return Err(Errno::EOPNOTSUPP);
        }

        // SIGKILL is not deferrable; publish process exit immediately so pidfd
        // pollers observe readiness even if the target is asleep in a futex.
        if is_local && signal == Signal::SIGKILL {
            let exit_status = 128 + signal.as_i32();
            super::guest_pid::try_mark_broker_process_exited(target.0, exit_status);
            let _ = self
                .global
                .litebox
                .process_registry()
                .exit_process(target, exit_status);
            self.global
                .litebox
                .process_registry()
                .notify_waiters(target);
            let target_key = target.0.cast_signed();
            if let Some(remote) = self.global.process_thread_handles.read().get(&target_key) {
                remote.request_exit();
            }
        }
        self.global
            .cross_process_signals
            .lock()
            .push(crate::CrossProcessSignal {
                target_process_id: target.0,
                target_tid: tid,
                signal,
                siginfo: siginfo_kill(signal),
            });

        let target_key = target.0.cast_signed();
        if let Some(remote) = self.global.process_thread_handles.read().get(&target_key) {
            remote.interrupt();
        }
        Ok(0)
    }

    #[cfg(feature = "trace_syscalls")]
    fn log_abort_stack(&self) {
        let Some(last_syscall) = self.last_syscall.get() else {
            return;
        };
        litebox::log_println!(
            self.global.platform,
            "[TRACE-ABORT] pid={} tid={} rsp={:#x} rbp={:#x}",
            self.pid,
            self.tid,
            last_syscall.entry_rsp,
            last_syscall.entry_rbp,
        );
        for slot in 0..8usize {
            let addr = last_syscall.entry_rsp + slot * core::mem::size_of::<usize>();
            let word = ConstPtr::<usize>::from_usize(addr).read_at_offset(0);
            match word {
                Some(word) => {
                    let summary = if word >= 0x10000 {
                        self.address_mapping_summary(word)
                    } else {
                        alloc::format!("addr={word:#x}")
                    };
                    litebox::log_println!(
                        self.global.platform,
                        "[TRACE-ABORT] stack[{}] @ {:#x} = {:#x} {}",
                        slot,
                        addr,
                        word,
                        summary,
                    );
                }
                None => {
                    litebox::log_println!(
                        self.global.platform,
                        "[TRACE-ABORT] stack[{}] @ {:#x} = <unreadable>",
                        slot,
                        addr,
                    );
                }
            }
        }
        let mut rbp = last_syscall.entry_rbp;
        for frame in 0..8usize {
            if rbp < 0x10000 {
                break;
            }
            let saved_rbp = ConstPtr::<usize>::from_usize(rbp).read_at_offset(0);
            let ret_addr = ConstPtr::<usize>::from_usize(rbp + core::mem::size_of::<usize>())
                .read_at_offset(0);
            let Some(ret_addr) = ret_addr else {
                litebox::log_println!(
                    self.global.platform,
                    "[TRACE-ABORT] frame[{}] rbp={:#x} ret=<unreadable>",
                    frame,
                    rbp,
                );
                break;
            };
            let summary = if ret_addr >= 0x10000 {
                self.address_mapping_summary(ret_addr)
            } else {
                alloc::format!("addr={ret_addr:#x}")
            };
            litebox::log_println!(
                self.global.platform,
                "[TRACE-ABORT] frame[{}] rbp={:#x} next_rbp={:?} ret={:#x} {}",
                frame,
                rbp,
                saved_rbp,
                ret_addr,
                summary,
            );
            let Some(next_rbp) = saved_rbp else {
                break;
            };
            if next_rbp <= rbp {
                break;
            }
            rbp = next_rbp;
        }
    }

    fn do_kill(&self, pid: Option<i32>, tid: Option<i32>, signal: i32) -> Result<usize, Errno> {
        let signal = if signal == 0 {
            None
        } else {
            Some(Signal::try_from(signal)?)
        };
        if pid.is_none_or(|pid| pid == self.pid) && tid.is_none_or(|tid| tid == self.tid) {
            // Sending signal to self.
            #[cfg(feature = "trace_syscalls")]
            if signal == Some(Signal::SIGABRT) {
                self.log_abort_stack();
            }
            if let Some(signal) = signal {
                self.send_signal(signal, siginfo_kill(signal));
            }
            Ok(0)
        } else if pid.is_none_or(|pid| pid == self.pid) {
            // Sending signal to a different thread in the same process.
            if let Some(target_tid) = tid {
                let inner = self.process().inner.lock();
                if let Some(remote) = inner.threads.get(&target_tid) {
                    if let Some(signal) = signal {
                        remote.pending_signals.lock().push(
                            &self.process().limits,
                            signal,
                            siginfo_kill(signal),
                        );
                        remote.interrupt();
                    }
                    return Ok(0);
                }
            }
            Err(Errno::ESRCH)
        } else if let Some(target_pid) = pid {
            // Sending signal to a thread in a different process.
            self.do_remote_process_kill(target_pid, tid, signal.map_or(0, |s| s.as_i32()))
        } else {
            Err(Errno::ESRCH)
        }
    }

    /// Returns whether there are any pending signals that can be delivered.
    pub(crate) fn has_pending_signals(&self) -> bool {
        let blocked = self.signals.blocked.get();
        let remote_pending = self.thread.remote().pending_signals.lock().pending & !blocked;
        if !remote_pending.is_empty() {
            return true;
        }
        let thread_pending = self.signals.pending.borrow().pending & !blocked;
        if !thread_pending.is_empty() {
            return true;
        }
        let shared_pending = self.signals.shared_pending.lock().pending & !blocked;
        !shared_pending.is_empty()
    }

    /// PE.14: returns true iff every pending non-blocked signal is
    /// effectively a no-op (SIG_IGN or SIG_DFL with default-ignore
    /// disposition like SIGCHLD). Used at sys_epoll_pwait to suppress
    /// spurious EINTR caused by SIGCHLD-from-child-exit racing with
    /// broker pipe data delivery under load.
    pub(crate) fn pending_signals_all_ignored(&self) -> bool {
        use litebox_common_linux::signal::{Signal, SignalDisposition};
        let blocked = self.signals.blocked.get();
        let remote = self.thread.remote().pending_signals.lock().pending & !blocked;
        let thread = self.signals.pending.borrow().pending & !blocked;
        let shared = self.signals.shared_pending.lock().pending & !blocked;
        let all = remote | thread | shared;
        if all.is_empty() {
            return false;
        }
        let handlers = self.signals.handlers.borrow();
        let inner = handlers.inner.lock();
        for n in 1..=64i32 {
            if let Ok(sig) = Signal::try_from(n) {
                if all.contains(sig) {
                    let action = inner[sig].action.sigaction;
                    let ignored = action == SIG_IGN
                        || (action == SIG_DFL
                            && matches!(sig.default_disposition(), SignalDisposition::Ignore));
                    if !ignored {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// PE.14: clear pending signals that are effectively ignored. Pair
    /// with pending_signals_all_ignored — after a spurious EINTR, drain
    /// the ignored signals so the wait loop doesn't see them again.
    pub(crate) fn drain_ignored_pending(&self) {
        use litebox_common_linux::signal::{Signal, SignalDisposition};
        let handlers = self.signals.handlers.borrow();
        let inner = handlers.inner.lock();
        let mut ignored_set = litebox_common_linux::signal::SigSet::empty();
        for n in 1..=64i32 {
            if let Ok(sig) = Signal::try_from(n) {
                let action = inner[sig].action.sigaction;
                let is_ignored = action == SIG_IGN
                    || (action == SIG_DFL
                        && matches!(sig.default_disposition(), SignalDisposition::Ignore));
                if is_ignored {
                    ignored_set.add(sig);
                }
            }
        }
        drop(inner);
        drop(handlers);
        // Clear from pending sets.
        {
            let mut remote = self.thread.remote().pending_signals.lock();
            remote.pending = remote.pending & !ignored_set;
            remote.queue.retain(|si| {
                Signal::try_from(si.signo)
                    .map(|s| !ignored_set.contains(s))
                    .unwrap_or(true)
            });
        }
        {
            let mut thread = self.signals.pending.borrow_mut();
            thread.pending = thread.pending & !ignored_set;
            thread.queue.retain(|si| {
                Signal::try_from(si.signo)
                    .map(|s| !ignored_set.contains(s))
                    .unwrap_or(true)
            });
        }
        {
            let mut shared = self.signals.shared_pending.lock();
            shared.pending = shared.pending & !ignored_set;
            shared.queue.retain(|si| {
                Signal::try_from(si.signo)
                    .map(|s| !ignored_set.contains(s))
                    .unwrap_or(true)
            });
        }
    }

    /// Returns the set of all pending (deliverable) signals.
    pub(crate) fn pending_signal_set(&self) -> SigSet {
        let blocked = self.signals.blocked.get();
        let remote = self.thread.remote().pending_signals.lock().pending & !blocked;
        let thread = self.signals.pending.borrow().pending & !blocked;
        let shared = self.signals.shared_pending.lock().pending & !blocked;
        remote | thread | shared
    }

    fn drain_thread_signals(&self) {
        let mut remote_pending = self.thread.remote().pending_signals.lock();
        if remote_pending.queue.is_empty() {
            return;
        }

        let mut local_pending = self.signals.pending.borrow_mut();
        while let Some(siginfo) = remote_pending.queue.pop_front() {
            let signal =
                Signal::try_from(siginfo.signo).expect("cross-thread pending signal is invalid");
            local_pending.push(&self.process().limits, signal, siginfo);
        }
        remote_pending.pending = SigSet::empty();
    }

    /// Move cross-process signals (e.g. SIGCHLD from a child exit) from the
    /// global queue into this process's shared pending queue so that
    /// [`has_pending_signals`](Self::has_pending_signals) reflects them.
    ///
    /// Signals are placed into `shared_pending` (process-directed) rather than
    /// thread-local `pending`, matching Linux semantics: any thread in the
    /// process may deliver a process-directed signal.
    ///
    /// This is called from [`check_for_interrupt`] during waits so that a
    /// child exit promptly interrupts `epoll_pwait`/`futex` instead of
    /// sleeping until the timeout expires.
    pub(crate) fn drain_cross_process_signals(&self) {
        let my_id = self.process_id.0;
        let mut queue = self.global.cross_process_signals.lock();
        let mut i = 0;
        while i < queue.len() {
            if queue[i].target_process_id == my_id {
                let sig = queue.swap_remove(i);
                if let Some(tid) = sig.target_tid {
                    // Thread-directed signal (e.g. from tgkill) — route to the
                    // specific thread's pending queue if it exists.
                    let inner = self.process().inner.lock();
                    if let Some(remote) = inner.threads.get(&tid) {
                        remote.pending_signals.lock().push(
                            &self.process().limits,
                            sig.signal,
                            sig.siginfo,
                        );
                        remote.interrupt();
                    }
                    // If the thread no longer exists, the signal is silently
                    // dropped — consistent with Linux behaviour after the
                    // target thread has exited.
                } else {
                    // Process-directed signal — goes to shared_pending.
                    if !self.deliver_signal_to_signalfd(sig.signal, &sig.siginfo) {
                        self.signals.shared_pending.lock().push(
                            &self.process().limits,
                            sig.signal,
                            sig.siginfo,
                        );
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    /// Rewind the execution context so the interrupted syscall re-executes.
    ///
    /// After a syscall, `ctx.rip` (or `ctx.eip`) points to the instruction
    /// *after* the 2-byte `syscall`/`int 0x80` instruction. Subtracting 2
    /// rewinds to the syscall itself. `rax`/`eax` is restored to the
    /// original syscall number (`orig_rax`/`orig_eax`) so the kernel sees a
    /// fresh invocation.
    fn restart_syscall(ctx: &mut litebox_common_linux::ExecutionContext) {
        // Rewind the guest to re-execute the interrupted syscall.
        //
        // Both interception paths store the syscall call-site address
        // in R11 (saved into pt_regs->r11 by syscall_callback via the
        // gs:saved_r11 TLS slot):
        //  - Rewriter trampoline: LEA R11, [replace_start]
        //  - Seccomp SIGSYS handler: sets R11 = si_call_addr
        //
        // Setting rip to that address re-enters the call site (the
        // trampoline JMP or the original syscall instruction) which
        // re-executes the syscall with the original arguments already
        // in the register file.
        #[cfg(target_arch = "x86_64")]
        {
            ctx.rip = ctx.r11;
            ctx.rax = ctx.orig_rax;
        }
        #[cfg(target_arch = "x86")]
        {
            ctx.eip -= 2;
            ctx.eax = ctx.orig_eax;
        }
    }

    /// Deliver any pending signals.
    pub(crate) fn process_signals(&self, ctx: &mut litebox_common_linux::ExecutionContext) {
        self.drain_thread_signals();
        // Drain cross-process signals for this process into our local pending queue.
        self.drain_cross_process_signals();

        // Track whether a user-space handler was actually delivered. If the
        // interrupted syscall was restartable and we only encountered
        // SIG_IGN / default-ignore signals (no handlers), we restart the
        // syscall unconditionally at the end.
        let mut handler_delivered = false;

        loop {
            let blocked = self.signals.blocked.get();
            let (signal, siginfo) = {
                let mut pending = self.signals.pending.borrow_mut();
                if let Some(signal) = pending.next(blocked) {
                    (signal, pending.remove(signal))
                } else {
                    // Then try shared pending.
                    let mut shared = self.signals.shared_pending.lock();
                    if let Some(signal) = shared.next(blocked) {
                        (signal, shared.remove(signal))
                    } else {
                        break;
                    }
                }
            };
            if self.is_exiting() {
                // Don't deliver any more signals if exiting.
                return;
            }

            let action = {
                let handlers = self.signals.handlers.borrow();
                let mut inner = handlers.inner.lock();
                let action = inner[signal].action;
                // SA_RESETHAND: atomically reset to SIG_DFL while still
                // holding the handler lock, before any other thread can
                // snapshot this handler for a concurrent delivery.
                if action.flags.contains(SaFlags::RESETHAND)
                    && action.sigaction != SIG_DFL
                    && action.sigaction != SIG_IGN
                {
                    inner[signal].action.sigaction = SIG_DFL;
                    inner[signal].action.flags &= !SaFlags::RESETHAND;
                }
                action
            };

            #[expect(clippy::match_same_arms)]
            match action.sigaction {
                SIG_DFL => {
                    match signal.default_disposition() {
                        SignalDisposition::Terminate | SignalDisposition::Core => {
                            // Core dumps are not currently supported.
                            //
                            // Only log full crash context for Core-disposition
                            // signals (SIGSEGV, SIGBUS, SIGABRT, etc).
                            // Normal termination signals like SIGHUP/SIGTERM
                            // are expected process lifecycle events and should
                            // not pollute the TTY with register dumps.
                            if signal.default_disposition() == SignalDisposition::Core {
                                self.log_fatal_signal_context(signal, ctx);
                                litebox::log_println!(
                                    self.global.platform,
                                    "-- Fatal signal {:?}: terminating task {}:{} fault_addr={:#x} error_code={:#x}",
                                    signal,
                                    self.pid,
                                    self.tid,
                                    self.signals.last_exception.get().cr2,
                                    self.signals.last_exception.get().error_code,
                                );
                            }
                            self.exit_group(ExitStatus::Signal(signal));
                        }
                        SignalDisposition::Stop => {
                            // STOP is not currently supported. Previously the
                            // shim treated Stop as Terminate, which killed
                            // interactive TUI apps (e.g., GitHub Copilot CLI)
                            // that send SIGTTIN to themselves as part of
                            // job-control patterns, and killed processes in
                            // a background pgrp that tried to read from their
                            // controlling terminal (kernel default behavior
                            // is to deliver SIGTTIN to the offending pgrp).
                            //
                            // Treating SIG_DFL Stop as a no-op (ignore) is
                            // the closer behavioral approximation: the
                            // process keeps running rather than being killed.
                            // Real STOP semantics (suspend the task until
                            // SIGCONT) require platform-level scheduler
                            // support and are out of scope.
                            //
                            // Surfaced by Goal A validation session 7c1fc95d
                            // round 5 — copilot::tui_noLLM cascade rooted
                            // here.
                        }
                        SignalDisposition::Ignore => {}
                        SignalDisposition::Continue => {
                            // Stop is not supported, so continue does nothing.
                        }
                    }
                }
                SIG_IGN => {}
                _ => {
                    // A user-space handler will be invoked. If the
                    // interrupted syscall was restartable, decide whether
                    // to rewind the program counter so the syscall
                    // re-executes after the handler returns.
                    if self.syscall_restartable.get() && !handler_delivered {
                        if action.flags.contains(SaFlags::RESTART) {
                            Self::restart_syscall(ctx);
                        }
                        self.syscall_restartable.set(false);
                    }
                    #[cfg(feature = "trace_syscalls")]
                    if matches!(
                        signal,
                        Signal::SIGSEGV
                            | Signal::SIGILL
                            | Signal::SIGBUS
                            | Signal::SIGFPE
                            | Signal::SIGTRAP
                            | Signal::SIGABRT
                    ) {
                        let last_exception = self.signals.last_exception.get();
                        #[cfg(target_arch = "x86_64")]
                        let rip = ctx.rip;
                        #[cfg(target_arch = "x86")]
                        let rip = ctx.eip;
                        litebox::log_println!(
                            self.global.platform,
                            "[TRACE-SIGNAL] pid={} tid={} deliver={:?} handler={:#x} restorer={:#x} flags={:#x} rip={:#x} rip_summary={} fault_addr={:#x} fault_summary={} error_code={:#x} rsp={:#x} rbp={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x} rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} rsi={:#x} rdi={:#x}",
                            self.pid,
                            self.tid,
                            signal,
                            action.sigaction,
                            action.restorer,
                            action.flags.bits(),
                            rip,
                            self.address_mapping_summary(rip),
                            last_exception.cr2,
                            self.address_mapping_summary(last_exception.cr2),
                            last_exception.error_code,
                            ctx.rsp,
                            ctx.rbp,
                            ctx.r12,
                            ctx.r13,
                            ctx.r14,
                            ctx.r15,
                            ctx.rax,
                            ctx.rbx,
                            ctx.rcx,
                            ctx.rdx,
                            ctx.rsi,
                            ctx.rdi,
                        );
                    }
                    handler_delivered = true;
                    if let Err(DeliverFault) = self
                        .signals
                        .deliver_signal(signal, &siginfo, &action, ctx, self)
                    {
                        // Failed to deliver signal. Inject a SIGSEGV
                        // (terminating the process if we were trying to deliver
                        // a SIGSEGV).
                        self.force_signal(Signal::SIGSEGV, signal == Signal::SIGSEGV);
                    }
                }
            }
        }

        // If the syscall was restartable but no handler was delivered (all
        // dequeued signals were SIG_IGN or default-ignore), restart the
        // syscall unconditionally — matching Linux kernel behaviour.
        if self.syscall_restartable.get() && !handler_delivered {
            Self::restart_syscall(ctx);
        }
        self.syscall_restartable.set(false);

        // If a deferred mask restore is pending (set by epoll_pwait/ppoll),
        // restore the original signal mask now that signals have been delivered
        // with the temporarily-unblocked mask.
        if let Some(old_mask) = self.signals.restore_mask.take() {
            self.signals.blocked.set(old_mask);
        }
    }

    /// Check whether the process-wide alarm deadline has passed and, if so,
    /// enqueue `SIGALRM`.
    ///
    /// Note this is a fallback in case the platform does not support timers.
    pub(crate) fn check_alarm_deadline(&self) {
        use litebox::platform::TimeProvider as _;
        let mut alarm = self.process().alarm_timer.lock();
        if alarm
            .deadline
            .is_some_and(|deadline| self.global.platform.now() >= deadline)
        {
            alarm.deadline = None;
            self.send_shared_signal(
                litebox_common_linux::signal::Signal::SIGALRM,
                siginfo_kill(litebox_common_linux::signal::Signal::SIGALRM),
            );
        }
    }

    pub(crate) fn queue_signals(&self, signal: litebox_common_linux::signal::Signal) {
        if signal == litebox_common_linux::signal::Signal::SIGALRM {
            // The platform timer fired; clear the stored deadline so that a
            // subsequent `alarm()` call does not see a stale positive remaining
            // time due to timer imprecision (the timer can fire slightly before
            // the exact deadline).
            self.process().alarm_timer.lock().deadline = None;
        }
        self.send_shared_signal(signal, siginfo_kill(signal));
    }

    /// Returns whether the given signal is currently blocked or ignored.
    pub(crate) fn is_signal_blocked_or_ignored(&self, signal: Signal) -> bool {
        // SIGKILL and SIGSTOP can never be blocked or ignored.
        if signal == Signal::SIGKILL || signal == Signal::SIGSTOP {
            return false;
        }
        if self.signals.blocked.get().contains(signal) {
            return true;
        }
        let handlers = self.signals.handlers.borrow();
        let inner = handlers.inner.lock();
        match inner[signal].action.sigaction {
            SIG_IGN => true,
            SIG_DFL => matches!(
                signal.default_disposition(),
                // Stop-disposition signals are treated as no-op (ignore)
                // under SIG_DFL because the shim does not implement
                // actual STOP semantics — see deliver_signal SIG_DFL arm.
                // Callers that gate signal delivery on this predicate
                // (e.g., broker_pty_background_read_sigttin) must skip
                // delivery in that case, otherwise reads end up in an
                // EINTR loop: SIGTTIN delivered → no-op handler → read
                // returns EINTR → caller retries → SIGTTIN delivered
                // again → infinite spin.
                SignalDisposition::Ignore | SignalDisposition::Stop
            ),
            _ => false,
        }
    }

    /// Returns whether the given signal is currently being ignored.
    fn is_signal_ignored(&self, signal: Signal) -> bool {
        // Blocked signals are never ignored, since the signal handler may
        // change by the time it is unblocked.
        if self.signals.blocked.get().contains(signal) {
            return false;
        }
        self.is_signal_blocked_or_ignored(signal)
    }

    fn try_deliver_remote_signalfd(
        &self,
        target_pid: u32,
        signal: Signal,
        siginfo: &Siginfo,
    ) -> bool {
        let Some(target) = self
            .global
            .remote_signalfd_targets
            .read()
            .get(&target_pid)
            .cloned()
        else {
            return false;
        };
        if !SigSet::from_u64(target.blocked_mask).contains(signal) {
            return false;
        }
        let Some(provider) = super::signalfd::broker_signalfd_provider() else {
            return false;
        };
        let payload = super::signalfd::signalfd_siginfo_payload(siginfo, self.pid);
        for sfd in target.signalfds {
            if SigSet::from_u64(sfd.mask_bits).contains(signal)
                && provider.push_siginfo(sfd.handle_id, &payload).is_ok()
            {
                return true;
            }
        }
        false
    }

    fn deliver_signal_to_signalfd(&self, signal: Signal, siginfo: &Siginfo) -> bool {
        if !self.signals.blocked.get().contains(signal) {
            return false;
        }

        let files = self.files.borrow();
        let rds = files.raw_descriptor_store.read();
        let signalfds: Vec<_> = rds
            .iter_alive()
            .filter_map(|raw_fd| {
                rds.fd_from_raw_integer::<super::signalfd::SignalfdSubsystem>(raw_fd)
                    .ok()
            })
            .collect();
        drop(rds);
        drop(files);

        for sfd in signalfds {
            let delivered = self
                .global
                .litebox
                .descriptor_table()
                .with_entry(&sfd, |file| {
                    if file.handles_signal(signal) {
                        file.push_siginfo(siginfo, self.pid).is_ok()
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
            if delivered {
                return true;
            }
        }
        false
    }

    /// Queue a thread-directed signal on the current task's pending set.
    pub(crate) fn send_signal(&self, signal: Signal, siginfo: Siginfo) {
        if self.deliver_signal_to_signalfd(signal, &siginfo) {
            return;
        }
        if self.is_signal_ignored(signal) {
            return;
        }
        self.signals
            .pending
            .borrow_mut()
            .push(&self.process().limits, signal, siginfo);
    }

    /// Sends a process-directed signal (stored in shared_pending).
    pub(crate) fn send_shared_signal(&self, signal: Signal, siginfo: Siginfo) {
        if self.deliver_signal_to_signalfd(signal, &siginfo) {
            return;
        }
        if self.is_signal_ignored(signal) {
            return;
        }
        self.signals
            .shared_pending
            .lock()
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
        assert!(matches!(
            signal,
            Signal::SIGKILL
                | Signal::SIGSEGV
                | Signal::SIGABRT
                | Signal::SIGBUS
                | Signal::SIGFPE
                | Signal::SIGILL
                | Signal::SIGTRAP
        ));

        self.signals
            .pending
            .borrow_mut()
            .push(&self.process().limits, signal, siginfo);

        // Update the handler if necessary to ensure the signal is handled.
        let handlers = self.signals.handlers.borrow();
        let mut inner = handlers.inner.lock();
        let handler = &mut inner[signal];
        let blocked_mask = self.signals.blocked.get();
        let signal_blocked = blocked_mask.contains(signal);
        let handler_ignored = handler.action.sigaction == SIG_IGN;
        let will_rewrite_default = force_exit || signal_blocked || handler_ignored;
        if will_rewrite_default {
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

    pub(crate) fn handle_exception_request(
        &self,
        info: &litebox::shim::ExceptionInfo,
        _ctx: &PtRegs,
    ) {
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
        self.force_signal_with_info(
            signal,
            false,
            siginfo_exception(
                signal,
                fault_address,
                (info.exception == Exception::PAGE_FAULT).then_some(info.error_code.into()),
            ),
        );
    }
}
