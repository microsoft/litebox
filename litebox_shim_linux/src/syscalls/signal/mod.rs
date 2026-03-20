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
use core::cell::{Cell, RefCell};
use litebox::{
    platform::{RawConstPointer as _, RawMutPointer as _},
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

    /// Get the current blocked signal mask.
    pub fn get_blocked(&self) -> SigSet {
        self.blocked.get()
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
            .write_signal_frame(frame_addr, siginfo, action, ctx, task.in_syscall.get())
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
            // Sending signal to self.
            self.send_signal(signal, siginfo_kill(signal));
            Ok(0)
        } else if pid.is_none_or(|pid| pid == self.pid) {
            // Sending signal to a different thread in the same process.
            // We can't enqueue the signal into the target thread's pending
            // set (it's thread-local), but we can interrupt its wait so it
            // gets a chance to reschedule. This is sufficient for Go's
            // goroutine preemption (SIGURG) and other cooperative schemes.
            if let Some(target_tid) = tid {
                let inner = self.process().inner.lock();
                if let Some(remote) = inner.threads.get(&target_tid) {
                    remote.interrupt();
                    return Ok(0);
                }
            }
            Err(Errno::ESRCH)
        } else {
            log_unsupported!(
                "sys_{{t|tg}}kill with remote pid (caller pid={}, tid={}, target pid={:?}, tid={:?})",
                self.pid,
                self.tid,
                pid,
                tid
            );
            Err(Errno::ESRCH)
        }
    }

    /// Returns whether there are any pending signals that can be delivered.
    pub(crate) fn has_pending_signals(&self) -> bool {
        let blocked = self.signals.blocked.get();
        let thread_pending = self.signals.pending.borrow().pending & !blocked;
        if !thread_pending.is_empty() {
            return true;
        }
        let shared_pending = self.signals.shared_pending.lock().pending & !blocked;
        !shared_pending.is_empty()
    }

    /// Returns the set of all pending (deliverable) signals.
    #[cfg(test)]
    pub(crate) fn pending_signal_set(&self) -> SigSet {
        let blocked = self.signals.blocked.get();
        let thread = self.signals.pending.borrow().pending & !blocked;
        let shared = self.signals.shared_pending.lock().pending & !blocked;
        thread | shared
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
                self.signals.shared_pending.lock().push(
                    &self.process().limits,
                    sig.signal,
                    sig.siginfo,
                );
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
                        SignalDisposition::Terminate
                        | SignalDisposition::Core
                        | SignalDisposition::Stop => {
                            // STOP is not currently supported, so treat as
                            // terminate. Core dumps are also not currently
                            // supported.
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
        if alarm.handle.is_some() {
            // If the platform supports timers, we rely on those to trigger SIGALRM, so we don't need
            // to check the deadline here.
            return;
        }

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

    /// Returns whether the given signal is currently being ignored.
    fn is_signal_ignored(&self, signal: Signal) -> bool {
        // SIGKILL and SIGSTOP can never be ignored.
        if signal == Signal::SIGKILL || signal == Signal::SIGSTOP {
            return false;
        }
        // Blocked signals are never ignored, since the signal handler may
        // change by the time it is unblocked.
        if self.signals.blocked.get().contains(signal) {
            return false;
        }
        let handlers = self.signals.handlers.borrow();
        let inner = handlers.inner.lock();
        match inner[signal].action.sigaction {
            SIG_IGN => true,
            SIG_DFL => matches!(signal.default_disposition(), SignalDisposition::Ignore),
            _ => false,
        }
    }

    /// Only supports sending signals to self for now.
    pub(crate) fn send_signal(&self, signal: Signal, siginfo: Siginfo) {
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
