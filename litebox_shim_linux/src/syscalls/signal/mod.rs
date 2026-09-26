// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Signal handling syscalls and support.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
use aarch64 as arch;
use litebox_common_linux::signal::SignalDisposition;
#[cfg(target_arch = "x86_64")]
use x86_64 as arch;
use zerocopy::FromZeros;

use crate::syscalls::process::ExitStatus;
use crate::{ShimFS, ShimPlatform, Task, UserPtr, UserPtrMut};
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::Arc;
use core::cell::{Cell, RefCell};
use litebox::event::wait::WaitError;
use litebox::{sync::Mutex, utils::ReinterpretUnsignedExt as _};
use litebox_common_linux::signal::{
    MINSIGSTKSZ, NSIG, SI_KERNEL, SI_TKILL, SI_USER, SIG_DFL, SIG_IGN, SaFlags, SigAction,
    SigAltStack, SigSet, Siginfo, SiginfoData, SigmaskHow, Signal, SsFlags, Ucontext,
};
use litebox_common_linux::{PtRegs, errno::Errno};

pub(crate) struct SignalState<Platform: ShimPlatform> {
    /// Pending thread signals.
    pending: RefCell<PendingSignals>,
    /// Pending process signals (shared across all threads).
    shared_pending: Arc<Mutex<Platform, PendingSignals>>,
    /// Currently blocked signals.
    blocked: Cell<SigSet>,
    /// Signal handlers.
    handlers: RefCell<Arc<SignalHandlers<Platform>>>,
    /// Alternate signal stack.
    altstack: Cell<SigAltStack>,
    /// The last exception info recorded for signal delivery.
    last_exception: Cell<litebox::shim::ExceptionInfo>,
    /// The signal mask to put back once the signal that ended an `rt_sigsuspend` has been
    /// delivered.
    ///
    /// `rt_sigsuspend(2)` installs a temporary mask, blocks, and must run the handler that woke
    /// it *under that temporary mask* -- restoring the caller's mask any earlier would re-block
    /// the very signal the caller was waiting for, and the guest would spin calling
    /// `rt_sigsuspend` forever. Linux solves this with `saved_sigmask` plus
    /// `TIF_RESTORE_SIGMASK`; this is that saved mask, and
    /// [`Task::restore_saved_signal_mask`] is the restore, run once signals have been processed
    /// on the way back to guest code.
    saved_blocked: Cell<Option<SigSet>>,
    /// The set an in-progress `rt_sigtimedwait` is waiting for: Linux's `real_blocked`.
    ///
    /// While the wait lasts these signals count as deliverable for wakeup purposes even though
    /// they stay in `blocked` (so a `SIG_IGN`'d member is queued rather than discarded, exactly
    /// as `sig_ignored()` consults `real_blocked`), and the waiter dequeues them itself instead
    /// of `process_signals`. Empty outside such a wait.
    sigwait_set: Cell<SigSet>,
}

impl<Platform: ShimPlatform> SignalState<Platform> {
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
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
            }),
            last_exception: Cell::new(arch::NO_EXCEPTION),
            saved_blocked: Cell::new(None),
            sigwait_set: Cell::new(SigSet::empty()),
        }
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
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
            }
            .into(),
            // Preserve last exception
            last_exception: self.last_exception.clone(),
            saved_blocked: Cell::new(None),
            sigwait_set: Cell::new(SigSet::empty()),
        }
    }

    /// Returns the signal state a `fork`ed child starts with.
    ///
    /// Unlike [`Self::clone_for_new_task`], which models `CLONE_THREAD` and therefore keeps the
    /// process-wide parts shared, a new process gets private copies: its own pending queues (a
    /// child does not inherit pending signals) and its own handler table (so a later
    /// `rt_sigaction` in either process cannot be seen by the other). The blocked mask *is*
    /// inherited, as `fork(2)` specifies.
    pub fn clone_for_new_process(&self) -> Self {
        Self {
            pending: RefCell::new(PendingSignals::new()),
            shared_pending: Arc::new(Mutex::new(PendingSignals::new())),
            blocked: Cell::new(self.blocked.get()),
            handlers: RefCell::new(Arc::new((**self.handlers.borrow()).clone())),
            altstack: SigAltStack {
                flags: SsFlags::DISABLE,
                sp: 0,
                size: 0,
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
            }
            .into(),
            last_exception: Cell::new(arch::NO_EXCEPTION),
            saved_blocked: Cell::new(None),
            sigwait_set: Cell::new(SigSet::empty()),
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
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
            };
        }
        self.clear_sigaltstack();
    }
}

/// A handle for posting a process-directed signal to a *different* guest process.
///
/// The sending thread cannot touch the target's [`SignalState`] -- that is full of `Cell`s owned
/// by the target's own host thread -- but the process-wide pending queue behind it is an
/// ordinary `Arc<Mutex<..>>` and is safe to push into from anywhere. Whether the signal is
/// actually deliverable is decided by the target, on its own thread, in
/// [`Task::process_signals`] and [`Task::has_pending_signals`], because only it can read its live
/// handler table.
pub(crate) struct RemoteSignalTarget<Platform: ShimPlatform> {
    shared_pending: Arc<Mutex<Platform, PendingSignals>>,
}

impl<Platform: ShimPlatform> Clone for RemoteSignalTarget<Platform> {
    fn clone(&self) -> Self {
        Self {
            shared_pending: self.shared_pending.clone(),
        }
    }
}

impl<Platform: ShimPlatform> RemoteSignalTarget<Platform> {
    /// Queues a shim-generated `siginfo` on the target process.
    ///
    /// # Panics
    ///
    /// Panics unless `signal` is a standard (non-realtime) signal with a kernel-originated
    /// `si_code`. Those are the ones Linux exempts from `RLIMIT_SIGPENDING`
    /// (`__send_signal_locked`'s `override_rlimit`), and exempting them is what lets this bypass
    /// the target's rlimits -- which the sender cannot read anyway, since they live in the
    /// target's `Process`.
    pub(crate) fn post(&self, signal: Signal, siginfo: Siginfo) {
        assert!(!signal.is_rt_signal() && siginfo.code >= 0);
        self.shared_pending.lock().push_from_kernel(signal, siginfo);
    }

    pub(crate) fn post_from_user(
        &self,
        limits: &super::process::ResourceLimits,
        signal: Signal,
        siginfo: Siginfo,
    ) {
        self.shared_pending.lock().push(limits, signal, siginfo);
    }
}

struct SignalHandlers<Platform: ShimPlatform> {
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

impl<Platform: ShimPlatform> SignalHandlers<Platform> {
    fn new() -> Self {
        Self {
            inner: Mutex::new(SignalHandlersInner {
                handlers: core::array::from_fn(|i| Handler {
                    action: SigAction {
                        sigaction: SIG_DFL,
                        restorer: 0,
                        flags: SaFlags::empty(),
                        mask: SigSet::empty(),
                        #[cfg(target_pointer_width = "64")]
                        __pad: 0,
                    },
                    immutable: i == SignalHandlersInner::sig_index(Signal::SIGKILL)
                        || i == SignalHandlersInner::sig_index(Signal::SIGSTOP),
                }),
            }),
        }
    }
}

impl<Platform: ShimPlatform> Clone for SignalHandlers<Platform> {
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

    /// Queues a standard signal generated by the shim itself, with no `RLIMIT_SIGPENDING` check.
    ///
    /// Linux applies that limit only to signals a *user* queued (`si_code < 0`, e.g. `SI_QUEUE`)
    /// and to realtime signals; a kernel-generated `SIGCHLD` is never dropped for it. The
    /// standard-signal dedup below means at most one such entry can be outstanding anyway.
    fn push_from_kernel(&mut self, signal: Signal, siginfo: Siginfo) {
        assert_eq!(signal.as_i32(), siginfo.signo);
        assert!(!signal.is_rt_signal());
        if self.pending.contains(signal) {
            return;
        }
        self.queue.push_back(siginfo);
        self.pending.add(signal);
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

    /// Moves every entry queued here into `dest`, preserving standard-signal dedup (an entry
    /// whose signal is already pending in `dest` is dropped, matching `push`'s own dedup rule --
    /// this can only apply to standard signals, since `push`'s realtime-signal branch never
    /// hits `pending.contains` at all). Does not re-apply an `RLIMIT_SIGPENDING` check: the
    /// limit was already enforced when each entry was queued here.
    pub(crate) fn drain_into(&mut self, dest: &mut Self) {
        for siginfo in self.queue.drain(..) {
            let signal = Signal::try_from(siginfo.signo).expect("queued an invalid signal");
            if !signal.is_rt_signal() && dest.pending.contains(signal) {
                continue;
            }
            dest.queue.push_back(siginfo);
            dest.pending.add(signal);
        }
        self.pending = SigSet::empty();
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
        #[cfg(target_pointer_width = "64")]
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
        #[cfg(target_pointer_width = "64")]
        __pad: 0,
        data: SiginfoData::new_zeroed(),
    }
}

/// Creates the kernel-originated signal requested through `PR_SET_PDEATHSIG`.
pub(crate) fn siginfo_parent_death(signal: Signal) -> Siginfo {
    Siginfo {
        signo: signal.as_i32(),
        errno: 0,
        code: SI_KERNEL,
        #[cfg(target_pointer_width = "64")]
        __pad: 0,
        data: SiginfoData::new_zeroed(),
    }
}

/// Creates the `SIGCHLD` a parent gets when one of its children becomes a zombie.
pub(crate) fn siginfo_child_exited(child: i32, status: ExitStatus) -> Siginfo {
    let (code, status) = match status {
        ExitStatus::Exit(code) => (
            litebox_common_linux::signal::CLD_EXITED,
            i32::from(code) & 0xff,
        ),
        ExitStatus::Signal(signal) => (litebox_common_linux::signal::CLD_KILLED, signal.as_i32()),
    };
    Siginfo {
        signo: Signal::SIGCHLD.as_i32(),
        errno: 0,
        code,
        #[cfg(target_pointer_width = "64")]
        __pad: 0,
        data: SiginfoData::new_child(child, 0, status),
    }
}

impl<Platform: ShimPlatform> SignalState<Platform> {
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
                #[cfg(target_pointer_width = "64")]
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
            #[cfg(target_pointer_width = "64")]
            __pad: 0,
        });
    }

    fn deliver_signal(
        &self,
        platform: &Platform,
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

        self.write_signal_frame(platform, frame_addr, siginfo, action, ctx)?;

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

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn with_temporary_signal_mask<R>(&self, mask: SigSet, f: impl FnOnce() -> R) -> R {
        let old = self.signals.blocked.get();
        self.signals.set_signal_mask(mask);
        let result = f();
        self.signals.set_signal_mask(old);
        result
    }

    pub(crate) fn sys_rt_sigprocmask(
        &self,
        how: SigmaskHow,
        set_ptr: Option<UserPtr<SigSet>>,
        oldset_ptr: Option<UserPtrMut<SigSet>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        let set = if let Some(set_ptr) = set_ptr {
            Some(set_ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?)
        } else {
            None
        };

        if let Some(oldset_ptr) = oldset_ptr {
            let oldset = self.signals.blocked.get();
            oldset_ptr
                .write_at_offset::<Platform>(0, oldset)
                .ok_or(Errno::EFAULT)?;
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

    /// Handle syscall `rt_sigsuspend`.
    ///
    /// Installs `mask_ptr` as the blocked set, blocks until a signal that is *not* in it becomes
    /// deliverable, and always fails with `EINTR` -- `rt_sigsuspend(2)` has no success return.
    ///
    /// The caller's original mask is not put back here. It is stashed in
    /// [`SignalState::saved_blocked`] and restored by [`Task::restore_saved_signal_mask`] after
    /// the return path has delivered the signal that ended the wait, so that the handler runs
    /// under the temporary mask exactly as Linux specifies. Restoring it here instead would
    /// re-block the awaited signal before its handler could observe it, which is precisely the
    /// livelock busybox's `ash` hits: its `waitproc` loops
    /// `while (!got_sigchld && !pending_sig) sigsuspend(&mask);`, and `got_sigchld` is only ever
    /// set by the `SIGCHLD` handler.
    pub(crate) fn sys_rt_sigsuspend(
        &self,
        mask_ptr: Option<UserPtr<SigSet>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        let mask = mask_ptr
            .ok_or(Errno::EFAULT)?
            .read_at_offset::<Platform>(0)
            .ok_or(Errno::EFAULT)?;
        // `SIGKILL` and `SIGSTOP` cannot be blocked, here or anywhere else.
        let mask = {
            let mut mask = mask;
            mask.remove(Signal::SIGKILL);
            mask.remove(Signal::SIGSTOP);
            mask
        };

        let previous = self.signals.blocked.get();
        // A nested `rt_sigsuspend` (only reachable from a signal handler) must not lose the
        // outermost caller's mask, so keep the first one stashed.
        if self.signals.saved_blocked.get().is_none() {
            self.signals.saved_blocked.set(Some(previous));
        }
        self.signals.set_signal_mask(mask);

        // A `SIGCHLD` posted by an exiting child in another host thread reaches this task's
        // pending set directly, but nothing would nudge *this* thread out of its wait. Registering
        // here is what turns a child's exit into a wakeup; it is the same list `wait4` uses.
        let table = &self.global.processes;
        let token = table.register_waiter(self.pid, self.wait_cx().waker().clone());
        let _unregister = litebox::utils::defer(|| table.unregister_waiter(token));

        // `wait_cx` interrupts on any deliverable signal or on task teardown, which is exactly
        // the set of reasons `rt_sigsuspend` returns. The condition is never true on its own.
        let _ = self.wait_cx().wait_until(|| false);
        Err(Errno::EINTR)
    }

    /// Puts back the mask an `rt_sigsuspend` replaced, if one is outstanding.
    ///
    /// Called from the return-to-guest path *after* `process_signals`, so the handler frame that
    /// signal delivery just built captured the temporary mask. See
    /// [`SignalState::saved_blocked`].
    pub(crate) fn restore_saved_signal_mask(&self) {
        if let Some(previous) = self.signals.saved_blocked.take() {
            self.signals.set_signal_mask(previous);
        }
    }

    pub(crate) fn sys_sigaltstack(
        &self,
        ss_ptr: Option<UserPtr<SigAltStack>>,
        old_ss_ptr: Option<UserPtrMut<SigAltStack>>,
        ctx: &PtRegs,
    ) -> Result<usize, Errno> {
        let mut old_ss = self.signals.altstack.get();
        let is_on_stack = is_on_stack(&old_ss, arch::sp(ctx));
        if let Some(old_ss_ptr) = old_ss_ptr {
            if is_on_stack {
                old_ss.flags |= SsFlags::ONSTACK;
            }
            old_ss_ptr
                .write_at_offset::<Platform>(0, old_ss)
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(ss_ptr) = ss_ptr {
            if is_on_stack {
                return Err(Errno::EPERM);
            }
            let ss = ss_ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
            self.signals.set_sigaltstack(ss)?;
        }
        Ok(0)
    }

    pub(crate) fn sys_rt_sigreturn(&self, ctx: &mut PtRegs) -> Result<usize, Errno> {
        let uctx_addr = arch::uctx_addr(ctx);
        let uctx_ptr = UserPtr::<Ucontext>::from_usize(uctx_addr);
        let Some(uctx) = uctx_ptr.read_at_offset::<Platform>(0) else {
            self.force_signal(Signal::SIGSEGV, false);
            return Err(Errno::EFAULT);
        };

        // Restore the alternate signal stack, ignoring errors.
        self.signals.set_sigaltstack(uctx.stack).ok();

        self.signals.set_signal_mask(uctx.sigmask);

        Ok(arch::restore_sigcontext(
            self.global.platform,
            ctx,
            &uctx.mcontext,
        ))
    }

    pub(crate) fn sys_rt_sigaction(
        &self,
        signal: Signal,
        act_ptr: Option<UserPtr<SigAction>>,
        oldact_ptr: Option<UserPtrMut<SigAction>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if signal == Signal::SIGKILL || signal == Signal::SIGSTOP {
            return Err(Errno::EINVAL);
        }
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        let act = if let Some(act_ptr) = act_ptr {
            Some(act_ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?)
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
                .write_at_offset::<Platform>(0, old_act)
                .ok_or(Errno::EFAULT)?;
        }

        Ok(0)
    }

    /// Handle syscall `kill`, with Linux's reading of `pid`: `> 0` names one process, `0` the
    /// caller's process group, `-1` every process but the caller (and init), and `< -1` the
    /// process group `-pid`. A group or broadcast target reports `ESRCH` only when nothing at all
    /// matched.
    pub(crate) fn sys_kill(&self, pid: i32, signal: i32) -> Result<usize, Errno> {
        let processes = &self.global.processes;
        let own_group = self.process().process_group_id();
        // `pid` is `i32::MIN` only for a group nothing can be in.
        let target_group = (pid < -1).then(|| pid.checked_neg()).flatten();
        if signal == 0 {
            let exists = match pid {
                0 => true,
                -1 => processes.has_other_live_process(self.pid),
                pid if pid < -1 => target_group.is_some_and(|group| {
                    own_group == group || processes.has_process_group_member(group, self.pid)
                }),
                pid => pid == self.pid || processes.is_live(pid),
            };
            return exists.then_some(0).ok_or(Errno::ESRCH);
        }
        let signal = Signal::try_from(signal)?;
        let delivered = match pid {
            0 => {
                self.send_shared_signal(signal, siginfo_kill(signal));
                processes.send_process_group_signal(
                    own_group,
                    self.pid,
                    signal,
                    siginfo_kill(signal),
                ) + 1
            }
            -1 => processes.send_signal_to_all_processes(self.pid, signal, siginfo_kill(signal)),
            pid if pid < -1 => {
                let Some(group) = target_group else {
                    return Err(Errno::ESRCH);
                };
                let mut delivered = processes.send_process_group_signal(
                    group,
                    self.pid,
                    signal,
                    siginfo_kill(signal),
                );
                if own_group == group {
                    self.send_shared_signal(signal, siginfo_kill(signal));
                    delivered += 1;
                }
                delivered
            }
            pid if pid != self.pid => {
                usize::from(processes.send_process_signal(pid, signal, siginfo_kill(signal)))
            }
            pid => return self.do_kill(Some(pid), None, signal.as_i32()),
        };
        (delivered > 0).then_some(0).ok_or(Errno::ESRCH)
    }

    pub(crate) fn sys_tkill(&self, tid: i32, signal: i32) -> Result<usize, Errno> {
        self.do_kill(None, Some(tid), signal)
    }

    pub(crate) fn sys_tgkill(&self, pid: i32, tid: i32, signal: i32) -> Result<usize, Errno> {
        self.do_kill(Some(pid), Some(tid), signal)
    }

    /// Handle syscall `rt_sigtimedwait`.
    ///
    /// Linux's `do_sigtimedwait`: dequeue a pending signal in `set` (thread-directed first, then
    /// process-directed; the caller's block mask is irrelevant to the dequeue), and if none is
    /// pending and `timeout` allows, sleep with `set` treated as unblocked until one arrives
    /// (`EAGAIN` when the timeout runs out first, `EINTR` when a signal outside `set` wakes the
    /// sleep instead). `SIGKILL`/`SIGSTOP` cannot be waited for. On success the signal number
    /// is returned and its `siginfo` is copied out to `info`.
    pub(crate) fn sys_rt_sigtimedwait(
        &self,
        set: Option<UserPtr<SigSet>>,
        info: Option<UserPtrMut<Siginfo>>,
        timeout: litebox_common_linux::TimeParam,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        let mut which = set
            .ok_or(Errno::EFAULT)?
            .read_at_offset::<Platform>(0)
            .ok_or(Errno::EFAULT)?;
        which.remove(Signal::SIGKILL);
        which.remove(Signal::SIGSTOP);
        // Read the timeout up front: a bad pointer is `EFAULT` even when a signal is ready.
        let timeout = timeout.read::<Platform>()?;
        let wait_allowed = match timeout {
            None => true,
            Some(t) => !t.is_zero(),
        };

        if let Some((signal, siginfo)) = self.dequeue_signal_in(which) {
            self.copy_siginfo_out(info, &siginfo)?;
            return Ok(signal.as_i32().cast_unsigned() as usize);
        }
        if !wait_allowed {
            return Err(Errno::EAGAIN);
        }

        // Sleep with `which` acting as unblocked (see `SignalState::sigwait_set`): the arrival
        // of any member interrupts the wait through `check_for_interrupt`, as does any other
        // deliverable signal or task teardown.
        self.signals.sigwait_set.set(which);
        let _restore = litebox::utils::defer(|| self.signals.sigwait_set.set(SigSet::empty()));
        let wait_cx = self.wait_cx();
        let wait_cx = match timeout {
            Some(t) => wait_cx.with_timeout(t),
            None => wait_cx,
        };
        let outcome = wait_cx.sleep();
        if let Some((signal, siginfo)) = self.dequeue_signal_in(which) {
            self.copy_siginfo_out(info, &siginfo)?;
            return Ok(signal.as_i32().cast_unsigned() as usize);
        }
        match outcome {
            WaitError::TimedOut => Err(Errno::EAGAIN),
            WaitError::Interrupted => Err(Errno::EINTR),
        }
    }

    /// Dequeues the first pending signal that is a member of `which`, thread-directed queue
    /// first (a remote `tkill` is drained in), then the process-wide queue -- the order
    /// `process_signals` uses. Ignores the block mask, like Linux's `dequeue_signal` with the
    /// caller's mask.
    fn dequeue_signal_in(&self, which: SigSet) -> Option<(Signal, Siginfo)> {
        self.thread_remote()
            .drain_remote_signals_into(&mut self.signals.pending.borrow_mut());
        let not_wanted = !which;
        {
            let mut pending = self.signals.pending.borrow_mut();
            if let Some(signal) = pending.next(not_wanted) {
                let siginfo = pending.remove(signal);
                return Some((signal, siginfo));
            }
        }
        let mut shared = self.signals.shared_pending.lock();
        let signal = shared.next(not_wanted)?;
        let siginfo = shared.remove(signal);
        Some((signal, siginfo))
    }

    fn copy_siginfo_out(
        &self,
        info: Option<UserPtrMut<Siginfo>>,
        siginfo: &Siginfo,
    ) -> Result<(), Errno> {
        if let Some(info) = info {
            info.write_at_offset::<Platform>(0, siginfo.clone())
                .ok_or(Errno::EFAULT)?;
        }
        Ok(())
    }

    /// Reads and validates the caller-supplied `siginfo` of `rt_sigqueueinfo`/
    /// `rt_tgsigqueueinfo`: `si_signo` is forced to `sig`, and a kernel-looking `si_code`
    /// (`>= 0`, or `SI_TKILL`) may only be sent to one's own process (`EPERM`), as Linux's
    /// `do_rt_sigqueueinfo` checks.
    fn read_queued_siginfo(
        &self,
        info: Option<UserPtr<Siginfo>>,
        sig: i32,
        target_pid: i32,
    ) -> Result<Siginfo, Errno> {
        let mut siginfo = info
            .ok_or(Errno::EFAULT)?
            .read_at_offset::<Platform>(0)
            .ok_or(Errno::EFAULT)?;
        if (siginfo.code >= 0 || siginfo.code == SI_TKILL) && target_pid != self.pid {
            return Err(Errno::EPERM);
        }
        siginfo.signo = sig;
        Ok(siginfo)
    }

    /// Handle syscall `rt_sigqueueinfo`: `kill(pid, sig)` carrying the caller's `siginfo`.
    pub(crate) fn sys_rt_sigqueueinfo(
        &self,
        pid: i32,
        sig: i32,
        info: Option<UserPtr<Siginfo>>,
    ) -> Result<usize, Errno> {
        let siginfo = self.read_queued_siginfo(info, sig, pid)?;
        if sig == 0 {
            // Existence/permission probe only, exactly as `kill(pid, 0)`.
            return self.sys_kill(pid, 0);
        }
        let signal = Signal::try_from(sig)?;
        if pid == self.pid {
            self.send_shared_signal(signal, siginfo);
            return Ok(0);
        }
        if pid <= 0 {
            log_unsupported!("rt_sigqueueinfo to a process group");
            return Err(Errno::EPERM);
        }
        self.global
            .processes
            .send_process_signal(pid, signal, siginfo)
            .then_some(0)
            .ok_or(Errno::ESRCH)
    }

    /// Handle syscall `rt_tgsigqueueinfo`: `tgkill(tgid, tid, sig)` carrying the caller's
    /// `siginfo` -- how crashpad's handler re-raises a crash signal with its original
    /// `siginfo` intact.
    #[allow(
        clippy::similar_names,
        reason = "tgid/tid are standard Linux terminology"
    )]
    pub(crate) fn sys_rt_tgsigqueueinfo(
        &self,
        tgid: i32,
        tid: i32,
        sig: i32,
        info: Option<UserPtr<Siginfo>>,
    ) -> Result<usize, Errno> {
        if tgid <= 0 || tid <= 0 {
            return Err(Errno::EINVAL);
        }
        let siginfo = self.read_queued_siginfo(info, sig, tgid)?;
        if sig == 0 {
            return self.do_kill(Some(tgid), Some(tid), 0).or_else(|err| {
                // `do_kill` rejects signal 0 as `EINVAL`; the probe form only needs existence.
                if err == Errno::EINVAL {
                    self.tgkill_target_exists(tgid, tid)
                        .then_some(0)
                        .ok_or(Errno::ESRCH)
                } else {
                    Err(err)
                }
            });
        }
        let signal = Signal::try_from(sig)?;
        if tgid != self.pid {
            let Some((remote, limits)) = self.global.processes.remote_thread(tgid, tid) else {
                return Err(Errno::ESRCH);
            };
            remote.deliver_remote_signal(&limits, signal, siginfo);
            return Ok(0);
        }
        if tid == self.tid {
            self.send_signal(signal, siginfo);
            return Ok(0);
        }
        let Some(remote) = self.process().thread_remote(tid) else {
            return Err(Errno::ESRCH);
        };
        remote.deliver_remote_signal(&self.process().limits, signal, siginfo);
        Ok(0)
    }

    #[allow(
        clippy::similar_names,
        reason = "tgid/tid are standard Linux terminology"
    )]
    fn tgkill_target_exists(&self, tgid: i32, tid: i32) -> bool {
        if tgid == self.pid {
            tid == self.tid || self.process().thread_remote(tid).is_some()
        } else {
            self.global.processes.remote_thread(tgid, tid).is_some()
        }
    }

    fn do_kill(&self, pid: Option<i32>, tid: Option<i32>, signal: i32) -> Result<usize, Errno> {
        let signal = Signal::try_from(signal)?;
        if let Some(pid) = pid
            && pid != self.pid
        {
            // `tgkill` at another process's thread: crashpad's handler does this to the crashed
            // client's threads. Delivered thread-directed through that thread's remote queue,
            // exactly as a sibling's is below.
            let tid = tid.unwrap_or(pid);
            let Some((remote, limits)) = self.global.processes.remote_thread(pid, tid) else {
                return Err(Errno::ESRCH);
            };
            remote.deliver_remote_signal(&limits, signal, siginfo_kill(signal));
            return Ok(0);
        }
        let Some(tid) = tid else {
            self.send_signal(signal, siginfo_kill(signal));
            return Ok(0);
        };
        if tid == self.tid {
            self.send_signal(signal, siginfo_kill(signal));
            return Ok(0);
        }
        // A sibling thread's `SignalState.pending` is a bare `RefCell`, not `Send`/`Sync` --
        // only reachable from the thread it belongs to -- so delivery goes through
        // `ThreadRemote::remote_pending`, the one piece of a thread's signal state built to be
        // touched remotely. `thread_remote` returns `None` once the target has detached
        // (exited), which is exactly when a real `tkill` would also report ESRCH: Linux never
        // resurrects a reaped tid.
        let Some(remote) = self.process().thread_remote(tid) else {
            return Err(Errno::ESRCH);
        };
        remote.deliver_remote_signal(&self.process().limits, signal, siginfo_kill(signal));
        Ok(0)
    }

    /// Returns whether there are any pending signals that can be delivered.
    ///
    /// A signal whose disposition is "ignore" does not count. It is pending only in the sense
    /// that [`Task::process_signals`] has not got round to discarding it yet, and treating it as
    /// deliverable would make it interrupt waits (`check_for_interrupt`) and hand the guest a
    /// spurious `EINTR` from a syscall that nothing actually interrupted. Linux never queues such
    /// a signal in the first place; this is where that is enforced, rather than at the sending
    /// end, because a sender in another guest process cannot see the target's live handler table.
    pub(crate) fn has_pending_signals(&self) -> bool {
        self.thread_remote()
            .drain_remote_signals_into(&mut self.signals.pending.borrow_mut());
        // A signal an `rt_sigtimedwait` is waiting for must wake the wait even while blocked.
        let blocked = self.signals.blocked.get() & !self.signals.sigwait_set.get();
        let thread_pending = self.signals.pending.borrow().pending & !blocked;
        let shared_pending = self.signals.shared_pending.lock().pending & !blocked;
        let pending = thread_pending | shared_pending;
        if pending.is_empty() {
            return false;
        }
        let handlers = self.signals.handlers.borrow();
        let inner = handlers.inner.lock();
        pending
            .into_iter()
            .any(|signal| match inner[signal].action.sigaction {
                SIG_IGN => false,
                SIG_DFL => !matches!(signal.default_disposition(), SignalDisposition::Ignore),
                _ => true,
            })
    }

    /// Returns the set of all pending (deliverable) signals.
    #[cfg(test)]
    pub(crate) fn pending_signal_set(&self) -> SigSet {
        let blocked = self.signals.blocked.get();
        let thread = self.signals.pending.borrow().pending & !blocked;
        let shared = self.signals.shared_pending.lock().pending & !blocked;
        thread | shared
    }

    /// Deliver any pending signals.
    pub(crate) fn process_signals(&self, ctx: &mut PtRegs) {
        self.thread_remote()
            .drain_remote_signals_into(&mut self.signals.pending.borrow_mut());
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
                            litebox_util_log::error!(
                                signal:? = signal,
                                pid:% = self.pid,
                                tid:% = self.tid;
                                "fatal signal: terminating task"
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
                    if let Err(DeliverFault) = self.signals.deliver_signal(
                        self.global.platform,
                        signal,
                        &siginfo,
                        &action,
                        ctx,
                    ) {
                        // Failed to deliver signal. Inject a SIGSEGV
                        // (terminating the process if we were trying to deliver
                        // a SIGSEGV).
                        self.force_signal(Signal::SIGSEGV, signal == Signal::SIGSEGV);
                    }
                }
            }
        }
    }

    /// Check whether the process-wide alarm deadline has passed and, if so,
    /// enqueue `SIGALRM`.
    ///
    /// Note this is a fallback in case the platform does not support timers.
    #[cfg(feature = "alarm_fallback")]
    #[inline]
    pub(crate) fn check_alarm_deadline(&self) {
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
        // change by the time it is unblocked. Nor is a signal an `rt_sigtimedwait` is
        // waiting for (Linux checks `real_blocked` here too).
        if (self.signals.blocked.get() | self.signals.sigwait_set.get()).contains(signal) {
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

    /// Returns a handle other guest processes can use to post a signal to this one.
    pub(crate) fn remote_signal_target(&self) -> RemoteSignalTarget<Platform> {
        RemoteSignalTarget {
            shared_pending: self.signals.shared_pending.clone(),
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
            #[cfg(target_pointer_width = "64")]
            __pad: 0,
            data: SiginfoData::new_zeroed(),
        };
        self.force_signal_with_info(signal, force_exit, siginfo);
    }

    fn force_signal_with_info(&self, signal: Signal, force_exit: bool, siginfo: Siginfo) {
        // This function resets the handler to `SIG_DFL` when forcing delivery,
        // so the signal must be fatal by default; otherwise the guest would
        // never actually see it acted on. `handle_exception_request` reaches
        // this with any signal `arch::exception_signal` can decode a hardware
        // exception into -- not just `SIGSEGV` (e.g. `SIGILL` for an
        // undefined instruction, `SIGTRAP` for a breakpoint, `SIGFPE` for a
        // floating-point exception) -- so the check has to match on
        // disposition rather than enumerate specific signals.
        assert!(matches!(
            signal.default_disposition(),
            SignalDisposition::Core | SignalDisposition::Terminate
        ));

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
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
            };
            // Don't allow further changes to this action.
            handler.immutable = true;
        }
    }

    pub(crate) fn handle_exception_request(&self, info: &litebox::shim::ExceptionInfo) {
        // Decoding an exception vector into a signal is entirely architectural,
        // so it lives alongside the rest of the per-architecture frame handling.
        let (signal, fault_address) = arch::exception_signal(info);
        litebox_util_log::error!(
            info:? = info,
            signal:? = signal,
            fault_address:? = fault_address,
            pid:% = self.pid,
            tid:% = self.tid;
            "guest hardware exception"
        );
        self.signals.last_exception.set(*info);
        self.force_signal_with_info(signal, false, siginfo_exception(signal, fault_address));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;

    #[test]
    fn kill_zero_signals_only_the_callers_process_group() {
        let caller = crate::syscalls::tests::init_platform(None);
        let peer = caller
            .global
            .clone()
            .new_test_task(caller.files.borrow().fs.clone());
        let outsider = caller
            .global
            .clone()
            .new_test_task(caller.files.borrow().fs.clone());

        caller.register_for_remote_signals();
        peer.register_for_remote_signals();
        outsider.register_for_remote_signals();
        assert_eq!(caller.sys_setpgid(0, 3131), Ok(()));
        assert_eq!(peer.sys_setpgid(0, 3131), Ok(()));
        assert_eq!(outsider.sys_setpgid(0, 4242), Ok(()));
        assert_eq!(caller.sys_kill(0, 0), Ok(0));
        assert!(caller.pending_signal_set().is_empty());
        assert!(peer.pending_signal_set().is_empty());
        assert!(outsider.pending_signal_set().is_empty());

        assert_eq!(caller.sys_kill(0, Signal::SIGUSR1.as_i32()), Ok(0));
        assert!(caller.pending_signal_set().contains(Signal::SIGUSR1));
        assert!(peer.pending_signal_set().contains(Signal::SIGUSR1));
        assert!(!outsider.pending_signal_set().contains(Signal::SIGUSR1));
    }
}
