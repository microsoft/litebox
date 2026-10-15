// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A runner process's threads (see `litebox_common_vm_abi`, Threads): what
//! each keeps apart from the process, and the calls on them.
//!
//! Every thread shares its process's [`Inner`]; only its registers, FS base,
//! platform state (extended state and GS base), upcall stack, and how it
//! stopped are its own. The main thread serves the process's requests.

use crate::memory::{checked_range, copy_from_user, copy_to_user};
use crate::{Inner, State, Suspended, layout};
use alloc::rc::Rc;
use core::cell::{Cell, RefCell};
use litebox::utils::TruncateExt as _;
use litebox_broker_vm_kernel::{EnterError, Entered, RingFutex};
use litebox_common_linux::PtRegs;
use litebox_common_vm_abi::{
    CloneKind, CloneReply, CloneRequest, FutexOp, FutexRequest, InterruptThreadRequest, NewThread,
    RUNNER_MANAGED_MIN, Registers, Status, USER_END, UserRange,
};
use litebox_platform::time::TimeProvider as _;
use litebox_platform_vm_kernel::{Instant, UserThreadState};

pub(crate) use litebox_common_vm_abi::MAIN_THREAD as MAIN;

/// Threads a process may have at once, including the main thread; a bound
/// on the kernel memory a process takes for them.
const MAX_THREADS: usize = 256;

pub(crate) struct Thread {
    pub(crate) id: u64,
    /// Borrowed only by the thread's run.
    pub(crate) ctx: RefCell<PtRegs>,
    /// Saved while it does not run.
    pub(crate) fs_base: Cell<usize>,
    /// Borrowed only by the thread's run.
    pub(crate) user_state: RefCell<UserThreadState>,
    pub(crate) upcall_stack: UserRange,
    pub(crate) suspended: Cell<Suspended>,
    /// [`CallId::InterruptThread`](litebox_common_vm_abi::CallId::InterruptThread):
    /// deliver an interrupt once it runs.
    pub(crate) kicked: Cell<bool>,
    /// [`CallId::ExitThread`](litebox_common_vm_abi::CallId::ExitThread);
    /// never runs again.
    pub(crate) exited: Cell<bool>,
    /// Nanoseconds, for `sched` to pick the thread that used the least.
    pub(crate) cpu_time: Cell<u64>,
}

impl Thread {
    pub(crate) fn main(upcall_stack: UserRange) -> Self {
        Self::new(
            MAIN,
            PtRegs::default(),
            UserThreadState::default(),
            &NewThread {
                upcall_stack,
                ..NewThread::default()
            },
        )
    }

    fn new(id: u64, ctx: PtRegs, user_state: UserThreadState, thread: &NewThread) -> Self {
        Self {
            id,
            ctx: RefCell::new(ctx),
            fs_base: Cell::new(thread.fs_base.trunc()),
            user_state: RefCell::new(user_state),
            upcall_stack: thread.upcall_stack,
            suspended: Cell::new(Suspended::No),
            kicked: Cell::new(false),
            exited: Cell::new(false),
            cpu_time: Cell::new(0),
        }
    }

    pub(crate) fn is_main(&self) -> bool {
        self.id == MAIN
    }

    /// Adds the CPU time since `start` (its run, or the worker's for it).
    pub(crate) fn charge(&self, platform: &litebox_platform_vm_kernel::VmKernel, start: Instant) {
        let used = platform.now().as_nanos().saturating_sub(start.as_nanos());
        self.cpu_time.set(self.cpu_time.get().saturating_add(used));
    }
}

/// A [`FutexOp::Wait`] that did not end at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FutexWait {
    addr: u64,
    deadline: Option<Instant>,
}

/// What a [`CallId::Futex`](litebox_common_vm_abi::CallId::Futex) leaves to
/// the caller.
pub(crate) enum FutexFlow {
    /// Return successfully, with how many threads it woke.
    Done(u64),
    /// Suspend the thread so.
    Block(Suspended),
    /// Make the call again later (see `Inner::retry`).
    Retry,
    /// The broker association failed.
    Failed,
}

/// Where a [`FutexWait`] stands.
pub(crate) enum FutexState {
    Ended(Result<(), Status>),
    /// Until a wake, an interrupt, or `wake`, if any.
    Blocked {
        wake: Option<Instant>,
    },
}

fn user_address(addr: u64) -> bool {
    (RUNNER_MANAGED_MIN..USER_END).contains(&addr)
}

fn pt_regs(regs: &Registers) -> PtRegs {
    PtRegs {
        r15: regs.r15.trunc(),
        r14: regs.r14.trunc(),
        r13: regs.r13.trunc(),
        r12: regs.r12.trunc(),
        rbp: regs.rbp.trunc(),
        rbx: regs.rbx.trunc(),
        r11: regs.r11.trunc(),
        r10: regs.r10.trunc(),
        r9: regs.r9.trunc(),
        r8: regs.r8.trunc(),
        rax: regs.rax.trunc(),
        rcx: regs.rcx.trunc(),
        rdx: regs.rdx.trunc(),
        rsi: regs.rsi.trunc(),
        rdi: regs.rdi.trunc(),
        orig_rax: regs.orig_rax.trunc(),
        rip: regs.rip.trunc(),
        cs: regs.cs.trunc(),
        eflags: regs.rflags.trunc(),
        rsp: regs.rsp.trunc(),
        ss: regs.ss.trunc(),
    }
}

impl Inner {
    /// The main thread, which every process has.
    pub(crate) fn main_thread(&self) -> Rc<Thread> {
        self.threads
            .borrow()
            .first()
            .filter(|thread| thread.is_main())
            .cloned()
            .expect("the main thread is the first")
    }

    /// The thread the worker's serving is for (see `sched`): the last to
    /// make a broker call, which may have published requests, else the main
    /// thread.
    pub(crate) fn broker_requester(&self) -> Rc<Thread> {
        let id = self.broker_requester.get();
        self.threads
            .borrow()
            .iter()
            .find(|thread| thread.id == id && !thread.exited.get())
            .cloned()
            .unwrap_or_else(|| self.main_thread())
    }

    /// The threads that have not exited.
    pub(crate) fn live_threads(&self) -> usize {
        self.threads
            .borrow()
            .iter()
            .filter(|thread| !thread.exited.get())
            .count()
    }

    /// Forgets `thread`, which exited.
    pub(crate) fn reap(&self, thread: &Thread) {
        self.threads
            .borrow_mut()
            .retain(|other| !core::ptr::eq(Rc::as_ptr(other), thread));
    }

    /// [`CallId::Clone`](litebox_common_vm_abi::CallId::Clone). The new
    /// thread starts as if preempted at `regs`, with `rax` its ID.
    pub(crate) fn clone_thread(&self, r: &CloneRequest) -> Result<CloneReply, Status> {
        if !matches!(*self.state.borrow(), State::Serving { .. }) {
            return Err(Status::Denied);
        }
        match r.kind {
            CloneKind::Thread => {}
        }
        let fs_base: usize = r.fs_base.trunc();
        if !(user_address(r.regs.rip) && user_address(r.regs.rsp))
            || (fs_base != 0 && !litebox_common_linux::arch::is_valid_user_fs_base(fs_base))
        {
            return Err(Status::InvalidArgument);
        }
        checked_range(
            r.upcall_stack.start,
            r.upcall_stack.len,
            RUNNER_MANAGED_MIN..USER_END,
        )
        .map_err(|_| Status::InvalidArgument)?;
        let user_state = UserThreadState::with_gs_base(r.gs_base).ok_or(Status::InvalidArgument)?;
        if self.live_threads() >= MAX_THREADS {
            return Err(Status::NoMemory);
        }
        let id = self.next_thread.get();
        self.next_thread.set(id + 1);
        let ctx = PtRegs {
            rax: id.trunc(),
            ..pt_regs(&r.regs)
        };
        let new = NewThread {
            regs: r.regs,
            fs_base: r.fs_base,
            gs_base: r.gs_base,
            upcall_stack: r.upcall_stack,
        };
        let thread = Thread::new(id, ctx, user_state, &new);
        thread.suspended.set(Suspended::Preempted);
        self.threads.borrow_mut().push(Rc::new(thread));
        self.share_cpu();
        log::debug!("thread {id} created");
        Ok(CloneReply { thread: id })
    }

    /// [`CallId::ExitThread`](litebox_common_vm_abi::CallId::ExitThread)'s
    /// `clear`, once `thread` is gone.
    ///
    /// The thread may have taken an interrupt for notifications in the
    /// runner's own code, which left them to its next guest entry, which
    /// never comes: another thread is interrupted for them (a waiting one
    /// sees them anyway, see `Inner::take_interrupt`).
    pub(crate) fn exit_thread(&self, thread: &Thread, clear: u64) {
        thread.exited.set(true);
        thread.suspended.set(Suspended::No);
        if self.broker.has_notifications() {
            self.notified.set(true);
        }
        if clear != 0 && clear.is_multiple_of(4) && copy_to_user(clear, &0u32.to_ne_bytes()).is_ok()
        {
            self.futex_wake(clear, u64::MAX);
        }
        log::debug!("thread {} exited", thread.id);
    }

    /// [`CallId::Futex`](litebox_common_vm_abi::CallId::Futex): the
    /// broker's on its control ring (see `litebox_common_vm_abi`, Broker),
    /// else between the process's threads.
    pub(crate) fn futex(&self, thread: &Thread, r: &FutexRequest) -> Result<FutexFlow, Status> {
        let unused = match r.op {
            FutexOp::Wait => r.count,
            FutexOp::Wake => u64::from(r.expected) | r.deadline,
        };
        if !r.addr.is_multiple_of(4) || unused != 0 {
            return Err(Status::InvalidArgument);
        }
        let ring = layout::BROKER_CONTROL_RING;
        if ring.contains(r.addr) {
            return self.ring_futex(thread, (r.addr - ring.start).trunc(), r);
        }
        Ok(match r.op {
            FutexOp::Wait => self
                .futex_wait(thread, r)?
                .map_or(FutexFlow::Done(0), |wait| {
                    FutexFlow::Block(Suspended::Futex(wait))
                }),
            FutexOp::Wake => FutexFlow::Done(self.futex_wake(r.addr, r.count)),
        })
    }

    /// The broker's futex, on the word at `offset` into the control ring.
    fn ring_futex(
        &self,
        thread: &Thread,
        offset: usize,
        r: &FutexRequest,
    ) -> Result<FutexFlow, Status> {
        if self.broker_busy.get() {
            // The worker is using the association (see `sched`).
            return Ok(FutexFlow::Retry);
        }
        // Either may have published requests.
        self.broker_requester.set(thread.id);
        let op = match r.op {
            FutexOp::Wait => RingFutex::Wait {
                expected: r.expected,
                deadline: (r.deadline != 0).then(|| Instant::from_nanos(r.deadline)),
            },
            FutexOp::Wake => RingFutex::Wake,
        };
        match self.broker.futex(offset, op) {
            Ok(Entered::Done) => Ok(FutexFlow::Done(0)),
            // The worker serves at once (see `sched`).
            Ok(Entered::Woke) => Ok(FutexFlow::Block(Suspended::Yielded)),
            Ok(Entered::Wait(wait)) => Ok(FutexFlow::Block(Suspended::Waiting(wait))),
            Err(EnterError::Status(status)) => Err(status),
            Err(EnterError::Failed) => Ok(FutexFlow::Failed),
        }
    }

    fn futex_wait(&self, thread: &Thread, r: &FutexRequest) -> Result<Option<FutexWait>, Status> {
        let word = copy_from_user(r.addr, 4)?;
        if *word != r.expected.to_ne_bytes() {
            return Ok(None);
        }
        let wait = FutexWait {
            addr: r.addr,
            deadline: (r.deadline != 0).then(|| Instant::from_nanos(r.deadline)),
        };
        match self.poll_futex(thread, &wait) {
            FutexState::Ended(result) => result.map(|()| None),
            FutexState::Blocked { .. } => Ok(Some(wait)),
        }
    }

    /// Where `wait` stands, after firing due timers and publishing
    /// readiness.
    pub(crate) fn poll_futex(&self, thread: &Thread, wait: &FutexWait) -> FutexState {
        self.broker.poll_events();
        if self.take_interrupt(thread) {
            return FutexState::Ended(Err(Status::Interrupted));
        }
        let now = self.platform.now();
        if wait.deadline.is_some_and(|deadline| now >= deadline) {
            return FutexState::Ended(Err(Status::TimedOut));
        }
        let wake = [
            wait.deadline,
            self.armed_deadline.get(),
            self.broker.next_timer_deadline(),
        ]
        .into_iter()
        .flatten()
        .min();
        FutexState::Blocked { wake }
    }

    /// Whether `thread` would take an interrupt now: it was kicked, which
    /// the interrupt that it then takes once it resumes consumes (a wait ends
    /// in the runner's own code, which may need it later, e.g., for the
    /// guest's next entry); or the process has notifications to receive or
    /// its deadline passed, which this consumes. Notifications are by the
    /// ring's state, not by their publication, which an earlier interrupt may
    /// have been for: one that came while the runner ran its own code, which
    /// leaves them to the guest's next entry, not to a wait.
    fn take_interrupt(&self, thread: &Thread) -> bool {
        if thread.kicked.get() {
            return true;
        }
        if self.broker.take_published() {
            self.notified.set(true);
        }
        if self.broker.has_notifications() {
            // The runner receives them next.
            self.notified.set(false);
            return true;
        }
        self.expire_deadline()
    }

    /// Whether the process's deadline
    /// ([`CallId::SetTimer`](litebox_common_vm_abi::CallId::SetTimer)) has
    /// passed. Then every thread takes an interrupt as it next runs, as for a
    /// process-directed signal, a thread waiting ending its wait first. One
    /// thread alone may be unable to act on it (e.g., the runner's main
    /// thread, once the guest's has exited).
    pub(crate) fn expire_deadline(&self) -> bool {
        let now = self.platform.now();
        if self
            .armed_deadline
            .get()
            .is_none_or(|deadline| deadline > now)
        {
            return false;
        }
        self.armed_deadline.set(None);
        for thread in self.threads.borrow().iter() {
            if thread.exited.get() {
                continue;
            }
            thread.kicked.set(true);
            if let Suspended::Futex(_) = thread.suspended.get() {
                thread
                    .suspended
                    .set(Suspended::Woken(Err(Status::Interrupted)));
            }
        }
        self.share_cpu();
        true
    }

    /// Wakes up to `count` threads waiting on `addr`; how many.
    pub(crate) fn futex_wake(&self, addr: u64, count: u64) -> u64 {
        let mut woken = 0;
        for thread in self.threads.borrow().iter() {
            if woken == count {
                break;
            }
            if let Suspended::Futex(wait) = thread.suspended.get()
                && wait.addr == addr
            {
                thread.suspended.set(Suspended::Woken(Ok(())));
                woken += 1;
            }
        }
        if woken != 0 {
            self.share_cpu();
        }
        woken
    }

    /// [`CallId::InterruptThread`](litebox_common_vm_abi::CallId::InterruptThread).
    pub(crate) fn interrupt_thread(&self, r: InterruptThreadRequest) -> Result<(), Status> {
        let threads = self.threads.borrow();
        let thread = threads
            .iter()
            .find(|thread| thread.id == r.thread && !thread.exited.get())
            .ok_or(Status::InvalidArgument)?;
        // Delivered as it next runs (see `Inner::rearm_timer`), even if this
        // ends its wait: the runner may be waiting in its own code, which it
        // returns to.
        thread.kicked.set(true);
        if let Suspended::Futex(_) = thread.suspended.get() {
            thread
                .suspended
                .set(Suspended::Woken(Err(Status::Interrupted)));
            self.share_cpu();
        }
        Ok(())
    }
}
