// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Cooperative tasks ([`Task`]), for the brokers: kernel work on stacks of
//! their own, which can [`suspend`] partway (e.g., to wait for a device, a
//! lock, or another process) while the CPU runs other work, and are resumed
//! later, by the same CPU, which may hold any number of them.
//!
//! Cooperative: a task runs, with interrupts disabled, until it finishes or
//! suspends. It touches user memory only through pinned pages
//! ([`crate::PinnedUserPages`]), never at user addresses, whose kernel faults
//! only a thread's run handles (see [`crate::run_thread_ref`]): so it runs in
//! whichever address space is current, and its resumer need restore none. Its
//! continuation stays on its CPU: what it holds across a suspension (e.g., a
//! lock's guard, or per-CPU data) need not be `Send`; and it has a
//! thread-local storage pointer of its own ([`crate::providers`]).
//!
//! A suspended task waits for a [`Wait`]: an event (e.g., a device's
//! interrupt), at the latest until a deadline, or a lock's word to change.
//! Wakers publish what they wake for, then bump the wake generation and kick
//! the CPUs holding suspended tasks ([`wake_blocked`]); a waiter reads the
//! generation before it last looks at what it waits for, so it is due once
//! the generation changed, however many wait, and whatever its word went
//! through meanwhile. A CPU's scheduler looks at its tasks in each step
//! ([`observe`], [`Task::is_due`]), and has a thread it runs make way for
//! them soon once they may be due ([`due`]).
//!
//! A task suspends holding no spin lock: its CPU, spinning for it, would
//! never resume it. It may hold platform locks ([`crate::RawMutex`]): a task
//! waiting for one suspends too, and code that is not a task spins for it,
//! so must not wait for one that a suspended task may hold: the CPU to
//! resume the task may be the spinning one, or wait for what that holds.
//! Debug builds check only part of this: they panic as such code would spin
//! on a CPU holding suspended tasks, whatever those hold, but not if the
//! holder is suspended on another CPU.
//!
//! Memory: a task has a stack of its own for its whole life, which
//! [`Task::try_new`] allocates, or fails to: `STACK_SIZE` and a guard page,
//! 256 KiB (512 KiB in debug builds), reserved even while the task is idle.
//! Starting, resuming, and finishing a task allocate nothing (its work, which
//! the caller boxes, may). Only the stack's allocation is fallible: the
//! task's context, a small one, aborts the kernel if the heap is exhausted, as
//! other kernel allocations do.

use crate::Instant;
use crate::cpu::{self, CpuId};
use crate::per_cpu::with_per_cpu_variables;
use alloc::alloc::Layout;
use alloc::boxed::Box;
use core::cell::Cell;
use core::ptr::NonNull;
#[cfg(debug_assertions)]
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use litebox_common_linux::PAGE_SIZE;

/// At least the CPU's kernel stack; with the guard page, a power of two, which
/// the allocator would round up to anyway.
const STACK_SIZE: usize =
    (crate::per_cpu::KERNEL_STACK_SIZE + PAGE_SIZE).next_power_of_two() - PAGE_SIZE;

/// The wake generation (see [`wake_blocked`]).
static WAKES: AtomicU64 = AtomicU64::new(0);

/// See [`stacks_in_use`].
#[cfg(debug_assertions)]
static IN_USE: AtomicUsize = AtomicUsize::new(0);

/// How [`Task::start`] or [`Task::resume`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ran {
    Finished,
    Suspended,
}

/// A cooperative task (see the [module](self) docs): work on its own stack
/// from [`Self::start`] until the work returns, which may suspend partway
/// ([`suspend`]); only the CPU it suspended on resumes it, but any may start
/// it while idle. Dropping one that has not finished panics: its stack holds
/// what the work holds (e.g., a lock's guard), which would leak.
pub struct Task {
    /// Heap-stable: the CPU running the task points to it (see
    /// `Tasks::current`), and so do the task's frames while it is suspended.
    context: Box<Context>,
    /// Each start runs on it, on whichever CPU.
    stack: Stack,
}

/// A task's state, which only the CPU running or holding it touches.
struct Context {
    state: Cell<TaskState>,
    /// The CPU holding its continuation, which alone resumes it: from its
    /// first suspension until it finishes (see `Tasks::live`).
    cpu: Cell<Option<CpuId>>,
    /// Its stack pointer, while it does not run.
    rsp: Cell<usize>,
    /// From its start until it runs.
    work: Cell<Option<Box<dyn FnOnce()>>>,
    /// Its thread-local storage pointer (see `crate::providers`), while it
    /// does not run.
    tls: Cell<*mut ()>,
}

#[derive(Clone, Copy)]
enum TaskState {
    Idle,
    Running,
    Suspended(Wait),
}

impl Task {
    /// An idle task, with its stack (see the [module](self) docs); `None` if
    /// the heap has no free block for the stack, which is contiguous. (Its
    /// context, a small allocation, aborts the kernel if the heap is
    /// exhausted.)
    pub fn try_new(platform: &'static crate::VmKernel) -> Option<Self> {
        let stack = Stack::try_new(platform)?;
        Some(Self {
            context: Box::new(Context {
                state: Cell::new(TaskState::Idle),
                cpu: Cell::new(None),
                rsp: Cell::new(0),
                work: Cell::new(None),
                tls: Cell::new(core::ptr::null_mut()),
            }),
            stack,
        })
    }

    /// Runs `work` on the task's stack until it finishes or suspends; the
    /// calling CPU may differ from the last start's.
    ///
    /// # Panics
    ///
    /// Unless the task is idle (new, or finished); or on a task, or in a
    /// thread's run.
    pub fn start(&self, work: Box<dyn FnOnce()>) -> Ran {
        let context = &*self.context;
        assert!(
            matches!(context.state.get(), TaskState::Idle),
            "the task has not finished"
        );
        self.stack.flush_guard();
        context.rsp.set(initial_rsp(self.stack.top()));
        context.work.set(Some(work));
        #[cfg(debug_assertions)]
        IN_USE.fetch_add(1, Ordering::Relaxed);
        self.switch_in()
    }

    /// Resumes the task until it finishes or suspends again.
    ///
    /// # Panics
    ///
    /// Unless it is suspended on the calling CPU; or on a task, or in a
    /// thread's run.
    pub fn resume(&self) -> Ran {
        let context = &*self.context;
        assert!(
            matches!(context.state.get(), TaskState::Suspended(_))
                && context.cpu.get() == Some(cpu::current()),
            "the task is not suspended on this CPU"
        );
        self.switch_in()
    }

    /// The CPU holding its continuation, which alone resumes it: from its
    /// first suspension until it finishes, also while resumed.
    pub fn cpu(&self) -> Option<CpuId> {
        self.context.cpu.get()
    }

    /// Whether it is suspended on the calling CPU, and its [`Wait`] may have
    /// ended as of `now`.
    pub fn is_due(&self, now: Instant) -> bool {
        match self.context.state.get() {
            TaskState::Suspended(wait) => {
                self.context.cpu.get() == Some(cpu::current()) && wait.is_due(now)
            }
            TaskState::Idle | TaskState::Running => false,
        }
    }

    /// If suspended, until when it waits at the latest.
    pub fn deadline(&self) -> Option<Instant> {
        match self.context.state.get() {
            TaskState::Suspended(wait) => wait.deadline(),
            TaskState::Idle | TaskState::Running => None,
        }
    }

    /// Switches to the task until it finishes or suspends.
    fn switch_in(&self) -> Ran {
        let context = &*self.context;
        let (resumer_rsp, resumer_tls) = with_per_cpu_variables(|pcv| {
            assert!(!pcv.asm.is_in_user(), "tasks run outside threads' runs");
            assert!(pcv.tasks.current.get().is_none(), "tasks run outside tasks");
            pcv.tasks.current.set(Some(NonNull::from(context)));
            (
                pcv.tasks.resumer_rsp.as_ptr(),
                pcv.tls.replace(context.tls.get()),
            )
        });
        context.state.set(TaskState::Running);
        // Safety: the task's stack pointer: initial, or saved by `switch` in
        // `suspend`, on its stack, which it owns.
        unsafe { switch(resumer_rsp, context.rsp.get()) };
        with_per_cpu_variables(|pcv| {
            pcv.tasks.current.set(None);
            context.tls.set(pcv.tls.replace(resumer_tls));
        });
        match context.state.get() {
            TaskState::Suspended(_) => Ran::Suspended,
            TaskState::Idle => {
                assert!(
                    context.tls.get().is_null(),
                    "a task finished with thread-local storage"
                );
                #[cfg(debug_assertions)]
                IN_USE.fetch_sub(1, Ordering::Relaxed);
                Ran::Finished
            }
            TaskState::Running => unreachable!("a task switched back while running"),
        }
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        assert!(
            matches!(self.context.state.get(), TaskState::Idle),
            "a task dropped before it finished"
        );
    }
}

/// What a suspended task waits for (see the [module](self) docs): it is due
/// once [`wakes`] is no longer `seen`, or, waiting for an event, once its
/// deadline passed, or, for a lock, once the lock's word changed.
#[derive(Clone, Copy, Debug)]
pub struct Wait {
    seen: u64,
    on: On,
}

/// What a [`Wait`] is for.
#[derive(Clone, Copy, Debug)]
enum On {
    Event {
        deadline: Option<Instant>,
    },
    Lock {
        word: NonNull<AtomicU32>,
        expected: u32,
    },
}

impl Wait {
    /// For an event, at the latest until `deadline`; `seen` is [`wakes`] as
    /// read before the waiter last looked at what it waits for.
    pub fn event(seen: u64, deadline: Option<Instant>) -> Self {
        Self {
            seen,
            on: On::Event { deadline },
        }
    }

    /// For `word` to differ from `expected`; `seen` as for [`Self::event`].
    ///
    /// # Safety
    ///
    /// `word` must outlive the wait (e.g., as the waiter borrows it across
    /// its suspension).
    pub(crate) unsafe fn lock(word: &AtomicU32, expected: u32, seen: u64) -> Self {
        Self {
            seen,
            on: On::Lock {
                word: NonNull::from(word),
                expected,
            },
        }
    }

    fn deadline(&self) -> Option<Instant> {
        match self.on {
            On::Event { deadline } => deadline,
            On::Lock { .. } => None,
        }
    }

    fn is_due(&self, now: Instant) -> bool {
        wakes() != self.seen
            || match self.on {
                On::Event { deadline } => deadline.is_some_and(|deadline| now >= deadline),
                On::Lock { word, expected } => {
                    // Safety: it outlives the wait (see `Self::lock`).
                    unsafe { word.as_ref() }.load(Ordering::Relaxed) != expected
                }
            }
    }
}

/// On a task, suspends it until its CPU resumes it, once `wait` may have
/// ended (see [`Task::is_due`]), and returns true; elsewhere, returns false
/// at once. Hold no spin lock across it (see the [module](self) docs).
pub fn suspend(wait: Wait) -> bool {
    let Some((context, resumer_rsp)) = with_per_cpu_variables(|pcv| {
        let context = pcv.tasks.current.get()?;
        Some((context, pcv.tasks.resumer_rsp.get()))
    }) else {
        return false;
    };
    // Safety: the running task's, which its `Task` keeps, at this address,
    // at least until it finishes.
    let context = unsafe { context.as_ref() };
    if context.cpu.get().is_none() {
        context.cpu.set(Some(cpu::current()));
        with_per_cpu_variables(|pcv| pcv.tasks.hold());
    }
    context.state.set(TaskState::Suspended(wait));
    // Safety: `resumer_rsp` was saved by `switch` in `Task::switch_in`, whose
    // stack is live; this one, the task's, stays allocated while the task is
    // suspended (see `Task`'s `Drop`).
    unsafe { switch(context.rsp.as_ptr(), resumer_rsp) };
    true
}

/// The wake generation, which [`wake_blocked`] bumps (sequentially
/// consistent).
pub fn wakes() -> u64 {
    WAKES.load(Ordering::SeqCst)
}

/// Makes the suspended tasks due (see [`Wait`]), once what may end their
/// waits is published: bumps the wake generation, then kicks the CPUs that
/// hold suspended tasks (`cpu::kick`), but `except` (e.g., the calling CPU,
/// which looks at its tasks again by itself). No locks, no per-CPU data:
/// usable in interrupt handlers.
pub fn wake_blocked(except: CpuId) {
    WAKES.fetch_add(1, Ordering::SeqCst);
    cpu::kick(cpu::blocked_mask() & !except.bit());
}

/// For the calling CPU's scheduler, as it looks at the tasks it holds:
/// [`wakes`] now, which [`due`] compares with until the next call.
pub fn observe() -> u64 {
    let wakes = wakes();
    with_per_cpu_variables(|pcv| pcv.tasks.seen.set(wakes));
    wakes
}

/// Whether a task the calling CPU holds may be due: the wake generation
/// changed since [`observe`]. (Their deadlines are the caller's to keep; see
/// [`Task::deadline`].)
pub fn due() -> bool {
    with_per_cpu_variables(|pcv| pcv.tasks.live.get() != 0 && wakes() != pcv.tasks.seen.get())
}

/// How many suspended tasks the calling CPU holds.
pub fn live_here() -> usize {
    with_per_cpu_variables(|pcv| pcv.tasks.live.get())
}

/// How many tasks, on every CPU, use their stacks: started, and not finished
/// (idle ones keep theirs unused). For diagnostics, in debug builds only:
/// every CPU updates the count as its tasks start and finish.
#[cfg(debug_assertions)]
pub fn stacks_in_use() -> usize {
    IN_USE.load(Ordering::Relaxed)
}

/// Whether the caller runs on a task.
pub fn on_task() -> bool {
    with_per_cpu_variables(|pcv| pcv.tasks.current.get().is_some())
}

/// A CPU's: the task it runs, and the suspended ones it holds; only it
/// touches them.
pub(crate) struct Tasks {
    /// The running task's context, from its switch in to its switch back.
    current: Cell<Option<NonNull<Context>>>,
    /// The resumer's stack pointer, while a task runs.
    resumer_rsp: Cell<usize>,
    /// How many suspended tasks it holds (see [`Task::cpu`]); meanwhile, its
    /// bit in `cpu::blocked_mask` is set.
    live: Cell<usize>,
    /// See [`observe`].
    seen: Cell<u64>,
}

impl Tasks {
    pub(crate) const fn new() -> Self {
        Self {
            current: Cell::new(None),
            resumer_rsp: Cell::new(0),
            live: Cell::new(0),
            seen: Cell::new(0),
        }
    }

    /// A task suspended for the first time; the first one sets the CPU's bit.
    fn hold(&self) {
        self.live.set(self.live.get() + 1);
        if self.live.get() == 1 {
            cpu::set_blocked(true);
        }
    }

    /// A suspended task finished; the last one clears the CPU's bit.
    fn release(&self) {
        self.live.set(self.live.get() - 1);
        if self.live.get() == 0 {
            cpu::set_blocked(false);
        }
    }
}

/// A task's stack, its own for its life: an allocation of a guard page,
/// unmapped, then [`STACK_SIZE`] bytes, not zeroed. One CPU at a time runs on
/// it (the task's owner serializes its starts, e.g., by a process's claim),
/// having flushed the guard first ([`Self::flush_guard`]): so an overflow that
/// reaches the guard faults. Freed on any CPU, once no task runs or is
/// suspended on it, mapping its guard again first.
struct Stack {
    guard: NonNull<u8>,
    /// For its kernel mappings.
    platform: &'static crate::VmKernel,
    /// The CPUs that flushed the guard since `try_new` unmapped it, a bit each
    /// (`CpuId::bit`).
    flushed: Cell<u64>,
}

impl Stack {
    const LAYOUT: Layout = match Layout::from_size_align(PAGE_SIZE + STACK_SIZE, PAGE_SIZE) {
        Ok(layout) => layout,
        Err(_) => panic!("a page-aligned stack"),
    };

    /// Unmaps its guard in the base table, whose kernel mappings every table
    /// shares, which flushes it on the calling CPU only; `None` if the heap
    /// has no free block for it.
    fn try_new(platform: &'static crate::VmKernel) -> Option<Self> {
        // Safety: nonzero size.
        let guard = NonNull::new(unsafe { alloc::alloc::alloc(Self::LAYOUT) })?;
        // Safety: its first page, unused; mapped again before it is freed.
        unsafe {
            crate::per_cpu::unmap_guard(
                &platform.page_table_manager.base_page_table,
                guard.as_ptr() as usize,
            );
        }
        Some(Self {
            guard,
            platform,
            flushed: Cell::new(cpu::current().bit()),
        })
    }

    /// Before the calling CPU runs on the stack: flushes the guard from its
    /// TLB, the first time. `try_new` flushed only its own CPU, while another
    /// may still translate the page as mapped before (e.g., having used the
    /// memory as another allocation), through which an overflow would write
    /// on, below the stack, rather than fault. Once a CPU flushed it, it
    /// cannot translate the guard until `drop` maps it again: nothing else
    /// maps the page, x86 caches no absent translation, and with no PCIDs,
    /// `invlpg` drops every translation of the page. A CPU resuming the task
    /// started it, so flushed already.
    fn flush_guard(&self) {
        let cpu = cpu::current().bit();
        if self.flushed.get() & cpu == 0 {
            x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(self.guard.as_ptr() as u64));
            self.flushed.set(self.flushed.get() | cpu);
        }
    }

    fn top(&self) -> usize {
        self.guard.as_ptr() as usize + PAGE_SIZE + STACK_SIZE
    }
}

impl Drop for Stack {
    /// Only once no task runs or is suspended on it (see `Task`'s `Drop`), on
    /// any CPU, with no flush: an absent translation is never cached, and a
    /// stale one is of the page as mapped again.
    fn drop(&mut self) {
        let guard = self.guard.as_ptr();
        // Safety: `try_new` unmapped it, and nothing runs on the stack
        // anymore.
        unsafe {
            crate::per_cpu::restore_guard(
                &self.platform.page_table_manager.base_page_table,
                guard as usize,
            );
        }
        if cfg!(debug_assertions) {
            // Mapped again, as the allocator expects: else this faults.
            // Safety: part of the allocation, which nothing else uses.
            unsafe { guard.write_volatile(0) };
        }
        // Safety: allocated with this layout, in `try_new`.
        unsafe { alloc::alloc::dealloc(guard, Self::LAYOUT) };
    }
}

/// A task stack's initial frame, for `switch` to pop: callee-saved
/// registers (zero), then `task_entry` as the return address, which it
/// reaches with a 16-byte aligned stack, as after a call's return.
fn initial_rsp(stack_top: usize) -> usize {
    const REGISTERS: usize = 6;
    let rsp = stack_top - (REGISTERS + 3) * 8;
    debug_assert_eq!(rsp % 16, 8);
    let frame = rsp as *mut usize;
    // Safety: within the stack, which nothing uses now.
    unsafe {
        for register in 0..REGISTERS {
            frame.add(register).write(0);
        }
        frame.add(REGISTERS).write(task_entry as *const () as usize);
    }
    rsp
}

/// Saves the callee-saved registers and the stack pointer in `*save`, then
/// restores those saved at `load` and returns there.
///
/// # Safety
///
/// `load` must be a stack pointer saved by this function (or `initial_rsp`'s)
/// on a live stack.
#[unsafe(naked)]
unsafe extern "C" fn switch(save: *mut usize, load: usize) {
    core::arch::naked_asm!(
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi], rsp",
        "mov rsp, rsi",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret",
    );
}

/// Where a task starts, on its stack.
#[unsafe(naked)]
unsafe extern "C" fn task_entry() -> ! {
    core::arch::naked_asm!("call {main}", "ud2", main = sym task_main);
}

extern "C" fn task_main() -> ! {
    let context = with_per_cpu_variables(|pcv| pcv.tasks.current.get()).expect("a task runs");
    // Safety: as in `suspend`.
    let context = unsafe { context.as_ref() };
    let work = context.work.take().expect("work to run");
    work();
    if context.cpu.take().is_some() {
        with_per_cpu_variables(|pcv| pcv.tasks.release());
    }
    context.state.set(TaskState::Idle);
    let resumer_rsp = with_per_cpu_variables(|pcv| pcv.tasks.resumer_rsp.get());
    // Safety: as in `suspend`; this stack, which holds nothing anymore
    // (the work was consumed), is abandoned, until the task's next start
    // begins it anew.
    unsafe { switch(context.rsp.as_ptr(), resumer_rsp) };
    unreachable!("a finished task resumed");
}

/// Self-check (debug builds, at boot, before the CPU takes interrupts: so
/// with no IPI, nor [`cpu::relax`]): eight tasks at once on the calling CPU,
/// each on its own stack, the first four suspended, waiting for an event, and
/// finishing in any order, and finished ones started again, on the same
/// stacks; a lock held across a suspension, which another task waits for,
/// through a spurious wake, and an unlock and lock again; a wake between a
/// waiter's last look and its suspension; deadlines; a wake the scheduler did
/// not see yet; thread-local storage; a task moved while suspended; and the
/// bookkeeping of guard flushes.
///
/// # Panics
///
/// On a failed check.
#[cfg(debug_assertions)]
pub(crate) fn self_check(platform: &'static crate::VmKernel) {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicUsize};
    use litebox::platform::ThreadLocalStorageProvider as _;
    use litebox_platform::time::{Instant as _, TimeProvider as _};
    type Mutex = litebox_platform::sync::Mutex<crate::VmKernel, u32>;
    let me = cpu::current();
    let now = || platform.now();
    let new_task = || Task::try_new(platform).expect("a task's stack at boot");
    let blocked = || cpu::blocked_mask() & me.bit() != 0;
    let event = || assert!(suspend(Wait::event(wakes(), None)));
    assert!(!suspend(Wait::event(wakes(), None)), "not on a task");

    // Per task, an address on the stack it ran on, and whether it finished.
    let seen: Arc<[(AtomicUsize, AtomicBool); 8]> = Arc::default();
    let record = |index: usize| -> Box<dyn FnOnce()> {
        let seen = seen.clone();
        Box::new(move || {
            let local = 0u8;
            seen[index]
                .0
                .store(core::ptr::from_ref(&local) as usize, Ordering::Relaxed);
            if index < 4 {
                event();
            }
            seen[index].1.store(true, Ordering::Relaxed);
        })
    };
    let tasks: [Task; 8] = core::array::from_fn(|_| new_task());
    for (index, task) in tasks.iter().enumerate() {
        let ran = task.start(record(index));
        assert_eq!(
            ran,
            if index < 4 {
                Ran::Suspended
            } else {
                Ran::Finished
            }
        );
    }
    assert_eq!(stacks_in_use(), 4);
    for (index, task) in tasks.iter().enumerate() {
        let suspended = index < 4;
        assert_eq!(task.cpu(), suspended.then_some(me));
        assert_eq!(seen[index].1.load(Ordering::Relaxed), !suspended);
        assert!(!task.is_due(now()), "nothing ended its wait");
        let stack = task.stack.top() - STACK_SIZE..task.stack.top();
        let address = seen[index].0.load(Ordering::Relaxed);
        assert!(stack.contains(&address), "task {index} ran off its stack");
    }
    assert_eq!(live_here(), 4);
    // As a device's interrupt would: they finish in any order, and the CPU
    // holds suspended tasks until the last does.
    wake_blocked(me);
    for (finished, index) in [2, 0, 3, 1].into_iter().enumerate() {
        assert!(blocked());
        assert!(tasks[index].is_due(now()));
        assert_eq!(tasks[index].resume(), Ran::Finished);
        assert!(seen[index].1.load(Ordering::Relaxed));
        assert_eq!(live_here(), 3 - finished);
    }
    assert!(!blocked());
    assert_eq!(stacks_in_use(), 0);
    // Started again, a finished task runs on its stack again, from its top.
    for (index, task) in tasks.iter().enumerate().skip(4) {
        let address = seen[index].0.load(Ordering::Relaxed);
        assert_eq!(task.start(record(index)), Ran::Finished);
        assert_eq!(seen[index].0.load(Ordering::Relaxed), address);
    }
    // The CPU that allocated a stack flushed its guard; another flushes it as
    // it first starts the task: here, as if this one had not, its bit
    // cleared. (Bookkeeping only: no TLB is looked at.)
    let task = &tasks[7];
    assert_eq!(task.stack.flushed.get(), me.bit());
    task.stack.flushed.set(0);
    assert_eq!(task.start(record(7)), Ran::Finished);
    assert_eq!(task.stack.flushed.get(), me.bit());
    // Idle, they free their stacks, mapping the guards again first (see
    // `Stack`'s `Drop`).
    drop(tasks);

    // A wake between the waiter's last look and its suspension: due at once.
    let task = new_task();
    let wake = Box::new(|| {
        let seen = wakes();
        wake_blocked(cpu::current());
        assert!(suspend(Wait::event(seen, None)));
    });
    assert_eq!(task.start(wake), Ran::Suspended);
    assert!(task.is_due(now()));
    assert_eq!(task.resume(), Ran::Finished);
    let deadline = now()
        .checked_add(core::time::Duration::from_secs(1))
        .expect("the clock is far from overflowing");
    let wait = Box::new(move || assert!(suspend(Wait::event(wakes(), Some(deadline)))));
    assert_eq!(task.start(wait), Ran::Suspended);
    assert_eq!(task.deadline(), Some(deadline));
    assert!(!task.is_due(now()) && task.is_due(deadline));
    assert_eq!(task.resume(), Ran::Finished);

    // A wake after the scheduler last looked at the CPU's tasks (e.g., as its
    // polls ended another's wait): one may be due until it looks again,
    // however often asked; none is, with none suspended.
    assert_eq!(task.start(Box::new(event)), Ran::Suspended);
    observe();
    assert!(!due());
    wake_blocked(me);
    assert!(due() && due());
    observe();
    assert!(!due());
    assert_eq!(task.resume(), Ran::Finished);
    wake_blocked(me);
    assert!(!due());

    // Each task has its own thread-local storage pointer.
    let tls = Box::new(move || {
        let own = core::ptr::dangling_mut::<u64>().cast::<()>();
        // Safety: nothing uses it.
        assert!(unsafe { crate::VmKernel::replace_thread_local_storage(own) }.is_null());
        event();
        assert_eq!(crate::VmKernel::get_thread_local_storage(), own);
        // Safety: as above.
        unsafe { crate::VmKernel::replace_thread_local_storage(core::ptr::null_mut()) };
    });
    assert_eq!(task.start(tls), Ran::Suspended);
    assert!(crate::VmKernel::get_thread_local_storage().is_null());
    assert_eq!(task.resume(), Ran::Finished);

    // Moved while suspended: its CPU and frames point to its context.
    assert_eq!(task.start(Box::new(event)), Ran::Suspended);
    let moved = Box::new(task);
    assert_eq!(moved.cpu(), Some(me));
    assert_eq!(moved.resume(), Ran::Finished);

    // A lock held across a suspension; its waiter, on the same CPU, suspends
    // until it is released, though woken for something else before.
    let mutex = Arc::new(Mutex::new(0));
    let (holder, waiter) = (new_task(), new_task());
    let lock = mutex.clone();
    let hold = Box::new(move || {
        let mut guard = lock.lock();
        event();
        *guard += 1;
    });
    assert_eq!(holder.start(hold), Ran::Suspended);
    let lock = mutex.clone();
    let wait = Box::new(move || *lock.lock() += 10);
    assert_eq!(waiter.start(wait), Ran::Suspended);
    assert!(!waiter.is_due(now()));
    wake_blocked(me);
    assert!(waiter.is_due(now()));
    assert_eq!(waiter.resume(), Ran::Suspended);
    assert!(!waiter.is_due(now()));
    assert_eq!(holder.resume(), Ran::Finished);
    assert!(waiter.is_due(now()));
    assert_eq!(waiter.resume(), Ran::Finished);
    assert_eq!(*mutex.lock(), 11);

    // The holder releases it and takes it again, and a third task waits too:
    // the word is again as the first waiter saw it, but it is due (as the
    // third, which saw the latest wake, is not, the word is unchanged).
    let lock = mutex.clone();
    let relock = Box::new(move || {
        let guard = lock.lock();
        event();
        drop(guard);
        let guard = lock.lock();
        event();
        drop(guard);
    });
    assert_eq!(holder.start(relock), Ran::Suspended);
    let lock = mutex.clone();
    let wait = Box::new(move || *lock.lock() += 100);
    assert_eq!(waiter.start(wait), Ran::Suspended);
    assert_eq!(holder.resume(), Ran::Suspended);
    let third = new_task();
    let lock = mutex.clone();
    let wait = Box::new(move || *lock.lock() += 1000);
    assert_eq!(third.start(wait), Ran::Suspended);
    assert!(waiter.is_due(now()) && !third.is_due(now()));
    assert_eq!(waiter.resume(), Ran::Suspended);
    assert!(!waiter.is_due(now()));
    assert_eq!(holder.resume(), Ran::Finished);
    for task in [&third, &waiter] {
        assert!(task.is_due(now()));
        assert_eq!(task.resume(), Ran::Finished);
    }
    assert_eq!(*mutex.lock(), 1111);
    assert_eq!(stacks_in_use(), 0);
}
