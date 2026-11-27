// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Preemptible kernel threads ([`Kthread`]) on stacks of their own
//! ([`Stack`]), which the kernel's scheduler runs and preempts
//! ([`Preemption`]).
//!
//! A thread runs with interrupts enabled but in the kernel services it enters
//! (see [`crate::preempt`]), which share only kernel-grade state with the
//! kernel. It is preempted only with interrupts enabled (at its safe points
//! and as its interrupts return), so never holding a kernel-grade lock; there
//! its frames may move to another CPU, so they hold nothing tied to a CPU (it
//! finds itself in one load, `current`, and reads its CPU's other variables
//! only with interrupts disabled, in `with_this_cpu`). It touches user memory
//! only through pinned pages.
//!
//! To sleep, a thread registers on a queue ([`WaitQueue::prepare`]), checks
//! what it waits for, and sleeps unless it happened ([`Prepared::sleep`]).

use crate::Instant;
use crate::mm::MemoryProvider as _;
use crate::per_cpu::{self, PerCpuVariables, PerCpuVariablesAsm, with_per_cpu_variables};
use crate::preempt::{KernelMutex, NoPreempt, Sections};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::Cell;
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use litebox_common_linux::PAGE_SIZE;
use litebox_platform::sync::{ImmediatelyWokenUp, RawMutex as _};
use litebox_platform::time::{Instant as _, TimeProvider as _};

/// Over three times the deepest broker thread work measured, interrupts
/// included.
#[cfg(debug_assertions)]
const STACK_SIZE: usize = 63 * PAGE_SIZE;
#[cfg(not(debug_assertions))]
const STACK_SIZE: usize = 15 * PAGE_SIZE;

const STACK_ALLOCATION: usize = PAGE_SIZE + STACK_SIZE;
const _: () = assert!(STACK_ALLOCATION.is_power_of_two());

const STACK_ORDER: u32 = (STACK_ALLOCATION / PAGE_SIZE).ilog2();

/// The control block's offset: at the top, 16-byte aligned for the frames
/// below, on a cache line of its own.
const CONTROL_OFFSET: usize = (STACK_ALLOCATION - size_of::<Control>()) & !63;

struct Kthreads {
    live: AtomicUsize,
    stacks: AtomicUsize,
    base_table: spin::Once<&'static crate::mm::PageTable<PAGE_SIZE>>,
    preemption: spin::Once<&'static dyn Preemption>,
}

static KTHREADS: Kthreads = Kthreads {
    live: AtomicUsize::new(0),
    stacks: AtomicUsize::new(0),
    base_table: spin::Once::new(),
    preemption: spin::Once::new(),
};

/// Has stacks mapped in `base_table`, the kernel's page table. Before any
/// stack is allocated.
pub(crate) fn init(base_table: &'static crate::mm::PageTable<PAGE_SIZE>) {
    let mut installed = false;
    KTHREADS.base_table.call_once(|| {
        installed = true;
        base_table
    });
    assert!(installed, "the kernel threads' page table is already set");
}

fn base_table() -> &'static crate::mm::PageTable<PAGE_SIZE> {
    KTHREADS
        .base_table
        .get()
        .expect("kernel threads run once the kernel booted")
}

/// Where a running thread's run is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    Interrupt,
    /// [`safe_point`] or [`yield_due`].
    SafePoint,
}

/// What [`Preemption::check`] decided, with the run's slice end from then on,
/// if ever: what [`Kthread::run`] returns once it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// The run ends here.
    Preempt(Option<Instant>),
    /// The thread runs on.
    Continue(Option<Instant>),
}

/// The scheduler's policy for the threads' runs, asked with interrupts
/// disabled, on the running thread's CPU.
pub trait Preemption: Sync {
    /// Whether to preempt the running thread at `point`, its slice ending at
    /// `slice_end`.
    fn check(&self, point: Point, slice_end: Option<Instant>) -> Check;

    /// Outside a check, the running thread's run is to end at once (a wake it
    /// made, or [`yield_due`]): its slice end from then on, which stays the
    /// run's.
    fn end_slice(&self, slice_end: Option<Instant>) -> Instant;

    /// A run with `slice_end` starts or resumes on this CPU ([`Kthread::run`]):
    /// arms what preempts it there past that end (e.g., the CPU's timer), as
    /// nothing else may until then.
    fn start(&self, slice_end: Instant);
}

/// Makes `preemption` the threads' policy: until then, nothing preempts them.
///
/// # Panics
///
/// On a second call.
pub fn set_preemption(preemption: &'static dyn Preemption) {
    let mut installed = false;
    KTHREADS.preemption.call_once(|| {
        installed = true;
        preemption
    });
    assert!(installed, "the kernel threads' preemption is already set");
}

/// How many threads exist: created, and not finished.
pub fn live() -> usize {
    KTHREADS.live.load(Ordering::SeqCst)
}

/// How many stacks are allocated.
pub fn stacks() -> usize {
    KTHREADS.stacks.load(Ordering::SeqCst)
}

/// [`with_per_cpu_variables`] for a thread, with interrupts disabled until
/// `f` returns, so that the thread is neither preempted nor moved to another
/// CPU meanwhile; nests. For the scheduler's entry points only (the policy's
/// check, the slice's end, the switch), which use the CPU's state inside and
/// return none of it (e.g., its ID), which the thread may leave at once; a
/// thread finds itself with [`current`]. After a switch (`stop`), it may go
/// on on another CPU: it no longer uses the variables.
fn with_this_cpu<F, R>(f: F) -> R
where
    F: FnOnce(&PerCpuVariables) -> R,
    R: 'static,
{
    let _no_preempt = NoPreempt::new();
    with_per_cpu_variables(f)
}

/// The running thread, if any: the CPU's slot, which [`Kthread::run`] sets
/// for the thread's run, read in one instruction, `mov reg, gs:[offset]`. So
/// it needs no guard: a preemption cannot split it, and a thread preempted
/// before it resumes on a CPU whose slot holds that same thread. The thread
/// reads itself, whichever CPU it is on.
fn current() -> Option<StackRef> {
    let control: usize;
    // Safety: in kernel mode, GS's base is the CPU's variables
    // (`per_cpu::install`), whose slot is a `usize` at this offset; a load.
    unsafe {
        core::arch::asm!(
            "mov {control}, gs:[{offset}]",
            control = out(reg) control,
            offset = const { PerCpuVariablesAsm::kthread_offset() },
            options(nostack, preserves_flags, readonly),
        );
    }
    NonNull::new(core::ptr::with_exposed_provenance_mut(control)).map(StackRef)
}

/// Whether the calling code runs in a thread.
pub fn in_kthread() -> bool {
    current().is_some()
}

/// The running thread's word, which the kernel broker keeps for code deeper
/// in its call stack (see [`set_local`]); only the thread reads or writes it,
/// so it goes with the thread from CPU to CPU. Zero in a new thread, and
/// outside a thread.
pub fn local() -> usize {
    current().map_or(0, |running| running.control().local.get())
}

/// Sets the running thread's word (see [`local`]).
///
/// # Panics
///
/// Outside a thread.
///
/// # Safety
///
/// The word has one user, the kernel broker's `serving`, which dereferences
/// what it holds: no other code may set it.
pub unsafe fn set_local(word: usize) {
    current()
        .expect("a kernel thread runs")
        .control()
        .local
        .set(word);
}

/// A [`NoPreempt`] begins, interrupts having been `enabled`: counts it among
/// the running thread's sections, if a thread runs (whether one does), so that
/// only the last of them to end enables interrupts again, in whatever order
/// they end. Other code needs no count: only threads run with interrupts
/// enabled. Until threads may exist ([`init`]), the boot CPU's variables may
/// not be installed: it does not look.
pub(crate) fn begin_section(enabled: bool) -> bool {
    if KTHREADS.base_table.get().is_none() {
        return false;
    }
    let Some(running) = current() else {
        return false;
    };
    let sections = &running.control().sections;
    let mut counted = sections.get();
    counted.begin(enabled);
    sections.set(counted);
    true
}

/// A section that [`begin_section`] counted ends: whether to enable
/// interrupts again.
pub(crate) fn end_section() -> bool {
    let running = current().expect("a thread's section ends in the thread");
    let sections = &running.control().sections;
    let mut counted = sections.get();
    let enable = counted.end();
    sections.set(counted);
    enable
}

/// A thread's stack, which its owner allocates and frees in the kernel: a
/// block of the page allocator, an unmapped guard page under it, the control
/// block at its top. Unmapping the guard flushes only this CPU's translation
/// of it, so each CPU flushes it before it first runs on the stack
/// ([`Kthread::run`]); mapping it back needs none.
pub struct Stack(StackRef);

// Safety: a stack, and the stopped thread on it, are touched only through
// their owner, which the kernel moves between CPUs; a stopped thread holds
// nothing tied to a CPU.
unsafe impl Send for Stack {}

impl Stack {
    /// A new stack; `None` if the page allocator has no block for it.
    ///
    /// # Panics
    ///
    /// In a thread.
    pub fn allocate() -> Option<Self> {
        assert!(!in_kthread(), "a kernel thread allocates a stack");
        let base = crate::VmKernel::mem_allocate_pages(STACK_ORDER)?;
        // Safety: the block's first page, unused, which `drop` maps back
        // before it frees the block.
        unsafe { per_cpu::unmap_guard(base_table(), base as usize) };
        #[expect(
            clippy::cast_ptr_alignment,
            reason = "the block is page-aligned, and `CONTROL_OFFSET` a multiple of 64"
        )]
        let control = NonNull::new(base.wrapping_add(CONTROL_OFFSET).cast::<Control>())
            .expect("an allocated block is not at address zero");
        // Safety: in the block, aligned (see above), and unused.
        unsafe {
            control.write(Control {
                rsp: Cell::new(0),
                state: Cell::new(State::Finished),
                work: Cell::new(None),
                deadline: Cell::new(None),
                local: Cell::new(0),
                sections: Cell::new(Sections::default()),
                waker: Arc::default(),
                slept_after: Cell::new(0),
                flushed: AtomicU64::new(crate::cpu::current().bit()),
            });
        }
        KTHREADS.stacks.fetch_add(1, Ordering::SeqCst);
        Some(Self(StackRef(control)))
    }
}

impl Drop for Stack {
    /// # Panics
    ///
    /// If a thread on it has not finished, whose frames would leak.
    fn drop(&mut self) {
        let stack = self.0;
        assert_eq!(
            stack.control().state.get(),
            State::Finished,
            "a kernel thread that did not finish was dropped"
        );
        debug_assert!(!in_kthread(), "a kernel thread frees a stack");
        let base = stack.base();
        // Safety: no thread is on it; the control block's last use.
        unsafe { core::ptr::drop_in_place(stack.0.as_ptr()) };
        // Safety: the guard `allocate` unmapped, of this block.
        unsafe { per_cpu::restore_guard(base_table(), base) };
        // Safety: allocated with this order, and no longer used.
        unsafe { crate::VmKernel::mem_free_pages(base as *mut u8, STACK_ORDER) };
        KTHREADS.stacks.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A thread that does not run: new, asleep, or preempted.
#[must_use = "a thread must be run until it finishes"]
pub struct Kthread(Stack);

/// How a thread's run ended.
#[must_use = "a thread that did not finish must be run again"]
pub enum Ran {
    Finished(Stack),
    Slept(Kthread),
    Preempted(Kthread),
}

impl Kthread {
    /// A thread to run `work` on `stack`.
    pub fn new(stack: Stack, work: Box<dyn FnOnce() + Send>) -> Self {
        let control = stack.0.control();
        debug_assert_eq!(
            Arc::strong_count(&control.waker),
            1,
            "a kernel thread's wait queue registration outlived it"
        );
        control.work.set(Some(work));
        control.deadline.set(None);
        control.local.set(0);
        control.sections.set(Sections::default());
        control.state.set(State::New);
        control.rsp.set(initial_rsp(stack.0.0.as_ptr() as usize));
        KTHREADS.live.fetch_add(1, Ordering::SeqCst);
        Self(stack)
    }

    /// Whether it may run: new, preempted, or asleep and woken or past its
    /// deadline.
    pub fn is_due(&self, now: Instant) -> bool {
        let control = self.0.0.control();
        match control.state.get() {
            State::Slept => {
                control.waker.wakes() != control.slept_after.get()
                    || control
                        .deadline
                        .get()
                        .is_some_and(|deadline| now >= deadline)
            }
            State::New | State::Preempted => true,
            State::Running | State::Finished => unreachable!("a thread that runs has no handle"),
        }
    }

    /// While it sleeps, when it is due without a wake, if ever.
    pub fn deadline(&self) -> Option<Instant> {
        let control = self.0.0.control();
        (control.state.get() == State::Slept)
            .then(|| control.deadline.get())
            .flatten()
    }

    /// Runs it on this CPU until it finishes, sleeps, or is preempted, with
    /// `slice_end` as its slice end, which it returns as the run left it
    /// (e.g., as the check that preempted it shortened it, see [`Check`]).
    /// With one, it first has the policy arm what preempts the run past it, on
    /// this CPU ([`Preemption::start`]).
    ///
    /// # Panics
    ///
    /// In a thread or a user thread's run, or with interrupts enabled.
    pub fn run(self, slice_end: Option<Instant>) -> (Ran, Option<Instant>) {
        let stack = self.0;
        assert!(
            !x86_64::instructions::interrupts::are_enabled(),
            "a thread is run with interrupts disabled"
        );
        let control = stack.0.control();
        let runner_rsp = with_per_cpu_variables(|pcv| {
            let (cpu, runner_rsp) =
                pcv.set_kthread(stack.0.0.as_ptr().expose_provenance(), slice_end);
            let cpu = cpu.bit();
            if control.flushed.fetch_or(cpu, Ordering::Relaxed) & cpu == 0 {
                x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(stack.0.base() as u64));
            }
            if let (Some(preemption), Some(slice_end)) = (KTHREADS.preemption.get(), slice_end) {
                preemption.start(slice_end);
            }
            runner_rsp
        });
        control.state.set(State::Running);
        // Safety: the thread's stack pointer, initial or saved by `switch`, on
        // its stack, which `stack` keeps allocated.
        unsafe { switch(runner_rsp, control.rsp.get()) };
        let slice_end = with_per_cpu_variables(PerCpuVariables::clear_kthread);
        let ran = match control.state.get() {
            State::Slept => Ran::Slept(Self(stack)),
            State::Preempted => Ran::Preempted(Self(stack)),
            State::Finished => {
                KTHREADS.live.fetch_sub(1, Ordering::SeqCst);
                Ran::Finished(stack)
            }
            State::New | State::Running => unreachable!("a thread stopped running"),
        };
        (ran, slice_end)
    }
}

/// A safe point of the running thread, which holds nothing others wait for:
/// the policy may preempt it here. In a section with interrupts disabled
/// (e.g., holding a kernel-grade lock), or outside a thread, which runs with
/// them disabled, it defers: the run ends at a later one, or at an interrupt.
pub fn safe_point() {
    if !x86_64::instructions::interrupts::are_enabled() {
        return;
    }
    with_this_cpu(|pcv| {
        if decide(pcv, Point::SafePoint) {
            stop(State::Preempted, None);
        }
    });
}

/// Whether the running thread's run is due to end, as at a safe point, but
/// without preempting it (e.g., for a spin to stop). A due run stays due,
/// whether or not the thread then sleeps. Not where [`safe_point`] defers.
pub fn yield_due() -> bool {
    if !x86_64::instructions::interrupts::are_enabled() {
        return false;
    }
    with_this_cpu(|pcv| {
        let due = decide(pcv, Point::SafePoint);
        if due {
            end_slice(pcv);
        }
        due
    })
}

/// An interrupt of kernel code returns: checks the thread it interrupted, if
/// any, on that thread's stack.
pub(crate) fn interrupted() {
    with_per_cpu_variables(|pcv| {
        if current().is_some() && decide(pcv, Point::Interrupt) {
            stop(State::Preempted, None);
        }
    });
}

/// Asks the policy whether to preempt the running thread at `point`, on its
/// CPU's variables, `pcv`.
fn decide(pcv: &PerCpuVariables, point: Point) -> bool {
    let Some(preemption) = KTHREADS.preemption.get() else {
        return false;
    };
    debug_assert!(current().is_some(), "only a thread is checked");
    pcv.kthread.checking.set(true);
    let check = preemption.check(point, pcv.kthread.slice_end.get());
    pcv.kthread.checking.set(false);
    let (Check::Preempt(slice_end) | Check::Continue(slice_end)) = check;
    pcv.kthread.slice_end.set(slice_end);
    matches!(check, Check::Preempt(_))
}

/// Has the policy end the running thread's slice, if one runs on `pcv`'s
/// CPU outside a check, which takes the marks itself.
fn end_slice(pcv: &PerCpuVariables) {
    let Some(preemption) = KTHREADS.preemption.get() else {
        return;
    };
    if current().is_some() && !pcv.kthread.checking.get() {
        let slice_end = preemption.end_slice(pcv.kthread.slice_end.get());
        pcv.kthread.slice_end.set(Some(slice_end));
    }
}

/// What threads sleep on; a wake marks only its waiters. Its lock is
/// kernel-grade.
pub struct WaitQueue(Waiters);

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self(Waiters::new())
    }

    /// Registers the calling thread: a wake from now on ends its sleep. It
    /// may also be registered elsewhere, even here, e.g., by a lock its check
    /// takes, which sleeps: each registration has an entry of its own, and
    /// ends a sleep for the wakes after it, whichever queue's, erasing none.
    ///
    /// # Panics
    ///
    /// Outside a thread.
    pub fn prepare(&self) -> Prepared<'_> {
        let waker = current()
            .expect("only a kernel thread waits on a queue")
            .control()
            .waker
            .clone();
        Prepared {
            registration: self.0.register(waker),
            _thread: PhantomData,
        }
    }

    /// Wakes up to `n` waiters, oldest first; how many. If any, has a CPU
    /// look at them ([`crate::cpu::wake_idle_or_resched`]): if it is this one,
    /// its thread's run ends its slice now.
    pub fn wake(&self, n: usize) -> usize {
        let woken = self.0.wake(n);
        if woken != 0 {
            with_this_cpu(|pcv| {
                if crate::cpu::wake_idle_or_resched() {
                    end_slice(pcv);
                }
            });
        }
        woken
    }
}

/// A thread's registration on a [`WaitQueue`], dropped before the thread
/// finishes: later threads on its stack take its waker over. Not `Send`: only
/// the thread it registered may sleep with it.
#[must_use = "check the condition, then sleep"]
pub struct Prepared<'q> {
    registration: Registration<'q>,
    _thread: PhantomData<*const ()>,
}

// `Prepared` is not `Send`: if it were, the call below would be ambiguous.
const _: fn() = || {
    trait AmbiguousIfSend<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    struct IfSend;
    impl<T: ?Sized + Send> AmbiguousIfSend<IfSend> for T {}
    let _ = <Prepared<'static> as AmbiguousIfSend<_>>::some_item;
};

impl Prepared<'_> {
    /// Sleeps until woken, or until `deadline`, unless woken since
    /// [`WaitQueue::prepare`].
    ///
    /// # Panics
    ///
    /// In a section with interrupts disabled (e.g., holding a kernel-grade
    /// lock), which the thread would hold asleep.
    pub fn sleep(self, deadline: Option<Instant>) {
        assert!(
            x86_64::instructions::interrupts::are_enabled(),
            "a kernel thread sleeps in a section with interrupts disabled"
        );
        let registration = &self.registration;
        if !registration.is_woken() {
            current()
                .expect("a registered kernel thread sleeps")
                .control()
                .slept_after
                .set(registration.seen);
            stop(State::Slept, deadline);
        }
    }
}

impl crate::RawMutex {
    /// A kernel thread sleeps on the lock's queue (see [`crate::RawMutex`]),
    /// warning with `started`'s clock.
    pub(crate) fn sleep(
        &self,
        val: u32,
        started: Option<&'static crate::VmKernel>,
    ) -> Result<(), ImmediatelyWokenUp> {
        // The boot self-check's threads run before the clock may be read.
        let mut warn_at = started.map(|platform| {
            let at = platform
                .now()
                .checked_add(crate::LOCK_WARNING)
                .expect("the clock is far from overflowing");
            (platform, at)
        });
        let mut slept = false;
        loop {
            let prepared = self.waiters.prepare();
            if self.underlying_atomic().load(Ordering::SeqCst) != val {
                return if slept {
                    Ok(())
                } else {
                    Err(ImmediatelyWokenUp)
                };
            }
            prepared.sleep(warn_at.map(|(_, at)| at));
            slept = true;
            match warn_at {
                Some((platform, at)) if platform.now() >= at => {
                    litebox_util_log::warn!(
                        lock:? = core::ptr::from_ref(self),
                        waited:? = crate::LOCK_WARNING;
                        "still sleeping for a lock: a deadlock? (see `RawMutex`)"
                    );
                    warn_at = None;
                }
                _ => return Ok(()),
            }
        }
    }
}

pub(crate) struct KthreadCpu {
    /// Its runner's stack pointer, while it runs one.
    pub(crate) runner_rsp: Cell<usize>,
    pub(crate) slice_end: Cell<Option<Instant>>,
    /// The policy checks the running thread.
    checking: Cell<bool>,
}

impl KthreadCpu {
    pub(crate) const fn new() -> Self {
        Self {
            runner_rsp: Cell::new(0),
            slice_end: Cell::new(None),
            checking: Cell::new(false),
        }
    }
}

/// A thread's control block, at the top of its stack: touched by the CPU
/// that runs the thread, else by the holder of its handle.
struct Control {
    /// The thread's stack pointer, while it does not run.
    rsp: Cell<usize>,
    state: Cell<State>,
    work: Cell<Option<Box<dyn FnOnce() + Send>>>,
    /// While it sleeps, when it is due without a wake.
    deadline: Cell<Option<Instant>>,
    local: Cell<usize>,
    /// Its sections with interrupts disabled (see [`begin_section`]).
    sections: Cell<Sections>,
    /// The stack's, for each of its threads in turn.
    waker: Arc<Waker>,
    /// While it sleeps, its waker's wakes before the registration it sleeps
    /// with: one more ends the sleep.
    slept_after: Cell<u64>,
    /// Bit `i`: CPU `i` flushed the guard (see [`Stack`]).
    flushed: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    New,
    Running,
    Slept,
    Preempted,
    /// Or none was created on the stack yet.
    Finished,
}

/// A stack, by its control block: not an owner.
#[derive(Clone, Copy)]
struct StackRef(NonNull<Control>);

impl StackRef {
    fn control(&self) -> &Control {
        // Safety: allocated, with its control block, as long as its `Stack`
        // is.
        unsafe { self.0.as_ref() }
    }

    /// The block's start: the guard page.
    fn base(self) -> usize {
        self.0.as_ptr() as usize - CONTROL_OFFSET
    }
}

/// A stack's threads' wakes, counted: each registration ends a sleep for
/// those after it, erasing none (see [`WaitQueue::prepare`]).
#[derive(Default)]
struct Waker {
    wakes: AtomicU64,
}

impl Waker {
    fn wakes(&self) -> u64 {
        self.wakes.load(Ordering::Acquire)
    }

    fn wake(&self) {
        // After what the thread waits for happened, which it then sees.
        self.wakes.fetch_add(1, Ordering::Release);
    }
}

/// Switches from the running thread to its runner, with interrupts disabled,
/// until a CPU runs it again. That may be another CPU, so a caller inside
/// [`with_this_cpu`] stops last, using its variables no more.
fn stop(state: State, deadline: Option<Instant>) {
    with_this_cpu(|pcv| {
        let stack = current().expect("only a kernel thread stops");
        let control = stack.control();
        control.deadline.set(deadline);
        control.state.set(state);
        // Safety: the runner's stack pointer was saved by `switch` in
        // `Kthread::run`, whose stack waits there; this thread's stack stays
        // allocated until it finishes.
        unsafe { switch(control.rsp.as_ptr(), pcv.kthread.runner_rsp.get()) };
    });
}

/// A [`WaitQueue`]'s waiters, an entry per registration, oldest first, behind
/// a kernel-grade lock.
struct Waiters {
    queue: KernelMutex<Entries>,
}

struct Entries {
    /// The next registration's ID.
    next: u64,
    /// Each registration's ID, and its waiter.
    waiting: VecDeque<(u64, Arc<Waker>)>,
}

impl Waiters {
    const fn new() -> Self {
        Self {
            queue: KernelMutex::new(Entries {
                next: 0,
                waiting: VecDeque::new(),
            }),
        }
    }

    /// Registers `waiter`, last, as of its wakes so far, read under the lock:
    /// only wakes before, whose effects the waiter's check sees, are not its.
    fn register(&self, waiter: Arc<Waker>) -> Registration<'_> {
        let mut queue = self.queue.lock();
        let id = queue.next;
        queue.next += 1;
        let seen = waiter.wakes();
        queue.waiting.push_back((id, waiter.clone()));
        Registration {
            waiters: self,
            waiter,
            seen,
            id,
        }
    }

    fn wake(&self, n: usize) -> usize {
        let mut queue = self.queue.lock();
        let woken = n.min(queue.waiting.len());
        for (_, waiter) in queue.waiting.drain(..woken) {
            waiter.wake();
        }
        woken
    }
}

/// A waiter's registration: its drop removes its entry, unless a wake did.
struct Registration<'q> {
    waiters: &'q Waiters,
    waiter: Arc<Waker>,
    /// The waiter's wakes as it registered.
    seen: u64,
    /// Its entry's ID.
    id: u64,
}

impl Registration<'_> {
    /// Whether a wake came since it registered: its own, or that of another
    /// registration of the thread's, which only ends a sleep early.
    fn is_woken(&self) -> bool {
        self.waiter.wakes() != self.seen
    }
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        let mut queue = self.waiters.queue.lock();
        if let Some(at) = queue.waiting.iter().position(|&(id, _)| id == self.id) {
            queue.waiting.remove(at);
        }
    }
}

/// A new thread's initial stack pointer, below `stack_top`, for `switch` to
/// pop: zeroed callee-saved registers, then `kthread_entry`, reached with a
/// 16-byte aligned stack, as after a call.
fn initial_rsp(stack_top: usize) -> usize {
    const REGISTERS: usize = 6;
    let rsp = stack_top - (REGISTERS + 3) * 8;
    debug_assert_eq!(rsp % 16, 8);
    let frame = rsp as *mut usize;
    // Safety: below the control block, in the new thread's stack, unused.
    unsafe {
        for register in 0..REGISTERS {
            frame.add(register).write(0);
        }
        frame
            .add(REGISTERS)
            .write(kthread_entry as *const () as usize);
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

#[unsafe(naked)]
unsafe extern "C" fn kthread_entry() -> ! {
    core::arch::naked_asm!("call {main}", "ud2", main = sym kthread_main);
}

extern "C" fn kthread_main() -> ! {
    let stack = current().expect("a kernel thread runs");
    let work = stack.control().work.take().expect("the thread's work");
    x86_64::instructions::interrupts::enable();
    work();
    stop(State::Finished, None);
    unreachable!("a finished kernel thread ran again");
}

/// Debug builds: a stack's guard is unmapped as it is allocated, and mapped
/// back as it is freed.
#[cfg(debug_assertions)]
pub(crate) fn self_check() {
    use x86_64::structures::paging::Page;
    let guarded = |base: usize| {
        !base_table().is_present(Page::containing_address(x86_64::VirtAddr::new(base as u64)))
    };
    let stack = Stack::allocate().expect("a stack");
    let base = stack.0.base();
    assert!(guarded(base), "a new stack's guard is unmapped");
    assert_eq!(stacks(), 1);
    drop(stack);
    assert!(!guarded(base), "a freed stack's guard is mapped again");
    assert_eq!(stacks(), 0);
}

#[cfg(test)]
mod tests {
    use super::{Waiters, Waker};
    use alloc::sync::Arc;

    #[test]
    fn a_nested_registration_erases_no_wake() {
        let (outer, inner) = (Waiters::new(), Waiters::new());
        let waker = Arc::new(Waker::default());
        let registered = outer.register(waker.clone());
        assert_eq!(outer.wake(1), 1);
        // E.g., a lock the check takes, which sleeps, then gives up.
        drop(inner.register(waker));
        assert!(registered.is_woken(), "the wake before it stays");
    }

    /// As `a = q.prepare(); q.wake(1); b = q.prepare(); drop(a)` registers.
    #[test]
    fn cancelling_a_registration_removes_only_its_own_entry() {
        let waiters = Waiters::new();
        let waker = Arc::new(Waker::default());
        let a = waiters.register(waker.clone());
        assert_eq!(waiters.wake(1), 1);
        let b = waiters.register(waker);
        drop(a);
        assert_eq!(waiters.queue.lock().waiting.len(), 1, "b's entry stays");
        assert!(!b.is_woken());
        assert_eq!(waiters.wake(1), 1);
        assert!(b.is_woken());
    }

    #[test]
    fn a_registration_ends_a_sleep_only_for_wakes_after_it() {
        let waiters = Waiters::new();
        let waker = Arc::new(Waker::default());
        let first = waiters.register(waker.clone());
        assert_eq!(waiters.wake(1), 1);
        assert!(first.is_woken());
        drop(first);
        let second = waiters.register(waker);
        assert!(!second.is_woken(), "the wake before it is not its");
        assert_eq!(waiters.wake(1), 1);
        assert!(second.is_woken());
    }
}
