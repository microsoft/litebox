// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Preemptible kernel threads ([`Kthread`]) on stacks of their own
//! ([`Stack`]), which the kernel's scheduler runs and preempts
//! ([`Preemption`]).
//!
//! A thread runs with interrupts enabled but in the kernel services it enters
//! ([`NoPreempt`]), which share only kernel-grade state with the kernel. It
//! is preempted only with interrupts enabled (at its safe points and as its
//! interrupts return), so never holding a kernel-grade lock; there its frames
//! may move to another CPU, so they hold nothing tied to a CPU. It touches
//! user memory only through pinned pages.
//!
//! To sleep, a thread registers on a queue ([`WaitQueue::prepare`]), checks
//! what it waits for, and sleeps unless it happened ([`Prepared::sleep`]).

use crate::Instant;
use crate::mm::MemoryProvider as _;
use crate::per_cpu::{self, with_per_cpu_variables};
use crate::preempt::NoPreempt;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::Cell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use litebox_common_linux::PAGE_SIZE;

#[cfg(test)]
mod tests;

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
    #[cfg(debug_assertions)]
    fail_next_stack: AtomicBool,
}

static KTHREADS: Kthreads = Kthreads {
    live: AtomicUsize::new(0),
    stacks: AtomicUsize::new(0),
    base_table: spin::Once::new(),
    preemption: spin::Once::new(),
    #[cfg(debug_assertions)]
    fail_next_stack: AtomicBool::new(false),
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

/// What [`Preemption::check`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    Preempt,
    /// The thread runs on, its slice ending then, if ever.
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

/// Debug builds, for tests: the next [`Stack::allocate`] fails.
#[cfg(debug_assertions)]
pub fn fail_next_stack() {
    KTHREADS.fail_next_stack.store(true, Ordering::SeqCst);
}

/// Whether the calling code runs in a thread.
pub fn in_kthread() -> bool {
    let _no_preempt = NoPreempt::new();
    with_per_cpu_variables(|pcv| pcv.kthread.running.get().is_some())
}

/// The running thread's word, which the kernel broker keeps for code deeper
/// in its call stack (see [`set_local`]); only the thread reads or writes it,
/// so it goes with the thread from CPU to CPU. Zero in a new thread, and
/// outside a thread.
pub fn local() -> usize {
    let _no_preempt = NoPreempt::new();
    with_per_cpu_variables(|pcv| pcv.kthread.running.get())
        .map_or(0, |running| running.control().local.get())
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
    let _no_preempt = NoPreempt::new();
    with_per_cpu_variables(|pcv| pcv.kthread.running.get())
        .expect("a kernel thread runs")
        .control()
        .local
        .set(word);
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
    /// In debug builds, in a thread.
    pub fn allocate() -> Option<Self> {
        debug_assert!(!in_kthread(), "a kernel thread allocates a stack");
        #[cfg(debug_assertions)]
        if KTHREADS.fail_next_stack.load(Ordering::Relaxed)
            && KTHREADS.fail_next_stack.swap(false, Ordering::SeqCst)
        {
            return None;
        }
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
                waker: Arc::default(),
                flushed: AtomicU64::new(crate::cpu::current().bit()),
                #[cfg(debug_assertions)]
                away_from: Cell::new(None),
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
        control.state.set(State::New);
        control.rsp.set(initial_rsp(stack.0.0.as_ptr() as usize));
        KTHREADS.live.fetch_add(1, Ordering::SeqCst);
        Self(stack)
    }

    /// Whether it may run: new, preempted, or asleep and woken or past its
    /// deadline.
    pub fn is_due(&self, now: Instant) -> bool {
        let control = self.0.0.control();
        #[cfg(debug_assertions)]
        if control.away_from.get() == Some(crate::cpu::current()) {
            return false;
        }
        match control.state.get() {
            State::Slept => {
                control.waker.is_woken()
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
    /// `slice_end` as its slice end, which it returns as the run left it.
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
            assert!(
                !pcv.asm.is_in_user() && pcv.kthread.running.get().is_none(),
                "a thread runs outside other threads' runs"
            );
            let cpu = pcv.cpu.bit();
            if control.flushed.fetch_or(cpu, Ordering::Relaxed) & cpu == 0 {
                x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(stack.0.base() as u64));
            }
            pcv.kthread.running.set(Some(stack.0));
            pcv.kthread.slice_end.set(slice_end);
            pcv.kthread.runner_rsp.as_ptr()
        });
        control.state.set(State::Running);
        // Safety: the thread's stack pointer, initial or saved by `switch`, on
        // its stack, which `stack` keeps allocated.
        unsafe { switch(runner_rsp, control.rsp.get()) };
        let slice_end = with_per_cpu_variables(|pcv| {
            pcv.kthread.running.set(None);
            pcv.kthread.slice_end.take()
        });
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
/// the policy may preempt it here.
pub fn safe_point() {
    debug_assert!(
        x86_64::instructions::interrupts::are_enabled(),
        "a thread's safe point is outside kernel services"
    );
    let _no_preempt = NoPreempt::new();
    if decide(Point::SafePoint) {
        stop(State::Preempted, None);
    }
}

/// Whether the running thread's run is due to end, as at a safe point, but
/// without preempting it (e.g., for a spin to stop). A due run stays due,
/// whether or not the thread then sleeps.
pub fn yield_due() -> bool {
    debug_assert!(
        x86_64::instructions::interrupts::are_enabled(),
        "a thread's safe point is outside kernel services"
    );
    let _no_preempt = NoPreempt::new();
    let due = decide(Point::SafePoint);
    if due {
        end_slice();
    }
    due
}

/// An interrupt of kernel code returns: checks the thread it interrupted, if
/// any, on that thread's stack.
pub(crate) fn interrupted() {
    if with_per_cpu_variables(|pcv| pcv.kthread.running.get().is_some()) && decide(Point::Interrupt)
    {
        stop(State::Preempted, None);
    }
}

/// Whether the policy preempts the running thread at `point`.
fn decide(point: Point) -> bool {
    let Some(preemption) = KTHREADS.preemption.get() else {
        return false;
    };
    let slice_end = with_per_cpu_variables(|pcv| {
        debug_assert!(
            pcv.kthread.running.get().is_some(),
            "only a thread is checked"
        );
        pcv.kthread.checking.set(true);
        pcv.kthread.slice_end.get()
    });
    let check = preemption.check(point, slice_end);
    with_per_cpu_variables(|pcv| {
        pcv.kthread.checking.set(false);
        if let Check::Continue(slice_end) = check {
            pcv.kthread.slice_end.set(slice_end);
        }
    });
    check == Check::Preempt
}

/// Has the policy end the running thread's slice, if one runs outside a
/// check, which takes the marks itself.
fn end_slice() {
    let _no_preempt = NoPreempt::new();
    let Some(preemption) = KTHREADS.preemption.get() else {
        return;
    };
    let slice_end = with_per_cpu_variables(|pcv| {
        (pcv.kthread.running.get().is_some() && !pcv.kthread.checking.get())
            .then(|| pcv.kthread.slice_end.get())
    });
    if let Some(slice_end) = slice_end {
        let slice_end = preemption.end_slice(slice_end);
        with_per_cpu_variables(|pcv| pcv.kthread.slice_end.set(Some(slice_end)));
    }
}

/// What threads sleep on; a wake marks only its waiters. Its lock is
/// kernel-grade.
pub struct WaitQueue(Waiters<Waker>);

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self(Waiters::new())
    }

    /// Registers the calling thread: a wake from now on ends its sleep.
    ///
    /// # Panics
    ///
    /// Outside a thread, or, in debug builds, registered already.
    pub fn prepare(&self) -> Prepared<'_> {
        let _no_preempt = NoPreempt::new();
        let waker = with_per_cpu_variables(|pcv| pcv.kthread.running.get())
            .expect("only a kernel thread waits on a queue")
            .control()
            .waker
            .clone();
        #[cfg(debug_assertions)]
        {
            assert!(
                !waker.registered.load(Ordering::Relaxed),
                "a kernel thread waits on one queue at a time"
            );
            waker.registered.store(true, Ordering::Relaxed);
        }
        Prepared {
            registration: Some(self.0.register(waker)),
        }
    }

    /// Wakes up to `n` waiters, oldest first; how many. If any, has a CPU
    /// look at them ([`crate::cpu::wake_idle_or_resched`]): if it is this one,
    /// its thread's run ends its slice now.
    pub fn wake(&self, n: usize) -> usize {
        let _no_preempt = NoPreempt::new();
        let woken = self.0.wake(n);
        if woken != 0 && crate::cpu::wake_idle_or_resched() {
            end_slice();
        }
        woken
    }

    /// Debug builds: holds the queue's lock, interrupts disabled, while
    /// `holding` returns true.
    #[cfg(debug_assertions)]
    pub fn hold_while(&self, mut holding: impl FnMut() -> bool) {
        let _no_preempt = NoPreempt::new();
        let _queue = self.0.queue.lock();
        while holding() {
            core::hint::spin_loop();
        }
    }
}

/// A thread's registration on a [`WaitQueue`], dropped before the thread
/// finishes: later threads on its stack take its waker over.
#[must_use = "check the condition, then sleep"]
pub struct Prepared<'q> {
    registration: Option<Registration<'q, Waker>>,
}

impl Prepared<'_> {
    /// Sleeps until woken, or until `deadline`, unless woken since
    /// [`WaitQueue::prepare`].
    pub fn sleep(self, deadline: Option<Instant>) {
        debug_assert!(
            x86_64::instructions::interrupts::are_enabled(),
            "a kernel thread sleeps outside kernel services"
        );
        let _no_preempt = NoPreempt::new();
        let woken = self
            .registration
            .as_ref()
            .is_some_and(|registration| registration.waiter().is_woken());
        if !woken {
            stop(State::Slept, deadline);
        }
    }
}

impl Drop for Prepared<'_> {
    fn drop(&mut self) {
        let _no_preempt = NoPreempt::new();
        let registration = self.registration.take();
        #[cfg(debug_assertions)]
        if let Some(registration) = &registration {
            registration
                .waiter()
                .registered
                .store(false, Ordering::Relaxed);
        }
        drop(registration);
    }
}

pub(crate) struct KthreadCpu {
    running: Cell<Option<StackRef>>,
    /// Its runner's stack pointer, while it runs one.
    runner_rsp: Cell<usize>,
    slice_end: Cell<Option<Instant>>,
    /// The policy checks the running thread.
    checking: Cell<bool>,
}

impl KthreadCpu {
    pub(crate) const fn new() -> Self {
        Self {
            running: Cell::new(None),
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
    /// The thread's word (see [`local`]).
    local: Cell<usize>,
    /// The stack's, for each of its threads in turn.
    waker: Arc<Waker>,
    /// Bit `i`: CPU `i` flushed the guard (see [`Stack`]).
    flushed: AtomicU64,
    /// Debug builds: the CPU the thread is not due on (see [`migrate`]).
    #[cfg(debug_assertions)]
    away_from: Cell<Option<crate::cpu::CpuId>>,
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

#[derive(Default)]
struct Waker {
    woken: AtomicBool,
    /// Debug builds: the thread waits on a queue.
    #[cfg(debug_assertions)]
    registered: AtomicBool,
}

impl Waker {
    fn is_woken(&self) -> bool {
        self.woken.load(Ordering::Acquire)
    }
}

impl Wake for Waker {
    fn clear(&self) {
        self.woken.store(false, Ordering::Relaxed);
    }

    fn wake(&self) {
        // After what the thread waits for happened, which it then sees.
        self.woken.store(true, Ordering::Release);
    }
}

/// Switches from the running thread to its runner, until a CPU runs it again.
/// With interrupts disabled, which the code that disabled them enables again,
/// on whichever CPU.
fn stop(state: State, deadline: Option<Instant>) {
    let (stack, runner_rsp) = with_per_cpu_variables(|pcv| {
        debug_assert!(
            pcv.tls.get().is_null(),
            "a kernel thread stops with a thread-local storage pointer, which is the CPU's"
        );
        (
            pcv.kthread
                .running
                .get()
                .expect("only a kernel thread stops"),
            pcv.kthread.runner_rsp.get(),
        )
    });
    let control = stack.control();
    control.deadline.set(deadline);
    control.state.set(state);
    // Safety: `runner_rsp` was saved by `switch` in `Kthread::run`, whose
    // stack waits there; this thread's stack stays allocated until it
    // finishes.
    unsafe { switch(control.rsp.as_ptr(), runner_rsp) };
}

/// Debug builds, for tests: moves the running thread to another CPU, and
/// checks that that CPU flushed the stack's guard.
///
/// # Panics
///
/// Outside a thread, or on a failed check.
#[cfg(debug_assertions)]
pub fn migrate() {
    let _no_preempt = NoPreempt::new();
    let (stack, cpu) = with_per_cpu_variables(|pcv| {
        let stack = pcv
            .kthread
            .running
            .get()
            .expect("only a kernel thread migrates");
        (stack, pcv.cpu)
    });
    let control = stack.control();
    control.flushed.store(cpu.bit(), Ordering::Relaxed);
    control.away_from.set(Some(cpu));
    control.waker.wake();
    crate::cpu::wake_idle(cpu);
    stop(State::Slept, None);
    control.away_from.set(None);
    let now = crate::cpu::current();
    assert_ne!(now, cpu, "a migrating kernel thread ran again on its CPU");
    assert!(
        control.flushed.load(Ordering::Relaxed) & now.bit() != 0,
        "a migrated kernel thread's CPU flushed its stack's guard"
    );
}

/// What a [`Waiters`] queue wakes: a thread's [`Waker`], or a host test's.
trait Wake {
    /// Forgets earlier wakes.
    fn clear(&self);
    fn wake(&self);
}

/// A [`WaitQueue`]'s waiters, oldest first; its lock taken with interrupts
/// disabled.
struct Waiters<W> {
    queue: spin::Mutex<VecDeque<Arc<W>>>,
}

impl<W: Wake> Waiters<W> {
    const fn new() -> Self {
        Self {
            queue: spin::Mutex::new(VecDeque::new()),
        }
    }

    /// Registers `waiter`, last. The clear, under the lock, erases only wakes
    /// before it, whose effects the waiter's check sees.
    fn register(&self, waiter: Arc<W>) -> Registration<'_, W> {
        crate::preempt::debug_assert_disabled();
        let mut queue = self.queue.lock();
        waiter.clear();
        queue.push_back(waiter.clone());
        Registration {
            waiters: self,
            waiter,
        }
    }

    fn wake(&self, n: usize) -> usize {
        crate::preempt::debug_assert_disabled();
        let mut queue = self.queue.lock();
        let woken = n.min(queue.len());
        for waiter in queue.drain(..woken) {
            waiter.wake();
        }
        woken
    }
}

/// A waiter's registration: its drop unregisters it, unless a wake did.
struct Registration<'q, W> {
    waiters: &'q Waiters<W>,
    waiter: Arc<W>,
}

impl<W> Registration<'_, W> {
    fn waiter(&self) -> &W {
        &self.waiter
    }
}

impl<W> Drop for Registration<'_, W> {
    fn drop(&mut self) {
        crate::preempt::debug_assert_disabled();
        let mut queue = self.waiters.queue.lock();
        if let Some(at) = queue
            .iter()
            .position(|waiter| Arc::ptr_eq(waiter, &self.waiter))
        {
            queue.remove(at);
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
    let stack =
        with_per_cpu_variables(|pcv| pcv.kthread.running.get()).expect("a kernel thread runs");
    let work = stack.control().work.take().expect("the thread's work");
    x86_64::instructions::interrupts::enable();
    work();
    let _no_preempt = NoPreempt::new();
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
