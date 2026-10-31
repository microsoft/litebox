// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Each CPU's worker: kernel work on a second kernel stack, which can
//! [`suspend`] partway (e.g., to wait for a device) while the kernel runs
//! user threads, and be resumed later, by the same CPU. These functions use
//! the calling CPU's.
//!
//! Cooperative: the work runs, with interrupts disabled, until it finishes or
//! suspends. It touches user memory only through pinned pages
//! ([`crate::PinnedUserPages`]), never at user addresses, whose kernel faults
//! only a thread's run handles (see [`crate::run_thread_ref`]): so it runs in
//! whichever address space is current, and its resumer need restore none.
//!
//! It must not suspend holding a lock that anything but work may take: its
//! CPU, spinning for it, would never resume it. The broker holds some across
//! a suspension (e.g., an open file's, across a console write), which only
//! requests take (closing a file takes none). So a CPU spinning for one
//! ([`crate::RawMutex`]) runs its own work, not suspended; and a work must not
//! wait for one while holding a lock that anything but work takes (the
//! holder's CPU, spinning for that, would never resume it), and works on
//! several CPUs must take such locks in one order, as a resumed work may take
//! another holding one (broker rules). Only a CPU waiting for a process's
//! claim (in the shim), which a work spinning for one may hold, must resume
//! its own work meanwhile.
//!
//! A device's interrupt may be for a suspended work: [`interrupt_suspended`]
//! has the CPUs whose work suspended enter the kernel, to resume it; but not
//! one whose new work has yet to suspend.

use crate::Instant;
use crate::cpu::{self, CpuId};
use crate::per_cpu::with_per_cpu_variables;
use alloc::boxed::Box;
use core::cell::Cell;
use litebox_common_linux::PAGE_SIZE;

/// At least the CPU's kernel stack; with the guard page, a power of two, which
/// the allocator would round up to anyway.
const STACK_SIZE: usize =
    (crate::per_cpu::KERNEL_STACK_SIZE + PAGE_SIZE).next_power_of_two() - PAGE_SIZE;

/// The worker's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// No work: [`start`] some.
    Idle,
    /// Its work runs (only seen from the work itself).
    Running,
    /// Its work suspended; resume it once something may have changed (an
    /// interrupt), or once `wake` passes.
    Suspended { wake: Option<Instant> },
}

/// How [`start`] or [`resume`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ran {
    Finished,
    Suspended,
}

/// Per-CPU.
pub(crate) struct Worker {
    /// Zero until the stack is allocated, at the first [`start`].
    stack_top: Cell<usize>,
    /// The work's saved stack pointer, while not running.
    rsp: Cell<usize>,
    /// The resumer's saved stack pointer, while the work runs.
    resumer_rsp: Cell<usize>,
    state: Cell<State>,
    work: Cell<Option<Box<dyn FnOnce()>>>,
}

impl Worker {
    pub(crate) const fn new() -> Self {
        Self {
            stack_top: Cell::new(0),
            rsp: Cell::new(0),
            resumer_rsp: Cell::new(0),
            state: Cell::new(State::Idle),
            work: Cell::new(None),
        }
    }
}

/// The worker's state.
pub fn state() -> State {
    with_per_cpu_variables(|pcv| pcv.worker.state.get())
}

/// Sends the wake IPI ([`cpu::Ipi::Wake`]) to the CPUs whose work suspended,
/// from its first suspension until it finishes (also while resumed), busy or
/// idle, but `except` (e.g., the one a device interrupts, which needs none):
/// one running a thread enters the kernel, which may then resume its worker
/// (e.g., for what a device's interrupt changed). Not those whose new work
/// has yet to suspend. No locks, no per-CPU data: usable in interrupt
/// handlers.
pub fn interrupt_suspended(except: CpuId) {
    cpu::interrupt_mask(cpu::suspended_mask() & !except.bit());
}

/// Runs `work` on the worker until it finishes or [`suspend`]s.
///
/// # Panics
///
/// Unless the worker is [`State::Idle`].
pub fn start(platform: &crate::VmKernel, work: Box<dyn FnOnce()>) -> Ran {
    with_per_cpu_variables(|pcv| {
        let worker = &pcv.worker;
        assert_eq!(worker.state.get(), State::Idle, "the worker is busy");
        if worker.stack_top.get() == 0 {
            worker
                .stack_top
                .set(platform.allocate_worker_stack(STACK_SIZE));
        }
        worker.work.set(Some(work));
        worker.rsp.set(initial_rsp(worker.stack_top.get()));
    });
    switch_to_work()
}

/// Resumes the worker's suspended work, until it finishes or suspends again.
///
/// # Panics
///
/// Unless the worker is [`State::Suspended`].
pub fn resume() -> Ran {
    assert!(
        matches!(state(), State::Suspended { .. }),
        "the worker is not suspended"
    );
    switch_to_work()
}

/// If called by the worker's work, suspends it until [`resume`]d, at the
/// latest once `wake` passes (see [`State::Suspended`]), and returns true;
/// otherwise returns false at once.
pub fn suspend(wake: Option<Instant>) -> bool {
    let Some((rsp, resumer_rsp)) = with_per_cpu_variables(|pcv| {
        let worker = &pcv.worker;
        if worker.state.get() != State::Running {
            return None;
        }
        worker.state.set(State::Suspended { wake });
        Some((worker.rsp.as_ptr(), worker.resumer_rsp.get()))
    }) else {
        return false;
    };
    // Safety: `resumer_rsp` was saved by `switch` in `switch_to_work`, whose
    // stack is live; this one stays allocated.
    unsafe { switch(rsp, resumer_rsp) };
    with_per_cpu_variables(|pcv| pcv.worker.state.set(State::Running));
    true
}

/// Self-check (debug builds, at boot): work starts on the worker's stack,
/// suspends, and resumes there until it finishes.
///
/// # Panics
///
/// On a failed check, or unless the worker is [`State::Idle`].
pub(crate) fn self_check(platform: &crate::VmKernel) {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    // Steps done, and an address on the work's stack.
    let seen = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let work = {
        let seen = seen.clone();
        Box::new(move || {
            let local = 0u8;
            seen[1].store(core::ptr::from_ref(&local) as usize, Ordering::Relaxed);
            seen[0].store(1, Ordering::Relaxed);
            assert!(suspend(None));
            assert_eq!(state(), State::Running, "resumed on the worker");
            seen[0].store(2, Ordering::Relaxed);
        })
    };
    assert_eq!(start(platform, work), Ran::Suspended);
    assert_eq!(seen[0].load(Ordering::Relaxed), 1);
    assert_eq!(state(), State::Suspended { wake: None });
    assert!(!suspend(None), "not on the worker");
    let top = with_per_cpu_variables(|pcv| pcv.worker.stack_top.get());
    assert!(
        (top - STACK_SIZE..top).contains(&seen[1].load(Ordering::Relaxed)),
        "work runs on the worker's stack"
    );
    assert_eq!(resume(), Ran::Finished);
    assert_eq!(seen[0].load(Ordering::Relaxed), 2);
    assert_eq!(state(), State::Idle);
}

/// Switches to the work (new or suspended) until it finishes or suspends.
fn switch_to_work() -> Ran {
    let (resumer_rsp, rsp) = with_per_cpu_variables(|pcv| {
        assert!(
            !pcv.asm.is_in_user(),
            "the worker runs outside other kernel work"
        );
        pcv.worker.state.set(State::Running);
        (pcv.worker.resumer_rsp.as_ptr(), pcv.worker.rsp.get())
    });
    // Safety: `rsp` is the work's: initial, or saved by `switch` in
    // `suspend`, on its allocated stack.
    unsafe { switch(resumer_rsp, rsp) };
    let ran = match state() {
        State::Idle => Ran::Finished,
        State::Suspended { .. } => Ran::Suspended,
        State::Running => unreachable!("the work switched back while running"),
    };
    cpu::set_suspended(ran == Ran::Suspended);
    ran
}

/// The worker stack's initial frame, for `switch` to pop: callee-saved
/// registers (zero), then `work_entry` as the return address, which it
/// reaches with a 16-byte aligned stack, as after a call's return.
fn initial_rsp(stack_top: usize) -> usize {
    const REGISTERS: usize = 6;
    let rsp = stack_top - (REGISTERS + 3) * 8;
    debug_assert_eq!(rsp % 16, 8);
    let frame = rsp as *mut usize;
    // Safety: within the worker's stack, which no work uses now.
    unsafe {
        for register in 0..REGISTERS {
            frame.add(register).write(0);
        }
        frame.add(REGISTERS).write(work_entry as *const () as usize);
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

/// Where new work starts, on the worker stack.
#[unsafe(naked)]
unsafe extern "C" fn work_entry() -> ! {
    core::arch::naked_asm!("call {main}", "ud2", main = sym work_main);
}

extern "C" fn work_main() -> ! {
    let work = with_per_cpu_variables(|pcv| pcv.worker.work.take()).expect("work to run");
    work();
    let (rsp, resumer_rsp) = with_per_cpu_variables(|pcv| {
        let worker = &pcv.worker;
        worker.state.set(State::Idle);
        (worker.rsp.as_ptr(), worker.resumer_rsp.get())
    });
    // Safety: as in `suspend`; this stack is abandoned, and reset by the next
    // `start`.
    unsafe { switch(rsp, resumer_rsp) };
    unreachable!("finished work resumed");
}
