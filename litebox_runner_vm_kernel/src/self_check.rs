// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Debug builds: a self-check of kernel threads ([`kthreads`]).

use crate::devices::Devices;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use litebox_platform::sync::Mutex;
use litebox_platform_vm_kernel::kthread::{self, Kthread, Ran, Stack, WaitQueue};
use litebox_platform_vm_kernel::preempt::NoPreempt;
use litebox_platform_vm_kernel::{Instant, VmKernel, cpu};
use litebox_shim_vm_kernel::ProcessTimer;

/// Sleeps, wakes and a contended lock, the boot CPU running the threads itself
/// before the other CPUs start: A sleeps on a queue holding a lock, B sleeps
/// for the lock, C sleeps on the queue; a wake of two wakes A and C; A
/// releases the lock, waking B. Then a run past its slice end with no safe
/// point, which only the timer its run armed ends; and a run whose CPU is
/// marked to reschedule, which a safe point in a section with interrupts
/// disabled does not end, but the next one does, returning that end.
pub(crate) fn kthreads(devices: &Devices) {
    assert_eq!(cpu::online_count(), 1, "before the other CPUs start");
    let queue = Arc::new(WaitQueue::new());
    let lock: Arc<Mutex<VmKernel, ()>> = Arc::new(Mutex::new(()));
    let a = start({
        let (queue, lock) = (queue.clone(), lock.clone());
        move || {
            let _guard = lock.lock();
            queue.prepare().sleep(None);
        }
    });
    let b = start({
        let lock = lock.clone();
        move || drop(lock.lock())
    });
    let c = start({
        let queue = queue.clone();
        move || queue.prepare().sleep(None)
    });
    let now = Instant::from_nanos(0);
    assert!(!a.is_due(now) && !b.is_due(now) && !c.is_due(now));
    assert_eq!(queue.wake(usize::MAX), 2);
    assert!(a.is_due(now) && !b.is_due(now) && c.is_due(now));
    finished(step(a));
    assert!(b.is_due(now), "a lock's release wakes its sleeper");
    finished(step(b));
    finished(step(c));
    // Waking B ended A's slice, which armed the timer.
    devices.arm(None);
    let spin = Arc::new(AtomicBool::new(true));
    let stack = Stack::allocate().expect("a kernel thread stack");
    let thread = Kthread::new(stack, {
        let spin = spin.clone();
        Box::new(move || {
            while spin.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        })
    });
    cpu::acknowledge();
    let Ran::Preempted(thread) = thread.run(Some(now)).0 else {
        panic!("a run past its slice end is preempted");
    };
    assert!(
        !devices.timer_disarmed(),
        "a run with a slice end arms the timer"
    );
    spin.store(false, Ordering::Relaxed);
    finished(step(thread));
    let deferred = Arc::new(AtomicBool::new(false));
    let stack = Stack::allocate().expect("a kernel thread stack");
    let thread = Kthread::new(stack, {
        let deferred = deferred.clone();
        Box::new(move || {
            {
                let _no_preempt = NoPreempt::new();
                cpu::wake_idle_or_resched();
                kthread::safe_point();
                deferred.store(true, Ordering::Relaxed);
            }
            kthread::safe_point();
        })
    });
    cpu::acknowledge();
    let (Ran::Preempted(thread), Some(_)) = thread.run(None) else {
        panic!("a run marked to reschedule ends at a safe point, with the end the mark made");
    };
    assert!(
        deferred.load(Ordering::Relaxed),
        "a safe point in a section with interrupts disabled defers"
    );
    finished(step(thread));
    devices.arm(None);
    cpu::acknowledge();
}

/// A new thread for `work`, run until it stops.
fn start(work: impl FnOnce() + Send + 'static) -> Kthread {
    let stack = Stack::allocate().expect("a kernel thread stack");
    match step(Kthread::new(stack, Box::new(work))) {
        Ran::Slept(thread) => thread,
        Ran::Finished(_) => panic!("the kernel thread finished, where it was to stop"),
        Ran::Preempted(_) => unreachable!("`step` resumes a preempted thread"),
    }
}

/// Runs `thread` with no slice end, which the kernel-thread API allows, until
/// it stops other than preempted: a wake it made arms the timer, which
/// preempts it if the host does not run this vCPU meanwhile.
fn step(mut thread: Kthread) -> Ran {
    loop {
        cpu::acknowledge();
        match thread.run(None).0 {
            Ran::Preempted(preempted) => thread = preempted,
            ran => return ran,
        }
    }
}

fn finished(ran: Ran) {
    assert!(matches!(ran, Ran::Finished(_)), "the kernel thread stopped");
}
