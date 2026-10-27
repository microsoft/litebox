// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Debug builds: self-checks of kernel threads, run by the boot CPU once the
//! devices and the scheduler's preemption are set up: alone ([`kthreads`]),
//! then with the other CPUs ([`smp_kthreads`]). The checks schedule the
//! threads themselves.

use crate::devices::Devices;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::time::Duration;
use litebox_platform::sync::Mutex;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::kthread::{self, Kthread, Ran, Stack, WaitQueue};
use litebox_platform_vm_kernel::preempt::NoPreempt;
use litebox_platform_vm_kernel::{Instant, VmKernel, cpu};
use litebox_shim_vm_kernel::ProcessTimer;
use litebox_shim_vm_kernel::sched::{GRACE, QUANTUM};

/// Before the other CPUs start: sleeps, wakes and a contended lock; slice
/// ends inside a kernel service; lone wakes; due runs.
pub(crate) fn kthreads(platform: &'static VmKernel, devices: &'static Devices) {
    assert_eq!(cpu::online_count(), 1, "before the other CPUs start");
    sleep_wake_and_contend();
    // Short of the grace by most of it, as the host may stall the VM.
    for in_service in [GRACE / 10, 2 * GRACE] {
        expiry_in_a_guard(platform, devices, in_service);
    }
    for inherited in [None, Some(100 * QUANTUM)] {
        for safe_point in [false, true] {
            lone_wake(platform, devices, inherited, safe_point);
        }
    }
    for safe_point in [false, true] {
        due_stays_due(platform, devices, safe_point);
    }
    devices.arm(None);
    cpu::acknowledge();
}

/// Once the other CPUs started: a shortened slice end is armed; due runs; a
/// thread's check at a device interrupt waits for the device waiters' lock,
/// which another CPU holds.
pub(crate) fn smp_kthreads(platform: &'static VmKernel, devices: &'static Devices) {
    if cpu::online_count() == 1 {
        return;
    }
    shortened_end_is_armed(platform, devices);
    for safe_point in [false, true] {
        due_stays_due(platform, devices, safe_point);
    }
    contended_check(platform, devices);
    devices.arm(None);
    cpu::acknowledge();
}

fn kthread(work: impl FnOnce() + Send + 'static) -> Kthread {
    Kthread::new(
        Stack::allocate().expect("a kernel thread stack"),
        Box::new(work),
    )
}

/// Runs `thread` with no slice end, as a step would.
fn step(thread: Kthread) -> Ran {
    cpu::acknowledge();
    thread.run(None).0
}

/// The thread a run stopped short of its end.
fn stopped(ran: Ran) -> Kthread {
    match ran {
        Ran::Slept(thread) | Ran::Preempted(thread) => thread,
        Ran::Finished(_) => panic!("the kernel thread finished, where it was to stop"),
    }
}

fn finished(ran: Ran) {
    assert!(matches!(ran, Ran::Finished(_)), "the kernel thread stopped");
}

fn after(at: Instant, duration: Duration) -> Instant {
    at.checked_add(duration)
        .expect("the clock is far from overflowing")
}

/// A checked thread's progress, read once it stopped.
#[derive(Clone, Default)]
struct Stage(Arc<AtomicUsize>);

impl Stage {
    const LEFT_SERVICE: usize = 1;
    const AT_SAFE_POINT: usize = 2;
    const SPINNING: usize = 3;
    const FINISHING: usize = 4;

    fn set(&self, stage: usize) {
        self.0.store(stage, Ordering::SeqCst);
    }

    fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// Runs `thread` with `slice_end`, which must preempt it at `stage`; then to
/// its end.
fn preempted_at(thread: Kthread, slice_end: Option<Instant>, at: &Stage, stage: usize) {
    cpu::acknowledge();
    let ran = thread.run(slice_end).0;
    assert!(
        matches!(ran, Ran::Preempted(_)) && at.get() == stage,
        "a kernel thread was preempted at stage {}, not {stage} (finished: {})",
        at.get(),
        matches!(ran, Ran::Finished(_))
    );
    finished(step(stopped(ran)));
    assert_eq!(at.get(), Stage::FINISHING);
}

/// A sleeps on a queue holding a lock, B sleeps for the lock, C sleeps on the
/// queue; a wake of two wakes A and C; A releases the lock, waking B.
fn sleep_wake_and_contend() {
    let queue = Arc::new(WaitQueue::new());
    let lock: Arc<Mutex<VmKernel, ()>> = Arc::new(Mutex::new(()));
    let a = stopped(step(kthread({
        let (queue, lock) = (queue.clone(), lock.clone());
        move || {
            let _guard = lock.lock();
            queue.prepare().sleep(None);
        }
    })));
    let b = stopped(step(kthread({
        let lock = lock.clone();
        move || drop(lock.lock())
    })));
    assert_eq!(
        litebox_platform_vm_kernel::lock_sleepers(),
        1,
        "a thread sleeps for a lock held"
    );
    let c = stopped(step(kthread({
        let queue = queue.clone();
        move || queue.prepare().sleep(None)
    })));
    let now = Instant::from_nanos(0);
    assert!(!a.is_due(now) && !b.is_due(now) && !c.is_due(now));
    assert_eq!(queue.wake(usize::MAX), 2);
    assert!(a.is_due(now) && !b.is_due(now) && c.is_due(now));
    finished(step(a));
    assert!(b.is_due(now), "a lock's release wakes its sleeper");
    finished(step(b));
    finished(step(c));
    assert_eq!(litebox_platform_vm_kernel::lock_sleepers(), 0);
}

/// A slice end inside a kernel service, which lasts `in_service` past it: the
/// thread yields at its next safe point if that is within the grace, else as
/// it leaves the service.
fn expiry_in_a_guard(platform: &'static VmKernel, devices: &'static Devices, in_service: Duration) {
    let stage = Stage::default();
    let slice_end = after(platform.now(), Duration::from_millis(1));
    let thread = kthread({
        let stage = stage.clone();
        move || {
            let frame: [u64; 8] = core::array::from_fn(|i| 0x1111 * i as u64);
            {
                let _service = NoPreempt::new();
                // Armed in the service, so that the end comes in it.
                devices.arm(Some(slice_end));
                while platform.now() < after(slice_end, in_service) {
                    core::hint::spin_loop();
                }
                stage.set(Stage::LEFT_SERVICE);
            }
            stage.set(Stage::AT_SAFE_POINT);
            kthread::safe_point();
            stage.set(Stage::FINISHING);
            assert_eq!(
                core::hint::black_box(frame),
                core::array::from_fn(|i| 0x1111 * i as u64),
                "a preempted kernel thread's frames are intact"
            );
        }
    });
    devices.arm(None);
    let at = if in_service < GRACE {
        Stage::AT_SAFE_POINT
    } else {
        Stage::LEFT_SERVICE
    };
    preempted_at(thread, Some(slice_end), &stage, at);
}

/// A lone thread, its run's timer inherited (`inherited`: a slice end from
/// now, if any): a notification arms no timer, and a wake ends its slice, so
/// that the woken thread runs at its next safe point (`safe_point`) or at the
/// grace, not at the inherited end.
fn lone_wake(
    platform: &'static VmKernel,
    devices: &'static Devices,
    inherited: Option<Duration>,
    safe_point: bool,
) {
    let queue = Arc::new(WaitQueue::new());
    let woken_ran = Arc::new(AtomicBool::new(false));
    let woken = stopped(step(kthread({
        let (queue, woken_ran) = (queue.clone(), woken_ran.clone());
        move || {
            queue.prepare().sleep(None);
            woken_ran.store(true, Ordering::SeqCst);
        }
    })));
    let armed = move || {
        let _service = NoPreempt::new();
        devices.armed().load(Ordering::Relaxed)
    };
    let waker = kthread({
        let woken_ran = woken_ran.clone();
        move || {
            let before = armed();
            cpu::notify_all();
            assert_eq!(
                armed(),
                before,
                "a notification arms no timer ({inherited:?})"
            );
            let (start, after_wake) = {
                let _service = NoPreempt::new();
                let start = platform.now();
                assert_eq!(queue.wake(1), 1);
                (start, armed())
            };
            assert!(
                (after(start, GRACE).as_nanos()..=after(platform.now(), GRACE).as_nanos())
                    .contains(&after_wake),
                "a wake ends the run's slice, arming the timer for the grace past it \
                 ({inherited:?}): {before} then {after_wake}"
            );
            if safe_point {
                kthread::safe_point();
                assert!(
                    woken_ran.load(Ordering::SeqCst),
                    "a woken thread runs at its waker's next safe point ({inherited:?})"
                );
            }
            while !woken_ran.load(Ordering::SeqCst) {
                assert!(
                    platform.now().duration_since(&start) < QUANTUM,
                    "a lone kernel thread's wake runs the woken thread within the grace \
                     ({inherited:?})"
                );
                core::hint::spin_loop();
            }
        }
    });
    let slice_end = inherited.map(|inherited| after(platform.now(), inherited));
    cpu::acknowledge();
    devices.arm(slice_end);
    let mut threads: Vec<Kthread> = alloc::vec![waker, woken];
    let mut first = Some(slice_end);
    while !threads.is_empty() {
        let now = platform.now();
        let at = threads
            .iter()
            .position(|thread| thread.is_due(now))
            .expect("one of the threads is due");
        let thread = threads.remove(at);
        cpu::acknowledge();
        // The waker's first run inherits the timer; later ones run alone.
        match thread.run(first.take().flatten()).0 {
            Ran::Finished(_) => {}
            Ran::Slept(thread) | Ran::Preempted(thread) => threads.push(thread),
        }
    }
    assert!(woken_ran.load(Ordering::SeqCst));
}

/// A run that [`kthread::yield_due`] finds due stays due: it is preempted at
/// its next safe point (`safe_point`), or at the grace.
fn due_stays_due(platform: &'static VmKernel, devices: &'static Devices, safe_point: bool) {
    let alone = cpu::online_count() == 1;
    let stage = Stage::default();
    let thread = kthread({
        let stage = stage.clone();
        move || {
            let start = platform.now();
            cpu::notify_all();
            if alone {
                assert!(kthread::yield_due(), "a notified lone run is due at once");
            } else {
                assert!(
                    !kthread::yield_due(),
                    "a notified run is due within NOTIFIED"
                );
                while !kthread::yield_due() {
                    assert!(
                        platform.now().duration_since(&start) < QUANTUM,
                        "a notified run is due once past the end the notification set"
                    );
                    core::hint::spin_loop();
                }
            }
            if safe_point {
                stage.set(Stage::AT_SAFE_POINT);
                kthread::safe_point();
            } else {
                stage.set(Stage::SPINNING);
                while platform.now() < after(start, 3 * GRACE + cpu::NOTIFIED) {
                    core::hint::spin_loop();
                }
            }
            stage.set(Stage::FINISHING);
        }
    });
    devices.arm(None);
    let at = if safe_point {
        Stage::AT_SAFE_POINT
    } else {
        Stage::SPINNING
    };
    preempted_at(thread, None, &stage, at);
}

/// A notification taken at a safe point shortens a run's slice end, and the
/// grace past it is armed: a spin with no safe point is preempted there.
fn shortened_end_is_armed(platform: &'static VmKernel, devices: &'static Devices) {
    let stage = Stage::default();
    let thread = kthread({
        let stage = stage.clone();
        move || {
            let start = platform.now();
            cpu::notify_all();
            kthread::safe_point();
            stage.set(Stage::SPINNING);
            while platform.now() < after(start, 3 * GRACE + cpu::NOTIFIED) {
                core::hint::spin_loop();
            }
            stage.set(Stage::FINISHING);
        }
    });
    // As a step arms a run's own timer.
    let slice_end = after(platform.now(), 10 * QUANTUM);
    devices.arm(Some(after(slice_end, GRACE)));
    preempted_at(thread, Some(slice_end), &stage, Stage::SPINNING);
}

/// A thread's check at a device interrupt wakes the threads that wait for a
/// device while another CPU holds their queue's lock: it spins until released.
fn contended_check(platform: &'static VmKernel, devices: &'static Devices) {
    let others = cpu::online_count() - 1;
    let waiting = stopped(step(kthread(move || {
        devices.waiters().prepare().sleep(None);
    })));
    devices.hold_waiters();
    let interrupter = kthread(move || {
        let release_at = {
            let _service = NoPreempt::new();
            devices.interrupt_self();
            let release_at = after(platform.now(), Duration::from_millis(2));
            devices.release_waiters(release_at);
            release_at
        };
        assert!(
            others > 1 || platform.now() >= release_at,
            "the reschedule check waited for the lock"
        );
    });
    let mut ran = step(interrupter);
    while let Ran::Slept(thread) | Ran::Preempted(thread) = ran {
        ran = step(thread);
    }
    finished(ran);
    // Another CPU's look, if it took the interrupt's, may still spin.
    let start = platform.now();
    while !waiting.is_due(platform.now()) {
        assert!(
            platform.now().duration_since(&start) < Duration::from_secs(1),
            "the reschedule check's wake landed"
        );
        core::hint::spin_loop();
    }
    finished(step(waiting));
}
