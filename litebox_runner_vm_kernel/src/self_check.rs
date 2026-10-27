// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Debug builds: self-checks of kernel threads, run by the boot CPU once the
//! devices and the scheduler's preemption are set up: alone ([`kthreads`]),
//! then with the other CPUs ([`smp_kthreads`]). The checks schedule the
//! threads themselves.

use crate::devices::Devices;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
        redone(|| expiry_in_a_guard(platform, devices, in_service));
    }
    for inherited in [None, Some(100 * QUANTUM)] {
        for safe_point in [false, true] {
            lone_wake(platform, devices, inherited, safe_point);
        }
    }
    for safe_point in [false, true] {
        redone(|| due_stays_due(platform, devices, safe_point));
    }
    devices.arm(None);
    cpu::acknowledge();
}

/// Once the other CPUs started: a shortened slice end is armed; due runs.
pub(crate) fn smp_kthreads(platform: &'static VmKernel, devices: &'static Devices) {
    if cpu::online_count() == 1 {
        return;
    }
    redone(|| shortened_end_is_armed(platform, devices));
    for safe_point in [false, true] {
        redone(|| due_stays_due(platform, devices, safe_point));
    }
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

/// How many times a check whose runs are inconclusive is run, at most.
const ATTEMPTS: usize = 3;

/// Runs `check` until a run of it is conclusive, at most [`ATTEMPTS`] times;
/// logs why each other one was not (e.g., a host stall cut it short).
fn redone(mut check: impl FnMut() -> Result<(), String>) {
    let mut why = String::new();
    for attempt in 1..=ATTEMPTS {
        match check() {
            Ok(()) => return,
            Err(reason) => {
                litebox_util_log::warn!(
                    attempt:% = attempt, why:% = reason; "a self-check's run was inconclusive"
                );
                why = reason;
            }
        }
    }
    panic!("in none of {ATTEMPTS} attempts: {why}");
}

/// A checked thread's progress, read once it stopped, and its stamps of the
/// time.
///
/// The checks of where a run is preempted assume that the vCPU runs: a host
/// stall can pass the run's end, or the timer for the grace past it, before
/// the thread gets to the stage a check expects. So the check stamps the time
/// as it sets the run's end, and as the run starts and stops; the thread, as
/// it sets its stages and as it waits in a kernel service or for
/// [`kthread::yield_due`]. A gap of half a `GRACE` or more between consecutive
/// stamps is a stall (each way a stall stops a run short needs one of nearly
/// `GRACE`): the run is then inconclusive. Any other wrong stop fails the
/// check.
#[derive(Clone)]
struct Stage(Arc<Stamps>);

struct Stamps {
    platform: &'static VmKernel,
    stage: AtomicUsize,
    /// The last stamp, in nanoseconds.
    last: AtomicU64,
    /// The largest gap between consecutive stamps, in nanoseconds.
    gap: AtomicU64,
}

impl Stage {
    const LEFT_SERVICE: usize = 1;
    const AT_SAFE_POINT: usize = 2;
    const SPINNING: usize = 3;
    const FINISHING: usize = 4;
    /// The thread gave up after a stall.
    const STALLED: usize = usize::MAX;

    /// No stage yet, and a first stamp.
    fn new(platform: &'static VmKernel) -> Self {
        Self(Arc::new(Stamps {
            platform,
            stage: AtomicUsize::new(0),
            last: AtomicU64::new(platform.now().as_nanos()),
            gap: AtomicU64::new(0),
        }))
    }

    /// Stamps the time, which it returns: with preemption off, so that the
    /// gap since the last stamp is never left unrecorded.
    fn stamp(&self) -> Instant {
        let _no_preempt = NoPreempt::new();
        let now = self.0.platform.now();
        let last = self.0.last.swap(now.as_nanos(), Ordering::SeqCst);
        self.0
            .gap
            .fetch_max(now.as_nanos().saturating_sub(last), Ordering::SeqCst);
        now
    }

    /// The largest gap between consecutive stamps.
    fn gap(&self) -> Duration {
        Duration::from_nanos(self.0.gap.load(Ordering::SeqCst))
    }

    /// Whether the stamps show a stall.
    fn stalled(&self) -> bool {
        self.gap() >= GRACE / 2
    }

    /// Stamps the time, which it returns, then sets `stage`.
    fn set(&self, stage: usize) -> Instant {
        let now = self.stamp();
        self.0.stage.store(stage, Ordering::SeqCst);
        now
    }

    fn get(&self) -> usize {
        self.0.stage.load(Ordering::SeqCst)
    }
}

/// Runs `thread`, `check`'s, with `slice_end`, which must preempt it at
/// `stage`; then to its end. A run stopped short of `stage` after a stall, or
/// given up after one (see [`Stage`]), is inconclusive; any other wrong stop
/// panics, naming `check`, with the time into the run.
fn preempted_at(
    check: &str,
    thread: Kthread,
    slice_end: Option<Instant>,
    at: &Stage,
    stage: usize,
) -> Result<(), String> {
    cpu::acknowledge();
    let start = at.stamp();
    let ran = thread.run(slice_end).0;
    let stop = at.stamp();
    let got = at.get();
    if matches!(ran, Ran::Preempted(_)) && got == stage {
        finished(step(stopped(ran)));
        assert_eq!(at.get(), Stage::FINISHING, "{check}");
        return Ok(());
    }
    let what = match (&ran, got) {
        (_, Stage::STALLED) => String::from("gave up after a stall"),
        (Ran::Finished(_), _) => String::from("finished"),
        (_, got) => format!("stopped at stage {got}"),
    };
    // In microseconds: the log's bytes are ASCII.
    let why = format!(
        "{check}: a kernel thread {what}, not preempted at stage {stage}, {} us into its run, \
         its stamps' largest gap {} us",
        stop.duration_since(&start).as_micros(),
        at.gap().as_micros()
    );
    if (got < stage || got == Stage::STALLED) && at.stalled() {
        if let Ran::Slept(thread) | Ran::Preempted(thread) = ran {
            finished(step(thread));
        }
        return Err(why);
    }
    panic!("{why}");
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
fn expiry_in_a_guard(
    platform: &'static VmKernel,
    devices: &'static Devices,
    in_service: Duration,
) -> Result<(), String> {
    let stage = Stage::new(platform);
    let slice_end = after(stage.stamp(), Duration::from_millis(1));
    let thread = kthread({
        let stage = stage.clone();
        move || {
            let frame: [u64; 8] = core::array::from_fn(|i| 0x1111 * i as u64);
            {
                let _service = NoPreempt::new();
                // Armed in the service, so that the end comes in it.
                devices.arm(Some(slice_end));
                while stage.stamp() < after(slice_end, in_service) {
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
    let check = format!(
        "expiry_in_a_guard(in_service: {} us)",
        in_service.as_micros()
    );
    preempted_at(&check, thread, Some(slice_end), &stage, at)
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
            // Read before the flag, the clock cannot pass the bound with the
            // woken thread not run, even across a host stall: the timer's
            // interrupt, due a grace past the wake, comes first. The bound
            // starts after the wake, which a stall could delay, and is short
            // of a `QUANTUM`, which the grace must be too.
            let woke = platform.now();
            loop {
                let now = platform.now();
                if woken_ran.load(Ordering::SeqCst) {
                    break;
                }
                assert!(
                    now.duration_since(&woke) < QUANTUM / 2,
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
fn due_stays_due(
    platform: &'static VmKernel,
    devices: &'static Devices,
    safe_point: bool,
) -> Result<(), String> {
    let alone = cpu::online_count() == 1;
    let stage = Stage::new(platform);
    let thread = kthread({
        let stage = stage.clone();
        move || {
            let start = stage.stamp();
            cpu::notify_all();
            if alone {
                assert!(kthread::yield_due(), "a notified lone run is due at once");
            } else {
                // Due at once only if an interrupt's check took the
                // notification, and the end it set passed: after a stall.
                if kthread::yield_due() {
                    stage.stamp();
                    assert!(stage.stalled(), "a notified run is due within NOTIFIED");
                    stage.set(Stage::STALLED);
                    return;
                }
                while !kthread::yield_due() {
                    if stage.stamp().duration_since(&start) >= QUANTUM {
                        assert!(
                            stage.stalled(),
                            "a notified run is due once past the end the notification set"
                        );
                        stage.set(Stage::STALLED);
                        return;
                    }
                    core::hint::spin_loop();
                }
            }
            if safe_point {
                stage.set(Stage::AT_SAFE_POINT);
                kthread::safe_point();
            } else {
                // From the stamp, past the grace the timer is armed for.
                let spinning = stage.set(Stage::SPINNING);
                while platform.now() < after(spinning, 3 * GRACE + cpu::NOTIFIED) {
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
    preempted_at(
        &format!("due_stays_due(safe_point: {safe_point}, alone: {alone})"),
        thread,
        None,
        &stage,
        at,
    )
}

/// A notification taken at a safe point shortens a run's slice end, and the
/// grace past it is armed: a spin with no safe point is preempted there.
fn shortened_end_is_armed(
    platform: &'static VmKernel,
    devices: &'static Devices,
) -> Result<(), String> {
    let stage = Stage::new(platform);
    let thread = kthread({
        let stage = stage.clone();
        move || {
            cpu::notify_all();
            kthread::safe_point();
            // From the stamp, past the grace the timer is armed for.
            let spinning = stage.set(Stage::SPINNING);
            while platform.now() < after(spinning, 3 * GRACE + cpu::NOTIFIED) {
                core::hint::spin_loop();
            }
            stage.set(Stage::FINISHING);
        }
    });
    // As a step arms a run's own timer.
    let slice_end = after(stage.stamp(), 10 * QUANTUM);
    devices.arm(Some(after(slice_end, GRACE)));
    preempted_at(
        "shortened_end_is_armed",
        thread,
        Some(slice_end),
        &stage,
        Stage::SPINNING,
    )
}
