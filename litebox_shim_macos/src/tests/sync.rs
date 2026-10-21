// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach semaphores, `__semwait_signal`, pthread cancellation and
//! `clock_get_time`, driven through the syscall dispatcher. Other guest
//! threads are sibling tasks on host test threads; every wait another thread
//! must end is bounded, so a broken implementation fails instead of hanging.

use super::mach::{bsd, kr, mig_call, ndr, new_task, trap, word};
use super::psynch::{
    CV_CBIT, CV_PBIT, EBIT, FIRSTFIT, INC, KBIT, Watchdog, await_waiters as await_psynch_waiters,
    clear_fillers, cvbroad, cvsignal, cvwait, fill_fake_budget, mutexdrop, mutexwait,
};
use super::*;
use crate::syscalls::cancel::ut;
use crate::syscalls::psynch::PSYNCH_MAX_FAKES;
use core::sync::atomic::Ordering;
use core::time::Duration;
use litebox::utils::TruncateExt as _;
use litebox_common_macos::{
    MachClock as _,
    errno::Errno,
    mach::msg_type,
    syscall::{MachPortName, mach_trap, nr},
};
use std::sync::mpsc;
use std::time::Instant;

/// Bounds every wait a test expects another thread to end.
const BOUND: Duration = Duration::from_secs(10);
const BOUND_SECONDS: usize = 10;
const SYNC_POLICY_FIFO: u32 = 0;
const SYNC_POLICY_LIFO: u32 = 2;

fn create_semaphore(task: &Task<Platform>, policy: u32, value: u32) -> usize {
    let own = trap(task, mach_trap::TASK_SELF, &[]);
    let reply = mig_call(task, own.trunc(), 3418, &ndr(&[policy, value]), false);
    word(&reply, 28) as usize
}

/// `semaphore_destroy`, moving the caller's send right.
fn destroy_semaphore(task: &Task<Platform>, semaphore: usize) -> u32 {
    let own = trap(task, mach_trap::TASK_SELF, &[]);
    let mut body = 1u32.to_ne_bytes().to_vec();
    body.extend_from_slice(zerocopy::IntoBytes::as_bytes(
        &litebox_common_macos::mach::MachMsgPortDescriptor {
            name: semaphore.trunc(),
            disposition: u8::try_from(msg_type::MOVE_SEND).unwrap(),
            ..Default::default()
        },
    ));
    let reply = mig_call(task, own.trunc(), 3419, &body, true);
    word(&reply, 32)
}

fn semaphore_id(task: &Task<Platform>, semaphore: usize) -> syscalls::semaphore::SemaphoreId {
    task.global
        .ipc
        .lock()
        .semaphore_for_name(MachPortName(semaphore.trunc()))
        .unwrap()
}

fn count(task: &Task<Platform>, semaphore: usize) -> Option<i32> {
    let id = semaphore_id(task, semaphore);
    task.global.semaphores.lock().count(id)
}

/// Wait until `count` threads block on `semaphore`.
fn await_semaphore_waiters(task: &Task<Platform>, semaphore: usize, count: usize) {
    let id = semaphore_id(task, semaphore);
    let start = Instant::now();
    while task.global.semaphores.lock().waiters(id) != Some(count) {
        assert!(start.elapsed() < BOUND, "waiters never blocked");
        std::thread::yield_now();
    }
}

/// `semaphore_timedwait` bounded by [`BOUND`].
fn bounded_wait(task: &Task<Platform>, semaphore: usize) -> KernReturn {
    kr(
        task,
        mach_trap::SEMAPHORE_TIMEDWAIT,
        &[semaphore, BOUND_SECONDS, 0],
    )
}

/// `__semwait_signal` (334) or `__semwait_signal_nocancel` (423).
fn semwait(
    task: &Task<Platform>,
    number: usize,
    semaphore: usize,
    signal: usize,
    timeout: Option<(bool, i64, i32)>,
) -> Result<usize, usize> {
    let (timed, relative, seconds, nanoseconds) = match timeout {
        Some((relative, seconds, nanoseconds)) => (1, usize::from(relative), seconds, nanoseconds),
        None => (0, 0, 0, 0),
    };
    bsd(
        task,
        number,
        &[
            semaphore,
            signal,
            timed,
            relative,
            usize::try_from(seconds.cast_unsigned()).unwrap(),
            nanoseconds.cast_unsigned() as usize,
        ],
    )
}

/// A name for `thread`'s port in its task's space, like the TSD slot holds.
fn port_of(task: &Task<Platform>, thread: &Task<Platform>) -> usize {
    task.global
        .ipc
        .lock()
        .copyout_send(thread.thread.guest.port) as usize
}

fn errno(error: Errno) -> Result<usize, usize> {
    Err(error.raw())
}

/// Run `f` on a sibling of `task` on a new host thread that, like a guest
/// thread, can be interrupted.
fn spawn_sibling<'scope, T: Send + 'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    task: &Task<Platform>,
    f: impl FnOnce(&Task<Platform>) -> T + Send + 'scope,
) -> std::thread::ScopedJoinHandle<'scope, T> {
    let sibling = task.new_sibling(0);
    scope.spawn(move || {
        <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            sibling.start_thread();
            f(&sibling)
        })
    })
}

/// Wait until the sibling `guest` can be interrupted.
fn await_interruptible(guest: &GuestThread<Platform>) {
    let start = Instant::now();
    while guest.interrupt.lock().is_none() {
        assert!(start.elapsed() < BOUND, "the thread never started");
        std::thread::yield_now();
    }
}

/// Waiters wake in queue order: FIFO, or the latest first for a LIFO
/// (`SYNC_POLICY_REVERSED`) semaphore.
#[test]
fn semaphore_waiters_wake_in_policy_order() {
    for (policy, order) in [(SYNC_POLICY_FIFO, [0, 1, 2]), (SYNC_POLICY_LIFO, [2, 1, 0])] {
        let task = new_task();
        let _watchdog = Watchdog::new(&task);
        let semaphore = create_semaphore(&task, policy, 0);
        let (sender, woken) = mpsc::channel();
        std::thread::scope(|scope| {
            for index in 0..3 {
                let sender = sender.clone();
                spawn_sibling(scope, &task, move |waiter| {
                    let result = bounded_wait(waiter, semaphore);
                    sender.send((index, result)).unwrap();
                });
                await_semaphore_waiters(&task, semaphore, index + 1);
            }
            assert_eq!(count(&task, semaphore), Some(-1));
            for expected in order {
                assert_eq!(
                    kr(&task, mach_trap::SEMAPHORE_SIGNAL, &[semaphore]),
                    KernReturn::SUCCESS
                );
                assert_eq!(
                    woken.recv_timeout(BOUND).unwrap(),
                    (expected, KernReturn::SUCCESS)
                );
            }
        });
        // The count stays -1 after the last waiter (XNU keeps no count of
        // waiters); the next signal finds nobody and preposts.
        assert_eq!(count(&task, semaphore), Some(-1));
        assert_eq!(
            kr(&task, mach_trap::SEMAPHORE_SIGNAL, &[semaphore]),
            KernReturn::SUCCESS
        );
        assert_eq!(count(&task, semaphore), Some(1));
    }
}

/// Counts, timeouts, `{0, 0}` polls, `signal_all` and `signal_thread`.
#[test]
fn semaphore_traps_count_time_out_and_signal_like_xnu() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let semaphore = create_semaphore(&task, SYNC_POLICY_FIFO, 2);
    for _ in 0..2 {
        assert_eq!(bounded_wait(&task, semaphore), KernReturn::SUCCESS);
    }
    // A {0, 0} timeout polls; a short one blocks and times out.
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_TIMEDWAIT, &[semaphore, 0, 0]),
        KernReturn::OPERATION_TIMED_OUT
    );
    assert_eq!(count(&task, semaphore), Some(0));
    let start = Instant::now();
    assert_eq!(
        kr(
            &task,
            mach_trap::SEMAPHORE_TIMEDWAIT,
            &[semaphore, 0, 20_000_000]
        ),
        KernReturn::OPERATION_TIMED_OUT
    );
    assert!(start.elapsed() >= Duration::from_millis(20));
    assert_eq!(count(&task, semaphore), Some(-1));
    // BAD_MACH_TIMESPEC.
    for nanoseconds in [1_000_000_000usize, u32::MAX as usize] {
        assert_eq!(
            kr(
                &task,
                mach_trap::SEMAPHORE_TIMEDWAIT,
                &[semaphore, 0, nanoseconds]
            ),
            KernReturn::INVALID_VALUE
        );
    }
    // signal_all with no waiter left resets the count and does not prepost.
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_SIGNAL_ALL, &[semaphore]),
        KernReturn::SUCCESS
    );
    assert_eq!(count(&task, semaphore), Some(0));
    // signal_thread never preposts, and reports a thread that is not waiting.
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_SIGNAL_THREAD, &[semaphore, 0]),
        KernReturn::NOT_WAITING
    );
    let own = trap(&task, mach_trap::THREAD_SELF, &[]);
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_SIGNAL_THREAD, &[semaphore, own]),
        KernReturn::NOT_WAITING
    );
    assert_eq!(count(&task, semaphore), Some(0));
    // A name that is not a thread fails before the semaphore is looked up.
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_SIGNAL_THREAD, &[0x7703, 0x7703]),
        KernReturn::INVALID_ARGUMENT
    );

    std::thread::scope(|scope| {
        let waiters: Vec<_> = (0..3)
            .map(|index| {
                let handle = spawn_sibling(scope, &task, move |waiter| {
                    (port_of(waiter, waiter), bounded_wait(waiter, semaphore))
                });
                await_semaphore_waiters(&task, semaphore, index + 1);
                handle
            })
            .collect();
        // signal_all wakes them all and leaves the count at 0.
        assert_eq!(
            kr(&task, mach_trap::SEMAPHORE_SIGNAL_ALL, &[semaphore]),
            KernReturn::SUCCESS
        );
        for waiter in waiters {
            assert_eq!(waiter.join().unwrap().1, KernReturn::SUCCESS);
        }
    });
    assert_eq!(count(&task, semaphore), Some(0));

    // signal_thread wakes the named thread.
    std::thread::scope(|scope| {
        let (sender, ports) = mpsc::channel();
        let handles: Vec<_> = (0..2)
            .map(|index| {
                let sender = sender.clone();
                let handle = spawn_sibling(scope, &task, move |waiter| {
                    sender.send(port_of(waiter, waiter)).unwrap();
                    bounded_wait(waiter, semaphore)
                });
                await_semaphore_waiters(&task, semaphore, index + 1);
                handle
            })
            .collect();
        let first = ports.recv_timeout(BOUND).unwrap();
        let second = ports.recv_timeout(BOUND).unwrap();
        assert_eq!(
            kr(
                &task,
                mach_trap::SEMAPHORE_SIGNAL_THREAD,
                &[semaphore, second]
            ),
            KernReturn::SUCCESS
        );
        let mut handles = handles.into_iter();
        let first_handle = handles.next().unwrap();
        assert_eq!(handles.next().unwrap().join().unwrap(), KernReturn::SUCCESS);
        await_semaphore_waiters(&task, semaphore, 1);
        assert_eq!(
            kr(
                &task,
                mach_trap::SEMAPHORE_SIGNAL_THREAD,
                &[semaphore, first]
            ),
            KernReturn::SUCCESS
        );
        assert_eq!(first_handle.join().unwrap(), KernReturn::SUCCESS);
    });
}

/// `port_name_to_semaphore`'s errors.
#[test]
fn semaphore_traps_reject_names_like_xnu() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let reply = trap(&task, mach_trap::MACH_REPLY_PORT, &[]);
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    for (name, error) in [
        (0, KernReturn::INVALID_NAME),
        (0x7703, KernReturn::INVALID_NAME),
        (reply, KernReturn::INVALID_RIGHT),
        (own, KernReturn::INVALID_CAPABILITY),
    ] {
        assert_eq!(kr(&task, mach_trap::SEMAPHORE_SIGNAL, &[name]), error);
        assert_eq!(kr(&task, mach_trap::SEMAPHORE_WAIT, &[name]), error);
    }
    // The signal semaphore is looked up first.
    let semaphore = create_semaphore(&task, SYNC_POLICY_FIFO, 1);
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_WAIT_SIGNAL, &[0, own]),
        KernReturn::INVALID_CAPABILITY
    );
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_WAIT_SIGNAL, &[own, semaphore]),
        KernReturn::INVALID_CAPABILITY
    );
    // A destroyed semaphore's name was its only right: it is gone.
    assert_eq!(destroy_semaphore(&task, semaphore), 0);
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_SIGNAL, &[semaphore]),
        KernReturn::INVALID_NAME
    );
}

/// `semaphore_wait_signal`: the signal happens once the waiter is queued,
/// and a semaphore that died ends the wait with `KERN_TERMINATED`.
#[test]
fn semaphore_wait_signal_signals_after_queueing() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let wait = create_semaphore(&task, SYNC_POLICY_FIFO, 0);
    let signal = create_semaphore(&task, SYNC_POLICY_FIFO, 0);
    // With a count, the wait does not block and still signals.
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_SIGNAL, &[wait]),
        KernReturn::SUCCESS
    );
    assert_eq!(
        kr(
            &task,
            mach_trap::SEMAPHORE_TIMEDWAIT_SIGNAL,
            &[wait, signal, BOUND_SECONDS, 0]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(
        (count(&task, wait), count(&task, signal)),
        (Some(0), Some(1))
    );
    // Ping-pong: the partner is already blocked on `signal`, so main's
    // signal wakes it, and main is queued on `wait` by then.
    std::thread::scope(|scope| {
        assert_eq!(bounded_wait(&task, signal), KernReturn::SUCCESS);
        let wait_id = semaphore_id(&task, wait);
        let partner = spawn_sibling(scope, &task, move |partner| {
            let taken = kr(partner, mach_trap::SEMAPHORE_TIMEDWAIT, &[signal, 10, 0]);
            let queued = {
                let table = partner.global.semaphores.lock();
                table.count(wait_id).zip(table.waiters(wait_id))
            };
            (
                taken,
                queued,
                kr(partner, mach_trap::SEMAPHORE_SIGNAL, &[wait]),
            )
        });
        await_semaphore_waiters(&task, signal, 1);
        assert_eq!(
            kr(
                &task,
                mach_trap::SEMAPHORE_TIMEDWAIT_SIGNAL,
                &[wait, signal, BOUND_SECONDS, 0]
            ),
            KernReturn::SUCCESS
        );
        assert_eq!(
            partner.join().unwrap(),
            (KernReturn::SUCCESS, Some((-1, 1)), KernReturn::SUCCESS)
        );
    });
    assert_eq!(
        (count(&task, wait), count(&task, signal)),
        (Some(-1), Some(-1))
    );
    // Signaling the semaphore it waits on wakes the caller itself: the
    // signal found it queued instead of preposting a count it then took.
    let both = create_semaphore(&task, SYNC_POLICY_FIFO, 0);
    assert_eq!(
        kr(
            &task,
            mach_trap::SEMAPHORE_TIMEDWAIT_SIGNAL,
            &[both, both, BOUND_SECONDS, 0]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(count(&task, both), Some(-1));
    // The semaphore to signal died after the lookup: the wait ends.
    let signal_id = semaphore_id(&task, signal);
    task.global.semaphores.lock().destroy(signal_id);
    assert_eq!(
        kr(
            &task,
            mach_trap::SEMAPHORE_TIMEDWAIT_SIGNAL,
            &[wait, signal, BOUND_SECONDS, 0]
        ),
        KernReturn::TERMINATED
    );
    assert_eq!(count(&task, wait), Some(-1));
}

/// `semaphore_create` admits `INT_MAX`; a prepost past it wraps to
/// `INT_MIN` like XNU's `int` count, which then reads as "may have
/// waiters": through `semaphore_signal`, `signal_all`, the wait traps, a
/// wait's signal and `__semwait_signal`.
#[test]
fn semaphore_counts_wrap_past_int_max_like_xnu() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let max = i32::MAX.cast_unsigned();
    let signal = |semaphore| kr(&task, mach_trap::SEMAPHORE_SIGNAL, &[semaphore]);
    let semaphore = create_semaphore(&task, SYNC_POLICY_FIFO, max);
    assert_eq!(count(&task, semaphore), Some(i32::MAX));
    assert_eq!(signal(semaphore), KernReturn::SUCCESS);
    assert_eq!(count(&task, semaphore), Some(i32::MIN));
    // The wrapped count does not satisfy a wait: a poll leaves it, a timed
    // wait blocks (-1) and times out, and the next signal preposts.
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_TIMEDWAIT, &[semaphore, 0, 0]),
        KernReturn::OPERATION_TIMED_OUT
    );
    assert_eq!(count(&task, semaphore), Some(i32::MIN));
    assert_eq!(
        kr(
            &task,
            mach_trap::SEMAPHORE_TIMEDWAIT,
            &[semaphore, 0, 1_000_000]
        ),
        KernReturn::OPERATION_TIMED_OUT
    );
    assert_eq!(count(&task, semaphore), Some(-1));
    assert_eq!(signal(semaphore), KernReturn::SUCCESS);
    assert_eq!(count(&task, semaphore), Some(1));

    // signal_all resets a wrapped count and never preposts past INT_MAX.
    let semaphore = create_semaphore(&task, SYNC_POLICY_FIFO, max);
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_SIGNAL_ALL, &[semaphore]),
        KernReturn::SUCCESS
    );
    assert_eq!(count(&task, semaphore), Some(i32::MAX));
    assert_eq!(signal(semaphore), KernReturn::SUCCESS);
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_SIGNAL_ALL, &[semaphore]),
        KernReturn::SUCCESS
    );
    assert_eq!(count(&task, semaphore), Some(0));

    // A wait takes one from INT_MAX; the signal of wait_signal and of
    // __semwait_signal wraps its semaphore.
    let full = create_semaphore(&task, SYNC_POLICY_FIFO, max);
    assert_eq!(bounded_wait(&task, full), KernReturn::SUCCESS);
    assert_eq!(count(&task, full), Some(i32::MAX - 1));
    assert_eq!(signal(full), KernReturn::SUCCESS);
    let taken = create_semaphore(&task, SYNC_POLICY_FIFO, 2);
    assert_eq!(
        kr(
            &task,
            mach_trap::SEMAPHORE_TIMEDWAIT_SIGNAL,
            &[taken, full, BOUND_SECONDS, 0]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(count(&task, full), Some(i32::MIN));
    let full = create_semaphore(&task, SYNC_POLICY_FIFO, max);
    assert_eq!(
        semwait(&task, nr::SEMWAIT_SIGNAL, taken, full, Some((true, 10, 0))),
        Ok(0)
    );
    assert_eq!(
        (count(&task, taken), count(&task, full)),
        (Some(0), Some(i32::MIN))
    );
}

/// A pending safe abort ends a semaphore wait before the thread queues
/// (`thread_mark_wait_locked`), so the wait's signal of the same semaphore
/// finds no waiter and preposts.
#[test]
fn a_pending_abort_ends_wait_signal_before_its_signal() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let semaphore = create_semaphore(&task, SYNC_POLICY_FIFO, 0);
    task.thread.guest.abort_safely();
    assert_eq!(
        kr(
            &task,
            mach_trap::SEMAPHORE_TIMEDWAIT_SIGNAL,
            &[semaphore, semaphore, BOUND_SECONDS, 0]
        ),
        KernReturn::ABORTED
    );
    assert_eq!(count(&task, semaphore), Some(1));
    assert!(!task.thread.guest.abort.load(Ordering::Relaxed), "consumed");
    // A pending cancellation does the same through __semwait_signal.
    let semaphore = create_semaphore(&task, SYNC_POLICY_FIFO, 0);
    let own = trap(&task, mach_trap::THREAD_SELF, &[]);
    assert_eq!(bsd(&task, nr::PTHREAD_MARKCANCEL, &[own]), Ok(0));
    assert_eq!(
        semwait(
            &task,
            nr::SEMWAIT_SIGNAL,
            semaphore,
            semaphore,
            Some((true, 10, 0))
        ),
        errno(Errno::EINTR)
    );
    assert_eq!(count(&task, semaphore), Some(1));
    assert!(!task.thread.guest.abort.load(Ordering::Relaxed), "consumed");
}

/// `semaphore_destroy` ends its waiters with `KERN_TERMINATED`; process exit
/// ends a wait with `KERN_ABORTED`.
#[test]
fn semaphore_waits_end_for_destroy_and_exit() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let semaphore = create_semaphore(&task, SYNC_POLICY_FIFO, 0);
    std::thread::scope(|scope| {
        let waiters: Vec<_> = (0..2)
            .map(|index| {
                let handle =
                    spawn_sibling(scope, &task, move |waiter| bounded_wait(waiter, semaphore));
                await_semaphore_waiters(&task, semaphore, index + 1);
                handle
            })
            .collect();
        assert_eq!(destroy_semaphore(&task, semaphore), 0);
        for waiter in waiters {
            assert_eq!(waiter.join().unwrap(), KernReturn::TERMINATED);
        }
    });
    assert_eq!(task.global.semaphores.lock().semaphore_count(), 0);

    let semaphore = create_semaphore(&task, SYNC_POLICY_FIFO, 0);
    std::thread::scope(|scope| {
        let sibling = task.new_sibling(0);
        let guest = Arc::clone(&sibling.thread.guest);
        let waiter = scope.spawn(move || {
            <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
                sibling.start_thread();
                let result = bounded_wait(&sibling, semaphore);
                (result, sibling.continuation(&mut PtRegs::default()))
            })
        });
        await_semaphore_waiters(&task, semaphore, 1);
        await_interruptible(&guest);
        assert_eq!(bsd(&task, nr::EXIT, &[3]), Ok(0));
        assert_eq!(
            waiter.join().unwrap(),
            (KernReturn::ABORTED, ContinueOperation::Terminate)
        );
    });
}

/// `__semwait_signal`: relative and absolute timeouts, a mutex semaphore
/// signaled, the 32-bit seconds limit, and the error mapping.
#[test]
fn semwait_signal_times_out_and_maps_results_like_xnu() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let semaphore = create_semaphore(&task, SYNC_POLICY_FIFO, 0);
    let mutex = create_semaphore(&task, SYNC_POLICY_FIFO, 0);
    for number in [nr::SEMWAIT_SIGNAL, nr::SEMWAIT_SIGNAL_NOCANCEL] {
        let start = Instant::now();
        assert_eq!(
            semwait(&task, number, semaphore, mutex, Some((true, 0, 30_000_000))),
            errno(Errno::ETIMEDOUT)
        );
        assert!(start.elapsed() >= Duration::from_millis(30));
    }
    assert_eq!(count(&task, mutex), Some(2), "signaled by each wait");
    // An absolute time in the past polls; one 30 ms ahead waits until it.
    assert_eq!(
        semwait(&task, nr::SEMWAIT_SIGNAL, semaphore, 0, Some((false, 1, 0))),
        errno(Errno::ETIMEDOUT)
    );
    // Started before the deadline is read, so a delay before the call only
    // lengthens the measurement.
    let start = Instant::now();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        + Duration::from_millis(30);
    assert_eq!(
        semwait(
            &task,
            nr::SEMWAIT_SIGNAL,
            semaphore,
            0,
            Some((
                false,
                i64::try_from(now.as_secs()).unwrap(),
                i32::try_from(now.subsec_nanos()).unwrap()
            ))
        ),
        errno(Errno::ETIMEDOUT)
    );
    assert!(start.elapsed() >= Duration::from_millis(25));
    // A count is taken; seconds beyond 32 bits report EINTR when the wait
    // does not block.
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_SIGNAL, &[semaphore]),
        KernReturn::SUCCESS
    );
    assert_eq!(
        semwait(&task, nr::SEMWAIT_SIGNAL, semaphore, 0, Some((true, 10, 0))),
        Ok(0)
    );
    assert_eq!(
        kr(&task, mach_trap::SEMAPHORE_SIGNAL, &[semaphore]),
        KernReturn::SUCCESS
    );
    assert_eq!(
        semwait(
            &task,
            nr::SEMWAIT_SIGNAL,
            semaphore,
            0,
            Some((true, 1 << 32, 0))
        ),
        errno(Errno::EINTR)
    );
    // Bad names, bad nanoseconds and destroyed semaphores are EINVAL.
    assert_eq!(
        semwait(&task, nr::SEMWAIT_SIGNAL, 0, 0, Some((true, 0, 0))),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        semwait(
            &task,
            nr::SEMWAIT_SIGNAL,
            semaphore,
            0,
            Some((true, 0, 1_000_000_000))
        ),
        errno(Errno::EINVAL)
    );
    std::thread::scope(|scope| {
        let waiter = spawn_sibling(scope, &task, move |waiter| {
            semwait(
                waiter,
                nr::SEMWAIT_SIGNAL,
                semaphore,
                0,
                Some((true, 10, 0)),
            )
        });
        await_semaphore_waiters(&task, semaphore, 1);
        assert_eq!(destroy_semaphore(&task, semaphore), 0);
        assert_eq!(waiter.join().unwrap(), errno(Errno::EINVAL));
    });
}

/// `__pthread_canceled` and `__pthread_markcancel` state, the generic
/// presyscall test, and `ULF_WAIT_CANCEL_POINT`.
#[test]
fn cancellation_state_follows_xnu() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let own = trap(&task, mach_trap::THREAD_SELF, &[]);
    let flags = || task.thread.guest.flags.load(Ordering::Relaxed);
    // Nothing to act on.
    assert_eq!(bsd(&task, nr::PTHREAD_CANCELED, &[0]), errno(Errno::EINVAL));
    assert_eq!(
        bsd(&task, nr::PTHREAD_MARKCANCEL, &[0x7703]),
        errno(Errno::ESRCH)
    );
    // Marking itself inside a BSD call does not abort anything.
    assert_eq!(bsd(&task, nr::PTHREAD_MARKCANCEL, &[own]), Ok(0));
    assert_eq!(
        flags() & (ut::CANCEL | ut::NO_SIGMASK),
        ut::CANCEL | ut::NO_SIGMASK
    );
    assert!(!task.thread.guest.abort.load(Ordering::Relaxed));
    // Every cancelable call fails before it runs; its _nocancel twin runs.
    for number in nr::CANCELABLE {
        assert_eq!(bsd(&task, number, &[0; 6]), errno(Errno::EINTR), "{number}");
    }
    assert_ne!(
        bsd(&task, nr::WRITE_NOCANCEL, &[usize::MAX, 0, 0]),
        errno(Errno::EINTR)
    );
    assert_eq!(bsd(&task, nr::GETPID, &[]), Ok(2));
    // ulock_wait only with ULF_WAIT_CANCEL_POINT, and with an errno even
    // with ULF_NO_ERRNO.
    let word = 0u32;
    let address = core::ptr::from_ref(&word) as usize;
    assert_eq!(
        bsd(&task, nr::ULOCK_WAIT, &[0x0102_0001, address, 1, 0]),
        errno(Errno::EINTR)
    );
    assert_eq!(
        bsd(&task, nr::ULOCK_WAIT, &[0x0100_0001, address, 1, 0]),
        Ok(0)
    );
    // Disabled, nothing is pending; enabled again, it is.
    assert_eq!(bsd(&task, nr::PTHREAD_CANCELED, &[2]), Ok(0));
    assert_eq!(
        bsd(&task, nr::READ, &[usize::MAX, 0, 0]),
        errno(Errno::EBADF)
    );
    assert_eq!(bsd(&task, nr::PTHREAD_CANCELED, &[0]), errno(Errno::EINVAL));
    assert_eq!(bsd(&task, nr::PTHREAD_CANCELED, &[1]), Ok(0));
    // Acting on it turns the mark into "canceled", once.
    assert_eq!(bsd(&task, nr::PTHREAD_CANCELED, &[0]), Ok(0));
    assert_eq!(flags() & (ut::CANCEL | ut::CANCELED), ut::CANCELED);
    assert_eq!(bsd(&task, nr::PTHREAD_CANCELED, &[0]), errno(Errno::EINVAL));
    assert_eq!(
        bsd(&task, nr::READ, &[usize::MAX, 0, 0]),
        errno(Errno::EBADF)
    );
    // A canceled thread is not marked again.
    assert_eq!(bsd(&task, nr::PTHREAD_MARKCANCEL, &[own]), Ok(0));
    assert_eq!(flags() & ut::CANCEL, 0);
    // __disable_threadsignal disables cancellation.
    let sibling = task.new_sibling(0);
    assert_eq!(bsd(&sibling, nr::DISABLE_THREADSIGNAL, &[]), Ok(0));
    let port = port_of(&task, &sibling);
    assert_eq!(bsd(&task, nr::PTHREAD_MARKCANCEL, &[port]), Ok(0));
    assert!(!sibling.thread.guest.is_cancelled());
    assert!(!sibling.thread.guest.abort.load(Ordering::Relaxed));
}

/// `pthread_cancel` of a thread blocked in a cancellation point ends its
/// wait with `EINTR`: `psynch_cvwait`, `__semwait_signal` and a cancelable
/// `ulock_wait`.
#[test]
fn markcancel_aborts_waits_at_cancellation_points() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let cv = 0x5_0000;
    let semaphore = create_semaphore(&task, SYNC_POLICY_FIFO, 0);
    let page = {
        let own = trap(&task, mach_trap::TASK_SELF, &[]);
        let mut address = 0usize;
        assert_eq!(
            kr(
                &task,
                mach_trap::MACH_VM_ALLOCATE,
                &[own, (&raw mut address) as usize, PAGE_SIZE, 1]
            ),
            KernReturn::SUCCESS
        );
        address
    };
    std::thread::scope(|scope| {
        let cv_waiter = spawn_sibling(scope, &task, move |waiter| {
            cvwait(waiter, cv, INC, 0, 0, 0, BOUND_SECONDS, 0)
        });
        let semwaiter = spawn_sibling(scope, &task, move |waiter| {
            semwait(
                waiter,
                nr::SEMWAIT_SIGNAL,
                semaphore,
                0,
                Some((true, 10, 0)),
            )
        });
        let joiner = spawn_sibling(scope, &task, move |waiter| {
            // pthread_join's cancelable ulock_wait.
            bsd(
                waiter,
                nr::ULOCK_WAIT,
                &[0x0102_0001, page, 0, BOUND_SECONDS * 1_000_000],
            )
        });
        await_psynch_waiters(&task, cv, 1);
        await_semaphore_waiters(&task, semaphore, 1);
        let start = Instant::now();
        while task.global.ulocks.lock().waiters(page) != 1 {
            assert!(start.elapsed() < BOUND);
            std::thread::yield_now();
        }
        let ports: Vec<usize> = task
            .process
            .0
            .threads
            .lock()
            .values()
            .filter(|thread| thread.id != task.thread.guest.id)
            .map(|thread| task.global.ipc.lock().copyout_send(thread.port) as usize)
            .collect();
        for port in ports {
            assert_eq!(bsd(&task, nr::PTHREAD_MARKCANCEL, &[port]), Ok(0));
        }
        assert_eq!(
            cv_waiter.join().unwrap().unwrap_err() & 0xff,
            Errno::EINTR.raw()
        );
        assert_eq!(semwaiter.join().unwrap(), errno(Errno::EINTR));
        // ULF_NO_ERRNO: the negated errno.
        assert_eq!(
            joiner.join().unwrap(),
            Ok(Errno::EINTR
                .raw()
                .cast_signed()
                .wrapping_neg()
                .cast_unsigned())
        );
    });
    assert_eq!(task.global.psynch.lock().waiters(cv), 0);
}

/// `__pthread_markcancel` aborts a wait outside BSD calls (a Mach trap) but
/// not one inside a BSD call that is not a cancellation point (a psynch
/// mutex wait), as XNU's `UT_NOTCANCELPT` rule does.
#[test]
fn markcancel_respects_non_cancellation_points() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let mutex = 0x6_0000;
    let semaphore = create_semaphore(&task, SYNC_POLICY_FIFO, 0);
    std::thread::scope(|scope| {
        let sibling = task.new_sibling(0);
        let guest = Arc::clone(&sibling.thread.guest);
        let port = port_of(&task, &sibling);
        let locker = scope.spawn(move || {
            <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
                sibling.start_thread();
                mutexwait(&sibling, mutex, 0x300 | KBIT | EBIT, 0x200, 0, FIRSTFIT)
            })
        });
        await_psynch_waiters(&task, mutex, 1);
        await_interruptible(&guest);
        assert_eq!(bsd(&task, nr::PTHREAD_MARKCANCEL, &[port]), Ok(0));
        assert!(guest.is_cancelled());
        assert!(
            !guest.abort.load(Ordering::Relaxed),
            "a wait that is not a cancellation point is not aborted"
        );
        assert_eq!(
            mutexdrop(&task, mutex, 0x300 | KBIT | EBIT, 0x300, FIRSTFIT),
            Ok(0)
        );
        assert_eq!(locker.join().unwrap(), Ok((0x300 | KBIT | EBIT) as usize));

        let waiter = spawn_sibling(scope, &task, move |waiter| bounded_wait(waiter, semaphore));
        await_semaphore_waiters(&task, semaphore, 1);
        let port = {
            let threads = task.process.0.threads.lock();
            let thread = threads
                .values()
                .find(|thread| thread.id != task.thread.guest.id)
                .unwrap();
            task.global.ipc.lock().copyout_send(thread.port) as usize
        };
        assert_eq!(bsd(&task, nr::PTHREAD_MARKCANCEL, &[port]), Ok(0));
        assert_eq!(waiter.join().unwrap(), KernReturn::ABORTED);
    });
}

/// A pending abort ends the next abort-safe wait unless the thread returns
/// to the guest first (`thread_apc_ast`).
#[test]
fn a_pending_abort_ends_the_next_wait_or_clears_on_return() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let sibling = task.new_sibling(0);
    let wait = |task: &Task<Platform>| {
        let deadline = Platform::new().mach_absolute_time() + 1_000_000;
        kr(task, mach_trap::MACH_WAIT_UNTIL, &[deadline.trunc()])
    };
    sibling.thread.guest.abort_safely();
    assert_eq!(wait(&sibling), KernReturn::ABORTED);
    assert_eq!(wait(&sibling), KernReturn::SUCCESS, "consumed");
    sibling.thread.guest.abort_safely();
    assert_eq!(
        sibling.continuation(&mut PtRegs::default()),
        ContinueOperation::Resume
    );
    sibling.thread.wait_state.finish_running_guest();
    assert_eq!(wait(&sibling), KernReturn::SUCCESS, "cleared");
}

/// Signals and broadcasts pass canceled condition variable waiters by
/// (`uthread_is_cancelled`), and a signal they passed by preposts beside
/// such a waiter.
#[test]
fn psynch_signals_pass_canceled_waiters_by() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let cv = 0x7_0000;
    let cancel = |guest: &GuestThread<Platform>| {
        guest.flags.fetch_or(ut::CANCEL, Ordering::AcqRel);
    };
    std::thread::scope(|scope| {
        let canceled = task.new_sibling(0);
        let canceled_guest = Arc::clone(&canceled.thread.guest);
        let canceled = scope.spawn(move || {
            <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
                canceled.start_thread();
                cvwait(&canceled, cv, INC, 0, 0, 0, BOUND_SECONDS, 0)
            })
        });
        await_psynch_waiters(&task, cv, 1);
        await_interruptible(&canceled_guest);
        cancel(&canceled_guest);
        let other = spawn_sibling(scope, &task, move |waiter| {
            cvwait(waiter, cv, 2 * INC, 0, 0, 0, BOUND_SECONDS, 0)
        });
        await_psynch_waiters(&task, cv, 2);
        // The signal skips the canceled waiter for the one at 2.
        assert!(cvsignal(&task, cv, 2 * INC, 0, 0, 0, 0).is_ok());
        assert_eq!(other.join().unwrap(), Ok(0));
        assert_eq!(task.global.psynch.lock().waiters(cv), 1);
        // A broadcast skips it too.
        let late = spawn_sibling(scope, &task, move |waiter| {
            cvwait(waiter, cv, 3 * INC, INC, 0, 0, BOUND_SECONDS, 0)
        });
        await_psynch_waiters(&task, cv, 2);
        // One woken (PTHRW_INC); the canceled waiter stays, beside the
        // broadcast entry that stands for it.
        assert_eq!(cvbroad(&task, cv, 3 * INC, INC, 0, 2, 0), Ok(INC as usize));
        assert_eq!(late.join().unwrap(), Ok(0));
        assert_eq!(task.global.psynch.lock().fake_count(), 1);
        canceled_guest.abort_safely();
        assert_eq!(
            canceled.join().unwrap().unwrap_err() & 0xff,
            Errno::EINTR.raw()
        );
    });

    // A signal that finds only a canceled waiter at its sequence preposts
    // beside it instead of failing with EBUSY.
    let cv = 0x8_0000;
    std::thread::scope(|scope| {
        let canceled = task.new_sibling(0);
        let canceled_guest = Arc::clone(&canceled.thread.guest);
        let canceled = scope.spawn(move || {
            <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
                canceled.start_thread();
                cvwait(&canceled, cv, INC, 0, 0, 0, BOUND_SECONDS, 0)
            })
        });
        await_psynch_waiters(&task, cv, 1);
        await_interruptible(&canceled_guest);
        cancel(&canceled_guest);
        let fakes = task.global.psynch.lock().fake_count();
        assert!(cvsignal(&task, cv, INC, 0, 0, 0, 0).is_ok());
        assert_eq!(task.global.psynch.lock().fake_count(), fakes + 1);
        canceled_guest.abort_safely();
        assert_eq!(
            canceled.join().unwrap().unwrap_err() & 0xff,
            Errno::EINTR.raw()
        );
    });
}

/// On `cv`, waiters at L=1 and L=2 block and are canceled but have not
/// withdrawn yet, and the signals libpthread reserved U for them are delayed
/// before their kernel calls. Waiters at L=3 and L=4 took their tickets but
/// are withheld. Signals at L=3 and L=4, and `before` timed waits at L=5..
/// that time out, each followed by its signal, pass the canceled waiters by
/// and prepost. The delayed signals then prepost beside the canceled waiter
/// at `firstnum`, after the higher preposts, and each canceled waiter
/// withdraws. `after` more timed waits and signals prepost behind those:
/// the queue holds 3, 4, .., 4 + before, 1, 2, 5 + before, .., 4 + before +
/// after in that order, with L - S = 2.
fn prepost_behind_canceled_waiters(task: &Task<Platform>, cv: usize, before: u32, after: u32) {
    let timed_round = |round: u32, s: u32, signaled: u32| {
        let l = (4 + round) * INC;
        assert_eq!(
            cvwait(task, cv, l, s * INC, s * INC, 0, 0, 1).map_err(|error| error & 0xff),
            Err(Errno::ETIMEDOUT.raw())
        );
        assert_eq!(
            cvsignal(task, cv, l, (s + 1) * INC, l - INC, 0, 0),
            Ok(signaled as usize)
        );
    };
    std::thread::scope(|scope| {
        let canceled: Vec<_> = (1..=2u32)
            .map(|l| {
                let waiter = task.new_sibling(0);
                let guest = Arc::clone(&waiter.thread.guest);
                let handle = scope.spawn(move || {
                    <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
                        waiter.start_thread();
                        cvwait(&waiter, cv, l * INC, 0, 0, 0, BOUND_SECONDS, 0)
                    })
                });
                (guest, handle)
            })
            .collect();
        await_psynch_waiters(task, cv, 2);
        for (guest, _) in &canceled {
            await_interruptible(guest);
            guest.flags.fetch_or(ut::CANCEL, Ordering::AcqRel);
        }
        assert_eq!(cvsignal(task, cv, 3 * INC, 0, 2 * INC, 0, 0), Ok(0));
        assert_eq!(cvsignal(task, cv, 4 * INC, 0, 3 * INC, 0, 0), Ok(0));
        for round in 1..=before {
            timed_round(round, round - 1, 0);
        }
        for (l, (guest, handle)) in (1..).zip(canceled) {
            assert_eq!(cvsignal(task, cv, l * INC, 0, (l - 1) * INC, 0, 0), Ok(0));
            guest.abort_safely();
            assert_eq!(
                handle.join().unwrap().unwrap_err() & 0xff,
                Errno::EINTR.raw()
            );
        }
    });
    for round in before + 1..=before + after {
        timed_round(round, round + 1, CV_PBIT);
    }
}

/// Preposts that passed canceled waiters by can queue after higher ones.
/// With the budget full, compaction keeps every prepost a withheld waiter
/// can still take there, and still drops the ones no call can reach from
/// runs in sequence order before and after them; each withheld waiter then
/// takes its signal. A thread blocked below preposts (behind a canceled
/// waiter at a higher sequence) keeps all of them: a late signal up to the
/// lowest still merges into it instead of waking that thread.
#[test]
fn psynch_compaction_keeps_preposts_queued_out_of_order() {
    const BEFORE: u32 = 8;
    const AFTER: u32 = 8;
    const BLOCKED_ROUNDS: u32 = 4;
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let (cv, longer, blocked) = (0x9_0000, 0x9_1000, 0x9_2000);
    prepost_behind_canceled_waiters(&task, cv, 0, 0);
    prepost_behind_canceled_waiters(&task, longer, BEFORE, AFTER);
    let fakes = || task.global.psynch.lock().fake_count();
    std::thread::scope(|scope| {
        // `blocked`: tickets up to 3 returned; a canceled waiter at 5 stays
        // queued while timed waits at 6.. time out and their signals prepost
        // past it; then a waiter at 4 blocks at the canceled one.
        let canceled = task.new_sibling(0);
        let canceled_guest = Arc::clone(&canceled.thread.guest);
        let canceled = scope.spawn(move || {
            <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
                canceled.start_thread();
                cvwait(&canceled, blocked, 5 * INC, 3 * INC, 0, 0, BOUND_SECONDS, 0)
            })
        });
        await_psynch_waiters(&task, blocked, 1);
        await_interruptible(&canceled_guest);
        canceled_guest.flags.fetch_or(ut::CANCEL, Ordering::AcqRel);
        for round in 1..=BLOCKED_ROUNDS {
            let (l, s) = ((5 + round) * INC, (2 + round) * INC);
            assert_eq!(
                cvwait(&task, blocked, l, s, s, 0, 0, 1).map_err(|error| error & 0xff),
                Err(Errno::ETIMEDOUT.raw())
            );
            assert_eq!(cvsignal(&task, blocked, l, s + INC, l - INC, 0, 0), Ok(0));
        }
        let waiter = spawn_sibling(scope, &task, move |waiter| {
            cvwait(waiter, blocked, 4 * INC, 3 * INC, 0, 0, BOUND_SECONDS, 0)
        });
        // The queue's entries: the two threads and the preposts.
        let queued = 2 + BLOCKED_ROUNDS as usize;
        await_psynch_waiters(&task, blocked, queued);

        let held = 4 + 4 + (BEFORE + AFTER + BLOCKED_ROUNDS) as usize;
        assert_eq!(fakes(), held);
        let fillers = 0x20_0000;
        let mut lwords = fill_fake_budget(&task, fillers, PSYNCH_MAX_FAKES);
        let last = fillers + 8 * (lwords.len() - 1);
        let l = lwords.last_mut().unwrap();
        *l += INC;
        // Of `longer`'s runs 3..=4+BEFORE and 5+BEFORE..=4+BEFORE+AFTER the
        // two withheld waiters can reach only into each one's highest three;
        // the rest go. Nothing goes from `cv` or `blocked`.
        assert_eq!(
            cvsignal(&task, last, *l, 0, *l - INC, 0, 0),
            Ok(CV_PBIT as usize)
        );
        let dropped = (BEFORE as usize - 1) + (AFTER as usize - 3);
        assert_eq!(fakes(), PSYNCH_MAX_FAKES - dropped + 1);
        clear_fillers(&task, fillers, &lwords);
        assert_eq!(fakes(), held - dropped);

        // A late signal up to 6 merges into the prepost there.
        assert_eq!(
            cvsignal(&task, blocked, 6 * INC, 3 * INC, 5 * INC, 0, 0),
            Ok(0)
        );
        assert_eq!(task.global.psynch.lock().waiters(blocked), queued);
        canceled_guest.abort_safely();
        assert_eq!(
            canceled.join().unwrap().unwrap_err() & 0xff,
            Errno::EINTR.raw()
        );
        let l = (5 + BLOCKED_ROUNDS) * INC;
        assert_eq!(
            cvbroad(&task, blocked, l, l - INC, l - INC, 1, 0),
            Ok((INC | CV_CBIT) as usize)
        );
        assert_eq!(waiter.join().unwrap(), Ok(0));
    });
    for cv in [cv, longer] {
        assert_eq!(
            cvwait(&task, cv, 4 * INC, 0, 0, 0, 0, 1_000_000),
            Ok((INC | CV_PBIT) as usize)
        );
        assert_eq!(
            cvwait(&task, cv, 3 * INC, 0, 0, 0, 0, 1_000_000),
            Ok((INC | CV_CBIT) as usize)
        );
    }
    assert_eq!(fakes(), 0);
    assert_eq!(task.global.psynch.lock().queue_count(), 0);
}

/// `clock_get_time` on the system (uptime) and calendar clocks.
#[test]
fn clock_get_time_reads_uptime_and_calendar_time() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let host = trap(&task, mach_trap::HOST_SELF, &[]);
    let platform = Platform::new();
    let uptime = || {
        let timebase = platform.mach_timebase_info();
        Duration::from_nanos(
            u64::try_from(
                u128::from(platform.mach_absolute_time()) * u128::from(timebase.numer)
                    / u128::from(timebase.denom),
            )
            .unwrap(),
        )
    };
    let calendar = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
    };
    for (clock_id, now) in [(0, &uptime as &dyn Fn() -> Duration), (1, &calendar)] {
        let reply = mig_call(&task, host.trunc(), 206, &ndr(&[clock_id]), false);
        let clock = word(&reply, 28);
        let before = now();
        let reply = mig_call(&task, clock, 1000, &[], false);
        let after = now();
        assert_eq!(reply.len(), 44);
        assert_eq!(word(&reply, 32), 0);
        let read = Duration::new(u64::from(word(&reply, 36)), word(&reply, 40));
        assert!(
            before.saturating_sub(Duration::from_micros(1)) <= read
                && read <= after + Duration::from_micros(1),
            "{before:?} <= {read:?} <= {after:?}"
        );
        // A request with arguments is malformed.
        let reply = mig_call(&task, clock, 1000, &ndr(&[0]), false);
        assert_eq!(
            word(&reply, 32).cast_signed(),
            litebox_common_macos::mach::mig::BAD_ARGUMENTS
        );
    }
}
