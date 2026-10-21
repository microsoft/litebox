// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! psynch mutex, condition variable and rwlock calls against libpthread's
//! `kern/kern_synch.c`, driven through the syscall dispatcher with the
//! sequence words libpthread passes. Private objects are keyed by address
//! alone and their memory is never read, so most tests use bare addresses.

use super::mach::{bsd, new_task, trap};
use super::*;
use crate::syscalls::mm::hook;
use crate::syscalls::psynch::{ECVCLEARED, ECVPREPOST, PSYNCH_MAX_FAKES, PSYNCH_MAX_QUEUES};
use core::time::Duration;
use litebox_common_macos::{
    errno::Errno,
    syscall::{mach_trap, nr},
};
use std::time::Instant;

/// Two sequence words in one argument register, `high` above `low`.
fn pair(high: u32, low: u32) -> usize {
    (high as usize) << 32 | low as usize
}

/// Bounds every wait a test expects another thread to end.
const BOUND: Duration = Duration::from_secs(10);
/// A cvwait timeout that bounds a wait another thread should end.
const BOUND_SECONDS: usize = 10;

pub(super) const INC: u32 = 0x100;
pub(super) const KBIT: u32 = 0x01;
pub(super) const EBIT: u32 = 0x02;
const WBIT: u32 = 0x04;
const MBIT: u32 = 0x40;
const CV_CBIT: u32 = 0x01;
const CV_PBIT: u32 = 0x02;
/// Mutex options: first-fit and fair-share policies, process-shared, and
/// the mutex bit cvclrprepost reads.
pub(super) const FIRSTFIT: u32 = 0x080;
const FAIRSHARE: u32 = 0x040;
const PSHARED: u32 = 0x010;
const MUTEX: u32 = 0x2000;
const RWL_INIT: u32 = 0x80;

fn errno(error: Errno) -> Result<usize, usize> {
    Err(error.raw())
}

pub(super) fn mutexwait(
    task: &Task<Platform>,
    mutex: usize,
    mgen: u32,
    ugen: u32,
    tid: u64,
    flags: u32,
) -> Result<usize, usize> {
    bsd(
        task,
        nr::PSYNCH_MUTEXWAIT,
        &[
            mutex,
            mgen as usize,
            ugen as usize,
            usize::try_from(tid).unwrap(),
            flags as usize,
        ],
    )
}

pub(super) fn mutexdrop(
    task: &Task<Platform>,
    mutex: usize,
    mgen: u32,
    ugen: u32,
    flags: u32,
) -> Result<usize, usize> {
    bsd(
        task,
        nr::PSYNCH_MUTEXDROP,
        &[mutex, mgen as usize, ugen as usize, 0, flags as usize],
    )
}

fn lsgen(l: u32, s: u32) -> usize {
    pair(s, l)
}

/// `psynch_cvwait` without a mutex.
#[expect(clippy::too_many_arguments)]
pub(super) fn cvwait(
    task: &Task<Platform>,
    cv: usize,
    l: u32,
    s: u32,
    u: u32,
    flags: u32,
    seconds: usize,
    nanoseconds: u32,
) -> Result<usize, usize> {
    cvwait_mutex(task, cv, l, s, u, 0, 0, flags, seconds, nanoseconds)
}

#[expect(clippy::too_many_arguments)]
fn cvwait_mutex(
    task: &Task<Platform>,
    cv: usize,
    l: u32,
    s: u32,
    u: u32,
    mutex: usize,
    mugen: usize,
    flags: u32,
    seconds: usize,
    nanoseconds: u32,
) -> Result<usize, usize> {
    bsd(
        task,
        nr::PSYNCH_CVWAIT,
        &[
            cv,
            lsgen(l, s),
            u as usize,
            mutex,
            mugen,
            flags as usize,
            seconds,
            nanoseconds as usize,
        ],
    )
}

pub(super) fn cvsignal(
    task: &Task<Platform>,
    cv: usize,
    l: u32,
    s: u32,
    u: u32,
    port: usize,
    flags: u32,
) -> Result<usize, usize> {
    bsd(
        task,
        nr::PSYNCH_CVSIGNAL,
        &[cv, lsgen(l, s), u as usize, port, 0, 0, 0, flags as usize],
    )
}

pub(super) fn cvbroad(
    task: &Task<Platform>,
    cv: usize,
    l: u32,
    s: u32,
    old_u: u32,
    waiters: u32,
    flags: u32,
) -> Result<usize, usize> {
    let udgen = pair(old_u, waiters * INC);
    bsd(
        task,
        nr::PSYNCH_CVBROAD,
        &[cv, lsgen(l, s), udgen, flags as usize, 0, 0, 0],
    )
}

fn rw(
    task: &Task<Platform>,
    number: usize,
    rwlock: usize,
    l: u32,
    u: u32,
    s: u32,
) -> Result<usize, usize> {
    bsd(
        task,
        number,
        &[rwlock, l as usize, u as usize, s as usize, 0],
    )
}

/// Bounds a test's waits, most of which have no timeout: after [`BOUND`]
/// it releases every thread blocked in psynch (with a zero grant), on a
/// semaphore (as if it was destroyed) or in ulock until the test ends,
/// and then fails the test, so a broken implementation fails instead of
/// hanging.
pub(super) struct Watchdog {
    done: Arc<core::sync::atomic::AtomicBool>,
    fired: Arc<core::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    pub(super) fn new(task: &Task<Platform>) -> Self {
        use core::sync::atomic::{AtomicBool, Ordering};
        let done = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        let global = Arc::clone(&task.global);
        let thread = std::thread::spawn({
            let (done, fired) = (Arc::clone(&done), Arc::clone(&fired));
            move || {
                let start = Instant::now();
                while !done.load(Ordering::Acquire) {
                    if start.elapsed() >= BOUND {
                        let released = global.psynch.lock().release_all_waiters()
                            + global.semaphores.lock().release_all_waiters()
                            + global.ulocks.lock().release_all_waiters();
                        if released > 0 {
                            fired.store(true, Ordering::Release);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        });
        Self {
            done,
            fired,
            thread: Some(thread),
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        use core::sync::atomic::Ordering;
        self.done.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap();
        assert!(
            !self.fired.load(Ordering::Acquire) || std::thread::panicking(),
            "a wait was still blocked after {BOUND:?}"
        );
    }
}

/// Wait until `count` threads block on the private object at `address`.
pub(super) fn await_waiters(task: &Task<Platform>, address: usize, count: usize) {
    let start = Instant::now();
    while task.global.psynch.lock().waiters(address) != count {
        assert!(start.elapsed() < BOUND, "waiters never blocked");
        std::thread::yield_now();
    }
}

/// The calling thread's own port name.
fn own_port(task: &Task<Platform>) -> usize {
    trap(task, mach_trap::THREAD_SELF, &[])
}

#[test]
fn psynch_syscalls_decode_like_xnu() {
    use litebox_common_macos::syscall::{PsynchRwOperation, SyscallRequest};
    assert!(matches!(
        SyscallRequest::from_args(
            nr::PSYNCH_CVSIGNAL,
            [1, 0x2_0000_0300, 0x1_0000_0200, 0x103, 5, 6, 7, 0x2010]
        ),
        Ok(SyscallRequest::PsynchCvsignal {
            cv: 1,
            cvlsgen: 0x2_0000_0300,
            cvudgen: 0x200,
            thread_port: Some(litebox_common_macos::syscall::MachPortName(0x103)),
            flags: 0x2010,
        })
    ));
    assert!(matches!(
        SyscallRequest::from_args(
            nr::PSYNCH_CVWAIT,
            [1, 2, 3, 4, 5, 6, usize::MAX, 0x4000_0001]
        ),
        Ok(SyscallRequest::PsynchCvwait {
            seconds: -1,
            nanoseconds: 0x4000_0001,
            ..
        })
    ));
    assert!(matches!(
        SyscallRequest::from_args(nr::PSYNCH_RW_UNLOCK2, [1, 2, 3, 4, 5, 0, 0, 0]),
        Ok(SyscallRequest::PsynchRw {
            operation: PsynchRwOperation::Unlock2,
            ..
        })
    ));
}

/// XNU's answers for the rwlock calls libpthread no longer makes.
#[test]
fn unused_rwlock_calls_answer_like_xnu() {
    let task = new_task();
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_LONGRDLOCK, 0x1000, INC, 0, 0),
        errno(Errno::ESRCH)
    );
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_YIELDWRLOCK, 0x1000, INC, 0, 0),
        errno(Errno::ESRCH)
    );
    assert_eq!(rw(&task, nr::PSYNCH_RW_UPGRADE, 0x1000, INC, 0, 0), Ok(0));
    assert_eq!(rw(&task, nr::PSYNCH_RW_DOWNGRADE, 0x1000, INC, 0, 0), Ok(0));
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_UNLOCK2, 0x1000, INC, 0, 0),
        errno(Errno::ENOTSUP)
    );
    assert_eq!(task.global.psynch.lock().queue_count(), 0);
}

/// First fit: an unlock that finds no waiter is preposted, so a locker
/// that contended before it but reaches the kernel after it is not lost; an
/// unlock with a waiter grants it the lock and makes it the owner.
#[test]
fn first_fit_mutex_unlocks_prepost_or_grant() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let mutex = 0x1000;
    // L=0x203 (owner and one contender), U=0x100 after the unlock.
    assert_eq!(
        mutexdrop(&task, mutex, 0x200 | KBIT | EBIT, 0x100, FIRSTFIT),
        Ok(0)
    );
    assert_eq!(
        mutexwait(&task, mutex, 0x200 | KBIT | EBIT, 0, 0, FIRSTFIT),
        Ok((0x200 | KBIT | EBIT) as usize)
    );
    assert_eq!(task.global.psynch.lock().queue_count(), 0);

    std::thread::scope(|scope| {
        let waiter = task.new_sibling(0);
        let handle =
            scope.spawn(move || mutexwait(&waiter, mutex, 0x300 | KBIT | EBIT, 0x200, 0, FIRSTFIT));
        await_waiters(&task, mutex, 1);
        assert_eq!(
            mutexdrop(&task, mutex, 0x300 | KBIT | EBIT, 0x300, FIRSTFIT),
            Ok(0)
        );
        // The grant: the highest queued sequence with the lock bits.
        assert_eq!(handle.join().unwrap(), Ok((0x300 | KBIT | EBIT) as usize));
    });
    assert_eq!(task.global.psynch.lock().queue_count(), 0);
}

/// Fair share: an unlock grants the waiter whose sequence is next, even
/// out of arrival order; a prepost waits for exactly that sequence; a
/// second first-fit prepost on the same queue is the "more than one
/// prepost" EINVAL.
#[test]
fn fair_share_mutex_grants_the_next_sequence() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let mutex = 0x2000;
    std::thread::scope(|scope| {
        let later = task.new_sibling(0);
        let earlier = task.new_sibling(0);
        let later =
            scope.spawn(move || mutexwait(&later, mutex, 0x300 | KBIT | EBIT, 0, 0, FAIRSHARE));
        await_waiters(&task, mutex, 1);
        let earlier =
            scope.spawn(move || mutexwait(&earlier, mutex, 0x200 | KBIT | EBIT, 0, 0, FAIRSHARE));
        await_waiters(&task, mutex, 2);
        // U=0x100: the next sequence is 0x200, queued second.
        assert_eq!(
            mutexdrop(&task, mutex, 0x300 | KBIT | EBIT, 0x100, FAIRSHARE),
            Ok(0)
        );
        assert_eq!(earlier.join().unwrap(), Ok((0x300 | KBIT | EBIT) as usize));
        assert!(!later.is_finished());
        assert_eq!(
            mutexdrop(&task, mutex, 0x300 | KBIT | EBIT, 0x200, FAIRSHARE),
            Ok(0)
        );
        assert_eq!(later.join().unwrap(), Ok((0x300 | KBIT | EBIT) as usize));
    });

    // The next sequence queued behind a lower one is found and granted.
    std::thread::scope(|scope| {
        let low = task.new_sibling(0);
        let next = task.new_sibling(0);
        let low = scope.spawn(move || mutexwait(&low, mutex, 0x300 | KBIT | EBIT, 0, 0, FAIRSHARE));
        await_waiters(&task, mutex, 1);
        let next =
            scope.spawn(move || mutexwait(&next, mutex, 0x400 | KBIT | EBIT, 0, 0, FAIRSHARE));
        await_waiters(&task, mutex, 2);
        // U=0x300: the next sequence is 0x400, above the queue's lowest.
        assert_eq!(
            mutexdrop(&task, mutex, 0x400 | KBIT | EBIT, 0x300, FAIRSHARE),
            Ok(0)
        );
        assert_eq!(next.join().unwrap(), Ok((0x400 | KBIT | EBIT) as usize));
        assert!(!low.is_finished());
        assert_eq!(
            mutexdrop(&task, mutex, 0x400 | KBIT | EBIT, 0x200, FAIRSHARE),
            Ok(0)
        );
        assert_eq!(low.join().unwrap(), Ok((0x300 | KBIT | EBIT) as usize));
    });

    // A prepost for sequence 0x200 is not taken by a locker at 0x300.
    assert_eq!(mutexdrop(&task, mutex, 0x300, 0x100, FAIRSHARE), Ok(0));
    std::thread::scope(|scope| {
        let waiter = task.new_sibling(0);
        let handle = scope.spawn(move || mutexwait(&waiter, mutex, 0x300, 0x100, 0, FAIRSHARE));
        await_waiters(&task, mutex, 1);
        assert_eq!(
            mutexwait(&task, mutex, 0x200, 0x100, 0, FAIRSHARE),
            Ok((0x300 | KBIT | EBIT) as usize)
        );
        assert_eq!(mutexdrop(&task, mutex, 0x300, 0x200, FAIRSHARE), Ok(0));
        assert_eq!(handle.join().unwrap(), Ok((0x300 | KBIT | EBIT) as usize));
    });

    let mutex = 0x3000;
    assert_eq!(mutexdrop(&task, mutex, 0x200, 0x100, FIRSTFIT), Ok(0));
    assert_eq!(mutexdrop(&task, mutex, 0x200, 0x100, FIRSTFIT), Ok(0));
    assert_eq!(
        mutexwait(&task, mutex, 0x200, 0, 0, FAIRSHARE),
        errno(Errno::EINVAL)
    );
    // The remaining prepost now waits for the next sequence.
    assert_eq!(
        mutexwait(&task, mutex, 0x300, 0, 0, FAIRSHARE),
        Ok((0x300 | KBIT | EBIT) as usize)
    );
    assert_eq!(task.global.psynch.lock().queue_count(), 0);
}

/// A queue serves one kind of object at a time: a call of another kind on
/// an address in use fails with EINVAL.
#[test]
fn a_queue_in_use_refuses_another_kind() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let address = 0x4000;
    assert_eq!(mutexdrop(&task, address, 0x200, 0x100, FIRSTFIT), Ok(0));
    assert_eq!(
        cvsignal(&task, address, INC, 0, 0, 0, 0),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_UNLOCK, address, INC, 0, 0),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        mutexwait(&task, address, 0x200, 0, 0, FIRSTFIT),
        Ok((0x200 | KBIT | EBIT) as usize)
    );
    // Unused again, the address serves a condition variable.
    assert_eq!(
        cvsignal(&task, address, INC, 0, 0, 0, 0),
        Ok(CV_PBIT as usize)
    );
}

/// A signal wakes a waiter in its range; a signal before its waiter is a
/// prepost the waiter consumes; a balanced condition variable (L == S) is
/// cleared and says so with the C bit.
#[test]
fn cv_signal_wakes_or_preposts() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let cv = 0x5000;
    std::thread::scope(|scope| {
        let waiter = task.new_sibling(0);
        let handle = scope.spawn(move || cvwait(&waiter, cv, INC, 0, 0, 0, 0, 0));
        await_waiters(&task, cv, 1);
        assert_eq!(
            cvsignal(&task, cv, INC, 0, 0, 0, 0),
            Ok((INC | CV_CBIT) as usize)
        );
        assert_eq!(handle.join().unwrap(), Ok(0));
    });
    assert_eq!(task.global.psynch.lock().queue_count(), 0);

    assert_eq!(cvsignal(&task, cv, INC, 0, 0, 0, 0), Ok(CV_PBIT as usize));
    assert_eq!(task.global.psynch.lock().fake_count(), 1);
    assert_eq!(
        cvwait(&task, cv, INC, 0, 0, 0, 0, 0),
        Ok((INC | CV_CBIT) as usize)
    );
    assert_eq!(task.global.psynch.lock().fake_count(), 0);
    assert_eq!(task.global.psynch.lock().queue_count(), 0);

    // S beyond L is EINVAL for a waiter and a signaler.
    assert_eq!(
        cvwait(&task, cv, INC, INC, 0, 0, 0, 0),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        cvsignal(&task, cv, INC, 2 * INC, 0, 0, 0),
        errno(Errno::EINVAL)
    );
}

/// A broadcast wakes every waiter up to L, without a mutex.
#[test]
fn cv_broadcast_wakes_every_waiter() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let cv = 0x6000;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (1..=3)
            .map(|i| {
                let waiter = task.new_sibling(0);
                let handle = scope.spawn(move || cvwait(&waiter, cv, i * INC, 0, 0, 0, 0, 0));
                await_waiters(&task, cv, i as usize);
                handle
            })
            .collect();
        assert_eq!(
            cvbroad(&task, cv, 3 * INC, 0, 0, 3, 0),
            Ok(((3 * INC) | CV_CBIT) as usize)
        );
        for handle in handles {
            assert_eq!(handle.join().unwrap(), Ok(0));
        }
    });
    assert_eq!(task.global.psynch.lock().fake_count(), 0);
    // More waiters than a task can have threads is EBUSY.
    assert_eq!(
        cvbroad(
            &task,
            cv,
            3 * INC,
            0,
            0,
            crate::thread::TASK_THREADMAX + 1,
            0
        ),
        errno(Errno::EBUSY)
    );
}

/// A signal to a thread wakes it; a thread that does not wait there turns
/// the signal into a broadcast; an unknown port is ESRCH.
#[test]
fn cv_signal_to_a_thread() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let cv = 0x7000;
    std::thread::scope(|scope| {
        let first = task.new_sibling(0);
        let second = task.new_sibling(0);
        let (port, port_rx) = std::sync::mpsc::channel();
        let first = scope.spawn(move || cvwait(&first, cv, INC, 0, 0, 0, 0, 0));
        await_waiters(&task, cv, 1);
        let second = scope.spawn(move || {
            port.send(own_port(&second)).unwrap();
            cvwait(&second, cv, 2 * INC, 0, 0, 0, 0, 0)
        });
        await_waiters(&task, cv, 2);
        let port = port_rx.recv_timeout(BOUND).unwrap();
        assert_eq!(
            cvsignal(&task, cv, 2 * INC, 0, 0, port, 0),
            Ok(INC as usize)
        );
        assert_eq!(second.join().unwrap(), Ok(0));
        assert!(!first.is_finished());
        // The caller does not wait here: the signal wakes everyone.
        let own = own_port(&task);
        assert_eq!(
            cvsignal(&task, cv, 2 * INC, INC, INC, own, 0),
            Ok((INC | CV_CBIT) as usize)
        );
        assert_eq!(first.join().unwrap(), Ok(0));
    });
    assert_eq!(
        cvsignal(&task, cv, INC, 0, 0, 0x1234_5603, 0),
        errno(Errno::ESRCH)
    );
}

/// A timed-out wait counts itself returned in S: it reports ECVCLEARED
/// when that balances the condition variable and ECVPREPOST when only
/// preposts remain, above ETIMEDOUT in x0.
#[test]
fn cv_timeouts_report_cleared_and_prepost_bits() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let cv = 0x8000;
    let start = Instant::now();
    assert_eq!(
        cvwait(&task, cv, INC, 0, 0, 0, 0, 20_000_000),
        Err(Errno::ETIMEDOUT.raw() | ECVCLEARED as usize)
    );
    assert!(start.elapsed() >= Duration::from_millis(20));
    assert_eq!(task.global.psynch.lock().queue_count(), 0);

    // A prepost below the waiter's sequence stays queued.
    assert_eq!(cvsignal(&task, cv, INC, 0, 0, 0, 0), Ok(CV_PBIT as usize));
    assert_eq!(
        cvwait(&task, cv, 2 * INC, 0, 0, 0, 0, 20_000_000),
        Err(Errno::ETIMEDOUT.raw() | ECVPREPOST as usize)
    );
    // The bits do not stick to a later failure.
    assert_eq!(
        cvwait(&task, cv, INC, INC, 0, 0, 0, 0),
        errno(Errno::EINVAL)
    );
    // cvclrprepost drops the prepost.
    assert_eq!(
        bsd(
            &task,
            nr::PSYNCH_CVCLRPREPOST,
            &[
                cv,
                2 * INC as usize,
                0,
                INC as usize,
                0,
                2 * INC as usize,
                0
            ]
        ),
        Ok(0)
    );
    assert_eq!(task.global.psynch.lock().fake_count(), 0);
}

/// A waiter whose timeout passes as a signal takes it is granted: the
/// signal is not lost and the wait succeeds, as if the signal came first.
#[test]
fn cv_wait_timing_out_as_a_signal_takes_it_succeeds() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let cv = 0x9000;
    std::thread::scope(|scope| {
        let signaler = task.new_sibling(0);
        let (go, start) = std::sync::mpsc::channel::<()>();
        let (report, done) = std::sync::mpsc::channel();
        let handle = scope.spawn(move || {
            <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
                start.recv_timeout(BOUND).unwrap();
                report
                    .send(cvsignal(&signaler, cv, INC, 0, 0, 0, 0))
                    .unwrap();
            });
        });
        let mut go = Some(go);
        let signal = std::sync::Arc::new(std::sync::Mutex::new(None));
        let result = std::sync::Arc::clone(&signal);
        task.global.mapping_hook.set(move |point| {
            if point == hook::Point::PsynchWaited {
                go.take().unwrap().send(()).unwrap();
                *result.lock().unwrap() = Some(done.recv_timeout(BOUND).unwrap());
            }
        });
        let waited = cvwait(&task, cv, INC, 0, 0, 0, 0, 1_000_000);
        task.global.mapping_hook.clear();
        handle.join().unwrap();
        assert_eq!(*signal.lock().unwrap(), Some(Ok((INC | CV_CBIT) as usize)));
        assert_eq!(waited, Ok(0));
    });
    assert_eq!(task.global.psynch.lock().queue_count(), 0);
}

/// cvwait releases the mutex when its unlock must notify the kernel: it
/// grants the thread blocked on the mutex, whose signal then reaches the
/// condition variable's waiter (queued, or as a prepost it consumes).
#[test]
fn cv_wait_releases_the_mutex_to_its_waiter() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let (cv, mutex) = (0xa000, 0xb000);
    std::thread::scope(|scope| {
        let locker = task.new_sibling(0);
        let waiter = task.new_sibling(0);
        let locker = scope.spawn(move || {
            let acquired = mutexwait(&locker, mutex, 0x200 | KBIT | EBIT, 0, 0, FIRSTFIT);
            (acquired, cvsignal(&locker, cv, INC, 0, 0, 0, 0))
        });
        await_waiters(&task, mutex, 1);
        let mugen = pair(0x100, 0x200 | KBIT | EBIT);
        let cv_waiter = scope.spawn(move || {
            cvwait_mutex(
                &waiter,
                cv,
                INC,
                0,
                0,
                mutex,
                mugen,
                FIRSTFIT,
                BOUND_SECONDS,
                0,
            )
        });
        let (acquired, signaled) = locker.join().unwrap();
        assert_eq!(acquired, Ok((0x200 | KBIT | EBIT) as usize));
        // The waiter was queued (the signal balances the condition variable)
        // or not yet (the signal is preposted for it).
        assert!(
            matches!(signaled.map(|bits| bits & 0xff), Ok(bits) if bits == CV_CBIT as usize || bits == CV_PBIT as usize),
            "{signaled:?}"
        );
        assert!(cv_waiter.join().unwrap().is_ok());
    });
    assert_eq!(task.global.psynch.lock().queue_count(), 0);
}

/// An rwlock unlock grants the readers before the first writer, then the
/// writer; an unlock before its waiter preposts, and the waiter takes it.
#[test]
fn rwlock_unlock_hands_off_to_readers_then_writers() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let rwlock = 0xc000;
    std::thread::scope(|scope| {
        let reader = task.new_sibling(0);
        let writer = task.new_sibling(0);
        let late_reader = task.new_sibling(0);
        let reader =
            scope.spawn(move || rw(&reader, nr::PSYNCH_RW_RDLOCK, rwlock, 0x200, 0x100, 0));
        await_waiters(&task, rwlock, 1);
        let writer =
            scope.spawn(move || rw(&writer, nr::PSYNCH_RW_WRLOCK, rwlock, 0x300, 0x100, 0));
        await_waiters(&task, rwlock, 2);
        let late_reader =
            scope.spawn(move || rw(&late_reader, nr::PSYNCH_RW_RDLOCK, rwlock, 0x400, 0x100, 0));
        await_waiters(&task, rwlock, 3);
        // The owner's unlock accounts for three waiters: the reader before
        // the writer gets the lock, with the writer pending.
        let grant = INC | WBIT | KBIT;
        assert_eq!(
            rw(&task, nr::PSYNCH_RW_UNLOCK, rwlock, 0x400, 0x100, 0x100),
            Ok(grant as usize)
        );
        assert_eq!(reader.join().unwrap(), Ok(grant as usize));
        assert!(!writer.is_finished() && !late_reader.is_finished());
        // The reader's unlock grants the writer, which the later reader
        // still follows.
        let grant = INC | KBIT | EBIT;
        assert_eq!(
            rw(&task, nr::PSYNCH_RW_UNLOCK, rwlock, 0x400, 0x200, 0x200),
            Ok(grant as usize)
        );
        assert_eq!(writer.join().unwrap(), Ok(grant as usize));
        assert_eq!(
            rw(&task, nr::PSYNCH_RW_UNLOCK, rwlock, 0x400, 0x300, 0x300),
            Ok(INC as usize)
        );
        assert_eq!(late_reader.join().unwrap(), Ok(INC as usize));
    });

    // An unlock that finds its reader not yet arrived preposts; the reader
    // takes the grant on arrival.
    let rwlock = 0xd000;
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_UNLOCK, rwlock, 0x200, 0x100, 0x100),
        Ok(0x200)
    );
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_RDLOCK, rwlock, 0x200, 0x100, 0x100),
        Ok(INC as usize)
    );
    // Readers alone: a later reader within the grant overlaps it.
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_RDLOCK, rwlock, 0x300, 0x100, 0x100),
        Ok((INC | MBIT) as usize)
    );
}

/// An idle rwlock queue keeps its last unlock for `KSYN_CLEANUP_DEADLINE`:
/// within it an older unlock is spurious; after it the state is gone.
#[test]
fn idle_rwlock_state_expires() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let rwlock = 0xe000;
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_UNLOCK, rwlock, 0x300, 0x200, 0x200),
        Ok(0x300)
    );
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_RDLOCK, rwlock, 0x300, 0x200, 0x200),
        Ok(INC as usize)
    );
    // The grant recorded unlock sequence 0x200: an unlock below it is
    // spurious and changes nothing.
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_UNLOCK, rwlock, 0x200, 0x100, 0x100),
        Ok(0)
    );
    assert_eq!(task.global.psynch.lock().queue_count(), 1);
    let expiry = task.psynch_cleanup_ticks();
    task.global.psynch.lock().age_idle_queues(expiry);
    // The state expired: the same unlock now preposts.
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_UNLOCK, rwlock, 0x200, 0x100, 0x100),
        Ok(0x200)
    );
    // A reinitialized lock (I bit) clears the state on first sight.
    assert_eq!(
        rw(
            &task,
            nr::PSYNCH_RW_UNLOCK,
            rwlock,
            0x200 | RWL_INIT,
            0x100,
            0x100
        ),
        Ok(0x200 | RWL_INIT as usize)
    );
}

/// The table holds at most `PSYNCH_MAX_QUEUES` queues and the condition
/// variables `PSYNCH_MAX_FAKES` preposts; beyond either a call fails with
/// ENOMEM, idle rwlock queues are freed early to make room, and freed
/// entries return to the budget.
#[test]
fn psynch_tables_are_bounded() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    // Preposted mutex unlocks hold queues.
    for i in 0..PSYNCH_MAX_QUEUES {
        assert_eq!(
            mutexdrop(&task, 0x10_0000 + 8 * i, 0x200, 0x100, FIRSTFIT),
            Ok(0)
        );
    }
    assert_eq!(
        mutexdrop(&task, 0x1, 0x200, 0x100, FIRSTFIT),
        errno(Errno::ENOMEM)
    );
    // An existing queue is still found.
    assert_eq!(
        mutexwait(&task, 0x10_0000, 0x200, 0, 0, FIRSTFIT),
        Ok((0x200 | KBIT | EBIT) as usize)
    );
    // Its slot is free again; an idle rwlock queue takes it and is freed
    // early when the table is full again.
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_UNLOCK, 0x2, 0x300, 0x200, 0x200),
        Ok(0x300)
    );
    assert_eq!(
        rw(&task, nr::PSYNCH_RW_RDLOCK, 0x2, 0x300, 0x200, 0x200),
        Ok(INC as usize)
    );
    assert_eq!(task.global.psynch.lock().queue_count(), PSYNCH_MAX_QUEUES);
    assert_eq!(mutexdrop(&task, 0x1, 0x200, 0x100, FIRSTFIT), Ok(0));
    assert_eq!(task.global.psynch.lock().queue_count(), PSYNCH_MAX_QUEUES);
    for i in 1..PSYNCH_MAX_QUEUES {
        assert_eq!(
            mutexwait(&task, 0x10_0000 + 8 * i, 0x200, 0, 0, FIRSTFIT),
            Ok((0x200 | KBIT | EBIT) as usize)
        );
    }
    assert_eq!(
        mutexwait(&task, 0x1, 0x200, 0, 0, FIRSTFIT),
        Ok((0x200 | KBIT | EBIT) as usize)
    );
    assert_eq!(task.global.psynch.lock().queue_count(), 0);

    // Signals at ever higher sequences each prepost.
    let cv = 0x3;
    let mut l = 0;
    for _ in 0..PSYNCH_MAX_FAKES {
        l += INC;
        assert_eq!(
            cvsignal(&task, cv, l, 0, l - INC, 0, 0),
            Ok(CV_PBIT as usize)
        );
    }
    assert_eq!(
        cvsignal(&task, cv, l + INC, 0, l, 0, 0),
        errno(Errno::ENOMEM)
    );
    assert_eq!(task.global.psynch.lock().fake_count(), PSYNCH_MAX_FAKES);
    // A broadcast folds them into one entry.
    assert_eq!(cvbroad(&task, cv, l, 0, 0, 0, 0), Ok(CV_PBIT as usize));
    assert_eq!(task.global.psynch.lock().fake_count(), 1);
    assert_eq!(
        bsd(
            &task,
            nr::PSYNCH_CVCLRPREPOST,
            &[cv, l as usize, 0, 0, 0, l as usize, 0]
        ),
        Ok(0)
    );
    assert_eq!(task.global.psynch.lock().fake_count(), 0);
    assert_eq!(task.global.psynch.lock().queue_count(), 0);
    // cvclrprepost of a mutex clears its first-fit prepost.
    assert_eq!(mutexdrop(&task, 0x4, 0x200, 0x100, FIRSTFIT), Ok(0));
    assert_eq!(
        bsd(
            &task,
            nr::PSYNCH_CVCLRPREPOST,
            &[0x4, 0x200, 0x100, 0, 0, 0, (MUTEX | FIRSTFIT) as usize]
        ),
        Ok(0)
    );
    assert_eq!(task.global.psynch.lock().queue_count(), 0);
}

/// Process-shared objects are keyed by the mapping: an unmapped address is
/// EINVAL, and a mapping change drops the old object's preposts while the
/// table is held, so no call meets them through the new mapping.
#[test]
fn shared_objects_go_with_their_mapping() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    let mut address = 0x7b_0000_0000usize;
    assert_eq!(
        super::mach::kr(
            &task,
            mach_trap::MACH_VM_ALLOCATE,
            &[own, (&raw mut address) as usize, PAGE_SIZE, 0]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(
        cvsignal(&task, address, INC, 0, 0, 0, PSHARED),
        Ok(CV_PBIT as usize)
    );
    let global = Arc::clone(&task.global);
    let (held, probe) = std::sync::mpsc::channel();
    task.global.mapping_hook.set(move |point| {
        if point == hook::Point::MappingsChanged {
            let held_now = std::thread::scope(|scope| {
                scope
                    .spawn(|| global.psynch.try_lock().is_none())
                    .join()
                    .unwrap()
            });
            held.send(held_now).unwrap();
        }
    });
    assert_eq!(bsd(&task, nr::MUNMAP, &[address, PAGE_SIZE]), Ok(0));
    task.global.mapping_hook.clear();
    assert!(probe.try_recv().unwrap(), "the psynch table was not held");
    assert_eq!(task.global.psynch.lock().fake_count(), 0);
    assert_eq!(
        cvsignal(&task, address, INC, 0, 0, 0, PSHARED),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        cvwait(&task, address, INC, 0, 0, PSHARED, 0, 1_000_000),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        super::mach::kr(
            &task,
            mach_trap::MACH_VM_ALLOCATE,
            &[own, (&raw mut address) as usize, PAGE_SIZE, 0]
        ),
        KernReturn::SUCCESS
    );
    assert_eq!(
        cvwait(&task, address, INC, 0, 0, PSHARED, 0, 1_000_000),
        Err(Errno::ETIMEDOUT.raw() | ECVCLEARED as usize)
    );
    // A private object at the same address is a different queue.
    assert_eq!(
        cvsignal(&task, address, INC, 0, 0, 0, PSHARED),
        Ok(CV_PBIT as usize)
    );
    assert_eq!(
        cvwait(&task, address, INC, 0, 0, 0, 0, 1_000_000),
        Err(Errno::ETIMEDOUT.raw() | ECVCLEARED as usize)
    );
    assert_eq!(
        cvwait(&task, address, INC, 0, 0, PSHARED, 0, 0),
        Ok((INC | CV_CBIT) as usize)
    );
    assert_eq!(task.global.psynch.lock().queue_count(), 0);
}

/// Process exit ends threads blocked on a mutex, a condition variable and
/// an rwlock with EINTR, and each ends at its next shim entry.
#[test]
fn process_exit_ends_psynch_waits() {
    let task = new_task();
    let _watchdog = Watchdog::new(&task);
    let addresses = [0xf000, 0xf100, 0xf200];
    std::thread::scope(|scope| {
        let handles: Vec<_> = addresses
            .iter()
            .enumerate()
            .map(|(index, &address)| {
                let waiter = task.new_sibling(0);
                scope.spawn(move || {
                    <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
                        waiter.start_thread();
                        let result = match index {
                            0 => mutexwait(&waiter, address, 0x200 | KBIT | EBIT, 0, 0, FIRSTFIT),
                            1 => cvwait(&waiter, address, INC, 0, 0, 0, 0, 0),
                            _ => rw(&waiter, nr::PSYNCH_RW_WRLOCK, address, 0x200, 0x100, 0),
                        };
                        (result, waiter.continuation(&PtRegs::default()))
                    })
                })
            })
            .collect();
        for address in addresses {
            await_waiters(&task, address, 1);
        }
        while task
            .process
            .0
            .threads
            .lock()
            .values()
            .filter(|thread| thread.interrupt.lock().is_some())
            .count()
            < 3
        {
            std::thread::yield_now();
        }
        assert_eq!(bsd(&task, nr::EXIT, &[7]), Ok(0));
        for handle in handles {
            let (result, next) = handle.join().unwrap();
            assert_eq!(next, ContinueOperation::Terminate);
            // The condition variable's waiter also reports ECVCLEARED.
            assert_eq!(result.unwrap_err() & 0xff, Errno::EINTR.raw());
        }
    });
    for address in addresses {
        assert_eq!(task.global.psynch.lock().waiters(address), 0);
    }
}
