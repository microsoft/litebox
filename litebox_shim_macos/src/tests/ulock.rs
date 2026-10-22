// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `ulock_wait`/`ulock_wake` results against `bsd/kern/sys_ulock.c`, driven
//! through the syscall dispatcher. Other guest threads are sibling tasks on
//! host test threads.

use super::mach::{bsd, guest_page, new_task, trap};
use super::thread::port_of;
use super::*;
use core::time::Duration;
use litebox::utils::TruncateExt as _;
use litebox_common_macos::{
    MachClock as _,
    errno::Errno,
    syscall::{mach_trap, nr},
    user_pointers::UserPtrMut,
};
use std::time::Instant;

pub(super) const UL_COMPARE_AND_WAIT: usize = 1;
pub(super) const UL_UNFAIR_LOCK: usize = 2;
const UL_UNFAIR_LOCK64_SHARED: usize = 4;
const UL_COMPARE_AND_WAIT64: usize = 5;
pub(super) const ULF_WAKE_ALL: usize = 0x100;
const ULF_WAKE_THREAD: usize = 0x200;
const ULF_WAKE_ALLOW_NON_OWNER: usize = 0x400;
const ULF_WAIT_WORKQ_DATA_CONTENTION: usize = 0x1_0000;
const ULF_WAIT_CANCEL_POINT: usize = 0x2_0000;
const ULF_WAIT_ADAPTIVE_SPIN: usize = 0x4_0000;
pub(super) const ULF_NO_ERRNO: usize = 0x100_0000;
const ULF_DEADLINE: usize = 0x200_0000;
/// Bounds every wait a test expects another thread to end, so a failing
/// test ends with ETIMEDOUT instead of hanging.
pub(super) const BOUND: Duration = Duration::from_secs(10);
/// [`BOUND`] in microseconds, as `ulock_wait` takes it.
pub(super) const BOUND_US: usize = 10_000_000;

pub(super) fn ulock_wait(
    task: &Task<Platform>,
    operation: usize,
    address: usize,
    value: usize,
    timeout_us: usize,
) -> Result<usize, usize> {
    bsd(
        task,
        nr::ULOCK_WAIT,
        &[operation, address, value, timeout_us],
    )
}

fn ulock_wait2(
    task: &Task<Platform>,
    operation: usize,
    address: usize,
    value: usize,
    timeout: usize,
) -> Result<usize, usize> {
    bsd(
        task,
        nr::ULOCK_WAIT2,
        &[operation, address, value, timeout, 0],
    )
}

pub(super) fn ulock_wake(
    task: &Task<Platform>,
    operation: usize,
    address: usize,
    value: usize,
) -> Result<usize, usize> {
    bsd(task, nr::ULOCK_WAKE, &[operation, address, value])
}

pub(super) fn errno(error: Errno) -> Result<usize, usize> {
    Err(error.raw())
}

/// A `ULF_NO_ERRNO` error result: the negated errno, sign-extended.
pub(super) fn negative(error: Errno) -> usize {
    (-(error as isize)).cast_unsigned()
}

/// Wait until `count` threads block on the lock word `address`.
pub(super) fn await_waiters(task: &Task<Platform>, address: usize, count: u32) {
    let start = Instant::now();
    while task.global.ulocks.lock().waiters(address) != count {
        assert!(start.elapsed() < BOUND, "waiters never blocked");
        std::thread::yield_now();
    }
}

#[test]
fn ulock_validates_operations_flags_and_addresses() {
    let task = new_task();
    let page = guest_page(&task);
    // Unknown operations, flags, and unaligned or null addresses. The
    // opcode switches of sys_ulock.c ulock_wait2 and ulock_wake accept no
    // UL_UNFAIR_LOCK64_SHARED (4).
    for operation in [0, UL_UNFAIR_LOCK64_SHARED, 7, UL_COMPARE_AND_WAIT | 0x100] {
        assert_eq!(
            ulock_wait(&task, operation, page, 0, 0),
            errno(Errno::EINVAL)
        );
    }
    for operation in [0, UL_UNFAIR_LOCK64_SHARED, UL_COMPARE_AND_WAIT | 0x1_0000] {
        assert_eq!(ulock_wake(&task, operation, page, 0), errno(Errno::EINVAL));
    }
    assert_eq!(
        ulock_wait(&task, UL_COMPARE_AND_WAIT, 0, 0, 0),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        ulock_wait(&task, UL_COMPARE_AND_WAIT64, page + 4, 0, 0),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        ulock_wake(&task, UL_COMPARE_AND_WAIT, 0, 0),
        errno(Errno::EINVAL)
    );
    // ULF_WAKE_THREAD excludes ULF_WAKE_ALL and unfair locks;
    // ULF_WAKE_ALLOW_NON_OWNER needs an unfair lock.
    for operation in [
        UL_COMPARE_AND_WAIT | ULF_WAKE_THREAD | ULF_WAKE_ALL,
        UL_UNFAIR_LOCK | ULF_WAKE_THREAD,
        UL_COMPARE_AND_WAIT | ULF_WAKE_ALLOW_NON_OWNER,
    ] {
        assert_eq!(ulock_wake(&task, operation, page, 0), errno(Errno::EINVAL));
    }
    assert_eq!(
        ulock_wait(&task, UL_COMPARE_AND_WAIT, PAGE_SIZE, 0, 0),
        errno(Errno::EFAULT)
    );
    // A changed value returns at once with no other waiters; every accepted
    // wait flag is allowed.
    for flags in [
        0,
        ULF_WAIT_WORKQ_DATA_CONTENTION | ULF_WAIT_CANCEL_POINT,
        ULF_WAIT_ADAPTIVE_SPIN,
    ] {
        assert_eq!(ulock_wait(&task, UL_UNFAIR_LOCK | flags, page, 1, 0), Ok(0));
    }
    // No waiter: ENOENT, or its negation without errno.
    assert_eq!(
        ulock_wake(&task, UL_COMPARE_AND_WAIT, page, 0),
        errno(Errno::ENOENT)
    );
    assert_eq!(
        ulock_wake(&task, UL_COMPARE_AND_WAIT | ULF_NO_ERRNO, page, 0),
        Ok(negative(Errno::ENOENT))
    );
    assert_eq!(
        ulock_wait(&task, UL_COMPARE_AND_WAIT | ULF_NO_ERRNO, 0, 0, 0),
        Ok(negative(Errno::EINVAL))
    );
    assert_eq!(task.global.ulocks.lock().waiters(page), 0);
}

/// `ulock_wait` times out in microseconds, `ulock_wait2` in nanoseconds or,
/// with `ULF_DEADLINE`, at a `mach_absolute_time` deadline, which a wake
/// before it ends early.
#[test]
fn ulock_waits_time_out() {
    let task = new_task();
    let page = guest_page(&task);
    let start = Instant::now();
    assert_eq!(
        ulock_wait(&task, UL_COMPARE_AND_WAIT, page, 0, 20_000),
        errno(Errno::ETIMEDOUT)
    );
    assert!(start.elapsed() >= Duration::from_millis(20));
    assert_eq!(
        ulock_wait2(
            &task,
            UL_COMPARE_AND_WAIT64 | ULF_NO_ERRNO,
            page,
            0,
            1_000_000
        ),
        Ok(negative(Errno::ETIMEDOUT))
    );
    let platform = task.global.platform;
    let deadline_in = |duration: Duration| {
        let timebase = platform.mach_timebase_info();
        let ticks = duration.as_nanos() * u128::from(timebase.denom) / u128::from(timebase.numer);
        (platform.mach_absolute_time() + u64::try_from(ticks).unwrap()).trunc()
    };
    let past: usize = platform.mach_absolute_time().trunc();
    assert_eq!(
        ulock_wait2(&task, UL_COMPARE_AND_WAIT | ULF_DEADLINE, page, 0, past),
        errno(Errno::ETIMEDOUT)
    );
    let start = Instant::now();
    assert_eq!(
        ulock_wait2(
            &task,
            UL_COMPARE_AND_WAIT | ULF_DEADLINE,
            page,
            0,
            deadline_in(Duration::from_millis(50))
        ),
        errno(Errno::ETIMEDOUT)
    );
    assert!(start.elapsed() >= Duration::from_millis(50));
    std::thread::scope(|scope| {
        let waiter = task.new_sibling(0);
        let deadline = deadline_in(BOUND);
        let handle = scope.spawn(move || {
            ulock_wait2(
                &waiter,
                UL_COMPARE_AND_WAIT | ULF_DEADLINE,
                page,
                0,
                deadline,
            )
        });
        await_waiters(&task, page, 1);
        assert_eq!(ulock_wake(&task, UL_COMPARE_AND_WAIT, page, 0), Ok(0));
        assert_eq!(handle.join().unwrap(), Ok(0));
    });
    assert_eq!(task.global.ulocks.lock().waiters(page), 0);
}

/// A wait that finds the value changed after joining the lock's record
/// returns the waiters that remain, like any other exit through
/// `ulock_wait_cleanup`.
#[test]
fn ulock_wait_on_a_changed_value_returns_the_remaining_waiters() {
    let task = new_task();
    let page = guest_page(&task);
    std::thread::scope(|scope| {
        let blocked = task.new_sibling(0);
        let handle =
            scope.spawn(move || ulock_wait(&blocked, UL_COMPARE_AND_WAIT, page, 0, BOUND_US));
        await_waiters(&task, page, 1);
        assert_eq!(ulock_wait(&task, UL_COMPARE_AND_WAIT, page, 1, 0), Ok(1));
        assert_eq!(
            ulock_wait(&task, UL_UNFAIR_LOCK, page, 1, 0),
            errno(Errno::EDOM)
        );
        assert_eq!(ulock_wake(&task, UL_COMPARE_AND_WAIT, page, 0), Ok(0));
        assert_eq!(handle.join().unwrap(), Ok(0));
    });
    assert_eq!(ulock_wait(&task, UL_COMPARE_AND_WAIT, page, 1, 0), Ok(0));
}

#[test]
fn ulock_wakes_one_all_or_a_named_thread() {
    let task = new_task();
    let page = guest_page(&task);
    // Wake one: the waiter returns the waiters left (none).
    std::thread::scope(|scope| {
        let waiter = task.new_sibling(0);
        let handle =
            scope.spawn(move || ulock_wait(&waiter, UL_COMPARE_AND_WAIT, page, 0, BOUND_US));
        await_waiters(&task, page, 1);
        // The wake's operation must match the waiters' (EDOM).
        assert_eq!(
            ulock_wake(&task, UL_COMPARE_AND_WAIT64, page, 0),
            errno(Errno::EDOM)
        );
        assert_eq!(ulock_wake(&task, UL_COMPARE_AND_WAIT, page, 0), Ok(0));
        assert_eq!(handle.join().unwrap(), Ok(0));
    });
    // Wake all: each waiter reports the waiters still in the call.
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let waiter = task.new_sibling(0);
                scope.spawn(move || ulock_wait(&waiter, UL_COMPARE_AND_WAIT, page, 0, BOUND_US))
            })
            .collect();
        await_waiters(&task, page, 3);
        assert_eq!(
            ulock_wake(&task, UL_COMPARE_AND_WAIT | ULF_WAKE_ALL, page, 0),
            Ok(0)
        );
        let mut left: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        left.sort_unstable();
        assert_eq!(left, [Ok(0), Ok(1), Ok(2)]);
    });
    // Wake a named thread; it must be another thread that waits here.
    std::thread::scope(|scope| {
        let first = task.new_sibling(0);
        let second = task.new_sibling(0);
        let idle = task.new_sibling(0);
        let second_port = port_of(&task, &second);
        let first_port = port_of(&task, &first);
        let idle_port = port_of(&task, &idle);
        let own = trap(&task, mach_trap::THREAD_SELF, &[]);
        let a = scope.spawn(move || ulock_wait(&first, UL_COMPARE_AND_WAIT, page, 0, BOUND_US));
        await_waiters(&task, page, 1);
        let b = scope.spawn(move || ulock_wait(&second, UL_COMPARE_AND_WAIT, page, 0, BOUND_US));
        await_waiters(&task, page, 2);
        let wake_thread = UL_COMPARE_AND_WAIT | ULF_WAKE_THREAD;
        assert_eq!(
            ulock_wake(&task, wake_thread, page, own),
            errno(Errno::ESRCH)
        );
        assert_eq!(
            ulock_wake(&task, wake_thread, page, 0x7703),
            errno(Errno::ESRCH)
        );
        // A live thread that is not waiting here.
        assert_eq!(
            ulock_wake(&task, wake_thread, page, idle_port),
            errno(Errno::EALREADY)
        );
        assert_eq!(ulock_wake(&task, wake_thread, page, second_port), Ok(0));
        assert_eq!(b.join().unwrap(), Ok(1));
        await_waiters(&task, page, 1);
        // The woken thread no longer waits; the other still does.
        assert_eq!(
            ulock_wake(&task, wake_thread, page, second_port),
            errno(Errno::ESRCH),
            "the woken thread has terminated"
        );
        assert_eq!(ulock_wake(&task, wake_thread, page, first_port), Ok(0));
        assert_eq!(a.join().unwrap(), Ok(0));
    });
    assert_eq!(task.global.ulocks.lock().waiters(page), 0);
}

#[test]
fn unfair_lock_waits_follow_the_owner_rules() {
    let task = new_task();
    let page = guest_page(&task);
    let word = UserPtrMut::<u32>::from_usize(page);
    let own = trap(&task, mach_trap::THREAD_SELF, &[]);
    // The lock value names the calling thread itself, or no thread.
    word.write_at_offset::<Platform>(0, own.trunc()).unwrap();
    assert_eq!(
        ulock_wait(&task, UL_UNFAIR_LOCK, page, own, 0),
        errno(Errno::EOWNERDEAD)
    );
    word.write_at_offset::<Platform>(0, 0x7702).unwrap();
    assert_eq!(
        ulock_wait(&task, UL_UNFAIR_LOCK | ULF_NO_ERRNO, page, 0x7702, 0),
        Ok(negative(Errno::EOWNERDEAD))
    );
    // The waiter blocks behind this thread (the owner), whose wake hands the
    // lock to it; the low bits of the value are the waiters bits.
    let owner_value = own & !0x1;
    word.write_at_offset::<Platform>(0, owner_value.trunc())
        .unwrap();
    std::thread::scope(|scope| {
        let waiter = task.new_sibling(0);
        let not_owner = task.new_sibling(0);
        let handle =
            scope.spawn(move || ulock_wait(&waiter, UL_UNFAIR_LOCK, page, owner_value, BOUND_US));
        await_waiters(&task, page, 1);
        // A wake by a thread that is not the owner is late: nothing happens.
        assert_eq!(ulock_wake(&not_owner, UL_UNFAIR_LOCK, page, 0), Ok(0));
        assert_eq!(task.global.ulocks.lock().waiters(page), 1);
        assert_eq!(ulock_wake(&task, UL_UNFAIR_LOCK, page, 0), Ok(0));
        assert_eq!(handle.join().unwrap(), Ok(0));
    });
    // A dead owner name (MACH_PORT_DEAD) waits without an owner: only a
    // non-owner wake reaches it.
    word.write_at_offset::<Platform>(0, u32::MAX).unwrap();
    std::thread::scope(|scope| {
        let waiter = task.new_sibling(0);
        let handle = scope
            .spawn(move || ulock_wait(&waiter, UL_UNFAIR_LOCK, page, u32::MAX as usize, BOUND_US));
        await_waiters(&task, page, 1);
        assert_eq!(ulock_wake(&task, UL_UNFAIR_LOCK, page, 0), Ok(0));
        assert_eq!(task.global.ulocks.lock().waiters(page), 1);
        assert_eq!(
            ulock_wake(
                &task,
                UL_UNFAIR_LOCK | ULF_WAKE_ALL | ULF_WAKE_ALLOW_NON_OWNER,
                page,
                0
            ),
            Ok(0)
        );
        assert_eq!(handle.join().unwrap(), Ok(0));
    });
}

/// Waking one waiter of an unfair lock hands the lock to it: its own wake
/// then reaches the next waiter, and the old owner's wake is a late wake
/// that changes nothing.
#[test]
fn unfair_lock_wake_one_makes_the_woken_thread_the_owner() {
    let task = new_task();
    let page = guest_page(&task);
    let word = UserPtrMut::<u32>::from_usize(page);
    let own = trap(&task, mach_trap::THREAD_SELF, &[]);
    let owner_value = own & !0x1;
    word.write_at_offset::<Platform>(0, owner_value.trunc())
        .unwrap();
    std::thread::scope(|scope| {
        let first = task.new_sibling(0);
        let second = task.new_sibling(0);
        let (go, wake_next) = std::sync::mpsc::channel::<()>();
        let a = scope.spawn(move || {
            let waited = ulock_wait(&first, UL_UNFAIR_LOCK, page, owner_value, BOUND_US);
            wake_next.recv_timeout(BOUND).unwrap();
            (waited, ulock_wake(&first, UL_UNFAIR_LOCK, page, 0))
        });
        await_waiters(&task, page, 1);
        let b =
            scope.spawn(move || ulock_wait(&second, UL_UNFAIR_LOCK, page, owner_value, BOUND_US));
        await_waiters(&task, page, 2);
        // The owner wakes the first waiter, which now owns the lock.
        assert_eq!(ulock_wake(&task, UL_UNFAIR_LOCK, page, 0), Ok(0));
        await_waiters(&task, page, 1);
        // The old owner no longer owns it: its wake reaches nobody.
        assert_eq!(ulock_wake(&task, UL_UNFAIR_LOCK, page, 0), Ok(0));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(task.global.ulocks.lock().waiters(page), 1);
        assert!(!b.is_finished());
        // The new owner's wake does.
        go.send(()).unwrap();
        assert_eq!(a.join().unwrap(), (Ok(1), Ok(0)));
        assert_eq!(b.join().unwrap(), Ok(0));
    });
    assert_eq!(task.global.ulocks.lock().waiters(page), 0);
}
