// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `ulock_wait`/`ulock_wake` results and keys against `bsd/kern/sys_ulock.c`,
//! driven through the syscall dispatcher. Other guest threads are sibling
//! tasks on host test threads.

use super::mach::{bsd, kr, new_task, trap};
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

const UL_COMPARE_AND_WAIT: usize = 1;
const UL_UNFAIR_LOCK: usize = 2;
const UL_COMPARE_AND_WAIT_SHARED: usize = 3;
const ULF_DEADLINE: usize = 0x200_0000;
const VM_FLAGS_FIXED: usize = 0;
const VM_FLAGS_ANYWHERE: usize = 1;
const VM_FLAGS_OVERWRITE: usize = 0x4000;
/// Bounds every wait a test expects another thread to end, so a failing
/// test ends with ETIMEDOUT instead of hanging, in microseconds.
const BOUND_US: usize = 10_000_000;
const BOUND: Duration = Duration::from_secs(10);

fn vm_allocate(task: &Task<Platform>, mut address: usize, flags: usize) -> usize {
    let own = trap(task, mach_trap::TASK_SELF, &[]);
    assert_eq!(
        kr(
            task,
            mach_trap::MACH_VM_ALLOCATE,
            &[own, (&raw mut address) as usize, PAGE_SIZE, flags]
        ),
        KernReturn::SUCCESS
    );
    address
}

fn ulock_wait(
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

fn ulock_wake(
    task: &Task<Platform>,
    operation: usize,
    address: usize,
    value: usize,
) -> Result<usize, usize> {
    bsd(task, nr::ULOCK_WAKE, &[operation, address, value])
}

fn errno(error: Errno) -> Result<usize, usize> {
    Err(error.raw())
}

/// Wait until `waiters(table)` reaches `count`.
fn await_count(task: &Task<Platform>, count: u32, waiters: impl Fn(&UlockTable) -> u32) {
    let start = Instant::now();
    while waiters(&task.global.ulocks.lock()) != count {
        assert!(start.elapsed() < BOUND, "waiters never blocked");
        std::thread::yield_now();
    }
}

type UlockTable = crate::syscalls::ulock::UlockTable<Platform>;

/// Wait until `count` threads block on the private lock word `address`.
fn await_waiters(task: &Task<Platform>, address: usize, count: u32) {
    await_count(task, count, |table| table.waiters(address));
}

/// `mach_absolute_time` ticks in `duration`.
fn mach_ticks(task: &Task<Platform>, duration: Duration) -> u64 {
    let timebase = task.global.platform.mach_timebase_info();
    let ticks = duration.as_nanos() * u128::from(timebase.denom) / u128::from(timebase.numer);
    u64::try_from(ticks).unwrap()
}

/// A wait that finds the value changed after joining the lock's record
/// returns the waiters that remain, like any other exit through
/// `ulock_wait_cleanup`.
#[test]
fn ulock_wait_on_a_changed_value_returns_the_remaining_waiters() {
    let task = new_task();
    let page = vm_allocate(&task, 0, VM_FLAGS_ANYWHERE);
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

/// A `ULF_DEADLINE` wait sleeps until its `mach_absolute_time` deadline, and
/// a wake before the deadline ends it early.
#[test]
fn ulock_wait_with_a_future_deadline() {
    let task = new_task();
    let page = vm_allocate(&task, 0, VM_FLAGS_ANYWHERE);
    let start = Instant::now();
    let deadline =
        task.global.platform.mach_absolute_time() + mach_ticks(&task, Duration::from_millis(50));
    assert_eq!(
        ulock_wait2(
            &task,
            UL_COMPARE_AND_WAIT | ULF_DEADLINE,
            page,
            0,
            deadline.trunc()
        ),
        errno(Errno::ETIMEDOUT)
    );
    assert!(start.elapsed() >= Duration::from_millis(50));

    let start = Instant::now();
    std::thread::scope(|scope| {
        let waiter = task.new_sibling(0);
        let deadline = task.global.platform.mach_absolute_time() + mach_ticks(&task, BOUND);
        let handle = scope.spawn(move || {
            ulock_wait2(
                &waiter,
                UL_COMPARE_AND_WAIT | ULF_DEADLINE,
                page,
                0,
                deadline.trunc(),
            )
        });
        await_waiters(&task, page, 1);
        assert_eq!(ulock_wake(&task, UL_COMPARE_AND_WAIT, page, 0), Ok(0));
        assert_eq!(handle.join().unwrap(), Ok(0));
    });
    assert!(start.elapsed() < BOUND);
}

/// Waking one waiter of an unfair lock hands the lock to it: its own wake
/// then reaches the next waiter, and the old owner's wake is a late wake
/// that changes nothing.
#[test]
fn unfair_lock_wake_one_makes_the_woken_thread_the_owner() {
    let task = new_task();
    let page = vm_allocate(&task, 0, VM_FLAGS_ANYWHERE);
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

/// Shared lock words are keyed by the object mapped at the address: a
/// mapping that replaces or removes it leaves its waiters behind, out of
/// reach of waits and wakes on the new object (`uaddr_findobj`). The old
/// waiters are released through the table at the end, since no syscall
/// reaches them.
#[test]
fn shared_ulock_waiters_stay_with_a_replaced_mapping() {
    let task = new_task();
    let replaced = vm_allocate(&task, 0, VM_FLAGS_ANYWHERE);
    let removed = vm_allocate(&task, 0, VM_FLAGS_ANYWHERE);
    let object_waiters = |address: usize, count: u32| {
        await_count(&task, count, |table| table.object_waiters(address));
    };
    std::thread::scope(|scope| {
        let old = [replaced, removed].map(|page| {
            let waiter = task.new_sibling(0);
            let handle = scope
                .spawn(move || ulock_wait(&waiter, UL_COMPARE_AND_WAIT_SHARED, page, 0, BOUND_US));
            object_waiters(page, 1);
            handle
        });
        assert_eq!(
            vm_allocate(&task, replaced, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE),
            replaced
        );
        assert_eq!(
            bsd(&task, nr::MUNMAP, &[removed, PAGE_SIZE]),
            Ok(0),
            "munmap"
        );
        assert_eq!(
            ulock_wake(&task, UL_COMPARE_AND_WAIT_SHARED, removed, 0),
            errno(Errno::EINVAL),
            "nothing is mapped"
        );
        assert_eq!(vm_allocate(&task, removed, VM_FLAGS_FIXED), removed);
        for page in [replaced, removed] {
            assert_eq!(
                ulock_wake(&task, UL_COMPARE_AND_WAIT_SHARED, page, 0),
                errno(Errno::ENOENT)
            );
            assert_eq!(task.global.ulocks.lock().object_waiters(page), 1);
            // A waiter on the new object meets only that object's wakes.
            let waiter = task.new_sibling(0);
            let new = scope
                .spawn(move || ulock_wait(&waiter, UL_COMPARE_AND_WAIT_SHARED, page, 0, BOUND_US));
            object_waiters(page, 2);
            assert_eq!(
                ulock_wake(&task, UL_COMPARE_AND_WAIT_SHARED, page, 0),
                Ok(0)
            );
            assert_eq!(new.join().unwrap(), Ok(0));
            assert_eq!(task.global.ulocks.lock().object_waiters(page), 1);
        }
        for page in [replaced, removed] {
            task.global.ulocks.lock().wake_all_objects_at(page);
        }
        for handle in old {
            assert_eq!(handle.join().unwrap(), Ok(0));
        }
    });
    // With every waiter gone, the objects mapped now take new waiters.
    for page in [replaced, removed] {
        assert_eq!(task.global.ulocks.lock().object_waiters(page), 0);
        assert_eq!(
            ulock_wait(&task, UL_COMPARE_AND_WAIT_SHARED, page, 0, 1_000),
            errno(Errno::ETIMEDOUT)
        );
    }
}

/// A shared wait on a mapping made at an address a concurrent munmap freed
/// stays reachable: the munmap retires the old objects before any wait can
/// key the new mapping, so its late retirement cannot strand the waiter.
#[test]
fn shared_wait_on_an_address_reused_during_munmap_is_woken() {
    use crate::syscalls::mm::hook;

    let task = new_task();
    // Far above where host allocations land, so none takes the page while
    // it is unmapped.
    let page = vm_allocate(&task, 0x7a_0000_0000, VM_FLAGS_FIXED);
    std::thread::scope(|scope| {
        let waiter = task.new_sibling(0);
        let (go, start) = std::sync::mpsc::channel::<()>();
        let (waiting, about_to_wait) = std::sync::mpsc::channel::<()>();
        let handle = scope.spawn(move || {
            <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
                start.recv_timeout(BOUND).unwrap();
                assert_eq!(vm_allocate(&waiter, page, VM_FLAGS_FIXED), page);
                waiting.send(()).unwrap();
                ulock_wait(&waiter, UL_COMPARE_AND_WAIT_SHARED, page, 0, BOUND_US)
            })
        });
        let global = Arc::clone(&task.global);
        // After munmap removed the page and before it retires the old
        // objects, the page is mapped again and a shared wait starts on it.
        task.global.mapping_hook.set(move |point| {
            assert_eq!(point, hook::Point::MappingsChanged);
            go.send(()).unwrap();
            about_to_wait.recv_timeout(BOUND).unwrap();
            // The wait either queues behind the table lock munmap holds, or
            // joins a record before the retirement.
            let start = Instant::now();
            while global
                .ulocks
                .try_lock()
                .is_some_and(|table| table.object_waiters(page) == 0)
            {
                assert!(start.elapsed() < BOUND, "the waiter never blocked");
                std::thread::yield_now();
            }
        });
        let unmapped = bsd(&task, nr::MUNMAP, &[page, PAGE_SIZE]);
        task.global.mapping_hook.clear();
        assert_eq!(unmapped, Ok(0));
        await_count(&task, 1, |table| table.object_waiters(page));
        assert_eq!(
            ulock_wake(&task, UL_COMPARE_AND_WAIT_SHARED, page, 0),
            Ok(0)
        );
        assert_eq!(handle.join().unwrap(), Ok(0));
    });
}
