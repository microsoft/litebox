// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Restartable ranges with sibling threads. A sibling "runs guest code"
//! between [`Task::continuation`] and [`Task::leave_guest`]; on failure
//! [`ExitOnFailure`] ends the process, which bounds every shim wait.

use super::mach::{guest_page, mig_call, ndr, new_task, trap, word};
use super::ulock::{
    BOUND, UL_COMPARE_AND_WAIT, ULF_WAKE_ALL, await_waiters, ulock_wait, ulock_wake,
};
use super::*;
use core::sync::atomic::Ordering;
use core::time::Duration;
use litebox::utils::TruncateExt as _;
use litebox_common_macos::syscall::mach_trap;
use std::sync::mpsc;
use std::time::Instant;

/// A range of 0x40 bytes whose recovery address is its start plus 0x30.
const RANGE: usize = 0x1_0000;
const RECOVERY: usize = RANGE + 0x30;
const INSIDE: usize = RANGE + 0x10;

fn register(task: &Task<Platform>) -> KernReturn {
    let own = trap(task, mach_trap::TASK_SELF, &[]);
    let mut ranges = ndr(&[1]);
    ranges.extend_from_slice(&(RANGE as u64).to_ne_bytes());
    ranges.extend_from_slice(&0x40u16.to_ne_bytes());
    ranges.extend_from_slice(&0x30u16.to_ne_bytes());
    ranges.extend_from_slice(&0u32.to_ne_bytes());
    KernReturn::from_raw(word(&mig_call(task, own.trunc(), 8000, &ranges, false), 32).cast_signed())
}

fn synchronize(task: &Task<Platform>) -> KernReturn {
    let own = trap(task, mach_trap::TASK_SELF, &[]);
    KernReturn::from_raw(word(&mig_call(task, own.trunc(), 8001, &[], false), 32).cast_signed())
}

/// Block in `ulock_wait` on the zero at `word` until a wake; whether it
/// returned success.
fn block_on(task: &Task<Platform>, word: usize) -> bool {
    ulock_wait(task, UL_COMPARE_AND_WAIT, word, 0, 0).is_ok()
}

/// Wake every thread blocked on `word`.
fn wake_all(task: &Task<Platform>, word: usize) {
    assert_eq!(
        ulock_wake(task, UL_COMPARE_AND_WAIT | ULF_WAKE_ALL, word, 0),
        Ok(0)
    );
}

/// Resume `task`'s guest code at `pc`.
fn resume_at(task: &Task<Platform>, pc: usize) -> PtRegs {
    let mut ctx = PtRegs {
        pc,
        ..PtRegs::default()
    };
    assert_eq!(task.continuation(&mut ctx), ContinueOperation::Resume);
    ctx
}

/// Run `f` on an interruptible sibling of `task` on a new host thread.
fn spawn_sibling<'scope, T: Send + 'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    task: &Task<Platform>,
    f: impl FnOnce(Task<Platform>) -> T + Send + 'scope,
) -> std::thread::ScopedJoinHandle<'scope, T> {
    let sibling = task.new_sibling(0);
    scope.spawn(move || {
        <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            sibling.start_thread();
            f(sibling)
        })
    })
}

/// Ends the process if the test fails. Declared after the test's channels,
/// it runs before they drop, and both before the scope joins the siblings.
struct ExitOnFailure<'a>(&'a Task<Platform>);

impl Drop for ExitOnFailure<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.exit_process(1);
        }
    }
}

/// Wait until `done` holds, failing past [`BOUND`].
fn await_bounded(what: &str, done: impl Fn() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < BOUND, "{what}");
        std::thread::yield_now();
    }
}

fn synchronizing(task: &Task<Platform>) -> bool {
    task.global
        .restartable_ranges
        .lock()
        .synchronizer_is_waiting()
}

/// XNU registers ranges only while the task has one thread, and release
/// kernels only once (restartable.c task_restartable_ranges_register);
/// without ranges a synchronize has nothing to do.
#[test]
fn restartable_ranges_register_once_and_only_single_threaded() {
    let task = new_task();
    assert_eq!(synchronize(&task), KernReturn::SUCCESS);
    let sibling = task.new_sibling(0);
    assert_eq!(register(&task), KernReturn::NOT_SUPPORTED);
    drop(sibling);
    assert_eq!(register(&task), KernReturn::SUCCESS);
    assert_eq!(register(&task), KernReturn::NOT_SUPPORTED);
    assert_eq!(synchronize(&task), KernReturn::SUCCESS);
}

/// A sibling running guest code in a range is interrupted, and the
/// synchronize waits until it has left the guest; it resumes at the range's
/// recovery address. A second synchronize meanwhile fails with
/// KERN_ALREADY_WAITING (task_restartable_ranges_synchronize).
#[test]
fn synchronize_waits_for_a_sibling_in_the_guest_and_moves_it_to_recovery() {
    let task = new_task();
    assert_eq!(register(&task), KernReturn::SUCCESS);
    std::thread::scope(|scope| {
        let (leave, left) = mpsc::channel::<()>();
        let (entered, in_guest) = mpsc::channel();
        let (returned, synchronize_returned) = mpsc::channel();
        let _exit_on_failure = ExitOnFailure(&task);
        let worker = spawn_sibling(scope, &task, move |worker| {
            resume_at(&worker, INSIDE);
            entered.send(Arc::clone(&worker.thread.guest)).unwrap();
            // Guest code until the test lets the interrupt land.
            left.recv().unwrap();
            worker.leave_guest();
            let first = resume_at(&worker, INSIDE).pc;
            worker.leave_guest();
            // The reset is consumed: a later return keeps its PC.
            let second = resume_at(&worker, INSIDE).pc;
            worker.leave_guest();
            (first, second)
        });
        let guest = in_guest.recv_timeout(BOUND).unwrap();
        let synchronizer = spawn_sibling(scope, &task, move |synchronizer| {
            let result = synchronize(&synchronizer);
            returned.send(()).unwrap();
            result
        });
        await_bounded("the synchronize never waited", || {
            synchronizing(&task) && guest.reset_pcs_ack.load(Ordering::Acquire)
        });
        let concurrent = spawn_sibling(scope, &task, |other| synchronize(&other));
        await_bounded("the concurrent synchronize waited", || {
            concurrent.is_finished()
        });
        assert_eq!(concurrent.join().unwrap(), KernReturn::ALREADY_WAITING);
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            synchronize_returned.try_recv().is_err(),
            "the synchronize returned while the sibling ran guest code"
        );
        leave.send(()).unwrap();
        await_bounded("the synchronize never returned", || {
            synchronizer.is_finished()
        });
        assert_eq!(synchronizer.join().unwrap(), KernReturn::SUCCESS);
        assert_eq!(worker.join().unwrap(), (RECOVERY, INSIDE));
    });
    assert!(!synchronizing(&task));
}

/// A sibling interrupted in the guest that enters the shim through a
/// syscall acknowledges at that entry: the synchronize returns while the
/// syscall blocks, and the sibling resumes at the recovery address when it
/// returns.
#[test]
fn synchronize_returns_while_an_interrupted_sibling_blocks_in_a_syscall() {
    let task = new_task();
    assert_eq!(register(&task), KernReturn::SUCCESS);
    let lock = guest_page(&task);
    std::thread::scope(|scope| {
        let (leave, left) = mpsc::channel::<()>();
        let (entered, in_guest) = mpsc::channel();
        let _exit_on_failure = ExitOnFailure(&task);
        let worker = spawn_sibling(scope, &task, move |worker| {
            resume_at(&worker, INSIDE);
            entered.send(Arc::clone(&worker.thread.guest)).unwrap();
            left.recv().unwrap();
            worker.leave_guest();
            let waited = block_on(&worker, lock);
            (waited, resume_at(&worker, INSIDE).pc)
        });
        let guest = in_guest.recv_timeout(BOUND).unwrap();
        let synchronizer = spawn_sibling(scope, &task, |synchronizer| synchronize(&synchronizer));
        await_bounded("the synchronize never waited", || {
            synchronizing(&task) && guest.reset_pcs_ack.load(Ordering::Acquire)
        });
        leave.send(()).unwrap();
        await_bounded("the synchronize waited for a blocked sibling", || {
            synchronizer.is_finished()
        });
        assert_eq!(synchronizer.join().unwrap(), KernReturn::SUCCESS);
        assert!(!worker.is_finished());
        await_waiters(&task, lock, 1);
        wake_all(&task, lock);
        await_bounded("the wake never reached the sibling", || {
            worker.is_finished()
        });
        assert_eq!(worker.join().unwrap(), (true, RECOVERY));
    });
}

/// A sibling already blocked in a syscall is not waited for: it is marked,
/// and resets its PC when the syscall returns. A sibling outside every
/// range keeps its PC.
#[test]
fn synchronize_marks_a_sibling_blocked_in_a_syscall_without_waiting() {
    let task = new_task();
    assert_eq!(register(&task), KernReturn::SUCCESS);
    let lock = guest_page(&task);
    std::thread::scope(|scope| {
        let _exit_on_failure = ExitOnFailure(&task);
        let blocked = |pc| {
            spawn_sibling(scope, &task, move |worker| {
                let waited = block_on(&worker, lock);
                (waited, resume_at(&worker, pc).pc)
            })
        };
        let inside = blocked(INSIDE);
        let outside = blocked(RANGE + 0x40);
        await_waiters(&task, lock, 2);
        let synchronizer = spawn_sibling(scope, &task, |synchronizer| synchronize(&synchronizer));
        await_bounded("the synchronize waited for blocked siblings", || {
            synchronizer.is_finished()
        });
        assert_eq!(synchronizer.join().unwrap(), KernReturn::SUCCESS);
        wake_all(&task, lock);
        await_bounded("the wake never reached the siblings", || {
            inside.is_finished() && outside.is_finished()
        });
        assert_eq!(inside.join().unwrap(), (true, RECOVERY));
        assert_eq!(outside.join().unwrap(), (true, RANGE + 0x40));
    });
}

/// A sibling interrupted in the guest that terminates instead of entering
/// the shim counts as acknowledged.
#[test]
fn synchronize_counts_a_terminated_sibling_as_acknowledged() {
    let task = new_task();
    assert_eq!(register(&task), KernReturn::SUCCESS);
    std::thread::scope(|scope| {
        let (end, ended) = mpsc::channel::<()>();
        let (entered, in_guest) = mpsc::channel();
        let _exit_on_failure = ExitOnFailure(&task);
        let worker = spawn_sibling(scope, &task, move |worker| {
            resume_at(&worker, INSIDE);
            entered.send(Arc::clone(&worker.thread.guest)).unwrap();
            ended.recv().unwrap();
            drop(worker);
        });
        let guest = in_guest.recv_timeout(BOUND).unwrap();
        let synchronizer = spawn_sibling(scope, &task, |synchronizer| synchronize(&synchronizer));
        await_bounded("the synchronize never waited", || {
            synchronizing(&task) && guest.reset_pcs_ack.load(Ordering::Acquire)
        });
        end.send(()).unwrap();
        worker.join().unwrap();
        await_bounded("the synchronize waited for a terminated sibling", || {
            synchronizer.is_finished()
        });
        assert_eq!(synchronizer.join().unwrap(), KernReturn::SUCCESS);
    });
}
