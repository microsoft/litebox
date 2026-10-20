// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thread lifecycle, thread ports, signal state, `bsdthread_ctl`, yield and
//! ulock behavior, driven through the syscall dispatcher. Other guest threads
//! are sibling tasks on host test threads.

use super::mach::{bsd, kr, mig_call, ndr, new_task, trap, word};
use super::*;
use core::time::Duration;
use litebox::utils::TruncateExt as _;
use litebox_common_macos::{
    MachClock as _,
    errno::Errno,
    syscall::{MachPortName, mach_trap, nr},
    user_pointers::UserPtrMut,
};
use std::time::Instant;

const UL_COMPARE_AND_WAIT: usize = 1;
const UL_UNFAIR_LOCK: usize = 2;
const UL_COMPARE_AND_WAIT_SHARED: usize = 3;
const UL_UNFAIR_LOCK64_SHARED: usize = 4;
const UL_COMPARE_AND_WAIT64: usize = 5;
const ULF_WAKE_ALL: usize = 0x100;
const ULF_WAKE_THREAD: usize = 0x200;
const ULF_WAKE_ALLOW_NON_OWNER: usize = 0x400;
const ULF_WAIT_WORKQ_DATA_CONTENTION: usize = 0x1_0000;
const ULF_WAIT_CANCEL_POINT: usize = 0x2_0000;
const ULF_WAIT_ADAPTIVE_SPIN: usize = 0x4_0000;
const ULF_NO_ERRNO: usize = 0x100_0000;
const ULF_DEADLINE: usize = 0x200_0000;

/// libpthread's registration data: version, offsets, and copy-out fields.
#[derive(Clone, Copy, Default, zerocopy::FromBytes, zerocopy::IntoBytes)]
#[repr(C, packed)]
struct Registration {
    version: u64,
    dispatch_queue_offset: u64,
    main_qos: u64,
    tsd_offset: u32,
    return_to_kernel_offset: u32,
    mach_thread_self_offset: u32,
    stack_addr_hint: u64,
    mutex_default_policy: u32,
    joinable_offset_bits: u32,
    wq_quantum_expiry_offset: u32,
}

/// The host libpthread's registration (`_pthread_bsdthread_init`).
fn host_registration() -> Registration {
    Registration {
        version: 0x38,
        dispatch_queue_offset: 0xa0,
        tsd_offset: 0xe0,
        return_to_kernel_offset: 0x30,
        mach_thread_self_offset: 0x18,
        joinable_offset_bits: 0x18,
        wq_quantum_expiry_offset: 0xd0,
        ..Registration::default()
    }
}

const PTHREAD_SIZE: usize = 0x4000;
const THREAD_START: usize = 0x1c14;

fn register(task: &Task<Platform>, data: &mut Registration) -> Result<usize, usize> {
    bsd(
        task,
        nr::BSDTHREAD_REGISTER,
        &[
            THREAD_START,
            0x1c08,
            PTHREAD_SIZE,
            core::ptr::from_mut(data) as usize,
            size_of::<Registration>(),
            0xa0,
        ],
    )
}

/// One page of guest memory.
fn guest_page(task: &Task<Platform>) -> usize {
    let own = trap(task, mach_trap::TASK_SELF, &[]);
    let mut address = 0usize;
    assert_eq!(
        kr(
            task,
            litebox_common_macos::syscall::mach_trap::MACH_VM_ALLOCATE,
            &[own, (&raw mut address) as usize, PAGE_SIZE, 1]
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
    bsd(task, 515, &[operation, address, value, timeout_us])
}

fn ulock_wake(
    task: &Task<Platform>,
    operation: usize,
    address: usize,
    value: usize,
) -> Result<usize, usize> {
    bsd(task, 516, &[operation, address, value])
}

fn errno(error: Errno) -> Result<usize, usize> {
    Err(error.raw())
}

/// A `ULF_NO_ERRNO` error result: the negated errno, sign-extended.
fn negative(error: Errno) -> usize {
    (-(error as isize)).cast_unsigned()
}

/// A name for `thread`'s port in its task's space, like the TSD slot holds.
fn port_of(task: &Task<Platform>, thread: &Task<Platform>) -> usize {
    task.global
        .ipc
        .lock()
        .copyout_send(thread.thread.guest.port) as usize
}

/// Wait until `count` threads block on the private lock word `address`.
fn await_waiters(task: &Task<Platform>, address: usize, count: u32) {
    let start = Instant::now();
    while task.global.ulocks.lock().waiters(address) != count {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "waiters never blocked"
        );
        std::thread::yield_now();
    }
}

#[test]
fn bsdthread_register_validates_clamps_and_copies_out() {
    let task = new_task();
    task.global
        .main_stack_top
        .store(0x16f_e04_000, Ordering::Relaxed);
    let mut data = host_registration();
    let call = |pthsize: usize, data: &mut Registration, size: usize| {
        bsd(
            &task,
            nr::BSDTHREAD_REGISTER,
            &[
                THREAD_START,
                0x1c08,
                pthsize,
                core::ptr::from_mut(data) as usize,
                size,
                0xa0,
            ],
        )
    };
    // The pthread size is a 32-bit int no larger than MAX_PTHREAD_SIZE.
    for pthsize in [0xffff_ffff, 64 * 1024 + 1, 0x8000_0000] {
        assert_eq!(call(pthsize, &mut data, 0x38), errno(Errno::EINVAL));
    }
    // The size must cover the version, which must equal it.
    assert_eq!(call(PTHREAD_SIZE, &mut data, 4), errno(Errno::EINVAL));
    assert_eq!(call(PTHREAD_SIZE, &mut data, 0x30), errno(Errno::EINVAL));
    assert_eq!(
        bsd(
            &task,
            nr::BSDTHREAD_REGISTER,
            &[1, 2, PTHREAD_SIZE, 8, 0x38, 0]
        ),
        errno(Errno::EFAULT)
    );
    // None of the failures registered.
    assert!(task.global.pthread_registration.lock().is_none());
    assert_eq!(
        register(&task, &mut data),
        Ok(syscalls::thread::PTHREAD_FEATURE_SUPPORTED as usize)
    );
    assert_eq!(syscalls::thread::PTHREAD_FEATURE_SUPPORTED, 0x4000_01df);
    let Registration {
        version,
        main_qos,
        stack_addr_hint,
        mutex_default_policy,
        tsd_offset,
        mach_thread_self_offset,
        ..
    } = data;
    assert_eq!(version, 0x38);
    // The unspecified main thread gets QOS_CLASS_DEFAULT (legacy) imposed.
    assert_eq!(main_qos, 0x8ff);
    assert_eq!(stack_addr_hint, 0x16f_e04_000);
    assert_eq!(mutex_default_policy, 0);
    assert_eq!((tsd_offset, mach_thread_self_offset), (0xe0, 0x18));
    // One registration per process.
    let mut again = host_registration();
    assert_eq!(register(&task, &mut again), errno(Errno::EINVAL));

    // Offsets beyond the pthread_t are cleared.
    let task = new_task();
    let mut data = Registration {
        tsd_offset: 0x100,
        dispatch_queue_offset: 0x100,
        mach_thread_self_offset: 0x20,
        ..host_registration()
    };
    assert!(call_with(&task, 0x110, &mut data).is_ok());
    let Registration {
        tsd_offset,
        dispatch_queue_offset,
        mach_thread_self_offset,
        return_to_kernel_offset,
        ..
    } = data;
    // max offset = 0x110 - 0x100 - 8 = 8.
    assert_eq!(
        (
            tsd_offset,
            dispatch_queue_offset,
            mach_thread_self_offset,
            return_to_kernel_offset
        ),
        (0x100, 0, 0, 0)
    );
    let task = new_task();
    let mut data = Registration {
        tsd_offset: 0x200,
        ..host_registration()
    };
    assert!(call_with(&task, 0x100, &mut data).is_ok());
    let Registration { tsd_offset, .. } = data;
    assert_eq!(tsd_offset, 0);
}

fn call_with(
    task: &Task<Platform>,
    pthsize: usize,
    data: &mut Registration,
) -> Result<usize, usize> {
    bsd(
        task,
        nr::BSDTHREAD_REGISTER,
        &[
            THREAD_START,
            0x1c08,
            pthsize,
            core::ptr::from_mut(data) as usize,
            size_of::<Registration>(),
            0,
        ],
    )
}

#[test]
fn bsdthread_create_rejects_bad_requests_and_releases_everything() {
    const CUSTOM: usize = 0x0100_0000;
    const QOSCLASS: usize = 0x0800_0000;
    const SUSPENDED: usize = 0x2000_0000;
    let task = new_task();
    let create = |pthread: usize, flags: usize| {
        bsd(
            &task,
            nr::BSDTHREAD_CREATE,
            &[0x1000, 0, pthread, pthread, flags],
        )
    };
    let pthread = guest_page(&task);
    // Before registration.
    assert_eq!(create(pthread, CUSTOM), errno(Errno::EINVAL));
    register(&task, &mut host_registration()).unwrap();
    let before = task.global.ipc.lock().live_counts();
    // No PTHREAD_START_CUSTOM; a suspended start; an invalid QoS; an
    // unwritable mach-thread-self slot.
    for (pthread, flags, error) in [
        (pthread, 0, Errno::EINVAL),
        (pthread, CUSTOM | SUSPENDED, Errno::EINVAL),
        (pthread, CUSTOM | QOSCLASS, Errno::EINVAL),
        (pthread, CUSTOM | QOSCLASS | 0x1505, Errno::EINVAL),
        (8, CUSTOM, Errno::EFAULT),
    ] {
        assert_eq!(create(pthread, flags), errno(error), "{flags:#x}");
    }
    // Each failure released the thread, its port and the port's name.
    assert_eq!(task.global.ipc.lock().live_counts(), before);
    assert_eq!(task.process.0.threads.lock().len(), 1);
    assert_eq!(
        task.process
            .0
            .live_threads
            .underlying_atomic()
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn bsdthread_terminate_releases_the_stack_signals_and_never_returns() {
    let task = new_task();
    let worker = task.new_sibling(0);
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    let stack = guest_page(&worker);
    // The thread's own port name, as bsdthread_create copied it out.
    let port = port_of(&worker, &worker);
    let created = mig_call(&task, own.trunc(), 3418, &ndr(&[0, 0]), false);
    let semaphore = word(&created, 28);
    assert_eq!(
        bsd(
            &worker,
            nr::BSDTHREAD_TERMINATE,
            &[stack, PAGE_SIZE, port, semaphore as usize]
        ),
        Ok(0)
    );
    assert!(worker.thread.terminated.get());
    assert_eq!(worker.global.mm.overlapping(stack..stack + 1), []);
    assert!(matches!(
        task.global
            .ipc
            .lock()
            .object_for_send_name(MachPortName(semaphore)),
        Some((
            _,
            syscalls::mach_ipc::KernelObject::Semaphore { count: 1, .. }
        ))
    ));
    assert_eq!(
        task.global.ipc.lock().thread_for_name(port.trunc()),
        None,
        "the port name was released"
    );
    assert_eq!(
        worker.continuation(&PtRegs::default()),
        ContinueOperation::Terminate
    );

    // The main thread's stack stays mapped, inaccessible below the page the
    // thread runs on.
    let main_stack = guest_page(&task);
    assert_eq!(
        bsd(
            &task,
            nr::BSDTHREAD_TERMINATE,
            &[main_stack, PAGE_SIZE + 1, 0, 0]
        ),
        Ok(0)
    );
    assert_eq!(
        task.global.mm.overlapping(main_stack..main_stack + 1)[0].1 & VmFlags::VM_ACCESS_FLAGS,
        VmFlags::empty()
    );
}

#[test]
fn thread_ports_name_live_threads_and_die_with_them() {
    let task = new_task();
    let own = trap(&task, mach_trap::THREAD_SELF, &[]);
    assert_eq!(trap(&task, mach_trap::THREAD_SELF, &[]), own);
    let sibling = task.new_sibling(0);
    let other = port_of(&task, &sibling);
    assert_ne!(other, own);
    assert_ne!(
        bsd(&sibling, nr::THREAD_SELFID, &[]),
        bsd(&task, nr::THREAD_SELFID, &[])
    );
    // thread_info(THREAD_IDENTIFIER_INFO) of another thread.
    let reply = mig_call(&task, other.trunc(), 3612, &ndr(&[4, 6]), false);
    assert_eq!((word(&reply, 32), word(&reply, 36)), (0, 6));
    let id = u64::from(word(&reply, 40)) | (u64::from(word(&reply, 44)) << 32);
    assert_eq!(id, sibling.thread.guest.id);
    for (flavor, count) in [(4, 5), (3, 10)] {
        let reply = mig_call(&task, other.trunc(), 3612, &ndr(&[flavor, count]), false);
        assert_eq!(word(&reply, 32), 4, "KERN_INVALID_ARGUMENT");
    }
    // __pthread_kill: signal 0 checks liveness; other signals fail closed.
    assert_eq!(bsd(&task, nr::PTHREAD_KILL, &[other, 0]), Ok(0));
    assert_eq!(
        bsd(&task, nr::PTHREAD_KILL, &[other, 32]),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        bsd(&task, nr::PTHREAD_KILL, &[other, 2]),
        errno(Errno::ENOTSUP)
    );
    assert_eq!(
        bsd(&task, nr::PTHREAD_KILL, &[0x7703, 0]),
        errno(Errno::ESRCH)
    );
    assert_eq!(bsd(&sibling, nr::DISABLE_THREADSIGNAL, &[1]), Ok(0));
    assert_eq!(
        bsd(&task, nr::PTHREAD_KILL, &[other, 0]),
        errno(Errno::ESRCH)
    );
    // UT_CANCELDISABLE too.
    assert!(sibling.thread.guest.cancel_disabled.load(Ordering::Relaxed));
    drop(sibling);
    // The name became a dead name.
    assert_eq!(task.global.ipc.lock().thread_for_name(other.trunc()), None);
    assert_eq!(
        bsd(&task, nr::PTHREAD_KILL, &[other, 0]),
        errno(Errno::ESRCH)
    );
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_DEALLOCATE,
            &[trap(&task, mach_trap::TASK_SELF, &[]), other]
        ),
        KernReturn::SUCCESS
    );
}

#[test]
fn signal_masks_are_per_thread_and_sigprocmask_reaches_every_thread() {
    let task = new_task();
    let sibling = task.new_sibling(0);
    let mask = |task: &Task<Platform>| task.thread.guest.signal_mask.load(Ordering::Relaxed);
    let set = 0b110u32 | (1 << 8);
    // __pthread_sigmask: this thread only; SIGKILL stays unmaskable.
    assert_eq!(
        bsd(
            &task,
            nr::PTHREAD_SIGMASK,
            &[1, (&raw const set) as usize, 0]
        ),
        Ok(0)
    );
    assert_eq!((mask(&task), mask(&sibling)), (0b110, 0));
    // A new thread inherits its creator's mask.
    assert_eq!(mask(&task.new_sibling(0)), 0b110);
    // sigprocmask: every thread.
    let other = 0b1000u32;
    let mut old = 0u32;
    assert_eq!(
        bsd(
            &sibling,
            nr::SIGPROCMASK,
            &[3, (&raw const other) as usize, (&raw mut old) as usize]
        ),
        Ok(0)
    );
    assert_eq!(old, 0);
    assert_eq!((mask(&task), mask(&sibling)), (0b1000, 0b1000));
    assert_eq!(
        bsd(
            &task,
            nr::PTHREAD_SIGMASK,
            &[9, (&raw const set) as usize, 0]
        ),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        bsd(&task, nr::PTHREAD_SIGMASK, &[1, 8, 0]),
        errno(Errno::EFAULT)
    );
}

#[test]
fn bsdthread_ctl_follows_xnu_for_a_non_workqueue_thread() {
    const SET_SELF: usize = 0x100;
    const QOS_FLAG: usize = 0x1;
    const VOUCHER_FLAG: usize = 0x2;
    const FIXEDPRIORITY_FLAG: usize = 0x4;
    const UNBIND: usize = 0x10;
    const USER_INITIATED: usize = 0x10ff;
    let task = new_task();
    let ctl = |command: usize, args: [usize; 3]| {
        bsd(
            &task,
            nr::BSDTHREAD_CTL,
            &[command, args[0], args[1], args[2]],
        )
    };
    // A thread opted out of QoS can't change it.
    assert_eq!(
        ctl(SET_SELF, [USER_INITIATED, 0, QOS_FLAG]),
        errno(Errno::EPERM)
    );
    register(&task, &mut host_registration()).unwrap();
    assert_eq!(ctl(SET_SELF, [USER_INITIATED, 0, QOS_FLAG]), Ok(0));
    assert_eq!(task.thread.guest.policy.lock().qos.tier, 5);
    // Invalid QoS and voucher together; then each alone.
    assert_eq!(
        ctl(SET_SELF, [0, 0x103, QOS_FLAG | VOUCHER_FLAG]),
        errno(Errno::EBADMSG)
    );
    assert_eq!(
        ctl(SET_SELF, [0, 0x103, VOUCHER_FLAG]),
        errno(Errno::ENOENT)
    );
    assert_eq!(ctl(SET_SELF, [0, 0, VOUCHER_FLAG]), Ok(0));
    assert_eq!(ctl(SET_SELF, [0, 0, UNBIND]), errno(Errno::EINVAL));
    assert_eq!(ctl(SET_SELF, [0, 0, FIXEDPRIORITY_FLAG]), Ok(0));
    assert!(!task.thread.guest.policy.lock().timeshare);
    let own = trap(&task, mach_trap::THREAD_SELF, &[]);
    // Explicit overrides: a valid QoS and a live thread.
    assert_eq!(ctl(0x40, [own, USER_INITIATED, 0]), Ok(0));
    assert_eq!(ctl(0x40, [own, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(ctl(0x40, [0x7703, USER_INITIATED, 0]), errno(Errno::ESRCH));
    assert_eq!(ctl(0x80, [own, 0, 1]), errno(Errno::EINVAL));
    assert_eq!(ctl(0x80, [own, 0, 0]), Ok(0));
    // Dispatch overrides need a workqueue thread.
    assert_eq!(ctl(0x400, [own, USER_INITIATED, 0]), errno(Errno::EPERM));
    assert_eq!(ctl(0x200, [0, 0, 0]), errno(Errno::EPERM));
    assert_eq!(ctl(0x1000, [1, 0, 0]), Ok(0));
    assert_eq!(ctl(0x1000, [1, 1, 0]), errno(Errno::EINVAL));
    assert_eq!(ctl(0x4000, [1 << 10, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(ctl(0x4000, [1 << 1, 0, 0]), Ok(0));
    assert_eq!(ctl(0x800, [0, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(ctl(0x800, [4, 0x4, 0]), errno(Errno::ENOTSUP));
    // The QoS is a thread_qos_t (uint8_t): 0x104 is QoS 4, past the checks.
    assert_eq!(ctl(0x800, [0x104, 0, 0]), errno(Errno::ENOTSUP));
    assert_eq!(ctl(0x800, [0x107, 0, 0]), errno(Errno::EINVAL));
    for removed in [0x10, 0x401, 0x402] {
        assert_eq!(ctl(removed, [0, 0, 0]), errno(Errno::ENOTSUP));
    }
    assert_eq!(ctl(0x20, [0, 0, 0]), errno(Errno::EINVAL));
}

/// The yield traps yield the host thread (see the platform's
/// `yield_thread_gives_up_the_processor`) and return XNU's values.
#[test]
fn yield_traps_return_like_xnu() {
    let task = new_task();
    assert_eq!(trap(&task, mach_trap::SWTCH_PRI, &[]), 0);
    assert_eq!(trap(&task, mach_trap::SWTCH, &[]), 0);
    for option in [0, 1, 4] {
        assert_eq!(
            kr(&task, mach_trap::THREAD_SWITCH, &[0, option, 1000]),
            KernReturn::SUCCESS
        );
    }
    let start = Instant::now();
    assert_eq!(
        kr(&task, mach_trap::THREAD_SWITCH, &[0, 2, 20]),
        KernReturn::SUCCESS
    );
    assert!(start.elapsed() >= Duration::from_millis(20));
    assert_eq!(
        kr(&task, mach_trap::THREAD_SWITCH, &[0, 6, 0]),
        KernReturn::INVALID_ARGUMENT
    );
}

#[test]
fn ulock_validates_operations_flags_and_addresses() {
    let task = new_task();
    let page = guest_page(&task);
    // Unknown operations (UL_UNFAIR_LOCK64_SHARED is not one), flags, and
    // unaligned or null addresses.
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
    // Shared operations need a mapped address.
    let unmapped = PAGE_SIZE;
    assert_eq!(
        ulock_wait(&task, UL_COMPARE_AND_WAIT_SHARED, unmapped, 0, 0),
        errno(Errno::EINVAL)
    );
    assert_eq!(
        ulock_wait(&task, UL_COMPARE_AND_WAIT, unmapped, 0, 0),
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

#[test]
fn ulock_waits_time_out() {
    let task = new_task();
    let page = guest_page(&task);
    let start = Instant::now();
    // ulock_wait: microseconds.
    assert_eq!(
        ulock_wait(&task, UL_COMPARE_AND_WAIT, page, 0, 20_000),
        errno(Errno::ETIMEDOUT)
    );
    assert!(start.elapsed() >= Duration::from_millis(20));
    // ulock_wait2: nanoseconds, or a mach_absolute_time deadline.
    assert_eq!(
        bsd(
            &task,
            nr::ULOCK_WAIT2,
            &[UL_COMPARE_AND_WAIT64 | ULF_NO_ERRNO, page, 0, 1_000_000, 0]
        ),
        Ok(negative(Errno::ETIMEDOUT))
    );
    let past: usize = task.global.platform.mach_absolute_time().trunc();
    assert_eq!(
        bsd(
            &task,
            nr::ULOCK_WAIT2,
            &[UL_COMPARE_AND_WAIT | ULF_DEADLINE, page, 0, past, 0]
        ),
        errno(Errno::ETIMEDOUT)
    );
    assert_eq!(task.global.ulocks.lock().waiters(page), 0);
}

#[test]
fn ulock_wakes_one_all_or_a_named_thread() {
    let task = new_task();
    let page = guest_page(&task);
    // Wake one: the waiter returns the waiters left (none).
    std::thread::scope(|scope| {
        let waiter = task.new_sibling(0);
        let handle = scope.spawn(move || ulock_wait(&waiter, UL_COMPARE_AND_WAIT, page, 0, 0));
        await_waiters(&task, page, 1);
        // The wake's operation must match the waiters' (EDOM).
        assert_eq!(
            ulock_wake(&task, UL_COMPARE_AND_WAIT64, page, 0),
            errno(Errno::EDOM)
        );
        // Shared and private keys are separate.
        assert_eq!(
            ulock_wake(&task, UL_COMPARE_AND_WAIT_SHARED, page, 0),
            errno(Errno::ENOENT)
        );
        assert_eq!(ulock_wake(&task, UL_COMPARE_AND_WAIT, page, 0), Ok(0));
        assert_eq!(handle.join().unwrap(), Ok(0));
    });
    // Wake all: each waiter reports the waiters still in the call.
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let waiter = task.new_sibling(0);
                scope.spawn(move || ulock_wait(&waiter, UL_COMPARE_AND_WAIT, page, 0, 0))
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
        let second_port = port_of(&task, &second);
        let first_port = port_of(&task, &first);
        let own = trap(&task, mach_trap::THREAD_SELF, &[]);
        let a = scope.spawn(move || ulock_wait(&first, UL_COMPARE_AND_WAIT, page, 0, 0));
        await_waiters(&task, page, 1);
        let b = scope.spawn(move || ulock_wait(&second, UL_COMPARE_AND_WAIT, page, 0, 0));
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
fn ulock_wake_thread_reports_a_thread_that_is_not_waiting() {
    let task = new_task();
    let page = guest_page(&task);
    let idle = task.new_sibling(0);
    let idle_port = port_of(&task, &idle);
    std::thread::scope(|scope| {
        let waiter = task.new_sibling(0);
        let handle = scope.spawn(move || ulock_wait(&waiter, UL_COMPARE_AND_WAIT, page, 0, 0));
        await_waiters(&task, page, 1);
        assert_eq!(
            ulock_wake(
                &task,
                UL_COMPARE_AND_WAIT | ULF_WAKE_THREAD,
                page,
                idle_port
            ),
            errno(Errno::EALREADY)
        );
        assert_eq!(ulock_wake(&task, UL_COMPARE_AND_WAIT, page, 0), Ok(0));
        assert_eq!(handle.join().unwrap(), Ok(0));
    });
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
        let handle = scope.spawn(move || ulock_wait(&waiter, UL_UNFAIR_LOCK, page, owner_value, 0));
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
        let handle =
            scope.spawn(move || ulock_wait(&waiter, UL_UNFAIR_LOCK, page, u32::MAX as usize, 0));
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

#[test]
fn bsdthread_terminate_wakes_a_user_join_ulock() {
    let task = new_task();
    let page = guest_page(&task);
    let worker = task.new_sibling(0);
    let worker_port: u32 = port_of(&task, &worker).trunc();
    let gate = UserPtrMut::<u32>::from_usize(page);
    gate.write_at_offset::<Platform>(0, worker_port).unwrap();
    std::thread::scope(|scope| {
        let joiner = task.new_sibling(0);
        let handle =
            scope.spawn(move || ulock_wait(&joiner, UL_UNFAIR_LOCK, page, worker_port as usize, 0));
        await_waiters(&task, page, 1);
        // An aligned address, not a port name, is the join word.
        assert_eq!(
            bsd(
                &worker,
                nr::BSDTHREAD_TERMINATE,
                &[0, 0, worker_port as usize, page]
            ),
            Ok(0)
        );
        assert_eq!(task.global.ulocks.lock().waiters(page), 1, "woken at exit");
        drop(worker);
        assert_eq!(handle.join().unwrap(), Ok(0));
    });
    assert_eq!(gate.read_at_offset::<Platform>(0), Some(worker_port & !0x3));
}

/// XNU's user-join order (thread.c thread_deallocate_complete,
/// pthread_shims.c bsdthread_terminate): the join word is published and the
/// joiners woken while the port still names the thread, then the saved name
/// is released and the port dies. In between, the thread has left the task.
#[test]
fn a_user_join_is_published_while_the_port_names_the_thread() {
    let task = new_task();
    let page = guest_page(&task);
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    let worker = task.new_sibling(0);
    let id = worker.thread.guest.id;
    let worker_port: u32 = port_of(&worker, &worker).trunc();
    let gate = UserPtrMut::<u32>::from_usize(page);
    gate.write_at_offset::<Platform>(0, worker_port).unwrap();
    bsd(
        &worker,
        nr::BSDTHREAD_TERMINATE,
        &[0, 0, worker_port as usize, page],
    )
    .unwrap();
    std::thread::scope(|scope| {
        // Hold the wake: the worker's teardown stops in it.
        let ulocks = task.global.ulocks.lock();
        let teardown = scope.spawn(move || drop(worker));
        let start = Instant::now();
        while gate.read_at_offset::<Platform>(0) == Some(worker_port) {
            assert!(start.elapsed() < Duration::from_secs(10), "never published");
            std::thread::yield_now();
        }
        assert_eq!(gate.read_at_offset::<Platform>(0), Some(worker_port & !0x3));
        assert_eq!(
            task.global.ipc.lock().thread_for_name(worker_port),
            Some(id),
            "the port still names the thread"
        );
        // The thread is no longer active.
        let reply = mig_call(&task, worker_port, 3612, &ndr(&[4, 6]), false);
        assert_eq!(word(&reply, 32), 37, "KERN_TERMINATED");
        let reply = mig_call(&task, worker_port, 3616, &ndr(&[1, 1, 31, 1]), false);
        assert_eq!(word(&reply, 32), 37, "KERN_TERMINATED");
        let (ports, names) = task.global.ipc.lock().live_counts();
        drop(ulocks);
        teardown.join().unwrap();
        // The thread's port and its one name are gone.
        assert_eq!(task.global.ipc.lock().live_counts(), (ports - 1, names - 1));
    });
    assert_eq!(task.global.ipc.lock().thread_for_name(worker_port), None);
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_PORT_DEALLOCATE,
            &[own, worker_port as usize]
        ),
        KernReturn::INVALID_NAME,
        "the saved port name was released"
    );
}

/// A joiner that read the join word before it was published resolves the
/// terminating thread as the owner and waits, or sees the published word;
/// it never finds a dead owner (EOWNERDEAD).
#[test]
fn a_user_joiner_racing_termination_never_sees_a_dead_owner() {
    let task = new_task();
    let page = guest_page(&task);
    let gate = UserPtrMut::<u32>::from_usize(page);
    for _ in 0..200 {
        let worker = task.new_sibling(0);
        let worker_port: u32 = port_of(&worker, &worker).trunc();
        gate.write_at_offset::<Platform>(0, worker_port).unwrap();
        bsd(
            &worker,
            nr::BSDTHREAD_TERMINATE,
            &[0, 0, worker_port as usize, page],
        )
        .unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let joiner = task.new_sibling(0);
            let barrier = &barrier;
            let handle = scope.spawn(move || {
                let gate = UserPtrMut::<u32>::from_usize(page);
                barrier.wait();
                // _pthread_joiner_wait.
                loop {
                    let current = gate.read_at_offset::<Platform>(0).unwrap();
                    if current != worker_port {
                        return Ok(current);
                    }
                    // Bounded: a lost wakeup fails the test (ETIMEDOUT).
                    let result = ulock_wait(
                        &joiner,
                        UL_UNFAIR_LOCK | ULF_NO_ERRNO,
                        page,
                        worker_port as usize,
                        10_000_000,
                    );
                    for error in [Errno::EOWNERDEAD, Errno::ETIMEDOUT] {
                        if result == Ok(negative(error)) {
                            return Err(error);
                        }
                    }
                }
            });
            barrier.wait();
            drop(worker);
            let result = handle.join().unwrap();
            assert_eq!(result, Ok(worker_port & !0x3));
        });
    }
}

/// Repeated user-join terminations release every port and name.
#[test]
fn user_join_terminations_release_their_ports_and_names() {
    let task = new_task();
    let page = guest_page(&task);
    let gate = UserPtrMut::<u32>::from_usize(page);
    let before = task.global.ipc.lock().live_counts();
    for _ in 0..8 {
        let worker = task.new_sibling(0);
        let worker_port: u32 = port_of(&worker, &worker).trunc();
        gate.write_at_offset::<Platform>(0, worker_port).unwrap();
        bsd(
            &worker,
            nr::BSDTHREAD_TERMINATE,
            &[0, 0, worker_port as usize, page],
        )
        .unwrap();
        drop(worker);
        assert_eq!(task.global.ipc.lock().live_counts(), before);
    }
}

fn live_threads(task: &Task<Platform>) -> u32 {
    task.process
        .0
        .live_threads
        .underlying_atomic()
        .load(Ordering::Relaxed)
}

/// XNU refuses threads past `task_threadmax` (`_bsdthread_create`: ENOMEM),
/// releasing everything, and admits again once a thread ends.
#[test]
fn thread_creation_stops_at_task_threadmax_and_recovers() {
    const CUSTOM: usize = 0x0100_0000;
    let limit = crate::thread::TASK_THREADMAX;
    let task = new_task();
    register(&task, &mut host_registration()).unwrap();
    let pthread = guest_page(&task);
    let mut threads: Vec<_> = (1..limit).map(|_| task.new_sibling(0)).collect();
    assert_eq!(live_threads(&task), limit);
    assert!(task.try_new_sibling(0).is_none());
    let before = task.global.ipc.lock().live_counts();
    assert_eq!(
        bsd(
            &task,
            nr::BSDTHREAD_CREATE,
            &[0x1000, 0, pthread, pthread, CUSTOM]
        ),
        errno(Errno::ENOMEM)
    );
    assert_eq!(task.global.ipc.lock().live_counts(), before);
    assert_eq!(live_threads(&task), limit);
    assert_eq!(task.process.0.threads.lock().len(), limit as usize);
    // A thread's end frees its slot.
    threads.pop();
    let again = task.try_new_sibling(0).expect("a slot was freed");
    assert!(task.try_new_sibling(0).is_none());
    drop(again);

    // Concurrent creators: exactly the free slots are admitted.
    let creators: Vec<_> = threads.drain(..4).collect();
    threads.pop();
    assert_eq!(live_threads(&task), limit - 2);
    let barrier = std::sync::Barrier::new(creators.len());
    let created: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = creators
            .into_iter()
            .map(|creator| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    (creator.try_new_sibling(0), creator)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(
        created.iter().filter(|(child, _)| child.is_some()).count(),
        2
    );
    assert_eq!(live_threads(&task), limit);
    assert_eq!(task.process.0.threads.lock().len(), limit as usize);
    drop(created);
    drop(threads);
    assert_eq!(live_threads(&task), 1);
    assert_eq!(task.process.0.threads.lock().len(), 1);
}

/// `thread_policy` (`pthread_setschedparam`): XNU's policy, count and
/// priority checks, then the thread's QoS is dropped and its mode and
/// importance recorded; nothing reaches the host.
#[test]
fn thread_policy_validates_and_records_another_threads_policy() {
    const THREAD_POLICY: i32 = 3616;
    const INVALID_POLICY: u32 = 28;
    const POLICY_LIMIT: u32 = 27;
    let task = new_task();
    let worker = task.new_sibling(0);
    let port: u32 = port_of(&task, &worker).trunc();
    worker.thread.guest.policy.lock().qos = syscalls::thread::ThreadQos {
        tier: 4,
        importance: 0,
    };
    let call = |fields: &[u32]| {
        word(
            &mig_call(&task, port, THREAD_POLICY, &ndr(fields), false),
            32,
        )
    };
    // policy, count, base[count], set_limit.
    assert_eq!(call(&[4, 1, 47, 1]), 0, "SCHED_FIFO at its maximum");
    let policy = *worker.thread.guest.policy.lock();
    assert_eq!(
        (policy.qos.tier, policy.timeshare, policy.importance),
        (0, false, 16)
    );
    assert_eq!(call(&[2, 2, 15, 0, 1]), 0, "SCHED_RR with its quantum");
    assert_eq!(worker.thread.guest.policy.lock().importance, -16);
    assert_eq!(call(&[1, 1, 31, 0]), 0, "SCHED_OTHER below the limit");
    let policy = *worker.thread.guest.policy.lock();
    assert_eq!((policy.timeshare, policy.importance), (true, 0));
    // Priorities beyond MAXPRI_USER are clamped.
    assert_eq!(call(&[1, 1, 100, 1]), 0);
    assert_eq!(worker.thread.guest.policy.lock().importance, 32);
    // Invalid policies, counts and priorities.
    assert_eq!(call(&[3, 1, 31, 1]), INVALID_POLICY);
    assert_eq!(call(&[0, 1, 31, 1]), INVALID_POLICY);
    assert_eq!(call(&[1, 2, 31, 0, 1]), 4, "KERN_INVALID_ARGUMENT");
    assert_eq!(call(&[2, 1, 31, 1]), 4, "KERN_INVALID_ARGUMENT");
    assert_eq!(call(&[1, 1, 128, 1]), 4, "KERN_INVALID_ARGUMENT");
    assert_eq!(call(&[1, 1, (-1i32).cast_unsigned(), 1]), 4);
    assert_eq!(call(&[1, 1, 64, 0]), POLICY_LIMIT);
    // A malformed request: the array bound, or a size that does not match
    // the count.
    assert_eq!(
        call(&[1, 6, 0, 0, 0, 0, 0, 0, 1]),
        litebox_common_macos::mach::mig::BAD_ARGUMENTS.cast_unsigned()
    );
    assert_eq!(
        call(&[1, 1, 31]),
        litebox_common_macos::mach::mig::BAD_ARGUMENTS.cast_unsigned()
    );
    let policy = *worker.thread.guest.policy.lock();
    assert_eq!((policy.timeshare, policy.importance), (true, 32));
}

#[test]
fn process_exit_ends_blocked_waits_and_the_last_thread_exits() {
    let task = new_task();
    let page = guest_page(&task);
    let process = task.process.clone();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let waiter = task.new_sibling(0);
                scope.spawn(move || {
                    <Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
                        waiter.start_thread();
                        let result = ulock_wait(&waiter, UL_COMPARE_AND_WAIT, page, 0, 0);
                        (result, waiter.continuation(&PtRegs::default()))
                    })
                })
            })
            .collect();
        await_waiters(&task, page, 3);
        // Wait until every waiter can be interrupted.
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
            assert_eq!(
                handle.join().unwrap(),
                (errno(Errno::EINTR), ContinueOperation::Terminate)
            );
        }
    });
    // A later exit does not change the status.
    assert_eq!(bsd(&task, nr::EXIT, &[9]), Ok(0));
    drop(task);
    assert_eq!(process.wait_for_exit(), 7);

    // Without an exit, the last thread's end exits the process with 0.
    let task = new_task();
    let process = task.process.clone();
    let worker = task.new_sibling(0);
    drop(task);
    assert_eq!(process.exit_status(), None);
    drop(worker);
    assert_eq!(process.wait_for_exit(), 0);
}
