// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thread lifecycle, thread ports, signal state, `bsdthread_ctl` and yield,
//! driven through the syscall dispatcher. Other guest threads are sibling
//! tasks on host test threads.

use super::mach::{bsd, guest_page, kr, mig_call, ndr, new_task, trap, word};
use super::ulock::{
    BOUND, BOUND_US, UL_COMPARE_AND_WAIT, UL_UNFAIR_LOCK, ULF_NO_ERRNO, await_waiters, errno,
    negative, ulock_wait,
};
use super::*;
use crate::syscalls::thread::PthreadRegistrationData;
use core::time::Duration;
use litebox::utils::TruncateExt as _;
use litebox_common_macos::{
    errno::Errno,
    syscall::{MachPortName, mach_trap, nr},
    user_pointers::UserPtrMut,
};
use std::time::Instant;

/// The host libpthread's registration (`_pthread_bsdthread_init`).
fn host_registration() -> PthreadRegistrationData {
    PthreadRegistrationData {
        version: 0x38,
        dispatch_queue_offset: 0xa0,
        tsd_offset: 0xe0,
        return_to_kernel_offset: 0x30,
        mach_thread_self_offset: 0x18,
        joinable_offset_bits: 0x18,
        wq_quantum_expiry_offset: 0xd0,
        ..PthreadRegistrationData::default()
    }
}

const PTHREAD_SIZE: usize = 0x4000;
const THREAD_START: usize = 0x1c14;

fn register(task: &Task<Platform>, data: &mut PthreadRegistrationData) -> Result<usize, usize> {
    register_with(
        task,
        PTHREAD_SIZE,
        data,
        size_of::<PthreadRegistrationData>(),
    )
}

fn register_with(
    task: &Task<Platform>,
    pthsize: usize,
    data: &mut PthreadRegistrationData,
    size: usize,
) -> Result<usize, usize> {
    bsd(
        task,
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
}

/// A name for `thread`'s port in its task's space, like the TSD slot holds.
pub(super) fn port_of(task: &Task<Platform>, thread: &Task<Platform>) -> usize {
    task.global
        .ipc
        .lock()
        .copyout_send(thread.thread.guest.port) as usize
}

#[test]
fn bsdthread_register_validates_clamps_and_copies_out() {
    let task = new_task();
    let mut data = host_registration();
    let call = |pthsize, data: &mut PthreadRegistrationData, size| {
        register_with(&task, pthsize, data, size)
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
    let PthreadRegistrationData {
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
    // 64 default stacks below the shared region, slid down by less than four.
    let hint = usize::try_from(stack_addr_hint).unwrap();
    let highest = 0x1_8000_0000 - 64 * 512 * 1024;
    assert!(
        (highest - 4 * 512 * 1024 < hint) && hint <= highest && hint % PAGE_SIZE == 0,
        "{hint:#x}"
    );
    assert_eq!(mutex_default_policy, 0);
    assert_eq!((tsd_offset, mach_thread_self_offset), (0xe0, 0x18));
    // One registration per process.
    let mut again = host_registration();
    assert_eq!(register(&task, &mut again), errno(Errno::EINVAL));

    // Offsets beyond the pthread_t are cleared.
    let task = new_task();
    let mut data = PthreadRegistrationData {
        tsd_offset: 0x100,
        dispatch_queue_offset: 0x100,
        mach_thread_self_offset: 0x20,
        ..host_registration()
    };
    assert!(
        register_with(
            &task,
            0x110,
            &mut data,
            size_of::<PthreadRegistrationData>()
        )
        .is_ok()
    );
    let PthreadRegistrationData {
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
    let mut data = PthreadRegistrationData {
        tsd_offset: 0x200,
        ..host_registration()
    };
    assert!(
        register_with(
            &task,
            0x100,
            &mut data,
            size_of::<PthreadRegistrationData>()
        )
        .is_ok()
    );
    let PthreadRegistrationData { tsd_offset, .. } = data;
    assert_eq!(tsd_offset, 0);
}

/// libpthread maps each pthread stack ANYWHERE at the registered
/// `stack_addr_hint`, which XNU only searches upward from, so the hint must
/// leave room above it with the main stack reserved at the top of the map.
#[test]
fn pthread_stacks_fit_above_the_registered_stack_hint() {
    use litebox::platform::{PageManagementProvider, page_mgmt::AllocationDirection};
    /// A default pthread stack, its guard page and the pthread_t, rounded.
    const STACK_ALLOCATION: usize = 0x8c000;
    const MAIN_STACK_RESERVATION: usize = 8 * 1024 * 1024 + PAGE_SIZE;
    const VM_FLAGS_ANYWHERE: usize = 1;
    const VM_PROT_DEFAULT: usize = 3;
    let task = new_task();
    // The loader's main stack reservation.
    let main_stack = task
        .reserve_anonymous(
            <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN,
            MAIN_STACK_RESERVATION,
            AllocationDirection::TopDown,
        )
        .unwrap();
    let mut data = host_registration();
    assert!(register(&task, &mut data).is_ok());
    let PthreadRegistrationData {
        stack_addr_hint, ..
    } = data;
    let hint = usize::try_from(stack_addr_hint).unwrap();
    let own = trap(&task, mach_trap::TASK_SELF, &[]);
    let mut address = hint;
    assert_eq!(
        kr(
            &task,
            mach_trap::MACH_VM_MAP,
            &[
                own,
                (&raw mut address) as usize,
                STACK_ALLOCATION,
                PAGE_SIZE - 1,
                VM_FLAGS_ANYWHERE,
                VM_PROT_DEFAULT,
            ]
        ),
        KernReturn::SUCCESS
    );
    assert!(
        hint <= address && address + STACK_ALLOCATION <= main_stack,
        "{address:#x} for hint {hint:#x}"
    );
}

#[test]
fn bsdthread_create_rejects_bad_requests_and_releases_everything() {
    const CUSTOM: usize = 0x0100_0000;
    const QOSCLASS: usize = 0x0800_0000;
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
    // No PTHREAD_START_CUSTOM; an invalid QoS; an unwritable
    // mach-thread-self slot.
    for (pthread, flags, error) in [
        (pthread, 0, Errno::EINVAL),
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
        worker.continuation(&mut PtRegs::default()),
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
    // A count below THREAD_IDENTIFIER_INFO_COUNT.
    let reply = mig_call(&task, other.trunc(), 3612, &ndr(&[4, 5]), false);
    assert_eq!(word(&reply, 32), 4, "KERN_INVALID_ARGUMENT");
    // __pthread_kill: signal 0 checks liveness; NSIG is out of range.
    assert_eq!(bsd(&task, nr::PTHREAD_KILL, &[other, 0]), Ok(0));
    assert_eq!(
        bsd(&task, nr::PTHREAD_KILL, &[other, 32]),
        errno(Errno::EINVAL)
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

/// `uthread_init` copies the creator's mask and links the new thread under
/// the proc lock `set_procsigmask` holds: a `sigprocmask` that completes
/// while a thread is being created reaches the new thread too.
#[test]
fn a_thread_created_during_sigprocmask_gets_the_new_process_mask() {
    use crate::syscalls::mm::hook;
    let task = new_task();
    let racer = task.new_sibling(0);
    let mask = 0b1000u32;
    let mask_address = (&raw const mask) as usize;
    let (go, start) = std::sync::mpsc::channel::<()>();
    let (report, changed) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            start.recv_timeout(BOUND).unwrap();
            report
                .send(bsd(&racer, nr::SIGPROCMASK, &[3, mask_address, 0]))
                .unwrap();
        });
        let mut go = Some(go);
        task.global.mapping_hook.set(move |point| {
            if point == hook::Point::ThreadAdmitted
                && let Some(go) = go.take()
            {
                go.send(()).unwrap();
                assert_eq!(changed.recv_timeout(BOUND).unwrap(), Ok(0));
            }
        });
        let child = task.new_sibling(0);
        task.global.mapping_hook.clear();
        let mask_of = |task: &Task<Platform>| task.thread.guest.signal_mask.load(Ordering::Relaxed);
        assert_eq!((mask_of(&task), mask_of(&child)), (mask, mask));
    });
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
    assert_eq!(*task.thread.guest.qos.lock(), 5);
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
    // QOS_MAX_PARALLELISM answers with the host's qos_max_parallelism, in
    // physical or (COUNT_LOGICAL) logical processors, or for realtime
    // threads (REALTIME, QoS 0).
    let host = |qos, logical| {
        litebox_common_macos::QosParallelism::qos_max_parallelism(
            task.global.platform,
            qos,
            logical,
        )
        .map(|count| usize::try_from(count).unwrap())
    };
    let logical = host(Some(4), true).expect("host parallelism");
    assert!(logical >= 1);
    assert_eq!(ctl(0x800, [4, 0x1, 0]), Ok(logical));
    assert_eq!(ctl(0x800, [4, 0, 0]).ok(), host(Some(4), false));
    assert_eq!(ctl(0x800, [0, 0x2 | 0x1, 0]).ok(), host(None, true));
    // The QoS is a thread_qos_t (uint8_t): 0x104 is QoS 4.
    assert_eq!(ctl(0x800, [0x104, 0x1, 0]), Ok(logical));
    assert_eq!(ctl(0x800, [0, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(ctl(0x800, [0x107, 0, 0]), errno(Errno::EINVAL));
    assert_eq!(ctl(0x800, [4, 0x2, 0]), errno(Errno::EINVAL));
    assert_eq!(ctl(0x800, [4, 0x8, 0]), errno(Errno::EINVAL));
    // pthread_workqueue.c bsdthread_get_max_parallelism: XNU without SME
    // units (!HAS_ARM_FEAT_SME) has no cluster shared resources.
    assert_eq!(ctl(0x800, [4, 0x4, 0]), errno(Errno::ENOTSUP));
    // Commands XNU retired (pthread_workqueue.c bsdthread_ctl).
    for removed in [0x10, 0x401, 0x402] {
        assert_eq!(ctl(removed, [0, 0, 0]), errno(Errno::ENOTSUP));
    }
    assert_eq!(ctl(0x20, [0, 0, 0]), errno(Errno::EINVAL));
}

/// The yield traps yield the host thread through the platform (the WAIT
/// options block instead) and return XNU's values.
#[test]
fn yield_traps_return_like_xnu() {
    let task = new_task();
    let yields = || task.thread.platform_yields.get();
    assert_eq!(trap(&task, mach_trap::SWTCH_PRI, &[]), 0);
    assert_eq!(trap(&task, mach_trap::SWTCH, &[]), 0);
    assert_eq!(yields(), 2);
    // SWITCH_OPTION_NONE, _DEPRESS and _OSLOCK_DEPRESS.
    for option in [0, 1, 4] {
        assert_eq!(
            kr(&task, mach_trap::THREAD_SWITCH, &[0, option, 1000]),
            KernReturn::SUCCESS
        );
    }
    assert_eq!(yields(), 5);
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
    assert_eq!(yields(), 5);
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
        let handle = scope.spawn(move || {
            ulock_wait(
                &joiner,
                UL_UNFAIR_LOCK,
                page,
                worker_port as usize,
                BOUND_US,
            )
        });
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
            assert!(start.elapsed() < BOUND, "never published");
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
/// it never finds a dead owner (EOWNERDEAD). Every termination releases its
/// port and names.
#[test]
fn a_user_joiner_racing_termination_never_sees_a_dead_owner() {
    let task = new_task();
    let page = guest_page(&task);
    let gate = UserPtrMut::<u32>::from_usize(page);
    let before = task.global.ipc.lock().live_counts();
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
                        BOUND_US,
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
                        let result = ulock_wait(&waiter, UL_COMPARE_AND_WAIT, page, 0, BOUND_US);
                        (result, waiter.continuation(&mut PtRegs::default()))
                    })
                })
            })
            .collect();
        await_waiters(&task, page, 3);
        // Wait until every waiter can be interrupted.
        let start = Instant::now();
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
            assert!(
                start.elapsed() < BOUND,
                "waiters never became interruptible"
            );
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

/// The last thread is counted until its `Task`'s other fields are torn down,
/// so a runner waiting for process completion cannot exit while that thread
/// still releases mappings or closes descriptors.
#[test]
fn process_wait_returns_after_the_last_thread_is_torn_down() {
    use crate::syscalls::mm::hook;
    let task = new_task();
    let process = task.process.clone();
    let worker = task.new_sibling(0);
    let files = Arc::downgrade(&worker.files);
    let global = Arc::downgrade(&worker.global);
    drop(task);
    let (sender, exited) = std::sync::mpsc::channel();
    let runner = std::thread::spawn({
        let process = process.clone();
        move || {
            let status = process.wait_for_exit();
            sender
                .send((
                    status,
                    files.upgrade().is_none(),
                    global.upgrade().is_none(),
                ))
                .unwrap();
        }
    });
    let live_while_releasing = Arc::new(AtomicU32::new(u32::MAX));
    worker.global.mapping_hook.set({
        let process = process.clone();
        let live_while_releasing = Arc::clone(&live_while_releasing);
        move |point| {
            if point == hook::Point::ReleasingMappings {
                let live = process.0.live_threads.underlying_atomic();
                live_while_releasing.store(live.load(Ordering::Acquire), Ordering::Relaxed);
            }
        }
    });
    drop(worker);
    assert_eq!(live_while_releasing.load(Ordering::Relaxed), 1);
    assert_eq!(exited.recv_timeout(BOUND), Ok((0, true, true)));
    runner.join().unwrap();
}
