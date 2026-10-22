// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! libpthread's kernel side: `bsdthread_register`, `bsdthread_create`,
//! `bsdthread_terminate`, `bsdthread_ctl`, per-thread signal state and the
//! yield traps, after libpthread's `kern/kern_support.c` and XNU's
//! `bsd/pthread/pthread_workqueue.c`, `bsd/kern/kern_sig.c` and
//! `osfmk/kern/syscall_subr.c`.

use crate::{ShimPlatform, Task, thread::NewThread};
use alloc::boxed::Box;
use core::sync::atomic::Ordering;
use litebox::utils::TruncateExt;
use litebox_common_linux::PtRegs;
use litebox_common_macos::{
    KernReturn, PAGE_SIZE, VmProtection,
    errno::Errno,
    mach::port_name_is_valid,
    syscall::{BsdthreadCreateFlags, MachPortName, SigSet, SigmaskHow},
    user_pointers::{UserPtr, UserPtrMut},
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// `PTHREAD_FEATURE_SUPPORTED` (kern_internal.h): DISPATCHFUNC, FINEPRIO,
/// BSDTHREADCTL, SETSELF, QOS_MAINTENANCE, KEVENT, WORKLOOP,
/// COOPERATIVE_WORKQ and QOS_DEFAULT. The guest is not JIT-entitled.
pub(crate) const PTHREAD_FEATURE_SUPPORTED: u32 =
    0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x40 | 0x80 | 0x100 | 0x4000_0000;
/// `MAX_PTHREAD_SIZE`.
const MAX_PTHREAD_SIZE: i32 = 64 * 1024;
/// `PTH_DEFAULT_STACKSIZE`.
const PTH_DEFAULT_STACKSIZE: usize = 512 * 1024;
/// `SHARED_REGION_BASE_ARM64`.
const SHARED_REGION_BASE_ARM64: usize = 0x1_8000_0000;
/// `NSIG`.
const NSIG: i32 = 32;

/// `struct _pthread_registration_data` (libpthread `kern/kern_internal.h`).
#[derive(Clone, Copy, Default, FromBytes, Immutable, IntoBytes)]
#[repr(C, packed)]
pub(crate) struct PthreadRegistrationData {
    pub version: u64,
    pub dispatch_queue_offset: u64,
    pub main_qos: u64,
    pub tsd_offset: u32,
    pub return_to_kernel_offset: u32,
    pub mach_thread_self_offset: u32,
    pub stack_addr_hint: u64,
    pub mutex_default_policy: u32,
    pub joinable_offset_bits: u32,
    pub wq_quantum_expiry_offset: u32,
}
const _: () = assert!(
    size_of::<PthreadRegistrationData>() == 0x38
        && core::mem::offset_of!(PthreadRegistrationData, stack_addr_hint) == 0x24
        && core::mem::offset_of!(PthreadRegistrationData, wq_quantum_expiry_offset) == 0x34
);

/// What the shim keeps of the process's `bsdthread_register`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PthreadRegistration {
    pub threadstart: usize,
    pub tsd_offset: u32,
    pub dispatch_queue_offset: u64,
    pub mach_thread_self_offset: u32,
}

/// `THREAD_QOS_UNSPECIFIED`: the thread has no QoS tier (it opted out).
pub(crate) const THREAD_QOS_UNSPECIFIED: u32 = 0;
/// `THREAD_QOS_LEGACY`.
const THREAD_QOS_LEGACY: u32 = 4;

/// `pthread_priority_t` decoding (`priority_private.h`).
mod priority {
    const SCHED_PRI_FLAG: u64 = 0x2000_0000;
    const EVENT_MANAGER_FLAG: u64 = 0x0200_0000;
    const OVERRIDE_QOS_FLAG: u64 = 0x0080_0000;
    const COOPERATIVE_FLAG: u64 = 0x0800_0000;
    const VALID_QOS_CLASS_MASK: u64 = 0x0000_3f00;
    const VALID_OVERRIDE_QOS_MASK: u64 = 0x003f_c000;
    const QOS_CLASS_SHIFT: u32 = 8;
    const PRIORITY_MASK: u64 = 0xff;
    /// `THREAD_QOS_LAST`.
    const THREAD_QOS_LAST: u32 = 7;
    /// `THREAD_QOS_MIN_TIER_IMPORTANCE`.
    const MIN_TIER_IMPORTANCE: i32 = -15;

    fn has_qos(pp: u64) -> bool {
        pp & (SCHED_PRI_FLAG | EVENT_MANAGER_FLAG) == 0 && pp & VALID_QOS_CLASS_MASK != 0
    }

    /// `_pthread_priority_thread_qos`.
    pub fn thread_qos(pp: u64) -> u32 {
        if has_qos(pp) {
            ((pp & VALID_QOS_CLASS_MASK) >> QOS_CLASS_SHIFT).trailing_zeros() + 1
        } else {
            0
        }
    }

    /// `_pthread_priority_relpri`.
    fn relpri(pp: u64) -> i32 {
        if has_qos(pp) {
            let priority: u8 = litebox::utils::TruncateExt::trunc(pp & PRIORITY_MASK);
            i32::from(priority.cast_signed()) + 1
        } else {
            0
        }
    }

    pub fn has_override_qos(pp: u64) -> bool {
        pp & (SCHED_PRI_FLAG | EVENT_MANAGER_FLAG) == 0
            && pp & OVERRIDE_QOS_FLAG != 0
            && pp & VALID_OVERRIDE_QOS_MASK != 0
    }

    pub fn is_cooperative(pp: u64) -> bool {
        pp & COOPERATIVE_FLAG != 0
    }

    /// `_pthread_priority_to_policy`: the QoS tier, if `pp` is a valid
    /// `THREAD_QOS_POLICY`.
    pub fn to_policy(pp: u64) -> Option<u32> {
        let tier = thread_qos(pp);
        (tier != 0 && (MIN_TIER_IMPORTANCE..=0).contains(&relpri(pp))).then_some(tier)
    }

    /// `_pthread_priority_make_from_thread_qos(qos, 0, 0)`.
    pub fn from_thread_qos(qos: u32) -> u64 {
        if qos != 0 && qos < THREAD_QOS_LAST {
            (1 << (QOS_CLASS_SHIFT + qos - 1)) | PRIORITY_MASK
        } else {
            0
        }
    }
}

/// `bsdthread_ctl` commands (`bsdthread_private.h`).
mod ctl {
    pub const SET_QOS: usize = 0x10;
    pub const QOS_OVERRIDE_START: usize = 0x40;
    pub const QOS_OVERRIDE_END: usize = 0x80;
    pub const SET_SELF: usize = 0x100;
    pub const QOS_OVERRIDE_RESET: usize = 0x200;
    pub const QOS_OVERRIDE_DISPATCH: usize = 0x400;
    pub const QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_ADD: usize = 0x401;
    pub const QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_RESET: usize = 0x402;
    pub const QOS_MAX_PARALLELISM: usize = 0x800;
    pub const WORKQ_ALLOW_KILL: usize = 0x1000;
    pub const DISPATCH_APPLY_ATTR: usize = 0x2000;
    pub const WORKQ_ALLOW_SIGMASK: usize = 0x4000;
}

/// `enum workq_set_self_flags`.
mod set_self {
    pub const QOS: usize = 0x01;
    pub const VOUCHER: usize = 0x02;
    pub const WQ_KEVENT_UNBIND: usize = 0x10;
    pub const QOS_OVERRIDE: usize = 0x40;
}

/// `workq_threadmask`: signals a workqueue thread may not allow.
const WORKQ_THREADMASK: u32 = {
    const fn bit(signal: u32) -> u32 {
        1 << (signal - 1)
    }
    // threadmask (SIGILL, SIGTRAP, SIGEMT, SIGFPE, SIGBUS, SIGSEGV, SIGSYS,
    // SIGPIPE, SIGKILL) | sigcantmask (SIGKILL, SIGSTOP) | SIGPROF.
    bit(4)
        | bit(5)
        | bit(7)
        | bit(8)
        | bit(10)
        | bit(11)
        | bit(12)
        | bit(13)
        | bit(9)
        | bit(17)
        | bit(27)
};

/// `sigcantmask`: SIGKILL and SIGSTOP.
const UNMASKABLE_SIGNALS: u32 = (1 << (9 - 1)) | (1 << (17 - 1));

/// `thread_switch` options.
mod switch_option {
    pub const NONE: i32 = 0;
    pub const DEPRESS: i32 = 1;
    pub const WAIT: i32 = 2;
    pub const DISPATCH_CONTENTION: i32 = 3;
    pub const OSLOCK_DEPRESS: i32 = 4;
    pub const OSLOCK_WAIT: i32 = 5;
}

impl<P: ShimPlatform> Task<P> {
    /// `_bsdthread_register`: one registration per process. Returns
    /// `PTHREAD_FEATURE_SUPPORTED`.
    pub(crate) fn sys_bsdthread_register(
        &self,
        threadstart: usize,
        pthread_size: i32,
        data: usize,
        data_size: usize,
        dispatch_queue_offset: u32,
    ) -> Result<u32, Errno> {
        if !(0..=MAX_PTHREAD_SIZE).contains(&pthread_size) {
            return Err(Errno::EINVAL);
        }
        let pthread_size = pthread_size.cast_unsigned();
        let mut registration = PthreadRegistrationData::default();
        let copy_size = size_of::<PthreadRegistrationData>().min(data_size);
        if data != 0 {
            if data_size < size_of::<u64>() {
                return Err(Errno::EINVAL);
            }
            let copied = UserPtr::<u8>::from_usize(data)
                .to_owned_slice::<P>(copy_size)
                .ok_or(Errno::EFAULT)?;
            registration.as_mut_bytes()[..copy_size].copy_from_slice(&copied);
            if registration.version != data_size as u64 {
                return Err(Errno::EINVAL);
            }
        } else {
            registration.dispatch_queue_offset = u64::from(dispatch_queue_offset);
        }
        let stack_addr_hint = self.stack_addr_hint();
        let mut registered = self.global.pthread_registration.lock();
        if registered.is_some() {
            return Err(Errno::EINVAL);
        }
        let slot: u32 = size_of::<u64>().trunc();
        let max_tsd_offset =
            if pthread_size >= slot && registration.tsd_offset <= pthread_size - slot {
                pthread_size - registration.tsd_offset - slot
            } else {
                registration.tsd_offset = 0;
                0
            };
        let clamp = |value: u32| if value > max_tsd_offset { 0 } else { value };
        if registration.dispatch_queue_offset > u64::from(max_tsd_offset) {
            registration.dispatch_queue_offset = 0;
        }
        registration.return_to_kernel_offset = clamp(registration.return_to_kernel_offset);
        registration.mach_thread_self_offset = clamp(registration.mach_thread_self_offset);
        registration.wq_quantum_expiry_offset = clamp(registration.wq_quantum_expiry_offset);
        *registered = Some(PthreadRegistration {
            threadstart,
            tsd_offset: registration.tsd_offset,
            dispatch_queue_offset: registration.dispatch_queue_offset,
            mach_thread_self_offset: registration.mach_thread_self_offset,
        });
        drop(registered);
        if data != 0 {
            registration.version = size_of::<PthreadRegistrationData>() as u64;
            // An unspecified main thread gets the legacy QoS imposed.
            let main_qos = {
                let mut qos = self.thread.guest.qos.lock();
                if *qos == THREAD_QOS_UNSPECIFIED {
                    *qos = THREAD_QOS_LEGACY;
                }
                *qos
            };
            registration.main_qos = priority::from_thread_qos(main_qos);
            registration.stack_addr_hint = stack_addr_hint as u64;
            // XNU's default kern.pthread_mutex_default_policy, as on the host.
            registration.mutex_default_policy = 0;
            UserPtrMut::<u8>::from_usize(data)
                .copy_from_slice::<P>(0, &registration.as_bytes()[..copy_size])
                .ok_or(Errno::EINVAL)?;
        }
        Ok(PTHREAD_FEATURE_SUPPORTED)
    }

    /// `stack_addr_hint` for arm64 (libpthread `kern/kern_support.c`): 64
    /// default stacks below the shared region, slid by up to four more. XNU
    /// starts at the main stack's top, above which XNU leaves free space;
    /// LiteBox reserves the main stack at the top of the guest map, so the
    /// other arm64 branch applies.
    fn stack_addr_hint(&self) -> usize {
        let mut random = [0u8; 8];
        let slide = if self.global.litebox.fill_random(&mut random).is_ok() {
            usize::from_ne_bytes(random) % (4 * PTH_DEFAULT_STACKSIZE)
        } else {
            0
        };
        SHARED_REGION_BASE_ARM64 - 64 * PTH_DEFAULT_STACKSIZE - (slide & !(PAGE_SIZE - 1))
    }

    /// `_bsdthread_create`: start a guest thread at the registered
    /// `thread_start` with libpthread's arguments. Returns `pthread`.
    pub(crate) fn sys_bsdthread_create(
        &self,
        function: usize,
        argument: usize,
        stack: usize,
        pthread: usize,
        flags: BsdthreadCreateFlags,
    ) -> Result<usize, Errno> {
        let Some(registration) = *self.global.pthread_registration.lock() else {
            return Err(Errno::EINVAL);
        };
        // TODO: caller-supplied stacks; libpthread joins such a thread through
        // __semwait_signal_nocancel, which is not emulated. Any error but
        // EMFILE makes pthread_create fail with EAGAIN.
        if stack != pthread {
            self.log_unsupported_once("bsdthread_create(custom stack)", 0, format_args!(""));
            return Err(Errno::ENOTSUP);
        }
        let tsd_base = if registration.tsd_offset == 0 {
            0
        } else {
            // machine_thread_set_tsd_base: addresses beyond the map become 0.
            let base = pthread.wrapping_add(registration.tsd_offset as usize);
            if base > P::TASK_ADDR_MAX { 0 } else { base }
        };
        // thread_create refuses a task at task_threadmax.
        let child = self.try_new_sibling(tsd_base).ok_or(Errno::ENOMEM)?;
        let port = self.global.ipc.lock().copyout_send(child.thread.guest.port);
        let result = self.prepare_thread(&child, port, pthread, flags, registration);
        let flags = match result {
            Ok(flags) => flags,
            Err(error) => {
                self.global.ipc.lock().deallocate(port);
                return Err(error);
            }
        };
        let mut ctx = PtRegs {
            pc: registration.threadstart,
            sp: stack,
            ..PtRegs::default()
        };
        ctx.regs[..6].copy_from_slice(&[
            pthread,
            port as usize,
            function,
            argument,
            stack,
            flags.bits() as usize,
        ]);
        // SAFETY: the context starts guest code at the registered entry point
        // on the guest's own stack; faults are delivered like any others.
        let spawned = unsafe {
            litebox::platform::ThreadProvider::spawn_thread(
                self.global.platform,
                &ctx,
                Box::new(NewThread(child)),
            )
        };
        if let Err(error) = spawned {
            litebox_util_log::error!(error:% = error; "cannot start a guest thread");
            self.global.ipc.lock().deallocate(port);
            return Err(Errno::ENOMEM);
        }
        Ok(pthread)
    }

    /// The checks and setup `_bsdthread_create` makes once the thread and its
    /// port exist. Returns the flags `thread_start` receives.
    fn prepare_thread(
        &self,
        child: &Task<P>,
        port: u32,
        pthread: usize,
        flags: BsdthreadCreateFlags,
        registration: PthreadRegistration,
    ) -> Result<BsdthreadCreateFlags, Errno> {
        if !port_name_is_valid(port) {
            return Err(Errno::EMFILE);
        }
        if !flags.contains(BsdthreadCreateFlags::CUSTOM) {
            return Err(Errno::EINVAL);
        }
        let mut flags = flags;
        if registration.tsd_offset != 0 {
            flags |= BsdthreadCreateFlags::TSD_BASE_SET;
        }
        if flags.contains(BsdthreadCreateFlags::SUSPENDED) {
            // A suspended thread waits for thread_resume, which is not emulated.
            self.log_unsupported_once(
                "bsdthread_create(PTHREAD_START_SUSPENDED)",
                0,
                format_args!(""),
            );
            return Err(Errno::EINVAL);
        }
        // With SETSCHED the thread leaves QoS, so its tier stays unspecified.
        // TODO: thread_policy (pthread_setschedparam): record SETSCHED's
        // policy and importance, and serve the thread_policy MIG routine.
        if flags.contains(BsdthreadCreateFlags::QOSCLASS)
            && !flags.contains(BsdthreadCreateFlags::SETSCHED)
        {
            let qos = priority::to_policy(u64::from(flags.qos_class())).ok_or(Errno::EINVAL)?;
            *child.thread.guest.qos.lock() = qos;
        }
        if registration.mach_thread_self_offset != 0 && registration.tsd_offset != 0 {
            let slot = pthread
                .wrapping_add(registration.tsd_offset as usize)
                .wrapping_add(registration.mach_thread_self_offset as usize);
            UserPtrMut::<u64>::from_usize(slot)
                .write_at_offset::<P>(0, u64::from(port))
                .ok_or(Errno::EFAULT)?;
        }
        Ok(flags.difference(BsdthreadCreateFlags::SUSPENDED))
    }

    /// `bsdthread_terminate`: release the thread's stack, signal the joiner's
    /// semaphore and release the port name; the thread never returns.
    pub(crate) fn sys_bsdthread_terminate(
        &self,
        stack: usize,
        size: usize,
        port: MachPortName,
        semaphore_or_ulock: usize,
    ) {
        let mut semaphore = MachPortName(semaphore_or_ulock.trunc());
        let mut port = port;
        // pthread_shims.c: a value that is not a port name (names end in
        // 0x3, ulocks are aligned) is a ulock woken once the thread is gone.
        if semaphore_or_ulock != 0 && semaphore_or_ulock != (semaphore.0 | 0x3) as usize {
            self.thread
                .user_join
                .set(Some((semaphore_or_ulock, port.0)));
            semaphore = MachPortName::NULL;
            port = MachPortName::NULL;
        }
        if stack != 0 && size != 0 {
            if self.thread.guest.is_main {
                // The main thread's stack is kept, made reusable and
                // inaccessible, up to the page the thread runs on.
                let size = (size - 1) & !(PAGE_SIZE - 1);
                if self.is_fully_mapped(stack, size) {
                    let _ = self.sys_mprotect(stack, size, VmProtection::empty());
                }
            } else {
                let _ = self.mach_vm_deallocate(stack, size);
            }
        }
        if semaphore != MachPortName::NULL {
            let _ = self.sys_semaphore_signal(semaphore);
        }
        if port != MachPortName::NULL {
            let _ = self.global.ipc.lock().deallocate(port.0);
        }
        self.thread.terminated.set(true);
    }

    /// Whether `[address, address + size)` is mapped without holes, as
    /// `mach_vm_behavior_set` requires.
    fn is_fully_mapped(&self, address: usize, size: usize) -> bool {
        let Some(end) = address.checked_add(size) else {
            return false;
        };
        let mut cursor = address;
        for (range, _) in self.global.mm.overlapping(address..end) {
            if range.start > cursor {
                return false;
            }
            cursor = cursor.max(range.end);
        }
        cursor >= end
    }

    /// `thread_terminate_self` for a user-join termination: clear the port
    /// name's low bits in the join word and wake every waiter on it.
    pub(crate) fn wake_user_joiner(&self, address: usize, port: u32) {
        let _ = UserPtrMut::<u32>::from_usize(address).write_at_offset::<P>(0, port & !0x3);
        self.ulock_wake_all_unfair(address);
    }

    /// `__disable_threadsignal`: no signal is delivered to this thread again.
    /// XNU also sets `UT_CANCELDISABLE`, which only pthread cancellation
    /// reads; it is not emulated.
    pub(crate) fn sys_disable_threadsignal(&self) {
        self.thread.guest.no_signals.store(true, Ordering::Relaxed);
    }

    /// `__pthread_kill`. Signal 0 checks liveness; the shim does not deliver
    /// other signals to guest threads, so they fail closed.
    pub(crate) fn sys_pthread_kill(&self, thread: MachPortName, signal: i32) -> Result<(), Errno> {
        let target = self
            .global
            .ipc
            .lock()
            .thread_for_name(thread.0)
            .and_then(|id| self.guest_thread(id))
            .ok_or(Errno::ESRCH)?;
        if !(0..NSIG).contains(&signal) {
            return Err(Errno::EINVAL);
        }
        if target.no_signals.load(Ordering::Relaxed) {
            return Err(Errno::ESRCH);
        }
        if signal != 0 {
            self.log_unsupported_once("__pthread_kill with a signal", 0, format_args!("{signal}"));
            return Err(Errno::ENOTSUP);
        }
        Ok(())
    }

    /// `sigprocmask`: the process mask, which XNU applies to every thread.
    pub(crate) fn sys_sigprocmask(
        &self,
        how: SigmaskHow,
        mask: Option<UserPtr<SigSet>>,
        old_mask: Option<UserPtrMut<SigSet>>,
    ) -> Result<(), Errno> {
        self.change_signal_mask(how, mask, old_mask, true)
    }

    /// `__pthread_sigmask`: the calling thread's mask.
    pub(crate) fn sys_pthread_sigmask(
        &self,
        how: SigmaskHow,
        mask: Option<UserPtr<SigSet>>,
        old_mask: Option<UserPtrMut<SigSet>>,
    ) -> Result<(), Errno> {
        self.change_signal_mask(how, mask, old_mask, false)
    }

    /// Masks are recorded per thread; the shim does not deliver signals to
    /// guest handlers, so they have no further effect. Only
    /// `__pthread_sigmask`'s unblock keeps unmaskable bits.
    fn change_signal_mask(
        &self,
        how: SigmaskHow,
        mask: Option<UserPtr<SigSet>>,
        old_mask: Option<UserPtrMut<SigSet>>,
        every_thread: bool,
    ) -> Result<(), Errno> {
        let old = self.thread.guest.signal_mask.load(Ordering::Relaxed);
        if let Some(mask) = mask {
            let SigSet(new) = mask.read_at_offset::<P>(0).ok_or(Errno::EFAULT)?;
            let change = |current: u32| match how {
                SigmaskHow::Block => Some(current | (new & !UNMASKABLE_SIGNALS)),
                SigmaskHow::Unblock if every_thread => Some(current & !(new & !UNMASKABLE_SIGNALS)),
                SigmaskHow::Unblock => Some(current & !new),
                SigmaskHow::SetMask => Some(new & !UNMASKABLE_SIGNALS),
                SigmaskHow::Unknown(_) => None,
            };
            change(old).ok_or(Errno::EINVAL)?;
            // One read-modify-write per thread, so a concurrent change of the
            // same thread's mask is not lost (XNU holds the proc lock).
            let apply = |thread: &crate::GuestThread<P>| {
                let _ = thread
                    .signal_mask
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, change);
            };
            if every_thread {
                self.for_each_thread(apply);
            } else {
                apply(&self.thread.guest);
            }
        }
        if let Some(old_mask) = old_mask {
            // XNU ignores this copyout's failure.
            let _ = old_mask.write_at_offset::<P>(0, SigSet(old));
        }
        Ok(())
    }

    /// `bsdthread_get_max_parallelism`: the host's `qos_max_parallelism`.
    fn bsdthread_get_max_parallelism(&self, qos: u8, flags: usize) -> Result<usize, Errno> {
        const COUNT_LOGICAL: usize = 0x1;
        const REALTIME: usize = 0x2;
        const CLUSTER_SHARED_RESOURCE: usize = 0x4;
        /// `THREAD_QOS_LAST`.
        const THREAD_QOS_LAST: u8 = 7;
        if flags & !(REALTIME | COUNT_LOGICAL | CLUSTER_SHARED_RESOURCE) != 0 {
            return Err(Errno::EINVAL);
        }
        // The answer of XNU built without SME units (!HAS_ARM_FEAT_SME,
        // pthread_workqueue.c bsdthread_get_max_parallelism).
        if flags & CLUSTER_SHARED_RESOURCE != 0 {
            return Err(Errno::ENOTSUP);
        }
        let qos = if flags & REALTIME != 0 {
            if qos != 0 {
                return Err(Errno::EINVAL);
            }
            None
        } else if qos == 0 || qos >= THREAD_QOS_LAST {
            return Err(Errno::EINVAL);
        } else {
            Some(qos)
        };
        let count = litebox_common_macos::QosParallelism::qos_max_parallelism(
            self.global.platform,
            qos,
            flags & COUNT_LOGICAL != 0,
        );
        // libpthread's _pthread_workqueue_parallelism_for_priority falls back
        // to the commpage CPU counts on ENOTSUP.
        count
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(Errno::ENOTSUP)
    }

    /// `bsdthread_ctl` for a thread that is not a workqueue thread.
    pub(crate) fn sys_bsdthread_ctl(
        &self,
        command: usize,
        arguments: [usize; 3],
    ) -> Result<usize, Errno> {
        let [arg1, arg2, arg3] = arguments;
        let unused = |argument: usize| {
            if argument == 0 {
                Ok(())
            } else {
                Err(Errno::EINVAL)
            }
        };
        let thread_of = |name: usize| {
            self.global
                .ipc
                .lock()
                .thread_for_name(name.trunc())
                .ok_or(Errno::ESRCH)
        };
        match command {
            ctl::QOS_OVERRIDE_START => {
                // An explicit override of a live thread; overrides only
                // change scheduling, which the host does.
                if priority::thread_qos(arg2 as u64) == 0 {
                    return Err(Errno::EINVAL);
                }
                thread_of(arg1).map(|_| 0)
            }
            ctl::QOS_OVERRIDE_END => {
                unused(arg3)?;
                thread_of(arg1).map(|_| 0)
            }
            ctl::QOS_OVERRIDE_DISPATCH => {
                if priority::thread_qos(arg2 as u64) == 0 {
                    return Err(Errno::EINVAL);
                }
                thread_of(arg1)?;
                // Only workqueue threads take dispatch overrides.
                Err(Errno::EPERM)
            }
            ctl::QOS_OVERRIDE_RESET => Err(Errno::EPERM),
            ctl::SET_SELF => self.bsdthread_set_self(arg1 as u64, arg2.trunc(), arg3),
            ctl::QOS_MAX_PARALLELISM => {
                unused(arg3)?;
                // thread_qos_t is a uint8_t.
                self.bsdthread_get_max_parallelism(arg1.trunc(), arg2)
            }
            ctl::WORKQ_ALLOW_KILL => {
                unused(arg2)?;
                unused(arg3)?;
                // Not a workqueue thread: nothing to allow.
                Ok(0)
            }
            ctl::DISPATCH_APPLY_ATTR => {
                // _PTHREAD_DISPATCH_APPLY_ATTR_CLUSTER_SHARED_RSRC_SET/CLEAR
                // bind to a host cluster's shared resources.
                if !matches!(arg1, 1 | 2) {
                    return Err(Errno::EINVAL);
                }
                self.log_unsupported_once("BSDTHREAD_CTL_DISPATCH_APPLY_ATTR", 0, format_args!(""));
                Err(Errno::ENOTSUP)
            }
            ctl::WORKQ_ALLOW_SIGMASK => {
                if TruncateExt::<u32>::trunc(arg1) & WORKQ_THREADMASK != 0 {
                    return Err(Errno::EINVAL);
                }
                // Recorded for workqueue threads; the shim creates none.
                Ok(0)
            }
            ctl::SET_QOS
            | ctl::QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_ADD
            | ctl::QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_RESET => Err(Errno::ENOTSUP),
            _ => Err(Errno::EINVAL),
        }
    }

    /// `bsdthread_set_self` on a thread that is not a workqueue thread.
    fn bsdthread_set_self(
        &self,
        priority: u64,
        voucher: u32,
        flags: usize,
    ) -> Result<usize, Errno> {
        let unbind = if flags & set_self::WQ_KEVENT_UNBIND != 0 {
            Err(Errno::EINVAL)
        } else {
            Ok(())
        };
        let qos = if flags & (set_self::QOS | set_self::QOS_OVERRIDE) != 0 {
            let qos = priority::to_policy(priority);
            let override_valid = if flags & set_self::QOS_OVERRIDE != 0 {
                priority::has_override_qos(priority) && priority::is_cooperative(priority)
            } else {
                !priority::has_override_qos(priority)
            };
            let mut current = self.thread.guest.qos.lock();
            match qos {
                None => Err(Errno::EINVAL),
                Some(_) if !override_valid => Err(Errno::EINVAL),
                // Threads opted out of QoS can't change QoS.
                Some(_) if *current == THREAD_QOS_UNSPECIFIED => Err(Errno::EPERM),
                Some(qos) => {
                    *current = qos;
                    Ok(())
                }
            }
        } else {
            Ok(())
        };
        // The shim creates no voucher objects, so no name in this space
        // denotes one and only adopting none (MACH_PORT_NULL) succeeds.
        let voucher_result = if flags & set_self::VOUCHER != 0 && voucher != 0 {
            Err(Errno::ENOENT)
        } else {
            Ok(())
        };
        // FIXEDPRIORITY and TIMESHARE pick a scheduling mode, which only the
        // host scheduler could apply.
        if qos.is_err() && voucher_result.is_err() {
            return Err(Errno::EBADMSG);
        }
        unbind.and(qos).and(voucher_result).map(|()| 0)
    }

    /// `swtch` and `swtch_pri`: yield the host thread. They return whether
    /// the thread should still yield afterwards (`thread_should_yield`),
    /// which only the host scheduler knows; FALSE is one of XNU's answers.
    pub(crate) fn sys_swtch(&self) -> usize {
        self.yield_host_thread();
        0
    }

    fn yield_host_thread(&self) {
        litebox_common_macos::ThreadYield::yield_thread(self.global.platform);
        #[cfg(test)]
        self.thread
            .platform_yields
            .set(self.thread.platform_yields.get() + 1);
    }

    /// `thread_switch`: the WAIT options block for the option time, the
    /// others yield the host thread. A directed handoff and priority
    /// depression are hints the host scheduler does not take.
    pub(crate) fn sys_thread_switch(&self, option: i32, option_time: u32) -> KernReturn {
        let scale = match option {
            switch_option::NONE | switch_option::DEPRESS | switch_option::OSLOCK_DEPRESS => {
                self.yield_host_thread();
                return KernReturn::SUCCESS;
            }
            switch_option::WAIT | switch_option::OSLOCK_WAIT => 1_000_000,
            switch_option::DISPATCH_CONTENTION => 1_000,
            _ => return KernReturn::INVALID_ARGUMENT,
        };
        // assert_wait_timeout: an interrupted or expired wait both succeed.
        let timeout = core::time::Duration::from_nanos(u64::from(option_time) * scale);
        let _ = self.wait_cx().with_timeout(timeout).sleep();
        KernReturn::SUCCESS
    }
}
