//! Process/thread related syscalls.

use core::mem::offset_of;
use core::ops::Range;

use alloc::boxed::Box;
use litebox::mm::linux::VmFlags;
use litebox::platform::{ExitProvider as _, RawMutPointer as _, ThreadProvider as _};
use litebox::platform::{Instant as _, SystemTime as _, TimeProvider};
use litebox::platform::{
    PunchthroughProvider as _, PunchthroughToken as _, RawConstPointer as _, RawMutex as _,
    RawMutexProvider as _, ThreadLocalStorageProvider as _,
};
use litebox::utils::TruncateExt as _;
use litebox_common_linux::{ArchPrctlArg, errno::Errno};
use litebox_common_linux::{CloneFlags, FutexArgs, PrctlArg};

/// A global counter for the number of threads in the system.
pub(super) static NR_THREADS: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(1);

/// Set the current task's command name.
pub fn set_task_comm(comm: &[u8]) {
    litebox_platform_multiplex::platform().with_thread_local_storage_mut(|tls| {
        let comm = &comm[..comm.len().min(litebox_common_linux::TASK_COMM_LEN - 1)];
        tls.current_task.comm[..comm.len()].copy_from_slice(comm);
    });
}

/// Handle syscall `prctl`.
pub(crate) fn sys_prctl(
    arg: PrctlArg<litebox_platform_multiplex::Platform>,
) -> Result<usize, Errno> {
    match arg {
        PrctlArg::GetName(name) => litebox_platform_multiplex::platform()
            .with_thread_local_storage_mut(|tls| {
                unsafe { name.write_slice_at_offset(0, &tls.current_task.comm) }
                    .ok_or(Errno::EFAULT)
            })
            .map(|()| 0),
        PrctlArg::SetName(name) => {
            let mut name_buf = [0u8; litebox_common_linux::TASK_COMM_LEN - 1];
            // strncpy
            for (i, byte) in name_buf.iter_mut().enumerate() {
                let b = *unsafe { name.read_at_offset(isize::try_from(i).unwrap()) }
                    .ok_or(Errno::EFAULT)?;
                if b == 0 {
                    break;
                }
                *byte = b;
            }
            set_task_comm(&name_buf);
            Ok(0)
        }
        _ => unimplemented!(),
    }
}

/// Handle syscall `arch_prctl`.
pub(crate) fn sys_arch_prctl(
    arg: ArchPrctlArg<litebox_platform_multiplex::Platform>,
) -> Result<(), Errno> {
    match arg {
        #[cfg(target_arch = "x86_64")]
        ArchPrctlArg::SetFs(addr) => {
            let punchthrough = litebox_common_linux::PunchthroughSyscall::SetFsBase { addr };
            let token = litebox_platform_multiplex::platform()
                .get_punchthrough_token_for(punchthrough)
                .expect("Failed to get punchthrough token for SET_FS");
            token.execute().map(|_| ()).map_err(|e| match e {
                litebox::platform::PunchthroughError::Failure(errno) => errno,
                _ => unimplemented!("Unsupported punchthrough error {:?}", e),
            })
        }
        #[cfg(target_arch = "x86_64")]
        ArchPrctlArg::GetFs(addr) => {
            let punchthrough = litebox_common_linux::PunchthroughSyscall::GetFsBase { addr };
            let token = litebox_platform_multiplex::platform()
                .get_punchthrough_token_for(punchthrough)
                .expect("Failed to get punchthrough token for GET_FS");
            token.execute().map(|_| ()).map_err(|e| match e {
                litebox::platform::PunchthroughError::Failure(errno) => errno,
                _ => unimplemented!("Unsupported punchthrough error {:?}", e),
            })
        }
        ArchPrctlArg::CETStatus | ArchPrctlArg::CETDisable | ArchPrctlArg::CETLock => {
            Err(Errno::EINVAL)
        }
        _ => unimplemented!(),
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn set_thread_area(
    user_desc: crate::MutPtr<litebox_common_linux::UserDesc>,
) -> Result<(), Errno> {
    Err(Errno::ENOSYS) // x86_64 does not support set_thread_area
}

#[cfg(target_arch = "x86")]
pub(crate) fn set_thread_area(
    user_desc: crate::MutPtr<litebox_common_linux::UserDesc>,
) -> Result<(), Errno> {
    use litebox::platform::{PunchthroughProvider as _, PunchthroughToken as _};
    let punchthrough = litebox_common_linux::PunchthroughSyscall::SetThreadArea { user_desc };
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(punchthrough)
        .expect("Failed to get punchthrough token for SET_THREAD_AREA");
    token.execute().map(|_| ()).map_err(|e| match e {
        litebox::platform::PunchthroughError::Failure(errno) => errno,
        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
    })
}

pub(crate) fn sys_rt_sigprocmask(
    how: litebox_common_linux::SigmaskHow,
    set: Option<crate::ConstPtr<litebox_common_linux::SigSet>>,
    oldset: Option<crate::MutPtr<litebox_common_linux::SigSet>>,
) -> Result<(), Errno> {
    let punchthrough =
        litebox_common_linux::PunchthroughSyscall::RtSigprocmask { how, set, oldset };
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(punchthrough)
        .expect("Failed to get punchthrough token for RT_SIGPROCMASK");
    token.execute().map(|_| ()).map_err(|e| match e {
        litebox::platform::PunchthroughError::Failure(errno) => errno,
        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
    })
}

pub(crate) fn sys_rt_sigaction(
    signum: litebox_common_linux::Signal,
    act: Option<crate::ConstPtr<litebox_common_linux::SigAction>>,
    oldact: Option<crate::MutPtr<litebox_common_linux::SigAction>>,
) -> Result<(), Errno> {
    let punchthrough = litebox_common_linux::PunchthroughSyscall::RtSigaction {
        signum,
        act,
        oldact,
    };
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(punchthrough)
        .expect("Failed to get punchthrough token for RT_SIGACTION");
    token.execute().map(|_| ()).map_err(|e| match e {
        litebox::platform::PunchthroughError::Failure(errno) => errno,
        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
    })
}

/// Handle syscall `rt_sigreturn`.
pub(crate) fn sys_rt_sigreturn(stack: usize) -> ! {
    let punchthrough = litebox_common_linux::PunchthroughSyscall::RtSigreturn { stack };
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(punchthrough)
        .expect("Failed to get punchthrough token for RT_SIGRETURN");
    token
        .execute()
        .map(|_| ())
        .map_err(|e| match e {
            litebox::platform::PunchthroughError::Failure(errno) => errno,
            _ => unimplemented!("Unsupported punchthrough error {:?}", e),
        })
        .expect("rt_sigreturn failed");
    unreachable!("rt_sigreturn should not return");
}

const ROBUST_LIST_LIMIT: isize = 2048;

/*
 * Process a futex-list entry, check whether it's owned by the
 * dying task, and do notification if so:
 */
fn handle_futex_death(
    futex_addr: crate::ConstPtr<u32>,
    pi: bool,
    pending_op: bool,
) -> Result<(), Errno> {
    if futex_addr.as_usize() % 4 != 0 {
        return Err(Errno::EINVAL);
    }

    todo!("handle_futex_death is not implemented yet");
}

fn fetch_robust_entry(
    head: crate::ConstPtr<litebox_common_linux::RobustList<litebox_platform_multiplex::Platform>>,
) -> (
    crate::ConstPtr<litebox_common_linux::RobustList<litebox_platform_multiplex::Platform>>,
    bool,
) {
    let next = head.as_usize();
    (crate::ConstPtr::from_usize(next & !1), next & 1 != 0)
}

fn wake_robust_list(
    head: crate::ConstPtr<
        litebox_common_linux::RobustListHead<litebox_platform_multiplex::Platform>,
    >,
) -> Result<(), Errno> {
    let mut limit = ROBUST_LIST_LIMIT;
    let head_ptr = head.as_usize();
    let head = unsafe { head.read_at_offset(0) }.ok_or(Errno::EFAULT)?;
    let (mut entry, mut pi) = fetch_robust_entry(head.list.next);
    let (pending, ppi) = fetch_robust_entry(head.list_op_pending);
    let futex_offset = head.futex_offset;
    let entry_head = head_ptr
        + offset_of!(
            litebox_common_linux::RobustListHead<litebox_platform_multiplex::Platform>,
            list
        );
    while entry.as_usize() != entry_head && limit > 0 {
        let nxt = unsafe { entry.read_at_offset(0) }.map(|e| fetch_robust_entry(e.next));
        if entry.as_usize() != pending.as_usize() {
            handle_futex_death(
                crate::ConstPtr::from_usize(entry.as_usize() + futex_offset),
                pi,
                false,
            )?;
        }
        let Some((next_entry, next_pi)) = nxt else {
            return Err(Errno::EFAULT);
        };

        entry = next_entry;
        pi = next_pi;
        limit -= 1;
    }

    if pending.as_usize() != 0 {
        let _ = handle_futex_death(
            crate::ConstPtr::from_usize(pending.as_usize() + futex_offset),
            ppi,
            true,
        );
    }
    Ok(())
}

fn exit_code(
    status: i32,
) -> <litebox_platform_multiplex::Platform as litebox::platform::ExitProvider>::ExitCode {
    if status == 0 {
        litebox_platform_multiplex::Platform::EXIT_SUCCESS
    } else {
        // TODO(jayb): We are currently folding away all non-zero exit codes as just failure. We
        // might wish to think of a better design for the ExitProvider to support a better handling
        // of this.
        litebox_platform_multiplex::Platform::EXIT_FAILURE
    }
}

pub(crate) fn sys_exit(status: i32) -> ! {
    let mut tls = litebox_platform_multiplex::platform().release_thread_local_storage();
    if let Some(clear_child_tid) = tls.current_task.clear_child_tid.take() {
        // Clear the child TID if requested
        // TODO: if we are the last thread, we don't need to clear it
        let _ = unsafe { clear_child_tid.write_at_offset(0, 0) };
        // Cast from *i32 to *u32
        let clear_child_tid = crate::MutPtr::from_usize(clear_child_tid.as_usize());
        let _ = sys_futex(litebox_common_linux::FutexArgs::Wake {
            addr: clear_child_tid,
            flags: litebox_common_linux::FutexFlags::PRIVATE,
            count: 1,
        });
    }
    if let Some(robust_list) = tls.current_task.robust_list.take() {
        let _ = wake_robust_list(robust_list);
    }

    NR_THREADS.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);

    litebox_platform_multiplex::platform().terminate_thread(exit_code(status))
}

pub(crate) fn sys_exit_group(status: i32) -> ! {
    litebox_platform_multiplex::platform().exit(exit_code(status))
}

fn new_thread_callback(
    args: litebox_common_linux::NewThreadArgs<litebox_platform_multiplex::Platform>,
) {
    let litebox_common_linux::NewThreadArgs {
        task,
        tls,
        set_child_tid,
        start_gate,
        callback: _,
    } = args;
    let child_tid = task.tid;

    // Wait for parent to write parent_tid if a start gate is present.
    if let Some(gate) = start_gate {
        let _ = gate.lock();
    }

    // Set the TLS for the platform itself
    let litebox_tls = litebox_common_linux::ThreadLocalStorage::new(task);
    litebox_platform_multiplex::platform().set_thread_local_storage(litebox_tls);

    // Set the TLS for the guest program
    if let Some(tls) = tls {
        // Set the TLS base pointer for the new thread
        #[cfg(target_arch = "x86")]
        set_thread_area(tls);

        #[cfg(target_arch = "x86_64")]
        {
            use litebox::platform::RawConstPointer as _;
            sys_arch_prctl(ArchPrctlArg::SetFs(tls.as_usize()));
        }
    }

    if let Some(set_child_tid) = set_child_tid {
        // Set the child TID if requested
        let _ = unsafe { set_child_tid.write_at_offset(0, child_tid) };
    }
}

/// Creates a new thread or process.
///
/// Note we currently only support creating threads with the VM, FS, and FILES flags set.
#[expect(clippy::too_many_arguments)]
pub(crate) fn sys_clone(
    flags: litebox_common_linux::CloneFlags,
    parent_tid: Option<crate::MutPtr<u32>>,
    stack: Option<crate::MutPtr<u8>>,
    stack_size: usize,
    child_tid: Option<crate::MutPtr<i32>>,
    tls: Option<crate::MutPtr<litebox_common_linux::ThreadLocalDescriptor>>,
    ctx: &litebox_common_linux::PtRegs,
    main: usize,
) -> Result<usize, Errno> {
    if !flags.contains(CloneFlags::VM) {
        unimplemented!("Clone without VM flag is not supported");
    }
    if !flags.contains(CloneFlags::FS) {
        unimplemented!("Clone without FS flag is not supported");
    }
    if !flags.contains(CloneFlags::FILES) {
        unimplemented!("Clone without FILES flag is not supported");
    }
    if !flags.contains(CloneFlags::SYSVSEM) {
        unimplemented!("Clone without SYSVSEM flag is not supported");
    }
    let unsupported_clone_flags = CloneFlags::PIDFD
        | CloneFlags::PTRACE
        | CloneFlags::VFORK
        | CloneFlags::PARENT
        | CloneFlags::NEWNS
        | CloneFlags::UNTRACED
        | CloneFlags::NEWCGROUP
        | CloneFlags::NEWUTS
        | CloneFlags::NEWIPC
        | CloneFlags::NEWUSER
        | CloneFlags::NEWPID
        | CloneFlags::NEWNET
        | CloneFlags::IO
        | CloneFlags::CLEAR_SIGHAND
        | CloneFlags::INTO_CGROUP
        | CloneFlags::NEWTIME;
    if flags.intersects(unsupported_clone_flags) {
        unimplemented!("Clone with unsupported flags: {:?}", flags);
    }

    let platform = litebox_platform_multiplex::platform();
    let (credentials, pid, parent_proc_id, comm) = platform.with_thread_local_storage_mut(|tls| {
        (
            tls.current_task.credentials.clone(),
            tls.current_task.pid,
            tls.current_task.ppid,
            tls.current_task.comm,
        )
    });

    let set_child_tid = if flags.contains(CloneFlags::CHILD_SETTID) {
        child_tid
    } else {
        None
    };
    let clear_child_tid = if flags.contains(CloneFlags::CHILD_CLEARTID) {
        child_tid
    } else {
        None
    };
    let set_parent_tid = if flags.contains(CloneFlags::PARENT_SETTID) {
        parent_tid
    } else {
        None
    };

    // Create an optional `guard` when parent_tid and child_tid point to the same address.
    // Clearing child_tid is always done after setting parent_tid, so this ensures these two
    // operations occur in order if they are on the same address.
    let start_gate = alloc::sync::Arc::new(crate::litebox().sync().new_mutex(()));
    let start_gate_clone = start_gate.clone();
    let guard = if let Some(parent_tid_ptr) = set_parent_tid
        && let Some(child_tid_ptr) = clear_child_tid
        && parent_tid_ptr.as_usize() == child_tid_ptr.as_usize()
    {
        // Lock the mutex before creating the thread, so that the new thread will block on it
        // until `guard` is dropped.
        Some(start_gate.lock())
    } else {
        None
    };

    let child_tid = unsafe {
        platform.spawn_thread(
            ctx,
            stack.expect("Stack pointer is required for thread creation"),
            stack_size,
            main,
            Box::new(litebox_common_linux::NewThreadArgs {
                tls,
                set_child_tid,
                start_gate: if guard.is_some() {
                    Some(start_gate_clone)
                } else {
                    None
                },
                task: Box::new(litebox_common_linux::Task {
                    pid,
                    tid: 0, // The actual TID will be set by the platform
                    ppid: parent_proc_id,
                    clear_child_tid,
                    robust_list: None,
                    credentials,
                    comm,
                }),
                callback: new_thread_callback,
            }),
        )
    }?;
    if let Some(parent_tid_ptr) = set_parent_tid {
        let _ = unsafe { parent_tid_ptr.write_at_offset(0, child_tid.truncate()) };
    }
    // After parent_tid is set, we can drop the guard to let the new thread proceed.
    drop(guard);

    NR_THREADS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Ok(child_tid)
}

/// Handle syscall `set_tid_address`.
pub(crate) fn sys_set_tid_address(tidptr: crate::MutPtr<i32>) -> i32 {
    unsafe {
        litebox_platform_multiplex::platform().with_thread_local_storage_mut(|tls| {
            tls.current_task.clear_child_tid = Some(tidptr);
            tls.current_task.tid
        })
    }
}

/// Handle syscall `gettid`.
pub(crate) fn sys_gettid() -> i32 {
    unsafe {
        litebox_platform_multiplex::platform()
            .with_thread_local_storage_mut(|tls| tls.current_task.tid)
    }
}

// TODO: enforce the following limits:
const RLIMIT_NOFILE_CUR: usize = 1024 * 1024;
const RLIMIT_NOFILE_MAX: usize = 1024 * 1024;

fn do_prlimit(
    pid: Option<i32>,
    resource: litebox_common_linux::RlimitResource,
    new_limit: Option<litebox_common_linux::Rlimit>,
) -> litebox_common_linux::Rlimit {
    if new_limit.is_some() {
        unimplemented!("Setting new limits is not supported yet");
    }
    if pid.is_some() {
        unimplemented!("prlimit for a specific PID is not supported yet");
    }

    match resource {
        litebox_common_linux::RlimitResource::STACK => litebox_common_linux::Rlimit {
            rlim_cur: crate::loader::DEFAULT_STACK_SIZE,
            rlim_max: litebox_common_linux::rlim_t::MAX,
        },
        litebox_common_linux::RlimitResource::NOFILE => litebox_common_linux::Rlimit {
            rlim_cur: RLIMIT_NOFILE_CUR,
            rlim_max: RLIMIT_NOFILE_MAX,
        },
        _ => unimplemented!("Unsupported resource for prlimit: {:?}", resource),
    }
}

/// Handle syscall `prlimit64`.
///
/// Note for now setting new limits is not supported yet, and thus returning constant values
/// for the requested resource. Getting resources for a specific PID is also not supported yet.
pub(crate) fn sys_prlimit(
    pid: Option<i32>,
    resource: litebox_common_linux::RlimitResource,
    new_rlim: Option<crate::ConstPtr<litebox_common_linux::Rlimit64>>,
    old_rlim: Option<crate::MutPtr<litebox_common_linux::Rlimit64>>,
) -> Result<(), Errno> {
    let new_limit = match new_rlim {
        Some(rlim) => {
            let rlim = unsafe { rlim.read_at_offset(0) }
                .ok_or(Errno::EINVAL)?
                .into_owned();
            Some(litebox_common_linux::rlimit64_to_rlimit(rlim))
        }
        None => None,
    };
    let old_limit = litebox_common_linux::rlimit_to_rlimit64(do_prlimit(pid, resource, new_limit));
    if let Some(old_rlim) = old_rlim {
        unsafe { old_rlim.write_at_offset(0, old_limit) }.ok_or(Errno::EINVAL)?;
    }
    Ok(())
}

/// Handle syscall `setrlimit`.
pub(crate) fn sys_getrlimit(
    resource: litebox_common_linux::RlimitResource,
    rlim: crate::MutPtr<litebox_common_linux::Rlimit>,
) -> Result<(), Errno> {
    let old_limit = do_prlimit(None, resource, None);
    unsafe { rlim.write_at_offset(0, old_limit) }.ok_or(Errno::EINVAL)
}

/// Handle syscall `setrlimit`.
pub(crate) fn sys_setrlimit(
    resource: litebox_common_linux::RlimitResource,
    rlim: crate::ConstPtr<litebox_common_linux::Rlimit>,
) -> Result<(), Errno> {
    let new_limit = unsafe { rlim.read_at_offset(0) }
        .ok_or(Errno::EFAULT)?
        .into_owned();
    let _ = do_prlimit(None, resource, Some(new_limit));
    Ok(())
}

/// Handle syscall `set_robust_list`.
pub(crate) fn sys_set_robust_list(head: usize) {
    let head = crate::ConstPtr::from_usize(head);
    litebox_platform_multiplex::platform().with_thread_local_storage_mut(|tls| {
        tls.current_task.robust_list = Some(head);
    });
}

/// Handle syscall `get_robust_list`.
pub(crate) fn sys_get_robust_list(
    pid: Option<i32>,
    head_ptr: crate::MutPtr<usize>,
) -> Result<(), Errno> {
    if pid.is_some() {
        unimplemented!("Getting robust list for a specific PID is not supported yet");
    }
    let head = litebox_platform_multiplex::platform().with_thread_local_storage_mut(|tls| {
        tls.current_task.robust_list.map_or(0, |ptr| ptr.as_usize())
    });
    unsafe { head_ptr.write_at_offset(0, head) }.ok_or(Errno::EFAULT)
}

fn real_time_as_duration_since_epoch() -> core::time::Duration {
    let now = litebox_platform_multiplex::platform().current_time();
    let unix_epoch = <litebox_platform_multiplex::Platform as TimeProvider>::SystemTime::UNIX_EPOCH;
    now.duration_since(&unix_epoch)
        .expect("must be after unix epoch")
}

/// Handle syscall `clock_gettime`.
pub(crate) fn sys_clock_gettime(
    clockid: litebox_common_linux::ClockId,
) -> Result<litebox_common_linux::Timespec, Errno> {
    let duration = gettime_as_duration(litebox_platform_multiplex::platform(), clockid)?;
    litebox_common_linux::Timespec::try_from(duration).or(Err(Errno::EOVERFLOW))
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "will fail for unknown clock IDs in the future"
)]
fn gettime_as_duration(
    platform: &litebox_platform_multiplex::Platform,
    clockid: litebox_common_linux::ClockId,
) -> Result<core::time::Duration, Errno> {
    let duration = match clockid {
        litebox_common_linux::ClockId::RealTime => {
            // CLOCK_REALTIME
            real_time_as_duration_since_epoch()
        }
        litebox_common_linux::ClockId::Monotonic => {
            // CLOCK_MONOTONIC
            platform.now().duration_since(crate::boot_time())
        }
        _ => unimplemented!(),
    };
    Ok(duration)
}

/// Handle syscall `clock_getres`.
pub(crate) fn sys_clock_getres(
    _clockid: litebox_common_linux::ClockId,
    res: crate::MutPtr<litebox_common_linux::Timespec>,
) {
    // Return the resolution of the clock
    // For most modern systems, the resolution is typically 1 nanosecond
    // This is a reasonable default for high-resolution timers
    let resolution = litebox_common_linux::Timespec {
        tv_sec: 0,
        tv_nsec: 1, // 1 nanosecond resolution
    };

    unsafe {
        res.write_at_offset(0, resolution);
    }
}

/// Handle syscall `clock_nanosleep`.
pub(crate) fn sys_clock_nanosleep(
    clockid: litebox_common_linux::ClockId,
    flags: litebox_common_linux::TimerFlags,
    request: crate::ConstPtr<litebox_common_linux::Timespec>,
    remain: Option<crate::MutPtr<litebox_common_linux::Timespec>>,
) -> Result<(), Errno> {
    let request = core::time::Duration::from(get_timeout(request)?);
    if flags.intersects(litebox_common_linux::TimerFlags::ABSTIME.complement()) {
        return Err(Errno::EINVAL);
    }
    let is_abs = flags.contains(litebox_common_linux::TimerFlags::ABSTIME);

    let platform = litebox_platform_multiplex::platform();
    let duration = if is_abs {
        let now = gettime_as_duration(platform, clockid)?;
        if request <= now {
            return Ok(());
        }
        request - now
    } else {
        request
    };

    // Reuse the raw mutex provider to implement sleep.
    //
    // TODO: consider a new litebox API to directly sleep, with integration with
    // interruptions.
    let r = platform.new_raw_mutex().block_or_timeout(0, duration);
    assert!(matches!(
        r,
        Ok(litebox::platform::UnblockedOrTimedOut::TimedOut)
    ),);

    // TODO: update the remainder for non-absolute sleeps interrupted by signals.
    let _ = remain;

    Ok(())
}

/// Handle syscall `gettimeofday`.
pub(crate) fn sys_gettimeofday(
    tv: crate::MutPtr<litebox_common_linux::TimeVal>,
    tz: crate::MutPtr<litebox_common_linux::TimeZone>,
) -> Result<(), Errno> {
    if tz.as_usize() != 0 {
        // `man 2 gettimeofday`: The use of the timezone structure is obsolete; the tz argument
        // should normally be specified as NULL.
        unimplemented!()
    }
    if tv.as_usize() == 0 {
        return Ok(());
    }
    let timeval = litebox_common_linux::Timespec::try_from(real_time_as_duration_since_epoch())
        .or(Err(Errno::EOVERFLOW))?
        .into();
    unsafe { tv.write_at_offset(0, timeval) }.ok_or(Errno::EFAULT)
}

/// Handle syscall `time`.
pub(crate) fn sys_time(
    tloc: crate::MutPtr<litebox_common_linux::time_t>,
) -> Result<litebox_common_linux::time_t, Errno> {
    let time = real_time_as_duration_since_epoch();
    let seconds: u64 = time.as_secs();
    let seconds: litebox_common_linux::time_t = seconds.try_into().or(Err(Errno::EOVERFLOW))?;
    if tloc.as_usize() != 0 {
        unsafe { tloc.write_at_offset(0, seconds) }.ok_or(Errno::EFAULT)?;
    }
    Ok(seconds)
}

/// Handle syscall `getpid`.
pub(crate) fn sys_getpid() -> i32 {
    litebox_platform_multiplex::platform().with_thread_local_storage_mut(|tls| tls.current_task.pid)
}

pub(crate) fn sys_getppid() -> i32 {
    litebox_platform_multiplex::platform()
        .with_thread_local_storage_mut(|tls| tls.current_task.ppid)
}

/// Handle syscall `getuid`.
pub(crate) fn sys_getuid() -> usize {
    litebox_platform_multiplex::platform()
        .with_thread_local_storage_mut(|tls| tls.current_task.credentials.uid)
}

/// Handle syscall `geteuid`.
pub(crate) fn sys_geteuid() -> usize {
    litebox_platform_multiplex::platform()
        .with_thread_local_storage_mut(|tls| tls.current_task.credentials.euid)
}

/// Handle syscall `getgid`.
pub(crate) fn sys_getgid() -> usize {
    litebox_platform_multiplex::platform()
        .with_thread_local_storage_mut(|tls| tls.current_task.credentials.gid)
}

/// Handle syscall `getegid`.
pub(crate) fn sys_getegid() -> usize {
    litebox_platform_multiplex::platform()
        .with_thread_local_storage_mut(|tls| tls.current_task.credentials.egid)
}

/// Number of CPUs
const NR_CPUS: usize = 2;

pub(crate) struct CpuSet {
    bits: bitvec::vec::BitVec<u8>,
}

impl CpuSet {
    pub(crate) fn len(&self) -> usize {
        self.bits.len()
    }
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bits.as_raw_slice()
    }
}

/// Handle syscall `sched_getaffinity`.
///
/// Note this is a dummy implementation that always returns the same CPU set
pub(crate) fn sys_sched_getaffinity(_pid: Option<i32>) -> CpuSet {
    let mut cpuset = bitvec::bitvec![u8, bitvec::order::Lsb0; 0; NR_CPUS];
    cpuset.iter_mut().for_each(|mut b| *b = true);
    CpuSet { bits: cpuset }
}

fn get_timeout(
    timeout: crate::ConstPtr<litebox_common_linux::Timespec>,
) -> Result<litebox_common_linux::Timespec, Errno> {
    let timeout = unsafe { timeout.read_at_offset(0) }.ok_or(Errno::EFAULT)?;
    if timeout.tv_sec < 0 || timeout.tv_nsec > 1_000_000_000 {
        return Err(Errno::EINVAL);
    }
    Ok(timeout.into_owned())
}

/// Handle syscall `futex`
pub(crate) fn sys_futex(
    arg: litebox_common_linux::FutexArgs<litebox_platform_multiplex::Platform>,
) -> Result<usize, Errno> {
    /// Note our mutex implementation assumes futexes are private as we don't support shared memory yet.
    /// It should be fine to treat shared futexes as private for now.
    macro_rules! warn_shared_futex {
        ($flag:ident) => {
            #[cfg(debug_assertions)]
            if !$flag.contains(litebox_common_linux::FutexFlags::PRIVATE) {
                litebox::log_println!(
                    litebox_platform_multiplex::platform(),
                    "warning: shared futexes\n"
                );
            }
        };
    }

    let res = match arg {
        FutexArgs::Wake { addr, flags, count } => {
            warn_shared_futex!(flags);
            let Some(count) = core::num::NonZeroU32::new(count) else {
                return Ok(0);
            };
            let futex_manager = crate::litebox_futex_manager();
            futex_manager.wake(addr, count, None)? as usize
        }
        FutexArgs::Wait {
            addr,
            flags,
            val,
            timeout,
        } => {
            warn_shared_futex!(flags);
            let futex_manager = crate::litebox_futex_manager();
            let timeout = timeout.map(get_timeout).transpose()?.map(Into::into);
            futex_manager.wait(addr, val, timeout, None)?;
            0
        }
        litebox_common_linux::FutexArgs::WaitBitset {
            addr,
            flags,
            val,
            timeout,
            bitmask,
        } => {
            warn_shared_futex!(flags);
            let timeout = timeout.map(get_timeout).transpose()?.map(|ts| {
                let now = sys_clock_gettime(
                    if flags.contains(litebox_common_linux::FutexFlags::CLOCK_REALTIME) {
                        litebox_common_linux::ClockId::RealTime
                    } else {
                        litebox_common_linux::ClockId::Monotonic
                    },
                )
                .expect("failed to get current time");
                ts.sub_timespec(&now).unwrap_or(core::time::Duration::ZERO)
            });
            let futex_manager = crate::litebox_futex_manager();
            futex_manager.wait(addr, val, timeout, core::num::NonZeroU32::new(bitmask))?;
            0
        }
        _ => unimplemented!("Unsupported futex operation"),
    };
    Ok(res)
}

pub type ExecveCallback = fn(
    path: &str,
    argv: alloc::vec::Vec<alloc::ffi::CString>,
    envp: alloc::vec::Vec<alloc::ffi::CString>,
) -> Result<(), Errno>;
static EXECVE_CALLBACK: once_cell::race::OnceBox<ExecveCallback> = once_cell::race::OnceBox::new();

/// Set the execve callback, which is responsible for loading and jumping to the new program.
///
/// # Panics
///
/// This function should be called only once during initialization.
pub fn set_execve_callback(callback: ExecveCallback) {
    EXECVE_CALLBACK
        .set(Box::new(callback))
        .expect("execve callback already set");
}

const MAX_VEC: usize = 4096; // limit count
const MAX_TOTAL_BYTES: usize = 256 * 1024; // size cap

// Handle syscall `execve`.
//
// Note this function does not return on success.
pub(crate) fn sys_execve(
    pathname: crate::ConstPtr<i8>,
    argv: crate::ConstPtr<crate::ConstPtr<i8>>,
    envp: crate::ConstPtr<crate::ConstPtr<i8>>,
) -> Result<(), Errno> {
    fn copy_vector(
        mut base: crate::ConstPtr<crate::ConstPtr<i8>>,
        which: &str,
    ) -> Result<alloc::vec::Vec<alloc::ffi::CString>, Errno> {
        let mut out = alloc::vec::Vec::new();
        let mut total = 0usize;
        for _ in 0..MAX_VEC {
            let p: crate::ConstPtr<i8> = unsafe {
                // read pointer-sized entries
                match base.read_at_offset(0) {
                    Some(ptr) => ptr.into_owned(),
                    None => return Err(Errno::EFAULT),
                }
            };
            if p.as_usize() == 0 {
                break;
            }
            let Some(cs) = p.to_cstring() else {
                return Err(Errno::EFAULT);
            };
            total += cs.as_bytes().len() + 1;
            if total > MAX_TOTAL_BYTES {
                return Err(Errno::E2BIG);
            }
            out.push(cs);
            // advance to next pointer
            base = crate::ConstPtr::from_usize(base.as_usize() + core::mem::size_of::<usize>());
        }
        Ok(out)
    }

    // Copy pathname
    let Some(path_cstr) = pathname.to_cstring() else {
        return Err(Errno::EFAULT);
    };
    let path = path_cstr.to_str().map_err(|_| Errno::ENOENT)?;

    // Copy argv and envp vectors
    let argv_vec = if argv.as_usize() == 0 {
        alloc::vec::Vec::new()
    } else {
        copy_vector(argv, "argv")?
    };
    let envp_vec = if envp.as_usize() == 0 {
        alloc::vec::Vec::new()
    } else {
        copy_vector(envp, "envp")?
    };

    // Close CLOEXEC descriptors
    crate::file_descriptors().write().close_on_exec();

    // unmmap all memory mappings and reset brk
    litebox_platform_multiplex::platform().with_thread_local_storage_mut(|tls| {
        tls.current_task.robust_list = None;

        if let Some(robust_list) = tls.current_task.robust_list.take() {
            let _ = wake_robust_list(robust_list);
        }

        // Check if we are the only thread in the process
        // Note since we don't support multiple processes yet; `NR_THREADS` is effectively the number of threads in
        // the current process.
        if NR_THREADS.load(core::sync::atomic::Ordering::Relaxed) != 1 {
            unimplemented!("execve when multiple threads exist is not supported yet");
        }
        let release = |r: Range<usize>, vm: VmFlags| {
            // Reserved mappings
            if vm.is_empty() {
                return false;
            }
            if vm.contains(VmFlags::VM_GROWSDOWN) {
                // Stack we are currently running on, don't unmap it.
                // This happens when litebox runs in user space so that
                // it shares the stack with the guest program.
                let rsp: usize;
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    core::arch::asm!(
                        "mov {}, rsp",
                        out(reg) rsp,
                    );
                }
                #[cfg(target_arch = "x86")]
                unsafe {
                    core::arch::asm!(
                        "mov {}, esp",
                        out(reg) rsp,
                    );
                }
                if r.start <= rsp && rsp < r.end {
                    return false;
                }
            }
            true
        };
        let page_manager = crate::litebox_page_manager();
        unsafe { page_manager.release_memory(release) }.expect("failed to release memory mappings");
    });
    #[cfg(target_arch = "x86")]
    litebox_platform_multiplex::platform().clear_guest_thread_local_storage();

    let callback = EXECVE_CALLBACK.get().expect("execve callback is not set");
    // if `execve` fails, it is unrecoverable at this point as we have already unmapped everything.
    // TODO: add some basic checks before we unmap everything
    callback(path, argv_vec, envp_vec).expect("we already released memory above");
    unreachable!("execve callback must not return on success");
}

/// Handle syscall `alarm`.
pub(crate) fn sys_alarm(seconds: u32) -> Result<usize, Errno> {
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(litebox_common_linux::PunchthroughSyscall::Alarm { seconds })
        .expect("Failed to get punchthrough token for SET_ALARM");
    token.execute().map_err(|e| match e {
        litebox::platform::PunchthroughError::Failure(errno) => errno,
        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
    })
}

/// Handle syscall `tgkill`.
pub(crate) fn sys_tgkill(
    thread_group_id: i32,
    thread_id: i32,
    sig: litebox_common_linux::Signal,
) -> Result<(), Errno> {
    if thread_id <= 0 || thread_group_id <= 0 {
        return Err(Errno::EINVAL);
    }
    if thread_group_id != sys_getpid() {
        unimplemented!("Sending signal to other processes is not supported yet");
    }
    let punchthrough = litebox_common_linux::PunchthroughSyscall::ThreadKill {
        thread_group_id,
        thread_id,
        sig,
    };
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(punchthrough)
        .expect("Failed to get punchthrough token for TGKILL");
    token.execute().map(|_| ()).map_err(|e| match e {
        litebox::platform::PunchthroughError::Failure(errno) => errno,
        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
    })
}

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;

    use litebox::{mm::linux::PAGE_SIZE, platform::RawConstPointer as _, utils::TruncateExt as _};
    use litebox_common_linux::{CloneFlags, MapFlags, ProtFlags};

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_arch_prctl() {
        use super::sys_arch_prctl;
        use crate::{MutPtr, syscalls::tests::init_platform};
        use core::mem::MaybeUninit;
        use litebox_common_linux::ArchPrctlArg;

        init_platform(None);

        // Save old FS base
        let mut old_fs_base = MaybeUninit::<usize>::uninit();
        let ptr = MutPtr {
            inner: old_fs_base.as_mut_ptr(),
        };
        sys_arch_prctl(ArchPrctlArg::GetFs(ptr)).expect("Failed to get FS base");
        let old_fs_base = unsafe { old_fs_base.assume_init() };

        // Set new FS base
        let mut new_fs_base: [u8; 16] = [0; 16];
        let ptr = crate::MutPtr {
            inner: new_fs_base.as_mut_ptr(),
        };
        sys_arch_prctl(ArchPrctlArg::SetFs(ptr.as_usize())).expect("Failed to set FS base");

        // Verify new FS base
        let mut current_fs_base = MaybeUninit::<usize>::uninit();
        let ptr = MutPtr {
            inner: current_fs_base.as_mut_ptr(),
        };
        sys_arch_prctl(ArchPrctlArg::GetFs(ptr)).expect("Failed to get FS base");
        let current_fs_base = unsafe { current_fs_base.assume_init() };
        assert_eq!(current_fs_base, new_fs_base.as_ptr() as usize);

        // Restore old FS base
        let ptr: crate::MutPtr<u8> = crate::MutPtr::from_usize(old_fs_base);
        sys_arch_prctl(ArchPrctlArg::SetFs(ptr.as_usize())).expect("Failed to restore FS base");
    }

    // Initialize a static TLS area with value `1`. This value is later on used to verify that
    // the TLS is set up correctly.
    static mut TLS: [u8; PAGE_SIZE] = [1; PAGE_SIZE];
    static mut CHILD_TID: i32 = 0;
    static mut PARENT_PID: i32 = 0;

    /// Create an aligned entry point for the new thread.
    ///
    /// The stack pointer at the entry of the new thread is 16-byte aligned, but x86_64 ABI expects
    /// RSP % 16 == 8 at normal function entry (because the CALL pushed a return address). Similarly,
    /// x86 ABI expects ESP % 16 == 12 on function entry.
    /// We only need to do this if we want to pass a Rust function to `sys_clone`.
    macro_rules! make_aligned_entry {
        ($wrapper:ident, $target:path) => {
            #[cfg(target_arch = "x86_64")]
            #[unsafe(no_mangle)]
            #[unsafe(naked)]
            pub extern "C" fn $wrapper() -> ! {
                unsafe {
                    core::arch::naked_asm!(
                        "and rsp, -16",  // make it 16-byte aligned
                        "call {func}",
                        func = sym $target,
                    )
                }
            }
            #[cfg(target_arch = "x86")]
            #[unsafe(no_mangle)]
            #[unsafe(naked)]
            pub extern "C" fn $wrapper() -> ! {
                unsafe {
                    core::arch::naked_asm!(
                        "and esp, -16",  // make it 16-byte aligned
                        "call {func}",
                        func = sym $target,
                    )
                }
            }
        };
    }

    #[unsafe(no_mangle)]
    extern "C" fn new_thread_main_test() -> ! {
        let tid = super::sys_gettid();
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "Child started {}",
            tid
        );

        assert_eq!(
            unsafe { PARENT_PID },
            super::sys_getppid(),
            "Parent PID should match"
        );

        #[cfg(target_arch = "x86_64")]
        {
            let mut current_fs_base = MaybeUninit::<usize>::uninit();
            super::sys_arch_prctl(litebox_common_linux::ArchPrctlArg::GetFs(crate::MutPtr {
                inner: current_fs_base.as_mut_ptr(),
            }))
            .expect("Failed to get FS base");
            #[allow(static_mut_refs)]
            let addr = unsafe { TLS.as_ptr() } as usize;
            assert_eq!(
                addr,
                unsafe { current_fs_base.assume_init() },
                "FS base should match TLS pointer"
            );

            // Check the TLS value from FS base
            let mut fs_0: u8;
            unsafe {
                core::arch::asm!("mov {0}, fs:0", out(reg_byte) fs_0);
            }
            // Verify that the TLS value is initialized to its correct value (`1`).
            assert_eq!(
                fs_0, 0x1,
                "TLS value from FS base should match the initialized value"
            );
        }

        assert!(unsafe { CHILD_TID } > 0, "Child TID should be set");
        assert_eq!(
            unsafe { CHILD_TID },
            tid,
            "Child TID should match sys_gettid result"
        );
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "Child TID: {}",
            unsafe { CHILD_TID }
        );
        super::sys_exit(0);
    }

    #[test]
    #[expect(clippy::too_many_lines)]
    fn test_thread_spawn() {
        crate::syscalls::tests::init_platform(None);

        let stack_size = 8 * 1024 * 1024; // 8 MiB
        let stack = crate::syscalls::mm::sys_mmap(
            0,
            stack_size,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
        .expect("Failed to allocate stack");

        let mut parent_tid = MaybeUninit::<u32>::uninit();
        let parent_tid_ptr = crate::MutPtr {
            inner: parent_tid.as_mut_ptr(),
        };

        #[allow(static_mut_refs)]
        let child_tid_ptr = crate::MutPtr {
            inner: &raw mut CHILD_TID,
        };

        let flags = CloneFlags::THREAD
            | CloneFlags::VM
            | CloneFlags::FS
            | CloneFlags::FILES
            | CloneFlags::SIGHAND
            | CloneFlags::PARENT_SETTID
            | CloneFlags::CHILD_SETTID
            | CloneFlags::CHILD_CLEARTID
            | CloneFlags::SYSVSEM;

        // Call sys_clone
        #[cfg(target_arch = "x86_64")]
        let pt_regs = litebox_common_linux::PtRegs {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            orig_rax: syscalls::Sysno::clone3 as usize,
            rip: 0,
            cs: 0x33, // __USER_CS
            eflags: 0,
            rsp: 0,
            ss: 0x2b, // __USER_DS
        };
        #[cfg(target_arch = "x86")]
        let pt_regs = litebox_common_linux::PtRegs {
            ebx: 0,
            ecx: 0,
            edx: 0,
            esi: 0,
            edi: 0,
            ebp: 0,
            eax: 0,
            xds: 0,
            xes: 0,
            xfs: 0,
            xgs: 0,
            orig_eax: syscalls::Sysno::clone3 as usize,
            eip: 0,
            xcs: 0x23, // __USER_CS
            eflags: 0,
            esp: 0,
            xss: 0x2b, // __USER_DS
        };
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "stack allocated at: {:#x}",
            stack.as_usize()
        );
        unsafe { PARENT_PID = super::sys_getppid() };

        #[cfg(target_arch = "x86")]
        let mut user_desc = {
            let mut flags = litebox_common_linux::UserDescFlags(0);
            flags.set_seg_32bit(true);
            flags.set_useable(true);
            litebox_common_linux::UserDesc {
                entry_number: u32::MAX,
                #[allow(static_mut_refs)]
                base_addr: unsafe { TLS.as_mut_ptr() } as u32,
                limit: u32::try_from(core::mem::size_of::<
                    litebox_common_linux::ThreadLocalStorage<litebox_platform_multiplex::Platform>,
                >())
                .unwrap()
                    - 1,
                flags,
            }
        };

        make_aligned_entry!(main_wrapper, new_thread_main_test);
        let child_tid = super::sys_clone(
            flags,
            Some(parent_tid_ptr),
            Some(stack),
            stack_size,
            Some(child_tid_ptr),
            Some(crate::MutPtr {
                #[cfg(target_arch = "x86_64")]
                #[allow(static_mut_refs)]
                inner: unsafe { TLS.as_mut_ptr() },
                #[cfg(target_arch = "x86")]
                inner: &raw mut user_desc,
            }),
            &pt_regs,
            main_wrapper as usize,
        )
        .expect("sys_clone failed");
        litebox::log_println!(
            litebox_platform_multiplex::platform(),
            "sys_clone returned: {}",
            child_tid
        );
        assert_eq!(
            unsafe { parent_tid.assume_init() } as usize,
            child_tid,
            "Child's TID mismatch"
        );
        // Test if CloneFlags::CHILD_CLEARTID works: child thread should clear it and wake up one thread
        // that is waiting on it.
        let futex_ptr = crate::MutPtr::from_usize(child_tid_ptr.as_usize());
        let _ = super::sys_futex(litebox_common_linux::FutexArgs::Wait {
            addr: futex_ptr,
            flags: litebox_common_linux::FutexFlags::PRIVATE,
            val: child_tid.truncate(),
            timeout: None,
        });
    }

    #[test]
    fn test_sched_getaffinity() {
        crate::syscalls::tests::init_platform(None);

        let cpuset = super::sys_sched_getaffinity(None);
        assert_eq!(cpuset.bits.len(), super::NR_CPUS);
        cpuset.bits.iter().for_each(|b| assert!(*b));
        let ones: usize = cpuset
            .as_bytes()
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum();
        assert_eq!(ones, super::NR_CPUS);
    }

    #[test]
    fn test_prctl_set_get_name() {
        crate::syscalls::tests::init_platform(None);

        // Prepare a null-terminated name to set
        let name: &[u8] = b"litebox-test\0";

        // Call prctl(PR_SET_NAME, set_buf)
        let set_ptr = crate::ConstPtr {
            inner: name.as_ptr(),
        };
        super::sys_prctl(litebox_common_linux::PrctlArg::SetName(set_ptr))
            .expect("sys_prctl SetName failed");

        // Prepare buffer for prctl(PR_GET_NAME, get_buf)
        let mut get_buf = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let get_ptr = crate::MutPtr {
            inner: get_buf.as_mut_ptr(),
        };

        super::sys_prctl(litebox_common_linux::PrctlArg::GetName(get_ptr))
            .expect("sys_prctl GetName failed");
        assert_eq!(
            &get_buf[..name.len()],
            name,
            "prctl get_name returned unexpected comm"
        );

        // Test too long name
        let long_name = [b'a'; litebox_common_linux::TASK_COMM_LEN + 10];
        let long_name_ptr = crate::ConstPtr {
            inner: long_name.as_ptr(),
        };
        super::sys_prctl(litebox_common_linux::PrctlArg::SetName(long_name_ptr))
            .expect("sys_prctl SetName failed");

        // Get the name again
        let mut get_buf = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let get_ptr = crate::MutPtr {
            inner: get_buf.as_mut_ptr(),
        };
        super::sys_prctl(litebox_common_linux::PrctlArg::GetName(get_ptr))
            .expect("sys_prctl GetName failed");
        assert_eq!(
            get_buf[litebox_common_linux::TASK_COMM_LEN - 1],
            0,
            "prctl get_name did not null-terminate the comm"
        );
        assert_eq!(
            &get_buf[..litebox_common_linux::TASK_COMM_LEN - 1],
            &long_name[..litebox_common_linux::TASK_COMM_LEN - 1],
            "prctl get_name returned unexpected comm for too long name"
        );
    }
}
