//! Process/thread related syscalls.

use core::mem::offset_of;

use alloc::boxed::Box;
use litebox::platform::{ExitProvider as _, RawMutPointer as _, ThreadProvider as _};
use litebox::platform::{Instant as _, SystemTime as _, TimeProvider};
use litebox::platform::{
    PunchthroughProvider as _, PunchthroughToken as _, RawConstPointer as _,
    ThreadLocalStorageProvider as _,
};
use litebox::utils::TruncateExt as _;
use litebox_common_linux::CloneFlags;
use litebox_common_linux::{ArchPrctlArg, errno::Errno};

use crate::MutPtr;

/// A global counter for the number of threads in the system.
pub(super) static NR_THREADS: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(1);

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

fn futex_wake(addr: MutPtr<i32>) {
    let punchthrough = litebox_common_linux::PunchthroughSyscall::WakeByAddress { addr };
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(punchthrough)
        .expect("Failed to get punchthrough token for FUTEX_WAKE");
    token.execute().unwrap_or_else(|e| match e {
        litebox::platform::PunchthroughError::Failure(errno) => {
            panic!("FUTEX_WAKE failed with error: {:?}", errno)
        }
        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
    });
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
        futex_wake(clear_child_tid);
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
        callback: _,
    } = args;
    let child_tid = task.tid;

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
    let (credentials, pid, parent_proc_id) = platform.with_thread_local_storage_mut(|tls| {
        (
            tls.current_task.credentials.clone(),
            tls.current_task.pid,
            tls.current_task.ppid,
        )
    });
    let child_tid = unsafe {
        platform.spawn_thread(
            ctx,
            stack.expect("Stack pointer is required for thread creation"),
            stack_size,
            main,
            Box::new(litebox_common_linux::NewThreadArgs {
                tls,
                set_child_tid: if flags.contains(CloneFlags::CHILD_SETTID) {
                    child_tid
                } else {
                    None
                },
                task: Box::new(litebox_common_linux::Task {
                    pid,
                    tid: 0, // The actual TID will be set by the platform
                    ppid: parent_proc_id,
                    clear_child_tid: if flags.contains(CloneFlags::CHILD_CLEARTID) {
                        child_tid
                    } else {
                        None
                    },
                    robust_list: None,
                    credentials,
                }),
                callback: new_thread_callback,
            }),
        )
    }?;
    if flags.contains(CloneFlags::PARENT_SETTID)
        && let Some(parent_tid_ptr) = parent_tid
    {
        let _ = unsafe { parent_tid_ptr.write_at_offset(0, child_tid.truncate()) };
    }
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
    clockid: i32,
    tp: crate::MutPtr<litebox_common_linux::Timespec>,
) -> Result<(), Errno> {
    let duration: core::time::Duration = match clockid {
        0 => {
            // CLOCK_REALTIME
            real_time_as_duration_since_epoch()
        }
        1 => {
            // CLOCK_MONOTONIC
            let now = litebox_platform_multiplex::platform().now();
            now.duration_since(crate::boot_time())
        }
        _ => unimplemented!(),
    };
    let timespec = litebox_common_linux::Timespec::try_from(duration).or(Err(Errno::EOVERFLOW))?;
    unsafe { tp.write_at_offset(0, timespec) }.ok_or(Errno::EFAULT)
}

/// Handle syscall `clock_getres`.
pub(crate) fn sys_clock_getres(_clockid: i32, res: crate::MutPtr<litebox_common_linux::Timespec>) {
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
pub(crate) fn sys_sched_getaffinity(pid: Option<i32>) -> CpuSet {
    if pid.is_some() {
        unimplemented!("Getting CPU affinity for a specific PID is not supported yet");
    }
    let mut cpuset = bitvec::bitvec![u8, bitvec::order::Lsb0; 0; NR_CPUS];
    cpuset.iter_mut().for_each(|mut b| *b = true);
    CpuSet { bits: cpuset }
}

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;

    use litebox::{mm::linux::PAGE_SIZE, platform::RawConstPointer as _};
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
            "Child started {tid}"
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
        let result = super::sys_clone(
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
            result
        );
        assert!(result > 0, "sys_clone should return a positive PID");
        assert_eq!(
            unsafe { parent_tid.assume_init() } as usize,
            result,
            "Parent TID mismatch"
        );
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
}
