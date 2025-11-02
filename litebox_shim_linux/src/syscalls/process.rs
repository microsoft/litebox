//! Process/thread related syscalls.

use crate::Task;
use crate::UserMutPointer;
use alloc::boxed::Box;
use core::mem::offset_of;
use core::ops::Range;
use core::sync::atomic::AtomicI32;
use litebox::mm::linux::VmFlags;
use litebox::platform::{Instant as _, SystemTime as _, TimeProvider};
use litebox::platform::{
    PunchthroughProvider as _, PunchthroughToken as _, RawConstPointer as _, RawMutex as _,
    RawMutexProvider as _, ThreadLocalStorageProvider as _,
};
use litebox::platform::{RawMutPointer as _, ThreadProvider as _};
#[cfg(target_arch = "x86")]
use litebox::utils::TruncateExt;
use litebox_common_linux::{ArchPrctlArg, errno::Errno};
use litebox_common_linux::{CloneFlags, FutexArgs, PrctlArg};

/// A structure representing a process
pub(crate) struct Process {
    /// number of threads in this process
    pub(crate) nr_threads: core::sync::atomic::AtomicU16,
    /// resource limits for this process
    pub(crate) limits: ResourceLimits,
}

impl Process {
    pub fn new() -> Self {
        Self {
            nr_threads: 1.into(),
            limits: ResourceLimits::default(),
        }
    }
}

/// Credentials of a process
#[derive(Clone)]
pub(crate) struct Credentials {
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
}

// TODO: better management of thread IDs
pub(crate) static NEXT_THREAD_ID: AtomicI32 = AtomicI32::new(2); // start from 2, as 1 is used by the main thread

impl Task {
    /// Set the current task's command name.
    pub(crate) fn set_task_comm(&self, comm: &[u8]) {
        let mut new_comm = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let comm = &comm[..comm.len().min(litebox_common_linux::TASK_COMM_LEN - 1)];
        new_comm[..comm.len()].copy_from_slice(comm);
        self.comm.set(new_comm);
    }

    /// Handle syscall `prctl`.
    pub(crate) fn sys_prctl(
        &self,
        arg: PrctlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<usize, Errno> {
        match arg {
            PrctlArg::GetName(name) => unsafe { name.write_slice_at_offset(0, &self.comm.get()) }
                .ok_or(Errno::EFAULT)
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
                self.set_task_comm(&name_buf);
                Ok(0)
            }
            PrctlArg::CapBSetRead(cap) => {
                // Return 1 if the capability specified in cap is in the calling
                // thread's capability bounding set, or 0 if it is not.
                if cap
                    > litebox_common_linux::CapSet::LAST_CAP
                        .bits()
                        .trailing_zeros() as usize
                {
                    return Err(Errno::EINVAL);
                }
                // Note we don't support capabilities in LiteBox, so we always return 0.
                Ok(0)
            }
            _ => unimplemented!(),
        }
    }

    /// Handle syscall `arch_prctl`.
    pub(crate) fn sys_arch_prctl(
        &self,
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
        &self,
        user_desc: crate::MutPtr<litebox_common_linux::UserDesc>,
    ) -> Result<(), Errno> {
        Err(Errno::ENOSYS) // x86_64 does not support set_thread_area
    }

    #[cfg(target_arch = "x86")]
    pub(crate) fn set_thread_area(
        &self,
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
        &self,
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
        &self,
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

impl Task {
    /// Called when the task is exiting.
    pub(crate) fn prepare_for_exit(&mut self) {
        if let Some(clear_child_tid) = self.clear_child_tid.take() {
            // Clear the child TID if requested
            // TODO: if we are the last thread, we don't need to clear it
            let _ = unsafe { clear_child_tid.write_at_offset(0, 0) };
            // Cast from *i32 to *u32
            let clear_child_tid = crate::MutPtr::from_usize(clear_child_tid.as_usize());
            let _ = self.sys_futex(litebox_common_linux::FutexArgs::Wake {
                addr: clear_child_tid,
                flags: litebox_common_linux::FutexFlags::PRIVATE,
                count: 1,
            });
        }
        if let Some(robust_list) = self.robust_list.take() {
            let _ = wake_robust_list(robust_list);
        }

        self.process
            .nr_threads
            .fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn sys_exit(&self, _status: i32) {
        // Nothing to do yet. The `Task` will be dropped on the way out of the
        // shim, which will call `self.prepare_for_exit()`.
    }

    pub(crate) fn sys_exit_group(&self, _status: i32) {
        // Tear down occurs similarly to `sys_exit`.
        //
        // TODO: remotely kill other threads.
    }
}

/// A descriptor for thread-local storage (TLS).
///
/// On `x86_64`, this is represented as a `u8`. The TLS pointer can point to
/// an arbitrary-sized memory region.
#[cfg(target_arch = "x86_64")]
type ThreadLocalDescriptor = u8;

/// A descriptor for thread-local storage (TLS).
///
/// On `x86`, this is represented as a `UserDesc`, which provides a more
/// structured descriptor (e.g., base address, limit, flags).
#[cfg(target_arch = "x86")]
type ThreadLocalDescriptor = litebox_common_linux::UserDesc;

struct NewThreadArgs {
    /// Pointer to thread-local storage (TLS) given by the guest program
    tls: Option<UserMutPointer<ThreadLocalDescriptor>>,
    /// Where to store child TID in child's memory
    set_child_tid: Option<UserMutPointer<i32>>,
    /// Task struct that maintains all per-thread data
    task: Task,
}

// FUTURE: Consider revisiting this impl, see <https://github.com/microsoft/litebox/issues/431>.
unsafe impl Send for NewThreadArgs {}

impl litebox::shim::InitThread for NewThreadArgs {
    fn init(self: alloc::boxed::Box<Self>) {
        let Self {
            task,
            tls,
            set_child_tid,
        } = *self;

        let child_tid = task.tid;

        // Set the TLS for the guest program.
        //
        // Note that the following calls happen _before_ setting `SHIM_TLS`, so
        // any calls to `with_current_task` will panic. This should be OK--only
        // entry point code should be calling `with_current_task`.
        if let Some(tls) = tls {
            // Set the TLS base pointer for the new thread
            #[cfg(target_arch = "x86")]
            task.set_thread_area(tls);

            #[cfg(target_arch = "x86_64")]
            {
                use litebox::platform::RawConstPointer as _;
                task.sys_arch_prctl(ArchPrctlArg::SetFs(tls.as_usize()));
            }
        }

        if let Some(child_tid_ptr) = set_child_tid {
            // Set the child TID if requested
            let _ = unsafe { child_tid_ptr.write_at_offset(0, child_tid) };
        }

        // Set the shim TLS to point to the new task.
        crate::SHIM_TLS.init(crate::LinuxShimTls { current_task: task });
    }
}

impl Task {
    /// Creates a new thread or process.
    ///
    /// Note we currently only support creating threads with the VM, FS, and FILES flags set.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn sys_clone(
        &self,
        flags: litebox_common_linux::CloneFlags,
        parent_tid: Option<crate::MutPtr<i32>>,
        stack: Option<crate::MutPtr<u8>>,
        stack_size: usize,
        child_tid: Option<crate::MutPtr<i32>>,
        tls: Option<crate::MutPtr<ThreadLocalDescriptor>>,
        ctx: &litebox_common_linux::PtRegs,
        main: usize,
    ) -> Result<usize, Errno> {
        if !flags.contains(CloneFlags::VM) {
            unimplemented!("Clone without VM flag is not supported");
        }
        if !flags.contains(CloneFlags::FILES) {
            unimplemented!("Clone without FILES flag is not supported");
        }
        if !flags.contains(CloneFlags::SYSVSEM) {
            unimplemented!("Clone without SYSVSEM flag is not supported");
        }
        if !flags.contains(CloneFlags::THREAD | CloneFlags::SIGHAND) {
            unimplemented!("Clone without THREAD or SIGHAND flag is not supported");
        }
        let unsupported_clone_flags = CloneFlags::PIDFD
            | CloneFlags::PTRACE
            | CloneFlags::VFORK
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
        let fs = if flags.contains(CloneFlags::FS) {
            self.fs.borrow().clone()
        } else {
            alloc::sync::Arc::new((**self.fs.borrow()).clone())
        };

        let child_tid = NEXT_THREAD_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if let Some(parent_tid_ptr) = set_parent_tid {
            let _ = unsafe { parent_tid_ptr.write_at_offset(0, child_tid) };
        }

        let stack = stack.expect("Stack must be provided when creating a new thread");

        let mut ctx_copy = *ctx;

        // Update the context for the new thread. Note that the new thread gets a
        // return value of 0.
        #[cfg(target_arch = "x86_64")]
        {
            ctx_copy.rip = main;
            ctx_copy.rsp = stack.as_usize() + stack_size;
            ctx_copy.rax = 0;
        }
        #[cfg(target_arch = "x86")]
        {
            ctx_copy.eip = main;
            ctx_copy.esp = stack.as_usize() + stack_size;
            ctx_copy.eax = 0;
        }

        self.process
            .nr_threads
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        let r = unsafe {
            litebox_platform_multiplex::platform().spawn_thread(
                &ctx_copy,
                Box::new(NewThreadArgs {
                    tls,
                    set_child_tid,
                    task: Task {
                        pid: self.pid,
                        tid: child_tid,
                        ppid: self.ppid,
                        clear_child_tid: clear_child_tid.into(),
                        robust_list: None.into(),
                        credentials: self.credentials.clone(),
                        comm: self.comm.clone(),
                        fs: fs.into(),
                        process: self.process.clone(),
                    },
                }),
            )
        };

        if let Err(err) = r {
            self.process
                .nr_threads
                .fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
            return Err(err);
        }

        Ok(usize::try_from(child_tid).unwrap())
    }

    /// Handle syscall `set_tid_address`.
    pub(crate) fn sys_set_tid_address(&self, tidptr: crate::MutPtr<i32>) -> i32 {
        self.clear_child_tid.set(Some(tidptr));
        self.tid
    }

    /// Handle syscall `gettid`.
    pub(crate) fn sys_gettid(&self) -> i32 {
        self.tid
    }
}

// TODO: enforce the following limits:
const RLIMIT_NOFILE_CUR: usize = 1024 * 1024;
const RLIMIT_NOFILE_MAX: usize = 1024 * 1024;

struct AtomicRlimit {
    cur: core::sync::atomic::AtomicUsize,
    max: core::sync::atomic::AtomicUsize,
}

impl AtomicRlimit {
    const fn new(cur: usize, max: usize) -> Self {
        Self {
            cur: core::sync::atomic::AtomicUsize::new(cur),
            max: core::sync::atomic::AtomicUsize::new(max),
        }
    }
}

pub(crate) struct ResourceLimits {
    limits: [AtomicRlimit; litebox_common_linux::RlimitResource::RLIM_NLIMITS],
}

impl ResourceLimits {
    const fn default() -> Self {
        seq_macro::seq!(N in 0..16 {
            let mut limits = [
                #(
                    AtomicRlimit::new(0, 0),
                )*
            ];
        });
        limits[litebox_common_linux::RlimitResource::NOFILE as usize] = AtomicRlimit {
            cur: core::sync::atomic::AtomicUsize::new(RLIMIT_NOFILE_CUR),
            max: core::sync::atomic::AtomicUsize::new(RLIMIT_NOFILE_MAX),
        };
        limits[litebox_common_linux::RlimitResource::STACK as usize] = AtomicRlimit {
            cur: core::sync::atomic::AtomicUsize::new(crate::loader::DEFAULT_STACK_SIZE),
            max: core::sync::atomic::AtomicUsize::new(litebox_common_linux::rlim_t::MAX),
        };
        Self { limits }
    }

    pub(crate) fn get_rlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
    ) -> litebox_common_linux::Rlimit {
        let r = &self.limits[resource as usize];
        litebox_common_linux::Rlimit {
            rlim_cur: r.cur.load(core::sync::atomic::Ordering::Relaxed),
            rlim_max: r.max.load(core::sync::atomic::Ordering::Relaxed),
        }
    }

    pub(crate) fn get_rlimit_cur(&self, resource: litebox_common_linux::RlimitResource) -> usize {
        let r = &self.limits[resource as usize];
        r.cur.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn set_rlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        new_limit: litebox_common_linux::Rlimit,
    ) {
        let r = &self.limits[resource as usize];
        r.cur
            .store(new_limit.rlim_cur, core::sync::atomic::Ordering::Relaxed);
        r.max
            .store(new_limit.rlim_max, core::sync::atomic::Ordering::Relaxed);
    }
}

impl Task {
    /// Get resource limits, and optionally set new limits.
    pub(crate) fn do_prlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        new_limit: Option<litebox_common_linux::Rlimit>,
    ) -> Result<litebox_common_linux::Rlimit, Errno> {
        let old_rlimit = match resource {
            litebox_common_linux::RlimitResource::NOFILE
            | litebox_common_linux::RlimitResource::STACK => {
                self.process.limits.get_rlimit(resource)
            }
            _ => unimplemented!("Unsupported resource for get_rlimit: {:?}", resource),
        };
        if let Some(new_limit) = new_limit {
            if new_limit.rlim_cur > new_limit.rlim_max {
                return Err(Errno::EINVAL);
            }
            if let litebox_common_linux::RlimitResource::NOFILE = resource
                && new_limit.rlim_max > RLIMIT_NOFILE_MAX
            {
                return Err(Errno::EPERM);
            }
            // Note process with `CAP_SYS_RESOURCE` can increase the hard limit, but we don't
            // support capabilities in LiteBox, so we don't check for that here.
            if new_limit.rlim_max > old_rlimit.rlim_max {
                return Err(Errno::EPERM);
            }
            match resource {
                litebox_common_linux::RlimitResource::NOFILE => {
                    self.process.limits.set_rlimit(resource, new_limit);
                }
                _ => unimplemented!("Unsupported resource for set_rlimit: {:?}", resource),
            }
        }
        Ok(old_rlimit)
    }

    /// Handle syscall `prlimit64`.
    ///
    /// Note for now setting new limits is not supported yet, and thus returning constant values
    /// for the requested resource. Getting resources for a specific PID is also not supported yet.
    pub(crate) fn sys_prlimit(
        &self,
        pid: Option<i32>,
        resource: litebox_common_linux::RlimitResource,
        new_rlim: Option<crate::ConstPtr<litebox_common_linux::Rlimit64>>,
        old_rlim: Option<crate::MutPtr<litebox_common_linux::Rlimit64>>,
    ) -> Result<(), Errno> {
        if pid.is_some() {
            unimplemented!("prlimit for a specific PID is not supported yet");
        }
        let new_limit = match new_rlim {
            Some(rlim) => {
                let rlim = unsafe { rlim.read_at_offset(0) }
                    .ok_or(Errno::EINVAL)?
                    .into_owned();
                Some(litebox_common_linux::rlimit64_to_rlimit(rlim))
            }
            None => None,
        };
        let old_limit =
            litebox_common_linux::rlimit_to_rlimit64(self.do_prlimit(resource, new_limit)?);
        if let Some(old_rlim) = old_rlim {
            unsafe { old_rlim.write_at_offset(0, old_limit) }.ok_or(Errno::EINVAL)?;
        }
        Ok(())
    }

    /// Handle syscall `setrlimit`.
    pub(crate) fn sys_getrlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        rlim: crate::MutPtr<litebox_common_linux::Rlimit>,
    ) -> Result<(), Errno> {
        let old_limit = self.do_prlimit(resource, None)?;
        unsafe { rlim.write_at_offset(0, old_limit) }.ok_or(Errno::EINVAL)
    }

    /// Handle syscall `setrlimit`.
    pub(crate) fn sys_setrlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        rlim: crate::ConstPtr<litebox_common_linux::Rlimit>,
    ) -> Result<(), Errno> {
        let new_limit = unsafe { rlim.read_at_offset(0) }
            .ok_or(Errno::EFAULT)?
            .into_owned();
        let _ = self.do_prlimit(resource, Some(new_limit))?;
        Ok(())
    }

    /// Handle syscall `set_robust_list`.
    pub(crate) fn sys_set_robust_list(&self, head: usize) {
        let head = crate::ConstPtr::from_usize(head);
        self.robust_list.set(Some(head));
    }

    /// Handle syscall `get_robust_list`.
    pub(crate) fn sys_get_robust_list(
        &self,
        pid: Option<i32>,
        head_ptr: crate::MutPtr<usize>,
    ) -> Result<(), Errno> {
        if pid.is_some() {
            unimplemented!("Getting robust list for a specific PID is not supported yet");
        }
        let head = self.robust_list.get().map_or(0, |ptr| ptr.as_usize());
        unsafe { head_ptr.write_at_offset(0, head) }.ok_or(Errno::EFAULT)
    }

    fn real_time_as_duration_since_epoch(&self) -> core::time::Duration {
        let now = litebox_platform_multiplex::platform().current_time();
        let unix_epoch =
            <litebox_platform_multiplex::Platform as TimeProvider>::SystemTime::UNIX_EPOCH;
        now.duration_since(&unix_epoch)
            .expect("must be after unix epoch")
    }

    /// Handle syscall `clock_gettime`.
    pub(crate) fn sys_clock_gettime(
        &self,
        clockid: litebox_common_linux::ClockId,
    ) -> Result<litebox_common_linux::Timespec, Errno> {
        let duration = self.gettime_as_duration(litebox_platform_multiplex::platform(), clockid)?;
        litebox_common_linux::Timespec::try_from(duration).or(Err(Errno::EOVERFLOW))
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "will fail for unknown clock IDs in the future"
    )]
    fn gettime_as_duration(
        &self,
        platform: &litebox_platform_multiplex::Platform,
        clockid: litebox_common_linux::ClockId,
    ) -> Result<core::time::Duration, Errno> {
        let duration = match clockid {
            litebox_common_linux::ClockId::RealTime => {
                // CLOCK_REALTIME
                self.real_time_as_duration_since_epoch()
            }
            litebox_common_linux::ClockId::Monotonic => {
                // CLOCK_MONOTONIC
                platform.now().duration_since(crate::boot_time())
            }
            litebox_common_linux::ClockId::MonotonicCoarse => {
                // CLOCK_MONOTONIC_COARSE - provides faster but less precise monotonic time
                // For simplicity, we can reuse the same monotonic time as CLOCK_MONOTONIC
                // In a real implementation, this would typically have lower resolution
                platform.now().duration_since(crate::boot_time())
            }
            _ => unimplemented!(),
        };
        Ok(duration)
    }

    /// Handle syscall `clock_getres`.
    pub(crate) fn sys_clock_getres(
        &self,
        clockid: litebox_common_linux::ClockId,
        res: crate::MutPtr<litebox_common_linux::Timespec>,
    ) {
        // Return the resolution of the clock
        let resolution = match clockid {
            litebox_common_linux::ClockId::MonotonicCoarse => {
                // Coarse clocks typically have lower resolution (e.g., 4 millisecond)
                litebox_common_linux::Timespec {
                    tv_sec: 0,
                    tv_nsec: 4_000_000, // 4 millisecond resolution
                }
            }
            litebox_common_linux::ClockId::RealTime | litebox_common_linux::ClockId::Monotonic => {
                // For most modern systems, the resolution is typically 1 nanosecond
                // This is a reasonable default for high-resolution timers
                litebox_common_linux::Timespec {
                    tv_sec: 0,
                    tv_nsec: 1, // 1 nanosecond resolution
                }
            }
            _ => unimplemented!(),
        };

        unsafe {
            res.write_at_offset(0, resolution);
        }
    }

    /// Handle syscall `clock_nanosleep`.
    pub(crate) fn sys_clock_nanosleep(
        &self,
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
            let now = self.gettime_as_duration(platform, clockid)?;
            if request <= now {
                return Ok(());
            }
            request.checked_sub(now).unwrap()
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
        &self,
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
        let timeval =
            litebox_common_linux::Timespec::try_from(self.real_time_as_duration_since_epoch())
                .or(Err(Errno::EOVERFLOW))?
                .into();
        unsafe { tv.write_at_offset(0, timeval) }.ok_or(Errno::EFAULT)
    }

    /// Handle syscall `time`.
    pub(crate) fn sys_time(
        &self,
        tloc: crate::MutPtr<litebox_common_linux::time_t>,
    ) -> Result<litebox_common_linux::time_t, Errno> {
        let time = self.real_time_as_duration_since_epoch();
        let seconds: u64 = time.as_secs();
        let seconds: litebox_common_linux::time_t = seconds.try_into().or(Err(Errno::EOVERFLOW))?;
        if tloc.as_usize() != 0 {
            unsafe { tloc.write_at_offset(0, seconds) }.ok_or(Errno::EFAULT)?;
        }
        Ok(seconds)
    }

    /// Handle syscall `getpid`.
    pub(crate) fn sys_getpid(&self) -> i32 {
        self.pid
    }

    pub(crate) fn sys_getppid(&self) -> i32 {
        self.ppid
    }

    /// Handle syscall `getuid`.
    pub(crate) fn sys_getuid(&self) -> u32 {
        self.credentials.uid
    }

    /// Handle syscall `geteuid`.
    pub(crate) fn sys_geteuid(&self) -> u32 {
        self.credentials.euid
    }

    /// Handle syscall `getgid`.
    pub(crate) fn sys_getgid(&self) -> u32 {
        self.credentials.gid
    }

    /// Handle syscall `getegid`.
    pub(crate) fn sys_getegid(&self) -> u32 {
        self.credentials.egid
    }
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

impl Task {
    /// Handle syscall `sched_getaffinity`.
    ///
    /// Note this is a dummy implementation that always returns the same CPU set
    pub(crate) fn sys_sched_getaffinity(&self, _pid: Option<i32>) -> CpuSet {
        let mut cpuset = bitvec::bitvec![u8, bitvec::order::Lsb0; 0; NR_CPUS];
        cpuset.iter_mut().for_each(|mut b| *b = true);
        CpuSet { bits: cpuset }
    }
}

// TODO: move elsewhere?
pub(crate) fn get_timeout(
    timeout: crate::ConstPtr<litebox_common_linux::Timespec>,
) -> Result<litebox_common_linux::Timespec, Errno> {
    let timeout = unsafe { timeout.read_at_offset(0) }.ok_or(Errno::EFAULT)?;
    if timeout.tv_sec < 0 || timeout.tv_nsec >= 1_000_000_000 {
        return Err(Errno::EINVAL);
    }
    Ok(timeout.into_owned())
}

impl Task {
    /// Handle syscall `futex`
    pub(crate) fn sys_futex(
        &self,
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
                    let now = self
                        .sys_clock_gettime(
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
}

const MAX_VEC: usize = 4096; // limit count
const MAX_TOTAL_BYTES: usize = 256 * 1024; // size cap

impl Task {
    /// Handle syscall `execve`.
    pub(crate) fn sys_execve(
        &self,
        pathname: crate::ConstPtr<i8>,
        argv: crate::ConstPtr<crate::ConstPtr<i8>>,
        envp: crate::ConstPtr<crate::ConstPtr<i8>>,
        ctx: &mut litebox_common_linux::PtRegs,
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
        let mut envp_vec = if envp.as_usize() == 0 {
            alloc::vec::Vec::new()
        } else {
            copy_vector(envp, "envp")?
        };

        // Close CLOEXEC descriptors
        crate::file_descriptors().write().close_on_exec(self);

        // unmmap all memory mappings and reset brk
        if let Some(robust_list) = self.robust_list.take() {
            let _ = wake_robust_list(robust_list);
        }

        // Check if we are the only thread in the process
        if self
            .process
            .nr_threads
            .load(core::sync::atomic::Ordering::Relaxed)
            != 1
        {
            unimplemented!("execve when multiple threads exist is not supported yet");
        }
        // Don't release reserved mappings.
        let release = |r: Range<usize>, vm: VmFlags| !vm.is_empty();
        let page_manager = crate::litebox_page_manager();
        unsafe { page_manager.release_memory(release) }.expect("failed to release memory mappings");

        litebox_platform_multiplex::Platform::clear_guest_thread_local_storage(
            #[cfg(target_arch = "x86")]
            ctx.xgs.truncate(),
        );

        // TODO: split this operation into pre-unmap and post-unmap parts, and handle failure properly for both cases.
        *ctx = self.load_program(path, argv_vec, envp_vec).unwrap();

        Ok(())
    }

    /// Handle syscall `alarm`.
    pub(crate) fn sys_alarm(&self, seconds: u32) -> Result<usize, Errno> {
        let token = litebox_platform_multiplex::platform()
            .get_punchthrough_token_for(litebox_common_linux::PunchthroughSyscall::Alarm {
                seconds,
            })
            .expect("Failed to get punchthrough token for SET_ALARM");
        token.execute().map_err(|e| match e {
            litebox::platform::PunchthroughError::Failure(errno) => errno,
            _ => unimplemented!("Unsupported punchthrough error {:?}", e),
        })
    }

    /// Handle syscall `tgkill`.
    pub(crate) fn sys_tgkill(
        &self,
        thread_group_id: i32,
        thread_id: i32,
        sig: litebox_common_linux::Signal,
    ) -> Result<(), Errno> {
        if thread_id <= 0 || thread_group_id <= 0 {
            return Err(Errno::EINVAL);
        }
        if thread_group_id != self.sys_getpid() {
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

    /// Handle syscall `setitimer`
    pub(crate) fn sys_setitimer(
        &self,
        which: litebox_common_linux::IntervalTimer,
        new_value: crate::ConstPtr<litebox_common_linux::ItimerVal>,
        old_value: Option<crate::MutPtr<litebox_common_linux::ItimerVal>>,
    ) -> Result<(), Errno> {
        let punchthrough = litebox_common_linux::PunchthroughSyscall::SetITimer {
            which,
            new_value,
            old_value,
        };
        let token = litebox_platform_multiplex::platform()
            .get_punchthrough_token_for(punchthrough)
            .expect("Failed to get punchthrough token for SETITIMER");
        token.execute().map(|_| ()).map_err(|e| match e {
            litebox::platform::PunchthroughError::Failure(errno) => errno,
            _ => unimplemented!("Unsupported punchthrough error {:?}", e),
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_arch_prctl() {
        use crate::{MutPtr, syscalls::tests::init_platform};
        use core::mem::MaybeUninit;
        use litebox::platform::RawConstPointer;
        use litebox_common_linux::ArchPrctlArg;

        let task = init_platform(None);

        // Save old FS base
        let mut old_fs_base = MaybeUninit::<usize>::uninit();
        let ptr = MutPtr {
            inner: old_fs_base.as_mut_ptr(),
        };
        task.sys_arch_prctl(ArchPrctlArg::GetFs(ptr))
            .expect("Failed to get FS base");
        let old_fs_base = unsafe { old_fs_base.assume_init() };

        // Set new FS base
        let mut new_fs_base: [u8; 16] = [0; 16];
        let ptr = crate::MutPtr {
            inner: new_fs_base.as_mut_ptr(),
        };
        task.sys_arch_prctl(ArchPrctlArg::SetFs(ptr.as_usize()))
            .expect("Failed to set FS base");

        // Verify new FS base
        let mut current_fs_base = MaybeUninit::<usize>::uninit();
        let ptr = MutPtr {
            inner: current_fs_base.as_mut_ptr(),
        };
        task.sys_arch_prctl(ArchPrctlArg::GetFs(ptr))
            .expect("Failed to get FS base");
        let current_fs_base = unsafe { current_fs_base.assume_init() };
        assert_eq!(current_fs_base, new_fs_base.as_ptr() as usize);

        // Restore old FS base
        let ptr: crate::MutPtr<u8> = crate::MutPtr::from_usize(old_fs_base);
        task.sys_arch_prctl(ArchPrctlArg::SetFs(ptr.as_usize()))
            .expect("Failed to restore FS base");
    }

    #[test]
    fn test_sched_getaffinity() {
        let task = crate::syscalls::tests::init_platform(None);

        let cpuset = task.sys_sched_getaffinity(None);
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
        let task = crate::syscalls::tests::init_platform(None);

        // Prepare a null-terminated name to set
        let name: &[u8] = b"litebox-test\0";

        // Call prctl(PR_SET_NAME, set_buf)
        let set_ptr = crate::ConstPtr {
            inner: name.as_ptr(),
        };
        task.sys_prctl(litebox_common_linux::PrctlArg::SetName(set_ptr))
            .expect("sys_prctl SetName failed");

        // Prepare buffer for prctl(PR_GET_NAME, get_buf)
        let mut get_buf = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let get_ptr = crate::MutPtr {
            inner: get_buf.as_mut_ptr(),
        };

        task.sys_prctl(litebox_common_linux::PrctlArg::GetName(get_ptr))
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
        task.sys_prctl(litebox_common_linux::PrctlArg::SetName(long_name_ptr))
            .expect("sys_prctl SetName failed");

        // Get the name again
        let mut get_buf = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let get_ptr = crate::MutPtr {
            inner: get_buf.as_mut_ptr(),
        };
        task.sys_prctl(litebox_common_linux::PrctlArg::GetName(get_ptr))
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
