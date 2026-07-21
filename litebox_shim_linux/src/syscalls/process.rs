// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process/thread related syscalls.

use crate::{ShimFS, Task, UserPtr, UserPtrMut};
use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::mem::offset_of;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use litebox::event::wait::WaitError;
use litebox::mm::linux::VmFlags;
use litebox::platform::ThreadProvider;
use litebox::platform::{ArchSpecificProvider as _, ArchSpecificRegister, RawMutex as _};
use litebox::platform::{Instant as _, SystemTime as _, TimeProvider};
use litebox::platform::{TimerHandle, TimerProvider};
use litebox::sync::Mutex;
use litebox::utils::TruncateExt as _;
use litebox_common_linux::{
    ArchPrctlArg, CloneFlags, FutexArgs, IntervalTimer, ItimerVal, PrctlArg, TimeParam,
    errno::Errno,
};
use litebox_platform_multiplex::Platform;

/// Process-management-related state on [`Task`].
pub(crate) struct ThreadState {
    init_state: Cell<ThreadInitState>,
    process: Arc<Process>,
    /// Thread state that can be accessed from a remote thread.
    remote: Arc<ThreadRemote>,
    attached_tid: Cell<Option<i32>>,
    /// When a thread whose `clear_child_tid` is not `None` terminates, and it shares memory with other threads,
    /// the kernel writes 0 to the address specified by `clear_child_tid` and then executes:
    ///
    /// futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
    ///
    /// This operation wakes a single thread waiting on the specified memory location via futex.
    /// Any errors from the futex wake operation are ignored.
    clear_child_tid: Cell<Option<UserPtrMut<i32>>>,
    /// The purpose of the robust futex list is to ensure that if a thread accidentally fails to unlock a futex before
    /// terminating or calling execve(2), another thread that is waiting on that futex is notified that the former owner
    /// of the futex has died. This notification consists of two pieces: the FUTEX_OWNER_DIED bit is set in the futex word,
    /// and the kernel performs a futex(2) FUTEX_WAKE operation on one of the threads waiting on the futex.
    robust_list: Cell<Option<UserPtr<litebox_common_linux::RobustListHead>>>,
}

// TODO: remove once we figure out how to handle Send/Sync for raw pointers.
unsafe impl Send for ThreadState {}

impl ThreadState {
    pub fn new_process(pid: i32) -> Self {
        let remote = Arc::new(ThreadRemote::new());
        Self {
            init_state: Cell::new(ThreadInitState::None),
            process: Arc::new(Process::new(pid, remote.clone())),
            remote,
            attached_tid: Cell::new(Some(pid)),
            clear_child_tid: Cell::new(None),
            robust_list: Cell::new(None),
        }
    }

    pub(crate) fn new_thread(&self, tid: i32) -> Option<Self> {
        let remote = self.process.attach_thread(tid)?;
        Some(Self {
            init_state: Cell::new(ThreadInitState::None),
            process: self.process.clone(),
            remote,
            attached_tid: Cell::new(Some(tid)),
            clear_child_tid: Cell::new(None),
            robust_list: Cell::new(None),
        })
    }

    fn detach_from_process(&self) {
        if let Some(tid) = self.attached_tid.take() {
            self.process.detach_thread(tid);
        }
    }
}

impl Drop for ThreadState {
    fn drop(&mut self) {
        self.detach_from_process();
    }
}

/// Thread state that can be accessed from a remote thread.
struct ThreadRemote {
    /// Always set under the process `inner` lock, but can be read without
    /// locking.
    is_exiting: AtomicBool,
    /// Handle to interrupt waits on this thread.
    handle: once_cell::race::OnceBox<litebox::event::wait::ThreadHandle<Platform>>,
}

impl ThreadRemote {
    fn new() -> Self {
        Self {
            is_exiting: AtomicBool::new(false),
            handle: once_cell::race::OnceBox::new(),
        }
    }

    fn interrupt(&self) {
        if let Some(handle) = self.handle.get() {
            handle.interrupt();
        }
    }
}

/// A Linux process, which may have multiple threads.
pub(crate) struct Process {
    /// Number of threads in this process. Always updated under the `inner`
    /// mutex lock.
    nr_threads:
        <litebox_platform_multiplex::Platform as litebox::platform::RawMutexProvider>::RawMutex,
    inner: Mutex<Platform, ProcessInner>,
    /// Resource limits for this process.
    pub(crate) limits: ResourceLimits,
    /// Process-wide alarm timer.
    pub(crate) alarm_timer: Mutex<Platform, Alarm>,
}

pub(crate) struct Alarm {
    /// Handle for the alarm timer.
    pub(crate) handle: Option<<Platform as litebox::platform::TimerProvider>::TimerHandle>,
    /// The deadline for the alarm.
    pub(crate) deadline: Option<<Platform as litebox::platform::TimeProvider>::Instant>,
}

impl Alarm {
    /// Returns the time remaining until [`Self::deadline`], or zero if the
    /// alarm is not armed or its deadline has already passed.
    pub(crate) fn remaining(
        &self,
        now: <Platform as litebox::platform::TimeProvider>::Instant,
    ) -> Duration {
        self.deadline
            .as_ref()
            .and_then(|d| d.checked_duration_since(&now))
            .unwrap_or(Duration::ZERO)
    }
}

/// The locked portion of the process state.
struct ProcessInner {
    /// If true, the whole process is exiting.
    group_exit: bool,
    /// If true, one thread is waiting for other threads to exit.
    is_killing_other_threads: bool,
    /// The exit code of the last exited thread in the process. Not updated once
    /// `group_exit` is set.
    exit_status: ExitStatus,
    /// The thread list for the process, mapped by thread ID.
    threads: BTreeMap<i32, Arc<ThreadRemote>>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ExitStatus {
    Exit(i8),
    Signal(litebox_common_linux::signal::Signal),
}

impl Process {
    /// Creates a new process with the given initial thread.
    fn new(pid: i32, remote: Arc<ThreadRemote>) -> Self {
        let nr_threads = <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT;
        nr_threads.underlying_atomic().store(1, Ordering::Relaxed);
        Self {
            nr_threads,
            inner: Mutex::new(ProcessInner {
                exit_status: ExitStatus::Exit(0),
                group_exit: false,
                is_killing_other_threads: false,
                threads: BTreeMap::from_iter([(pid, remote)]),
            }),
            limits: ResourceLimits::default(),
            alarm_timer: Mutex::new(Alarm {
                handle: None,
                deadline: None,
            }),
        }
    }

    /// Returns the current number of threads in this process.
    pub fn nr_threads(&self) -> u32 {
        self.nr_threads.underlying_atomic().load(Ordering::Relaxed)
    }

    /// Waits for all threads in this process to exit, returning the exit code.
    pub fn wait_for_exit(&self) -> ExitStatus {
        loop {
            let n = self.nr_threads.underlying_atomic().load(Ordering::Acquire);
            if n == 0 {
                break;
            }
            let _ = self.nr_threads.block(n);
        }
        self.inner.lock().exit_status
    }

    /// Attaches a new thread to this process, returning a new remote state for
    /// the thread.
    fn attach_thread(&self, tid: i32) -> Option<Arc<ThreadRemote>> {
        // Allocate outside the lock.
        let remote = Arc::new(ThreadRemote::new());
        let mut inner = self.inner.lock();
        if inner.group_exit || inner.is_killing_other_threads {
            return None;
        }
        let old_thread = inner.threads.insert(tid, remote.clone());
        assert!(old_thread.is_none(), "thread ID {tid} already exists");
        let nr_threads = self.nr_threads.underlying_atomic();
        nr_threads.store(nr_threads.load(Ordering::Relaxed) + 1, Ordering::Release);
        Some(remote)
    }

    /// Detaches a thread from this process.
    ///
    /// # Panics
    /// Panics if the thread ID does not exist in this process.
    fn detach_thread(&self, tid: i32) {
        let data;
        let notify = {
            let mut inner = self.inner.lock();
            data = inner.threads.remove(&tid);
            assert!(data.is_some());

            let nr_threads = self.nr_threads.underlying_atomic();
            let n = nr_threads.load(Ordering::Relaxed);
            let new_count = n.checked_sub(1).expect("decrementing from zero threads");
            nr_threads.store(new_count, Ordering::Release);
            if new_count == 0 {
                assert!(inner.threads.is_empty());
                // The last thread exited. Prevent new threads.
                inner.group_exit = true;
            }

            // Notify waiters if this is the last thread of the process
            // (`wait_for_exit`) or if this is the last thread being killed
            // during an exec (`kill_other_threads`).
            new_count == 0 || (new_count == 1 && inner.is_killing_other_threads)
        };
        if notify {
            self.nr_threads.wake_all();
        }
    }
}

impl<FS: ShimFS> Task<FS> {
    /// Updates the process exit status for a thread exit.
    fn exit_thread(&self, code: i8) {
        let mut inner = self.thread.process.inner.lock();
        if self.is_exiting() {
            return;
        }
        inner.exit_status = ExitStatus::Exit(code);
        self.thread.remote.is_exiting.store(true, Ordering::Relaxed);
    }

    /// Updates the process exit status for a group exit and signals all threads
    /// to exit.
    pub(crate) fn exit_group(&self, status: ExitStatus) {
        let mut inner = self.thread.process.inner.lock();
        if self.is_exiting() {
            return;
        }
        assert!(!inner.group_exit);
        inner.exit_status = status;
        inner.group_exit = true;
        for thread in inner.threads.values() {
            thread.is_exiting.store(true, Ordering::Relaxed);
            thread.interrupt();
        }
    }

    /// Kills all other threads in the process, waiting for them to exit.
    ///
    /// Returns false if this thread is already exiting.
    #[must_use]
    fn kill_other_threads(&self) -> bool {
        {
            let mut inner = self.thread.process.inner.lock();
            if self.is_exiting() {
                return false;
            }
            for (&tid, thread) in &inner.threads {
                if tid == self.tid {
                    continue;
                }
                thread.is_exiting.store(true, Ordering::Relaxed);
                thread.interrupt();
            }
            assert!(!inner.is_killing_other_threads);
            inner.is_killing_other_threads = true;
        }
        // Wait for other threads to exit.
        loop {
            let n = self
                .thread
                .process
                .nr_threads
                .underlying_atomic()
                .load(Ordering::Acquire);
            if n == 1 {
                break;
            }
            let _ = self.thread.process.nr_threads.block(n);
        }
        self.thread.process.inner.lock().is_killing_other_threads = false;
        true
    }

    /// Returns true if the task is exiting and should not continue running
    /// guest code.
    pub fn is_exiting(&self) -> bool {
        self.thread.remote.is_exiting.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
enum ThreadInitState {
    #[default]
    None,
    NewProcess(crate::loader::elf::ElfLoadInfo),
    NewThread {
        stack: Option<usize>,
        tls: Option<ThreadLocalDescriptor>,
        set_child_tid: Option<UserPtrMut<i32>>,
    },
}

/// Credentials of a process
#[derive(Clone)]
pub(crate) struct Credentials {
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
}

impl<FS: ShimFS> Task<FS> {
    pub(crate) fn process(&self) -> &Arc<Process> {
        &self.thread.process
    }

    /// Set the current task's command name.
    pub(crate) fn set_task_comm(&self, comm: &[u8]) {
        let mut new_comm = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let comm = &comm[..comm.len().min(litebox_common_linux::TASK_COMM_LEN - 1)];
        new_comm[..comm.len()].copy_from_slice(comm);
        self.comm.set(new_comm);
    }

    /// Handle syscall `prctl`.
    pub(crate) fn sys_prctl(&self, arg: PrctlArg) -> Result<usize, Errno> {
        match arg {
            PrctlArg::GetName(name) => name
                .write_slice_at_offset::<Platform>(0, &self.comm.get())
                .ok_or(Errno::EFAULT)
                .map(|()| 0),
            PrctlArg::SetName(name) => {
                let mut name_buf = [0u8; litebox_common_linux::TASK_COMM_LEN - 1];
                // strncpy
                for (i, byte) in name_buf.iter_mut().enumerate() {
                    let b = name
                        .read_at_offset::<Platform>(isize::try_from(i).unwrap())
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
    pub(crate) fn sys_arch_prctl(&self, arg: ArchPrctlArg) -> Result<(), Errno> {
        match arg {
            #[cfg(target_arch = "x86_64")]
            ArchPrctlArg::SetFs(addr) => self
                .global
                .platform
                .set_arch_specific_register(&ArchSpecificRegister::FsBase, addr)
                .map_err(Errno::from),
            #[cfg(target_arch = "x86_64")]
            ArchPrctlArg::GetFs(addr) => {
                let fsbase = self
                    .global
                    .platform
                    .get_arch_specific_register(&ArchSpecificRegister::FsBase)?;
                addr.write_at_offset::<Platform>(0, fsbase)
                    .ok_or(Errno::EFAULT)?;
                Ok(())
            }
            ArchPrctlArg::CETStatus | ArchPrctlArg::CETDisable | ArchPrctlArg::CETLock => {
                Err(Errno::EINVAL)
            }
            _ => unimplemented!(),
        }
    }
}

const ROBUST_LIST_LIMIT: isize = 2048;

/*
 * Process a futex-list entry, check whether it's owned by the
 * dying task, and do notification if so:
 */
fn handle_futex_death(futex_addr: UserPtr<u32>, _pi: bool, _pending_op: bool) -> Result<(), Errno> {
    if !futex_addr.as_usize().is_multiple_of(4) {
        return Err(Errno::EINVAL);
    }

    todo!("handle_futex_death is not implemented yet");
}

fn fetch_robust_entry(
    head: UserPtr<litebox_common_linux::RobustList>,
) -> (UserPtr<litebox_common_linux::RobustList>, bool) {
    let next = head.as_usize();
    (UserPtr::from_usize(next & !1), next & 1 != 0)
}

fn wake_robust_list(head: UserPtr<litebox_common_linux::RobustListHead>) -> Result<(), Errno> {
    let mut limit = ROBUST_LIST_LIMIT;
    let head_ptr = head.as_usize();
    let head = head.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
    let (mut entry, mut pi) = fetch_robust_entry(UserPtr::from_usize(head.list.next));
    let (pending, ppi) = fetch_robust_entry(UserPtr::from_usize(head.list_op_pending));
    let futex_offset = head.futex_offset;
    let entry_head = head_ptr + offset_of!(litebox_common_linux::RobustListHead, list);
    while entry.as_usize() != entry_head && limit > 0 {
        let nxt = entry
            .read_at_offset::<Platform>(0)
            .map(|e| fetch_robust_entry(UserPtr::from_usize(e.next)));
        if entry.as_usize() != pending.as_usize() {
            handle_futex_death(
                UserPtr::from_usize(entry.as_usize() + futex_offset),
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
            UserPtr::from_usize(pending.as_usize() + futex_offset),
            ppi,
            true,
        );
    }
    Ok(())
}

impl<FS: ShimFS> Task<FS> {
    /// Called when the task is exiting.
    pub(crate) fn prepare_for_exit(&mut self) {
        self.thread.detach_from_process();

        if let Some(clear_child_tid) = self.thread.clear_child_tid.take() {
            // Clear the child TID if requested
            // TODO: if we are the last thread, we don't need to clear it
            let _ = clear_child_tid.write_at_offset::<Platform>(0, 0);
            // Cast from *i32 to *u32
            let clear_child_tid = UserPtrMut::from_usize(clear_child_tid.as_usize());
            let _ = self.sys_futex(litebox_common_linux::FutexArgs::Wake {
                addr: clear_child_tid,
                flags: litebox_common_linux::FutexFlags::PRIVATE,
                count: 1,
            });
        }
        if let Some(robust_list) = self.thread.robust_list.take() {
            let _ = wake_robust_list(robust_list);
        }
    }

    pub(crate) fn sys_exit(&self, status: i32) {
        // The `Task` will be dropped on the way out of the shim, which will
        // call `self.prepare_for_exit()`.
        self.exit_thread(status.trunc());
    }

    pub(crate) fn sys_exit_group(&self, status: i32) {
        // Tear down occurs similarly to `sys_exit`.
        self.exit_group(ExitStatus::Exit(status.trunc()));
    }
}

/// A descriptor for thread-local storage (TLS).
///
/// On `x86_64`, this is represented as a `*mut u8`. The TLS pointer can point to
/// an arbitrary-sized memory region.
#[cfg(target_arch = "x86_64")]
type ThreadLocalDescriptor = UserPtrMut<u8>;

struct NewThreadArgs<FS: ShimFS> {
    /// Task struct that maintains all per-thread data
    task: Task<FS>,
}

impl<FS: ShimFS> litebox::shim::InitThread for NewThreadArgs<FS> {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(
        self: alloc::boxed::Box<Self>,
    ) -> alloc::boxed::Box<dyn litebox::shim::EnterShim<ExecutionContext = Self::ExecutionContext>>
    {
        let Self { task } = *self;

        Box::new(crate::LinuxShimEntrypoints {
            task,
            _not_send: core::marker::PhantomData,
        })
    }
}

impl<FS: ShimFS> Task<FS> {
    pub(crate) fn sys_clone(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        args: &litebox_common_linux::CloneArgs,
    ) -> Result<usize, Errno> {
        self.do_clone(ctx, args, false)
    }

    pub(crate) fn sys_clone3(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        args: UserPtr<litebox_common_linux::CloneArgs>,
    ) -> Result<usize, Errno> {
        let args = args.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        self.do_clone(ctx, &args, true)
    }

    /// Creates a new thread or process.
    ///
    /// Note we currently only support creating threads with the VM, FS, and FILES flags set.
    fn do_clone(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        args: &litebox_common_linux::CloneArgs,
        clone3: bool,
    ) -> Result<usize, Errno> {
        const MAX_SIGNAL_NUMBER: u64 = 64;

        let litebox_common_linux::CloneArgs {
            mut flags,
            pidfd: _,
            child_tid,
            parent_tid,
            exit_signal,
            stack,
            stack_size,
            tls,
            set_tid,
            set_tid_size,
            cgroup,
        } = *args;

        // `CLONE_DETACHED` is ignored but has been reserved for reuse with
        // `clone3` or in combination with `CLONE_PIDFD`.
        if !clone3 && !flags.contains(CloneFlags::PIDFD) {
            flags.remove(CloneFlags::DETACHED);
        }

        let required_clone_flags =
            CloneFlags::VM | CloneFlags::THREAD | CloneFlags::SIGHAND | CloneFlags::FILES;

        let supported_clone_flags = CloneFlags::VM
            | CloneFlags::FS
            | CloneFlags::FILES
            | CloneFlags::SIGHAND
            | CloneFlags::PARENT
            | CloneFlags::THREAD
            | CloneFlags::SETTLS
            | CloneFlags::PARENT_SETTID
            | CloneFlags::CHILD_CLEARTID
            | CloneFlags::CHILD_SETTID
            // Ignored since we don't support sysv semaphores anyway.
            | CloneFlags::SYSVSEM;

        if flags.intersects(!supported_clone_flags) {
            log_unsupported!(
                "clone with unsupported flags: {:?}",
                flags & !supported_clone_flags
            );
            return Err(Errno::EINVAL);
        }
        if !flags.contains(required_clone_flags) {
            log_unsupported!(
                "clone with missing required flags: {:?}",
                required_clone_flags & !flags
            );
            return Err(Errno::EINVAL);
        }

        if cgroup != 0 {
            log_unsupported!("clone with cgroup");
            return Err(Errno::EINVAL);
        }

        if set_tid != 0 || set_tid_size != 0 {
            log_unsupported!("clone with set_tid");
            return Err(Errno::EINVAL);
        }

        // Note `exit_signal` is ignored because we don't support `fork` yet; we just validate it.
        if exit_signal > MAX_SIGNAL_NUMBER {
            return Err(Errno::EINVAL);
        }

        let tls = if flags.contains(CloneFlags::SETTLS) {
            let addr = tls.trunc();
            #[cfg(target_arch = "x86_64")]
            {
                // Validate the user-controlled TLS base before spawning the thread.
                if !litebox_common_linux::arch::is_valid_user_fs_base(addr) {
                    return Err(Errno::EPERM);
                }
            }
            #[cfg(target_arch = "x86_64")]
            let desc = UserPtrMut::from_usize(addr);
            Some(desc)
        } else {
            None
        };

        let child_tid = if child_tid == 0 {
            None
        } else {
            Some(UserPtrMut::from_usize(child_tid.trunc()))
        };
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
        let set_parent_tid = if flags.contains(CloneFlags::PARENT_SETTID) && parent_tid != 0 {
            Some(UserPtrMut::from_usize(parent_tid.trunc()))
        } else {
            None
        };

        let fs = if flags.contains(CloneFlags::FS) {
            self.fs.borrow().clone()
        } else {
            alloc::sync::Arc::new((**self.fs.borrow()).clone())
        };

        let child_tid = self.global.next_thread_id.fetch_add(1, Ordering::Relaxed);
        if let Some(parent_tid_ptr) = set_parent_tid {
            let _ = parent_tid_ptr.write_at_offset::<Platform>(0, child_tid);
        }

        if (stack == 0 && stack_size != 0) || (stack != 0 && clone3 && stack_size == 0) {
            return Err(Errno::EINVAL);
        }
        let sp = if stack != 0 {
            let stack: usize = stack.trunc();
            Some(stack.wrapping_add(stack_size.trunc()))
        } else {
            None
        };

        let thread = self.thread.new_thread(child_tid).ok_or(Errno::EBUSY)?;
        thread.init_state.set(ThreadInitState::NewThread {
            stack: sp,
            tls,
            set_child_tid,
        });
        thread.clear_child_tid.set(clear_child_tid);

        let r = unsafe {
            self.global.platform.spawn_thread(
                ctx,
                Box::new(NewThreadArgs {
                    task: Task {
                        global: self.global.clone(),
                        wait_state: crate::wait::WaitState::new(self.global.platform),
                        thread,
                        pid: self.pid,
                        tid: child_tid,
                        ppid: self.ppid,
                        credentials: self.credentials.clone(),
                        comm: self.comm.clone(),
                        fs: fs.into(),
                        files: self.files.clone(), // TODO: !CLONE_FILES support
                        signals: self.signals.clone_for_new_task(),
                    },
                }),
            )
        };
        if let Err(err) = r {
            litebox_util_log::error!(err:% = err; "failed to spawn thread");
            // Treat all spawn errors as `ENOMEM`. `EAGAIN` and other errors are
            // for conditions the user can control (such as "in-shim" rlimit
            // violations).
            return Err(Errno::ENOMEM);
        }

        Ok(usize::try_from(child_tid).unwrap())
    }

    /// Handle syscall `set_tid_address`.
    pub(crate) fn sys_set_tid_address(&self, tidptr: UserPtrMut<i32>) -> i32 {
        self.thread.clear_child_tid.set(Some(tidptr));
        self.tid
    }

    /// Handle syscall `gettid`.
    pub(crate) fn sys_gettid(&self) -> i32 {
        self.tid
    }
}

// TODO: enforce the following limits:
pub(crate) const RLIMIT_NOFILE_CUR: usize = 1024 * 1024;
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
            rlim_cur: r.cur.load(Ordering::Relaxed),
            rlim_max: r.max.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn get_rlimit_cur(&self, resource: litebox_common_linux::RlimitResource) -> usize {
        let r = &self.limits[resource as usize];
        r.cur.load(Ordering::Relaxed)
    }

    fn set_rlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        new_limit: litebox_common_linux::Rlimit,
    ) {
        let r = &self.limits[resource as usize];
        r.cur.store(new_limit.rlim_cur, Ordering::Relaxed);
        r.max.store(new_limit.rlim_max, Ordering::Relaxed);
    }
}

impl<FS: ShimFS> Task<FS> {
    /// Get resource limits, and optionally set new limits.
    pub(crate) fn do_prlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        new_limit: Option<litebox_common_linux::Rlimit>,
    ) -> Result<litebox_common_linux::Rlimit, Errno> {
        let old_rlimit = match resource {
            litebox_common_linux::RlimitResource::NOFILE
            | litebox_common_linux::RlimitResource::STACK => {
                self.thread.process.limits.get_rlimit(resource)
            }
            _ => {
                log_unsupported!("Unsupported resource for get_rlimit: {:?}", resource);
                return Err(Errno::EINVAL);
            }
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
                    let new_max_fd = new_limit.rlim_cur.saturating_sub(1);
                    self.thread.process.limits.set_rlimit(resource, new_limit);
                    self.files.borrow().set_max_fd(new_max_fd);
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
        pid: i32,
        resource: litebox_common_linux::RlimitResource,
        new_rlim: Option<UserPtr<litebox_common_linux::Rlimit64>>,
        old_rlim: Option<UserPtrMut<litebox_common_linux::Rlimit64>>,
    ) -> Result<(), Errno> {
        if pid != 0 {
            unimplemented!("prlimit for a specific PID is not supported yet");
        }
        let new_limit = match new_rlim {
            Some(rlim) => {
                let rlim = rlim.read_at_offset::<Platform>(0).ok_or(Errno::EINVAL)?;
                Some(litebox_common_linux::rlimit64_to_rlimit(rlim))
            }
            None => None,
        };
        let old_limit =
            litebox_common_linux::rlimit_to_rlimit64(self.do_prlimit(resource, new_limit)?);
        if let Some(old_rlim) = old_rlim {
            old_rlim
                .write_at_offset::<Platform>(0, old_limit)
                .ok_or(Errno::EINVAL)?;
        }
        Ok(())
    }

    /// Handle syscall `setrlimit`.
    pub(crate) fn sys_getrlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        rlim: UserPtrMut<litebox_common_linux::Rlimit>,
    ) -> Result<(), Errno> {
        let old_limit = self.do_prlimit(resource, None)?;
        rlim.write_at_offset::<Platform>(0, old_limit)
            .ok_or(Errno::EINVAL)
    }

    /// Handle syscall `setrlimit`.
    pub(crate) fn sys_setrlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        rlim: UserPtr<litebox_common_linux::Rlimit>,
    ) -> Result<(), Errno> {
        let new_limit = rlim.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        let _ = self.do_prlimit(resource, Some(new_limit))?;
        Ok(())
    }

    /// Handle syscall `set_robust_list`.
    pub(crate) fn sys_set_robust_list(&self, head: usize) {
        let head = UserPtr::from_usize(head);
        self.thread.robust_list.set(Some(head));
    }

    /// Handle syscall `get_robust_list`.
    pub(crate) fn sys_get_robust_list(
        &self,
        pid: Option<i32>,
        head_ptr: UserPtrMut<usize>,
    ) -> Result<(), Errno> {
        if pid.is_some() {
            unimplemented!("Getting robust list for a specific PID is not supported yet");
        }
        let head = self
            .thread
            .robust_list
            .get()
            .map_or(0, |ptr| ptr.as_usize());
        head_ptr
            .write_at_offset::<Platform>(0, head)
            .ok_or(Errno::EFAULT)
    }

    fn real_time_as_duration_since_epoch(&self) -> core::time::Duration {
        let now = self.global.platform.current_time();
        let unix_epoch =
            <litebox_platform_multiplex::Platform as TimeProvider>::SystemTime::UNIX_EPOCH;
        now.duration_since(&unix_epoch)
            .expect("must be after unix epoch")
    }

    /// Handle syscall `clock_gettime`.
    pub(crate) fn sys_clock_gettime(
        &self,
        clockid: litebox_common_linux::ClockId,
        tp: TimeParam,
    ) -> Result<(), Errno> {
        let duration = self.gettime_as_duration(clockid)?;
        tp.write::<Platform>(duration)
    }

    fn gettime_as_duration(
        &self,
        clockid: litebox_common_linux::ClockId,
    ) -> Result<core::time::Duration, Errno> {
        let duration = match clockid {
            litebox_common_linux::ClockId::RealTime => {
                // CLOCK_REALTIME
                self.real_time_as_duration_since_epoch()
            }
            litebox_common_linux::ClockId::Monotonic => {
                // CLOCK_MONOTONIC
                self.global
                    .platform
                    .now()
                    .duration_since(&self.global.boot_time)
            }
            litebox_common_linux::ClockId::MonotonicCoarse => {
                // CLOCK_MONOTONIC_COARSE - provides faster but less precise monotonic time
                // For simplicity, we can reuse the same monotonic time as CLOCK_MONOTONIC
                // In a real implementation, this would typically have lower resolution
                self.global
                    .platform
                    .now()
                    .duration_since(&self.global.boot_time)
            }
            _ => {
                log_unsupported!("gettime for {clockid:?}");
                return Err(Errno::EINVAL);
            }
        };
        Ok(duration)
    }

    /// Convert an absolute time, specified as a duration since the epoch of the
    /// given clock, to a `Platform::Instant` suitable for use as a deadline.
    ///
    /// If the time is so far in the future that it cannot be represented as an
    /// `Instant`, returns `Ok(None)`. If the time occurs in the past, returns
    /// the current time.
    fn duration_since_epoch_to_deadline(
        &self,
        clock_id: litebox_common_linux::ClockId,
        duration: Duration,
    ) -> Result<Option<<Platform as TimeProvider>::Instant>, Errno> {
        match clock_id {
            litebox_common_linux::ClockId::Monotonic
            | litebox_common_linux::ClockId::MonotonicCoarse => {
                // No need to compute the current time since the offset from the
                // request to `Instant` is known.
                Ok(self.global.boot_time.checked_add(duration))
            }
            _ => {
                // Convert between time domains. If the requested time is in the past,
                // return the current time.
                let current_time = self.gettime_as_duration(clock_id)?;
                Ok(self
                    .global
                    .platform
                    .now()
                    .checked_add(duration.checked_sub(current_time).unwrap_or(Duration::ZERO)))
            }
        }
    }

    /// Handle syscall `clock_getres`.
    pub(crate) fn sys_clock_getres(
        &self,
        clockid: litebox_common_linux::ClockId,
        res: TimeParam,
    ) -> Result<(), Errno> {
        // Return the resolution of the clock
        let resolution = match clockid {
            litebox_common_linux::ClockId::MonotonicCoarse => {
                // Coarse clocks typically have lower resolution (e.g., 4 millisecond)
                Duration::from_millis(4)
            }
            litebox_common_linux::ClockId::RealTime | litebox_common_linux::ClockId::Monotonic => {
                // For most modern systems, the resolution is typically 1 nanosecond
                // This is a reasonable default for high-resolution timers
                Duration::from_nanos(1)
            }
            _ => unimplemented!(),
        };

        res.write::<Platform>(resolution)
    }

    /// Handle syscall `clock_nanosleep`.
    pub(crate) fn sys_clock_nanosleep(
        &self,
        clockid: litebox_common_linux::ClockId,
        flags: litebox_common_linux::TimerFlags,
        request: TimeParam,
        remain: TimeParam,
    ) -> Result<(), Errno> {
        let request = request.read::<Platform>()?.ok_or(Errno::EFAULT)?;
        if flags.intersects(litebox_common_linux::TimerFlags::ABSTIME.complement()) {
            return Err(Errno::EINVAL);
        }
        let is_abs = flags.contains(litebox_common_linux::TimerFlags::ABSTIME);

        // Set up a wait context with the right deadline/timeout.
        let wait_cx = self.wait_cx();
        let wait_cx = if is_abs {
            wait_cx.with_deadline(self.duration_since_epoch_to_deadline(clockid, request)?)
        } else {
            // Relative. Treat all clocks the same. TODO: handle the different clocks differently.
            wait_cx.with_timeout(request)
        };

        match wait_cx.sleep() {
            WaitError::TimedOut => {}
            WaitError::Interrupted => {
                if is_abs {
                    return Err(Errno::EINTR);
                }
                if let Some(remaining_timeout) = wait_cx.remaining_timeout() {
                    remain.write::<Platform>(remaining_timeout)?;
                    return Err(Errno::EINTR);
                }
                // Whoops, time ran out after getting interrupted. Treat this as a timeout.
            }
        }

        Ok(())
    }

    /// Handle syscall `gettimeofday`.
    pub(crate) fn sys_gettimeofday(
        &self,
        tv: Option<UserPtrMut<litebox_common_linux::TimeVal>>,
        tz: Option<UserPtrMut<litebox_common_linux::TimeZone>>,
    ) -> Result<(), Errno> {
        if let Some(tz) = tz {
            // `man 2 gettimeofday`: The use of the timezone structure is obsolete; the tz argument
            // should normally be specified as NULL. Linux still accepts a non-NULL tz and fills it
            // in (typically with zeros for UTC systems) rather than returning an error.
            let utc_tz = litebox_common_linux::TimeZone::new(0, 0);
            tz.write_at_offset::<Platform>(0, utc_tz)
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(tv) = tv {
            tv.write_at_offset::<Platform>(0, self.real_time_as_duration_since_epoch().into())
                .ok_or(Errno::EFAULT)?;
        }
        Ok(())
    }

    /// Handle syscall `time`.
    pub(crate) fn sys_time(
        &self,
        tloc: Option<UserPtrMut<litebox_common_linux::time_t>>,
    ) -> Result<litebox_common_linux::time_t, Errno> {
        let time = self.real_time_as_duration_since_epoch();
        let seconds: u64 = time.as_secs();
        let seconds: litebox_common_linux::time_t = seconds.try_into().or(Err(Errno::EOVERFLOW))?;
        if let Some(tloc) = tloc {
            tloc.write_at_offset::<Platform>(0, seconds)
                .ok_or(Errno::EFAULT)?;
        }
        Ok(seconds)
    }

    /// Handle syscall `alarm`.
    ///
    /// Sets a process-wide timer to deliver SIGALRM after `seconds` seconds. If
    /// `seconds` is 0, any pending alarm is cancelled. Returns the number of
    /// seconds remaining on a previously set alarm (rounded up), or 0 if none
    /// was set.
    ///
    /// The alarm is per-process: all threads share the same alarm timer.
    pub(crate) fn sys_alarm(&self, seconds: u32) -> Result<u32, Errno> {
        let prev = self.arm_real_timer(Duration::from_secs(u64::from(seconds)))?;
        // Round remaining time up to whole seconds, saturating to u32::MAX.
        if prev.is_zero() {
            Ok(0)
        } else {
            let extra = u64::from(prev.subsec_nanos() > 0);
            Ok(u32::try_from(prev.as_secs() + extra).unwrap_or(u32::MAX))
        }
    }

    /// Arm or disarm the per-process `ITIMER_REAL` timer. Returns the raw
    /// `Duration` remaining on the previous arming; zero means "was not
    /// armed". `delay = 0` disarms.
    fn arm_real_timer(&self, delay: Duration) -> Result<Duration, Errno> {
        let mut alarm = self.process().alarm_timer.lock();
        let now = self.global.platform.now();
        let prev = alarm.remaining(now);
        let new_deadline = if delay.is_zero() {
            None
        } else {
            Some(now.checked_add(delay).ok_or(Errno::EINVAL)?)
        };
        if alarm.handle.is_none() {
            match self
                .global
                .platform
                .create_timer(litebox_common_linux::signal::Signal::SIGALRM)
            {
                Ok(handle) => alarm.handle = Some(handle),
                Err(litebox::platform::TimerCreationError::Unsupported) => {}
                Err(_) => unimplemented!(),
            }
        }
        if let Some(handle) = &alarm.handle {
            handle.set_timer(delay);
        }
        alarm.deadline = new_deadline;
        Ok(prev)
    }

    /// Handle syscall `setitimer`.
    pub(crate) fn sys_setitimer(
        &self,
        which: IntervalTimer,
        new_value: Option<UserPtr<ItimerVal>>,
        old_value: Option<UserPtrMut<ItimerVal>>,
    ) -> Result<(), Errno> {
        let new = match new_value {
            Some(ptr) => ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?,
            // Linux supports NULL `new_value` but says it would be removed in the future.
            None => ItimerVal::default(),
        };
        // tv_usec range check is performed by `Duration::try_from(TimeVal)`.
        let new_interval = Duration::try_from(new.it_interval())?;
        let new_remaining = Duration::try_from(new.it_value())?;

        let prev = match which {
            IntervalTimer::Real => {
                if new_remaining.is_zero() {
                    ItimerVal::single_shot(self.arm_real_timer(Duration::ZERO)?)
                } else if !new_interval.is_zero() {
                    // TODO: support periodic timers
                    log_unsupported!("setitimer: nonzero it_interval not supported");
                    return Err(Errno::ENOSYS);
                } else {
                    ItimerVal::single_shot(self.arm_real_timer(new_remaining)?)
                }
            }
            IntervalTimer::Virtual | IntervalTimer::Prof => {
                log_unsupported!("setitimer: ITIMER_VIRTUAL/PROF not supported");
                return Err(Errno::ENOSYS);
            }
        };

        if let Some(out) = old_value {
            out.write_at_offset::<Platform>(0, prev)
                .ok_or(Errno::EFAULT)?;
        }
        Ok(())
    }

    /// Handle syscall `getitimer`.
    pub(crate) fn sys_getitimer(
        &self,
        which: IntervalTimer,
        curr_value: UserPtrMut<ItimerVal>,
    ) -> Result<(), Errno> {
        let value = match which {
            IntervalTimer::Real => {
                let alarm = self.process().alarm_timer.lock();
                let now = self.global.platform.now();
                alarm.remaining(now)
            }
            IntervalTimer::Virtual | IntervalTimer::Prof => {
                log_unsupported!("getitimer: ITIMER_VIRTUAL/PROF not supported");
                Duration::ZERO
            }
        };
        curr_value
            .write_at_offset::<Platform>(0, ItimerVal::single_shot(value))
            .ok_or(Errno::EFAULT)
    }

    /// Handle syscall `pause`.
    pub(crate) fn sys_pause(&self) -> Result<(), Errno> {
        match self.wait_cx().sleep() {
            WaitError::Interrupted => Err(Errno::EINTR),
            WaitError::TimedOut => unreachable!("pause sleep has no deadline"),
        }
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

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `sched_getaffinity`.
    ///
    /// Note this is a dummy implementation that always returns the same CPU set
    pub(crate) fn sys_sched_getaffinity(&self, _pid: Option<i32>) -> CpuSet {
        let mut cpuset = bitvec::bitvec![u8, bitvec::order::Lsb0; 0; NR_CPUS];
        cpuset.iter_mut().for_each(|mut b| *b = true);
        CpuSet { bits: cpuset }
    }
}

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `futex`
    pub(crate) fn sys_futex(&self, arg: litebox_common_linux::FutexArgs) -> Result<usize, Errno> {
        /// Note our mutex implementation assumes futexes are private as we don't support shared memory yet.
        /// It should be fine to treat shared futexes as private for now.
        macro_rules! warn_shared_futex {
            ($flag:ident) => {
                if !$flag.contains(litebox_common_linux::FutexFlags::PRIVATE) {
                    log_unsupported!("shared futex");
                }
            };
        }

        let res = match arg {
            FutexArgs::Wake { addr, flags, count } => {
                warn_shared_futex!(flags);
                let Some(count) = core::num::NonZeroU32::new(count) else {
                    return Ok(0);
                };
                self.global
                    .futex_manager
                    .wake(addr.to_platform_ptr::<Platform>(), count, None)? as usize
            }
            FutexArgs::Wait {
                addr,
                flags,
                val,
                timeout,
            } => {
                warn_shared_futex!(flags);
                let timeout = timeout.read::<Platform>()?;
                self.global.futex_manager.wait(
                    &self.wait_cx().with_timeout(timeout),
                    addr.to_platform_ptr::<Platform>(),
                    val,
                    None,
                )?;
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
                let deadline = if let Some(timeout) = timeout.read::<Platform>()? {
                    let clock_id =
                        if flags.contains(litebox_common_linux::FutexFlags::CLOCK_REALTIME) {
                            litebox_common_linux::ClockId::RealTime
                        } else {
                            litebox_common_linux::ClockId::Monotonic
                        };
                    self.duration_since_epoch_to_deadline(clock_id, timeout)?
                } else {
                    None
                };
                self.global.futex_manager.wait(
                    &self.wait_cx().with_deadline(deadline),
                    addr.to_platform_ptr::<Platform>(),
                    val,
                    core::num::NonZeroU32::new(bitmask),
                )?;
                0
            }
            _ => unimplemented!("Unsupported futex operation"),
        };
        Ok(res)
    }
}

const MAX_VEC: usize = 4096; // limit count
const MAX_TOTAL_BYTES: usize = 256 * 1024; // size cap

/// Maximum shebang (#!) recursion depth (from Linux's `exec_binprm`)
const SHEBANG_MAX_RECURSION: u32 = 6;

/// Maximum length of a shebang line that we inspect. Matches Linux `BINPRM_BUF_SIZE`.
const SHEBANG_MAX_LINE: usize = 256;

/// Parse a `#!interpreter [optional-arg]` line from a file header buffer.
///
/// Returns `Some((interpreter, optional_arg))` when `buf` starts with `#!` and
/// contains a non-empty interpreter path. The optional argument, if present, is everything
/// between the first whitespace after the interpreter and the end of the line
/// (trimmed), treated as a single token — matching Linux kernel semantics.
fn parse_shebang(buf: &[u8]) -> Option<(&str, Option<&str>)> {
    if buf.len() < 2 || buf[0] != b'#' || buf[1] != b'!' {
        return None;
    }
    let line_end = buf[2..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(buf.len(), |p| p + 2);
    let line = core::str::from_utf8(&buf[2..line_end]).ok()?;
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    match line.find([' ', '\t']) {
        Some(i) => {
            let arg = line[i..].trim();
            Some((&line[..i], if arg.is_empty() { None } else { Some(arg) }))
        }
        None => Some((line, None)),
    }
}

impl<FS: ShimFS> Task<FS> {
    /// Resolve shebang (`#!`) chains for the given path and argv if the file starts with a shebang line.
    /// Otherwise, returns the original path and argv.
    pub(crate) fn resolve_shebang(
        &self,
        mut path: alloc::string::String,
        mut argv: alloc::vec::Vec<alloc::ffi::CString>,
    ) -> Result<(alloc::string::String, alloc::vec::Vec<alloc::ffi::CString>), Errno> {
        for _ in 0..SHEBANG_MAX_RECURSION {
            let full_path = self.resolve_path(&path)?;
            let file = self.do_open(
                full_path,
                litebox::fs::OFlags::RDONLY,
                litebox::fs::Mode::empty(),
            )?;
            let mut header = [0u8; SHEBANG_MAX_LINE];
            let files = self.files.borrow();
            let n = match files.fs.read(&file, &mut header, Some(0)) {
                Ok(n) => n,
                Err(e) => {
                    let _ = files.fs.close(&file);
                    return Err(Errno::from(e));
                }
            };
            let _ = files.fs.close(&file);

            match parse_shebang(&header[..n]) {
                Some((interp, opt_arg)) => {
                    let mut new_argv = alloc::vec::Vec::new();
                    new_argv.push(alloc::ffi::CString::new(interp).map_err(|_| Errno::EINVAL)?);
                    if let Some(arg) = opt_arg {
                        new_argv.push(alloc::ffi::CString::new(arg).map_err(|_| Errno::EINVAL)?);
                    }
                    new_argv
                        .push(alloc::ffi::CString::new(path.as_str()).map_err(|_| Errno::EINVAL)?);
                    if argv.len() > 1 {
                        new_argv.extend_from_slice(&argv[1..]);
                    }
                    path = alloc::string::String::from(interp);
                    argv = new_argv;
                }
                None => return Ok((path, argv)),
            }
        }
        Err(Errno::ELOOP)
    }

    /// Handle syscall `execve`.
    pub(crate) fn sys_execve(
        &self,
        pathname: UserPtr<i8>,
        argv: UserPtr<UserPtr<i8>>,
        envp: UserPtr<UserPtr<i8>>,
        ctx: &mut litebox_common_linux::PtRegs,
    ) -> Result<usize, Errno> {
        fn copy_vector(
            mut base: UserPtr<UserPtr<i8>>,
            _which: &str,
        ) -> Result<alloc::vec::Vec<alloc::ffi::CString>, Errno> {
            let mut out = alloc::vec::Vec::new();
            let mut total = 0usize;
            for _ in 0..MAX_VEC {
                let p: UserPtr<i8> = {
                    // read pointer-sized entries
                    match base.read_at_offset::<Platform>(0) {
                        Some(ptr) => ptr,
                        None => return Err(Errno::EFAULT),
                    }
                };
                if p.as_usize() == 0 {
                    break;
                }
                let Some(cs) = p.to_cstring::<Platform>() else {
                    return Err(Errno::EFAULT);
                };
                total += cs.as_bytes().len() + 1;
                if total > MAX_TOTAL_BYTES {
                    return Err(Errno::E2BIG);
                }
                out.push(cs);
                // advance to next pointer
                base = UserPtr::from_usize(base.as_usize() + core::mem::size_of::<usize>());
            }
            Ok(out)
        }

        // Copy pathname
        let Some(path_cstr) = pathname.to_cstring::<Platform>() else {
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

        let (path, argv_vec) = self.resolve_shebang(alloc::string::String::from(path), argv_vec)?;

        let loader = crate::loader::elf::ElfLoader::new(self, &path)?;

        // After this point, the old program is torn down and failures must terminate the process.

        // Kill all the other threads in this process and wait for them to exit.
        if !self.kill_other_threads() {
            // Another thread is already in the process of execve. This thread
            // will exit; return any error code.
            return Err(Errno::EBUSY);
        }

        // Close CLOEXEC descriptors
        self.close_on_exec();

        // unmmap all memory mappings and reset brk
        if let Some(robust_list) = self.thread.robust_list.take() {
            let _ = wake_robust_list(robust_list);
        }
        self.thread.clear_child_tid.set(None);

        self.signals.reset_for_exec();

        // Don't release reserved mappings.
        let release = |_r: Range<usize>, vm: VmFlags| !vm.is_empty();
        unsafe { self.global.pm.release_memory(release) }
            .expect("failed to release memory mappings");

        self.global
            .platform
            .set_arch_specific_register(&ArchSpecificRegister::FsBase, 0)
            .expect("failed to clear guest TLS on execve");

        self.load_program(loader, argv_vec, envp_vec)
            .expect("TODO: terminate the process cleanly");

        self.init_thread_context(ctx);
        Ok(0)
    }

    /// Loads the specified program into the process's address space and prepares the thread
    /// to start executing it.
    pub(crate) fn load_program(
        &self,
        mut loader: crate::loader::elf::ElfLoader<'_, FS>,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
    ) -> Result<(), crate::loader::elf::ElfLoaderError> {
        let load_info = loader.load(argv, envp, self.init_auxv())?;

        self.set_task_comm(loader.comm());

        self.thread
            .init_state
            .set(ThreadInitState::NewProcess(load_info));
        Ok(())
    }

    pub(crate) fn handle_init_request(&self, ctx: &mut litebox_common_linux::PtRegs) {
        self.init_thread_context(ctx);
        // Attach the thread handle so that the thread can be interrupted.
        self.thread
            .remote
            .handle
            .set(Box::new(self.wait_state.thread_handle()))
            .ok();
    }

    /// Initialize the thread context for a new process or thread, and perform any
    /// other initial setup required.
    fn init_thread_context(&self, ctx: &mut litebox_common_linux::PtRegs) {
        match self.thread.init_state.take() {
            ThreadInitState::None => {}
            ThreadInitState::NewProcess(load_info) => {
                #[cfg(target_arch = "x86_64")]
                {
                    *ctx = litebox_common_linux::PtRegs {
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
                        orig_rax: 0,
                        rip: load_info.entry_point,
                        cs: 0x33, // __USER_CS
                        eflags: 0,
                        rsp: load_info.user_stack_top,
                        ss: 0x2b, // __USER_DS
                    };
                }
            }
            ThreadInitState::NewThread {
                tls,
                stack,
                set_child_tid,
            } => {
                // Set the stack and the return value from clone().
                #[cfg(target_arch = "x86_64")]
                {
                    if let Some(stack) = stack {
                        ctx.rsp = stack;
                    }
                    ctx.rax = 0;
                }

                // Set the TLS for the new thread.
                if let Some(tls) = tls {
                    #[cfg(target_arch = "x86_64")]
                    {
                        self.sys_arch_prctl(ArchPrctlArg::SetFs(tls.as_usize()))
                            .unwrap();
                    }
                }

                if let Some(child_tid_ptr) = set_child_tid {
                    // Set the child TID if requested.
                    let _ = child_tid_ptr.write_at_offset::<Platform>(0, self.tid);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{UserPtr, UserPtrMut};

    extern crate std;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_arch_prctl() {
        use crate::syscalls::tests::init_platform;
        use litebox_common_linux::ArchPrctlArg;

        let task = init_platform(None);

        // Save old FS base
        let mut old_fs_base: usize = 0;
        let ptr = UserPtrMut::from_ptr(&raw mut old_fs_base);
        task.sys_arch_prctl(ArchPrctlArg::GetFs(ptr))
            .expect("Failed to get FS base");

        // Set new FS base
        let mut new_fs_base: [u8; 16] = [0; 16];
        let ptr = UserPtrMut::from_ptr(new_fs_base.as_mut_ptr());
        task.sys_arch_prctl(ArchPrctlArg::SetFs(ptr.as_usize()))
            .expect("Failed to set FS base");

        // Verify new FS base
        let mut current_fs_base: usize = 0;
        let ptr = UserPtrMut::from_ptr(&raw mut current_fs_base);
        task.sys_arch_prctl(ArchPrctlArg::GetFs(ptr))
            .expect("Failed to get FS base");
        assert_eq!(current_fs_base, new_fs_base.as_ptr() as usize);

        // Restore old FS base
        let ptr: UserPtrMut<u8> = UserPtrMut::from_usize(old_fs_base);
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
        let set_ptr = UserPtr::from_ptr(name.as_ptr());
        task.sys_prctl(litebox_common_linux::PrctlArg::SetName(set_ptr))
            .expect("sys_prctl SetName failed");

        // Prepare buffer for prctl(PR_GET_NAME, get_buf)
        let mut get_buf = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let get_ptr = UserPtrMut::from_ptr(get_buf.as_mut_ptr());

        task.sys_prctl(litebox_common_linux::PrctlArg::GetName(get_ptr))
            .expect("sys_prctl GetName failed");
        assert_eq!(
            &get_buf[..name.len()],
            name,
            "prctl get_name returned unexpected comm"
        );

        // Test too long name
        let long_name = [b'a'; litebox_common_linux::TASK_COMM_LEN + 10];
        let long_name_ptr = UserPtr::from_ptr(long_name.as_ptr());
        task.sys_prctl(litebox_common_linux::PrctlArg::SetName(long_name_ptr))
            .expect("sys_prctl SetName failed");

        // Get the name again
        let mut get_buf = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let get_ptr = UserPtrMut::from_ptr(get_buf.as_mut_ptr());
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

    /// Installing a custom handler for SIGINT: a background OS thread sends
    /// a real SIGINT via `libc::kill`, which should interrupt a blocking sleep
    /// with `EINTR`.
    /// Target Linux only because it use tgkill syscall to send signal to specific thread.
    #[cfg(all(target_os = "linux", debug_assertions))]
    #[test]
    fn test_sigint_with_custom_handler() {
        use litebox_common_linux::signal::{SaFlags, SigAction, SigSet, Signal};
        use litebox_common_linux::{ClockId, TimerFlags, Timespec};

        let callback_addr = 0x1000usize; // dummy non-null address for the callback
        let task = crate::syscalls::tests::init_platform(None);
        <litebox_platform_multiplex::Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            let act = SigAction {
                sigaction: callback_addr,
                flags: SaFlags::RESTORER,
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
                restorer: 0,
                mask: SigSet::empty(),
            };
            let act_ptr = UserPtr::from_ptr(&raw const act);
            task.sys_rt_sigaction(
                Signal::SIGINT,
                Some(act_ptr),
                None,
                core::mem::size_of::<SigSet>(),
            )
            .expect("rt_sigaction failed");

            // Spawn a plain OS thread that sends a real SIGINT to this
            // specific thread after a short delay, giving it time to enter nanosleep.
            let pid = unsafe { libc::getpid() };
            let tid = unsafe { libc::syscall(libc::SYS_gettid) };
            let handle = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(200));
                // Safety: sending a signal to a thread in our own process is always valid.
                let ret = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGINT) };
                assert_eq!(ret, 0, "tgkill failed");
            });

            let mut request = Timespec {
                tv_sec: 10,
                tv_nsec: 0,
            };
            let result = task.sys_clock_nanosleep(
                ClockId::Monotonic,
                TimerFlags::empty(),
                litebox_common_linux::TimeParam::Timespec64(UserPtrMut::from_ptr(
                    &raw mut request,
                )),
                litebox_common_linux::TimeParam::None,
            );
            assert_eq!(
                result,
                Err(litebox_common_linux::errno::Errno::EINTR),
                "nanosleep should be interrupted by SIGINT from background thread"
            );

             // `process_signals` is called when about to switch back to userspace, so simulate that here.
             let mut stack = [0u8; 4096];
             #[cfg(target_arch = "x86_64")]
             let mut regs = litebox_common_linux::PtRegs { rsp: stack.as_mut_ptr() as usize + stack.len(), ..Default::default() };
             task.process_signals(&mut regs);
            assert_eq!(
                regs.get_ip(), callback_addr,
                "after processing signals, execution should be redirected to the custom handler"
            );

            handle.join().expect("background thread panicked");
        });
    }

    /// After the alarm deadline passes, a blocking operation should be
    /// interrupted and SIGALRM should be pending.
    #[test]
    fn test_alarm_fires_after_deadline() {
        use litebox::platform::{Instant as _, TimeProvider};
        use litebox_common_linux::{ClockId, TimerFlags, Timespec};

        let task = crate::syscalls::tests::init_platform(None);
        <litebox_platform_multiplex::Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            let platform = task.global.platform;

            // Set a 1-second alarm.
            assert_eq!(task.sys_alarm(1).unwrap(), 0);

            let start = platform.now();

            // Block in a nanosleep longer than the alarm
            let mut remain = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let mut request = Timespec {
                tv_sec: 3,
                tv_nsec: 0,
            };
            let result = task.sys_clock_nanosleep(
                ClockId::Monotonic,
                TimerFlags::empty(),
                litebox_common_linux::TimeParam::Timespec64(UserPtrMut::from_ptr(&raw mut request)),
                litebox_common_linux::TimeParam::Timespec64(UserPtrMut::from_ptr(&raw mut remain)),
            );

            let elapsed = platform.now().duration_since(&start);

            // The nanosleep should have been interrupted by SIGALRM.
            assert_eq!(
                result,
                Err(litebox_common_linux::errno::Errno::EINTR),
                "nanosleep should have been interrupted"
            );
            let millis = remain.tv_sec.cast_unsigned() * 1000 + remain.tv_nsec / 1_000_000;
            // Allow tolerance for timer imprecision (especially on Windows).
            assert!(
                (1900..=2100).contains(&millis),
                "expected ~2s remaining, got {millis:?}"
            );

            let elapsed_ms = elapsed.as_millis();
            std::println!("Alarm fired after {elapsed_ms} ms");
            assert!(
                (900..=1100).contains(&elapsed_ms),
                "expected alarm after ~1000 ms, got {elapsed_ms} ms"
            );

            // The alarm should be consumed (deadline cleared).
            let remaining = task.sys_alarm(0).unwrap();
            assert_eq!(remaining, 0, "alarm should have been cleared by check");
        });
    }

    /// Cancelling an alarm before it fires should prevent signal delivery
    /// even if a blocking operation runs past the original deadline.
    #[test]
    fn test_alarm_cancel_prevents_signal() {
        use litebox_common_linux::{ClockId, TimerFlags, Timespec};

        let task = crate::syscalls::tests::init_platform(None);
        <litebox_platform_multiplex::Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            assert_eq!(task.sys_alarm(1).unwrap(), 0);
            // Cancel before it fires.
            let remaining = task.sys_alarm(0).unwrap();
            assert!(remaining >= 1, "alarm should still have had time remaining");

            // A short nanosleep past the original deadline should complete
            // normally — no signal should interrupt it.
            let mut request = Timespec {
                tv_sec: 2,
                tv_nsec: 0,
            };
            let result = task.sys_clock_nanosleep(
                ClockId::Monotonic,
                TimerFlags::empty(),
                litebox_common_linux::TimeParam::Timespec64(UserPtrMut::from_ptr(&raw mut request)),
                litebox_common_linux::TimeParam::None,
            );
            assert_eq!(result, Ok(()), "nanosleep should not have been interrupted");

            assert!(
                !task.has_pending_signals(),
                "cancelled alarm should not produce SIGALRM"
            );
        });
    }

    #[test]
    fn test_pause_wakes_on_pending_signal() {
        use litebox_common_linux::{
            PtRegs,
            errno::Errno,
            signal::{SigSet, SigmaskHow, Signal},
        };

        let task = crate::syscalls::tests::init_platform(None);
        <litebox_platform_multiplex::Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            let block_set = SigSet::empty().with(Signal::SIGUSR1);
            task.sys_rt_sigprocmask(
                SigmaskHow::SIG_BLOCK,
                Some(UserPtr::from_ptr(&raw const block_set)),
                None,
                core::mem::size_of::<SigSet>(),
            )
            .expect("block SIGUSR1 failed");

            assert_eq!(task.sys_alarm(1).unwrap(), 0);
            task.sys_tkill(task.tid, Signal::SIGUSR1.as_i32())
                .expect("tkill failed");
            assert!(!task.has_pending_signals(), "blocked SIGUSR1 should not be deliverable");

            let mut regs = PtRegs::default();
            task.process_signals(&mut regs);
            assert!(!task.has_pending_signals(), "blocked SIGUSR1 should remain undeliverable");

            task.sys_rt_sigprocmask(
                SigmaskHow::SIG_UNBLOCK,
                Some(UserPtr::from_ptr(&raw const block_set)),
                None,
                core::mem::size_of::<SigSet>(),
            )
            .expect("unblock SIGUSR1 failed");

            assert_eq!(task.sys_pause(), Err(Errno::EINTR));
            task.sys_alarm(0).unwrap();

            let pending = task.pending_signal_set();
            assert!(pending.contains(Signal::SIGUSR1), "expected SIGUSR1 pending");
            assert!(
                !pending.contains(Signal::SIGALRM),
                "SIGALRM must not be what woke pause()"
            );
        });
    }

    /// Setting alarm with SIG_IGN for SIGALRM: a blocking operation is still
    /// interrupted, but `process_signals` discards the signal.
    #[test]
    fn test_alarm_with_sigign() {
        use litebox_common_linux::signal::{SIG_IGN, SaFlags, SigAction, SigSet, Signal};
        use litebox_common_linux::{ClockId, TimerFlags, Timespec};

        let task = crate::syscalls::tests::init_platform(None);
        <litebox_platform_multiplex::Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            // Install SIG_IGN for SIGALRM.
            let act = SigAction {
                sigaction: SIG_IGN,
                flags: SaFlags::empty(),
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
                restorer: 0,
                mask: SigSet::empty(),
            };
            let act_ptr = UserPtr::from_ptr(&raw const act);
            task.sys_rt_sigaction(
                Signal::SIGALRM,
                Some(act_ptr),
                None,
                core::mem::size_of::<SigSet>(),
            )
            .expect("rt_sigaction failed");

            // Set a 1-second alarm and block in a short nanosleep.
            assert_eq!(task.sys_alarm(1).unwrap(), 0);
            let mut request = Timespec {
                tv_sec: 3,
                tv_nsec: 0,
            };
            let result = task.sys_clock_nanosleep(
                ClockId::Monotonic,
                TimerFlags::empty(),
                litebox_common_linux::TimeParam::Timespec64(UserPtrMut::from_ptr(&raw mut request)),
                litebox_common_linux::TimeParam::None,
            );

            // With SIG_IGN, nanosleep should NOT be interrupted — matching real
            // Linux behaviour where ignored signals are silently dropped at
            // send time and never make blocking syscalls return EINTR.
            assert_eq!(
                result,
                Ok(()),
                "nanosleep should complete normally when SIGALRM is ignored"
            );

            // No pending signals because the ignored SIGALRM was silently dropped.
            assert!(
                !task.has_pending_signals(),
                "SIG_IGN should cause SIGALRM to be silently dropped"
            );
        });
    }

    #[test]
    fn test_timer_delivers_correct_signal() {
        use litebox::platform::{TimerHandle as _, TimerProvider as _};
        use litebox_common_linux::signal::Signal;
        use litebox_common_linux::{ClockId, TimerFlags, Timespec};

        let task = crate::syscalls::tests::init_platform(None);
        <litebox_platform_multiplex::Platform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            let platform = task.global.platform;

            // Create a timer that requests SIGUSR1
            let handle = platform
                .create_timer(Signal::SIGUSR1)
                .expect("create_timer failed");
            handle.set_timer(core::time::Duration::from_secs(1));

            // Block in a nanosleep longer than the timer.
            let mut request = Timespec {
                tv_sec: 5,
                tv_nsec: 0,
            };
            let result = task.sys_clock_nanosleep(
                ClockId::Monotonic,
                TimerFlags::empty(),
                litebox_common_linux::TimeParam::Timespec64(UserPtrMut::from_ptr(
                    &raw mut request,
                )),
                litebox_common_linux::TimeParam::None,
            );
            // The nanosleep should have been interrupted.
            assert_eq!(
                result,
                Err(litebox_common_linux::errno::Errno::EINTR),
                "nanosleep should be interrupted by the timer"
            );

            // Verify that SIGUSR1 (not SIGALRM) is the pending signal.
            let pending = task.pending_signal_set();
            assert!(
                pending.contains(Signal::SIGUSR1),
                "expected SIGUSR1 pending"
            );
            assert!(
                !pending.contains(Signal::SIGALRM),
                "SIGALRM should NOT be pending — the timer should have delivered SIGUSR1 instead"
            );

            // Clean up the timer.
            handle.delete_timer();
        });
    }

    #[test]
    fn test_parse_shebang_basic() {
        use super::parse_shebang;

        // Basic interpreter only
        assert_eq!(
            parse_shebang(b"#!/bin/bash\necho hello\n"),
            Some(("/bin/bash", None))
        );

        // Interpreter with single argument
        assert_eq!(
            parse_shebang(b"#!/usr/bin/env python3\nimport sys\n"),
            Some(("/usr/bin/env", Some("python3")))
        );

        // Leading spaces after #!
        assert_eq!(parse_shebang(b"#!  /bin/sh\n"), Some(("/bin/sh", None)));

        // Trailing spaces
        assert_eq!(parse_shebang(b"#!/bin/sh  \n"), Some(("/bin/sh", None)));

        // Argument with extra whitespace
        assert_eq!(
            parse_shebang(b"#!/usr/bin/env  -S python3\n"),
            Some(("/usr/bin/env", Some("-S python3")))
        );

        // No newline (truncated line — still valid)
        assert_eq!(parse_shebang(b"#!/bin/bash"), Some(("/bin/bash", None)));

        // Not a shebang
        assert_eq!(parse_shebang(b"\x7fELF"), None);

        // Empty after #!
        assert_eq!(parse_shebang(b"#!\n"), None);

        // Too short
        assert_eq!(parse_shebang(b"#"), None);
        assert_eq!(parse_shebang(b""), None);

        // Tab separator
        assert_eq!(
            parse_shebang(b"#!/usr/bin/env\tpython3\n"),
            Some(("/usr/bin/env", Some("python3")))
        );
    }
}
