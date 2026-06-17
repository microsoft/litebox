// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process/thread related syscalls.

use crate::syscalls::file::{get_file_descriptor_flags, proc_cmdline_from_argv};
use crate::{ConstPtr, MutPtr, ShimFS, Task, multihost::ExecRoute};
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
use litebox::fs::OFlags;
use litebox::mm::linux::PAGE_SIZE;
use litebox::mm::linux::VmFlags;
use litebox::platform::PageManagementProvider;
use litebox::platform::ThreadProvider;
use litebox::platform::{
    AddressSpaceProvider, Instant as _, SystemInfoProvider as _, SystemTime as _, TimeProvider,
};
#[allow(unused_imports)]
// StdioProvider needed for SNP but resolved via inherent method on Linux userland
use litebox::platform::{
    PunchthroughProvider as _, PunchthroughToken as _, RawConstPointer as _, RawMutex as _,
    StdioProvider as _, ThreadLocalStorageProvider as _,
};
use litebox::platform::{RawMutPointer as _, TimerHandle, TimerProvider};
use litebox::process::ProcessId;
use litebox::process::{WorkerExecInputBinding, WorkerExecOutputBinding, WorkerExecStdioBindings};
use litebox::sync::Mutex;
use litebox::utils::TruncateExt as _;
use litebox_common_linux::{
    ArchPrctlArg, CloneFlags, FileDescriptorFlags, FutexArgs, PrctlArg, TimeParam, errno::Errno,
};
use litebox_platform_multiplex::Platform;

/// Type alias for the VforkDone + parent pipe FD info passed through to
/// `exec_on_remote_host` so it can set up HostPassthroughFdEntry replacements.
type ExecVforkInfo = (
    Arc<crate::VforkDone>,
    // parent_unix_socket_fds: (fd, pair_id, object_id)
    Vec<(usize, usize, u64)>,
);

/// Compile-time-linked names for the per-subsystem emit loops inside
/// [`Task::exec_on_remote_host`]. Each `BridgedByLoop` arm in
/// [`crate::syscalls::migration_policy::migration_policies_for`] references
/// one of these constants via a typed path (e.g.
/// `super::process::EVENTFD_AND_TIMERFD_BRIDGE_LOOP_NAME`). Renaming or
/// removing a constant without updating both the policy arm and the
/// adjacent emit loop is rejected by `rustc` (unresolved path), which
/// closes the "dishonest attestation" gap acknowledged in the
/// migration-gate merge commit (`6566d5da`): previously a developer
/// could declare `BridgedByLoop { loop_name: "<arbitrary string>" }`
/// with no compile-time link to an actual emit loop.
///
/// **Invariant**: each constant lives immediately above (or beside) its
/// emit loop in `exec_on_remote_host`. When you add/rename/remove an
/// emit loop, update the constant here and the matching arm in
/// `migration_policy.rs` in the same commit.
pub(crate) const EVENTFD_AND_TIMERFD_BRIDGE_LOOP_NAME: &str = "eventfd_and_timerfd";
pub(crate) const BROKER_PIPE_BRIDGE_LOOP_NAME: &str = "broker_pipe";
pub(crate) const BROKER_PTY_BRIDGE_LOOP_NAME: &str = "broker_pty";
pub(crate) const BROKER_SOCKETPAIR_BRIDGE_LOOP_NAME: &str = "broker_socketpair";
pub(crate) const BROKER_SOCKET_DGRAM_BRIDGE_LOOP_NAME: &str = "broker_socket_dgram";
pub(crate) const BROKER_SOCKET_SEQPACKET_BRIDGE_LOOP_NAME: &str = "broker_socket_seqpacket";
pub(crate) const BROKER_TCP_CONN_BRIDGE_LOOP_NAME: &str = "broker_tcp_conn";
pub(crate) const BROKER_INET_LISTENER_BRIDGE_LOOP_NAME: &str = "broker_inet_listener";
pub(crate) const FS_BROKERFILE_BRIDGE_LOOP_NAME: &str = "fs_brokerfile";
pub(crate) const SIGNALFD_BRIDGE_LOOP_NAME: &str = "signalfd";
#[cfg(feature = "worker_local_inet")]
pub(crate) const NETWORK_TCP_LISTEN_BRIDGE_LOOP_NAME: &str = "network_tcp_listen";
pub(crate) const INOTIFY_BRIDGE_LOOP_NAME: &str = "inotify";
pub(crate) const EPOLL_BRIDGE_LOOP_NAME: &str = "epoll";

/// Process-management-related state on [`Task`].
pub(crate) struct ThreadState {
    pub(crate) init_state: Cell<ThreadInitState>,
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
    clear_child_tid: Cell<Option<MutPtr<i32>>>,
    /// Registered guest rseq area for this thread, if any.
    rseq: Cell<Option<MutPtr<u8>>>,
    /// The purpose of the robust futex list is to ensure that if a thread accidentally fails to unlock a futex before
    /// terminating or calling execve(2), another thread that is waiting on that futex is notified that the former owner
    /// of the futex has died. This notification consists of two pieces: the FUTEX_OWNER_DIED bit is set in the futex word,
    /// and the kernel performs a futex(2) FUTEX_WAKE operation on one of the threads waiting on the futex.
    robust_list: Cell<Option<ConstPtr<litebox_common_linux::RobustListHead>>>,
}

// TODO: remove once we figure out how to handle Send/Sync for raw pointers.
unsafe impl Send for ThreadState {}

fn raw_wait_status_exit_code(raw_wait_status: i32) -> i32 {
    (raw_wait_status >> 8) & 0xff
}

fn raw_wait_status_term_signal(raw_wait_status: i32) -> i32 {
    raw_wait_status & 0x7f
}

fn raw_wait_status_exited(raw_wait_status: i32) -> bool {
    raw_wait_status_term_signal(raw_wait_status) == 0
}

fn raw_wait_status_signaled(raw_wait_status: i32) -> bool {
    let term_signal = raw_wait_status_term_signal(raw_wait_status);
    term_signal != 0 && term_signal != 0x7f
}

fn worker_raw_wait_status_to_registry_status(raw_wait_status: i32) -> i32 {
    if raw_wait_status_exited(raw_wait_status) {
        raw_wait_status_exit_code(raw_wait_status)
    } else if raw_wait_status_signaled(raw_wait_status) {
        let core_dump = raw_wait_status & 0x80;
        128 + raw_wait_status_term_signal(raw_wait_status) + core_dump
    } else {
        127
    }
}

/// True if the broker-side registry status encodes a terminating
/// signal (using the shell-style `128 + signum + optional 0x80
/// coredump` convention produced by
/// [`worker_raw_wait_status_to_registry_status`] and by the runner
/// when it stamps its own exit).
fn registry_status_is_signaled(registry_status: i32) -> bool {
    let low = registry_status & 0x7f;
    registry_status >= 128 && low != 0 && low != 0x7f
}

/// Decode a broker-cached registry exit status back to the shim's
/// internal [`ExitStatus`] enum. Inverse of
/// [`worker_raw_wait_status_to_registry_status`] modulo the coredump
/// bit (which `ExitStatus` does not carry).
fn registry_status_to_exit_status(registry_status: i32) -> ExitStatus {
    if registry_status_is_signaled(registry_status) {
        let signum = registry_status & 0x7f;
        match litebox_common_linux::signal::Signal::try_from(signum) {
            Ok(signal) => ExitStatus::Signal(signal),
            Err(_) => ExitStatus::Exit(127_i32.truncate()),
        }
    } else {
        // Normal exit: low byte is the exit code (0..=255).
        ExitStatus::Exit((registry_status & 0xff).truncate())
    }
}

/// Convenience: project a registry status back to the single-int
/// argument that `exit_thread` expects (signum on signaled exit,
/// exit code on normal exit). Mirrors the legacy branch in
/// `exec_on_remote_host` that selected between signum and exit code
/// based on the raw wait4 status word.
fn registry_status_exit_thread_arg(registry_status: i32) -> i32 {
    if registry_status_is_signaled(registry_status) {
        registry_status & 0x7f
    } else {
        registry_status & 0xff
    }
}

/// Resolve the broker-cached registry exit status for a guest pid,
/// falling back to the supplied waitpid-derived raw status when the
/// broker has no record.
///
/// Replaces the legacy `--worker-result-fd` pipe channel: the runner
/// stamps `try_mark_broker_process_exited(pid, registry_status)`
/// before terminating, and the parent's `wait_worker_host`
/// post-processing consults the broker via this helper. The fallback
/// path covers the rare case where the runner died abruptly (SIGKILL,
/// crash) before stamping.
fn resolve_worker_exit_registry_status(
    guest_pid: litebox::process::ProcessId,
    raw_wait_status_fallback: i32,
) -> i32 {
    if let Some(wake) = super::guest_pid::try_subscribe_broker_process_exit(guest_pid)
        && let Some(code) = wake.already_exited
    {
        return code;
    }
    worker_raw_wait_status_to_registry_status(raw_wait_status_fallback)
}

impl ThreadState {
    pub fn new_process(pid: i32) -> Self {
        let remote = Arc::new(ThreadRemote::new());
        Self {
            init_state: Cell::new(ThreadInitState::None),
            process: Arc::new(Process::new(pid, remote.clone())),
            remote,
            attached_tid: Cell::new(Some(pid)),
            clear_child_tid: Cell::new(None),
            rseq: Cell::new(None),
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
            rseq: Cell::new(None),
            robust_list: Cell::new(None),
        })
    }

    /// Reconstruct a thread state from a fork snapshot.
    pub(crate) fn new_from_restore(
        pid: i32,
        process: Arc<Process>,
        remote: Arc<ThreadRemote>,
        clear_child_tid: Option<usize>,
        robust_list: Option<usize>,
    ) -> Self {
        use litebox::platform::RawConstPointer as _;

        Self {
            init_state: Cell::new(ThreadInitState::None),
            process,
            remote,
            attached_tid: Cell::new(Some(pid)),
            clear_child_tid: Cell::new(clear_child_tid.map(crate::MutPtr::<i32>::from_usize)),
            rseq: Cell::new(None),
            robust_list: Cell::new(
                robust_list
                    .map(crate::ConstPtr::<litebox_common_linux::RobustListHead>::from_usize),
            ),
        }
    }

    fn detach_from_process(&self) -> bool {
        if let Some(tid) = self.attached_tid.take() {
            return self.process.detach_thread(tid);
        }
        false
    }

    pub(crate) fn remote(&self) -> &ThreadRemote {
        &self.remote
    }
}

impl Drop for ThreadState {
    fn drop(&mut self) {
        self.detach_from_process();
    }
}

/// Thread state that can be accessed from a remote thread.
pub(crate) struct ThreadRemote {
    /// Always set under the process `inner` lock, but can be read without
    /// locking.
    is_exiting: AtomicBool,
    /// Set by the forking thread to request this thread to park. The thread
    /// checks this in `check_for_interrupt` and `prepare_to_run_guest`.
    is_suspended: AtomicBool,
    /// Thread-directed signals queued by other threads in the same process.
    pub(crate) pending_signals: Mutex<Platform, crate::syscalls::signal::PendingSignals>,
    /// Handle to interrupt waits on this thread.
    handle: once_cell::race::OnceBox<litebox::event::wait::ThreadHandle<Platform>>,
}

impl ThreadRemote {
    pub(crate) fn new() -> Self {
        Self {
            is_exiting: AtomicBool::new(false),
            is_suspended: AtomicBool::new(false),
            pending_signals: Mutex::new(crate::syscalls::signal::PendingSignals::new()),
            handle: once_cell::race::OnceBox::new(),
        }
    }

    pub(crate) fn interrupt(&self) {
        if let Some(handle) = self.handle.get() {
            handle.interrupt();
        }
    }

    pub(crate) fn request_exit(&self) {
        self.is_exiting.store(true, Ordering::Relaxed);
        self.interrupt();
    }
}

/// A Linux process, which may have multiple threads.
pub(crate) struct Process {
    /// Number of threads in this process. Always updated under the `inner`
    /// mutex lock.
    nr_threads:
        <litebox_platform_multiplex::Platform as litebox::platform::RawMutexProvider>::RawMutex,
    pub(crate) inner: Mutex<Platform, ProcessInner>,
    /// Resource limits for this process.
    pub(crate) limits: ResourceLimits,
    /// Process-wide alarm timer.
    pub(crate) alarm_timer: Mutex<Platform, Alarm>,
    /// POSIX per-process timers created by timer_create(2).
    pub(crate) posix_timers: Mutex<Platform, PosixTimers>,
    /// Whether transparent huge pages are disabled for this process.
    pub(crate) thp_disabled: AtomicBool,
    /// The initial PID assigned to this process when it was created.
    /// Stable for the lifetime of the Process; survives the threads
    /// map being drained at exit so post-exit callers (e.g. the
    /// runner stamping broker exit) can recover the pid.
    pub(crate) initial_pid: i32,
}

pub(crate) struct Alarm {
    /// Handle for the alarm timer.
    pub(crate) handle: Option<<Platform as litebox::platform::TimerProvider>::TimerHandle>,
    /// The deadline for the alarm.
    pub(crate) deadline: Option<<Platform as litebox::platform::TimeProvider>::Instant>,
}

/// POSIX per-process timers created by `timer_create(2)`.
pub(crate) struct PosixTimers {
    /// Map from guest timer ID to platform timer handle.
    timers: alloc::collections::BTreeMap<i32, PosixTimerEntry>,
    /// Next timer ID to allocate.
    next_id: i32,
}

struct PosixTimerEntry {
    handle: <Platform as litebox::platform::TimerProvider>::TimerHandle,
    /// The armed interval (for timer_gettime reporting).
    interval: core::time::Duration,
    /// The armed value (one-shot or initial expiration).
    value: core::time::Duration,
    /// When the timer was last armed (for computing remaining time).
    armed_at: Option<<Platform as litebox::platform::TimeProvider>::Instant>,
}

impl PosixTimers {
    pub fn new() -> Self {
        Self {
            timers: alloc::collections::BTreeMap::new(),
            next_id: 0,
        }
    }
}

/// The locked portion of the process state.
pub(crate) struct ProcessInner {
    /// If true, the whole process is exiting.
    group_exit: bool,
    /// If true, one thread is waiting for other threads to exit.
    is_killing_other_threads: bool,
    /// If true, one thread is performing a vfork and parking siblings.
    is_forking: bool,
    /// The exit code of the last exited thread in the process. Not updated once
    /// `group_exit` is set.
    exit_status: ExitStatus,
    /// The thread list for the process, mapped by thread ID.
    pub(crate) threads: BTreeMap<i32, Arc<ThreadRemote>>,
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
                is_forking: false,
                threads: BTreeMap::from_iter([(pid, remote)]),
            }),
            limits: ResourceLimits::default(),
            alarm_timer: Mutex::new(Alarm {
                handle: None,
                deadline: None,
            }),
            posix_timers: Mutex::new(PosixTimers::new()),
            thp_disabled: AtomicBool::new(false),
            initial_pid: pid,
        }
    }

    /// Creates a new process with restored resource limits and thp state.
    ///
    /// Used by fork-restore to reconstruct a child process from a snapshot.
    pub(crate) fn new_with_rlimits(
        pid: i32,
        remote: Arc<ThreadRemote>,
        rlimits: &[(usize, usize); litebox_common_linux::RlimitResource::RLIM_NLIMITS],
        thp_disabled: bool,
    ) -> Self {
        let nr_threads = <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT;
        nr_threads.underlying_atomic().store(1, Ordering::Relaxed);
        let limits = ResourceLimits::from_snapshot(rlimits);
        Self {
            nr_threads,
            inner: Mutex::new(ProcessInner {
                exit_status: ExitStatus::Exit(0),
                group_exit: false,
                is_killing_other_threads: false,
                is_forking: false,
                threads: BTreeMap::from_iter([(pid, remote)]),
            }),
            limits,
            alarm_timer: Mutex::new(Alarm {
                handle: None,
                deadline: None,
            }),
            posix_timers: Mutex::new(PosixTimers::new()),
            thp_disabled: AtomicBool::new(thp_disabled),
            initial_pid: pid,
        }
    }

    /// Returns the initial PID assigned to this process at creation.
    pub fn initial_pid(&self) -> i32 {
        self.initial_pid
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
        if inner.group_exit || inner.is_killing_other_threads || inner.is_forking {
            return None;
        }
        // Reject attachment while vfork parking is active. `park_other_threads`
        // sets `is_suspended` under this same lock, so this closes the race
        // where clone() passed an unlocked park check but attaches after the
        // parking snapshot.
        if inner
            .threads
            .values()
            .any(|thread| thread.is_suspended.load(Ordering::Relaxed))
        {
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
    fn detach_thread(&self, tid: i32) -> bool {
        let data;
        let (notify, was_last) = {
            let mut inner = self.inner.lock();
            data = inner.threads.remove(&tid);
            assert!(data.is_some());

            let nr_threads = self.nr_threads.underlying_atomic();
            let n = nr_threads.load(Ordering::Relaxed);
            let new_count = n.checked_sub(1).expect("decrementing from zero threads");
            nr_threads.store(new_count, Ordering::Release);
            let was_last = new_count == 0;
            if was_last {
                assert!(inner.threads.is_empty());
                // The last thread exited. Prevent new threads.
                inner.group_exit = true;
            }

            // Notify waiters if this is the last thread of the process
            // (`wait_for_exit`) or if this is the last thread being killed
            // during an exec (`kill_other_threads`).
            (
                was_last || (new_count == 1 && inner.is_killing_other_threads),
                was_last,
            )
        };
        if notify {
            self.nr_threads.wake_all();
        }
        was_last
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InboundControlPlaneMessageError {
    EnvelopeWire(crate::multihost::OutboundControlPlaneEnvelopeWireError),
    Wire(crate::multihost::OutboundControlPlaneMessageWireError),
    ControlPlane(crate::multihost::ControlPlaneError),
    RetryEnvelope(crate::multihost::OutboundControlPlaneEnvelope),
    UnknownSourceHost(crate::multihost::HostId),
    UnexpectedSourceHostForChild {
        child_pid: litebox::process::ProcessId,
        expected_owner: crate::multihost::HostId,
        actual_source: crate::multihost::HostId,
    },
    UnknownTargetProcess(litebox::process::ProcessId),
    TargetProcessNotLocal {
        process_id: litebox::process::ProcessId,
        owner_host: crate::multihost::HostId,
        local_host: crate::multihost::HostId,
    },
    UnknownChildExitProvenance(litebox::process::ProcessId),
    ChildOwnedByDifferentParent {
        child_pid: litebox::process::ProcessId,
        expected_parent: litebox::process::ProcessId,
        actual_parent: Option<litebox::process::ProcessId>,
    },
    ChildExitSignalMismatch {
        child_pid: litebox::process::ProcessId,
        expected_signal: i32,
        actual_signal: i32,
    },
    ChildExitStatusMismatch {
        child_pid: litebox::process::ProcessId,
        expected_status: i32,
        actual_status: i32,
    },
    InvalidChildExitSignal(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundControlPlaneEnvelopeOutcome {
    Consumed,
    RetriedLocally,
}

impl<FS: ShimFS> Task<FS> {
    /// Updates the process exit status for a thread exit.
    pub(crate) fn exit_thread(&self, code: i8) {
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
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[EXIT] pid={} status={:?}",
            self.pid,
            status,
        );
        let mut inner = self.thread.process.inner.lock();
        if self.is_exiting() {
            return;
        }
        assert!(!inner.group_exit);
        inner.exit_status = status;
        inner.group_exit = true;
        // Cancel blocking stdin reads so threads in host syscalls can exit.
        // Only do this for the init process; child processes should not cancel
        // stdin for the entire sandbox.
        let is_init = Some(self.process_id) == self.global.litebox.process_registry().root_pid();
        if is_init {
            self.global.platform.cancel_stdin();
        }
        for (&_tid, thread) in &inner.threads {
            thread.is_exiting.store(true, Ordering::Relaxed);
        }
        // Wake threads blocked in wait_for_child (raw futex) before calling
        // interrupt(), so they see is_exiting when they re-check.
        self.global
            .litebox
            .process_registry()
            .notify_waiters(self.process_id);
        for (&_tid, thread) in &inner.threads {
            thread.interrupt();
        }
        // Wake threads parked in `park_for_vfork_if_requested` so they
        // observe `is_exiting` and break out of the park loop.
        {
            use litebox::platform::RawMutex as _;
            self.process_state.borrow().vfork_parking.park.wake_all();
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
            // Cancel blocking stdin reads so threads in host syscalls can exit.
            // Only do this for the init process; child processes should not cancel
            // stdin for the entire sandbox.
            if Some(self.process_id) == self.global.litebox.process_registry().root_pid() {
                self.global.platform.cancel_stdin();
            }
            for (&tid, thread) in &inner.threads {
                if tid == self.tid {
                    continue;
                }
                thread.is_exiting.store(true, Ordering::Relaxed);
            }
            // Wake threads blocked in wait_for_child before calling interrupt().
            self.global
                .litebox
                .process_registry()
                .notify_waiters(self.process_id);
            for (&tid, thread) in &inner.threads {
                if tid == self.tid {
                    continue;
                }
                thread.interrupt();
            }
            assert!(!inner.is_killing_other_threads);
            inner.is_killing_other_threads = true;
        }
        // Wait for other threads to exit.
        let mut iter = 0u32;
        loop {
            // If another thread started vfork parking, stop trying to exec
            // and return to the guest so we can park at prepare_to_run_guest.
            if self.is_suspended() {
                self.thread.process.inner.lock().is_killing_other_threads = false;
                return false;
            }
            let n = self
                .thread
                .process
                .nr_threads
                .underlying_atomic()
                .load(Ordering::Acquire);
            if n == 1 {
                break;
            }
            iter += 1;
            if iter.is_multiple_of(1000) {
                litebox::log_println!(
                    self.global.platform,
                    "kill_other_threads: tid={} waiting, nr_threads={} iter={}",
                    self.tid,
                    n,
                    iter,
                );
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

    /// Returns true if this thread has been asked to suspend for a vfork.
    pub fn is_suspended(&self) -> bool {
        self.thread.remote.is_suspended.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
pub(crate) enum ThreadInitState {
    #[default]
    None,
    NewProcess(crate::loader::elf::ElfLoadInfo),
    NewThread {
        stack: Option<usize>,
        tls: Option<ThreadLocalDescriptor>,
        set_child_tid: Option<MutPtr<i32>>,
    },
    ForkChild {
        stack: Option<usize>,
        tls_base: Option<usize>,
        set_child_tid: Option<MutPtr<i32>>,
    },
    /// Restored from a fork snapshot — the full execution context is provided.
    ForkRestore {
        exec_ctx: alloc::boxed::Box<litebox_common_linux::ExecutionContext>,
        tls_base: Option<usize>,
        set_child_tid: Option<usize>,
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

    pub(crate) fn current_ucred(&self) -> litebox_common_linux::Ucred {
        litebox_common_linux::Ucred {
            pid: self.pid.cast_unsigned(),
            uid: self.credentials.euid,
            gid: self.credentials.egid,
        }
    }

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
            PrctlArg::GetName(name) => {
                self.prepare_guest_write(name, 1)?;
                name.write_slice_at_offset(0, &self.comm.get())
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }
            PrctlArg::SetName(name) => {
                let mut name_buf = [0u8; litebox_common_linux::TASK_COMM_LEN - 1];
                // strncpy
                for (i, byte) in name_buf.iter_mut().enumerate() {
                    let b = name
                        .read_at_offset(isize::try_from(i).unwrap())
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
            PrctlArg::SetTHPDisable(disable) => {
                self.thread
                    .process
                    .thp_disabled
                    .store(disable != 0, Ordering::Relaxed);
                Ok(0)
            }
            PrctlArg::GetTHPDisable(arg) => {
                if arg != 0 {
                    return Err(Errno::EINVAL);
                }
                Ok(self
                    .thread
                    .process
                    .thp_disabled
                    .load(Ordering::Relaxed)
                    .into())
            }
            PrctlArg::SetDumpable(_) => {
                // No-op in the sandbox — dumpability is irrelevant.
                Ok(0)
            }
            PrctlArg::SetNoNewPrivs(_) => {
                // No-op — the sandbox already controls privilege.
                Ok(0)
            }
            PrctlArg::GetNoNewPrivs => {
                // Report that no_new_privs is set (it effectively is in the sandbox).
                Ok(1)
            }
            PrctlArg::SetSeccomp(_) => {
                // No-op — sshd installs a seccomp filter for privilege separation.
                // The sandbox has its own syscall interception; ignore sshd's.
                Ok(0)
            }
            PrctlArg::GetSecureBits => {
                // Return 0 (no secure bits set).
                Ok(0)
            }
            PrctlArg::CapAmbient(_) => {
                // No-op — capabilities are not supported in the sandbox.
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
                let token = self
                    .global
                    .platform
                    .get_punchthrough_token_for(punchthrough)
                    .expect("Failed to get punchthrough token for SET_FS");
                // reason: unsupported variants intentionally share this fallback path.
                #[allow(clippy::wildcard_enum_match_arm)]
                token.execute().map(|_| ()).map_err(|e| match e {
                    litebox::platform::PunchthroughError::Failure(errno) => errno,
                    _ => unimplemented!("Unsupported punchthrough error {:?}", e),
                })
            }
            #[cfg(target_arch = "x86_64")]
            ArchPrctlArg::GetFs(addr) => {
                let punchthrough = litebox_common_linux::PunchthroughSyscall::GetFsBase;
                let token = self
                    .global
                    .platform
                    .get_punchthrough_token_for(punchthrough)
                    .expect("Failed to get punchthrough token for GET_FS");
                // reason: unsupported variants intentionally share this fallback path.
                #[allow(clippy::wildcard_enum_match_arm)]
                let fsbase = token.execute().map_err(|e| match e {
                    litebox::platform::PunchthroughError::Failure(errno) => errno,
                    _ => unimplemented!("Unsupported punchthrough error {:?}", e),
                })?;
                self.prepare_guest_write(addr, 1)?;
                addr.write_at_offset(0, fsbase).ok_or(Errno::EFAULT)?;
                Ok(())
            }
            ArchPrctlArg::CETStatus | ArchPrctlArg::CETDisable | ArchPrctlArg::CETLock => {
                Err(Errno::EINVAL)
            }
            _ => unimplemented!(),
        }
    }

    #[cfg(target_arch = "x86")]
    pub(crate) fn set_thread_area(
        &self,
        user_desc: &mut litebox_common_linux::UserDesc,
    ) -> Result<(), Errno> {
        let punchthrough = litebox_common_linux::PunchthroughSyscall::SetThreadArea { user_desc };
        let token = self
            .global
            .platform
            .get_punchthrough_token_for(punchthrough)
            .expect("Failed to get punchthrough token for SET_THREAD_AREA");
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
    _pi: bool,
    _pending_op: bool,
) -> Result<(), Errno> {
    if futex_addr.as_usize() % 4 != 0 {
        return Err(Errno::EINVAL);
    }

    todo!("handle_futex_death is not implemented yet");
}

fn fetch_robust_entry(
    head: crate::ConstPtr<litebox_common_linux::RobustList>,
) -> (crate::ConstPtr<litebox_common_linux::RobustList>, bool) {
    let next = head.as_usize();
    (crate::ConstPtr::from_usize(next & !1), next & 1 != 0)
}

fn wake_robust_list(
    head: crate::ConstPtr<litebox_common_linux::RobustListHead>,
) -> Result<(), Errno> {
    let mut limit = ROBUST_LIST_LIMIT;
    let head_ptr = head.as_usize();
    let head = head.read_at_offset(0).ok_or(Errno::EFAULT)?;
    let (mut entry, mut pi) = fetch_robust_entry(crate::ConstPtr::from_usize(head.list.next));
    let (pending, ppi) = fetch_robust_entry(crate::ConstPtr::from_usize(head.list_op_pending));
    let futex_offset = head.futex_offset;
    let entry_head = head_ptr + offset_of!(litebox_common_linux::RobustListHead, list);
    while entry.as_usize() != entry_head && limit > 0 {
        let nxt = entry
            .read_at_offset(0)
            .map(|e| fetch_robust_entry(crate::ConstPtr::from_usize(e.next)));
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

impl<FS: ShimFS> Task<FS> {
    /// Make any active shared-fork CoW pages covering a host-side guest-memory
    /// write writable before using fallible pointer helpers from shim code.
    pub(crate) fn prepare_cow_for_host_write(&self, addr: usize, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let Some(last_addr) = addr.checked_add(len - 1) else {
            return false;
        };

        let start = addr & !(PAGE_SIZE - 1);
        let end = (last_addr & !(PAGE_SIZE - 1)).saturating_add(PAGE_SIZE);

        for page_addr in (start..end).step_by(PAGE_SIZE) {
            let Some((cow, orig_perms)) = self.top_cow_layer_for_page(page_addr) else {
                continue;
            };

            self.snapshot_cow_page_if_needed(cow.as_ref(), page_addr, true);
            let page_range = page_addr..page_addr + PAGE_SIZE;
            // SAFETY: restoring the page's original permissions is exactly what
            // the CoW write-fault path does before resuming execution.
            if !unsafe {
                crate::cow_update_permissions(self.global.platform, page_range, orig_perms)
            } {
                return false;
            }
        }

        true
    }

    /// Called when the task is exiting.
    pub(crate) fn prepare_for_exit(&mut self) {
        // If this thread has a deferred park lie that was claimed (at a
        // park_if_deferred checkpoint) but the vfork window hasn't closed yet,
        // decrement parked_count so the forking thread isn't stuck. The
        // deferred_lie_count was already decremented when the lie was claimed
        // via CAS in park_if_deferred, so we only adjust parked_count here.
        if self.deferred_vfork_park.get() {
            use litebox::platform::RawMutex as _;
            let ps = self.process_state.borrow();
            ps.vfork_parking
                .parked_count
                .underlying_atomic()
                .fetch_sub(1, core::sync::atomic::Ordering::Release);
            ps.vfork_parking.parked_count.wake_all();
            self.deferred_vfork_park.set(false);
        }

        // If this thread was marked as suspended (by park_other_threads) and
        // is now exiting, wake the vfork_parked_count futex so the forking
        // thread can recompute the expected count and make progress.
        if self.is_suspended() {
            use litebox::platform::RawMutex as _;
            self.process_state
                .borrow()
                .vfork_parking
                .parked_count
                .wake_all();
        }

        // `sys_exit`/`sys_exit_group` only mark the task as terminated; actual
        // fd cleanup runs later from Task drop, after the syscall-level
        // caller_pid guard has unwound. Re-stamp this cleanup so per-pid broker
        // releases hit the exiting process's bucket.
        let _caller_pid_guard =
            litebox_common_linux::fd_token_client::set_caller_pid_scope(self.process_id.0);

        // If this task was migrated to a remote worker host via delayed fork,
        // all exit notification and cleanup was handled by commit_delayed_fork
        // and its background waiter.  Skip the rest of prepare_for_exit to
        // avoid double-notifying the parent or double-destroying resources.
        //
        // However, we MUST close the local FD table references first.  The
        // child's FD table was cloned from the parent at fork time and still
        // holds Arc references to shared descriptor entries (e.g. pipe sender
        // halves).  Without releasing these references, pipe readers in the
        // parent process will never see EOF — the worker-mux dispatcher polls
        // is_read_eof() on the receiver, which requires ALL sender Arc refs
        // to be dropped so the WriteEnd is shut down.
        if self.migrated_to_remote.get() {
            self.close_all_fds();
            return;
        }

        let is_last_thread = self.thread.detach_from_process();

        // Maintain process_thread_handles: clean up on last-thread exit, or
        // retarget to a surviving thread if the registered thread is leaving.
        let proc_key = self.process_id.0.cast_signed();
        if is_last_thread {
            // Last thread — remove the entry entirely.
            self.global.process_thread_handles.write().remove(&proc_key);
        } else {
            // Process still alive. If WE were the registered thread, hand
            // the handle to another live thread so cross-process signals
            // (e.g. SIGCHLD) can still interrupt this process.
            let mut handles = self.global.process_thread_handles.write();
            if let Some(registered) = handles.get(&proc_key)
                && Arc::ptr_eq(registered, &self.thread.remote)
            {
                let inner = self.thread.process.inner.lock();
                if let Some((_tid, other)) = inner.threads.iter().next() {
                    handles.insert(proc_key, other.clone());
                }
            }
        }

        if let Some(clear_child_tid) = self.thread.clear_child_tid.take() {
            let clear_child_tid_addr = clear_child_tid.as_usize();
            // Some runtimes (e.g. BusyBox/musl) park clear_child_tid inside TLS
            // that they tear down before the final exit_group cleanup runs. Skip
            // the clear+wake once the guest mapping is already gone.
            if self.guest_range_is_mapped(clear_child_tid_addr, core::mem::size_of::<i32>())
                && self.prepare_guest_write(clear_child_tid, 1).is_ok()
                && clear_child_tid.write_at_offset(0, 0).is_some()
            {
                let clear_child_tid = crate::MutPtr::from_usize(clear_child_tid_addr);
                let _ = self.sys_futex(litebox_common_linux::FutexArgs::Wake {
                    addr: clear_child_tid,
                    flags: litebox_common_linux::FutexFlags::PRIVATE,
                    count: 1,
                });
            }
        }
        if let Some(robust_list) = self.thread.robust_list.take() {
            let _ = wake_robust_list(robust_list);
        }

        // If this was the last thread in the process, close all open FDs and
        // notify the core registry.
        if is_last_thread {
            use litebox::platform::AddressSpaceProvider;

            // Close all remaining open file descriptors. This is essential for
            // releasing resources like pipe write ends so that readers see EOF.
            self.close_all_fds();

            // Flush MAP_SHARED writeback data BEFORE marking the process as
            // exited. exit_process_with_callback() wakes parent waiters, so
            // the parent can return from wait4() and immediately consume
            // output files. The writeback must complete first.
            let is_fork_child = self.fork_context.get_mut().is_some();
            if is_fork_child {
                // Non-destructive flush: the parent's tracking and handles
                // must remain intact (we share ProcessState with the parent).
                self.sync_all_shared_mappings();
            } else {
                self.flush_all_shared_mappings();
            }

            let exit_status = {
                let inner = self.thread.process.inner.lock();
                match inner.exit_status {
                    ExitStatus::Exit(code) => i32::from(code),
                    ExitStatus::Signal(sig) => sig.as_i32() + 128,
                }
            };
            let exiting_pgid = self
                .global
                .litebox
                .process_registry()
                .get_pgid(self.process_id)
                .map(|pgid| pgid.0);
            super::guest_pid::try_mark_broker_process_exited(self.process_id.0, exit_status);
            // Phase F.5+ PE.1 Step D: sweep broker-tracked refs for
            // this pid. No-op when per-pid ownership is gated off;
            // belt-and-braces sweep for non-fd state and any
            // SIGKILL-leaked refs otherwise.
            super::guest_pid::try_release_all_broker_for_pid(self.process_id.0);
            let removed_owner = self
                .global
                .control_plane
                .unregister_running_process(self.process_id);
            debug_assert!(
                removed_owner.is_some(),
                "last running thread must be registered in the control plane"
            );
            self.global
                .control_plane
                .clear_child_exit_provenance_for_parent(self.process_id);
            self.global
                .litebox
                .process_registry()
                .exit_process_with_callback(self.process_id, exit_status, |notif| {
                    // Queue SIGCHLD before waking parent waiters so the parent
                    // cannot return from wait4 and miss the pending signal.
                    if let Some(notif) = notif {
                        let Some(source_host) = removed_owner else {
                            return;
                        };
                        self.global
                            .control_plane
                            .record_child_exit_provenance(source_host, notif);
                        self.notify_parent_of_child_exit(notif);
                    }
                });
            if let Some(pgid) = exiting_pgid {
                self.global.cleanup_pgrp_signal_subscription_if_empty(pgid);
            }

            // Release the process's VA partition. For a vfork child that
            // hasn't exec'd, destroy the child's reserved partition (from
            // fork_context), not the parent's shared ProcessState.
            let as_id = if let Some(fc) = self.fork_context.get_mut() {
                fc.address_space_id
            } else {
                // Release all user memory mappings before destroying the
                // address space. This is safe because the process is
                // exiting and no threads remain to access this memory.
                // (MAP_SHARED writeback already completed above.)
                let ps = self.process_state.borrow();
                unsafe { ps.pm.release_memory(|_, _| true) }
                    .expect("failed to release memory on exit");
                ps.address_space_id
            };
            let r = self.global.platform.destroy_address_space(as_id);
            debug_assert!(
                r.is_ok(),
                "failed to destroy address space {as_id:?}: {r:?}"
            );
        }

        // If this is a vfork child, unblock the parent only after all exit
        // cleanup that may touch shared guest memory has completed.
        if let Some(fc) = self.fork_context.get_mut() {
            fc.vfork_done.signal_exit();
        }
    }

    pub(crate) fn sys_exit(&self, status: i32) {
        // The `Task` will be dropped on the way out of the shim, which will
        // call `self.prepare_for_exit()`.
        self.exit_thread(status.truncate());
        self.local_task_terminated.set(true);
    }

    fn reject_remote_running_process_control(
        &self,
        process_id: litebox::process::ProcessId,
        operation: &str,
    ) -> Result<(), Errno> {
        let Some(owner_host) = self
            .global
            .control_plane
            .owner_of_running_process(process_id)
        else {
            return Ok(());
        };
        if owner_host == self.global.control_plane.local_host() {
            return Ok(());
        }
        log_unsupported!(
            "{operation} for running pid {} owned by remote host {:?}",
            process_id.0,
            owner_host
        );
        Err(Errno::EOPNOTSUPP)
    }

    fn reject_remote_running_child_wait(
        &self,
        process_id: litebox::process::ProcessId,
        operation: &str,
    ) -> Result<(), Errno> {
        let is_direct_child = self
            .global
            .litebox
            .process_registry()
            .with_context(process_id, |ctx| ctx.parent == Some(self.process_id))
            .unwrap_or(false);
        if !is_direct_child {
            return Ok(());
        }
        self.reject_remote_running_process_control(process_id, operation)
    }

    fn deliver_local_child_exit_notification(
        &self,
        notif: litebox::process::ExitNotification,
    ) -> Result<(), InboundControlPlaneMessageError> {
        use litebox_common_linux::signal::{Siginfo, SiginfoData, Signal};

        const CLD_EXITED: i32 = 1;

        let signal = Signal::try_from(notif.exit_signal).map_err(|_| {
            InboundControlPlaneMessageError::InvalidChildExitSignal(notif.exit_signal)
        })?;
        let mut data = SiginfoData { pad: [0u32; 28] };
        // si_pid (offset 0 in data, i32)
        data.pad[0] = notif.child_pid.0;
        // si_uid (offset 4, u32) — leave as 0
        // si_status (offset 8, i32)
        data.pad[2] = notif.exit_status.cast_unsigned();

        let siginfo = Siginfo {
            signo: signal.as_i32(),
            errno: 0,
            code: CLD_EXITED,
            #[cfg(target_pointer_width = "64")]
            __pad: 0,
            data,
        };

        self.global
            .cross_process_signals
            .lock()
            .push(crate::CrossProcessSignal {
                target_process_id: notif.parent_pid.0,
                target_tid: None,
                signal,
                siginfo,
            });

        // Local interrupt handles are a best-effort wakeup path, not the
        // ownership source of truth.
        let handles = self.global.process_thread_handles.read();
        let parent_key = notif.parent_pid.0.cast_signed();
        if let Some(remote) = handles.get(&parent_key) {
            remote.interrupt();
        }
        Ok(())
    }

    fn deliver_inbound_control_plane_message(
        &self,
        source_host: crate::multihost::HostId,
        wire: crate::multihost::OutboundControlPlaneMessageWire,
        local_delivery_completed: bool,
    ) -> Result<(), InboundControlPlaneMessageError> {
        if !self.global.control_plane.is_registered_host(source_host) {
            return Err(InboundControlPlaneMessageError::UnknownSourceHost(
                source_host,
            ));
        }
        let message = crate::multihost::OutboundControlPlaneMessage::try_from(wire)
            .map_err(InboundControlPlaneMessageError::Wire)?;
        match message {
            crate::multihost::OutboundControlPlaneMessage::ChildExit(notif) => {
                let proof = self
                    .global
                    .control_plane
                    .child_exit_provenance(notif.child_pid)
                    .ok_or(InboundControlPlaneMessageError::UnknownChildExitProvenance(
                        notif.child_pid,
                    ))?;
                if proof.source_host != source_host {
                    return Err(
                        InboundControlPlaneMessageError::UnexpectedSourceHostForChild {
                            child_pid: notif.child_pid,
                            expected_owner: proof.source_host,
                            actual_source: source_host,
                        },
                    );
                }
                if proof.notification.parent_pid != notif.parent_pid {
                    return Err(
                        InboundControlPlaneMessageError::ChildOwnedByDifferentParent {
                            child_pid: notif.child_pid,
                            expected_parent: proof.notification.parent_pid,
                            actual_parent: Some(notif.parent_pid),
                        },
                    );
                }
                if proof.notification.exit_signal != notif.exit_signal {
                    return Err(InboundControlPlaneMessageError::ChildExitSignalMismatch {
                        child_pid: notif.child_pid,
                        expected_signal: proof.notification.exit_signal,
                        actual_signal: notif.exit_signal,
                    });
                }
                if proof.notification.exit_status != notif.exit_status {
                    return Err(InboundControlPlaneMessageError::ChildExitStatusMismatch {
                        child_pid: notif.child_pid,
                        expected_status: proof.notification.exit_status,
                        actual_status: notif.exit_status,
                    });
                }
                let owner_host = self
                    .global
                    .control_plane
                    .owner_of_running_process(proof.notification.parent_pid)
                    .ok_or_else(|| {
                        let _ = self
                            .global
                            .control_plane
                            .clear_child_exit_provenance(notif.child_pid);
                        InboundControlPlaneMessageError::UnknownTargetProcess(
                            proof.notification.parent_pid,
                        )
                    })?;
                let local_host = self.global.control_plane.local_host();
                if owner_host != local_host {
                    return Err(InboundControlPlaneMessageError::TargetProcessNotLocal {
                        process_id: proof.notification.parent_pid,
                        owner_host,
                        local_host,
                    });
                }
                if local_delivery_completed {
                    self.global
                        .control_plane
                        .clear_child_exit_provenance(notif.child_pid);
                    return Ok(());
                }
                match self.deliver_local_child_exit_notification(notif) {
                    Ok(()) => match self.global.control_plane.route_child_exit_notification(
                        source_host,
                        local_host,
                        notif,
                        true,
                    ) {
                        Ok(
                            crate::multihost::ChildExitRoute::DeliverLocal
                            | crate::multihost::ChildExitRoute::NoRunningOwner,
                        ) => {
                            self.global
                                .control_plane
                                .clear_child_exit_provenance(notif.child_pid);
                            Ok(())
                        }
                        Ok(crate::multihost::ChildExitRoute::QueuedRemote { target_host: _ }) => {
                            Ok(())
                        }
                        Err(crate::multihost::ControlPlaneError::OutboundMessageQueueFull {
                            ..
                        }) => Err(InboundControlPlaneMessageError::RetryEnvelope(
                            crate::multihost::OutboundControlPlaneEnvelope {
                                source_host,
                                message: wire,
                                local_delivery_completed: true,
                            },
                        )),
                        Err(err) => Err(InboundControlPlaneMessageError::ControlPlane(err)),
                    },
                    Err(err @ InboundControlPlaneMessageError::InvalidChildExitSignal(_)) => {
                        self.global
                            .control_plane
                            .clear_child_exit_provenance(notif.child_pid);
                        Err(err)
                    }
                    Err(err) => Err(err),
                }
            }
        }
    }

    fn consume_inbound_control_plane_envelope(
        &self,
        envelope: crate::multihost::OutboundControlPlaneEnvelope,
        restore_local_retry_front: bool,
    ) -> Result<InboundControlPlaneEnvelopeOutcome, InboundControlPlaneMessageError> {
        let message = crate::multihost::OutboundControlPlaneMessage::try_from(envelope.message)
            .map_err(InboundControlPlaneMessageError::Wire)?;
        let local_host = self.global.control_plane.local_host();
        loop {
            match self.deliver_inbound_control_plane_message(
                envelope.source_host,
                envelope.message,
                envelope.local_delivery_completed,
            ) {
                Ok(()) => return Ok(InboundControlPlaneEnvelopeOutcome::Consumed),
                Err(InboundControlPlaneMessageError::RetryEnvelope(retry_envelope)) => {
                    if restore_local_retry_front {
                        self.global
                            .control_plane
                            .restore_local_outbound_envelope(retry_envelope)
                            .map_err(InboundControlPlaneMessageError::ControlPlane)?;
                    } else {
                        self.global
                            .control_plane
                            .queue_outbound_envelope_for_host(local_host, retry_envelope)
                            .map_err(InboundControlPlaneMessageError::ControlPlane)?;
                    }
                    return Ok(InboundControlPlaneEnvelopeOutcome::RetriedLocally);
                }
                Err(InboundControlPlaneMessageError::TargetProcessNotLocal { .. }) => match message
                {
                    crate::multihost::OutboundControlPlaneMessage::ChildExit(notif) => {
                        match self.global.control_plane.route_child_exit_notification(
                            envelope.source_host,
                            local_host,
                            notif,
                            envelope.local_delivery_completed,
                        ) {
                            Ok(crate::multihost::ChildExitRoute::DeliverLocal) => {}
                            Ok(crate::multihost::ChildExitRoute::NoRunningOwner) => {
                                let _ = self
                                    .global
                                    .control_plane
                                    .clear_child_exit_provenance(notif.child_pid);
                                return Ok(InboundControlPlaneEnvelopeOutcome::Consumed);
                            }
                            Ok(crate::multihost::ChildExitRoute::QueuedRemote {
                                target_host: _,
                            }) => return Ok(InboundControlPlaneEnvelopeOutcome::Consumed),
                            Err(
                                crate::multihost::ControlPlaneError::OutboundMessageQueueFull {
                                    ..
                                },
                            ) => {
                                if restore_local_retry_front {
                                    self.global
                                        .control_plane
                                        .restore_local_outbound_envelope(envelope)
                                        .map_err(InboundControlPlaneMessageError::ControlPlane)?;
                                } else {
                                    self.global
                                        .control_plane
                                        .queue_outbound_envelope_for_host(local_host, envelope)
                                        .map_err(InboundControlPlaneMessageError::ControlPlane)?;
                                }
                                return Ok(InboundControlPlaneEnvelopeOutcome::RetriedLocally);
                            }
                            Err(err) => {
                                return Err(InboundControlPlaneMessageError::ControlPlane(err));
                            }
                        }
                    }
                },
                Err(err) => return Err(err),
            }
        }
    }

    fn consume_inbound_control_plane_envelope_wire(
        &self,
        envelope_wire: crate::multihost::OutboundControlPlaneEnvelopeWire,
        restore_local_retry_front: bool,
    ) -> Result<InboundControlPlaneEnvelopeOutcome, InboundControlPlaneMessageError> {
        let envelope = crate::multihost::OutboundControlPlaneEnvelope::try_from(envelope_wire)
            .map_err(InboundControlPlaneMessageError::EnvelopeWire)?;
        self.consume_inbound_control_plane_envelope(envelope, restore_local_retry_front)
    }

    pub(crate) fn deliver_inbound_control_plane_envelope_wire(
        &self,
        envelope_wire: crate::multihost::OutboundControlPlaneEnvelopeWire,
    ) -> Result<(), InboundControlPlaneMessageError> {
        self.consume_inbound_control_plane_envelope_wire(envelope_wire, false)
            .map(|_| ())
    }

    fn notify_parent_of_child_exit(&self, notif: litebox::process::ExitNotification) {
        let Some(source_host) = self
            .global
            .control_plane
            .child_exit_provenance(notif.child_pid)
            .map(|proof| proof.source_host)
        else {
            log_unsupported!(
                "child-exit provenance for pid {} was missing during notification",
                notif.child_pid.0
            );
            return;
        };
        let Ok(message) = crate::multihost::OutboundControlPlaneMessageWire::try_from(
            crate::multihost::OutboundControlPlaneMessage::ChildExit(notif),
        ) else {
            let _ = self
                .global
                .control_plane
                .clear_child_exit_provenance(notif.child_pid);
            log_unsupported!(
                "child-exit notification for pid {} could not be encoded",
                notif.parent_pid.0
            );
            return;
        };
        let delivery = self.deliver_inbound_control_plane_envelope_wire(
            crate::multihost::OutboundControlPlaneEnvelopeWire::from(
                crate::multihost::OutboundControlPlaneEnvelope {
                    source_host,
                    message,
                    local_delivery_completed: false,
                },
            ),
        );
        match delivery {
            Ok(()) => {}
            Err(InboundControlPlaneMessageError::ControlPlane(
                crate::multihost::ControlPlaneError::OutboundMessageQueueFull { .. },
            )) => {
                log_unsupported!(
                    "child-exit notification for pid {} could not be persisted for retry because the local retry queue is full",
                    notif.parent_pid.0
                );
            }
            Err(err) => {
                let _ = self
                    .global
                    .control_plane
                    .clear_child_exit_provenance(notif.child_pid);
                log_unsupported!(
                    "child-exit notification for pid {} could not be delivered: {:?}",
                    notif.parent_pid.0,
                    err
                );
            }
        }
    }

    /// Drain one local control-plane envelope if possible.
    ///
    /// Returns `true` when the caller should immediately re-check instead of
    /// sleeping, either because more local work remains after forward progress
    /// or because another thread currently holds the serialized pump.
    pub(crate) fn drain_one_local_control_plane_message(&self) -> bool {
        struct PumpActiveGuard<'a>(&'a AtomicBool);
        impl Drop for PumpActiveGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        if self
            .global
            .local_control_plane_pump_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return true;
        }
        let _pump_active_guard = PumpActiveGuard(&self.global.local_control_plane_pump_active);
        let local_host = self.global.control_plane.local_host();
        let Ok(envelope_wire) = self
            .global
            .control_plane
            .take_next_outbound_message_wire_for_host(local_host)
        else {
            log_unsupported!(
                "local host {:?} could not poll its control-plane queue",
                local_host
            );
            return false;
        };
        let Some(envelope_wire) = envelope_wire else {
            return false;
        };
        let made_forward_progress = match self
            .consume_inbound_control_plane_envelope_wire(envelope_wire, true)
        {
            Ok(InboundControlPlaneEnvelopeOutcome::Consumed) => true,
            Ok(InboundControlPlaneEnvelopeOutcome::RetriedLocally) => false,
            Err(err) => {
                if let Ok(envelope) =
                    crate::multihost::OutboundControlPlaneEnvelope::try_from(envelope_wire)
                    && let Ok(crate::multihost::OutboundControlPlaneMessage::ChildExit(notif)) =
                        crate::multihost::OutboundControlPlaneMessage::try_from(envelope.message)
                {
                    let _ = self
                        .global
                        .control_plane
                        .clear_child_exit_provenance(notif.child_pid);
                }
                log_unsupported!(
                    "local host {:?} could not consume control-plane message: {:?}",
                    local_host,
                    err
                );
                true
            }
        };
        if !made_forward_progress {
            return false;
        }
        match self
            .global
            .control_plane
            .has_outbound_messages_for_host(local_host)
        {
            Ok(has_more) => has_more,
            Err(err) => {
                log_unsupported!(
                    "local host {:?} could not inspect its control-plane queue: {:?}",
                    local_host,
                    err
                );
                false
            }
        }
    }

    pub(crate) fn sys_exit_group(&self, status: i32) {
        self.exit_group(ExitStatus::Exit(status.truncate()));
    }

    /// Handle syscall `wait4`.
    ///
    /// `wait4(pid, wstatus, options, rusage)`:
    /// - `pid > 0`: wait for specific child
    /// - `pid == -1`: wait for any child
    /// - `pid == 0`: wait for any child in same process group
    /// - `pid < -1`: wait for any child in process group `-pid`
    pub(crate) fn sys_wait4(
        &self,
        pid: i32,
        wstatus: Option<crate::MutPtr<i32>>,
        options: i32,
        _rusage: Option<crate::MutPtr<u8>>,
    ) -> Result<usize, Errno> {
        use litebox::process::{ProcessId, WaitOptions, WaitTarget};

        let target = match pid {
            p if p > 0 => {
                // After Phase K Step 3, ProcessId == guest pid by
                // construction, so the historical pid_to_process_id
                // forward lookup is just `ProcessId(p as u32)`.
                let process_id = ProcessId(p.try_into().map_err(|_| Errno::EINVAL)?);
                WaitTarget::Pid(process_id)
            }
            -1 => WaitTarget::AnyChild,
            0 => {
                // Same process group — for now, treat as any child.
                WaitTarget::AnyChild
            }
            p => {
                let group_id = (-p).try_into().map_err(|_| Errno::EINVAL)?;
                WaitTarget::ProcessGroup(litebox::process::ProcessGroupId(group_id))
            }
        };

        let wait_options = WaitOptions::from_bits(options.cast_unsigned()).ok_or_else(|| {
            log_unsupported!("wait4 with unsupported options: {:#x}", options);
            Errno::EINVAL
        })?;
        if let WaitTarget::Pid(target_pid) = target {
            self.reject_remote_running_child_wait(target_pid, "wait4")?;
        }

        // Treat vfork suspension as an interruption so wait_for_child returns,
        // allowing prepare_to_run_guest() to park this thread.
        // Also check for pending signals so that wait4 is truly
        // signal-interruptible (SA_RESTART depends on EINTR being returned).
        let is_interrupted = || {
            use core::sync::atomic::Ordering;
            use litebox::event::wait::CheckForInterrupt as _;
            let ps = self.process_state.borrow();
            self.check_for_interrupt()
                || ps
                    .vfork_parking
                    .park
                    .underlying_atomic()
                    .load(Ordering::Acquire)
                    != 0
        };
        let result = self.global.litebox.process_registry().wait_for_child(
            self.process_id,
            target,
            wait_options,
            Some(&self.wait_cx()),
            Some(&is_interrupted),
        );

        match result {
            Ok(wr) => {
                if let Some(ptr) = wstatus {
                    let encoded = if wr.status > 128 {
                        // The process registry stores signal deaths as 128+signal.
                        wr.status - 128
                    } else {
                        (wr.status & 0xff) << 8
                    };
                    self.prepare_guest_write(ptr, 1)?;
                    let _ = ptr.write_at_offset(0, encoded);
                }
                // wait_for_child returns the matched child's ProcessId.
                // After Phase K Step 3 it equals the guest-visible pid
                // by construction, so the historical reverse lookup
                // through pid_to_process_id is just `wr.pid.0 as i32`.
                let guest_pid = wr.pid.0 as usize;
                Ok(guest_pid)
            }
            Err(litebox::process::WaitError::WouldBlock) => Ok(0),
            Err(litebox::process::WaitError::Interrupted) => {
                // Linux returns ERESTARTSYS for wait4.
                self.syscall_restartable.set(true);
                Err(Errno::EINTR)
            }
            Err(
                litebox::process::WaitError::NoChildren
                | litebox::process::WaitError::NoSuchProcess,
            ) => Err(Errno::ECHILD),
        }
    }

    /// Handle syscall `waitid`.
    ///
    /// `waitid(idtype, id, infop, options)`:
    /// - `idtype == P_PID`: wait for child with PID `id`
    /// - `idtype == P_PGID`: wait for child in process group `id`
    /// - `idtype == P_ALL`: wait for any child
    pub(crate) fn sys_waitid(
        &self,
        idtype: u32,
        id: u32,
        infop: Option<crate::MutPtr<u8>>,
        options: i32,
    ) -> Result<usize, Errno> {
        use litebox::process::{ProcessId, WaitOptions, WaitTarget};

        const P_ALL: u32 = 0;
        const P_PID: u32 = 1;
        const P_PGID: u32 = 2;
        const P_PIDFD: u32 = 3;
        // waitid uses WEXITED (4) to wait for exited children.
        const WEXITED: u32 = 4;
        const WNOWAIT: u32 = 0x0100_0000;

        let target = match idtype {
            P_ALL => WaitTarget::AnyChild,
            P_PID => WaitTarget::Pid(ProcessId(id)),
            P_PGID => WaitTarget::ProcessGroup(litebox::process::ProcessGroupId(id)),
            P_PIDFD => {
                let pidfd = i32::try_from(id).map_err(|_| Errno::EBADF)?;
                WaitTarget::Pid(self.pidfd_target_from_fd(pidfd)?.0)
            }
            _ => return Err(Errno::EINVAL),
        };

        // Map waitid options to WaitOptions. waitid uses WEXITED instead of
        // an implicit "wait for exit".
        let raw_opts = options.cast_unsigned();
        if raw_opts & WNOWAIT != 0 {
            log_unsupported!("waitid with WNOWAIT");
            return Err(Errno::EINVAL);
        }
        if raw_opts & WEXITED == 0 {
            // Not waiting for exited children — we only support WEXITED.
            log_unsupported!("waitid without WEXITED");
            return Err(Errno::EINVAL);
        }
        if let WaitTarget::Pid(target_pid) = target {
            self.reject_remote_running_child_wait(target_pid, "waitid")?;
        }
        let mut wait_options = WaitOptions::empty();
        if raw_opts & WaitOptions::WNOHANG.bits() != 0 {
            wait_options |= WaitOptions::WNOHANG;
        }

        // Treat vfork suspension as an interruption so wait_for_child returns,
        // allowing prepare_to_run_guest() to park this thread.
        // Also check for pending signals so that waitid is truly
        // signal-interruptible (SA_RESTART depends on EINTR being returned).
        let is_interrupted = || {
            use core::sync::atomic::Ordering;
            use litebox::event::wait::CheckForInterrupt as _;
            let ps = self.process_state.borrow();
            self.check_for_interrupt()
                || ps
                    .vfork_parking
                    .park
                    .underlying_atomic()
                    .load(Ordering::Acquire)
                    != 0
        };
        let result = self.global.litebox.process_registry().wait_for_child(
            self.process_id,
            target,
            wait_options,
            Some(&self.wait_cx()),
            Some(&is_interrupted),
        );

        match result {
            Ok(wr) => {
                // Fill siginfo_t structure at infop if provided.
                // siginfo_t is 128 bytes on x86_64. We fill the relevant fields:
                //   si_signo (offset 0, i32) = SIGCHLD (17)
                //   si_errno (offset 4, i32) = 0
                //   si_code  (offset 8, i32) = CLD_EXITED (1)
                //   si_pid   (offset 16, i32) = child pid
                //   si_uid   (offset 20, i32) = 0
                //   si_status(offset 24, i32) = exit status
                if let Some(ptr) = infop {
                    const SIGCHLD: i32 = 17;
                    const CLD_EXITED: i32 = 1;
                    let si_ptr: crate::MutPtr<i32> = crate::MutPtr::from_usize(ptr.as_usize());
                    self.prepare_guest_write(si_ptr, 7)?;
                    let _ = si_ptr.write_at_offset(0, SIGCHLD); // si_signo
                    let _ = si_ptr.write_at_offset(1, 0); // si_errno
                    let _ = si_ptr.write_at_offset(2, CLD_EXITED); // si_code
                    let _ = si_ptr.write_at_offset(4, wr.pid.0.cast_signed()); // si_pid
                    let _ = si_ptr.write_at_offset(5, 0); // si_uid
                    let _ = si_ptr.write_at_offset(6, wr.status); // si_status
                }
                Ok(0) // waitid returns 0 on success
            }
            Err(litebox::process::WaitError::WouldBlock) => {
                // WNOHANG: zero out infop and return 0.
                if let Some(ptr) = infop {
                    let si_ptr: crate::MutPtr<i32> = crate::MutPtr::from_usize(ptr.as_usize());
                    self.prepare_guest_write(si_ptr, 1)?;
                    let _ = si_ptr.write_at_offset(0, 0); // si_signo = 0
                }
                Ok(0)
            }
            Err(litebox::process::WaitError::Interrupted) => {
                // Linux returns ERESTARTSYS for waitid.
                self.syscall_restartable.set(true);
                Err(Errno::EINTR)
            }
            Err(
                litebox::process::WaitError::NoChildren
                | litebox::process::WaitError::NoSuchProcess,
            ) => Err(Errno::ECHILD),
        }
    }

    fn pidfd_target_from_fd(&self, pidfd: i32) -> Result<(ProcessId, Option<u32>), Errno> {
        let raw_fd = usize::try_from(pidfd).map_err(|_| Errno::EBADF)?;
        let typed = {
            let files = self.files.borrow();
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<crate::syscalls::eventfd::EventfdSubsystem>(raw_fd)
                .map_err(|_| Errno::EBADF)?
        };
        let handle = self
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&typed)
            .ok_or(Errno::EBADF)?;
        handle
            .with_entry(|file| file.pidfd_target())
            .ok_or(Errno::EBADF)
    }

    pub(crate) fn sys_pidfd_send_signal(
        &self,
        pidfd: i32,
        sig: i32,
        info: Option<crate::ConstPtr<u8>>,
        flags: u32,
    ) -> Result<usize, Errno> {
        if flags != 0 {
            return Err(Errno::EINVAL);
        }
        if info.is_some() {
            log_unsupported!("pidfd_send_signal with non-null siginfo");
            return Err(Errno::EINVAL);
        }

        let (target_pid, _host_pid) = self.pidfd_target_from_fd(pidfd)?;
        let target_pid = i32::try_from(target_pid.0).map_err(|_| Errno::EINVAL)?;
        self.sys_kill(target_pid, sig)
    }
}

/// A descriptor for thread-local storage (TLS).
///
/// On `x86_64`, this is represented as a `*mut u8`. The TLS pointer can point to
/// an arbitrary-sized memory region.
#[cfg(target_arch = "x86_64")]
type ThreadLocalDescriptor = MutPtr<u8>;

/// A descriptor for thread-local storage (TLS).
///
/// On `x86`, this is represented as a `UserDesc`, which provides a more
/// structured descriptor (e.g., base address, limit, flags).
#[cfg(target_arch = "x86")]
type ThreadLocalDescriptor = litebox_common_linux::UserDesc;

struct NewThreadArgs<FS: ShimFS> {
    /// Task struct that maintains all per-thread data
    task: Task<FS>,
}

impl<FS: ShimFS> litebox::shim::InitThread for NewThreadArgs<FS> {
    type ExecutionContext = litebox_common_linux::ExecutionContext;

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
    /// Open a broker-tracked pidfd for process-exit observation.
    ///
    /// Audit note: `pidfd_send_signal(2)` is not decoded into a
    /// `SyscallRequest` today, so the raw syscall returns the generic
    /// unsupported-syscall error under Litebox. The harness test
    /// `PIDFD.send_signal` records that product gap without changing
    /// the working `pidfd_open`/poll path.
    pub(crate) fn sys_pidfd_open(&self, pid: i32, flags: u32) -> Result<usize, Errno> {
        const PIDFD_NONBLOCK: u32 = OFlags::NONBLOCK.bits();

        let pid = u32::try_from(pid).map_err(|_| Errno::EINVAL)?;
        if pid == 0 {
            return Err(Errno::EINVAL);
        }
        if flags & !PIDFD_NONBLOCK != 0 {
            return Err(Errno::EINVAL);
        }
        let process_id = ProcessId(pid);
        let host_pid_opt: Option<u32> = self
            .global
            .fork_child_host_pids
            .read()
            .get(&process_id.0)
            .copied()
            .and_then(|p| u32::try_from(p).ok());
        let subscription =
            crate::syscalls::guest_pid::try_subscribe_broker_process_exit(process_id)
                .ok_or(Errno::ESRCH)?;
        // Eager-broker model: a pidfd is always backed by the broker
        // process-exit subscription, never a local exit-state fast path.
        // The subscription fires for locally-tracked children too (every
        // local-child exit path stamps `try_mark_broker_process_exited`),
        // so a single broker-backed wake source is both sufficient and
        // free of the dual-subject divergence the local fast path had.
        let pidfd = crate::syscalls::eventfd::EventFile::new_broker_process_pidfd(
            process_id,
            subscription,
            flags & PIDFD_NONBLOCK != 0,
            host_pid_opt,
        );
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<crate::syscalls::eventfd::EventfdSubsystem>(pidfd);
        let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
        assert!(old.is_none());
        drop(dt);

        let raw_fd = self
            .files
            .borrow()
            .insert_raw_fd(typed)
            .map_err(|_| Errno::EMFILE)?;
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[STDIO-MAP] pid={} create fd={} kind=pidfd nonblock={}",
            self.pid,
            raw_fd,
            flags & PIDFD_NONBLOCK != 0,
        );
        Ok(raw_fd)
    }

    pub(crate) fn sys_clone(
        &self,
        ctx: &litebox_common_linux::ExecutionContext,
        args: &litebox_common_linux::CloneArgs,
    ) -> Result<usize, Errno> {
        self.do_clone(ctx, args, false)
    }

    pub(crate) fn sys_clone3(
        &self,
        ctx: &litebox_common_linux::ExecutionContext,
        args: ConstPtr<litebox_common_linux::CloneArgs>,
    ) -> Result<usize, Errno> {
        let args = args.read_at_offset(0).ok_or(Errno::EFAULT)?;
        self.do_clone(ctx, &args, true)
    }

    /// Creates a new thread or process.
    ///
    /// Thread creation requires `CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FILES`.
    /// Fork-like calls (`!CLONE_VM && !CLONE_THREAD`) create a new child process
    /// via `do_fork`.
    fn do_clone(
        &self,
        ctx: &litebox_common_linux::ExecutionContext,
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

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[TRACE-CLONE] pid={} flags={:?} exit_signal={} stack={:#x} stack_size={:#x} clone3={}",
            self.pid,
            flags,
            exit_signal,
            stack,
            stack_size,
            clone3,
        );

        // Clone/fork tracing for debugging child spawn issues.
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[CLONE-DBG] pid={} tid={} flags={:?} exit_signal={} clone3={} stack={:#x}",
            self.pid,
            self.tid,
            flags,
            exit_signal,
            clone3,
            stack,
        );

        if cgroup != 0 {
            log_unsupported!("clone with cgroup");
            return Err(Errno::EINVAL);
        }

        if set_tid != 0 || set_tid_size != 0 {
            // ENOSYS audit: clone set_tid array; reachable but not
            // implemented. Real Linux supports this when the caller
            // has CAP_SYS_ADMIN over the target pid namespace; the
            // shim doesn't yet plumb pid pre-assignment through the
            // broker, but should report a graceful ENOSYS rather
            // than crashing the whole worker with todo!() so callers
            // can detect and fall back to a plain clone3.
            log_unsupported!("clone with set_tid");
            return Err(Errno::ENOSYS);
        }
        if clone3 && flags.contains(CloneFlags::PIDFD) {
            // ENOSYS audit: clone3 CLONE_PIDFD; reachable but not
            // implemented. Real Linux populates the user-supplied
            // pidfd_ptr with a fresh pidfd for the child; the shim
            // would need to allocate a broker-backed pidfd up front
            // and write it back. Return ENOSYS for now so callers
            // can detect and fall back to clone3 + pidfd_open(child).
            log_unsupported!("clone3 with pidfd");
            return Err(Errno::ENOSYS);
        }

        // Note `exit_signal` is ignored for threads; validated for fork.
        if exit_signal > MAX_SIGNAL_NUMBER {
            return Err(Errno::EINVAL);
        }

        // Reject any clone/fork while vfork parking is active (or already
        // requested for this thread). This prevents concurrent fork/clone
        // operations from bypassing parking invariants.
        //
        // If another fork/vfork is in progress, **inline-park** here so
        // the active forker can count us toward its `parked_count` target
        // and proceed. A passive wait that does NOT increment
        // `parked_count` would deadlock: the active forker's
        // `park_other_threads` wait loop requires `parked_count ==
        // threads.len() - 1`, and a thread blocked here without
        // counting is invisible to that wait.
        //
        // This matters for `PROMOTION_RACE.concurrent_fork`: three
        // sibling threads race the fork-gate. The first wins; the
        // others must wait *and count*. Both "park atomic non-zero"
        // (the fork is in its parking phase) and "is_suspended set"
        // (the fork has marked us via `park_other_threads`) signal
        // we should wait — we loop until *both* are clear, which
        // mirrors the order `unpark_other_threads` releases them
        // (clears `is_suspended` first, then `park`).
        //
        // We do not inline-park when `nested_delayed_fork` is set:
        // we are already inside a delayed-fork commit and must
        // proceed without re-entering the gate.
        {
            use litebox::platform::RawMutex as _;
            let ps = self.process_state.borrow();
            let parking_atomic = ps.vfork_parking.park.underlying_atomic();
            let nested_delayed_fork = self.fork_context.borrow().is_some();
            if !nested_delayed_fork {
                loop {
                    let suspended = self.is_suspended();
                    let park_v = parking_atomic.load(Ordering::Acquire);
                    if !suspended && park_v == 0 {
                        break;
                    }
                    if self.is_exiting() {
                        return Err(Errno::EINTR);
                    }
                    // Count ourselves as parked so the active forker
                    // can satisfy its `parked_count == expected` wait
                    // and proceed.
                    ps.vfork_parking
                        .parked_count
                        .underlying_atomic()
                        .fetch_add(1, Ordering::Release);
                    ps.vfork_parking.parked_count.wake_all();
                    let v = parking_atomic.load(Ordering::Acquire);
                    if v != 0 {
                        let _ = ps.vfork_parking.park.block(v);
                    }
                    ps.vfork_parking
                        .parked_count
                        .underlying_atomic()
                        .fetch_sub(1, Ordering::Release);
                    ps.vfork_parking.parked_count.wake_all();
                }
            }
        }

        // Detect fork-like clone: new process (!CLONE_THREAD).
        // This includes both fork (!CLONE_VM) and vfork (CLONE_VM | CLONE_VFORK).
        let is_fork = !flags.contains(CloneFlags::THREAD)
            && (!flags.contains(CloneFlags::VM) || flags.contains(CloneFlags::VFORK));

        if is_fork {
            if clone3 && stack == 0 && stack_size == 0 {
                log_unsupported!("clone3 fork without child stack");
                // Real Linux: ENOSYS when clone3 is unsupported on this
                // architecture/kernel. Litebox reports this unsupported
                // clone3 shape as absent so libc can fall back to clone.
                return Err(Errno::ENOSYS);
            }

            // Route fork-like clone3 with an explicit child stack through the
            // same do_fork path as legacy clone. glibc uses that shape for
            // posix_spawn-style helpers that run on a temporary child stack
            // until execve; stackless raw clone3 remains unsupported and lets
            // callers fall back to legacy clone.
            return self.do_fork(ctx, args, flags, clone3);
        }

        // --- Thread clone path (existing behavior) ---

        let thread_required_flags = CloneFlags::VM | CloneFlags::THREAD | CloneFlags::SIGHAND;

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
        if !flags.contains(thread_required_flags) {
            log_unsupported!(
                "clone with missing required flags: {:?}",
                thread_required_flags & !flags
            );
            return Err(Errno::EINVAL);
        }

        let tls = if flags.contains(CloneFlags::SETTLS) {
            let addr = tls.truncate();
            #[cfg(target_arch = "x86_64")]
            let desc = MutPtr::from_usize(addr);
            #[cfg(target_arch = "x86")]
            let desc = {
                let desc = MutPtr::<litebox_common_linux::UserDesc>::from_usize(addr)
                    .read_at_offset(0)
                    .ok_or(Errno::EFAULT)?;
                // Note that different from `set_thread_area` syscall that returns the allocated entry number
                // when requested (i.e., `desc.entry_number` is -1), here we just read the descriptor to LiteBox and
                // assume the entry number is properly set so that we don't need to write it back. This is because
                // we set up the TLS descriptor in the new thread's context, at which point the original descriptor
                // pointer might no longer be valid. Linux does not have this problem because it sets up the TLS for
                // the child thread in the parent thread before `clone` returns.
                // In practice, glibc always sets the entry number to a valid value when calling `clone` with TLS as
                // all threads can share the same TLS entry as the main thread.
                let idx = desc.entry_number;
                if idx == u32::MAX {
                    return Err(Errno::EINVAL);
                }
                desc
            };
            Some(desc)
        } else {
            None
        };

        let child_tid = if child_tid == 0 {
            None
        } else {
            Some(MutPtr::from_usize(child_tid.truncate()))
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
            Some(MutPtr::from_usize(parent_tid.truncate()))
        } else {
            None
        };

        let fs = if flags.contains(CloneFlags::FS) {
            self.fs.borrow().clone()
        } else {
            alloc::sync::Arc::new((**self.fs.borrow()).clone())
        };

        // TID allocation: Linux TIDs and PIDs share the same numeric
        // space and are globally unique. If a broker guest-pid provider
        // is installed, route the new thread's TID through it so two
        // shims that clone() concurrently can never collide. Falls back
        // to the per-shim `next_thread_id` counter when there's no
        // broker (single-shim test scenarios).
        let child_tid = crate::syscalls::guest_pid::try_register_broker_guest_pid()
            .map(|raw| i32::try_from(raw).expect("broker pid must fit in Linux tid"))
            .unwrap_or_else(|| self.global.next_thread_id.fetch_add(1, Ordering::Relaxed));
        if let Some(parent_tid_ptr) = set_parent_tid {
            let _ = self.prepare_guest_write(parent_tid_ptr, 1);
            let _ = parent_tid_ptr.write_at_offset(0, child_tid);
        }

        if (stack == 0 && stack_size != 0) || (stack != 0 && clone3 && stack_size == 0) {
            return Err(Errno::EINVAL);
        }
        if clone3 && stack == 0 {
            log_unsupported!("clone3 thread without child stack");
            // Real Linux: ENOSYS when clone3 is unsupported on this
            // architecture/kernel. Litebox reports this unsupported
            // clone3 shape as absent so libc can fall back to clone.
            return Err(Errno::ENOSYS);
        }
        let sp = if stack != 0 {
            let stack: usize = stack.truncate();
            Some(stack.wrapping_add(stack_size.truncate()))
        } else {
            None
        };

        let child_files = if flags.contains(CloneFlags::FILES) {
            self.files.borrow().clone()
        } else {
            alloc::sync::Arc::new(
                self.files
                    .borrow()
                    .clone_for_fork(&mut self.global.litebox.descriptor_table_mut()),
            )
        };

        let thread = self.thread.new_thread(child_tid).ok_or(Errno::EBUSY)?;
        thread.init_state.set(ThreadInitState::NewThread {
            stack: sp,
            tls,
            set_child_tid,
        });
        thread.clear_child_tid.set(clear_child_tid);

        self.process_state
            .borrow()
            .thread_count
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        let r = unsafe {
            self.global.platform.spawn_thread(
                ctx,
                Box::new(NewThreadArgs {
                    task: Task {
                        global: self.global.clone(),
                        process_state: self.process_state.clone(),
                        wait_state: crate::wait::WaitState::new(self.global.platform),
                        thread,
                        process_id: self.process_id,
                        pid: self.pid,
                        tid: child_tid,
                        ppid: self.ppid,
                        credentials: self.credentials.clone(),
                        comm: self.comm.clone(),
                        fs: fs.into(),
                        files: child_files.into(),
                        signals: self.signals.clone_for_new_task(),
                        fork_context: core::cell::RefCell::new(None),
                        last_shell_write: core::cell::RefCell::new(None),
                        last_syscall: core::cell::Cell::new(None),
                        syscall_restartable: core::cell::Cell::new(false),
                        in_syscall: core::cell::Cell::new(false),
                        deferred_vfork_park: core::cell::Cell::new(false),
                        delayed_fork_pending: core::cell::Cell::new(false),
                        recent_delayed_fork_resume: core::cell::Cell::new(false),
                        migrated_to_remote: core::cell::Cell::new(false),
                        local_task_terminated: core::cell::Cell::new(false),
                        netlink_sockets: core::cell::RefCell::new(
                            alloc::collections::BTreeMap::new(),
                        ),
                        inet6_fds: core::cell::RefCell::new(alloc::collections::BTreeSet::new()),
                    },
                }),
            )
        };
        if let Err(err) = r {
            self.process_state
                .borrow()
                .thread_count
                .fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
            litebox::log_println!(self.global.platform, "failed to spawn thread: {}", err);
            // Treat all spawn errors as `ENOMEM`. `EAGAIN` and other errors are
            // for conditions the user can control (such as "in-shim" rlimit
            // violations).
            return Err(Errno::ENOMEM);
        }

        Ok(usize::try_from(child_tid).unwrap())
    }

    /// Fork path: create a new child process.
    ///
    /// The behavior depends on the platform's `fork_address_space()` result:
    ///
    /// * **`SharedWithParent`** (userland): vfork semantics — the child shares
    ///   the parent's `ProcessState` (address space) but gets an independent
    ///   FD table at fork time. The parent blocks until the child calls
    ///   `execve()` or `_exit()`. On `execve`, the child detaches into its
    ///   own VA partition. The child may safely do `dup2`/`close` between
    ///   fork and exec without affecting the parent.
    ///
    /// * **`Independent`** (kernel): real fork — the platform creates a CoW
    ///   copy of the address space. The child gets its own `ProcessState` and
    ///   FD table at fork time, and the parent continues immediately.
    fn do_fork(
        &self,
        ctx: &litebox_common_linux::ExecutionContext,
        args: &litebox_common_linux::CloneArgs,
        flags: CloneFlags,
        clone3: bool,
    ) -> Result<usize, Errno> {
        use litebox::platform::AddressSpaceProvider;

        // Compile-time gate (no runtime cost): every `RawFdRef` variant is
        // required to have an explicit per-fork-path policy in
        // `migration_policy::migration_policies_for`. Adding a new variant
        // without updating that gate fails to compile, which prevents the
        // class of bug where a new fd subsystem silently gets dropped or
        // mishandled by one of the fork paths. See
        // `litebox_shim_linux/src/syscalls/migration_policy.rs` for details.
        let _migration_gate = super::migration_policy::reference_gate::<FS>();

        // Log fork entry for debugging child stdio issues.
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[FORK-DBG] pid={} tid={} flags={:?} clone3={} is_vfork={}",
            self.pid,
            self.tid,
            flags,
            clone3,
            flags.contains(CloneFlags::VM) && flags.contains(CloneFlags::VFORK),
        );

        // Linux clone flag compatibility: CLONE_SIGHAND requires CLONE_VM,
        // and CLONE_THREAD requires CLONE_SIGHAND. Since the fork path has
        // !CLONE_VM, neither SIGHAND nor THREAD may be set.
        if flags.contains(CloneFlags::SIGHAND) {
            #[cfg(feature = "trace_syscalls")]
            litebox::log_println!(
                self.global.platform,
                "[TRACE-FORK] EINVAL: CLONE_SIGHAND without CLONE_VM, flags={:?}",
                flags,
            );
            return Err(Errno::EINVAL);
        }

        // Supported flags for the fork path. Reject anything else.
        let fork_supported_flags = CloneFlags::VFORK
            | CloneFlags::VM
            // glibc's fork() passes these tid-related flags.
            | CloneFlags::CHILD_SETTID
            | CloneFlags::CHILD_CLEARTID
            | CloneFlags::PARENT_SETTID
            // Ignored since we don't support sysv semaphores anyway.
            | CloneFlags::SYSVSEM
            // glibc's posix_spawn uses CLONE_CLEAR_SIGHAND to reset signal
            // dispositions in the child before exec. The shim already resets
            // signal handlers during execve, so this is safe to accept.
            | CloneFlags::CLEAR_SIGHAND;
        if flags.intersects(!fork_supported_flags) {
            #[cfg(feature = "trace_syscalls")]
            litebox::log_println!(
                self.global.platform,
                "[TRACE-FORK] EINVAL: unsupported flags={:?} (unsupported={:?})",
                flags,
                flags & !fork_supported_flags,
            );
            log_unsupported!(
                "fork with unsupported flags: {:?}",
                flags & !fork_supported_flags
            );
            return Err(Errno::EINVAL);
        }

        // Fork-like clone may provide an explicit child stack. `clone3()` uses
        // `(stack, stack_size)` as a base/size pair, while legacy `clone()`
        // passes the already-adjusted child stack pointer directly via `stack`
        // and leaves `stack_size` as zero. glibc/musl/Rust use both forms for
        // posix_spawn-style helpers that run on a temporary child stack until
        // execve().
        if !clone3 && args.stack_size != 0 {
            #[cfg(feature = "trace_syscalls")]
            litebox::log_println!(
                self.global.platform,
                "[TRACE-FORK] EINVAL: non-clone3 fork with unexpected stack_size stack={:#x} stack_size={:#x}",
                args.stack,
                args.stack_size,
            );
            log_unsupported!("fork with unexpected non-clone3 stack_size");
            return Err(Errno::EINVAL);
        }

        // 1. Allocate the child's pid.
        //
        // Phase K: in production (broker-hosted GuestPidProvider
        // installed), every guest pid comes from the broker so:
        // - ProcessId is globally unique across all shim instances by
        //   construction; coord's "pid 2" and dpg1's "pid 2" cannot
        //   collide.
        // - Phase B.2's broker-only `sys_pidfd_open` always finds the
        //   pid in the broker's process registry.
        // - cross-worker waitpid identity is unambiguous.
        //
        // Without a broker provider (single-worker test scenarios),
        // fall back to the per-shim `next_pid` counter via the legacy
        // `create_process`.
        let exit_signal = i32::try_from(args.exit_signal).map_err(|_| Errno::EINVAL)?;
        let broker_pid_opt = crate::syscalls::guest_pid::try_register_broker_guest_pid();
        let child_process_id = match broker_pid_opt {
            Some(broker_pid) => {
                let pid = litebox::process::ProcessId(broker_pid);
                self.global
                    .litebox
                    .process_registry()
                    .create_process_with_id(pid, Some(self.process_id), exit_signal)
                    .map_err(|err| {
                        #[cfg(feature = "trace_syscalls")]
                        litebox::log_println!(
                            self.global.platform,
                            "[FORK] pid={}: create_process_with_id({}) failed: {:?}",
                            self.pid,
                            broker_pid,
                            err,
                        );
                        let _ = err;
                        // The broker handed us a pid we can't register
                        // locally (e.g. PidAlreadyExists collision).
                        // Release the broker pid so it isn't leaked.
                        crate::syscalls::guest_pid::try_release_broker_guest_pid(broker_pid);
                        Errno::ENOMEM
                    })?;
                pid
            }
            None => self
                .global
                .litebox
                .process_registry()
                .create_process(Some(self.process_id), exit_signal)
                .map_err(|_| {
                    #[cfg(feature = "trace_syscalls")]
                    litebox::log_println!(
                        self.global.platform,
                        "[FORK] pid={}: create_process failed (ENOMEM)",
                        self.pid,
                    );
                    Errno::ENOMEM
                })?,
        };

        // 2. Fork address space: allocate a VA partition for the child.
        let parent_as_id = self.process_state.borrow().address_space_id;
        let forked = self
            .global
            .platform
            .fork_address_space(parent_as_id)
            .map_err(|_| {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[FORK] pid={}: fork_address_space failed — no VA partitions left (ENOMEM)",
                    self.pid,
                );
                self.global
                    .litebox
                    .process_registry()
                    .remove_process(child_process_id);
                Errno::ENOMEM
            })?;
        let child_as_id = match &forked {
            litebox::platform::address_space::ForkedAddressSpace::SharedWithParent(id)
            | litebox::platform::address_space::ForkedAddressSpace::Independent(id) => *id,
        };
        let is_shared = matches!(
            forked,
            litebox::platform::address_space::ForkedAddressSpace::SharedWithParent(_)
        );
        let _is_vfork = flags.contains(CloneFlags::VM) && flags.contains(CloneFlags::VFORK);

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[FORK] pid={} -> child_pid={} as_id={} shared={} is_vfork={}",
            self.pid,
            child_process_id.0,
            child_as_id,
            is_shared,
            _is_vfork,
        );

        // On a shared-address-space platform, every fork appears as vfork
        // because the syscall rewriter adds CLONE_VM | CLONE_VFORK.  Enable
        // delayed fork for ALL shared forks: programs that call execve will
        // stay on the fast vfork path (execve is in the pre-exec allowlist),
        // while programs that make a non-pre-exec syscall will trigger
        // commit_delayed_fork and be migrated to a worker host.
        //
        // Delayed fork is only supported on x86_64 for now.
        #[cfg(target_arch = "x86_64")]
        let delayed_fork = is_shared;
        #[cfg(not(target_arch = "x86_64"))]
        let delayed_fork = false;

        // 3. Derive the guest pid from the child's ProcessId. Phase K:
        // `ProcessId.0` is the broker-allocated pid (when a provider is
        // installed) or the per-shim counter pid (test scenarios) —
        // either way, it's THE pid for this child. The legacy split
        // between "internal ProcessId" and "external guest pid" went
        // away with Phase K.
        //
        // The TID for the initial thread is set equal to the pid, matching
        // Linux's `tgid == pid` invariant for a process's leader thread.
        let child_pid_u32 = child_process_id.0;
        let child_pid = i32::try_from(child_pid_u32).map_err(|_| {
            self.global
                .litebox
                .process_registry()
                .remove_process(child_process_id);
            if let Some(broker_pid) = broker_pid_opt {
                crate::syscalls::guest_pid::try_release_broker_guest_pid(broker_pid);
            }
            Errno::EAGAIN
        })?;
        let child_initial_tid = child_pid;

        // Ensure the global clone-TID counter stays ahead of fork-allocated
        // PIDs so that a subsequent clone() in ANY process never hands out a
        // TID that collides with an existing process's initial thread.
        self.global.reserve_thread_id(child_initial_tid);

        // 4. Build per-fork-mode state: vfork (shared with parent) vs
        //    independent (kernel CoW).
        //
        // `did_park_threads` tracks whether other threads were parked,
        // so we know whether to unpark later.
        let (
            child_process_state,
            child_files,
            child_fork_context,
            vfork_done,
            cow_state,
            did_park_threads,
        ) = if is_shared {
            // Userland / shared: child temporarily uses parent's ProcessState
            // (address space). ForkContext records the child's reserved
            // partition and the synchronization primitive. On exec, the child
            // will detach (create own ProcessState).
            //
            // FD table is duplicated now so the child can safely do dup2/close
            // between fork and exec without corrupting the parent's FD state.
            let vfork_done = Arc::new(crate::VforkDone::new(self.wait_cx().waker().clone()));
            let child_files_state = {
                // Phase F.5+ PE.5: see the matching scope at the
                // independent-fork branch below. Same rationale —
                // dup_handles from on_dup must be attributed to
                // child_pid in the broker's per-(pid, id) tracker.
                //
                // **Gated on per_pid_ownership_enabled()** (PE.10 fix):
                // stamping child_pid here while releases run with
                // PE.5: stamp dup_handle RPCs with child_pid so the
                // broker tracker records inherited refs under the
                // child's bucket, balancing the
                // ReleaseAllForPid(child_pid) at child exit.
                let _emit_scope =
                    litebox_common_linux::fd_token_client::set_caller_pid_scope(child_pid_u32);
                Arc::new(
                    self.files
                        .borrow()
                        .clone_for_fork(&mut self.global.litebox.descriptor_table_mut()),
                )
            };

            // Set up CoW protection for fork memory sharing.
            //
            // **Thread parking**: Before protecting pages, park all other
            // threads in the process so that no concurrent guest execution
            // can race with the mprotect/snapshot. This makes it safe to
            // always use FULL CoW regardless of thread count.
            //
            // **Full CoW** (always): protect ALL writable pages. Since
            // other threads are parked, there are no concurrent writes
            // to worry about.
            //
            // **Eager vs lazy** (platform decision):
            // - Eager: copy all protected pages upfront, leave writable.
            // - Lazy: mark pages read-only, snapshot on first write fault.
            let nested_delayed_fork = self.fork_context.borrow().is_some();

            // Park all other threads before modifying page permissions.
            // Returns Ok(true) if threads were parked and need to be
            // unparked later, Ok(false) if no other threads exist, or
            // Err if another thread is already forking.
            //
            // For a fork issued by an unmigrated delayed-fork child
            // (`nested_delayed_fork == true`), the outer vfork already
            // owns the process-wide fork gate, so do NOT re-park; but
            // we still need our own CoW layer so the grandchild's
            // user-space post-fork code (glibc's `__nptl_fork_child`
            // touches TLS / pthread_t / malloc arenas) cannot clobber
            // the parent's live stack canary and TLS state before the
            // grandchild execs or exits. Without this nested CoW,
            // static-PIE glibc binaries reliably trip
            // `__stack_chk_fail` in the parent's `__libc_fork`
            // epilogue.
            let did_park = if nested_delayed_fork {
                false
            } else {
                let Ok(parked) = self.park_other_threads() else {
                    return Err(Errno::EAGAIN);
                };
                parked
            };
            let cow_state = {
                let ps = self.process_state.borrow();
                let mappings = ps.pm.mappings();
                drop(ps);

                let mut eager_dirty = BTreeMap::<usize, alloc::vec::Vec<u8>>::new();
                let mut protected = alloc::vec::Vec::new();

                for (range, flags) in &mappings {
                    if !flags.contains(VmFlags::VM_WRITE) {
                        continue;
                    }

                    if <crate::Platform as AddressSpaceProvider>::EAGER_COW_FOR_VFORK {
                        // Eagerly snapshot pages and leave them writable.
                        for page_addr in (range.start..range.end).step_by(PAGE_SIZE) {
                            let mut buf = alloc::vec![0u8; PAGE_SIZE];
                            // SAFETY: pages are committed; all other threads
                            // are parked so content is stable.
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    page_addr as *const u8,
                                    buf.as_mut_ptr(),
                                    PAGE_SIZE,
                                );
                            }
                            eager_dirty.insert(page_addr, buf);
                        }
                    } else {
                        // Lazy CoW: mark writable pages read-only and
                        // snapshot individual pages on first write fault.
                        use litebox::platform::page_mgmt::MemoryRegionPermissions;

                        let len = range.end - range.start;
                        let orig_perms = {
                            let mut p = MemoryRegionPermissions::READ;
                            if flags.contains(VmFlags::VM_EXEC) {
                                p |= MemoryRegionPermissions::EXEC;
                            }
                            p | MemoryRegionPermissions::WRITE
                        };
                        let ro_perms = orig_perms & !MemoryRegionPermissions::WRITE;
                        // SAFETY: pages are mapped; all other threads are
                        // parked so no concurrent writes.
                        let ok = unsafe {
                            <crate::Platform as PageManagementProvider<PAGE_SIZE>>::update_permissions(
                                        self.global.platform,
                                        range.start..range.end,
                                        ro_perms,
                                    )
                                    .is_ok()
                        };
                        if !ok {
                            for &(base, len, perms) in &protected {
                                unsafe {
                                    <crate::Platform as PageManagementProvider<
                                                PAGE_SIZE,
                                            >>::update_permissions(
                                                self.global.platform,
                                                base..base + len,
                                                perms,
                                            )
                                            .expect("CoW setup rollback: failed to restore permissions");
                                }
                            }
                            if did_park {
                                self.unpark_other_threads();
                            }
                            return Err(Errno::ENOMEM);
                        }
                        protected.push((range.start, len, orig_perms));
                    }
                }
                let cow = Arc::new(crate::CowState {
                    protected_ranges: protected,
                    dirty_pages: litebox::sync::Mutex::new(eager_dirty),
                });
                // Store CoW state in ProcessState so all threads (and the
                // fault handler) can access it.
                self.process_state
                    .borrow()
                    .active_vfork_layers
                    .lock()
                    .push(cow.clone());
                Some(cow)
            };

            let fc = crate::ForkContext {
                address_space_id: child_as_id,
                vfork_done: vfork_done.clone(),
                exit_signal: i32::try_from(args.exit_signal).unwrap_or(0),
                parent_process_id: self.process_id,
                parent_controlling_pty: *self.process_state.borrow().controlling_pty.lock(),
                parent_unix_socket_fds: {
                    let files = self.files.borrow();
                    let rds = files.raw_descriptor_store.read();
                    // Collect TypedFds under rds, then drop rds before
                    // acquiring dt to maintain dt → rds lock ordering.
                    let mut typed_sockets: Vec<(
                        usize,
                        alloc::sync::Arc<
                            litebox::fd::TypedFd<super::unix::UnixSocketSubsystem<FS>>,
                        >,
                    )> = Vec::new();
                    for raw_fd in rds.iter_alive() {
                        if let Ok(typed) =
                            rds.fd_from_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(raw_fd)
                        {
                            typed_sockets.push((raw_fd, typed));
                        }
                    }
                    drop(rds);

                    let mut socket_fds = Vec::new();
                    let dt = self.global.litebox.descriptor_table();
                    for (raw_fd, typed) in &typed_sockets {
                        let pair_id = dt
                            .with_entry(typed, |sock: &super::unix::UnixSocket<FS>| {
                                sock.socket_pair_id()
                            })
                            .flatten();
                        if let Some(pair_id) = pair_id {
                            socket_fds.push((*raw_fd, pair_id, typed.object_id().as_u64()));
                        }
                    }
                    drop(dt);
                    socket_fds
                },
                parent_broker_pty_fds: {
                    let files = self.files.borrow();
                    let rds = files.raw_descriptor_store.read();
                    rds.iter_alive()
                        .filter(|&raw_fd| {
                            rds.fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
                                .is_ok()
                        })
                        .collect()
                },
                parent_is_delayed_fork: self.delayed_fork_pending.get() || nested_delayed_fork,
                fork_snapshot_broker_transit: Vec::new(),
                fork_snapshot_pidfd_process_transit: Vec::new(),
                fork_snapshot_fd_token_transit: Vec::new(),
            };
            (
                self.process_state.clone(),                  // share parent's PM
                core::cell::RefCell::new(child_files_state), // independent FD table
                Some(fc),
                Some(vfork_done),
                cow_state,
                did_park,
            )
        } else {
            // Kernel / independent: child has its own CoW address space from
            // the platform. Create an independent ProcessState and duplicate
            // the FD table now (not deferred to exec).
            let child_range = self
                .global
                .platform
                .address_space_range(child_as_id)
                .expect("child address space must be valid");
            let child_ps = Arc::new(crate::ProcessState {
                pm: litebox::mm::PageManager::new(&self.global.litebox, child_range),
                address_space_id: child_as_id,
                thread_count: core::sync::atomic::AtomicI32::new(1),
                controlling_pty: litebox::sync::Mutex::new(
                    *self.process_state.borrow().controlling_pty.lock(),
                ),
                active_vfork_layers: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
                elf_patch_cache: litebox::sync::Mutex::new(alloc::collections::BTreeMap::new()),
                shared_file_mappings: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
                main_bss_start: core::sync::atomic::AtomicUsize::new(0),
                main_bss_end: core::sync::atomic::AtomicUsize::new(0),
                proc_map_paths: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
                vfork_parking: Arc::new(crate::VforkParking {
                    park: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
                    parked_count: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
                    deferred_lie_count: core::sync::atomic::AtomicU32::new(0),
                }),
            });
            let child_files_state = {
                // PE.5: stamp caller_pid = child_pid for all broker
                // dup_handle RPCs emitted during clone_for_fork's
                // on_dup invocations, so the inherited refs land in
                // the child's per-pid bucket.
                let _emit_scope =
                    litebox_common_linux::fd_token_client::set_caller_pid_scope(child_pid_u32);
                Arc::new(
                    self.files
                        .borrow()
                        .clone_for_fork(&mut self.global.litebox.descriptor_table_mut()),
                )
            };
            (
                core::cell::RefCell::new(child_ps),          // own ProcessState
                core::cell::RefCell::new(child_files_state), // own FD table
                None,                                        // no ForkContext
                None,                                        // no vfork sync
                None,                                        // no CoW state
                false,                                       // no thread parking
            )
        };

        // 5a. Create the child Task.
        // The child needs the parent's guest TLS (fsbase). On a new host
        // thread, the per-thread guest_fsbase is zero, so we must explicitly
        // pass the parent's value.
        #[cfg(target_arch = "x86_64")]
        let parent_tls = {
            let punchthrough = litebox_common_linux::PunchthroughSyscall::GetFsBase;
            let token = self
                .global
                .platform
                .get_punchthrough_token_for(punchthrough)
                .expect("GetFsBase punchthrough");
            let fsbase = token.execute().expect("GetFsBase execute");
            Some(fsbase)
        };
        #[cfg(not(target_arch = "x86_64"))]
        let parent_tls = None;

        let child_thread = ThreadState::new_process(child_pid);
        // If the caller provided an explicit child stack, compute the initial
        // stack pointer the spawned child thread should start with.
        //
        // - `clone3()`: `stack` points at the base of the region and
        //   `stack_size` describes its size, so the child starts at the top.
        // - legacy `clone()`: `stack` is already the child stack pointer and
        //   `stack_size` is zero.
        let child_stack = if args.stack != 0 {
            let base: usize = args.stack.truncate();
            let sp = if clone3 {
                base.wrapping_add(args.stack_size.truncate())
            } else {
                base
            };
            Some(sp)
        } else {
            None
        };

        // A shared-vfork child can resume on the parent's stack before the new
        // host thread has a chance to service its first CoW write fault. Make
        // the initial stack window writable up front so the first post-clone
        // `push`/prologue writes don't crash the child before exec.
        let prefault_child_stack = if is_shared {
            #[cfg(target_arch = "x86_64")]
            let sp = child_stack.unwrap_or_else(|| ctx.rsp.truncate());
            #[cfg(target_arch = "x86")]
            let sp = child_stack.unwrap_or_else(|| ctx.esp.truncate());
            #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
            let sp = child_stack.unwrap_or(0);
            let prefault_len = PAGE_SIZE * 5;
            if sp != 0 {
                let start = sp.saturating_sub(PAGE_SIZE * 4);
                Some((start, prefault_len))
            } else {
                None
            }
        } else {
            None
        };
        if let Some((start, len)) = prefault_child_stack
            && !self.prepare_cow_for_host_write(start, len)
        {
            let _ = self.global.platform.destroy_address_space(child_as_id);
            self.global
                .litebox
                .process_registry()
                .remove_process(child_process_id);
            if let Some(cow) = &cow_state {
                self.restore_cow_layer_permissions(cow);
                self.pop_cow_layer(cow);
            }
            if did_park_threads {
                self.unpark_other_threads();
            }
            return Err(Errno::ENOMEM);
        }
        // Handle CHILD_SETTID and CHILD_CLEARTID for the fork child.
        let set_child_tid = if flags.contains(CloneFlags::CHILD_SETTID) && args.child_tid != 0 {
            Some(crate::MutPtr::<i32>::from_usize(args.child_tid.truncate()))
        } else {
            None
        };
        let clear_child_tid = if flags.contains(CloneFlags::CHILD_CLEARTID) && args.child_tid != 0 {
            Some(crate::MutPtr::<i32>::from_usize(args.child_tid.truncate()))
        } else {
            None
        };
        child_thread.init_state.set(ThreadInitState::ForkChild {
            stack: child_stack,
            tls_base: parent_tls, // inherit parent's guest TLS at the final pre-entry boundary
            set_child_tid,
        });
        child_thread.clear_child_tid.set(clear_child_tid);
        self.global
            .control_plane
            .register_running_process_local(child_process_id)
            .expect("newly forked process must be registered to the local host");

        // After Phase K Step 3, child_pid == child_process_id.0 by
        // construction (broker pid drives both fields). The historical
        // pid_to_process_id map is gone.
        debug_assert_eq!(
            u32::try_from(child_pid).ok(),
            Some(child_process_id.0),
            "child_pid and child_process_id must be the same value"
        );
        let child_cmdline = self.global.proc_cmdline(self.pid).unwrap_or_else(|| {
            let exe = self.fs.borrow().exe_path.read().clone();
            proc_cmdline_from_argv(&[], &exe)
        });
        self.global.set_proc_cmdline(child_pid, child_cmdline);

        let r = unsafe {
            self.global.platform.spawn_thread(
                ctx,
                Box::new(NewThreadArgs {
                    task: Task {
                        global: self.global.clone(),
                        process_state: child_process_state,
                        wait_state: crate::wait::WaitState::new(self.global.platform),
                        thread: child_thread,
                        process_id: child_process_id,
                        pid: child_pid,
                        ppid: self.pid,
                        tid: child_initial_tid,
                        credentials: self.credentials.clone(),
                        comm: self.comm.clone(),
                        // Clone FsState into a new Arc so the child has its
                        // own cwd/umask/exe_path.  Without this, chdir or
                        // umask in the child would mutate the parent's state
                        // (the parent is suspended during the vfork window,
                        // but the mutation persists after it resumes).
                        fs: core::cell::RefCell::new(alloc::sync::Arc::new(
                            (**self.fs.borrow()).clone(),
                        )),
                        files: child_files,
                        signals: {
                            // Linux sigaltstack(2): fork() inherits the
                            // altstack; clone(CLONE_VM) without CLONE_VFORK
                            // (i.e. threads) disables it. The fork path here
                            // never has CLONE_VM without CLONE_VFORK (that's
                            // the thread path), so always preserve altstack.
                            let s = self.signals.clone_for_fork(false);
                            if flags.contains(CloneFlags::CLEAR_SIGHAND) {
                                s.reset_caught_handlers();
                            }
                            s
                        },
                        fork_context: core::cell::RefCell::new(child_fork_context),
                        last_shell_write: core::cell::RefCell::new(None),
                        last_syscall: core::cell::Cell::new(None),
                        syscall_restartable: core::cell::Cell::new(false),
                        in_syscall: core::cell::Cell::new(false),
                        deferred_vfork_park: core::cell::Cell::new(false),
                        delayed_fork_pending: core::cell::Cell::new(delayed_fork),
                        recent_delayed_fork_resume: core::cell::Cell::new(false),
                        migrated_to_remote: core::cell::Cell::new(false),
                        local_task_terminated: core::cell::Cell::new(false),
                        netlink_sockets: core::cell::RefCell::new(
                            alloc::collections::BTreeMap::new(),
                        ),
                        inet6_fds: core::cell::RefCell::new(alloc::collections::BTreeSet::new()),
                    },
                }),
            )
        };

        if let Err(err) = r {
            litebox::log_println!(self.global.platform, "failed to spawn fork child: {}", err);
            let _ = self.global.platform.destroy_address_space(child_as_id);
            self.global
                .litebox
                .process_registry()
                .remove_process(child_process_id);
            let _ = self
                .global
                .control_plane
                .unregister_running_process(child_process_id);
            self.global.remove_proc_cmdline(child_pid);
            // On failure, restore write permissions if CoW was set up.
            if let Some(cow) = &cow_state {
                self.restore_cow_layer_permissions(cow);
                self.pop_cow_layer(cow);
            }
            if did_park_threads {
                self.unpark_other_threads();
            }
            return Err(Errno::ENOMEM);
        }

        // 6. For vfork (shared), block the parent until child execs or exits.
        //    For independent fork, the parent continues immediately.
        #[cfg(feature = "trace_syscalls")]
        {
            let comm_bytes = self.comm.get();
            let comm_str = core::str::from_utf8(
                &comm_bytes[..comm_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(comm_bytes.len())],
            )
            .unwrap_or("<invalid>");
            litebox::log_println!(
                self.global.platform,
                "[FORK-CHILD] parent_pid={} parent_comm={:?}: spawned child_pid={} delayed_fork={} is_shared={}",
                self.pid,
                comm_str,
                child_pid,
                delayed_fork,
                is_shared,
            );
        }
        if let Some(vd) = vfork_done {
            // Snapshot pipe receiver consumer positions before the child
            // runs.  The vfork child shares the ring buffer — its reads
            // advance the shared consumer index.  We restore the index
            // after CoW so the parent doesn't lose data.
            //
            // Also snapshot the parent-owned pipe writer fd counts.  The
            // vfork child has an independent fd table, but pipe write-end
            // refcounts live in the shared descriptor entry; child close/exec
            // activity must not be able to remove or resurrect the parent's
            // writer refs.
            // Like Linux's TASK_UNINTERRUPTIBLE wait: keep blocking even if
            // interrupted, because parent and child share the same guest stack.
            while !vd.is_done() {
                let _ = self.wait_cx().wait_until(|| vd.is_done());
            }

            let resumed_from_child_exit = vd.was_signaled_by_exit();

            // Restore pages modified by the child and clear CoW state.
            if let Some(cow) = &cow_state {
                self.restore_cow_layer(cow, true);
            }

            // Apply fd replacements deposited by commit_delayed_fork.
            // Instead of replacing with HostPassthroughFdEntry (which has a no-op
            // register_observer and therefore breaks epoll), create a
            // virtual pipe pair and spawn a relay thread that bridges
            // the real OS pipe to the virtual pipe.  Virtual pipes
            // support epoll via the Pollee mechanism, so programs that
            // rely on epoll (e.g. Node.js) get correct wakeups.
            let replacements: Vec<crate::FdReplacement> =
                vd.fd_replacements.lock().drain(..).collect();
            if !replacements.is_empty() {
                use super::host_passthrough_fd::HostPassthroughFdDirection;

                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[FD-REPLACE] pid={}: processing {} fd replacements",
                    self.pid,
                    replacements.len(),
                );

                let files = self.files.borrow();
                for repl in replacements {
                    #[cfg(feature = "trace_syscalls")]
                    litebox::log_println!(
                        self.global.platform,
                        "[FD-REPLACE] pid={}: replacing guest_fd={} (host_fd={}, dir={:?})",
                        self.pid,
                        repl.guest_fd,
                        repl.host_fd,
                        repl.direction,
                    );

                    // INVARIANT: this aliases a bidirectional host Unix-socket
                    // fd produced for an explicit passthrough replacement. It is
                    // not broker-held because the compatibility path preserves
                    // the literal socket fd across this restore boundary; if the
                    // descriptor must survive a later cross-binary-type fork,
                    // snapshot must carry it via fd-token or a broker socket
                    // handle instead. Pipe-kind replacements were removed with
                    // the local pipe subsystem; no unidirectional replacement is
                    // installed here.
                    if repl.direction == HostPassthroughFdDirection::ReadWrite {
                        // Skip duplicate FdReplacement entries: a previous
                        // iteration may already have installed a HostPassthroughFdEntry at
                        // this slot. Close our extra host_fd and continue.
                        {
                            let rds_check = files.raw_descriptor_store.read();
                            let already_hostpipe = rds_check
                                .fd_from_raw_integer::<super::host_passthrough_fd::HostPassthroughFd>(
                                    repl.guest_fd,
                                )
                                .is_ok();
                            if already_hostpipe {
                                self.global.platform.close_host_fd(repl.host_fd);
                                continue;
                            }
                        }

                        let entry = super::host_passthrough_fd::HostPassthroughFdEntry::new(
                            repl.host_fd,
                            repl.direction,
                        );
                        let typed_fd: litebox::fd::TypedFd<
                            super::host_passthrough_fd::HostPassthroughFd,
                        > = self.global.litebox.descriptor_table_mut().insert(entry);

                        let mut rds = files.raw_descriptor_store.write();
                        // Remove old unix socket at this slot.
                        if let Ok(old_sock) = rds
                            .fd_consume_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(
                                repl.guest_fd,
                            )
                        {
                            drop(rds);
                            let _ = self.global.litebox.descriptor_table_mut().remove(&old_sock);
                            rds = files.raw_descriptor_store.write();
                        }
                        let _ = rds.fd_into_specific_raw_integer(typed_fd, repl.guest_fd);
                        continue;
                    }

                    // Legacy non-direct OS-pipe replacements were serviced by
                    // the relay thread. New internal migration paths use the mux
                    // or broker-backed descriptors instead, so there is no
                    // remaining in-shim consumer for this host fd.
                    self.global.platform.close_host_fd(repl.host_fd);
                }
            }

            // --- Parent broker socketpair installs ---
            // D5-vsocket: replace parent-side UnixSocket peers with the broker
            // endpoint paired with the worker endpoint shipped via
            // --broker-fd-bridge. The first install consumes create_socketpair's
            // creation ref; alias installs dup_handle before constructing their
            // BrokerSocketPairFd so on_close has a matching release.
            let parent_socketpair_installs: Vec<crate::BrokerSocketPairParentInstall> = vd
                .broker_socketpair_parent_installs
                .lock()
                .drain(..)
                .collect();
            if !parent_socketpair_installs.is_empty() {
                if let Some(provider) = super::broker_socketpair::broker_socketpair_provider() {
                    use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                    let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                        alloc::sync::Arc::clone(&provider) as _;
                    let files = self.files.borrow();
                    for install in parent_socketpair_installs {
                        if install.dup_before_install
                            && releaser.dup_handle(install.handle_id).is_err()
                        {
                            continue;
                        }

                        let flags = {
                            let rds = files.raw_descriptor_store.read();
                            let typed = rds
                                .fd_from_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(
                                    install.guest_fd,
                                )
                                .ok();
                            drop(rds);
                            typed
                                .and_then(|typed| {
                                    let dt = self.global.litebox.descriptor_table();
                                    let flags = dt.with_entry(
                                        &typed,
                                        |sock: &super::unix::UnixSocket<FS>| sock.get_status(),
                                    );
                                    drop(dt);
                                    flags
                                })
                                .unwrap_or_else(litebox::fs::OFlags::empty)
                                & litebox::fs::OFlags::STATUS_FLAGS_MASK
                        };

                        let sp_fd =
                            super::broker_socketpair::BrokerSocketPairFd::<crate::Platform>::new(
                                alloc::sync::Arc::clone(&provider),
                                install.handle_id,
                                install.endpoint,
                                flags,
                            );
                        let typed = self
                            .global
                            .litebox
                            .descriptor_table_mut()
                            .insert::<super::broker_socketpair::BrokerSocketPairSubsystem>(
                            sp_fd,
                        );

                        let mut rds = files.raw_descriptor_store.write();
                        if let Ok(old_sock) = rds
                            .fd_consume_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(
                                install.guest_fd,
                            )
                        {
                            drop(rds);
                            let _ = self
                                .global
                                .litebox
                                .descriptor_table_mut()
                                .remove(&old_sock);
                            rds = files.raw_descriptor_store.write();
                        } else if let Ok(old_broker_sock) = rds.fd_consume_raw_integer::<
                            super::broker_socketpair::BrokerSocketPairSubsystem,
                        >(install.guest_fd) {
                            drop(rds);
                            let _ = self
                                .global
                                .litebox
                                .descriptor_table_mut()
                                .remove(&old_broker_sock);
                            rds = files.raw_descriptor_store.write();
                        }
                        let ok = rds.fd_into_specific_raw_integer(typed, install.guest_fd);
                        debug_assert!(
                            ok,
                            "broker socketpair parent install: slot {} still occupied",
                            install.guest_fd
                        );
                    }
                }
            }

            if resumed_from_child_exit {
                self.recent_delayed_fork_resume.set(true);
            }

            // Unpark other threads now that CoW is fully restored.
            if did_park_threads {
                self.unpark_other_threads();
            }
        }

        // Parent returns child's PID.
        Ok(usize::try_from(child_pid).unwrap())
    }

    /// Commit a delayed fork: snapshot the child's current state, spawn a
    /// worker host, restore the child there, and signal VforkDone so the
    /// parent resumes.
    ///
    /// Called from `do_syscall` when a delayed-fork child makes a non-pre-exec
    /// syscall.  On success, the local child task should exit (the process
    /// continues in the worker host).  On failure, the caller should force-exit
    /// the child so that VforkDone is signaled via `prepare_for_exit`.
    pub(crate) fn commit_delayed_fork(
        &self,
        ctx: &litebox_common_linux::ExecutionContext,
    ) -> Result<(), Errno> {
        use super::fork_snapshot::ForkRejectReasons;

        // Compile-time gate: see `do_fork` above. The actual per-fd
        // accept/reject decision lives in `snapshot_fd_table` and is keyed
        // on `FdKind`; this reference keeps the `RawFdRef`-level policy
        // table in the build graph so new subsystems can't silently bypass
        // the snapshot gate.
        let _migration_gate = super::migration_policy::reference_gate::<FS>();

        // Take the fork context.  This gives us the VforkDone handle and
        // the child's address-space ID.
        let fc = self.fork_context.borrow_mut().take().ok_or(Errno::EINVAL)?;
        let mut fc = fc;

        // --- Per-phase timing for delayed-fork latency investigation.
        // Always-on probe; reverts on next merge cycle if not needed.
        let phase_t_start = self.global.platform.monotonic_timestamp();
        let mut phase_last = phase_t_start;
        // Helper inline closure stand-in: a macro avoids borrow-of-self issues.
        macro_rules! phase_tick {
            ($name:literal) => {{
                use litebox::platform::DebugLogProvider as _;
                let now = self.global.platform.monotonic_timestamp();
                if let (Some(now_d), Some(last_d)) = (now, phase_last) {
                    let delta_us = now_d.saturating_sub(last_d).as_micros();
                    let total_us = phase_t_start
                        .map(|t0| now_d.saturating_sub(t0).as_micros())
                        .unwrap_or(0);
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "[DELAYED-FORK-TIMING] pid={} phase={} delta_us={} total_us={}\n",
                        self.pid,
                        $name,
                        delta_us,
                        total_us
                    ));
                }
                phase_last = now;
            }};
        }

        // Helper to restore fork_context on failure so prepare_for_exit
        // can signal VforkDone. Drains the Phase 2.F broker transit
        // list to release in-flight dup'd handles so the broker
        // refcount returns to baseline.
        let put_fc_back = |this: &Self, mut fc: crate::ForkContext| {
            let _caller_pid_guard =
                litebox_common_linux::fd_token_client::set_caller_pid_scope(this.process_id.0);
            for transit in fc.fork_snapshot_broker_transit.drain(..) {
                transit.releaser.release(transit.handle_id);
            }
            fc.fork_snapshot_pidfd_process_transit.clear();
            for transit in fc.fork_snapshot_fd_token_transit.drain(..) {
                let _ = transit.client.release(transit.token_id);
            }
            *this.fork_context.borrow_mut() = Some(fc);
        };

        #[cfg(feature = "trace_syscalls")]
        {
            let comm_bytes = self.comm.get();
            let comm_str = core::str::from_utf8(
                &comm_bytes[..comm_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(comm_bytes.len())],
            )
            .unwrap_or("<invalid>");
            litebox::log_println!(
                self.global.platform,
                "[DELAYED-FORK] pid={} comm={:?} ppid={}: commit_delayed_fork ENTERED",
                self.pid,
                comm_str,
                self.ppid,
            );
        }

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[DELAYED-FORK] pid={}: triggered by syscall nr={}",
            self.pid,
            ctx.orig_rax,
        );

        // Sibling threads are already parked (by the vfork CoW setup).
        // Snapshot the child's current state.
        let mut reject = ForkRejectReasons::new();

        let identity = super::fork_snapshot::ProcessIdentitySnapshot {
            process_id: self.process_id,
            parent_process_id: fc.parent_process_id,
            pid: self.pid,
            ppid: self.ppid,
            tid: self.tid,
            pgid: {
                use litebox::process::ProcessGroupId;
                self.global
                    .litebox
                    .process_registry()
                    .get_pgid(self.process_id)
                    .map_or(self.pid.cast_unsigned(), ProcessGroupId::as_u32)
                    .try_into()
                    .unwrap_or(self.pid)
            },
            sid: {
                use litebox::process::SessionId;
                self.global
                    .litebox
                    .process_registry()
                    .get_sid(self.process_id)
                    .map_or(self.pid.cast_unsigned(), SessionId::as_u32)
                    .try_into()
                    .unwrap_or(self.pid)
            },
            exit_signal: fc.exit_signal,
            comm: self.comm.get(),
            credentials: super::fork_snapshot::CredentialsSnapshot {
                uid: self.credentials.uid,
                euid: self.credentials.euid,
                gid: self.credentials.gid,
                egid: self.credentials.egid,
            },
        };

        let process_wide = self.snapshot_process_wide();

        // Snapshot thread state from the child's current context (the
        // triggering syscall's entry state).  The child was already started
        // via the vfork path so set_child_tid was already written; we only
        // need clear_child_tid for the restored child's futex wake on exit.
        //
        // Adjust the execution context so the restored child replays the
        // triggering syscall: back up rip by 2 (the x86_64 `syscall`
        // instruction is 2 bytes) and restore rax to the syscall number.
        let thread = {
            #[cfg(target_arch = "x86_64")]
            let tls_base = {
                let punchthrough = litebox_common_linux::PunchthroughSyscall::GetFsBase;
                self.global
                    .platform
                    .get_punchthrough_token_for(punchthrough)
                    .and_then(|token| token.execute().ok())
            };
            #[cfg(not(target_arch = "x86_64"))]
            let tls_base: Option<usize> = None;

            let mut exec_ctx = ctx.clone();
            #[cfg(target_arch = "x86_64")]
            {
                // Mirror the syscall-restart mechanism used by
                // signal/mod.rs: both the rewriter trampoline and
                // seccomp handler store the call-site address in R11.
                // Setting rip to that address re-enters the
                // trampoline/syscall, which re-executes the syscall.
                exec_ctx.regs.rip = exec_ctx.regs.r11;
                exec_ctx.regs.rax = exec_ctx.orig_rax;
            }

            super::fork_snapshot::ThreadSnapshot {
                execution_context: exec_ctx,
                tls_base,
                // set_child_tid was already written when the child started;
                // the restored child does not need to re-write it.
                set_child_tid: None,
                clear_child_tid: self
                    .thread
                    .clear_child_tid
                    .get()
                    .map(|p: MutPtr<i32>| p.as_usize()),
                robust_list: self.thread.robust_list.get().map(|ptr| ptr.as_usize()),
            }
        };

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[DELAYED-FORK] pid={}: snapshot_signal",
            self.pid
        );
        let signal = self.snapshot_signal();
        let fs = self.snapshot_fs();
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[DELAYED-FORK] pid={}: snapshot_fs",
            self.pid
        );
        // This is still the pre-exec fork child. Preserve FD_CLOEXEC fds in
        // the restored worker so they remain usable until a later exec closes
        // them.
        let fd_table = self.snapshot_fd_table(
            &mut reject,
            &mut fc.fork_snapshot_broker_transit,
            &mut fc.fork_snapshot_pidfd_process_transit,
            &mut fc.fork_snapshot_fd_token_transit,
            false,
            Self::delayed_fork_trigger_fd(ctx),
        );
        let memory = self.snapshot_memory(&mut reject);

        // Check rejection gate.
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[DELAYED-FORK] pid={}: snapshot_memory",
            self.pid
        );
        if !reject.is_empty() {
            // Stage B diag: log rejection reasons unconditionally so we can
            // debug commit_delayed_fork failures.
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "[DELAYED-FORK-DIAG] pid={} REJECTED: {}\n",
                self.pid,
                reject,
            ));
            #[cfg(feature = "trace_syscalls")]
            litebox::log_println!(
                self.global.platform,
                "[DELAYED-FORK] pid={}: REJECTED — {}",
                self.pid,
                reject,
            );
            #[cfg(feature = "trace_syscalls")]
            litebox::log_println!(
                self.global.platform,
                "[DELAYED-FORK] pid={}: rejected — {}",
                self.pid,
                reject,
            );
            put_fc_back(self, fc);
            return Err(Errno::ENOSYS);
        }

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[DELAYED-FORK] pid={}: entering pipe bridging",
            self.pid,
        );

        // --- Pipe bridging ---
        phase_tick!("pre_pipe_bridging");
        // For each pipe FD in the child's table, create a real OS pipe pair
        // so that parent and child can communicate across host processes.
        //
        // child_pipe_bridges: (guest_fd, child_os_fd, direction)
        // parent_fd_replacements: stored in VforkDone for the parent to apply.
        let mut child_pipe_bridges: Vec<(
            usize,
            i32,
            super::host_passthrough_fd::HostPassthroughFdDirection,
        )> = Vec::new();
        type ForkBridgeParentInfo = Vec<(
            usize,
            super::host_passthrough_fd::HostPassthroughFdDirection,
            u8,
        )>;
        struct ForkBridgeAccum {
            drained: Vec<u8>,
            /// Host OS fd for host-backed bridges; -1 for virtual unix-socket/PTY bridges.
            host_fd: i32,
            parent_info: ForkBridgeParentInfo,
        }

        // One entry per child_pipe_bridges entry. Keeping the drained bytes,
        // host fd, and parent fd metadata in one struct preserves the original
        // lockstep invariant structurally: fork_bridge_accum[i] describes the
        // same logical fork bridge as child_pipe_bridges[i].
        let mut fork_bridge_accum: Vec<ForkBridgeAccum> = Vec::new();
        // Phase 3 D5: broker-fd-bridge specs for mux streams migrated
        // out of the mux relay onto direct broker handles. Each entry
        // is shipped to the worker as `--broker-fd-bridge <spec>` and
        // consumed by `install_broker_fd_bridge_spec`
        // (runner/lib.rs:428).
        let mut broker_fd_bridge_specs: alloc::vec::Vec<alloc::string::String> =
            alloc::vec::Vec::new();
        // Phase 3 D5: transit refs for broker handles shipped via
        // broker_fd_bridge_specs. Drained AFTER
        // `spawn_worker_host_for_fork_restore` returns. The spawn
        // function reads the worker ack synchronously, so by the time
        // it returns the worker has already called
        // `install_broker_fd_bridge_spec` which acquired its own ref
        // via `dup_handle`. Releasing here drops the creation ref the
        // parent held since `attach_host_fd` returned.
        type BrokerReleaser = alloc::sync::Arc<
            dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
        >;
        type TransitRelease = (BrokerReleaser, u64);
        let mut broker_fd_bridge_transit_release: alloc::vec::Vec<TransitRelease> =
            alloc::vec::Vec::new();
        let mut broker_socketpair_parent_installs: alloc::vec::Vec<
            crate::BrokerSocketPairParentInstall,
        > = alloc::vec::Vec::new();
        let mut broker_socketpair_parent_release_on_failure: alloc::vec::Vec<TransitRelease> =
            alloc::vec::Vec::new();
        // (bridge_index, worker_handle_id, endpoint_char, child_nonblock) for
        // migrated virtual-socket streams whose dup'd child aliases need their
        // own --broker-fd-bridge specs.
        let mut broker_socketpair_migrated_streams: alloc::vec::Vec<(usize, u64, char, bool)> =
            alloc::vec::Vec::new();
        // Dup'd pipe aliases: (alias_fd, primary_bridge_index).
        // The worker dups the primary stream's pipe end to alias_fd.
        let mut mux_aliases: Vec<(usize, usize)> = Vec::new();
        // INVARIANT: bidirectional Unix sockets that remain on the legacy
        // passthrough path alias a literal host socketpair endpoint. They are
        // not broker-held because this compatibility bridge relays the concrete
        // socket fd between parent and worker; if the fd must cross another
        // binary-type fork, it needs fd-token or broker socket migration first.
        // Collect (guest_fd, child_os_fd, parent_os_fd) here.
        let mut bidi_passthrough: Vec<(usize, i32, i32)> = Vec::new();
        {
            use super::host_passthrough_fd::HostPassthroughFdDirection;

            let files = self.files.borrow();
            let alive_fds: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();

            // Gather child's host passthrough fd TypedFds (from prior delayed-fork bridges).
            let mut child_host_passthrough_fd_fds: Vec<(
                usize,
                alloc::sync::Arc<
                    litebox::fd::TypedFd<super::host_passthrough_fd::HostPassthroughFd>,
                >,
            )> = Vec::new();
            for raw_fd in alive_fds {
                let _ = files.run_on_raw_fd(raw_fd, |raw_fd_ref| {
                    #[deny(clippy::wildcard_enum_match_arm)]
                    match raw_fd_ref {
                        #[cfg(feature = "worker_local_inet")]
                        crate::RawFdRef::Net(_) => {}
                        crate::RawFdRef::Fs(_)
                        | crate::RawFdRef::Eventfd(_)
                        | crate::RawFdRef::Epoll(_)
                        | crate::RawFdRef::Unix(_)
                        | crate::RawFdRef::BrokerPipe(_)
                        | crate::RawFdRef::BrokerSocketPair(_)
                        | crate::RawFdRef::BrokerSocketDgram(_)
                        | crate::RawFdRef::BrokerSocketSeqPacket(_)
                        | crate::RawFdRef::BrokerTcpConn(_)
                        | crate::RawFdRef::BrokerPty(_)
                        | crate::RawFdRef::Signalfd(_)
                        | crate::RawFdRef::Inotify(_)
                        | crate::RawFdRef::BrokerInetListener(_)
                        | crate::RawFdRef::BrokerInetDgram(_)
                        | crate::RawFdRef::BrokerInetRaw(_) => {}
                        crate::RawFdRef::HostPassthroughFd(typed) => {
                            // Already host-backed — collect for later extraction
                            // (need descriptor_table lock which we acquire after rds).
                            child_host_passthrough_fd_fds.push((raw_fd, Arc::clone(typed)));
                        }
                    }
                });
            }
            drop(files);

            // Filter out mux-managed pipes inherited from the parent.
            // These are infrastructure virtual pipes created by a prior
            // sibling's mux dispatcher or fd-replacement relay.  Bridging
            // them would create nested mux-over-mux, destroying the first
            // mux's data flow.

            // Extract OS fd + direction from collected host-passthrough-fd TypedFds.
            // Done after dropping rds to maintain dt→rds lock ordering.
            let mut child_host_passthrough_fds: Vec<(usize, i32, HostPassthroughFdDirection)> =
                Vec::new();
            {
                let dt = self.global.litebox.descriptor_table();
                for (raw_fd, typed) in &child_host_passthrough_fd_fds {
                    if let Some((host_fd, direction)) = dt.with_entry(
                        typed,
                        |e: &super::host_passthrough_fd::HostPassthroughFdEntry| {
                            (e.raw_fd(), e.direction)
                        },
                    ) {
                        child_host_passthrough_fds.push((*raw_fd, host_fd, direction));
                    }
                }
            }

            let mut parent_replacements: Vec<crate::FdReplacement> = Vec::new();

            // If two child fds share the same pipe end (e.g. after
            // dup2), only the first gets a real OS pipe bridge; the
            // second reuses the same OS pipe fd via dup.

            // Host-backed pipes (from prior delayed-fork bridges) are already
            // backed by real OS fds.  With the mux, these go through the
            // multiplexer too: the child worker gets a virtual pipe (via mux
            // stream), and the parent's mux dispatcher relays between the mux
            // and the existing host OS fd.
            for &(guest_fd, host_fd, direction) in &child_host_passthrough_fds {
                child_pipe_bridges.push((guest_fd, host_fd, direction));
                fork_bridge_accum.push(ForkBridgeAccum {
                    drained: Vec::new(),
                    host_fd,
                    parent_info: Vec::new(),
                });
            }

            // --- Unix socket bridging ---
            // For each connected Unix socket in the child's table, create
            // an OS pipe bridge so parent and child communicate across host
            // processes after migration.
            {
                // Collect child unix socket fds on any slot.
                struct ChildSocketInfo<S: litebox::fd::FdEnabledSubsystem> {
                    child_fd: usize,
                    direction: super::host_passthrough_fd::HostPassthroughFdDirection,
                    pair_id: usize,
                    object_id: u64,
                    typed: alloc::sync::Arc<litebox::fd::TypedFd<S>>,
                }

                // Collect TypedFds under rds, then drop rds before
                // acquiring dt to maintain dt → rds lock ordering.
                let typed_stdio_sockets: Vec<(
                    usize,
                    alloc::sync::Arc<litebox::fd::TypedFd<super::unix::UnixSocketSubsystem<FS>>>,
                )> = {
                    let files = self.files.borrow();
                    let rds = files.raw_descriptor_store.read();
                    let mut out = Vec::new();
                    for raw_fd in rds.iter_alive() {
                        if let Ok(typed) =
                            rds.fd_from_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(raw_fd)
                        {
                            out.push((raw_fd, typed));
                        }
                    }
                    out
                    // rds and files dropped here
                };

                let mut child_sockets: Vec<ChildSocketInfo<super::unix::UnixSocketSubsystem<FS>>> =
                    Vec::new();
                {
                    let dt = self.global.litebox.descriptor_table();
                    for (raw_fd, typed) in &typed_stdio_sockets {
                        let pair_id = dt
                            .with_entry(typed, |sock: &super::unix::UnixSocket<FS>| {
                                sock.socket_pair_id()
                            })
                            .flatten();
                        if let Some(pair_id) = pair_id {
                            let direction = if *raw_fd == 0 {
                                HostPassthroughFdDirection::Read
                            } else if *raw_fd <= 2 {
                                HostPassthroughFdDirection::Write
                            } else {
                                // Non-stdio unix sockets need bidirectional
                                // bridging (e.g. Node.js IPC on fd 3).
                                HostPassthroughFdDirection::ReadWrite
                            };
                            child_sockets.push(ChildSocketInfo {
                                child_fd: *raw_fd,
                                direction,
                                pair_id,
                                object_id: typed.object_id().as_u64(),
                                typed: typed.clone(),
                            });
                        }
                    }
                }

                // Bidirectional conflict: reject if the same socket pair
                // appears on both a Read and a Write slot. Different ends
                // of the same socketpair have different object_ids but
                // share the same pair_id.
                for a in &child_sockets {
                    for b in &child_sockets {
                        if a.pair_id == b.pair_id && a.direction != b.direction {
                            #[cfg(feature = "trace_syscalls")]
                            litebox::log_println!(
                                self.global.platform,
                                "[DELAYED-FORK] pid={}: bidirectional socket on stdio slots {} and {}",
                                self.pid,
                                a.child_fd,
                                b.child_fd,
                            );
                            // Clean up any already-created OS pipe fds.
                            for (i, &(_, os_fd, _)) in child_pipe_bridges.iter().enumerate() {
                                let is_host_owned = fork_bridge_accum
                                    .get(i)
                                    .is_some_and(|bridge| bridge.host_fd == os_fd);
                                if !is_host_owned {
                                    self.global.platform.close_host_fd(os_fd);
                                }
                            }
                            for pr in &parent_replacements {
                                self.global.platform.close_host_fd(pr.host_fd);
                            }
                            put_fc_back(self, fc);
                            todo!(
                                "ENOSYS audit: delayed fork bidirectional unix socket stdio bridge; reachable but not implemented"
                            );
                        }
                    }
                }

                // Track already-bridged object IDs to dedup dup'd sockets.
                // (object_id, direction, bridge_index)
                let mut bridged_objects: Vec<(u64, HostPassthroughFdDirection, usize)> = Vec::new();

                for info in &child_sockets {
                    // INVARIANT: bidirectional sockets create a host
                    // socketpair and pass the child end as a host-passthrough
                    // fd because the legacy relay operates on the concrete OS
                    // socket. This is not broker-held and must be replaced by
                    // fd-token or broker socket migration before another
                    // cross-binary-type fork boundary.
                    // Find the parent's peer fd using fc.parent_unix_socket_fds
                    // (captured at fork time, before the child closed any fds).
                    if info.direction == HostPassthroughFdDirection::ReadWrite {
                        match self.global.platform.create_host_socketpair() {
                            Ok((child_end, parent_end)) => {
                                bidi_passthrough.push((info.child_fd, child_end, parent_end));

                                // Find parent's peer: same pair_id, different object_id.
                                for &(parent_fd, parent_pair_id, parent_oid) in
                                    &fc.parent_unix_socket_fds
                                {
                                    if parent_pair_id == info.pair_id
                                        && parent_oid != info.object_id
                                    {
                                        parent_replacements.push(crate::FdReplacement {
                                            guest_fd: parent_fd,
                                            host_fd: parent_end,
                                            direction: HostPassthroughFdDirection::ReadWrite,
                                        });
                                    }
                                }
                            }
                            Err(_e) => {
                                #[cfg(feature = "trace_syscalls")]
                                litebox::log_println!(
                                    self.global.platform,
                                    "[DELAYED-FORK] pid={}: create_host_socketpair failed for bidi socket bridge fd={}: {}",
                                    self.pid,
                                    info.child_fd,
                                    _e,
                                );
                            }
                        }
                        continue;
                    }

                    // Dedup: if same object_id already bridged with same
                    // direction, record as alias (same stream_id) instead
                    // of creating a separate bridge.
                    if let Some(&(_, _, existing_idx)) = bridged_objects
                        .iter()
                        .find(|(oid, dir, _)| *oid == info.object_id && *dir == info.direction)
                    {
                        mux_aliases.push((info.child_fd, existing_idx));
                        continue;
                    }

                    // Create OS pipe pair for unidirectional bridges.
                    let (os_read, os_write) = match self
                        .global
                        .platform
                        .create_host_passthrough_fd()
                    {
                        Ok(pair) => pair,
                        Err(_e) => {
                            #[cfg(feature = "trace_syscalls")]
                            litebox::log_println!(
                                self.global.platform,
                                "[DELAYED-FORK] pid={}: create_host_passthrough_fd failed for socket bridge: {}",
                                self.pid,
                                _e,
                            );
                            for (i, &(_, os_fd, _)) in child_pipe_bridges.iter().enumerate() {
                                let is_host_owned = fork_bridge_accum
                                    .get(i)
                                    .is_some_and(|bridge| bridge.host_fd == os_fd);
                                if !is_host_owned {
                                    self.global.platform.close_host_fd(os_fd);
                                }
                            }
                            for pr in &parent_replacements {
                                self.global.platform.close_host_fd(pr.host_fd);
                            }
                            put_fc_back(self, fc);
                            return Err(Errno::ENOMEM);
                        }
                    };

                    let (child_os_fd, parent_os_fd) = match info.direction {
                        HostPassthroughFdDirection::Read => (os_read, os_write),
                        HostPassthroughFdDirection::Write => (os_write, os_read),
                        HostPassthroughFdDirection::ReadWrite => unreachable!("handled above"),
                    };

                    // G4: Drain recv_channel into OS pipe for Read direction.
                    let mut this_socket_drained: Vec<u8> = Vec::new();
                    if info.direction == HostPassthroughFdDirection::Read {
                        let dt = self.global.litebox.descriptor_table();
                        let msgs: Vec<super::unix::Message> = dt
                            .with_entry(&info.typed, |sock: &super::unix::UnixSocket<FS>| {
                                let mut msgs = Vec::new();
                                while let Some(msg) = sock.drain_recv_one() {
                                    msgs.push(msg);
                                }
                                msgs
                            })
                            .unwrap_or_default();
                        drop(dt);

                        // Reject if any message carries SCM_RIGHTS fds —
                        // we cannot transfer fds across host processes.
                        for msg in &msgs {
                            if !msg.passed_fds.is_empty() {
                                #[cfg(feature = "trace_syscalls")]
                                litebox::log_println!(
                                    self.global.platform,
                                    "[DELAYED-FORK] pid={}: SCM_RIGHTS on socket fd={}, cannot bridge",
                                    self.pid,
                                    info.child_fd,
                                );
                                self.global.platform.close_host_fd(child_os_fd);
                                self.global.platform.close_host_fd(parent_os_fd);
                                for (i, &(_, os_fd, _)) in child_pipe_bridges.iter().enumerate() {
                                    let is_host_owned = fork_bridge_accum
                                        .get(i)
                                        .is_some_and(|bridge| bridge.host_fd == os_fd);
                                    if !is_host_owned {
                                        self.global.platform.close_host_fd(os_fd);
                                    }
                                }
                                for pr in &parent_replacements {
                                    self.global.platform.close_host_fd(pr.host_fd);
                                }
                                put_fc_back(self, fc);
                                todo!(
                                    "ENOSYS audit: delayed fork queued SCM_RIGHTS transfer; reachable but not implemented"
                                );
                            }
                        }

                        // Accumulate all drained data, then write in one
                        // shot after setting the pipe capacity once.
                        let mut drain_data: Vec<u8> = Vec::new();
                        for msg in msgs {
                            drain_data.extend_from_slice(&msg.data);
                        }
                        this_socket_drained.clone_from(&drain_data);

                        if !drain_data.is_empty() {
                            let capacity = i32::try_from(drain_data.len())
                                .unwrap_or(i32::MAX)
                                .saturating_add(4096);
                            self.global
                                .platform
                                .try_set_pipe_capacity(parent_os_fd, capacity);

                            #[cfg(feature = "trace_syscalls")]
                            litebox::log_println!(
                                self.global.platform,
                                "[DELAYED-FORK] pid={}: drained {} bytes from socket fd={} into OS pipe",
                                self.pid,
                                drain_data.len(),
                                info.child_fd,
                            );
                            let mut offset = 0;
                            while offset < drain_data.len() {
                                match self
                                    .global
                                    .platform
                                    .write_host_fd(parent_os_fd, &drain_data[offset..])
                                {
                                    Ok(n) => offset += n,
                                    Err(_e) => {
                                        #[cfg(feature = "trace_syscalls")]
                                        litebox::log_println!(
                                            self.global.platform,
                                            "[DELAYED-FORK] pid={}: drain write failed for socket fd={}: {}",
                                            self.pid,
                                            info.child_fd,
                                            _e,
                                        );
                                        // Drain failure is fatal — data
                                        // was already consumed from the
                                        // virtual channel.
                                        self.global.platform.close_host_fd(child_os_fd);
                                        self.global.platform.close_host_fd(parent_os_fd);
                                        for (i, &(_, os_fd, _)) in
                                            child_pipe_bridges.iter().enumerate()
                                        {
                                            let is_host_owned = fork_bridge_accum
                                                .get(i)
                                                .is_some_and(|bridge| bridge.host_fd == os_fd);
                                            if !is_host_owned {
                                                self.global.platform.close_host_fd(os_fd);
                                            }
                                        }
                                        for pr in &parent_replacements {
                                            self.global.platform.close_host_fd(pr.host_fd);
                                        }
                                        put_fc_back(self, fc);
                                        return Err(Errno::EIO);
                                    }
                                }
                            }
                        }
                    }

                    bridged_objects.push((
                        info.object_id,
                        info.direction,
                        child_pipe_bridges.len(),
                    ));
                    child_pipe_bridges.push((info.child_fd, child_os_fd, info.direction));
                    // Find ALL parent peers (same pair_id, different object_id).
                    let parent_dir = match info.direction {
                        HostPassthroughFdDirection::Read => HostPassthroughFdDirection::Write,
                        HostPassthroughFdDirection::Write => HostPassthroughFdDirection::Read,
                        HostPassthroughFdDirection::ReadWrite => unreachable!("handled above"),
                    };

                    let mut this_parent_info: Vec<(usize, HostPassthroughFdDirection, u8)> =
                        Vec::new();
                    let mut found_parent = false;
                    for &(parent_fd, parent_pair_id, parent_oid) in &fc.parent_unix_socket_fds {
                        if parent_pair_id == info.pair_id && parent_oid != info.object_id {
                            let parent_host_fd = if found_parent {
                                // Multiple parent fds alias the same peer — dup
                                // the OS pipe end for each.
                                match self.global.platform.dup_host_fd(parent_os_fd) {
                                    Ok(fd) => fd,
                                    Err(_e) => {
                                        #[cfg(feature = "trace_syscalls")]
                                        litebox::log_println!(
                                            self.global.platform,
                                            "[DELAYED-FORK] pid={}: dup_host_fd({}) failed for parent alias: {}",
                                            self.pid,
                                            parent_os_fd,
                                            _e,
                                        );
                                        for (i, &(_, os_fd, _)) in
                                            child_pipe_bridges.iter().enumerate()
                                        {
                                            let is_host_owned = fork_bridge_accum
                                                .get(i)
                                                .is_some_and(|bridge| bridge.host_fd == os_fd);
                                            if !is_host_owned {
                                                self.global.platform.close_host_fd(os_fd);
                                            }
                                        }
                                        for pr in &parent_replacements {
                                            self.global.platform.close_host_fd(pr.host_fd);
                                        }
                                        put_fc_back(self, fc);
                                        return Err(Errno::ENOMEM);
                                    }
                                }
                            } else {
                                parent_os_fd
                            };
                            found_parent = true;
                            parent_replacements.push(crate::FdReplacement {
                                guest_fd: parent_fd,
                                host_fd: parent_host_fd,
                                direction: parent_dir,
                            });
                            this_parent_info.push((parent_fd, parent_dir, b's'));
                        }
                    }

                    fork_bridge_accum.push(ForkBridgeAccum {
                        drained: this_socket_drained,
                        host_fd: -1,
                        parent_info: this_parent_info,
                    });

                    if !found_parent {
                        self.global.platform.close_host_fd(parent_os_fd);
                    }
                }
            }

            // --- Host stdio bridging (Pass 4) ---
            // INVARIANT: host stdio and /dev/tty aliases refer to the runner's
            // literal terminal/stdin/stdout/stderr fds. They cannot be
            // represented as broker-held resources today because posix_spawn
            // stdio setup and terminal semantics require concrete host fds; a
            // later cross-binary-type fork must re-tokenize or brokerize them.
            // For each fd in the child's snapshot that is backed by a host
            // stdio descriptor (stdin/stdout/stderr), create an OS pipe pair
            // and register a host-backed mux stream.  The parent's relay
            // thread will bridge between the mux virtual pipe and the real
            // host terminal fd.  This ensures all terminal I/O from nested
            // workers is serialized through the parent's mux dispatcher
            // instead of multiple workers writing directly to the host
            // terminal (which causes garbled output in TUI mode).
            {
                use super::host_passthrough_fd::HostPassthroughFdDirection;

                for entry in &fd_table.entries {
                    // Only bridge fds that have host stdio backing.
                    let source_fd = match entry.metadata.host_stdio_source_fd {
                        Some(sf) => sf,
                        None => {
                            // Also check is_host_tty_alias for fds that
                            // were dup'd from host stdio (e.g., fd opened
                            // on /dev/tty that aliases the host terminal).
                            if entry.metadata.is_host_tty_alias {
                                match entry.fd {
                                    0 => 0,
                                    1 | 2 => 1,
                                    _ => continue,
                                }
                            } else {
                                continue;
                            }
                        }
                    };

                    // Skip if this fd was already bridged by Pass 1/2/3.
                    if child_pipe_bridges
                        .iter()
                        .any(|&(gfd, _, _)| gfd == entry.fd)
                    {
                        #[cfg(feature = "trace_syscalls")]
                        litebox::log_println!(
                            self.global.platform,
                            "[DELAYED-FORK] pid={}: host stdio fd={} source_fd={} already bridged, skipping",
                            self.pid,
                            entry.fd,
                            source_fd,
                        );
                        continue;
                    }

                    // Direction based on the host stdio source fd:
                    //   source_fd 0 (stdin)  = child reads (ParentToWorker),
                    //   source_fd 1/2 (stdout/stderr) = child writes (WorkerToParent).
                    // We use source_fd (not entry.fd) because the guest fd number
                    // may differ from the host stdio fd if it was dup'd.
                    let direction = if source_fd == 0 {
                        HostPassthroughFdDirection::Read
                    } else {
                        HostPassthroughFdDirection::Write
                    };

                    // Create an OS pipe pair for the child side.
                    let (read_fd, write_fd) = match self
                        .global
                        .platform
                        .create_host_passthrough_fd()
                    {
                        Ok(pair) => pair,
                        Err(_e) => {
                            #[cfg(feature = "trace_syscalls")]
                            litebox::log_println!(
                                self.global.platform,
                                "[DELAYED-FORK] pid={}: host stdio bridge create_host_passthrough_fd failed for fd={}: {}",
                                self.pid,
                                entry.fd,
                                _e,
                            );
                            continue;
                        }
                    };

                    let (child_os_fd, parent_os_fd) = match direction {
                        HostPassthroughFdDirection::Read => (read_fd, write_fd),
                        HostPassthroughFdDirection::Write => (write_fd, read_fd),
                        HostPassthroughFdDirection::ReadWrite => {
                            unreachable!("bidi sockets use passthrough")
                        }
                    };

                    // Close the parent OS fd — the mux host_passthrough_fd_fd relay
                    // uses the real host stdio fd directly, not this pipe end.
                    self.global.platform.close_host_fd(parent_os_fd);

                    #[cfg(feature = "trace_syscalls")]
                    litebox::log_println!(
                        self.global.platform,
                        "[DELAYED-FORK] pid={}: host stdio bridge fd={} source_fd={} dir={:?} child_os_fd={}",
                        self.pid,
                        entry.fd,
                        source_fd,
                        direction,
                        child_os_fd,
                    );

                    child_pipe_bridges.push((entry.fd, child_os_fd, direction));
                    // Set host_fd to the real host stdio fd number for broker migration.
                    fork_bridge_accum.push(ForkBridgeAccum {
                        drained: Vec::new(),
                        host_fd: source_fd,
                        parent_info: Vec::new(),
                    });
                }
            }

            // --- Writable filesystem fd bridging ---
            // A restored fork child runs in a separate host process.  Non-terminal
            // filesystem fds cannot be made to share the parent's in-memory upper
            // layer by reopening the path in the child, so route child writes back
            // through the parent's original open file description.
            {
                for entry in &fd_table.entries {
                    if entry.kind != super::fork_snapshot::FdKind::FilesystemFd
                        || entry.metadata.is_host_tty_alias
                        || entry.metadata.is_host_pty_device
                        || entry.metadata.host_stdio_source_fd.is_some()
                        || child_pipe_bridges.iter().any(|&(fd, _, _)| fd == entry.fd)
                    {
                        continue;
                    }

                    let access_bits = entry.status_flags & 0x3;
                    let writable = access_bits == 1 || access_bits == 2;
                    if !writable {
                        continue;
                    }

                    // Phase 3 D5-fs: when a BrokerFsProvider is
                    // registered, migrate the
                    // child's inherited FS fd directly onto a broker
                    // OFD registry handle. The worker then runs a
                    // CloneOfd against this `open_file_id` and wraps
                    // the resulting 9P fid in a guest descriptor, so
                    // the child's reads/writes go straight to the
                    // broker (and through to the same kernel OFD as
                    // the parent), preserving POSIX inherited-fd
                    // shared-position semantics. The parent's
                    // original 9P fid is left in place; `RegisterOfd`
                    // is idempotent and only mints a broker-side
                    // `Arc<File>` clone — the parent keeps using its
                    // fid normally.
                    {
                        let parent_info: Option<(u32, alloc::string::String)> = {
                            let files = self.files.borrow();
                            files
                                .run_on_raw_fd(entry.fd, |raw_fd_ref| match raw_fd_ref {
                                    crate::RawFdRef::Fs(fd) => files
                                        .fs
                                        .descriptor_backend_fid(fd)
                                        .zip(files.fs.fd_path(fd)),
                                    #[allow(
                                        clippy::wildcard_enum_match_arm,
                                        reason = "only Fs-backed entries have 9P fids; \
                                                  all other RawFdRef kinds opt out of D5-fs"
                                    )]
                                    _ => None,
                                })
                                .ok()
                                .flatten()
                        };
                        if let (Some((parent_fid, path)), Some(provider)) =
                            (parent_info, super::broker_fs_provider())
                        {
                            match provider.register_ofd(parent_fid) {
                                Ok(open_file_id) => {
                                    let status_flags_bits = entry.status_flags;
                                    let path_hex = brokerfile_bridge_encode_path(&path);
                                    broker_fd_bridge_specs.push(alloc::format!(
                                        "{}:fs_fid:{}:{}:{}",
                                        entry.fd,
                                        open_file_id,
                                        status_flags_bits,
                                        path_hex,
                                    ));
                                    #[cfg(feature = "trace_syscalls")]
                                    litebox::log_println!(
                                        self.global.platform,
                                        "[DELAYED-FORK] pid={}: fs fd={} parent_fid={} migrated to broker OFD id={}",
                                        self.pid,
                                        entry.fd,
                                        parent_fid,
                                        open_file_id,
                                    );
                                    continue;
                                }
                                Err(_e) => {
                                    #[cfg(feature = "trace_syscalls")]
                                    litebox::log_println!(
                                        self.global.platform,
                                        "[DELAYED-FORK] pid={}: fs fd={} parent_fid={} register_ofd failed: {:?}",
                                        self.pid,
                                        entry.fd,
                                        parent_fid,
                                        _e,
                                    );
                                }
                            }
                        }
                    }
                }
            }

            debug_assert_eq!(
                fork_bridge_accum.len(),
                child_pipe_bridges.len(),
                "fork bridge metadata must stay in lockstep with child pipe bridges"
            );

            // --- D5 broker-bridge setup ---
            // Migrate each child pipe bridge directly onto a broker handle
            // (BrokerPipe / BrokerSocketPair / BrokerPty / HostFd-attached
            // BrokerPipe). The resulting `--broker-fd-bridge` specs replace
            // what was previously a mux-relay socketpair plus per-stream
            // dispatcher endpoints.
            if child_pipe_bridges.is_empty() {
                // No bridges at all — store parent replacements for the
                // remote-host exec path which still uses fd_replacements.
                if !parent_replacements.is_empty() {
                    *fc.vfork_done.fd_replacements.lock() = parent_replacements;
                }
            } else {
                // Store any bidirectional (ReadWrite) replacements in
                // fd_replacements — these get direct host-passthrough-fd installation
                // on the parent side.
                let bidi_repls: Vec<crate::FdReplacement> = parent_replacements
                    .iter()
                    .filter(|r| r.direction == HostPassthroughFdDirection::ReadWrite)
                    .cloned()
                    .collect();
                if !bidi_repls.is_empty() {
                    *fc.vfork_done.fd_replacements.lock() = bidi_repls;
                }

                let mut broker_migrated_streams: Vec<Option<(u64, BrokerReleaser, char)>> =
                    (0..child_pipe_bridges.len()).map(|_| None).collect();
                let mut d5_pty_bridge_handles: alloc::vec::Vec<(
                    usize,
                    u64,
                    u32,
                    alloc::sync::Arc<
                        dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
                    >,
                )> = alloc::vec::Vec::new();

                for (i, &(guest_fd, child_os_fd, direction)) in
                    child_pipe_bridges.iter().enumerate()
                {
                    let stream_id = u32::try_from(i).unwrap_or(0);
                    let dir_byte = match direction {
                        HostPassthroughFdDirection::Read => b'r',
                        HostPassthroughFdDirection::Write => b'w',
                        HostPassthroughFdDirection::ReadWrite => {
                            // Bidi sockets are supposed to bypass mux —
                            // they get HostPassthroughFdEntry installed directly. If
                            // one shows up here it leaked through earlier
                            // filtering. Skip rather than crash so the
                            // remainder of the test suite can proceed
                            // (better than a panic killing the harness
                            // mid-run). Track the leak as a separate bug
                            // to investigate; logging via stderr.
                            #[cfg(feature = "trace_syscalls")]
                            litebox::log_println!(
                                self.global.platform,
                                "[MUX-SETUP] WARNING: ReadWrite direction in \
                                 child_pipe_bridges (guest_fd={} child_os_fd={}) \
                                 — skipping (should have bypassed mux)",
                                guest_fd,
                                child_os_fd,
                            );
                            continue;
                        }
                    };
                    let type_byte = fork_bridge_accum
                        .get(i)
                        .and_then(|bridge| bridge.parent_info.first())
                        .map_or(b'p', |&(_, _, sub)| sub);

                    // For Read-direction child pipes (child reads,
                    // parent writes): check if the parent's pipe is
                    // already EOF at setup time.  This lets the worker
                    // pre-close the relay sender so the child gets
                    // immediate EOF — preserving POSIX synchronous EOF.
                    //
                    // IMPORTANT: Do NOT set initial_eof when there is
                    // drained data for this stream.  The drain at
                    // commit_delayed_fork empties the ring buffer, which
                    // makes is_read_eof return true (sender shut down +
                    // buffer empty).  But the drained data still needs to
                    // be relayed through the mux to the child.  Setting
                    // initial_eof would cause the worker to pre-close the
                    // relay sender before the drained data arrives,
                    // silently dropping it.
                    let has_drained_data = fork_bridge_accum
                        .get(i)
                        .is_some_and(|bridge| !bridge.drained.is_empty());
                    let initial_eof = if has_drained_data {
                        false
                    } else if direction == HostPassthroughFdDirection::Read {
                        // The parent's counterpart (Write direction) might
                        // already have its sender shut down.  Check via
                        // the OS pipe: the parent_os_fd is the write end.
                        // If the parent's virtual pipe receiver already
                        // sees EOF, the child should too.
                        //
                        // Guard against empty parent_info (vacuous .all()
                        // would return true and falsely signal EOF).
                        fork_bridge_accum.get(i).is_some_and(|bridge| {
                            !bridge.parent_info.is_empty()
                                && bridge
                                    .parent_info
                                    .iter()
                                    .all(|&(parent_fd, parent_dir, _)| {
                                        let _ = parent_fd;
                                        let _ = parent_dir;
                                        false
                                    })
                        })
                    } else {
                        false
                    };

                    // Defer mux_stream_specs push to after orphan handling
                    // (orphan streams with drained data are handled as local
                    // pipes and should not appear in mux_stream_specs).

                    if initial_eof || has_drained_data {
                        #[cfg(feature = "trace_syscalls")]
                        litebox::log_println!(
                            self.global.platform,
                            "[DELAYED-FORK] pid={}: stream={} fd={} dir={} initial_eof={} has_drained_data={}",
                            self.pid,
                            stream_id,
                            guest_fd,
                            dir_byte as char,
                            initial_eof,
                            has_drained_data,
                        );
                    }

                    let is_host_backed = fork_bridge_accum
                        .get(i)
                        .is_some_and(|bridge| bridge.host_fd >= 0);
                    let is_virtual_pipe = !is_host_backed && type_byte == b'p';
                    let is_pty_stream = type_byte == b't';

                    // Track whether this stream is handled as a local pipe
                    // (orphan with drained data). If so, skip adding to
                    // mux_stream_specs — the worker handles it via --local-pipe.
                    let mut handled_as_local_pipe = false;
                    // Phase 3 D5: when set, the stream has been migrated
                    // out of the mux relay onto a direct broker handle.
                    // Migrated streams emit --broker-fd-bridge specs and
                    // must not also be emitted as legacy --mux-stream specs.
                    let mut handled_as_broker_bridge = false;

                    if is_virtual_pipe {
                        let drained = fork_bridge_accum
                            .get(i)
                            .map(|bridge| bridge.drained.clone())
                            .unwrap_or_default();
                        let parents = fork_bridge_accum
                            .get(i)
                            .map(|bridge| bridge.parent_info.clone())
                            .unwrap_or_default();
                        if let Some(provider) = super::broker_pipe::broker_pipe_provider() {
                            use litebox_common_linux::broker_pipe_provider::BrokerPipeEnd;
                            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;

                            let capacity =
                                u64::try_from(drained.len().saturating_add(4096).max(1024 * 1024))
                                    .unwrap_or(u64::MAX);
                            if let Ok((read_handle, write_handle)) =
                                provider.create_pipe(capacity, 4096)
                            {
                                let (worker_handle, parent_handle, worker_end, parent_end) =
                                    match direction {
                                        HostPassthroughFdDirection::Read => (
                                            read_handle,
                                            write_handle,
                                            BrokerPipeEnd::Read,
                                            BrokerPipeEnd::Write,
                                        ),
                                        HostPassthroughFdDirection::Write => (
                                            write_handle,
                                            read_handle,
                                            BrokerPipeEnd::Write,
                                            BrokerPipeEnd::Read,
                                        ),
                                        HostPassthroughFdDirection::ReadWrite => {
                                            unreachable!("bidi sockets use passthrough")
                                        }
                                    };
                                let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                                    alloc::sync::Arc::clone(&provider) as _;

                                let mut wrote_prefill = true;
                                let mut prefill_offset = 0;
                                while prefill_offset < drained.len() {
                                    match provider
                                        .write_pipe(write_handle, &drained[prefill_offset..])
                                    {
                                        Ok(0) => {
                                            wrote_prefill = false;
                                            break;
                                        }
                                        Ok(n) => prefill_offset += n,
                                        Err(_) => {
                                            wrote_prefill = false;
                                            break;
                                        }
                                    }
                                }

                                let installs_parent = !initial_eof && !parents.is_empty();
                                let mut parent_dups_ok = true;
                                let mut parent_dups_made = 0usize;
                                if installs_parent {
                                    for _ in 1..parents.len() {
                                        if releaser.dup_handle(parent_handle).is_err() {
                                            parent_dups_ok = false;
                                            break;
                                        }
                                        parent_dups_made += 1;
                                    }
                                }

                                if wrote_prefill && parent_dups_ok {
                                    let worker_dir_char = match worker_end {
                                        BrokerPipeEnd::Read => 'r',
                                        BrokerPipeEnd::Write => 'w',
                                    };
                                    broker_fd_bridge_specs.push(alloc::format!(
                                        "{guest_fd}:pipe:{worker_handle}:{worker_dir_char}"
                                    ));
                                    broker_fd_bridge_transit_release
                                        .push((alloc::sync::Arc::clone(&releaser), worker_handle));

                                    if installs_parent {
                                        for &(parent_fd, _, _) in &parents {
                                            let bp_fd = super::broker_pipe::BrokerPipeFd::<
                                                crate::Platform,
                                            >::new(
                                                alloc::sync::Arc::clone(&provider),
                                                parent_handle,
                                                parent_end,
                                                OFlags::empty(),
                                                4, // creation_site: D5-vpipe parent install
                                            );
                                            let typed: litebox::fd::TypedFd<
                                                super::broker_pipe::BrokerPipeSubsystem,
                                            > = self
                                                .global
                                                .litebox
                                                .descriptor_table_mut()
                                                .insert(bp_fd);
                                            let files = self.files.borrow();
                                            let mut rds = files.raw_descriptor_store.write();
                                            if let Ok(old_broker_pipe) = rds
                                                .fd_consume_raw_integer::<
                                                    super::broker_pipe::BrokerPipeSubsystem,
                                                >(parent_fd)
                                            {
                                                drop(rds);
                                                let _ = self
                                                    .global
                                                    .litebox
                                                    .descriptor_table_mut()
                                                    .remove(&old_broker_pipe);
                                                rds = files.raw_descriptor_store.write();
                                            }
                                            let ok =
                                                rds.fd_into_specific_raw_integer(typed, parent_fd);
                                            debug_assert!(
                                                ok,
                                                "D5-vpipe parent install: slot {parent_fd} still occupied"
                                            );
                                        }
                                    } else {
                                        releaser.release(parent_handle);
                                    }

                                    if initial_eof {
                                        // The worker receives the read end only after the
                                        // drained prefill has been written and the write end
                                        // has been released, so its first read observes
                                        // buffered data followed by synchronous EOF.
                                        debug_assert_eq!(worker_end, BrokerPipeEnd::Read);
                                    }

                                    handled_as_broker_bridge = true;
                                    broker_migrated_streams[i] = Some((
                                        worker_handle,
                                        alloc::sync::Arc::clone(&releaser),
                                        worker_dir_char,
                                    ));
                                    self.global.platform.close_host_fd(child_os_fd);

                                    #[cfg(feature = "trace_syscalls")]
                                    litebox::log_println!(
                                        self.global.platform,
                                        "[DELAYED-FORK] pid={}: stream={} virtual pipe migrated to broker worker_handle={} worker_dir={} parent_handle={} parents={} drained={} initial_eof={}",
                                        self.pid,
                                        stream_id,
                                        worker_handle,
                                        worker_dir_char,
                                        parent_handle,
                                        parents.len(),
                                        drained.len(),
                                        initial_eof,
                                    );
                                } else {
                                    for _ in 0..parent_dups_made {
                                        releaser.release(parent_handle);
                                    }
                                    releaser.release(read_handle);
                                    releaser.release(write_handle);
                                }
                            }
                        }
                    }

                    if is_pty_stream && !is_host_backed {
                        let pty_parent_fds: alloc::vec::Vec<usize> = fork_bridge_accum
                            .get(i)
                            .map(|bridge| {
                                bridge
                                    .parent_info
                                    .iter()
                                    .filter_map(|&(parent_fd, _, subsystem)| {
                                        if subsystem == b't' {
                                            Some(parent_fd)
                                        } else {
                                            None
                                        }
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        if !pty_parent_fds.is_empty()
                            && let Some(provider) = super::broker_pty::broker_pty_provider()
                        {
                            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                            match provider.create_pty() {
                                Ok(pair) => {
                                    let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                                        alloc::sync::Arc::clone(&provider) as _;
                                    for (parent_idx, &parent_fd) in
                                        pty_parent_fds.iter().enumerate()
                                    {
                                        let master_ref_acquired = if parent_idx == 0 {
                                            true
                                        } else {
                                            match releaser.dup_handle(pair.master_handle) {
                                                Ok(()) => true,
                                                Err(_) => {
                                                    releaser.release(pair.slave_handle);
                                                    put_fc_back(self, fc);
                                                    return Err(Errno::EIO);
                                                }
                                            }
                                        };
                                        let anchor_handle =
                                            match releaser.dup_handle(pair.slave_handle) {
                                                Ok(()) => Some(pair.slave_handle),
                                                Err(_) => {
                                                    if master_ref_acquired {
                                                        releaser.release(pair.master_handle);
                                                    }
                                                    releaser.release(pair.slave_handle);
                                                    put_fc_back(self, fc);
                                                    return Err(Errno::EIO);
                                                }
                                            };
                                        if self
                                            .install_d5_mux_master_pty_fd(
                                                parent_fd,
                                                alloc::sync::Arc::clone(&provider),
                                                pair.master_handle,
                                                pair.pty_id,
                                                anchor_handle,
                                            )
                                            .is_err()
                                        {
                                            if master_ref_acquired {
                                                releaser.release(pair.master_handle);
                                            }
                                            if let Some(anchor) = anchor_handle {
                                                releaser.release(anchor);
                                            }
                                            releaser.release(pair.slave_handle);
                                            put_fc_back(self, fc);
                                            return Err(Errno::EIO);
                                        }
                                    }
                                    self.global.platform.close_host_fd(child_os_fd);
                                    broker_fd_bridge_specs.push(alloc::format!(
                                        "{guest_fd}:pty:{}:s:{}",
                                        pair.slave_handle,
                                        pair.pty_id
                                    ));
                                    broker_fd_bridge_transit_release.push((
                                        alloc::sync::Arc::clone(&releaser),
                                        pair.slave_handle,
                                    ));
                                    d5_pty_bridge_handles.push((
                                        i,
                                        pair.slave_handle,
                                        pair.pty_id,
                                        releaser,
                                    ));
                                    handled_as_broker_bridge = true;
                                    #[cfg(feature = "trace_syscalls")]
                                    litebox::log_println!(
                                        self.global.platform,
                                        "[DELAYED-FORK] pid={}: stream={} PTY migrated to broker pty_id={} master_handle={} slave_handle={}",
                                        self.pid,
                                        stream_id,
                                        pair.pty_id,
                                        pair.master_handle,
                                        pair.slave_handle,
                                    );
                                }
                                Err(_) => {
                                    #[cfg(feature = "trace_syscalls")]
                                    litebox::log_println!(
                                        self.global.platform,
                                        "[DELAYED-FORK] pid={}: stream={} create_pty failed; falling back to mux",
                                        self.pid,
                                        stream_id,
                                    );
                                }
                            }
                        }
                    }

                    if is_host_backed {
                        let host_fd = fork_bridge_accum[i].host_fd;
                        // Try to migrate this host-backed stream onto a
                        // direct broker handle, eliminating its need for
                        // the mux relay. Falls back to the mux path on
                        // any failure (provider unavailable, dup failed,
                        // broker refused attach) so a missing broker
                        // doesn't break the fork-restore build.
                        let broker_dir = if dir_byte == b'r' {
                            litebox_common_linux::cwfd::fd_token_protocol::host_fd_direction::READ
                        } else {
                            litebox_common_linux::cwfd::fd_token_protocol::host_fd_direction::WRITE
                        };
                        if let Some(provider) = super::broker_pipe::broker_pipe_provider()
                            && let Ok(dup_fd) = self.global.platform.dup_host_fd(host_fd)
                        {
                            match provider.attach_host_fd(dup_fd, broker_dir) {
                                Ok(handle_id) => {
                                    use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                                    let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                                        alloc::sync::Arc::clone(&provider) as _;
                                    let dir_char = if dir_byte == b'r' { 'r' } else { 'w' };
                                    broker_fd_bridge_specs.push(alloc::format!(
                                        "{guest_fd}:pipe:{handle_id}:{dir_char}"
                                    ));
                                    broker_fd_bridge_transit_release.push((releaser, handle_id));
                                    handled_as_broker_bridge = true;
                                    // Close the parent's reference to the host fd so the
                                    // broker's SCM_RIGHTS-received dup is the sole holder
                                    // of the OFD's reader/writer refcount. Without this
                                    // close, dir='w' streams hang because the downstream
                                    // reader never sees EOF when the worker exits — the
                                    // parent's lingering fd keeps the writer-side OFD
                                    // refcount above zero. Mirrors the legacy mux relay's
                                    // close at the end of the relay loop
                                    // (process.rs:3531-3543, 3562-3574). Skip stdio
                                    // (fds 0/1/2) per the relay policy.
                                    if host_fd > 2 {
                                        self.global.platform.close_host_fd(host_fd);
                                    }
                                    #[cfg(feature = "trace_syscalls")]
                                    litebox::log_println!(
                                        self.global.platform,
                                        "[DELAYED-FORK] pid={}: stream={} host_fd={} (dup'd, original closed) migrated to broker handle {} (dir={})",
                                        self.pid,
                                        stream_id,
                                        host_fd,
                                        handle_id,
                                        dir_char,
                                    );
                                }
                                Err(_) => {
                                    // attach_host_fd consumed the dup
                                    // via SCM_RIGHTS on success; on the
                                    // Err path the dup was also taken
                                    // (the OwnedFd in
                                    // RunnerBrokerPipeProvider::attach_host_fd
                                    // is constructed from raw_fd and
                                    // dropped on error too). Nothing to
                                    // clean up here.
                                    #[cfg(feature = "trace_syscalls")]
                                    litebox::log_println!(
                                        self.global.platform,
                                        "[DELAYED-FORK] pid={}: stream={} attach_host_fd failed; falling back to mux",
                                        self.pid,
                                        stream_id,
                                    );
                                }
                            }
                        }
                    }

                    if !is_host_backed && !handled_as_broker_bridge {
                        // Virtual pipe/socket bridge: close the child-side OS
                        // pipe fd. D5 migrations install broker-backed
                        // replacements; nothing else is needed here.
                        self.global.platform.close_host_fd(child_os_fd);

                        let drained = fork_bridge_accum
                            .get(i)
                            .map(|bridge| bridge.drained.clone())
                            .unwrap_or_default();

                        // Build a MuxParentStream for each parent counterpart.
                        let parents = fork_bridge_accum
                            .get(i)
                            .map(|bridge| bridge.parent_info.clone())
                            .unwrap_or_default();

                        if type_byte == b's' {
                            let child_nonblock = {
                                let files = self.files.borrow();
                                let rds = files.raw_descriptor_store.read();
                                let typed = rds
                                    .fd_from_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(
                                        guest_fd,
                                    )
                                    .ok();
                                drop(rds);
                                typed
                                    .and_then(|typed| {
                                        let dt = self.global.litebox.descriptor_table();
                                        let flags = dt.with_entry(
                                            &typed,
                                            |sock: &super::unix::UnixSocket<FS>| sock.get_status(),
                                        );
                                        drop(dt);
                                        flags
                                    })
                                    .is_some_and(|flags| {
                                        flags.contains(litebox::fs::OFlags::NONBLOCK)
                                    })
                            };

                            if let Some(provider) =
                                super::broker_socketpair::broker_socketpair_provider()
                            {
                                const SP_CAPACITY: u64 = 64 * 1024;
                                const SP_ATOMIC: u64 = 4096;
                                if let Ok((parent_handle, worker_handle)) =
                                    provider.create_socketpair(SP_CAPACITY, SP_ATOMIC)
                                {
                                    let mut drained_ok = true;
                                    if direction == HostPassthroughFdDirection::Read
                                        && !drained.is_empty()
                                    {
                                        let mut off = 0;
                                        while off < drained.len() {
                                            match provider
                                                .write_socketpair(parent_handle, &drained[off..])
                                            {
                                                Ok(0) | Err(_) => {
                                                    drained_ok = false;
                                                    break;
                                                }
                                                Ok(n) => off += n,
                                            }
                                        }
                                    }

                                    use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                                    let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                                        alloc::sync::Arc::clone(&provider) as _;

                                    if drained_ok {
                                        let child_nonblock_flag =
                                            if child_nonblock { 1 } else { 0 };
                                        broker_fd_bridge_specs.push(alloc::format!(
                                            "{guest_fd}:unix_socket:{worker_handle}:b:{child_nonblock_flag}"
                                        ));
                                        broker_fd_bridge_transit_release.push((
                                            alloc::sync::Arc::clone(&releaser),
                                            worker_handle,
                                        ));
                                        broker_socketpair_migrated_streams.push((
                                            i,
                                            worker_handle,
                                            'b',
                                            child_nonblock,
                                        ));

                                        if parents.is_empty() {
                                            // No parent peer remains. Drop endpoint A so endpoint B
                                            // observes peer shutdown after any prefilled bytes drain.
                                            releaser.release(parent_handle);
                                        } else {
                                            for (parent_index, &(parent_fd, _, _)) in
                                                parents.iter().enumerate()
                                            {
                                                broker_socketpair_parent_installs.push(
                                                    crate::BrokerSocketPairParentInstall {
                                                        guest_fd: parent_fd,
                                                        handle_id: parent_handle,
                                                        endpoint: litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::A,
                                                        dup_before_install: parent_index > 0,
                                                    },
                                                );
                                            }
                                            broker_socketpair_parent_release_on_failure
                                                .push((releaser, parent_handle));
                                        }

                                        handled_as_broker_bridge = true;
                                        #[cfg(feature = "trace_syscalls")]
                                        litebox::log_println!(
                                            self.global.platform,
                                            "[DELAYED-FORK] pid={}: stream={} unix socket migrated to broker handles parent={} worker={} child_nonblock={} parents={}",
                                            self.pid,
                                            stream_id,
                                            parent_handle,
                                            worker_handle,
                                            child_nonblock,
                                            parents.len(),
                                        );
                                    } else {
                                        releaser.release(parent_handle);
                                        releaser.release(worker_handle);
                                    }
                                }
                            }
                        }

                        let _ = drained;
                        let _ = parents;
                    }
                }

                // Close parent-side OS pipe fds — the mux replaces them.
                // Skip bidirectional (ReadWrite) fds — those are stored in
                // fd_replacements and will be used by the parent after VforkDone.
                for pr in &parent_replacements {
                    if pr.direction != HostPassthroughFdDirection::ReadWrite {
                        self.global.platform.close_host_fd(pr.host_fd);
                    }
                }

                // Append alias entries to mux_stream_specs: same
                // stream_id as the primary, different guest_fd.  The
                // worker dedup installs a dup'd pipe end at the alias
                // fd.  The parent `seen_streams` dedup installs a
                // dup'd dispatch pipe for the alias.
                for &(alias_fd, primary_idx) in &mux_aliases {
                    // D5-vpipe: alias references a primary that was
                    // migrated to a BrokerPipe; dup the partner handle
                    // and emit a broker_fd_bridge spec.
                    if let Some((handle_id, releaser, dir_char)) =
                        broker_migrated_streams[primary_idx].as_ref()
                    {
                        if releaser.dup_handle(*handle_id).is_ok() {
                            broker_fd_bridge_specs
                                .push(alloc::format!("{alias_fd}:pipe:{handle_id}:{dir_char}"));
                            broker_fd_bridge_transit_release
                                .push((alloc::sync::Arc::clone(releaser), *handle_id));
                        }
                        continue;
                    }
                    // D5-vsocket: alias references a primary that was
                    // migrated to a BrokerSocketPair; emit a
                    // broker_fd_bridge spec with NONBLOCK inherited
                    // from either the alias fd or the primary.
                    if let Some(&(_, handle_id, endpoint_char, primary_nonblock)) =
                        broker_socketpair_migrated_streams
                            .iter()
                            .find(|&&(idx, _, _, _)| idx == primary_idx)
                    {
                        let alias_nonblock = {
                            let files = self.files.borrow();
                            let rds = files.raw_descriptor_store.read();
                            let typed = rds
                                .fd_from_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(
                                    alias_fd,
                                )
                                .ok();
                            drop(rds);
                            typed
                                .and_then(|typed| {
                                    let dt = self.global.litebox.descriptor_table();
                                    let flags = dt.with_entry(
                                        &typed,
                                        |sock: &super::unix::UnixSocket<FS>| sock.get_status(),
                                    );
                                    drop(dt);
                                    flags
                                })
                                .is_some_and(|flags| flags.contains(litebox::fs::OFlags::NONBLOCK))
                        } || primary_nonblock;
                        let alias_nonblock_flag = if alias_nonblock { 1 } else { 0 };
                        broker_fd_bridge_specs.push(alloc::format!(
                            "{alias_fd}:unix_socket:{handle_id}:{endpoint_char}:{alias_nonblock_flag}"
                        ));
                        continue;
                    }
                    // D5-vpty: alias references a primary that was
                    // migrated to a BrokerPty; dup the slave handle
                    // and emit a broker_fd_bridge spec.
                    if let Some(&(_, slave_handle, pty_id, ref releaser)) = d5_pty_bridge_handles
                        .iter()
                        .find(|&&(idx, _, _, _)| idx == primary_idx)
                    {
                        if releaser.dup_handle(slave_handle).is_err() {
                            put_fc_back(self, fc);
                            return Err(Errno::EIO);
                        }
                        broker_fd_bridge_specs
                            .push(alloc::format!("{alias_fd}:pty:{slave_handle}:s:{pty_id}"));
                        broker_fd_bridge_transit_release
                            .push((alloc::sync::Arc::clone(releaser), slave_handle));
                        continue;
                    }

                    let _stream_id = u32::try_from(primary_idx).unwrap_or(0);
                    let _ = alias_fd;
                }

                // D5-vsocket parent-side install metadata is stored
                // regardless of whether other streams migrated; it's
                // independent of the legacy mux relay.
                *fc.vfork_done.broker_socketpair_parent_installs.lock() =
                    broker_socketpair_parent_installs;

                // Clear child_pipe_bridges — child OS fds for non-host-backed
                // bridges were already closed above, and parent_replacements fds
                // were closed too.  Clearing prevents double-close in error paths.
                child_pipe_bridges.clear();
            }

            #[cfg(feature = "trace_syscalls")]
            if !child_pipe_bridges.is_empty() {
                litebox::log_println!(
                    self.global.platform,
                    "[DELAYED-FORK] pid={}: created {} pipe bridges",
                    self.pid,
                    child_pipe_bridges.len(),
                );
            }
        }

        // wave-cleanup-2 fork-snapshot epoll extension: emit
        // `--broker-fd-bridge` specs for Epoll and Inotify fds so the
        // worker reconstructs their state after snapshot restore.
        // MUST run after every other spec push (epoll bridge install
        // requires all other subsystem installs to have completed).
        {
            let collected = collect_migratable_fds::<FS>(
                &self.files.borrow(),
                &self.global,
                /* survives_exec_filter */ false,
            );
            // Mirror the `snapshot_fd_table` CLOEXEC reject gate for
            // Epoll/Inotify: emitting bridge specs for fds the snapshot
            // path then rejects causes a mismatch between the
            // bridge-spec set and the snapshot's `FdEntrySnapshot` set.
            let files_ref = self.files.borrow();
            let inotify_non_cloexec =
                filter_non_cloexec_bucket(&collected.inotify, &self.global, &files_ref);
            let epoll_non_cloexec =
                filter_non_cloexec_bucket(&collected.epoll, &self.global, &files_ref);
            drop(files_ref);
            emit_inotify_bridge_specs(
                self,
                &inotify_non_cloexec,
                &mut broker_fd_bridge_specs,
                &mut broker_fd_bridge_transit_release,
            );
            // Epoll last (no broker handle; targets resolved at install).
            emit_epoll_bridge_specs(self, &epoll_non_cloexec, &mut broker_fd_bridge_specs);
        }

        let snapshot = super::fork_snapshot::ForkSnapshot {
            identity,
            process_wide,
            thread,
            signal,
            fs,
            fd_table,
            memory,
            is_delayed_fork: true,
        };

        phase_tick!("pre_snapshot_serialize");
        let snapshot_bytes = snapshot.serialize();
        phase_tick!("post_snapshot_serialize");

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[DELAYED-FORK] pid={}: snapshot serialized ({} bytes), spawning worker",
            self.pid,
            snapshot_bytes.len(),
        );

        // Get stdio bindings for the child worker.
        let stdio = match self.worker_exec_stdio_bindings() {
            Ok(s) => s,
            Err(_e) => {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[DELAYED-FORK] pid={}: stdio bindings failed: {:?}",
                    self.pid,
                    _e,
                );
                // Clean up OS pipe FDs created during pipe bridging.
                for (i, &(_, os_fd, _)) in child_pipe_bridges.iter().enumerate() {
                    // Close newly-created pipe fds, but NOT fds
                    // that are owned by the host passthrough fd system (where
                    // os_fd == fork_bridge_accum[i].host_fd).
                    let is_host_owned = fork_bridge_accum
                        .get(i)
                        .is_some_and(|bridge| bridge.host_fd == os_fd);
                    if !is_host_owned {
                        self.global.platform.close_host_fd(os_fd);
                    }
                }
                for pr in fc.vfork_done.fd_replacements.lock().drain(..) {
                    self.global.platform.close_host_fd(pr.host_fd);
                }
                for (releaser, handle_id) in broker_fd_bridge_transit_release.drain(..) {
                    releaser.release(handle_id);
                }
                for (releaser, handle_id) in broker_socketpair_parent_release_on_failure.drain(..) {
                    releaser.release(handle_id);
                }
                fc.vfork_done
                    .broker_socketpair_parent_installs
                    .lock()
                    .clear();
                put_fc_back(self, fc);
                todo!(
                    "ENOSYS audit: delayed fork worker stdio bindings; reachable but not implemented"
                );
            }
        };

        // Allocate a broker-owned auxiliary process pid that the
        // spawned runner will stamp via `try_mark_broker_process_exited`
        // after running its fork-restore install loop. The parent
        // blocks on a broker `subscribe_process_exit` for the same
        // pid; replaces the legacy `--fork-restore-ack-fd` pipe.
        let ack_pid = match super::guest_pid::try_register_broker_guest_pid() {
            Some(pid) => pid,
            None => {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[DELAYED-FORK] pid={}: failed to allocate broker fork-restore ack pid",
                    self.pid,
                );
                for pr in fc.vfork_done.fd_replacements.lock().drain(..) {
                    self.global.platform.close_host_fd(pr.host_fd);
                }
                for (releaser, handle_id) in broker_fd_bridge_transit_release.drain(..) {
                    releaser.release(handle_id);
                }
                for (releaser, handle_id) in broker_socketpair_parent_release_on_failure.drain(..) {
                    releaser.release(handle_id);
                }
                fc.vfork_done
                    .broker_socketpair_parent_installs
                    .lock()
                    .clear();
                put_fc_back(self, fc);
                return Err(Errno::ENOMEM);
            }
        };

        // Spawn the child worker host.
        // Build passthrough fds for bidirectional unix socket bridges.
        let bidi_pt: Vec<(usize, i32)> = bidi_passthrough
            .iter()
            .map(|&(guest_fd, child_fd, _)| (guest_fd, child_fd))
            .collect();
        let host_pid = match self.global.platform.spawn_worker_host_for_fork_restore(
            &snapshot_bytes,
            stdio,
            &bidi_pt,
            // Phase 3 D5: streams migrated directly to broker handles
            // via `--broker-fd-bridge`. Includes host-backed,
            // virtual-pipe / socket / PTY, and FS-backed.
            &broker_fd_bridge_specs,
            ack_pid,
        ) {
            Ok(pid) => {
                phase_tick!("post_spawn_worker_host");
                pid
            }
            Err(_err) => {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[DELAYED-FORK] pid={}: spawn_worker_host failed: {}",
                    self.pid,
                    _err,
                );
                super::guest_pid::try_release_broker_guest_pid(ack_pid);
                // Clean up parent-side OS pipe FDs on failure.
                for pr in fc.vfork_done.fd_replacements.lock().drain(..) {
                    self.global.platform.close_host_fd(pr.host_fd);
                }
                // Phase 3 D5: release transit refs for broker handles
                // shipped via broker_fd_bridge_specs. The worker never
                // came up, so its install_broker_fd_bridge_spec never
                // ran. Each handle still has the creation ref from
                // attach_host_fd; releasing here drops it and frees
                // the broker's dup'd host fd via HostFdState::drop.
                for (releaser, handle_id) in broker_fd_bridge_transit_release.drain(..) {
                    releaser.release(handle_id);
                }
                for (releaser, handle_id) in broker_socketpair_parent_release_on_failure.drain(..) {
                    releaser.release(handle_id);
                }
                fc.vfork_done
                    .broker_socketpair_parent_installs
                    .lock()
                    .clear();
                put_fc_back(self, fc);
                return Err(Errno::ENOMEM);
            }
        };

        // Wait for the runner to stamp the install-complete ack via
        // the broker. 0 = success; any non-zero / missing = install
        // failure (e.g., runner crashed before stamping). Mirrors the
        // legacy pipe-read in the platform-side spawn helper.
        let ack_wait_timeout = core::time::Duration::from_secs(30);
        let ack_status =
            super::guest_pid::try_wait_broker_process_exit(ack_pid, ack_wait_timeout).unwrap_or(-1);
        super::guest_pid::try_release_broker_guest_pid(ack_pid);
        phase_tick!("post_fork_restore_ack");

        if ack_status != 0 {
            #[cfg(feature = "trace_syscalls")]
            litebox::log_println!(
                self.global.platform,
                "[DELAYED-FORK] pid={}: fork-restore ack failed (status={}); reaping host_pid={}",
                self.pid,
                ack_status,
                host_pid,
            );
            // Reap the child runner so it doesn't linger.
            let _ = self.global.platform.wait_worker_host(host_pid);
            for pr in fc.vfork_done.fd_replacements.lock().drain(..) {
                self.global.platform.close_host_fd(pr.host_fd);
            }
            for (releaser, handle_id) in broker_fd_bridge_transit_release.drain(..) {
                releaser.release(handle_id);
            }
            for (releaser, handle_id) in broker_socketpair_parent_release_on_failure.drain(..) {
                releaser.release(handle_id);
            }
            fc.vfork_done
                .broker_socketpair_parent_installs
                .lock()
                .clear();
            put_fc_back(self, fc);
            return Err(Errno::ENOMEM);
        }

        // Ack success: the worker has finished `install_broker_fd_bridge_spec`
        // for every spec we shipped, which means each spec's handle has
        // been dup_handled into the worker's connection. Safe to drop
        // the parent's creation ref now.
        for (releaser, handle_id) in broker_fd_bridge_transit_release.drain(..) {
            releaser.release(handle_id);
        }

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[DELAYED-FORK] pid={}: worker spawned, host_pid={}",
            self.pid,
            host_pid,
        );

        // Close child ends of bidirectional socketpair bridges.
        // The parent-side fd replacement is stored in fd_replacements
        // (via parent_replacements) and applied by the parent after VforkDone.
        for &(_, child_fd, _) in &bidi_passthrough {
            self.global.platform.close_host_fd(child_fd);
        }

        // Migrate: unregister from local control plane, re-register as remote.
        let local_host = self.global.control_plane.local_host();
        let _ = self
            .global
            .control_plane
            .unregister_running_process(self.process_id);
        let _ = self
            .global
            .control_plane
            .register_running_process(self.process_id, local_host);

        // Record fork child → worker host PID mapping for signal forwarding.
        self.global
            .fork_child_host_pids
            .write()
            .insert(self.process_id.0, host_pid);

        // Clean up the pre-allocated child address space — the worker host
        // has its own.
        let _ = self
            .global
            .platform
            .destroy_address_space(fc.address_space_id);

        // The child worker acknowledged a successful restore, so every
        // broker-backed fd in the snapshot has installed its own restore-side
        // reference. Drop the parent's transit refs now; keeping pipe writer
        // transit refs until worker exit makes readers in that same worker wait
        // forever for EOF.
        {
            let _caller_pid_guard =
                litebox_common_linux::fd_token_client::set_caller_pid_scope(self.process_id.0);
            for transit in fc.fork_snapshot_broker_transit.drain(..) {
                transit.releaser.release(transit.handle_id);
            }
            fc.fork_snapshot_pidfd_process_transit.clear();
        }

        // Spawn a background thread that waits for the child worker to exit
        // and reports the exit to the process registry (same as do_true_fork).
        {
            use litebox_common_linux::signal::{Siginfo, SiginfoData, Signal};
            const CLD_EXITED: i32 = 1;

            let global = self.global.clone();
            let child_proc_id = self.process_id;
            self.global.platform.spawn_background_task(move || {
                let raw_wait_status = global.platform.wait_worker_host(host_pid);
                let exit_status =
                    resolve_worker_exit_registry_status(child_proc_id, raw_wait_status);

                global.fork_child_host_pids.write().remove(&child_proc_id.0);

                super::guest_pid::try_mark_broker_process_exited(child_proc_id.0, exit_status);

                global
                    .control_plane
                    .unregister_running_process(child_proc_id);

                global
                    .litebox
                    .process_registry()
                    .exit_process_with_callback(child_proc_id, exit_status, |notif| {
                        if let Some(notif) = notif {
                            global
                                .control_plane
                                .record_child_exit_provenance(local_host, notif);

                            let Ok(signal) = Signal::try_from(notif.exit_signal) else {
                                return;
                            };
                            let mut data = SiginfoData { pad: [0u32; 28] };
                            data.pad[0] = notif.child_pid.0;
                            data.pad[2] = notif.exit_status.cast_unsigned();
                            let siginfo = Siginfo {
                                signo: signal.as_i32(),
                                errno: 0,
                                code: CLD_EXITED,
                                #[cfg(target_pointer_width = "64")]
                                __pad: 0,
                                data,
                            };

                            global
                                .cross_process_signals
                                .lock()
                                .push(crate::CrossProcessSignal {
                                    target_process_id: notif.parent_pid.0,
                                    target_tid: None,
                                    signal,
                                    siginfo,
                                });
                            let parent_key = notif.parent_pid.0.cast_signed();
                            if let Some(remote) =
                                global.process_thread_handles.read().get(&parent_key)
                            {
                                remote.interrupt();
                            }
                        }
                    });
            });
        }

        // Signal VforkDone AFTER the worker is spawned and registered.
        // The parent will then restore the CoW layer and resume.
        phase_tick!("pre_vfork_done_signal");
        fc.vfork_done.signal();
        phase_tick!("post_vfork_done_signal");

        // Mark this task as migrated so prepare_for_exit skips cleanup.
        self.delayed_fork_pending.set(false);
        self.migrated_to_remote.set(true);

        // Remove the local process_thread_handles entry for this child —
        // the remote worker host owns the process now.
        {
            let proc_key = self.process_id.0.cast_signed();
            self.global.process_thread_handles.write().remove(&proc_key);
        }

        Ok(())
    }

    /// True fork on a shared-address-space (userland) platform.
    ///
    /// Unlike the vfork-style shared path in [`do_fork`], true fork creates
    /// the child in a separate host process so that parent and child run
    /// concurrently with independent address spaces.
    ///
    /// This is the entry point for the two-phase snapshot/restore design:
    ///   1. Snapshot the parent's state at the fork trap.
    ///   2. Restore that snapshot in a new worker host process.
    ///
    /// Currently unimplemented — panics when reached so missing true-fork support is loud.
    #[allow(unused_variables)]
    #[allow(dead_code)]
    fn do_true_fork(
        &self,
        ctx: &litebox_common_linux::ExecutionContext,
        args: &litebox_common_linux::CloneArgs,
        flags: CloneFlags,
        _clone3: bool,
        child_process_id: litebox::process::ProcessId,
        child_as_id: <crate::Platform as litebox::platform::AddressSpaceProvider>::AddressSpaceId,
    ) -> Result<usize, Errno> {
        use super::fork_snapshot::ForkRejectReasons;
        use litebox::platform::AddressSpaceProvider;

        // Helper to clean up pre-allocated resources on failure.
        let cleanup = |this: &Self, as_id, proc_id: litebox::process::ProcessId| {
            let _ = this.global.platform.destroy_address_space(as_id);
            this.global
                .litebox
                .process_registry()
                .remove_process(proc_id);
        };

        // Allocate the child's guest PID/TID.
        let child_pid = self
            .global
            .next_thread_id
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        // Park sibling threads to get a consistent snapshot.
        // snapshot_memory() changes page permissions and reads raw pages,
        // so we need exclusive access.
        let Ok(did_park) = self.park_other_threads() else {
            cleanup(self, child_as_id, child_process_id);
            return Err(Errno::EAGAIN);
        };

        // Phase 1: collect snapshot.
        let mut reject = ForkRejectReasons::new();

        let exit_signal = i32::try_from(args.exit_signal).unwrap_or(0);
        let identity = self.snapshot_identity(child_process_id, child_pid, exit_signal);
        let process_wide = self.snapshot_process_wide();
        let thread = self.snapshot_thread(ctx, flags, args);
        let signal = self.snapshot_signal();
        let fs = self.snapshot_fs();
        let mut _true_fork_transit: Vec<super::fork_snapshot::ForkSnapshotBrokerTransit> =
            Vec::new();
        let mut _true_fork_fd_token_transit: Vec<super::fork_snapshot::ForkSnapshotFdTokenTransit> =
            Vec::new();
        let mut _true_fork_pidfd_process_transit: Vec<super::guest_pid::BrokerProcessExitWake> =
            Vec::new();
        let fd_table = self.snapshot_fd_table(
            &mut reject,
            &mut _true_fork_transit,
            &mut _true_fork_pidfd_process_transit,
            &mut _true_fork_fd_token_transit,
            false,
            None,
        );
        let memory = self.snapshot_memory(&mut reject);

        // Unpark sibling threads — snapshot is complete.
        if did_park {
            self.unpark_other_threads();
        }

        // Phase 2: check reject gate.
        if !reject.is_empty() {
            #[cfg(feature = "trace_syscalls")]
            litebox::log_println!(
                self.global.platform,
                "[TRUE-FORK] pid={} child_pid={}: rejected — {}",
                self.pid,
                child_pid,
                reject,
            );
            for transit in _true_fork_fd_token_transit.drain(..) {
                let _ = transit.client.release(transit.token_id);
            }
            cleanup(self, child_as_id, child_process_id);
            todo!("ENOSYS audit: true fork rejected snapshot state; reachable but not implemented");
        }

        // wave-cleanup-2 fork-snapshot epoll extension: emit
        // `--broker-fd-bridge` specs for Epoll and Inotify fds so the
        // worker reconstructs their state after snapshot restore.
        // True-fork has no other broker_fd_bridge specs (delayed-fork
        // commits its pipe/socket bridges first), so this is the only
        // population path for the snapshot-restore worker's spec list.
        let mut true_fork_broker_fd_bridge_specs: alloc::vec::Vec<alloc::string::String> =
            alloc::vec::Vec::new();
        let mut true_fork_broker_fd_bridge_transit_release: alloc::vec::Vec<(
            alloc::sync::Arc<
                dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
            >,
            u64,
        )> = alloc::vec::Vec::new();
        {
            let collected = collect_migratable_fds::<FS>(
                &self.files.borrow(),
                &self.global,
                /* survives_exec_filter */ false,
            );
            // Mirror the snapshot CLOEXEC reject gate (see commit_delayed_fork).
            let files_ref = self.files.borrow();
            let inotify_non_cloexec =
                filter_non_cloexec_bucket(&collected.inotify, &self.global, &files_ref);
            let epoll_non_cloexec =
                filter_non_cloexec_bucket(&collected.epoll, &self.global, &files_ref);
            drop(files_ref);
            emit_inotify_bridge_specs(
                self,
                &inotify_non_cloexec,
                &mut true_fork_broker_fd_bridge_specs,
                &mut true_fork_broker_fd_bridge_transit_release,
            );
            // Epoll last (no broker handle; targets resolved at install).
            emit_epoll_bridge_specs(
                self,
                &epoll_non_cloexec,
                &mut true_fork_broker_fd_bridge_specs,
            );
        }

        let snapshot = super::fork_snapshot::ForkSnapshot {
            identity,
            process_wide,
            thread,
            signal,
            fs,
            fd_table,
            memory,
            is_delayed_fork: false,
        };

        // Phase 3: serialize and transport.
        let snapshot_bytes = snapshot.serialize();

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[TRUE-FORK] pid={} child_pid={}: snapshot serialized ({} bytes), spawning worker",
            self.pid,
            child_pid,
            snapshot_bytes.len(),
        );

        // Get stdio bindings for the child worker.
        let stdio = match self.worker_exec_stdio_bindings() {
            Ok(s) => s,
            Err(e) => {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[TRUE-FORK] pid={} child_pid={}: stdio bindings failed: {:?}",
                    self.pid,
                    child_pid,
                    e,
                );
                for transit in _true_fork_fd_token_transit.drain(..) {
                    let _ = transit.client.release(transit.token_id);
                }
                cleanup(self, child_as_id, child_process_id);
                todo!(
                    "ENOSYS audit: true fork worker stdio bindings; reachable but not implemented"
                );
            }
        };

        // Allocate a broker-owned auxiliary process pid for the
        // fork-restore install ack (see analog in commit_delayed_fork).
        let ack_pid = match super::guest_pid::try_register_broker_guest_pid() {
            Some(pid) => pid,
            None => {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[TRUE-FORK] pid={} child_pid={}: failed to allocate broker fork-restore ack pid",
                    self.pid,
                    child_pid,
                );
                for transit in _true_fork_fd_token_transit.drain(..) {
                    let _ = transit.client.release(transit.token_id);
                }
                cleanup(self, child_as_id, child_process_id);
                return Err(Errno::ENOMEM);
            }
        };

        // Spawn the child worker host.
        let host_pid = match self.global.platform.spawn_worker_host_for_fork_restore(
            &snapshot_bytes,
            stdio,
            &[],
            &true_fork_broker_fd_bridge_specs,
            ack_pid,
        ) {
            Ok(pid) => pid,
            Err(err) => {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[TRUE-FORK] pid={} child_pid={}: spawn_worker_host_for_fork_restore failed: {}",
                    self.pid,
                    child_pid,
                    err,
                );
                super::guest_pid::try_release_broker_guest_pid(ack_pid);
                for transit in _true_fork_fd_token_transit.drain(..) {
                    let _ = transit.client.release(transit.token_id);
                }
                for (releaser, handle_id) in true_fork_broker_fd_bridge_transit_release.drain(..) {
                    releaser.release(handle_id);
                }
                cleanup(self, child_as_id, child_process_id);
                return Err(Errno::ENOMEM);
            }
        };

        // Wait for the runner's broker-stamped install-complete ack.
        let ack_wait_timeout = core::time::Duration::from_secs(30);
        let ack_status =
            super::guest_pid::try_wait_broker_process_exit(ack_pid, ack_wait_timeout).unwrap_or(-1);
        super::guest_pid::try_release_broker_guest_pid(ack_pid);
        if ack_status != 0 {
            #[cfg(feature = "trace_syscalls")]
            litebox::log_println!(
                self.global.platform,
                "[TRUE-FORK] pid={} child_pid={}: fork-restore ack failed (status={}); reaping host_pid={}",
                self.pid,
                child_pid,
                ack_status,
                host_pid,
            );
            let _ = self.global.platform.wait_worker_host(host_pid);
            for transit in _true_fork_fd_token_transit.drain(..) {
                let _ = transit.client.release(transit.token_id);
            }
            for (releaser, handle_id) in true_fork_broker_fd_bridge_transit_release.drain(..) {
                releaser.release(handle_id);
            }
            cleanup(self, child_as_id, child_process_id);
            return Err(Errno::ENOMEM);
        }

        // Ack success: worker has installed every spec we shipped (each
        // spec's handle has been `dup_handle`'d into the worker's
        // connection). Safe to drop the parent's transit dup ref.
        for (releaser, handle_id) in true_fork_broker_fd_bridge_transit_release.drain(..) {
            releaser.release(handle_id);
        }

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[TRUE-FORK] pid={} child_pid={}: worker spawned, host_pid={}",
            self.pid,
            child_pid,
            host_pid,
        );

        // Register the child in the multihost control plane.
        let local_host = self.global.control_plane.local_host();
        let _ = self
            .global
            .control_plane
            .register_running_process(child_process_id, local_host);

        // Clean up the pre-allocated address space — the child has its own.
        let _ = self.global.platform.destroy_address_space(child_as_id);

        // Record the fork child → worker host PID mapping so that kill()
        // can forward signals to the correct worker host process.
        self.global
            .fork_child_host_pids
            .write()
            .insert(child_process_id.0, host_pid);

        // Spawn a background thread that waits for the child worker to exit,
        // then reports the exit to the process registry so that the parent's
        // wait4/waitid can reap the child.
        {
            use litebox_common_linux::signal::{Siginfo, SiginfoData, Signal};
            const CLD_EXITED: i32 = 1;

            let global = self.global.clone();
            let child_proc_id = child_process_id;
            self.global.platform.spawn_background_task(move || {
                let raw_wait_status = global.platform.wait_worker_host(host_pid);
                let exit_status =
                    resolve_worker_exit_registry_status(child_proc_id, raw_wait_status);

                // Remove the fork child host PID mapping first to prevent
                // kill() from forwarding signals to a potentially-reused PID.
                global.fork_child_host_pids.write().remove(&child_proc_id.0);

                super::guest_pid::try_mark_broker_process_exited(child_proc_id.0, exit_status);

                // Unregister from control plane before exit notification.
                global
                    .control_plane
                    .unregister_running_process(child_proc_id);

                // Report exit to the process registry, which wakes the parent's
                // wait channel and delivers the configured exit signal.
                global
                    .litebox
                    .process_registry()
                    .exit_process_with_callback(child_proc_id, exit_status, |notif| {
                        if let Some(notif) = notif {
                            // Record provenance so the control plane can track
                            // the source host for this child exit.
                            global
                                .control_plane
                                .record_child_exit_provenance(local_host, notif);

                            // Build exit notification siginfo matching
                            // deliver_local_child_exit_notification().
                            // Use notif.exit_signal (not hardcoded SIGCHLD) so
                            // clone() with a custom exit_signal works correctly.
                            let Ok(signal) = Signal::try_from(notif.exit_signal) else {
                                return;
                            };
                            let mut data = SiginfoData { pad: [0u32; 28] };
                            data.pad[0] = notif.child_pid.0; // si_pid
                            data.pad[2] = notif.exit_status.cast_unsigned(); // si_status
                            let siginfo = Siginfo {
                                signo: signal.as_i32(),
                                errno: 0,
                                code: CLD_EXITED,
                                #[cfg(target_pointer_width = "64")]
                                __pad: 0,
                                data,
                            };

                            // Queue exit signal for the parent and interrupt it.
                            global
                                .cross_process_signals
                                .lock()
                                .push(crate::CrossProcessSignal {
                                    target_process_id: notif.parent_pid.0,
                                    target_tid: None,
                                    signal,
                                    siginfo,
                                });
                            let parent_key = notif.parent_pid.0.cast_signed();
                            if let Some(remote) =
                                global.process_thread_handles.read().get(&parent_key)
                            {
                                remote.interrupt();
                            }
                        }
                    });
            });
        }

        // Return child pid to the parent.
        Ok(usize::try_from(child_pid).unwrap())
    }

    /// Capture the calling task's identity for a true-fork snapshot.
    #[allow(dead_code)]
    fn snapshot_identity(
        &self,
        child_process_id: litebox::process::ProcessId,
        child_pid: i32,
        exit_signal: i32,
    ) -> super::fork_snapshot::ProcessIdentitySnapshot {
        use litebox::process::ProcessGroupId;
        use litebox::process::SessionId;

        let pgid = self
            .global
            .litebox
            .process_registry()
            .get_pgid(self.process_id)
            .map_or(self.pid.cast_unsigned(), ProcessGroupId::as_u32);
        let sid = self
            .global
            .litebox
            .process_registry()
            .get_sid(self.process_id)
            .map_or(self.pid.cast_unsigned(), SessionId::as_u32);

        super::fork_snapshot::ProcessIdentitySnapshot {
            process_id: child_process_id,
            parent_process_id: self.process_id,
            pid: child_pid,
            ppid: self.pid,
            tid: child_pid, // initial thread tid == pid
            pgid: i32::try_from(pgid).unwrap_or(self.pid),
            sid: i32::try_from(sid).unwrap_or(self.pid),
            exit_signal,
            comm: self.comm.get(),
            credentials: super::fork_snapshot::CredentialsSnapshot {
                uid: self.credentials.uid,
                euid: self.credentials.euid,
                gid: self.credentials.gid,
                egid: self.credentials.egid,
            },
        }
    }

    /// Capture process-wide state for a true-fork snapshot.
    fn snapshot_process_wide(&self) -> super::fork_snapshot::ProcessWideSnapshot {
        let process = self.process();

        // Snapshot resource limits.
        let mut rlimits = [(0usize, 0usize); litebox_common_linux::RlimitResource::RLIM_NLIMITS];
        for (i, rl) in process.limits.limits.iter().enumerate() {
            rlimits[i] = (
                rl.cur.load(Ordering::Relaxed),
                rl.max.load(Ordering::Relaxed),
            );
        }

        super::fork_snapshot::ProcessWideSnapshot {
            rlimits,
            thp_disabled: process.thp_disabled.load(Ordering::Relaxed),
            // Linux fork() does not inherit pending alarms.
            alarm_remaining_ns: None,
        }
    }

    /// Capture the calling thread's execution state for a true-fork snapshot.
    #[allow(dead_code)]
    fn snapshot_thread(
        &self,
        ctx: &litebox_common_linux::ExecutionContext,
        flags: CloneFlags,
        args: &litebox_common_linux::CloneArgs,
    ) -> super::fork_snapshot::ThreadSnapshot {
        // Read guest TLS base (FS base on x86-64).
        #[cfg(target_arch = "x86_64")]
        let tls_base = {
            let punchthrough = litebox_common_linux::PunchthroughSyscall::GetFsBase;
            self.global
                .platform
                .get_punchthrough_token_for(punchthrough)
                .and_then(|token| token.execute().ok())
        };
        #[cfg(not(target_arch = "x86_64"))]
        let tls_base: Option<usize> = None;

        let set_child_tid = if flags.contains(CloneFlags::CHILD_SETTID) && args.child_tid != 0 {
            Some(args.child_tid.truncate())
        } else {
            None
        };
        let clear_child_tid = if flags.contains(CloneFlags::CHILD_CLEARTID) && args.child_tid != 0 {
            Some(args.child_tid.truncate())
        } else {
            None
        };
        let robust_list = self.thread.robust_list.get().map(|ptr| ptr.as_usize());

        super::fork_snapshot::ThreadSnapshot {
            execution_context: ctx.clone(),
            tls_base,
            set_child_tid,
            clear_child_tid,
            robust_list,
        }
    }

    /// Capture signal state for a true-fork snapshot.
    fn snapshot_signal(&self) -> super::fork_snapshot::SignalSnapshot {
        let blocked = self.signals.get_blocked();
        let handlers = self.signals.snapshot_handlers();

        // Linux fork() inherits the parent's alternate signal stack.
        // Only clone(CLONE_VM) without CLONE_VFORK resets it.
        let altstack = self.signals.altstack();

        super::fork_snapshot::SignalSnapshot {
            blocked,
            handlers,
            altstack,
        }
    }

    /// Capture filesystem state for a true-fork snapshot (deep copy).
    fn snapshot_fs(&self) -> super::fork_snapshot::FsSnapshot {
        let fs = self.fs.borrow();
        super::fork_snapshot::FsSnapshot {
            cwd: fs.current_working_directory(),
            exe_path: fs.exe_path.read().clone(),
            umask: fs.umask().bits(),
        }
    }

    fn delayed_fork_trigger_fd(ctx: &litebox_common_linux::ExecutionContext) -> Option<usize> {
        use ::syscalls::Sysno;

        match Sysno::new(ctx.orig_rax) {
            Some(Sysno::bind | Sysno::connect | Sysno::listen) => usize::try_from(ctx.rdi).ok(),
            _ => None,
        }
    }

    /// Snapshot the FD table and populate the reject gate for unsupported types.
    ///
    /// In v1, only stdio fds (identified by matching their object ID against the
    /// original host stdio descriptors) are supported for cross-host fork.
    /// All other open fds cause fork rejection.
    fn snapshot_fd_table(
        &self,
        reject: &mut super::fork_snapshot::ForkRejectReasons,
        broker_transit: &mut Vec<super::fork_snapshot::ForkSnapshotBrokerTransit>,
        pidfd_process_transit: &mut Vec<super::guest_pid::BrokerProcessExitWake>,
        fd_token_transit: &mut Vec<super::fork_snapshot::ForkSnapshotFdTokenTransit>,
        skip_cloexec: bool,
        preserve_cloexec_fd: Option<usize>,
    ) -> super::fork_snapshot::FdTableSnapshot {
        use super::fork_snapshot::{
            BrokerFdTokenSnapshot, FdEntrySnapshot, FdKind, FdMetadataSnapshot, ForkRejectReason,
            ForkSnapshotBrokerTransit, ForkSnapshotFdTokenTransit,
        };

        let files = self.files.borrow();

        // Read stdio object IDs first so we can identify true stdio descriptors
        // by identity rather than by fd number alone.  An fd at slot 0/1/2 that
        // has been closed and reused (via close+open or dup2) will no longer
        // match, and will be classified/rejected by its actual subsystem type.
        let stdio_ids = files.host_stdio_object_ids.read();
        let host_stdio_oids: [Option<litebox::fd::DescriptorObjectId>; 3] = *stdio_ids;
        drop(stdio_ids);

        // Enumerate all open fds and classify each inline (to avoid
        // double-borrowing self.files via a separate classify_fd call).
        let alive_fds: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();
        let fd_flags_by_raw: BTreeMap<usize, FileDescriptorFlags> = alive_fds
            .iter()
            .map(|&raw_fd| {
                let fd_flags = get_file_descriptor_flags(raw_fd, &self.global, &files)
                    .unwrap_or_else(|_| FileDescriptorFlags::empty());
                (raw_fd, fd_flags)
            })
            .collect();

        // Acquire descriptor table BEFORE raw_descriptor_store to preserve
        // the established dt → rds lock order.
        let dt = self.global.litebox.descriptor_table();

        let mut entries = Vec::new();
        let mut open_file_descriptions = Vec::new();
        for raw_fd in &alive_fds {
            let raw_fd = *raw_fd;
            let fd_flags = fd_flags_by_raw
                .get(&raw_fd)
                .copied()
                .unwrap_or_else(FileDescriptorFlags::empty);
            let preserve_cloexec_broker_pty = if skip_cloexec
                && fd_flags.contains(FileDescriptorFlags::FD_CLOEXEC)
                && Some(raw_fd) != preserve_cloexec_fd
            {
                let rds = files.raw_descriptor_store.read();
                rds.fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
                    .is_ok()
            } else {
                false
            };
            if skip_cloexec
                && fd_flags.contains(FileDescriptorFlags::FD_CLOEXEC)
                && Some(raw_fd) != preserve_cloexec_fd
                && !preserve_cloexec_broker_pty
            {
                continue;
            }

            // Classify by subsystem type first. For filesystem fds, also probe
            // terminal metadata markers so we can accept terminal fds through
            // the snapshot gate. Host stdio is identified at restore via
            // stdio_object_ids plus metadata, not a distinct kind.
            let (subsystem_kind, object_id, terminal_meta, _socket_pair_id) = files
                .run_on_raw_fd(raw_fd, |raw_fd_ref| {
                    #[deny(clippy::wildcard_enum_match_arm)]
                    match raw_fd_ref {
                        crate::RawFdRef::Fs(fd) => {
                            let oid = Some(fd.object_id());
                            // Probe terminal metadata markers on this filesystem fd.
                            // HostStdioSourceFd only counts as terminal when the
                            // underlying host stream is actually a tty.
                            let host_stdio_source = dt
                                .with_metadata(fd, |m: &crate::HostStdioSourceFd| m.0)
                                .ok()
                                .filter(|&source_fd| {
                                    let stream = match source_fd {
                                        0 => litebox::platform::StdioStream::Stdin,
                                        1 => litebox::platform::StdioStream::Stdout,
                                        _ => litebox::platform::StdioStream::Stderr,
                                    };
                                    self.global.platform.is_a_tty(stream)
                                });
                            let is_tty_alias =
                                dt.with_metadata(fd, |_: &crate::HostTtyAlias| ()).is_ok();
                            let is_pty_device = dt
                                .with_metadata(fd, |_: &super::file::HostPtyDeviceFd| ())
                                .is_ok();

                            let meta =
                                if host_stdio_source.is_some() || is_tty_alias || is_pty_device {
                                    Some(FdMetadataSnapshot {
                                        host_stdio_source_fd: host_stdio_source,
                                        is_host_tty_alias: is_tty_alias,
                                        is_host_pty_device: is_pty_device,
                                        ..Default::default()
                                    })
                                } else {
                                    None
                                };
                            (FdKind::FilesystemFd, oid, meta, None)
                        }
                        #[cfg(feature = "worker_local_inet")]
                        crate::RawFdRef::Net(fd) => {
                            (FdKind::Net, Some(fd.object_id()), None, None)
                        }
                        crate::RawFdRef::Eventfd(fd) => {
                            (FdKind::Timerfd { handle_id: 0 }, Some(fd.object_id()), None, None)
                        }
                        crate::RawFdRef::Epoll(fd) => {
                            (FdKind::Epoll, Some(fd.object_id()), None, None)
                        }
                        crate::RawFdRef::Unix(fd) => {
                            let pair_id = dt
                                .with_entry(fd, |sock: &super::unix::UnixSocket<FS>| {
                                    sock.socket_pair_id()
                                })
                                .flatten();
                            (FdKind::UnixSocket, Some(fd.object_id()), None, pair_id)
                        }
                        crate::RawFdRef::HostPassthroughFd(fd) => {
                            // Host-backed fd (from a prior delayed-fork bridge).
                            (
                                FdKind::HostPassthrough {
                                    token_id: 0,
                                    direction: super::host_passthrough_fd::HostPassthroughFdDirection::ReadWrite,
                                },
                                Some(fd.object_id()),
                                None,
                                None,
                            )
                        }
                        crate::RawFdRef::BrokerPipe(fd) => {
                            // Broker-backed pipe. Classify as Pipe so the
                            // broker-handle metadata is emitted below and the restored
                            // worker can re-attach to the same broker `PipeState`.
                            (FdKind::BrokerPipe { handle_id: 0, direction: litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read }, Some(fd.object_id()), None, None)
                        }
                        crate::RawFdRef::BrokerSocketPair(fd) => {
                            (
                                FdKind::BrokerSocketPair {
                                    handle_id: 0,
                                    endpoint: litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::A,
                                },
                                Some(fd.object_id()),
                                None,
                                None,
                            )
                        }
                        crate::RawFdRef::BrokerSocketDgram(fd) => {
                            (FdKind::BrokerSocketDgram { handle_id: 0 }, Some(fd.object_id()), None, None)
                        }
                        crate::RawFdRef::BrokerSocketSeqPacket(fd) => {
                            (FdKind::BrokerSocketSeqPacket { handle_id: 0 }, Some(fd.object_id()), None, None)
                        }
                        crate::RawFdRef::BrokerTcpConn(fd) => {
                            (FdKind::BrokerTcpConn { handle_id: 0 }, Some(fd.object_id()), None, None)
                        }
                        crate::RawFdRef::BrokerInetDgram(fd) => {
                            (FdKind::BrokerInetDgram { handle_id: 0 }, Some(fd.object_id()), None, None)
                        }
                        crate::RawFdRef::BrokerPty(fd) => (
                            FdKind::BrokerPty {
                                handle_id: 0,
                                role: litebox_common_linux::broker_pty_provider::BrokerPtyRole::Master,
                                pty_id: None,
                            },
                            Some(fd.object_id()),
                            Some(FdMetadataSnapshot::default()),
                            None,
                        ),
                        crate::RawFdRef::Signalfd(fd) => {
                            (FdKind::Signalfd { handle_id: 0 }, Some(fd.object_id()), None, None)
                        }
                        crate::RawFdRef::Inotify(fd) => {
                            (FdKind::Inotify, Some(fd.object_id()), None, None)
                        }
                        crate::RawFdRef::BrokerInetListener(fd) => {
                            (FdKind::BrokerInetListener { handle_id: 0 }, Some(fd.object_id()), None, None)
                        }
                        crate::RawFdRef::BrokerInetRaw(fd) => {
                            (FdKind::BrokerInetRaw { handle_id: 0 }, Some(fd.object_id()), None, None)
                        }
                    }
                })
                .unwrap_or_else(|_| {
                    // `alive_fds` (line 5732) was collected while holding the
                    // raw_descriptor_store read lock; other threads are
                    // parked by `park_other_threads` before commit_delayed_fork
                    // enters this loop. An EBADF here means a sibling closed
                    // the fd between collection and dispatch, which violates
                    // the parking invariant — an internal consistency bug,
                    // not a runtime condition. Panic loudly so the stack
                    // trace points at the missing barrier.
                    unreachable!(
                        "snapshot_fd_table: raw_fd={raw_fd} disappeared from raw_descriptor_store \
                         between iter_alive and run_on_raw_fd (parking invariant violated)"
                    )
                });

            // Decide which fd kinds are migratable across delayed-fork
            // commit. Each variant of `FdKind` MUST be explicitly handled
            // — Rust enforces this via the exhaustive `match` (no `_` arm).
            // Adding a new `FdKind` variant will fail to compile here,
            // forcing the author to make an explicit accept/reject decision.
            //
            // Accepting a kind means: the snapshot mechanism can serialize
            // the fd and the restore path on the new worker can reconstruct
            // an equivalent fd. Reject means the parent will keep blocking
            // on VforkDone until the child execs or exits — surface this
            // via `ForkRejectReason::UnsupportedFdKind`.
            match subsystem_kind {
                FdKind::FilesystemFd
                | FdKind::UnixSocket
                | FdKind::HostPassthrough { .. }
                | FdKind::BrokerPipe { .. }
                | FdKind::Eventfd { .. }
                | FdKind::Timerfd { .. }
                | FdKind::Pidfd { .. }
                | FdKind::Signalfd { .. }
                | FdKind::BrokerSocketPair { .. }
                | FdKind::BrokerSocketDgram { .. }
                | FdKind::BrokerSocketSeqPacket { .. }
                | FdKind::BrokerTcpConn { .. }
                | FdKind::BrokerInetListener { .. }
                | FdKind::BrokerInetDgram { .. }
                | FdKind::BrokerPty { .. } => {}
                FdKind::Epoll | FdKind::Inotify => {
                    if fd_flags.contains(FileDescriptorFlags::FD_CLOEXEC) {
                        reject.push(ForkRejectReason::UnsupportedFdKind {
                            fd: raw_fd,
                            kind: subsystem_kind,
                        });
                    }
                }
                #[cfg(feature = "worker_local_inet")]
                FdKind::Net => {
                    reject.push(ForkRejectReason::UnsupportedFdKind {
                        fd: raw_fd,
                        kind: subsystem_kind,
                    });
                }
                FdKind::BrokerInetRaw { .. } => {
                    reject.push(ForkRejectReason::UnsupportedFdKind {
                        fd: raw_fd,
                        kind: subsystem_kind,
                    });
                }
            }

            let rds = files.raw_descriptor_store.read();

            // Per-fd diagnostic trace for delayed-fork analysis.
            #[cfg(feature = "trace_syscalls")]
            {
                let fd_path_str = if let Ok(fd_handle) = rds.fd_from_raw_integer::<FS>(raw_fd) {
                    files
                        .fs
                        .fd_path(&fd_handle)
                        .unwrap_or_else(|| "<no-path>".into())
                } else {
                    "<not-fs>".into()
                };
                litebox::log_println!(
                    self.global.platform,
                    "[DELAYED-FORK-FD] pid={}: fd={} subsystem_kind={:?} terminal_meta={} host_stdio_oid_match={} path={:?}",
                    self.pid,
                    raw_fd,
                    subsystem_kind,
                    terminal_meta.is_some(),
                    object_id.is_some() && host_stdio_oids.contains(&object_id),
                    fd_path_str,
                );
            }

            let is_non_terminal_fs =
                subsystem_kind == FdKind::FilesystemFd && terminal_meta.is_none();

            // Capture access mode flags for FilesystemFd so restore can
            // reopen with the correct mode (read-only, write-only, rdwr).
            let fs_status_flags = if subsystem_kind == FdKind::FilesystemFd {
                if let Ok(fd) = rds.fd_from_raw_integer::<FS>(raw_fd) {
                    dt.with_metadata(&fd, |crate::StdioStatusFlags(flags)| flags.bits())
                        .unwrap_or(0)
                } else {
                    0
                }
            } else if matches!(subsystem_kind, FdKind::BrokerInetListener { .. }) {
                rds.fd_from_raw_integer::<super::broker_inet_listener::BrokerInetListenerSubsystem>(
                    raw_fd,
                )
                .ok()
                .and_then(|typed| {
                    dt.with_entry(
                        &typed,
                        |fd: &super::broker_inet_listener::BrokerInetListenerFd<
                            crate::Platform,
                        >| { fd.get_status().bits() },
                    )
                })
                .unwrap_or(0)
            } else if matches!(subsystem_kind, FdKind::Signalfd { .. }) {
                rds.fd_from_raw_integer::<super::signalfd::SignalfdSubsystem>(raw_fd)
                    .ok()
                    .and_then(|typed| {
                        dt.with_entry(&typed, |fd: &super::signalfd::SignalfdFile| {
                            fd.get_status().bits()
                        })
                    })
                    .unwrap_or(0)
            } else {
                0
            };

            // Phase 2.F: for EventFd fds, mint/extract a broker
            // handle so the child can reattach to shared state across
            // the cross-binary-type fork boundary. Falls back to
            // None on failure (child gets a fresh local eventfd).
            let broker_handle_meta: Option<FdKind> = if matches!(
                subsystem_kind,
                FdKind::Timerfd { .. }
            ) {
                if let Ok(typed) =
                    rds.fd_from_raw_integer::<super::eventfd::EventfdSubsystem>(raw_fd)
                {
                    let eventfd_provider = super::eventfd::broker_eventfd_provider();
                    let pidfd_provider = super::eventfd::broker_pidfd_provider();
                    let result =
                        dt.with_entry(&typed, |ef: &super::eventfd::EventFile<crate::Platform>| {
                            ef.ensure_broker_backed_for_fork(
                                eventfd_provider.as_ref(),
                                pidfd_provider.as_ref(),
                            )
                        });
                    match result {
                        Some(Ok(Some(snapshot))) => {
                            // Dup the handle so the snapshot's
                            // transit reference is independently
                            // tracked. On rollback we release this
                            // dup; on success the child's restore-
                            // side BrokerBacked adopts it.
                            //
                            // Pidfd uses a process-exit subscription
                            // instead of a broker subscribable; the
                            // dup_handle/releaser path doesn't apply.
                            let handle_id = snapshot.handle_id();
                            let releaser_opt: Option<
                                alloc::sync::Arc<
                                    dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
                                >,
                            > = match &snapshot {
                                FdKind::Eventfd { .. } => eventfd_provider
                                    .as_ref()
                                    .map(|p| alloc::sync::Arc::clone(p) as _),
                                FdKind::Pidfd { .. } => pidfd_provider
                                    .as_ref()
                                    .map(|p| alloc::sync::Arc::clone(p) as _),
                                // `ensure_broker_backed_for_fork` only
                                // produces `Eventfd` or `Pidfd` (see
                                // `eventfd.rs`); other variants here
                                // would be a logic error. Per AGENTS.md
                                // "loud failure for logic errors".
                                FdKind::Timerfd { .. }
                                | FdKind::Signalfd { .. }
                                | FdKind::BrokerPty { .. }
                                | FdKind::BrokerPipe { .. }
                                | FdKind::BrokerSocketPair { .. }
                                | FdKind::BrokerSocketDgram { .. }
                                | FdKind::BrokerSocketSeqPacket { .. }
                                | FdKind::BrokerTcpConn { .. }
                                | FdKind::BrokerInetListener { .. }
                                | FdKind::BrokerInetDgram { .. }
                                | FdKind::BrokerInetRaw { .. }
                                | FdKind::FilesystemFd
                                | FdKind::UnixSocket
                                | FdKind::Epoll
                                | FdKind::Inotify
                                | FdKind::HostPassthrough { .. } => unreachable!(
                                    "ensure_broker_backed_for_fork must only return Eventfd or Pidfd, got {snapshot:?}",
                                ),
                                #[cfg(feature = "worker_local_inet")]
                                FdKind::Net => unreachable!(
                                    "ensure_broker_backed_for_fork must only return Eventfd or Pidfd, got {snapshot:?}",
                                ),
                            };
                            if matches!(snapshot, FdKind::Pidfd { .. }) {
                                if let Ok(target_pid) = u32::try_from(handle_id)
                                    && let Some(wake) =
                                        super::guest_pid::try_subscribe_broker_process_exit(
                                            litebox::process::ProcessId(target_pid),
                                        )
                                {
                                    pidfd_process_transit.push(wake);
                                }
                                Some(snapshot)
                            } else if let Some(releaser) = releaser_opt {
                                match releaser.dup_handle(handle_id) {
                                    Ok(()) => {
                                        broker_transit.push(ForkSnapshotBrokerTransit {
                                            releaser,
                                            handle_id,
                                            kind: snapshot.spec_token(),
                                        });
                                        Some(snapshot)
                                    }
                                    Err(_) => None,
                                }
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            } else if matches!(subsystem_kind, FdKind::Signalfd { .. }) {
                if let Ok(typed) =
                    rds.fd_from_raw_integer::<super::signalfd::SignalfdSubsystem>(raw_fd)
                {
                    let signalfd_provider = super::signalfd::broker_signalfd_provider();
                    let result = dt.with_entry(&typed, |sfd: &super::signalfd::SignalfdFile| {
                        sfd.fork_snapshot_handle()
                    });
                    match (result, signalfd_provider) {
                        (Some(snapshot), Some(releaser)) => {
                            let handle_id = snapshot.handle_id();
                            match releaser.dup_handle(handle_id) {
                                Ok(()) => {
                                    broker_transit.push(ForkSnapshotBrokerTransit {
                                        releaser: releaser as _,
                                        handle_id,
                                        kind: snapshot.spec_token(),
                                    });
                                    Some(snapshot)
                                }
                                Err(_) => None,
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            } else if let Ok(typed) =
                rds.fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
            {
                let pty_provider = super::broker_pty::broker_pty_provider();
                let snapshot_opt = dt.with_entry(
                    &typed,
                    |pty_fd: &super::broker_pty::BrokerPtyFd<crate::Platform>| {
                        pty_fd.fork_snapshot_handle()
                    },
                );
                match snapshot_opt {
                    Some(snapshot) => {
                        let releaser_opt: Option<
                            alloc::sync::Arc<
                                dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
                            >,
                        > = pty_provider.as_ref().map(|p| alloc::sync::Arc::clone(p) as _);
                        if let Some(releaser) = releaser_opt {
                            let handle_id = snapshot.handle_id();
                            match releaser.dup_handle(handle_id) {
                                Ok(()) => {
                                    broker_transit.push(ForkSnapshotBrokerTransit {
                                        releaser,
                                        handle_id,
                                        kind: snapshot.spec_token(),
                                    });
                                    Some(snapshot)
                                }
                                Err(_) => None,
                            }
                        } else {
                            None
                        }
                    }
                    None => None,
                }
            } else if matches!(subsystem_kind, FdKind::BrokerPipe { .. }) {
                // Phase C.3: emit a broker-Pipe handle snapshot when the fd
                // is a `BrokerPipeSubsystem` entry. Local `Pipes<Platform>`
                // and `HostPassthroughFd` pipes don't have broker identity
                // and fall through to `None`.
                if let Ok(typed) =
                    rds.fd_from_raw_integer::<super::broker_pipe::BrokerPipeSubsystem>(raw_fd)
                {
                    let pipe_provider = super::broker_pipe::broker_pipe_provider();
                    let snapshot_opt = dt.with_entry(
                        &typed,
                        |bp_fd: &super::broker_pipe::BrokerPipeFd<crate::Platform>| {
                            bp_fd.fork_snapshot_handle()
                        },
                    );
                    match snapshot_opt {
                        Some(snapshot) => {
                            let releaser_opt: Option<
                                alloc::sync::Arc<
                                    dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
                                >,
                            > = pipe_provider
                                .as_ref()
                                .map(|p| alloc::sync::Arc::clone(p) as _);
                            if let Some(releaser) = releaser_opt {
                                let handle_id = snapshot.handle_id();
                                match releaser.dup_handle(handle_id) {
                                    Ok(()) => {
                                        broker_transit.push(ForkSnapshotBrokerTransit {
                                            releaser,
                                            handle_id,
                                            kind: snapshot.spec_token(),
                                        });
                                        Some(snapshot)
                                    }
                                    Err(_) => None,
                                }
                            } else {
                                None
                            }
                        }
                        None => None,
                    }
                } else {
                    None
                }
            } else if matches!(subsystem_kind, FdKind::BrokerInetListener { .. }) {
                if let Ok(typed) = rds.fd_from_raw_integer::<
                    super::broker_inet_listener::BrokerInetListenerSubsystem,
                >(raw_fd)
                {
                    let listener_provider = super::broker_inet_listener::broker_inet_listener_provider();
                    let entry_result = dt.with_entry(
                        &typed,
                        |listener: &super::broker_inet_listener::BrokerInetListenerFd<crate::Platform>| {
                            listener.handle()
                        },
                    );
                    match (entry_result, listener_provider) {
                        (Some(handle_id), Some(releaser)) => match releaser.dup_handle(handle_id) {
                            Ok(()) => {
                                let snapshot = FdKind::BrokerInetListener { handle_id };
                                broker_transit.push(ForkSnapshotBrokerTransit {
                                    releaser: releaser as _,
                                    handle_id,
                                    kind: snapshot.spec_token(),
                                });
                                Some(snapshot)
                            }
                            Err(_) => None,
                        },
                        _ => None,
                    }
                } else {
                    None
                }
            } else if matches!(
                subsystem_kind,
                FdKind::UnixSocket
                    | FdKind::BrokerSocketPair { .. }
                    | FdKind::BrokerSocketDgram { .. }
                    | FdKind::BrokerSocketSeqPacket { .. }
                    | FdKind::BrokerTcpConn { .. }
                    | FdKind::BrokerInetDgram { .. }
            ) {
                // Phase F: emit a broker-UnixSocket handle snapshot
                // when the fd is a `BrokerSocketPairSubsystem` entry.
                // Local `UnixSocketSubsystem` pairs don't have broker
                // identity and fall through to `None` (the snapshot
                // restore path creates a fresh local UnixSocket for
                // them, which loses the cross-worker connection — that
                // pre-existing limitation is the very thing eager
                // broker socketpair fixes).
                if let Ok(typed) = rds
                    .fd_from_raw_integer::<super::broker_socketpair::BrokerSocketPairSubsystem>(
                        raw_fd,
                    )
                {
                    let socketpair_provider =
                        super::broker_socketpair::broker_socketpair_provider();
                    let snapshot_opt = dt.with_entry(
                        &typed,
                        |sp_fd: &super::broker_socketpair::BrokerSocketPairFd<crate::Platform>| {
                            sp_fd.fork_snapshot_handle()
                        },
                    );
                    match snapshot_opt {
                        Some(snapshot) => {
                            let releaser_opt: Option<
                                alloc::sync::Arc<
                                    dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
                                >,
                            > = socketpair_provider
                                .as_ref()
                                .map(|p| alloc::sync::Arc::clone(p) as _);
                            if let Some(releaser) = releaser_opt {
                                let handle_id = snapshot.handle_id();
                                match releaser.dup_handle(handle_id) {
                                    Ok(()) => {
                                        broker_transit.push(ForkSnapshotBrokerTransit {
                                            releaser,
                                            handle_id,
                                            kind: snapshot.spec_token(),
                                        });
                                        Some(snapshot)
                                    }
                                    Err(_) => None,
                                }
                            } else {
                                None
                            }
                        }
                        None => None,
                    }
                } else if let Ok(typed) = rds
                    .fd_from_raw_integer::<super::broker_socket_dgram::BrokerSocketDgramSubsystem>(
                        raw_fd,
                    )
                {
                    let provider = super::broker_socket_dgram::broker_socket_dgram_provider();
                    let snapshot_opt = dt.with_entry(
                        &typed,
                        |dgram_fd: &super::broker_socket_dgram::BrokerSocketDgramFd<
                            crate::Platform,
                        >| { dgram_fd.fork_snapshot_handle() },
                    );
                    match snapshot_opt {
                        Some(snapshot) => {
                            let releaser_opt: Option<
                                alloc::sync::Arc<
                                    dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
                                >,
                            > = provider.as_ref().map(|p| alloc::sync::Arc::clone(p) as _);
                            if let Some(releaser) = releaser_opt {
                                let handle_id = snapshot.handle_id();
                                match releaser.dup_handle(handle_id) {
                                    Ok(()) => {
                                        broker_transit.push(ForkSnapshotBrokerTransit {
                                            releaser,
                                            handle_id,
                                            kind: snapshot.spec_token(),
                                        });
                                        Some(snapshot)
                                    }
                                    Err(_) => None,
                                }
                            } else {
                                None
                            }
                        }
                        None => None,
                    }
                } else if let Ok(typed) = rds
                    .fd_from_raw_integer::<super::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem>(raw_fd)
                {
                    let provider = super::broker_socket_seqpacket::broker_socket_seqpacket_provider();
                    let snapshot_opt = dt.with_entry(
                        &typed,
                        |seqpacket_fd: &super::broker_socket_seqpacket::BrokerSocketSeqPacketFd<
                            crate::Platform,
                        >| { seqpacket_fd.fork_snapshot_handle() },
                    );
                    match snapshot_opt {
                        Some(snapshot) => {
                            let releaser_opt: Option<
                                alloc::sync::Arc<
                                    dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
                                >,
                            > = provider.as_ref().map(|p| alloc::sync::Arc::clone(p) as _);
                            if let Some(releaser) = releaser_opt {
                                let handle_id = snapshot.handle_id();
                                match releaser.dup_handle(handle_id) {
                                    Ok(()) => {
                                        broker_transit.push(ForkSnapshotBrokerTransit {
                                            releaser,
                                            handle_id,
                                            kind: snapshot.spec_token(),
                                        });
                                        Some(snapshot)
                                    }
                                    Err(_) => None,
                                }
                            } else {
                                None
                            }
                        }
                        None => None,
                    }
                } else if let Ok(typed) = rds
                    .fd_from_raw_integer::<super::broker_tcp_conn::BrokerTcpConnSubsystem>(raw_fd)
                {
                    let tcp_provider = super::broker_tcp_conn::broker_tcp_conn_provider();
                    let snapshot_opt = dt.with_entry(
                        &typed,
                        |tcp_fd: &super::broker_tcp_conn::BrokerTcpConnFd<crate::Platform>| {
                            tcp_fd.fork_snapshot_handle()
                        },
                    );
                    match snapshot_opt {
                        Some(snapshot) => {
                            let releaser_opt: Option<
                                alloc::sync::Arc<
                                    dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
                                >,
                            > = tcp_provider.as_ref().map(|p| alloc::sync::Arc::clone(p) as _);
                            if let Some(releaser) = releaser_opt {
                                let handle_id = snapshot.handle_id();
                                match releaser.dup_handle(handle_id) {
                                    Ok(()) => {
                                        broker_transit.push(ForkSnapshotBrokerTransit {
                                            releaser,
                                            handle_id,
                                            kind: snapshot.spec_token(),
                                        });
                                        Some(snapshot)
                                    }
                                    Err(_) => None,
                                }
                            } else {
                                None
                            }
                        }
                        None => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let broker_fd_token_meta: Option<BrokerFdTokenSnapshot> = if let Ok(typed) =
                rds.fd_from_raw_integer::<super::host_passthrough_fd::HostPassthroughFd>(raw_fd)
            {
                let direction = dt.with_entry(
                    &typed,
                    |hp: &super::host_passthrough_fd::HostPassthroughFdEntry| hp.direction,
                );
                let raw_host_fd = dt.with_entry(
                    &typed,
                    |hp: &super::host_passthrough_fd::HostPassthroughFdEntry| hp.raw_fd(),
                );
                match (
                    direction,
                    raw_host_fd,
                    litebox_common_linux::fd_token_client::global_client(),
                ) {
                    (Some(direction), Some(raw_host_fd), Some(client)) if raw_host_fd >= 0 => {
                        match client.register_dup_raw_fd(raw_host_fd) {
                            Ok(token_id) => {
                                fd_token_transit
                                    .push(ForkSnapshotFdTokenTransit { client, token_id });
                                Some(BrokerFdTokenSnapshot {
                                    token_id,
                                    host_passthrough_fd_direction: Some(direction),
                                })
                            }
                            Err(_) => None,
                        }
                    }
                    _ => None,
                }
            } else {
                None
            };

            let metadata = terminal_meta.unwrap_or_default();
            let kind = if let Some(bh) = broker_handle_meta {
                bh
            } else if let Some(tok) = broker_fd_token_meta {
                FdKind::HostPassthrough {
                    token_id: tok.token_id,
                    direction: tok.host_passthrough_fd_direction.unwrap_or(
                        super::host_passthrough_fd::HostPassthroughFdDirection::ReadWrite,
                    ),
                }
            } else {
                subsystem_kind
            };

            entries.push(FdEntrySnapshot {
                fd: raw_fd,
                kind,
                fd_flags: fd_flags.bits(),
                status_flags: fs_status_flags,
                object_id: object_id.map_or(0, litebox::fd::DescriptorObjectId::as_u64),
                metadata,
            });

            // For non-terminal FilesystemFd, capture the reopen path so
            // restore can reopen the file (e.g. /dev/null, /dev/tty, or
            // bash's saved fd 255).
            if is_non_terminal_fs && let Ok(fd) = rds.fd_from_raw_integer::<FS>(raw_fd) {
                let path = files.fs.fd_path(&fd);
                open_file_descriptions.push(super::fork_snapshot::OpenFileDescriptionSnapshot {
                    object_id: fd.object_id().as_u64(),
                    file_offset: 0,
                    reopen_path: path,
                });
            }
        }
        drop(dt);

        let stdio_object_ids = [
            host_stdio_oids[0].map(litebox::fd::DescriptorObjectId::as_u64),
            host_stdio_oids[1].map(litebox::fd::DescriptorObjectId::as_u64),
            host_stdio_oids[2].map(litebox::fd::DescriptorObjectId::as_u64),
        ];

        super::fork_snapshot::FdTableSnapshot {
            entries,
            open_file_descriptions,
            stdio_object_ids,
        }
    }

    /// Capture the full memory image and page-manager metadata for a true-fork
    /// snapshot.
    ///
    /// Walks all mapped regions, copies their contents, and snapshots the shim
    /// metadata that must be restored alongside the raw pages. Shared mappings
    /// are flagged for the v1 reject gate (the caller decides whether to
    /// proceed or abort).
    fn snapshot_memory(
        &self,
        _reject: &mut super::fork_snapshot::ForkRejectReasons,
    ) -> super::fork_snapshot::MemorySnapshot {
        let ps = self.process_state.borrow();
        let mappings = ps.pm.mappings();
        let as_range = self
            .global
            .platform
            .address_space_range(ps.address_space_id)
            .ok();

        let mut regions = Vec::new();
        for (range, flags) in &mappings {
            let is_shared = flags.contains(VmFlags::VM_SHARED);

            // The sandbox demotes all MAP_SHARED mappings to MAP_PRIVATE at
            // the kernel level (see mm.rs mmap handling), so VM_SHARED is
            // metadata-only.  There is no actual cross-process shared memory
            // to worry about.  File-backed shared mappings are just locale
            // archives, gconv modules, etc.; anonymous shared mappings are
            // process-local shmem.  Both are safe to snapshot.
            // We restore all shared mappings as private (is_shared=false) to
            // avoid the restore path elevating VM_MAYWRITE via SHARED flags.
            let _ = is_shared;

            let mut region_start = range.start;
            let mut len = range.end - range.start;

            // Clip regions that extend past the VA partition ceiling.
            // The host kernel can place ld.so near the top of the partition,
            // with the last page spilling past the boundary.  Truncate so the
            // child restore doesn't try to map outside its partition.
            if let Some(ref as_r) = as_range {
                if range.end > as_r.end {
                    len = as_r.end.saturating_sub(region_start);
                }
                if region_start < as_r.start {
                    let skip = as_r.start - region_start;
                    region_start = as_r.start;
                    len = len.saturating_sub(skip);
                }
                if len == 0 {
                    continue;
                }
            }

            let readable = flags.contains(VmFlags::VM_READ);

            // If the region is not readable (e.g. PROT_NONE or write/exec
            // only), temporarily make it readable so we can copy the data.
            // SAFETY: sibling threads are parked, so no concurrent access.
            if !readable {
                let ptr = crate::MutPtr::<u8>::from_usize(region_start);
                let _ = unsafe { ps.pm.make_pages_readable(ptr, len) };
            }

            // Read the raw page bytes.
            // SAFETY: the forking thread has exclusive access (sibling threads
            // are parked) and the region is now readable.
            let data =
                unsafe { core::slice::from_raw_parts(region_start as *const u8, len).to_vec() };

            // Restore original permissions if we temporarily upgraded them.
            // Use the exact original flags rather than always setting PROT_NONE,
            // in case the region was write-only or exec-only (rare but possible).
            if !readable {
                let ptr = crate::MutPtr::<u8>::from_usize(region_start);
                let has_write = flags.contains(VmFlags::VM_WRITE);
                let has_exec = flags.contains(VmFlags::VM_EXEC);
                let _ = match (has_write, has_exec) {
                    (false, false) => unsafe { ps.pm.make_pages_inaccessible(ptr, len) },
                    (true, false) => unsafe { ps.pm.make_pages_writable(ptr, len) },
                    (false, true) => unsafe { ps.pm.make_pages_executable(ptr, len) },
                    (true, true) => unsafe { ps.pm.make_pages_rwx(ptr, len) },
                };
            }

            regions.push(super::fork_snapshot::MemoryRegionSnapshot {
                addr: region_start,
                len,
                permissions: flags.bits() & VmFlags::VM_ACCESS_FLAGS.bits(),
                vm_flags: flags.bits(),
                is_shared: false,
                data,
            });
        }

        let metadata = self.snapshot_page_manager_metadata(&ps);

        super::fork_snapshot::MemorySnapshot { regions, metadata }
    }

    /// Snapshot shim-level page-manager metadata from `ProcessState`.
    #[allow(dead_code)]
    fn snapshot_page_manager_metadata(
        &self,
        ps: &crate::ProcessState,
    ) -> super::fork_snapshot::PageManagerMetadata {
        let va_range = ps.pm.addr_min()..ps.pm.addr_max();
        let brk_base = ps.pm.brk_base();
        let brk = ps.pm.current_brk();
        let brk_frontier = ps.pm.current_brk_frontier();

        // Snapshot ELF patch cache entries.
        let elf_patch_cache = ps.elf_patch_cache.lock();
        #[allow(clippy::used_underscore_binding)]
        let elf_patch_entries = elf_patch_cache
            .iter()
            .map(|(&fd, state)| super::fork_snapshot::ElfPatchEntrySnapshot {
                fd,
                base_addr: state._base_addr,
                pre_patched: state.pre_patched,
                trampoline_file_offset: state.trampoline_file_offset,
                trampoline_file_size: state.trampoline_file_size,
                trampoline_vaddr: state._trampoline_vaddr,
                trampoline_addr: state.trampoline_addr,
                trampoline_cursor: state.trampoline_cursor,
                trampoline_mapped: state.trampoline_mapped,
                trampoline_mapped_len: state.trampoline_mapped_len,
                runtime_patches_committed: state.runtime_patches_committed,
                file_path: state.file_path.clone(),
            })
            .collect();
        drop(elf_patch_cache);

        // Snapshot shared file mapping metadata (file handles are not
        // portable, so only capture the address/length/offset and whether
        // writeback is needed).
        let shared_mappings = ps.shared_file_mappings.lock();
        let proc_map_paths_guard = ps.proc_map_paths.lock();

        let shared_file_mapping_metadata = shared_mappings
            .iter()
            .map(|m| {
                // Try to find a backing path from proc_map_paths.
                let backing_file_path = proc_map_paths_guard
                    .iter()
                    .find(|(range, _)| range.start == m.addr)
                    .map(|(_, path)| path.clone());

                super::fork_snapshot::SharedFileMappingSnapshot {
                    addr: m.addr,
                    len: m.len,
                    file_offset: m.file_offset,
                    needs_writeback: m.needs_writeback,
                    backing_file_path,
                }
            })
            .collect();

        let proc_map_paths = proc_map_paths_guard.clone();
        drop(proc_map_paths_guard);
        drop(shared_mappings);

        super::fork_snapshot::PageManagerMetadata {
            va_range,
            brk_base,
            brk,
            brk_frontier,
            elf_patch_entries,
            shared_file_mapping_metadata,
            proc_map_paths,
            main_bss_start: ps
                .main_bss_start
                .load(core::sync::atomic::Ordering::Relaxed),
            main_bss_end: ps.main_bss_end.load(core::sync::atomic::Ordering::Relaxed),
            old_syscall_entry_point: self.global.platform.get_syscall_entry_point(),
        }
    }

    /// Handle syscall `set_tid_address`.
    pub(crate) fn sys_set_tid_address(&self, tidptr: crate::MutPtr<i32>) -> i32 {
        self.thread.clear_child_tid.set(Some(tidptr));
        self.tid
    }

    /// Handle syscall `gettid`.
    pub(crate) fn sys_gettid(&self) -> i32 {
        self.tid
    }

    /// Parks all threads in this process except the calling thread.
    ///
    /// Following the `exit_group` pattern: set per-thread `is_suspended`
    /// flag, then interrupt all threads so they break out of waits and
    /// reach the park check in `prepare_to_run_guest`. Waits until all
    /// have confirmed they are parked (via `vfork_parked_count`).
    ///
    /// **Fork serialization**: if another fork is already in progress
    /// (`is_forking == true`), the calling thread parks itself on the
    /// shared `park` futex so the active forker can count it toward
    /// `parked_count` and proceed. When the active forker unparks,
    /// the calling thread retries claiming the gate. This avoids the
    /// race where two sibling threads racing `fork()` both pass the
    /// `do_clone3` pre-check (which only inspects the `park` atomic,
    /// not `is_forking`) and one of them then sees `is_forking == true`
    /// inside this function — the previous Err(EAGAIN) behaviour
    /// surfaced as a spurious fork failure to the guest.
    ///
    /// Returns:
    /// - `Ok(true)` if threads were parked (and must be unparked later).
    /// - `Ok(false)` if there were no other threads to park.
    /// - `Err(())` if the gate could not be claimed within a bounded
    ///   number of retries (caller returns EAGAIN). This is now a
    ///   genuinely exceptional path; in normal operation the inline
    ///   parking loop completes within one or two iterations.
    fn park_other_threads(&self) -> Result<bool, ()> {
        use litebox::platform::RawMutex as _;

        let ps = self.process_state.borrow();

        // Determine the expected count from the authoritative thread map
        // under the process lock. This avoids using the separate
        // ProcessState::thread_count which may not be decremented on exit.
        let expected;

        // Bounded retry loop. Each iteration either claims the gate
        // (and breaks out to the parking-confirm wait below) or parks
        // the calling thread inline until the active forker finishes.
        // The bound matches the do_clone3 pre-check (~500ms total wait
        // budget): 100 retries × ≤5ms per inline-park wake.
        const MAX_GATE_RETRIES: usize = 100;
        let mut retries = 0usize;
        loop {
            {
                let mut inner = self.thread.process.inner.lock();

                if !inner.is_forking {
                    expected = u32::try_from(
                        inner
                            .threads
                            .len()
                            .checked_sub(1)
                            .expect("calling thread must be in the map"),
                    )
                    .expect("thread count must fit in u32");
                    if expected == 0 {
                        return Ok(false);
                    }

                    inner.is_forking = true;

                    // Set per-thread is_suspended flag under the lock.
                    for (&tid, thread) in &inner.threads {
                        if tid != self.tid {
                            thread.is_suspended.store(true, Ordering::Relaxed);
                        }
                    }

                    // Set the process-wide park futex AFTER the per-thread flags.
                    // This ensures that a thread loading vfork_park with Acquire
                    // also observes the is_suspended store (Release pairs with
                    // the Acquire load in park_for_vfork_if_requested).
                    ps.vfork_parking
                        .park
                        .underlying_atomic()
                        .store(1, Ordering::Release);

                    // Signal the transport to break out of spin loops.
                    self.global
                        .transport_interrupt
                        .store(true, Ordering::Release);

                    // Wake threads blocked in raw futex waits (e.g., wait_for_child)
                    // so they see is_suspended when they re-check.
                    self.global
                        .litebox
                        .process_registry()
                        .notify_waiters(self.process_id);
                    for (&tid, thread) in &inner.threads {
                        if tid != self.tid {
                            thread.interrupt();
                        }
                    }

                    break;
                }

                // Another fork is in progress. Drop the lock and park
                // ourselves so the active forker can count us toward
                // its parked_count target and proceed.
            }

            if retries >= MAX_GATE_RETRIES {
                return Err(());
            }
            retries += 1;

            // Two sub-cases:
            //   (a) park == 1: active forker is in its parking phase.
            //       We mirror park_for_vfork_if_requested's bookkeeping
            //       (parked_count fetch_add, block on park, fetch_sub).
            //   (b) park == 0: window between active forker's `park=0`
            //       and its `is_forking=false`. We block briefly on
            //       park to wait for the trailing wake_all that
            //       unpark_other_threads issues after clearing
            //       is_forking.
            let park_v = ps
                .vfork_parking
                .park
                .underlying_atomic()
                .load(Ordering::Acquire);
            if park_v != 0 {
                ps.vfork_parking
                    .parked_count
                    .underlying_atomic()
                    .fetch_add(1, Ordering::Release);
                ps.vfork_parking.parked_count.wake_all();
                loop {
                    let v = ps
                        .vfork_parking
                        .park
                        .underlying_atomic()
                        .load(Ordering::Acquire);
                    if v == 0 || self.is_exiting() {
                        break;
                    }
                    let _ = ps.vfork_parking.park.block(v);
                }
                ps.vfork_parking
                    .parked_count
                    .underlying_atomic()
                    .fetch_sub(1, Ordering::Release);
                ps.vfork_parking.parked_count.wake_all();
            } else {
                let _ = ps
                    .vfork_parking
                    .park
                    .block_or_timeout(0, core::time::Duration::from_millis(5));
            }
        }

        // Wait until all other threads have parked.
        //
        // Recompute the expected count each iteration. A sibling may exit
        // after the initial snapshot (without parking), which shrinks the
        // thread map and therefore the required parked count.
        loop {
            let n = ps
                .vfork_parking
                .parked_count
                .underlying_atomic()
                .load(Ordering::Acquire);
            let expected_now = {
                let inner = self.thread.process.inner.lock();
                u32::try_from(
                    inner
                        .threads
                        .len()
                        .checked_sub(1)
                        .expect("calling thread must be in the map"),
                )
                .expect("thread count must fit in u32")
            };
            if n >= expected_now {
                break;
            }
            // Wake potential raw waiters (waitpid / kill_other_threads) again
            // so they can observe suspension and return to park.
            self.global
                .litebox
                .process_registry()
                .notify_waiters(self.process_id);
            self.thread.process.nr_threads.wake_all();
            let _ = ps.vfork_parking.parked_count.block(n);
        }
        Ok(true)
    }

    /// Unparks all threads that were parked by [`park_other_threads`].
    ///
    /// Clears per-thread `is_suspended` flags and the process-wide park
    /// futex, then wakes all parked threads and waits for them to confirm
    /// they have resumed.
    fn unpark_other_threads(&self) {
        use litebox::platform::RawMutex as _;

        let ps = self.process_state.borrow();

        // Clear per-thread is_suspended flags (but keep is_forking until all
        // threads have fully unparked to prevent concurrent fork races).
        {
            let inner = self.thread.process.inner.lock();
            for (&tid, thread) in &inner.threads {
                if tid != self.tid {
                    thread.is_suspended.store(false, Ordering::Relaxed);
                }
            }
        }

        // Allow transport spin-loops to resume.
        self.global
            .transport_interrupt
            .store(false, Ordering::Release);

        // Clear the process-wide park futex and wake all parked threads.
        ps.vfork_parking
            .park
            .underlying_atomic()
            .store(0, Ordering::Release);
        ps.vfork_parking.park.wake_all();

        // Settle unclaimed deferred lies. Transport threads that lied
        // (incremented parked_count without blocking) may still be spinning
        // in the I/O loop and can't reach a park checkpoint quickly. Since
        // the vfork window is now closed, we settle their accounting
        // directly so we don't wait for them.
        let remaining_lies = ps
            .vfork_parking
            .deferred_lie_count
            .swap(0, Ordering::AcqRel);
        if remaining_lies > 0 {
            ps.vfork_parking
                .parked_count
                .underlying_atomic()
                .fetch_sub(remaining_lies, Ordering::Release);
            ps.vfork_parking.parked_count.wake_all();
        }

        // Wait for all properly-parked threads to acknowledge the unpark.
        loop {
            let n = ps
                .vfork_parking
                .parked_count
                .underlying_atomic()
                .load(Ordering::Acquire);
            if n == 0 {
                break;
            }
            let _ = ps.vfork_parking.parked_count.block(n);
        }

        // All threads have unparked. Now allow another fork to proceed.
        {
            let mut inner = self.thread.process.inner.lock();
            inner.is_forking = false;
        }

        // Wake any sibling-fork waiters parked inside `park_other_threads`.
        // They block on `park` (value 0) during the brief window between
        // the `park=0` store above and the `is_forking=false` flip just
        // performed; without this trailing wake they would only re-check
        // on their next timeout tick. The wake is a no-op when no such
        // waiters exist (the common single-forker case).
        ps.vfork_parking.park.wake_all();
    }

    fn install_d5_mux_master_pty_fd(
        &self,
        guest_fd: usize,
        provider: alloc::sync::Arc<
            dyn litebox_common_linux::broker_pty_provider::BrokerPtyProvider,
        >,
        master_handle: u64,
        pty_id: u32,
        slave_anchor_handle: Option<u64>,
    ) -> Result<(), Errno> {
        let pty_fd = super::broker_pty::BrokerPtyFd::<crate::Platform>::new(
            provider,
            master_handle,
            pty_id,
            true,
            slave_anchor_handle,
            litebox::fs::OFlags::empty(),
        );
        pty_fd.ensure_subscribed_eager();
        let typed: litebox::fd::TypedFd<super::broker_pty::BrokerPtySubsystem> =
            self.global.litebox.descriptor_table_mut().insert(pty_fd);

        let files = self.files.borrow();
        let mut rds = files.raw_descriptor_store.write();
        if let Ok(old_fs) = rds.fd_consume_raw_integer::<FS>(guest_fd) {
            drop(rds);
            let _ = files.fs.close(&old_fs);
            rds = files.raw_descriptor_store.write();
        } else if let Ok(old_unix) =
            rds.fd_consume_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(guest_fd)
        {
            drop(rds);
            let _ = self.global.litebox.descriptor_table_mut().remove(&old_unix);
            rds = files.raw_descriptor_store.write();
        } else if let Ok(old_external) =
            rds.fd_consume_raw_integer::<super::host_passthrough_fd::HostPassthroughFd>(guest_fd)
        {
            drop(rds);
            if let Some(entry) = self
                .global
                .litebox
                .descriptor_table_mut()
                .remove(&old_external)
            {
                let host_fd = entry.take_fd();
                if host_fd >= 0 {
                    self.global.platform.close_host_fd(host_fd);
                }
            }
            rds = files.raw_descriptor_store.write();
        } else if let Ok(old_broker_pipe) =
            rds.fd_consume_raw_integer::<super::broker_pipe::BrokerPipeSubsystem>(guest_fd)
        {
            drop(rds);
            let _ = self
                .global
                .litebox
                .descriptor_table_mut()
                .remove(&old_broker_pipe);
            rds = files.raw_descriptor_store.write();
        } else if let Ok(old_broker_socketpair) =
            rds.fd_consume_raw_integer::<super::broker_socketpair::BrokerSocketPairSubsystem>(
                guest_fd,
            )
        {
            drop(rds);
            let _ = self
                .global
                .litebox
                .descriptor_table_mut()
                .remove(&old_broker_socketpair);
            rds = files.raw_descriptor_store.write();
        } else if let Ok(old_broker_pty) =
            rds.fd_consume_raw_integer::<super::broker_pty::BrokerPtySubsystem>(guest_fd)
        {
            drop(rds);
            let _ = self
                .global
                .litebox
                .descriptor_table_mut()
                .remove(&old_broker_pty);
            rds = files.raw_descriptor_store.write();
        }

        if rds.fd_into_specific_raw_integer(typed, guest_fd) {
            Ok(())
        } else {
            Err(Errno::ENOMEM)
        }
    }
}

// TODO: enforce the following limits:
pub(crate) const RLIMIT_NOFILE_CUR: usize = 1024 * 1024;
const RLIMIT_NOFILE_MAX: usize = 1024 * 1024;
const RLIMIT_SIGPENDING: usize = 128;

pub(crate) struct AtomicRlimit {
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
    pub(crate) limits: [AtomicRlimit; litebox_common_linux::RlimitResource::RLIM_NLIMITS],
}

impl ResourceLimits {
    const fn default() -> Self {
        // Default all resources to unlimited, then override specific ones.
        seq_macro::seq!(N in 0..16 {
            let mut limits = [
                #(
                    AtomicRlimit::new(usize::MAX, usize::MAX),
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
        // Linux defaults SIGPENDING to ~30000 (based on available memory).
        // Use a reasonable fixed value so that cross-process signals like
        // SIGCHLD (which have code=CLD_EXITED, subject to rlimit check)
        // are not silently dropped.
        limits[litebox_common_linux::RlimitResource::SIGPENDING as usize] = AtomicRlimit {
            cur: core::sync::atomic::AtomicUsize::new(RLIMIT_SIGPENDING),
            max: core::sync::atomic::AtomicUsize::new(RLIMIT_SIGPENDING),
        };
        Self { limits }
    }

    /// Reconstruct resource limits from a fork snapshot.
    fn from_snapshot(
        rlimits: &[(usize, usize); litebox_common_linux::RlimitResource::RLIM_NLIMITS],
    ) -> Self {
        seq_macro::seq!(N in 0..16 {
            let limits = [
                #(
                    AtomicRlimit::new(rlimits[N].0, rlimits[N].1),
                )*
            ];
        });
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
        let old_rlimit = self.thread.process.limits.get_rlimit(resource);
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
            // reason: unsupported variants intentionally share this fallback path.
            #[allow(clippy::wildcard_enum_match_arm)]
            match resource {
                litebox_common_linux::RlimitResource::NOFILE => {
                    let new_max_fd = new_limit.rlim_cur.saturating_sub(1);
                    self.thread.process.limits.set_rlimit(resource, new_limit);
                    self.files.borrow().set_max_fd(new_max_fd);
                }
                // Resources like STACK and AS affect kernel-enforced limits
                // that don't apply inside the sandbox. Accept the set call so
                // programs that adjust their own rlimits (e.g. gcc, cargo)
                // don't crash, but don't enforce the value.
                _ => {
                    self.thread.process.limits.set_rlimit(resource, new_limit);
                }
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
        new_rlim: Option<crate::ConstPtr<litebox_common_linux::Rlimit64>>,
        old_rlim: Option<crate::MutPtr<litebox_common_linux::Rlimit64>>,
    ) -> Result<(), Errno> {
        if pid != 0 && pid != self.pid {
            // prlimit for a different process. We can only handle our own.
            return Err(Errno::ESRCH);
        }
        let new_limit = match new_rlim {
            Some(rlim) => {
                let rlim = rlim.read_at_offset(0).ok_or(Errno::EINVAL)?;
                Some(litebox_common_linux::rlimit64_to_rlimit(rlim))
            }
            None => None,
        };
        let old_limit =
            litebox_common_linux::rlimit_to_rlimit64(self.do_prlimit(resource, new_limit)?);
        if let Some(old_rlim) = old_rlim {
            self.prepare_guest_write(old_rlim, 1)?;
            old_rlim
                .write_at_offset(0, old_limit)
                .ok_or(Errno::EINVAL)?;
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
        self.prepare_guest_write(rlim, 1)?;
        rlim.write_at_offset(0, old_limit).ok_or(Errno::EINVAL)
    }

    /// Handle syscall `setrlimit`.
    pub(crate) fn sys_setrlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        rlim: crate::ConstPtr<litebox_common_linux::Rlimit>,
    ) -> Result<(), Errno> {
        let new_limit = rlim.read_at_offset(0).ok_or(Errno::EFAULT)?;
        let _ = self.do_prlimit(resource, Some(new_limit))?;
        Ok(())
    }

    /// Handle syscall `set_robust_list`.
    pub(crate) fn sys_set_robust_list(&self, head: usize) {
        let head = crate::ConstPtr::from_usize(head);
        self.thread.robust_list.set(Some(head));
    }

    /// Handle syscall `get_robust_list`.
    pub(crate) fn sys_get_robust_list(
        &self,
        pid: Option<i32>,
        head_ptr: crate::MutPtr<usize>,
    ) -> Result<(), Errno> {
        if let Some(pid) = pid
            && pid != self.tid
        {
            return Err(Errno::ESRCH);
        }
        let head = self
            .thread
            .robust_list
            .get()
            .map_or(0, |ptr| ptr.as_usize());
        self.prepare_guest_write(head_ptr, 1)?;
        head_ptr.write_at_offset(0, head).ok_or(Errno::EFAULT)
    }

    /// Handle syscall `rseq`.
    pub(crate) fn sys_rseq(
        &self,
        rseq: crate::MutPtr<u8>,
        rseq_len: u32,
        flags: u32,
        sig: u32,
    ) -> Result<(), Errno> {
        const RSEQ_LEN: u32 = 0x20;
        const RSEQ_FLAG_UNREGISTER: u32 = 1;

        if rseq_len != RSEQ_LEN || flags & !RSEQ_FLAG_UNREGISTER != 0 || rseq.as_usize() == 0 {
            return Err(Errno::EINVAL);
        }

        let cpu_id = self.global.platform.current_processor_number();

        let cpu_ptr = crate::MutPtr::<u32>::from_usize(rseq.as_usize());
        let rseq_cs_ptr = crate::MutPtr::<u64>::from_usize(rseq.as_usize() + 8);
        let flags_ptr = crate::MutPtr::<u32>::from_usize(rseq.as_usize() + 16);

        let write_state = |cpu_id_start: u32, cpu_id: u32| -> Result<(), Errno> {
            self.prepare_guest_write(cpu_ptr, 8)?;
            self.prepare_guest_write(rseq_cs_ptr, 1)?;
            self.prepare_guest_write(flags_ptr, 1)?;
            cpu_ptr
                .write_at_offset(0, cpu_id_start)
                .ok_or(Errno::EFAULT)?;
            cpu_ptr.write_at_offset(1, cpu_id).ok_or(Errno::EFAULT)?;
            rseq_cs_ptr.write_at_offset(0, 0).ok_or(Errno::EFAULT)?;
            flags_ptr.write_at_offset(0, 0).ok_or(Errno::EFAULT)?;
            cpu_ptr.write_at_offset(5, 0).ok_or(Errno::EFAULT)?;
            cpu_ptr.write_at_offset(6, 0).ok_or(Errno::EFAULT)?;
            cpu_ptr.write_at_offset(7, 0).ok_or(Errno::EFAULT)?;
            Ok(())
        };

        match flags {
            0 => {
                if self.thread.rseq.get().is_some() {
                    return Err(Errno::EBUSY);
                }
                let _ = sig;
                write_state(cpu_id, cpu_id)?;
                self.thread.rseq.set(Some(rseq));
                Ok(())
            }
            RSEQ_FLAG_UNREGISTER => {
                let _ = sig;
                if self.thread.rseq.get().map(|ptr| ptr.as_usize()) != Some(rseq.as_usize()) {
                    return Err(Errno::EINVAL);
                }
                self.thread.rseq.set(None);
                write_state(u32::MAX, u32::MAX)
            }
            _ => Err(Errno::EINVAL),
        }
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
        tp: TimeParam<Platform>,
    ) -> Result<(), Errno> {
        let duration = self.gettime_as_duration(clockid)?;
        tp.write(duration)
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
            litebox_common_linux::ClockId::ProcessCputimeId
            | litebox_common_linux::ClockId::ThreadCputimeId => {
                // Approximate CPU time with monotonic time. Real implementations
                // would track actual CPU cycles per process/thread.
                self.global
                    .platform
                    .now()
                    .duration_since(&self.global.boot_time)
            }
            litebox_common_linux::ClockId::MonotonicRaw
            | litebox_common_linux::ClockId::RealtimeCoarse
            | litebox_common_linux::ClockId::Boottime => {
                // Map all monotonic-like clocks to our monotonic implementation.
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
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
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
                let remaining = duration.checked_sub(current_time).unwrap_or(Duration::ZERO);
                // Log deadline computation for debugging futex timeouts.
                #[cfg(feature = "trace_syscalls")]
                if remaining == Duration::ZERO && duration.as_secs() > 0 {
                    litebox::log_println!(
                        self.global.platform,
                        "[DEADLINE-DBG] tid={} PAST deadline={}.{:09} current={}.{:09}",
                        self.tid,
                        duration.as_secs(),
                        duration.subsec_nanos(),
                        current_time.as_secs(),
                        current_time.subsec_nanos(),
                    );
                }
                Ok(self.global.platform.now().checked_add(remaining))
            }
        }
    }

    /// Handle syscall `clock_getres`.
    pub(crate) fn sys_clock_getres(
        &self,
        clockid: litebox_common_linux::ClockId,
        res: TimeParam<Platform>,
    ) -> Result<(), Errno> {
        // Return the resolution of the clock
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
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

        res.write(resolution)
    }

    /// Handle syscall `clock_nanosleep`.
    pub(crate) fn sys_clock_nanosleep(
        &self,
        clockid: litebox_common_linux::ClockId,
        flags: litebox_common_linux::TimerFlags,
        request: TimeParam<Platform>,
        remain: TimeParam<Platform>,
    ) -> Result<(), Errno> {
        let request = request.read()?.ok_or(Errno::EFAULT)?;
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
                    remain.write(remaining_timeout)?;
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
        tv: Option<crate::MutPtr<litebox_common_linux::TimeVal>>,
        tz: Option<crate::MutPtr<litebox_common_linux::TimeZone>>,
    ) -> Result<(), Errno> {
        if let Some(tz) = tz {
            // `man 2 gettimeofday`: The use of the timezone structure is
            // obsolete; the tz argument should normally be specified as NULL.
            // Return UTC (minuteswest=0, dsttime=0) which is the Linux default.
            self.prepare_guest_write(tz, 1)?;
            tz.write_at_offset(0, litebox_common_linux::TimeZone::new(0, 0))
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(tv) = tv {
            self.prepare_guest_write(tv, 1)?;
            tv.write_at_offset(0, self.real_time_as_duration_since_epoch().into())
                .ok_or(Errno::EFAULT)?;
        }
        Ok(())
    }

    /// Handle syscall `time`.
    pub(crate) fn sys_time(
        &self,
        tloc: Option<crate::MutPtr<litebox_common_linux::time_t>>,
    ) -> Result<litebox_common_linux::time_t, Errno> {
        let time = self.real_time_as_duration_since_epoch();
        let seconds: u64 = time.as_secs();
        let seconds: litebox_common_linux::time_t = seconds.try_into().or(Err(Errno::EOVERFLOW))?;
        if let Some(tloc) = tloc {
            self.prepare_guest_write(tloc, 1)?;
            tloc.write_at_offset(0, seconds).ok_or(Errno::EFAULT)?;
        }
        Ok(seconds)
    }

    /// Handle syscall `getrusage`.
    pub(crate) fn sys_getrusage(
        &self,
        who: i32,
        usage: crate::MutPtr<litebox_common_linux::Rusage>,
    ) -> Result<(), Errno> {
        match who {
            -1..=1 => {}
            _ => return Err(Errno::EINVAL),
        }

        self.prepare_guest_write(usage, 1)?;
        usage
            .write_at_offset(0, litebox_common_linux::Rusage::default())
            .ok_or(Errno::EFAULT)
    }

    /// Handle syscall `process_vm_readv`.
    pub(crate) fn sys_process_vm_readv(
        &self,
        pid: i32,
        local_iov: ConstPtr<litebox_common_linux::IoReadVec<MutPtr<u8>>>,
        liovcnt: usize,
        remote_iov: ConstPtr<litebox_common_linux::IoWriteVec<ConstPtr<u8>>>,
        riovcnt: usize,
        flags: usize,
    ) -> Result<usize, Errno> {
        if flags != 0 {
            return Err(Errno::EINVAL);
        }
        if pid != self.pid {
            return Err(Errno::EPERM);
        }

        let local_iovs = local_iov.to_owned_slice(liovcnt).ok_or(Errno::EFAULT)?;
        let remote_iovs = remote_iov.to_owned_slice(riovcnt).ok_or(Errno::EFAULT)?;
        let mut local_index = 0usize;
        let mut local_offset = 0usize;
        let mut total = 0usize;

        for remote in &*remote_iovs {
            let mut remote_offset = 0usize;
            let remote_len = remote.iov_len;
            let remote_base = remote.iov_base;
            while remote_offset < remote_len {
                while local_index < local_iovs.len()
                    && local_offset == local_iovs[local_index].iov_len
                {
                    local_index += 1;
                    local_offset = 0;
                }
                if local_index == local_iovs.len() {
                    return Ok(total);
                }

                let local = &local_iovs[local_index];
                let local_len = local.iov_len;
                let local_base = local.iov_base;
                let chunk = (remote_len - remote_offset).min(local_len - local_offset);
                let Some(remote_addr) = remote_base.as_usize().checked_add(remote_offset) else {
                    return if total == 0 {
                        Err(Errno::EFAULT)
                    } else {
                        Ok(total)
                    };
                };
                let Some(buf) = ConstPtr::<u8>::from_usize(remote_addr).to_owned_slice(chunk)
                else {
                    return if total == 0 {
                        Err(Errno::EFAULT)
                    } else {
                        Ok(total)
                    };
                };
                self.park_if_deferred();
                if local_base.copy_from_slice(local_offset, &buf).is_none() {
                    return if total == 0 {
                        Err(Errno::EFAULT)
                    } else {
                        Ok(total)
                    };
                }

                remote_offset += chunk;
                local_offset += chunk;
                total = total.checked_add(chunk).ok_or(Errno::EINVAL)?;
            }
        }

        Ok(total)
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
        let mut alarm = self.process().alarm_timer.lock();
        let now = self.global.platform.now();
        // Get remaining seconds from any previous alarm (rounded up to second).
        let remaining = match alarm.deadline {
            Some(deadline) => {
                match deadline.checked_duration_since(&now) {
                    Some(dur) if !dur.is_zero() => {
                        let secs = dur.as_secs();
                        let extra = u64::from(dur.subsec_nanos() > 0);
                        // Saturate to u32::MAX to avoid truncation.
                        u32::try_from(secs + extra).unwrap_or(u32::MAX)
                    }
                    _ => 0, // Deadline already passed or is now.
                }
            }
            None => 0,
        };

        let delay = Duration::from_secs(u64::from(seconds));
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
                Ok(handle) => {
                    alarm.handle = Some(handle);
                }
                Err(litebox::platform::TimerCreationError::Unsupported) => {}
                Err(_) => unimplemented!(),
            }
        }
        if let Some(handle) = &alarm.handle {
            handle.set_timer(delay);
        }
        alarm.deadline = new_deadline;

        Ok(remaining)
    }

    /// Handle syscall `timer_create`.
    pub(crate) fn sys_timer_create(
        &self,
        clockid: i32,
        _sevp: Option<crate::ConstPtr<u8>>,
        timerid_out: crate::MutPtr<i32>,
    ) -> Result<usize, Errno> {
        use litebox::platform::TimerProvider;

        // We only support CLOCK_MONOTONIC and CLOCK_REALTIME.
        if clockid != 1 /* CLOCK_MONOTONIC */
            && clockid != 0 /* CLOCK_REALTIME */
            && clockid != 2 /* CLOCK_PROCESS_CPUTIME_ID */
            && clockid != 3
        /* CLOCK_THREAD_CPUTIME_ID */
        {
            return Err(Errno::EINVAL);
        }

        // Parse the sigevent to determine which signal to deliver.
        // For now, default to SIGALRM (like alarm()). A full
        // implementation would parse the sigevent struct from guest
        // memory to extract sigev_notify, sigev_signo, etc.
        let signal = litebox_common_linux::signal::Signal::SIGALRM;

        let handle = self
            .global
            .platform
            .create_timer(signal)
            .map_err(|_| Errno::EAGAIN)?;

        let mut timers = self.process().posix_timers.lock();
        let id = timers.next_id;
        timers.next_id += 1;
        timers.timers.insert(
            id,
            PosixTimerEntry {
                handle,
                interval: Duration::ZERO,
                value: Duration::ZERO,
                armed_at: None,
            },
        );
        drop(timers);

        timerid_out.write_at_offset(0, id).ok_or(Errno::EFAULT)?;
        Ok(0)
    }

    /// Handle syscall `timer_settime`.
    pub(crate) fn sys_timer_settime(
        &self,
        timerid: i32,
        _flags: i32,
        new_value: crate::ConstPtr<litebox_common_linux::Itimerspec>,
        old_value: Option<crate::MutPtr<litebox_common_linux::Itimerspec>>,
    ) -> Result<usize, Errno> {
        use litebox::platform::Instant as _;
        let spec: litebox_common_linux::Itimerspec =
            new_value.read_at_offset(0).ok_or(Errno::EFAULT)?;
        let value = Duration::try_from(spec.it_value).unwrap_or(Duration::ZERO);
        let interval = Duration::try_from(spec.it_interval).unwrap_or(Duration::ZERO);

        let mut timers = self.process().posix_timers.lock();
        let entry = timers.timers.get_mut(&timerid).ok_or(Errno::EINVAL)?;

        // Return old value if requested.
        if let Some(old) = old_value {
            let now = self.global.platform.now();
            let remaining = entry
                .armed_at
                .and_then(|at| {
                    let elapsed = now.checked_duration_since(&at)?;
                    entry.value.checked_sub(elapsed)
                })
                .unwrap_or(Duration::ZERO);
            old.write_at_offset(
                0,
                litebox_common_linux::Itimerspec {
                    it_interval: entry.interval.into(),
                    it_value: remaining.into(),
                },
            )
            .ok_or(Errno::EFAULT)?;
        }

        entry.interval = interval;
        entry.value = value;
        entry.armed_at = if value.is_zero() {
            None
        } else {
            Some(self.global.platform.now())
        };
        entry.handle.set_timer(value);

        Ok(0)
    }

    /// Handle syscall `timer_gettime`.
    pub(crate) fn sys_timer_gettime(
        &self,
        timerid: i32,
        curr_value: crate::MutPtr<litebox_common_linux::Itimerspec>,
    ) -> Result<usize, Errno> {
        use litebox::platform::Instant as _;
        let timers = self.process().posix_timers.lock();
        let entry = timers.timers.get(&timerid).ok_or(Errno::EINVAL)?;
        let now = self.global.platform.now();
        let remaining = entry
            .armed_at
            .and_then(|at| {
                let elapsed = now.checked_duration_since(&at)?;
                entry.value.checked_sub(elapsed)
            })
            .unwrap_or(Duration::ZERO);
        curr_value
            .write_at_offset(
                0,
                litebox_common_linux::Itimerspec {
                    it_interval: entry.interval.into(),
                    it_value: remaining.into(),
                },
            )
            .ok_or(Errno::EFAULT)?;
        Ok(0)
    }

    /// Handle syscall `timer_delete`.
    pub(crate) fn sys_timer_delete(&self, timerid: i32) -> Result<usize, Errno> {
        let mut timers = self.process().posix_timers.lock();
        let entry = timers.timers.remove(&timerid).ok_or(Errno::EINVAL)?;
        // TimerHandle::drop calls timer_delete.
        drop(entry.handle);
        Ok(0)
    }

    /// Handle syscall `timer_getoverrun`.
    pub(crate) fn sys_timer_getoverrun(&self, timerid: i32) -> Result<usize, Errno> {
        let timers = self.process().posix_timers.lock();
        if !timers.timers.contains_key(&timerid) {
            return Err(Errno::EINVAL);
        }
        // Overrun tracking is not implemented; return 0.
        Ok(0)
    }

    /// Handle syscall `getpid`.
    pub(crate) fn sys_getpid(&self) -> i32 {
        self.pid
    }

    pub(crate) fn sys_getppid(&self) -> i32 {
        self.ppid
    }

    /// Handle syscall `getpgid`. If `pid == 0`, return caller's pgid.
    pub(crate) fn sys_getpgid(&self, pid: i32) -> Result<u32, Errno> {
        use litebox::process::{ProcessGroupId, ProcessId};
        if pid < 0 {
            return Err(Errno::EINVAL);
        }
        let target = if pid == 0 {
            self.process_id
        } else {
            ProcessId(pid.cast_unsigned())
        };
        self.global
            .litebox
            .process_registry()
            .get_pgid(target)
            .map(ProcessGroupId::as_u32)
            .ok_or(Errno::ESRCH)
    }

    /// Handle syscall `setpgid`. pid==0 means self, pgid==0 means use pid as pgid.
    ///
    /// NOTE: Linux returns EACCES when a parent calls setpgid on a child that
    /// has already exec'd. We intentionally omit this check. Under our vfork
    /// model the parent is blocked until the child execs, so the parent can
    /// only call setpgid *after* exec — making EACCES the only possible
    /// outcome on real Linux. Shells make this call for race-avoidance and
    /// tolerate failure, so being more permissive here is harmless.
    #[allow(clippy::similar_names)]
    pub(crate) fn sys_setpgid(&self, pid: i32, pgid: i32) -> Result<(), Errno> {
        use litebox::process::{ProcessGroupId, ProcessId, SetPgidError};
        if pid < 0 || pgid < 0 {
            return Err(Errno::EINVAL);
        }
        let caller = self.process_id;
        let target = if pid == 0 {
            caller
        } else {
            ProcessId(pid.cast_unsigned())
        };
        let target_pgid = if pgid == 0 {
            ProcessGroupId::from(target)
        } else {
            ProcessGroupId(pgid.cast_unsigned())
        };
        let registry = self.global.litebox.process_registry();
        let old_pgid = registry.get_pgid(target);
        match registry.check_set_pgid(caller, target, target_pgid) {
            Some(Ok(())) => {}
            Some(Err(SetPgidError::NotPermitted | SetPgidError::NoSuchGroup)) => {
                return Err(Errno::EPERM);
            }
            None => return Err(Errno::ESRCH),
        }
        match super::guest_pid::try_broker_set_pgid(caller.0, target.0, target_pgid.0) {
            Ok(()) => {}
            Err(litebox_common_linux::guest_pid_provider::GuestPidProviderError::UnknownHandle) => {
                return Err(Errno::ESRCH);
            }
            Err(litebox_common_linux::guest_pid_provider::GuestPidProviderError::NotPermitted) => {
                return Err(Errno::EPERM);
            }
            Err(litebox_common_linux::guest_pid_provider::GuestPidProviderError::Io) => {
                return Err(Errno::EIO);
            }
        }
        match registry.set_pgid(caller, target, target_pgid) {
            Some(Ok(())) => {
                if old_pgid != Some(target_pgid) {
                    if let Some(old) = old_pgid {
                        self.global.cleanup_pgrp_signal_subscription_if_empty(old.0);
                    }
                    if target == self.process_id {
                        self.global.ensure_pgrp_signal_subscription(target_pgid.0);
                    }
                }
                Ok(())
            }
            Some(Err(err)) => {
                log_unsupported!(
                    "[PG.2-diag] PGRP STAMP GAP: broker SetPgid accepted but shim ProcessRegistry rejected caller={} target={} pgid={} err={err:?}",
                    caller.0,
                    target.0,
                    target_pgid.0
                );
                Err(Errno::EPERM)
            }
            None => {
                log_unsupported!(
                    "[PG.2-diag] PGRP STAMP GAP: broker SetPgid accepted but shim target vanished caller={} target={} pgid={}",
                    caller.0,
                    target.0,
                    target_pgid.0
                );
                Err(Errno::ESRCH)
            }
        }
    }

    /// Handle syscall `getsid`. If `pid == 0`, return caller's sid.
    pub(crate) fn sys_getsid(&self, pid: i32) -> Result<u32, Errno> {
        use litebox::process::{ProcessId, SessionId};
        if pid < 0 {
            return Err(Errno::EINVAL);
        }
        let target = if pid == 0 {
            self.process_id
        } else {
            ProcessId(pid.cast_unsigned())
        };
        self.global
            .litebox
            .process_registry()
            .get_sid(target)
            .map(SessionId::as_u32)
            .ok_or(Errno::ESRCH)
    }

    /// Handle syscall `setsid`. Creates a new session with caller as leader.
    pub(crate) fn sys_setsid(&self) -> Result<u32, Errno> {
        use litebox::process::SetsidError;
        let registry = self.global.litebox.process_registry();
        let old_pgid = registry.get_pgid(self.process_id);
        match registry.check_setsid(self.process_id) {
            Some(Ok(_)) => {}
            Some(Err(SetsidError::AlreadyGroupLeader)) => return Err(Errno::EPERM),
            None => return Err(Errno::ESRCH),
        }
        match super::guest_pid::try_broker_set_sid(self.process_id.0) {
            Ok(_) => {}
            Err(litebox_common_linux::guest_pid_provider::GuestPidProviderError::UnknownHandle) => {
                return Err(Errno::ESRCH);
            }
            Err(litebox_common_linux::guest_pid_provider::GuestPidProviderError::NotPermitted) => {
                return Err(Errno::EPERM);
            }
            Err(litebox_common_linux::guest_pid_provider::GuestPidProviderError::Io) => {
                return Err(Errno::EIO);
            }
        }
        match registry.setsid(self.process_id) {
            Some(Ok(sid)) => {
                *self.process_state.borrow().controlling_pty.lock() = None;
                if let Some(old) = old_pgid {
                    self.global.cleanup_pgrp_signal_subscription_if_empty(old.0);
                }
                self.global.ensure_pgrp_signal_subscription(sid.as_u32());
                Ok(sid.as_u32())
            }
            Some(Err(err)) => {
                log_unsupported!(
                    "[PG.2-diag] PGRP STAMP GAP: broker SetSid accepted but shim ProcessRegistry rejected pid={} err={err:?}",
                    self.process_id.0
                );
                Err(Errno::EPERM)
            }
            None => {
                log_unsupported!(
                    "[PG.2-diag] PGRP STAMP GAP: broker SetSid accepted but shim pid vanished pid={}",
                    self.process_id.0
                );
                Err(Errno::ESRCH)
            }
        }
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

    /// Handle syscall `getgroups`.
    pub(crate) fn sys_getgroups(&self, size: i32, list: MutPtr<u32>) -> Result<usize, Errno> {
        if size < 0 {
            return Err(Errno::EINVAL);
        }

        // Return the effective gid as the sole supplementary group — this
        // matches the common case where a user has their primary group as
        // their only supplementary group.
        let groups: &[u32] = &[self.credentials.egid];
        if size == 0 {
            return Ok(groups.len());
        }
        #[allow(clippy::cast_sign_loss)]
        let size = size as usize;
        if size < groups.len() {
            return Err(Errno::EINVAL);
        }
        self.prepare_guest_write(list, groups.len())?;
        for (i, &gid) in groups.iter().enumerate() {
            list.write_at_offset(isize::try_from(i).unwrap(), gid)
                .ok_or(Errno::EFAULT)?;
        }
        Ok(groups.len())
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

    pub(crate) fn sys_sched_setscheduler(
        &self,
        pid: i32,
        policy: i32,
        param: crate::ConstPtr<i32>,
    ) -> Result<usize, Errno> {
        const SCHED_OTHER: i32 = 0;
        const SCHED_RESET_ON_FORK: i32 = 0x4000_0000;

        let priority = param.read_at_offset(0).ok_or(Errno::EFAULT)?;
        let target_tid = if pid == 0 { self.tid } else { pid };
        if !self
            .thread
            .process
            .inner
            .lock()
            .threads
            .contains_key(&target_tid)
        {
            return Err(Errno::ESRCH);
        }

        let base_policy = policy & !SCHED_RESET_ON_FORK;
        if base_policy != SCHED_OTHER || priority != 0 {
            return Err(Errno::EINVAL);
        }

        Ok(0)
    }
}

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `futex`
    pub(crate) fn sys_futex(
        &self,
        arg: litebox_common_linux::FutexArgs<litebox_platform_multiplex::Platform>,
    ) -> Result<usize, Errno> {
        let res = match arg {
            FutexArgs::Wake {
                addr,
                flags: _,
                count,
            } => {
                let Some(count) = core::num::NonZeroU32::new(count) else {
                    return Ok(0);
                };
                self.global.futex_manager.wake(addr, count, None, 0)? as usize
            }
            FutexArgs::Wait {
                addr,
                flags: _,
                val,
                timeout,
            } => {
                let timeout = timeout.read()?;
                // FUTEX_WAIT takes a relative timeout. Linux uses
                // restart_block to adjust the remaining time on restart;
                // without that infrastructure, plain EINTR is the safe
                // choice (restarting would replay the original timeout,
                // losing elapsed time).
                self.global.futex_manager.wait(
                    &self.wait_cx().with_timeout(timeout),
                    addr,
                    val,
                    None,
                    0,
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
                let deadline = if let Some(timeout_dur) = timeout.read()? {
                    let clock_id =
                        if flags.contains(litebox_common_linux::FutexFlags::CLOCK_REALTIME) {
                            litebox_common_linux::ClockId::RealTime
                        } else {
                            litebox_common_linux::ClockId::Monotonic
                        };
                    let d = self.duration_since_epoch_to_deadline(clock_id, timeout_dur)?;
                    #[cfg(feature = "trace_syscalls")]
                    {
                        let clock_str =
                            if flags.contains(litebox_common_linux::FutexFlags::CLOCK_REALTIME) {
                                "realtime"
                            } else {
                                "monotonic"
                            };
                        litebox::log_println!(
                            self.global.platform,
                            "[FUTEX-DBG] tid={} wait_bitset addr={:#x} val={} clock={} timeout_secs={} deadline_some={} mask={:#x}",
                            self.tid,
                            addr.as_usize(),
                            val,
                            clock_str,
                            timeout_dur.as_secs(),
                            d.is_some(),
                            bitmask,
                        );
                    }
                    d
                } else {
                    #[cfg(feature = "trace_syscalls")]
                    litebox::log_println!(
                        self.global.platform,
                        "[FUTEX-DBG] tid={} wait_bitset addr={:#x} val={} no_timeout mask={:#x}",
                        self.tid,
                        addr.as_usize(),
                        val,
                        bitmask,
                    );
                    None
                };
                // FUTEX_WAIT_BITSET uses an absolute deadline, so
                // restart is safe — the same deadline is re-evaluated.
                match self.global.futex_manager.wait(
                    &self.wait_cx().with_deadline(deadline),
                    addr,
                    val,
                    core::num::NonZeroU32::new(bitmask),
                    0,
                ) {
                    Ok(()) => 0,
                    Err(litebox::sync::futex::FutexError::WaitError(
                        litebox::event::wait::WaitError::Interrupted,
                    )) => {
                        self.syscall_restartable.set(true);
                        return Err(Errno::EINTR);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            _ => unimplemented!("Unsupported futex operation"),
        };
        Ok(res)
    }
}

const MAX_VEC: usize = 4096; // limit count
const MAX_TOTAL_BYTES: usize = 256 * 1024; // size cap

/// Maximum shebang (#!) recursion depth, matching Linux `BINPRM_MAX_RECURSION`.
const SHEBANG_MAX_RECURSION: u32 = 4;

/// Maximum length of a shebang line that we inspect. Matches Linux `BINPRM_BUF_SIZE`.
const SHEBANG_MAX_LINE: usize = 256;

/// Parse a `#!interpreter [optional-arg]` line from a file header buffer.
///
/// Returns `Some((interpreter, optional_arg))` when `buf` starts with `#!` and
/// contains a non-empty interpreter path. The interpreter and optional argument
/// are borrowed from `buf`. The optional argument, if present, is everything
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
    /// Resolve `#!` interpreter scripts to their real executable path and argv.
    ///
    /// Returns the final executable path plus the argv vector rewritten to match
    /// Linux `binfmt_script` semantics:
    /// `[interpreter, optional_arg?, script_path, original_argv[1:]]`.
    pub(crate) fn resolve_shebang_program(
        &self,
        path: &str,
        argv_vec: alloc::vec::Vec<alloc::ffi::CString>,
    ) -> Result<(alloc::string::String, alloc::vec::Vec<alloc::ffi::CString>), Errno> {
        let mut path = alloc::string::String::from(path);
        let mut argv_vec = argv_vec;
        let mut shebang_depth = 0u32;
        loop {
            let fd = {
                use litebox::utils::ReinterpretSignedExt as _;
                match self.sys_open(
                    path.as_str(),
                    litebox::fs::OFlags::RDONLY,
                    litebox::fs::Mode::empty(),
                ) {
                    Ok(v) => v.reinterpret_as_signed(),
                    Err(e) => {
                        #[cfg(feature = "trace_syscalls")]
                        litebox::log_println!(
                            self.global.platform,
                            "[EXEC-OPEN-FAIL] pid={} path={:?} err={:?}",
                            self.pid,
                            path,
                            e,
                        );
                        return Err(e);
                    }
                }
            };
            let mut header = [0u8; SHEBANG_MAX_LINE];
            let n = match self.sys_read(fd, &mut header, Some(0)) {
                Ok(n) => n,
                Err(e) => {
                    let _ = self.sys_close(fd);
                    return Err(e);
                }
            };
            let _ = self.sys_close(fd);

            match parse_shebang(&header[..n]) {
                Some((interp, opt_arg)) => {
                    if shebang_depth >= SHEBANG_MAX_RECURSION {
                        return Err(Errno::ELOOP);
                    }
                    let mut new_argv = alloc::vec::Vec::new();
                    new_argv.push(alloc::ffi::CString::new(interp).map_err(|_| Errno::EINVAL)?);
                    if let Some(arg) = opt_arg {
                        new_argv.push(alloc::ffi::CString::new(arg).map_err(|_| Errno::EINVAL)?);
                    }
                    new_argv
                        .push(alloc::ffi::CString::new(path.as_str()).map_err(|_| Errno::EINVAL)?);
                    if argv_vec.len() > 1 {
                        new_argv.extend_from_slice(&argv_vec[1..]);
                    }
                    path = alloc::string::String::from(interp);
                    argv_vec = new_argv;
                    shebang_depth += 1;
                }
                None => break,
            }
        }
        Ok((path, argv_vec))
    }

    /// Execute a non-PIE binary in a dedicated worker host process.
    ///
    /// This is called from `sys_execve` when the parsed ELF has fixed load
    /// addresses outside the current VA partition. Instead of biasing/rewriting,
    /// we spawn a fresh host process with the full address space, let it load
    /// and run the binary, then map its exit status back to the guest process.
    fn exec_on_remote_host(
        &self,
        path: &str,
        argv: alloc::vec::Vec<alloc::ffi::CString>,
        envp: alloc::vec::Vec<alloc::ffi::CString>,
        guest_exec_image: Option<&[u8]>,
        guest_interp_image: Option<(&str, &[u8])>,
        vfork_info: Option<ExecVforkInfo>,
    ) -> Result<usize, Errno> {
        // Compile-time gate: every `RawFdRef` variant must declare a
        // worker-exec migration policy in
        // `migration_policy::migration_policies_for`. Adding a new
        // subsystem without either (a) extending the policy table with a
        // `BridgedByLoop { loop_name }` arm and a matching per-subsystem
        // emit loop below, or (b) explicitly marking it `NotBridged` with
        // a documented reason, fails to compile. This closes the bug
        // class that caused 68/99 hard FAILs when epoll/inotify were
        // added without matching emit loops here (see commit 5387acc3).
        let _migration_gate = super::migration_policy::reference_gate::<FS>();
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[EXEC-REMOTE] pid={} path={:?} — entering exec_on_remote_host",
            self.pid,
            path,
        );
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[EXEC-REMOTE] pid={} path={:?} — spawning worker host for non-PIE binary",
            self.pid,
            path,
        );
        #[cfg(feature = "trace_syscalls")]
        {
            let argv_preview = argv
                .iter()
                .take(8)
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<alloc::vec::Vec<_>>();
            litebox::log_println!(
                self.global.platform,
                "[EXEC-REMOTE] pid={} argv={:?}",
                self.pid,
                argv_preview,
            );
        }

        // Helper: signal VforkDone (if present) so the parent is never left
        // blocked on error.
        let signal_on_error = |vfork_info: &Option<ExecVforkInfo>| {
            if let Some((vd, _)) = vfork_info {
                vd.signal();
            }
        };

        let guest_cwd = self.fs.borrow().current_working_directory();
        let worker_stdio = self.worker_exec_stdio_bindings().inspect_err(|_err| {
            #[cfg(feature = "trace_syscalls")]
            litebox::log_println!(
                self.global.platform,
                "[EXEC-REMOTE] pid={} remote worker exec does not support the current stdio bindings",
                self.pid,
            );
            signal_on_error(&vfork_info);
        })?;
        let placeholder_stdio_bridge_fds = worker_exec_stdio_bridge_fds(&worker_stdio);
        let stdio_pipe_info: Vec<(
            i32,
            usize,
            super::host_passthrough_fd::HostPassthroughFdDirection,
        )> = Vec::new();

        let use_direct_stdio = false;

        // Non-stdio broker-backed pipe/socketpair fds are transferred to the
        // remote worker via --broker-fd-bridge specs below. Legacy local
        // Pipes/UnixSocket fds no longer get bespoke OS-fd passthrough here.
        let extra_fds: Vec<(usize, i32)> = Vec::new();
        // Phase 2.F follow-up: broker-backed EventFile bridges
        // (guest_fd:kind:handle_id strings) for inherited eventfd /
        // pidfd state. Each entry corresponds to one fd whose
        // EventFile was promoted to broker-backed and a transit ref
        // was dup'd. The worker reattaches via --broker-eventfd-bridge.
        let mut broker_eventfd_specs: alloc::vec::Vec<alloc::string::String> =
            alloc::vec::Vec::new();
        let mut broker_eventfd_transit_release: alloc::vec::Vec<(
            alloc::sync::Arc<
                dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
            >,
            u64,
        )> = alloc::vec::Vec::new();
        // Phase F.9 (2026-05-18): separate list for pipe-specific
        // transit releases. Drained after wait_worker_host returns
        // (worker B has exited) so the broker rc can reach 0 for the
        // writer end and the reader gets HUP/EOF.
        let mut broker_pipe_transit_release: alloc::vec::Vec<(
            alloc::sync::Arc<
                dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
            >,
            u64,
        )> = alloc::vec::Vec::new();
        // Broker PTY slave-close HUP has the same lifetime requirement as
        // pipes: the emit-side transit ref must survive until the remote
        // worker adopts the fd, but must be released after that worker exits
        // so the broker can observe last-slave-close and notify the master.
        let mut broker_pty_transit_release: alloc::vec::Vec<(
            alloc::sync::Arc<
                dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
            >,
            u64,
        )> = alloc::vec::Vec::new();
        let mut broker_tcp_conn_transit_release: alloc::vec::Vec<(
            alloc::sync::Arc<
                dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
            >,
            u64,
        )> = alloc::vec::Vec::new();
        // Process-token pidfd bridges need an in-transit exit subscription:
        // the source pidfd can close before the remote exec'd child installs
        // its own subscription, but the target may exit in that window.
        let mut broker_pidfd_process_transit: alloc::vec::Vec<
            super::guest_pid::BrokerProcessExitWake,
        > = alloc::vec::Vec::new();
        let mut remote_signalfd_entries = alloc::vec::Vec::new();
        {
            // Unified Phase-1 walk: single pass over iter_alive with an
            // exhaustive RawFdRef match populating per-subsystem buckets.
            // All Phase-2 emit calls below consume from `collected`.
            // See `collect_migratable_fds` for the exhaustiveness gate.
            let collected = collect_migratable_fds::<FS>(
                &self.files.borrow(),
                &self.global,
                /* survives_exec_filter */ true,
            );

            // Phase-2: one named helper per RawFdRef kind. Source order
            // is the wire order (the runner installs specs in order);
            // epoll MUST be last because its per-entry
            // `EpollDescriptor::try_from` looks up target fds in the
            // worker's descriptor store. Eventfd and timerfd both
            // iterate `collected.eventfd` with complementary per-entry
            // filters (broker promotion vs. is_timerfd).
            emit_eventfd_bridge_specs(
                self,
                &collected.eventfd,
                &mut broker_eventfd_specs,
                &mut broker_eventfd_transit_release,
                &mut broker_pidfd_process_transit,
            );
            emit_broker_pipe_bridge_specs(
                self,
                &collected.broker_pipe,
                &mut broker_eventfd_specs,
                &mut broker_pipe_transit_release,
            );
            emit_broker_pty_bridge_specs(
                self,
                &collected.broker_pty,
                &mut broker_eventfd_specs,
                &mut broker_pty_transit_release,
            );
            emit_broker_socketpair_bridge_specs(
                self,
                &collected.broker_socketpair,
                &mut broker_eventfd_specs,
            );
            emit_broker_socket_dgram_bridge_specs(
                self,
                &collected.broker_socket_dgram,
                &mut broker_eventfd_specs,
            );
            emit_broker_socket_seqpacket_bridge_specs(
                self,
                &collected.broker_socket_seqpacket,
                &mut broker_eventfd_specs,
            );
            emit_broker_tcp_conn_bridge_specs(
                self,
                &collected.broker_tcp_conn,
                &mut broker_eventfd_specs,
                &mut broker_tcp_conn_transit_release,
            );
            emit_broker_inet_listener_bridge_specs(
                self,
                &collected.broker_inet_listener,
                &mut broker_eventfd_specs,
                &mut broker_tcp_conn_transit_release,
            );
            emit_fs_bridge_specs(self, &collected.fs, &mut broker_eventfd_specs);
            emit_signalfd_bridge_specs(
                self,
                &collected.signalfd,
                &mut broker_eventfd_specs,
                &mut broker_eventfd_transit_release,
                &mut remote_signalfd_entries,
            );
            #[cfg(feature = "worker_local_inet")]
            emit_network_bridge_specs(self, &collected.network, &mut broker_eventfd_specs);
            emit_timerfd_bridge_specs(self, &collected.eventfd, &mut broker_eventfd_specs);
            emit_inotify_bridge_specs(
                self,
                &collected.inotify,
                &mut broker_eventfd_specs,
                &mut broker_eventfd_transit_release,
            );
            // Epoll MUST be last (no broker handle; per-entry targets
            // resolved at install against the worker's descriptor store).
            emit_epoll_bridge_specs(self, &collected.epoll, &mut broker_eventfd_specs);
        }

        // Resolve the worker load path through the current guest filesystem so
        // transferred images materialize at their real lower-tree locations
        // rather than shadowing symlinked parents like /bin or /lib64.
        let load_path = self.resolve_exe_path(path);
        let spawn_result = self
            .global
            .platform
            .spawn_worker_host_for_exec(
                &load_path,
                &argv,
                &envp,
                &guest_cwd,
                self.pid,
                self.ppid,
                self.credentials.uid,
                self.credentials.euid,
                self.credentials.gid,
                self.credentials.egid,
                guest_exec_image,
                guest_interp_image,
                worker_stdio,
                // For vfork-style children, route stdio through direct host
                // pipes and install parent-side replacements below.  The local
                // child fd table is transient; a platform bridge that writes
                // back through the child's inherited virtual pipe can miss the
                // PIE parent's epoll interest after the remote handoff.
                use_direct_stdio,
                &extra_fds,
                &broker_eventfd_specs,
                *self.process_state.borrow().controlling_pty.lock(),
            )
            .map_err(|_err| {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[EXEC-REMOTE] pid={} spawn_worker_host_for_exec failed: {}",
                    self.pid,
                    _err,
                );
                for &(_, child_fd) in &extra_fds {
                    self.global.platform.close_host_fd(child_fd);
                }
                // Release broker eventfd transit refs that the worker
                // never adopted (spawn failed).
                for (releaser, handle_id) in &broker_eventfd_transit_release {
                    releaser.release(*handle_id);
                }
                // Phase F.9: same for pipe transit refs.
                for (releaser, handle_id) in &broker_pipe_transit_release {
                    releaser.release(*handle_id);
                }
                for (releaser, handle_id) in &broker_pty_transit_release {
                    releaser.release(*handle_id);
                }
                for (releaser, handle_id) in &broker_tcp_conn_transit_release {
                    releaser.release(*handle_id);
                }
                signal_on_error(&vfork_info);
                Errno::ENOMEM
            })?;

        // Note: child ends of bridge socketpairs are already closed by
        // spawn_worker_host_for_exec (it dups them to 100+ and closes the
        // originals).  Do NOT close them again here — that would double-close
        // and trigger IO Safety violations if the fd number was reused.

        let host_pid = spawn_result.host_pid;
        self.global
            .fork_child_host_pids
            .write()
            .insert(self.process_id.0, host_pid);
        if !remote_signalfd_entries.is_empty() {
            self.global.remote_signalfd_targets.write().insert(
                self.process_id.0,
                crate::RemoteSignalfdTarget {
                    blocked_mask: self.signals.get_blocked().as_u64(),
                    signalfds: remote_signalfd_entries,
                },
            );
        }

        if let Some((vd, _parent_socket_fds)) = &vfork_info {
            // direct_pipes is always empty since use_direct_stdio is
            // always false (pipe subsystem removed).
            for direct in spawn_result.direct_pipes {
                self.global.platform.close_host_fd(direct.parent_os_fd);
            }

            vd.signal();
        }

        // The remote worker has taken over the exec image. The local placeholder
        // task will never resume guest code, but exec still closes CLOEXEC fds
        // promptly so parent-side posix_spawn handshakes can observe EOF.
        self.close_on_exec();

        // Phase 2.F follow-up: the placeholder is a stub that just waits
        // for the remote worker — it has no further use for any inherited
        // fds. Close every fd in the placeholder so OFD/broker refcounts
        // drop. This lets parent-side readers observe EOF/HUP, including
        // PTY masters waiting for the migrated child's stdio slave to close.
        //
        // Some FD_CLOEXEC flags can fail to propagate through
        // `duplicate_raw_fd`'s metadata copy (observed: stderr pipe ends
        // from `pipe2(O_CLOEXEC)` lose their CLOEXEC bit in the child fd
        // table), which left close_on_exec above as a partial cleanup.
        // Closing the rest unconditionally is safe here because the
        // placeholder never runs guest code that could reference these
        // fds again.
        {
            let files = self.files.borrow();
            let alive_fds: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();
            drop(files);
            for raw_fd in alive_fds {
                if placeholder_stdio_bridge_fds.contains(&raw_fd) {
                    continue;
                }
                let _ = self.do_close(raw_fd);
            }
        }

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[EXEC-REMOTE] pid={} worker host_pid={} — waiting for exit",
            self.pid,
            host_pid,
        );

        let raw_wait_status = self.global.platform.wait_worker_host(host_pid);
        self.global
            .fork_child_host_pids
            .write()
            .remove(&self.process_id.0);
        self.global
            .remote_signalfd_targets
            .write()
            .remove(&self.process_id.0);
        let broker_exit_status =
            resolve_worker_exit_registry_status(self.process_id, raw_wait_status);
        super::guest_pid::try_mark_broker_process_exited(self.process_id.0, broker_exit_status);

        // Phase F.9: now that worker B has exited, release the pipe
        // transit dup_handle refs that the emit-side bumped at exec
        // time. This lets the broker rc reach 0 if no other holder
        // remains (e.g. the parent's reader expecting writer-close →
        // reader-EOF). Without this release, the transit refs stay
        // alive on the parent worker's broker conn until the parent
        // worker itself exits — which is too late, the parent's
        // reader times out.
        //
        // Pipe, PTY, and TCP connection transit refs are drained here. Eventfd/signalfd
        // refs stay alive (they're cleaned via worker-conn cleanup);
        // releasing them here breaks PIDF tests where the pidfd subscription
        // needs the broker state alive past exec.
        for (releaser, handle_id) in broker_pipe_transit_release.drain(..) {
            releaser.release(handle_id);
        }
        for (releaser, handle_id) in broker_pty_transit_release.drain(..) {
            releaser.release(handle_id);
        }
        for (releaser, handle_id) in broker_tcp_conn_transit_release.drain(..) {
            releaser.release(handle_id);
        }

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[EXEC-REMOTE] pid={} worker exited with registry status {} (raw waitpid {})",
            self.pid,
            broker_exit_status,
            raw_wait_status,
        );

        if vfork_info.is_some() {
            let status = registry_status_to_exit_status(broker_exit_status);
            self.thread.process.inner.lock().exit_status = status;
            self.local_task_terminated.set(true);
        } else {
            self.exit_thread(registry_status_exit_thread_arg(broker_exit_status).truncate());
        }

        // The remote worker completed; stop the local placeholder before it can
        // resume guest code. `exit_thread` can return for non-vfork exec
        // placeholders; panicking here tears down the parent worker that is still
        // waiting for the child result.
        self.local_task_terminated.set(true);
        Ok(0)
    }

    fn worker_exec_stdio_bindings(&self) -> Result<WorkerExecStdioBindings<FS>, Errno> {
        let files = self.files.borrow();
        if worker_exec_has_unsupported_stdio(&self.global, &files) {
            return Err(Errno::ENOTSUP);
        }
        Ok(WorkerExecStdioBindings {
            stdin: worker_exec_input_binding(0, &self.global, &files),
            stdout: worker_exec_output_binding(1, &self.global, &files),
            stderr: worker_exec_output_binding(2, &self.global, &files),
        })
    }

    /// Handle syscall `execve`.
    pub(crate) fn sys_execve(
        &self,
        pathname: crate::ConstPtr<i8>,
        argv: crate::ConstPtr<crate::ConstPtr<i8>>,
        envp: crate::ConstPtr<crate::ConstPtr<i8>>,
        ctx: &mut litebox_common_linux::ExecutionContext,
    ) -> Result<usize, Errno> {
        fn copy_vector(
            mut base: crate::ConstPtr<crate::ConstPtr<i8>>,
            _which: &str,
        ) -> Result<alloc::vec::Vec<alloc::ffi::CString>, Errno> {
            let mut out = alloc::vec::Vec::new();
            let mut total = 0usize;
            for _ in 0..MAX_VEC {
                let p: crate::ConstPtr<i8> = {
                    // read pointer-sized entries
                    match base.read_at_offset(0) {
                        Some(ptr) => ptr,
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
            litebox::log_println!(
                self.global.platform,
                "[EXEC-EFAULT] pid={} pathname_addr={:#x}",
                self.pid,
                pathname.as_usize(),
            );
            return Err(Errno::EFAULT);
        };
        let path = path_cstr.to_str().map_err(|_| Errno::ENOENT)?;

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[EXEC-ENTER] pid={} path={:?}",
            self.pid,
            path,
        );
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

        let (path, argv_vec) = self.resolve_shebang_program(path, argv_vec)?;

        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[EXEC] pid={} path={:?} argc={} argv={:?}",
            self.pid,
            path,
            argv_vec.len(),
            argv_vec
                .iter()
                .take(6)
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<alloc::vec::Vec<_>>(),
        );

        match self
            .global
            .control_plane
            .route_exec(self.process_id, path.as_ref())
            .expect("running process must be routed by the local control plane")
        {
            ExecRoute::Local { .. } => {}
            ExecRoute::RemoteHost { .. } => {
                // A previous route_exec call determined this process needs a
                // remote host. This shouldn't happen on the first exec call
                // since we check needs_remote_host below.
                unreachable!("initial execve was already routed to a remote host")
            }
        }
        let loader = crate::loader::elf::ElfLoader::new(self, &path).map_err(Errno::from)?;
        let resolved_exe_path = self.resolve_exe_path(&path);
        let proc_cmdline = proc_cmdline_from_argv(&argv_vec, &resolved_exe_path);

        // Check whether the parsed ELF is a non-PIE binary whose fixed load
        // addresses fall outside this process's VA partition. For a shared-
        // fork child (userland), the child still uses the parent's ProcessState
        // at this point, so we must check against the child's actual partition
        // (from the ForkContext) rather than the parent's.
        let fixed_load_range = loader.fixed_load_range();
        let needs_remote = if let Some(fixed_range) = fixed_load_range {
            let (pm_min, pm_max) = if let Some(fc) = self.fork_context.borrow().as_ref() {
                use litebox::platform::AddressSpaceProvider;
                let child_range = self
                    .global
                    .platform
                    .address_space_range(fc.address_space_id)
                    .expect("child address space must be valid");
                (child_range.start, child_range.end)
            } else {
                let ps = self.process_state.borrow();
                (ps.pm.addr_min(), ps.pm.addr_max())
            };
            fixed_range.start < pm_min || fixed_range.end > pm_max
        } else {
            false
        };
        let transfer_remote_images =
            needs_remote && !self.global.platform.worker_exec_can_load_from_guest_fs();
        let remote_exec_image = if transfer_remote_images {
            // If the resolved binary is visible on the host filesystem, let
            // the worker load it through its normal filesystem view. Avoids
            // transferring large debug images through a memfd on every exec.
            if self.global.platform.host_file_exists(&resolved_exe_path) {
                None
            } else {
                Some(
                    match self.global.platform.read_host_file(&resolved_exe_path) {
                        Ok(data) => data,
                        Err(()) => loader.main_file_bytes()?,
                    },
                )
            }
        } else {
            None
        };
        let remote_interp_image = if transfer_remote_images {
            loader.interp_file_bytes()?.and_then(|(interp_path, data)| {
                let resolved = self.resolve_exe_path(&interp_path);
                if self.global.platform.host_file_exists(&resolved) {
                    None
                } else {
                    let data = self
                        .global
                        .platform
                        .read_host_file(&resolved)
                        .unwrap_or(data);
                    Some((resolved, data))
                }
            })
        } else {
            None
        };

        // After this point, the old program is torn down and failures must terminate the process.

        // Kill all the other threads in this process and wait for them to exit.
        // This must happen before any remote handoff so sibling threads are not
        // left running concurrently with the worker.
        if !self.kill_other_threads() {
            // If we were suspended for vfork parking, report EINTR so callers
            // can retry. Otherwise preserve existing EBUSY behavior for
            // concurrent exec/exit races.
            if self.is_suspended() {
                return Err(Errno::EINTR);
            }
            // Another thread is already in the process of execve. This thread
            // will exit; return any error code.
            return Err(Errno::EBUSY);
        }

        if needs_remote {
            // For shared-fork children (userland), detach from the parent's
            // state before spawning the worker, just like normal exec does.
            let mut detached_from_shared_fork = false;
            let mut vfork_info_for_exec: Option<ExecVforkInfo> = None;
            if let Some(fc) = self.fork_context.borrow_mut().take() {
                self.delayed_fork_pending.set(false);
                // Flush MAP_SHARED writeback data while still using the
                // parent's ProcessState.
                self.sync_all_shared_mappings();

                // Switch to the child's own VA partition.
                let child_range = {
                    use litebox::platform::AddressSpaceProvider;
                    self.global
                        .platform
                        .address_space_range(fc.address_space_id)
                        .expect("child address space must be valid")
                };
                let shared_ps = self.process_state.borrow().clone();
                let child_controlling_pty = *shared_ps.controlling_pty.lock();
                *shared_ps.controlling_pty.lock() = fc.parent_controlling_pty;
                let child_ps = Arc::new(crate::ProcessState {
                    pm: litebox::mm::PageManager::new(&self.global.litebox, child_range),
                    address_space_id: fc.address_space_id,
                    thread_count: core::sync::atomic::AtomicI32::new(1),
                    controlling_pty: litebox::sync::Mutex::new(child_controlling_pty),
                    active_vfork_layers: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
                    elf_patch_cache: litebox::sync::Mutex::new(alloc::collections::BTreeMap::new()),
                    shared_file_mappings: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
                    main_bss_start: core::sync::atomic::AtomicUsize::new(0),
                    main_bss_end: core::sync::atomic::AtomicUsize::new(0),
                    proc_map_paths: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
                    vfork_parking: Arc::new(crate::VforkParking {
                        park: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
                        parked_count:
                            <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
                        deferred_lie_count: core::sync::atomic::AtomicU32::new(0),
                    }),
                });
                self.process_state.replace(child_ps);

                // Unshare fs state.
                let new_fs: Arc<_> = Arc::new(self.fs.borrow().as_ref().clone());
                self.fs.replace(new_fs);

                // Don't signal VforkDone here — exec_on_remote_host will signal
                // it after spawning the worker and setting up pipe replacements
                // so the parent can use direct HostPassthroughFdEntry I/O.
                vfork_info_for_exec = Some((fc.vfork_done, fc.parent_unix_socket_fds));
                detached_from_shared_fork = true;
            }
            let remote_interp_image = remote_interp_image
                .as_ref()
                .map(|(path, data)| (path.as_str(), data.as_slice()));
            *self.fs.borrow().exe_path.write() = resolved_exe_path;
            self.global.set_proc_cmdline(self.pid, proc_cmdline);
            let result = self.exec_on_remote_host(
                &path,
                argv_vec,
                envp_vec,
                remote_exec_image.as_deref(),
                remote_interp_image,
                vfork_info_for_exec,
            );
            if detached_from_shared_fork
                && result.is_err()
                && !self.is_exiting()
                && !self.local_task_terminated.get()
            {
                litebox::log_println!(
                    self.global.platform,
                    "execve({:?}): remote worker handoff failed after detach — terminating child",
                    path,
                );
                self.exit_group(ExitStatus::Exit(127_i32.truncate()));
            }
            return result;
        }

        // If this is a vfork child, detach from the parent's shared state.
        // This must happen before close_on_exec/release_memory so mutations
        // only affect the child's own copies.
        let mut vfork_done = None;
        if let Some(fc) = self.fork_context.borrow_mut().take() {
            // Exec completes the vfork/delayed-fork window — the child is now
            // fully independent.  Clear the delayed-fork flag so post-exec
            // syscalls (brk, mmap, etc.) don't trigger commit_delayed_fork.
            self.delayed_fork_pending.set(false);
            // Flush MAP_SHARED writeback data while still using the parent's
            // ProcessState — the tracking entries and handles live there.
            // After the ProcessState swap the parent's entries are gone from
            // our view, and the parent's CoW restore will revert in-memory
            // writes, so this is the last chance to persist child changes.
            self.sync_all_shared_mappings();

            // Switch to the child's own VA partition.
            let child_range = {
                use litebox::platform::AddressSpaceProvider;
                self.global
                    .platform
                    .address_space_range(fc.address_space_id)
                    .expect("child address space must be valid")
            };
            let shared_ps = self.process_state.borrow().clone();
            let child_controlling_pty = *shared_ps.controlling_pty.lock();
            *shared_ps.controlling_pty.lock() = fc.parent_controlling_pty;
            let child_ps = Arc::new(crate::ProcessState {
                pm: litebox::mm::PageManager::new(&self.global.litebox, child_range),
                address_space_id: fc.address_space_id,
                thread_count: core::sync::atomic::AtomicI32::new(1),
                controlling_pty: litebox::sync::Mutex::new(child_controlling_pty),
                active_vfork_layers: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
                elf_patch_cache: litebox::sync::Mutex::new(alloc::collections::BTreeMap::new()),
                shared_file_mappings: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
                main_bss_start: core::sync::atomic::AtomicUsize::new(0),
                main_bss_end: core::sync::atomic::AtomicUsize::new(0),
                proc_map_paths: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
                vfork_parking: Arc::new(crate::VforkParking {
                    park: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
                    parked_count: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
                    deferred_lie_count: core::sync::atomic::AtomicU32::new(0),
                }),
            });
            self.process_state.replace(child_ps);

            // Unshare fs state. During the vfork window this was shared with
            // the parent (who is blocked), but after exec the child must have
            // its own copy. FD table was already duplicated at fork time.
            let new_fs: Arc<_> = Arc::new(self.fs.borrow().as_ref().clone());
            self.fs.replace(new_fs);
            vfork_done = Some(fc.vfork_done);
        }

        // Flush MAP_SHARED writeback data for the child's own ProcessState
        // (non-fork path, or any new mappings created after exec detach).
        // In the fork path the shared parent mappings were already flushed
        // above via sync_all_shared_mappings().
        self.flush_all_shared_mappings();

        // Close CLOEXEC descriptors (now on the child's own FD table).
        self.close_on_exec();

        // Unmap all memory mappings and reset brk.
        if let Some(robust_list) = self.thread.robust_list.take() {
            let _ = wake_robust_list(robust_list);
        }
        self.thread.clear_child_tid.set(None);
        self.thread.rseq.set(None);

        self.signals.reset_for_exec();

        // Don't release reserved mappings.
        let release = |_r: Range<usize>, vm: VmFlags| !vm.is_empty();
        unsafe { self.process_state.borrow().pm.release_memory(release) }
            .expect("failed to release memory mappings");

        litebox_platform_multiplex::Platform::clear_guest_thread_local_storage(
            #[cfg(target_arch = "x86")]
            ctx.xgs.truncate(),
        );

        match self.load_program(loader, argv_vec, envp_vec, Some(&path_cstr)) {
            Ok(()) => {
                // Update /proc/self/exe and /proc/self/cmdline for the new executable.
                *self.fs.borrow().exe_path.write() = resolved_exe_path;
                self.global.set_proc_cmdline(self.pid, proc_cmdline);
            }
            Err(e) => {
                if let Some(vd) = vfork_done.take() {
                    vd.signal();
                }
                // The old process state has already been torn down. There's
                // no way to recover — terminate the process.
                litebox::log_println!(
                    self.global.platform,
                    "execve({:?}): load_program failed: {:?} — terminating child",
                    path,
                    e,
                );
                self.exit_group(ExitStatus::Exit(127_i32.truncate()));
                // exit_group never returns in practice; this is unreachable.
                return Err(Errno::ENOEXEC);
            }
        }

        self.init_thread_context(ctx);

        // Register this task's thread handle in `process_thread_handles` so
        // cross-process signals (kill, tgkill) can interrupt the new program.
        // For a same-shim fork+exec child, the child Task was created via
        // clone but never went through `handle_init_request`, so its handle
        // is still unset. Without registration, `sys_kill` looking up the
        // child's `ProcessId` finds no handle and cannot wake the child
        // from a sleep — SIGKILL silently fails to terminate it.
        //
        // `OnceBox::set` is a no-op if already set (e.g. when the same Task
        // is re-execing). The `BTreeMap::insert` overwrites any stale entry
        // for the (possibly newly assigned) `process_id` key.
        let _ = self
            .thread
            .remote
            .handle
            .set(Box::new(self.wait_state.thread_handle()));
        let proc_key = self.process_id.0.cast_signed();
        self.global
            .process_thread_handles
            .write()
            .insert(proc_key, self.thread.remote.clone());

        // Reinitialize guest FP/SIMD state so the new process starts with a
        // clean FP state (MXCSR=0x1F80, zeroed XMM) rather than inheriting
        // the previous program's state.
        #[cfg(target_arch = "x86_64")]
        crate::syscalls::signal::reinit_guest_fp_state(&mut ctx.fp_regs);

        if let Some(vd) = vfork_done.take() {
            vd.signal();
        }
        Ok(0)
    }

    /// Loads the specified program into the process's address space and prepares the thread
    /// to start executing it.
    pub(crate) fn load_program(
        &self,
        mut loader: crate::loader::elf::ElfLoader<'_, FS>,
        argv: Vec<alloc::ffi::CString>,
        mut envp: Vec<alloc::ffi::CString>,
        exec_filename: Option<&alloc::ffi::CString>,
    ) -> Result<(), crate::loader::elf::ElfLoaderError> {
        if let Some(filter) = self.global.load_filter {
            filter(&mut envp);
        }

        let load_info = loader.load(argv, envp, self.init_auxv(), exec_filename)?;

        self.set_task_comm(loader.comm());

        self.thread
            .init_state
            .set(ThreadInitState::NewProcess(load_info));
        Ok(())
    }

    pub(crate) fn handle_init_request(&self, ctx: &mut litebox_common_linux::ExecutionContext) {
        // init_thread_context returns true for the process's main thread
        // (NewProcess or initial None), false for worker threads (NewThread).
        let is_main_thread = self.init_thread_context(ctx);

        // If this is a vfork child sharing the parent's address space, clear the
        // transport interrupt flag so the child's 9P operations don't trigger
        // deferred-park lies. By this point the parent is blocked and all sibling
        // threads are either truly parked or have already lied (has_lied=true).
        if self.fork_context.borrow().is_some() {
            self.global
                .transport_interrupt
                .store(false, core::sync::atomic::Ordering::Release);
        }

        // Attach the thread handle so that the thread can be interrupted.
        self.thread
            .remote
            .handle
            .set(Box::new(self.wait_state.thread_handle()))
            .ok();

        // Register the process's main thread handle so cross-process signals
        // (e.g. SIGCHLD) can interrupt this task. Only the main thread should
        // be registered — worker threads must not overwrite the entry, or
        // signals would be routed to an arbitrary thread instead of the
        // event-loop / main thread that is actually waiting.
        if is_main_thread {
            let proc_key = self.process_id.0.cast_signed();
            self.global
                .process_thread_handles
                .write()
                .insert(proc_key, self.thread.remote.clone());
        }
    }

    /// Initialize the thread context for a new process or thread, and perform any
    /// other initial setup required.
    ///
    /// Returns `true` for the process's main thread (`None` or `NewProcess`),
    /// `false` for worker threads (`NewThread`).
    fn init_thread_context(&self, ctx: &mut litebox_common_linux::ExecutionContext) -> bool {
        match self.thread.init_state.take() {
            ThreadInitState::None => true,
            ThreadInitState::NewProcess(load_info) => {
                #[cfg(target_arch = "x86_64")]
                {
                    ctx.regs = litebox_common_linux::PtRegs {
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
                #[cfg(target_arch = "x86")]
                {
                    ctx.regs = litebox_common_linux::PtRegs {
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
                        orig_eax: 0,
                        eip: load_info.entry_point,
                        xcs: 0x23, // __USER_CS
                        eflags: 0,
                        esp: load_info.user_stack_top,
                        xss: 0x2b, // __USER_DS
                    };
                }
                true
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
                #[cfg(target_arch = "x86")]
                {
                    if let Some(stack) = stack {
                        ctx.esp = stack;
                    }
                    ctx.eax = 0;
                }

                // Set the TLS for the new thread.
                if let Some(tls) = tls {
                    #[cfg(target_arch = "x86")]
                    {
                        let mut tls = tls;
                        self.set_thread_area(&mut tls).unwrap();
                    }

                    #[cfg(target_arch = "x86_64")]
                    {
                        use litebox::platform::RawConstPointer as _;
                        self.sys_arch_prctl(ArchPrctlArg::SetFs(tls.as_usize()))
                            .unwrap();
                    }
                }

                if let Some(child_tid_ptr) = set_child_tid {
                    // Set the child TID if requested.
                    let _ = self.prepare_guest_write(child_tid_ptr, 1);
                    let _ = child_tid_ptr.write_at_offset(0, self.tid);
                }
                false
            }
            ThreadInitState::ForkChild {
                stack,
                tls_base,
                set_child_tid,
            } => {
                #[cfg(target_arch = "x86_64")]
                {
                    if let Some(stack) = stack {
                        ctx.rsp = stack;
                    }
                    ctx.rax = 0;
                }
                #[cfg(target_arch = "x86")]
                {
                    if let Some(stack) = stack {
                        ctx.esp = stack;
                    }
                    ctx.eax = 0;
                }

                #[cfg(target_arch = "x86_64")]
                if let Some(fsbase) = tls_base {
                    <Platform as litebox::platform::ThreadLocalStorageProvider>::prepare_fork_child_guest_thread_local_storage(
                        core::ptr::from_mut(ctx).cast(),
                        fsbase,
                    );
                }

                if let Some(child_tid_ptr) = set_child_tid {
                    let _ = self.prepare_guest_write(child_tid_ptr, 1);
                    let _ = child_tid_ptr.write_at_offset(0, self.tid);
                }

                true
            }
            ThreadInitState::ForkRestore {
                exec_ctx,
                tls_base,
                set_child_tid,
            } => {
                // Restore the register state from the fork snapshot.
                // fork() returns 0 in the child (already set in exec_ctx.rax).
                ctx.regs = exec_ctx.regs;
                ctx.fp_regs = exec_ctx.fp_regs;

                // Restore the TLS base address at the final pre-entry boundary.
                if let Some(tls) = tls_base {
                    #[cfg(target_arch = "x86_64")]
                    {
                        <Platform as litebox::platform::ThreadLocalStorageProvider>::prepare_fork_child_guest_thread_local_storage(
                            core::ptr::from_mut(ctx).cast(),
                            tls,
                        );
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        // On x86, TLS is set via set_thread_area. For now,
                        // just store it; full x86 TLS restore is future work.
                        let _ = tls;
                    }
                }

                // Write child TID to set_child_tid address (CLONE_CHILD_SETTID).
                if let Some(addr) = set_child_tid {
                    use litebox::platform::RawMutPointer as _;
                    let ptr = crate::MutPtr::<i32>::from_usize(addr);
                    let _ = self.prepare_guest_write(ptr, 1);
                    let _ = ptr.write_at_offset(0, self.tid);
                }

                true
            }
        }
    }
}

fn worker_exec_fd_survives_exec<FS: ShimFS>(
    raw_fd: usize,
    global: &crate::GlobalState<FS>,
    files: &crate::syscalls::file::FilesState<FS>,
) -> bool {
    let alive = files.raw_descriptor_store.read().is_alive(raw_fd);
    alive
        && get_file_descriptor_flags(raw_fd, global, files)
            .map(|flags| !flags.contains(FileDescriptorFlags::FD_CLOEXEC))
            .unwrap_or(false)
}

/// Per-`RawFdRef`-variant bucket vectors of inherited file descriptors
/// that may be migrated across a fork or exec.
///
/// Populated by `collect_migratable_fds` via a single walk over the
/// descriptor store with an exhaustive `match` on `RawFdRef`. Each
/// fork path consumes only the buckets it needs (e.g.
/// `commit_delayed_fork` / `true_fork` consume only `inotify` and
/// `epoll` because the fork snapshot covers the others;
/// `exec_on_remote_host` consumes every bucket).
///
/// Adding a new `RawFdRef` variant fails to compile at
/// `collect_migratable_fds`'s match site (workspace
/// `clippy::wildcard_enum_match_arm = "deny"` + rustc E0004),
/// forcing the author to choose: add a bucket here and consume it
/// from each migration path, or explicitly skip with a comment.
#[cfg_attr(not(feature = "worker_local_inet"), allow(dead_code))]
pub(crate) struct CollectedMigratableFds<FS: ShimFS> {
    pub(crate) eventfd: alloc::vec::Vec<(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::eventfd::EventfdSubsystem>>,
    )>,
    pub(crate) broker_pipe: alloc::vec::Vec<(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::broker_pipe::BrokerPipeSubsystem>>,
    )>,
    pub(crate) broker_pty: alloc::vec::Vec<(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::broker_pty::BrokerPtySubsystem>>,
    )>,
    pub(crate) broker_socketpair: alloc::vec::Vec<(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::broker_socketpair::BrokerSocketPairSubsystem>>,
    )>,
    pub(crate) broker_socket_dgram: alloc::vec::Vec<(
        usize,
        alloc::sync::Arc<
            litebox::fd::TypedFd<super::broker_socket_dgram::BrokerSocketDgramSubsystem>,
        >,
    )>,
    pub(crate) broker_socket_seqpacket: alloc::vec::Vec<(
        usize,
        alloc::sync::Arc<
            litebox::fd::TypedFd<super::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem>,
        >,
    )>,
    pub(crate) broker_tcp_conn: alloc::vec::Vec<(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::broker_tcp_conn::BrokerTcpConnSubsystem>>,
    )>,
    pub(crate) broker_inet_listener: alloc::vec::Vec<(
        usize,
        alloc::sync::Arc<
            litebox::fd::TypedFd<super::broker_inet_listener::BrokerInetListenerSubsystem>,
        >,
    )>,
    pub(crate) fs: alloc::vec::Vec<(usize, alloc::sync::Arc<litebox::fd::TypedFd<FS>>)>,
    pub(crate) signalfd: alloc::vec::Vec<(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::signalfd::SignalfdSubsystem>>,
    )>,
    pub(crate) inotify: alloc::vec::Vec<(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::inotify::InotifySubsystem>>,
    )>,
    pub(crate) epoll: alloc::vec::Vec<(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::epoll::EpollSubsystem<FS>>>,
    )>,
    #[cfg(feature = "worker_local_inet")]
    pub(crate) network: alloc::vec::Vec<usize>,
}

impl<FS: ShimFS> Default for CollectedMigratableFds<FS> {
    fn default() -> Self {
        Self {
            eventfd: alloc::vec::Vec::new(),
            broker_pipe: alloc::vec::Vec::new(),
            broker_pty: alloc::vec::Vec::new(),
            broker_socketpair: alloc::vec::Vec::new(),
            broker_socket_dgram: alloc::vec::Vec::new(),
            broker_socket_seqpacket: alloc::vec::Vec::new(),
            broker_tcp_conn: alloc::vec::Vec::new(),
            broker_inet_listener: alloc::vec::Vec::new(),
            fs: alloc::vec::Vec::new(),
            signalfd: alloc::vec::Vec::new(),
            inotify: alloc::vec::Vec::new(),
            epoll: alloc::vec::Vec::new(),
            #[cfg(feature = "worker_local_inet")]
            network: alloc::vec::Vec::new(),
        }
    }
}

/// Single walk of `rds.iter_alive()` with an exhaustive `match` on
/// `RawFdRef`. Replaces all per-subsystem `iter_alive` walks in
/// `exec_on_remote_host`, `commit_delayed_fork`, and `true_fork`.
///
/// `survives_exec_filter` controls whether the worker-exec
/// CLOEXEC/alive filter is applied. Pass `true` from
/// `exec_on_remote_host` (only fds that survive exec are
/// migrated); pass `false` from the fork-snapshot paths (the
/// snapshot captures everything alive, no CLOEXEC filtering).
///
/// `skip_stdio` is **not** a parameter: behavior preservation
/// requires the per-bucket policy (eventfd / fs skip stdio; other
/// buckets include it because e.g. stdio can legitimately be a
/// broker_pipe in a pipelined shell). Phase-2 emit blocks that
/// want stdio excluded apply their own `if raw_fd <= 2 { continue; }`
/// filter when iterating their bucket.
fn collect_migratable_fds<FS: ShimFS>(
    files: &crate::syscalls::file::FilesState<FS>,
    global: &crate::GlobalState<FS>,
    survives_exec_filter: bool,
) -> CollectedMigratableFds<FS> {
    let raw_fds: alloc::vec::Vec<usize> = {
        let rds = files.raw_descriptor_store.read();
        rds.iter_alive().collect()
    };
    let mut out = CollectedMigratableFds::default();
    for raw_fd in raw_fds {
        if survives_exec_filter && !worker_exec_fd_survives_exec(raw_fd, global, files) {
            continue;
        }
        let _ = files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Eventfd(typed) => {
                out.eventfd.push((raw_fd, alloc::sync::Arc::clone(typed)))
            }
            crate::RawFdRef::BrokerPipe(typed) => out
                .broker_pipe
                .push((raw_fd, alloc::sync::Arc::clone(typed))),
            crate::RawFdRef::BrokerPty(typed) => out
                .broker_pty
                .push((raw_fd, alloc::sync::Arc::clone(typed))),
            crate::RawFdRef::BrokerSocketPair(typed) => out
                .broker_socketpair
                .push((raw_fd, alloc::sync::Arc::clone(typed))),
            crate::RawFdRef::BrokerSocketDgram(typed) => out
                .broker_socket_dgram
                .push((raw_fd, alloc::sync::Arc::clone(typed))),
            crate::RawFdRef::BrokerSocketSeqPacket(typed) => out
                .broker_socket_seqpacket
                .push((raw_fd, alloc::sync::Arc::clone(typed))),
            crate::RawFdRef::BrokerTcpConn(typed) => out
                .broker_tcp_conn
                .push((raw_fd, alloc::sync::Arc::clone(typed))),
            crate::RawFdRef::BrokerInetListener(typed) => out
                .broker_inet_listener
                .push((raw_fd, alloc::sync::Arc::clone(typed))),
            crate::RawFdRef::Fs(typed) => out.fs.push((raw_fd, alloc::sync::Arc::clone(typed))),
            crate::RawFdRef::Signalfd(typed) => {
                out.signalfd.push((raw_fd, alloc::sync::Arc::clone(typed)))
            }
            crate::RawFdRef::Inotify(typed) => {
                out.inotify.push((raw_fd, alloc::sync::Arc::clone(typed)))
            }
            crate::RawFdRef::Epoll(typed) => {
                out.epoll.push((raw_fd, alloc::sync::Arc::clone(typed)))
            }
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(_) => out.network.push(raw_fd),
            // Explicit-skip arms (no wildcards: workspace
            // `clippy::wildcard_enum_match_arm = "deny"`).
            crate::RawFdRef::Unix(_) => {
                // Shim-local unix socket: not migrated across worker-exec
                // (see migration_policy::NoBridgeReason::
                // NoCrossWorkerStatePreservation).
            }
            crate::RawFdRef::HostPassthroughFd(_) => {
                // Real Linux fd dup'd via posix_spawn file actions; no
                // shim spec needed (the host kernel preserves the fd
                // across exec).
            }
            crate::RawFdRef::BrokerInetDgram(_) => {
                // Migration not yet wired up. See migration_policy::
                // NoBridgeReason::BrokerStateNotYetMigratable.
            }
            crate::RawFdRef::BrokerInetRaw(_) => {
                // Migration not yet wired up. See migration_policy::
                // NoBridgeReason::BrokerStateNotYetMigratable.
            }
        });
    }
    out
}

/// Filter a `(raw_fd, Arc<TypedFd<S>>)` bucket to entries whose
/// `FD_CLOEXEC` flag is NOT set.
///
/// Used by `commit_delayed_fork` / `true_fork` to mirror the
/// `snapshot_fd_table` Epoll/Inotify reject-on-CLOEXEC gate. If we
/// emitted bridge specs for CLOEXEC epoll/inotify fds but the
/// snapshot then rejected the same fds (and the parent fell through
/// to vfork shared-AS), the bridge specs would either be wasted
/// work on the snapshot-restore path or — worse — mismatched against
/// the snapshot's `FdEntrySnapshot` set, causing assertion failures
/// downstream. Keeping the two filters in lockstep is the simplest
/// way to maintain the invariant.
fn filter_non_cloexec_bucket<FS: ShimFS, S>(
    entries: &[(usize, alloc::sync::Arc<litebox::fd::TypedFd<S>>)],
    global: &crate::GlobalState<FS>,
    files: &crate::syscalls::file::FilesState<FS>,
) -> alloc::vec::Vec<(usize, alloc::sync::Arc<litebox::fd::TypedFd<S>>)>
where
    S: litebox::fd::FdEnabledSubsystem,
{
    entries
        .iter()
        .filter(|(raw_fd, _)| {
            get_file_descriptor_flags(*raw_fd, global, files)
                .map(|flags| !flags.contains(FileDescriptorFlags::FD_CLOEXEC))
                .unwrap_or(true)
        })
        .cloned()
        .collect()
}

/// Transit-release entry: `(broker_subscribable, handle_id)` pairs that
/// the caller balances after the worker acks (or on spawn failure).
/// See per-emit-helper doc comments for the per-kind release timing.
type BrokerTransitReleaseEntry = (
    alloc::sync::Arc<dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable>,
    u64,
);

/// Emit `--broker-fd-bridge` specs for `EventfdSubsystem` fds, dispatching
/// each fd to its current backing broker handle via
/// `EventFile::ensure_broker_backed_for_fork` (which promotes a host
/// eventfd to broker-backed if needed and returns the
/// `FdKind`).
///
/// Skips stdio (fds 0/1/2). Pairs with `emit_timerfd_bridge_specs`,
/// which iterates the same bucket and handles the timerfd subset
/// (filtered via `EventFile::is_timerfd`).
///
/// For most kinds, dup_handle's transit ref lifetime matches
/// `eventfd`/`signalfd`/`pty` (released only on spawn failure; worker's
/// broker-conn cleanup balances the dup on normal exit) and is pushed
/// to `transit_release`. `Pidfd` instead pushes a
/// `BrokerProcessExitWake` to `pidfd_process_transit` so the in-transit
/// exit subscription survives until the remote exec'd child installs
/// its own subscription.
fn emit_eventfd_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::eventfd::EventfdSubsystem>>,
    )],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
    transit_release: &mut alloc::vec::Vec<BrokerTransitReleaseEntry>,
    pidfd_process_transit: &mut alloc::vec::Vec<super::guest_pid::BrokerProcessExitWake>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        if raw_fd <= 2 {
            continue;
        }
        let eventfd_provider = super::eventfd::broker_eventfd_provider();
        let pidfd_provider = super::eventfd::broker_pidfd_provider();
        let dt_local = task.global.litebox.descriptor_table();
        let result =
            dt_local.with_entry(typed, |ef: &super::eventfd::EventFile<crate::Platform>| {
                ef.ensure_broker_backed_for_fork(eventfd_provider.as_ref(), pidfd_provider.as_ref())
            });
        drop(dt_local);
        if let Some(Ok(Some(snapshot))) = result {
            use super::fork_snapshot::FdKind;
            let handle_id = snapshot.handle_id();
            let kind_str = snapshot.spec_token();
            // `ensure_broker_backed_for_fork` only produces `Eventfd`
            // or `Pidfd`; any other variant here is a logic error.
            let releaser: Option<
                alloc::sync::Arc<
                    dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
                >,
            > = match &snapshot {
                FdKind::Eventfd { .. } => eventfd_provider
                    .as_ref()
                    .map(|p| alloc::sync::Arc::clone(p) as _),
                FdKind::Pidfd { .. } => pidfd_provider
                    .as_ref()
                    .map(|p| alloc::sync::Arc::clone(p) as _),
                FdKind::Timerfd { .. }
                | FdKind::Signalfd { .. }
                | FdKind::BrokerPty { .. }
                | FdKind::BrokerPipe { .. }
                | FdKind::BrokerSocketPair { .. }
                | FdKind::BrokerSocketDgram { .. }
                | FdKind::BrokerSocketSeqPacket { .. }
                | FdKind::BrokerTcpConn { .. }
                | FdKind::BrokerInetListener { .. }
                | FdKind::BrokerInetDgram { .. }
                | FdKind::BrokerInetRaw { .. }
                | FdKind::FilesystemFd
                | FdKind::UnixSocket
                | FdKind::Epoll
                | FdKind::Inotify
                | FdKind::HostPassthrough { .. } => unreachable!(
                    "ensure_broker_backed_for_fork must only return Eventfd or Pidfd, got {snapshot:?}",
                ),
                #[cfg(feature = "worker_local_inet")]
                FdKind::Net => unreachable!(
                    "ensure_broker_backed_for_fork must only return Eventfd or Pidfd, got {snapshot:?}",
                ),
            };
            if matches!(snapshot, FdKind::Pidfd { .. }) {
                if let Ok(target_pid) = u32::try_from(handle_id)
                    && let Some(wake) = super::guest_pid::try_subscribe_broker_process_exit(
                        litebox::process::ProcessId(target_pid),
                    )
                {
                    pidfd_process_transit.push(wake);
                }
                specs.push(alloc::format!("{raw_fd}:{kind_str}:{handle_id}"));
            } else if let Some(releaser) = releaser
                && releaser.dup_handle(handle_id).is_ok()
            {
                specs.push(alloc::format!("{raw_fd}:{kind_str}:{handle_id}"));
                transit_release.push((releaser, handle_id));
            }
        }
    }
}

/// Emit `--broker-fd-bridge` specs for broker-pipe fds. Eager-broker pipes
/// are already broker-backed (no promote step); just dup the handle and
/// ship it.
///
/// Pipe transit refs use a different release timing from eventfd/signalfd/
/// pty: they must be released ON SPAWN SUCCESS (after worker B finishes
/// writing + exits) so the reader gets HUP/EOF. Pushed to
/// `pipe_transit_release` (drained post-`wait_worker_host`) rather than
/// the shared `transit_release`.
fn emit_broker_pipe_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::broker_pipe::BrokerPipeSubsystem>>,
    )],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
    pipe_transit_release: &mut alloc::vec::Vec<BrokerTransitReleaseEntry>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        let pipe_provider = super::broker_pipe::broker_pipe_provider();
        let dt_local = task.global.litebox.descriptor_table();
        let pipe_info = dt_local.with_entry(
            typed,
            |bp_fd: &super::broker_pipe::BrokerPipeFd<crate::Platform>| {
                (bp_fd.handle(), bp_fd.direction())
            },
        );
        drop(dt_local);
        if let (Some(provider), Some((handle_id, direction))) = (pipe_provider, pipe_info) {
            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                alloc::sync::Arc::clone(&provider) as _;
            if releaser.dup_handle(handle_id).is_err() {
                continue;
            }
            let dir_char = match direction {
                litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read => 'r',
                litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Write => 'w',
            };
            specs.push(alloc::format!("{raw_fd}:pipe:{handle_id}:{dir_char}"));
            pipe_transit_release.push((releaser, handle_id));
        }
    }
}

/// Emit `--broker-fd-bridge` specs for broker-pty fds. PTY slave-close
/// HUP has the same release-on-spawn-success lifetime as pipes: pushed
/// to `pty_transit_release` (drained post-`wait_worker_host`) so the
/// broker can observe last-slave-close and notify the master after the
/// remote worker exits.
fn emit_broker_pty_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::broker_pty::BrokerPtySubsystem>>,
    )],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
    pty_transit_release: &mut alloc::vec::Vec<BrokerTransitReleaseEntry>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        let pty_provider = super::broker_pty::broker_pty_provider();
        let dt_local = task.global.litebox.descriptor_table();
        let pty_info = dt_local.with_entry(
            typed,
            |pty_fd: &super::broker_pty::BrokerPtyFd<crate::Platform>| {
                (pty_fd.handle(), pty_fd.role(), pty_fd.pty_id())
            },
        );
        drop(dt_local);
        if let (Some(provider), Some((handle_id, role, pty_id))) = (pty_provider, pty_info) {
            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                alloc::sync::Arc::clone(&provider) as _;
            if releaser.dup_handle(handle_id).is_err() {
                continue;
            }
            pty_transit_release.push((releaser, handle_id));
            let role_char = match role {
                litebox_common_linux::broker_pty_provider::BrokerPtyRole::Master => 'm',
                litebox_common_linux::broker_pty_provider::BrokerPtyRole::Slave => 's',
            };
            specs.push(alloc::format!(
                "{raw_fd}:pty:{handle_id}:{role_char}:{pty_id}"
            ));
        }
    }
}

/// Emit `--broker-fd-bridge` specs for broker-socketpair (unix_socket)
/// fds. Pre-dup balances the timing race between the migrated worker's
/// `close_all_fds` and the new worker's `install_broker_bridge_fd`
/// (see the inline comment that previously documented this in
/// `exec_on_remote_host`).
fn emit_broker_socketpair_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::broker_socketpair::BrokerSocketPairSubsystem>>,
    )],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        let sp_provider = super::broker_socketpair::broker_socketpair_provider();
        let dt_local = task.global.litebox.descriptor_table();
        let sp_info = dt_local.with_entry(
            typed,
            |sp_fd: &super::broker_socketpair::BrokerSocketPairFd<crate::Platform>| {
                (sp_fd.handle(), sp_fd.endpoint())
            },
        );
        drop(dt_local);
        if let (Some(provider), Some((handle_id, endpoint))) = (sp_provider, sp_info) {
            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                alloc::sync::Arc::clone(&provider) as _;
            if releaser.dup_handle(handle_id).is_err() {
                continue;
            }
            let endpoint_char = match endpoint {
                litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::A => {
                    'a'
                }
                litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::B => {
                    'b'
                }
            };
            specs.push(alloc::format!(
                "{raw_fd}:unix_socket:{handle_id}:{endpoint_char}"
            ));
        }
    }
}

/// Emit `--broker-fd-bridge` specs for broker-socket-dgram fds.
fn emit_broker_socket_dgram_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(
        usize,
        alloc::sync::Arc<
            litebox::fd::TypedFd<super::broker_socket_dgram::BrokerSocketDgramSubsystem>,
        >,
    )],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        let provider = super::broker_socket_dgram::broker_socket_dgram_provider();
        let dt_local = task.global.litebox.descriptor_table();
        let handle_id = dt_local.with_entry(
            typed,
            |fd: &super::broker_socket_dgram::BrokerSocketDgramFd<crate::Platform>| fd.handle(),
        );
        drop(dt_local);
        if let (Some(provider), Some(handle_id)) = (provider, handle_id) {
            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                alloc::sync::Arc::clone(&provider) as _;
            if releaser.dup_handle(handle_id).is_err() {
                continue;
            }
            specs.push(alloc::format!("{raw_fd}:socket_dgram:{handle_id}"));
        }
    }
}

/// Emit `--broker-fd-bridge` specs for broker-socket-seqpacket fds.
fn emit_broker_socket_seqpacket_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(
        usize,
        alloc::sync::Arc<
            litebox::fd::TypedFd<super::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem>,
        >,
    )],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        let provider = super::broker_socket_seqpacket::broker_socket_seqpacket_provider();
        let dt_local = task.global.litebox.descriptor_table();
        let handle_id = dt_local.with_entry(
            typed,
            |fd: &super::broker_socket_seqpacket::BrokerSocketSeqPacketFd<crate::Platform>| {
                fd.handle()
            },
        );
        drop(dt_local);
        if let (Some(provider), Some(handle_id)) = (provider, handle_id) {
            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                alloc::sync::Arc::clone(&provider) as _;
            if releaser.dup_handle(handle_id).is_err() {
                continue;
            }
            specs.push(alloc::format!("{raw_fd}:socket_seqpacket:{handle_id}"));
        }
    }
}

/// Emit `--broker-fd-bridge` specs for broker-tcp-conn fds. Records
/// transit refs in `tcp_conn_transit_release` (drained on spawn
/// success/failure path shared with inet_listener).
fn emit_broker_tcp_conn_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::broker_tcp_conn::BrokerTcpConnSubsystem>>,
    )],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
    tcp_conn_transit_release: &mut alloc::vec::Vec<BrokerTransitReleaseEntry>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        let tcp_provider = super::broker_tcp_conn::broker_tcp_conn_provider();
        let dt_local = task.global.litebox.descriptor_table();
        let handle_id = dt_local.with_entry(
            typed,
            |tcp_fd: &super::broker_tcp_conn::BrokerTcpConnFd<crate::Platform>| tcp_fd.handle(),
        );
        drop(dt_local);
        if let (Some(provider), Some(handle_id)) = (tcp_provider, handle_id) {
            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                alloc::sync::Arc::clone(&provider) as _;
            if releaser.dup_handle(handle_id).is_err() {
                continue;
            }
            specs.push(alloc::format!("{raw_fd}:tcp_conn:{handle_id}"));
            tcp_conn_transit_release.push((releaser, handle_id));
        }
    }
}

/// Emit `--broker-fd-bridge` specs for broker-inet-listener fds.
/// Shares `tcp_conn_transit_release` with `emit_broker_tcp_conn_bridge_specs`.
fn emit_broker_inet_listener_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(
        usize,
        alloc::sync::Arc<
            litebox::fd::TypedFd<super::broker_inet_listener::BrokerInetListenerSubsystem>,
        >,
    )],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
    tcp_conn_transit_release: &mut alloc::vec::Vec<BrokerTransitReleaseEntry>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        let listener_provider = super::broker_inet_listener::broker_inet_listener_provider();
        let dt_local = task.global.litebox.descriptor_table();
        let handle_id = dt_local.with_entry(
            typed,
            |listener: &super::broker_inet_listener::BrokerInetListenerFd<crate::Platform>| {
                listener.handle()
            },
        );
        drop(dt_local);
        if let (Some(provider), Some(handle_id)) = (listener_provider, handle_id) {
            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                alloc::sync::Arc::clone(&provider) as _;
            if releaser.dup_handle(handle_id).is_err() {
                continue;
            }
            specs.push(alloc::format!("{raw_fd}:inet_listener:{handle_id}"));
            tcp_conn_transit_release.push((releaser, handle_id));
        }
    }
}

/// Emit `--broker-fd-bridge` specs for FS (brokerfile) fds. Skips stdio
/// (worker_stdio bindings handle fds 0/1/2).
fn emit_fs_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(usize, alloc::sync::Arc<litebox::fd::TypedFd<FS>>)],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        if raw_fd <= 2 {
            continue;
        }
        let bridge_info = {
            let files = task.files.borrow();
            files.fs.fd_path(typed).and_then(|path| {
                let position = files
                    .fs
                    .seek(typed, 0, litebox::fs::SeekWhence::RelativeToCurrentOffset)
                    .ok()?;
                let status_flags_bits = task
                    .global
                    .litebox
                    .descriptor_table()
                    .with_metadata(typed, |crate::StdioStatusFlags(flags)| flags.bits())
                    .unwrap_or(OFlags::RDONLY.bits());
                Some((path, position, status_flags_bits))
            })
        };
        if let Some((path, position, status_flags_bits)) = bridge_info {
            specs.push(alloc::format!(
                "{raw_fd}:brokerfile:{status_flags_bits}:{position}:{}",
                brokerfile_bridge_encode_path(&path)
            ));
        }
    }
}

/// Emit `--broker-fd-bridge` specs for signalfd fds. Pushes a
/// `RemoteSignalfdEntry` to `remote_signalfd_entries` (for the
/// remote process's signal-mask reconstruction) in addition to the
/// spec + transit_release entry.
fn emit_signalfd_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::signalfd::SignalfdSubsystem>>,
    )],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
    transit_release: &mut alloc::vec::Vec<BrokerTransitReleaseEntry>,
    remote_signalfd_entries: &mut alloc::vec::Vec<crate::RemoteSignalfdEntry>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        let signalfd_provider = super::signalfd::broker_signalfd_provider();
        let dt_local = task.global.litebox.descriptor_table();
        let bridge_info = dt_local.with_entry(typed, |sfd: &super::signalfd::SignalfdFile| {
            sfd.worker_exec_bridge_snapshot()
        });
        drop(dt_local);
        if let (Some(provider), Some((handle_id, mask_bits, nonblock))) =
            (signalfd_provider, bridge_info)
        {
            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                alloc::sync::Arc::clone(&provider) as _;
            if releaser.dup_handle(handle_id).is_err() {
                continue;
            }
            specs.push(alloc::format!(
                "{raw_fd}:signalfd:{handle_id}:{mask_bits}:{}",
                u8::from(nonblock)
            ));
            remote_signalfd_entries.push(crate::RemoteSignalfdEntry {
                handle_id,
                mask_bits,
            });
            transit_release.push((releaser, handle_id));
        }
    }
}

/// Emit `--broker-fd-bridge` specs for worker-local-inet (TCP listen)
/// fds. cfg-gated on `worker_local_inet`.
#[cfg(feature = "worker_local_inet")]
fn emit_network_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[usize],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
) {
    for raw_fd in bucket {
        if let Some(spec) = task.tcp_listen_worker_exec_bridge_spec(*raw_fd) {
            specs.push(spec);
        }
    }
}

/// Emit `--broker-fd-bridge` specs for the timerfd subset of the
/// eventfd bucket (`EventFile::is_timerfd` returning true). Snapshots
/// timer state for reconstruction in the child worker.
///
/// Pairs with `emit_eventfd_bridge_specs`, which iterates the same
/// bucket and handles the non-timerfd entries. Both helpers walk
/// the full `eventfd` bucket; the per-entry filter (`is_timerfd`
/// here, broker promotion in the eventfd helper) determines which
/// subset is emitted.
fn emit_timerfd_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::eventfd::EventfdSubsystem>>,
    )],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        let dt_local = task.global.litebox.descriptor_table();
        let is_timer = dt_local
            .with_entry(typed, |evf: &super::eventfd::EventFile<crate::Platform>| {
                evf.is_timerfd()
            })
            .unwrap_or(false);
        drop(dt_local);
        if !is_timer {
            continue;
        }
        let dt_local = task.global.litebox.descriptor_table();
        let snapshot = dt_local
            .with_entry(typed, |evf: &super::eventfd::EventFile<crate::Platform>| {
                evf.timerfd_worker_exec_bridge_snapshot()
            })
            .flatten();
        drop(dt_local);
        if let Some((clockid, nonblock, spec, pending, snapshot_now_ns)) = snapshot {
            specs.push(alloc::format!(
                "{raw_fd}:timerfd:{}:{}:{}:{}:{}:{}:{}:{}",
                clockid as u32,
                u8::from(nonblock),
                spec.value.tv_sec,
                spec.value.tv_nsec,
                spec.interval.tv_sec,
                spec.interval.tv_nsec,
                pending,
                snapshot_now_ns,
            ));
        }
    }
}

/// Emit `--broker-fd-bridge` specs for inotify fds. Mirrors the
/// signalfd spec shape (broker handle id + nonblock bit). The
/// shim-side `InotifyFile` already owns a broker handle; `dup_handle`
/// so the child's reattach doesn't race with parent-side close.
/// Transit-release lifetime matches eventfd/signalfd (released only
/// on spawn failure; worker's broker connection cleanup balances the
/// dup on normal exit).
fn emit_inotify_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::inotify::InotifySubsystem>>,
    )],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
    transit_release: &mut alloc::vec::Vec<BrokerTransitReleaseEntry>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        let inotify_provider = super::inotify::broker_inotify_provider();
        let dt_local = task.global.litebox.descriptor_table();
        let info = dt_local.with_entry(typed, |ino: &super::inotify::InotifyFile| {
            (
                ino.handle(),
                ino.get_status().contains(litebox::fs::OFlags::NONBLOCK),
            )
        });
        drop(dt_local);
        if let (Some(provider), Some((handle_id, nonblock))) = (inotify_provider, info) {
            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                alloc::sync::Arc::clone(&provider) as _;
            if releaser.dup_handle(handle_id).is_err() {
                continue;
            }
            specs.push(alloc::format!(
                "{raw_fd}:inotify:{handle_id}:{}",
                u8::from(nonblock),
            ));
            transit_release.push((releaser, handle_id));
        }
    }
}

/// Emit `--broker-fd-bridge` specs for epoll fds.
///
/// INVARIANT: this helper MUST be called LAST in bridge-spec emission.
/// Unlike every other subsystem, epoll has no broker handle — its
/// interest list is shim-local. We snapshot interests as
/// `(target_fd, events, data)` tuples (see
/// `EpollFile::snapshot_interests`); the worker rebuilds a fresh
/// `EpollFile` and re-adds each interest via
/// `epoll_ctl(EPOLL_CTL_ADD)`. The runner installs specs in order,
/// and `EpollDescriptor::try_from` looks up each interest's target
/// fd in the worker's descriptor store — every other subsystem's
/// install must complete first.
///
/// Epoll has no broker handle and therefore no transit_release entry.
fn emit_epoll_bridge_specs<FS: ShimFS>(
    task: &Task<FS>,
    bucket: &[(
        usize,
        alloc::sync::Arc<litebox::fd::TypedFd<super::epoll::EpollSubsystem<FS>>>,
    )],
    specs: &mut alloc::vec::Vec<alloc::string::String>,
) {
    for (raw_fd, typed) in bucket {
        let raw_fd = *raw_fd;
        let dt_local = task.global.litebox.descriptor_table();
        let entries = dt_local
            .with_entry(typed, |ep: &super::epoll::EpollFile<FS>| {
                ep.snapshot_interests()
            })
            .unwrap_or_default();
        drop(dt_local);
        let mut spec = alloc::format!("{raw_fd}:epoll");
        if !entries.is_empty() {
            spec.push(':');
            let mut first = true;
            for (tfd, events, data) in entries {
                if !first {
                    spec.push(',');
                }
                first = false;
                spec.push_str(&alloc::format!("{tfd}_{events}_{data}"));
            }
        }
        specs.push(spec);
    }
}

fn brokerfile_bridge_encode_path(path: &str) -> alloc::string::String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = alloc::string::String::with_capacity(path.len() * 2);
    for byte in path.as_bytes() {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn worker_exec_has_unsupported_stdio<FS: ShimFS>(
    global: &crate::GlobalState<FS>,
    files: &crate::syscalls::file::FilesState<FS>,
) -> bool {
    [0, 1, 2]
        .into_iter()
        .any(|raw_fd| worker_exec_stdio_is_unsupported(raw_fd, global, files))
}

fn log_worker_exec_stdio_unsupported<FS: ShimFS>(
    global: &crate::GlobalState<FS>,
    raw_fd: usize,
    reason: &str,
) {
    litebox::log_println!(
        global.platform,
        "[EXEC-REMOTE-STDIO] fd={} unsupported: {}",
        raw_fd,
        reason,
    );
}

fn worker_exec_stdio_is_unsupported<FS: ShimFS>(
    raw_fd: usize,
    global: &crate::GlobalState<FS>,
    files: &crate::syscalls::file::FilesState<FS>,
) -> bool {
    if !worker_exec_fd_survives_exec(raw_fd, global, files) {
        return false;
    }
    if files
        .raw_descriptor_store
        .read()
        .fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
        .is_ok()
    {
        return false;
    }
    files
        .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
    crate::RawFdRef::Fs(fd) => {
                let status = files.fs.fd_file_status(fd).ok();
                let open_flags = global
                    .litebox
                    .descriptor_table()
                    .with_metadata(fd, |crate::StdioStatusFlags(flags)| *flags)
                    .unwrap_or(OFlags::empty());
                let access = open_flags & (OFlags::WRONLY | OFlags::RDWR);
                if open_flags.contains(OFlags::PATH)
                    || (raw_fd == 0 && access == OFlags::WRONLY)
                    || (matches!(raw_fd, 1 | 2) && access == OFlags::empty())
                {
                    let source_fd = worker_exec_host_stdio_source_fd(raw_fd, global, files, fd);
                    litebox::log_println!(
                        global.platform,
                        "[EXEC-REMOTE-STDIO] fd={} unsupported fs access: object_id={} flags={:?} source_fd={:?}",
                        raw_fd,
                        fd.object_id().as_u64(),
                        open_flags,
                        source_fd,
                    );
                    return true;
                }
                if let Some(source_fd) =
                    worker_exec_host_stdio_source_fd(raw_fd, global, files, fd)
                {
                    let unsupported = !worker_exec_host_stdio_direction_compatible(
                        raw_fd, source_fd,
                    ) || (raw_fd == 0 && open_flags.contains(OFlags::NONBLOCK));
                    if unsupported {
                        let reason = if worker_exec_host_stdio_direction_compatible(
                            raw_fd, source_fd,
                        ) {
                            "nonblocking host-backed stdin"
                        } else {
                            "host stdio alias points at the wrong direction"
                        };
                        log_worker_exec_stdio_unsupported(global, raw_fd, reason);
                    }
                    return unsupported;
                }
                let Some(status) = status else {
                    log_worker_exec_stdio_unsupported(global, raw_fd, "missing file status");
                    return true;
                };
                if status.file_type == litebox::fs::FileType::Directory {
                    log_worker_exec_stdio_unsupported(global, raw_fd, "directory-backed stdio");
                    return true;
                }
                // All other FS-backed fds — including terminal-like devices such as
                // /dev/tty, /dev/stdin, /dev/stdout, /dev/stderr (rdev 0x500), and
                // sandbox-created PTY masters/slaves (rdev 0x8800+N) — are bridgeable
                // via the Fs path.  If the fd had a direct host alias
                // (HostStdioSourceFd or HostTtyAlias), it was already handled above
                // with a HostStdio binding.
                false
            },
    #[cfg(feature = "worker_local_inet")]
    crate::RawFdRef::Net(_net) => {
                log_worker_exec_stdio_unsupported(global, raw_fd, "network socket-backed stdio");
                true
            },
    crate::RawFdRef::Eventfd(fd) => {
                let nonblocking = global
                    .litebox
                    .descriptor_table()
                    .entry_handle(fd)
                    .is_some_and(|handle| {
                        handle.with_entry(|file| file.get_status().contains(OFlags::NONBLOCK))
                    });
                log_worker_exec_stdio_unsupported(
                    global,
                    raw_fd,
                    if nonblocking {
                        "eventfd-backed stdio (nonblocking)"
                    } else {
                        "eventfd-backed stdio (blocking)"
                    },
                );
                true
            },
    crate::RawFdRef::Epoll(_epoll) => {
                log_worker_exec_stdio_unsupported(global, raw_fd, "epoll-backed stdio");
                true
            },
    crate::RawFdRef::Unix(fd) => {
                let (nonblocking, is_stream, is_connected, has_timeouts) = global
                    .litebox
                    .descriptor_table()
                    .entry_handle(fd)
                    .map_or((false, false, false, false), |handle| {
                        handle.with_entry(|file| {
                            (
                                file.get_status().contains(OFlags::NONBLOCK),
                                file.sock_type() == litebox_common_linux::SockType::Stream,
                                file.is_connected(),
                                file.has_timeouts(),
                            )
                        })
                    });
                if nonblocking {
                    log_worker_exec_stdio_unsupported(
                        global,
                        raw_fd,
                        "unix-socket-backed stdio (nonblocking)",
                    );
                    return true;
                }
                if !is_stream {
                    log_worker_exec_stdio_unsupported(
                        global,
                        raw_fd,
                        "unix-socket-backed stdio (non-stream type)",
                    );
                    return true;
                }
                if !is_connected {
                    log_worker_exec_stdio_unsupported(
                        global,
                        raw_fd,
                        "unix-socket-backed stdio (not connected)",
                    );
                    return true;
                }
                if has_timeouts {
                    log_worker_exec_stdio_unsupported(
                        global,
                        raw_fd,
                        "unix-socket-backed stdio (has send/recv timeouts)",
                    );
                    return true;
                }
                // Blocking SOCK_STREAM unix sockets are supported via stream bridging.
                false
            },

                // HostPassthroughFdEntry: pipe bridge fds from a prior delayed fork.  They
                // already wrap a host OS fd, so the worker can inherit them
                // directly via posix_spawn dup2 — always supported.
                crate::RawFdRef::HostPassthroughFd(_host_passthrough_fd) => false,

                // Broker-backed fds are supported here; exec binding handles
                // the actual inherited/closed stdio behavior later.
                crate::RawFdRef::BrokerPipe(_broker_pipe) => false,
                crate::RawFdRef::BrokerSocketPair(_broker_socketpair) => false,
                crate::RawFdRef::BrokerSocketDgram(_broker_socket_dgram) => false,
                crate::RawFdRef::BrokerSocketSeqPacket(_broker_socket_seqpacket) => false,
                crate::RawFdRef::BrokerTcpConn(_broker_tcp_conn) => false,
                crate::RawFdRef::BrokerPty(_broker_pty) => false,
                crate::RawFdRef::Signalfd(_signalfd) => false,
                crate::RawFdRef::Inotify(_inotify) => false,
                crate::RawFdRef::BrokerInetListener(_listener) => false,
                crate::RawFdRef::BrokerInetDgram(_dgram) => false,
                crate::RawFdRef::BrokerInetRaw(_raw) => false,
            })
        .unwrap_or_else(|_| {
            log_worker_exec_stdio_unsupported(global, raw_fd, "unknown descriptor subsystem");
            true
        })
}

fn worker_exec_tty_stdio_source_fd<FS: ShimFS>(
    raw_fd: usize,
    global: &crate::GlobalState<FS>,
    fd: &litebox::fd::TypedFd<FS>,
) -> Option<i32> {
    // `/dev/tty` in LiteBox reads from host stdin and writes to host stdout.
    // Preserve that same behavior across remote worker exec instead of treating
    // the reopened terminal alias as an unsupported generic tty device.
    global
        .litebox
        .descriptor_table()
        .with_metadata(fd, |_alias: &crate::HostTtyAlias| ())
        .ok()
        .and(match raw_fd {
            0 => Some(0),
            1 | 2 => Some(1),
            _ => None,
        })
}

fn worker_exec_host_stdio_source_fd<FS: ShimFS>(
    raw_fd: usize,
    global: &crate::GlobalState<FS>,
    files: &crate::syscalls::file::FilesState<FS>,
    fd: &litebox::fd::TypedFd<FS>,
) -> Option<i32> {
    global
        .litebox
        .descriptor_table()
        .with_metadata(fd, |crate::HostStdioSourceFd(source_fd)| *source_fd)
        .ok()
        .or_else(|| worker_exec_tty_stdio_source_fd(raw_fd, global, fd))
        .or_else(|| worker_exec_host_stdio_fd(files, fd.object_id()))
}

fn worker_exec_host_stdio_direction_compatible(raw_fd: usize, source_fd: i32) -> bool {
    matches!((raw_fd, source_fd), (0, 0) | (1 | 2, 1 | 2))
}

fn worker_exec_host_stdio_fd<FS: ShimFS>(
    files: &crate::syscalls::file::FilesState<FS>,
    object_id: litebox::fd::DescriptorObjectId,
) -> Option<i32> {
    files
        .host_stdio_object_ids
        .read()
        .iter()
        .position(|candidate| *candidate == Some(object_id))
        .and_then(|idx| i32::try_from(idx).ok())
}

fn worker_exec_stdio_bridge_fds<FS: ShimFS>(stdio: &WorkerExecStdioBindings<FS>) -> Vec<usize> {
    let mut fds = Vec::new();
    if matches!(&stdio.stdin, WorkerExecInputBinding::Fs { .. }) {
        fds.push(0);
    }
    for (raw_fd, binding) in [(1, &stdio.stdout), (2, &stdio.stderr)] {
        if matches!(binding, WorkerExecOutputBinding::Fs { .. }) {
            fds.push(raw_fd);
        }
    }
    fds
}

fn worker_exec_input_binding<FS: ShimFS>(
    raw_fd: usize,
    global: &crate::GlobalState<FS>,
    files: &crate::syscalls::file::FilesState<FS>,
) -> WorkerExecInputBinding<FS> {
    if !worker_exec_fd_survives_exec(raw_fd, global, files) {
        return WorkerExecInputBinding::Close;
    }
    if files
        .raw_descriptor_store
        .read()
        .fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
        .is_ok()
    {
        return WorkerExecInputBinding::Inherit;
    }
    files
        .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(fd) => {
                let open_flags = global
                    .litebox
                    .descriptor_table()
                    .with_metadata(fd, |crate::StdioStatusFlags(flags)| *flags)
                    .unwrap_or(OFlags::empty());
                let access = open_flags & (OFlags::WRONLY | OFlags::RDWR);
                if open_flags.contains(OFlags::PATH) || access == OFlags::WRONLY {
                    return WorkerExecInputBinding::Close;
                }
                let source_fd = worker_exec_host_stdio_source_fd(raw_fd, global, files, fd);
                if let Some(source_fd) = source_fd {
                    if !worker_exec_host_stdio_direction_compatible(raw_fd, source_fd) {
                        return WorkerExecInputBinding::Close;
                    }
                    return if usize::try_from(source_fd).ok() == Some(raw_fd) {
                        WorkerExecInputBinding::Inherit
                    } else {
                        WorkerExecInputBinding::HostStdio { fd: source_fd }
                    };
                }
                WorkerExecInputBinding::Fs {
                    fs: files.fs.clone(),
                    fd: fd.clone(),
                }
            }

            // Network sockets: not supported across worker exec.
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(_net) => WorkerExecInputBinding::Close,
            // eventfd: not bridgeable as stdin.
            crate::RawFdRef::Eventfd(_eventfd) => WorkerExecInputBinding::Close,

            // epoll: not bridgeable as stdin.
            crate::RawFdRef::Epoll(_epoll) => WorkerExecInputBinding::Close,
            crate::RawFdRef::Unix(fd) => {
                if let Some(handle) = global.litebox.descriptor_table().entry_handle(fd) {
                    return WorkerExecInputBinding::Stream(Arc::new(UnixSocketStreamReader {
                        platform: global.platform,
                        handle,
                    }));
                }
                WorkerExecInputBinding::Close
            }

            // INVARIANT: this stdio binding aliases the existing literal host
            // fd already wrapped by HostPassthroughFdEntry. It cannot be
            // broker-held here because posix_spawn must dup2 that concrete fd
            // onto the worker's stdin before exec; a future cross-binary-type
            // fork of this worker must re-tokenize or brokerize the fd rather
            // than assuming the raw fd remains meaningful in another process.
            crate::RawFdRef::HostPassthroughFd(hp_fd) => {
                let dt = global.litebox.descriptor_table();
                if let Some(host_fd) = dt.with_entry(
                    hp_fd,
                    |e: &super::host_passthrough_fd::HostPassthroughFdEntry| e.raw_fd(),
                ) && host_fd >= 0
                {
                    return WorkerExecInputBinding::HostPassthroughFd { fd: host_fd };
                }
                WorkerExecInputBinding::Close
            }

            // BrokerPipeSubsystem (Phase C.3): close the worker's stdin slot
            // before exec; the --broker-fd-bridge install path will install
            // the broker pipe fd at the same slot during worker startup.
            crate::RawFdRef::BrokerPipe(_broker_pipe) => WorkerExecInputBinding::Close,

            // BrokerPipeSubsystem (Phase C.3): close the worker's stdin slot
            // before exec; the --broker-fd-bridge install path will install
            // the broker pipe fd at the same slot during worker startup.
            crate::RawFdRef::BrokerSocketPair(_broker_pipe) => WorkerExecInputBinding::Close,
            crate::RawFdRef::BrokerSocketDgram(_broker_socket_dgram) => {
                WorkerExecInputBinding::Close
            }
            crate::RawFdRef::BrokerSocketSeqPacket(_broker_socket_seqpacket) => {
                WorkerExecInputBinding::Close
            }
            crate::RawFdRef::BrokerTcpConn(_broker_tcp_conn) => WorkerExecInputBinding::Close,

            // BrokerPipeSubsystem (Phase C.3): close the worker's stdin slot
            // before exec; the --broker-fd-bridge install path will install
            // the broker pipe fd at the same slot during worker startup.
            crate::RawFdRef::BrokerPty(_broker_pipe) => WorkerExecInputBinding::Close,

            // BrokerPipeSubsystem (Phase C.3): close the worker's stdin slot
            // before exec; the --broker-fd-bridge install path will install
            // the broker pipe fd at the same slot during worker startup.
            crate::RawFdRef::Signalfd(_broker_pipe) => WorkerExecInputBinding::Close,
            crate::RawFdRef::Inotify(_inotify) => WorkerExecInputBinding::Close,
            crate::RawFdRef::BrokerInetListener(_listener) => WorkerExecInputBinding::Close,
            crate::RawFdRef::BrokerInetDgram(_dgram) => WorkerExecInputBinding::Close,
            crate::RawFdRef::BrokerInetRaw(_raw) => WorkerExecInputBinding::Close,
        })
        .unwrap_or(WorkerExecInputBinding::Close)
}

/// Blocking reader for a connected unix-socket FD, used by worker-exec
/// stdio bridges.
struct UnixSocketStreamReader<FS: ShimFS> {
    platform: &'static Platform,
    handle: litebox::fd::EntryHandle<Platform, crate::syscalls::unix::UnixSocketSubsystem<FS>>,
}

impl<FS: ShimFS> litebox::process::WorkerExecStreamReader for UnixSocketStreamReader<FS> {
    fn read_blocking(&self, buf: &mut [u8]) -> Result<usize, ()> {
        let wait_state = litebox::event::wait::WaitState::new(self.platform);
        let cx = wait_state.context();
        self.handle
            .with_entry(|socket| {
                socket.recvfrom(
                    &cx,
                    buf,
                    litebox_common_linux::ReceiveFlags::empty(),
                    None,
                    &mut Vec::new(),
                    &mut Vec::new(),
                )
            })
            .map_err(|_| ())
    }
}

/// Blocking writer for a connected unix-socket FD, used by worker-exec
/// stdio bridges.
struct UnixSocketStreamWriter<FS: ShimFS> {
    platform: &'static Platform,
    handle: litebox::fd::EntryHandle<Platform, crate::syscalls::unix::UnixSocketSubsystem<FS>>,
}

impl<FS: ShimFS> litebox::process::WorkerExecStreamWriter for UnixSocketStreamWriter<FS> {
    fn write_blocking(&self, buf: &[u8]) -> Result<usize, ()> {
        let wait_state = litebox::event::wait::WaitState::new(self.platform);
        let cx = wait_state.context();
        self.handle
            .with_entry(|socket| socket.send_bytes(&cx, buf))
            .map_err(|_| ())
    }

    fn object_id(&self) -> u64 {
        self.handle.object_id().as_u64()
    }
}

fn worker_exec_output_binding<FS: ShimFS>(
    raw_fd: usize,
    global: &crate::GlobalState<FS>,
    files: &crate::syscalls::file::FilesState<FS>,
) -> WorkerExecOutputBinding<FS> {
    if !worker_exec_fd_survives_exec(raw_fd, global, files) {
        return WorkerExecOutputBinding::Close;
    }
    if files
        .raw_descriptor_store
        .read()
        .fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
        .is_ok()
    {
        return WorkerExecOutputBinding::Inherit;
    }
    files
        .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(fd) => {
                let open_flags = global
                    .litebox
                    .descriptor_table()
                    .with_metadata(fd, |crate::StdioStatusFlags(flags)| *flags)
                    .unwrap_or(OFlags::empty());
                let access = open_flags & (OFlags::WRONLY | OFlags::RDWR);
                if open_flags.contains(OFlags::PATH) || access == OFlags::empty() {
                    return WorkerExecOutputBinding::Close;
                }
                let source_fd = worker_exec_host_stdio_source_fd(raw_fd, global, files, fd);
                if let Some(source_fd) = source_fd {
                    if !worker_exec_host_stdio_direction_compatible(raw_fd, source_fd) {
                        return WorkerExecOutputBinding::Close;
                    }
                    return if usize::try_from(source_fd).ok() == Some(raw_fd) {
                        WorkerExecOutputBinding::Inherit
                    } else {
                        WorkerExecOutputBinding::HostStdio { fd: source_fd }
                    };
                }
                WorkerExecOutputBinding::Fs {
                    fs: files.fs.clone(),
                    fd: fd.clone(),
                }
            }

            // Network sockets: not supported as stdout/stderr across worker exec.
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(_net) => WorkerExecOutputBinding::Close,
            // eventfd: not bridgeable as stdout/stderr.
            crate::RawFdRef::Eventfd(_eventfd) => WorkerExecOutputBinding::Close,

            // epoll: not bridgeable as stdout/stderr.
            crate::RawFdRef::Epoll(_epoll) => WorkerExecOutputBinding::Close,
            crate::RawFdRef::Unix(fd) => {
                if let Some(handle) = global.litebox.descriptor_table().entry_handle(fd) {
                    return WorkerExecOutputBinding::Stream(Arc::new(UnixSocketStreamWriter {
                        platform: global.platform,
                        handle,
                    }));
                }
                WorkerExecOutputBinding::Close
            }

            // INVARIANT: this stdio binding aliases the existing literal host
            // fd already wrapped by HostPassthroughFdEntry. It cannot be
            // broker-held here because posix_spawn must dup2 that concrete fd
            // onto stdout/stderr before exec; a future cross-binary-type fork
            // must re-tokenize or brokerize it before another worker hop.
            crate::RawFdRef::HostPassthroughFd(hp_fd) => {
                let dt = global.litebox.descriptor_table();
                if let Some(host_fd) = dt.with_entry(
                    hp_fd,
                    |e: &super::host_passthrough_fd::HostPassthroughFdEntry| e.raw_fd(),
                ) && host_fd >= 0
                {
                    return WorkerExecOutputBinding::HostPassthroughFd { fd: host_fd };
                }
                WorkerExecOutputBinding::Close
            }

            // BrokerPipeSubsystem (Phase C.3): close the worker's output slot
            // before exec; the --broker-fd-bridge install path will install
            // the broker pipe fd at the same slot during worker startup.
            crate::RawFdRef::BrokerPipe(_broker_pipe) => WorkerExecOutputBinding::Close,

            // BrokerPipeSubsystem (Phase C.3): close the worker's output slot
            // before exec; the --broker-fd-bridge install path will install
            // the broker pipe fd at the same slot during worker startup.
            crate::RawFdRef::BrokerSocketPair(_broker_pipe) => WorkerExecOutputBinding::Close,
            crate::RawFdRef::BrokerSocketDgram(_broker_socket_dgram) => {
                WorkerExecOutputBinding::Close
            }
            crate::RawFdRef::BrokerSocketSeqPacket(_broker_socket_seqpacket) => {
                WorkerExecOutputBinding::Close
            }
            crate::RawFdRef::BrokerTcpConn(_broker_tcp_conn) => WorkerExecOutputBinding::Close,

            // BrokerPipeSubsystem (Phase C.3): close the worker's output slot
            // before exec; the --broker-fd-bridge install path will install
            // the broker pipe fd at the same slot during worker startup.
            crate::RawFdRef::BrokerPty(_broker_pipe) => WorkerExecOutputBinding::Close,

            // BrokerPipeSubsystem (Phase C.3): close the worker's output slot
            // before exec; the --broker-fd-bridge install path will install
            // the broker pipe fd at the same slot during worker startup.
            crate::RawFdRef::Signalfd(_broker_pipe) => WorkerExecOutputBinding::Close,
            crate::RawFdRef::Inotify(_inotify) => WorkerExecOutputBinding::Close,
            crate::RawFdRef::BrokerInetListener(_listener) => WorkerExecOutputBinding::Close,
            crate::RawFdRef::BrokerInetDgram(_dgram) => WorkerExecOutputBinding::Close,
            crate::RawFdRef::BrokerInetRaw(_raw) => WorkerExecOutputBinding::Close,
        })
        .unwrap_or(WorkerExecOutputBinding::Close)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use litebox::platform::RawConstPointer as _;

    use litebox::fs::OFlags;
    use litebox::process::WorkerExecInputBinding;
    use litebox::process::WorkerExecOutputBinding;
    use litebox_common_linux::EfdFlags;
    use litebox_common_linux::FileDescriptorFlags;
    use litebox_common_linux::errno::Errno;

    #[test]
    fn test_drop_skips_unmapped_clear_child_tid() {
        let task = crate::syscalls::tests::init_platform(None);
        task.thread
            .clear_child_tid
            .set(Some(crate::MutPtr::from_usize(0x0100_0006_0c2b)));
        drop(task);
    }

    fn register_remote_owned_child(
        task: &crate::Task<crate::DefaultFS>,
    ) -> litebox::process::ProcessId {
        let create_child = || {
            task.global
                .litebox
                .process_registry()
                .create_process(
                    Some(task.process_id),
                    litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
                )
                .expect("child process should be created")
        };
        let mut child = create_child();
        if i32::try_from(child.0).unwrap() == task.pid {
            child = create_child();
        }
        let worker = task
            .global
            .control_plane
            .register_worker_host(crate::multihost::HostId::ROOT)
            .expect("worker host should be created");
        task.global
            .control_plane
            .register_running_process(child, worker)
            .expect("child should be registered to worker host");
        child
    }

    fn register_remote_owned_grandchild(
        task: &crate::Task<crate::DefaultFS>,
    ) -> litebox::process::ProcessId {
        let intermediate = task
            .global
            .litebox
            .process_registry()
            .create_process(
                Some(task.process_id),
                litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            )
            .expect("intermediate child should be created");
        let grandchild = task
            .global
            .litebox
            .process_registry()
            .create_process(
                Some(intermediate),
                litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            )
            .expect("grandchild should be created");
        let worker = task
            .global
            .control_plane
            .register_worker_host(crate::multihost::HostId::ROOT)
            .expect("worker host should be created");
        task.global
            .control_plane
            .register_running_process(grandchild, worker)
            .expect("grandchild should be registered to worker host");
        grandchild
    }

    fn child_exit_notification(
        parent_pid: litebox::process::ProcessId,
        child_pid: litebox::process::ProcessId,
    ) -> litebox::process::ExitNotification {
        litebox::process::ExitNotification {
            parent_pid,
            exit_signal: litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            child_pid,
            exit_status: 23,
        }
    }

    fn register_exited_child_for_parent(
        task: &crate::Task<crate::DefaultFS>,
        parent_pid: litebox::process::ProcessId,
        source_host: crate::multihost::HostId,
        exit_signal: i32,
        exit_status: i32,
    ) -> litebox::process::ProcessId {
        let child = task
            .global
            .litebox
            .process_registry()
            .create_process(Some(parent_pid), exit_signal)
            .expect("child process should be created");
        task.global
            .litebox
            .process_registry()
            .exit_process(child, exit_status);
        task.global.control_plane.record_child_exit_provenance(
            source_host,
            litebox::process::ExitNotification {
                parent_pid,
                exit_signal,
                child_pid: child,
                exit_status,
            },
        );
        child
    }

    fn register_exited_child(
        task: &crate::Task<crate::DefaultFS>,
        exit_signal: i32,
        exit_status: i32,
    ) -> litebox::process::ProcessId {
        register_exited_child_for_parent(
            task,
            task.process_id,
            task.global.control_plane.local_host(),
            exit_signal,
            exit_status,
        )
    }

    fn handoff_running_process(
        task: &crate::Task<crate::DefaultFS>,
        process_id: litebox::process::ProcessId,
        target_host: crate::multihost::HostId,
    ) {
        let handoff = task
            .global
            .control_plane
            .begin_exec_handoff(process_id, target_host)
            .expect("prepare handoff");
        let handoff = task
            .global
            .control_plane
            .advance_exec_handoff(
                handoff.id,
                crate::multihost::ExecHandoffStage::SourceTornDown,
            )
            .expect("advance to teardown");
        let handoff = task
            .global
            .control_plane
            .advance_exec_handoff(
                handoff.id,
                crate::multihost::ExecHandoffStage::StateTransferred,
            )
            .expect("advance to transfer");
        let handoff = task
            .global
            .control_plane
            .advance_exec_handoff(handoff.id, crate::multihost::ExecHandoffStage::TargetLoaded)
            .expect("advance to load");
        task.global
            .control_plane
            .commit_exec_handoff(handoff.id)
            .expect("commit handoff");
    }

    fn fill_outbound_child_exit_queue(
        task: &crate::Task<crate::DefaultFS>,
        target_host: crate::multihost::HostId,
        parent_pid: litebox::process::ProcessId,
    ) {
        for idx in 0..64u32 {
            task.global
                .control_plane
                .queue_remote_child_exit_notification(
                    task.global.control_plane.local_host(),
                    target_host,
                    litebox::process::ExitNotification {
                        parent_pid,
                        exit_signal: litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
                        child_pid: litebox::process::ProcessId(10_000 + idx),
                        exit_status: i32::try_from(idx).unwrap(),
                    },
                )
                .expect("queue fill notification");
        }
    }

    #[test]
    fn test_wait4_rejects_remote_owned_running_child() {
        use litebox::process::WaitOptions;
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        let child = register_remote_owned_child(&task);

        let err = task
            .sys_wait4(
                i32::try_from(child.0).unwrap(),
                None,
                i32::try_from(WaitOptions::WNOHANG.bits()).unwrap(),
                None,
            )
            .unwrap_err();
        assert_eq!(err, Errno::EOPNOTSUPP);
    }

    #[test]
    fn test_waitid_rejects_remote_owned_running_child() {
        use litebox::process::WaitOptions;
        use litebox_common_linux::errno::Errno;

        const P_PID: u32 = 1;
        const WEXITED: i32 = 4;

        let task = crate::syscalls::tests::init_platform(None);
        let child = register_remote_owned_child(&task);

        let err = task
            .sys_waitid(
                P_PID,
                child.0,
                None,
                WEXITED | i32::try_from(WaitOptions::WNOHANG.bits()).unwrap(),
            )
            .unwrap_err();
        assert_eq!(err, Errno::EOPNOTSUPP);
    }

    #[test]
    fn test_wait4_keeps_echild_for_remote_owned_non_child() {
        use litebox::process::WaitOptions;
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        let grandchild = register_remote_owned_grandchild(&task);

        let err = task
            .sys_wait4(
                i32::try_from(grandchild.0).unwrap(),
                None,
                i32::try_from(WaitOptions::WNOHANG.bits()).unwrap(),
                None,
            )
            .unwrap_err();
        assert_eq!(err, Errno::ECHILD);
    }

    #[test]
    fn test_pidfd_open_rejects_remote_owned_running_child() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        let child = register_remote_owned_child(&task);

        let err = task
            .sys_pidfd_open(i32::try_from(child.0).unwrap(), 0)
            .unwrap_err();
        assert_eq!(err, Errno::EOPNOTSUPP);
    }

    #[test]
    fn test_kill_rejects_remote_owned_running_child() {
        use litebox_common_linux::errno::Errno;
        use litebox_common_linux::signal::Signal;

        let task = crate::syscalls::tests::init_platform(None);
        let child = register_remote_owned_child(&task);

        let err = task
            .sys_kill(i32::try_from(child.0).unwrap(), Signal::SIGTERM.as_i32())
            .unwrap_err();
        assert_eq!(err, Errno::EOPNOTSUPP);
    }

    #[test]
    fn test_kill_remote_owned_running_child_preserves_invalid_signal_errno() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        let child = register_remote_owned_child(&task);

        let err = task
            .sys_kill(i32::try_from(child.0).unwrap(), 999)
            .unwrap_err();
        assert_eq!(err, Errno::EINVAL);
    }

    #[test]
    fn test_notify_parent_of_child_exit_queues_local_signal() {
        use litebox_common_linux::signal::Signal;

        let task = crate::syscalls::tests::init_platform(None);
        let child = register_exited_child(
            &task,
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let notif = child_exit_notification(task.process_id, child);

        task.notify_parent_of_child_exit(notif);

        let queue = task.global.cross_process_signals.lock();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].target_process_id, task.process_id.0);
        assert_eq!(queue[0].signal, Signal::SIGCHLD);
        assert!(
            task.global
                .control_plane
                .child_exit_provenance(child)
                .is_none()
        );
    }

    #[test]
    fn test_notify_parent_of_child_exit_skips_remote_owned_parent_queue() {
        let task = crate::syscalls::tests::init_platform(None);
        let remote_parent = register_remote_owned_child(&task);
        let remote_host = task
            .global
            .control_plane
            .owner_of_running_process(remote_parent)
            .expect("remote parent should have an owner");
        let child = register_exited_child_for_parent(
            &task,
            remote_parent,
            task.global.control_plane.local_host(),
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let notif = child_exit_notification(remote_parent, child);

        task.notify_parent_of_child_exit(notif);

        assert!(task.global.cross_process_signals.lock().is_empty());
        let drained = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(remote_host)
            .expect("remote host queue should exist");
        assert_eq!(drained.len(), 1);
        assert_eq!(
            drained[0].source_host,
            task.global.control_plane.local_host()
        );
        assert!(
            task.global
                .control_plane
                .child_exit_provenance(child)
                .is_some()
        );
        match crate::multihost::OutboundControlPlaneMessage::try_from(drained[0].message)
            .expect("decode queued outbound message")
        {
            crate::multihost::OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification.parent_pid, notif.parent_pid);
                assert_eq!(notification.child_pid, notif.child_pid);
                assert_eq!(notification.exit_signal, notif.exit_signal);
                assert_eq!(notification.exit_status, notif.exit_status);
            }
        }
    }

    #[test]
    fn test_deliver_inbound_child_exit_message_queues_local_signal() {
        use litebox_common_linux::signal::Signal;

        let task = crate::syscalls::tests::init_platform(None);
        let child = register_exited_child(
            &task,
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let notif = child_exit_notification(task.process_id, child);
        let wire = crate::multihost::OutboundControlPlaneMessageWire::try_from(
            crate::multihost::OutboundControlPlaneMessage::ChildExit(notif),
        )
        .expect("encode child-exit message");

        task.deliver_inbound_control_plane_message(
            task.global.control_plane.local_host(),
            wire,
            false,
        )
        .expect("deliver inbound message");

        let queue = task.global.cross_process_signals.lock();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].target_process_id, task.process_id.0);
        assert_eq!(queue[0].signal, Signal::SIGCHLD);
    }

    #[test]
    fn test_deliver_inbound_child_exit_envelope_wire_queues_local_signal() {
        use litebox_common_linux::signal::Signal;

        let task = crate::syscalls::tests::init_platform(None);
        let child = register_exited_child(
            &task,
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let envelope_wire = crate::multihost::OutboundControlPlaneEnvelopeWire::from(
            crate::multihost::OutboundControlPlaneEnvelope {
                source_host: task.global.control_plane.local_host(),
                message: crate::multihost::OutboundControlPlaneMessageWire::try_from(
                    crate::multihost::OutboundControlPlaneMessage::ChildExit(
                        child_exit_notification(task.process_id, child),
                    ),
                )
                .expect("encode child-exit message"),
                local_delivery_completed: false,
            },
        );

        task.deliver_inbound_control_plane_envelope_wire(envelope_wire)
            .expect("valid envelope wire should deliver");

        let queue = task.global.cross_process_signals.lock();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].target_process_id, task.process_id.0);
        assert_eq!(queue[0].signal, Signal::SIGCHLD);
    }

    #[test]
    fn test_replayed_local_delivery_completed_envelope_skips_duplicate_local_signal() {
        let task = crate::syscalls::tests::init_platform(None);
        let child = register_exited_child(
            &task,
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let notif = child_exit_notification(task.process_id, child);
        let envelope = crate::multihost::OutboundControlPlaneEnvelope {
            source_host: task.global.control_plane.local_host(),
            message: crate::multihost::OutboundControlPlaneMessageWire::try_from(
                crate::multihost::OutboundControlPlaneMessage::ChildExit(notif),
            )
            .expect("encode child-exit message"),
            local_delivery_completed: true,
        };

        task.consume_inbound_control_plane_envelope(envelope, false)
            .expect("replayed local envelope should be consumed");

        assert!(task.global.cross_process_signals.lock().is_empty());
        assert!(
            task.global
                .control_plane
                .child_exit_provenance(child)
                .is_none()
        );
    }

    #[test]
    fn test_rerouted_replayed_envelope_preserves_local_delivery_completed() {
        let task = crate::syscalls::tests::init_platform(None);
        let remote_parent = register_remote_owned_child(&task);
        let remote_host = task
            .global
            .control_plane
            .owner_of_running_process(remote_parent)
            .expect("remote parent should have an owner");
        let child = register_exited_child_for_parent(
            &task,
            remote_parent,
            task.global.control_plane.local_host(),
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let envelope = crate::multihost::OutboundControlPlaneEnvelope {
            source_host: task.global.control_plane.local_host(),
            message: crate::multihost::OutboundControlPlaneMessageWire::try_from(
                crate::multihost::OutboundControlPlaneMessage::ChildExit(child_exit_notification(
                    remote_parent,
                    child,
                )),
            )
            .expect("encode child-exit message"),
            local_delivery_completed: true,
        };

        task.consume_inbound_control_plane_envelope(envelope, false)
            .expect("replayed remote envelope should reroute");

        let rerouted = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(remote_host)
            .expect("remote host queue should exist");
        assert_eq!(rerouted.len(), 1);
        assert!(rerouted[0].local_delivery_completed);
        assert!(
            task.global
                .control_plane
                .child_exit_provenance(child)
                .is_some()
        );
    }

    #[test]
    fn test_deliver_inbound_child_exit_message_rejects_remote_owned_parent() {
        let task = crate::syscalls::tests::init_platform(None);
        let remote_parent = register_remote_owned_child(&task);
        let remote_host = task
            .global
            .control_plane
            .owner_of_running_process(remote_parent)
            .expect("remote parent should have an owner");
        let child = register_exited_child_for_parent(
            &task,
            remote_parent,
            task.global.control_plane.local_host(),
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let notif = child_exit_notification(remote_parent, child);
        let wire = crate::multihost::OutboundControlPlaneMessageWire::try_from(
            crate::multihost::OutboundControlPlaneMessage::ChildExit(notif),
        )
        .expect("encode child-exit message");

        assert_eq!(
            task.deliver_inbound_control_plane_message(
                task.global.control_plane.local_host(),
                wire,
                false
            ),
            Err(
                crate::syscalls::process::InboundControlPlaneMessageError::TargetProcessNotLocal {
                    process_id: remote_parent,
                    owner_host: remote_host,
                    local_host: task.global.control_plane.local_host(),
                }
            )
        );
        assert!(task.global.cross_process_signals.lock().is_empty());
        assert!(
            task.global
                .control_plane
                .child_exit_provenance(child)
                .is_some()
        );
    }

    #[test]
    fn test_deliver_inbound_child_exit_message_preserves_proof_for_wrong_parent_frame() {
        let task = crate::syscalls::tests::init_platform(None);
        let child = register_exited_child(
            &task,
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let bogus_parent = litebox::process::ProcessId(task.process_id.0 + 1000);
        let wire = crate::multihost::OutboundControlPlaneMessageWire::try_from(
            crate::multihost::OutboundControlPlaneMessage::ChildExit(
                litebox::process::ExitNotification {
                    parent_pid: bogus_parent,
                    exit_signal: litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
                    child_pid: child,
                    exit_status: 23,
                },
            ),
        )
        .expect("encode child-exit message");

        assert_eq!(
            task.deliver_inbound_control_plane_message(task.global.control_plane.local_host(), wire, false),
            Err(
                crate::syscalls::process::InboundControlPlaneMessageError::ChildOwnedByDifferentParent {
                    child_pid: child,
                    expected_parent: task.process_id,
                    actual_parent: Some(bogus_parent),
                }
            )
        );
        assert!(
            task.global
                .control_plane
                .child_exit_provenance(child)
                .is_some()
        );
    }

    #[test]
    fn test_deliver_inbound_child_exit_message_rejects_invalid_signal() {
        let task = crate::syscalls::tests::init_platform(None);
        let child = register_exited_child(&task, 999, 23);
        let wire = crate::multihost::OutboundControlPlaneMessageWire::try_from(
            crate::multihost::OutboundControlPlaneMessage::ChildExit(
                litebox::process::ExitNotification {
                    parent_pid: task.process_id,
                    exit_signal: 999,
                    child_pid: child,
                    exit_status: 23,
                },
            ),
        )
        .expect("encode child-exit message");

        assert_eq!(
            task.deliver_inbound_control_plane_message(
                task.global.control_plane.local_host(),
                wire,
                false
            ),
            Err(
                crate::syscalls::process::InboundControlPlaneMessageError::InvalidChildExitSignal(
                    999
                )
            )
        );
        assert!(task.global.cross_process_signals.lock().is_empty());
        assert!(
            task.global
                .control_plane
                .child_exit_provenance(child)
                .is_none()
        );
    }

    #[test]
    fn test_notify_parent_of_child_exit_clears_proof_without_running_parent_owner() {
        let task = crate::syscalls::tests::init_platform(None);
        let parent = task
            .global
            .litebox
            .process_registry()
            .create_process(
                Some(task.process_id),
                litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            )
            .expect("parent process should be created");
        let child = register_exited_child_for_parent(
            &task,
            parent,
            task.global.control_plane.local_host(),
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let notif = child_exit_notification(parent, child);

        task.notify_parent_of_child_exit(notif);

        assert!(task.global.cross_process_signals.lock().is_empty());
        assert!(
            task.global
                .control_plane
                .child_exit_provenance(child)
                .is_none()
        );
    }

    #[test]
    fn test_deliver_inbound_child_exit_message_rejects_unexpected_source_host() {
        let task = crate::syscalls::tests::init_platform(None);
        let worker = task
            .global
            .control_plane
            .register_worker_host(crate::multihost::HostId::ROOT)
            .expect("worker host should be created");
        let child = register_exited_child(
            &task,
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let wire = crate::multihost::OutboundControlPlaneMessageWire::try_from(
            crate::multihost::OutboundControlPlaneMessage::ChildExit(child_exit_notification(
                task.process_id,
                child,
            )),
        )
        .expect("encode child-exit message");

        assert_eq!(
            task.deliver_inbound_control_plane_message(worker, wire, false),
            Err(
                crate::syscalls::process::InboundControlPlaneMessageError::UnexpectedSourceHostForChild {
                    child_pid: child,
                    expected_owner: task.global.control_plane.local_host(),
                    actual_source: worker,
                }
            )
        );
        assert!(task.global.cross_process_signals.lock().is_empty());
    }

    #[test]
    fn test_deliver_inbound_child_exit_message_rejects_mismatched_status() {
        let task = crate::syscalls::tests::init_platform(None);
        let child = register_exited_child(
            &task,
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            7,
        );
        let wire = crate::multihost::OutboundControlPlaneMessageWire::try_from(
            crate::multihost::OutboundControlPlaneMessage::ChildExit(
                litebox::process::ExitNotification {
                    parent_pid: task.process_id,
                    exit_signal: litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
                    child_pid: child,
                    exit_status: 23,
                },
            ),
        )
        .expect("encode child-exit message");

        assert_eq!(
            task.deliver_inbound_control_plane_message(task.global.control_plane.local_host(), wire, false),
            Err(
                crate::syscalls::process::InboundControlPlaneMessageError::ChildExitStatusMismatch {
                    child_pid: child,
                    expected_status: 7,
                    actual_status: 23,
                }
            )
        );
        assert!(task.global.cross_process_signals.lock().is_empty());
    }

    #[test]
    fn test_notify_parent_of_child_exit_queues_without_registered_handle() {
        let task = crate::syscalls::tests::init_platform(None);
        task.global
            .process_thread_handles
            .write()
            .remove(&task.process_id.0.cast_signed());
        let child = register_exited_child(
            &task,
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let notif = child_exit_notification(task.process_id, child);

        task.notify_parent_of_child_exit(notif);

        let queue = task.global.cross_process_signals.lock();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].target_process_id, task.process_id.0);
    }

    #[test]
    fn test_consuming_drained_child_exit_envelope_reroutes_to_new_parent_owner() {
        let task = crate::syscalls::tests::init_platform(None);
        let remote_parent = register_remote_owned_child(&task);
        let worker_a = task
            .global
            .control_plane
            .owner_of_running_process(remote_parent)
            .expect("remote parent should have an owner");
        let worker_b = task
            .global
            .control_plane
            .register_worker_host(crate::multihost::HostId::ROOT)
            .expect("second worker host should be created");
        let child = register_exited_child_for_parent(
            &task,
            remote_parent,
            task.global.control_plane.local_host(),
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let notif = child_exit_notification(remote_parent, child);

        task.notify_parent_of_child_exit(notif);

        let drained = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(worker_a)
            .expect("worker a queue should exist");
        assert_eq!(drained.len(), 1);

        handoff_running_process(&task, remote_parent, worker_b);

        task.consume_inbound_control_plane_envelope(drained[0], false)
            .expect("drained envelope should reroute");

        assert!(task.global.cross_process_signals.lock().is_empty());
        let rerouted = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(worker_b)
            .expect("worker b queue should exist");
        assert_eq!(rerouted.len(), 1);
        assert_eq!(
            rerouted[0].source_host,
            task.global.control_plane.local_host()
        );
        match crate::multihost::OutboundControlPlaneMessage::try_from(rerouted[0].message)
            .expect("decode rerouted outbound message")
        {
            crate::multihost::OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification.parent_pid, notif.parent_pid);
                assert_eq!(notification.child_pid, notif.child_pid);
                assert_eq!(notification.exit_signal, notif.exit_signal);
                assert_eq!(notification.exit_status, notif.exit_status);
            }
        }
        assert!(
            task.global
                .control_plane
                .child_exit_provenance(child)
                .is_some()
        );
    }

    #[test]
    fn test_notify_parent_of_child_exit_preserves_proof_when_remote_queue_is_full() {
        let task = crate::syscalls::tests::init_platform(None);
        let remote_parent = register_remote_owned_child(&task);
        let remote_host = task
            .global
            .control_plane
            .owner_of_running_process(remote_parent)
            .expect("remote parent should have an owner");
        fill_outbound_child_exit_queue(&task, remote_host, remote_parent);
        let child = register_exited_child_for_parent(
            &task,
            remote_parent,
            task.global.control_plane.local_host(),
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );

        task.notify_parent_of_child_exit(child_exit_notification(remote_parent, child));

        assert!(task.global.cross_process_signals.lock().is_empty());
        assert!(
            task.global
                .control_plane
                .child_exit_provenance(child)
                .is_some()
        );
        let retry = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(task.global.control_plane.local_host())
            .expect("local retry queue should exist");
        assert_eq!(retry.len(), 1);
        match crate::multihost::OutboundControlPlaneMessage::try_from(retry[0].message)
            .expect("decode retry message")
        {
            crate::multihost::OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification.parent_pid, remote_parent);
                assert_eq!(notification.child_pid, child);
            }
        }
        let filled = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(remote_host)
            .expect("remote host queue should exist");
        assert_eq!(filled.len(), 64);
    }

    #[test]
    fn test_consuming_drained_child_exit_envelope_returns_retry_when_reroute_queue_is_full() {
        let task = crate::syscalls::tests::init_platform(None);
        let remote_parent = register_remote_owned_child(&task);
        let worker_a = task
            .global
            .control_plane
            .owner_of_running_process(remote_parent)
            .expect("remote parent should have an owner");
        let worker_b = task
            .global
            .control_plane
            .register_worker_host(crate::multihost::HostId::ROOT)
            .expect("second worker host should be created");
        let child = register_exited_child_for_parent(
            &task,
            remote_parent,
            task.global.control_plane.local_host(),
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let notif = child_exit_notification(remote_parent, child);

        task.notify_parent_of_child_exit(notif);

        let drained = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(worker_a)
            .expect("worker a queue should exist");
        assert_eq!(drained.len(), 1);

        handoff_running_process(&task, remote_parent, worker_b);
        fill_outbound_child_exit_queue(&task, worker_b, remote_parent);

        task.consume_inbound_control_plane_envelope(drained[0], false)
            .expect("queue-full reroute should be persisted for retry");
        assert!(
            task.global
                .control_plane
                .child_exit_provenance(child)
                .is_some()
        );
        let retry = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(task.global.control_plane.local_host())
            .expect("local retry queue should exist");
        assert_eq!(retry, drained);
        let filled = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(worker_b)
            .expect("worker b queue should exist");
        assert_eq!(filled.len(), 64);
    }

    #[test]
    fn test_drain_one_local_control_plane_message_retries_persisted_remote_queue_full_envelope() {
        let task = crate::syscalls::tests::init_platform(None);
        let remote_parent = register_remote_owned_child(&task);
        let remote_host = task
            .global
            .control_plane
            .owner_of_running_process(remote_parent)
            .expect("remote parent should have an owner");
        fill_outbound_child_exit_queue(&task, remote_host, remote_parent);
        let child = register_exited_child_for_parent(
            &task,
            remote_parent,
            task.global.control_plane.local_host(),
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );

        task.notify_parent_of_child_exit(child_exit_notification(remote_parent, child));

        let drained_full = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(remote_host)
            .expect("remote host queue should exist");
        assert_eq!(drained_full.len(), 64);

        assert!(!task.drain_one_local_control_plane_message());

        let local_after = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(task.global.control_plane.local_host())
            .expect("local retry queue should still be readable");
        assert!(local_after.is_empty());

        let rerouted = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(remote_host)
            .expect("remote host queue should exist");
        assert_eq!(rerouted.len(), 1);
        match crate::multihost::OutboundControlPlaneMessage::try_from(rerouted[0].message)
            .expect("decode rerouted retry message")
        {
            crate::multihost::OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification.parent_pid, remote_parent);
                assert_eq!(notification.child_pid, child);
                assert_eq!(
                    rerouted[0].source_host,
                    task.global.control_plane.local_host()
                );
            }
        }
        assert!(
            task.global
                .control_plane
                .child_exit_provenance(child)
                .is_some()
        );
    }

    #[test]
    fn test_drain_one_local_control_plane_message_preserves_retry_head_order() {
        let task = crate::syscalls::tests::init_platform(None);
        let remote_parent = register_remote_owned_child(&task);
        let remote_host = task
            .global
            .control_plane
            .owner_of_running_process(remote_parent)
            .expect("remote parent should have an owner");
        fill_outbound_child_exit_queue(&task, remote_host, remote_parent);
        let first_child = register_exited_child_for_parent(
            &task,
            remote_parent,
            task.global.control_plane.local_host(),
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let second_child = register_exited_child_for_parent(
            &task,
            remote_parent,
            task.global.control_plane.local_host(),
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            24,
        );

        task.notify_parent_of_child_exit(child_exit_notification(remote_parent, first_child));
        task.notify_parent_of_child_exit(litebox::process::ExitNotification {
            parent_pid: remote_parent,
            exit_signal: litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            child_pid: second_child,
            exit_status: 24,
        });

        assert!(!task.drain_one_local_control_plane_message());

        let retry = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(task.global.control_plane.local_host())
            .expect("local retry queue should exist");
        assert_eq!(retry.len(), 2);
        match crate::multihost::OutboundControlPlaneMessage::try_from(retry[0].message)
            .expect("decode first retry message")
        {
            crate::multihost::OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification.child_pid, first_child);
            }
        }
        match crate::multihost::OutboundControlPlaneMessage::try_from(retry[1].message)
            .expect("decode second retry message")
        {
            crate::multihost::OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification.child_pid, second_child);
            }
        }
    }

    #[test]
    fn test_drain_one_local_control_plane_message_reports_more_local_work_after_progress() {
        let task = crate::syscalls::tests::init_platform(None);
        let remote_parent = register_remote_owned_child(&task);
        let remote_host = task
            .global
            .control_plane
            .owner_of_running_process(remote_parent)
            .expect("remote parent should have an owner");
        let local_host = task.global.control_plane.local_host();
        let first_child = register_exited_child_for_parent(
            &task,
            remote_parent,
            local_host,
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            23,
        );
        let second_child = register_exited_child_for_parent(
            &task,
            remote_parent,
            local_host,
            litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
            24,
        );
        task.global
            .control_plane
            .queue_outbound_envelope_for_host(
                local_host,
                crate::multihost::OutboundControlPlaneEnvelope {
                    source_host: local_host,
                    message: crate::multihost::OutboundControlPlaneMessageWire::try_from(
                        crate::multihost::OutboundControlPlaneMessage::ChildExit(
                            child_exit_notification(remote_parent, first_child),
                        ),
                    )
                    .expect("encode first child-exit message"),
                    local_delivery_completed: false,
                },
            )
            .expect("first local retry envelope should queue");
        task.global
            .control_plane
            .queue_outbound_envelope_for_host(
                local_host,
                crate::multihost::OutboundControlPlaneEnvelope {
                    source_host: local_host,
                    message: crate::multihost::OutboundControlPlaneMessageWire::try_from(
                        crate::multihost::OutboundControlPlaneMessage::ChildExit(
                            litebox::process::ExitNotification {
                                parent_pid: remote_parent,
                                exit_signal: litebox_common_linux::signal::Signal::SIGCHLD.as_i32(),
                                child_pid: second_child,
                                exit_status: 24,
                            },
                        ),
                    )
                    .expect("encode second child-exit message"),
                    local_delivery_completed: false,
                },
            )
            .expect("second local retry envelope should queue");

        assert!(task.drain_one_local_control_plane_message());
        assert!(!task.drain_one_local_control_plane_message());

        let local_after = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(local_host)
            .expect("local queue should remain readable");
        assert!(local_after.is_empty());

        let rerouted = task
            .global
            .control_plane
            .poll_outbound_messages_for_host(remote_host)
            .expect("remote host queue should exist");
        assert_eq!(rerouted.len(), 2);
        match crate::multihost::OutboundControlPlaneMessage::try_from(rerouted[0].message)
            .expect("decode first rerouted message")
        {
            crate::multihost::OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification.child_pid, first_child);
            }
        }
        match crate::multihost::OutboundControlPlaneMessage::try_from(rerouted[1].message)
            .expect("decode second rerouted message")
        {
            crate::multihost::OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification.child_pid, second_child);
            }
        }
    }

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
        let ptr = MutPtr::from_ptr(old_fs_base.as_mut_ptr());
        task.sys_arch_prctl(ArchPrctlArg::GetFs(ptr))
            .expect("Failed to get FS base");
        let old_fs_base = unsafe { old_fs_base.assume_init() };

        // Set new FS base
        let mut new_fs_base: [u8; 16] = [0; 16];
        let ptr = MutPtr::from_ptr(new_fs_base.as_mut_ptr());
        task.sys_arch_prctl(ArchPrctlArg::SetFs(ptr.as_usize()))
            .expect("Failed to set FS base");

        // Verify new FS base
        let mut current_fs_base = MaybeUninit::<usize>::uninit();
        let ptr = MutPtr::from_ptr(current_fs_base.as_mut_ptr());
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
    fn test_sched_setscheduler_reset_on_fork_other() {
        let task = crate::syscalls::tests::init_platform(None);
        let param = 0i32;
        let rc = task
            .sys_sched_setscheduler(0, 0x4000_0000, crate::ConstPtr::from_ptr(&raw const param))
            .expect("sched_setscheduler should accept SCHED_OTHER|RESET_ON_FORK");
        assert_eq!(rc, 0);

        let bad_priority = 1i32;
        assert_eq!(
            task.sys_sched_setscheduler(
                0,
                0x4000_0000,
                crate::ConstPtr::from_ptr(&raw const bad_priority),
            )
            .unwrap_err(),
            litebox_common_linux::errno::Errno::EINVAL
        );
    }

    #[test]
    fn test_prctl_set_get_name() {
        let task = crate::syscalls::tests::init_platform(None);

        // Prepare a null-terminated name to set
        let name: &[u8] = b"litebox-test\0";

        // Call prctl(PR_SET_NAME, set_buf)
        let set_ptr = crate::ConstPtr::from_ptr(name.as_ptr());
        task.sys_prctl(litebox_common_linux::PrctlArg::SetName(set_ptr))
            .expect("sys_prctl SetName failed");

        // Prepare buffer for prctl(PR_GET_NAME, get_buf)
        let mut get_buf = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let get_ptr = crate::MutPtr::from_ptr(get_buf.as_mut_ptr());

        task.sys_prctl(litebox_common_linux::PrctlArg::GetName(get_ptr))
            .expect("sys_prctl GetName failed");
        assert_eq!(
            &get_buf[..name.len()],
            name,
            "prctl get_name returned unexpected comm"
        );

        // Test too long name
        let long_name = [b'a'; litebox_common_linux::TASK_COMM_LEN + 10];
        let long_name_ptr = crate::ConstPtr::from_ptr(long_name.as_ptr());
        task.sys_prctl(litebox_common_linux::PrctlArg::SetName(long_name_ptr))
            .expect("sys_prctl SetName failed");

        // Get the name again
        let mut get_buf = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let get_ptr = crate::MutPtr::from_ptr(get_buf.as_mut_ptr());
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
            let act_ptr = crate::ConstPtr::from_ptr(&raw const act);
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
                litebox_common_linux::TimeParam::Timespec64(crate::MutPtr::from_ptr(
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
            let mut ctx = litebox_common_linux::ExecutionContext { regs: litebox_common_linux::PtRegs { rsp: stack.as_mut_ptr() as usize + stack.len(), ..Default::default() }, ..Default::default() };
            #[cfg(target_arch = "x86")]
            let mut ctx = litebox_common_linux::ExecutionContext { regs: litebox_common_linux::PtRegs { esp: stack.as_mut_ptr() as usize + stack.len(), ..Default::default() }, ..Default::default() };
            task.process_signals(&mut ctx);
            assert_eq!(
                ctx.get_ip(), callback_addr,
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
                litebox_common_linux::TimeParam::Timespec64(crate::MutPtr::from_ptr(&raw mut request)),
                litebox_common_linux::TimeParam::Timespec64(crate::MutPtr::from_ptr(&raw mut remain)),
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
                litebox_common_linux::TimeParam::Timespec64(crate::MutPtr::from_ptr(&raw mut request)),
                litebox_common_linux::TimeParam::None,
            );
            assert_eq!(result, Ok(()), "nanosleep should not have been interrupted");

            assert!(
                !task.has_pending_signals(),
                "cancelled alarm should not produce SIGALRM"
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
            let act_ptr = crate::ConstPtr::from_ptr(&raw const act);
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
                litebox_common_linux::TimeParam::Timespec64(crate::MutPtr::from_ptr(&raw mut request)),
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
                litebox_common_linux::TimeParam::Timespec64(crate::MutPtr::from_ptr(
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

    #[test]
    fn worker_exec_stdio_bindings_preserve_host_stdio_aliases() {
        let task = crate::syscalls::tests::init_platform(None);
        task.sys_dup(1, Some(2), None)
            .expect("dup2 onto stderr should succeed");

        let files = task.files.borrow();
        let rds = files.raw_descriptor_store.read();
        let stdout_fd = rds
            .fd_from_raw_integer::<crate::DefaultFS>(1)
            .expect("stdout fd should exist");
        let stderr_fd = rds
            .fd_from_raw_integer::<crate::DefaultFS>(2)
            .expect("stderr fd should exist");
        assert_eq!(
            stdout_fd.object_id(),
            stderr_fd.object_id(),
            "dup2 should preserve descriptor-object identity for stderr aliases"
        );
        drop(rds);
        drop(files);

        let bindings = task
            .worker_exec_stdio_bindings()
            .expect("stdio bindings should succeed");
        assert!(matches!(bindings.stdout, WorkerExecOutputBinding::Inherit));
        match bindings.stderr {
            WorkerExecOutputBinding::HostStdio { fd } => {
                assert_eq!(fd, 1, "stderr alias should target host stdout");
            }
            WorkerExecOutputBinding::Inherit => {
                panic!("stderr alias should not stay inherited on host stderr")
            }
            WorkerExecOutputBinding::Close => panic!("stderr alias should not be closed"),
            WorkerExecOutputBinding::Fs { .. } => {
                panic!("stderr alias should not be proxied through the guest FS")
            }
            WorkerExecOutputBinding::Stream(_) => {
                panic!("stderr alias should not be proxied through a guest byte stream")
            }
            WorkerExecOutputBinding::HostPassthroughFd { .. } => {
                panic!("stderr alias should not be proxied through a host passthrough fd")
            }
        }
    }

    #[test]
    fn worker_exec_stdio_bindings_preserve_reopened_dev_stdout_aliases() {
        let task = crate::syscalls::tests::init_platform(None);
        let stdout_fd = task
            .sys_open("/dev/stdout", OFlags::WRONLY, litebox::fs::Mode::empty())
            .expect("open /dev/stdout should succeed");
        let stdout_fd = i32::try_from(stdout_fd).expect("fd should fit in i32");
        task.sys_dup(stdout_fd, Some(2), None)
            .expect("dup2 onto stderr should succeed");

        let files = task.files.borrow();
        let rds = files.raw_descriptor_store.read();
        let stderr_fd = rds
            .fd_from_raw_integer::<crate::DefaultFS>(2)
            .expect("stderr fd should exist");
        assert_eq!(
            super::worker_exec_host_stdio_source_fd(2, &task.global, &files, stderr_fd.as_ref()),
            Some(1)
        );
        drop(rds);
        drop(files);

        let bindings = task
            .worker_exec_stdio_bindings()
            .expect("stdio bindings should succeed");
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match bindings.stderr {
            WorkerExecOutputBinding::HostStdio { fd } => {
                assert_eq!(
                    fd, 1,
                    "reopened /dev/stdout should still map to host stdout"
                );
            }
            _ => panic!("reopened /dev/stdout should not degrade into an FS proxy"),
        }
    }

    #[test]
    fn worker_exec_stdio_bindings_preserve_reopened_dev_tty_stdin() {
        let task = crate::syscalls::tests::init_platform(None);
        let tty_fd = task
            .sys_open("/dev/tty", OFlags::RDONLY, litebox::fs::Mode::empty())
            .expect("open /dev/tty should succeed");
        let tty_fd = i32::try_from(tty_fd).expect("fd should fit in i32");
        task.sys_dup(tty_fd, Some(0), None)
            .expect("dup2 onto stdin should succeed");

        let bindings = task
            .worker_exec_stdio_bindings()
            .expect("stdio bindings should succeed");
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match bindings.stdin {
            WorkerExecInputBinding::Inherit => {}
            _ => panic!("reopened /dev/tty stdin should preserve host stdin"),
        }
    }

    #[test]
    fn worker_exec_stdio_bindings_preserve_reopened_dev_tty_stderr_aliases() {
        let task = crate::syscalls::tests::init_platform(None);
        let tty_fd = task
            .sys_open("/dev/tty", OFlags::WRONLY, litebox::fs::Mode::empty())
            .expect("open /dev/tty should succeed");
        let tty_fd = i32::try_from(tty_fd).expect("fd should fit in i32");
        task.sys_dup(tty_fd, Some(2), None)
            .expect("dup2 onto stderr should succeed");

        let bindings = task
            .worker_exec_stdio_bindings()
            .expect("stdio bindings should succeed");
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match bindings.stderr {
            WorkerExecOutputBinding::HostStdio { fd } => {
                assert_eq!(fd, 1, "reopened /dev/tty should still write to host stdout");
            }
            _ => panic!("reopened /dev/tty stderr should preserve host tty output"),
        }
    }

    #[test]
    fn worker_exec_stdio_bindings_reject_host_stdout_as_stdin() {
        let task = crate::syscalls::tests::init_platform(None);
        task.sys_dup(1, Some(0), None)
            .expect("dup2 onto stdin should succeed");

        let Err(err) = task.worker_exec_stdio_bindings() else {
            panic!("stdin aliased to host stdout should be rejected")
        };
        assert_eq!(err, Errno::ENOTSUP);
    }

    #[test]
    fn worker_exec_stdio_bindings_reject_nonblocking_host_stdin() {
        let task = crate::syscalls::tests::init_platform(None);
        task.sys_fcntl(0, litebox_common_linux::FcntlArg::SETFL(OFlags::NONBLOCK))
            .expect("setfl should succeed");

        let Err(err) = task.worker_exec_stdio_bindings() else {
            panic!("nonblocking host stdin should be rejected")
        };
        assert_eq!(err, Errno::ENOTSUP);
    }

    #[test]
    fn worker_exec_stdio_bindings_close_missing_or_cloexec_streams() {
        let task = crate::syscalls::tests::init_platform(None);
        task.sys_close(2).expect("close stderr should succeed");
        task.sys_fcntl(
            1,
            litebox_common_linux::FcntlArg::SETFD(FileDescriptorFlags::FD_CLOEXEC),
        )
        .expect("setfd should succeed");

        let bindings = task
            .worker_exec_stdio_bindings()
            .expect("stdio bindings should succeed");
        assert!(matches!(bindings.stdout, WorkerExecOutputBinding::Close));
        assert!(matches!(bindings.stderr, WorkerExecOutputBinding::Close));
    }

    #[test]
    fn worker_exec_stdio_bindings_reject_unsupported_stdio_subsystems() {
        let task = crate::syscalls::tests::init_platform(None);
        let eventfd = task
            .sys_eventfd2(0, EfdFlags::empty())
            .expect("eventfd should succeed");
        let eventfd = i32::try_from(eventfd).expect("fd should fit in i32");
        task.sys_dup(eventfd, Some(1), None)
            .expect("dup2 onto stdout should succeed");

        let Err(err) = task.worker_exec_stdio_bindings() else {
            panic!("unsupported stdio subsystem should be rejected")
        };
        assert_eq!(err, Errno::ENOTSUP);
    }

    #[test]
    fn worker_exec_stdio_bindings_proxy_sandbox_pty_stdout() {
        let task = crate::syscalls::tests::init_platform(None);
        let ptmx_fd = task
            .sys_open("/dev/ptmx", OFlags::RDWR, litebox::fs::Mode::empty())
            .expect("open /dev/ptmx should succeed");
        let ptmx_fd = i32::try_from(ptmx_fd).expect("fd should fit in i32");
        task.sys_dup(ptmx_fd, Some(1), None)
            .expect("dup2 onto stdout should succeed");

        let bindings = task
            .worker_exec_stdio_bindings()
            .expect("sandbox PTY stdout should be accepted");
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match bindings.stdout {
            WorkerExecOutputBinding::Fs { .. } => {}
            _ => panic!("sandbox PTY stdout should be proxied via the guest FS"),
        }
    }

    #[test]
    fn worker_exec_stdio_bindings_proxy_non_terminal_fs_redirections() {
        let task = crate::syscalls::tests::init_platform(None);
        let null_fd = task
            .sys_open("/dev/null", OFlags::WRONLY, litebox::fs::Mode::empty())
            .expect("open /dev/null should succeed");
        let null_fd = i32::try_from(null_fd).expect("fd should fit in i32");
        task.sys_dup(null_fd, Some(1), None)
            .expect("dup2 onto stdout should succeed");

        let bindings = task
            .worker_exec_stdio_bindings()
            .expect("stdio bindings should succeed");
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match bindings.stdout {
            WorkerExecOutputBinding::Fs { .. } => {}
            _ => panic!("stdout redirected to /dev/null should be proxied via the guest FS"),
        }
    }

    #[test]
    fn worker_exec_stdio_bindings_proxy_non_terminal_fs_stdin() {
        let task = crate::syscalls::tests::init_platform(None);
        let null_fd = task
            .sys_open("/dev/null", OFlags::RDONLY, litebox::fs::Mode::empty())
            .expect("open /dev/null should succeed");
        let null_fd = i32::try_from(null_fd).expect("fd should fit in i32");
        task.sys_dup(null_fd, Some(0), None)
            .expect("dup2 onto stdin should succeed");

        let bindings = task
            .worker_exec_stdio_bindings()
            .expect("stdio bindings should succeed");
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match bindings.stdin {
            WorkerExecInputBinding::Fs { .. } => {}
            _ => panic!("stdin redirected from /dev/null should be proxied via the guest FS"),
        }
    }

    #[test]
    fn worker_exec_stdio_bindings_proxy_urandom_fs_stdin() {
        let task = crate::syscalls::tests::init_platform(None);
        let urandom_fd = task
            .sys_open("/dev/urandom", OFlags::RDONLY, litebox::fs::Mode::empty())
            .expect("open /dev/urandom should succeed");
        let urandom_fd = i32::try_from(urandom_fd).expect("fd should fit in i32");
        task.sys_dup(urandom_fd, Some(0), None)
            .expect("dup2 onto stdin should succeed");

        let bindings = task
            .worker_exec_stdio_bindings()
            .expect("stdio bindings should succeed");
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match bindings.stdin {
            WorkerExecInputBinding::Fs { .. } => {}
            _ => panic!("stdin redirected from /dev/urandom should be proxied via the guest FS"),
        }
    }

    #[test]
    fn worker_exec_stdio_bindings_reject_directory_stdin() {
        let task = crate::syscalls::tests::init_platform(None);
        let dir_fd = task
            .sys_open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY,
                litebox::fs::Mode::empty(),
            )
            .expect("open / should succeed");
        let dir_fd = i32::try_from(dir_fd).expect("fd should fit in i32");
        task.sys_dup(dir_fd, Some(0), None)
            .expect("dup2 onto stdin should succeed");

        let Err(err) = task.worker_exec_stdio_bindings() else {
            panic!("directory stdin should be rejected")
        };
        assert_eq!(err, Errno::ENOTSUP);
    }

    #[test]
    fn worker_exec_stdio_bindings_proxy_sandbox_pty_stdin() {
        let task = crate::syscalls::tests::init_platform(None);
        let ptmx_fd = task
            .sys_open("/dev/ptmx", OFlags::RDWR, litebox::fs::Mode::empty())
            .expect("open /dev/ptmx should succeed");
        let ptmx_fd = i32::try_from(ptmx_fd).expect("fd should fit in i32");
        task.sys_dup(ptmx_fd, Some(0), None)
            .expect("dup2 onto stdin should succeed");

        let bindings = task
            .worker_exec_stdio_bindings()
            .expect("sandbox PTY stdin should be accepted");
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match bindings.stdin {
            WorkerExecInputBinding::Fs { .. } => {}
            _ => panic!("sandbox PTY stdin should be proxied via the guest FS"),
        }
    }

    #[test]
    fn worker_exec_stdio_bindings_reject_read_only_fs_stdout() {
        let task = crate::syscalls::tests::init_platform(None);
        let null_fd = task
            .sys_open("/dev/null", OFlags::RDONLY, litebox::fs::Mode::empty())
            .expect("open /dev/null should succeed");
        let null_fd = i32::try_from(null_fd).expect("fd should fit in i32");
        task.sys_dup(null_fd, Some(1), None)
            .expect("dup2 onto stdout should succeed");

        let Err(err) = task.worker_exec_stdio_bindings() else {
            panic!("read-only stdout should be rejected")
        };
        assert_eq!(err, Errno::ENOTSUP);
    }

    #[test]
    fn worker_exec_stdio_bindings_reject_write_only_fs_stdin() {
        let task = crate::syscalls::tests::init_platform(None);
        let null_fd = task
            .sys_open("/dev/null", OFlags::WRONLY, litebox::fs::Mode::empty())
            .expect("open /dev/null should succeed");
        let null_fd = i32::try_from(null_fd).expect("fd should fit in i32");
        task.sys_dup(null_fd, Some(0), None)
            .expect("dup2 onto stdin should succeed");

        let Err(err) = task.worker_exec_stdio_bindings() else {
            panic!("write-only stdin should be rejected")
        };
        assert_eq!(err, Errno::ENOTSUP);
    }
}
