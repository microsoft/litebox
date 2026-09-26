// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process/thread related syscalls.

use crate::{ShimFS, ShimPlatform, Task, UserPtr, UserPtrMut};
use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell, UnsafeCell};
use core::mem::offset_of;
use core::ops::{Deref, DerefMut, Range};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering};
use core::time::Duration;
use litebox::event::wait::WaitError;
use litebox::mm::vmem::{PAGE_SIZE, VmFlags};
use litebox::platform::TimerHandle;
use litebox::platform::{ArchSpecificRegister, RawMutex as _};
use litebox::platform::{Instant as _, SystemTime as _, TimeProvider};
use litebox::sync::{
    Mutex,
    futex::{FutexKey, FutexManager},
};
use litebox::utils::TruncateExt as _;
use litebox_common_linux::{
    ArchPrctlArg, CloneFlags, FutexArgs, IntervalTimer, ItimerVal, PrctlArg, TimeParam,
    errno::Errno, signal::Signal,
};

/// Process-management-related state on [`Task`].
pub(crate) struct ThreadState<Platform: ShimPlatform> {
    init_state: Cell<ThreadInitState>,
    process: Arc<Process<Platform>>,
    /// Thread state that can be accessed from a remote thread.
    remote: Arc<ThreadRemote<Platform>>,
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
    /// Signal requested with `PR_SET_PDEATHSIG`, delivered when this process's parent exits.
    /// Linux clears it in every freshly cloned task and preserves it across `execve`.
    parent_death_signal: Cell<Option<Signal>>,
    /// The program the thread is about to `exec`, staged by [`Task::resolve_shebang`] and
    /// consumed by `Task::load_program` once the image is live: the absolute, symlink-resolved
    /// path of the image (`/proc/<pid>/exe`) and the command name (`comm`), which Linux takes
    /// from the basename of the filename handed to `execve` -- `sh` for `/bin/sh`, the script's
    /// own name for a `#!` script -- not from the image finally mapped. Staged rather than
    /// threaded through the ELF loader because the loader keeps its path private and the
    /// initial-program path is resolved by the shim's own `load_program` entry point, which
    /// never sees a `Task` method.
    staged_exec: RefCell<Option<StagedExec>>,
}

/// See `ThreadState::staged_exec`.
struct StagedExec {
    exe: alloc::string::String,
    comm: Vec<u8>,
}

// TODO: remove once we figure out how to handle Send/Sync for raw pointers.
unsafe impl<Platform: ShimPlatform> Send for ThreadState<Platform> {}

impl<Platform: ShimPlatform> ThreadState<Platform> {
    pub fn new_process(pid: i32, process_group_id: i32) -> Self {
        Self::new_process_with_shared_futex_manager(
            pid,
            process_group_id,
            Arc::new(FutexManager::new()),
            None,
        )
    }

    fn new_forked_process(
        pid: i32,
        process_group_id: i32,
        shared_futex_manager: Arc<FutexManager<Platform>>,
        launch: Arc<ProcessLaunch<Platform>>,
    ) -> Self {
        Self::new_process_with_shared_futex_manager(
            pid,
            process_group_id,
            shared_futex_manager,
            Some(launch),
        )
    }

    fn new_vfork_copy_process(
        pid: i32,
        process_group_id: i32,
        shared_futex_manager: Arc<FutexManager<Platform>>,
        completion: Arc<VforkCompletion<Platform>>,
        launch: Arc<ProcessLaunch<Platform>>,
    ) -> Self {
        let futex_namespace = shared_futex_manager.new_private_namespace();
        Self::new_process_with_futex_namespace(
            pid,
            process_group_id,
            shared_futex_manager,
            futex_namespace,
            Some(completion),
            None,
            Some(launch),
        )
    }

    fn new_vforked_process(
        pid: i32,
        process_group_id: i32,
        parent: &Process<Platform>,
        completion: Arc<VforkCompletion<Platform>>,
        launch: Arc<ProcessLaunch<Platform>>,
    ) -> Self {
        Self::new_process_with_futex_namespace(
            pid,
            process_group_id,
            parent.futex_manager.clone(),
            parent.futex_namespace(),
            Some(completion),
            Some(parent),
            Some(launch),
        )
    }

    fn new_process_with_shared_futex_manager(
        pid: i32,
        process_group_id: i32,
        shared_futex_manager: Arc<FutexManager<Platform>>,
        launch: Option<Arc<ProcessLaunch<Platform>>>,
    ) -> Self {
        let futex_namespace = shared_futex_manager.new_private_namespace();
        Self::new_process_with_futex_namespace(
            pid,
            process_group_id,
            shared_futex_manager,
            futex_namespace,
            None,
            None,
            launch,
        )
    }

    fn new_process_with_futex_namespace(
        pid: i32,
        process_group_id: i32,
        futex_manager: Arc<FutexManager<Platform>>,
        futex_namespace: usize,
        vfork_completion: Option<Arc<VforkCompletion<Platform>>>,
        shared_vm_parent: Option<&Process<Platform>>,
        launch: Option<Arc<ProcessLaunch<Platform>>>,
    ) -> Self {
        let remote = Arc::new(ThreadRemote::new());
        Self {
            init_state: Cell::new(ThreadInitState::None),
            process: Arc::new(Process::new(
                pid,
                process_group_id,
                remote.clone(),
                futex_manager,
                futex_namespace,
                vfork_completion,
                shared_vm_parent,
                launch,
            )),
            remote,
            attached_tid: Cell::new(Some(pid)),
            clear_child_tid: Cell::new(None),
            robust_list: Cell::new(None),
            parent_death_signal: Cell::new(None),
            staged_exec: RefCell::new(None),
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
            parent_death_signal: Cell::new(None),
            staged_exec: RefCell::new(None),
        })
    }

    /// Detaches this thread from its process.
    ///
    /// Returns `true` if this was the last thread of the process to detach (i.e., the whole
    /// process is now gone), `false` otherwise -- including when this thread was already
    /// detached (so callers relying on this to run exactly-once cleanup, like closing every fd
    /// on process exit, don't double-run it if `Drop` invokes this a second time).
    fn detach_from_process(&self) -> bool {
        if let Some(tid) = self.attached_tid.take() {
            self.process.detach_thread(tid)
        } else {
            false
        }
    }
}

impl<Platform: ShimPlatform> Drop for ThreadState<Platform> {
    fn drop(&mut self) {
        self.detach_from_process();
    }
}

/// Thread state that can be accessed from a remote thread.
/// Closed bit of [`Process::fork_gate`]'s word; the low 31 bits count parked
/// threads.
const FORK_GATE_CLOSED: u32 = 1 << 31;

/// Reopens a [`Process::fork_gate`] closed by
/// [`Task::park_sibling_threads_for_fork`] when dropped, releasing every
/// parked sibling. Held across the whole of `do_fork`'s remaining body --
/// including the parent's suspension for the child's address-space turn -- so
/// the gate reopens on success, on any error return, and on panic alike.
struct ForkGateGuard<'a, Platform: ShimPlatform> {
    process: &'a Process<Platform>,
}

impl<Platform: ShimPlatform> Drop for ForkGateGuard<'_, Platform> {
    fn drop(&mut self) {
        self.process
            .fork_gate
            .underlying_atomic()
            .fetch_and(!FORK_GATE_CLOSED, Ordering::AcqRel);
        self.process.fork_gate.wake_all();
    }
}

pub(crate) struct ThreadRemote<Platform: ShimPlatform> {
    /// Always set under the process `inner` lock, but can be read without
    /// locking.
    is_exiting: AtomicBool,
    /// Handle to interrupt waits on this thread.
    handle: once_cell::race::OnceBox<litebox::event::wait::ThreadHandle<Platform>>,
    /// Signals directed at this specific thread by a remote `tkill`/`tgkill` (as opposed to a
    /// process-directed `kill`, which uses [`Process`]-wide `shared_pending` instead). The
    /// owning task's own `signals.pending` is a bare `RefCell` and therefore neither `Send` nor
    /// `Sync` -- it can only ever be touched by the thread it belongs to -- so a sender on a
    /// different thread has nowhere else to hand off a specifically-targeted signal. Drained
    /// into that `RefCell` by the owning thread itself in `Task::process_signals`/
    /// `Task::has_pending_signals`, the same way `Process::shared_pending` already is.
    remote_pending: Mutex<Platform, super::signal::PendingSignals>,
    /// `ptrace` attach/stop state for this thread. See [`super::ptrace::PtraceState`].
    ///
    /// AArch64-only: `NT_PRSTATUS`/`NT_ARM_TLS` wire layouts and the `PTRACE_*` request numbers
    /// this builds on live in `litebox_common_linux::ptrace`, gated the same way.
    #[cfg(target_arch = "aarch64")]
    pub(crate) ptrace: super::ptrace::PtraceState<Platform>,
    /// This thread's command name, as `/proc/<pid>/task/<tid>/comm` reports it. The owning
    /// task's `comm` is a `Cell` only its own thread may read, so the value is mirrored here for
    /// `/proc` readers on other threads (see `Task::set_task_comm`).
    comm: Mutex<Platform, [u8; litebox_common_linux::TASK_COMM_LEN]>,
    /// This thread's nice value (`-20..=19`), the `setpriority(PRIO_PROCESS, tid)` /
    /// `getpriority` state. Per thread, as on Linux, where every thread is its own scheduling
    /// entity; lives here so a sibling thread's `getpriority(tid)` can read it. Purely
    /// bookkeeping -- the host scheduler is never told.
    nice: core::sync::atomic::AtomicI32,
}

impl<Platform: ShimPlatform> ThreadRemote<Platform> {
    fn new() -> Self {
        Self {
            is_exiting: AtomicBool::new(false),
            handle: once_cell::race::OnceBox::new(),
            remote_pending: Mutex::new(super::signal::PendingSignals::new()),
            #[cfg(target_arch = "aarch64")]
            ptrace: super::ptrace::PtraceState::new(),
            comm: Mutex::new([0; litebox_common_linux::TASK_COMM_LEN]),
            nice: core::sync::atomic::AtomicI32::new(0),
        }
    }

    /// The thread's nice value; see [`Self::nice`].
    pub(crate) fn nice(&self) -> i32 {
        self.nice.load(Ordering::Relaxed)
    }

    pub(crate) fn set_nice(&self, nice: i32) {
        self.nice.store(nice, Ordering::Relaxed);
    }

    /// Mirror the owning task's command name for `/proc` readers.
    pub(crate) fn set_comm(&self, comm: &[u8; litebox_common_linux::TASK_COMM_LEN]) {
        *self.comm.lock() = *comm;
    }

    /// The command name, trimmed of trailing NULs.
    fn comm(&self) -> Vec<u8> {
        let comm = *self.comm.lock();
        let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
        comm[..end].to_vec()
    }

    /// Interrupts a wait or, under HVF, kicks the vCPU lane this thread may currently be running
    /// on -- see [`litebox::event::wait::ThreadHandle::interrupt`]. `pub(crate)` (rather than
    /// only `super`-visible) so `syscalls::ptrace`'s `PTRACE_ATTACH` can reach a tracee that may
    /// be deep inside a blocking syscall or `hv_vcpu_run`, the same way `tkill`/process-directed
    /// signals already do.
    pub(crate) fn interrupt(&self) {
        if let Some(handle) = self.handle.get() {
            handle.interrupt();
        }
    }

    /// Queues `signal` for specifically this thread (a `tkill`/`tgkill` target) and wakes it out
    /// of any interruptible wait so it notices next time it checks for pending signals. Safe to
    /// call from any thread: `remote_pending` is the one piece of this thread's signal state
    /// that is `Send`/`Sync`, precisely so a sender elsewhere never has to touch the owning
    /// thread's local, non-`Send` `SignalState`.
    pub(crate) fn deliver_remote_signal(
        &self,
        rlimits: &ResourceLimits,
        signal: litebox_common_linux::signal::Signal,
        siginfo: litebox_common_linux::signal::Siginfo,
    ) {
        self.remote_pending.lock().push(rlimits, signal, siginfo);
        self.interrupt();
    }

    /// Drains any signals queued for specifically this thread (see `remote_pending`) into
    /// `local`, the owning task's own thread-local pending set. Called only by the thread this
    /// `ThreadRemote` belongs to.
    pub(crate) fn drain_remote_signals_into(&self, local: &mut super::signal::PendingSignals) {
        let mut remote = self.remote_pending.lock();
        remote.drain_into(local);
    }
}

/// Sentinel used by [`Process::controlling_pty`]. PTY numbers are allocated upward from zero and
/// never use this value.
const NO_CONTROLLING_PTY: u32 = u32::MAX;

/// A Linux process, which may have multiple threads.
pub(crate) struct Process<Platform: ShimPlatform> {
    /// Number of threads in this process. Always updated under the `inner`
    /// mutex lock.
    nr_threads: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    /// Stop-the-world gate for `fork` from a multithreaded process.
    ///
    /// The delayed-address-space-handoff fork model (see [`SharedAddressSpace`])
    /// requires that no sibling thread touches guest memory during the child's
    /// turn: the parent's private memory is snapshotted at `fork` and restored
    /// when the turn comes back, so a sibling that kept running would have its
    /// writes silently rolled back. Rather than refusing `fork` outright for
    /// multithreaded guests (which breaks every libuv/Node `spawn`, whose
    /// child does nothing but the classic dup2/close/execve dance), the
    /// forking thread closes this gate: every sibling parks here -- woken out
    /// of any interruptible wait by [`ThreadRemote::interrupt`] and caught at
    /// the `CheckForInterrupt::check_for_interrupt`/
    /// [`Task::prepare_to_run_guest`] choke points before it can touch guest
    /// memory again -- until the parent's turn resumes and the gate reopens.
    ///
    /// Word layout: bit 31 = closed; low 31 bits = number of currently-parked
    /// threads. Mirrors how `nr_threads` uses its `RawMutex` word purely as a
    /// blockable atomic.
    fork_gate: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    inner: Arc<Mutex<Platform, ProcessInner<Platform>>>,
    /// The swappable identity of the Linux `mm_struct`-like bookkeeping this process uses.
    /// A vfork child gets its own slot pointing at the parent's identity, then swaps only its slot
    /// to a fresh identity on successful exec.
    vm: Arc<VmBookkeepingSlot<Platform>>,
    /// Futex wait queues inherited by every process in one fork family.
    ///
    /// Each independent VM identity has a distinct private futex namespace; MAP_SHARED
    /// non-private keys instead use the manager's reserved shared namespace zero.
    futex_manager: Arc<FutexManager<Platform>>,
    vfork_completion: Mutex<Platform, Option<Arc<VforkCompletion<Platform>>>>,
    /// Whether this vfork child points at its parent's live VM identity, independently of whether
    /// its parent waits for exec/exit. Lone `CLONE_VFORK` waits but owns a copied VM.
    shares_parent_vm: AtomicBool,
    launch: Option<Arc<ProcessLaunch<Platform>>>,
    /// Resource limits for this process.
    pub(crate) limits: Arc<ResourceLimits>,
    /// Process-wide alarm timer.
    pub(crate) alarm_timer: Mutex<Platform, Alarm<Platform>>,
    /// The address ranges this process (as opposed to some other guest process sharing the same
    /// host address space) had mapped.
    ///
    /// Needed because `fork` has to be able to save and restore *this* process's memory without
    /// touching a sibling's -- see [`Task::save_address_space`]. The page manager's own view is
    /// process-blind: it is one flat map of every guest mapping in the shim.
    pub(crate) owned_ranges: SharedVmLockedField<Platform, OwnedRanges>,
    /// Runtime ELF rewriting state for this process's VM identity.
    pub(crate) elf_patch_cache: SharedVmLockedField<Platform, super::mm::ElfPatchCache>,
    /// This process's program break.
    ///
    /// Every guest process shares one [`litebox::mm::PageManager`] (they live at disjoint
    /// addresses in the one host address space), and that manager tracks a single break, so the
    /// authoritative per-process value has to live here and be swapped into the manager around
    /// each break operation. See `Task::sys_brk`.
    pub(crate) brk: SharedVmAtomicUsize<Platform>,
    /// Total host CPU time (nanoseconds) consumed by every thread of this process so far.
    ///
    /// Each thread adds its own [`litebox::platform::TimeProvider::thread_cpu_time`] reading
    /// here as it exits (see
    /// `Task::prepare_for_exit`), since that clock is only readable by the thread it measures.
    /// Reported to a `wait4(..., &rusage)` caller as `ru_utime` once the whole process is a
    /// zombie -- see `Task::sys_wait4`.
    pub(crate) cpu_time_nanos: core::sync::atomic::AtomicU64,
    /// Session inherited across `fork` and replaced by `setsid`.
    session_id: AtomicI32,
    /// Process-group identity inherited across `fork` and shared by every thread in this process.
    /// The process table keeps only a weak reference to this atomic, so remote parent operations do
    /// not make the whole (platform-specific and potentially non-`Send`) process object global.
    #[expect(
        clippy::struct_field_names,
        reason = "the full POSIX term distinguishes it from session identity"
    )]
    process_group_id: Arc<AtomicI32>,
    /// Unix98 PTY number serving as this process's controlling terminal, or
    /// [`NO_CONTROLLING_PTY`] when it has none.
    controlling_pty: AtomicU32,
    /// This process's place in a [`SharedAddressSpace`], `None` when its memory is its own.
    /// Process-wide (every thread runs on the same memory and takes turns as one member), see
    /// [`AddressSpaceMembership`].
    pub(crate) address_space: Mutex<Platform, Option<Arc<AddressSpaceMembership<Platform>>>>,
    /// `prctl(PR_SET_DUMPABLE)` state. Linux keeps this on the `mm` (so it is process-wide,
    /// inherited by `fork` and reset by `execve`: to 1 for an ordinary exec, to the
    /// `suid_dumpable` sysctl's default 0 for a set-uid/set-gid one). Only the flag itself is
    /// modelled -- LiteBox writes no core dumps and has no `ptrace` access check that consults
    /// it -- so that a launcher like Chromium's `chrome-sandbox`, which clears it before
    /// dropping root and `CHECK`s that it read back 0, sees Linux's answers.
    dumpable: AtomicBool,
}

/// What `/proc/<pid>/{status,stat,cmdline,exe}` describe about a process, kept where a reader
/// on another thread can see it (the owning task's credentials and `comm` are thread-local
/// `Cell`s/`RefCell`s). Refreshed by the owning task on every change it makes (`execve`,
/// `prctl(PR_SET_NAME)`) and ahead of each of its own `/proc` lookups, so a reader sees at worst
/// the state as of the target's last publish -- a live `setuid` by a process that never looks at
/// `/proc` afterwards is the one thing that can lag.
#[derive(Clone, Default)]
pub(crate) struct ProcIdentity {
    ppid: i32,
    uid: u32,
    gid: u32,
    /// The thread-group leader's command name, trimmed of trailing NULs.
    comm: Vec<u8>,
    /// NUL-separated, NUL-terminated `argv` of the current image.
    cmdline: Vec<u8>,
    /// Absolute, symlink-resolved path of the current image (`/proc/<pid>/exe`).
    exe: Option<alloc::string::String>,
}

/// A set of address ranges, kept sorted and non-overlapping.
///
/// Small and linear on purpose: it holds one entry per live mapping of a single guest process,
/// which is a handful for the programs this shim runs, and it is only walked when that process
/// `fork`s.
#[derive(Clone, Default)]
pub(crate) struct OwnedRanges {
    ranges: Vec<Range<usize>>,
}

impl OwnedRanges {
    /// Adds `range`, replacing anything it overlaps.
    pub(crate) fn insert(&mut self, range: Range<usize>) {
        if range.is_empty() {
            return;
        }
        self.remove(range.clone());
        let at = self.ranges.partition_point(|r| r.start < range.start);
        self.ranges.insert(at, range);
    }

    /// The parts of this set that `other` does not cover.
    fn difference(&self, other: &OwnedRanges) -> OwnedRanges {
        let mut out = OwnedRanges::default();
        for range in &self.ranges {
            let mut cursor = range.start;
            for covered in other.intersect(range) {
                if cursor < covered.start {
                    out.ranges.push(cursor..covered.start);
                }
                cursor = cursor.max(covered.end);
            }
            if cursor < range.end {
                out.ranges.push(cursor..range.end);
            }
        }
        out
    }

    /// Adds every range of `other`, merging with whatever it overlaps (a true union, unlike
    /// [`Self::insert`], which replaces).
    fn union_with(&mut self, other: &OwnedRanges) {
        for range in &other.ranges {
            let mut lo = range.start;
            let mut hi = range.end;
            for existing in &self.ranges {
                if existing.start < hi && lo < existing.end {
                    lo = lo.min(existing.start);
                    hi = hi.max(existing.end);
                }
            }
            self.insert(lo..hi);
        }
    }

    fn insert_bounded(&mut self, range: Range<usize>, max_ranges: usize) {
        self.insert(range);
        if self.ranges.len() > max_ranges {
            let start = self.ranges.first().unwrap().start;
            let end = self.ranges.last().unwrap().end;
            self.ranges.clear();
            self.ranges.push(start..end);
        }
    }

    /// Removes `range`, splitting any entry that only partially overlaps it.
    pub(crate) fn remove(&mut self, range: Range<usize>) {
        if range.is_empty() {
            return;
        }
        let mut out = Vec::with_capacity(self.ranges.len() + 1);
        for r in self.ranges.drain(..) {
            if r.end <= range.start || r.start >= range.end {
                out.push(r);
                continue;
            }
            if r.start < range.start {
                out.push(r.start..range.start);
            }
            if r.end > range.end {
                out.push(range.end..r.end);
            }
        }
        self.ranges = out;
    }

    pub(crate) fn clear(&mut self) {
        self.ranges.clear();
    }

    /// The parts of `range` that this set covers.
    fn intersect(&self, range: &Range<usize>) -> impl Iterator<Item = Range<usize>> + '_ {
        let range = range.clone();
        self.ranges.iter().filter_map(move |r| {
            let start = r.start.max(range.start);
            let end = r.end.min(range.end);
            (start < end).then_some(start..end)
        })
    }
}

struct VmLockedValue<Platform: ShimPlatform, T> {
    state: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    value: UnsafeCell<T>,
}

impl<Platform: ShimPlatform, T> VmLockedValue<Platform, T> {
    fn new(value: T) -> Self {
        Self {
            state: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
            value: UnsafeCell::new(value),
        }
    }

    fn lock(&self) {
        loop {
            if self
                .state
                .underlying_atomic()
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
            let _ = self.state.block(1);
        }
    }

    unsafe fn unlock(&self) {
        self.state.underlying_atomic().store(0, Ordering::Release);
        self.state.wake_all();
    }
}

unsafe impl<Platform: ShimPlatform, T: Send> Send for VmLockedValue<Platform, T> {}
unsafe impl<Platform: ShimPlatform, T: Send> Sync for VmLockedValue<Platform, T> {}

struct VmBookkeeping<Platform: ShimPlatform> {
    owned_ranges: VmLockedValue<Platform, OwnedRanges>,
    elf_patch_cache: VmLockedValue<Platform, super::mm::ElfPatchCache>,
    brk: AtomicUsize,
    futex_namespace: usize,
    /// DIAGNOSTIC (musl-fork-struct-pthread-corruption, temporary, additive-only): identity of
    /// this process's current `SharedAddressSpace` family, as `Arc::as_ptr(&membership.shared)
    /// as usize` (0 = not currently a family member). Lives here, rather than on `Process`
    /// directly, so [`ProcessTable::overlaps_another_process`] can read it through the same
    /// narrow `Weak<VmBookkeepingSlot<_>>` already kept for `owned_ranges` -- see that field's
    /// own doc comment for why a `Weak<Process<_>>` is not used. Set in `Task::join_address_space`,
    /// cleared wherever a membership is dropped (`Task::release_address_space`'s single-threaded
    /// branch, `Task::leave_address_space_if_alone`). Distinguishes an overlap that is *expected*
    /// (two members of the SAME family, which by this platform's design believe they own the
    /// same addresses -- see `SharedAddressSpace`'s own doc comment) from one between processes
    /// that should have disjoint memory, which is the actual corruption candidate.
    family_id: AtomicUsize,
}

impl<Platform: ShimPlatform> VmBookkeeping<Platform> {
    fn new(futex_namespace: usize) -> Self {
        Self {
            owned_ranges: VmLockedValue::new(OwnedRanges::default()),
            elf_patch_cache: VmLockedValue::new(BTreeMap::new()),
            brk: AtomicUsize::new(0),
            futex_namespace,
            family_id: AtomicUsize::new(0),
        }
    }
}

struct VmBookkeepingSlot<Platform: ShimPlatform> {
    current: Mutex<Platform, Arc<VmBookkeeping<Platform>>>,
}

impl<Platform: ShimPlatform> VmBookkeepingSlot<Platform> {
    fn new(futex_namespace: usize) -> Self {
        Self {
            current: Mutex::new(Arc::new(VmBookkeeping::new(futex_namespace))),
        }
    }

    fn shared_with(other: &Self) -> Self {
        Self {
            current: Mutex::new(other.current.lock().clone()),
        }
    }

    fn current(&self) -> Arc<VmBookkeeping<Platform>> {
        self.current.lock().clone()
    }

    fn detach(&self, futex_namespace: usize) {
        *self.current.lock() = Arc::new(VmBookkeeping::new(futex_namespace));
    }
}

pub(crate) struct SharedVmLockedField<Platform: ShimPlatform, T> {
    vm: Arc<VmBookkeepingSlot<Platform>>,
    field: fn(&VmBookkeeping<Platform>) -> &VmLockedValue<Platform, T>,
}

impl<Platform: ShimPlatform, T> SharedVmLockedField<Platform, T> {
    fn new(
        vm: Arc<VmBookkeepingSlot<Platform>>,
        field: fn(&VmBookkeeping<Platform>) -> &VmLockedValue<Platform, T>,
    ) -> Self {
        Self { vm, field }
    }

    pub(crate) fn lock(&self) -> SharedVmLockedFieldGuard<Platform, T> {
        let vm = self.vm.current();
        (self.field)(&vm).lock();
        SharedVmLockedFieldGuard {
            vm,
            field: self.field,
        }
    }
}

pub(crate) struct SharedVmLockedFieldGuard<Platform: ShimPlatform, T> {
    vm: Arc<VmBookkeeping<Platform>>,
    field: fn(&VmBookkeeping<Platform>) -> &VmLockedValue<Platform, T>,
}

impl<Platform: ShimPlatform, T> SharedVmLockedFieldGuard<Platform, T> {
    fn value(&self) -> &VmLockedValue<Platform, T> {
        (self.field)(&self.vm)
    }
}

impl<Platform: ShimPlatform, T> Deref for SharedVmLockedFieldGuard<Platform, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.value().value.get() }
    }
}

impl<Platform: ShimPlatform, T> DerefMut for SharedVmLockedFieldGuard<Platform, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.value().value.get() }
    }
}

impl<Platform: ShimPlatform, T> Drop for SharedVmLockedFieldGuard<Platform, T> {
    fn drop(&mut self) {
        unsafe { self.value().unlock() };
    }
}

pub(crate) struct SharedVmAtomicUsize<Platform: ShimPlatform> {
    vm: Arc<VmBookkeepingSlot<Platform>>,
    field: fn(&VmBookkeeping<Platform>) -> &AtomicUsize,
}

impl<Platform: ShimPlatform> SharedVmAtomicUsize<Platform> {
    fn new(
        vm: Arc<VmBookkeepingSlot<Platform>>,
        field: fn(&VmBookkeeping<Platform>) -> &AtomicUsize,
    ) -> Self {
        Self { vm, field }
    }

    pub(crate) fn load(&self, order: Ordering) -> usize {
        (self.field)(&self.vm.current()).load(order)
    }

    pub(crate) fn store(&self, value: usize, order: Ordering) {
        (self.field)(&self.vm.current()).store(value, order);
    }
}

/// One guest address space, shared by a `fork`ed child and its parent, plus the hand-off that
/// keeps exactly one of them running on it at a time.
///
/// LiteBox executes guest code natively, so a guest virtual address *is* a host virtual address
/// (see `litebox::mm::vmem::Vmem::insert_mapping`, which passes the guest's own range straight to
/// the platform allocator). One host address space therefore cannot hold two guest processes that
/// both believe they own the same addresses, which is exactly what a copying `fork` would have to
/// produce. So the child runs in the parent's address space, on the parent's stack.
///
/// What this type adds is that the parent does not have to stay suspended for the child's whole
/// lifetime. The address space is a *token*. Its holder is the one member whose memory is
/// currently live in it; every other member is parked, holding a host-memory copy of its own view
/// (see [`AddressSpaceMembership::parked`]). A member gives the token up whenever it is about to
/// block -- `litebox::event::wait::CheckForInterrupt::yield_while_blocking`, which fires for every
/// interruptible wait in the shim -- and takes it back before it looks at guest memory again.
/// Since a member only ever reads or writes guest memory while it holds the token, and taking the
/// token restores that member's own copy, each member sees exactly the memory `fork(2)` promises
/// it.
///
/// That is what makes a `fork`ed child that never `execve`s -- a shell builtin on the left of a
/// pipeline, a background subshell -- able to run concurrently with its parent: when it blocks on
/// a full pipe, the parent gets the address space back and can fork the stage that drains it.
///
/// A member leaves for good when it `execve`s (the new image is loaded at addresses no other
/// member owns, so it no longer needs the token) or when it exits.
///
/// Known limits, all of them "it hangs", never "it silently returns the wrong bytes":
///
/// * A member that never blocks and never exits starves the others. The token is only ever
///   yielded voluntarily; there is no preemption, because memory cannot be taken away from a
///   thread that is in the middle of executing guest instructions on it.
/// * Membership is per *process*: every thread of a member runs on the memory while the process
///   holds the token. A single-threaded member gives the token up whenever it blocks, as above.
///   A multithreaded member gives it up only when another member is waiting for it (a waiter
///   kicks the holder's threads, see [`Self::acquire`]): the first thread to notice at a safe
///   point closes the process's fork gate so every sibling parks off the memory
///   ([`Task::quiesce_and_hand_off`]), copies the image out, releases, and waits for the token
///   to come back before reopening the gate. That is what lets a `fork`ed child that never
///   `exec`s -- a Chromium zygote's renderer -- create threads. The cost is that every hand-off
///   copies the member's whole shared image, and a member busy in guest code yields only at its
///   next syscall or vCPU kick.
pub(crate) struct SharedAddressSpace<Platform: ShimPlatform> {
    /// [`ADDRESS_SPACE_FREE`], or the pid of the member holding the token. Used directly as the
    /// word members block on while waiting to acquire.
    holder: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    /// Members currently blocked in [`Self::acquire`]. A multithreaded holder yields only while
    /// this is non-zero (see [`Task::yield_address_space_to_waiters`]).
    waiters: AtomicUsize,
    /// The holder's thread table, so a waiter can kick its threads to a safe point. Cleared on
    /// release.
    #[allow(
        clippy::type_complexity,
        reason = "a type alias would obscure the Weak<Mutex<...>> chain"
    )]
    holder_threads: Mutex<Platform, Option<Weak<Mutex<Platform, ProcessInner<Platform>>>>>,
}

const PROCESS_LAUNCH_PENDING: u32 = 0;
const PROCESS_LAUNCH_COMMITTED: u32 = 1;
const PROCESS_LAUNCH_ABORTED: u32 = 2;

struct ProcessLaunch<Platform: ShimPlatform> {
    state: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
}

impl<Platform: ShimPlatform> ProcessLaunch<Platform> {
    fn new() -> Self {
        Self {
            state: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
        }
    }

    fn commit(&self) {
        self.state
            .underlying_atomic()
            .store(PROCESS_LAUNCH_COMMITTED, Ordering::Release);
        self.state.wake_all();
    }

    fn abort(&self) {
        self.state
            .underlying_atomic()
            .store(PROCESS_LAUNCH_ABORTED, Ordering::Release);
        self.state.wake_all();
    }

    fn wait(&self) -> bool {
        loop {
            let state = self.state.underlying_atomic().load(Ordering::Acquire);
            match state {
                PROCESS_LAUNCH_COMMITTED => return true,
                PROCESS_LAUNCH_ABORTED => return false,
                PROCESS_LAUNCH_PENDING => {
                    let _ = self.state.block(PROCESS_LAUNCH_PENDING);
                }
                _ => unreachable!("invalid process launch state"),
            }
        }
    }

    fn is_committed(&self) -> bool {
        self.state.underlying_atomic().load(Ordering::Acquire) == PROCESS_LAUNCH_COMMITTED
    }
}

const VFORK_ACTIVE: u32 = 0;
const VFORK_COMPLETE: u32 = 1;

pub(crate) struct VforkCompletion<Platform: ShimPlatform> {
    state: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    /// Whether the vfork parent was already a [`SharedAddressSpace`] member when it vforked. A
    /// child on the parent's memory then cannot fork (see `do_process_clone`): the membership it
    /// would hand back below has nowhere to go.
    parent_shares_address_space: bool,
    /// The membership a `CLONE_VM` child that forked while still on its parent's memory hands to
    /// that parent as it exits or execs. See [`Task::hand_address_space_to_vfork_parent`].
    inherited_membership: Mutex<Platform, Option<Arc<AddressSpaceMembership<Platform>>>>,
}

impl<Platform: ShimPlatform> VforkCompletion<Platform> {
    fn new(parent_shares_address_space: bool) -> Self {
        let state = <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT;
        state
            .underlying_atomic()
            .store(VFORK_ACTIVE, Ordering::Relaxed);
        Self {
            state,
            parent_shares_address_space,
            inherited_membership: Mutex::new(None),
        }
    }

    fn complete(&self) {
        if self
            .state
            .underlying_atomic()
            .swap(VFORK_COMPLETE, Ordering::Release)
            == VFORK_ACTIVE
        {
            self.state.wake_all();
        }
    }

    fn wait(&self) {
        loop {
            let state = self.state.underlying_atomic().load(Ordering::Acquire);
            if state == VFORK_COMPLETE {
                return;
            }
            let _ = self.state.block(state);
        }
    }
}

/// One piece of a guest process's view of the memory it shares with other members: the page
/// protection it had, and -- for a writable piece -- its contents.
struct SavedRange {
    start: usize,
    end: usize,
    /// The mapping's protection (`VM_READ`/`VM_WRITE`/`VM_EXEC`) at save time.
    flags: VmFlags,
    /// The bytes, for a writable piece. A non-writable piece (a `PROT_NONE` allocator
    /// reservation, a read-only segment) carries only its protection, which the restore
    /// re-applies -- and, for `PROT_NONE`, clears whatever another member left there, since
    /// Linux hands a process zero pages when it commits such a range.
    bytes: Option<alloc::boxed::Box<[u8]>>,
}

/// A copy of a guest process's view of its shared memory; see [`SavedRange`].
type MemoryImage = Vec<SavedRange>;

/// The `mprotect` protection a page-manager mapping's flags describe.
fn prot_of(flags: VmFlags) -> litebox_common_linux::ProtFlags {
    use litebox_common_linux::ProtFlags;
    let mut prot = ProtFlags::PROT_NONE;
    prot.set(ProtFlags::PROT_READ, flags.contains(VmFlags::VM_READ));
    prot.set(ProtFlags::PROT_WRITE, flags.contains(VmFlags::VM_WRITE));
    prot.set(ProtFlags::PROT_EXEC, flags.contains(VmFlags::VM_EXEC));
    prot
}

/// The protection bits of a mapping's flags, for comparing two members' views of one range.
fn access_bits(flags: VmFlags) -> VmFlags {
    flags & (VmFlags::VM_READ | VmFlags::VM_WRITE | VmFlags::VM_EXEC)
}

/// Above this many disjoint below-SP ABI ranges, preserve their one bounding interval instead.
const MAX_PRESERVED_STACK_RANGES: usize = 64;

/// One member process's place in a [`SharedAddressSpace`], shared by all of its threads (hence
/// `Arc` in [`Process::address_space`] and interior synchronization throughout).
pub(crate) struct AddressSpaceMembership<Platform: ShimPlatform> {
    shared: Arc<SharedAddressSpace<Platform>>,
    /// Whether this member currently holds the token.
    holding: AtomicBool,
    /// This member's copy of its own private memory, taken when it gave the token up. `Some`
    /// exactly while [`Self::holding`] is false and the member still intends to come back.
    parked: Mutex<Platform, Option<MemoryImage>>,
    /// Small guest ranges whose contents remain semantically live even when they sit below the
    /// current stack pointer. Clone child-TID words are the canonical case.
    preserved_stack_ranges: Mutex<Platform, OwnedRanges>,
    /// The ranges this member has ever shared with another member: its owned ranges at every
    /// `fork` it took part in (for a child, the parent's at that moment). Only these need
    /// copying out and back on a hand-off -- memory a member mapped afterwards is at addresses
    /// no other member owns, so nobody else can disturb it. For a renderer that grows to
    /// hundreds of megabytes after being forked from a small zygote, this is the difference
    /// between copying the zygote's image and copying everything.
    shared_ranges: Mutex<Platform, OwnedRanges>,
    /// Set by the one thread quiescing this multithreaded member for a hand-off; see
    /// [`Task::quiesce_and_hand_off`].
    quiescing: AtomicBool,
    /// When this member last took the token, as the platform's monotonic clock. A
    /// multithreaded member keeps the token for at least [`Self::QUANTUM`] before yielding to
    /// a waiter: every hand-off copies its whole shared image out and back, so yielding at the
    /// first syscall after each acquisition -- with several runnable members, every few
    /// microseconds -- spent everything on copying and nothing on the guest (live-measured:
    /// 22,606 hand-offs in 90 s, none of the members getting anywhere).
    acquired_at: Mutex<Platform, Option<Platform::Instant>>,
}

impl<Platform: ShimPlatform> AddressSpaceMembership<Platform> {
    fn new(
        shared: Arc<SharedAddressSpace<Platform>>,
        preserved_stack_ranges: OwnedRanges,
        shared_ranges: OwnedRanges,
    ) -> Self {
        Self {
            shared,
            holding: AtomicBool::new(true),
            parked: Mutex::new(None),
            preserved_stack_ranges: Mutex::new(preserved_stack_ranges),
            shared_ranges: Mutex::new(shared_ranges),
            quiescing: AtomicBool::new(false),
            acquired_at: Mutex::new(None),
        }
    }

    /// The least a multithreaded member runs between hand-offs; see [`Self::acquired_at`].
    const QUANTUM: Duration = Duration::from_millis(40);

    fn holding(&self) -> bool {
        self.holding.load(Ordering::Acquire)
    }

    fn mark_acquired(&self, now: Platform::Instant) {
        *self.acquired_at.lock() = Some(now);
    }

    /// Whether this member has had the token for at least [`Self::QUANTUM`].
    fn quantum_elapsed(&self, now: Platform::Instant) -> bool {
        self.acquired_at
            .lock()
            .is_none_or(|since| now.duration_since(&since) >= Self::QUANTUM)
    }
}

/// The value of [`SharedAddressSpace::holder`] when no member holds the token. No tid is ever
/// zero, so this cannot collide with one.
const ADDRESS_SPACE_FREE: u32 = 0;

/// Encodes a tid as a [`SharedAddressSpace::holder`] value.
fn tid_as_holder(tid: i32) -> u32 {
    let raw = tid.cast_unsigned();
    assert_ne!(raw, ADDRESS_SPACE_FREE, "tid 0 cannot own an address space");
    raw
}

impl<Platform: ShimPlatform> SharedAddressSpace<Platform> {
    /// How long to block before re-checking whether this task is being torn down, and between
    /// kicks of a multithreaded holder's threads. The token is handed over explicitly, so in the
    /// single-threaded case this only bounds how long a *dying* task waits for a holder that
    /// will never release; it is not a polling interval in the normal case.
    const ABANDON_CHECK_INTERVAL: Duration = Duration::from_millis(20);

    fn new(
        initial_holder: i32,
        holder_inner: &Arc<Mutex<Platform, ProcessInner<Platform>>>,
    ) -> Self {
        let holder = <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT;
        holder
            .underlying_atomic()
            .store(tid_as_holder(initial_holder), Ordering::Relaxed);
        Self {
            holder,
            waiters: AtomicUsize::new(0),
            holder_threads: Mutex::new(Some(Arc::downgrade(holder_inner))),
        }
    }

    fn waiters(&self) -> usize {
        self.waiters.load(Ordering::Acquire)
    }

    /// Interrupts every thread of the current holder so each reaches a safe point and, if the
    /// holder is multithreaded, notices the waiter (see [`Task::yield_address_space_to_waiters`]).
    fn kick_holder(&self) {
        let holder = self.holder_threads.lock().clone();
        if let Some(inner) = holder.and_then(|weak| weak.upgrade()) {
            for thread in inner.lock().threads.values() {
                thread.interrupt();
            }
        }
    }

    /// Blocks until the token is free and takes it for the process `pid`, whose thread table is
    /// `inner`.
    ///
    /// Returns `true` once the process holds the token -- taken here, or (`already_held`) by a
    /// sibling thread of the same process in the meantime. Returns `false` if `abandon` became
    /// true first, which only happens when the caller is being torn down and will never run
    /// guest code again.
    fn acquire(
        &self,
        pid: i32,
        already_held: impl Fn() -> bool,
        mut abandon: impl FnMut() -> bool,
        inner: &Arc<Mutex<Platform, ProcessInner<Platform>>>,
    ) -> bool {
        let me = tid_as_holder(pid);
        let mut waiting = false;
        let outcome = loop {
            if already_held() {
                break true;
            }
            match self.holder.underlying_atomic().compare_exchange(
                ADDRESS_SPACE_FREE,
                me,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    *self.holder_threads.lock() = Some(Arc::downgrade(inner));
                    // Siblings blocked below on the holder word re-check `already_held`.
                    self.holder.wake_all();
                    break true;
                }
                Err(current) => {
                    if abandon() {
                        break false;
                    }
                    if !waiting {
                        waiting = true;
                        self.waiters.fetch_add(1, Ordering::AcqRel);
                    }
                    self.kick_holder();
                    let _ = self
                        .holder
                        .block_or_timeout(current, Self::ABANDON_CHECK_INTERVAL);
                }
            }
        };
        if waiting {
            self.waiters.fetch_sub(1, Ordering::AcqRel);
        }
        outcome
    }

    /// Gives the token up, waking anything waiting for it.
    fn release(&self) {
        *self.holder_threads.lock() = None;
        self.holder
            .underlying_atomic()
            .store(ADDRESS_SPACE_FREE, Ordering::Release);
        self.holder.wake_all();
    }

    /// After a [`Self::release`] made on a waiter's behalf: blocks until some waiter has taken
    /// the token (or every waiter has given up), so the releasing member -- still on-CPU and
    /// about to re-acquire -- cannot snatch it straight back. Without this a multithreaded
    /// member quiesced, released and re-acquired thousands of times a second while the waiter
    /// it had yielded for never once won the race (live-measured: 23,444 hand-offs with
    /// `away_us=0` in 90 s).
    fn wait_until_taken(&self, mut abandon: impl FnMut() -> bool) {
        loop {
            if self.waiters() == 0 || abandon() {
                return;
            }
            let current = self.holder.underlying_atomic().load(Ordering::Acquire);
            if current != ADDRESS_SPACE_FREE {
                return;
            }
            let _ = self
                .holder
                .block_or_timeout(ADDRESS_SPACE_FREE, Self::ABANDON_CHECK_INTERVAL);
        }
    }

    /// Passes the token straight to process `pid` (thread table `inner`) without ever making it
    /// free.
    ///
    /// Used by `fork`: the child is not running yet and so cannot [`Self::acquire`] for itself,
    /// and a free window here would let some other member take the address space out from under
    /// it before its first instruction.
    fn hand_off_to(&self, pid: i32, inner: &Arc<Mutex<Platform, ProcessInner<Platform>>>) {
        *self.holder_threads.lock() = Some(Arc::downgrade(inner));
        self.holder
            .underlying_atomic()
            .store(tid_as_holder(pid), Ordering::Release);
    }
}

/// Parent/child relationships and exit statuses of every guest process in the shim.
///
/// This is the bookkeeping `wait4` reaps from. It is deliberately separate from [`Process`],
/// which models a *thread group*: a zombie has to outlive its `Process` (the parent may not call
/// `wait4` until long after the child's last thread is gone), and a waiting parent has to be able
/// to name a child it holds no reference to.
pub(crate) struct ProcessTable<Platform: ShimPlatform> {
    inner: Mutex<Platform, ProcessTableInner<Platform>>,
}

struct ProcessTableInner<Platform: ShimPlatform> {
    /// Every live or zombie child, keyed by its pid.
    children: BTreeMap<i32, ChildRecord>,
    /// Parents currently blocked in `wait4`, as (parent pid, registration token, waker).
    waiters: Vec<(i32, u64, litebox::event::wait::Waker<Platform>)>,
    next_waiter_token: u64,
    /// Every live guest process, so that a signal can be posted to one of them from another.
    live: BTreeMap<i32, LiveProcess<Platform>>,
}

/// The handle needed to post a process-directed signal to another guest process.
///
/// Deliberately not a `Task`: the sender runs on a different host thread, and a `Task` is
/// full of `Cell`s and `RefCell`s that only its own thread may touch. Everything here is
/// `Sync`.
struct LiveProcess<Platform: ShimPlatform> {
    /// The target's process-group identity. Kept separate from `Process` because platform timer
    /// handles inside that object are not required to be `Send`, while this table is shim-global.
    process_group_id: Weak<AtomicI32>,
    /// The target's process-wide pending queue -- the same one its own threads drain from.
    /// Survives `execve` (which replaces the handler table, not this).
    signals: crate::syscalls::signal::RemoteSignalTarget<Platform>,
    /// The target state needed to wake every thread after posting a signal.
    process_inner: Weak<Mutex<Platform, ProcessInner<Platform>>>,
    /// The target's live resource limits, used when queueing user-originated signals.
    limits: Weak<ResourceLimits>,
    /// The target's VM identity slot, so a cross-lineage guest-address-range overlap can be
    /// detected against its `owned_ranges` (see [`ProcessTable::overlaps_another_process`]).
    /// `Weak<VmBookkeepingSlot<_>>` rather than `Weak<Process<_>>`: the latter drags in
    /// `Process::alarm_timer`'s platform `TimerHandle`, which is not `Send`, and this table must
    /// stay `Sync` (see the other fields' narrow `Weak`s, chosen for the same reason).
    ///
    /// DIAGNOSTIC (musl-fork-struct-pthread-corruption, temporary, additive-only): added to
    /// directly test the hypothesis in `litebox-chromium-zygote-fork-corruption.md` -- that the
    /// one flat, process-blind host address space (see `Process::owned_ranges`'s own doc
    /// comment: "they live at disjoint addresses in the one host address space") ever actually
    /// fails to keep two unrelated guest processes' address ranges disjoint, which is the
    /// precondition for one process's fork/save/restore machinery to ever touch another's live
    /// memory.
    vm: Weak<VmBookkeepingSlot<Platform>>,
}

/// One selected recipient of a process-directed signal: its pending queue, the thread list to
/// wake once the signal is posted, and the limits a user-originated signal is queued against.
type SignalTarget<Platform> = (
    crate::syscalls::signal::RemoteSignalTarget<Platform>,
    Arc<Mutex<Platform, ProcessInner<Platform>>>,
    Arc<ResourceLimits>,
);

/// The initial guest process's pid; `GlobalState::next_thread_id` starts at 2 to leave it free.
const INIT_PID: i32 = 1;

struct ChildRecord {
    ppid: i32,
    /// Signal the child asked to receive if `ppid` exits; `None` means disabled.
    parent_death_signal: Option<Signal>,
    /// `None` while the child is still running; `Some` once it is a zombie awaiting `wait4`.
    status: Option<ExitStatus>,
    /// Total host CPU time (nanoseconds) the child consumed, set alongside `status`. See
    /// `Process::cpu_time_nanos`.
    cpu_time_nanos: u64,
}

impl<Platform: ShimPlatform> ProcessTable<Platform> {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(ProcessTableInner {
                children: BTreeMap::new(),
                waiters: Vec::new(),
                next_waiter_token: 0,
                live: BTreeMap::new(),
            }),
        }
    }

    /// Records a newly `fork`ed child of `parent`.
    fn add_child(&self, child: i32, parent: i32) {
        let old = self.inner.lock().children.insert(
            child,
            ChildRecord {
                ppid: parent,
                parent_death_signal: None,
                status: None,
                cpu_time_nanos: 0,
            },
        );
        assert!(old.is_none(), "pid {child} is already live");
    }

    /// Registers a live guest process so signals can be posted to it.
    fn register_process(
        &self,
        pid: i32,
        signals: crate::syscalls::signal::RemoteSignalTarget<Platform>,
        process: &Arc<Process<Platform>>,
    ) {
        self.inner.lock().live.insert(
            pid,
            LiveProcess {
                process_group_id: Arc::downgrade(&process.process_group_id),
                signals,
                process_inner: Arc::downgrade(&process.inner),
                limits: Arc::downgrade(&process.limits),
                vm: Arc::downgrade(&process.owned_ranges.vm),
            },
        );
    }

    /// DIAGNOSTIC (musl-fork-struct-pthread-corruption, temporary, additive-only): every OTHER
    /// live process (by pid) whose `owned_ranges` currently overlaps `range` AND whose
    /// `family_id` differs from `self_family_id` (0 = not in any family) -- i.e. excludes the
    /// EXPECTED overlap between two members of the SAME `SharedAddressSpace` family (which, by
    /// this platform's design, believe they own the same addresses; see that type's own doc
    /// comment), surfacing only overlap between processes that are supposed to have disjoint
    /// memory. Each hit also carries the other process's own `family_id`, so a hit can still be
    /// told apart from "family-id tracking itself missed a relationship" (e.g. vfork, which does
    /// not go through `Task::join_address_space`) during triage. An empty result under every
    /// real trial is direct evidence against the "flat shared address space lets unrelated
    /// lineages collide" hypothesis; any non-empty result is the smoking gun the investigation is
    /// looking for -- see call sites in `Task::save_address_space` / `Task::restore_address_space`.
    fn overlaps_another_process(
        &self,
        self_pid: i32,
        self_family_id: usize,
        range: &Range<usize>,
    ) -> Vec<(i32, usize, Range<usize>)> {
        if range.start >= range.end {
            return Vec::new();
        }
        let others: Vec<(i32, Arc<VmBookkeepingSlot<Platform>>)> = {
            let inner = self.inner.lock();
            inner
                .live
                .iter()
                .filter(|&(&pid, _)| pid != self_pid)
                .filter_map(|(&pid, live)| Some((pid, live.vm.upgrade()?)))
                .collect()
        };
        let mut hits = Vec::new();
        for (other_pid, vm) in others {
            let bookkeeping = vm.current();
            let other_family_id = bookkeeping.family_id.load(Ordering::Acquire);
            if self_family_id != 0 && self_family_id == other_family_id {
                continue;
            }
            bookkeeping.owned_ranges.lock();
            // SAFETY: `owned_ranges.lock()` above establishes exclusive access to the cell until
            // `unlock()` below, mirroring `SharedVmLockedFieldGuard`'s own Deref.
            let overlaps: Vec<Range<usize>> = unsafe { &*bookkeeping.owned_ranges.value.get() }
                .intersect(range)
                .collect();
            unsafe { bookkeeping.owned_ranges.unlock() };
            for overlap in overlaps {
                hits.push((other_pid, other_family_id, overlap));
            }
        }
        hits
    }

    /// Every registered live pid, ascending -- what `/proc` lists.
    pub(crate) fn live_pids(&self) -> Vec<i32> {
        self.inner.lock().live.keys().copied().collect()
    }

    /// Thread `tid` of live process `tgid`, with that process's resource limits, for a
    /// thread-directed signal from another process (`tgkill`/`rt_tgsigqueueinfo`). `None` when
    /// either is not live, which is Linux's `ESRCH`.
    #[allow(
        clippy::similar_names,
        reason = "tgid/tid are standard Linux terminology"
    )]
    pub(crate) fn remote_thread(
        &self,
        tgid: i32,
        tid: i32,
    ) -> Option<(Arc<ThreadRemote<Platform>>, Arc<ResourceLimits>)> {
        let (process_inner, limits) = {
            let inner = self.inner.lock();
            let live = inner.live.get(&tgid)?;
            (live.process_inner.upgrade()?, live.limits.upgrade()?)
        };
        let thread = process_inner.lock().threads.get(&tid).cloned()?;
        Some((thread, limits))
    }

    /// The live threads of process `pid` (empty when it is not live), plus its process group
    /// and real uid, for `getpriority`/`setpriority` over another process. Table lock first,
    /// then the process lock, the order `send_process_signal` uses.
    #[allow(
        clippy::similar_names,
        reason = "pid/pgid are standard Linux terminology"
    )]
    #[allow(
        clippy::type_complexity,
        reason = "tuple return keeps the caller's match ergonomic"
    )]
    pub(crate) fn priority_targets(
        &self,
        pid: i32,
    ) -> Option<(Vec<Arc<ThreadRemote<Platform>>>, i32, u32)> {
        let (process_inner, pgid) = {
            let inner = self.inner.lock();
            let live = inner.live.get(&pid)?;
            (
                live.process_inner.upgrade()?,
                live.process_group_id.upgrade()?.load(Ordering::Relaxed),
            )
        };
        let inner = process_inner.lock();
        Some((
            inner.threads.values().cloned().collect(),
            pgid,
            inner.identity.uid,
        ))
    }

    /// The `/proc/<pid>` view of registered live process `pid`, or `None` when no such process
    /// is registered (or it has already torn down its `Process`).
    pub(crate) fn proc_task_info(&self, pid: i32) -> Option<litebox::fs::proc::ProcTaskInfo> {
        // Take the process handle out from under the table lock before locking the process
        // itself, the same order `send_process_signal` uses.
        let process_inner = self.inner.lock().live.get(&pid)?.process_inner.upgrade()?;
        let inner = process_inner.lock();
        Some(proc_task_info(pid, &inner))
    }

    pub(crate) fn send_process_signal(
        &self,
        pid: i32,
        signal: litebox_common_linux::signal::Signal,
        siginfo: litebox_common_linux::signal::Siginfo,
    ) -> bool {
        let Some((signals, process_inner, limits)) = ({
            let inner = self.inner.lock();
            inner.live.get(&pid).and_then(|live| {
                Some((
                    live.signals.clone(),
                    live.process_inner.upgrade()?,
                    live.limits.upgrade()?,
                ))
            })
        }) else {
            return false;
        };
        signals.post_from_user(&limits, signal, siginfo);
        let inner = process_inner.lock();
        for thread in inner.threads.values() {
            thread.interrupt();
        }
        true
    }

    /// Selects every live process `select` accepts.
    ///
    /// Target discovery and weak-reference upgrades happen under one process-table lock, so an
    /// exit cannot leave a selected target half-upgraded. Signal delivery and thread wakeups happen
    /// after releasing that lock, in [`Self::post_to_targets`].
    fn select_signal_targets(
        &self,
        mut select: impl FnMut(i32, &LiveProcess<Platform>) -> bool,
    ) -> Vec<SignalTarget<Platform>> {
        let inner = self.inner.lock();
        inner
            .live
            .iter()
            .filter_map(|(&pid, live)| {
                select(pid, live).then(|| {
                    Some((
                        live.signals.clone(),
                        live.process_inner.upgrade()?,
                        live.limits.upgrade()?,
                    ))
                })?
            })
            .collect()
    }

    /// Posts a user-originated `signal` to each of `targets` and wakes every one of their threads.
    /// Returns how many processes were signalled.
    fn post_to_targets(
        targets: &[SignalTarget<Platform>],
        signal: litebox_common_linux::signal::Signal,
        siginfo: &litebox_common_linux::signal::Siginfo,
    ) -> usize {
        for (signals, process_inner, limits) in targets {
            signals.post_from_user(limits, signal, siginfo.clone());
            for thread in process_inner.lock().threads.values() {
                thread.interrupt();
            }
        }
        targets.len()
    }

    fn in_process_group(live: &LiveProcess<Platform>, process_group_id: i32) -> bool {
        live.process_group_id
            .upgrade()
            .is_some_and(|group| group.load(Ordering::Acquire) == process_group_id)
    }

    /// Posts a process-directed signal to every live process in `process_group_id` except
    /// `excluded_pid`. Returns how many processes were signalled.
    pub(crate) fn send_process_group_signal(
        &self,
        process_group_id: i32,
        excluded_pid: i32,
        signal: litebox_common_linux::signal::Signal,
        siginfo: litebox_common_linux::signal::Siginfo,
    ) -> usize {
        let targets = self.select_signal_targets(|pid, live| {
            pid != excluded_pid && Self::in_process_group(live, process_group_id)
        });
        Self::post_to_targets(&targets, signal, &siginfo)
    }

    /// Posts a process-directed signal to every live process except `excluded_pid` and the
    /// initial process, which `kill(-1, sig)` spares exactly as Linux spares init. Returns how
    /// many processes were signalled.
    pub(crate) fn send_signal_to_all_processes(
        &self,
        excluded_pid: i32,
        signal: litebox_common_linux::signal::Signal,
        siginfo: litebox_common_linux::signal::Siginfo,
    ) -> usize {
        let targets = self.select_signal_targets(|pid, _| pid != excluded_pid && pid != INIT_PID);
        Self::post_to_targets(&targets, signal, &siginfo)
    }

    /// Whether some live process other than `excluded_pid` is in `process_group_id` -- the
    /// existence test behind `kill(-pgid, 0)`.
    pub(crate) fn has_process_group_member(
        &self,
        process_group_id: i32,
        excluded_pid: i32,
    ) -> bool {
        self.inner.lock().live.iter().any(|(&pid, live)| {
            pid != excluded_pid && Self::in_process_group(live, process_group_id)
        })
    }

    /// Whether [`Self::send_signal_to_all_processes`] from `excluded_pid` would reach anything --
    /// the existence test behind `kill(-1, 0)`.
    pub(crate) fn has_other_live_process(&self, excluded_pid: i32) -> bool {
        self.inner
            .lock()
            .live
            .keys()
            .any(|&pid| pid != excluded_pid && pid != INIT_PID)
    }

    /// Returns whether `pid` currently names a live guest process.
    pub(crate) fn is_live(&self, pid: i32) -> bool {
        self.inner.lock().live.contains_key(&pid)
    }

    /// Returns the process-group identity for `child` only when it is a live child of `parent`.
    ///
    /// Parentage and liveness are observed under one table lock, so exit cannot interleave between
    /// validating the relationship and upgrading the live process's weak group reference.
    fn live_child_process_group_id(&self, parent: i32, child: i32) -> Option<Arc<AtomicI32>> {
        let inner = self.inner.lock();
        if inner.children.get(&child)?.ppid != parent {
            return None;
        }
        inner.live.get(&child)?.process_group_id.upgrade()
    }

    /// Removes a process that has exited from the live set.
    fn unregister_process(&self, pid: i32) {
        self.inner.lock().live.remove(&pid);
    }

    /// Turns `child` into a zombie carrying `status`, wakes its parent if one is waiting, and
    /// posts `SIGCHLD` to that parent.
    ///
    /// Does nothing for a pid with no recorded parent (the initial process, or a child whose
    /// parent already exited and dropped it).
    fn record_exit(&self, child: i32, status: ExitStatus, cpu_time_nanos: u64) {
        let mut inner = self.inner.lock();
        let Some(record) = inner.children.get_mut(&child) else {
            return;
        };
        record.status = Some(status);
        record.cpu_time_nanos = cpu_time_nanos;
        let parent = record.ppid;
        let wakers: Vec<_> = inner
            .waiters
            .iter()
            .filter(|(waiting, _, _)| *waiting == parent)
            .map(|(_, _, waker)| waker.clone())
            .collect();
        // Queue the parent's `SIGCHLD` before the wakeups, so that whichever of its threads wakes
        // first already finds the signal pending.
        //
        // Without this, a guest that blocks waiting for `SIGCHLD` -- which is exactly how
        // busybox's `ash` implements a blocking `wait`, via `sigsuspend` -- never wakes up. The
        // signal is discarded harmlessly by a parent that has no `SIGCHLD` handler; see
        // [`Task::has_pending_signals`].
        let parent_inner = inner.live.get(&parent).and_then(|live| {
            live.signals.post(
                litebox_common_linux::signal::Signal::SIGCHLD,
                crate::syscalls::signal::siginfo_child_exited(child, status),
            );
            live.process_inner.upgrade()
        });
        drop(inner);
        for waker in wakers {
            waker.wake();
        }
        // The wakers above only cover a parent registered in `wait4`/`rt_sigsuspend`. One blocked
        // anywhere else interruptible -- `ppoll`, `read`, `nanosleep`, `epoll_pwait` -- has to be
        // kicked the way `send_process_signal` kicks it, or it runs its `SIGCHLD` handler (or gets
        // its `EINTR`) only once something unrelated wakes it: `sudo` and xterm's close path both
        // hang exactly there. Deliverability stays the parent's own call, in
        // `check_for_interrupt`; a parent ignoring `SIGCHLD` simply goes back to sleep.
        if let Some(parent_inner) = parent_inner {
            for thread in parent_inner.lock().threads.values() {
                thread.interrupt();
            }
        }
    }

    fn set_parent_death_signal(&self, child: i32, signal: Option<Signal>) {
        if let Some(record) = self.inner.lock().children.get_mut(&child) {
            record.parent_death_signal = signal;
        }
    }

    /// Drops every record naming `parent` as a parent, delivering each live child's configured
    /// parent-death signal first.
    ///
    /// Real Linux reparents orphans to init, which then reaps them; this shim has no init, and a
    /// record nobody can ever wait on is just a leak, so they are discarded instead.
    fn signal_and_discard_children_of(&self, parent: i32) {
        let targets = {
            let mut inner = self.inner.lock();
            let targets: Vec<_> = inner
                .children
                .iter()
                .filter_map(|(&child, record)| {
                    (record.ppid == parent && record.status.is_none())
                        .then_some(record.parent_death_signal.map(|signal| (child, signal)))
                        .flatten()
                })
                .collect();
            inner.children.retain(|_, record| record.ppid != parent);
            targets
        };
        for (child, signal) in targets {
            self.send_process_signal(
                child,
                signal,
                crate::syscalls::signal::siginfo_parent_death(signal),
            );
        }
    }

    /// Whether `parent` has any child matching `filter`, zombie or not.
    fn has_child(&self, parent: i32, filter: WaitFilter) -> bool {
        self.inner
            .lock()
            .children
            .iter()
            .any(|(&child, r)| r.ppid == parent && filter.matches(child))
    }

    /// Reaps one zombie child of `parent` matching `filter`, removing it from the table.
    fn reap(&self, parent: i32, filter: WaitFilter) -> Option<(i32, ExitStatus, u64)> {
        let mut inner = self.inner.lock();
        let (child, status, cpu_time_nanos) = inner.children.iter().find_map(|(&child, r)| {
            (r.ppid == parent && filter.matches(child))
                .then_some(r.status)
                .flatten()
                .map(|status| (child, status, r.cpu_time_nanos))
        })?;
        inner.children.remove(&child);
        Some((child, status, cpu_time_nanos))
    }

    /// Whether [`Self::reap`] would find something right now, without consuming it.
    fn reap_ready(&self, parent: i32, filter: WaitFilter) -> bool {
        self.inner
            .lock()
            .children
            .iter()
            .any(|(&child, r)| r.ppid == parent && filter.matches(child) && r.status.is_some())
    }

    /// Removes every process-table trace of a child whose host thread could not be spawned.
    fn forget_failed_spawn(&self, child: i32) {
        let mut inner = self.inner.lock();
        inner.children.remove(&child);
        inner.live.remove(&child);
    }

    pub(crate) fn register_waiter(
        &self,
        parent: i32,
        waker: litebox::event::wait::Waker<Platform>,
    ) -> u64 {
        let mut inner = self.inner.lock();
        let token = inner.next_waiter_token;
        inner.next_waiter_token += 1;
        inner.waiters.push((parent, token, waker));
        token
    }

    pub(crate) fn unregister_waiter(&self, token: u64) {
        self.inner.lock().waiters.retain(|(_, t, _)| *t != token);
    }
}

/// The guest stack pointer recorded in a saved register context.
pub(crate) fn guest_stack_pointer(ctx: &litebox_common_linux::PtRegs) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        ctx.rsp
    }
    #[cfg(target_arch = "aarch64")]
    {
        ctx.sp
    }
}

/// Packs an exit status into the `int` layout `wait4`'s `wstatus` uses, as decoded by libc's
/// `WIFEXITED`/`WEXITSTATUS`/`WTERMSIG` macros: a normal exit puts the code in bits 8..16 and
/// leaves the low seven bits (the terminating signal) zero, while a signal death puts the signal
/// number in those low bits.
fn encode_wait_status(status: ExitStatus) -> i32 {
    match status {
        ExitStatus::Exit(code) => (i32::from(code) & 0xff) << 8,
        ExitStatus::Signal(signal) => signal.as_i32() & 0x7f,
    }
}

/// Which children a `wait4` call is willing to reap.
#[derive(Clone, Copy)]
enum WaitFilter {
    /// `pid < -1` and `pid == 0` are process-group filters on Linux. LiteBox now tracks
    /// per-process groups, but `wait4` group filtering is not implemented yet, so both remain the
    /// same conservative "any child" approximation as `pid == -1`.
    Any,
    Pid(i32),
}

impl WaitFilter {
    fn matches(self, pid: i32) -> bool {
        match self {
            WaitFilter::Any => true,
            WaitFilter::Pid(p) => p == pid,
        }
    }
}

pub(crate) struct Alarm<Platform: ShimPlatform> {
    /// Handle for the alarm timer.
    pub(crate) handle: Option<<Platform as litebox::platform::TimerProvider>::TimerHandle>,
    /// The deadline for the alarm.
    pub(crate) deadline: Option<<Platform as litebox::platform::TimeProvider>::Instant>,
}

impl<Platform: ShimPlatform> Alarm<Platform> {
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
struct ProcessInner<Platform: ShimPlatform> {
    /// If true, the whole process is exiting.
    group_exit: bool,
    /// If true, one thread is waiting for other threads to exit.
    is_killing_other_threads: bool,
    /// The exit code of the last exited thread in the process. Not updated once
    /// `group_exit` is set.
    exit_status: ExitStatus,
    /// The thread list for the process, mapped by thread ID.
    threads: BTreeMap<i32, Arc<ThreadRemote<Platform>>>,
    /// See [`ProcIdentity`].
    identity: ProcIdentity,
}

/// [`ProcessInner`] as `/proc/<pid>` describes it: the published identity plus every live
/// thread's id and command name, ascending by tid.
fn proc_task_info<Platform: ShimPlatform>(
    pid: i32,
    inner: &ProcessInner<Platform>,
) -> litebox::fs::proc::ProcTaskInfo {
    let identity = &inner.identity;
    litebox::fs::proc::ProcTaskInfo {
        pid,
        ppid: identity.ppid,
        uid: identity.uid,
        gid: identity.gid,
        comm: identity.comm.clone(),
        cmdline: identity.cmdline.clone(),
        exe: identity.exe.clone(),
        threads: inner
            .threads
            .iter()
            .map(|(&tid, remote)| litebox::fs::proc::ProcThreadInfo {
                tid,
                comm: remote.comm(),
            })
            .collect(),
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ExitStatus {
    Exit(i8),
    Signal(litebox_common_linux::signal::Signal),
}

impl<Platform: ShimPlatform> Process<Platform> {
    /// Creates a new process with the given initial thread.
    #[allow(
        clippy::too_many_arguments,
        reason = "each parameter is independently required to construct a process"
    )]
    fn new(
        pid: i32,
        process_group_id: i32,
        remote: Arc<ThreadRemote<Platform>>,
        futex_manager: Arc<FutexManager<Platform>>,
        futex_namespace: usize,
        vfork_completion: Option<Arc<VforkCompletion<Platform>>>,
        shared_vm_parent: Option<&Process<Platform>>,
        launch: Option<Arc<ProcessLaunch<Platform>>>,
    ) -> Self {
        let nr_threads = <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT;
        nr_threads.underlying_atomic().store(1, Ordering::Relaxed);
        let fork_gate = <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT;
        fork_gate.underlying_atomic().store(0, Ordering::Relaxed);
        let shares_parent_vm = shared_vm_parent.is_some();
        let vm = Arc::new(match shared_vm_parent {
            Some(parent) => VmBookkeepingSlot::shared_with(&parent.vm),
            None => VmBookkeepingSlot::new(futex_namespace),
        });
        Self {
            nr_threads,
            fork_gate,
            inner: Arc::new(Mutex::new(ProcessInner {
                exit_status: ExitStatus::Exit(0),
                group_exit: false,
                is_killing_other_threads: false,
                threads: BTreeMap::from_iter([(pid, remote)]),
                identity: ProcIdentity::default(),
            })),
            vm: vm.clone(),
            futex_manager,
            vfork_completion: Mutex::new(vfork_completion),
            shares_parent_vm: AtomicBool::new(shares_parent_vm),
            launch,
            limits: Arc::new(ResourceLimits::default()),
            alarm_timer: Mutex::new(Alarm {
                handle: None,
                deadline: None,
            }),
            brk: SharedVmAtomicUsize::new(vm.clone(), |vm| &vm.brk),
            owned_ranges: SharedVmLockedField::new(vm.clone(), |vm| &vm.owned_ranges),
            elf_patch_cache: SharedVmLockedField::new(vm, |vm| &vm.elf_patch_cache),
            cpu_time_nanos: core::sync::atomic::AtomicU64::new(0),
            session_id: AtomicI32::new(pid),
            process_group_id: Arc::new(AtomicI32::new(process_group_id)),
            controlling_pty: AtomicU32::new(NO_CONTROLLING_PTY),
            dumpable: AtomicBool::new(true),
            address_space: Mutex::new(None),
        }
    }

    /// `PR_GET_DUMPABLE`.
    pub(crate) fn dumpable(&self) -> bool {
        self.dumpable.load(Ordering::Relaxed)
    }

    /// `PR_SET_DUMPABLE`, and the `execve`/`fork` resets described on the field.
    pub(crate) fn set_dumpable(&self, dumpable: bool) {
        self.dumpable.store(dumpable, Ordering::Relaxed);
    }

    /// `/proc/<pid>` view of this process: see [`ProcIdentity`].
    pub(crate) fn proc_task_info(&self, pid: i32) -> litebox::fs::proc::ProcTaskInfo {
        proc_task_info(pid, &self.inner.lock())
    }

    /// Publish the credential half of [`ProcIdentity`].
    fn set_proc_credentials(&self, ppid: i32, uid: u32, gid: u32) {
        let mut inner = self.inner.lock();
        inner.identity.ppid = ppid;
        inner.identity.uid = uid;
        inner.identity.gid = gid;
    }

    /// Publish the thread-group leader's command name (`/proc/<pid>/comm`).
    fn set_proc_comm(&self, comm: &[u8]) {
        let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
        self.inner.lock().identity.comm = comm[..end].to_vec();
    }

    /// Publish the image half of [`ProcIdentity`] after a successful `execve`.
    fn set_proc_image(&self, cmdline: Vec<u8>, exe: Option<alloc::string::String>) {
        let mut inner = self.inner.lock();
        inner.identity.cmdline = cmdline;
        inner.identity.exe = exe;
    }

    /// A `fork` child starts out describing the same image as its parent (a new pid, and a
    /// parent of its own, but the same `argv`/`exe`/`comm` until it `exec`s).
    fn inherit_proc_identity(&self, parent: &Process<Platform>, ppid: i32) {
        let mut identity = parent.inner.lock().identity.clone();
        identity.ppid = ppid;
        let mut inner = self.inner.lock();
        inner.identity = identity;
        self.dumpable.store(parent.dumpable(), Ordering::Relaxed);
        drop(inner);
    }

    fn futex_manager(&self) -> &FutexManager<Platform> {
        self.futex_manager.as_ref()
    }

    fn futex_namespace(&self) -> usize {
        self.vm.current().futex_namespace
    }

    fn detach_vfork_vm(&self) {
        let futex_namespace = self.futex_manager.new_private_namespace();
        self.vm.detach(futex_namespace);
        self.shares_parent_vm.store(false, Ordering::Release);
    }

    fn shares_parent_vm(&self) -> bool {
        self.shares_parent_vm.load(Ordering::Acquire)
    }

    fn complete_vfork(&self) {
        if let Some(completion) = self.vfork_completion.lock().take() {
            completion.complete();
        }
    }

    /// Whether the parent this vfork child shares its memory with is itself a
    /// [`SharedAddressSpace`] member. `false` once the vfork has completed.
    fn vfork_parent_shares_address_space(&self) -> bool {
        self.vfork_completion
            .lock()
            .as_ref()
            .is_some_and(|completion| completion.parent_shares_address_space)
    }

    fn await_launch(&self) -> bool {
        self.launch.as_ref().is_none_or(|launch| launch.wait())
    }

    fn exit_is_publishable(&self) -> bool {
        self.launch
            .as_ref()
            .is_none_or(|launch| launch.is_committed())
    }

    /// Returns this process's process-group ID.
    pub(crate) fn process_group_id(&self) -> i32 {
        self.process_group_id.load(Ordering::Acquire)
    }

    /// Returns this process's controlling Unix98 PTY number, if one is assigned.
    pub(crate) fn controlling_pty(&self) -> Option<u32> {
        let number = self.controlling_pty.load(Ordering::Acquire);
        (number != NO_CONTROLLING_PTY).then_some(number)
    }

    /// Assigns `number` as the controlling terminal when the caller is a session leader.
    ///
    /// Returns `true` when this call makes the assignment and `false` when the same terminal was
    /// already assigned. Stealing a different terminal is rejected.
    pub(crate) fn acquire_controlling_pty(&self, pid: i32, number: u32) -> Result<bool, Errno> {
        if self.session_id.load(Ordering::Acquire) != pid {
            return Err(Errno::EPERM);
        }
        match self.controlling_pty.compare_exchange(
            NO_CONTROLLING_PTY,
            number,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(true),
            Err(current) if current == number => Ok(false),
            Err(_) => Err(Errno::EPERM),
        }
    }

    /// Returns the current number of threads in this process.
    pub fn nr_threads(&self) -> u32 {
        self.nr_threads.underlying_atomic().load(Ordering::Relaxed)
    }

    /// Returns the remote handle for thread `tid` of this process, if it is currently attached
    /// (i.e. running or blocked, not yet exited). Used by `tkill`/`tgkill` to deliver a
    /// specifically-targeted signal without reaching into another thread's non-`Send` local
    /// state -- see [`ThreadRemote::remote_pending`].
    pub(crate) fn thread_remote(&self, tid: i32) -> Option<Arc<ThreadRemote<Platform>>> {
        self.inner.lock().threads.get(&tid).cloned()
    }

    /// Parks the calling thread while this process's fork gate is closed.
    ///
    /// The fast path -- gate open, the only case any thread sees outside a
    /// concurrent multithreaded `fork` -- is a single atomic load. A parked
    /// thread blocks on the raw gate word (never an interruptible wait: this
    /// is called from `CheckForInterrupt::check_for_interrupt`, whose
    /// contract forbids interruptible waiting) and resumes when
    /// [`ForkGateGuard`] reopens the gate. An exiting thread never parks --
    /// it proceeds to detach, and `detach_thread` wakes the gate so the
    /// forker re-evaluates how many siblings it is still waiting for.
    fn park_while_fork_gate_closed(&self, is_exiting: bool) {
        let word = self.fork_gate.underlying_atomic();
        if word.load(Ordering::Acquire) & FORK_GATE_CLOSED == 0 {
            return;
        }
        if is_exiting {
            return;
        }
        word.fetch_add(1, Ordering::AcqRel);
        // The forker blocks on this same word until enough siblings are
        // parked; every increment must wake it to re-count.
        self.fork_gate.wake_all();
        loop {
            let cur = word.load(Ordering::Acquire);
            if cur & FORK_GATE_CLOSED == 0 {
                break;
            }
            let _ = self.fork_gate.block(cur);
        }
        word.fetch_sub(1, Ordering::AcqRel);
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
    fn attach_thread(&self, tid: i32) -> Option<Arc<ThreadRemote<Platform>>> {
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
    /// Returns `true` if this was the last thread in the process (i.e., the process as a whole
    /// is now exiting), `false` if other threads remain.
    ///
    /// # Panics
    /// Panics if the thread ID does not exist in this process.
    fn detach_thread(&self, tid: i32) -> bool {
        let data;
        let (notify, is_last_thread) = {
            let mut inner = self.inner.lock();
            data = inner.threads.remove(&tid);
            assert!(data.is_some());

            let nr_threads = self.nr_threads.underlying_atomic();
            let n = nr_threads.load(Ordering::Relaxed);
            let new_count = n.checked_sub(1).expect("decrementing from zero threads");
            nr_threads.store(new_count, Ordering::Release);
            let is_last_thread = new_count == 0;
            if is_last_thread {
                assert!(inner.threads.is_empty());
                // The last thread exited. Prevent new threads.
                inner.group_exit = true;
            }

            // Notify waiters if this is the last thread of the process
            // (`wait_for_exit`) or if this is the last thread being killed
            // during an exec (`kill_other_threads`).
            (
                is_last_thread || (new_count == 1 && inner.is_killing_other_threads),
                is_last_thread,
            )
        };
        if notify {
            self.nr_threads.wake_all();
        }
        // A forker blocked in `park_sibling_threads_for_fork` counts parked
        // siblings against `nr_threads`; an exiting sibling shrinks the
        // latter without ever parking, so the forker must recount.
        if self.fork_gate.underlying_atomic().load(Ordering::Acquire) & FORK_GATE_CLOSED != 0 {
            self.fork_gate.wake_all();
        }
        // Release any attached tracer rather than leaving it blocked forever on a rendezvous
        // that can now never happen: this thread is gone, so a stop it may still owe its tracer
        // will never arrive. A tracer's next `ptrace` request against this `tid` finds no
        // `ThreadRemote` at all (already removed from `threads` above) and gets `ESRCH`, exactly
        // like `tkill` against an exited thread -- PID/TID-reuse-safe by the same construction.
        #[cfg(target_arch = "aarch64")]
        if let Some(remote) = &data {
            remote.ptrace.on_thread_exit();
        }
        is_last_thread
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
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

    /// Closes the process's fork gate and waits until every sibling thread is
    /// parked at it, so the caller can take the address-space turn (see
    /// [`SharedAddressSpace`]) with the same guarantees a single-threaded
    /// process has: nothing else will touch guest memory until the returned
    /// guard reopens the gate.
    ///
    /// Modeled on [`Self::kill_other_threads`]'s stop-the-world shape:
    /// interrupt every sibling ([`ThreadRemote::interrupt`] wakes a thread
    /// blocked in any interruptible shim wait, and yanks one executing guest
    /// code back into the shim via the platform interrupt), then block on the
    /// gate word until the parked count accounts for every sibling. A sibling
    /// mid-syscall parks at the next
    /// `CheckForInterrupt::check_for_interrupt` or
    /// [`Task::prepare_to_run_guest`] point -- in particular, one mid-copy
    /// into guest memory finishes that copy *before* parking, so the snapshot
    /// taken after this returns cannot lose an in-flight write. Siblings that
    /// exit instead of parking are handled by `detach_thread` waking the gate
    /// so the count converges either way.
    /// [`Process::park_while_fork_gate_closed`] for this task; see
    /// `Process::fork_gate`. Called from the two guest-memory choke points in
    /// `crate::wait`.
    pub(crate) fn park_while_fork_gate_closed(&self) {
        self.process()
            .park_while_fork_gate_closed(self.is_exiting());
    }

    fn park_sibling_threads_for_fork(&self) -> ForkGateGuard<'_, Platform> {
        let process = self.process();
        let word = process.fork_gate.underlying_atomic();
        // If another thread is mid-fork, park like any other sibling until
        // its gate reopens, then take our own turn.
        loop {
            let prev = word.fetch_or(FORK_GATE_CLOSED, Ordering::AcqRel);
            if prev & FORK_GATE_CLOSED == 0 {
                break;
            }
            process.park_while_fork_gate_closed(self.is_exiting());
        }
        let guard = ForkGateGuard { process };
        {
            let inner = process.inner.lock();
            for (&tid, thread) in &inner.threads {
                if tid != self.tid {
                    thread.interrupt();
                }
            }
        }
        loop {
            let cur = word.load(Ordering::Acquire);
            let parked = cur & !FORK_GATE_CLOSED;
            let others = process.nr_threads().saturating_sub(1);
            if parked >= others {
                break;
            }
            let _ = process.fork_gate.block(cur);
        }
        guard
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
        /// The parent's FPSIMD register file at the moment of `clone`/`fork`,
        /// captured on the parent thread (where [`ThreadProvider::get_fp_state`]
        /// reads the *calling* thread's state) since the new host OS thread's
        /// own per-thread FP shadow otherwise starts zeroed -- Linux's
        /// `copy_thread` copies the parent's FPSIMD state into the child task,
        /// so a cloned/forked guest thread must observe the same vector/FPCR/
        /// FPSR values the parent had at the syscall, not a cleared file (that
        /// reset is correct only for `execve`, via `NewProcess`).
        ///
        /// [`ThreadProvider::get_fp_state`]: litebox::platform::ThreadProvider::get_fp_state
        ///
        /// Boxed: the register file is 528 bytes, which would otherwise make
        /// this variant dwarf the others (`clippy::large_enum_variant`).
        #[cfg(target_arch = "aarch64")]
        fp: Box<litebox::platform::FpSimdState64>,
    },
}

#[derive(Clone, Default)]
struct SupplementaryGroups(Box<[u32]>);

impl SupplementaryGroups {
    const MAX: usize = 65_536;

    fn from_user<Platform: ShimPlatform>(size: usize, list: UserPtr<u32>) -> Result<Self, Errno> {
        if size > Self::MAX {
            return Err(Errno::EINVAL);
        }
        let mut groups = if size == 0 {
            Box::default()
        } else {
            list.to_owned_slice::<Platform>(size).ok_or(Errno::EFAULT)?
        };
        groups.sort_unstable();
        Ok(Self(groups))
    }

    fn as_slice(&self) -> &[u32] {
        &self.0
    }
}

/// Credentials of a process
#[derive(Clone)]
pub(crate) struct Credentials {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    supplementary_groups: SupplementaryGroups,
    no_new_privs: bool,
    /// `PR_SET_KEEPCAPS` state. LiteBox does not model capabilities (see
    /// `PrctlArg::SetKeepCaps`'s doc comment), so this is stored only so
    /// `PR_GET_KEEPCAPS` reads back whatever was last set -- there is no
    /// actual capability set for it to gate.
    keep_caps: bool,
}

impl Credentials {
    #[expect(
        clippy::similar_names,
        reason = "uid, euid, gid, and egid are the POSIX credential names"
    )]
    pub(crate) fn new(uid: u32, euid: u32, gid: u32, egid: u32) -> Self {
        Self {
            uid,
            euid,
            suid: euid,
            gid,
            egid,
            sgid: egid,
            supplementary_groups: SupplementaryGroups::default(),
            no_new_privs: false,
            keep_caps: false,
        }
    }

    pub(crate) fn supplementary_groups(&self) -> &[u32] {
        self.supplementary_groups.as_slice()
    }

    pub(crate) fn no_new_privs(&self) -> bool {
        self.no_new_privs
    }

    pub(crate) fn keep_caps(&self) -> bool {
        self.keep_caps
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn process(&self) -> &Arc<Process<Platform>> {
        &self.thread.process
    }

    /// This task's own remote handle -- the piece of its signal/wait state a `tkill`/`tgkill`
    /// from another thread can safely touch. See [`ThreadRemote::remote_pending`].
    pub(crate) fn thread_remote(&self) -> &Arc<ThreadRemote<Platform>> {
        &self.thread.remote
    }

    /// Set the current task's command name.
    pub(crate) fn set_task_comm(&self, comm: &[u8]) {
        let mut new_comm = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let comm = &comm[..comm.len().min(litebox_common_linux::TASK_COMM_LEN - 1)];
        new_comm[..comm.len()].copy_from_slice(comm);
        self.comm.set(new_comm);

        // Publish to `/proc/<pid>/task/<tid>/comm` (every thread) and `/proc/<pid>/comm` (the
        // leader), alongside the credentials `/proc/<pid>/status` reports -- see `ProcIdentity`.
        self.thread.remote.set_comm(&new_comm);
        if self.tid == self.pid {
            self.process().set_proc_comm(&new_comm);
        }
        self.publish_proc_credentials();
    }

    /// Refresh the credential half of this process's [`ProcIdentity`] from this task's live
    /// credentials.
    pub(crate) fn publish_proc_credentials(&self) {
        let credentials = self.credentials.borrow();
        self.process()
            .set_proc_credentials(self.ppid, credentials.uid, credentials.gid);
    }

    /// This task's own `/proc/<pid>` view, refreshed from its live credentials first; what the
    /// shim publishes as `/proc/self` ahead of each lookup (see `syscalls::file`'s
    /// `publish_proc_view`).
    pub(crate) fn proc_task_info(&self) -> litebox::fs::proc::ProcTaskInfo {
        self.publish_proc_credentials();
        self.process().proc_task_info(self.pid)
    }

    /// Handle syscall `seccomp` (and `prctl(PR_SET_SECCOMP)`, which decodes to it).
    ///
    /// The shim has no BPF filter engine, so this answers as a kernel built without
    /// `CONFIG_SECCOMP`: `ENOSYS` for both mode-setting operations, never a fake success. A `0`
    /// here would make a sandboxed program believe its filter is enforced when nothing is --
    /// Chromium's renderer would then run with a "layer-2 sandbox" that filters nothing.
    /// Chromium's probes (`sandbox/linux/seccomp-bpf/sandbox_bpf.cc`,
    /// `KernelSupportsSeccompBPF`/`KernelSupportsSeccompFlags`) take only `EFAULT` as "supported"
    /// and `DCHECK` that anything else is `ENOSYS` or `EINVAL`, so `seccomp_bpf_supported_`
    /// stays false, `StartSeccompBPF` returns without a promise and `CheckForBrokenPromises`
    /// has nothing to `CHECK`; the setuid/namespace layer-1 sandbox is unaffected. The two
    /// query operations answer as a kernel without `CONFIG_SECCOMP_FILTER` does
    /// (`EOPNOTSUPP`); an unknown operation is `EINVAL`, as in Linux's `do_seccomp`.
    pub(crate) fn sys_seccomp(
        &self,
        operation: u32,
        flags: u32,
        args: UserPtr<u8>,
    ) -> Result<usize, Errno> {
        const SECCOMP_SET_MODE_STRICT: u32 = 0;
        const SECCOMP_SET_MODE_FILTER: u32 = 1;
        const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
        const SECCOMP_GET_NOTIF_SIZES: u32 = 3;
        // One line per (operation, flags), not per call: the per-call `args` pointer is in
        // the trace-level `syscall req=` record.
        let _ = args;
        match operation {
            SECCOMP_SET_MODE_STRICT | SECCOMP_SET_MODE_FILTER => {
                log_unsupported!(
                    "seccomp(operation = {operation}, flags = {flags:#x}): no BPF filtering -> ENOSYS"
                );
                Err(Errno::ENOSYS)
            }
            SECCOMP_GET_ACTION_AVAIL | SECCOMP_GET_NOTIF_SIZES => {
                log_unsupported!("seccomp(operation = {operation}) -> EOPNOTSUPP");
                Err(Errno::EOPNOTSUPP)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// Handle syscall `prctl`.
    pub(crate) fn sys_prctl(&self, arg: PrctlArg) -> Result<usize, Errno> {
        match arg {
            PrctlArg::SetPDeathSig(signal) => {
                self.thread.parent_death_signal.set(signal);
                self.global
                    .processes
                    .set_parent_death_signal(self.pid, signal);
                Ok(0)
            }
            PrctlArg::GetPDeathSig(signal_ptr) => {
                let signal = self.thread.parent_death_signal.get();
                signal_ptr
                    .write_at_offset::<Platform>(0, signal.map_or(0, |signal| signal.as_i32()))
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }
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
            PrctlArg::GetDumpable => Ok(usize::from(self.process().dumpable())),
            // Only `SUID_DUMP_DISABLE` (0) and `SUID_DUMP_USER` (1) may be set; Linux refuses
            // `SUID_DUMP_ROOT` (2) and anything else with `EINVAL`.
            PrctlArg::SetDumpable(value) => match value {
                0 | 1 => {
                    self.process().set_dumpable(value == 1);
                    Ok(0)
                }
                _ => Err(Errno::EINVAL),
            },
            PrctlArg::SetNoNewPrivs => {
                let mut credentials = self.credentials.borrow().as_ref().clone();
                credentials.no_new_privs = true;
                *self.credentials.borrow_mut() = Arc::new(credentials);
                Ok(0)
            }
            PrctlArg::GetNoNewPrivs => Ok(usize::from(self.credentials.borrow().no_new_privs())),
            PrctlArg::SetKeepCaps(keep) => {
                let mut credentials = self.credentials.borrow().as_ref().clone();
                credentials.keep_caps = keep;
                *self.credentials.borrow_mut() = Arc::new(credentials);
                Ok(0)
            }
            PrctlArg::GetKeepCaps => Ok(usize::from(self.credentials.borrow().keep_caps())),
            // `PrctlArg` is `#[non_exhaustive]`; the syscall decoder rejects every option not
            // represented above with `EINVAL` before constructing one.
            _ => unreachable!(),
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
            // `ArchPrctlArg` is `#[non_exhaustive]`, but on every target it declares (`SetFs`/
            // `GetFs` exist only under x86_64) every variant is matched above, and the syscall
            // decoder itself only runs `#[cfg(target_arch = "x86_64")]`, so on other targets this
            // is never even reachable via a real `arch_prctl` syscall.
            _ => unreachable!(),
        }
    }
}

const ROBUST_LIST_LIMIT: isize = 2048;

/// Bit set in a robust futex word's low bits by the kernel (here, the shim) when the thread
/// that held the lock dies without releasing it, so the next owner can detect the previous
/// holder died mid-critical-section. Matches Linux's `FUTEX_OWNER_DIED`.
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
/// Bit set in a robust futex word's low bits when at least one thread is (or might be) sleeping
/// in `FUTEX_WAIT` on it, so the unlocker knows to `FUTEX_WAKE`. Matches Linux's `FUTEX_WAITERS`.
const FUTEX_WAITERS: u32 = 0x8000_0000;
/// Mask isolating the TID stored in a robust futex word's low bits. Matches Linux's
/// `FUTEX_TID_MASK`.
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Processes a single robust-futex-list entry belonging to a dying thread: if the futex word
    /// still records this thread as the owner, marks it dead (setting [`FUTEX_OWNER_DIED`] and
    /// clearing the TID) and, if a waiter may be present, wakes one -- mirroring Linux's
    /// `handle_futex_death` (`kernel/futex/core.c`). Without this, a thread that dies while
    /// still holding a robust `pthread_mutex_t` would leave every future waiter on that lock
    /// blocked forever, since its owner can never call `FUTEX_WAKE` again.
    fn handle_futex_death(&self, futex_addr: UserPtr<u32>, pending_op: bool) -> Result<(), Errno> {
        if !futex_addr.as_usize().is_multiple_of(4) {
            return Err(Errno::EINVAL);
        }
        let futex_addr = UserPtrMut::from_usize(futex_addr.as_usize());

        let Some(mut word) = futex_addr.read_at_offset::<Platform>(0) else {
            return Err(Errno::EFAULT);
        };

        loop {
            // Only touch the word if it's still (nominally) owned by this dying thread -- a lock
            // that was already unlocked and re-acquired by someone else, or never actually locked
            // by us despite being linked into our robust list, must be left alone.
            #[expect(
                clippy::cast_sign_loss,
                reason = "tid is always non-negative; only ever compared against another tid read \
                          back from a futex word, never used arithmetically"
            )]
            if (word & FUTEX_TID_MASK) != self.tid as u32 {
                return Ok(());
            }

            let had_waiters = word & FUTEX_WAITERS != 0;
            let new_word = (word & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
            match futex_addr.compare_exchange::<Platform>(word, new_word) {
                None => return Err(Errno::EFAULT),
                Some(Err(actual)) => {
                    word = actual;
                }
                Some(Ok(_)) => {
                    if had_waiters || pending_op {
                        let _ = self.sys_futex(FutexArgs::Wake {
                            addr: futex_addr,
                            flags: litebox_common_linux::FutexFlags::empty(),
                            count: 1,
                        });
                    }
                    return Ok(());
                }
            }
        }
    }
}

fn fetch_robust_entry(
    head: UserPtr<litebox_common_linux::RobustList>,
) -> (UserPtr<litebox_common_linux::RobustList>, bool) {
    let next = head.as_usize();
    (UserPtr::from_usize(next & !1), next & 1 != 0)
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn wake_robust_list(
        &self,
        head: UserPtr<litebox_common_linux::RobustListHead>,
    ) -> Result<(), Errno> {
        let mut limit = ROBUST_LIST_LIMIT;
        let head_ptr = head.as_usize();
        let head = head.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        let (mut entry, _pi) = fetch_robust_entry(UserPtr::from_usize(head.list.next));
        let (pending, _ppi) = fetch_robust_entry(UserPtr::from_usize(head.list_op_pending));
        let futex_offset = head.futex_offset;
        let entry_head = head_ptr + offset_of!(litebox_common_linux::RobustListHead, list);
        while entry.as_usize() != entry_head && limit > 0 {
            let nxt = entry
                .read_at_offset::<Platform>(0)
                .map(|e| fetch_robust_entry(UserPtr::from_usize(e.next)));
            if entry.as_usize() != pending.as_usize() {
                self.handle_futex_death(
                    UserPtr::from_usize(entry.as_usize().wrapping_add_signed(futex_offset)),
                    false,
                )?;
            }
            let Some((next_entry, _next_pi)) = nxt else {
                return Err(Errno::EFAULT);
            };

            entry = next_entry;
            limit -= 1;
        }

        if pending.as_usize() != 0 {
            let _ = self.handle_futex_death(
                UserPtr::from_usize(pending.as_usize().wrapping_add_signed(futex_offset)),
                true,
            );
        }
        Ok(())
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Called when the task is exiting.
    pub(crate) fn prepare_for_exit(&mut self) {
        // `CLOCK_THREAD_CPUTIME_ID` only ever reads the calling thread's own clock, so this has
        // to happen here, on the exiting thread itself, rather than later from whichever thread
        // ends up reaping it. Accumulated into the process (rather than overwritten) so that a
        // multithreaded process's rusage reflects every thread that has exited so far, not just
        // the last one.
        self.thread.process.cpu_time_nanos.fetch_add(
            self.global
                .platform
                .thread_cpu_time()
                .as_nanos()
                .try_into()
                .unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );

        let exit_is_publishable = self.process().exit_is_publishable();
        let clear_child_tid_on_exit =
            self.process().nr_threads() > 1 || self.process().shares_parent_vm();
        let can_touch_guest_memory = self
            .membership()
            .is_none_or(|membership| membership.holding());
        if exit_is_publishable && can_touch_guest_memory {
            if let Some(clear_child_tid) = self.thread.clear_child_tid.take()
                && clear_child_tid_on_exit
            {
                let _ = clear_child_tid.write_at_offset::<Platform>(0, 0);
                // Cast from *i32 to *u32.
                let clear_child_tid = UserPtrMut::from_usize(clear_child_tid.as_usize());
                let _ = self.sys_futex(litebox_common_linux::FutexArgs::Wake {
                    addr: clear_child_tid,
                    flags: litebox_common_linux::FutexFlags::empty(),
                    count: 1,
                });
            }
            if let Some(robust_list) = self.thread.robust_list.take() {
                let _ = self.wake_robust_list(robust_list);
            }
        } else {
            // An aborted `ProcessLaunch` never entered guest userspace, and a parked copying-fork
            // task does not currently own the bytes at its guest addresses. Neither may clear a
            // child-TID word or walk a robust list in whichever process image is actually live.
            self.thread.clear_child_tid.take();
            self.thread.robust_list.take();
        }

        // Keep this thread counted until every exit-time access to guest memory is complete. An
        // execing sibling waits for `nr_threads == 1` before tearing the old address space down.
        let is_last_thread = self.thread.detach_from_process();

        // Every write to guest memory above is done, so a task that shares its address space can
        // now hand it back -- which it must, or the members still alive would wait for it
        // forever. An aborted launch never received the fork token in the first place, despite its
        // not-yet-running membership being constructed as the future holder, so it must only drop
        // that membership rather than release the actual parent's token. See [`SharedAddressSpace`].
        // The ranges this process shared with its family, captured before the membership is
        // given up below: what is *not* in them is this process's alone to release.
        let shared_ranges = self
            .membership()
            .map(|membership| membership.shared_ranges.lock().clone());
        // Membership is the process's, so only its last thread settles it; a sibling still
        // running needs the token exactly as before.
        let alone_in_address_space = if !is_last_thread {
            false
        } else if !exit_is_publishable {
            self.process().address_space.lock().take();
            false
        } else if self.process().shares_parent_vm() {
            // The memory is the vfork parent's, and so is any family this task forked into.
            self.hand_address_space_to_vfork_parent();
            false
        } else {
            self.leave_address_space()
        };

        // `FilesState` is shared (via `Arc`) across every `CLONE_FILES` thread of the process,
        // and closing an fd is only ever done explicitly (via `do_close`, which routes through
        // `Descriptors::remove` and the resource's own `Drop` impl -- e.g. a pipe write-end's
        // `Drop` firing its `HUP` notification). Just letting `FilesState`/`RawDescriptorStorage`
        // fall out of scope does NOT do this: `OwnedFd::drop` is a no-op for any fd that was
        // never explicitly closed, so any fd still open when the process exits would otherwise
        // leak forever at the descriptor-table level -- e.g. hanging a reader elsewhere in the
        // process that is blocked in `read()` waiting for a pipe write-end's `EOF`, regardless of
        // whether something else (like an epoll registration, see `epoll.rs`) also still
        // references the fd. Real Linux closes every fd of a process as part of process exit, so
        // mirror that here -- but only once, when the *last* thread sharing this file table is
        // the one exiting, matching `CLONE_FILES` semantics (a single thread of a still-running
        // multithreaded process exiting must NOT close fds out from under its siblings).
        if is_last_thread {
            // Descriptors go first: anything at the other end of one of them (an X server seeing
            // its client vanish, a pipe reader getting EOF) then learns of the exit before the
            // slower memory teardown below, and nothing in a close path needs the mappings --
            // shared-file copy-back holds its own entry handles, not fds, and runs on `munmap`.
            self.close_all_fds_on_exit();
            // Linux tears a process's address space down when its last thread exits. Here that
            // is only safe when no other guest process can be using the bytes at this process's
            // addresses: a fork-family member that is not alone has a parked sibling whose live
            // image occupies exactly these ranges (the child took the parent's image over at
            // the same addresses), and a vfork-shared child's `owned_ranges` *are* its parent's.
            // Both of those keep their memory for the survivor, exactly as `execve` decides via
            // `leave_address_space_if_alone`/`detach_vfork_vm`. Everything else -- every
            // ordinary exec'd process -- releases what it owns, so short-lived processes stop
            // leaking their whole image and stack into the process-blind page manager forever.
            if alone_in_address_space && exit_is_publishable && !self.process().shares_parent_vm() {
                self.release_owned_memory_on_exit();
            } else if exit_is_publishable
                && !self.process().shares_parent_vm()
                && let Some(shared_ranges) = shared_ranges
            {
                // Still a family member's sibling: the shared ranges stay (the others own them
                // too), but what this process mapped for itself after the fork is nobody else's
                // and would otherwise leak for the family's lifetime -- a zygote spawns many
                // short-lived children.
                self.release_private_memory_on_exit(&shared_ranges);
            }
            // The process is gone: become a zombie its parent can `wait4`, and let go of any
            // children of our own (nothing can ever reap them now).
            let status = self.thread.process.inner.lock().exit_status;
            let cpu_time_nanos = self.thread.process.cpu_time_nanos.load(Ordering::Relaxed);
            self.global.processes.unregister_process(self.pid);
            if exit_is_publishable {
                self.global
                    .processes
                    .record_exit(self.pid, status, cpu_time_nanos);
                self.global
                    .processes
                    .signal_and_discard_children_of(self.pid);
            }
            self.process().complete_vfork();
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
/// On both `x86_64` and `aarch64` this is a `*mut u8` pointing at an
/// arbitrarily sized memory region: the value `clone(CLONE_SETTLS)` supplies
/// becomes `FS.base` on x86-64 and `TPIDR_EL0` on aarch64.
type ThreadLocalDescriptor = UserPtrMut<u8>;

/// The architecture register holding the guest's thread pointer.
///
/// The platform owns the hardware register in both cases and virtualizes the
/// guest's view of it, so the shim always goes through [`ArchSpecificRegister`]
/// rather than touching it directly.
#[cfg(target_arch = "x86_64")]
const GUEST_TLS_REGISTER: ArchSpecificRegister = ArchSpecificRegister::FsBase;
#[cfg(target_arch = "aarch64")]
const GUEST_TLS_REGISTER: ArchSpecificRegister = ArchSpecificRegister::TpidrEl0;

struct NewThreadArgs<Platform: ShimPlatform, FS: ShimFS> {
    /// Task struct that maintains all per-thread data
    task: Task<Platform, FS>,
}

#[derive(Clone, Copy)]
enum ProcessCloneKind {
    Fork,
    VforkCopy,
    VforkShared,
}

impl ProcessCloneKind {
    fn copies_vm(self) -> bool {
        matches!(self, Self::Fork | Self::VforkCopy)
    }

    fn waits_for_exec_or_exit(self) -> bool {
        matches!(self, Self::VforkCopy | Self::VforkShared)
    }

    fn shares_parent_vm(self) -> bool {
        matches!(self, Self::VforkShared)
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> litebox::shim::InitThread for NewThreadArgs<Platform, FS> {
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

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
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

    pub(crate) fn sys_unshare(&self, flags: CloneFlags) -> Result<usize, Errno> {
        if flags.is_empty() {
            return Ok(0);
        }
        let namespace_flags = CloneFlags::NEWNS
            | CloneFlags::NEWCGROUP
            | CloneFlags::NEWUTS
            | CloneFlags::NEWIPC
            | CloneFlags::NEWUSER
            | CloneFlags::NEWPID
            | CloneFlags::NEWNET
            | CloneFlags::NEWTIME;
        if flags.intersects(namespace_flags) {
            // LiteBox deliberately exposes no namespace-creation capability. `EPERM` matches a
            // kernel where the caller lacks that capability and lets sandbox probes fail closed.
            return Err(Errno::EPERM);
        }
        log_unsupported!("unshare with unsupported flags: {flags:?}");
        Err(Errno::EINVAL)
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

        let process_kind_flags = CloneFlags::VM | CloneFlags::VFORK;
        let process_tid_flags =
            CloneFlags::PARENT_SETTID | CloneFlags::CHILD_SETTID | CloneFlags::CHILD_CLEARTID;
        // `CLONE_FS` on a new *process* shares the cwd/umask/root with the parent, the way
        // Chromium's `chrome-sandbox` spawns its chroot helper (`clone(CLONE_FS | SIGCHLD)`)
        // so that the helper's `chroot` lands on the sandboxed process.
        let supported_process_flags = process_kind_flags | process_tid_flags | CloneFlags::FS;
        if !flags.intersects(!supported_process_flags) {
            match flags & process_kind_flags {
                kind_flags if kind_flags.is_empty() => {
                    return self.do_process_clone(ctx, args, flags, ProcessCloneKind::Fork);
                }
                kind_flags if kind_flags.bits() == CloneFlags::VFORK.bits() => {
                    return self.do_process_clone(ctx, args, flags, ProcessCloneKind::VforkCopy);
                }
                kind_flags if kind_flags.bits() == process_kind_flags.bits() => {
                    return self.do_process_clone(ctx, args, flags, ProcessCloneKind::VforkShared);
                }
                _ => {}
            }
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

        // `exit_signal` names the signal to send the parent when this task dies. Only its range
        // is checked: this shim always sends `SIGCHLD` (see `ProcessTable::record_exit`), and a
        // parent that asked for something else would learn of its children through `wait4`
        // anyway (see `Task::sys_wait4`).
        if exit_signal > MAX_SIGNAL_NUMBER {
            return Err(Errno::EINVAL);
        }

        // A new thread shares its process's place in a `SharedAddressSpace` (membership is
        // per process), so a forked child that never `exec`s may go multithreaded; see
        // `Task::quiesce_and_hand_off` for how such a process takes its turns. This used to
        // opportunistically drop the membership here when the process had gone solo in its
        // family (every forked child since exited or exec'ed) -- but a process is not done
        // forking just because its most recent child already exited (a fork server's ordinary
        // loop), and doing this on the hottest possible path (`pthread_create`, called before
        // every new thread) churned through disjoint families constantly, implicated live
        // 2026-09-07 in guest-level `struct pthread` corruption after a fork (see
        // `Task::release_address_space`'s doc comment and memory
        // litebox-chromium-zygote-fork-corruption.md). A solo-but-still-membered process costs
        // nothing to leave as is: `leave_address_space` (execve, or this process's last thread
        // exiting) retires it for real when the process is actually done with it.

        let tls = if flags.contains(CloneFlags::SETTLS) {
            let addr = tls.trunc();
            #[cfg(target_arch = "x86_64")]
            {
                // Validate the user-controlled TLS base before spawning the
                // thread: `wrfsbase` faults on a non-canonical address, so an
                // unchecked value would take down the host, not the guest.
                // aarch64 needs no equivalent check -- the guest thread pointer
                // is virtualized into a memory slot rather than written to the
                // hardware register, so any value is inert until the guest
                // dereferences it. Linux's `copy_thread` likewise stores the
                // aarch64 value unvalidated.
                if !litebox_common_linux::arch::is_valid_user_fs_base(addr) {
                    return Err(Errno::EPERM);
                }
            }
            Some(ThreadLocalDescriptor::from_usize(addr))
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
        thread.remote.set_comm(&self.comm.get());
        thread.init_state.set(ThreadInitState::NewThread {
            stack: sp,
            tls,
            set_child_tid,
            // Captured on this (the parent/calling) thread: `get_fp_state`
            // reads whichever thread it is called on, so the child's FPSIMD
            // file must be read here, before the new host OS thread (with its
            // own zeroed FP shadow) starts running.
            #[cfg(target_arch = "aarch64")]
            fp: Box::new(self.global.platform.get_fp_state()),
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
                        credentials: RefCell::new(self.credentials.borrow().clone()),
                        comm: self.comm.clone(),
                        fs: fs.into(),
                        files: self.files.clone(), // TODO: !CLONE_FILES support
                        signals: self.signals.clone_for_new_task(),
                        guest_sp: Cell::new(0),
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

    fn do_process_clone(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        args: &litebox_common_linux::CloneArgs,
        flags: CloneFlags,
        kind: ProcessCloneKind,
    ) -> Result<usize, Errno> {
        const MAX_SIGNAL_NUMBER: u64 = 64;
        if args.exit_signal > MAX_SIGNAL_NUMBER {
            return Err(Errno::EINVAL);
        }
        if args.set_tid != 0 || args.set_tid_size != 0 || args.cgroup != 0 {
            log_unsupported!("fork with set_tid or cgroup");
            return Err(Errno::EINVAL);
        }
        // A stack of the child's own is honoured only when the child runs on the parent's live
        // memory (`CLONE_VM|CLONE_VFORK`): musl's `posix_spawn` is `clone(CLONE_VM|CLONE_VFORK|
        // SIGCHLD, stack, ...)` with the child function's frame on a small buffer in the parent,
        // and the suspended parent is exactly why that memory stays valid. A copying fork snapshots
        // and restores memory around the parent's own `sp`, which a foreign stack would sit outside
        // of, so it is still refused. Legacy `clone` passes the initial `sp` itself (`stack_size`
        // 0); `clone3` passes the base and size, the way `do_clone` already reads them.
        let child_sp = if args.stack != 0 || args.stack_size != 0 {
            if !kind.shares_parent_vm() || args.stack == 0 {
                log_unsupported!("fork with a stack");
                return Err(Errno::EINVAL);
            }
            let stack: usize = args.stack.trunc();
            Some(stack.wrapping_add(args.stack_size.trunc()))
        } else {
            None
        };
        let child_tid_ptr =
            (args.child_tid != 0).then(|| UserPtrMut::from_usize(args.child_tid.trunc()));
        let set_child_tid = flags
            .contains(CloneFlags::CHILD_SETTID)
            .then_some(child_tid_ptr)
            .flatten();
        let clear_child_tid = flags
            .contains(CloneFlags::CHILD_CLEARTID)
            .then_some(child_tid_ptr)
            .flatten();
        let set_parent_tid = if flags.contains(CloneFlags::PARENT_SETTID) {
            Some(UserPtrMut::from_usize(args.parent_tid.trunc()))
        } else {
            None
        };
        if matches!(kind, ProcessCloneKind::VforkCopy) && self.process().nr_threads() > 1 {
            // A copied VM still uses the one native host mapping. Keeping only the calling parent
            // task suspended while sibling threads continue on the parent's copy needs a
            // process-wide address-space membership, which this backend does not yet have.
            log_unsupported!("CLONE_VFORK without CLONE_VM from a multithreaded process");
            return Err(Errno::ENOSYS);
        }
        // A vfork child that has not exec'd yet runs on its *parent's* memory, so the family
        // this fork creates is really the parent's: the child stands in for it until it exits or
        // execs and hands the membership over (`hand_address_space_to_vfork_parent`). That has
        // nowhere to go when the parent is already a member of another family, so refuse rather
        // than run two token protocols over one memory.
        if kind.copies_vm()
            && self.process().shares_parent_vm()
            && self.process().vfork_parent_shares_address_space()
        {
            log_unsupported!("fork from a vfork child whose parent has itself forked");
            return Err(Errno::ENOSYS);
        }
        let _fork_gate_guard = match kind {
            ProcessCloneKind::Fork if self.process().nr_threads() > 1 => {
                Some(self.park_sibling_threads_for_fork())
            }
            ProcessCloneKind::Fork
            | ProcessCloneKind::VforkCopy
            | ProcessCloneKind::VforkShared => None,
        };
        let parent_tid_is_shared = set_parent_tid.is_some_and(|ptr| {
            let start = ptr.as_usize();
            let end = start.saturating_add(core::mem::size_of::<i32>());
            self.global.pm.mappings().into_iter().any(|(range, flags)| {
                range.start <= start && end <= range.end && flags.contains(VmFlags::VM_SHARED)
            })
        });
        // A vfork child shares every byte with its parent. An ordinary fork child sees a
        // CLONE_PARENT_SETTID store only when the pointer itself names a shared mapping; private
        // parent memory is updated after the parent reacquires its own image below.
        let set_parent_tid_before_child = kind.shares_parent_vm() || parent_tid_is_shared;

        let child_pid = self.global.next_thread_id.fetch_add(1, Ordering::Relaxed);
        let files = self.files.borrow().fork_copy(self)?;
        let fs = if flags.contains(CloneFlags::FS) {
            self.fs.borrow().clone()
        } else {
            alloc::sync::Arc::new((**self.fs.borrow()).clone())
        };

        // The guest's thread pointer lives in a per-host-thread slot, so the new host thread has
        // to be told the value the parent is running with -- the libc data it points at is in the
        // address space the child is about to share.
        let tls = self
            .global
            .platform
            .get_arch_specific_register(&GUEST_TLS_REGISTER)
            .ok()
            .filter(|tls| *tls != 0)
            .map(ThreadLocalDescriptor::from_usize);

        let created_parent_address_space = kind.copies_vm() && !self.shares_address_space();
        let fork_sp = guest_stack_pointer(ctx);
        let child_tid_range = (set_child_tid.is_some() || clear_child_tid.is_some())
            .then(|| {
                let start = child_tid_ptr.unwrap().as_usize();
                start..start.saturating_add(core::mem::size_of::<i32>())
            })
            .and_then(|tid_range| {
                self.global
                    .pm
                    .mappings()
                    .into_iter()
                    .any(|(stack, flags)| {
                        flags.contains(VmFlags::VM_WRITE)
                            && !flags.contains(VmFlags::VM_SHARED)
                            && stack.start < fork_sp
                            && fork_sp <= stack.end
                            && stack.start <= tid_range.start
                            && tid_range.end <= stack.end
                    })
                    .then_some(tid_range)
            });
        let (shared, preserved_stack_ranges, shared_ranges) = if kind.copies_vm() {
            let membership = self.join_address_space();
            let mut ranges = self.preserved_address_space_ranges();
            if let Some(range) = child_tid_range.as_ref() {
                ranges.insert_bounded(range.clone(), MAX_PRESERVED_STACK_RANGES);
            }
            // Everything the parent owns right now is what the child inherits, and so what the
            // two of them must copy out and back for each other.
            let shared_ranges = self.process().owned_ranges.lock().clone();
            (Some(membership.shared.clone()), ranges, shared_ranges)
        } else {
            (None, OwnedRanges::default(), OwnedRanges::default())
        };
        let vfork_completion = kind
            .waits_for_exec_or_exit()
            .then(|| Arc::new(VforkCompletion::new(self.shares_address_space())));
        let launch = Arc::new(ProcessLaunch::new());

        let thread = match kind {
            ProcessCloneKind::Fork => ThreadState::new_forked_process(
                child_pid,
                self.process().process_group_id(),
                self.process().futex_manager.clone(),
                launch.clone(),
            ),
            ProcessCloneKind::VforkCopy => ThreadState::new_vfork_copy_process(
                child_pid,
                self.process().process_group_id(),
                self.process().futex_manager.clone(),
                vfork_completion.as_ref().unwrap().clone(),
                launch.clone(),
            ),
            ProcessCloneKind::VforkShared => ThreadState::new_vforked_process(
                child_pid,
                self.process().process_group_id(),
                self.process(),
                vfork_completion.as_ref().unwrap().clone(),
                launch.clone(),
            ),
        };
        thread.init_state.set(ThreadInitState::NewThread {
            // Usually no stack of its own: it runs on the parent's, below the parent's `sp`.
            stack: child_sp,
            tls,
            set_child_tid,
            // See the `do_clone` call site's identical capture: read on the
            // parent thread, before the child's own OS thread (and its
            // separately zeroed FP shadow) starts running.
            #[cfg(target_arch = "aarch64")]
            fp: Box::new(self.global.platform.get_fp_state()),
        });
        thread.clear_child_tid.set(clear_child_tid);

        let child = Task {
            global: self.global.clone(),
            wait_state: crate::wait::WaitState::new(self.global.platform),
            thread,
            pid: child_pid,
            tid: child_pid,
            ppid: self.pid,
            credentials: RefCell::new(self.credentials.borrow().clone()),
            comm: self.comm.clone(),
            fs: fs.into(),
            files: Arc::new(files).into(),
            signals: self.signals.clone_for_new_process(),
            guest_sp: Cell::new(fork_sp),
        };
        if let Some(shared) = shared.as_ref() {
            let membership = Arc::new(AddressSpaceMembership::new(
                shared.clone(),
                preserved_stack_ranges.clone(),
                shared_ranges,
            ));
            membership.mark_acquired(self.global.platform.now());
            *child.process().address_space.lock() = Some(membership);
            // DIAGNOSTIC (musl-fork-struct-pthread-corruption, temporary, additive-only): see
            // `VmBookkeeping::family_id`. This is the CHILD's side of joining the family --
            // `Task::join_address_space` (which sets `family_id` on the parent) only ever runs
            // on the forking (parent) task, so without this the child's own `family_id` would
            // stay at its default 0 despite genuinely, correctly sharing `shared` with the
            // parent, producing a false-positive "cross-lineage" reading for every legitimate
            // parent/child overlap.
            child
                .process()
                .vm
                .current()
                .family_id
                .store(Arc::as_ptr(shared) as usize, Ordering::Release);
        }
        let child_inner = child.process().inner.clone();
        child.process().limits.inherit_from(&self.process().limits);
        child
            .process()
            .inherit_proc_identity(self.process(), self.pid);
        child.thread.remote.set_comm(&self.comm.get());
        child.process().session_id.store(
            self.process().session_id.load(Ordering::Acquire),
            Ordering::Release,
        );
        child.process().controlling_pty.store(
            self.process().controlling_pty.load(Ordering::Acquire),
            Ordering::Release,
        );
        if kind.copies_vm() {
            child.process().brk.store(
                self.process().brk.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            // A forked child initially owns a snapshot of the same ranges and patch state. A
            // vfork child already resolves these fields through the parent's live VM identity.
            *child.process().owned_ranges.lock() = self.process().owned_ranges.lock().clone();
            *child.process().elf_patch_cache.lock() = self.process().elf_patch_cache.lock().clone();
        }
        self.global.processes.add_child(child_pid, self.pid);
        // Registered before the child can run, so a child that exits immediately still finds its
        // parent (this one) in the live set and can post it a `SIGCHLD`.
        self.register_for_remote_signals();
        self.global.processes.register_process(
            child_pid,
            child.remote_signal_target(),
            child.process(),
        );

        let r = unsafe {
            self.global
                .platform
                .spawn_thread(ctx, Box::new(NewThreadArgs { task: child }))
        };
        if let Err(err) = r {
            litebox_util_log::error!(err:% = err; "failed to spawn child process");
            launch.abort();
            self.global.processes.forget_failed_spawn(child_pid);
            if created_parent_address_space {
                // `join_address_space` made this membership solely for the child that failed to
                // launch. The parent still holds the token, so discard the bookkeeping without
                // releasing it.
                self.process().address_space.lock().take();
            }
            return Err(Errno::ENOMEM);
        }
        if kind.copies_vm()
            && let Some(range) = child_tid_range
        {
            self.preserve_address_space_range(range);
        }
        // The child host thread exists but remains blocked behind `ProcessLaunch`. A shared-memory
        // parent-TID store must be visible before it starts; a private ordinary-fork store is
        // deliberately deferred until the parent's snapshotted image is live again.
        if set_parent_tid_before_child && let Some(parent_tid_ptr) = set_parent_tid {
            let _ = parent_tid_ptr.write_at_offset::<Platform>(0, child_pid);
        }
        // Keep the new host thread behind its launch gate until spawn has succeeded. This makes
        // registration and exit publication transactional: an error cannot leave a zombie or
        // SIGCHLD for a child that never ran. For a copying fork, hand off the snapshotted address
        // space only now: if host-thread creation failed, the parent still owns the token and can
        // return ENOMEM instead of waiting forever for a child that does not exist.
        if kind.copies_vm() {
            self.park_and_hand_off(fork_sp, child_pid, &child_inner);
        }
        launch.commit();

        let parent_image_is_live = match kind {
            ProcessCloneKind::Fork => self.acquire_address_space(),
            ProcessCloneKind::VforkCopy => {
                vfork_completion.as_ref().unwrap().wait();
                self.acquire_address_space()
            }
            ProcessCloneKind::VforkShared => {
                let completion = vfork_completion.as_ref().unwrap();
                completion.wait();
                self.inherit_address_space_from_vfork_child(completion)
            }
        };
        if parent_image_is_live
            && !set_parent_tid_before_child
            && let Some(parent_tid_ptr) = set_parent_tid
        {
            let _ = parent_tid_ptr.write_at_offset::<Platform>(0, child_pid);
        }
        Ok(usize::try_from(child_pid).unwrap())
    }

    /// Returns this process's membership in a shared address space, creating one (with this
    /// process as its first member and current holder) if it is not in one yet, and records the
    /// ranges this process owns right now as shared: a child forked now inherits all of them.
    fn join_address_space(&self) -> Arc<AddressSpaceMembership<Platform>> {
        let owned = self.process().owned_ranges.lock().clone();
        let mut slot = self.process().address_space.lock();
        if let Some(membership) = slot.as_ref() {
            debug_assert!(
                membership.holding(),
                "forking without holding the address space"
            );
            membership.shared_ranges.lock().union_with(&owned);
            return membership.clone();
        }
        // DIAGNOSTIC (musl-fork-atfork-parent-corruption-20260905, temporary, additive-only):
        // logs every time a fork starts a *brand new* SharedAddressSpace rather than reusing an
        // existing one for this process. Fires legitimately on a process's first-ever fork; if it
        // also fires on a LATER fork by a process with a live fork-family history, that would mean
        // `leave_address_space_if_alone` (called from every plain `do_clone`/pthread_create) raced
        // this fork and dropped the prior membership out from under it, silently starting a second,
        // disconnected token/SharedAddressSpace over the same physical guest memory.
        litebox_util_log::debug!(
            pid:? = self.pid, tid:? = self.tid;
            "diag: join_address_space creating a brand-new SharedAddressSpace (no prior membership)"
        );
        let shared = Arc::new(SharedAddressSpace::new(self.pid, &self.process().inner));
        // DIAGNOSTIC (musl-fork-struct-pthread-corruption, temporary, additive-only): see
        // `VmBookkeeping::family_id`.
        self.process()
            .vm
            .current()
            .family_id
            .store(Arc::as_ptr(&shared) as usize, Ordering::Release);
        let membership = Arc::new(AddressSpaceMembership::new(
            shared,
            OwnedRanges::default(),
            owned,
        ));
        *slot = Some(membership.clone());
        membership
    }

    fn preserve_address_space_range(&self, range: Range<usize>) {
        let membership = self
            .membership()
            .expect("preserving a range before fork join");
        membership
            .preserved_stack_ranges
            .lock()
            .insert_bounded(range, MAX_PRESERVED_STACK_RANGES);
    }

    /// This process's membership, if its memory is shared with another guest process.
    fn membership(&self) -> Option<Arc<AddressSpaceMembership<Platform>>> {
        self.process().address_space.lock().clone()
    }

    fn preserved_address_space_ranges(&self) -> OwnedRanges {
        let membership = self.membership().expect("copying ranges before fork join");
        membership.preserved_stack_ranges.lock().clone()
    }

    /// Copies this process's memory out and passes the address space directly to the child
    /// process `pid` (thread table `inner`).
    ///
    /// # Panics
    ///
    /// Panics if this process is not currently a member holding the token; `fork` is the only
    /// caller and it has just made sure of both.
    fn park_and_hand_off(
        &self,
        sp: usize,
        pid: i32,
        inner: &Arc<Mutex<Platform, ProcessInner<Platform>>>,
    ) {
        let membership = self.membership().expect("forking outside an address space");
        assert!(membership.holding());
        let saved = {
            let preserved = membership.preserved_stack_ranges.lock();
            let shared_ranges = membership.shared_ranges.lock();
            self.save_address_space(sp, &preserved, &shared_ranges)
        };
        // Linux `dup_mmap`: `MADV_WIPEONFORK` ranges are zero-filled in the child. The parent's
        // copy has just been saved, so wiping the live pages now (before the child runs on them)
        // is exactly what the child sees and nothing the parent cannot restore. Wipes are
        // clamped to this process's own ranges: the manager's entries may cover a neighbour.
        let owned = self.process().owned_ranges.lock();
        let wiped = unsafe {
            self.global
                .pm
                .wipe_on_fork_child(|r, _| owned.intersect(&r).collect::<Vec<_>>())
        };
        drop(owned);
        if wiped != 0 {
            litebox_util_log::debug!(pid:? = self.pid, tid:? = pid, wiped; "fork: wiped MADV_WIPEONFORK ranges for the child");
        }
        *membership.parked.lock() = Some(saved);
        membership.holding.store(false, Ordering::Release);
        membership.shared.hand_off_to(pid, inner);
    }

    /// Gives the address space up for as long as this task is blocked, so that another member can
    /// run on it. Paired with [`Task::acquire_address_space`].
    ///
    /// Does nothing if this process is not sharing an address space, or is already parked. If it
    /// is the *only* remaining member, membership is dropped instead of parked: nobody can take
    /// the token, so copying memory out and back would be pure cost. (A new member can only
    /// appear via `fork`, which requires holding the token, so no member can turn up while this
    /// runs.)
    ///
    /// A single-threaded member parks eagerly, every time it blocks: it has nothing else to run,
    /// and a shell's forked child must be able to run the moment the shell waits on it. A
    /// multithreaded member parks only when another member is actually waiting -- a sibling
    /// thread may well have work to do, and a hand-off means quiescing all of them -- see
    /// [`Task::quiesce_and_hand_off`].
    pub(crate) fn release_address_space(&self) {
        let Some(membership) = self.membership() else {
            return;
        };
        if !membership.holding() {
            return;
        }
        // `strong_count == 1` ("nobody else is left in this family") is only a safe signal to
        // tear the membership down outright for a single-threaded member: it is about to park
        // anyway (below), so there is nothing else useful the fact could gate. For a
        // multithreaded member -- a fork server / zygote is exactly this shape -- it is not:
        // the most recently forked child dying does not mean THIS process will not fork again
        // shortly, and destroying the family here just forces the next fork's `join_address_space`
        // to build a brand-new one from scratch instead of reusing this one. Diagnosed live
        // 2026-09-07 (musl-fork-atfork-parent-corruption-20260905): a Chromium zygote observed
        // creating 23 independent, disjoint `SharedAddressSpace` families in a single ~7 s run
        // this way, immediately before/around guest-level `struct pthread` corruption in forked
        // children (see memory litebox-chromium-zygote-fork-corruption.md). The multithreaded
        // branch below already no-ops correctly when genuinely alone (`waiters()` is 0 with
        // nobody left to wait), so skipping this shortcut there costs nothing but leaving an
        // otherwise-idle membership allocated a little longer, until `leave_address_space`
        // (execve or last-thread-exit) retires it for real.
        if self.process().nr_threads() > 1 {
            if membership.shared.waiters() > 0
                && membership.quantum_elapsed(self.global.platform.now())
            {
                self.quiesce_and_hand_off(&membership);
            }
            return;
        }
        if Arc::strong_count(&membership.shared) == 1 {
            *self.process().address_space.lock() = None;
            // DIAGNOSTIC (musl-fork-struct-pthread-corruption, temporary, additive-only): see
            // `VmBookkeeping::family_id`.
            self.process()
                .vm
                .current()
                .family_id
                .store(0, Ordering::Release);
            return;
        }
        let saved = {
            let preserved = membership.preserved_stack_ranges.lock();
            let shared_ranges = membership.shared_ranges.lock();
            self.save_address_space(self.guest_sp.get(), &preserved, &shared_ranges)
        };
        *membership.parked.lock() = Some(saved);
        membership.holding.store(false, Ordering::Release);
        membership.shared.release();
    }

    /// Hands the address space to a waiting member and takes it back, on behalf of this whole
    /// multithreaded process. Called at every safe point -- before blocking, when kicked out of
    /// a wait, and before re-entering guest code -- once a waiter exists.
    ///
    /// A single-threaded member does not go through here: it yields when it blocks, and only
    /// then (no preemption), which is the behaviour every shell-shaped guest was built against.
    pub(crate) fn yield_address_space_to_waiters(&self) {
        let Some(membership) = self.membership() else {
            return;
        };
        if !membership.holding() || membership.shared.waiters() == 0 || self.is_exiting() {
            return;
        }
        if self.process().nr_threads() <= 1 {
            return;
        }
        if !membership.quantum_elapsed(self.global.platform.now()) {
            return;
        }
        self.quiesce_and_hand_off(&membership);
    }

    /// The multithreaded hand-off. The first thread here becomes the initiator: it closes the
    /// fork gate so every sibling parks at its next safe point (blocked siblings are kicked
    /// there; one mid-copy into guest memory finishes first), copies the process's shared image
    /// out, releases the token, waits for it to come back, restores the image and reopens the
    /// gate. Any later thread just parks at that gate like a sibling. Nothing but the initiator
    /// touches guest memory between the copy out and the copy back.
    fn quiesce_and_hand_off(&self, membership: &Arc<AddressSpaceMembership<Platform>>) {
        if membership
            .quiescing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.park_while_fork_gate_closed();
            return;
        }
        let started = self.global.platform.now();
        let guard = self.park_sibling_threads_for_fork();
        let quiesced = self.global.platform.now();
        // Re-checked with every sibling parked: the token may have changed hands while this
        // thread was closing the gate (a sibling won the race in `acquire_address_space`).
        if membership.holding() && membership.shared.waiters() > 0 {
            let saved = {
                let preserved = membership.preserved_stack_ranges.lock();
                let shared_ranges = membership.shared_ranges.lock();
                self.save_address_space(self.guest_sp.get(), &preserved, &shared_ranges)
            };
            *membership.parked.lock() = Some(saved);
            membership.holding.store(false, Ordering::Release);
            membership.shared.release();
            membership.shared.wait_until_taken(|| self.is_exiting());
            let released = self.global.platform.now();
            let got = membership.shared.acquire(
                self.pid,
                || membership.holding(),
                || self.is_exiting(),
                &self.process().inner,
            );
            let back = self.global.platform.now();
            if got && !membership.holding() {
                if let Some(saved) = membership.parked.lock().take() {
                    self.restore_address_space(saved);
                }
                membership.holding.store(true, Ordering::Release);
            }
            if got {
                membership.mark_acquired(self.global.platform.now());
            }
            litebox_util_log::debug!(
                pid:? = self.pid, tid:? = self.tid,
                quiesce_us:? = quiesced.duration_since(&started).as_micros(),
                save_us:? = released.duration_since(&quiesced).as_micros(),
                away_us:? = back.duration_since(&released).as_micros(),
                got;
                "address space: multithreaded hand-off complete"
            );
        }
        membership.quiescing.store(false, Ordering::Release);
        drop(guard);
    }

    /// Takes the address space back and restores this process's memory into it, blocking until
    /// the current holder gives it up.
    ///
    /// Does nothing if this process is not sharing an address space, or already holds it. Returns
    /// whether this process's own memory image is live when the call completes.
    pub(crate) fn acquire_address_space(&self) -> bool {
        let Some(membership) = self.membership() else {
            return true;
        };
        if membership.holding() {
            return true;
        }
        if !membership.shared.acquire(
            self.pid,
            || membership.holding(),
            || self.is_exiting(),
            &self.process().inner,
        ) {
            // Preserve the non-holding membership until exit cleanup. Dropping it here would make
            // `prepare_for_exit` mistake whichever sibling's image is live for this task's own and
            // dereference stale robust-list/child-TID pointers into that sibling.
            return false;
        }
        if !membership.holding() {
            if let Some(saved) = membership.parked.lock().take() {
                self.restore_address_space(saved);
            }
            membership.holding.store(true, Ordering::Release);
            membership.mark_acquired(self.global.platform.now());
        }
        true
    }

    /// Leaves the shared address space for good, waking anything waiting for it.
    ///
    /// Returns `true` if, afterwards, this process's guest memory is its alone -- either it was
    /// never shared, or this was the last member -- and so is safe to tear down. Called from
    /// `execve`, whose new image lives at addresses no other member owns, and from the exit of
    /// a process's last thread.
    fn leave_address_space(&self) -> bool {
        let Some(membership) = self.process().address_space.lock().take() else {
            return true;
        };
        // DIAGNOSTIC (musl-fork-struct-pthread-corruption, temporary, additive-only): see
        // `VmBookkeeping::family_id`. This process is leaving its family for good either way.
        self.process()
            .vm
            .current()
            .family_id
            .store(0, Ordering::Release);
        if membership.holding() {
            membership.shared.release();
        }
        // The only other strong reference is this one, so no other member is left to care about
        // the memory. A member can only be created by `fork`, which needs the token, and this
        // task held it until the line above.
        Arc::strong_count(&membership.shared) == 1
    }

    /// Whether this process's guest memory is shared with another guest process.
    fn shares_address_space(&self) -> bool {
        self.process().address_space.lock().is_some()
    }

    /// Passes this vfork child's [`AddressSpaceMembership`] -- token, parked image and all -- to
    /// the parent whose memory it has been running on, which
    /// [`Task::inherit_address_space_from_vfork_child`] installs once the vfork completes.
    ///
    /// The family was created by a `fork` this child issued on the parent's memory (see
    /// `do_process_clone`), so its other members' images alias the *parent's* mappings; the
    /// parent has to keep taking turns with them, exactly as it would had it forked itself. A
    /// membership is only ever handed over before [`Process::complete_vfork`] wakes the parent.
    /// Dropped nothing: a child that never forked has no membership to pass.
    fn hand_address_space_to_vfork_parent(&self) {
        let Some(membership) = self.process().address_space.lock().take() else {
            return;
        };
        match self.process().vfork_completion.lock().as_ref() {
            Some(completion) => *completion.inherited_membership.lock() = Some(membership),
            // The vfork already completed (an exec'd child exiting), so this membership is the
            // child's own and leaves the family the ordinary way.
            None => {
                if membership.holding() {
                    membership.shared.release();
                }
            }
        }
    }

    /// Takes over the family a vfork child forked into while on this task's memory, and returns
    /// whether this task's own image is live afterwards.
    ///
    /// The child may have died parked (killed while waiting for the token), in which case the
    /// token is taken and the child's last image put back before this task runs another guest
    /// instruction on it.
    fn inherit_address_space_from_vfork_child(
        &self,
        completion: &VforkCompletion<Platform>,
    ) -> bool {
        let Some(membership) = completion.inherited_membership.lock().take() else {
            return false;
        };
        debug_assert!(
            self.process().address_space.lock().is_none(),
            "vfork parent was refused a family of its own (see do_process_clone)"
        );
        // The membership now belongs to this process; its threads are the ones to kick.
        if membership.holding() {
            membership
                .shared
                .hand_off_to(self.pid, &self.process().inner);
        }
        // DIAGNOSTIC (musl-fork-struct-pthread-corruption, temporary, additive-only): see
        // `VmBookkeeping::family_id`.
        self.process()
            .vm
            .current()
            .family_id
            .store(Arc::as_ptr(&membership.shared) as usize, Ordering::Release);
        *self.process().address_space.lock() = Some(membership);
        self.acquire_address_space()
    }

    /// Leaves the shared address space if this task is its only remaining member, and reports
    /// whether this task's guest memory is now unshared.
    ///
    /// `execve` uses this to decide whether the old mappings are its to tear down. A sole member
    /// still holds the token, so no new member can appear while this runs.
    /// Releases every mapping this process owns, at process exit, with the same
    /// intersection discipline `execve` uses when it discards an old image: only
    /// `owned_ranges ∩ mapping`, never a whole coalesced page-manager entry that
    /// merely overlaps (an adjacent sibling's memory shares entries with ours),
    /// reserved mappings (empty `VmFlags`) untouched, and a live `/dev/fb0`
    /// guest mapping deregistered before its pages go away. Callers must have
    /// established that no other guest process can be using these bytes.
    /// Releases, at the exit of a process that is still sharing an address space with others,
    /// only the ranges no other member can own: `owned_ranges` minus the ranges shared with the
    /// family (see [`AddressSpaceMembership::shared_ranges`]). Same intersection discipline as
    /// [`Self::release_owned_memory_on_exit`].
    fn release_private_memory_on_exit(&self, shared_ranges: &OwnedRanges) {
        let mut owned = self.process().owned_ranges.lock();
        let private = owned.difference(shared_ranges);
        if private.ranges.is_empty() {
            return;
        }
        litebox_util_log::debug!(
            pid:? = self.pid, count:? = private.ranges.len();
            "exit: releasing the process's private mappings, shared ones stay with the family"
        );
        if let Some(fb) = self.global.framebuffer.as_ref()
            && let Some((fb_addr, fb_len)) = fb.guest_mapping()
            && private
                .intersect(&(fb_addr..fb_addr.saturating_add(fb_len)))
                .next()
                .is_some()
        {
            fb.clear_guest_mapping_overlapping(fb_addr, fb_len);
        }
        let release = |r: Range<usize>, vm: VmFlags| {
            if vm.is_empty() {
                Vec::new()
            } else {
                private.intersect(&r).collect::<Vec<_>>()
            }
        };
        // SAFETY: only ranges this process mapped after it joined the family are released --
        // no other member's `owned_ranges` can include them -- and its last thread is exiting.
        if let Err(error) = unsafe { self.global.pm.release_memory(release) } {
            litebox_util_log::error!(error:? = error; "exit: failed to release the process's private mappings");
        }
        let remaining = owned.difference(&private);
        *owned = remaining;
    }

    fn release_owned_memory_on_exit(&self) {
        let owned = self.process().owned_ranges.lock();
        if let Some(fb) = self.global.framebuffer.as_ref()
            && let Some((fb_addr, fb_len)) = fb.guest_mapping()
            && owned
                .intersect(&(fb_addr..fb_addr.saturating_add(fb_len)))
                .next()
                .is_some()
        {
            fb.clear_guest_mapping_overlapping(fb_addr, fb_len);
        }
        let release = |r: Range<usize>, vm: VmFlags| {
            if vm.is_empty() {
                Vec::new()
            } else {
                owned.intersect(&r).collect::<Vec<_>>()
            }
        };
        // SAFETY: the caller established that this process is the sole user of its owned
        // ranges (alone in its address-space family and not vfork-sharing a parent), and its
        // last thread is exiting, so no guest code can touch them again.
        if let Err(error) = unsafe { self.global.pm.release_memory(release) } {
            litebox_util_log::error!(error:? = error; "exit: failed to release the process's mappings");
        }
        drop(owned);
        self.process().owned_ranges.lock().clear();
    }

    fn leave_address_space_if_alone(&self) -> bool {
        let mut slot = self.process().address_space.lock();
        let Some(membership) = slot.as_ref() else {
            return true;
        };
        if Arc::strong_count(&membership.shared) != 1 {
            return false;
        }
        // DIAGNOSTIC (musl-fork-atfork-parent-corruption-20260905, temporary, additive-only):
        // logs every time a plain do_clone (pthread_create) drops this process's
        // AddressSpaceMembership because it observed strong_count==1. See the matching
        // diagnostic in join_address_space: if that one also fires soon after for the SAME pid,
        // the drop-then-recreate pair is the suspected TOCTOU.
        litebox_util_log::debug!(
            pid:? = self.pid, tid:? = self.tid;
            "diag: leave_address_space_if_alone dropping membership (strong_count==1)"
        );
        debug_assert!(membership.holding());
        *slot = None;
        // DIAGNOSTIC (musl-fork-struct-pthread-corruption, temporary, additive-only): see
        // `VmBookkeeping::family_id`.
        self.process()
            .vm
            .current()
            .family_id
            .store(0, Ordering::Release);
        true
    }

    /// Records the guest stack pointer for the current trip through the shim.
    pub(crate) fn record_guest_sp(&self, sp: usize) {
        self.guest_sp.set(sp);
    }

    /// GUARD (litebox-ordinary-syscall-cross-process-clobber): whether `range` currently belongs,
    /// in whole or in part, to a live process outside this one's own family.
    ///
    /// `overlaps_another_process` (used by `save_address_space`/`restore_address_space` above) is
    /// otherwise the *only* place in this codebase that checks "a process may only ever touch its
    /// own memory" before acting -- confirmed live during this investigation: an ordinary guest
    /// `munmap`/`mprotect`/`mmap(MAP_FIXED)` reaches `litebox_common_linux::mm`'s handlers, which
    /// operate directly on the guest-supplied address with no such check, because on real Linux a
    /// process's own address space makes touching another process's memory this way physically
    /// impossible -- an invariant this platform's one flat, shared, permission-mirrored host
    /// address space (`hvf_backend.rs`'s own doc comment) does not itself provide. The *only* thing
    /// that stopped an ordinary mutating call from ever landing on a stranger's memory was `Vmem`'s
    /// own bookkeeping happening to stay perfectly consistent -- true for a placement decision
    /// (already covered elsewhere: `Vmem::reserve_external`), but not a defense against a wrong or
    /// stale *explicit* address a caller already has in hand for any other reason. This is called
    /// from the ordinary-syscall dispatch path in `lib.rs` (not `syscalls/mm.rs`, which stays
    /// unmodified) for exactly the operations that can make another process's memory disappear or
    /// change permissions out from under it: `munmap`, `mprotect`, and a `MAP_FIXED` `mmap`.
    pub(crate) fn touches_another_process(&self, addr: usize, length: usize) -> bool {
        let Some(end) = addr.checked_add(length) else {
            return false;
        };
        let self_family_id = self
            .process()
            .vm
            .current()
            .family_id
            .load(Ordering::Acquire);
        let hits =
            self.global
                .processes
                .overlaps_another_process(self.pid, self_family_id, &(addr..end));
        if !hits.is_empty() {
            // Permanent diagnostic aid, not a temporary probe: firing here is rare (a real
            // cross-process overlap on an ordinary syscall) and worth a permanent record when it
            // does. Confirmed 2026-09-08: across repeated live reproductions of the concurrent
            // multi-`node`-process SIGSEGV this guard was added for, it never fired once, ruling
            // out an ordinary explicit-address `munmap`/`mprotect`/`mmap(MAP_FIXED)` collision as
            // that crash's mechanism -- the guard stays in as a real, independently-justified
            // safety net regardless (see this function's own doc comment), not because it was
            // shown to fix that specific bug.
            litebox_util_log::error!(
                pid:? = self.pid, addr:? = addr, end:? = end, hits:? = hits;
                "diag: touches_another_process fired on an ordinary syscall"
            );
        }
        !hits.is_empty()
    }

    /// Copies this process's view of the memory it shares with other members out into host
    /// memory: the protection of every shared piece, plus the contents of the writable ones.
    ///
    /// This is what makes a shared-address-space `fork` behave like a real one for a guest that
    /// was built for a real one. The child necessarily runs on the parent's memory (see
    /// [`SharedAddressSpace`]), and `vfork(2)`'s contract -- "the child may only `exec` or
    /// `_exit`" -- is one a `fork(2)`-using program has no reason to honour. busybox's shell, for
    /// instance, *returns* out of the function that called `fork`, overwriting the frames its
    /// parent is parked in, and its `forkchild` frees the parent's job list on the shared heap.
    /// But only the token holder ever runs on that memory, so none of that has to be visible to
    /// anyone else: this copies the memory out, and [`Task::restore_address_space`] puts it back
    /// before the task executes another guest instruction. Each member then sees exactly what
    /// `fork(2)` promises -- its own memory, untouched -- while the child saw a faithful copy of
    /// the parent's, because it *was* it.
    ///
    /// Protections are part of the view. An allocator (PartitionAlloc in every Chromium
    /// process) reserves gigabytes `PROT_NONE` and commits pieces with `mprotect` as it goes; a
    /// member that commits and writes into a piece its sibling still has reserved must not leave
    /// the sibling reading its data once the sibling commits the same piece expecting zero pages.
    /// So every shared piece is recorded with its protection, and the restore re-establishes it
    /// (see [`SavedRange`]).
    ///
    /// Deliberate limits on what is saved:
    ///
    /// * Only ranges this process owns *and* has shared with another member (see
    ///   [`AddressSpaceMembership::shared_ranges`]), so that a sibling guest process running
    ///   concurrently at other addresses is never rolled back, and memory a member mapped for
    ///   itself after the fork is never copied.
    /// * Of the mapping holding the stack pointer, only the ABI-live suffix is copied: `[sp, end)`
    ///   on AArch64 and the 128-byte red zone plus that suffix on x86-64. Explicit kernel ABI
    ///   pointers below that boundary, such as clone child-TID words, are copied separately through
    ///   `preserved_stack_ranges`; this avoids copying the whole 8 MiB stack on every handoff.
    /// * Read-only pieces (the image's text and rodata) carry no contents: nothing correct writes
    ///   to them, and they are the bulk of the image.
    fn save_address_space(
        &self,
        sp: usize,
        preserved_stack_ranges: &OwnedRanges,
        shared_ranges: &OwnedRanges,
    ) -> MemoryImage {
        let started = self.global.platform.now();
        // Cloned, not held: the diagnostic `overlaps_another_process` call inside `save` below
        // (musl-fork-struct-pthread-corruption, temporary, additive-only) locks OTHER processes'
        // `owned_ranges` while running, and this process is quiesced for the whole duration of a
        // hand-off (see `Task::quiesce_and_hand_off`/the single-threaded caller in
        // `release_address_space`), so nothing mutates `owned_ranges` underneath a snapshot here
        // -- but holding this process's OWN lock while acquiring another's would be a lock-order
        // inversion against a concurrent, unrelated process doing the same in the other
        // direction (deadlock, live-reproduced during this investigation).
        let owned = self.process().owned_ranges.lock().clone();
        // DIAGNOSTIC (musl-fork-struct-pthread-corruption, temporary, additive-only): see
        // `VmBookkeeping::family_id`.
        let self_family_id = self
            .process()
            .vm
            .current()
            .family_id
            .load(Ordering::Acquire);
        let mut saved = Vec::new();
        let mut save = |start: usize, end: usize, flags: VmFlags, with_bytes: bool| {
            if start >= end {
                return;
            }
            // DIAGNOSTIC (musl-fork-struct-pthread-corruption, temporary, additive-only): see
            // `ProcessTable::overlaps_another_process`. This range is believed to be exclusively
            // this process's own (per `owned_ranges`); if it also belongs to another live
            // process OUTSIDE this process's own family right now, saving it is reading memory
            // this process does not own.
            let cross = self.global.processes.overlaps_another_process(
                self.pid,
                self_family_id,
                &(start..end),
            );
            if !cross.is_empty() {
                litebox_util_log::error!(
                    pid:? = self.pid, tid:? = self.tid, self_family_id:? = self_family_id,
                    start:? = start, end:? = end, cross:? = cross;
                    "diag: CROSS-LINEAGE OVERLAP -- save_address_space range also owned by another live process"
                );
            }
            let bytes = if with_bytes {
                if let Some(bytes) =
                    UserPtr::<u8>::from_usize(start).to_owned_slice::<Platform>(end - start)
                {
                    Some(bytes)
                } else {
                    // Only reachable if a mapping this process owns is no longer readable, which no
                    // correct program arranges. Loud, because the consequence is that this task's
                    // own writes to that range are silently lost the next time another member runs.
                    litebox_util_log::error!(
                        pid:? = self.pid, start:? = start, end:? = end;
                        "could not copy a mapping out before giving up the address space; this \
                         process's data in it will be whatever the next process to run leaves there"
                    );
                    return;
                }
            } else {
                None
            };
            saved.push(SavedRange {
                start,
                end,
                flags: access_bits(flags),
                bytes,
            });
        };
        #[cfg(target_arch = "x86_64")]
        let live_stack_start = sp.saturating_sub(128);
        #[cfg(target_arch = "aarch64")]
        let live_stack_start = sp;

        // The stack-suffix shortcut is only sound when this thread's stack is the only live one
        // in its mapping: musl thread stacks are separate mmaps that the page manager coalesces
        // with their neighbours, so in a multithreaded process the mapping holding `sp` may also
        // hold sibling threads' stacks and TCBs, below `sp`. Save it whole then.
        let suffix_only = self.process().nr_threads() <= 1;
        for (range, flags) in self.global.pm.mappings() {
            if flags.contains(VmFlags::VM_SHARED) {
                continue;
            }
            let writable = flags.contains(VmFlags::VM_WRITE);
            let stack = suffix_only && range.start < sp && sp <= range.end;
            for owned_part in owned.intersect(&range) {
                // Only what another member may also own (see
                // `AddressSpaceMembership::shared_ranges`); the rest is this process's alone.
                for part in shared_ranges.intersect(&owned_part) {
                    if !writable {
                        save(part.start, part.end, flags, false);
                        continue;
                    }
                    let start = if stack {
                        part.start.max(live_stack_start)
                    } else {
                        part.start
                    };
                    save(start, part.end, flags, true);
                    if stack {
                        for extra in preserved_stack_ranges.intersect(&part) {
                            // The main suffix already includes anything at or above `start`.
                            save(extra.start, extra.end.min(start), flags, true);
                        }
                    }
                }
            }
        }
        let bytes: usize = saved
            .iter()
            .map(|p| p.bytes.as_ref().map_or(0, |b| b.len()))
            .sum();
        let elapsed = self.global.platform.now().duration_since(&started);
        litebox_util_log::debug!(
            pid:? = self.pid, tid:? = self.tid, pieces:? = saved.len(), bytes,
            elapsed_us:? = elapsed.as_micros();
            "address space: saved this process's view"
        );
        // GUARD (litebox-fork-family-allocator-reuse): this process's addresses are about to
        // vanish from `vmas` (a sibling keeps running, and may `execve`, tearing down and
        // rebuilding the very ranges this snapshot remembers -- `leave_address_space`'s own
        // doc comment assumes "the new image lives at addresses no other member owns," which
        // nothing previously enforced). Reserve every saved range so a fresh, flexible placement
        // is steered elsewhere for as long as this snapshot is outstanding; released by
        // `restore_address_space` below.
        for piece in &saved {
            self.global.pm.reserve_external(piece.start..piece.end);
        }
        saved
    }

    /// Puts back what [`Task::save_address_space`] took, undoing everything another member did
    /// to this process's view of the shared memory: protections first (a piece another member
    /// committed while this process had it reserved is dropped back to zero pages and
    /// `PROT_NONE`; one it decommitted is made writable again), then contents.
    fn restore_address_space(&self, saved: MemoryImage) {
        use litebox_common_linux::{MadviseBehavior, MapFlags, ProtFlags};
        // GUARD (litebox-fork-family-allocator-reuse): releases what `save_address_space`
        // reserved. From here on this snapshot is being actively replayed back (or, per the
        // existing cross-family guard below, refused piece by piece) rather than merely
        // remembered, so a fresh placement colliding with it is once again this process's own
        // problem to detect the ordinary way, not something the allocator needs to steer around.
        for piece in &saved {
            self.global.pm.release_external(piece.start..piece.end);
        }
        let started = self.global.platform.now();
        // DIAGNOSTIC (musl-fork-struct-pthread-corruption, temporary, additive-only): see
        // `VmBookkeeping::family_id`.
        let self_family_id = self
            .process()
            .vm
            .current()
            .family_id
            .load(Ordering::Acquire);
        let (
            mut pieces,
            mut bytes_copied,
            mut protects,
            mut drops,
            mut remaps,
            mut protected_from_clobber,
        ) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        for piece in saved {
            pieces += 1;
            // GUARD (litebox-restore-stale-mappings-snapshot): re-queried per piece, not once for
            // the whole restore. A single up-front snapshot went stale the moment any earlier
            // piece in this same loop actually mutated the address space below
            // (`sys_mmap`/`sys_mprotect`/`sys_madvise`/`copy_from_slice`) -- and adjacent pieces
            // from the very same original mapping are routine, not an edge case: the stack-suffix
            // split above (`save_address_space`'s `preserved_stack_ranges.intersect`) deliberately
            // emits two directly-touching `SavedRange`s from one VMA. A later piece reconciling
            // against a stale "what's mapped right now" view can misjudge a range an earlier piece
            // just re-created or re-protected -- e.g. treating a gap the earlier piece already
            // filled as still needing a fresh `MAP_FIXED` remap, which zero-fills over content that
            // piece just wrote. Live-observed downstream symptom: a translation fault reading a
            // musl heap chunk header 4 bytes before an otherwise-valid pointer, on a page with no
            // mapping at all, matching exactly what a wrongly-re-mapped-over-real-content gap would
            // produce for a neighboring allocation.
            let mappings = self.global.pm.mappings();
            let SavedRange {
                start,
                end,
                flags: wanted,
                bytes,
            } = piece;
            // GUARD (musl-fork-struct-pthread-corruption): confirmed live during this
            // investigation -- `Task::restore_address_space` had no check that a saved piece's
            // addresses still belong to this process's own family before touching them. When a
            // piece is currently mapped but read-only (this process remembers it writable), the
            // code just below would `mprotect` it to PROT_READ|PROT_WRITE and then blindly
            // `copy_from_slice` this process's stale saved bytes into it; when a piece is
            // currently unmapped, the code just below would `MAP_FIXED`-remap it. Neither check
            // considered WHO else might legitimately, currently own that address: this platform
            // has no per-process hardware isolation (`hvf_backend.rs`'s own doc comment -- one
            // flat, permission-mirrored host address space, guest VA == host VA), so a family's
            // remembered range that has since been reused by a completely unrelated, live guest
            // process (e.g. its own fresh `execve`'s interpreter landing at the same top-down
            // "highest free slot" while this family's member was parked) is real, currently-live
            // memory belonging to someone else. Live-reproduced: a Chromium browser-process
            // thread's restore repeatedly `mprotect`+overwrote a 16 KiB slice of an unrelated,
            // concurrently-running process's just-loaded `ld-musl-aarch64.so.1` mapping this way,
            // immediately preceding a real guest SIGSEGV inside musl. `overlaps_another_process`
            // (added this investigation) is the one place in this codebase that checks the
            // invariant "a process may only ever touch its own memory" before acting -- refusing
            // this piece entirely (not just the offending sub-range) trades this process's own,
            // now on its own head, incomplete restore for never writing into a byte that belongs
            // to someone else: the same "honest, contained failure beats silent cross-process
            // corruption" preference this whole platform is built on elsewhere.
            let cross = self.global.processes.overlaps_another_process(
                self.pid,
                self_family_id,
                &(start..end),
            );
            if !cross.is_empty() {
                protected_from_clobber += 1;
                litebox_util_log::error!(
                    pid:? = self.pid, tid:? = self.tid, self_family_id:? = self_family_id,
                    start:? = start, end:? = end, cross:? = cross, has_bytes:? = bytes.is_some();
                    "restore_address_space: range now owned by another live process outside this \
                     family -- refusing to touch it (would silently corrupt that process's live \
                     memory); this process's own restore for this piece is incomplete"
                );
                continue;
            }
            // What is at these addresses right now, piece by piece; a gap means another member
            // unmapped it.
            let mut cursor = start;
            let mut current: Vec<(Range<usize>, VmFlags)> = Vec::new();
            for (range, flags) in &mappings {
                if range.end <= start || range.start >= end {
                    continue;
                }
                let lo = range.start.max(start);
                let hi = range.end.min(end);
                if cursor < lo {
                    current.push((cursor..lo, VmFlags::empty()));
                }
                current.push((lo..hi, *flags));
                cursor = hi;
            }
            if cursor < end {
                current.push((cursor..end, VmFlags::empty()));
            }
            for (range, flags) in current {
                let mapped = !flags.is_empty() || {
                    // `mappings()` reports reserved (empty-flag) entries too; a truly unmapped
                    // gap is what `VmFlags::empty()` with no entry means here.
                    mappings
                        .iter()
                        .any(|(m, _)| m.start <= range.start && range.end <= m.end)
                };
                let prot_now = access_bits(flags);
                if !mapped {
                    // Re-create the mapping another member removed, with this process's
                    // protection; contents (if any) follow below.
                    let initial = if bytes.is_some() {
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
                    } else {
                        prot_of(wanted)
                    };
                    remaps += 1;
                    if let Err(error) = self.sys_mmap(
                        range.start,
                        range.end - range.start,
                        initial,
                        MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                        -1,
                        0,
                    ) {
                        litebox_util_log::error!(
                            pid:? = self.pid, start:? = range.start, end:? = range.end, error:?;
                            "failed to re-map a range another member unmapped"
                        );
                    }
                } else if bytes.is_some() {
                    if !flags.contains(VmFlags::VM_WRITE) {
                        protects += 1;
                    }
                    if !flags.contains(VmFlags::VM_WRITE)
                        && let Err(error) = self.sys_mprotect(
                            UserPtrMut::from_usize(range.start),
                            range.end - range.start,
                            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                        )
                    {
                        litebox_util_log::error!(
                            pid:? = self.pid, start:? = range.start, end:? = range.end, error:?;
                            "failed to make a range writable when taking the address space back"
                        );
                    }
                } else if prot_now != wanted {
                    protects += 1;
                    if !wanted.contains(VmFlags::VM_READ) {
                        // Reserved in this process's view, committed and written by another
                        // member: what Linux hands out on a later commit is zero pages.
                        drops += 1;
                        if let Err(error) = self.sys_madvise(
                            UserPtrMut::from_usize(range.start),
                            range.end - range.start,
                            MadviseBehavior::DontNeed,
                        ) {
                            litebox_util_log::error!(
                                pid:? = self.pid, start:? = range.start, end:? = range.end, error:?;
                                "failed to drop another member's pages from a reserved range"
                            );
                        }
                    }
                    if let Err(error) = self.sys_mprotect(
                        UserPtrMut::from_usize(range.start),
                        range.end - range.start,
                        prot_of(wanted),
                    ) {
                        litebox_util_log::error!(
                            pid:? = self.pid, start:? = range.start, end:? = range.end, error:?;
                            "failed to put a range's protection back when taking the address space back"
                        );
                    }
                }
            }
            if let Some(bytes) = bytes {
                bytes_copied += bytes.len();
                if UserPtrMut::<u8>::from_usize(start)
                    .copy_from_slice::<Platform>(0, &bytes)
                    .is_none()
                {
                    let pm_view = self
                        .global
                        .pm
                        .mappings()
                        .into_iter()
                        .find(|(range, _)| range.contains(&start))
                        .map(|(range, flags)| (range.start, range.end, flags));
                    litebox_util_log::error!(
                        pid:? = self.pid, start:? = start, len:? = bytes.len(), pm_view:? = pm_view;
                        "failed to restore a mapping when taking the address space back"
                    );
                    continue;
                }
                let prot = prot_of(wanted);
                if prot != (ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
                    && let Err(error) =
                        self.sys_mprotect(UserPtrMut::from_usize(start), end - start, prot)
                {
                    litebox_util_log::error!(
                        pid:? = self.pid, start:? = start, end:? = end, error:?;
                        "failed to put a restored range's protection back"
                    );
                }
            }
        }
        let elapsed = self.global.platform.now().duration_since(&started);
        litebox_util_log::debug!(
            pid:? = self.pid, tid:? = self.tid, pieces, bytes_copied, protects, drops, remaps,
            protected_from_clobber, elapsed_us:? = elapsed.as_micros();
            "address space: restored this process's view"
        );
    }

    /// Publishes this process in the shim's live-process set so other processes can post signals
    /// to it. Idempotent: re-registering simply replaces the entry with an identical one.
    ///
    /// Done at `fork` rather than at task construction because that is the first moment a process
    /// can acquire a child, and a process with no children has nothing to receive.
    pub(crate) fn register_for_remote_signals(&self) {
        self.global.processes.register_process(
            self.pid,
            self.remote_signal_target(),
            self.process(),
        );
    }

    /// Handle syscall `wait4`.
    pub(crate) fn sys_wait4(
        &self,
        pid: i32,
        wstatus: Option<UserPtrMut<i32>>,
        options: i32,
        rusage: usize,
    ) -> Result<i32, Errno> {
        /// `WNOHANG`: return immediately if no child has exited.
        const WNOHANG: u32 = 0x1;
        /// `WUNTRACED`/`WCONTINUED`: accepted and then never acted on, because this shim has no
        /// way to stop or continue a process in the first place, so a wait for either event
        /// simply never has one to report.
        const WUNTRACED: u32 = 0x2;
        const WCONTINUED: u32 = 0x8;
        /// `__WNOTHREAD`/`__WALL`/`__WCLONE`: which *kinds* of child to consider. Every child
        /// here is an ordinary one belonging to the caller alone, so all three are no-ops.
        const WNOTHREAD: u32 = 0x2000_0000;
        const WALL: u32 = 0x4000_0000;
        const WCLONE: u32 = 0x8000_0000;
        /// Deliberately absent: `WNOWAIT` (leave the child reapable), which this cannot honour
        /// -- the reap below is destructive -- and `WEXITED`/`WSTOPPED`, which are `waitid`'s,
        /// not `wait4`'s.
        const SUPPORTED: u32 = WNOHANG | WUNTRACED | WCONTINUED | WNOTHREAD | WALL | WCLONE;

        let options = options.cast_unsigned();
        if options & !SUPPORTED != 0 {
            log_unsupported!("wait4 with options {options:#x}");
            return Err(Errno::EINVAL);
        }
        let rusage =
            (rusage != 0).then(|| UserPtrMut::<litebox_common_linux::Rusage>::from_usize(rusage));

        let filter = if pid > 0 {
            WaitFilter::Pid(pid)
        } else {
            // `-1` means any child. Linux applies process-group filters for `0` and `< -1`; that
            // filtering is not implemented yet, so both currently use the same any-child path.
            WaitFilter::Any
        };
        let table = &self.global.processes;

        // Registered before the first check so that a child exiting in the gap between the check
        // and the block cannot be missed.
        let token = table.register_waiter(self.pid, self.wait_cx().waker().clone());
        let _unregister = litebox::utils::defer(|| table.unregister_waiter(token));

        loop {
            if let Some((pid, status, cpu_time_nanos)) = table.reap(self.pid, filter) {
                if let Some(wstatus) = wstatus {
                    wstatus
                        .write_at_offset::<Platform>(0, encode_wait_status(status))
                        .ok_or(Errno::EFAULT)?;
                }
                if let Some(rusage) = rusage {
                    // `ru_utime` is the one field real scripts actually consume (`busybox time`
                    // among them) and the one this shim can measure honestly: real, host-metered
                    // CPU time summed across every thread the child ever ran (see
                    // `Process::cpu_time_nanos`). `ru_stime` is left at zero rather than
                    // fabricated -- guest syscalls run as ordinary host user-mode Rust, so this
                    // shim has no meaningful "kernel time" of its own to attribute, and reporting
                    // a fake nonzero value would be worse than reporting none. Every other field
                    // (`ru_maxrss` etc.) is zeroed for the same reason. This is still a strict
                    // improvement over leaving the caller's buffer untouched: reading uninitialized
                    // guest memory back as a `struct rusage` is both a correctness bug (nonsensical
                    // output, as seen from `busybox time`) and an information disclosure.
                    let value = litebox_common_linux::Rusage {
                        ru_utime: core::time::Duration::from_nanos(cpu_time_nanos).into(),
                        ..Default::default()
                    };
                    rusage
                        .write_at_offset::<Platform>(0, value)
                        .ok_or(Errno::EFAULT)?;
                }
                return Ok(pid);
            }
            if !table.has_child(self.pid, filter) {
                return Err(Errno::ECHILD);
            }
            if options & WNOHANG != 0 {
                return Ok(0);
            }
            self.wait_cx()
                .wait_until(|| table.reap_ready(self.pid, filter))
                .map_err(|_| Errno::EINTR)?;
        }
    }

    /// Records `range` as mapped by this process. See [`Process::owned_ranges`].
    pub(crate) fn record_mapped(&self, start: usize, len: usize) {
        if len != 0 {
            self.process()
                .owned_ranges
                .lock()
                .insert(start..start.saturating_add(len));
        }
    }

    /// Records `range` as no longer mapped by this process.
    pub(crate) fn record_unmapped(&self, start: usize, len: usize) {
        if len != 0 {
            self.process()
                .owned_ranges
                .lock()
                .remove(start..start.saturating_add(len));
        }
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
//
// The soft (`cur`) default is deliberately much lower than the hard ceiling, matching real Linux
// distros (e.g. systemd's `DefaultLimitNOFILE=1024:524288`-style split): a process that wants
// more can still raise it via `setrlimit`/`prlimit` up to `RLIMIT_NOFILE_MAX`. This split isn't
// just convention -- it's load-bearing here. Startup code across many real daemons (observed
// live via `dbus-daemon`, whose `bus/main.c` closes every fd up to the reported soft
// `RLIMIT_NOFILE` with one `fcntl(fd, F_GETFD)` syscall per candidate fd) scales the length of
// that loop directly off this value. With a 1,048,576 soft default that trace showed the guest
// still counting up through fd 298000+ after 6 real seconds, so dbus-daemon never became ready
// within any reasonable readiness-probe window; a low soft default keeps that a sub-millisecond,
// unnoticeable loop, exactly as it is on a real Linux host.
pub(crate) const RLIMIT_NOFILE_SOFT_DEFAULT: usize = 1024;
pub(crate) const RLIMIT_NOFILE_MAX: usize = 1024 * 1024;

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

/// `RLIMIT_NPROC` and `RLIMIT_SIGPENDING` default. Linux fills both in at boot from
/// `max_threads / 2`, which lands around here on an ordinary machine; neither is enforced.
const RLIMIT_NPROC_DEFAULT: usize = 16384;
/// `RLIMIT_MEMLOCK` default: Linux's `MLOCK_LIMIT`, 8 MiB.
const RLIMIT_MEMLOCK_DEFAULT: usize = 8 * 1024 * 1024;
/// `RLIMIT_MSGQUEUE` default: Linux's `MQ_BYTES_MAX`.
const RLIMIT_MSGQUEUE_DEFAULT: usize = 819_200;
const RLIM_INFINITY: usize = litebox_common_linux::rlim_t::MAX;

impl ResourceLimits {
    /// Linux's `INIT_RLIMITS`, plus the boot-time `NPROC`/`SIGPENDING` fill-in. Every resource
    /// is stored and reported; only `NOFILE` (descriptor table) and `SIGPENDING` (signal queue)
    /// are actually charged anywhere.
    const fn default() -> Self {
        use litebox_common_linux::RlimitResource as R;
        seq_macro::seq!(N in 0..16 {
            let mut limits = [
                #(
                    AtomicRlimit::new(RLIM_INFINITY, RLIM_INFINITY),
                )*
            ];
        });
        limits[R::STACK as usize] =
            AtomicRlimit::new(crate::loader::DEFAULT_STACK_SIZE, RLIM_INFINITY);
        limits[R::CORE as usize] = AtomicRlimit::new(0, RLIM_INFINITY);
        limits[R::NPROC as usize] = AtomicRlimit::new(RLIMIT_NPROC_DEFAULT, RLIMIT_NPROC_DEFAULT);
        limits[R::NOFILE as usize] =
            AtomicRlimit::new(RLIMIT_NOFILE_SOFT_DEFAULT, RLIMIT_NOFILE_MAX);
        limits[R::MEMLOCK as usize] =
            AtomicRlimit::new(RLIMIT_MEMLOCK_DEFAULT, RLIMIT_MEMLOCK_DEFAULT);
        limits[R::SIGPENDING as usize] =
            AtomicRlimit::new(RLIMIT_NPROC_DEFAULT, RLIMIT_NPROC_DEFAULT);
        limits[R::MSGQUEUE as usize] =
            AtomicRlimit::new(RLIMIT_MSGQUEUE_DEFAULT, RLIMIT_MSGQUEUE_DEFAULT);
        limits[R::NICE as usize] = AtomicRlimit::new(0, 0);
        limits[R::RTPRIO as usize] = AtomicRlimit::new(0, 0);
        Self { limits }
    }

    /// Copies every limit from `parent`: `fork` inherits them, and a shell's `ulimit` is only
    /// ever observed by the children it then spawns.
    fn inherit_from(&self, parent: &Self) {
        for (mine, theirs) in self.limits.iter().zip(&parent.limits) {
            mine.cur
                .store(theirs.cur.load(Ordering::Relaxed), Ordering::Relaxed);
            mine.max
                .store(theirs.max.load(Ordering::Relaxed), Ordering::Relaxed);
        }
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

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Get resource limits, and optionally set new limits.
    pub(crate) fn do_prlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        new_limit: Option<litebox_common_linux::Rlimit>,
    ) -> Result<litebox_common_linux::Rlimit, Errno> {
        let limits = &self.thread.process.limits;
        let old_rlimit = limits.get_rlimit(resource);
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
            let new_max_fd = new_limit.rlim_cur.saturating_sub(1);
            limits.set_rlimit(resource, new_limit);
            if let litebox_common_linux::RlimitResource::NOFILE = resource {
                self.files.borrow().set_max_fd(new_max_fd);
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
        if pid != 0 && pid != self.pid {
            unimplemented!("prlimit for a specific PID is not supported yet");
        }
        let new_limit = match new_rlim {
            Some(rlim) => {
                let rlim = rlim.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                Some(litebox_common_linux::rlimit64_to_rlimit(rlim))
            }
            None => None,
        };
        let old_limit =
            litebox_common_linux::rlimit_to_rlimit64(self.do_prlimit(resource, new_limit)?);
        if let Some(old_rlim) = old_rlim {
            old_rlim
                .write_at_offset::<Platform>(0, old_limit)
                .ok_or(Errno::EFAULT)?;
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
            .ok_or(Errno::EFAULT)
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
        if pid.is_some_and(|pid| pid != self.tid) {
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

    pub(crate) fn real_time_as_duration_since_epoch(&self) -> core::time::Duration {
        let now = self.global.platform.current_time();
        let unix_epoch = <Platform as TimeProvider>::SystemTime::UNIX_EPOCH;
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
            litebox_common_linux::ClockId::RealTimeCoarse => {
                // CLOCK_REALTIME_COARSE - a faster, lower-resolution CLOCK_REALTIME.
                // Simplification: we have no cheaper coarse clock source, so we reuse the exact
                // same (full-precision) value as CLOCK_REALTIME; see `sys_clock_getres` for the
                // (still coarse) resolution we report for this clock.
                self.real_time_as_duration_since_epoch()
            }
            litebox_common_linux::ClockId::Monotonic
            | litebox_common_linux::ClockId::MonotonicCoarse
            | litebox_common_linux::ClockId::MonotonicRaw
            | litebox_common_linux::ClockId::Boottime => {
                // CLOCK_MONOTONIC / CLOCK_MONOTONIC_COARSE / CLOCK_MONOTONIC_RAW /
                // CLOCK_BOOTTIME.
                //
                // Simplification: LiteBox tracks only a single monotonic clock, so all four map
                // onto it. This is exact for CLOCK_MONOTONIC; for the others it elides real
                // Linux's distinctions (COARSE trades precision for speed; RAW excludes NTP
                // slewing; BOOTTIME additionally counts suspend time) -- see the `ClockId`
                // variant docs for why each is a legitimate simplification here.
                self.global
                    .platform
                    .now()
                    .duration_since(&self.global.boot_time)
            }
            litebox_common_linux::ClockId::ProcessCpuTime => {
                // CLOCK_PROCESS_CPUTIME_ID - genuine per-process CPU-time accounting, sourced
                // from the host (not wall-clock time).
                self.global.platform.process_cpu_time()
            }
            litebox_common_linux::ClockId::ThreadCpuTime => {
                // CLOCK_THREAD_CPUTIME_ID - genuine per-thread CPU-time accounting, sourced from
                // the host (not wall-clock time).
                self.global.platform.thread_cpu_time()
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
            | litebox_common_linux::ClockId::MonotonicCoarse
            | litebox_common_linux::ClockId::MonotonicRaw
            | litebox_common_linux::ClockId::Boottime => {
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
            litebox_common_linux::ClockId::MonotonicCoarse
            | litebox_common_linux::ClockId::RealTimeCoarse => {
                // Coarse clocks typically have lower resolution (e.g., 4 millisecond). We report
                // this even though we actually source these from the full-precision clock (see
                // `gettime_as_duration`), matching the resolution real coarse clocks advertise.
                Duration::from_millis(4)
            }
            litebox_common_linux::ClockId::RealTime
            | litebox_common_linux::ClockId::Monotonic
            | litebox_common_linux::ClockId::MonotonicRaw
            | litebox_common_linux::ClockId::Boottime
            | litebox_common_linux::ClockId::ProcessCpuTime
            | litebox_common_linux::ClockId::ThreadCpuTime => {
                // For most modern systems, the resolution is typically 1 nanosecond
                // This is a reasonable default for high-resolution timers
                Duration::from_nanos(1)
            }
            // `ClockId` is `#[non_exhaustive]` but only declares the variants matched above;
            // `clockid` only reaches here via `ClockId::try_from`, which rejects anything else
            // with `EINVAL` before construction.
            _ => unreachable!(),
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
        if matches!(
            clockid,
            litebox_common_linux::ClockId::ProcessCpuTime
                | litebox_common_linux::ClockId::ThreadCpuTime
        ) {
            // Real Linux rejects sleeping against a CPU-time clock: a blocked (not-running)
            // thread cannot accumulate CPU time, so waiting for one of these clocks to reach a
            // given value could never wake up.
            return Err(Errno::EINVAL);
        }
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
            Some(now.checked_add(delay).ok_or(Errno::EFAULT)?)
        };
        if alarm.handle.is_none() {
            match self
                .global
                .platform
                .create_timer(litebox_common_linux::signal::Signal::SIGALRM)
            {
                Ok(handle) => alarm.handle = Some(handle),
                Err(litebox::platform::TimerCreationError::Unsupported) => {}
                // `TimerCreationError` is `#[non_exhaustive]` but only declares this one
                // variant, already matched above.
                Err(_) => unreachable!(),
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

    /// Resolves `pid`, as passed to `setpgid`/`getpgid`, to the process-group identity of the
    /// calling process or one of its live children.
    fn pgid_target(&self, pid: i32) -> Result<Arc<AtomicI32>, Errno> {
        if pid == 0 || pid == self.pid {
            return Ok(self.process().process_group_id.clone());
        }
        let Some(target) = self
            .global
            .processes
            .live_child_process_group_id(self.pid, pid)
        else {
            log_unsupported!("setpgid/getpgid for a pid that is not a live child");
            return Err(Errno::ESRCH);
        };
        Ok(target)
    }

    /// Handle syscall `setsid`.
    ///
    /// A process-group leader cannot create a new session. On success the caller becomes both the
    /// session and process-group leader and loses any controlling terminal, matching Linux.
    pub(crate) fn sys_setsid(&self) -> Result<i32, Errno> {
        let process = self.process();
        if process.process_group_id() == self.pid {
            return Err(Errno::EPERM);
        }
        process.session_id.store(self.pid, Ordering::Release);
        process
            .controlling_pty
            .store(NO_CONTROLLING_PTY, Ordering::Release);
        process.process_group_id.store(self.pid, Ordering::Release);
        Ok(self.pid)
    }

    /// Handle syscall `getpgid`.
    ///
    /// `pid == 0` means "the calling process". A parent may also query one of its live children.
    pub(crate) fn sys_getpgid(&self, pid: i32) -> Result<i32, Errno> {
        Ok(self.pgid_target(pid)?.load(Ordering::Acquire))
    }

    /// Handle syscall `setpgid`.
    ///
    /// Real Linux additionally restricts this to processes in the same session and forbids
    /// retargeting a child that has already called `execve` (`EACCES`). LiteBox does not yet track
    /// an exec generation per child, so only the live self/child identity check is enforced.
    /// `pgid == 0` means "use the target's own pid", matching Linux.
    #[allow(clippy::similar_names)]
    pub(crate) fn sys_setpgid(&self, pid: i32, pgid: i32) -> Result<(), Errno> {
        if pgid < 0 {
            return Err(Errno::EINVAL);
        }
        let target_pid = if pid == 0 { self.pid } else { pid };
        let target = self.pgid_target(pid)?;
        let new_pgid = if pgid == 0 { target_pid } else { pgid };
        target.store(new_pgid, Ordering::Release);
        Ok(())
    }

    /// Handle syscall `getuid`.
    pub(crate) fn sys_getuid(&self) -> u32 {
        self.credentials.borrow().uid
    }

    /// Handle syscall `geteuid`.
    pub(crate) fn sys_geteuid(&self) -> u32 {
        self.credentials.borrow().euid
    }

    /// Handle syscall `getgid`.
    pub(crate) fn sys_getgid(&self) -> u32 {
        self.credentials.borrow().gid
    }

    /// Handle syscall `getegid`.
    pub(crate) fn sys_getegid(&self) -> u32 {
        self.credentials.borrow().egid
    }

    /// Whether this task may change its uid/gid to an arbitrary value.
    ///
    /// LiteBox models no capability set, so `CAP_SETUID`/`CAP_SETGID` have
    /// nothing to check. An effective uid of 0 is used as the stand-in,
    /// mirroring the classic pre-capabilities Unix kernel, which gated the
    /// same operations on `suser()` (effective uid 0) alone.
    /// Whether this task may perform a privileged identity change (`setuid`
    /// family, `setgroups`).
    ///
    /// Real Linux gates these on holding `CAP_SETUID`/`CAP_SETGID` in the
    /// effective capability set, not literally on `euid == 0` -- the two
    /// usually coincide (root normally holds every capability), but they
    /// diverge exactly when a process has called `PR_SET_KEEPCAPS` before
    /// dropping its uid away from 0: without that flag the kernel would
    /// clear the permitted set on the uid change, but with it the
    /// capabilities survive, so a later `setresgid`/`setresuid` from the
    /// now-unprivileged-looking euid still succeeds. This is the standard
    /// sequence `setpriv --reuid --regid` uses (`PR_SET_KEEPCAPS(1)` ->
    /// `capset` -> `setresuid` -> `setresgid`), and LiteBox does not model
    /// individual capability bits at all (`CapBSetRead`/`capget` always
    /// report an empty set) -- the same coarse stance extended here: once
    /// `keep_caps` is set, treat this task as retaining root's implicit
    /// authority for these calls, mirroring what a real kernel would do for
    /// a process that actually held (and kept) `CAP_SETUID`/`CAP_SETGID`.
    fn is_privileged(&self) -> bool {
        let credentials = self.credentials.borrow();
        credentials.euid == 0 || credentials.keep_caps()
    }

    /// Install `new` as this task's credentials with the side effects Linux's `commit_creds`
    /// (`kernel/cred.c`) attaches to a change of *effective* identity: the process becomes
    /// non-dumpable (`suid_dumpable`'s default 0) and loses its parent-death signal. The kernel's
    /// test is on `euid`/`egid`/`fsuid`/`fsgid` and the capability sets -- a change of only the
    /// real or saved ids leaves both alone -- and LiteBox models neither `fsuid` nor capability
    /// bits, so the effective ids are the whole test. This is what makes a `setuid` helper that
    /// drops root (`doas`, `chrome-sandbox`) read back `PR_GET_DUMPABLE == 0` afterwards, as on
    /// Linux, instead of the `1` an unrelated earlier exec left behind.
    #[allow(
        clippy::similar_names,
        reason = "old/new euid/egid pairs are the natural naming here"
    )]
    fn commit_credentials(&self, new: Credentials) {
        let (old_euid, old_egid) = {
            let old = self.credentials.borrow();
            (old.euid, old.egid)
        };
        let identity_changed = old_euid != new.euid || old_egid != new.egid;
        let (new_euid, new_egid) = (new.euid, new.egid);
        *self.credentials.borrow_mut() = Arc::new(new);
        if identity_changed {
            litebox_util_log::debug!(
                pid:? = self.pid, old_euid:? = old_euid, new_euid:? = new_euid,
                old_egid:? = old_egid, new_egid:? = new_egid;
                "effective identity changed: process is no longer dumpable, parent-death signal cleared"
            );
            self.process().set_dumpable(false);
            self.thread.parent_death_signal.set(None);
            self.global
                .processes
                .set_parent_death_signal(self.pid, None);
        }
    }

    /// Handle syscall `setuid`.
    ///
    /// A privileged task sets its real, effective, and saved user IDs together. An
    /// unprivileged task may only select its real or saved ID as the new effective ID.
    pub(crate) fn sys_setuid(&self, uid: u32) -> Result<(), Errno> {
        let old = self.credentials.borrow().clone();
        let mut new = old.as_ref().clone();
        if old.euid == 0 {
            new.uid = uid;
            new.euid = uid;
            new.suid = uid;
        } else if uid == old.uid || uid == old.suid {
            new.euid = uid;
        } else {
            return Err(Errno::EPERM);
        }
        self.commit_credentials(new);
        Ok(())
    }

    /// Handle syscall `setgid`; see [`Self::sys_setuid`] for the analogous user-ID rules.
    pub(crate) fn sys_setgid(&self, gid: u32) -> Result<(), Errno> {
        let old = self.credentials.borrow().clone();
        let mut new = old.as_ref().clone();
        if old.euid == 0 {
            new.gid = gid;
            new.egid = gid;
            new.sgid = gid;
        } else if gid == old.gid || gid == old.sgid {
            new.egid = gid;
        } else {
            return Err(Errno::EPERM);
        }
        self.commit_credentials(new);
        Ok(())
    }

    /// Handle syscall `setresuid`. `u32::MAX` leaves the corresponding field unchanged.
    pub(crate) fn sys_setresuid(&self, ruid: u32, euid: u32, suid: u32) -> Result<(), Errno> {
        let old = self.credentials.borrow().clone();
        let privileged = self.is_privileged();
        let allowed =
            |value: u32| privileged || value == old.uid || value == old.euid || value == old.suid;
        for value in [ruid, euid, suid] {
            if value != u32::MAX && !allowed(value) {
                return Err(Errno::EPERM);
            }
        }

        let mut new = old.as_ref().clone();
        if ruid != u32::MAX {
            new.uid = ruid;
        }
        if euid != u32::MAX {
            new.euid = euid;
        }
        if suid != u32::MAX {
            new.suid = suid;
        }
        self.commit_credentials(new);
        Ok(())
    }

    /// Handle syscall `setresgid`; see [`Self::sys_setresuid`], with group IDs.
    pub(crate) fn sys_setresgid(&self, rgid: u32, egid: u32, sgid: u32) -> Result<(), Errno> {
        let old = self.credentials.borrow().clone();
        let privileged = self.is_privileged();
        let allowed =
            |value: u32| privileged || value == old.gid || value == old.egid || value == old.sgid;
        for value in [rgid, egid, sgid] {
            if value != u32::MAX && !allowed(value) {
                return Err(Errno::EPERM);
            }
        }

        let mut new = old.as_ref().clone();
        if rgid != u32::MAX {
            new.gid = rgid;
        }
        if egid != u32::MAX {
            new.egid = egid;
        }
        if sgid != u32::MAX {
            new.sgid = sgid;
        }
        self.commit_credentials(new);
        Ok(())
    }

    /// Handle syscall `getresuid`.
    pub(crate) fn sys_getresuid(
        &self,
        ruid: UserPtrMut<u32>,
        euid: UserPtrMut<u32>,
        suid: UserPtrMut<u32>,
    ) -> Result<(), Errno> {
        let credentials = self.credentials.borrow();
        ruid.write_at_offset::<Platform>(0, credentials.uid)
            .ok_or(Errno::EFAULT)?;
        euid.write_at_offset::<Platform>(0, credentials.euid)
            .ok_or(Errno::EFAULT)?;
        suid.write_at_offset::<Platform>(0, credentials.suid)
            .ok_or(Errno::EFAULT)?;
        Ok(())
    }

    /// Handle syscall `getresgid`; see [`Self::sys_getresuid`], with group IDs.
    pub(crate) fn sys_getresgid(
        &self,
        rgid: UserPtrMut<u32>,
        egid: UserPtrMut<u32>,
        sgid: UserPtrMut<u32>,
    ) -> Result<(), Errno> {
        let credentials = self.credentials.borrow();
        rgid.write_at_offset::<Platform>(0, credentials.gid)
            .ok_or(Errno::EFAULT)?;
        egid.write_at_offset::<Platform>(0, credentials.egid)
            .ok_or(Errno::EFAULT)?;
        sgid.write_at_offset::<Platform>(0, credentials.sgid)
            .ok_or(Errno::EFAULT)?;
        Ok(())
    }

    pub(crate) fn sys_getgroups(&self, size: i32, list: UserPtrMut<u32>) -> Result<usize, Errno> {
        if size < 0 {
            return Err(Errno::EINVAL);
        }
        let size = usize::try_from(size).map_err(|_| Errno::EINVAL)?;
        let credentials = self.credentials.borrow();
        let groups = credentials.supplementary_groups.as_slice();
        if size == 0 {
            return Ok(groups.len());
        }
        if size < groups.len() {
            return Err(Errno::EINVAL);
        }
        list.write_slice_at_offset::<Platform>(0, groups)
            .ok_or(Errno::EFAULT)?;
        Ok(groups.len())
    }

    pub(crate) fn sys_setgroups(&self, size: usize, list: UserPtr<u32>) -> Result<(), Errno> {
        if !self.is_privileged() {
            return Err(Errno::EPERM);
        }
        let supplementary_groups = SupplementaryGroups::from_user::<Platform>(size, list)?;
        let mut new = self.credentials.borrow().as_ref().clone();
        new.supplementary_groups = supplementary_groups;
        *self.credentials.borrow_mut() = Arc::new(new);
        Ok(())
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

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Resolves `which`/`who` of `getpriority`/`setpriority` to the threads it names, each with
    /// the real uid of its process (what `set_one_prio_perm` compares against). `PRIO_PROCESS`
    /// names one thread (`who == 0` is the caller; a tid selects that thread, in this or any
    /// live process); `PRIO_PGRP` every thread of every process in the group (`who == 0`: the
    /// caller's group); `PRIO_USER` every thread of every process with that real uid (`who ==
    /// 0`: the caller's). Returns `EINVAL` for an unknown `which`, `ESRCH` when nothing matched.
    #[allow(
        clippy::type_complexity,
        reason = "tuple return keeps the caller's loop ergonomic"
    )]
    fn priority_targets(
        &self,
        which: i32,
        who: i32,
    ) -> Result<Vec<(Arc<ThreadRemote<Platform>>, u32)>, Errno> {
        const PRIO_PROCESS: i32 = 0;
        const PRIO_PGRP: i32 = 1;
        const PRIO_USER: i32 = 2;
        let own_uid = self.credentials.borrow().uid;
        let mut out = Vec::new();
        match which {
            PRIO_PROCESS => {
                let who = if who == 0 { self.tid } else { who };
                if who == self.tid || self.process().thread_remote(who).is_some() {
                    let remote = self
                        .process()
                        .thread_remote(who)
                        .unwrap_or_else(|| self.thread_remote().clone());
                    out.push((remote, own_uid));
                } else if let Some((threads, _, uid)) = self.global.processes.priority_targets(who)
                {
                    // A tid in another process: Linux resolves `who` as a tid (`find_task_by_vpid`),
                    // and the table is keyed by pid = leader tid, so this selects that leader.
                    if let Some(leader) = threads.into_iter().next() {
                        out.push((leader, uid));
                    }
                }
            }
            PRIO_PGRP => {
                let group = if who == 0 {
                    self.process().process_group_id()
                } else {
                    who
                };
                for pid in self.global.processes.live_pids() {
                    if let Some((threads, pgid, uid)) = self.global.processes.priority_targets(pid)
                        && pgid == group
                    {
                        out.extend(threads.into_iter().map(|t| (t, uid)));
                    }
                }
            }
            PRIO_USER => {
                let target = if who == 0 {
                    own_uid
                } else {
                    who.cast_unsigned()
                };
                for pid in self.global.processes.live_pids() {
                    if let Some((threads, _, uid)) = self.global.processes.priority_targets(pid)
                        && uid == target
                    {
                        out.extend(threads.into_iter().map(|t| (t, uid)));
                    }
                }
            }
            _ => return Err(Errno::EINVAL),
        }
        if out.is_empty() {
            return Err(Errno::ESRCH);
        }
        Ok(out)
    }

    /// Handle syscall `getpriority`.
    ///
    /// Returns the *highest* priority (lowest nice) among the matched threads, encoded as Linux's
    /// syscall does -- `20 - nice`, so `1..=40` -- for the libc wrapper to turn back into a
    /// nice value.
    pub(crate) fn sys_getpriority(&self, which: i32, who: i32) -> Result<usize, Errno> {
        let targets = self.priority_targets(which, who)?;
        let lowest_nice = targets
            .iter()
            .map(|(thread, _)| thread.nice())
            .min()
            .unwrap_or(0);
        Ok((20 - lowest_nice).cast_unsigned() as usize)
    }

    /// Handle syscall `setpriority`.
    ///
    /// `niceval` is clamped to `-20..=19`. Linux's `set_one_prio` rules: a target owned by a
    /// different real uid needs the caller to be privileged (`EPERM`); lowering a nice value
    /// (raising priority) needs `CAP_SYS_NICE` or an `RLIMIT_NICE` that admits it (`EACCES`);
    /// raising nice is always allowed. One matched thread in error does not stop the others
    /// (the last error is reported after all are tried), as in the kernel's loop.
    #[allow(
        clippy::similar_names,
        reason = "own_euid/own_uid mirror Linux's euid/uid pair"
    )]
    pub(crate) fn sys_setpriority(&self, which: i32, who: i32, niceval: i32) -> Result<(), Errno> {
        let niceval = niceval.clamp(-20, 19);
        let targets = self.priority_targets(which, who)?;
        let privileged = self.is_privileged();
        let own_euid = self.credentials.borrow().euid;
        let own_uid = self.credentials.borrow().uid;
        // `nice_to_rlimit`: a nice of `n` needs `RLIMIT_NICE >= 20 - n`.
        let nice_rlim = (20 - niceval).cast_unsigned() as usize;
        let rlimit_nice = self
            .process()
            .limits
            .get_rlimit_cur(litebox_common_linux::RlimitResource::NICE);
        let mut error = None;
        for (thread, target_uid) in targets {
            if !privileged && target_uid != own_uid && target_uid != own_euid {
                error = Some(Errno::EPERM);
                continue;
            }
            if niceval < thread.nice() && !privileged && nice_rlim > rlimit_nice {
                error = Some(Errno::EACCES);
                continue;
            }
            thread.set_nice(niceval);
        }
        error.map_or(Ok(()), Err)
    }

    /// Handle syscall `membarrier`.
    ///
    /// Answers as a kernel built with `CONFIG_MEMBARRIER=n` does: `ENOSYS` for every command,
    /// `MEMBARRIER_CMD_QUERY` included. A membarrier's guarantee is that every *other* thread
    /// of the process has executed a full barrier before the call returns; the host (no
    /// `membarrier(2)` on macOS, guest threads running on vCPU lanes) has no primitive for that
    /// yet, and a command that returned `0` without providing it would be a lie a lock-free
    /// algorithm could act on. Callers must already handle `ENOSYS` (pre-4.3 kernels, or this
    /// config). Decoded rather than left to the unknown-syscall path so the log names the
    /// command the guest asked for.
    pub(crate) fn sys_membarrier(&self, cmd: i32, flags: u32, cpu_id: i32) -> Result<usize, Errno> {
        log_unsupported!(
            "membarrier(cmd = {cmd:#x}, flags = {flags:#x}, cpu_id = {cpu_id}): no cross-thread barrier primitive -> ENOSYS"
        );
        Err(Errno::ENOSYS)
    }

    /// Handle syscall `sched_getaffinity`.
    ///
    /// Note this is a dummy implementation that always returns the same CPU set
    pub(crate) fn sys_sched_getaffinity(&self, _pid: Option<i32>) -> CpuSet {
        let mut cpuset = bitvec::bitvec![u8, bitvec::order::Lsb0; 0; NR_CPUS];
        cpuset.iter_mut().for_each(|mut b| *b = true);
        CpuSet { bits: cpuset }
    }

    /// Returns whether `pid`, as passed to one of the `sched_*` syscalls below, refers to the
    /// calling thread. `pid == 0` (as with all four `sched_*` syscalls per their man pages) means
    /// "the calling thread"; `sched_*` operates at thread (not process) granularity on Linux, so
    /// this compares against `self.tid`, not a process-wide id.
    fn sched_target_is_self(&self, pid: Option<i32>) -> bool {
        pid.is_none_or(|pid| pid == self.tid)
    }

    /// Handle syscall `sched_getparam`.
    ///
    /// LiteBox's process model has no real scheduling-class enforcement to expose, so every
    /// thread is always reported as `SCHED_OTHER` with priority 0 -- the same default every
    /// unprivileged Linux thread starts with, and the only priority `SCHED_OTHER` ever accepts.
    pub(crate) fn sys_sched_getparam(
        &self,
        pid: Option<i32>,
        param: UserPtrMut<litebox_common_linux::SchedParam>,
    ) -> Result<usize, Errno> {
        if !self.sched_target_is_self(pid) {
            log_unsupported!("sched_getparam for a remote pid");
            return Err(Errno::ESRCH);
        }
        param
            .write_at_offset::<Platform>(0, litebox_common_linux::SchedParam { sched_priority: 0 })
            .ok_or(Errno::EFAULT)?;
        Ok(0)
    }

    /// Handle syscall `sched_setparam`.
    ///
    /// Since every thread is always `SCHED_OTHER` (see [`Self::sys_sched_getparam`]), and
    /// `SCHED_OTHER`'s only valid priority is 0, this accepts a priority-0 request as a no-op and
    /// rejects anything else with `EINVAL`, matching what real Linux would do to a process that
    /// never leaves `SCHED_OTHER`.
    pub(crate) fn sys_sched_setparam(
        &self,
        pid: Option<i32>,
        param: UserPtr<litebox_common_linux::SchedParam>,
    ) -> Result<usize, Errno> {
        if !self.sched_target_is_self(pid) {
            log_unsupported!("sched_setparam for a remote pid");
            return Err(Errno::ESRCH);
        }
        let param = param.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        if param.sched_priority != 0 {
            return Err(Errno::EINVAL);
        }
        Ok(0)
    }

    /// Handle syscall `sched_getscheduler`.
    pub(crate) fn sys_sched_getscheduler(&self, pid: Option<i32>) -> Result<usize, Errno> {
        if !self.sched_target_is_self(pid) {
            log_unsupported!("sched_getscheduler for a remote pid");
            return Err(Errno::ESRCH);
        }
        // The return value of `sched_getscheduler` IS the policy (unlike most syscalls, it is
        // not a separate out-parameter), so no bitwise cast/sign issues arise turning a small
        // non-negative `i32` constant into a `usize` success value.
        Ok(usize::try_from(litebox_common_linux::sched_policy::SCHED_OTHER).unwrap())
    }

    /// Handle syscall `sched_setscheduler`.
    ///
    /// Non-real-time policies (`SCHED_OTHER`/`SCHED_BATCH`/`SCHED_IDLE`) are accepted as no-ops,
    /// same as a real unprivileged Linux process switching between them would experience.
    /// Real-time policies (`SCHED_FIFO`/`SCHED_RR`/`SCHED_DEADLINE`) are rejected with `EPERM`,
    /// matching real Linux's behavior for a process without `CAP_SYS_NICE` -- a real, accurate
    /// constraint here, since LiteBox guests never have that capability, not a shortcut.
    pub(crate) fn sys_sched_setscheduler(
        &self,
        pid: Option<i32>,
        policy: i32,
        param: UserPtr<litebox_common_linux::SchedParam>,
    ) -> Result<usize, Errno> {
        use litebox_common_linux::sched_policy::{
            SCHED_BATCH, SCHED_DEADLINE, SCHED_FIFO, SCHED_IDLE, SCHED_OTHER, SCHED_RESET_ON_FORK,
            SCHED_RR,
        };

        if !self.sched_target_is_self(pid) {
            log_unsupported!("sched_setscheduler for a remote pid");
            return Err(Errno::ESRCH);
        }
        match policy & !SCHED_RESET_ON_FORK {
            SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => {}
            SCHED_FIFO | SCHED_RR | SCHED_DEADLINE => {
                log_unsupported!(
                    "sched_setscheduler(policy = {policy}): real-time scheduling is never available to a LiteBox guest"
                );
                return Err(Errno::EPERM);
            }
            _ => return Err(Errno::EINVAL),
        }
        let param = param.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        if param.sched_priority != 0 {
            return Err(Errno::EINVAL);
        }
        Ok(0)
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn futex_key(
        &self,
        mappings: &litebox::mm::MappingReadGuard<'_, Platform, PAGE_SIZE>,
        addr: UserPtrMut<u32>,
        flags: &litebox_common_linux::FutexFlags,
    ) -> Result<FutexKey, Errno> {
        if !addr.as_usize().is_multiple_of(align_of::<u32>()) {
            return Err(Errno::EINVAL);
        }
        let key = if flags.contains(litebox_common_linux::FutexFlags::PRIVATE) {
            FutexKey::new(self.process().futex_namespace(), addr.as_usize())
        } else {
            let mapping = mappings.flags_at(addr.as_usize()).ok_or(Errno::EFAULT)?;
            if mapping.contains(VmFlags::VM_SHARED) {
                let (backing, offset) = mappings
                    .shared_futex_key_at(addr.as_usize())
                    .ok_or(Errno::EFAULT)?;
                FutexKey::new_shared(backing, offset)
            } else {
                FutexKey::new(self.process().futex_namespace(), addr.as_usize())
            }
        };
        Ok(key)
    }

    /// Handle syscall `futex`
    pub(crate) fn sys_futex(&self, arg: litebox_common_linux::FutexArgs) -> Result<usize, Errno> {
        let res = match arg {
            FutexArgs::Wake { addr, flags, count } => {
                // Linux's traditional FUTEX_WAKE takes a signed `int`. Its queue loop wakes one
                // waiter before testing whether the count has been reached, so zero and negative
                // raw values both mean one wake rather than zero or an enormous unsigned quota.
                let count = if count.cast_signed() <= 0 { 1 } else { count };
                let count = core::num::NonZeroU32::new(count).unwrap();
                let mappings = self.global.pm.lock_mappings();
                let key = self.futex_key(&mappings, addr, &flags)?;
                self.process()
                    .futex_manager()
                    .wake_keyed(key, count, None)? as usize
            }
            FutexArgs::WakeBitset {
                addr,
                flags,
                count,
                bitmask,
            } => {
                let count = if count.cast_signed() <= 0 { 1 } else { count };
                let count = core::num::NonZeroU32::new(count).unwrap();
                let bitmask = core::num::NonZeroU32::new(bitmask).ok_or(Errno::EFAULT)?;
                let mappings = self.global.pm.lock_mappings();
                let key = self.futex_key(&mappings, addr, &flags)?;
                self.process()
                    .futex_manager()
                    .wake_keyed(key, count, Some(bitmask))? as usize
            }
            FutexArgs::Wait {
                addr,
                flags,
                val,
                timeout,
            } => {
                let timeout = timeout.read::<Platform>()?;
                let mappings = self.global.pm.lock_mappings();
                let key = self.futex_key(&mappings, addr, &flags)?;
                self.process().futex_manager().wait_keyed(
                    &self.wait_cx().with_timeout(timeout),
                    key,
                    addr.to_platform_ptr::<Platform>(),
                    val,
                    None,
                    || drop(mappings),
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
                let bitmask = core::num::NonZeroU32::new(bitmask).ok_or(Errno::EFAULT)?;
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
                let mappings = self.global.pm.lock_mappings();
                let key = self.futex_key(&mappings, addr, &flags)?;
                self.process().futex_manager().wait_keyed(
                    &self.wait_cx().with_deadline(deadline),
                    key,
                    addr.to_platform_ptr::<Platform>(),
                    val,
                    Some(bitmask),
                    || drop(mappings),
                )?;
                0
            }
            litebox_common_linux::FutexArgs::Requeue {
                addr,
                flags,
                num_to_wake,
                num_to_requeue,
                addr2,
            } => {
                let mappings = self.global.pm.lock_mappings();
                let key1 = self.futex_key(&mappings, addr, &flags)?;
                let key2 = self.futex_key(&mappings, addr2, &flags)?;
                self.process().futex_manager().requeue_keyed(
                    key1,
                    key2,
                    addr.to_platform_ptr::<Platform>(),
                    num_to_wake,
                    num_to_requeue,
                    None,
                )? as usize
            }
            litebox_common_linux::FutexArgs::CmpRequeue {
                addr,
                flags,
                num_to_wake,
                num_to_requeue,
                addr2,
                expected_value,
            } => {
                let mappings = self.global.pm.lock_mappings();
                let key1 = self.futex_key(&mappings, addr, &flags)?;
                let key2 = self.futex_key(&mappings, addr2, &flags)?;
                self.process().futex_manager().requeue_keyed(
                    key1,
                    key2,
                    addr.to_platform_ptr::<Platform>(),
                    num_to_wake,
                    num_to_requeue,
                    Some(expected_value),
                )? as usize
            }
            _ => {
                log_unsupported!("futex operation {:?}", arg);
                return Err(Errno::ENOSYS);
            }
        };
        Ok(res)
    }
}

const MAX_VEC: usize = 4096; // limit count
const MAX_TOTAL_BYTES: usize = 256 * 1024; // size cap

/// Maximum shebang (#!) recursion depth (from Linux's `exec_binprm`)
const SHEBANG_MAX_RECURSION: u32 = 4;

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

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Resolve shebang (`#!`) chains for the given path and argv.
    ///
    /// Every probe follows symlinks. A script still contributes the spelling used to reach it to
    /// the interpreter's argv, while the returned non-script path is the final followed target the
    /// ELF loader must open.
    pub(crate) fn resolve_shebang(
        &self,
        mut path: alloc::string::String,
        mut argv: alloc::vec::Vec<alloc::ffi::CString>,
    ) -> Result<(alloc::string::String, alloc::vec::Vec<alloc::ffi::CString>), Errno> {
        let mut recursion = 0;
        let comm = path
            .rsplit('/')
            .next()
            .unwrap_or("unknown")
            .as_bytes()
            .to_vec();
        loop {
            let full_path = self.resolve_path(&path)?;
            let full_path = self.follow_open_path(full_path, litebox::fs::OFlags::RDONLY)?;
            let mut header = [0u8; SHEBANG_MAX_LINE];
            let n =
                crate::loader::elf::read_executable_header(self, full_path.clone(), &mut header)?;

            if let Some((interp, opt_arg)) = parse_shebang(&header[..n]) {
                if recursion == SHEBANG_MAX_RECURSION {
                    return Err(Errno::ELOOP);
                }
                recursion += 1;
                let mut new_argv = alloc::vec::Vec::new();
                new_argv.push(alloc::ffi::CString::new(interp).map_err(|_| Errno::EINVAL)?);
                if let Some(arg) = opt_arg {
                    new_argv.push(alloc::ffi::CString::new(arg).map_err(|_| Errno::EINVAL)?);
                }
                new_argv.push(alloc::ffi::CString::new(path.as_str()).map_err(|_| Errno::EINVAL)?);
                if argv.len() > 1 {
                    new_argv.extend_from_slice(&argv[1..]);
                }
                path = alloc::string::String::from(interp);
                argv = new_argv;
            } else {
                let path = full_path.into_string().map_err(|_| Errno::EINVAL)?;
                // Linux's `/proc/<pid>/exe` names the image actually mapped: for a `#!`
                // script that is the interpreter, which is what `path` is by now.
                *self.thread.staged_exec.borrow_mut() = Some(StagedExec {
                    exe: path.clone(),
                    comm,
                });
                return Ok((path, argv));
            }
        }
    }

    fn credentials_for_exec(&self, status: &litebox::fs::FileStatus) -> (Arc<Credentials>, bool) {
        let old = self.credentials.borrow().clone();
        let mut candidate = old.as_ref().clone();
        if !old.no_new_privs() {
            if status.mode.contains(litebox::fs::Mode::SUID) {
                candidate.euid = u32::from(status.owner.user);
            }
            if status
                .mode
                .contains(litebox::fs::Mode::SGID | litebox::fs::Mode::XGRP)
            {
                candidate.egid = u32::from(status.owner.group);
            }
        }
        candidate.suid = candidate.euid;
        candidate.sgid = candidate.egid;
        let transitioned = candidate.euid != old.euid || candidate.egid != old.egid;
        let secure =
            transitioned || candidate.euid != candidate.uid || candidate.egid != candidate.gid;
        (Arc::new(candidate), secure)
    }

    /// Handle syscall `execve`.
    // `c_char` rather than a fixed `i8`: it is signed on x86-64 and on Apple's
    // AArch64 ABI but unsigned on AArch64 Linux, and `SyscallRequest::Execve`
    // hands these over as `UserPtr<c_char>`.
    pub(crate) fn sys_execve(
        &self,
        pathname: UserPtr<core::ffi::c_char>,
        argv: UserPtr<UserPtr<core::ffi::c_char>>,
        envp: UserPtr<UserPtr<core::ffi::c_char>>,
        ctx: &mut litebox_common_linux::PtRegs,
    ) -> Result<usize, Errno> {
        fn copy_vector<Platform: ShimPlatform>(
            mut base: UserPtr<UserPtr<core::ffi::c_char>>,
            _which: &str,
        ) -> Result<alloc::vec::Vec<alloc::ffi::CString>, Errno> {
            let mut out = alloc::vec::Vec::new();
            let mut total = 0usize;
            for _ in 0..MAX_VEC {
                let p: UserPtr<core::ffi::c_char> = {
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
            copy_vector::<Platform>(argv, "argv")?
        };
        let envp_vec = if envp.as_usize() == 0 {
            alloc::vec::Vec::new()
        } else {
            copy_vector::<Platform>(envp, "envp")?
        };

        let (path, argv_vec) = self.resolve_shebang(alloc::string::String::from(path), argv_vec)?;

        let loader = crate::loader::elf::ElfLoader::new(self, &path)?;
        let (exec_credentials, secure_exec) = self.credentials_for_exec(loader.main_status());

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
            let _ = self.wake_robust_list(robust_list);
        }
        let shares_parent_vm = self.process().shares_parent_vm();
        if shares_parent_vm {
            // Linux's mm_release clears and wakes this address on vfork exec while the old VM is
            // still shared with the suspended parent. Do it before detaching the child's VM slot;
            // retaining the pointer into the old image would instead corrupt parent memory later.
            if let Some(clear_child_tid) = self.thread.clear_child_tid.take() {
                let _ = clear_child_tid.write_at_offset::<Platform>(0, 0);
                let _ = self.sys_futex(litebox_common_linux::FutexArgs::Wake {
                    addr: UserPtrMut::from_usize(clear_child_tid.as_usize()),
                    flags: litebox_common_linux::FutexFlags::empty(),
                    count: 1,
                });
            }
        } else {
            self.thread.clear_child_tid.set(None);
        }

        self.signals.reset_for_exec();

        if shares_parent_vm {
            // The child has so far operated on the parent's live VM identity. Swap only this
            // process's slot to a fresh identity before building the new image; the suspended
            // parent keeps the original identity, including every pre-exec mapping and brk change.
            self.process().detach_vfork_vm();
        } else if self.leave_address_space_if_alone() {
            // Release only the mappings this process owns, not everything the
            // (process-blind) page manager tracks. "Alone in the shared
            // address space" -- or never having shared at all -- does not
            // mean alone in the page manager: a forked child that already
            // completed one exec has left the shared space, yet its suspended
            // parent's entire live memory is still in the manager, and a
            // release-everything here destroys it. Observed live as Node's
            // `execSync("/bin/sh -c ...")`: fork, exec /bin/sh (first exec
            // keeps the parent's memory via the branch below), sh execs the
            // command (second exec took this branch and unmapped the
            // suspended parent wholesale -- every one of its subsequent
            // address-space restores failed and it died on the first libc
            // global it touched). `owned_ranges` exists precisely to name
            // which mappings are this process's, and the fork/exec paths
            // maintain it for every mapping source (mmap, mremap, brk, the
            // loader's stack); reserved mappings carry empty `VmFlags` and
            // are skipped as before.
            //
            // What is released is the *intersection* with `owned_ranges`, never a whole tracked
            // mapping that merely overlaps it. The page manager coalesces adjacent ranges with
            // identical properties into a single entry (see `PageManager::mappings`), and
            // adjacency between this process's memory and a suspended sibling's is not a
            // coincidence here: `Vmem::get_unmmaped_area` hands out the address immediately below
            // an existing range, so a forked child's very first anonymous `mmap` lands flush
            // against whatever its parent had there. Observed live, exactly so: the
            // `execSync("/bin/sh -c ...")` child `mmap`ed 16 KiB that abutted 48 KiB of its
            // parent's musl heap, and (via `mprotect`) another 16 KiB that abutted 160 KiB more
            // of it -- four of the parent's ranges the manager had silently merged into two of
            // this process's -- and a whole-entry release then unmapped all 208 KiB of the
            // parent's, which died on the first libc global it touched after taking its address
            // space back.
            let owned = self.process().owned_ranges.lock();
            // A live `/dev/fb0` guest mapping (see `do_mmap_framebuffer`) whose pages this
            // release is about to free must be deregistered first -- the framebuffer would
            // otherwise keep reading freed memory. A sibling's registration is not in this
            // process's `owned_ranges` and is left alone.
            if let Some(fb) = self.global.framebuffer.as_ref()
                && let Some((fb_addr, fb_len)) = fb.guest_mapping()
                && owned
                    .intersect(&(fb_addr..fb_addr.saturating_add(fb_len)))
                    .next()
                    .is_some()
            {
                fb.clear_guest_mapping_overlapping(fb_addr, fb_len);
            }
            let release = |r: Range<usize>, vm: VmFlags| {
                if vm.is_empty() {
                    Vec::new()
                } else {
                    owned.intersect(&r).collect::<Vec<_>>()
                }
            };
            if let Err(error) = unsafe { self.global.pm.release_memory(release) } {
                litebox_util_log::error!(error:? = error; "execve: failed to release old mappings");
                self.exit_group(ExitStatus::Signal(
                    litebox_common_linux::signal::Signal::SIGKILL,
                ));
                return Err(error.into());
            }
        }

        // Either the old mappings are gone or (for a `fork`ed child) they were never this
        // process's to begin with. `load_program` re-populates this as it maps the new image.
        self.process().owned_ranges.lock().clear();
        self.process().elf_patch_cache.lock().clear();

        if let Err(error) = self
            .global
            .platform
            .set_arch_specific_register(&GUEST_TLS_REGISTER, 0)
        {
            litebox_util_log::error!(error:? = error; "execve: failed to clear guest TLS");
            self.exit_group(ExitStatus::Signal(
                litebox_common_linux::signal::Signal::SIGKILL,
            ));
            return Err(Errno::EIO);
        }

        if let Err(error) = self.load_program_with_credentials(
            loader,
            argv_vec,
            envp_vec,
            exec_credentials,
            secure_exec,
        ) {
            self.exit_group(ExitStatus::Signal(
                litebox_common_linux::signal::Signal::SIGKILL,
            ));
            return Err(error.into());
        }

        self.init_thread_context(ctx);
        // The new image is fully built, at addresses no other member of the old address space
        // owns, so this task no longer needs the shared one. Handing it back here rather than
        // earlier means no other member ever observes a half-built image. A vfork child that
        // forked while on its parent's memory hands its place to the parent it is about to wake
        // instead: the family is the parent's memory, and the parent runs on it next.
        if shares_parent_vm {
            self.hand_address_space_to_vfork_parent();
        } else {
            let _ = self.leave_address_space();
        }
        self.process().complete_vfork();
        Ok(0)
    }

    /// Loads the specified program into the process's address space and prepares the thread
    /// to start executing it.
    pub(crate) fn load_program(
        &self,
        loader: crate::loader::elf::ElfLoader<'_, Platform, FS>,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
    ) -> Result<(), crate::loader::elf::ElfLoaderError> {
        let (credentials, secure) = self.credentials_for_exec(loader.main_status());
        self.load_program_with_credentials(loader, argv, envp, credentials, secure)
    }

    fn load_program_with_credentials(
        &self,
        mut loader: crate::loader::elf::ElfLoader<'_, Platform, FS>,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
        credentials: Arc<Credentials>,
        secure: bool,
    ) -> Result<(), crate::loader::elf::ElfLoaderError> {
        let mut proc_cmdline = Vec::new();
        for arg in &argv {
            proc_cmdline.extend_from_slice(arg.as_bytes());
            proc_cmdline.push(0);
        }

        // The loader publishes the new image's initial break through the (single, shared) page
        // manager; take it back out into this process's own slot, restoring the manager's
        // "no break set" sentinel, so that a sibling process's break is unaffected. See
        // `Process::brk`.
        let load_info = {
            let _guard = self.global.brk_lock.lock();
            let auxv = self.init_auxv(credentials.as_ref(), secure);
            let load_info = loader.load(argv, envp, auxv);
            // Take the break back out even when the load failed part-way: a loader that already
            // published one and then bailed would otherwise leave it in the manager for the
            // next image (any process) to inherit.
            let initial_brk = self.global.pm.swap_brk(0);
            let load_info = load_info?;
            if initial_brk == 0 {
                // The loader did not publish a break for this image; the first `brk` this
                // process makes will fail (see `PageManager::brk`'s zero-break refusal) and
                // its libc will fall back to mmap. Loud, because it means a loader path
                // skipped `set_initial_brk` -- the root cause worth fixing.
                litebox_util_log::warn!(pid:? = self.pid; "execve: loader left no initial brk");
            }
            self.process().brk.store(initial_brk, Ordering::Relaxed);
            load_info
        };

        // Commit the candidate credentials only after every fallible image-building step succeeded.
        *self.credentials.borrow_mut() = credentials;
        // Linux: `setup_new_exec` makes an ordinary exec dumpable again and a secure (set-uid/
        // set-gid) one not, per the default `suid_dumpable` of 0.
        self.process().set_dumpable(!secure);
        if secure {
            // Linux `begin_new_exec`: "Make sure parent cannot signal privileged process."
            self.thread.parent_death_signal.set(None);
            self.global
                .processes
                .set_parent_death_signal(self.pid, None);
        }
        let staged = self.thread.staged_exec.borrow_mut().take();
        let (exe, comm) =
            staged.map_or((None, None), |staged| (Some(staged.exe), Some(staged.comm)));
        self.process().set_proc_image(proc_cmdline, exe);
        self.set_task_comm(comm.as_deref().unwrap_or_else(|| loader.comm()));
        // Every process with an image is reachable through the live table from here on, so
        // `/proc/<pid>` and `kill(pid)` work for it whether or not it ever forks.
        self.register_for_remote_signals();

        self.thread
            .init_state
            .set(ThreadInitState::NewProcess(load_info));
        Ok(())
    }

    pub(crate) fn handle_init_request(&self, ctx: &mut litebox_common_linux::PtRegs) {
        if !self.process().await_launch() {
            self.thread.remote.is_exiting.store(true, Ordering::Release);
            return;
        }
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
                #[cfg(target_arch = "aarch64")]
                {
                    // A fresh aarch64 process starts with every general-purpose
                    // register cleared, `sp` at the top of the initial stack and
                    // `pc` at the entry point. `pstate` starts at 0, which is
                    // EL0t/AArch64 with no flags set and nothing masked --
                    // exactly what `SAFE_USER_PSTATE` permits.
                    *ctx = litebox_common_linux::PtRegs {
                        regs: [0; litebox_common_linux::AARCH64_GENERAL_REGISTER_COUNT],
                        sp: load_info.user_stack_top,
                        pc: load_info.entry_point,
                        pstate: 0,
                        orig_x0: 0,
                        // No syscall is in flight on entry.
                        syscallno: -1,
                        unused2: 0,
                    };
                }
            }
            ThreadInitState::NewThread {
                tls,
                stack,
                set_child_tid,
                #[cfg(target_arch = "aarch64")]
                fp,
            } => {
                // Set the stack and the return value from clone().
                #[cfg(target_arch = "x86_64")]
                {
                    if let Some(stack) = stack {
                        ctx.rsp = stack;
                    }
                    ctx.rax = 0;
                }
                #[cfg(target_arch = "aarch64")]
                {
                    if let Some(stack) = stack {
                        ctx.sp = stack;
                    }
                    // `clone` returns 0 in the child, in x0.
                    ctx.regs[0] = 0;
                }

                // Set the TLS for the new thread.
                if let Some(tls) = tls {
                    self.global
                        .platform
                        .set_arch_specific_register(&GUEST_TLS_REGISTER, tls.as_usize())
                        .expect("failed to set guest TLS for new thread");
                }

                // Linux's `copy_thread` copies the parent's FPSIMD register
                // file into the child task at clone/fork time; this new host
                // OS thread's own per-thread FP shadow otherwise starts
                // zeroed (correct only for `execve`, see `NewProcess` above),
                // so seed it here with the snapshot taken on the parent
                // thread at the `clone`/`fork` syscall itself.
                #[cfg(target_arch = "aarch64")]
                self.global.platform.set_fp_state(&fp);

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
    use core::time::Duration;

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

    /// Reproduces the V8-startup-abort scenario this row was filed for: V8's own startup code
    /// aborts the whole process if `clock_gettime` returns an error for any of these clock IDs.
    /// Before this change, `ClockId::try_from` rejected everything but `RealTime`/`Monotonic`/
    /// `MonotonicCoarse`, so a real guest binary probing any of the other five clocks at startup
    /// (as V8 does) would see `clock_gettime` fail and abort. Verifies every clock ID Linux
    /// actually defines round-trips successfully through the real syscall path (`sys_clock_gettime`
    /// on `MacOsUserland`/`LinuxUserland`/`WindowsUserland`, backed by real host clocks -- not a
    /// mock), and returns a plausible (non-negative) value.
    #[test]
    fn test_clock_gettime_and_getres_succeed_for_every_clock_id() {
        use litebox_common_linux::{ClockId, TimeParam, Timespec};

        let task = crate::syscalls::tests::init_platform(None);

        for clock_id in [
            ClockId::RealTime,
            ClockId::Monotonic,
            ClockId::ProcessCpuTime,
            ClockId::ThreadCpuTime,
            ClockId::MonotonicRaw,
            ClockId::RealTimeCoarse,
            ClockId::MonotonicCoarse,
            ClockId::Boottime,
        ] {
            let mut ts = Timespec {
                tv_sec: -1,
                tv_nsec: 0,
            };
            let ptr = UserPtrMut::from_ptr(&raw mut ts);
            task.sys_clock_gettime(clock_id, TimeParam::Timespec64(ptr))
                .unwrap_or_else(|e| {
                    panic!(
                        "clock_gettime({clock_id:?}) unexpectedly failed with {e:?} -- this is \
                         exactly the error that makes V8 abort at startup"
                    )
                });
            assert!(
                ts.tv_sec >= 0,
                "clock_gettime({clock_id:?}) returned a nonsensical negative tv_sec: {}",
                ts.tv_sec
            );
            assert!(
                ts.tv_nsec < 1_000_000_000,
                "clock_gettime({clock_id:?}) returned an out-of-range tv_nsec: {}",
                ts.tv_nsec
            );

            let mut res = Timespec {
                tv_sec: -1,
                tv_nsec: 0,
            };
            let res_ptr = UserPtrMut::from_ptr(&raw mut res);
            task.sys_clock_getres(clock_id, TimeParam::Timespec64(res_ptr))
                .unwrap_or_else(|e| {
                    panic!("clock_getres({clock_id:?}) unexpectedly failed: {e:?}")
                });
            assert!(
                res.tv_sec > 0 || res.tv_nsec > 0,
                "clock_getres({clock_id:?}) reported a zero resolution"
            );
        }
    }

    /// The newly added monotonic-family clocks (`CLOCK_MONOTONIC_RAW`, `CLOCK_BOOTTIME`) must
    /// behave like real monotonic clocks: never go backwards, and actually advance across real
    /// elapsed wall-clock time.
    #[test]
    fn test_clock_gettime_monotonic_raw_and_boottime_are_monotonic() {
        use litebox_common_linux::{ClockId, TimeParam, Timespec};

        let task = crate::syscalls::tests::init_platform(None);

        let read = |clock_id: ClockId| -> Duration {
            let mut ts = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ptr = UserPtrMut::from_ptr(&raw mut ts);
            task.sys_clock_gettime(clock_id, TimeParam::Timespec64(ptr))
                .unwrap_or_else(|e| panic!("clock_gettime({clock_id:?}) failed: {e:?}"));
            Duration::try_from(ts).expect("valid timespec")
        };

        for clock_id in [ClockId::MonotonicRaw, ClockId::Boottime] {
            let before = read(clock_id);
            std::thread::sleep(Duration::from_millis(50));
            let after = read(clock_id);
            assert!(
                after > before,
                "{clock_id:?} did not advance across a real 50ms sleep: before={before:?} after={after:?}"
            );
        }
    }

    /// Real, host-sourced CPU-time accounting: `CLOCK_THREAD_CPUTIME_ID` must genuinely advance
    /// while the thread burns real CPU, and must *not* advance (by anywhere close to the same
    /// amount) while the thread is merely sleeping -- proving this isn't wall-clock time
    /// silently mislabeled as CPU time.
    #[test]
    fn test_clock_gettime_thread_cpu_time_tracks_real_cpu_usage_not_wall_clock() {
        use litebox_common_linux::{ClockId, TimeParam, Timespec};

        let task = crate::syscalls::tests::init_platform(None);

        let read_thread_cpu_time = || -> Duration {
            let mut ts = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ptr = UserPtrMut::from_ptr(&raw mut ts);
            task.sys_clock_gettime(ClockId::ThreadCpuTime, TimeParam::Timespec64(ptr))
                .expect("clock_gettime(CLOCK_THREAD_CPUTIME_ID) failed");
            Duration::try_from(ts).expect("valid timespec")
        };

        let before_busy = read_thread_cpu_time();

        // Burn real CPU on this thread. `std::hint::black_box` keeps the optimizer from
        // eliminating the loop.
        let mut acc: u64 = 0;
        for i in 0..300_000_000u64 {
            acc = std::hint::black_box(acc.wrapping_add(std::hint::black_box(i)));
        }
        std::hint::black_box(acc);

        let after_busy = read_thread_cpu_time();
        assert!(
            after_busy > before_busy,
            "thread CPU time did not increase after a real busy loop: before={before_busy:?} \
             after={after_busy:?}"
        );
        let consumed_by_busy_loop = after_busy.saturating_sub(before_busy);
        assert!(
            consumed_by_busy_loop > Duration::from_millis(1),
            "expected a meaningful amount of CPU time consumed by the busy loop, got \
             {consumed_by_busy_loop:?}"
        );

        // Sleep for much longer than the busy loop took, without doing any CPU work, and
        // confirm thread CPU time barely moves.
        std::thread::sleep(Duration::from_millis(300));
        let after_sleep = read_thread_cpu_time();
        let consumed_by_sleep = after_sleep.saturating_sub(after_busy);
        assert!(
            consumed_by_sleep < Duration::from_millis(100),
            "thread CPU time advanced by {consumed_by_sleep:?} across a 300ms *sleep* (no CPU \
             work performed) -- real CPU-time accounting should barely move here, this looks \
             like wall-clock time mislabeled as CPU time"
        );
    }

    /// `CLOCK_PROCESS_CPUTIME_ID` sums CPU time across the whole process; it must at least
    /// reflect the real CPU work done by the calling thread (the only thread in this test).
    #[test]
    fn test_clock_gettime_process_cpu_time_tracks_real_cpu_usage() {
        use litebox_common_linux::{ClockId, TimeParam, Timespec};

        let task = crate::syscalls::tests::init_platform(None);

        let read_process_cpu_time = || -> Duration {
            let mut ts = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ptr = UserPtrMut::from_ptr(&raw mut ts);
            task.sys_clock_gettime(ClockId::ProcessCpuTime, TimeParam::Timespec64(ptr))
                .expect("clock_gettime(CLOCK_PROCESS_CPUTIME_ID) failed");
            Duration::try_from(ts).expect("valid timespec")
        };

        let before = read_process_cpu_time();
        let mut acc: u64 = 0;
        for i in 0..300_000_000u64 {
            acc = std::hint::black_box(acc.wrapping_add(std::hint::black_box(i)));
        }
        std::hint::black_box(acc);
        let after = read_process_cpu_time();

        assert!(
            after > before,
            "process CPU time did not increase after a real busy loop: before={before:?} \
             after={after:?}"
        );
    }

    /// `clock_nanosleep` against a CPU-time clock can never wake up (a blocked thread cannot
    /// accumulate CPU time), so real Linux rejects it outright; confirm LiteBox does too now that
    /// these clock IDs are otherwise recognized.
    #[test]
    fn test_clock_nanosleep_rejects_cpu_time_clocks() {
        use litebox_common_linux::{ClockId, TimeParam, Timespec};

        let task = crate::syscalls::tests::init_platform(None);

        for clock_id in [ClockId::ProcessCpuTime, ClockId::ThreadCpuTime] {
            let mut request = Timespec {
                tv_sec: 0,
                tv_nsec: 1,
            };
            let result = task.sys_clock_nanosleep(
                clock_id,
                litebox_common_linux::TimerFlags::empty(),
                TimeParam::Timespec64(UserPtrMut::from_ptr(&raw mut request)),
                TimeParam::None,
            );
            assert_eq!(
                result,
                Err(litebox_common_linux::errno::Errno::EINVAL),
                "clock_nanosleep({clock_id:?}) should be rejected with EINVAL"
            );
        }
    }

    /// `sched_getscheduler`/`sched_setscheduler` round-trip: every thread is always reported as
    /// (and can always be, as a no-op, "set" to) `SCHED_OTHER`, matching what any real guest
    /// program checking "did the syscall succeed, and is the policy the plain default" would
    /// see.
    #[test]
    fn test_sched_getscheduler_and_setscheduler_round_trip() {
        use litebox_common_linux::sched_policy::SCHED_OTHER;

        let task = crate::syscalls::tests::init_platform(None);

        assert_eq!(
            task.sys_sched_getscheduler(None),
            Ok(usize::try_from(SCHED_OTHER).unwrap())
        );

        let param = litebox_common_linux::SchedParam { sched_priority: 0 };
        let param_ptr = UserPtr::from_ptr(&raw const param);
        assert_eq!(
            task.sys_sched_setscheduler(None, SCHED_OTHER, param_ptr),
            Ok(0)
        );

        // Also works when explicitly targeting our own tid (pid == 0 and pid == self.tid are
        // both "self", matching real Linux semantics for these thread-granularity syscalls).
        assert_eq!(
            task.sys_sched_getscheduler(Some(task.sys_gettid())),
            Ok(usize::try_from(SCHED_OTHER).unwrap())
        );
    }

    /// Real, unprivileged-process-accurate rejection: LiteBox guests never have `CAP_SYS_NICE`,
    /// so real-time policies must be rejected with `EPERM`, exactly as they would be on a real
    /// unprivileged Linux process. Also checks the ordinary `EINVAL` cases (unknown policy,
    /// out-of-range priority for `SCHED_OTHER`).
    #[test]
    fn test_sched_setscheduler_rejects_real_time_policies_and_bad_priority() {
        use litebox_common_linux::errno::Errno;
        use litebox_common_linux::sched_policy::{
            SCHED_DEADLINE, SCHED_FIFO, SCHED_OTHER, SCHED_RR,
        };

        let task = crate::syscalls::tests::init_platform(None);

        let param_zero = litebox_common_linux::SchedParam { sched_priority: 0 };
        let param_zero_ptr = UserPtr::from_ptr(&raw const param_zero);

        for policy in [SCHED_FIFO, SCHED_RR, SCHED_DEADLINE] {
            assert_eq!(
                task.sys_sched_setscheduler(None, policy, param_zero_ptr),
                Err(Errno::EPERM),
                "real-time policy {policy} should be rejected with EPERM (no CAP_SYS_NICE)"
            );
        }

        // An unrecognized policy value is EINVAL, not EPERM.
        assert_eq!(
            task.sys_sched_setscheduler(None, 0x1234, param_zero_ptr),
            Err(Errno::EINVAL)
        );

        // SCHED_OTHER only accepts priority 0.
        let param_nonzero = litebox_common_linux::SchedParam { sched_priority: 5 };
        let param_nonzero_ptr = UserPtr::from_ptr(&raw const param_nonzero);
        assert_eq!(
            task.sys_sched_setscheduler(None, SCHED_OTHER, param_nonzero_ptr),
            Err(Errno::EINVAL)
        );
    }

    /// `sched_getparam`/`sched_setparam` round-trip.
    #[test]
    fn test_sched_getparam_setparam_round_trip() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);

        let mut got = litebox_common_linux::SchedParam { sched_priority: -1 };
        let got_ptr = UserPtrMut::from_ptr(&raw mut got);
        assert_eq!(task.sys_sched_getparam(None, got_ptr), Ok(0));
        assert_eq!(got.sched_priority, 0);

        let set = litebox_common_linux::SchedParam { sched_priority: 0 };
        let set_ptr = UserPtr::from_ptr(&raw const set);
        assert_eq!(task.sys_sched_setparam(None, set_ptr), Ok(0));

        let bad = litebox_common_linux::SchedParam { sched_priority: 1 };
        let bad_ptr = UserPtr::from_ptr(&raw const bad);
        assert_eq!(task.sys_sched_setparam(None, bad_ptr), Err(Errno::EINVAL));
    }

    /// None of the four `sched_*` syscalls can honestly answer for a thread other than the
    /// caller (LiteBox tracks no state for one), so a pid that isn't "self" must fail with
    /// `ESRCH`, matching what real Linux would do for a genuinely nonexistent target thread.
    #[test]
    fn test_sched_calls_reject_a_remote_pid() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        let remote_pid = task.sys_gettid().wrapping_add(999_999);

        assert_eq!(
            task.sys_sched_getscheduler(Some(remote_pid)),
            Err(Errno::ESRCH)
        );

        let mut param = litebox_common_linux::SchedParam { sched_priority: 0 };
        let param_ptr = UserPtrMut::from_ptr(&raw mut param);
        assert_eq!(
            task.sys_sched_getparam(Some(remote_pid), param_ptr),
            Err(Errno::ESRCH)
        );

        let set_param = litebox_common_linux::SchedParam { sched_priority: 0 };
        let set_param_ptr = UserPtr::from_ptr(&raw const set_param);
        assert_eq!(
            task.sys_sched_setparam(Some(remote_pid), set_param_ptr),
            Err(Errno::ESRCH)
        );
        assert_eq!(
            task.sys_sched_setscheduler(
                Some(remote_pid),
                litebox_common_linux::sched_policy::SCHED_OTHER,
                set_param_ptr
            ),
            Err(Errno::ESRCH)
        );
    }

    /// `setpgid(0, N)` followed by `getpgid` (both `pid == 0` and the caller's own pid) must
    /// observe `N`.
    #[test]
    fn test_setpgid_getpgid_self_round_trip() {
        let task = crate::syscalls::tests::init_platform(None);

        assert_eq!(task.sys_setpgid(0, 4242), Ok(()));
        assert_eq!(task.sys_getpgid(0), Ok(4242));
        assert_eq!(task.sys_getpgid(task.pid), Ok(4242));
        assert_eq!(task.sys_setpgid(0, 4242), Ok(()));
        assert_eq!(task.sys_getpgid(0), Ok(4242));
    }

    /// `setpgid(pid, 0)` means "make `pid` its own group leader" -- real `setpgid`'s
    /// well-known zero-pgid convention, used by busybox `ash` to start a new job.
    #[test]
    fn test_setpgid_zero_pgid_targets_own_pid() {
        let task = crate::syscalls::tests::init_platform(None);

        assert_eq!(task.sys_setpgid(0, 4242), Ok(()));
        assert_eq!(task.sys_setpgid(0, 0), Ok(()));
        assert_eq!(task.sys_getpgid(0), Ok(task.pid));
    }

    #[test]
    fn test_setpgid_rejects_negative_pgid() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);

        assert_eq!(task.sys_setpgid(0, -1), Err(Errno::EINVAL));
    }

    /// A pid this shim cannot vouch for (neither the caller nor a recorded child) is `ESRCH` for
    /// both syscalls, matching real Linux's response to a genuinely nonexistent target.
    #[test]
    fn test_setpgid_getpgid_reject_unrelated_pid() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        let unrelated_pid = task.pid.wrapping_add(999_999);

        assert_eq!(task.sys_getpgid(unrelated_pid), Err(Errno::ESRCH));
        assert_eq!(task.sys_setpgid(unrelated_pid, 4242), Err(Errno::ESRCH));
    }

    /// A live child (registered exactly as `do_fork` registers it) is a permitted
    /// `setpgid`/`getpgid` target. Updating it must not alter the parent's own process group.
    #[test]
    fn test_setpgid_getpgid_accept_a_live_child() {
        let parent = crate::syscalls::tests::init_platform(None);
        let child = parent
            .global
            .clone()
            .new_test_task(parent.files.borrow().fs.clone());
        parent.global.processes.add_child(child.pid, parent.pid);
        parent.global.processes.register_process(
            child.pid,
            child.remote_signal_target(),
            child.process(),
        );

        assert_eq!(parent.sys_setpgid(0, 3131), Ok(()));
        assert_eq!(parent.sys_setpgid(child.pid, 4242), Ok(()));
        assert_eq!(parent.sys_getpgid(child.pid), Ok(4242));
        assert_eq!(child.sys_getpgid(0), Ok(4242));
        assert_eq!(parent.sys_getpgid(0), Ok(3131));
    }

    /// Threads of one process share one group identity. The channels impose an explicit
    /// happens-before order between writes, so both threads and the original task must observe the
    /// second write after first observing the first.
    #[test]
    fn test_setpgid_threads_share_happens_before_order() {
        let task = crate::syscalls::tests::init_platform(None);
        let first = task.clone_for_test().expect("clone first test thread");
        let second = task.clone_for_test().expect("clone second test thread");
        let (first_done_tx, first_done_rx) = std::sync::mpsc::channel();
        let (second_done_tx, second_done_rx) = std::sync::mpsc::channel();

        let first_handle = std::thread::spawn(move || {
            let first_write = first.sys_setpgid(0, 3131);
            first_done_tx.send(()).expect("publish first write");
            second_done_rx.recv().expect("await second write");
            (first_write, first.sys_getpgid(0))
        });
        let second_handle = std::thread::spawn(move || {
            first_done_rx.recv().expect("await first write");
            let after_first = second.sys_getpgid(0);
            let second_write = second.sys_setpgid(0, 4242);
            second_done_tx.send(()).expect("publish second write");
            (after_first, second_write)
        });

        assert_eq!(
            second_handle.join().expect("second test thread"),
            (Ok(3131), Ok(()))
        );
        assert_eq!(
            first_handle.join().expect("first test thread"),
            (Ok(()), Ok(4242))
        );
        assert_eq!(task.sys_getpgid(0), Ok(4242));
    }

    /// Process-group identity belongs to a process, not the shim. Each barrier round puts writes
    /// from two independent processes in the same concurrency window, then makes both reads happen
    /// only after both writes. A shim-global group would therefore deterministically make at least
    /// one observation wrong in every round.
    #[test]
    fn test_setpgid_is_isolated_between_concurrent_independent_processes() {
        const ROUNDS: i32 = 64;

        let first = crate::syscalls::tests::init_platform(None);
        let second = first
            .global
            .clone()
            .new_test_task(first.files.borrow().fs.clone());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let first_barrier = barrier.clone();

        let first_handle = std::thread::spawn(move || {
            let mut observations = std::vec::Vec::new();
            for round in 0..ROUNDS {
                first_barrier.wait();
                let expected = 10_000 + round;
                let write = first.sys_setpgid(0, expected);
                first_barrier.wait();
                observations.push((expected, write, first.sys_getpgid(0)));
                first_barrier.wait();
            }
            observations
        });
        let second_handle = std::thread::spawn(move || {
            let mut observations = std::vec::Vec::new();
            for round in 0..ROUNDS {
                barrier.wait();
                let expected = 20_000 + round;
                let write = second.sys_setpgid(0, expected);
                barrier.wait();
                observations.push((expected, write, second.sys_getpgid(0)));
                barrier.wait();
            }
            observations
        });

        for (expected, write, observed) in first_handle.join().expect("first test process") {
            assert_eq!(write, Ok(()));
            assert_eq!(observed, Ok(expected));
        }
        for (expected, write, observed) in second_handle.join().expect("second test process") {
            assert_eq!(write, Ok(()));
            assert_eq!(observed, Ok(expected));
        }
    }

    #[test]
    fn test_prctl_set_get_parent_death_signal() {
        use litebox_common_linux::PrctlArg;
        use litebox_common_linux::signal::Signal;

        let task = crate::syscalls::tests::init_platform(None);
        let mut value = -1i32;
        let value_ptr = UserPtrMut::from_ptr(&raw mut value);

        task.sys_prctl(PrctlArg::GetPDeathSig(value_ptr))
            .expect("initial PR_GET_PDEATHSIG failed");
        assert_eq!(value, 0);

        task.sys_prctl(PrctlArg::SetPDeathSig(Some(Signal::SIGKILL)))
            .expect("PR_SET_PDEATHSIG failed");
        task.sys_prctl(PrctlArg::GetPDeathSig(value_ptr))
            .expect("PR_GET_PDEATHSIG failed");
        assert_eq!(value, Signal::SIGKILL.as_i32());

        task.sys_prctl(PrctlArg::SetPDeathSig(None))
            .expect("clearing PR_SET_PDEATHSIG failed");
        task.sys_prctl(PrctlArg::GetPDeathSig(value_ptr))
            .expect("PR_GET_PDEATHSIG after clear failed");
        assert_eq!(value, 0);
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
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
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

        let _guard = crate::syscalls::tests::async_signal_guard();
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
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
            // The upper bound guards against the alarm firing early; the lower
            // bound only bounds scheduler lateness, which loaded CI runners
            // stretch past 100 ms (witnessed: 1888 on the CI macOS runner).
            assert!(
                (1500..=2100).contains(&millis),
                "expected ~2s remaining, got {millis:?}"
            );

            let elapsed_ms = elapsed.as_millis();
            std::println!("Alarm fired after {elapsed_ms} ms");
            // The lower bound guards against the alarm firing early; the
            // upper bound only bounds scheduler lateness on loaded runners.
            assert!(
                (900..=1500).contains(&elapsed_ms),
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

        let _guard = crate::syscalls::tests::async_signal_guard();
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
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

        let _guard = crate::syscalls::tests::async_signal_guard();
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
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

        let _guard = crate::syscalls::tests::async_signal_guard();
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
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

        let _guard = crate::syscalls::tests::async_signal_guard();
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
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

    #[test]
    fn test_setuid_privileged_sets_uid_and_euid() {
        let task = crate::syscalls::tests::init_platform(None);
        assert_eq!(task.sys_getuid(), 0);

        task.sys_setuid(1000)
            .expect("privileged setuid to an arbitrary uid should succeed");
        assert_eq!(task.sys_getuid(), 1000);
        assert_eq!(task.sys_geteuid(), 1000);
    }

    #[test]
    fn test_setuid_unprivileged_restricted_to_current_ids() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        task.sys_setuid(1000)
            .expect("privileged setuid should succeed");

        // No longer privileged: switching to its own uid is a no-op success...
        task.sys_setuid(1000)
            .expect("setuid to the caller's own uid should succeed");
        // ...but becoming any other uid is not.
        let err = task.sys_setuid(0).unwrap_err();
        assert_eq!(err, Errno::EPERM);
        assert_eq!(task.sys_getuid(), 1000);
    }

    #[test]
    fn test_setgid_privileged_sets_gid_and_egid() {
        let task = crate::syscalls::tests::init_platform(None);
        assert_eq!(task.sys_getgid(), 0);

        task.sys_setgid(1000)
            .expect("privileged setgid to an arbitrary gid should succeed");
        assert_eq!(task.sys_getgid(), 1000);
        assert_eq!(task.sys_getegid(), 1000);
    }

    #[test]
    fn test_setgid_unprivileged_restricted_to_current_ids() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        // The privilege check keys off euid, not gid, so pick a gid while
        // still privileged, then drop uid to make the calls below run
        // unprivileged and confirm the gid check isn't secretly keying off uid.
        task.sys_setgid(2000)
            .expect("privileged setgid should succeed");
        task.sys_setuid(1000)
            .expect("privileged setuid should succeed");

        task.sys_setgid(2000)
            .expect("setgid to the caller's own gid should succeed");
        let err = task.sys_setgid(0).unwrap_err();
        assert_eq!(err, Errno::EPERM);
        assert_eq!(task.sys_getgid(), 2000);
    }

    #[test]
    fn test_setuid_does_not_affect_sibling_thread_credentials() {
        let task = crate::syscalls::tests::init_platform(None);
        let sibling = task
            .clone_for_test()
            .expect("clone_for_test should succeed");

        task.sys_setuid(1000).expect("setuid should succeed");

        assert_eq!(task.sys_getuid(), 1000);
        assert_eq!(sibling.sys_getuid(), 0);
    }

    #[test]
    fn test_setgroups_getgroups_round_trip_boundaries_and_copy_on_write() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        let null_list = UserPtr::from_usize(0);
        let null_out = UserPtrMut::from_usize(0);

        assert_eq!(task.sys_getgroups(0, null_out), Ok(0));
        assert_eq!(task.sys_getgroups(-1, null_out), Err(Errno::EINVAL));

        let input = [41u32, 7, 41];
        task.sys_setgroups(input.len(), UserPtr::from_ptr(input.as_ptr()))
            .expect("root setgroups should succeed");
        assert_eq!(task.sys_getgroups(0, null_out), Ok(input.len()));

        let mut short = [u32::MAX; 2];
        assert_eq!(
            task.sys_getgroups(2, UserPtrMut::from_ptr(short.as_mut_ptr())),
            Err(Errno::EINVAL)
        );
        assert_eq!(short, [u32::MAX; 2]);

        let mut output = [0u32; 3];
        assert_eq!(
            task.sys_getgroups(3, UserPtrMut::from_ptr(output.as_mut_ptr())),
            Ok(3)
        );
        assert_eq!(output, [7, 41, 41]);

        let sibling = task
            .clone_for_test()
            .expect("clone_for_test should succeed");
        let sibling_input = [9u32];
        sibling
            .sys_setgroups(
                sibling_input.len(),
                UserPtr::from_ptr(sibling_input.as_ptr()),
            )
            .expect("sibling setgroups should succeed");
        let mut sibling_output = [0u32; 1];
        assert_eq!(
            sibling.sys_getgroups(1, UserPtrMut::from_ptr(sibling_output.as_mut_ptr()),),
            Ok(1)
        );
        assert_eq!(sibling_output, sibling_input);
        assert_eq!(
            task.sys_getgroups(3, UserPtrMut::from_ptr(output.as_mut_ptr())),
            Ok(3)
        );
        assert_eq!(output, [7, 41, 41]);

        assert_eq!(task.sys_setgroups(1, null_list), Err(Errno::EFAULT));
        assert_eq!(
            task.sys_setgroups(super::SupplementaryGroups::MAX + 1, null_list),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            task.sys_getgroups(3, UserPtrMut::from_ptr(output.as_mut_ptr())),
            Ok(3)
        );
        assert_eq!(output, [7, 41, 41]);

        task.sys_setuid(1000).expect("setuid should succeed");
        let denied_input = [11u32];
        assert_eq!(
            task.sys_setgroups(denied_input.len(), UserPtr::from_ptr(denied_input.as_ptr()),),
            Err(Errno::EPERM)
        );
        assert_eq!(
            task.sys_getgroups(3, UserPtrMut::from_ptr(output.as_mut_ptr())),
            Ok(3)
        );
        assert_eq!(output, [7, 41, 41]);

        sibling
            .sys_setgroups(0, null_list)
            .expect("setgroups with size zero should clear the set");
        assert_eq!(sibling.sys_getgroups(0, null_out), Ok(0));
    }

    #[test]
    fn test_prlimit_own_pid_is_self() {
        let task = crate::syscalls::tests::init_platform(None);

        task.sys_prlimit(
            task.pid,
            litebox_common_linux::RlimitResource::NOFILE,
            None,
            None,
        )
        .expect("own pid should be treated the same as pid 0");
        task.sys_prlimit(0, litebox_common_linux::RlimitResource::NOFILE, None, None)
            .expect("pid 0 should still mean self");
    }

    #[test]
    fn test_get_robust_list_own_tid_is_self() {
        let task = crate::syscalls::tests::init_platform(None);

        let mut head_via_tid: usize = 0;
        task.sys_get_robust_list(Some(task.tid), UserPtrMut::from_ptr(&raw mut head_via_tid))
            .expect("own tid should be treated the same as pid None");

        let mut head_via_none: usize = 0;
        task.sys_get_robust_list(None, UserPtrMut::from_ptr(&raw mut head_via_none))
            .expect("None should still mean self");

        assert_eq!(head_via_tid, head_via_none);
    }

    /// Real threads, real `sys_futex` syscalls: `FUTEX_REQUEUE` must wake exactly
    /// `num_to_wake` waiters directly and *move* the rest onto the second futex word's own wait
    /// queue without waking them -- provable only by observing that the requeued waiters stay
    /// blocked until a separate, later `FUTEX_WAKE` on the new address, not merely that every
    /// thread eventually finishes.
    #[test]
    fn test_futex_requeue_across_real_threads() {
        use litebox_common_linux::{FutexArgs, FutexFlags, TimeParam};
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicUsize, Ordering};

        const N: usize = 4;
        const NUM_TO_WAKE: u32 = 1;

        let task = crate::syscalls::tests::init_platform(None);

        // Real, shared guest-visible memory for both futex words; each spawned thread reaches it
        // via the raw address (a `Send` `usize`), reconstructing the pointer on its own thread,
        // exactly as translated syscall arguments would be.
        let mut futex1: u32 = 0;
        let mut futex2: u32 = 0;
        let futex1_addr = core::ptr::from_mut(&mut futex1) as usize;
        let futex2_addr = core::ptr::from_mut(&mut futex2) as usize;

        let completed = std::sync::Arc::new(AtomicUsize::new(0));
        let ready = std::sync::Arc::new(Barrier::new(N + 1));

        let waiters: std::vec::Vec<_> = (0..N)
            .map(|_| {
                let completed = std::sync::Arc::clone(&completed);
                let ready = std::sync::Arc::clone(&ready);
                task.spawn_clone_for_test(move |task| {
                    ready.wait();
                    let result = task.sys_futex(FutexArgs::Wait {
                        addr: UserPtrMut::from_usize(futex1_addr),
                        flags: FutexFlags::PRIVATE,
                        val: 0,
                        timeout: TimeParam::Milliseconds(10_000),
                    });
                    completed.fetch_add(1, Ordering::SeqCst);
                    result
                })
            })
            .collect();

        ready.wait(); // release all N waiters together
        std::thread::sleep(core::time::Duration::from_millis(100)); // let them genuinely block

        let woken = task
            .sys_futex(FutexArgs::Requeue {
                addr: UserPtrMut::from_usize(futex1_addr),
                flags: FutexFlags::PRIVATE,
                num_to_wake: NUM_TO_WAKE,
                num_to_requeue: u32::try_from(N).unwrap() - NUM_TO_WAKE,
                addr2: UserPtrMut::from_usize(futex2_addr),
            })
            .expect("futex requeue failed");
        assert_eq!(
            N, woken,
            "futex(FUTEX_REQUEUE) returns the total woken-or-requeued count, not just the wake \
             count"
        );

        // Give the directly-woken waiter(s) ample time to actually return, and any
        // incorrectly-also-woken requeued waiters a real chance to (wrongly) return too.
        std::thread::sleep(core::time::Duration::from_millis(150));
        assert_eq!(
            completed.load(Ordering::SeqCst),
            usize::try_from(NUM_TO_WAKE).unwrap(),
            "only the directly-woken waiter(s) should have returned -- the requeued ones must \
             still be genuinely blocked, now waiting on futex2, not woken early by the requeue \
             call itself"
        );

        // A stale wake on the *original* address must find nobody left there.
        //
        // `count` is read back out as a signed `int` (matching real Linux's FUTEX_WAKE ABI, see
        // `sys_futex`'s `count.cast_signed()` check), so `u32::MAX` (all bits set, i.e. -1
        // signed) is *not* "wake everyone" here -- it clamps down to 1. `i32::MAX` is the actual
        // "as many as possible" sentinel at this layer.
        let woken_on_stale_addr = task
            .sys_futex(FutexArgs::Wake {
                addr: UserPtrMut::from_usize(futex1_addr),
                flags: FutexFlags::PRIVATE,
                count: i32::MAX.cast_unsigned(),
            })
            .expect("wake on stale addr failed");
        assert_eq!(
            woken_on_stale_addr, 0,
            "the requeued waiters must have genuinely moved off futex1's wait queue"
        );

        // Now wake the requeued waiters via their new address.
        let woken_on_addr2 = task
            .sys_futex(FutexArgs::Wake {
                addr: UserPtrMut::from_usize(futex2_addr),
                flags: FutexFlags::PRIVATE,
                count: i32::MAX.cast_unsigned(),
            })
            .expect("wake on addr2 failed");
        assert_eq!(
            woken_on_addr2,
            N - usize::try_from(NUM_TO_WAKE).unwrap(),
            "every requeued waiter must be discoverable, and wakeable, via the new address"
        );

        for waiter in waiters {
            waiter
                .join()
                .expect("waiter thread panicked")
                .expect("sys_futex(Wait) should not have errored");
        }
        assert_eq!(completed.load(Ordering::SeqCst), N);
    }

    /// Real threads, real `sys_futex` syscalls: `FUTEX_CMP_REQUEUE` must actually check the
    /// futex word before requeuing and fail with `EAGAIN` (never wake or move anyone) once it no
    /// longer matches -- the documented race-closing behavior that plain `FUTEX_REQUEUE` does
    /// not perform.
    #[test]
    fn test_futex_cmp_requeue_rejects_stale_value_across_real_threads() {
        use litebox_common_linux::errno::Errno;
        use litebox_common_linux::{FutexArgs, FutexFlags, TimeParam};

        let task = crate::syscalls::tests::init_platform(None);

        let mut futex1: u32 = 5;
        let mut futex2: u32 = 0;
        let futex1_addr = core::ptr::from_mut(&mut futex1) as usize;
        let futex2_addr = core::ptr::from_mut(&mut futex2) as usize;

        let waiter = task.spawn_clone_for_test(move |task| {
            task.sys_futex(FutexArgs::Wait {
                addr: UserPtrMut::from_usize(futex1_addr),
                flags: FutexFlags::PRIVATE,
                val: 5,
                timeout: TimeParam::Milliseconds(10_000),
            })
        });

        std::thread::sleep(core::time::Duration::from_millis(100)); // let it genuinely block

        let err = task
            .sys_futex(FutexArgs::CmpRequeue {
                addr: UserPtrMut::from_usize(futex1_addr),
                flags: FutexFlags::PRIVATE,
                num_to_wake: 1,
                num_to_requeue: 0,
                addr2: UserPtrMut::from_usize(futex2_addr),
                expected_value: 999, // stale on purpose: the real word is still 5
            })
            .expect_err("a value-mismatched CMP_REQUEUE must fail, not silently requeue");
        assert_eq!(err, Errno::EAGAIN);

        // The waiter must still be genuinely blocked on the original address.
        let woken = task
            .sys_futex(FutexArgs::Wake {
                addr: UserPtrMut::from_usize(futex1_addr),
                flags: FutexFlags::PRIVATE,
                count: 1,
            })
            .expect("wake on futex1 failed");
        assert_eq!(
            woken, 1,
            "the waiter must still be on futex1's own wait queue -- a mismatched CMP_REQUEUE \
             must not have moved it"
        );

        waiter
            .join()
            .expect("waiter thread panicked")
            .expect("sys_futex(Wait) should not have errored");
    }

    /// Regression test for a thread that dies while still recorded as the owner of a robust
    /// futex: [`Task::handle_futex_death`] must set [`FUTEX_OWNER_DIED`] on the futex word and
    /// wake a waiter -- mirroring Linux's `handle_futex_death`/`exit_robust_list`
    /// (`kernel/futex/core.c`). Before this fix, `handle_futex_death` was `todo!()`, so any
    /// dying thread whose robust list was non-empty would panic mid-teardown instead of
    /// notifying waiters, permanently stranding a sibling thread blocked in `FUTEX_WAIT` on that
    /// lock.
    ///
    /// This drives `Task::handle_futex_death` directly (rather than round-tripping through a
    /// hand-built `RobustListHead`/`RobustList` guest-memory layout, which is real guest-ABI
    /// plumbing already covered by `wake_robust_list`'s straightforward list-walking logic) to
    /// isolate exactly the piece that was unimplemented: does processing one owned, waited-on
    /// futex entry correctly mark it dead and wake the waiter, without panicking.
    #[test]
    fn test_handle_futex_death_wakes_waiter_and_sets_owner_died() {
        use litebox_common_linux::{FutexArgs, FutexFlags, MapFlags, ProtFlags, TimeParam};
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicU32, Ordering};

        let _guard = crate::syscalls::tests::address_space_guard();
        let task = crate::syscalls::tests::init_platform(None);

        // The robust futex word lives in guest memory, as it would for a real guest.
        // `handle_futex_death` wakes with shared (non-`PRIVATE`) semantics, whose key lookup
        // resolves the word through the VMM; a host-stack word is only known to the VMM if this
        // test thread's stack happened to be mapped when the process-wide test platform took its
        // one-time host-mapping snapshot, so with a stack word the wake `EFAULT`s (and is
        // swallowed) depending purely on test order -- not on timing.
        let page = task
            .sys_mmap(
                0,
                super::PAGE_SIZE,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                -1,
                0,
            )
            .expect("mmap for the futex word failed");
        let futex_addr = page.as_usize();
        let barrier = std::sync::Arc::new(Barrier::new(2));

        let bg = {
            let barrier = std::sync::Arc::clone(&barrier);
            task.spawn_clone_for_test(move |bg_task| {
                // Simulate this (cloned) thread having locked a robust mutex: the futex word
                // records this thread as owner, with the waiters bit set since the main thread
                // is about to block on it.
                #[expect(clippy::cast_sign_loss, reason = "tid is always non-negative")]
                let owner_word = (bg_task.tid as u32) | super::FUTEX_WAITERS;
                let futex_atomic = unsafe { &*(futex_addr as *const AtomicU32) };
                futex_atomic.store(owner_word, Ordering::SeqCst);

                barrier.wait();
                // Give the main thread time to actually park in FUTEX_WAIT before "dying" --
                // otherwise this would trivially pass even with the pre-fix `todo!()` never
                // running (there would be nothing parked to prove got woken).
                std::thread::sleep(core::time::Duration::from_millis(100));

                bg_task
                    .handle_futex_death(UserPtr::from_usize(futex_addr), false)
                    .expect("handle_futex_death should not error for a well-formed entry");
            })
        };

        barrier.wait();
        let owner_word = {
            let futex_atomic = unsafe { &*(futex_addr as *const AtomicU32) };
            futex_atomic.load(Ordering::SeqCst)
        };
        let result = task.sys_futex(FutexArgs::Wait {
            addr: UserPtrMut::from_usize(futex_addr),
            flags: FutexFlags::PRIVATE,
            val: owner_word,
            timeout: TimeParam::Milliseconds(10_000),
        });
        assert_eq!(
            result,
            Ok(0),
            "main thread's FUTEX_WAIT on the robust futex should be woken once \
             handle_futex_death runs for its dying owner, not hang forever"
        );

        let final_word = {
            let futex_atomic = unsafe { &*(futex_addr as *const AtomicU32) };
            futex_atomic.load(Ordering::SeqCst)
        };
        assert_eq!(
            final_word & super::FUTEX_OWNER_DIED,
            super::FUTEX_OWNER_DIED,
            "the futex word should have FUTEX_OWNER_DIED set once its owner dies without \
             unlocking"
        );

        bg.join().expect("background thread panicked");
        task.sys_munmap(page, super::PAGE_SIZE).unwrap();
    }

    /// Real process-exit teardown (`prepare_for_exit`), a real pipe, and a real epoll
    /// registration on its write end: proves a still-open write-end fd left behind when the
    /// *last* thread of a process exits -- with no explicit `close()` from the guest, exactly
    /// how a real Linux program that just calls `_exit()` (or crashes) behaves, relying on the
    /// kernel to close its fds -- is unconditionally closed, so a reader elsewhere gets `EOF`
    /// instead of hanging forever, regardless of the epoll registration.
    #[test]
    fn test_process_exit_closes_pipe_write_end_even_with_epoll_registered() {
        use litebox::fd::TypedFd;
        use litebox::fs::OFlags;
        use litebox::pipes::Pipes;
        use litebox_common_linux::{EpollCreateFlags, EpollEvent, EpollOp};

        let writer_task = crate::syscalls::tests::init_platform(None);
        let fs = writer_task.files.borrow().fs.clone();
        // A second, wholly independent process -- its own `Process` and its own `FilesState` --
        // sharing only the same underlying `GlobalState`/`litebox` object, exactly as two real
        // OS processes sharing one machine would. This is what makes "the reader is unaffected
        // by the writer's own fd-table teardown" a meaningful, non-tautological claim: the
        // reader's fd table is not the one `prepare_for_exit` walks.
        let reader_task = writer_task.global.clone().new_test_task(fs);

        let (read_fd, write_fd) = writer_task
            .sys_pipe2(OFlags::empty())
            .expect("pipe2 failed");
        let write_fd_i32 = i32::try_from(write_fd).unwrap();

        // Register the write end with an epoll instance the writer also owns -- the exact
        // scenario under investigation: an epoll registration must not keep the write end alive
        // past the writer's exit.
        let epfd = writer_task
            .sys_epoll_create(EpollCreateFlags::empty())
            .expect("epoll_create failed");
        let event = EpollEvent::new(litebox::event::Events::OUT.bits(), 0);
        writer_task
            .sys_epoll_ctl(
                i32::try_from(epfd).unwrap(),
                EpollOp::EpollCtlAdd,
                write_fd_i32,
                UserPtr::from_ptr(&raw const event),
            )
            .expect("epoll_ctl(ADD) on the write end failed");

        // Hand the *read* end to the independent reader process, mirroring what real fd
        // inheritance (fork, or SCM_RIGHTS over a Unix socket) would produce: a second,
        // independent owning reference to the same underlying pipe object, reachable through a
        // completely different process's fd table.
        let dup_read_fd = {
            let writer_files = writer_task.files.borrow();
            let rds = writer_files.raw_descriptor_store.read();
            let original: alloc::sync::Arc<TypedFd<Pipes<crate::syscalls::tests::TestPlatform>>> =
                rds.fd_from_raw_integer(read_fd as usize).unwrap();
            drop(rds);
            writer_task
                .global
                .litebox
                .descriptor_table_mut()
                .duplicate(&original)
                .expect("duplicating the read end should succeed")
        };
        let reader_raw_fd = {
            let reader_files = reader_task.files.borrow();
            let mut rds = reader_files.raw_descriptor_store.write();
            rds.fd_into_raw_integer(dup_read_fd)
        };
        let reader_raw_fd = i32::try_from(reader_raw_fd).unwrap();

        // The reader blocks in a real `read()` on its own, independent fd, waiting for EOF.
        let reader = reader_task.spawn_clone_for_test(move |task| {
            let mut buf = [0u8; 1];
            task.sys_read(reader_raw_fd, &mut buf, None)
        });

        std::thread::sleep(core::time::Duration::from_millis(100)); // let it genuinely block
        assert!(
            !reader.is_finished(),
            "the reader should still be blocked: the write end is still open"
        );

        // The writer "process" exits -- its last (only) thread -- *without* explicitly closing
        // either the pipe write end or the epoll fd.
        drop(writer_task);

        let result = reader
            .join()
            .expect("reader thread panicked")
            .expect("read() should not have errored");
        assert_eq!(
            result, 0,
            "the reader should observe EOF (a 0-byte read) once the writer's process exits, not \
             hang forever"
        );
    }

    /// [`super::OwnedRanges`] has to be a real set -- inserting over, and removing out of the
    /// middle of, an existing range must split rather than drop or duplicate it -- because a
    /// stale entry would let `fork`'s snapshot roll back memory that by then belongs to a
    /// different guest process.
    #[test]
    fn owned_ranges_splits_on_partial_overlap() {
        let mut ranges = super::OwnedRanges::default();
        ranges.insert(0x1000..0x5000);

        // A hole punched out of the middle leaves the two ends.
        ranges.remove(0x2000..0x3000);
        assert_eq!(
            ranges
                .intersect(&(0..0x10000))
                .collect::<std::vec::Vec<_>>(),
            std::vec![0x1000..0x2000, 0x3000..0x5000]
        );

        // Re-inserting across the hole coalesces back into one entry, replacing what it overlaps
        // rather than duplicating it.
        ranges.insert(0x1000..0x5000);
        assert_eq!(
            ranges
                .intersect(&(0..0x10000))
                .collect::<std::vec::Vec<_>>(),
            std::vec![0x1000..0x5000]
        );

        // `intersect` clips to the queried range, since callers use it to pick the owned parts of
        // a mapping that may extend past them.
        assert_eq!(
            ranges
                .intersect(&(0x4000..0x9000))
                .collect::<std::vec::Vec<_>>(),
            std::vec![0x4000..0x5000]
        );

        ranges.remove(0..usize::MAX);
        assert_eq!(ranges.intersect(&(0..0x10000)).count(), 0);
    }

    /// The `wstatus` word `wait4` writes is what libc's `WIFEXITED`/`WEXITSTATUS`/`WTERMSIG`
    /// decode, so the packing has to match theirs exactly -- a shell reports `$?` straight out of
    /// it.
    #[test]
    fn wait_status_matches_the_libc_macros() {
        use litebox_common_linux::signal::Signal;

        let exited = super::encode_wait_status(super::ExitStatus::Exit(42));
        assert_eq!(exited & 0x7f, 0, "WIFEXITED: low seven bits clear");
        assert_eq!((exited >> 8) & 0xff, 42, "WEXITSTATUS");

        let zero = super::encode_wait_status(super::ExitStatus::Exit(0));
        assert_eq!(zero, 0);

        // An exit code is truncated to 8 bits by the kernel, so `exit(-1)` reads back as 255.
        assert_eq!(
            (super::encode_wait_status(super::ExitStatus::Exit(-1)) >> 8) & 0xff,
            255
        );

        let killed = super::encode_wait_status(super::ExitStatus::Signal(Signal::SIGSEGV));
        assert_eq!(killed & 0x7f, Signal::SIGSEGV.as_i32(), "WTERMSIG");
        assert_ne!(
            killed & 0x7f,
            0,
            "WIFEXITED must be false for a signal death"
        );
    }

    /// `wait4` has to distinguish "no children at all" (`ECHILD`) from "children, none finished"
    /// (block, or return 0 under `WNOHANG`), and must reap exactly once.
    #[test]
    fn wait4_reports_no_children_children_running_and_a_finished_child() {
        use litebox_common_linux::errno::Errno;
        const WNOHANG: i32 = 1;
        let task = crate::syscalls::tests::init_platform(None);
        let table = &task.global.processes;

        assert_eq!(
            task.sys_wait4(-1, None, 0, 0).unwrap_err(),
            Errno::ECHILD,
            "a task with no children cannot wait for one"
        );

        let child = 0x4242;
        table.add_child(child, task.pid);
        assert_eq!(
            task.sys_wait4(-1, None, WNOHANG, 0).unwrap(),
            0,
            "a running child is not reapable, and WNOHANG must not block for it"
        );
        assert_eq!(
            task.sys_wait4(child + 1, None, WNOHANG, 0).unwrap_err(),
            Errno::ECHILD,
            "waiting for a pid that is not our child is ECHILD even though we have one"
        );

        table.record_exit(child, super::ExitStatus::Exit(7), 0);
        let mut status = 0i32;
        let status_ptr = UserPtrMut::from_ptr(&raw mut status);
        assert_eq!(task.sys_wait4(-1, Some(status_ptr), 0, 0).unwrap(), child);
        assert_eq!((status >> 8) & 0xff, 7);

        assert_eq!(
            task.sys_wait4(-1, None, 0, 0).unwrap_err(),
            Errno::ECHILD,
            "a reaped child is gone: waiting again is ECHILD, not a second reap"
        );
    }

    /// Regression test for a `wait4(..., &rusage)` bug: the buffer used to be left completely
    /// untouched whenever a caller passed one, so a reader like `busybox time` printed whatever
    /// was already sitting in that guest memory -- observed in practice as `sys 2367004162h 16m
    /// 32s`. `sys_wait4` must now populate it for real, using each thread's host-measured CPU
    /// time (see `Process::cpu_time_nanos`), and must not leave any field -- including the ones
    /// this shim cannot measure -- as leftover uninitialized memory.
    #[test]
    fn wait4_populates_real_rusage_instead_of_leaving_it_uninitialized() {
        use litebox_common_linux::{Rusage, TimeVal};
        use zerocopy::{FromBytes as _, IntoBytes as _};

        let task = crate::syscalls::tests::init_platform(None);
        let table = &task.global.processes;

        let child = 0x4343;
        table.add_child(child, task.pid);
        // As if the child had genuinely consumed 2.5s of host CPU time across its threads.
        let cpu_time = Duration::from_millis(2500);
        table.record_exit(
            child,
            super::ExitStatus::Exit(0),
            u64::try_from(cpu_time.as_nanos()).unwrap(),
        );

        // A sentinel fill: if `sys_wait4` ever again leaves the buffer untouched, this pattern
        // survives every assertion below rather than silently reading back as zero.
        let mut buf = [0xAAu8; core::mem::size_of::<Rusage>()];
        let rusage_ptr = UserPtrMut::<Rusage>::from_ptr(buf.as_mut_ptr().cast());

        assert_eq!(
            task.sys_wait4(-1, None, 0, rusage_ptr.as_usize()).unwrap(),
            child
        );

        let rusage = Rusage::read_from_bytes(&buf).unwrap();
        assert_eq!(
            rusage.ru_utime.as_bytes(),
            TimeVal::from(cpu_time).as_bytes(),
            "ru_utime must be the real, host-measured CPU time, not the sentinel or garbage"
        );
        assert_eq!(
            rusage.ru_stime.as_bytes(),
            TimeVal::default().as_bytes(),
            "ru_stime is honestly zero (this shim has no meaningful kernel time of its own to \
             attribute), not the sentinel"
        );
        assert_eq!(
            rusage.ru_maxrss, 0,
            "unmeasured fields are zeroed, not sentinel garbage"
        );
    }

    /// A `fork`ed child gets its own descriptor *table* over the same open file *descriptions*.
    /// The shell relies on both halves: it rearranges fds 0/1/2 for the command it is about to
    /// `exec` (which must not reach back into the shell), and it expects the descriptions
    /// themselves -- offsets, pipe ends -- to be shared with what it forked from.
    #[test]
    fn fork_copies_the_descriptor_table_but_shares_the_descriptions() {
        let _guard = crate::syscalls::tests::address_space_guard();
        let task = crate::syscalls::tests::init_platform(None);

        let (read_fd, write_fd) = task.sys_pipe2(litebox::fs::OFlags::empty()).unwrap();
        let (read_fd, write_fd) = (
            i32::try_from(read_fd).unwrap(),
            i32::try_from(write_fd).unwrap(),
        );

        let child_files = task.files.borrow().fork_copy(&task).unwrap();
        let child_fds: std::vec::Vec<usize> = child_files
            .raw_descriptor_store
            .read()
            .iter_alive()
            .collect();
        let parent_fds: std::vec::Vec<usize> = task
            .files
            .borrow()
            .raw_descriptor_store
            .read()
            .iter_alive()
            .collect();
        assert_eq!(
            child_fds, parent_fds,
            "every descriptor is duplicated at the same number"
        );

        // Closing in the child's table leaves the parent's number alive...
        let parent_files = task.files.replace(alloc::sync::Arc::new(child_files));
        task.sys_close(write_fd).unwrap();
        let child_files = task.files.replace(parent_files);
        assert!(
            !child_files
                .raw_descriptor_store
                .read()
                .iter_alive()
                .any(|fd| fd == usize::try_from(write_fd).unwrap())
        );
        assert!(
            task.files
                .borrow()
                .raw_descriptor_store
                .read()
                .iter_alive()
                .any(|fd| fd == usize::try_from(write_fd).unwrap()),
            "the parent's write end must survive the child closing its own"
        );

        // ...and the shared description is still open, so the read end has not seen EOF: a write
        // through the parent's still-open write end is readable.
        assert_eq!(task.sys_write(write_fd, b"hi", None).unwrap(), 2);
        let mut buf = [0u8; 2];
        assert_eq!(task.sys_read(read_fd, &mut buf, None).unwrap(), 2);
        assert_eq!(&buf, b"hi");

        task.sys_close(read_fd).unwrap();
        task.sys_close(write_fd).unwrap();
    }

    /// The address-space token is a strict hand-off: only one member holds it at a time, a
    /// waiter takes it the moment it is released, and `hand_off_to` never lets it go free (which
    /// is what stops a third member from stealing a freshly `fork`ed child's memory before its
    /// first instruction).
    #[test]
    fn address_space_token_is_held_by_exactly_one_member() {
        use super::{
            ADDRESS_SPACE_FREE, ExitStatus, Ordering, ProcIdentity, ProcessInner,
            SharedAddressSpace,
        };
        use alloc::collections::btree_map::BTreeMap;
        use alloc::sync::Arc;
        use litebox::platform::RawMutex as _;
        use litebox::sync::Mutex;

        // The token hand-off logic under test never inspects the thread table -- it is only
        // used by `kick_holder` to interrupt a multithreaded holder's threads, which this test
        // never triggers -- so an empty one is a valid stand-in.
        let inner: Arc<Mutex<crate::syscalls::tests::TestPlatform, ProcessInner<_>>> =
            Arc::new(Mutex::new(ProcessInner {
                exit_status: ExitStatus::Exit(0),
                group_exit: false,
                is_killing_other_threads: false,
                threads: BTreeMap::new(),
                identity: ProcIdentity::default(),
            }));

        let shared: SharedAddressSpace<crate::syscalls::tests::TestPlatform> =
            SharedAddressSpace::new(1000, &inner);
        let word = || shared.holder.underlying_atomic().load(Ordering::Relaxed);
        assert_eq!(word(), 1000);

        // Acquiring while another member holds it must not succeed. `1001` is not already the
        // holder, so `already_held` must be `false` here -- a caller-supplied `true` would
        // (correctly, given the contract) short-circuit to success regardless of contention.
        // `abandon` must be `true` so the call returns `false` on first contention instead of
        // blocking forever waiting for a release nothing in this test will ever perform.
        assert!(!shared.acquire(1001, || false, || true, &inner));
        assert_eq!(word(), 1000);

        // A direct hand-off never passes through the free state.
        shared.hand_off_to(1001, &inner);
        assert_eq!(word(), 1001);

        shared.release();
        assert_eq!(word(), ADDRESS_SPACE_FREE);
        // `already_held` is consulted on every loop pass by design (it re-checks whether a
        // sibling thread already took the token on this process's behalf while this call was
        // about to run, not only while blocked), so it is called even on this immediately-free,
        // first-iteration-succeeds path; `false` is correct since 1002 has never held this token.
        assert!(shared.acquire(1002, || false, || false, &inner));
        assert_eq!(word(), 1002);
    }

    /// A child becoming a zombie posts `SIGCHLD` to its parent.
    ///
    /// Without this, busybox `ash`'s blocking `wait` -- which is a `sigsuspend` loop waiting for
    /// its `SIGCHLD` handler to set a flag -- spins forever.
    #[test]
    fn child_exit_posts_sigchld_to_the_parent() {
        use litebox_common_linux::signal::{SaFlags, SigAction, SigSet, Signal};

        let task = crate::syscalls::tests::init_platform(None);
        let table = &task.global.processes;
        let child = task.pid + 1;
        table.register_process(task.pid, task.remote_signal_target(), task.process());
        table.add_child(child, task.pid);

        // With the default disposition (ignore), the signal must not make blocking syscalls
        // return `EINTR`, exactly as on Linux, where an ignored signal is never queued at all.
        table.record_exit(child, super::ExitStatus::Exit(0), 0);
        assert!(
            !task.has_pending_signals(),
            "an ignored SIGCHLD must not count as deliverable"
        );

        // With a handler installed it must be deliverable.
        let act = SigAction {
            sigaction: 0x1234,
            flags: SaFlags::empty(),
            #[cfg(target_pointer_width = "64")]
            __pad: 0,
            restorer: 0,
            mask: SigSet::empty(),
        };
        task.sys_rt_sigaction(
            Signal::SIGCHLD,
            Some(UserPtr::from_ptr(&raw const act)),
            None,
            core::mem::size_of::<SigSet>(),
        )
        .expect("rt_sigaction failed");
        assert!(
            task.has_pending_signals(),
            "a handled SIGCHLD must be deliverable"
        );
        assert!(task.pending_signal_set().contains(Signal::SIGCHLD));
    }

    /// `rt_sigsuspend` always fails with `EINTR`, and leaves the caller's original mask to be put
    /// back by the return-to-guest path rather than restoring it itself -- restoring it early
    /// would re-block the signal whose handler the caller is waiting to run.
    #[test]
    fn rt_sigsuspend_defers_restoring_the_callers_mask() {
        use litebox_common_linux::{
            errno::Errno,
            signal::{SigSet, SigmaskHow, Signal},
        };

        let _guard = crate::syscalls::tests::async_signal_guard();
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(
            || {
                // Block everything, as busybox's `waitproc` does before it suspends.
                let everything = !SigSet::empty();
                task.sys_rt_sigprocmask(
                    SigmaskHow::SIG_SETMASK,
                    Some(UserPtr::from_ptr(&raw const everything)),
                    None,
                    core::mem::size_of::<SigSet>(),
                )
                .expect("block everything failed");

                // Suspend under a mask that leaves everything through, and let the alarm end it.
                let allow_everything = SigSet::empty();
                assert_eq!(task.sys_alarm(1).unwrap(), 0);
                assert_eq!(
                    task.sys_rt_sigsuspend(
                        Some(UserPtr::from_ptr(&raw const allow_everything)),
                        core::mem::size_of::<SigSet>()
                    ),
                    Err(Errno::EINTR)
                );
                task.sys_alarm(0).unwrap();

                // Still under the temporary mask, so the signal that ended the wait is still
                // deliverable and its handler would run with SIGALRM unblocked.
                assert!(
                    task.pending_signal_set().contains(Signal::SIGALRM),
                    "the suspending mask must still be in effect on return"
                );

                // The return-to-guest path puts the caller's mask back.
                task.restore_saved_signal_mask();
                let mut current = SigSet::empty();
                task.sys_rt_sigprocmask(
                    SigmaskHow::SIG_BLOCK,
                    None,
                    Some(UserPtrMut::from_ptr(&raw mut current)),
                    core::mem::size_of::<SigSet>(),
                )
                .expect("read mask failed");
                assert_eq!(
                    current.as_u64(),
                    everything.as_u64(),
                    "the mask in force before rt_sigsuspend must be restored afterwards"
                );
            },
        );
    }
}
