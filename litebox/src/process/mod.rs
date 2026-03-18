// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process management abstractions for multi-process support.
//!
//! This module provides the core identity types ([`ProcessId`], [`ProcessGroupId`],
//! [`SessionId`]) and the [`ProcessRegistry`] for managing multiple guest processes
//! within LiteBox.
//!
//! See `docs/multi-process-single-address-space.md` for the full design.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::event::wait::{WaitContext, Waker};
use crate::platform::RawMutex as RawMutexTrait;
use crate::sync::{Mutex, RawSyncPrimitivesProvider, RwLock};

// ---------------------------------------------------------------------------
// Identity types
// ---------------------------------------------------------------------------

/// A process identifier, analogous to Linux's `tgid`.
///
/// Process IDs are monotonically allocated starting from 1 and never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(pub u32);

impl ProcessId {
    /// The initial guest process.
    pub const INIT: Self = Self(1);

    /// Returns the raw numeric value.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

/// A process group identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessGroupId(pub u32);

impl ProcessGroupId {
    /// Returns the raw numeric value.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<ProcessId> for ProcessGroupId {
    fn from(pid: ProcessId) -> Self {
        Self(pid.0)
    }
}

/// A session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u32);

impl SessionId {
    /// Returns the raw numeric value.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<ProcessId> for SessionId {
    fn from(pid: ProcessId) -> Self {
        Self(pid.0)
    }
}

// ---------------------------------------------------------------------------
// Process state & context
// ---------------------------------------------------------------------------

/// The lifecycle state of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// The process is running (or runnable).
    Running,
    /// The process has exited with the given status but has not yet been reaped.
    Zombie(i32),
}

/// Pure identity and lifecycle data for a process (platform-agnostic).
#[derive(Debug)]
pub struct ProcessContext {
    /// This process's ID (tgid).
    pub id: ProcessId,
    /// Parent process ID. `None` only for the init process (PID 1).
    pub parent: Option<ProcessId>,
    /// Process group ID. Defaults to the parent's pgid, or `pid` for init.
    pub pgid: ProcessGroupId,
    /// Session ID. Defaults to the parent's sid, or `pid` for init.
    pub sid: SessionId,
    /// Signal sent to parent on exit (typically `SIGCHLD` for fork, 0 for threads).
    pub exit_signal: i32,
    /// Current lifecycle state.
    pub state: ProcessState,
}

// ---------------------------------------------------------------------------
// Wait types
// ---------------------------------------------------------------------------

/// Information about a child process exit, returned by
/// [`ProcessRegistry::exit_process`] so the caller can deliver the exit
/// signal (typically `SIGCHLD`) to the parent.
#[derive(Debug, Clone, Copy)]
pub struct ExitNotification {
    /// The parent process that should receive the signal.
    pub parent_pid: ProcessId,
    /// The signal number to deliver (from the child's `exit_signal`).
    pub exit_signal: i32,
    /// The child process that exited.
    pub child_pid: ProcessId,
    /// The child's exit status.
    pub exit_status: i32,
}

/// The target of a `waitpid`-style call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitTarget {
    /// Wait for a specific child by PID.
    Pid(ProcessId),
    /// Wait for any child (`waitpid(-1, ...)`).
    AnyChild,
    /// Wait for any child in the given process group.
    ProcessGroup(ProcessGroupId),
}

bitflags::bitflags! {
    /// Options for `waitpid`-style calls (matches Linux flag values).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct WaitOptions: u32 {
        /// Return immediately if no child has exited.
        const WNOHANG    = 1;
        /// Also report stopped children.
        const WUNTRACED  = 2;
        /// Also report continued children.
        const WCONTINUED = 8;
    }
}

/// Result of a successful reap via [`ProcessRegistry::wait_for_child`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitResult {
    /// PID of the reaped child.
    pub pid: ProcessId,
    /// Exit status of the child.
    pub status: i32,
}

/// Errors from [`ProcessRegistry::wait_for_child`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitError {
    /// No children (or no matching children) exist for this parent.
    NoChildren,
    /// `WNOHANG` was specified and no child has exited yet.
    WouldBlock,
    /// The specified process was not found in the registry.
    NoSuchProcess,
    /// The wait was interrupted (e.g., by `exit_group` or a signal).
    Interrupted,
}

/// Errors from [`ProcessRegistry::create_process`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateProcessError {
    /// The specified parent PID does not exist in the registry.
    NoSuchParent,
    /// A root (init) process already exists; only one is allowed.
    InitAlreadyExists,
}

/// Errors from [`ProcessRegistry::set_pgid`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetPgidError {
    /// Caller does not have permission (not self or child, different session,
    /// or target is a session leader).
    NotPermitted,
    /// The specified process group does not exist in this session.
    NoSuchGroup,
}

/// Errors from [`ProcessRegistry::setsid`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetsidError {
    /// The caller is already a process group leader.
    AlreadyGroupLeader,
}
// ---------------------------------------------------------------------------
// Wait notification channel (futex-based)
// ---------------------------------------------------------------------------

/// A per-process notification channel used by `waitpid`.
///
/// When a child exits, the parent's channel is signaled. Parents block on
/// their channel when no zombie child is available.
///
/// Supports two blocking modes:
/// - **Raw futex**: backward-compatible path used when no [`WaitContext`] is
///   available (e.g. unit tests). Only wakes on child-exit notifications.
/// - **Waker-based**: when a caller registers a [`Waker`] via
///   [`register_waker`](Self::register_waker), [`notify`](Self::notify)
///   also wakes the caller's [`WaitContext`], making the wait interruptible
///   by signals on all platforms.
struct WaitChannel<Platform: RawSyncPrimitivesProvider> {
    futex: Platform::RawMutex,
    /// Wakers registered by threads currently blocked in `wait_for_child`.
    wakers: Mutex<Platform, Vec<Waker<Platform>>>,
}

impl<Platform: RawSyncPrimitivesProvider> WaitChannel<Platform> {
    fn new() -> Self {
        Self {
            futex: <Platform::RawMutex as RawMutexTrait>::INIT,
            wakers: Mutex::new(Vec::new()),
        }
    }

    /// Signal that a child has exited — wakes all waiters.
    fn notify(&self) {
        self.futex
            .underlying_atomic()
            .fetch_add(1, Ordering::Release);
        self.futex.wake_all();
        // Also wake any WaitContext-based waiters so they re-check for
        // zombies and/or pending signals.
        for waker in self.wakers.lock().iter() {
            waker.wake();
        }
    }

    /// Capture the current futex value. Must be called while the table lock
    /// is held so that any concurrent `notify()` will invalidate this snapshot.
    fn snapshot(&self) -> u32 {
        self.futex.underlying_atomic().load(Ordering::Acquire)
    }

    /// Block until the futex value differs from `snapshot`.
    /// Call this after releasing the table lock.
    fn block(&self, snapshot: u32) {
        let _ = self.futex.block(snapshot);
    }

    /// Register a waker so that [`notify`](Self::notify) also wakes the
    /// caller's [`WaitContext`].
    fn register_waker(&self, waker: Waker<Platform>) {
        self.wakers.lock().push(waker);
    }

    /// Remove a previously-registered waker.
    fn unregister_waker(&self, waker: &Waker<Platform>) {
        let mut wakers = self.wakers.lock();
        if let Some(pos) = wakers.iter().position(|w| w.ptr_eq(waker)) {
            wakers.swap_remove(pos);
        }
    }
}

// ---------------------------------------------------------------------------
// Internal per-process entry
// ---------------------------------------------------------------------------

/// Entry stored in the process table for each process.
struct ProcessEntry<Platform: RawSyncPrimitivesProvider> {
    context: ProcessContext,
    children: Vec<ProcessId>,
    /// Notification channel for this process's `waitpid` callers.
    /// Wrapped in [`Arc`] so it can be held outside the table lock.
    wait_channel: Arc<WaitChannel<Platform>>,
}

/// RAII guard that unregisters a [`Waker`] from a [`WaitChannel`] on drop.
struct WakerRegistration<Platform: RawSyncPrimitivesProvider> {
    channel: Arc<WaitChannel<Platform>>,
    waker: Waker<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider> Drop for WakerRegistration<Platform> {
    fn drop(&mut self) {
        self.channel.unregister_waker(&self.waker);
    }
}

// ---------------------------------------------------------------------------
// ProcessRegistry
// ---------------------------------------------------------------------------

/// A registry of all processes in the system.
///
/// Manages process contexts, PID allocation, parent-child relationships,
/// and wait/notify for process exit. This is a concrete struct in core
/// (not a platform trait), parameterized only by the platform's sync primitives.
pub struct ProcessRegistry<Platform: RawSyncPrimitivesProvider> {
    table: RwLock<Platform, hashbrown::HashMap<ProcessId, ProcessEntry<Platform>>>,
    next_pid: AtomicU32,
}

impl<Platform: RawSyncPrimitivesProvider> Default for ProcessRegistry<Platform> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Platform: RawSyncPrimitivesProvider> ProcessRegistry<Platform> {
    /// Create a new, empty process registry.
    pub fn new() -> Self {
        Self {
            table: RwLock::new(hashbrown::HashMap::new()),
            next_pid: AtomicU32::new(1),
        }
    }

    /// Create a new process and return its [`ProcessId`].
    ///
    /// If `parent` is `None`, this creates the init process (PID 1) with no
    /// parent and `exit_signal = 0`. Otherwise, the new process inherits
    /// `pgid` and `sid` from the parent and is registered as the parent's
    /// child. The caller supplies `exit_signal` — the signal (in the platform's
    /// numbering) delivered to the parent when this process exits; typically
    /// `SIGCHLD` for fork-style children, 0 for threads.
    ///
    /// # Errors
    ///
    /// Returns [`CreateProcessError::NoSuchParent`] if `parent` is `Some` but
    /// the parent PID is not in the registry, or
    /// [`CreateProcessError::InitAlreadyExists`] if `parent` is `None` and a
    /// root process already exists.
    pub fn create_process(
        &self,
        parent: Option<ProcessId>,
        exit_signal: i32,
    ) -> Result<ProcessId, CreateProcessError> {
        let raw = self.next_pid.fetch_add(1, Ordering::Relaxed);
        let new_pid = ProcessId(raw);

        let mut table = self.table.write();

        let (pgid, sid) = if let Some(parent_pid) = parent {
            let parent_entry = table
                .get_mut(&parent_pid)
                .ok_or(CreateProcessError::NoSuchParent)?;
            parent_entry.children.push(new_pid);
            (parent_entry.context.pgid, parent_entry.context.sid)
        } else {
            if table.values().any(|e| e.context.parent.is_none()) {
                return Err(CreateProcessError::InitAlreadyExists);
            }
            (ProcessGroupId::from(new_pid), SessionId::from(new_pid))
        };

        let entry = ProcessEntry {
            context: ProcessContext {
                id: new_pid,
                parent,
                pgid,
                sid,
                exit_signal,
                state: ProcessState::Running,
            },
            children: Vec::new(),
            wait_channel: Arc::new(WaitChannel::new()),
        };

        let prev = table.insert(new_pid, entry);
        debug_assert!(prev.is_none(), "PID collision: {}", new_pid.0);

        Ok(new_pid)
    }

    /// Remove a process that was never started (e.g., fork setup failed).
    ///
    /// This undoes [`create_process`](Self::create_process): removes the
    /// process from its parent's child list and drops the entry. The process
    /// must be in [`ProcessState::Running`] and have no children of its own.
    ///
    /// # Panics
    ///
    /// Panics if `id` is not in the registry, has children, or is not `Running`.
    pub fn remove_process(&self, id: ProcessId) {
        let mut table = self.table.write();
        let entry = table.remove(&id).expect("process must exist");
        assert!(
            matches!(entry.context.state, ProcessState::Running),
            "can only remove a running process"
        );
        assert!(
            entry.children.is_empty(),
            "cannot remove a process with children"
        );
        // Remove from parent's child list.
        if let Some(parent_pid) = entry.context.parent
            && let Some(parent_entry) = table.get_mut(&parent_pid)
        {
            parent_entry.children.retain(|&c| c != id);
        }
    }

    /// Mark a process as exited with the given status.
    ///
    /// The process transitions to [`ProcessState::Zombie`]. Its children are
    /// reparented to PID 1 (the init process), and any zombie orphans are
    /// automatically reaped. The parent's wait channel is notified.
    ///
    /// Returns the parent's PID and the child's exit signal (e.g. `SIGCHLD`)
    /// if the parent is still alive. The caller can use this to deliver the
    /// exit signal to the parent process.
    ///
    /// # Panics
    ///
    /// Panics if `id` is not in the registry or the process has already exited.
    pub fn exit_process(&self, id: ProcessId, status: i32) -> Option<ExitNotification> {
        self.exit_process_with_callback(id, status, |_| {})
    }

    /// Mark a process as exited and run `before_notify` after the process table
    /// update but before parent waiters are woken.
    ///
    /// This lets callers publish child-exit side effects (for example queueing
    /// `SIGCHLD`) before a waiting parent resumes from `wait4`.
    ///
    /// # Panics
    ///
    /// Panics if `id` does not exist in the process table.
    pub fn exit_process_with_callback<F>(
        &self,
        id: ProcessId,
        status: i32,
        before_notify: F,
    ) -> Option<ExitNotification>
    where
        F: FnOnce(Option<ExitNotification>),
    {
        let parent_wait_channel;
        let exit_notification;

        {
            let mut table = self.table.write();

            let entry = table.get_mut(&id).expect("process must exist");

            // Guard against double-exit. In release builds the debug_assert
            // would be stripped, so we check unconditionally.
            if matches!(entry.context.state, ProcessState::Zombie(_)) {
                return None;
            }
            entry.context.state = ProcessState::Zombie(status);

            let parent = entry.context.parent;
            let exit_signal = entry.context.exit_signal;

            // In Linux, init (PID 1) exiting is a kernel panic. In LiteBox,
            // we allow it (sandbox teardown) but skip reparenting since there
            // is no ancestor to reparent to.
            if id != ProcessId::INIT {
                let orphaned_children: Vec<ProcessId> = entry.children.drain(..).collect();
                if !orphaned_children.is_empty() {
                    // Separate zombie orphans (auto-reap) from running orphans (reparent).
                    let mut zombies_to_reap = Vec::new();
                    let mut to_reparent = Vec::new();
                    for &child_pid in &orphaned_children {
                        let is_zombie = table
                            .get(&child_pid)
                            .is_some_and(|e| matches!(e.context.state, ProcessState::Zombie(_)));
                        if is_zombie {
                            zombies_to_reap.push(child_pid);
                        } else {
                            to_reparent.push(child_pid);
                        }
                    }

                    // Reparent running children to PID 1.
                    for &child_pid in &to_reparent {
                        if let Some(child_entry) = table.get_mut(&child_pid) {
                            child_entry.context.parent = Some(ProcessId::INIT);
                        }
                    }
                    if let Some(init_entry) = table.get_mut(&ProcessId::INIT) {
                        init_entry.children.extend(to_reparent);
                    }

                    // Auto-reap zombie orphans.
                    for pid in zombies_to_reap {
                        table.remove(&pid);
                    }
                }
            }

            // Clone the parent's wait channel (if parent exists and is
            // running) before dropping the lock. If the parent is already a
            // zombie (or gone), nobody will ever reap us, so auto-reap now.
            parent_wait_channel = match parent {
                Some(parent_pid) => match table.get(&parent_pid) {
                    Some(pe) if matches!(pe.context.state, ProcessState::Running) => {
                        Some(Arc::clone(&pe.wait_channel))
                    }
                    _ => {
                        // Parent is zombie or missing — auto-reap ourselves
                        // and remove from parent's children list.
                        table.remove(&id);
                        if let Some(pe) = table.get_mut(&parent_pid) {
                            pe.children.retain(|&c| c != id);
                        }
                        None
                    }
                },
                None => None,
            };

            // Build exit notification for the caller if parent is alive and
            // the child specified a non-zero exit signal.
            exit_notification = if parent_wait_channel.is_some() && exit_signal > 0 {
                parent.map(|ppid| ExitNotification {
                    parent_pid: ppid,
                    exit_signal,
                    child_pid: id,
                    exit_status: status,
                })
            } else {
                None
            };
        }

        before_notify(exit_notification);

        // Notify the parent outside the table lock.
        if let Some(wc) = parent_wait_channel {
            wc.notify();
        }

        exit_notification
    }

    /// Wake any threads blocked in [`wait_for_child`](Self::wait_for_child)
    /// for the given process. Used by `exit_group` to unblock sibling threads
    /// that are waiting on children.
    pub fn notify_waiters(&self, pid: ProcessId) {
        let table = self.table.read();
        if let Some(entry) = table.get(&pid) {
            entry.wait_channel.notify();
        }
    }

    /// Wait for a child process to exit (`waitpid` semantics).
    ///
    /// Blocks unless `WNOHANG` is set in `options`. On success, the zombie
    /// child is reaped (removed from the registry) and its status returned.
    ///
    /// If `cx` is provided, the wait uses the [`WaitContext`] for blocking,
    /// making it interruptible by signal delivery on all platforms. When
    /// `cx` is `None`, a raw futex block is used (suitable for tests and
    /// contexts without a `WaitContext`).
    ///
    /// If `is_interrupted` is provided, it is checked before each blocking
    /// wait.  If it returns `true`, the call returns `Err(Interrupted)`
    /// immediately.  This allows `exit_group` to break threads out of a
    /// blocking wait by first calling [`notify_waiters`](Self::notify_waiters)
    /// and then setting the interrupt flag.
    ///
    /// # Panics
    ///
    /// Panics if the parent disappears from the registry during a blocking wait.
    pub fn wait_for_child(
        &self,
        parent: ProcessId,
        target: WaitTarget,
        options: WaitOptions,
        cx: Option<&WaitContext<'_, Platform>>,
        is_interrupted: Option<&dyn Fn() -> bool>,
    ) -> Result<WaitResult, WaitError>
    where
        Platform: crate::platform::TimeProvider,
    {
        // When a WaitContext is provided, register its waker so that
        // notify() wakes the WaitContext condvar (making the wait
        // interruptible by signals on all platforms). Registration is
        // deferred until the first blocking iteration and cleaned up on
        // return via Drop.
        let mut waker_registration: Option<WakerRegistration<Platform>> = None;

        let result = self.wait_for_child_inner(
            parent,
            target,
            options,
            cx,
            is_interrupted,
            &mut waker_registration,
        );

        // Drop cleans up the waker registration.
        drop(waker_registration);
        result
    }

    fn wait_for_child_inner(
        &self,
        parent: ProcessId,
        target: WaitTarget,
        options: WaitOptions,
        cx: Option<&WaitContext<'_, Platform>>,
        is_interrupted: Option<&dyn Fn() -> bool>,
        waker_registration: &mut Option<WakerRegistration<Platform>>,
    ) -> Result<WaitResult, WaitError>
    where
        Platform: crate::platform::TimeProvider,
    {
        loop {
            let wait_channel;
            let wait_snapshot;

            {
                let mut table = self.table.write();

                let parent_entry = table.get(&parent).ok_or(WaitError::NoSuchProcess)?;

                // Check that the parent has at least one child matching the target.
                let has_matching_child = parent_entry
                    .children
                    .iter()
                    .any(|&child_pid| Self::matches_target(&table, child_pid, target));

                if !has_matching_child {
                    return Err(WaitError::NoChildren);
                }

                // Look for a zombie child matching the target.
                let zombie = parent_entry
                    .children
                    .iter()
                    .filter(|&&child_pid| Self::matches_target(&table, child_pid, target))
                    .find_map(|&child_pid| {
                        let child = table.get(&child_pid)?;
                        if let ProcessState::Zombie(status) = child.context.state {
                            Some((child_pid, status))
                        } else {
                            None
                        }
                    });

                if let Some((zombie_pid, status)) = zombie {
                    // Reap: remove from table and from parent's children list.
                    table.remove(&zombie_pid);
                    if let Some(parent_entry) = table.get_mut(&parent) {
                        parent_entry.children.retain(|&pid| pid != zombie_pid);
                    }
                    return Ok(WaitResult {
                        pid: zombie_pid,
                        status,
                    });
                }

                if options.contains(WaitOptions::WNOHANG) {
                    return Err(WaitError::WouldBlock);
                }

                // Check if the caller has been interrupted (e.g., exit_group,
                // pending signals, vfork parking).
                if let Some(check) = is_interrupted
                    && check()
                {
                    return Err(WaitError::Interrupted);
                }

                // Clone the wait channel and snapshot its notification counter
                // while the table lock is held, so any concurrent notify()
                // will invalidate the snapshot.
                let entry = table.get(&parent).expect("parent still exists");
                wait_channel = Arc::clone(&entry.wait_channel);
                wait_snapshot = wait_channel.snapshot();

                // Register the waker on the first blocking iteration so that
                // notify() can wake the WaitContext condvar.
                if let Some(cx) = cx
                    && waker_registration.is_none()
                {
                    let waker = cx.waker().clone();
                    wait_channel.register_waker(waker.clone());
                    *waker_registration = Some(WakerRegistration {
                        channel: Arc::clone(&wait_channel),
                        waker,
                    });
                }
            }

            // Block outside the table lock until a child exits (or a signal
            // arrives).
            if let Some(cx) = cx {
                // WaitContext-based blocking: interruptible by signal delivery
                // on all platforms. The readiness check detects child-exit
                // notifications via the counter change; signal interruption
                // is handled by WaitContext's check_for_interrupt.
                let wc = &wait_channel;
                let s = wait_snapshot;
                let _ = cx.wait_until(|| wc.snapshot() != s);
            } else {
                // Raw futex blocking: only wakes on child-exit notifications.
                wait_channel.block(wait_snapshot);
            }
            // Re-acquire the lock and re-check (loop).
        }
    }

    /// Read a process's context through a closure (avoids exposing the lock).
    pub fn with_context<R>(
        &self,
        id: ProcessId,
        f: impl FnOnce(&ProcessContext) -> R,
    ) -> Option<R> {
        let table = self.table.read();
        table.get(&id).map(|entry| f(&entry.context))
    }

    /// Returns the parent PID of the given process, or `None` if it has no parent.
    pub fn get_parent(&self, id: ProcessId) -> Option<ProcessId> {
        self.with_context(id, |ctx| ctx.parent)?
    }

    /// Returns the list of child PIDs for the given process.
    pub fn get_children(&self, id: ProcessId) -> Option<Vec<ProcessId>> {
        let table = self.table.read();
        table.get(&id).map(|entry| entry.children.clone())
    }

    /// Returns the number of processes currently tracked (including zombies).
    pub fn process_count(&self) -> usize {
        self.table.read().len()
    }

    /// Get the process group ID of a process.
    pub fn get_pgid(&self, id: ProcessId) -> Option<ProcessGroupId> {
        self.with_context(id, |ctx| ctx.pgid)
    }

    /// Set the process group ID of a process.
    ///
    /// `target` is the process to modify, `pgid` is the new process group.
    /// Returns `Ok(())` on success. Errors:
    /// - `None` if `target` does not exist
    /// - `Err(SetPgidError::*)` for permission/validity failures
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn set_pgid(
        &self,
        caller: ProcessId,
        target: ProcessId,
        pgid: ProcessGroupId,
    ) -> Option<Result<(), SetPgidError>> {
        let mut table = self.table.write();
        // Target must exist.
        let entry = table.get(&target)?;

        // Can only change pgid of self or a direct child.
        let is_self = target == caller;
        let is_child = entry.context.parent == Some(caller);
        if !is_self && !is_child {
            return Some(Err(SetPgidError::NotPermitted));
        }

        // Target must be in the same session as caller.
        let caller_sid = table.get(&caller)?.context.sid;
        if entry.context.sid != caller_sid {
            return Some(Err(SetPgidError::NotPermitted));
        }

        // Cannot change pgid of a session leader.
        let target_sid = SessionId::from(target);
        if entry.context.sid == target_sid {
            return Some(Err(SetPgidError::NotPermitted));
        }

        // If setting to a specific pgid (not target's own), the target group
        // must already exist in the same session. We check if any process in
        // the table has that pgid and the same session.
        let target_pid_as_pgid = ProcessGroupId::from(target);
        if pgid != target_pid_as_pgid {
            let group_exists = table
                .values()
                .any(|e| e.context.pgid == pgid && e.context.sid == caller_sid);
            if !group_exists {
                return Some(Err(SetPgidError::NoSuchGroup));
            }
        }

        table.get_mut(&target).unwrap().context.pgid = pgid;
        Some(Ok(()))
    }

    /// Get the session ID of a process.
    pub fn get_sid(&self, id: ProcessId) -> Option<SessionId> {
        self.with_context(id, |ctx| ctx.sid)
    }

    /// Create a new session with `caller` as the session leader and sole
    /// member of a new process group.
    ///
    /// Returns the new session ID (== caller's pid) on success.
    /// Fails with `Err(())` if caller is already a process group leader.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn setsid(&self, caller: ProcessId) -> Option<Result<SessionId, SetsidError>> {
        let mut table = self.table.write();
        let entry = table.get(&caller)?;

        // Fail if caller is already a process group leader (pgid == pid).
        if entry.context.pgid == ProcessGroupId::from(caller) {
            return Some(Err(SetsidError::AlreadyGroupLeader));
        }

        let new_sid = SessionId::from(caller);
        let new_pgid = ProcessGroupId::from(caller);
        let entry = table.get_mut(&caller).unwrap();
        entry.context.sid = new_sid;
        entry.context.pgid = new_pgid;
        Some(Ok(new_sid))
    }

    /// Check if a child PID matches the given wait target.
    fn matches_target(
        table: &hashbrown::HashMap<ProcessId, ProcessEntry<Platform>>,
        child_pid: ProcessId,
        target: WaitTarget,
    ) -> bool {
        debug_assert!(
            table.contains_key(&child_pid),
            "child PID {} in parent's children list but missing from table",
            child_pid.as_u32()
        );
        match target {
            WaitTarget::Pid(target_pid) => child_pid == target_pid,
            WaitTarget::AnyChild => true,
            WaitTarget::ProcessGroup(pgid) => table
                .get(&child_pid)
                .is_some_and(|e| e.context.pgid == pgid),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::LiteBox;
    use crate::platform::mock::MockPlatform;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn setup() -> (
        &'static MockPlatform,
        alloc::sync::Arc<ProcessRegistry<MockPlatform>>,
    ) {
        let platform = MockPlatform::new();
        let _litebox = LiteBox::new(platform);
        let registry = alloc::sync::Arc::new(ProcessRegistry::new());
        (platform, registry)
    }

    #[test]
    fn test_create_init_process() {
        let (_platform, registry) = setup();
        let pid = registry.create_process(None, 0).unwrap();
        assert_eq!(pid, ProcessId::INIT);

        registry
            .with_context(pid, |ctx| {
                assert_eq!(ctx.id, ProcessId::INIT);
                assert_eq!(ctx.parent, None);
                assert_eq!(ctx.pgid, ProcessGroupId::from(pid));
                assert_eq!(ctx.sid, SessionId::from(pid));
                assert_eq!(ctx.exit_signal, 0);
                assert_eq!(ctx.state, ProcessState::Running);
            })
            .expect("init process should exist");
    }

    #[test]
    fn test_create_child_process() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(parent), 17).unwrap();

        assert_ne!(parent, child);
        assert!(child.as_u32() > parent.as_u32());

        registry
            .with_context(child, |ctx| {
                assert_eq!(ctx.parent, Some(parent));
                // Inherits parent's pgid/sid
                assert_eq!(ctx.pgid, ProcessGroupId::from(parent));
                assert_eq!(ctx.sid, SessionId::from(parent));
                assert_eq!(ctx.exit_signal, 17);
                assert_eq!(ctx.state, ProcessState::Running);
            })
            .expect("child process should exist");

        // Parent should list child
        let children = registry.get_children(parent).unwrap();
        assert_eq!(children, alloc::vec![child]);
    }

    #[test]
    fn test_pid_allocation_monotonic() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let p2 = registry.create_process(Some(init), 17).unwrap();
        let p3 = registry.create_process(Some(init), 17).unwrap();
        let p4 = registry.create_process(Some(init), 17).unwrap();

        assert!(p2.as_u32() > init.as_u32());
        assert!(p3.as_u32() > p2.as_u32());
        assert!(p4.as_u32() > p3.as_u32());
    }

    #[test]
    fn test_exit_process_becomes_zombie() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(parent), 17).unwrap();

        registry.exit_process(child, 42);

        registry
            .with_context(child, |ctx| {
                assert_eq!(ctx.state, ProcessState::Zombie(42));
            })
            .expect("zombie should still be in table");
    }

    #[test]
    fn test_wait_for_child_nohang_reaps_zombie() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(parent), 17).unwrap();

        registry.exit_process(child, 7);

        let result = registry
            .wait_for_child(
                parent,
                WaitTarget::AnyChild,
                WaitOptions::WNOHANG,
                None,
                None,
            )
            .expect("should reap zombie");
        assert_eq!(result.pid, child);
        assert_eq!(result.status, 7);

        // Zombie should be removed from the table
        assert!(registry.with_context(child, |_| ()).is_none());
        // Parent should have no children left
        assert!(registry.get_children(parent).unwrap().is_empty());
    }

    #[test]
    fn test_wait_for_child_nohang_no_zombie() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let _child = registry.create_process(Some(parent), 17).unwrap();

        let result = registry.wait_for_child(
            parent,
            WaitTarget::AnyChild,
            WaitOptions::WNOHANG,
            None,
            None,
        );
        assert_eq!(result, Err(WaitError::WouldBlock));
    }

    #[test]
    fn test_wait_no_children() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();

        let result = registry.wait_for_child(
            parent,
            WaitTarget::AnyChild,
            WaitOptions::WNOHANG,
            None,
            None,
        );
        assert_eq!(result, Err(WaitError::NoChildren));
    }

    #[test]
    fn test_wait_for_specific_child() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child1 = registry.create_process(Some(parent), 17).unwrap();
        let child2 = registry.create_process(Some(parent), 17).unwrap();

        registry.exit_process(child1, 10);
        registry.exit_process(child2, 20);

        // Wait for child2 specifically
        let result = registry
            .wait_for_child(
                parent,
                WaitTarget::Pid(child2),
                WaitOptions::WNOHANG,
                None,
                None,
            )
            .expect("should reap child2");
        assert_eq!(result.pid, child2);
        assert_eq!(result.status, 20);

        // child1 should still be a zombie
        registry
            .with_context(child1, |ctx| {
                assert_eq!(ctx.state, ProcessState::Zombie(10));
            })
            .expect("child1 should still exist");
    }

    #[test]
    fn test_wait_for_child_blocks_until_exit() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(parent), 17).unwrap();

        let registry_clone = alloc::sync::Arc::clone(&registry);
        let barrier = alloc::sync::Arc::new(Barrier::new(2));
        let barrier_clone = alloc::sync::Arc::clone(&barrier);

        // Spawn a thread that will exit the child after a delay.
        let exit_thread = thread::spawn(move || {
            barrier_clone.wait();
            thread::sleep(Duration::from_millis(20));
            registry_clone.exit_process(child, 99);
        });

        barrier.wait();

        // This should block until the child exits.
        let result = registry
            .wait_for_child(
                parent,
                WaitTarget::AnyChild,
                WaitOptions::empty(),
                None,
                None,
            )
            .expect("should reap child");
        assert_eq!(result.pid, child);
        assert_eq!(result.status, 99);

        exit_thread.join().unwrap();
    }

    #[test]
    fn test_exit_callback_runs_before_parent_waiters_wake() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(parent), 17).unwrap();

        let (waiter_done_tx, waiter_done_rx) = mpsc::channel();
        let waiter_seen_callback = alloc::sync::Arc::new(AtomicBool::new(false));
        let waiter_seen_callback_clone = alloc::sync::Arc::clone(&waiter_seen_callback);
        let registry_for_waiter = alloc::sync::Arc::clone(&registry);
        let waiter = thread::spawn(move || {
            let result = registry_for_waiter
                .wait_for_child(
                    parent,
                    WaitTarget::AnyChild,
                    WaitOptions::empty(),
                    None,
                    None,
                )
                .expect("waiter should reap child");
            assert_eq!(result.pid, child);
            waiter_done_tx.send(()).unwrap();
            assert!(
                waiter_seen_callback_clone.load(Ordering::SeqCst),
                "parent waiter woke before exit callback finished"
            );
        });

        let (callback_started_tx, callback_started_rx) = mpsc::channel();
        let (release_callback_tx, release_callback_rx) = mpsc::channel();
        let waiter_seen_callback_clone = alloc::sync::Arc::clone(&waiter_seen_callback);
        let registry_for_exit = alloc::sync::Arc::clone(&registry);
        let exit_thread = thread::spawn(move || {
            registry_for_exit.exit_process_with_callback(child, 0, |notification| {
                assert_eq!(notification.map(|n| n.parent_pid), Some(parent));
                callback_started_tx.send(()).unwrap();
                release_callback_rx.recv().unwrap();
                waiter_seen_callback_clone.store(true, Ordering::SeqCst);
            });
        });

        callback_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("exit callback should start");
        assert!(
            waiter_done_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "parent waiter woke before callback released notification ordering"
        );

        release_callback_tx.send(()).unwrap();
        waiter.join().unwrap();
        exit_thread.join().unwrap();
    }

    #[test]
    fn test_reparent_children_on_exit() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let mid = registry.create_process(Some(init), 17).unwrap();
        let grandchild = registry.create_process(Some(mid), 17).unwrap();

        // Mid exits — grandchild should be reparented to init.
        registry.exit_process(mid, 0);

        registry
            .with_context(grandchild, |ctx| {
                assert_eq!(ctx.parent, Some(ProcessId::INIT));
            })
            .expect("grandchild should exist");

        // Init should now list grandchild as a child.
        let init_children = registry.get_children(init).unwrap();
        assert!(init_children.contains(&grandchild));
    }

    #[test]
    fn test_auto_reap_zombie_orphans() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let mid = registry.create_process(Some(init), 17).unwrap();
        let grandchild = registry.create_process(Some(mid), 17).unwrap();

        // Grandchild exits first (becomes zombie under mid).
        registry.exit_process(grandchild, 5);
        assert!(registry.with_context(grandchild, |_| ()).is_some());

        // Mid exits — zombie grandchild should be auto-reaped.
        registry.exit_process(mid, 0);
        assert!(
            registry.with_context(grandchild, |_| ()).is_none(),
            "zombie orphan should have been auto-reaped"
        );
    }

    #[test]
    fn test_process_count() {
        let (_platform, registry) = setup();
        assert_eq!(registry.process_count(), 0);

        let init = registry.create_process(None, 0).unwrap();
        assert_eq!(registry.process_count(), 1);

        let child = registry.create_process(Some(init), 17).unwrap();
        assert_eq!(registry.process_count(), 2);

        registry.exit_process(child, 0);
        // Zombie still counted
        assert_eq!(registry.process_count(), 2);

        // Reap
        registry
            .wait_for_child(init, WaitTarget::AnyChild, WaitOptions::WNOHANG, None, None)
            .unwrap();
        assert_eq!(registry.process_count(), 1);
    }

    #[test]
    fn test_wait_for_process_group() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let child1 = registry.create_process(Some(init), 17).unwrap();
        let _child2 = registry.create_process(Some(init), 17).unwrap();

        // Both children inherit init's pgid (which is ProcessGroupId(1))
        let init_pgid = ProcessGroupId::from(init);

        registry.exit_process(child1, 11);

        let result = registry
            .wait_for_child(
                init,
                WaitTarget::ProcessGroup(init_pgid),
                WaitOptions::WNOHANG,
                None,
                None,
            )
            .expect("should reap child in same process group");
        assert_eq!(result.pid, child1);
        assert_eq!(result.status, 11);

        // child2 still running, so WouldBlock
        let result = registry.wait_for_child(
            init,
            WaitTarget::ProcessGroup(init_pgid),
            WaitOptions::WNOHANG,
            None,
            None,
        );
        assert_eq!(result, Err(WaitError::WouldBlock));
    }

    #[test]
    fn test_no_such_process() {
        let (_platform, registry) = setup();
        let bogus = ProcessId(999);
        let result = registry.wait_for_child(
            bogus,
            WaitTarget::AnyChild,
            WaitOptions::WNOHANG,
            None,
            None,
        );
        assert_eq!(result, Err(WaitError::NoSuchProcess));
    }

    #[test]
    fn test_create_with_missing_parent_returns_error() {
        let (_platform, registry) = setup();
        let _init = registry.create_process(None, 0).unwrap();
        let bogus_parent = ProcessId(999);
        let result = registry.create_process(Some(bogus_parent), 17);
        assert_eq!(result, Err(CreateProcessError::NoSuchParent));
    }

    #[test]
    fn test_double_exit_is_idempotent() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(parent), 17).unwrap();

        registry.exit_process(child, 42);
        // Second exit must not panic or overwrite the status.
        registry.exit_process(child, 99);

        let result = registry
            .wait_for_child(
                parent,
                WaitTarget::AnyChild,
                WaitOptions::WNOHANG,
                None,
                None,
            )
            .expect("should reap zombie");
        assert_eq!(result.status, 42, "first exit status must be preserved");
    }

    #[test]
    fn test_duplicate_root_returns_error() {
        let (_platform, registry) = setup();
        let _init = registry.create_process(None, 0).unwrap();
        // Second root should return an error.
        let result = registry.create_process(None, 0);
        assert_eq!(result, Err(CreateProcessError::InitAlreadyExists));
    }

    #[test]
    fn test_remove_process_cleans_up() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(parent), 17).unwrap();

        // Remove the child before it starts running.
        registry.remove_process(child);

        // Parent should have no children to wait for.
        let result = registry.wait_for_child(
            parent,
            WaitTarget::AnyChild,
            WaitOptions::WNOHANG,
            None,
            None,
        );
        assert_eq!(result, Err(WaitError::NoChildren));
    }

    #[test]
    fn test_child_auto_reaped_when_parent_is_zombie() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(init), 17).unwrap();

        // Init exits first (sandbox teardown scenario).
        registry.exit_process(init, 0);

        // Child exits — should be auto-reaped since parent is zombie.
        registry.exit_process(child, 1);

        // Child should no longer be in the table.
        assert!(
            registry.with_context(child, |_| ()).is_none(),
            "child should have been auto-reaped"
        );
    }

    #[test]
    fn test_get_pgid_and_sid() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(init), 17).unwrap();

        // Init: pgid == pid, sid == pid
        assert_eq!(registry.get_pgid(init), Some(ProcessGroupId::from(init)));
        assert_eq!(registry.get_sid(init), Some(SessionId::from(init)));

        // Child inherits parent's pgid and sid
        assert_eq!(registry.get_pgid(child), Some(ProcessGroupId::from(init)));
        assert_eq!(registry.get_sid(child), Some(SessionId::from(init)));

        // Non-existent process
        assert_eq!(registry.get_pgid(ProcessId(999)), None);
        assert_eq!(registry.get_sid(ProcessId(999)), None);
    }

    #[test]
    fn test_setpgid_self() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(init), 17).unwrap();

        // Child creates its own process group
        assert_eq!(
            registry.set_pgid(child, child, ProcessGroupId::from(child)),
            Some(Ok(()))
        );
        assert_eq!(registry.get_pgid(child), Some(ProcessGroupId::from(child)));
    }

    #[test]
    fn test_setpgid_child() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(init), 17).unwrap();

        // Parent sets child's pgid to child's own pid (create new group)
        assert_eq!(
            registry.set_pgid(init, child, ProcessGroupId::from(child)),
            Some(Ok(()))
        );
        assert_eq!(registry.get_pgid(child), Some(ProcessGroupId::from(child)));
    }

    #[test]
    fn test_setpgid_join_existing_group() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let child1 = registry.create_process(Some(init), 17).unwrap();
        let child2 = registry.create_process(Some(init), 17).unwrap();

        // child1 creates its own group
        registry
            .set_pgid(child1, child1, ProcessGroupId::from(child1))
            .unwrap()
            .unwrap();

        // child2 joins child1's group
        registry
            .set_pgid(child2, child2, ProcessGroupId::from(child1))
            .unwrap()
            .unwrap();
        assert_eq!(
            registry.get_pgid(child2),
            Some(ProcessGroupId::from(child1))
        );
    }

    #[test]
    fn test_setpgid_nonexistent_group() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(init), 17).unwrap();

        // Try to join a group that doesn't exist
        assert_eq!(
            registry.set_pgid(child, child, ProcessGroupId(999)),
            Some(Err(SetPgidError::NoSuchGroup))
        );
    }

    #[test]
    fn test_setpgid_session_leader_fails() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();

        // Init is a session leader (sid == pid), cannot change pgid
        assert_eq!(
            registry.set_pgid(init, init, ProcessGroupId(999)),
            Some(Err(SetPgidError::NotPermitted))
        );
    }

    #[test]
    fn test_setpgid_not_child_fails() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let child1 = registry.create_process(Some(init), 17).unwrap();
        let child2 = registry.create_process(Some(init), 17).unwrap();

        // child1 tries to set child2's pgid — not permitted (not parent)
        assert_eq!(
            registry.set_pgid(child1, child2, ProcessGroupId::from(child2)),
            Some(Err(SetPgidError::NotPermitted))
        );
    }

    #[test]
    fn test_setsid() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(init), 17).unwrap();

        // Child inherits init's pgid, so pgid != child's pid → can setsid
        let sid = registry.setsid(child).unwrap().unwrap();
        assert_eq!(sid, SessionId::from(child));
        assert_eq!(registry.get_sid(child), Some(SessionId::from(child)));
        assert_eq!(registry.get_pgid(child), Some(ProcessGroupId::from(child)));
    }

    #[test]
    fn test_setsid_already_group_leader() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(init), 17).unwrap();

        // Make child a group leader first
        registry
            .set_pgid(child, child, ProcessGroupId::from(child))
            .unwrap()
            .unwrap();

        // setsid should fail — child is already a process group leader
        assert_eq!(
            registry.setsid(child),
            Some(Err(SetsidError::AlreadyGroupLeader))
        );
    }

    #[test]
    fn test_setsid_init_fails() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();

        // Init is always a group leader (pgid == pid)
        assert_eq!(
            registry.setsid(init),
            Some(Err(SetsidError::AlreadyGroupLeader))
        );
    }
}
