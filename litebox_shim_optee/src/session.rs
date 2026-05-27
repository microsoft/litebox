// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Session and instance management for OP-TEE TAs.
//!
//! This module handles the lifecycle of TA sessions and instances:
//! - Session tracking (session_id → instance mapping)
//! - Single-instance TA caching (uuid → instance)
//! - Instance lifecycle (load, run, cleanup)
//!
//! ## Concurrency Model
//!
//! TA execution is serialized externally; [`TaInstance`] is shared as a plain
//! `Arc<TaInstance>` without an inner mutex. The exclusivity invariant lives in
//! [`SessionManager`] and is acquired through an internal RAII `SessionToken`
//! that bundles whichever locks the current operation requires:
//!
//! - **Single-instance TAs** (with `TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION`)
//!   share one [`TaInstance`] across all sessions. The token internally holds a
//!   per-UUID `SpinMutex` so Open/Invoke/Close serialize on the same UUID.
//!
//! - **Multi-instance TAs** have one [`TaInstance`] per session. The token
//!   internally holds a per-`session_id` marker so Invoke/Close cannot
//!   re-enter the same session concurrently, while different sessions run
//!   in parallel on their own instances.
//!
//! Both [`SessionManager::with_ta`] (OpenSession) and
//! [`SessionManager::with_session`] (Invoke/Close) acquire the token
//! non-blockingly, run the caller's closure under it, and release on return.
//! On contention they return `EThreadLimit`.
//!
//! ### Difference from OP-TEE OS
//!
//! OP-TEE OS uses RPC-based waiting: when a TA is busy, it returns to normal world
//! via `mutex_lock()` issuing an RPC, allowing the Linux kernel to schedule other
//! work while waiting. This is efficient but fundamentally insecure because normal
//! world is untrusted.
//!
//! ### LiteBox Behavior
//!
//! We return `OPTEE_SMC_RETURN_ETHREAD_LIMIT` at the SMC level instead of RPC-waiting.
//! The Linux OP-TEE driver handles this by:
//! 1. Adding the caller to a wait queue (`optee_cq_wait_for_completion`)
//! 2. Sleeping until another call completes (`optee_cq_wait_final` wakes waiters)
//! 3. Automatically retrying the SMC
//!
//! This provides transparent retry behavior for client applications while keeping
//! the waiting logic in normal world (where scheduling is appropriate), without
//! requiring RPCs that would give untrusted code control over secure world execution.
//!
//! On panic teardown or last-session close, sibling sessions of a single-instance
//! TA are flipped to `Dead` *before* the cached instance is
//! evicted (see [`SessionManager::remove_single_instance_if_same`]). A racing
//! handler that subsequently enters [`SessionManager::with_ta`] or
//! [`SessionManager::with_session`] for the UUID will therefore observe `Dead`
//! on its re-read of the session entry and short-circuit through the
//! dead-target path.
//!
//! Reference: <https://optee.readthedocs.io/en/latest/architecture/trusted_applications.html#multi-session>
//!
//! ## OP-TEE OS Thread IDs and RPC
//!
//! In OP-TEE OS, **session IDs** and **thread IDs** serve different purposes:
//!
//! ### Session IDs
//!
//! - Allocated by secure world, globally unique at any point in time
//! - Stored in `msg_arg.session` and returned to normal world on `OpenSession`
//! - Used by `InvokeCommand` and `CloseSession` to look up the target session
//! - Multiple sessions (with different IDs) can share the same TA instance
//!
//! ### Thread IDs
//!
//! - Logical indices into OP-TEE's global `threads[]` array
//! - Identify the execution context (thread) handling a request
//! - **Stable across core migrations**: a thread keeps its ID even if rescheduled to another CPU
//!
//! ### Thread IDs and RPC Resume
//!
//! When a secure thread suspends for RPC (e.g., to request file I/O from normal world),
//! OP-TEE returns the **thread ID** to normal world via SMC registers:
//!
//! - ARM64: `a3` contains "Thread ID when returning from RPC"
//! - Registers `a3-a7` are "resume information"—opaque to normal world, passed back unchanged
//!
//! Normal world calls `OPTEE_SMC_CALL_RETURN_FROM_RPC` with these registers intact.
//! OP-TEE uses `thread_resume_from_rpc(thread_id, ...)` to resume the correct thread.
//!
//! **Note**: `a3-a7` are opaque from normal world's view—secure world can store anything
//! (thread ID, encrypted token, pointer, etc.). OP-TEE uses thread ID, but the protocol
//! just requires normal world to preserve and return them.
//!
//! ### Security Consideration
//!
//! Normal world is **untrusted** but expected to preserve `a3-a7` and pass them back correctly.
//! There's no enforcement—normal world could tamper, delay, or corrupt resume information.
//! OP-TEE OS validates thread IDs but fundamentally trusts normal world to cooperate.
//!
//! ### Key Distinction
//!
//! - **Session ID**: lookup key for `InvokeCommand`
//! - **Thread ID**: identifies suspended thread for RPC resume
//!
//! In OP-TEE OS, multiple threads can have pending operations on a session, but only one
//! **executes** at a time—others wait via RPC (suspended in normal world).
//!
//! ### LiteBox Status (TODO)
//!
//! - We return `ETHREAD_LIMIT` instead of RPC-based waiting
//! - RPC needed for secure storage—will require:
//!   - Saving CPU context (registers, stack, etc.) when suspending for RPC
//!   - Indexing saved contexts by an identifier (passed via `a3-a7`)
//!   - Restoring context when normal world calls `RETURN_FROM_RPC`
//!   - Encrypting the resume identifier (thread ID, etc.) with authenticated encryption
//!     (e.g., AES-GCM) to detect tampering and replay attacks from normal world

use crate::{LoadedProgram, OpteeShim, SessionIdPool};
use alloc::sync::Arc;
use hashbrown::{HashMap, HashSet};
use litebox_common_optee::{OpteeSmcReturnCode, TaFlags, TeeUuid};
use spin::mutex::SpinMutex;

/// Maximum number of concurrent TA instances to avoid out of memory situations.
pub const MAX_TA_INSTANCES: usize = 16;

/// A loaded TA instance that can be shared across multiple sessions.
///
/// For single-instance TAs (with `TA_FLAG_SINGLE_INSTANCE`), one TA instance
/// is shared across all sessions. The TA is loaded once and stays in memory until
/// the last session closes (or with `TA_FLAG_INSTANCE_KEEP_ALIVE`, until explicit destroy).
///
/// Each instance has its own task page table that provides memory isolation from other TAs.
///
/// Fields are private; external callers obtain instances through
/// [`SessionManager::with_ta`] / [`SessionManager::with_session`] closures
/// (which run under a `SessionToken` that serializes access) and reach the
/// internals via the accessor methods on this type.
pub struct TaInstance {
    /// The shim must be kept alive to keep the loaded program's memory mappings valid.
    shim: OpteeShim,
    /// The loaded TA program state including entrypoints.
    /// Boxed to keep it at a fixed heap address - the Task inside must not be moved
    /// after initialization because it contains internal state that may not survive moves.
    loaded_program: alloc::boxed::Box<LoadedProgram>,
    /// The task page table ID associated with this TA instance.
    task_page_table_id: usize,
}

impl TaInstance {
    /// Construct a new instance from its three constituent parts.
    pub fn new(
        shim: OpteeShim,
        loaded_program: alloc::boxed::Box<LoadedProgram>,
        task_page_table_id: usize,
    ) -> Self {
        Self {
            shim,
            loaded_program,
            task_page_table_id,
        }
    }

    /// Task page table ID associated with this instance.
    pub fn task_page_table_id(&self) -> usize {
        self.task_page_table_id
    }

    /// Reference to the underlying shim (needed for releasing user mappings
    /// during teardown).
    pub fn shim(&self) -> &OpteeShim {
        &self.shim
    }

    /// Reference to the loaded program (entry points, parameter address, TA flags).
    pub fn loaded_program(&self) -> &LoadedProgram {
        &self.loaded_program
    }
}

// SAFETY: `TaInstance`'s interior (`shim`, `loaded_program`) is not
// auto-`Send`/`Sync`, but every access goes through a `SessionToken` that
// serializes execution on the per-UUID lock (single-instance TAs) or the
// per-`session_id` marker (multi-instance TAs), so at most one core is
// ever inside a given instance. See the module-level "Concurrency Model".
unsafe impl Send for TaInstance {}
unsafe impl Sync for TaInstance {}

/// The target associated with a normal-world session ID.
///
/// This is the in-map representation, kept private to the module. External
/// callers see [`TargetView`] inside a [`SessionView`] delivered by the
/// session-token-bound closure APIs ([`SessionManager::with_ta`],
/// [`SessionManager::with_session`]).
#[derive(Clone)]
pub(crate) enum SessionTarget {
    /// The session still targets a live TA instance.
    Live(Arc<TaInstance>),
    /// The TA died, but normal world may still issue Invoke/Close for this ID.
    Dead,
}

/// Borrowed view of a [`TaInstance`], valid only inside the
/// [`SessionManager::with_ta`] / [`SessionManager::with_session`] closure
/// that received it.
///
/// The lifetime ties the view to the `SessionToken` held internally by
/// the closure; the closure cannot smuggle this borrow out (HRTB on the
/// closure forces it to be valid for any lifetime the manager picks),
/// cannot clone it into an owned `Arc<TaInstance>`, and cannot extract
/// the wrapped `Arc`. All mutation paths that need instance identity
/// (sibling marking, count, cache eviction, sibling-session registration)
/// take an `InstanceRef<'_>`. `Copy` is fine — it just produces another
/// borrow with the same lifetime, not an escape.
#[derive(Clone, Copy)]
pub struct InstanceRef<'a> {
    arc: &'a Arc<TaInstance>,
}

impl<'a> InstanceRef<'a> {
    fn new(arc: &'a Arc<TaInstance>) -> Self {
        Self { arc }
    }

    /// Task page table ID associated with this instance.
    pub fn task_page_table_id(&self) -> usize {
        self.arc.task_page_table_id()
    }

    /// Reference to the underlying shim.
    pub fn shim(&self) -> &OpteeShim {
        self.arc.shim()
    }

    /// Reference to the loaded program (entry points, parameter address, TA flags).
    pub fn loaded_program(&self) -> &LoadedProgram {
        self.arc.loaded_program()
    }
}

/// Closure-bound view of a session's target. Mirrors the internal
/// `SessionTarget` enum but exposes [`InstanceRef`] instead of
/// `Arc<TaInstance>`.
pub enum TargetView<'a> {
    Live(InstanceRef<'a>),
    Dead,
}

/// Closure-bound view of a session entry. Delivered by
/// [`SessionManager::with_session`].
pub struct SessionView<'a> {
    pub ta_uuid: TeeUuid,
    pub ta_flags: TaFlags,
    pub target: TargetView<'a>,
}

/// Per-session entry in the session map. Module-private; the closure-bound
/// public view is [`SessionView`].
#[derive(Clone)]
pub(crate) struct SessionEntry {
    /// The TA target (may be shared with other sessions for single-instance TAs).
    pub target: SessionTarget,
    /// The TA UUID (needed for cleanup of single-instance TAs).
    pub ta_uuid: TeeUuid,
    /// TA flags parsed from the `.ta_head` section.
    pub ta_flags: TaFlags,
}

/// Session map for tracking active sessions.
///
/// Maps runner-allocated session IDs to session entries.
pub(crate) struct SessionMap {
    inner: SpinMutex<HashMap<u32, SessionEntry>>,
}

impl SessionMap {
    /// Create a new empty session map.
    pub(crate) fn new() -> Self {
        Self {
            inner: SpinMutex::new(HashMap::new()),
        }
    }

    /// Get full session entry by session ID.
    pub(crate) fn get_entry(&self, session_id: u32) -> Option<SessionEntry> {
        self.inner.lock().get(&session_id).cloned()
    }

    /// Insert a session into the map.
    pub(crate) fn insert(
        &self,
        session_id: u32,
        instance: Arc<TaInstance>,
        ta_uuid: TeeUuid,
        ta_flags: TaFlags,
    ) {
        self.inner.lock().insert(
            session_id,
            SessionEntry {
                target: SessionTarget::Live(instance),
                ta_uuid,
                ta_flags,
            },
        );
    }

    /// Remove a session from the map.
    pub(crate) fn remove(&self, session_id: u32) -> Option<SessionEntry> {
        self.inner.lock().remove(&session_id)
    }

    /// Count sessions for a specific TA instance (by Arc pointer equality).
    pub(crate) fn count_sessions_for_instance(&self, instance: &Arc<TaInstance>) -> usize {
        self.inner
            .lock()
            .values()
            .filter(|e| match &e.target {
                SessionTarget::Live(current) => Arc::ptr_eq(current, instance),
                SessionTarget::Dead => false,
            })
            .count()
    }

    /// Mark all sessions pointing at `instance` as dead.
    pub(crate) fn mark_sessions_dead_for_instance(&self, instance: &Arc<TaInstance>) {
        for entry in self.inner.lock().values_mut() {
            if matches!(&entry.target, SessionTarget::Live(current) if Arc::ptr_eq(current, instance))
            {
                entry.target = SessionTarget::Dead;
            }
        }
    }
}

impl Default for SessionMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache for single-instance TAs.
///
/// Single-instance TAs (with `TA_FLAG_SINGLE_INSTANCE`) share a single TA instance
/// across all sessions. This cache stores instances by UUID for fast reuse lookup.
pub(crate) struct SingleInstanceCache {
    inner: SpinMutex<HashMap<TeeUuid, Arc<TaInstance>>>,
}

impl SingleInstanceCache {
    /// Create a new empty cache.
    pub(crate) fn new() -> Self {
        Self {
            inner: SpinMutex::new(HashMap::new()),
        }
    }

    /// Get a cached single-instance TA by UUID.
    pub(crate) fn get(&self, uuid: &TeeUuid) -> Option<Arc<TaInstance>> {
        self.inner.lock().get(uuid).cloned()
    }

    /// Cache a single-instance TA by UUID.
    pub(crate) fn insert(&self, uuid: TeeUuid, instance: Arc<TaInstance>) {
        self.inner.lock().insert(uuid, instance);
    }

    /// Remove a cached single-instance TA only if it is the expected instance.
    fn remove_if_same(&self, uuid: &TeeUuid, expected: &Arc<TaInstance>) -> bool {
        let mut guard = self.inner.lock();
        match guard.get(uuid) {
            Some(current) if Arc::ptr_eq(current, expected) => {
                guard.remove(uuid);
                true
            }
            _ => false,
        }
    }

    /// Get the number of cached single-instance TAs.
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

impl Default for SingleInstanceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Allocate a new unique session ID.
///
/// Delegates to `SessionIdPool::allocate` for unified session ID management.
/// Returns `None` if all session IDs are exhausted.
pub fn allocate_session_id() -> Option<u32> {
    SessionIdPool::allocate()
}

/// Recycle a session ID for potential future reuse.
///
/// Delegates to `SessionIdPool::recycle`.
fn recycle_session_id(session_id: u32) {
    SessionIdPool::recycle(session_id);
}

/// RAII guard that recycles a session ID on drop unless disarmed.
///
/// Session IDs are allocated before the TA is invoked and only registered on
/// success via [`SessionManager::register_new_session`] or
/// [`SessionManager::register_sibling_session`]. This guard ensures it is
/// recycled on all error paths before this registration.
pub struct SessionIdGuard {
    session_id: Option<u32>,
}

impl SessionIdGuard {
    /// Create a new guard that will recycle `session_id` on drop.
    pub fn new(session_id: u32) -> Self {
        Self {
            session_id: Some(session_id),
        }
    }

    /// Return the guarded session ID, or `None` if already disarmed.
    pub fn id(&self) -> Option<u32> {
        self.session_id
    }

    /// Disarm the guard so the session ID is **not** recycled on drop.
    ///
    /// Call this after the session ID has been successfully registered.
    /// Once registered, [`SessionManager::unregister_session`] owns recycling.
    ///
    /// Returns `None` if the guard was already disarmed.
    pub fn disarm(mut self) -> Option<u32> {
        self.session_id.take()
    }
}

impl Drop for SessionIdGuard {
    fn drop(&mut self) {
        if let Some(id) = self.session_id {
            recycle_session_id(id);
        }
    }
}

/// RAII token bundling the serialization primitives required to safely
/// execute an OP-TEE TA operation.
///
/// Held only inside [`SessionManager::with_ta`] (OpenSession) and
/// [`SessionManager::with_session`] (Invoke/Close); never exposed to
/// external callers. Bundles whichever combination of locks is required:
///
/// - **Single-instance TAs**: a per-UUID `SpinMutex` that serializes all
///   sessions on the same TA.
/// - **Existing-session operations** (Invoke/Close): a per-session-id marker
///   that prevents concurrent SMC entry by another core for the same id.
///
/// For multi-instance OpenSession, the token holds nothing (each session
/// gets its own private instance, so no exclusion is required).
///
/// On drop, the per-UUID lock is released first, then the per-session-id
/// marker.
pub(crate) struct SessionToken<'a> {
    manager: &'a SessionManager,
    /// Held `Arc` of the per-UUID `SpinMutex`. The guard returned by
    /// `try_lock()` was [`core::mem::forget`]-ed at acquisition time; this
    /// type's `Drop` calls `force_unlock` to release the mutex. The `Arc`
    /// keeps the mutex alive across acquisition and release.
    uuid_lock: Option<Arc<SpinMutex<()>>>,
    /// Session id reserved in [`SessionManager::active_sessions`].
    active_session_id: Option<u32>,
}

impl Drop for SessionToken<'_> {
    fn drop(&mut self) {
        if let Some(lock) = self.uuid_lock.take() {
            // SAFETY: This token holds the per-UUID lock because the
            // acquisition path called `try_lock()` and forgot the resulting
            // guard. No other holder exists, so `force_unlock` is sound.
            unsafe { lock.force_unlock() };
        }
        if let Some(id) = self.active_session_id.take() {
            self.manager.active_sessions.lock().remove(&id);
        }
    }
}

/// Session manager that coordinates session and instance lifecycle.
///
/// This provides a unified interface for:
/// - Opening sessions (with single-instance TA reuse)
/// - Looking up sessions
/// - Closing sessions (with proper cleanup)
pub struct SessionManager {
    /// Active sessions mapped by session ID.
    sessions: SessionMap,
    /// Cache of single-instance TAs by UUID.
    single_instance_cache: SingleInstanceCache,
    /// Number of instances currently being created (not yet registered).
    /// Added to [`SessionManager::instance_count`] for the capacity check
    /// in [`SessionManager::with_ta`] so two concurrent loads cannot both
    /// pass the limit before either registers.
    pending_count: SpinMutex<usize>,
    /// Cached TA flags by UUID, populated on first successful session registration.
    known_flags: SpinMutex<HashMap<TeeUuid, TaFlags>>,
    /// Per-UUID serialization locks for single-instance TA handling.
    single_instance_locks: SpinMutex<HashMap<TeeUuid, Arc<SpinMutex<()>>>>,
    /// Session ids currently being handled (Invoke/Close). Guards a session
    /// against concurrent SMC entry by another core that targets the same id.
    active_sessions: SpinMutex<HashSet<u32>>,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new() -> Self {
        Self {
            sessions: SessionMap::new(),
            single_instance_cache: SingleInstanceCache::new(),
            pending_count: SpinMutex::new(0),
            known_flags: SpinMutex::new(HashMap::new()),
            single_instance_locks: SpinMutex::new(HashMap::new()),
            active_sessions: SpinMutex::new(HashSet::new()),
        }
    }

    /// Mark every session currently pointing at `instance` as `Dead`.
    ///
    /// Must be called before evicting `instance` from the single-instance
    /// cache (see [`SessionManager::remove_single_instance_if_same`]) so
    /// a racing handler re-reads `Dead` on its sibling session entry.
    pub fn mark_sessions_dead_for_instance(&self, instance: InstanceRef<'_>) {
        self.sessions.mark_sessions_dead_for_instance(instance.arc);
    }

    /// Count sessions currently pointing at `instance`. Used by the
    /// last-close path to detect whether teardown is appropriate.
    pub fn count_sessions_for_instance(&self, instance: InstanceRef<'_>) -> usize {
        self.sessions.count_sessions_for_instance(instance.arc)
    }

    /// Look up previously observed TA flags for a UUID.
    ///
    /// Returns `None` if this UUID has never been successfully loaded.
    /// Callers should conservatively assume single-instance when `None`.
    pub fn get_known_flags(&self, uuid: &TeeUuid) -> Option<TaFlags> {
        self.known_flags.lock().get(uuid).copied()
    }

    /// Whether `uuid` should be treated as single-instance for serialization.
    ///
    /// Returns the cached `is_single_instance()` if known, or `true` for the
    /// first-ever load (we have not yet observed the TA's flags) to preserve
    /// safety invariants conservatively.
    fn assume_single_instance(&self, uuid: &TeeUuid) -> bool {
        self.get_known_flags(uuid)
            .is_none_or(|f| f.is_single_instance())
    }

    /// Get or create the per-UUID serialization mutex `Arc`.
    fn uuid_lock_arc(&self, uuid: TeeUuid) -> Arc<SpinMutex<()>> {
        self.single_instance_locks
            .lock()
            .entry(uuid)
            .or_insert_with(|| Arc::new(SpinMutex::new(())))
            .clone()
    }

    /// Try to take the per-UUID serialization mutex non-blockingly. On
    /// success returns the `Arc` whose forgotten guard is owned by the
    /// caller — release via `force_unlock` on the returned `Arc`.
    fn try_acquire_uuid_lock(&self, uuid: TeeUuid) -> Option<Arc<SpinMutex<()>>> {
        let lock = self.uuid_lock_arc(uuid);
        let guard = lock.try_lock()?;
        // The lock now belongs to the SessionToken about to wrap us. Forget
        // the guard so its `Drop` does not unlock; the token's `Drop` calls
        // `force_unlock` via the retained `Arc`.
        core::mem::forget(guard);
        Some(lock)
    }

    /// Acquire a `SessionToken` for an OpenSession request.
    ///
    /// For single-instance TAs (including first-ever load of an unknown
    /// UUID) this takes the per-UUID `SpinMutex` non-blockingly. For
    /// already-known multi-instance TAs the returned token holds no locks —
    /// each session creates its own private instance, so no exclusion is
    /// required.
    ///
    /// Returns `Err(EThreadLimit)` if another core is currently inside an
    /// operation on the same single-instance UUID.
    fn try_acquire_for_open(&self, uuid: TeeUuid) -> Result<SessionToken<'_>, OpteeSmcReturnCode> {
        let uuid_lock = if self.assume_single_instance(&uuid) {
            Some(
                self.try_acquire_uuid_lock(uuid)
                    .ok_or(OpteeSmcReturnCode::EThreadLimit)?,
            )
        } else {
            None
        };
        Ok(SessionToken {
            manager: self,
            uuid_lock,
            active_session_id: None,
        })
    }

    /// Acquire a token + validated entry for an Invoke/Close on an existing
    /// session. Returns the entry that survived the post-marker re-read so
    /// callers don't need to look it up again.
    ///
    /// Always reserves the per-session-id slot in `active_sessions`. For
    /// single-instance TAs additionally takes the per-UUID `SpinMutex` so
    /// sibling sessions on the same TA serialize against this operation.
    ///
    /// Returns `Err(EBadCmd)` if `session_id` is not registered, or
    /// `Err(EThreadLimit)` if another core is inside the same session or
    /// holds the per-UUID lock for the same single-instance TA. On failure
    /// any partial acquisition is released via the token's `Drop`.
    ///
    /// Defense in depth: after the per-session-id marker is held, the entry
    /// is re-read and its `(uuid, flags)` validated against the pre-marker
    /// snapshot used to decide whether to take the per-UUID lock. If they
    /// diverge (the id was recycled and reused under a different TA between
    /// our first read and the marker insert), `Err(EThreadLimit)` is
    /// returned so the Linux driver retries — a fresh acquisition will see
    /// the new entry from the start.
    fn try_acquire_for_session(
        &self,
        session_id: u32,
    ) -> Result<(SessionToken<'_>, SessionEntry), OpteeSmcReturnCode> {
        let entry = self
            .sessions
            .get_entry(session_id)
            .ok_or(OpteeSmcReturnCode::EBadCmd)?;
        let snapshot_uuid = entry.ta_uuid;
        let snapshot_single = entry.ta_flags.is_single_instance();

        if !self.active_sessions.lock().insert(session_id) {
            return Err(OpteeSmcReturnCode::EThreadLimit);
        }
        let mut token = SessionToken {
            manager: self,
            uuid_lock: None,
            active_session_id: Some(session_id),
        };

        // Validate the snapshot under the marker. If the entry has changed
        // identity (or vanished), our snapshot is stale; bail so the caller
        // retries with a fresh view. Token's `Drop` releases the marker.
        let entry_now = self
            .sessions
            .get_entry(session_id)
            .ok_or(OpteeSmcReturnCode::EBadCmd)?;
        if entry_now.ta_uuid != snapshot_uuid
            || entry_now.ta_flags.is_single_instance() != snapshot_single
        {
            return Err(OpteeSmcReturnCode::EThreadLimit);
        }

        // Only take the per-UUID lock for `Live` single-instance sessions.
        // A `Dead` entry needs no sibling serialization — its instance is
        // already gone, and contending with live siblings (or a freshly
        // created instance for the same UUID) just to call
        // `finalize_dead_session` would needlessly delay them.
        if snapshot_single && matches!(entry_now.target, SessionTarget::Live(_)) {
            // On failure, dropping `token` releases the marker we just took.
            token.uuid_lock = Some(
                self.try_acquire_uuid_lock(snapshot_uuid)
                    .ok_or(OpteeSmcReturnCode::EThreadLimit)?,
            );
        }
        Ok((token, entry_now))
    }

    /// Drive an Invoke/Close to completion under the right serialization.
    ///
    /// Internally acquires the per-session-id marker (and, for single-
    /// instance TAs, the per-UUID lock), passes the validated `SessionEntry`
    /// to `f`, and releases the locks when `f` returns. `f` runs entirely
    /// under the token: state mutations it performs on the session manager
    /// (e.g. `unregister_session`, `mark_sessions_dead_for_instance`,
    /// `remove_single_instance_if_same`) are serialized against other
    /// cores' Invoke/Close on the same session and (for single-instance)
    /// the same UUID.
    ///
    /// Returns `Err(EBadCmd)` if `session_id` is not registered, or
    /// `Err(EThreadLimit)` on lock contention; the Linux OP-TEE driver
    /// retries `EThreadLimit` transparently.
    pub fn with_session<F>(&self, session_id: u32, f: F) -> Result<(), OpteeSmcReturnCode>
    where
        F: for<'a> FnOnce(SessionView<'a>) -> Result<(), OpteeSmcReturnCode>,
    {
        let (_token, entry) = self.try_acquire_for_session(session_id)?;
        let view = SessionView {
            ta_uuid: entry.ta_uuid,
            ta_flags: entry.ta_flags,
            target: match &entry.target {
                SessionTarget::Live(arc) => TargetView::Live(InstanceRef::new(arc)),
                SessionTarget::Dead => TargetView::Dead,
            },
        };
        f(view)
    }

    /// Register a session for a freshly-loaded TA instance.
    ///
    /// Takes `TaInstance` by value, wraps it in an `Arc` owned solely by the
    /// manager (no clone returned to the caller), and — for single-instance
    /// TAs — caches that `Arc` under `ta_uuid`. The caller therefore cannot
    /// retain an `Arc<TaInstance>` past this call, which is what makes the
    /// `unsafe impl Send/Sync for TaInstance` invariant enforceable.
    pub fn register_new_session(
        &self,
        session_id: u32,
        instance: TaInstance,
        ta_uuid: TeeUuid,
        ta_flags: TaFlags,
    ) {
        let arc = Arc::new(instance);
        self.known_flags.lock().entry(ta_uuid).or_insert(ta_flags);
        self.sessions
            .insert(session_id, arc.clone(), ta_uuid, ta_flags);
        if ta_flags.is_single_instance() {
            self.single_instance_cache.insert(ta_uuid, arc);
        }
    }

    /// Register a session that re-uses an existing single-instance TA.
    ///
    /// `instance` is the borrow handed to the [`SessionManager::with_ta`]
    /// closure on the cache-hit branch.
    pub fn register_sibling_session(
        &self,
        session_id: u32,
        instance: InstanceRef<'_>,
        ta_uuid: TeeUuid,
        ta_flags: TaFlags,
    ) {
        self.known_flags.lock().entry(ta_uuid).or_insert(ta_flags);
        self.sessions
            .insert(session_id, instance.arc.clone(), ta_uuid, ta_flags);
    }

    /// Unregister a session and recycle its session ID. Returns whether
    /// the session was registered and what flags it had (the latter for
    /// callers that need to dispatch on `is_single_instance` /
    /// `is_keep_alive` after removal).
    pub fn unregister_session(&self, session_id: u32) -> Option<TaFlags> {
        let entry = self.sessions.remove(session_id);
        if entry.is_some() {
            recycle_session_id(session_id);
        }
        entry.map(|e| e.ta_flags)
    }

    /// Remove a single-instance TA from the cache only if the currently
    /// cached `Arc` is the same as `instance`.
    ///
    /// Callers tearing down on TA panic must have already called
    /// [`SessionManager::mark_sessions_dead_for_instance`] before invoking
    /// this, so any handler that subsequently enters
    /// [`SessionManager::with_ta`] or [`SessionManager::with_session`] for
    /// the UUID will observe `Dead` on its re-read of the session entry.
    /// Callers on the last-session-close path may skip the mark step — by
    /// that point there are no sibling sessions to fence out.
    pub fn remove_single_instance_if_same(
        &self,
        uuid: &TeeUuid,
        instance: InstanceRef<'_>,
    ) -> bool {
        self.single_instance_cache
            .remove_if_same(uuid, instance.arc)
    }

    /// Get the total count of unique TA instances (for limit checking).
    ///
    /// This counts:
    /// - All single-instance TAs in the cache (each UUID = 1 instance, regardless of session count)
    /// - All multi-instance TA sessions (each session = 1 instance)
    pub fn instance_count(&self) -> usize {
        let single_instance_count = self.single_instance_cache.len();
        let multi_instance_count = self.count_multi_instance_sessions();
        single_instance_count + multi_instance_count
    }

    /// Count multi-instance TA sessions (sessions whose TAs are NOT single-instance).
    fn count_multi_instance_sessions(&self) -> usize {
        self.sessions
            .inner
            .lock()
            .values()
            .filter(|e| !e.ta_flags.is_single_instance())
            .count()
    }

    /// Check if instance limit is reached.
    pub fn is_at_capacity(&self) -> bool {
        self.instance_count() >= MAX_TA_INSTANCES
    }

    /// Drive an OpenSession to completion under the right serialization.
    ///
    /// Internally acquires the per-UUID `SpinMutex` for single-instance TAs
    /// (or no lock for known multi-instance TAs), then either:
    ///
    /// - Calls `f(Some(existing))` if a cached single-instance TA is found
    ///   for `uuid`. The lock is held throughout the call so the existing
    ///   instance cannot be torn down or replaced beneath `f`.
    /// - Reserves a creation slot (atomic capacity check against
    ///   `instance_count() + pending_count`) and calls `f(None)` to load
    ///   and register a new instance. The slot is released when `f`
    ///   returns, regardless of outcome.
    ///
    /// The per-UUID lock is released when this function returns; `f` runs
    /// under it. For multi-instance TAs each session gets its own
    /// independent `TaInstance`, so no per-UUID exclusion is required.
    ///
    /// `pending_count` exists only for capacity accounting (so two
    /// multi-instance loads can't both pass the limit check before either
    /// registers). Duplicate-prevention for single-instance TAs is provided
    /// by the per-UUID lock above — it serializes the cache check and any
    /// new load for the same UUID, so two concurrent loads cannot both miss
    /// the cache and create rival instances.
    pub fn with_ta<F>(&self, uuid: &TeeUuid, f: F) -> Result<(), OpteeSmcReturnCode>
    where
        F: for<'a> FnOnce(Option<InstanceRef<'a>>) -> Result<(), OpteeSmcReturnCode>,
    {
        let token = self.try_acquire_for_open(*uuid)?;
        let is_single_instance = token.uuid_lock.is_some();

        // For single-instance TAs the per-UUID lock above keeps our UUID's
        // cache entry stable. For multi-instance we don't consult the cache.
        if is_single_instance && let Some(existing) = self.single_instance_cache.get(uuid) {
            return f(Some(InstanceRef::new(&existing)));
        }

        {
            let mut pending = self.pending_count.lock();
            // Capacity check including in-flight creations.
            if self.instance_count() + *pending >= MAX_TA_INSTANCES {
                return Err(OpteeSmcReturnCode::ENomem);
            }
            *pending += 1;
        }

        let result = f(None);

        {
            let mut pending = self.pending_count.lock();
            *pending = pending.saturating_sub(1);
        }

        result
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
