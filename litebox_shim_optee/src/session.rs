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
//! [`SessionManager`] and is acquired through a single RAII [`SessionToken`]
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
//! OpenSession callers go through [`SessionManager::with_creation_slot`],
//! which manages the token internally. Invoke/Close callers acquire a token
//! via [`SessionManager::try_acquire_for_session`]. Both are non-blocking
//! and return `EThreadLimit` on contention.
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
//! TA are flipped to [`SessionTarget::Dead`] *before* the cached instance is
//! evicted (see [`SessionManager::remove_single_instance_if_same`]). A racing
//! handler that subsequently acquires its own [`SessionToken`] for the UUID
//! will therefore observe `Dead` on its re-read of the session entry and
//! short-circuit through the dead-target path.
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
pub struct TaInstance {
    /// The shim must be kept alive to keep the loaded program's memory mappings valid.
    pub shim: OpteeShim,
    /// The loaded TA program state including entrypoints.
    /// Boxed to keep it at a fixed heap address - the Task inside must not be moved
    /// after initialization because it contains internal state that may not survive moves.
    pub loaded_program: alloc::boxed::Box<LoadedProgram>,
    /// The task page table ID associated with this TA instance.
    pub task_page_table_id: usize,
}

// SAFETY: TaInstance is shared as `Arc<TaInstance>`, but only one core is ever
// inside the TA at a time: single-instance TAs serialize on the per-UUID lock,
// multi-instance TAs on the per-`session_id` entry in `active_sessions`. See
// the module-level "Concurrency Model" doc.
unsafe impl Send for TaInstance {}
unsafe impl Sync for TaInstance {}

/// The target associated with a normal-world session ID.
#[derive(Clone)]
pub enum SessionTarget {
    /// The session still targets a live TA instance.
    Live(Arc<TaInstance>),
    /// The TA died, but normal world may still issue Invoke/Close for this ID.
    Dead,
}

/// Per-session entry in the session map.
#[derive(Clone)]
pub struct SessionEntry {
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
pub struct SessionMap {
    inner: SpinMutex<HashMap<u32, SessionEntry>>,
}

impl SessionMap {
    /// Create a new empty session map.
    pub fn new() -> Self {
        Self {
            inner: SpinMutex::new(HashMap::new()),
        }
    }

    /// Get a session's TA instance by session ID.
    pub fn get(&self, session_id: u32) -> Option<Arc<TaInstance>> {
        match self.inner.lock().get(&session_id).map(|e| &e.target) {
            Some(SessionTarget::Live(instance)) => Some(instance.clone()),
            Some(SessionTarget::Dead) | None => None,
        }
    }

    /// Get full session entry by session ID.
    pub fn get_entry(&self, session_id: u32) -> Option<SessionEntry> {
        self.inner.lock().get(&session_id).cloned()
    }

    /// Insert a session into the map.
    pub fn insert(
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
    pub fn remove(&self, session_id: u32) -> Option<SessionEntry> {
        self.inner.lock().remove(&session_id)
    }

    /// Get the number of active sessions.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Check if the session map is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Count sessions for a specific TA instance (by Arc pointer equality).
    pub fn count_sessions_for_instance(&self, instance: &Arc<TaInstance>) -> usize {
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
    pub fn mark_sessions_dead_for_instance(&self, instance: &Arc<TaInstance>) {
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
pub struct SingleInstanceCache {
    inner: SpinMutex<HashMap<TeeUuid, Arc<TaInstance>>>,
}

impl SingleInstanceCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            inner: SpinMutex::new(HashMap::new()),
        }
    }

    /// Get a cached single-instance TA by UUID.
    pub fn get(&self, uuid: &TeeUuid) -> Option<Arc<TaInstance>> {
        self.inner.lock().get(uuid).cloned()
    }

    /// Cache a single-instance TA by UUID.
    pub fn insert(&self, uuid: TeeUuid, instance: Arc<TaInstance>) {
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
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
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
pub fn recycle_session_id(session_id: u32) {
    SessionIdPool::recycle(session_id);
}

/// RAII guard that recycles a session ID on drop unless disarmed.
///
/// Session IDs are allocated before the TA is invoked and only registered on
/// success via [`SessionManager::register_session`]. This guard ensures it is
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
/// Acquired non-blockingly via [`SessionManager::try_acquire_for_session`]
/// for Invoke/Close on an existing session. OpenSession uses the same
/// token type internally through [`SessionManager::with_creation_slot`],
/// which manages acquisition and release on the caller's behalf.
///
/// Holds whichever combination of locks is required for the operation:
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
pub struct SessionToken<'a> {
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

/// State for coordinating concurrent instance creation.
///
/// Guarded by a single lock to provide atomic capacity checks.
struct CreationState {
    /// Number of instances currently being created (not yet registered).
    /// Added to [`SessionManager::instance_count`] for accurate capacity checks.
    pending_count: usize,
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
    /// Coordination state for concurrent instance creation.
    creation_state: SpinMutex<CreationState>,
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
            creation_state: SpinMutex::new(CreationState { pending_count: 0 }),
            known_flags: SpinMutex::new(HashMap::new()),
            single_instance_locks: SpinMutex::new(HashMap::new()),
            active_sessions: SpinMutex::new(HashSet::new()),
        }
    }

    /// Get the session map.
    pub fn sessions(&self) -> &SessionMap {
        &self.sessions
    }

    /// Get the single-instance cache.
    pub fn single_instance_cache(&self) -> &SingleInstanceCache {
        &self.single_instance_cache
    }

    /// Cache a single-instance TA.
    pub fn cache_single_instance(&self, uuid: TeeUuid, instance: Arc<TaInstance>) {
        self.single_instance_cache.insert(uuid, instance);
    }

    /// Get a session by ID.
    pub fn get_session(&self, session_id: u32) -> Option<Arc<TaInstance>> {
        self.sessions.get(session_id)
    }

    /// Get full session entry by ID.
    pub fn get_session_entry(&self, session_id: u32) -> Option<SessionEntry> {
        self.sessions.get_entry(session_id)
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

    /// Acquire a [`SessionToken`] for an OpenSession request.
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

    /// Acquire a [`SessionToken`] for an Invoke/Close on an existing session.
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
    /// the new entry from the start. This guards against the read/marker
    /// TOCTOU without relying on
    /// [`IdPool`](litebox::utils::id_pool::IdPool)'s hint+wrap to quarantine
    /// recycled ids.
    pub fn try_acquire_for_session(
        &self,
        session_id: u32,
    ) -> Result<SessionToken<'_>, OpteeSmcReturnCode> {
        let entry = self
            .sessions
            .get_entry(session_id)
            .ok_or(OpteeSmcReturnCode::EBadCmd)?;
        let snapshot_uuid = entry.ta_uuid;
        let snapshot_single = entry.ta_flags.is_single_instance();
        drop(entry);

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

        if snapshot_single {
            // On failure, dropping `token` releases the marker we just took.
            token.uuid_lock = Some(
                self.try_acquire_uuid_lock(snapshot_uuid)
                    .ok_or(OpteeSmcReturnCode::EThreadLimit)?,
            );
        }
        Ok(token)
    }

    /// Register a new session.
    pub fn register_session(
        &self,
        session_id: u32,
        instance: Arc<TaInstance>,
        ta_uuid: TeeUuid,
        ta_flags: TaFlags,
    ) {
        self.known_flags.lock().entry(ta_uuid).or_insert(ta_flags);
        self.sessions
            .insert(session_id, instance, ta_uuid, ta_flags);
    }

    /// Unregister a session, recycle its session ID, and return the entry.
    pub fn unregister_session(&self, session_id: u32) -> Option<SessionEntry> {
        let entry = self.sessions.remove(session_id);
        if entry.is_some() {
            recycle_session_id(session_id);
        }
        entry
    }

    /// Remove a single-instance TA from the cache only if the currently
    /// cached `Arc` is the same as `expected`.
    ///
    /// Callers tearing down on TA panic must have already called
    /// [`SessionMap::mark_sessions_dead_for_instance`] before invoking this,
    /// so any handler that subsequently acquires its own [`SessionToken`]
    /// for the UUID will observe `Dead` on its re-read of the session
    /// entry. Callers on the last-session-close path may skip the mark
    /// step — by that point there are no sibling sessions to fence out.
    pub fn remove_single_instance_if_same(
        &self,
        uuid: &TeeUuid,
        expected: &Arc<TaInstance>,
    ) -> bool {
        self.single_instance_cache.remove_if_same(uuid, expected)
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
    /// - Reserves a creation slot (atomic capacity check including in-flight
    ///   creations) and calls `f(None)` to load and register a new instance.
    ///   The slot is released when `f` returns, regardless of outcome.
    ///
    /// The per-UUID lock is released when this function returns; `f` runs
    /// under it. For multi-instance TAs each session gets its own
    /// independent `TaInstance`, so no per-UUID exclusion is required.
    pub fn with_creation_slot<F>(&self, uuid: &TeeUuid, f: F) -> Result<(), OpteeSmcReturnCode>
    where
        F: FnOnce(Option<Arc<TaInstance>>) -> Result<(), OpteeSmcReturnCode>,
    {
        let token = self.try_acquire_for_open(*uuid)?;
        let is_single_instance = token.uuid_lock.is_some();

        // For single-instance TAs the per-UUID lock above keeps our UUID's
        // cache entry stable. For multi-instance we don't consult the cache.
        if is_single_instance && let Some(existing) = self.single_instance_cache.get(uuid) {
            return f(Some(existing));
        }

        {
            let mut state = self.creation_state.lock();
            // Capacity check including in-flight creations.
            let total = self.instance_count() + state.pending_count;
            if total >= MAX_TA_INSTANCES {
                return Err(OpteeSmcReturnCode::ENomem);
            }
            state.pending_count += 1;
        }

        let result = f(None);

        {
            let mut state = self.creation_state.lock();
            state.pending_count = state.pending_count.saturating_sub(1);
        }

        result
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
