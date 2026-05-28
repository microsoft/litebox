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
//! TA execution is serialized externally; [`TaInstance`] is shared without an
//! inner mutex. The exclusivity invariant lives in [`SessionManager`] and is
//! acquired through an internal RAII `SessionToken` that bundles whichever
//! locks the current operation requires:
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
//! Cleanup paths flip sibling sessions to `Dead` before evicting the
//! cached instance; see [`SessionManager::evict_cached_instance`]
//! for the ordering rationale.
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
const MAX_TA_INSTANCES: usize = 16;

/// A loaded TA instance.
///
/// For single-instance TAs one instance is shared across all sessions; the
/// TA stays in memory until the last session closes (or, with
/// `TA_FLAG_INSTANCE_KEEP_ALIVE`, until explicit destroy). Each instance
/// has its own task page table that provides memory isolation from other TAs.
pub struct TaInstance {
    /// The shim must be kept alive to keep the loaded program's memory mappings valid.
    shim: OpteeShim,
    /// The loaded TA program state including entrypoints.
    /// Boxed to keep it at a fixed heap address - the Task inside must not be moved
    /// after initialization because it contains internal state that may not survive moves.
    loaded_program: alloc::boxed::Box<LoadedProgram>,
    /// The task page table ID associated with this TA instance.
    ///
    /// Also serves as the instance's identity for sibling-tracking
    /// operations: page table ids are minted by `create_task_page_table()`
    /// and not reused until the owning instance is fully torn down.
    task_page_table_id: usize,
    ta_uuid: TeeUuid,
}

impl TaInstance {
    pub fn task_page_table_id(&self) -> usize {
        self.task_page_table_id
    }

    pub fn shim(&self) -> &OpteeShim {
        &self.shim
    }

    pub fn loaded_program(&self) -> &LoadedProgram {
        &self.loaded_program
    }

    pub fn uuid(&self) -> TeeUuid {
        self.ta_uuid
    }
}

// SAFETY: `TaInstance`'s interior (`shim`, `loaded_program`) is not
// auto-`Send`/`Sync`, but every access goes through a `SessionToken` that
// serializes execution on the per-UUID lock (single-instance TAs) or the
// per-`session_id` marker (multi-instance TAs), so at most one core is
// ever inside a given instance. See the module-level "Concurrency Model".
unsafe impl Send for TaInstance {}
unsafe impl Sync for TaInstance {}

/// Per-session entry in the session map. The `Dead` variant retains
/// `(ta_uuid, ta_flags)` so cleanup paths and `try_acquire_for_session`'s
/// snapshot still have them after the instance is gone.
#[derive(Clone)]
enum SessionEntry {
    Live(Arc<TaInstance>),
    Dead { ta_uuid: TeeUuid, ta_flags: TaFlags },
}

impl SessionEntry {
    fn ta_uuid(&self) -> TeeUuid {
        match self {
            SessionEntry::Live(arc) => arc.ta_uuid,
            SessionEntry::Dead { ta_uuid, .. } => *ta_uuid,
        }
    }

    fn ta_flags(&self) -> TaFlags {
        match self {
            SessionEntry::Live(arc) => arc.loaded_program.ta_flags,
            SessionEntry::Dead { ta_flags, .. } => *ta_flags,
        }
    }
}

/// Session map for tracking active sessions.
///
/// Maps runner-allocated session IDs to session entries.
struct SessionMap {
    inner: SpinMutex<HashMap<u32, SessionEntry>>,
}

impl SessionMap {
    fn new() -> Self {
        Self {
            inner: SpinMutex::new(HashMap::new()),
        }
    }

    fn get_entry(&self, session_id: u32) -> Option<SessionEntry> {
        self.inner.lock().get(&session_id).cloned()
    }

    fn insert_live(&self, session_id: u32, instance: Arc<TaInstance>) {
        self.inner
            .lock()
            .insert(session_id, SessionEntry::Live(instance));
    }

    fn remove(&self, session_id: u32) -> Option<SessionEntry> {
        self.inner.lock().remove(&session_id)
    }

    /// Count live sessions whose instance has the given page table id.
    fn count_sessions_for_pt(&self, task_page_table_id: usize) -> usize {
        self.inner
            .lock()
            .values()
            .filter(|e| match e {
                SessionEntry::Live(arc) => arc.task_page_table_id == task_page_table_id,
                SessionEntry::Dead { .. } => false,
            })
            .count()
    }

    /// Mark all live sessions whose instance has the given page table id
    /// as `Dead`, capturing the instance's uuid and flags on the way out
    /// so cleanup paths still have them.
    fn mark_sessions_dead_for_pt(&self, task_page_table_id: usize) {
        for entry in self.inner.lock().values_mut() {
            let dead = match entry {
                SessionEntry::Live(arc) if arc.task_page_table_id == task_page_table_id => {
                    Some((arc.ta_uuid, arc.loaded_program.ta_flags))
                }
                _ => None,
            };
            if let Some((ta_uuid, ta_flags)) = dead {
                *entry = SessionEntry::Dead { ta_uuid, ta_flags };
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
struct SingleInstanceCache {
    inner: SpinMutex<HashMap<TeeUuid, Arc<TaInstance>>>,
}

impl SingleInstanceCache {
    fn new() -> Self {
        Self {
            inner: SpinMutex::new(HashMap::new()),
        }
    }

    fn get(&self, uuid: &TeeUuid) -> Option<Arc<TaInstance>> {
        self.inner.lock().get(uuid).cloned()
    }

    fn insert(&self, uuid: TeeUuid, instance: Arc<TaInstance>) {
        self.inner.lock().insert(uuid, instance);
    }

    /// Evict only if the cached instance matches `task_page_table_id`.
    /// Distinguishes the live instance from a freshly-created one with the
    /// same UUID when the caller wants to remove a specific one.
    fn remove_if_pt(&self, uuid: &TeeUuid, task_page_table_id: usize) -> bool {
        let mut guard = self.inner.lock();
        match guard.get(uuid) {
            Some(current) if current.task_page_table_id == task_page_table_id => {
                guard.remove(uuid);
                true
            }
            _ => false,
        }
    }

    fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

impl Default for SingleInstanceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `None` if all session IDs are exhausted.
pub fn allocate_session_id() -> Option<u32> {
    SessionIdPool::allocate()
}

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
    pub fn new(session_id: u32) -> Self {
        Self {
            session_id: Some(session_id),
        }
    }

    /// Returns `None` if already disarmed.
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
/// Bundles whichever combination of locks the current operation requires:
///
/// - **Single-instance TAs**: a per-UUID `SpinMutex` that serializes all
///   sessions on the same TA.
/// - **Existing-session operations** (Invoke/Close): a per-session-id marker
///   that prevents concurrent SMC entry by another core for the same id.
///
/// For multi-instance OpenSession the token holds nothing (each session
/// gets its own private instance, so no exclusion is required). The
/// first-ever OpenSession for an unknown UUID is the exception: until the
/// TA is loaded its flags aren't known, so it's conservatively serialized
/// under the per-UUID lock until flags are observed.
///
/// On drop, the per-UUID lock is released first, then the per-session-id
/// marker.
struct SessionToken<'a> {
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
/// The public entry points are the closure-bound [`SessionManager::with_ta`]
/// (OpenSession) and [`SessionManager::with_session`] (Invoke/Close), which
/// run the caller's closure under an internal `SessionToken`. State
/// mutations the closure performs on the manager (registration,
/// sibling-marking, cache eviction) are serialized by that token.
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

    /// Mark every session currently pointing at `instance` as `Dead`. Must
    /// be paired with [`SessionManager::evict_cached_instance`]
    /// in the documented order — see that function for the rationale.
    pub fn mark_sessions_dead_for_instance(&self, instance: &TaInstance) {
        self.sessions
            .mark_sessions_dead_for_pt(instance.task_page_table_id);
    }

    /// Count live sessions currently pointing at `instance` (`Dead` entries
    /// are skipped). Used by the last-close path to detect whether teardown
    /// is appropriate.
    pub fn count_sessions_for_instance(&self, instance: &TaInstance) -> usize {
        self.sessions
            .count_sessions_for_pt(instance.task_page_table_id)
    }

    /// Look up previously observed TA flags for a UUID.
    ///
    /// Returns `None` if this UUID has never been successfully loaded.
    /// Callers should conservatively assume single-instance when `None`.
    fn get_known_flags(&self, uuid: &TeeUuid) -> Option<TaFlags> {
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
    /// session. Returns the entry that survived the post-lock re-read so
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
    /// # Ordering
    ///
    /// The per-UUID lock is acquired *before* the final session-map
    /// re-read. This excludes concurrent `mark_sessions_dead_for_instance`
    /// and cache eviction (both of which require the UUID lock), so the
    /// `Live` / `Dead` state observed in the re-read remains authoritative
    /// for the lifetime of the returned token. Reading the entry before
    /// taking the UUID lock would let a sibling complete the entire
    /// mark-dead / evict / teardown sequence between our read and our
    /// lock acquisition, leaving us holding a stale `Live` entry pointing
    /// at a torn-down page table.
    ///
    /// Defense in depth: the entry's `(uuid, flags)` are validated against
    /// the pre-marker snapshot. If they diverge (the id was recycled and
    /// reused under a different TA between our first read and the marker
    /// insert), we return `EThreadLimit` so the Linux driver retries.
    fn try_acquire_for_session(
        &self,
        session_id: u32,
    ) -> Result<(SessionToken<'_>, SessionEntry), OpteeSmcReturnCode> {
        let entry = self
            .sessions
            .get_entry(session_id)
            .ok_or(OpteeSmcReturnCode::EBadCmd)?;
        let snapshot_uuid = entry.ta_uuid();
        let snapshot_single = entry.ta_flags().is_single_instance();

        if !self.active_sessions.lock().insert(session_id) {
            return Err(OpteeSmcReturnCode::EThreadLimit);
        }
        let mut token = SessionToken {
            manager: self,
            uuid_lock: None,
            active_session_id: Some(session_id),
        };

        // Take the per-UUID lock BEFORE the final re-read for single-
        // instance TAs. This blocks any concurrent mark-dead / cache
        // eviction so the re-read result is stable. On failure, the
        // token's `Drop` releases the marker we already took.
        if snapshot_single {
            token.uuid_lock = Some(
                self.try_acquire_uuid_lock(snapshot_uuid)
                    .ok_or(OpteeSmcReturnCode::EThreadLimit)?,
            );
        }

        // Re-read under both locks and validate against the snapshot.
        let entry_now = self
            .sessions
            .get_entry(session_id)
            .ok_or(OpteeSmcReturnCode::EBadCmd)?;
        if entry_now.ta_uuid() != snapshot_uuid
            || entry_now.ta_flags().is_single_instance() != snapshot_single
        {
            return Err(OpteeSmcReturnCode::EThreadLimit);
        }

        Ok((token, entry_now))
    }

    /// Drive an Invoke/Close to completion under the right serialization.
    ///
    /// Internally acquires the per-session-id marker (and, for single-
    /// instance TAs, the per-UUID lock), passes `Some(&TaInstance)` to `f`
    /// for live sessions or `None` for dead ones, and releases the locks
    /// when `f` returns. `f` runs entirely under the token: state
    /// mutations it performs on the session manager (e.g.
    /// `unregister_session`, `mark_sessions_dead_for_instance`,
    /// `evict_cached_instance`) are serialized against other
    /// cores' Invoke/Close on the same session and (for single-instance)
    /// the same UUID.
    ///
    /// Returns `Err(EBadCmd)` if `session_id` is not registered, or
    /// `Err(EThreadLimit)` on lock contention; the Linux OP-TEE driver
    /// retries `EThreadLimit` transparently.
    pub fn with_session<F>(&self, session_id: u32, f: F) -> Result<(), OpteeSmcReturnCode>
    where
        F: for<'a> FnOnce(Option<&'a TaInstance>) -> Result<(), OpteeSmcReturnCode>,
    {
        let (_token, entry) = self.try_acquire_for_session(session_id)?;
        let instance = match &entry {
            SessionEntry::Live(arc) => Some(&**arc),
            SessionEntry::Dead { .. } => None,
        };
        f(instance)
    }

    /// Register a session for a freshly-loaded TA. The three parts (`shim`,
    /// `loaded_program`, `task_page_table_id`) are taken by value and stored
    /// inside the manager; for single-instance TAs the instance is also
    /// cached under `ta_uuid` for later reuse.
    pub fn register_new_session(
        &self,
        session_id: u32,
        shim: OpteeShim,
        loaded_program: alloc::boxed::Box<LoadedProgram>,
        task_page_table_id: usize,
        ta_uuid: TeeUuid,
    ) {
        let ta_flags = loaded_program.ta_flags;
        let arc = Arc::new(TaInstance {
            shim,
            loaded_program,
            task_page_table_id,
            ta_uuid,
        });
        self.known_flags.lock().entry(ta_uuid).or_insert(ta_flags);
        self.sessions.insert_live(session_id, arc.clone());
        if ta_flags.is_single_instance() {
            self.single_instance_cache.insert(ta_uuid, arc);
        }
    }

    /// Register a session that re-uses an existing single-instance TA.
    ///
    /// `instance` is the borrow handed to the [`SessionManager::with_ta`]
    /// closure on the cache-hit branch. The cached instance for `ta_uuid`
    /// is matched against `task_page_table_id`. Under correct usage the
    /// caller holds the per-UUID lock (via `with_ta`'s token) for the
    /// duration, so the cache entry is stable and the lookup succeeds.
    ///
    /// Returns `Err(EBadCmd)` if no matching cached instance is found.
    /// This is an internal-consistency check rather than a recoverable
    /// runtime condition; in kernel code we surface it as an error rather
    /// than panicking.
    pub fn register_sibling_session(
        &self,
        session_id: u32,
        instance: &TaInstance,
    ) -> Result<(), OpteeSmcReturnCode> {
        let arc = self
            .single_instance_cache
            .get(&instance.ta_uuid)
            .filter(|cached| cached.task_page_table_id == instance.task_page_table_id)
            .ok_or(OpteeSmcReturnCode::EBadCmd)?;
        self.known_flags
            .lock()
            .entry(instance.ta_uuid)
            .or_insert(instance.loaded_program.ta_flags);
        self.sessions.insert_live(session_id, arc);
        Ok(())
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
        entry.map(|e| e.ta_flags())
    }

    /// Evict `instance` from the single-instance cache. No-op (returns
    /// `false`) if the cached entry under `instance.uuid()` is a different
    /// instance — matched by `task_page_table_id` to distinguish the
    /// caller's instance from a freshly-cached replacement.
    ///
    /// Callers tearing down on TA panic must have already called
    /// [`SessionManager::mark_sessions_dead_for_instance`] before invoking
    /// this, so any handler that subsequently enters
    /// [`SessionManager::with_ta`] or [`SessionManager::with_session`] for
    /// the UUID will observe `Dead` on its re-read of the session entry.
    /// Callers on the last-session-close path may skip the mark step — by
    /// that point there are no sibling sessions to fence out.
    pub fn evict_cached_instance(&self, instance: &TaInstance) -> bool {
        self.single_instance_cache
            .remove_if_pt(&instance.ta_uuid, instance.task_page_table_id)
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
            .filter(|e| !e.ta_flags().is_single_instance())
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
        F: for<'a> FnOnce(Option<&'a TaInstance>) -> Result<(), OpteeSmcReturnCode>,
    {
        let token = self.try_acquire_for_open(*uuid)?;
        let is_single_instance = token.uuid_lock.is_some();

        // For single-instance TAs the per-UUID lock above keeps our UUID's
        // cache entry stable. For multi-instance we don't consult the cache.
        if is_single_instance && let Some(existing) = self.single_instance_cache.get(uuid) {
            return f(Some(&existing));
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

        // `single_instance_locks` entries are never evicted; safe removal
        // would need generational tracking. Leak is bounded by distinct UUIDs.
        result
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::tests::init_platform;

    fn make_shim() -> OpteeShim {
        let _ = init_platform();
        crate::OpteeShimBuilder::new().build()
    }

    fn make_loaded_program(ta_flags: TaFlags) -> alloc::boxed::Box<LoadedProgram> {
        alloc::boxed::Box::new(LoadedProgram {
            entrypoints: None,
            params_address: None,
            ta_flags,
        })
    }

    fn make_uuid(seed: u8) -> TeeUuid {
        TeeUuid::from_bytes([seed; 16])
    }

    fn single_instance_flags() -> TaFlags {
        TaFlags::SINGLE_INSTANCE | TaFlags::MULTI_SESSION
    }

    /// Identity is by `task_page_table_id`, not by Arc pointer. After an
    /// instance is evicted and a fresh one registered under the same UUID,
    /// the stale handle must not evict the new one.
    #[test]
    fn evict_cached_instance_distinguishes_stale_handle() {
        let manager = SessionManager::new();
        let uuid = make_uuid(0xA4);

        manager.register_new_session(
            105,
            make_shim(),
            make_loaded_program(single_instance_flags()),
            10,
            uuid,
        );
        let arc_first = manager.single_instance_cache.get(&uuid).unwrap();
        manager.evict_cached_instance(&arc_first);

        manager.register_new_session(
            106,
            make_shim(),
            make_loaded_program(single_instance_flags()),
            11,
            uuid,
        );
        assert!(!manager.evict_cached_instance(&arc_first));
        assert!(manager.single_instance_cache.get(&uuid).is_some());
    }

    /// `mark_sessions_dead_for_instance` flips Live entries to Dead — they
    /// stop counting for `count_sessions_for_instance`, and `with_session`
    /// thereafter sees `None` so cleanup paths run.
    #[test]
    fn mark_dead_makes_with_session_observe_none() {
        let manager = SessionManager::new();
        let uuid = make_uuid(0xA6);
        manager.register_new_session(
            108,
            make_shim(),
            make_loaded_program(single_instance_flags()),
            55,
            uuid,
        );
        let arc = manager.single_instance_cache.get(&uuid).unwrap();
        assert_eq!(manager.count_sessions_for_instance(&arc), 1);

        manager.mark_sessions_dead_for_instance(&arc);
        assert_eq!(manager.count_sessions_for_instance(&arc), 0);

        manager
            .with_session(108, |instance| {
                assert!(instance.is_none());
                Ok(())
            })
            .unwrap();
    }

    /// Per-session-id marker excludes re-entry on the same id, but releases
    /// when the closure returns.
    #[test]
    fn with_session_marker_excludes_reentry() {
        let manager = SessionManager::new();
        let uuid = make_uuid(0xA7);
        manager.register_new_session(
            109,
            make_shim(),
            make_loaded_program(single_instance_flags()),
            6,
            uuid,
        );

        manager
            .with_session(109, |_| {
                assert_eq!(
                    manager.with_session(109, |_| Ok(())),
                    Err(OpteeSmcReturnCode::EThreadLimit)
                );
                Ok(())
            })
            .unwrap();
        manager.with_session(109, |_| Ok(())).unwrap();
    }

    /// `single_instance_locks` entries are never evicted, even on failure
    /// of a previously-unknown UUID.
    #[test]
    fn with_ta_never_evicts_lock_entry() {
        let manager = SessionManager::new();
        let uuid = make_uuid(0xA9);
        assert!(manager.get_known_flags(&uuid).is_none());

        let _ = manager.with_ta(&uuid, |_| Err(OpteeSmcReturnCode::ENotAvail));
        assert!(manager.single_instance_locks.lock().get(&uuid).is_some());
    }

    /// `try_acquire_for_session` returns the entry observed by the
    /// post-marker re-read, not a stale handle from before the marker was
    /// taken. After a recycle+re-register under a new UUID, the returned
    /// entry must reflect the current UUID. (The mismatch-rejection branch
    /// itself can only be triggered by a concurrent swap between snapshot
    /// and re-read, which isn't reproducible in a single-threaded test;
    /// this just verifies the re-read is the source of truth.)
    #[test]
    fn try_acquire_for_session_returns_current_entry_after_recycle() {
        let manager = SessionManager::new();
        let uuid_a = make_uuid(0xB0);
        let uuid_b = make_uuid(0xB1);
        let session_id = 222;

        manager.register_new_session(
            session_id,
            make_shim(),
            make_loaded_program(single_instance_flags()),
            70,
            uuid_a,
        );
        manager.unregister_session(session_id);
        manager.register_new_session(
            session_id,
            make_shim(),
            make_loaded_program(single_instance_flags()),
            71,
            uuid_b,
        );

        let (_, validated) = manager.try_acquire_for_session(session_id).unwrap();
        assert_eq!(validated.ta_uuid(), uuid_b);
    }

    /// `pending_count` is bumped only on the create path, never on the
    /// cache-hit path, and is decremented when the closure returns whether
    /// success or failure — across multiple calls it must return to zero.
    #[test]
    fn pending_count_returns_to_zero_across_paths() {
        let manager = SessionManager::new();
        let uuid_multi = make_uuid(0xC0);
        let uuid_single = make_uuid(0xC1);

        // Successful create path.
        manager
            .with_ta(&uuid_multi, |existing| {
                assert!(existing.is_none());
                manager.register_new_session(
                    301,
                    make_shim(),
                    make_loaded_program(TaFlags::default()),
                    80,
                    uuid_multi,
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(*manager.pending_count.lock(), 0);

        // Failing create path on an unknown UUID.
        let _ = manager.with_ta(&uuid_single, |_| Err(OpteeSmcReturnCode::ENotAvail));
        assert_eq!(*manager.pending_count.lock(), 0);

        // Cache-hit path doesn't touch pending_count.
        manager.register_new_session(
            302,
            make_shim(),
            make_loaded_program(single_instance_flags()),
            81,
            uuid_single,
        );
        manager.with_ta(&uuid_single, |_| Ok(())).unwrap();
        assert_eq!(*manager.pending_count.lock(), 0);
    }
}
