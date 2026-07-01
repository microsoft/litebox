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
//! TA execution is serialized externally; [`TaInstance`] is shared without
//! an inner mutex. The exclusivity invariant lives in [`SessionManager`]
//! and is acquired through an internal RAII `SessionToken` that bundles
//! whichever locks the current operation requires — see `SessionToken`'s
//! doc for the per-case breakdown.
//!
//! Both [`SessionManager::with_ta`] (OpenSession) and
//! [`SessionManager::with_session`] (Invoke/Close) acquire the token
//! non-blockingly, run the caller's closure under it, and release on
//! return. On contention they return `EThreadLimit`.
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
//! Panic cleanup paths flip all sessions for the failed instance to `Dead`
//! and evict the matching cached instance via
//! [`SessionManager::mark_sessions_dead_for_instance`].
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
use core::sync::atomic::{AtomicBool, Ordering};
use hashbrown::{HashMap, HashSet};
use litebox_common_optee::{OpteeSmcReturnCode, TaFlags, TeeIdentity, TeeLogin, TeeUuid};
use spin::mutex::SpinMutex;

/// Maximum number of concurrent TA instances to avoid out of memory situations.
const MAX_TA_INSTANCES: usize = 16;

/// The anonymous public client identity. Used as the fallback when no per-session
/// identity is recorded, matching OP-TEE OS / the Linux driver.
const ANONYMOUS_CLIENT_IDENTITY: TeeIdentity = TeeIdentity {
    login: TeeLogin::Public,
    uuid: TeeUuid::NIL,
};

/// A loaded TA instance.
///
/// For single-instance TAs one instance is shared across all sessions; the
/// TA stays in memory until the last session closes (if it does not have the
/// `TA_FLAG_INSTANCE_KEEP_ALIVE` flag). Each instance has its own task page
/// table that provides memory isolation from other TAs.
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

/// What an OpenSession should do given the current cache state for a
/// `uuid`, as decided by [`SessionManager::with_ta`] under its
/// serialization. The closure dispatches on the variant.
pub enum OpenSessionTarget<'a> {
    /// No cached single-instance instance for this UUID (either it's
    /// not single-instance, or the cache is empty). Closure should load
    /// a fresh TA and call `register_new_session`.
    NewInstance,
    /// A cached single-instance TA is available for sharing. Closure
    /// should reuse it for a sibling session via `register_sibling_session`.
    Sibling(&'a TaInstance),
    /// A cached single-instance TA exists but it lacks `TA_FLAG_MULTI_SESSION`
    /// and already has at least one live session. Per OP-TEE OS
    /// `tee_ta_init_session_with_context`, reject with
    /// `TEE_ERROR_BUSY` (origin TEE).
    Busy,
}

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
    /// Create a new empty session map.
    fn new() -> Self {
        Self {
            inner: SpinMutex::new(HashMap::new()),
        }
    }

    /// Get full session entry by session ID.
    fn get_entry(&self, session_id: u32) -> Option<SessionEntry> {
        self.inner.lock().get(&session_id).cloned()
    }

    /// Insert a live session into the map.
    fn insert_live(&self, session_id: u32, instance: Arc<TaInstance>) {
        self.inner
            .lock()
            .insert(session_id, SessionEntry::Live(instance));
    }

    /// Remove a session from the map.
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
    /// Create a new empty cache.
    fn new() -> Self {
        Self {
            inner: SpinMutex::new(HashMap::new()),
        }
    }

    /// Get a cached single-instance TA by UUID.
    fn get(&self, uuid: &TeeUuid) -> Option<Arc<TaInstance>> {
        self.inner.lock().get(uuid).cloned()
    }

    /// Cache a single-instance TA by UUID.
    fn insert(&self, uuid: TeeUuid, instance: Arc<TaInstance>) {
        self.inner.lock().insert(uuid, instance);
    }

    /// Evict only if the cached instance matches `task_page_table_id`.
    /// Distinguishes the live instance from a freshly-created one with the
    /// same UUID when the caller wants to remove a specific one.
    fn remove_matching_instance(&self, uuid: &TeeUuid, task_page_table_id: usize) -> bool {
        let mut guard = self.inner.lock();
        match guard.get(uuid) {
            Some(current) if current.task_page_table_id == task_page_table_id => {
                guard.remove(uuid);
                true
            }
            _ => false,
        }
    }

    /// Get the number of cached single-instance TAs.
    fn len(&self) -> usize {
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
fn allocate_session_id() -> Option<u32> {
    SessionIdPool::allocate()
}

/// Recycle a session ID for potential future reuse.
///
/// Delegates to `SessionIdPool::recycle`.
fn recycle_session_id(session_id: u32) {
    SessionIdPool::recycle(session_id);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeldUuidLock {
    SingleInstance(TeeUuid),
    TaLoad,
}

/// An unified RAII token to safely execute an OP-TEE TA operation with
/// instance- or session-specific serialization primitives.
///
/// Bundles whichever combination of locks the current operation requires:
///
/// - **Known single-instance TAs**: a per-UUID lock flag (a `bool` slot in
///   `single_instance_locks`) that serializes all sessions on the same TA.
/// - **First-ever load of a not-yet-known UUID** (OpenSession only): the
///   global `ta_load_lock`, used until the TA's flags (single-instance vs
///   multi-instance) are observed.
/// - **Existing-session operations** (Invoke/Close): a per-session-id
///   marker (slot in `SessionManager::active_sessions`) that prevents
///   concurrent SMC entry by another core for the same id.
/// - **OpenSession (runner-facing)**: same per-session-id marker plus
///   a freshly-allocated `session_id` whose recycling the token owns
///   until [`Self::disarm`]. Acquired via
///   [`SessionManager::try_acquire_open_session_token`].
///
/// For known multi-instance OpenSession the token (from `with_ta`)
/// holds nothing — each session gets its own private instance, so no
/// exclusion is required there.
///
/// On drop the held UUID-level lock is released first (whether per-UUID
/// or the global load lock), then the per-session-id marker, then
/// (if still owned) the session id is recycled.
pub struct SessionToken<'a> {
    manager: &'a SessionManager,
    /// Logical UUID-level lock owned by this token. The actual lock state
    /// lives in `SessionManager`; `Drop` releases it (clears the held flag).
    uuid_lock: Option<HeldUuidLock>,
    /// `Some(id)` while the token holds the active-session marker for `id`
    /// in [`SessionManager::active_sessions`]. Drop releases the marker.
    active_session_id: Option<u32>,
    /// Whether `active_session_id` should also be recycled to the id pool
    /// on drop (in addition to releasing the marker). Set when the id was
    /// freshly allocated by
    /// [`SessionManager::try_acquire_open_session_token`]; cleared by
    /// [`Self::disarm`] after the id is transferred to the session map via
    /// `register_*_session`. Only meaningful when `active_session_id` is
    /// `Some`; ignored otherwise.
    owns_id_recycling: bool,
}

impl SessionToken<'_> {
    /// Session id this token reserves the active-session marker for, if any.
    /// Set for tokens minted by
    /// [`SessionManager::try_acquire_open_session_token`] or
    /// `try_acquire_for_session` (Invoke/Close).
    pub fn session_id(&self) -> Option<u32> {
        self.active_session_id
    }

    /// Transfer id-recycling responsibility off the token. Call after the
    /// id has been registered via `register_new_session` /
    /// `register_sibling_session`; from that point the session map (via
    /// `unregister_session`) owns recycling, and the token's drop will
    /// only release the marker (and any locks).
    pub fn disarm(&mut self) {
        self.owns_id_recycling = false;
    }
}

impl Drop for SessionToken<'_> {
    fn drop(&mut self) {
        if let Some(lock) = self.uuid_lock.take() {
            self.manager.release_uuid_lock(lock);
        }
        if let Some(id) = self.active_session_id.take() {
            self.manager.active_sessions.lock().remove(&id);
            if self.owns_id_recycling {
                // The session was never published (an OpenSession failure
                // path), so the id is recycled here. Drop any client identity
                // recorded for it to avoid unnecessary memory leak.
                self.manager.clear_session_client_identity(id);
                recycle_session_id(id);
            }
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
    ///
    /// TODO: a TA's flags (in particular single- vs multi-instance) can
    /// change across a version update of the same UUID. Key this map by
    /// `(uuid, version)` — or invalidate on version mismatch — once TA
    /// versioning is wired through, so a re-loaded TA isn't serialized
    /// under the old flags.
    known_flags: SpinMutex<HashMap<TeeUuid, TaFlags>>,
    /// Per-UUID serialization state for single-instance TA handling
    /// (`true` == held). Entries are created lazily only for UUIDs that
    /// have been observed to be single-instance — never for unknown UUIDs
    /// whose load might fail or turn out to be multi-instance.
    ///
    /// We do not remove its entry even if the instance is destroyed to
    /// support a future reload of the same TA. This is bounded in
    /// practice because we only support a few managed TAs. This entry
    /// management should be aligned with `known_flags`.
    single_instance_locks: SpinMutex<HashMap<TeeUuid, bool>>,
    /// Global gate that serializes the first-ever load of not-yet-known
    /// UUIDs. Held by a first-loader until the TA's flags are observed; for a
    /// single-instance TA, ownership is then handed off to its per-UUID lock
    /// (see [`SessionToken`]). Known multi-instance UUIDs take no lock.
    ta_load_lock: AtomicBool,
    /// Session ids currently being handled (Invoke/Close). Guards a session
    /// against concurrent SMC entry by another core that targets the same id.
    active_sessions: SpinMutex<HashSet<u32>>,
    /// Per-session client identity, matching OP-TEE OS's `tee_ta_session.clnt_id`.
    ///
    /// Populated before the OpenSession entry point runs and removed when
    /// the session is unregistered.
    session_client_identities: SpinMutex<HashMap<u32, TeeIdentity>>,
}

/// Get the global session manager.
pub fn session_manager() -> &'static SessionManager {
    static SESSION_MANAGER: once_cell::race::OnceBox<SessionManager> =
        once_cell::race::OnceBox::new();
    SESSION_MANAGER.get_or_init(|| alloc::boxed::Box::new(SessionManager::new()))
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: SessionMap::new(),
            single_instance_cache: SingleInstanceCache::new(),
            pending_count: SpinMutex::new(0),
            known_flags: SpinMutex::new(HashMap::new()),
            single_instance_locks: SpinMutex::new(HashMap::new()),
            ta_load_lock: AtomicBool::new(false),
            active_sessions: SpinMutex::new(HashSet::new()),
            session_client_identities: SpinMutex::new(HashMap::new()),
        }
    }

    /// Allocate a fresh `session_id` and reserve its active-session slot.
    /// See [`SessionToken`] for what the returned token carries.
    ///
    /// # Drop-order requirement
    ///
    /// On the OpenSession path the runner activates a TA page table
    /// (`TaskPageTableGuard`) inside the same scope. The token *must* be
    /// declared **before** that guard so it drops **after** it — the
    /// marker must outlive the CR3 switch back to base, otherwise a
    /// forged Close on the freshly-registered session can win the
    /// marker race and tear down the task page table while CR3 still
    /// points at it. (Single-instance is already covered by `with_ta`'s
    /// per-UUID lock; this is the only defense for multi-instance.)
    ///
    /// # Errors
    /// - `EBusy` if the id pool is exhausted.
    pub fn try_acquire_open_session_token(&self) -> Result<SessionToken<'_>, OpteeSmcReturnCode> {
        let session_id = allocate_session_id().ok_or(OpteeSmcReturnCode::EBusy)?;
        // The id pool's hint+wrap allocator defers reuse of recycled ids,
        // so a freshly-allocated id can never collide with a marker slot
        // that's still held by a previous owner.
        let inserted = self.active_sessions.lock().insert(session_id);
        if !inserted && !cfg!(debug_assertions) {
            litebox_util_log::warn!(session_id = session_id; "freshly-allocated session_id collided with an active marker");
        }
        debug_assert!(
            inserted,
            "freshly-allocated session_id collided with an active marker"
        );
        Ok(SessionToken {
            manager: self,
            uuid_lock: None,
            active_session_id: Some(session_id),
            owns_id_recycling: true,
        })
    }

    /// Retire a dead single-instance TA from service.
    ///
    /// Marks every session currently pointing at `instance` as `Dead` and
    /// evicts the matching entry from the single-instance cache. Use when
    /// tearing down a *failed* TA that may still have sibling sessions.
    pub fn mark_sessions_dead_for_instance(&self, instance: &TaInstance) {
        self.sessions
            .mark_sessions_dead_for_pt(instance.task_page_table_id);
        let _ = self.evict_cached_instance(instance);
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

    /// Try to take the per-UUID serialization state non-blockingly.
    fn try_acquire_uuid_lock(&self, uuid: TeeUuid) -> Option<HeldUuidLock> {
        let mut locks = self.single_instance_locks.lock();
        let held = locks.entry(uuid).or_insert(false);
        if *held {
            None
        } else {
            *held = true;
            Some(HeldUuidLock::SingleInstance(uuid))
        }
    }

    fn release_uuid_lock(&self, lock: HeldUuidLock) {
        match lock {
            HeldUuidLock::SingleInstance(uuid) => {
                if let Some(held) = self.single_instance_locks.lock().get_mut(&uuid) {
                    debug_assert!(*held);
                    *held = false;
                }
            }
            HeldUuidLock::TaLoad => {
                let was_held = self.ta_load_lock.swap(false, Ordering::Release);
                debug_assert!(was_held);
            }
        }
    }

    /// Try to take the global `ta_load_lock` non-blockingly.
    fn try_acquire_ta_load_lock(&self) -> Option<HeldUuidLock> {
        self.ta_load_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| HeldUuidLock::TaLoad)
    }

    /// Acquire a `SessionToken` for an OpenSession request.
    ///
    /// Dispatches by what's known about `uuid`:
    ///
    /// - **Known single-instance**: per-UUID lock flag.
    /// - **Known multi-instance**: no lock (each session is independent).
    /// - **Unknown**: the global `ta_load_lock`. This serializes first-loads
    ///   of all not-yet-known UUIDs together, but avoids minting a per-UUID
    ///   lock entry until the TA has been confirmed single-instance. A failed
    ///   or multi-instance load therefore leaves no stale entry in
    ///   `single_instance_locks`.
    ///
    /// Returns `Err(EThreadLimit)` on contention.
    fn try_acquire_for_open(&self, uuid: TeeUuid) -> Result<SessionToken<'_>, OpteeSmcReturnCode> {
        let uuid_lock = match self.get_known_flags(&uuid) {
            Some(flags) if flags.is_single_instance() => Some(
                self.try_acquire_uuid_lock(uuid)
                    .ok_or(OpteeSmcReturnCode::EThreadLimit)?,
            ),
            Some(_) => None,
            None => Some(
                self.try_acquire_ta_load_lock()
                    .ok_or(OpteeSmcReturnCode::EThreadLimit)?,
            ),
        };
        Ok(SessionToken {
            manager: self,
            uuid_lock,
            active_session_id: None,
            owns_id_recycling: false,
        })
    }

    /// Acquire a token + validated entry for an Invoke/Close on an existing
    /// session. Returns the entry that survived the post-lock re-read so
    /// callers don't need to look it up again.
    ///
    /// Always reserves the per-session-id slot in `active_sessions`. For
    /// single-instance TAs additionally takes the per-UUID lock so
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
    /// and cache eviction (which callers perform only while holding the UUID
    /// lock), so the `Live` / `Dead` state observed in the re-read remains
    /// authoritative for the lifetime of the returned token. Reading the
    /// entry before taking the UUID lock would let a sibling complete the
    /// entire mark-dead / evict / teardown sequence between our read and our
    /// lock acquisition, leaving us holding a stale `Live` entry pointing
    /// at a torn-down page table.
    ///
    /// Defense in depth: the entry's `(uuid, flags)` are validated against
    /// the state observed before inserting the active-session marker. If
    /// they diverge (the id was recycled and reused under a different TA
    /// between our first read and the marker insert), we return
    /// `EThreadLimit` so the Linux driver retries.
    fn try_acquire_for_session(
        &self,
        session_id: u32,
    ) -> Result<(SessionToken<'_>, SessionEntry), OpteeSmcReturnCode> {
        let entry = self
            .sessions
            .get_entry(session_id)
            .ok_or(OpteeSmcReturnCode::EBadCmd)?;
        let pre_marker_uuid = entry.ta_uuid();
        let pre_marker_single = entry.ta_flags().is_single_instance();

        if !self.active_sessions.lock().insert(session_id) {
            return Err(OpteeSmcReturnCode::EThreadLimit);
        }
        let mut token = SessionToken {
            manager: self,
            uuid_lock: None,
            active_session_id: Some(session_id),
            owns_id_recycling: false,
        };

        // Take the per-UUID lock BEFORE the final re-read for single-
        // instance TAs. This blocks any concurrent mark-dead / cache
        // eviction so the re-read result is stable. On failure, the
        // token's `Drop` releases the marker we already took.
        if pre_marker_single {
            token.uuid_lock = Some(
                self.try_acquire_uuid_lock(pre_marker_uuid)
                    .ok_or(OpteeSmcReturnCode::EThreadLimit)?,
            );
        }

        // Re-read under both locks and validate against the pre-marker state.
        let entry_now = self
            .sessions
            .get_entry(session_id)
            .ok_or(OpteeSmcReturnCode::EBadCmd)?;
        if entry_now.ta_uuid() != pre_marker_uuid
            || entry_now.ta_flags().is_single_instance() != pre_marker_single
        {
            return Err(OpteeSmcReturnCode::EThreadLimit);
        }

        Ok((token, entry_now))
    }

    /// Drive an Invoke/Close to completion under the right serialization
    /// (see [`SessionToken`] for the locks held). Passes
    /// `Some(&TaInstance)` to `f` for live sessions, `None` for dead
    /// ones. State mutations `f` performs on the manager
    /// (`unregister_session`, `mark_sessions_dead_for_instance`,
    /// `evict_cached_instance`) are serialized against concurrent
    /// Invoke/Close on the same session and (single-instance) the same UUID.
    ///
    /// Returns `Err(EBadCmd)` if `session_id` is not registered, or
    /// `Err(EThreadLimit)` on lock contention (driver retries
    /// transparently).
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
    ///
    /// # Publication order
    ///
    /// `sessions` and (for single-instance) `single_instance_cache` are
    /// populated *before* `known_flags`. Other openers gate on
    /// `known_flags` to decide their lock path — once they observe `uuid`
    /// as known single-instance, the cache is guaranteed to already
    /// contain the entry, so they take the sibling/cache-hit branch
    /// rather than racing into a duplicate load.
    ///
    /// # Unknown→per-UUID transition
    ///
    /// For single-instance TAs we mark the per-UUID state held *before*
    /// publishing `known_flags` so any later opener that observes `uuid`
    /// as known single-instance and routes to the per-UUID state finds it
    /// already held. [`Self::with_ta`] adopts this state for *its own*
    /// `uuid` by replacing the token's load-lock marker with a
    /// per-UUID marker. This is UUID-keyed end-to-end: no shared side
    /// channel, so concurrent `with_ta` calls for different UUIDs cannot
    /// interfere with each other's adoptions.
    ///
    /// `try_acquire_uuid_lock` succeeds only on the load-lock path (caller
    /// holds `ta_load_lock`, no sessions or `known_flags` entry for
    /// `uuid` yet). On the known-cache-evicted path the caller already
    /// holds the per-UUID state and acquisition returns `None`, so
    /// nothing changes (the caller's existing lock is sufficient).
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

        // Pre-hold per-UUID state for atomic unknown→per-UUID transition
        // (see method doc). On known-cache-evicted paths this returns
        // `None` because the caller already owns the per-UUID state.
        if ta_flags.is_single_instance() {
            let _ = self.try_acquire_uuid_lock(ta_uuid);
        }

        self.sessions.insert_live(session_id, arc.clone());
        if ta_flags.is_single_instance() {
            self.single_instance_cache.insert(ta_uuid, arc);
        }
        // Publish `known_flags` last — this is the gate other openers check.
        self.known_flags.lock().entry(ta_uuid).or_insert(ta_flags);
    }

    /// Register a session that re-uses an existing single-instance TA.
    ///
    /// `instance` is the cached handle handed to the
    /// [`SessionManager::with_ta`] closure on the cache-hit branch.
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
        // `known_flags` is already populated for this UUID — sibling path
        // implies the instance was previously registered.
        self.sessions.insert_live(session_id, arc);
        Ok(())
    }

    /// Record the client identity for `session_id`.
    pub fn set_session_client_identity(&self, session_id: u32, identity: Option<TeeIdentity>) {
        self.session_client_identities
            .lock()
            .insert(session_id, identity.unwrap_or(ANONYMOUS_CLIENT_IDENTITY));
    }

    /// The client identity recorded for `session_id`, or the anonymous public
    /// client if none was recorded.
    pub(crate) fn client_identity(&self, session_id: u32) -> TeeIdentity {
        self.session_client_identities
            .lock()
            .get(&session_id)
            .copied()
            .unwrap_or(ANONYMOUS_CLIENT_IDENTITY)
    }

    /// Drop the recorded client identity for `session_id`.
    ///
    /// Called directly only on OpenSession rollback paths (the TA's OpenSession
    /// failed, so the session is never published). The normal close path calls
    /// this indirectly via [`Self::unregister_session`].
    pub fn clear_session_client_identity(&self, session_id: u32) {
        self.session_client_identities.lock().remove(&session_id);
    }

    /// Unregister a session and recycle its session ID. Returns whether
    /// the session was registered and what flags it had (the latter for
    /// callers that need to dispatch on `is_single_instance` /
    /// `is_keep_alive` after removal).
    pub fn unregister_session(&self, session_id: u32) -> Option<TaFlags> {
        let entry = self.sessions.remove(session_id);
        self.clear_session_client_identity(session_id);
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
    /// TA panic teardown should use
    /// [`SessionManager::mark_sessions_dead_for_instance`] instead; it marks
    /// all sessions for the failed instance dead and evicts the cache entry
    /// in one transition. Later [`SessionManager::with_session`] calls for
    /// existing session IDs will observe `Dead` on re-read, while later
    /// [`SessionManager::with_ta`] calls for the UUID cannot reuse the dead
    /// cached instance.
    /// Callers on the last-session-close path may skip the mark step — by
    /// that point there are no sibling sessions to fence out.
    pub fn evict_cached_instance(&self, instance: &TaInstance) -> bool {
        self.single_instance_cache
            .remove_matching_instance(&instance.ta_uuid, instance.task_page_table_id)
    }

    /// Get the total count of unique TA instances (for limit checking).
    ///
    /// This counts:
    /// - All single-instance TAs in the cache (each UUID = 1 instance, regardless of session count)
    /// - All multi-instance TA sessions (each session = 1 instance)
    fn instance_count(&self) -> usize {
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

    /// Drive an OpenSession to completion under the right serialization.
    ///
    /// Acquires the UUID-level lock for `uuid` (see [`SessionToken`] for
    /// the case breakdown), classifies the cache state, and dispatches
    /// via [`OpenSessionTarget`]:
    ///
    /// - [`OpenSessionTarget::Sibling`] for a cached single-instance TA
    ///   that admits another session.
    /// - [`OpenSessionTarget::Busy`] for the OP-TEE-OS-defined
    ///   `TA_FLAG_MULTI_SESSION` violation (single-instance without
    ///   MULTI_SESSION already has a live session).
    /// - [`OpenSessionTarget::NewInstance`] otherwise: reserves a
    ///   creation slot (capacity check against
    ///   `instance_count() + pending_count`) and lets the closure load
    ///   and register a fresh instance.
    ///
    /// `pending_count` exists only for capacity accounting so two
    /// concurrent multi-instance loads can't both pass the limit before
    /// either registers. The single-instance / unknown paths are
    /// serialized by the UUID-level lock itself.
    pub fn with_ta<F>(&self, uuid: &TeeUuid, f: F) -> Result<(), OpteeSmcReturnCode>
    where
        F: for<'a> FnOnce(OpenSessionTarget<'a>) -> Result<(), OpteeSmcReturnCode>,
    {
        let mut token = self.try_acquire_for_open(*uuid)?;
        // Captured before `f` runs so we know whether to perform the
        // load-lock→per-UUID adoption step after successful registration.
        let on_ta_load_path = matches!(token.uuid_lock, Some(HeldUuidLock::TaLoad));

        // Cache lookup is unconditional: it returns `None` for known
        // multi-instance and unknown UUIDs (never populated), and only
        // returns `Some` for known single-instance UUIDs whose entry the
        // per-UUID lock above keeps stable.
        if let Some(existing) = self.single_instance_cache.get(uuid) {
            // MULTI_SESSION enforcement (matches OP-TEE OS
            // `tee_ta_init_session_with_context`). Under the per-UUID lock
            // the session count is stable across this check and the
            // closure, so a parallel Close/Invoke can't change it.
            let flags = existing.loaded_program().ta_flags;
            let target =
                if !flags.is_multi_session() && self.count_sessions_for_instance(&existing) > 0 {
                    OpenSessionTarget::Busy
                } else {
                    OpenSessionTarget::Sibling(&existing)
                };
            return f(target);
        }

        {
            let mut pending = self.pending_count.lock();
            // Capacity check including in-flight creations.
            if self.instance_count() + *pending >= MAX_TA_INSTANCES {
                return Err(OpteeSmcReturnCode::ENomem);
            }
            *pending += 1;
        }

        let result = f(OpenSessionTarget::NewInstance);

        {
            let mut pending = self.pending_count.lock();
            *pending = pending.saturating_sub(1);
        }

        // Complete the load-lock→per-UUID transition (see
        // `register_new_session` doc). Only fires when we held the
        // `ta_load_lock` AND the closure registered a single-instance
        // TA for *our* `uuid`. The per-UUID state is already held from
        // `register_new_session`'s pre-hold; swap the token to own that
        // state and release the load lock. Token drop then releases the
        // per-UUID state at the end of `with_ta`. UUID-keyed throughout, so
        // concurrent `with_ta(other_uuid)` cannot adopt our lock.
        if result.is_ok()
            && on_ta_load_path
            && self.single_instance_cache.get(uuid).is_some()
            && let Some(old) = token.uuid_lock.replace(HeldUuidLock::SingleInstance(*uuid))
        {
            self.release_uuid_lock(old);
        }

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

    /// Test helper: call `register_new_session` directly and release the
    /// pre-held per-UUID lock state the way `with_ta` would, so subsequent
    /// operations (Invoke/Close, evict, count, etc.) aren't blocked.
    fn register_for_test(
        manager: &SessionManager,
        session_id: u32,
        ta_flags: TaFlags,
        task_page_table_id: usize,
        ta_uuid: TeeUuid,
    ) {
        manager.register_new_session(
            session_id,
            make_shim(),
            make_loaded_program(ta_flags),
            task_page_table_id,
            ta_uuid,
        );
        if ta_flags.is_single_instance()
            && let Some(held) = manager.single_instance_locks.lock().get_mut(&ta_uuid)
        {
            *held = false;
        }
    }

    /// Identity is by `task_page_table_id`, not by Arc pointer. After an
    /// instance is evicted and a fresh one registered under the same UUID,
    /// the stale handle must not evict the new one.
    #[test]
    fn evict_cached_instance_distinguishes_stale_handle() {
        let manager = SessionManager::new();
        let uuid = make_uuid(0xA4);

        register_for_test(&manager, 105, single_instance_flags(), 10, uuid);
        let arc_first = manager.single_instance_cache.get(&uuid).unwrap();
        manager.evict_cached_instance(&arc_first);

        register_for_test(&manager, 106, single_instance_flags(), 11, uuid);
        assert!(!manager.evict_cached_instance(&arc_first));
        assert!(manager.single_instance_cache.get(&uuid).is_some());
    }

    /// `mark_sessions_dead_for_instance` retires the cached single-instance
    /// TA: Live entries become Dead, stop counting for
    /// `count_sessions_for_instance`, `with_session` thereafter sees `None`,
    /// and new opens cannot reuse the dead cached instance.
    #[test]
    fn mark_dead_makes_with_session_observe_none() {
        let manager = SessionManager::new();
        let uuid = make_uuid(0xA6);
        register_for_test(&manager, 108, single_instance_flags(), 55, uuid);
        let arc = manager.single_instance_cache.get(&uuid).unwrap();
        assert_eq!(manager.count_sessions_for_instance(&arc), 1);

        manager.mark_sessions_dead_for_instance(&arc);
        assert_eq!(manager.count_sessions_for_instance(&arc), 0);
        assert!(manager.single_instance_cache.get(&uuid).is_none());

        manager
            .with_session(108, |instance| {
                assert!(instance.is_none());
                Ok(())
            })
            .unwrap();
    }

    /// A failed first-load of an unknown UUID must not mint a per-UUID
    /// lock entry. Such loads serialize on `ta_load_lock`, so
    /// `single_instance_locks` stays empty when the load fails or the TA
    /// turns out to be multi-instance.
    #[test]
    fn with_ta_does_not_mint_lock_entry_for_failed_unknown_load() {
        let manager = SessionManager::new();
        let uuid = make_uuid(0xA9);
        assert!(manager.get_known_flags(&uuid).is_none());

        let _ = manager.with_ta(&uuid, |_| Err(OpteeSmcReturnCode::ENotAvail));
        assert!(manager.single_instance_locks.lock().get(&uuid).is_none());
        assert!(manager.get_known_flags(&uuid).is_none());
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
            .with_ta(&uuid_multi, |target| {
                assert!(matches!(target, OpenSessionTarget::NewInstance));
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
        register_for_test(&manager, 302, single_instance_flags(), 81, uuid_single);
        manager.with_ta(&uuid_single, |_| Ok(())).unwrap();
        assert_eq!(*manager.pending_count.lock(), 0);
    }

    /// After `with_ta` completes the unknown→per-UUID transition, the
    /// per-UUID lock state must be released — a subsequent acquisition for
    /// the same UUID must succeed.
    #[test]
    fn with_ta_releases_per_uuid_lock_after_unknown_load() {
        let manager = SessionManager::new();
        let uuid = make_uuid(0xD0);

        manager
            .with_ta(&uuid, |target| {
                assert!(matches!(target, OpenSessionTarget::NewInstance));
                manager.register_new_session(
                    401,
                    make_shim(),
                    make_loaded_program(single_instance_flags()),
                    90,
                    uuid,
                );
                Ok(())
            })
            .unwrap();

        assert_eq!(
            manager.single_instance_locks.lock().get(&uuid),
            Some(&false)
        );
        assert!(manager.try_acquire_uuid_lock(uuid).is_some());
    }

    /// A concurrent `with_ta` for an unrelated UUID must NOT adopt or
    /// release the per-UUID lock held by another first-load opener.
    /// Adoption is keyed by the `with_ta` call's own UUID, so an opener
    /// for a different UUID leaves the original opener's per-UUID lock
    /// untouched.
    #[test]
    fn unrelated_with_ta_does_not_adopt_other_uuids_lock() {
        let manager = SessionManager::new();
        let uuid_locked = make_uuid(0xE1);
        let uuid_other = make_uuid(0xE2);

        // Simulate the "lock pre-taken during a first-load" state. This
        // mirrors what `register_new_session` does mid-first-load before
        // `with_ta` adopts.
        assert!(manager.try_acquire_uuid_lock(uuid_locked).is_some());

        // A `with_ta` call for a completely different UUID must not touch
        // `uuid_locked`'s lock. The closure registers nothing, but the
        // post-`f` adoption logic still runs.
        manager.with_ta(&uuid_other, |_| Ok(())).unwrap();

        assert_eq!(
            manager.single_instance_locks.lock().get(&uuid_locked),
            Some(&true)
        );
    }
}
