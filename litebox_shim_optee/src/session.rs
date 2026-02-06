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
//! Single-instance TAs (with `TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION`) share
//! one TA instance across multiple sessions. When multiple CPUs try to invoke commands
//! on the same TA instance concurrently, we use `try_lock()` and return
//! `OPTEE_SMC_RETURN_ETHREAD_LIMIT` at the SMC level if the lock is held.
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
use hashbrown::HashMap;
use litebox_common_optee::{TaFlags, TeeUuid};
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

// SAFETY: The shim is designed to be used in single-threaded contexts per-CPU.
unsafe impl Send for TaInstance {}
unsafe impl Sync for TaInstance {}

/// Per-session entry in the session map.
#[derive(Clone)]
pub struct SessionEntry {
    /// The TA instance (may be shared with other sessions for single-instance TAs).
    pub instance: Arc<SpinMutex<TaInstance>>,
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
    pub fn get(&self, session_id: u32) -> Option<Arc<SpinMutex<TaInstance>>> {
        self.inner
            .lock()
            .get(&session_id)
            .map(|e| e.instance.clone())
    }

    /// Get full session entry by session ID.
    pub fn get_entry(&self, session_id: u32) -> Option<SessionEntry> {
        self.inner.lock().get(&session_id).cloned()
    }

    /// Insert a session into the map.
    pub fn insert(
        &self,
        session_id: u32,
        instance: Arc<SpinMutex<TaInstance>>,
        ta_uuid: TeeUuid,
        ta_flags: TaFlags,
    ) {
        self.inner.lock().insert(
            session_id,
            SessionEntry {
                instance,
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
    pub fn count_sessions_for_instance(&self, instance: &Arc<SpinMutex<TaInstance>>) -> usize {
        self.inner
            .lock()
            .values()
            .filter(|e| Arc::ptr_eq(&e.instance, instance))
            .count()
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
    inner: SpinMutex<HashMap<TeeUuid, Arc<SpinMutex<TaInstance>>>>,
}

impl SingleInstanceCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            inner: SpinMutex::new(HashMap::new()),
        }
    }

    /// Get a cached single-instance TA by UUID.
    pub fn get(&self, uuid: &TeeUuid) -> Option<Arc<SpinMutex<TaInstance>>> {
        self.inner.lock().get(uuid).cloned()
    }

    /// Cache a single-instance TA by UUID.
    pub fn insert(&self, uuid: TeeUuid, instance: Arc<SpinMutex<TaInstance>>) {
        self.inner.lock().insert(uuid, instance);
    }

    /// Remove a cached single-instance TA by UUID.
    pub fn remove(&self, uuid: &TeeUuid) -> Option<Arc<SpinMutex<TaInstance>>> {
        self.inner.lock().remove(uuid)
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
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new() -> Self {
        Self {
            sessions: SessionMap::new(),
            single_instance_cache: SingleInstanceCache::new(),
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

    /// Get a cached single-instance TA by UUID.
    pub fn get_single_instance(&self, uuid: &TeeUuid) -> Option<Arc<SpinMutex<TaInstance>>> {
        self.single_instance_cache.get(uuid)
    }

    /// Cache a single-instance TA.
    pub fn cache_single_instance(&self, uuid: TeeUuid, instance: Arc<SpinMutex<TaInstance>>) {
        self.single_instance_cache.insert(uuid, instance);
    }

    /// Get a session by ID.
    pub fn get_session(&self, session_id: u32) -> Option<Arc<SpinMutex<TaInstance>>> {
        self.sessions.get(session_id)
    }

    /// Get full session entry by ID.
    pub fn get_session_entry(&self, session_id: u32) -> Option<SessionEntry> {
        self.sessions.get_entry(session_id)
    }

    /// Register a new session.
    pub fn register_session(
        &self,
        session_id: u32,
        instance: Arc<SpinMutex<TaInstance>>,
        ta_uuid: TeeUuid,
        ta_flags: TaFlags,
    ) {
        self.sessions
            .insert(session_id, instance, ta_uuid, ta_flags);
    }

    /// Unregister a session and return its entry.
    pub fn unregister_session(&self, session_id: u32) -> Option<SessionEntry> {
        self.sessions.remove(session_id)
    }

    /// Remove a single-instance TA from the cache.
    pub fn remove_single_instance(&self, uuid: &TeeUuid) -> Option<Arc<SpinMutex<TaInstance>>> {
        self.single_instance_cache.remove(uuid)
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
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
