// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-global registry of live 9P sessions, keyed by the
//! broker-assigned `conn_id`.
//!
//! Legacy-pipes Phase 3 (D3 step 2d.2): the fd-token-socket and 9P
//! data plane arrive on the broker as two distinct connections from
//! the same shim host process. They are paired by an explicit
//! handshake: at 9P accept time the broker assigns a monotone
//! `conn_id` and stores the freshly-constructed `Arc<nine_p::Server>`
//! here; the runner reads the conn_id back as part of the
//! bootstrap ACK; the runner's fd-token-socket connection then
//! issues `BindNinePSession(conn_id)` and the broker handler looks
//! up this registry to populate `ConnState::nine_p_server`.
//!
//! Lifecycle:
//! - Insert at 9P `accept` (in the spawn closure, before `serve`).
//! - Remove at 9P clean disconnect (when `serve` returns).
//! - The fd-token-socket `ConnState` holds an `Arc<Server>` so
//!   removing from the registry doesn't drop the Server while a
//!   paired fd-token-socket is still issuing ops against it.

use crate::nine_p::server::Server;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Process-global table of live 9P sessions.
pub struct NinePSessionRegistry {
    sessions: RwLock<HashMap<u64, Arc<Server>>>,
}

impl NinePSessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Insert a freshly-constructed `Server` and return the
    /// previous mapping for `conn_id`, if any (which would indicate
    /// the caller reused a conn_id — a bug; this method does not
    /// allocate ids).
    pub fn insert(&self, conn_id: u64, server: Arc<Server>) -> Option<Arc<Server>> {
        // Best-effort: poisoning is possible if a panic happened
        // while inserting, but we'd rather keep going than abort
        // the broker. `into_inner` is not available on `&RwLock`.
        self.sessions
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(conn_id, server)
    }

    /// Lookup. Returns `None` if the session has disconnected or
    /// the conn_id was never registered.
    pub fn get(&self, conn_id: u64) -> Option<Arc<Server>> {
        self.sessions
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&conn_id)
            .cloned()
    }

    /// Remove on session disconnect. Safe to call even if the
    /// session was never inserted; returns the removed entry for
    /// the caller's convenience (typically dropped).
    pub fn remove(&self, conn_id: u64) -> Option<Arc<Server>> {
        self.sessions
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&conn_id)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.sessions
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }
}

impl Default for NinePSessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-global monotone conn_id counter for 9P sessions.
/// Starts at 1 so `0` (the `Server` field's default for tests) is
/// distinguishable from any real production id.
pub fn next_conn_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Process-global singleton accessor. Set once at broker startup
/// (in `main.rs`); read by the fd-token-socket `BindNinePSession`
/// handler. The fd-token-socket dispatch path has many call sites
/// that already thread `BrokerStateRegistry` and
/// `InotifyDispatcher`; using a `OnceLock` here avoids a
/// 22-site refactor and matches the pragmatic shim-side
/// `broker_fs_provider` singleton pattern.
///
/// Tests construct a fresh `NinePSessionRegistry` directly and pass
/// it to handler functions that take a `&NinePSessionRegistry`.
/// The singleton is only consulted when the handler is reached via
/// the production dispatch path.
mod global {
    use super::NinePSessionRegistry;
    use std::sync::{Arc, OnceLock};
    static GLOBAL: OnceLock<Arc<NinePSessionRegistry>> = OnceLock::new();
    pub fn set(reg: Arc<NinePSessionRegistry>) {
        let _ = GLOBAL.set(reg);
    }
    pub fn get() -> Option<&'static Arc<NinePSessionRegistry>> {
        GLOBAL.get()
    }
}

/// Set the process-global registry (broker startup).
pub fn set_global(reg: Arc<NinePSessionRegistry>) {
    global::set(reg);
}

/// Get the process-global registry, if any. Returns `None` in
/// tests and unit-test contexts where startup never ran.
pub fn global_registry() -> Option<&'static Arc<NinePSessionRegistry>> {
    global::get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nine_p::server::Server;
    use crate::policy::AllowAllPolicy;
    use std::path::PathBuf;

    fn make_server() -> Arc<Server> {
        Arc::new(Server::new(
            PathBuf::from("/tmp"),
            Arc::new(AllowAllPolicy),
            false,
            Arc::new(crate::inotify_dispatcher::InotifyDispatcher::new()),
        ))
    }

    #[test]
    fn insert_and_get() {
        let r = NinePSessionRegistry::new();
        let s = make_server();
        assert!(r.insert(1, Arc::clone(&s)).is_none());
        let got = r.get(1).expect("get 1");
        assert!(Arc::ptr_eq(&got, &s));
    }

    #[test]
    fn get_missing_returns_none() {
        let r = NinePSessionRegistry::new();
        assert!(r.get(42).is_none());
    }

    #[test]
    fn remove_drops_entry() {
        let r = NinePSessionRegistry::new();
        let s = make_server();
        r.insert(5, s);
        assert_eq!(r.len(), 1);
        assert!(r.remove(5).is_some());
        assert_eq!(r.len(), 0);
        assert!(r.get(5).is_none());
    }

    #[test]
    fn remove_unknown_is_noop() {
        let r = NinePSessionRegistry::new();
        assert!(r.remove(7).is_none());
    }

    #[test]
    fn next_conn_id_is_monotone_and_nonzero() {
        let a = next_conn_id();
        let b = next_conn_id();
        assert!(a > 0);
        assert!(b > a);
    }
}
