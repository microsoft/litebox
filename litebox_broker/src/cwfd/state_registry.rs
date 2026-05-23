// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted state objects and their registry.
//!
//! # The "broker hosts the kernel state" model
//!
//! Litebox's worker shims emulate kernel-managed resources (eventfd,
//! timerfd, signalfd, smoltcp TCP/UDP, in-memory unix-socket channels)
//! in *worker* userspace. That's fine for resources used inside a
//! single worker process: state lives where the operations happen.
//!
//! It breaks the moment a resource has to be observed by *more than
//! one* worker process — across fork/exec, across `SCM_RIGHTS`
//! cross-worker passing, or wherever else the kernel's own
//! cross-process sharing semantics need to be reproduced.
//!
//! Litebox already solves this for two big surfaces: the **9P
//! filesystem** is broker-hosted (the directory tree + open file
//! handles live in the broker; workers RPC into them), and the
//! **smoltcp networking stack** is broker-hosted (TCP/UDP state lives
//! in the broker's `SocketSet`; workers hold smoltcp handles that
//! RPC into the broker).
//!
//! This module is the foundation for extending that pattern to the
//! rest of the shim-emulated subsystems. A [`StateObject`] is some
//! piece of broker-hosted state that one or more workers reference
//! by an opaque [`StateHandle`]. The [`BrokerStateRegistry`] tracks
//! the live set, refcounts each handle, and frees the underlying
//! state when the last reference drops.
//!
//! Cross-worker SCM_RIGHTS becomes "the broker dups the handle for a
//! second worker"; fork inheritance becomes "the broker increments
//! the refcount for the child worker"; exec inheritance becomes "no
//! change — the proxy handle survives". All three boil down to the
//! same refcount mechanic on the registry.
//!
//! # Relationship to `BrokerFdTokenRegistry`
//!
//! [`BrokerFdTokenRegistry`](crate::fd_tokens::BrokerFdTokenRegistry)
//! is the special case where the broker-held state is *itself* a
//! host kernel fd (e.g. a real eventfd2 fd, a real socket, a real
//! pipe). The `OwnedFd` is the canonical resource, and the broker
//! becomes its anchor. That registry stays in place — it's still the
//! right tool for the external-fd-bridge case in `commit_delayed_fork`
//! and for any subsystem where the kernel itself is willing to be
//! the cross-process state owner.
//!
//! The two registries can coexist forever: each handle's
//! [`SubsystemTag`] selects which registry handles it.
//!
//! # Concurrency
//!
//! [`BrokerStateRegistry`] uses a single [`std::sync::Mutex`] over
//! its internal table. Operations are short (HashMap insert / lookup /
//! Arc clone), so contention isn't expected. If profiling later shows
//! it, the table can be sharded; the public API is shape-stable
//! against that change.
//!
//! Each `Arc<dyn StateObject + Send + Sync>` is responsible for its
//! own internal synchronization — the registry is just a table.

use core::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use litebox_common_linux::cwfd::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::cwfd::notification_ring::NotificationSender;

use crate::cwfd::subscription_list::{SubscribeError, UnsubscribeError};

/// An opaque, broker-global handle to a [`StateObject`] held by the
/// broker on behalf of one or more workers.
///
/// Handle IDs are monotonically allocated and never reused. Workers
/// serialize them on the wire as the `id` field of a `PassedToken`
/// (the `SubsystemTag` rides in the same `PassedToken`). A stale or
/// forged handle yields [`StateRegistryError::UnknownHandle`] when
/// presented back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateHandle(u64);

impl StateHandle {
    /// Returns the raw 56-bit id, intended for the `PassedToken` wire
    /// encoding.
    #[inline]
    pub fn id(self) -> u64 {
        self.0
    }

    /// Reconstructs a handle from a raw id received over the wire.
    /// No validation — callers must verify against a registry.
    #[inline]
    pub fn from_id(id: u64) -> Self {
        Self(id)
    }
}

/// A broker-hosted piece of state that one or more workers reference.
///
/// Implementors model a single resource (one eventfd, one TCP socket,
/// etc.) and carry whatever per-resource state they need (counter,
/// socket handle, ...). The registry holds them as
/// `Arc<dyn StateObject + Send + Sync>` so it can dispatch refcount
/// management without knowing the concrete type.
///
/// The trait itself is intentionally minimal — concrete types expose
/// rich operation APIs through the dyn-`Any` downcast. The broker's
/// service handlers downcast to the appropriate concrete state type
/// based on the request opcode and the handle's recorded
/// [`SubsystemTag`].
pub trait StateObject: Any + Send + Sync + core::fmt::Debug {
    /// Returns the subsystem tag that classifies this state. Used by
    /// the registry for cross-checks (e.g. "this handle is tagged
    /// Eventfd, so I expect Read/Write/Subscribe ops, not Accept").
    fn subsystem_tag(&self) -> SubsystemTag;

    /// Returns `self` as `&dyn Any` for downcasting to the concrete
    /// state type. Concrete subsystem services use this to recover
    /// type-specific operation APIs.
    fn as_any(&self) -> &dyn Any;

    /// Kind-agnostic subscribe. Adds `subscription_id` to this
    /// state-object's notification fan-out for the given
    /// `events_mask`, using `sender` as the worker-side ring.
    /// Implementations typically delegate to an internal
    /// [`crate::cwfd::subscription_list::SubscriptionList`].
    ///
    /// Implementations SHOULD prime the new subscription with any
    /// currently-ready events so workers that subscribe after the
    /// event don't miss the wake-up — this matches Linux
    /// level-triggered poll semantics.
    fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError>;

    /// Kind-agnostic unsubscribe. Removes the subscription previously
    /// installed via [`Self::subscribe`].
    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError>;
}

/// Errors returned by [`BrokerStateRegistry`] operations.
#[derive(Debug, thiserror::Error)]
pub enum StateRegistryError {
    /// The presented handle id was not in the registry. Either it was
    /// already fully released, was never registered with this
    /// registry, or is a forged value.
    #[error("unknown broker state handle: {0:?}")]
    UnknownHandle(StateHandle),

    /// Refcount overflow on [`BrokerStateRegistry::dup`]. In practice
    /// only reachable after `u32::MAX` outstanding duplications of a
    /// single handle, which isn't expected during normal operation but
    /// is surfaced rather than panicked to keep the broker resilient
    /// against worker bugs.
    #[error("broker state handle refcount overflow for {0:?}")]
    RefcountOverflow(StateHandle),

    /// The handle exists but its recorded subsystem tag doesn't match
    /// the tag a caller expected (e.g. a `Read` for what's actually a
    /// TcpSocket-tagged handle). Indicates a worker bug or a forged
    /// handle.
    #[error("subsystem tag mismatch for {handle:?}: expected {expected:?}, got {actual:?}")]
    TagMismatch {
        handle: StateHandle,
        expected: SubsystemTag,
        actual: SubsystemTag,
    },
}

struct Entry {
    state: Arc<dyn StateObject + Send + Sync>,
    refcount: u32,
}

struct State {
    next_id: u64,
    table: HashMap<u64, Entry>,
}

/// Snapshot of one live registry entry, for diagnostic dumps and
/// leak detection. C.5l follow-up: returned by
/// [`BrokerStateRegistry::diagnostic_snapshot`] so callers can
/// report leaks by handle id, kind, and refcount without
/// holding the registry lock.
#[derive(Debug, Clone)]
pub struct DiagnosticEntry {
    pub handle_id: u64,
    pub subsystem_tag: SubsystemTag,
    pub refcount: u32,
}

/// Broker-global registry of [`StateObject`]s reachable by opaque
/// [`StateHandle`]s.
pub struct BrokerStateRegistry {
    state: Mutex<State>,
}

impl Default for BrokerStateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerStateRegistry {
    /// Creates an empty registry. Handle ids start at 1; `0` is
    /// reserved as a sentinel "no handle" for any wire encoding that
    /// wants an absent value.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                next_id: 1,
                table: HashMap::new(),
            }),
        }
    }

    /// Returns the number of currently-registered handles.
    ///
    /// Intended for leak detection: this should drop to zero once all
    /// clients have disconnected and all per-connection cleanup has run.
    /// A non-zero value at "quiescence" indicates broker-rc bookkeeping
    /// is off (e.g., a `dup_handle` not matched by a corresponding
    /// `release`, often surfaced as a peer-stall in tests).
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .expect("BrokerStateRegistry poisoned")
            .table
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a per-entry snapshot suitable for diagnostic logging.
    /// Sorted by handle_id for deterministic dump output. Holds the
    /// registry lock for the duration of the iteration; cheap because
    /// the registry is small (single-digit-thousand entries at most).
    pub fn diagnostic_snapshot(&self) -> Vec<DiagnosticEntry> {
        let s = self.state.lock().expect("BrokerStateRegistry poisoned");
        let mut out: Vec<DiagnosticEntry> = s
            .table
            .iter()
            .map(|(&id, e)| DiagnosticEntry {
                handle_id: id,
                subsystem_tag: e.state.subsystem_tag(),
                refcount: e.refcount,
            })
            .collect();
        out.sort_by_key(|e| e.handle_id);
        out
    }

    /// Inserts a new state object with refcount = 1 and returns its
    /// handle.
    pub fn register(&self, state: Arc<dyn StateObject + Send + Sync>) -> StateHandle {
        let mut s = self.state.lock().expect("BrokerStateRegistry poisoned");
        let id = s.next_id;
        s.next_id = s
            .next_id
            .checked_add(1)
            .expect("BrokerStateRegistry id space exhausted");
        let tag = state.subsystem_tag();
        s.table.insert(id, Entry { state, refcount: 1 });
        drop(s);
        // PE.10 diag: opt-in via LITEBOX_PE10_DIAG.
        if std::env::var_os("LITEBOX_PE10_DIAG").is_some() {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/rst-diag.log")
            {
                let _ = writeln!(f, "[PE.10-diag] REGISTER {tag:?} handle={id} new_rc=1");
            }
        }
        StateHandle(id)
    }

    pub fn dup(&self, handle: StateHandle) -> Result<StateHandle, StateRegistryError> {
        let mut s = self.state.lock().expect("BrokerStateRegistry poisoned");
        let entry = s
            .table
            .get_mut(&handle.0)
            .ok_or(StateRegistryError::UnknownHandle(handle))?;
        debug_assert!(
            entry.refcount > 0,
            "BrokerStateRegistry::dup: entry for handle={} has refcount=0 (resurrection?)",
            handle.0,
        );
        entry.refcount = entry
            .refcount
            .checked_add(1)
            .ok_or(StateRegistryError::RefcountOverflow(handle))?;
        let new_rc = entry.refcount;
        let tag = entry.state.subsystem_tag();
        drop(s);
        if std::env::var_os("LITEBOX_PE10_DIAG").is_some() {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/rst-diag.log")
            {
                let _ = writeln!(
                    f,
                    "[PE.10-diag] DUP {tag:?} handle={} new_rc={new_rc}",
                    handle.0
                );
            }
        }
        tracing::debug!(handle = handle.0, new_rc, ?tag, "REG-DUP");
        Ok(handle)
    }

    /// Decrements the refcount of an existing handle. When the
    /// refcount reaches zero the state object is dropped (its `Arc`
    /// reference count reaches zero or its `Drop` runs depending on
    /// whether anyone else still holds it externally — by convention
    /// the broker is the sole owner of registered states).
    ///
    /// Returns the new refcount after this release. 0 means the
    /// state was dropped; >0 means other holders remain. Subsystems
    /// can use this to fire endpoint-specific close semantics
    /// (e.g., PTY master HUP when the last slave fd-holder releases
    /// but the master still anchors the slave registry slot).
    pub fn release(&self, handle: StateHandle) -> Result<u32, StateRegistryError> {
        let mut s = self.state.lock().expect("BrokerStateRegistry poisoned");
        let entry = s
            .table
            .get_mut(&handle.0)
            .ok_or(StateRegistryError::UnknownHandle(handle))?;
        assert!(
            entry.refcount > 0,
            "BrokerStateRegistry::release: entry for handle={} has refcount=0 (stale/double-release)",
            handle.0,
        );
        entry.refcount -= 1;
        let new_rc = entry.refcount;
        let tag = entry.state.subsystem_tag();
        if new_rc == 0 {
            s.table.remove(&handle.0);
        }
        drop(s);
        // PE.10 diag: log every release with the new rc. Opt-in via
        // LITEBOX_PE10_DIAG to avoid spam in normal use.
        if std::env::var_os("LITEBOX_PE10_DIAG").is_some() {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/rst-diag.log")
            {
                let _ = writeln!(
                    f,
                    "[PE.10-diag] release {tag:?} handle={} new_rc={new_rc}",
                    handle.0
                );
            }
        }
        tracing::debug!(handle = handle.0, new_rc, ?tag, "REG-REL");
        Ok(new_rc)
    }

    /// Resolves a handle to its underlying state object without
    /// changing the refcount. Returns an error if the handle is
    /// unknown or its subsystem tag doesn't match `expected_tag`.
    ///
    /// The tag check guards against misrouted handles: callers always
    /// know what kind of state they expect for a given opcode (Read
    /// against a TcpSocket-tagged handle is a worker bug), and the
    /// registry validates that before handing back the state object.
    pub fn resolve(
        &self,
        handle: StateHandle,
        expected_tag: SubsystemTag,
    ) -> Result<Arc<dyn StateObject + Send + Sync>, StateRegistryError> {
        let s = self.state.lock().expect("BrokerStateRegistry poisoned");
        let entry = s
            .table
            .get(&handle.0)
            .ok_or(StateRegistryError::UnknownHandle(handle))?;
        let actual = entry.state.subsystem_tag();
        if actual != expected_tag {
            return Err(StateRegistryError::TagMismatch {
                handle,
                expected: expected_tag,
                actual,
            });
        }
        Ok(Arc::clone(&entry.state))
    }

    /// Same as [`Self::resolve`] but skips the tag check. Used by
    /// service handlers that need to read the tag *before* dispatching
    /// (e.g. for diagnostics or for opcodes that accept any tag).
    pub fn resolve_untyped(
        &self,
        handle: StateHandle,
    ) -> Result<Arc<dyn StateObject + Send + Sync>, StateRegistryError> {
        let s = self.state.lock().expect("BrokerStateRegistry poisoned");
        let entry = s
            .table
            .get(&handle.0)
            .ok_or(StateRegistryError::UnknownHandle(handle))?;
        Ok(Arc::clone(&entry.state))
    }

    /// Returns the count of live handles. Intended for tests and
    /// broker telemetry.
    pub fn live_handle_count(&self) -> usize {
        self.state
            .lock()
            .expect("BrokerStateRegistry poisoned")
            .table
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal `StateObject` for tests: a `Mutex<u64>` counter,
    /// reachable as `Eventfd` for tag-check purposes.
    #[derive(Debug)]
    struct TestCounter {
        value: Mutex<u64>,
    }

    impl TestCounter {
        fn new(initial: u64) -> Arc<Self> {
            Arc::new(Self {
                value: Mutex::new(initial),
            })
        }

        fn get(&self) -> u64 {
            *self.value.lock().expect("test counter poisoned")
        }

        fn add(&self, n: u64) {
            *self.value.lock().expect("test counter poisoned") += n;
        }
    }

    impl StateObject for TestCounter {
        fn subsystem_tag(&self) -> SubsystemTag {
            SubsystemTag::Eventfd
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn subscribe(
            &self,
            _subscription_id: u64,
            _events_mask: u32,
            _sender: Arc<Mutex<NotificationSender>>,
        ) -> Result<(), SubscribeError> {
            // Test stubs ignore subscriptions.
            Ok(())
        }
        fn unsubscribe(&self, _subscription_id: u64) -> Result<(), UnsubscribeError> {
            Ok(())
        }
    }

    /// A second test state for tag-mismatch checks.
    #[derive(Debug)]
    struct OtherState;
    impl StateObject for OtherState {
        fn subsystem_tag(&self) -> SubsystemTag {
            SubsystemTag::TcpSocket
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn subscribe(
            &self,
            _subscription_id: u64,
            _events_mask: u32,
            _sender: Arc<Mutex<NotificationSender>>,
        ) -> Result<(), SubscribeError> {
            Ok(())
        }
        fn unsubscribe(&self, _subscription_id: u64) -> Result<(), UnsubscribeError> {
            Ok(())
        }
    }

    #[test]
    fn register_returns_unique_handles() {
        let reg = BrokerStateRegistry::new();
        let h1 = reg.register(TestCounter::new(0));
        let h2 = reg.register(TestCounter::new(0));
        assert_ne!(h1.id(), h2.id());
        assert_eq!(reg.live_handle_count(), 2);
    }

    #[test]
    fn register_id_monotonically_increasing() {
        let reg = BrokerStateRegistry::new();
        let h1 = reg.register(TestCounter::new(0));
        let h2 = reg.register(TestCounter::new(0));
        let h3 = reg.register(TestCounter::new(0));
        assert!(h1.id() < h2.id() && h2.id() < h3.id());
        reg.release(h1).unwrap();
        let h4 = reg.register(TestCounter::new(0));
        assert!(h4.id() > h3.id(), "ids must not be reused after release");
    }

    #[test]
    fn release_drops_at_zero_refcount() {
        let reg = BrokerStateRegistry::new();
        let counter = TestCounter::new(7);
        assert_eq!(Arc::strong_count(&counter), 1);
        let counter_clone = Arc::clone(&counter);

        let h = reg.register(counter_clone);
        // Registry holds one Arc reference; our local also holds one.
        assert_eq!(Arc::strong_count(&counter), 2);

        reg.release(h).unwrap();
        // Registry dropped its reference; only our local remains.
        assert_eq!(Arc::strong_count(&counter), 1);
        assert_eq!(reg.live_handle_count(), 0);

        // Counter value still accessible since we held a reference.
        assert_eq!(counter.get(), 7);
    }

    #[test]
    fn dup_increments_refcount_release_balances() {
        let reg = BrokerStateRegistry::new();
        let h1 = reg.register(TestCounter::new(0));
        let h2 = reg.dup(h1).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(reg.live_handle_count(), 1);

        reg.release(h1).unwrap();
        assert_eq!(
            reg.live_handle_count(),
            1,
            "still alive after partial release"
        );
        reg.release(h2).unwrap();
        assert_eq!(reg.live_handle_count(), 0);
    }

    #[test]
    fn release_unknown_handle_errors() {
        let reg = BrokerStateRegistry::new();
        match reg.release(StateHandle::from_id(999)) {
            Err(StateRegistryError::UnknownHandle(h)) => assert_eq!(h.id(), 999),
            other => panic!("expected UnknownHandle, got {other:?}"),
        }
    }

    #[test]
    fn dup_unknown_handle_errors() {
        let reg = BrokerStateRegistry::new();
        match reg.dup(StateHandle::from_id(42)) {
            Err(StateRegistryError::UnknownHandle(h)) => assert_eq!(h.id(), 42),
            other => panic!("expected UnknownHandle, got {other:?}"),
        }
    }

    #[test]
    fn resolve_returns_same_arc_for_repeated_calls() {
        let reg = BrokerStateRegistry::new();
        let counter = TestCounter::new(0);
        let h = reg.register(Arc::clone(&counter) as Arc<dyn StateObject + Send + Sync>);

        let r1 = reg.resolve(h, SubsystemTag::Eventfd).unwrap();
        let r2 = reg.resolve(h, SubsystemTag::Eventfd).unwrap();
        assert!(Arc::ptr_eq(&r1, &r2), "resolve must return the same Arc");

        // Mutate via one reference, observe via another.
        let r1_typed = r1.as_any().downcast_ref::<TestCounter>().unwrap();
        r1_typed.add(5);
        let r2_typed = r2.as_any().downcast_ref::<TestCounter>().unwrap();
        assert_eq!(r2_typed.get(), 5);

        reg.release(h).unwrap();
    }

    #[test]
    fn resolve_unknown_handle_errors() {
        let reg = BrokerStateRegistry::new();
        match reg.resolve(StateHandle::from_id(7), SubsystemTag::Eventfd) {
            Err(StateRegistryError::UnknownHandle(_)) => {}
            other => panic!("expected UnknownHandle, got {other:?}"),
        }
    }

    #[test]
    fn resolve_tag_mismatch_errors() {
        let reg = BrokerStateRegistry::new();
        let h = reg.register(TestCounter::new(0));
        // TestCounter reports Eventfd; ask for TcpSocket.
        match reg.resolve(h, SubsystemTag::TcpSocket) {
            Err(StateRegistryError::TagMismatch {
                handle,
                expected,
                actual,
            }) => {
                assert_eq!(handle, h);
                assert_eq!(expected, SubsystemTag::TcpSocket);
                assert_eq!(actual, SubsystemTag::Eventfd);
            }
            other => panic!("expected TagMismatch, got {other:?}"),
        }
        reg.release(h).unwrap();
    }

    #[test]
    fn resolve_untyped_works_for_both_tags() {
        let reg = BrokerStateRegistry::new();
        let h_ev = reg.register(TestCounter::new(0));
        let h_tcp = reg.register(Arc::new(OtherState));

        let s1 = reg.resolve_untyped(h_ev).unwrap();
        let s2 = reg.resolve_untyped(h_tcp).unwrap();
        assert_eq!(s1.subsystem_tag(), SubsystemTag::Eventfd);
        assert_eq!(s2.subsystem_tag(), SubsystemTag::TcpSocket);

        reg.release(h_ev).unwrap();
        reg.release(h_tcp).unwrap();
    }

    #[test]
    fn concurrent_register_resolve_release_is_safe() {
        // Soundness smoke test for the Mutex.
        use std::thread;

        let reg = Arc::new(BrokerStateRegistry::new());
        let n_threads = 4;
        let n_iters = 200;
        let mut handles = Vec::new();
        for _ in 0..n_threads {
            let reg = Arc::clone(&reg);
            handles.push(thread::spawn(move || {
                for _ in 0..n_iters {
                    let h = reg.register(TestCounter::new(0));
                    let h2 = reg.dup(h).unwrap();
                    let _arc = reg.resolve(h, SubsystemTag::Eventfd).unwrap();
                    reg.release(h2).unwrap();
                    reg.release(h).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(reg.live_handle_count(), 0);
    }
}
