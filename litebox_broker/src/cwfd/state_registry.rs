// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted state objects and their registry.
//!
//! # The "broker hosts the kernel state" model
//!
//! Litebox's worker shims emulate kernel-managed resources (eventfd,
//! timerfd, signalfd, in-memory unix-socket channels) in *worker*
//! userspace. That's fine for resources used inside a single worker
//! process: state lives where the operations happen.
//!
//! It breaks the moment a resource has to be observed by *more than
//! one* worker process — across fork/exec, across `SCM_RIGHTS`
//! cross-worker passing, or wherever else the kernel's own
//! cross-process sharing semantics need to be reproduced.
//!
//! Litebox already solves this for two big surfaces: the **9P
//! filesystem** is broker-hosted (the directory tree + open file
//! handles live in the broker; workers RPC into them), and broker-held
//! **inet sockets** are broker-hosted (TCP/UDP state lives in broker
//! state objects; workers hold opaque handles that RPC into the broker).
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
//! right tool for the host-passthrough-fd-bridge case in `commit_delayed_fork`
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
//! Each [`StateObjectEnum`] variant is responsible for its own internal
//! synchronization — the registry is just a table.

use core::any::Any;
use std::collections::{HashMap, HashSet};
#[cfg(debug_assertions)]
use std::string::{String, ToString as _};
use std::sync::{Arc, Mutex};

use litebox_common_linux::cwfd::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::cwfd::notification_ring::NotificationSender;

use crate::cwfd::eventfd_state::EventfdState;
use crate::cwfd::host_fd_state::HostFdState;
use crate::cwfd::inet_dgram_state::InetDgramState;
use crate::cwfd::inet_listener_state::{AddressFamily, InetListenerState};
use crate::cwfd::inet_raw_state::InetRawState;
use crate::cwfd::inotify_state::InotifyState;
use crate::cwfd::pidfd_state::PidfdState;
use crate::cwfd::pipe_state::{PipeReadEnd, PipeWriteEnd};
use crate::cwfd::process_state::ProcessState;
use crate::cwfd::pty_state::PtyState;
use crate::cwfd::signalfd_state::SignalfdState;
use crate::cwfd::socket_dgram_state::SocketDgramState;
use crate::cwfd::socket_seqpacket_state::SocketSeqPacketState;
use crate::cwfd::socketpair_state::SocketPairEnd;
use crate::cwfd::subscription_list::{SubscribeError, UnsubscribeError};
use crate::cwfd::tcp_conn_state::TcpConnState;
use crate::cwfd::timerfd_state::TimerfdState;
use crate::cwfd::unix_stream_state::UnixStreamState;

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
/// socket handle, ...). The registry stores the closed
/// [`StateObjectEnum`] so RPC dispatch can match exhaustively over every
/// broker-owned state kind.
pub trait StateObject: Any + Send + Sync + core::fmt::Debug {
    /// Returns the subsystem tag that classifies this state. Used by
    /// the registry for cross-checks (e.g. "this handle is tagged
    /// Eventfd, so I expect Read/Write/Subscribe ops, not Accept").
    fn subsystem_tag(&self) -> SubsystemTag;

    /// Returns `self` as `&dyn Any` for legacy helpers and unit tests.
    /// RPC dispatch should match on [`StateObjectEnum`] instead of
    /// downcasting through this method.
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

    /// Returns the broker's authoritative current view of which
    /// `NOTIFY_EVENT_*` bits are set for this state object.
    /// Used by [`Opcode::QueryEvents`][crate::cwfd::fd_token_protocol::Opcode::QueryEvents]
    /// so worker-side `poll`/`select`/`epoll_wait` paths can fetch
    /// readiness synchronously rather than relying on a stale
    /// subscription-mirror cache — the broker is the single source of
    /// truth for broker-held resources.
    fn current_events(&self) -> u32;

    /// Opportunistically re-attempts delivery of any edge/payload
    /// notifications previously deferred (per
    /// [`crate::cwfd::subscription_list::SubscriptionList`]'s A6
    /// in-flight bound or I4 ring-full retry path). Called by
    /// [`crate::cwfd::state_service::handle_request`] after every
    /// RPC dispatch; the worker's act of issuing a syscall RPC
    /// implies it has drained the prior frame, so the broker may
    /// now observe `reader_pos` advanced past the in-flight cursor
    /// and successfully emit pending bits.
    ///
    /// **Why this method has no default:** producer-exit
    /// "orphaned deferred bit" is a real failure mode. If a state
    /// type implements `SubscriptionList`-backed notification but
    /// does not flush on RPC boundaries, level-triggered consumer
    /// patterns time out (see
    /// `litebox_test_harness` `SCM.pass_pipe_double_wake` for the
    /// minimal repro). Requiring every impl to choose ensures no
    /// subsystem accidentally inherits the orphaned-bit bug by
    /// forgetting to flush.
    fn try_flush_subscriptions(&self);

    #[cfg(debug_assertions)]
    fn debug_repr(&self) -> String {
        core::any::type_name::<Self>().to_string()
    }
}

/// Closed set of broker-hosted state object variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateKind {
    Eventfd,
    PipeReadEnd,
    PipeWriteEnd,
    SocketPairEnd,
    SocketDgram,
    SocketSeqPacket,
    UnixStream,
    TcpConn,
    InetListener,
    InetDgram,
    InetRaw,
    Signalfd,
    Inotify,
    Pty,
    Pidfd,
    Process,
    HostFdAttached,
    Timerfd,
}

/// A tagged broker-hosted state object.
#[derive(Clone, Debug)]
pub enum StateObjectEnum {
    Eventfd(Arc<EventfdState>),
    PipeReadEnd(Arc<PipeReadEnd>),
    PipeWriteEnd(Arc<PipeWriteEnd>),
    SocketPairEnd(Arc<SocketPairEnd>),
    SocketDgram(Arc<SocketDgramState>),
    SocketSeqPacket(Arc<SocketSeqPacketState>),
    UnixStream(Arc<UnixStreamState>),
    TcpConn(Arc<TcpConnState>),
    InetListener(Arc<InetListenerState>),
    InetDgram(Arc<InetDgramState>),
    InetRaw(Arc<InetRawState>),
    Signalfd(Arc<SignalfdState>),
    Inotify(Arc<InotifyState>),
    Pty(Arc<PtyState>),
    Pidfd(Arc<PidfdState>),
    Process(Arc<ProcessState>),
    HostFdAttached(Arc<HostFdState>),
    Timerfd(Arc<TimerfdState>),
}

impl StateObjectEnum {
    pub fn kind(&self) -> StateKind {
        match self {
            StateObjectEnum::Eventfd(_) => StateKind::Eventfd,
            StateObjectEnum::PipeReadEnd(_) => StateKind::PipeReadEnd,
            StateObjectEnum::PipeWriteEnd(_) => StateKind::PipeWriteEnd,
            StateObjectEnum::SocketPairEnd(_) => StateKind::SocketPairEnd,
            StateObjectEnum::SocketDgram(_) => StateKind::SocketDgram,
            StateObjectEnum::SocketSeqPacket(_) => StateKind::SocketSeqPacket,
            StateObjectEnum::UnixStream(_) => StateKind::UnixStream,
            StateObjectEnum::TcpConn(_) => StateKind::TcpConn,
            StateObjectEnum::InetListener(_) => StateKind::InetListener,
            StateObjectEnum::InetDgram(_) => StateKind::InetDgram,
            StateObjectEnum::InetRaw(_) => StateKind::InetRaw,
            StateObjectEnum::Signalfd(_) => StateKind::Signalfd,
            StateObjectEnum::Inotify(_) => StateKind::Inotify,
            StateObjectEnum::Pty(_) => StateKind::Pty,
            StateObjectEnum::Pidfd(_) => StateKind::Pidfd,
            StateObjectEnum::Process(_) => StateKind::Process,
            StateObjectEnum::HostFdAttached(_) => StateKind::HostFdAttached,
            StateObjectEnum::Timerfd(_) => StateKind::Timerfd,
        }
    }

    pub fn subsystem_tag(&self) -> SubsystemTag {
        match self {
            StateObjectEnum::Eventfd(state) => state.subsystem_tag(),
            StateObjectEnum::PipeReadEnd(state) => state.subsystem_tag(),
            StateObjectEnum::PipeWriteEnd(state) => state.subsystem_tag(),
            StateObjectEnum::SocketPairEnd(state) => state.subsystem_tag(),
            StateObjectEnum::SocketDgram(state) => state.subsystem_tag(),
            StateObjectEnum::SocketSeqPacket(state) => state.subsystem_tag(),
            StateObjectEnum::UnixStream(state) => state.subsystem_tag(),
            StateObjectEnum::TcpConn(state) => state.subsystem_tag(),
            StateObjectEnum::InetListener(state) => state.subsystem_tag(),
            StateObjectEnum::InetDgram(state) => state.subsystem_tag(),
            StateObjectEnum::InetRaw(state) => state.subsystem_tag(),
            StateObjectEnum::Signalfd(state) => state.subsystem_tag(),
            StateObjectEnum::Inotify(state) => state.subsystem_tag(),
            StateObjectEnum::Pty(state) => state.subsystem_tag(),
            StateObjectEnum::Pidfd(state) => state.subsystem_tag(),
            StateObjectEnum::Process(state) => state.subsystem_tag(),
            StateObjectEnum::HostFdAttached(state) => state.subsystem_tag(),
            StateObjectEnum::Timerfd(state) => state.subsystem_tag(),
        }
    }

    pub fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        match self {
            StateObjectEnum::Eventfd(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::PipeReadEnd(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::PipeWriteEnd(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::SocketPairEnd(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::SocketDgram(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::SocketSeqPacket(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::UnixStream(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::TcpConn(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::InetListener(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::InetDgram(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::InetRaw(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::Signalfd(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::Inotify(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::Pty(state) => state.subscribe(subscription_id, events_mask, sender),
            StateObjectEnum::Pidfd(state) => state.subscribe(subscription_id, events_mask, sender),
            StateObjectEnum::Process(state) => {
                StateObject::subscribe(state.as_ref(), subscription_id, events_mask, sender)
            }
            StateObjectEnum::HostFdAttached(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
            StateObjectEnum::Timerfd(state) => {
                state.subscribe(subscription_id, events_mask, sender)
            }
        }
    }

    pub fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        match self {
            StateObjectEnum::Eventfd(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::PipeReadEnd(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::PipeWriteEnd(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::SocketPairEnd(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::SocketDgram(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::SocketSeqPacket(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::UnixStream(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::TcpConn(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::InetListener(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::InetDgram(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::InetRaw(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::Signalfd(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::Inotify(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::Pty(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::Pidfd(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::Process(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::HostFdAttached(state) => state.unsubscribe(subscription_id),
            StateObjectEnum::Timerfd(state) => state.unsubscribe(subscription_id),
        }
    }

    pub fn current_events(&self) -> u32 {
        match self {
            StateObjectEnum::Eventfd(state) => state.current_events(),
            StateObjectEnum::PipeReadEnd(state) => state.current_events(),
            StateObjectEnum::PipeWriteEnd(state) => state.current_events(),
            StateObjectEnum::SocketPairEnd(state) => state.current_events(),
            StateObjectEnum::SocketDgram(state) => state.current_events(),
            StateObjectEnum::SocketSeqPacket(state) => state.current_events(),
            StateObjectEnum::UnixStream(state) => state.current_events(),
            StateObjectEnum::TcpConn(state) => state.current_events(),
            StateObjectEnum::InetListener(state) => state.current_events(),
            StateObjectEnum::InetDgram(state) => state.current_events(),
            StateObjectEnum::InetRaw(state) => state.current_events(),
            StateObjectEnum::Signalfd(state) => state.current_events(),
            StateObjectEnum::Inotify(state) => state.current_events(),
            StateObjectEnum::Pty(state) => state.current_events(),
            StateObjectEnum::Pidfd(state) => state.current_events(),
            StateObjectEnum::Process(state) => state.current_events(),
            StateObjectEnum::HostFdAttached(state) => state.current_events(),
            StateObjectEnum::Timerfd(state) => state.current_events(),
        }
    }

    pub fn try_flush_subscriptions(&self) {
        match self {
            StateObjectEnum::Eventfd(state) => state.try_flush_subscriptions(),
            StateObjectEnum::PipeReadEnd(state) => state.try_flush_subscriptions(),
            StateObjectEnum::PipeWriteEnd(state) => state.try_flush_subscriptions(),
            StateObjectEnum::SocketPairEnd(state) => state.try_flush_subscriptions(),
            StateObjectEnum::SocketDgram(state) => state.try_flush_subscriptions(),
            StateObjectEnum::SocketSeqPacket(state) => state.try_flush_subscriptions(),
            StateObjectEnum::UnixStream(state) => state.try_flush_subscriptions(),
            StateObjectEnum::TcpConn(state) => state.try_flush_subscriptions(),
            StateObjectEnum::InetListener(state) => state.try_flush_subscriptions(),
            StateObjectEnum::InetDgram(state) => state.try_flush_subscriptions(),
            StateObjectEnum::InetRaw(state) => state.try_flush_subscriptions(),
            StateObjectEnum::Signalfd(state) => state.try_flush_subscriptions(),
            StateObjectEnum::Inotify(state) => state.try_flush_subscriptions(),
            StateObjectEnum::Pty(state) => state.try_flush_subscriptions(),
            StateObjectEnum::Pidfd(state) => state.try_flush_subscriptions(),
            StateObjectEnum::Process(state) => state.try_flush_subscriptions(),
            StateObjectEnum::HostFdAttached(state) => state.try_flush_subscriptions(),
            StateObjectEnum::Timerfd(state) => state.try_flush_subscriptions(),
        }
    }

    #[cfg(debug_assertions)]
    pub fn debug_repr(&self) -> String {
        match self {
            StateObjectEnum::Eventfd(state) => state.debug_repr(),
            StateObjectEnum::PipeReadEnd(state) => state.debug_repr(),
            StateObjectEnum::PipeWriteEnd(state) => state.debug_repr(),
            StateObjectEnum::SocketPairEnd(state) => state.debug_repr(),
            StateObjectEnum::SocketDgram(state) => state.debug_repr(),
            StateObjectEnum::SocketSeqPacket(state) => state.debug_repr(),
            StateObjectEnum::UnixStream(state) => state.debug_repr(),
            StateObjectEnum::TcpConn(state) => state.debug_repr(),
            StateObjectEnum::InetListener(state) => state.debug_repr(),
            StateObjectEnum::InetDgram(state) => state.debug_repr(),
            StateObjectEnum::InetRaw(state) => state.debug_repr(),
            StateObjectEnum::Signalfd(state) => state.debug_repr(),
            StateObjectEnum::Inotify(state) => state.debug_repr(),
            StateObjectEnum::Pty(state) => state.debug_repr(),
            StateObjectEnum::Pidfd(state) => state.debug_repr(),
            StateObjectEnum::Process(state) => state.debug_repr(),
            StateObjectEnum::HostFdAttached(state) => state.debug_repr(),
            StateObjectEnum::Timerfd(state) => state.debug_repr(),
        }
    }
}

impl StateObject for StateObjectEnum {
    fn subsystem_tag(&self) -> SubsystemTag {
        StateObjectEnum::subsystem_tag(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        StateObjectEnum::subscribe(self, subscription_id, events_mask, sender)
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        StateObjectEnum::unsubscribe(self, subscription_id)
    }

    fn current_events(&self) -> u32 {
        StateObjectEnum::current_events(self)
    }

    fn try_flush_subscriptions(&self) {
        StateObjectEnum::try_flush_subscriptions(self);
    }

    #[cfg(debug_assertions)]
    fn debug_repr(&self) -> String {
        StateObjectEnum::debug_repr(self)
    }
}

impl From<Arc<EventfdState>> for StateObjectEnum {
    fn from(state: Arc<EventfdState>) -> Self {
        StateObjectEnum::Eventfd(state)
    }
}

impl From<Arc<PipeReadEnd>> for StateObjectEnum {
    fn from(state: Arc<PipeReadEnd>) -> Self {
        StateObjectEnum::PipeReadEnd(state)
    }
}

impl From<Arc<PipeWriteEnd>> for StateObjectEnum {
    fn from(state: Arc<PipeWriteEnd>) -> Self {
        StateObjectEnum::PipeWriteEnd(state)
    }
}

impl From<Arc<SocketPairEnd>> for StateObjectEnum {
    fn from(state: Arc<SocketPairEnd>) -> Self {
        StateObjectEnum::SocketPairEnd(state)
    }
}

impl From<Arc<SocketDgramState>> for StateObjectEnum {
    fn from(state: Arc<SocketDgramState>) -> Self {
        StateObjectEnum::SocketDgram(state)
    }
}

impl From<Arc<SocketSeqPacketState>> for StateObjectEnum {
    fn from(state: Arc<SocketSeqPacketState>) -> Self {
        StateObjectEnum::SocketSeqPacket(state)
    }
}

impl From<Arc<UnixStreamState>> for StateObjectEnum {
    fn from(state: Arc<UnixStreamState>) -> Self {
        StateObjectEnum::UnixStream(state)
    }
}

impl From<Arc<TcpConnState>> for StateObjectEnum {
    fn from(state: Arc<TcpConnState>) -> Self {
        StateObjectEnum::TcpConn(state)
    }
}

impl From<Arc<InetListenerState>> for StateObjectEnum {
    fn from(state: Arc<InetListenerState>) -> Self {
        StateObjectEnum::InetListener(state)
    }
}

impl From<Arc<InetDgramState>> for StateObjectEnum {
    fn from(state: Arc<InetDgramState>) -> Self {
        StateObjectEnum::InetDgram(state)
    }
}

impl From<Arc<InetRawState>> for StateObjectEnum {
    fn from(state: Arc<InetRawState>) -> Self {
        StateObjectEnum::InetRaw(state)
    }
}

impl From<Arc<SignalfdState>> for StateObjectEnum {
    fn from(state: Arc<SignalfdState>) -> Self {
        StateObjectEnum::Signalfd(state)
    }
}

impl From<Arc<InotifyState>> for StateObjectEnum {
    fn from(state: Arc<InotifyState>) -> Self {
        StateObjectEnum::Inotify(state)
    }
}

impl From<Arc<PtyState>> for StateObjectEnum {
    fn from(state: Arc<PtyState>) -> Self {
        StateObjectEnum::Pty(state)
    }
}

impl From<Arc<HostFdState>> for StateObjectEnum {
    fn from(state: Arc<HostFdState>) -> Self {
        StateObjectEnum::HostFdAttached(state)
    }
}

impl From<Arc<PidfdState>> for StateObjectEnum {
    fn from(state: Arc<PidfdState>) -> Self {
        StateObjectEnum::Pidfd(state)
    }
}

impl From<Arc<ProcessState>> for StateObjectEnum {
    fn from(state: Arc<ProcessState>) -> Self {
        StateObjectEnum::Process(state)
    }
}

impl From<Arc<TimerfdState>> for StateObjectEnum {
    fn from(state: Arc<TimerfdState>) -> Self {
        StateObjectEnum::Timerfd(state)
    }
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
    state: Arc<StateObjectEnum>,
    refcount: u32,
}

struct State {
    next_id: u64,
    table: HashMap<u64, Entry>,
    broker_held_inet_listeners: HashMap<(u16, AddressFamily), u64>,
    /// Ports already owned by the broker's `net_proxy` inbound forwarders.
    /// Worker-side `bind(port)` requests for these ports use a virtual bind
    /// (no host `bind()` call) because the broker already owns the host
    /// listener and will deliver accepted streams via `accept_inbound`.
    inbound_forwarded_ports: HashSet<u16>,
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
                broker_held_inet_listeners: HashMap::new(),
                inbound_forwarded_ports: HashSet::new(),
            }),
        }
    }

    /// Records the set of guest ports that the broker's `net_proxy`
    /// already owns inbound host listeners for. Workers that
    /// `bind(port)` for these ports get a "virtual bind" (no host
    /// `bind()` call) because the broker already accepts on the host
    /// port and delivers accepted streams via `accept_inbound`.
    pub fn add_inbound_forwarded_port(&self, port: u16) {
        let mut s = self.state.lock().expect("BrokerStateRegistry poisoned");
        s.inbound_forwarded_ports.insert(port);
    }

    pub fn is_inbound_forwarded(&self, port: u16) -> bool {
        let s = self.state.lock().expect("BrokerStateRegistry poisoned");
        s.inbound_forwarded_ports.contains(&port)
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

    /// Calls [`StateObjectEnum::try_flush_subscriptions`] on every
    /// currently-registered state object. Invoked by
    /// [`crate::cwfd::state_service::handle_request`] after every
    /// RPC dispatch as the **A4 liveness chokepoint** for the
    /// notification protocol: the worker's act of issuing a syscall
    /// RPC implies it has drained its prior notification frame, so
    /// the broker should retry any bits that were deferred (per
    /// `SubscriptionList` invariant A6) while the previous frame
    /// was in flight. Without this hook, a producer that quiesces
    /// after issuing back-to-back notifies (e.g., `find | head -5
    /// > pty_slave` then both exit) leaves the second notify
    /// "orphaned" in `pending_mask` — receivers block on
    /// `epoll_wait` forever despite data sitting in the broker.
    ///
    /// Cost: `O(N)` per RPC where `N` is the count of registered
    /// state objects. Each `try_flush_subscriptions` early-exits
    /// when there are no pending bits, so the steady-state cost is
    /// `N` mutex acquire/release pairs with no I/O. Targeted-flush
    /// optimisation (only the touched state) is left as future
    /// work; correctness first.
    ///
    /// Snapshots `Arc<StateObjectEnum>` references under the
    /// registry lock and drops the lock before calling each
    /// `try_flush_subscriptions`. This avoids holding the registry
    /// lock across notification-ring sends (which take the
    /// per-subscription `Mutex<NotificationSender>`), preserving
    /// the existing lock-order discipline used by `notify`.
    pub fn try_flush_all_subscriptions(&self) {
        let states: Vec<Arc<StateObjectEnum>> = {
            let s = self.state.lock().expect("BrokerStateRegistry poisoned");
            s.table
                .values()
                .map(|entry| Arc::clone(&entry.state))
                .collect()
        };
        for state in &states {
            state.try_flush_subscriptions();
        }
    }

    #[cfg(debug_assertions)]
    pub fn debug_query(
        &self,
        handle: StateHandle,
    ) -> Result<(SubsystemTag, u32, String), StateRegistryError> {
        let s = self.state.lock().expect("BrokerStateRegistry poisoned");
        let entry = s
            .table
            .get(&handle.0)
            .ok_or(StateRegistryError::UnknownHandle(handle))?;
        Ok((
            entry.state.subsystem_tag(),
            entry.refcount,
            entry.state.debug_repr(),
        ))
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
    pub fn register(&self, state: impl Into<StateObjectEnum>) -> StateHandle {
        let state = Arc::new(state.into());
        let mut s = self.state.lock().expect("BrokerStateRegistry poisoned");
        let id = s.next_id;
        s.next_id = s
            .next_id
            .checked_add(1)
            .expect("BrokerStateRegistry id space exhausted");
        Self::insert_locked(&mut s, id, state)
    }

    pub fn register_with_id(
        &self,
        id: u64,
        state: impl Into<StateObjectEnum>,
    ) -> Result<StateHandle, StateRegistryError> {
        let state = Arc::new(state.into());
        let mut s = self.state.lock().expect("BrokerStateRegistry poisoned");
        if s.table.contains_key(&id) {
            return Err(StateRegistryError::RefcountOverflow(StateHandle(id)));
        }
        if s.next_id <= id {
            s.next_id = id
                .checked_add(1)
                .expect("BrokerStateRegistry id space exhausted");
        }
        Ok(Self::insert_locked(&mut s, id, state))
    }

    pub fn has_broker_held_inet_listener(
        &self,
        port: u16,
        family: AddressFamily,
        except: StateHandle,
    ) -> bool {
        let s = self.state.lock().expect("BrokerStateRegistry poisoned");
        s.broker_held_inet_listeners
            .get(&(port, family))
            .is_some_and(|handle| *handle != except.0)
    }

    pub fn register_broker_held_inet_listener(
        &self,
        port: u16,
        family: AddressFamily,
        handle: StateHandle,
    ) -> Result<(), StateRegistryError> {
        let mut s = self.state.lock().expect("BrokerStateRegistry poisoned");
        if s.broker_held_inet_listeners
            .get(&(port, family))
            .is_some_and(|registered| *registered != handle.0)
        {
            return Err(StateRegistryError::RefcountOverflow(handle));
        }
        let entry = s
            .table
            .get(&handle.0)
            .ok_or(StateRegistryError::UnknownHandle(handle))?;
        match entry.state.as_ref() {
            StateObjectEnum::InetListener(listener) => {
                debug_assert_eq!(listener.family(), family);
            }
            StateObjectEnum::Eventfd(_)
            | StateObjectEnum::PipeReadEnd(_)
            | StateObjectEnum::PipeWriteEnd(_)
            | StateObjectEnum::SocketPairEnd(_)
            | StateObjectEnum::SocketDgram(_)
            | StateObjectEnum::SocketSeqPacket(_)
            | StateObjectEnum::UnixStream(_)
            | StateObjectEnum::TcpConn(_)
            | StateObjectEnum::InetDgram(_)
            | StateObjectEnum::InetRaw(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Inotify(_)
            | StateObjectEnum::Pty(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::Process(_)
            | StateObjectEnum::HostFdAttached(_)
            | StateObjectEnum::Timerfd(_) => {
                return Err(StateRegistryError::TagMismatch {
                    handle,
                    expected: SubsystemTag::InetListener,
                    actual: entry.state.subsystem_tag(),
                });
            }
        }
        s.broker_held_inet_listeners
            .insert((port, family), handle.0);
        Ok(())
    }

    pub fn resolve_broker_held_inet_listener(
        &self,
        port: u16,
        family: AddressFamily,
    ) -> Option<Arc<InetListenerState>> {
        let s = self.state.lock().expect("BrokerStateRegistry poisoned");
        let handle = *s.broker_held_inet_listeners.get(&(port, family))?;
        let entry = s.table.get(&handle)?;
        Some(Self::inet_listener_from_entry_or_panic(
            entry, handle, port, family,
        ))
    }

    pub fn resolve_broker_held_inet_listener_for_inbound(
        &self,
        port: u16,
    ) -> Option<Arc<InetListenerState>> {
        let s = self.state.lock().expect("BrokerStateRegistry poisoned");
        for family in [AddressFamily::V4, AddressFamily::V6] {
            if let Some(handle) = s.broker_held_inet_listeners.get(&(port, family)).copied() {
                let entry = s.table.get(&handle)?;
                return Some(Self::inet_listener_from_entry_or_panic(
                    entry, handle, port, family,
                ));
            }
        }
        None
    }

    fn inet_listener_from_entry_or_panic(
        entry: &Entry,
        handle: u64,
        port: u16,
        family: AddressFamily,
    ) -> Arc<InetListenerState> {
        match entry.state.as_ref() {
            StateObjectEnum::InetListener(listener) => Arc::clone(listener),
            StateObjectEnum::Eventfd(_)
            | StateObjectEnum::PipeReadEnd(_)
            | StateObjectEnum::PipeWriteEnd(_)
            | StateObjectEnum::SocketPairEnd(_)
            | StateObjectEnum::SocketDgram(_)
            | StateObjectEnum::SocketSeqPacket(_)
            | StateObjectEnum::UnixStream(_)
            | StateObjectEnum::TcpConn(_)
            | StateObjectEnum::InetDgram(_)
            | StateObjectEnum::InetRaw(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Inotify(_)
            | StateObjectEnum::Pty(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::Process(_)
            | StateObjectEnum::HostFdAttached(_)
            | StateObjectEnum::Timerfd(_) => {
                panic!(
                    "broker-held inet listener route for port {port} family {family:?} points at non-listener handle {handle}"
                );
            }
        }
    }

    fn insert_locked(s: &mut State, id: u64, state: Arc<StateObjectEnum>) -> StateHandle {
        let tag = state.subsystem_tag();
        s.table.insert(id, Entry { state, refcount: 1 });
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

    /// Returns the current refcount of a handle, or 0 if the handle
    /// is unknown. Used by subsystems that need to compare two
    /// handles' refcounts to derive an invariant (e.g., PTY's
    /// `user_slave_count = rc(slave) - rc(master)` after a slave
    /// release).
    pub fn refcount(&self, handle: StateHandle) -> u32 {
        let s = self.state.lock().expect("BrokerStateRegistry poisoned");
        s.table.get(&handle.0).map(|e| e.refcount).unwrap_or(0)
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
            s.broker_held_inet_listeners
                .retain(|_, registered| *registered != handle.0);
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
    ) -> Result<Arc<StateObjectEnum>, StateRegistryError> {
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
    ) -> Result<Arc<StateObjectEnum>, StateRegistryError> {
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

    fn test_eventfd(initial: u64) -> Arc<EventfdState> {
        EventfdState::new(initial, false)
    }

    #[test]
    fn register_returns_unique_handles() {
        let reg = BrokerStateRegistry::new();
        let h1 = reg.register(test_eventfd(0));
        let h2 = reg.register(test_eventfd(0));
        assert_ne!(h1.id(), h2.id());
        assert_eq!(reg.live_handle_count(), 2);
    }

    #[test]
    fn register_id_monotonically_increasing() {
        let reg = BrokerStateRegistry::new();
        let h1 = reg.register(test_eventfd(0));
        let h2 = reg.register(test_eventfd(0));
        let h3 = reg.register(test_eventfd(0));
        assert!(h1.id() < h2.id() && h2.id() < h3.id());
        reg.release(h1).unwrap();
        let h4 = reg.register(test_eventfd(0));
        assert!(h4.id() > h3.id(), "ids must not be reused after release");
    }

    #[test]
    fn release_drops_at_zero_refcount() {
        let reg = BrokerStateRegistry::new();
        let counter = test_eventfd(7);
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
        assert_eq!(counter.current_value(), 7);
    }

    #[test]
    fn dup_increments_refcount_release_balances() {
        let reg = BrokerStateRegistry::new();
        let h1 = reg.register(test_eventfd(0));
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
        let counter = test_eventfd(0);
        let h = reg.register(Arc::clone(&counter));

        let r1 = reg.resolve(h, SubsystemTag::Eventfd).unwrap();
        let r2 = reg.resolve(h, SubsystemTag::Eventfd).unwrap();
        assert!(Arc::ptr_eq(&r1, &r2), "resolve must return the same Arc");

        // Mutate via one reference, observe via another.
        let StateObjectEnum::Eventfd(r1_typed) = r1.as_ref() else {
            panic!("expected Eventfd variant");
        };
        r1_typed.write(5).unwrap();
        let StateObjectEnum::Eventfd(r2_typed) = r2.as_ref() else {
            panic!("expected Eventfd variant");
        };
        assert_eq!(r2_typed.current_value(), 5);

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
        let h = reg.register(test_eventfd(0));
        // EventfdState reports Eventfd; ask for Process.
        match reg.resolve(h, SubsystemTag::Process) {
            Err(StateRegistryError::TagMismatch {
                handle,
                expected,
                actual,
            }) => {
                assert_eq!(handle, h);
                assert_eq!(expected, SubsystemTag::Process);
                assert_eq!(actual, SubsystemTag::Eventfd);
            }
            other => panic!("expected TagMismatch, got {other:?}"),
        }
        reg.release(h).unwrap();
    }

    #[test]
    fn resolve_untyped_works_for_both_tags() {
        let reg = BrokerStateRegistry::new();
        let h_ev = reg.register(test_eventfd(0));
        let h_proc = reg.register(ProcessState::arc());

        let s1 = reg.resolve_untyped(h_ev).unwrap();
        let s2 = reg.resolve_untyped(h_proc).unwrap();
        assert_eq!(s1.subsystem_tag(), SubsystemTag::Eventfd);
        assert_eq!(s2.subsystem_tag(), SubsystemTag::Process);

        reg.release(h_ev).unwrap();
        reg.release(h_proc).unwrap();
    }

    #[test]
    fn inet_listener_registry_v4_and_v6_coexist_on_same_port() {
        let reg = BrokerStateRegistry::new();
        let v4 = InetListenerState::new(AddressFamily::V4);
        let v6 = InetListenerState::new(AddressFamily::V6);
        let h4 = reg.register(Arc::clone(&v4));
        let h6 = reg.register(Arc::clone(&v6));

        reg.register_broker_held_inet_listener(22, AddressFamily::V4, h4)
            .unwrap();
        reg.register_broker_held_inet_listener(22, AddressFamily::V6, h6)
            .unwrap();

        let inbound = reg
            .resolve_broker_held_inet_listener_for_inbound(22)
            .unwrap();
        assert!(Arc::ptr_eq(&inbound, &v4));

        let v4_specific = reg
            .resolve_broker_held_inet_listener(22, AddressFamily::V4)
            .unwrap();
        assert!(Arc::ptr_eq(&v4_specific, &v4));

        let v6_specific = reg
            .resolve_broker_held_inet_listener(22, AddressFamily::V6)
            .unwrap();
        assert!(Arc::ptr_eq(&v6_specific, &v6));

        reg.release(h4).unwrap();
        let inbound = reg
            .resolve_broker_held_inet_listener_for_inbound(22)
            .unwrap();
        assert!(Arc::ptr_eq(&inbound, &v6));

        reg.release(h6).unwrap();
        assert!(
            reg.resolve_broker_held_inet_listener_for_inbound(22)
                .is_none()
        );
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
                    let h = reg.register(test_eventfd(0));
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
