// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker authority core independent of protocol envelopes and channels.
//!
//! `litebox_broker_core` owns broker-side object identity, reference lifetime,
//! rights checks, handle validity checks, and policy calls. It may use
//! shared semantic DTOs from `litebox_broker_protocol` for values that both the
//! local core and broker understand, such as handles and readiness state. It
//! deliberately has no dependency on protocol envelopes, channel traits, wire
//! codecs, Unix sockets, shared-memory rings, kernel traps, or any other
//! channel implementation.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod error;
pub mod event;
pub mod pipe;
mod policy;
pub mod random;
pub mod readiness;
mod session;
pub mod socket;
pub mod stdio;
pub mod sync;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use hashbrown::HashMap;
use litebox_broker_protocol::ObjectHandle;
use spin::rwlock::RwLock;

pub use error::BrokerError;
pub use policy::{
    DestinationPortRange, DestinationRule, Ipv4Cidr, MAX_DESTINATION_RULES, PolicyEngine,
    PolicyProfile, SocketPolicy, SocketPolicyError,
};
use random::RandomProvider;
use session::ObjectReference;
pub use session::{
    AssociationCancellation, BrokerSession, CallerCredential, ObjectRights, SessionId,
};
use socket::{BrokerSocketPorts, SocketProvider};
use stdio::StdioProvider;

/// BrokerCore result type.
pub type Result<T> = core::result::Result<T, BrokerError>;

/// Broker-wide ceilings and per-session quotas for broker-owned authority state.
///
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BrokerCoreLimits {
    /// Maximum live object references across all sessions.
    pub max_references: usize,
    /// Maximum live object references owned by one session.
    pub max_references_per_session: usize,
    /// Maximum total capacity in bytes reserved by live pipes across all sessions.
    pub max_total_pipe_capacity: usize,
    /// Maximum capacity in bytes reserved by live pipes created by one session.
    pub max_pipe_capacity_per_session: usize,
    /// Maximum live platform socket resources across all sessions.
    pub max_sockets: usize,
    /// Maximum live platform socket resources owned by one session.
    pub max_sockets_per_session: usize,
}

impl BrokerCoreLimits {
    /// Conservative default limits that allow four sessions to reach each
    /// broker-wide ceiling only when all four spend their full quotas.
    pub const DEFAULT: Self = Self {
        max_references: 4096,
        max_references_per_session: 1024,
        max_total_pipe_capacity: 64 * 1024 * 1024,
        max_pipe_capacity_per_session: 16 * 1024 * 1024,
        max_sockets: 1024,
        max_sockets_per_session: 256,
    };

    /// Creates a broker core limit set.
    ///
    /// The reference and pipe-capacity session quotas initially match their
    /// broker-wide limits. Use [`Self::with_session_quotas`] to override them.
    pub const fn new(max_references: usize, max_total_pipe_capacity: usize) -> Self {
        Self {
            max_references,
            max_references_per_session: max_references,
            max_total_pipe_capacity,
            max_pipe_capacity_per_session: max_total_pipe_capacity,
            max_sockets: Self::DEFAULT.max_sockets,
            max_sockets_per_session: Self::DEFAULT.max_sockets_per_session,
        }
    }

    /// Creates a broker core limit set with explicit socket limits.
    ///
    /// The reference and pipe-capacity session quotas initially match their
    /// broker-wide limits. Use [`Self::with_session_quotas`] to override them.
    pub const fn new_with_all_limits(
        max_references: usize,
        max_total_pipe_capacity: usize,
        max_sockets: usize,
        max_sockets_per_session: usize,
    ) -> Self {
        Self {
            max_references,
            max_references_per_session: max_references,
            max_total_pipe_capacity,
            max_pipe_capacity_per_session: max_total_pipe_capacity,
            max_sockets,
            max_sockets_per_session,
        }
    }

    /// Returns these limits with explicit per-session reference and pipe-capacity quotas.
    ///
    /// A quota above its broker-wide limit is accepted; the broker-wide limit
    /// still applies, so the effective limit is the smaller value.
    #[must_use]
    pub const fn with_session_quotas(
        self,
        max_references_per_session: usize,
        max_pipe_capacity_per_session: usize,
    ) -> Self {
        Self {
            max_references_per_session,
            max_pipe_capacity_per_session,
            ..self
        }
    }
}

impl Default for BrokerCoreLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Channel-independent broker authority handle.
///
/// A broker process may construct only one broker core for its process
/// lifetime. Constructors return [`BrokerError::BrokerCoreAlreadyExists`] if a
/// core has already been constructed.
#[derive(Clone)]
pub struct BrokerCore {
    pub(crate) policy: Arc<PolicyEngine>,
    pub(crate) limits: BrokerCoreLimits,
    pub(crate) next_session_id: Arc<RwLock<u64>>,
    pub(crate) next_reference_handle: Arc<RwLock<u64>>,
    pub(crate) references: Arc<RwLock<HashMap<ObjectHandle, ObjectReference>>>,
    pub(crate) pending_references: Arc<AtomicUsize>,
    pub(crate) reserved_pipe_capacity: Arc<AtomicUsize>,
    pub(crate) reserved_sockets: Arc<AtomicUsize>,
    pub(crate) random_provider: Arc<dyn RandomProvider>,
    pub(crate) stdio_provider: Arc<dyn StdioProvider>,
    pub(crate) socket_provider: Arc<dyn SocketProvider>,
    pub(crate) socket_ports: BrokerSocketPorts,
}

static BROKER_CORE_CREATED: AtomicBool = AtomicBool::new(false);

impl BrokerCore {
    /// Creates the broker core with broker-wide platform service providers.
    pub fn new(
        policy: PolicyEngine,
        socket_provider: Arc<dyn SocketProvider>,
        random_provider: Arc<dyn RandomProvider>,
        stdio_provider: Arc<dyn StdioProvider>,
    ) -> Result<Self> {
        Self::new_with_limits(
            policy,
            BrokerCoreLimits::DEFAULT,
            socket_provider,
            random_provider,
            stdio_provider,
        )
    }

    /// Creates the broker core with explicit limits and platform service providers.
    pub fn new_with_limits(
        policy: PolicyEngine,
        limits: BrokerCoreLimits,
        socket_provider: Arc<dyn SocketProvider>,
        random_provider: Arc<dyn RandomProvider>,
        stdio_provider: Arc<dyn StdioProvider>,
    ) -> Result<Self> {
        BROKER_CORE_CREATED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| BrokerError::BrokerCoreAlreadyExists)?;

        Ok(Self {
            policy: Arc::new(policy),
            limits,
            next_session_id: Arc::new(RwLock::new(1)),
            next_reference_handle: Arc::new(RwLock::new(1)),
            references: Arc::new(RwLock::new(HashMap::new())),
            pending_references: Arc::new(AtomicUsize::new(0)),
            reserved_pipe_capacity: Arc::new(AtomicUsize::new(0)),
            reserved_sockets: Arc::new(AtomicUsize::new(0)),
            random_provider,
            stdio_provider,
            socket_provider,
            socket_ports: BrokerSocketPorts::default(),
        })
    }

    /// Returns the configured authority-state limits.
    #[must_use]
    pub const fn limits(&self) -> BrokerCoreLimits {
        self.limits
    }

    pub(crate) fn allocate_reference_handle(&self) -> Result<ObjectHandle> {
        let mut next_reference_handle = self.next_reference_handle.write();
        let handle = ObjectHandle(*next_reference_handle);
        *next_reference_handle = handle
            .0
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(handle)
    }

    pub(crate) fn allocate_reference_handle_pair(&self) -> Result<(ObjectHandle, ObjectHandle)> {
        let mut next_reference_handle = self.next_reference_handle.write();
        let first = ObjectHandle(*next_reference_handle);
        let second = ObjectHandle(
            first
                .0
                .checked_add(1)
                .ok_or(BrokerError::ResourceExhausted)?,
        );
        *next_reference_handle = second
            .0
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok((first, second))
    }

    /// Allocates broker authority state for one authenticated caller session.
    pub fn create_session(&self, caller_credential: CallerCredential) -> Result<BrokerSession> {
        let mut next_session_id = self.next_session_id.write();
        let session_id = *next_session_id;
        *next_session_id = session_id
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(BrokerSession::new(
            self.clone(),
            SessionId(session_id),
            caller_credential,
        ))
    }
}
