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
mod policy;
mod session;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use hashbrown::HashMap;
use litebox_broker_protocol::ObjectHandle;
use spin::rwlock::RwLock;

pub use error::BrokerError;
pub use policy::{PolicyEngine, PolicyProfile, PrincipalRights};
use session::ObjectReference;
pub use session::{BrokerSession, CallerCredential, ObjectRights};

/// BrokerCore result type.
pub type Result<T> = core::result::Result<T, BrokerError>;

/// Resource limits for broker-owned authority state.
///
/// These limits are global to the broker core, not per session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BrokerCoreLimits {
    /// Maximum live object references.
    pub max_references: usize,
}

impl BrokerCoreLimits {
    /// Conservative default limits for initial broker deployments.
    pub const DEFAULT: Self = Self {
        max_references: 4096,
    };

    /// Creates a broker core limit set.
    pub const fn new(max_references: usize) -> Self {
        Self { max_references }
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
    pub(crate) policy: PolicyEngine,
    pub(crate) limits: BrokerCoreLimits,
    pub(crate) next_session_id: Arc<RwLock<u64>>,
    pub(crate) next_reference_handle: Arc<RwLock<u64>>,
    pub(crate) references: Arc<RwLock<HashMap<ObjectHandle, ObjectReference>>>,
}

static BROKER_CORE_CREATED: AtomicBool = AtomicBool::new(false);

impl BrokerCore {
    /// Creates the broker core with the provided policy engine.
    pub fn new(policy: PolicyEngine) -> Result<Self> {
        Self::new_with_limits(policy, BrokerCoreLimits::DEFAULT)
    }

    /// Creates the broker core with explicit authority-state limits.
    pub fn new_with_limits(policy: PolicyEngine, limits: BrokerCoreLimits) -> Result<Self> {
        BROKER_CORE_CREATED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| BrokerError::BrokerCoreAlreadyExists)?;

        Ok(Self {
            policy,
            limits,
            next_session_id: Arc::new(RwLock::new(1)),
            next_reference_handle: Arc::new(RwLock::new(1)),
            references: Arc::new(RwLock::new(HashMap::new())),
        })
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

    /// Allocates broker authority state for one authenticated caller session.
    pub fn create_session(&self, caller_credential: CallerCredential) -> Result<BrokerSession> {
        let mut next_session_id = self.next_session_id.write();
        let session_id = *next_session_id;
        *next_session_id = session_id
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(BrokerSession::new(
            self.clone(),
            session::SessionId(session_id),
            caller_credential,
        ))
    }

    pub(crate) fn close_session(&self, session_id: session::SessionId) {
        let mut references = self.references.write();
        references.retain(|_, reference| reference.session_id != session_id);
    }
}
