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
mod identity;
mod object;
mod policy;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use litebox_broker_protocol::ObjectHandle;
use slotmap::SlotMap;
use spin::rwlock::RwLock;

pub use error::BrokerError;
pub use identity::{BrokerSession, CallerCredential};
pub use object::ObjectRights;
use object::{ObjectEntry, ObjectId, ObjectReference};
pub use policy::{PolicyEngine, PolicyProfile};

/// BrokerCore result type.
pub type Result<T> = core::result::Result<T, BrokerError>;

/// Resource limits for broker-owned authority state.
///
/// These limits are global to the broker core, not per session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BrokerCoreLimits {
    /// Maximum live broker objects.
    pub max_objects: usize,
    /// Maximum live object references.
    pub max_references: usize,
}

impl BrokerCoreLimits {
    /// Conservative default limits for initial broker deployments.
    pub const DEFAULT: Self = Self {
        max_objects: 4096,
        max_references: 4096,
    };

    /// Creates a broker core limit set.
    pub const fn new(max_objects: usize, max_references: usize) -> Self {
        Self {
            max_objects,
            max_references,
        }
    }
}

impl Default for BrokerCoreLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

const MAX_OBJECTS: usize = u32::MAX as usize - 1;

/// Channel-independent broker authority handle.
///
/// A broker process may construct only one broker core for its process
/// lifetime. Constructors return [`BrokerError::BrokerCoreAlreadyExists`] if a
/// core has already been constructed.
#[derive(Clone)]
pub struct BrokerCore {
    pub(crate) state: Arc<RwLock<BrokerCoreState>>,
}

pub(crate) struct BrokerCoreState {
    pub(crate) policy: PolicyEngine,
    pub(crate) limits: BrokerCoreLimits,
    pub(crate) next_session_id: u64,
    pub(crate) next_reference_handle: u64,
    pub(crate) objects: SlotMap<ObjectId, Arc<RwLock<ObjectEntry>>>,
    pub(crate) references: BTreeMap<ObjectHandle, ObjectReference>,
}

static BROKER_CORE_CREATED: AtomicBool = AtomicBool::new(false);

impl BrokerCore {
    /// Creates the broker core with the provided policy engine.
    pub fn new(policy: PolicyEngine) -> Result<Self> {
        Self::new_with_limits(policy, BrokerCoreLimits::DEFAULT)
    }

    /// Creates the broker core with explicit authority-state limits.
    pub fn new_with_limits(policy: PolicyEngine, limits: BrokerCoreLimits) -> Result<Self> {
        if limits.max_objects > MAX_OBJECTS {
            return Err(BrokerError::ResourceExhausted);
        }

        BROKER_CORE_CREATED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| BrokerError::BrokerCoreAlreadyExists)?;

        Ok(Self {
            state: Arc::new(RwLock::new(BrokerCoreState {
                policy,
                limits,
                next_session_id: 1,
                next_reference_handle: 1,
                objects: SlotMap::with_key(),
                references: BTreeMap::new(),
            })),
        })
    }

    /// Allocates broker authority state for one authenticated caller session.
    pub fn create_session(&self, caller_credential: CallerCredential) -> Result<BrokerSession> {
        let mut state = self.state.write();
        let session_id = allocate_id(&mut state.next_session_id)?;
        Ok(BrokerSession::new(
            self.clone(),
            identity::SessionId::new(session_id),
            caller_credential,
        ))
    }

    pub(crate) fn close_session(&self, session_id: identity::SessionId) {
        object::drop_references_for_session(self, session_id);
    }
}

fn allocate_id(next_id: &mut u64) -> Result<u64> {
    let id = *next_id;
    *next_id = id.checked_add(1).ok_or(BrokerError::ResourceExhausted)?;
    Ok(id)
}
