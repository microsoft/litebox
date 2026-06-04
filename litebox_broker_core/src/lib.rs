// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker authority core independent of protocol envelopes and channels.
//!
//! `litebox_broker_core` owns broker-side object identity, reference lifetime,
//! rights checks, reference generation checks, and policy calls. It may use
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
mod event;
mod identity;
mod object;
mod policy;

use alloc::collections::BTreeMap;

pub use error::BrokerError;
use identity::BrokerCoreId;
pub use identity::{BrokerAssociation, CallerCredential};
use litebox_broker_protocol::ObjectReferenceId;
use object::{ObjectEntry, ObjectId, ObjectReference};
pub use object::{ObjectRights, ObjectType};
pub use policy::{ObjectOperation, PolicyDecision, PolicyEngine, PolicyOperation, PolicyProfile};

/// BrokerCore result type.
pub type Result<T> = core::result::Result<T, BrokerError>;

/// Resource limits for broker-owned authority state.
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

/// Channel-independent broker authority state.
pub struct BrokerCore {
    core_id: BrokerCoreId,
    policy: PolicyEngine,
    limits: BrokerCoreLimits,
    next_process_id: u64,
    next_object_id: u64,
    next_reference_id: u64,
    objects: BTreeMap<ObjectId, ObjectEntry>,
    references: BTreeMap<ObjectReferenceId, ObjectReference>,
}

impl BrokerCore {
    /// Creates a broker core with the provided policy engine.
    pub fn new(policy: PolicyEngine) -> Self {
        Self::new_with_limits(policy, BrokerCoreLimits::DEFAULT)
    }

    /// Creates a broker core with explicit authority-state limits.
    pub fn new_with_limits(policy: PolicyEngine, limits: BrokerCoreLimits) -> Self {
        Self {
            core_id: identity::allocate_core_id(),
            policy,
            limits,
            next_process_id: 1,
            next_object_id: 1,
            next_reference_id: 1,
            objects: BTreeMap::new(),
            references: BTreeMap::new(),
        }
    }
}

const EXHAUSTED_ID: u64 = 0;

fn allocate_id(next_id: &mut u64) -> Result<u64> {
    if *next_id == EXHAUSTED_ID {
        return Err(BrokerError::ResourceExhausted);
    }

    let id = *next_id;
    *next_id = id.checked_add(1).unwrap_or(EXHAUSTED_ID);
    Ok(id)
}
