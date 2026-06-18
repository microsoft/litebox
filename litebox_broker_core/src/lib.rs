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
mod event;
mod identity;
mod object;
mod policy;

use core::sync::atomic::{AtomicBool, Ordering};

use alloc::collections::BTreeMap;
use slotmap::SlotMap;

pub use error::BrokerError;
pub use identity::{BrokerAssociation, CallerCredential};
use litebox_broker_protocol::ObjectHandle;
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

const MAX_OBJECTS: usize = u32::MAX as usize - 1;

/// Channel-independent broker authority state.
///
/// A broker process may construct only one broker core for its process
/// lifetime. Constructors return [`BrokerError::BrokerCoreAlreadyExists`] if a
/// core has already been constructed.
pub struct BrokerCore {
    policy: PolicyEngine,
    limits: BrokerCoreLimits,
    next_process_id: u64,
    next_reference_handle: u64,
    objects: SlotMap<ObjectId, ObjectEntry>,
    references: BTreeMap<ObjectHandle, ObjectReference>,
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
            policy,
            limits,
            next_process_id: 1,
            next_reference_handle: 1,
            objects: SlotMap::with_key(),
            references: BTreeMap::new(),
        })
    }
}

fn allocate_id(next_id: &mut u64) -> Result<u64> {
    let id = *next_id;
    *next_id = id.checked_add(1).ok_or(BrokerError::ResourceExhausted)?;
    Ok(id)
}
