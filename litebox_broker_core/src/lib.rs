// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Protocol- and channel-independent broker authority core.
//!
//! `litebox_broker_core` owns broker-side object identity, reference lifetime,
//! rights checks, reference generation checks, and policy calls. It deliberately has no
//! dependency on protocol request/response types, Unix sockets, shared-memory
//! rings, kernel traps, or any other channel implementation.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod error;
mod event;
mod identity;
mod object;
mod policy;
mod types;

use alloc::collections::BTreeMap;

pub use error::BrokerError;
pub use event::{ReadinessState, WaitOutcome};
pub use identity::{BrokerAssociation, CallerCredential};
use object::{ObjectEntry, ObjectId, ObjectReference};
pub use object::{ObjectHandle, ObjectReferenceGeneration, ObjectReferenceId};
pub use policy::{
    DefaultDenyPolicy, EventOnlyPolicy, ObjectOperation, PolicyDecision, PolicyEngine,
    PolicyOperation,
};
pub use types::{ObjectRights, ObjectType};

/// BrokerCore result type.
pub type Result<T> = core::result::Result<T, BrokerError>;

/// Channel-independent broker authority state.
pub struct BrokerCore<P> {
    policy: P,
    next_process_id: u64,
    next_object_id: u64,
    next_reference_id: u64,
    objects: BTreeMap<ObjectId, ObjectEntry>,
    references: BTreeMap<ObjectReferenceId, ObjectReference>,
}

impl<P> BrokerCore<P> {
    /// Creates a broker core with the provided policy engine.
    pub fn new(policy: P) -> Self {
        Self {
            policy,
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
