// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Transport-independent broker authority core.
//!
//! `litebox_broker_core` owns broker-side object identity, reference lifetime,
//! rights checks, generation checks, and policy calls. It deliberately has no
//! dependency on Unix sockets, shared-memory rings, or any other transport.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod connection;
mod event;
mod identity;
mod object;
mod policy;
mod types;

use alloc::collections::BTreeMap;

pub use connection::{BrokerConnection, BrokerDispatch, CloseReason, DispatchOutcome};
use litebox_broker_protocol::{ErrorCode, ObjectId, ObjectReferenceId, ProtocolVersion};
use object::{ObjectEntry, ObjectReference};
pub use policy::{
    DefaultDenyPolicy, EventOnlyPolicy, ObjectOperation, PolicyEngine, PolicyOperation,
};
pub use types::{ObjectRights, ObjectType};

/// BrokerCore result type.
pub type Result<T> = core::result::Result<T, ErrorCode>;

/// Protocol version this broker core implementation supports.
pub const SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(0, 1);

/// Transport-independent broker authority state.
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
        return Err(ErrorCode::ResourceExhausted);
    }

    let id = *next_id;
    *next_id = id.checked_add(1).unwrap_or(EXHAUSTED_ID);
    Ok(id)
}
