// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared broker protocol types and channel contracts.
//!
//! This crate describes broker-visible opaque handles, errors, versions,
//! request/response messages, and the transport-neutral control-channel
//! contracts used to carry them. It does not know whether messages move over
//! Unix sockets, shared rings, kernel traps, or another IPC mechanism.

#![no_std]

extern crate alloc;

pub mod channel;
pub mod error;
pub mod event;
pub mod message;
pub mod wire;

pub use channel::{
    HostControlChannel, LocalControlChannel, PeerCredential, ReceivedBrokerRequest,
    ReceivedBrokerResponse,
};
pub use error::ErrorCode;
pub use event::{
    AddEventRequest, AddEventResponse, ConsumeEventRequest, ConsumeEventResponse,
    CreateEventRequest, CreateEventResponse, EventConsumeMode, EventConsumption, ReadinessState,
    WaitEventRequest, WaitEventResponse, WaitOutcome,
};
pub use message::{
    BrokerRequest, BrokerResponse, CoreRequest, CoreResponse, EventRequest, EventResponse,
};

/// Opaque broker object reference handle.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectHandle(pub u64);

/// Broker protocol version.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    /// Creates a protocol version.
    pub const fn new(version: u16) -> Self {
        Self(version)
    }
}

/// Current broker protocol version.
pub const BROKER_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1);
