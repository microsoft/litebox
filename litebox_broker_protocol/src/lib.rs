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

/// Major/minor broker protocol version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    /// Incompatible protocol version.
    pub major: u16,
    /// Protocol revision within a major version.
    pub minor: u16,
}

impl ProtocolVersion {
    /// Creates a protocol version.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Returns whether this requested version is supported by the broker.
    ///
    /// The initial split-broker protocol requires both peers to speak the same
    /// major/minor version. Future compatible protocol evolution can loosen this
    /// check when there is a concrete compatibility rule to enforce.
    pub const fn is_supported_by(self, broker: Self) -> bool {
        self.major == broker.major && self.minor == broker.minor
    }
}

/// Initial broker protocol version implemented by the split-broker POC.
pub const INITIAL_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(0, 1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_support_requires_exact_match() {
        let version = ProtocolVersion::new(1, 2);

        assert!(version.is_supported_by(version));
        assert!(!version.is_supported_by(ProtocolVersion::new(1, 3)));
        assert!(!version.is_supported_by(ProtocolVersion::new(1, 1)));
        assert!(!version.is_supported_by(ProtocolVersion::new(2, 2)));
    }
}
