// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared broker protocol types.
//!
//! This crate is intentionally channel-neutral. It describes broker-visible
//! opaque handles, errors, and versions, but does not know whether the bytes
//! move over Unix sockets, shared rings, kernel traps, or another IPC mechanism.

#![no_std]

mod error;
mod message;
mod object;

pub use error::ErrorCode;
pub use message::{
    BrokerRequest, BrokerResponse, CoreRequest, CoreResponse, EventRequest, EventResponse,
    ReadinessState, WaitOutcome,
};
pub use object::{ObjectHandle, ObjectReferenceGeneration, ObjectReferenceId};

/// Major/minor broker protocol version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    /// Incompatible protocol version.
    pub major: u16,
    /// Backward-compatible protocol revision within a major version.
    pub minor: u16,
}

impl ProtocolVersion {
    /// Creates a protocol version.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Returns whether this requested version is supported by `supported`.
    ///
    /// Minor revisions are backward-compatible within a major version, so a
    /// broker can serve a peer requesting the same major version and a minor
    /// version no newer than the broker supports.
    pub const fn is_supported_by(self, supported: Self) -> bool {
        self.major == supported.major && self.minor <= supported.minor
    }
}
