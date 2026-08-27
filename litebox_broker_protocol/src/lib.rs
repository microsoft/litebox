// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared broker protocol contracts.
//!
//! This crate describes what broker peers agree on: opaque handles, errors,
//! versions, handshake/request/response/notification messages, the shared-buffer
//! layout those messages reference, and the wire codecs that encode them. It
//! does not describe how messages move; runtime channel and shared-memory
//! interfaces live in `litebox_broker_transport`.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod error;
pub mod event;
pub mod message;
pub mod pipe;
pub mod readiness;
pub mod shared_buffer;
pub mod socket;
pub mod wire;

/// Opaque broker object reference handle.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectHandle(pub u64);

/// Association-scoped broker request identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub u64);

/// Broker protocol version.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(pub u16);

/// Broker features negotiated for one association.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BrokerCapabilities(u64);

impl BrokerCapabilities {
    /// No optional broker features.
    pub const NONE: Self = Self(0);
    /// Broker-controlled DNS identity is available.
    pub const BROKER_DNS: Self = Self(1 << 0);

    const KNOWN_BITS: u64 = Self::BROKER_DNS.0;

    /// Creates a capability set when every bit is understood.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits & !Self::KNOWN_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Returns the encoded capability bits.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns whether every capability in `other` is present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Current broker protocol version.
pub const BROKER_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(1);
