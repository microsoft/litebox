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
pub mod fs;
pub mod message;
pub mod pipe;
pub mod random;
pub mod readiness;
pub mod shared_buffer;
pub mod socket;
pub mod stdio;
pub mod wire;

/// Highest numeric process or thread identity allocated by the broker.
///
/// Linux reserves the next value, `0x3fff_ffff`, as its futex TID mask. uLiteBox
/// uses that reserved value for the synthetic Windows CSR server identity and
/// never allocates it to a guest process or thread.
pub const MAX_ALLOCATED_TASK_ID: u32 = 0x3fff_fffe;

/// Broker-assigned guest process identity.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(u32);

impl ProcessId {
    /// Creates a checked broker process identity.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value > 0 && value <= MAX_ALLOCATED_TASK_ID {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the guest-visible numeric identity.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Process identity assigned during broker negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    /// Identity of this process.
    pub id: ProcessId,
    /// Authoritative parent identity, absent for a root process.
    pub parent_id: Option<ProcessId>,
}

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

/// Current broker protocol version.
pub const BROKER_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(2);

#[cfg(test)]
mod tests {
    use super::{MAX_ALLOCATED_TASK_ID, ProcessId};

    #[test]
    fn process_id_checks_allocatable_range() {
        assert_eq!(ProcessId::new(0), None);
        assert_eq!(
            ProcessId::new(MAX_ALLOCATED_TASK_ID).map(ProcessId::get),
            Some(MAX_ALLOCATED_TASK_ID)
        );
        assert_eq!(ProcessId::new(MAX_ALLOCATED_TASK_ID + 1), None);
    }
}
