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

#[macro_use]
mod macros;

pub mod error;
pub mod event;
pub mod fs;
pub mod message;
pub mod pipe;
pub mod process;
pub mod process_group;
pub mod random;
pub mod readiness;
pub mod readiness_queue;
pub mod shared_buffer;
pub mod shared_futex;
pub mod signal;
pub mod socket;
pub mod terminal;
pub mod timer;
pub mod unix_socket;
pub mod vsock_socket;
pub mod wire;

/// Guest process ID carried by broker protocol messages.
///
/// The broker core owns allocation and validity rules; the protocol preserves
/// the numeric value without applying semantic checks.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(pub u32);

/// Guest thread ID carried by broker protocol messages.
///
/// The broker core owns allocation and validity rules; the protocol preserves
/// the numeric value without applying semantic checks.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(pub u32);

/// Guest process group ID carried by broker protocol messages.
///
/// A process group is identified by the ID of the process that created it.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessGroupId(pub u32);

impl From<ProcessId> for ProcessGroupId {
    fn from(creator: ProcessId) -> Self {
        Self(creator.0)
    }
}

/// Guest session ID carried by broker protocol messages.
///
/// A session is identified by the ID of the process that created it.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub u32);

impl From<ProcessId> for SessionId {
    fn from(creator: ProcessId) -> Self {
        Self(creator.0)
    }
}

/// Opaque broker object reference handle.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectHandle(pub u64);

impl ObjectHandle {
    /// Length in bytes of a handle encoded in a shared buffer.
    pub const ENCODED_SIZE: usize = size_of::<u64>();

    /// Encodes the handle for a shared buffer.
    #[must_use]
    pub fn encode(self) -> [u8; Self::ENCODED_SIZE] {
        self.0.to_le_bytes()
    }

    /// Decodes a handle produced by [`Self::encode`].
    #[must_use]
    pub fn decode(encoded: &[u8; Self::ENCODED_SIZE]) -> Self {
        Self(u64::from_le_bytes(*encoded))
    }

    /// Encodes `handles` one after another for a shared buffer.
    pub fn encode_all(handles: &[Self]) -> impl Iterator<Item = u8> + '_ {
        handles.iter().flat_map(|handle| handle.encode())
    }

    /// Decodes the handles [`Self::encode_all`] produced, ignoring trailing
    /// bytes too few for a handle.
    pub fn decode_all(encoded: &[u8]) -> impl Iterator<Item = Self> + '_ {
        encoded
            .as_chunks::<{ Self::ENCODED_SIZE }>()
            .0
            .iter()
            .map(Self::decode)
    }
}

/// Association-scoped broker request identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub u64);

/// Token under which the broker delivered a host object to a runner out of band, which the
/// runner can use to distinguish the object.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SharedObjectToken(pub u64);

/// Broker protocol version.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(pub u16);

/// Current broker protocol version.
pub const BROKER_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(1);
