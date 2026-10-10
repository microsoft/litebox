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
pub mod process;
pub mod process_group;
pub mod random;
pub mod readiness;
pub mod shared_buffer;
pub mod signal;
pub mod socket;
pub mod timer;
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

/// Association-scoped broker request identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub u64);

/// Broker protocol version.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(pub u16);

/// Current broker protocol version.
pub const BROKER_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(1);
