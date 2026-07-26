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

/// Current broker protocol version.
pub const BROKER_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(1);
