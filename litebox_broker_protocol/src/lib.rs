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
pub mod readiness;
pub mod wire;

/// Opaque broker object reference handle.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectHandle(pub u64);

/// Broker protocol version.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(pub u16);

/// Current broker protocol version.
pub const BROKER_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(1);
