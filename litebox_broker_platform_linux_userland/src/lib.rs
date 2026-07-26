// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux-userland platform binding for the broker/host side of an association.
//!
//! This crate holds the concrete broker-side (host) endpoints of the hosted
//! userland deployment: peer authentication, Unix-domain-socket setup, and the
//! host halves of the shared control rings. It is the platform boundary for the
//! broker: `litebox_broker_core`, `litebox_broker_host`, and
//! `litebox_broker_protocol` stay OS-neutral, and only this crate binds them to
//! Linux userland primitives.
//!
//! Portable control-ring primitives, the memfd shared memory backing them, the
//! shared setup framing, and the matching *local* (guest-side) endpoints live in
//! `litebox_broker_transport`; this crate builds on them rather than
//! reimplementing framing or ring logic.

#[cfg(target_os = "linux")]
pub mod unix_socket;
