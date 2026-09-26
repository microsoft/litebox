// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux-userland broker association transport.
//!
//! This crate binds a broker association to Linux userland. It owns both sides
//! of the hosted deployment: the local (guest-side) endpoints a runner uses and
//! the host (broker-side) endpoints the broker uses, together with the
//! Linux-specific machinery they share, namely memfd-backed shared memory,
//! futex waits, Unix-domain-socket setup framing, descriptor transfer, peer
//! authentication, and liveness monitoring.
//!
//! The crate deliberately uses `std` because Unix-domain sockets and `std::io`
//! framing are hosted userland concerns. Everything portable stays out of it:
//! peer-visible messages and layouts live in `litebox_broker_protocol`, runtime
//! channel interfaces, shared-memory interfaces, and the control-ring state
//! machines live in `litebox_broker_transport`, and the local, host, and core
//! authority adapters live in their own OS-neutral crates.

#![cfg(target_os = "linux")]

mod setup;

pub mod memfd;

mod unix_io;

pub mod unix_socket;
