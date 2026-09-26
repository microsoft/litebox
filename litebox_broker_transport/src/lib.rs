// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runtime broker transport interfaces and portable transport mechanisms.
//!
//! This crate owns what a broker association needs in order to *move* messages
//! once both peers agree on the protocol: the local-side and host-side channel
//! contracts, the runtime shared-memory interfaces and the checked
//! shared-buffer pool built on them, and the portable shared control-ring state
//! machines.
//!
//! Nothing here is tied to an operating system or to hosted userland. The crate
//! is unconditionally `no_std`, so a kernel deployment can use the same
//! interfaces and control rings. Concrete association bindings, such as the
//! Unix-domain-socket and memfd endpoints in
//! `litebox_broker_transport_linux_userland`, live in separate crates, and a
//! deployment may implement the channel traits directly instead of using the
//! control ring.
//!
//! Peer-visible message and layout contracts live in `litebox_broker_protocol`,
//! while the portable local-side, host-side, and core authority adapters live in
//! their own crates.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod channel;
pub mod control_ring;
pub mod shared_memory;
