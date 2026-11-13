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

mod control_message;
mod setup;

pub mod existing_runner;
pub mod memfd;
pub mod shared_objects;

mod unix_io;

pub mod unix_socket;

/// Returns whether `error` reports that this process or the system ran out of descriptors or
/// memory, which callers must report as such rather than as the operation being unsupported.
pub fn is_resource_exhaustion(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM)
    )
}

/// Returns uninitialized space for the ancillary data of one message, `N` bytes as
/// `rustix::cmsg_space!` computes.
fn control_space<const N: usize>() -> [core::mem::MaybeUninit<u8>; N] {
    [core::mem::MaybeUninit::uninit(); N]
}
