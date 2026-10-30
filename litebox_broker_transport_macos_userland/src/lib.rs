// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS-userland broker association transport.
//!
//! This crate binds a broker association to macOS userland. It owns both sides
//! of the hosted deployment: the local (guest-side) endpoints a runner uses and
//! the host (broker-side) endpoints the broker uses, together with the
//! macOS-specific machinery they share, namely POSIX shared memory,
//! `os_sync_wait_on_address` waits, Unix-domain-socket setup framing,
//! descriptor transfer, peer authentication, and liveness monitoring.
//!
//! The crate keeps the public names of `litebox_broker_transport_linux_userland`
//! but has no process-image transfer, no shared-object channel (macOS Unix
//! sockets lack `SOCK_SEQPACKET`), and no adoption of a natively forked runner.
//!
//! The crate deliberately uses `std` because Unix-domain sockets and `std::io`
//! framing are hosted userland concerns. Everything portable stays out of it:
//! peer-visible messages and layouts live in `litebox_broker_protocol`, runtime
//! channel interfaces, shared-memory interfaces, and the control-ring state
//! machines live in `litebox_broker_transport`, and the local, host, and core
//! authority adapters live in their own OS-neutral crates.

#![cfg(target_os = "macos")]

mod setup;

pub mod shared_memory;

mod unix_io;

pub mod unix_socket;

/// Returns uninitialized space for the ancillary data of one message, `N` bytes as
/// `rustix::cmsg_space!` computes.
fn control_space<const N: usize>() -> [core::mem::MaybeUninit<u8>; N] {
    [core::mem::MaybeUninit::uninit(); N]
}
