// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64 macOS broker transport for an untrusted runner and trusted broker.
//!
//! Setup uses a Unix socket authenticated with LOCAL_PEERPID. The broker sends
//! fixed-size POSIX shared-memory descriptors; active traffic uses the portable
//! shared control rings. The socket remains open for fail-closed liveness.
//!
//! This transport does not install a Seatbelt profile. The launcher must confine
//! the runner separately; in particular it must not grant access to the broker's
//! task port. No in-process broker deployment is supported.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod fd_transfer;
mod pending_calls;
mod setup;
pub mod shared_memory;
mod unix_io;
pub mod unix_socket;
