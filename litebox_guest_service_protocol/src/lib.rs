// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The protocol between the LiteBox guest service and the containerd shim: the Rust that
//! `build.rs` generates from `guest_service.proto` (messages, sync ttrpc client and server, and
//! with the `async` feature async ones on Unix), and the constants both sides share.

/// The messages.
#[allow(warnings, clippy::all, clippy::pedantic)]
pub mod guest_service {
    include!(concat!(env!("OUT_DIR"), "/guest_service.rs"));
}

/// The ttrpc client and server.
#[allow(warnings, clippy::all, clippy::pedantic)]
pub mod guest_service_ttrpc {
    include!(concat!(env!("OUT_DIR"), "/guest_service_ttrpc.rs"));
}

/// The async ttrpc client and server, which ttrpc has no Windows support for.
#[cfg(all(unix, feature = "async"))]
#[allow(warnings, clippy::all, clippy::pedantic)]
pub mod guest_service_ttrpc_async {
    include!(concat!(env!("OUT_DIR"), "/async/guest_service_ttrpc.rs"));
}

/// The guest's vsock port on which the guest service serves ttrpc.
pub const GUEST_SERVICE_PORT: u32 = 1024;
