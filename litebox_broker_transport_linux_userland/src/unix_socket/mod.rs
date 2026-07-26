// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-domain-socket broker endpoints for hosted userland deployments.
//!
//! Both sides of one association live here: the local (guest-side) endpoints a
//! runner activates and the host (broker-side) endpoints the broker activates.
//! Keeping them in one module lets their shared, security-sensitive setup
//! framing stay private to this crate.
//!
//! Setup negotiates the association over the Unix stream and transfers the
//! memfds backing the shared buffers and the control ring. After setup, the
//! authenticated socket is retained only for liveness and fail-closed shutdown:
//! active requests, responses, and notifications use the shared control rings.

mod host;
mod local;

pub use host::{
    UnixControlRingHostNotificationChannel, UnixControlRingHostRequestSource,
    UnixControlRingHostResponseSink, UnixControlRingHostShutdown, UnixStreamHostSetupChannel,
    validate_peer_process,
};
pub use local::{
    MAX_PENDING_CALLS, UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
    UnixControlRingLocalShutdown, UnixStreamLocalSetupChannel,
};
