// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fixed resource limits for the egress proxy.
//!
//! None of these limits is caller-configurable: the proxy is a trusted
//! component whose behaviour must be identical for every sandbox.

use core::time::Duration;

/// Maximum number of client connections served concurrently.
///
/// Additional connections stay in the listener backlog until a slot frees up.
pub const MAX_CONCURRENT_CLIENT_CONNECTIONS: usize = 256;

/// Maximum number of bytes buffered for a client request head.
pub const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;

/// Maximum number of individual header fields parsed per message.
pub const MAX_HEADER_FIELDS: usize = 100;

/// Total timeout for hostname resolution and connection attempts.
pub const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle timeout applied to HTTP bodies and CONNECT tunnels.
///
/// A stream that makes no read or write progress for this long is torn down.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum time a client may take to send a complete request head.
pub const REQUEST_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time spent draining client input after a non-upgraded response.
pub const CLIENT_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum client input discarded while closing a non-upgraded connection.
pub const MAX_CLIENT_CLOSE_DRAIN_BYTES: usize = 64 * 1024;
