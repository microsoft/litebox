// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fixed resource limits for the egress proxy.
//!
//! None of these limits is caller-configurable: the proxy is a trusted
//! component whose behaviour must be identical for every sandbox.

use core::time::Duration;

/// Maximum number of distinct canonical hostnames in the policy.
pub const MAX_HOST_RULES: usize = 64;

/// Maximum number of pinned IPv4 addresses retained per hostname.
pub const MAX_PINNED_ADDRESSES_PER_HOST: usize = 16;

/// Maximum number of additional proxy-only resolved-destination CIDRs.
pub const MAX_RESOLVED_DESTINATION_RULES: usize = 64;

/// Maximum number of client connections served concurrently.
///
/// Additional connections stay in the listener backlog until a slot frees up.
pub const MAX_CONCURRENT_CLIENT_CONNECTIONS: usize = 256;

/// Maximum number of bytes buffered for a client request head.
pub const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;

/// Maximum number of bytes buffered for an upstream response head.
pub const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

/// Maximum number of individual header fields parsed per message.
pub const MAX_HEADER_FIELDS: usize = 100;

/// EDNS payload size advertised for UDP DNS queries.
///
/// Larger responses are truncated by the server, which makes the resolver fall
/// back to TCP.
pub const MAX_UDP_DNS_RESPONSE_BYTES: u16 = 1232;

/// Maximum number of hostname resolutions performed concurrently at startup.
pub const MAX_CONCURRENT_STARTUP_RESOLUTIONS: usize = 16;

/// Per-hostname DNS resolution timeout.
pub const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for one DNS transport attempt within a hostname lookup.
///
/// This is shorter than [`DNS_QUERY_TIMEOUT`] so the resolver has time to
/// fall back from UDP to TCP before the whole hostname lookup expires.
pub const DNS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// Total startup budget, covering listener acquisition and every resolution.
pub const STARTUP_BUDGET: Duration = Duration::from_secs(30);

const _: () = assert!(
    MAX_HOST_RULES.div_ceil(MAX_CONCURRENT_STARTUP_RESOLUTIONS) <= 5
        && DNS_QUERY_TIMEOUT.as_secs() * 5 < STARTUP_BUDGET.as_secs()
);

/// Total timeout shared by all pinned-address connection attempts.
pub const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle timeout applied to HTTP bodies and CONNECT tunnels.
///
/// A stream that makes no read or write progress for this long is torn down.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Total lifetime of a single forwarded HTTP request, measured from the moment
/// its dedicated upstream connection is established.
///
/// The design requires a total request time limit but does not fix its value;
/// ten minutes is long enough for large bounded transfers while still keeping
/// every upstream connection bounded.
pub const TOTAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

/// Maximum time a client may take to send a complete request head.
pub const REQUEST_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time spent draining client input after a non-upgraded response.
pub const CLIENT_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum client input discarded while closing a non-upgraded connection.
pub const MAX_CLIENT_CLOSE_DRAIN_BYTES: usize = 64 * 1024;
