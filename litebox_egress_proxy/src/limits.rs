// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fixed resource limits for the egress proxy.
//!
//! None of these limits is caller-configurable: the proxy is a trusted
//! component whose behaviour must be identical for every sandbox.

use core::time::Duration;

/// Maximum number of distinct canonical hostnames in the policy.
pub const MAX_HOST_RULES: usize = 64;

/// Maximum number of IPv4 addresses used from one DNS answer.
pub const MAX_RESOLVED_ADDRESSES: usize = 16;

/// EDNS payload size advertised for UDP DNS queries.
///
/// Larger responses are truncated by the server, which makes the resolver fall
/// back to TCP.
pub const MAX_UDP_DNS_RESPONSE_BYTES: u16 = 1232;

/// Total timeout for one on-demand hostname resolution.
pub const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for one DNS transport attempt within a hostname lookup.
///
/// This is shorter than [`DNS_QUERY_TIMEOUT`] so the resolver has time to
/// fall back from UDP to TCP before the whole hostname lookup expires.
pub const DNS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
