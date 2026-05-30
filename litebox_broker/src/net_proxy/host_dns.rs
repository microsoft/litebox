// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::net::Ipv4Addr;

use tracing::info;

/// Discover the host's DNS resolver by parsing `/etc/resolv.conf`.
///
/// Returns the first `nameserver` entry found, or `8.8.8.8` as a fallback.
pub(super) fn discover_host_dns() -> Ipv4Addr {
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if let Some(addr_str) = line.strip_prefix("nameserver") {
                let addr_str = addr_str.trim();
                if let Ok(addr) = addr_str.parse::<Ipv4Addr>() {
                    info!("host DNS resolver: {addr}");
                    return addr;
                }
            }
        }
    }
    let fallback = Ipv4Addr::new(8, 8, 8, 8);
    info!("no host DNS resolver found, using fallback: {fallback}");
    fallback
}
