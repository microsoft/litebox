// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::net::Ipv4Addr;

use tracing::info;

/// Discover the host's DNS resolver by parsing resolv.conf.
///
/// `/etc/resolv.conf.host` is written by the tool executor before the guest
/// rootfs is pointed at Litebox's virtual DNS service. Returns the first usable
/// nameserver entry found, or `8.8.8.8` as a fallback.
pub(crate) fn discover_host_dns() -> Ipv4Addr {
    for path in ["/etc/resolv.conf.host", "/etc/resolv.conf"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if let Some(addr_str) = line.strip_prefix("nameserver") {
                    let addr_str = addr_str.trim();
                    if let Ok(addr) = addr_str.parse::<Ipv4Addr>() {
                        if addr == Ipv4Addr::new(10, 0, 0, 1) {
                            continue;
                        }
                        info!("host DNS resolver: {addr} from {path}");
                        return addr;
                    }
                }
            }
        }
    }
    let fallback = Ipv4Addr::new(8, 8, 8, 8);
    info!("no host DNS resolver found, using fallback: {fallback}");
    fallback
}
