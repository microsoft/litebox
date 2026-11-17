// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Published ports: rules that a guest listener's host port follows.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;

use litebox_broker_core::Ipv4Cidr;
use litebox_broker_protocol::socket::Ipv4Address;

/// What the broker publishes to the host, and to which clients.
#[derive(Clone, Debug, Default)]
pub struct Publishing {
    /// Published ports.
    pub rules: Vec<Publish>,
    /// Where other guest listeners are mirrored, at their own ports, while they listen.
    pub listener_ip: Option<Ipv4Addr>,
    /// The networks whose clients published and mirrored ports admit, as the guest sees them.
    pub tcp_sources: Vec<Ipv4Cidr>,
}

/// Parses a canonical IPv4 CIDR, `NETWORK/PREFIX_LENGTH`.
///
/// # Errors
///
/// Fails if `value` is not one.
pub fn parse_ipv4_cidr(value: &str) -> Result<Ipv4Cidr, String> {
    let (network, prefix_length) = value
        .split_once('/')
        .ok_or_else(|| "expected an IPv4 CIDR prefix".to_owned())?;
    let network = network
        .parse::<Ipv4Addr>()
        .map_err(|error| format!("invalid IPv4 network: {error}"))?;
    let prefix_length = prefix_length
        .parse::<u8>()
        .map_err(|error| format!("invalid IPv4 prefix length: {error}"))?;
    Ipv4Cidr::new(Ipv4Address(network.octets()), prefix_length).ok_or_else(|| {
        "IPv4 CIDR must have a valid prefix and canonical network address".to_owned()
    })
}

/// A published port, `[HOST_IP:]HOST_PORT:GUEST_PORT`; the host IP is `0.0.0.0` by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Publish {
    pub(crate) host: SocketAddrV4,
    pub(crate) guest_port: u16,
}

impl fmt::Display for Publish {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.host, self.guest_port)
    }
}

impl FromStr for Publish {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (host, guest) = value.rsplit_once(':').ok_or("no guest port")?;
        let (ip, host_port) = host.rsplit_once(':').unwrap_or(("0.0.0.0", host));
        let port = |port: &str| port.parse().ok().filter(|port| *port != 0);
        let ip = ip.parse().map_err(|_| "invalid host IPv4 address")?;
        Ok(Self {
            host: SocketAddrV4::new(ip, port(host_port).ok_or("invalid host port")?),
            guest_port: port(guest).ok_or("invalid guest port")?,
        })
    }
}

/// Returns a rule of `published` whose host endpoint overlaps an earlier one's (the same port,
/// at the same or the unspecified IP), or whose guest port an earlier one names.
#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
pub(crate) fn duplicate(published: &[Publish]) -> Option<Publish> {
    published.iter().enumerate().find_map(|(index, p)| {
        let mut earlier = published[..index].iter();
        earlier
            .any(|q| {
                let any = |rule: &Publish| rule.host.ip().is_unspecified();
                let ip = q.host.ip() == p.host.ip() || any(q) || any(p);
                (ip && q.host.port() == p.host.port()) || q.guest_port == p.guest_port
            })
            .then_some(*p)
    })
}
