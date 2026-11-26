// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! How guest sockets meet the host's network, and published ports: rules that a guest
//! listener's or UDP socket's host port follows.

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
    /// Where other guest servers are mirrored, at their own ports, while they serve them.
    pub listener_ip: Option<Ipv4Addr>,
    /// The networks whose clients published and mirrored TCP ports admit, as the guest sees them.
    pub tcp_sources: Vec<Ipv4Cidr>,
    /// The networks whose senders published and mirrored UDP ports admit, as the guest sees them.
    pub udp_sources: Vec<Ipv4Cidr>,
}

/// How guest sockets meet the host's network.
#[derive(Clone, Debug)]
pub enum Networking {
    /// Guests share a private network behind the broker, which publishes their ports to the host
    /// as `Publishing` says.
    Isolated(Publishing),
    /// Each guest TCP socket is a host socket at the guest's own host address and port, as when
    /// the broker runs in a network namespace of the guest's own; the host's own addresses,
    /// loopback included, are the guest's. Guest UDP sockets are not supported yet. Only a Linux
    /// host supports it.
    ///
    /// Connections to broker listeners on an address owned by this namespace stay in memory,
    /// even if a policy route would send a native connection elsewhere. Their ports stay taken
    /// on the host while open, more conservatively than for native connections: a listener that
    /// stops listening keeps its host socket bound, not listening, until the last server socket
    /// accepted in memory closes. A wildcard listener thus reserves the port on every host
    /// address while its accepted sockets drain. Rebinding requires `SO_REUSEADDR` on the new
    /// socket and on every remaining socket that shares the bind.
    Mirrored {
        /// The networks whose clients the guest's TCP listeners admit.
        tcp_sources: Vec<Ipv4Cidr>,
        /// The networks whose senders the guest's UDP sockets admit.
        udp_sources: Vec<Ipv4Cidr>,
    },
}

impl Default for Networking {
    fn default() -> Self {
        Self::Isolated(Publishing::default())
    }
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

/// A published port, `[HOST_IP:]HOST_PORT:GUEST_PORT[/tcp|/udp]`; the host IP is `0.0.0.0` and
/// the protocol TCP by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Publish {
    pub(crate) host: SocketAddrV4,
    pub(crate) guest_port: u16,
    pub(crate) protocol: Protocol,
}

/// The transport a rule publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Publish {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.host, self.guest_port)?;
        if self.protocol == Protocol::Udp {
            formatter.write_str("/udp")?;
        }
        Ok(())
    }
}

impl FromStr for Publish {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (value, protocol) = match value.rsplit_once('/') {
            None => (value, Protocol::Tcp),
            Some((value, "tcp")) => (value, Protocol::Tcp),
            Some((value, "udp")) => (value, Protocol::Udp),
            Some(_) => return Err("unknown protocol"),
        };
        let (host, guest) = value.rsplit_once(':').ok_or("no guest port")?;
        let (ip, host_port) = host.rsplit_once(':').unwrap_or(("0.0.0.0", host));
        let port = |port: &str| port.parse().ok().filter(|port| *port != 0);
        let ip = ip.parse().map_err(|_| "invalid host IPv4 address")?;
        Ok(Self {
            host: SocketAddrV4::new(ip, port(host_port).ok_or("invalid host port")?),
            guest_port: port(guest).ok_or("invalid guest port")?,
            protocol,
        })
    }
}

/// Returns a rule of `published` whose host endpoint overlaps an earlier one's of its protocol
/// (the same port, at the same or the unspecified IP), or whose guest port such a one names.
#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
pub(crate) fn duplicate(published: &[Publish]) -> Option<Publish> {
    published.iter().enumerate().find_map(|(index, p)| {
        let mut earlier = published[..index].iter();
        earlier
            .any(|q| {
                let any = |rule: &Publish| rule.host.ip().is_unspecified();
                let ip = q.host.ip() == p.host.ip() || any(q) || any(p);
                let host = ip && q.host.port() == p.host.port();
                q.protocol == p.protocol && (host || q.guest_port == p.guest_port)
            })
            .then_some(*p)
    })
}
