// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The payload's `policy` (see the [crate] docs).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::net::Ipv4Addr;
use litebox_broker_core::{
    CallerCredential, DestinationPortRange, DestinationRule, Ipv4Cidr, SocketPolicy,
    SocketPolicyError,
};
use litebox_broker_protocol::socket::{Ipv4Address, Port};

/// Why [`parse`] rejected a `policy`.
#[derive(Debug)]
pub enum PolicyError {
    /// Line `line` (from 1) is not `egress`, `tcp` or `udp`, and a value.
    Line { line: usize },
    /// The destination on line `line`, `value`, is not `CIDR:PORT[-PORT]`.
    Destination {
        line: usize,
        value: String,
        reason: String,
    },
    /// `protocol` (`tcp` or `udp`) has too many destinations.
    Rules {
        protocol: &'static str,
        error: SocketPolicyError,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Line { line } => write!(
                f,
                "line {line} is not `egress`, `tcp` or `udp`, and CIDR:PORT[-PORT]"
            ),
            Self::Destination {
                line,
                value,
                reason,
            } => write!(
                f,
                "line {line}: {value:?} is not CIDR:PORT[-PORT]: {reason}"
            ),
            Self::Rules { protocol, error } => write!(f, "{protocol}: {error}"),
        }
    }
}

impl core::error::Error for PolicyError {}

/// Parses `policy` (see the [crate] docs) as the socket policy: the guest
/// network, and the `egress` destinations.
///
/// # Errors
///
/// If `policy` does not follow the format.
pub fn parse(policy: &[u8]) -> Result<SocketPolicy, PolicyError> {
    let (mut tcp, mut udp) = (Vec::new(), Vec::new());
    for (index, text) in policy.split(|&byte| byte == b'\n').enumerate() {
        let line = index + 1;
        if text.is_empty() {
            continue;
        }
        let mut fields = core::str::from_utf8(text)
            .map_err(|_| PolicyError::Line { line })?
            .split(' ');
        let (Some("egress"), Some(protocol), Some(value), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(PolicyError::Line { line });
        };
        let rules = match protocol {
            "tcp" => &mut tcp,
            "udp" => &mut udp,
            _ => return Err(PolicyError::Line { line }),
        };
        let rule = parse_destination(value).map_err(|reason| PolicyError::Destination {
            line,
            value: value.into(),
            reason,
        })?;
        rules.push(rule);
    }
    SocketPolicy::guest_network()
        .with_tcp_destination_rules(&tcp)
        .map_err(|error| PolicyError::Rules {
            protocol: "tcp",
            error,
        })?
        .with_udp_destination_rules(&udp)
        .map_err(|error| PolicyError::Rules {
            protocol: "udp",
            error,
        })
}

/// A canonical IPv4 `NETWORK/PREFIX_LENGTH`, as the userland broker parses
/// `--allow-tcp-source`.
fn parse_cidr(value: &str) -> Result<Ipv4Cidr, String> {
    let (network, prefix_length) = value
        .split_once('/')
        .ok_or("expected an IPv4 CIDR prefix")?;
    let network: Ipv4Addr = network
        .parse()
        .map_err(|error| format!("invalid IPv4 network: {error}"))?;
    let prefix_length: u8 = prefix_length
        .parse()
        .map_err(|error| format!("invalid IPv4 prefix length: {error}"))?;
    Ipv4Cidr::new(Ipv4Address(network.octets()), prefix_length)
        .ok_or_else(|| "IPv4 CIDR must have a valid prefix and canonical network address".into())
}

/// `CIDR:PORT` or `CIDR:START-END`, as the userland broker parses
/// `--allow-tcp-destination`.
fn parse_destination(value: &str) -> Result<DestinationRule, String> {
    let (cidr, ports) = value
        .rsplit_once(':')
        .ok_or("expected CIDR:PORT or CIDR:START-END")?;
    if !cidr.contains('/') {
        return Err("destination must include an IPv4 CIDR prefix".into());
    }
    let destination = parse_cidr(cidr)?;
    let (start, end) = ports.split_once('-').unwrap_or((ports, ports));
    let port = |port: &str| {
        port.parse()
            .map(Port)
            .map_err(|error| format!("invalid port: {error}"))
    };
    let ports = DestinationPortRange::new(port(start)?, port(end)?)
        .ok_or("port range must be ordered and exclude port zero")?;
    Ok(DestinationRule::new(
        CallerCredential::HostGuaranteed,
        destination,
        ports,
    ))
}

#[cfg(test)]
mod tests {
    use super::{PolicyError, parse, parse_destination};
    use alloc::string::ToString as _;
    use litebox_broker_core::{
        CallerCredential, DestinationPortRange, DestinationRule, Ipv4Cidr, MAX_DESTINATION_RULES,
        SocketPolicy,
    };
    use litebox_broker_protocol::socket::{Ipv4Address, Port};

    fn rule(network: [u8; 4], prefix_length: u8, start: u16, end: u16) -> DestinationRule {
        DestinationRule::new(
            CallerCredential::HostGuaranteed,
            Ipv4Cidr::new(Ipv4Address(network), prefix_length).unwrap(),
            DestinationPortRange::new(Port(start), Port(end)).unwrap(),
        )
    }

    #[test]
    fn destinations_parse_as_the_userland_brokers() {
        assert_eq!(
            parse_destination("203.0.113.0/24:443-444"),
            Ok(rule([203, 0, 113, 0], 24, 443, 444))
        );
        assert_eq!(
            parse_destination("10.0.2.100/32:7"),
            Ok(rule([10, 0, 2, 100], 32, 7, 7))
        );
        for invalid in [
            "203.0.113.1/24:443",
            "203.0.113.0/24:0",
            "203.0.113.0/24:444-443",
            "203.0.113.0/33:443",
            "203.0.113.0:443",
            "203.0.113.0/24",
            "203.0.113/24:443",
            "203.0.113.0/24:65536",
        ] {
            assert!(parse_destination(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn destinations_extend_the_guest_network_by_protocol() {
        let policy = parse(
            b"egress tcp 0.0.0.0/0:80\negress udp 10.0.2.1/32:53\negress tcp 10.0.2.1/32:3128\n",
        )
        .unwrap();
        assert_eq!(
            policy.tcp_destination_rules(),
            Some(
                &[
                    rule([0, 0, 0, 0], 0, 80, 80),
                    rule([10, 0, 2, 1], 32, 3128, 3128)
                ][..]
            )
        );
        assert_eq!(
            policy.udp_destination_rules(),
            Some(&[rule([10, 0, 2, 1], 32, 53, 53)][..])
        );
    }

    #[test]
    fn missing_lines_leave_the_guest_network_only() {
        assert_eq!(parse(b"").unwrap(), SocketPolicy::guest_network());
        assert_eq!(parse(b"\n\n").unwrap(), SocketPolicy::guest_network());
        let policy = parse(b"egress udp 10.0.2.1/32:53").unwrap();
        assert_eq!(policy.tcp_destination_rules(), Some(&[][..]));
        assert_eq!(
            policy.udp_destination_rules(),
            Some(&[rule([10, 0, 2, 1], 32, 53, 53)][..])
        );
    }

    #[test]
    fn malformed_policies_are_rejected() {
        for (policy, bad) in [
            (&b"egress tcp"[..], 1),
            (b"tcp 10.0.2.100/32:7", 1),
            (
                b"egress tcp 10.0.2.100/32:7\negress icmp 10.0.2.100/32:7",
                2,
            ),
            (b"EGRESS tcp 10.0.2.100/32:7", 1),
            (b"egress tcp\t10.0.2.100/32:7", 1),
            (b"egress tcp  10.0.2.100/32:7", 1),
            (b"egress tcp 10.0.2.100/32:7 extra", 1),
            (b"\negress tcp \xff", 2),
            (b"publish tcp 8080:80", 1),
            (b"ingress tcp 10.0.2.1/32", 1),
        ] {
            assert!(
                matches!(parse(policy), Err(PolicyError::Line { line }) if line == bad),
                "{policy:?}"
            );
        }
        let error = parse(b"egress tcp 10.0.2.100/32:7\negress udp 10.0.2.1/32:x\n").unwrap_err();
        assert_eq!(
            error.to_string(),
            r#"line 2: "10.0.2.1/32:x" is not CIDR:PORT[-PORT]: invalid port: invalid digit found in string"#
        );
        for protocol in ["tcp", "udp"] {
            let too_many = alloc::format!("egress {protocol} 10.0.2.100/32:7\n")
                .repeat(MAX_DESTINATION_RULES + 1);
            assert!(
                matches!(
                    parse(too_many.as_bytes()),
                    Err(PolicyError::Rules { protocol: rejected, .. }) if rejected == protocol
                ),
                "{protocol}"
            );
        }
    }
}
