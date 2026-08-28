// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Executable configuration.
//!
//! Command-line arguments are parsed into typed, canonical values once. Only
//! those typed values reach the rest of the proxy: no raw argument string is
//! ever re-interpreted later.

use std::net::{Ipv4Addr, SocketAddrV4};

use clap::{ArgGroup, Parser};
use thiserror::Error;

use crate::dns::{TargetPolicy, TargetPolicyError, is_permitted_dns_server_ipv4};
use crate::listener::ListenerSource;
use crate::policy::{HostPolicy, HostRule, HostRuleError, PolicyError, parse_port};

/// Default DNS server port used when `--dns-server` carries no port.
pub const DEFAULT_DNS_PORT: u16 = 53;

/// The standalone egress proxy for LiteBox sandboxes.
///
/// Exactly one listener mode must be selected: `--listen` binds a loopback
/// listener itself, while `--listener-fd` adopts a listener that a launcher
/// bound and inherited to this process.
#[derive(Debug, Parser)]
#[command(
    name = "litebox_egress_proxy",
    about = "Hostname-filtering HTTP/HTTPS egress proxy",
    group(ArgGroup::new("listener").required(true).args(["listen", "listener_fd"]))
)]
pub struct Cli {
    /// Loopback address to bind, for example `127.0.0.1:0`.
    #[arg(long, value_name = "IPV4:PORT")]
    listen: Option<String>,

    /// Inherited, already-bound loopback listener descriptor.
    #[arg(long, value_name = "FD", conflicts_with = "listen")]
    listener_fd: Option<i32>,

    /// The only DNS server used to resolve policy hostnames.
    #[arg(long, value_name = "IPV4[:PORT]")]
    dns_server: String,

    /// Allowed hostname and destination ports, repeatable.
    #[arg(long = "allow-host", value_name = "HOST:PORT[-PORT]")]
    allow_host: Vec<String>,

    /// Additional proxy-only CIDRs to which policy hostnames may resolve.
    ///
    /// Public IPv4 targets are permitted by default. This option deliberately
    /// does not grant the guest direct access to the CIDR.
    #[arg(long = "allow-resolved-destination", value_name = "CIDR")]
    allow_resolved_destination: Vec<String>,
}

/// Reason the arguments were rejected.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// `--listen` was not a socket address.
    #[error("--listen must be an IPv4 address and port, for example 127.0.0.1:0")]
    ListenAddress,
    /// `--listen` was not canonical IPv4 loopback.
    #[error("--listen must use the canonical loopback address 127.0.0.1")]
    ListenNotLoopback,
    /// `--dns-server` was not an IPv4 address with an optional port.
    #[error("--dns-server must be an IPv4 address with an optional port")]
    DnsServerAddress,
    /// `--dns-server` was not an externally usable unicast address.
    #[error(
        "--dns-server must be a non-loopback unicast IPv4 address; unspecified, multicast, \
         broadcast, and reserved addresses are rejected"
    )]
    DnsServerNotExternal,
    /// An `--allow-host` rule was invalid.
    #[error("invalid --allow-host rule: {0}")]
    Rule(#[from] HostRuleError),
    /// The rules could not be combined into a policy.
    #[error("invalid policy: {0}")]
    Policy(#[from] PolicyError),
    /// A proxy-only resolved-destination CIDR was invalid.
    #[error("invalid --allow-resolved-destination CIDR: {0}")]
    ResolvedDestination(String),
    /// Too many resolved-destination CIDRs were configured.
    #[error("invalid resolved-destination policy: {0}")]
    TargetPolicy(#[from] TargetPolicyError),
}

/// The validated configuration of one proxy process.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// Where the listener comes from.
    pub listener: ListenerSource,
    /// The single DNS server used for startup resolution.
    pub dns_server: SocketAddrV4,
    /// The immutable hostname policy.
    pub policy: HostPolicy,
    /// Permitted resolved upstream addresses.
    pub targets: TargetPolicy,
}

impl Cli {
    /// Converts parsed arguments into a validated configuration.
    pub fn into_config(self) -> Result<ProxyConfig, ConfigError> {
        let listener = match (self.listen, self.listener_fd) {
            (Some(address), _) => ListenerSource::Bind(parse_listen_address(&address)?),
            (None, Some(descriptor)) => ListenerSource::Inherited(descriptor),
            // `clap` enforces that one of the two is present.
            (None, None) => return Err(ConfigError::ListenAddress),
        };

        let dns_server = parse_dns_server(&self.dns_server)?;

        let mut rules = Vec::with_capacity(self.allow_host.len());
        for rule in &self.allow_host {
            rules.push(rule.parse::<HostRule>()?);
        }
        let policy = HostPolicy::from_rules(rules)?;
        let targets = TargetPolicy::new(
            self.allow_resolved_destination
                .iter()
                .map(|cidr| parse_resolved_destination(cidr))
                .collect::<Result<Vec<_>, _>>()?,
        )?;

        Ok(ProxyConfig {
            listener,
            dns_server,
            policy,
            targets,
        })
    }
}

/// Parses one canonical proxy-only resolved-destination CIDR.
fn parse_resolved_destination(raw: &str) -> Result<ipnet::Ipv4Net, ConfigError> {
    let network: ipnet::Ipv4Net = raw
        .parse()
        .map_err(|error| ConfigError::ResolvedDestination(format!("{raw}: {error}")))?;
    if network.addr() != network.network() {
        return Err(ConfigError::ResolvedDestination(format!(
            "{raw}: network address contains host bits"
        )));
    }
    Ok(network)
}

/// Parses `--listen`, which is restricted to canonical IPv4 loopback.
fn parse_listen_address(raw: &str) -> Result<SocketAddrV4, ConfigError> {
    let address: SocketAddrV4 = raw.parse().map_err(|_| ConfigError::ListenAddress)?;
    if *address.ip() != Ipv4Addr::LOCALHOST {
        return Err(ConfigError::ListenNotLoopback);
    }
    Ok(address)
}

/// Parses `--dns-server`, which accepts an optional port.
///
/// The server must be an externally usable unicast IPv4 address. Private and
/// link-local servers are accepted because this address is selected directly
/// by the trusted operator rather than learned from an untrusted DNS answer.
fn parse_dns_server(raw: &str) -> Result<SocketAddrV4, ConfigError> {
    let (address, port) = match raw.split_once(':') {
        Some((address, port)) => (
            address,
            parse_port(port).map_err(|_| ConfigError::DnsServerAddress)?,
        ),
        None => (raw, DEFAULT_DNS_PORT),
    };

    let address: Ipv4Addr = address.parse().map_err(|_| ConfigError::DnsServerAddress)?;
    if !is_permitted_dns_server_ipv4(address) {
        return Err(ConfigError::DnsServerNotExternal);
    }
    Ok(SocketAddrV4::new(address, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::policy::Hostname;

    fn parse(arguments: &[&str]) -> Result<ProxyConfig, ConfigError> {
        let mut all = vec!["litebox_egress_proxy"];
        all.extend_from_slice(arguments);
        Cli::try_parse_from(all).unwrap().into_config()
    }

    #[test]
    fn parses_a_standalone_configuration() {
        let config = parse(&[
            "--listen",
            "127.0.0.1:0",
            "--dns-server",
            "9.9.9.9",
            "--allow-host",
            "Example.COM:443",
            "--allow-host",
            "example.com:8000-8100",
            "--allow-resolved-destination",
            "10.0.0.0/8",
        ])
        .unwrap();

        assert_eq!(
            config.listener,
            ListenerSource::Bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        );
        assert_eq!(
            config.dns_server,
            SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), DEFAULT_DNS_PORT)
        );

        let host = Hostname::parse("example.com").unwrap();
        assert_eq!(config.policy.len(), 1);
        assert!(config.policy.allows(&host, 443));
        assert!(config.policy.allows(&host, 8100));
        assert!(!config.policy.allows(&host, 80));
        assert!(config.targets.allows(Ipv4Addr::new(10, 1, 2, 3)));
    }

    #[test]
    fn parses_an_inherited_listener_configuration() {
        let config = parse(&["--listener-fd", "7", "--dns-server", "9.9.9.9:5353"]).unwrap();
        assert_eq!(config.listener, ListenerSource::Inherited(7));
        assert_eq!(config.dns_server.port(), 5353);
        assert!(config.policy.is_empty());
    }

    #[test]
    fn listener_modes_are_mutually_exclusive_and_required() {
        assert!(
            Cli::try_parse_from([
                "litebox_egress_proxy",
                "--listen",
                "127.0.0.1:0",
                "--listener-fd",
                "3",
                "--dns-server",
                "9.9.9.9",
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["litebox_egress_proxy", "--dns-server", "9.9.9.9"]).is_err());
    }

    #[test]
    fn rejects_non_loopback_listen_addresses() {
        assert!(matches!(
            parse(&["--listen", "0.0.0.0:8080", "--dns-server", "9.9.9.9"]),
            Err(ConfigError::ListenNotLoopback)
        ));
        assert!(matches!(
            parse(&["--listen", "127.0.0.2:8080", "--dns-server", "9.9.9.9"]),
            Err(ConfigError::ListenNotLoopback)
        ));
        assert!(matches!(
            parse(&["--listen", "localhost:8080", "--dns-server", "9.9.9.9"]),
            Err(ConfigError::ListenAddress)
        ));
    }

    #[test]
    fn accepts_explicit_private_dns_servers_but_rejects_invalid_endpoints() {
        assert!(parse(&["--listen", "127.0.0.1:0", "--dns-server", "10.0.0.1"]).is_ok());
        assert!(parse(&["--listen", "127.0.0.1:0", "--dns-server", "169.254.169.253",]).is_ok());

        for server in ["127.0.0.1:5353", "224.0.0.1", "240.0.0.1", "0.0.0.0"] {
            assert!(
                matches!(
                    parse(&["--listen", "127.0.0.1:0", "--dns-server", server]),
                    Err(ConfigError::DnsServerNotExternal)
                ),
                "{server} must be rejected"
            );
        }
        assert!(matches!(
            parse(&["--listen", "127.0.0.1:0", "--dns-server", "not-an-address"]),
            Err(ConfigError::DnsServerAddress)
        ));
    }

    #[test]
    fn rejects_reserved_dns_ports_in_rules() {
        assert!(matches!(
            parse(&[
                "--listen",
                "127.0.0.1:0",
                "--dns-server",
                "9.9.9.9",
                "--allow-host",
                "example.com:853",
            ]),
            Err(ConfigError::Rule(_))
        ));
    }

    #[test]
    fn rejects_invalid_resolved_destination_cidr() {
        assert!(matches!(
            parse(&[
                "--listen",
                "127.0.0.1:0",
                "--dns-server",
                "9.9.9.9",
                "--allow-resolved-destination",
                "10.0.0.1/8",
            ]),
            Err(ConfigError::ResolvedDestination(_))
        ));
    }
}
