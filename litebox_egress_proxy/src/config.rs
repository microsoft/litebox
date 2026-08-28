// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Executable configuration.

use std::net::{Ipv4Addr, SocketAddrV4};

use clap::Parser;
use thiserror::Error;

use crate::policy::{HostPolicy, PolicyError};

/// The standalone egress proxy for LiteBox sandboxes.
#[derive(Debug, Parser)]
#[command(
    name = "litebox_egress_proxy",
    about = "Hostname-filtering HTTP/HTTPS egress proxy"
)]
pub struct Cli {
    /// Loopback address to bind, for example `127.0.0.1:0`.
    #[arg(long, value_name = "IPV4:PORT")]
    listen: String,

    /// Allowed hostname and destination ports, repeatable.
    #[arg(long = "allow-host", value_name = "HOST:PORT[-PORT]")]
    allow_host: Vec<String>,
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
    /// An `--allow-host` rule was invalid.
    #[error("invalid --allow-host rule: {0}")]
    Policy(#[from] PolicyError),
}

/// The validated configuration of one proxy process.
#[derive(Debug)]
pub struct ProxyConfig {
    /// IPv4 loopback address to bind.
    pub listen: SocketAddrV4,
    /// The immutable hostname policy.
    pub policy: HostPolicy,
}

impl Cli {
    /// Converts parsed arguments into a validated configuration.
    pub fn into_config(self) -> Result<ProxyConfig, ConfigError> {
        let listen = parse_listen_address(&self.listen)?;
        let policy = HostPolicy::from_rules(&self.allow_host)?;

        Ok(ProxyConfig { listen, policy })
    }
}

fn parse_listen_address(raw: &str) -> Result<SocketAddrV4, ConfigError> {
    let address: SocketAddrV4 = raw.parse().map_err(|_| ConfigError::ListenAddress)?;
    if *address.ip() != Ipv4Addr::LOCALHOST {
        return Err(ConfigError::ListenNotLoopback);
    }
    Ok(address)
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
            "--allow-host",
            "Example.COM:443",
            "--allow-host",
            "example.com:8000-8100",
        ])
        .unwrap();

        assert_eq!(config.listen, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let host = Hostname::parse("example.com").unwrap();
        assert!(config.policy.allows(&host, 443));
        assert!(config.policy.allows(&host, 8100));
        assert!(!config.policy.allows(&host, 80));
    }

    #[test]
    fn rejects_non_loopback_listen_addresses() {
        assert!(matches!(
            parse(&["--listen", "0.0.0.0:8080"]),
            Err(ConfigError::ListenNotLoopback)
        ));
        assert!(matches!(
            parse(&["--listen", "127.0.0.2:8080"]),
            Err(ConfigError::ListenNotLoopback)
        ));
        assert!(matches!(
            parse(&["--listen", "localhost:8080"]),
            Err(ConfigError::ListenAddress)
        ));
    }
}
