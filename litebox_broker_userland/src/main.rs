// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::str::FromStr;
use std::time::{Duration, Instant};

use clap::Parser;
use litebox_broker_core::{
    CallerCredential, DestinationPortRange, DestinationRule, Ipv4Cidr, SocketPolicy,
    SocketPolicyError,
};
use litebox_broker_protocol::socket::{Ipv4Address, Port};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AllowedDestination {
    destination: Ipv4Cidr,
    ports: DestinationPortRange,
}

impl FromStr for AllowedDestination {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (cidr, ports) = value
            .rsplit_once(':')
            .ok_or_else(|| "expected CIDR:PORT or CIDR:START-END".to_owned())?;
        let (network, prefix_length) = cidr
            .split_once('/')
            .ok_or_else(|| "destination must include an IPv4 CIDR prefix".to_owned())?;
        let network = network
            .parse::<Ipv4Addr>()
            .map_err(|error| format!("invalid IPv4 network: {error}"))?;
        let prefix_length = prefix_length
            .parse::<u8>()
            .map_err(|error| format!("invalid IPv4 prefix length: {error}"))?;
        let destination =
            Ipv4Cidr::new(Ipv4Address(network.octets()), prefix_length).ok_or_else(|| {
                "IPv4 CIDR must have a valid prefix and canonical network address".to_owned()
            })?;

        let (start, end) = ports
            .split_once('-')
            .map_or((ports, ports), |(start, end)| (start, end));
        let start = start
            .parse::<u16>()
            .map_err(|error| format!("invalid port: {error}"))?;
        let end = end
            .parse::<u16>()
            .map_err(|error| format!("invalid port: {error}"))?;
        let ports = DestinationPortRange::new(Port(start), Port(end))
            .ok_or_else(|| "port range must be ordered and exclude port zero".to_owned())?;

        Ok(Self { destination, ports })
    }
}

#[derive(Parser, Debug)]
struct CliArgs {
    /// Permit HTTP and HTTPS proxy requests to a hostname and destination ports.
    #[cfg(target_os = "linux")]
    #[arg(long = "allow-host", value_name = "HOST:PORT[-PORT]")]
    allow_host: Vec<String>,
    /// Permit outbound TCP connections to a destination CIDR and port range.
    ///
    /// May be repeated to extend the default guest-network policy for TCP.
    /// `0.0.0.0/0:1-65535` permits every nonzero IPv4 TCP destination.
    #[arg(long, value_name = "CIDR:PORT[-PORT]")]
    allow_tcp_destination: Vec<AllowedDestination>,
    /// Permit outbound UDP traffic to a destination CIDR and port range.
    ///
    /// May be repeated to extend the default guest-network policy for UDP.
    /// `0.0.0.0/0:1-65535` permits every nonzero IPv4 UDP destination.
    #[arg(long, value_name = "CIDR:PORT[-PORT]")]
    allow_udp_destination: Vec<AllowedDestination>,
    /// Local runner executable to launch.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::ExecutablePath)]
    runner: PathBuf,
    /// Arguments to pass to the local runner.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, value_hint = clap::ValueHint::CommandWithArguments)]
    runner_arguments: Vec<OsString>,
}

fn run_runner_process(
    args: &CliArgs,
    control_channel: &OsStr,
    proxy_url: Option<&str>,
    serve: impl FnOnce(&mut Child, u32) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let mut command = Command::new(&args.runner);
    command
        .arg("--unstable")
        .arg("--broker-control-channel")
        .arg(control_channel);
    if let Some(proxy_url) = proxy_url {
        command.arg("--broker-proxy-url").arg(proxy_url);
    }
    let mut runner = command.args(&args.runner_arguments).spawn()?;
    let runner_process_id = runner.id();
    let association_result = serve(&mut runner, runner_process_id);
    if association_result.is_err() {
        let _ = runner.kill();
    }
    let runner_status = runner.wait()?;
    association_result?;
    if !runner_status.success() {
        return Err(IoError::other(format!("runner exited with {runner_status}")).into());
    }
    Ok(())
}

fn configured_socket_policy(
    allowed_tcp_destinations: &[AllowedDestination],
    allowed_udp_destinations: &[AllowedDestination],
) -> Result<SocketPolicy, SocketPolicyError> {
    let mut policy = SocketPolicy::guest_network();
    if !allowed_tcp_destinations.is_empty() {
        let rules = destination_rules(allowed_tcp_destinations);
        policy = policy.with_tcp_destination_rules(&rules)?;
    }
    if !allowed_udp_destinations.is_empty() {
        let rules = destination_rules(allowed_udp_destinations);
        policy = policy.with_udp_destination_rules(&rules)?;
    }
    Ok(policy)
}

fn destination_rules(allowed_destinations: &[AllowedDestination]) -> Vec<DestinationRule> {
    allowed_destinations
        .iter()
        .map(|allowed| {
            DestinationRule::new(
                CallerCredential::HostGuaranteed,
                allowed.destination,
                allowed.ports,
            )
        })
        .collect()
}

fn accept_runner_channel<Channel>(
    runner: &mut Child,
    deadline: Instant,
    channel_name: &'static str,
    mut try_accept: impl FnMut() -> IoResult<Channel>,
) -> IoResult<Channel> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IoError::new(
                ErrorKind::TimedOut,
                format!("timed out waiting for runner {channel_name} channel"),
            ));
        }
        if let Some(status) = runner.try_wait()? {
            return Err(IoError::new(
                ErrorKind::BrokenPipe,
                format!("runner exited with {status} before connecting its {channel_name} channel"),
            ));
        }
        match try_accept() {
            Ok(channel) => return Ok(channel),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(remaining.min(ACCEPT_RETRY_DELAY));
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run(CliArgs::parse())
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows::run(CliArgs::parse())
}

#[cfg(not(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64")
)))]
fn main() {}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn cli_accepts_tcp_and_udp_destination_arguments() {
        let args = CliArgs::try_parse_from([
            "litebox-broker-userland",
            "--allow-tcp-destination",
            "127.0.0.0/8:80",
            "--allow-udp-destination",
            "10.0.2.1/32:53",
            "--runner",
            "runner",
            "guest",
        ])
        .unwrap();

        assert_eq!(args.allow_tcp_destination.len(), 1);
        assert_eq!(args.allow_udp_destination.len(), 1);
    }

    #[test]
    fn destination_argument_parses_canonical_cidr_and_ports() {
        let allowed = "203.0.113.0/24:443-444"
            .parse::<AllowedDestination>()
            .unwrap();

        assert_eq!(
            allowed,
            AllowedDestination {
                destination: Ipv4Cidr::new(Ipv4Address([203, 0, 113, 0]), 24).unwrap(),
                ports: DestinationPortRange::new(Port(443), Port(444)).unwrap(),
            }
        );
        assert!("203.0.113.1/24:443".parse::<AllowedDestination>().is_err());
        assert!("203.0.113.0/24:0".parse::<AllowedDestination>().is_err());
    }

    #[test]
    fn destination_arguments_extend_the_guest_network_default_by_protocol() {
        assert_eq!(
            configured_socket_policy(&[], &[]).unwrap(),
            SocketPolicy::guest_network()
        );

        let tcp = "0.0.0.0/0:80".parse::<AllowedDestination>().unwrap();
        let udp = "10.0.2.1/32:53".parse::<AllowedDestination>().unwrap();
        let proxy = "10.0.2.1/32:3128".parse::<AllowedDestination>().unwrap();
        let policy = configured_socket_policy(&[tcp, proxy], &[udp]).unwrap();
        let tcp_rules = policy.tcp_destination_rules().unwrap();
        assert_eq!(tcp_rules.len(), 2);
        assert_eq!(
            tcp_rules[0],
            DestinationRule::new(CallerCredential::HostGuaranteed, tcp.destination, tcp.ports,)
        );
        assert_eq!(
            tcp_rules[1],
            DestinationRule::new(
                CallerCredential::HostGuaranteed,
                proxy.destination,
                proxy.ports,
            )
        );
        let udp_rules = policy.udp_destination_rules().unwrap();
        assert_eq!(udp_rules.len(), 1);
        assert_eq!(
            udp_rules[0],
            DestinationRule::new(CallerCredential::HostGuaranteed, udp.destination, udp.ports,)
        );
    }
}
