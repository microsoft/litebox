// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::borrow::Cow;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use clap::Parser;
#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
use litebox_broker_core::BrokerCore;
#[cfg(target_os = "linux")]
use litebox_broker_core::VsockPolicy;
use litebox_broker_core::fs::FileService;
use litebox_broker_core::fs::composer::Composer;
use litebox_broker_core::fs::in_mem::{InMem, InitialNode};
use litebox_broker_core::fs::overlay::Overlay;
use litebox_broker_core::fs::resolver::Resolver;
use litebox_broker_core::fs::tar_ro::{EMPTY_TAR_FILE, TarRo};
use litebox_broker_core::{
    CallerCredential, DestinationPortRange, DestinationRule, Ipv4Cidr, SocketPolicy,
    SocketPolicyError,
};
#[cfg(target_os = "linux")]
use litebox_broker_platform_linux_userland::vsock::{DEFAULT_GUEST_CID, is_guest_cid};
use litebox_broker_protocol::fs::{FileMode as Mode, FileUser as UserInfo};
use litebox_broker_protocol::socket::{Ipv4Address, Port};
use litebox_broker_userland::fs::LocalFs;
use litebox_broker_userland::mapped_file;
use litebox_broker_userland::random::UserlandRandomProvider;
use litebox_broker_userland::stdio::UserlandStdioProvider;
use litebox_platform::sync::RawSyncPrimitivesProvider;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(windows, target_arch = "x86_64"))]
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

/// A host directory exposed to the guest via `--mount HOST:GUEST`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct MountSpec {
    host: PathBuf,
    guest: String,
}

impl FromStr for MountSpec {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // Paths may themselves contain colons (e.g. `C:\dir`), so a lone `:` is only accepted
        // when unambiguous; otherwise `::` must separate the two paths.
        let (host, guest) = if let Some((host, guest)) = value.split_once("::") {
            if guest.contains("::") {
                return Err("`::` separator must appear exactly once".to_owned());
            }
            (host, guest)
        } else {
            match value.matches(':').count() {
                0 => return Err("expected HOST_PATH:GUEST_PATH".to_owned()),
                1 => value.split_once(':').unwrap(),
                _ => {
                    return Err(
                        "ambiguous mount with multiple `:`; use HOST_PATH::GUEST_PATH".to_owned(),
                    );
                }
            }
        };
        if host.is_empty() {
            return Err("host path must not be empty".to_owned());
        }
        if !guest.starts_with('/') {
            return Err("guest path must be absolute".to_owned());
        }
        Ok(Self {
            host: PathBuf::from(host),
            guest: guest.to_owned(),
        })
    }
}

#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
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
    /// Allow using unstable options.
    #[arg(short = 'Z', long = "unstable")]
    unstable: bool,
    /// Run the runner library for this platform as a thread in this broker process.
    ///
    /// This mode does not provide a security boundary between the runner and
    /// broker and is intended only for testing and development.
    #[arg(long, hide = true, requires = "unstable", conflicts_with = "runner")]
    in_process_runner: bool,
    /// Enable the experimental constrained process-duplication path.
    #[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
    #[arg(
        long,
        hide = true,
        requires = "unstable",
        conflicts_with = "in_process_runner"
    )]
    allow_process_duplication: bool,
    /// Local runner executable to launch.
    #[arg(
        long,
        value_name = "PATH",
        value_hint = clap::ValueHint::ExecutablePath,
        required_unless_present = "in_process_runner",
        conflicts_with = "in_process_runner"
    )]
    runner: Option<PathBuf>,
    /// Tar archive to mount as the broker-owned initial file system.
    ///
    /// The archive is mapped into memory rather than copied, so it must not be modified while the
    /// broker runs.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    fs_initial_files: Option<PathBuf>,
    /// Mount a host directory at a guest path, with read/write access governed by host
    /// permissions.
    ///
    /// May be repeated. The guest path must be absolute and normalized. If either path contains
    /// `:`, separate them with `::` instead (e.g. `C:\data::/data`).
    #[arg(long = "mount", value_name = "HOST_PATH:GUEST_PATH")]
    mounts: Vec<MountSpec>,
    /// Bridge the guest's vsock sockets to host Unix sockets at PATH, as hybrid vsock.
    ///
    /// This is Firecracker's and Cloud Hypervisor's convention, which Kata's runtime speaks as
    /// `hvsock://PATH:PORT`. The broker creates the Unix socket PATH (the umask sets its mode),
    /// and removes it when it ends if it is still that socket; PATH must not exist, and its
    /// directory must. A host client
    /// connects to PATH and writes `CONNECT <port>\n` to reach the guest's listener on that port,
    /// which answers `OK <host port>\n`. The guest's connects to the host's port P go to
    /// `PATH_P`, in the same directory, which the broker resolves once, as it starts. Whoever can
    /// connect to PATH reaches the guest's listeners, and whoever can write PATH's directory can
    /// take the guest's connects or replace PATH: that directory must be writable only by the
    /// broker's user. Removing PATH and connecting to `PATH_P` are safe only if no other process,
    /// including ones running as the broker's user, creates, replaces or renames entries in
    /// PATH's directory (or its ancestors) while the broker runs; otherwise the broker may remove
    /// an entry it did not create, or connect the guest to a listener it did not expect.
    #[cfg(target_os = "linux")]
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    vsock_uds: Option<PathBuf>,
    /// The guest's vsock CID, with `--vsock-uds`: neither 0, 1, 2 (the host), nor 4294967295.
    #[cfg(target_os = "linux")]
    #[arg(
        long,
        value_name = "N",
        default_value_t = DEFAULT_GUEST_CID,
        requires = "vsock_uds",
        value_parser = parse_vsock_guest_cid
    )]
    vsock_guest_cid: u32,
    /// Opaque arguments to pass to the local runner without interpretation.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, value_hint = clap::ValueHint::CommandWithArguments)]
    runner_arguments: Vec<OsString>,
}

/// A guest's vsock CID ([`is_guest_cid`]).
#[cfg(target_os = "linux")]
fn parse_vsock_guest_cid(value: &str) -> Result<u32, String> {
    let cid = value
        .parse::<u32>()
        .map_err(|error| format!("invalid CID: {error}"))?;
    if !is_guest_cid(cid) {
        return Err(format!("CID {cid} is reserved, not a guest's"));
    }
    Ok(cid)
}

/// The vsock policy: any vsock socket with a hybrid-vsock bridge
/// (`--vsock-uds`), else none.
#[cfg(target_os = "linux")]
fn configured_vsock_policy(vsock_uds: bool) -> VsockPolicy {
    if vsock_uds {
        VsockPolicy::any()
    } else {
        VsockPolicy::deny()
    }
}

fn create_file_service<Platform>(
    initial_files: Option<&Path>,
    mounts: &[MountSpec],
    stdio: Arc<UserlandStdioProvider>,
) -> IoResult<Arc<dyn FileService>>
where
    Platform: RawSyncPrimitivesProvider,
{
    let writable_directory = |owner| InitialNode::Directory {
        mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
        owner,
    };
    let entries = vec![
        ("/tmp".to_owned(), writable_directory(UserInfo::ROOT)),
        ("/registry".to_owned(), writable_directory(UserInfo::ROOT)),
    ];

    let tar_data = match initial_files {
        Some(path) => {
            if path.extension().and_then(|extension| extension.to_str()) != Some("tar") {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    format!("expected a .tar file, found {}", path.display()),
                ));
            }
            // SAFETY: As documented on `--fs-initial-files`, the archive must not be modified
            // while the broker runs.
            Cow::Borrowed(unsafe { mapped_file::map_static(path) }?)
        }
        None => Cow::Borrowed(EMPTY_TAR_FILE),
    };
    let in_mem = InMem::<Platform>::new_initialized(entries);
    let mut builder = Composer::builder()
        .mount_nestable("/", |allocators| {
            Overlay::<Platform>::new(
                in_mem,
                TarRo::new(tar_data, allocators.next()),
                allocators.next(),
            )
        })
        .mount("/dev", |allocator| {
            litebox_broker_core::fs::devices::Devices::new(
                allocator,
                stdio,
                Arc::new(UserlandRandomProvider),
            )
        });
    for mount in mounts {
        builder = builder
            .try_mount(&mount.guest, |allocator| {
                LocalFs::new(&mount.host, allocator)
            })
            .map_err(|error| {
                IoError::new(
                    error.kind(),
                    format!("failed to mount {}: {error}", mount.host.display()),
                )
            })?;
    }
    let backend = builder.build().map_err(|error| {
        IoError::new(
            ErrorKind::InvalidInput,
            format!("failed to construct broker file service: {error}"),
        )
    })?;
    Ok(Arc::new(Resolver::<Platform, _>::new(backend)))
}

fn runner_command_arguments(
    args: &CliArgs,
    control_channel: &OsStr,
    proxy_url: Option<&str>,
) -> Vec<OsString> {
    let mut runner_arguments = vec![
        OsString::from("--unstable"),
        OsString::from("--broker-control-channel"),
        control_channel.to_os_string(),
    ];
    if let Some(proxy_url) = proxy_url {
        runner_arguments.push(OsString::from("--broker-proxy-url"));
        runner_arguments.push(OsString::from(proxy_url));
    }
    runner_arguments.extend(args.runner_arguments.iter().cloned());
    runner_arguments
}

#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
fn run_runner_instance(
    args: &CliArgs,
    proxy_url: Option<&str>,
    broker: &BrokerCore,
) -> Result<(), Box<dyn Error>> {
    let runner_path = args.runner.as_ref().ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidInput,
            "--runner is required outside in-process mode",
        )
    })?;
    let mut config = litebox_broker_userland::runner::RunnerConfig::new(
        runner_path.clone(),
        args.runner_arguments.clone(),
    );
    if let Some(proxy_url) = proxy_url {
        config = config.with_proxy_url(proxy_url.to_owned());
    }
    #[cfg(target_os = "linux")]
    if args.allow_process_duplication {
        config = config.with_aslr_disabled();
    }
    let runner_status = litebox_broker_userland::runner::run_to_completion(config, broker)?;
    if !runner_status.success() {
        return Err(IoError::other(format!("runner exited with {runner_status}")).into());
    }
    Ok(())
}

type InProcessRunnerResult = Result<i32, String>;

fn finish_in_process_runner(
    runner: JoinHandle<InProcessRunnerResult>,
    association_result: IoResult<()>,
) -> Result<(), Box<dyn Error>> {
    if let Err(error) = &association_result
        && !runner.is_finished()
    {
        return Err(
            IoError::new(error.kind(), format!("broker association failed: {error}")).into(),
        );
    }

    let runner_result = runner
        .join()
        .map_err(|_| IoError::other("in-process runner thread panicked"))?;
    match (runner_result, association_result) {
        (Ok(0), Ok(())) => Ok(()),
        (Ok(exit_code), Ok(())) => Err(IoError::other(format!(
            "in-process runner exited with status code {exit_code}"
        ))
        .into()),
        (Err(runner_error), Ok(())) => {
            Err(IoError::other(format!("in-process runner failed: {runner_error}")).into())
        }
        (Ok(0), Err(association_error)) => Err(association_error.into()),
        (Ok(exit_code), Err(association_error)) => Err(IoError::other(format!(
            "in-process runner exited with status code {exit_code}; \
             broker association failed: {association_error}"
        ))
        .into()),
        (Err(runner_error), Err(association_error)) => Err(IoError::other(format!(
            "in-process runner failed: {runner_error}; \
             broker association failed: {association_error}"
        ))
        .into()),
    }
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
    deadline: Instant,
    channel_name: &'static str,
    mut runner_status: impl FnMut() -> IoResult<Option<String>>,
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
        if let Some(status) = runner_status()? {
            return Err(IoError::new(
                ErrorKind::BrokenPipe,
                format!("runner {status} before connecting its {channel_name} channel"),
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

#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();
    #[cfg(target_os = "linux")]
    // Terminal workers are host threads, so guest signals must not reach them.
    let stdio = Arc::new(litebox_platform_linux_userland::with_guest_signals_blocked(
        UserlandStdioProvider::open_terminal,
    )?);
    #[cfg(not(target_os = "linux"))]
    let stdio = Arc::new(UserlandStdioProvider::default());
    #[cfg(target_os = "linux")]
    let result = linux::run(args, Arc::clone(&stdio));
    #[cfg(all(windows, target_arch = "x86_64"))]
    let result = windows::run(args, Arc::clone(&stdio));
    // Guest output accepted before the runner exited must reach the host.
    stdio.flush();
    stdio.close_terminal()?;
    result
}

#[cfg(not(any(target_os = "linux", all(windows, target_arch = "x86_64"))))]
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

    #[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
    #[test]
    fn cli_rejects_process_duplication_with_in_process_runner() {
        let error = CliArgs::try_parse_from([
            "litebox-broker-userland",
            "--unstable",
            "--in-process-runner",
            "--allow-process-duplication",
            "guest",
        ])
        .unwrap_err();

        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cli_accepts_vsock_uds_with_a_guest_cid() {
        let parse = |extra: &[&str]| {
            CliArgs::try_parse_from(
                ["litebox-broker-userland"]
                    .iter()
                    .chain(extra)
                    .chain(&["--runner", "runner", "guest"]),
            )
        };
        let args = parse(&[]).unwrap();
        assert_eq!(args.vsock_uds, None);
        assert_eq!(
            configured_vsock_policy(args.vsock_uds.is_some()),
            VsockPolicy::deny()
        );

        let args = parse(&["--vsock-uds", "/run/vsock.sock"]).unwrap();
        assert_eq!(
            args.vsock_uds.as_deref(),
            Some(Path::new("/run/vsock.sock"))
        );
        assert_eq!(args.vsock_guest_cid, DEFAULT_GUEST_CID);
        assert_eq!(
            configured_vsock_policy(args.vsock_uds.is_some()),
            VsockPolicy::any()
        );

        let args = parse(&["--vsock-uds", "vsock.sock", "--vsock-guest-cid", "42"]).unwrap();
        assert_eq!(args.vsock_guest_cid, 42);
        assert_eq!(
            parse(&["--vsock-uds", "v", "--vsock-guest-cid", "4294967294"])
                .unwrap()
                .vsock_guest_cid,
            u32::MAX - 1
        );

        for cid in ["0", "1", "2", "4294967295", "4294967296", "-1", "x"] {
            let error = parse(&["--vsock-uds", "v", "--vsock-guest-cid", cid]).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::ValueValidation,
                "CID {cid}"
            );
        }
        let error = parse(&["--vsock-guest-cid", "5"]).unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
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
