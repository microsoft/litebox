// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Error as IoError, ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use clap::Parser as _;
use litebox_broker_core::pid_namespace::PidNamespace;
use litebox_broker_core::socket::HOST_GATEWAY_IPV4_ADDRESS;
use litebox_broker_core::stdio::StdioProvider as _;
use litebox_broker_core::{BrokerCoreLimits, BrokerProcess, ObjectRights, PolicyEngine};
use litebox_broker_platform_linux_userland::LinuxSyncPrimitivesProvider;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_protocol::vsock_socket::VsockCid;
use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
use litebox_broker_transport_linux_userland::shared_objects::SharedObjectSender;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixStreamHostSetupChannel, validate_peer_process,
};
use litebox_broker_userland::shared_objects::linux::MemfdDelivery;
use litebox_broker_userland::stdio::UserlandStdioProvider;

use super::{SETUP_TIMEOUT, configured_socket_policy};

const PROXY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// `--runner-user`'s `UID[:GID]`: neither root's nor 4294967295, which `setuid` refuses and
/// `chown` takes for "unchanged".
pub(super) fn parse_runner_user(value: &str) -> Result<(u32, u32), String> {
    let (uid, gid) = value.split_once(':').unwrap_or((value, value));
    let id = |id: &str| id.parse().ok().filter(|id| ![0, u32::MAX].contains(id));
    id(uid)
        .zip(id(gid))
        .ok_or_else(|| format!("{value:?} is not UID[:GID], with neither 0 nor 4294967295"))
}

/// Whether a broker that is `root` or not, with the uid map `uid_map` (none without user
/// namespaces), may be the host's root: its uid 0 maps to an outer 0, conservatively the host's.
fn is_host_root(root: bool, uid_map: Option<&str>) -> bool {
    root && uid_map.is_none_or(|map| {
        map.lines()
            .any(|line| line.split_whitespace().take(2).eq(["0", "0"]))
    })
}

pub(super) fn run(
    mut args: super::CliArgs,
    stdio: Arc<UserlandStdioProvider>,
) -> Result<(), Box<dyn Error>> {
    let uid_map = std::fs::read_to_string("/proc/self/uid_map").ok();
    let root = rustix::process::geteuid().is_root();
    if is_host_root(root, uid_map.as_deref()) {
        // Its runners must not be root.
        if args.in_process_runner {
            return Err(
                "a broker that is the host's root cannot run its runner in process, a \
                 debugging mode: runners must not be root"
                    .into(),
            );
        }
        if args.runner_user.is_none() {
            return Err(
                "a broker that is the host's root needs --runner-user: runners must not be root"
                    .into(),
            );
        }
    }
    let proxy = if args.allow_host.is_empty() {
        None
    } else {
        Some(ManagedEgressProxy::start(
            &args.allow_host,
            args.runner_user,
        )?)
    };
    if let Some(proxy) = &proxy {
        let proxy_destination = format!("{HOST_GATEWAY_IPV4_ADDRESS}/32:{}", proxy.port)
            .parse()
            .map_err(|error: String| IoError::new(ErrorKind::InvalidData, error))?;
        args.allow_tcp_destination.push(proxy_destination);
    }
    let proxy_url = proxy
        .as_ref()
        .map(|proxy| format!("http://{HOST_GATEWAY_IPV4_ADDRESS}:{}", proxy.port));

    let policy = PolicyEngine::with_host_guaranteed_rights(ObjectRights::all())
        .with_socket_policy(configured_socket_policy(
            &args.allow_tcp_destination,
            &args.allow_udp_destination,
        )?)
        .with_process_duplication_enabled(args.allow_process_duplication)
        .with_vsock_policy(super::configured_vsock_policy(args.vsock_uds.is_some()));
    let terminal = stdio.terminal();
    let limits = BrokerCoreLimits::DEFAULT;
    let fs = super::create_file_service::<LinuxSyncPrimitivesProvider>(
        args.fs_initial_files.as_deref(),
        &args.mounts,
        &args.read_only_mounts,
        limits.max_shared_files,
        stdio,
    )?;
    let vsock_uds = args
        .vsock_uds
        .as_deref()
        .map(|path| (path, VsockCid(args.vsock_guest_cid)));
    let build = || super::build_broker(policy, limits, vsock_uds);
    // The bridge runs until `run` returns.
    let (core, _vsock) = if args.in_process_runner {
        litebox_platform_linux_userland::with_guest_signals_blocked(build)?
    } else {
        build()?
    };
    let pid_namespace = Arc::new(PidNamespace::new(&core)?);

    if args.in_process_runner {
        debug_assert!(args.unstable);
        let socket_dir = tempfile::Builder::new()
            .prefix("litebox-broker-userland-")
            .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .tempdir()?;
        let control_socket_path = socket_dir.path().join("broker.sock");
        let control_listener = UnixListener::bind(&control_socket_path)?;
        control_listener.set_nonblocking(true)?;
        crate::with_in_process_root(&core, pid_namespace, fs, terminal, |root| {
            run_runner_in_process(
                &args,
                control_socket_path.as_os_str(),
                proxy_url.as_deref(),
                root,
                &control_listener,
            )
        })
    } else {
        crate::run_runner_instance(
            &args,
            proxy_url.as_deref(),
            &core,
            pid_namespace,
            fs,
            terminal,
        )
    }
}

struct ManagedEgressProxy {
    child: Child,
    port: u16,
}

impl ManagedEgressProxy {
    /// Starts the proxy as the host user `(uid, gid)`, if any: it serves the guest, as runners do.
    fn start(allowed_hosts: &[String], user: Option<(u32, u32)>) -> IoResult<Self> {
        let executable = std::env::current_exe()?.with_file_name("litebox_egress_proxy");
        let mut command = Command::new(executable);
        command
            .arg("--listen")
            .arg("127.0.0.1:0")
            .arg("--exit-on-stdin-close")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for allowed_host in allowed_hosts {
            command.arg("--allow-host").arg(allowed_host);
        }
        if let Some(user) = user {
            litebox_broker_userland::runner::set_host_user(&mut command, user);
        }

        let mut proxy = Self {
            child: command.spawn().map_err(|error| {
                IoError::new(
                    error.kind(),
                    format!("cannot start the egress proxy: {error}"),
                )
            })?,
            port: 0,
        };
        let stdout = proxy
            .child
            .stdout
            .take()
            .ok_or_else(|| IoError::other("egress proxy stdout was not piped"))?;
        let (sender, receiver) = sync_channel(1);
        let reader = std::thread::spawn(move || {
            let _ = sender.send(read_proxy_ready(stdout));
        });

        let readiness = match receiver.recv_timeout(SETUP_TIMEOUT) {
            Ok(readiness) => readiness,
            Err(RecvTimeoutError::Timeout) => {
                return Err(IoError::new(
                    ErrorKind::TimedOut,
                    "timed out waiting for egress proxy readiness",
                ));
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(IoError::other("egress proxy readiness reader stopped"));
            }
        };
        if reader.join().is_err() {
            return Err(IoError::other("egress proxy readiness reader panicked"));
        }
        let address = readiness?;
        match proxy.child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => {
                return Err(IoError::new(
                    ErrorKind::BrokenPipe,
                    format!("egress proxy exited after reporting readiness with {status}"),
                ));
            }
            Err(error) => return Err(error),
        }

        proxy.port = address.port();
        Ok(proxy)
    }
}

impl Drop for ManagedEgressProxy {
    fn drop(&mut self) {
        self.child.stdin.take();
        let deadline = Instant::now() + PROXY_SHUTDOWN_TIMEOUT;
        loop {
            match self.child.try_wait() {
                Ok(Some(_status)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_proxy_ready(stdout: ChildStdout) -> IoResult<SocketAddrV4> {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(IoError::new(
            ErrorKind::UnexpectedEof,
            "egress proxy exited before reporting readiness",
        ));
    }
    line.strip_prefix("READY ")
        .and_then(|value| value.trim_end().parse::<SocketAddrV4>().ok())
        .filter(|address| *address.ip() == Ipv4Addr::LOCALHOST && address.port() != 0)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "invalid egress proxy readiness"))
}

fn run_runner_in_process(
    args: &super::CliArgs,
    control_socket_path: &std::ffi::OsStr,
    proxy_url: Option<&str>,
    root: &Arc<BrokerProcess>,
    control_listener: &UnixListener,
) -> Result<(), Box<dyn Error>> {
    let runner_args = litebox_runner_linux_userland::CliArgs::try_parse_from(
        std::iter::once(OsString::from("litebox-runner-linux-userland")).chain(
            crate::runner_command_arguments(args, control_socket_path, proxy_url),
        ),
    )?;
    litebox_platform_linux_userland::with_guest_signals_blocked(|| {
        let runner = std::thread::Builder::new()
            .name("litebox-runner".to_owned())
            .spawn(move || {
                litebox_platform_linux_userland::unblock_guest_signals();
                litebox_runner_linux_userland::run_in_broker_process(runner_args)
                    .map_err(|error| format!("{error:#}"))
            })?;
        let association_result = serve_runner_in_process(root, control_listener, &runner);
        crate::finish_in_process_runner(runner, association_result)
    })
}

fn serve_runner_in_process(
    root: &Arc<BrokerProcess>,
    control_listener: &UnixListener,
    runner: &JoinHandle<super::InProcessRunnerResult>,
) -> IoResult<()> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = crate::accept_runner_channel(
        setup_deadline,
        "control",
        || Ok(runner.is_finished().then(|| "thread stopped".to_owned())),
        || control_listener.accept().map(|(stream, _)| stream),
    )?;
    validate_peer_process(&control_stream, std::process::id())?;
    serve_control_stream(root, control_stream, setup_deadline)
}

fn serve_control_stream(
    root: &Arc<BrokerProcess>,
    control_stream: UnixStream,
    setup_deadline: Instant,
) -> IoResult<()> {
    let control_channel =
        UnixStreamHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline);
    let (shared_objects, runner_shared_objects) = SharedObjectSender::pair()?;
    litebox_broker_userland::runtime::serve_in_process_runner_association(
        root,
        control_channel,
        || MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        MemfdSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_memfd(shared_memory, Some(setup_deadline))?;
            channel.send_memfd(control_memory, Some(setup_deadline))?;
            channel
                .send_shared_object_channel(runner_shared_objects.as_fd(), Some(setup_deadline))?;
            channel.send_process_image(None, Some(setup_deadline))
        },
        UnixStreamHostSetupChannel::into_active,
        Some(MemfdDelivery(Arc::new(shared_objects))),
    )
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    #[test]
    fn runner_users_are_not_root_and_a_root_broker_needs_one() {
        let parse = |user| {
            crate::CliArgs::try_parse_from(["b", "--runner-user", user, "--runner", "r", "g"])
        };
        assert_eq!(parse("5").unwrap().runner_user, Some((5, 5)));
        assert_eq!(parse("5:6").unwrap().runner_user, Some((5, 6)));
        for bad in ["0", "5:0", "0:5", "4294967295", "5:4294967295", "x", "5:"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert!(super::is_host_root(true, Some("  0  0 4294967295\n")));
        assert!(super::is_host_root(true, Some("1 1000 1\n0 0 1\n")));
        assert!(super::is_host_root(true, None));
        assert!(!super::is_host_root(true, Some("0 1002 1\n1 0 65536\n")));
        assert!(!super::is_host_root(false, None));
    }
}
