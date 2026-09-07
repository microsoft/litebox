// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Error as IoError, ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use clap::Parser as _;
use litebox_broker_core::socket::HOST_GATEWAY_IPV4_ADDRESS;
use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixStreamHostSetupChannel, validate_peer_process,
};
use litebox_broker_userland::builder::BrokerCoreBuilder;

use super::{SETUP_TIMEOUT, configured_socket_policy};

const PROXY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn run(mut args: super::CliArgs) -> Result<(), Box<dyn Error>> {
    let proxy = if args.allow_host.is_empty() {
        None
    } else {
        Some(ManagedEgressProxy::start(&args.allow_host)?)
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

    let socket_dir = tempfile::Builder::new()
        .prefix("litebox-broker-userland-")
        .tempdir()?;
    let control_socket_path = socket_dir.path().join("broker.sock");
    let control_listener = UnixListener::bind(&control_socket_path)?;
    control_listener.set_nonblocking(true)?;
    let policy = PolicyEngine::with_host_guaranteed_rights(ObjectRights::all()).with_socket_policy(
        configured_socket_policy(&args.allow_tcp_destination, &args.allow_udp_destination)?,
    );
    let build_broker = || BrokerCoreBuilder::new(policy).build();
    let broker = if args.in_process_runner {
        litebox_platform_linux_userland::with_guest_signals_blocked(build_broker)?
    } else {
        build_broker()?
    };

    if args.in_process_runner {
        debug_assert!(args.unstable);
        run_runner_in_process(
            &args,
            control_socket_path.as_os_str(),
            proxy_url.as_deref(),
            &broker,
            &control_listener,
        )
    } else {
        crate::run_runner_process(
            &args,
            control_socket_path.as_os_str(),
            proxy_url.as_deref(),
            |runner, runner_process_id| {
                serve_runner_process(&broker, &control_listener, runner, runner_process_id)?;
                Ok(())
            },
        )
    }
}

struct ManagedEgressProxy {
    child: Child,
    port: u16,
}

impl ManagedEgressProxy {
    fn start(allowed_hosts: &[String]) -> IoResult<Self> {
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

        let mut proxy = Self {
            child: command.spawn()?,
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
    broker: &BrokerCore,
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
                litebox_runner_linux_userland::run(runner_args)
                    .map_err(|error| format!("{error:#}"))
            })?;
        let association_result = serve_runner_in_process(broker, control_listener, &runner);
        crate::finish_in_process_runner(runner, association_result)
    })
}

fn serve_runner_process(
    broker: &BrokerCore,
    control_listener: &UnixListener,
    runner: &mut Child,
    runner_process_id: u32,
) -> IoResult<()> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = crate::accept_runner_channel(
        setup_deadline,
        "control",
        || {
            runner
                .try_wait()
                .map(|status| status.map(|status| format!("exited with {status}")))
        },
        || control_listener.accept().map(|(stream, _)| stream),
    )?;
    validate_peer_process(&control_stream, runner_process_id)?;
    serve_control_stream(broker, control_stream, setup_deadline)
}

fn serve_runner_in_process(
    broker: &BrokerCore,
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
    serve_control_stream(broker, control_stream, setup_deadline)
}

fn serve_control_stream(
    broker: &BrokerCore,
    control_stream: UnixStream,
    setup_deadline: Instant,
) -> IoResult<()> {
    let control_channel =
        UnixStreamHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline);
    litebox_broker_userland::runtime::serve_association(
        broker,
        control_channel,
        || MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        MemfdSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_memfd(shared_memory, Some(setup_deadline))?;
            channel.send_memfd(control_memory, Some(setup_deadline))?;
            Ok(())
        },
        UnixStreamHostSetupChannel::into_active,
    )
}
