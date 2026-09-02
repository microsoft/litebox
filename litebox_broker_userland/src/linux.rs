// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::io::{BufRead, BufReader, Error as IoError, ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::net::UnixListener;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::{Duration, Instant};

use litebox_broker_core::socket::HOST_GATEWAY_IPV4_ADDRESS;
use litebox_broker_core::{BrokerCore, BrokerCoreLimits, ObjectRights, PolicyEngine};
use litebox_broker_platform_linux_userland::LinuxSocketProvider;
use litebox_broker_protocol::message::{BrokerRequest, BrokerResponse};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::channel::HostReceive;
use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixControlRingHostRequestSource, UnixControlRingHostResponseSink, UnixControlRingHostShutdown,
    UnixStreamHostSetupChannel, validate_peer_process,
};

use super::{
    HostAssociationShutdown, HostRequestSource, HostResponseSink, SETUP_TIMEOUT,
    configured_socket_policy,
};

const PROXY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

impl HostRequestSource for UnixControlRingHostRequestSource {
    fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        Self::recv_request(self)
    }
}

impl HostResponseSink for UnixControlRingHostResponseSink {
    fn send_response(&self, response: &BrokerResponse) -> IoResult<()> {
        Self::send_response(self, response)
    }
}

impl HostAssociationShutdown for UnixControlRingHostShutdown {
    fn shutdown(&self) -> IoResult<()> {
        Self::shutdown(self)
    }
}

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
    let limits = BrokerCoreLimits::DEFAULT;
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_host_guaranteed_rights(ObjectRights::all()).with_socket_policy(
            configured_socket_policy(&args.allow_tcp_destination, &args.allow_udp_destination)?,
        ),
        limits,
        Arc::new(LinuxSocketProvider::new(
            limits.max_sockets,
            limits.max_sockets_per_session,
        )?),
    )?;

    crate::run_runner_process(
        &args,
        control_socket_path.as_os_str(),
        proxy_url.as_deref(),
        |runner, runner_process_id| {
            serve_runner(&broker, &control_listener, runner, runner_process_id)
        },
    )
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
        let address = parse_proxy_ready(&readiness?)?;
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
        stop_proxy(&mut self.child);
    }
}

fn read_proxy_ready(stdout: ChildStdout) -> IoResult<String> {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(IoError::new(
            ErrorKind::UnexpectedEof,
            "egress proxy exited before reporting readiness",
        ));
    }
    Ok(line)
}

fn parse_proxy_ready(line: &str) -> IoResult<SocketAddrV4> {
    let address = line
        .strip_prefix("READY ")
        .and_then(|value| value.trim_end().parse::<SocketAddrV4>().ok())
        .filter(|address| *address.ip() == Ipv4Addr::LOCALHOST && address.port() != 0)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "invalid egress proxy readiness"))?;
    Ok(address)
}

fn stop_proxy(child: &mut Child) {
    child.stdin.take();
    let deadline = Instant::now() + PROXY_SHUTDOWN_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) | Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn serve_runner(
    broker: &BrokerCore,
    control_listener: &UnixListener,
    runner: &mut Child,
    runner_process_id: u32,
) -> Result<(), Box<dyn Error>> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = crate::accept_runner_channel(runner, setup_deadline, "control", || {
        control_listener.accept().map(|(stream, _)| stream)
    })?;
    validate_peer_process(&control_stream, runner_process_id)?;
    let control_channel =
        UnixStreamHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline);
    crate::serve_runner(
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
