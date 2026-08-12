// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::{OsStr, OsString};
use std::io::{ErrorKind, Result};
use std::path::Path;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_buffer::{
    SHARED_BUFFER_POOL_SIZE, SharedBufferDescriptor, SharedBufferSlotIndex,
};
use litebox_broker_transport::control_ring::ControlRing;
use litebox_broker_transport_linux_userland::unix_socket::UnixStreamLocalSetupChannel;

const RUNNER_ARGUMENT: &str = "broker-userland-test-runner";
const NETWORK_RUNNER_ARGUMENT: &str = "broker-userland-network-test-runner";

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args
        .first()
        .is_some_and(|arg| arg == OsStr::new("--unstable"))
    {
        run_fake_runner(&args);
    } else {
        run_parent_test();
    }
}

fn run_parent_test() {
    // This custom-harness integration test uses its own executable as the broker's
    // runner. Cargo starts this executable without broker args, so it runs the
    // parent path here. The broker then starts the same executable with the real
    // runner argv (`--unstable --broker-control-socket <path>`), which runs
    // `run_fake_runner`. After
    // the fake runner finishes its broker requests, it terminates the broker
    // parent process; this lets the test exercise the long-running broker
    // without a test-only shutdown path.
    let mut event_command = Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"));
    event_command
        .arg("--runner")
        .arg(std::env::current_exe().unwrap())
        .arg(RUNNER_ARGUMENT);
    wait_for_broker(event_command);

    let Some((host_address, listener)) = non_loopback_listener() else {
        return;
    };
    let port = listener.local_addr().unwrap().port();
    let mut network_command = Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"));
    network_command
        .arg("--allow-tcp-destination")
        .arg(format!("{host_address}/32:{port}"))
        .arg("--runner")
        .arg(std::env::current_exe().unwrap())
        .arg(NETWORK_RUNNER_ARGUMENT)
        .arg(host_address.to_string())
        .arg(port.to_string());
    wait_for_broker(network_command);

    let (_stream, peer_address) = listener.accept().unwrap();
    assert_eq!(peer_address.ip(), host_address);
}

fn non_loopback_listener() -> Option<(std::net::Ipv4Addr, std::net::TcpListener)> {
    let probe = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    if let Err(error) = probe.connect((std::net::Ipv4Addr::new(192, 0, 2, 1), 9)) {
        eprintln!("skipping non-loopback broker TCP test: IPv4 route unavailable: {error}");
        return None;
    }
    let std::net::IpAddr::V4(host_address) = probe.local_addr().unwrap().ip() else {
        unreachable!("an IPv4 route probe must select an IPv4 source address");
    };
    if host_address.is_loopback() || host_address.is_unspecified() {
        eprintln!(
            "skipping non-loopback broker TCP test: route selected unusable address {host_address}"
        );
        return None;
    }
    match std::net::TcpListener::bind((host_address, 0)) {
        Ok(listener) => Some((host_address, listener)),
        Err(error) => {
            eprintln!("skipping non-loopback broker TCP test: cannot bind {host_address}: {error}");
            None
        }
    }
}

fn wait_for_broker(mut command: Command) {
    let mut broker = ChildGuard {
        child: command.spawn().unwrap(),
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(status) = broker.child.try_wait().unwrap() {
            assert!(status.success(), "broker failed with {status}");
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for broker to stop");
}

fn run_fake_runner(args: &[OsString]) {
    assert_eq!(
        args.first().map(OsString::as_os_str),
        Some(OsStr::new("--unstable"))
    );
    assert_eq!(
        args.get(1).map(OsString::as_os_str),
        Some(OsStr::new("--broker-control-socket"))
    );

    let control_socket_path = args.get(2).unwrap();
    let setup_channel = connect_control_with_retry(Path::new(control_socket_path)).unwrap();
    let (local, ()) = BrokerLocal::negotiate(setup_channel, |mut setup| {
        let shared_memory = setup.receive_memfd(
            SHARED_BUFFER_POOL_SIZE,
            Some(Instant::now() + Duration::from_secs(5)),
        )?;
        let control_memory =
            setup.receive_control_ring(Some(Instant::now() + Duration::from_secs(5)))?;
        let control_ring = ControlRing::new(control_memory).map_err(|error| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid test control ring: {error:?}"),
            )
        })?;
        let (call_channel, _notifications, _shutdown) = setup.into_active(control_ring, || {})?;
        Ok((call_channel, Arc::new(shared_memory), ()))
    })
    .unwrap();
    let local = Arc::new(local);

    if args.get(3).and_then(|argument| argument.to_str()) == Some(NETWORK_RUNNER_ARGUMENT) {
        use litebox_broker_protocol::socket::SocketConnectionStatus;

        assert_eq!(args.len(), 6, "unexpected runner arguments: {args:?}");
        let address = args[4]
            .to_str()
            .unwrap()
            .parse::<std::net::Ipv4Addr>()
            .unwrap();
        let port = args[5].to_str().unwrap().parse::<u16>().unwrap();
        let handle = local.create_tcp_socket().unwrap();
        let mut status = local
            .connect_socket(handle, std::net::SocketAddrV4::new(address, port))
            .unwrap()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while status == SocketConnectionStatus::Connecting && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
            status = local.socket_status(handle).unwrap().status;
        }
        assert_eq!(status, SocketConnectionStatus::Connected);
        local.close_object(handle).unwrap();
        return;
    }
    assert_eq!(
        args.get(3).map(OsString::as_os_str),
        Some(OsStr::new(RUNNER_ARGUMENT))
    );
    assert_eq!(args.len(), 4, "unexpected runner arguments: {args:?}");

    let start = Arc::new(std::sync::Barrier::new(17));
    let callers = (0..16)
        .map(|initial_count| {
            let local = Arc::clone(&local);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                local.create_event_with_count(initial_count).unwrap()
            })
        })
        .collect::<Vec<_>>();
    start.wait();
    let mut concurrent_handles = callers
        .into_iter()
        .map(|caller| caller.join().unwrap())
        .collect::<Vec<_>>();
    concurrent_handles.sort();
    concurrent_handles.dedup();
    assert_eq!(concurrent_handles.len(), 16);

    let handle = local.create_event_with_count(0).unwrap();
    assert_eq!(
        local.check_readiness(handle).unwrap(),
        ReadinessFlags::WRITE
    );

    let readiness = ReadinessFlags::READ | ReadinessFlags::WRITE;
    assert_eq!(local.add_event(handle, 1).unwrap(), readiness);

    assert_eq!(
        local.check_readiness(handle).unwrap(),
        ReadinessFlags::READ | ReadinessFlags::WRITE
    );

    let pipe = local.create_pipe(64, 16).unwrap();
    let data = b"shared pipe data";
    let write_buffer = SharedBufferDescriptor {
        slot_index: SharedBufferSlotIndex(0),
        length: data.len().try_into().unwrap(),
    };
    assert_eq!(
        local
            .write_pipe(pipe.write_handle, write_buffer, data)
            .unwrap(),
        data.len()
    );
    let mut received = [0; 16];
    let read = local
        .read_pipe(
            pipe.read_handle,
            SharedBufferDescriptor {
                slot_index: SharedBufferSlotIndex(1),
                length: received.len().try_into().unwrap(),
            },
            &mut received,
        )
        .unwrap();
    assert_eq!(&received[..read], data);
    drop(local);
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_status))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn connect_control_with_retry(socket_path: &Path) -> Result<UnixStreamLocalSetupChannel> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStreamLocalSetupChannel::connect_with_setup_deadline(socket_path, deadline) {
            Ok(channel) => return Ok(channel),
            Err(error) if Instant::now() < deadline => {
                if error.kind() != ErrorKind::NotFound
                    && error.kind() != ErrorKind::ConnectionRefused
                {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}
