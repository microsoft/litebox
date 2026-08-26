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
use litebox_broker_protocol::socket::{ReceiveFromFlags, SendFlags, SocketConnectionStatus};
use litebox_broker_transport::control_ring::ControlRing;
use litebox_broker_transport_linux_userland::unix_socket::UnixStreamLocalSetupChannel;

const RUNNER_ARGUMENT: &str = "broker-userland-test-runner";
const NETWORK_RUNNER_ARGUMENT: &str = "broker-userland-network-test-runner";
const BROKER_PROCESS_TIMEOUT: Duration = Duration::from_secs(30);

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
    // runner argv (`--unstable --broker-control-channel <path>`), which runs
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

    let gateway = std::net::Ipv4Addr::new(10, 0, 2, 1);
    let tcp_listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    let udp_socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    udp_socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let udp_port = udp_socket.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (_stream, peer_address) = tcp_listener.accept().unwrap();
        assert!(peer_address.ip().is_loopback());

        let mut request = [0; 16];
        let (received, source) = udp_socket.recv_from(&mut request).unwrap();
        assert_eq!(&request[..received], b"gateway request");
        udp_socket.send_to(b"gateway reply", source).unwrap();
    });
    let mut network_command = Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"));
    network_command
        .arg("--allow-tcp-destination")
        .arg(format!("{gateway}/32:{tcp_port}"))
        .arg("--allow-udp-destination")
        .arg(format!("{gateway}/32:{udp_port}"))
        .arg("--runner")
        .arg(std::env::current_exe().unwrap())
        .arg(NETWORK_RUNNER_ARGUMENT)
        .arg(tcp_port.to_string())
        .arg(udp_port.to_string());
    wait_for_broker(network_command);
    server.join().unwrap();
}

fn wait_for_broker(mut command: Command) {
    let mut broker = ChildGuard {
        child: command.spawn().unwrap(),
    };

    let deadline = Instant::now() + BROKER_PROCESS_TIMEOUT;
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
        Some(OsStr::new("--broker-control-channel"))
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
        assert_eq!(args.len(), 6, "unexpected runner arguments: {args:?}");
        let tcp_port = args[4].to_str().unwrap().parse::<u16>().unwrap();
        let udp_port = args[5].to_str().unwrap().parse::<u16>().unwrap();
        let gateway = std::net::Ipv4Addr::new(10, 0, 2, 1);
        let handle = local.create_tcp_socket().unwrap();
        let mut status = local
            .connect_socket(handle, std::net::SocketAddrV4::new(gateway, tcp_port))
            .unwrap()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while status == SocketConnectionStatus::Connecting && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
            status = local.socket_status(handle).unwrap().status;
        }
        assert_eq!(status, SocketConnectionStatus::Connected);
        local.close_object(handle).unwrap();

        let handle = local.create_udp_socket().unwrap();
        let request = b"gateway request";
        assert_eq!(
            local
                .send_to_socket(
                    handle,
                    SharedBufferDescriptor {
                        slot_index: SharedBufferSlotIndex(0),
                        length: request.len().try_into().unwrap(),
                    },
                    request,
                    SendFlags::NONE,
                    Some(std::net::SocketAddrV4::new(gateway, udp_port)),
                )
                .unwrap(),
            Ok(request.len())
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !local
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::READ)
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            local
                .check_readiness(handle)
                .unwrap()
                .contains(ReadinessFlags::READ),
            "timed out waiting for gateway UDP reply"
        );
        let mut reply = [0; 16];
        let received = local
            .receive_from_socket(
                handle,
                SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(1),
                    length: reply.len().try_into().unwrap(),
                },
                &mut reply,
                ReceiveFromFlags::NONE,
            )
            .unwrap()
            .unwrap();
        assert_eq!(&reply[..received.received as usize], b"gateway reply");
        assert_eq!(
            received.source_address,
            std::net::SocketAddrV4::new(gateway, udp_port)
        );
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
