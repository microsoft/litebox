// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::{OsStr, OsString};
use std::io::{ErrorKind, Read, Result, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use litebox_broker_core::test_support::TestBrokerCoreBuilder;
use litebox_broker_core::{ObjectRights, PolicyEngine};
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_buffer::{
    SHARED_BUFFER_POOL_SIZE, SharedBufferSequence, SharedBufferSlotIndex,
};
use litebox_broker_protocol::socket::{ReceiveFromFlags, SendFlags, SocketConnectionStatus};
use litebox_broker_transport::control_ring::ControlRing;
use litebox_broker_transport_linux_userland::unix_socket::UnixStreamLocalSetupChannel;
use litebox_broker_userland::runner::RunnerConfig;
use litebox_broker_userland::supervisor::RunnerSupervisor;

const RUNNER_ARGUMENT: &str = "broker-userland-test-runner";
const NETWORK_RUNNER_ARGUMENT: &str = "broker-userland-network-test-runner";
const SUPERVISOR_FIRST_RUNNER_ARGUMENT: &str = "broker-userland-supervisor-first-runner";
const SUPERVISOR_SECOND_RUNNER_ARGUMENT: &str = "broker-userland-supervisor-second-runner";
const BROKER_PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const SUPERVISOR_EXIT: u8 = 0;
const SUPERVISOR_CHECK_BROKER: u8 = 1;
const SUPERVISOR_BROKER_OK: u8 = 2;
const SUPERVISOR_FIRST_RUNNER: u8 = 3;
const SUPERVISOR_SECOND_RUNNER: u8 = 4;
const SUPERVISOR_FIRST_EXIT_CODE: i32 = 7;

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
    // `run_fake_runner`. After the fake runner finishes its broker requests,
    // the broker exits naturally when its sole runner and association drain.
    let test_executable = std::env::current_exe().unwrap();
    run_supervisor_test(&test_executable);

    let mut event_command = Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"));
    event_command
        .arg("--runner")
        .arg(&test_executable)
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
        .arg(test_executable)
        .arg(NETWORK_RUNNER_ARGUMENT)
        .arg(tcp_port.to_string())
        .arg(udp_port.to_string());
    wait_for_broker(network_command);
    server.join().unwrap();
}

fn run_supervisor_test(test_executable: &Path) {
    let coordinator = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    coordinator.set_nonblocking(true).unwrap();
    let coordinator_port = coordinator.local_addr().unwrap().port();
    let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_host_guaranteed_rights(
        ObjectRights::all(),
    ))
    .build()
    .unwrap();
    let runner_executable = test_executable.to_owned();
    let runner_config = |argument| {
        RunnerConfig::new(
            runner_executable.clone(),
            vec![
                OsString::from(argument),
                OsString::from(coordinator_port.to_string()),
            ],
        )
    };
    let runners = vec![
        runner_config(SUPERVISOR_FIRST_RUNNER_ARGUMENT),
        runner_config(SUPERVISOR_SECOND_RUNNER_ARGUMENT),
    ];
    let supervisor =
        std::thread::spawn(move || RunnerSupervisor::new(broker).run_to_completion(runners));

    let deadline = Instant::now() + BROKER_PROCESS_TIMEOUT;
    let mut first = None;
    let mut second = None;
    while (first.is_none() || second.is_none()) && Instant::now() < deadline {
        match coordinator.accept() {
            Ok((mut runner, _address)) => {
                runner
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                runner
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut registration = [0; 5];
                runner.read_exact(&mut registration).unwrap();
                let process_id = u32::from_ne_bytes(registration[1..].try_into().unwrap());
                match registration[0] {
                    SUPERVISOR_FIRST_RUNNER => {
                        assert!(first.replace((runner, process_id)).is_none());
                    }
                    SUPERVISOR_SECOND_RUNNER => {
                        assert!(second.replace((runner, process_id)).is_none());
                    }
                    runner => panic!("unexpected supervised runner {runner}"),
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("failed to accept supervised runner: {error}"),
        }
    }

    let (mut first, first_process_id) = first.expect("first supervised runner did not connect");
    let (mut second, second_process_id) = second.expect("second supervised runner did not connect");
    assert_ne!(first_process_id, second_process_id);

    first.write_all(&[SUPERVISOR_EXIT]).unwrap();
    let mut unexpected = [0];
    assert_eq!(first.read(&mut unexpected).unwrap(), 0);

    second.write_all(&[SUPERVISOR_CHECK_BROKER]).unwrap();
    let mut response = [0];
    second.read_exact(&mut response).unwrap();
    assert_eq!(response[0], SUPERVISOR_BROKER_OK);
    second.write_all(&[SUPERVISOR_EXIT]).unwrap();
    assert_eq!(second.read(&mut unexpected).unwrap(), 0);

    let mut runner_results = supervisor.join().unwrap().into_iter();
    assert_eq!(
        runner_results.next().unwrap().unwrap().code(),
        Some(SUPERVISOR_FIRST_EXIT_CODE)
    );
    assert!(runner_results.next().unwrap().unwrap().success());
    assert!(runner_results.next().is_none());
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

    let runner_argument = args.get(3).and_then(|argument| argument.to_str());
    if matches!(
        runner_argument,
        Some(SUPERVISOR_FIRST_RUNNER_ARGUMENT | SUPERVISOR_SECOND_RUNNER_ARGUMENT)
    ) {
        assert_eq!(args.len(), 5, "unexpected runner arguments: {args:?}");
        let coordinator_port = args[4].to_str().unwrap().parse::<u16>().unwrap();
        let mut coordinator =
            TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, coordinator_port)).unwrap();
        coordinator
            .write_all(&[
                if runner_argument == Some(SUPERVISOR_FIRST_RUNNER_ARGUMENT) {
                    SUPERVISOR_FIRST_RUNNER
                } else {
                    SUPERVISOR_SECOND_RUNNER
                },
            ])
            .unwrap();
        coordinator
            .write_all(&local.process_id().0.to_ne_bytes())
            .unwrap();

        let mut command = [0];
        coordinator.read_exact(&mut command).unwrap();
        if runner_argument == Some(SUPERVISOR_FIRST_RUNNER_ARGUMENT) {
            assert_eq!(command[0], SUPERVISOR_EXIT);
            std::process::exit(SUPERVISOR_FIRST_EXIT_CODE);
        }

        assert_eq!(command[0], SUPERVISOR_CHECK_BROKER);
        let handle = local.create_event_with_count(0).unwrap();
        local.close_object(handle).unwrap();
        coordinator.write_all(&[SUPERVISOR_BROKER_OK]).unwrap();
        coordinator.read_exact(&mut command).unwrap();
        assert_eq!(command[0], SUPERVISOR_EXIT);
        return;
    }

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
                    SharedBufferSequence::new(
                        &[SharedBufferSlotIndex(0)],
                        request.len().try_into().unwrap(),
                    )
                    .unwrap(),
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
                SharedBufferSequence::new(
                    &[SharedBufferSlotIndex(1)],
                    reply.len().try_into().unwrap(),
                )
                .unwrap(),
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
    let write_buffer =
        SharedBufferSequence::new(&[SharedBufferSlotIndex(0)], data.len().try_into().unwrap())
            .unwrap();
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
            SharedBufferSequence::new(
                &[SharedBufferSlotIndex(1)],
                received.len().try_into().unwrap(),
            )
            .unwrap(),
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
