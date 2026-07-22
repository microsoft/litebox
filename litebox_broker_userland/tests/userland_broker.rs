// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::{OsStr, OsString};
use std::io::{ErrorKind, Result};
use std::path::Path;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::pipe::PIPE_TRANSFER_BUFFER_SIZE;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_transport::unix_socket::{
    UnixStreamLocalControlChannel, UnixStreamLocalNotificationChannel,
};

const RUNNER_ARGUMENT: &str = "broker-userland-test-runner";

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
    // runner argv (`--unstable --broker-control-socket <path>
    // --broker-notification-socket <path>`), which runs `run_fake_runner`. After
    // the fake runner finishes its broker requests, it terminates the broker
    // parent process; this lets the test exercise the long-running broker
    // without a test-only shutdown path.
    let mut broker = ChildGuard {
        child: Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
            .arg("--runner")
            .arg(std::env::current_exe().unwrap())
            .arg(RUNNER_ARGUMENT)
            .spawn()
            .unwrap(),
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
    assert_eq!(
        args.get(3).map(OsString::as_os_str),
        Some(OsStr::new("--broker-notification-socket"))
    );
    assert_eq!(
        args.get(5).map(OsString::as_os_str),
        Some(OsStr::new(RUNNER_ARGUMENT))
    );
    assert_eq!(args.len(), 6, "unexpected runner arguments: {args:?}");

    let control_socket_path = args.get(2).unwrap();
    let notification_socket_path = args.get(4).unwrap();
    let control_channel = connect_control_with_retry(Path::new(control_socket_path)).unwrap();
    let _notification_channel =
        connect_notification_with_retry(Path::new(notification_socket_path)).unwrap();
    let local = BrokerLocal::negotiate(control_channel, |channel| {
        let shared_memory = channel.receive_memfd(
            PIPE_TRANSFER_BUFFER_SIZE,
            Some(Instant::now() + Duration::from_secs(5)),
        )?;
        let _cancellation = channel.activate(|| {})?;
        Ok(Arc::new(shared_memory))
    })
    .unwrap();

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
    assert_eq!(
        local.write_pipe(pipe.write_handle, data).unwrap(),
        data.len()
    );
    assert_eq!(
        local
            .read_pipe(pipe.read_handle, data.len().try_into().unwrap())
            .unwrap(),
        data
    );
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

fn connect_control_with_retry(socket_path: &Path) -> Result<UnixStreamLocalControlChannel> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStreamLocalControlChannel::connect_with_setup_deadline(socket_path, deadline) {
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

fn connect_notification_with_retry(
    socket_path: &Path,
) -> Result<UnixStreamLocalNotificationChannel> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStreamLocalNotificationChannel::connect(socket_path) {
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
