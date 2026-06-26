// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::{OsStr, OsString};
use std::io::{Error, ErrorKind, Result};
use std::os::unix::net::UnixListener;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::channel::{HostNotificationChannel, LocalNotificationChannel};
use litebox_broker_protocol::event::ReadinessState;
use litebox_broker_protocol::message::{BrokerNotification, EventReadinessNotification};
use litebox_broker_transport::unix_socket::{
    UnixStreamHostNotificationChannel, UnixStreamLocalControlChannel,
    UnixStreamLocalNotificationChannel,
};

const RUNNER_ARGUMENT: &str = "broker-userland-test-runner";
const NOTIFICATION_SOCKET_ARGUMENT: &str = "--notification-socket";

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
    // runner argv (`--unstable --broker-socket <path>`), which runs `run_fake_runner`.
    // After the fake runner finishes its broker requests, it terminates the broker
    // parent process; this lets the test exercise the long-running broker without a
    // test-only shutdown path.
    let notification_socket_path = unique_socket_path("notification");
    let notification_sender = spawn_notification_sender(notification_socket_path.clone());
    let mut broker = ChildGuard {
        child: Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
            .arg("--runner")
            .arg(std::env::current_exe().unwrap())
            .arg(RUNNER_ARGUMENT)
            .arg(NOTIFICATION_SOCKET_ARGUMENT)
            .arg(&notification_socket_path)
            .spawn()
            .unwrap(),
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(status) = broker.child.try_wait().unwrap() {
            assert_eq!(status.signal(), Some(libc::SIGTERM));
            notification_sender.join().unwrap();
            let _ = std::fs::remove_file(&notification_socket_path);
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    notification_sender.join().unwrap();
    let _ = std::fs::remove_file(&notification_socket_path);
    panic!("timed out waiting for broker to stop");
}

fn run_fake_runner(args: &[OsString]) {
    assert_eq!(
        args.first().map(OsString::as_os_str),
        Some(OsStr::new("--unstable"))
    );
    assert_eq!(
        args.get(1).map(OsString::as_os_str),
        Some(OsStr::new("--broker-socket"))
    );
    assert_eq!(
        args.get(3).map(OsString::as_os_str),
        Some(OsStr::new(RUNNER_ARGUMENT))
    );
    assert_eq!(
        args.get(4).map(OsString::as_os_str),
        Some(OsStr::new(NOTIFICATION_SOCKET_ARGUMENT))
    );
    assert_eq!(args.len(), 6, "unexpected runner arguments: {args:?}");

    let socket_path = args.get(2).unwrap();
    let channel = connect_with_retry(Path::new(socket_path)).unwrap();
    let mut local = BrokerLocal::negotiate(channel).unwrap();

    let handle = local.create_event_with_count(0).unwrap();
    assert_eq!(
        local.wait_event(handle).unwrap(),
        ReadinessState {
            read_ready: false,
            write_ready: true,
        }
    );

    assert_eq!(
        local.add_event(handle, 1).unwrap(),
        ReadinessState {
            read_ready: true,
            write_ready: true,
        }
    );

    assert_eq!(
        local.wait_event(handle).unwrap(),
        ReadinessState {
            read_ready: true,
            write_ready: true,
        }
    );
    drop(local);

    let notification_socket_path = args.get(5).unwrap();
    let mut notifications = connect_notification_with_retry(Path::new(notification_socket_path))
        .expect("failed to connect notification channel");
    assert_eq!(
        notifications.recv_notification().unwrap(),
        Some(expected_notification())
    );

    // SAFETY: `getppid` takes no pointer arguments and has no Rust-side aliasing requirements.
    let broker_pid = unsafe { libc::getppid() };
    // SAFETY: `broker_pid` is the runner's parent process and `SIGTERM` is a valid signal number.
    let kill_result = unsafe { libc::kill(broker_pid, libc::SIGTERM) };
    assert_eq!(
        kill_result,
        0,
        "failed to stop broker: {}",
        Error::last_os_error()
    );
}

fn spawn_notification_sender(socket_path: PathBuf) -> std::thread::JoinHandle<()> {
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();

    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("failed to accept notification connection: {error}"),
            }
        };
        let mut channel = UnixStreamHostNotificationChannel::from_accepted(stream);
        channel.send_notification(&expected_notification()).unwrap();
    })
}

fn expected_notification() -> BrokerNotification {
    BrokerNotification::EventReadiness(EventReadinessNotification {
        handle: ObjectHandle(7),
        readiness: ReadinessState {
            read_ready: true,
            write_ready: false,
        },
    })
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

fn connect_with_retry(socket_path: &Path) -> Result<UnixStreamLocalControlChannel> {
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

fn unique_socket_path(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "litebox-broker-userland-{name}-{}-{nonce}.sock",
        std::process::id()
    ))
}
