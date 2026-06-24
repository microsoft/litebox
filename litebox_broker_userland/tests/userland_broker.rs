// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::ReadinessState;
use litebox_broker_transport::unix_socket::UnixStreamLocalControlChannel;

#[test]
fn separate_process_broker_spawns_runner_and_serves_until_stopped() {
    // This test uses a shell adapter as the broker's runner because the real broker
    // passes the socket path with runner CLI flags, while the Rust test binary only
    // understands libtest arguments. The adapter validates the broker-supplied
    // `--broker-socket` argv, converts it to a test-only environment variable, and
    // execs this same test binary's `broker_test_runner_child` test. Once the child
    // test has connected and completed its broker requests, it terminates the broker
    // parent process. The parent test only waits for that broker exit so the
    // long-running broker does not need a test-only shutdown path.
    let dir = tempfile::Builder::new()
        .prefix("litebox-broker-userland-test-")
        .tempdir()
        .unwrap();
    let runner_path = dir.path().join("test-runner.sh");
    fs::write(
        &runner_path,
        b"#!/bin/sh
[ \"$1\" = \"--unstable\" ] || exit 1
[ \"$2\" = \"--broker-socket\" ] || exit 1
socket=$3
shift 3
LITEBOX_BROKER_USERLAND_TEST_SOCKET=\"$socket\" exec \"$@\" --exact --nocapture
",
    )
    .unwrap();
    let mut permissions = fs::metadata(&runner_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&runner_path, permissions).unwrap();

    let mut broker = ChildGuard::new(
        Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
            .arg("--runner")
            .arg(&runner_path)
            .arg(env::current_exe().unwrap())
            .arg("broker_test_runner_child")
            .env("LITEBOX_BROKER_USERLAND_TEST_RUNNER", "1")
            .spawn()
            .unwrap(),
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(status) = broker.try_wait().unwrap() {
            assert_eq!(status.signal(), Some(libc::SIGTERM));
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for broker to stop");
}

#[test]
fn broker_test_runner_child() {
    if env::var_os("LITEBOX_BROKER_USERLAND_TEST_RUNNER").is_none() {
        return;
    }
    let socket_path = env::var("LITEBOX_BROKER_USERLAND_TEST_SOCKET").unwrap();
    let mut channel = connect_with_retry(Path::new(&socket_path)).unwrap();
    channel
        .set_io_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut local = BrokerLocal::negotiate(channel).unwrap();

    let handle = local.create_event().unwrap();
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
    // SAFETY: `getppid` takes no pointer arguments and has no Rust-side aliasing requirements.
    let broker_pid = unsafe { libc::getppid() };
    // SAFETY: `broker_pid` is the runner's parent process and `SIGTERM` is a valid signal number.
    let kill_result = unsafe { libc::kill(broker_pid, libc::SIGTERM) };
    assert_eq!(
        kill_result,
        0,
        "failed to stop broker: {}",
        io::Error::last_os_error()
    );
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_status))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn connect_with_retry(socket_path: &Path) -> io::Result<UnixStreamLocalControlChannel> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStreamLocalControlChannel::connect(socket_path) {
            Ok(channel) => return Ok(channel),
            Err(error) if Instant::now() < deadline => {
                if error.kind() != io::ErrorKind::NotFound
                    && error.kind() != io::ErrorKind::ConnectionRefused
                {
                    return Err(error);
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}
