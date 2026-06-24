// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::ReadinessState;
use litebox_broker_transport::unix_socket::UnixStreamLocalControlChannel;

#[test]
fn separate_process_broker_spawns_runner_and_serves_until_stopped() {
    let runner = TestRunnerScript::new();
    let mut broker = ChildGuard::new(spawn_broker(&runner));

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if runner.status_path.exists() {
            let status = fs::read_to_string(&runner.status_path).unwrap();
            assert_eq!(status.trim(), "0");
            return;
        }
        if let Some(status) = broker.try_wait().unwrap() {
            panic!("broker exited before runner completed: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for test runner to complete");
}

#[test]
fn broker_test_runner_child() {
    let Ok(socket_path) = env::var("LITEBOX_BROKER_TEST_SOCKET") else {
        return;
    };
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
}

fn spawn_broker(runner: &TestRunnerScript) -> Child {
    Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
        .arg("--runner")
        .arg(&runner.path)
        .arg("broker_test_runner_child")
        .env("LITEBOX_BROKER_TEST_EXE", env::current_exe().unwrap())
        .env("LITEBOX_BROKER_TEST_STATUS", &runner.status_path)
        .spawn()
        .unwrap()
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

struct TestRunnerScript {
    _dir: tempfile::TempDir,
    path: PathBuf,
    status_path: PathBuf,
}

impl TestRunnerScript {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("litebox-broker-userland-test-")
            .tempdir()
            .unwrap();
        let path = dir.path().join("test-runner.sh");
        let status_path = dir.path().join("test-runner.status");
        fs::write(
            &path,
            b"#!/bin/sh
[ \"$1\" = \"--unstable\" ] || exit 1
[ \"$2\" = \"--broker-socket\" ] || exit 1
socket=$3
shift 3
LITEBOX_BROKER_TEST_SOCKET=\"$socket\" \"$LITEBOX_BROKER_TEST_EXE\" \"$@\" --exact --nocapture
echo \"$?\" > \"$LITEBOX_BROKER_TEST_STATUS\"
",
        )
        .unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        Self {
            _dir: dir,
            path,
            status_path,
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
