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
fn separate_process_broker_spawns_runner_and_serves_event_object_requests() {
    let runner = TestRunnerScript::new();
    let mut child = ChildGuard::new(spawn_broker(runner.path()));

    assert!(child.wait().unwrap().success());
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

fn spawn_broker(runner: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
        .arg("--runner")
        .arg(runner)
        .arg("broker-test-runner-child")
        .env("LITEBOX_BROKER_TEST_EXE", env::current_exe().unwrap())
        .spawn()
        .unwrap()
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        let status = self.child.as_mut().expect("child process missing").wait();
        if status.is_ok() {
            self.child = None;
        }
        status
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            match child.try_wait() {
                Ok(Some(_status)) => {}
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(_error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
}

struct TestRunnerScript {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl TestRunnerScript {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("litebox-broker-userland-test-")
            .tempdir()
            .unwrap();
        let path = dir.path().join("test-runner.sh");
        fs::write(
            &path,
            b"#!/bin/sh
socket=
while [ \"$#\" -gt 0 ]; do
    case \"$1\" in
        --broker-socket)
            socket=$2
            shift 2
            ;;
        --unstable)
            shift
            ;;
        *)
            shift
            ;;
    esac
done
LITEBOX_BROKER_TEST_SOCKET=\"$socket\" exec \"$LITEBOX_BROKER_TEST_EXE\" broker_test_runner_child --exact --nocapture
",
        )
        .unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        Self { _dir: dir, path }
    }

    fn path(&self) -> &Path {
        &self.path
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
