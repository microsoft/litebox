// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::ReadinessState;
use litebox_broker_transport::unix_socket::UnixStreamLocalControlChannel;

#[test]
fn separate_process_broker_spawns_runner_and_serves_until_stopped() {
    let dir = tempfile::Builder::new()
        .prefix("litebox-broker-userland-test-")
        .tempdir()
        .unwrap();
    let status_path = dir.path().join("test-runner.status");

    let mut broker = ChildGuard::new(
        Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
            .arg("--runner")
            .arg(env::current_exe().unwrap())
            .arg("broker_test_runner_child")
            .arg("--exact")
            .arg("--nocapture")
            .env("LITEBOX_BROKER_TEST_STATUS", &status_path)
            .spawn()
            .unwrap(),
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if status_path.exists() {
            let status = fs::read_to_string(&status_path).unwrap();
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
    let Some(status_path) = env::var_os("LITEBOX_BROKER_TEST_STATUS") else {
        return;
    };
    let result = std::panic::catch_unwind(|| {
        let socket_path = env::var("LITEBOX_BROKER_SOCKET").unwrap();
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
    });
    fs::write(&status_path, if result.is_ok() { "0" } else { "101" }).unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
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
