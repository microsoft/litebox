// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::ReadinessState;
use litebox_broker_transport::unix_socket::UnixStreamLocalControlChannel;

#[test]
fn separate_process_broker_serves_event_object_requests() {
    let socket_path = SocketPathGuard::new(unique_socket_path());
    let mut child = ChildGuard::new(spawn_broker(socket_path.path()));
    let mut channel = connect_with_retry(socket_path.path()).unwrap();
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
    assert!(child.wait().unwrap().success());
}

fn spawn_broker(socket_path: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
        .arg("--socket")
        .arg(socket_path)
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

struct SocketPathGuard {
    path: PathBuf,
}

impl SocketPathGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
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

fn unique_socket_path() -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    env::temp_dir().join(format!(
        "litebox-broker-userland-{}-{now}.sock",
        std::process::id()
    ))
}
