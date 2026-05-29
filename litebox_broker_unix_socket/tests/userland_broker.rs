// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use litebox_broker_client::BrokerClient;
use litebox_broker_protocol::{ReadinessState, WaitOutcome};
use litebox_broker_server::SUPPORTED_PROTOCOL_VERSION;
use litebox_broker_unix_socket::UnixStreamClientTransport;

#[test]
fn separate_process_broker_serves_event_object_requests() {
    let socket_path = unique_socket_path();
    let mut child = spawn_broker(&socket_path);
    let transport = connect_with_retry(&socket_path).unwrap();
    let mut client = BrokerClient::new(transport);

    assert_eq!(client.negotiate().unwrap(), SUPPORTED_PROTOCOL_VERSION);

    let handle = client.create_event().unwrap();
    assert_eq!(
        client.wait_event(handle).unwrap(),
        WaitOutcome::WouldBlock(ReadinessState::new(false, 0))
    );

    assert_eq!(
        client.signal_event(handle).unwrap(),
        ReadinessState::new(true, 1)
    );

    assert_eq!(
        client.wait_event(handle).unwrap(),
        WaitOutcome::Ready(ReadinessState::new(true, 1))
    );

    drop(client);
    assert!(child.wait().unwrap().success());
    let _ = fs::remove_file(socket_path);
}

fn spawn_broker(socket_path: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_litebox-broker-userland"))
        .arg("--socket")
        .arg(socket_path)
        .spawn()
        .unwrap()
}

fn connect_with_retry(socket_path: &Path) -> io::Result<UnixStreamClientTransport> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStreamClientTransport::connect(socket_path) {
            Ok(transport) => return Ok(transport),
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
