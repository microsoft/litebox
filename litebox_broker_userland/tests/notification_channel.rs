// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Error, ErrorKind, Result};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, PolicyEngine, PrincipalRights};
use litebox_broker_host::{ConnectionTermination, serve_connection};
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::channel::{
    HostControlChannel, HostNotificationChannel, HostReceive, LocalNotificationChannel,
    PeerCredential,
};
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
    BrokerResponse, EventReadinessNotification, EventRequest, EventResponse,
};
use litebox_broker_transport::unix_socket::{
    UnixStreamHostControlChannel, UnixStreamHostNotificationChannel, UnixStreamLocalControlChannel,
    UnixStreamLocalNotificationChannel,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn broker_sends_event_readiness_notification_over_userland_channel() {
    let control_socket_path = unique_socket_path("control");
    let notification_socket_path = unique_socket_path("notification");
    let broker = spawn_test_broker(
        control_socket_path.clone(),
        notification_socket_path.clone(),
    );

    let mut notifications = connect_notification_with_retry(&notification_socket_path).unwrap();
    let control_channel = connect_control_with_retry(&control_socket_path).unwrap();
    let mut local = BrokerLocal::negotiate(control_channel).unwrap();

    let handle = local.create_event_with_count(0).unwrap();
    let readiness = local.add_event(handle, 1).unwrap();
    assert_eq!(
        notifications.recv_notification().unwrap(),
        Some(BrokerNotification::EventReadiness(
            EventReadinessNotification { handle, readiness }
        ))
    );

    drop(local);
    broker.join();
}

fn spawn_test_broker(
    control_socket_path: PathBuf,
    notification_socket_path: PathBuf,
) -> TestBroker {
    let _ = std::fs::remove_file(&control_socket_path);
    let _ = std::fs::remove_file(&notification_socket_path);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let thread_control_socket_path = control_socket_path.clone();
    let thread_notification_socket_path = notification_socket_path.clone();
    let thread = std::thread::spawn(move || {
        let control_listener = UnixListener::bind(&thread_control_socket_path).unwrap();
        let notification_listener = UnixListener::bind(&thread_notification_socket_path).unwrap();
        control_listener.set_nonblocking(true).unwrap();
        notification_listener.set_nonblocking(true).unwrap();
        ready_tx.send(()).unwrap();

        let notification_stream = accept_with_retry(&notification_listener).unwrap();
        let control_stream = accept_with_retry(&control_listener).unwrap();
        let broker = BrokerCore::new(PolicyEngine::with_unauthenticated_rights(
            PrincipalRights::all(),
        ))
        .unwrap();
        let mut channel = NotifyingHostControlChannel {
            inner: UnixStreamHostControlChannel::from_accepted(control_stream),
            notifications: UnixStreamHostNotificationChannel::from_accepted(notification_stream),
            pending_add_handle: None,
        };

        assert_eq!(
            serve_connection(&broker, &mut channel).unwrap(),
            ConnectionTermination::PeerClosed
        );
    });

    ready_rx
        .recv_timeout(TEST_TIMEOUT)
        .expect("broker test host did not start");
    TestBroker {
        thread: Some(thread),
        control_socket_path,
        notification_socket_path,
    }
}

struct TestBroker {
    thread: Option<std::thread::JoinHandle<()>>,
    control_socket_path: PathBuf,
    notification_socket_path: PathBuf,
}

impl TestBroker {
    fn join(mut self) {
        self.thread
            .take()
            .expect("broker test host thread missing")
            .join()
            .expect("broker test host panicked");
    }

    fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.control_socket_path);
        let _ = std::fs::remove_file(&self.notification_socket_path);
    }
}

impl Drop for TestBroker {
    fn drop(&mut self) {
        self.cleanup();
    }
}

struct NotifyingHostControlChannel {
    inner: UnixStreamHostControlChannel,
    notifications: UnixStreamHostNotificationChannel,
    pending_add_handle: Option<ObjectHandle>,
}

impl HostControlChannel for NotifyingHostControlChannel {
    type Error = Error;

    fn peer_credential(&self) -> Result<PeerCredential> {
        self.inner.peer_credential()
    }

    fn recv_handshake_request(&mut self) -> Result<HostReceive<BrokerHandshakeRequest>> {
        self.inner.recv_handshake_request()
    }

    fn send_handshake_response(&mut self, response: &BrokerHandshakeResponse) -> Result<()> {
        self.inner.send_handshake_response(response)
    }

    fn recv_request(&mut self) -> Result<HostReceive<BrokerRequest>> {
        let request = self.inner.recv_request()?;
        self.pending_add_handle = match &request {
            HostReceive::Message(BrokerRequest::Event(EventRequest::Add(request))) => {
                Some(request.handle)
            }
            _ => None,
        };
        Ok(request)
    }

    fn send_response(&mut self, response: &BrokerResponse) -> Result<()> {
        if let (Some(handle), BrokerResponse::Event(EventResponse::Add(response))) =
            (self.pending_add_handle.take(), response)
        {
            self.notifications
                .send_notification(&BrokerNotification::EventReadiness(
                    EventReadinessNotification {
                        handle,
                        readiness: response.readiness,
                    },
                ))?;
        }
        self.inner.send_response(response)
    }
}

fn connect_control_with_retry(socket_path: &Path) -> Result<UnixStreamLocalControlChannel> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        match UnixStreamLocalControlChannel::connect_with_setup_deadline(socket_path, deadline) {
            Ok(channel) => return Ok(channel),
            Err(error) if retry_socket_connect(&error, deadline) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn connect_notification_with_retry(
    socket_path: &Path,
) -> Result<UnixStreamLocalNotificationChannel> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        match UnixStreamLocalNotificationChannel::connect(socket_path) {
            Ok(channel) => return Ok(channel),
            Err(error) if retry_socket_connect(&error, deadline) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn retry_socket_connect(error: &Error, deadline: Instant) -> bool {
    Instant::now() < deadline
        && matches!(
            error.kind(),
            ErrorKind::NotFound | ErrorKind::ConnectionRefused
        )
}

fn accept_with_retry(listener: &UnixListener) -> Result<UnixStream> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
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
        "litebox-broker-userland-notification-channel-{name}-{}-{nonce}.sock",
        std::process::id()
    ))
}
