// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    os::fd::{AsFd, AsRawFd, RawFd},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_protocol::message::BrokerNotification;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::control_ring::{CONTROL_RING_MEMORY_SIZE, ControlRing};
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
    UnixControlRingLocalShutdown, UnixStreamLocalSetupChannel,
};

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_millis(20);

pub(crate) struct BrokerConnection {
    pub(crate) local: BrokerLocal<UnixControlRingLocalCallChannel>,
    pub(crate) notifications: BrokerNotifications<UnixControlRingLocalNotificationChannel>,
    pub(crate) coordinator: Arc<BrokerAssociationFailureCoordinator>,
    pub(crate) positional_io_fds: [RawFd; 2],
    pub(crate) shutdown_fd: RawFd,
}

pub(crate) fn connect(control_socket_path: &Path) -> Result<BrokerConnection> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let setup_channel = connect_with_retry(
        control_socket_path,
        setup_deadline,
        "timed out connecting to broker",
        |path, deadline| UnixStreamLocalSetupChannel::connect_with_setup_deadline(path, deadline),
    )
    .with_context(|| {
        format!(
            "failed to connect to broker at {}",
            control_socket_path.display()
        )
    })?;
    let association_coordinator = Arc::new(BrokerAssociationFailureCoordinator::new());
    let (local, (notification_channel, positional_io_fds, shutdown_fd)) =
        BrokerLocal::negotiate(setup_channel, |mut setup| {
            let shared_memory =
                setup.receive_memfd(SHARED_BUFFER_POOL_SIZE, Some(setup_deadline))?;
            let control_memory =
                setup.receive_memfd(CONTROL_RING_MEMORY_SIZE, Some(setup_deadline))?;
            let positional_io_fds = [
                shared_memory.as_fd().as_raw_fd(),
                control_memory.as_fd().as_raw_fd(),
            ];
            let control_ring = ControlRing::new(control_memory).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid broker control ring: {error:?}"),
                )
            })?;
            let weak_association_coordinator = Arc::downgrade(&association_coordinator);
            let (call_channel, notification_channel, association_shutdown) =
                setup.into_active(control_ring, move || {
                    if let Some(association_coordinator) = weak_association_coordinator.upgrade() {
                        association_coordinator.report_failure();
                    }
                })?;
            let shutdown_fd = association_shutdown.as_fd().as_raw_fd();
            association_coordinator.install_shutdown(association_shutdown)?;
            Ok((
                call_channel,
                Arc::new(shared_memory),
                (notification_channel, positional_io_fds, shutdown_fd),
            ))
        })
        .context("broker negotiation failed")?;
    Ok(BrokerConnection {
        local,
        notifications: BrokerNotifications::new(notification_channel),
        coordinator: association_coordinator,
        positional_io_fds,
        shutdown_fd,
    })
}

pub(crate) fn start_notification_receiver(
    mut notifications: BrokerNotifications<UnixControlRingLocalNotificationChannel>,
    association_coordinator: Arc<BrokerAssociationFailureCoordinator>,
    dispatch_notification: impl Fn(BrokerNotification) + Send + 'static,
) -> Result<()> {
    std::thread::Builder::new()
        .name("litebox-broker-notifications".to_owned())
        .spawn(move || {
            let receive_error = loop {
                match notifications.recv_notification() {
                    Ok(Some(notification)) => dispatch_notification(notification),
                    Ok(None) => break None,
                    Err(error) => break Some(error),
                }
            };
            association_coordinator.report_failure();
            if let Some(error) = receive_error {
                eprintln!("failed to receive broker notification: {error}");
            }
        })
        .context("failed to start broker notification receiver")?;
    Ok(())
}

pub(crate) struct BrokerAssociationFailureCoordinator {
    failed: AtomicBool,
    shutdown: Mutex<Option<UnixControlRingLocalShutdown>>,
    dispatch_failure: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl BrokerAssociationFailureCoordinator {
    fn new() -> Self {
        Self {
            failed: AtomicBool::new(false),
            shutdown: Mutex::new(None),
            dispatch_failure: Mutex::new(None),
        }
    }

    fn install_shutdown(&self, shutdown: UnixControlRingLocalShutdown) -> std::io::Result<()> {
        let mut installed = self
            .shutdown
            .lock()
            .expect("broker association shutdown mutex poisoned");
        assert!(
            installed.is_none(),
            "broker association shutdown already installed"
        );
        if self.failed.load(Ordering::Acquire) {
            shutdown.shutdown()?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "broker association failed during activation",
            ));
        }
        *installed = Some(shutdown);
        Ok(())
    }

    pub(crate) fn install_dispatch(&self, dispatch_failure: impl FnOnce() + Send + 'static) {
        let mut installed = self
            .dispatch_failure
            .lock()
            .expect("broker failure dispatch mutex poisoned");
        assert!(
            installed.is_none(),
            "broker failure dispatch already installed"
        );
        if self.failed.load(Ordering::Acquire) {
            drop(installed);
            dispatch_failure();
        } else {
            *installed = Some(Box::new(dispatch_failure));
        }
    }

    fn report_failure(&self) {
        if self.failed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(shutdown_handle) = self
            .shutdown
            .lock()
            .expect("broker association shutdown mutex poisoned")
            .as_ref()
            && let Err(error) = shutdown_handle.shutdown()
        {
            eprintln!("failed to shut down broker association: {error}");
        }
        let dispatch_failure = self
            .dispatch_failure
            .lock()
            .expect("broker failure dispatch mutex poisoned")
            .take();
        if let Some(dispatch_failure) = dispatch_failure {
            dispatch_failure();
        }
    }
}

fn connect_with_retry<Channel>(
    socket_path: &Path,
    setup_deadline: Instant,
    timeout_message: &'static str,
    mut connect: impl FnMut(&Path, Instant) -> std::io::Result<Channel>,
) -> Result<Channel> {
    loop {
        match connect(socket_path, setup_deadline) {
            Ok(channel) => return Ok(channel),
            Err(error) => {
                if Instant::now() >= setup_deadline {
                    return Err(error).context(timeout_message);
                }
            }
        }
        let remaining = setup_deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(RETRY_DELAY.min(remaining));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::message::{BrokerNotification, ReadinessNotification};
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_transport::channel::{
        HostNotificationChannel, HostReceive, HostSetupChannel, LocalSetupChannel,
    };
    use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
    use litebox_broker_transport_linux_userland::unix_socket::{
        UnixControlRingHostNotificationChannel, UnixControlRingHostRequestSource,
        UnixControlRingHostResponseSink, UnixControlRingHostShutdown, UnixStreamHostSetupChannel,
    };
    use litebox_broker_transport_linux_userland::unix_socket::{
        UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
        UnixControlRingLocalShutdown, UnixStreamLocalSetupChannel,
    };
    use std::io::ErrorKind;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;

    fn negotiate_control_pair(
        local_stream: UnixStream,
        host_stream: UnixStream,
    ) -> (UnixStreamLocalSetupChannel, UnixStreamHostSetupChannel) {
        let mut local = UnixStreamLocalSetupChannel::from_connected(local_stream);
        let mut host = UnixStreamHostSetupChannel::from_accepted(host_stream);
        let request = litebox_broker_protocol::message::BrokerHandshakeRequest {
            protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
        };
        local.send_handshake_request(&request).unwrap();
        assert_eq!(
            host.recv_handshake_request().unwrap(),
            HostReceive::Message(request)
        );
        host.send_handshake_response(
            &litebox_broker_protocol::message::BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
            },
        )
        .unwrap();
        assert!(matches!(
            local.recv_handshake_response().unwrap(),
            Some(litebox_broker_protocol::message::BrokerHandshakeResponse::Negotiated { .. })
        ));
        (local, host)
    }

    fn activate_control_channel(
        setup: UnixStreamLocalSetupChannel,
        host_channel: UnixStreamHostSetupChannel,
        association_coordinator: &Arc<BrokerAssociationFailureCoordinator>,
    ) -> (
        UnixControlRingLocalCallChannel,
        UnixControlRingLocalShutdown,
        UnixControlRingLocalNotificationChannel,
        UnixControlRingHostRequestSource,
        UnixControlRingHostResponseSink,
        UnixControlRingHostNotificationChannel,
        UnixControlRingHostShutdown,
    ) {
        let local_memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
        let host_memory = MemfdSharedMemory::from_received_fd(
            local_memory.as_fd().try_clone_to_owned().unwrap(),
            CONTROL_RING_MEMORY_SIZE,
        )
        .unwrap();
        let local_ring = ControlRing::new(local_memory).unwrap();
        let host_ring = ControlRing::new(host_memory).unwrap();
        let host_activation =
            std::thread::spawn(move || host_channel.into_active(host_ring).unwrap());
        let weak_association_coordinator = Arc::downgrade(association_coordinator);
        let (local_call, local_notifications, local_shutdown) = setup
            .into_active(local_ring, move || {
                if let Some(association_coordinator) = weak_association_coordinator.upgrade() {
                    association_coordinator.report_failure();
                }
            })
            .unwrap();
        let (request_source, response_sink, host_notifications, host_shutdown) =
            host_activation.join().unwrap();
        (
            local_call,
            local_shutdown,
            local_notifications,
            request_source,
            response_sink,
            host_notifications,
            host_shutdown,
        )
    }

    #[test]
    fn control_failure_cancels_notifications() {
        let (local_control, host_control) = UnixStream::pair().unwrap();
        let (local_setup, host_control) = negotiate_control_pair(local_control, host_control);
        let association_coordinator = Arc::new(BrokerAssociationFailureCoordinator::new());
        let (
            active_channel,
            association_shutdown,
            notification_channel,
            host_request_source,
            host_response_sink,
            _host_notifications,
            host_shutdown,
        ) = activate_control_channel(local_setup, host_control, &association_coordinator);
        association_coordinator
            .install_shutdown(association_shutdown)
            .unwrap();
        let (failure_sender, failure_receiver) = mpsc::sync_channel(1);
        association_coordinator.install_dispatch(move || failure_sender.send(()).unwrap());
        start_notification_receiver(
            BrokerNotifications::new(notification_channel),
            Arc::clone(&association_coordinator),
            |_| {},
        )
        .unwrap();

        host_shutdown.shutdown().unwrap();
        drop(host_request_source);
        drop(host_response_sink);

        failure_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        drop(active_channel);
    }

    #[test]
    fn failure_before_installation_cancels_association_and_dispatches_failure() {
        let (local_control, host_control) = UnixStream::pair().unwrap();
        host_control
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (local_setup, host_control) = negotiate_control_pair(local_control, host_control);
        let association_coordinator = Arc::new(BrokerAssociationFailureCoordinator::new());
        let (
            active_channel,
            association_shutdown,
            _notification_channel,
            mut host_request_source,
            _host_response_sink,
            _host_notifications,
            _host_shutdown,
        ) = activate_control_channel(local_setup, host_control, &association_coordinator);

        association_coordinator.report_failure();

        assert_eq!(
            association_coordinator
                .install_shutdown(association_shutdown)
                .unwrap_err()
                .kind(),
            ErrorKind::ConnectionAborted
        );
        let (failure_sender, failure_receiver) = mpsc::sync_channel(1);
        association_coordinator.install_dispatch(move || failure_sender.send(()).unwrap());
        failure_receiver.try_recv().unwrap();
        assert_eq!(
            host_request_source.recv_request().unwrap(),
            HostReceive::PeerClosed
        );
        drop(active_channel);
    }

    #[test]
    fn notification_receiver_dispatches_ring_message() {
        let (local_control, host_control) = UnixStream::pair().unwrap();
        let (local_setup, host_control) = negotiate_control_pair(local_control, host_control);
        let association_coordinator = Arc::new(BrokerAssociationFailureCoordinator::new());
        let (
            active_channel,
            association_shutdown,
            notification_channel,
            _host_request_source,
            _host_response_sink,
            mut host_notifications,
            host_shutdown,
        ) = activate_control_channel(local_setup, host_control, &association_coordinator);
        association_coordinator
            .install_shutdown(association_shutdown)
            .unwrap();
        association_coordinator.install_dispatch(|| {});
        let (notification_sender, notification_receiver) = mpsc::sync_channel(1);
        start_notification_receiver(
            BrokerNotifications::new(notification_channel),
            Arc::clone(&association_coordinator),
            move |notification| notification_sender.send(notification).unwrap(),
        )
        .unwrap();
        let notification = BrokerNotification::Readiness(ReadinessNotification {
            handle: ObjectHandle(7),
            readiness: ReadinessFlags::READ,
        });

        host_notifications.send_notification(&notification).unwrap();

        assert_eq!(
            notification_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap(),
            notification
        );
        host_shutdown.shutdown().unwrap();
        drop(active_channel);
    }
}
