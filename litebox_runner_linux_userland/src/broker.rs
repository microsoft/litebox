// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
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
use litebox_broker_protocol::shared_memory::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::control_ring::{CONTROL_RING_MEMORY_SIZE, ControlRing};
use litebox_broker_transport::unix_socket::{
    UnixStreamLocalControlCancellation, UnixStreamLocalControlChannel,
    UnixStreamLocalNotificationCancellation, UnixStreamLocalNotificationChannel,
};

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_millis(20);

pub(crate) fn connect(
    control_socket_path: &Path,
    notification_socket_path: &Path,
) -> Result<(
    BrokerLocal<UnixStreamLocalControlChannel>,
    BrokerNotifications<UnixStreamLocalNotificationChannel>,
    Arc<BrokerAssociationFailureCoordinator>,
)> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_channel = connect_with_retry(
        control_socket_path,
        setup_deadline,
        "timed out connecting to broker",
        |path, deadline| UnixStreamLocalControlChannel::connect_with_setup_deadline(path, deadline),
    )
    .with_context(|| {
        format!(
            "failed to connect to broker at {}",
            control_socket_path.display()
        )
    })?;
    let notification_channel = connect_with_retry(
        notification_socket_path,
        setup_deadline,
        "timed out connecting to broker notifications",
        |path, _deadline| UnixStreamLocalNotificationChannel::connect(path),
    )
    .with_context(|| {
        format!(
            "failed to connect to broker notifications at {}",
            notification_socket_path.display()
        )
    })?;
    let notification_cancellation_handle = notification_channel
        .cancellation_handle()
        .context("failed to create broker notification cancellation handle")?;
    let association_coordinator = Arc::new(BrokerAssociationFailureCoordinator::new(
        notification_cancellation_handle,
    ));
    let local = BrokerLocal::negotiate(control_channel, {
        let association_coordinator = Arc::clone(&association_coordinator);
        move |channel| {
            let shared_memory =
                channel.receive_memfd(SHARED_BUFFER_POOL_SIZE, Some(setup_deadline))?;
            let control_memory =
                channel.receive_memfd(CONTROL_RING_MEMORY_SIZE, Some(setup_deadline))?;
            let control_ring = ControlRing::new(control_memory).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid broker control ring: {error:?}"),
                )
            })?;
            let weak_association_coordinator = Arc::downgrade(&association_coordinator);
            let control_cancellation_handle = channel.activate(control_ring, move || {
                if let Some(association_coordinator) = weak_association_coordinator.upgrade() {
                    association_coordinator.report_failure();
                }
            })?;
            association_coordinator
                .install_control_cancellation_handle(control_cancellation_handle)?;
            Ok(Arc::new(shared_memory))
        }
    })
    .context("broker negotiation failed")?;
    Ok((
        local,
        BrokerNotifications::new(notification_channel),
        association_coordinator,
    ))
}

pub(crate) fn start_notification_receiver(
    mut notifications: BrokerNotifications<UnixStreamLocalNotificationChannel>,
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
    control_cancellation_handle: Mutex<Option<UnixStreamLocalControlCancellation>>,
    notification_cancellation_handle: UnixStreamLocalNotificationCancellation,
    dispatch_failure: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl BrokerAssociationFailureCoordinator {
    fn new(notification_cancellation_handle: UnixStreamLocalNotificationCancellation) -> Self {
        Self {
            failed: AtomicBool::new(false),
            control_cancellation_handle: Mutex::new(None),
            notification_cancellation_handle,
            dispatch_failure: Mutex::new(None),
        }
    }

    fn install_control_cancellation_handle(
        &self,
        control_cancellation_handle: UnixStreamLocalControlCancellation,
    ) -> std::io::Result<()> {
        let mut installed = self
            .control_cancellation_handle
            .lock()
            .expect("broker control cancellation mutex poisoned");
        assert!(
            installed.is_none(),
            "broker control cancellation already installed"
        );
        if self.failed.load(Ordering::Acquire) {
            control_cancellation_handle.cancel()?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "broker association failed during activation",
            ));
        }
        *installed = Some(control_cancellation_handle);
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
        if let Some(cancellation_handle) = self
            .control_cancellation_handle
            .lock()
            .expect("broker control cancellation mutex poisoned")
            .as_ref()
            && let Err(error) = cancellation_handle.cancel()
        {
            eprintln!("failed to cancel broker control channel: {error}");
        }
        if let Err(error) = self.notification_cancellation_handle.cancel() {
            eprintln!("failed to cancel broker notification channel: {error}");
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
    use litebox_broker_protocol::channel::{HostReceive, HostSetupChannel, LocalControlChannel};
    use litebox_broker_protocol::message::{BrokerOperation, BrokerRequest};
    use litebox_broker_protocol::{ObjectHandle, RequestId};
    use litebox_broker_transport::shared_memory::MemfdSharedMemory;
    use litebox_broker_transport::unix_socket::{
        UnixStreamHostControlChannel, UnixStreamHostControlShutdown, UnixStreamHostRequestSource,
        UnixStreamHostResponseSink,
    };
    use std::io::{ErrorKind, Read};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;

    fn negotiate_control_pair(
        local_stream: UnixStream,
        host_stream: UnixStream,
    ) -> (UnixStreamLocalControlChannel, UnixStreamHostControlChannel) {
        let mut local = UnixStreamLocalControlChannel::from_connected(local_stream);
        let mut host = UnixStreamHostControlChannel::from_accepted(host_stream);
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
        channel: &mut UnixStreamLocalControlChannel,
        host_channel: UnixStreamHostControlChannel,
        association_coordinator: &Arc<BrokerAssociationFailureCoordinator>,
    ) -> (
        UnixStreamLocalControlCancellation,
        UnixStreamHostRequestSource,
        UnixStreamHostResponseSink,
        UnixStreamHostControlShutdown,
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
        let cancellation = channel
            .activate(local_ring, move || {
                if let Some(association_coordinator) = weak_association_coordinator.upgrade() {
                    association_coordinator.report_failure();
                }
            })
            .unwrap();
        let (request_source, response_sink, shutdown) = host_activation.join().unwrap();
        (cancellation, request_source, response_sink, shutdown)
    }

    #[test]
    fn control_failure_cancels_notifications() {
        let (local_control, host_control) = UnixStream::pair().unwrap();
        let (mut active_channel, host_control) =
            negotiate_control_pair(local_control, host_control);
        let (local_notification, mut host_notification) = UnixStream::pair().unwrap();
        host_notification
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let notification_channel =
            UnixStreamLocalNotificationChannel::from_connected(local_notification);
        let association_coordinator = Arc::new(BrokerAssociationFailureCoordinator::new(
            notification_channel.cancellation_handle().unwrap(),
        ));
        let (control_cancellation_handle, host_request_source, host_response_sink, host_shutdown) =
            activate_control_channel(&mut active_channel, host_control, &association_coordinator);
        association_coordinator
            .install_control_cancellation_handle(control_cancellation_handle)
            .unwrap();
        let (failure_sender, failure_receiver) = mpsc::sync_channel(1);
        association_coordinator.install_dispatch(move || failure_sender.send(()).unwrap());

        host_shutdown.shutdown().unwrap();
        drop(host_request_source);
        drop(host_response_sink);

        failure_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        let mut byte = [0];
        assert_eq!(host_notification.read(&mut byte).unwrap(), 0);
        drop(active_channel);
        drop(notification_channel);
    }

    #[test]
    fn failure_before_installation_cancels_control_and_dispatches_failure() {
        let (local_control, host_control) = UnixStream::pair().unwrap();
        host_control
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (mut active_channel, host_control) =
            negotiate_control_pair(local_control, host_control);
        let (local_notification, mut host_notification) = UnixStream::pair().unwrap();
        host_notification
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let notification_channel =
            UnixStreamLocalNotificationChannel::from_connected(local_notification);
        let association_coordinator = Arc::new(BrokerAssociationFailureCoordinator::new(
            notification_channel.cancellation_handle().unwrap(),
        ));
        let (
            control_cancellation_handle,
            mut host_request_source,
            _host_response_sink,
            _host_shutdown,
        ) = activate_control_channel(&mut active_channel, host_control, &association_coordinator);

        association_coordinator.report_failure();

        assert_eq!(
            association_coordinator
                .install_control_cancellation_handle(control_cancellation_handle)
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
        let mut byte = [0];
        assert_eq!(host_notification.read(&mut byte).unwrap(), 0);
        drop(active_channel);
        drop(notification_channel);
    }

    #[test]
    fn notification_failure_cancels_control() {
        let (local_control, host_control) = UnixStream::pair().unwrap();
        let (mut active_channel, host_control) =
            negotiate_control_pair(local_control, host_control);
        let (local_notification, host_notification) = UnixStream::pair().unwrap();
        let notification_channel =
            UnixStreamLocalNotificationChannel::from_connected(local_notification);
        let association_coordinator = Arc::new(BrokerAssociationFailureCoordinator::new(
            notification_channel.cancellation_handle().unwrap(),
        ));
        let (
            control_cancellation_handle,
            mut host_request_source,
            _host_response_sink,
            _host_shutdown,
        ) = activate_control_channel(&mut active_channel, host_control, &association_coordinator);
        association_coordinator
            .install_control_cancellation_handle(control_cancellation_handle)
            .unwrap();
        let (failure_sender, failure_receiver) = mpsc::sync_channel(1);
        association_coordinator.install_dispatch(move || failure_sender.send(()).unwrap());
        start_notification_receiver(
            BrokerNotifications::new(notification_channel),
            Arc::clone(&association_coordinator),
            |_| {},
        )
        .unwrap();
        let active_channel = Arc::new(active_channel);
        let pending_channel = Arc::clone(&active_channel);
        let pending_call = std::thread::spawn(move || {
            pending_channel.call(BrokerRequest {
                request_id: RequestId(1),
                operation: BrokerOperation::CloseObject(ObjectHandle(1)),
            })
        });
        assert!(matches!(
            host_request_source.recv_request().unwrap(),
            HostReceive::Message(_)
        ));

        drop(host_notification);

        failure_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert!(pending_call.join().unwrap().is_err());
        assert_eq!(
            host_request_source.recv_request().unwrap(),
            HostReceive::PeerClosed
        );
    }
}
