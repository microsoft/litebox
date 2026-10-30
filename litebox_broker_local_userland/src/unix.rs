// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side association plumbing shared by the Linux and macOS userland
//! transports, which expose the same Unix-socket endpoint names.

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
use litebox_broker_local::BrokerNotifications;
use litebox_broker_protocol::message::BrokerNotification;
use litebox_broker_transport::control_ring::{ControlRing, ControlRingLayout};

#[cfg(target_os = "linux")]
use litebox_broker_transport_linux_userland as transport;
#[cfg(target_os = "macos")]
use litebox_broker_transport_macos_userland as transport;

use transport::unix_socket::{
    UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
    UnixControlRingLocalShutdown, UnixStreamLocalSetupChannel,
};

/// Shared memory backing the control ring on this host.
#[cfg(target_os = "linux")]
pub(crate) type ControlMemory = transport::memfd::MemfdSharedMemory;
/// Shared memory backing the control ring on this host.
#[cfg(target_os = "macos")]
pub(crate) type ControlMemory = transport::shared_memory::MacosSharedMemory;

pub(crate) const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const RETRY_DELAY: Duration = Duration::from_millis(20);

/// Activates a negotiated setup channel on the received control ring and
/// installs its shutdown in `association_coordinator`, which observes every
/// later transport failure.
///
/// Returns the call and notification channels and the association-shutdown
/// descriptor.
pub(crate) fn activate(
    setup: UnixStreamLocalSetupChannel,
    control_memory: ControlMemory,
    layout: ControlRingLayout,
    association_coordinator: &Arc<BrokerAssociationFailureCoordinator>,
) -> std::io::Result<(
    UnixControlRingLocalCallChannel,
    UnixControlRingLocalNotificationChannel,
    RawFd,
)> {
    let control_ring = ControlRing::new(control_memory, layout).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid broker control ring: {error:?}"),
        )
    })?;
    let weak_association_coordinator = Arc::downgrade(association_coordinator);
    let (call_channel, notification_channel, association_shutdown) =
        setup.into_active(control_ring, move || {
            if let Some(association_coordinator) = weak_association_coordinator.upgrade() {
                association_coordinator.report_failure();
            }
        })?;
    let shutdown_fd = association_shutdown.as_fd().as_raw_fd();
    association_coordinator.install_shutdown(association_shutdown)?;
    Ok((call_channel, notification_channel, shutdown_fd))
}

/// Starts the broker notification receiver for an active association.
pub fn start_notification_receiver(
    mut notifications: BrokerNotifications<UnixControlRingLocalNotificationChannel>,
    association_coordinator: Arc<BrokerAssociationFailureCoordinator>,
    dispatch_notification: impl Fn(BrokerNotification) + Send + 'static,
) -> Result<()> {
    let (started, wait_for_start) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("litebox-broker-notifications".to_owned())
        .spawn(move || {
            let _ = started.send(());
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
    // Wait until the receiver runs, past the runtime's own thread startup, which holds a
    // process-wide lock. A runner may clone itself as soon as this returns, and a clone that
    // inherited that lock held could never start a thread.
    let _ = wait_for_start.recv();
    Ok(())
}

/// Coordinates failure across the broker call and notification channels.
pub struct BrokerAssociationFailureCoordinator {
    failed: AtomicBool,
    shutdown: Mutex<Option<UnixControlRingLocalShutdown>>,
    dispatch_failure: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl BrokerAssociationFailureCoordinator {
    pub(crate) fn new() -> Self {
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

    /// Installs the callback used to fail broker-backed LiteBox resources.
    ///
    /// # Panics
    ///
    /// Panics if a failure callback was already installed or an internal mutex is poisoned.
    pub fn install_dispatch(&self, dispatch_failure: impl FnOnce() + Send + 'static) {
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

/// Connects to `socket_path`, retrying until `setup_deadline`. The first retry
/// follows `first_retry_delay`, and each later wait doubles up to
/// [`RETRY_DELAY`].
pub(crate) fn connect_with_retry<Channel>(
    socket_path: &Path,
    first_retry_delay: Duration,
    setup_deadline: Instant,
    timeout_message: &'static str,
    mut connect: impl FnMut(&Path, Instant) -> std::io::Result<Channel>,
) -> Result<Channel> {
    let mut retry_delay = first_retry_delay.min(RETRY_DELAY);
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
        std::thread::sleep(retry_delay.min(remaining));
        retry_delay = (retry_delay * 2).min(RETRY_DELAY);
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
    use std::io::ErrorKind;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use transport::unix_socket::{
        UnixControlRingHostCallLaneSource, UnixControlRingHostNotificationChannel,
        UnixControlRingHostShutdown, UnixStreamHostSetupChannel,
    };
    use transport::unix_socket::{
        UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
        UnixControlRingLocalShutdown, UnixStreamLocalSetupChannel,
    };

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
                process_id: litebox_broker_protocol::ProcessId(1),
                initial_thread_id: litebox_broker_protocol::ThreadId(2),
                startup: None,
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
        UnixControlRingHostCallLaneSource,
        UnixControlRingHostNotificationChannel,
        UnixControlRingHostShutdown,
    ) {
        let layout = ControlRingLayout::MULTI_LANE;
        let local_memory = ControlMemory::create_control_ring(layout).unwrap();
        let host_memory = ControlMemory::control_ring_from_received_fd(
            local_memory.as_fd().try_clone_to_owned().unwrap(),
            layout,
        )
        .unwrap();
        let local_ring = ControlRing::new(local_memory, layout).unwrap();
        let host_ring = ControlRing::new(host_memory, layout).unwrap();
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
        let (host_lanes, host_notifications, host_shutdown) = host_activation.join().unwrap();
        (
            local_call,
            local_shutdown,
            local_notifications,
            host_lanes,
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
            host_lanes,
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
        drop(host_lanes);

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
            mut host_lanes,
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
        // Lane 0 is always demanded, so the broker may hand it out before it
        // sees the close.
        while host_lanes.next_lane().unwrap().is_some() {}
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
            _host_lanes,
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
