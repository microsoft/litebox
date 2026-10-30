// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    os::fd::{AsFd, AsRawFd, OwnedFd, RawFd},
    os::unix::net::UnixStream,
    path::Path,
    sync::Arc,
    time::Instant,
};

use anyhow::{Context as _, Result};
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_protocol::process::ProcessStartupData;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::control_ring::ControlRingLayout;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
    UnixStreamLocalSetupChannel,
};

use crate::unix::{
    BrokerAssociationFailureCoordinator, SETUP_TIMEOUT, activate, connect_with_retry,
};

/// An active Linux-userland broker association.
pub struct BrokerConnection {
    /// Synchronous broker request channel.
    pub local: BrokerLocal<UnixControlRingLocalCallChannel>,
    /// Asynchronous broker notification channel.
    pub notifications: BrokerNotifications<UnixControlRingLocalNotificationChannel>,
    /// Coordinates transport shutdown and LiteBox failure notification.
    pub coordinator: Arc<BrokerAssociationFailureCoordinator>,
    /// Shared-memory descriptors that a runner's syscall filter must permit.
    pub positional_io_fds: [RawFd; 2],
    /// Association-shutdown descriptor that a runner's syscall filter must permit.
    pub shutdown_fd: RawFd,
    /// Socket over which the broker delivers host shared objects.
    pub shared_object_channel: OwnedFd,
    /// Sealed memfd holding the memory image this process starts from, if
    /// its parent wrote one.
    pub process_image: Option<OwnedFd>,
}

/// Connects to and negotiates an association with a Linux-userland broker.
pub fn connect(
    control_socket_path: &Path,
) -> Result<(BrokerConnection, Option<ProcessStartupData>)> {
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
    negotiate(setup_channel, setup_deadline)
}

/// Negotiates an association over a stream whose peer end the broker already holds, as in a
/// natively cloned runner.
pub fn connect_stream(
    stream: UnixStream,
) -> Result<(BrokerConnection, Option<ProcessStartupData>)> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    negotiate(
        UnixStreamLocalSetupChannel::from_connected_with_setup_deadline(stream, setup_deadline),
        setup_deadline,
    )
}

fn negotiate(
    setup_channel: UnixStreamLocalSetupChannel,
    setup_deadline: Instant,
) -> Result<(BrokerConnection, Option<ProcessStartupData>)> {
    let association_coordinator = Arc::new(BrokerAssociationFailureCoordinator::new());
    let (
        local,
        startup,
        (
            notification_channel,
            positional_io_fds,
            shutdown_fd,
            shared_object_channel,
            process_image,
        ),
    ) = BrokerLocal::negotiate(setup_channel, |mut setup| {
        let shared_memory = setup.receive_memfd(SHARED_BUFFER_POOL_SIZE, Some(setup_deadline))?;
        let layout = ControlRingLayout::MULTI_LANE;
        let control_memory = setup.receive_control_ring(layout, Some(setup_deadline))?;
        let shared_object_channel = setup.receive_shared_object_channel(Some(setup_deadline))?;
        let process_image = setup.receive_process_image(Some(setup_deadline))?;
        let positional_io_fds = [
            shared_memory.as_fd().as_raw_fd(),
            control_memory.as_fd().as_raw_fd(),
        ];
        let (call_channel, notification_channel, shutdown_fd) =
            activate(setup, control_memory, layout, &association_coordinator)?;
        Ok((
            call_channel,
            Arc::new(shared_memory),
            (
                notification_channel,
                positional_io_fds,
                shutdown_fd,
                shared_object_channel,
                process_image,
            ),
        ))
    })
    .context("broker negotiation failed")?;
    Ok((
        BrokerConnection {
            local,
            notifications: BrokerNotifications::new(notification_channel),
            coordinator: association_coordinator,
            positional_io_fds,
            shutdown_fd,
            shared_object_channel,
            process_image,
        },
        startup,
    ))
}
