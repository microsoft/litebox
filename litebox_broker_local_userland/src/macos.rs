// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{os::fd::OwnedFd, os::unix::net::UnixStream, path::Path, sync::Arc, time::Instant};

use anyhow::{Context as _, Result};
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_protocol::process::ProcessStartupData;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::control_ring::ControlRingLayout;
use litebox_broker_transport_macos_userland::unix_socket::{
    UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
    UnixStreamLocalSetupChannel,
};

use crate::unix::{
    BrokerAssociationFailureCoordinator, SETUP_TIMEOUT, activate, connect_with_retry,
};

/// An active macOS-userland broker association.
pub struct BrokerConnection {
    /// Synchronous broker request channel.
    pub local: BrokerLocal<UnixControlRingLocalCallChannel>,
    /// Asynchronous broker notification channel.
    pub notifications: BrokerNotifications<UnixControlRingLocalNotificationChannel>,
    /// Coordinates transport shutdown and LiteBox failure notification.
    pub coordinator: Arc<BrokerAssociationFailureCoordinator>,
    /// Socket over which the broker delivers host shared objects.
    pub shared_object_channel: OwnedFd,
}

/// Connects to and negotiates an association with a macOS-userland broker.
///
/// The broker sends no process image on macOS, so a runner started this way
/// can only begin from a fresh program.
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
/// natively forked runner.
///
/// Negotiating parks the calling thread, so in a natively forked runner it must have been
/// created after the fork: a thread that parked before a macOS `fork` traps when it parks again
/// in the child, because the dispatch semaphore behind `std`'s thread parker does not survive
/// the fork.
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
    let (local, startup, (notification_channel, shared_object_channel)) =
        BrokerLocal::negotiate(setup_channel, |mut setup| {
            let shared_memory =
                setup.receive_shared_memory(SHARED_BUFFER_POOL_SIZE, Some(setup_deadline))?;
            let layout = ControlRingLayout::MULTI_LANE;
            let control_memory = setup.receive_control_ring(layout, Some(setup_deadline))?;
            let shared_object_channel =
                setup.receive_shared_object_channel(Some(setup_deadline))?;
            let (call_channel, notification_channel, _shutdown_fd) =
                activate(setup, control_memory, layout, &association_coordinator)?;
            Ok((
                call_channel,
                Arc::new(shared_memory),
                (notification_channel, shared_object_channel),
            ))
        })
        .context("broker negotiation failed")?;
    Ok((
        BrokerConnection {
            local,
            notifications: BrokerNotifications::new(notification_channel),
            coordinator: association_coordinator,
            shared_object_channel,
        },
        startup,
    ))
}
