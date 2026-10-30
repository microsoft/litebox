// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{path::Path, sync::Arc, time::Instant};

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
}

/// Connects to and negotiates an association with a macOS-userland broker.
///
/// The broker sends no process image or shared-object channel on macOS, so a
/// runner started this way can only begin from a fresh program.
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
    let association_coordinator = Arc::new(BrokerAssociationFailureCoordinator::new());
    let (local, startup, notification_channel) =
        BrokerLocal::negotiate(setup_channel, |mut setup| {
            let shared_memory =
                setup.receive_shared_memory(SHARED_BUFFER_POOL_SIZE, Some(setup_deadline))?;
            let layout = ControlRingLayout::MULTI_LANE;
            let control_memory = setup.receive_control_ring(layout, Some(setup_deadline))?;
            let (call_channel, notification_channel, _shutdown_fd) =
                activate(setup, control_memory, layout, &association_coordinator)?;
            Ok((call_channel, Arc::new(shared_memory), notification_channel))
        })
        .context("broker negotiation failed")?;
    Ok((
        BrokerConnection {
            local,
            notifications: BrokerNotifications::new(notification_channel),
            coordinator: association_coordinator,
        },
        startup,
    ))
}
