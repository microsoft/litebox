// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_protocol::process::ProcessStartupData;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::control_ring::ControlRingLayout;
use litebox_broker_transport_macos_userland::existing_runner::ExistingRunnerDescriptor;
use litebox_broker_transport_macos_userland::unix_socket::{
    UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
    UnixStreamLocalSetupChannel,
};

use crate::unix::{
    BrokerAssociationFailureCoordinator, RETRY_DELAY, SETUP_TIMEOUT, activate, connect_with_retry,
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
    connect_at(control_socket_path, RETRY_DELAY)
}

/// Connects a runner natively forked by another runner to the broker that adopts it.
///
/// `control_socket_path` is the `--broker-control-channel` path the forking runner was started
/// with, which the clone inherits unchanged. The broker binds the clone's rendezvous socket in
/// that path's directory once its parent requests adoption with an
/// [`ExistingRunnerDescriptor`] naming this process, so connecting retries until the setup
/// deadline. The clone usually starts connecting before that, so the first retries are short.
///
/// Connecting parks the calling thread, so it must have been created after the fork: a thread
/// that parked before a macOS `fork` traps when it parks again in the child, because the
/// dispatch semaphore behind `std`'s thread parker does not survive the fork.
pub fn connect_native_fork_clone(
    control_socket_path: &Path,
) -> Result<(BrokerConnection, Option<ProcessStartupData>)> {
    let runner_directory = control_socket_path
        .parent()
        .context("broker control socket path has no directory")?;
    let descriptor = ExistingRunnerDescriptor {
        process_id: std::process::id(),
    };
    connect_at(
        &descriptor.rendezvous_socket_path(runner_directory),
        Duration::from_millis(1),
    )
}

fn connect_at(
    socket_path: &Path,
    first_retry_delay: Duration,
) -> Result<(BrokerConnection, Option<ProcessStartupData>)> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let setup_channel = connect_with_retry(
        socket_path,
        first_retry_delay,
        setup_deadline,
        "timed out connecting to broker",
        |path, deadline| UnixStreamLocalSetupChannel::connect_with_setup_deadline(path, deadline),
    )
    .with_context(|| format!("failed to connect to broker at {}", socket_path.display()))?;
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
