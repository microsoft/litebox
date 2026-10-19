// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::OsStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_protocol::message::BrokerNotification;
use litebox_broker_protocol::process::ProcessStartupData;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::control_ring::ControlRing;
use litebox_broker_transport_windows_userland::control_ring::{
    WindowsControlRingLocalCallChannel, WindowsControlRingLocalNotificationChannel,
};
use litebox_broker_transport_windows_userland::named_pipe::WindowsNamedPipeLocalSetupChannel;
use litebox_broker_transport_windows_userland::process_image::WindowsReceivedProcessImage;

use crate::quiescence::HelperWork;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);

/// An active Windows-userland broker association.
pub struct BrokerConnection {
    /// Synchronous broker request channel.
    pub local: BrokerLocal<WindowsControlRingLocalCallChannel>,
    /// Asynchronous broker notification channel.
    pub notifications: BrokerNotifications<WindowsControlRingLocalNotificationChannel>,
    /// Memory image this process starts from, if its parent wrote one.
    pub process_image: Option<WindowsReceivedProcessImage>,
    /// Host process ID of the broker serving the control pipe.
    pub broker_process_id: u32,
}

/// Connects to and negotiates an association with a Windows-userland broker.
///
/// If `expected_broker_process_id` is given, the pipe server must be that process, so a
/// process that created the pipe name first cannot pose as the broker.
pub fn connect(
    control_pipe: &OsStr,
    expected_broker_process_id: Option<u32>,
) -> Result<(BrokerConnection, Option<ProcessStartupData>)> {
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let setup =
        WindowsNamedPipeLocalSetupChannel::connect_with_setup_deadline(control_pipe, deadline)
            .with_context(|| {
                format!(
                    "failed to connect to broker at {}",
                    std::path::Path::new(control_pipe).display()
                )
            })?;
    let broker_process_id = setup
        .server_process_id()
        .context("failed to identify the broker")?;
    if let Some(expected) = expected_broker_process_id
        && broker_process_id != expected
    {
        anyhow::bail!(
            "broker pipe is served by process {broker_process_id}, not the broker ({expected})"
        );
    }
    let (local, startup, (notifications, process_image)) =
        BrokerLocal::negotiate(setup, |mut setup| {
            let shared_memory = Arc::new(setup.receive_shared_memory(SHARED_BUFFER_POOL_SIZE)?);
            let control_memory = setup.receive_control_ring()?;
            let process_image = setup.receive_process_image()?;
            let control_ring = ControlRing::new(control_memory).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid broker control ring: {error:?}"),
                )
            })?;
            let (calls, notifications) = setup.into_active(control_ring)?;
            Ok((calls, shared_memory, (notifications, process_image)))
        })
        .context("broker negotiation failed")?;
    Ok((
        BrokerConnection {
            local,
            notifications: BrokerNotifications::new(notifications),
            process_image,
            broker_process_id,
        },
        startup,
    ))
}

/// Starts the broker notification receiver for an active association.
pub fn start_notification_receiver(
    mut notifications: BrokerNotifications<WindowsControlRingLocalNotificationChannel>,
    dispatch_notification: impl Fn(BrokerNotification) + Send + 'static,
    dispatch_failure: impl Fn() + Send + 'static,
) -> Result<()> {
    std::thread::Builder::new()
        .name("litebox-broker-notifications".to_owned())
        .spawn(move || {
            let error = loop {
                match notifications.recv_notification() {
                    Ok(Some(notification)) => {
                        let _work = HelperWork::begin();
                        dispatch_notification(notification);
                    }
                    Ok(None) => break None,
                    Err(error) => break Some(error),
                }
            };
            let _work = HelperWork::begin();
            dispatch_failure();
            if let Some(error) = error {
                eprintln!("failed to receive broker notification: {error}");
            }
        })
        .context("failed to start broker notification receiver")?;
    Ok(())
}
