// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::OsStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::control_ring::{
    WindowsControlRingLocalCallChannel, WindowsControlRingLocalNotificationChannel,
};
use crate::named_pipe::WindowsNamedPipeLocalSetupChannel;
use anyhow::{Context as _, Result};
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_protocol::message::BrokerNotification;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::control_ring::ControlRing;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);

pub struct BrokerConnection {
    pub local: BrokerLocal<WindowsControlRingLocalCallChannel>,
    pub notifications: BrokerNotifications<WindowsControlRingLocalNotificationChannel>,
}

pub fn connect(control_pipe: &OsStr) -> Result<BrokerConnection> {
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let setup =
        WindowsNamedPipeLocalSetupChannel::connect_with_setup_deadline(control_pipe, deadline)
            .with_context(|| {
                format!(
                    "failed to connect to broker at {}",
                    std::path::Path::new(control_pipe).display()
                )
            })?;
    let (local, notifications) = BrokerLocal::negotiate(setup, |mut setup| {
        let shared_memory = Arc::new(setup.receive_shared_memory(SHARED_BUFFER_POOL_SIZE)?);
        let control_memory = setup.receive_control_ring()?;
        let control_ring = ControlRing::new(control_memory).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid broker control ring: {error:?}"),
            )
        })?;
        let (calls, notifications) = setup.into_active(control_ring)?;
        Ok((calls, shared_memory, notifications))
    })
    .context("broker negotiation failed")?;
    Ok(BrokerConnection {
        local,
        notifications: BrokerNotifications::new(notifications),
    })
}

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
                    Ok(Some(notification)) => dispatch_notification(notification),
                    Ok(None) => break None,
                    Err(error) => break Some(error),
                }
            };
            dispatch_failure();
            if let Some(error) = error {
                eprintln!("failed to receive broker notification: {error}");
            }
        })
        .context("failed to start broker notification receiver")?;
    Ok(())
}
