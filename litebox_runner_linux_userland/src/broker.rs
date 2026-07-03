// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_protocol::message::BrokerNotification;
use litebox_broker_transport::unix_socket::{
    UnixStreamLocalControlChannel, UnixStreamLocalNotificationChannel,
};

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_millis(20);

pub(crate) fn connect(
    control_socket_path: &Path,
    notification_socket_path: &Path,
) -> Result<(
    BrokerLocal<UnixStreamLocalControlChannel>,
    BrokerNotifications<UnixStreamLocalNotificationChannel>,
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
    let local = BrokerLocal::negotiate(control_channel).context("broker negotiation failed")?;
    Ok((local, BrokerNotifications::new(notification_channel)))
}

pub(crate) fn start_notification_receiver(
    mut notifications: BrokerNotifications<UnixStreamLocalNotificationChannel>,
    dispatch_notification: impl Fn(BrokerNotification) + Send + 'static,
) -> Result<()> {
    std::thread::Builder::new()
        .name("litebox-broker-notifications".to_owned())
        .spawn(move || {
            loop {
                match notifications.recv_notification() {
                    Ok(Some(notification)) => dispatch_notification(notification),
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!("failed to receive broker notification: {error}");
                        break;
                    }
                }
            }
        })
        .context("failed to start broker notification receiver")?;
    Ok(())
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
