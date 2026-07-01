// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    path::Path,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_transport::unix_socket::{
    UnixStreamLocalControlChannel, UnixStreamLocalNotificationChannel,
};

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_millis(20);
type Local = BrokerLocal<UnixStreamLocalControlChannel>;

pub(crate) struct BrokerConnection {
    local: Local,
    #[expect(
        dead_code,
        reason = "keeps the notification receiver thread alive while the broker connection is installed"
    )]
    notification_receiver_thread: JoinHandle<()>,
}

pub(crate) fn connect(
    control_socket_path: Option<&Path>,
    notification_socket_path: Option<&Path>,
) -> Result<Option<BrokerConnection>> {
    match (control_socket_path, notification_socket_path) {
        (Some(control_path), Some(notification_path)) => {
            connect_to_endpoint(control_path, notification_path).map(Some)
        }
        (None, None) => Ok(None),
        (Some(_), None) => {
            bail!("broker notification socket is required with broker control socket")
        }
        (None, Some(_)) => {
            bail!("broker control socket is required with broker notification socket")
        }
    }
}

impl BrokerConnection {
    pub(crate) fn into_local(self) -> Local {
        self.local
    }
}

fn connect_to_endpoint(
    control_socket_path: &Path,
    notification_socket_path: &Path,
) -> Result<BrokerConnection> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_channel = connect_control_with_retry(control_socket_path, setup_deadline)
        .with_context(|| {
            format!(
                "failed to connect to broker at {}",
                control_socket_path.display()
            )
        })?;
    let notification_channel =
        connect_notification_with_retry(notification_socket_path, setup_deadline).with_context(
            || {
                format!(
                    "failed to connect to broker notifications at {}",
                    notification_socket_path.display()
                )
            },
        )?;
    let local = BrokerLocal::negotiate(control_channel).context("broker negotiation failed")?;
    let mut notifications = BrokerNotifications::new(notification_channel);
    let notification_thread = std::thread::Builder::new()
        .name("litebox-broker-notifications".to_owned())
        .spawn(move || {
            loop {
                match notifications.recv_notification() {
                    Ok(Some(_notification)) => {}
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!("failed to receive broker notification: {error}");
                        break;
                    }
                }
            }
        })
        .context("failed to start broker notification receiver")?;
    Ok(BrokerConnection {
        local,
        notification_receiver_thread: notification_thread,
    })
}

fn connect_control_with_retry(
    socket_path: &Path,
    setup_deadline: Instant,
) -> Result<UnixStreamLocalControlChannel> {
    loop {
        match UnixStreamLocalControlChannel::connect_with_setup_deadline(
            socket_path,
            setup_deadline,
        ) {
            Ok(channel) => return Ok(channel),
            Err(error) => {
                if Instant::now() >= setup_deadline {
                    return Err(error).context("timed out connecting to broker");
                }
            }
        }
        let remaining = setup_deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(RETRY_DELAY.min(remaining));
    }
}

fn connect_notification_with_retry(
    socket_path: &Path,
    setup_deadline: Instant,
) -> Result<UnixStreamLocalNotificationChannel> {
    loop {
        match UnixStreamLocalNotificationChannel::connect(socket_path) {
            Ok(channel) => return Ok(channel),
            Err(error) => {
                if Instant::now() >= setup_deadline {
                    return Err(error).context("timed out connecting to broker notifications");
                }
            }
        }
        let remaining = setup_deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(RETRY_DELAY.min(remaining));
    }
}
