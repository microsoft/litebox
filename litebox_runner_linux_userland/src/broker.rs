// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    path::Path,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
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
    control_socket_path: &Path,
    notification_socket_path: &Path,
) -> Result<BrokerConnection> {
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

impl BrokerConnection {
    pub(crate) fn into_local(self) -> Local {
        self.local
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
