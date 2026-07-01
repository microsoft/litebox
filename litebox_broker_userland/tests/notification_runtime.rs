// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::os::unix::net::UnixStream;
use std::time::Duration;

use litebox_broker_core::{BrokerCore, PolicyEngine, PrincipalRights};
use litebox_broker_host::{ConnectionTermination, serve_connection};
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_protocol::event::ReadinessState;
use litebox_broker_protocol::message::{BrokerNotification, EventReadinessNotification};
use litebox_broker_transport::unix_socket::{
    UnixStreamHostControlChannel, UnixStreamHostNotificationChannel, UnixStreamLocalControlChannel,
    UnixStreamLocalNotificationChannel,
};

#[test]
fn host_sends_readiness_notifications_over_paired_userland_channel() {
    let broker = BrokerCore::new(PolicyEngine::with_unauthenticated_rights(
        PrincipalRights::all(),
    ))
    .unwrap();
    let (local_control, host_control) = UnixStream::pair().unwrap();
    let (local_notification, host_notification) = UnixStream::pair().unwrap();
    local_notification
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let host_thread = std::thread::spawn(move || {
        let mut control = UnixStreamHostControlChannel::from_accepted(host_control);
        let mut notification = UnixStreamHostNotificationChannel::from_accepted(host_notification);
        serve_connection(&broker, &mut control, &mut notification)
    });

    let mut local =
        BrokerLocal::negotiate(UnixStreamLocalControlChannel::from_connected(local_control))
            .unwrap();
    let mut notifications = BrokerNotifications::new(
        UnixStreamLocalNotificationChannel::from_connected(local_notification),
    );

    let handle = local.create_event_with_count(0).unwrap();
    let readiness = ReadinessState {
        read_ready: true,
        write_ready: true,
    };
    assert_eq!(local.add_event(handle, 1).unwrap(), readiness);
    assert_eq!(
        notifications.recv_notification().unwrap(),
        Some(BrokerNotification::EventReadiness(
            EventReadinessNotification { handle, readiness }
        ))
    );

    drop(local);
    assert_eq!(
        host_thread.join().unwrap().unwrap(),
        ConnectionTermination::PeerClosed
    );
}
