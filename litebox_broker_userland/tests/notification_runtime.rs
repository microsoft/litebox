// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_host::{ConnectionTermination, setup_connection};
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::channel::{HostNotificationChannel, HostReceive};
use litebox_broker_protocol::message::{BrokerNotification, ReadinessNotification};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_memory::{
    SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE, SharedBufferPool,
};
use litebox_broker_transport::control_ring::{CONTROL_RING_MEMORY_SIZE, ControlRing};
use litebox_broker_transport::shared_memory::MemfdSharedMemory;
use litebox_broker_transport::unix_socket::{
    UnixStreamHostSetupChannel, UnixStreamLocalSetupChannel,
};

#[test]
fn host_serves_control_requests_and_notifications_over_shared_rings() {
    let broker = BrokerCore::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
    .unwrap();
    let (local_control, host_control) = UnixStream::pair().unwrap();
    let host_shared_memory = MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE).unwrap();
    let host_shared_buffers =
        SharedBufferPool::new(host_shared_memory, SHARED_BUFFER_LAYOUT).unwrap();
    let host_control_memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
    let host_control_ring = ControlRing::new(host_control_memory).unwrap();
    let notification = BrokerNotification::Readiness(ReadinessNotification {
        handle: ObjectHandle(7),
        readiness: ReadinessFlags::READ,
    });
    let host_notification = notification.clone();

    let host_thread = std::thread::spawn(move || {
        let mut control = UnixStreamHostSetupChannel::from_accepted(host_control);
        let association =
            setup_connection(&broker, &mut control, &host_shared_buffers, |channel| {
                channel.send_memfd(host_shared_buffers.memory(), None)?;
                channel.send_memfd(host_control_ring.memory(), None)
            })
            .unwrap()
            .unwrap();
        let (mut request_source, response_sink, mut notifications, _shutdown) =
            control.into_active(host_control_ring).unwrap();
        notifications.send_notification(&host_notification).unwrap();
        loop {
            match request_source.recv_request().unwrap() {
                HostReceive::Message(request) => association
                    .execute_request(request, |response| response_sink.send_response(response))
                    .unwrap(),
                HostReceive::PeerClosed => return ConnectionTermination::PeerClosed,
                HostReceive::ProtocolViolation => {
                    return ConnectionTermination::ProtocolViolation;
                }
            }
        }
    });

    let (local, notification_channel) = BrokerLocal::negotiate(
        UnixStreamLocalSetupChannel::from_connected(local_control),
        |mut setup| {
            let shared_memory = setup.receive_memfd(SHARED_BUFFER_POOL_SIZE, None)?;
            let control_memory = setup.receive_memfd(CONTROL_RING_MEMORY_SIZE, None)?;
            let control_ring = ControlRing::new(control_memory).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid test control ring: {error:?}"),
                )
            })?;
            let (call_channel, notifications, _shutdown) =
                setup.into_active(control_ring, || {})?;
            Ok((call_channel, Arc::new(shared_memory), notifications))
        },
    )
    .unwrap();
    let mut notifications = BrokerNotifications::new(notification_channel);
    assert_eq!(
        notifications.recv_notification().unwrap(),
        Some(notification)
    );

    let handle = local.create_event_with_count(0).unwrap();
    let readiness = ReadinessFlags::READ | ReadinessFlags::WRITE;
    assert_eq!(local.add_event(handle, 1).unwrap(), readiness);

    drop(local);
    assert_eq!(
        host_thread.join().unwrap(),
        ConnectionTermination::PeerClosed
    );
}
