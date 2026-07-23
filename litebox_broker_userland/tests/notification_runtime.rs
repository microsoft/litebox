// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_host::{ConnectionTermination, setup_connection};
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::channel::HostReceive;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_memory::{
    SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE, SharedBufferPool,
};
use litebox_broker_transport::control_ring::{CONTROL_RING_MEMORY_SIZE, ControlRing};
use litebox_broker_transport::shared_memory::MemfdSharedMemory;
use litebox_broker_transport::unix_socket::{
    UnixStreamHostControlChannel, UnixStreamHostNotificationChannel, UnixStreamLocalControlChannel,
};

#[test]
fn host_serves_control_requests_over_paired_userland_channels() {
    let broker = BrokerCore::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
    .unwrap();
    let (local_control, host_control) = UnixStream::pair().unwrap();
    let (_local_notification, host_notification) = UnixStream::pair().unwrap();
    let host_shared_memory = MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE).unwrap();
    let host_shared_buffers =
        SharedBufferPool::new(host_shared_memory, SHARED_BUFFER_LAYOUT).unwrap();
    let host_control_memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
    let host_control_ring = ControlRing::new(host_control_memory).unwrap();

    let host_thread = std::thread::spawn(move || {
        let mut control = UnixStreamHostControlChannel::from_accepted(host_control);
        let _notification = UnixStreamHostNotificationChannel::from_accepted(host_notification);
        let association =
            setup_connection(&broker, &mut control, &host_shared_buffers, |channel| {
                channel.send_memfd(host_shared_buffers.memory(), None)?;
                channel.send_memfd(host_control_ring.memory(), None)
            })
            .unwrap()
            .unwrap();
        let (mut request_source, response_sink, _shutdown) =
            control.into_active(host_control_ring).unwrap();
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

    let local = BrokerLocal::negotiate(
        UnixStreamLocalControlChannel::from_connected(local_control),
        |channel| {
            let shared_memory = channel.receive_memfd(SHARED_BUFFER_POOL_SIZE, None)?;
            let control_memory = channel.receive_memfd(CONTROL_RING_MEMORY_SIZE, None)?;
            let control_ring = ControlRing::new(control_memory).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid test control ring: {error:?}"),
                )
            })?;
            let _cancellation = channel.activate(control_ring, || {})?;
            Ok(Arc::new(shared_memory))
        },
    )
    .unwrap();

    let handle = local.create_event_with_count(0).unwrap();
    let readiness = ReadinessFlags::READ | ReadinessFlags::WRITE;
    assert_eq!(local.add_event(handle, 1).unwrap(), readiness);

    drop(local);
    assert_eq!(
        host_thread.join().unwrap(),
        ConnectionTermination::PeerClosed
    );
}
