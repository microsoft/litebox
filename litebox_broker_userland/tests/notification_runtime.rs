// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_host::{ConnectionTermination, serve_connection};
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_memory::{
    SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE, SharedBufferPool,
};
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

    let host_thread = std::thread::spawn(move || {
        let mut control = UnixStreamHostControlChannel::from_accepted(host_control);
        let mut notification = UnixStreamHostNotificationChannel::from_accepted(host_notification);
        serve_connection(
            &broker,
            &mut control,
            &mut notification,
            &host_shared_buffers,
            |channel| channel.send_memfd(host_shared_buffers.memory(), None),
        )
    });

    let local = BrokerLocal::negotiate(
        UnixStreamLocalControlChannel::from_connected(local_control),
        |channel| {
            let shared_memory = channel.receive_memfd(SHARED_BUFFER_POOL_SIZE, None)?;
            let _cancellation = channel.activate(|| {})?;
            Ok(Arc::new(shared_memory))
        },
    )
    .unwrap();

    let handle = local.create_event_with_count(0).unwrap();
    let readiness = ReadinessFlags::READ | ReadinessFlags::WRITE;
    assert_eq!(local.add_event(handle, 1).unwrap(), readiness);

    drop(local);
    assert_eq!(
        host_thread.join().unwrap().unwrap(),
        ConnectionTermination::PeerClosed
    );
}
