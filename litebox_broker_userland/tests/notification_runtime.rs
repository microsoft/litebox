// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// This broker speaks the Linux host transport (`memfd` shared memory and
// `SCM_RIGHTS` over Unix sockets), which `litebox_broker_transport_linux_userland`
// confines to Linux, so the whole crate follows it there.
#![cfg(target_os = "linux")]

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::thread::JoinHandle;
use std::time::Duration;

use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_host::{ConnectionTermination, setup_connection};
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{BrokerNotification, ReadinessNotification};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE};
use litebox_broker_transport::channel::{HostNotificationChannel, HostReceive};
use litebox_broker_transport::control_ring::{
    CONTROL_RING_MEMORY_SIZE, CONTROL_RING_NOTIFICATION_SLOT_COUNT, ControlRing,
};
use litebox_broker_transport::shared_memory::SharedBufferPool;
use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixControlRingHostNotificationChannel, UnixControlRingHostShutdown, UnixStreamHostSetupChannel,
};
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
    UnixStreamLocalSetupChannel,
};
use litebox_broker_userland::readiness::ReadinessPublisherRuntime;

/// Long enough that a hung wakeup fails the test instead of hanging CI.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Long enough for the local endpoint to reach its blocking receive.
const BLOCK_DELAY: Duration = Duration::from_millis(50);
/// More objects than the notification ring holds, so publication must block.
const OVERSUBSCRIBED_OBJECT_COUNT: u64 = CONTROL_RING_NOTIFICATION_SLOT_COUNT * 3;

/// Runs one host association whose only traffic is readiness notifications.
///
/// The reader thread mirrors production: it is the endpoint that observes local
/// termination and interrupts every ring wait of the association.
fn spawn_host(
    stream: UnixStream,
    host: impl FnOnce(UnixControlRingHostNotificationChannel, UnixControlRingHostShutdown)
    + Send
    + 'static,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let broker = BrokerCore::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .unwrap();
        let shared_memory = MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE).unwrap();
        let shared_buffers = SharedBufferPool::new(shared_memory, SHARED_BUFFER_LAYOUT).unwrap();
        let control_memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
        let control_ring = ControlRing::new(control_memory).unwrap();
        let mut control = UnixStreamHostSetupChannel::from_accepted(stream);
        let association = setup_connection(&broker, &mut control, &shared_buffers, |channel| {
            channel.send_memfd(shared_buffers.memory(), None)?;
            channel.send_memfd(control_ring.memory(), None)
        })
        .unwrap()
        .unwrap();
        let (mut request_source, response_sink, notifications, shutdown) =
            control.into_active(control_ring).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while let Ok(HostReceive::Message(request)) = request_source.recv_request() {
                    association
                        .execute_request(request, |response| response_sink.send_response(response))
                        .unwrap();
                }
            });
            host(notifications, shutdown);
        });
    })
}

/// Negotiates the local half of an association created by [`spawn_host`].
fn negotiate_local(
    stream: UnixStream,
) -> (
    BrokerLocal<UnixControlRingLocalCallChannel>,
    BrokerNotifications<UnixControlRingLocalNotificationChannel>,
) {
    let (local, notifications) = BrokerLocal::negotiate(
        UnixStreamLocalSetupChannel::from_connected(stream),
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
    (local, BrokerNotifications::new(notifications))
}

/// Receives a publisher's outcome under the test deadline, so publication that
/// never ends fails the test instead of hanging its join.
fn expect_publication_ended(outcomes: &Receiver<std::io::Result<()>>) {
    outcomes
        .recv_timeout(TEST_TIMEOUT)
        .expect("publication must end")
        .expect("publication must end without a transport error");
}

fn readiness_of(notification: Option<BrokerNotification>) -> ReadinessNotification {
    let Some(BrokerNotification::Readiness(readiness)) = notification else {
        panic!("expected a readiness notification, got {notification:?}");
    };
    readiness
}

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

#[test]
fn a_host_readiness_source_wakes_a_blocked_local_receiver() {
    const HANDLE: ObjectHandle = ObjectHandle(11);
    let readiness = ReadinessFlags::READ | ReadinessFlags::WRITE;
    let (local_control, host_control) = UnixStream::pair().unwrap();
    let (finish_sender, finish_receiver) = channel::<()>();
    let (outcome_sender, outcome_receiver) = channel();

    let host = spawn_host(host_control, move |mut notifications, _shutdown| {
        let runtime = Arc::new(ReadinessPublisherRuntime::new());
        let publishing = Arc::clone(&runtime);
        let publisher = std::thread::spawn(move || publishing.run(&mut notifications));

        // The local endpoint is blocked in its notification receive by now, so
        // this update is the only thing that can wake it.
        std::thread::sleep(BLOCK_DELAY);
        runtime.publish(HANDLE, readiness).unwrap();

        let _ = finish_receiver.recv();
        runtime.close();
        // Reporting the publisher's outcome rather than joining here keeps a
        // close that stops waking it a test failure instead of a hang.
        outcome_sender.send(publisher.join().unwrap()).unwrap();
    });

    let (local, notifications) = negotiate_local(local_control);
    let (notification_sender, notification_receiver) = channel();
    let receiver_thread = std::thread::spawn(move || {
        let mut notifications = notifications;
        // Receiving on a helper thread keeps a wake that never arrives a test
        // failure rather than a hang: the notification wait has no deadline of
        // its own.
        let notification = readiness_of(notifications.recv_notification().unwrap());
        notification_sender.send(notification).unwrap();
        notifications
    });

    assert_eq!(
        notification_receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("a host readiness source must wake the blocked local receiver"),
        ReadinessNotification {
            handle: HANDLE,
            readiness,
        }
    );
    let _notifications = receiver_thread.join().unwrap();
    drop(finish_sender);
    drop(local);
    expect_publication_ended(&outcome_receiver);
    host.join().unwrap();
}

#[test]
fn a_full_notification_ring_does_not_block_readiness_sources() {
    let (local_control, host_control) = UnixStream::pair().unwrap();
    let (published_sender, published_receiver) = channel::<()>();
    let (finish_sender, finish_receiver) = channel::<()>();
    let (outcome_sender, outcome_receiver) = channel();

    let host = spawn_host(host_control, move |mut notifications, _shutdown| {
        let runtime = Arc::new(ReadinessPublisherRuntime::new());
        let publishing = Arc::clone(&runtime);
        let publisher = std::thread::spawn(move || publishing.run(&mut notifications));

        // The local endpoint drains nothing until it sees this signal, so the
        // ring fills and the publisher blocks while the source runs to
        // completion.
        for handle in 0..OVERSUBSCRIBED_OBJECT_COUNT {
            runtime
                .publish(ObjectHandle(handle), ReadinessFlags::READ)
                .unwrap();
        }
        published_sender.send(()).unwrap();

        let _ = finish_receiver.recv();
        runtime.close();
        outcome_sender.send(publisher.join().unwrap()).unwrap();
    });

    let (local, notifications) = negotiate_local(local_control);
    published_receiver.recv_timeout(TEST_TIMEOUT).unwrap();

    // Draining on a helper thread keeps an update that is wrongly coalesced
    // away a test failure rather than a hang, because only this thread can
    // release the host closure.
    let (drained_sender, drained_receiver) = channel();
    let drain = std::thread::spawn(move || {
        let mut notifications = notifications;
        let drained: Vec<_> = (0..OVERSUBSCRIBED_OBJECT_COUNT)
            .map(|_| readiness_of(notifications.recv_notification().unwrap()))
            .collect();
        drained_sender.send(drained).unwrap();
        notifications
    });
    let drained = drained_receiver
        .recv_timeout(TEST_TIMEOUT)
        .expect("a full ring must still deliver every published update");
    let _notifications = drain.join().unwrap();

    for (handle, notification) in drained.into_iter().enumerate() {
        assert_eq!(
            notification,
            ReadinessNotification {
                handle: ObjectHandle(handle as u64),
                readiness: ReadinessFlags::READ,
            }
        );
    }

    drop(finish_sender);
    drop(local);
    expect_publication_ended(&outcome_receiver);
    host.join().unwrap();
}

#[test]
fn a_clean_local_close_ends_a_publisher_blocked_on_a_full_ring() {
    let (local_control, host_control) = UnixStream::pair().unwrap();
    let (published_sender, published_receiver) = channel::<()>();
    let (outcome_sender, outcome_receiver) = channel();

    let host = spawn_host(host_control, move |mut notifications, _shutdown| {
        let runtime = Arc::new(ReadinessPublisherRuntime::new());
        let publishing = Arc::clone(&runtime);
        let publisher = std::thread::spawn(move || publishing.run(&mut notifications));

        for handle in 0..OVERSUBSCRIBED_OBJECT_COUNT {
            runtime
                .publish(ObjectHandle(handle), ReadinessFlags::READ)
                .unwrap();
        }
        published_sender.send(()).unwrap();

        // The publisher is blocked on notification-ring capacity that the local
        // endpoint will never make available. Only teardown can end it.
        outcome_sender.send(publisher.join().unwrap()).unwrap();
    });

    let (local, notifications) = negotiate_local(local_control);
    published_receiver.recv_timeout(TEST_TIMEOUT).unwrap();
    drop(notifications);
    drop(local);

    let outcome = outcome_receiver.recv_timeout(TEST_TIMEOUT).unwrap();
    let error = outcome.expect_err("a closed association must end the blocked publisher");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe,
        "a closed peer must end publication as a closure rather than a transport failure, got {error:?}"
    );
    host.join().unwrap();
}
