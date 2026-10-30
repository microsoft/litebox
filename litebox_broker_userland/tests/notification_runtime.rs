// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use std::sync::mpsc::{Receiver, channel};
use std::thread::JoinHandle;
use std::time::Duration;

use litebox_broker_core::test_support::TestBrokerCoreBuilder;
use litebox_broker_core::{ObjectRights, PolicyEngine};
use litebox_broker_host::{BrokerHostAssociation, setup_connection};
use litebox_broker_local::{BrokerLocal, BrokerNotifications};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::FileOpenFlags;
use litebox_broker_protocol::message::{BrokerNotification, ReadinessNotification};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE};
use litebox_broker_transport::channel::{HostNotificationChannel, HostReceive};
use litebox_broker_transport::control_ring::{
    CONTROL_RING_NOTIFICATION_SLOT_COUNT, ControlRing, ControlRingLayout,
};
use litebox_broker_transport::shared_memory::SharedBufferPool;
#[cfg(target_os = "linux")]
use litebox_broker_transport_linux_userland as transport;
#[cfg(target_os = "macos")]
use litebox_broker_transport_macos_userland as transport;
use litebox_broker_userland::readiness::ReadinessPublisherRuntime;
#[cfg(target_os = "linux")]
use transport::memfd::MemfdSharedMemory as UnixSharedMemory;
#[cfg(target_os = "macos")]
use transport::shared_memory::MacosSharedMemory as UnixSharedMemory;
use transport::unix_socket::{
    UnixControlRingHostCallLaneSource, UnixControlRingHostNotificationChannel,
    UnixControlRingHostShutdown, UnixStreamHostSetupChannel,
};
use transport::unix_socket::{
    UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
    UnixStreamLocalSetupChannel,
};

/// Long enough that a hung wakeup fails the test instead of hanging CI.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Long enough for the local endpoint to reach its blocking receive.
const BLOCK_DELAY: Duration = Duration::from_millis(50);
/// More objects than the notification ring holds, so publication must block.
const OVERSUBSCRIBED_OBJECT_COUNT: u64 = CONTROL_RING_NOTIFICATION_SLOT_COUNT * 3;
/// Layout of every test association's control ring.
const LAYOUT: ControlRingLayout = ControlRingLayout::MULTI_LANE;

/// Sends `memory` during setup with this host's shared-memory transfer.
fn send_setup_memory(
    channel: &mut UnixStreamHostSetupChannel,
    memory: &UnixSharedMemory,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        channel.send_memfd(memory, None)
    }
    #[cfg(target_os = "macos")]
    {
        channel.send_shared_memory(memory, None)
    }
}

/// Receives the shared-buffer pool during setup with this host's shared-memory transfer.
fn receive_setup_pool(
    setup: &mut UnixStreamLocalSetupChannel,
) -> std::io::Result<UnixSharedMemory> {
    #[cfg(target_os = "linux")]
    {
        setup.receive_memfd(SHARED_BUFFER_POOL_SIZE, None)
    }
    #[cfg(target_os = "macos")]
    {
        setup.receive_shared_memory(SHARED_BUFFER_POOL_SIZE, None)
    }
}

/// Serves each call lane the local endpoint starts using on its own thread,
/// until the association ends: `Ok` if the local endpoint closed it.
fn serve_lanes(
    mut lanes: UnixControlRingHostCallLaneSource,
    association: &BrokerHostAssociation<UnixSharedMemory>,
) -> std::io::Result<()> {
    std::thread::scope(|scope| {
        while let Some(mut lane) = lanes.next_lane()? {
            scope.spawn(move || {
                while let Ok(HostReceive::Message(request)) = lane.recv_request() {
                    association
                        .execute_request(request, |response| lane.send_response(response))
                        .unwrap();
                }
            });
        }
        Ok(())
    })
}

/// Runs one host association whose only traffic is readiness notifications.
///
/// Its call lanes are served as in production, so the association ends when
/// the local endpoint closes it.
fn spawn_host(
    stream: UnixStream,
    host: impl FnOnce(UnixControlRingHostNotificationChannel, UnixControlRingHostShutdown)
    + Send
    + 'static,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let shared_memory = UnixSharedMemory::create(SHARED_BUFFER_POOL_SIZE).unwrap();
        let shared_buffers =
            Arc::new(SharedBufferPool::new(shared_memory, SHARED_BUFFER_LAYOUT).unwrap());
        let control_memory = UnixSharedMemory::create_control_ring(LAYOUT).unwrap();
        let control_ring = ControlRing::new(control_memory, LAYOUT).unwrap();
        let mut control = UnixStreamHostSetupChannel::from_accepted(stream);
        let association = setup_connection(
            &broker,
            None,
            None,
            &mut control,
            Arc::clone(&shared_buffers),
            Arc::new(ReadinessPublisherRuntime::new()),
            |_| false,
            |channel| {
                send_setup_memory(channel, shared_buffers.memory())?;
                send_setup_memory(channel, control_ring.memory())
            },
        )
        .unwrap()
        .unwrap();
        let (lanes, notifications, shutdown) = control.into_active(control_ring).unwrap();
        std::thread::scope(|scope| {
            // Dropping `shutdown` when `host` returns can end the association
            // before the local endpoint closes it.
            scope.spawn(|| {
                let _ = serve_lanes(lanes, &association);
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
    let (local, _startup, notifications) = BrokerLocal::negotiate(
        UnixStreamLocalSetupChannel::from_connected(stream),
        |mut setup| {
            let shared_memory = receive_setup_pool(&mut setup)?;
            let control_memory = setup.receive_control_ring(LAYOUT, None)?;
            let control_ring = ControlRing::new(control_memory, LAYOUT).map_err(|error| {
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
    let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
    .build()
    .unwrap();
    let (local_control, host_control) = UnixStream::pair().unwrap();
    let host_shared_memory = UnixSharedMemory::create(SHARED_BUFFER_POOL_SIZE).unwrap();
    let host_shared_buffers =
        Arc::new(SharedBufferPool::new(host_shared_memory, SHARED_BUFFER_LAYOUT).unwrap());
    let host_control_memory = UnixSharedMemory::create_control_ring(LAYOUT).unwrap();
    let host_control_ring = ControlRing::new(host_control_memory, LAYOUT).unwrap();
    let notification = BrokerNotification::Readiness(ReadinessNotification {
        handle: ObjectHandle(7),
        readiness: ReadinessFlags::READ,
    });
    let host_notification = notification.clone();

    let host_thread = std::thread::spawn(move || {
        let mut control = UnixStreamHostSetupChannel::from_accepted(host_control);
        let association = setup_connection(
            &broker,
            None,
            None,
            &mut control,
            Arc::clone(&host_shared_buffers),
            Arc::new(ReadinessPublisherRuntime::new()),
            |_| false,
            |channel| {
                send_setup_memory(channel, host_shared_buffers.memory())?;
                send_setup_memory(channel, host_control_ring.memory())
            },
        )
        .unwrap()
        .unwrap();
        let (lanes, mut notifications, _shutdown) = control.into_active(host_control_ring).unwrap();
        notifications.send_notification(&host_notification).unwrap();
        serve_lanes(lanes, &association)
    });

    let (local, _startup, notification_channel) = BrokerLocal::negotiate(
        UnixStreamLocalSetupChannel::from_connected(local_control),
        |mut setup| {
            let shared_memory = receive_setup_pool(&mut setup)?;
            let control_memory = setup.receive_control_ring(LAYOUT, None)?;
            let control_ring = ControlRing::new(control_memory, LAYOUT).map_err(|error| {
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

    let handle = local
        .create_event_with_count(0, FileOpenFlags::NONE)
        .unwrap();
    let readiness = ReadinessFlags::READ | ReadinessFlags::WRITE;
    assert_eq!(local.add_event(handle, 1).unwrap(), readiness);

    drop(local);
    host_thread
        .join()
        .unwrap()
        .expect("the host must see a clean close");
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
