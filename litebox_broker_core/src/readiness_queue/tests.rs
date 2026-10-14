// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::event::EventConsumeMode;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileOpenFlags, FileStatusFlags, SetStatusFlagsRequest,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::readiness_queue::{
    ReadinessQueueEntryFlags, ReadinessQueueError, ReadinessQueueInterest, ReadyEvent,
};

use crate::readiness::ReadinessSink;
use crate::readiness::tests::TestReadinessSink;
use crate::test_support::TestBrokerCoreBuilder;
use crate::{
    BrokerCoreLimits, BrokerError, BrokerProcess, CallerCredential, ObjectRights, PolicyEngine,
};

fn builder() -> TestBrokerCoreBuilder {
    TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
}

fn process(builder: TestBrokerCoreBuilder) -> Arc<BrokerProcess> {
    builder
        .build()
        .unwrap()
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap()
}

fn create(process: &BrokerProcess, sink: &Arc<TestReadinessSink>) -> ObjectHandle {
    super::create(process, &(sink.clone() as Arc<dyn ReadinessSink>)).unwrap()
}

fn interest(
    readiness: ReadinessFlags,
    flags: ReadinessQueueEntryFlags,
    token: u64,
) -> ReadinessQueueInterest {
    ReadinessQueueInterest {
        readiness,
        flags,
        token,
    }
}

fn read_interest(token: u64) -> ReadinessQueueInterest {
    interest(
        ReadinessFlags::READ,
        ReadinessQueueEntryFlags::empty(),
        token,
    )
}

fn event(token: u64, readiness: ReadinessFlags) -> ReadyEvent {
    ReadyEvent { token, readiness }
}

fn take(process: &BrokerProcess, queue: ObjectHandle) -> Vec<ReadyEvent> {
    super::take_ready(process, queue, 16).unwrap()
}

fn event_counter(process: &BrokerProcess, count: u64) -> ObjectHandle {
    crate::event::create(process, count, FileOpenFlags::NONE).unwrap()
}

fn entries(process: &BrokerProcess) -> usize {
    process.readiness_queue_entries.load(Ordering::Relaxed)
}

#[test]
fn level_triggered_entries_report_while_their_targets_stay_ready() {
    let process = process(builder());
    let sink = Arc::new(TestReadinessSink::default());
    let queue = create(&process, &sink);
    let (read, write) = crate::pipe::create(&process, 16, 1, FileOpenFlags::NONE).unwrap();
    let woken = || sink.republished.lock().unwrap().len();

    super::add(&process, queue, read, 3, read_interest(7))
        .unwrap()
        .unwrap();
    assert_eq!(take(&process, queue), []);
    assert_eq!(
        process.check_readiness(queue),
        Ok(ReadinessFlags::default())
    );
    assert_eq!(woken(), 0);

    crate::pipe::write(&process, write, b"ab").unwrap();
    assert_eq!(
        *sink.republished.lock().unwrap(),
        [(queue, ReadinessFlags::READ)]
    );
    assert_eq!(process.check_readiness(queue), Ok(ReadinessFlags::READ));
    assert_eq!(take(&process, queue), [event(7, ReadinessFlags::READ)]);
    // Queueing the entry again for the next take wakes no one.
    assert_eq!(woken(), 1);
    assert_eq!(take(&process, queue), [event(7, ReadinessFlags::READ)]);

    crate::pipe::read(&process, read, 2).unwrap();
    assert_eq!(take(&process, queue), []);
    assert_eq!(
        process.check_readiness(queue),
        Ok(ReadinessFlags::default())
    );

    // Only readiness within the interest is reported.
    super::modify(
        &process,
        queue,
        read,
        3,
        interest(
            ReadinessFlags::READ | ReadinessFlags::CLOSED,
            ReadinessQueueEntryFlags::empty(),
            8,
        ),
    )
    .unwrap()
    .unwrap();
    process.close_object_reference(write).unwrap();
    assert_eq!(take(&process, queue), [event(8, ReadinessFlags::CLOSED)]);
}

#[test]
fn edge_triggered_entries_report_once_per_publication() {
    let process = process(builder());
    let sink = Arc::new(TestReadinessSink::default());
    let queue = create(&process, &sink);
    let counter = event_counter(&process, 1);
    let edge = interest(
        ReadinessFlags::READ,
        ReadinessQueueEntryFlags::EDGE_TRIGGERED,
        1,
    );

    super::add(&process, queue, counter, 0, edge)
        .unwrap()
        .unwrap();
    assert_eq!(take(&process, queue), [event(1, ReadinessFlags::READ)]);
    assert_eq!(take(&process, queue), []);

    // Each change queues the entry again, even if it stays readable.
    crate::event::add(&process, counter, 1).unwrap();
    assert_eq!(take(&process, queue), [event(1, ReadinessFlags::READ)]);
    assert_eq!(take(&process, queue), []);

    // A publication the target no longer matches by the take reports nothing.
    crate::event::add(&process, counter, 1).unwrap();
    crate::event::consume(&process, counter, EventConsumeMode::All).unwrap();
    assert_eq!(take(&process, queue), []);
}

#[test]
fn one_shot_entries_are_disabled_until_modified() {
    let process = process(builder());
    let sink = Arc::new(TestReadinessSink::default());
    let queue = create(&process, &sink);
    let counter = event_counter(&process, 1);
    let one_shot = |token| {
        interest(
            ReadinessFlags::READ,
            ReadinessQueueEntryFlags::ONE_SHOT,
            token,
        )
    };

    super::add(&process, queue, counter, 0, one_shot(4))
        .unwrap()
        .unwrap();
    assert_eq!(take(&process, queue), [event(4, ReadinessFlags::READ)]);
    assert_eq!(take(&process, queue), []);
    crate::event::add(&process, counter, 1).unwrap();
    assert_eq!(take(&process, queue), []);

    super::modify(&process, queue, counter, 0, one_shot(5))
        .unwrap()
        .unwrap();
    assert_eq!(take(&process, queue), [event(5, ReadinessFlags::READ)]);
    assert_eq!(take(&process, queue), []);
}

#[test]
fn takes_are_bounded_and_resume_where_they_stopped() {
    let process = process(builder());
    let sink = Arc::new(TestReadinessSink::default());
    let queue = create(&process, &sink);
    let first = event_counter(&process, 1);
    let second = event_counter(&process, 1);
    super::add(&process, queue, first, 0, read_interest(1))
        .unwrap()
        .unwrap();
    super::add(&process, queue, second, 0, read_interest(2))
        .unwrap()
        .unwrap();

    assert_eq!(
        super::take_ready(&process, queue, 1),
        Ok(alloc::vec![event(1, ReadinessFlags::READ)])
    );
    assert_eq!(
        super::take_ready(&process, queue, 1),
        Ok(alloc::vec![event(2, ReadinessFlags::READ)])
    );
    assert_eq!(
        take(&process, queue),
        [
            event(1, ReadinessFlags::READ),
            event(2, ReadinessFlags::READ)
        ]
    );
}

#[test]
fn entries_are_identified_by_target_and_key() {
    let process = process(builder());
    let sink = Arc::new(TestReadinessSink::default());
    let queue = create(&process, &sink);
    let first = event_counter(&process, 1);
    let second = event_counter(&process, 0);

    super::add(&process, queue, first, 1, read_interest(1))
        .unwrap()
        .unwrap();
    assert_eq!(
        super::add(&process, queue, first, 1, read_interest(9)),
        Ok(Err(ReadinessQueueError::AlreadyRegistered))
    );
    super::add(&process, queue, first, 2, read_interest(2))
        .unwrap()
        .unwrap();
    super::add(&process, queue, second, 1, read_interest(3))
        .unwrap()
        .unwrap();
    assert_eq!(
        super::modify(&process, queue, second, 2, read_interest(4)),
        Ok(Err(ReadinessQueueError::NotRegistered))
    );

    // Removing a queued entry also removes it from the ready entries.
    super::remove(&process, queue, first, 1).unwrap().unwrap();
    assert_eq!(
        super::remove(&process, queue, first, 1),
        Ok(Err(ReadinessQueueError::NotRegistered))
    );
    assert_eq!(take(&process, queue), [event(2, ReadinessFlags::READ)]);
    super::remove(&process, queue, first, 2).unwrap().unwrap();
    assert_eq!(take(&process, queue), []);
    assert_eq!(
        process.check_readiness(queue),
        Ok(ReadinessFlags::default())
    );
    assert_eq!(entries(&process), 1);
}

#[test]
fn objects_without_published_readiness_cannot_be_watched() {
    let process = process(builder());
    let sink = Arc::new(TestReadinessSink::default());
    let queue = create(&process, &sink);
    let other = create(&process, &sink);
    let signals = crate::signal::open(&process, sink.clone() as Arc<dyn ReadinessSink>).unwrap();

    for target in [queue, other, signals] {
        assert_eq!(
            super::add(&process, queue, target, 0, read_interest(0)),
            Err(BrokerError::UnsupportedOperation)
        );
    }
    assert_eq!(entries(&process), 0);
    assert_eq!(
        super::add(&process, signals, queue, 0, read_interest(0)),
        Err(BrokerError::InvalidRights)
    );
}

#[test]
fn entries_of_closed_targets_are_removed() {
    let process = process(
        builder().with_limits(BrokerCoreLimits::DEFAULT.with_readiness_queue_limits(16, 2)),
    );
    let sink = Arc::new(TestReadinessSink::default());
    let queue = create(&process, &sink);
    let ready = event_counter(&process, 1);
    let idle = event_counter(&process, 0);
    let third = event_counter(&process, 0);
    let fourth = event_counter(&process, 1);
    super::add(&process, queue, ready, 0, read_interest(1))
        .unwrap()
        .unwrap();
    super::add(&process, queue, idle, 0, read_interest(2))
        .unwrap()
        .unwrap();
    assert_eq!(
        super::add(&process, queue, third, 0, read_interest(3)),
        Err(BrokerError::ResourceExhausted)
    );

    // A queued entry is removed when taken after its target closes.
    process.close_object_reference(ready).unwrap();
    assert_eq!(take(&process, queue), []);
    assert_eq!(entries(&process), 1);

    // An idle one lingers until the quota runs out.
    process.close_object_reference(idle).unwrap();
    super::add(&process, queue, third, 0, read_interest(3))
        .unwrap()
        .unwrap();
    super::add(&process, queue, fourth, 0, read_interest(4))
        .unwrap()
        .unwrap();
    assert_eq!(entries(&process), 2);
    assert_eq!(take(&process, queue), [event(4, ReadinessFlags::READ)]);

    // Closing the queue releases its entries.
    process.close_object_reference(queue).unwrap();
    assert_eq!(entries(&process), 0);
    assert_eq!(
        process.core.readiness_queue_entries.load(Ordering::Relaxed),
        0
    );
}

#[test]
fn queues_are_shared_by_every_process_holding_them() {
    let broker = builder().build().unwrap();
    let parent = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let child = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let parent_sink = Arc::new(TestReadinessSink::default());
    let child_sink = Arc::new(TestReadinessSink::default());
    let queue = create(&parent, &parent_sink);
    let counter = event_counter(&parent, 0);
    let child_queue = parent
        .duplicate_object_reference_to(queue, &child, ObjectRights::all())
        .unwrap();
    let child_counter = parent
        .duplicate_object_reference_to(counter, &child, ObjectRights::all())
        .unwrap();
    child
        .register_readiness(&(child_sink.clone() as Arc<dyn ReadinessSink>))
        .unwrap();

    // An entry added through either reference is visible through the other,
    // and its target's changes wake both.
    super::add(&child, child_queue, child_counter, 5, read_interest(6))
        .unwrap()
        .unwrap();
    assert_eq!((entries(&parent), entries(&child)), (0, 1));
    assert_eq!(
        super::add(&parent, queue, counter, 5, read_interest(6)),
        Ok(Err(ReadinessQueueError::AlreadyRegistered))
    );
    crate::event::add(&parent, counter, 1).unwrap();
    assert_eq!(
        *parent_sink.republished.lock().unwrap(),
        [(queue, ReadinessFlags::READ)]
    );
    assert!(
        child_sink
            .republished
            .lock()
            .unwrap()
            .contains(&(child_queue, ReadinessFlags::READ))
    );
    assert_eq!(take(&parent, queue), [event(6, ReadinessFlags::READ)]);
    assert_eq!(take(&child, child_queue), [event(6, ReadinessFlags::READ)]);

    // The entry outlives the parent's references to the queue and target.
    parent.close_object_reference(queue).unwrap();
    parent.close_object_reference(counter).unwrap();
    assert_eq!(take(&child, child_queue), [event(6, ReadinessFlags::READ)]);
    super::remove(&child, child_queue, child_counter, 5)
        .unwrap()
        .unwrap();
    assert_eq!(entries(&child), 0);
}

#[test]
fn queue_status_flags_are_shared() {
    let broker = builder().build().unwrap();
    let parent = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let child = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let sink = Arc::new(TestReadinessSink::default());
    let queue = create(&parent, &sink);
    let child_queue = parent
        .duplicate_object_reference_to(queue, &child, ObjectRights::all())
        .unwrap();

    assert_eq!(
        parent.get_status_flags(queue),
        Ok(FileStatusFlags {
            access: FileAccessMode::ReadWrite,
            flags: FileOpenFlags::NONE,
        })
    );
    child
        .set_status_flags(SetStatusFlagsRequest {
            handle: child_queue,
            mask: FileOpenFlags::NONBLOCKING,
            flags: FileOpenFlags::NONBLOCKING,
        })
        .unwrap();
    assert_eq!(
        parent.get_status_flags(queue).unwrap().flags,
        FileOpenFlags::NONBLOCKING
    );
}
