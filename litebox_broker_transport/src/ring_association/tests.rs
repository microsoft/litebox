// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Condvar, Mutex};

use litebox_broker_protocol::message::{BrokerOperation, BrokerRequest};
use litebox_broker_protocol::wire::{decode_request, encode_request};
use litebox_broker_protocol::{ObjectHandle, RequestId};

use super::*;
use crate::channel::{HostReceive, LocalCallChannel, LocalNotificationChannel};
use crate::control_ring::{
    ControlRing, ControlRingLayout, ControlRingProducer, ControlRingReadStatus,
    ControlRingWriteStatus, LocalControlRingEndpoints, WaitableSharedMemory,
};
use crate::shared_memory::{ControlRingMemory, SharedMemory, SharedMemoryError};

const LAYOUT: ControlRingLayout = ControlRingLayout::MULTI_LANE;

/// Control-ring memory that endpoints share by cloning, whose waits return at
/// once.
#[derive(Clone)]
struct TestMemory(Arc<Mutex<Vec<u8>>>);

impl TestMemory {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(vec![0; LAYOUT.memory_size()])))
    }

    fn with_range<const N: usize, T>(
        &self,
        offset: usize,
        access: impl FnOnce(&mut [u8; N]) -> T,
    ) -> Result<T, SharedMemoryError> {
        if !offset.is_multiple_of(N) {
            return Err(SharedMemoryError::UnalignedWord);
        }
        let mut bytes = self.0.lock().unwrap();
        let end = offset
            .checked_add(N)
            .ok_or(SharedMemoryError::InvalidRange)?;
        let range = bytes
            .get_mut(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?;
        Ok(access(range.try_into().unwrap()))
    }
}

impl SharedMemory for TestMemory {
    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        let bytes = self.0.lock().unwrap();
        let end = offset
            .checked_add(destination.len())
            .ok_or(SharedMemoryError::InvalidRange)?;
        destination.copy_from_slice(
            bytes
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?,
        );
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        let mut bytes = self.0.lock().unwrap();
        let end = offset
            .checked_add(source.len())
            .ok_or(SharedMemoryError::InvalidRange)?;
        bytes
            .get_mut(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?
            .copy_from_slice(source);
        Ok(())
    }
}

impl ControlRingMemory for TestMemory {
    fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
        self.with_range(offset, |bytes| u32::from_ne_bytes(*bytes))
    }

    fn increment_u32_release(&self, offset: usize) -> Result<(), SharedMemoryError> {
        self.with_range(offset, |bytes| {
            *bytes = u32::from_ne_bytes(*bytes).wrapping_add(1).to_ne_bytes();
        })
    }

    fn store_u32_release(&self, offset: usize, value: u32) -> Result<(), SharedMemoryError> {
        self.with_range(offset, |bytes| *bytes = value.to_ne_bytes())
    }

    fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
        self.with_range(offset, |bytes| u64::from_ne_bytes(*bytes))
    }

    fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
        self.with_range(offset, |bytes| *bytes = value.to_ne_bytes())
    }

    fn store_u64_and_increment_u32_release(
        &self,
        store_offset: usize,
        value: u64,
        increment_offset: usize,
    ) -> Result<(), SharedMemoryError> {
        self.load_u32_acquire(increment_offset)?;
        self.store_u64_release(store_offset, value)?;
        self.increment_u32_release(increment_offset)
    }
}

impl WaitableSharedMemory for TestMemory {
    type Error = Error;

    fn wait_access_error(error: SharedMemoryError) -> Error {
        Error::new(ErrorKind::InvalidData, error)
    }

    fn wait_while_equal(&self, _offset: usize, _expected: u32) -> Result<(), Error> {
        Ok(())
    }

    fn wake_one(&self, _offset: usize) -> Result<(), Error> {
        Ok(())
    }
}

/// A setup stream whose peer acknowledges the ring and stays open until the
/// stream is shut down.
struct TestStream {
    ready: Option<Vec<u8>>,
    shut_down: Arc<(Mutex<bool>, Condvar)>,
}

fn test_stream() -> Box<dyn AssociationStream> {
    Box::new(TestStream {
        ready: Some(LAYOUT.ready_token().to_vec()),
        shut_down: Arc::default(),
    })
}

impl AssociationStream for TestStream {
    fn read_frame(&mut self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.ready.take())
    }

    fn write_frame(&mut self, _frame: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn wait_for_close(&self) -> Result<(), Error> {
        let (shut_down, changed) = &*self.shut_down;
        drop(
            changed
                .wait_while(shut_down.lock().unwrap(), |shut_down| !*shut_down)
                .unwrap(),
        );
        Ok(())
    }

    fn shutdown(&self) -> Result<(), Error> {
        let (shut_down, changed) = &*self.shut_down;
        *shut_down.lock().unwrap() = true;
        changed.notify_all();
        Ok(())
    }
}

fn ring_pair() -> (ControlRing<TestMemory>, ControlRing<TestMemory>) {
    let memory = TestMemory::new();
    (
        ControlRing::new(memory.clone(), LAYOUT).unwrap(),
        ControlRing::new(memory, LAYOUT).unwrap(),
    )
}

/// Activates a host association and takes its always-demanded first lane.
fn activate_host_lane() -> (
    ControlRingHostCallLane<TestMemory>,
    ControlRingHostShutdown<TestMemory>,
    LocalControlRingEndpoints<TestMemory>,
) {
    let (local_ring, host_ring) = ring_pair();
    let (mut lanes, _notifications, shutdown) = activate_host(host_ring, test_stream()).unwrap();
    let lane = lanes.next_lane().unwrap().unwrap();
    (lane, shutdown, local_ring.into_local())
}

fn write_payload(producer: &mut ControlRingProducer<TestMemory>, payload: &[u8]) {
    assert_eq!(
        producer.try_write(payload).unwrap(),
        ControlRingWriteStatus::Written
    );
    producer.wake_consumer().unwrap();
}

fn request(id: u64) -> BrokerRequest {
    BrokerRequest {
        request_id: RequestId(id),
        operation: BrokerOperation::CloseObject(ObjectHandle(id)),
    }
}

#[test]
fn host_failure_preempts_queued_and_decoded_requests_but_peer_close_drains() {
    let (mut lane, _shutdown, mut local) = activate_host_lane();
    write_payload(
        &mut local.lanes[0].request_producer,
        &encode_request(request(1)),
    );
    lane.association
        .fail(Error::new(ErrorKind::TimedOut, "test failure"))
        .unwrap();
    assert_eq!(lane.recv_request().unwrap_err().kind(), ErrorKind::TimedOut);

    let (mut lane, _shutdown, mut local) = activate_host_lane();
    write_payload(
        &mut local.lanes[0].request_producer,
        &encode_request(request(2)),
    );
    assert!(matches!(
        lane.lane.request_consumer.try_read(decode_request).unwrap(),
        ControlRingReadStatus::Message(_)
    ));
    lane.association
        .fail(Error::new(ErrorKind::TimedOut, "test failure"))
        .unwrap();
    assert_eq!(
        lane.association
            .acknowledge_request(&mut lane.lane.request_consumer)
            .unwrap_err()
            .kind(),
        ErrorKind::TimedOut
    );

    let (mut lane, _shutdown, mut local) = activate_host_lane();
    write_payload(
        &mut local.lanes[0].request_producer,
        &encode_request(request(3)),
    );
    lane.association.peer_closed();
    assert!(matches!(
        lane.recv_request().unwrap(),
        HostReceive::Message(BrokerRequest {
            request_id: RequestId(3),
            ..
        })
    ));
    assert_eq!(lane.recv_request().unwrap(), HostReceive::PeerClosed);
}

#[test]
fn malformed_notification_fails_the_association() {
    let (local_ring, host_ring) = ring_pair();
    let (control, mut local, _shutdown) = activate_local(local_ring, test_stream(), || {}).unwrap();
    write_payload(&mut host_ring.into_host().notification_producer, &[0xff]);

    assert_eq!(
        local.recv_notification().unwrap_err().kind(),
        ErrorKind::InvalidData
    );
    // The local association is failed, so it refuses further calls without
    // ever reaching the ring.
    assert!(control.call(request(1)).is_err());
}
