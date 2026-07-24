// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hostile-peer-safe shared control-ring state machines.

use alloc::sync::Arc;
use core::mem::size_of;
use core::ops::Range;
#[cfg(test)]
use core::sync::atomic::fence;

#[cfg(test)]
use litebox_broker_protocol::shared_memory::SharedMemory;
use litebox_broker_protocol::shared_memory::{AtomicSharedMemory, SharedMemoryError};

/// Size of one shared control-ring slot.
pub const CONTROL_RING_SLOT_SIZE: usize = 128;

/// Size of the fixed metadata at the start of a control-ring slot.
pub const CONTROL_RING_SLOT_HEADER_SIZE: usize = 16;

/// Maximum encoded control message size in one ring slot.
pub const CONTROL_RING_PAYLOAD_CAPACITY: usize =
    CONTROL_RING_SLOT_SIZE - CONTROL_RING_SLOT_HEADER_SIZE;

const _: () = assert!(
    CONTROL_RING_PAYLOAD_CAPACITY >= litebox_broker_protocol::wire::MAX_ENCODED_ACTIVE_MESSAGE_SIZE
);
const _: () = assert!(
    CONTROL_RING_PAYLOAD_CAPACITY >= litebox_broker_protocol::wire::MAX_ENCODED_NOTIFICATION_SIZE
);
const _: () = assert!(CONTROL_RING_SLOT_SIZE.is_multiple_of(size_of::<u64>()));

/// Number of slots in each request or response direction.
pub const CONTROL_RING_SLOT_COUNT: u64 = 64;

/// Number of slots in the broker-to-local notification direction.
pub const CONTROL_RING_NOTIFICATION_SLOT_COUNT: u64 = 64;

/// Exact shared-memory size required for all association control directions.
pub const CONTROL_RING_MEMORY_SIZE: usize =
    CONTROL_RING_DATA_SIZE + CONTROL_RING_SYNC_DIRECTION_SIZE * 3;

// The fixed count is representable by `usize` on every supported target.
#[allow(clippy::cast_possible_truncation)]
const CONTROL_RING_DIRECTION_SIZE: usize =
    CONTROL_RING_SLOT_SIZE * CONTROL_RING_SLOT_COUNT as usize;
// The fixed count is representable by `usize` on every supported target.
#[allow(clippy::cast_possible_truncation)]
const CONTROL_RING_NOTIFICATION_DIRECTION_SIZE: usize =
    CONTROL_RING_SLOT_SIZE * CONTROL_RING_NOTIFICATION_SLOT_COUNT as usize;
const CONTROL_RING_DATA_SIZE: usize =
    CONTROL_RING_DIRECTION_SIZE * 2 + CONTROL_RING_NOTIFICATION_DIRECTION_SIZE;
const CONTROL_RING_SYNC_DIRECTION_SIZE: usize = 16;
const PRODUCER_EPOCH_OFFSET: usize = 0;
const CONSUMER_EPOCH_OFFSET: usize = 4;
const CONSUMER_HEAD_OFFSET: usize = 8;

/// One direction in the shared control-ring mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlRingDirection {
    /// Local-to-broker request ring.
    Requests,
    /// Broker-to-local response ring.
    Responses,
    /// Broker-to-local asynchronous notification ring.
    Notifications,
}

impl ControlRingDirection {
    fn slot_range(self, slot: u64) -> Range<usize> {
        debug_assert!(slot < self.slot_count());
        let slot = usize::try_from(slot).expect("control-ring slot index is bounded");
        let data_offset = match self {
            Self::Requests => 0,
            Self::Responses => CONTROL_RING_DIRECTION_SIZE,
            Self::Notifications => CONTROL_RING_DIRECTION_SIZE * 2,
        };
        let start = data_offset + slot * CONTROL_RING_SLOT_SIZE;
        start..start + CONTROL_RING_SLOT_SIZE
    }

    /// Returns the number of slots in this direction.
    pub const fn slot_count(self) -> u64 {
        match self {
            Self::Requests | Self::Responses => CONTROL_RING_SLOT_COUNT,
            Self::Notifications => CONTROL_RING_NOTIFICATION_SLOT_COUNT,
        }
    }

    /// Returns the atomic `u32` epoch incremented when the producer publishes
    /// work for this direction.
    pub const fn producer_epoch_offset(self) -> usize {
        self.sync_offset() + PRODUCER_EPOCH_OFFSET
    }

    /// Returns the atomic `u32` epoch incremented when the consumer publishes
    /// progress for this direction.
    pub const fn consumer_epoch_offset(self) -> usize {
        self.sync_offset() + CONSUMER_EPOCH_OFFSET
    }

    /// Returns the atomic `u64` consumer-head offset for this direction.
    pub const fn consumer_head_offset(self) -> usize {
        self.sync_offset() + CONSUMER_HEAD_OFFSET
    }

    const fn sync_offset(self) -> usize {
        CONTROL_RING_DATA_SIZE
            + match self {
                Self::Requests => 0,
                Self::Responses => CONTROL_RING_SYNC_DIRECTION_SIZE,
                Self::Notifications => CONTROL_RING_SYNC_DIRECTION_SIZE * 2,
            }
    }
}

/// Error validating or accessing shared control-ring state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlRingError {
    /// The backing shared-memory length is not the exact control-ring size.
    MemoryLengthMismatch {
        /// Required mapping length.
        expected: usize,
        /// Actual mapping length.
        actual: usize,
    },
    /// An empty encoded envelope cannot be written to the ring.
    EmptyPayload,
    /// The encoded envelope does not fit in one ring slot.
    PayloadTooLarge {
        /// Supplied envelope length.
        length: usize,
    },
    /// A peer progress counter moved backward.
    CounterRegressed {
        /// Last accepted counter value.
        previous: u64,
        /// Newly received counter value.
        received: u64,
    },
    /// A peer progress counter violates the locally known ring window.
    CounterOutOfRange {
        /// Trusted local counter bounding the received value.
        local: u64,
        /// Newly received counter value.
        received: u64,
    },
    /// The non-wrapping absolute slot sequence is exhausted.
    CounterExhausted,
    /// A copied slot does not carry the expected absolute sequence.
    UnexpectedSequence {
        /// Sequence derived from trusted endpoint-local state.
        expected: u64,
        /// Sequence copied from the shared slot.
        actual: u64,
    },
    /// A copied slot has nonzero reserved metadata.
    NonzeroReserved {
        /// Reserved value copied from the shared slot.
        value: u32,
    },
    /// A copied slot has a zero or oversized payload length.
    InvalidPayloadLength {
        /// Length copied from the shared slot.
        length: u32,
    },
    /// The backing shared-memory access failed.
    SharedMemory(SharedMemoryError),
}

impl From<SharedMemoryError> for ControlRingError {
    fn from(error: SharedMemoryError) -> Self {
        Self::SharedMemory(error)
    }
}

/// Result of a nonblocking control-ring write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlRingWriteStatus {
    /// The payload and metadata were copied and the sequence was published.
    Written,
    /// The producer cannot reuse a slot until the peer acknowledges progress.
    Full {
        /// Consumer epoch sampled before the final full check.
        wait_epoch: u32,
    },
}

/// Result of a nonblocking control-ring read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlRingReadStatus<Message> {
    /// One complete slot was copied, validated, and decoded.
    Message(Message),
    /// The next slot still carries its previous sequence.
    Empty {
        /// Producer epoch sampled before the final empty check.
        wait_epoch: u32,
    },
}

/// Error copying, validating, or decoding one control-ring slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlRingReadError<DecodeError> {
    /// Ring metadata or shared-memory access is invalid.
    Ring(ControlRingError),
    /// The owned encoded envelope was rejected by its protocol decoder.
    Decode(DecodeError),
}

/// Exact-size shared memory containing request, response, and notification rings.
pub struct ControlRing<Memory: AtomicSharedMemory> {
    memory: Memory,
}

/// Role-bound association ring endpoints owned by the local peer.
pub struct LocalControlRingEndpoints<Memory: AtomicSharedMemory> {
    /// Local-to-broker request producer.
    pub request_producer: ControlRingProducer<Memory>,
    /// Broker-to-local response consumer.
    pub response_consumer: ControlRingConsumer<Memory>,
    /// Broker-to-local notification consumer.
    pub notification_consumer: ControlRingConsumer<Memory>,
}

/// Role-bound association ring endpoints owned by the broker peer.
pub struct BrokerControlRingEndpoints<Memory: AtomicSharedMemory> {
    /// Local-to-broker request consumer.
    pub request_consumer: ControlRingConsumer<Memory>,
    /// Broker-to-local response producer.
    pub response_producer: ControlRingProducer<Memory>,
    /// Broker-to-local notification producer.
    pub notification_producer: ControlRingProducer<Memory>,
}

impl<Memory: AtomicSharedMemory> ControlRing<Memory> {
    /// Attaches to an exact-size shared control-ring mapping.
    pub fn new(memory: Memory) -> Result<Self, ControlRingError> {
        let actual = memory.len();
        if actual != CONTROL_RING_MEMORY_SIZE {
            return Err(ControlRingError::MemoryLengthMismatch {
                expected: CONTROL_RING_MEMORY_SIZE,
                actual,
            });
        }
        Ok(Self { memory })
    }

    /// Returns the copy-only shared-memory resource.
    pub const fn memory(&self) -> &Memory {
        &self.memory
    }

    /// Consumes the mapping into endpoints owned by the local peer.
    pub fn into_local(self) -> LocalControlRingEndpoints<Memory> {
        let ring = Arc::new(self);
        LocalControlRingEndpoints {
            request_producer: ControlRingProducer::new(
                Arc::clone(&ring),
                ControlRingDirection::Requests,
            ),
            response_consumer: ControlRingConsumer::new(
                Arc::clone(&ring),
                ControlRingDirection::Responses,
            ),
            notification_consumer: ControlRingConsumer::new(
                ring,
                ControlRingDirection::Notifications,
            ),
        }
    }

    /// Consumes the mapping into endpoints owned by the broker peer.
    pub fn into_broker(self) -> BrokerControlRingEndpoints<Memory> {
        let ring = Arc::new(self);
        BrokerControlRingEndpoints {
            request_consumer: ControlRingConsumer::new(
                Arc::clone(&ring),
                ControlRingDirection::Requests,
            ),
            response_producer: ControlRingProducer::new(
                Arc::clone(&ring),
                ControlRingDirection::Responses,
            ),
            notification_producer: ControlRingProducer::new(
                ring,
                ControlRingDirection::Notifications,
            ),
        }
    }

    #[cfg(test)]
    fn into_endpoints(
        self,
        producer_direction: ControlRingDirection,
        consumer_direction: ControlRingDirection,
    ) -> (ControlRingProducer<Memory>, ControlRingConsumer<Memory>) {
        let ring = Arc::new(self);
        (
            ControlRingProducer::new(Arc::clone(&ring), producer_direction),
            ControlRingConsumer::new(ring, consumer_direction),
        )
    }

    fn write_slot(
        &self,
        direction: ControlRingDirection,
        position: u64,
        metadata: [u8; CONTROL_RING_SLOT_HEADER_SIZE - size_of::<u64>()],
        payload: &[u8],
        sequence: u64,
    ) -> Result<(), ControlRingError> {
        let slot = position % direction.slot_count();
        let range = direction.slot_range(slot);
        self.memory
            .write(range.start + CONTROL_RING_SLOT_HEADER_SIZE, payload)?;
        self.memory
            .write(range.start + size_of::<u64>(), &metadata)?;
        self.memory.store_u64_and_fetch_add_u32_release(
            range.start,
            sequence.to_le(),
            direction.producer_epoch_offset(),
            1,
        )?;
        Ok(())
    }

    fn load_sequence(
        &self,
        direction: ControlRingDirection,
        position: u64,
    ) -> Result<u64, ControlRingError> {
        let slot = position % direction.slot_count();
        let range = direction.slot_range(slot);
        Ok(u64::from_le(self.memory.load_u64_acquire(range.start)?))
    }

    fn read_slot_body(
        &self,
        direction: ControlRingDirection,
        position: u64,
        body: &mut [u8],
    ) -> Result<(), ControlRingError> {
        let slot = position % direction.slot_count();
        let range = direction.slot_range(slot);
        self.memory.read(range.start + size_of::<u64>(), body)?;
        Ok(())
    }

    fn load_producer_epoch(
        &self,
        direction: ControlRingDirection,
    ) -> Result<u32, ControlRingError> {
        Ok(self
            .memory
            .load_u32_acquire(direction.producer_epoch_offset())?)
    }

    fn load_consumer_epoch(
        &self,
        direction: ControlRingDirection,
    ) -> Result<u32, ControlRingError> {
        Ok(self
            .memory
            .load_u32_acquire(direction.consumer_epoch_offset())?)
    }

    fn load_consumer_head(&self, direction: ControlRingDirection) -> Result<u64, ControlRingError> {
        Ok(u64::from_le(
            self.memory
                .load_u64_acquire(direction.consumer_head_offset())?,
        ))
    }
}

/// Trusted endpoint-local state for one control-ring producer.
pub struct ControlRingProducer<Memory: AtomicSharedMemory> {
    ring: Arc<ControlRing<Memory>>,
    direction: ControlRingDirection,
    tail: u64,
    acknowledged_head: u64,
}

/// Cloneable, narrow handle for interrupting a wait on one ring endpoint.
///
/// This handle intentionally exposes neither the backing memory nor endpoint
/// state. Hosted transports use it to make liveness and cancellation events
/// visible to a thread blocked in an OS-specific wait.
#[cfg(any(test, all(feature = "linux-userland", target_os = "linux")))]
pub(crate) struct ControlRingWakeHandle<Memory: AtomicSharedMemory> {
    ring: Arc<ControlRing<Memory>>,
    wait_epoch: ControlRingWaitEpoch,
}

#[cfg(any(test, all(feature = "linux-userland", target_os = "linux")))]
#[derive(Clone, Copy)]
enum ControlRingWaitEpoch {
    Producer(ControlRingDirection),
    Consumer(ControlRingDirection),
}

#[cfg(any(test, all(feature = "linux-userland", target_os = "linux")))]
impl ControlRingWaitEpoch {
    const fn offset(self) -> usize {
        match self {
            Self::Producer(direction) => direction.producer_epoch_offset(),
            Self::Consumer(direction) => direction.consumer_epoch_offset(),
        }
    }
}

#[cfg(any(test, all(feature = "linux-userland", target_os = "linux")))]
impl<Memory: AtomicSharedMemory> Clone for ControlRingWakeHandle<Memory> {
    fn clone(&self) -> Self {
        Self {
            ring: Arc::clone(&self.ring),
            wait_epoch: self.wait_epoch,
        }
    }
}

#[cfg(any(test, all(feature = "linux-userland", target_os = "linux")))]
impl<Memory: AtomicSharedMemory> ControlRingWakeHandle<Memory> {
    pub(crate) const fn wait_epoch_offset(&self) -> usize {
        self.wait_epoch.offset()
    }

    pub(crate) fn memory(&self) -> &Memory {
        self.ring.memory()
    }
}

impl<Memory: AtomicSharedMemory> ControlRingProducer<Memory> {
    fn new(ring: Arc<ControlRing<Memory>>, direction: ControlRingDirection) -> Self {
        Self {
            ring,
            direction,
            tail: 0,
            acknowledged_head: 0,
        }
    }

    /// Returns the ring direction written by this producer.
    pub const fn direction(&self) -> ControlRingDirection {
        self.direction
    }

    #[cfg(any(test, all(feature = "linux-userland", target_os = "linux")))]
    pub(crate) fn wake_handle(&self) -> ControlRingWakeHandle<Memory> {
        ControlRingWakeHandle {
            ring: Arc::clone(&self.ring),
            wait_epoch: ControlRingWaitEpoch::Consumer(self.direction),
        }
    }

    #[cfg(any(test, all(feature = "linux-userland", target_os = "linux")))]
    pub(crate) fn memory(&self) -> &Memory {
        self.ring.memory()
    }

    fn refresh_head(&mut self) -> Result<(), ControlRingError> {
        let head = self.ring.load_consumer_head(self.direction)?;
        if head < self.acknowledged_head {
            return Err(ControlRingError::CounterRegressed {
                previous: self.acknowledged_head,
                received: head,
            });
        }
        if head > self.tail {
            return Err(ControlRingError::CounterOutOfRange {
                local: self.tail,
                received: head,
            });
        }
        self.acknowledged_head = head;
        Ok(())
    }

    /// Copies an encoded envelope and its header into the next available slot.
    pub fn try_write(
        &mut self,
        payload: &[u8],
    ) -> Result<ControlRingWriteStatus, ControlRingError> {
        if payload.is_empty() {
            return Err(ControlRingError::EmptyPayload);
        }
        if payload.len() > CONTROL_RING_PAYLOAD_CAPACITY {
            return Err(ControlRingError::PayloadTooLarge {
                length: payload.len(),
            });
        }
        if self.tail == u64::MAX {
            return Err(ControlRingError::CounterExhausted);
        }
        let slot_count = self.direction.slot_count();
        if self.tail - self.acknowledged_head == slot_count {
            let wait_epoch = self.ring.load_consumer_epoch(self.direction)?;
            self.refresh_head()?;
            if self.tail - self.acknowledged_head == slot_count {
                return Ok(ControlRingWriteStatus::Full { wait_epoch });
            }
        }

        let sequence = self.tail + 1;
        let length =
            u32::try_from(payload.len()).map_err(|_| ControlRingError::PayloadTooLarge {
                length: payload.len(),
            })?;
        let mut metadata = [0; CONTROL_RING_SLOT_HEADER_SIZE - size_of::<u64>()];
        metadata[..size_of::<u32>()].copy_from_slice(&length.to_le_bytes());
        self.ring
            .write_slot(self.direction, self.tail, metadata, payload, sequence)?;
        self.tail = sequence;
        Ok(ControlRingWriteStatus::Written)
    }
}

/// Trusted endpoint-local state for one control-ring consumer.
pub struct ControlRingConsumer<Memory: AtomicSharedMemory> {
    ring: Arc<ControlRing<Memory>>,
    direction: ControlRingDirection,
    head: u64,
    published_head: u64,
}

impl<Memory: AtomicSharedMemory> ControlRingConsumer<Memory> {
    fn new(ring: Arc<ControlRing<Memory>>, direction: ControlRingDirection) -> Self {
        Self {
            ring,
            direction,
            head: 0,
            published_head: 0,
        }
    }

    /// Returns the ring direction read by this consumer.
    pub const fn direction(&self) -> ControlRingDirection {
        self.direction
    }

    #[cfg(any(test, all(feature = "linux-userland", target_os = "linux")))]
    pub(crate) fn wake_handle(&self) -> ControlRingWakeHandle<Memory> {
        ControlRingWakeHandle {
            ring: Arc::clone(&self.ring),
            wait_epoch: ControlRingWaitEpoch::Producer(self.direction),
        }
    }

    #[cfg(any(test, all(feature = "linux-userland", target_os = "linux")))]
    pub(crate) fn memory(&self) -> &Memory {
        self.ring.memory()
    }

    /// Publishes newly consumed slots and advances the consumer wake epoch.
    pub fn publish_head(&mut self) -> Result<(), ControlRingError> {
        if self.head == self.published_head {
            return Ok(());
        }
        self.ring.memory.store_u64_and_fetch_add_u32_release(
            self.direction.consumer_head_offset(),
            self.head.to_le(),
            self.direction.consumer_epoch_offset(),
            1,
        )?;
        self.published_head = self.head;
        Ok(())
    }

    /// Polls, copies, validates, and decodes one peer-published slot.
    ///
    /// The decoder receives only an owned snapshot of the exact encoded
    /// envelope. It must reject malformed message tags, phases, and trailing
    /// bytes. The trusted head advances only after successful decoding.
    pub fn try_read<Message, DecodeError>(
        &mut self,
        decode: impl FnOnce(&[u8]) -> Result<Message, DecodeError>,
    ) -> Result<ControlRingReadStatus<Message>, ControlRingReadError<DecodeError>> {
        let expected_sequence = self.head.checked_add(1).ok_or(ControlRingReadError::Ring(
            ControlRingError::CounterExhausted,
        ))?;
        let wait_epoch = self
            .ring
            .load_producer_epoch(self.direction)
            .map_err(ControlRingReadError::Ring)?;
        let actual_sequence = self
            .ring
            .load_sequence(self.direction, self.head)
            .map_err(ControlRingReadError::Ring)?;
        let stale_sequence = expected_sequence.saturating_sub(self.direction.slot_count());
        if actual_sequence == stale_sequence {
            return Ok(ControlRingReadStatus::Empty { wait_epoch });
        }
        if actual_sequence != expected_sequence {
            return Err(ControlRingReadError::Ring(
                ControlRingError::UnexpectedSequence {
                    expected: expected_sequence,
                    actual: actual_sequence,
                },
            ));
        }
        let mut image = [0; CONTROL_RING_SLOT_SIZE];
        image[..size_of::<u64>()].copy_from_slice(&actual_sequence.to_le_bytes());
        self.ring
            .read_slot_body(self.direction, self.head, &mut image[size_of::<u64>()..])
            .map_err(ControlRingReadError::Ring)?;
        let verified_sequence = self
            .ring
            .load_sequence(self.direction, self.head)
            .map_err(ControlRingReadError::Ring)?;
        if verified_sequence != expected_sequence {
            return Err(ControlRingReadError::Ring(
                ControlRingError::UnexpectedSequence {
                    expected: expected_sequence,
                    actual: verified_sequence,
                },
            ));
        }
        let reserved = u32::from_le_bytes([image[12], image[13], image[14], image[15]]);
        if reserved != 0 {
            return Err(ControlRingReadError::Ring(
                ControlRingError::NonzeroReserved { value: reserved },
            ));
        }
        let length = u32::from_le_bytes([image[8], image[9], image[10], image[11]]);
        let length_usize = length as usize;
        if length_usize == 0 || length_usize > CONTROL_RING_PAYLOAD_CAPACITY {
            return Err(ControlRingReadError::Ring(
                ControlRingError::InvalidPayloadLength { length },
            ));
        }
        let payload =
            &image[CONTROL_RING_SLOT_HEADER_SIZE..CONTROL_RING_SLOT_HEADER_SIZE + length_usize];
        let message = decode(payload).map_err(ControlRingReadError::Decode)?;
        self.head = expected_sequence;
        Ok(ControlRingReadStatus::Message(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::align_of;
    use litebox_broker_protocol::RequestId;
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerOperation, BrokerRequest,
    };
    use litebox_broker_protocol::wire::{
        WireError, decode_request, encode_handshake_request, encode_request,
    };
    use litebox_broker_protocol::{ObjectHandle, ProtocolVersion};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::vec;
    use std::vec::Vec;

    const SEQUENCE_RANGE: core::ops::Range<usize> = 0..8;
    const LENGTH_RANGE: core::ops::Range<usize> = 8..12;
    const RESERVED_RANGE: core::ops::Range<usize> = 12..16;

    #[test]
    fn mapping_requires_the_exact_control_ring_size() {
        assert_eq!(CONTROL_RING_MEMORY_SIZE, 24_624);
        assert!(matches!(
            ControlRing::new(TestMemory::new(CONTROL_RING_MEMORY_SIZE - 1)),
            Err(ControlRingError::MemoryLengthMismatch {
                expected: CONTROL_RING_MEMORY_SIZE,
                actual
            }) if actual == CONTROL_RING_MEMORY_SIZE - 1
        ));
        assert!(matches!(
            ControlRing::new(TestMemory::new(CONTROL_RING_MEMORY_SIZE + 1)),
            Err(ControlRingError::MemoryLengthMismatch {
                expected: CONTROL_RING_MEMORY_SIZE,
                actual
            }) if actual == CONTROL_RING_MEMORY_SIZE + 1
        ));
        assert!(ControlRing::new(TestMemory::new(CONTROL_RING_MEMORY_SIZE)).is_ok());
    }

    #[test]
    fn directions_occupy_disjoint_data_and_sync_ranges() {
        let directions = [
            ControlRingDirection::Requests,
            ControlRingDirection::Responses,
            ControlRingDirection::Notifications,
        ];
        let mut next_data_offset = 0;
        for direction in directions {
            let first = direction.slot_range(0);
            let last = direction.slot_range(direction.slot_count() - 1);
            assert_eq!(first.start, next_data_offset);
            assert_eq!(
                last.end - first.start,
                usize::try_from(direction.slot_count()).unwrap() * CONTROL_RING_SLOT_SIZE
            );
            next_data_offset = last.end;
        }
        assert_eq!(next_data_offset, CONTROL_RING_DATA_SIZE);

        for (index, direction) in directions.into_iter().enumerate() {
            assert_eq!(
                direction.producer_epoch_offset(),
                CONTROL_RING_DATA_SIZE + index * CONTROL_RING_SYNC_DIRECTION_SIZE
            );
            assert_eq!(
                direction.consumer_epoch_offset(),
                direction.producer_epoch_offset() + size_of::<u32>()
            );
            assert_eq!(
                direction.consumer_head_offset(),
                direction.producer_epoch_offset() + size_of::<u64>()
            );
            assert!(
                direction
                    .consumer_head_offset()
                    .is_multiple_of(align_of::<u64>())
            );
        }
        assert_eq!(
            ControlRingDirection::Notifications.consumer_head_offset() + size_of::<u64>(),
            CONTROL_RING_MEMORY_SIZE
        );
    }

    #[test]
    fn endpoint_roles_bind_opposite_directions_to_one_mapping() {
        let local = test_ring().into_local();
        assert_eq!(
            local.request_producer.direction(),
            ControlRingDirection::Requests
        );
        assert_eq!(
            local.response_consumer.direction(),
            ControlRingDirection::Responses
        );
        assert_eq!(
            local.notification_consumer.direction(),
            ControlRingDirection::Notifications
        );
        assert!(Arc::ptr_eq(
            &local.request_producer.ring,
            &local.response_consumer.ring
        ));
        assert!(Arc::ptr_eq(
            &local.request_producer.ring,
            &local.notification_consumer.ring
        ));

        let broker = test_ring().into_broker();
        assert_eq!(
            broker.request_consumer.direction(),
            ControlRingDirection::Requests
        );
        assert_eq!(
            broker.response_producer.direction(),
            ControlRingDirection::Responses
        );
        assert_eq!(
            broker.notification_producer.direction(),
            ControlRingDirection::Notifications
        );
        assert!(Arc::ptr_eq(
            &broker.request_consumer.ring,
            &broker.response_producer.ring
        ));
        assert!(Arc::ptr_eq(
            &broker.request_consumer.ring,
            &broker.notification_producer.ring
        ));
    }

    #[test]
    fn request_response_and_notification_rings_publish_independently() {
        let ring = Arc::new(test_ring());
        let mut request_producer =
            ControlRingProducer::new(Arc::clone(&ring), ControlRingDirection::Requests);
        let mut request_consumer =
            ControlRingConsumer::new(Arc::clone(&ring), ControlRingDirection::Requests);
        let mut response_producer =
            ControlRingProducer::new(Arc::clone(&ring), ControlRingDirection::Responses);
        let mut response_consumer =
            ControlRingConsumer::new(Arc::clone(&ring), ControlRingDirection::Responses);
        let mut notification_producer =
            ControlRingProducer::new(Arc::clone(&ring), ControlRingDirection::Notifications);
        let mut notification_consumer =
            ControlRingConsumer::new(ring, ControlRingDirection::Notifications);

        assert_eq!(
            request_producer.try_write(&[1, 2, 3]),
            Ok(ControlRingWriteStatus::Written)
        );
        assert_eq!(
            response_producer.try_write(&[4, 5]),
            Ok(ControlRingWriteStatus::Written)
        );
        assert_eq!(
            notification_producer.try_write(&[6]),
            Ok(ControlRingWriteStatus::Written)
        );

        assert_eq!(
            request_consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Message(vec![1, 2, 3]))
        );
        assert_eq!(
            response_consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Message(vec![4, 5]))
        );
        assert_eq!(
            notification_consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Message(vec![6]))
        );
        assert_eq!(
            request_consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Empty { wait_epoch: 1 })
        );
        assert_eq!(
            response_consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Empty { wait_epoch: 1 })
        );
        assert_eq!(
            notification_consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Empty { wait_epoch: 1 })
        );
    }

    #[test]
    fn payload_length_bounds_are_enforced() {
        let (mut producer, mut consumer) = test_endpoints();

        assert_eq!(producer.try_write(&[]), Err(ControlRingError::EmptyPayload));
        assert_eq!(
            producer.try_write(&[0; CONTROL_RING_PAYLOAD_CAPACITY + 1]),
            Err(ControlRingError::PayloadTooLarge {
                length: CONTROL_RING_PAYLOAD_CAPACITY + 1
            })
        );
        assert_eq!(
            producer.try_write(&[7; CONTROL_RING_PAYLOAD_CAPACITY]),
            Ok(ControlRingWriteStatus::Written)
        );

        assert_eq!(
            consumer.try_read(|payload| Ok::<_, ()>(payload.len())),
            Ok(ControlRingReadStatus::Message(
                CONTROL_RING_PAYLOAD_CAPACITY
            ))
        );
    }

    #[test]
    fn each_direction_enforces_its_own_capacity() {
        for direction in [
            ControlRingDirection::Requests,
            ControlRingDirection::Responses,
            ControlRingDirection::Notifications,
        ] {
            let (mut producer, mut consumer) = test_ring().into_endpoints(direction, direction);
            for value in 0..direction.slot_count() {
                assert_eq!(
                    producer.try_write(&[u8::try_from(value % 256).unwrap()]),
                    Ok(ControlRingWriteStatus::Written)
                );
            }
            assert_eq!(
                producer.try_write(&[0xff]),
                Ok(ControlRingWriteStatus::Full { wait_epoch: 0 })
            );

            for value in 0..direction.slot_count() {
                assert_eq!(
                    consumer.try_read(owned_bytes),
                    Ok(ControlRingReadStatus::Message(vec![
                        u8::try_from(value % 256).unwrap()
                    ]))
                );
            }
            assert_eq!(
                consumer.try_read(owned_bytes),
                Ok(ControlRingReadStatus::Empty {
                    wait_epoch: u32::try_from(direction.slot_count()).unwrap()
                })
            );
        }
    }

    #[test]
    fn producer_publishes_sequence_after_payload_and_metadata() {
        let (mut producer, _) = test_endpoints();

        assert_eq!(
            producer.try_write(&[1, 2, 3]),
            Ok(ControlRingWriteStatus::Written)
        );
        assert_eq!(
            producer.memory().write_log(),
            vec![
                (CONTROL_RING_SLOT_HEADER_SIZE, 3),
                (
                    size_of::<u64>(),
                    CONTROL_RING_SLOT_HEADER_SIZE - size_of::<u64>()
                ),
                (0, size_of::<u64>()),
                (
                    ControlRingDirection::Requests.producer_epoch_offset(),
                    size_of::<u32>()
                ),
            ]
        );
    }

    #[test]
    fn failed_payload_metadata_or_atomic_publication_does_not_publish_progress() {
        for failed_write in [1, 2, 3] {
            let ring = ControlRing::new(FailingWriteMemory::new()).unwrap();
            let (mut producer, mut consumer) = ring.into_endpoints(
                ControlRingDirection::Requests,
                ControlRingDirection::Requests,
            );
            producer.try_write(&[7]).unwrap();
            producer.memory().fail_after(failed_write);
            assert_eq!(
                producer.try_write(&[1, 2, 3]),
                Err(ControlRingError::SharedMemory(
                    SharedMemoryError::InvalidRange
                ))
            );
            assert_eq!(producer.tail, 1);
            assert_eq!(
                consumer.try_read(owned_bytes),
                Ok(ControlRingReadStatus::Message(vec![7]))
            );
            assert_eq!(
                consumer.try_read(owned_bytes),
                Ok(ControlRingReadStatus::Empty { wait_epoch: 1 })
            );

            assert_eq!(
                producer.try_write(&[1, 2, 3]),
                Ok(ControlRingWriteStatus::Written)
            );
            assert_eq!(
                consumer.try_read(owned_bytes),
                Ok(ControlRingReadStatus::Message(vec![1, 2, 3]))
            );
        }
    }

    #[test]
    fn shorter_reused_payload_does_not_expose_stale_trailing_bytes() {
        let (mut producer, mut consumer) = test_endpoints();

        producer.try_write(&[7; 100]).unwrap();
        for _ in 1..CONTROL_RING_SLOT_COUNT {
            producer.try_write(&[8]).unwrap();
        }
        assert_eq!(
            consumer.try_read(|payload| Ok::<_, ()>(payload.len())),
            Ok(ControlRingReadStatus::Message(100))
        );
        for _ in 1..CONTROL_RING_SLOT_COUNT {
            consumer.try_read(owned_bytes).unwrap();
        }
        consumer.publish_head().unwrap();

        producer.try_write(&[9]).unwrap();
        assert_eq!(
            &producer.memory().bytes()
                [CONTROL_RING_SLOT_HEADER_SIZE + 1..CONTROL_RING_SLOT_HEADER_SIZE + 100],
            &[7; 99]
        );
        assert_eq!(
            consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Message(vec![9]))
        );
    }

    #[test]
    fn shared_epochs_publish_and_acknowledge_a_full_batch() {
        let (mut producer, mut consumer) = test_endpoints();

        for value in 0..CONTROL_RING_SLOT_COUNT {
            let value = u8::try_from(value).unwrap();
            assert_eq!(
                producer.try_write(&[value]),
                Ok(ControlRingWriteStatus::Written)
            );
        }
        assert_eq!(
            producer.try_write(&[0xff]),
            Ok(ControlRingWriteStatus::Full { wait_epoch: 0 })
        );

        for value in 0..CONTROL_RING_SLOT_COUNT {
            let value = u8::try_from(value).unwrap();
            assert_eq!(
                consumer.try_read(owned_bytes),
                Ok(ControlRingReadStatus::Message(vec![value]))
            );
        }
        assert_eq!(
            consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Empty {
                wait_epoch: u32::try_from(CONTROL_RING_SLOT_COUNT).unwrap()
            })
        );
        assert_eq!(
            producer.try_write(&[0xff]),
            Ok(ControlRingWriteStatus::Full { wait_epoch: 0 })
        );

        consumer.publish_head().unwrap();
        assert_eq!(
            producer.try_write(&[0xff]),
            Ok(ControlRingWriteStatus::Written)
        );
        assert_eq!(
            consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Message(vec![0xff]))
        );
    }

    #[test]
    fn wakeup_epochs_wrap_without_controlling_ring_progress() {
        let (mut producer, mut consumer) = test_endpoints();

        producer
            .memory()
            .fetch_add_u32_release(
                ControlRingDirection::Requests.producer_epoch_offset(),
                u32::MAX,
            )
            .unwrap();
        producer.try_write(&[7]).unwrap();
        assert_eq!(
            consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Message(vec![7]))
        );
        assert_eq!(
            consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Empty { wait_epoch: 0 })
        );

        consumer
            .memory()
            .fetch_add_u32_release(
                ControlRingDirection::Requests.consumer_epoch_offset(),
                u32::MAX,
            )
            .unwrap();
        consumer.publish_head().unwrap();
        assert_eq!(
            producer
                .memory()
                .load_u32_acquire(ControlRingDirection::Requests.consumer_epoch_offset()),
            Ok(0)
        );
        assert_eq!(producer.refresh_head(), Ok(()));
    }

    #[test]
    fn unchanged_consumer_head_does_not_advance_the_epoch() {
        let (mut producer, mut consumer) = test_endpoints();
        consumer.publish_head().unwrap();
        assert_eq!(
            consumer
                .memory()
                .load_u32_acquire(ControlRingDirection::Requests.consumer_epoch_offset()),
            Ok(0)
        );

        producer.try_write(&[7]).unwrap();
        consumer.try_read(owned_bytes).unwrap();
        consumer.publish_head().unwrap();
        consumer.publish_head().unwrap();
        assert_eq!(
            consumer
                .memory()
                .load_u32_acquire(ControlRingDirection::Requests.consumer_epoch_offset()),
            Ok(1)
        );
    }

    #[test]
    fn producer_rejects_regressed_or_future_shared_heads() {
        let (mut producer, _) = test_endpoints();
        producer.try_write(&[1]).unwrap();
        producer.try_write(&[2]).unwrap();

        store_test_consumer_head(producer.memory(), 1);
        assert_eq!(producer.refresh_head(), Ok(()));
        assert_eq!(producer.refresh_head(), Ok(()));
        store_test_consumer_head(producer.memory(), 0);
        assert_eq!(
            producer.refresh_head(),
            Err(ControlRingError::CounterRegressed {
                previous: 1,
                received: 0
            })
        );
        store_test_consumer_head(producer.memory(), 3);
        assert_eq!(
            producer.refresh_head(),
            Err(ControlRingError::CounterOutOfRange {
                local: 2,
                received: 3
            })
        );
    }

    #[test]
    fn consumer_rejects_hostile_slot_metadata() {
        fn assert_rejected(image: &[u8; CONTROL_RING_SLOT_SIZE], expected: ControlRingError) {
            let ring = test_ring();
            install_slot(ring.memory(), image);
            let (_, mut consumer) = ring.into_endpoints(
                ControlRingDirection::Responses,
                ControlRingDirection::Requests,
            );
            assert_eq!(
                consumer.try_read(owned_bytes),
                Err(ControlRingReadError::Ring(expected))
            );
            assert_eq!(consumer.head, 0);
        }

        assert_rejected(
            &raw_slot(2, 1, 0, &[1]),
            ControlRingError::UnexpectedSequence {
                expected: 1,
                actual: 2,
            },
        );
        assert_rejected(
            &raw_slot(1, 1, 7, &[1]),
            ControlRingError::NonzeroReserved { value: 7 },
        );
        assert_rejected(
            &raw_slot(1, 0, 0, &[]),
            ControlRingError::InvalidPayloadLength { length: 0 },
        );
        let oversized = u32::try_from(CONTROL_RING_PAYLOAD_CAPACITY + 1).unwrap();
        assert_rejected(
            &raw_slot(1, oversized, 0, &[]),
            ControlRingError::InvalidPayloadLength { length: oversized },
        );
    }

    #[test]
    fn consumer_treats_the_previous_slot_sequence_as_empty() {
        let (_, mut consumer) = test_endpoints();

        assert_eq!(
            consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Empty { wait_epoch: 0 })
        );
        install_slot(consumer.memory(), &raw_slot(1, 1, 0, &[7]));
        consumer.head = CONTROL_RING_SLOT_COUNT;
        assert_eq!(
            consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Empty { wait_epoch: 0 })
        );
    }

    #[test]
    fn active_decoder_rejects_truncated_trailing_and_wrong_phase_slots() {
        let request = BrokerRequest {
            request_id: RequestId(13),
            operation: BrokerOperation::CloseObject(ObjectHandle(17)),
        };
        let encoded = encode_request(request.clone());
        let frames = [
            (
                encoded[..encoded.len() - 1].to_vec(),
                WireError::TruncatedFrame,
            ),
            (
                {
                    let mut trailing = encoded.clone();
                    trailing.push(0xff);
                    trailing
                },
                WireError::TrailingBytes,
            ),
            (
                encode_handshake_request(BrokerHandshakeRequest {
                    protocol_version: ProtocolVersion(1),
                }),
                WireError::WrongMessagePhase,
            ),
        ];

        for (frame, expected) in frames {
            let (mut producer, mut consumer) = test_endpoints();
            producer.try_write(&frame).unwrap();
            assert_eq!(
                consumer.try_read(decode_request),
                Err(ControlRingReadError::Decode(expected))
            );
            assert_eq!(consumer.head, 0);
        }

        let (mut producer, mut consumer) = test_endpoints();
        producer.try_write(&encoded).unwrap();
        assert_eq!(
            consumer.try_read(decode_request),
            Ok(ControlRingReadStatus::Message(request))
        );
    }

    #[test]
    fn decoder_observes_only_the_owned_slot_snapshot() {
        let (mut producer, mut consumer) = test_endpoints();
        producer.try_write(&[1, 2, 3]).unwrap();
        let memory = producer.memory();

        assert_eq!(
            consumer.try_read(|payload| {
                memory
                    .write(CONTROL_RING_SLOT_HEADER_SIZE, &[9, 9, 9])
                    .unwrap();
                Ok::<_, ()>(payload.to_vec())
            }),
            Ok(ControlRingReadStatus::Message(vec![1, 2, 3]))
        );
        assert_eq!(
            &memory.bytes()[CONTROL_RING_SLOT_HEADER_SIZE..CONTROL_RING_SLOT_HEADER_SIZE + 3],
            &[9, 9, 9]
        );
    }

    #[test]
    fn torn_length_snapshot_is_rejected_before_payload_slicing() {
        let memory = TearingMemory::with_torn_length(&raw_slot(1, 1, 0, &[7]));
        let ring = ControlRing::new(memory).unwrap();
        let (_, mut consumer) = ring.into_endpoints(
            ControlRingDirection::Responses,
            ControlRingDirection::Requests,
        );

        assert_eq!(
            consumer.try_read(owned_bytes),
            Err(ControlRingReadError::Ring(
                ControlRingError::InvalidPayloadLength {
                    length: 0xffff_0001
                }
            ))
        );
        assert_eq!(consumer.head, 0);
    }

    #[test]
    fn sequence_change_during_body_copy_is_rejected() {
        let memory = TearingMemory::with_changed_sequence(&raw_slot(1, 1, 0, &[7]));
        let ring = ControlRing::new(memory).unwrap();
        let (_, mut consumer) = ring.into_endpoints(
            ControlRingDirection::Responses,
            ControlRingDirection::Requests,
        );

        assert_eq!(
            consumer.try_read(owned_bytes),
            Err(ControlRingReadError::Ring(
                ControlRingError::UnexpectedSequence {
                    expected: 1,
                    actual: 2,
                }
            ))
        );
        assert_eq!(consumer.head, 0);
    }

    #[test]
    fn terminal_sequence_is_used_once_without_wrapping() {
        let (mut producer, mut consumer) = test_endpoints();
        producer.tail = u64::MAX - 1;
        producer.acknowledged_head = u64::MAX - 1;

        assert_eq!(
            producer.try_write(&[7]),
            Ok(ControlRingWriteStatus::Written)
        );
        let writes = producer.memory().write_count.load(Ordering::Relaxed);
        assert_eq!(
            producer.try_write(&[8]),
            Err(ControlRingError::CounterExhausted)
        );
        assert_eq!(
            producer.memory().write_count.load(Ordering::Relaxed),
            writes
        );

        consumer.head = u64::MAX - 1;
        assert_eq!(
            consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Message(vec![7]))
        );
        assert_eq!(consumer.head, u64::MAX);
        assert_eq!(
            consumer.try_read(owned_bytes),
            Err(ControlRingReadError::Ring(
                ControlRingError::CounterExhausted
            ))
        );
    }

    fn test_ring() -> ControlRing<TestMemory> {
        ControlRing::new(TestMemory::new(CONTROL_RING_MEMORY_SIZE)).unwrap()
    }

    fn test_endpoints() -> (
        ControlRingProducer<TestMemory>,
        ControlRingConsumer<TestMemory>,
    ) {
        test_ring().into_endpoints(
            ControlRingDirection::Requests,
            ControlRingDirection::Requests,
        )
    }

    fn owned_bytes(payload: &[u8]) -> Result<Vec<u8>, ()> {
        if payload.is_empty() {
            Err(())
        } else {
            Ok(payload.to_vec())
        }
    }

    fn raw_slot(
        sequence: u64,
        length: u32,
        reserved: u32,
        payload: &[u8],
    ) -> [u8; CONTROL_RING_SLOT_SIZE] {
        let mut image = [0; CONTROL_RING_SLOT_SIZE];
        image[SEQUENCE_RANGE].copy_from_slice(&sequence.to_le_bytes());
        image[LENGTH_RANGE].copy_from_slice(&length.to_le_bytes());
        image[RESERVED_RANGE].copy_from_slice(&reserved.to_le_bytes());
        image[CONTROL_RING_SLOT_HEADER_SIZE..CONTROL_RING_SLOT_HEADER_SIZE + payload.len()]
            .copy_from_slice(payload);
        image
    }

    fn install_slot(memory: &TestMemory, image: &[u8; CONTROL_RING_SLOT_SIZE]) {
        memory
            .write(size_of::<u64>(), &image[size_of::<u64>()..])
            .unwrap();
        let sequence = u64::from_le_bytes(image[..size_of::<u64>()].try_into().unwrap());
        memory.store_u64_release(0, sequence.to_le()).unwrap();
    }

    fn store_test_consumer_head(memory: &TestMemory, head: u64) {
        memory
            .store_u64_release(
                ControlRingDirection::Requests.consumer_head_offset(),
                head.to_le(),
            )
            .unwrap();
    }

    struct TestMemory {
        bytes: Mutex<Vec<u8>>,
        write_log: Mutex<Vec<(usize, usize)>>,
        write_count: AtomicUsize,
    }

    impl TestMemory {
        fn new(length: usize) -> Self {
            Self {
                bytes: Mutex::new(vec![0; length]),
                write_log: Mutex::new(Vec::new()),
                write_count: AtomicUsize::new(0),
            }
        }

        fn bytes(&self) -> Vec<u8> {
            self.bytes.lock().unwrap().clone()
        }

        fn write_log(&self) -> Vec<(usize, usize)> {
            self.write_log.lock().unwrap().clone()
        }
    }

    impl SharedMemory for TestMemory {
        fn len(&self) -> usize {
            self.bytes.lock().unwrap().len()
        }

        fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
            let bytes = self.bytes.lock().unwrap();
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
            let mut bytes = self.bytes.lock().unwrap();
            let end = offset
                .checked_add(source.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            bytes
                .get_mut(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?
                .copy_from_slice(source);
            self.write_log.lock().unwrap().push((offset, source.len()));
            self.write_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    impl AtomicSharedMemory for TestMemory {
        fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
            test_load_u32_acquire(&self.bytes, offset)
        }

        fn fetch_add_u32_release(
            &self,
            offset: usize,
            value: u32,
        ) -> Result<u32, SharedMemoryError> {
            let previous = test_fetch_add_u32_release(&self.bytes, offset, value)?;
            self.write_log
                .lock()
                .unwrap()
                .push((offset, size_of::<u32>()));
            self.write_count.fetch_add(1, Ordering::Relaxed);
            Ok(previous)
        }

        fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
            test_load_u64_acquire(&self.bytes, offset)
        }

        fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
            test_store_u64_release(&self.bytes, offset, value)?;
            self.write_log
                .lock()
                .unwrap()
                .push((offset, size_of::<u64>()));
            self.write_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn store_u64_and_fetch_add_u32_release(
            &self,
            store_offset: usize,
            value: u64,
            add_offset: usize,
            add_value: u32,
        ) -> Result<u32, SharedMemoryError> {
            let previous = test_store_u64_and_fetch_add_u32_release(
                &self.bytes,
                store_offset,
                value,
                add_offset,
                add_value,
            )?;
            self.write_log.lock().unwrap().extend([
                (store_offset, size_of::<u64>()),
                (add_offset, size_of::<u32>()),
            ]);
            self.write_count.fetch_add(2, Ordering::Relaxed);
            Ok(previous)
        }
    }

    struct FailingWriteMemory {
        bytes: Mutex<Vec<u8>>,
        write_count: AtomicUsize,
        fail_on_write: AtomicUsize,
    }

    impl FailingWriteMemory {
        fn new() -> Self {
            Self {
                bytes: Mutex::new(vec![0; CONTROL_RING_MEMORY_SIZE]),
                write_count: AtomicUsize::new(0),
                fail_on_write: AtomicUsize::new(usize::MAX),
            }
        }

        fn fail_after(&self, writes: usize) {
            let current = self.write_count.load(Ordering::Relaxed);
            self.fail_on_write
                .store(current + writes, Ordering::Relaxed);
        }
    }

    impl SharedMemory for FailingWriteMemory {
        fn len(&self) -> usize {
            self.bytes.lock().unwrap().len()
        }

        fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
            let bytes = self.bytes.lock().unwrap();
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
            let call = self.write_count.fetch_add(1, Ordering::Relaxed) + 1;
            let mut bytes = self.bytes.lock().unwrap();
            let end = offset
                .checked_add(source.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let destination = bytes
                .get_mut(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            if call == self.fail_on_write.load(Ordering::Relaxed) {
                let partial = source.len().div_ceil(2);
                destination[..partial].copy_from_slice(&source[..partial]);
                return Err(SharedMemoryError::InvalidRange);
            }
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    impl AtomicSharedMemory for FailingWriteMemory {
        fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
            test_load_u32_acquire(&self.bytes, offset)
        }

        fn fetch_add_u32_release(
            &self,
            offset: usize,
            value: u32,
        ) -> Result<u32, SharedMemoryError> {
            test_fetch_add_u32_release(&self.bytes, offset, value)
        }

        fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
            test_load_u64_acquire(&self.bytes, offset)
        }

        fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
            if !offset.is_multiple_of(align_of::<u64>()) {
                return Err(SharedMemoryError::UnalignedAtomic);
            }
            let call = self.write_count.fetch_add(1, Ordering::Relaxed) + 1;
            if call == self.fail_on_write.load(Ordering::Relaxed) {
                return Err(SharedMemoryError::InvalidRange);
            }
            test_store_u64_release(&self.bytes, offset, value)
        }

        fn store_u64_and_fetch_add_u32_release(
            &self,
            store_offset: usize,
            value: u64,
            add_offset: usize,
            add_value: u32,
        ) -> Result<u32, SharedMemoryError> {
            let call = self.write_count.fetch_add(1, Ordering::Relaxed) + 1;
            if call == self.fail_on_write.load(Ordering::Relaxed) {
                return Err(SharedMemoryError::InvalidRange);
            }
            test_store_u64_and_fetch_add_u32_release(
                &self.bytes,
                store_offset,
                value,
                add_offset,
                add_value,
            )
        }
    }

    enum Tear {
        Length,
        Sequence,
    }

    struct TearingMemory {
        bytes: Mutex<Vec<u8>>,
        tear: Tear,
    }

    impl TearingMemory {
        fn with_torn_length(first_slot: &[u8; CONTROL_RING_SLOT_SIZE]) -> Self {
            Self::new(first_slot, Tear::Length)
        }

        fn with_changed_sequence(first_slot: &[u8; CONTROL_RING_SLOT_SIZE]) -> Self {
            Self::new(first_slot, Tear::Sequence)
        }

        fn new(first_slot: &[u8; CONTROL_RING_SLOT_SIZE], tear: Tear) -> Self {
            let mut bytes = vec![0; CONTROL_RING_MEMORY_SIZE];
            bytes[..CONTROL_RING_SLOT_SIZE].copy_from_slice(first_slot);
            Self {
                bytes: Mutex::new(bytes),
                tear,
            }
        }
    }

    impl SharedMemory for TearingMemory {
        fn len(&self) -> usize {
            self.bytes.lock().unwrap().len()
        }

        fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
            let mut bytes = self.bytes.lock().unwrap();
            let end = offset
                .checked_add(destination.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            bytes
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;

            match self.tear {
                Tear::Length => {
                    destination[..2].copy_from_slice(&bytes[offset..offset + 2]);
                    bytes[offset + 2..offset + 4].fill(0xff);
                    destination[2..].copy_from_slice(&bytes[offset + 2..end]);
                }
                Tear::Sequence => {
                    destination.copy_from_slice(&bytes[offset..end]);
                    bytes[..size_of::<u64>()].copy_from_slice(&2_u64.to_le_bytes());
                }
            }
            Ok(())
        }

        fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
            let mut bytes = self.bytes.lock().unwrap();
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

    impl AtomicSharedMemory for TearingMemory {
        fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
            test_load_u32_acquire(&self.bytes, offset)
        }

        fn fetch_add_u32_release(
            &self,
            offset: usize,
            value: u32,
        ) -> Result<u32, SharedMemoryError> {
            test_fetch_add_u32_release(&self.bytes, offset, value)
        }

        fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
            test_load_u64_acquire(&self.bytes, offset)
        }

        fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
            test_store_u64_release(&self.bytes, offset, value)
        }

        fn store_u64_and_fetch_add_u32_release(
            &self,
            store_offset: usize,
            value: u64,
            add_offset: usize,
            add_value: u32,
        ) -> Result<u32, SharedMemoryError> {
            test_store_u64_and_fetch_add_u32_release(
                &self.bytes,
                store_offset,
                value,
                add_offset,
                add_value,
            )
        }
    }

    fn test_load_u32_acquire(
        bytes: &Mutex<Vec<u8>>,
        offset: usize,
    ) -> Result<u32, SharedMemoryError> {
        if !offset.is_multiple_of(align_of::<u32>()) {
            return Err(SharedMemoryError::UnalignedAtomic);
        }
        let bytes = bytes.lock().unwrap();
        let end = offset
            .checked_add(size_of::<u32>())
            .ok_or(SharedMemoryError::InvalidRange)?;
        let value = u32::from_ne_bytes(
            bytes
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?
                .try_into()
                .unwrap(),
        );
        fence(Ordering::Acquire);
        Ok(value)
    }

    fn test_fetch_add_u32_release(
        bytes: &Mutex<Vec<u8>>,
        offset: usize,
        value: u32,
    ) -> Result<u32, SharedMemoryError> {
        if !offset.is_multiple_of(align_of::<u32>()) {
            return Err(SharedMemoryError::UnalignedAtomic);
        }
        fence(Ordering::Release);
        let mut bytes = bytes.lock().unwrap();
        let end = offset
            .checked_add(size_of::<u32>())
            .ok_or(SharedMemoryError::InvalidRange)?;
        let destination = bytes
            .get_mut(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?;
        let previous = u32::from_ne_bytes(destination.try_into().unwrap());
        destination.copy_from_slice(&previous.wrapping_add(value).to_ne_bytes());
        Ok(previous)
    }

    fn test_load_u64_acquire(
        bytes: &Mutex<Vec<u8>>,
        offset: usize,
    ) -> Result<u64, SharedMemoryError> {
        if !offset.is_multiple_of(align_of::<u64>()) {
            return Err(SharedMemoryError::UnalignedAtomic);
        }
        let bytes = bytes.lock().unwrap();
        let end = offset
            .checked_add(size_of::<u64>())
            .ok_or(SharedMemoryError::InvalidRange)?;
        let value = u64::from_ne_bytes(
            bytes
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?
                .try_into()
                .unwrap(),
        );
        fence(Ordering::Acquire);
        Ok(value)
    }

    fn test_store_u64_release(
        bytes: &Mutex<Vec<u8>>,
        offset: usize,
        value: u64,
    ) -> Result<(), SharedMemoryError> {
        if !offset.is_multiple_of(align_of::<u64>()) {
            return Err(SharedMemoryError::UnalignedAtomic);
        }
        fence(Ordering::Release);
        let mut bytes = bytes.lock().unwrap();
        let end = offset
            .checked_add(size_of::<u64>())
            .ok_or(SharedMemoryError::InvalidRange)?;
        bytes
            .get_mut(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?
            .copy_from_slice(&value.to_ne_bytes());
        Ok(())
    }

    fn test_store_u64_and_fetch_add_u32_release(
        bytes: &Mutex<Vec<u8>>,
        store_offset: usize,
        value: u64,
        add_offset: usize,
        add_value: u32,
    ) -> Result<u32, SharedMemoryError> {
        if !store_offset.is_multiple_of(align_of::<u64>())
            || !add_offset.is_multiple_of(align_of::<u32>())
        {
            return Err(SharedMemoryError::UnalignedAtomic);
        }
        let store_end = store_offset
            .checked_add(size_of::<u64>())
            .ok_or(SharedMemoryError::InvalidRange)?;
        let add_end = add_offset
            .checked_add(size_of::<u32>())
            .ok_or(SharedMemoryError::InvalidRange)?;
        if store_offset < add_end && add_offset < store_end {
            return Err(SharedMemoryError::InvalidRange);
        }
        let mut bytes = bytes.lock().unwrap();
        if store_end > bytes.len() || add_end > bytes.len() {
            return Err(SharedMemoryError::InvalidRange);
        }
        let previous = u32::from_ne_bytes(
            bytes[add_offset..add_end]
                .try_into()
                .expect("checked u32 range"),
        );
        fence(Ordering::Release);
        bytes[store_offset..store_end].copy_from_slice(&value.to_ne_bytes());
        bytes[add_offset..add_end].copy_from_slice(&previous.wrapping_add(add_value).to_ne_bytes());
        Ok(previous)
    }
}
