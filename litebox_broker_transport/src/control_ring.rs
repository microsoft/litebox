// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hostile-peer-safe shared control-ring state machines.

use core::mem::size_of;
use core::sync::atomic::{Ordering, fence};

use litebox_broker_protocol::control_ring::{
    CONTROL_RING_MEMORY_SIZE, CONTROL_RING_PAYLOAD_CAPACITY, CONTROL_RING_SLOT_COUNT,
    CONTROL_RING_SLOT_HEADER_SIZE, CONTROL_RING_SLOT_SIZE, ControlRingDirection,
};
use litebox_broker_protocol::shared_memory::{AtomicSharedMemory, SharedMemory, SharedMemoryError};

#[cfg(test)]
const SEQUENCE_RANGE: core::ops::Range<usize> = 0..8;
#[cfg(test)]
const LENGTH_RANGE: core::ops::Range<usize> = 8..12;
#[cfg(test)]
const RESERVED_RANGE: core::ops::Range<usize> = 12..16;

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
    Full,
}

/// Result of a nonblocking control-ring read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlRingReadStatus<Message> {
    /// One complete slot was copied, validated, and decoded.
    Message(Message),
    /// The next slot still carries its previous sequence.
    Empty,
}

/// Error copying, validating, or decoding one control-ring slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlRingReadError<DecodeError> {
    /// Ring metadata or shared-memory access is invalid.
    Ring(ControlRingError),
    /// The owned encoded envelope was rejected by its protocol decoder.
    Decode(DecodeError),
}

/// Exact-size shared memory containing request and response control rings.
pub struct ControlRing<Memory: SharedMemory> {
    memory: Memory,
}

impl<Memory: SharedMemory> ControlRing<Memory> {
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

    fn write_slot(
        &self,
        direction: ControlRingDirection,
        position: u64,
        metadata: [u8; CONTROL_RING_SLOT_HEADER_SIZE - size_of::<u64>()],
        payload: &[u8],
        sequence: u64,
    ) -> Result<(), ControlRingError>
    where
        Memory: AtomicSharedMemory,
    {
        let slot = position % CONTROL_RING_SLOT_COUNT;
        let range = direction
            .slot_range(slot)
            .expect("modulo-derived control-ring slot is valid");
        self.memory
            .write(range.start + CONTROL_RING_SLOT_HEADER_SIZE, payload)?;
        self.memory
            .write(range.start + size_of::<u64>(), &metadata)?;
        self.memory
            .store_u64_release(range.start, sequence.to_le())?;
        Ok(())
    }

    fn load_sequence(
        &self,
        direction: ControlRingDirection,
        position: u64,
    ) -> Result<u64, ControlRingError>
    where
        Memory: AtomicSharedMemory,
    {
        let slot = position % CONTROL_RING_SLOT_COUNT;
        let range = direction
            .slot_range(slot)
            .expect("modulo-derived control-ring slot is valid");
        Ok(u64::from_le(self.memory.load_u64_acquire(range.start)?))
    }

    fn read_slot_body(
        &self,
        direction: ControlRingDirection,
        position: u64,
        body: &mut [u8],
    ) -> Result<(), ControlRingError> {
        let slot = position % CONTROL_RING_SLOT_COUNT;
        let range = direction
            .slot_range(slot)
            .expect("modulo-derived control-ring slot is valid");
        self.memory.read(range.start + size_of::<u64>(), body)?;
        Ok(())
    }
}

/// Trusted endpoint-local state for one control-ring producer.
pub struct ControlRingProducer {
    direction: ControlRingDirection,
    tail: u64,
    acknowledged_head: u64,
}

impl ControlRingProducer {
    /// Creates an empty producer for one ring direction.
    pub const fn new(direction: ControlRingDirection) -> Self {
        Self {
            direction,
            tail: 0,
            acknowledged_head: 0,
        }
    }

    /// Returns the ring direction written by this producer.
    pub const fn direction(&self) -> ControlRingDirection {
        self.direction
    }

    /// Returns the tail to publish in a socket doorbell.
    ///
    /// The release fence orders preceding sequence publications before a
    /// socket wakeup carrying the returned progress.
    pub fn published_tail(&self) -> u64 {
        fence(Ordering::Release);
        self.tail
    }

    /// Accepts peer-consumed progress from a socket doorbell.
    pub fn observe_head(&mut self, head: u64) -> Result<(), ControlRingError> {
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
        fence(Ordering::Acquire);
        Ok(())
    }

    /// Copies an encoded envelope and its header into the next available slot.
    pub fn try_write<Memory: AtomicSharedMemory>(
        &mut self,
        ring: &ControlRing<Memory>,
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
        if self.tail - self.acknowledged_head == CONTROL_RING_SLOT_COUNT {
            return Ok(ControlRingWriteStatus::Full);
        }

        let sequence = self.tail + 1;
        let length =
            u32::try_from(payload.len()).map_err(|_| ControlRingError::PayloadTooLarge {
                length: payload.len(),
            })?;
        let mut metadata = [0; CONTROL_RING_SLOT_HEADER_SIZE - size_of::<u64>()];
        metadata[..size_of::<u32>()].copy_from_slice(&length.to_le_bytes());
        ring.write_slot(self.direction, self.tail, metadata, payload, sequence)?;
        self.tail = sequence;
        Ok(ControlRingWriteStatus::Written)
    }
}

/// Trusted endpoint-local state for one control-ring consumer.
pub struct ControlRingConsumer {
    direction: ControlRingDirection,
    head: u64,
    notified_tail: u64,
}

impl ControlRingConsumer {
    /// Creates an empty consumer for one ring direction.
    pub const fn new(direction: ControlRingDirection) -> Self {
        Self {
            direction,
            head: 0,
            notified_tail: 0,
        }
    }

    /// Returns the ring direction read by this consumer.
    pub const fn direction(&self) -> ControlRingDirection {
        self.direction
    }

    /// Returns the head to publish in a socket doorbell.
    ///
    /// The release fence orders the preceding slot copy and decode before the
    /// peer can observe that the slot is reusable.
    pub fn published_head(&self) -> u64 {
        fence(Ordering::Release);
        self.head
    }

    /// Validates peer progress carried by a socket wakeup.
    ///
    /// This progress does not gate reads; the next slot's atomic sequence is
    /// the publication authority.
    pub fn observe_tail(&mut self, tail: u64) -> Result<(), ControlRingError> {
        if tail < self.notified_tail {
            return Err(ControlRingError::CounterRegressed {
                previous: self.notified_tail,
                received: tail,
            });
        }
        if tail > self.head && tail - self.head > CONTROL_RING_SLOT_COUNT {
            return Err(ControlRingError::CounterOutOfRange {
                local: self.head,
                received: tail,
            });
        }
        self.notified_tail = tail;
        Ok(())
    }

    /// Polls, copies, validates, and decodes one peer-published slot.
    ///
    /// The decoder receives only an owned snapshot of the exact encoded
    /// envelope. It must reject malformed message tags, phases, and trailing
    /// bytes. The trusted head advances only after successful decoding.
    pub fn try_read<Memory, Message, DecodeError>(
        &mut self,
        ring: &ControlRing<Memory>,
        decode: impl FnOnce(&[u8]) -> Result<Message, DecodeError>,
    ) -> Result<ControlRingReadStatus<Message>, ControlRingReadError<DecodeError>>
    where
        Memory: AtomicSharedMemory,
    {
        let expected_sequence = self.head.checked_add(1).ok_or(ControlRingReadError::Ring(
            ControlRingError::CounterExhausted,
        ))?;
        let actual_sequence = ring
            .load_sequence(self.direction, self.head)
            .map_err(ControlRingReadError::Ring)?;
        let stale_sequence = expected_sequence.saturating_sub(CONTROL_RING_SLOT_COUNT);
        if actual_sequence == stale_sequence {
            return Ok(ControlRingReadStatus::Empty);
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
        ring.read_slot_body(self.direction, self.head, &mut image[size_of::<u64>()..])
            .map_err(ControlRingReadError::Ring)?;
        let verified_sequence = ring
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
    use litebox_broker_protocol::control_ring::CONTROL_RING_MEMORY_SIZE;
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerOperation, BrokerRequest,
    };
    use litebox_broker_protocol::wire::{
        WireError, decode_request, encode_handshake_request, encode_request,
    };
    use litebox_broker_protocol::{ObjectHandle, ProtocolVersion};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn mapping_requires_the_exact_control_ring_size() {
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
    fn request_and_response_sequences_publish_without_doorbells() {
        let ring = test_ring();
        let mut request_producer = ControlRingProducer::new(ControlRingDirection::Requests);
        let mut request_consumer = ControlRingConsumer::new(ControlRingDirection::Requests);
        let mut response_producer = ControlRingProducer::new(ControlRingDirection::Responses);
        let mut response_consumer = ControlRingConsumer::new(ControlRingDirection::Responses);

        assert_eq!(
            request_producer.try_write(&ring, &[1, 2, 3]),
            Ok(ControlRingWriteStatus::Written)
        );
        assert_eq!(
            response_producer.try_write(&ring, &[4, 5]),
            Ok(ControlRingWriteStatus::Written)
        );

        assert_eq!(
            request_consumer.try_read(&ring, owned_bytes),
            Ok(ControlRingReadStatus::Message(vec![1, 2, 3]))
        );
        assert_eq!(
            response_consumer.try_read(&ring, owned_bytes),
            Ok(ControlRingReadStatus::Message(vec![4, 5]))
        );
        assert_eq!(
            request_consumer.try_read(&ring, owned_bytes),
            Ok(ControlRingReadStatus::Empty)
        );
        assert_eq!(
            response_consumer.try_read(&ring, owned_bytes),
            Ok(ControlRingReadStatus::Empty)
        );
    }

    #[test]
    fn payload_length_bounds_are_enforced() {
        let ring = test_ring();
        let mut producer = ControlRingProducer::new(ControlRingDirection::Requests);

        assert_eq!(
            producer.try_write(&ring, &[]),
            Err(ControlRingError::EmptyPayload)
        );
        assert_eq!(
            producer.try_write(&ring, &[0; CONTROL_RING_PAYLOAD_CAPACITY + 1]),
            Err(ControlRingError::PayloadTooLarge {
                length: CONTROL_RING_PAYLOAD_CAPACITY + 1
            })
        );
        assert_eq!(
            producer.try_write(&ring, &[7; CONTROL_RING_PAYLOAD_CAPACITY]),
            Ok(ControlRingWriteStatus::Written)
        );

        let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);
        consumer.observe_tail(producer.published_tail()).unwrap();
        assert_eq!(
            consumer.try_read(&ring, |payload| Ok::<_, ()>(payload.len())),
            Ok(ControlRingReadStatus::Message(
                CONTROL_RING_PAYLOAD_CAPACITY
            ))
        );
    }

    #[test]
    fn producer_writes_payload_metadata_then_sequence_without_full_slot_staging() {
        let memory = Arc::new(TestMemory::new(CONTROL_RING_MEMORY_SIZE));
        let ring = ControlRing::new(Arc::clone(&memory)).unwrap();
        let mut producer = ControlRingProducer::new(ControlRingDirection::Requests);

        assert_eq!(
            producer.try_write(&ring, &[1, 2, 3]),
            Ok(ControlRingWriteStatus::Written)
        );
        assert_eq!(
            memory.write_log(),
            vec![
                (CONTROL_RING_SLOT_HEADER_SIZE, 3),
                (
                    size_of::<u64>(),
                    CONTROL_RING_SLOT_HEADER_SIZE - size_of::<u64>()
                ),
                (0, size_of::<u64>()),
            ]
        );
    }

    #[test]
    fn failed_payload_metadata_or_sequence_write_does_not_publish_progress() {
        for failed_write in [1, 2, 3] {
            let memory = Arc::new(FailingWriteMemory::new());
            let ring = ControlRing::new(Arc::clone(&memory)).unwrap();
            let mut producer = ControlRingProducer::new(ControlRingDirection::Requests);
            let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);

            producer.try_write(&ring, &[7]).unwrap();
            consumer.observe_tail(producer.published_tail()).unwrap();
            memory.fail_after(failed_write);
            assert_eq!(
                producer.try_write(&ring, &[1, 2, 3]),
                Err(ControlRingError::SharedMemory(
                    SharedMemoryError::InvalidRange
                ))
            );
            assert_eq!(producer.published_tail(), 1);
            assert_eq!(
                consumer.try_read(&ring, owned_bytes),
                Ok(ControlRingReadStatus::Message(vec![7]))
            );
            assert_eq!(
                consumer.try_read(&ring, owned_bytes),
                Ok(ControlRingReadStatus::Empty)
            );

            assert_eq!(
                producer.try_write(&ring, &[1, 2, 3]),
                Ok(ControlRingWriteStatus::Written)
            );
            consumer.observe_tail(producer.published_tail()).unwrap();
            assert_eq!(
                consumer.try_read(&ring, owned_bytes),
                Ok(ControlRingReadStatus::Message(vec![1, 2, 3]))
            );
        }
    }

    #[test]
    fn shorter_reused_payload_does_not_expose_stale_trailing_bytes() {
        let memory = Arc::new(TestMemory::new(CONTROL_RING_MEMORY_SIZE));
        let ring = ControlRing::new(Arc::clone(&memory)).unwrap();
        let mut producer = ControlRingProducer::new(ControlRingDirection::Requests);
        let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);

        producer.try_write(&ring, &[7; 100]).unwrap();
        for _ in 1..CONTROL_RING_SLOT_COUNT {
            producer.try_write(&ring, &[8]).unwrap();
        }
        consumer.observe_tail(producer.published_tail()).unwrap();
        assert_eq!(
            consumer.try_read(&ring, |payload| Ok::<_, ()>(payload.len())),
            Ok(ControlRingReadStatus::Message(100))
        );
        for _ in 1..CONTROL_RING_SLOT_COUNT {
            consumer.try_read(&ring, owned_bytes).unwrap();
        }
        producer.observe_head(consumer.published_head()).unwrap();

        producer.try_write(&ring, &[9]).unwrap();
        assert_eq!(
            &memory.bytes()[CONTROL_RING_SLOT_HEADER_SIZE + 1..CONTROL_RING_SLOT_HEADER_SIZE + 100],
            &[7; 99]
        );
        consumer.observe_tail(producer.published_tail()).unwrap();
        assert_eq!(
            consumer.try_read(&ring, owned_bytes),
            Ok(ControlRingReadStatus::Message(vec![9]))
        );
    }

    #[test]
    fn one_wakeup_notifies_and_acknowledges_a_full_batch() {
        let ring = test_ring();
        let mut producer = ControlRingProducer::new(ControlRingDirection::Requests);
        let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);

        for value in 0..CONTROL_RING_SLOT_COUNT {
            let value = u8::try_from(value).unwrap();
            assert_eq!(
                producer.try_write(&ring, &[value]),
                Ok(ControlRingWriteStatus::Written)
            );
        }
        assert_eq!(
            producer.try_write(&ring, &[0xff]),
            Ok(ControlRingWriteStatus::Full)
        );

        consumer.observe_tail(producer.published_tail()).unwrap();
        for value in 0..CONTROL_RING_SLOT_COUNT {
            let value = u8::try_from(value).unwrap();
            assert_eq!(
                consumer.try_read(&ring, owned_bytes),
                Ok(ControlRingReadStatus::Message(vec![value]))
            );
        }
        assert_eq!(
            consumer.try_read(&ring, owned_bytes),
            Ok(ControlRingReadStatus::Empty)
        );
        assert_eq!(
            producer.try_write(&ring, &[0xff]),
            Ok(ControlRingWriteStatus::Full)
        );

        producer.observe_head(consumer.published_head()).unwrap();
        assert_eq!(
            producer.try_write(&ring, &[0xff]),
            Ok(ControlRingWriteStatus::Written)
        );
        consumer.observe_tail(producer.published_tail()).unwrap();
        assert_eq!(
            consumer.try_read(&ring, owned_bytes),
            Ok(ControlRingReadStatus::Message(vec![0xff]))
        );
    }

    #[test]
    fn producer_rejects_regressed_or_future_heads() {
        let ring = test_ring();
        let mut producer = ControlRingProducer::new(ControlRingDirection::Requests);
        producer.try_write(&ring, &[1]).unwrap();
        producer.try_write(&ring, &[2]).unwrap();

        assert_eq!(producer.observe_head(1), Ok(()));
        assert_eq!(producer.observe_head(1), Ok(()));
        assert_eq!(
            producer.observe_head(0),
            Err(ControlRingError::CounterRegressed {
                previous: 1,
                received: 0
            })
        );
        assert_eq!(
            producer.observe_head(3),
            Err(ControlRingError::CounterOutOfRange {
                local: 2,
                received: 3
            })
        );
    }

    #[test]
    fn consumer_rejects_regressed_or_over_capacity_tails() {
        let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);

        assert_eq!(consumer.observe_tail(CONTROL_RING_SLOT_COUNT), Ok(()));
        assert_eq!(consumer.observe_tail(CONTROL_RING_SLOT_COUNT), Ok(()));
        assert_eq!(
            consumer.observe_tail(CONTROL_RING_SLOT_COUNT - 1),
            Err(ControlRingError::CounterRegressed {
                previous: CONTROL_RING_SLOT_COUNT,
                received: CONTROL_RING_SLOT_COUNT - 1
            })
        );

        let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);
        assert_eq!(
            consumer.observe_tail(CONTROL_RING_SLOT_COUNT + 1),
            Err(ControlRingError::CounterOutOfRange {
                local: 0,
                received: CONTROL_RING_SLOT_COUNT + 1
            })
        );
        consumer.head = CONTROL_RING_SLOT_COUNT;
        assert_eq!(consumer.observe_tail(1), Ok(()));

        let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);
        consumer.head = 1;
        consumer.notified_tail = 1;
        assert_eq!(
            consumer.observe_tail(0),
            Err(ControlRingError::CounterRegressed {
                previous: 1,
                received: 0
            })
        );
    }

    #[test]
    fn consumer_rejects_hostile_slot_metadata() {
        fn assert_rejected(image: &[u8; CONTROL_RING_SLOT_SIZE], expected: ControlRingError) {
            let ring = test_ring();
            install_slot(&ring, image);
            let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);
            assert_eq!(
                consumer.try_read(&ring, owned_bytes),
                Err(ControlRingReadError::Ring(expected))
            );
            assert_eq!(consumer.published_head(), 0);
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
        let ring = test_ring();
        let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);

        assert_eq!(
            consumer.try_read(&ring, owned_bytes),
            Ok(ControlRingReadStatus::Empty)
        );
        install_slot(&ring, &raw_slot(1, 1, 0, &[7]));
        consumer.head = CONTROL_RING_SLOT_COUNT;
        assert_eq!(
            consumer.try_read(&ring, owned_bytes),
            Ok(ControlRingReadStatus::Empty)
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
            let ring = test_ring();
            let mut producer = ControlRingProducer::new(ControlRingDirection::Requests);
            producer.try_write(&ring, &frame).unwrap();
            let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);
            consumer.observe_tail(producer.published_tail()).unwrap();
            assert_eq!(
                consumer.try_read(&ring, decode_request),
                Err(ControlRingReadError::Decode(expected))
            );
            assert_eq!(consumer.published_head(), 0);
        }

        let ring = test_ring();
        let mut producer = ControlRingProducer::new(ControlRingDirection::Requests);
        producer.try_write(&ring, &encoded).unwrap();
        let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);
        consumer.observe_tail(producer.published_tail()).unwrap();
        assert_eq!(
            consumer.try_read(&ring, decode_request),
            Ok(ControlRingReadStatus::Message(request))
        );
    }

    #[test]
    fn decoder_observes_only_the_owned_slot_snapshot() {
        let memory = Arc::new(TestMemory::new(CONTROL_RING_MEMORY_SIZE));
        let ring = ControlRing::new(Arc::clone(&memory)).unwrap();
        let mut producer = ControlRingProducer::new(ControlRingDirection::Requests);
        producer.try_write(&ring, &[1, 2, 3]).unwrap();
        let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);
        consumer.observe_tail(producer.published_tail()).unwrap();

        assert_eq!(
            consumer.try_read(&ring, |payload| {
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
        let memory = TearingMemory::new(&raw_slot(1, 1, 0, &[7]));
        let ring = ControlRing::new(memory).unwrap();
        let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);
        consumer.observe_tail(1).unwrap();

        assert_eq!(
            consumer.try_read(&ring, owned_bytes),
            Err(ControlRingReadError::Ring(
                ControlRingError::InvalidPayloadLength {
                    length: 0xffff_0001
                }
            ))
        );
        assert_eq!(consumer.published_head(), 0);
    }

    #[test]
    fn terminal_sequence_is_used_once_without_wrapping() {
        let memory = Arc::new(TestMemory::new(CONTROL_RING_MEMORY_SIZE));
        let ring = ControlRing::new(Arc::clone(&memory)).unwrap();
        let mut producer = ControlRingProducer::new(ControlRingDirection::Requests);
        producer.tail = u64::MAX - 1;
        producer.acknowledged_head = u64::MAX - 1;

        assert_eq!(
            producer.try_write(&ring, &[7]),
            Ok(ControlRingWriteStatus::Written)
        );
        let writes = memory.write_count.load(Ordering::Relaxed);
        assert_eq!(
            producer.try_write(&ring, &[8]),
            Err(ControlRingError::CounterExhausted)
        );
        assert_eq!(memory.write_count.load(Ordering::Relaxed), writes);

        let mut consumer = ControlRingConsumer::new(ControlRingDirection::Requests);
        consumer.head = u64::MAX - 1;
        consumer.notified_tail = u64::MAX - 1;
        consumer.observe_tail(u64::MAX).unwrap();
        assert_eq!(
            consumer.try_read(&ring, owned_bytes),
            Ok(ControlRingReadStatus::Message(vec![7]))
        );
        assert_eq!(consumer.published_head(), u64::MAX);
        assert_eq!(
            consumer.try_read(&ring, owned_bytes),
            Err(ControlRingReadError::Ring(
                ControlRingError::CounterExhausted
            ))
        );
    }

    fn test_ring() -> ControlRing<TestMemory> {
        ControlRing::new(TestMemory::new(CONTROL_RING_MEMORY_SIZE)).unwrap()
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

    fn install_slot(ring: &ControlRing<TestMemory>, image: &[u8; CONTROL_RING_SLOT_SIZE]) {
        ring.memory()
            .write(size_of::<u64>(), &image[size_of::<u64>()..])
            .unwrap();
        let sequence = u64::from_le_bytes(image[..size_of::<u64>()].try_into().unwrap());
        ring.memory()
            .store_u64_release(0, sequence.to_le())
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
    }

    struct TearingMemory(Mutex<Vec<u8>>);

    impl TearingMemory {
        fn new(first_slot: &[u8; CONTROL_RING_SLOT_SIZE]) -> Self {
            let mut bytes = vec![0; CONTROL_RING_MEMORY_SIZE];
            bytes[..CONTROL_RING_SLOT_SIZE].copy_from_slice(first_slot);
            Self(Mutex::new(bytes))
        }
    }

    impl SharedMemory for TearingMemory {
        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
        }

        fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
            let mut bytes = self.0.lock().unwrap();
            let end = offset
                .checked_add(destination.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            bytes
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;

            destination[..2].copy_from_slice(&bytes[offset..offset + 2]);
            bytes[offset + 2..offset + 4].fill(0xff);
            destination[2..].copy_from_slice(&bytes[offset + 2..end]);
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

    impl AtomicSharedMemory for TearingMemory {
        fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
            test_load_u64_acquire(&self.0, offset)
        }

        fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
            test_store_u64_release(&self.0, offset, value)
        }
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
}
