// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hostile-peer-safe shared control-ring state machines.
//!
//! The memory layout in this module is a transport ABI shared by both
//! control-ring endpoints. Layout changes must also change the versioned
//! activation token so endpoints with incompatible ring layouts fail setup
//! rather than interpreting the same shared memory differently.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ops::Range;
use core::sync::atomic::{Ordering, fence};

use crate::shared_memory::{ControlRingMemory, SharedMemoryError};

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

/// Number of slots in the broker-to-local notification direction.
pub const CONTROL_RING_NOTIFICATION_SLOT_COUNT: u64 = 64;

/// A [`WaitableSharedMemory::spin_limit`] for endpoints whose peer can run in
/// parallel: polling for on the order of 100 µs outlasts a typical broker call
/// yet is far shorter than a scheduler time slice.
pub const CONTROL_RING_PARALLEL_SPIN_LIMIT: u32 = 4000;

// The fixed count is representable by `usize` on every supported target.
#[allow(clippy::cast_possible_truncation)]
const CONTROL_RING_NOTIFICATION_DIRECTION_SIZE: usize =
    CONTROL_RING_SLOT_SIZE * CONTROL_RING_NOTIFICATION_SLOT_COUNT as usize;
const PRODUCER_EPOCH_OFFSET: usize = 0;
const CONSUMER_EPOCH_OFFSET: usize = 4;
const CONSUMER_HEAD_OFFSET: usize = 8;
/// Nonzero while the consumer may block on the producer epoch.
const CONSUMER_WAITING_OFFSET: usize = 16;
/// Nonzero while the producer may block on the consumer epoch.
const PRODUCER_WAITING_OFFSET: usize = 20;
/// Size of the synchronization words of one direction.
const SYNC_WORDS_SIZE: usize = 24;
/// Cache-line size assumed when separating words that different threads poll.
const CACHE_LINE_SIZE: usize = 64;
/// Number of lanes the local peer asks the broker to serve.
const DEMANDED_LANE_COUNT_OFFSET: usize = 0;
/// Incremented whenever the local peer raises its demanded lane count.
const DEMAND_EPOCH_OFFSET: usize = 4;
const DEMAND_WORDS_SIZE: usize = 8;

/// Shape of a control-ring mapping: its call lanes and their capacity.
///
/// A mapping holds one or more *lanes*, each a request direction and a
/// response direction of the same slot count, and one broker-to-local
/// notification direction. Calls on different lanes never queue behind each
/// other, so a deployment that serves each lane separately can run as many
/// calls in parallel as it has lanes.
///
/// The mapping starts with the slots of every direction, in the order lane 0
/// requests, lane 0 responses, lane 1 requests, and so on, then notifications.
/// The synchronization words of each direction follow in the same order, one
/// block of `sync_stride` bytes per direction. With more than one lane, the
/// lane-demand words come last: the local peer raises the number of lanes it
/// uses there, so the broker can start serving a lane only once it is needed.
/// Lane 0 is always in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlRingLayout {
    lane_count: usize,
    call_slots: u64,
    sync_stride: usize,
    ready: &'static [u8],
}

const _: () = assert!(ControlRingLayout::SINGLE_LANE.memory_size() == 24_648);
const _: () = assert!(ControlRingLayout::MULTI_LANE.memory_size() == 11_336);

impl ControlRingLayout {
    /// One lane of 64 slots per direction, served by one broker thread.
    pub const SINGLE_LANE: Self = Self {
        lane_count: 1,
        call_slots: 64,
        sync_stride: SYNC_WORDS_SIZE,
        ready: b"litebox-control-ring-ready-v1",
    };

    /// Eight single-slot lanes, each carrying one call at a time.
    ///
    /// The synchronization words of each direction have a cache line to
    /// themselves, so neither the two directions of a call nor lanes in use at
    /// the same time contend for one.
    pub const MULTI_LANE: Self = Self {
        lane_count: 8,
        call_slots: 1,
        sync_stride: CACHE_LINE_SIZE,
        ready: b"litebox-control-ring-lanes-ready-v1",
    };

    /// Returns the number of lanes.
    pub const fn lane_count(self) -> usize {
        self.lane_count
    }

    /// Returns the versioned token endpoints exchange before activating a
    /// mapping with this layout.
    pub const fn ready_token(self) -> &'static [u8] {
        self.ready
    }

    /// Returns the exact size of a mapping with this layout.
    pub const fn memory_size(self) -> usize {
        if self.lane_count > 1 {
            self.demand_offset() + DEMAND_WORDS_SIZE
        } else {
            self.demand_offset()
        }
    }

    /// Returns the local-to-broker request direction of `lane`.
    ///
    /// # Panics
    ///
    /// Panics if `lane` is not less than [`Self::lane_count`].
    pub const fn requests(self, lane: usize) -> ControlRingDirection {
        assert!(lane < self.lane_count, "control-ring lane out of range");
        self.direction(2 * lane)
    }

    /// Returns the broker-to-local response direction of `lane`.
    ///
    /// # Panics
    ///
    /// Panics if `lane` is not less than [`Self::lane_count`].
    pub const fn responses(self, lane: usize) -> ControlRingDirection {
        assert!(lane < self.lane_count, "control-ring lane out of range");
        self.direction(2 * lane + 1)
    }

    /// Returns the broker-to-local notification direction.
    pub const fn notifications(self) -> ControlRingDirection {
        self.direction(2 * self.lane_count)
    }

    /// Returns whether this layout permits a byte-copy range.
    ///
    /// Concrete shared-memory implementations use this together with
    /// [`Self::permits_u32`] and [`Self::permits_u64`] to keep their own byte
    /// and typed-word accesses disjoint. A peer can bypass these checks through
    /// its backing-resource alias, so implementations must remain memory-safe
    /// under arbitrary peer writes.
    pub const fn permits_byte_range(self, offset: usize, length: usize) -> bool {
        let Some(end) = offset.checked_add(length) else {
            return false;
        };
        if end > self.memory_size() {
            return false;
        }
        if length == 0 {
            return true;
        }
        let slot_offset = offset % CONTROL_RING_SLOT_SIZE;
        end <= self.data_size()
            && slot_offset >= size_of::<u64>()
            && slot_offset + length <= CONTROL_RING_SLOT_SIZE
    }

    /// Returns whether this layout permits a `u32` access at `offset`.
    pub const fn permits_u32(self, offset: usize) -> bool {
        let Some(relative) = offset.checked_sub(self.data_size()) else {
            return false;
        };
        if relative < self.sync_size() {
            return matches!(
                relative % self.sync_stride,
                PRODUCER_EPOCH_OFFSET
                    | CONSUMER_EPOCH_OFFSET
                    | CONSUMER_WAITING_OFFSET
                    | PRODUCER_WAITING_OFFSET
            );
        }
        self.lane_count > 1
            && matches!(
                relative - self.sync_size(),
                DEMANDED_LANE_COUNT_OFFSET | DEMAND_EPOCH_OFFSET
            )
    }

    /// Returns whether this layout permits a `u64` access at `offset`.
    pub const fn permits_u64(self, offset: usize) -> bool {
        if offset < self.data_size() {
            return offset.is_multiple_of(CONTROL_RING_SLOT_SIZE);
        }
        let relative = offset - self.data_size();
        relative < self.sync_size() && relative % self.sync_stride == CONSUMER_HEAD_OFFSET
    }

    /// Returns the number of `u32` words an endpoint may block on: the
    /// producer and consumer epochs of every direction and, with more than one
    /// lane, the lane-demand epoch.
    pub const fn waitable_word_count(self) -> usize {
        2 * self.direction_count() + if self.lane_count > 1 { 1 } else { 0 }
    }

    /// Returns the position of the waitable `u32` at `offset` among the
    /// [`Self::waitable_word_count`] words, or `None` if no endpoint blocks
    /// on it.
    pub const fn waitable_word_index(self, offset: usize) -> Option<usize> {
        let Some(relative) = offset.checked_sub(self.data_size()) else {
            return None;
        };
        if relative < self.sync_size() {
            let direction = relative / self.sync_stride;
            return match relative % self.sync_stride {
                PRODUCER_EPOCH_OFFSET => Some(2 * direction),
                CONSUMER_EPOCH_OFFSET => Some(2 * direction + 1),
                _ => None,
            };
        }
        if self.lane_count > 1 && relative - self.sync_size() == DEMAND_EPOCH_OFFSET {
            Some(2 * self.direction_count())
        } else {
            None
        }
    }

    const fn direction_count(self) -> usize {
        2 * self.lane_count + 1
    }

    // Layout slot counts are small constants representable by `usize`.
    #[allow(clippy::cast_possible_truncation)]
    const fn call_direction_size(self) -> usize {
        CONTROL_RING_SLOT_SIZE * self.call_slots as usize
    }

    const fn data_size(self) -> usize {
        2 * self.lane_count * self.call_direction_size() + CONTROL_RING_NOTIFICATION_DIRECTION_SIZE
    }

    const fn sync_size(self) -> usize {
        self.direction_count() * self.sync_stride
    }

    const fn demand_offset(self) -> usize {
        self.data_size() + self.sync_size()
    }

    /// Returns the direction at `index` in mapping order, the notification
    /// direction coming after every lane's.
    const fn direction(self, index: usize) -> ControlRingDirection {
        ControlRingDirection {
            data_offset: index * self.call_direction_size(),
            slot_count: if index == 2 * self.lane_count {
                CONTROL_RING_NOTIFICATION_SLOT_COUNT
            } else {
                self.call_slots
            },
            sync_offset: self.data_size() + index * self.sync_stride,
        }
    }
}

const _: () = assert!(SYNC_WORDS_SIZE.is_multiple_of(size_of::<u64>()));
const _: () = assert!(CACHE_LINE_SIZE >= SYNC_WORDS_SIZE);
const _: () = assert!(
    ControlRingLayout::MULTI_LANE
        .data_size()
        .is_multiple_of(CACHE_LINE_SIZE)
);

/// Access model enforced by a concrete shared-memory mapping.
///
/// This keeps byte-copy memory from exposing typed control-ring operations and
/// constrains control-ring accesses to the disjoint regions defined by its ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryAccessPolicy {
    /// General shared memory supporting only byte copies.
    Bytes,
    /// Control-ring memory supporting the byte and word accesses its layout
    /// defines.
    ControlRing(ControlRingLayout),
}

impl MemoryAccessPolicy {
    /// Returns whether this policy permits a byte-copy range.
    pub const fn permits_byte_range(self, offset: usize, length: usize) -> bool {
        match self {
            Self::Bytes => true,
            Self::ControlRing(layout) => layout.permits_byte_range(offset, length),
        }
    }

    /// Returns whether this policy permits a `u32` access at `offset`.
    pub const fn permits_u32(self, offset: usize) -> bool {
        match self {
            Self::Bytes => false,
            Self::ControlRing(layout) => layout.permits_u32(offset),
        }
    }

    /// Returns whether this policy permits a `u64` access at `offset`.
    pub const fn permits_u64(self, offset: usize) -> bool {
        match self {
            Self::Bytes => false,
            Self::ControlRing(layout) => layout.permits_u64(offset),
        }
    }
}

/// One direction in a control-ring mapping, as placed by its
/// [`ControlRingLayout`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlRingDirection {
    data_offset: usize,
    slot_count: u64,
    sync_offset: usize,
}

impl ControlRingDirection {
    fn slot_range(self, slot: u64) -> Range<usize> {
        debug_assert!(slot < self.slot_count);
        let slot = usize::try_from(slot).expect("control-ring slot index is bounded");
        let start = self.data_offset + slot * CONTROL_RING_SLOT_SIZE;
        start..start + CONTROL_RING_SLOT_SIZE
    }

    /// Returns the number of slots in this direction.
    pub const fn slot_count(self) -> u64 {
        self.slot_count
    }

    /// Returns the `u32` epoch incremented when the producer publishes work for
    /// this direction.
    pub const fn producer_epoch_offset(self) -> usize {
        self.sync_offset + PRODUCER_EPOCH_OFFSET
    }

    /// Returns the `u32` epoch incremented when the consumer publishes progress
    /// for this direction.
    pub const fn consumer_epoch_offset(self) -> usize {
        self.sync_offset + CONSUMER_EPOCH_OFFSET
    }

    /// Returns the `u64` consumer-head offset for this direction.
    pub const fn consumer_head_offset(self) -> usize {
        self.sync_offset + CONSUMER_HEAD_OFFSET
    }

    const fn consumer_waiting_offset(self) -> usize {
        self.sync_offset + CONSUMER_WAITING_OFFSET
    }

    const fn producer_waiting_offset(self) -> usize {
        self.sync_offset + PRODUCER_WAITING_OFFSET
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

/// Exact-size shared memory holding the directions of a [`ControlRingLayout`].
pub struct ControlRing<Memory: ControlRingMemory> {
    memory: Memory,
    layout: ControlRingLayout,
}

/// The local peer's ends of one call lane.
pub struct LocalControlRingLane<Memory: ControlRingMemory> {
    /// Local-to-broker request producer.
    pub request_producer: ControlRingProducer<Memory>,
    /// Broker-to-local response consumer.
    pub response_consumer: ControlRingConsumer<Memory>,
}

/// The broker peer's ends of one call lane.
pub struct BrokerControlRingLane<Memory: ControlRingMemory> {
    /// Local-to-broker request consumer.
    pub request_consumer: ControlRingConsumer<Memory>,
    /// Broker-to-local response producer.
    pub response_producer: ControlRingProducer<Memory>,
}

/// Role-bound association ring endpoints owned by the local peer.
pub struct LocalControlRingEndpoints<Memory: ControlRingMemory> {
    /// Call lanes, in lane order.
    pub lanes: Vec<LocalControlRingLane<Memory>>,
    /// Lane-demand publisher, present when the layout has more than one lane.
    pub lane_demand: Option<LocalLaneDemand<Memory>>,
    /// Broker-to-local notification consumer.
    pub notification_consumer: ControlRingConsumer<Memory>,
}

/// Role-bound association ring endpoints owned by the broker peer.
pub struct BrokerControlRingEndpoints<Memory: ControlRingMemory> {
    /// Call lanes, in lane order.
    pub lanes: Vec<BrokerControlRingLane<Memory>>,
    /// Lane-demand observer, present when the layout has more than one lane.
    pub lane_demand: Option<BrokerLaneDemand<Memory>>,
    /// Broker-to-local notification producer.
    pub notification_producer: ControlRingProducer<Memory>,
}

impl<Memory: ControlRingMemory> LocalControlRingEndpoints<Memory> {
    /// Returns handles that interrupt every wait these endpoints offer.
    pub fn wake_handles(&self) -> Vec<ControlRingWakeHandle<Memory>> {
        self.lanes
            .iter()
            .flat_map(|lane| {
                [
                    lane.request_producer.wake_handle(),
                    lane.response_consumer.wake_handle(),
                ]
            })
            .chain([self.notification_consumer.wake_handle()])
            .collect()
    }
}

impl<Memory: ControlRingMemory> BrokerControlRingEndpoints<Memory> {
    /// Returns handles that interrupt every wait these endpoints offer.
    pub fn wake_handles(&self) -> Vec<ControlRingWakeHandle<Memory>> {
        self.lanes
            .iter()
            .flat_map(|lane| {
                [
                    lane.request_consumer.wake_handle(),
                    lane.response_producer.wake_handle(),
                ]
            })
            .chain([self.notification_producer.wake_handle()])
            .chain(self.lane_demand.as_ref().map(BrokerLaneDemand::wake_handle))
            .collect()
    }
}

impl<Memory: ControlRingMemory> ControlRing<Memory> {
    /// Attaches to an exact-size shared control-ring mapping with `layout`.
    pub fn new(memory: Memory, layout: ControlRingLayout) -> Result<Self, ControlRingError> {
        let actual = memory.len();
        let expected = layout.memory_size();
        if actual != expected {
            return Err(ControlRingError::MemoryLengthMismatch { expected, actual });
        }
        Ok(Self { memory, layout })
    }

    /// Returns the layout of this mapping.
    pub const fn layout(&self) -> ControlRingLayout {
        self.layout
    }

    /// Returns the copy-only shared-memory resource.
    pub const fn memory(&self) -> &Memory {
        &self.memory
    }

    /// Consumes the mapping into endpoints owned by the local peer.
    pub fn into_local(self) -> LocalControlRingEndpoints<Memory> {
        let layout = self.layout;
        let ring = Arc::new(self);
        LocalControlRingEndpoints {
            lanes: (0..layout.lane_count())
                .map(|lane| LocalControlRingLane {
                    request_producer: ControlRingProducer::new(
                        Arc::clone(&ring),
                        layout.requests(lane),
                    ),
                    response_consumer: ControlRingConsumer::new(
                        Arc::clone(&ring),
                        layout.responses(lane),
                    ),
                })
                .collect(),
            lane_demand: (layout.lane_count() > 1).then(|| LocalLaneDemand {
                ring: Arc::clone(&ring),
            }),
            notification_consumer: ControlRingConsumer::new(ring, layout.notifications()),
        }
    }

    /// Consumes the mapping into endpoints owned by the broker peer.
    pub fn into_broker(self) -> BrokerControlRingEndpoints<Memory> {
        let layout = self.layout;
        let ring = Arc::new(self);
        BrokerControlRingEndpoints {
            lanes: (0..layout.lane_count())
                .map(|lane| BrokerControlRingLane {
                    request_consumer: ControlRingConsumer::new(
                        Arc::clone(&ring),
                        layout.requests(lane),
                    ),
                    response_producer: ControlRingProducer::new(
                        Arc::clone(&ring),
                        layout.responses(lane),
                    ),
                })
                .collect(),
            lane_demand: (layout.lane_count() > 1).then(|| BrokerLaneDemand {
                ring: Arc::clone(&ring),
                started_lane_count: 0,
            }),
            notification_producer: ControlRingProducer::new(ring, layout.notifications()),
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
        self.memory.store_u64_and_increment_u32_release(
            range.start,
            sequence.to_le(),
            direction.producer_epoch_offset(),
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

/// Local-peer end of the lane-demand words of a multi-lane control ring.
///
/// The local peer raises the number of lanes it uses before it first writes a
/// request to a lane, and the broker starts serving a lane once it is
/// demanded. Lane 0 is always demanded.
pub struct LocalLaneDemand<Memory: ControlRingMemory> {
    ring: Arc<ControlRing<Memory>>,
}

impl<Memory: ControlRingMemory> LocalLaneDemand<Memory> {
    /// Publishes that the local peer uses the first `lanes` lanes.
    ///
    /// The count must not decrease within an association.
    ///
    /// # Panics
    ///
    /// Panics if `lanes` exceeds the layout's lane count.
    pub fn request(&self, lanes: usize) -> Result<(), ControlRingError> {
        let layout = self.ring.layout;
        assert!(lanes <= layout.lane_count(), "lane demand out of range");
        let lanes = u32::try_from(lanes).expect("lane count is bounded by the layout");
        let demand = layout.demand_offset();
        self.ring
            .memory
            .store_u32_release(demand + DEMANDED_LANE_COUNT_OFFSET, lanes.to_le())?;
        self.ring
            .memory
            .increment_u32_release(demand + DEMAND_EPOCH_OFFSET)?;
        Ok(())
    }
}

impl<Memory: WaitableSharedMemory> LocalLaneDemand<Memory> {
    /// Wakes the broker after [`Self::request`].
    ///
    /// The wake is unconditional: demand rises at most once per lane, so
    /// there is nothing to gain from an announcement word.
    pub fn wake_broker(&self) -> Result<(), Memory::Error> {
        self.ring
            .memory
            .wake_one(self.ring.layout.demand_offset() + DEMAND_EPOCH_OFFSET)
    }
}

/// Result of polling a [`BrokerLaneDemand`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlRingDemandStatus {
    /// The local peer demands this lane, which the broker has yet to serve.
    Lane(usize),
    /// The broker serves every demanded lane.
    Satisfied {
        /// Demand epoch sampled before the demand was read.
        wait_epoch: u32,
    },
}

/// Broker-peer end of the lane-demand words of a multi-lane control ring.
///
/// It hands out each lane, in lane order, once the local peer demands it.
/// The local peer can publish any count; the broker clamps it to the layout's
/// lanes and never takes a lane back.
pub struct BrokerLaneDemand<Memory: ControlRingMemory> {
    ring: Arc<ControlRing<Memory>>,
    started_lane_count: usize,
}

impl<Memory: ControlRingMemory> BrokerLaneDemand<Memory> {
    /// Returns the next demanded lane the broker has yet to serve, if any.
    pub fn try_next_lane(&mut self) -> Result<ControlRingDemandStatus, ControlRingError> {
        let layout = self.ring.layout;
        let demand = layout.demand_offset();
        let wait_epoch = self
            .ring
            .memory
            .load_u32_acquire(demand + DEMAND_EPOCH_OFFSET)?;
        let demanded_lane_count = u32::from_le(
            self.ring
                .memory
                .load_u32_acquire(demand + DEMANDED_LANE_COUNT_OFFSET)?,
        );
        let demanded_lane_count = usize::try_from(demanded_lane_count)
            .unwrap_or(usize::MAX)
            .clamp(1, layout.lane_count());
        if self.started_lane_count < demanded_lane_count {
            let lane = self.started_lane_count;
            self.started_lane_count += 1;
            return Ok(ControlRingDemandStatus::Lane(lane));
        }
        Ok(ControlRingDemandStatus::Satisfied { wait_epoch })
    }

    /// Returns a handle that can interrupt [`Self::wait_for_demand`].
    pub fn wake_handle(&self) -> ControlRingWakeHandle<Memory> {
        ControlRingWakeHandle::new(
            &self.ring,
            self.ring.layout.demand_offset() + DEMAND_EPOCH_OFFSET,
        )
    }
}

impl<Memory: WaitableSharedMemory> BrokerLaneDemand<Memory> {
    /// Waits for new demand after [`ControlRingDemandStatus::Satisfied`].
    ///
    /// The caller must poll again after this possibly spurious wakeup.
    pub fn wait_for_demand(&mut self, wait_epoch: u32) -> Result<(), Memory::Error> {
        self.ring.memory.wait_while_equal(
            self.ring.layout.demand_offset() + DEMAND_EPOCH_OFFSET,
            wait_epoch,
        )
    }
}

/// Trusted endpoint-local state for one control-ring producer.
pub struct ControlRingProducer<Memory: ControlRingMemory> {
    ring: Arc<ControlRing<Memory>>,
    direction: ControlRingDirection,
    tail: u64,
    acknowledged_head: u64,
}

/// Cloneable, narrow handle for interrupting a wait on one ring endpoint.
///
/// This handle intentionally exposes neither the backing memory nor endpoint
/// state. Concrete transports use it to interrupt a ring wait provided by
/// [`WaitableSharedMemory`] when liveness or cancellation state changes. It is
/// public so that transport bindings outside this crate, such as the endpoints
/// in `litebox_broker_transport_linux_userland`, can interrupt ring waits
/// without gaining access to ring memory.
pub struct ControlRingWakeHandle<Memory: ControlRingMemory> {
    ring: Arc<ControlRing<Memory>>,
    epoch_offset: usize,
}

/// Shared-memory wait and wake support for control-ring epoch words.
///
/// The ring state machines themselves are nonblocking: they report
/// [`Full`](ControlRingWriteStatus::Full) or [`Empty`](ControlRingReadStatus::Empty)
/// together with the epoch that was sampled before the final check. Shared
/// memory that can also block and wake threads on those epoch words implements
/// this trait, which lets ring endpoints offer blocking waits without knowing
/// whether the backing memory uses a futex, a kernel event, or something else.
///
/// Implementations must publish and observe epoch changes through the same
/// coherent shared memory the ring uses, so a wake that follows an epoch change
/// can never be missed by a waiter that sampled the previous epoch.
///
/// Ring endpoints first poll the epoch for up to [`Self::spin_limit`]
/// iterations, then announce in a shared word that they may block, and their
/// peer wakes them only while that word is set. A peer that clears the word
/// only loses its own wakes, as it could by never publishing progress.
pub trait WaitableSharedMemory: ControlRingMemory {
    /// Error reported by blocking operations on this shared memory.
    type Error;

    /// Converts a shared-memory access failure into [`Self::Error`].
    fn wait_access_error(error: SharedMemoryError) -> Self::Error;

    /// Waits while the naturally aligned `u32` at `offset` equals `expected`.
    ///
    /// A value change or an interruption must be reported as a successful,
    /// possibly spurious wakeup, so callers must recheck their wait condition.
    fn wait_while_equal(&self, offset: usize, expected: u32) -> Result<(), Self::Error>;

    /// Wakes one waiter blocked on the naturally aligned `u32` at `offset`.
    fn wake_one(&self, offset: usize) -> Result<(), Self::Error>;

    /// Returns how many times a ring endpoint polls an epoch before blocking.
    ///
    /// Polling sees a peer running on another CPU publish progress without the
    /// cost of blocking and waking, so it pays off only when the peers can run
    /// in parallel.
    fn spin_limit(&self) -> u32 {
        0
    }
}

impl<Memory: ControlRingMemory> Clone for ControlRingWakeHandle<Memory> {
    fn clone(&self) -> Self {
        Self {
            ring: Arc::clone(&self.ring),
            epoch_offset: self.epoch_offset,
        }
    }
}

impl<Memory: ControlRingMemory> ControlRingWakeHandle<Memory> {
    fn new(ring: &Arc<ControlRing<Memory>>, epoch_offset: usize) -> Self {
        Self {
            ring: Arc::clone(ring),
            epoch_offset,
        }
    }

    pub(crate) const fn wait_epoch_offset(&self) -> usize {
        self.epoch_offset
    }

    pub(crate) fn memory(&self) -> &Memory {
        self.ring.memory()
    }
}

impl<Memory: WaitableSharedMemory> ControlRing<Memory> {
    /// Waits while the epoch at `epoch_offset` equals `expected`: polls it,
    /// then blocks with the wait announced in the `u32` at `waiting_offset`.
    ///
    /// Each announcement word has one waiter, as endpoint waits take
    /// `&mut self`.
    fn wait_while_equal(
        &self,
        epoch_offset: usize,
        expected: u32,
        waiting_offset: usize,
    ) -> Result<(), Memory::Error> {
        let memory = &self.memory;
        for _ in 0..memory.spin_limit() {
            let epoch = memory
                .load_u32_acquire(epoch_offset)
                .map_err(Memory::wait_access_error)?;
            if epoch != expected {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        memory
            .store_u32_release(waiting_offset, 1)
            .map_err(Memory::wait_access_error)?;
        // Orders the announcement before the epoch check in the wait, as
        // `wake_waiter` orders the epoch change before its announcement check:
        // the waiter sees the new epoch or the waker sees the announcement.
        fence(Ordering::SeqCst);
        let result = memory.wait_while_equal(epoch_offset, expected);
        memory
            .store_u32_release(waiting_offset, 0)
            .map_err(Memory::wait_access_error)?;
        result
    }

    /// Wakes the waiter on the epoch at `epoch_offset`, already changed, if
    /// the `u32` at `waiting_offset` announces it may be blocked.
    fn wake_waiter(&self, epoch_offset: usize, waiting_offset: usize) -> Result<(), Memory::Error> {
        // Pairs with the fence in `wait_while_equal`.
        fence(Ordering::SeqCst);
        let waiting = self
            .memory
            .load_u32_acquire(waiting_offset)
            .map_err(Memory::wait_access_error)?;
        if waiting == 0 {
            return Ok(());
        }
        self.memory.wake_one(epoch_offset)
    }
}

impl<Memory: WaitableSharedMemory> ControlRingWakeHandle<Memory> {
    /// Changes and wakes the epoch observed by this endpoint's wait operation.
    ///
    /// Incrementing before waking closes the race where cancellation happens
    /// after a ring operation samples its epoch but before it starts to wait.
    /// The wake ignores the announcement word, which the peer can clear.
    pub fn interrupt_wait(&self) -> Result<(), Memory::Error> {
        self.memory()
            .increment_u32_release(self.wait_epoch_offset())
            .map_err(Memory::wait_access_error)?;
        self.memory().wake_one(self.wait_epoch_offset())
    }
}

impl<Memory: ControlRingMemory> ControlRingProducer<Memory> {
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

    /// Whether the consumer has yet to publish its progress past a written
    /// message.
    pub fn has_unconsumed(&self) -> Result<bool, ControlRingError> {
        Ok(self.ring.load_consumer_head(self.direction)? < self.tail)
    }

    /// Returns a handle that can interrupt a wait on this producer's ring
    /// direction.
    pub fn wake_handle(&self) -> ControlRingWakeHandle<Memory> {
        ControlRingWakeHandle::new(&self.ring, self.direction.consumer_epoch_offset())
    }

    #[cfg(test)]
    fn memory(&self) -> &Memory {
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

impl<Memory: WaitableSharedMemory> ControlRingProducer<Memory> {
    /// Waits for consumer progress after [`ControlRingWriteStatus::Full`].
    ///
    /// The caller must retry the write after this possibly spurious wakeup.
    pub fn wait_for_capacity(&mut self, wait_epoch: u32) -> Result<(), Memory::Error> {
        self.ring.wait_while_equal(
            self.direction.consumer_epoch_offset(),
            wait_epoch,
            self.direction.producer_waiting_offset(),
        )
    }

    /// Wakes the consumer, if it may be blocked, after publishing one or more
    /// messages.
    pub fn wake_consumer(&self) -> Result<(), Memory::Error> {
        self.ring.wake_waiter(
            self.direction.producer_epoch_offset(),
            self.direction.consumer_waiting_offset(),
        )
    }
}

/// Trusted endpoint-local state for one control-ring consumer.
pub struct ControlRingConsumer<Memory: ControlRingMemory> {
    ring: Arc<ControlRing<Memory>>,
    direction: ControlRingDirection,
    head: u64,
    published_head: u64,
}

impl<Memory: ControlRingMemory> ControlRingConsumer<Memory> {
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

    /// Returns a handle that can interrupt a wait on this consumer's ring
    /// direction.
    pub fn wake_handle(&self) -> ControlRingWakeHandle<Memory> {
        ControlRingWakeHandle::new(&self.ring, self.direction.producer_epoch_offset())
    }

    #[cfg(test)]
    fn memory(&self) -> &Memory {
        self.ring.memory()
    }

    /// Publishes newly consumed slots and advances the consumer wake epoch.
    pub fn publish_head(&mut self) -> Result<(), ControlRingError> {
        if self.head == self.published_head {
            return Ok(());
        }
        self.ring.memory.store_u64_and_increment_u32_release(
            self.direction.consumer_head_offset(),
            self.head.to_le(),
            self.direction.consumer_epoch_offset(),
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
        // Keep every slot-body load before the sequence recheck so a hostile
        // producer cannot pass validation with a body read after publication.
        fence(Ordering::Acquire);
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

impl<Memory: WaitableSharedMemory> ControlRingConsumer<Memory> {
    /// Waits for producer progress after [`ControlRingReadStatus::Empty`].
    ///
    /// The caller must retry the read after this possibly spurious wakeup.
    pub fn wait_for_message(&mut self, wait_epoch: u32) -> Result<(), Memory::Error> {
        self.ring.wait_while_equal(
            self.direction.producer_epoch_offset(),
            wait_epoch,
            self.direction.consumer_waiting_offset(),
        )
    }

    /// Wakes the producer, if it may be blocked, after publishing newly
    /// consumed slots.
    pub fn wake_producer(&self) -> Result<(), Memory::Error> {
        self.ring.wake_waiter(
            self.direction.consumer_epoch_offset(),
            self.direction.producer_waiting_offset(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_memory::SharedMemory;
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
    const LAYOUT: ControlRingLayout = ControlRingLayout::SINGLE_LANE;
    const LAYOUTS: [ControlRingLayout; 2] = [
        ControlRingLayout::SINGLE_LANE,
        ControlRingLayout::MULTI_LANE,
    ];
    const MEMORY_SIZE: usize = LAYOUT.memory_size();
    const REQUESTS: ControlRingDirection = LAYOUT.requests(0);
    const RESPONSES: ControlRingDirection = LAYOUT.responses(0);
    const NOTIFICATIONS: ControlRingDirection = LAYOUT.notifications();
    const SLOT_COUNT: u64 = REQUESTS.slot_count();

    #[test]
    fn mapping_requires_the_exact_control_ring_size() {
        assert_eq!(ControlRingLayout::SINGLE_LANE.memory_size(), 24_648);
        for layout in LAYOUTS {
            let size = layout.memory_size();
            assert!(matches!(
                ControlRing::new(TestMemory::new(size - 1), layout),
                Err(ControlRingError::MemoryLengthMismatch { expected, actual })
                    if expected == size && actual == size - 1
            ));
            assert!(matches!(
                ControlRing::new(TestMemory::new(size + 1), layout),
                Err(ControlRingError::MemoryLengthMismatch { expected, actual })
                    if expected == size && actual == size + 1
            ));
            assert!(ControlRing::new(TestMemory::new(size), layout).is_ok());
        }
    }

    #[test]
    fn memory_layout_separates_byte_and_word_regions() {
        for layout in LAYOUTS {
            assert!(layout.permits_u64(0));
            assert!(!layout.permits_u32(0));
            assert!(!layout.permits_byte_range(0, 1));
            assert!(
                layout.permits_byte_range(
                    size_of::<u64>(),
                    CONTROL_RING_SLOT_SIZE - size_of::<u64>()
                )
            );
            assert!(!layout.permits_byte_range(
                size_of::<u64>(),
                CONTROL_RING_SLOT_SIZE - size_of::<u64>() + 1
            ));

            let sync_start = layout.data_size();
            assert!(!layout.permits_byte_range(sync_start - 1, 2));
            assert!(layout.permits_u32(sync_start + PRODUCER_EPOCH_OFFSET));
            assert!(layout.permits_u32(sync_start + CONSUMER_EPOCH_OFFSET));
            assert!(layout.permits_u64(sync_start + CONSUMER_HEAD_OFFSET));
            assert!(layout.permits_u32(sync_start + CONSUMER_WAITING_OFFSET));
            assert!(layout.permits_u32(sync_start + PRODUCER_WAITING_OFFSET));
            assert!(!layout.permits_u64(sync_start + CONSUMER_WAITING_OFFSET));
            assert!(!layout.permits_u32(sync_start + CONSUMER_HEAD_OFFSET));
            assert!(!layout.permits_byte_range(sync_start, 1));
            let size = layout.memory_size();
            assert!(!layout.permits_u32(size));
            assert!(!layout.permits_u64(size));
            assert!(!layout.permits_byte_range(size, 1));
            assert!(layout.permits_byte_range(size, 0));
        }

        let multi_lane = ControlRingLayout::MULTI_LANE;
        let padding = multi_lane.data_size() + SYNC_WORDS_SIZE;
        assert!(!multi_lane.permits_u32(padding));
        assert!(!multi_lane.permits_u64(padding));
        let demand = multi_lane.demand_offset();
        assert!(multi_lane.permits_u32(demand + DEMANDED_LANE_COUNT_OFFSET));
        assert!(multi_lane.permits_u32(demand + DEMAND_EPOCH_OFFSET));
        assert!(!multi_lane.permits_u64(demand));
        assert!(!multi_lane.permits_byte_range(demand, 1));
    }

    #[test]
    fn directions_occupy_disjoint_data_and_sync_ranges() {
        for layout in LAYOUTS {
            let directions: Vec<_> = (0..layout.lane_count())
                .flat_map(|lane| [layout.requests(lane), layout.responses(lane)])
                .chain([layout.notifications()])
                .collect();
            let mut next_data_offset = 0;
            for direction in &directions {
                let first = direction.slot_range(0);
                let last = direction.slot_range(direction.slot_count() - 1);
                assert_eq!(first.start, next_data_offset);
                assert_eq!(
                    last.end - first.start,
                    usize::try_from(direction.slot_count()).unwrap() * CONTROL_RING_SLOT_SIZE
                );
                next_data_offset = last.end;
            }
            assert_eq!(next_data_offset, layout.data_size());

            for (index, direction) in directions.iter().enumerate() {
                assert_eq!(
                    direction.producer_epoch_offset(),
                    layout.data_size() + index * layout.sync_stride
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
                assert_eq!(
                    direction.consumer_waiting_offset(),
                    direction.consumer_head_offset() + size_of::<u64>()
                );
                assert_eq!(
                    direction.producer_waiting_offset(),
                    direction.consumer_waiting_offset() + size_of::<u32>()
                );
            }
            assert_eq!(
                layout.notifications().sync_offset + layout.sync_stride,
                layout.demand_offset()
            );
        }
        assert_eq!(
            ControlRingLayout::SINGLE_LANE.demand_offset(),
            ControlRingLayout::SINGLE_LANE.memory_size()
        );
        assert_eq!(
            ControlRingLayout::MULTI_LANE.demand_offset() + DEMAND_WORDS_SIZE,
            ControlRingLayout::MULTI_LANE.memory_size()
        );
    }

    #[test]
    fn waitable_words_are_indexed_densely() {
        for layout in LAYOUTS {
            let mut indices: Vec<_> = (0..layout.memory_size())
                .filter_map(|offset| layout.waitable_word_index(offset))
                .collect();
            assert_eq!(indices.len(), layout.waitable_word_count());
            indices.sort_unstable();
            indices.dedup();
            assert_eq!(indices.len(), layout.waitable_word_count());
            assert!(
                indices
                    .iter()
                    .all(|&index| index < layout.waitable_word_count())
            );
            for offset in 0..layout.memory_size() {
                if layout.waitable_word_index(offset).is_some() {
                    assert!(layout.permits_u32(offset));
                }
            }
            let mut wait_offsets: Vec<_> = (0..layout.lane_count())
                .flat_map(|lane| [layout.requests(lane), layout.responses(lane)])
                .chain([layout.notifications()])
                .flat_map(|direction| {
                    [
                        direction.producer_epoch_offset(),
                        direction.consumer_epoch_offset(),
                    ]
                })
                .collect();
            if layout.lane_count() > 1 {
                wait_offsets.push(layout.demand_offset() + DEMAND_EPOCH_OFFSET);
            }
            assert_eq!(wait_offsets.len(), layout.waitable_word_count());
            for offset in wait_offsets {
                assert!(layout.waitable_word_index(offset).is_some());
            }
        }
        assert_eq!(ControlRingLayout::SINGLE_LANE.waitable_word_count(), 6);
    }

    #[test]
    fn endpoint_roles_bind_opposite_directions_to_one_mapping() {
        for layout in LAYOUTS {
            let local = test_ring_with(layout).into_local();
            assert_eq!(local.lanes.len(), layout.lane_count());
            assert_eq!(local.lane_demand.is_some(), layout.lane_count() > 1);
            for (index, lane) in local.lanes.iter().enumerate() {
                assert_eq!(lane.request_producer.direction(), layout.requests(index));
                assert_eq!(lane.response_consumer.direction(), layout.responses(index));
                assert!(Arc::ptr_eq(
                    &lane.request_producer.ring,
                    &local.notification_consumer.ring
                ));
                assert!(Arc::ptr_eq(
                    &lane.response_consumer.ring,
                    &local.notification_consumer.ring
                ));
            }
            assert_eq!(
                local.notification_consumer.direction(),
                layout.notifications()
            );
            assert_eq!(local.wake_handles().len(), 2 * layout.lane_count() + 1);

            let broker = test_ring_with(layout).into_broker();
            assert_eq!(broker.lanes.len(), layout.lane_count());
            assert_eq!(broker.lane_demand.is_some(), layout.lane_count() > 1);
            for (index, lane) in broker.lanes.iter().enumerate() {
                assert_eq!(lane.request_consumer.direction(), layout.requests(index));
                assert_eq!(lane.response_producer.direction(), layout.responses(index));
                assert!(Arc::ptr_eq(
                    &lane.request_consumer.ring,
                    &broker.notification_producer.ring
                ));
                assert!(Arc::ptr_eq(
                    &lane.response_producer.ring,
                    &broker.notification_producer.ring
                ));
            }
            assert_eq!(
                broker.notification_producer.direction(),
                layout.notifications()
            );
            assert_eq!(
                broker.wake_handles().len(),
                2 * layout.lane_count() + 1 + usize::from(layout.lane_count() > 1)
            );
        }
    }

    #[test]
    fn single_slot_lanes_carry_one_call_at_a_time() {
        let layout = ControlRingLayout::MULTI_LANE;
        let ring = Arc::new(test_ring_with(layout));
        let mut lanes: Vec<_> = (0..layout.lane_count())
            .map(|lane| {
                let local = LocalControlRingLane {
                    request_producer: ControlRingProducer::new(
                        Arc::clone(&ring),
                        layout.requests(lane),
                    ),
                    response_consumer: ControlRingConsumer::new(
                        Arc::clone(&ring),
                        layout.responses(lane),
                    ),
                };
                let broker = BrokerControlRingLane {
                    request_consumer: ControlRingConsumer::new(
                        Arc::clone(&ring),
                        layout.requests(lane),
                    ),
                    response_producer: ControlRingProducer::new(
                        Arc::clone(&ring),
                        layout.responses(lane),
                    ),
                };
                (local, broker)
            })
            .collect();
        for round in 0..3_u8 {
            for (index, (local, broker)) in lanes.iter_mut().enumerate() {
                let request = [round, u8::try_from(index).unwrap()];
                assert_eq!(
                    local.request_producer.try_write(&request),
                    Ok(ControlRingWriteStatus::Written)
                );
                assert!(matches!(
                    local.request_producer.try_write(&request),
                    Ok(ControlRingWriteStatus::Full { .. })
                ));
                assert_eq!(
                    broker.request_consumer.try_read(owned_bytes),
                    Ok(ControlRingReadStatus::Message(request.to_vec()))
                );
                assert!(matches!(
                    broker.request_consumer.try_read(owned_bytes),
                    Ok(ControlRingReadStatus::Empty { .. })
                ));
                broker.request_consumer.publish_head().unwrap();
                let response = [round, u8::try_from(index).unwrap(), 0xff];
                assert_eq!(
                    broker.response_producer.try_write(&response),
                    Ok(ControlRingWriteStatus::Written)
                );
                assert_eq!(
                    local.response_consumer.try_read(owned_bytes),
                    Ok(ControlRingReadStatus::Message(response.to_vec()))
                );
                local.response_consumer.publish_head().unwrap();
            }
        }
    }

    #[test]
    fn broker_hands_out_lanes_in_order_as_demand_rises() {
        let ring = Arc::new(test_ring_with(ControlRingLayout::MULTI_LANE));
        let local = LocalLaneDemand {
            ring: Arc::clone(&ring),
        };
        let mut broker = BrokerLaneDemand {
            ring: Arc::clone(&ring),
            started_lane_count: 0,
        };
        assert_eq!(broker.try_next_lane(), Ok(ControlRingDemandStatus::Lane(0)));
        let Ok(ControlRingDemandStatus::Satisfied { wait_epoch }) = broker.try_next_lane() else {
            panic!("only lane 0 is demanded initially");
        };
        local.request(3).unwrap();
        let epoch_offset = ring.layout.demand_offset() + DEMAND_EPOCH_OFFSET;
        assert_ne!(
            ring.memory.load_u32_acquire(epoch_offset).unwrap(),
            wait_epoch
        );
        assert_eq!(broker.try_next_lane(), Ok(ControlRingDemandStatus::Lane(1)));
        assert_eq!(broker.try_next_lane(), Ok(ControlRingDemandStatus::Lane(2)));
        assert!(matches!(
            broker.try_next_lane(),
            Ok(ControlRingDemandStatus::Satisfied { .. })
        ));

        // A hostile peer can lower or overstate demand; the broker never
        // takes back a lane and never exceeds the layout.
        local.request(1).unwrap();
        assert!(matches!(
            broker.try_next_lane(),
            Ok(ControlRingDemandStatus::Satisfied { .. })
        ));
        ring.memory
            .store_u32_release(
                ring.layout.demand_offset() + DEMANDED_LANE_COUNT_OFFSET,
                u32::MAX.to_le(),
            )
            .unwrap();
        for lane in 3..ControlRingLayout::MULTI_LANE.lane_count() {
            assert_eq!(
                broker.try_next_lane(),
                Ok(ControlRingDemandStatus::Lane(lane))
            );
        }
        assert!(matches!(
            broker.try_next_lane(),
            Ok(ControlRingDemandStatus::Satisfied { .. })
        ));
    }

    #[test]
    fn request_response_and_notification_rings_publish_independently() {
        let ring = Arc::new(test_ring());
        let mut request_producer = ControlRingProducer::new(Arc::clone(&ring), REQUESTS);
        let mut request_consumer = ControlRingConsumer::new(Arc::clone(&ring), REQUESTS);
        let mut response_producer = ControlRingProducer::new(Arc::clone(&ring), RESPONSES);
        let mut response_consumer = ControlRingConsumer::new(Arc::clone(&ring), RESPONSES);
        let mut notification_producer = ControlRingProducer::new(Arc::clone(&ring), NOTIFICATIONS);
        let mut notification_consumer = ControlRingConsumer::new(ring, NOTIFICATIONS);

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
        for direction in [REQUESTS, RESPONSES, NOTIFICATIONS] {
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
                (REQUESTS.producer_epoch_offset(), size_of::<u32>()),
            ]
        );
    }

    #[test]
    fn failed_payload_metadata_or_word_publication_does_not_publish_progress() {
        for failed_write in [1, 2, 3] {
            let ring = ControlRing::new(FailingWriteMemory::new(), LAYOUT).unwrap();
            let (mut producer, mut consumer) = ring.into_endpoints(REQUESTS, REQUESTS);
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
        for _ in 1..SLOT_COUNT {
            producer.try_write(&[8]).unwrap();
        }
        assert_eq!(
            consumer.try_read(|payload| Ok::<_, ()>(payload.len())),
            Ok(ControlRingReadStatus::Message(100))
        );
        for _ in 1..SLOT_COUNT {
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

        for value in 0..SLOT_COUNT {
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

        for value in 0..SLOT_COUNT {
            let value = u8::try_from(value).unwrap();
            assert_eq!(
                consumer.try_read(owned_bytes),
                Ok(ControlRingReadStatus::Message(vec![value]))
            );
        }
        assert_eq!(
            consumer.try_read(owned_bytes),
            Ok(ControlRingReadStatus::Empty {
                wait_epoch: u32::try_from(SLOT_COUNT).unwrap()
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
            .store_u32_for_test(REQUESTS.producer_epoch_offset(), u32::MAX);
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
            .store_u32_for_test(REQUESTS.consumer_epoch_offset(), u32::MAX);
        consumer.publish_head().unwrap();
        assert_eq!(
            producer
                .memory()
                .load_u32_acquire(REQUESTS.consumer_epoch_offset()),
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
                .load_u32_acquire(REQUESTS.consumer_epoch_offset()),
            Ok(0)
        );

        producer.try_write(&[7]).unwrap();
        consumer.try_read(owned_bytes).unwrap();
        consumer.publish_head().unwrap();
        consumer.publish_head().unwrap();
        assert_eq!(
            consumer
                .memory()
                .load_u32_acquire(REQUESTS.consumer_epoch_offset()),
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
            let (_, mut consumer) = ring.into_endpoints(RESPONSES, REQUESTS);
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
        consumer.head = SLOT_COUNT;
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
        let ring = ControlRing::new(memory, LAYOUT).unwrap();
        let (_, mut consumer) = ring.into_endpoints(RESPONSES, REQUESTS);

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
        let ring = ControlRing::new(memory, LAYOUT).unwrap();
        let (_, mut consumer) = ring.into_endpoints(RESPONSES, REQUESTS);

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
        test_ring_with(LAYOUT)
    }

    fn test_ring_with(layout: ControlRingLayout) -> ControlRing<TestMemory> {
        ControlRing::new(TestMemory::new(layout.memory_size()), layout).unwrap()
    }

    fn test_endpoints() -> (
        ControlRingProducer<TestMemory>,
        ControlRingConsumer<TestMemory>,
    ) {
        test_ring().into_endpoints(REQUESTS, REQUESTS)
    }

    fn owned_bytes(payload: &[u8]) -> Result<Vec<u8>, ()> {
        if payload.is_empty() {
            Err(())
        } else {
            Ok(payload.to_vec())
        }
    }

    #[test]
    fn wakes_skip_peers_that_announce_no_wait() {
        let (mut producer, mut consumer) = ControlRing::new(TestMemory::new(MEMORY_SIZE), LAYOUT)
            .unwrap()
            .into_endpoints(REQUESTS, REQUESTS);
        let direction = REQUESTS;
        assert_eq!(
            producer.try_write(b"x"),
            Ok(ControlRingWriteStatus::Written)
        );
        producer.wake_consumer().unwrap();
        assert_eq!(producer.memory().wakes(), []);

        producer
            .memory()
            .store_u32_for_test(direction.consumer_waiting_offset(), 1);
        producer.wake_consumer().unwrap();
        assert_eq!(
            producer.memory().wakes(),
            [direction.producer_epoch_offset()]
        );

        assert!(matches!(
            consumer.try_read(|frame| Ok::<_, ()>(frame.to_vec())),
            Ok(ControlRingReadStatus::Message(_))
        ));
        consumer.publish_head().unwrap();
        consumer.wake_producer().unwrap();
        assert_eq!(consumer.memory().wakes().len(), 1);
        consumer
            .memory()
            .store_u32_for_test(direction.producer_waiting_offset(), 1);
        consumer.wake_producer().unwrap();
        assert_eq!(
            consumer.memory().wakes()[1..],
            [direction.consumer_epoch_offset()]
        );
    }

    #[test]
    fn waits_announce_themselves_only_while_blocking() {
        let (mut producer, mut consumer) = ControlRing::new(TestMemory::new(MEMORY_SIZE), LAYOUT)
            .unwrap()
            .into_endpoints(RESPONSES, REQUESTS);
        let requests = REQUESTS;
        let responses = RESPONSES;
        let Ok(ControlRingReadStatus::Empty { wait_epoch }) =
            consumer.try_read(|frame| Ok::<_, ()>(frame.to_vec()))
        else {
            panic!("an empty ring");
        };
        consumer.wait_for_message(wait_epoch).unwrap();
        producer.wait_for_capacity(7).unwrap();
        let memory = consumer.memory();
        let waits = memory.waits();
        assert_eq!(
            waits
                .iter()
                .map(|(offset, expected, _)| (*offset, *expected))
                .collect::<Vec<_>>(),
            [
                (requests.producer_epoch_offset(), wait_epoch),
                (responses.consumer_epoch_offset(), 7),
            ]
        );
        assert_eq!(word_at(&waits[0].2, requests.consumer_waiting_offset()), 1);
        assert_eq!(word_at(&waits[1].2, responses.producer_waiting_offset()), 1);
        for offset in [
            requests.consumer_waiting_offset(),
            responses.producer_waiting_offset(),
        ] {
            assert_eq!(memory.load_u32_acquire(offset), Ok(0));
        }
    }

    fn word_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_ne_bytes(bytes[offset..offset + size_of::<u32>()].try_into().unwrap())
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
            .store_u64_release(REQUESTS.consumer_head_offset(), head.to_le())
            .unwrap();
    }

    struct TestMemory {
        bytes: Mutex<Vec<u8>>,
        write_log: Mutex<Vec<(usize, usize)>>,
        write_count: AtomicUsize,
        /// Each wait's offset, expected value, and memory snapshot.
        waits: Mutex<Vec<(usize, u32, Vec<u8>)>>,
        wakes: Mutex<Vec<usize>>,
    }

    impl TestMemory {
        fn new(length: usize) -> Self {
            Self {
                bytes: Mutex::new(vec![0; length]),
                write_log: Mutex::new(Vec::new()),
                write_count: AtomicUsize::new(0),
                waits: Mutex::new(Vec::new()),
                wakes: Mutex::new(Vec::new()),
            }
        }

        fn waits(&self) -> Vec<(usize, u32, Vec<u8>)> {
            self.waits.lock().unwrap().clone()
        }

        fn wakes(&self) -> Vec<usize> {
            self.wakes.lock().unwrap().clone()
        }

        fn bytes(&self) -> Vec<u8> {
            self.bytes.lock().unwrap().clone()
        }

        fn write_log(&self) -> Vec<(usize, usize)> {
            self.write_log.lock().unwrap().clone()
        }

        fn store_u32_for_test(&self, offset: usize, value: u32) {
            self.bytes.lock().unwrap()[offset..offset + size_of::<u32>()]
                .copy_from_slice(&value.to_ne_bytes());
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

    /// Records waits, which return at once, and wakes.
    impl WaitableSharedMemory for TestMemory {
        type Error = SharedMemoryError;

        fn wait_access_error(error: SharedMemoryError) -> SharedMemoryError {
            error
        }

        fn wait_while_equal(&self, offset: usize, expected: u32) -> Result<(), SharedMemoryError> {
            let snapshot = self.bytes();
            self.waits
                .lock()
                .unwrap()
                .push((offset, expected, snapshot));
            Ok(())
        }

        fn wake_one(&self, offset: usize) -> Result<(), SharedMemoryError> {
            self.wakes.lock().unwrap().push(offset);
            Ok(())
        }
    }

    impl ControlRingMemory for TestMemory {
        fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
            test_load_u32_acquire(&self.bytes, offset)
        }

        fn increment_u32_release(&self, offset: usize) -> Result<(), SharedMemoryError> {
            test_increment_u32_release(&self.bytes, offset)?;
            self.write_log
                .lock()
                .unwrap()
                .push((offset, size_of::<u32>()));
            self.write_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn store_u32_release(&self, offset: usize, value: u32) -> Result<(), SharedMemoryError> {
            test_store_u32_release(&self.bytes, offset, value)?;
            self.write_log
                .lock()
                .unwrap()
                .push((offset, size_of::<u32>()));
            self.write_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
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

        fn store_u64_and_increment_u32_release(
            &self,
            store_offset: usize,
            value: u64,
            increment_offset: usize,
        ) -> Result<(), SharedMemoryError> {
            test_store_u64_and_increment_u32_release(
                &self.bytes,
                store_offset,
                value,
                increment_offset,
            )?;
            self.write_log.lock().unwrap().extend([
                (store_offset, size_of::<u64>()),
                (increment_offset, size_of::<u32>()),
            ]);
            self.write_count.fetch_add(2, Ordering::Relaxed);
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
                bytes: Mutex::new(vec![0; MEMORY_SIZE]),
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

    impl ControlRingMemory for FailingWriteMemory {
        fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
            test_load_u32_acquire(&self.bytes, offset)
        }

        fn increment_u32_release(&self, offset: usize) -> Result<(), SharedMemoryError> {
            test_increment_u32_release(&self.bytes, offset)
        }

        fn store_u32_release(&self, offset: usize, value: u32) -> Result<(), SharedMemoryError> {
            test_store_u32_release(&self.bytes, offset, value)
        }

        fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
            test_load_u64_acquire(&self.bytes, offset)
        }

        fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
            if !offset.is_multiple_of(align_of::<u64>()) {
                return Err(SharedMemoryError::UnalignedWord);
            }
            let call = self.write_count.fetch_add(1, Ordering::Relaxed) + 1;
            if call == self.fail_on_write.load(Ordering::Relaxed) {
                return Err(SharedMemoryError::InvalidRange);
            }
            test_store_u64_release(&self.bytes, offset, value)
        }

        fn store_u64_and_increment_u32_release(
            &self,
            store_offset: usize,
            value: u64,
            increment_offset: usize,
        ) -> Result<(), SharedMemoryError> {
            let call = self.write_count.fetch_add(1, Ordering::Relaxed) + 1;
            if call == self.fail_on_write.load(Ordering::Relaxed) {
                return Err(SharedMemoryError::InvalidRange);
            }
            test_store_u64_and_increment_u32_release(
                &self.bytes,
                store_offset,
                value,
                increment_offset,
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
            let mut bytes = vec![0; MEMORY_SIZE];
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

    impl ControlRingMemory for TearingMemory {
        fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
            test_load_u32_acquire(&self.bytes, offset)
        }

        fn increment_u32_release(&self, offset: usize) -> Result<(), SharedMemoryError> {
            test_increment_u32_release(&self.bytes, offset)
        }

        fn store_u32_release(&self, offset: usize, value: u32) -> Result<(), SharedMemoryError> {
            test_store_u32_release(&self.bytes, offset, value)
        }

        fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
            test_load_u64_acquire(&self.bytes, offset)
        }

        fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
            test_store_u64_release(&self.bytes, offset, value)
        }

        fn store_u64_and_increment_u32_release(
            &self,
            store_offset: usize,
            value: u64,
            increment_offset: usize,
        ) -> Result<(), SharedMemoryError> {
            test_store_u64_and_increment_u32_release(
                &self.bytes,
                store_offset,
                value,
                increment_offset,
            )
        }
    }

    fn test_load_u32_acquire(
        bytes: &Mutex<Vec<u8>>,
        offset: usize,
    ) -> Result<u32, SharedMemoryError> {
        if !offset.is_multiple_of(align_of::<u32>()) {
            return Err(SharedMemoryError::UnalignedWord);
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

    fn test_increment_u32_release(
        bytes: &Mutex<Vec<u8>>,
        offset: usize,
    ) -> Result<(), SharedMemoryError> {
        if !offset.is_multiple_of(align_of::<u32>()) {
            return Err(SharedMemoryError::UnalignedWord);
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
        destination.copy_from_slice(&previous.wrapping_add(1).to_ne_bytes());
        Ok(())
    }

    fn test_store_u32_release(
        bytes: &Mutex<Vec<u8>>,
        offset: usize,
        value: u32,
    ) -> Result<(), SharedMemoryError> {
        if !offset.is_multiple_of(align_of::<u32>()) {
            return Err(SharedMemoryError::UnalignedWord);
        }
        fence(Ordering::Release);
        let mut bytes = bytes.lock().unwrap();
        let end = offset
            .checked_add(size_of::<u32>())
            .ok_or(SharedMemoryError::InvalidRange)?;
        bytes
            .get_mut(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?
            .copy_from_slice(&value.to_ne_bytes());
        Ok(())
    }

    fn test_load_u64_acquire(
        bytes: &Mutex<Vec<u8>>,
        offset: usize,
    ) -> Result<u64, SharedMemoryError> {
        if !offset.is_multiple_of(align_of::<u64>()) {
            return Err(SharedMemoryError::UnalignedWord);
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
            return Err(SharedMemoryError::UnalignedWord);
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

    fn test_store_u64_and_increment_u32_release(
        bytes: &Mutex<Vec<u8>>,
        store_offset: usize,
        value: u64,
        increment_offset: usize,
    ) -> Result<(), SharedMemoryError> {
        if !store_offset.is_multiple_of(align_of::<u64>())
            || !increment_offset.is_multiple_of(align_of::<u32>())
        {
            return Err(SharedMemoryError::UnalignedWord);
        }
        let store_end = store_offset
            .checked_add(size_of::<u64>())
            .ok_or(SharedMemoryError::InvalidRange)?;
        let increment_end = increment_offset
            .checked_add(size_of::<u32>())
            .ok_or(SharedMemoryError::InvalidRange)?;
        if store_offset < increment_end && increment_offset < store_end {
            return Err(SharedMemoryError::InvalidRange);
        }
        let mut bytes = bytes.lock().unwrap();
        if store_end > bytes.len() || increment_end > bytes.len() {
            return Err(SharedMemoryError::InvalidRange);
        }
        let previous = u32::from_ne_bytes(
            bytes[increment_offset..increment_end]
                .try_into()
                .expect("checked u32 range"),
        );
        fence(Ordering::Release);
        bytes[store_offset..store_end].copy_from_slice(&value.to_ne_bytes());
        bytes[increment_offset..increment_end]
            .copy_from_slice(&previous.wrapping_add(1).to_ne_bytes());
        Ok(())
    }
}
