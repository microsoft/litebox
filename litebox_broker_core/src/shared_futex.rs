// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Futex wait queues for memory that several processes share.
//!
//! The broker never sees the memory. Processes name it by a
//! [`SharedMemoryId`] from a block that [`reserve_memory_ids`] reserves, and each waiter checks
//! its futex word itself after arming, as the [protocol](litebox_broker_protocol::shared_futex)
//! describes. Waiters are queued by [`SharedFutexKey`] in buckets chosen by hashing the key.
//!
//! The broker does not check that a process maps the memory whose futexes it names. Instead, each
//! process may only name the IDs of [`SharedMemoryBlocks`] it reserved, or that its creator could
//! name when creating it, so a process cannot reach the futexes of memory created after it was.
//!
//! A waiter is armed on at most one futex at a time, so the buckets hold at most one entry per
//! waiter. A wake marks waiters woken and publishes it with the generation of their arm, and
//! disarming reports it, so a wake racing a timeout or interruption is not lost. A woken waiter
//! may also be armed again without disarming, as its readiness already told it of the wake.

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_futex::{
    FUTEX_WAITER_GENERATIONS, FUTEX_WORD_SIZE, FutexArmRequest, FutexDisarmRequest,
    FutexWakeRequest, SharedFutexKey, SharedMemoryId, futex_waiter_woken_readiness,
};
use spin::Mutex;

use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::{BrokerError, BrokerProcess, Result};

/// Most blocks of shared memory IDs that one process may name, counting the ones it inherits.
const MAX_SHARED_MEMORY_BLOCKS: usize = 1 << 16;

/// Base-two logarithm of the number of wait queue buckets.
const BUCKET_BITS: u32 = 8;
const BUCKETS: usize = 1 << BUCKET_BITS;

/// The waiters armed on the futex words whose keys hash to one bucket, oldest first.
type Bucket = Mutex<VecDeque<QueuedWaiter>>;

/// Broker-wide state of futexes in shared memory.
pub(crate) struct SharedFutexes {
    /// Lock order: a bucket, then a waiter's state.
    buckets: [Bucket; BUCKETS],
    /// The upper 64 bits of the next block of shared memory IDs to reserve.
    next_block: AtomicU64,
}

impl Default for SharedFutexes {
    fn default() -> Self {
        Self {
            buckets: core::array::from_fn(|_| Mutex::new(VecDeque::new())),
            next_block: AtomicU64::new(0),
        }
    }
}

impl SharedFutexes {
    fn bucket(&self, key: SharedFutexKey) -> &Bucket {
        // Fibonacci hashing of the memory ID, folding its block into its position in the block,
        // and the word's index in the memory.
        const MULTIPLIER: u128 = 0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835;
        let mixed = key.memory.0 ^ (key.memory.0 >> 64) ^ u128::from(key.offset / FUTEX_WORD_SIZE);
        let hash = mixed.wrapping_mul(MULTIPLIER) >> (u128::BITS - BUCKET_BITS);
        &self.buckets[usize::try_from(hash).unwrap_or_default() % BUCKETS]
    }
}

/// Reserves a block of shared memory IDs that the caller, and the processes it creates from now
/// on, may name, and returns its first ID.
///
/// The block is the 2^64 IDs that share the first ID's upper 64 bits, which no other reservation
/// returns.
///
/// Fails with `PolicyDenied` if the caller may not wait on objects, and with `ResourceExhausted`
/// once the caller may name [`MAX_SHARED_MEMORY_BLOCKS`] blocks or every block is reserved.
pub fn reserve_memory_ids(process: &BrokerProcess) -> Result<SharedMemoryId> {
    process.require_object_rights(ObjectRights::WAIT)?;
    // Reserving under the lock keeps the caller's blocks in ascending order.
    let mut blocks = process.shared_memory_blocks.0.lock();
    if blocks.len() >= MAX_SHARED_MEMORY_BLOCKS {
        return Err(BrokerError::ResourceExhausted);
    }
    blocks
        .try_reserve(1)
        .map_err(|_| BrokerError::OutOfMemory)?;
    let block = process
        .core
        .shared_futexes
        .next_block
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |block| {
            block.checked_add(1)
        })
        .map_err(|_| BrokerError::ResourceExhausted)?;
    blocks.push(block);
    Ok(SharedMemoryId(u128::from(block) << 64))
}

/// The blocks of shared memory IDs that a process may name, in ascending order.
#[derive(Default)]
pub(crate) struct SharedMemoryBlocks(Mutex<Vec<u64>>);

impl SharedMemoryBlocks {
    /// Returns the blocks of a process that `creator` creates: those `creator` may name now,
    /// which include the memory the new process may share with it.
    pub(crate) fn inherit(creator: &Self) -> Result<Self> {
        let blocks = creator.0.lock();
        let mut inherited = Vec::new();
        inherited
            .try_reserve_exact(blocks.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        inherited.extend_from_slice(&blocks);
        Ok(Self(Mutex::new(inherited)))
    }

    /// Fails with `PolicyDenied` unless the process may name `memory`.
    fn authorize(&self, memory: SharedMemoryId) -> Result<()> {
        if self.0.lock().binary_search(&memory.block()).is_ok() {
            Ok(())
        } else {
            Err(BrokerError::PolicyDenied)
        }
    }
}

/// Creates an idle futex waiter whose reference publishes its readiness through
/// `readiness_sink`.
///
/// Fails with `PolicyDenied` if the caller may not wait on objects.
pub fn create_futex_waiter(
    process: &BrokerProcess,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let rights = process.require_object_rights(ObjectRights::WAIT)?;
    let reference = process.reserve_object_reference(rights)?;
    let registration = ReadinessRegistration::new(reference.handle(), Arc::clone(readiness_sink));
    reference.commit(ObjectEntry::FutexWaiter(FutexWaiterObject(Arc::new(
        FutexWaiter {
            futexes: Arc::clone(&process.core.shared_futexes),
            state: Mutex::new(WaiterState::Idle),
            registration,
        },
    ))))
}

/// Arms a futex waiter that is idle, or was woken since it was last armed, on the futex word
/// `request.key`.
///
/// Fails with `UnsupportedOperation` if the offset is unaligned, the mask is zero, the generation
/// is out of range, or the waiter is armed, and with `PolicyDenied` if the caller may not name
/// the key's memory.
pub fn futex_arm(process: &BrokerProcess, request: FutexArmRequest) -> Result<()> {
    validate_key_and_bitset(request.key, request.bitset)?;
    process.shared_memory_blocks.authorize(request.key.memory)?;
    if request.generation >= FUTEX_WAITER_GENERATIONS {
        return Err(BrokerError::UnsupportedOperation);
    }
    // Holding the waiter's object defers a concurrent close, whose disarm then dequeues the
    // arming, until after this request's locks are released.
    let waiter_object = process.authorized_object(request.waiter, ObjectRights::WAIT)?;
    let waiter = Arc::clone(&waiter_object.read().as_futex_waiter()?.0);
    let mut bucket = waiter.futexes.bucket(request.key).lock();
    let mut state = waiter.state.lock();
    if matches!(*state, WaiterState::Armed { .. }) {
        return Err(BrokerError::UnsupportedOperation);
    }
    bucket
        .try_reserve(1)
        .map_err(|_| BrokerError::OutOfMemory)?;
    bucket.push_back(QueuedWaiter {
        key: request.key,
        waiter: Arc::downgrade(&waiter),
        bitset: request.bitset,
    });
    *state = WaiterState::Armed {
        key: request.key,
        generation: request.generation,
    };
    drop(state);
    drop(bucket);
    drop(waiter_object);
    Ok(())
}

/// Wakes up to `request.count` of the oldest waiters armed on the futex word `request.key`
/// whose masks intersect `request.bitset`, returning how many it woke.
///
/// Fails with `UnsupportedOperation` if the offset is unaligned or the mask is zero, and with
/// `PolicyDenied` if the caller may not wait on objects or name the key's memory.
pub fn futex_wake(process: &BrokerProcess, request: FutexWakeRequest) -> Result<u32> {
    validate_key_and_bitset(request.key, request.bitset)?;
    process.require_object_rights(ObjectRights::WAIT)?;
    process.shared_memory_blocks.authorize(request.key.memory)?;
    let mut woken = Vec::new();
    let mut count = 0;
    {
        let mut bucket = process.core.shared_futexes.bucket(request.key).lock();
        // Reserve first: a waiter marked woken must have its wake published.
        woken
            .try_reserve(bucket.len().min(request.count as usize))
            .map_err(|_| BrokerError::OutOfMemory)?;
        let mut index = 0;
        while count < request.count {
            let Some(queued) = bucket.get(index) else {
                break;
            };
            if queued.key != request.key || queued.bitset & request.bitset == 0 {
                index += 1;
                continue;
            }
            // Selected entries leave the queue even if their waiter is gone or disarmed. Most
            // wakes select the oldest entries, which the deque removes in constant time.
            let Some(queued) = bucket.remove(index) else {
                break;
            };
            if let Some(waiter) = queued.waiter.upgrade() {
                let mut state = waiter.state.lock();
                if let WaiterState::Armed { generation, .. } = *state {
                    *state = WaiterState::Woken { generation };
                    drop(state);
                    woken.push((waiter, generation));
                    count += 1;
                }
            }
        }
    }
    for (waiter, generation) in &woken {
        waiter
            .registration
            .republish(futex_waiter_woken_readiness(*generation));
    }
    Ok(count)
}

/// Disarms a futex waiter, returning whether a wake selected it since it was armed.
///
/// Disarming an idle waiter returns `false`.
pub fn futex_disarm(process: &BrokerProcess, request: FutexDisarmRequest) -> Result<bool> {
    let waiter = process.authorized_object(request.waiter, ObjectRights::WAIT)?;
    let waiter = Arc::clone(&waiter.read().as_futex_waiter()?.0);
    Ok(waiter.disarm_and_take_woken())
}

/// Fails with `UnsupportedOperation` if `key` names an unaligned futex word or `bitset` is
/// empty, which well-behaved clients never ask for.
fn validate_key_and_bitset(key: SharedFutexKey, bitset: u32) -> Result<()> {
    if !key.offset.is_multiple_of(FUTEX_WORD_SIZE) || bitset == 0 {
        return Err(BrokerError::UnsupportedOperation);
    }
    Ok(())
}

impl ObjectEntry {
    fn as_futex_waiter(&self) -> Result<&FutexWaiterObject> {
        match self {
            Self::FutexWaiter(waiter) => Ok(waiter),
            _ => Err(BrokerError::InvalidRights),
        }
    }
}

struct QueuedWaiter {
    /// The futex word the waiter is armed on.
    key: SharedFutexKey,
    /// The waiter, which its reference owns.
    waiter: Weak<FutexWaiter>,
    bitset: u32,
}

/// A thread's futex waiter, which disarms when its reference drops.
pub(crate) struct FutexWaiterObject(Arc<FutexWaiter>);

impl FutexWaiterObject {
    /// Returns the waiter's readiness: [`futex_waiter_woken_readiness`] from a wake until it is disarmed or
    /// armed again.
    pub(crate) fn readiness(&self) -> ReadinessFlags {
        if let WaiterState::Woken { generation } = *self.0.state.lock() {
            futex_waiter_woken_readiness(generation)
        } else {
            ReadinessFlags::default()
        }
    }
}

impl Drop for FutexWaiterObject {
    fn drop(&mut self) {
        self.0.disarm_and_take_woken();
    }
}

struct FutexWaiter {
    futexes: Arc<SharedFutexes>,
    state: Mutex<WaiterState>,
    /// Publication of wakes to the owning process.
    registration: ReadinessRegistration,
}

enum WaiterState {
    Idle,
    /// Queued on the futex word `key` by the arm with `generation`.
    Armed {
        key: SharedFutexKey,
        generation: u32,
    },
    /// Selected by a wake while armed with `generation`.
    Woken {
        generation: u32,
    },
}

impl FutexWaiter {
    /// Disarms the waiter, returning whether it was woken and resetting a woken waiter to idle.
    fn disarm_and_take_woken(&self) -> bool {
        loop {
            // Only an armed waiter needs its bucket, which must be locked before its state.
            let key = {
                let mut state = self.state.lock();
                match *state {
                    WaiterState::Armed { key, .. } => key,
                    WaiterState::Woken { .. } => {
                        *state = WaiterState::Idle;
                        return true;
                    }
                    WaiterState::Idle => return false,
                }
            };
            let mut bucket = self.futexes.bucket(key).lock();
            let mut state = self.state.lock();
            if matches!(*state, WaiterState::Armed { key: armed, .. } if armed == key) {
                if let Some(index) = bucket
                    .iter()
                    .position(|queued| core::ptr::eq(queued.waiter.as_ptr(), self))
                {
                    bucket.remove(index);
                }
                *state = WaiterState::Idle;
                return false;
            }
            // A wake or another disarm changed the state while it was unlocked.
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::shared_futex::{
        FUTEX_WAITER_GENERATIONS, FutexArmRequest, FutexDisarmRequest, FutexWakeRequest,
        SharedFutexKey, SharedMemoryId, futex_waiter_woken_readiness,
        woken_futex_waiter_generation,
    };

    use crate::readiness::ReadinessSink;
    use crate::readiness::tests::TestReadinessSink;
    use crate::test_support::TestBrokerCoreBuilder;
    use crate::{BrokerCore, BrokerError, BrokerProcess, CallerCredential, ObjectRights};
    use crate::{PolicyEngine, Result};

    /// The first block the broker reserves, which the fixture's parent reserves before creating
    /// its child.
    const MEMORY: SharedMemoryId = SharedMemoryId(0);

    fn key(offset: u64) -> SharedFutexKey {
        SharedFutexKey {
            memory: MEMORY,
            offset,
        }
    }

    struct Fixture {
        core: BrokerCore,
        parent: Arc<BrokerProcess>,
        child: Arc<BrokerProcess>,
        sink: Arc<TestReadinessSink>,
    }

    fn core(rights: ObjectRights) -> BrokerCore {
        TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(rights))
            .build()
            .unwrap()
    }

    fn fixture() -> Fixture {
        let core = core(ObjectRights::WAIT | ObjectRights::WRITE);
        let parent = core
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        assert_eq!(super::reserve_memory_ids(&parent), Ok(MEMORY));
        let child = core
            .create_process(CallerCredential::Unauthenticated, Some(parent.id()))
            .unwrap();
        Fixture {
            core,
            parent,
            child,
            sink: Arc::new(TestReadinessSink::default()),
        }
    }

    impl Fixture {
        fn waiter(&self, process: &BrokerProcess) -> ObjectHandle {
            super::create_futex_waiter(process, &(self.sink.clone() as Arc<dyn ReadinessSink>))
                .unwrap()
        }

        fn arm(
            process: &BrokerProcess,
            key: SharedFutexKey,
            bitset: u32,
            waiter: ObjectHandle,
        ) -> Result<()> {
            Self::arm_generation(process, key, bitset, waiter, 0)
        }

        fn arm_generation(
            process: &BrokerProcess,
            key: SharedFutexKey,
            bitset: u32,
            waiter: ObjectHandle,
            generation: u32,
        ) -> Result<()> {
            super::futex_arm(
                process,
                FutexArmRequest {
                    key,
                    bitset,
                    waiter,
                    generation,
                },
            )
        }

        fn disarm(process: &BrokerProcess, waiter: ObjectHandle) -> Result<bool> {
            super::futex_disarm(process, FutexDisarmRequest { waiter })
        }

        /// Returns how many futex words have waiters queued, and how many waiters are queued.
        fn queued(&self) -> (usize, usize) {
            let mut keys = std::collections::BTreeSet::new();
            let mut waiters = 0;
            for bucket in &self.core.shared_futexes.buckets {
                for queued in bucket.lock().iter() {
                    keys.insert(queued.key);
                    waiters += 1;
                }
            }
            (keys.len(), waiters)
        }

        fn wake(
            process: &BrokerProcess,
            key: SharedFutexKey,
            count: u32,
            bitset: u32,
        ) -> Result<u32> {
            super::futex_wake(process, FutexWakeRequest { key, count, bitset })
        }

        fn woken_handles(&self) -> std::vec::Vec<ObjectHandle> {
            self.sink
                .republished
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, readiness)| woken_futex_waiter_generation(*readiness).is_some())
                .map(|(handle, _)| *handle)
                .collect()
        }
    }

    #[test]
    fn wake_reaches_waiter_in_another_process() {
        let fixture = fixture();
        let waiter = fixture.waiter(&fixture.child);
        Fixture::arm(&fixture.child, key(8), u32::MAX, waiter).unwrap();
        assert_eq!(
            fixture.child.check_readiness(waiter),
            Ok(ReadinessFlags::default())
        );

        assert_eq!(Fixture::wake(&fixture.parent, key(8), 1, u32::MAX), Ok(1));
        assert_eq!(fixture.woken_handles(), [waiter]);
        assert_eq!(
            fixture.child.check_readiness(waiter),
            Ok(futex_waiter_woken_readiness(0))
        );
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(true));
        assert_eq!(
            fixture.child.check_readiness(waiter),
            Ok(ReadinessFlags::default())
        );
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(false));
        assert_eq!(fixture.queued(), (0, 0));
    }

    #[test]
    fn wake_selects_oldest_matching_waiters_up_to_count() {
        let fixture = fixture();
        let waiters: std::vec::Vec<_> = (0..4).map(|_| fixture.waiter(&fixture.child)).collect();
        for (index, &waiter) in waiters.iter().enumerate() {
            let bitset = if index == 1 { 0b10 } else { 0b01 };
            Fixture::arm(&fixture.child, key(0), bitset, waiter).unwrap();
        }
        // Another futex word, in the same memory or in other memory, is not woken.
        let other_offset = fixture.waiter(&fixture.parent);
        Fixture::arm(&fixture.parent, key(4), u32::MAX, other_offset).unwrap();
        let other_memory = fixture.waiter(&fixture.parent);
        let other_memory_key = SharedFutexKey {
            memory: MEMORY.nth_in_block(1),
            offset: 0,
        };
        Fixture::arm(&fixture.parent, other_memory_key, u32::MAX, other_memory).unwrap();

        assert_eq!(Fixture::wake(&fixture.parent, key(0), 2, 0b01), Ok(2));
        assert_eq!(fixture.woken_handles(), [waiters[0], waiters[2]]);
        assert_eq!(
            Fixture::wake(&fixture.parent, key(0), u32::MAX, u32::MAX),
            Ok(2)
        );
        assert_eq!(
            fixture.woken_handles(),
            [waiters[0], waiters[2], waiters[1], waiters[3]]
        );
        assert_eq!(fixture.queued(), (2, 2));
        assert_eq!(Fixture::disarm(&fixture.parent, other_offset), Ok(false));
        assert_eq!(Fixture::wake(&fixture.parent, key(4), 1, u32::MAX), Ok(0));
        assert_eq!(
            Fixture::wake(&fixture.parent, other_memory_key, 1, u32::MAX),
            Ok(1)
        );
    }

    #[test]
    fn disarmed_waiter_is_not_woken_and_can_rearm() {
        let fixture = fixture();
        let waiter = fixture.waiter(&fixture.child);
        Fixture::arm(&fixture.child, key(0), u32::MAX, waiter).unwrap();
        assert_eq!(
            Fixture::arm(&fixture.child, key(0), u32::MAX, waiter),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(false));
        assert_eq!(fixture.queued(), (0, 0));
        assert_eq!(Fixture::wake(&fixture.parent, key(0), 1, u32::MAX), Ok(0));

        Fixture::arm(&fixture.child, key(0), u32::MAX, waiter).unwrap();
        assert_eq!(Fixture::wake(&fixture.parent, key(0), 1, u32::MAX), Ok(1));
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(true));
    }

    #[test]
    fn closed_waiter_leaves_its_queue() {
        let fixture = fixture();
        let closed = fixture.waiter(&fixture.child);
        let remaining = fixture.waiter(&fixture.child);
        Fixture::arm(&fixture.child, key(0), u32::MAX, closed).unwrap();
        Fixture::arm(&fixture.child, key(0), u32::MAX, remaining).unwrap();
        fixture.child.close_object_reference(closed).unwrap();
        assert_eq!(fixture.queued(), (1, 1));

        assert_eq!(Fixture::wake(&fixture.parent, key(0), 1, u32::MAX), Ok(1));
        assert_eq!(fixture.woken_handles(), [remaining]);
        assert_eq!(fixture.queued(), (0, 0));
    }

    #[test]
    fn concurrent_arm_and_disarm_never_orphan_queue_entries() {
        let fixture = Arc::new(fixture());
        let waiter = fixture.waiter(&fixture.child);
        let armer = {
            let fixture = Arc::clone(&fixture);
            std::thread::spawn(move || {
                for _ in 0..2000 {
                    let _ = Fixture::arm(&fixture.child, key(0), 1, waiter);
                }
            })
        };
        for _ in 0..2000 {
            Fixture::disarm(&fixture.child, waiter).unwrap();
        }
        armer.join().unwrap();
        // At most the last arming remains queued, and disarming removes it.
        assert!(fixture.queued().1 <= 1);
        Fixture::disarm(&fixture.child, waiter).unwrap();
        assert_eq!(fixture.queued(), (0, 0));
    }

    #[test]
    fn closing_a_waiter_while_it_arms_never_orphans_queue_entries() {
        let fixture = Arc::new(fixture());
        for _ in 0..500 {
            let waiter = fixture.waiter(&fixture.child);
            let armer = {
                let fixture = Arc::clone(&fixture);
                std::thread::spawn(move || {
                    let _ = Fixture::arm(&fixture.child, key(0), 1, waiter);
                })
            };
            fixture.child.close_object_reference(waiter).unwrap();
            armer.join().unwrap();
            assert_eq!(fixture.queued(), (0, 0));
        }
    }

    #[test]
    fn rejects_invalid_requests() {
        let fixture = fixture();
        let waiter = fixture.waiter(&fixture.child);
        for (offset, bitset) in [(2, u32::MAX), (u64::MAX, 1), (0, 0)] {
            assert_eq!(
                Fixture::arm(&fixture.child, key(offset), bitset, waiter),
                Err(BrokerError::UnsupportedOperation)
            );
            assert_eq!(
                Fixture::wake(&fixture.child, key(offset), 1, bitset),
                Err(BrokerError::UnsupportedOperation)
            );
        }
        assert_eq!(fixture.queued(), (0, 0));
        // Handles are per process, so another process cannot name the waiter.
        assert_eq!(
            Fixture::arm(&fixture.parent, key(0), 1, waiter),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            Fixture::disarm(&fixture.parent, waiter),
            Err(BrokerError::UnknownObject)
        );
        // Waiters belong to their thread's process.
        assert_eq!(
            fixture.child.duplicate_object_reference_to(
                waiter,
                &fixture.parent,
                ObjectRights::WAIT
            ),
            Err(BrokerError::UnsupportedOperation)
        );
    }

    #[test]
    fn exited_process_waiters_leave_their_queues() {
        let fixture = fixture();
        let exiting = fixture.waiter(&fixture.child);
        let remaining = fixture.waiter(&fixture.parent);
        Fixture::arm(&fixture.child, key(0), u32::MAX, exiting).unwrap();
        Fixture::arm(&fixture.parent, key(0), u32::MAX, remaining).unwrap();
        fixture.child.cleanup(true);
        assert_eq!(fixture.queued(), (1, 1));

        // A wake is not spent on the waiter of the process that exited.
        assert_eq!(Fixture::wake(&fixture.parent, key(0), 1, u32::MAX), Ok(1));
        assert_eq!(fixture.woken_handles(), [remaining]);
        assert_eq!(fixture.queued(), (0, 0));
    }

    #[test]
    fn processes_name_only_blocks_they_reserved_or_their_creator_had() {
        let fixture = fixture();
        let unrelated = fixture
            .core
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        // The parent reserves another block after creating its child, which the child must not
        // reach, as the memory it names was created after the child was.
        let later = super::reserve_memory_ids(&fixture.parent).unwrap();
        assert_ne!(later.block(), MEMORY.block());
        let later_key = SharedFutexKey {
            memory: later,
            offset: 0,
        };
        let parent_waiter = fixture.waiter(&fixture.parent);
        Fixture::arm(&fixture.parent, later_key, u32::MAX, parent_waiter).unwrap();
        let child_waiter = fixture.waiter(&fixture.child);
        let unrelated_waiter = fixture.waiter(&unrelated);
        for (process, waiter, key) in [
            (&fixture.child, child_waiter, later_key),
            (&unrelated, unrelated_waiter, key(0)),
            (&unrelated, unrelated_waiter, later_key),
        ] {
            assert_eq!(
                Fixture::arm(process, key, u32::MAX, waiter),
                Err(BrokerError::PolicyDenied)
            );
            assert_eq!(
                Fixture::wake(process, key, 1, u32::MAX),
                Err(BrokerError::PolicyDenied)
            );
        }
        assert_eq!(fixture.queued(), (1, 1));
        // The child inherited the block reserved before it was created, and its own reservation
        // reaches neither its parent nor the unrelated process.
        Fixture::arm(&fixture.child, key(0), u32::MAX, child_waiter).unwrap();
        assert_eq!(Fixture::wake(&fixture.parent, key(0), 1, u32::MAX), Ok(1));
        let own = SharedFutexKey {
            memory: super::reserve_memory_ids(&fixture.child).unwrap(),
            offset: 0,
        };
        assert_eq!(Fixture::wake(&fixture.child, own, 1, u32::MAX), Ok(0));
        for process in [&fixture.parent, &unrelated] {
            assert_eq!(
                Fixture::wake(process, own, 1, u32::MAX),
                Err(BrokerError::PolicyDenied)
            );
        }
        assert_eq!(
            Fixture::wake(&fixture.parent, later_key, 1, u32::MAX),
            Ok(1)
        );
    }

    #[test]
    fn callers_that_may_not_wait_cannot_use_futexes() {
        let core = core(ObjectRights::WRITE);
        let process = core
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let sink: Arc<dyn ReadinessSink> = Arc::new(TestReadinessSink::default());
        assert_eq!(
            super::reserve_memory_ids(&process),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            super::create_futex_waiter(&process, &sink),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            Fixture::wake(&process, key(0), 1, u32::MAX),
            Err(BrokerError::PolicyDenied)
        );
    }

    #[test]
    fn woken_waiter_rearms_without_disarming_and_reports_each_generation() {
        let fixture = fixture();
        let waiter = fixture.waiter(&fixture.child);
        for generation in [3, 4] {
            Fixture::arm_generation(&fixture.child, key(0), u32::MAX, waiter, generation).unwrap();
            assert_eq!(Fixture::wake(&fixture.parent, key(0), 1, u32::MAX), Ok(1));
            let published = *fixture.sink.republished.lock().unwrap().last().unwrap();
            assert_eq!(
                published,
                (waiter, futex_waiter_woken_readiness(generation))
            );
            assert_eq!(
                fixture.child.check_readiness(waiter),
                Ok(futex_waiter_woken_readiness(generation))
            );
        }
        // Arming again clears the earlier wake, so a timed-out wait reports no wake.
        Fixture::arm_generation(&fixture.child, key(0), u32::MAX, waiter, 5).unwrap();
        assert_eq!(
            fixture.child.check_readiness(waiter),
            Ok(ReadinessFlags::default())
        );
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(false));
        assert_eq!(fixture.queued(), (0, 0));
        assert_eq!(
            Fixture::arm_generation(
                &fixture.child,
                key(0),
                u32::MAX,
                waiter,
                FUTEX_WAITER_GENERATIONS
            ),
            Err(BrokerError::UnsupportedOperation)
        );
    }
}
