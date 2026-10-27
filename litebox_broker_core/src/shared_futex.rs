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
//! process may only name the IDs of blocks it reserved, or that its creator could name when
//! creating it. Enforcement is by block, so a process cannot reach the futexes of memory whose
//! IDs come from blocks reserved after it was created. Each block is named by the process that
//! reserved it and how many blocks that process reserved before, so what a process may name is,
//! for itself and each of its ancestors, how many blocks that process had reserved by then, which
//! takes no broker memory per block.
//!
//! A waiter is armed on at most one futex at a time, so the buckets hold at most one entry per
//! waiter. A wake marks waiters woken and publishes readiness for them, and disarming reports
//! it, so a wake racing a timeout or interruption is not lost.

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_futex::{
    FUTEX_WAITER_WOKEN, FUTEX_WORD_SIZE, FutexArmRequest, FutexDisarmRequest, FutexWakeRequest,
    SharedFutexKey, SharedMemoryId,
};
use spin::Mutex;

use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::{BrokerError, BrokerProcess, Result};

/// Most ancestors that reserved blocks whose IDs a process may name, which bounds the broker
/// memory each process needs to authorize them.
const MAX_RESERVING_ANCESTORS: usize = 1 << 10;

/// Base-two logarithm of the number of wait queue buckets.
const BUCKET_BITS: u32 = 8;
const BUCKETS: usize = 1 << BUCKET_BITS;

/// The waiters armed on the futex words whose keys hash to one bucket, oldest first.
type Bucket = Mutex<VecDeque<QueuedWaiter>>;

/// Broker-wide state of futexes in shared memory.
pub(crate) struct SharedFutexes {
    /// Lock order: a bucket, then a waiter's state.
    buckets: [Bucket; BUCKETS],
    /// The reserver ID of the next process created.
    next_reserver: AtomicU64,
}

impl Default for SharedFutexes {
    fn default() -> Self {
        Self {
            buckets: core::array::from_fn(|_| Mutex::new(VecDeque::new())),
            next_reserver: AtomicU64::new(0),
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
/// Fails with `PolicyDenied` if the caller may not wait on objects, and with `ResourceExhausted`
/// once the caller reserved `u32::MAX` blocks, or if it may name the blocks of 2^10 ancestors.
pub fn reserve_memory_ids(process: &BrokerProcess) -> Result<SharedMemoryId> {
    process.require_object_rights(ObjectRights::WAIT)?;
    let authority = &process.shared_memory;
    // The processes it creates may name the blocks of one more ancestor than it may.
    if authority.ancestors.len() >= MAX_RESERVING_ANCESTORS {
        return Err(BrokerError::ResourceExhausted);
    }
    let block = authority
        .reserved
        .try_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
            reserved.checked_add(1)
        })
        .map_err(|_| BrokerError::ResourceExhausted)?;
    Ok(SharedMemoryId::first_in_block(authority.reserver, block))
}

/// The blocks of shared memory IDs that a process may name.
pub(crate) struct SharedMemoryAuthority {
    /// The process's reserver ID, which names the blocks it reserves.
    reserver: u64,
    /// How many blocks the process reserved, whose indices are below it.
    reserved: AtomicU32,
    /// For each ancestor of the process, oldest first, the ancestor's reserver ID and how many
    /// blocks it had reserved when it created the next process on the way to this one, omitting
    /// those that had reserved none.
    ancestors: Vec<(u64, u32)>,
}

impl SharedMemoryAuthority {
    /// Returns the authority of a new process that `creator`, if any, creates: it may name its
    /// own blocks and those `creator` may name now, which include the memory the new process
    /// may share with it.
    ///
    /// Fails with `ResourceExhausted` once the broker created 2^64 processes.
    pub(crate) fn new(futexes: &SharedFutexes, creator: Option<&Self>) -> Result<Self> {
        let mut ancestors = Vec::new();
        if let Some(creator) = creator {
            // A reservation the creator completed before this is included, and any later one
            // gets a larger index.
            let reserved = creator.reserved.load(Ordering::Acquire);
            let own = usize::from(reserved != 0);
            ancestors
                .try_reserve_exact(creator.ancestors.len() + own)
                .map_err(|_| BrokerError::OutOfMemory)?;
            ancestors.extend_from_slice(&creator.ancestors);
            if reserved != 0 {
                // Creators are created before their processes, so reserver IDs stay ascending.
                ancestors.push((creator.reserver, reserved));
            }
        }
        let reserver = futexes
            .next_reserver
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |reserver| {
                reserver.checked_add(1)
            })
            .map_err(|_| BrokerError::ResourceExhausted)?;
        Ok(Self {
            reserver,
            reserved: AtomicU32::new(0),
            ancestors,
        })
    }

    /// Fails with `PolicyDenied` unless the process may name `memory`.
    fn authorize(&self, memory: SharedMemoryId) -> Result<()> {
        let reserved = if memory.reserver() == self.reserver {
            self.reserved.load(Ordering::Acquire)
        } else {
            self.ancestors
                .binary_search_by_key(&memory.reserver(), |&(reserver, _)| reserver)
                .ok()
                .and_then(|index| self.ancestors.get(index))
                .map_or(0, |&(_, reserved)| reserved)
        };
        if memory.block() < reserved {
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

/// Arms an idle futex waiter on the futex word `request.key`.
///
/// Fails with `UnsupportedOperation` if the offset is unaligned, the mask is zero, or the waiter
/// is not idle, and with `PolicyDenied` if the caller may not name the key's memory.
pub fn futex_arm(process: &BrokerProcess, request: FutexArmRequest) -> Result<()> {
    validate_key_and_bitset(request.key, request.bitset)?;
    process.shared_memory.authorize(request.key.memory)?;
    // Holding the waiter's object defers a concurrent close, whose disarm then dequeues the
    // arming, until after this request's locks are released.
    let waiter_object = process.authorized_object(request.waiter, ObjectRights::WAIT)?;
    let waiter = Arc::clone(&waiter_object.read().as_futex_waiter()?.0);
    let mut bucket = waiter.futexes.bucket(request.key).lock();
    let mut state = waiter.state.lock();
    if !matches!(*state, WaiterState::Idle) {
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
    *state = WaiterState::Armed { key: request.key };
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
    process.shared_memory.authorize(request.key.memory)?;
    let selects =
        |queued: &QueuedWaiter| queued.key == request.key && queued.bitset & request.bitset != 0;
    let mut woken = Vec::new();
    let mut count = 0;
    {
        let mut bucket = process.core.shared_futexes.bucket(request.key).lock();
        let most = bucket
            .len()
            .min(usize::try_from(request.count).unwrap_or(usize::MAX));
        if most == 0 {
            return Ok(0);
        }
        // Reserve first: a waiter marked woken must have its wake published.
        woken
            .try_reserve(most)
            .map_err(|_| BrokerError::OutOfMemory)?;
        // One stable pass removes the selected entries in linear time, keeping the others oldest
        // first. Selected entries leave the queue even if their waiter is gone or disarmed.
        bucket.retain_mut(|queued| {
            if count == request.count || !selects(queued) {
                return true;
            }
            if let Some(waiter) = queued.waiter.upgrade() {
                let mut state = waiter.state.lock();
                if let WaiterState::Armed { .. } = *state {
                    *state = WaiterState::Woken;
                    drop(state);
                    woken.push(waiter);
                    count += 1;
                }
            }
            false
        });
    }
    for waiter in &woken {
        waiter.registration.republish(FUTEX_WAITER_WOKEN);
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
    /// Returns the waiter's readiness: [`FUTEX_WAITER_WOKEN`] from a wake until it is disarmed.
    pub(crate) fn readiness(&self) -> ReadinessFlags {
        if matches!(*self.0.state.lock(), WaiterState::Woken) {
            FUTEX_WAITER_WOKEN
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
    /// Queued on the futex word `key`.
    Armed {
        key: SharedFutexKey,
    },
    /// Selected by a wake while armed.
    Woken,
}

impl FutexWaiter {
    /// Disarms the waiter, returning whether it was woken and resetting a woken waiter to idle.
    fn disarm_and_take_woken(&self) -> bool {
        loop {
            // Only an armed waiter needs its bucket, which must be locked before its state.
            let key = {
                let mut state = self.state.lock();
                match *state {
                    WaiterState::Armed { key } => key,
                    WaiterState::Woken => {
                        *state = WaiterState::Idle;
                        return true;
                    }
                    WaiterState::Idle => return false,
                }
            };
            let mut bucket = self.futexes.bucket(key).lock();
            let mut state = self.state.lock();
            if matches!(*state, WaiterState::Armed { key: armed } if armed == key) {
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
        FUTEX_WAITER_WOKEN, FutexArmRequest, FutexDisarmRequest, FutexWakeRequest, SharedFutexKey,
        SharedMemoryId,
    };

    use crate::readiness::ReadinessSink;
    use crate::readiness::tests::TestReadinessSink;
    use crate::test_support::TestBrokerCoreBuilder;
    use crate::{BrokerCore, BrokerError, BrokerProcess, CallerCredential, ObjectRights};
    use crate::{PolicyEngine, Result};

    /// The first block of the first process, the fixture's parent, which reserves it before
    /// creating its child.
    const MEMORY: SharedMemoryId = SharedMemoryId::first_in_block(0, 0);

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
            super::futex_arm(
                process,
                FutexArmRequest {
                    key,
                    bitset,
                    waiter,
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
                .filter(|(_, readiness)| readiness.contains(FUTEX_WAITER_WOKEN))
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
            Ok(FUTEX_WAITER_WOKEN)
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
            memory: MEMORY.next_in_block().unwrap(),
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
    fn partial_wake_keeps_unselected_waiters_oldest_first() {
        let fixture = fixture();
        let waiters: std::vec::Vec<_> = (0..6).map(|_| fixture.waiter(&fixture.child)).collect();
        for (index, &waiter) in waiters.iter().enumerate() {
            let bitset = if index % 2 == 0 { 0b10 } else { 0b01 };
            Fixture::arm(&fixture.child, key(0), bitset, waiter).unwrap();
        }
        // A wake that selects nothing leaves the queue as it was.
        assert_eq!(Fixture::wake(&fixture.parent, key(0), 1, 0b100), Ok(0));
        assert_eq!(Fixture::wake(&fixture.parent, key(4), 1, u32::MAX), Ok(0));
        assert_eq!(fixture.queued(), (1, 6));

        // Selecting interleaved entries keeps the rest, including the matching entry past the
        // count, in their order.
        assert_eq!(Fixture::wake(&fixture.parent, key(0), 2, 0b01), Ok(2));
        assert_eq!(fixture.woken_handles(), [waiters[1], waiters[3]]);
        assert_eq!(fixture.queued(), (1, 4));
        assert_eq!(Fixture::wake(&fixture.parent, key(0), 3, u32::MAX), Ok(3));
        assert_eq!(
            fixture.woken_handles(),
            [waiters[1], waiters[3], waiters[0], waiters[2], waiters[4]]
        );
        assert_eq!(Fixture::wake(&fixture.parent, key(0), 1, 0b10), Ok(0));
        assert_eq!(Fixture::wake(&fixture.parent, key(0), 1, 0b01), Ok(1));
        assert_eq!(fixture.queued(), (0, 0));
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
    fn descendants_name_the_blocks_each_ancestor_had_when_creating_their_line() {
        let fixture = fixture();
        let grandchild = fixture
            .core
            .create_process(CallerCredential::Unauthenticated, Some(fixture.child.id()))
            .unwrap();
        // The child reserves after creating the grandchild, so only the grandparent's block
        // reaches the grandchild.
        let child_block = super::reserve_memory_ids(&fixture.child).unwrap();
        let great_grandchild = fixture
            .core
            .create_process(CallerCredential::Unauthenticated, Some(grandchild.id()))
            .unwrap();
        for process in [&grandchild, &great_grandchild] {
            assert_eq!(Fixture::wake(process, key(0), 1, u32::MAX), Ok(0));
            let key = SharedFutexKey {
                memory: child_block,
                offset: 0,
            };
            assert_eq!(
                Fixture::wake(process, key, 1, u32::MAX),
                Err(BrokerError::PolicyDenied)
            );
        }
        // A process may not name the blocks it has yet to reserve.
        let unreserved = SharedFutexKey {
            memory: SharedMemoryId::first_in_block(child_block.reserver(), 1),
            offset: 0,
        };
        assert_eq!(
            Fixture::wake(&fixture.child, unreserved, 1, u32::MAX),
            Err(BrokerError::PolicyDenied)
        );
    }

    #[test]
    fn many_reservations_take_no_memory_per_block() {
        let fixture = fixture();
        // Each fork in a loop of shared mappings and forks reserves a block.
        for block in 1..100_000 {
            assert_eq!(
                super::reserve_memory_ids(&fixture.parent).map(SharedMemoryId::block),
                Ok(block)
            );
        }
        let child = fixture
            .core
            .create_process(CallerCredential::Unauthenticated, Some(fixture.parent.id()))
            .unwrap();
        assert_eq!(child.shared_memory.ancestors.len(), 1);
        let last = SharedFutexKey {
            memory: SharedMemoryId::first_in_block(MEMORY.reserver(), 99_999),
            offset: 0,
        };
        assert_eq!(Fixture::wake(&child, last, 1, u32::MAX), Ok(0));
    }

    #[test]
    fn wakes_racing_disarms_are_each_reported_once() {
        let fixture = Arc::new(fixture());
        let waiter = fixture.waiter(&fixture.child);
        let done = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let waker = {
            let fixture = Arc::clone(&fixture);
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                let mut woken = 0;
                while !done.load(core::sync::atomic::Ordering::Acquire) {
                    woken += Fixture::wake(&fixture.parent, key(0), 1, u32::MAX).unwrap();
                }
                woken
            })
        };
        let mut reported = 0;
        for _ in 0..5000 {
            Fixture::arm(&fixture.child, key(0), u32::MAX, waiter).unwrap();
            if Fixture::disarm(&fixture.child, waiter).unwrap() {
                reported += 1;
            }
        }
        done.store(true, core::sync::atomic::Ordering::Release);
        // Every wake that selected the waiter is reported by exactly one disarm.
        assert_eq!(waker.join().unwrap(), reported);
        assert_eq!(fixture.queued(), (0, 0));
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
    fn woken_waiter_reports_the_wake_until_disarmed_before_rearming() {
        let fixture = fixture();
        let waiter = fixture.waiter(&fixture.child);
        Fixture::arm(&fixture.child, key(0), u32::MAX, waiter).unwrap();
        assert_eq!(Fixture::wake(&fixture.parent, key(0), 1, u32::MAX), Ok(1));
        let published = *fixture.sink.republished.lock().unwrap().last().unwrap();
        assert_eq!(published, (waiter, FUTEX_WAITER_WOKEN));
        assert_eq!(
            fixture.child.check_readiness(waiter),
            Ok(FUTEX_WAITER_WOKEN)
        );
        // A woken waiter must be disarmed, which takes the wake, before it is armed again.
        assert_eq!(
            Fixture::arm(&fixture.child, key(0), u32::MAX, waiter),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(true));
        assert_eq!(
            fixture.child.check_readiness(waiter),
            Ok(ReadinessFlags::default())
        );
        Fixture::arm(&fixture.child, key(0), u32::MAX, waiter).unwrap();
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(false));
        assert_eq!(fixture.queued(), (0, 0));
    }
}
