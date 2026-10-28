// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Futex wait queues for memory that several processes share.
//!
//! The broker never sees the memory. Processes name it by a [`SharedMemoryId`] that
//! [`issue_shared_memory_id`] issues, and each waiter checks its futex word itself after arming,
//! as the [protocol](litebox_broker_protocol::shared_futex) describes. Waiters are queued by
//! [`SharedFutexKey`] in buckets chosen by hashing the key.
//!
//! The broker signs each ID it issues with a key only it knows, and rejects keys naming IDs it
//! did not sign. So a process can only name memory whose ID it was given: memory it created, or
//! that it inherited by copying its creator's memory, as native fork does. Like a capability
//! handle, which a process could keep after unmapping the memory too, an ID grants access for as
//! long as the process holds it, but it takes no broker state.
//!
//! A waiter is armed on at most one futex at a time, so the buckets hold at most one entry per
//! waiter. A wake marks waiters woken and publishes readiness for them, and disarming reports
//! it, so a wake racing a timeout or interruption is not lost.

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hmac::{Hmac, Mac};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_futex::{
    FUTEX_WAITER_WOKEN, FUTEX_WORD_SIZE, FutexArmRequest, FutexDisarmRequest, FutexWakeRequest,
    SharedFutexKey, SharedMemoryId,
};
use sha2::Sha256;
use spin::{Mutex, Once};

use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::{BrokerError, BrokerProcess, Result};

/// Base-two logarithm of the number of wait queue buckets.
const BUCKET_BITS: u32 = 8;
const BUCKETS: usize = 1 << BUCKET_BITS;

/// Length in bytes of the key that signs shared memory IDs.
const SIGNING_KEY_LEN: usize = 32;

/// Separates the signatures of shared memory IDs from any other signatures made with the same
/// key.
const SIGNING_DOMAIN: &[u8] = b"litebox shared memory id\0";

/// The waiters armed on the futex words whose keys hash to one bucket, oldest first.
type Bucket = Mutex<VecDeque<QueuedWaiter>>;

/// Broker-wide state of futexes in shared memory.
pub(crate) struct SharedFutexes {
    /// Lock order: a bucket, then a waiter's state.
    buckets: [Bucket; BUCKETS],
    /// The serial of the next shared memory ID to create.
    next_serial: AtomicU64,
    /// Signs shared memory IDs, keyed with random bytes when the first ID is issued.
    signer: Once<Hmac<Sha256>>,
}

impl Default for SharedFutexes {
    fn default() -> Self {
        Self {
            buckets: core::array::from_fn(|_| Mutex::new(VecDeque::new())),
            next_serial: AtomicU64::new(0),
            signer: Once::new(),
        }
    }
}

impl SharedFutexes {
    fn bucket(&self, key: SharedFutexKey) -> &Bucket {
        // Fibonacci hashing of the memory ID, folding its serial into its tag, and the word's
        // index in the memory.
        const MULTIPLIER: u128 = 0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835;
        let mixed = key.memory.0 ^ (key.memory.0 >> 64) ^ u128::from(key.offset / FUTEX_WORD_SIZE);
        let hash = mixed.wrapping_mul(MULTIPLIER) >> (u128::BITS - BUCKET_BITS);
        &self.buckets[usize::try_from(hash).unwrap_or_default() % BUCKETS]
    }

    /// Returns the signer, keying it from `process`'s broker random provider the first time.
    fn signer(&self, process: &BrokerProcess) -> Result<&Hmac<Sha256>> {
        if let Some(signer) = self.signer.get() {
            return Ok(signer);
        }
        let mut key = [0; SIGNING_KEY_LEN];
        process
            .core
            .random_provider
            .fill(&mut key)
            .map_err(|_| BrokerError::Internal)?;
        let signer = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| BrokerError::Internal)?;
        // Concurrent first uses may each draw a key; the first one kept signs every ID.
        Ok(self.signer.call_once(|| signer))
    }

    /// Returns `signer`'s signature over `serial`.
    fn sign(signer: &Hmac<Sha256>, serial: u64) -> Hmac<Sha256> {
        let mut mac = signer.clone();
        mac.update(SIGNING_DOMAIN);
        mac.update(&serial.to_le_bytes());
        mac
    }

    /// Fails with `PolicyDenied` unless the broker signed `memory`.
    fn authorize(&self, memory: SharedMemoryId) -> Result<()> {
        // Without a signer, no ID was ever created.
        let signer = self.signer.get().ok_or(BrokerError::PolicyDenied)?;
        Self::sign(signer, memory.serial())
            .verify_truncated_left(&memory.tag().to_le_bytes())
            .map_err(|_| BrokerError::PolicyDenied)
    }
}

/// Issues a signed ID for new shared memory.
pub fn issue_shared_memory_id(process: &BrokerProcess) -> Result<SharedMemoryId> {
    process.require_object_rights(ObjectRights::WAIT)?;
    let futexes = &process.core.shared_futexes;
    let signer = futexes.signer(process)?;
    let serial = futexes
        .next_serial
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |serial| {
            serial.checked_add(1)
        })
        .map_err(|_| BrokerError::ResourceExhausted)?;
    let signature = SharedFutexes::sign(signer, serial).finalize().into_bytes();
    let mut tag = [0; size_of::<u64>()];
    tag.copy_from_slice(&signature[..size_of::<u64>()]);
    Ok(SharedMemoryId::new(serial, u64::from_le_bytes(tag)))
}

/// Creates an idle futex waiter whose reference publishes its readiness through
/// `readiness_sink`.
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
pub fn futex_arm(process: &BrokerProcess, request: FutexArmRequest) -> Result<()> {
    validate_key_and_bitset(request.key, request.bitset)?;
    process.core.shared_futexes.authorize(request.key.memory)?;
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
pub fn futex_wake(process: &BrokerProcess, request: FutexWakeRequest) -> Result<u32> {
    validate_key_and_bitset(request.key, request.bitset)?;
    process.require_object_rights(ObjectRights::WAIT)?;
    process.core.shared_futexes.authorize(request.key.memory)?;
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

    use crate::random::TestRandomProvider;
    use crate::readiness::ReadinessSink;
    use crate::readiness::tests::TestReadinessSink;
    use crate::test_support::TestBrokerCoreBuilder;
    use crate::{BrokerCore, BrokerError, BrokerProcess, CallerCredential, ObjectRights};
    use crate::{PolicyEngine, Result};

    struct Fixture {
        core: BrokerCore,
        parent: Arc<BrokerProcess>,
        child: Arc<BrokerProcess>,
        sink: Arc<TestReadinessSink>,
        /// Memory the parent created before creating its child.
        memory: SharedMemoryId,
    }

    fn core(rights: ObjectRights) -> BrokerCore {
        TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(rights))
            .with_random_provider(Arc::new(TestRandomProvider))
            .build()
            .unwrap()
    }

    fn fixture() -> Fixture {
        let core = core(ObjectRights::WAIT | ObjectRights::WRITE);
        let parent = core
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let memory = super::issue_shared_memory_id(&parent).unwrap();
        let child = core
            .create_process(CallerCredential::Unauthenticated, Some(parent.id()))
            .unwrap();
        Fixture {
            core,
            parent,
            child,
            sink: Arc::new(TestReadinessSink::default()),
            memory,
        }
    }

    impl Fixture {
        fn key(&self, offset: u64) -> SharedFutexKey {
            SharedFutexKey {
                memory: self.memory,
                offset,
            }
        }

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
    fn waiter_reports_a_wake_from_another_process_until_disarmed() {
        let fixture = fixture();
        let waiter = fixture.waiter(&fixture.child);
        let readiness = || fixture.child.check_readiness(waiter);
        // An armed waiter may not be armed again, and disarming it before any wake reports none
        // and leaves it unwakeable.
        Fixture::arm(&fixture.child, fixture.key(8), u32::MAX, waiter).unwrap();
        assert_eq!(
            Fixture::arm(&fixture.child, fixture.key(8), u32::MAX, waiter),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(false));
        assert_eq!(fixture.queued(), (0, 0));
        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.key(8), 1, u32::MAX),
            Ok(0)
        );

        // A wake from another process marks the rearmed waiter woken and publishes it.
        Fixture::arm(&fixture.child, fixture.key(8), u32::MAX, waiter).unwrap();
        assert_eq!(readiness(), Ok(ReadinessFlags::default()));
        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.key(8), 1, u32::MAX),
            Ok(1)
        );
        let published = *fixture.sink.republished.lock().unwrap().last().unwrap();
        assert_eq!(published, (waiter, FUTEX_WAITER_WOKEN));
        assert_eq!(readiness(), Ok(FUTEX_WAITER_WOKEN));
        // A woken waiter must be disarmed, which takes the wake, before it is armed again.
        assert_eq!(
            Fixture::arm(&fixture.child, fixture.key(8), u32::MAX, waiter),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(true));
        assert_eq!(readiness(), Ok(ReadinessFlags::default()));
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(false));
        assert_eq!(fixture.queued(), (0, 0));
    }

    #[test]
    fn wake_selects_oldest_matching_waiters_up_to_count_and_keeps_the_rest_in_order() {
        let fixture = fixture();
        let waiters: std::vec::Vec<_> = (0..6).map(|_| fixture.waiter(&fixture.child)).collect();
        for (index, &waiter) in waiters.iter().enumerate() {
            let bitset = if index % 2 == 0 { 0b10 } else { 0b01 };
            Fixture::arm(&fixture.child, fixture.key(0), bitset, waiter).unwrap();
        }
        // Waiters on another futex word, in the same memory or in other memory, are never
        // selected.
        let other_offset = fixture.waiter(&fixture.parent);
        Fixture::arm(&fixture.parent, fixture.key(4), u32::MAX, other_offset).unwrap();
        let other_memory = fixture.waiter(&fixture.parent);
        let other_memory_key = SharedFutexKey {
            memory: super::issue_shared_memory_id(&fixture.parent).unwrap(),
            offset: 0,
        };
        Fixture::arm(&fixture.parent, other_memory_key, u32::MAX, other_memory).unwrap();

        // A wake that selects nothing leaves the queues as they were.
        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.key(0), 1, 0b100),
            Ok(0)
        );
        assert_eq!(fixture.queued(), (3, 8));

        // Selecting interleaved entries keeps the rest, including the matching entry past the
        // count, in their order.
        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.key(0), 2, 0b01),
            Ok(2)
        );
        assert_eq!(fixture.woken_handles(), [waiters[1], waiters[3]]);
        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.key(0), 3, u32::MAX),
            Ok(3)
        );
        assert_eq!(
            fixture.woken_handles(),
            [waiters[1], waiters[3], waiters[0], waiters[2], waiters[4]]
        );
        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.key(0), 1, 0b10),
            Ok(0)
        );
        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.key(0), 1, 0b01),
            Ok(1)
        );
        assert_eq!(fixture.queued(), (2, 2));
        for key in [fixture.key(4), other_memory_key] {
            assert_eq!(Fixture::wake(&fixture.parent, key, 1, u32::MAX), Ok(1));
        }
        assert_eq!(fixture.queued(), (0, 0));
    }

    #[test]
    fn closed_and_exited_waiters_leave_their_queues() {
        let fixture = fixture();
        let closed = fixture.waiter(&fixture.parent);
        let exiting = fixture.waiter(&fixture.child);
        let remaining = fixture.waiter(&fixture.parent);
        for (process, waiter) in [
            (&fixture.parent, closed),
            (&fixture.child, exiting),
            (&fixture.parent, remaining),
        ] {
            Fixture::arm(process, fixture.key(0), u32::MAX, waiter).unwrap();
        }
        fixture.parent.close_object_reference(closed).unwrap();
        fixture.child.cleanup(true);
        assert_eq!(fixture.queued(), (1, 1));

        // A wake is not spent on waiters that are gone.
        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.key(0), 1, u32::MAX),
            Ok(1)
        );
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
                    let _ = Fixture::arm(&fixture.child, fixture.key(0), 1, waiter);
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
                    let _ = Fixture::arm(&fixture.child, fixture.key(0), 1, waiter);
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
                Fixture::arm(&fixture.child, fixture.key(offset), bitset, waiter),
                Err(BrokerError::UnsupportedOperation)
            );
            assert_eq!(
                Fixture::wake(&fixture.child, fixture.key(offset), 1, bitset),
                Err(BrokerError::UnsupportedOperation)
            );
        }
        assert_eq!(fixture.queued(), (0, 0));
        // Handles are per process, so another process cannot name the waiter.
        assert_eq!(
            Fixture::arm(&fixture.parent, fixture.key(0), 1, waiter),
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
    fn processes_name_only_memory_whose_signed_id_they_were_given() {
        let fixture = fixture();
        let unrelated = fixture
            .core
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        // IDs are unique, whoever asks for them.
        let created = [&fixture.parent, &fixture.child, &unrelated]
            .map(|process| super::issue_shared_memory_id(process).unwrap());
        assert!(
            created.iter().all(|&id| id != fixture.memory)
                && created[0] != created[1]
                && created[1] != created[2]
                && created[0] != created[2]
        );
        let waiter = fixture.waiter(&fixture.child);
        // Changing any bit of a signed ID, in its serial or its tag, yields an unsigned one, as
        // does an ID with a serial the broker has yet to use.
        let memory = fixture.memory.0;
        let unissued = SharedMemoryId::new(u64::MAX, fixture.memory.tag());
        for forged in [memory ^ 1, memory ^ 1 << 63, memory ^ 1 << 64, unissued.0] {
            let key = SharedFutexKey {
                memory: SharedMemoryId(forged),
                offset: 0,
            };
            assert_eq!(
                Fixture::arm(&fixture.child, key, u32::MAX, waiter),
                Err(BrokerError::PolicyDenied)
            );
            assert_eq!(
                Fixture::wake(&unrelated, key, 1, u32::MAX),
                Err(BrokerError::PolicyDenied)
            );
        }
        assert_eq!(fixture.queued(), (0, 0));
        // A signed ID is honored from any process holding it.
        Fixture::arm(&fixture.child, fixture.key(0), u32::MAX, waiter).unwrap();
        assert_eq!(
            Fixture::wake(&unrelated, fixture.key(0), 1, u32::MAX),
            Ok(1)
        );
        assert_eq!(fixture.woken_handles(), [waiter]);
    }

    #[test]
    fn creating_memory_needs_randomness() {
        let core = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::WAIT,
        ))
        .build()
        .unwrap();
        let process = core
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        assert_eq!(
            super::issue_shared_memory_id(&process),
            Err(BrokerError::Internal)
        );
        // A broker that never issued an ID accepts none.
        let key = SharedFutexKey {
            memory: SharedMemoryId(0),
            offset: 0,
        };
        assert_eq!(
            Fixture::wake(&process, key, 1, u32::MAX),
            Err(BrokerError::PolicyDenied)
        );
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
                    woken += Fixture::wake(&fixture.parent, fixture.key(0), 1, u32::MAX).unwrap();
                }
                woken
            })
        };
        let mut reported = 0;
        for _ in 0..5000 {
            Fixture::arm(&fixture.child, fixture.key(0), u32::MAX, waiter).unwrap();
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
            super::issue_shared_memory_id(&process),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            super::create_futex_waiter(&process, &sink),
            Err(BrokerError::PolicyDenied)
        );
        let key = SharedFutexKey {
            memory: SharedMemoryId(0),
            offset: 0,
        };
        assert_eq!(
            Fixture::wake(&process, key, 1, u32::MAX),
            Err(BrokerError::PolicyDenied)
        );
    }
}
