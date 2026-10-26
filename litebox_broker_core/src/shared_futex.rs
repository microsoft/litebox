// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Futex wait queues for memory that several processes share.
//!
//! The broker keeps no record of the memory: the processes sharing it name it by a
//! [`SharedMemoryId`](litebox_broker_protocol::shared_futex::SharedMemoryId) from a prefix that
//! [`reserve_memory_ids`] returns, and the broker keys wait queues by [`SharedFutexKey`]. A queue
//! exists only while a waiter is armed on it. The
//! broker never touches the memory itself: each waiter compares its futex word after arming, as
//! the [protocol](litebox_broker_protocol::shared_futex) describes.
//!
//! Any process may name any key, so a process can wake, or take wakes from, futexes of other
//! processes. As on Linux, where a process may wake any futex in memory it maps, that disturbs
//! only the guests involved; the broker's own state stays bounded and consistent.
//!
//! Each futex waiter belongs to one thread and is armed on at most one futex at a time, so the
//! queues together hold at most one entry per live waiter. A wake marks the oldest matching armed
//! waiters woken and publishes their readiness, and disarming a waiter reports whether it was
//! woken, so a wake is never lost to a waiter that times out or is interrupted at the same
//! moment.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_futex::{
    FUTEX_WAITER_WOKEN, FutexArmRequest, FutexDisarmRequest, FutexWakeRequest, SharedFutexKey,
};
use spin::Mutex;

use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::{BrokerError, BrokerProcess, Result};

/// Size of a futex word, which futex offsets are aligned to.
const FUTEX_WORD_SIZE: u64 = 4;

/// Broker-wide state of futexes in shared memory.
#[derive(Default)]
pub(crate) struct SharedFutexes {
    /// The waiters armed on each futex word, oldest first.
    ///
    /// Lock order: these queues, then a waiter's state.
    queues: Mutex<BTreeMap<SharedFutexKey, VecDeque<QueuedWaiter>>>,
    /// The next shared memory ID prefix to reserve.
    next_prefix: AtomicU64,
}

/// Reserves the shared memory IDs that start with the returned prefix, which no other
/// reservation returns.
///
/// Fails with `ResourceExhausted` once every prefix is reserved.
pub fn reserve_memory_ids(process: &BrokerProcess) -> Result<u64> {
    process
        .core
        .shared_futexes
        .next_prefix
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |prefix| {
            prefix.checked_add(1)
        })
        .map_err(|_| BrokerError::ResourceExhausted)
}

/// Creates an idle futex waiter whose reference publishes its readiness through
/// `readiness_sink`.
///
/// Fails with `PolicyDenied` if the caller may not wait on objects.
pub fn create_futex_waiter(
    process: &BrokerProcess,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let rights = process
        .core
        .policy
        .principal_object_rights(process.caller_credential)?;
    if !rights.contains(ObjectRights::WAIT) {
        return Err(BrokerError::PolicyDenied);
    }
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
/// is not idle.
pub fn futex_arm(process: &BrokerProcess, request: FutexArmRequest) -> Result<()> {
    check_futex(request.key, request.bitset)?;
    // Holding the waiter's object defers a concurrent close, whose disarm then dequeues the
    // arming, until after this request's locks are released.
    let waiter_object = process.authorized_object(request.waiter, ObjectRights::WAIT)?;
    let waiter = Arc::clone(&waiter_object.read().as_futex_waiter()?.0);
    let mut queues = waiter.futexes.queues.lock();
    let mut state = waiter.state.lock();
    if !matches!(*state, WaiterState::Idle) {
        return Err(BrokerError::UnsupportedOperation);
    }
    let queue = queues.entry(request.key).or_default();
    if queue.try_reserve(1).is_err() {
        if queue.is_empty() {
            queues.remove(&request.key);
        }
        return Err(BrokerError::OutOfMemory);
    }
    queue.push_back(QueuedWaiter {
        waiter: Arc::downgrade(&waiter),
        bitset: request.bitset,
    });
    *state = WaiterState::Armed { key: request.key };
    drop(state);
    drop(queues);
    drop(waiter_object);
    Ok(())
}

/// Wakes up to `request.count` of the oldest waiters armed on the futex word `request.key`
/// whose masks intersect `request.bitset`, returning how many it woke.
///
/// Fails with `UnsupportedOperation` if the offset is unaligned or the mask is zero.
pub fn futex_wake(process: &BrokerProcess, request: FutexWakeRequest) -> Result<u32> {
    check_futex(request.key, request.bitset)?;
    let mut woken = Vec::new();
    let mut count = 0;
    {
        let mut queues = process.core.shared_futexes.queues.lock();
        if let Some(queue) = queues.get_mut(&request.key) {
            // Reserve first: a waiter marked woken must have its wake published.
            woken
                .try_reserve(queue.len().min(request.count as usize))
                .map_err(|_| BrokerError::OutOfMemory)?;
            // One stable pass, so removing interleaved selections stays linear.
            queue.retain(|queued| {
                if count >= request.count || queued.bitset & request.bitset == 0 {
                    return true;
                }
                // Selected entries leave the queue even if their waiter is gone or disarmed.
                if let Some(waiter) = queued.waiter.upgrade() {
                    let mut state = waiter.state.lock();
                    if matches!(*state, WaiterState::Armed { .. }) {
                        *state = WaiterState::Woken;
                        drop(state);
                        woken.push(waiter);
                        count += 1;
                    }
                }
                false
            });
            if queue.is_empty() {
                queues.remove(&request.key);
            }
        }
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

fn check_futex(key: SharedFutexKey, bitset: u32) -> Result<()> {
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

pub(crate) struct QueuedWaiter {
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
    Woken,
}

impl FutexWaiter {
    /// Disarms the waiter, returning whether it was woken and resetting a woken waiter to idle.
    fn disarm_and_take_woken(&self) -> bool {
        let mut queues = self.futexes.queues.lock();
        let mut state = self.state.lock();
        match *state {
            WaiterState::Armed { key } => {
                if let Some(queue) = queues.get_mut(&key) {
                    queue.retain(|queued| !core::ptr::eq(queued.waiter.as_ptr(), self));
                    if queue.is_empty() {
                        queues.remove(&key);
                    }
                }
                *state = WaiterState::Idle;
                false
            }
            WaiterState::Woken => {
                *state = WaiterState::Idle;
                true
            }
            WaiterState::Idle => false,
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

    const MEMORY: SharedMemoryId = SharedMemoryId(7);

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

    fn fixture() -> Fixture {
        let core = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::WAIT | ObjectRights::WRITE,
        ))
        .build()
        .unwrap();
        let parent = core
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let child = core
            .create_process(CallerCredential::Unauthenticated, None)
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

        /// Returns how many futex words have queues, and how many waiters they hold.
        fn queued(&self) -> (usize, usize) {
            let queues = self.core.shared_futexes.queues.lock();
            (
                queues.len(),
                queues.values().map(alloc::collections::VecDeque::len).sum(),
            )
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
                .filter(|(_, readiness)| *readiness == FUTEX_WAITER_WOKEN)
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
            memory: SharedMemoryId(MEMORY.0 + 1),
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
    fn reserved_memory_id_prefixes_are_unique() {
        let fixture = fixture();
        let first = super::reserve_memory_ids(&fixture.parent).unwrap();
        let second = super::reserve_memory_ids(&fixture.child).unwrap();
        assert_ne!(first, second);
        fixture
            .core
            .shared_futexes
            .next_prefix
            .store(u64::MAX, core::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            super::reserve_memory_ids(&fixture.parent),
            Err(BrokerError::ResourceExhausted)
        );
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
        // Waiters of other processes are rejected.
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
}
