// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned shared memory and the futexes on it.
//!
//! A shared memory object stands for memory that every process holding a reference to it maps,
//! and keys futex wait queues by byte offset. The broker never touches the memory itself: each
//! waiter compares its futex word after arming, as the
//! [protocol](litebox_broker_protocol::shared_memory) describes.
//!
//! Each futex waiter belongs to one thread and is armed on at most one futex at a time. A wake
//! marks the oldest matching armed waiters woken and publishes their readiness, and disarming a
//! waiter reports whether it was woken, so a wake is never lost to a waiter that
//! times out or is interrupted at the same moment.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_memory::{
    FUTEX_WAITER_WOKEN, FutexArmRequest, FutexDisarmRequest, FutexWakeRequest,
};
use spin::Mutex;
use spin::rwlock::RwLock;

use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::{BrokerError, BrokerProcess, Result};

/// Size of a futex word, which futex offsets are aligned to.
const FUTEX_WORD_SIZE: u64 = 4;

/// Creates a broker-owned shared memory object of `length` bytes.
pub fn create(process: &BrokerProcess, length: u64) -> Result<ObjectHandle> {
    if length < FUTEX_WORD_SIZE {
        return Err(BrokerError::UnsupportedOperation);
    }
    process.create_object_reference(ObjectEntry::SharedMemory(SharedMemoryObject {
        length,
        queues: Mutex::new(BTreeMap::new()),
    }))
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
            state: Mutex::new(WaiterState::Idle),
            registration,
        },
    ))))
}

/// Arms an idle futex waiter on the futex word at `request.offset` of the shared memory.
///
/// Fails with `UnsupportedOperation` if the offset is unaligned or out of range, the mask is
/// zero, or the waiter is not idle.
pub fn futex_arm(process: &BrokerProcess, request: FutexArmRequest) -> Result<()> {
    // Holding the waiter's object defers a concurrent close, whose disarm then dequeues the
    // arming, until after this request's locks are released.
    let waiter_object = process.authorized_object(request.waiter, ObjectRights::WAIT)?;
    let waiter = Arc::clone(&waiter_object.read().as_futex_waiter()?.0);
    let memory = futex_memory(process, request.memory, request.offset, request.bitset)?;
    let entry = memory.read();
    let mut queues = entry.as_shared_memory()?.queues.lock();
    let mut state = waiter.state.lock();
    if !matches!(*state, WaiterState::Idle) {
        return Err(BrokerError::UnsupportedOperation);
    }
    let queue = queues.entry(request.offset).or_default();
    if queue.try_reserve(1).is_err() {
        if queue.is_empty() {
            queues.remove(&request.offset);
        }
        return Err(BrokerError::OutOfMemory);
    }
    queue.push_back(QueuedWaiter {
        waiter: Arc::downgrade(&waiter),
        bitset: request.bitset,
    });
    *state = WaiterState::Armed {
        memory: Arc::clone(&memory),
        offset: request.offset,
    };
    drop(state);
    drop(queues);
    drop(entry);
    drop(waiter_object);
    Ok(())
}

/// Wakes up to `request.count` of the oldest waiters armed on the futex word at
/// `request.offset` whose masks intersect `request.bitset`, returning how many it woke.
///
/// Fails with `UnsupportedOperation` if the offset is unaligned or out of range, or the mask is
/// zero.
pub fn futex_wake(process: &BrokerProcess, request: FutexWakeRequest) -> Result<u32> {
    let memory = futex_memory(process, request.memory, request.offset, request.bitset)?;
    let entry = memory.read();
    let mut woken = Vec::new();
    let mut count = 0;
    {
        let mut queues = entry.as_shared_memory()?.queues.lock();
        if let Some(queue) = queues.get_mut(&request.offset) {
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
                queues.remove(&request.offset);
            }
        }
    }
    drop(entry);
    for waiter in &woken {
        waiter.registration.republish(FUTEX_WAITER_WOKEN);
    }
    Ok(count)
}

/// Disarms a futex waiter, returning whether a wake selected it since it was armed.
///
/// Disarming an idle waiter returns `false`.
pub fn futex_disarm(process: &BrokerProcess, request: FutexDisarmRequest) -> Result<bool> {
    Ok(futex_waiter(process, request.waiter)?.disarm())
}

/// Returns the caller's futex waiter `handle`.
fn futex_waiter(process: &BrokerProcess, handle: ObjectHandle) -> Result<Arc<FutexWaiter>> {
    let waiter = process.authorized_object(handle, ObjectRights::WAIT)?;
    let waiter = waiter.read();
    Ok(Arc::clone(&waiter.as_futex_waiter()?.0))
}

/// Returns the caller's shared memory `handle` after checking that it holds a futex word at
/// `offset` and that `bitset` selects some waiter.
fn futex_memory(
    process: &BrokerProcess,
    handle: ObjectHandle,
    offset: u64,
    bitset: u32,
) -> Result<Arc<RwLock<ObjectEntry>>> {
    if bitset == 0 {
        return Err(BrokerError::UnsupportedOperation);
    }
    let memory = process.authorized_object(handle, ObjectRights::WAIT)?;
    memory.read().as_shared_memory()?.check_offset(offset)?;
    Ok(memory)
}

impl ObjectEntry {
    fn as_shared_memory(&self) -> Result<&SharedMemoryObject> {
        match self {
            Self::SharedMemory(memory) => Ok(memory),
            _ => Err(BrokerError::InvalidRights),
        }
    }

    fn as_futex_waiter(&self) -> Result<&FutexWaiterObject> {
        match self {
            Self::FutexWaiter(waiter) => Ok(waiter),
            _ => Err(BrokerError::InvalidRights),
        }
    }
}

/// Memory shared by every process holding a reference, with its futex wait queues.
pub(crate) struct SharedMemoryObject {
    length: u64,
    /// The waiters armed on each futex word, oldest first, by byte offset.
    ///
    /// Each waiter is armed on at most one futex, so the queues together hold at most one entry
    /// per live waiter.
    queues: Mutex<BTreeMap<u64, VecDeque<QueuedWaiter>>>,
}

impl SharedMemoryObject {
    fn check_offset(&self, offset: u64) -> Result<()> {
        if !offset.is_multiple_of(FUTEX_WORD_SIZE)
            || offset
                .checked_add(FUTEX_WORD_SIZE)
                .is_none_or(|end| end > self.length)
        {
            return Err(BrokerError::UnsupportedOperation);
        }
        Ok(())
    }
}

struct QueuedWaiter {
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
        self.0.disarm();
    }
}

struct FutexWaiter {
    state: Mutex<WaiterState>,
    /// Publication of wakes to the owning process.
    registration: ReadinessRegistration,
}

enum WaiterState {
    Idle,
    /// Queued on the futex word at `offset` of `memory`, which the waiter keeps alive.
    Armed {
        memory: Arc<RwLock<ObjectEntry>>,
        offset: u64,
    },
    Woken,
}

impl FutexWaiter {
    /// Disarms the waiter, returning whether it was woken.
    fn disarm(&self) -> bool {
        let armed = match &*self.state.lock() {
            WaiterState::Armed { memory, offset } => Some((Arc::clone(memory), *offset)),
            WaiterState::Idle | WaiterState::Woken => None,
        };
        let Some((memory, offset)) = armed else {
            let mut state = self.state.lock();
            // A concurrent request may have armed the waiter since; that arming stays.
            return match *state {
                WaiterState::Woken => {
                    *state = WaiterState::Idle;
                    true
                }
                WaiterState::Idle | WaiterState::Armed { .. } => false,
            };
        };
        // Queues lock before waiters, so take both before changing the arming they record.
        let entry = memory.read();
        let Ok(shared) = entry.as_shared_memory() else {
            unreachable!("waiters are armed only on shared memory");
        };
        let mut queues = shared.queues.lock();
        let mut state = self.state.lock();
        match &*state {
            WaiterState::Armed {
                memory: armed_memory,
                offset: armed_offset,
            } if Arc::ptr_eq(armed_memory, &memory) && *armed_offset == offset => {
                if let Some(queue) = queues.get_mut(&offset) {
                    queue.retain(|queued| !core::ptr::eq(queued.waiter.as_ptr(), self));
                    if queue.is_empty() {
                        queues.remove(&offset);
                    }
                }
                *state = WaiterState::Idle;
                false
            }
            // A wake dequeued the waiter after the state was first read.
            WaiterState::Woken => {
                *state = WaiterState::Idle;
                true
            }
            // A concurrent disarm and arm replaced the arming read above; the new one stays.
            WaiterState::Idle | WaiterState::Armed { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::shared_memory::{
        FUTEX_WAITER_WOKEN, FutexArmRequest, FutexDisarmRequest, FutexWakeRequest,
    };

    use crate::readiness::ReadinessSink;
    use crate::readiness::tests::TestReadinessSink;
    use crate::test_support::TestBrokerCoreBuilder;
    use crate::{BrokerCore, BrokerError, BrokerProcess, CallerCredential, ObjectRights};
    use crate::{PolicyEngine, Result};

    struct Fixture {
        _core: BrokerCore,
        parent: Arc<BrokerProcess>,
        child: Arc<BrokerProcess>,
        sink: Arc<TestReadinessSink>,
        parent_memory: ObjectHandle,
        child_memory: ObjectHandle,
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
        let parent_memory = super::create(&parent, 4096).unwrap();
        let child_memory = parent
            .duplicate_object_reference_to(parent_memory, &child, ObjectRights::WAIT)
            .unwrap();
        Fixture {
            _core: core,
            parent,
            child,
            sink: Arc::new(TestReadinessSink::default()),
            parent_memory,
            child_memory,
        }
    }

    impl Fixture {
        fn waiter(&self, process: &BrokerProcess) -> ObjectHandle {
            super::create_futex_waiter(process, &(self.sink.clone() as Arc<dyn ReadinessSink>))
                .unwrap()
        }

        fn arm(
            process: &BrokerProcess,
            memory: ObjectHandle,
            offset: u64,
            bitset: u32,
            waiter: ObjectHandle,
        ) -> Result<()> {
            super::futex_arm(
                process,
                FutexArmRequest {
                    memory,
                    offset,
                    bitset,
                    waiter,
                },
            )
        }

        fn disarm(process: &BrokerProcess, waiter: ObjectHandle) -> Result<bool> {
            super::futex_disarm(process, FutexDisarmRequest { waiter })
        }

        fn queued_waiters(&self) -> usize {
            let memory = self
                .parent
                .authorized_object(self.parent_memory, ObjectRights::WAIT)
                .unwrap();
            let memory = memory.read();
            let queues = memory.as_shared_memory().unwrap().queues.lock();
            queues.values().map(alloc::collections::VecDeque::len).sum()
        }

        fn wake(
            process: &BrokerProcess,
            memory: ObjectHandle,
            offset: u64,
            count: u32,
            bitset: u32,
        ) -> Result<u32> {
            super::futex_wake(
                process,
                FutexWakeRequest {
                    memory,
                    offset,
                    count,
                    bitset,
                },
            )
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
        Fixture::arm(&fixture.child, fixture.child_memory, 8, u32::MAX, waiter).unwrap();
        assert_eq!(
            fixture.child.check_readiness(waiter),
            Ok(ReadinessFlags::default())
        );

        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.parent_memory, 8, 1, u32::MAX),
            Ok(1)
        );
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
    }

    #[test]
    fn wake_selects_oldest_matching_waiters_up_to_count() {
        let fixture = fixture();
        let waiters: std::vec::Vec<_> = (0..4).map(|_| fixture.waiter(&fixture.child)).collect();
        for (index, &waiter) in waiters.iter().enumerate() {
            let bitset = if index == 1 { 0b10 } else { 0b01 };
            Fixture::arm(&fixture.child, fixture.child_memory, 0, bitset, waiter).unwrap();
        }
        // A different futex word is not woken.
        let other = fixture.waiter(&fixture.parent);
        Fixture::arm(&fixture.parent, fixture.parent_memory, 4, u32::MAX, other).unwrap();

        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.parent_memory, 0, 2, 0b01),
            Ok(2)
        );
        assert_eq!(fixture.woken_handles(), [waiters[0], waiters[2]]);
        assert_eq!(
            Fixture::wake(
                &fixture.parent,
                fixture.parent_memory,
                0,
                u32::MAX,
                u32::MAX
            ),
            Ok(2)
        );
        assert_eq!(
            fixture.woken_handles(),
            [waiters[0], waiters[2], waiters[1], waiters[3]]
        );
        assert_eq!(Fixture::disarm(&fixture.parent, other), Ok(false));
        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.parent_memory, 4, 1, u32::MAX),
            Ok(0)
        );
    }

    #[test]
    fn disarmed_waiter_is_not_woken_and_can_rearm() {
        let fixture = fixture();
        let waiter = fixture.waiter(&fixture.child);
        Fixture::arm(&fixture.child, fixture.child_memory, 0, u32::MAX, waiter).unwrap();
        assert_eq!(
            Fixture::arm(&fixture.child, fixture.child_memory, 0, u32::MAX, waiter),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(false));
        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.parent_memory, 0, 1, u32::MAX),
            Ok(0)
        );

        Fixture::arm(&fixture.child, fixture.child_memory, 0, u32::MAX, waiter).unwrap();
        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.parent_memory, 0, 1, u32::MAX),
            Ok(1)
        );
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(true));
    }

    #[test]
    fn closed_waiter_leaves_its_queue() {
        let fixture = fixture();
        let closed = fixture.waiter(&fixture.child);
        let remaining = fixture.waiter(&fixture.child);
        Fixture::arm(&fixture.child, fixture.child_memory, 0, u32::MAX, closed).unwrap();
        Fixture::arm(&fixture.child, fixture.child_memory, 0, u32::MAX, remaining).unwrap();
        fixture.child.close_object_reference(closed).unwrap();

        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.parent_memory, 0, 1, u32::MAX),
            Ok(1)
        );
        assert_eq!(fixture.woken_handles(), [remaining]);
    }

    #[test]
    fn armed_waiter_keeps_memory_alive_after_its_references_close() {
        let fixture = fixture();
        let waiter = fixture.waiter(&fixture.child);
        Fixture::arm(&fixture.child, fixture.child_memory, 0, u32::MAX, waiter).unwrap();
        fixture
            .child
            .close_object_reference(fixture.child_memory)
            .unwrap();
        assert_eq!(
            Fixture::wake(&fixture.parent, fixture.parent_memory, 0, 1, u32::MAX),
            Ok(1)
        );
        assert_eq!(Fixture::disarm(&fixture.child, waiter), Ok(true));
    }

    #[test]
    fn concurrent_arm_and_disarm_never_orphan_queue_entries() {
        let fixture = Arc::new(fixture());
        let waiter = fixture.waiter(&fixture.child);
        let armer = {
            let fixture = Arc::clone(&fixture);
            std::thread::spawn(move || {
                for _ in 0..2000 {
                    let _ = Fixture::arm(&fixture.child, fixture.child_memory, 0, 1, waiter);
                }
            })
        };
        for _ in 0..2000 {
            Fixture::disarm(&fixture.child, waiter).unwrap();
        }
        armer.join().unwrap();
        // At most the last arming remains queued, and disarming removes it.
        assert!(fixture.queued_waiters() <= 1);
        Fixture::disarm(&fixture.child, waiter).unwrap();
        assert_eq!(fixture.queued_waiters(), 0);
    }

    #[test]
    fn closing_a_waiter_while_it_arms_never_orphans_queue_entries() {
        let fixture = Arc::new(fixture());
        for _ in 0..500 {
            let waiter = fixture.waiter(&fixture.child);
            let armer = {
                let fixture = Arc::clone(&fixture);
                std::thread::spawn(move || {
                    let _ = Fixture::arm(&fixture.child, fixture.child_memory, 0, 1, waiter);
                })
            };
            fixture.child.close_object_reference(waiter).unwrap();
            armer.join().unwrap();
            assert_eq!(fixture.queued_waiters(), 0);
        }
    }

    #[test]
    fn rejects_invalid_requests() {
        let fixture = fixture();
        let waiter = fixture.waiter(&fixture.child);
        assert_eq!(
            super::create(&fixture.parent, 0),
            Err(BrokerError::UnsupportedOperation)
        );
        for (offset, bitset) in [(2, u32::MAX), (4096, u32::MAX), (u64::MAX - 3, 1), (0, 0)] {
            assert_eq!(
                Fixture::arm(&fixture.child, fixture.child_memory, offset, bitset, waiter),
                Err(BrokerError::UnsupportedOperation)
            );
            assert_eq!(
                Fixture::wake(&fixture.child, fixture.child_memory, offset, 1, bitset),
                Err(BrokerError::UnsupportedOperation)
            );
        }
        // Handles of other kinds, or of other processes, are rejected.
        assert_eq!(
            Fixture::arm(
                &fixture.child,
                fixture.child_memory,
                0,
                1,
                fixture.child_memory
            ),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            Fixture::wake(&fixture.child, waiter, 0, 1, 1),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            Fixture::wake(&fixture.child, fixture.parent_memory, 0, 1, 1),
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
