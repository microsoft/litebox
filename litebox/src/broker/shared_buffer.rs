// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::Ordering::{Acquire, Release};

use litebox_broker_protocol::shared_buffer::{
    SHARED_BUFFER_LAYOUT, SHARED_BUFFER_SLOT_COUNT, SHARED_BUFFER_SLOT_SIZE,
    SharedBufferDescriptor, SharedBufferSequence,
};
use litebox_platform::sync::RawMutex as _;

use crate::sync::{Mutex, RawSyncPrimitivesProvider};

const ALLOCATED_SLOT_MASK: u64 = (1 << SHARED_BUFFER_SLOT_COUNT) - 1;

pub(super) struct SlotAllocator<Platform: RawSyncPrimitivesProvider> {
    state: Mutex<Platform, AllocatorState<Platform>>,
}

struct AllocatorState<Platform: RawSyncPrimitivesProvider> {
    allocated_slots: u64,
    next_slot: u32,
    failed: bool,
    waiters: VecDeque<Arc<SlotWaiter<Platform>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AcquireError {
    TooLarge,
    AssociationFailed,
}

pub(super) struct SlotLease<'a, Platform: RawSyncPrimitivesProvider> {
    allocator: &'a SlotAllocator<Platform>,
    sequence: SharedBufferSequence,
}

struct SlotWaiter<Platform: RawSyncPrimitivesProvider> {
    length: u32,
    slot_count: u32,
    result: Mutex<Platform, Option<Result<SharedBufferSequence, AcquireError>>>,
    completion: Platform::RawMutex,
}

impl<Platform: RawSyncPrimitivesProvider> SlotAllocator<Platform> {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(AllocatorState {
                allocated_slots: 0,
                next_slot: 0,
                failed: false,
                waiters: VecDeque::new(),
            }),
        }
    }

    pub(super) fn acquire(&self, length: u32) -> Result<SlotLease<'_, Platform>, AcquireError> {
        let slot_count = if length == 0 {
            1
        } else {
            length.div_ceil(SHARED_BUFFER_SLOT_SIZE)
        };
        if slot_count > SHARED_BUFFER_SLOT_COUNT {
            return Err(AcquireError::TooLarge);
        }
        self.acquire_count(length, slot_count)
    }

    fn acquire_count(
        &self,
        length: u32,
        slot_count: u32,
    ) -> Result<SlotLease<'_, Platform>, AcquireError> {
        {
            let mut state = self.state.lock();
            if state.failed {
                return Err(AcquireError::AssociationFailed);
            }
            if state.waiters.is_empty()
                && let Some(sequence) = state.allocate(length, slot_count)
            {
                return Ok(SlotLease {
                    allocator: self,
                    sequence,
                });
            }
        }

        let waiter = Arc::new(SlotWaiter::new(length, slot_count));
        {
            let mut state = self.state.lock();
            if state.failed {
                return Err(AcquireError::AssociationFailed);
            }
            if state.waiters.is_empty()
                && let Some(sequence) = state.allocate(length, slot_count)
            {
                return Ok(SlotLease {
                    allocator: self,
                    sequence,
                });
            }
            state.waiters.push_back(Arc::clone(&waiter));
        }

        let sequence = waiter.wait()?;
        Ok(SlotLease {
            allocator: self,
            sequence,
        })
    }

    pub(super) fn fail(&self) -> bool {
        let waiters = {
            let mut state = self.state.lock();
            if state.failed {
                return false;
            }
            state.failed = true;
            core::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.resolve(Err(AcquireError::AssociationFailed));
        }
        true
    }

    fn release(&self, slot_mask: u32) {
        {
            let mut state = self.state.lock();
            let slot_mask = u64::from(slot_mask);
            assert_eq!(
                state.allocated_slots & slot_mask,
                slot_mask,
                "shared-buffer slot released without an active lease"
            );
            state.allocated_slots &= !slot_mask;
            if state.failed {
                return;
            }
        }

        loop {
            let resolved = {
                let mut state = self.state.lock();
                if state.failed {
                    return;
                }
                let Some(waiter) = state.waiters.front() else {
                    return;
                };
                let length = waiter.length;
                let slot_count = waiter.slot_count;
                let Some(sequence) = state.allocate(length, slot_count) else {
                    return;
                };
                let waiter = state
                    .waiters
                    .pop_front()
                    .expect("front shared-buffer waiter must remain queued");
                (waiter, sequence)
            };
            resolved.0.resolve(Ok(resolved.1));
        }
    }

    #[cfg(test)]
    fn waiter_count(&self) -> usize {
        self.state.lock().waiters.len()
    }
}

impl<Platform: RawSyncPrimitivesProvider> SlotWaiter<Platform> {
    fn new(length: u32, slot_count: u32) -> Self {
        Self {
            length,
            slot_count,
            result: Mutex::new(None),
            completion: Platform::RawMutex::INIT,
        }
    }

    fn resolve(&self, result: Result<SharedBufferSequence, AcquireError>) {
        let mut stored = self.result.lock();
        assert!(stored.is_none(), "shared-buffer waiter already resolved");
        *stored = Some(result);
        drop(stored);
        self.completion.underlying_atomic().fetch_add(1, Release);
        self.completion.wake_one();
    }

    fn wait(&self) -> Result<SharedBufferSequence, AcquireError> {
        loop {
            let mut result = self.result.lock();
            if let Some(result) = result.take() {
                return result;
            }
            let observed = self.completion.underlying_atomic().load(Acquire);
            drop(result);
            let _ = self.completion.block(observed);
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider> SlotLease<'_, Platform> {
    pub(super) fn descriptor(&self) -> SharedBufferDescriptor {
        let mut descriptors = self
            .sequence
            .descriptors(SHARED_BUFFER_LAYOUT)
            .expect("allocated shared-buffer sequence must be valid");
        let descriptor = descriptors
            .next()
            .expect("allocated shared-buffer sequence must contain one slot");
        assert!(
            descriptors.next().is_none(),
            "multi-slot lease cannot be used as one shared-buffer descriptor"
        );
        descriptor
    }

    pub(super) const fn sequence(&self) -> SharedBufferSequence {
        self.sequence
    }
}

impl<Platform: RawSyncPrimitivesProvider> Drop for SlotLease<'_, Platform> {
    fn drop(&mut self) {
        self.allocator.release(self.sequence.slot_mask);
    }
}

impl<Platform: RawSyncPrimitivesProvider> AllocatorState<Platform> {
    fn allocate(&mut self, length: u32, slot_count: u32) -> Option<SharedBufferSequence> {
        let mut available_slots = !self.allocated_slots & ALLOCATED_SLOT_MASK;
        if available_slots.count_ones() < slot_count {
            return None;
        }

        let mut slot_mask = 0_u32;
        let mut next_slot = self.next_slot;
        for _ in 0..slot_count {
            let slot_index = Self::next_free_slot(available_slots, next_slot)
                .expect("validated shared-buffer capacity must contain a free slot");
            available_slots &= !(1 << slot_index);
            slot_mask |= 1 << slot_index;
            next_slot = (slot_index + 1) % SHARED_BUFFER_SLOT_COUNT;
        }
        self.allocated_slots |= u64::from(slot_mask);
        self.next_slot = next_slot;
        Some(SharedBufferSequence { slot_mask, length })
    }

    fn next_free_slot(available_slots: u64, next_slot: u32) -> Option<u32> {
        if available_slots == 0 {
            return None;
        }
        let available_slots_after_next = available_slots & (u64::MAX << next_slot);
        Some(if available_slots_after_next == 0 {
            available_slots.trailing_zeros()
        } else {
            available_slots_after_next.trailing_zeros()
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use litebox_broker_protocol::shared_buffer::SharedBufferSlotIndex;
    use std::sync::mpsc;
    use std::time::Duration;

    use crate::platform::mock::MockPlatform;

    #[test]
    fn leases_use_distinct_slots_and_reuse_released_slots() {
        let allocator = SlotAllocator::<MockPlatform>::new();
        let mut leases = (0..SHARED_BUFFER_SLOT_COUNT)
            .map(|_| allocator.acquire(7).unwrap())
            .collect::<Vec<_>>();

        for (index, lease) in leases.iter().enumerate() {
            assert_eq!(lease.descriptor().slot_index.0 as usize, index);
            assert_eq!(lease.descriptor().length, 7);
        }

        drop(leases.remove(0));
        let reused = allocator.acquire(9).unwrap();
        assert_eq!(reused.descriptor().slot_index, SharedBufferSlotIndex(0));
    }

    #[test]
    fn oversized_acquisitions_do_not_fail_the_allocator() {
        let allocator = SlotAllocator::<MockPlatform>::new();

        assert!(matches!(
            allocator.acquire(SHARED_BUFFER_SLOT_COUNT * SHARED_BUFFER_SLOT_SIZE + 1),
            Err(AcquireError::TooLarge)
        ));
        assert!(allocator.acquire(1).is_ok());
    }

    #[test]
    fn sequence_leases_acquire_all_required_slots_atomically() {
        let allocator = Arc::new(SlotAllocator::<MockPlatform>::new());
        let mut leases = (0..9)
            .map(|_| allocator.acquire(1).unwrap())
            .collect::<Vec<_>>();
        let waiter_allocator = Arc::clone(&allocator);
        let (sender, receiver) = mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            let lease = waiter_allocator
                .acquire(8 * SHARED_BUFFER_SLOT_SIZE)
                .unwrap();
            sender.send(lease.sequence()).unwrap();
        });
        while allocator.waiter_count() == 0 {
            std::thread::yield_now();
        }

        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        drop(leases.remove(0));
        let sequence = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(sequence.slot_mask.count_ones(), 8);
        assert_eq!(sequence.length, 8 * SHARED_BUFFER_SLOT_SIZE);
        let retained_slot_mask = leases.iter().fold(0, |mask, lease| {
            mask | (1 << lease.descriptor().slot_index.0)
        });
        assert_eq!(sequence.slot_mask & retained_slot_mask, 0);
        waiter.join().unwrap();
    }

    #[test]
    fn exhausted_allocator_wakes_one_waiter_on_release() {
        let allocator = Arc::new(SlotAllocator::<MockPlatform>::new());
        let mut leases = (0..SHARED_BUFFER_SLOT_COUNT)
            .map(|_| allocator.acquire(1).unwrap())
            .collect::<Vec<_>>();
        let waiter_allocator = Arc::clone(&allocator);
        let (sender, receiver) = mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            let lease = waiter_allocator.acquire(1).unwrap();
            sender.send(lease.descriptor()).unwrap();
        });
        while allocator.waiter_count() == 0 {
            std::thread::yield_now();
        }
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        drop(leases.remove(0));
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            SharedBufferDescriptor {
                slot_index: SharedBufferSlotIndex(0),
                length: 1,
            }
        );
        waiter.join().unwrap();
    }

    #[test]
    fn exhausted_allocator_serves_waiters_in_arrival_order() {
        let allocator = Arc::new(SlotAllocator::<MockPlatform>::new());
        let mut leases = (0..SHARED_BUFFER_SLOT_COUNT)
            .map(|_| allocator.acquire(1).unwrap())
            .collect::<Vec<_>>();

        let first_allocator = Arc::clone(&allocator);
        let (first_acquired_sender, first_acquired_receiver) = mpsc::sync_channel(1);
        let (release_first_sender, release_first_receiver) = mpsc::sync_channel(1);
        let first = std::thread::spawn(move || {
            let lease = first_allocator.acquire(1).unwrap();
            first_acquired_sender.send(lease.descriptor()).unwrap();
            release_first_receiver.recv().unwrap();
        });
        while allocator.waiter_count() != 1 {
            std::thread::yield_now();
        }

        let second_allocator = Arc::clone(&allocator);
        let (second_acquired_sender, second_acquired_receiver) = mpsc::sync_channel(1);
        let second = std::thread::spawn(move || {
            let lease = second_allocator.acquire(1).unwrap();
            second_acquired_sender.send(lease.descriptor()).unwrap();
        });
        while allocator.waiter_count() != 2 {
            std::thread::yield_now();
        }

        drop(leases.remove(0));
        assert_eq!(
            first_acquired_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .slot_index,
            SharedBufferSlotIndex(0)
        );
        assert!(matches!(
            second_acquired_receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        release_first_sender.send(()).unwrap();
        assert_eq!(
            second_acquired_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .slot_index,
            SharedBufferSlotIndex(0)
        );
        first.join().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn association_failure_wakes_waiters_and_prevents_new_leases() {
        let allocator = Arc::new(SlotAllocator::<MockPlatform>::new());
        let _leases = (0..SHARED_BUFFER_SLOT_COUNT)
            .map(|_| allocator.acquire(1).unwrap())
            .collect::<Vec<_>>();
        let waiter_allocator = Arc::clone(&allocator);
        let (sender, receiver) = mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            sender.send(waiter_allocator.acquire(1).err()).unwrap();
        });
        while allocator.waiter_count() == 0 {
            std::thread::yield_now();
        }

        assert!(allocator.fail());
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            Some(AcquireError::AssociationFailed)
        );
        assert!(matches!(
            allocator.acquire(1),
            Err(AcquireError::AssociationFailed)
        ));
        waiter.join().unwrap();
    }
}
