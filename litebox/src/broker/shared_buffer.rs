// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering::{Acquire, Release};

use litebox_broker_protocol::shared_buffer::{
    MAX_SHARED_BUFFER_SEQUENCE_SLOTS, SHARED_BUFFER_SLOT_COUNT, SHARED_BUFFER_SLOT_SIZE,
    SharedBufferSequence, SharedBufferSlotIndex,
};
use litebox_platform::sync::RawMutex as _;

use crate::sync::{Mutex, RawSyncPrimitivesProvider};

pub(super) struct SlotAllocator<Platform: RawSyncPrimitivesProvider> {
    state: Mutex<Platform, AllocatorState<Platform>>,
}

struct AllocatorState<Platform: RawSyncPrimitivesProvider> {
    allocated_slots: Vec<bool>,
    next_slot: usize,
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
    slot_count: usize,
    result: Mutex<Platform, Option<Result<SharedBufferSequence, AcquireError>>>,
    completion: Platform::RawMutex,
}

impl<Platform: RawSyncPrimitivesProvider> SlotAllocator<Platform> {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(AllocatorState {
                allocated_slots: vec![false; SHARED_BUFFER_SLOT_COUNT as usize],
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
        } as usize;
        if slot_count > MAX_SHARED_BUFFER_SEQUENCE_SLOTS {
            return Err(AcquireError::TooLarge);
        }
        self.acquire_count(length, slot_count)
    }

    fn acquire_count(
        &self,
        length: u32,
        slot_count: usize,
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

    fn release(&self, sequence: SharedBufferSequence) {
        {
            let mut state = self.state.lock();
            for slot_index in sequence.slot_indices() {
                let slot_index = slot_index.0 as usize;
                let allocated = state
                    .allocated_slots
                    .get_mut(slot_index)
                    .expect("leased shared-buffer slot must exist");
                assert!(
                    *allocated,
                    "shared-buffer slot released without an active lease"
                );
                *allocated = false;
            }
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
    fn new(length: u32, slot_count: usize) -> Self {
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
    pub(super) const fn sequence(&self) -> SharedBufferSequence {
        self.sequence
    }
}

impl<Platform: RawSyncPrimitivesProvider> Drop for SlotLease<'_, Platform> {
    fn drop(&mut self) {
        self.allocator.release(self.sequence);
    }
}

impl<Platform: RawSyncPrimitivesProvider> AllocatorState<Platform> {
    fn allocate(&mut self, length: u32, slot_count: usize) -> Option<SharedBufferSequence> {
        if self
            .allocated_slots
            .iter()
            .filter(|allocated| !**allocated)
            .count()
            < slot_count
        {
            return None;
        }

        let mut slot_indices = [SharedBufferSlotIndex::default(); MAX_SHARED_BUFFER_SEQUENCE_SLOTS];
        let mut next_slot = self.next_slot;
        for stored_slot in &mut slot_indices[..slot_count] {
            let slot_index = self
                .next_free_slot(next_slot)
                .expect("validated shared-buffer capacity must contain a free slot");
            self.allocated_slots[slot_index] = true;
            *stored_slot = SharedBufferSlotIndex(
                u32::try_from(slot_index).expect("shared-buffer slot index must fit in u32"),
            );
            next_slot = (slot_index + 1) % self.allocated_slots.len();
        }
        self.next_slot = next_slot;
        Some(
            SharedBufferSequence::new(&slot_indices[..slot_count], length)
                .expect("allocated shared-buffer sequence must be valid"),
        )
    }

    fn next_free_slot(&self, next_slot: usize) -> Option<usize> {
        (0..self.allocated_slots.len())
            .map(|offset| (next_slot + offset) % self.allocated_slots.len())
            .find(|slot_index| !self.allocated_slots[*slot_index])
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::sync::Arc;
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
            assert_eq!(lease.sequence().slot_indices()[0].0 as usize, index);
            assert_eq!(lease.sequence().length(), 7);
        }

        drop(leases.remove(0));
        let reused = allocator.acquire(9).unwrap();
        assert_eq!(
            reused.sequence().slot_indices(),
            &[SharedBufferSlotIndex(0)]
        );
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
    fn allocator_state_supports_slots_beyond_bitmap_widths() {
        let mut state = AllocatorState::<MockPlatform> {
            allocated_slots: alloc::vec![true; 65],
            next_slot: 64,
            failed: false,
            waiters: VecDeque::new(),
        };
        state.allocated_slots[64] = false;

        let sequence = state.allocate(1, 1).unwrap();
        assert_eq!(sequence.slot_indices(), &[SharedBufferSlotIndex(64)]);
    }

    #[test]
    fn sequence_leases_acquire_all_required_slots_atomically() {
        let allocator = Arc::new(SlotAllocator::<MockPlatform>::new());
        let mut leases = (0..(SHARED_BUFFER_SLOT_COUNT - 7))
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
        assert_eq!(sequence.slot_indices().len(), 8);
        assert_eq!(sequence.length(), 8 * SHARED_BUFFER_SLOT_SIZE);
        assert!(sequence.slot_indices().iter().all(|slot_index| {
            leases
                .iter()
                .all(|lease| !lease.sequence().slot_indices().contains(slot_index))
        }));
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
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            SharedBufferSequence::new(&[SharedBufferSlotIndex(0)], 1).unwrap()
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
            first_acquired_sender.send(lease.sequence()).unwrap();
            release_first_receiver.recv().unwrap();
        });
        while allocator.waiter_count() != 1 {
            std::thread::yield_now();
        }

        let second_allocator = Arc::clone(&allocator);
        let (second_acquired_sender, second_acquired_receiver) = mpsc::sync_channel(1);
        let second = std::thread::spawn(move || {
            let lease = second_allocator.acquire(1).unwrap();
            second_acquired_sender.send(lease.sequence()).unwrap();
        });
        while allocator.waiter_count() != 2 {
            std::thread::yield_now();
        }

        drop(leases.remove(0));
        assert_eq!(
            first_acquired_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .slot_indices(),
            &[SharedBufferSlotIndex(0)]
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
                .slot_indices(),
            &[SharedBufferSlotIndex(0)]
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
