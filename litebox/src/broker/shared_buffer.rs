// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::Ordering::{Acquire, Release};

use litebox_broker_protocol::shared_buffer::{
    SHARED_BUFFER_SLOT_COUNT, SharedBufferDescriptor, SharedBufferSlotIndex,
};

use crate::platform::RawMutex as _;
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
pub(super) struct AcquireError;

pub(super) struct SlotLease<'a, Platform: RawSyncPrimitivesProvider> {
    allocator: &'a SlotAllocator<Platform>,
    descriptor: SharedBufferDescriptor,
}

struct SlotWaiter<Platform: RawSyncPrimitivesProvider> {
    length: u32,
    result: Mutex<Platform, Option<Result<SharedBufferDescriptor, AcquireError>>>,
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
        {
            let mut state = self.state.lock();
            if state.failed {
                return Err(AcquireError);
            }
            if state.waiters.is_empty()
                && let Some(descriptor) = state.allocate(length)
            {
                return Ok(SlotLease {
                    allocator: self,
                    descriptor,
                });
            }
        }

        let waiter = Arc::new(SlotWaiter::new(length));
        {
            let mut state = self.state.lock();
            if state.failed {
                return Err(AcquireError);
            }
            if state.waiters.is_empty()
                && let Some(descriptor) = state.allocate(length)
            {
                return Ok(SlotLease {
                    allocator: self,
                    descriptor,
                });
            }
            state.waiters.push_back(Arc::clone(&waiter));
        }

        let descriptor = waiter.wait()?;
        Ok(SlotLease {
            allocator: self,
            descriptor,
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
            waiter.resolve(Err(AcquireError));
        }
        true
    }

    fn release(&self, slot_index: SharedBufferSlotIndex) {
        let mut state = self.state.lock();
        let slot_mask = 1 << slot_index.0;
        assert_ne!(
            state.allocated_slots & slot_mask,
            0,
            "shared-buffer slot released without an active lease"
        );
        state.allocated_slots &= !slot_mask;
        if state.failed {
            return;
        }
        let Some(waiter) = state.waiters.pop_front() else {
            return;
        };
        let descriptor = state
            .allocate(waiter.length)
            .expect("released slot was not available");
        drop(state);
        waiter.resolve(Ok(descriptor));
    }

    #[cfg(test)]
    fn waiter_count(&self) -> usize {
        self.state.lock().waiters.len()
    }
}

impl<Platform: RawSyncPrimitivesProvider> SlotWaiter<Platform> {
    fn new(length: u32) -> Self {
        Self {
            length,
            result: Mutex::new(None),
            completion: Platform::RawMutex::INIT,
        }
    }

    fn resolve(&self, result: Result<SharedBufferDescriptor, AcquireError>) {
        let mut stored = self.result.lock();
        assert!(stored.is_none(), "shared-buffer waiter already resolved");
        *stored = Some(result);
        drop(stored);
        self.completion.underlying_atomic().fetch_add(1, Release);
        self.completion.wake_one();
    }

    fn wait(&self) -> Result<SharedBufferDescriptor, AcquireError> {
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
    pub(super) const fn descriptor(&self) -> SharedBufferDescriptor {
        self.descriptor
    }
}

impl<Platform: RawSyncPrimitivesProvider> Drop for SlotLease<'_, Platform> {
    fn drop(&mut self) {
        self.allocator.release(self.descriptor.slot_index);
    }
}

impl<Platform: RawSyncPrimitivesProvider> AllocatorState<Platform> {
    fn allocate(&mut self, length: u32) -> Option<SharedBufferDescriptor> {
        let slot_index = self.next_free_slot()?;
        self.allocated_slots |= 1 << slot_index;
        self.next_slot = (slot_index + 1) % SHARED_BUFFER_SLOT_COUNT;
        Some(SharedBufferDescriptor {
            slot_index: SharedBufferSlotIndex(slot_index),
            length,
        })
    }

    fn next_free_slot(&self) -> Option<u32> {
        let available_slots = !self.allocated_slots & ALLOCATED_SLOT_MASK;
        if available_slots == 0 {
            return None;
        }
        let available_slots_after_next = available_slots & (u64::MAX << self.next_slot);
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
            sender.send(waiter_allocator.acquire(1).is_err()).unwrap();
        });
        while allocator.waiter_count() == 0 {
            std::thread::yield_now();
        }

        assert!(allocator.fail());
        assert!(receiver.recv_timeout(Duration::from_secs(1)).unwrap());
        assert!(allocator.acquire(1).is_err());
        waiter.join().unwrap();
    }
}
