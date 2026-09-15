// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{collections::VecDeque, sync::Arc};

use hashbrown::{HashMap, HashSet};
use litebox_broker_protocol::{MAX_ALLOCATED_TASK_ID, ProcessId};
use spin::Mutex;

use crate::{BrokerError, Result};

/// Broker-internal authority identity for one process generation.
///
/// The numeric process ID is guest-visible and reusable. This key is opaque to
/// providers so stale state cannot authorize or charge a later generation that
/// receives the same numeric ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessAuthorityKey {
    process_id: ProcessId,
    generation: u64,
}

impl ProcessAuthorityKey {
    pub(crate) const fn process_id(self) -> ProcessId {
        self.process_id
    }
}

pub(crate) struct ProcessIdLease {
    allocator: Arc<Mutex<ProcessIdAllocator>>,
    key: ProcessAuthorityKey,
    active: bool,
}

impl ProcessIdLease {
    pub(crate) const fn new(
        allocator: Arc<Mutex<ProcessIdAllocator>>,
        key: ProcessAuthorityKey,
    ) -> Self {
        Self {
            allocator,
            key,
            active: true,
        }
    }

    pub(crate) const fn key(&self) -> ProcessAuthorityKey {
        self.key
    }

    pub(crate) fn release(mut self, poison: bool) {
        self.allocator.lock().release(self.key, poison);
        self.active = false;
    }
}

impl Drop for ProcessIdLease {
    fn drop(&mut self) {
        if self.active {
            self.allocator.lock().release(self.key, true);
            self.active = false;
        }
    }
}

pub(crate) struct ProcessIdAllocator {
    next_fresh: u32,
    next_generation: u64,
    quarantine_capacity: usize,
    max_poisoned: usize,
    retired: VecDeque<ProcessId>,
    active: HashMap<ProcessId, u64>,
    poisoned: HashSet<ProcessId>,
    reuse_cursor: u32,
    has_untracked_retired: bool,
    failed: bool,
}

impl ProcessIdAllocator {
    pub(crate) fn new(quarantine_capacity: usize, max_poisoned: usize) -> Result<Self> {
        if quarantine_capacity == 0 {
            return Err(BrokerError::ResourceExhausted);
        }
        Ok(Self {
            next_fresh: 1,
            next_generation: 1,
            quarantine_capacity,
            max_poisoned,
            retired: VecDeque::new(),
            active: HashMap::new(),
            poisoned: HashSet::new(),
            reuse_cursor: 1,
            has_untracked_retired: false,
            failed: false,
        })
    }

    pub(crate) fn allocate(&mut self) -> Result<ProcessAuthorityKey> {
        if self.failed {
            return Err(BrokerError::ResourceExhausted);
        }
        self.active
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        let generation = self.next_generation;
        let next_generation = generation
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;

        let process_id = if self.next_fresh <= MAX_ALLOCATED_TASK_ID
            && self.retired.len() < self.quarantine_capacity
        {
            self.allocate_fresh()?
        } else if let Some(process_id) = self.allocate_untracked_retired() {
            process_id
        } else if let Some(process_id) = self.retired.pop_front() {
            process_id
        } else if self.next_fresh <= MAX_ALLOCATED_TASK_ID {
            self.allocate_fresh()?
        } else {
            return Err(BrokerError::ResourceExhausted);
        };

        self.next_generation = next_generation;
        if self.active.insert(process_id, generation).is_some() {
            self.failed = true;
            return Err(BrokerError::Internal);
        }
        Ok(ProcessAuthorityKey {
            process_id,
            generation,
        })
    }

    pub(crate) fn release(&mut self, key: ProcessAuthorityKey, poison: bool) {
        if self.active.get(&key.process_id) != Some(&key.generation) {
            self.failed = true;
            return;
        }
        self.active.remove(&key.process_id);

        if poison {
            if self.poisoned.contains(&key.process_id) {
                return;
            }
            if self.poisoned.len() >= self.max_poisoned {
                self.failed = true;
                return;
            }
            if self.poisoned.try_reserve(1).is_err() {
                self.failed = true;
                return;
            }
            self.poisoned.insert(key.process_id);
            return;
        }

        if self.retired.len() == self.quarantine_capacity
            && let Some(oldest) = self.retired.pop_front()
        {
            if !self.has_untracked_retired {
                self.reuse_cursor = oldest.get();
            }
            self.has_untracked_retired = true;
        }
        if self.retired.try_reserve(1).is_err() {
            self.failed = true;
            return;
        }
        self.retired.push_back(key.process_id);
    }

    fn allocate_fresh(&mut self) -> Result<ProcessId> {
        let process_id = ProcessId::new(self.next_fresh).ok_or(BrokerError::ResourceExhausted)?;
        self.next_fresh = self
            .next_fresh
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(process_id)
    }

    fn allocate_untracked_retired(&mut self) -> Option<ProcessId> {
        if !self.has_untracked_retired || self.next_fresh <= 1 {
            return None;
        }

        let first = self.reuse_cursor;
        let mut candidate = first;
        loop {
            let process_id = ProcessId::new(candidate)?;
            if !self.active.contains_key(&process_id)
                && !self.poisoned.contains(&process_id)
                && !self.retired.contains(&process_id)
            {
                self.reuse_cursor = if candidate + 1 < self.next_fresh {
                    candidate + 1
                } else {
                    1
                };
                return Some(process_id);
            }
            candidate = if candidate + 1 < self.next_fresh {
                candidate + 1
            } else {
                1
            };
            if candidate == first {
                self.has_untracked_retired = false;
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use spin::Mutex;

    use super::{ProcessIdAllocator, ProcessIdLease};
    use crate::BrokerError;

    #[test]
    fn allocator_quarantines_then_reuses_oldest_identity() {
        let mut allocator = ProcessIdAllocator::new(2, 1).unwrap();
        let first = allocator.allocate().unwrap();
        let second = allocator.allocate().unwrap();
        allocator.release(first, false);
        let third = allocator.allocate().unwrap();
        assert_ne!(third.process_id, first.process_id);
        allocator.release(second, false);
        allocator.release(third, false);

        let reused = allocator.allocate().unwrap();
        assert_eq!(reused.process_id, first.process_id);
        assert_ne!(reused.generation, first.generation);
    }

    #[test]
    fn poisoned_identity_is_never_reused() {
        let mut allocator = ProcessIdAllocator::new(1, 1).unwrap();
        let poisoned = allocator.allocate().unwrap();
        allocator.release(poisoned, true);
        let next = allocator.allocate().unwrap();
        assert_ne!(next.process_id, poisoned.process_id);
    }

    #[test]
    fn poisoned_identity_fault_bound_fails_closed() {
        let mut allocator = ProcessIdAllocator::new(1, 0).unwrap();
        let poisoned = allocator.allocate().unwrap();
        allocator.release(poisoned, true);
        assert_eq!(allocator.allocate(), Err(BrokerError::ResourceExhausted));
    }

    #[test]
    fn dropped_lease_poisons_identity() {
        let allocator = Arc::new(Mutex::new(ProcessIdAllocator::new(1, 1).unwrap()));
        let key = allocator.lock().allocate().unwrap();
        drop(ProcessIdLease::new(Arc::clone(&allocator), key));

        let replacement = allocator.lock().allocate().unwrap();
        assert_ne!(replacement.process_id, key.process_id);
    }
}
