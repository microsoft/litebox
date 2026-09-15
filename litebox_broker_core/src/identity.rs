// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use hashbrown::HashSet;
use litebox_broker_protocol::MAX_ALLOCATED_ID;
use spin::Mutex;

use crate::{BrokerError, Result};

pub(crate) struct IdReservation {
    allocator: Arc<Mutex<IdAllocator>>,
    id: u32,
}

impl IdReservation {
    pub(crate) const fn new(allocator: Arc<Mutex<IdAllocator>>, id: u32) -> Self {
        Self { allocator, id }
    }

    pub(crate) const fn id(&self) -> u32 {
        self.id
    }

    pub(crate) fn release(self) {
        self.allocator.lock().release(self.id);
    }
}

pub(crate) struct IdAllocator {
    next: u32,
    max_id: u32,
    occupied: HashSet<u32>,
    failed: bool,
}

impl IdAllocator {
    pub(crate) fn new(max_id: u32) -> Result<Self> {
        if max_id == 0 || max_id > MAX_ALLOCATED_ID {
            return Err(BrokerError::ResourceExhausted);
        }
        Ok(Self {
            next: 1,
            max_id,
            occupied: HashSet::new(),
            failed: false,
        })
    }

    pub(crate) fn allocate(&mut self) -> Result<u32> {
        if self.failed || self.occupied.len() >= self.max_id as usize {
            return Err(BrokerError::ResourceExhausted);
        }
        self.occupied
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;

        let first = self.next;
        loop {
            let candidate = self.next;
            self.next = if candidate == self.max_id {
                1
            } else {
                candidate + 1
            };
            if self.occupied.insert(candidate) {
                return Ok(candidate);
            }
            if self.next == first {
                return Err(BrokerError::ResourceExhausted);
            }
        }
    }

    fn release(&mut self, id: u32) {
        if !self.occupied.remove(&id) {
            self.failed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use spin::Mutex;

    use super::{IdAllocator, IdReservation};
    use crate::BrokerError;

    #[test]
    fn allocator_rotates_and_reuses_released_ids() {
        let mut allocator = IdAllocator::new(2).unwrap();
        let first = allocator.allocate().unwrap();
        let second = allocator.allocate().unwrap();
        assert_eq!(allocator.allocate(), Err(BrokerError::ResourceExhausted));

        allocator.release(first);

        assert_eq!(allocator.allocate().unwrap(), first);
        assert_ne!(first, second);
    }

    #[test]
    fn dropped_reservation_remains_occupied() {
        let allocator = Arc::new(Mutex::new(IdAllocator::new(1).unwrap()));
        let id = allocator.lock().allocate().unwrap();
        drop(IdReservation::new(Arc::clone(&allocator), id));

        assert_eq!(
            allocator.lock().allocate(),
            Err(BrokerError::ResourceExhausted)
        );
    }
}
