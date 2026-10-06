// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared broker process and thread ID allocation.

use hashbrown::HashMap;

use crate::{BrokerError, Result};

/// Highest numeric process or thread identity allocated by the broker.
///
/// Linux reserves the next value, `0x3fff_ffff`, as its futex TID mask.
/// uLiteBox uses that reserved value for the synthetic Windows CSR server
/// identity and never allocates it to a guest process or thread.
pub(crate) const MAX_ALLOCATED_ID: u32 = 0x3fff_fffe;

pub(crate) struct IdAllocator {
    next: u32,
    max_id: u32,
    /// The number of users of each allocated ID, which is reused only once
    /// it has none.
    occupied: HashMap<u32, usize>,
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
            occupied: HashMap::new(),
            failed: false,
        })
    }

    /// Allocates an unused ID with one user.
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
            if !self.occupied.contains_key(&candidate) {
                self.occupied.insert(candidate, 1);
                return Ok(candidate);
            }
            if self.next == first {
                return Err(BrokerError::ResourceExhausted);
            }
        }
    }

    /// Adds a user of the allocated ID `id`.
    pub(crate) fn retain(&mut self, id: u32) {
        match self.occupied.get_mut(&id) {
            Some(users) => *users += 1,
            None => self.failed = true,
        }
    }

    /// Removes a user of `id`, which becomes free for reuse once it has none.
    pub(crate) fn release(&mut self, id: u32) {
        let Some(users) = self.occupied.get_mut(&id) else {
            self.failed = true;
            return;
        };
        *users -= 1;
        if *users == 0 {
            self.occupied.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IdAllocator, MAX_ALLOCATED_ID};
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
    fn allocator_reuses_an_id_only_after_its_last_user_releases_it() {
        let mut allocator = IdAllocator::new(2).unwrap();
        let shared = allocator.allocate().unwrap();
        allocator.retain(shared);
        allocator.release(shared);
        let other = allocator.allocate().unwrap();
        assert_eq!(allocator.allocate(), Err(BrokerError::ResourceExhausted));

        allocator.release(shared);

        assert_eq!(allocator.allocate().unwrap(), shared);
        assert_ne!(shared, other);
    }

    #[test]
    fn allocator_rejects_ids_outside_the_guest_range() {
        assert!(matches!(
            IdAllocator::new(0),
            Err(BrokerError::ResourceExhausted)
        ));
        assert!(matches!(
            IdAllocator::new(MAX_ALLOCATED_ID + 1),
            Err(BrokerError::ResourceExhausted)
        ));
    }
}
