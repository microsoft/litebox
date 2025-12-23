// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Handling the allocation of local ports

use core::num::{NonZeroU16, NonZeroU64};

use hashbrown::HashMap;
use thiserror::Error;

use crate::utils::rng::FastRng;

/// An allocator for local ports, making sure that no already-allocated ports are given out either
/// in case of ephemeral port allocation, or in the case of asking for a specific port.
pub(crate) struct LocalPortAllocator {
    // map from port number -> reference count
    //
    // using a non-zero u16 for the reference count is a memory optimization; if this is ever an
    // issue, it can trivially be bumped up to a larger size.
    refcount: HashMap<NonZeroU16, NonZeroU16>,
    rng: FastRng,
}

impl Default for LocalPortAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalPortAllocator {
    /// Sets up a new local port allocator
    pub(crate) fn new() -> Self {
        Self {
            refcount: HashMap::new(),
            rng: FastRng::new_from_seed(NonZeroU64::new(0x13374a4159421337).unwrap()),
        }
    }

    /// Allocate a new ephemeral local port (i.e., port in the range 49152 and 65535)
    pub(crate) fn ephemeral_port(&mut self) -> Result<LocalPort, LocalPortAllocationError> {
        for _ in 0..100 {
            let port =
                NonZeroU16::new(u16::try_from(self.rng.next_in_range_u32(49152..65536)).unwrap())
                    .unwrap();
            if let Ok(local_port) = self.specific_port(port) {
                return Ok(local_port);
            }
        }
        // If we haven't yet found a port after 100 tries, it is highly likely lots of ports are
        // already in use, so we should start looking over them one by one
        for port in 49152..=65535 {
            let port = NonZeroU16::new(port).unwrap();
            if let Ok(local_port) = self.specific_port(port) {
                return Ok(local_port);
            }
        }
        // If we _still_ haven't found any, then we have run out of ports to give out
        Err(LocalPortAllocationError::NoAvailableFreePorts)
    }

    /// Allocate a specific local port, if available
    pub(crate) fn specific_port(
        &mut self,
        port: NonZeroU16,
    ) -> Result<LocalPort, LocalPortAllocationError> {
        if self.refcount.contains_key(&port) {
            Err(LocalPortAllocationError::AlreadyInUse(port.get()))
        } else {
            self.refcount.insert(port, NonZeroU16::new(1).unwrap());
            Ok(LocalPort { port })
        }
    }

    /// Allocate a local port, either ephemeral (if `port` is 0) or specific (if `port` is non-zero)
    pub(crate) fn allocate_local_port(
        &mut self,
        port: u16,
    ) -> Result<LocalPort, LocalPortAllocationError> {
        let Some(port) = NonZeroU16::new(port) else {
            return self.ephemeral_port();
        };
        self.specific_port(port)
    }

    /// Increments the ref-count for a local port, producing a new [`LocalPort`] token to be used
    #[must_use]
    pub(crate) fn allocate_same_local_port(&mut self, port: &LocalPort) -> LocalPort {
        let Some(refcount) = self.refcount.get_mut(&port.port) else {
            // Because we have a `LocalPort`, it is (as an invariant) impossible to have the value
            // be missing from the refcount.
            unreachable!()
        };
        // We just bump the refcount, making sure there is no overflow, and then produce the new
        // `LocalPort` token.
        *refcount = refcount.checked_add(1).unwrap();
        LocalPort { port: port.port }
    }

    /// Consumes a [`LocalPort`], possibly marking it as available again.
    pub(crate) fn deallocate(&mut self, port: LocalPort) {
        let Some(refcount) = self.refcount.get_mut(&port.port) else {
            // Because we have a `LocalPort`, it is (as an invariant) impossible to have the value
            // be missing from the refcount.
            unreachable!()
        };
        match refcount.get() {
            0 => unreachable!(),
            1 => {
                // Need to drop
                self.refcount.remove(&port.port);
            }
            _ => {
                *refcount = NonZeroU16::new(refcount.get() - 1).unwrap();
            }
        }
    }
}

/// A token expressing ownership over a specific local port.
///
/// Explicitly not cloneable/copyable.
pub(crate) struct LocalPort {
    port: NonZeroU16,
}

impl LocalPort {
    pub(crate) fn port(&self) -> u16 {
        self.port.get()
    }
}

/// Errors that could be returned when allocating a port
#[derive(Debug, Error)]
pub enum LocalPortAllocationError {
    #[error("Port {0} is already in use")]
    AlreadyInUse(u16),
    #[error("No free ports are available")]
    NoAvailableFreePorts,
}
