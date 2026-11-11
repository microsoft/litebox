// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The IDs of one process or thread, one in each PID namespace that sees it.
//!
//! A process or thread is numbered in its own PID namespace and in every
//! namespace above it, and is visible only from those. Process groups and
//! sessions use their leaders' numbers.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{PidNamespace, Result};

/// The numbers of one process or thread: one per namespace, from its own
/// namespace up to the top-level one.
pub(crate) struct PidNumbers {
    /// Each namespace and the number allocated in it, own namespace first.
    levels: Box<[(Arc<PidNamespace>, u32)]>,
}

impl PidNumbers {
    /// Allocates a number in `pid_namespace` and in each namespace above it.
    ///
    /// Numbers are allocated from the top-level namespace down, so a failure
    /// consumes no number in `pid_namespace` itself; numbers already allocated
    /// are released.
    pub(crate) fn allocate(pid_namespace: &Arc<PidNamespace>) -> Result<Arc<Self>> {
        let chain = pid_namespace.chain();
        let mut levels = Vec::new();
        levels
            .try_reserve_exact(chain.len())
            .map_err(|_| crate::BrokerError::OutOfMemory)?;
        for namespace in chain.iter().rev() {
            match namespace.ids.lock().allocate() {
                Ok(number) => levels.push((Arc::clone(namespace), number)),
                Err(error) => {
                    for (namespace, number) in &levels {
                        namespace.ids.lock().release(*number);
                    }
                    return Err(error);
                }
            }
        }
        levels.reverse();
        Ok(Arc::new(Self {
            levels: levels.into_boxed_slice(),
        }))
    }

    /// Returns the number in the owning namespace.
    pub(crate) fn own(&self) -> u32 {
        self.levels[0].1
    }

    /// Returns the owning namespace.
    pub(crate) fn namespace(&self) -> &Arc<PidNamespace> {
        &self.levels[0].0
    }

    /// Returns the number in `pid_namespace`, or `None` if it doesn't see
    /// these numbers' owner.
    pub(crate) fn pid_number_in_namespace(&self, pid_namespace: &PidNamespace) -> Option<u32> {
        let own_level = self.namespace().level();
        let index = own_level.checked_sub(pid_namespace.level())?;
        let (namespace, number) = self.levels.get(usize::try_from(index).ok()?)?;
        core::ptr::eq(Arc::as_ptr(namespace), pid_namespace).then_some(*number)
    }

    /// Each namespace and the number in it, own namespace first.
    pub(crate) fn levels(&self) -> impl DoubleEndedIterator<Item = (&Arc<PidNamespace>, u32)> {
        self.levels
            .iter()
            .map(|(namespace, number)| (namespace, *number))
    }

    /// Adds a user of every number, so none is reused until a matching
    /// [`Self::release`].
    pub(crate) fn retain(&self) {
        for (namespace, number) in self.levels() {
            namespace.ids.lock().retain(number);
        }
    }

    /// Removes a user of every number; each becomes free for reuse once it has
    /// none.
    pub(crate) fn release(&self) {
        for (namespace, number) in self.levels() {
            namespace.ids.lock().release(number);
        }
    }
}
