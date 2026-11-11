// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The IDs of one process or thread, one in each PID namespace that sees it.
//!
//! A process or thread has an ID in its own PID namespace and in every
//! namespace above it, and is visible only from those. Process groups and
//! sessions use their leaders' IDs.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{PidNamespace, Result};

/// The IDs of one process or thread, one per PID namespace, from its own
/// namespace up to the top-level one.
///
/// It also identifies the process or thread: compare it by identity
/// ([`Arc::ptr_eq`]), never by ID.
pub(crate) struct PerNamespaceIds {
    /// Each namespace and the ID allocated in it, own namespace first.
    levels: Box<[(Arc<PidNamespace>, u32)]>,
}

impl PerNamespaceIds {
    /// Allocates an ID in `pid_namespace` and in each namespace above it.
    ///
    /// IDs are allocated from the top-level namespace down, so a failure
    /// consumes no ID in `pid_namespace` itself; IDs already allocated are
    /// released.
    pub(crate) fn allocate(pid_namespace: &Arc<PidNamespace>) -> Result<Arc<Self>> {
        let chain = pid_namespace.chain();
        let mut levels = Vec::new();
        levels
            .try_reserve_exact(chain.len())
            .map_err(|_| crate::BrokerError::OutOfMemory)?;
        for namespace in chain.iter().rev() {
            match namespace.id_allocator.lock().allocate() {
                Ok(id) => levels.push((Arc::clone(namespace), id)),
                Err(error) => {
                    for (namespace, id) in &levels {
                        namespace.id_allocator.lock().release(*id);
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

    /// Returns the ID in its own namespace.
    pub(crate) fn own_id(&self) -> u32 {
        self.levels[0].1
    }

    /// Returns its own namespace, the innermost one it has an ID in.
    pub(crate) fn namespace(&self) -> &Arc<PidNamespace> {
        &self.levels[0].0
    }

    /// Returns the ID in `pid_namespace`, or `None` if that namespace doesn't
    /// see the process or thread these IDs belong to.
    pub(crate) fn id_in_namespace(&self, pid_namespace: &PidNamespace) -> Option<u32> {
        let own_level = self.namespace().level();
        let index = own_level.checked_sub(pid_namespace.level())?;
        let (namespace, id) = self.levels.get(usize::try_from(index).ok()?)?;
        core::ptr::eq(Arc::as_ptr(namespace), pid_namespace).then_some(*id)
    }

    /// Each namespace and the ID in it, own namespace first.
    pub(crate) fn levels(&self) -> impl DoubleEndedIterator<Item = (&Arc<PidNamespace>, u32)> {
        self.levels.iter().map(|(namespace, id)| (namespace, *id))
    }

    /// Adds a user of every ID, so none is reused until a matching
    /// [`Self::release`].
    pub(crate) fn retain(&self) {
        for (namespace, id) in self.levels() {
            namespace.id_allocator.lock().retain(id);
        }
    }

    /// Removes a user of every ID; each becomes free for reuse once it has
    /// none.
    pub(crate) fn release(&self) {
        for (namespace, id) in self.levels() {
            namespace.id_allocator.lock().release(id);
        }
    }
}
