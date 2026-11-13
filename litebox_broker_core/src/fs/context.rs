// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File-system contexts: the mount namespace, root and working directory that a process's paths
//! resolve in.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use spin::Mutex;

use super::mount::{HeldLocation, Location, MountNamespace};
use crate::{BrokerCore, BrokerError, Result};

/// The mount namespace, root and working directory that a process's paths resolve in, which all
/// of its threads share.
///
/// Every context is registered in its core, so operations that move roots and working
/// directories (pivot) can find all of them, whatever namespace they are in.
pub(crate) struct FsContext {
    state: Mutex<FsContextState>,
}

struct FsContextState {
    namespace: Arc<MountNamespace>,
    /// Where absolute paths start, which `..` never climbs above.
    root: HeldLocation,
    /// Where relative paths start.
    cwd: HeldLocation,
}

/// What a context holds, taken at once, for a path request to resolve in without holding its
/// lock.
pub(crate) struct FsContextSnapshot {
    pub(crate) namespace: Arc<MountNamespace>,
    pub(crate) root: Location,
    pub(crate) cwd: Location,
}

impl FsContext {
    /// A context, registered in `core`, whose root and working directory are the root of
    /// `namespace`.
    pub(crate) fn new(core: &BrokerCore, namespace: Arc<MountNamespace>) -> Result<Arc<Self>> {
        let root = namespace.root();
        Self::register(
            core,
            FsContextState {
                namespace,
                root: HeldLocation::new(root.clone()),
                cwd: HeldLocation::new(root),
            },
        )
    }

    /// A copy of this context, registered in `core`, for a new child process.
    pub(crate) fn copy(&self, core: &BrokerCore) -> Result<Arc<Self>> {
        let state = {
            let state = self.state.lock();
            FsContextState {
                namespace: Arc::clone(&state.namespace),
                root: state.root.clone(),
                cwd: state.cwd.clone(),
            }
        };
        Self::register(core, state)
    }

    fn register(core: &BrokerCore, state: FsContextState) -> Result<Arc<Self>> {
        let context = Arc::new(Self {
            state: Mutex::new(state),
        });
        let mut contexts = core.fs_contexts.lock();
        // Contexts that ended are pruned when the registry would grow.
        if contexts.len() == contexts.capacity() {
            contexts.retain(|context| context.strong_count() != 0);
        }
        contexts
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        contexts.push(Arc::downgrade(&context));
        drop(contexts);
        Ok(context)
    }

    /// The namespace, root and working directory, as of now.
    pub(crate) fn snapshot(&self) -> FsContextSnapshot {
        let state = self.state.lock();
        FsContextSnapshot {
            namespace: Arc::clone(&state.namespace),
            root: Location::clone(&state.root),
            cwd: Location::clone(&state.cwd),
        }
    }

    /// Make `cwd` the working directory.
    #[cfg_attr(not(test), expect(dead_code, reason = "changing directory uses it"))]
    pub(crate) fn set_cwd(&self, cwd: Location) {
        let cwd = HeldLocation::new(cwd);
        let replaced = core::mem::replace(&mut self.state.lock().cwd, cwd);
        // Dropping a location can reach the backend.
        drop(replaced);
    }
}

/// The registry of every context in a core, which holds them weakly; contexts that ended are
/// pruned lazily.
pub(crate) type FsContexts = Mutex<Vec<Weak<FsContext>>>;
