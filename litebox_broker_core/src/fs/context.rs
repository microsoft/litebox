// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File-system contexts: the mount namespace, root and working directory that a thread's paths
//! resolve in.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use spin::Mutex;

use super::mount::{HeldLocation, Location, MountNamespace};
use crate::{BrokerCore, BrokerError, BrokerProcess, Result};

/// The mount namespace, root and working directory that paths resolve in, which threads share as
/// Linux's `CLONE_FS` threads share their `fs_struct`.
///
/// Every context is registered in its core, so operations that move roots and working
/// directories (pivot) can find all of them, whatever namespace they are in.
pub(crate) struct FsContext {
    state: Mutex<FsContextState>,
    /// How many threads use this context: it is shared if more than one does.
    threads: AtomicUsize,
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

    /// A copy of this context, registered in `core`, used by no thread yet, as a new process gets
    /// (Linux's fork copies `fs_struct`).
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

    /// A copy of this context, registered in `core`, used by no thread yet, in a copy of its
    /// mount namespace, with its root and working directory moved onto the copies of their
    /// mounts, as Linux's `CLONE_NEWNS` gives.
    ///
    /// The namespace and its mounts are charged to `process`.
    pub(crate) fn copy_with_namespace(&self, process: &BrokerProcess) -> Result<Arc<Self>> {
        let snapshot = self.snapshot();
        let (namespace, copies) = snapshot.namespace.copy(process)?;
        let state = FsContextState {
            namespace,
            root: HeldLocation::new(copies.moved(&snapshot.root)),
            cwd: HeldLocation::new(copies.moved(&snapshot.cwd)),
        };
        Self::register(&process.core, state)
    }

    fn register(core: &BrokerCore, state: FsContextState) -> Result<Arc<Self>> {
        let context = Arc::new(Self {
            state: Mutex::new(state),
            threads: AtomicUsize::new(0),
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
    pub(crate) fn set_cwd(&self, cwd: Location) {
        let cwd = HeldLocation::new(cwd);
        let replaced = core::mem::replace(&mut self.state.lock().cwd, cwd);
        // Dropping a location can reach the backend.
        drop(replaced);
    }

    /// Make `root` the root, where absolute paths start and above which `..` doesn't climb.
    pub(crate) fn set_root(&self, root: Location) {
        let root = HeldLocation::new(root);
        let replaced = core::mem::replace(&mut self.state.lock().root, root);
        drop(replaced);
    }

    /// Move the root and the working directory to `to` where they are at `from`, returning what
    /// they replace, for the caller to drop outside its locks.
    pub(crate) fn move_from(&self, from: &Location, to: &Location) -> Vec<HeldLocation> {
        let mut replaced = Vec::new();
        let mut state = self.state.lock();
        let FsContextState { root, cwd, .. } = &mut *state;
        for held in [root, cwd] {
            if held.is_at(from) {
                replaced.push(core::mem::replace(held, HeldLocation::new(to.clone())));
            }
        }
        replaced
    }

    /// Count one more thread using this context.
    pub(crate) fn enter(&self) {
        self.threads.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one thread fewer using this context.
    pub(crate) fn leave(&self) {
        self.threads.fetch_sub(1, Ordering::Relaxed);
    }

    /// How many threads use this context: it is shared if more than one does.
    pub(crate) fn threads(&self) -> usize {
        self.threads.load(Ordering::Relaxed)
    }
}

/// The registry of every context in a core, which holds them weakly; contexts that ended are
/// pruned lazily.
pub(crate) type FsContexts = Mutex<Vec<Weak<FsContext>>>;
