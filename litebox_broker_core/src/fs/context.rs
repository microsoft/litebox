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
        // The root is read and the context registered under the namespace's `mutation` lock, then
        // the registry's: a pivot moves the registered contexts and then publishes its tree, both
        // under `mutation`, so the context either starts at the new root or is moved there.
        let (context, registered) = namespace.under_mutation(|| {
            let root = namespace.root();
            let context = Self::unregistered(FsContextState {
                namespace: Arc::clone(&namespace),
                root: HeldLocation::new(root.clone()),
                cwd: HeldLocation::new(root),
            });
            let registered = Self::register_in(&mut core.fs_contexts.lock(), &context);
            (context, registered)
        });
        // On failure, the context drops here, outside the locks, as dropping a location can reach
        // a backend.
        registered.map(|()| context)
    }

    /// A copy of this context, registered in `core`, used by no thread yet, as a new process gets
    /// (Linux's fork copies `fs_struct`).
    pub(crate) fn copy(&self, core: &BrokerCore) -> Result<Arc<Self>> {
        // Copied and registered under the registry's lock, which a pivot holds while it moves
        // roots and working directories, so no move can miss the copy.
        let mut contexts = core.fs_contexts.lock();
        let state = {
            let state = self.state.lock();
            FsContextState {
                namespace: Arc::clone(&state.namespace),
                root: state.root.clone(),
                cwd: state.cwd.clone(),
            }
        };
        let context = Self::unregistered(state);
        let registered = Self::register_in(&mut contexts, &context);
        drop(contexts);
        // On failure, the copy drops here, outside the lock, as dropping a location can reach a
        // backend.
        registered.map(|()| context)
    }

    /// A copy of this context, registered in `core`, used by no thread yet, in a copy of its
    /// mount namespace, with its root and working directory moved onto the copies of their
    /// mounts, as Linux's `CLONE_NEWNS` gives.
    ///
    /// The namespace and its mounts are charged to `process`.
    pub(crate) fn copy_with_namespace(&self, process: &BrokerProcess) -> Result<Arc<Self>> {
        // A context's namespace never changes. The root and working directory are taken under its
        // `mutation` lock, as a pivot moves them under it too, and under the registry's lock,
        // which is kept until the copy is registered, as for a copy in the same namespace.
        let source = Arc::clone(&self.state.lock().namespace);
        let (namespace, copies, (mut contexts, snapshot)) = source.copy(process, || {
            (process.core.fs_contexts.lock(), self.snapshot())
        })?;
        let context = Self::unregistered(FsContextState {
            namespace,
            root: HeldLocation::new(copies.moved(&snapshot.root)),
            cwd: HeldLocation::new(copies.moved(&snapshot.cwd)),
        });
        let registered = Self::register_in(&mut contexts, &context);
        drop(contexts);
        registered.map(|()| context)
    }

    fn unregistered(state: FsContextState) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(state),
            threads: AtomicUsize::new(0),
        })
    }

    /// Add `context` to `contexts`, the locked registry of its core.
    fn register_in(contexts: &mut Vec<Weak<Self>>, context: &Arc<Self>) -> Result<()> {
        // Contexts that ended are pruned when the registry would grow.
        if contexts.len() == contexts.capacity() {
            contexts.retain(|context| context.strong_count() != 0);
        }
        contexts
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        contexts.push(Arc::downgrade(context));
        Ok(())
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
///
/// Its lock is held while a context is copied and registered, and while a pivot moves roots and
/// working directories, so neither misses the other. It is taken after a namespace's `mutation`
/// lock and before a context's; no backend call or final drop of a context or location happens
/// under it.
pub(crate) type FsContexts = Mutex<Vec<Weak<FsContext>>>;
