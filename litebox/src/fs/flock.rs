// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Whole-file advisory locking, as used by `flock(2)`.
//!
//! Unlike `fcntl`'s POSIX record locking (which LiteBox currently stubs out as an always-succeeds
//! no-op, since a single LiteBox guest is always a single OS process from the host's perspective),
//! `flock(2)` locks are tracked here with real state and real contention, because LiteBox *does*
//! support multiple concurrent guest threads within that one process, and those threads can
//! legitimately race for the same whole-file lock.
//!
//! # Scope
//!
//! This is intentionally an in-process-only implementation:
//! - It arbitrates between concurrent holders *within a single LiteBox instance*, keyed by the
//!   underlying file's [`super::NodeInfo`] (device + inode). It provides no protection against a
//!   second, independent LiteBox instance, or a real host process, touching the same host-backed
//!   file -- LiteBox has no multi-process model to make that meaningful (see the `fork()`-related
//!   design notes elsewhere in this codebase).
//! - Holders are identified by a caller-supplied [`FlockHolder`] token. The intended caller
//!   (the Linux shim's `flock(2)` handler) uses the guest-visible raw fd number. This means two
//!   independently-`open()`ed fds are correctly treated as independent, contending holders, but two
//!   fds produced by `dup()`-ing the same original fd are (unlike real Linux's open-file-description
//!   based sharing) also treated as independent holders. This is a deliberate simplification: the
//!   common `flock`/work/`unlock`-or-`close` pattern is handled correctly, and `dup`-sharing a lock
//!   is a rare pattern that would require deeper plumbing than the current fd/entry model exposes to
//!   callers outside this crate.

use hashbrown::HashMap;

use crate::event::wait::{WaitContext, WaitError, Waker};
use crate::sync::{Mutex, RawSyncPrimitivesProvider};

use super::NodeInfo;

/// Caller-chosen identity for "who is asking" a whole-file lock question. See the module docs for
/// the intended (fd-number-based) convention and its limitations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlockHolder(pub u64);

/// The kind of whole-file lock being requested, per `flock(2)`'s `LOCK_SH`/`LOCK_EX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlockKind {
    /// `LOCK_SH`: any number of holders may hold a shared lock simultaneously.
    Shared,
    /// `LOCK_EX`: only one holder may hold an exclusive lock, and only if no one else holds any
    /// lock (shared or exclusive).
    Exclusive,
}

/// Why a (non-blocking) lock attempt did not succeed immediately.
#[derive(Debug, PartialEq, Eq)]
pub struct WouldBlock;

/// Why a blocking lock attempt did not succeed.
#[derive(Debug)]
pub enum FlockError {
    /// The wait was interrupted (e.g., by a signal) before the lock could be acquired.
    Interrupted,
}

impl From<WaitError> for FlockError {
    fn from(_: WaitError) -> Self {
        // `lock`'s blocking path never sets a deadline, so `WaitError::TimedOut` cannot occur;
        // any wait failure is therefore an interruption.
        FlockError::Interrupted
    }
}

/// Current holders of a whole-file lock.
enum Holders {
    Shared(hashbrown::HashSet<FlockHolder>),
    Exclusive(FlockHolder),
}

impl Holders {
    fn is_empty(&self) -> bool {
        match self {
            Holders::Shared(holders) => holders.is_empty(),
            Holders::Exclusive(_) => false,
        }
    }

    /// Attempt to acquire/convert `holder`'s lock to `kind`, given the current holders.
    fn try_acquire(&mut self, holder: FlockHolder, kind: FlockKind) -> Result<(), WouldBlock> {
        match (&mut *self, kind) {
            (Holders::Shared(holders), FlockKind::Shared) => {
                holders.insert(holder);
                Ok(())
            }
            (Holders::Shared(holders), FlockKind::Exclusive) => {
                if holders.is_empty() || (holders.len() == 1 && holders.contains(&holder)) {
                    *self = Holders::Exclusive(holder);
                    Ok(())
                } else {
                    Err(WouldBlock)
                }
            }
            (Holders::Exclusive(existing), FlockKind::Exclusive) if *existing == holder => {
                // Already the sole exclusive holder: a no-op re-affirmation.
                Ok(())
            }
            (Holders::Exclusive(existing), FlockKind::Shared) if *existing == holder => {
                // Real `flock(2)` allows converting an exclusive lock the caller holds down to
                // shared, in place, without an intervening unlock.
                *self = Holders::Shared(hashbrown::HashSet::from_iter([holder]));
                Ok(())
            }
            (Holders::Exclusive(_), _) => Err(WouldBlock),
        }
    }
}

/// Per-file lock-state entry.
struct NodeLock<Platform: RawSyncPrimitivesProvider> {
    holders: Holders,
    /// Threads currently blocked trying to acquire a conflicting lock on this file, woken (to
    /// re-check) whenever the holder set changes.
    waiters: alloc::vec::Vec<Waker<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider> NodeLock<Platform> {
    fn unlocked() -> Self {
        Self {
            holders: Holders::Shared(hashbrown::HashSet::new()),
            waiters: alloc::vec::Vec::new(),
        }
    }
}

/// A table of whole-file advisory locks, shared for the lifetime of a `LiteBox` instance. See the
/// module docs for the exact semantics and scope of what is modeled.
pub struct FlockTable<Platform: RawSyncPrimitivesProvider> {
    nodes: Mutex<Platform, HashMap<NodeInfo, NodeLock<Platform>>>,
}

impl<Platform: RawSyncPrimitivesProvider> FlockTable<Platform> {
    pub(crate) fn new() -> Self {
        Self {
            nodes: Mutex::new(HashMap::new()),
        }
    }

    /// Attempt to acquire/convert `holder`'s lock on `node` to `kind`, without blocking.
    ///
    /// A successful conversion can itself free up room for others (e.g. downgrading an exclusive
    /// lock to shared), so on success this also wakes anyone currently blocked in [`Self::lock`]
    /// on `node`, the same as [`Self::unlock`] does.
    pub fn try_lock(
        &self,
        node: NodeInfo,
        holder: FlockHolder,
        kind: FlockKind,
    ) -> Result<(), WouldBlock> {
        let waiters = {
            let mut nodes = self.nodes.lock();
            let entry = nodes.entry(node).or_insert_with(NodeLock::unlocked);
            entry.holders.try_acquire(holder, kind)?;
            core::mem::take(&mut entry.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
        Ok(())
    }

    /// Acquire/convert `holder`'s lock on `node` to `kind`, blocking via `cx` until it is available
    /// or the wait is interrupted.
    pub fn lock(
        &self,
        cx: &WaitContext<'_, Platform>,
        node: NodeInfo,
        holder: FlockHolder,
        kind: FlockKind,
    ) -> Result<(), FlockError>
    where
        Platform: crate::platform::TimeProvider,
    {
        cx.wait_until(|| {
            let mut nodes = self.nodes.lock();
            let entry = nodes.entry(node.clone()).or_insert_with(NodeLock::unlocked);
            if entry.holders.try_acquire(holder, kind).is_err() {
                entry.waiters.push(cx.waker().clone());
                return false;
            }
            // See `try_lock`'s doc comment: our own conversion can unblock others too.
            let waiters = core::mem::take(&mut entry.waiters);
            drop(nodes);
            for waiter in waiters {
                waiter.wake();
            }
            true
        })?;
        Ok(())
    }

    /// Release `holder`'s lock on `node`, if any. A no-op if `holder` does not currently hold a
    /// lock on `node`, matching `flock(2)`'s `LOCK_UN` behavior on an fd that isn't locked.
    pub fn unlock(&self, node: NodeInfo, holder: FlockHolder) {
        let mut nodes = self.nodes.lock();
        let Some(entry) = nodes.get_mut(&node) else {
            return;
        };
        match &mut entry.holders {
            Holders::Shared(holders) => {
                holders.remove(&holder);
            }
            Holders::Exclusive(existing) if *existing == holder => {
                entry.holders = Holders::Shared(hashbrown::HashSet::new());
            }
            Holders::Exclusive(_) => return,
        }
        let waiters = core::mem::take(&mut entry.waiters);
        if entry.holders.is_empty() && waiters.is_empty() {
            nodes.remove(&node);
        }
        // Wake waiters after releasing the table lock, so their re-check of `try_acquire` doesn't
        // contend with us for the same mutex we're still holding.
        drop(nodes);
        for waiter in waiters {
            waiter.wake();
        }
    }
}
