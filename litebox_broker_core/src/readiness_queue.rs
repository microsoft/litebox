// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned readiness queue operations.
//!
//! Each entry holds a registration in its target's watchers, and a
//! publication that includes the entry's watched readiness queues the entry.
//! Taking ready entries re-checks each target's current readiness, so stale
//! publications report nothing.
//!
//! Lock order: a target's locks, then a queue's state, then its watchers. A
//! queue never touches a target while holding its state, and drops targets
//! only after releasing it, since dropping an object may publish to the
//! queue.

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use hashbrown::HashMap;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::readiness_queue::{
    ReadinessQueueEntryFlags, ReadinessQueueError, ReadinessQueueInterest, ReadyEvent,
};
use spin::Mutex;
use spin::rwlock::RwLock;

use crate::object::{self, ObjectEntry, ObjectRights, StatusFlags};
use crate::quota::QuotaReservation;
use crate::readiness::{ReadinessRegistration, ReadinessSink, ReadinessWatchers};
use crate::{BrokerError, BrokerProcess, Result};

/// Guest-visible result of a readiness queue operation.
pub type ReadinessQueueResult<T> = core::result::Result<T, ReadinessQueueError>;

/// Creates an empty readiness queue, whose reference publishes readiness
/// through `readiness_sink`.
pub fn create(
    process: &BrokerProcess,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let status = StatusFlags::new(FileOpenFlags::NONE)?;
    let rights = process
        .core
        .policy
        .principal_object_rights(process.caller_credential)?;
    let reference = process.reserve_object_reference(rights)?;
    let registration = ReadinessRegistration::new(reference.handle(), Arc::clone(readiness_sink));
    let queue = Queue::new();
    queue.watchers.lock().watch(&registration)?;
    reference.commit_with_readiness(
        ObjectEntry::ReadinessQueue(ReadinessQueueObject { queue, status }),
        Some(registration),
    )
}

/// Adds an entry watching `target` under `key`, queueing it at once if the
/// target already has the watched readiness.
///
/// Fails with `UnsupportedOperation` if the target never publishes its
/// readiness or is a readiness queue.
pub fn add(
    process: &BrokerProcess,
    queue: ObjectHandle,
    target: ObjectHandle,
    key: u64,
    interest: ReadinessQueueInterest,
) -> Result<ReadinessQueueResult<()>> {
    let queue = authorized_queue(process, queue, ObjectRights::WRITE)?;
    let target = process.authorized_object(target, ObjectRights::WAIT)?;
    queue.add(process, &target, key, interest)
}

/// Replaces the interest of the entry watching `target` under `key`,
/// re-enabling it and queueing it if the target has the new watched
/// readiness.
pub fn modify(
    process: &BrokerProcess,
    queue: ObjectHandle,
    target: ObjectHandle,
    key: u64,
    interest: ReadinessQueueInterest,
) -> Result<ReadinessQueueResult<()>> {
    let queue = authorized_queue(process, queue, ObjectRights::WRITE)?;
    let target = process.authorized_object(target, ObjectRights::WAIT)?;
    Ok(queue.modify(&target, key, interest))
}

/// Removes the entry watching `target` under `key`.
pub fn remove(
    process: &BrokerProcess,
    queue: ObjectHandle,
    target: ObjectHandle,
    key: u64,
) -> Result<ReadinessQueueResult<()>> {
    let queue = authorized_queue(process, queue, ObjectRights::WRITE)?;
    let target = process.authorized_object(target, ObjectRights::WAIT)?;
    Ok(queue.remove(&target, key))
}

/// Takes up to `max_events` events from the queue's ready entries without
/// waiting, returning none if no entry is ready.
///
/// A level-triggered entry stays queued after reporting an event, a one-shot
/// entry is disabled until modified, and an edge-triggered entry is queued
/// again by its target's next publication.
pub fn take_ready(
    process: &BrokerProcess,
    queue: ObjectHandle,
    max_events: usize,
) -> Result<Vec<ReadyEvent>> {
    let queue = authorized_queue(process, queue, ObjectRights::WAIT)?;
    queue.take_ready(max_events)
}

fn authorized_queue(
    process: &BrokerProcess,
    handle: ObjectHandle,
    rights: ObjectRights,
) -> Result<Arc<Queue>> {
    let object = process.authorized_object(handle, rights)?;
    let queue = match &*object.read() {
        ObjectEntry::ReadinessQueue(queue) => Arc::clone(&queue.queue),
        _ => return Err(BrokerError::InvalidRights),
    };
    Ok(queue)
}

/// A readiness queue, whose references share its entries and status flags.
pub(crate) struct ReadinessQueueObject {
    queue: Arc<Queue>,
    status: StatusFlags,
}

impl ReadinessQueueObject {
    /// Returns `READ` if any entry is queued.
    pub(crate) fn readiness(&self) -> ReadinessFlags {
        let mut state = self.queue.state.lock();
        if state.ready.is_empty() {
            state.found_empty = true;
            ReadinessFlags::default()
        } else {
            ReadinessFlags::READ
        }
    }

    /// Publishes this queue's later readiness changes through `registration`
    /// until every clone of `registration` drops.
    pub(crate) fn watch(&self, registration: &ReadinessRegistration) -> Result<()> {
        self.queue.watchers.lock().watch(registration)
    }

    /// Returns the queue's access mode and status flags.
    pub(crate) fn get_status_flags(&self) -> FileStatusFlags {
        self.status.get(FileAccessMode::ReadWrite)
    }

    /// Changes the status flags in `mask` to their values in `flags`.
    pub(crate) fn set_status_flags(&mut self, mask: FileOpenFlags, flags: FileOpenFlags) {
        self.status.set(mask, flags);
    }
}

struct Queue {
    state: Mutex<QueueState>,
    /// Registrations of the queue's references, woken when an entry is
    /// queued.
    watchers: Mutex<ReadinessWatchers>,
    /// Sink of every entry's registration, keyed by entry ID.
    entry_sink: Arc<dyn ReadinessSink>,
}

#[derive(Default)]
struct QueueState {
    entries: HashMap<u64, Entry>,
    entry_ids: HashMap<EntryKey, u64>,
    /// Queued entry IDs and the sequence numbers they were queued with.
    ready: VecDeque<(u64, u64)>,
    /// Whether a caller found no entry queued since the queue last woke its
    /// watchers, so it may be waiting while a take holds entries it will
    /// queue again.
    found_empty: bool,
    next_id: u64,
    next_sequence: u64,
}

/// Identifies an entry by its caller-chosen key and its target's address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct EntryKey {
    key: u64,
    target: usize,
}

impl EntryKey {
    fn new(key: u64, target: &Arc<RwLock<ObjectEntry>>) -> Self {
        Self {
            key,
            target: Arc::as_ptr(target).addr(),
        }
    }
}

struct Entry {
    key: EntryKey,
    /// The watched object, held weakly so that the entry does not keep it
    /// open. Its allocation stays live, so its address is not reused while
    /// the entry exists.
    target: Weak<RwLock<ObjectEntry>>,
    interest: ReadinessQueueInterest,
    /// Whether the entry may be queued, which is false once a one-shot entry
    /// has reported an event.
    enabled: bool,
    queued: bool,
    _registration: ReadinessRegistration,
    _quota: QuotaReservation,
}

impl Queue {
    fn new() -> Arc<Self> {
        Arc::new_cyclic(|queue| Self {
            state: Mutex::new(QueueState::default()),
            watchers: Mutex::new(ReadinessWatchers::default()),
            entry_sink: Arc::new(EntrySink(queue.clone())),
        })
    }

    fn add(
        &self,
        process: &BrokerProcess,
        target: &Arc<RwLock<ObjectEntry>>,
        key: u64,
        interest: ReadinessQueueInterest,
    ) -> Result<ReadinessQueueResult<()>> {
        let key = EntryKey::new(key, target);
        if self.state.lock().entry_ids.contains_key(&key) {
            return Ok(Err(ReadinessQueueError::AlreadyRegistered));
        }
        let quota = self.reserve_entry(process)?;
        let id = {
            let mut state = self.state.lock();
            let id = state.next_id;
            state.next_id += 1;
            id
        };
        let registration =
            ReadinessRegistration::new(ObjectHandle(id), Arc::clone(&self.entry_sink));
        target.read().add_watcher(&registration)?;
        {
            let mut state = self.state.lock();
            if state.entry_ids.contains_key(&key) {
                return Ok(Err(ReadinessQueueError::AlreadyRegistered));
            }
            // Each entry is queued at most once, so this keeps queueing from
            // allocating.
            let ready_capacity = (state.entries.len() + 1).saturating_sub(state.ready.len());
            state
                .ready
                .try_reserve(ready_capacity)
                .map_err(|_| BrokerError::OutOfMemory)?;
            state
                .entries
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            state
                .entry_ids
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            state.entry_ids.insert(key, id);
            state.entries.insert(
                id,
                Entry {
                    key,
                    target: Arc::downgrade(target),
                    interest,
                    enabled: true,
                    queued: false,
                    _registration: registration,
                    _quota: quota,
                },
            );
        }
        // Publications before the entry was inserted were ignored.
        self.poll(id, target);
        Ok(Ok(()))
    }

    fn modify(
        &self,
        target: &Arc<RwLock<ObjectEntry>>,
        key: u64,
        interest: ReadinessQueueInterest,
    ) -> ReadinessQueueResult<()> {
        let id = {
            let mut state = self.state.lock();
            let Some(&id) = state.entry_ids.get(&EntryKey::new(key, target)) else {
                return Err(ReadinessQueueError::NotRegistered);
            };
            let entry = state
                .entries
                .get_mut(&id)
                .expect("every entry ID maps to an entry");
            entry.interest = interest;
            entry.enabled = true;
            id
        };
        self.poll(id, target);
        Ok(())
    }

    fn remove(&self, target: &Arc<RwLock<ObjectEntry>>, key: u64) -> ReadinessQueueResult<()> {
        let removed = {
            let mut state = self.state.lock();
            let Some(&id) = state.entry_ids.get(&EntryKey::new(key, target)) else {
                return Err(ReadinessQueueError::NotRegistered);
            };
            state.remove(id)
        };
        drop(removed);
        Ok(())
    }

    fn take_ready(&self, max_events: usize) -> Result<Vec<ReadyEvent>> {
        let mut events = Vec::new();
        events
            .try_reserve_exact(max_events)
            .map_err(|_| BrokerError::OutOfMemory)?;
        // Entries queued during this call, including level-triggered entries
        // it queues again, are left for the next call.
        let end = self.state.lock().next_sequence;
        while events.len() < max_events {
            let (id, target) = {
                let mut state = self.state.lock();
                let Some(&(id, sequence)) = state.ready.front() else {
                    break;
                };
                if sequence >= end {
                    break;
                }
                state.ready.pop_front();
                let entry = state
                    .entries
                    .get_mut(&id)
                    .expect("every queued entry ID maps to an entry");
                entry.queued = false;
                (id, entry.target.clone())
            };
            let readiness = target
                .upgrade()
                .map(|target| object::readiness(&target).unwrap_or_default());
            let mut state = self.state.lock();
            let Some(readiness) = readiness else {
                // Like Linux, an entry is removed once its target closes.
                let removed = state.remove(id);
                drop(state);
                drop(removed);
                continue;
            };
            let Some(entry) = state.entries.get_mut(&id) else {
                continue;
            };
            let readiness = readiness & entry.interest.readiness;
            if !entry.enabled || readiness.is_empty() {
                continue;
            }
            events.push(ReadyEvent {
                token: entry.interest.token,
                readiness,
            });
            let flags = entry.interest.flags;
            if flags.contains(ReadinessQueueEntryFlags::ONE_SHOT) {
                entry.enabled = false;
            } else if !flags.contains(ReadinessQueueEntryFlags::EDGE_TRIGGERED) {
                state.queue(id, readiness);
            }
        }
        // Entries queued again by a take woke no waiters, so like Linux, wake
        // them if any remain queued and a caller found none meanwhile, or this
        // call skipped some.
        let wake = {
            let mut state = self.state.lock();
            if state.ready.is_empty() {
                state.found_empty |= events.is_empty();
                false
            } else {
                let wake = state.found_empty || events.is_empty();
                state.found_empty &= !wake;
                wake
            }
        };
        if wake {
            self.watchers.lock().publish(ReadinessFlags::READ);
        }
        Ok(events)
    }

    /// Charges a new entry to the broker and to `process`, first removing
    /// entries whose targets closed if either quota is exhausted.
    fn reserve_entry(&self, process: &BrokerProcess) -> Result<QuotaReservation> {
        let reserve = || {
            QuotaReservation::new(
                &process.core.readiness_queue_entries,
                process.core.limits.max_readiness_queue_entries,
                &process.readiness_queue_entries,
                process.core.limits.max_readiness_queue_entries_per_process,
            )
        };
        match reserve() {
            Err(BrokerError::ResourceExhausted) => {
                self.remove_closed_entries();
                reserve()
            }
            result => result,
        }
    }

    /// Removes entries whose targets closed, which only queue themselves
    /// for removal if their targets publish after closing.
    fn remove_closed_entries(&self) {
        let mut state = self.state.lock();
        let QueueState {
            entries,
            entry_ids,
            ready,
            ..
        } = &mut *state;
        entries.retain(|_, entry| entry.target.strong_count() != 0);
        entry_ids.retain(|_, id| entries.contains_key(id));
        ready.retain(|(id, _)| entries.contains_key(id));
    }

    /// Queues entry `id` if its target has its watched readiness.
    fn poll(&self, id: u64, target: &RwLock<ObjectEntry>) {
        let readiness = object::readiness(target).unwrap_or_default();
        self.entry_changed(id, readiness);
    }

    /// Queues entry `id` if `readiness` includes its watched readiness,
    /// waking the queue's waiters if it did.
    fn entry_changed(&self, id: u64, readiness: ReadinessFlags) {
        let queued = {
            let mut state = self.state.lock();
            let queued = state.queue(id, readiness);
            state.found_empty &= !queued;
            queued
        };
        if queued {
            self.watchers.lock().publish(ReadinessFlags::READ);
        }
    }
}

impl QueueState {
    /// Queues entry `id` if it is enabled, is not already queued, and
    /// `readiness` includes its watched readiness, returning whether it did.
    fn queue(&mut self, id: u64, readiness: ReadinessFlags) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else {
            return false;
        };
        if !entry.enabled || entry.queued || (readiness & entry.interest.readiness).is_empty() {
            return false;
        }
        entry.queued = true;
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.ready.push_back((id, sequence));
        true
    }

    /// Removes entry `id`, which the caller drops after releasing the
    /// queue's state.
    fn remove(&mut self, id: u64) -> Option<Entry> {
        let entry = self.entries.remove(&id)?;
        self.entry_ids.remove(&entry.key);
        if entry.queued {
            self.ready.retain(|(queued, _)| *queued != id);
        }
        Some(entry)
    }
}

/// Sink of one queue's entry registrations, which queues an entry when its
/// target publishes.
struct EntrySink(Weak<Queue>);

impl ReadinessSink for EntrySink {
    fn max_tracked_objects(&self) -> usize {
        usize::MAX
    }

    fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
        if let Some(queue) = self.0.upgrade() {
            queue.entry_changed(handle.0, readiness);
        }
        Ok(())
    }

    fn republish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
        self.publish(handle, readiness)
    }

    fn retire(&self, _handle: ObjectHandle) {}
}

#[cfg(test)]
mod tests;
