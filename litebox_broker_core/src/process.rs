// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::event::EventObject;
use crate::fs::File;
use crate::pipe::PipeObject;
use crate::socket::SocketObject;
use crate::{BrokerCore, BrokerError, Result};
use hashbrown::HashMap;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::{ObjectHandle, ProcessId, ThreadId};
use spin::{Mutex, rwlock::RwLock};

/// Caller identity information supplied by the broker entry layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but BrokerCore still accepts an explicit credential value so authenticated
/// servers or hosts can plumb identity through the same process-creation seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CallerCredential {
    /// The trusted broker entry layer authenticated and bound the caller.
    HostGuaranteed,
    /// Explicit deployment mode for the initial unauthenticated userland POC.
    Unauthenticated,
}

/// Cancellation state shared by potentially blocking operations in one broker
/// association.
#[derive(Debug, Default)]
pub struct AssociationCancellation {
    cancelled: AtomicBool,
}

impl AssociationCancellation {
    /// Returns whether the broker association is ending.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

bitflags::bitflags! {
    /// Broker rights attached to an object reference.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct ObjectRights: u32 {
        /// Right to observe or consume object state, including readiness and file reads.
        const WAIT = 1 << 0;
        /// Right to mutate object state, such as file contents or event readiness credits.
        const WRITE = 1 << 1;
    }
}

pub(crate) struct ObjectReference {
    pub(crate) object: Arc<RwLock<ObjectEntry>>,
    pub(crate) owner: ProcessId,
    pub(crate) rights: ObjectRights,
    process_reference_index: usize,
}

pub(crate) enum ObjectEntry {
    Reserved,
    Event(EventObject),
    File(File),
    Pipe(PipeObject),
    Socket(SocketObject),
}

struct ProcessReferences {
    handles: Vec<ObjectHandle>,
    pending_handles: usize,
}

/// Broker-owned state for one guest thread.
///
/// Execution remains platform-local. This object owns the authoritative
/// broker identity and is the extension point for execution-control state when
/// a broker platform needs to manage thread execution.
pub struct BrokerThread {
    id: ThreadId,
}

impl BrokerThread {
    const fn new(id: ThreadId) -> Self {
        Self { id }
    }

    /// Returns the assigned thread ID.
    #[must_use]
    pub const fn id(&self) -> ThreadId {
        self.id
    }
}

/// Broker-owned state for one authenticated guest process.
///
/// User mode cannot choose the process ID. The broker entry layer authenticates
/// the caller, then [`BrokerCore`] creates and registers this object before
/// serving its association.
pub struct BrokerProcess {
    pub(crate) core: BrokerCore,
    /// Assigned process ID and internal authority.
    pub(crate) id: ProcessId,
    cleaned_up: bool,
    /// Authoritative parent process ID, absent for a root process.
    parent_id: Option<ProcessId>,
    /// Broker-entry-authenticated caller credential for this process.
    pub(crate) caller_credential: CallerCredential,
    /// Handles of the live object references owned by this process.
    references: Mutex<ProcessReferences>,
    /// Authoritative broker threads owned by this process.
    threads: Mutex<HashMap<ThreadId, BrokerThread>>,
    /// Pipe capacity charged to this process by live pipe objects.
    pub(crate) reserved_pipe_capacity: Arc<AtomicUsize>,
    /// Socket quota held by pending, live, and closing in-flight resources.
    pub(crate) reserved_sockets: Arc<AtomicUsize>,
    /// Cancellation state for potentially blocking operations in this process.
    pub(crate) cancellation: AssociationCancellation,
}

impl BrokerProcess {
    /// Creates authenticated broker process state.
    pub(crate) fn new(
        core: BrokerCore,
        id: ProcessId,
        parent_id: Option<ProcessId>,
        caller_credential: CallerCredential,
    ) -> Self {
        Self {
            core,
            id,
            cleaned_up: false,
            parent_id,
            caller_credential,
            references: Mutex::new(ProcessReferences {
                handles: Vec::new(),
                pending_handles: 0,
            }),
            threads: Mutex::new(HashMap::new()),
            reserved_pipe_capacity: Arc::new(AtomicUsize::new(0)),
            reserved_sockets: Arc::new(AtomicUsize::new(0)),
            cancellation: AssociationCancellation::default(),
        }
    }

    /// Returns the assigned process ID.
    #[must_use]
    pub const fn id(&self) -> ProcessId {
        self.id
    }

    /// Returns the current parent process ID, if any.
    #[must_use]
    pub const fn parent_id(&self) -> Option<ProcessId> {
        self.parent_id
    }

    /// Creates a broker thread belonging to this process.
    ///
    /// # Panics
    ///
    /// Panics if the shared ID allocator violates its range or uniqueness
    /// invariants.
    pub fn create_thread(&self) -> Result<ThreadId> {
        let mut threads = self.threads.lock();
        if threads.len() >= self.core.limits.max_threads_per_process {
            return Err(BrokerError::ResourceExhausted);
        }
        threads
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        self.core
            .active_thread_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < self.core.limits.max_threads).then(|| count + 1)
            })
            .map_err(|_| BrokerError::ResourceExhausted)?;
        let raw_id = match self.core.ids.lock().allocate() {
            Ok(id) => id,
            Err(error) => {
                self.core
                    .active_thread_count
                    .fetch_sub(1, Ordering::Relaxed);
                return Err(error);
            }
        };
        let thread = BrokerThread::new(ThreadId(raw_id));
        let thread_id = thread.id();
        assert!(
            threads.insert(thread_id, thread).is_none(),
            "the ID allocator returned an occupied thread ID"
        );
        Ok(thread_id)
    }

    /// Records broker thread exit after its local task teardown completes.
    pub fn exit_thread(&self, thread_id: ThreadId) -> Result<()> {
        let thread = self
            .threads
            .lock()
            .remove(&thread_id)
            .ok_or(BrokerError::UnknownObject)?;
        self.core
            .active_thread_count
            .fetch_sub(1, Ordering::Relaxed);
        self.core.ids.lock().release(thread.id().0);
        Ok(())
    }

    /// Requests cooperative cancellation of potentially blocking operations
    /// because this association is ending.
    pub fn request_cancellation(&self) {
        self.cancellation.cancel();
    }

    /// Completes non-unwinding process teardown and releases its IDs.
    ///
    /// Dropping a process without calling this method performs authority
    /// cleanup but leaves its numeric IDs occupied so they cannot be reused
    /// after an unwind.
    /// # Panics
    ///
    /// Panics if another owner still holds this process.
    pub fn finish(self: Arc<Self>) {
        let Ok(mut process) = Arc::try_unwrap(self) else {
            panic!("all broker process owners must be released before teardown");
        };
        process.cleanup(true);
    }

    pub(crate) fn create_object_reference(&self, object: ObjectEntry) -> Result<ObjectHandle> {
        let rights = self
            .core
            .policy
            .principal_object_rights(self.caller_credential)?;
        let object = Arc::new(RwLock::new(object));
        self.create_object_reference_with_rights(object, rights)
    }

    fn create_object_reference_with_rights(
        &self,
        object: Arc<RwLock<ObjectEntry>>,
        rights: ObjectRights,
    ) -> Result<ObjectHandle> {
        let mut process_references = self.references.lock();
        self.prepare_process_references(&mut process_references, 1)?;
        let mut references = self.core.references.write();
        let preparation = (|| {
            let pending = self.core.pending_references.load(Ordering::Relaxed);
            if references
                .len()
                .checked_add(pending)
                .is_none_or(|count| count >= self.core.limits.max_references)
            {
                return Err(BrokerError::ResourceExhausted);
            }
            references
                .try_reserve(
                    pending
                        .checked_add(1)
                        .ok_or(BrokerError::ResourceExhausted)?,
                )
                .map_err(|_| BrokerError::OutOfMemory)?;
            let handle = self.core.allocate_reference_handle()?;
            if references.contains_key(&handle) {
                return Err(BrokerError::Internal);
            }
            Ok(handle)
        })();
        let handle = match preparation {
            Ok(handle) => handle,
            Err(error) => {
                drop(references);
                drop(process_references);
                return Err(error);
            }
        };
        self.insert_object_reference(
            &mut references,
            &mut process_references.handles,
            handle,
            object,
            rights,
        );

        Ok(handle)
    }

    /// Duplicates a supported object reference into another process.
    ///
    /// The returned handle is owned by `target` and refers to the same
    /// underlying event, file, or pipe endpoint. `rights` must be nonempty, allowed by
    /// the target's policy, and no broader than the source reference's rights.
    /// The source reference is unchanged. Socket references are not supported
    /// because their readiness registration is currently bound to one process
    /// and handle.
    ///
    /// Pipe capacity remains charged to the process that created the pipe.
    /// Child creation must call this operation explicitly according to the
    /// guest operating system's inheritance semantics.
    pub fn duplicate_object_reference_to(
        &self,
        handle: ObjectHandle,
        target: &BrokerProcess,
        rights: ObjectRights,
    ) -> Result<ObjectHandle> {
        if rights.is_empty() {
            return Err(BrokerError::InvalidRights);
        }

        let object = {
            let references = self.core.references.read();
            let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
            if reference.owner != self.id {
                return Err(BrokerError::UnknownObject);
            }
            if !reference.rights.contains(rights) {
                return Err(BrokerError::InvalidRights);
            }
            Arc::clone(&reference.object)
        };

        {
            let object = object.read();
            match &*object {
                ObjectEntry::Event(_) | ObjectEntry::File(_) | ObjectEntry::Pipe(_) => {}
                ObjectEntry::Socket(_) => return Err(BrokerError::UnsupportedOperation),
                ObjectEntry::Reserved => return Err(BrokerError::Internal),
            }
        }

        let target_rights = target
            .core
            .policy
            .principal_object_rights(target.caller_credential)?;
        if !target_rights.contains(rights) {
            return Err(BrokerError::PolicyDenied);
        }
        target.create_object_reference_with_rights(object, rights)
    }

    pub(crate) fn create_object_reference_pair(
        &self,
        first: ObjectEntry,
        second: ObjectEntry,
    ) -> Result<(ObjectHandle, ObjectHandle)> {
        let rights = self
            .core
            .policy
            .principal_object_rights(self.caller_credential)?;
        let first = Arc::new(RwLock::new(first));
        let second = Arc::new(RwLock::new(second));
        let mut process_references = self.references.lock();
        self.prepare_process_references(&mut process_references, 2)?;
        let mut references = self.core.references.write();
        let preparation = (|| {
            let pending = self.core.pending_references.load(Ordering::Relaxed);
            if references
                .len()
                .checked_add(pending)
                .and_then(|count| count.checked_add(2))
                .is_none_or(|count| count > self.core.limits.max_references)
            {
                return Err(BrokerError::ResourceExhausted);
            }
            references
                .try_reserve(
                    pending
                        .checked_add(2)
                        .ok_or(BrokerError::ResourceExhausted)?,
                )
                .map_err(|_| BrokerError::OutOfMemory)?;
            let (first_handle, second_handle) = self.core.allocate_reference_handle_pair()?;
            if first_handle == second_handle
                || references.contains_key(&first_handle)
                || references.contains_key(&second_handle)
            {
                return Err(BrokerError::Internal);
            }
            Ok((first_handle, second_handle))
        })();
        let (first_handle, second_handle) = match preparation {
            Ok(handles) => handles,
            Err(error) => {
                drop(references);
                drop(process_references);
                return Err(error);
            }
        };
        for (handle, object) in [(first_handle, first), (second_handle, second)] {
            self.insert_object_reference(
                &mut references,
                &mut process_references.handles,
                handle,
                object,
                rights,
            );
        }
        Ok((first_handle, second_handle))
    }

    pub(crate) fn reserve_object_reference(
        &self,
        rights: ObjectRights,
    ) -> Result<PendingObjectReference<'_>> {
        let object = Arc::new(RwLock::new(ObjectEntry::Reserved));
        let mut process_references = self.references.lock();
        let next_process_pending = self.prepare_process_references(&mut process_references, 1)?;
        let mut references = self.core.references.write();
        let pending_references = self.core.pending_references.load(Ordering::Relaxed);
        if references
            .len()
            .checked_add(pending_references)
            .is_none_or(|count| count >= self.core.limits.max_references)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        let handle = self.core.allocate_reference_handle()?;
        if references.contains_key(&handle) {
            return Err(BrokerError::Internal);
        }
        references
            .try_reserve(
                pending_references
                    .checked_add(1)
                    .ok_or(BrokerError::ResourceExhausted)?,
            )
            .map_err(|_| BrokerError::OutOfMemory)?;
        self.core
            .pending_references
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
                pending.checked_add(1)
            })
            .map_err(|_| BrokerError::ResourceExhausted)?;
        process_references.pending_handles = next_process_pending;
        Ok(PendingObjectReference {
            process: self,
            handle,
            rights,
            object,
            active: true,
        })
    }

    fn prepare_process_references(
        &self,
        process_references: &mut ProcessReferences,
        additional: usize,
    ) -> Result<usize> {
        let pending_and_additional = process_references
            .pending_handles
            .checked_add(additional)
            .ok_or(BrokerError::ResourceExhausted)?;
        if process_references
            .handles
            .len()
            .checked_add(pending_and_additional)
            .is_none_or(|count| count > self.core.limits.max_references_per_process)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        process_references
            .handles
            .try_reserve(pending_and_additional)
            .map_err(|_| BrokerError::OutOfMemory)?;
        Ok(pending_and_additional)
    }

    fn insert_object_reference(
        &self,
        references: &mut HashMap<ObjectHandle, ObjectReference>,
        reference_handles: &mut Vec<ObjectHandle>,
        handle: ObjectHandle,
        object: Arc<RwLock<ObjectEntry>>,
        rights: ObjectRights,
    ) {
        let process_reference_index = reference_handles.len();
        references.insert(
            handle,
            ObjectReference {
                object,
                owner: self.id,
                rights,
                process_reference_index,
            },
        );
        reference_handles.push(handle);
    }

    /// Returns an authorized object lease without holding the reference-table lock.
    ///
    /// Callers explicitly choose the object-lock lifetime. Socket operations use
    /// that control to release all broker locks before calling an external
    /// platform implementation, then reacquire only the object lock if they need
    /// to update broker-owned state.
    pub(crate) fn authorized_object(
        &self,
        handle: ObjectHandle,
        required_rights: ObjectRights,
    ) -> Result<Arc<RwLock<ObjectEntry>>> {
        let references = self.core.references.read();
        let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
        if reference.owner != self.id {
            return Err(BrokerError::UnknownObject);
        }
        if !reference.rights.contains(required_rights) {
            return Err(BrokerError::InvalidRights);
        }
        Ok(Arc::clone(&reference.object))
    }

    pub(crate) fn authorized_object_with_any_rights(
        &self,
        handle: ObjectHandle,
        allowed_rights: ObjectRights,
    ) -> Result<Arc<RwLock<ObjectEntry>>> {
        debug_assert!(!allowed_rights.is_empty());
        let references = self.core.references.read();
        let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
        if reference.owner != self.id {
            return Err(BrokerError::UnknownObject);
        }
        if !reference.rights.intersects(allowed_rights) {
            return Err(BrokerError::InvalidRights);
        }
        Ok(Arc::clone(&reference.object))
    }

    /// Returns the current readiness of a broker-owned object.
    pub fn check_readiness(&self, handle: ObjectHandle) -> Result<ReadinessFlags> {
        let object = self.authorized_object(handle, ObjectRights::WAIT)?;
        let socket = {
            let object = object.read();
            match &*object {
                ObjectEntry::Event(event) => return Ok(event.readiness()),
                ObjectEntry::File(_) => return Err(BrokerError::InvalidRights),
                ObjectEntry::Pipe(pipe) => return Ok(pipe.readiness()),
                ObjectEntry::Socket(socket) => socket.resource(),
                ObjectEntry::Reserved => return Err(BrokerError::Internal),
            }
        };
        Ok(socket.readiness())
    }

    /// Closes one object reference owned by this process.
    ///
    /// The underlying object is released when this was the last live reference.
    /// Destruction happens after releasing the process-wide reference-table
    /// lock, so an object may safely release platform resources.
    pub fn close_object_reference(&self, handle: ObjectHandle) -> Result<()> {
        let reference = self.remove_object_reference(handle)?;
        drop(reference);
        Ok(())
    }

    fn remove_object_reference(&self, handle: ObjectHandle) -> Result<ObjectReference> {
        let mut process_references = self.references.lock();
        let reference_handles = &mut process_references.handles;
        let mut references = self.core.references.write();
        let reference = references
            .remove(&handle)
            .ok_or(BrokerError::UnknownObject)?;
        let index = reference.process_reference_index;
        // Keep fallible validation in a nested scope so `?` and early returns
        // reach the shared rollback below instead of dropping the removed
        // reference while either reference-index lock is held.
        let removal_result = (|| {
            if reference.owner != self.id {
                return Err(BrokerError::UnknownObject);
            }
            if reference_handles.get(index) != Some(&handle) {
                return Err(BrokerError::Internal);
            }
            let last_index = reference_handles
                .len()
                .checked_sub(1)
                .ok_or(BrokerError::Internal)?;
            if index != last_index {
                let moved_handle = *reference_handles
                    .get(last_index)
                    .ok_or(BrokerError::Internal)?;
                let moved_reference = references
                    .get_mut(&moved_handle)
                    .ok_or(BrokerError::Internal)?;
                if moved_reference.owner != self.id
                    || moved_reference.process_reference_index != last_index
                {
                    return Err(BrokerError::Internal);
                }
                moved_reference.process_reference_index = index;
            }
            reference_handles.swap_remove(index);
            Ok(())
        })();

        if let Err(error) = removal_result {
            let replaced_reference = references.insert(handle, reference);
            drop(references);
            drop(process_references);
            if replaced_reference.is_some() {
                return Err(BrokerError::Internal);
            }
            return Err(error);
        }
        Ok(reference)
    }

    fn cleanup(&mut self, release_ids: bool) -> bool {
        if self.cleaned_up {
            return false;
        }
        self.cleaned_up = true;

        let mut invariant_fault = self.references.lock().pending_handles != 0;
        loop {
            let Some(handle) = self.references.lock().handles.pop() else {
                break;
            };
            // Do not restore an inconsistent handle: retrying it forever would
            // prevent later valid references from being released.
            let reference = {
                let mut references = self.core.references.write();
                let Some(reference) = references.get(&handle) else {
                    invariant_fault = true;
                    continue;
                };
                if reference.owner != self.id {
                    invariant_fault = true;
                    continue;
                }
                let Some(reference) = references.remove(&handle) else {
                    invariant_fault = true;
                    continue;
                };
                reference
            };
            // Object destruction may release platform resources and must never
            // run while either reference index lock is held.
            drop(reference);
        }

        loop {
            let stale = {
                let references = self.core.references.read();
                references
                    .iter()
                    .find_map(|(handle, reference)| (reference.owner == self.id).then_some(*handle))
            };
            let Some(handle) = stale else {
                break;
            };
            invariant_fault = true;
            let reference = self.core.references.write().remove(&handle);
            drop(reference);
        }
        debug_assert!(
            !self
                .core
                .references
                .read()
                .values()
                .any(|reference| reference.owner == self.id)
        );

        self.core.socket_provider.close_process(self.id);

        if self.core.processes.write().remove(&self.id).is_none() {
            invariant_fault = true;
        }

        let threads = core::mem::take(&mut *self.threads.lock());
        if release_ids && !invariant_fault {
            self.core
                .active_thread_count
                .fetch_sub(threads.len(), Ordering::Relaxed);
            let mut ids = self.core.ids.lock();
            for thread in threads.into_values() {
                ids.release(thread.id().0);
            }
            ids.release(self.id.0);
        }
        invariant_fault
    }
}

pub(crate) struct PendingObjectReference<'process> {
    process: &'process BrokerProcess,
    handle: ObjectHandle,
    rights: ObjectRights,
    object: Arc<RwLock<ObjectEntry>>,
    active: bool,
}

impl PendingObjectReference<'_> {
    pub(crate) const fn handle(&self) -> ObjectHandle {
        self.handle
    }

    pub(crate) fn commit(mut self, object: ObjectEntry) -> Result<ObjectHandle> {
        if !matches!(&*self.object.read(), ObjectEntry::Reserved) {
            return Err(BrokerError::Internal);
        }
        let mut process_references = self.process.references.lock();
        let mut references = self.process.core.references.write();
        if references.contains_key(&self.handle) {
            drop(references);
            drop(process_references);
            return Err(BrokerError::Internal);
        }
        if !release_pending_reference(
            &self.process.core.pending_references,
            &mut process_references,
        ) {
            self.active = false;
            drop(references);
            drop(process_references);
            return Err(BrokerError::Internal);
        }
        self.active = false;
        *self.object.write() = object;
        self.process.insert_object_reference(
            &mut references,
            &mut process_references.handles,
            self.handle,
            Arc::clone(&self.object),
            self.rights,
        );
        Ok(self.handle)
    }
}

impl Drop for PendingObjectReference<'_> {
    fn drop(&mut self) {
        if self.active {
            let mut process_references = self.process.references.lock();
            let released = release_pending_reference(
                &self.process.core.pending_references,
                &mut process_references,
            );
            self.active = false;
            assert!(
                released,
                "pending object reference counters are inconsistent"
            );
        }
    }
}

fn release_pending_reference(
    core_pending_references: &AtomicUsize,
    process_references: &mut ProcessReferences,
) -> bool {
    let next_pending_handles = process_references.pending_handles.checked_sub(1);
    let core_released = core_pending_references
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
            pending.checked_sub(1)
        })
        .is_ok();
    if let Some(next_pending_handles) = next_pending_handles {
        process_references.pending_handles = next_pending_handles;
    }
    next_pending_handles.is_some() && core_released
}

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        let _ = self.cleanup(false);
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{ProcessReferences, release_pending_reference};
    use crate::test_platform::TestPlatform;
    use crate::test_support::{TestBrokerCoreBuilder, TestStdioProvider};
    use crate::{
        BrokerCore, BrokerCoreLimits, BrokerError, CallerCredential, ObjectRights, PolicyEngine,
        SocketPolicy,
    };
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::event::{EventConsumeMode, EventConsumption};
    use litebox_broker_protocol::fs::{
        FileAccessMode, FileError, FileMode, FileOpenFlags, FileSeekWhence, FileType, FileUser,
    };
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::stdio::StdioOutputStream;
    use std::{sync::Arc, vec, vec::Vec};

    const TEST_MAX_REFERENCES: usize = 4;
    const TEST_MAX_PIPE_CAPACITY: usize = 8;
    const TEST_MAX_REFERENCES_PER_PROCESS: usize = 2;
    const TEST_MAX_PIPE_CAPACITY_PER_PROCESS: usize = 4;
    const ROOT: FileUser = FileUser { user: 0, group: 0 };

    #[test]
    fn process_and_thread_ids_share_one_numeric_namespace() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let first = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let thread = first.create_thread().unwrap();
        let second = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();

        assert_eq!(first.id().0, 1);
        assert_eq!(first.parent_id(), None);
        assert_eq!(thread.0, 2);
        assert_eq!(second.id().0, 3);
        assert_eq!(second.parent_id(), None);
    }

    #[test]
    fn released_thread_id_is_reused_after_rotation() {
        let mut broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        broker.ids =
            alloc::sync::Arc::new(spin::Mutex::new(crate::id::IdAllocator::new(2).unwrap()));
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let first = process.create_thread().unwrap();

        process.exit_thread(first).unwrap();

        assert_eq!(process.create_thread().unwrap(), first);
    }

    #[test]
    fn process_cannot_release_another_process_thread_id() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let first = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let second = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let thread = first.create_thread().unwrap();

        assert_eq!(second.exit_thread(thread), Err(BrokerError::UnknownObject));
        assert_eq!(first.exit_thread(thread), Ok(()));
    }

    #[test]
    fn thread_quotas_are_global_and_per_process() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_limits(BrokerCoreLimits::DEFAULT.with_thread_quotas(2, 1))
        .build()
        .unwrap();
        let first = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let second = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let third = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let first_thread = first.create_thread().unwrap();
        let second_thread = second.create_thread().unwrap();

        assert_eq!(first.create_thread(), Err(BrokerError::ResourceExhausted));
        assert_eq!(third.create_thread(), Err(BrokerError::ResourceExhausted));

        first.exit_thread(first_thread).unwrap();
        assert!(third.create_thread().is_ok());
        second.exit_thread(second_thread).unwrap();
    }

    #[test]
    fn finish_removes_process_and_releases_owned_ids() {
        let mut broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        broker.ids =
            alloc::sync::Arc::new(spin::Mutex::new(crate::id::IdAllocator::new(2).unwrap()));
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let process_id = process.id();
        let thread_id = process.create_thread().unwrap();
        assert_eq!(broker.active_thread_count.load(Ordering::Relaxed), 1);
        let registered = broker
            .processes
            .read()
            .get(&process_id)
            .and_then(alloc::sync::Weak::upgrade)
            .unwrap();
        assert!(Arc::ptr_eq(&process, &registered));
        drop(registered);

        process.finish();
        assert!(!broker.processes.read().contains_key(&process_id));
        assert_eq!(broker.active_thread_count.load(Ordering::Relaxed), 0);

        let replacement = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(replacement.id(), process_id);
        assert_eq!(replacement.create_thread().unwrap(), thread_id);
    }

    #[test]
    fn fallback_drop_retains_process_and_thread_ids_and_quota() {
        let mut broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_limits(BrokerCoreLimits::DEFAULT.with_thread_quotas(1, 1))
        .build()
        .unwrap();
        broker.ids =
            alloc::sync::Arc::new(spin::Mutex::new(crate::id::IdAllocator::new(4).unwrap()));
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let process_id = process.id();
        let thread_id = process.create_thread().unwrap();

        drop(process);
        assert_eq!(broker.active_thread_count.load(Ordering::Relaxed), 1);

        let first_replacement = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let second_replacement = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        assert_ne!(first_replacement.id(), process_id);
        assert_ne!(first_replacement.id().0, thread_id.0);
        assert_ne!(second_replacement.id(), process_id);
        assert_ne!(second_replacement.id().0, thread_id.0);
        assert_eq!(
            first_replacement.create_thread(),
            Err(BrokerError::ResourceExhausted)
        );
        assert!(matches!(
            broker.create_process(CallerCredential::Unauthenticated),
            Err(BrokerError::ResourceExhausted)
        ));
    }

    #[test]
    fn drop_sweeps_unindexed_references_and_leaves_id_occupied() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let process_id = process.id();
        crate::event::create(&process, 1).unwrap();
        process.references.lock().handles.clear();

        drop(process);

        assert!(broker.references.read().is_empty());
        let replacement = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        assert_ne!(replacement.id(), process_id);
    }

    #[test]
    fn pending_reference_release_checks_both_counters() {
        let core_pending_references = AtomicUsize::new(1);
        let mut process_references = ProcessReferences {
            handles: Vec::new(),
            pending_handles: 1,
        };
        assert!(release_pending_reference(
            &core_pending_references,
            &mut process_references
        ));
        assert_eq!(core_pending_references.load(Ordering::Relaxed), 0);
        assert_eq!(process_references.pending_handles, 0);

        assert!(!release_pending_reference(
            &core_pending_references,
            &mut process_references
        ));
        assert_eq!(core_pending_references.load(Ordering::Relaxed), 0);
        assert_eq!(process_references.pending_handles, 0);
    }

    fn check_supported_references_duplicate_between_processes(broker: &BrokerCore) {
        let source = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let target = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let denied_target = broker
            .create_process(CallerCredential::HostGuaranteed)
            .unwrap();

        let event = crate::event::create(&source, 1).unwrap();
        let duplicated_event = source
            .duplicate_object_reference_to(event, &target, ObjectRights::WAIT)
            .unwrap();
        assert_ne!(duplicated_event, event);
        assert_eq!(
            source.duplicate_object_reference_to(event, &denied_target, ObjectRights::WAIT),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(source.close_object_reference(event), Ok(()));
        assert_eq!(
            crate::event::add(&target, duplicated_event, 1),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            crate::event::consume(&target, duplicated_event, EventConsumeMode::One),
            Ok(EventConsumption {
                value: 1,
                readiness: ReadinessFlags::WRITE,
            })
        );
        assert_eq!(
            target.duplicate_object_reference_to(duplicated_event, &source, ObjectRights::WRITE),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(target.close_object_reference(duplicated_event), Ok(()));

        let (reader, writer) = crate::pipe::create(&source, 4, 2).unwrap();
        let duplicated_writer = source
            .duplicate_object_reference_to(writer, &target, ObjectRights::WRITE)
            .unwrap();
        assert_eq!(source.close_object_reference(writer), Ok(()));
        assert_eq!(crate::pipe::write(&target, duplicated_writer, &[1]), Ok(1));
        assert_eq!(
            crate::pipe::read(&source, reader, 1),
            Ok(std::vec::Vec::from([1]))
        );

        let event = crate::event::create(&target, 0).unwrap();
        assert_eq!(
            source.duplicate_object_reference_to(reader, &target, ObjectRights::WAIT),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(broker.references.read().len(), 3);

        assert_eq!(target.close_object_reference(event), Ok(()));
        assert_eq!(target.close_object_reference(duplicated_writer), Ok(()));
        assert_eq!(source.close_object_reference(reader), Ok(()));
        assert!(broker.references.read().is_empty());
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_file_reference_lifecycle(broker: &BrokerCore, stdio_provider: &TestStdioProvider) {
        let source = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let target = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let mode = FileMode::from_bits(0o600).unwrap();
        let file = crate::fs::open(
            &source,
            "/file",
            ROOT,
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
            mode,
        )
        .unwrap()
        .unwrap();

        assert_eq!(crate::fs::write(&source, file, b"abcdef", None), Ok(Ok(6)));
        assert_eq!(
            crate::fs::seek(&source, file, 0, FileSeekWhence::RelativeToBeginning),
            Ok(Ok(0))
        );

        let event = crate::event::create(&source, 0).unwrap();
        let mut byte = [0];
        assert_eq!(
            crate::fs::read(&source, event, &mut byte, None),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            crate::event::consume(&source, file, EventConsumeMode::One),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            source.check_readiness(file),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            crate::fs::open(
                &source,
                "/uncommitted",
                ROOT,
                FileAccessMode::ReadWrite,
                FileOpenFlags::CREATE,
                mode,
            ),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(source.close_object_reference(event), Ok(()));
        assert_eq!(
            crate::fs::path_status(&source, "/uncommitted", ROOT),
            Ok(Err(FileError::NoSuchFileOrDirectory))
        );

        let mut first = [0; 2];
        assert_eq!(crate::fs::read(&source, file, &mut first, None), Ok(Ok(2)));
        assert_eq!(&first, b"ab");

        let duplicate = source
            .duplicate_object_reference_to(file, &target, ObjectRights::WAIT)
            .unwrap();
        let mut second = [0; 2];
        assert_eq!(
            crate::fs::read(&target, duplicate, &mut second, None),
            Ok(Ok(2))
        );
        assert_eq!(&second, b"cd");

        let mut explicit = [0; 2];
        assert_eq!(
            crate::fs::read(&source, file, &mut explicit, Some(0)),
            Ok(Ok(2))
        );
        assert_eq!(&explicit, b"ab");
        let mut final_bytes = [0; 2];
        assert_eq!(
            crate::fs::read(&source, file, &mut final_bytes, None),
            Ok(Ok(2))
        );
        assert_eq!(&final_bytes, b"ef");

        let status = crate::fs::handle_status(&target, duplicate)
            .unwrap()
            .unwrap();
        assert_eq!(status.file_type, FileType::RegularFile);
        assert_eq!(status.size, 6);
        assert_eq!(source.close_object_reference(file), Ok(()));
        assert_eq!(
            crate::fs::seek(&target, duplicate, 0, FileSeekWhence::RelativeToBeginning),
            Ok(Ok(0))
        );
        assert_eq!(
            crate::fs::read(&target, duplicate, &mut byte, None),
            Ok(Ok(1))
        );
        assert_eq!(&byte, b"a");
        assert_eq!(target.close_object_reference(duplicate), Ok(()));
        assert_eq!(crate::fs::unlink(&source, "/file", ROOT), Ok(Ok(())));

        let directory = crate::fs::open(
            &source,
            "/",
            ROOT,
            FileAccessMode::ReadOnly,
            FileOpenFlags::DIRECTORY,
            FileMode::default(),
        )
        .unwrap()
        .unwrap();
        let entries = crate::fs::read_directory(&source, directory)
            .unwrap()
            .unwrap();
        assert!(entries.iter().any(|entry| entry.name == "."));
        assert!(entries.iter().any(|entry| entry.name == "dev"));
        assert_eq!(source.close_object_reference(directory), Ok(()));

        let write_only_directory = crate::fs::open(
            &source,
            "/",
            ROOT,
            FileAccessMode::WriteOnly,
            FileOpenFlags::DIRECTORY,
            FileMode::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            crate::fs::read_directory(&source, write_only_directory),
            Ok(Err(FileError::NotForReading))
        );
        assert_eq!(source.close_object_reference(write_only_directory), Ok(()));

        let random = crate::fs::open(
            &source,
            "/dev/urandom",
            ROOT,
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
            FileMode::default(),
        )
        .unwrap()
        .unwrap();
        let mut random_bytes =
            vec![0; litebox_broker_protocol::random::MAX_RANDOM_TRANSFER_SIZE as usize + 1];
        assert_eq!(
            crate::fs::read(&source, random, &mut random_bytes, None),
            Ok(Ok(random_bytes.len()))
        );
        assert!(random_bytes.iter().all(|byte| *byte == 0x5a));
        assert_eq!(source.close_object_reference(random), Ok(()));

        let write_only_random = broker
            .fs
            .open(
                &source,
                "/dev/urandom",
                ROOT,
                FileAccessMode::WriteOnly,
                FileOpenFlags::NONE,
                FileMode::default(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            broker.fs.read(&source, &write_only_random, &mut [0], None),
            Ok(Err(FileError::NotForReading))
        );

        let read_only_null = broker
            .fs
            .open(
                &source,
                "/dev/null",
                ROOT,
                FileAccessMode::ReadOnly,
                FileOpenFlags::NONE,
                FileMode::default(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            broker.fs.write(&source, &read_only_null, &[0], None),
            Ok(Err(FileError::NotForWriting))
        );

        let stdout = crate::fs::open(
            &source,
            "/dev/stdout",
            ROOT,
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE,
            FileMode::default(),
        )
        .unwrap()
        .unwrap();
        let duplicated_stdout = source
            .duplicate_object_reference_to(stdout, &target, ObjectRights::WRITE)
            .unwrap();
        source.request_cancellation();
        assert_eq!(
            crate::fs::write(&source, stdout, b"source", None),
            Ok(Err(FileError::Io))
        );
        let stdio_input =
            vec![b'x'; litebox_broker_protocol::stdio::MAX_STDIO_TRANSFER_SIZE as usize + 1];
        assert_eq!(
            crate::fs::write(&target, duplicated_stdout, &stdio_input, None),
            Ok(Ok(
                litebox_broker_protocol::stdio::MAX_STDIO_TRANSFER_SIZE as usize
            ))
        );
        assert_eq!(
            stdio_provider.writes(),
            vec![(
                StdioOutputStream::Stdout,
                stdio_input[..litebox_broker_protocol::stdio::MAX_STDIO_TRANSFER_SIZE as usize]
                    .to_vec()
            )]
        );
        assert_eq!(source.close_object_reference(stdout), Ok(()));
        assert_eq!(target.close_object_reference(duplicated_stdout), Ok(()));
    }

    #[test]
    fn object_reference_lifecycle_uses_public_core_constructor_once() {
        let socket_provider = Arc::new(crate::socket::tests::TestSocketProvider::default());
        let fs = crate::fs::composer::Composer::builder()
            .mount("/", crate::fs::in_mem::InMem::<TestPlatform>::new)
            .mount("/dev", crate::fs::devices::Devices::new)
            .build()
            .unwrap();
        let stdio_provider = Arc::new(TestStdioProvider::default());
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::guest_network()),
        )
        .with_limits(
            BrokerCoreLimits::new_with_all_limits(
                TEST_MAX_REFERENCES,
                TEST_MAX_PIPE_CAPACITY,
                2,
                1,
            )
            .with_process_quotas(
                TEST_MAX_REFERENCES_PER_PROCESS,
                TEST_MAX_PIPE_CAPACITY_PER_PROCESS,
            ),
        )
        .with_socket_provider(socket_provider.clone())
        .with_random_provider(Arc::new(crate::random::TestRandomProvider))
        .with_stdio_provider(stdio_provider.clone())
        .with_file_service(Arc::new(
            crate::fs::resolver::Resolver::<TestPlatform, _>::new(fs),
        ))
        .build()
        .unwrap();

        check_event_reference_lifecycle(&broker);
        check_process_drop_releases_references(&broker);
        check_pipe_lifecycle(&broker);
        check_pipe_reader_closure(&broker);
        check_corrupt_index_fails_without_mutation(&broker);
        check_corrupt_index_does_not_break_teardown(&broker);
        check_reference_quota_is_per_process(&broker);
        check_pending_references_count_toward_process_quota(&broker);
        check_pipe_capacity_quota_is_per_process(&broker);
        check_pipe_capacity_outlives_process_for_in_flight_object(&broker);
        check_supported_references_duplicate_between_processes(&broker);
        check_file_reference_lifecycle(&broker, &stdio_provider);
        crate::socket::tests::check_socket_lifecycle(&broker, &socket_provider);
        check_pair_handle_exhaustion(&broker);

        assert!(broker.references.read().is_empty());
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_event_reference_lifecycle(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let other = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = crate::event::create(&process, 0).unwrap();
        let unknown_handle = ObjectHandle(handle.0.checked_add(1).unwrap());

        assert_ne!(unknown_handle, handle);
        assert_eq!(
            process.check_readiness(unknown_handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(
            other.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(process.check_readiness(handle), Ok(ReadinessFlags::WRITE));
        assert_eq!(
            crate::event::add(&process, handle, 1),
            Ok(ReadinessFlags::READ | ReadinessFlags::WRITE)
        );
        assert_eq!(
            crate::event::consume(&process, handle, EventConsumeMode::One),
            Ok(EventConsumption {
                value: 1,
                readiness: ReadinessFlags::WRITE,
            })
        );
        let second_handle = crate::event::create(&process, 0).unwrap();
        assert_eq!(
            crate::event::create(&process, 0),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            crate::pipe::create(&process, 4, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(process.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        // Closing the older handle exercises swap-removing a non-last entry.
        assert_eq!(process.close_object_reference(handle), Ok(()));
        assert_eq!(
            process.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(process.close_object_reference(second_handle), Ok(()));
        assert!(broker.references.read().is_empty());
    }

    fn check_process_drop_releases_references(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let first = crate::event::create(&process, 0).unwrap();
        let second = crate::event::create(&process, 0).unwrap();
        assert_ne!(first, second);
        {
            let references = broker.references.read();
            assert_eq!(references.len(), 2);
        }

        drop(process);

        {
            let references = broker.references.read();
            assert!(references.is_empty());
        }
    }

    fn check_pipe_lifecycle(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(
            crate::pipe::create(&process, 5, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        let (reader, writer) = crate::pipe::create(&process, 4, 2).unwrap();
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(
            process.check_readiness(reader),
            Ok(ReadinessFlags::default())
        );
        assert_eq!(
            crate::pipe::read(&process, reader, 1),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(crate::pipe::write(&process, writer, &[1, 2]), Ok(2));
        assert_eq!(crate::pipe::write(&process, writer, &[3, 4, 5]), Ok(2));
        assert_eq!(
            crate::pipe::write(&process, writer, &[5]),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(
            crate::pipe::read(&process, reader, 3),
            Ok(std::vec::Vec::from([1, 2, 3]))
        );
        assert_eq!(crate::pipe::write(&process, writer, &[5, 6]), Ok(2));
        assert_eq!(process.close_object_reference(writer), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(
            process.check_readiness(reader),
            Ok(ReadinessFlags::READ | ReadinessFlags::HANGUP)
        );
        assert_eq!(
            crate::pipe::read(&process, reader, 4),
            Ok(std::vec::Vec::from([4, 5, 6]))
        );
        assert_eq!(
            crate::pipe::read(&process, reader, 1),
            Ok(std::vec::Vec::new())
        );
        assert_eq!(process.close_object_reference(reader), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_pipe_reader_closure(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let (reader, writer) = crate::pipe::create(&process, 4, 2).unwrap();
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(process.close_object_reference(reader), Ok(()));
        assert_eq!(crate::pipe::write(&process, writer, &[]), Ok(0));
        assert_eq!(
            crate::pipe::write(&process, writer, &[1]),
            Err(BrokerError::PeerClosed)
        );
        assert_eq!(
            process.check_readiness(writer),
            Ok(ReadinessFlags::WRITE | ReadinessFlags::ERROR)
        );
        assert_eq!(process.close_object_reference(writer), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_corrupt_index_fails_without_mutation(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let older = crate::event::create(&process, 0).unwrap();
        let newer = crate::event::create(&process, 0).unwrap();
        {
            let mut references = broker.references.write();
            references.get_mut(&older).unwrap().process_reference_index = usize::MAX;
        }

        assert_eq!(
            process.close_object_reference(older),
            Err(BrokerError::Internal)
        );
        {
            let mut references = broker.references.write();
            references.get_mut(&older).unwrap().process_reference_index = 0;
        }
        assert_eq!(process.close_object_reference(older), Ok(()));
        assert_eq!(process.close_object_reference(newer), Ok(()));
    }

    fn check_corrupt_index_does_not_break_teardown(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let _older = crate::event::create(&process, 0).unwrap();
        let newer = crate::event::create(&process, 0).unwrap();
        broker
            .references
            .write()
            .get_mut(&newer)
            .unwrap()
            .process_reference_index = usize::MAX;

        drop(process);

        assert!(broker.references.read().is_empty());
    }

    fn check_reference_quota_is_per_process(broker: &BrokerCore) {
        let greedy = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let neighbor = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();

        let greedy_first = crate::event::create(&greedy, 0).unwrap();
        let greedy_second = crate::event::create(&greedy, 0).unwrap();
        assert_eq!(
            crate::event::create(&greedy, 0),
            Err(BrokerError::ResourceExhausted)
        );

        let neighbor_first = crate::event::create(&neighbor, 0).unwrap();
        let neighbor_second = crate::event::create(&neighbor, 0).unwrap();
        assert_eq!(broker.references.read().len(), TEST_MAX_REFERENCES);

        let latecomer = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(
            crate::event::create(&latecomer, 0),
            Err(BrokerError::ResourceExhausted)
        );

        assert_eq!(greedy.close_object_reference(greedy_first), Ok(()));
        let latecomer_handle = crate::event::create(&latecomer, 0).unwrap();

        assert_eq!(greedy.close_object_reference(greedy_second), Ok(()));
        assert_eq!(neighbor.close_object_reference(neighbor_first), Ok(()));
        assert_eq!(neighbor.close_object_reference(neighbor_second), Ok(()));
        assert_eq!(latecomer.close_object_reference(latecomer_handle), Ok(()));
        assert!(broker.references.read().is_empty());
    }

    fn check_pending_references_count_toward_process_quota(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let neighbor = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();

        let first = process
            .reserve_object_reference(ObjectRights::WAIT)
            .unwrap();
        let second = process
            .reserve_object_reference(ObjectRights::WAIT)
            .unwrap();
        assert!(matches!(
            process.reserve_object_reference(ObjectRights::WAIT),
            Err(BrokerError::ResourceExhausted)
        ));

        let neighbor_handle = crate::event::create(&neighbor, 0).unwrap();
        drop(first);
        drop(second);
        assert_eq!(neighbor.close_object_reference(neighbor_handle), Ok(()));
        assert!(broker.references.read().is_empty());
        assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
    }

    fn check_pipe_capacity_quota_is_per_process(broker: &BrokerCore) {
        let greedy = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let neighbor = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();

        let (greedy_reader, greedy_writer) =
            crate::pipe::create(&greedy, TEST_MAX_PIPE_CAPACITY_PER_PROCESS as u64, 2).unwrap();
        assert_eq!(
            crate::pipe::create(&greedy, 1, 1),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            greedy.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY_PER_PROCESS
        );

        let (neighbor_reader, neighbor_writer) =
            crate::pipe::create(&neighbor, TEST_MAX_PIPE_CAPACITY_PER_PROCESS as u64, 2).unwrap();
        assert_eq!(
            broker.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY
        );

        let latecomer = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(
            crate::pipe::create(&latecomer, 1, 1),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(latecomer.reserved_pipe_capacity.load(Ordering::Relaxed), 0);

        assert_eq!(greedy.close_object_reference(greedy_reader), Ok(()));
        assert_eq!(greedy.close_object_reference(greedy_writer), Ok(()));
        assert_eq!(greedy.reserved_pipe_capacity.load(Ordering::Relaxed), 0);

        assert_eq!(neighbor.close_object_reference(neighbor_reader), Ok(()));
        assert_eq!(neighbor.close_object_reference(neighbor_writer), Ok(()));
        assert_eq!(neighbor.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_pipe_capacity_outlives_process_for_in_flight_object(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let (reader, _writer) =
            crate::pipe::create(&process, TEST_MAX_PIPE_CAPACITY_PER_PROCESS as u64, 2).unwrap();
        let object = process
            .authorized_object(reader, ObjectRights::WAIT)
            .unwrap();
        let process_capacity = Arc::clone(&process.reserved_pipe_capacity);

        drop(process);

        assert!(broker.references.read().is_empty());
        assert_eq!(
            process_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY_PER_PROCESS
        );
        assert_eq!(
            broker.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY_PER_PROCESS
        );

        drop(object);

        assert_eq!(process_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_pair_handle_exhaustion(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        {
            let mut next_reference_handle = broker.next_reference_handle.write();
            *next_reference_handle = u64::MAX - 1;
        }
        assert_eq!(
            crate::pipe::create(&process, 4, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(*broker.next_reference_handle.read(), u64::MAX - 1);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        let handle = crate::event::create(&process, 0).unwrap();
        assert_eq!(handle, ObjectHandle(u64::MAX - 1));
        assert_eq!(process.close_object_reference(handle), Ok(()));
        assert_eq!(
            crate::event::create(&process, 0),
            Err(BrokerError::ResourceExhausted)
        );
    }
}
