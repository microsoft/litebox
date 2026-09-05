// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::event::EventObject;
use crate::filesystem::OpenFileDescription;
use crate::pipe::PipeObject;
use crate::socket::SocketObject;
use crate::{BrokerCore, BrokerError, Result};
use hashbrown::HashMap;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use spin::{Mutex, rwlock::RwLock};

/// Caller identity information supplied by the broker entry layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but BrokerCore still accepts an explicit credential value so authenticated
/// servers or hosts can plumb identity through the same session-creation seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CallerCredential {
    /// The trusted broker entry layer authenticated and bound the caller.
    HostGuaranteed,
    /// Explicit deployment mode for the initial unauthenticated userland POC.
    Unauthenticated,
}

/// Broker-assigned session identity.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub u64);

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
        /// Right to wait for readiness.
        const WAIT = 1 << 0;
        /// Right to mutate object state, such as adding event readiness credits.
        const WRITE = 1 << 1;
    }
}

pub(crate) struct ObjectReference {
    pub(crate) object: Arc<RwLock<ObjectEntry>>,
    pub(crate) session_id: SessionId,
    pub(crate) rights: ObjectRights,
    session_reference_index: usize,
}

pub(crate) enum ObjectEntry {
    Reserved,
    Event(EventObject),
    Pipe(PipeObject),
    Socket(SocketObject),
    Filesystem(Arc<dyn OpenFileDescription>),
}

struct SessionReferences {
    handles: Vec<ObjectHandle>,
    pending_handles: usize,
}

/// Broker-owned authority token for one authenticated caller session.
///
/// User mode does not choose this value. The broker entry layer authenticates
/// the caller, then BrokerCore assigns this identity for all operations received
/// on that session. Dropping the session releases all object references it owns.
pub struct BrokerSession {
    pub(crate) core: BrokerCore,
    /// Broker-assigned session identity.
    pub(crate) session_id: SessionId,
    /// Broker-entry-authenticated caller credential for this session.
    pub(crate) caller_credential: CallerCredential,
    /// Handles of the live object references owned by this session.
    references: Mutex<SessionReferences>,
    /// Pipe capacity charged to this session by live pipe objects.
    pub(crate) reserved_pipe_capacity: Arc<AtomicUsize>,
    /// Socket quota held by pending, live, and closing in-flight resources.
    pub(crate) reserved_sockets: Arc<AtomicUsize>,
    /// Cancellation state for potentially blocking operations in this session.
    pub(crate) cancellation: AssociationCancellation,
}

impl BrokerSession {
    /// Creates an authenticated session identity.
    pub(crate) fn new(
        core: BrokerCore,
        session_id: SessionId,
        caller_credential: CallerCredential,
    ) -> Self {
        Self {
            core,
            session_id,
            caller_credential,
            references: Mutex::new(SessionReferences {
                handles: Vec::new(),
                pending_handles: 0,
            }),
            reserved_pipe_capacity: Arc::new(AtomicUsize::new(0)),
            reserved_sockets: Arc::new(AtomicUsize::new(0)),
            cancellation: AssociationCancellation::default(),
        }
    }

    /// Requests cooperative cancellation of potentially blocking operations
    /// because this association is ending.
    pub fn request_cancellation(&self) {
        self.cancellation.cancel();
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
        let mut session_references = self.references.lock();
        self.prepare_session_references(&mut session_references, 1)?;
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
                drop(session_references);
                return Err(error);
            }
        };
        self.insert_object_reference(
            &mut references,
            &mut session_references.handles,
            handle,
            object,
            rights,
        );

        Ok(handle)
    }

    /// Duplicates a supported object reference into another session.
    ///
    /// The returned handle is owned by `target` and refers to the same
    /// underlying event or pipe endpoint. `rights` must be nonempty, allowed by
    /// the target's policy, and no broader than the source reference's rights.
    /// The source reference is unchanged. Socket references are not supported
    /// because their readiness registration is currently bound to one session
    /// and handle.
    ///
    /// Pipe capacity remains charged to the session that created the pipe.
    /// Child creation must call this operation explicitly according to the
    /// guest operating system's inheritance semantics.
    pub fn duplicate_object_reference_to(
        &self,
        handle: ObjectHandle,
        target: &BrokerSession,
        rights: ObjectRights,
    ) -> Result<ObjectHandle> {
        if rights.is_empty() {
            return Err(BrokerError::InvalidRights);
        }

        let object = {
            let references = self.core.references.read();
            let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
            if reference.session_id != self.session_id {
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
                ObjectEntry::Event(_) | ObjectEntry::Pipe(_) | ObjectEntry::Filesystem(_) => {}
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
        let mut session_references = self.references.lock();
        self.prepare_session_references(&mut session_references, 2)?;
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
                drop(session_references);
                return Err(error);
            }
        };
        for (handle, object) in [(first_handle, first), (second_handle, second)] {
            self.insert_object_reference(
                &mut references,
                &mut session_references.handles,
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
        let mut session_references = self.references.lock();
        let next_session_pending = self.prepare_session_references(&mut session_references, 1)?;
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
        session_references.pending_handles = next_session_pending;
        Ok(PendingObjectReference {
            session: self,
            handle,
            rights,
            object,
            active: true,
        })
    }

    fn prepare_session_references(
        &self,
        session_references: &mut SessionReferences,
        additional: usize,
    ) -> Result<usize> {
        let pending_and_additional = session_references
            .pending_handles
            .checked_add(additional)
            .ok_or(BrokerError::ResourceExhausted)?;
        if session_references
            .handles
            .len()
            .checked_add(pending_and_additional)
            .is_none_or(|count| count > self.core.limits.max_references_per_session)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        session_references
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
        let session_reference_index = reference_handles.len();
        references.insert(
            handle,
            ObjectReference {
                object,
                session_id: self.session_id,
                rights,
                session_reference_index,
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
        if reference.session_id != self.session_id {
            return Err(BrokerError::UnknownObject);
        }
        if !reference.rights.contains(required_rights) {
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
                ObjectEntry::Pipe(pipe) => return Ok(pipe.readiness()),
                ObjectEntry::Socket(socket) => socket.resource(),
                ObjectEntry::Filesystem(_) => return Err(BrokerError::InvalidRights),
                ObjectEntry::Reserved => return Err(BrokerError::Internal),
            }
        };
        Ok(socket.readiness())
    }

    /// Closes one object reference owned by this session.
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
        let mut session_references = self.references.lock();
        let reference_handles = &mut session_references.handles;
        let mut references = self.core.references.write();
        let reference = references
            .remove(&handle)
            .ok_or(BrokerError::UnknownObject)?;
        let index = reference.session_reference_index;
        // Keep fallible validation in a nested scope so `?` and early returns
        // reach the shared rollback below instead of dropping the removed
        // reference while either reference-index lock is held.
        let removal_result = (|| {
            if reference.session_id != self.session_id {
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
                if moved_reference.session_id != self.session_id
                    || moved_reference.session_reference_index != last_index
                {
                    return Err(BrokerError::Internal);
                }
                moved_reference.session_reference_index = index;
            }
            reference_handles.swap_remove(index);
            Ok(())
        })();

        if let Err(error) = removal_result {
            let replaced_reference = references.insert(handle, reference);
            drop(references);
            drop(session_references);
            if replaced_reference.is_some() {
                return Err(BrokerError::Internal);
            }
            return Err(error);
        }
        Ok(reference)
    }
}

pub(crate) struct PendingObjectReference<'session> {
    session: &'session BrokerSession,
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
        let mut session_references = self.session.references.lock();
        let mut references = self.session.core.references.write();
        if references.contains_key(&self.handle) {
            drop(references);
            drop(session_references);
            return Err(BrokerError::Internal);
        }
        if !release_pending_reference(
            &self.session.core.pending_references,
            &mut session_references,
        ) {
            self.active = false;
            drop(references);
            drop(session_references);
            return Err(BrokerError::Internal);
        }
        self.active = false;
        *self.object.write() = object;
        self.session.insert_object_reference(
            &mut references,
            &mut session_references.handles,
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
            let mut session_references = self.session.references.lock();
            let released = release_pending_reference(
                &self.session.core.pending_references,
                &mut session_references,
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
    session_references: &mut SessionReferences,
) -> bool {
    let next_pending_handles = session_references.pending_handles.checked_sub(1);
    let core_released = core_pending_references
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
            pending.checked_sub(1)
        })
        .is_ok();
    if let Some(next_pending_handles) = next_pending_handles {
        session_references.pending_handles = next_pending_handles;
    }
    next_pending_handles.is_some() && core_released
}

impl Drop for BrokerSession {
    fn drop(&mut self) {
        loop {
            let Some(handle) = self.references.lock().handles.pop() else {
                break;
            };
            // Do not restore an inconsistent handle: retrying it forever would
            // prevent later valid references from being released.
            let reference = {
                let mut references = self.core.references.write();
                let Some(reference) = references.get(&handle) else {
                    continue;
                };
                if reference.session_id != self.session_id {
                    continue;
                }
                let Some(reference) = references.remove(&handle) else {
                    continue;
                };
                reference
            };
            // Object destruction may release platform resources and must never
            // run while either reference index lock is held.
            drop(reference);
        }
        self.core.socket_provider.close_session(self.session_id);
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{SessionReferences, release_pending_reference};
    use crate::{
        BrokerCore, BrokerCoreLimits, BrokerError, CallerCredential, ObjectRights, PolicyEngine,
        SocketPolicy,
    };
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::event::{EventConsumeMode, EventConsumption};
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use std::{sync::Arc, vec::Vec};

    const TEST_MAX_REFERENCES: usize = 4;
    const TEST_MAX_PIPE_CAPACITY: usize = 8;
    const TEST_MAX_REFERENCES_PER_SESSION: usize = 2;
    const TEST_MAX_PIPE_CAPACITY_PER_SESSION: usize = 4;

    #[test]
    fn pending_reference_release_checks_both_counters() {
        let core_pending_references = AtomicUsize::new(1);
        let mut session_references = SessionReferences {
            handles: Vec::new(),
            pending_handles: 1,
        };
        assert!(release_pending_reference(
            &core_pending_references,
            &mut session_references
        ));
        assert_eq!(core_pending_references.load(Ordering::Relaxed), 0);
        assert_eq!(session_references.pending_handles, 0);

        assert!(!release_pending_reference(
            &core_pending_references,
            &mut session_references
        ));
        assert_eq!(core_pending_references.load(Ordering::Relaxed), 0);
        assert_eq!(session_references.pending_handles, 0);
    }

    fn check_supported_references_duplicate_between_sessions(broker: &BrokerCore) {
        let source = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let target = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let denied_target = broker
            .create_session(CallerCredential::HostGuaranteed)
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

    #[test]
    fn object_reference_lifecycle_uses_public_core_constructor_once() {
        let socket_provider = Arc::new(crate::socket::tests::TestSocketProvider::default());
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::guest_network()),
            BrokerCoreLimits::new_with_all_limits(
                TEST_MAX_REFERENCES,
                TEST_MAX_PIPE_CAPACITY,
                2,
                1,
            )
            .with_session_quotas(
                TEST_MAX_REFERENCES_PER_SESSION,
                TEST_MAX_PIPE_CAPACITY_PER_SESSION,
            ),
            socket_provider.clone(),
            Arc::new(crate::random::TestRandomProvider),
            Arc::new(crate::stdio::UnsupportedStdioProvider),
            Arc::new(crate::filesystem::UnsupportedFilesystemProvider),
        )
        .unwrap();

        check_event_reference_lifecycle(&broker);
        check_session_drop_releases_references(&broker);
        check_pipe_lifecycle(&broker);
        check_pipe_reader_closure(&broker);
        check_corrupt_index_fails_without_mutation(&broker);
        check_corrupt_index_does_not_break_teardown(&broker);
        check_reference_quota_is_per_session(&broker);
        check_pending_references_count_toward_session_quota(&broker);
        check_pipe_capacity_quota_is_per_session(&broker);
        check_pipe_capacity_outlives_session_for_in_flight_object(&broker);
        check_supported_references_duplicate_between_sessions(&broker);
        crate::socket::tests::check_socket_lifecycle(&broker, &socket_provider);
        check_pair_handle_exhaustion(&broker);

        assert!(broker.references.read().is_empty());
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_event_reference_lifecycle(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let other = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = crate::event::create(&session, 0).unwrap();
        let unknown_handle = ObjectHandle(handle.0.checked_add(1).unwrap());

        assert_ne!(unknown_handle, handle);
        assert_eq!(
            session.check_readiness(unknown_handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(
            other.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(session.check_readiness(handle), Ok(ReadinessFlags::WRITE));
        assert_eq!(
            crate::event::add(&session, handle, 1),
            Ok(ReadinessFlags::READ | ReadinessFlags::WRITE)
        );
        assert_eq!(
            crate::event::consume(&session, handle, EventConsumeMode::One),
            Ok(EventConsumption {
                value: 1,
                readiness: ReadinessFlags::WRITE,
            })
        );
        let second_handle = crate::event::create(&session, 0).unwrap();
        assert_eq!(
            crate::event::create(&session, 0),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            crate::pipe::create(&session, 4, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(session.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        // Closing the older handle exercises swap-removing a non-last entry.
        assert_eq!(session.close_object_reference(handle), Ok(()));
        assert_eq!(
            session.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(session.close_object_reference(second_handle), Ok(()));
        assert!(broker.references.read().is_empty());
    }

    fn check_session_drop_releases_references(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let first = crate::event::create(&session, 0).unwrap();
        let second = crate::event::create(&session, 0).unwrap();
        assert_ne!(first, second);
        {
            let references = broker.references.read();
            assert_eq!(references.len(), 2);
        }

        drop(session);

        {
            let references = broker.references.read();
            assert!(references.is_empty());
        }
    }

    fn check_pipe_lifecycle(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(
            crate::pipe::create(&session, 5, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        let (reader, writer) = crate::pipe::create(&session, 4, 2).unwrap();
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(
            session.check_readiness(reader),
            Ok(ReadinessFlags::default())
        );
        assert_eq!(
            crate::pipe::read(&session, reader, 1),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(crate::pipe::write(&session, writer, &[1, 2]), Ok(2));
        assert_eq!(crate::pipe::write(&session, writer, &[3, 4, 5]), Ok(2));
        assert_eq!(
            crate::pipe::write(&session, writer, &[5]),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(
            crate::pipe::read(&session, reader, 3),
            Ok(std::vec::Vec::from([1, 2, 3]))
        );
        assert_eq!(crate::pipe::write(&session, writer, &[5, 6]), Ok(2));
        assert_eq!(session.close_object_reference(writer), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(
            session.check_readiness(reader),
            Ok(ReadinessFlags::READ | ReadinessFlags::HANGUP)
        );
        assert_eq!(
            crate::pipe::read(&session, reader, 4),
            Ok(std::vec::Vec::from([4, 5, 6]))
        );
        assert_eq!(
            crate::pipe::read(&session, reader, 1),
            Ok(std::vec::Vec::new())
        );
        assert_eq!(session.close_object_reference(reader), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_pipe_reader_closure(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (reader, writer) = crate::pipe::create(&session, 4, 2).unwrap();
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(session.close_object_reference(reader), Ok(()));
        assert_eq!(crate::pipe::write(&session, writer, &[]), Ok(0));
        assert_eq!(
            crate::pipe::write(&session, writer, &[1]),
            Err(BrokerError::PeerClosed)
        );
        assert_eq!(
            session.check_readiness(writer),
            Ok(ReadinessFlags::WRITE | ReadinessFlags::ERROR)
        );
        assert_eq!(session.close_object_reference(writer), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_corrupt_index_fails_without_mutation(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let older = crate::event::create(&session, 0).unwrap();
        let newer = crate::event::create(&session, 0).unwrap();
        {
            let mut references = broker.references.write();
            references.get_mut(&older).unwrap().session_reference_index = usize::MAX;
        }

        assert_eq!(
            session.close_object_reference(older),
            Err(BrokerError::Internal)
        );
        {
            let mut references = broker.references.write();
            references.get_mut(&older).unwrap().session_reference_index = 0;
        }
        assert_eq!(session.close_object_reference(older), Ok(()));
        assert_eq!(session.close_object_reference(newer), Ok(()));
    }

    fn check_corrupt_index_does_not_break_teardown(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let _older = crate::event::create(&session, 0).unwrap();
        let newer = crate::event::create(&session, 0).unwrap();
        broker
            .references
            .write()
            .get_mut(&newer)
            .unwrap()
            .session_reference_index = usize::MAX;

        drop(session);

        assert!(broker.references.read().is_empty());
    }

    fn check_reference_quota_is_per_session(broker: &BrokerCore) {
        let greedy = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let neighbor = broker
            .create_session(CallerCredential::Unauthenticated)
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
            .create_session(CallerCredential::Unauthenticated)
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

    fn check_pending_references_count_toward_session_quota(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let neighbor = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();

        let first = session
            .reserve_object_reference(ObjectRights::WAIT)
            .unwrap();
        let second = session
            .reserve_object_reference(ObjectRights::WAIT)
            .unwrap();
        assert!(matches!(
            session.reserve_object_reference(ObjectRights::WAIT),
            Err(BrokerError::ResourceExhausted)
        ));

        let neighbor_handle = crate::event::create(&neighbor, 0).unwrap();
        drop(first);
        drop(second);
        assert_eq!(neighbor.close_object_reference(neighbor_handle), Ok(()));
        assert!(broker.references.read().is_empty());
        assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
    }

    fn check_pipe_capacity_quota_is_per_session(broker: &BrokerCore) {
        let greedy = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let neighbor = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();

        let (greedy_reader, greedy_writer) =
            crate::pipe::create(&greedy, TEST_MAX_PIPE_CAPACITY_PER_SESSION as u64, 2).unwrap();
        assert_eq!(
            crate::pipe::create(&greedy, 1, 1),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            greedy.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY_PER_SESSION
        );

        let (neighbor_reader, neighbor_writer) =
            crate::pipe::create(&neighbor, TEST_MAX_PIPE_CAPACITY_PER_SESSION as u64, 2).unwrap();
        assert_eq!(
            broker.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY
        );

        let latecomer = broker
            .create_session(CallerCredential::Unauthenticated)
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

    fn check_pipe_capacity_outlives_session_for_in_flight_object(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (reader, _writer) =
            crate::pipe::create(&session, TEST_MAX_PIPE_CAPACITY_PER_SESSION as u64, 2).unwrap();
        let object = session
            .authorized_object(reader, ObjectRights::WAIT)
            .unwrap();
        let session_capacity = Arc::clone(&session.reserved_pipe_capacity);

        drop(session);

        assert!(broker.references.read().is_empty());
        assert_eq!(
            session_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY_PER_SESSION
        );
        assert_eq!(
            broker.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY_PER_SESSION
        );

        drop(object);

        assert_eq!(session_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_pair_handle_exhaustion(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        {
            let mut next_reference_handle = broker.next_reference_handle.write();
            *next_reference_handle = u64::MAX - 1;
        }
        assert_eq!(
            crate::pipe::create(&session, 4, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(*broker.next_reference_handle.read(), u64::MAX - 1);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        let handle = crate::event::create(&session, 0).unwrap();
        assert_eq!(handle, ObjectHandle(u64::MAX - 1));
        assert_eq!(session.close_object_reference(handle), Ok(()));
        assert_eq!(
            crate::event::create(&session, 0),
            Err(BrokerError::ResourceExhausted)
        );
    }
}
