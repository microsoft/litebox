// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use crate::event::EventObject;
use crate::pipe::PipeObject;
use crate::{BrokerCore, BrokerError, Result};
use hashbrown::HashMap;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use spin::rwlock::RwLock;

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
pub(crate) struct SessionId(pub u64);

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
    previous_session_handle: Option<ObjectHandle>,
    next_session_handle: Option<ObjectHandle>,
}

pub(crate) enum ObjectEntry {
    Event(EventObject),
    Pipe(PipeObject),
    #[cfg(test)]
    DropProbe {
        _probe: tests::ObjectDropProbe,
    },
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
    /// Head of this session's intrusive live-reference list.
    reference_list_head: RwLock<Option<ObjectHandle>>,
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
            reference_list_head: RwLock::new(None),
        }
    }

    pub(crate) fn create_object_reference(&self, object: ObjectEntry) -> Result<ObjectHandle> {
        let rights = self
            .core
            .policy
            .principal_object_rights(self.caller_credential)?;
        let mut reference_list_head = self.reference_list_head.write();
        let mut references = self.core.references.write();
        if references.len() >= self.core.limits.max_references {
            return Err(BrokerError::ResourceExhausted);
        }
        let handle = self.core.allocate_reference_handle()?;
        let next_session_handle = *reference_list_head;
        if let Some(next_handle) = next_session_handle {
            let next_reference = references
                .get_mut(&next_handle)
                .expect("the session reference list must name a live reference");
            debug_assert_eq!(next_reference.session_id, self.session_id);
            next_reference.previous_session_handle = Some(handle);
        }
        references.insert(
            handle,
            ObjectReference {
                object: Arc::new(RwLock::new(object)),
                session_id: self.session_id,
                rights,
                previous_session_handle: None,
                next_session_handle,
            },
        );
        *reference_list_head = Some(handle);

        Ok(handle)
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
        let mut reference_list_head = self.reference_list_head.write();
        let mut references = self.core.references.write();
        if references
            .len()
            .checked_add(2)
            .is_none_or(|count| count > self.core.limits.max_references)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        let (first_handle, second_handle) = self.core.allocate_reference_handle_pair()?;
        for (handle, object) in [(first_handle, first), (second_handle, second)] {
            let next_session_handle = *reference_list_head;
            if let Some(next_handle) = next_session_handle {
                let next_reference = references
                    .get_mut(&next_handle)
                    .expect("the session reference list must name a live reference");
                debug_assert_eq!(next_reference.session_id, self.session_id);
                next_reference.previous_session_handle = Some(handle);
            }
            references.insert(
                handle,
                ObjectReference {
                    object: Arc::new(RwLock::new(object)),
                    session_id: self.session_id,
                    rights,
                    previous_session_handle: None,
                    next_session_handle,
                },
            );
            *reference_list_head = Some(handle);
        }
        Ok((first_handle, second_handle))
    }

    pub(crate) fn with_authorized_object<T>(
        &self,
        handle: ObjectHandle,
        required_rights: ObjectRights,
        f: impl FnOnce(&ObjectEntry) -> Result<T>,
    ) -> Result<T> {
        let object = {
            let references = self.core.references.read();
            self.authorize_use_object(&references, handle, required_rights)?
        };
        let object = object.read();
        f(&object)
    }

    pub(crate) fn with_authorized_object_mut<T>(
        &self,
        handle: ObjectHandle,
        required_rights: ObjectRights,
        f: impl FnOnce(&mut ObjectEntry) -> Result<T>,
    ) -> Result<T> {
        let object = {
            let references = self.core.references.read();
            self.authorize_use_object(&references, handle, required_rights)?
        };
        let mut object = object.write();
        f(&mut object)
    }

    /// Returns the current readiness of a broker-owned object.
    pub fn check_readiness(&self, handle: ObjectHandle) -> Result<ReadinessFlags> {
        self.with_authorized_object(handle, ObjectRights::WAIT, |object| {
            Ok(match object {
                ObjectEntry::Event(event) => event.readiness(),
                ObjectEntry::Pipe(pipe) => pipe.readiness(),
                #[cfg(test)]
                ObjectEntry::DropProbe { .. } => ReadinessFlags::default(),
            })
        })
    }

    fn authorize_use_object(
        &self,
        references: &HashMap<ObjectHandle, ObjectReference>,
        handle: ObjectHandle,
        required_rights: ObjectRights,
    ) -> Result<Arc<RwLock<ObjectEntry>>> {
        let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
        if reference.session_id != self.session_id {
            return Err(BrokerError::UnknownObject);
        }
        if !reference.rights.contains(required_rights) {
            return Err(BrokerError::InvalidRights);
        }
        let object = Arc::clone(&reference.object);
        Ok(object)
    }

    /// Closes one object reference owned by this session.
    ///
    /// The underlying object is released when this was the last live reference.
    /// Destruction happens after releasing the process-wide reference-table
    /// lock, so an object may safely release platform resources.
    pub fn close_object_reference(&self, handle: ObjectHandle) -> Result<()> {
        let reference = self.take_object_reference(handle)?;
        drop(reference);
        Ok(())
    }

    fn take_object_reference(&self, handle: ObjectHandle) -> Result<ObjectReference> {
        let mut reference_list_head = self.reference_list_head.write();
        let mut references = self.core.references.write();
        let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
        if reference.session_id != self.session_id {
            return Err(BrokerError::UnknownObject);
        }
        let previous_session_handle = reference.previous_session_handle;
        let next_session_handle = reference.next_session_handle;

        if let Some(previous_handle) = previous_session_handle {
            let previous_reference = references
                .get_mut(&previous_handle)
                .expect("the previous session reference must be live");
            debug_assert_eq!(previous_reference.session_id, self.session_id);
            previous_reference.next_session_handle = next_session_handle;
        } else {
            debug_assert_eq!(*reference_list_head, Some(handle));
            *reference_list_head = next_session_handle;
        }
        if let Some(next_handle) = next_session_handle {
            let next_reference = references
                .get_mut(&next_handle)
                .expect("the next session reference must be live");
            debug_assert_eq!(next_reference.session_id, self.session_id);
            next_reference.previous_session_handle = previous_session_handle;
        }

        let reference = references
            .remove(&handle)
            .ok_or(BrokerError::UnknownObject)?;
        Ok(reference)
    }

    fn take_one_object_reference(&self) -> Option<ObjectReference> {
        let handle = (*self.reference_list_head.read())?;
        Some(
            self.take_object_reference(handle)
                .expect("the session reference list must name a live owned reference"),
        )
    }
}

impl Drop for BrokerSession {
    fn drop(&mut self) {
        while let Some(reference) = self.take_one_object_reference() {
            // Object destruction may release platform resources and must never
            // run while either reference index spin lock is held.
            drop(reference);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BrokerSession, ObjectEntry};
    use alloc::sync::{Arc, Weak};
    use core::sync::atomic::{AtomicBool, Ordering};

    use crate::{
        BrokerCore, BrokerCoreLimits, BrokerError, CallerCredential, ObjectRights, PolicyEngine,
    };
    use hashbrown::HashMap;
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::event::{EventConsumeMode, EventConsumption};
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use spin::rwlock::RwLock;

    pub(crate) struct ObjectDropProbe {
        references: Weak<RwLock<HashMap<ObjectHandle, super::ObjectReference>>>,
        dropped_outside_lock: Arc<AtomicBool>,
    }

    impl Drop for ObjectDropProbe {
        fn drop(&mut self) {
            let references = self
                .references
                .upgrade()
                .expect("broker core must outlive its object references");
            self.dropped_outside_lock
                .store(references.try_write().is_some(), Ordering::Relaxed);
        }
    }

    #[test]
    fn object_reference_lifecycle_uses_public_core_constructor_once() {
        let broker = BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all()),
            BrokerCoreLimits::new(2, 4),
        )
        .unwrap();

        check_event_reference_lifecycle(&broker);
        check_session_drop_releases_references(&broker);
        check_pipe_lifecycle(&broker);
        check_pipe_reader_closure(&broker);
        check_explicit_close_drops_object_outside_lock(&broker);
        check_session_close_drops_objects_outside_lock(&broker);
        check_pair_handle_exhaustion(&broker);

        assert!(broker.references.read().is_empty());
    }

    fn check_event_reference_lifecycle(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let other = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = crate::event::create(&session, 0).unwrap();
        let unknown_handle = ObjectHandle(handle.0 + 1);

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
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(session.close_object_reference(second_handle), Ok(()));

        assert_eq!(session.close_object_reference(handle), Ok(()));
        {
            let references = broker.references.read();
            assert!(references.is_empty());
        }
        assert_eq!(
            session.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );
    }

    fn check_session_drop_releases_references(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let _handle = crate::event::create(&session, 0).unwrap();
        {
            let references = broker.references.read();
            assert_eq!(references.len(), 1);
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

    fn create_drop_probe(
        broker: &BrokerCore,
        session: &BrokerSession,
    ) -> (ObjectHandle, Arc<AtomicBool>) {
        let dropped_outside_lock = Arc::new(AtomicBool::new(false));
        let probe = ObjectDropProbe {
            references: Arc::downgrade(&broker.references),
            dropped_outside_lock: Arc::clone(&dropped_outside_lock),
        };
        let handle = session
            .create_object_reference(ObjectEntry::DropProbe { _probe: probe })
            .unwrap();
        (handle, dropped_outside_lock)
    }

    fn check_explicit_close_drops_object_outside_lock(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (first, first_dropped_outside_lock) = create_drop_probe(broker, &session);
        let (_, second_dropped_outside_lock) = create_drop_probe(broker, &session);

        // The first object is not the list head, so this also exercises
        // unlinking a reference with a live predecessor.
        assert_eq!(session.close_object_reference(first), Ok(()));
        assert!(first_dropped_outside_lock.load(Ordering::Relaxed));
        assert!(!second_dropped_outside_lock.load(Ordering::Relaxed));

        drop(session);
        assert!(second_dropped_outside_lock.load(Ordering::Relaxed));
    }

    fn check_session_close_drops_objects_outside_lock(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (_, first_dropped_outside_lock) = create_drop_probe(broker, &session);
        let (_, second_dropped_outside_lock) = create_drop_probe(broker, &session);

        drop(session);

        assert!(first_dropped_outside_lock.load(Ordering::Relaxed));
        assert!(second_dropped_outside_lock.load(Ordering::Relaxed));
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
