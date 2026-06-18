// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::event::EventObject;
use crate::session::{BrokerSession, SessionId};
use crate::{BrokerCore, BrokerError, Result};
use litebox_broker_protocol::ObjectHandle;
use slotmap::SlotMap;
use spin::rwlock::RwLock;

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

slotmap::new_key_type! {
    /// Broker-owned object identifier.
    pub(crate) struct ObjectId;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjectReference {
    pub(crate) object_id: ObjectId,
    pub(crate) session_id: SessionId,
    pub(crate) rights: ObjectRights,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectEntry {
    Event(EventObject),
}

impl BrokerSession {
    pub(crate) fn create_object(
        &self,
        object: ObjectEntry,
        rights: ObjectRights,
    ) -> Result<ObjectHandle> {
        let object_id = {
            let mut objects = self.core.objects.write();
            if objects.len() >= self.core.limits.max_objects {
                return Err(BrokerError::ResourceExhausted);
            }
            if objects.len() == objects.capacity() {
                objects
                    .try_reserve(1)
                    .map_err(|_| BrokerError::ResourceExhausted)?;
            }
            objects.insert(Arc::new(RwLock::new(object)))
        };

        match self.create_object_reference(object_id, rights) {
            Ok(handle) => Ok(handle),
            Err(error) => {
                let removed_object = self.core.objects.write().remove(object_id);
                debug_assert!(removed_object.is_some());
                Err(error)
            }
        }
    }

    fn create_object_reference(
        &self,
        object_id: ObjectId,
        rights: ObjectRights,
    ) -> Result<ObjectHandle> {
        let mut references = self.core.references.write();
        if references.len() >= self.core.limits.max_references {
            return Err(BrokerError::ResourceExhausted);
        }

        let handle = self.core.allocate_reference_handle()?;
        let old_reference = references.insert(
            handle,
            ObjectReference {
                object_id,
                session_id: self.session_id,
                rights,
            },
        );
        debug_assert!(old_reference.is_none());

        Ok(handle)
    }

    pub(crate) fn with_authorized_object<T>(
        &self,
        handle: ObjectHandle,
        required_rights: ObjectRights,
        f: impl FnOnce(&ObjectEntry) -> Result<T>,
    ) -> Result<T> {
        let object = {
            let references = self.core.references.read();
            let objects = self.core.objects.read();
            self.authorize_use_object(&references, &objects, handle, required_rights)?
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
            let objects = self.core.objects.read();
            self.authorize_use_object(&references, &objects, handle, required_rights)?
        };
        let mut object = object.write();
        f(&mut object)
    }

    fn authorize_use_object(
        &self,
        references: &BTreeMap<ObjectHandle, ObjectReference>,
        objects: &SlotMap<ObjectId, Arc<RwLock<ObjectEntry>>>,
        handle: ObjectHandle,
        required_rights: ObjectRights,
    ) -> Result<Arc<RwLock<ObjectEntry>>> {
        let reference = validate_handle(references, self.session_id, handle, required_rights)?;
        let object = objects
            .get(reference.object_id)
            .ok_or(BrokerError::UnknownObject)?;
        self.core
            .policy
            .authorize_use_event(self.caller_credential, required_rights)?;
        Ok(Arc::clone(object))
    }

    /// Closes one object reference owned by this session.
    ///
    /// The underlying object is released when this was the last live reference.
    pub fn close_object_reference(&self, handle: ObjectHandle) -> Result<()> {
        let mut references = self.core.references.write();
        let mut objects = self.core.objects.write();
        let object_id = reference_for_handle(&references, self.session_id, handle)?.object_id;
        if !objects.contains_key(object_id) {
            return Err(BrokerError::UnknownObject);
        }

        references.remove(&handle);
        drop_object_if_unreferenced(&mut objects, &references, object_id);
        Ok(())
    }
}

pub(super) fn drop_references_for_session(broker: &BrokerCore, session_id: SessionId) {
    let mut references = broker.references.write();
    let mut objects = broker.objects.write();
    references.retain(|_, reference| reference.session_id != session_id);
    objects.retain(|object_id, _| {
        references
            .values()
            .any(|reference| reference.object_id == object_id)
    });
}
fn validate_handle(
    references: &BTreeMap<ObjectHandle, ObjectReference>,
    session_id: SessionId,
    handle: ObjectHandle,
    required_rights: ObjectRights,
) -> Result<ObjectReference> {
    let reference = reference_for_handle(references, session_id, handle)?;
    if !reference.rights.contains(required_rights) {
        return Err(BrokerError::InvalidRights);
    }

    Ok(*reference)
}

fn reference_for_handle(
    references: &BTreeMap<ObjectHandle, ObjectReference>,
    session_id: SessionId,
    handle: ObjectHandle,
) -> Result<&ObjectReference> {
    let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
    if reference.session_id != session_id {
        return Err(BrokerError::UnknownObject);
    }
    Ok(reference)
}

fn drop_object_if_unreferenced(
    objects: &mut SlotMap<ObjectId, Arc<RwLock<ObjectEntry>>>,
    references: &BTreeMap<ObjectHandle, ObjectReference>,
    object_id: ObjectId,
) {
    if !references
        .values()
        .any(|reference| reference.object_id == object_id)
    {
        objects.remove(object_id);
    }
}

#[cfg(test)]
mod tests {
    use crate::{BrokerCore, BrokerCoreLimits, BrokerError, CallerCredential, PolicyEngine, event};
    use litebox_broker_protocol::{ObjectHandle, WaitOutcome};

    #[test]
    fn oversized_object_slotmap_limits_are_rejected_before_core_construction() {
        let too_many_entries = u32::MAX as usize;

        assert!(matches!(
            BrokerCore::new_with_limits(
                PolicyEngine::event_only(),
                BrokerCoreLimits::new(too_many_entries, 1)
            ),
            Err(BrokerError::ResourceExhausted)
        ));
    }

    #[test]
    fn object_reference_lifecycle_uses_public_core_constructor_once() {
        let broker = BrokerCore::new(PolicyEngine::event_only()).unwrap();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let other = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = event::create(&session, 0).unwrap();
        let unknown_handle = ObjectHandle(handle.0 + 1);

        assert_ne!(unknown_handle, handle);
        assert_eq!(
            event::wait(&session, unknown_handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(
            other.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        assert!(matches!(
            event::wait(&session, handle),
            Ok(WaitOutcome::WouldBlock(_))
        ));

        assert_eq!(session.close_object_reference(handle), Ok(()));
        {
            let references = broker.references.read();
            let objects = broker.objects.read();
            assert!(references.is_empty());
            assert!(objects.is_empty());
        }
        assert_eq!(
            session.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let _handle = event::create(&session, 0).unwrap();
        {
            let references = broker.references.read();
            let objects = broker.objects.read();
            assert_eq!(references.len(), 1);
            assert_eq!(objects.len(), 1);
        }

        drop(session);

        {
            let references = broker.references.read();
            let objects = broker.objects.read();
            assert!(references.is_empty());
            assert!(objects.is_empty());
        }

        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        {
            let mut next_reference_handle = broker.next_reference_handle.write();
            *next_reference_handle = u64::MAX;
        }
        assert_eq!(
            event::create(&session, 0),
            Err(BrokerError::ResourceExhausted)
        );
        let references = broker.references.read();
        let objects = broker.objects.read();
        assert!(references.is_empty());
        assert!(objects.is_empty());
    }
}
