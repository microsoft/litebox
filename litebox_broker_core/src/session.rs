// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::event::EventObject;
use crate::{BrokerCore, BrokerError, Result};
use litebox_broker_protocol::ObjectHandle;
use spin::rwlock::RwLock;

/// Caller identity information supplied by the broker entry layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but BrokerCore still accepts an explicit credential value so authenticated
/// servers or hosts can plumb identity through the same session-creation seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CallerCredential {
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

slotmap::new_key_type! {
    /// Broker-owned object identifier.
    pub(crate) struct ObjectId;
}

pub(crate) struct ObjectReference {
    pub(crate) object_id: ObjectId,
    pub(crate) object: Arc<ObjectRecord>,
    pub(crate) session_id: SessionId,
    pub(crate) rights: ObjectRights,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectEntry {
    Event(EventObject),
}

pub(crate) struct ObjectRecord {
    entry: RwLock<ObjectEntry>,
    reference_count: AtomicUsize,
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
        }
    }

    pub(crate) fn create_object(
        &self,
        object: ObjectEntry,
        rights: ObjectRights,
    ) -> Result<ObjectHandle> {
        let object = Arc::new(ObjectRecord {
            entry: RwLock::new(object),
            reference_count: AtomicUsize::new(0),
        });
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
            objects.insert(Arc::clone(&object))
        };

        match self.create_object_reference(object_id, object, rights) {
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
        object: Arc<ObjectRecord>,
        rights: ObjectRights,
    ) -> Result<ObjectHandle> {
        let mut references = self.core.references.write();
        if references.len() >= self.core.limits.max_references {
            return Err(BrokerError::ResourceExhausted);
        }

        let handle = self.core.allocate_reference_handle()?;
        let old_count = object.reference_count.fetch_add(1, Ordering::Relaxed);
        debug_assert!(old_count < self.core.limits.max_references);
        let old_reference = references.insert(
            handle,
            ObjectReference {
                object_id,
                object,
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
            self.authorize_use_object(&references, handle, required_rights)?
        };
        let object = object.entry.read();
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
        let mut object = object.entry.write();
        f(&mut object)
    }

    fn authorize_use_object(
        &self,
        references: &BTreeMap<ObjectHandle, ObjectReference>,
        handle: ObjectHandle,
        required_rights: ObjectRights,
    ) -> Result<Arc<ObjectRecord>> {
        let reference = validate_handle(references, self.session_id, handle, required_rights)?;
        self.core
            .policy
            .authorize_use_event(self.caller_credential, required_rights)?;
        Ok(Arc::clone(&reference.object))
    }

    /// Closes one object reference owned by this session.
    ///
    /// The underlying object is released when this was the last live reference.
    pub fn close_object_reference(&self, handle: ObjectHandle) -> Result<()> {
        let mut references = self.core.references.write();
        let reference = reference_for_handle(&references, self.session_id, handle)?;
        let object_id = reference.object_id;
        let last_reference = reference.object.reference_count.load(Ordering::Acquire) == 1;

        if last_reference {
            let mut objects = self.core.objects.write();
            if !objects.contains_key(object_id) {
                return Err(BrokerError::UnknownObject);
            }
            let reference = references
                .remove(&handle)
                .ok_or(BrokerError::UnknownObject)?;
            let old_count = reference
                .object
                .reference_count
                .fetch_sub(1, Ordering::AcqRel);
            debug_assert_eq!(old_count, 1);
            objects.remove(object_id);
        } else {
            let reference = references
                .remove(&handle)
                .ok_or(BrokerError::UnknownObject)?;
            let old_count = reference
                .object
                .reference_count
                .fetch_sub(1, Ordering::AcqRel);
            debug_assert!(old_count > 1);
        }
        Ok(())
    }
}

impl Drop for BrokerSession {
    fn drop(&mut self) {
        self.core.close_session(self.session_id);
    }
}

pub(crate) fn drop_references_for_session(broker: &BrokerCore, session_id: SessionId) {
    let mut references = broker.references.write();
    let mut objects = broker.objects.write();
    references.retain(|_, reference| {
        if reference.session_id != session_id {
            return true;
        }

        let old_count = reference
            .object
            .reference_count
            .fetch_sub(1, Ordering::AcqRel);
        debug_assert!(old_count > 0);
        if old_count == 1 {
            objects.remove(reference.object_id);
        }
        false
    });
}

fn validate_handle(
    references: &BTreeMap<ObjectHandle, ObjectReference>,
    session_id: SessionId,
    handle: ObjectHandle,
    required_rights: ObjectRights,
) -> Result<&ObjectReference> {
    let reference = reference_for_handle(references, session_id, handle)?;
    if !reference.rights.contains(required_rights) {
        return Err(BrokerError::InvalidRights);
    }

    Ok(reference)
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
