// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::event::EventObject;
use crate::identity::{BrokerAssociation, ProcessId};
use crate::{BrokerCore, BrokerError, PolicyDecision, PolicyOperation, Result, allocate_id};
use litebox_broker_protocol::ObjectHandle;

/// Broker object type known to the authority core and policy engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ObjectType {
    /// Broker-owned event object.
    Event,
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

slotmap::new_key_type! {
    /// Broker-owned object identifier.
    pub(crate) struct ObjectId;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjectReference {
    pub(crate) object_id: ObjectId,
    pub(crate) owner: ProcessId,
    pub(crate) rights: ObjectRights,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectEntry {
    Event(EventObject),
}

impl ObjectEntry {
    pub(crate) const fn object_type(self) -> ObjectType {
        match self {
            Self::Event(_) => ObjectType::Event,
        }
    }
}

impl BrokerCore {
    /// Inserts a broker object and mints its first owned reference.
    pub(crate) fn insert_object_with_reference(
        &mut self,
        association: &BrokerAssociation,
        object: ObjectEntry,
        rights: ObjectRights,
    ) -> Result<ObjectHandle> {
        if self.objects.len() >= self.limits.max_objects
            || self.references.len() >= self.limits.max_references
        {
            return Err(BrokerError::ResourceExhausted);
        }

        let handle = ObjectHandle(allocate_id(&mut self.next_reference_handle)?);
        let object_id = self.objects.insert(object);
        let old_reference = self.references.insert(
            handle,
            ObjectReference {
                object_id,
                owner: association.process_id(),
                rights,
            },
        );
        debug_assert!(old_reference.is_none());

        Ok(handle)
    }

    pub(crate) fn authorize_create_object(
        &mut self,
        association: &BrokerAssociation,
        object_type: ObjectType,
    ) -> Result<ObjectRights> {
        match self.policy.authorize(PolicyOperation::create_object(
            association.caller_credential(),
            object_type,
        ))? {
            PolicyDecision::GrantObjectReference { rights } => Ok(rights),
            _ => Err(BrokerError::InvalidPolicyDecision),
        }
    }

    pub(crate) fn authorize_use_object(
        &mut self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
        object_type: ObjectType,
        rights: ObjectRights,
    ) -> Result<AuthorizedObject> {
        let reference = self.validate_handle(association, handle, object_type, rights)?;
        let object_id = reference.object_id;
        let reference_rights = reference.rights;
        match self.policy.authorize(PolicyOperation::use_object(
            association.caller_credential(),
            object_type,
            rights,
        ))? {
            PolicyDecision::Authorized => Ok(AuthorizedObject {
                object_id,
                rights: reference_rights,
            }),
            _ => Err(BrokerError::InvalidPolicyDecision),
        }
    }

    pub(crate) fn object(&self, object_id: ObjectId) -> Result<&ObjectEntry> {
        self.objects
            .get(object_id)
            .ok_or(BrokerError::UnknownObject)
    }

    pub(crate) fn object_mut(&mut self, object_id: ObjectId) -> Result<&mut ObjectEntry> {
        self.objects
            .get_mut(object_id)
            .ok_or(BrokerError::UnknownObject)
    }

    fn validate_handle(
        &self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
        expected_type: ObjectType,
        required_rights: ObjectRights,
    ) -> Result<ObjectReference> {
        let reference = self.reference_for_handle(association, handle)?;
        if !reference.rights.contains(required_rights) {
            return Err(BrokerError::InvalidRights);
        }

        let object = self
            .objects
            .get(reference.object_id)
            .ok_or(BrokerError::UnknownObject)?;
        if object.object_type() != expected_type {
            return Err(BrokerError::WrongObjectType);
        }

        Ok(*reference)
    }
}

impl BrokerCore {
    /// Closes one object reference owned by an association.
    ///
    /// The underlying object is released when this was the last live reference.
    pub fn close_object_reference(
        &mut self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
    ) -> Result<()> {
        let object_id = self.reference_for_handle(association, handle)?.object_id;
        if !self.objects.contains_key(object_id) {
            return Err(BrokerError::UnknownObject);
        }

        self.references.remove(&handle);
        self.drop_object_if_unreferenced(object_id);
        Ok(())
    }

    /// Closes a broker association and releases references owned by it.
    pub fn close_association(&mut self, association: BrokerAssociation) {
        let process_id = association.process_id();
        self.references
            .retain(|_, reference| reference.owner != process_id);
        let references = &self.references;
        self.objects.retain(|object_id, _| {
            references
                .values()
                .any(|reference| reference.object_id == object_id)
        });
    }

    fn reference_for_handle(
        &self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
    ) -> Result<&ObjectReference> {
        let reference = self
            .references
            .get(&handle)
            .ok_or(BrokerError::UnknownObject)?;
        if reference.owner != association.process_id() {
            return Err(BrokerError::UnknownObject);
        }
        Ok(reference)
    }

    fn drop_object_if_unreferenced(&mut self, object_id: ObjectId) {
        if !self
            .references
            .values()
            .any(|reference| reference.object_id == object_id)
        {
            self.objects.remove(object_id);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthorizedObject {
    pub(crate) object_id: ObjectId,
    pub(crate) rights: ObjectRights,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrokerCoreLimits, BrokerError, CallerCredential, PolicyEngine, allocate_id};
    use litebox_broker_protocol::{ObjectHandle, WaitOutcome};

    #[test]
    fn allocator_exhausts_before_id_overflow() {
        let mut next_id = u64::MAX;

        assert_eq!(
            allocate_id(&mut next_id),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            allocate_id(&mut next_id),
            Err(BrokerError::ResourceExhausted)
        );
    }

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
        let mut core = BrokerCore::new(PolicyEngine::event_only()).unwrap();
        let owner = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let other = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = core.create_event(&owner).unwrap();
        let unknown_handle = ObjectHandle(handle.0 + 1);

        assert_ne!(unknown_handle, handle);
        assert_eq!(
            core.wait_event(&owner, unknown_handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(
            core.close_object_reference(&other, handle),
            Err(BrokerError::UnknownObject)
        );

        assert!(matches!(
            core.wait_event(&owner, handle),
            Ok(WaitOutcome::WouldBlock(_))
        ));

        assert_eq!(core.close_object_reference(&owner, handle), Ok(()));
        assert!(core.references.is_empty());
        assert!(core.objects.is_empty());
        assert_eq!(
            core.close_object_reference(&owner, handle),
            Err(BrokerError::UnknownObject)
        );

        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let _handle = core.create_event(&association).unwrap();
        assert_eq!(core.references.len(), 1);
        assert_eq!(core.objects.len(), 1);

        core.close_association(association);

        assert!(core.references.is_empty());
        assert!(core.objects.is_empty());

        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        core.next_reference_handle = u64::MAX;
        assert_eq!(
            core.create_event(&association),
            Err(BrokerError::ResourceExhausted)
        );
        assert!(core.references.is_empty());
        assert!(core.objects.is_empty());
    }
}
