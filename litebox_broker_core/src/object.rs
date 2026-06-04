// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::ops::BitOr;

use crate::event::EventObject;
use crate::identity::{AssociationIdentity, BrokerAssociation};
use crate::{BrokerCore, BrokerError, PolicyDecision, PolicyOperation, Result, allocate_id};
use litebox_broker_protocol::{ObjectHandle, ObjectReferenceGeneration, ObjectReferenceId};

/// Broker object type known to the authority core and policy engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ObjectType {
    /// Broker-owned event object.
    Event,
}

/// Broker rights attached to an object reference.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ObjectRights(u32);

impl ObjectRights {
    /// Empty rights set.
    pub const NONE: Self = Self(0);
    /// Right to wait for readiness.
    pub const WAIT: Self = Self(1 << 0);
    /// Right to mutate object state, such as adding event readiness credits.
    pub const WRITE: Self = Self(1 << 1);

    /// Returns true when no rights are present.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns true when all `required` rights are present.
    pub const fn contains(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }

    /// Returns the union of two rights sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl BitOr for ObjectRights {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

/// Broker-owned object identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ObjectId(u64);

impl ObjectId {
    /// Creates an object identifier from its raw value.
    const fn new(raw: u64) -> Self {
        Self(raw)
    }
}

const FIRST_REFERENCE_GENERATION: ObjectReferenceGeneration = ObjectReferenceGeneration::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjectReference {
    pub(crate) object_id: ObjectId,
    pub(crate) reference_generation: ObjectReferenceGeneration,
    pub(crate) owner: AssociationIdentity,
    pub(crate) object_type: ObjectType,
    pub(crate) rights: ObjectRights,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjectEntry {
    pub(crate) kind: ObjectKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectKind {
    Event(EventObject),
}

impl ObjectKind {
    pub(crate) const fn object_type(self) -> ObjectType {
        match self {
            Self::Event(_) => ObjectType::Event,
        }
    }
}

impl BrokerCore {
    /// Inserts a broker object and mints its first owned reference.
    ///
    /// The current POC never reuses reference slots, so the reference
    /// generation starts at the authority-owned first generation. Any future
    /// reference-slot reuse path must bump the generation before reissuing a
    /// slot so stale handles cannot validate against a recycled reference.
    pub(crate) fn insert_object_with_reference(
        &mut self,
        association: &BrokerAssociation,
        kind: ObjectKind,
        object_type: ObjectType,
        rights: ObjectRights,
    ) -> Result<ObjectHandle> {
        if self.objects.len() >= self.limits.max_objects
            || self.references.len() >= self.limits.max_references
        {
            return Err(BrokerError::ResourceExhausted);
        }

        let object_id = self.allocate_object_id()?;
        let reference_id = self.allocate_reference_id()?;
        let reference_generation = FIRST_REFERENCE_GENERATION;

        self.objects.insert(object_id, ObjectEntry { kind });
        self.references.insert(
            reference_id,
            ObjectReference {
                object_id,
                reference_generation,
                owner: association.identity(),
                object_type,
                rights,
            },
        );

        Ok(ObjectHandle::new(reference_id, reference_generation))
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
            .get(&object_id)
            .ok_or(BrokerError::UnknownObject)
    }

    pub(crate) fn object_mut(&mut self, object_id: ObjectId) -> Result<&mut ObjectEntry> {
        self.objects
            .get_mut(&object_id)
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
        if reference.object_type != expected_type {
            return Err(BrokerError::WrongObjectType);
        }
        if !reference.rights.contains(required_rights) {
            return Err(BrokerError::InvalidRights);
        }

        let object = self
            .objects
            .get(&reference.object_id)
            .ok_or(BrokerError::UnknownObject)?;
        if object.kind.object_type() != expected_type {
            return Err(BrokerError::WrongObjectType);
        }

        Ok(*reference)
    }

    fn allocate_object_id(&mut self) -> Result<ObjectId> {
        allocate_id(&mut self.next_object_id).map(ObjectId::new)
    }

    fn allocate_reference_id(&mut self) -> Result<ObjectReferenceId> {
        allocate_id(&mut self.next_reference_id).map(ObjectReferenceId::new)
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
        if !self.objects.contains_key(&object_id) {
            return Err(BrokerError::UnknownObject);
        }

        self.references.remove(&handle.reference_id);
        self.drop_object_if_unreferenced(object_id);
        Ok(())
    }

    /// Closes a broker association and releases references owned by it.
    pub fn close_association(&mut self, association: BrokerAssociation) {
        let identity = association.identity();
        self.references
            .retain(|_, reference| reference.owner != identity);
        let references = &self.references;
        self.objects.retain(|object_id, _| {
            references
                .values()
                .any(|reference| reference.object_id == *object_id)
        });
    }

    fn reference_for_handle(
        &self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
    ) -> Result<&ObjectReference> {
        let reference = self
            .references
            .get(&handle.reference_id)
            .ok_or(BrokerError::UnknownObject)?;
        if reference.owner != association.identity() {
            return Err(BrokerError::UnknownObject);
        }
        if reference.reference_generation != handle.reference_generation {
            return Err(BrokerError::StaleHandle);
        }
        Ok(reference)
    }

    fn drop_object_if_unreferenced(&mut self, object_id: ObjectId) {
        if !self
            .references
            .values()
            .any(|reference| reference.object_id == object_id)
        {
            self.objects.remove(&object_id);
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
    use crate::{BrokerCoreLimits, BrokerError, CallerCredential, PolicyEngine};

    #[test]
    fn object_and_reference_allocators_issue_max_id_then_exhaust() {
        let mut core = BrokerCore::new(PolicyEngine::default_deny());
        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        core.next_object_id = u64::MAX;
        core.next_reference_id = u64::MAX;

        let handle = core
            .insert_object_with_reference(
                &association,
                ObjectKind::Event(EventObject::new(0)),
                ObjectType::Event,
                ObjectRights::WAIT,
            )
            .unwrap();

        assert_eq!(handle.reference_id, ObjectReferenceId::new(u64::MAX));
        assert_eq!(core.next_object_id, 0);
        assert_eq!(core.next_reference_id, 0);
        assert_eq!(
            core.insert_object_with_reference(
                &association,
                ObjectKind::Event(EventObject::new(0)),
                ObjectType::Event,
                ObjectRights::WAIT,
            ),
            Err(BrokerError::ResourceExhausted)
        );
    }

    #[test]
    fn insert_object_with_reference_enforces_object_and_reference_limits() {
        let mut object_limited =
            BrokerCore::new_with_limits(PolicyEngine::event_only(), BrokerCoreLimits::new(0, 1));
        let association = object_limited
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();

        assert_eq!(
            object_limited.create_event(&association),
            Err(BrokerError::ResourceExhausted)
        );

        let mut reference_limited =
            BrokerCore::new_with_limits(PolicyEngine::event_only(), BrokerCoreLimits::new(1, 0));
        let association = reference_limited
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();

        assert_eq!(
            reference_limited.create_event(&association),
            Err(BrokerError::ResourceExhausted)
        );
    }

    #[test]
    fn close_association_releases_owned_references_and_orphaned_objects() {
        let mut core = BrokerCore::new(PolicyEngine::event_only());
        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();

        let _handle = core.create_event(&association).unwrap();
        assert_eq!(core.references.len(), 1);
        assert_eq!(core.objects.len(), 1);

        core.close_association(association);

        assert!(core.references.is_empty());
        assert!(core.objects.is_empty());
    }

    #[test]
    fn foreign_core_association_cannot_authorize_matching_handle_values() {
        let mut owner_core = BrokerCore::new(PolicyEngine::event_only());
        let owner = owner_core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = owner_core.create_event(&owner).unwrap();

        let mut other_core = BrokerCore::new(PolicyEngine::event_only());
        let other = other_core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let other_handle = other_core.create_event(&other).unwrap();
        assert_eq!(handle, other_handle);

        assert_eq!(
            other_core.wait_event(&owner, handle),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn close_object_reference_releases_reference_and_orphaned_object() {
        let mut core = BrokerCore::new(PolicyEngine::event_only());
        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = core.create_event(&association).unwrap();

        assert_eq!(core.close_object_reference(&association, handle), Ok(()));
        assert!(core.references.is_empty());
        assert!(core.objects.is_empty());
        assert_eq!(
            core.close_object_reference(&association, handle),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn close_object_reference_rejects_stale_and_foreign_handles() {
        let mut core = BrokerCore::new(PolicyEngine::event_only());
        let owner = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let other = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = core.create_event(&owner).unwrap();

        assert_eq!(
            core.close_object_reference(&other, handle),
            Err(BrokerError::UnknownObject)
        );

        let stale = ObjectHandle::new(
            handle.reference_id,
            ObjectReferenceGeneration::new(handle.reference_generation.get() + 1),
        );
        assert_eq!(
            core.close_object_reference(&owner, stale),
            Err(BrokerError::StaleHandle)
        );
        assert!(matches!(
            core.wait_event(&owner, handle),
            Ok(litebox_broker_protocol::WaitOutcome::WouldBlock(_))
        ));
    }
}
