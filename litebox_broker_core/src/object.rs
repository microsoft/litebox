// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use crate::event::EventObject;
use crate::identity::{AssociationIdentity, BrokerAssociation};
use crate::{
    BrokerCore, BrokerError, ObjectRights, ObjectType, PolicyEngine, PolicyOperation, Result,
    allocate_id,
};

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Creates an identifier from its raw value.
            pub const fn new(raw: u64) -> Self {
                Self(raw)
            }

            /// Returns the raw identifier value.
            pub const fn get(self) -> u64 {
                self.0
            }
        }
    };
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

id_type! {
    /// Broker-owned object reference identifier.
    ObjectReferenceId
}

id_type! {
    /// Generation attached to a broker object reference.
    ObjectReferenceGeneration
}

/// Broker-owned reference handle returned by BrokerCore.
///
/// UserLiteBox may cache this value, but the broker remains authoritative for
/// object identity, object lifetime, reference lifetime, type, rights, and
/// reference generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectHandle {
    /// Opaque broker reference identifier owned by one authenticated process association.
    pub reference_id: ObjectReferenceId,
    /// Reference generation used to reject stale handles after reference-slot reuse.
    pub reference_generation: ObjectReferenceGeneration,
}

impl ObjectHandle {
    /// Creates an object handle.
    pub const fn new(
        reference_id: ObjectReferenceId,
        reference_generation: ObjectReferenceGeneration,
    ) -> Self {
        Self {
            reference_id,
            reference_generation,
        }
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

impl<P: PolicyEngine> BrokerCore<P> {
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
    ) -> Result<()> {
        self.policy.authorize(PolicyOperation::create_object(
            association.caller_credential(),
            object_type,
        ))
    }

    pub(crate) fn authorize_use_object(
        &mut self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
        object_type: ObjectType,
        rights: ObjectRights,
    ) -> Result<ObjectId> {
        let object_id = self.validate_handle(association, handle, object_type, rights)?;
        self.policy.authorize(PolicyOperation::use_object(
            association.caller_credential(),
            object_type,
            rights,
        ))?;
        Ok(object_id)
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
    ) -> Result<ObjectId> {
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

        Ok(reference.object_id)
    }

    fn allocate_object_id(&mut self) -> Result<ObjectId> {
        allocate_id(&mut self.next_object_id).map(ObjectId::new)
    }

    fn allocate_reference_id(&mut self) -> Result<ObjectReferenceId> {
        allocate_id(&mut self.next_reference_id).map(ObjectReferenceId::new)
    }
}

impl<P> BrokerCore<P> {
    /// Closes a broker association and releases references owned by it.
    pub fn close_association(&mut self, association: BrokerAssociation) {
        let identity = association.identity();
        let reference_ids = self
            .references
            .iter()
            .filter_map(|(reference_id, reference)| {
                (reference.owner == identity).then_some(*reference_id)
            })
            .collect::<Vec<_>>();

        for reference_id in reference_ids {
            self.references.remove(&reference_id);
        }

        let object_ids = self
            .objects
            .keys()
            .copied()
            .filter(|object_id| {
                !self
                    .references
                    .values()
                    .any(|reference| reference.object_id == *object_id)
            })
            .collect::<Vec<_>>();

        for object_id in object_ids {
            self.objects.remove(&object_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrokerError, CallerCredential, DefaultDenyPolicy, EventOnlyPolicy};

    #[test]
    fn object_and_reference_allocators_issue_max_id_then_exhaust() {
        let mut core = BrokerCore::new(DefaultDenyPolicy);
        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        core.next_object_id = u64::MAX;
        core.next_reference_id = u64::MAX;

        let handle = core
            .insert_object_with_reference(
                &association,
                ObjectKind::Event(EventObject::new()),
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
                ObjectKind::Event(EventObject::new()),
                ObjectType::Event,
                ObjectRights::WAIT,
            ),
            Err(BrokerError::ResourceExhausted)
        );
    }

    #[test]
    fn close_association_releases_owned_references_and_orphaned_objects() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
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
}
