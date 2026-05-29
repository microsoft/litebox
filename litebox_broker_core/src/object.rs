// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use crate::event::EventObject;
use crate::identity::Association;
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

id_type! {
    /// Broker-owned object identifier.
    ObjectId
}

id_type! {
    /// Generation attached to a broker object.
    ObjectGeneration
}

id_type! {
    /// Broker-owned object reference identifier.
    ObjectReferenceId
}

id_type! {
    /// Generation attached to a broker object reference.
    ObjectReferenceGeneration
}

/// Broker-owned object handle returned by BrokerCore.
///
/// UserLiteBox may cache this value, but the broker remains authoritative for
/// object lifetime, reference lifetime, type, rights, and generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectHandle {
    /// Opaque broker object identifier.
    pub object_id: ObjectId,
    /// Object generation used to reject stale handles after object-slot reuse.
    pub object_generation: ObjectGeneration,
    /// Opaque broker reference identifier owned by one authenticated process association.
    pub reference_id: ObjectReferenceId,
    /// Reference generation used to reject stale handles after reference-slot reuse.
    pub reference_generation: ObjectReferenceGeneration,
}

impl ObjectHandle {
    /// Creates an object handle.
    pub const fn new(
        object_id: ObjectId,
        object_generation: ObjectGeneration,
        reference_id: ObjectReferenceId,
        reference_generation: ObjectReferenceGeneration,
    ) -> Self {
        Self {
            object_id,
            object_generation,
            reference_id,
            reference_generation,
        }
    }
}

const FIRST_OBJECT_GENERATION: ObjectGeneration = ObjectGeneration::new(1);
const FIRST_REFERENCE_GENERATION: ObjectReferenceGeneration = ObjectReferenceGeneration::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjectReference {
    pub(crate) object_id: ObjectId,
    /// Mirrors the referenced object's generation when this reference is minted.
    ///
    /// The duplicate lets stale-reference validation reject mismatched handles
    /// before trusting any object-table lookup; object validation below still
    /// checks the authoritative entry generation.
    pub(crate) object_generation: ObjectGeneration,
    pub(crate) reference_generation: ObjectReferenceGeneration,
    pub(crate) owner: Association,
    pub(crate) object_type: ObjectType,
    pub(crate) rights: ObjectRights,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjectEntry {
    pub(crate) generation: ObjectGeneration,
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
    /// The current POC never reuses object or reference slots, so both
    /// generations start at the authority-owned first generation. Any future
    /// slot-reuse path must bump the corresponding generation before reissuing
    /// a slot so stale handles cannot validate against a recycled entry.
    pub(crate) fn insert_object_with_reference(
        &mut self,
        association: Association,
        kind: ObjectKind,
        object_type: ObjectType,
        rights: ObjectRights,
    ) -> Result<ObjectHandle> {
        let object_id = self.allocate_object_id()?;
        let reference_id = self.allocate_reference_id()?;
        let object_generation = FIRST_OBJECT_GENERATION;
        let reference_generation = FIRST_REFERENCE_GENERATION;
        debug_assert_eq!(reference_generation, FIRST_REFERENCE_GENERATION);

        self.objects.insert(
            object_id,
            ObjectEntry {
                generation: object_generation,
                kind,
            },
        );
        self.references.insert(
            reference_id,
            ObjectReference {
                object_id,
                object_generation,
                reference_generation,
                owner: association,
                object_type,
                rights,
            },
        );

        Ok(ObjectHandle::new(
            object_id,
            object_generation,
            reference_id,
            reference_generation,
        ))
    }

    pub(crate) fn authorize_create_object(
        &mut self,
        association: Association,
        object_type: ObjectType,
    ) -> Result<()> {
        self.policy.authorize(PolicyOperation::create_object(
            association.caller_credential(),
            object_type,
        ))
    }

    pub(crate) fn authorize_object_use(
        &mut self,
        association: Association,
        handle: ObjectHandle,
        object_type: ObjectType,
        rights: ObjectRights,
    ) -> Result<()> {
        self.validate_handle(association, handle, object_type, rights)?;
        self.policy.authorize(PolicyOperation::use_object(
            association.caller_credential(),
            object_type,
            rights,
        ))
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
        association: Association,
        handle: ObjectHandle,
        expected_type: ObjectType,
        required_rights: ObjectRights,
    ) -> Result<()> {
        let reference = self
            .references
            .get(&handle.reference_id)
            .ok_or(BrokerError::UnknownObject)?;
        debug_assert_eq!(reference.reference_generation, FIRST_REFERENCE_GENERATION);
        if reference.owner != association {
            return Err(BrokerError::UnknownObject);
        }
        if reference.reference_generation != handle.reference_generation
            || reference.object_generation != handle.object_generation
            || reference.object_id != handle.object_id
        {
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
        debug_assert_eq!(reference.object_generation, object.generation);
        if object.generation != handle.object_generation {
            return Err(BrokerError::StaleHandle);
        }
        if object.kind.object_type() != expected_type {
            return Err(BrokerError::WrongObjectType);
        }

        Ok(())
    }

    fn allocate_object_id(&mut self) -> Result<ObjectId> {
        allocate_id(&mut self.next_object_id).map(ObjectId::new)
    }

    fn allocate_reference_id(&mut self) -> Result<ObjectReferenceId> {
        allocate_id(&mut self.next_reference_id).map(ObjectReferenceId::new)
    }
}

impl<P> BrokerCore<P> {
    pub(crate) fn close_association(&mut self, association: Association) {
        let reference_ids = self
            .references
            .iter()
            .filter_map(|(reference_id, reference)| {
                (reference.owner == association).then_some(*reference_id)
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
    use crate::{BrokerError, CallerCredential, DefaultDenyPolicy};

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
                association,
                ObjectKind::Event(EventObject::new()),
                ObjectType::Event,
                ObjectRights::WAIT,
            )
            .unwrap();

        assert_eq!(handle.object_id, ObjectId::new(u64::MAX));
        assert_eq!(handle.reference_id, ObjectReferenceId::new(u64::MAX));
        assert_eq!(core.next_object_id, 0);
        assert_eq!(core.next_reference_id, 0);
        assert_eq!(
            core.insert_object_with_reference(
                association,
                ObjectKind::Event(EventObject::new()),
                ObjectType::Event,
                ObjectRights::WAIT,
            ),
            Err(BrokerError::ResourceExhausted)
        );
    }

    #[test]
    fn validate_handle_rejects_reference_object_generation_mismatch() {
        let mut core = BrokerCore::new(DefaultDenyPolicy);
        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = core
            .insert_object_with_reference(
                association,
                ObjectKind::Event(EventObject::new()),
                ObjectType::Event,
                ObjectRights::WAIT,
            )
            .unwrap();

        core.references
            .get_mut(&handle.reference_id)
            .unwrap()
            .object_generation = ObjectGeneration::new(handle.object_generation.get() + 1);

        assert_eq!(
            core.validate_handle(association, handle, ObjectType::Event, ObjectRights::WAIT),
            Err(BrokerError::StaleHandle)
        );
    }

    #[test]
    fn validate_handle_rejects_stale_reference_generation() {
        let mut core = BrokerCore::new(DefaultDenyPolicy);
        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = core
            .insert_object_with_reference(
                association,
                ObjectKind::Event(EventObject::new()),
                ObjectType::Event,
                ObjectRights::WAIT,
            )
            .unwrap();
        let stale_handle = ObjectHandle::new(
            handle.object_id,
            handle.object_generation,
            handle.reference_id,
            ObjectReferenceGeneration::new(handle.reference_generation.get() + 1),
        );

        assert_eq!(
            core.validate_handle(
                association,
                stale_handle,
                ObjectType::Event,
                ObjectRights::WAIT
            ),
            Err(BrokerError::StaleHandle)
        );
    }
}
