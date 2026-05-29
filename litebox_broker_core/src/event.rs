// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::object::{ObjectId, ObjectKind};
use crate::{
    BrokerAssociation, BrokerCore, BrokerError, ObjectHandle, ObjectRights, ObjectType,
    PolicyEngine, Result,
};

/// Event readiness snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadinessState {
    /// Whether the event is currently ready.
    pub ready: bool,
    /// Monotonic generation incremented on readiness changes.
    pub generation: u64,
}

impl ReadinessState {
    /// Creates a readiness snapshot.
    pub const fn new(ready: bool, generation: u64) -> Self {
        Self { ready, generation }
    }
}

/// Result of checking an event wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WaitOutcome {
    /// The event was ready and a nonblocking wait would complete.
    Ready(ReadinessState),
    /// The event was not ready and a blocking wait would sleep.
    WouldBlock(ReadinessState),
}

impl<P: PolicyEngine> BrokerCore<P> {
    /// Creates a broker-owned event object.
    pub fn create_event(&mut self, association: &BrokerAssociation) -> Result<ObjectHandle> {
        let rights = self.authorize_create_object(association, ObjectType::Event)?;

        self.insert_object_with_reference(
            association,
            ObjectKind::Event(EventObject::new()),
            ObjectType::Event,
            rights,
        )
    }

    /// Checks whether an event wait would complete now.
    ///
    /// Blocking is intentionally outside BrokerCore for the first proof of
    /// concept. Userland or kernel deployments can block on deployment-specific
    /// wait primitives after BrokerCore authorizes and reports readiness state.
    pub fn wait_event(
        &mut self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
    ) -> Result<WaitOutcome> {
        let object_id =
            self.authorize_use_object(association, handle, ObjectType::Event, ObjectRights::WAIT)?;
        let state = self.event_state(object_id)?;
        Ok(if state.ready {
            WaitOutcome::Ready(state)
        } else {
            WaitOutcome::WouldBlock(state)
        })
    }

    /// Signals a broker-owned event object.
    pub fn signal_event(
        &mut self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
    ) -> Result<ReadinessState> {
        let object_id =
            self.authorize_use_object(association, handle, ObjectType::Event, ObjectRights::WRITE)?;
        match &mut self.object_mut(object_id)?.kind {
            ObjectKind::Event(event) => event.signal(),
        }
    }

    fn event_state(&self, object_id: ObjectId) -> Result<ReadinessState> {
        match &self.object(object_id)?.kind {
            ObjectKind::Event(event) => Ok(event.readiness_state()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EventObject {
    ready: bool,
    readiness_generation: u64,
}

impl EventObject {
    pub(crate) const fn new() -> Self {
        Self {
            ready: false,
            readiness_generation: 0,
        }
    }

    pub(crate) const fn readiness_state(self) -> ReadinessState {
        ReadinessState::new(self.ready, self.readiness_generation)
    }

    fn signal(&mut self) -> Result<ReadinessState> {
        self.ready = true;
        self.readiness_generation = self
            .readiness_generation
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(self.readiness_state())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BrokerCore, CallerCredential, EventOnlyPolicy, ObjectOperation, ObjectReferenceGeneration,
        PolicyDecision, PolicyEngine, PolicyOperation,
    };

    #[test]
    fn wait_rejects_reference_without_wait_right() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = core
            .insert_object_with_reference(
                &association,
                ObjectKind::Event(EventObject::new()),
                ObjectType::Event,
                ObjectRights::WRITE,
            )
            .unwrap();

        assert_eq!(
            core.wait_event(&association, handle),
            Err(BrokerError::InvalidRights)
        );
    }

    #[test]
    fn wait_rejects_stale_reference_generation() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let mut handle = core.create_event(&association).unwrap();
        handle.reference_generation =
            ObjectReferenceGeneration::new(handle.reference_generation.get() + 1);

        assert_eq!(
            core.wait_event(&association, handle),
            Err(BrokerError::StaleHandle)
        );
    }

    #[test]
    fn wait_hides_handle_owned_by_another_association() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let owner = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let other = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = core.create_event(&owner).unwrap();

        assert_eq!(
            core.wait_event(&other, handle),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn create_event_uses_policy_granted_reference_rights() {
        let mut core = BrokerCore::new(WaitOnlyCreatePolicy);
        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();

        let handle = core.create_event(&association).unwrap();

        assert!(matches!(
            core.wait_event(&association, handle),
            Ok(WaitOutcome::WouldBlock(_))
        ));
        assert_eq!(
            core.signal_event(&association, handle),
            Err(BrokerError::InvalidRights)
        );
    }

    struct WaitOnlyCreatePolicy;

    impl PolicyEngine for WaitOnlyCreatePolicy {
        fn authorize(&mut self, operation: PolicyOperation) -> Result<PolicyDecision> {
            match operation {
                PolicyOperation::Object {
                    object_type: ObjectType::Event,
                    operation: ObjectOperation::Create,
                    ..
                } => Ok(PolicyDecision::GrantObjectReference {
                    rights: ObjectRights::WAIT,
                }),
                PolicyOperation::Object {
                    object_type: ObjectType::Event,
                    operation: ObjectOperation::Use { .. },
                    ..
                } => Ok(PolicyDecision::Authorized),
            }
        }
    }
}
