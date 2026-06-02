// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::object::{ObjectId, ObjectKind};
use crate::{
    BrokerAssociation, BrokerCore, BrokerError, ObjectHandle, ObjectRights, ObjectType,
    PolicyEngine, Result,
};
use litebox_broker_protocol::{
    ConsumeEventResponse, EventConsumeMode, ReadinessState, WaitOutcome,
};

const MAX_EVENT_COUNT: u64 = u64::MAX - 1;

impl<P: PolicyEngine> BrokerCore<P> {
    /// Creates a broker-owned event object.
    pub fn create_event(&mut self, association: &BrokerAssociation) -> Result<ObjectHandle> {
        self.create_event_with_count(association, 0)
    }

    /// Creates a broker-owned event object with initial readiness credits.
    pub fn create_event_with_count(
        &mut self,
        association: &BrokerAssociation,
        initial_count: u64,
    ) -> Result<ObjectHandle> {
        if initial_count > MAX_EVENT_COUNT {
            return Err(BrokerError::ResourceExhausted);
        }
        let rights = self.authorize_create_object(association, ObjectType::Event)?;

        self.insert_object_with_reference(
            association,
            ObjectKind::Event(EventObject::new(initial_count)),
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

    /// Adds readiness credits to a broker-owned event object.
    pub fn add_event(
        &mut self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
        value: u64,
    ) -> Result<ReadinessState> {
        let object_id =
            self.authorize_use_object(association, handle, ObjectType::Event, ObjectRights::WRITE)?;
        match &mut self.object_mut(object_id)?.kind {
            ObjectKind::Event(event) => event.add(value),
        }
    }

    /// Consumes readiness credits from a broker-owned event object.
    pub fn consume_event(
        &mut self,
        association: &BrokerAssociation,
        handle: ObjectHandle,
        mode: EventConsumeMode,
    ) -> Result<ConsumeEventResponse> {
        let object_id =
            self.authorize_use_object(association, handle, ObjectType::Event, ObjectRights::WAIT)?;
        match &mut self.object_mut(object_id)?.kind {
            ObjectKind::Event(event) => event.consume(mode),
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
    count: u64,
    readiness_generation: u64,
}

impl EventObject {
    pub(crate) const fn new(count: u64) -> Self {
        Self {
            count,
            readiness_generation: 0,
        }
    }

    pub(crate) const fn readiness_state(self) -> ReadinessState {
        ReadinessState::new(self.count > 0, self.readiness_generation)
    }

    fn add(&mut self, value: u64) -> Result<ReadinessState> {
        let new_count = self
            .count
            .checked_add(value)
            .filter(|count| *count <= MAX_EVENT_COUNT)
            .ok_or(BrokerError::WouldBlock)?;
        self.count = new_count;
        self.bump_generation()?;
        Ok(self.readiness_state())
    }

    fn consume(&mut self, mode: EventConsumeMode) -> Result<ConsumeEventResponse> {
        if self.count == 0 {
            return Err(BrokerError::WouldBlock);
        }

        let value = match mode {
            EventConsumeMode::All => self.count,
            EventConsumeMode::One => 1,
            _ => return Err(BrokerError::UnsupportedOperation),
        };
        self.count -= value;
        self.bump_generation()?;
        Ok(ConsumeEventResponse::new(value, self.readiness_state()))
    }

    fn bump_generation(&mut self) -> Result<()> {
        self.readiness_generation = self
            .readiness_generation
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(())
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
                ObjectKind::Event(EventObject::new(0)),
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
            core.add_event(&association, handle, 1),
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
