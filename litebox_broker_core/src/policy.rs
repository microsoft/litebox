// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{BrokerError, CallerCredential, ObjectRights, ObjectType};

/// Broker operation submitted to the policy engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyOperation {
    /// Perform an operation on a broker-owned object type.
    Object {
        /// Broker-entry-authenticated credential for the caller.
        caller_credential: CallerCredential,
        /// Object type targeted by the operation.
        object_type: ObjectType,
        /// Operation requested for the object type.
        operation: ObjectOperation,
    },
}

/// Generic object operation submitted to the policy engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectOperation {
    /// Create a new broker-owned object.
    Create,
    /// Use an existing object handle with the requested rights.
    Use { rights: ObjectRights },
}

/// Policy decision returned after authorizing a broker operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyDecision {
    /// Operation is authorized and does not grant new authority material.
    Authorized,
    /// Object creation is authorized with rights for the initial object reference.
    GrantObjectReference {
        /// Rights to attach to the newly minted object reference.
        rights: ObjectRights,
    },
}

impl PolicyOperation {
    /// Creates a policy operation for creating a broker-owned object type.
    pub const fn create_object(
        caller_credential: CallerCredential,
        object_type: ObjectType,
    ) -> Self {
        Self::Object {
            caller_credential,
            object_type,
            operation: ObjectOperation::Create,
        }
    }

    /// Creates a policy operation for using a broker-owned object with rights.
    pub const fn use_object(
        caller_credential: CallerCredential,
        object_type: ObjectType,
        rights: ObjectRights,
    ) -> Self {
        Self::Object {
            caller_credential,
            object_type,
            operation: ObjectOperation::Use { rights },
        }
    }
}

/// Broker policy decision interface.
pub trait PolicyEngine {
    /// Authorizes or denies a broker operation.
    fn authorize(&mut self, operation: PolicyOperation) -> Result<PolicyDecision, BrokerError>;
}

/// Policy engine that denies every operation.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultDenyPolicy;

impl PolicyEngine for DefaultDenyPolicy {
    fn authorize(&mut self, _operation: PolicyOperation) -> Result<PolicyDecision, BrokerError> {
        Err(BrokerError::PolicyDenied)
    }
}

/// Policy engine that allows only the first POC event-object surface.
///
/// The current event create operation grants `WAIT | WRITE` on the initial
/// reference. Use requests may ask for any non-empty subset of those rights.
#[derive(Clone, Copy, Debug, Default)]
pub struct EventOnlyPolicy;

const EVENT_REFERENCE_RIGHTS: ObjectRights = ObjectRights::WAIT.union(ObjectRights::WRITE);

impl PolicyEngine for EventOnlyPolicy {
    fn authorize(&mut self, operation: PolicyOperation) -> Result<PolicyDecision, BrokerError> {
        match operation {
            PolicyOperation::Object {
                caller_credential: CallerCredential::Unauthenticated,
                object_type: ObjectType::Event,
                operation: ObjectOperation::Create,
            } => Ok(PolicyDecision::GrantObjectReference {
                rights: EVENT_REFERENCE_RIGHTS,
            }),
            PolicyOperation::Object {
                caller_credential: CallerCredential::Unauthenticated,
                object_type: ObjectType::Event,
                operation: ObjectOperation::Use { rights },
            } if !rights.is_empty() && EVENT_REFERENCE_RIGHTS.contains(rights) => {
                Ok(PolicyDecision::Authorized)
            }
            PolicyOperation::Object {
                object_type: ObjectType::Event,
                ..
            } => Err(BrokerError::PolicyDenied),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_only_policy_allows_only_current_event_surface() {
        let mut policy = EventOnlyPolicy;

        assert_eq!(
            policy.authorize(PolicyOperation::create_object(
                CallerCredential::Unauthenticated,
                ObjectType::Event
            )),
            Ok(PolicyDecision::GrantObjectReference {
                rights: ObjectRights::WAIT | ObjectRights::WRITE
            })
        );
        assert_eq!(
            policy.authorize(PolicyOperation::use_object(
                CallerCredential::Unauthenticated,
                ObjectType::Event,
                ObjectRights::WAIT
            )),
            Ok(PolicyDecision::Authorized)
        );
        assert_eq!(
            policy.authorize(PolicyOperation::use_object(
                CallerCredential::Unauthenticated,
                ObjectType::Event,
                ObjectRights::WRITE
            )),
            Ok(PolicyDecision::Authorized)
        );
        assert_eq!(
            policy.authorize(PolicyOperation::use_object(
                CallerCredential::Unauthenticated,
                ObjectType::Event,
                ObjectRights::WAIT | ObjectRights::WRITE
            )),
            Ok(PolicyDecision::Authorized)
        );
        assert_eq!(
            policy.authorize(PolicyOperation::use_object(
                CallerCredential::Unauthenticated,
                ObjectType::Event,
                ObjectRights::NONE
            )),
            Err(BrokerError::PolicyDenied)
        );
    }
}
