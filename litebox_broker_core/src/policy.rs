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

/// Configured broker policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyProfile {
    /// Deny every operation.
    DefaultDeny,
    /// Allow the current event-object surface.
    EventOnly {
        /// Rights to attach to newly created event references.
        event_reference_rights: ObjectRights,
        /// Maximum event rights this policy may authorize for use requests.
        event_use_rights: ObjectRights,
    },
}

/// Broker policy decision and audit component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEngine {
    profile: PolicyProfile,
}

impl PolicyEngine {
    /// Creates a policy engine from a policy profile.
    pub const fn new(profile: PolicyProfile) -> Self {
        Self { profile }
    }

    /// Creates a policy engine that denies every operation.
    pub const fn default_deny() -> Self {
        Self::new(PolicyProfile::DefaultDeny)
    }

    /// Creates a policy engine that allows only the current event-object surface.
    pub const fn event_only() -> Self {
        Self::event_only_with_reference_rights(EVENT_REFERENCE_RIGHTS)
    }

    /// Creates an event-only policy engine with explicit initial reference rights.
    ///
    /// Use authorization still allows the normal event-only rights; BrokerCore's
    /// reference validation enforces the rights on each created reference.
    pub const fn event_only_with_reference_rights(event_reference_rights: ObjectRights) -> Self {
        Self::new(PolicyProfile::EventOnly {
            event_reference_rights,
            event_use_rights: EVENT_REFERENCE_RIGHTS,
        })
    }

    /// Authorizes or denies a broker operation.
    pub(crate) fn authorize(
        &mut self,
        operation: PolicyOperation,
    ) -> Result<PolicyDecision, BrokerError> {
        match self.profile {
            PolicyProfile::DefaultDeny => Err(BrokerError::PolicyDenied),
            PolicyProfile::EventOnly {
                event_reference_rights,
                event_use_rights,
            } => authorize_event_only(event_reference_rights, event_use_rights, operation),
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::default_deny()
    }
}

/// Policy profile that allows only the current event-object surface.
///
/// The default event create operation grants `WAIT | WRITE` on the initial
/// reference. Use requests may ask for any non-empty subset of configured event
/// use rights; BrokerCore separately enforces each reference's actual rights.
const EVENT_REFERENCE_RIGHTS: ObjectRights = ObjectRights::WAIT.union(ObjectRights::WRITE);

fn authorize_event_only(
    event_reference_rights: ObjectRights,
    event_use_rights: ObjectRights,
    operation: PolicyOperation,
) -> Result<PolicyDecision, BrokerError> {
    match operation {
        PolicyOperation::Object {
            caller_credential: CallerCredential::Unauthenticated,
            object_type: ObjectType::Event,
            operation: ObjectOperation::Create,
        } => Ok(PolicyDecision::GrantObjectReference {
            rights: event_reference_rights,
        }),
        PolicyOperation::Object {
            caller_credential: CallerCredential::Unauthenticated,
            object_type: ObjectType::Event,
            operation: ObjectOperation::Use { rights },
        } if !rights.is_empty() && event_use_rights.contains(rights) => {
            Ok(PolicyDecision::Authorized)
        }
        PolicyOperation::Object {
            object_type: ObjectType::Event,
            ..
        } => Err(BrokerError::PolicyDenied),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_only_policy_allows_only_current_event_surface() {
        let mut policy = PolicyEngine::event_only();

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

    #[test]
    fn explicit_event_reference_rights_do_not_narrow_event_use_policy() {
        let mut policy = PolicyEngine::event_only_with_reference_rights(ObjectRights::WAIT);

        assert_eq!(
            policy.authorize(PolicyOperation::create_object(
                CallerCredential::Unauthenticated,
                ObjectType::Event
            )),
            Ok(PolicyDecision::GrantObjectReference {
                rights: ObjectRights::WAIT
            })
        );
        assert_eq!(
            policy.authorize(PolicyOperation::use_object(
                CallerCredential::Unauthenticated,
                ObjectType::Event,
                ObjectRights::WRITE
            )),
            Ok(PolicyDecision::Authorized)
        );
    }
}
