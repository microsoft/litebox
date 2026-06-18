// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{BrokerError, CallerCredential, ObjectRights};

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

    pub(crate) fn authorize_create_event(
        &mut self,
        caller_credential: CallerCredential,
    ) -> Result<ObjectRights, BrokerError> {
        match self.profile {
            PolicyProfile::DefaultDeny => Err(BrokerError::PolicyDenied),
            PolicyProfile::EventOnly {
                event_reference_rights,
                ..
            } => authorize_create_event(event_reference_rights, caller_credential),
        }
    }

    pub(crate) fn authorize_use_event(
        &mut self,
        caller_credential: CallerCredential,
        rights: ObjectRights,
    ) -> Result<(), BrokerError> {
        match self.profile {
            PolicyProfile::DefaultDeny => Err(BrokerError::PolicyDenied),
            PolicyProfile::EventOnly {
                event_use_rights, ..
            } => authorize_use_event(event_use_rights, caller_credential, rights),
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

fn authorize_create_event(
    event_reference_rights: ObjectRights,
    caller_credential: CallerCredential,
) -> Result<ObjectRights, BrokerError> {
    if caller_credential == CallerCredential::Unauthenticated {
        Ok(event_reference_rights)
    } else {
        Err(BrokerError::PolicyDenied)
    }
}

fn authorize_use_event(
    event_use_rights: ObjectRights,
    caller_credential: CallerCredential,
    rights: ObjectRights,
) -> Result<(), BrokerError> {
    if caller_credential == CallerCredential::Unauthenticated
        && !rights.is_empty()
        && event_use_rights.contains(rights)
    {
        Ok(())
    } else {
        Err(BrokerError::PolicyDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_only_policy_allows_only_current_event_surface() {
        let mut policy = PolicyEngine::event_only();

        assert_eq!(
            policy.authorize_create_event(CallerCredential::Unauthenticated),
            Ok(ObjectRights::WAIT | ObjectRights::WRITE)
        );
        assert_eq!(
            policy.authorize_use_event(CallerCredential::Unauthenticated, ObjectRights::WAIT),
            Ok(())
        );
        assert_eq!(
            policy.authorize_use_event(CallerCredential::Unauthenticated, ObjectRights::WRITE),
            Ok(())
        );
        assert_eq!(
            policy.authorize_use_event(
                CallerCredential::Unauthenticated,
                ObjectRights::WAIT | ObjectRights::WRITE
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_use_event(CallerCredential::Unauthenticated, ObjectRights::empty()),
            Err(BrokerError::PolicyDenied)
        );
    }

    #[test]
    fn explicit_event_reference_rights_do_not_narrow_event_use_policy() {
        let mut policy = PolicyEngine::event_only_with_reference_rights(ObjectRights::WAIT);

        assert_eq!(
            policy.authorize_create_event(CallerCredential::Unauthenticated),
            Ok(ObjectRights::WAIT)
        );
        assert_eq!(
            policy.authorize_use_event(CallerCredential::Unauthenticated, ObjectRights::WRITE),
            Ok(())
        );
    }
}
