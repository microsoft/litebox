// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::session::ObjectKind;
use crate::{BrokerError, CallerCredential, ObjectRights};

/// Configured broker policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyProfile {
    /// Deny every operation.
    DefaultDeny,
    /// Allow configured broker object operations.
    AllowObjects {
        /// Rights to attach to newly created object references.
        reference_rights: ObjectRights,
        /// Maximum object rights this policy may authorize for use requests.
        use_rights: ObjectRights,
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

    /// Creates a policy engine that allows configured broker object operations.
    pub const fn allow_objects() -> Self {
        Self::allow_objects_with_reference_rights(DEFAULT_OBJECT_RIGHTS)
    }

    /// Creates an object policy engine with explicit initial reference rights.
    ///
    /// Use authorization still allows the normal object rights; BrokerCore's
    /// reference validation enforces the rights on each created reference.
    pub const fn allow_objects_with_reference_rights(reference_rights: ObjectRights) -> Self {
        Self::new(PolicyProfile::AllowObjects {
            reference_rights,
            use_rights: DEFAULT_OBJECT_RIGHTS,
        })
    }

    pub(crate) fn authorize_create_object(
        &self,
        caller_credential: CallerCredential,
        object_kind: ObjectKind,
    ) -> Result<ObjectRights, BrokerError> {
        match (self.profile, object_kind) {
            (
                PolicyProfile::AllowObjects {
                    reference_rights, ..
                },
                ObjectKind::Event,
            ) if caller_credential == CallerCredential::Unauthenticated => Ok(reference_rights),
            (PolicyProfile::DefaultDeny | PolicyProfile::AllowObjects { .. }, _) => {
                Err(BrokerError::PolicyDenied)
            }
        }
    }

    pub(crate) fn authorize_use_object(
        &self,
        caller_credential: CallerCredential,
        object_kind: ObjectKind,
        rights: ObjectRights,
    ) -> Result<(), BrokerError> {
        match (self.profile, object_kind) {
            (PolicyProfile::AllowObjects { use_rights, .. }, ObjectKind::Event)
                if caller_credential == CallerCredential::Unauthenticated
                    && !rights.is_empty()
                    && use_rights.contains(rights) =>
            {
                Ok(())
            }
            (PolicyProfile::DefaultDeny | PolicyProfile::AllowObjects { .. }, _) => {
                Err(BrokerError::PolicyDenied)
            }
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::default_deny()
    }
}

/// Policy profile that allows configured broker object operations.
///
/// The default object create operation grants `WAIT | WRITE` on the initial
/// reference. Use requests may ask for any non-empty subset of configured object
/// use rights; BrokerCore separately enforces each reference's actual rights.
const DEFAULT_OBJECT_RIGHTS: ObjectRights = ObjectRights::WAIT.union(ObjectRights::WRITE);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_policy_allows_configured_object_surface() {
        let policy = PolicyEngine::allow_objects();

        assert_eq!(
            policy.authorize_create_object(CallerCredential::Unauthenticated, ObjectKind::Event),
            Ok(ObjectRights::WAIT | ObjectRights::WRITE)
        );
        assert_eq!(
            policy.authorize_use_object(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::WAIT
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_use_object(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::WRITE
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_use_object(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::WAIT | ObjectRights::WRITE
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_use_object(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::empty()
            ),
            Err(BrokerError::PolicyDenied)
        );
    }

    #[test]
    fn explicit_reference_rights_do_not_narrow_object_use_policy() {
        let policy = PolicyEngine::allow_objects_with_reference_rights(ObjectRights::WAIT);

        assert_eq!(
            policy.authorize_create_object(CallerCredential::Unauthenticated, ObjectKind::Event),
            Ok(ObjectRights::WAIT)
        );
        assert_eq!(
            policy.authorize_use_object(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::WRITE
            ),
            Ok(())
        );
    }
}
