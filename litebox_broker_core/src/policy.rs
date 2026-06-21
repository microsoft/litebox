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
    /// Static rights for known broker principals.
    Static {
        /// Rights for the unauthenticated principal used by the initial POC.
        unauthenticated: PrincipalRights,
    },
}

/// Rights granted to one broker principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrincipalRights {
    /// Rights for event objects.
    pub event: ObjectRights,
}

impl PrincipalRights {
    /// Grants all currently supported object rights.
    pub const fn all() -> Self {
        Self {
            event: ObjectRights::WAIT.union(ObjectRights::WRITE),
        }
    }

    fn object_rights(self, object_kind: ObjectKind) -> ObjectRights {
        match object_kind {
            ObjectKind::Event => self.event,
        }
    }
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

    /// Creates a policy engine with rights for the unauthenticated principal.
    pub const fn with_unauthenticated_rights(unauthenticated: PrincipalRights) -> Self {
        Self::new(PolicyProfile::Static { unauthenticated })
    }

    pub(crate) fn authorize_object_rights(
        &self,
        caller_credential: CallerCredential,
        object_kind: ObjectKind,
        rights: ObjectRights,
    ) -> Result<(), BrokerError> {
        let principal_rights = match (self.profile, caller_credential) {
            (PolicyProfile::Static { unauthenticated }, CallerCredential::Unauthenticated) => {
                unauthenticated
            }
            (PolicyProfile::DefaultDeny, _) => return Err(BrokerError::PolicyDenied),
        };
        if rights.is_empty() {
            return Err(BrokerError::InvalidRights);
        }
        if !principal_rights.object_rights(object_kind).contains(rights) {
            return Err(BrokerError::PolicyDenied);
        }
        Ok(())
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::default_deny()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_policy_allows_configured_principal_rights() {
        let policy = PolicyEngine::with_unauthenticated_rights(PrincipalRights::all());

        assert_eq!(
            policy.authorize_object_rights(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::WAIT | ObjectRights::WRITE
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_object_rights(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::WAIT
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_object_rights(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::WRITE
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_object_rights(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::WAIT | ObjectRights::WRITE
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_object_rights(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::empty()
            ),
            Err(BrokerError::InvalidRights)
        );
    }

    #[test]
    fn object_rights_must_fit_principal_rights() {
        let policy = PolicyEngine::with_unauthenticated_rights(PrincipalRights {
            event: ObjectRights::WAIT,
        });

        assert_eq!(
            policy.authorize_object_rights(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::WAIT
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_object_rights(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::WAIT | ObjectRights::WRITE
            ),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            policy.authorize_object_rights(
                CallerCredential::Unauthenticated,
                ObjectKind::Event,
                ObjectRights::WRITE
            ),
            Err(BrokerError::PolicyDenied)
        );
    }
}
