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
#[non_exhaustive]
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

    pub(crate) fn principal_object_rights(
        &self,
        caller_credential: CallerCredential,
        object_kind: ObjectKind,
    ) -> Result<ObjectRights, BrokerError> {
        let principal_rights = match (self.profile, caller_credential) {
            (PolicyProfile::Static { unauthenticated }, CallerCredential::Unauthenticated) => {
                unauthenticated
            }
            (PolicyProfile::DefaultDeny, _) => return Err(BrokerError::PolicyDenied),
        };
        let rights = principal_rights.object_rights(object_kind);
        if rights.is_empty() {
            return Err(BrokerError::PolicyDenied);
        }
        Ok(rights)
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
            policy.principal_object_rights(CallerCredential::Unauthenticated, ObjectKind::Event),
            Ok(ObjectRights::WAIT | ObjectRights::WRITE)
        );
    }

    #[test]
    fn static_policy_returns_configured_principal_rights() {
        let policy = PolicyEngine::with_unauthenticated_rights(PrincipalRights {
            event: ObjectRights::WAIT,
        });

        assert_eq!(
            policy.principal_object_rights(CallerCredential::Unauthenticated, ObjectKind::Event),
            Ok(ObjectRights::WAIT)
        );
    }

    #[test]
    fn empty_principal_rights_deny_object_authorization() {
        let policy = PolicyEngine::with_unauthenticated_rights(PrincipalRights {
            event: ObjectRights::empty(),
        });

        assert_eq!(
            policy.principal_object_rights(CallerCredential::Unauthenticated, ObjectKind::Event),
            Err(BrokerError::PolicyDenied)
        );
    }
}
