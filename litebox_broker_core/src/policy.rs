// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{ObjectRights, ObjectType};
use litebox_broker_protocol::ErrorCode;
use litebox_broker_transport::PeerCredential;

/// Broker operation submitted to the policy engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyOperation {
    /// Perform an operation on a broker-owned object type.
    Object {
        /// Transport-authenticated peer credential for the caller.
        peer_credential: PeerCredential,
        object_type: ObjectType,
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

impl PolicyOperation {
    /// Creates a policy operation for creating a broker-owned object type.
    pub const fn create_object(peer_credential: PeerCredential, object_type: ObjectType) -> Self {
        Self::Object {
            peer_credential,
            object_type,
            operation: ObjectOperation::Create,
        }
    }

    /// Creates a policy operation for using a broker-owned object with rights.
    pub const fn use_object(
        peer_credential: PeerCredential,
        object_type: ObjectType,
        rights: ObjectRights,
    ) -> Self {
        Self::Object {
            peer_credential,
            object_type,
            operation: ObjectOperation::Use { rights },
        }
    }
}

/// Broker policy decision interface.
pub trait PolicyEngine {
    /// Authorizes or denies a broker operation.
    fn authorize(&mut self, operation: PolicyOperation) -> Result<(), ErrorCode>;
}

/// Policy engine that denies every operation.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultDenyPolicy;

impl PolicyEngine for DefaultDenyPolicy {
    fn authorize(&mut self, _operation: PolicyOperation) -> Result<(), ErrorCode> {
        Err(ErrorCode::PolicyDenied)
    }
}

/// Policy engine that allows only the first POC event-object surface.
///
/// The current event methods request exactly one operation right at a time:
/// `WAIT` for wait and `WRITE` for signal. Combined-right use requests are
/// intentionally denied until an event method that needs combined rights is
/// designed.
#[derive(Clone, Copy, Debug, Default)]
pub struct EventOnlyPolicy;

impl PolicyEngine for EventOnlyPolicy {
    fn authorize(&mut self, operation: PolicyOperation) -> Result<(), ErrorCode> {
        match operation {
            PolicyOperation::Object {
                peer_credential: PeerCredential::Unauthenticated,
                object_type: ObjectType::Event,
                operation: ObjectOperation::Create,
            } => Ok(()),
            PolicyOperation::Object {
                peer_credential: PeerCredential::Unauthenticated,
                object_type: ObjectType::Event,
                operation: ObjectOperation::Use { rights },
            } if rights == ObjectRights::WAIT || rights == ObjectRights::WRITE => Ok(()),
            PolicyOperation::Object {
                object_type: ObjectType::Event,
                ..
            } => Err(ErrorCode::PolicyDenied),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_transport::PeerCredential;

    #[test]
    fn event_only_policy_allows_only_current_event_surface() {
        let mut policy = EventOnlyPolicy;

        assert_eq!(
            policy.authorize(PolicyOperation::create_object(
                PeerCredential::Unauthenticated,
                ObjectType::Event
            )),
            Ok(())
        );
        assert_eq!(
            policy.authorize(PolicyOperation::use_object(
                PeerCredential::Unauthenticated,
                ObjectType::Event,
                ObjectRights::WAIT
            )),
            Ok(())
        );
        assert_eq!(
            policy.authorize(PolicyOperation::use_object(
                PeerCredential::Unauthenticated,
                ObjectType::Event,
                ObjectRights::WRITE
            )),
            Ok(())
        );
        assert_eq!(
            policy.authorize(PolicyOperation::use_object(
                PeerCredential::Unauthenticated,
                ObjectType::Event,
                ObjectRights::WAIT | ObjectRights::WRITE
            )),
            Err(ErrorCode::PolicyDenied)
        );
    }
}
