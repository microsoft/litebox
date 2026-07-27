// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{BrokerError, CallerCredential, ObjectRights};
use litebox_broker_protocol::socket::{
    AddressFamily, CreateSocketRequest, IpProtocol, SocketAddressV4, SocketError, SocketType,
};

/// Network access available to broker-owned sockets.
///
/// This is separate from [`PolicyProfile`] because that profile grants generic
/// object rights shared by events, pipes, and sockets. Granting those rights
/// must not implicitly grant network access, so socket creation and destination
/// restrictions are configured as an independent, default-deny policy axis.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SocketPolicy {
    /// Deny all socket creation and connection attempts.
    #[default]
    Deny,
    /// Allow IPv4 TCP sockets to connect only to the IPv4 loopback network.
    Ipv4LoopbackTcp,
}

/// Configured broker policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyProfile {
    /// Deny every operation.
    DefaultDeny,
    /// Static rights for known broker principals.
    Static {
        /// Rights for the unauthenticated principal used by the initial POC.
        unauthenticated: ObjectRights,
    },
    /// Static rights for a principal authenticated by the broker entry layer.
    HostGuaranteed {
        /// Rights granted to the host-guaranteed principal.
        rights: ObjectRights,
    },
}

/// Broker policy decision and audit component.
///
/// This initial engine is a placeholder static policy surface for the broker
/// POC. A fuller policy model is intentionally deferred until the broker needs
/// authenticated principals, richer rules, and audit integration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEngine {
    profile: PolicyProfile,
    socket_policy: SocketPolicy,
}

impl PolicyEngine {
    /// Creates a policy engine from a policy profile.
    pub const fn new(profile: PolicyProfile) -> Self {
        Self {
            profile,
            socket_policy: SocketPolicy::Deny,
        }
    }

    /// Creates a policy engine that denies every operation.
    pub const fn default_deny() -> Self {
        Self::new(PolicyProfile::DefaultDeny)
    }

    /// Creates a policy engine with rights for the unauthenticated principal.
    pub const fn with_unauthenticated_rights(unauthenticated: ObjectRights) -> Self {
        Self::new(PolicyProfile::Static { unauthenticated })
    }

    /// Creates a policy engine with rights for a host-guaranteed principal.
    pub const fn with_host_guaranteed_rights(rights: ObjectRights) -> Self {
        Self::new(PolicyProfile::HostGuaranteed { rights })
    }

    /// Configures network access for broker-owned sockets.
    #[must_use]
    pub const fn with_socket_policy(mut self, socket_policy: SocketPolicy) -> Self {
        self.socket_policy = socket_policy;
        self
    }

    pub(crate) fn principal_object_rights(
        &self,
        caller_credential: CallerCredential,
    ) -> Result<ObjectRights, BrokerError> {
        let rights = match (self.profile, caller_credential) {
            (PolicyProfile::Static { unauthenticated }, CallerCredential::Unauthenticated) => {
                unauthenticated
            }
            (PolicyProfile::HostGuaranteed { rights }, CallerCredential::HostGuaranteed) => rights,
            _ => return Err(BrokerError::PolicyDenied),
        };
        if rights.is_empty() {
            return Err(BrokerError::PolicyDenied);
        }
        Ok(rights)
    }

    pub(crate) fn authorize_socket_create(
        &self,
        caller_credential: CallerCredential,
        request: CreateSocketRequest,
    ) -> Result<ObjectRights, BrokerError> {
        let rights = self.principal_object_rights(caller_credential)?;
        match self.socket_policy {
            SocketPolicy::Ipv4LoopbackTcp
                if request.address_family == AddressFamily::Ipv4
                    && request.socket_type == SocketType::Stream
                    && request.protocol == IpProtocol::Tcp =>
            {
                Ok(rights)
            }
            SocketPolicy::Deny | SocketPolicy::Ipv4LoopbackTcp => Err(BrokerError::PolicyDenied),
        }
    }

    pub(crate) fn authorize_socket_connect(
        &self,
        caller_credential: CallerCredential,
        address: SocketAddressV4,
    ) -> Result<(), SocketError> {
        self.principal_object_rights(caller_credential)
            .map_err(|_| SocketError::PolicyDenied)?;
        match self.socket_policy {
            // The initial loopback profile intentionally permits every port.
            // Destination-port rules belong to the later Layer 3/4 policy.
            SocketPolicy::Ipv4LoopbackTcp if address.address.0[0] == 127 => Ok(()),
            SocketPolicy::Deny | SocketPolicy::Ipv4LoopbackTcp => Err(SocketError::PolicyDenied),
        }
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
    use litebox_broker_protocol::socket::{Ipv4Address, Port};

    #[test]
    fn static_policy_allows_configured_principal_rights() {
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::all());

        assert_eq!(
            policy.principal_object_rights(CallerCredential::Unauthenticated),
            Ok(ObjectRights::WAIT | ObjectRights::WRITE)
        );
    }

    #[test]
    fn static_policy_returns_configured_principal_rights() {
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::WAIT);

        assert_eq!(
            policy.principal_object_rights(CallerCredential::Unauthenticated),
            Ok(ObjectRights::WAIT)
        );
    }

    #[test]
    fn host_guaranteed_policy_returns_configured_principal_rights() {
        let policy = PolicyEngine::with_host_guaranteed_rights(ObjectRights::WAIT);

        assert_eq!(
            policy.principal_object_rights(CallerCredential::HostGuaranteed),
            Ok(ObjectRights::WAIT)
        );
        assert_eq!(
            policy.principal_object_rights(CallerCredential::Unauthenticated),
            Err(BrokerError::PolicyDenied)
        );
    }

    #[test]
    fn empty_principal_rights_deny_object_authorization() {
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::empty());

        assert_eq!(
            policy.principal_object_rights(CallerCredential::Unauthenticated),
            Err(BrokerError::PolicyDenied)
        );
    }

    #[test]
    fn socket_policy_defaults_to_deny() {
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::all());
        assert_eq!(
            policy.authorize_socket_create(
                CallerCredential::Unauthenticated,
                CreateSocketRequest {
                    address_family: AddressFamily::Ipv4,
                    socket_type: SocketType::Stream,
                    protocol: IpProtocol::Tcp,
                },
            ),
            Err(BrokerError::PolicyDenied)
        );
    }

    #[test]
    fn loopback_socket_policy_rejects_non_loopback_destinations() {
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4LoopbackTcp);
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                SocketAddressV4 {
                    address: Ipv4Address([127, 0, 0, 1]),
                    port: Port(80),
                },
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                SocketAddressV4 {
                    address: Ipv4Address([10, 0, 0, 1]),
                    port: Port(80),
                },
            ),
            Err(SocketError::PolicyDenied)
        );
    }
}
