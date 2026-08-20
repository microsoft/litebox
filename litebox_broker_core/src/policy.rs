// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::net::SocketAddrV4;

use crate::socket::is_guest_network_address;
use crate::{BrokerError, CallerCredential, ObjectRights};
use litebox_broker_protocol::socket::{
    AddressFamily, CreateSocketRequest, IpProtocol, Ipv4Address, Port, SocketType,
};
use thiserror::Error;

/// Maximum number of destination rules in one transport policy.
pub const MAX_DESTINATION_RULES: usize = 64;

/// An IPv4 network in canonical CIDR form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Cidr {
    network: Ipv4Address,
    prefix_length: u8,
}

impl Ipv4Cidr {
    /// Creates a CIDR if the prefix is valid and the address has no host bits set.
    #[must_use]
    pub const fn new(network: Ipv4Address, prefix_length: u8) -> Option<Self> {
        if prefix_length > 32 {
            return None;
        }
        let mask = ipv4_prefix_mask(prefix_length);
        if u32::from_be_bytes(network.0) & !mask != 0 {
            return None;
        }
        Some(Self {
            network,
            prefix_length,
        })
    }

    /// Returns the canonical network address.
    #[must_use]
    pub const fn network(self) -> Ipv4Address {
        self.network
    }

    /// Returns the CIDR prefix length.
    #[must_use]
    pub const fn prefix_length(self) -> u8 {
        self.prefix_length
    }

    const fn contains(self, address: Ipv4Address) -> bool {
        let mask = ipv4_prefix_mask(self.prefix_length);
        u32::from_be_bytes(address.0) & mask == u32::from_be_bytes(self.network.0)
    }
}

const fn ipv4_prefix_mask(prefix_length: u8) -> u32 {
    if prefix_length == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_length)
    }
}

/// Inclusive nonzero transport destination-port range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestinationPortRange {
    start: Port,
    end: Port,
}

impl DestinationPortRange {
    /// Creates a nonempty range of valid transport destination ports.
    #[must_use]
    pub const fn new(start: Port, end: Port) -> Option<Self> {
        if start.0 == 0 || start.0 > end.0 {
            return None;
        }
        Some(Self { start, end })
    }

    /// Returns the first allowed port.
    #[must_use]
    pub const fn start(self) -> Port {
        self.start
    }

    /// Returns the last allowed port.
    #[must_use]
    pub const fn end(self) -> Port {
        self.end
    }

    const fn contains(self, port: Port) -> bool {
        self.start.0 <= port.0 && port.0 <= self.end.0
    }
}

/// One static IPv4 destination authorization rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestinationRule {
    caller_credential: CallerCredential,
    destination: Ipv4Cidr,
    ports: DestinationPortRange,
}

impl DestinationRule {
    /// Creates a rule for one caller, destination network, and port range.
    #[must_use]
    pub const fn new(
        caller_credential: CallerCredential,
        destination: Ipv4Cidr,
        ports: DestinationPortRange,
    ) -> Self {
        Self {
            caller_credential,
            destination,
            ports,
        }
    }

    /// Returns the caller authorized by this rule.
    #[must_use]
    pub const fn caller_credential(self) -> CallerCredential {
        self.caller_credential
    }

    /// Returns the authorized destination network.
    #[must_use]
    pub const fn destination(self) -> Ipv4Cidr {
        self.destination
    }

    /// Returns the authorized destination-port range.
    #[must_use]
    pub const fn ports(self) -> DestinationPortRange {
        self.ports
    }

    fn permits(self, caller_credential: CallerCredential, address: SocketAddrV4) -> bool {
        self.caller_credential == caller_credential
            && self
                .destination
                .contains(Ipv4Address(address.ip().octets()))
            && self.ports.contains(Port(address.port()))
    }
}

const EMPTY_DESTINATION_RULE: DestinationRule = DestinationRule {
    caller_credential: CallerCredential::Unauthenticated,
    destination: Ipv4Cidr {
        network: Ipv4Address([0, 0, 0, 0]),
        prefix_length: 0,
    },
    ports: DestinationPortRange {
        start: Port(1),
        end: Port(1),
    },
};

/// Invalid socket-policy configuration.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SocketPolicyError {
    /// The configured rule count exceeds [`MAX_DESTINATION_RULES`].
    #[error("destination policy has {actual} rules; maximum is {maximum}")]
    TooManyRules {
        /// Maximum supported rule count.
        maximum: usize,
        /// Requested rule count.
        actual: usize,
    },
}

/// Bounded static IPv4 destination rules for one transport protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DestinationPolicy {
    destination_rules: [DestinationRule; MAX_DESTINATION_RULES],
    destination_rule_count: usize,
}

impl DestinationPolicy {
    const fn empty() -> Self {
        Self {
            destination_rules: [EMPTY_DESTINATION_RULE; MAX_DESTINATION_RULES],
            destination_rule_count: 0,
        }
    }

    /// Returns the configured destination rules.
    #[must_use]
    pub fn rules(&self) -> &[DestinationRule] {
        &self.destination_rules[..self.destination_rule_count]
    }
}

/// Socket creation and outbound destination access available to broker-owned sockets.
///
/// Local bind authority is separate from egress destination rules and is
/// enforced by the broker's guest binding namespace.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketPolicy {
    tcp: Option<DestinationPolicy>,
    udp: Option<DestinationPolicy>,
}

impl SocketPolicy {
    /// Creates a policy that denies all socket creation and connection attempts.
    #[must_use]
    pub const fn deny() -> Self {
        Self {
            tcp: None,
            udp: None,
        }
    }

    /// Creates a policy allowing IPv4 TCP and UDP within the shared guest network.
    #[must_use]
    pub const fn guest_network() -> Self {
        Self {
            tcp: Some(DestinationPolicy::empty()),
            udp: Some(DestinationPolicy::empty()),
        }
    }

    /// Enables TCP with bounded native IPv4 destination rules.
    pub fn with_tcp_destination_rules(
        mut self,
        rules: &[DestinationRule],
    ) -> Result<Self, SocketPolicyError> {
        self.tcp = Some(copy_destination_rules(rules)?);
        Ok(self)
    }

    /// Enables UDP with bounded native IPv4 destination rules.
    pub fn with_udp_destination_rules(
        mut self,
        rules: &[DestinationRule],
    ) -> Result<Self, SocketPolicyError> {
        self.udp = Some(copy_destination_rules(rules)?);
        Ok(self)
    }

    /// Returns the native TCP destination rules, or `None` when TCP is denied.
    #[must_use]
    pub fn tcp_destination_rules(&self) -> Option<&[DestinationRule]> {
        self.tcp.as_ref().map(DestinationPolicy::rules)
    }

    /// Returns the native UDP destination rules, or `None` when UDP is denied.
    #[must_use]
    pub fn udp_destination_rules(&self) -> Option<&[DestinationRule]> {
        self.udp.as_ref().map(DestinationPolicy::rules)
    }

    const fn permits_tcp_socket(self) -> bool {
        self.tcp.is_some()
    }

    const fn permits_udp_socket(self) -> bool {
        self.udp.is_some()
    }

    fn permits_tcp_destination(
        self,
        caller_credential: CallerCredential,
        address: SocketAddrV4,
    ) -> bool {
        self.tcp.is_some_and(|policy| {
            is_guest_network_address(*address.ip())
                || policy
                    .rules()
                    .iter()
                    .any(|rule| rule.permits(caller_credential, address))
        })
    }

    fn permits_udp_destination(
        self,
        caller_credential: CallerCredential,
        address: SocketAddrV4,
    ) -> bool {
        self.udp.is_some_and(|policy| {
            is_guest_network_address(*address.ip())
                || policy
                    .rules()
                    .iter()
                    .any(|rule| rule.permits(caller_credential, address))
        })
    }
}

fn copy_destination_rules(
    rules: &[DestinationRule],
) -> Result<DestinationPolicy, SocketPolicyError> {
    if rules.len() > MAX_DESTINATION_RULES {
        return Err(SocketPolicyError::TooManyRules {
            maximum: MAX_DESTINATION_RULES,
            actual: rules.len(),
        });
    }
    let mut policy = DestinationPolicy::empty();
    policy.destination_rules[..rules.len()].copy_from_slice(rules);
    policy.destination_rule_count = rules.len();
    Ok(policy)
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
            socket_policy: SocketPolicy::deny(),
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
        let permitted = match (request.socket_type, request.protocol) {
            (SocketType::Stream, IpProtocol::Tcp) => self.socket_policy.permits_tcp_socket(),
            (SocketType::Datagram, IpProtocol::Udp) => self.socket_policy.permits_udp_socket(),
            _ => false,
        };
        if request.address_family == AddressFamily::Ipv4 && permitted {
            Ok(rights)
        } else {
            Err(BrokerError::PolicyDenied)
        }
    }

    pub(crate) fn authorize_socket_connect(
        &self,
        caller_credential: CallerCredential,
        protocol: IpProtocol,
        address: SocketAddrV4,
    ) -> Result<(), BrokerError> {
        let permitted = match protocol {
            IpProtocol::Tcp => self
                .socket_policy
                .permits_tcp_destination(caller_credential, address),
            IpProtocol::Udp => self
                .socket_policy
                .permits_udp_destination(caller_credential, address),
            _ => false,
        };
        if permitted {
            Ok(())
        } else {
            Err(BrokerError::PolicyDenied)
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
    use core::net::Ipv4Addr;

    const IPV4_TCP: CreateSocketRequest = CreateSocketRequest {
        address_family: AddressFamily::Ipv4,
        socket_type: SocketType::Stream,
        protocol: IpProtocol::Tcp,
    };
    const IPV4_UDP: CreateSocketRequest = CreateSocketRequest {
        address_family: AddressFamily::Ipv4,
        socket_type: SocketType::Datagram,
        protocol: IpProtocol::Udp,
    };

    fn cidr(address: [u8; 4], prefix_length: u8) -> Ipv4Cidr {
        Ipv4Cidr::new(Ipv4Address(address), prefix_length).unwrap()
    }

    fn ports(start: u16, end: u16) -> DestinationPortRange {
        DestinationPortRange::new(Port(start), Port(end)).unwrap()
    }

    fn address(address: [u8; 4], port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(address), port)
    }

    #[test]
    fn static_policy_allows_configured_principal_rights() {
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::all());

        assert_eq!(
            policy.principal_object_rights(CallerCredential::Unauthenticated),
            Ok(ObjectRights::WAIT | ObjectRights::WRITE)
        );
    }

    #[test]
    fn host_guaranteed_policy_rejects_other_principals() {
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
        let socket_policy = SocketPolicy::default();
        assert_eq!(socket_policy, SocketPolicy::deny());
        assert_eq!(socket_policy.tcp_destination_rules(), None);
        assert_eq!(socket_policy.udp_destination_rules(), None);

        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::all());
        assert_eq!(
            policy.authorize_socket_create(CallerCredential::Unauthenticated, IPV4_TCP),
            Err(BrokerError::PolicyDenied)
        );
    }

    #[test]
    fn cidr_requires_canonical_networks_and_matches_partial_bytes() {
        assert_eq!(Ipv4Cidr::new(Ipv4Address([10, 0, 0, 0]), 33), None);
        assert_eq!(Ipv4Cidr::new(Ipv4Address([10, 1, 0, 1]), 24), None);
        assert_eq!(Ipv4Cidr::new(Ipv4Address([10, 8, 0, 1]), 13), None);

        let all = cidr([0, 0, 0, 0], 0);
        assert!(all.contains(Ipv4Address([203, 0, 113, 9])));

        let network = cidr([10, 8, 0, 0], 13);
        assert!(network.contains(Ipv4Address([10, 15, 255, 255])));
        assert!(!network.contains(Ipv4Address([10, 16, 0, 0])));

        let host = cidr([192, 0, 2, 7], 32);
        assert!(host.contains(Ipv4Address([192, 0, 2, 7])));
        assert!(!host.contains(Ipv4Address([192, 0, 2, 8])));
    }

    #[test]
    fn port_ranges_are_nonzero_ordered_and_inclusive() {
        assert_eq!(DestinationPortRange::new(Port(0), Port(80)), None);
        assert_eq!(DestinationPortRange::new(Port(81), Port(80)), None);

        let range = ports(443, 444);
        assert!(!range.contains(Port(442)));
        assert!(range.contains(Port(443)));
        assert!(range.contains(Port(444)));
        assert!(!range.contains(Port(445)));
    }

    #[test]
    fn destination_policy_is_bounded() {
        let rule = DestinationRule::new(
            CallerCredential::Unauthenticated,
            cidr([127, 0, 0, 0], 8),
            ports(1, u16::MAX),
        );
        let maximum = [rule; MAX_DESTINATION_RULES];
        assert_eq!(
            SocketPolicy::deny()
                .with_tcp_destination_rules(&maximum)
                .unwrap()
                .tcp_destination_rules()
                .unwrap(),
            &maximum
        );
        assert_eq!(
            SocketPolicy::deny()
                .with_tcp_destination_rules(&maximum)
                .unwrap()
                .udp_destination_rules(),
            None
        );

        let excessive = [rule; MAX_DESTINATION_RULES + 1];
        assert_eq!(
            SocketPolicy::deny().with_tcp_destination_rules(&excessive),
            Err(SocketPolicyError::TooManyRules {
                maximum: MAX_DESTINATION_RULES,
                actual: MAX_DESTINATION_RULES + 1,
            })
        );
    }

    #[test]
    fn udp_destination_policy_is_bounded() {
        let rule = DestinationRule::new(
            CallerCredential::Unauthenticated,
            cidr([127, 0, 0, 0], 8),
            ports(1, u16::MAX),
        );
        let maximum = [rule; MAX_DESTINATION_RULES];
        assert_eq!(
            SocketPolicy::deny()
                .with_udp_destination_rules(&maximum)
                .unwrap()
                .udp_destination_rules()
                .unwrap(),
            &maximum
        );
        assert_eq!(
            SocketPolicy::deny()
                .with_udp_destination_rules(&maximum)
                .unwrap()
                .tcp_destination_rules(),
            None
        );

        let excessive = [rule; MAX_DESTINATION_RULES + 1];
        assert_eq!(
            SocketPolicy::deny().with_udp_destination_rules(&excessive),
            Err(SocketPolicyError::TooManyRules {
                maximum: MAX_DESTINATION_RULES,
                actual: MAX_DESTINATION_RULES + 1,
            })
        );
    }

    #[test]
    fn destination_rules_enforce_principal_cidr_and_port() {
        let socket_policy = SocketPolicy::deny()
            .with_tcp_destination_rules(&[
                DestinationRule::new(
                    CallerCredential::Unauthenticated,
                    cidr([10, 8, 0, 0], 13),
                    ports(443, 444),
                ),
                DestinationRule::new(
                    CallerCredential::HostGuaranteed,
                    cidr([192, 0, 2, 7], 32),
                    ports(8443, 8443),
                ),
            ])
            .unwrap();
        let unauthenticated = PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(socket_policy);
        assert_eq!(
            unauthenticated.authorize_socket_create(CallerCredential::Unauthenticated, IPV4_TCP),
            Ok(ObjectRights::all())
        );
        assert_eq!(
            unauthenticated.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IpProtocol::Tcp,
                address([10, 15, 0, 1], 443),
            ),
            Ok(())
        );
        assert_eq!(
            unauthenticated.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IpProtocol::Tcp,
                address([10, 0, 2, 15], 1),
            ),
            Ok(())
        );
        for denied in [
            address([10, 16, 0, 1], 443),
            address([10, 15, 0, 1], 445),
            address([192, 0, 2, 7], 8443),
            address([10, 15, 0, 1], 0),
        ] {
            assert_eq!(
                unauthenticated.authorize_socket_connect(
                    CallerCredential::Unauthenticated,
                    IpProtocol::Tcp,
                    denied,
                ),
                Err(BrokerError::PolicyDenied)
            );
        }
    }

    #[test]
    fn guest_network_policy_allows_tcp_and_udp_only_within_the_guest_network() {
        let socket_policy = SocketPolicy::guest_network();
        assert_eq!(socket_policy.tcp_destination_rules(), Some([].as_slice()));
        assert_eq!(socket_policy.udp_destination_rules(), Some([].as_slice()));
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(socket_policy);
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IpProtocol::Tcp,
                address([127, 255, 0, 1], 80),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IpProtocol::Tcp,
                address([10, 0, 2, 15], 80),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IpProtocol::Tcp,
                address([10, 0, 0, 1], 80),
            ),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IpProtocol::Tcp,
                address([127, 0, 0, 1], 0),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IpProtocol::Udp,
                address([127, 0, 0, 1], 53),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IpProtocol::Udp,
                address([10, 0, 2, 15], 53),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IpProtocol::Udp,
                address([10, 0, 0, 1], 53),
            ),
            Err(BrokerError::PolicyDenied)
        );
    }

    #[test]
    fn mixed_policy_authorizes_udp_independently_from_tcp() {
        let tcp_rule = DestinationRule::new(
            CallerCredential::Unauthenticated,
            cidr([192, 0, 2, 0], 24),
            ports(443, 443),
        );
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(
                SocketPolicy::guest_network()
                    .with_tcp_destination_rules(&[tcp_rule])
                    .unwrap(),
            );

        assert_eq!(
            policy.authorize_socket_create(CallerCredential::Unauthenticated, IPV4_UDP),
            Ok(ObjectRights::all())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IpProtocol::Udp,
                address([10, 0, 2, 15], 53),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IpProtocol::Udp,
                address([192, 0, 2, 1], 443),
            ),
            Err(BrokerError::PolicyDenied)
        );
    }
}
