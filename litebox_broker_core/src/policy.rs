// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::net::SocketAddrV4;

use crate::socket::SocketDestination;
use crate::{BrokerError, CallerCredential, ObjectRights};
use litebox_broker_protocol::socket::{
    AddressFamily, CreateSocketRequest, IpProtocol, Ipv4Address, Port, SocketType,
};
use thiserror::Error;

/// Maximum number of destination rules in one transport policy.
pub const MAX_DESTINATION_RULES: usize = 64;

/// Maximum number of host-gateway port rules for one transport protocol.
pub const MAX_GATEWAY_RULES: usize = 64;

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

/// One static host-gateway port authorization rule.
///
/// A gateway rule authorizes replacement access to a host service reached
/// through the guest-visible gateway address. It is destination-port scoped
/// because the gateway address itself is fixed by the broker configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayPortRule {
    caller_credential: CallerCredential,
    ports: DestinationPortRange,
}

impl GatewayPortRule {
    /// Creates a rule for one caller and destination-port range.
    #[must_use]
    pub const fn new(caller_credential: CallerCredential, ports: DestinationPortRange) -> Self {
        Self {
            caller_credential,
            ports,
        }
    }

    /// Returns the caller authorized by this rule.
    #[must_use]
    pub const fn caller_credential(self) -> CallerCredential {
        self.caller_credential
    }

    /// Returns the authorized destination-port range.
    #[must_use]
    pub const fn ports(self) -> DestinationPortRange {
        self.ports
    }

    fn permits(self, caller_credential: CallerCredential, port: Port) -> bool {
        self.caller_credential == caller_credential && self.ports.contains(port)
    }
}

const EMPTY_GATEWAY_RULE: GatewayPortRule = GatewayPortRule {
    caller_credential: CallerCredential::Unauthenticated,
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
    /// External rules were supplied for a protocol whose sockets are denied.
    #[error("destination rules were supplied for denied protocol {protocol:?}")]
    RulesForDeniedProtocol {
        /// Protocol whose guest-network admission is false.
        protocol: IpProtocol,
    },
}

/// Bounded static IPv4 destination rules for one transport protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestinationPolicy {
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

/// Bounded host-gateway port rules for one transport protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GatewayPolicy {
    rules: [GatewayPortRule; MAX_GATEWAY_RULES],
    rule_count: usize,
}

impl GatewayPolicy {
    const fn empty() -> Self {
        Self {
            rules: [EMPTY_GATEWAY_RULE; MAX_GATEWAY_RULES],
            rule_count: 0,
        }
    }

    fn permits(&self, caller_credential: CallerCredential, port: Port) -> bool {
        self.rules[..self.rule_count]
            .iter()
            .any(|rule| rule.permits(caller_credential, port))
    }
}

/// Socket creation and outbound destination access available to broker-owned sockets.
///
/// Local bind authority is separate from egress destination rules and is
/// enforced by the broker's guest binding namespace.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SocketPolicy {
    /// Deny all socket creation and connection attempts.
    #[default]
    Deny,
    /// Allow IPv4 TCP and UDP sockets to reach only the literal IPv4 loopback
    /// network inside the guest namespace.
    Ipv4Loopback,
    /// Apply bounded TCP destination rules.
    TcpDestinationRules(DestinationPolicy),
    /// Apply bounded UDP destination rules.
    UdpDestinationRules(DestinationPolicy),
    /// Apply independent bounded TCP and UDP destination rules.
    TcpUdpDestinationRules {
        /// TCP destination policy.
        tcp: DestinationPolicy,
        /// UDP destination policy.
        udp: DestinationPolicy,
    },
    /// Admit guest networking independently per protocol, with bounded
    /// external destination rules.
    ///
    /// An admitted protocol reaches the whole guest namespace, including the
    /// configured private guest address, and may reach the host gateway when a
    /// matching gateway port rule also exists.
    GuestNetwork {
        /// Whether IPv4 TCP socket creation and guest routing are admitted.
        admit_tcp: bool,
        /// TCP external destination policy.
        tcp: DestinationPolicy,
        /// Whether IPv4 UDP socket creation and guest routing are admitted.
        admit_udp: bool,
        /// UDP external destination policy.
        udp: DestinationPolicy,
    },
}

impl SocketPolicy {
    /// Creates a bounded policy from static IPv4 TCP destination rules.
    pub fn from_tcp_destination_rules(
        rules: &[DestinationRule],
    ) -> Result<Self, SocketPolicyError> {
        Ok(Self::TcpDestinationRules(copy_destination_rules(rules)?))
    }

    /// Creates a bounded policy from static IPv4 UDP destination rules.
    pub fn from_udp_destination_rules(
        rules: &[DestinationRule],
    ) -> Result<Self, SocketPolicyError> {
        let policy = copy_destination_rules(rules)?;
        Ok(Self::UdpDestinationRules(policy))
    }

    /// Creates a policy with independent static IPv4 TCP and UDP rules.
    pub fn from_tcp_udp_destination_rules(
        tcp_rules: &[DestinationRule],
        udp_rules: &[DestinationRule],
    ) -> Result<Self, SocketPolicyError> {
        let tcp = copy_destination_rules(tcp_rules)?;
        let udp = copy_destination_rules(udp_rules)?;
        Ok(Self::TcpUdpDestinationRules { tcp, udp })
    }

    /// Creates independently admitted guest networking with bounded external rules.
    pub fn from_guest_network_destination_rules(
        admit_tcp: bool,
        tcp_rules: &[DestinationRule],
        admit_udp: bool,
        udp_rules: &[DestinationRule],
    ) -> Result<Self, SocketPolicyError> {
        if !admit_tcp && !tcp_rules.is_empty() {
            return Err(SocketPolicyError::RulesForDeniedProtocol {
                protocol: IpProtocol::Tcp,
            });
        }
        if !admit_udp && !udp_rules.is_empty() {
            return Err(SocketPolicyError::RulesForDeniedProtocol {
                protocol: IpProtocol::Udp,
            });
        }
        Ok(Self::GuestNetwork {
            admit_tcp,
            tcp: copy_destination_rules(tcp_rules)?,
            admit_udp,
            udp: copy_destination_rules(udp_rules)?,
        })
    }

    /// Returns the configured rules for a bounded destination policy.
    #[must_use]
    pub fn tcp_destination_rules(&self) -> Option<&[DestinationRule]> {
        match self {
            Self::TcpDestinationRules(policy)
            | Self::TcpUdpDestinationRules { tcp: policy, .. }
            | Self::GuestNetwork {
                admit_tcp: true,
                tcp: policy,
                ..
            } => Some(policy.rules()),
            Self::Deny
            | Self::Ipv4Loopback
            | Self::UdpDestinationRules(_)
            | Self::GuestNetwork {
                admit_tcp: false, ..
            } => None,
        }
    }

    /// Returns the configured UDP rules for a bounded destination policy.
    #[must_use]
    pub fn udp_destination_rules(&self) -> Option<&[DestinationRule]> {
        match self {
            Self::UdpDestinationRules(policy)
            | Self::TcpUdpDestinationRules { udp: policy, .. }
            | Self::GuestNetwork {
                admit_udp: true,
                udp: policy,
                ..
            } => Some(policy.rules()),
            Self::Deny
            | Self::Ipv4Loopback
            | Self::TcpDestinationRules(_)
            | Self::GuestNetwork {
                admit_udp: false, ..
            } => None,
        }
    }

    fn permits_tcp_socket(self, caller_credential: CallerCredential) -> bool {
        match self {
            Self::Deny | Self::UdpDestinationRules(_) => false,
            Self::Ipv4Loopback => true,
            Self::GuestNetwork { admit_tcp, .. } => admit_tcp,
            Self::TcpDestinationRules(policy)
            | Self::TcpUdpDestinationRules { tcp: policy, .. } => policy
                .rules()
                .iter()
                .any(|rule| rule.caller_credential == caller_credential),
        }
    }

    fn permits_udp_socket(self, caller_credential: CallerCredential) -> bool {
        match self {
            Self::Deny | Self::TcpDestinationRules(_) => false,
            Self::Ipv4Loopback => true,
            Self::GuestNetwork { admit_udp, .. } => admit_udp,
            Self::UdpDestinationRules(policy)
            | Self::TcpUdpDestinationRules { udp: policy, .. } => policy
                .rules()
                .iter()
                .any(|rule| rule.caller_credential == caller_credential),
        }
    }

    /// Returns whether TCP may reach one guest-namespace destination.
    ///
    /// Literal loopback policy stays literal: it admits the loopback network
    /// but not the configured private guest address.
    fn permits_tcp_guest_destination(self, address: SocketAddrV4) -> bool {
        match self {
            Self::Deny
            | Self::TcpDestinationRules(_)
            | Self::UdpDestinationRules(_)
            | Self::TcpUdpDestinationRules { .. } => false,
            Self::Ipv4Loopback => address.ip().is_loopback(),
            Self::GuestNetwork { admit_tcp, .. } => admit_tcp,
        }
    }

    /// Returns whether UDP may reach one guest-namespace destination.
    fn permits_udp_guest_destination(self, address: SocketAddrV4) -> bool {
        match self {
            Self::Deny
            | Self::TcpDestinationRules(_)
            | Self::UdpDestinationRules(_)
            | Self::TcpUdpDestinationRules { .. } => false,
            Self::Ipv4Loopback => address.ip().is_loopback(),
            Self::GuestNetwork { admit_udp, .. } => admit_udp,
        }
    }

    /// Returns whether the policy shape admits any TCP host-gateway route.
    fn admits_tcp_gateway(self) -> bool {
        matches!(
            self,
            Self::GuestNetwork {
                admit_tcp: true,
                ..
            }
        )
    }

    /// Returns whether the policy shape admits any UDP host-gateway route.
    fn admits_udp_gateway(self) -> bool {
        matches!(
            self,
            Self::GuestNetwork {
                admit_udp: true,
                ..
            }
        )
    }

    fn permits_tcp_external_destination(
        self,
        caller_credential: CallerCredential,
        address: SocketAddrV4,
    ) -> bool {
        match self {
            Self::Deny
            | Self::Ipv4Loopback
            | Self::UdpDestinationRules(_)
            | Self::GuestNetwork {
                admit_tcp: false, ..
            } => false,
            Self::TcpDestinationRules(policy)
            | Self::TcpUdpDestinationRules { tcp: policy, .. }
            | Self::GuestNetwork {
                admit_tcp: true,
                tcp: policy,
                ..
            } => policy
                .rules()
                .iter()
                .any(|rule| rule.permits(caller_credential, address)),
        }
    }

    fn permits_udp_external_destination(
        self,
        caller_credential: CallerCredential,
        address: SocketAddrV4,
    ) -> bool {
        match self {
            Self::Deny
            | Self::Ipv4Loopback
            | Self::TcpDestinationRules(_)
            | Self::GuestNetwork {
                admit_udp: false, ..
            } => false,
            Self::UdpDestinationRules(policy)
            | Self::TcpUdpDestinationRules { udp: policy, .. }
            | Self::GuestNetwork {
                admit_udp: true,
                udp: policy,
                ..
            } => policy
                .rules()
                .iter()
                .any(|rule| rule.permits(caller_credential, address)),
        }
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

fn copy_gateway_rules(rules: &[GatewayPortRule]) -> Result<GatewayPolicy, SocketPolicyError> {
    if rules.len() > MAX_GATEWAY_RULES {
        return Err(SocketPolicyError::TooManyRules {
            maximum: MAX_GATEWAY_RULES,
            actual: rules.len(),
        });
    }
    let mut policy = GatewayPolicy::empty();
    policy.rules[..rules.len()].copy_from_slice(rules);
    policy.rule_count = rules.len();
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
    tcp_gateway_policy: GatewayPolicy,
    udp_gateway_policy: GatewayPolicy,
}

impl PolicyEngine {
    /// Creates a policy engine from a policy profile.
    pub const fn new(profile: PolicyProfile) -> Self {
        Self {
            profile,
            socket_policy: SocketPolicy::Deny,
            tcp_gateway_policy: GatewayPolicy::empty(),
            udp_gateway_policy: GatewayPolicy::empty(),
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

    /// Replaces the bounded TCP and UDP host-gateway port rules.
    ///
    /// A gateway rule alone never authorizes a route; the socket policy must
    /// also admit host-gateway access for that protocol.
    pub fn with_gateway_rules(
        mut self,
        tcp_rules: &[GatewayPortRule],
        udp_rules: &[GatewayPortRule],
    ) -> Result<Self, SocketPolicyError> {
        self.tcp_gateway_policy = copy_gateway_rules(tcp_rules)?;
        self.udp_gateway_policy = copy_gateway_rules(udp_rules)?;
        Ok(self)
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
            (SocketType::Stream, IpProtocol::Tcp) => {
                self.socket_policy.permits_tcp_socket(caller_credential)
            }
            (SocketType::Datagram, IpProtocol::Udp) => {
                self.socket_policy.permits_udp_socket(caller_credential)
            }
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
        request: CreateSocketRequest,
        destination: SocketDestination,
    ) -> Result<(), BrokerError> {
        self.principal_object_rights(caller_credential)?;
        let permitted = match (request.socket_type, request.protocol, destination) {
            (SocketType::Stream, IpProtocol::Tcp, SocketDestination::Guest { requested }) => {
                self.socket_policy.permits_tcp_guest_destination(requested)
            }
            (SocketType::Stream, IpProtocol::Tcp, SocketDestination::Gateway { requested }) => {
                self.socket_policy.admits_tcp_gateway()
                    && self
                        .tcp_gateway_policy
                        .permits(caller_credential, Port(requested.port()))
            }
            (SocketType::Stream, IpProtocol::Tcp, SocketDestination::External { requested }) => {
                self.socket_policy
                    .permits_tcp_external_destination(caller_credential, requested)
            }
            (SocketType::Datagram, IpProtocol::Udp, SocketDestination::Guest { requested }) => {
                self.socket_policy.permits_udp_guest_destination(requested)
            }
            (SocketType::Datagram, IpProtocol::Udp, SocketDestination::Gateway { requested }) => {
                self.socket_policy.admits_udp_gateway()
                    && self
                        .udp_gateway_policy
                        .permits(caller_credential, Port(requested.port()))
            }
            (SocketType::Datagram, IpProtocol::Udp, SocketDestination::External { requested }) => {
                self.socket_policy
                    .permits_udp_external_destination(caller_credential, requested)
            }
            _ => false,
        };
        if request.address_family == AddressFamily::Ipv4 && permitted {
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
    use crate::socket::BrokerNetworkConfig;
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

    fn route(config: &BrokerNetworkConfig, address: SocketAddrV4) -> SocketDestination {
        config
            .classify_destination(address)
            .expect("test destinations are routable")
    }

    fn gateway_ports(start: u16, end: u16) -> GatewayPortRule {
        GatewayPortRule::new(CallerCredential::Unauthenticated, ports(start, end))
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
            SocketPolicy::from_tcp_destination_rules(&maximum)
                .unwrap()
                .tcp_destination_rules()
                .unwrap(),
            &maximum
        );

        let excessive = [rule; MAX_DESTINATION_RULES + 1];
        assert_eq!(
            SocketPolicy::from_tcp_destination_rules(&excessive),
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
            SocketPolicy::from_udp_destination_rules(&maximum)
                .unwrap()
                .udp_destination_rules()
                .unwrap(),
            &maximum
        );

        let excessive = [rule; MAX_DESTINATION_RULES + 1];
        assert_eq!(
            SocketPolicy::from_udp_destination_rules(&excessive),
            Err(SocketPolicyError::TooManyRules {
                maximum: MAX_DESTINATION_RULES,
                actual: MAX_DESTINATION_RULES + 1,
            })
        );
    }

    #[test]
    fn destination_rules_enforce_principal_cidr_and_port() {
        let network_config = BrokerNetworkConfig::default();
        let socket_policy = SocketPolicy::from_tcp_destination_rules(&[
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
                IPV4_TCP,
                route(&network_config, address([10, 15, 0, 1], 443)),
            ),
            Ok(())
        );
        for denied in [
            address([10, 16, 0, 1], 443),
            address([10, 15, 0, 1], 445),
            address([192, 0, 2, 7], 8443),
        ] {
            assert_eq!(
                unauthenticated.authorize_socket_connect(
                    CallerCredential::Unauthenticated,
                    IPV4_TCP,
                    route(&network_config, denied),
                ),
                Err(BrokerError::PolicyDenied)
            );
        }
        // External destination rules never reach the guest namespace or the
        // host gateway, even when their network would match.
        for guest_or_gateway in [
            address([127, 0, 0, 1], 443),
            SocketAddrV4::new(network_config.guest_ipv4_address(), 443),
            SocketAddrV4::new(network_config.gateway_ipv4_address(), 443),
        ] {
            assert_eq!(
                unauthenticated.authorize_socket_connect(
                    CallerCredential::Unauthenticated,
                    IPV4_TCP,
                    route(&network_config, guest_or_gateway),
                ),
                Err(BrokerError::PolicyDenied)
            );
        }
    }

    #[test]
    fn loopback_policy_allows_only_literal_loopback_destinations() {
        let network_config = BrokerNetworkConfig::default();
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback)
            .with_gateway_rules(&[gateway_ports(1, u16::MAX)], &[gateway_ports(1, u16::MAX)])
            .unwrap();
        assert_eq!(
            policy.authorize_socket_create(CallerCredential::Unauthenticated, IPV4_TCP),
            Ok(ObjectRights::all())
        );
        assert_eq!(
            policy.authorize_socket_create(CallerCredential::Unauthenticated, IPV4_UDP),
            Ok(ObjectRights::all())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_TCP,
                route(&network_config, address([127, 255, 0, 1], 80)),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_UDP,
                route(&network_config, address([127, 0, 0, 1], 53)),
            ),
            Ok(())
        );
        // The private guest address, the host gateway, and external networks
        // remain denied even though a gateway rule exists.
        for denied in [
            SocketAddrV4::new(network_config.guest_ipv4_address(), 80),
            SocketAddrV4::new(network_config.gateway_ipv4_address(), 80),
            address([10, 0, 0, 1], 80),
        ] {
            for request in [IPV4_TCP, IPV4_UDP] {
                assert_eq!(
                    policy.authorize_socket_connect(
                        CallerCredential::Unauthenticated,
                        request,
                        route(&network_config, denied),
                    ),
                    Err(BrokerError::PolicyDenied)
                );
            }
        }
    }

    #[test]
    fn mixed_policy_authorizes_udp_independently_from_tcp() {
        let network_config = BrokerNetworkConfig::default();
        let tcp_rule = DestinationRule::new(
            CallerCredential::Unauthenticated,
            cidr([192, 0, 2, 0], 24),
            ports(443, 443),
        );
        let udp_rule = DestinationRule::new(
            CallerCredential::Unauthenticated,
            cidr([198, 51, 100, 0], 24),
            ports(53, 53),
        );
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(
                SocketPolicy::from_tcp_udp_destination_rules(&[tcp_rule], &[udp_rule]).unwrap(),
            );

        assert_eq!(
            policy.authorize_socket_create(CallerCredential::Unauthenticated, IPV4_UDP),
            Ok(ObjectRights::all())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_UDP,
                route(&network_config, address([198, 51, 100, 1], 53)),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_UDP,
                route(&network_config, address([192, 0, 2, 1], 443)),
            ),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_TCP,
                route(&network_config, address([198, 51, 100, 1], 53)),
            ),
            Err(BrokerError::PolicyDenied)
        );
        // A socket request whose type and protocol disagree is never routable.
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                CreateSocketRequest {
                    address_family: AddressFamily::Ipv4,
                    socket_type: SocketType::Stream,
                    protocol: IpProtocol::Udp,
                },
                route(&network_config, address([198, 51, 100, 1], 53)),
            ),
            Err(BrokerError::PolicyDenied)
        );
    }

    #[test]
    fn guest_network_policy_separates_guest_gateway_and_external_routes() {
        let network_config = BrokerNetworkConfig::default();
        let external_rule = DestinationRule::new(
            CallerCredential::Unauthenticated,
            cidr([203, 0, 113, 0], 24),
            ports(80, 80),
        );
        let socket_policy = SocketPolicy::from_guest_network_destination_rules(
            true,
            &[external_rule],
            true,
            &[external_rule],
        )
        .unwrap();
        let without_gateway = PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(socket_policy);
        let with_gateway = without_gateway
            .clone()
            .with_gateway_rules(&[gateway_ports(8080, 8080)], &[gateway_ports(53, 53)])
            .unwrap();
        let loopback = address([127, 0, 0, 1], 80);
        let guest = SocketAddrV4::new(network_config.guest_ipv4_address(), 80);
        let external = address([203, 0, 113, 9], 80);
        let unauthorized_external = address([203, 0, 113, 9], 81);

        for request in [IPV4_TCP, IPV4_UDP] {
            for permitted in [loopback, guest, external] {
                assert_eq!(
                    without_gateway.authorize_socket_connect(
                        CallerCredential::Unauthenticated,
                        request,
                        route(&network_config, permitted),
                    ),
                    Ok(())
                );
            }
            assert_eq!(
                without_gateway.authorize_socket_connect(
                    CallerCredential::Unauthenticated,
                    request,
                    route(&network_config, unauthorized_external),
                ),
                Err(BrokerError::PolicyDenied)
            );
        }

        // Guest networking alone never reaches the host gateway.
        for (request, port) in [(IPV4_TCP, 8080), (IPV4_UDP, 53)] {
            let gateway = SocketAddrV4::new(network_config.gateway_ipv4_address(), port);
            assert_eq!(
                without_gateway.authorize_socket_connect(
                    CallerCredential::Unauthenticated,
                    request,
                    route(&network_config, gateway),
                ),
                Err(BrokerError::PolicyDenied)
            );
            assert_eq!(
                with_gateway.authorize_socket_connect(
                    CallerCredential::Unauthenticated,
                    request,
                    route(&network_config, gateway),
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn guest_network_admits_protocols_independently() {
        let network_config = BrokerNetworkConfig::default();
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(
                SocketPolicy::from_guest_network_destination_rules(true, &[], false, &[]).unwrap(),
            )
            .with_gateway_rules(&[gateway_ports(80, 80)], &[gateway_ports(53, 53)])
            .unwrap();
        let loopback = address([127, 0, 0, 1], 80);
        let gateway = SocketAddrV4::new(network_config.gateway_ipv4_address(), 80);

        assert_eq!(
            policy.authorize_socket_create(CallerCredential::Unauthenticated, IPV4_TCP),
            Ok(ObjectRights::all())
        );
        assert_eq!(
            policy.authorize_socket_create(CallerCredential::Unauthenticated, IPV4_UDP),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_TCP,
                route(&network_config, loopback),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_TCP,
                route(&network_config, gateway),
            ),
            Ok(())
        );
        for denied in [loopback, gateway] {
            assert_eq!(
                policy.authorize_socket_connect(
                    CallerCredential::Unauthenticated,
                    IPV4_UDP,
                    route(&network_config, denied),
                ),
                Err(BrokerError::PolicyDenied)
            );
        }
        assert_eq!(
            SocketPolicy::from_guest_network_destination_rules(
                false,
                &[DestinationRule::new(
                    CallerCredential::Unauthenticated,
                    cidr([203, 0, 113, 0], 24),
                    ports(80, 80),
                )],
                true,
                &[],
            ),
            Err(SocketPolicyError::RulesForDeniedProtocol {
                protocol: IpProtocol::Tcp,
            })
        );
    }

    #[test]
    fn gateway_rules_are_credential_scoped_and_bounded() {
        let network_config = BrokerNetworkConfig::default();
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(
                SocketPolicy::from_guest_network_destination_rules(true, &[], true, &[]).unwrap(),
            )
            .with_gateway_rules(
                &[GatewayPortRule::new(
                    CallerCredential::HostGuaranteed,
                    ports(8080, 8080),
                )],
                &[gateway_ports(53, 53)],
            )
            .unwrap();
        let tcp_gateway = SocketAddrV4::new(network_config.gateway_ipv4_address(), 8080);
        let udp_gateway = SocketAddrV4::new(network_config.gateway_ipv4_address(), 53);

        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_TCP,
                route(&network_config, tcp_gateway),
            ),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_UDP,
                route(&network_config, udp_gateway),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_UDP,
                route(&network_config, tcp_gateway),
            ),
            Err(BrokerError::PolicyDenied)
        );

        let maximum = [gateway_ports(1, u16::MAX); MAX_GATEWAY_RULES];
        assert!(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_gateway_rules(&maximum, &maximum)
                .is_ok()
        );
        let excessive = [gateway_ports(1, u16::MAX); MAX_GATEWAY_RULES + 1];
        assert_eq!(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_gateway_rules(&excessive, &maximum),
            Err(SocketPolicyError::TooManyRules {
                maximum: MAX_GATEWAY_RULES,
                actual: MAX_GATEWAY_RULES + 1,
            })
        );
    }
}
