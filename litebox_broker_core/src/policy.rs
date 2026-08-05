// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::net::SocketAddrV4;

use crate::{BrokerError, CallerCredential, ObjectRights};
use litebox_broker_protocol::socket::{
    AddressFamily, CreateSocketRequest, IpProtocol, Ipv4Address, Port, SocketType,
};
use thiserror::Error;

/// Maximum number of TCP destination rules in one socket policy.
pub const MAX_TCP_DESTINATION_RULES: usize = 64;
/// Maximum number of UDP destination rules in one socket policy.
pub const MAX_UDP_DESTINATION_RULES: usize = 64;

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
pub struct TcpPortRange {
    start: Port,
    end: Port,
}

/// Inclusive nonzero UDP destination-port range.
pub type UdpPortRange = TcpPortRange;

impl TcpPortRange {
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

/// One static IPv4 TCP destination authorization rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpDestinationRule {
    caller_credential: CallerCredential,
    destination: Ipv4Cidr,
    ports: TcpPortRange,
}

impl TcpDestinationRule {
    /// Creates a rule for one caller, destination network, and port range.
    #[must_use]
    pub const fn new(
        caller_credential: CallerCredential,
        destination: Ipv4Cidr,
        ports: TcpPortRange,
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
    pub const fn ports(self) -> TcpPortRange {
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

/// One static IPv4 UDP destination authorization rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpDestinationRule {
    caller_credential: CallerCredential,
    destination: Ipv4Cidr,
    ports: UdpPortRange,
}

impl UdpDestinationRule {
    /// Creates a rule for one caller, destination network, and port range.
    #[must_use]
    pub const fn new(
        caller_credential: CallerCredential,
        destination: Ipv4Cidr,
        ports: UdpPortRange,
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
    pub const fn ports(self) -> UdpPortRange {
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

const EMPTY_TCP_DESTINATION_RULE: TcpDestinationRule = TcpDestinationRule {
    caller_credential: CallerCredential::Unauthenticated,
    destination: Ipv4Cidr {
        network: Ipv4Address([0, 0, 0, 0]),
        prefix_length: 0,
    },
    ports: TcpPortRange {
        start: Port(1),
        end: Port(1),
    },
};

const EMPTY_UDP_DESTINATION_RULE: UdpDestinationRule = UdpDestinationRule {
    caller_credential: CallerCredential::Unauthenticated,
    destination: Ipv4Cidr {
        network: Ipv4Address([0, 0, 0, 0]),
        prefix_length: 0,
    },
    ports: UdpPortRange {
        start: Port(1),
        end: Port(1),
    },
};

/// Invalid socket-policy configuration.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SocketPolicyError {
    /// The configured rule count exceeds [`MAX_TCP_DESTINATION_RULES`].
    #[error("TCP destination policy has {actual} rules; maximum is {maximum}")]
    TooManyRules {
        /// Maximum supported rule count.
        maximum: usize,
        /// Requested rule count.
        actual: usize,
    },
    /// The configured rule count exceeds [`MAX_UDP_DESTINATION_RULES`].
    #[error("UDP destination policy has {actual} rules; maximum is {maximum}")]
    TooManyUdpRules {
        /// Maximum supported rule count.
        maximum: usize,
        /// Requested rule count.
        actual: usize,
    },
}

/// Bounded static IPv4 TCP destination rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpDestinationPolicy {
    tcp_destination_rules: [TcpDestinationRule; MAX_TCP_DESTINATION_RULES],
    tcp_destination_rule_count: usize,
}

impl TcpDestinationPolicy {
    const fn empty() -> Self {
        Self {
            tcp_destination_rules: [EMPTY_TCP_DESTINATION_RULE; MAX_TCP_DESTINATION_RULES],
            tcp_destination_rule_count: 0,
        }
    }

    /// Returns the configured TCP destination rules.
    #[must_use]
    pub fn rules(&self) -> &[TcpDestinationRule] {
        &self.tcp_destination_rules[..self.tcp_destination_rule_count]
    }
}

/// Bounded static IPv4 UDP destination rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpDestinationPolicy {
    udp_destination_rules: [UdpDestinationRule; MAX_UDP_DESTINATION_RULES],
    udp_destination_rule_count: usize,
}

impl UdpDestinationPolicy {
    const fn empty() -> Self {
        Self {
            udp_destination_rules: [EMPTY_UDP_DESTINATION_RULE; MAX_UDP_DESTINATION_RULES],
            udp_destination_rule_count: 0,
        }
    }

    /// Returns the configured UDP destination rules.
    #[must_use]
    pub fn rules(&self) -> &[UdpDestinationRule] {
        &self.udp_destination_rules[..self.udp_destination_rule_count]
    }
}

/// Socket creation and outbound destination access available to broker-owned sockets.
///
/// Local bind authority is separate from egress destination rules: an admitted
/// IPv4 TCP or UDP socket may bind only within the IPv4 loopback network.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
#[expect(
    clippy::large_enum_variant,
    reason = "fixed-capacity policy storage avoids infallible allocation in no_std configuration"
)]
pub enum SocketPolicy {
    /// Deny all socket creation and connection attempts.
    #[default]
    Deny,
    /// Allow IPv4 TCP sockets to connect only to the IPv4 loopback network.
    Ipv4LoopbackTcp,
    /// Allow IPv4 TCP and UDP sockets to use only the IPv4 loopback network.
    Ipv4LoopbackTcpUdp,
    /// Apply bounded caller, IPv4 CIDR, and destination-port rules.
    TcpDestinationRules(TcpDestinationPolicy),
    /// Apply bounded UDP caller, IPv4 CIDR, and destination-port rules.
    UdpDestinationRules(UdpDestinationPolicy),
    /// Apply independent bounded TCP and UDP destination rules.
    TcpUdpDestinationRules {
        /// TCP destination policy.
        tcp: TcpDestinationPolicy,
        /// UDP destination policy.
        udp: UdpDestinationPolicy,
    },
}

impl SocketPolicy {
    /// Creates a bounded policy from static IPv4 TCP destination rules.
    pub fn from_tcp_destination_rules(
        rules: &[TcpDestinationRule],
    ) -> Result<Self, SocketPolicyError> {
        Ok(Self::TcpDestinationRules(copy_tcp_destination_rules(
            rules,
        )?))
    }

    /// Creates a bounded policy from static IPv4 UDP destination rules.
    pub fn from_udp_destination_rules(
        rules: &[UdpDestinationRule],
    ) -> Result<Self, SocketPolicyError> {
        let policy = copy_udp_destination_rules(rules)?;
        Ok(Self::UdpDestinationRules(policy))
    }

    /// Creates a policy with independent static IPv4 TCP and UDP rules.
    pub fn from_tcp_udp_destination_rules(
        tcp_rules: &[TcpDestinationRule],
        udp_rules: &[UdpDestinationRule],
    ) -> Result<Self, SocketPolicyError> {
        let tcp = copy_tcp_destination_rules(tcp_rules)?;
        let udp = copy_udp_destination_rules(udp_rules)?;
        Ok(Self::TcpUdpDestinationRules { tcp, udp })
    }

    /// Returns the configured rules for a bounded destination policy.
    #[must_use]
    pub fn tcp_destination_rules(&self) -> Option<&[TcpDestinationRule]> {
        match self {
            Self::TcpDestinationRules(policy)
            | Self::TcpUdpDestinationRules { tcp: policy, .. } => Some(policy.rules()),
            Self::Deny
            | Self::Ipv4LoopbackTcp
            | Self::Ipv4LoopbackTcpUdp
            | Self::UdpDestinationRules(_) => None,
        }
    }

    /// Returns the configured UDP rules for a bounded destination policy.
    #[must_use]
    pub fn udp_destination_rules(&self) -> Option<&[UdpDestinationRule]> {
        match self {
            Self::UdpDestinationRules(policy)
            | Self::TcpUdpDestinationRules { udp: policy, .. } => Some(policy.rules()),
            Self::Deny
            | Self::Ipv4LoopbackTcp
            | Self::Ipv4LoopbackTcpUdp
            | Self::TcpDestinationRules(_) => None,
        }
    }

    fn permits_tcp_socket(self, caller_credential: CallerCredential) -> bool {
        match self {
            Self::Deny | Self::UdpDestinationRules(_) => false,
            Self::Ipv4LoopbackTcp | Self::Ipv4LoopbackTcpUdp => true,
            Self::TcpDestinationRules(policy)
            | Self::TcpUdpDestinationRules { tcp: policy, .. } => policy
                .rules()
                .iter()
                .any(|rule| rule.caller_credential == caller_credential),
        }
    }

    fn permits_udp_socket(self, caller_credential: CallerCredential) -> bool {
        match self {
            Self::Deny | Self::Ipv4LoopbackTcp | Self::TcpDestinationRules(_) => false,
            Self::Ipv4LoopbackTcpUdp => true,
            Self::UdpDestinationRules(policy)
            | Self::TcpUdpDestinationRules { udp: policy, .. } => policy
                .rules()
                .iter()
                .any(|rule| rule.caller_credential == caller_credential),
        }
    }

    fn permits_tcp_destination(
        self,
        caller_credential: CallerCredential,
        address: SocketAddrV4,
    ) -> bool {
        match self {
            Self::Deny | Self::UdpDestinationRules(_) => false,
            Self::Ipv4LoopbackTcp | Self::Ipv4LoopbackTcpUdp => address.ip().is_loopback(),
            Self::TcpDestinationRules(policy)
            | Self::TcpUdpDestinationRules { tcp: policy, .. } => policy
                .rules()
                .iter()
                .any(|rule| rule.permits(caller_credential, address)),
        }
    }

    fn permits_udp_destination(
        self,
        caller_credential: CallerCredential,
        address: SocketAddrV4,
    ) -> bool {
        match self {
            Self::Deny | Self::Ipv4LoopbackTcp | Self::TcpDestinationRules(_) => false,
            Self::Ipv4LoopbackTcpUdp => address.ip().is_loopback(),
            Self::UdpDestinationRules(policy)
            | Self::TcpUdpDestinationRules { udp: policy, .. } => policy
                .rules()
                .iter()
                .any(|rule| rule.permits(caller_credential, address)),
        }
    }
}

fn copy_tcp_destination_rules(
    rules: &[TcpDestinationRule],
) -> Result<TcpDestinationPolicy, SocketPolicyError> {
    if rules.len() > MAX_TCP_DESTINATION_RULES {
        return Err(SocketPolicyError::TooManyRules {
            maximum: MAX_TCP_DESTINATION_RULES,
            actual: rules.len(),
        });
    }
    let mut policy = TcpDestinationPolicy::empty();
    policy.tcp_destination_rules[..rules.len()].copy_from_slice(rules);
    policy.tcp_destination_rule_count = rules.len();
    Ok(policy)
}

fn copy_udp_destination_rules(
    rules: &[UdpDestinationRule],
) -> Result<UdpDestinationPolicy, SocketPolicyError> {
    if rules.len() > MAX_UDP_DESTINATION_RULES {
        return Err(SocketPolicyError::TooManyUdpRules {
            maximum: MAX_UDP_DESTINATION_RULES,
            actual: rules.len(),
        });
    }
    let mut policy = UdpDestinationPolicy::empty();
    policy.udp_destination_rules[..rules.len()].copy_from_slice(rules);
    policy.udp_destination_rule_count = rules.len();
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
        address: SocketAddrV4,
    ) -> Result<(), BrokerError> {
        self.principal_object_rights(caller_credential)?;
        let permitted = match (request.socket_type, request.protocol) {
            (SocketType::Stream, IpProtocol::Tcp) => self
                .socket_policy
                .permits_tcp_destination(caller_credential, address),
            (SocketType::Datagram, IpProtocol::Udp) => self
                .socket_policy
                .permits_udp_destination(caller_credential, address),
            _ => false,
        };
        if request.address_family == AddressFamily::Ipv4 && permitted {
            Ok(())
        } else {
            Err(BrokerError::PolicyDenied)
        }
    }

    pub(crate) fn authorize_socket_bind(
        &self,
        caller_credential: CallerCredential,
        request: CreateSocketRequest,
        address: SocketAddrV4,
    ) -> Result<(), BrokerError> {
        self.principal_object_rights(caller_credential)?;
        // Egress rules do not describe local listener authority. Socket
        // creation admission plus this fixed loopback boundary governs binds.
        let supported_socket = matches!(
            (request.socket_type, request.protocol),
            (SocketType::Stream, IpProtocol::Tcp) | (SocketType::Datagram, IpProtocol::Udp)
        );
        if request.address_family == AddressFamily::Ipv4
            && supported_socket
            && address.ip().is_loopback()
        {
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

    fn ports(start: u16, end: u16) -> TcpPortRange {
        TcpPortRange::new(Port(start), Port(end)).unwrap()
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
        assert_eq!(TcpPortRange::new(Port(0), Port(80)), None);
        assert_eq!(TcpPortRange::new(Port(81), Port(80)), None);

        let range = ports(443, 444);
        assert!(!range.contains(Port(442)));
        assert!(range.contains(Port(443)));
        assert!(range.contains(Port(444)));
        assert!(!range.contains(Port(445)));
    }

    #[test]
    fn destination_policy_is_bounded() {
        let rule = TcpDestinationRule::new(
            CallerCredential::Unauthenticated,
            cidr([127, 0, 0, 0], 8),
            ports(1, u16::MAX),
        );
        let maximum = [rule; MAX_TCP_DESTINATION_RULES];
        assert_eq!(
            SocketPolicy::from_tcp_destination_rules(&maximum)
                .unwrap()
                .tcp_destination_rules()
                .unwrap(),
            &maximum
        );

        let excessive = [rule; MAX_TCP_DESTINATION_RULES + 1];
        assert_eq!(
            SocketPolicy::from_tcp_destination_rules(&excessive),
            Err(SocketPolicyError::TooManyRules {
                maximum: MAX_TCP_DESTINATION_RULES,
                actual: MAX_TCP_DESTINATION_RULES + 1,
            })
        );
    }

    #[test]
    fn udp_destination_policy_is_bounded() {
        let rule = UdpDestinationRule::new(
            CallerCredential::Unauthenticated,
            cidr([127, 0, 0, 0], 8),
            ports(1, u16::MAX),
        );
        let maximum = [rule; MAX_UDP_DESTINATION_RULES];
        assert_eq!(
            SocketPolicy::from_udp_destination_rules(&maximum)
                .unwrap()
                .udp_destination_rules()
                .unwrap(),
            &maximum
        );

        let excessive = [rule; MAX_UDP_DESTINATION_RULES + 1];
        assert_eq!(
            SocketPolicy::from_udp_destination_rules(&excessive),
            Err(SocketPolicyError::TooManyUdpRules {
                maximum: MAX_UDP_DESTINATION_RULES,
                actual: MAX_UDP_DESTINATION_RULES + 1,
            })
        );
    }

    #[test]
    fn destination_rules_enforce_principal_cidr_and_port() {
        let socket_policy = SocketPolicy::from_tcp_destination_rules(&[
            TcpDestinationRule::new(
                CallerCredential::Unauthenticated,
                cidr([10, 8, 0, 0], 13),
                ports(443, 444),
            ),
            TcpDestinationRule::new(
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
                address([10, 15, 0, 1], 443),
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
                    IPV4_TCP,
                    denied,
                ),
                Err(BrokerError::PolicyDenied)
            );
        }
    }

    #[test]
    fn loopback_policy_preserves_initial_production_scope() {
        let policy = PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4LoopbackTcp);
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_TCP,
                address([127, 255, 0, 1], 80),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_TCP,
                address([10, 0, 0, 1], 80),
            ),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_TCP,
                address([127, 0, 0, 1], 0),
            ),
            Ok(())
        );
    }

    #[test]
    fn mixed_policy_authorizes_udp_independently_from_tcp() {
        let tcp_rule = TcpDestinationRule::new(
            CallerCredential::Unauthenticated,
            cidr([192, 0, 2, 0], 24),
            ports(443, 443),
        );
        let udp_rule = UdpDestinationRule::new(
            CallerCredential::Unauthenticated,
            cidr([127, 0, 0, 0], 8),
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
                address([127, 0, 0, 1], 53),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_connect(
                CallerCredential::Unauthenticated,
                IPV4_UDP,
                address([192, 0, 2, 1], 443),
            ),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            policy.authorize_socket_bind(
                CallerCredential::Unauthenticated,
                IPV4_UDP,
                address([127, 0, 0, 1], 0),
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize_socket_bind(
                CallerCredential::Unauthenticated,
                IPV4_UDP,
                address([0, 0, 0, 0], 0),
            ),
            Err(BrokerError::PolicyDenied)
        );
    }
}
