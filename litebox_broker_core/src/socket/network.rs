// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned IPv4 identity and trusted socket routing values.

use alloc::sync::Arc;
use core::fmt;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::sync::atomic::{AtomicBool, Ordering};

use litebox_broker_protocol::socket::SocketError;

use super::GuestBindingLease;

/// Opaque core-issued identity for one guest TCP listener generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GuestTcpListenerTarget(pub(super) u64);

/// Immutable network identity shared by broker core and its socket provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerNetworkConfig {
    guest_ipv4_address: Ipv4Addr,
    gateway_ipv4_address: Ipv4Addr,
}

impl BrokerNetworkConfig {
    /// Creates a configuration for distinct RFC1918 guest and gateway addresses.
    #[must_use]
    pub fn new(guest_ipv4_address: Ipv4Addr, gateway_ipv4_address: Ipv4Addr) -> Option<Self> {
        if !is_private_unicast(guest_ipv4_address)
            || !is_private_unicast(gateway_ipv4_address)
            || guest_ipv4_address == gateway_ipv4_address
        {
            return None;
        }
        Some(Self {
            guest_ipv4_address,
            gateway_ipv4_address,
        })
    }

    /// Returns the broker-wide guest IPv4 identity.
    #[must_use]
    pub const fn guest_ipv4_address(&self) -> Ipv4Addr {
        self.guest_ipv4_address
    }

    /// Returns the guest-visible gateway IPv4 address.
    #[must_use]
    pub const fn gateway_ipv4_address(&self) -> Ipv4Addr {
        self.gateway_ipv4_address
    }

    /// Normalizes and classifies one nonzero destination.
    pub(crate) fn classify_destination(
        &self,
        requested: SocketAddrV4,
    ) -> Result<SocketDestination, SocketError> {
        if requested.port() == 0 {
            return Err(SocketError::InvalidArgument);
        }
        let requested = if requested.ip().is_unspecified() {
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, requested.port())
        } else {
            requested
        };
        if is_invalid_destination(*requested.ip()) {
            return Err(SocketError::InvalidArgument);
        }
        if requested.ip().is_loopback() || *requested.ip() == self.guest_ipv4_address {
            Ok(SocketDestination::Guest { requested })
        } else if *requested.ip() == self.gateway_ipv4_address {
            Ok(SocketDestination::Gateway { requested })
        } else {
            Ok(SocketDestination::External { requested })
        }
    }

    pub(crate) fn binding_is_valid(&self, requested: SocketAddrV4) -> bool {
        requested.ip().is_unspecified()
            || requested.ip().is_loopback()
            || *requested.ip() == self.guest_ipv4_address
    }
}

impl Default for BrokerNetworkConfig {
    fn default() -> Self {
        Self::new(Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 1))
            .expect("the default broker network addresses are valid")
    }
}

fn is_private_unicast(address: Ipv4Addr) -> bool {
    address.is_private()
        && !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_broadcast()
        && !address.is_multicast()
}

fn is_invalid_destination(address: Ipv4Addr) -> bool {
    let first = address.octets()[0];
    address.is_broadcast()
        || address.is_multicast()
        || first >= 240
        || (first == 0 && !address.is_unspecified())
}

/// Broker-authorized guest binding passed to a platform provider.
#[derive(Clone)]
pub struct GuestSocketBinding {
    requested: SocketAddrV4,
    lease: GuestBindingLease,
}

impl GuestSocketBinding {
    pub(crate) fn new(
        config: &BrokerNetworkConfig,
        requested: SocketAddrV4,
        lease: GuestBindingLease,
    ) -> Option<Self> {
        if requested.port() == 0
            || !config.binding_is_valid(requested)
            || lease.requested_address() != requested
        {
            return None;
        }
        Some(Self { requested, lease })
    }

    /// Returns the broker-reserved guest-visible binding.
    #[must_use]
    pub const fn requested(&self) -> SocketAddrV4 {
        self.requested
    }

    /// Returns whether the original binding used the wildcard address.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        self.requested.ip().is_unspecified()
    }

    /// Checks that this value is valid for a provider's shared configuration.
    #[must_use]
    pub fn is_valid_for(&self, config: &BrokerNetworkConfig) -> bool {
        self.requested.port() != 0
            && config.binding_is_valid(self.requested)
            && self.lease.requested_address() == self.requested
    }

    /// Returns whether this reservation covers one concrete guest address.
    #[must_use]
    pub fn covers(&self, config: &BrokerNetworkConfig, address: SocketAddrV4) -> bool {
        self.is_valid_for(config) && self.lease.covers(address, config)
    }

    /// Returns the opaque target reserved for this TCP binding.
    #[must_use]
    pub fn tcp_listener_target(&self) -> Option<GuestTcpListenerTarget> {
        (self.lease.transport() == super::GuestTransport::Tcp)
            .then_some(GuestTcpListenerTarget(self.lease.id()))
    }

    /// Selects the concrete guest source identity for one route.
    #[must_use]
    pub fn concrete_address_for(
        &self,
        config: &BrokerNetworkConfig,
        destination: SocketDestination,
    ) -> Option<SocketAddrV4> {
        if !self.is_valid_for(config) || !destination.is_valid_for(config) {
            return None;
        }
        if !self.is_wildcard() {
            if self.requested.ip().is_loopback()
                && !matches!(destination, SocketDestination::Guest { .. })
            {
                return None;
            }
            return Some(self.requested);
        }
        let ip = match destination {
            SocketDestination::Guest { requested } if requested.ip().is_loopback() => {
                Ipv4Addr::LOCALHOST
            }
            SocketDestination::Guest { .. }
            | SocketDestination::Gateway { .. }
            | SocketDestination::External { .. } => config.guest_ipv4_address,
        };
        Some(SocketAddrV4::new(ip, self.requested.port()))
    }

    pub(crate) fn lease(&self) -> GuestBindingLease {
        self.lease.clone()
    }
}

impl fmt::Debug for GuestSocketBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestSocketBinding")
            .field("requested", &self.requested)
            .finish_non_exhaustive()
    }
}

impl PartialEq for GuestSocketBinding {
    fn eq(&self, other: &Self) -> bool {
        self.requested == other.requested
    }
}

impl Eq for GuestSocketBinding {}

/// Trusted classification of one validated socket destination.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum SocketDestination {
    /// Route only through the broker-wide guest namespace.
    Guest {
        /// Normalized guest-requested destination.
        requested: SocketAddrV4,
    },
    /// Translate through the explicitly authorized host gateway.
    Gateway {
        /// Guest-visible gateway destination.
        requested: SocketAddrV4,
    },
    /// Route only through the platform's native external path.
    External {
        /// Original guest-requested destination.
        requested: SocketAddrV4,
    },
}

impl SocketDestination {
    /// Returns the normalized guest-requested destination.
    #[must_use]
    pub const fn requested(self) -> SocketAddrV4 {
        match self {
            Self::Guest { requested }
            | Self::Gateway { requested }
            | Self::External { requested } => requested,
        }
    }

    /// Checks that this classification is valid for a provider's shared config.
    #[must_use]
    pub fn is_valid_for(self, config: &BrokerNetworkConfig) -> bool {
        config.classify_destination(self.requested()) == Ok(self)
    }
}

/// Core-issued guest TCP source identity retained through routed accept.
#[derive(Clone)]
pub struct GuestSourceLease {
    inner: Arc<GuestSourceLeaseInner>,
}

struct GuestSourceLeaseInner {
    binding: GuestBindingLease,
    source: SocketAddrV4,
    destination: SocketAddrV4,
    listener_target: GuestTcpListenerTarget,
    id: u64,
    transferred: AtomicBool,
}

impl GuestSourceLease {
    pub(crate) fn new(
        binding: GuestBindingLease,
        source: SocketAddrV4,
        destination: SocketAddrV4,
        listener_target: GuestTcpListenerTarget,
        id: u64,
    ) -> Self {
        Self {
            inner: Arc::new(GuestSourceLeaseInner {
                binding,
                source,
                destination,
                listener_target,
                id,
                transferred: AtomicBool::new(false),
            }),
        }
    }

    /// Returns the exact guest-visible connector source.
    #[must_use]
    pub fn source(&self) -> SocketAddrV4 {
        self.inner.source
    }

    /// Returns the exact guest destination used by the connector.
    #[must_use]
    pub fn destination(&self) -> SocketAddrV4 {
        self.inner.destination
    }

    /// Returns the exact listener generation selected by broker core.
    #[must_use]
    pub fn listener_target(&self) -> GuestTcpListenerTarget {
        self.inner.listener_target
    }

    pub(crate) fn binding(&self) -> GuestBindingLease {
        self.inner.binding.clone()
    }

    pub(crate) fn claim_accept(&self) -> bool {
        self.inner
            .transferred
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

impl fmt::Debug for GuestSourceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestSourceLease")
            .field("source", &self.inner.source)
            .field("destination", &self.inner.destination)
            .field("listener_target", &self.inner.listener_target)
            .field("id", &self.inner.id)
            .finish_non_exhaustive()
    }
}

/// Trusted routed connect request passed to a platform provider.
#[derive(Clone, Debug)]
pub struct RoutedSocketConnect {
    destination: SocketDestination,
    guest_source: Option<GuestSourceLease>,
}

impl RoutedSocketConnect {
    pub(crate) fn new(
        destination: SocketDestination,
        guest_source: Option<GuestSourceLease>,
    ) -> Self {
        Self {
            destination,
            guest_source,
        }
    }

    /// Returns the classified destination.
    #[must_use]
    pub const fn destination(&self) -> SocketDestination {
        self.destination
    }

    /// Returns the core-issued source token for a guest TCP connect.
    #[must_use]
    pub const fn guest_source(&self) -> Option<&GuestSourceLease> {
        self.guest_source.as_ref()
    }

    /// Returns the core-selected guest TCP listener target, when present.
    #[must_use]
    pub fn guest_listener_target(&self) -> Option<GuestTcpListenerTarget> {
        self.guest_source
            .as_ref()
            .map(GuestSourceLease::listener_target)
    }

    /// Splits this request into its provider-owned values.
    #[must_use]
    pub fn into_parts(self) -> (SocketDestination, Option<GuestSourceLease>) {
        (self.destination, self.guest_source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::BrokerSocketPorts;
    use litebox_broker_protocol::socket::{
        AddressFamily, CreateSocketRequest, IpProtocol, SocketOutcome, SocketType,
    };

    const fn create_request() -> CreateSocketRequest {
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Stream,
            protocol: IpProtocol::Tcp,
        }
    }

    #[test]
    fn network_config_validates_distinct_private_unicast_addresses() {
        let config = BrokerNetworkConfig::default();
        assert_eq!(config.guest_ipv4_address(), Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(config.gateway_ipv4_address(), Ipv4Addr::new(10, 0, 2, 1));
        assert!(
            BrokerNetworkConfig::new(Ipv4Addr::new(172, 16, 0, 2), Ipv4Addr::new(172, 16, 0, 1))
                .is_some()
        );
        for invalid in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
        ] {
            assert_eq!(
                BrokerNetworkConfig::new(invalid, Ipv4Addr::new(10, 0, 2, 1)),
                None
            );
        }
        assert_eq!(
            BrokerNetworkConfig::new(Ipv4Addr::new(10, 0, 2, 15), Ipv4Addr::new(10, 0, 2, 15)),
            None
        );
    }

    #[test]
    fn destination_classification_normalizes_and_separates_routes() {
        let config = BrokerNetworkConfig::default();
        let guest = SocketAddrV4::new(config.guest_ipv4_address(), 80);
        let gateway = SocketAddrV4::new(config.gateway_ipv4_address(), 80);
        let loopback = SocketAddrV4::new(Ipv4Addr::new(127, 2, 3, 4), 80);
        let normalized = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80);
        assert_eq!(
            config.classify_destination(guest),
            Ok(SocketDestination::Guest { requested: guest })
        );
        assert_eq!(
            config.classify_destination(loopback),
            Ok(SocketDestination::Guest {
                requested: loopback
            })
        );
        assert_eq!(
            config.classify_destination(gateway),
            Ok(SocketDestination::Gateway { requested: gateway })
        );
        assert_eq!(
            config.classify_destination(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 80)),
            Ok(SocketDestination::Guest {
                requested: normalized
            })
        );
        for invalid in [
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 80),
            SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 80),
            SocketAddrV4::new(Ipv4Addr::new(240, 0, 0, 1), 80),
            SocketAddrV4::new(Ipv4Addr::new(0, 1, 2, 3), 80),
        ] {
            assert_eq!(
                config.classify_destination(invalid),
                Err(SocketError::InvalidArgument)
            );
        }
    }

    #[test]
    fn guest_binding_preserves_exact_and_wildcard_identity() {
        let config = BrokerNetworkConfig::default();
        let ports = BrokerSocketPorts::default();
        let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 49152);
        let SocketOutcome::Completed((wildcard, lease)) =
            ports.reserve(create_request(), wildcard).unwrap()
        else {
            panic!("wildcard reservation failed");
        };
        let binding = GuestSocketBinding::new(&config, wildcard, lease).unwrap();
        assert!(binding.is_wildcard());
        assert_eq!(
            binding.concrete_address_for(
                &config,
                SocketDestination::Guest {
                    requested: SocketAddrV4::new(Ipv4Addr::new(127, 2, 3, 4), 80)
                }
            ),
            Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152))
        );
        assert_eq!(
            binding.concrete_address_for(
                &config,
                SocketDestination::Gateway {
                    requested: SocketAddrV4::new(config.gateway_ipv4_address(), 80)
                }
            ),
            Some(SocketAddrV4::new(config.guest_ipv4_address(), 49152))
        );
    }
}
