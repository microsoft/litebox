// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned IPv4 identity and trusted socket routing values.

use core::fmt;
use core::net::{Ipv4Addr, SocketAddrV4};

use litebox_broker_protocol::socket::SocketError;

use super::{GuestBindingReservation, GuestTransport};

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

    /// Normalizes and classifies one guest-requested destination.
    ///
    /// A nonzero unspecified destination becomes loopback, and destination
    /// classes that no broker route can represent are rejected before any
    /// provider dispatch.
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
        if self.is_guest_local_ip(*requested.ip()) {
            Ok(SocketDestination::Guest { requested })
        } else if *requested.ip() == self.gateway_ipv4_address {
            Ok(SocketDestination::Gateway { requested })
        } else {
            Ok(SocketDestination::External { requested })
        }
    }

    /// Returns whether an address may be reserved in a guest binding namespace.
    pub(crate) fn binding_is_valid(&self, requested: SocketAddrV4) -> bool {
        requested.ip().is_unspecified() || self.is_guest_local_ip(*requested.ip())
    }

    /// Returns whether one concrete address names this broker's guest identity.
    pub(crate) fn is_guest_local_ip(&self, address: Ipv4Addr) -> bool {
        address.is_loopback() || address == self.guest_ipv4_address
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
        /// Guest-requested external destination.
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

    /// Checks that this classification is valid for a shared configuration.
    ///
    /// A route tag that disagrees with the configuration's own classification
    /// is rejected, so untrusted or stale metadata cannot select a route.
    #[must_use]
    pub fn is_valid_for(self, config: &BrokerNetworkConfig) -> bool {
        config.classify_destination(self.requested()) == Ok(self)
    }
}

/// Broker-authorized guest binding passed to a platform provider.
#[derive(Clone)]
pub struct GuestSocketBinding {
    requested: SocketAddrV4,
    transport: GuestTransport,
}

impl GuestSocketBinding {
    pub(super) fn new(reservation: &GuestBindingReservation) -> Self {
        Self {
            requested: reservation.requested_address(),
            transport: reservation.transport(),
        }
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
        self.requested.port() != 0 && config.binding_is_valid(self.requested)
    }

    /// Returns whether this binding belongs to the TCP guest namespace.
    #[must_use]
    pub fn is_tcp(&self) -> bool {
        self.transport == GuestTransport::Tcp
    }

    /// Returns whether this binding covers one concrete guest address.
    #[must_use]
    pub fn covers(&self, config: &BrokerNetworkConfig, address: SocketAddrV4) -> bool {
        self.is_valid_for(config)
            && address.port() != 0
            && config.is_guest_local_ip(*address.ip())
            && if self.is_wildcard() {
                address.port() == self.requested.port()
            } else {
                address == self.requested
            }
    }

    /// Selects the concrete guest source identity for one route.
    ///
    /// A wildcard binding answers a guest loopback destination with the
    /// loopback identity and every other route with the configured private
    /// guest address. An exact loopback binding cannot leave the guest
    /// namespace, and an exact private guest binding always keeps itself.
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
                *requested.ip()
            }
            SocketDestination::Guest { .. }
            | SocketDestination::Gateway { .. }
            | SocketDestination::External { .. } => config.guest_ipv4_address,
        };
        Some(SocketAddrV4::new(ip, self.requested.port()))
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
        self.requested == other.requested && self.transport == other.transport
    }
}

impl Eq for GuestSocketBinding {}

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

    fn binding(config: &BrokerNetworkConfig, requested: SocketAddrV4) -> GuestSocketBinding {
        let ports = BrokerSocketPorts::default();
        let SocketOutcome::Completed((_, reservation)) =
            ports.reserve(config, create_request(), requested).unwrap()
        else {
            panic!("guest binding reservation failed");
        };
        GuestSocketBinding::new(&reservation)
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
            assert_eq!(
                BrokerNetworkConfig::new(Ipv4Addr::new(10, 0, 2, 15), invalid),
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
        let external = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 80);

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
            config.classify_destination(external),
            Ok(SocketDestination::External {
                requested: external
            })
        );
        assert_eq!(
            config.classify_destination(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 80)),
            Ok(SocketDestination::Guest {
                requested: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)
            })
        );
    }

    #[test]
    fn invalid_destination_classes_are_rejected_before_routing() {
        let config = BrokerNetworkConfig::default();
        for invalid in [
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 80),
            SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 80),
            SocketAddrV4::new(Ipv4Addr::new(240, 0, 0, 1), 80),
            SocketAddrV4::new(Ipv4Addr::new(255, 0, 0, 1), 80),
            SocketAddrV4::new(Ipv4Addr::new(0, 1, 2, 3), 80),
        ] {
            assert_eq!(
                config.classify_destination(invalid),
                Err(SocketError::InvalidArgument)
            );
        }
    }

    #[test]
    fn malformed_route_tags_are_invalid_for_the_configuration() {
        let config = BrokerNetworkConfig::default();
        let guest = SocketAddrV4::new(config.guest_ipv4_address(), 80);
        let gateway = SocketAddrV4::new(config.gateway_ipv4_address(), 80);
        let loopback = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80);
        let external = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 80);

        for valid in [
            SocketDestination::Guest { requested: guest },
            SocketDestination::Guest {
                requested: loopback,
            },
            SocketDestination::Gateway { requested: gateway },
            SocketDestination::External {
                requested: external,
            },
        ] {
            assert!(valid.is_valid_for(&config));
        }
        for malformed in [
            SocketDestination::External {
                requested: loopback,
            },
            SocketDestination::External { requested: guest },
            SocketDestination::External { requested: gateway },
            SocketDestination::Guest { requested: gateway },
            SocketDestination::Guest {
                requested: external,
            },
            SocketDestination::Guest {
                requested: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 80),
            },
            SocketDestination::Gateway { requested: guest },
            SocketDestination::Gateway {
                requested: SocketAddrV4::new(config.gateway_ipv4_address(), 0),
            },
            SocketDestination::External {
                requested: SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 80),
            },
        ] {
            assert!(!malformed.is_valid_for(&config));
        }
    }

    #[test]
    fn wildcard_bindings_select_route_specific_guest_sources() {
        let config = BrokerNetworkConfig::default();
        let binding = binding(&config, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 49152));
        assert!(binding.is_wildcard());
        assert!(binding.is_valid_for(&config));

        for (destination, expected_ip) in [
            (
                SocketDestination::Guest {
                    requested: SocketAddrV4::new(Ipv4Addr::new(127, 2, 3, 4), 80),
                },
                Ipv4Addr::new(127, 2, 3, 4),
            ),
            (
                SocketDestination::Guest {
                    requested: SocketAddrV4::new(config.guest_ipv4_address(), 80),
                },
                config.guest_ipv4_address(),
            ),
            (
                SocketDestination::Gateway {
                    requested: SocketAddrV4::new(config.gateway_ipv4_address(), 80),
                },
                config.guest_ipv4_address(),
            ),
            (
                SocketDestination::External {
                    requested: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 80),
                },
                config.guest_ipv4_address(),
            ),
        ] {
            assert_eq!(
                binding.concrete_address_for(&config, destination),
                Some(SocketAddrV4::new(expected_ip, 49152))
            );
        }
        assert_eq!(
            binding.concrete_address_for(
                &config,
                SocketDestination::External {
                    requested: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)
                }
            ),
            None
        );
        assert!(binding.covers(&config, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152)));
        assert!(binding.covers(
            &config,
            SocketAddrV4::new(config.guest_ipv4_address(), 49152)
        ));
        assert!(!binding.covers(&config, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 49152)));
        assert!(!binding.covers(
            &config,
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 49152)
        ));
    }

    #[test]
    fn exact_bindings_keep_their_identity_and_cannot_escape_loopback() {
        let config = BrokerNetworkConfig::default();
        let loopback_source = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 49153);
        let guest_source = SocketAddrV4::new(config.guest_ipv4_address(), 49154);
        let loopback = binding(&config, loopback_source);
        let private = binding(&config, guest_source);
        let guest_destination = SocketDestination::Guest {
            requested: SocketAddrV4::new(config.guest_ipv4_address(), 80),
        };
        let gateway_destination = SocketDestination::Gateway {
            requested: SocketAddrV4::new(config.gateway_ipv4_address(), 80),
        };
        let external_destination = SocketDestination::External {
            requested: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 80),
        };

        assert_eq!(
            loopback.concrete_address_for(
                &config,
                SocketDestination::Guest {
                    requested: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)
                }
            ),
            Some(loopback_source)
        );
        assert_eq!(
            loopback.concrete_address_for(&config, guest_destination),
            Some(loopback_source)
        );
        assert_eq!(
            loopback.concrete_address_for(&config, gateway_destination),
            None
        );
        assert_eq!(
            loopback.concrete_address_for(&config, external_destination),
            None
        );

        for destination in [guest_destination, gateway_destination, external_destination] {
            assert_eq!(
                private.concrete_address_for(&config, destination),
                Some(guest_source)
            );
        }
        assert!(private.covers(&config, guest_source));
        assert!(!private.covers(&config, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49154)));
    }
}
