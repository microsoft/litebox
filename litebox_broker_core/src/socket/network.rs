// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned IPv4 identity and trusted socket routing values.

use core::net::{Ipv4Addr, SocketAddrV4};

use litebox_broker_protocol::socket::SocketError;

/// Immutable network identity shared by broker core and its socket provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerNetworkConfig {
    guest_ipv4_address: Ipv4Addr,
}

impl BrokerNetworkConfig {
    /// Creates a configuration for one RFC1918 guest IPv4 address.
    #[must_use]
    pub fn new(guest_ipv4_address: Ipv4Addr) -> Option<Self> {
        if !guest_ipv4_address.is_private()
            || guest_ipv4_address.is_unspecified()
            || guest_ipv4_address.is_loopback()
            || guest_ipv4_address.is_broadcast()
            || guest_ipv4_address.is_multicast()
        {
            return None;
        }
        Some(Self { guest_ipv4_address })
    }

    /// Returns the broker-wide guest IPv4 identity.
    #[must_use]
    pub const fn guest_ipv4_address(&self) -> Ipv4Addr {
        self.guest_ipv4_address
    }

    /// Returns the concrete guest identity for a wildcard or private binding.
    #[must_use]
    pub fn canonical_guest_address(&self, address: SocketAddrV4) -> Option<SocketAddrV4> {
        if address.port() == 0 {
            return None;
        }
        if address.ip().is_unspecified() || *address.ip() == self.guest_ipv4_address {
            Some(SocketAddrV4::new(self.guest_ipv4_address, address.port()))
        } else {
            None
        }
    }

    pub(crate) fn classify_destination(
        &self,
        requested: SocketAddrV4,
    ) -> Result<SocketDestination, SocketError> {
        if requested.ip().is_unspecified() || requested.port() == 0 {
            return Err(SocketError::InvalidArgument);
        }
        if *requested.ip() == self.guest_ipv4_address {
            Ok(SocketDestination::Guest { requested })
        } else {
            Ok(SocketDestination::External { requested })
        }
    }
}

impl Default for BrokerNetworkConfig {
    fn default() -> Self {
        Self::new(Ipv4Addr::new(10, 0, 2, 15)).expect("the default guest IPv4 address is valid")
    }
}

/// Broker-authorized guest binding passed to a platform provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestSocketBinding {
    requested: SocketAddrV4,
    wildcard: bool,
}

impl GuestSocketBinding {
    /// Creates a binding valid for one broker network configuration.
    ///
    /// Broker core constructs this only after policy and port authorization.
    /// Platform providers must still call [`Self::is_valid_for`] because this
    /// portable value is not itself an authorization boundary.
    #[must_use]
    pub fn new(config: &BrokerNetworkConfig, requested: SocketAddrV4) -> Option<Self> {
        if requested.port() == 0
            || (!requested.ip().is_unspecified() && *requested.ip() != config.guest_ipv4_address())
        {
            return None;
        }
        Some(Self {
            requested,
            wildcard: requested.ip().is_unspecified(),
        })
    }

    /// Returns the broker-reserved guest-visible binding.
    #[must_use]
    pub const fn requested(self) -> SocketAddrV4 {
        self.requested
    }

    /// Returns whether the original binding used the wildcard address.
    #[must_use]
    pub const fn is_wildcard(self) -> bool {
        self.wildcard
    }

    /// Checks that this value is valid for a provider's shared configuration.
    #[must_use]
    pub fn is_valid_for(self, config: &BrokerNetworkConfig) -> bool {
        Self::new(config, self.requested) == Some(self)
    }

    /// Returns the concrete guest source identity for this binding.
    #[must_use]
    pub fn canonical_address(self, config: &BrokerNetworkConfig) -> Option<SocketAddrV4> {
        if !self.is_valid_for(config) {
            return None;
        }
        config.canonical_guest_address(self.requested)
    }
}

/// Trusted classification of one validated socket destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketDestination {
    /// Route only through the broker-wide guest namespace.
    Guest {
        /// Original guest-requested destination.
        requested: SocketAddrV4,
    },
    /// Route only through the platform's native external path.
    External {
        /// Original guest-requested destination.
        requested: SocketAddrV4,
    },
}

impl SocketDestination {
    /// Returns the original guest-requested destination.
    #[must_use]
    pub const fn requested(self) -> SocketAddrV4 {
        match self {
            Self::Guest { requested } | Self::External { requested } => requested,
        }
    }

    /// Checks that this classification is valid for a provider's shared config.
    #[must_use]
    pub fn is_valid_for(self, config: &BrokerNetworkConfig) -> bool {
        config.classify_destination(self.requested()) == Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_config_validates_private_unicast_identity() {
        assert_eq!(
            BrokerNetworkConfig::default().guest_ipv4_address(),
            Ipv4Addr::new(10, 0, 2, 15)
        );
        for valid in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 0, 1),
        ] {
            assert_eq!(
                BrokerNetworkConfig::new(valid)
                    .expect("private unicast address should be valid")
                    .guest_ipv4_address(),
                valid
            );
        }
        for invalid in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
        ] {
            assert_eq!(BrokerNetworkConfig::new(invalid), None);
        }
    }

    #[test]
    fn destination_classification_uses_only_the_guest_identity() {
        let config = BrokerNetworkConfig::default();
        let guest = SocketAddrV4::new(config.guest_ipv4_address(), 80);
        let loopback = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80);
        assert_eq!(
            config.classify_destination(guest),
            Ok(SocketDestination::Guest { requested: guest })
        );
        assert_eq!(
            config.classify_destination(loopback),
            Ok(SocketDestination::External {
                requested: loopback
            })
        );
        assert_eq!(
            config.classify_destination(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 80)),
            Err(SocketError::InvalidArgument)
        );
        assert_eq!(
            config.classify_destination(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            Err(SocketError::InvalidArgument)
        );
    }

    #[test]
    fn guest_binding_preserves_wildcard_and_canonicalizes_identity() {
        let config = BrokerNetworkConfig::default();
        let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 49152);
        let binding = GuestSocketBinding::new(&config, wildcard).unwrap();
        assert!(binding.is_wildcard());
        assert_eq!(
            binding.canonical_address(&config),
            Some(SocketAddrV4::new(config.guest_ipv4_address(), 49152))
        );
        assert_eq!(
            GuestSocketBinding::new(&config, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152)),
            None
        );
    }
}
