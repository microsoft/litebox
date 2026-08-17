// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-authorized guest binding values.

use core::fmt;
use core::net::SocketAddrV4;

use super::{GuestBindingLease, guest_binding_address_is_valid};

/// Broker-authorized guest binding passed to a platform provider.
#[derive(Clone)]
pub struct GuestSocketBinding {
    requested: SocketAddrV4,
    lease: GuestBindingLease,
}

impl GuestSocketBinding {
    pub(super) fn new(requested: SocketAddrV4, lease: GuestBindingLease) -> Option<Self> {
        if requested.port() == 0
            || !guest_binding_address_is_valid(requested)
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

    /// Checks that this value represents a live supported guest binding.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.requested.port() != 0
            && guest_binding_address_is_valid(self.requested)
            && self.lease.requested_address() == self.requested
    }

    /// Returns whether this binding belongs to the TCP guest namespace.
    #[must_use]
    pub fn is_tcp(&self) -> bool {
        self.lease.inner.transport == super::GuestTransport::Tcp
    }

    /// Returns whether this binding covers one concrete guest loopback address.
    #[must_use]
    pub fn covers(&self, address: SocketAddrV4) -> bool {
        self.is_valid() && self.lease.covers(address)
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
