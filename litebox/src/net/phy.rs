// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Connection to the physical (i.e., "lower") side for networking.

// TODO(jayb): Do we need to wrap/unwrap the IPv4 header here, or is a better place within the
// implementer of the `platform::IPInterfaceProvider` trait?

use core::cell::RefCell;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::platform;

/// The maximum transmission unit for a device
pub(crate) const DEVICE_MTU: usize = 1600;

/// Upper bound on packets held in the loopback queue. A guest that pushes more
/// than this into loopback faster than the interface drains it loses the
/// excess (TCP retransmits; UDP is lossy by contract), which is strictly
/// better than unbounded host-memory growth from a runaway guest.
const LOOPBACK_QUEUE_CAP: usize = 256;

pub(crate) struct Device<Platform: platform::IPInterfaceProvider + 'static> {
    pub(crate) platform: &'static Platform,
    interface_ip: core::net::Ipv4Addr,
    receive_buffer: [u8; DEVICE_MTU],
    send_buffer: [u8; DEVICE_MTU],
    /// Packets the guest sent to a local interface address (`127.0.0.0/8`, or
    /// the interface's own IP), queued to be handed straight back to the same
    /// interface's receive path instead of out to the platform. This is the
    /// whole of loopback: one interface, one socket set, the real TCP state
    /// machine driving both ends. `RefCell` because a single `Device::receive`
    /// borrow hands out a `TxToken` (which may push here) and an `RxToken`
    /// (drained from here) together.
    loopback: RefCell<VecDeque<Vec<u8>>>,
}

impl<Platform: platform::IPInterfaceProvider> Device<Platform> {
    pub(crate) fn new(platform: &'static Platform) -> Self {
        Self {
            platform,
            interface_ip: super::INTERFACE_IP_ADDR,
            receive_buffer: [0u8; DEVICE_MTU],
            send_buffer: [0u8; DEVICE_MTU],
            loopback: RefCell::new(VecDeque::new()),
        }
    }
}

impl<Platform> super::Network<Platform>
where
    Platform: platform::IPInterfaceProvider
        + platform::TimeProvider
        + crate::sync::RawSyncPrimitivesProvider,
{
    /// Construct a network with optional interface and gateway address overrides.
    pub fn new_with_optional_addrs(
        litebox: &crate::LiteBox<Platform>,
        interface_ip: Option<core::net::Ipv4Addr>,
        gateway_ip: Option<core::net::Ipv4Addr>,
    ) -> Self {
        let mut network = Self::new(litebox);
        if let Some(interface_ip) = interface_ip {
            let default_interface_cidr = smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv4(super::INTERFACE_IP_ADDR),
                24,
            );
            let configured_interface_cidr =
                smoltcp::wire::IpCidr::new(smoltcp::wire::IpAddress::Ipv4(interface_ip), 24);
            network.interface.update_ip_addrs(|ip_addrs| {
                for cidr in ip_addrs.iter_mut() {
                    if *cidr == default_interface_cidr {
                        *cidr = configured_interface_cidr;
                    }
                }
            });
            network.device.interface_ip = interface_ip;
        }
        if let Some(gateway_ip) = gateway_ip {
            let default_route_cidr = smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv4(core::net::Ipv4Addr::UNSPECIFIED),
                0,
            );
            network.interface.routes_mut().update(|routes| {
                for route in routes.iter_mut() {
                    if route.cidr == default_route_cidr {
                        route.via_router = smoltcp::wire::IpAddress::Ipv4(gateway_ip);
                    }
                }
            });
            network.gateway_ip = gateway_ip;
        }
        network
    }

    /// Return the configured IPv4 address for this network's synthetic interface.
    pub fn interface_ip(&self) -> core::net::Ipv4Addr {
        self.device.interface_ip
    }

    /// Return the configured IPv4 default-route gateway for this network.
    pub fn gateway_ip(&self) -> core::net::Ipv4Addr {
        self.gateway_ip
    }

    /// Whether a packet for a destination other than this interface's own addresses (its
    /// external IP and `127.0.0.0/8`, which loop back in-process) can actually leave this
    /// process -- `false` when the platform has no external interface attached and would
    /// silently drop it. See [`platform::IPInterfaceProvider::has_external_interface`].
    pub fn external_interface_available(&self) -> bool {
        self.device.platform.has_external_interface()
    }

    /// Whether `ip` is served entirely inside this network stack (loopback or the interface's
    /// own address), i.e. reachable even with no external interface attached.
    pub fn is_local_ip(&self, ip: core::net::Ipv4Addr) -> bool {
        ip.is_loopback() || ip == self.device.interface_ip
    }

    /// Whether `ip` is the directed broadcast address of the interface's own `/24` (e.g.
    /// `10.0.0.255` for `10.0.0.2/24`). Nothing answers it: the platform side only forwards
    /// unicast, so a caller is told up front instead of waiting out a SYN timeout.
    pub fn is_directed_broadcast(&self, ip: core::net::Ipv4Addr) -> bool {
        let [a, b, c, d] = ip.octets();
        let [ia, ib, ic, _] = self.device.interface_ip.octets();
        d == 255 && [a, b, c] == [ia, ib, ic]
    }
}

/// Whether an IPv4 packet's destination address is one the interface loops
/// back to itself: any `127.0.0.0/8` address, or its own external IP (so a
/// guest connecting to its own `10.0.0.2` also reaches its local servers). A
/// malformed/short packet is not looped.
fn is_loopback_destination(packet: &[u8], interface_ip: core::net::Ipv4Addr) -> bool {
    // The IPv4 destination address is bytes 16..20; require at least an IPv4
    // header's worth of bytes and IP version 4.
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let dst = [packet[16], packet[17], packet[18], packet[19]];
    dst[0] == 127 || dst == interface_ip.octets()
}

impl<Platform: platform::IPInterfaceProvider> smoltcp::phy::Device for Device<Platform> {
    type RxToken<'a>
        = RxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a, Platform>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Drain the loopback queue ahead of the platform: a busy external
        // device must never starve in-process loopback, and a looped packet is
        // always ready. The `TxToken` handed out alongside can push a reply
        // right back into the same queue within this `poll()`.
        let looped = self.loopback.borrow_mut().pop_front();
        if let Some(packet) = looped {
            return Some((
                RxToken::Owned(packet),
                TxToken {
                    platform: self.platform,
                    interface_ip: self.interface_ip,
                    buffer: &mut self.send_buffer,
                    loopback: &self.loopback,
                },
            ));
        }
        match self.platform.receive_ip_packet(&mut self.receive_buffer) {
            Ok(size) => Some((
                RxToken::Borrowed(&self.receive_buffer[..size]),
                TxToken {
                    platform: self.platform,
                    interface_ip: self.interface_ip,
                    buffer: &mut self.send_buffer,
                    loopback: &self.loopback,
                },
            )),
            Err(platform::ReceiveError::WouldBlock) => None,
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            platform: self.platform,
            interface_ip: self.interface_ip,
            buffer: &mut self.send_buffer,
            loopback: &self.loopback,
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = DEVICE_MTU;
        caps
    }
}

/// A received packet: either borrowed from the platform's receive buffer (the
/// external path, no copy) or owned from the loopback queue.
pub(crate) enum RxToken<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl smoltcp::phy::RxToken for RxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        match self {
            RxToken::Borrowed(buffer) => f(buffer),
            RxToken::Owned(packet) => f(&packet),
        }
    }
}

pub(crate) struct TxToken<'a, Platform: platform::IPInterfaceProvider> {
    platform: &'a Platform,
    interface_ip: core::net::Ipv4Addr,
    buffer: &'a mut [u8],
    loopback: &'a RefCell<VecDeque<Vec<u8>>>,
}

impl<Platform: platform::IPInterfaceProvider> smoltcp::phy::TxToken for TxToken<'_, Platform> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let packet = &mut self.buffer[..len];
        let res = f(packet);
        if is_loopback_destination(packet, self.interface_ip) {
            // Loop it back into this interface's own receive path instead of
            // handing it to the platform. The copy is required: `buffer` is
            // the device's reused `send_buffer`.
            let mut queue = self.loopback.borrow_mut();
            if queue.len() < LOOPBACK_QUEUE_CAP {
                queue.push_back(packet.to_vec());
            }
            // Over the cap: drop, as a real loopback would under memory
            // pressure; TCP retransmits.
        } else {
            self.platform
                .send_ip_packet(packet)
                .expect("Sending IP packet failed");
        }
        res
    }
}
