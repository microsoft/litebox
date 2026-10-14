// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The stack's smoltcp device: [`Ethernet`], over the [`Network`] device.

use alloc::vec;
use alloc::vec::Vec;
use core::net::SocketAddrV4;
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, TcpPacket};

use super::Network;

/// Frames to and from the [`Network`] device. smoltcp computes and checks
/// every checksum: the device offloads none.
///
/// Frames it drops (see [`admits`]) still reach smoltcp, empty,
/// which counts them as processed and ignores them: a run's frame budget
/// covers every frame taken off the device.
pub(super) struct Ethernet {
    network: &'static dyn Network,
    receive: Vec<u8>,
    transmit: Vec<u8>,
    /// The connections TCP segments came for (see [`Heard`]).
    pub(super) heard: Heard,
}

impl Ethernet {
    pub(super) fn new(network: &'static dyn Network) -> Self {
        Self {
            network,
            receive: vec![0; super::MAX_FRAME_SIZE],
            transmit: vec![0; super::ETHERNET_MTU],
            heard: Vec::new(),
        }
    }
}

impl phy::Device for Ethernet {
    type RxToken<'a> = RxToken<'a>;
    type TxToken<'a> = EthernetTxToken<'a>;

    fn receive(&mut self, _now: Instant) -> Option<(RxToken<'_>, EthernetTxToken<'_>)> {
        let len = self.network.receive(&mut self.receive)?;
        // Truncated (longer than any the stack sends), or martian.
        let len = if len <= self.receive.len() && admits(&self.receive[..len]) {
            len
        } else {
            0
        };
        if let Ok(frame) = EthernetFrame::new_checked(&self.receive[..len])
            && frame.ethertype() == EthernetProtocol::Ipv4
            && let Some(connection) = tcp_connection(frame.payload())
        {
            self.heard.push(connection);
        }
        Some((
            RxToken(&self.receive[..len]),
            EthernetTxToken {
                network: self.network,
                buffer: &mut self.transmit,
            },
        ))
    }

    fn transmit(&mut self, _now: Instant) -> Option<EthernetTxToken<'_>> {
        self.network.can_transmit().then_some(EthernetTxToken {
            network: self.network,
            buffer: &mut self.transmit,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = super::ETHERNET_MTU;
        capabilities
    }
}

/// Whether `frame` from the device may reach the stack: not an IPv4 packet
/// with a martian address, which Linux drops by default (as with
/// `route_localnet` and `accept_local` off): a source on loopback, in
/// `0.0.0.0/8`, or the guest's own (the device cannot carry the guest's own
/// traffic); a destination on loopback or in `0.0.0.0/8`. smoltcp drops
/// broadcast and multicast sources itself. Without this, e.g., a datagram
/// "from 127.0.0.1" would reach a socket connected to a loopback peer.
pub(super) fn admits(frame: &[u8]) -> bool {
    let Ok(ethernet) = EthernetFrame::new_checked(frame) else {
        return true;
    };
    if ethernet.ethertype() != EthernetProtocol::Ipv4 {
        return true;
    }
    let Ok(ip) = Ipv4Packet::new_checked(ethernet.payload()) else {
        return true;
    };
    let martian = |address: core::net::Ipv4Addr| address.is_loopback() || address.octets()[0] == 0;
    let (source, destination) = (ip.src_addr(), ip.dst_addr());
    !(martian(source) || source == super::GUEST_IPV4_ADDRESS || martian(destination))
}

/// Connections, as (local, remote) endpoints, that TCP segments came for,
/// in a run: when smoltcp last heard from a peer, which it counts its
/// timeouts from but does not tell.
pub(super) type Heard = Vec<(SocketAddrV4, SocketAddrV4)>;

/// The connection `packet` (IPv4) is a TCP segment for.
fn tcp_connection(packet: &[u8]) -> Option<(SocketAddrV4, SocketAddrV4)> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    Some((
        SocketAddrV4::new(ip.dst_addr(), tcp.dst_port()),
        SocketAddrV4::new(ip.src_addr(), tcp.src_port()),
    ))
}

pub(super) struct RxToken<'a>(&'a [u8]);

impl phy::RxToken for RxToken<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0)
    }
}

pub(super) struct EthernetTxToken<'a> {
    network: &'static dyn Network,
    buffer: &'a mut [u8],
}

impl phy::TxToken for EthernetTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let frame = &mut self.buffer[..len];
        let result = f(frame);
        // The device had room when the token was made; if it no longer does,
        // the frame is lost, as on a congested wire.
        if !self.network.transmit(frame) {
            log::debug!("network device dropped a {len}-byte frame");
        }
        result
    }
}
