// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The stack's two smoltcp devices: [`Ethernet`], over the runner's
//! [`Link`], and [`Loopback`], for traffic between guest sockets.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use smoltcp::phy::{self, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{IpListenEndpoint, IpProtocol, Ipv4Packet, TcpPacket};

use super::Link;

/// Frames to and from the runner's [`Link`]. smoltcp computes and checks
/// every checksum: the link offloads none.
pub(super) struct Ethernet {
    link: &'static dyn Link,
    receive: Vec<u8>,
    transmit: Vec<u8>,
}

impl Ethernet {
    pub(super) fn new(link: &'static dyn Link) -> Self {
        Self {
            link,
            receive: vec![0; super::MAX_FRAME_SIZE],
            transmit: vec![0; super::ETHERNET_MTU],
        }
    }
}

impl phy::Device for Ethernet {
    type RxToken<'a> = RxToken<'a>;
    type TxToken<'a> = EthernetTxToken<'a>;

    fn receive(&mut self, _now: Instant) -> Option<(RxToken<'_>, EthernetTxToken<'_>)> {
        // A truncated frame (longer than any the stack sends) is dropped.
        let len = loop {
            let len = self.link.receive(&mut self.receive)?;
            if len <= self.receive.len() {
                break len;
            }
        };
        Some((
            RxToken(&self.receive[..len]),
            EthernetTxToken {
                link: self.link,
                buffer: &mut self.transmit,
            },
        ))
    }

    fn transmit(&mut self, _now: Instant) -> Option<EthernetTxToken<'_>> {
        self.link.can_transmit().then_some(EthernetTxToken {
            link: self.link,
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

pub(super) struct RxToken<'a>(&'a [u8]);

impl phy::RxToken for RxToken<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0)
    }
}

pub(super) struct EthernetTxToken<'a> {
    link: &'static dyn Link,
    buffer: &'a mut [u8],
}

impl phy::TxToken for EthernetTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let frame = &mut self.buffer[..len];
        let result = f(frame);
        // The link had room when the token was made; if it no longer does,
        // the frame is lost, as on a congested wire.
        if !self.link.transmit(frame) {
            log::debug!("network link dropped a {len}-byte frame");
        }
        result
    }
}

/// IP packets from the stack back to itself, in order.
pub(super) struct Loopback {
    queue: VecDeque<Vec<u8>>,
    listeners: Vec<ListenerRoom>,
}

/// How many more connections a guest listener can take: now (its
/// listening sockets), and in all (its backlog's room). smoltcp resets a SYN
/// it has no listening socket for: right for a full backlog, which refuses
/// connections, as on the userland broker. But a burst may outrun the
/// listening sockets while the backlog has room; [`Loopback`] then drops the
/// SYN instead, and the sender retries once they are refilled.
pub(super) struct ListenerRoom {
    pub(super) endpoint: IpListenEndpoint,
    pub(super) idle: usize,
    pub(super) backlog: usize,
}

impl Loopback {
    pub(super) const MTU: usize = 65535;

    pub(super) fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            listeners: Vec::new(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// The listeners' room, until set again.
    pub(super) fn set_listeners(&mut self, listeners: Vec<ListenerRoom>) {
        self.listeners = listeners;
    }

    /// Whether `packet` goes to the stack: all but a SYN to a listener
    /// whose backlog has room but whose listening sockets are taken. A SYN
    /// it admits takes some of the room.
    pub(super) fn admits(&mut self, packet: &[u8]) -> bool {
        let Ok(ip) = Ipv4Packet::new_checked(packet) else {
            return true;
        };
        if ip.next_header() != IpProtocol::Tcp {
            return true;
        }
        let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else {
            return true;
        };
        if !tcp.syn() || tcp.ack() {
            return true;
        }
        let destination = ip.dst_addr();
        let Some(listener) = self.listeners.iter_mut().find(|listener| {
            listener.endpoint.port == tcp.dst_port()
                && listener
                    .endpoint
                    .addr
                    .is_none_or(|addr| addr == destination.into())
        }) else {
            // No listener: refused.
            return true;
        };
        let Some(backlog) = listener.backlog.checked_sub(1) else {
            // Full: refused.
            return true;
        };
        let Some(idle) = listener.idle.checked_sub(1) else {
            return false;
        };
        (listener.idle, listener.backlog) = (idle, backlog);
        true
    }
}

impl phy::Device for Loopback {
    type RxToken<'a> = LoopbackRxToken;
    type TxToken<'a> = LoopbackTxToken<'a>;

    fn receive(&mut self, _now: Instant) -> Option<(LoopbackRxToken, LoopbackTxToken<'_>)> {
        let packet = loop {
            let packet = self.queue.pop_front()?;
            if self.admits(&packet) {
                break packet;
            }
        };
        Some((LoopbackRxToken(packet), LoopbackTxToken(&mut self.queue)))
    }

    fn transmit(&mut self, _now: Instant) -> Option<LoopbackTxToken<'_>> {
        Some(LoopbackTxToken(&mut self.queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = Self::MTU;
        // Packets never leave memory.
        capabilities.checksum = ChecksumCapabilities::ignored();
        capabilities
    }
}

pub(super) struct LoopbackRxToken(Vec<u8>);

impl phy::RxToken for LoopbackRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub(super) struct LoopbackTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::TxToken for LoopbackTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}
