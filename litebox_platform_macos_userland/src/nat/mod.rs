// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Rootless guest NAT: a second smoltcp stack, private to this platform, that
//! terminates guest TCP flows and relays guest UDP datagrams over ordinary
//! host sockets, so outbound guest connectivity works with neither a `utun`
//! device (which needs root) nor the `--net-proxy` loopback proxy (which needs
//! proxy env vars in the guest).
//!
//! The engine's interface owns only the gateway address as a /32 and sets
//! `any_ip`, so every externally routed guest packet is accepted locally. The
//! guest is unaware: its own stack keeps `10.0.0.2/24` with its default route
//! via the gateway, and every guest-visible semantic -- readiness, blocking,
//! `getsockname`/`getpeername`, close -- comes from the guest's own sockets,
//! unchanged.
//!
//! The engine runs entirely inside the platform's `send_ip_packet` /
//! `receive_ip_packet` bodies on the shim's net_worker, so it is
//! single-threaded by construction. The `Mutex` on each device queue exists
//! because smoltcp's `phy::Device` hands out a transmit token that must push
//! into the egress queue while `receive`/`transmit` hold only `&mut self`
//! borrows -- the same role `RefCell` plays for the loopback queue in
//! litebox's `phy`.

use std::collections::{HashMap, VecDeque};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::Mutex;

mod tcp;
mod udp;

use tcp::TcpFlow;
use udp::UdpFlow;

/// MTU of the engine's interface, mirroring litebox's `phy::DEVICE_MTU`
/// (private there) so both sides of the platform boundary fragment
/// identically.
const DEVICE_MTU: usize = 1600;

/// Cap on packets queued toward the guest, mirroring litebox's
/// `LOOPBACK_QUEUE_CAP` (also private): past this, drops bound host-memory
/// growth -- TCP retransmits, and UDP is lossy by contract.
const TO_GUEST_QUEUE_CAP: usize = 256;

/// Hard cap on live flow-table entries across both protocols. Every flow owns
/// a host socket, so the table stays well inside the runner's (raised) fd
/// budget. A `connect` past the cap gets the failed-dial treatment: the SYN
/// is fed with no listener and the interface's no-match fallback answers RST,
/// so the guest sees a prompt ECONNREFUSED rather than a hang. UDP has no
/// refusal to send back, so a datagram that would exceed the cap is dropped
/// and the guest retransmits if the loss matters.
const FLOW_ENTRIES_MAX: usize = 4096;

/// Identifies one guest-initiated flow. The guest's source IP is not part of
/// the key: the guest has exactly one interface address, so
/// (proto, src_port, dst) is already unique.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FlowKey {
    /// IP protocol number (6 = TCP, 17 = UDP).
    proto: u8,
    /// Guest-side source port.
    src_port: u16,
    /// The destination the guest dialed; the NAT-side socket listens on
    /// exactly this, and the host-side flow connects to it.
    dst_ip: core::net::Ipv4Addr,
    dst_port: u16,
}

/// The smoltcp `phy::Device` bridging guest packets into the engine's
/// interface and the interface's replies back toward the guest.
pub(crate) struct NatDevice {
    /// Guest-originated packets waiting to be fed to the interface
    /// (`Device::receive` pops here).
    ingress: Mutex<VecDeque<Vec<u8>>>,
    /// Packets the interface emitted toward the guest (`Device::transmit`'s
    /// token pushes here, `NatEngine::take_packet_to_guest` pops).
    egress: Mutex<VecDeque<Vec<u8>>>,
}

impl smoltcp::phy::Device for NatDevice {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.ingress.lock().unwrap().pop_front()?;
        Some((
            RxToken(packet),
            TxToken {
                egress: &self.egress,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            egress: &self.egress,
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = DEVICE_MTU;
        caps
    }
}

/// A received guest packet, owned: it was popped out of the ingress queue.
pub(crate) struct RxToken(Vec<u8>);

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub(crate) struct TxToken<'a> {
    egress: &'a Mutex<VecDeque<Vec<u8>>>,
}

impl smoltcp::phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let res = f(&mut packet);
        let mut egress = self.egress.lock().unwrap();
        if egress.len() < TO_GUEST_QUEUE_CAP {
            egress.push_back(packet);
        }
        // Over the cap: drop, as a real NIC would under memory pressure.
        res
    }
}

/// The NAT engine: one any-IP smoltcp interface over a [`NatDevice`], plus the
/// per-flow relay tables.
pub(crate) struct NatEngine {
    iface: smoltcp::iface::Interface,
    sockets: smoltcp::iface::SocketSet<'static>,
    device: NatDevice,
    tcp_flows: HashMap<FlowKey, TcpFlow>,
    /// Readiness of every connected host TCP stream: each is registered
    /// here for `EVFILT_READ` when its dial completes and drops out when the
    /// stream closes, so a tick learns which flows to `read` in O(ready)
    /// rather than O(flows) kernel work.
    tcp_kqueue: OwnedFd,
    /// The registered host stream descriptors, back to their flows -- what
    /// a `kevent` result's `ident` is resolved through.
    tcp_host_fds: HashMap<RawFd, FlowKey>,
    udp_flows: HashMap<FlowKey, UdpFlow>,
    /// smoltcp timestamps are relative; this anchors them to host time.
    zero_time: std::time::Instant,
}

impl NatEngine {
    /// Build the engine's interface for the guest's gateway address: own
    /// exactly that address as a /32, accept any destination that routes
    /// through it (`set_any_ip`), and default-route everything via it. This is
    /// the `Config::new` / `Interface::new` / `add_default_ipv4_route`
    /// sequence litebox's `Network::new` uses, with a /32 plus `any_ip` in
    /// place of the guest's /24.
    pub(crate) fn new(gateway_ip: core::net::Ipv4Addr) -> Self {
        let mut device = NatDevice {
            ingress: Mutex::new(VecDeque::new()),
            egress: Mutex::new(VecDeque::new()),
        };
        let config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut iface =
            smoltcp::iface::Interface::new(config, &mut device, smoltcp::time::Instant::ZERO);
        iface.update_ip_addrs(|ip_addrs| {
            match ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv4(gateway_ip),
                32,
            )) {
                Ok(()) => {}
                Err(_) => unreachable!(),
            }
        });
        iface.set_any_ip(true);
        match iface.routes_mut().add_default_ipv4_route(gateway_ip) {
            Ok(None) => {}
            _ => unreachable!(),
        }
        // SAFETY: `kqueue` returns a fresh descriptor this engine alone owns;
        // it fails only on descriptor or memory exhaustion, which at engine
        // construction (pre-sandbox, nofile raised) cannot be recovered from.
        let kqueue = unsafe { libc::kqueue() };
        assert!(
            kqueue >= 0,
            "nat: kqueue() failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: a valid, exclusively owned descriptor from `kqueue()`.
        let tcp_kqueue = unsafe { OwnedFd::from_raw_fd(kqueue) };
        Self {
            iface,
            sockets: smoltcp::iface::SocketSet::new(vec![]),
            device,
            tcp_flows: HashMap::new(),
            tcp_kqueue,
            tcp_host_fds: HashMap::new(),
            udp_flows: HashMap::new(),
            zero_time: std::time::Instant::now(),
        }
    }

    /// The current (smoltcp) Instant, relative to `zero_time`.
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(
            // This conversion from u128 to i64 should practically never fail, since 2^63
            // microseconds is roughly 250 years. If a system has been up for that long, then it
            // deserves to panic.
            i64::try_from(self.zero_time.elapsed().as_micros()).unwrap(),
        )
    }

    /// Take one packet the guest tried to send externally and route it to its
    /// relay: TCP segments to the flow relay, UDP datagrams to the datagram
    /// relay, anything else dropped as a NIC drops what it cannot use. The
    /// flow-table cap is enforced here, at the dispatch edge, so one bound
    /// covers both protocols; flows that already exist are never affected by
    /// it.
    pub(crate) fn ingest_guest_packet(&mut self, packet: &[u8]) {
        let Ok(ip) = smoltcp::wire::Ipv4Packet::new_checked(packet) else {
            litebox_util_log::debug!(len:? = packet.len(); "nat: dropping malformed guest packet");
            return;
        };
        match ip.next_header() {
            smoltcp::wire::IpProtocol::Tcp => {
                if let Ok(segment) = smoltcp::wire::TcpPacket::new_checked(ip.payload()) {
                    let key = FlowKey {
                        proto: 6, // TCP
                        src_port: segment.src_port(),
                        dst_ip: ip.dst_addr(),
                        dst_port: segment.dst_port(),
                    };
                    // A novel SYN past the cap is fed to the interface with no
                    // listener; the no-match fallback answers RST -- the same
                    // treatment the relay gives a failed dial.
                    if segment.syn()
                        && !segment.ack()
                        && !self.tcp_flows.contains_key(&key)
                        && self.tcp_flows.len() + self.udp_flows.len() >= FLOW_ENTRIES_MAX
                    {
                        litebox_util_log::debug!(dst:% = key.dst_ip, dst_port:% = key.dst_port; "nat: flow table full; refusing guest SYN");
                        self.device
                            .ingress
                            .lock()
                            .unwrap()
                            .push_back(packet.to_vec());
                        return;
                    }
                }
                // Malformed segments, segments for known flows, and novel
                // SYNs under the cap: the relay owns the rest of the
                // classifier.
                self.ingest_tcp_packet(packet);
            }
            smoltcp::wire::IpProtocol::Udp => {
                let Ok(datagram) = smoltcp::wire::UdpPacket::new_checked(ip.payload()) else {
                    litebox_util_log::debug!(dst:% = ip.dst_addr(); "nat: dropping malformed guest UDP datagram");
                    return;
                };
                let dst = ip.dst_addr();
                if dst.is_multicast() || dst == core::net::Ipv4Addr::BROADCAST {
                    litebox_util_log::debug!(dst:% = dst; "nat: dropping guest datagram to a non-unicast address");
                    return;
                }
                // The guest fabric is the gateway's /24 by runner
                // construction. Packets to the guest's own address loop back
                // inside litebox's phy and never arrive here; anything else in
                // the /24 is not ours to NAT.
                if let Some(gateway) = self.iface.ipv4_addr()
                    && gateway.octets()[..3] == dst.octets()[..3]
                {
                    litebox_util_log::debug!(dst:% = dst; "nat: dropping guest datagram to the guest fabric");
                    return;
                }
                let key = FlowKey {
                    proto: 17, // UDP
                    src_port: datagram.src_port(),
                    dst_ip: dst,
                    dst_port: datagram.dst_port(),
                };
                if !self.udp_flows.contains_key(&key)
                    && self.tcp_flows.len() + self.udp_flows.len() >= FLOW_ENTRIES_MAX
                {
                    litebox_util_log::debug!(dst:% = dst, dst_port:% = key.dst_port; "nat: flow table full; dropping guest datagram");
                    return;
                }
                udp::relay_from_guest(&mut self.udp_flows, key, ip.src_addr(), datagram.payload());
            }
            _ => litebox_util_log::debug!(
                dst:% = ip.dst_addr(), protocol:? = ip.next_header();
                "nat: dropping guest packet of unrelayed protocol"
            ),
        }
    }

    /// Advance the engine one tick: the TCP relay first (it ends with an
    /// interface poll of its own, so dial outcomes, re-fed SYNs, and freshly
    /// pumped data all reach the guest this tick), then UDP readiness toward
    /// the guest and the idle reap.
    pub(crate) fn poll_host_side(&mut self) {
        self.poll_tcp_flows();
        udp::poll_to_guest(&mut self.udp_flows, &self.device);
        let reaped = udp::reap_idle(&mut self.udp_flows, std::time::Instant::now());
        if reaped > 0 {
            litebox_util_log::debug!(reaped:% = reaped; "nat: reaped idle udp flows");
        }
    }

    /// Pop one engine-emitted packet for the platform's receive path to hand
    /// to the guest. `None` means the queue is empty (the platform maps that
    /// to `WouldBlock`).
    pub(crate) fn take_packet_to_guest(&mut self, buf: &mut [u8]) -> Option<usize> {
        let packet = self.device.egress.lock().unwrap().pop_front()?;
        if packet.len() > buf.len() {
            // The caller's buffer is the guest device's MTU-sized receive
            // buffer; a packet larger than that is dropped, as a NIC would.
            return None;
        }
        buf[..packet.len()].copy_from_slice(&packet);
        Some(packet.len())
    }
}
