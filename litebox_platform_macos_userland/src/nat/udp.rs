// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! UDP flow relay: one nonblocking host datagram socket per guest UDP flow.
//!
//! Guest-to-host: a datagram for a new flow binds an ephemeral host socket --
//! the `UdpSocket::bind("0.0.0.0:0")` `net_proxy`'s DNS resolver already
//! performs under the runner's Seatbelt profile -- and `send_to`s the
//! payload. Host-to-guest: once per engine-loop tick a zero-timeout `poll(2)`
//! over the flow set finds readable sockets; each reply is re-wrapped with
//! the dialed destination as its source (source preservation, so the guest's
//! connected UDP socket accepts it as the remote's answer) and queued toward
//! the guest. Flows idle past [`UDP_IDLE_TIMEOUT`] are reaped on the same
//! tick; a re-sent datagram on the same 4-tuple dials a fresh flow, which is
//! how a real NAT's rebinding behaves too.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IPV4_HEADER_LEN, IpProtocol, Ipv4Packet, Ipv4Repr, UDP_HEADER_LEN, UdpPacket, UdpRepr,
};

use super::{DEVICE_MTU, FlowKey, NatDevice, TO_GUEST_QUEUE_CAP};

/// Flows idle longer than this are closed and removed on an engine-loop
/// tick: the `nf_conntrack_udp_timeout_stream` ballpark.
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Bound on concurrent flows; a dial past it evicts the idlest flow (LRU),
/// bounding host fd and memory use.
const UDP_FLOWS_MAX: usize = 1024;

/// Largest host-to-guest payload relayed in one packet: the engine MTU minus
/// the IPv4 and UDP headers. Larger datagrams are dropped -- UDP is lossy,
/// and standards-compliant DNS retries over TCP, which the TCP relay carries.
const MAX_INBOUND_PAYLOAD: usize = DEVICE_MTU - IPV4_HEADER_LEN - UDP_HEADER_LEN;

/// Datagrams drained from one host socket per engine tick; bounds the time one
/// busy (or wedged) socket can hold the net_worker.
const MAX_DATAGRAMS_PER_TICK: usize = 64;

/// Larger than any UDP/IPv4 datagram (the protocol caps payloads at 65507
/// bytes), so a receive buffer this size cannot truncate: a datagram reported
/// longer than [`MAX_INBOUND_PAYLOAD`] is genuinely oversize.
const MAX_DATAGRAM: usize = 65536;

/// Per-flow UDP relay state: the host socket the flow's datagrams are relayed
/// through, the guest address replies are sent back to, and the liveness
/// stamp the idle reap consults. (The guest's source port and the dialed
/// destination live in the flow's [`FlowKey`].)
pub(crate) struct UdpFlow {
    host: UdpSocket,
    guest_ip: core::net::Ipv4Addr,
    last_activity: Instant,
}

impl UdpFlow {
    /// Bind an ephemeral host UDP socket for a new flow, nonblocking: the
    /// engine loop services it on its tick rather than blocking a thread the
    /// way `net_proxy`'s resolver does.
    fn dial(guest_ip: core::net::Ipv4Addr) -> Option<Self> {
        let host = match UdpSocket::bind("0.0.0.0:0") {
            Ok(host) => host,
            Err(e) => {
                litebox_util_log::debug!(error:% = e; "nat: udp flow dial failed");
                return None;
            }
        };
        if let Err(e) = host.set_nonblocking(true) {
            litebox_util_log::debug!(error:% = e; "nat: udp flow nonblocking setup failed");
            return None;
        }
        Some(Self {
            host,
            guest_ip,
            last_activity: Instant::now(),
        })
    }
}

/// Relay one guest-to-host datagram: dial on a flow miss (evicting the
/// idlest flow when the table is full), then `send_to`. A bind or send
/// failure drops the datagram -- UDP is lossy, and the guest retransmits if
/// the loss matters.
pub(crate) fn relay_from_guest(
    flows: &mut HashMap<FlowKey, UdpFlow>,
    key: FlowKey,
    guest_ip: core::net::Ipv4Addr,
    payload: &[u8],
) {
    let dst = SocketAddr::from((key.dst_ip, key.dst_port));
    // A send that fails gets exactly one retry on a fresh host socket. Witnessed on this
    // host (macOS, plain std, sandboxed or not): a few hundred milliseconds after a UDP
    // socket has received its replies the kernel parks a pending error on it (`recvfrom`
    // reports errno 65435 -- `(u16)-101` -- with `POLLIN` set) and every later `sendto`
    // on that socket fails with `EINVAL`. Keeping such a flow lost the guest's next
    // datagram on the same 4-tuple (a resolver's AAAA query after its A query, seen as
    // `nslookup: No answer`); replacing the socket delivers it.
    for attempt in 0..2 {
        if !flows.contains_key(&key) {
            if flows.len() >= UDP_FLOWS_MAX {
                evict_idlest(flows);
            }
            let Some(flow) = UdpFlow::dial(guest_ip) else {
                return;
            };
            flows.insert(key, flow);
        }
        let Some(flow) = flows.get_mut(&key) else {
            return;
        };
        match flow.host.send_to(payload, dst) {
            Ok(_) => {
                flow.last_activity = Instant::now();
                return;
            }
            Err(e) => {
                litebox_util_log::debug!(error:% = e, raw:? = e.raw_os_error(), fd:? = flow.host.as_raw_fd(), dst:% = key.dst_ip, dst_port:? = key.dst_port, len:? = payload.len(), attempt:? = attempt; "nat: udp send failed; replacing the flow's host socket");
                flows.remove(&key);
            }
        }
    }
}

/// Service host-to-guest readiness for the whole flow set; run once per
/// engine-loop tick. One `poll(2)` with a zero timeout (readiness is
/// sampled, never waited on -- the net_worker tick is the wait), then a
/// drain of each readable socket.
pub(crate) fn poll_to_guest(flows: &mut HashMap<FlowKey, UdpFlow>, device: &NatDevice) {
    if flows.is_empty() {
        return;
    }
    let keys: Vec<FlowKey> = flows.keys().copied().collect();
    let mut fds: Vec<libc::pollfd> = keys
        .iter()
        .map(|key| libc::pollfd {
            fd: flows[key].host.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    // The fds are owned by the flows in the table, which outlive this call.
    let ready = unsafe {
        libc::poll(
            fds.as_mut_ptr(),
            // The flow cap keeps this well under nfds_t's range.
            libc::nfds_t::try_from(fds.len()).unwrap(),
            0,
        )
    };
    if ready <= 0 {
        return;
    }
    let mut buf = vec![0u8; MAX_DATAGRAM];
    // Host sockets that reported an error: closed below, so the guest's next datagram on
    // the 4-tuple dials a fresh one (see `relay_from_guest` for the pending-error story).
    let mut dead: Vec<FlowKey> = Vec::new();
    for (key, pfd) in keys.iter().zip(&fds) {
        if pfd.revents == 0 {
            continue;
        }
        let expected = SocketAddr::from((key.dst_ip, key.dst_port));
        let Some(flow) = flows.get_mut(key) else {
            continue;
        };
        // Bounded per tick: a socket that keeps reporting readiness (a connected macOS
        // UDP socket answers `recv` with 0 bytes forever once its pending error fired)
        // must not pin the net_worker, which is every flow's clock.
        for _ in 0..MAX_DATAGRAMS_PER_TICK {
            match flow.host.recv_from(&mut buf) {
                Ok((n, source)) => {
                    // The socket is unconnected, so off-path sources are
                    // filtered here the way `net_proxy`'s resolver does.
                    if source != expected {
                        continue;
                    }
                    flow.last_activity = Instant::now();
                    if n > MAX_INBOUND_PAYLOAD {
                        litebox_util_log::debug!(len:? = n; "nat: dropping oversize udp reply");
                        continue;
                    }
                    push_reply(device, key, flow.guest_ip, &buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    litebox_util_log::debug!(error:% = e, raw:? = e.raw_os_error(), fd:? = flow.host.as_raw_fd(), revents:? = pfd.revents; "nat: udp host socket reported an error; closing it");
                    dead.push(*key);
                    break;
                }
            }
        }
    }
    for key in dead {
        flows.remove(&key);
    }
}

/// Close and remove every flow idle past [`UDP_IDLE_TIMEOUT`]; run once per
/// engine-loop tick. Dropping a flow closes its host socket. Returns the
/// reaped count for the caller's debug log.
pub(crate) fn reap_idle(flows: &mut HashMap<FlowKey, UdpFlow>, now: Instant) -> usize {
    let before = flows.len();
    flows.retain(|_, flow| now.duration_since(flow.last_activity) <= UDP_IDLE_TIMEOUT);
    before - flows.len()
}

/// Drop the flow with the oldest activity stamp, making room for a new dial.
fn evict_idlest(flows: &mut HashMap<FlowKey, UdpFlow>) {
    let Some((&idlest, _)) = flows.iter().min_by_key(|(_, flow)| flow.last_activity) else {
        return;
    };
    flows.remove(&idlest);
}

/// Re-wrap a host reply as an IP packet from the dialed destination to the
/// guest and queue it toward the guest, dropping over the queue cap as a NIC
/// under memory pressure would (mirroring the device `TxToken`).
fn push_reply(device: &NatDevice, key: &FlowKey, guest_ip: core::net::Ipv4Addr, payload: &[u8]) {
    let mut packet = vec![0u8; IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len()];
    let src = smoltcp::wire::IpAddress::Ipv4(key.dst_ip);
    let dst = smoltcp::wire::IpAddress::Ipv4(guest_ip);
    UdpRepr {
        src_port: key.dst_port,
        dst_port: key.src_port,
    }
    .emit(
        &mut UdpPacket::new_unchecked(&mut packet[IPV4_HEADER_LEN..]),
        &src,
        &dst,
        payload.len(),
        |buf| buf.copy_from_slice(payload),
        &ChecksumCapabilities::default(),
    );
    Ipv4Repr {
        src_addr: key.dst_ip,
        dst_addr: guest_ip,
        next_header: IpProtocol::Udp,
        payload_len: UDP_HEADER_LEN + payload.len(),
        hop_limit: 64,
    }
    .emit(
        &mut Ipv4Packet::new_unchecked(&mut packet[..]),
        &ChecksumCapabilities::default(),
    );
    // The capability defaults already computed both checksums above; fill
    // them explicitly so the packet is valid under any capability set.
    UdpPacket::new_unchecked(&mut packet[IPV4_HEADER_LEN..]).fill_checksum(&src, &dst);
    Ipv4Packet::new_unchecked(&mut packet[..]).fill_checksum();
    let mut egress = device.egress.lock().unwrap();
    if egress.len() < TO_GUEST_QUEUE_CAP {
        egress.push_back(packet);
    } else {
        litebox_util_log::debug!("nat: dropping udp reply, guest-bound queue full");
    }
}
