// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker sockets on smoltcp: a [`SocketProvider`] for brokers without a
//! host network stack to put sockets on, e.g., the LiteBox VM kernel's,
//! which has only a network device. (Hosted brokers use their host's, e.g.,
//! `litebox_broker_platform_linux_userland`.)
//!
//! Runner processes' IPv4 TCP and UDP sockets are the broker's (see
//! `litebox_broker_core::socket`). Here they are smoltcp sockets on one of
//! two interfaces:
//! - Loopback, for the guest network: between guest sockets, at
//!   `127.0.0.1` or [`GUEST_IPV4_ADDRESS`]. Listening sockets are only here,
//!   as on other broker platforms: the guest is not reachable from outside.
//! - Ethernet, over a [`Link`] (e.g., a virtio network device):
//!   everything else, from [`GUEST_IPV4_ADDRESS`] on a /24, through
//!   [`HOST_GATEWAY_IPV4_ADDRESS`]. Without a link, such destinations are
//!   unreachable. With QEMU's user networking, the gateway is the host, e.g.,
//!   `-netdev user,id=n0,net=10.0.2.0/24,host=10.0.2.1`.
//!
//! A guest TCP socket lives on the interface its destination chose; a UDP
//! socket has one smoltcp socket per interface it may use.
//!
//! The stack has no thread of its own: it runs when the broker does
//! ([`Network::poll`], and after every socket operation), and the broker
//! must not sleep past [`Network::next_poll`]. Readiness is published after
//! each run, outside the stack's lock. Time is the broker's [`Clock`].

#![no_std]

extern crate alloc;

mod device;
mod socket;
mod tcp;
mod udp;

#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use litebox_broker_core::BrokerCoreLimits;
use litebox_broker_core::readiness::ReadinessRegistration;
use litebox_broker_core::socket::{
    GUEST_IPV4_ADDRESS, GuestSourceLease, HOST_GATEWAY_IPV4_ADDRESS, SocketProvider,
};
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::SocketError;
use smoltcp::iface::{Config, Interface, Route, SocketHandle, SocketSet};
use smoltcp::socket::AnySocket as _;
use smoltcp::socket::raw;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, IpVersion,
};
use spin::Mutex;

use device::{Ethernet, Loopback};

/// A monotonic clock.
pub trait Clock: Sync {
    /// The time since an arbitrary, fixed instant.
    fn now(&self) -> Duration;
}

/// An Ethernet link for the stack, e.g., a network device. Frames exclude
/// the FCS.
pub trait Link: Sync {
    fn mac(&self) -> [u8; 6];

    /// Copies the next received frame into `frame`, truncated to fit;
    /// returns its length, or `None` if none is waiting.
    fn receive(&self, frame: &mut [u8]) -> Option<usize>;

    /// Whether [`Self::transmit`] would take a frame now.
    fn can_transmit(&self) -> bool;

    /// Sends `frame`, at most [`ETHERNET_MTU`] bytes; false if the link had
    /// no room for it.
    fn transmit(&self, frame: &[u8]) -> bool;

    /// Whether receiving a frame raises an interrupt (ending a broker halt);
    /// else the stack polls the link.
    fn interrupts(&self) -> bool;
}

/// The longest frame sent: a 1500-byte IP packet and its Ethernet header.
pub const ETHERNET_MTU: usize = 1514;

/// The longest frame received: [`ETHERNET_MTU`] and a VLAN tag.
pub const MAX_FRAME_SIZE: usize = 1518;

/// The external network's prefix length.
const PREFIX_LENGTH: u8 = 24;

/// The largest UDP payload sent externally: one unfragmented datagram (the
/// stack does not fragment).
const MAX_EXTERNAL_DATAGRAM: usize = ETHERNET_MTU - 14 - 20 - 8;

/// How long a TCP connection attempt may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(75);

/// How long a closed socket may take to end its connection gracefully.
const CLOSE_TIMEOUT: Duration = Duration::from_mins(1);

/// How often a link that does not interrupt is polled, while the broker
/// halts or a process runs.
const LINK_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// At most this many retired TCP sockets finish their connections at once;
/// beyond, the oldest is dropped.
const MAX_CLOSING: usize = 64;

/// The stack is never asked to run sooner than this after it last did, so a
/// deadline it cannot meet (e.g., output the link has no room for) does not
/// keep the CPU.
const MIN_POLL_DELAY: Duration = Duration::from_millis(1);

/// Bounds a run of the loopback interface, which feeds itself: rounds, and
/// packets in all.
const LOOPBACK_ROUNDS: usize = 1024;
const MAX_LOOPBACK_PACKETS: usize = 16 * 1024;

/// At most this many frames are taken from the link per run, so a flood
/// cannot keep the (single) CPU; the rest wait for the next run, at most
/// [`MIN_POLL_DELAY`] later. One receive ring's worth.
const MAX_FRAMES_PER_RUN: usize = 64;

/// Received datagrams are sifted out of smoltcp's queues (see `Udp::sift`)
/// after at most this many packets, fewer than a UDP socket's queue holds.
const SIFT_BATCH: usize = 16;

/// Each raw ICMP socket's receive queue: packets, of at most the minimum
/// MTU, which ICMP errors fit.
const ICMP_PACKETS: usize = 8;
const IPV4_MIN_MTU: usize = 576;

/// The broker's sockets and their interfaces; clones share them.
#[derive(Clone)]
pub struct Network(Arc<Shared>);

struct Shared {
    stack: Mutex<Stack>,
    /// The link does not interrupt.
    polled: bool,
}

impl Network {
    /// Sockets reach beyond the guest through `link`, if any. `seed` (e.g.,
    /// from a CSPRNG) randomizes, e.g., TCP initial sequence numbers.
    /// `limits` are the broker core's: guest connections not yet accepted
    /// count against their connecting processes' socket limits, as sockets.
    pub fn new(
        clock: &'static dyn Clock,
        link: Option<&'static dyn Link>,
        seed: u64,
        limits: &BrokerCoreLimits,
    ) -> Self {
        Self(Arc::new(Shared {
            stack: Mutex::new(Stack::new(clock, link, seed, limits).with_icmp()),
            polled: link.is_some_and(|link| !link.interrupts()),
        }))
    }

    /// The earliest the stack should run again, e.g., after a device
    /// interrupt: [`MIN_POLL_DELAY`] after it last did, so interrupts cannot
    /// keep the CPU either.
    pub fn earliest_run(&self) -> Duration {
        self.0.stack.lock().last_run.saturating_add(MIN_POLL_DELAY)
    }

    /// For the broker core.
    pub fn provider(&self) -> Arc<dyn SocketProvider> {
        Arc::new(socket::Provider(self.0.clone()))
    }

    /// Runs the stack: sends and receives what it can, and publishes
    /// sockets' readiness.
    pub fn poll(&self) {
        self.0.run(|_| ());
    }

    /// When, on the [`Clock`], the stack must next run (e.g., to
    /// retransmit, or to poll a link that does not interrupt), if ever.
    ///
    /// Relative to when the stack last ran, not to now: a caller comparing
    /// it with its own earlier reading of the clock must see it come due.
    pub fn next_poll(&self) -> Option<Duration> {
        let mut stack = self.0.stack.lock();
        let now = stack.now();
        let last_run = stack.last_run;
        let next = stack
            .next_poll(now)
            .map(|next| next.max(last_run.saturating_add(MIN_POLL_DELAY)));
        if self.0.polled {
            earliest(next, Some(last_run.saturating_add(LINK_POLL_INTERVAL)))
        } else {
            next
        }
    }
}

impl Shared {
    /// Runs `f` on the stack, then the stack itself, then publishes
    /// readiness changes.
    fn run<R>(&self, f: impl FnOnce(&mut Stack) -> R) -> R {
        let mut stack = self.stack.lock();
        let result = f(&mut stack);
        stack.poll();
        let publications = core::mem::take(&mut stack.publications);
        drop(stack);
        for publication in publications {
            // A sink that cannot take an update keeps the snapshot, which
            // `PlatformSocket::readiness` reports.
            let _ = if publication.republish {
                publication.registration.republish(publication.flags)
            } else {
                publication.registration.publish(publication.flags)
            };
        }
        result
    }
}

fn earliest(a: Option<Duration>, b: Option<Duration>) -> Option<Duration> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The interface a socket is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Internal,
    External,
}

/// smoltcp sockets, by interface.
struct Sockets {
    internal: SocketSet<'static>,
    /// With a link.
    external: Option<SocketSet<'static>>,
}

impl Sockets {
    fn set(&mut self, side: Side) -> &mut SocketSet<'static> {
        match side {
            Side::Internal => &mut self.internal,
            Side::External => self
                .external
                .as_mut()
                .expect("external sockets exist only with a link"),
        }
    }

    fn tcp(
        &mut self,
        side: Side,
        handle: SocketHandle,
    ) -> &mut smoltcp::socket::tcp::Socket<'static> {
        self.set(side).get_mut(handle)
    }

    fn udp(
        &mut self,
        side: Side,
        handle: SocketHandle,
    ) -> &mut smoltcp::socket::udp::Socket<'static> {
        self.set(side).get_mut(handle)
    }
}

/// A broker socket.
struct Entry {
    /// The process it is charged to.
    process: ProcessId,
    registration: ReadinessRegistration,
    /// Its readiness as last published; see `PlatformSocket::readiness`.
    snapshot: Arc<AtomicU32>,
    kind: Kind,
}

enum Kind {
    Tcp(tcp::Tcp),
    Udp(udp::Udp),
}

impl Entry {
    fn new(process: ProcessId, registration: ReadinessRegistration, kind: Kind) -> Self {
        Self {
            process,
            registration,
            snapshot: Arc::new(AtomicU32::new(0)),
            kind,
        }
    }

    /// Records `flags` as the snapshot and queues its publication if it
    /// changed, or if `republish` (waking waiters whose condition changed).
    fn update(&self, flags: ReadinessFlags, republish: bool, publications: &mut Vec<Publication>) {
        let changed = self.snapshot.swap(flags.0, Ordering::Relaxed) != flags.0;
        if changed || republish {
            publications.push(Publication {
                registration: self.registration.clone(),
                flags,
                republish: !changed,
            });
        }
    }
}

struct Publication {
    registration: ReadinessRegistration,
    flags: ReadinessFlags,
    republish: bool,
}

/// A guest connection's source lease, charged to the connecting process
/// until the connection is accepted.
struct Lease {
    lease: GuestSourceLease,
    process: ProcessId,
}

/// A retired TCP socket finishing its connection.
struct Closing {
    side: Side,
    handle: SocketHandle,
    deadline: Duration,
}

struct Stack {
    clock: &'static dyn Clock,
    loopback_interface: Interface,
    loopback: Loopback,
    ethernet: Option<(Interface, Ethernet)>,
    sockets: Sockets,
    entries: BTreeMap<u64, Entry>,
    next_id: u64,
    /// Guest TCP connections' sources, kept until their connections are
    /// accepted (which hands them over) or end; see `PlatformSocket::connect`.
    leases: Vec<Lease>,
    max_sockets: usize,
    max_sockets_per_process: usize,
    closing: Vec<Closing>,
    /// When [`Self::poll`] last ran.
    last_run: Duration,
    /// The last run left packets to receive.
    ingress_pending: bool,
    /// By interface: a raw socket receiving ICMP, for errors about UDP
    /// datagrams (see `Udp::destination_error`).
    icmp: [Option<SocketHandle>; 2],
    /// Readiness changes, published after the stack's lock is released.
    publications: Vec<Publication>,
}

impl Stack {
    fn new(
        clock: &'static dyn Clock,
        link: Option<&'static dyn Link>,
        seed: u64,
        limits: &BrokerCoreLimits,
    ) -> Self {
        let now = timestamp(clock.now());
        let mut loopback = Loopback::new();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut loopback_interface = Interface::new(config, &mut loopback, now);
        loopback_interface.update_ip_addrs(|addresses| {
            for cidr in [
                IpCidr::new(Ipv4Addr::LOCALHOST.into(), 8),
                IpCidr::new(GUEST_IPV4_ADDRESS.into(), 32),
            ] {
                addresses.push(cidr).expect("room for two addresses");
            }
        });
        // All of 127.0.0.0/8 is the guest's, as on Linux: accept packets to
        // any of it, not just 127.0.0.1.
        loopback_interface.set_any_ip(true);
        loopback_interface.routes_mut().update(|routes| {
            routes
                .push(Route {
                    cidr: IpCidr::new(Ipv4Addr::new(127, 0, 0, 0).into(), 8),
                    via_router: Ipv4Addr::LOCALHOST.into(),
                    preferred_until: None,
                    expires_at: None,
                })
                .expect("room for a route");
        });
        let ethernet = link.map(|link| {
            let mut device = Ethernet::new(link);
            let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(link.mac())));
            config.random_seed = seed.rotate_left(32);
            let mut interface = Interface::new(config, &mut device, now);
            interface.update_ip_addrs(|addresses| {
                addresses
                    .push(IpCidr::new(GUEST_IPV4_ADDRESS.into(), PREFIX_LENGTH))
                    .expect("room for an address");
            });
            interface
                .routes_mut()
                .add_default_ipv4_route(HOST_GATEWAY_IPV4_ADDRESS)
                .expect("room for a route");
            (interface, device)
        });
        Self {
            clock,
            loopback_interface,
            loopback,
            sockets: Sockets {
                internal: SocketSet::new(vec![]),
                external: ethernet.as_ref().map(|_| SocketSet::new(vec![])),
            },
            ethernet,
            entries: BTreeMap::new(),
            next_id: 0,
            leases: Vec::new(),
            max_sockets: limits.max_sockets,
            max_sockets_per_process: limits.max_sockets_per_process,
            closing: Vec::new(),
            last_run: clock.now(),
            ingress_pending: false,
            icmp: [None, None],
            publications: Vec::new(),
        }
    }

    /// Adds the raw ICMP sockets; see [`Self::icmp`].
    fn with_icmp(mut self) -> Self {
        let socket = || {
            let buffer = |packets, payload| {
                raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; packets], vec![0; payload])
            };
            raw::Socket::new(
                IpVersion::Ipv4,
                IpProtocol::Icmp,
                buffer(ICMP_PACKETS, ICMP_PACKETS * IPV4_MIN_MTU),
                buffer(1, 0),
            )
        };
        self.icmp[Side::Internal as usize] = Some(self.sockets.internal.add(socket()));
        if let Some(external) = self.sockets.external.as_mut() {
            self.icmp[Side::External as usize] = Some(external.add(socket()));
        }
        self
    }

    fn has_link(&self) -> bool {
        self.ethernet.is_some()
    }

    fn now(&self) -> Duration {
        self.clock.now()
    }

    /// Adds a socket, publishing its initial readiness if any.
    fn insert(&mut self, entry: Entry, readiness: ReadinessFlags) -> (u64, Arc<AtomicU32>) {
        let id = self.next_id;
        self.next_id += 1;
        entry.update(readiness, false, &mut self.publications);
        let snapshot = entry.snapshot.clone();
        self.entries.insert(id, entry);
        (id, snapshot)
    }

    /// Runs both interfaces, within bounds ([`MAX_FRAMES_PER_RUN`],
    /// [`MAX_LOOPBACK_PACKETS`]; what is left makes [`Self::next_poll`] due),
    /// then follows every socket's state.
    fn poll(&mut self) {
        let now = self.now();
        self.last_run = now;
        let at = timestamp(now);
        // Guest traffic completes within the run, as far as the bound allows.
        let mut budget = MAX_LOOPBACK_PACKETS;
        for _ in 0..LOOPBACK_ROUNDS {
            budget -= self.receive(Side::Internal, at, budget);
            self.loopback_interface
                .poll_egress(at, &mut self.loopback, &mut self.sockets.internal);
            if self.loopback.is_empty() || budget == 0 {
                break;
            }
        }
        let mut link_pending = false;
        if self.has_link() {
            link_pending =
                self.receive(Side::External, at, MAX_FRAMES_PER_RUN) == MAX_FRAMES_PER_RUN;
            if let (Some((interface, device)), Some(sockets)) =
                (&mut self.ethernet, &mut self.sockets.external)
            {
                interface.poll_egress(at, device, sockets);
            }
        }
        self.ingress_pending = link_pending || !self.loopback.is_empty();
        self.reap(now);
        self.release_leases();
        for entry in self.entries.values_mut() {
            let (flags, republish) = match &mut entry.kind {
                Kind::Tcp(tcp) => tcp.update(&mut self.sockets, now),
                Kind::Udp(udp) => (udp.readiness(&mut self.sockets), false),
            };
            entry.update(flags, republish, &mut self.publications);
        }
    }

    /// Receives at most `budget` packets on `side`; returns how many. Sifts
    /// what UDP sockets received, and refills listeners (guest connections
    /// arrive in bursts), every [`SIFT_BATCH`] packets and at the end.
    fn receive(&mut self, side: Side, at: smoltcp::time::Instant, budget: usize) -> usize {
        use smoltcp::iface::PollIngressSingleResult;
        let mut received = 0;
        while received < budget {
            let result = match side {
                Side::Internal => self.loopback_interface.poll_ingress_single(
                    at,
                    &mut self.loopback,
                    &mut self.sockets.internal,
                ),
                Side::External => {
                    let (Some((interface, device)), Some(sockets)) =
                        (&mut self.ethernet, &mut self.sockets.external)
                    else {
                        break;
                    };
                    interface.poll_ingress_single(at, device, sockets)
                }
            };
            if matches!(result, PollIngressSingleResult::None) {
                break;
            }
            received += 1;
            if received % SIFT_BATCH == 0 {
                self.sift(side);
            }
        }
        self.sift(side);
        received
    }

    /// Moves what UDP sockets on `side` received into their queues, takes
    /// ICMP errors to the sockets they are for, and, for guest traffic,
    /// refills listeners.
    fn sift(&mut self, side: Side) {
        if side == Side::Internal {
            self.refill_listeners();
        }
        let Self {
            entries, sockets, ..
        } = self;
        let set = sockets.set(side);
        for entry in entries.values_mut() {
            if let Kind::Udp(udp) = &mut entry.kind {
                udp.sift(side, set);
            }
        }
        let Some(icmp) = self.icmp[side as usize] else {
            return;
        };
        let set = self.sockets.set(side);
        while let Ok(packet) = set.get_mut::<raw::Socket>(icmp).recv() {
            let Some((source_port, destination, error)) = udp_error(packet, side) else {
                continue;
            };
            for entry in self.entries.values_mut() {
                if let Kind::Udp(udp) = &mut entry.kind
                    && udp.port() == Some(source_port)
                {
                    udp.destination_error(side, destination, error);
                }
            }
        }
    }
    /// Keeps listeners' pools of listening sockets filled, and tells the
    /// loopback device how many connections each can take now.
    fn refill_listeners(&mut self) {
        let mut room = Vec::new();
        for entry in self.entries.values_mut() {
            if let Kind::Tcp(tcp) = &mut entry.kind
                && let Some(listener_room) = tcp.refill(&mut self.sockets.internal)
            {
                room.push(listener_room);
            }
        }
        self.loopback.set_listeners(room);
    }

    fn next_poll(&mut self, now: Duration) -> Option<Duration> {
        let at = timestamp(now);
        let internal = self.loopback_interface.poll_at(at, &self.sockets.internal);
        let external = match (&mut self.ethernet, &self.sockets.external) {
            (Some((interface, _)), Some(sockets)) => interface.poll_at(at, sockets),
            _ => None,
        };
        let closing = self.closing.iter().map(|closing| closing.deadline).min();
        let pending = self.ingress_pending.then_some(Duration::ZERO);
        earliest(
            earliest(internal.map(instant), external.map(instant)),
            earliest(closing, pending),
        )
    }

    /// Removes retired sockets whose connections ended.
    fn reap(&mut self, now: Duration) {
        use smoltcp::socket::tcp::State;
        let sockets = &mut self.sockets;
        self.closing.retain(|closing| {
            let socket = sockets.tcp(closing.side, closing.handle);
            // An aborted socket keeps its endpoints until it sends its reset,
            // which it may never manage (e.g., to a neighbor that does not
            // answer ARP).
            let ended = match socket.state() {
                State::Closed => socket.local_endpoint().is_none() || now >= closing.deadline,
                State::TimeWait => true,
                _ => now >= closing.deadline,
            };
            if ended {
                sockets.set(closing.side).remove(closing.handle);
            }
            !ended
        });
    }

    /// Ends the leases of guest connections that ended before being
    /// accepted.
    fn release_leases(&mut self) {
        use smoltcp::socket::tcp;
        let sockets = &self.sockets.internal;
        self.leases.retain(|lease| {
            let source = IpEndpoint::from(lease.lease.source_address());
            sockets.iter().any(|(_, socket)| {
                tcp::Socket::downcast(socket).is_some_and(|socket| {
                    socket.state() != tcp::State::Closed
                        && (socket.local_endpoint() == Some(source)
                            || socket.remote_endpoint() == Some(source))
                })
            })
        });
    }

    /// Hands a retired TCP socket over to finish its connection: with a
    /// reset if `abort`, else gracefully.
    fn close_tcp(&mut self, side: Side, handle: SocketHandle, abort: bool) {
        let socket = self.sockets.tcp(side, handle);
        if abort {
            socket.abort();
        } else {
            socket.close();
        }
        let deadline = self.now().saturating_add(CLOSE_TIMEOUT);
        self.push_closing(Closing {
            side,
            handle,
            deadline,
        });
    }

    /// Lets a socket finish its connection, within [`MAX_CLOSING`].
    fn push_closing(&mut self, closing: Closing) {
        if self.closing.len() >= MAX_CLOSING {
            let oldest = self.closing.remove(0);
            self.sockets.set(oldest.side).remove(oldest.handle);
        }
        self.closing.push(closing);
    }

    /// How many sockets `process` has, counting guest connections it made
    /// that are not yet accepted; and how many all processes have.
    fn socket_counts(&self, process: ProcessId) -> (usize, usize) {
        let process_count = self
            .entries
            .values()
            .filter(|entry| entry.process == process)
            .count()
            + self
                .leases
                .iter()
                .filter(|lease| lease.process == process)
                .count();
        (process_count, self.entries.len() + self.leases.len())
    }

    /// Discards the guest connections `process` made that are not yet
    /// accepted, and their leases.
    fn close_process(&mut self, process: ProcessId) {
        let sources: Vec<IpEndpoint> = self
            .leases
            .iter()
            .filter(|lease| lease.process == process)
            .map(|lease| IpEndpoint::from(lease.lease.source_address()))
            .collect();
        if sources.is_empty() {
            return;
        }
        self.leases.retain(|lease| lease.process != process);
        for entry in self.entries.values_mut() {
            if let Kind::Tcp(tcp) = &mut entry.kind {
                tcp.discard_pending(&mut self.sockets, &sources);
            }
        }
    }

    fn retire(&mut self, id: u64) {
        let Some(entry) = self.entries.remove(&id) else {
            return;
        };
        match entry.kind {
            Kind::Tcp(tcp) => tcp.retire(self),
            Kind::Udp(udp) => udp.retire(&mut self.sockets),
        }
    }
}

/// From an ICMP "destination unreachable" `packet` (IPv4, as received on
/// `side`) about a UDP datagram: the datagram's source port, its
/// destination, and the error it means, if Linux reports it.
///
/// Linux reports only "hard" errors to a connected UDP socket (without
/// `IP_RECVERR`): those `icmp_err_convert` marks fatal, as `__udp4_lib_err`
/// applies it. Soft ones (e.g., network or host unreachable, codes 0 and 1)
/// are ignored. Errnos the broker protocol lacks map to the nearest it has
/// (`EHOSTDOWN`, `ENONET`: host unreachable; `ENOPROTOOPT`: other).
/// "Fragmentation needed" is not reported: the stack sends no datagram
/// larger than its MTU, and has no `EMSGSIZE`.
///
/// Parsed here, not by smoltcp, which rejects the usual quote: the
/// datagram's headers and only the start of its payload (e.g., eight bytes,
/// per RFC 792).
fn udp_error(packet: &[u8], side: Side) -> Option<(u16, SocketAddrV4, SocketError)> {
    use smoltcp::wire::{Icmpv4Packet, Ipv4Packet};
    /// ICMP type 3, and its header's length.
    const DESTINATION_UNREACHABLE: u8 = 3;
    const ICMP_HEADER: usize = 8;
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    let icmp = ip.payload();
    // Loopback packets carry no checksums.
    if side == Side::External && !Icmpv4Packet::new_checked(icmp).ok()?.verify_checksum() {
        return None;
    }
    if icmp.len() < ICMP_HEADER || icmp[0] != DESTINATION_UNREACHABLE {
        return None;
    }
    let quote = &icmp[ICMP_HEADER..];
    if quote.len() < 20 {
        return None;
    }
    let quoted = Ipv4Packet::new_unchecked(quote);
    let header_len = usize::from(quoted.header_len());
    let ports = quote.get(header_len..header_len + 4)?;
    if header_len < 20 || quoted.next_header() != IpProtocol::Udp {
        return None;
    }
    // By code, as `icmp_err_convert`'s fatal entries: protocol and port
    // unreachable; network unknown and prohibited; host unknown, isolated
    // and prohibited, communication prohibited, precedence violation and
    // cutoff.
    let error = match icmp[1] {
        2 => SocketError::Other,
        3 => SocketError::ConnectionRefused,
        6 | 9 => SocketError::NetworkUnreachable,
        7 | 8 | 10 | 13..=15 => SocketError::HostUnreachable,
        _ => return None,
    };
    let source_port = u16::from_be_bytes([ports[0], ports[1]]);
    let destination =
        SocketAddrV4::new(quoted.dst_addr(), u16::from_be_bytes([ports[2], ports[3]]));
    Some((source_port, destination, error))
}

fn timestamp(time: Duration) -> smoltcp::time::Instant {
    smoltcp::time::Instant::from_micros(i64::try_from(time.as_micros()).unwrap_or(i64::MAX))
}

fn instant(timestamp: smoltcp::time::Instant) -> Duration {
    Duration::from_micros(u64::try_from(timestamp.total_micros()).unwrap_or(0))
}

fn ipv4(address: IpAddress) -> Ipv4Addr {
    let IpAddress::Ipv4(address) = address;
    address
}

fn socket_address(endpoint: IpEndpoint) -> SocketAddrV4 {
    SocketAddrV4::new(ipv4(endpoint.addr), endpoint.port)
}
