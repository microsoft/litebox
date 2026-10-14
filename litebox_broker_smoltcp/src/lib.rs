// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker sockets on smoltcp: a
//! [`SocketProvider`](litebox_broker_core::socket::SocketProvider) for
//! brokers with a network device but no host network stack to put sockets
//! on, e.g., the LiteBox VM kernel's (a virtio network device). Brokers
//! with a host network stack put their sockets on the host's instead, as
//! `litebox_broker_platform_linux_userland` does. It is `no_std`, with
//! `alloc`.
//!
//! Runner processes' IPv4 TCP and UDP sockets are the broker's (see
//! `litebox_broker_core::socket`), which mediates all their traffic:
//! - To other hosts, through smoltcp sockets on an Ethernet interface
//!   over a [`Network`] device, from [`GUEST_IPV4_ADDRESS`] on a /24,
//!   through [`HOST_GATEWAY_IPV4_ADDRESS`]. Without a device, such
//!   destinations are unreachable. (E.g., with QEMU's user networking, the
//!   gateway is the host: `-netdev user,id=n0,net=10.0.2.0/24,host=10.0.2.1`.)
//! - Between guest sockets (at `127.0.0.1` or [`GUEST_IPV4_ADDRESS`]),
//!   which guests use while they have no `AF_UNIX`: within this provider,
//!   as the userland one does. A TCP connection is a socket pair (see
//!   `socket_pair`), queued at its listener until accepted; a datagram goes
//!   to the bound socket's queue. Listening sockets are only here, as on
//!   other broker platforms: the guest is not reachable from outside.
//!
//! The stack has no thread of its own: it runs when the broker does
//! ([`SmoltcpSocketProvider::poll`], and after every socket operation), and
//! the broker must not wait past [`SmoltcpSocketProvider::next_deadline`].
//! Readiness is published after each run, outside the stack's lock. Time is
//! the broker's clock (its [`TimerProvider`]'s).

#![no_std]

extern crate alloc;

mod device;
mod socket;
mod socket_pair;
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
use litebox_broker_core::BrokerError;
use litebox_broker_core::readiness::ReadinessRegistration;
use litebox_broker_core::socket::{GUEST_IPV4_ADDRESS, HOST_GATEWAY_IPV4_ADDRESS};
use litebox_broker_core::timer::TimerProvider;
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::SocketError;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::AnySocket as _;
use smoltcp::socket::raw;
use smoltcp::wire::{
    ETHERNET_HEADER_LEN, EthernetAddress, HardwareAddress, IPV4_HEADER_LEN, IPV4_MIN_MTU,
    IpAddress, IpCidr, IpEndpoint, IpProtocol, IpVersion, Ipv4Cidr, UDP_HEADER_LEN,
};
use spin::Mutex;

use device::{Ethernet, Heard};
use socket_pair::SocketPair;

/// The device the stack reaches beyond the guest through: an Ethernet one,
/// e.g., `litebox_hal`'s `NetworkDevice`, or a TAP device. Frames exclude
/// the FCS. (A TUN device, as `litebox_platform_linux_userland` uses on
/// `main`, carries IP packets instead: it would need the stack's interface
/// on smoltcp's IP medium.)
pub trait Network: Sync {
    fn mac(&self) -> [u8; 6];

    /// The next frame's length, its bytes copied into `frame` (truncated);
    /// `None` if none is waiting.
    fn receive(&self, frame: &mut [u8]) -> Option<usize>;

    /// Whether [`Self::transmit`] would take a frame now.
    fn can_transmit(&self) -> bool;

    /// Sends `frame`, at most 1514 bytes (a 1500-byte IP packet and its
    /// Ethernet header); false if the device had no room for it.
    fn transmit(&self, frame: &[u8]) -> bool;

    /// Whether the device wakes the broker as a frame arrives (e.g., by an
    /// interrupt, or a readable file descriptor); else the stack polls it.
    fn interrupts(&self) -> bool;
}

/// The longest frame sent: a 1500-byte IP packet and its Ethernet header.
const ETHERNET_MTU: usize = 1514;

/// The longest frame received: [`ETHERNET_MTU`] and a VLAN tag.
const MAX_FRAME_SIZE: usize = 1518;

/// The external network's prefix length.
const PREFIX_LENGTH: u8 = 24;

/// Whether `address` is the external network's broadcast address, which a
/// guest may not send to: Linux needs `SO_BROADCAST` for that, which the
/// broker protocol does not carry (the userland broker's host sockets lack
/// it too). (The core rejects the limited broadcast address itself.)
fn is_broadcast(address: Ipv4Addr) -> bool {
    Ipv4Cidr::new(GUEST_IPV4_ADDRESS, PREFIX_LENGTH).broadcast() == Some(address)
}

/// The largest UDP payload sent externally: one unfragmented datagram (the
/// stack does not fragment).
const MAX_EXTERNAL_DATAGRAM: usize =
    ETHERNET_MTU - ETHERNET_HEADER_LEN - IPV4_HEADER_LEN - UDP_HEADER_LEN;

/// How long a TCP connection attempt may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(75);

/// How long a closed socket may take to end its connection gracefully.
const CLOSE_TIMEOUT: Duration = Duration::from_mins(1);

/// How often a network device that does not wake the broker is polled.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// At most this many retired TCP sockets finish their connections at once;
/// beyond, the oldest are reset (see `Stack::reap`).
const MAX_CLOSING: usize = 64;

/// The stack is never asked to run sooner than this after it last did, so a
/// deadline it cannot meet (e.g., output the device has no room for) does not
/// keep the CPU.
const MIN_POLL_DELAY: Duration = Duration::from_millis(1);

/// At most this many frames are taken from the device per run, so a flood
/// cannot keep the (single) CPU; the rest wait for the next run, at most
/// [`MIN_POLL_DELAY`] later. One receive ring's worth.
const MAX_FRAMES_PER_RUN: usize = 64;

/// Received datagrams are sifted out of smoltcp's queues (see `Udp::sift`)
/// after at most this many packets, fewer than a UDP socket's queue holds.
const SIFT_BATCH: usize = 16;

/// The raw ICMP socket's receive queue: packets, of at most the minimum
/// MTU, which ICMP errors fit.
const ICMP_PACKETS: usize = 8;

/// The broker's sockets (see the crate's docs).
pub struct SmoltcpSocketProvider(Arc<Shared>);

struct Shared {
    stack: Mutex<Stack>,
    /// The network device does not interrupt.
    polled: bool,
}

impl SmoltcpSocketProvider {
    /// The socket limits are the broker core's, as for
    /// `LinuxSocketProvider`: guest connections not yet accepted count
    /// against their connecting processes'. Time is `timers`' clock.
    /// Sockets reach beyond the guest through `network`, if any. `seed`
    /// (e.g., from a CSPRNG) randomizes, e.g., TCP initial sequence numbers.
    pub fn new(
        max_sockets: usize,
        max_sockets_per_process: usize,
        timers: Arc<dyn TimerProvider>,
        network: Option<&'static dyn Network>,
        seed: u64,
    ) -> Self {
        let stack = Stack::new(timers, network, seed, max_sockets, max_sockets_per_process);
        Self(Arc::new(Shared {
            stack: Mutex::new(stack.with_icmp()),
            polled: network.is_some_and(|network| !network.interrupts()),
        }))
    }

    /// Runs the stack now, e.g., on a network interrupt, or at
    /// [`Self::next_deadline`].
    pub fn poll(&self) {
        self.0.run(|_| ());
    }

    /// When, on the broker's clock, the stack must next run (e.g., to
    /// retransmit, or to poll a network device that does not interrupt), if ever.
    ///
    /// Relative to when the stack last ran, not to now: a caller comparing
    /// it with its own earlier reading of the clock must see it come due.
    pub fn next_deadline(&self) -> Option<Duration> {
        let mut stack = self.0.stack.lock();
        let now = stack.now();
        let last_run = stack.last_run;
        let next = stack
            .next_deadline(now)
            .map(|next| next.max(last_run.saturating_add(MIN_POLL_DELAY)));
        if self.0.polled {
            earliest(next, Some(last_run.saturating_add(POLL_INTERVAL)))
        } else {
            next
        }
    }
}

impl Shared {
    /// `f`, with the stack; then a run of the stack, so that what `f` queued
    /// goes out at once. Readiness is published after the lock is
    /// released.
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

/// The most memory the stack's socket buffers and queued data may take, as
/// Linux caps them (`tcp_mem`, `udp_mem`), so a guest cannot exhaust the
/// broker's. Beyond it, a socket that needs buffers fails with
/// out-of-memory, guest connections take no more data, guest datagrams are
/// dropped, and arriving ones wait in, or are dropped by, smoltcp's
/// queues. What an external connection holds apart (`Tcp::saved`) is a
/// copy of what smoltcp received, which may go past it by at most a
/// receive buffer per connection.
const MAX_BUFFER_BYTES: usize = 64 * 1024 * 1024;

/// `len` zeroed bytes for a buffer; out of memory fails rather than panics.
fn zeroed(len: usize) -> Result<Vec<u8>, BrokerError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(len)
        .map_err(|_| BrokerError::OutOfMemory)?;
    buffer.resize(len, 0);
    Ok(buffer)
}

/// The sockets' buffers: smoltcp's, on the Ethernet interface (none
/// without a network device), and guest connections'.
struct Sockets {
    set: SocketSet<'static>,
    /// Guest TCP connections, by ID.
    pairs: BTreeMap<u64, SocketPair>,
    next_pair: u64,
    /// What UDP sockets' own queues, guest connections, and TCP sockets'
    /// data held apart (`Tcp::saved`) take, in bytes allocated.
    queued: usize,
}

impl Sockets {
    /// What is left of [`MAX_BUFFER_BYTES`].
    fn room(&self) -> usize {
        use smoltcp::socket::Socket;
        let buffers: usize = self
            .set
            .iter()
            .map(|(_, socket)| match socket {
                Socket::Tcp(socket) => socket.recv_capacity() + socket.send_capacity(),
                Socket::Udp(socket) => {
                    socket.payload_recv_capacity() + socket.payload_send_capacity()
                }
                Socket::Raw(_) => 0,
            })
            .sum();
        MAX_BUFFER_BYTES.saturating_sub(buffers + self.queued)
    }

    fn tcp(&mut self, handle: SocketHandle) -> &mut smoltcp::socket::tcp::Socket<'static> {
        self.set.get_mut(handle)
    }

    fn udp(&mut self, handle: SocketHandle) -> &mut smoltcp::socket::udp::Socket<'static> {
        self.set.get_mut(handle)
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

/// What a run learned, for `Tcp::update`.
struct Run<'a> {
    now: Duration,
    /// The connections smoltcp timed out.
    timed_out: &'a [SocketHandle],
    /// The connections TCP segments came for, sorted.
    heard: &'a Heard,
    /// What is left of [`MAX_BUFFER_BYTES`].
    room: usize,
}

/// A retired TCP socket finishing its connection.
struct Closing {
    handle: SocketHandle,
    deadline: Duration,
}

struct Stack {
    clock: Arc<dyn TimerProvider>,
    ethernet: Option<(Interface, Ethernet)>,
    sockets: Sockets,
    entries: BTreeMap<u64, Entry>,
    next_id: u64,
    max_sockets: usize,
    max_sockets_per_process: usize,
    closing: Vec<Closing>,
    /// When [`Self::poll`] last ran.
    last_run: Duration,
    /// The last run left packets to receive.
    ingress_pending: bool,
    /// The connections smoltcp timed out in this run (see
    /// [`Self::egress`]).
    timed_out: Vec<SocketHandle>,
    /// With a network device: a raw socket receiving ICMP, for errors about UDP
    /// datagrams (see `Udp::destination_error`).
    icmp: Option<SocketHandle>,
    /// Readiness changes, published after the stack's lock is released.
    publications: Vec<Publication>,
}

impl Stack {
    fn new(
        clock: Arc<dyn TimerProvider>,
        network: Option<&'static dyn Network>,
        seed: u64,
        max_sockets: usize,
        max_sockets_per_process: usize,
    ) -> Self {
        let now = clock.now();
        let ethernet = network.map(|network| {
            let mut device = Ethernet::new(network);
            let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(network.mac())));
            config.random_seed = seed;
            let mut interface = Interface::new(config, &mut device, timestamp(now));
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
            sockets: Sockets {
                set: SocketSet::new(vec![]),
                pairs: BTreeMap::new(),
                next_pair: 0,
                queued: 0,
            },
            ethernet,
            entries: BTreeMap::new(),
            next_id: 0,
            max_sockets,
            max_sockets_per_process,
            closing: Vec::new(),
            last_run: now,
            ingress_pending: false,
            timed_out: Vec::new(),
            icmp: None,
            publications: Vec::new(),
        }
    }

    /// With a network device, adds the raw ICMP socket; see [`Self::icmp`].
    fn with_icmp(mut self) -> Self {
        if !self.has_network() {
            return self;
        }
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
        self.icmp = Some(self.sockets.set.add(socket()));
        self
    }

    fn has_network(&self) -> bool {
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

    /// One run, bounded by [`MAX_FRAMES_PER_RUN`] (what is left makes
    /// [`Self::next_deadline`] due); it recomputes every socket's readiness.
    fn poll(&mut self) {
        let now = self.now();
        self.last_run = now;
        let at = timestamp(now);
        self.timed_out.clear();
        self.ingress_pending = false;
        if self.has_network() {
            self.ingress_pending = self.receive(at) == MAX_FRAMES_PER_RUN;
            self.egress(at);
        }
        self.reap(now);
        let mut heard = self
            .ethernet
            .as_mut()
            .map(|(_, device)| core::mem::take(&mut device.heard))
            .unwrap_or_default();
        heard.sort_unstable();
        heard.dedup();
        let run = Run {
            now,
            timed_out: &self.timed_out,
            heard: &heard,
            room: self.sockets.room(),
        };
        for entry in self.entries.values_mut() {
            let (flags, republish) = match &mut entry.kind {
                Kind::Tcp(tcp) => tcp.update(&mut self.sockets, &run),
                Kind::Udp(udp) => (udp.readiness(&mut self.sockets, now), false),
            };
            entry.update(flags, republish, &mut self.publications);
        }
    }

    /// Sends what is due, noting the connections smoltcp times out: it does
    /// so only as it sends (closing them, as a reset received does, but then
    /// before sending).
    fn egress(&mut self, at: smoltcp::time::Instant) {
        use smoltcp::socket::tcp;
        let Some((interface, device)) = &mut self.ethernet else {
            return;
        };
        let sockets = &mut self.sockets.set;
        let timing: Vec<SocketHandle> = sockets
            .iter()
            .filter_map(|(handle, socket)| {
                let socket = tcp::Socket::downcast(socket)?;
                // TIME-WAIT ends as it sends, too, but gracefully.
                (socket.timeout().is_some()
                    && !matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait))
                .then_some(handle)
            })
            .collect();
        // smoltcp sends at most one packet per socket per egress pass (e.g.,
        // one TCP segment): pass until none goes out, as far as the device
        // takes them, within the run's bound.
        for _ in 0..MAX_FRAMES_PER_RUN {
            if matches!(
                interface.poll_egress(at, device, sockets),
                smoltcp::iface::PollResult::None
            ) {
                break;
            }
        }
        for handle in timing {
            if sockets.get::<tcp::Socket>(handle).state() == tcp::State::Closed {
                self.timed_out.push(handle);
            }
        }
    }

    /// How many frames it took, at most [`MAX_FRAMES_PER_RUN`]. Sifting every
    /// [`SIFT_BATCH`] keeps smoltcp's small UDP queues from overflowing
    /// within a run.
    fn receive(&mut self, at: smoltcp::time::Instant) -> usize {
        use smoltcp::iface::PollIngressSingleResult;
        let mut received = 0;
        while received < MAX_FRAMES_PER_RUN {
            let Some((interface, device)) = &mut self.ethernet else {
                break;
            };
            let result = interface.poll_ingress_single(at, device, &mut self.sockets.set);
            if matches!(result, PollIngressSingleResult::None) {
                break;
            }
            received += 1;
            if received % SIFT_BATCH == 0 {
                self.sift();
            }
        }
        self.sift();
        received
    }

    /// Hands what smoltcp received to the UDP sockets: datagrams, and ICMP
    /// errors.
    fn sift(&mut self) {
        let mut room = self.sockets.room();
        let Self {
            entries, sockets, ..
        } = self;
        for entry in entries.values_mut() {
            if let Kind::Udp(udp) = &mut entry.kind {
                udp.sift(sockets, &mut room);
            }
        }
        let Some(icmp) = self.icmp else {
            return;
        };
        while let Ok(packet) = self.sockets.set.get_mut::<raw::Socket>(icmp).recv() {
            let Some((source, destination, error)) = udp_error(packet) else {
                continue;
            };
            for entry in self.entries.values_mut() {
                if let Kind::Udp(udp) = &mut entry.kind {
                    udp.destination_error(source, destination, error);
                }
            }
        }
    }

    fn next_deadline(&mut self, now: Duration) -> Option<Duration> {
        let at = timestamp(now);
        let external = match &mut self.ethernet {
            Some((interface, _)) => interface.poll_at(at, &self.sockets.set),
            None => None,
        };
        let closing = self.closing.iter().map(|closing| closing.deadline).min();
        let pending = self.ingress_pending.then_some(Duration::ZERO);
        earliest(external.map(instant), earliest(closing, pending))
    }

    /// Removes retired sockets whose connections ended. Beyond
    /// [`MAX_CLOSING`], resets the oldest, as Linux beyond
    /// `tcp_max_orphans`, and removes them as the next run has sent that.
    fn reap(&mut self, now: Duration) {
        use smoltcp::socket::tcp::State;
        let sockets = &mut self.sockets;
        self.closing.retain(|closing| {
            let socket = sockets.tcp(closing.handle);
            // TIME-WAIT, smoltcp's 10 s (Linux's 60 s), ends in `Closed`. An
            // aborted socket keeps its endpoints until it sends its reset,
            // which it may never manage (e.g., to a neighbor that does not
            // answer ARP).
            let ended = if socket.state() == State::Closed {
                socket.local_endpoint().is_none() || now >= closing.deadline
            } else {
                // Data for a closed socket: as Linux (per RFC 1122), which
                // shut its receive side, a reset. (Data unread at the close
                // reset it then.)
                if socket.recv_queue() != 0 {
                    socket.abort();
                }
                now >= closing.deadline
            };
            if ended {
                sockets.set.remove(closing.handle);
            }
            !ended
        });
        let excess = self.closing.len().saturating_sub(MAX_CLOSING);
        let mut index = 0;
        self.closing.retain(|closing| {
            index += 1;
            if index > excess {
                return true;
            }
            let socket = sockets.tcp(closing.handle);
            // As Linux beyond `tcp_max_tw_buckets`, TIME-WAIT is not kept.
            if matches!(socket.state(), State::Closed | State::TimeWait) {
                sockets.set.remove(closing.handle);
                return false;
            }
            socket.abort();
            true
        });
    }

    /// Hands a retired TCP socket over to finish its connection: with a
    /// reset if `abort`, else gracefully.
    fn close_tcp(&mut self, handle: SocketHandle, abort: bool) {
        let socket = self.sockets.tcp(handle);
        if abort {
            socket.abort();
        } else {
            socket.close();
        }
        let deadline = self.now().saturating_add(CLOSE_TIMEOUT);
        self.closing.push(Closing { handle, deadline });
    }

    /// Whether an external connection from `source` to `destination`
    /// exists, e.g., a retired one still finishing.
    fn connection_exists(&self, source: SocketAddrV4, destination: SocketAddrV4) -> bool {
        use smoltcp::socket::tcp;
        self.sockets.set.iter().any(|(_, socket)| {
            tcp::Socket::downcast(socket).is_some_and(|socket| {
                socket.state() != tcp::State::Closed
                    && socket.local_endpoint() == Some(source.into())
                    && socket.remote_endpoint() == Some(destination.into())
            })
        })
    }

    /// How many sockets `process` has, counting guest connections it made
    /// that are not yet accepted; and how many all processes have.
    fn socket_counts(&self, process: ProcessId) -> (usize, usize) {
        let (mut process_count, mut count) = (0, self.entries.len());
        for entry in self.entries.values() {
            if entry.process == process {
                process_count += 1;
            }
            if let Kind::Tcp(tcp) = &entry.kind {
                for queued in tcp.queued() {
                    count += 1;
                    if queued.process == process {
                        process_count += 1;
                    }
                }
            }
        }
        (process_count, count)
    }

    /// Discards the guest connections `process` made that are not yet
    /// accepted.
    fn close_process(&mut self, process: ProcessId) {
        let Self {
            entries, sockets, ..
        } = self;
        for entry in entries.values_mut() {
            if let Kind::Tcp(tcp) = &mut entry.kind {
                tcp.discard_queued(sockets, |queued| queued.process == process);
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

/// From an ICMP "destination unreachable" `packet` (IPv4) about a UDP
/// datagram: the datagram's source and destination,
/// and the error it means, if Linux reports it.
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
fn udp_error(packet: &[u8]) -> Option<(SocketAddrV4, SocketAddrV4, SocketError)> {
    use smoltcp::wire::{Icmpv4Packet, Ipv4Packet};
    /// ICMP type 3, and its header's length.
    const DESTINATION_UNREACHABLE: u8 = 3;
    const ICMP_HEADER: usize = 8;
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    let icmp = ip.payload();
    if !Icmpv4Packet::new_checked(icmp).ok()?.verify_checksum() {
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
    let source = SocketAddrV4::new(quoted.src_addr(), u16::from_be_bytes([ports[0], ports[1]]));
    let destination =
        SocketAddrV4::new(quoted.dst_addr(), u16::from_be_bytes([ports[2], ports[3]]));
    Some((source, destination, error))
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
