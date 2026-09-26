// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Network-related functionality

use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::event::Events;
use crate::net::socket_channel::NetworkProxy;
use crate::platform::{Instant, TimeProvider};
use crate::sync::RawSyncPrimitivesProvider;
use crate::{LiteBox, platform, sync};

use bitflags::bitflags;
use smoltcp::socket::{icmp, raw, tcp, udp};

pub mod errors;
pub mod local_ports;
mod phy;
pub mod socket_channel;

#[cfg(test)]
mod tests;

use errors::{
    AcceptError, BindError, CloseError, ConnectError, ListenError, LocalAddrError, ReceiveError,
    RemoteAddrError, SendError, SocketError,
};
use local_ports::{LocalPort, LocalPortAllocator};

/// Default IP address for the LiteBox interface (overridable via [`Network::new_with_addrs`]).
pub const INTERFACE_IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// Default IP address for the gateway (overridable via [`Network::new_with_addrs`]).
pub const GATEWAY_IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// The loopback address. Packets destined anywhere in `127.0.0.0/8` are looped
/// back into the interface's own receive path (see [`phy`]).
const LOOPBACK_IP_ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// Internal guest endpoint for the bounded ICMP echo bridge used by rootless macOS networking.
///
/// This is not a general raw-packet interface: the Linux shim frames only IPv4 Echo Requests for
/// this endpoint, and the macOS runner validates them again before using its unprivileged ping
/// socket.
#[doc(hidden)]
pub const ICMP_ECHO_PROXY_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3130);

/// IPv4 destination prefix carried on internal ICMP echo proxy datagrams.
#[doc(hidden)]
pub const ICMP_ECHO_PROXY_PREFIX_LEN: usize = 4;

/// Maximum size of rx/tx buffers for sockets
pub const SOCKET_BUFFER_SIZE: usize = 65536 * 4;

/// Limits maximum number of packets in a buffer
const MAX_PACKET_COUNT: usize = 32;

/// TCP connection timeout.
const TCP_CONNECT_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(75);

/// How long unacknowledged data may sit in a socket's transmit queue with no packet at all from
/// the peer before the connection is aborted. Linux gives up after `tcp_retries2` (15)
/// retransmissions, roughly 15 minutes. This is the only time an established connection is
/// timed out: an idle one is never dropped (see the timeout policy in
/// [`Network::drain_socket_channel_buffers`]).
const TCP_RETRANSMIT_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(900);

/// How long a socket whose descriptor is already closed may wait for the peer to finish the
/// close handshake (FIN-WAIT-2 waiting for the peer's FIN, or the last writes draining to a
/// slow peer) before it is reset and reaped. Linux: `tcp_fin_timeout`, 60 s.
const TCP_ORPHAN_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(60);

/// Whether a listening socket's child has completed its handshake and belongs in the accept
/// queue. Linux hands out a connection as soon as it is established, including one whose peer
/// has already sent FIN (`CloseWait`): a client that writes its request and half-closes before
/// the server gets around to `accept` (busybox wget, `nc -q`, any "send then shutdown(SHUT_WR)"
/// client) must still be accepted, and then read to EOF. Only `Established` was accepted before,
/// so such connections sat unaccepted until they were reaped, and their data was lost.
fn accept_ready(state: tcp::State) -> bool {
    matches!(state, tcp::State::Established | tcp::State::CloseWait)
}

/// The `Network` provides access to all networking related functionality provided by LiteBox.
///
/// A LiteBox `Network` is parametric in the platform it runs on.
///
/// An important decision that must be made by a user of a `Network` is decided by
/// [`set_platform_interaction`](Self::set_platform_interaction), whose docs explain this further.
///
/// A user of `Network` who care about [events](crate::event) should call [set_socket_proxy](Self::set_socket_proxy)
/// to set up a proxy for each socket created, so that events can be notified properly.
pub struct Network<Platform>
where
    Platform:
        platform::IPInterfaceProvider + platform::TimeProvider + sync::RawSyncPrimitivesProvider,
{
    litebox: LiteBox<Platform>,
    /// The set of sockets
    socket_set: smoltcp::iface::SocketSet<'static>,
    /// The actual "physical" device, that connects to the platform
    device: phy::Device<Platform>,
    /// The default-route gateway address the interface was configured with
    /// (`GATEWAY_IP_ADDR` unless overridden); exposed so routing-table views
    /// (netlink `RTM_GETROUTE`, `/proc/net/route`) report what smoltcp uses.
    gateway_ip: Ipv4Addr,
    /// The smoltcp network interface
    interface: smoltcp::iface::Interface,
    /// Initial instant of creation, used as an arbitrary stop point from when time begins
    zero_time: Platform::Instant,
    /// An allocator for local ports
    // TODO: Maybe we should have separate allocators for TCP, UDP, ...?
    local_port_allocator: LocalPortAllocator,
    /// Whether outside interaction is automatic or manual
    platform_interaction: PlatformInteraction,
    /// FDs that are queued for eventual closure
    queued_for_closure: Vec<SocketFd<Platform>>,
    /// Sockets that are closing in the background
    closing_in_background: Vec<ClosingSocket>,
    /// Closed TCP sockets whose channel TX ring still holds bytes the application wrote before
    /// `close()`; they are moved into smoltcp first and the FIN follows (see
    /// [`Self::drain_closing_with_pending_tx`]).
    closing_with_pending_tx: Vec<DrainingSocket<Platform>>,
}

/// A TCP socket whose file descriptor is gone but whose smoltcp state machine is still finishing
/// the close handshake (or has an RST to emit).
struct ClosingSocket {
    handle: smoltcp::iface::SocketHandle,
    /// When the descriptor was closed; bounds the wait for the peer by [`TCP_ORPHAN_TIMEOUT`].
    closed_at: smoltcp::time::Instant,
}

/// A [`ClosingSocket`] that still has application data in its channel's TX ring.
struct DrainingSocket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    handle: smoltcp::iface::SocketHandle,
    closed_at: smoltcp::time::Instant,
    proxy: alloc::sync::Arc<NetworkProxy<Platform>>,
}

impl<Platform> Network<Platform>
where
    Platform:
        platform::IPInterfaceProvider + platform::TimeProvider + sync::RawSyncPrimitivesProvider,
{
    /// Construct a new `Network` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialization step,
    /// and the created `Network` handle is expected to be shared across all usage over the
    /// system.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self::new_with_addrs(litebox, None, None)
    }

    /// Same as [`Self::new`], but lets the caller override the interface/gateway
    /// addresses instead of the fixed `INTERFACE_IP_ADDR`/`GATEWAY_IP_ADDR`
    /// defaults (`None` = use the default). Needed by any caller that runs more
    /// than one `Network` on the same host at once (each one needs a distinct
    /// address to be independently reachable).
    pub fn new_with_addrs(
        litebox: &LiteBox<Platform>,
        interface_ip: Option<Ipv4Addr>,
        gateway_ip: Option<Ipv4Addr>,
    ) -> Self {
        let interface_ip = interface_ip.unwrap_or(INTERFACE_IP_ADDR);
        let gateway_ip = gateway_ip.unwrap_or(GATEWAY_IP_ADDR);
        let mut device = phy::Device::new(litebox.x.platform);
        let config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut interface =
            smoltcp::iface::Interface::new(config, &mut device, smoltcp::time::Instant::ZERO);
        interface.update_ip_addrs(|ip_addrs| {
            match ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv4(interface_ip),
                24,
            )) {
                Ok(()) => {}
                Err(_) => unreachable!(),
            }
            // Own `127.0.0.0/8` so the interface both accepts inbound packets
            // to `127.0.0.1` as local and, under `Medium::Ip` (no ARP), sends
            // to it directly without the default gateway. The `phy::Device`
            // loops any packet destined here straight back into its own
            // receive queue (see `phy.rs`), which is what makes an in-process
            // guest server reachable from the same guest -- a Node http server
            // on `127.0.0.1` fetched by the same process, and the many test
            // frameworks and IPC paths that assume a working loopback.
            match ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv4(LOOPBACK_IP_ADDR),
                8,
            )) {
                Ok(()) => {}
                Err(_) => unreachable!(),
            }
        });
        match interface.routes_mut().add_default_ipv4_route(gateway_ip) {
            Ok(None) => {}
            _ => unreachable!(),
        }
        Self {
            litebox: litebox.clone(),
            socket_set: smoltcp::iface::SocketSet::new(vec![]),
            device,
            gateway_ip,
            interface,
            zero_time: litebox.x.platform.now(),
            local_port_allocator: LocalPortAllocator::new(),
            platform_interaction: PlatformInteraction::Automatic,
            queued_for_closure: vec![],
            closing_in_background: vec![],
            closing_with_pending_tx: vec![],
        }
    }
}

/// [`SocketHandle`] stores all relevant information for a specific [`SocketFd`], for easy access
/// from [`SocketFd`], _except_ the `Socket` itself which is stored in the [`Network::socket_set`].
pub(crate) struct SocketHandle<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// Whether this socket handle is going away soon (i.e., `close` has been invoked upon it but
    /// it lingers for a bit to allow pending data to be sent).
    consider_closed: bool,
    /// The handle into the `socket_set`
    handle: smoltcp::iface::SocketHandle,
    // Protocol-specific data
    specific: ProtocolSpecific,
    /// The proxy associated with this socket to enable lock-free data transfer
    /// and event notification
    proxy: Option<alloc::sync::Arc<NetworkProxy<Platform>>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> SocketHandle<Platform> {
    /// Convenience function to perform an operation depending on the socket type
    fn with_socket<TCP, UDP, R>(
        &self,
        socket_set: &smoltcp::iface::SocketSet<'static>,
        tcp: TCP,
        udp: UDP,
    ) -> R
    where
        TCP: FnOnce(&tcp::Socket) -> R,
        UDP: FnOnce(&udp::Socket) -> R,
    {
        match self.protocol() {
            crate::net::Protocol::Tcp => {
                let tcp_socket = socket_set.get::<tcp::Socket>(self.handle);
                tcp(tcp_socket)
            }
            crate::net::Protocol::Udp => {
                let udp_socket = socket_set.get::<udp::Socket>(self.handle);
                udp(udp_socket)
            }
            crate::net::Protocol::Icmp | crate::net::Protocol::Raw { protocol: _ } => {
                unimplemented!()
            }
        }
    }

    // Convenience function to perform a mutable operation depending on the socket type
    fn with_socket_mut<TCP, UDP, R>(
        &mut self,
        socket_set: &mut smoltcp::iface::SocketSet<'static>,
        tcp: TCP,
        udp: UDP,
    ) -> R
    where
        TCP: FnOnce(&mut tcp::Socket) -> R,
        UDP: FnOnce(&mut udp::Socket) -> R,
    {
        match self.protocol() {
            crate::net::Protocol::Tcp => {
                let tcp_socket = socket_set.get_mut::<tcp::Socket>(self.handle);
                tcp(tcp_socket)
            }
            crate::net::Protocol::Udp => {
                let udp_socket = socket_set.get_mut::<udp::Socket>(self.handle);
                udp(udp_socket)
            }
            crate::net::Protocol::Icmp | crate::net::Protocol::Raw { protocol: _ } => {
                unimplemented!()
            }
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> core::ops::Deref
    for SocketHandle<Platform>
{
    type Target = ProtocolSpecific;
    fn deref(&self) -> &Self::Target {
        &self.specific
    }
}
impl<Platform: RawSyncPrimitivesProvider + TimeProvider> core::ops::DerefMut
    for SocketHandle<Platform>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.specific
    }
}

/// The [`ProtocolSpecific`] stores socket-type-specific data
#[expect(
    dead_code,
    reason = "these might eventually get used, they exist for completeness sake"
)]
pub(crate) enum ProtocolSpecific {
    Tcp(TcpSpecific),
    Udp(UdpSpecific),
    Icmp(IcmpSpecific),
    Raw(RawSpecific),
}

/// Socket-specific data for TCP sockets
pub(crate) struct TcpSpecific {
    /// A local port associated with this socket, if any
    local_port: Option<LocalPort>,
    /// Server socket specific data
    server_socket: Option<TcpServerSpecific>,
    /// Whether to immediately close the socket when closed (i.e., no graceful FIN handshake)
    immediate_close: AtomicBool,
    /// Timestamp when `connect` was initiated
    connect_initiated_at_us: Option<smoltcp::time::Instant>,
    /// Set by the network worker once the peer's FIN has been seen, every byte before it has
    /// been handed to the application, and the socket channel's read side has been closed so
    /// `read()` reports end-of-file. Sticky.
    rx_eof_signaled: AtomicBool,
    /// Set by the network worker the moment the peer's FIN is observed, regardless of whether the
    /// application has drained data queued ahead of it -- unlike `rx_eof_signaled`, which gates
    /// `read()` returning 0, this only gates `POLLRDHUP` (Linux's `tcp_fin()` sets `RCV_SHUTDOWN`,
    /// and so `POLLRDHUP`, immediately on FIN arrival, independent of unread data). Sticky.
    peer_fin_notified: AtomicBool,
    /// `shutdown(SHUT_RD)`: received data is discarded instead of queued.
    read_shutdown: AtomicBool,
    /// `shutdown(SHUT_WR)`: the FIN is sent once the channel's TX ring has drained into smoltcp.
    write_shutdown: AtomicBool,
}

impl TcpSpecific {
    fn new(local_port: Option<LocalPort>) -> Self {
        Self {
            local_port,
            server_socket: None,
            immediate_close: AtomicBool::new(false),
            connect_initiated_at_us: None,
            rx_eof_signaled: AtomicBool::new(false),
            peer_fin_notified: AtomicBool::new(false),
            read_shutdown: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
        }
    }
}

/// Whether the peer's FIN has been received and every byte it sent before it has already been
/// dequeued. smoltcp keeps `rx_fin_received` private, but a zero-length `recv_slice` reports
/// exactly that condition as [`tcp::RecvError::Finished`], and has no other effect.
fn peer_finished(tcp_socket: &mut tcp::Socket<'_>) -> bool {
    matches!(
        tcp_socket.recv_slice(&mut []),
        Err(tcp::RecvError::Finished)
    )
}

/// Socket-specific data for TCP server sockets
struct TcpServerSpecific {
    /// IP listening endpoint, if used as a server socket
    ip_listen_endpoint: smoltcp::wire::IpListenEndpoint,
    /// Specified backlog via `listen`, no packets can be `accept`ed unless this is `Some`
    backlog: Option<u16>,
    /// Handles into the top-level `socket_set` for when things are `accept`ed.
    socket_set_handles: Vec<smoltcp::iface::SocketHandle>,
}

impl TcpServerSpecific {
    fn refill_to_backlog(&mut self, socket_set: &mut smoltcp::iface::SocketSet) {
        let backlog = self.backlog.unwrap();
        for _ in self.socket_set_handles.len()..backlog.into() {
            let mut listening_socket = tcp::Socket::new(
                smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
                smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
            );
            match listening_socket.listen(self.ip_listen_endpoint) {
                Ok(()) => {}
                Err(tcp::ListenError::InvalidState) => {
                    // Impossible, because we _just_ created a new tcp::Socket, which begins
                    // in CLOSED state.
                    unreachable!()
                }
                Err(tcp::ListenError::Unaddressable) => {
                    // Impossible, since listen endpoint port is non 0.
                    unreachable!()
                }
            }
            self.socket_set_handles
                .push(socket_set.add(listening_socket));
        }
    }
}

/// Socket-specific data for UDP sockets
pub(crate) struct UdpSpecific {
    /// Remote endpoint
    ///
    /// If `connect`-ed, this is the remote endpoint to which packets are sent by default.
    remote_endpoint: Option<smoltcp::wire::IpEndpoint>,
}

/// Socket-specific data for ICMP sockets
pub(crate) struct IcmpSpecific {}

/// Socket-specific data for RAW sockets
pub(crate) struct RawSpecific {
    protocol: u8,
}

#[expect(
    dead_code,
    reason = "the dead ones exist for completeness sake, might eventually get used"
)]
impl ProtocolSpecific {
    /// Get the [`Protocol`] for this socket
    fn protocol(&self) -> Protocol {
        match self {
            ProtocolSpecific::Tcp(_) => Protocol::Tcp,
            ProtocolSpecific::Udp(_) => Protocol::Udp,
            ProtocolSpecific::Icmp(_) => Protocol::Icmp,
            ProtocolSpecific::Raw(RawSpecific { protocol, .. }) => Protocol::Raw {
                protocol: *protocol,
            },
        }
    }

    /// Obtain a reference to the tcp-socket-specific data. Panics if non-TCP.
    fn tcp(&self) -> &TcpSpecific {
        match self {
            ProtocolSpecific::Tcp(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a mutable reference to the tcp-socket-specific data. Panics if non-TCP.
    fn tcp_mut(&mut self) -> &mut TcpSpecific {
        match self {
            ProtocolSpecific::Tcp(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a reference to the udp-socket-specific data. Panics if non-UDP.
    fn udp(&self) -> &UdpSpecific {
        match self {
            ProtocolSpecific::Udp(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a mutable reference to the udp-socket-specific data. Panics if non-UDP.
    fn udp_mut(&mut self) -> &mut UdpSpecific {
        match self {
            ProtocolSpecific::Udp(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a reference to the icmp-socket-specific data. Panics if non-ICMP.
    fn icmp(&self) -> &IcmpSpecific {
        match self {
            ProtocolSpecific::Icmp(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a mutable reference to the icmp-socket-specific data. Panics if non-ICMP.
    fn icmp_mut(&mut self) -> &mut IcmpSpecific {
        match self {
            ProtocolSpecific::Icmp(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a reference to the raw-socket-specific data. Panics if non-RAW.
    fn raw(&self) -> &RawSpecific {
        match self {
            ProtocolSpecific::Raw(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a mutable reference to the raw-socket-specific data. Panics if non-RAW.
    fn raw_mut(&mut self) -> &mut RawSpecific {
        match self {
            ProtocolSpecific::Raw(specific) => specific,
            _ => unreachable!(),
        }
    }
}

/// Whether [`Network::perform_platform_interaction`] needs to be manually invoked or not.
pub enum PlatformInteraction {
    /// Automatically (internally) invoked whenever any calls like `send`/`recv`/... are made.
    Automatic,
    /// Requires manually (periodically) invoking [`Network::perform_platform_interaction`]
    Manual,
}

/// Direction of polling for platform interaction
#[derive(Clone, Copy)]
enum PollDirection {
    /// Ingress (receiving) direction
    Ingress,
    /// Egress (sending) direction
    Egress,
    /// Both directions
    Both,
}

/// Advice on when to invoke [`Network::perform_platform_interaction`] again.
///
/// It is perfectly ok to ignore this advice by calling things sooner (say, in a tight loop).
/// Specifically, it is harmless (but wastes energy) to call for interaction again sooner than
/// advised. In contrast, it _may_ be harmful (impacting quality of service) to call it later than
/// requested.
#[derive(Clone, Copy, Debug)]
pub enum PlatformInteractionReinvocationAdvice {
    /// It is likely helpful to call again immediately, without any delay. The function has returned
    /// control back to you to prevent unbounded length waits (crucial to prevent in
    /// non-pre-emptible environments), but otherwise has more work it anticipates it can do.
    CallAgainImmediately,
    /// You don't need to call again until more packets arrive on the device's receive side (i.e., `timeout` is `None`),
    /// or the given `timeout` expires.
    WaitOnDeviceOrSocketInteraction {
        timeout: Option<core::time::Duration>,
    },
}
impl PlatformInteractionReinvocationAdvice {
    /// Convenience function to match against [`Self::CallAgainImmediately`]
    #[must_use]
    pub fn call_again_immediately(self) -> bool {
        matches!(self, Self::CallAgainImmediately)
    }
}

impl<Platform> Network<Platform>
where
    Platform:
        platform::IPInterfaceProvider + platform::TimeProvider + sync::RawSyncPrimitivesProvider,
{
    /// Sets the interaction with the outside world to `platform_interaction`.
    ///
    /// If this is set to automatic, then a user of the network does not need to worry about
    /// scheduling or calling [`perform_platform_interaction`](Self::perform_platform_interaction).
    /// However, this may reduce predictability in terms of how quickly LiteBox responds to calls,
    /// since any network calls may incur non-trivial performance penalty.
    ///
    /// On the other hand, more performance can be had in scenarios that can support (say) a
    /// separate thread that repeatedly invokes
    /// [`perform_platform_interaction`](Self::perform_platform_interaction), or in scenarios where
    /// the user wants greater control over _when_ processing is performed, if done synchronously.
    ///
    /// By default, for convenience, the default setting (if this function is not invoked) is
    /// [`PlatformInteraction::Automatic`].
    pub fn set_platform_interaction(&mut self, platform_interaction: PlatformInteraction) {
        self.platform_interaction = platform_interaction;
    }

    /// Performs queued interactions with the outside world.
    ///
    /// # Panics
    ///
    /// This function panics if run without first using [`Self::set_platform_interaction`] to set
    /// interactions to manual.
    pub fn perform_platform_interaction(&mut self) -> PlatformInteractionReinvocationAdvice {
        assert!(
            matches!(self.platform_interaction, PlatformInteraction::Manual),
            "Requires manual-mode interactions"
        );
        match self.internal_perform_platform_interaction() {
            smoltcp::iface::PollResult::SocketStateChanged => {
                PlatformInteractionReinvocationAdvice::CallAgainImmediately
            }
            smoltcp::iface::PollResult::None => {
                let poll_at = self.poll_at();
                PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction {
                    timeout: poll_at,
                }
            }
        }
    }

    /// Return a _soft timeout_ (duration to wait) before calling [`Self::perform_platform_interaction`] again.
    ///
    /// Returns `None` if there is no pending timeout (i.e., no scheduled work requiring network operations).
    fn poll_at(&mut self) -> Option<core::time::Duration> {
        let timestamp = self.now();
        self.interface
            .poll_at(timestamp, &self.socket_set)
            .map(|instant| {
                if timestamp < instant {
                    let diff = instant - timestamp;
                    diff.into()
                } else {
                    core::time::Duration::ZERO
                }
            })
    }

    /// (Internal-only API) Actually perform the queued interactions with the outside world.
    fn internal_perform_platform_interaction(&mut self) -> smoltcp::iface::PollResult {
        self.attempt_to_close_queued();
        self.remove_dead_sockets();
        self.close_pending_sockets();
        self.drain_closing_with_pending_tx();

        // Drain all socket channel buffers before polling to ensure data flows
        self.drain_all_socket_channel_buffers();
        self.interface
            .poll(self.now(), &mut self.device, &mut self.socket_set)
    }

    /// (Internal-only API) Perform the queued interactions.
    fn automated_platform_interaction(&mut self, _direction: PollDirection) {
        match self.platform_interaction {
            PlatformInteraction::Automatic => {
                self.internal_perform_platform_interaction();
            }
            PlatformInteraction::Manual => {}
        }
    }

    /// Remove dead sockets that were closing in the background
    fn remove_dead_sockets(&mut self) {
        let now = self.now();
        self.closing_in_background.retain(|closing| {
            let handle = closing.handle;
            let tcp_socket = self.socket_set.get_mut::<tcp::Socket>(handle);
            if tcp_socket.is_open() {
                // Nobody will ever read this socket again. Linux resets an orphan as soon as
                // data arrives for it (RFC 2525 s2.17) instead of ACKing it into a buffer, and
                // gives it `tcp_fin_timeout` to finish the handshake before reaping it; without
                // either, a killed downloader's socket kept ACKing the stream and sat in
                // FIN-WAIT-2 until the server gave up.
                if tcp_socket.recv_queue() > 0 || now - closing.closed_at >= TCP_ORPHAN_TIMEOUT {
                    tcp_socket.abort();
                }
                return true;
            }
            // a socket in the CLOSED state with the remote endpoint set means that an outgoing RST packet is pending
            if tcp_socket.remote_endpoint().is_none() {
                self.socket_set.remove(handle);
                false
            } else {
                true
            }
        });
    }

    /// Finish the writes an application made right before `close()`: keep moving the closed
    /// socket's TX ring into smoltcp and send the FIN only once the ring is empty. Linux's
    /// `close()` returns at once and the kernel keeps transmitting; before this the ring's
    /// contents were dropped with the descriptor.
    fn drain_closing_with_pending_tx(&mut self) {
        if self.closing_with_pending_tx.is_empty() {
            return;
        }
        let now = self.now();
        for draining in core::mem::take(&mut self.closing_with_pending_tx) {
            let NetworkProxy::Stream(channel) = draining.proxy.as_ref() else {
                unreachable!("a TCP socket carries a stream channel")
            };
            let tcp_socket = self.socket_set.get_mut::<tcp::Socket>(draining.handle);
            while tcp_socket.can_send() {
                let sent = channel
                    .pop_tx_data_with(|data| tcp_socket.send_slice(data).unwrap_or_default());
                if sent == 0 {
                    break;
                }
            }
            let finished = if !tcp_socket.may_send() {
                // Reset by the peer (or otherwise dead): nothing more can go out.
                true
            } else if tcp_socket.recv_queue() > 0 || now - draining.closed_at >= TCP_ORPHAN_TIMEOUT
            {
                // Same rules as `remove_dead_sockets`: an orphan does not buffer the peer's
                // data, nor wait forever for a peer that stopped reading.
                tcp_socket.abort();
                true
            } else if !channel.has_pending_tx() {
                tcp_socket.close();
                true
            } else {
                false
            };
            if finished {
                self.closing_in_background.push(ClosingSocket {
                    handle: draining.handle,
                    closed_at: draining.closed_at,
                });
            } else {
                self.closing_with_pending_tx.push(draining);
            }
        }
    }

    /// Close all finished sockets that are marked as closed but waiting for pending data to be sent
    fn close_pending_sockets(&mut self) {
        let table = self.litebox.descriptor_table();
        for (_, mut handle) in table.iter_mut::<Network<Platform>>() {
            let socket_handle = &mut handle.entry;
            if socket_handle.consider_closed {
                // check if there is pending data to be sent
                if let Some(proxy) = &socket_handle.proxy
                    && proxy.has_pending_tx()
                {
                    continue;
                }

                let closed = socket_handle.with_socket_mut(
                    &mut self.socket_set,
                    |tcp_socket| {
                        let has_pending_data = tcp_socket.may_send() && tcp_socket.send_queue() > 0;
                        if !has_pending_data {
                            tcp_socket.close();
                        }
                        !has_pending_data
                    },
                    |udp_socket| {
                        let has_pending_data = udp_socket.is_open() && udp_socket.send_queue() > 0;
                        if !has_pending_data {
                            udp_socket.close();
                        }
                        !has_pending_data
                    },
                );
                if closed {
                    socket_handle.consider_closed = false;
                }
            }
        }
    }

    /// Drain all socket channel buffers
    fn drain_all_socket_channel_buffers(&mut self) {
        let now = self.now();
        let table = self.litebox.descriptor_table();
        for (_, entry) in table.iter::<Network<Platform>>() {
            Self::drain_socket_channel_buffers(&mut self.socket_set, &entry.entry, now);
        }
    }

    /// Drain data between socket channels and smoltcp sockets.
    ///
    /// This transfers data from the TX ring buffer (user writes) to the smoltcp socket,
    /// and from the smoltcp socket to the RX ring buffer (user reads).
    ///
    /// Should be called periodically by the network worker to keep data flowing.
    fn drain_socket_channel_buffers(
        socket_set: &mut smoltcp::iface::SocketSet<'static>,
        socket_handle: &SocketHandle<Platform>,
        now: smoltcp::time::Instant,
    ) {
        let proxy = match &socket_handle.proxy {
            Some(proxy) => proxy.as_ref(),
            None => return,
        };
        match (socket_handle.protocol(), proxy) {
            (Protocol::Tcp, NetworkProxy::Stream(proxy)) => {
                let tcp_socket = socket_set.get_mut::<tcp::Socket>(socket_handle.handle);
                let tcp_specific = socket_handle.specific.tcp();

                // Drain TX buffer: from ring buffer directly to smoltcp
                while tcp_socket.can_send() {
                    let sent = proxy
                        .pop_tx_data_with(|data| tcp_socket.send_slice(data).unwrap_or_default());
                    if sent == 0 {
                        break;
                    }
                }

                // `shutdown(SHUT_WR)`: the FIN goes out only after everything the application
                // wrote before it has been handed to smoltcp, so it sequences after the data.
                if tcp_specific.write_shutdown.load(Ordering::Acquire)
                    && !proxy.has_pending_tx()
                    && matches!(
                        tcp_socket.state(),
                        tcp::State::SynReceived | tcp::State::Established | tcp::State::CloseWait
                    )
                {
                    tcp_socket.close();
                }

                // Drain RX buffer: from smoltcp directly to ring buffer. After `shutdown(SHUT_RD)`
                // the data is discarded instead, so the window stays open and the peer is not
                // stalled by a reader that will never come.
                if tcp_specific.read_shutdown.load(Ordering::Acquire) {
                    while tcp_socket.can_recv() {
                        let discarded = tcp_socket
                            .recv(|data| (data.len(), data.len()))
                            .unwrap_or_default();
                        if discarded == 0 {
                            break;
                        }
                    }
                } else {
                    while tcp_socket.can_recv() {
                        let received = proxy.push_rx_data_with(|buf| {
                            tcp_socket.recv_slice(buf).unwrap_or_default()
                        });
                        if received == 0 {
                            break;
                        }
                    }
                }

                // Peer FIN, `POLLRDHUP` half: Linux's `tcp_fin()` sets `RCV_SHUTDOWN` -- and so
                // `POLLRDHUP` -- the instant the FIN arrives, independent of whatever data is
                // still queued ahead of it for the application to read. Fired once, as soon as
                // the FIN is observed, well before the ring-drain-gated `read()`-returns-0
                // transition below (which is a separate, later event).
                if !tcp_specific.peer_fin_notified.load(Ordering::Acquire)
                    && tcp_specific.server_socket.is_none()
                    && peer_finished(tcp_socket)
                {
                    tcp_specific
                        .peer_fin_notified
                        .store(true, Ordering::Release);
                    proxy.notify_peer_fin();
                    proxy.notify_io_event(Events::RDHUP);
                }

                // Peer FIN, `read()`-returns-0 half. Once every byte before it has left smoltcp
                // and the application has emptied the ring, the channel's read side is closed so
                // `read()` returns 0 and `poll()` reports readable -- Linux's `RCV_SHUTDOWN`
                // becoming visible to a reader that has caught up. The write side is untouched:
                // in CLOSE-WAIT the application may still send. Before this a peer close went
                // unnoticed until the 75 s socket timeout aborted the connection, and then
                // surfaced as `ECONNRESET`.
                if !tcp_specific.rx_eof_signaled.load(Ordering::Acquire)
                    && !tcp_specific.read_shutdown.load(Ordering::Acquire)
                    && tcp_specific.server_socket.is_none()
                    && peer_finished(tcp_socket)
                    && !proxy.is_readable()
                {
                    tcp_specific.rx_eof_signaled.store(true, Ordering::Release);
                    proxy.shutdown_read();
                    proxy.set_readable(true);
                    proxy.notify_io_event(Events::IN | Events::RDHUP);
                }

                // Timeout policy. smoltcp's socket timeout aborts the connection once the peer
                // has been silent for that long, counted from its last packet and regardless of
                // whether it owes anything -- left at `TCP_CONNECT_TIMEOUT` after `connect`, it
                // killed every idle connection (and every CLOSE-WAIT one) after 75 s. Linux only
                // gives up when *unacknowledged data* goes unanswered, so the timeout is armed
                // only while the transmit queue is non-empty (smoltcp restarts the clock when
                // data enters an empty queue) and disarmed otherwise.
                if matches!(
                    tcp_socket.state(),
                    tcp::State::Established
                        | tcp::State::CloseWait
                        | tcp::State::FinWait1
                        | tcp::State::FinWait2
                        | tcp::State::Closing
                        | tcp::State::LastAck
                ) {
                    let wanted = (tcp_socket.send_queue() > 0).then_some(TCP_RETRANSMIT_TIMEOUT);
                    if tcp_socket.timeout() != wanted {
                        tcp_socket.set_timeout(wanted);
                    }
                }

                if let tcp::State::Established = tcp_socket.state() {
                    proxy.set_state(socket_channel::SocketState::Connected);
                    proxy.clear_async_error();
                }
                // Update socket state in the channel
                // server socket that is listening also has closed state
                // (`recv_queue() > 0`: the socket is done on the wire but the application has
                // not yet been handed everything it received -- keep the channel open until the
                // ring has room for the rest, so the bytes precede the EOF or error.)
                if !tcp_socket.is_open()
                    && tcp_specific.server_socket.is_none()
                    && tcp_socket.recv_queue() == 0
                {
                    // Determine error based on previous socket state
                    match proxy.state() {
                        socket_channel::SocketState::Connecting => {
                            // Socket closed while connecting. Distinguish RST from timeout.
                            let error = match tcp_specific.connect_initiated_at_us {
                                Some(initiated_at) if now - initiated_at >= TCP_CONNECT_TIMEOUT => {
                                    errors::SocketAsyncError::TimedOut
                                }
                                _ => errors::SocketAsyncError::ConnectionRefused,
                            };
                            proxy.set_async_error(error);
                            proxy.set_state(socket_channel::SocketState::Error);
                        }
                        socket_channel::SocketState::Connected => {
                            // A close that went through the FIN handshake (TIME-WAIT, or CLOSED
                            // after LAST-ACK) is not an error; only an RST or abort is.
                            let graceful = tcp_specific.rx_eof_signaled.load(Ordering::Acquire)
                                || peer_finished(tcp_socket);
                            if !graceful {
                                proxy.set_async_error(errors::SocketAsyncError::ConnectionReset);
                            }
                            proxy.set_state(socket_channel::SocketState::Closed);
                        }
                        _ => {
                            proxy.set_state(socket_channel::SocketState::Closed);
                        }
                    }
                }

                if let Some(server_socket) = tcp_specific.server_socket.as_ref()
                    && !proxy.is_readable()
                {
                    server_socket
                        .socket_set_handles
                        .iter()
                        .any(|&h| {
                            let socket: &tcp::Socket = socket_set.get(h);
                            accept_ready(socket.state())
                        })
                        .then(|| {
                            proxy.set_readable(true);
                            proxy.notify_io_event(Events::IN);
                        });
                }
            }
            (Protocol::Udp, NetworkProxy::Datagram(udp_proxy)) => {
                let udp_socket = socket_set.get_mut::<udp::Socket>(socket_handle.handle);
                let remote_endpoint = socket_handle.udp().remote_endpoint;

                // Drain TX queue: try to send datagrams, consume only on success
                while udp_socket.can_send() {
                    // Try to send - consumes datagram only if closure returns true
                    let result = udp_proxy.try_send_datagram_with(|data, addr| {
                        let destination = addr
                            .map(|s| match s {
                                SocketAddr::V4(addr) => smoltcp::wire::IpEndpoint::from(addr),
                                SocketAddr::V6(_) => unimplemented!(),
                            })
                            .or(remote_endpoint);
                        if let Some(endpoint) = destination {
                            match udp_socket.send_slice(data, endpoint) {
                                // Retry once smoltcp has room.
                                Err(udp::SendError::BufferFull) => false,
                                // Sent, or can never be sent: either way don't retry. An
                                // unaddressable destination is discarded rather than retried, or
                                // it would wedge the queue behind it forever (a blocking sender
                                // would never wake).
                                Ok(()) | Err(udp::SendError::Unaddressable) => true,
                            }
                        } else {
                            // No destination - discard
                            true
                        }
                    });
                    if result != Some(true) {
                        // Either queue empty or send failed
                        break;
                    }
                }

                // Drain RX: receive from smoltcp, push to channel
                while udp_socket.can_recv() {
                    let received = udp_proxy.try_recv_datagram_with(|| {
                        let (data, meta) = udp_socket.recv().ok()?;
                        let source_addr = match meta.endpoint.addr {
                            smoltcp::wire::IpAddress::Ipv4(ipv4) => SocketAddr::V4(
                                core::net::SocketAddrV4::new(ipv4, meta.endpoint.port),
                            ),
                        };
                        Some((data.into(), source_addr))
                    });
                    if received.is_none() {
                        break;
                    }
                }
            }
            (Protocol::Icmp | Protocol::Raw { .. }, _) => {
                unimplemented!()
            }
            _ => panic!("Mismatched protocol and proxy type"),
        }
    }
}

impl<Platform> Network<Platform>
where
    Platform:
        platform::IPInterfaceProvider + platform::TimeProvider + sync::RawSyncPrimitivesProvider,
{
    /// Explicitly private-only function that returns the current (smoltcp) Instant, relative to the
    /// initialized arbitrary 0-point in time.
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(
            // This conversion from u128 to i64 should practically never fail, since 2^63
            // microseconds is roughly 250 years. If a system has been up for that long, then it
            // deserves to panic.
            i64::try_from(
                self.device
                    .platform
                    .now()
                    .duration_since(&self.zero_time)
                    .as_micros(),
            )
            .unwrap(),
        )
    }

    /// Creates a socket.
    ///
    /// By default, the created socket has no associated proxy; to set a proxy, use
    /// [`set_socket_proxy`](Self::set_socket_proxy).
    pub fn socket(&mut self, protocol: Protocol) -> Result<SocketFd<Platform>, SocketError> {
        let handle = match protocol {
            Protocol::Tcp => self.socket_set.add(tcp::Socket::new(
                smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
                smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
            )),
            Protocol::Udp => self.socket_set.add(udp::Socket::new(
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
            )),
            Protocol::Icmp => self.socket_set.add(icmp::Socket::new(
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
            )),
            Protocol::Raw { protocol } => {
                // TODO: Should we maintain a specific allow-list of protocols for raw sockets?
                // Should we allow everything except TCP/UDP/ICMP? Should we allow everything? These
                // questions should be resolved; for now I am disallowing everything else.
                return Err(SocketError::UnsupportedProtocol(protocol));

                #[expect(
                    unreachable_code,
                    reason = "currently raw is just directly disallowed; we might bring this code back in the future"
                )]
                self.socket_set.add(raw::Socket::new(
                    smoltcp::wire::IpVersion::Ipv4,
                    smoltcp::wire::IpProtocol::from(protocol),
                    smoltcp::storage::PacketBuffer::new(
                        vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                        vec![0u8; SOCKET_BUFFER_SIZE],
                    ),
                    smoltcp::storage::PacketBuffer::new(
                        vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                        vec![0u8; SOCKET_BUFFER_SIZE],
                    ),
                ))
            }
        };

        Ok(self.new_socket_fd_for(SocketHandle {
            consider_closed: false,
            handle,
            specific: match protocol {
                Protocol::Tcp => ProtocolSpecific::Tcp(TcpSpecific::new(None)),
                Protocol::Udp => ProtocolSpecific::Udp(UdpSpecific {
                    remote_endpoint: None,
                }),
                Protocol::Icmp => unimplemented!(),
                Protocol::Raw { protocol: _ } => unimplemented!(),
            },
            proxy: None,
        }))
    }

    /// Creates a new [`SocketFd`] for a newly-created [`SocketHandle`].
    fn new_socket_fd_for(&mut self, socket_handle: SocketHandle<Platform>) -> SocketFd<Platform> {
        self.litebox.descriptor_table_mut().insert(socket_handle)
    }

    /// Set the network proxy for the socket at `fd`
    ///
    /// Associating a proxy enables event notification and sending/receiving data without accessing
    /// [`Network`] (which may help avoid lock contention but still requires a periodic call to
    /// [`perform_platform_interaction`](Self::perform_platform_interaction) to move data between smoltcp
    /// and the socket channels though).
    ///
    /// If no proxy is set, then the socket can still be used for sending/receiving data via [`Network`]
    /// interfaces like [`send`](Self::send)/[`receive`](Self::receive), but no events will be notified.
    #[must_use]
    pub fn set_socket_proxy(
        &mut self,
        fd: &SocketFd<Platform>,
        proxy: alloc::sync::Arc<NetworkProxy<Platform>>,
    ) -> bool {
        let descriptor_table = self.litebox.descriptor_table();
        let Some(mut table_entry) = descriptor_table.get_entry_mut(fd) else {
            return false;
        };
        let socket_handle = &mut table_entry.entry;
        socket_handle.proxy = Some(proxy);
        true
    }

    /// Close the socket at `fd`
    pub fn close(
        &mut self,
        fd: &SocketFd<Platform>,
        behavior: CloseBehavior,
    ) -> Result<(), CloseError> {
        let mut dt = self.litebox.descriptor_table_mut();
        // We close immediately if we can
        match dt
            .close_and_duplicate_if_shared(fd, |entry| {
                match behavior {
                    CloseBehavior::Immediate => {
                        let socket_handle = &entry.entry;
                        if let crate::net::Protocol::Tcp = socket_handle.protocol() {
                            socket_handle
                                .tcp()
                                .immediate_close
                                .store(true, Ordering::SeqCst);
                        }
                        return true;
                    }
                    CloseBehavior::Graceful => return true,
                    CloseBehavior::GracefulIfNoPendingData => {}
                }
                // check if there is pending data to be sent
                let socket_handle = &entry.entry;
                if let Some(proxy) = &socket_handle.proxy
                    && proxy.has_pending_tx()
                {
                    return false;
                }
                !socket_handle.with_socket(
                    &self.socket_set,
                    |tcp_socket| tcp_socket.may_send() && tcp_socket.send_queue() > 0,
                    |udp_socket| udp_socket.is_open() && udp_socket.send_queue() > 0,
                )
            })
            .ok_or(CloseError::InvalidFd)?
        {
            super::fd::CloseResult::Closed(socket_handle) => {
                // Can immediately close it out.
                drop(dt);
                self.close_handle(socket_handle.entry);
            }
            super::fd::CloseResult::Duplicated(dup_fd) => {
                // It seems like there might be other duplicates around (e.g., due to `dup`), so we
                // can't immediately close it out.
                // We attempt to queue it for future closure and then just return.
                self.queued_for_closure.push(dup_fd);
            }
            super::fd::CloseResult::Deferred => {
                let Some(()) = dt.with_entry_mut(fd, |entry| entry.entry.consider_closed = true)
                else {
                    unreachable!()
                };
                return Err(CloseError::DataPending);
            }
        }
        Ok(())
    }

    /// Attempt to close as many queued-to-close FDs as possible. Returns `true` iff any of them
    /// were closed.
    fn attempt_to_close_queued(&mut self) -> bool {
        if self.queued_for_closure.is_empty() {
            // fast path
            return false;
        }
        let mut dt = self.litebox.descriptor_table_mut();
        let entries = dt.drain_entries_full_covered_by(&mut self.queued_for_closure);
        drop(dt);
        if entries.is_empty() {
            return false;
        }
        for entry in entries {
            self.close_handle(entry.entry);
        }
        true
    }

    /// Close the `socket_handle`
    fn close_handle(&mut self, socket_handle: SocketHandle<Platform>) {
        let SocketHandle {
            consider_closed: _,
            handle,
            mut specific,
            proxy,
        } = socket_handle;
        match specific.protocol() {
            Protocol::Raw { .. } | Protocol::Icmp => {
                // There is no close/abort for raw and icmp sockets
                let _ = self.socket_set.remove(handle);
            }
            Protocol::Udp => {
                let smoltcp::socket::Socket::Udp(mut socket) = self.socket_set.remove(handle)
                else {
                    unreachable!()
                };
                self.local_port_allocator
                    .deallocate_port(socket.endpoint().port);
                socket.close();
            }
            Protocol::Tcp => {
                let closed_at = self.now();
                let tcp_specific = specific.tcp_mut();
                let was_server = tcp_specific.server_socket.is_some();
                if let Some(server_socket) = tcp_specific.server_socket.take() {
                    // remove all listening sockets in the backlog
                    for handle in server_socket.socket_set_handles {
                        let _ = self.socket_set.remove(handle);
                    }
                }
                if let Some(local_port) = tcp_specific.local_port.take() {
                    self.local_port_allocator.deallocate(local_port);
                }
                let channel = match proxy.as_deref() {
                    Some(NetworkProxy::Stream(channel)) => Some(channel),
                    _ => None,
                };
                let tcp_socket: &mut tcp::Socket = self.socket_set.get_mut(handle);
                // Data the application never read -- still in smoltcp, or in the ring (whose
                // `readable` flag is also how EOF and `SHUT_RD` are signalled, hence the
                // guards). Linux answers such a close with an RST rather than a FIN, since the
                // peer's bytes are being thrown away (RFC 2525 s2.17, `tcp_close`).
                let unread = !was_server
                    && (tcp_socket.recv_queue() > 0
                        || (!tcp_specific.rx_eof_signaled.load(Ordering::Relaxed)
                            && !tcp_specific.read_shutdown.load(Ordering::Relaxed)
                            && channel
                                .is_some_and(socket_channel::StreamSocketChannel::is_readable)));
                if tcp_specific.immediate_close.load(Ordering::Relaxed) || unread {
                    tcp_socket.abort();
                    self.closing_in_background
                        .push(ClosingSocket { handle, closed_at });
                } else if channel.is_some_and(socket_channel::StreamSocketChannel::has_pending_tx)
                    && tcp_socket.may_send()
                {
                    // The last writes have not reached smoltcp yet: keep the pair alive until
                    // they have, then FIN (see `drain_closing_with_pending_tx`).
                    let Some(proxy) = proxy.clone() else {
                        unreachable!("`channel` was taken from `proxy`")
                    };
                    self.closing_with_pending_tx.push(DrainingSocket {
                        handle,
                        closed_at,
                        proxy,
                    });
                } else {
                    tcp_socket.close();
                    self.closing_in_background
                        .push(ClosingSocket { handle, closed_at });
                }
            }
        }
        if let Some(proxy) = proxy {
            proxy.set_state(socket_channel::SocketState::Closed);
        }
        self.automated_platform_interaction(PollDirection::Both);
    }

    /// `shutdown(2)`: close the receive (`read`) and/or transmit (`write`) half of a connected
    /// socket, leaving the descriptor open.
    ///
    /// For TCP, `write` sends a FIN once the bytes already written have been handed to smoltcp
    /// (later writes fail), and `read` makes reads report end-of-file and discards whatever the
    /// peer still sends. A connected UDP socket accepts the call as a no-op, as on Linux.
    pub fn shutdown(
        &mut self,
        fd: &SocketFd<Platform>,
        read: bool,
        write: bool,
    ) -> Result<(), ShutdownError> {
        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table
            .get_entry_mut(fd)
            .ok_or(ShutdownError::InvalidFd)?;
        let socket_handle = &mut table_entry.entry;
        match socket_handle.protocol() {
            Protocol::Tcp => {
                let tcp_specific = socket_handle.specific.tcp();
                if tcp_specific
                    .server_socket
                    .as_ref()
                    .is_some_and(|server| server.backlog.is_some())
                {
                    return Err(ShutdownError::NotConnected);
                }
                let tcp_socket = self.socket_set.get_mut::<tcp::Socket>(socket_handle.handle);
                if !matches!(
                    tcp_socket.state(),
                    tcp::State::Established
                        | tcp::State::CloseWait
                        | tcp::State::FinWait1
                        | tcp::State::FinWait2
                        | tcp::State::Closing
                        | tcp::State::LastAck
                        | tcp::State::TimeWait
                ) {
                    return Err(ShutdownError::NotConnected);
                }
                let channel = match socket_handle.proxy.as_deref() {
                    Some(NetworkProxy::Stream(channel)) => Some(channel),
                    _ => None,
                };
                if read {
                    tcp_specific.read_shutdown.store(true, Ordering::Release);
                    if let Some(channel) = channel {
                        channel.shutdown_read();
                        // Readable-with-nothing-to-read is how poll learns of the EOF.
                        channel.set_readable(true);
                        channel.notify_io_event(Events::IN | Events::RDHUP);
                    }
                }
                if write {
                    tcp_specific.write_shutdown.store(true, Ordering::Release);
                    if let Some(channel) = channel {
                        channel.shutdown_write();
                        channel.notify_io_event(Events::OUT);
                    }
                    // The FIN itself is sent by the drain once the TX ring is empty.
                }
            }
            Protocol::Udp => {
                if socket_handle.udp().remote_endpoint.is_none() {
                    return Err(ShutdownError::NotConnected);
                }
            }
            Protocol::Icmp | Protocol::Raw { protocol: _ } => unimplemented!(),
        }
        drop(table_entry);
        drop(descriptor_table);

        self.automated_platform_interaction(PollDirection::Both);
        Ok(())
    }

    /// Initiate a connection to an IP address
    ///
    /// When `check_progress` is false, this function attempts to initiate a connection.
    /// Otherwise, this function checks the progress of an ongoing connection.
    pub fn connect(
        &mut self,
        fd: &SocketFd<Platform>,
        addr: &SocketAddr,
        check_progress: bool,
    ) -> Result<(), ConnectError> {
        let SocketAddr::V4(addr) = addr else {
            return Err(ConnectError::UnsupportedAddress(*addr));
        };

        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table
            .get_entry_mut(fd)
            .ok_or(ConnectError::InvalidFd)?;
        let socket_handle = &mut table_entry.entry;
        let now = self.now();
        let ret = match socket_handle.protocol() {
            Protocol::Tcp => {
                let check_state = |state: tcp::State| -> Result<(), ConnectError> {
                    match state {
                        tcp::State::Established => {
                            // already connected
                            Ok(())
                        }
                        // The peer may already have closed (or the caller half-closed) by the
                        // time a blocking `connect` re-checks progress: still a success.
                        tcp::State::CloseWait
                        | tcp::State::FinWait1
                        | tcp::State::FinWait2
                        | tcp::State::Closing
                        | tcp::State::LastAck => Ok(()),
                        tcp::State::Closed | tcp::State::TimeWait | tcp::State::Listen => {
                            Err(ConnectError::InvalidState)
                        }
                        tcp::State::SynSent | tcp::State::SynReceived => {
                            Err(ConnectError::InProgress)
                        }
                    }
                };

                let socket: &mut tcp::Socket = self.socket_set.get_mut(socket_handle.handle);
                if check_progress {
                    check_state(socket.state())
                } else {
                    let tcp_specific = socket_handle.tcp_mut();
                    if tcp_specific
                        .server_socket
                        .as_ref()
                        .is_some_and(|server| server.backlog.is_some())
                    {
                        // A listening socket cannot be turned into a client.
                        return Err(ConnectError::InvalidState);
                    }
                    // A socket `bind` already gave a local port (and possibly a local address)
                    // keeps it, exactly as Linux does for a source-bound client; only an
                    // unbound socket gets an ephemeral port here.
                    let (local_port, local_endpoint, was_bound) =
                        if let Some(bound) = tcp_specific.local_port.take() {
                            let addr = tcp_specific
                                .server_socket
                                .as_ref()
                                .and_then(|server| server.ip_listen_endpoint.addr);
                            let endpoint = smoltcp::wire::IpListenEndpoint {
                                addr,
                                port: bound.port(),
                            };
                            (bound, endpoint, true)
                        } else {
                            let fresh = self.local_port_allocator.ephemeral_port()?;
                            let endpoint: smoltcp::wire::IpListenEndpoint = fresh.port().into();
                            (fresh, endpoint, false)
                        };
                    let addr: smoltcp::wire::IpEndpoint = (*addr).into();
                    match socket.connect(self.interface.context(), addr, local_endpoint) {
                        Ok(()) => {
                            socket.set_timeout(Some(TCP_CONNECT_TIMEOUT));
                            tcp_specific.connect_initiated_at_us = Some(now);
                            tcp_specific.local_port = Some(local_port);
                            // A client is no longer a (bound, never-listened) server socket:
                            // `get_local_addr`/`listen` must see the established endpoint, not
                            // the bind-time listen endpoint.
                            tcp_specific.server_socket = None;
                            check_state(socket.state())
                        }
                        Err(tcp::ConnectError::InvalidState) => unreachable!(),
                        Err(tcp::ConnectError::Unaddressable) => {
                            if was_bound {
                                tcp_specific.local_port = Some(local_port);
                            } else {
                                self.local_port_allocator.deallocate(local_port);
                            }
                            Err(ConnectError::Unaddressable)
                        }
                    }
                }
            }
            Protocol::Udp => {
                if addr.port() == 0 {
                    return Err(ConnectError::Unaddressable);
                }
                let socket: &mut udp::Socket = self.socket_set.get_mut(socket_handle.handle);
                if !socket.is_open() {
                    let local_port = self.local_port_allocator.ephemeral_port()?;
                    let local_endpoint: smoltcp::wire::IpListenEndpoint = local_port.port().into();
                    let Ok(()) = socket.bind(local_endpoint) else {
                        unreachable!("binding to a free port cannot fail")
                    };
                }
                let addr: smoltcp::wire::IpEndpoint = (*addr).into();
                socket_handle.udp_mut().remote_endpoint = Some(addr);
                Ok(())
            }
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol: _ } => unimplemented!(),
        };

        let mut result = ret;
        if let Some(proxy) = &socket_handle.proxy {
            match ret {
                Ok(()) => proxy.set_state(socket_channel::SocketState::Connected),
                Err(ConnectError::InProgress) => {
                    proxy.set_state(socket_channel::SocketState::Connecting);
                }
                Err(ConnectError::Unaddressable) => {
                    proxy.set_async_error(errors::SocketAsyncError::ConnectionRefused);
                }
                Err(ConnectError::InvalidState) => {
                    // Distinguish timeout from RST using elapsed time
                    match socket_handle.tcp().connect_initiated_at_us {
                        Some(initiated_at) if now - initiated_at >= TCP_CONNECT_TIMEOUT => {
                            proxy.set_async_error(errors::SocketAsyncError::TimedOut);
                            result = Err(ConnectError::TimedOut);
                        }
                        _ => proxy.set_async_error(errors::SocketAsyncError::ConnectionRefused),
                    }
                }
                Err(_) => {}
            }
        }
        drop(table_entry);
        drop(descriptor_table);

        self.automated_platform_interaction(PollDirection::Both);
        result
    }

    /// Get the local address and port a socket is bound to.
    pub fn get_local_addr(&self, fd: &SocketFd<Platform>) -> Result<SocketAddr, LocalAddrError> {
        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table
            .get_entry_mut(fd)
            .ok_or(LocalAddrError::InvalidFd)?;
        let socket_handle = &mut table_entry.entry;

        match socket_handle.protocol() {
            Protocol::Tcp => {
                // A *listening* socket's address is not on the original
                // `socket()` handle -- `listen`/`refill_to_backlog` create
                // separate accept sockets, and the original never gets a
                // `local_endpoint`, so reading it here returns `0.0.0.0:0` and
                // a guest's `getsockname` (Node's `server.address().port`)
                // sees port 0. The bound listen endpoint recorded at `bind`
                // time is the authoritative answer for a server socket.
                let tcp = socket_handle.tcp();
                if let Some(server) = tcp.server_socket.as_ref() {
                    let ep = &server.ip_listen_endpoint;
                    let addr = match ep.addr {
                        Some(smoltcp::wire::IpAddress::Ipv4(ipv4)) => ipv4,
                        None => Ipv4Addr::UNSPECIFIED,
                    };
                    return Ok(SocketAddr::V4(SocketAddrV4::new(addr, ep.port)));
                }
                // An accepted or connected socket also carries a `local_port`
                // (copied at `accept` time), but its authoritative identity is
                // the established endpoint smoltcp chose: getsockname on an
                // accepted connection must report the concrete local address
                // (e.g. 10.0.0.2:8080), not 0.0.0.0. Only fall back to the
                // bare bound port when no endpoint is established.
                let socket: &tcp::Socket = self.socket_set.get(socket_handle.handle);
                if let Some(endpoint) = socket.local_endpoint() {
                    match endpoint.addr {
                        smoltcp::wire::IpAddress::Ipv4(ipv4) => {
                            return Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, endpoint.port)));
                        }
                    }
                }
                if let Some(local_port) = tcp.local_port.as_ref() {
                    let port = local_port.port();
                    if port != 0 {
                        return Ok(SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::UNSPECIFIED,
                            port,
                        )));
                    }
                }
                Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
            }
            Protocol::Udp => {
                let socket: &udp::Socket = self.socket_set.get(socket_handle.handle);
                let local_endpoint = socket.endpoint();
                match local_endpoint.addr {
                    Some(smoltcp::wire::IpAddress::Ipv4(ipv4)) => {
                        Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, local_endpoint.port)))
                    }
                    None => Ok(SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::UNSPECIFIED,
                        local_endpoint.port,
                    ))),
                }
            }
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol: _ } => unimplemented!(),
        }
    }

    /// Get the remote address and port a socket is connected to, if any.
    pub fn get_remote_addr(&self, fd: &SocketFd<Platform>) -> Result<SocketAddr, RemoteAddrError> {
        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table
            .get_entry_mut(fd)
            .ok_or(RemoteAddrError::InvalidFd)?;
        let socket_handle = &mut table_entry.entry;
        self.get_remote_addr_for_handle(socket_handle)
    }

    /// Get the remote address and port a `SocketHandle` is connected to, if any.
    fn get_remote_addr_for_handle(
        &self,
        socket_handle: &SocketHandle<Platform>,
    ) -> Result<SocketAddr, RemoteAddrError> {
        let endpoint = match socket_handle.protocol() {
            Protocol::Tcp => self
                .socket_set
                .get::<tcp::Socket>(socket_handle.handle)
                .remote_endpoint()
                .ok_or(RemoteAddrError::NotConnected)?,
            Protocol::Udp => socket_handle
                .udp()
                .remote_endpoint
                .ok_or(RemoteAddrError::NotConnected)?,
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol: _ } => unimplemented!(),
        };
        match endpoint.addr {
            smoltcp::wire::IpAddress::Ipv4(ipv4) => {
                Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, endpoint.port)))
            }
        }
    }

    /// Bind a socket to a specific address and port. If the port is 0, an ephemeral port is allocated.
    pub fn bind(
        &mut self,
        fd: &SocketFd<Platform>,
        socket_addr: &SocketAddr,
    ) -> Result<(), BindError> {
        let SocketAddr::V4(addr) = socket_addr else {
            return Err(BindError::UnsupportedAddress(*socket_addr));
        };

        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table
            .get_entry_mut(fd)
            .ok_or(BindError::InvalidFd)?;
        let socket_handle = &mut table_entry.entry;
        match socket_handle.protocol() {
            Protocol::Tcp => {
                // Already bound, or already connected (a client owns a local port without a
                // server-side record): Linux answers a second `bind` with `EINVAL`.
                if socket_handle.tcp().server_socket.is_some()
                    || socket_handle.tcp().local_port.is_some()
                {
                    return Err(BindError::AlreadyBound);
                }
                let lp = self
                    .local_port_allocator
                    .allocate_local_port(addr.port())
                    .map_err(|_| BindError::PortAlreadyInUse(addr.port()))?;
                let new_port = lp.port();
                socket_handle.tcp_mut().local_port = Some(lp);
                socket_handle.tcp_mut().server_socket = Some(TcpServerSpecific {
                    ip_listen_endpoint: smoltcp::wire::IpListenEndpoint {
                        addr: (!addr.ip().is_unspecified())
                            .then(|| smoltcp::wire::IpAddress::Ipv4(*addr.ip())),
                        port: new_port,
                    },
                    backlog: None,
                    socket_set_handles: vec![],
                });
            }
            Protocol::Udp => {
                let lp = self
                    .local_port_allocator
                    .allocate_local_port(addr.port())
                    .map_err(|_| BindError::PortAlreadyInUse(addr.port()))?;
                let local_endpoint = smoltcp::wire::IpListenEndpoint {
                    addr: (!addr.ip().is_unspecified())
                        .then(|| smoltcp::wire::IpAddress::Ipv4(*addr.ip())),
                    port: lp.port(),
                };
                let socket: &mut udp::Socket = self.socket_set.get_mut(socket_handle.handle);
                if let Err(e) = socket.bind(local_endpoint) {
                    self.local_port_allocator.deallocate(lp);
                    return Err(match e {
                        udp::BindError::InvalidState => BindError::AlreadyBound,
                        udp::BindError::Unaddressable => unreachable!(),
                    });
                }
            }
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol: _ } => unimplemented!(),
        }

        drop(table_entry);
        drop(descriptor_table);

        self.automated_platform_interaction(PollDirection::Both);
        Ok(())
    }

    /// Prepare a socket to accept incoming connections. Marks the socket as a passive socket, such
    /// that it will be used to accept new connection requests via [`accept`](Self::accept).
    ///
    /// The `backlog` argument defines the maximum length to which the queue of pending connections
    /// the `fd` may grow. This function is allowed to silently cap the value to a reasonable upper
    /// bound.
    pub fn listen(&mut self, fd: &SocketFd<Platform>, backlog: u16) -> Result<(), ListenError> {
        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table
            .get_entry_mut(fd)
            .ok_or(ListenError::InvalidFd)?;
        let socket_handle = &mut table_entry.entry;
        if backlog == 0 {
            // What should actually happen here?
            unimplemented!()
        }

        // This prevents users from overloading things too badly; 4096 is the upper limit with
        // similar silent-cap behavior since Linux 5.4 (earlier versions capped even smaller, at
        // 128, but we use the larger value to be more flexible).
        //
        // TODO: smoltcp performs a linear search through SocketSet when dispatching an incoming
        // packet to the socket it belongs to, so having a large backlog can cause performance issues
        // (see https://github.com/smoltcp-rs/smoltcp/issues/973). Restricting the backlog to a smaller
        // value for now until we have a better solution.
        let backlog = backlog.min(8);

        match &mut socket_handle.specific {
            ProtocolSpecific::Tcp(handle) => {
                if handle.server_socket.is_none() {
                    if handle.local_port.is_some() {
                        // A local port without a server record means `connect` was called:
                        // a client socket cannot listen (Linux: `EINVAL`).
                        return Err(ListenError::InvalidState);
                    }
                    let local_port =
                        self.local_port_allocator
                            .ephemeral_port()
                            .map_err(|e| match e {
                                local_ports::LocalPortAllocationError::AlreadyInUse(_) => {
                                    unreachable!()
                                }
                                local_ports::LocalPortAllocationError::NoAvailableFreePorts => {
                                    ListenError::NoAvailableFreeEphemeralPorts
                                }
                            })?;
                    let port = local_port.port();
                    handle.local_port = Some(local_port);
                    handle.server_socket = Some(TcpServerSpecific {
                        ip_listen_endpoint: smoltcp::wire::IpListenEndpoint {
                            addr: Some(smoltcp::wire::IpAddress::v4(0, 0, 0, 0)),
                            port,
                        },
                        backlog: None,
                        socket_set_handles: vec![],
                    });
                }
                let Some(server_socket) = &mut handle.server_socket else {
                    unreachable!()
                };
                if server_socket.ip_listen_endpoint.port == 0 {
                    return Err(ListenError::InvalidAddress);
                }
                if server_socket.backlog.is_some() || !server_socket.socket_set_handles.is_empty() {
                    // Need to change the amount of backlog; growing will just work, but truncating
                    // might need some effort to pick which ones to keep/drop
                    unimplemented!()
                } else {
                    server_socket.backlog = Some(backlog);
                    server_socket.socket_set_handles = Vec::with_capacity(backlog.into());
                }
                server_socket.refill_to_backlog(&mut self.socket_set);
            }
            ProtocolSpecific::Udp(_) => unimplemented!(),
            ProtocolSpecific::Icmp(_) => unimplemented!(),
            ProtocolSpecific::Raw(_) => unimplemented!(),
        }

        if let Some(proxy) = &socket_handle.proxy {
            proxy.set_state(socket_channel::SocketState::Listening);
        }

        drop(table_entry);
        drop(descriptor_table);

        self.automated_platform_interaction(PollDirection::Ingress);
        Ok(())
    }

    /// Accept a new incoming connection on a listening socket.
    ///
    /// If `peer` is provided, it is filled with the remote address of the accepted connection.
    ///
    /// Note that the returned new socket has no associated proxy; to set a proxy, use
    /// [`set_socket_proxy`](Self::set_socket_proxy).
    pub fn accept(
        &mut self,
        fd: &SocketFd<Platform>,
        peer: Option<&mut SocketAddr>,
    ) -> Result<SocketFd<Platform>, AcceptError> {
        self.automated_platform_interaction(PollDirection::Both);
        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table
            .get_entry_mut(fd)
            .ok_or(AcceptError::InvalidFd)?;
        let socket_handle = &mut table_entry.entry;
        match &mut socket_handle.specific {
            ProtocolSpecific::Tcp(handle) => {
                let Some(server_socket) = &mut handle.server_socket else {
                    return Err(AcceptError::NotListening);
                };
                if server_socket.backlog.is_none() {
                    return Err(AcceptError::NotListening);
                }
                // (Purely an optimization) remove all handles that are closed, by only keeping ones
                // that are not closed
                server_socket.socket_set_handles.retain(|&h| {
                    let socket: &tcp::Socket = self.socket_set.get(h);
                    socket.is_open()
                });
                // Find a socket that has completed its handshake (see `accept_ready`).
                let Some(position) = server_socket.socket_set_handles.iter().position(|&h| {
                    let socket: &tcp::Socket = self.socket_set.get(h);
                    accept_ready(socket.state())
                }) else {
                    if let Some(proxy) = &socket_handle.proxy {
                        // No connections are ready; make sure the readable flag is cleared
                        proxy.set_readable(false);
                    }
                    return Err(AcceptError::NoConnectionsReady);
                };
                if let Some(proxy) = &socket_handle.proxy {
                    // reset the readable flag so that we send one [`Events::In`] event per accepted connection
                    proxy.set_readable(false);
                }
                // Pull that position out of the listening handles
                let ready_handle = server_socket.socket_set_handles.swap_remove(position);
                // Refill to the backlog, so that we can have more listening sockets again if needed
                server_socket.refill_to_backlog(&mut self.socket_set);
                // Grab the local port again, so we can put it into the new `TcpSpecific`
                let local_port = handle
                    .local_port
                    .as_ref()
                    .map(|lp| self.local_port_allocator.allocate_same_local_port(lp));
                // Release the locks, needed to be able to use `self` below
                drop(table_entry);
                drop(descriptor_table);
                // Create a new FD to hand it back out to the user
                let handle = SocketHandle {
                    consider_closed: false,
                    handle: ready_handle,
                    specific: ProtocolSpecific::Tcp(TcpSpecific::new(local_port)),
                    proxy: None,
                };
                if let Some(peer) = peer {
                    let Ok(remote_addr) = self.get_remote_addr_for_handle(&handle) else {
                        unreachable!("a connected TCP socket must have a remote address")
                    };
                    *peer = remote_addr;
                }
                Ok(self.new_socket_fd_for(handle))
            }
            ProtocolSpecific::Udp(_) => unimplemented!(),
            ProtocolSpecific::Icmp(_) => unimplemented!(),
            ProtocolSpecific::Raw(_) => unimplemented!(),
        }
    }

    /// Send data over a socket, optionally specifying the destination address.
    ///
    /// If the socket is connection-mode and the destination address is provided,
    /// `Err(SendError::UnnecessaryDestinationAddress)` is returned.
    pub fn send(
        &mut self,
        fd: &SocketFd<Platform>,
        buf: &[u8],
        flags: SendFlags,
        destination: Option<SocketAddr>,
    ) -> Result<usize, SendError> {
        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table
            .get_entry_mut(fd)
            .ok_or(SendError::InvalidFd)?;
        let socket_handle = &mut table_entry.entry;
        if !flags.is_empty() {
            unimplemented!()
        }

        let ret = match socket_handle.protocol() {
            Protocol::Tcp => {
                if destination.is_some() {
                    // TCP is connection-oriented, so no destination address should be provided
                    return Err(SendError::UnnecessaryDestinationAddress);
                }
                self.socket_set
                    .get_mut::<tcp::Socket>(socket_handle.handle)
                    .send_slice(buf)
                    .map_err(|tcp::SendError::InvalidState| SendError::SocketInInvalidState)
            }
            Protocol::Udp => {
                let destination = destination
                    .map(|s| match s {
                        SocketAddr::V4(addr) => smoltcp::wire::IpEndpoint::from(addr),
                        SocketAddr::V6(_) => unimplemented!(),
                    })
                    .or_else(|| socket_handle.udp().remote_endpoint);
                let Some(remote_endpoint) = destination else {
                    return Err(SendError::DestinationAddressRequired);
                };
                let udp_socket: &mut udp::Socket = self.socket_set.get_mut(socket_handle.handle);
                if !udp_socket.is_open() {
                    let local_port = self
                        .local_port_allocator
                        .ephemeral_port()
                        .map_err(SendError::PortAllocationFailure)?;
                    let port = local_port.port();
                    let Ok(()) =
                        udp_socket.bind(smoltcp::wire::IpListenEndpoint { addr: None, port })
                    else {
                        self.local_port_allocator.deallocate(local_port);
                        unreachable!("binding to a free port cannot fail")
                    };
                }
                udp_socket
                    .send_slice(buf, remote_endpoint)
                    .map(|()| buf.len())
                    .map_err(|e| match e {
                        udp::SendError::BufferFull => SendError::BufferFull,
                        udp::SendError::Unaddressable => SendError::Unaddressable,
                    })
            }
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol: _ } => unimplemented!(),
        };

        drop(table_entry);
        drop(descriptor_table);

        self.automated_platform_interaction(PollDirection::Egress);
        ret
    }

    /// Receive data from a connected socket.
    ///
    /// If the `source_addr` is `Some` and the underlying protocol provides a source address, it will be updated.
    /// e.g., UDP does provide the source address, while TCP does not (because it is connection-oriented,
    /// once it is established, both ends should already know each other's addresses).
    ///
    /// On success, returns the number of bytes received.
    pub fn receive(
        &mut self,
        fd: &SocketFd<Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, ReceiveError> {
        // Note that we do an earlier-than-usual automated interaction to ingress packets since it
        // doesn't hurt to do this too often (other than wasting energy), and this allows us to
        // possibly get packets where we might otherwise return with size 0 on the `receive`.
        self.automated_platform_interaction(PollDirection::Ingress);
        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table
            .get_entry_mut(fd)
            .ok_or(ReceiveError::InvalidFd)?;
        let socket_handle = &mut table_entry.entry;
        if flags.intersects(
            (ReceiveFlags::DONTWAIT | ReceiveFlags::TRUNC | ReceiveFlags::DISCARD).complement(),
        ) {
            unimplemented!("flags: {:?}", flags);
        }

        let ret = match socket_handle.protocol() {
            Protocol::Tcp => {
                if let Some(source_addr) = source_addr {
                    // TCP is connection-oriented, so no need to provide a source address
                    *source_addr = None;
                }
                let tcp_socket = self.socket_set.get_mut::<tcp::Socket>(socket_handle.handle);
                if flags.contains(ReceiveFlags::TRUNC) {
                    unimplemented!("TRUNC flag for tcp");
                }
                if flags.contains(ReceiveFlags::DISCARD) {
                    let discard_slice =
                        |tcp_socket: &mut tcp::Socket<'_>| -> Result<usize, tcp::RecvError> {
                            // See [`tcp::Socket::recv_slice`] and [`tcp::Socket::recv`] for why we do two `recv` calls.
                            // Basically, the socket buffer is implemented as a ring buffer, and if the data to be read
                            // wraps around, a single `recv` call will not be able to read all the data.
                            let size1 = tcp_socket.recv(|data| (data.len(), data.len()))?;
                            let size2 = tcp_socket.recv(|data| (data.len(), data.len()))?;
                            Ok(size1 + size2)
                        };
                    discard_slice(tcp_socket)
                } else {
                    tcp_socket.recv_slice(buf)
                }
                .map_err(|e| match e {
                    tcp::RecvError::InvalidState => ReceiveError::SocketInInvalidState,
                    tcp::RecvError::Finished => ReceiveError::OperationFinished,
                })
            }
            Protocol::Udp => {
                let udp_socket = self.socket_set.get_mut::<udp::Socket>(socket_handle.handle);
                match udp_socket.recv() {
                    Ok((data, meta)) => {
                        if let Some(source_addr) = source_addr {
                            let remote_addr = match meta.endpoint.addr {
                                smoltcp::wire::IpAddress::Ipv4(ipv4_addr) => {
                                    SocketAddr::V4(SocketAddrV4::new(ipv4_addr, meta.endpoint.port))
                                }
                            };
                            *source_addr = Some(remote_addr);
                        }
                        let n = if flags.contains(ReceiveFlags::DISCARD) {
                            data.len()
                        } else {
                            let length = data.len().min(buf.len());
                            buf[..length].copy_from_slice(&data[..length]);
                            if flags.contains(ReceiveFlags::TRUNC) {
                                // return the real size of the packet or datagram,
                                // even when it was longer than the passed buffer.
                                data.len()
                            } else {
                                length
                            }
                        };
                        Ok(n)
                    }
                    Err(udp::RecvError::Exhausted) => Ok(0),
                    Err(udp::RecvError::Truncated) => unreachable!(),
                }
            }
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol: _ } => unimplemented!(),
        };

        drop(table_entry);
        drop(descriptor_table);

        self.automated_platform_interaction(PollDirection::Ingress);
        ret
    }

    /// Set TCP options
    pub fn set_tcp_option(
        &mut self,
        fd: &SocketFd<Platform>,
        data: TcpOptionData,
    ) -> Result<(), errors::SetTcpOptionError> {
        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table
            .get_entry_mut(fd)
            .ok_or(errors::SetTcpOptionError::InvalidFd)?;
        let socket_handle = &mut table_entry.entry;
        match socket_handle.protocol() {
            Protocol::Tcp => {
                let tcp_socket = self.socket_set.get_mut::<tcp::Socket>(socket_handle.handle);
                match data {
                    TcpOptionData::NODELAY(nodelay) => {
                        tcp_socket.set_nagle_enabled(!nodelay);
                    }
                    TcpOptionData::KEEPALIVE(keepalive) => {
                        tcp_socket.set_keep_alive(keepalive.map(smoltcp::time::Duration::from));
                    }
                    TcpOptionData::CONGESTION(congestion) => match congestion {
                        CongestionControl::None => {
                            tcp_socket.set_congestion_control(tcp::CongestionControl::None);
                        }
                        _ => unimplemented!(),
                    },
                }
                Ok(())
            }
            Protocol::Udp | Protocol::Icmp | Protocol::Raw { .. } => {
                Err(errors::SetTcpOptionError::NotTcpSocket)
            }
        }
    }
    /// Get TCP options
    pub fn get_tcp_option(
        &self,
        fd: &SocketFd<Platform>,
        name: TcpOptionName,
    ) -> Result<TcpOptionData, errors::GetTcpOptionError> {
        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table
            .get_entry_mut(fd)
            .ok_or(errors::GetTcpOptionError::InvalidFd)?;
        let socket_handle = &mut table_entry.entry;
        match socket_handle.protocol() {
            Protocol::Tcp => {
                let tcp_socket = self.socket_set.get::<tcp::Socket>(socket_handle.handle);
                match name {
                    TcpOptionName::NODELAY => {
                        Ok(TcpOptionData::NODELAY(!tcp_socket.nagle_enabled()))
                    }
                    TcpOptionName::KEEPALIVE => Ok(TcpOptionData::KEEPALIVE(
                        tcp_socket.keep_alive().map(core::time::Duration::from),
                    )),
                    TcpOptionName::CONGESTION => Ok(TcpOptionData::CONGESTION(
                        match tcp_socket.congestion_control() {
                            tcp::CongestionControl::None => CongestionControl::None,
                        },
                    )),
                }
            }
            Protocol::Udp | Protocol::Icmp | Protocol::Raw { .. } => {
                Err(errors::GetTcpOptionError::NotTcpSocket)
            }
        }
    }
}

/// Protocols for sockets supported by LiteBox
#[non_exhaustive]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Raw { protocol: u8 },
}

bitflags! {
    /// Flags for the `receive` function.
    #[derive(Clone, Copy, Debug)]
    pub struct ReceiveFlags: u32 {
        /// `MSG_CMSG_CLOEXEC`: close-on-exec for the associated file descriptor
        const CMSG_CLOEXEC = 0x40000000;
        /// `MSG_DONTWAIT`: non-blocking operation
        const DONTWAIT = 0x40;
        /// `MSG_ERRQUEUE`: destination for error messages
        const ERRQUEUE = 0x2000;
        /// `MSG_OOB`: requests receipt of out-of-band data
        const OOB = 0x1;
        /// `MSG_PEEK`: requests to peek at incoming messages
        const PEEK = 0x2;
        /// `MSG_TRUNC`: truncate the message
        const TRUNC = 0x20;
        /// `MSG_WAITALL`: wait for the full amount of data
        const WAITALL = 0x100;
        /// Discard the received data
        const DISCARD = 0x8000;
    }
}

bitflags! {
    /// Flags for the `send` function.
    #[derive(Clone, Copy, Debug)]
    pub struct SendFlags: u32 {
        /// `MSG_CONFIRM`: requests confirmation of the message delivery.
        const CONFIRM = 0x800;
        /// `MSG_DONTROUTE`: send the message directly to the interface, bypassing routing.
        const DONTROUTE = 0x4;
        /// `MSG_DONTWAIT`: non-blocking operation, do not wait for buffer space to become available.
        const DONTWAIT = 0x40;
        /// `MSG_EOR`: indicates the end of a record for message-oriented sockets.
        const EOR = 0x80;
        /// `MSG_MORE`: indicates that more data will follow.
        const MORE = 0x8000;
        /// `MSG_NOSIGNAL`: prevents the sending of SIGPIPE signals when writing to a socket that is closed.
        const NOSIGNAL = 0x4000;
        /// `MSG_OOB`: sends out-of-band data.
        const OOB = 0x1;
    }
}

/// Socket options for TCP
#[non_exhaustive]
pub enum TcpOptionName {
    /// If set, disable the Nagle algorithm. This means that
    /// segments are always sent as soon as possible, even if there
    /// is only a small amount of data.
    NODELAY,
    /// Enable sending of keep-alive messages.
    KEEPALIVE,
    /// TCP congestion control algorithm
    CONGESTION,
}

/// Data for TCP options
///
/// Note it should be paired with the correct [`TcpOptionName`] variant.
/// For example, `TcpOptionName::NODELAY` should be paired with `TcpOptionData::NODELAY(true)`.
#[non_exhaustive]
pub enum TcpOptionData {
    NODELAY(bool),
    KEEPALIVE(Option<core::time::Duration>),
    CONGESTION(CongestionControl),
}

/// TCP Congestion Control Algorithms
#[non_exhaustive]
pub enum CongestionControl {
    None,
    Reno,
    Cubic,
}

/// Possible errors from [`Network::shutdown`]
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, Copy)]
pub enum ShutdownError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Socket is not connected")]
    NotConnected,
}

#[derive(Debug, Clone, Copy)]
pub enum CloseBehavior {
    /// Close the socket immediately (i.e., abortive close).
    Immediate,
    /// Close the socket in background and return immediately
    Graceful,
    /// Close the socket in background only if there is not unsent data remaining,
    /// else return an error.
    GracefulIfNoPendingData,
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { platform::IPInterfaceProvider + platform::TimeProvider + sync::RawSyncPrimitivesProvider };
    Network<Platform>;
    @Platform: { platform::TimeProvider + sync::RawSyncPrimitivesProvider };
    SocketHandle<Platform>;
    -> SocketFd<Platform>;
}
