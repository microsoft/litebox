//! Network-related functionality

use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::event::{Events, IOPollable};
use crate::platform::{Instant, TimeProvider};
use crate::sync::RawSyncPrimitivesProvider;
use crate::{LiteBox, platform, sync};

use bitflags::bitflags;
use smoltcp::socket::{icmp, raw, tcp, udp};

pub mod errors;
pub mod local_ports;
mod phy;

#[cfg(test)]
mod tests;

use errors::{
    AcceptError, BindError, CloseError, ConnectError, ListenError, LocalAddrError, ReceiveError,
    RemoteAddrError, SendError, SocketError,
};
use local_ports::{LocalPort, LocalPortAllocator};

/// IP address for LiteBox interface
// TODO: Make this configurable
const INTERFACE_IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// IP address for the gateway
// TODO: Make this configurable
const GATEWAY_IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Maximum size of rx/tx buffers for sockets
pub const SOCKET_BUFFER_SIZE: usize = 65536;

/// Limits maximum number of packets in a buffer
const MAX_PACKET_COUNT: usize = 32;

/// The `Network` provides access to all networking related functionality provided by LiteBox.
///
/// A LiteBox `Network` is parametric in the platform it runs on.
///
/// An important decision that must be made by a user of a `Network` is decided by
/// [`set_platform_interaction`](Self::set_platform_interaction), whose docs explain this further.
///
/// A user of `Network` who does not care about [events](crate::event) can choose to have a trivial
/// provider for [`platform::RawMutexProvider`] that panics on all calls except `new_raw_mutex` and
/// `underlying_atomic`.
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
        let mut device = phy::Device::new(litebox.x.platform);
        let config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut interface =
            smoltcp::iface::Interface::new(config, &mut device, smoltcp::time::Instant::ZERO);
        interface.update_ip_addrs(|ip_addrs| {
            match ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv4(INTERFACE_IP_ADDR),
                24,
            )) {
                Ok(()) => {}
                Err(_) => unreachable!(),
            }
        });
        match interface
            .routes_mut()
            .add_default_ipv4_route(GATEWAY_IP_ADDR)
        {
            Ok(None) => {}
            _ => unreachable!(),
        }
        Self {
            litebox: litebox.clone(),
            socket_set: smoltcp::iface::SocketSet::new(vec![]),
            device,
            interface,
            zero_time: litebox.x.platform.now(),
            local_port_allocator: LocalPortAllocator::new(),
            platform_interaction: PlatformInteraction::Automatic,
            queued_for_closure: vec![],
        }
    }
}

/// [`SocketHandle`] stores all relevant information for a specific [`SocketFd`], for easy access
/// from [`SocketFd`], _except_ the `Socket` itself which is stored in the [`Network::socket_set`].
pub(crate) struct SocketHandle<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// Whether this socket handle is going away soon (i.e., `close` has been invoked upon it).
    consider_closed: bool,
    /// The handle into the `socket_set`
    handle: smoltcp::iface::SocketHandle,
    // Protocol-specific data
    specific: ProtocolSpecific,
    pollee: crate::event::polling::Pollee<Platform>,
    /// Whether the socket was last known to be able to send
    previously_sendable: core::sync::atomic::AtomicBool,
    /// Number of octets in the receive queue
    recv_queue: core::sync::atomic::AtomicUsize,
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

struct PollableSocketHandle<'a, Platform: RawSyncPrimitivesProvider + TimeProvider> {
    socket_handle: &'a SocketHandle<Platform>,
    socket_set: &'a smoltcp::iface::SocketSet<'static>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> PollableSocketHandle<'_, Platform> {
    /// Get the [`Events`] for a socket handle [`SocketHandle`].
    ///
    /// If `new_events_only` is true, only events representing meaningful state changes
    /// since the last check are returned (e.g., new data arrived, socket became writable,
    /// new connections became acceptable).
    ///
    /// Note this is still just an approximation; for example, if data arrives multiple times
    /// before this is called, only one `Events::IN` will be sent. This is probably fine
    /// because we also update the internal state (i.e., `recv_queue`) in [`Network::receive`] calls
    /// so that the following common pattern won't get stuck (it may miss some duplicate `Events::IN`
    /// events, but they are not necessary to make progress; one is sufficient):
    ///
    /// ```text
    /// loop {
    ///     if (poll(socket, Events::IN) > 0) {
    ///         assert!(receive(socket, ...) > 0);
    ///     }
    /// }
    /// ```
    fn check_socket_events(&self, new_events_only: bool) -> Events {
        if self.socket_handle.consider_closed {
            // TODO: update this when we support graceful close
            return Events::empty();
        }
        let mut events = Events::empty();
        let recv_queue_last = self
            .socket_handle
            .recv_queue
            .load(core::sync::atomic::Ordering::Relaxed);
        let (recv_queue_now, sendable_now, receivable_now) = match self.socket_handle.protocol() {
            Protocol::Tcp => {
                let tcp_socket = self
                    .socket_set
                    .get::<tcp::Socket>(self.socket_handle.handle);
                (
                    tcp_socket.recv_queue(),
                    tcp_socket.can_send(),
                    tcp_socket.can_recv(),
                )
            }
            Protocol::Udp => {
                let udp_socket = self
                    .socket_set
                    .get::<udp::Socket>(self.socket_handle.handle);
                (
                    udp_socket.recv_queue(),
                    udp_socket.can_send(),
                    udp_socket.can_recv(),
                )
            }
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol: _ } => unimplemented!(),
        };

        if new_events_only {
            if recv_queue_now > recv_queue_last && receivable_now {
                self.socket_handle
                    .recv_queue
                    .store(recv_queue_now, core::sync::atomic::Ordering::Relaxed);
                // We have more data to receive than last time, so we should notify
                events |= Events::IN;
            }

            let previously_sendable = self
                .socket_handle
                .previously_sendable
                .load(core::sync::atomic::Ordering::Relaxed);
            if !previously_sendable && sendable_now {
                self.socket_handle
                    .previously_sendable
                    .store(true, core::sync::atomic::Ordering::Relaxed);
                // We can now send, so we should notify
                events |= Events::OUT;
            }
        } else {
            if receivable_now {
                events |= Events::IN;
            }
            if sendable_now {
                events |= Events::OUT;
            }
        }

        // A server socket should have `Events::IN` if any of its listening sockets is connected.
        if let Protocol::Tcp = self.socket_handle.protocol()
            && !events.contains(Events::IN)
        {
            let tcp_specific = self.socket_handle.specific.tcp();
            if let Some(server_socket) = tcp_specific.server_socket.as_ref() {
                let previously_acceptable = tcp_specific
                    .previously_acceptable
                    .load(core::sync::atomic::Ordering::Relaxed);
                if !new_events_only || !previously_acceptable {
                    server_socket
                        .socket_set_handles
                        .iter()
                        .any(|&h| {
                            let socket: &tcp::Socket = self.socket_set.get(h);
                            socket.state() == tcp::State::Established
                        })
                        .then(|| {
                            tcp_specific
                                .previously_acceptable
                                .store(true, core::sync::atomic::Ordering::Relaxed);
                            events.insert(Events::IN);
                        });
                }
            }
        }

        events
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable
    for PollableSocketHandle<'_, Platform>
{
    fn register_observer(
        &self,
        observer: alloc::sync::Weak<dyn crate::event::observer::Observer<Events>>,
        mask: Events,
    ) {
        self.socket_handle.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.check_socket_events(false)
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
    /// Whether the socket was last known to be able to accept
    previously_acceptable: core::sync::atomic::AtomicBool,
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

#[derive(Clone, Copy)]
enum PollDirection {
    Ingress,
    Egress,
    Both,
}
impl PollDirection {
    fn ingress(self) -> bool {
        matches!(self, PollDirection::Ingress | PollDirection::Both)
    }
    fn egress(self) -> bool {
        matches!(self, PollDirection::Egress | PollDirection::Both)
    }
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
    /// You don't need to call again until more packets arrive on the device's receive side or if
    /// any socket interaction has occurred.
    WaitOnDeviceOrSocketInteraction,
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
        self.internal_perform_platform_interaction(PollDirection::Both)
    }

    /// (Internal-only API) Actually perform the queued interactions with the outside world.
    fn internal_perform_platform_interaction(
        &mut self,
        direction: PollDirection,
    ) -> PlatformInteractionReinvocationAdvice {
        if self.attempt_to_close_queued() {
            return PlatformInteractionReinvocationAdvice::CallAgainImmediately;
        }
        let timestamp = self.now();
        let mut socket_state_changed = false;
        let ingress_advice = if direction.ingress() {
            match self.interface.poll_ingress_single(
                timestamp,
                &mut self.device,
                &mut self.socket_set,
            ) {
                smoltcp::iface::PollIngressSingleResult::None => {
                    Some(PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction)
                }
                smoltcp::iface::PollIngressSingleResult::PacketProcessed => {
                    Some(PlatformInteractionReinvocationAdvice::CallAgainImmediately)
                }
                smoltcp::iface::PollIngressSingleResult::SocketStateChanged => {
                    socket_state_changed = true;
                    Some(PlatformInteractionReinvocationAdvice::CallAgainImmediately)
                }
            }
        } else {
            None
        };
        if direction.egress() {
            match self
                .interface
                .poll_egress(timestamp, &mut self.device, &mut self.socket_set)
            {
                smoltcp::iface::PollResult::None => {}
                smoltcp::iface::PollResult::SocketStateChanged => {
                    socket_state_changed = true;
                }
            }
        }
        if socket_state_changed {
            self.check_and_update_events();
            PlatformInteractionReinvocationAdvice::CallAgainImmediately
        } else {
            ingress_advice
                .unwrap_or(PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction)
        }
    }

    /// (Internal-only API) Perform the queued interactions only in automatic mode.
    fn automated_platform_interaction(&mut self, direction: PollDirection) {
        match self.platform_interaction {
            PlatformInteraction::Automatic => {
                while self
                    .internal_perform_platform_interaction(direction)
                    .call_again_immediately()
                {
                    // We just loop until all platform interaction is completed, _roughly_ analogous
                    // to smoltcp's `poll`.
                }
            }
            PlatformInteraction::Manual => {}
        }
    }

    /// (Internal-only API) Socket states could have changed, update events
    #[expect(
        unused_variables,
        reason = "this implementation is undergoing change due to change in underlying interfaces for events"
    )]
    fn check_and_update_events(&mut self) {
        for (internal_fd, socket_handle) in
            self.litebox.descriptor_table().iter::<Network<Platform>>()
        {
            let socket_handle = &socket_handle.entry;
            let events = PollableSocketHandle {
                socket_handle,
                socket_set: &self.socket_set,
            }
            .check_socket_events(true);
            if !events.is_empty() {
                socket_handle.pollee.notify_observers(events);
            }
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
                self.zero_time
                    .duration_since(&self.device.platform.now())
                    .as_micros(),
            )
            .unwrap(),
        )
    }

    /// Creates a socket.
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
                Protocol::Tcp => ProtocolSpecific::Tcp(TcpSpecific {
                    local_port: None,
                    server_socket: None,
                    previously_acceptable: core::sync::atomic::AtomicBool::new(false),
                }),
                Protocol::Udp => ProtocolSpecific::Udp(UdpSpecific {
                    remote_endpoint: None,
                }),
                Protocol::Icmp => unimplemented!(),
                Protocol::Raw { protocol: _ } => unimplemented!(),
            },
            pollee: crate::event::polling::Pollee::new(&self.litebox),
            previously_sendable: core::sync::atomic::AtomicBool::new(false),
            recv_queue: core::sync::atomic::AtomicUsize::new(0),
        }))
    }

    /// Creates a new [`SocketFd`] for a newly-created [`SocketHandle`].
    fn new_socket_fd_for(&mut self, socket_handle: SocketHandle<Platform>) -> SocketFd<Platform> {
        self.litebox.descriptor_table_mut().insert(socket_handle)
    }

    /// Close the socket at `fd`
    pub fn close(&mut self, fd: &SocketFd<Platform>) -> Result<(), CloseError> {
        // We close immediately if we can
        let mut dt = self.litebox.descriptor_table_mut();
        if let Some(socket_handle) = dt.remove(fd) {
            // Can immediately close it out.
            drop(dt);
            self.close_handle(socket_handle.entry);
            Ok(())
        } else {
            // It seems like there might be other duplicates around (e.g., due to `dup`), so we
            // can't immediately close it out (or this FD has already been closed out). We
            // attempt to queue it for future closure and then just return.
            let fd = dt.duplicate(fd).ok_or(CloseError::InvalidFd)?;
            let Some(()) = dt.with_entry_mut(&fd, |entry| entry.entry.consider_closed = true)
            else {
                unreachable!()
            };
            self.queued_for_closure.push(fd);
            Ok(())
        }
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
    fn close_handle(&mut self, mut socket_handle: SocketHandle<Platform>) {
        let socket = self.socket_set.remove(socket_handle.handle);
        match socket {
            smoltcp::socket::Socket::Raw(_) | smoltcp::socket::Socket::Icmp(_) => {
                // There is no close/abort for raw and icmp sockets
            }
            smoltcp::socket::Socket::Udp(mut socket) => {
                socket.close();
            }
            smoltcp::socket::Socket::Tcp(mut socket) => {
                if let Some(local_port) = socket_handle.specific.tcp_mut().local_port.take() {
                    self.local_port_allocator.deallocate(local_port);
                }
                // TODO: Should we `.close()` or should we `.abort()`?
                socket.abort();
                socket_handle.pollee.notify_observers(Events::HUP);
            }
        }
        self.automated_platform_interaction(PollDirection::Both);
    }

    /// Initiate a connection to an IP address
    pub fn connect(
        &mut self,
        fd: &SocketFd<Platform>,
        addr: &SocketAddr,
    ) -> Result<(), ConnectError> {
        let SocketAddr::V4(addr) = addr else {
            return Err(ConnectError::UnsupportedAddress(*addr));
        };

        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table
            .get_entry_mut(fd)
            .ok_or(ConnectError::InvalidFd)?;
        let socket_handle = &mut table_entry.entry;
        if socket_handle.consider_closed {
            return Err(ConnectError::InvalidFd);
        }

        match socket_handle.protocol() {
            Protocol::Tcp => {
                let socket: &mut tcp::Socket = self.socket_set.get_mut(socket_handle.handle);
                let local_port = self.local_port_allocator.ephemeral_port()?;
                let local_endpoint: smoltcp::wire::IpListenEndpoint = local_port.port().into();
                let addr: smoltcp::wire::IpEndpoint = (*addr).into();
                match socket.connect(self.interface.context(), addr, local_endpoint) {
                    Ok(()) => {}
                    Err(tcp::ConnectError::InvalidState) => unreachable!(),
                    Err(tcp::ConnectError::Unaddressable) => {
                        self.local_port_allocator.deallocate(local_port);
                        return Err(ConnectError::Unaddressable);
                    }
                }
                let old_port = socket_handle.tcp_mut().local_port.replace(local_port);
                if old_port.is_some() {
                    // Need to think about how to handle this situation
                    unimplemented!()
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
            }
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol: _ } => unimplemented!(),
        }

        drop(table_entry);
        drop(descriptor_table);

        self.automated_platform_interaction(PollDirection::Both);
        Ok(())
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
                let socket: &tcp::Socket = self.socket_set.get(socket_handle.handle);
                match socket.local_endpoint() {
                    Some(endpoint) => match endpoint.addr {
                        smoltcp::wire::IpAddress::Ipv4(ipv4) => {
                            Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, endpoint.port)))
                        }
                    },
                    None => Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))),
                }
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
        if socket_handle.consider_closed {
            return Err(BindError::InvalidFd);
        }

        match socket_handle.protocol() {
            Protocol::Tcp => {
                if socket_handle.tcp().server_socket.is_some() {
                    return Err(BindError::AlreadyBound);
                }
                let lp = self
                    .local_port_allocator
                    .allocate_local_port(addr.port())
                    .map_err(|_| BindError::PortAlreadyInUse(addr.port()))?;
                let new_port = lp.port();
                let old_lp = socket_handle.tcp_mut().local_port.replace(lp);
                if let Some(old) = old_lp {
                    self.local_port_allocator.deallocate(old);
                    // Currently unsure if the dealloc is sufficient and if we need to do
                    // anything else here (possibly return an error message due to trying to
                    // do things to a connected socket, not sure), so just marking as
                    // unimplemented for now to trigger a panic.
                    unimplemented!()
                }
                socket_handle.tcp_mut().server_socket = Some(TcpServerSpecific {
                    ip_listen_endpoint: smoltcp::wire::IpListenEndpoint {
                        addr: Some(smoltcp::wire::IpAddress::Ipv4(*addr.ip())),
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
                    addr: Some(smoltcp::wire::IpAddress::Ipv4(*addr.ip())),
                    port: lp.port(),
                };
                let socket: &mut udp::Socket = self.socket_set.get_mut(socket_handle.handle);
                let _ = socket.bind(local_endpoint).map_err(|e| match e {
                    udp::BindError::InvalidState => BindError::AlreadyBound,
                    udp::BindError::Unaddressable => unreachable!(),
                });
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
        if socket_handle.consider_closed {
            return Err(ListenError::InvalidFd);
        }

        if backlog == 0 {
            // What should actually happen here?
            unimplemented!()
        }

        // This prevents users from overloading things too badly; 4096 is the upper limit with
        // similar silent-cap behavior since Linux 5.4 (earlier versions capped even smaller, at
        // 128, but we use the larger value to be more flexible).
        //
        // We don't actively depend on this specific value, and it can be changed out at any time
        // without any significant issue.
        let backlog = backlog.min(4096);

        match &mut socket_handle.specific {
            ProtocolSpecific::Tcp(handle) => {
                if handle.server_socket.is_none() {
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
                    let old_local_port = handle.local_port.replace(local_port);
                    if let Some(lp) = old_local_port {
                        self.local_port_allocator.deallocate(lp);
                        // Should anything else be done here?
                        unimplemented!()
                    }
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

        drop(table_entry);
        drop(descriptor_table);

        self.automated_platform_interaction(PollDirection::Ingress);
        Ok(())
    }

    /// Accept a new incoming connection on a listening socket.
    ///
    /// If `peer` is provided, it is filled with the remote address of the accepted connection.
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
        if socket_handle.consider_closed {
            return Err(AcceptError::InvalidFd);
        }

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
                    socket.state() != tcp::State::Closed
                });
                // Find a socket that has progressed further in its TCP state machine, by finding a
                // socket in a may-send-or-recv state
                let Some(position) = server_socket.socket_set_handles.iter().position(|&h| {
                    let socket: &tcp::Socket = self.socket_set.get(h);
                    socket.may_send() || socket.may_recv()
                }) else {
                    return Err(AcceptError::NoConnectionsReady);
                };
                // reset the accept state so that [`PollableSocketHandle::check_socket_events`] can send
                // one [`Events::In`] per accepted connection.
                handle
                    .previously_acceptable
                    .store(false, core::sync::atomic::Ordering::Relaxed);
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
                // Trigger some automated platform interaction, to keep things flowing
                self.automated_platform_interaction(PollDirection::Both);
                // Create a new FD to hand it back out to the user
                let handle = SocketHandle {
                    consider_closed: false,
                    handle: ready_handle,
                    specific: ProtocolSpecific::Tcp(TcpSpecific {
                        local_port,
                        server_socket: None,
                        previously_acceptable: core::sync::atomic::AtomicBool::new(false),
                    }),
                    pollee: crate::event::polling::Pollee::new(&self.litebox),
                    previously_sendable: core::sync::atomic::AtomicBool::new(true),
                    recv_queue: core::sync::atomic::AtomicUsize::new(0),
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
        if socket_handle.consider_closed {
            return Err(SendError::InvalidFd);
        }

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
                    return Err(SendError::Unaddressable);
                };
                let udp_socket: &mut udp::Socket = self.socket_set.get_mut(socket_handle.handle);
                if !udp_socket.is_open() {
                    let Ok(()) = udp_socket.bind(smoltcp::wire::IpListenEndpoint {
                        addr: None,
                        port: self
                            .local_port_allocator
                            .ephemeral_port()
                            .map_err(SendError::PortAllocationFailure)?
                            .port(),
                    }) else {
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
        if let Ok(0) = ret {
            // If we sent 0 bytes, then we are not writable anymore
            socket_handle
                .previously_sendable
                .store(false, core::sync::atomic::Ordering::Relaxed);
        }

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
        if socket_handle.consider_closed {
            return Err(ReceiveError::InvalidFd);
        }

        if flags.intersects(
            (ReceiveFlags::DONTWAIT | ReceiveFlags::TRUNC | ReceiveFlags::DISCARD).complement(),
        ) {
            unimplemented!("flags: {:?}", flags);
        }

        let (ret, recv_queue_left) = match socket_handle.protocol() {
            Protocol::Tcp => {
                if let Some(source_addr) = source_addr {
                    // TCP is connection-oriented, so no need to provide a source address
                    *source_addr = None;
                }
                let tcp_socket = self.socket_set.get_mut::<tcp::Socket>(socket_handle.handle);
                if flags.contains(ReceiveFlags::TRUNC) {
                    unimplemented!("TRUNC flag for tcp");
                }
                let ret = if flags.contains(ReceiveFlags::DISCARD) {
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
                });
                (ret, tcp_socket.recv_queue())
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
                        (Ok(n), udp_socket.recv_queue())
                    }
                    Err(udp::RecvError::Exhausted) => (Ok(0), 0),
                    Err(udp::RecvError::Truncated) => unreachable!(),
                }
            }
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol: _ } => unimplemented!(),
        };
        // Update the recv_queue size for event tracking
        socket_handle
            .recv_queue
            .store(recv_queue_left, core::sync::atomic::Ordering::Relaxed);

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
        if socket_handle.consider_closed {
            return Err(errors::SetTcpOptionError::InvalidFd);
        }
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
                }
            }
            Protocol::Udp | Protocol::Icmp | Protocol::Raw { .. } => {
                Err(errors::GetTcpOptionError::NotTcpSocket)
            }
        }
    }

    /// Perform `f` with the [`IOPollable`] for the socket at `fd`.
    ////
    /// Returns `None` if the `fd` is closed.
    pub fn with_iopollable<R>(
        &self,
        fd: &SocketFd<Platform>,
        f: impl FnOnce(&dyn IOPollable) -> R,
    ) -> Option<R> {
        let descriptor_table = self.litebox.descriptor_table();
        let table_entry = descriptor_table.get_entry(fd)?;
        let socket_handle = &table_entry.entry;
        Some(f(&PollableSocketHandle {
            socket_handle,
            socket_set: &self.socket_set,
        }))
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
}

/// Data for TCP options
///
/// Note it should be paired with the correct [`TcpOptionName`] variant.
/// For example, `TcpOptionName::NODELAY` should be paired with `TcpOptionData::NODELAY(true)`.
#[non_exhaustive]
pub enum TcpOptionData {
    NODELAY(bool),
    KEEPALIVE(Option<core::time::Duration>),
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { platform::IPInterfaceProvider + platform::TimeProvider + sync::RawSyncPrimitivesProvider };
    Network<Platform>;
    @Platform: { platform::TimeProvider + sync::RawSyncPrimitivesProvider };
    SocketHandle<Platform>;
    -> SocketFd<Platform>;
}
