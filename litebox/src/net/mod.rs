//! Network-related functionality

use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddr};

use crate::event::Events;
use crate::platform::Instant;
use crate::utilities::anymap::AnyMap;
use crate::{LiteBox, platform, sync};

use bitflags::bitflags;
use smoltcp::socket::{icmp, raw, tcp, udp};

pub mod errors;
mod local_ports;
mod phy;

#[cfg(test)]
mod tests;

use errors::{
    AcceptError, BindError, CloseError, ConnectError, ListenError, MetadataError, ReceiveError,
    SendError, SetMetadataError, SocketError,
};
use local_ports::{LocalPort, LocalPortAllocator};

/// IP address for LiteBox interface
// TODO: Make this configurable
const INTERFACE_IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// IP address for the gateway
// TODO: Make this configurable
const GATEWAY_IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Maximum size of rx/tx buffers for sockets
const SOCKET_BUFFER_SIZE: usize = 65536;

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
        }
    }
}

/// [`SocketHandle`] stores all relevant information for a specific [`SocketFd`], for easy access
/// from [`SocketFd`], _except_ the `Socket` itself which is stored in the [`Network::socket_set`].
pub(crate) struct SocketHandle {
    /// The handle into the `socket_set`
    handle: smoltcp::iface::SocketHandle,
    // Protocol-specific data
    specific: ProtocolSpecific,
    /// Socket-level metadata
    /// TODO: FD-specific metadata (similar to fs) will be added in the future.
    /// This needs to be handled when switching to the Arc-based implementation
    /// (possibly connected to #31) and is tracked in #120.
    socket_metadata: AnyMap,
}

impl core::ops::Deref for SocketHandle {
    type Target = ProtocolSpecific;
    fn deref(&self) -> &Self::Target {
        &self.specific
    }
}
impl core::ops::DerefMut for SocketHandle {
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
pub(crate) struct UdpSpecific {}

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
            match socket_handle.entry.protocol() {
                Protocol::Tcp => {
                    // TODO: We need to actually update events here; with the previous event-manager interfaces we had, this could be done with:
                    // ```
                    // let socket: &tcp::Socket = self.socket_set.get(socket_handle.entry.handle);
                    // self.event_manager
                    //     .set_events(internal_fd, Events::IN, socket.can_recv());
                    // self.event_manager
                    //     .set_events(internal_fd, Events::OUT, socket.can_send());
                    // ```
                    //
                    // We need to migrate this to the newer interfaces that use observers.
                }
                Protocol::Udp => unimplemented!(),
                Protocol::Icmp => unimplemented!(),
                Protocol::Raw { protocol: _ } => unimplemented!(),
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
            handle,
            specific: match protocol {
                Protocol::Tcp => ProtocolSpecific::Tcp(TcpSpecific {
                    local_port: None,
                    server_socket: None,
                }),
                Protocol::Udp => unimplemented!(),
                Protocol::Icmp => unimplemented!(),
                Protocol::Raw { protocol: _ } => unimplemented!(),
            },
            socket_metadata: AnyMap::new(),
        }))
    }

    /// Creates a new [`SocketFd`] for a newly-created [`SocketHandle`].
    fn new_socket_fd_for(&mut self, socket_handle: SocketHandle) -> SocketFd<Platform> {
        self.litebox.descriptor_table_mut().insert(socket_handle)
    }

    /// Close the socket at `fd`
    pub fn close(&mut self, fd: SocketFd<Platform>) -> Result<(), CloseError> {
        let Some(mut socket_handle) = self.litebox.descriptor_table_mut().remove(fd) else {
            // There might be other duplicates around (e.g., due to `dup`), so we don't want to do
            // any deallocations and such. We just return.
            return Ok(());
        };
        let socket = self.socket_set.remove(socket_handle.entry.handle);
        match socket {
            smoltcp::socket::Socket::Raw(_) | smoltcp::socket::Socket::Icmp(_) => {
                // There is no close/abort for raw and icmp sockets
            }
            smoltcp::socket::Socket::Udp(mut socket) => {
                socket.close();
            }
            smoltcp::socket::Socket::Tcp(mut socket) => {
                if let Some(local_port) = socket_handle.entry.specific.tcp_mut().local_port.take() {
                    self.local_port_allocator.deallocate(local_port);
                }
                // TODO: Should we `.close()` or should we `.abort()`?
                socket.abort();
                // TODO: We need to actually update events here; with the previous event-manager interfaces we had, this could be done with:
                // ```
                // self.event_manager.mark_events(internal_fd, Events::HUP);
                // ```
                //
                // We need to migrate this to the newer interfaces that use observers.
            }
        }
        self.automated_platform_interaction(PollDirection::Both);
        Ok(())
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
        let mut table_entry = descriptor_table.get_entry_mut(fd);
        let socket_handle = &mut table_entry.entry;

        match socket_handle.protocol() {
            Protocol::Tcp => {
                let socket: &mut tcp::Socket = self.socket_set.get_mut(socket_handle.handle);
                let local_port = self.local_port_allocator.ephemeral_port()?;
                let local_endpoint: smoltcp::wire::IpListenEndpoint = local_port.port().into();
                let addr: smoltcp::wire::IpEndpoint = (*addr).into();
                match socket.connect(self.interface.context(), addr, local_endpoint) {
                    Ok(()) => {}
                    Err(tcp::ConnectError::InvalidState) => unreachable!(),
                    Err(tcp::ConnectError::Unaddressable) => todo!(),
                }
                let old_port = socket_handle.tcp_mut().local_port.replace(local_port);
                if old_port.is_some() {
                    // Need to think about how to handle this situation
                    unimplemented!()
                }
            }
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol: _ } => unimplemented!(),
        }

        drop(table_entry);
        drop(descriptor_table);

        self.automated_platform_interaction(PollDirection::Both);
        Ok(())
    }

    /// Bind a socket to a specific address and port.
    pub fn bind(
        &mut self,
        fd: &SocketFd<Platform>,
        socket_addr: &SocketAddr,
    ) -> Result<(), BindError> {
        let SocketAddr::V4(addr) = socket_addr else {
            return Err(BindError::UnsupportedAddress(*socket_addr));
        };

        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table.get_entry_mut(fd);
        let socket_handle = &mut table_entry.entry;

        match socket_handle.protocol() {
            Protocol::Tcp => {
                if socket_handle.tcp().server_socket.is_some() {
                    // Need to think about how to handle this situation where this has already been
                    // marked as a server socket.
                    unimplemented!()
                }
                let port = match self.local_port_allocator.specific_port(
                    addr.port()
                        .try_into()
                        .or(Err(BindError::UnsupportedAddress(*socket_addr)))?,
                ) {
                    Ok(lp) => {
                        let old_lp = socket_handle.tcp_mut().local_port.replace(lp);
                        if let Some(old) = old_lp {
                            self.local_port_allocator.deallocate(old);
                            // Currently unsure if the dealloc is sufficient and if we need to do
                            // anything else here (possibly return an error message due to trying to
                            // do things to a connected socket, not sure), so just marking as
                            // unimplemented for now to trigger a panic.
                            unimplemented!()
                        }
                        addr.port()
                    }
                    Err(e) => match e {
                        local_ports::LocalPortAllocationError::AlreadyInUse(p) => {
                            return Err(BindError::PortAlreadyInUse(p));
                        }
                        local_ports::LocalPortAllocationError::NoAvailableFreePorts => {
                            unreachable!()
                        }
                    },
                };
                socket_handle.tcp_mut().server_socket = Some(TcpServerSpecific {
                    ip_listen_endpoint: smoltcp::wire::IpListenEndpoint {
                        addr: Some(smoltcp::wire::IpAddress::Ipv4(*addr.ip())),
                        port,
                    },
                    backlog: None,
                    socket_set_handles: vec![],
                });
            }
            Protocol::Udp => unimplemented!(),
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
        let mut table_entry = descriptor_table.get_entry_mut(fd);
        let socket_handle = &mut table_entry.entry;

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
    pub fn accept(&mut self, fd: &SocketFd<Platform>) -> Result<SocketFd<Platform>, AcceptError> {
        self.automated_platform_interaction(PollDirection::Both);
        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table.get_entry_mut(fd);
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
                Ok(self.new_socket_fd_for(SocketHandle {
                    handle: ready_handle,
                    specific: ProtocolSpecific::Tcp(TcpSpecific {
                        local_port,
                        server_socket: None,
                    }),
                    socket_metadata: AnyMap::new(),
                }))
            }
            ProtocolSpecific::Udp(_) => unimplemented!(),
            ProtocolSpecific::Icmp(_) => unimplemented!(),
            ProtocolSpecific::Raw(_) => unimplemented!(),
        }
    }

    /// Send data over a connected socket.
    pub fn send(
        &mut self,
        fd: &SocketFd<Platform>,
        buf: &[u8],
        flags: SendFlags,
    ) -> Result<usize, SendError> {
        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table.get_entry_mut(fd);
        let socket_handle = &mut table_entry.entry;

        if !flags.is_empty() {
            unimplemented!()
        }

        let ret = match socket_handle.protocol() {
            Protocol::Tcp => self
                .socket_set
                .get_mut::<tcp::Socket>(socket_handle.handle)
                .send_slice(buf)
                .map_err(|tcp::SendError::InvalidState| SendError::SocketInInvalidState),
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol: _ } => unimplemented!(),
        };

        drop(table_entry);
        drop(descriptor_table);

        self.automated_platform_interaction(PollDirection::Egress);
        ret
    }

    /// Receive data from a connected socket.
    pub fn receive(
        &mut self,
        fd: &SocketFd<Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
    ) -> Result<usize, ReceiveError> {
        // Note that we do an earlier-than-usual automated interaction to ingress packets since it
        // doesn't hurt to do this too often (other than wasting energy), and this allows us to
        // possibly get packets where we might otherwise return with size 0 on the `receive`.
        self.automated_platform_interaction(PollDirection::Ingress);
        let descriptor_table = self.litebox.descriptor_table();
        let mut table_entry = descriptor_table.get_entry_mut(fd);
        let socket_handle = &mut table_entry.entry;

        if flags.intersects(ReceiveFlags::DONTWAIT.complement()) {
            unimplemented!()
        }

        let ret = match socket_handle.protocol() {
            Protocol::Tcp => self
                .socket_set
                .get_mut::<tcp::Socket>(socket_handle.handle)
                .recv_slice(buf)
                .map_err(|e| match e {
                    tcp::RecvError::InvalidState => ReceiveError::SocketInInvalidState,
                    tcp::RecvError::Finished => ReceiveError::OperationFinished,
                }),
            Protocol::Udp => unimplemented!(),
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
        let mut table_entry = descriptor_table.get_entry_mut(fd);
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
                }
                Ok(())
            }
            Protocol::Udp | Protocol::Icmp | Protocol::Raw { .. } => {
                Err(errors::SetTcpOptionError::NotTcpSocket)
            }
        }
    }

    /// Apply `f` on metadata at a socket fd, if it exists.
    pub fn with_metadata<T: core::any::Any, R>(
        &self,
        fd: &SocketFd<Platform>,
        f: impl FnOnce(&T) -> R,
    ) -> Result<R, MetadataError> {
        let descriptor_table = self.litebox.descriptor_table();
        let table_entry = descriptor_table.get_entry(fd);
        let socket_handle = &table_entry.entry;

        if let Some(m) = socket_handle.socket_metadata.get::<T>() {
            Ok(f(m))
        } else {
            Err(MetadataError::NoSuchMetadata)
        }
    }

    /// Similar to [`Self::with_metadata`] but mutable.
    pub fn with_metadata_mut<T: core::any::Any, R>(
        &mut self,
        fd: &SocketFd<Platform>,
        f: impl FnOnce(&mut T) -> R,
    ) -> Result<R, MetadataError> {
        let descriptor_table = self.litebox.descriptor_table_mut();
        let mut table_entry = descriptor_table.get_entry_mut(fd);
        let socket_handle = &mut table_entry.entry;

        if let Some(m) = socket_handle.socket_metadata.get_mut::<T>() {
            Ok(f(m))
        } else {
            Err(MetadataError::NoSuchMetadata)
        }
    }

    /// Store arbitrary metadata into a socket.
    ///
    /// Returns the old metadata if any such metadata exists.
    pub fn set_socket_metadata<T: core::any::Any>(
        &mut self,
        fd: &SocketFd<Platform>,
        metadata: T,
    ) -> Result<Option<T>, SetMetadataError<T>> {
        let descriptor_table = self.litebox.descriptor_table_mut();
        let mut table_entry = descriptor_table.get_entry_mut(fd);
        let socket_handle = &mut table_entry.entry;

        Ok(socket_handle.socket_metadata.insert(metadata))
    }

    /// Get the [`Events`] for a socket.
    pub fn check_events(&self, fd: &SocketFd<Platform>) -> Option<Events> {
        let descriptor_table = self.litebox.descriptor_table_mut();
        let mut table_entry = descriptor_table.get_entry_mut(fd);
        let socket_handle = &mut table_entry.entry;
        match socket_handle.protocol() {
            Protocol::Tcp => {
                let tcp_socket = self.socket_set.get::<tcp::Socket>(socket_handle.handle);
                let mut events = Events::empty();
                if tcp_socket.can_recv() {
                    events |= Events::IN;
                }
                if tcp_socket.can_send() {
                    events |= Events::OUT;
                }
                if !tcp_socket.is_open() {
                    events |= Events::HUP;
                } else if !events.contains(Events::IN) {
                    // A server socket should have `Events::IN` if any of its listening sockets is connected.
                    if let Some(server_socket) = socket_handle.specific.tcp().server_socket.as_ref()
                    {
                        server_socket
                            .socket_set_handles
                            .iter()
                            .any(|&h| {
                                let socket: &tcp::Socket = self.socket_set.get(h);
                                socket.state() == tcp::State::Established
                            })
                            .then(|| events.insert(Events::IN));
                    }
                }
                Some(events)
            }
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol: _ } => unimplemented!(),
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
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
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
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
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
    SocketHandle;
    -> SocketFd<Platform>;
}
