// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Network proxy — terminates guest TCP/UDP via smoltcp and bridges to host sockets.
//!
//! # Architecture
//!
//! ```text
//! Guest ←IPC→ [broker smoltcp] ←relay→ host TCP/UDP sockets
//! ```
//!
//! The broker runs its own smoltcp instance with `set_any_ip(true)`. Before each
//! smoltcp poll, incoming packets are staged and inspected. TCP SYN packets
//! trigger on-demand creation of listen sockets so smoltcp can complete the
//! handshake. Once a connection is ESTABLISHED, a host-side `TcpStream` is
//! opened and data is relayed bidirectionally.

mod device;
pub mod dns_tracker;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::audit::AuditLog;
use crate::sandbox_policy::SandboxPolicy;
use crate::sock_compat::{
    self, AsRawSock, IpcListener, IpcStream, POLLERR, POLLHUP, POLLIN, POLLOUT, PollFd, RawSock,
};
use crate::state_registry::BrokerStateRegistry;
use crate::tcp_conn_state::TcpConnState;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address};
use tracing::{debug, error, info, trace, warn};

use device::{DEVICE_MTU, IpcDevice};

/// Broker IP address (gateway from the guest's perspective).
const BROKER_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
/// Broker IP as std Ipv4Addr.
const BROKER_IPV4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// Broker IP as byte array.
const BROKER_IP_BYTES: [u8; 4] = [10, 0, 0, 1];

/// Maximum concurrent TCP flows.
const MAX_CONNECTIONS: usize = 1024;

/// smoltcp socket buffer size (64 KB — broker relays immediately).
const SOCKET_BUFFER_SIZE: usize = 65536;

/// UDP flow idle timeout before garbage collection.
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// IPC handshake magic bytes.
const HANDSHAKE_MAGIC: &[u8; 4] = b"LBNP";

/// Handshake protocol version.
const HANDSHAKE_VERSION: u16 = 1;

/// Full TCP 4-tuple identifying a unique connection.
/// (guest_src_ip, guest_src_port, dst_ip, dst_port)
type TcpFlowKey = ([u8; 4], u16, [u8; 4], u16);

/// Allocate a unique ephemeral source port for smoltcp `connect()`.
///
/// Uses a global atomic counter so that all proxy threads (one per worker)
/// get distinct ports. Without this, two proxies could pick the same source
/// port for bridges in the same smoltcp instance, causing the second
/// `connect()` to fail with a duplicate-socket RST.
fn alloc_inbound_src_port() -> u16 {
    static COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(49152);
    let port = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if port < 49152 {
        // Wrapped around — reset to base. Extremely unlikely in practice.
        COUNTER.store(49153, std::sync::atomic::Ordering::Relaxed);
        49152
    } else {
        port
    }
}

/// State for an active TCP bridge between smoltcp and a host socket.
struct TcpBridge {
    smoltcp_handle: SocketHandle,
    host_stream: std::net::TcpStream,
    dest: SocketAddr,
    /// Whether the host side has reached EOF.
    host_eof: bool,
    /// Whether the guest side has reached EOF (FIN received).
    guest_eof: bool,
}

/// A TCP connection in the process of connecting to the host (non-blocking).
/// The smoltcp listen socket is NOT created until the host connect succeeds,
/// so guest connect() only succeeds after the real host connection is ready.
struct PendingConnect {
    /// Full 4-tuple so parallel connections to the same server are distinguished.
    flow_key: TcpFlowKey,
    dest: SocketAddr,
    /// Connecting stream.
    stream: IpcStream,
    /// When the connect was initiated (for timeout).
    started: Instant,
}

/// A newly accepted connection waiting for transport classification.
/// Drained opportunistically each event-loop iteration with zero blocking.
struct PendingHandshake {
    stream: Option<IpcStream>,
    raw_socket: RawSock,
    handshake: [u8; 8],
    got: usize,
    deadline: Instant,
}

/// Timeout for the LB9P handshake on an accepted connection.
const HANDSHAKE_ACCEPT_TIMEOUT: Duration = Duration::from_millis(100);

/// Maximum total time to receive direct shared-memory 9P upgrade metadata.
#[cfg(windows)]
const LB9P_RING_UPGRADE_TIMEOUT: Duration = Duration::from_secs(2);

/// Hard cap on concurrent background direct 9P ring-upgrade workers.
#[cfg(any(unix, windows))]
const MAX_CONCURRENT_LB9P_RING_UPGRADES: usize = 32;

/// Number of currently active background direct 9P ring-upgrade workers.
#[cfg(any(unix, windows))]
static ACTIVE_LB9P_RING_UPGRADES: AtomicUsize = AtomicUsize::new(0);

/// Maximum concurrently active extra LBNP proxy sessions accepted from the
/// listener while an initial session is already running.
const MAX_ADDITIONAL_LBNP_SESSIONS: usize = 32;

/// Maximum accepted-but-not-yet-classified listener sockets kept in the
/// pending handshake queue at once.
const MAX_PENDING_ACCEPTED_HANDSHAKES: usize = 32;

/// An inbound TCP port forward: host listens on a port and relays connections
/// to a guest IP:port inside the smoltcp virtual network.
struct InboundForward {
    listener: std::net::TcpListener,
    guest_ip: Ipv4Addr,
    guest_port: u16,
}

/// Routes inbound TCP connections to the correct worker's smoltcp proxy.
///
/// When a worker process calls `listen(port)`, it registers a channel sender
/// in the port router. When the main proxy accepts an inbound connection for
/// that port, it sends the host `TcpStream` (with the guest port) through the
/// channel to the worker, which creates an inbound bridge on its own smoltcp.
///
/// Thread-safe: shared between the main proxy and all worker proxy threads.
pub struct PortRouter {
    /// Port → (worker_id, sender) for forwarding accepted TCP streams.
    /// The worker_id tracks ownership so that cleanup only removes
    /// routes belonging to the dying worker, not routes re-registered
    /// by a different (still-alive) worker.
    routes: std::sync::Mutex<HashMap<u16, (u64, std::sync::mpsc::Sender<RoutedStream>)>>,
    next_worker_id: std::sync::atomic::AtomicU64,
}

/// A TCP stream routed from the main proxy to a worker proxy.
pub struct RoutedStream {
    pub stream: std::net::TcpStream,
    pub guest_ip: Ipv4Addr,
    pub guest_port: u16,
    pub broker_tcp_conn_handle: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferListenRouteOutcome {
    Transferred,
    AlreadyOwnedByTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferListenRouteError {
    PortNotRegistered,
    SourceNotOwner { actual_owner: u64 },
}

fn broker_tcp_conn_accept_enabled() -> bool {
    std::env::var("LITEBOX_BROKER_TCP_CONN")
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn broker_tcp_conn_source_port(handle: u64) -> Option<u16> {
    let port = u16::try_from(handle).ok()?;
    (port > 0).then_some(port)
}

fn make_routed_stream(
    stream: std::net::TcpStream,
    guest_ip: Ipv4Addr,
    guest_port: u16,
    state_registry: Option<&BrokerStateRegistry>,
) -> RoutedStream {
    if broker_tcp_conn_accept_enabled()
        && let Some(registry) = state_registry
        && let Ok(state_stream) = stream.try_clone()
    {
        let handle = u64::from(alloc_inbound_src_port());
        if let Ok((dummy_peer, dummy_worker_end)) = create_tcp_pair() {
            let state = TcpConnState::new(state_stream);
            if registry.register_with_id(handle, state).is_ok() {
                let _ = dummy_peer.set_nonblocking(true);
                std::mem::forget(dummy_peer);
                return RoutedStream {
                    stream: dummy_worker_end,
                    guest_ip,
                    guest_port,
                    broker_tcp_conn_handle: Some(handle),
                };
            }
        }
    }

    RoutedStream {
        stream,
        guest_ip,
        guest_port,
        broker_tcp_conn_handle: None,
    }
}

impl Default for PortRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl PortRouter {
    pub fn new() -> Self {
        Self {
            routes: std::sync::Mutex::new(HashMap::new()),
            next_worker_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Allocate a unique worker ID for ownership tracking.
    pub fn alloc_worker_id(&self) -> u64 {
        self.next_worker_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Check if any worker has registered for this port.
    pub fn has_route(&self, port: u16) -> bool {
        self.routes.lock().unwrap().contains_key(&port)
    }

    /// Register a worker's interest in receiving inbound connections on `port`.
    pub fn register(
        &self,
        port: u16,
        worker_id: u64,
        sender: std::sync::mpsc::Sender<RoutedStream>,
    ) {
        let mut routes = self.routes.lock().unwrap();
        if routes.contains_key(&port) {
            warn!("port {port} already registered, overwriting");
        }
        info!("port router: registered port {port} (worker {worker_id})");
        routes.insert(port, (worker_id, sender));
    }

    /// Unregister a port (e.g., when the worker stops listening).
    pub fn unregister(&self, port: u16) {
        let mut routes = self.routes.lock().unwrap();
        if routes.remove(&port).is_some() {
            info!("port router: unregistered port {port}");
        }
    }

    /// Unregister a port only if it is still owned by `worker_id`.
    /// Fork children inherit listen sockets and may re-register the
    /// same port. When the child dies, this prevents removing the
    /// parent's (or another worker's) registration.
    pub fn unregister_if_owner(&self, port: u16, worker_id: u64) {
        let mut routes = self.routes.lock().unwrap();
        if let Some(&(owner, _)) = routes.get(&port) {
            if owner == worker_id {
                routes.remove(&port);
                info!("port router: unregistered port {port} (worker {worker_id})");
            } else {
                info!(
                    "port router: skipping unregister of port {port} \
                     (owned by worker {owner}, not {worker_id})"
                );
            }
        }
    }

    /// Transfer a TCP listen route from one worker proxy to another.
    pub fn transfer_listen_route(
        &self,
        port: u16,
        from_worker_id: u64,
        to_worker_id: u64,
        to_sender: std::sync::mpsc::Sender<RoutedStream>,
    ) -> Result<TransferListenRouteOutcome, TransferListenRouteError> {
        let mut routes = self.routes.lock().unwrap();
        let Some((owner, sender)) = routes.get_mut(&port) else {
            return Err(TransferListenRouteError::PortNotRegistered);
        };

        if *owner == to_worker_id {
            return Ok(TransferListenRouteOutcome::AlreadyOwnedByTarget);
        }
        if *owner != from_worker_id {
            return Err(TransferListenRouteError::SourceNotOwner {
                actual_owner: *owner,
            });
        }

        *owner = to_worker_id;
        *sender = to_sender;
        info!(
            "port router: transferred port {port} from worker {from_worker_id} to worker {to_worker_id}"
        );
        Ok(TransferListenRouteOutcome::Transferred)
    }

    /// Transfer a TCP listen route to `to_worker_id`, inferring the source from
    /// the current route owner.
    pub fn transfer_listen_route_from_current(
        &self,
        port: u16,
        to_worker_id: u64,
        to_sender: std::sync::mpsc::Sender<RoutedStream>,
    ) -> Result<TransferListenRouteOutcome, TransferListenRouteError> {
        let mut routes = self.routes.lock().unwrap();
        let Some((owner, sender)) = routes.get_mut(&port) else {
            return Err(TransferListenRouteError::PortNotRegistered);
        };

        if *owner == to_worker_id {
            return Ok(TransferListenRouteOutcome::AlreadyOwnedByTarget);
        }

        let from_worker_id = *owner;
        *owner = to_worker_id;
        *sender = to_sender;
        info!(
            "port router: transferred port {port} from worker {from_worker_id} to worker {to_worker_id}"
        );
        Ok(TransferListenRouteOutcome::Transferred)
    }

    /// Try to route an accepted TCP stream to the worker that owns `guest_port`.
    /// Returns `Some(stream)` if no worker is registered (caller should handle it).
    pub fn try_route(
        &self,
        guest_port: u16,
        guest_ip: Ipv4Addr,
        stream: std::net::TcpStream,
        state_registry: Option<&BrokerStateRegistry>,
    ) -> Option<std::net::TcpStream> {
        let routes = self.routes.lock().unwrap();
        if let Some((_, sender)) = routes.get(&guest_port) {
            let routed = make_routed_stream(stream, guest_ip, guest_port, state_registry);
            match sender.send(routed) {
                Ok(()) => {
                    debug!("port router: forwarded connection to worker on port {guest_port}");
                    None // consumed
                }
                Err(e) => {
                    warn!("port router: worker channel closed for port {guest_port}");
                    if let Some(handle) = e.0.broker_tcp_conn_handle
                        && let Some(registry) = state_registry
                    {
                        let _ =
                            registry.release(crate::state_registry::StateHandle::from_id(handle));
                        None
                    } else {
                        Some(e.0.stream)
                    }
                }
            }
        } else {
            Some(stream) // no worker registered, caller handles
        }
    }
}

/// Parse a port-forward spec: "HOST_PORT:GUEST_IP:GUEST_PORT"
pub fn parse_forward_spec(spec: &str) -> Option<(u16, Ipv4Addr, u16)> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.len() != 3 {
        return None;
    }
    let host_port: u16 = parts[0].parse().ok()?;
    let guest_ip: Ipv4Addr = parts[1].parse().ok()?;
    let guest_port: u16 = parts[2].parse().ok()?;
    Some((host_port, guest_ip, guest_port))
}

/// Timeout for non-blocking host TCP connect.
const HOST_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

struct LbnpSessionPermit {
    session_slots: Arc<AtomicUsize>,
}

impl Drop for LbnpSessionPermit {
    fn drop(&mut self) {
        self.session_slots.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_lbnp_session_permit(session_slots: &Arc<AtomicUsize>) -> Option<LbnpSessionPermit> {
    loop {
        let active = session_slots.load(Ordering::Acquire);
        if active >= MAX_ADDITIONAL_LBNP_SESSIONS {
            return None;
        }
        if session_slots
            .compare_exchange_weak(active, active + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(LbnpSessionPermit {
                session_slots: Arc::clone(session_slots),
            });
        }
    }
}

/// Extract the raw socket descriptor from any std socket type.
fn raw_socket<T: AsRawSock>(socket: &T) -> RawSock {
    socket.as_raw_sock()
}

/// Key for a UDP flow: (src_ip, src_port, dst_ip, dst_port).
type UdpFlowKey = ([u8; 4], u16, [u8; 4], u16);

/// State for a UDP flow (guest↔host datagram relay, bypassing smoltcp).
struct UdpFlow {
    /// Host-side UDP socket bound to an ephemeral port.
    host_socket: UdpSocket,
    /// Guest source IP (for constructing reply packets).
    guest_src_ip: [u8; 4],
    /// Guest source port.
    guest_src_port: u16,
    /// Destination IP the guest was sending to.
    dest_ip: [u8; 4],
    /// Destination port.
    dest_port: u16,
    /// Last activity timestamp for GC.
    last_activity: Instant,
}

// ---------------------------------------------------------------------------
// SCM_RIGHTS fd receiving (Unix only)
// ---------------------------------------------------------------------------

/// Receive two file descriptors from an IPC stream via `SCM_RIGHTS`.
///
/// The runner sends the shared-memory ring buffer fds immediately after the
/// `LB9P` magic bytes. This function performs a blocking `recvmsg` to receive
/// a single dummy byte plus the ancillary `SCM_RIGHTS` message carrying two
/// file descriptors (tx_fd, rx_fd from the creator's perspective).
#[cfg(unix)]
fn recv_ring_fds(
    stream: &IpcStream,
) -> Result<(std::os::unix::io::OwnedFd, std::os::unix::io::OwnedFd), std::io::Error> {
    use std::os::unix::io::FromRawFd;

    // Control message buffer: large enough for SCM_RIGHTS with 2 fds.
    // Use a union to guarantee the buffer is aligned for `cmsghdr`.
    // `CMSG_FIRSTHDR` / `CMSG_NXTHDR` return `*mut cmsghdr` pointing into
    // this buffer, so it must satisfy `cmsghdr`'s alignment requirement.
    #[allow(clippy::cast_possible_truncation)] // 2 * 4 = 8 always fits u32
    const CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE((2 * size_of::<i32>()) as u32) as usize };
    #[repr(C)]
    union CmsgBuf {
        _align: libc::cmsghdr,
        buf: [u8; CMSG_SPACE],
    }

    let raw_fd = stream.raw();

    // Make the socket blocking with a receive timeout for the fd-receive step.
    // A timeout prevents this recvmsg from blocking the event loop indefinitely
    // if the runner stalls after sending the marker byte.
    // SAFETY: `raw_fd` is a valid open file descriptor.
    unsafe {
        let flags = libc::fcntl(raw_fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(raw_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        libc::setsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Buffer for the dummy data byte.
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr().cast(),
        iov_len: 1,
    };

    let mut cmsg_buf = CmsgBuf {
        buf: [0u8; CMSG_SPACE],
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: accessing the `buf` field of a zero-initialised union is safe.
    msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
    #[allow(clippy::cast_possible_truncation)]
    {
        msg.msg_controllen = CMSG_SPACE as _;
    }

    // SAFETY: `raw_fd` is a valid socket, `msg` points to properly initialised
    // buffers, and the control-message buffer is large enough for 2 fds.
    let n = unsafe { libc::recvmsg(raw_fd, &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed before ring fds received",
        ));
    }
    if n != 1 || dummy[0] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected LB9P transport marker",
        ));
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SCM_RIGHTS control data was truncated",
        ));
    }

    // Walk the control messages looking for SCM_RIGHTS.
    // SAFETY: `msg` was filled by a successful `recvmsg`; iterating with
    // `CMSG_FIRSTHDR`/`CMSG_NXTHDR` is the standard way to walk ancillary
    // data.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` is a valid pointer returned by CMSG_FIRSTHDR/CMSG_NXTHDR.
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
            // SAFETY: the kernel placed the fd array right after the cmsghdr.
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
            let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
            if (hdr.cmsg_len as usize) < header_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed SCM_RIGHTS message",
                ));
            }
            let fd_count = ((hdr.cmsg_len as usize) - header_len) / size_of::<i32>();
            if fd_count != 2 {
                for i in 0..fd_count {
                    // SAFETY: `data_ptr` points to `fd_count` consecutive `i32`
                    // values written by the kernel for this SCM_RIGHTS message.
                    let leaked_fd =
                        unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>().add(i)) };
                    // SAFETY: these fds were opened in this process by recvmsg;
                    // close any unexpected extras before returning an error.
                    unsafe {
                        libc::close(leaked_fd);
                    }
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("expected exactly 2 fds in SCM_RIGHTS, got {fd_count}"),
                ));
            }
            // SAFETY: `data_ptr` points to at least 2 consecutive `i32` values
            // written by the kernel.
            let tx_raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>()) };
            let rx_raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>().add(1)) };
            // SAFETY: these are valid open fds received via SCM_RIGHTS.
            let tx_fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(tx_raw) };
            let rx_fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(rx_raw) };
            return Ok((tx_fd, rx_fd));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&raw const msg, cmsg) };
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "no SCM_RIGHTS message received with ring fds",
    ))
}

#[cfg(any(unix, windows))]
const LB9P_RING_ACK: u8 = b'K';

#[cfg(unix)]
const LB9P_RING_MARKER: u8 = 0;

#[cfg(windows)]
const LB9P_RING_MARKER: u8 = litebox_common_windows::shmem_ring::TRANSPORT_MARKER;

#[cfg(windows)]
fn recv_ring_connection_info(
    stream: &mut IpcStream,
) -> Result<litebox_common_windows::shmem_ring::RingConnectionInfo, std::io::Error> {
    use std::io::Read as _;

    stream.set_nonblocking(false)?;
    let mut payload = [0u8; 1 + litebox_common_windows::shmem_ring::CONNECTION_INFO_SIZE];
    let deadline = Instant::now() + LB9P_RING_UPGRADE_TIMEOUT;
    let mut got = 0usize;
    while got < payload.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out receiving Windows ring metadata",
            ));
        }

        let timeout = if remaining < Duration::from_millis(1) {
            Duration::from_millis(1)
        } else {
            remaining
        };
        stream.set_read_timeout(Some(timeout))?;

        match stream.read(&mut payload[got..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before Windows ring metadata was complete",
                ));
            }
            Ok(n) => got += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }

    if payload[0] != LB9P_RING_MARKER {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected LB9P transport marker",
        ));
    }

    let info_bytes: &[u8; litebox_common_windows::shmem_ring::CONNECTION_INFO_SIZE] = payload[1..]
        .try_into()
        .expect("fixed-size ring metadata payload");
    litebox_common_windows::shmem_ring::RingConnectionInfo::decode(info_bytes).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid Windows ring metadata: {err}"),
        )
    })
}

#[cfg(any(unix, windows))]
fn ack_ring_connection(stream: &mut IpcStream) {
    stream.set_nonblocking(false).ok();
    use std::io::Write as _;
    let _ = stream.write_all(&[LB9P_RING_ACK]);
}

#[cfg(unix)]
fn handle_shared_memory_lb9p_connection(stream: &mut IpcStream, ring_spawner: RingServiceSpawner) {
    match recv_ring_fds(stream) {
        Ok((tx_fd, rx_fd)) => {
            match litebox_common_linux::shmem_ring::ShmemRingPair::open(tx_fd, rx_fd) {
                Ok((writer, reader)) => {
                    ack_ring_connection(stream);
                    ring_spawner(writer, reader);
                    info!("direct 9P channel connected (shared memory)");
                }
                Err(e) => {
                    warn!("failed to open ring pair: {e}");
                }
            }
        }
        Err(e) => {
            warn!("failed to receive ring fds: {e}");
        }
    }
}

#[cfg(windows)]
fn handle_shared_memory_lb9p_connection(stream: &mut IpcStream, ring_spawner: RingServiceSpawner) {
    match recv_ring_connection_info(stream) {
        Ok(info) => match litebox_common_windows::shmem_ring::ShmemRingPair::open(&info) {
            Ok((writer, reader)) => {
                ack_ring_connection(stream);
                ring_spawner(writer, reader);
                info!("direct 9P channel connected (shared memory)");
            }
            Err(e) => {
                warn!("failed to open Windows ring pair: {e}");
            }
        },
        Err(e) => {
            warn!("failed to receive Windows ring metadata: {e}");
        }
    }
}

#[cfg(any(unix, windows))]
struct RingUpgradePermit;

#[cfg(any(unix, windows))]
impl RingUpgradePermit {
    fn acquire() -> Option<Self> {
        loop {
            let current = ACTIVE_LB9P_RING_UPGRADES.load(Ordering::Acquire);
            if current >= MAX_CONCURRENT_LB9P_RING_UPGRADES {
                return None;
            }
            if ACTIVE_LB9P_RING_UPGRADES
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(Self);
            }
        }
    }
}

#[cfg(any(unix, windows))]
impl Drop for RingUpgradePermit {
    fn drop(&mut self) {
        ACTIVE_LB9P_RING_UPGRADES.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(any(unix, windows))]
fn spawn_shared_memory_lb9p_connection(stream: IpcStream, ring_spawner: RingServiceSpawner) {
    let Some(permit) = RingUpgradePermit::acquire() else {
        warn!("dropping LB9P ring upgrade connection: too many concurrent background upgrades");
        return;
    };

    if let Err(e) = std::thread::Builder::new()
        .name("lb9p-ring-upgrade".into())
        .spawn(move || {
            let _permit = permit;
            let mut stream = stream;
            handle_shared_memory_lb9p_connection(&mut stream, ring_spawner);
        })
    {
        warn!("failed to spawn LB9P ring upgrade thread: {e}");
    }
}

// ---------------------------------------------------------------------------
// Local service registry — broker-internal services on BROKER_IP
// ---------------------------------------------------------------------------

/// Factory that spawns a service handler on a bidirectional byte stream.
///
/// The handler runs in a separate thread. The returned `JoinHandle` is kept
/// so the proxy can detect service exit.
pub type ServiceSpawner =
    Box<dyn Fn(std::net::TcpStream) -> std::thread::JoinHandle<()> + Send + Sync>;

/// Factory that spawns a service handler on a shared-memory ring buffer pair.
///
/// Used for direct IPC connections (LB9P handshake) where the runner upgrades
/// the control stream to a platform-specific shared-memory transport. The
/// handler runs in a separate thread.
#[cfg(any(unix, windows))]
pub type RingServiceSpawner = std::sync::Arc<
    dyn Fn(
            crate::nine_p::transport::ShmemRingWriter,
            crate::nine_p::transport::ShmemRingReader,
        ) -> std::thread::JoinHandle<()>
        + Send
        + Sync,
>;

/// Registry of broker-internal services keyed by TCP port.
///
/// When a guest connects to `BROKER_IP:<port>`, the proxy looks up this
/// registry. If a service is registered, the connection is handled
/// in-process via a loopback TCP pair instead of opening a host TCP socket.
///
/// On Unix and Windows, services may also be registered with a ring spawner
/// for direct shared-memory IPC via the `LB9P` handshake path.
pub struct LocalServiceRegistry {
    services: HashMap<u16, ServiceSpawner>,
    #[cfg(any(unix, windows))]
    ring_services: HashMap<u16, RingServiceSpawner>,
}

impl Default for LocalServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalServiceRegistry {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            #[cfg(any(unix, windows))]
            ring_services: HashMap::new(),
        }
    }

    /// Register a service on the given port. The `spawner` is called with one
    /// end of a loopback TCP pair; the other end is relayed to the smoltcp TCP
    /// socket.
    pub fn register(&mut self, port: u16, spawner: ServiceSpawner) {
        self.services.insert(port, spawner);
    }

    /// Register a shared-memory ring spawner for the given port.
    ///
    /// When a direct IPC connection (LB9P) arrives, the proxy receives
    /// platform-specific ring metadata and calls this spawner with the
    /// resulting ring writer/reader pair.
    #[cfg(any(unix, windows))]
    pub fn register_ring(&mut self, port: u16, spawner: RingServiceSpawner) {
        self.ring_services.insert(port, spawner);
    }

    fn get(&self, port: u16) -> Option<&ServiceSpawner> {
        self.services.get(&port)
    }

    #[cfg(any(unix, windows))]
    fn get_ring(&self, port: u16) -> Option<RingServiceSpawner> {
        self.ring_services.get(&port).cloned()
    }
}

/// State for a TCP bridge to a broker-internal (local) service.
/// Analogous to `TcpBridge` but the "host side" is a loopback TCP stream
/// connected to an in-process service thread.
struct LocalBridge {
    smoltcp_handle: SocketHandle,
    /// Our end of the loopback pair — the service thread owns the other end.
    stream: std::net::TcpStream,
    dest_port: u16,
    host_eof: bool,
    _thread: std::thread::JoinHandle<()>,
}

/// Run the network proxy event loop.
///
/// `ipc_fd` is one end of an IPC stream connected to the runner.
/// This function takes ownership and runs until the IPC connection closes.
///
/// If `magic_prefix` is `Some`, the caller (e.g. [`accept_ipc_client`]) has
/// already read and validated the 4-byte `LBNP` magic from the fd.  The
/// handshake then only reads the remaining 4 bytes (version + MTU).
///
/// If `local_services` is provided, connections to `BROKER_IP:<port>` are
/// handled in-process by the registered service instead of proxied to the host.
///
/// If `accept_listener` is provided, the event loop also accepts new IPC
/// connections on it. Additional `LBNP` clients are handed off to their own
/// proxy sessions, while a connection sending `LB9P` magic is dispatched to the
/// first registered local service (port 5640 / 9P) as a direct byte-stream
/// channel, bypassing smoltcp entirely.
///
/// If `handshake_done` is true, the caller (e.g. [`accept_ipc_client`]) has
/// already completed the full LBNP handshake on the fd.
pub fn run(
    ipc_fd: IpcStream,
    handshake_done: bool,
    local_services: Option<LocalServiceRegistry>,
    accept_listener: Option<&IpcListener>,
    sandbox_policy: Option<Arc<SandboxPolicy>>,
    audit_log: Option<AuditLog>,
    inbound_forwards: Vec<(u16, Ipv4Addr, u16)>,
    state_registry: Option<Arc<BrokerStateRegistry>>,
) -> Result<(), Box<dyn std::error::Error>> {
    run_with_session_slots(
        ipc_fd,
        handshake_done,
        local_services,
        accept_listener,
        Arc::new(AtomicUsize::new(0)),
        sandbox_policy,
        audit_log,
        inbound_forwards,
        state_registry,
    )
}

pub fn run_with_session_slots(
    ipc_fd: IpcStream,
    handshake_done: bool,
    local_services: Option<LocalServiceRegistry>,
    accept_listener: Option<&IpcListener>,
    session_slots: Arc<AtomicUsize>,
    sandbox_policy: Option<Arc<SandboxPolicy>>,
    audit_log: Option<AuditLog>,
    inbound_forwards: Vec<(u16, Ipv4Addr, u16)>,
    state_registry: Option<Arc<BrokerStateRegistry>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let port_router = Arc::new(PortRouter::new());
    let (init_routed_tx, init_routed_rx) = std::sync::mpsc::channel::<RoutedStream>();
    run_inner(
        ipc_fd,
        handshake_done,
        Arc::new(local_services.unwrap_or_default()),
        accept_listener,
        session_slots,
        sandbox_policy,
        audit_log,
        inbound_forwards,
        port_router,
        state_registry,
        Some(init_routed_rx),
        Some(init_routed_tx),
    )
}

fn run_inner(
    ipc_fd: IpcStream,
    handshake_done: bool,
    local_services: Arc<LocalServiceRegistry>,
    accept_listener: Option<&IpcListener>,
    session_slots: Arc<AtomicUsize>,
    sandbox_policy: Option<Arc<SandboxPolicy>>,
    audit_log: Option<AuditLog>,
    inbound_forwards: Vec<(u16, Ipv4Addr, u16)>,
    port_router: Arc<PortRouter>,
    state_registry: Option<Arc<BrokerStateRegistry>>,
    // Receiver for inbound TCP streams routed to this proxy by the port router.
    inbound_routed_rx: Option<std::sync::mpsc::Receiver<RoutedStream>>,
    // Sender for this proxy's inbound channel — registered with port_router
    // when the guest sends a port-listen control message.
    inbound_routed_tx: Option<std::sync::mpsc::Sender<RoutedStream>>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("network proxy starting");

    if !handshake_done {
        perform_handshake(&ipc_fd)?;
        info!("IPC handshake complete");
    }

    // Set non-blocking after handshake so send_ipc_frame() doesn't stall
    // the event loop when the socket buffer fills.
    ipc_fd.set_nonblocking(true).ok();

    let mut device = IpcDevice::new(ipc_fd);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, smoltcp::time::Instant::ZERO);

    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(BROKER_IP), 24))
            .unwrap();
    });
    // Default route through ourselves (BROKER_IP). smoltcp's AnyIP check
    // requires that the route gateway is one of our own addresses — otherwise
    // packets to arbitrary Internet IPs are rejected.
    iface
        .routes_mut()
        .add_default_ipv4_route(BROKER_IP)
        .unwrap();
    iface.set_any_ip(true);

    let mut sockets = SocketSet::new(vec![]);
    let zero_time = Instant::now();

    let mut tcp_bridges: Vec<TcpBridge> = Vec::new();
    let mut local_bridges: Vec<LocalBridge> = Vec::new();
    let mut pending_connects: Vec<PendingConnect> = Vec::new();
    // Host streams that connected but await smoltcp handshake completion,
    // keyed by the full 4-tuple so parallel connections to the same server work.
    let mut ready_host_streams: HashMap<TcpFlowKey, (std::net::TcpStream, Instant)> =
        HashMap::new();
    let mut listen_sockets: HashMap<(Ipv4Addr, u16), SocketHandle> = HashMap::new();
    // Sockets that accepted a SYN (no longer in Listen state) but haven't
    // been promoted to TcpBridge yet. Tracked separately so
    // `ensure_listen_socket` can create a replacement listener while the
    // original socket completes the handshake.
    let mut accepting_sockets: Vec<(SocketHandle, Ipv4Addr, u16)> = Vec::new();
    // UDP flows keyed by (src_ip, src_port, dst_ip, dst_port).
    let mut udp_flows: HashMap<UdpFlowKey, UdpFlow> = HashMap::new();
    // DNS tracker for hostname-based network policy enforcement.
    let mut dns_tracker = dns_tracker::DnsTracker::new();

    // Inbound TCP port forwards: host listeners that relay to guest ports.
    let mut inbound_listeners: Vec<InboundForward> = Vec::new();

    for (host_port, guest_ip, guest_port) in &inbound_forwards {
        match std::net::TcpListener::bind(format!("0.0.0.0:{host_port}")) {
            Ok(listener) => {
                listener.set_nonblocking(true).ok();
                info!("inbound TCP forward: host:{host_port} → {guest_ip}:{guest_port}");
                inbound_listeners.push(InboundForward {
                    listener,
                    guest_ip: *guest_ip,
                    guest_port: *guest_port,
                });
            }
            Err(e) => {
                error!("failed to bind inbound forward on port {host_port}: {e}");
            }
        }
    }
    // Host DNS resolver for forwarding guest DNS queries.
    let host_dns = discover_host_dns();
    // Pending LB9P handshakes — drained non-blocking each loop iteration.
    let mut pending_handshakes: Vec<PendingHandshake> = Vec::new();
    // Ports registered by this proxy in the port router (for cleanup on exit).
    let mut registered_ports: Vec<u16> = Vec::new();
    let worker_id = port_router.alloc_worker_id();

    info!("network proxy ready, entering event loop");

    loop {
        let smoltcp_now = smoltcp::time::Instant::from_millis(
            i64::try_from(zero_time.elapsed().as_millis()).unwrap_or(i64::MAX),
        );

        // Step 1: Stage-receive a packet from IPC.
        if device.stage_recv().is_err() {
            error!("IPC protocol error: closing connection");
            device.send_shutdown();
            break;
        }

        // Step 1b: Check for port-listen control messages.
        // Workers send these when they call listen(port) to register
        // their interest in receiving inbound connections.
        if let Some((port, action)) = device.take_port_listen_msg() {
            match action {
                device::PortListenAction::Listen => {
                    if let Some(ref tx) = inbound_routed_tx {
                        port_router.register(port, worker_id, tx.clone());
                        registered_ports.push(port);
                        info!("worker registered listen on port {port}");
                        // File-based diagnostic
                        use std::io::Write;
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("/tmp/rst-diag.log")
                        {
                            let _ = writeln!(
                                f,
                                "BROKER PORT REGISTER: port={port} worker_id={worker_id}"
                            );
                        }
                    } else {
                        // Init proxy received a listen notification — register
                        // but no routing needed (init handles its own inbound).
                        info!("init proxy listen on port {port} (local)");
                        use std::io::Write;
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("/tmp/rst-diag.log")
                        {
                            let _ = writeln!(f, "BROKER PORT REGISTER (init, local): port={port}");
                        }
                    }
                }
                device::PortListenAction::Unlisten => {
                    port_router.unregister(port);
                    registered_ports.retain(|p| *p != port);
                    info!("unregistered listen on port {port}");
                }
                device::PortListenAction::Transfer => {
                    if let Some(ref tx) = inbound_routed_tx {
                        match port_router.transfer_listen_route_from_current(
                            port,
                            worker_id,
                            tx.clone(),
                        ) {
                            Ok(TransferListenRouteOutcome::Transferred) => {
                                if !registered_ports.contains(&port) {
                                    registered_ports.push(port);
                                }
                                info!("worker transferred listen route for port {port}");
                            }
                            Ok(TransferListenRouteOutcome::AlreadyOwnedByTarget) => {
                                if !registered_ports.contains(&port) {
                                    registered_ports.push(port);
                                }
                                info!("listen route for port {port} already owned by worker");
                            }
                            Err(err) => {
                                warn!("failed to transfer listen route for port {port}: {err:?}");
                            }
                        }
                    } else {
                        warn!("init proxy cannot transfer listen route for port {port}");
                    }
                }
            }
        }

        // Step 2: Resolve pending host connects BEFORE SYN dispatch.
        // This way, connects that complete quickly (localhost, fast LAN) create
        // their listen sockets before we decide whether to drop the current SYN.
        resolve_pending_connects(&mut pending_connects, &mut ready_host_streams);

        // Step 3: Peek at the staged packet and dispatch.
        let mut suppress_from_smoltcp = false;
        if let Some(len) = device.rx_len {
            let packet = &device.rx_buf[..len];

            // Diagnostic: detect RST packets and log all TCP packets with port 63084.
            if let Some((src_port, dst_port, flags)) = device::parse_tcp_flags(packet) {
                if flags & 0x04 != 0 {
                    warn!(
                        "RST packet received (worker {worker_id}): src_port={src_port} dst_port={dst_port} flags=0x{flags:02x}"
                    );
                }
                // Log ALL TCP packets involving the VS Code port for debugging.
                if src_port == 63084 || dst_port == 63084 {
                    let src_ip = &packet[12..16];
                    let dst_ip = &packet[16..20];
                    info!(
                        "TCP pkt rx (worker {worker_id}): {}.{}.{}.{}:{} → {}.{}.{}.{}:{} flags=0x{flags:02x}",
                        src_ip[0],
                        src_ip[1],
                        src_ip[2],
                        src_ip[3],
                        src_port,
                        dst_ip[0],
                        dst_ip[1],
                        dst_ip[2],
                        dst_ip[3],
                        dst_port,
                    );
                }
            }

            // TCP SYN dispatch.
            if let Some((src_ip, src_port, dst_ip, dst_port)) = device::parse_tcp_syn(packet) {
                let dest_ipv4 = Ipv4Addr::from(dst_ip);
                let flow_key = (src_ip, src_port, dst_ip, dst_port);

                if dest_ipv4 == BROKER_IPV4 && local_services.get(dst_port).is_some() {
                    // Local service — no host connect needed. Create a listen
                    // socket immediately and let the SYN through to smoltcp.
                    ensure_listen_socket(
                        &mut sockets,
                        &mut listen_sockets,
                        &mut accepting_sockets,
                        dest_ipv4,
                        dst_port,
                    );
                    // Let SYN through (suppress_from_smoltcp stays false).
                } else if pending_connects.iter().any(|pc| pc.flow_key == flow_key) {
                    // Host connect still in progress — drop SYN, guest retransmits.
                    suppress_from_smoltcp = true;
                } else if ready_host_streams.contains_key(&flow_key) {
                    // Host connected. Ensure a listen socket exists (a prior
                    // parallel flow may have consumed the previous one).
                    ensure_listen_socket(
                        &mut sockets,
                        &mut listen_sockets,
                        &mut accepting_sockets,
                        dest_ipv4,
                        dst_port,
                    );
                    // Let SYN through to smoltcp.
                } else if dest_ipv4 == BROKER_IPV4
                    || dest_ipv4 == Ipv4Addr::LOCALHOST
                    || dest_ipv4 == Ipv4Addr::new(10, 0, 0, 2)
                {
                    // Connection to BROKER_IP, localhost, or the guest's own
                    // IP — check if a worker registered a listen on this port
                    // via port_router (cross-worker loopback).
                    let routed_to_worker = port_router.has_route(dst_port);

                    if routed_to_worker {
                        // Cross-worker loopback: create a TCP pair.
                        // One end stays here (as a ready host stream for
                        // promote_established), the other end is routed
                        // to the target worker.
                        match create_tcp_pair() {
                            Ok((local_end, remote_end)) => {
                                // The target worker's smoltcp connects to its
                                // guest (10.0.0.2), not to the broker IP.
                                let guest_ip = Ipv4Addr::new(10, 0, 0, 2);
                                if port_router
                                    .try_route(
                                        dst_port,
                                        guest_ip,
                                        remote_end,
                                        state_registry.as_deref(),
                                    )
                                    .is_some()
                                {
                                    warn!("port_router rejected routed stream for port {dst_port}");
                                    suppress_from_smoltcp = true;
                                } else {
                                    local_end.set_nonblocking(true).ok();
                                    ready_host_streams
                                        .insert(flow_key, (local_end, Instant::now()));
                                    ensure_listen_socket(
                                        &mut sockets,
                                        &mut listen_sockets,
                                        &mut accepting_sockets,
                                        dest_ipv4,
                                        dst_port,
                                    );
                                    debug!(
                                        "cross-worker loopback: SYN {src_ip:?}:{src_port} → BROKER:{dst_port}, TCP pair created"
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("failed to create TCP pair for cross-worker loopback: {e}");
                                suppress_from_smoltcp = true;
                            }
                        }
                    } else if local_services.get(dst_port).is_some() {
                        // Local service — create listen socket, let SYN through.
                        ensure_listen_socket(
                            &mut sockets,
                            &mut listen_sockets,
                            &mut accepting_sockets,
                            dest_ipv4,
                            dst_port,
                        );
                    } else {
                        // No service, no worker — drop SYN.
                        debug!("no local service or worker on port {dst_port}, dropping SYN");
                        suppress_from_smoltcp = true;
                    }
                } else {
                    // New flow to external host.
                    // Check network policy before connecting.
                    if let Some(ref policy) = sandbox_policy {
                        let hostname = dns_tracker.lookup(dest_ipv4);
                        let decision = policy.check_connect(dest_ipv4, dst_port, hostname);
                        if decision == crate::sandbox_policy::Decision::Deny {
                            let hostname_info =
                                hostname.map(|h| format!(" ({h})")).unwrap_or_default();
                            info!("policy denied TCP to {dest_ipv4}:{dst_port}{hostname_info}");
                            if let Some(ref al) = audit_log {
                                al.tcp_denied(hostname, dest_ipv4, dst_port);
                            }
                            suppress_from_smoltcp = true;
                        }
                    }
                    if !suppress_from_smoltcp {
                        // Policy allowed (or no policy). Log the allowed connection.
                        if let Some(ref al) = audit_log {
                            let hostname = dns_tracker.lookup(dest_ipv4);
                            al.tcp_allowed(hostname, dest_ipv4, dst_port);
                        }
                        // Start non-blocking host connect.
                        let total_flows = pending_connects.len()
                            + ready_host_streams.len()
                            + accepting_sockets.len()
                            + tcp_bridges.len()
                            + local_bridges.len();
                        let dest = SocketAddr::V4(SocketAddrV4::new(dest_ipv4, dst_port));
                        if total_flows >= MAX_CONNECTIONS {
                            warn!("connection limit reached, dropping SYN to {dest}");
                            suppress_from_smoltcp = true;
                        } else {
                            match start_nonblocking_connect(&dest) {
                                Ok(stream) => {
                                    debug!(
                                        "SYN {src_ip:?}:{src_port} → {dest}, async host connect"
                                    );
                                    pending_connects.push(PendingConnect {
                                        flow_key,
                                        dest,
                                        stream,
                                        started: Instant::now(),
                                    });
                                    // Immediately try to resolve (handles localhost /
                                    // already-completed connects without waiting for
                                    // a SYN retransmit).
                                    resolve_pending_connects(
                                        &mut pending_connects,
                                        &mut ready_host_streams,
                                    );
                                    if ready_host_streams.contains_key(&flow_key) {
                                        // Completed instantly — create listen socket
                                        // and let this SYN through.
                                        ensure_listen_socket(
                                            &mut sockets,
                                            &mut listen_sockets,
                                            &mut accepting_sockets,
                                            dest_ipv4,
                                            dst_port,
                                        );
                                    } else {
                                        suppress_from_smoltcp = true;
                                    }
                                }
                                Err(e) => {
                                    warn!("failed to create socket for {dest}: {e}");
                                    suppress_from_smoltcp = true;
                                }
                            }
                        }
                    }
                }
            }

            // UDP — handle at raw packet level (bypasses smoltcp).
            if let Some((src_ip, src_port, dst_ip, dst_port, payload_off, payload_len)) =
                device::parse_udp(packet)
            {
                suppress_from_smoltcp = true;
                let payload =
                    &packet[payload_off..payload_off + payload_len.min(packet.len() - payload_off)];

                // DNS query tracking — intercept outbound UDP port 53.
                if dst_port == 53 {
                    dns_tracker.process_query(payload);
                }

                // Network policy check for non-DNS UDP.
                let mut udp_blocked = false;
                if dst_port != 53
                    && let Some(ref policy) = sandbox_policy
                {
                    let dest_ipv4 = Ipv4Addr::from(dst_ip);
                    let hostname = dns_tracker.lookup(dest_ipv4);
                    if policy.check_connect(dest_ipv4, dst_port, hostname)
                        == crate::sandbox_policy::Decision::Deny
                    {
                        let hostname_info = hostname.map(|h| format!(" ({h})")).unwrap_or_default();
                        debug!(
                            "policy denied UDP to {}:{dst_port}{hostname_info}",
                            Ipv4Addr::from(dst_ip)
                        );
                        if let Some(ref al) = audit_log {
                            al.udp_denied(hostname, Ipv4Addr::from(dst_ip), dst_port);
                        }
                        udp_blocked = true;
                    }
                }
                if !udp_blocked {
                    // Rewrite DNS queries addressed to the broker IP to the
                    // host's actual DNS resolver.
                    let effective_dst_ip = if dst_port == 53 && dst_ip == BROKER_IP_BYTES {
                        host_dns.octets()
                    } else {
                        dst_ip
                    };
                    handle_udp_outbound(
                        &mut udp_flows,
                        src_ip,
                        src_port,
                        effective_dst_ip,
                        dst_port,
                        payload,
                    );
                }
            }

            // ICMP Echo Request — synthesize reply directly.
            if device::is_icmp_echo_request(packet) {
                suppress_from_smoltcp = true;
                let mut reply = vec![0u8; packet.len()];
                reply.copy_from_slice(packet);
                device::synthesize_icmp_echo_reply(&mut reply);
                device.send_framed(&reply);
                trace!("synthesized ICMP echo reply");
            }
        }

        // Step 4: Poll smoltcp for TCP processing.
        if suppress_from_smoltcp {
            device.rx_len = None;
        }

        // Diagnostic: snapshot SynSent bridges before iface.poll() so we can
        // detect transitions caused by incoming packets (e.g. RST from runner).
        let pre_poll_synsent: Vec<(usize, std::net::SocketAddr)> = tcp_bridges
            .iter()
            .enumerate()
            .filter(|(_, b)| {
                let s: &tcp::Socket = sockets.get(b.smoltcp_handle);
                s.state() == tcp::State::SynSent
            })
            .map(|(i, b)| (i, b.dest))
            .collect();

        let had_rx = device.rx_len.is_some();
        iface.poll(smoltcp_now, &mut device, &mut sockets);
        // Clear staged packet after poll — enforce single-consumption.
        device.rx_len = None;

        // Diagnostic: check if any SynSent bridges changed state during poll.
        for (i, dest) in &pre_poll_synsent {
            if let Some(bridge) = tcp_bridges.get(*i) {
                if bridge.dest == *dest {
                    let s: &tcp::Socket = sockets.get(bridge.smoltcp_handle);
                    let new_state = s.state();
                    if new_state != tcp::State::SynSent {
                        warn!(
                            "bridge[{i}] {dest} SynSent → {new_state:?} during iface.poll() (worker {worker_id}, had_rx={had_rx})"
                        );
                    }
                }
            }
        }

        // Step 5: Promote ESTABLISHED connections to TcpBridge or LocalBridge.
        // After promoting, recreate listen sockets for any remaining
        // ready_host_streams with the same destination.
        promote_established(
            &mut sockets,
            &mut listen_sockets,
            &mut accepting_sockets,
            &mut tcp_bridges,
            &mut local_bridges,
            &mut ready_host_streams,
            &local_services,
        );

        // Step 5b: Relay data on active TCP bridges (external connections).
        relay_tcp(&mut sockets, &mut tcp_bridges);

        // Step 5c: Relay data on local bridges (broker-internal services).
        relay_local(&mut sockets, &mut local_bridges);

        // Step 6: Check for UDP replies from host and send back to guest.
        relay_udp_replies(&mut udp_flows, &mut device, &mut dns_tracker, &audit_log);

        // Step 7: GC idle UDP flows.
        udp_flows.retain(|key, flow| {
            if flow.last_activity.elapsed() > UDP_IDLE_TIMEOUT {
                debug!("GC idle UDP flow {:?}", key);
                false
            } else {
                true
            }
        });

        // Step 8: GC stale ready_host_streams (guest abandoned connect).
        ready_host_streams.retain(|key, (_stream, created)| {
            if created.elapsed() > HOST_CONNECT_TIMEOUT {
                debug!("GC stale ready_host_stream {:?}", key);
                false
            } else {
                true
            }
        });

        // Also GC listen sockets whose destination has no remaining ready_host_streams.
        // Skip local service listeners — those don't use ready_host_streams.
        let stale_listeners: Vec<(Ipv4Addr, u16)> = listen_sockets
            .keys()
            .filter(|&&(ip, port)| {
                // Keep listeners for local services unconditionally.
                if ip == BROKER_IPV4 && local_services.get(port).is_some() {
                    return false;
                }
                let octets = ip.octets();
                !ready_host_streams
                    .keys()
                    .any(|&(_, _, di, dp)| di == octets && dp == port)
            })
            .copied()
            .collect();
        for key in stale_listeners {
            if let Some(handle) = listen_sockets.remove(&key) {
                let socket: &mut tcp::Socket = sockets.get_mut(handle);
                socket.abort();
                sockets.remove(handle);
                debug!("GC orphaned listen socket {:?}", key);
            }
        }

        // GC accepting_sockets that are no longer progressing (e.g., Closed
        // after timeout, or the guest abandoned the handshake).
        accepting_sockets.retain(|&(handle, dest_ip, dest_port)| {
            let socket: &tcp::Socket = sockets.get(handle);
            let state = socket.state();
            if state == tcp::State::Closed
                || state == tcp::State::TimeWait
                || state == tcp::State::CloseWait
            {
                debug!("GC stale accepting socket for {dest_ip}:{dest_port} in state {state:?}");
                let socket: &mut tcp::Socket = sockets.get_mut(handle);
                socket.abort();
                sockets.remove(handle);
                false
            } else {
                true
            }
        });

        // Step 8: Check for IPC EOF via POLLHUP (always, not just when idle).
        // Also check when state tables are empty to catch clean shutdown.
        {
            let mut probe_pfd = PollFd {
                fd: device.raw_socket(),
                events: 0, // Only check for POLLHUP/POLLERR (always reported).
                revents: 0,
            };
            sock_compat::poll_fds(std::slice::from_mut(&mut probe_pfd), 0);
            if probe_pfd.revents & (POLLHUP | POLLERR) != 0 {
                info!("IPC connection closed (POLLHUP), shutting down");
                break;
            }
        }

        // Step 8b: Accept new connections on the listener (non-blocking) and
        // queue them for handshake.  The handshake bytes are drained below with
        // zero blocking so a stray/slow client cannot stall the proxy loop.
        if let Some(listener) = accept_listener {
            match listener.accept() {
                Ok(Some(stream)) => {
                    if pending_handshakes.len() >= MAX_PENDING_ACCEPTED_HANDSHAKES {
                        warn!(
                            limit = MAX_PENDING_ACCEPTED_HANDSHAKES,
                            "too many pending accepted listener clients; dropping accepted connection"
                        );
                        drop(stream);
                    } else {
                        stream.set_nonblocking(true).ok();
                        let raw_socket = stream.raw();
                        pending_handshakes.push(PendingHandshake {
                            stream: Some(stream),
                            raw_socket,
                            handshake: [0u8; 8],
                            got: 0,
                            deadline: Instant::now() + HANDSHAKE_ACCEPT_TIMEOUT,
                        });
                    }
                }
                Ok(None) => {} // Would-block, nothing to accept.
                Err(e) => {
                    warn!("listener accept error: {e}");
                }
            }
        }

        // Drain pending handshakes: one non-blocking recv attempt per entry.
        pending_handshakes.retain_mut(|ph| {
            if Instant::now() >= ph.deadline {
                debug!(
                    "accepted connection handshake timed out ({}/8 bytes), dropping",
                    ph.got
                );
                return false;
            }

            if ph.got < 4 {
                let n = sock_compat::recv_nb(ph.raw_socket, &mut ph.handshake[ph.got..4], 0);
                if n > 0 {
                    #[allow(clippy::cast_sign_loss)]
                    {
                        ph.got += n as usize;
                    }
                } else if n == 0 {
                    debug!(
                        "accepted connection closed during handshake (got {}/4 bytes), dropping",
                        ph.got
                    );
                    return false;
                } else {
                    let err = sock_compat::last_socket_error();
                    if !sock_compat::is_would_block(err) {
                        debug!("accepted connection handshake read failed: {err}");
                        return false;
                    }
                }
            }

            if ph.got < 4 {
                return true; // keep in queue
            }

            let magic = &ph.handshake[0..4];
            if magic == HANDSHAKE_MAGIC {
                if ph.got < 8 {
                    let n = sock_compat::recv_nb(ph.raw_socket, &mut ph.handshake[ph.got..], 0);
                    if n > 0 {
                        #[allow(clippy::cast_sign_loss)]
                        {
                            ph.got += n as usize;
                        }
                    } else if n == 0 {
                        debug!(
                            "accepted LBNP connection closed during handshake (got {}/8 bytes), dropping",
                            ph.got
                        );
                        return false;
                    } else {
                        let err = sock_compat::last_socket_error();
                        if !sock_compat::is_would_block(err) {
                            debug!("accepted LBNP handshake read failed: {err}");
                            return false;
                        }
                    }
                }

                if ph.got < 8 {
                    return true;
                }

                let request = ph.handshake;
                if let Err(e) = validate_handshake_request(&request) {
                    debug!("accepted LBNP connection with invalid handshake, dropping: {e}");
                    return false;
                }

                let Some(stream) = ph.stream.take() else {
                    return false;
                };
                let local_services = Arc::clone(&local_services);
                let Some(session_permit) = try_acquire_lbnp_session_permit(&session_slots) else {
                    warn!(
                        limit = MAX_ADDITIONAL_LBNP_SESSIONS,
                        "too many concurrent additional LBNP sessions; dropping connection"
                    );
                    return false;
                };
                let session_slots = Arc::clone(&session_slots);
                let sandbox_policy = sandbox_policy.clone();
                let audit_log = audit_log.clone();
                let port_router = Arc::clone(&port_router);
                let state_registry_for_session = state_registry.clone();
                let (inbound_tx, inbound_rx) = std::sync::mpsc::channel::<RoutedStream>();
                std::thread::spawn(move || {
                    let _session_permit = session_permit;
                    if let Err(e) = send_handshake_response(&stream) {
                        warn!("failed to send accepted LBNP handshake response: {e}");
                        return;
                    }
                    info!("accepted additional LBNP client, handshake complete");
                    if let Err(e) = run_inner(stream, true, local_services, None, session_slots, sandbox_policy, audit_log, vec![], port_router, state_registry_for_session, Some(inbound_rx), Some(inbound_tx)) {
                        tracing::error!("network proxy error: {e}");
                    }
                });
                return false;
            }
            if magic == b"LB9P" {
                #[cfg(any(unix, windows))]
                {
                    if local_services.get_ring(5640).is_some() {
                        let mut marker = [0u8; 1];
                        let Some(stream) = ph.stream.as_ref() else {
                            return false;
                        };
                        match stream.peek(&mut marker) {
                            Ok(0) => return true,
                            Ok(_) => {}
                            Err(e) => {
                                warn!("failed to classify LB9P transport: {e}");
                                return false;
                            }
                        }

                        if marker[0] == LB9P_RING_MARKER {
                            let Some(stream) = ph.stream.take() else {
                                return false;
                            };
                            let Some(ring_spawner) = local_services.get_ring(5640) else {
                                warn!("LB9P ring marker received but no ring service registered");
                                return false;
                            };
                            spawn_shared_memory_lb9p_connection(stream, ring_spawner);
                            return false;
                        }
                    }
                }

                if let Some(stream) = ph.stream.take() {
                    if let Some(spawner) = local_services.get(5640) {
                        let stream = sock_compat::into_blocking_tcp_stream(stream);
                        spawner(stream);
                        info!("direct 9P channel connected");
                    } else {
                        warn!("LB9P connection but no 9P service registered");
                    }
                }
            } else {
                debug!("accepted connection with unknown handshake magic, dropping");
            }
            false // remove from queue
        });

        // Step 8c: Accept inbound TCP forwards and create smoltcp connections.
        for fwd in &inbound_listeners {
            loop {
                match fwd.listener.accept() {
                    Ok((stream, peer)) => {
                        stream.set_nonblocking(true).ok();
                        info!(
                            "inbound TCP: accepted from {peer} → {}:{}",
                            fwd.guest_ip, fwd.guest_port
                        );

                        // Check if a worker has registered for this port.
                        // If so, route the stream to the worker's proxy.
                        let stream = match port_router.try_route(
                            fwd.guest_port,
                            fwd.guest_ip,
                            stream,
                            state_registry.as_deref(),
                        ) {
                            None => continue, // routed to worker, they handle it
                            Some(s) => s,     // no worker, we handle it
                        };

                        // Create a smoltcp TCP socket that connects to the guest.
                        let tcp_rx =
                            smoltcp::socket::tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]);
                        let tcp_tx =
                            smoltcp::socket::tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]);
                        let mut tcp_socket = smoltcp::socket::tcp::Socket::new(tcp_rx, tcp_tx);
                        // Disable Nagle — the broker is a relay. Nagle + delayed ACK
                        // causes multi-second stalls on the SSH key exchange.
                        tcp_socket.set_nagle_enabled(false);
                        let handle = sockets.add(tcp_socket);

                        let src_port = alloc_inbound_src_port();

                        let sock = sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
                        let local =
                            smoltcp::wire::IpEndpoint::new(IpAddress::Ipv4(BROKER_IP), src_port);
                        let octets = fwd.guest_ip.octets();
                        let remote = smoltcp::wire::IpEndpoint::new(
                            IpAddress::Ipv4(Ipv4Address::new(
                                octets[0], octets[1], octets[2], octets[3],
                            )),
                            fwd.guest_port,
                        );
                        if let Err(e) = sock.connect(iface.context(), remote, local) {
                            error!("inbound TCP: smoltcp connect failed: {e}");
                            sockets.remove(handle);
                            continue;
                        }

                        let dest = SocketAddr::V4(SocketAddrV4::new(fwd.guest_ip, fwd.guest_port));
                        tcp_bridges.push(TcpBridge {
                            smoltcp_handle: handle,
                            host_stream: stream,
                            dest,
                            host_eof: false,
                            guest_eof: false,
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        warn!("inbound TCP accept error: {e}");
                        break;
                    }
                }
            }
        }

        // Step 8d: Receive inbound streams routed to this worker by the port router.
        if let Some(ref rx) = inbound_routed_rx {
            while let Ok(routed) = rx.try_recv() {
                info!(
                    "received routed inbound stream for {}:{}",
                    routed.guest_ip, routed.guest_port
                );
                routed.stream.set_nonblocking(true).ok();

                // Create a smoltcp TCP socket connecting to the guest.
                let tcp_rx = smoltcp::socket::tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]);
                let tcp_tx = smoltcp::socket::tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]);
                let mut tcp_socket = smoltcp::socket::tcp::Socket::new(tcp_rx, tcp_tx);
                tcp_socket.set_nagle_enabled(false);
                let handle = sockets.add(tcp_socket);

                let src_port = routed
                    .broker_tcp_conn_handle
                    .and_then(broker_tcp_conn_source_port)
                    .unwrap_or_else(alloc_inbound_src_port);

                let sock = sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
                let local = smoltcp::wire::IpEndpoint::new(IpAddress::Ipv4(BROKER_IP), src_port);
                let octets = routed.guest_ip.octets();
                let remote = smoltcp::wire::IpEndpoint::new(
                    IpAddress::Ipv4(Ipv4Address::new(octets[0], octets[1], octets[2], octets[3])),
                    routed.guest_port,
                );
                if let Err(e) = sock.connect(iface.context(), remote, local) {
                    error!("routed inbound: smoltcp connect failed: {e}");
                    sockets.remove(handle);
                    continue;
                }
                info!(
                    "routed inbound: smoltcp connect {}:{} → {}:{} state={:?}",
                    BROKER_IP,
                    src_port,
                    routed.guest_ip,
                    routed.guest_port,
                    sockets.get::<smoltcp::socket::tcp::Socket>(handle).state()
                );

                let dest = SocketAddr::V4(SocketAddrV4::new(routed.guest_ip, routed.guest_port));
                tcp_bridges.push(TcpBridge {
                    smoltcp_handle: handle,
                    host_stream: routed.stream,
                    dest,
                    host_eof: false,
                    guest_eof: false,
                });
            }
        }

        // Step 9: Compute delay and wait for readability on IPC + host sockets.
        //
        // Cap at 100µs to match the guest-side polling cadence.  ppoll wakes
        // immediately on any fd becoming readable, so the timeout only governs
        // the idle case (smoltcp timers like delayed ACK, retransmit, etc.).
        // A short cap ensures those timers fire promptly instead of sleeping
        // for the full smoltcp interval (which can be 10 ms+).
        let wait = Duration::from_micros(100);

        // Build poll set: IPC fd + listener + pending connects + host TCP + local bridges + host UDP.
        let mut pfds: Vec<PollFd> = Vec::with_capacity(
            2 + pending_connects.len() + tcp_bridges.len() + local_bridges.len() + udp_flows.len(),
        );
        pfds.push(PollFd {
            fd: device.raw_socket(),
            events: POLLIN,
            revents: 0,
        });
        if let Some(listener) = accept_listener {
            pfds.push(PollFd {
                fd: listener.raw(),
                events: POLLIN,
                revents: 0,
            });
        }
        // Include inbound forward listeners in the poll set.
        for fwd in &inbound_listeners {
            pfds.push(PollFd {
                fd: raw_socket(&fwd.listener),
                events: POLLIN,
                revents: 0,
            });
        }
        for pc in pending_connects.iter() {
            pfds.push(PollFd {
                fd: pc.stream.raw(),
                events: POLLOUT, // Wake when connect completes.
                revents: 0,
            });
        }
        for bridge in tcp_bridges.iter() {
            if !bridge.host_eof {
                pfds.push(PollFd {
                    fd: raw_socket(&bridge.host_stream),
                    events: POLLIN,
                    revents: 0,
                });
            }
        }
        for bridge in local_bridges.iter() {
            if !bridge.host_eof {
                pfds.push(PollFd {
                    fd: raw_socket(&bridge.stream),
                    events: POLLIN,
                    revents: 0,
                });
            }
        }
        for flow in udp_flows.values() {
            pfds.push(PollFd {
                fd: raw_socket(&flow.host_socket),
                events: POLLIN,
                revents: 0,
            });
        }

        sock_compat::poll_fds_timeout(&mut pfds, wait);
    }

    device.send_shutdown();

    // Clean up port registrations owned by this proxy.
    for port in &registered_ports {
        port_router.unregister_if_owner(*port, worker_id);
    }
    if !registered_ports.is_empty() {
        info!("cleaned up {} port registrations", registered_ports.len());
    }

    info!("network proxy shut down");
    Ok(())
}

/// Accept the IPC network-proxy client from `listener`.
///
/// Loops until a connection either:
/// - completes the full LBNP handshake and returns `Ok(Some(stream))`, or
/// - is recognized as a direct local `LB9P` service connection and handled
///   inline, returning `Ok(None)` so the caller can keep listening.
///
/// Connections that are slow, send wrong magic/version/MTU, or close early are
/// dropped so a stray local client cannot monopolize the listener.
///
/// Returns an error if no valid client arrives within `overall_timeout`. Pass
/// `None` to wait indefinitely.
pub fn accept_ipc_client(
    listener: &IpcListener,
    local_services: Option<&LocalServiceRegistry>,
    overall_timeout: Option<Duration>,
) -> Result<Option<IpcStream>, Box<dyn std::error::Error>> {
    let deadline = overall_timeout.map(|d| Instant::now() + d);
    let per_client_timeout = Duration::from_secs(2);

    loop {
        if deadline.is_some_and(|dl| Instant::now() >= dl) {
            return Err("no valid LBNP client connected within timeout".into());
        }

        // Non-blocking accept.
        let stream = match listener.accept() {
            Ok(Some(stream)) => stream,
            Ok(None) => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                return Err(format!("listener accept error: {e}").into());
            }
        };

        stream.set_nonblocking(true).ok();
        let raw_socket = stream.raw();

        // Read the 4-byte magic prefix first so we can distinguish LBNP from
        // direct LB9P local-service connections.
        let client_deadline = Instant::now() + per_client_timeout;
        let mut buf = [0u8; 8];
        let mut got = 0usize;
        let magic_ok = loop {
            if Instant::now() >= client_deadline {
                break false;
            }
            let remaining_ms = client_deadline
                .saturating_duration_since(Instant::now())
                .as_millis();
            let mut rpfd = PollFd {
                fd: raw_socket,
                events: POLLIN,
                revents: 0,
            };
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let ret = sock_compat::poll_fds(
                std::slice::from_mut(&mut rpfd),
                remaining_ms.min(100) as i32,
            );
            if ret <= 0 {
                continue;
            }
            let n = sock_compat::recv_nb(raw_socket, &mut buf[got..4], 0);
            if n > 0 {
                #[allow(clippy::cast_sign_loss)]
                {
                    got += n as usize;
                }
                if got == 4 {
                    break true;
                }
            } else if n == 0 {
                break false; // peer closed
            } else {
                let err = sock_compat::last_socket_error();
                if !sock_compat::is_would_block(err) {
                    break false;
                }
            }
        };

        if !magic_ok || got < 4 {
            debug!("rejected connection: only got {got}/4 magic bytes");
            continue;
        }

        if &buf[0..4] == b"LB9P" {
            let Some(local_services) = local_services else {
                debug!("rejected connection: LB9P client arrived with no local services available");
                continue;
            };

            #[cfg(any(unix, windows))]
            {
                if local_services.get_ring(5640).is_some() {
                    let mut marker = [0u8; 1];
                    let marker_ready = loop {
                        match stream.peek(&mut marker) {
                            Ok(0) => {
                                if Instant::now() >= client_deadline {
                                    break false;
                                }
                                let remaining_ms = client_deadline
                                    .saturating_duration_since(Instant::now())
                                    .as_millis();
                                let mut rpfd = PollFd {
                                    fd: raw_socket,
                                    events: POLLIN,
                                    revents: 0,
                                };
                                #[allow(
                                    clippy::cast_possible_truncation,
                                    clippy::cast_possible_wrap
                                )]
                                let ret = sock_compat::poll_fds(
                                    std::slice::from_mut(&mut rpfd),
                                    remaining_ms.min(100) as i32,
                                );
                                if ret <= 0 {
                                    continue;
                                }
                            }
                            Ok(_) => break true,
                            Err(e) => {
                                warn!("failed to classify LB9P transport: {e}");
                                break false;
                            }
                        }
                    };

                    if !marker_ready {
                        debug!("rejected LB9P connection: timed out waiting for transport marker");
                        continue;
                    }

                    if marker[0] == LB9P_RING_MARKER {
                        let Some(ring_spawner) = local_services.get_ring(5640) else {
                            warn!("LB9P ring marker received but no ring service registered");
                            continue;
                        };
                        spawn_shared_memory_lb9p_connection(stream, ring_spawner);
                        return Ok(None);
                    }
                }
            }

            if let Some(spawner) = local_services.get(5640) {
                let stream = sock_compat::into_blocking_tcp_stream(stream);
                spawner(stream);
                info!("direct 9P channel connected");
            } else {
                warn!("LB9P connection but no 9P service registered");
            }
            return Ok(None);
        }

        if &buf[0..4] != HANDSHAKE_MAGIC {
            debug!("rejected connection: wrong magic {:02x?}", &buf[0..4]);
            continue;
        }

        // Read the remaining 4 bytes of the LBNP handshake:
        // version(2) + MTU(2).
        let ok = loop {
            if Instant::now() >= client_deadline {
                break false;
            }
            let remaining_ms = client_deadline
                .saturating_duration_since(Instant::now())
                .as_millis();
            let mut rpfd = PollFd {
                fd: raw_socket,
                events: POLLIN,
                revents: 0,
            };
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let ret = sock_compat::poll_fds(
                std::slice::from_mut(&mut rpfd),
                remaining_ms.min(100) as i32,
            );
            if ret <= 0 {
                continue;
            }
            let n = sock_compat::recv_nb(raw_socket, &mut buf[got..], 0);
            if n > 0 {
                #[allow(clippy::cast_sign_loss)]
                {
                    got += n as usize;
                }
                if got == 8 {
                    break true;
                }
            } else if n == 0 {
                break false; // peer closed
            } else {
                let err = sock_compat::last_socket_error();
                if !sock_compat::is_would_block(err) {
                    break false;
                }
            }
        };

        if !ok || got < 8 {
            debug!("rejected connection: only got {got}/8 LBNP handshake bytes");
            continue;
        }

        let version = u16::from_le_bytes([buf[4], buf[5]]);
        let mtu = u16::from_le_bytes([buf[6], buf[7]]);
        #[allow(clippy::cast_possible_truncation)]
        let our_mtu = DEVICE_MTU as u16;
        if version != HANDSHAKE_VERSION {
            debug!("rejected connection: version {version} != {HANDSHAKE_VERSION}");
            continue;
        }
        if mtu != our_mtu {
            debug!("rejected connection: MTU {mtu} != {our_mtu}");
            continue;
        }

        // Send handshake response.
        let mut response = [0u8; 8];
        response[0..4].copy_from_slice(HANDSHAKE_MAGIC);
        response[4..6].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
        response[6..8].copy_from_slice(&our_mtu.to_le_bytes());

        let mut sent = 0usize;
        let send_deadline = Instant::now() + per_client_timeout;
        let send_ok = loop {
            if Instant::now() >= send_deadline {
                break false;
            }
            let n = sock_compat::send_nb(raw_socket, &response[sent..], 0);
            if n > 0 {
                #[allow(clippy::cast_sign_loss)]
                {
                    sent += n as usize;
                }
                if sent == 8 {
                    break true;
                }
            } else if n == 0 {
                break false;
            } else {
                let err = sock_compat::last_socket_error();
                if sock_compat::is_would_block(err) {
                    let mut wpfd = PollFd {
                        fd: raw_socket,
                        events: POLLOUT,
                        revents: 0,
                    };
                    sock_compat::poll_fds(std::slice::from_mut(&mut wpfd), 100);
                    continue;
                }
                break false;
            }
        };

        if !send_ok {
            debug!("rejected connection: failed to send handshake response");
            continue;
        }

        info!(
            version,
            mtu, "accepted valid LBNP client, handshake complete"
        );
        return Ok(Some(stream));
    }
}

/// Perform the IPC handshake (broker side).
///
/// Reads all 8 bytes (magic + version + MTU), validates, and sends the
/// response.  Used only by the `--network-proxy-fd` path where the runner
/// passes the fd directly.
fn perform_handshake(fd: &IpcStream) -> Result<(), Box<dyn std::error::Error>> {
    // Wait for handshake with 10s timeout.
    let mut pfd = PollFd {
        fd: fd.raw(),
        events: POLLIN,
        revents: 0,
    };
    let ret = sock_compat::poll_fds(std::slice::from_mut(&mut pfd), 10_000);
    if ret <= 0 {
        return Err("IPC handshake timeout".into());
    }

    // Read handshake: magic (4) + version (2) + MTU (2) = 8 bytes.
    // Handles would-block/short reads on non-blocking sockets.
    let mut buf = [0u8; 8];
    let mut read = 0;
    let deadline = Instant::now() + Duration::from_secs(10);
    while read < 8 {
        let ret = sock_compat::recv_nb(fd.raw(), &mut buf[read..], 0);
        if ret > 0 {
            #[allow(clippy::cast_sign_loss)]
            {
                read += ret as usize;
            }
        } else if ret == 0 {
            return Err("IPC handshake: peer closed".into());
        } else {
            let err = sock_compat::last_socket_error();
            if sock_compat::is_would_block(err) {
                if Instant::now() > deadline {
                    return Err("IPC handshake read timeout".into());
                }
                let mut rpfd = PollFd {
                    fd: fd.raw(),
                    events: POLLIN,
                    revents: 0,
                };
                sock_compat::poll_fds(std::slice::from_mut(&mut rpfd), 100);
                continue;
            }
            return Err(format!("IPC handshake read failed: errno {err}").into());
        }
    }

    validate_handshake_request(&buf)?;
    send_handshake_response(fd)
}

fn validate_handshake_request(buf: &[u8; 8]) -> Result<(), Box<dyn std::error::Error>> {
    if &buf[0..4] != HANDSHAKE_MAGIC {
        return Err(format!(
            "IPC handshake: bad magic {:02x?}, expected {:02x?}",
            &buf[0..4],
            HANDSHAKE_MAGIC
        )
        .into());
    }

    let version = u16::from_le_bytes([buf[4], buf[5]]);
    let mtu = u16::from_le_bytes([buf[6], buf[7]]);
    info!(version, mtu, "IPC handshake received");

    if version != HANDSHAKE_VERSION {
        return Err(format!(
            "IPC handshake: unsupported version {version}, expected {HANDSHAKE_VERSION}"
        )
        .into());
    }

    #[allow(clippy::cast_possible_truncation)]
    let our_mtu = DEVICE_MTU as u16;
    if mtu != our_mtu {
        return Err(
            format!("IPC handshake: MTU mismatch — peer sent {mtu}, we expect {our_mtu}").into(),
        );
    }
    Ok(())
}

fn send_handshake_response(fd: &IpcStream) -> Result<(), Box<dyn std::error::Error>> {
    // Send handshake response (retry on would-block).
    #[allow(clippy::cast_possible_truncation)]
    let response_mtu = DEVICE_MTU as u16;
    let mut response = [0u8; 8];
    response[0..4].copy_from_slice(HANDSHAKE_MAGIC);
    response[4..6].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
    response[6..8].copy_from_slice(&response_mtu.to_le_bytes());

    let mut sent = 0usize;
    while sent < 8 {
        let ret = sock_compat::send_nb(fd.raw(), &response[sent..], 0);
        if ret > 0 {
            #[allow(clippy::cast_sign_loss)]
            {
                sent += ret as usize;
            }
        } else if ret == 0 {
            return Err("IPC handshake response: peer closed".into());
        } else {
            let err = sock_compat::last_socket_error();
            if sock_compat::is_would_block(err) {
                let mut wpfd = PollFd {
                    fd: fd.raw(),
                    events: POLLOUT,
                    revents: 0,
                };
                sock_compat::poll_fds(std::slice::from_mut(&mut wpfd), 100);
                continue;
            }
            return Err(format!("IPC handshake response send failed: errno {err}").into());
        }
    }

    Ok(())
}

/// Ensure a listen socket exists and is still in the Listen state for the
/// given destination. Only one listener per (dst_ip, dst_port) — smoltcp
/// matches SYNs by local endpoint only, so multiple listeners for the same
/// endpoint would cause cross-wiring.
///
/// If a previous listener has moved out of Listen state (accepted a SYN and
/// transitioned to SynReceived/Established), it is moved to
/// `accepting_sockets` for `promote_established` to handle, and a fresh
/// listener is created.
fn ensure_listen_socket(
    sockets: &mut SocketSet<'_>,
    listen_sockets: &mut HashMap<(Ipv4Addr, u16), SocketHandle>,
    accepting_sockets: &mut Vec<(SocketHandle, Ipv4Addr, u16)>,
    dest_ip: Ipv4Addr,
    dest_port: u16,
) {
    let key = (dest_ip, dest_port);
    if let Some(&handle) = listen_sockets.get(&key) {
        let socket: &tcp::Socket = sockets.get(handle);
        if socket.state() == tcp::State::Listen {
            return; // Still actively listening — nothing to do.
        }
        // Socket accepted a SYN and is no longer listening. Move to
        // accepting_sockets for promote_established to find.
        listen_sockets.remove(&key);
        accepting_sockets.push((handle, dest_ip, dest_port));
    }

    let rx_buf = smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]);
    let tx_buf = smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]);
    let mut socket = tcp::Socket::new(rx_buf, tx_buf);
    // Disable Nagle — the broker is a relay, not an application generating
    // small writes.  Nagle interacts badly with delayed ACK on the guest's
    // smoltcp stack, adding ~10 ms per round-trip.
    socket.set_nagle_enabled(false);

    let o = dest_ip.octets();
    let endpoint = IpListenEndpoint {
        addr: Some(IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3]))),
        port: dest_port,
    };

    match socket.listen(endpoint) {
        Ok(()) => {
            let handle = sockets.add(socket);
            listen_sockets.insert(key, handle);
            debug!("created listen socket for {dest_ip}:{dest_port}");
        }
        Err(e) => {
            warn!("failed to create listen socket for {dest_ip}:{dest_port}: {e}");
        }
    }
}

/// Initiate a non-blocking TCP connect. Returns the IPC stream.
/// Create a connected pair of TCP streams via a temporary localhost listener.
/// Returns `(local_end, remote_end)` — both set to non-blocking.
fn create_tcp_pair() -> Result<(std::net::TcpStream, std::net::TcpStream), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let client = std::net::TcpStream::connect(addr)?;
    let (server, _) = listener.accept()?;
    client.set_nonblocking(true)?;
    server.set_nonblocking(true)?;
    Ok((client, server))
}

fn start_nonblocking_connect(dest: &SocketAddr) -> Result<IpcStream, std::io::Error> {
    sock_compat::start_nonblocking_connect(dest)
}

fn check_connect(ipc: &IpcStream) -> Option<Result<(), std::io::Error>> {
    sock_compat::check_connect(ipc)
}

/// Check pending host connects for completion.
///
/// On success: stash the host `TcpStream` in `ready_host_streams` keyed by
/// the full 4-tuple. The caller (SYN dispatch) creates listen sockets.
///
/// On failure/timeout: remove silently. Guest sees TCP timeout.
fn resolve_pending_connects(
    pending: &mut Vec<PendingConnect>,
    ready_host_streams: &mut HashMap<TcpFlowKey, (std::net::TcpStream, Instant)>,
) {
    let mut successes: Vec<usize> = Vec::new();
    let mut failures: Vec<usize> = Vec::new();

    for (i, pc) in pending.iter().enumerate() {
        if pc.started.elapsed() > HOST_CONNECT_TIMEOUT {
            warn!("host TCP connect to {} timed out", pc.dest);
            failures.push(i);
            continue;
        }

        match check_connect(&pc.stream) {
            Some(Ok(())) => {
                info!("host TCP connected to {}", pc.dest);
                successes.push(i);
            }
            Some(Err(e)) => {
                warn!("host TCP connect to {} failed: {e}", pc.dest);
                failures.push(i);
            }
            None => continue,
        }
    }

    // Remove in reverse index order (swap_remove safe).
    let mut all: Vec<(usize, bool)> = successes
        .iter()
        .map(|&i| (i, true))
        .chain(failures.iter().map(|&i| (i, false)))
        .collect();
    all.sort_unstable_by(|a, b| b.0.cmp(&a.0)); // Reverse order.
    for (i, is_success) in all {
        let pc = pending.swap_remove(i);
        if is_success {
            let stream = sock_compat::into_blocking_tcp_stream(pc.stream);
            stream.set_nonblocking(true).ok();
            ready_host_streams.insert(pc.flow_key, (stream, Instant::now()));
        }
        // Failures: stream drops and closes.
    }
}

/// Promote sockets that have reached ESTABLISHED into TcpBridge or LocalBridge.
/// Matches by the full 4-tuple via smoltcp's `remote_endpoint()`.
///
/// For connections to `BROKER_IP`, spawns the registered local service via a
/// loopback TCP pair. For external connections, matches against
/// `ready_host_streams`.
fn promote_established(
    sockets: &mut SocketSet<'_>,
    listen_sockets: &mut HashMap<(Ipv4Addr, u16), SocketHandle>,
    accepting_sockets: &mut Vec<(SocketHandle, Ipv4Addr, u16)>,
    bridges: &mut Vec<TcpBridge>,
    local_bridges: &mut Vec<LocalBridge>,
    ready_host_streams: &mut HashMap<TcpFlowKey, (std::net::TcpStream, Instant)>,
    local_services: &LocalServiceRegistry,
) {
    // Collect established sockets from listen_sockets.
    // Also promote sockets in CloseWait — the guest may have sent data + FIN
    // in a single TCP segment, causing the socket to skip Established and land
    // directly in CloseWait within one iface.poll() call.
    let mut newly_established: Vec<(SocketHandle, Ipv4Addr, u16)> = Vec::new();
    let mut listen_keys_to_remove: Vec<(Ipv4Addr, u16)> = Vec::new();
    for (&key, &handle) in listen_sockets.iter() {
        let socket: &tcp::Socket = sockets.get(handle);
        if matches!(
            socket.state(),
            tcp::State::Established | tcp::State::CloseWait
        ) {
            listen_keys_to_remove.push(key);
            newly_established.push((handle, key.0, key.1));
        }
    }
    for key in &listen_keys_to_remove {
        listen_sockets.remove(key);
    }

    // Collect established sockets from accepting_sockets.
    let mut accepting_indices: Vec<usize> = Vec::new();
    for (i, &(handle, dest_ip, dest_port)) in accepting_sockets.iter().enumerate() {
        let socket: &tcp::Socket = sockets.get(handle);
        if matches!(
            socket.state(),
            tcp::State::Established | tcp::State::CloseWait
        ) {
            accepting_indices.push(i);
            newly_established.push((handle, dest_ip, dest_port));
        }
    }
    for &i in accepting_indices.iter().rev() {
        accepting_sockets.swap_remove(i);
    }

    for (handle, dest_ip, dest_port) in newly_established {
        if dest_ip == BROKER_IPV4
            || dest_ip == Ipv4Addr::LOCALHOST
            || dest_ip == Ipv4Addr::new(10, 0, 0, 2)
        {
            // Check for a ready host stream (from cross-worker loopback TCP pair).
            let socket: &tcp::Socket = sockets.get(handle);
            let remote = socket.remote_endpoint();
            let mut found_host_stream = false;
            if let Some(remote) = remote {
                #[allow(unreachable_patterns)]
                let IpAddress::Ipv4(ip) = remote.addr;
                let src_ip = ip.octets();
                let flow_key = (src_ip, remote.port, dest_ip.octets(), dest_port);
                if let Some((stream, _)) = ready_host_streams.remove(&flow_key) {
                    stream.set_nonblocking(true).ok();
                    let dest = SocketAddr::V4(SocketAddrV4::new(dest_ip, dest_port));
                    bridges.push(TcpBridge {
                        smoltcp_handle: handle,
                        host_stream: stream,
                        dest,
                        host_eof: false,
                        guest_eof: false,
                    });
                    info!("cross-worker bridge created for {dest_ip}:{dest_port}");
                    found_host_stream = true;
                }
            }
            if found_host_stream {
                continue;
            }

            // No host stream — try local service.
            if let Some(spawner) = local_services.get(dest_port) {
                match TcpListener::bind("127.0.0.1:0") {
                    Ok(listener) => match listener.local_addr() {
                        Ok(addr) => match std::net::TcpStream::connect(addr) {
                            Ok(proxy_end) => match listener.accept() {
                                Ok((service_end, _)) => {
                                    proxy_end.set_nonblocking(true).ok();
                                    let thread = spawner(service_end);
                                    info!("local service spawned on port {dest_port}");
                                    local_bridges.push(LocalBridge {
                                        smoltcp_handle: handle,
                                        stream: proxy_end,
                                        dest_port,
                                        host_eof: false,
                                        _thread: thread,
                                    });
                                }
                                Err(e) => {
                                    warn!("failed to accept loopback service connection: {e}");
                                    let socket: &mut tcp::Socket = sockets.get_mut(handle);
                                    socket.abort();
                                    sockets.remove(handle);
                                }
                            },
                            Err(e) => {
                                warn!("failed to connect loopback service stream: {e}");
                                let socket: &mut tcp::Socket = sockets.get_mut(handle);
                                socket.abort();
                                sockets.remove(handle);
                            }
                        },
                        Err(e) => {
                            warn!("failed to resolve loopback service listener address: {e}");
                            let socket: &mut tcp::Socket = sockets.get_mut(handle);
                            socket.abort();
                            sockets.remove(handle);
                        }
                    },
                    Err(e) => {
                        warn!("failed to create loopback service listener: {e}");
                        let socket: &mut tcp::Socket = sockets.get_mut(handle);
                        socket.abort();
                        sockets.remove(handle);
                    }
                }
            } else {
                warn!("no local service on BROKER_IP port {dest_port}, aborting");
                let socket: &mut tcp::Socket = sockets.get_mut(handle);
                socket.abort();
                sockets.remove(handle);
            }
            continue;
        }

        // External connection: match to a ready host stream.
        let socket: &tcp::Socket = sockets.get(handle);
        let remote = socket.remote_endpoint();
        let dest = SocketAddr::V4(SocketAddrV4::new(dest_ip, dest_port));

        if let Some(remote) = remote {
            #[allow(unreachable_patterns)]
            let IpAddress::Ipv4(a) = remote.addr;
            let src_ip = a.octets();
            let flow_key = (src_ip, remote.port, dest_ip.octets(), dest_port);

            if let Some((stream, _created)) = ready_host_streams.remove(&flow_key) {
                bridges.push(TcpBridge {
                    smoltcp_handle: handle,
                    host_stream: stream,
                    dest,
                    host_eof: false,
                    guest_eof: false,
                });
            } else {
                let socket: &mut tcp::Socket = sockets.get_mut(handle);
                socket.abort();
                sockets.remove(handle);
            }
        } else {
            let socket: &mut tcp::Socket = sockets.get_mut(handle);
            socket.abort();
            sockets.remove(handle);
        }

        // If more ready_host_streams await the same (dst_ip, dst_port),
        // ensure a listen socket exists for the next SYN retransmit.
        let dest_octets = dest_ip.octets();
        let has_more = ready_host_streams
            .keys()
            .any(|&(_, _, di, dp)| di == dest_octets && dp == dest_port);
        if has_more {
            ensure_listen_socket(
                sockets,
                listen_sockets,
                accepting_sockets,
                dest_ip,
                dest_port,
            );
        }
    }
}

/// Relay data between smoltcp TCP sockets and host TCP streams.
///
/// Uses peek-before-consume (guest→host) and capacity-limited reads (host→guest)
/// to prevent data loss on partial writes.
fn relay_tcp(sockets: &mut SocketSet<'_>, bridges: &mut Vec<TcpBridge>) {
    let mut to_remove: Vec<usize> = Vec::new();

    for (i, bridge) in bridges.iter_mut().enumerate() {
        let socket: &mut tcp::Socket = sockets.get_mut(bridge.smoltcp_handle);

        // Log non-Established states to trace connection lifecycle.
        let state = socket.state();
        if state != tcp::State::Established {
            info!(
                "bridge[{i}] {} state={state:?} can_recv={} can_send={}",
                bridge.dest,
                socket.can_recv(),
                socket.can_send(),
            );
        }

        // Guest → Host:peek from smoltcp, write to host, then consume only
        // the bytes the host actually accepted.
        if socket.can_recv() {
            let mut buf = [0u8; 8192];
            match socket.peek_slice(&mut buf) {
                Ok(n) if n > 0 => {
                    match std::io::Write::write(&mut bridge.host_stream, &buf[..n]) {
                        Ok(sent) if sent > 0 => {
                            // Consume only the bytes the host accepted.
                            let mut discard = vec![0u8; sent];
                            let _ = socket.recv_slice(&mut discard);
                            debug!("relayed {sent} bytes guest→host for {}", bridge.dest);
                        }
                        Ok(_) => {
                            // Zero-byte write — host buffer full. Leave data in
                            // smoltcp; backpressure propagates via TCP window.
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Host not writable — leave data in smoltcp.
                        }
                        Err(e) => {
                            debug!("host write error for {}: {e}", bridge.dest);
                            socket.abort();
                            to_remove.push(i);
                            continue;
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    debug!("smoltcp peek error for {}: {e}", bridge.dest);
                    to_remove.push(i);
                    continue;
                }
            }
        } else if !bridge.guest_eof
            && matches!(
                socket.state(),
                tcp::State::CloseWait
                    | tcp::State::LastAck
                    | tcp::State::Closing
                    | tcp::State::TimeWait
            )
        {
            // Guest sent FIN — propagate half-close to the host stream so the
            // other end of the TCP pair (or real host socket) sees EOF.
            bridge.guest_eof = true;
            use std::net::Shutdown;
            bridge.host_stream.shutdown(Shutdown::Write).ok();
            debug!("guest EOF, shutdown host write for {}", bridge.dest);
        }

        // Host → Guest: read from host only up to what smoltcp can accept.
        if socket.can_send() && !bridge.host_eof {
            let free = socket.send_capacity() - socket.send_queue();
            if free > 0 {
                let read_limit = free.min(8192);
                let mut buf = vec![0u8; read_limit];
                match std::io::Read::read(&mut bridge.host_stream, &mut buf) {
                    Ok(0) => {
                        debug!("host EOF for {}", bridge.dest);
                        bridge.host_eof = true;
                        socket.close();
                    }
                    Ok(n) => {
                        debug!("relayed {n} bytes host→guest for {}", bridge.dest);
                        match socket.send_slice(&buf[..n]) {
                            Ok(sent) => {
                                trace!("relayed {sent} bytes host→guest for {}", bridge.dest);
                            }
                            Err(e) => {
                                debug!("smoltcp send error for {}: {e}", bridge.dest);
                                to_remove.push(i);
                                continue;
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        debug!("host read error for {}: {e}", bridge.dest);
                        socket.abort();
                        to_remove.push(i);
                        continue;
                    }
                }
            }
        }

        // Check if connection is fully closed.
        match socket.state() {
            tcp::State::Closed | tcp::State::TimeWait => {
                info!(
                    "TCP bridge closed for {} state={:?} remote={:?}",
                    bridge.dest,
                    socket.state(),
                    socket.remote_endpoint(),
                );
                to_remove.push(i);
            }
            tcp::State::Listen
            | tcp::State::SynSent
            | tcp::State::SynReceived
            | tcp::State::Established
            | tcp::State::FinWait1
            | tcp::State::FinWait2
            | tcp::State::CloseWait
            | tcp::State::Closing
            | tcp::State::LastAck => {}
        }
    }

    // Remove closed bridges (in reverse order to preserve indices).
    // Also remove the underlying smoltcp socket to free buffer memory.
    to_remove.sort_unstable();
    to_remove.dedup();
    for &i in to_remove.iter().rev() {
        let bridge = bridges.swap_remove(i);
        sockets.remove(bridge.smoltcp_handle);
        debug!("removed TCP bridge for {}", bridge.dest);
    }
}

/// Relay data between smoltcp TCP sockets and local service TCP streams.
/// Same pattern as `relay_tcp` but uses the loopback service stream.
fn relay_local(sockets: &mut SocketSet<'_>, bridges: &mut Vec<LocalBridge>) {
    let mut to_remove: Vec<usize> = Vec::new();

    for (i, bridge) in bridges.iter_mut().enumerate() {
        let socket: &mut tcp::Socket = sockets.get_mut(bridge.smoltcp_handle);

        // Guest → Service: peek from smoltcp, write to the service stream.
        if socket.can_recv() {
            let mut buf = [0u8; 8192];
            match socket.peek_slice(&mut buf) {
                Ok(n) if n > 0 => match std::io::Write::write(&mut bridge.stream, &buf[..n]) {
                    Ok(written) if written > 0 => {
                        let mut discard = vec![0u8; written];
                        let _ = socket.recv_slice(&mut discard);
                        trace!(
                            "relayed {written} bytes guest→service port {}",
                            bridge.dest_port
                        );
                    }
                    Ok(_) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        debug!("service write error port {}: {e}", bridge.dest_port);
                        socket.abort();
                        to_remove.push(i);
                        continue;
                    }
                },
                Ok(_) | Err(_) => {}
            }
        }

        // Service → Guest: read from the service stream, send to smoltcp.
        if socket.can_send() && !bridge.host_eof {
            let free = socket.send_capacity() - socket.send_queue();
            if free > 0 {
                let read_limit = free.min(8192);
                let mut buf = vec![0u8; read_limit];
                match std::io::Read::read(&mut bridge.stream, &mut buf) {
                    Ok(0) => {
                        debug!("service EOF for port {}", bridge.dest_port);
                        bridge.host_eof = true;
                        socket.close();
                    }
                    Ok(n) => match socket.send_slice(&buf[..n]) {
                        Ok(sent) => {
                            trace!(
                                "relayed {sent} bytes service→guest port {}",
                                bridge.dest_port
                            );
                        }
                        Err(e) => {
                            debug!("smoltcp send error port {}: {e}", bridge.dest_port);
                            to_remove.push(i);
                            continue;
                        }
                    },
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        debug!("service read error port {}: {e}", bridge.dest_port);
                        socket.abort();
                        to_remove.push(i);
                        continue;
                    }
                }
            }
        }

        // Check if connection is fully closed.
        match socket.state() {
            tcp::State::Closed | tcp::State::TimeWait => {
                debug!("local bridge closed for port {}", bridge.dest_port);
                to_remove.push(i);
            }
            tcp::State::Listen
            | tcp::State::SynSent
            | tcp::State::SynReceived
            | tcp::State::Established
            | tcp::State::FinWait1
            | tcp::State::FinWait2
            | tcp::State::CloseWait
            | tcp::State::Closing
            | tcp::State::LastAck => {}
        }
    }

    to_remove.sort_unstable();
    to_remove.dedup();
    for &i in to_remove.iter().rev() {
        let bridge = bridges.swap_remove(i);
        sockets.remove(bridge.smoltcp_handle);
        debug!("removed local bridge for port {}", bridge.dest_port);
    }
}

/// Handle an outbound UDP datagram from the guest.
///
/// Creates a host UDP socket per flow and forwards the payload.
fn handle_udp_outbound(
    flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    payload: &[u8],
) {
    let key = (src_ip, src_port, dst_ip, dst_port);
    let dest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(dst_ip), dst_port));

    let flow = flows.entry(key).or_insert_with(|| {
        // Create a new host UDP socket bound to an ephemeral port.
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                warn!("failed to create UDP socket for {dest}: {e}");
                // Return a dummy flow that will fail on send.
                return UdpFlow {
                    host_socket: UdpSocket::bind("0.0.0.0:0").unwrap(),
                    guest_src_ip: src_ip,
                    guest_src_port: src_port,
                    dest_ip: dst_ip,
                    dest_port: dst_port,
                    last_activity: Instant::now(),
                };
            }
        };
        socket.set_nonblocking(true).ok();
        debug!("created UDP flow for {dest}");
        UdpFlow {
            host_socket: socket,
            guest_src_ip: src_ip,
            guest_src_port: src_port,
            dest_ip: dst_ip,
            dest_port: dst_port,
            last_activity: Instant::now(),
        }
    });

    flow.last_activity = Instant::now();
    if let Err(e) = flow.host_socket.send_to(payload, dest) {
        debug!("UDP send_to {dest} failed: {e}");
    } else {
        trace!("forwarded {} bytes UDP to {dest}", payload.len());
    }
}

/// Check all UDP flows for replies from host and send raw IP+UDP packets back
/// to guest via IPC. DNS responses (from port 53 flows) are also fed to the
/// DNS tracker for hostname→IP mapping.
fn relay_udp_replies(
    flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    device: &mut IpcDevice,
    dns_tracker: &mut dns_tracker::DnsTracker,
    audit_log: &Option<AuditLog>,
) {
    for flow in flows.values_mut() {
        let mut buf = [0u8; 65535];
        loop {
            match flow.host_socket.recv_from(&mut buf) {
                Ok((n, _from)) => {
                    flow.last_activity = Instant::now();

                    // Track DNS responses for hostname-based policy.
                    if flow.dest_port == 53 {
                        if let Some((hostname, ips)) = dns_tracker.process_response(&buf[..n]) {
                            if let Some(al) = audit_log {
                                al.dns_resolved(&hostname, &ips);
                            }
                        }
                    }

                    // Construct raw IP+UDP packet.
                    let packet = build_udp_packet(
                        &flow.dest_ip,
                        flow.dest_port,
                        &flow.guest_src_ip,
                        flow.guest_src_port,
                        &buf[..n],
                    );
                    device.send_framed(&packet);
                    trace!(
                        "relayed {} bytes UDP reply to guest {}:{} from {}:{}",
                        n,
                        Ipv4Addr::from(flow.guest_src_ip),
                        flow.guest_src_port,
                        Ipv4Addr::from(flow.dest_ip),
                        flow.dest_port,
                    );
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    debug!("UDP recv error: {e}");
                    break;
                }
            }
        }
    }
}

/// Build a raw IPv4+UDP packet.
fn build_udp_packet(
    src_ip: &[u8; 4],
    src_port: u16,
    dst_ip: &[u8; 4],
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0u8; total_len];

    // IPv4 header (20 bytes, no options).
    packet[0] = 0x45; // Version=4, IHL=5
    // packet[1] = 0; // DSCP/ECN
    packet[2] = (total_len >> 8) as u8;
    packet[3] = (total_len & 0xFF) as u8;
    // packet[4..6]: identification (0)
    packet[6] = 0x40; // Don't Fragment
    packet[8] = 64; // TTL
    packet[9] = 17; // Protocol: UDP
    // packet[10..12]: header checksum (computed below)
    packet[12..16].copy_from_slice(src_ip);
    packet[16..20].copy_from_slice(dst_ip);

    // IP header checksum.
    let cksum = device::internet_checksum(&packet[..20]);
    packet[10] = (cksum >> 8) as u8;
    packet[11] = (cksum & 0xFF) as u8;

    // UDP header.
    packet[20] = (src_port >> 8) as u8;
    packet[21] = (src_port & 0xFF) as u8;
    packet[22] = (dst_port >> 8) as u8;
    packet[23] = (dst_port & 0xFF) as u8;
    packet[24] = (udp_len >> 8) as u8;
    packet[25] = (udp_len & 0xFF) as u8;
    // packet[26..28]: UDP checksum (optional for IPv4, leave 0)

    // Payload.
    packet[28..].copy_from_slice(payload);

    packet
}

/// Discover the host's DNS resolver by parsing `/etc/resolv.conf`.
///
/// Returns the first `nameserver` entry found, or `8.8.8.8` as a fallback.
fn discover_host_dns() -> Ipv4Addr {
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if let Some(addr_str) = line.strip_prefix("nameserver") {
                let addr_str = addr_str.trim();
                if let Ok(addr) = addr_str.parse::<Ipv4Addr>() {
                    info!("host DNS resolver: {addr}");
                    return addr;
                }
            }
        }
    }
    let fallback = Ipv4Addr::new(8, 8, 8, 8);
    info!("no host DNS resolver found, using fallback: {fallback}");
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    #[cfg(windows)]
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::Duration;

    fn routed_stream_sender() -> std::sync::mpsc::Sender<RoutedStream> {
        std::sync::mpsc::channel().0
    }

    #[test]
    fn transfer_listen_route_swaps_owner() {
        let router = PortRouter::new();
        router.register(12345, 1, routed_stream_sender());

        let result = router.transfer_listen_route(12345, 1, 2, routed_stream_sender());
        assert_eq!(result, Ok(TransferListenRouteOutcome::Transferred));
        assert_eq!(router.routes.lock().unwrap().get(&12345).unwrap().0, 2);
    }

    #[test]
    fn transfer_listen_route_is_idempotent_for_target_owner() {
        let router = PortRouter::new();
        router.register(12345, 2, routed_stream_sender());

        let result = router.transfer_listen_route(12345, 1, 2, routed_stream_sender());
        assert_eq!(result, Ok(TransferListenRouteOutcome::AlreadyOwnedByTarget));
        assert_eq!(router.routes.lock().unwrap().get(&12345).unwrap().0, 2);
    }

    #[test]
    fn transfer_listen_route_reports_missing_port() {
        let router = PortRouter::new();

        let result = router.transfer_listen_route(12345, 1, 2, routed_stream_sender());
        assert_eq!(result, Err(TransferListenRouteError::PortNotRegistered));
    }

    #[test]
    fn transfer_listen_route_rejects_unexpected_source() {
        let router = PortRouter::new();
        router.register(12345, 3, routed_stream_sender());

        let result = router.transfer_listen_route(12345, 1, 2, routed_stream_sender());
        assert_eq!(
            result,
            Err(TransferListenRouteError::SourceNotOwner { actual_owner: 3 })
        );
        assert_eq!(router.routes.lock().unwrap().get(&12345).unwrap().0, 3);
    }

    #[test]
    fn transfer_listen_route_from_current_swaps_owner() {
        let router = PortRouter::new();
        router.register(12345, 1, routed_stream_sender());

        let result = router.transfer_listen_route_from_current(12345, 2, routed_stream_sender());
        assert_eq!(result, Ok(TransferListenRouteOutcome::Transferred));
        assert_eq!(router.routes.lock().unwrap().get(&12345).unwrap().0, 2);
    }

    #[test]
    fn test_build_udp_packet_valid() {
        let payload = b"hello world";
        let pkt = build_udp_packet(&[8, 8, 8, 8], 53, &[10, 0, 0, 2], 5353, payload);

        // Verify it parses back correctly.
        let parsed = device::parse_udp(&pkt);
        assert!(parsed.is_some());
        let (src_ip, src_port, dst_ip, dst_port, offset, len) = parsed.unwrap();
        assert_eq!(src_ip, [8, 8, 8, 8]);
        assert_eq!(src_port, 53);
        assert_eq!(dst_ip, [10, 0, 0, 2]);
        assert_eq!(dst_port, 5353);
        assert_eq!(&pkt[offset..offset + len], payload);

        // Verify IP header checksum is valid.
        assert_eq!(device::internet_checksum(&pkt[..20]), 0);
    }

    #[cfg(windows)]
    #[test]
    fn test_accept_ipc_client_handles_initial_lb9p_connection() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
        let port = probe.local_addr().expect("probe local_addr").port();
        drop(probe);

        let listener =
            IpcListener::bind_endpoint(&format!("127.0.0.1:{port}")).expect("bind IPC listener");

        let invoked = Arc::new(AtomicBool::new(false));
        let invoked_flag = Arc::clone(&invoked);
        let mut local_services = LocalServiceRegistry::new();
        local_services.register(
            5640,
            Box::new(move |_stream| {
                let invoked_flag = Arc::clone(&invoked_flag);
                std::thread::spawn(move || {
                    invoked_flag.store(true, Ordering::SeqCst);
                })
            }),
        );

        let endpoint = format!("127.0.0.1:{port}");
        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(&endpoint).expect("connect test client");
            use std::io::Write as _;
            stream.write_all(b"LB9P").expect("send LB9P magic");
            std::thread::sleep(Duration::from_millis(100));
        });

        let accepted = accept_ipc_client(
            &listener,
            Some(&local_services),
            Some(Duration::from_secs(2)),
        )
        .expect("accept direct LB9P connection");
        assert!(
            accepted.is_none(),
            "LB9P connection should be handled inline"
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !invoked.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "local 9P service was not spawned"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        client.join().expect("join client thread");
    }

    #[cfg(windows)]
    #[test]
    fn test_accept_ipc_client_handles_initial_lb9p_ring_connection() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
        let port = probe.local_addr().expect("probe local_addr").port();
        drop(probe);

        let listener =
            IpcListener::bind_endpoint(&format!("127.0.0.1:{port}")).expect("bind IPC listener");

        let invoked = Arc::new(AtomicBool::new(false));
        let invoked_flag = Arc::clone(&invoked);
        let mut local_services = LocalServiceRegistry::new();
        local_services.register_ring(
            5640,
            Arc::new(move |_writer, _reader| {
                invoked_flag.store(true, Ordering::SeqCst);
                std::thread::spawn(|| {})
            }),
        );

        let endpoint = format!("127.0.0.1:{port}");
        let client = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            let mut stream = std::net::TcpStream::connect(&endpoint).expect("connect test client");
            stream.write_all(b"LB9P").expect("send LB9P magic");

            let (_pair, info) = litebox_common_windows::shmem_ring::ShmemRingPair::create()
                .expect("create Windows ring pair");
            let metadata = info.encode();
            stream
                .write_all(&[litebox_common_windows::shmem_ring::TRANSPORT_MARKER])
                .expect("send ring transport marker");
            stream
                .write_all(&metadata)
                .expect("send ring metadata payload");

            let mut ack = [0u8; 1];
            stream.read_exact(&mut ack).expect("read ring ACK");
            assert_eq!(ack, [LB9P_RING_ACK], "broker should ACK ring metadata");
        });

        let accepted = accept_ipc_client(
            &listener,
            Some(&local_services),
            Some(Duration::from_secs(2)),
        )
        .expect("accept direct LB9P ring connection");
        assert!(
            accepted.is_none(),
            "LB9P ring connection should be consumed by the broker"
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !invoked.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "local shared-memory 9P service was not spawned"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        client.join().expect("join client thread");
    }

    #[cfg(windows)]
    #[test]
    fn test_accept_ipc_client_ignores_truncated_lb9p_ring_then_accepts_valid_one() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
        let port = probe.local_addr().expect("probe local_addr").port();
        drop(probe);

        let listener =
            IpcListener::bind_endpoint(&format!("127.0.0.1:{port}")).expect("bind IPC listener");

        let invocation_count = Arc::new(AtomicUsize::new(0));
        let invocation_count_flag = Arc::clone(&invocation_count);
        let mut local_services = LocalServiceRegistry::new();
        local_services.register_ring(
            5640,
            Arc::new(move |_writer, _reader| {
                invocation_count_flag.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(|| {})
            }),
        );

        let endpoint = format!("127.0.0.1:{port}");
        let bad_endpoint = endpoint.clone();
        let (bad_ready_tx, bad_ready_rx) = std::sync::mpsc::sync_channel::<()>(0);
        let (release_bad_tx, release_bad_rx) = std::sync::mpsc::sync_channel::<()>(0);
        let bad_client = std::thread::spawn(move || {
            use std::io::Write as _;

            let mut stream =
                std::net::TcpStream::connect(&bad_endpoint).expect("connect truncated test client");
            stream.write_all(b"LB9P").expect("send LB9P magic");
            stream
                .write_all(&[litebox_common_windows::shmem_ring::TRANSPORT_MARKER])
                .expect("send ring transport marker");
            stream
                .write_all(&[0u8; 16])
                .expect("send truncated ring metadata");
            bad_ready_tx
                .send(())
                .expect("report truncated client readiness");
            release_bad_rx
                .recv()
                .expect("wait for permission to release truncated client");
        });

        bad_ready_rx
            .recv()
            .expect("wait for truncated client readiness");
        let first_start = std::time::Instant::now();
        let first = accept_ipc_client(
            &listener,
            Some(&local_services),
            Some(Duration::from_secs(2)),
        )
        .expect("handle truncated ring connection");
        assert!(
            first.is_none(),
            "truncated LB9P ring connection should be consumed by the broker"
        );
        assert!(
            first_start.elapsed() < Duration::from_millis(500),
            "truncated LB9P ring connection should not monopolize the accept loop"
        );
        assert_eq!(
            invocation_count.load(Ordering::SeqCst),
            0,
            "truncated LB9P ring connection must not spawn a local service"
        );

        let good_client = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            let mut stream =
                std::net::TcpStream::connect(&endpoint).expect("connect valid test client");
            stream.write_all(b"LB9P").expect("send LB9P magic");

            let (_pair, info) = litebox_common_windows::shmem_ring::ShmemRingPair::create()
                .expect("create Windows ring pair");
            let metadata = info.encode();
            stream
                .write_all(&[litebox_common_windows::shmem_ring::TRANSPORT_MARKER])
                .expect("send ring transport marker");
            stream
                .write_all(&metadata)
                .expect("send ring metadata payload");

            let mut ack = [0u8; 1];
            stream.read_exact(&mut ack).expect("read ring ACK");
            assert_eq!(ack, [LB9P_RING_ACK], "broker should ACK ring metadata");
        });

        let second = accept_ipc_client(
            &listener,
            Some(&local_services),
            Some(Duration::from_secs(2)),
        )
        .expect("accept valid LB9P ring connection after truncated one");
        assert!(
            second.is_none(),
            "valid LB9P ring connection should be consumed by the broker"
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while invocation_count.load(Ordering::SeqCst) != 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "valid LB9P ring connection did not spawn a local service"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        release_bad_tx.send(()).expect("release truncated client");
        bad_client.join().expect("join truncated client");
        good_client.join().expect("join valid client");
    }

    #[cfg(unix)]
    #[test]
    fn run_accepts_additional_lbnp_client() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("litebox-netproxy-{unique}.sock"));
        let listener = IpcListener::bind_unix(&path).expect("bind unix listener");

        let mut client1 = std::os::unix::net::UnixStream::connect(&path).expect("connect client1");
        client1
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set client1 timeout");
        client1
            .write_all(&build_lbnp_handshake())
            .expect("write client1 handshake");
        let server_ipc = accept_ipc_client(&listener, None, Some(Duration::from_secs(2)))
            .expect("accept client1")
            .expect("client1 should be an LBNP connection");
        let mut resp = [0u8; 8];
        client1
            .read_exact(&mut resp)
            .expect("read client1 handshake response");
        assert_eq!(&resp[0..4], HANDSHAKE_MAGIC);

        let run_thread = std::thread::spawn(move || {
            run(
                server_ipc,
                true,
                None,
                Some(&listener),
                None,
                None,
                Vec::new(),
                None,
            )
            .expect("proxy thread should run")
        });

        let mut client2 = std::os::unix::net::UnixStream::connect(&path).expect("connect client2");
        client2
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set client2 timeout");
        client2
            .write_all(&build_lbnp_handshake())
            .expect("write client2 handshake");
        client2
            .read_exact(&mut resp)
            .expect("read client2 handshake response");
        assert_eq!(&resp[0..4], HANDSHAKE_MAGIC);

        drop(client2);
        drop(client1);
        run_thread.join().expect("join proxy thread");
        let _ = std::fs::remove_file(path);
    }

    fn build_lbnp_handshake() -> [u8; 8] {
        #[allow(clippy::cast_possible_truncation)]
        let mtu = DEVICE_MTU as u16;
        let mut msg = [0u8; 8];
        msg[0..4].copy_from_slice(HANDSHAKE_MAGIC);
        msg[4..6].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
        msg[6..8].copy_from_slice(&mtu.to_le_bytes());
        msg
    }
}
