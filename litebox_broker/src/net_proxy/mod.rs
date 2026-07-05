// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Network proxy session acceptor and host-side inbound forward dispatcher.
//!
//! Broker-held inet state owns TCP/UDP after Phase F.2. This module now keeps
//! only the LBNP/LB9P session handshakes and host listener plumbing needed to
//! deliver accepted host streams to broker-held listeners.

mod device;
pub(crate) mod host_dns;
mod inbound_forward;
mod lb9p_handshake;
mod lbnp_handshake;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::audit::AuditLog;
use crate::sandbox_policy::SandboxPolicy;
use crate::sock_compat::{
    self, AsRawSock, IpcListener, IpcStream, PollFd, RawSock, POLLERR, POLLHUP, POLLIN,
};
use crate::state_registry::BrokerStateRegistry;

use device::{IpcDrainResult, DEVICE_MTU};
use lb9p_handshake::{PendingLb9pResult, RingServiceSpawner};
use lbnp_handshake::{
    perform_handshake, send_handshake_response, validate_handshake_request, HANDSHAKE_MAGIC,
    HANDSHAKE_VERSION,
};
use tracing::{debug, info, warn};

/// A newly accepted connection waiting for transport classification.
/// Drained opportunistically each event-loop iteration with zero blocking.
struct PendingHandshake {
    stream: Option<IpcStream>,
    raw_socket: RawSock,
    handshake: [u8; 8],
    got: usize,
    deadline: Instant,
}

struct PendingInbound {
    fwd_index: usize,
    stream: Option<std::net::TcpStream>,
    peer: std::net::SocketAddr,
    deadline: Instant,
}

/// Timeout for the LB9P handshake on an accepted connection.
const HANDSHAKE_ACCEPT_TIMEOUT: Duration = Duration::from_millis(100);

/// Maximum concurrently active extra LBNP proxy sessions accepted from the
/// listener while an initial session is already running.
const MAX_ADDITIONAL_LBNP_SESSIONS: usize = 32;

/// Maximum accepted-but-not-yet-classified listener sockets kept in the
/// pending handshake queue at once.
const MAX_PENDING_ACCEPTED_HANDSHAKES: usize = 32;
const MAX_PENDING_INBOUND_STREAMS: usize = 32;
const INBOUND_LISTENER_GRACE: Duration = Duration::from_secs(30);

/// Parse a port-forward spec: "HOST_PORT:GUEST_IP:GUEST_PORT".
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

// ---------------------------------------------------------------------------
// Local service registry — broker-internal direct LB9P services
// ---------------------------------------------------------------------------

/// Factory that spawns a service handler on a bidirectional byte stream.
pub type ServiceSpawner =
    Box<dyn Fn(std::net::TcpStream) -> std::thread::JoinHandle<()> + Send + Sync>;

/// Registry of broker-internal services keyed by TCP port.
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

    /// Register a service on the given port for direct LB9P byte-stream handoff.
    pub fn register(&mut self, port: u16, spawner: ServiceSpawner) {
        self.services.insert(port, spawner);
    }

    /// Register a shared-memory ring spawner for the given port.
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

/// Run the network proxy event loop.
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
    run_inner(
        ipc_fd,
        handshake_done,
        Arc::new(local_services.unwrap_or_default()),
        accept_listener,
        session_slots,
        sandbox_policy,
        audit_log,
        inbound_forwards,
        state_registry,
    )
}

fn run_inner(
    ipc_fd: IpcStream,
    handshake_done: bool,
    local_services: Arc<LocalServiceRegistry>,
    accept_listener: Option<&IpcListener>,
    session_slots: Arc<AtomicUsize>,
    _sandbox_policy: Option<Arc<SandboxPolicy>>,
    _audit_log: Option<AuditLog>,
    inbound_forwards: Vec<(u16, Ipv4Addr, u16)>,
    state_registry: Option<Arc<BrokerStateRegistry>>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("network proxy starting");

    if !handshake_done {
        perform_handshake(&ipc_fd)?;
        info!("IPC handshake complete");
    }

    ipc_fd.set_nonblocking(true).ok();
    let ipc_raw = ipc_fd.raw();

    let inbound_listeners =
        inbound_forward::setup_inbound_listeners(&inbound_forwards, state_registry.as_deref());
    let _host_dns = host_dns::discover_host_dns();
    let mut pending_handshakes: Vec<PendingHandshake> = Vec::new();
    let mut pending_inbound: Vec<PendingInbound> = Vec::new();

    info!("network proxy ready, entering event loop");

    loop {
        match drain_ipc_frames(ipc_raw) {
            IpcLoopState::Continue => {}
            IpcLoopState::Shutdown => break,
            IpcLoopState::ProtocolError => {
                device::send_shutdown(ipc_raw);
                break;
            }
        }

        if let Some(listener) = accept_listener {
            loop {
                match listener.accept() {
                    Ok(Some(stream)) => {
                        stream.set_nonblocking(true).ok();
                        let raw_socket = stream.raw();
                        if pending_handshakes.len() >= MAX_PENDING_ACCEPTED_HANDSHAKES {
                            warn!(
                                limit = MAX_PENDING_ACCEPTED_HANDSHAKES,
                                "too many pending accepted handshakes; dropping connection"
                            );
                            continue;
                        }
                        pending_handshakes.push(PendingHandshake {
                            stream: Some(stream),
                            raw_socket,
                            handshake: [0u8; 8],
                            got: 0,
                            deadline: Instant::now() + HANDSHAKE_ACCEPT_TIMEOUT,
                        });
                    }
                    Ok(None) => break,
                    Err(e) => {
                        warn!("accept listener error: {e}");
                        break;
                    }
                }
            }
        }

        drain_pending_handshakes(
            &mut pending_handshakes,
            &local_services,
            &session_slots,
            _sandbox_policy.clone(),
            _audit_log.clone(),
            state_registry.clone(),
        );

        drain_pending_inbound(
            &mut pending_inbound,
            &inbound_listeners,
            state_registry.as_deref(),
        );

        for (fwd_index, fwd) in inbound_listeners.iter().enumerate() {
            loop {
                match fwd.listener.accept() {
                    Ok((stream, peer)) => {
                        stream.set_nonblocking(true).ok();
                        info!(
                            "inbound TCP: accepted from {peer} → {}:{}",
                            fwd.guest_ip, fwd.guest_port
                        );

                        match inbound_forward::try_accept_broker_held(
                            fwd,
                            stream,
                            peer,
                            state_registry.as_deref(),
                        ) {
                            inbound_forward::BrokerHeldAccept::Delivered
                            | inbound_forward::BrokerHeldAccept::Rejected => {}
                            inbound_forward::BrokerHeldAccept::NoListener(stream) => {
                                if pending_inbound.len() >= MAX_PENDING_INBOUND_STREAMS {
                                    warn!(
                                        limit = MAX_PENDING_INBOUND_STREAMS,
                                        "too many host-inbound streams awaiting guest listener; \
                                         dropping connection for {}:{}",
                                        fwd.guest_ip,
                                        fwd.guest_port
                                    );
                                } else {
                                    debug!(
                                        "inbound TCP: guest listener for {}:{} is not registered yet; \
                                         holding host stream from {peer}",
                                        fwd.guest_ip, fwd.guest_port
                                    );
                                    pending_inbound.push(PendingInbound {
                                        fwd_index,
                                        stream: Some(stream),
                                        peer,
                                        deadline: Instant::now() + INBOUND_LISTENER_GRACE,
                                    });
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        warn!("inbound TCP accept error: {e}");
                        break;
                    }
                }
            }
        }

        let mut pfds: Vec<PollFd> =
            Vec::with_capacity(2 + pending_handshakes.len() + inbound_listeners.len());
        pfds.push(PollFd {
            fd: ipc_raw,
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
        for ph in &pending_handshakes {
            pfds.push(PollFd {
                fd: ph.raw_socket,
                events: POLLIN,
                revents: 0,
            });
        }
        for fwd in &inbound_listeners {
            pfds.push(PollFd {
                fd: raw_socket(&fwd.listener),
                events: POLLIN,
                revents: 0,
            });
        }

        let ret = sock_compat::poll_fds(&mut pfds, 100);
        if ret < 0 {
            warn!(
                "network proxy poll failed: {}",
                sock_compat::last_socket_error()
            );
            break;
        }
        if pfds
            .first()
            .is_some_and(|pfd| pfd.revents & (POLLHUP | POLLERR) != 0)
        {
            match drain_ipc_frames(ipc_raw) {
                IpcLoopState::Continue | IpcLoopState::Shutdown => break,
                IpcLoopState::ProtocolError => {
                    device::send_shutdown(ipc_raw);
                    break;
                }
            }
        }
    }

    device::send_shutdown(ipc_raw);
    info!("network proxy shut down");
    Ok(())
}

fn drain_pending_inbound(
    pending_inbound: &mut Vec<PendingInbound>,
    inbound_listeners: &[inbound_forward::InboundForward],
    state_registry: Option<&BrokerStateRegistry>,
) {
    pending_inbound.retain_mut(|pending| {
        if Instant::now() >= pending.deadline {
            if let Some(fwd) = inbound_listeners.get(pending.fwd_index) {
                warn!(
                    "timed out waiting for guest listener {}:{}, dropping held host stream from {}",
                    fwd.guest_ip, fwd.guest_port, pending.peer
                );
            }
            return false;
        }

        let Some(fwd) = inbound_listeners.get(pending.fwd_index) else {
            return false;
        };
        let Some(stream) = pending.stream.take() else {
            return false;
        };

        match inbound_forward::try_accept_broker_held(fwd, stream, pending.peer, state_registry) {
            inbound_forward::BrokerHeldAccept::Delivered
            | inbound_forward::BrokerHeldAccept::Rejected => false,
            inbound_forward::BrokerHeldAccept::NoListener(stream) => {
                pending.stream = Some(stream);
                true
            }
        }
    });
}

enum IpcLoopState {
    Continue,
    Shutdown,
    ProtocolError,
}

fn drain_ipc_frames(ipc_raw: RawSock) -> IpcLoopState {
    loop {
        match device::drain_one_ipc_frame(ipc_raw) {
            IpcDrainResult::Frame => {
                debug!("discarded obsolete worker-local inet frame");
            }
            IpcDrainResult::WouldBlock => return IpcLoopState::Continue,
            IpcDrainResult::Closed => return IpcLoopState::Shutdown,
            IpcDrainResult::ProtocolError => return IpcLoopState::ProtocolError,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_pending_handshakes(
    pending_handshakes: &mut Vec<PendingHandshake>,
    local_services: &Arc<LocalServiceRegistry>,
    session_slots: &Arc<AtomicUsize>,
    sandbox_policy: Option<Arc<SandboxPolicy>>,
    audit_log: Option<AuditLog>,
    state_registry: Option<Arc<BrokerStateRegistry>>,
) {
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
            return true;
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
            let local_services = Arc::clone(local_services);
            let Some(session_permit) = try_acquire_lbnp_session_permit(session_slots) else {
                warn!(
                    limit = MAX_ADDITIONAL_LBNP_SESSIONS,
                    "too many concurrent additional LBNP sessions; dropping connection"
                );
                return false;
            };
            let session_slots = Arc::clone(session_slots);
            let sandbox_policy = sandbox_policy.clone();
            let audit_log = audit_log.clone();
            let state_registry_for_session = state_registry.clone();
            std::thread::spawn(move || {
                let _session_permit = session_permit;
                if let Err(e) = send_handshake_response(&stream) {
                    warn!("failed to send accepted LBNP handshake response: {e}");
                    return;
                }
                info!("accepted additional LBNP client, handshake complete");
                if let Err(e) = run_inner(
                    stream,
                    true,
                    local_services,
                    None,
                    session_slots,
                    sandbox_policy,
                    audit_log,
                    vec![],
                    state_registry_for_session,
                ) {
                    tracing::error!("network proxy error: {e}");
                }
            });
            return false;
        }
        if magic == b"LB9P" {
            if lb9p_handshake::drain_pending_lb9p_connection(&mut ph.stream, local_services)
                == PendingLb9pResult::KeepWaiting
            {
                return true;
            }
        } else {
            debug!("accepted connection with unknown handshake magic, dropping");
        }
        false
    });
}

/// Accept the IPC network-proxy client from `listener`.
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
                break false;
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

            if lb9p_handshake::handle_accepted_lb9p_connection(
                stream,
                raw_socket,
                local_services,
                client_deadline,
            ) {
                return Ok(None);
            }
            continue;
        }

        if &buf[0..4] != HANDSHAKE_MAGIC {
            debug!("rejected connection: wrong magic {:02x?}", &buf[0..4]);
            continue;
        }

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
                break false;
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

        send_handshake_response(&stream)?;
        info!(
            version,
            mtu, "accepted valid LBNP client, handshake complete"
        );
        return Ok(Some(stream));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    #[cfg(windows)]
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;

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
            Arc::new(move |_writer, _reader, _conn_id| {
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

            let mut ack = [0u8; 9];
            stream.read_exact(&mut ack).expect("read ring ACK");
            assert_eq!(ack[0], LB9P_RING_ACK, "broker should ACK ring metadata");
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
            Arc::new(move |_writer, _reader, _conn_id| {
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

            let mut ack = [0u8; 9];
            stream.read_exact(&mut ack).expect("read ring ACK");
            assert_eq!(ack[0], LB9P_RING_ACK, "broker should ACK ring metadata");
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
        let socket_dir = std::path::Path::new("target").join("s");
        std::fs::create_dir_all(&socket_dir).expect("create test socket dir");
        let path = socket_dir.join(format!("np-{unique}.sock"));
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
