// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest web access without root: an HTTP proxy on the guest's loopback, bridged to real host
//! sockets.
//!
//! The macOS host has no `tun` device without root, so the guest's IP packets normally have
//! nowhere to go. But the *host* owns the guest's smoltcp stack, so it can terminate guest TCP
//! itself: `LinuxShim::listen_in_guest` plants a host-owned listener at `127.0.0.1:3128`
//! inside the guest's network, and this module speaks just enough HTTP-proxy protocol on the
//! accepted connections to re-originate each request as an ordinary host connection: `CONNECT`
//! remains a byte tunnel, absolute `http://` requests are rewritten to origin form, and absolute
//! `https://` requests (BusyBox's proxy form) receive a system-rooted, hostname-validated TLS hop
//! to the origin. A guest browser pointed at `http_proxy=http://127.0.0.1:3128` browses the real
//! web; the guest itself still cannot emit a single raw packet.
//!
//! Hostname resolution happens here, over UDP directly to the resolvers snapshotted from
//! `/etc/resolv.conf` before the sandbox came up -- deliberately not `getaddrinfo`, whose
//! mDNSResponder path stays closed under the widened Seatbelt profile (see
//! `RUNNER_PROFILE_WITH_OUTBOUND_NETWORK`).

use std::collections::HashMap;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};

use litebox_platform_macos_userland::MacOsUserland as Platform;
use litebox_shim_linux::host_service::{
    DatagramRead, GuestDatagramSocket, GuestListener, GuestStream, StreamRead,
};

/// Where the proxy listens inside the guest network. Fixed rather than configurable until
/// something needs it to move: 3128 is squid's conventional port, and the guest loopback is
/// the one address every guest can already reach.
pub const PROXY_ADDR: (Ipv4Addr, u16) = (Ipv4Addr::LOCALHOST, 3128);

/// Load the host trust store into a pure-Rust TLS configuration while host files and Security
/// framework services are still reachable. The runner must call this before installing Seatbelt;
/// subsequent handshakes use only this in-memory root set and ordinary outbound sockets.
///
/// rustls only enables TLS 1.2 and 1.3, and its default verifier performs both chain and hostname
/// validation. Passing the origin host as [`ServerName`] also supplies SNI for DNS names.
pub fn build_tls_client_config() -> io::Result<Arc<ClientConfig>> {
    let native = rustls_native_certs::load_native_certs();
    let source_errors = native.errors.len();
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(native.certs);
    if added == 0 {
        return Err(io::Error::other(format!(
            "host trust store yielded no usable certificates ({source_errors} load errors, {ignored} invalid certificates)"
        )));
    }
    if source_errors != 0 || ignored != 0 {
        litebox_util_log::debug!(
            source_errors:% = source_errors,
            ignored:% = ignored,
            added:% = added;
            "net-proxy: skipped unusable host trust anchors"
        );
    }
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// Open the host's unprivileged IPv4 ping socket before Seatbelt is installed.
///
/// Darwin permits `SOCK_DGRAM`/`IPPROTO_ICMP` without root and limits it to echo traffic; raw
/// sockets remain unavailable. The descriptor is retained by [`serve_icmp`] for the runner's
/// lifetime.
pub fn open_icmp_socket() -> io::Result<OwnedFd> {
    // SAFETY: constant socket arguments have no pointer preconditions.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `socket` and is not owned elsewhere.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: `fd` is live; a failed close-on-exec hint does not affect socket correctness.
    unsafe {
        libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
    }
    Ok(fd)
}

/// Serve the shim's bounded ICMP Echo bridge over its private in-guest UDP endpoint.
///
/// Requests and responses carry a four-byte IPv4 address prefix followed by one ICMP message.
/// Both ends accept Echo Request/Reply only; no arbitrary raw packet can traverse this channel.
/// An echo to one of the guest's own addresses (`local_ips`: its interface and gateway, plus
/// loopback) is answered here directly -- those addresses exist only inside the guest's
/// synthetic network, so forwarding them to the host would ping some unrelated LAN host or
/// nothing at all.
pub fn serve_icmp(socket: &GuestDatagramSocket<Platform>, host: OwnedFd, local_ips: [Ipv4Addr; 2]) {
    const MAX_FRAME_SIZE: usize = 4 + 4096;
    let mut frame = [0u8; MAX_FRAME_SIZE];
    loop {
        let (len, from) = match socket.try_recv_from(&mut frame) {
            DatagramRead::Data { len, from } => (len, from),
            DatagramRead::Empty => {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
        };
        let Some(response) = local_icmp_echo(&frame[..len], &local_ips)
            .or_else(|| proxy_icmp_echo(&host, &frame[..len]))
        else {
            continue;
        };
        // A full guest UDP ring is transient. Retry for a short bound rather than losing a real
        // echo reply at exactly the point the guest is waiting for it.
        for _ in 0..50 {
            if socket.try_send_to(&response, from) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Synthesize the Echo Reply for a request aimed at one of the guest's own addresses (or
/// loopback): the request with its type flipped and checksum redone. `None` for anything else,
/// or for a frame that is not a well-formed Echo Request.
fn local_icmp_echo(frame: &[u8], local_ips: &[Ipv4Addr]) -> Option<Vec<u8>> {
    const PREFIX: usize = litebox::net::ICMP_ECHO_PROXY_PREFIX_LEN;
    if !(PREFIX + 8..=PREFIX + 4096).contains(&frame.len()) {
        return None;
    }
    let target = Ipv4Addr::new(frame[0], frame[1], frame[2], frame[3]);
    if !(target.is_loopback() || local_ips.contains(&target)) {
        return None;
    }
    let request = &frame[PREFIX..];
    if request[0] != 8 || request[1] != 0 {
        return None;
    }
    let mut reply = request.to_vec();
    reply[0] = 0; // Echo Reply
    reply[2..4].copy_from_slice(&[0, 0]);
    let checksum = icmp_checksum(&reply).to_be_bytes();
    reply[2..4].copy_from_slice(&checksum);
    let mut response = Vec::with_capacity(PREFIX + reply.len());
    response.extend_from_slice(&target.octets());
    response.extend_from_slice(&reply);
    Some(response)
}

fn proxy_icmp_echo(host: &OwnedFd, frame: &[u8]) -> Option<Vec<u8>> {
    const PREFIX: usize = litebox::net::ICMP_ECHO_PROXY_PREFIX_LEN;
    if !(PREFIX + 8..=PREFIX + 4096).contains(&frame.len()) {
        return None;
    }
    let target = Ipv4Addr::new(frame[0], frame[1], frame[2], frame[3]);
    if target.is_unspecified() || target.is_multicast() || target == Ipv4Addr::BROADCAST {
        return None;
    }
    let request = &frame[PREFIX..];
    if request[0] != 8 || request[1] != 0 {
        return None;
    }
    let original_id = [request[4], request[5]];
    let sequence = [request[6], request[7]];
    let payload = &request[8..];

    // Darwin's `sockaddr_in` contains an explicit length byte. `s_addr` is stored in network byte
    // order, so constructing the native integer from the desired memory-order octets preserves the
    // address bytes on both host endiannesses.
    // SAFETY: all-zero is a valid baseline for `sockaddr_in`.
    let mut destination: libc::sockaddr_in = unsafe { core::mem::zeroed() };
    destination.sin_len = u8::try_from(core::mem::size_of::<libc::sockaddr_in>()).ok()?;
    destination.sin_family = u8::try_from(libc::AF_INET).ok()?;
    destination.sin_addr.s_addr = u32::from_ne_bytes(target.octets());
    // SAFETY: all pointers reference live values for the exact lengths supplied.
    let sent = unsafe {
        libc::sendto(
            host.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&raw const destination).cast(),
            u32::from(destination.sin_len),
        )
    };
    if usize::try_from(sent).ok()? != request.len() {
        return None;
    }

    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut packet = [0u8; 4160];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let mut pollfd = libc::pollfd {
            fd: host.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
        // SAFETY: `pollfd` is one live element and the timeout is bounded above.
        let ready = unsafe { libc::poll(&raw mut pollfd, 1, timeout_ms) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
        if ready == 0 {
            return None;
        }

        // SAFETY: all-zero is a valid baseline for `sockaddr_in`; recvfrom receives at most the
        // live packet buffer and writes the supplied address/length objects.
        let mut source: libc::sockaddr_in = unsafe { core::mem::zeroed() };
        let mut source_len = u32::try_from(core::mem::size_of::<libc::sockaddr_in>()).ok()?;
        let received = unsafe {
            libc::recvfrom(
                host.as_raw_fd(),
                packet.as_mut_ptr().cast(),
                packet.len(),
                0,
                (&raw mut source).cast(),
                &raw mut source_len,
            )
        };
        let Ok(received) = usize::try_from(received) else {
            continue;
        };
        if Ipv4Addr::from(source.sin_addr.s_addr.to_ne_bytes()) != target {
            continue;
        }
        let ip_header_len = match packet.first() {
            Some(first) if first >> 4 == 4 => usize::from(first & 0x0f) * 4,
            _ => 0,
        };
        let end = ip_header_len.checked_add(8)?;
        if received < end {
            continue;
        }
        let reply = &packet[ip_header_len..received];
        if reply[0] != 0 || reply[1] != 0 || reply[6..8] != sequence || reply[8..] != *payload {
            continue;
        }

        // Darwin assigns its own identifier to an unprivileged ping socket. Restore the guest's
        // identifier and checksum so stock Linux ping sees the reply it requested.
        let mut reply = reply.to_vec();
        reply[2..4].copy_from_slice(&[0, 0]);
        reply[4..6].copy_from_slice(&original_id);
        let checksum = icmp_checksum(&reply).to_be_bytes();
        reply[2..4].copy_from_slice(&checksum);
        let mut response = Vec::with_capacity(PREFIX + reply.len());
        response.extend_from_slice(&target.octets());
        response.extend_from_slice(&reply);
        return Some(response);
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the carry-folding loop leaves `sum` within 16 bits before the final cast"
)]
fn icmp_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let [last] = remainder {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Snapshot the host's DNS resolvers while `/etc/resolv.conf` is still readable (pre-sandbox),
/// then append well-known public resolvers as a fallback.
///
/// The host's configured resolver(s) are tried first, but some networks (corporate VPNs
/// enforcing DNS-over-HTTPS/TLS, for instance) silently drop plain UDP port 53 to the
/// resolver an OS has configured while still permitting it to other addresses -- observed on
/// a network where `/etc/resolv.conf`'s `1.0.0.1` never answered a raw UDP query but `8.8.8.8`
/// did. `Resolver::query` already tries every entry in order and only fails if all of them do,
/// so appending (not replacing with) the fallbacks costs nothing when the host resolver works
/// and recovers transparently when it doesn't.
pub fn snapshot_resolvers() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let mut it = line.split_whitespace();
            if it.next() == Some("nameserver")
                && let Some(addr) = it.next()
                && let Ok(IpAddr::V4(v4)) = addr.parse::<IpAddr>()
            {
                out.push(v4);
            }
        }
    }
    for fallback in [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)] {
        if !out.contains(&fallback) {
            out.push(fallback);
        }
    }
    out
}

/// What one name lookup established, as the guest-facing responder must report it.
#[derive(Clone)]
enum Lookup {
    /// `NOERROR` with these A records -- possibly none at all (a real name with no A record).
    Answers(Vec<Ipv4Addr>),
    /// The name does not exist (`NXDOMAIN`).
    NxDomain,
    /// No upstream produced a usable answer within the budget (`SERVFAIL`). Never cached.
    ServFail,
}

/// A minimal, cache-backed A-record resolver over plain UDP port 53. Shared read-only between
/// the HTTP proxy's thread and the DNS responder's worker pool; the cache is the only mutable
/// state and is held only for the duration of a hash lookup, never across an upstream query.
struct Resolver {
    servers: Vec<Ipv4Addr>,
    cache: std::sync::Mutex<HashMap<String, (Lookup, Instant)>>,
}

static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(0x1337);

impl Resolver {
    const TTL: Duration = Duration::from_mins(2);
    /// `NXDOMAIN`/`NODATA` are remembered briefly too: a resolver retrying a bad name (musl
    /// fires A and AAAA, `getaddrinfo` callers retry) must not re-pay the upstream round trip.
    const NEGATIVE_TTL: Duration = Duration::from_secs(30);
    const QUERY_BUDGET: Duration = Duration::from_secs(4);

    fn new(servers: Vec<Ipv4Addr>) -> Self {
        Self {
            servers,
            cache: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The addresses for `host`, or none when it has no A record, does not exist, or could not
    /// be resolved -- the HTTP proxy's `502` does not distinguish those.
    fn resolve_until(&self, host: &str, deadline: Instant) -> Vec<Ipv4Addr> {
        match self.lookup(host, deadline) {
            Lookup::Answers(ips) => ips,
            Lookup::NxDomain | Lookup::ServFail => Vec::new(),
        }
    }

    fn normalize(host: &str) -> String {
        host.trim_end_matches('.').to_ascii_lowercase()
    }

    /// A still-fresh cached lookup for an already-normalized name.
    fn cached(&self, host: &str) -> Option<Lookup> {
        let cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (lookup, at) = cache.get(host)?;
        let ttl = match lookup {
            Lookup::Answers(ips) if !ips.is_empty() => Self::TTL,
            _ => Self::NEGATIVE_TTL,
        };
        (at.elapsed() < ttl).then(|| lookup.clone())
    }

    fn lookup(&self, host: &str, deadline: Instant) -> Lookup {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Lookup::Answers(vec![ip]);
        }
        let host = Self::normalize(host);
        if host.is_empty() || host.len() > 253 {
            return Lookup::NxDomain;
        }
        if let Some(hit) = self.cached(&host) {
            return hit;
        }
        let dns_deadline = deadline.min(Instant::now() + Self::QUERY_BUDGET);
        let result = self.query(&host, dns_deadline);
        if !matches!(result, Lookup::ServFail) {
            self.cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(host, (result.clone(), Instant::now()));
        }
        result
    }

    fn query(&self, host: &str, deadline: Instant) -> Lookup {
        let id = DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        let mut packet = vec![
            id[0], id[1], // id
            0x01, 0x00, // RD
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1 question
        ];
        for label in host.split('.') {
            let bytes = label.as_bytes();
            if bytes.is_empty() || bytes.len() > 63 {
                return Lookup::NxDomain;
            }
            packet.push(u8::try_from(bytes.len()).unwrap_or(0));
            packet.extend_from_slice(bytes);
        }
        packet.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]); // root, A, IN
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                litebox_util_log::debug!(error:% = e; "net-proxy: dns udp bind failed");
                return Lookup::ServFail;
            }
        };
        for (index, server) in self.servers.iter().enumerate() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let servers_left = u32::try_from(self.servers.len() - index).unwrap_or(1);
            let server_budget = (remaining / servers_left)
                .max(Duration::from_millis(1))
                .min(remaining);
            if let Err(e) = sock.set_read_timeout(Some(server_budget)) {
                litebox_util_log::debug!(error:% = e; "net-proxy: dns timeout setup failed");
                continue;
            }
            let expected_source = SocketAddr::from((*server, 53));
            if let Err(e) = sock.send_to(&packet, expected_source) {
                litebox_util_log::debug!(error:% = e; "net-proxy: dns send failed");
                continue;
            }
            let server_deadline = deadline.min(Instant::now() + server_budget);
            loop {
                let response_budget = server_deadline.saturating_duration_since(Instant::now());
                if response_budget.is_zero() {
                    break;
                }
                let _ = sock.set_read_timeout(Some(response_budget));
                let mut buf = [0u8; 4096];
                let (n, source) = match sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        litebox_util_log::debug!(error:% = e; "net-proxy: dns recv failed");
                        break;
                    }
                };
                if source != expected_source {
                    continue;
                }
                match parse_dns_response(&buf[..n], id) {
                    Some(answer @ (Lookup::Answers(_) | Lookup::NxDomain)) => return answer,
                    // This server could not answer (SERVFAIL/REFUSED): move on to the next one
                    // rather than waiting out its budget for a reply that already came.
                    Some(Lookup::ServFail) => break,
                    None => {}
                }
            }
        }
        Lookup::ServFail
    }
}

/// Classify one matching DNS response: `NXDOMAIN`, a failure code, or the deduplicated A
/// records of a `NOERROR` answer (possibly none). Name compression only needs to be skipped
/// here; the proxy does not need to reconstruct owner names. `None` for a packet that is not a
/// response to `id` at all.
#[expect(
    clippy::similar_names,
    reason = "`qdcount`/`ancount`/`nscount`/`arcount` are the DNS header's own field names"
)]
fn parse_dns_response(msg: &[u8], id: [u8; 2]) -> Option<Lookup> {
    if msg.len() < 12 || msg.get(..2)? != id.as_slice() {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 == 0 {
        return None;
    }
    match flags & 0x000f {
        0 => {}
        3 => return Some(Lookup::NxDomain),
        _ => return Some(Lookup::ServFail),
    }
    let qdcount = usize::from(u16::from_be_bytes([msg[4], msg[5]]));
    let ancount = usize::from(u16::from_be_bytes([msg[6], msg[7]]));
    let nscount = usize::from(u16::from_be_bytes([msg[8], msg[9]]));
    let arcount = usize::from(u16::from_be_bytes([msg[10], msg[11]]));
    let record_count = ancount.checked_add(nscount)?.checked_add(arcount)?;
    let mut pos = 12;
    for _ in 0..qdcount {
        skip_dns_name(msg, &mut pos)?;
        pos = pos.checked_add(4)?;
        if pos > msg.len() {
            return None;
        }
    }
    let mut out = Vec::new();
    for _ in 0..record_count {
        skip_dns_name(msg, &mut pos)?;
        let header_end = pos.checked_add(10)?;
        let header = msg.get(pos..header_end)?;
        let rtype = u16::from_be_bytes([header[0], header[1]]);
        let rclass = u16::from_be_bytes([header[2], header[3]]);
        let rdlen = usize::from(u16::from_be_bytes([header[8], header[9]]));
        pos = header_end;
        let data_end = pos.checked_add(rdlen)?;
        let data = msg.get(pos..data_end)?;
        if rtype == 1 && rclass == 1 && data.len() == 4 {
            let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
        pos = data_end;
    }
    Some(Lookup::Answers(out))
}

fn skip_dns_name(msg: &[u8], pos: &mut usize) -> Option<()> {
    loop {
        let len = *msg.get(*pos)?;
        if len == 0 {
            *pos = pos.checked_add(1)?;
            return Some(());
        }
        if len & 0xc0 == 0xc0 {
            msg.get(pos.checked_add(1)?)?;
            *pos = pos.checked_add(2)?;
            return Some(());
        }
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        *pos = pos.checked_add(1 + usize::from(len))?;
        if *pos > msg.len() {
            return None;
        }
    }
}

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

enum Upstream {
    Plain(TcpStream),
    // Boxed: a TLS stream carries the whole rustls connection state, which would otherwise make
    // every `Upstream` that large (`clippy::large_enum_variant`).
    Tls(Box<TlsStream>),
}

impl std::io::Read for Upstream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl std::io::Write for Upstream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

/// One proxied connection's lifecycle.
enum ConnState {
    /// Accumulating the request head until `\r\n\r\n`.
    ReadingRequest(Vec<u8>),
    /// Pumping bytes both ways.
    Relaying,
}

struct Conn {
    guest: GuestStream<Platform>,
    host: Option<Upstream>,
    state: ConnState,
    /// Bytes destined for the host socket that its kernel buffer hasn't taken yet.
    to_host: Vec<u8>,
    /// Bytes destined for the guest that its TX ring hasn't taken yet.
    to_guest: Vec<u8>,
    /// The host side saw EOF; once `to_guest` drains, the connection is done.
    host_eof: bool,
    /// The guest half-closed its sending side (`shutdown(SHUT_WR)` / close after the request).
    /// That is not the end of the conversation: busybox wget, `nc -q`, and any "send the request
    /// then FIN" client still expect the whole response. Nothing more is read from the guest, the
    /// half-close is propagated to a plain upstream once `to_host` drains, and relaying continues
    /// host -> guest until the origin is done.
    guest_eof: bool,
    /// The upstream's write side has been half-closed (plain TCP only; see `guest_eof`).
    host_write_closed: bool,
}

/// Drive the proxy forever. Runs on its own host thread, spawned before the sandbox comes up
/// (thread creation is unmediated, and the widened profile keeps `connect` working after).
pub fn serve(listener: &GuestListener<Platform>, resolvers: Vec<Ipv4Addr>, tls: Arc<ClientConfig>) {
    let resolver = Resolver::new(resolvers);
    let mut conns: Vec<Conn> = Vec::new();
    let mut scratch = vec![0u8; 64 * 1024];
    loop {
        while let Some(guest) = listener.try_accept() {
            litebox_util_log::debug!("net-proxy: accepted a guest connection");
            conns.push(Conn {
                guest,
                host: None,
                state: ConnState::ReadingRequest(Vec::new()),
                to_host: Vec::new(),
                to_guest: Vec::new(),
                host_eof: false,
                guest_eof: false,
                host_write_closed: false,
            });
        }
        let mut progressed = false;
        conns.retain_mut(|conn| match step(conn, &resolver, &tls, &mut scratch) {
            StepOutcome::Progressed => {
                progressed = true;
                true
            }
            StepOutcome::Idle => true,
            StepOutcome::Done => false,
        });
        if !progressed {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

enum StepOutcome {
    Progressed,
    Idle,
    Done,
}

fn step(
    conn: &mut Conn,
    resolver: &Resolver,
    tls: &Arc<ClientConfig>,
    scratch: &mut [u8],
) -> StepOutcome {
    let mut progressed = false;
    match &mut conn.state {
        ConnState::ReadingRequest(head) => match conn.guest.try_read(scratch) {
            StreamRead::Data(n) => {
                head.extend_from_slice(&scratch[..n]);
                if let Some(split) = find_header_end(head) {
                    let body = head.split_off(split);
                    let head = std::mem::take(head);
                    litebox_util_log::debug!(
                        head:% = String::from_utf8_lossy(&head);
                        "net-proxy: request head complete"
                    );
                    let Some((stream, forward, reply)) = open_upstream(&head, resolver, tls) else {
                        let _ = conn
                            .guest
                            .try_write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
                        return StepOutcome::Done;
                    };
                    litebox_util_log::debug!("net-proxy: upstream dialed");
                    conn.host = Some(stream);
                    conn.to_host = forward;
                    conn.to_host.extend_from_slice(&body);
                    conn.to_guest = reply;
                    conn.state = ConnState::Relaying;
                } else if head.len() > 64 * 1024 {
                    // A request head this large is not a real browser's; drop it.
                    return StepOutcome::Done;
                }
                StepOutcome::Progressed
            }
            StreamRead::Empty => StepOutcome::Idle,
            StreamRead::Closed => StepOutcome::Done,
        },
        ConnState::Relaying => {
            let Some(host) = conn.host.as_mut() else {
                return StepOutcome::Done;
            };
            // guest -> host
            if conn.to_host.is_empty() && !conn.guest_eof {
                match conn.guest.try_read(scratch) {
                    StreamRead::Data(n) => {
                        conn.to_host.extend_from_slice(&scratch[..n]);
                        progressed = true;
                    }
                    StreamRead::Empty => {}
                    StreamRead::Closed => {
                        // Half-close, not close: keep relaying the origin's reply.
                        conn.guest_eof = true;
                        progressed = true;
                    }
                }
            }
            if conn.guest_eof && conn.to_host.is_empty() && !conn.host_write_closed {
                conn.host_write_closed = true;
                if let Upstream::Plain(stream) = host {
                    // Propagate the guest's FIN so an origin (or CONNECT tunnel peer) that
                    // waits for end-of-request sees it. A TLS upstream is left open: a
                    // close_notify this early makes some origins drop the request instead of
                    // answering it, and the origin closes on its own after the reply.
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                }
                progressed = true;
            }
            if !conn.to_host.is_empty() {
                match host.write(&conn.to_host) {
                    Ok(n) if n > 0 => {
                        conn.to_host.drain(..n);
                        progressed = true;
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return StepOutcome::Done,
                }
            }
            // host -> guest
            if conn.to_guest.is_empty() && !conn.host_eof {
                match host.read(scratch) {
                    Ok(0) => {
                        conn.host_eof = true;
                        progressed = true;
                    }
                    Ok(n) => {
                        litebox_util_log::debug!(n:% = n; "net-proxy: read from host");
                        conn.to_guest.extend_from_slice(&scratch[..n]);
                        progressed = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return StepOutcome::Done,
                }
            }
            if !conn.to_guest.is_empty() {
                match conn.guest.try_write(&conn.to_guest) {
                    Some(n) if n > 0 => {
                        conn.to_guest.drain(..n);
                        progressed = true;
                    }
                    Some(_) => {}
                    None => return StepOutcome::Done,
                }
            }
            if conn.host_eof && conn.to_guest.is_empty() {
                // Everything the origin had to say is queued toward the guest; the drop path's
                // deferred close FINs once the stack drains it.
                return StepOutcome::Done;
            }
            if progressed {
                StepOutcome::Progressed
            } else {
                StepOutcome::Idle
            }
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parse the request head, connect to the origin, and produce `(stream, bytes_to_forward,
/// immediate_reply_to_guest)`. `CONNECT` remains a raw tunnel and replies `200`; absolute HTTP
/// and HTTPS requests are rewritten to origin form. For absolute HTTPS the proxy terminates the
/// guest's plaintext proxy hop and establishes a separately authenticated TLS connection upstream.
fn open_upstream(
    head: &[u8],
    resolver: &Resolver,
    tls: &Arc<ClientConfig>,
) -> Option<(Upstream, Vec<u8>, Vec<u8>)> {
    const TOTAL_DEADLINE: Duration = Duration::from_secs(20);

    let text = core::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return None;
    }
    let headers = lines
        .take_while(|line| !line.is_empty())
        .map(|line| line.split_once(':'))
        .collect::<Option<Vec<_>>>()?;
    let deadline = Instant::now() + TOTAL_DEADLINE;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target, 443)?;
        let stream = open_origin(resolver, host, port, false, tls, deadline)?;
        return Some((
            stream,
            Vec::new(),
            b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec(),
        ));
    }

    let scheme_end = target.find("://")?;
    let scheme = &target[..scheme_end];
    let (secure, default_port) = if scheme.eq_ignore_ascii_case("http") {
        (false, 80)
    } else if scheme.eq_ignore_ascii_case("https") {
        (true, 443)
    } else {
        return None;
    };
    let rest = target.get(scheme_end + 3..)?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..authority_end)?;
    let (host, port) = split_host_port(authority, default_port)?;
    let suffix = rest.get(authority_end..).unwrap_or_default();
    let suffix = suffix.split_once('#').map_or(suffix, |(path, _)| path);
    let path = if suffix.is_empty() {
        "/".to_owned()
    } else if suffix.starts_with('?') {
        format!("/{suffix}")
    } else if suffix.starts_with('/') {
        suffix.to_owned()
    } else {
        return None;
    };
    let stream = open_origin(resolver, host, port, secure, tls, deadline)?;

    let connection_tokens = headers
        .iter()
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    let mut forward = format!("{method} {path} {version}\r\nHost: {authority}\r\n").into_bytes();
    for (name, value) in headers {
        let name = name.trim();
        if name.is_empty()
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("keep-alive")
            || name.eq_ignore_ascii_case("te")
            || name.eq_ignore_ascii_case("trailer")
            || name.eq_ignore_ascii_case("upgrade")
            || connection_tokens
                .iter()
                .any(|token| name.eq_ignore_ascii_case(token))
        {
            continue;
        }
        forward.extend_from_slice(name.as_bytes());
        forward.extend_from_slice(b":");
        forward.extend_from_slice(value.as_bytes());
        forward.extend_from_slice(b"\r\n");
    }
    forward.extend_from_slice(b"Connection: close\r\n\r\n");
    Some((stream, forward, Vec::new()))
}

fn split_host_port(authority: &str, default_port: u16) -> Option<(&str, u16)> {
    if authority.is_empty()
        || authority.contains('@')
        || authority.starts_with('[')
        || authority.contains(['\r', '\n'])
    {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.contains(':')
                || port.is_empty()
                || !port.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            (host, port.parse::<u16>().ok()?)
        }
        None => (authority, default_port),
    };
    let host = host.trim_end_matches('.');
    (!host.is_empty() && port != 0).then_some((host, port))
}

/// Where the in-guest DNS responder listens. `busybox`'s resolver (used by `ping`, `wget`,
/// `nslookup`, ...) reads `/etc/resolv.conf` for its nameserver and issues a plain UDP query to
/// port 53 -- unlike the HTTP proxy path, which resolves internally and is invisible to any
/// tool that isn't itself HTTP-aware. Loopback, like the TCP proxy: every guest can already
/// reach it, and litebox's guest-root packaging can ship an `/etc/resolv.conf` pointing here.
pub const DNS_ADDR: (Ipv4Addr, u16) = (Ipv4Addr::LOCALHOST, 53);

/// The guest's own host name, as the shim's `uname` reports it; resolved to the interface
/// address so `hostname -i` and anything that looks itself up work without an `/etc/hosts` entry.
const GUEST_HOSTNAME: &str = "litebox";

/// Upstream lookups run on this many worker threads, so one slow or unanswerable name cannot
/// hold every other guest query behind its full [`Resolver::QUERY_BUDGET`].
const DNS_WORKERS: usize = 4;
/// Queries waiting for a free worker beyond this are dropped; the guest's resolver retries,
/// exactly as it would against an overloaded real nameserver.
const DNS_QUEUE_DEPTH: usize = 64;

/// Drive the in-guest DNS responder forever, on its own host thread. For each guest query,
/// resolves the question through [`Resolver`] (the same UDP-to-real-resolvers path the HTTP
/// proxy uses to dial out) and replies with a synthesized A-record answer.
///
/// This answers real questions with real addresses -- resolution is genuine, over the host's
/// actual network -- but nothing else about raw IP networking works here (no ICMP, no other
/// record types): a tool that only needs a name to turn into an address (`wget`, `curl` through
/// the HTTP proxy, TLS `SNI` lookups) is fully served. The separately bounded ICMP Echo bridge
/// also uses this responder for hostname-based `ping`; no general raw-IP path is exposed.
///
/// Anything answerable without the network (AAAA, the guest's own name, `localhost`, an
/// address literal, a cache hit) is answered inline; everything else is handed to a small
/// worker pool so a query stuck waiting on an upstream never delays the next one.
pub fn serve_dns(
    socket: &GuestDatagramSocket<Platform>,
    resolvers: Vec<Ipv4Addr>,
    interface_ip: Ipv4Addr,
) {
    let resolver = Arc::new(Resolver::new(resolvers));
    let (work_tx, work_rx) =
        std::sync::mpsc::sync_channel::<(DnsQuestion, SocketAddr)>(DNS_QUEUE_DEPTH);
    let work_rx = Arc::new(std::sync::Mutex::new(work_rx));
    let (done_tx, done_rx) = std::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>();
    for _ in 0..DNS_WORKERS {
        let work_rx = Arc::clone(&work_rx);
        let done_tx = done_tx.clone();
        let resolver = Arc::clone(&resolver);
        std::thread::spawn(move || {
            loop {
                let job = work_rx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .recv();
                let Ok((question, from)) = job else { return };
                let lookup =
                    resolver.lookup(&question.host, Instant::now() + Resolver::QUERY_BUDGET);
                if done_tx.send((question.reply(&lookup), from)).is_err() {
                    return;
                }
            }
        });
    }
    let mut buf = [0u8; 512];
    loop {
        let mut progressed = false;
        while let Ok((response, to)) = done_rx.try_recv() {
            send_to_guest(socket, &response, to);
            progressed = true;
        }
        if let DatagramRead::Data { len, from } = socket.try_recv_from(&mut buf) {
            progressed = true;
            if let Some(question) = DnsQuestion::parse(&buf[..len]) {
                match question.answer_locally(&resolver, interface_ip) {
                    Some(response) => send_to_guest(socket, &response, from),
                    None => {
                        if work_tx.try_send((question, from)).is_err() {
                            litebox_util_log::debug!(
                                "net-proxy: dns worker queue full; dropping query"
                            );
                        }
                    }
                }
            }
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

/// A full guest UDP ring is transient. Retry for a short bound rather than losing an answer at
/// exactly the point the guest is waiting for it.
fn send_to_guest(socket: &GuestDatagramSocket<Platform>, response: &[u8], to: SocketAddr) {
    for _ in 0..50 {
        if socket.try_send_to(response, to) {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

const QTYPE_A: u16 = 1;
const QCLASS_IN: u16 = 1;
const RCODE_NOERROR: u8 = 0;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;

/// One parsed guest question. The header id and the question section are kept verbatim so
/// the reply echoes back exactly the name/qtype/qclass the guest sent, rather than a
/// re-encoding of them.
struct DnsQuestion {
    id: [u8; 2],
    question: Vec<u8>,
    host: String,
    qtype: u16,
    qclass: u16,
}

impl DnsQuestion {
    /// `None` for a query this responder cannot parse at all (too short, no question, a
    /// compressed or malformed name) -- the guest's resolver retries or times out, the same
    /// outward behavior as an unreachable real nameserver.
    fn parse(query: &[u8]) -> Option<Self> {
        if query.len() < 12 {
            return None;
        }
        let qdcount = u16::from_be_bytes([query[4], query[5]]);
        if qdcount == 0 {
            return None;
        }
        let mut pos = 12;
        let name_start = pos;
        loop {
            let len = *query.get(pos)? as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            // A compressed name can't appear in the question section of a query a real
            // resolver originates, and nothing here originates one either; treat it as
            // malformed.
            if len & 0xc0 == 0xc0 {
                return None;
            }
            pos += 1 + len;
        }
        let name_end = pos;
        let qtype = u16::from_be_bytes([*query.get(pos)?, *query.get(pos + 1)?]);
        let qclass = u16::from_be_bytes([*query.get(pos + 2)?, *query.get(pos + 3)?]);
        pos += 4; // qtype + qclass
        let question_end = pos;

        // Decode the dotted name back out of its length-prefixed labels to resolve it.
        let mut host = String::new();
        let mut label_pos = name_start;
        while label_pos < name_end - 1 {
            let len = query[label_pos] as usize;
            if !host.is_empty() {
                host.push('.');
            }
            host.push_str(
                core::str::from_utf8(query.get(label_pos + 1..label_pos + 1 + len)?).ok()?,
            );
            label_pos += 1 + len;
        }
        Some(Self {
            id: [query[0], query[1]],
            question: query[12..question_end].to_vec(),
            host,
            qtype,
            qclass,
        })
    }

    /// A reply that needs no upstream round trip, or `None` when the name has to be resolved.
    ///
    /// musl's resolver fires A and AAAA queries in parallel and waits for a reply to *both*
    /// before `getaddrinfo` returns -- dropping the AAAA query outright (this responder has no
    /// IPv6 records to offer) left musl's read loop blocked until its own internal timeout,
    /// discarding the A answer it had already received and failing the whole lookup ("bad
    /// address") even though the hostname resolved fine. An explicit NOERROR/ancount=0 reply is
    /// what a real resolver sends for a name with no AAAA records, and completes musl's wait
    /// immediately; the same NODATA shape answers any other record type this responder does not
    /// serve.
    fn answer_locally(&self, resolver: &Resolver, interface_ip: Ipv4Addr) -> Option<Vec<u8>> {
        if self.qclass != QCLASS_IN || self.qtype != QTYPE_A {
            return Some(self.reply(&Lookup::Answers(Vec::new())));
        }
        let host = Resolver::normalize(&self.host);
        let local = match host.as_str() {
            GUEST_HOSTNAME => Some(interface_ip),
            "localhost" | "localhost.localdomain" => Some(Ipv4Addr::LOCALHOST),
            _ => host.parse::<Ipv4Addr>().ok(),
        };
        if let Some(ip) = local {
            return Some(self.reply(&Lookup::Answers(vec![ip])));
        }
        resolver.cached(&host).map(|hit| self.reply(&hit))
    }

    /// Encode `lookup` as the wire reply to this question: `NXDOMAIN`/`SERVFAIL` carry the
    /// question and nothing else; a `NOERROR` answer appends one A record per address.
    fn reply(&self, lookup: &Lookup) -> Vec<u8> {
        let (rcode, ips): (u8, &[Ipv4Addr]) = match lookup {
            Lookup::Answers(ips) => (RCODE_NOERROR, ips),
            Lookup::NxDomain => (RCODE_NXDOMAIN, &[]),
            Lookup::ServFail => (RCODE_SERVFAIL, &[]),
        };
        let ips = &ips[..ips.len().min(16)];
        let mut response = Vec::with_capacity(12 + self.question.len() + 16 * ips.len());
        response.extend_from_slice(&self.id);
        // flags: response, recursion desired + available, rcode
        response.extend_from_slice(&[0x81, 0x80 | rcode]);
        response.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        response.extend_from_slice(&u16::try_from(ips.len()).unwrap_or(0).to_be_bytes());
        response.extend_from_slice(&[0, 0]); // nscount
        response.extend_from_slice(&[0, 0]); // arcount
        response.extend_from_slice(&self.question); // question, verbatim
        for ip in ips {
            response.extend_from_slice(&[0xc0, 0x0c]); // answer name: pointer to question's name
            response.extend_from_slice(&QTYPE_A.to_be_bytes());
            response.extend_from_slice(&QCLASS_IN.to_be_bytes());
            response.extend_from_slice(&60u32.to_be_bytes()); // ttl
            response.extend_from_slice(&4u16.to_be_bytes()); // rdlength
            response.extend_from_slice(&ip.octets());
        }
        response
    }
}

fn open_origin(
    resolver: &Resolver,
    host: &str,
    port: u16,
    secure: bool,
    tls: &Arc<ClientConfig>,
    deadline: Instant,
) -> Option<Upstream> {
    let server_name = if secure {
        match ServerName::try_from(host.to_owned()) {
            Ok(name) => Some(name),
            Err(error) => {
                litebox_util_log::debug!(host:% = host, error:? = error; "net-proxy: invalid TLS server name");
                return None;
            }
        }
    } else {
        None
    };
    let ips = resolver.resolve_until(host, deadline);
    if ips.is_empty() {
        litebox_util_log::debug!(host:% = host; "net-proxy: dns resolution failed");
        return None;
    }
    litebox_util_log::debug!(host:% = host, ips:? = ips; "net-proxy: resolved");

    for (index, ip) in ips.iter().copied().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let addresses_left = u32::try_from(ips.len() - index).unwrap_or(1);
        let mut address_budget = remaining / addresses_left;
        if address_budget.is_zero() {
            address_budget = Duration::from_nanos(1);
        }
        let address_deadline = deadline.min(Instant::now() + address_budget);
        let stream = match TcpStream::connect_timeout(&SocketAddr::from((ip, port)), address_budget)
        {
            Ok(stream) => stream,
            Err(error) => {
                litebox_util_log::debug!(host:% = host, ip:% = ip, error:% = error; "net-proxy: connect failed");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);

        let Some(server_name) = server_name.clone() else {
            if stream.set_nonblocking(true).is_ok() {
                return Some(Upstream::Plain(stream));
            }
            continue;
        };
        let handshake_budget = address_deadline.saturating_duration_since(Instant::now());
        if handshake_budget.is_zero() {
            continue;
        }
        let connection = match ClientConnection::new(tls.clone(), server_name) {
            Ok(connection) => connection,
            Err(error) => {
                litebox_util_log::debug!(host:% = host, error:% = error; "net-proxy: TLS client setup failed");
                return None;
            }
        };
        let mut stream = StreamOwned::new(connection, stream);
        let handshake = loop {
            if !stream.conn.is_handshaking() {
                break Ok(());
            }
            let remaining = address_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TLS handshake deadline expired",
                ));
            }
            let io_budget = remaining.min(Duration::from_millis(500));
            if let Err(error) = stream.sock.set_read_timeout(Some(io_budget)) {
                break Err(error);
            }
            if let Err(error) = stream.sock.set_write_timeout(Some(io_budget)) {
                break Err(error);
            }
            match stream.conn.complete_io(&mut stream.sock) {
                Ok((0, 0)) => std::thread::yield_now(),
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => break Err(error),
            }
        };
        if let Err(error) = handshake {
            litebox_util_log::debug!(host:% = host, ip:% = ip, error:% = error; "net-proxy: TLS handshake failed");
            continue;
        }
        if stream.sock.set_read_timeout(None).is_err()
            || stream.sock.set_write_timeout(None).is_err()
            || stream.sock.set_nonblocking(true).is_err()
        {
            continue;
        }
        return Some(Upstream::Tls(Box::new(stream)));
    }
    None
}
