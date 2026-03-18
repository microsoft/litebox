# IPC Network Proxy for Litebox

> **Status:** Design proposal. The `IPInterfaceProvider` trait and smoltcp
> integration exist today; the IPC transport, broker network proxy mode, and
> policy layers described below are **not yet implemented**.

## Problem Statement

Litebox currently uses TUN devices for guest networking. On Linux this requires
root (`ip tuntap add`, iptables NAT, dnsmasq). On Windows it requires a kernel
driver (WinTUN) and Administrator privileges (adapter creation, `New-NetNat`).

This setup friction is the single largest barrier to running Copilot (or any
networked program) in the sandbox. It also limits deployment scenarios —
containers, CI runners, and unprivileged developer machines cannot use TUN.

## Scope

**In scope (Phase 1):** Outbound TCP and UDP connections initiated by the
guest (e.g., HTTPS API calls, DNS queries). This covers the primary Copilot
workload.

**Out of scope for IPC mode (initially):** Inbound connections to guest
server sockets (`bind`/`listen`/`accept`). The current TUN-based networking
supports inbound connections and has end-to-end tests for this. IPC mode
will not support inbound connections in Phase 1 — this requires a
reverse-proxy design in the broker (accepting host-side connections and
forwarding into the guest's smoltcp) which is deferred to a future phase.
The TUN backend remains available for workloads that need server sockets.

## Goals

1. **Zero admin/root** — the runner and broker both run as a regular user.
2. **Cross-platform** — same architecture on Linux, Windows, and future platforms.
3. **Preserve security model** — smoltcp remains the guest's TCP/IP stack;
   untrusted guest packets never reach the host kernel's network stack.
4. **Extensible to policy enforcement** — the broker becomes a natural point
   for allow/deny rules, rate limiting, DNS control, audit logging, and
   future TLS interception (MITM).
5. **Minimal changes to litebox core and the shim** — the `IPInterfaceProvider`
   trait already provides the right abstraction. Runner plumbing to set up IPC
   connections and pass them to the platform layer will be needed, but the core
   sandbox logic and shim syscall handlers remain unchanged. The runners do
   have significant TUN-specific coupling today (see [Runner Plumbing
   Changes](#runner-plumbing-changes)) that must be refactored.

## Design

### Architecture

```
┌─────────────────────────────────────────────────────┐
│  Sandbox (litebox runner process)                   │
│                                                     │
│  Guest app ──→ shim syscall handlers                │
│                    │                                │
│                    ▼                                │
│               smoltcp (guest TCP/IP stack)           │
│                    │                                │
│                    ▼                                │
│         IPInterfaceProvider::send/receive            │
│             (IPC implementation)                    │
│                    │                                │
└────────────────────┼────────────────────────────────┘
                     │  Named pipe (Win) / Unix socket (Linux)
                     │  Raw IP packets as framed messages
                     ▼
┌─────────────────────────────────────────────────────┐
│  Broker process (unprivileged)                      │
│                                                     │
│  IPC listener                                       │
│       │                                             │
│       ▼                                             │
│  smoltcp (broker TCP/IP stack)                      │
│       │  ← terminates guest TCP/UDP connections     │
│       ▼                                             │
│  Byte streams / datagrams                           │
│       │                                             │
│       ▼                                             │
│  Host socket API                                    │
│  (TcpStream::connect, UdpSocket::send_to, ...)     │
│                                                     │
│  ┌─ Extensible layer stack ──────────────────────┐  │
│  │  streams → [TLS termination] → [HTTP parse]   │  │
│  │         → [policy engine]   → [audit log]     │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

The key insight: the broker runs its **own smoltcp instance** to terminate
guest TCP/UDP connections. This gives the broker clean byte streams (TCP) and
datagrams (UDP) without any manual IP/TCP header parsing or seq/ack
bookkeeping. smoltcp is already a project dependency and is battle-tested.

### Packet Flow

**TCP connection establishment:**

```
1. Guest calls connect(93.184.216.34:443)
2. Runner smoltcp constructs SYN → IP packet → IPC pipe
3. Broker peeks SYN, creates listen socket, feeds to smoltcp
4. Broker smoltcp completes TCP handshake with runner smoltcp
5. Broker sees ESTABLISHED socket → starts host TcpStream::connect()
6. Guest connect() returns (before host connect completes — see Error Propagation)
```

**Data transfer:**

```
1. Guest calls send(data)
2. Runner smoltcp wraps in TCP segment → IP packet → IPC
3. Broker smoltcp receives, delivers bytes to broker TCP socket
4. Broker reads byte stream, writes to host TcpStream
5. Host response arrives on host TcpStream::read()
6. Broker writes response bytes to broker smoltcp TCP socket
7. Broker smoltcp wraps in TCP segment → IP packet → IPC
8. Runner smoltcp delivers to guest recv()
```

**UDP (e.g., DNS):**

```
1. Guest sends UDP datagram to 10.0.0.1:53 (the guest's configured DNS resolver)
2. Broker smoltcp receives UDP datagram with parsed src/dst
3. Broker forwards payload via host UdpSocket::send_to() to upstream DNS
4. Response arrives, broker writes to smoltcp UDP socket → IP packet → IPC → guest
```

**ICMP:**

```
1. Guest sends ICMP echo request (e.g., ping)
2. Broker smoltcp receives ICMP packet
3. Broker can: (a) proxy via host raw socket (needs CAP_NET_RAW),
   (b) synthesize echo reply locally, or (c) drop silently
4. For sandboxed workloads, option (b) or (c) is sufficient
```

Note: in all flows, **neither side does manual header parsing or synthesis**.
Both smoltcp instances handle TCP state machines, seq/ack, retransmits, and
windowing. The broker only shuttles byte streams and datagrams.

### IPC Transport

**Framing:** Each message is prefixed with a 4-byte little-endian length
header. This is necessary because pipes/sockets are stream-oriented while IP
packets are message-oriented.

```
┌──────────┬─────────────────────────┐
│ len (u32)│  IP packet (len bytes)  │
└──────────┴─────────────────────────┘
```

**Handshake:** On connection, the runner sends a hello message before any IP
packets:

```
┌─────────┬─────────┬──────┐
│ magic   │ version │ MTU  │
│ (4B)    │ (u16)   │(u16) │
└─────────┴─────────┴──────┘
```

- `magic`: `b"LBNP"` (LiteBox Network Proxy)
- `version`: protocol version (initially `1`)
- `MTU`: maximum IP packet size (must match both smoltcp instances; currently
  `1600`)

The broker responds with the same structure. If versions or MTUs don't match,
the connection is rejected.

**Validation:** The receiver must reject frames with `len > 65535` (maximum
IP packet size) to prevent memory exhaustion from malformed or malicious
length prefixes.

**Shutdown:** A frame with `len = 0` signals graceful shutdown. The receiver
should drain in-flight data and close its end.

**Platform-specific transport:**

| Platform | Transport | Why |
|---|---|---|
| Linux | Unix domain socket pair (`socketpair()`) | No filesystem path needed, `poll()`-able, inherits parent permissions |
| Windows | Named pipe (`\\.\pipe\litebox-net-{id}`) | Native, no driver needed, `WaitForSingleObject`-able |

Both are bidirectional, support non-blocking I/O, and require no privileges.

**IPC security:**

- **Linux:** Prefer `socketpair()` (no filesystem path, no access control
  issues). If a filesystem socket is needed, create it in `$XDG_RUNTIME_DIR`
  with `0700` directory permissions.
- **Windows:** Named pipes must be created with an explicit security
  descriptor restricting access to the current user's SID. Without a DACL,
  any process on the machine can connect to `\\.\pipe\litebox-net-*`.
- **Windows I/O:** Named pipes require `FILE_FLAG_OVERLAPPED` for proper
  non-blocking I/O. Use `GetOverlappedResult` or an event object for
  waiting, not simple `ReadFile`/`WriteFile`.

### Broker: TCP Peer via smoltcp

The broker runs its own smoltcp instance, configured as the "other end" of
the guest's network. Raw IP packets arrive over IPC; smoltcp demultiplexes
them into typed sockets (TCP streams, UDP datagrams, ICMP). The broker then
bridges each to the host equivalent.

#### smoltcp Configuration

The broker's smoltcp instance requires specific configuration to accept
packets destined to arbitrary remote IPs (not just the broker's own address):

1. **AnyIP mode.** smoltcp only delivers packets to sockets matching configured
   IP addresses unless `set_any_ip(true)` is called. The broker must enable
   AnyIP and configure a default route (e.g., `0.0.0.0/0` via gateway
   `10.0.0.2`) so that smoltcp accepts packets addressed to any destination.

2. **Pre-allocated listen sockets.** smoltcp does not dynamically create
   sockets for incoming SYNs — it only delivers a SYN to an already-existing
   socket in `State::Listen` that matches the destination port. The guest can
   `connect()` to any port on any IP, so the broker cannot pre-allocate one
   listen socket per port.

   **Solution: wildcard catch-all listener.** The broker maintains a pool of
   TCP sockets listening on `IpListenEndpoint { addr: None, port: 0 }` — this
   is not directly supported by smoltcp (port 0 is rejected). Instead, the
   broker uses one of two approaches:

   - **(a) Packet-peek dispatch.** Before feeding a packet into smoltcp, the
     broker peeks at the IP+TCP headers. If the packet is a SYN to a port/IP
     with no existing listen socket, the broker creates a new `tcp::Socket`,
     calls `listen(IpListenEndpoint { addr: Some(dst_ip), port: dst_port })`,
     adds it to the socket set, then feeds the packet. This is a lightweight
     header read (20 bytes IP + 20 bytes TCP), not full TCP state management.

   - **(b) Port-range pre-allocation.** Pre-allocate listen sockets for common
     port ranges (80, 443, 8080, 53, etc.) and dynamically add sockets for
     uncommon ports on first SYN (same peek as (a) for the fallback case).

   Approach (a) is preferred — it handles arbitrary destinations with no
   configuration and the header peek is trivial compared to the full TCP
   state machine that was rejected in the NAT approach.

3. **Interface IP.** The broker's smoltcp uses `10.0.0.1` (the gateway address
   from the guest's perspective). The guest's smoltcp uses `10.0.0.2`. Both
   use `Medium::Ip` (no Ethernet/ARP layer) which matches the existing
   point-to-point TUN model.

#### Connection Establishment and Error Propagation

The TCP connection flow must handle the timing gap between the broker
accepting the SYN from the guest and the host `TcpStream::connect()`
completing:

```
1. Guest calls connect(93.184.216.34:443)
2. Runner smoltcp constructs SYN → IP packet → IPC pipe
3. Broker peeks at SYN, creates listen socket for 93.184.216.34:443
4. Broker feeds packet into smoltcp; smoltcp completes handshake
5. Broker sees ESTABLISHED socket → starts async host TcpStream::connect()
6. Runner smoltcp completes handshake, guest connect() returns
7. Host connect() result determines what happens next:
   - Success: broker begins relaying data
   - ECONNREFUSED: broker sends RST via smoltcp → guest gets ECONNRESET on
     next send/recv
   - ETIMEDOUT: broker closes smoltcp socket with RST after host timeout
   - ENETUNREACH: broker closes smoltcp socket with RST
```

**Note:** The implementation uses a **late-accept** strategy: on receiving a
guest SYN, the broker starts a non-blocking host `connect()` but does NOT
create the smoltcp listen socket. The guest SYN is silently dropped and will
be retransmitted (~200ms by default). Only after the host connect succeeds
does the broker create the listen socket, so the next SYN retransmit triggers
the smoltcp handshake. This means:

- **Guest `connect()` only succeeds after the real host connection is ready.**
  Failed host connects result in guest TCP timeout (no misleading success).
- **Latency cost:** One SYN retransmit delay (~200ms–1s) per new connection.
  For connection pools or keep-alive, this is a one-time cost. For workloads
  with many short-lived connections, the overhead may be measurable.
- **Parallel connections** to the same server work correctly — each flow is
  tracked by the full 4-tuple (src_ip, src_port, dst_ip, dst_port).

**Full error propagation table:**

| Host error | Broker action | Guest sees |
|---|---|---|
| `connect()` refused | Never create listen socket | TCP timeout (SYN retransmit exhaustion) |
| `connect()` timeout | Never create listen socket | TCP timeout |
| `connect()` unreachable | Never create listen socket | TCP timeout |
| `write()` to closed socket | Close smoltcp socket with RST | `ECONNRESET` on `recv()` |
| DNS resolution failure | Return NXDOMAIN/SERVFAIL via UDP | Guest DNS query fails normally |

#### Broker Event Loop

```rust
// Conceptual sketch — broker event loop
loop {
    // Feed raw IP packets from IPC into broker's smoltcp
    if let Ok(packet) = ipc.receive_framed_packet() {
        // Peek at SYN packets and create listen sockets as needed
        if is_tcp_syn(&packet) {
            ensure_listen_socket(&mut sockets, dst_ip, dst_port);
        }
        smoltcp_device.enqueue_rx(packet);
    }

    // Poll smoltcp — drives TCP state machines, timers, retransmits
    smoltcp_iface.poll(&mut sockets);

    // Detect newly ESTABLISHED sockets → start host connections
    for handle in &newly_established {
        let sock = sockets.get::<tcp::Socket>(handle);
        let dst = sock.remote_endpoint();
        let host_stream = TcpStream::connect(dst);  // async
        tcp_connections.insert(handle, host_stream);
    }

    // Handle TCP: read bytes from smoltcp socket, write to host TcpStream
    for (socket_handle, host_stream) in &mut tcp_connections {
        let smoltcp_sock = sockets.get_mut::<tcp::Socket>(socket_handle);
        if smoltcp_sock.can_recv() {
            let n = smoltcp_sock.recv_slice(&mut buf)?;
            host_stream.write_all(&buf[..n])?;
        }
        if smoltcp_sock.can_send() {
            let n = host_stream.read(&mut buf)?;
            smoltcp_sock.send_slice(&buf[..n])?;
        }
    }

    // Handle UDP: read datagrams from smoltcp, forward via host UdpSocket
    // UDP mappings are created on first datagram; idle mappings are garbage-
    // collected after UDP_IDLE_TIMEOUT (default: 60 seconds).

    // Transmit any outgoing packets from smoltcp back over IPC
    while let Some(packet) = smoltcp_device.dequeue_tx() {
        ipc.send_framed_packet(packet)?;
    }
}
```

**Why not a userspace NAT?** An earlier version of this design had the broker
manually parsing IP/TCP headers, maintaining a connection table with seq/ack
bookkeeping, and synthesizing response packets. This was rejected because:

1. **Manual seq/ack tracking is the hardest part of TCP** — bugs cause
   retransmits, stalls, or silent data corruption.
2. **smoltcp is already a dependency** — reusing it eliminates hand-rolled
   header logic with zero new dependencies.
3. **Layer 7 extensibility** — a NAT only has raw packet fragments; to add
   TLS termination or HTTP inspection it must be refactored into a TCP peer
   anyway. Starting with byte streams avoids the dead-end.

**Protocol handling summary:**

| Protocol | Broker smoltcp provides | Broker bridges to host via |
|---|---|---|
| TCP | Byte stream (`tcp::Socket`) | `TcpStream::connect()` / `read()` / `write()` |
| UDP | Datagrams (`udp::Socket`) | `UdpSocket::send_to()` / `recv_from()` |
| DNS | UDP datagram (port 53) | Host `UdpSocket` to upstream resolver (or L7 interception) |
| ICMP | ICMP packet (`icmp::Socket`) | Synthesize reply, proxy, or drop |

### Platform Layer Changes

**No changes to `IPInterfaceProvider` trait.** The trait already abstracts at
the right level:

```rust
pub trait IPInterfaceProvider {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), SendError>;
    fn receive_ip_packet(&self, packet: &mut [u8]) -> Result<usize, ReceiveError>;
}
```

The existing error types (`SendError::Io(i32)` and `ReceiveError::WouldBlock`)
are marked `#[non_exhaustive]`. New variants may be needed for IPC-specific
failures (pipe disconnected, framing error) but can be added without breaking
changes.

**New IPC-based implementation** (one per platform):

```rust
// Conceptual sketch — Linux
impl IPInterfaceProvider for LinuxUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), SendError> {
        let pipe = self.broker_pipe.lock();
        pipe.write_all(&(packet.len() as u32).to_le_bytes())?;
        pipe.write_all(packet)?;
        Ok(())
    }

    fn receive_ip_packet(&self, buf: &mut [u8]) -> Result<usize, ReceiveError> {
        let pipe = self.broker_pipe.lock();
        let mut len_buf = [0u8; 4];
        match pipe.try_read(&mut len_buf) {
            Ok(4) => { /* read len bytes into buf */ }
            _ => return Err(ReceiveError::WouldBlock),
        }
    }
}
```

**Existing TUN implementations remain** as an alternative backend. The runner
chooses IPC vs TUN based on CLI flags.

### Runner Plumbing Changes

The current runners have significant TUN-specific coupling that must be
refactored for the IPC backend:

1. **Platform construction.** Both Linux and Windows runners pass
   `tun_device_name` to `Platform::new()`. The IPC backend needs a pipe/socket
   handle instead. The platform constructor should accept an enum:
   ```rust
   enum NetworkBackend {
       Tun(String),            // device name
       Ipc(OwnedFd),           // Linux: socketpair fd
       // Ipc(OwnedHandle),    // Windows: named pipe handle
       None,                   // no networking
   }
   ```

2. **`wait_on_tun()`.** Currently a TUN-specific platform API: `poll()` on TUN
   fd (Linux) or `WaitForSingleObject` on WinTUN event (Windows). Must be
   generalized to `wait_on_network()` that works with any fd/handle. For IPC
   on Linux, `poll()` on the Unix socket fd works identically. For IPC on
   Windows, `WaitForSingleObject` works on named pipe handles but requires
   `FILE_FLAG_OVERLAPPED` (see IPC Transport section).

3. **9P broker decoupling.** The `--nine-p-broker` CLI flag currently
   `requires_all = ["unstable", "tun_device_name"]`. This hard dependency
   must be relaxed so that the 9P broker can operate over the IPC network
   backend. The shim's TCP stack connects to the 9P broker at
   `10.0.0.1:5640` — this works identically over IPC since smoltcp handles
   the TCP connection regardless of the underlying `IPInterfaceProvider`.

4. **Network worker startup.** Both runners conditionally start the network
   worker only when `tun_device_name` is present. The condition should be
   generalized to "any network backend configured."

### Security Analysis

**Compared to TUN (current model):**

| Attack vector | TUN | IPC proxy |
|---|---|---|
| Guest-crafted raw IP packets → host kernel | Possible (via TUN device) | Blocked (broker's smoltcp parses in userspace) |
| Host kernel TCP/IP stack bugs | Exposed to raw guest traffic | Only exposed to well-formed socket API calls from the broker |
| Privilege requirements | root / Administrator | None |
| New attack surface | Kernel TUN driver | smoltcp parser in broker (Rust, userspace) |

The IPC proxy model is **stronger for raw packet isolation**: the host kernel
never sees guest-crafted IP packets. However, the host kernel TCP/IP stack is
still involved for the broker's outbound connections via normal socket API
(`connect()`, `send()`, `recv()`). The difference is that the broker
validates and terminates guest traffic before it reaches the kernel — the
kernel only sees well-formed socket operations, not arbitrary packet content.

**Broker compromise.** If a vulnerability in smoltcp or broker code allows
code execution, the attacker gains the broker's unprivileged host socket
access — equivalent to a regular network-connected process. This is not
catastrophic but is worth noting. The broker should be hardened:

- Disable unused smoltcp protocol features (e.g., don't enable raw sockets
  in broker smoltcp if only TCP/UDP are needed).
- Set conservative socket buffer limits to prevent memory exhaustion from a
  malicious guest opening many connections.
- Enforce a maximum concurrent connection limit (configurable, default: 1024).
- Consider fuzzing the broker's smoltcp packet ingestion path.

**smoltcp trust model difference.** On the guest side, smoltcp processes
packets the guest application generates — parsing failures only affect the
guest (already untrusted). On the broker side, smoltcp processes packets from
an untrusted sandbox — this is a higher-stakes trust boundary. The same
library is used on both sides, but broker-side hardening is more important.

**TLS handling:** TLS is negotiated end-to-end between the guest application
and the remote server. The broker relays encrypted byte streams — it cannot
inspect or tamper with TLS content. This preserves the guest's expectations
about TLS security.

**Layer 7 extension (TLS interception / HTTP proxy):** Because the broker
already has clean byte streams from smoltcp, Layer 7 capabilities slot in as
additional processing layers without architectural changes:

```
smoltcp TCP socket → [TLS termination] → [HTTP parser] → [policy engine] → host TLS connection
```

**TLS MITM** requires injecting a broker-controlled CA certificate into the
guest's trust store (achievable via the 9P filesystem — the CA must be
present before any TLS connection attempt). The broker would:

1. Accept guest TLS connection on the smoltcp byte stream using a dynamically
   generated certificate signed by the injected CA. Certificates should be
   **cached by SNI** to avoid key generation latency on every connection.
2. Establish a separate TLS connection to the real destination via host socket.
3. Relay plaintext between the two TLS sessions, with the ability to inspect,
   filter, or log the content.

**Limitations:** Applications using certificate pinning (e.g., some security
tools, mobile SDKs) will reject the MITM certificate and fail. This is an
inherent limitation of any TLS interception approach.

**HTTP-level policy** (once TLS is terminated):

- URL / domain allow/deny rules.
- Request/response body inspection for security scanning.
- Header injection or modification.
- Rate limiting by endpoint.

This layered design is only possible because the TCP peer approach provides
byte streams. A Layer 4 NAT would require reassembling TCP segments into
streams first — effectively reimplementing TCP peer to reach this point.

### Performance

For Copilot's workload (HTTPS API calls, small JSON payloads):

#### Context Switch Analysis

A single packet round-trip in the IPC model involves:

```
1. Guest send() → runner smoltcp → write to pipe     (user→kernel)
2. Broker reads from pipe                             (kernel→user)
3. Broker smoltcp → host TcpStream::write()           (user→kernel)
4. Host TcpStream::read() response                    (kernel→user)
5. Broker smoltcp → write to pipe                     (user→kernel)
6. Runner reads from pipe → runner smoltcp → guest     (kernel→user)
```

That's **6 context switches** per round-trip. The TUN model has a similar
count (TUN fd reads/writes are also kernel-mediated). The per-switch cost is
~1-2 μs, totaling ~6-12 μs per round-trip — negligible compared to network
RTT (~10-100 ms for API calls).

#### Double-TCP Buffering

Each guest TCP connection traverses three independent TCP state machines:
runner smoltcp → broker smoltcp → host kernel. This has implications:

1. **Buffering.** Per-connection memory: runner smoltcp socket buffers
   (currently 256KB = `SOCKET_BUFFER_SIZE = 65536 * 4`) + IPC pipe buffer
   (64KB-1MB depending on OS) + broker smoltcp socket buffers + host kernel
   socket buffers. The broker should use smaller smoltcp buffers (e.g., 64KB)
   since it relays data immediately rather than buffering for the application.

2. **Congestion window interaction.** The runner smoltcp sees IPC-level RTT
   (~microseconds), making its congestion window effectively unbounded for
   WAN connections. This is fine for small API payloads but could cause
   excessive in-flight data for bulk transfers. Broker-side smoltcp buffer
   sizing provides natural backpressure via IPC pipe filling up.

3. **Retransmission.** If the IPC pipe delays packets (unlikely for local
   sockets but possible under memory pressure), both smoltcp instances may
   independently retransmit. This is self-correcting and unlikely to cause
   issues for the target workload.

For the target workload (Copilot HTTPS), these concerns are theoretical. For
high-throughput scenarios, the IPC transport could be upgraded to shared
memory with event signaling, reducing copy overhead and buffering.

| Metric | TUN | IPC proxy | Notes |
|---|---|---|---|
| Round-trip context switches | ~6 | ~6 | Both are kernel-mediated I/O |
| Per-connection memory | ~512KB | ~640KB-1MB | IPC adds broker-side smoltcp buffers |
| DNS resolution | dnsmasq (TUN gateway) | Broker forwards to host resolver | Comparable |

### Implementation Plan

#### Phase 1: IPC transport (MVP)

1. Refactor runner plumbing: `NetworkBackend` enum, generalize `wait_on_tun()`
   to `wait_on_network()`, decouple `--nine-p-broker` from
   `--tun-device-name`.
2. Add IPC-based `IPInterfaceProvider` to both Linux and Windows platforms.
   - Linux: `socketpair()` (no filesystem path).
   - Windows: Named pipe with DACL restricting to current user.
3. Add broker network proxy mode: smoltcp instance with AnyIP, SYN-peek
   listen socket creation, TCP/UDP bridge to host sockets.
4. Runner flag: `--network-broker <pipe-path>` as alternative to
   `--tun-device-name`.
5. IPC handshake: magic + version + MTU exchange.

#### Phase 2: Policy enforcement and DNS

6. Broker config file for allow/deny rules by destination IP, port, domain.
7. DNS interception — broker reads UDP datagrams on port 53 from smoltcp,
   resolves on behalf of the guest, applies domain-based policy.
8. Audit logging of all connection attempts.

#### Phase 3: Layer 7 proxy (TLS interception)

9. Optional TLS MITM mode with CA injection via 9P filesystem.
10. HTTP-level policy engine (URL filtering, header inspection).
11. Content inspection hooks for security scanning.

#### Phase 4 (future): Inbound connections and optimizations

12. Reverse-proxy mode for guest server sockets (broker accepts host-side
    connections, forwards into guest smoltcp).
13. Shared memory IPC transport for high-throughput workloads.

### Backward Compatibility

The TUN-based `IPInterfaceProvider` implementations remain available. The
runner selects the transport based on CLI flags:

- `--tun-device-name <name>` — use TUN device (requires admin/root). *Exists today.*
- `--network-broker <path>` — use IPC to broker (no privileges needed). *Proposed.*

Existing deployments using TUN continue to work unchanged. Workloads
requiring inbound connections (server sockets) must continue using TUN until
Phase 4 reverse-proxy support is implemented.

### Open Design Questions

1. **Broker process model.** Should the network proxy be a new mode of the
   existing `litebox_broker` binary (`--mode network-proxy`) or a separate
   binary? Co-locating allows sharing the policy engine and configuration.
   A separate binary is simpler to develop and test initially.

2. **Multi-sandbox.** Can one broker serve multiple runner processes? If yes,
   each runner gets its own IPC pipe and the broker manages per-connection
   state keyed by IPC connection. If 1:1, the broker is simpler but incurs
   process overhead per sandbox.

3. **Broker lifecycle.** What happens when the broker crashes? The runner's
   smoltcp will retransmit into a dead pipe. The runner should detect IPC
   pipe EOF and surface a clear error to the guest (or shut down
   networking). Reconnection/restart is out of scope for Phase 1.

4. **DNS resolver configuration.** The guest must know to send DNS queries to
   `10.0.0.1:53`. Currently in the TUN model, `dnsmasq` runs at the gateway
   address. In IPC mode, the guest's `/etc/resolv.conf` (served via 9P) must
   point to `10.0.0.1`, and the broker must intercept port-53 UDP.

5. **IPv6.** The current smoltcp configuration is IPv4-only (`proto-ipv4`
   feature, `10.0.0.0/24` network). IPv6 support is out of scope for this
   proposal but the architecture supports it (smoltcp has IPv6 support,
   the IPC transport is IP-version-agnostic).

6. **ICMP and traceroute.** Synthesizing ICMP echo replies is sufficient for
   most workloads, but `traceroute` (which uses ICMP TTL Exceeded) will not
   work. This is an acceptable limitation for sandboxed environments.

### Alternatives Considered

**SOCKS5 proxy.** A SOCKS5 proxy in the broker would be simpler (no smoltcp,
no IPC framing) but requires shim-level changes to redirect socket syscalls
to the proxy. It also loses IP-level isolation — guest traffic would go
through the host kernel's TCP/IP stack directly. It cannot support raw
sockets, ICMP, or UDP easily. Rejected because it violates Goal 3 (preserve
security model).

**virtio-net.** The standard VM networking interface. For litebox's userspace
process model, virtio-net would require either a TAP backend (same privilege
problem as TUN) or a userspace vhost-user implementation (essentially what
this design proposes, with more complexity and less flexibility). Rejected
for unnecessary complexity.

**Raw relay / `SO_ORIGINAL_DST`.** The broker could use raw sockets to relay
packets without terminating TCP. This reintroduces privilege requirements
(`CAP_NET_RAW`) and violates Goal 1. Rejected.
