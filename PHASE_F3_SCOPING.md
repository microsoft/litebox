# Phase F.3 scoping: reclaim broker `net_proxy` after worker-local inet removal

Scope: size the work to shrink `litebox_broker/src/net_proxy/mod.rs` after Phase F.2 removes all linux_userland worker-local `litebox::net::Network<Platform>` usage.  The target end state keeps broker-side responsibilities that are still real after broker-held inet sockets are the only linux_userland inet implementation, and deletes the old per-worker smoltcp router.

## Executive summary

- **Top-line estimate:** remove or move roughly **65-75%** of `mod.rs` by the end of F.3.  The file is 3,480 LOC at `e87d5cb0`; about 700-900 LOC remain in or near `net_proxy` as LBNP/IPC accept, LB9P/shared-memory 9P handshake, inbound forwarders, and DNS resolver advertisement/control-plane glue.
- **Recommended phase count:** 4 phases after F.2: F.3.a extract/lock down keep paths, F.3.b delete outbound TCP/UDP/ICMP smoltcp emulation, F.3.c delete PortRouter/listen-route plumbing, F.3.d cleanup tests/docs/callers and optionally split the survivor module.
- **Main prerequisite:** F.2.a/F.2.b/F.2.c must leave linux_userland unable to construct or drive worker-local `Network`; otherwise deleting the smoltcp event loop strands any remaining packet-framed worker RPCs.
- **pb5 dependency:** `pb5-inet6-tcp` should land before the final delete if AF_INET6 stream sockets still fall back to worker-local `Network` in F.2.  If pb5 is intentionally deferred, F.3 must keep a narrow fallback gate or make AF_INET6 TCP an explicit unsupported broker-path errno before deleting the old router.
- **Likely retained shape:** `net_proxy` stops being a network stack.  It becomes a session acceptor plus host-side forwarder that wires accepted host streams directly into `InetListenerState::accept_inbound`, plus LB9P bootstrap and DNS resolver configuration.

Approximate end-state by current `mod.rs` LOC:

| Category | Current LOC | Approx. share | Summary |
|---|---:|---:|---|
| `KEEP_AS_IS` | ~330-430 | ~10-12% | Parse `--forward-port`, low-level LBNP handshake validation/response, shared-memory LB9P ring receive/ack, a subset of tests. |
| `KEEP_MODIFY` | ~650-900 | ~19-26% | Public `run*` entry points, accepted-client/session loop, local service registry, inbound forward listener setup/accept, DNS advertisement, call-site signatures/tests. |
| `DELETE` | ~2,100-2,500 | ~60-72% | smoltcp `Interface`/`SocketSet`, packet parsing, TCP bridge/listen sockets, UDP flows, ICMP echo synthesis, PortRouter, local TCP 9P bridge, worker listen-route control messages. |

The percentages are intentionally ranges because F.3 may either keep a compatibility shell during migration or move reusable pieces into smaller modules while deleting the same behavior.

## Inventory: `litebox_broker/src/net_proxy/mod.rs`

### Module imports and smoltcp constants

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1-79`
- **Rough LOC:** 79
- **Classification:** `KEEP_MODIFY`
- **Rationale:** This top block mixes survivor constants (`HANDSHAKE_MAGIC`, `HANDSHAKE_VERSION`) with smoltcp-era constants (`BROKER_IP`, `MAX_CONNECTIONS`, `SOCKET_BUFFER_SIZE`, `UDP_IDLE_TIMEOUT`, `TcpFlowKey`, `alloc_inbound_src_port`).  After F.2, keep the LBNP constants and any inbound-forward address helpers, but delete packet-stack constants that exist only for smoltcp sockets.
- **Dependencies first:** F.2.a/F.2.b to guarantee no worker-local packet stack remains; pb5 if AF_INET6 TCP would otherwise still need smoltcp.
- **Notes:** `BROKER_IP` may survive only as a guest-visible address constant for 9P/DNS advertisement.  Do not keep it just because `Interface::update_ip_addrs` used it at `:973-985`.

### TCP bridge / pending outbound-connect state

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:87-120`
- **Rough LOC:** 34
- **Classification:** `DELETE`
- **Rationale:** `TcpBridge` and `PendingConnect` are purely the worker-local smoltcp TCP relay: they connect raw guest TCP packets to host `TcpStream`s after SYN peeking and `promote_established`.  Broker-held `TcpConn` state owns outbound TCP after F.1/F.2, so these structs should disappear with `resolve_pending_connects`, `promote_established`, and `relay_tcp`.
- **Dependencies first:** F.2.b/F.2.c; all AF_INET/AF_INET6 stream connect paths must route through broker-held `TcpConn` or explicitly fail before this is deleted.

### Accepted-client handshake queue

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:112-142`
- **Rough LOC:** 31
- **Classification:** `KEEP_MODIFY`
- **Rationale:** `PendingHandshake`, `HANDSHAKE_ACCEPT_TIMEOUT`, `MAX_ADDITIONAL_LBNP_SESSIONS`, and `MAX_PENDING_ACCEPTED_HANDSHAKES` are still needed when `--network-proxy-listen` accepts additional LBNP clients on the same listener (`run_inner` drains them at `:1577-1752`).  The queue should be kept but moved into an accept/session helper that no longer shares an event loop with smoltcp polling.
- **Dependencies first:** None for keeping.  Simplification should wait for F.3.a extraction so tests cover both initial `accept_ipc_client` and in-loop additional-client handling.

### Inbound forward listener descriptor

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:145-157`
- **Rough LOC:** 13
- **Classification:** `KEEP_MODIFY`
- **Rationale:** `InboundForward` is still the core host-side `--forward-port` listener state.  It should keep only host listener, guest port, and any address metadata required to call `InetListenerState::accept_inbound`; its current smoltcp guest-IP fields are no longer used to synthesize TCP packets.
- **Dependencies first:** F.2.b so every forwarded guest listener is broker-held; F.2.c to remove worker-local listener fallback.

### `PortRouter`, `RoutedStream`, listen-route transfer

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:159-397`
- **Rough LOC:** 239
- **Classification:** `DELETE`
- **Rationale:** This is the smoltcp-era cross-worker port routing table.  It receives worker `LBPL` listen notifications and routes host streams to per-worker smoltcp proxies; after broker-held listeners and shared state handles own listen/accept, cross-worker routing should be through `BrokerStateRegistry` / inherited state handles rather than packet-forwarded streams.
- **Dependencies first:** F.2.c plus any follow-up that removes `litebox_platform_linux_userland::Platform::on_listen_socket_change` notifications at `litebox_platform_linux_userland/src/lib.rs:4873-4891`.  PR/INHERIT tests must pass through broker state, not PortRouter.
- **Notes:** The unit tests at `mod.rs:3107-3156` are PortRouter-only and should be deleted or replaced by broker-state inheritance tests.  Design docs mentioning PortRouter (`docs/design/cross-worker-fd-transport.md`, `docs/audit/cross-worker-state-inventory.md`) need follow-up after the code delete.

### `parse_forward_spec`

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:398-408`
- **Rough LOC:** 11
- **Classification:** `KEEP_AS_IS`
- **Rationale:** `litebox_broker/src/main.rs:91-95` uses this to parse `--forward-port` CLI strings before entering `net_proxy::run*`.  The syntax is independent of smoltcp.
- **Dependencies first:** None.
- **Notes:** It may be moved into a smaller inbound-forward module in F.3.d, but the behavior should not change during deletion phases.

### Host-connect timeout / raw-socket helper / UDP flow state

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:410-473`
- **Rough LOC:** 64
- **Classification:** mixed: `KEEP_MODIFY` for session-slot permit, `DELETE` for host TCP/UDP helpers
- **Rationale:** `LbnpSessionPermit` and `try_acquire_lbnp_session_permit` control additional LBNP sessions and remain useful.  `HOST_CONNECT_TIMEOUT`, `raw_socket`, `UdpFlowKey`, and `UdpFlow` exist for nonblocking host TCP connect and UDP raw-packet forwarding from worker smoltcp and should be deleted once broker-held TCP/UDP are mandatory.
- **Dependencies first:** F.2.b/F.2.c for deleting host-connect/UDP state; none for keeping session permit.

### Shared-memory LB9P ring receive and acknowledgement

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:474-728`
- **Rough LOC:** 255
- **Classification:** `KEEP_AS_IS`
- **Rationale:** This code receives the shared-memory ring transport metadata/fds and ACKs a direct LB9P channel.  It is not smoltcp routing; it is one of the explicit minimum survivors for shared-memory 9P.
- **Dependencies first:** None.  It must remain green while the rest of `net_proxy` is deleted.
- **Notes:** The duplicated `handle_shared_memory_lb9p_connection` cfg bodies at `:689-727` should remain behaviorally identical.  If F.3.d splits modules, this block belongs in `lb9p.rs` or an accept/session module.

### Ring upgrade concurrency guard and spawner

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:729-782`
- **Rough LOC:** 54
- **Classification:** `KEEP_AS_IS`
- **Rationale:** `RingUpgradePermit` and `spawn_shared_memory_lb9p_connection` cap direct LB9P ring upgrades and offload them so the accept loop is not monopolized.  This protects the 9P shared-memory path and should not be coupled to smoltcp deletion.
- **Dependencies first:** None.

### Local service registry and 9P service spawners

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:783-858`
- **Rough LOC:** 76
- **Classification:** `KEEP_MODIFY`
- **Rationale:** `LocalServiceRegistry` is still needed for `accept_ipc_client` to route direct `LB9P` handshakes to either TCP 9P (`register`) or shared-memory ring 9P (`register_ring`).  After worker-local `Network` is gone, the TCP spawner may become a compatibility-only 9P-over-TCP fallback; the ring spawner is the keeper.
- **Dependencies first:** F.2.a/F.2.c decision on linux_userland TUN TCP-9P / 9P-over-TCP fallback.  If fallback is removed, delete `ServiceSpawner` and `register/get` while keeping `RingServiceSpawner`.
- **Call sites:** `litebox_broker/src/main.rs:145-175` registers the TCP 9P spawner; later code registers the ring path in the same builder.  F.3 must update that builder in lockstep with the registry type.

### LocalBridge

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:860-887`
- **Rough LOC:** 28
- **Classification:** `DELETE`
- **Rationale:** `LocalBridge` relays bytes between a smoltcp TCP socket and a local service stream, mainly the legacy 9P-over-BROKER_IP path.  Direct LB9P/shared-memory handshakes bypass this bridge, so it should be removed once the TCP fallback is either deleted or moved elsewhere.
- **Dependencies first:** F.2.c and a decision on 9P-over-TCP/TUN fallback.  If TUN mode remains supported, keep it under a separate `worker_local_inet`-style capability rather than in broker `net_proxy`.

### Public `run` / `run_with_session_slots`

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:889-940`
- **Rough LOC:** 52
- **Classification:** `KEEP_MODIFY`
- **Rationale:** These are the public broker entry points used by `litebox_broker/src/main.rs:334-344` for `--network-proxy-fd` and `:439-449` for `--network-proxy-listen`.  They should survive, but their parameter list can drop `PortRouter` creation and smoltcp-only concepts once `run_inner` is simplified.
- **Dependencies first:** F.3.a should preserve signatures initially to keep callers stable, then F.3.d can narrow signatures after deletion.

### `run_inner` setup: handshake, `IpcDevice`, smoltcp interface, state tables

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:941-1042`
- **Rough LOC:** 102
- **Classification:** mixed: `KEEP_MODIFY` for handshake/inbound setup, `DELETE` for smoltcp state
- **Rationale:** `perform_handshake` and inbound-forward listener binding remain real.  `IpcDevice`, `Interface`, `SocketSet`, `tcp_bridges`, `local_bridges`, `pending_connects`, `listen_sockets`, `accepting_sockets`, `udp_flows`, and `dns_tracker` here are the worker-local packet router and should not survive as runtime state.
- **Dependencies first:** F.2.b/F.2.c.  DNS tracker deletion or relocation depends on whether hostname-based sandbox policy still observes DNS via broker-held UDP after F.2.
- **Important keeper:** `registry.add_inbound_forwarded_port(*guest_port)` at `:1025-1027` is required for virtual bind; it connects to `BrokerStateRegistry::add_inbound_forwarded_port` at `litebox_broker/src/cwfd/state_registry.rs:535-548` and `state_service.rs:1995-2006`.

### Worker port-listen control messages (`LBPL`)

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1049-1125`
- **Rough LOC:** 77
- **Classification:** `DELETE`
- **Rationale:** This dispatches `IpcDevice::take_port_listen_msg` and updates PortRouter on Listen/Unlisten/Transfer.  Once worker-local `Network` no longer emits listen-route notifications and broker-held listener inheritance owns the state, this control plane is dead.
- **Dependencies first:** F.2.c, plus removal of `send_port_listen_notification` / `on_listen_socket_change` paths from linux_userland.
- **Risk:** Do not delete until `PR.*` and `INHERIT.*` probes prove inherited broker-held listeners still survive fork/exec and cross-worker connection attempts.

### SYN peeking and outbound TCP routing

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1127-1374`
- **Rough LOC:** 248
- **Classification:** `DELETE`
- **Rationale:** This is the core smoltcp-era TCP path: parse guest TCP SYNs, start nonblocking host connects, create local TCP pairs for cross-worker loopback, or create listen sockets so smoltcp can accept the guest SYN.  Broker-held `TcpConn`/`InetListenerState` replaces these paths.
- **Dependencies first:** F.2.b/F.2.c and pb5 if IPv6 TCP would otherwise still fall back to local `Network`.
- **Special case:** The broker-held listener path at `:1202-1285` was a bridge added for partial migration.  It should not survive as packet-level SYN handling; the replacement is direct `accept_inbound` from real host accept loops or broker state-object connections.

### UDP packet forwarding and DNS query tracking in the smoltcp loop

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1375-1426`
- **Rough LOC:** 52
- **Classification:** `DELETE` for UDP forwarding, `KEEP_MODIFY` for DNS policy concept
- **Rationale:** `device::parse_udp`, `handle_udp_outbound`, and `udp_flows` are worker-local raw-packet UDP emulation.  Broker-held UDP after F.1/F.2 should own send/recv; if hostname policy still needs DNS correlation, move `DnsTracker` integration to the broker-held UDP state service instead of keeping this loop.
- **Dependencies first:** F.2.b/F.2.c and confirmation that `BL.udp_recvfrom_remote_addr` / `INV.udp_truncation` no longer depend on this path.

### ICMP echo synthesis

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1428-1436`
- **Rough LOC:** 9
- **Classification:** `DELETE`
- **Rationale:** Synthetic ICMP echo replies are a packet-stack convenience for worker-local raw paths.  Broker-held raw sockets or explicit unsupported/permission-denied behavior should cover raw ICMP tests after F.2.
- **Dependencies first:** F.2.c raw fallback cleanup; `BL.raw_icmp_echo` must still pass with either `PermissionDenied` or `EchoSucceeded` as documented in `broker_listener_tests.rs:794-808`.

### smoltcp poll, bridge promotion, relay, and garbage collection

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1439-1560`
- **Rough LOC:** 122
- **Classification:** `DELETE`
- **Rationale:** `iface.poll`, `promote_established`, `relay_tcp`, `relay_local`, `relay_udp_replies`, and GC of smoltcp state tables are pure worker-local routing infrastructure.  They disappear when no packet-framed inet traffic reaches the broker.
- **Dependencies first:** F.2.b/F.2.c.

### IPC EOF check

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1562-1575`
- **Rough LOC:** 14
- **Classification:** `KEEP_MODIFY`
- **Rationale:** The simplified session loop still needs to notice IPC shutdown, but it should no longer be embedded among smoltcp timers and socket table GC.  Keep the behavior as a small helper that polls the LBNP stream/listener set.
- **Dependencies first:** F.3.a extraction.

### Additional LBNP client accept/drain loop

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1577-1707`
- **Rough LOC:** 131
- **Classification:** `KEEP_MODIFY`
- **Rationale:** `--network-proxy-listen` accepts multiple LBNP clients over time; the in-loop code validates handshakes and spawns additional sessions.  This remains required, but the spawned `run_inner` should enter a simplified session loop without smoltcp or PortRouter channels.
- **Dependencies first:** F.3.a should extract and test this before deleting surrounding loop code.
- **Tests:** `run_accepts_additional_lbnp_client` at `mod.rs:3413-3469` directly covers this behavior on Unix.

### In-loop LB9P classification

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1708-1752`
- **Rough LOC:** 45
- **Classification:** `KEEP_MODIFY`
- **Rationale:** A direct `LB9P` connection can arrive on the same listener as LBNP.  Classification and ring/TCP service dispatch must remain, ideally sharing one helper with `accept_ipc_client` to avoid maintaining two handshake variants.
- **Dependencies first:** None for keeping; F.3.a should deduplicate against `accept_ipc_client`.
- **Risk:** There are multiple LBNP/LB9P handshake variants: initial accept path, additional-client in-loop path, and direct `--network-proxy-fd` `perform_handshake` path.  Test all three after refactoring.

### Host inbound forward accept loop

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1754-1837`
- **Rough LOC:** 84
- **Classification:** mixed: `KEEP_MODIFY` for `accept_inbound`, `DELETE` for smoltcp fallback
- **Rationale:** The keeper is `listener.accept_inbound(stream, peer)` at `:1765-1778`, which delivers Docker/host NAT connections to broker-held listeners.  The subsequent `PortRouter::try_route` and smoltcp `Socket::connect` fallback at `:1780-1828` should be deleted after F.2.
- **Dependencies first:** F.2.b/F.2.c.  Also require `BrokerStateRegistry::resolve_broker_held_inet_listener` to be the only valid delivery target for forwarded guest ports.
- **Important behavior:** If no broker-held listener is registered for the forwarded port, the post-F.3 loop should close/drop the accepted host stream and log loudly.  It should not resurrect smoltcp routing.

### Routed inbound streams from PortRouter

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1839-1890`
- **Rough LOC:** 52
- **Classification:** `DELETE`
- **Rationale:** This receives `RoutedStream` from another worker's PortRouter route and creates a smoltcp connection to the guest.  Broker-held listeners/state handles make this obsolete.
- **Dependencies first:** F.2.c and PortRouter removal.

### Poll set / event-loop wait

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1892-1959`
- **Rough LOC:** 68
- **Classification:** `KEEP_MODIFY`
- **Rationale:** A simplified broker loop still needs to poll the LBNP IPC fd, optional accept listener, pending handshakes, and inbound forward listeners.  The current poll set also includes pending host connects, TCP/local bridges, and UDP flows; those entries and the fixed smoltcp timer cadence should be deleted.
- **Dependencies first:** F.3.a extraction and F.3.b deletion.

### Shutdown and PortRouter cleanup

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1961-1972`
- **Rough LOC:** 12
- **Classification:** `KEEP_MODIFY`
- **Rationale:** Sending a shutdown frame may remain useful for LBNP clients.  Registered PortRouter cleanup at `:1963-1969` is deleted with PortRouter.
- **Dependencies first:** F.3.c.

### `accept_ipc_client`

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:1975-2247`
- **Rough LOC:** 273
- **Classification:** `KEEP_MODIFY`
- **Rationale:** This is the front-door acceptor for `--network-proxy-listen` and still distinguishes LBNP from direct LB9P clients.  It should remain, but share handshake parsing with the additional-client path and narrow the local-service API if TCP 9P fallback is removed.
- **Dependencies first:** None for keeping; F.3.a should add/extract focused tests before changing behavior.
- **Call sites:** `litebox_broker/src/main.rs:421-425` calls it in the network-proxy listener loop.

### Direct `perform_handshake` helpers

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:2249-2378`
- **Rough LOC:** 130
- **Classification:** `KEEP_AS_IS`
- **Rationale:** The `--network-proxy-fd` path calls `run(..., handshake_done=false, ...)`, which uses `perform_handshake` at `:960-963`; validation and response helpers are independent of smoltcp.  They should remain until/unless the direct-fd mode is removed.
- **Dependencies first:** None.

### smoltcp listen socket and connect helper functions

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:2379-2494`
- **Rough LOC:** 116
- **Classification:** `DELETE`, except possibly `create_tcp_pair`
- **Rationale:** `ensure_listen_socket`, `start_nonblocking_connect`, `check_connect`, and `resolve_pending_connects` are outbound/loopback smoltcp routing support.  `create_tcp_pair` is only still useful if a broker-held state path needs a local pair; otherwise delete with cross-worker smoltcp routing.
- **Dependencies first:** F.2.b/F.2.c.  Confirm no `InetListenerState::accept_inbound` call still needs a local pair after direct host streams are delivered.

### `promote_established`

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:2496-2680`
- **Rough LOC:** 185
- **Classification:** `DELETE`
- **Rationale:** This promotes smoltcp listening sockets to `TcpBridge`/`LocalBridge` after a guest TCP handshake.  Broker-held listener accept queues replace it.
- **Dependencies first:** F.2.b/F.2.c and 9P fallback decision.

### TCP and local-service relays

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:2682-2920`
- **Rough LOC:** 239
- **Classification:** `DELETE`
- **Rationale:** `relay_tcp` and `relay_local` copy data between smoltcp sockets and host/local streams.  After F.2, broker-held `TcpConn` and direct LB9P ring paths own byte movement; this code should not be reachable.
- **Dependencies first:** F.2.b/F.2.c.

### UDP forwarding and reply packet construction

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:2922-3069`
- **Rough LOC:** 148
- **Classification:** `DELETE`
- **Rationale:** `handle_udp_outbound`, `relay_udp_replies`, and `build_udp_packet` are raw packet UDP emulation for the per-worker smoltcp stack.  Broker-held UDP must own UDP semantics after F.2.
- **Dependencies first:** F.2.b/F.2.c.  `test_build_udp_packet_valid` at `:3158-3175` should be deleted with this code.

### Host DNS resolver discovery

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:3071-3090`
- **Rough LOC:** 20
- **Classification:** `KEEP_MODIFY`
- **Rationale:** Host DNS resolver advertisement is still listed as a minimum requirement, but it should not be anchored in the smoltcp UDP loop.  Keep resolver discovery and move it either to broker-held UDP DNS handling or to whatever configuration frame tells workers which resolver to use.
- **Dependencies first:** F.2.b/F.2.c plus design decision for per-worker DNS handling.
- **Risk:** `/etc/resolv.conf` parsing currently accepts only IPv4 nameservers; pb5/IPv6 DNS may expose this limitation.

### Unit tests in `mod.rs`

- **File:line range:** `litebox_broker/src/net_proxy/mod.rs:3092-3480`
- **Rough LOC:** 389
- **Classification:** `KEEP_MODIFY`
- **Rationale:** Keep LBNP/LB9P handshake tests; delete PortRouter and UDP-packet tests with their code.  The Unix `run_accepts_additional_lbnp_client` test uses `std::env::temp_dir()` at `:3420`, which is pre-existing but worth moving to a repo-local test socket if these tests are touched.
- **Dependencies first:** F.3.a should preserve or improve tests before behavior changes; F.3.b/F.3.c deletes tests only when their implementation is deleted.

## Inventory: sibling modules and call sites

### `litebox_broker/src/net_proxy/device.rs`

- **File:line range:** `litebox_broker/src/net_proxy/device.rs:1-507`
- **Rough LOC:** 507
- **Classification:** `DELETE`, with a possible `send_ipc_frame` extraction
- **Rationale:** The module is explicitly a smoltcp `phy::Device` backed by LBNP framing (`device.rs:4-11`) and exposes packet parsers for TCP/UDP/ICMP (`:344-490`).  After F.2, worker inet RPCs should not be raw IP packets, and the port-listen control message parser is tied to PortRouter.
- **Dependencies first:** F.2.c and F.3.c.  If `send_ipc_frame` / shutdown frame are still used by LBNP non-packet RPC, extract them before deleting `IpcDevice`.

### `litebox_broker/src/net_proxy/dns_tracker.rs`

- **File:line range:** `litebox_broker/src/net_proxy/dns_tracker.rs:1-201` plus tests below
- **Rough LOC:** ~300 including tests
- **Classification:** `KEEP_MODIFY`
- **Rationale:** The DNS tracker is currently wired to raw UDP in `mod.rs:1383-1424` and `:2976-2996`, but hostname-based policy may still need it for broker-held UDP.  Keep the concept, but move ownership from `net_proxy` to the broker-held UDP/state-service path if policy still depends on DNS correlation.
- **Dependencies first:** F.2.b/F.2.c and a policy decision.  If broker-held UDP does not inspect DNS payloads, document that hostname policy no longer has per-worker DNS learning before deleting this module.

### `litebox_broker/src/net_proxy/local_transport.rs`

- **File:line range:** not present at `e87d5cb0`
- **Rough LOC:** 0
- **Classification:** N/A
- **Rationale:** The requested file does not exist in this worktree.  TUN/local-transport risk instead appears in `litebox_runner_linux_userland/src/lib.rs`, where TUN mode and `--network-broker` are CLI/runtime options.
- **Dependencies first:** F.2.a/F.2.c must decide whether TUN TCP 9P remains under a worker-local-inet capability or is declared unsupported for broker-held linux_userland.

### Broker main call sites

- **File:line range:** `litebox_broker/src/main.rs:91-95`, `:145-175`, `:334-344`, `:421-449`
- **Rough LOC:** ~85 relevant lines
- **Classification:** `KEEP_MODIFY`
- **Rationale:** CLI parsing, local 9P service registration, direct-fd run, and listener-mode accept all call into `net_proxy`.  F.3 should keep CLI behavior stable, then narrow `LocalServiceRegistry` and `run*` signatures after the smoltcp delete.
- **Dependencies first:** F.3.a for extraction and F.3.d for signature cleanup.

### Broker-held inbound APIs

- **File:line range:** `litebox_broker/src/cwfd/state_registry.rs:535-548`, `:636-694`; `litebox_broker/src/cwfd/inet_listener_state.rs:127-149`, `:185-241`, `:262-285`; `litebox_broker/src/cwfd/state_service.rs:1995-2006`
- **Rough LOC:** ~130 relevant lines
- **Classification:** `KEEP_AS_IS`
- **Rationale:** These are the replacement path for host inbound forwarders: mark forwarded ports, virtual-bind worker listener state, resolve registered broker-held listeners, and queue accepted streams via `accept_inbound`.  F.3 should lean on these rather than add another routing layer.
- **Dependencies first:** Already landed with Phase F.1/F.2 work; validate under F.3 with host-forward tests.

### Platform listen notification call site

- **File:line range:** `litebox_platform_linux_userland/src/lib.rs:4873-4891`
- **Rough LOC:** ~19 relevant lines
- **Classification:** `DELETE` after F.2/F.3.c
- **Rationale:** This sends worker listen notifications so broker `PortRouter` can route cross-worker TCP.  Once PortRouter is deleted and broker-held listener handles are inherited/transferred through the state registry, this notification should go away or become a no-op under a removed compatibility feature.
- **Dependencies first:** F.2.c and `PR.*`/`INHERIT.*` tests passing through broker state.

## Suggested phased breakdown

### F.3.a: extract and freeze survivor paths

Goal: create a small, tested surface for the parts that must survive before deleting any routing behavior.

Work items:

1. Extract or at least isolate LBNP handshake parsing/response shared by `accept_ipc_client`, `perform_handshake`, and additional-client handling.
2. Extract LB9P classification/spawn code so initial accept and in-loop accept call the same helper.
3. Extract inbound-forward listener setup and direct `accept_inbound` delivery into helpers with no smoltcp parameters.
4. Keep public `run`/`run_with_session_slots` signatures initially stable.
5. Add/adjust unit tests for malformed LBNP, direct LB9P, LB9P ring marker, additional LBNP client, and inbound-forward no-listener behavior if missing.

Can land independently: yes, because it should be mostly movement/refactoring with existing behavior.

Estimated complexity: **Medium**.  The risk is not code volume; it is preserving three handshake paths while separating them from one large event loop.

Validation:

- `cargo test -p litebox_broker net_proxy::tests::run_accepts_additional_lbnp_client`
- Existing LB9P tests where enabled by platform/cfg.
- `cargo build -p litebox_broker`

### F.3.b: delete worker-local outbound packet routing

Goal: remove the broker-side smoltcp emulation for outbound TCP, UDP, and ICMP once F.2 has made those paths unreachable.

Work items:

1. Delete `IpcDevice` smoltcp `Interface`/`SocketSet` setup from `run_inner`.
2. Delete TCP SYN peeking, `PendingConnect`, `TcpBridge`, `ensure_listen_socket`, `resolve_pending_connects`, `promote_established`, and `relay_tcp`.
3. Delete UDP raw packet flow state and `handle_udp_outbound` / `relay_udp_replies` / `build_udp_packet` from `mod.rs`; move/keep DNS tracking only if broker-held UDP uses it.
4. Delete ICMP echo synthesis from `net_proxy` once raw socket behavior is broker-held or explicitly unsupported.
5. Shrink the poll loop to LBNP IPC, optional listener, pending handshakes, and inbound-forward listeners.

Can land independently: yes, after F.2.  It should not delete PortRouter yet if a temporary listen-route compatibility shell still exists, but no outbound packet emulation should remain.

Estimated complexity: **Medium-high**.  Large deletion with compile fallout around imports, tests, and poll-loop control flow.

Validation:

- `cargo test -p litebox_broker`
- `cargo test -p litebox_test_harness --test integration -- BL.connect_basic.pie-glibc.dpg1`
- `cargo test -p litebox_test_harness --test integration -- BL.udp_recvfrom_remote_addr.pie-glibc.dpg1`
- `cargo test -p litebox_test_harness --test integration -- INV.udp_truncation.pie-glibc.dpg1`
- `cargo test -p litebox_test_harness --test integration -- BL.raw_icmp_echo.pie-glibc.dpg1`

### F.3.c: delete PortRouter and listen-route IPC

Goal: remove smoltcp-era cross-worker port routing after broker-held listener inheritance is the only listen/accept model.

Work items:

1. Delete `PortRouter`, `RoutedStream`, transfer outcome/error enums, route registration, and route cleanup.
2. Delete `IpcDevice::take_port_listen_msg` and worker `LBPL` listen/unlisten/transfer handling.
3. Remove `port_router` parameters/channels from `run_inner` and `run_with_session_slots`.
4. Remove linux_userland `send_port_listen_notification` / `on_listen_socket_change` call sites that only fed PortRouter.
5. Delete PortRouter unit tests and update docs that present PortRouter as current architecture.

Can land independently: yes, after F.2 and after PR/INHERIT coverage is broker-state green.

Estimated complexity: **High**.  Cross-worker listen inheritance is subtle; the delete is straightforward only if F.2 has already moved all listener ownership into broker state handles.

Validation:

- Port-router coordinator suite: `PR.fork_exec.*`, `PR.fork_single.*`, `PR.fork_multi_x5`, `PR.child_listen_cross`, `PR.fork_child_parent`, `PR.child_listen_depth2`.
- Inheritance matrix entries that include inet listeners: `INHERIT.*` broker/listener cases.
- `INV.broker_inet.kind_typeid_match.dpg1` and `INV.broker_handle_refcount.dpg1`.

### F.3.d: final shape, docs, and API narrowing

Goal: make `net_proxy` no longer look like a network stack.

Work items:

1. Split survivors into names matching responsibilities, for example `lbnp_session`, `lb9p_accept`, `inbound_forward`, and maybe `dns_config`.
2. Rename or document `net_proxy::run*` if the name remains for CLI compatibility but no longer proxies IP packets.
3. Narrow `LocalServiceRegistry` to ring-only if TCP 9P fallback is removed.
4. Move DNS resolver discovery to the broker-held UDP/config owner or document why it stays here.
5. Remove stale docs/playbook references that say smoltcp lives in broker `net_proxy`.

Can land independently: yes, after F.3.b/F.3.c.

Estimated complexity: **Low-medium**.  Mostly cleanup, but broad docs/import churn.

Validation:

- `cargo fmt`
- `cargo build`
- `cargo clippy --all-targets --all-features`
- Focused integration tests listed below; full `cargo test -p litebox_test_harness --test integration` if targeted runs pass.

## Risk register

### Phase-mixing: any worker still using `Network`

- **Risk:** A partial F.2 landing leaves AF_INET6 TCP, raw fallbacks, ioctl/setsockopt fallback, or TUN TCP 9P still emitting raw IP packets to `net_proxy`.
- **Symptom:** F.3.b deletes smoltcp packet handling and those workers see hangs/timeouts instead of clear errno.
- **Mitigation:** Before F.3.b, grep/build must show linux_userland has no `Network::new`, no `RawFdRef::Net` inet fallback, and no `send_port_listen_notification` dependency.  Keep loud `unreachable!()`/explicit errno in F.2 for any intentionally unsupported runtime case.

### 9P 9P-over-TCP fallback path

- **Risk:** `LocalServiceRegistry::register` at `mod.rs:833-842`, `LocalBridge`, and `main.rs:161-175` support a TCP-spawned 9P server.  Shared-memory LB9P is the desired survivor, but TUN mode comments in the runner still mention TCP transport.
- **Symptom:** Docker/VS Code startup loses filesystem access in a mode that still asks for TCP 9P rather than shared-memory/ring 9P.
- **Mitigation:** Decide in F.2 whether TUN TCP 9P remains behind a separate worker-local-inet capability.  F.3 should not silently delete `ServiceSpawner` until a harness probe covers shared-memory 9P bootstrap and any supported fallback mode is either green or explicitly unsupported.

### TUN local-transport gating

- **Risk:** `litebox_broker/src/net_proxy/local_transport.rs` does not exist at this commit, but `litebox_runner_linux_userland/src/lib.rs` still has `--tun-device-name` and `--network-broker` paths.  Some local transport may bypass the broker-held state objects.
- **Symptom:** TUN/local mode compile errors or runtime hangs after `net_proxy` stops accepting packet traffic.
- **Mitigation:** Include runner TUN options in F.2 audit.  Gate or remove TUN TCP-9P/local inet support before F.3.b deletion.

### BL.* probes

- **Risk:** `BL.listen_basic`, `BL.connect_basic`, `BL.udp_recvfrom_remote_addr`, and `BL.raw_icmp_echo` were created during the broker inet migration and may still tolerate fallback paths.
- **Symptom:** Tests pass under one environment because they fall back to worker-local smoltcp or host permissions, then fail after deletion.
- **Mitigation:** Run them with broker inet defaults and no `LITEBOX_BROKER_INET_*` opt-outs.  For raw, preserve the documented `EPERM`/permission-denied pass condition from `broker_listener_tests.rs:801-807`.

### INHERIT.* probes

- **Risk:** Inherited listening sockets across fork/exec used PortRouter ownership fixes.  Deleting PortRouter without equivalent broker-held listener refcount/ownership behavior breaks child/parent listener survival.
- **Symptom:** `INHERIT.*` or `PR.*` tests fail only after child exit or route transfer.
- **Mitigation:** Require broker-held handle inheritance coverage before F.3.c.  Confirm listener handles survive fork/exec through `BrokerStateRegistry`, not worker `LBPL` notifications.

### INV.* probes

- **Risk:** Invariants such as `INV.broker_inet.kind_typeid_match.dpg1`, `INV.broker_handle_refcount.dpg1`, and `INV.udp_truncation.pie-glibc.dpg1` can reveal stale state-object or UDP behavior after deleting packet paths.
- **Symptom:** Handle leaks, wrong subsystem tags, or UDP truncation/peer-address mismatches.
- **Mitigation:** Run invariant tests after each phase.  Treat failures as migration bugs, not reasons to keep smoltcp routing.

### Per-worker DNS handling

- **Risk:** `DnsTracker` currently learns hostname mappings by watching raw UDP port 53 in the net_proxy loop.  Broker-held UDP may not have equivalent per-worker visibility yet.
- **Symptom:** Sandbox hostname policy loses context and allows/denies based only on IP.
- **Mitigation:** Move DNS query/response observation into broker-held UDP state or introduce an explicit DNS resolver advertisement/config path.  Add a probe where a guest resolves a hostname and a hostname-based network policy decision uses the learned mapping.

### LBNP handshake variants

- **Risk:** Handshake logic exists in `accept_ipc_client`, `perform_handshake`, and the in-loop additional-session accept path.  LB9P classification is duplicated too.
- **Symptom:** One startup mode works while another rejects clients, accepts slow/truncated clients, or blocks the listener.
- **Mitigation:** F.3.a should centralize handshake classification.  Unit tests should cover initial LBNP, direct-fd LBNP, additional LBNP, direct LB9P TCP, LB9P ring, truncated ring, wrong magic, wrong version, and wrong MTU.

### Host-inbound routing to broker-held listeners

- **Risk:** The keeper path added around `mod.rs:1765-1778` depends on `BrokerStateRegistry::resolve_broker_held_inet_listener`; deleting fallback routing makes missing registrations fatal to host-forwarded connections.
- **Symptom:** `--forward-port` accepts a host connection but drops it because the guest listener did not virtual-bind/register in time.
- **Mitigation:** Keep `add_inbound_forwarded_port` on listener setup and ensure bind/listen ordering registers broker-held listeners before host connects.  Add a targeted inbound-forward probe that fails if smoltcp fallback is accidentally used.

### Diagnostics and `/tmp/rst-diag.log`

- **Risk:** The current PortRouter path writes ad-hoc diagnostics to `/tmp/rst-diag.log` at `mod.rs:1067-1088` and `litebox_platform_linux_userland/src/lib.rs:4876-4903`.  Removing the path may also remove useful failure breadcrumbs.
- **Symptom:** Harder diagnosis of listener inheritance regressions.
- **Mitigation:** Prefer structured tracing or existing `debug_log_print` conventions in remaining code.  Do not keep PortRouter just for diagnostics.

## Sequencing with F.2 and pb5-inet6-tcp

F.3 should not begin destructive deletion until F.2.a/F.2.b/F.2.c have landed on the work stream or amalgamation branch and linux_userland no longer constructs, stores, polls, or falls back to `litebox::net::Network<Platform>`.  F.2.a can unblock F.3.a refactoring because survivor extraction does not change semantics.  F.2.b/F.2.c are required before F.3.b/F.3.c delete packet routing and PortRouter.  `pb5-inet6-tcp` should land before the final smoltcp delete if AF_INET6 stream sockets still depend on worker-local Network; otherwise F.2 must convert AF_INET6 TCP to an explicit broker-held path or an explicit unsupported errno so F.3 does not mask a fallback as a hang.

## Test plan

### Always run for code phases

- `cargo fmt` before commits.
- `cargo build -p litebox_broker` after F.3.a and F.3.b.
- `cargo test -p litebox_broker` after deleting unit-tested helpers.
- Escalate to `cargo clippy --all-targets --all-features` once the delete series compiles.

### Focused broker `net_proxy` unit coverage

- Keep or replace `run_accepts_additional_lbnp_client` for additional LBNP sessions.
- Keep or replace LB9P direct/ring/truncated tests currently under Windows cfg at `mod.rs:3177-3411`.
- Add non-Windows/unit-level tests for common handshake parsing if the helper can be made platform-independent.
- Delete PortRouter unit tests only when F.3.c deletes PortRouter.
- Delete `test_build_udp_packet_valid` only when F.3.b deletes UDP packet construction.

### Integration tests that should stay green

- `BL.listen_basic.pie-glibc.dpg1` — broker-held listener bind/listen/accept remains the main listen path.
- `BL.connect_basic.pie-glibc.dpg1` — outbound TCP must be broker-held, not smoltcp.
- `BL.udp_recvfrom_remote_addr.pie-glibc.dpg1` — broker-held UDP peer address behavior remains correct.
- `INV.udp_truncation.pie-glibc.dpg1` — UDP truncation semantics survive deletion of raw packet UDP.
- `BL.raw_icmp_echo.pie-glibc.dpg1` — raw behavior remains either permitted echo or expected permission-denied/unsupported result.
- `INV.broker_inet.kind_typeid_match.dpg1` — state-object tags stay consistent after listener/UDP/raw cleanup.
- `INV.broker_handle_refcount.dpg1` — no leaks after deleting PortRouter/session routing state.
- `INV.setsockopt_passthrough.*` and `INV.getifaddrs_sandbox_view.*` — edge socket metadata and sandbox-view behavior do not regress when local Network disappears.
- `PR.fork_exec.*`, `PR.fork_single.*`, `PR.fork_multi_x5`, `PR.child_listen_cross`, `PR.fork_child_parent`, `PR.child_listen_depth2` — run before and after F.3.c to prove PortRouter removal is safe.
- `INHERIT.*` inet-listener cases — inherited broker-held listener handles must work without `LBPL` listen-route transfer.
- Host-forwarding harness section around `integration.rs:2079-2253`, especially `H2.data_forward` — proves host `--forward-port` accept reaches broker-held listener via `accept_inbound`.
- 9P file-read path in the same host-forwarding trial (`H3` around `integration.rs:2256+`) and normal rootfs startup — proves direct/shared-memory 9P bootstrap still works.

### New probes recommended

1. **Inbound-forward direct-to-broker probe:** Start a guest broker-held TCP listener on a forwarded port, connect from the host through Docker NAT, echo data, and assert the broker log/path used `accept_inbound` rather than PortRouter/smoltcp.  This can extend the existing `H2.data_forward` host-forwarding trial.
2. **No-smoltcp-fallback guard:** A harness mode or debug assertion that fails if `IpcDevice::stage_recv`, PortRouter `LBPL`, or smoltcp `Interface::poll` is exercised in linux_userland after F.2.  Use this during F.3.b/F.3.c to catch phase mixing.
3. **LB9P shared-memory handshake probe:** Connect with `LB9P` plus ring marker/metadata and assert ACK + service spawn without a TCP 9P `LocalBridge`.
4. **DNS hostname-policy probe:** Guest resolves a hostname, then connects to the resolved IP under a hostname-based sandbox policy.  The test should fail if DNS tracking was accidentally deleted instead of moved to broker-held UDP.
5. **AF_INET6 stream probe:** If pb5 lands first, add a v6 loopback/listener/connect test that proves AF_INET6 TCP does not need worker-local Network.  If pb5 is deferred, add a negative test for the explicit errno chosen by F.2.

## Definition of done for F.3

- `litebox_broker/src/net_proxy/mod.rs` no longer contains smoltcp `Interface`, `SocketSet`, TCP/UDP packet parsing, `TcpBridge`, `LocalBridge`, `UdpFlow`, `PortRouter`, or worker `LBPL` route transfer logic.
- Host inbound `--forward-port` still binds host listeners and delivers accepted streams to broker-held `InetListenerState::accept_inbound`.
- Direct/shared-memory 9P LB9P handshake still works.
- LBNP initial, direct-fd, and additional-session handshakes still work.
- DNS resolver advertisement/tracking is either preserved in a new owner or explicitly redesigned with tests.
- BL/INV/INHERIT/PR and host-forwarding tests listed above stay green with no worker-local inet fallback.
