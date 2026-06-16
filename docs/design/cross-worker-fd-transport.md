# Cross-Worker fd Transport: Architecture as of `bf3e60f1`

> **Status:** Audit notes (Phase 0 of the cross-worker fd transport
> workstream). This document describes what the code did **at
> commit `bf3e60f1`**, not what it should do. Use as the reference
> baseline for design changes.
>
> **Update 2026-05-30 (Phase F.3 landed):** the "Path B — broker TCP
> via smoltcp" and "Broker port routing (PortRouter)" sections below
> describe code that has been DELETED. Broker-held inet is now the
> only path under linux_userland: TCP listener/connect, UDP, and
> ICMP all live as `StateObject`s in the broker's
> `BrokerStateRegistry`, and host-inbound connections are routed
> through `BrokerHeldListenerRegistry` (broker `accept_inbound` →
> per-listener queue → worker `accept()` RPC). PortRouter and
> `litebox_broker::net_proxy`'s smoltcp paths are gone. The shim
> no longer constructs `litebox::net::Network<Platform>` for
> linux_userland builds. See `PHASE_F3_SCOPING.md` for the
> deletion inventory.
>
> See also: `expanded-fd-support-delayed-fork.md`,
> `inter-process-stream-multiplexer.md`, `mux-mesh-pipe-bridging.md`,
> `PHASE_F2_SCOPING.md`, `PHASE_F3_SCOPING.md`.

## Problem the audit is scoped to

54 wave-5 residual FAILs cluster into three symptoms with one root cause:

1. **SCM_RIGHTS cmsg passthrough** (16 FAILs) — sender does
   `sendmsg(SCM_RIGHTS)`; receiver's `recvmsg` returns no cmsg.
2. **FKLC.inherit listen-fd preservation** (5 FAILs) — child does
   `accept(inherited_fd)` → `ENOTSOCK`.
3. **Within-tree cross-worker socket fork-restore** (visible in
   `dpg1_to_dpg1_dng` SCM paths in wave-5 — currently rejected with
   `ENOSYS` rather than failing later).

Root cause: kernel-special fds (sockets, pidfds, eventfds) and
broker-mediated socketpair endpoints are managed state, not real kernel
fds; cross-process operations don't carry the managing reference.

## What exists today

### Two cross-worker transport mechanisms (separate paths)

#### Path A — host-OS pipe / socketpair bridge (fork-restore migration)

Code: `litebox_shim_linux/src/syscalls/process.rs::commit_delayed_fork`,
specifically the UnixSocket bridging block at lines 5200-5510.

Triggered when a guest process is fork-restored to a different worker
host (delayed-fork migration, typically across binary-type boundaries
e.g. `dpg1 → dpg1_dng`).

For each guest UnixSocket fd in the parent's table:

- **Stdio slot heuristic** (lines 5235-5244): fd 0 → Read direction;
  fd 1/2 → Write; fd 3+ → ReadWrite (Node.js IPC, etc.).
- **Bidirectional** (`ExternalFdDirection::ReadWrite`, line 5297-5331):
  create a host kernel `socketpair()`; child gets one end, parent peer
  gets the other. Pairing is by `(pair_id, object_id)`: same `pair_id`,
  different `object_id` ⇒ peer.
- **Unidirectional** (lines 5345-5510): create a host kernel `pipe()`;
  drain in-memory `recv_channel` messages into the parent's pipe end so
  the child sees the buffered data after restore.

The crucial *capability* of this path: parent and child are different
worker processes on the same host. The bridge uses real host kernel fds,
which can carry **passed_fds via `SCM_RIGHTS` at the host kernel level**
in principle. Today, however, this path **rejects the fork** if any
buffered message in the unix socket has `passed_fds`:

```rust
// process.rs:5391-5400
for msg in &msgs {
    if !msg.passed_fds.is_empty() {
        // [DELAYED-FORK] pid=...: SCM_RIGHTS on socket fd=..., cannot bridge
        ... return Err(Errno::ENOSYS);
    }
}
```

That's the **first concrete gap**: bridging refuses to carry queued
SCM_RIGHTS data, so any test that fork-migrates a worker holding
SCM_RIGHTS-carrying sockets fails. (Few tests hit this directly today; it
is a correctness blocker.)

`replaced subsystem` (`shim_linux/lib.rs`):
```rust
enum replaced subsystem {
    Pipe,
    UnixSocket,
    Pty,
    Filesystem,    // wave-3 fs-parent-open
}
```

#### Path B — broker TCP via smoltcp (independent worker connect/accept)

Code: `litebox_shim_linux/src/syscalls/unix.rs`:
- `try_connect_remote` (line 1036) — connector side.
- `UnixListenStream::start_tcp_listener` (line 440) — listener side.
- `accept` (line 1124) — accept side.

Triggered when two **independent top-level** workers (e.g.
`dpg1 ↔ dpg2`, both spawned at the start, never fork-related) try to
talk over a unix-domain socket.

Discovery: a **sidecar metadata file** on the shared 9P-served filesystem
maps `unix-socket key → guest TCP port` (`read_sidecar` / `write_sidecar`,
lines 1047 / 945). When a connector resolves an abstract path, it looks
up the TCP port via the sidecar.

Transport: the connector opens a guest TCP socket, calls `do_connect` to
the sidecar's port; the broker routes the SYN to the listener's TCP
proxy. Both endpoints get a `NetworkProxy::Stream(...)` and wrap it in
`UnixConnectedStream { transport: UnixTransport::Tcp { proxy } }`.

The `UnixTransport` enum (`unix.rs:604`):
```rust
enum UnixTransport {
    Channel { recv: ReadEnd<Message>, send: WriteEnd<Message> },  // same-worker
    Tcp     { proxy: Arc<NetworkProxy<Platform>> },               // cross-worker
}
```

This path's `try_sendto` and `try_recvfrom` (`unix.rs:704-744`) use
`proxy.try_write(buf)` / `proxy.try_read(buf)` — pure byte streams.
**`Message.passed_fds` is silently dropped** on send (line 707 only
serializes `msg.data`).

That's the **second concrete gap**: post-fork SCM_RIGHTS sends through
broker TCP carry no fd content.

### Worker ↔ broker IPC (the shm ring)

Code: `litebox_common_linux/src/shmem_ring.rs`, `litebox_runner_linux_userland/src/lib.rs::connect_nine_p_channel` (line 2348), `litebox_broker/src/net_proxy/mod.rs::handle_shared_memory_lb9p_connection` (line 563).

The runner connects to broker via Unix-socket IPC, then upgrades to a
shared-memory ring buffer (`RingWriter` / `RingReader`). The ring carries
9P traffic for filesystem operations + control plane.

The ring is **per-runner, not per-guest-process**. Each worker host
process has its own ring connection to the broker. Tokens, if added, are
addressable by the receiving worker's ring identity.

### Broker port routing (the only broker-global table today)

Code: `litebox_broker/src/net_proxy/mod.rs`, struct `PortRouter` (around
line 158).

```rust
// Port → (worker_id, sender) for forwarding accepted TCP streams.
next_worker_id: AtomicU64,  // monotonic worker IDs
register(port, worker_id, sender)
unregister_if_owner(port, worker_id)
try_route(port, ...)
```

This is the only broker-global routing table that exists today. It's
keyed by **port**, not by fd or backing object. There is **no
broker-global fd-token table**.

For the architectural goal "broker mediates: when sender hands an fd to a
peer-worker, broker assigns a new opaque token in the peer's table",
this is the surface where the new abstraction would live.

### fd ranges (already enforced)

`litebox_platform_linux_userland/src/lib.rs:6-20`:

| Range | Owner | Constant |
|---|---|---|
| 0–2 | stdio | — |
| 3–99 | guest bridge targets (posix_spawn dup2) | — |
| 100–199 | parent-side bridge fds | `PARENT_BRIDGE_FD_MIN` |
| 200–499 | child-side bridge host fds | `WORKER_BRIDGE_FD_MIN` |
| 500+ | infrastructure fds | `INFRA_FD_MIN` |

Use named constants; never hardcode minimums.

### `Message` struct (already carries fd content in-memory)

`unix.rs:585`:
```rust
pub(crate) struct Message {
    pub(crate) data: Vec<u8>,
    pub(crate) passed_fds: Vec<PassedFd>,  // SCM_RIGHTS ancillary data
}
```

`PassedFd` is a `litebox::fd::PassedFd`. The same-worker channel
(`UnixTransport::Channel`) preserves it through `try_write_one(msg)`
because the channel is in-memory message-oriented. Both gaps above are
where `passed_fds` falls off the message during cross-worker delivery.

### Acceptance gate notes

`process.rs::snapshot_fd_table` (lines 7008-7047) **already accepts**
`FdKind::UnixSocket` unconditionally. The `expanded-fd-support-delayed-fork.md`
doc that said UnixSocket was rejected is stale; the wave-3-era work
broadened the gate. The remaining gates in the existing UnixSocket
bridge: bidirectional-conflict rejection (`process.rs:5260-5286`), and
the SCM_RIGHTS-message rejection (`process.rs:5391-5400`).

### Stdio is special-cased throughout

The stdio fds (0, 1, 2) have heavily branched handling in
`snapshot_fd_table` and `commit_delayed_fork`:

- `host_stdio_source_fd` metadata identifies fds aliased to the original
  host stdio descriptors (e.g. `dup2(1, 2)`). The classifier prefers
  `FdKind::StdioFd` over `FdKind::FilesystemFd` when the slot is 0/1/2
  and `object_id` matches the host stdio OID.
- The wave-3 fs-parent-open bridge (`process.rs:5786-5827`) explicitly
  excludes any entry with `host_stdio_source_fd.is_some()` — stdio is
  routed via mux/direct-stdio, never the FilesystemFd bridge.
- Stdio for the UnixSocket bridge gets direction-based handling (fd 0 →
  Read, fd 1/2 → Write); non-stdio is bidirectional. This reflects the
  real Unix posix-spawn pattern (parent reads from child stdout via fd 0
  in child).
- Mux pipe bridge (`docs/design/mux-mesh-pipe-bridging.md`) carries
  stdio framing for the mesh worker hierarchy.

**Any change to bridge plumbing must preserve stdio routing exactly.**
This has been the single most regression-heavy surface in the codebase
(see `stdio-propagation-invariants.md`).

## Identified gaps and incoherences

1. **Path A rejects SCM_RIGHTS-carrying messages** (`process.rs:5391-5400`).
   The bridge could pass fds via host SCM_RIGHTS but doesn't. Concrete
   first-target work for token transport.

2. **Path B silently drops `Message.passed_fds`** (`unix.rs:704-734`).
   The TCP byte stream has no framing for passed_fds. Concrete work for
   broker-mediated tokens via shm ring + frame-on-byte-stream.

3. **Two paths share no common abstraction**. Path A's `child_pipe_bridges`
   and Path B's `UnixTransport::Tcp { proxy }` are unrelated state. The
   `UnixConnectedStream::clone_for_fork` likely doesn't even attempt to
   transition Channel→Tcp on fork-migration; the existing Path A
   replaces the in-memory channel with a external fd, but the post-restore
   guest doesn't end up with `UnixTransport::Tcp` — it ends up with a
   `ExternalFd`-style replacement that's NOT a unix socket subsystem fd.
   This is why post-fork follow-up sendmsg with SCM_RIGHTS doesn't even
   reach `try_sendto`'s passed_fds drop — it goes through the pipe
   bridge layer where SCM_RIGHTS isn't a concept at all.

4. **Sidecar discovery is a side channel**. Cross-worker connect (Path B)
   relies on a sidecar metadata file on shared FS to find the listener's
   TCP port. This is the existing "broker mediates location" pattern;
   tokens could be discovered the same way (or via the shm ring directly).

5. **No broker-global fd-token table.** The broker has only port routing.
   Adding fd tokens requires new broker state.

6. **Listen socket inheritance (FKLC.inherit) is unimplemented at the
   product level.** The harness has `Fork.inherit_listen_ports` and the
   protocol is wired (per the wave-5 fklc-inherit agent), but the child
   doesn't preserve the listen socket as a network fd — only as an
   inherited host kernel fd that fails `accept(2)` with `ENOTSOCK`.

## Decision log

### Q: Introduce a brand-new `BrokerFdToken` abstraction, or extend `NetworkProxy`?

**Tentative answer: introduce `BrokerFdToken`** (light, broker-global,
narrowly-scoped to fd transport).

Rationale:
- `NetworkProxy` is already a per-connection enum spanning Stream /
  Datagram / Raw. Extending it to be "the universal fd backing object"
  would conflate connection state with fd-table semantics.
- The token's job is small: identify a backing object (smoltcp socket,
  pidfd in broker, eventfd in broker, ...) so the receiving worker can
  reference it. It's a `(kind, id)` pair; opaque to byte transport.
- Lifecycle (refcounting across workers) is a clean separate
  responsibility.

Concrete shape (proposal):
```rust
// In litebox_broker:
pub struct BrokerFdToken(u64);

pub enum BrokerFdBacking {
    UnixStream { /* refs into UnixListenStream / UnixConnectedStream */ },
    UnixDatagram { ... },
    Pidfd { ... },
    EventFd { ... },
    Listener { ... },  // for FKLC.inherit
}

pub struct BrokerFdTokenTable {
    next_token: AtomicU64,
    table: RwLock<HashMap<BrokerFdToken, Arc<BrokerFdBacking>>>,
}
```

Wire-level: token is a `u64` in shm ring control messages and inside
`Message.data` framing for cross-worker SCM_RIGHTS.

### Q: Does the worker↔broker shm ring need a new wire format?

**Likely yes, additive.** The ring carries 9P traffic today. Adding a
small set of control opcodes (TokenRegister, TokenAcquire, TokenRelease,
TokenLookup) is an additive extension. 9P has its own message-typing,
and the ring is binary-framed; mixing in a new tag prefix is feasible.

Alternative: a separate side channel for tokens. Adds connection state
(workers must establish a second link to broker). Not preferred unless
9P framing genuinely can't accommodate.

### Q: Path A (external-fd bridge) — host SCM_RIGHTS or token via shm ring?

**Both, but token via shm ring is the architecturally aligned answer.**

- Host SCM_RIGHTS at the bridge layer would let one worker hand a real
  kernel fd to the other (same machine, same kernel). But the kernel fd
  alone isn't sufficient — the **broker** still needs to know about the
  shared backing object so subsequent read/write/close go to the same
  state. So the worker still has to register with broker, which means
  going through the shm ring anyway. SCM_RIGHTS doesn't save a step.
- Token via shm ring is uniform with Path B. Both paths use the same
  registration mechanism; only the byte transport differs.

### Q: Path B (broker TCP) — frame format for `passed_fds`?

Tentatively: **frame the byte stream as message envelopes**.

Each `Message` becomes a frame:
```
[u8 frame_kind][u32 data_len][u32 fd_count][data bytes][token bytes (8*fd_count)]
```

Receiver buffers bytes, decodes frames, looks up tokens via shm ring,
allocates guest fds, builds `Message { data, passed_fds }` for the
local in-memory channel.

This adds a framing layer the bytes-only transport doesn't have today.
Implementation detail: `UnixTransport::Tcp` becomes a wrapper that owns
both the proxy and a per-direction frame parser/serializer.

## Outstanding questions for Phase 1+

- Does the existing UnixSocket bridge (Path A) need to be folded into
  Path B's `UnixTransport::Tcp` — i.e., should fork-migrated unix sockets
  use TCP-via-broker instead of external fds? Cleaner, but a much bigger
  diff with stdio implications.
- For listen-fd inheritance (FKLC.inherit), is the new abstraction a
  `Listener` token kind, or a separate "register listener with peer"
  protocol op?
- pidfd / eventfd / signalfd / timerfd: each has its own backing kind in
  the token table. Audit how each is implemented today before deciding.

These are the questions Phase 1's failing tests should illuminate.
