# Inter-Process Stream Multiplexer for Fork Workers

## Problem

When a fork child is migrated to a worker host process via delayed fork,
virtual fd endpoints (pipes, PTY channels, Unix sockets) don't survive
across process boundaries.  The current approach creates ad-hoc OS pipe
bridges per fd, with type-specific relay threads.  This leads to:

1. **PTY breakage**: virtual PTY master/slave pairs are in-memory channels.
   The worker gets a disconnected slave — output goes nowhere.
2. **Nested bridge chains**: grandchild workers create bridges to child
   workers, not to the original fd owner.  Data traverses multiple hops
   with no relay at intermediate workers.
3. **Epoll incompatibility**: `ExternalFd` (raw OS pipe wrapper) doesn't
   support `register_observer`, so epoll-driven programs (Node.js) never
   wake up.
4. **Per-fd overhead**: each bridged fd creates 2 OS pipe fds + a bridge
   thread.  A process with 5 bridged fds needs 10 OS fds and 5 threads.
5. **Type-specific code**: pipes, Unix sockets, PTY, and FilesystemFd each
   need separate bridge logic in `commit_delayed_fork`.

## Design: Stream Multiplexer

### Overview

Replace per-fd OS pipe bridges with a **single multiplexed channel**
between each worker and its parent.  The channel carries framed messages
tagged by stream ID.  Each end has a **dispatcher** that routes data
between the channel and the appropriate virtual fd endpoint.

```
┌─────────────────┐       transport            ┌─────────────────┐
│  Parent process  │◄────────────────────────►│  Worker process  │
│                  │    framed messages:       │                  │
│  Dispatcher:     │    (stream_id, type, data)│  Dispatcher:     │
│  stream 0 ←→ PTY │                           │  stream 0 ←→ PTY*│
│  stream 1 ←→ pipe│                           │  stream 1 ←→ pipe│
│  stream 2 ←→ sock│                           │  stream 2 ←→ sock│
│  ...             │                           │  ...             │
└─────────────────┘                           └─────────────────┘
                                              * = virtual PTY endpoint
```

### Transport

**Primary**: shared-memory ring pairs (`ShmemRingPair` from
`litebox_common_linux/src/shmem_ring.rs`).  Two rings per worker — one
per direction (parent→worker, worker→parent).  This reuses the proven
9P shmem transport: `memfd_create` + `mmap(MAP_SHARED)`, lock-free SPSC
design, futex-based notification with spin-then-sleep.  Zero kernel
copies on the data path.

The shmem rings are created by the parent, the memfds are inherited by
the worker via `posix_spawn` (CLOEXEC cleared).

**Fallback**: `AF_UNIX socketpair(SOCK_SEQPACKET)` for environments
where shared memory is unavailable.  `SOCK_SEQPACKET` preserves message
boundaries, avoiding partial-write concerns and simplifying the receive
path (each `recv()` returns exactly one frame).

### Framing

Each message on the transport:

```
┌──────────┬───────────┬──────┬──────┬──────────┐
│ len (u32)│stream (u32)│ type │flags │  data    │
│  LE      │  LE        │ (u8) │(u8)  │(len-10)  │
└──────────┴───────────┴──────┴──────┴──────────┘
```

- **len** (4 bytes): total message length including header (minimum 10)
- **stream** (4 bytes): stream ID (u32, opaque — mapped from object_id)
- **type** (1 byte):
  - `0x00` = Data — payload bytes for the stream
  - `0x01` = Control — ioctl/termios/window-size forwarding
  - `0x02` = Signal — stream-level signal delivery
- **flags** (1 byte):
  - bit 0: `EOF` — stream closed by sender
  - bit 1: `RESET` — stream aborted (error, maps to EPIPE/SIGPIPE for
    writers, EOF for readers)
  - bits 2-7: reserved
- **data** (len - 10 bytes): payload (may be empty for control messages)

Control message data format (type=0x01):

```
┌──────────┬──────────────────┐
│ ctrl (u16)│  payload         │
│  LE       │  (varies)        │
└──────────┴──────────────────┘
```

Control subtypes:
- `0x0001` = `TIOCSWINSZ` — window size (4 bytes: rows u16 + cols u16)
- `0x0002` = `TCSETS` — termios attributes (serialized termios struct)
- `0x0003` = `TCGETS_REPLY` — termios query response

### Stream IDs and Object-Based Mapping

Streams are mapped **per underlying object** (using `object_id`), not
per fd slot.  This correctly handles dup'd fds: if fd 1 and fd 2 point
to the same underlying pipe/PTY/socket (same `object_id`), they share
one stream.  This preserves:

- **Ordering**: writes to aliased fds are serialized on one stream
- **Close semantics**: the stream closes when ALL aliased fds are closed
- **Epoll identity**: all aliased fds share the same poll notifications

```rust
struct StreamMapping {
    stream_id: u32,
    object_id: u64,
    guest_fds: Vec<usize>,    // all fds sharing this object
    direction: StreamDirection,
    endpoint_type: EndpointType,
}

enum StreamDirection {
    ParentToWorker,    // parent writes, worker reads (stdin)
    WorkerToParent,    // worker writes, parent reads (stdout)
    Bidirectional,     // Unix sockets
}

enum EndpointType {
    Pipe,              // virtual pipe endpoint (for pipe-backed fds)
    Pty,               // virtual PTY endpoint (for terminal fds)
    Socket,            // virtual Unix socket endpoint
}
```

### Worker-Side Endpoints: Type-Preserving Replacement

The worker replaces guest fds with **type-appropriate virtual endpoints**,
not generic pipes.  This preserves fd semantics:

**For pipe-backed fds**: replace with a virtual pipe endpoint.  Supports
epoll via `Pollee`, read/write semantics, `O_NONBLOCK`.

**For PTY/terminal fds**: replace with a **virtual PTY pair**.  The
worker creates a `PtyPair` (using the existing `litebox/src/fs/devices.rs`
infrastructure), installs the slave as the guest fd, and connects the
master to the dispatcher.  This preserves:
- `isatty()` returns true
- `TCGETS`/`TCSETS` work (termios state on the virtual PTY)
- `TIOCGWINSZ` returns the forwarded window size
- Line discipline processing (ICRNL, ECHO, ONLCR)
- `SIGWINCH` delivery on window resize (via control messages)

**For Unix socket fds**: replace with a virtual pipe pair (unidirectional
per stdio slot).  Socket-specific semantics (SCM_RIGHTS, MSG_PEEK) are
not preserved — acceptable for the stdio use case.

### Exec Worker Binding Compatibility

When the fork-restore worker's guest does `execve`, the
`worker_exec_stdio_bindings` classifies fds by type.  With type-
preserving endpoints:

- Virtual PTY → classified as `FilesystemFd` → `Fs` binding → bridge
  thread reads exec worker's host stdout and writes to virtual PTY slave
  → correct (same as base branch)
- Virtual pipe → classified as `Pipe` → `Pipe` binding → bridge writes
  to virtual pipe → correct
- ExternalFd (from prior bridge) → classified as `Pipe` → `ExternalFd`
  binding → posix_spawn dup2 → correct

No changes to the exec worker mechanism needed.

### Parent-Side Dispatcher

The parent runs a **dispatcher event loop** per worker multiplexer
connection (single background thread).  It uses non-blocking I/O with
per-stream queues to avoid head-of-line blocking:

1. **Read transport**: non-blocking read from shmem ring / socketpair.
   Dispatch each message by stream ID to the appropriate per-stream
   outbound queue.
2. **Drain queues**: for each stream with pending data, try a non-blocking
   write to the virtual fd (pipe sender / PTY slave / Unix socket).
   If the write would block, leave the data in the queue and register
   for OUT notification via `Pollee`.
3. **Collect inbound**: for `ParentToWorker` streams, try a non-blocking
   read from the virtual fd.  If data is available, write a framed
   message to the transport.

This avoids head-of-line blocking: a slow consumer on one stream only
fills that stream's queue.  Other streams continue to flow as long as
the transport has capacity.

For the common case (few streams, low throughput), a simpler blocking
model is acceptable as a first implementation, with the event-loop
model as a documented upgrade path.

### Tree Topology

Workers form a tree rooted at the initial process.  Each worker connects
to its **parent** only.  For a grandchild to reach the root:

```
git (worker C) writes to virtual PTY slave
  → PTY line discipline processes output (ONLCR, etc.)
  → PTY master data available
  → worker C dispatcher reads PTY master → frames message → transport
  → worker B (bash) dispatcher receives message
  → writes to bash's virtual PTY slave (stream endpoint)
  → bash's PTY processes output
  → bash dispatcher reads PTY master → frames message → transport
  → root process dispatcher receives message
  → writes to original PTY slave (the real one)
  → PTY master delivers data to Node.js
```

PTY line discipline is preserved at **every hop** because each endpoint
is a virtual PTY, not a pipe.

### Error Handling

- **Worker crash**: transport closes → parent dispatcher reads EOF →
  sends RESET on all streams → virtual fd senders close → readers
  get EOF, writers get EPIPE/SIGPIPE
- **Parent fd close (reader)**: parent closes virtual pipe receiver →
  dispatcher sends RESET for that stream → worker's writer gets
  EPIPE/SIGPIPE
- **Parent fd close (writer)**: parent closes virtual pipe sender →
  dispatcher sends EOF for that stream → worker's reader gets EOF
- **Backpressure**: per-stream queues in the dispatcher bound per-stream
  backlog.  Transport-level backpressure only kicks in when the total
  queue across all streams exceeds the transport buffer.

### Protocol Handshake

On connection, the parent sends a handshake message:

```
┌──────────┬──────────┬──────────┐
│ magic(4) │version(2)│features(2)│
└──────────┴──────────┴──────────┘
```

- **magic**: `0x4C425358` ("LBSX")
- **version**: protocol version (currently 1)
- **features**: bitmask of supported features (initially 0)

The worker validates and replies with its own handshake.  This enables
forward compatibility without per-frame overhead.

## Implementation Plan

### Phase 1: Multiplexer Core + Pipe Endpoints

Add `litebox_shim_linux/src/multiplexer.rs`:
- Framing: `MuxMessage { stream_id, msg_type, flags, data }`
- Transport: shmem ring read/write (reuse `ShmemRingPair`)
- `MuxEndpoint`: owns the transport, provides `send(msg)` / `recv()`
- Pipe-backed stream endpoints (virtual pipe + dispatcher glue)

### Phase 2: PTY Endpoints + Control Messages

- Virtual PTY stream endpoints using existing `PtyPair`
- Control message routing for `TIOCSWINSZ` → window size forwarding
- `TCGETS`/`TCSETS` forwarding for remote termios queries
- Preserve `isatty()` / line discipline at every hop

### Phase 3: Parent + Worker Dispatchers

- Parent dispatcher with per-stream queues (non-blocking event loop)
- Worker dispatcher replacing `install_external_fd`
- Object-based stream mapping (dedup by `object_id`)
- Integration with `commit_delayed_fork` and `restore_process`

### Phase 4: Remove Ad-hoc Bridges

- Remove `ExternalFd` and related code
- Remove per-fd OS pipe bridge creation
- Remove `FdReplacement` / relay thread mechanism
- Remove `child_pipe_bridges` vector
- Verify exec worker bindings work with new endpoints

## Limitations & Future Work

1. **SCM_RIGHTS**: Unix socket fd passing not supported through streams.
2. **Non-stdio fds**: initial implementation bridges stdio only.  Extend
   to arbitrary fds (IPC channels, etc.) as needed.
3. **Direct connections**: for deep trees (>3 levels), allow grandchild
   to connect directly to root via forwarded shmem fd (SCM_RIGHTS or
   `/proc/pid/fd`).  Tree forwarding is sufficient for 2-3 levels.
4. **9P broker**: keeps its own transport.  Not routed through the
   multiplexer — different traffic patterns (request/response vs
   streaming), different backpressure requirements.
