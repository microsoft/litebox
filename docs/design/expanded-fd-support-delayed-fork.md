# Expanded FD Support for Delayed Fork

## Problem

Historically, delayed fork rejected processes whose fd tables contained
UnixSocket or non-host-stdio FilesystemFd entries.  That caused 100% fork
failure for Node.js child processes: Node.js uses `socketpair(AF_UNIX)` for
child stdio instead of `pipe()`, and sometimes redirects unused stdio to
`/dev/null`. The landed `FdKind` design has since made those decisions
explicit in an exhaustive snapshot gate rather than in a coarse-class
reject-all path.

From trace data (7 delayed forks attempted, 7 rejected, 0 succeeded):

| Pattern | Count | Cause |
|---------|-------|-------|
| fd 0/2 are `UnixSocket` | 4 | Node.js `socketpair()` for child stdio |
| fd 0/1/2 are `FilesystemFd` (non-host-stdio OID) | 3 | stdio redirected to `/dev/null` or similar |

Historically, both patterns fell into a reject-all arm of the snapshot
gate in `snapshot_fd_table()`. The landed code now uses an exhaustive
`match` on `FdKind`, with no wildcard arm, so every fd kind has an explicit
accept/reject decision.

## Background

### Current acceptance gate

```text
FdKind::FilesystemFd                                      → accepted (stdio identity is metadata)
FdKind::UnixSocket                                        → accepted
FdKind::HostPassthrough { .. }                            → accepted
FdKind::BrokerPipe { .. } and broker socket/inet/pty kinds → accepted
FdKind::Eventfd/Timerfd/Pidfd/Signalfd { .. }             → accepted
FdKind::Epoll / FdKind::Inotify                           → accepted unless CLOEXEC needs bridging
FdKind::BrokerInetRaw { .. } and local Net                → rejected
```

Stdio no longer has its own kind. Host stdio slots are identified by
`FdTableSnapshot::stdio_object_ids` plus per-fd metadata, while the entry's
`FdKind` remains its real subsystem kind.

### How pipe bridging works today

1. **At fork time** (`do_fork`): the child gets an **independent clone** of
   the fd table via `clone_for_fork()` (process.rs:2196–2200).  The parent
   captures `parent_pipe_fds` — a list of `(guest_fd, direction,
   pipe_pair_id)` for every pipe fd in its own table.  The parent is then
   parked until the child calls exec or exits.

2. **During pre-exec**: the child runs on the cloned fd table.  Its
   dup2/close operations do **not** affect the parent's fd table (they are
   independent clones).  However, both tables share the same underlying
   virtual pipe objects (via `Arc`), so `pipe_pair_id()` returns consistent
   values across parent and child.

3. **At commit time** (`commit_delayed_fork`): for each pipe fd in the
   child's (modified) fd table:
   - Create an OS pipe pair via `create_external_fd()`.
   - Assign endpoints by direction: child-reads → child gets read end;
     child-writes → child gets write end.
   - Drain any buffered virtual pipe data into the OS pipe.
   - Find the parent's matching fd (same `pipe_pair_id`, opposite
     direction) from the captured `parent_pipe_fds`.
   - Store a `PipeReplacement { guest_fd, host_fd, direction }` for the
     parent.
   - Add child bridge to `child_pipe_bridges` for the worker spawn CLI.

4. **After vfork completes**: the parent wakes and applies each
   `PipeReplacement` — consuming the old virtual pipe fd from its own
   fd table and inserting a `ExternalFd` at the same slot.

5. **In the child worker**: `install_external_fd()` inserts `ExternalFd`
   entries at the bridge fd slots.  When the child later calls `exec`,
   `worker_exec_input/output_binding` returns `ExternalFd { fd }`, and
   `posix_spawn_file_actions_adddup2` wires the OS fd onto the stdio slot.

### Unix socket internals

Unix sockets are **fully virtual** — no underlying OS fd.  Data flows
through in-memory `Channel<Message>` ring buffers (capacity 65536 bytes).

A connected stream socketpair consists of two `UnixConnectedStream` objects
cross-wired via two channels:

```
Socket A                          Socket B
  recv_channel  ← ReadEnd  ← Channel₁ ← WriteEnd  ← connected_send_channel
  send_channel  → WriteEnd → Channel₂ → ReadEnd   → recv_channel
```

Each `Message` contains `data: Vec<u8>` and `passed_fds: Vec<PassedFd>`.

There is **no pair identifier** on `UnixConnectedStream` today.  The only
way to check if two sockets are peers is `WriteEnd::is_pair(&ReadEnd)`,
which compares `Arc` pointers on channel endpoints.

### FD table independence at fork

In delayed fork, the child gets an independently cloned fd table via
`clone_for_fork()` (process.rs:2196–2200).  The child's pre-exec
dup2/close operations modify only the child's copy.  The parent's fd table
is **unchanged** throughout.

However, the underlying virtual objects (pipe endpoints, socket endpoints)
are **shared via `Arc`** between parent and child tables.  This means:
- `pipe_pair_id()` / `socket_pair_id()` return the same values from both
  tables (pointer-based identity on shared `Arc` allocations).
- Drain operations on the child's channel endpoints affect the shared ring
  buffer (visible to the parent's matching endpoint).
- The parent's `parent_pipe_fds` / `parent_unix_socket_fds` capture is
  needed to know the parent's fd numbers (which may differ from the child's
  after dup2/close), not because the table is shared.

---

## Design

### Overview

Follow the pipe bridge pattern for Unix sockets, using OS pipes for the
bridge (unidirectional per stdio stream).  For non-host-stdio FilesystemFd,
reopen by path (via `fd_path()`) or fall back to `/dev/null` in the child.
Direction for each socket bridge is inferred from the stdio slot
(fd 0 = Read, fd 1/2 = Write).

**Scope limitation**: this design only handles the conventional stdio
pattern where fd 0 is read-only input and fd 1/2 are write-only output.
Programs that write to fd 0 or read from fd 1/2 will get `EBADF` from the
`ExternalFd` direction check, matching real pipe semantics.  Fully
bidirectional bridging (using OS socketpair) is deferred to future work.

### Phase G1: Socket pair identification

**Goal**: Enable commit_delayed_fork to find the parent's peer socket for a
given child socket.

**Approach**: Add a `socket_pair_id()` method to `UnixConnectedStream` that
returns a stable identifier shared by both ends of a socketpair.

```rust
impl<FS: ShimFS> UnixConnectedStream<FS> {
    /// Returns a pair identifier shared by both ends of a connected pair.
    ///
    /// Computed as `min(recv_endpoint_ptr, send_peer_ptr)`.  Both peers
    /// produce the same value because the channels are cross-wired:
    ///
    ///   Socket A: recv = ReadEnd(EP_R1),  send = WriteEnd(EP_W2, peer→EP_R2)
    ///   Socket B: recv = ReadEnd(EP_R2),  send = WriteEnd(EP_W1, peer→EP_R1)
    ///
    ///   A: min(ptr(EP_R1), ptr(EP_R2)) = min(R1, R2)
    ///   B: min(ptr(EP_R2), ptr(EP_R1)) = min(R1, R2)  ✓ same value
    ///
    /// Stability: Weak::as_ptr is stable even after the peer's strong
    /// Arc is dropped (the allocation survives while weak count > 0).
    /// The clone_for_fork creates independent fd table entries but
    /// shares the same underlying Arc allocations, so parent and child
    /// compute the same pair_id.
    pub(crate) fn socket_pair_id(&self) -> usize {
        let recv_ptr = self.recv_channel.endpoint_ptr() as usize;
        let send_peer_ptr = self.connected_send_channel.peer_ptr() as usize;
        core::cmp::min(recv_ptr, send_peer_ptr)
    }
}
```

This mirrors `pipe_pair_id()` (pipes.rs:274–288), which uses
`Arc::as_ptr()` of the write-end as the canonical identity.

**Required helpers on Channel types** (channel.rs):
- `ReadEnd::endpoint_ptr(&self) -> *const ()` — expose `Arc::as_ptr`
- `WriteEnd::peer_ptr(&self) -> *const ()` — expose `Weak::as_ptr`

**Expose through UnixSocket API** (unix.rs):
- `UnixSocket::socket_pair_id(&self) -> Option<usize>` — returns `Some(id)`
  for connected stream sockets, `None` for init/listen/datagram.

**Files**: `channel.rs`, `unix.rs`
**Complexity**: Low — ~20 lines of new methods, no structural changes.

### Phase G2: Snapshot gate expansion

**Goal**: Make `UnixSocket` and non-host-stdio `FilesystemFd` acceptance
explicit in the `FdKind` snapshot gate, while keeping stdio routing as
metadata rather than as a separate fd kind.

**Changes to `snapshot_fd_table()`** (process.rs):

```rust
match subsystem_kind {
    FdKind::FilesystemFd
    | FdKind::UnixSocket
    | FdKind::HostPassthrough { .. }
    | FdKind::BrokerPipe { .. }
    | FdKind::Eventfd { .. }
    | FdKind::Timerfd { .. }
    | FdKind::Pidfd { .. }
    | FdKind::Signalfd { .. }
    | FdKind::BrokerSocketPair { .. }
    | FdKind::BrokerSocketDgram { .. }
    | FdKind::BrokerSocketSeqPacket { .. }
    | FdKind::BrokerTcpConn { .. }
    | FdKind::BrokerInetListener { .. }
    | FdKind::BrokerInetDgram { .. }
    | FdKind::BrokerPty { .. } => {}
    FdKind::Epoll | FdKind::Inotify => {
        if fd_flags.contains(FileDescriptorFlags::FD_CLOEXEC) {
            reject.push(ForkRejectReason::UnsupportedFdKind { fd: raw_fd, kind: subsystem_kind });
        }
    }
    #[cfg(feature = "worker_local_inet")]
    FdKind::Net => {
        reject.push(ForkRejectReason::UnsupportedFdKind { fd: raw_fd, kind: subsystem_kind });
    }
    FdKind::BrokerInetRaw { .. } => {
        reject.push(ForkRejectReason::UnsupportedFdKind { fd: raw_fd, kind: subsystem_kind });
    }
}
```

The landed gate no longer restricts `FdKind::UnixSocket` or non-terminal
`FdKind::FilesystemFd` to stdio slots. Later bridge and restore code still
make stdio-specific routing decisions from fd number, `object_id`, and
`FdTableSnapshot::stdio_object_ids` metadata.

The `socket_pair_id` is computed during classification for bridge setup:
probe `UnixSocketSubsystem`, downcast to `UnixSocket`, and call
`socket_pair_id()`.  It is not a second taxonomy key and does not replace
`FdKind`; socket restore/bridging decisions still start from the matched
`FdKind` variant.

**No metadata extension needed**: `socket_pair_id` is only used at commit
time (not serialized into the snapshot).  The non-stdio FilesystemFd
condition is derivable at restore time from `entry.kind == FdKind::FilesystemFd`,
the fd number, terminal metadata, and `stdio_object_ids`.  Keep
`FdMetadataSnapshot` focused on per-fd metadata; kind-specific broker handles
belong inside `FdKind` variants.

**Files**: `process.rs` (snapshot_fd_table)
**Complexity**: Low — gate expansion only, no schema changes.

### Phase G3: Unix socket bridge creation

**Goal**: Create OS pipe bridges for child Unix socket stdio fds, and
`FdReplacement`s for the parent's peer sockets.

#### Rename PipeReplacement → FdReplacement

The existing `PipeReplacement` struct is reused for socket bridges.  Rename
to `FdReplacement` to reflect broader scope:

```rust
struct FdReplacement {
    guest_fd: usize,
    host_fd: i32,
    direction: HostPassthroughFdDirection,
}
```

The old replacement-subsystem tag was removed. Parent-side replacement code
tries the concrete descriptor stores it knows how to replace (pipe, Unix
socket, PTY, filesystem as applicable) and the fork snapshot itself uses
`FdKind` as the only fd taxonomy.

#### Fork-time capture

In `do_fork()`, alongside `parent_pipe_fds`, capture
`parent_unix_socket_fds`:

```rust
parent_unix_socket_fds: Vec<(usize, usize, u64)>,
//                       guest_fd, socket_pair_id, object_id
```

Scan all alive fds in the **parent's** fd table for
`UnixSocketSubsystem`, call `socket_pair_id()`, store the triple.  This
captures the parent's socket topology before the child's pre-exec
modifications.

#### Generalize parent-side replacement

The parent wake-up code in `do_fork()` (process.rs:2573–2620) currently
only consumes `Pipes<Platform>` via `fd_consume_raw_integer`.  Generalize
to handle `UnixSocketSubsystem` as well:

```rust
for repl in replacements {
    let entry = ExternalFd::new(repl.host_fd, repl.direction);
    let mut dt = self.global.litebox.descriptor_table_mut();
    let typed_fd = dt.insert(entry);
    drop(dt);

    let old_fd_consumed;
    {
        let mut rds = files.raw_descriptor_store.write();
        // Try consuming as Pipe first, then as UnixSocket
        old_fd_consumed = rds
            .fd_consume_raw_integer::<litebox::pipes::Pipes<crate::Platform>>(repl.guest_fd)
            .map(|fd| ConsumedFd::Pipe(fd))
            .or_else(|_| rds
                .fd_consume_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(repl.guest_fd)
                .map(|fd| ConsumedFd::Socket(fd)))
            .ok();
        rds.fd_into_specific_raw_integer(typed_fd, repl.guest_fd);
    }
    // Close the consumed virtual fd
    match old_fd_consumed {
        Some(ConsumedFd::Pipe(old)) => { let _ = self.global.pipes.close(&old); }
        Some(ConsumedFd::Socket(_old)) => { /* socket drop cleans up */ }
        None => {}
    }
}
```

#### Generalize child-side installation

`install_external_fd()` (lib.rs:99–139) must also consume
`UnixSocketSubsystem` entries.  Add a probe after the existing `Pipes` and
`FS` probes:

```rust
else if let Ok(_old_sock) = rds
    .fd_consume_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(guest_fd)
{
    // Socket consumed, slot is free
}
```

#### Commit-time bridging

In `commit_delayed_fork()`, after the existing pipe bridge loop, add a
Unix socket bridge loop:

```
For each child fd that is a connected UnixSocket on a stdio slot (0/1/2):
  1. Determine direction from slot: fd 0 → Read, fd 1/2 → Write
  2. Get socket_pair_id and object_id from the child's socket
  3. Check bidirectional conflict: if the same socket appears on both
     a Read slot AND a Write slot, reject with
     ForkRejectReason::BidirectionalSocketOnMultipleStdioSlots
  4. Deduplicate: if same object_id already bridged (dup'd socket on
     multiple same-direction slots), dup the existing bridge's OS fd
  5. Create OS pipe: (os_read, os_write) = create_external_fd()
  6. Assign: child gets os_read (if Read) or os_write (if Write)
  7. Drain child's recv_channel into OS pipe (if direction == Read)
     — see Phase G4 for drain details
  8. Find ALL parent peers: filter parent_unix_socket_fds for
     matching socket_pair_id AND different object_id
  9. For EACH matching parent fd: push FdReplacement
     (handles dup'd parent fds correctly)
 10. If no matches: close unused OS end
 11. Push (child_fd, child_os_fd, direction) into child_pipe_bridges
```

**Dup'd parent fds**: when the parent has multiple fds pointing to the same
peer socket (e.g., fd 4 and fd 9 both dup'd from the same socketpair end),
ALL matching fds get replaced with `ExternalFd`.  Use `filter()` instead of
`find()` to collect all matches.  Each replacement gets a `dup_host_fd()`
of the same OS pipe end.

**Error handling**: if bridge creation fails partway through (OS pipe
creation fails, drain fails), the entire delayed fork is aborted — the
child is killed and the parent's `do_fork` returns the fork error.  Since
drain is destructive (data removed from the virtual channel), partial
drain failure must NOT allow the child to resume locally.

**Files**: `process.rs` (do_fork, commit_delayed_fork), `lib.rs`
  (ForkContext, FdReplacement, install_external_fd)
**Complexity**: Medium — follows pipe bridge pattern closely but with
  pair_id matching via object_id exclusion and dup-aware replacement.

### Phase G4: Unix socket data drain

**Goal**: Transfer any buffered data from the virtual channel into the OS
pipe before migration.

For a child socket on stdin (Read direction), the `recv_channel` may
contain `Message`s that the parent wrote before commit.  These must be
drained into the OS pipe so the child can read them after migration.

```rust
// Drain recv_channel messages into OS pipe
if direction == Read {
    while let Some(msg) = socket.drain_recv_one() {
        if !msg.data.is_empty() {
            // Enlarge OS pipe capacity (same pattern as pipe drain)
            let capacity = i32::try_from(msg.data.len())
                .unwrap_or(i32::MAX)
                .saturating_add(4096);
            platform.try_set_pipe_capacity(os_write, capacity);
            platform.write_host_fd(os_write, &msg.data)?;
        }
        // Drop msg.passed_fds — SCM_RIGHTS across host processes
        // is not supported in this bridging model.
    }
}
```

**Write direction (stdout/stderr)**: in the delayed fork model, the child
only runs pre-exec syscalls (dup2, close, setsid, ioctl) — no writes.
The child's write-side channel is therefore empty.  This is enforced by
the pre-exec allowlist which does not include write/writev/sendto.
No write-direction drain is needed.

**Drain failure semantics**: once drain starts, it is destructive (messages
are consumed from the channel).  If `write_host_fd` fails mid-drain, the
data is lost.  In this case, abort the entire delayed fork migration — do
NOT allow the child to resume locally with a partially-drained channel.
The child is killed and `do_fork` returns an error.

**Accessing the channel**: add methods to `UnixSocket`:

```rust
impl<FS: ShimFS> UnixSocket<FS> {
    /// Pop one message from the recv channel (connected stream only).
    /// Returns None if empty, not connected, or datagram.
    pub(crate) fn drain_recv_one(&self) -> Option<Message> { ... }
}
```

**Files**: `unix.rs` (drain method), `process.rs` (drain call in
  commit_delayed_fork)
**Complexity**: Low — drain is straightforward, SCM_RIGHTS is dropped.

### Phase G5: Non-host-stdio FilesystemFd handling

**Goal**: Handle non-host-stdio FilesystemFd on stdio slots so the child
worker gets a functional fd.

**Approach**: Use `fd_path()` from the filesystem trait to capture the open
path at snapshot time.  At restore time, reopen by path.  Fall back to
`/dev/null` if the path is unavailable.

**In `snapshot_fd_table()`** (process.rs): when a non-terminal
`FilesystemFd` on a stdio slot is accepted, call `fd_path()` to capture
the open path and store it in the snapshot's `open_file_descriptions`
vector (currently empty / TODO):

```rust
if subsystem_kind == FdKind::FilesystemFd && terminal_meta.is_none() {
    if let Some(path) = files.fs.fd_path(&typed_fd, &*dt) {
        open_file_descriptions.push(OpenFileDescriptionSnapshot {
            object_id: typed_fd.object_id(),
            file_offset: 0, // TODO: capture seek position
            reopen_path: Some(path),
        });
    }
}
```

**In `restore_process()`** (lib.rs): for non-terminal FilesystemFd on
stdio slots, look up the `reopen_path` from `open_file_descriptions`.  If
available, reopen.  Otherwise, open `/dev/null`:

```rust
FdKind::FilesystemFd => {
    if entry.fd <= 2 && snapshot.fd_table.stdio_object_ids.contains(&Some(entry.object_id)) {
        continue;
    }

    let path = snapshot.fd_table.open_file_descriptions.iter()
        .find(|ofd| ofd.object_id == entry.object_id)
        .and_then(|ofd| ofd.reopen_path.as_deref())
        .unwrap_or("/dev/null");
    let flags = if entry.fd == 0 { OFlags::RDONLY } else { OFlags::WRONLY };
    let fd = files.open(path, flags, Mode::empty())?;
    rds.fd_into_specific_raw_integer(fd, entry.fd);
}
```

Note: `restore_process()` pre-populates fds 0/1/2 via
`initialize_stdio_in_shared_descriptors_table()`.  The reopen above must
first consume the existing entry at the slot before inserting.

**No bridge needed**: the child's reopened fd is independent of the parent.
The parent's fd table is unmodified (tables are independent clones).

**Files**: `lib.rs` (restore_process), `process.rs` (snapshot_fd_table),
  `fork_snapshot.rs` (OpenFileDescriptionSnapshot — already defined)
**Complexity**: Low.

---

## Implementation Order

| Phase | Description | Dependencies |
|-------|-------------|--------------|
| G1 | Socket pair identification | None |
| G2 | Snapshot gate expansion | G1 (for socket_pair_id probe) |
| G3 | Unix socket bridge creation | G1, G2 |
| G4 | Unix socket data drain | G3 |
| G5 | Non-host-stdio FilesystemFd | G2 |

G5 is independent of G3/G4 and can be implemented in any order after G2.

## Limitations & Future Work

1. **Bidirectional bridging**: the current design uses unidirectional OS
   pipes.  Programs using a single socketpair for both stdin AND stdout
   (different directions on different stdio slots) are explicitly rejected
   with `ForkRejectReason::BidirectionalSocketOnMultipleStdioSlots`.
   Full-duplex support via OS socketpair is deferred to future work.

2. **Non-stdio Unix sockets**: the old stdio-only gate is gone. Local
   `FdKind::UnixSocket` entries are accepted by the snapshot gate, and
   broker-backed socketpair/datagram/seqpacket sockets have distinct
   `FdKind` variants carrying their handles. Any remaining limitation is in
   the specific restore/bridge path, not in lossy snapshot classification.

3. **SCM_RIGHTS (fd passing)**: `passed_fds` in drained messages are
   dropped.  Cross-process fd passing is not supported.

4. **Datagram sockets**: broker datagram and seqpacket sockets are no
   longer folded into a generic Unix-socket bucket; they are accepted as
   distinct `FdKind::BrokerSocketDgram` / `FdKind::BrokerSocketSeqPacket`
   entries with their own broker handles. Local Unix-socket edge cases
   should be evaluated against their concrete restore arm.

5. **FilesystemFd on fd > 2**: non-stdio filesystem fds are accepted as
   `FdKind::FilesystemFd` and reopened from the recorded OFD path when
   available. Seek restoration remains future work.

6. **Seek position**: `OpenFileDescriptionSnapshot.file_offset` is not yet
   captured.  Regular file redirections may resume at the wrong offset.

7. **ExternalFd direction enforcement**: after bridging, the child's fd 0
   is a Read-only ExternalFd and fd 1/2 are Write-only.  Programs that
   write to fd 0 or read from fd 1/2 get `EBADF`, matching real pipe
   semantics.  This is correct for conventional stdio usage but breaks
   programs using bidirectional sockets on single fd slots.
