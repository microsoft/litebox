# Mux Mesh: Pipe Bridging Across Nested Worker Hosts

## Problem

When a guest process forks and the child migrates to a worker host via
delayed fork, virtual pipe endpoints (pipes, Unix sockets) don't survive
across host process boundaries.  The mux multiplexer bridges them over a
socketpair.  But when the child worker itself forks a grandchild (another
worker host), the pipe chain can break:

1. The child worker's pipe at fd=N was installed by the parent's mux
   (`install_mux_pipe_fd`).
2. When the child forks a grandchild, `commit_delayed_fork` replaces
   fd=N with a new pipe for the grandchild's mux.
3. The parent's mux relay receiver loses its peer → `is_peer_shutdown()`
   → parent mux sends RESET → data stops flowing.

Additionally, pipe pairs created by the child between fork and exec
(e.g., bash's self-pipe at fds 3/4) have no parent counterpart.
The parent sends RESET for these orphaned streams → child gets
SIGPIPE → child killed before producing stdout output.

## Model: Every Worker Is a Potential Parent

A **host process** (worker) runs a shim that manages guest processes
in a shared address space.  Each guest process's pipe fd falls into
one of four cases relative to the host boundary:

```
┌─────────────────────────────────────────────────────┐
│  HOST PROCESS                                       │
│                                                     │
│  ┌─────────┐  virtual pipe  ┌─────────┐            │
│  │ Process A│ ←────────────→ │ Process B│  CASE 1   │
│  └─────────┘                └─────────┘            │
│       │                                             │
│       │ mux relay (receiver end)                    │
│       │                                             │
├───────┼─────────────────────────────────────────────┤
│       │ socketpair to parent host          CASE 2   │
└───────┼─────────────────────────────────────────────┘
        ↕
  PARENT HOST
```

| Case | Both ends | Mechanism |
|------|-----------|-----------|
| 1. Both inside | Parent and child in same host | Virtual pipe, shared ring buffer. No mux. |
| 2. Parent outside | Pipe installed by parent host's mux | Mux relay connects virtual pipe → parent socketpair |
| 3. Child outside | Guest forked child that migrated out | New mux connects virtual pipe → child socketpair |
| 4. Chained (both outside) | Installed by parent mux, needed by child mux | Same pipe serves both relays (see below) |

## Design: Pipe Counterpart Matching

When `commit_delayed_fork` bridges child pipes, it must find the
correct parent counterpart for each child fd.  The matching uses a
two-tier strategy:

### 1. pair_id + opposite direction (primary)

The child may `dup2` a pipe to a different fd number between fork and
exec (e.g., `dup2(6, 1)` for stdout redirection).  Matching by fd
number would miss the counterpart.  Instead, match by `pipe_pair_id`
(the `Arc` pointer identity of the pipe pair) and opposite direction:

```
child fd=1 (Write, pair_P)  →  find parent fd with (pair_P, Read)
                                → parent fd=4 (Read, pair_P) ✓
```

### 2. Same fd number (fallback)

When pair_id matching fails (child created a new pipe at a fd slot
the parent also uses for a different pipe), fall back to fd-number
matching.  The direction is set to the **opposite of the child's
direction** (representing the data flow from the parent's perspective):

```
child fd=3 (Write, pair_Q)  →  pair_Q not in parent
                             →  fallback: parent fd=3 exists
                             →  direction = Read (opposite of Write)
```

### 3. Deduplication

A `claimed_parent_fds` set prevents two streams from claiming the
same parent fd (which would corrupt the replacement).  pair_id
matches have priority; fd-number fallback skips claimed fds.

### 4. Child-only pipe pairs

Pipe pairs where both ends (same `pair_id`, opposite directions) are
in the child's fd table but NOT in `parent_pipe_fds` were created by
the child between fork and exec.  These are excluded from the mux
entirely and passed to the worker via `--local-pipe write_fd:read_fd`.
The worker creates a connected pipe pair via `create_pipe()` and
installs both ends.  This pipe is a real virtual pipe that
participates in future fork bridges if the child becomes a parent.

## Design: Chain-Safe Replacement

When the parent has the **opposite end** of the pipe (first-fork case),
the parent's fd is replaced with a new virtual pipe connected to the
mux dispatcher.  Two invariants prevent chain breakage:

### Invariant 1: Old pipes are never closed during replacement

`fd_consume_raw_integer` frees the fd slot.  But `pipes.close()` is
**not** called on the consumed entry.  Instead, the old `TypedFd` is
moved into a keepalive store (`keepalive_pipes` in the dispatcher
closure).  This preserves the `SharedEntry` and the `Weak` peer link:

```
Before replacement:
  fd=4: old_receiver (SharedEntry A)  ←Weak→  sender (SharedEntry B)

After replacement:
  fd=4: new_receiver (SharedEntry C)  ←Weak→  new_sender (SharedEntry D)
  keepalive: old_receiver (SharedEntry A still alive)
             → sender's Weak<A> still upgrades
             → is_peer_shutdown() = false
```

### Invariant 2: New parent pipe is duplicated for keepalive

The new pipe end installed at the parent's fd is duplicated via
`descriptor_table.duplicate()` before installation.  The duplicate
lives in the keepalive store.  When the parent later closes the fd
(removing the DT entry), the duplicate keeps the `SharedEntry` alive:

```
Parent closes fd=4:
  fd=4: removed from DT
  keepalive: duplicate of new_receiver (SharedEntry C still alive)
           → new_sender's Weak<C> still upgrades
           → dispatcher can still write to new_sender
```

## Design: Chained Data Flow (Case 4)

When a host's mux-installed pipe is also needed by a child's mux,
the same-direction fd-number fallback produces `use_existing_pipe=true`.
The child's mux dispatcher uses the **existing** pipe — no replacement:

```
HOST A                    HOST B                    HOST C
(grandparent)             (parent)                  (child)

P has fd=4 (recv)         C has fd=1 (sender)       G has fd=1 (sender)
P has fd=5 (sender)       installed by A's mux      installed by B's mux
                          B's relay reads recv
replaced by mux ←sock→   B's relay writes sender ←sock→  G writes to
to A                      existing pipe!                   mux sender
                          (use_existing=true)

Data flow:
G writes fd=1 → HOST C mux → HOST B dispatcher
  → writes to existing sender at fd=1 in HOST B
  → ring buffer
  → HOST B's parent-mux relay reads from receiver
  → HOST B mux → HOST A dispatcher
  → writes to new pipe at fd=4 in HOST A
  → P reads from fd=4
```

The chain works because:

1. **HOST A** (first fork): pair_id match finds opposite-direction
   counterpart → replacement at fd=4 → keepalive preserves old pipe
2. **HOST B** (nested fork): same-direction fd-number fallback →
   `is_first_fork=false` (only sender in fd table, no receiver) →
   `use_existing_pipe=true` → no replacement → parent relay stays
   connected
3. **HOST C, D, ...**: same pattern as HOST B — each level uses
   `use_existing_pipe=true`, chaining through

### Critical: `is_first_fork` must not self-match

The fd-number fallback computes `flow_dir` (opposite of child's
direction) for the counterpart tuple.  The `is_first_fork` check
must compare against the parent's **actual** direction at the matched
fd, not `flow_dir` — otherwise the matched fd satisfies its own
"opposite end" predicate and every nested fork is incorrectly
classified as first-fork (causing replacement instead of reuse).

```
WRONG: dir != flow_dir         → matched fd itself matches → always true
RIGHT: dir != actual_parent_dir → requires a genuinely different fd
```

## Design: Orphan Handling

After matching, some child streams have no parent counterpart:

- **Read-direction orphans**: RESET is correct — POSIX EOF semantics.
  The child reads EOF from this fd.
- **Write-direction orphans**: RESET would cause SIGPIPE if the child
  writes.  With child-only pair detection, most write-direction
  orphans are already excluded (they're one end of a child-only
  pair).  Remaining write-direction orphans are genuinely broken
  pipes and SHOULD get RESET (correct POSIX EPIPE).

## Summary of Changes

| Component | Change |
|-----------|--------|
| `commit_delayed_fork` | pair_id matching, fd-number fallback, claimed dedup, child-only pair detection |
| `commit_delayed_fork` | Pass `local_pipe_pairs` to worker spawn |
| `do_fork` (parent resume) | Keepalive for old pipes and new pipe duplicates; direction fix for fd-number fallback |
| `spawn_worker_host_for_fork_restore` | Accept + forward `--local-pipe` CLI args |
| `fork_restore_and_ack` (worker) | Create connected pipe pairs for `--local-pipe` specs |
| Orphan handling | RESET for read-direction only; child-only pairs excluded entirely |
