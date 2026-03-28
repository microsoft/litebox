# Delayed Fork: Deferred True-Fork for Linux Userland

## Problem Statement

The true `fork()` implementation (Phases 1–10) snapshots the parent process
state and restores it in a new worker host process.  This is correct but
expensive: serializing memory, spawning a new process, and deserializing the
snapshot have measurable cost.

In practice, the vast majority of `fork()` calls are immediately followed by
`execve()`.  The existing vfork-style path (parent suspended, child shares
address space with CoW protection) handles this pattern efficiently — the child
never needs its own copy of the parent's memory because `execve()` replaces it
entirely.

The remaining cases where a true fork is actually needed are:

1. **Non-PIE exec**: The child calls `execve()` with a non-PIE binary that
   requires a fixed load address incompatible with the current VA layout.
   This is already detected at exec time and handled by spawning a worker host.

2. **Fork without exec**: The child never calls `execve()` — it continues
   running the same binary independently.  This is the only case that truly
   requires the snapshot+restore path.

**Goal**: Avoid paying the snapshot+restore cost for fork+exec, which is the
common case.  Only trigger the expensive path when we detect the child intends
to run independently.

## Design: Delayed Fork

### Core Idea

Instead of deciding at `fork()` time whether to use vfork-style or true-fork,
**always start with vfork-style** (parent suspended, CoW protection) and defer
the decision:

- If the child calls `execve()` → proceed with the fast vfork path (no
  snapshot needed).
- If the child calls `_exit()` / `exit_group()` → proceed with the fast vfork
  path.
- If the child calls a syscall that indicates independent execution → trigger a
  **delayed true fork**: snapshot the child's current state, spawn a worker
  host, restore the child there, and resume the parent.

### Three-Tier Routing

```
fork() syscall
  │
  ▼
Always start vfork-style (parent suspended, CoW layer)
  │
  ├─ Child calls execve()
  │   └─ Fast path: exec in shared address space (or spawn worker for non-PIE)
  │      Parent resumes via VforkDone
  │
  ├─ Child calls _exit() / exit_group()
  │   └─ Fast path: child exits, parent resumes via VforkDone
  │
  └─ Child calls a "non-pre-exec" syscall
      └─ Delayed true fork:
         1. Snapshot child's current state
         2. Spawn worker host, restore child
         3. Signal VforkDone → parent resumes
         4. Child continues in worker host
```

### Pre-Exec Syscall Allowlist

The vfork contract allows the child to call only `execve()` or `_exit()`.
In practice, `posix_spawn()` and runtime libraries perform a small set of
fd/signal/process-group setup operations between fork and exec.  These are
safe because they don't require an independent address space.

**Allowed syscalls** (child remains in vfork-style mode):

| Category | Syscalls | Notes |
|----------|----------|-------|
| Exec/exit | `execve`, `execveat`, `exit`, `exit_group` | Terminal — child leaves vfork mode |
| FD plumbing | `close`, `dup`, `dup2`, `dup3`, `open`, `openat`, `pipe2` | Number-only match sufficient |
| FD plumbing | `fcntl` with `F_SETFD`, `F_DUPFD`, `F_DUPFD_CLOEXEC` | **Argument-aware**: check second arg |
| FD plumbing | `write` | For posix_spawn error-pipe reporting |
| Directory | `chdir`, `fchdir` | |
| Process group | `setpgid`, `setsid` | |
| Signal setup | `rt_sigaction`, `rt_sigprocmask`, `sigaltstack` | |
| Process attrs | `prctl` with `PR_SET_PDEATHSIG`, `PR_SET_NAME` | **Argument-aware**: check first arg |
| Identity | `setuid`, `setgid`, `setgroups`, `setreuid`, `setregid` | |
| Scheduling | `sched_setscheduler`, `sched_setaffinity` | |
| Resource | `setrlimit`, `prlimit64` | |
| No-ops | `getpid`, `getppid`, `gettid`, `getuid`, `getgid` | |

**Any syscall not in this list triggers the delayed true fork.**

#### Argument-Aware Filtering

Two syscalls (`fcntl` and `prctl`) cannot be matched by syscall number alone
because they multiplex many operations through a single number:

- **`fcntl`**: Only `F_SETFD`, `F_DUPFD`, and `F_DUPFD_CLOEXEC` are pre-exec
  operations (setting close-on-exec, duplicating fds).  Other commands like
  `F_SETLK` (file locking), `F_SETFL` (changing O_NONBLOCK), or `F_SETOWN`
  (signal ownership) imply independent execution and must trigger the fork.
  The check reads the command from the second syscall argument (`ctx.rsi` on
  x86_64) before `SyscallRequest` parsing.

- **`prctl`**: Only `PR_SET_PDEATHSIG` and `PR_SET_NAME` are pre-exec
  operations.  Other sub-commands like `PR_SET_MM`, `PR_SET_SECCOMP`, or
  `PR_SET_TIMERSLACK` imply independent execution.  The check reads the
  operation from the first syscall argument (`ctx.rdi` on x86_64).

The check uses raw register values (not parsed `SyscallRequest`) because it
runs before the normal dispatch path.

#### Notable Triggers (Non-Allowlisted)

- `read` — any read implies the child is doing real work, not just pre-exec setup
- `mmap`, `mprotect`, `munmap`, `brk` — address space mutation
- `clone`, `clone3` — thread creation or nested fork
- `wait4`, `waitid` — managing child processes
- `socket`, `connect`, `bind` — network activity
- `epoll_create`, `eventfd`, `timerfd_create` — event infrastructure

#### Known False Positives

- **`write` on posix_spawn exec-failure path**: When `execve()` fails inside
  a posix_spawn child, the child writes the errno to the error pipe then calls
  `_exit()`.  `write` is in the allowlist for this reason.  However, `write`
  to a regular file (not an error pipe) also passes through without triggering
  the fork.  This is acceptable: the child will either exec (fast path) or
  make another non-allowlisted syscall shortly after.

- **`fcntl(F_DUPFD)` for non-pre-exec purposes**: Rare, and the child will
  subsequently make a non-allowlisted syscall that triggers the fork.

### Detailed Flow

#### Step 1: Fork Entry (Unchanged from Current)

`do_fork()` always enters the vfork-style path for `is_shared && !is_vfork`:

```rust
if is_shared && !is_vfork {
    // Instead of calling do_true_fork() immediately, set up vfork-style
    // with a "delayed fork pending" flag on the child task.
}
```

The child Task is created with:
- `fork_context = Some(ForkContext { ... })` (same as current vfork)
- A new flag: `delayed_fork_pending = true`
- Parent blocks on `VforkDone` (same as current vfork)

#### Step 2: Child Syscall Interception

In `do_syscall()`, before dispatching the syscall request, check for the
delayed fork trigger:

```rust
fn do_syscall(&self, ctx: &mut ExecutionContext) -> Result<usize, Errno> {
    // Check for delayed fork trigger.
    if self.delayed_fork_pending.get() {
        if !is_pre_exec_syscall(ctx) {
            self.commit_delayed_fork(ctx)?;
            // After commit, this task's local process is about to exit.
            // The child continues in the worker host.  See Step 3/4.
        }
    }

    // Normal dispatch continues (for allowlisted syscalls, or after
    // commit_delayed_fork returns for the local cleanup path).
    let request = SyscallRequest::try_from_raw(...);
    match request { ... }
}
```

The `is_pre_exec_syscall(ctx)` function performs a two-level check:
1. Extract the syscall number from `ctx` (e.g., `ctx.orig_rax` on x86_64).
2. For most syscalls, match on number alone.
3. For `fcntl`: also check the command argument (`ctx.rsi`) — only allow
   `F_SETFD`, `F_DUPFD`, `F_DUPFD_CLOEXEC`.
4. For `prctl`: also check the operation argument (`ctx.rdi`) — only allow
   `PR_SET_PDEATHSIG`, `PR_SET_NAME`.
5. Any unrecognized syscall number returns `false` (triggers delayed fork).

#### Step 3: Commit Delayed Fork

When the trigger fires, `commit_delayed_fork()` performs the full
snapshot+restore sequence:

```
commit_delayed_fork(ctx):
    1. Park sibling threads (should already be parked by vfork)
    2. Snapshot the child's CURRENT state:
       - Memory: read live pages directly (child's CoW writes are in-place)
       - Registers: from ctx (the triggering syscall's entry state)
       - FD table: child's clone_for_fork'd table (may have close/dup2 changes)
       - FS state: child's FsState clone (may have chdir/umask changes)
       - Signal state: child's SignalState (may have sigaction changes)
       - Other: credentials, rlimits, etc.
    3. Serialize snapshot
    4. Spawn worker host for fork restore
    5. Wait for restore ack
    6. On success:
       a. Restore CoW layer (undo child's memory writes in parent's address space)
       b. Signal VforkDone → parent resumes
       c. Spawn background waiter thread (Phase 9 pattern)
       d. Register child in control plane (migrate from local to remote)
       e. The local child task exits (returns special "migrated" status)
       f. Worker host child re-executes the triggering syscall
    7. On failure:
       a. Force-exit the child task (deliver SIGKILL-equivalent)
       b. Signal VforkDone with error indicator → parent resumes
       c. Parent's fork() returns -ENOMEM
```

**Critical ordering in step 6**: The snapshot must read live memory (step 2)
*before* `restore_cow_layer()` undoes the child's writes (step 6a).  And
`restore_cow_layer()` must complete *before* `VforkDone` is signaled (step 6b),
otherwise the parent resumes with the child's mutations still in its address
space.

**Failure semantics (step 7)**: Returning an error to the child while the
parent remains suspended would leave the system in a problematic state — the
child would retry or behave unpredictably while the parent is blocked.
Instead, on failure we force-exit the child and propagate the error back to
the parent's `fork()` call.  This requires extending `VforkDone` to carry an
optional error status (a small change — add an `AtomicU32` for the error code
alongside the existing `AtomicBool`).

#### Step 4: Child Continues in Worker Host

The worker host restores the child and resumes execution at the syscall
that triggered the delayed fork.  The child's registers are set to the
state at syscall entry, so the syscall dispatch in the worker host will
re-execute the triggering syscall from scratch.

The **local** child task (in the parent's process) exits after
`commit_delayed_fork()` succeeds.  It does not continue dispatching
syscalls locally — its execution has migrated to the worker host.

**PID/TID identity**: The child's guest PID and TID were allocated during
`do_fork()` (before the delayed fork trigger).  The worker host's restored
child must use these same PID/TID values, not allocate fresh ones.  The
existing snapshot format already captures `pid` and `tid` fields, so
`commit_delayed_fork()` reuses the eager fork's serialization path with
the child's already-assigned identity.

**Control-plane migration**: At `do_fork()` time, the child is registered
in the local process registry.  At `commit_delayed_fork()` time, it must
be migrated: deregistered locally and re-registered as a remote child
(same pattern as the eager `do_true_fork()` path, which registers the
child in `fork_child_host_pids` and the control plane).

#### Step 5: Parent Resumes

`VforkDone::signal()` wakes the parent, which:
1. Restores the CoW layer (already done in step 6a, before VforkDone)
2. Unparks sibling threads
3. Returns the child PID to the parent's `fork()` call

If `VforkDone` carries an error (step 7b), the parent instead returns
`-ENOMEM` from `fork()`.

## Key Design Decisions

### Why an Allowlist, Not a Denylist?

A denylist ("trigger on mmap, brk, clone, ...") is fragile — new syscalls
could slip through without triggering the fork.  An allowlist is conservative:
any unknown or unexpected syscall triggers the fork.  The worst case is a
slightly premature fork (costing performance), never a missed fork (causing
correctness bugs).

### What If a Pre-Exec Syscall Mutates State?

The child may call `close(3); dup2(5, 0); chdir("/tmp")` before triggering
the delayed fork.  These mutations are captured correctly because:

- **FD table**: The child has its own `FilesState` (cloned at fork time via
  `clone_for_fork`).  `close`/`dup2` modify only the child's table.

- **FS state** (`cwd`, `umask`, `exe_path`): Currently shared via
  `Arc<FsState>` between parent and child in vfork mode.  The child's
  `chdir()` would mutate the parent's cwd, and `umask()` would mutate the
  parent's umask.  **Phase A clones FsState at fork time** (like FilesState),
  so the child gets its own copy of all three fields.  After the clone:
  - `chdir`/`fchdir` modify only the child's cwd
  - `umask` (if it were allowlisted) would modify only the child's umask
  - At delayed-fork time, the snapshot captures the child's mutated FsState

- **Signal state**: `rt_sigaction`/`rt_sigprocmask` modify per-task state
  (already cloned at fork time).

- **Memory**: Pre-exec syscalls like `close`/`dup2`/`chdir` don't allocate
  guest memory, but `open`/`openat` may write to guest buffers.  These writes
  go through the CoW layer and are captured in the live-memory snapshot.

### Snapshot Source: Child vs. Parent

At delayed-fork time, we snapshot the **child's** current state:
- **Registers**: from the child's `ctx` at the triggering syscall entry
- **Memory**: read live pages directly — child's CoW writes are in-place,
  parent's originals are saved in `CowState.dirty_pages`.  The snapshot
  reads current memory as-is (no reconstruction from parent + overlay).
  After the snapshot is serialized and sent, `restore_cow_layer()` undoes
  the child's writes.
- **FD table**: from the child's `FilesState` (cloned at fork, may have
  close/dup2/open mutations)
- **FS state**: from the child's `FsState` (cloned at fork, may have
  chdir mutations)
- **Signal state**: from the child's `SignalState` (cloned at fork, may
  have sigaction/sigprocmask mutations)

This is different from the eager true fork (Phases 1–10), which snapshots
the **parent's** state at fork time.  The delayed fork snapshots are
slightly more complex because they must account for pre-exec mutations.

### Snapshot FD Portability

The current eager fork snapshot rejects processes with non-stdio host-backed
FDs (pipes, sockets, eventfds, etc.) because host FD numbers are not portable
across processes.  For the delayed fork path, the child may have called
`open()` or `pipe2()` during the pre-exec window, creating new FDs.

The same rejection policy applies: if the child's FD table contains
non-portable host FDs (beyond the stdin/stdout/stderr that are remapped
during restore), `commit_delayed_fork()` must either:
1. Reject the snapshot (fall back to error path), or
2. Extend the snapshot format to carry host FD contents (future work).

In practice, pre-exec `open()` creates VFS-backed FDs (which are portable)
or 9P-backed FDs (which are portable via the broker).  Host-backed pipes
from `pipe2()` are the main concern — these could be handled by reading
their contents into the snapshot, but this is deferred to a later phase.

### Parent Suspension Duration

The parent is suspended from `fork()` until either:
- `execve()` (fast path, current behavior)
- A non-allowlisted syscall triggers delayed fork (snapshot+restore time)

The delayed fork path adds latency proportional to the snapshot size.  For
programs that call `fork()` and immediately do non-exec work (e.g., daemon
double-fork patterns), the parent suspension is:

```
time = pre-exec syscalls + snapshot + spawn + restore + ack
```

This is comparable to the eager true fork latency, but deferred to the
point where we know it's needed.

### Non-PIE Exec Detection

The existing non-PIE detection in `execve()` is orthogonal to this design.
When a vfork child calls `execve()` with a non-PIE binary:
1. The exec path detects the fixed-address conflict
2. It spawns a worker host for the exec (existing mechanism)
3. Signals `VforkDone` → parent resumes

This works regardless of whether the child was in delayed-fork-pending mode
or not.

## Interaction with Existing Implementation

### Changes to Existing True Fork (Phases 1–10)

The eager `do_true_fork()` path becomes the **implementation of
`commit_delayed_fork()`**.  The core snapshot/serialize/spawn/restore
machinery is reused.  The differences are:

1. **Trigger point**: Called from `do_syscall()` instead of `do_fork()`.
2. **Snapshot source**: Child's current state (with pre-exec mutations)
   instead of parent's state at fork time.  Memory is read from live pages
   (child's CoW writes in-place), not from the parent's perspective.
3. **VforkDone signaling**: `commit_delayed_fork()` restores the CoW layer
   and signals VforkDone after the worker host ack, instead of
   `do_true_fork()` returning to the parent directly.
4. **Child continuation**: The worker host child re-executes the triggering
   syscall, instead of returning 0 from fork.
5. **Identity reuse**: The child's PID/TID were already allocated in
   `do_fork()`.  The snapshot carries these existing values — no fresh
   allocation in the worker host.
6. **Control-plane migration**: The child is already registered locally at
   `do_fork()` time.  `commit_delayed_fork()` must deregister it locally
   and re-register as a remote child (in `fork_child_host_pids` and the
   control plane), matching the eager fork pattern.

### Changes to `do_fork()`

The `is_shared && !is_vfork` branch no longer calls `do_true_fork()`.
Instead, it falls through to the vfork-style path with an additional flag:

```rust
if is_shared && !is_vfork {
    // Mark child for delayed fork instead of eager true fork.
    delayed_fork = true;
}
```

### Changes to `Task` State

```rust
struct Task<FS: ShimFS> {
    // ... existing fields ...

    /// When true, this task is a fork child running in vfork-style mode
    /// that should be upgraded to a true fork if it makes a non-pre-exec
    /// syscall.
    ///
    /// Note: This is distinct from the existing `deferred_vfork_park` flag,
    /// which controls sibling-thread parking coordination.  The two flags
    /// serve orthogonal purposes and do not interact.
    delayed_fork_pending: Cell<bool>,
}
```

### Changes to `do_syscall()`

A check at the top of `do_syscall()`:

```rust
if self.delayed_fork_pending.get() {
    if !is_pre_exec_syscall(ctx) {
        // Trigger delayed fork.  On success, the child has been migrated
        // to a worker host.  This local task should exit.
        match self.commit_delayed_fork(ctx) {
            Ok(()) => return Ok(MIGRATED_SENTINEL),  // local task exits
            Err(e) => {
                // Force-exit child, signal VforkDone with error.
                // Parent's fork() returns -ENOMEM.
                self.force_exit_delayed_fork_child();
                return Err(e);
            }
        }
    }
    // Allowlisted syscall — continue normal dispatch in vfork mode.
}
```

## Edge Cases

### Fork Bomb / Recursive Fork

If the child calls `fork()` again before exec, this triggers the delayed
fork (since `clone`/`clone3` is not in the allowlist).  The
`commit_delayed_fork()` snapshots the child and spawns it in a worker host.
The grandchild's `fork()` is then handled normally by the worker host's shim.

### Child Dies Before Triggering

If the child crashes (signal death) before calling any syscall, the
`prepare_for_exit()` path signals `VforkDone` and the parent resumes.
No delayed fork is needed.

### Multiple Threads at Fork Time

Other threads are parked by the vfork CoW setup (same as current behavior).
They remain parked until `VforkDone` is signaled.  The delayed fork path
does not change this.

### Exec After Pre-Exec Mutations

If the child does `close(3); dup2(5, 0); execve(...)`, the exec path runs
normally in vfork-style mode.  The FD mutations are visible to the exec'd
program.  No delayed fork is triggered.

### Signal Delivery During Delayed-Fork Window

If a signal with a user-registered handler is delivered to the child
between `fork()` and the delayed-fork trigger, the handler may execute
arbitrary syscalls.  These syscalls go through `do_syscall()`, hit the
`delayed_fork_pending` check, and could trigger the delayed fork **from
inside a signal handler context**.

At that point:
- The `ctx` registers reflect the signal handler's frame, not a normal
  syscall entry.
- The snapshot captures signal-handler-mid-execution state.
- The worker host restores into a signal handler frame.

This is technically correct — the child's state *is* mid-signal-handler —
but subtle.  In practice, `posix_spawn` implementations block all signals
in the child via `sigprocmask` before doing fd setup, so this is rare for
the fork+exec path.  For a plain `fork()` child that hasn't blocked
signals, the snapshot correctly captures the full execution state including
any in-progress signal handler frames.

### Exec Failure (posix_spawn Error Pipe)

When `execve()` fails inside a posix_spawn child, the standard pattern is:
```c
write(error_pipe_fd, &errno, sizeof(errno));  // report failure to parent
_exit(127);
```

Since `write` is in the allowlist, this completes without triggering a
delayed fork — the child writes the error and exits, the parent resumes
via VforkDone.  This is the desired behavior.

## Performance Characteristics

| Scenario | Current (Eager) | Delayed Fork |
|----------|----------------|--------------|
| fork + exec (99% of cases) | Snapshot + spawn + restore | vfork-style (fast) |
| fork + non-PIE exec | Snapshot + spawn + restore | vfork + exec detects non-PIE (same cost) |
| fork without exec (rare) | Snapshot + spawn + restore | vfork + delayed snapshot (same cost, deferred) |

The delayed fork approach eliminates the snapshot+restore cost for the common
case (fork+exec) and defers it to the point of actual need for the rare case
(fork without exec).

## Implementation Phases

### Phase A: FsState Cloning at Fork

Clone `FsState` at fork time (like `FilesState`) so pre-exec `chdir()` and
`umask()` in the child do not mutate the parent's state.  All three fields
(`cwd`, `umask`, `exe_path`) are isolated by the clone.  This is a
prerequisite for the delayed fork optimization but is also a correctness fix
for the existing vfork path (child's chdir currently leaks into the parent).

### Phase B: Delayed Fork Flag and Allowlist

1. Add `delayed_fork_pending: Cell<bool>` to `Task`.
2. Change `do_fork()` to set the flag instead of calling `do_true_fork()`.
3. Implement `is_pre_exec_syscall()` allowlist check.
4. Add the trigger check in `do_syscall()`.

### Phase C: Commit Delayed Fork

1. Refactor `do_true_fork()` into `commit_delayed_fork()`.
2. Adapt snapshot capture to use the child's current state.
3. Signal `VforkDone` after worker host ack.
4. Handle the child's syscall re-execution in the worker host.

### Phase D: Testing

1. Verify fork+exec path is not affected (vfork behavior preserved).
2. Verify fork-without-exec triggers delayed fork and child runs correctly.
3. Verify pre-exec mutations (close, dup2, chdir) are captured in snapshot.
4. Performance comparison: fork+exec latency before and after optimization.
