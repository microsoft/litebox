# True `fork()` on Linux Userland

## Problem Statement

The Linux shim currently does not implement a true `fork()` when running on the
Linux userland platform.

On Linux userland, `AddressSpaceProvider::fork_address_space()` returns
`SharedWithParent`, and the shim's `do_fork()` path therefore behaves like a
shim-managed `vfork()`:

- the child initially shares the parent's `ProcessState`
- sibling threads are parked
- writable pages are protected with shim-managed copy-on-write
- the parent blocks until the child `execve()`s or exits
- the child only detaches into its own address space on `execve()`

That is good enough for the current `vfork`-style implementation, but it is not
correct for a true `fork()`, where the parent and child must both continue
running concurrently after the syscall returns.

The goal of this design is to implement a true `fork()` on Linux userland in
two explicit steps:

1. snapshot the parent process state at the fork point
2. restore that snapshot in another host process and resume execution there

## Current State

### Fork and clone behavior today

The syscall decoding layer translates `fork()` and `vfork()` into `Clone`
requests, with `vfork()` setting `CLONE_VM | CLONE_VFORK`.

In the Linux shim:

- `Task::do_clone()` routes fork-like calls to `Task::do_fork()`
- `Task::do_fork()` creates the child process entry in `ProcessRegistry`
- the Linux userland platform returns `ForkedAddressSpace::SharedWithParent`
- the child is started on a new host thread in the same host process
- the parent waits for `VforkDone`

The key consequence is that Linux userland currently has **shared-fork**
semantics, not independent-fork semantics.

### Remote host support today

The codebase already has one important piece of prior art: remote worker-host
startup for `execve()` of binaries that cannot be loaded in the current virtual
address-space partition.

That worker-host path is useful infrastructure, but it is not a process-restore
path:

- the worker boots a fresh shim instance
- it restores guest-visible `pid`, `ppid`, and credentials from CLI flags
- internally, it still runs as a freshly bootstrapped local process
- the control plane already has pieces of running-process ownership and child-exit
  routing across hosts, but user-visible control of a live remote-owned process
  is still incomplete

Today, operations like `wait4`, `pidfd_open`, and `kill` against a running
remote-owned process are rejected with `EOPNOTSUPP`. That is acceptable for the
current remote-exec handoff, but not for a true remote `fork()`. The true-fork
design therefore needs to extend the existing ownership and exit-routing
machinery rather than assuming there is no remote-running-process support at
all.

### What already works well

Several parts of the current implementation are strong building blocks for true
fork:

- `FilesState::clone_for_fork()` and `RawDescriptorStorage::clone_for_fork()`
  already model POSIX "new fd table, shared open-file descriptions" semantics
  inside one host process
- `SignalState::clone_for_fork()` already deep-copies handlers and resets
  pending state in a fork-friendly way
- the existing vfork CoW implementation already shows how to freeze sibling
  threads and walk writable mappings safely
- the worker-host launcher in `litebox_platform_linux_userland` already knows
  how to spawn a new runner instance and pass bootstrap resources to it

## Design Goals

- Implement true `fork()` semantics on Linux userland.
- Make the child run in a separate host process from the beginning.
- Preserve Linux-visible process identity, ancestry, signals, fd behavior, and
  memory state.
- Reuse existing worker-host spawning infrastructure where practical.
- Keep the design correctness-first; optimize later.

## Non-Goals

- This design does not change the existing `vfork()` implementation.
- This design does not attempt to optimize snapshot size in the first version.
- This design does not require full cross-host migration of arbitrary running
  processes; it is specifically about creating a new fork child in another host
  process.

## Proposed Design

Implement true `fork()` as two explicit phases:

- **Phase 1: snapshot in the parent host process**
- **Phase 2: restore in a new child host process**

The snapshot boundary is the guest fork trap: after syscall arguments are
validated, but before the parent returns to guest mode.

### Phase 1: snapshot in the parent host process

The parent performs the following steps:

1. Validate fork flags and allocate the child `ProcessId`.
2. Allocate the child address-space slot / partition.
3. Park sibling threads so the process state is stable while snapshotting.
4. Capture the child-visible state into a `ForkSnapshot`.
5. Export or hand off any resources that cannot be represented purely as bytes.
6. Spawn a new worker host process in "fork restore" mode.
7. Unpark the parent's sibling threads.
8. Return the child PID to the parent.

Unlike the current shared-fork path, the parent does **not** wait for the child
to `execve()` or exit. Once the child host has acknowledged restore success, the
parent resumes independently.

### Phase 2: restore in the child host process

The child host performs the following steps:

1. Start the runner in a new `--fork-restore-fd` mode.
2. Deserialize `ForkSnapshot`.
3. Build a shim instance suitable for restoring an already-existing child
   process, not a fresh init process.
4. Recreate the child `ProcessState`, `Task`, fd table, signal state, and
   filesystem state.
5. Reconstruct the child address space and populate it with the snapshotted
   guest memory image.
6. Restore guest TLS base and the saved execution context.
7. Re-enter guest execution with the child return value set to `0`.

## Snapshot Contents

The snapshot should be explicit and self-describing. A suitable high-level shape
is:

```text
ForkSnapshot {
  process_identity,
  process_wide_state,
  thread_state,
  signal_state,
  filesystem_state,
  fd_table_state,
  memory_image,
  external_resource_refs,
}
```

### Process identity

Capture:

- guest `pid`, `ppid`, `tid`
- internal `ProcessId`
- parent `ProcessId`
- process group id
- session id
- exit signal
- command name (`comm`)
- credentials (`uid`, `euid`, `gid`, `egid`)

This is required because a true restored child must be the same logical process
from the perspective of parent/child relationships, process groups, sessions,
and future `wait4()` / `kill()` routing.

### Process-wide state

Capture:

- resource limits
- transparent huge-page disable state
- alarm timer state

This is important because the current `ThreadState::new_process()` /
`Process::new()` path initializes fresh defaults. That is acceptable in the
current shared-fork implementation because it is effectively `vfork()` plus
`exec`, but it would be wrong for a true fork child.

### Thread state

The child begins as a single-threaded process, so restore should recreate only
the calling thread.

Capture:

- guest execution context (registers)
- guest TLS base / FS base
- `set_child_tid` state required by the fork flags
- `clear_child_tid` state required by the fork flags
- robust futex list pointer

Do **not** inherit host-thread wait handles, host-side pending interrupts, or
other host-specific thread bookkeeping.

`rseq` registration should be cleared in the child. The robust futex list
pointer should be inherited, matching Linux fork semantics. The current code
stores both in `ThreadState`, but the present fork path does not provide a full
cross-host inheritance model for them.

### Signal state

Capture:

- blocked mask
- installed handlers
- alternate signal stack

Do not inherit:

- pending thread-directed signals
- pending process-directed signals
- deferred restore-mask state
- last-exception / fault metadata from the parent

This matches the existing fork-friendly shape of `SignalState::clone_for_fork()`
and keeps restore deterministic.

### Filesystem state

Capture:

- current working directory
- `/proc/self/exe` path
- umask

The current `do_fork()` path shares `FsState` between parent and child, which
is acceptable only for the current shared-fork approximation and is wrong for a
true fork. A true fork must deep-copy `FsState` at snapshot time so current
directory, umask, and executable path become independent immediately.

### FD table state

Capture:

- raw fd numbers
- fd flags such as `FD_CLOEXEC`
- status flags such as `O_NONBLOCK`
- alias relationships between duplicated fds
- open-file-description state such as file position
- descriptor class for each unique descriptor object
- sidecar fd state that is not stored in raw descriptors alone, such as
  inotify instance state and stdio object ids
- any coordination state needed to preserve shared open-file-description
  semantics across hosts

The snapshot must preserve POSIX semantics:

- the child gets a new fd table
- duplicate fds in the child still alias the same underlying open-file
  description
- offsets are shared where Linux would share them

One subtlety is that same-host fork can preserve open-file-description semantics
with in-memory coordination such as shared file-position state and locking. A
cross-host fork cannot assume those `Arc`-backed coordination objects remain
shared, so the implementation must either move them behind a portable shared
service or reject the affected descriptor classes in the first version.

### Memory image

The first implementation should snapshot the **actual child-visible memory
image**, not a deferred CoW recipe.

Capture:

- mapping ranges
- mapping permissions / flags
- all resident page bytes needed to recreate the child address space exactly
- page-manager metadata needed to preserve current shim behavior, including
  syscall-patching state, tracked shared-file-mapping state, `/proc/self/maps`
  path annotations, and main-binary BSS annotations

This is intentionally conservative. The current vfork CoW implementation is
useful prior art for freezing the process and enumerating mappings, but a true
cross-host restore should not depend on parent-owned CoW layers after the child
starts running elsewhere.

Optimizations such as "reopen file-backed clean mappings instead of copying
bytes" can be added later.

### Shared mappings are a first-version gating condition

A byte-for-byte memory snapshot is not enough when the process has live shared
mappings. File-backed `MAP_SHARED` mappings, anonymous shared mappings, and any
shared-memory regions that participate in futex sharing must remain truly
shared between parent and child after fork.

If the implementation cannot preserve that semantics across host processes, the
first version should reject `fork()` whenever such mappings are present rather
than silently turning shared state into private copies.

## Restoring in Another Host Process

The child host should not use the existing "load a fresh init process" path.
Instead, it needs a dedicated restore bootstrap API, for example:

```rust
LinuxShim::restore_process(snapshot, imported_resources)
```

That restore path should:

- create a real `ProcessState` for the child partition
- create a `Task` with the snapshotted logical identity and credentials
- recreate a single-thread `Process` whose thread map contains only the child
- rebuild `FsState`, `FilesState`, and `SignalState`
- rebuild page-manager metadata, not just raw pages
- copy the snapshotted pages into the child address-space partition
- restore guest TLS base
- re-enter guest at the saved instruction pointer

The worker host must acknowledge restore success back to the parent before the
parent resumes. If restore fails, the parent should receive a synchronous fork
failure rather than creating a half-live zombie child.

## Descriptor and Subsystem Export/Import

This is the hardest part of the design.

Within one host process, fork inheritance is easy because fd objects are Rust
heap objects stored in the local descriptor table. Across host processes, those
objects are not portable. The snapshot therefore needs an explicit
export/import model per descriptor class.

The raw descriptor classes currently visible through `run_on_raw_fd()` are:

- filesystem fds
- network fds
- pipe fds
- eventfd / timerfd / pidfd
- epoll
- Unix domain sockets

In addition, `FilesState` carries sidecar fd state that must also be portable,
notably inotify instance state and stdio object-id tracking.

### Recommended import strategy by class

**Filesystem fds**

Path-backed regular files can be recreated by restoring the mutable guest
filesystem state, reopening the same inode or path, and then restoring file
position and flags.

Anonymous or special filesystem descriptors, such as `memfd` and host
stdio/PTY-backed descriptors, need explicit export/import support or must cause
fork rejection in the first version.

**epoll**

Do not serialize live observer pointers or entry handles. Recreate epoll
instances by replaying interest registrations after all watched descriptors have
been restored.

**eventfd / timerfd**

Can be recreated from explicit serialized state, but need new export/import
format.

**pidfd**

Requires cross-host process-lifetime tracking, not just object recreation.

**inotify and stdio side state**

These are not reconstructible from the raw descriptor table alone. They need
explicit serialization and restore logic.

**pipes, Unix sockets, and network sockets**

These are host-local today and need explicit export/import support or
brokerization. Without that, a fully general cross-host fork is impossible.

For Unix sockets in particular, queued data, queued `SCM_RIGHTS`, and
peer-credential state are part of the portable state surface.

This is the biggest conclusion from the code analysis:

**the hardest problem is not copying guest memory; it is making host-local fd
subsystems portable across host processes.**

## Sandbox-Global State That Cannot Be Implicit

Several pieces of state currently live in `GlobalState` and are local to one
host process:

- futex manager
- pipes subsystem
- network subsystem
- Unix socket address table
- cross-process signal queue
- process-thread interrupt handles
- foreground tty process-group state
- control plane instance

A restored child host cannot simply "share" those Rust objects. The design must
therefore do one of the following for each subsystem:

- rebuild from serialized state
- reconnect to a broker-backed shared service
- or reject fork while that subsystem has live non-portable state

## Control Plane and Process Registry Changes

The current multihost control plane already has pieces of running-process
ownership and child-exit routing, but it is still not sufficient for true
remote fork.

Minimum required changes:

- allow a restored child to keep its original logical `ProcessId`
- register the restored child with its original logical identity without going
  through the fresh-init bootstrap path
- keep authoritative parent/child, process-group, and session state consistent
  across hosts
- route child exit back to the authoritative owner so the parent can `wait4()`
- support `kill`, `tgkill`, and pidfd behavior across host boundaries

The recommended first model is:

- keep one authoritative process tree
- let the control plane track which host currently owns execution
- route lifecycle events and control operations through the control plane

That aligns with the existing host-ownership and handoff structures, but
extends them from "remote exec" to "remote running process."

## Validation Plan

1. Add focused unit tests for snapshot serialization and restore of:
   - process-wide state
   - process identity and credentials
   - signal state
   - fd alias groups
   - memory image reconstruction

2. Add Linux userland integration tests covering:
   - simple `fork()` parent/child return values
   - independent parent/child execution after fork
   - `CHILD_SETTID` / `CHILD_CLEARTID`
   - robust futex list inheritance and `rseq` reset
   - `wait4()` on a remote-owned child
   - signal delivery to a remote-owned child
   - fd sharing semantics across fork

3. Add negative tests that reject fork when unsupported state is present, until
   those cases have explicit portability support:
   - shared mappings whose semantics cannot yet be preserved across hosts
   - `memfd` or other anonymous special filesystem descriptors
   - inotify state
   - Unix sockets with queued data or queued `SCM_RIGHTS`

4. Verify that existing `vfork()` behavior remains unchanged.

## Risks and Open Questions

1. **Descriptor portability is the main risk.**

   Path-backed filesystem fds are manageable. `memfd`, inotify, pipes, Unix
   sockets with queued state, smoltcp-backed sockets, and pidfds require
   additional architecture.

2. **Shared mappings are a semantic cliff.**

   A pure byte snapshot is wrong if it turns live shared mappings into private
   copies. The first implementation either needs a real shared-backing design or
   must reject such cases.

3. **True fork needs a new restore bootstrap API.**

   The current worker host path restores guest-visible identity but still boots
   a fresh local process. That is not sufficient for a remote-owned fork child.

4. **`madvise(DONTFORK)` / `WIPEONFORK` are currently no-ops.**

   A true fork implementation must define and enforce those policies.

5. **Per-thread registration semantics need deliberate handling.**

   `robust_list` should be inherited and `rseq` should be cleared. Any other
   thread-local Linux ABI state should be implemented deliberately, not
   inherited accidentally.

## Recommendation

Proceed with a correctness-first implementation that:

- introduces an explicit `ForkSnapshot`
- adds a new worker-host restore mode
- adds a non-init process restore bootstrap path
- restores full child memory state and page-manager metadata in the new host
  process
- supports only descriptor classes with explicit export/import logic
- rejects shared mappings and unsupported descriptor classes until the remaining
  subsystems are made portable

That keeps the first version honest: it provides a real two-step cross-host
fork design, without pretending that existing same-host descriptor sharing and
exec-worker infrastructure are already enough to make arbitrary live processes
portable.
