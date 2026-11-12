# Guest procfs design

Status: procfs backend, mounted by the userland broker's `--linux-procfs` and used by every
Linux runner integration test, with authenticated caller context, automatic broker
process lifetimes, loader-published read-only executable object links, path-based
working-directory links, generated `limits` and `status` files, and descriptor links that
the caller's shim resolves. This is not a claim of general Linux compatibility.

## Goals and boundaries

Provide a coherent guest `/proc` filesystem rather than adding pathname checks to
individual syscalls. Start with process introspection needed by development tools,
but design lookup and open handles to support process and thread directories later.

Linux names, formatting, authorization rules, and errno translation belong to the
Linux shim. Shared filesystem machinery and broker requests must remain guest-neutral.
Never use host `/proc` as the guest filesystem: host PIDs, file descriptors, mappings,
and credentials do not describe the guest.

This design does not introduce a new security boundary between a userland guest and
its runner. It must still preserve broker object ownership, configured filesystem
exposure, and guest-visible access semantics. Other platforms must not require host
procfs to implement guest procfs.

Initial non-goals are Linux namespace virtualization, arbitrary writable proc controls,
`/proc/<pid>/mem`, and exhaustive kernel statistics. Unsupported functionality must be
explicit, not populated with plausible host values or success-shaped placeholders.

## Current implementation and constraints

* [File syscall handling](src/syscalls/file.rs) retains the legacy
  `readlink("/proc/self/exe")` behavior only when executable publication is explicitly
  unsupported. With procfs enabled, readlink/stat/open use real nodes, and the broker
  hands `fd/N` back to the shim (see [Descriptor links](#descriptor-links)); the legacy
  `/proc/self/fd/N` prefix check applies only to processes whose broker does not serve
  procfs.
* [Process state](src/syscalls/process.rs) records where its `/proc` state comes from
  (`ProcSource`): the broker, or, for that compatibility fallback, the shim with the
  program's pathname. Published executable identity and fork inheritance are
  broker-owned and survive rename/unlink independently of the display path.
* The shim's file open description wraps a broker-backed file. The broker owns its
  offset, and for directories also a name-sorted listing snapshot that the position
  indexes, so dup/fork share both (see [Implementation decisions](#implementation-decisions)).
* [Client file operations](../litebox/src/fs/file.rs) send normalized paths to the
  broker. Lexical normalization already loses some Linux symlink semantics, including
  `link/..` and trailing-slash requirements.
* The broker [resolver](../litebox_broker_core/src/fs/resolver.rs) walks ordinary
  symlinks and retained read-only regular-file targets without reopening display paths. The
  [backend interface](../litebox_broker_core/src/fs/backend.rs) now receives explicit
  accessing-process context for broker-originated path walks. Accessing-thread
  identity is not yet available.
* Native fork, copy-based fork, vfork-to-exec, and descriptor inheritance span runners.
  An `Arc` to shim state is not a transferable open file description.

Consequently, neither an ordinary context-free broker `Backend` implementation nor a shim
`starts_with("/proc/")` check is sufficient.

## Ownership and placement

Split implementation into three layers:

1. **Guest-neutral namespace and handle machinery:** component-wise walking,
   mount transitions, ordinary and object-backed links, open descriptions, and
   transferable references. Reuse existing resolver/backend abstractions where they
   fit; extend them only for demonstrated gaps.
2. **Linux ProcFs provider:** nodes, process/thread interpretation, generated content,
   access checks, and conversion of failures to Linux errors.
3. **State sources:** shim-published process state; broker-owned generic object
   identity and lifecycle; eventually bounded queries to other Linux runners.

The Linux-specific provider runs broker-side and is registered during filesystem
composition by startup code that knows which guest shim is used. Today the broker
executable's `create_file_service` constructs that namespace; the runner does not
construct it directly. The provider's Linux implementation stays outside generic
broker core. The broker remains namespace and object authority.

There are two distinct registrations: one provider per composed namespace, and a
per-process state source with fork/exec/exit lifecycle. Prefer narrow publication
of coherent state to forwarding filesystem operations synchronously into a runner.
Linux text formatting, Linux PID rules, and requests named "read proc maps" do not
belong in generic broker interfaces. The state-publication transport uses a generic file-capability request; no general
callback/RPC framework is needed for this first prototype.

### Implemented foundation

The generic backend `LookupContext` contains acting filesystem credentials plus
an optional `FileCaller` (non-reusable broker process key and visible process ID).
Broker file services derive the caller from their existing process association;
no process identity is added to guest-controlled file-request payloads.

All path-based service operations use a request-local resolver view over the same
backend. `root_with_context`, `resolve_with_context`, and
`read_link_at_with_context` pass this context through `Composer` mount transitions,
including nested composers and symlink expansion. Ordinary backends retain their
existing implementations. No ambient current-process state or provider registry
is introduced. Open descriptions still refer to the object selected during open,
not to a caller-dependent link that gets re-evaluated at read time.

[Provider integration tests](../litebox_broker_core/src/fs/tests/caller.rs) exercise
two broker processes, concurrent lookups, acting credentials, path mutations,
links entering a mounted provider and returning to ordinary files, and retained
open-target identity. A test-only provider demonstrates registration using the
existing `Composer` builder; Linux-specific coverage is in the provider tests below.

Caller-context propagation alone does not implement object-backed magic links,
thread identity, cross-runner transfer, or client path normalization fixes.
Context-aware providers must be mounted through `Composer`,
not stacked inside `Overlay`, whose layer and copy-up operations are not yet
caller-aware. `ReadOnly` passes the context through. Direct legacy resolver/backend calls have no associated process;
caller-dependent providers must explicitly reject that case. Existing shim proc
special cases remain until equivalent filesystem nodes have acceptance coverage.

### Initial Linux provider and registration API

The optional `litebox_shim_linux/procfs` feature exposes the broker-side
[`ProcFs` backend](src/procfs.rs). Like the device backend's injected providers, a
filesystem view receives a separate `ProcState` controller: construct it with
`ProcState::new(allocator, limit)`, then mount `ProcFs::new(state.clone())` through
`Composer`. Controller clones share the bounded registry and implement `FilePublisher`;
filesystem clones preserve root/link inode identities. The controller does not retain
the view, and namespace metadata stays in the filesystem view. Enabling the feature by itself
does not mount `/proc` or change the existing shim special cases.

`ProcState::register_process` takes an authenticated `BrokerProcess` and initial Linux
filesystem owner. It returns a non-cloneable `ProcessRegistration` guard. The owner
is updated from the effective UID/GID in trusted credential publication; its initial
value is used before that publication. The live
registration count is bounded by the namespace's configured limit; duplicate keys
or PIDs and exhausted capacity return explicit errors, never replacement or eviction.
PIDs are the broker's PID-namespace-relative IDs. Every process sharing one file
service must therefore share one PID namespace, as the userland brokers do today;
a file service shared across PID namespaces would see colliding PIDs and needs
`FileCaller` to carry the namespace before procfs can scope its listings to it.
Drop the guard on exit or runner failure, but retain it across exec. Manual
registration remains available for other startup integrations. For automatic
registration, configure `with_process_lifecycle(owner)` before mounting the provider.
The generic backend `process_created(process, parent)` hook receives the new
`BrokerProcess` and its creator's `FileCaller`, and returns an opaque
resource retained by the broker process across exec and released on exit, startup
failure, or final cleanup. Composition rolls back earlier resources if another
provider fails. Callbacks run outside process-state locks; resource destructors must
not call back into broker process state.

The userland broker mounts this provider at `/proc` when invoked with `--linux-procfs`.
Its `linux_procfs` feature, which provides the flag, is on by default; requesting the
flag from a broker built without it reports an explicit startup error. The broker
cannot tell which guest a runner hosts, so the flag stays a runtime choice; the Linux
runner's integration tests always pass it. The initial owner is UID/GID 1000, matching
the default Linux runner, until the process's runner publishes its starting credentials,
whose effective UID/GID then owns its directory; later credential changes are not yet
published. Children inherit the creator's owner and all of its published state.
Capacity follows the broker's maximum process count.

Named entries are defined once in a directory-scoped `ProcEntry` table, following
the device backend's entry-table pattern. Lookup and link following select entries
from that table; listing uses the same visibility checks and link metadata as lookup.
Numeric process-directory names remain dynamic. Resolution and metadata do not open
the target or create per-open resources.

The current nodes are deliberately small:

* The root lists `self` and the opener's own registered numeric process directory,
  plus the resolver's normal dot entries. Other processes are not exposed.
* `self` is an ordinary relative symlink to the accessing caller's registered PID.
  Readlink, lstat, following stat/open, directory enumeration, and
  `O_PATH | O_NOFOLLOW` use actual backend nodes, not pathname special cases.
  Link metadata belongs to the namespace rather than a process incarnation, and
  reports a zero size, matching native Linux's dynamic `self` link.
* A process directory is read-only. It contains `exe`, `cwd`, `limits`, and `status`
  only once the shim has published their state (see the sections below), and `fd` (see
  [Descriptor links](#descriptor-links)). Unsupported names such as `thread-self` are
  not fabricated.
* Procfs enforces directory permissions and entry-mutation errors in the Linux backend,
  rather than advertising an ordinary read-only mount to the resolver. Creating a missing
  entry fails with `ENOENT`, creating an existing entry with `EEXIST`, unlinking `self`
  with `EACCES` (Linux reports `EPERM` to root, which backends cannot yet tell apart), and
  changing its mode with `EPERM`. Rename and directory removal remain
  unsupported (`EROFS`). Opening a directory for writing fails with `EISDIR`, as on Linux.

An open process directory pins its process incarnation and inode identity. Removing
its registration makes subsequent lookup and directory enumeration fail with ENOENT;
already-held metadata retains the old identity. PID reuse creates a new inode and
cannot retarget old handles. Directory path failures are carried through broker
file errors, the client file API, and Linux errno translation rather than becoming
an empty listing or generic I/O error.

[Linux provider tests](src/procfs/tests.rs) exercise this subset through broker file
services, plus deterministic registration-capacity, exit, and PID-reuse cases and
a native Linux comparison of link/target type, size, and permissions. This is the
initial behavior contract, not yet differential coverage for all Linux proc
directory lifetime and snapshot semantics.

### Retained executable objects

The trusted publication API validates process ownership and read rights of the
source broker reference. It retains the regular-file object, not its pathname or
open-description offset. Generic `FileRequest::Publish { handle, key }` carries no
guest-selected process identity; the service derives that from the association.
Startup attaches the state controller as the resolver's `FilePublisher`, independently
of mounting the filesystem view. Only the shim defines its executable key. Unknown keys and absent
consumers return `NotSupported` without changing state; other failures propagate.
The broker protocol version is bumped so stale peers fail the handshake rather
than encountering an unknown operation mid-load.

`LinkTarget::File` carries this capability through the same
authoritative walk and symlink budget used for ordinary links. Following stat and
open continue to select the original object after rename, unlink, pathname
replacement, and source-descriptor close. Each reopen starts at offset zero and
rechecks current read permissions; writes, truncation, and metadata mutation through
these targets are explicitly rejected in this first slice. A writable open fails with the
generic `InUse` error, which the shim reports as `ETXTBSY`, as Linux does for a running
executable.

`O_PATH | O_NOFOLLOW` retains the proc link inode, whereas following `O_PATH` retains
the executable object. A regular-file target cannot accept a suffix or a trailing
slash. The physical-path-string resolver rejects object targets as non-directories
(so `chdir` fails with `ENOTDIR`, as on Linux) rather than turning their display names
back into authority. Generic retained-path identity tracks successful
resolver-managed renames and unlinks; readlink returns that current path, with the Linux
backend appending ` (deleted)` after unlink. Out-of-band host filesystem mutations are
not tracked.

The target's backend reference is weak to avoid a composed namespace/provider/image
cycle. Opening upgrades it for that descriptor's lifetime. Tests cover capability
attenuation, independent offsets, caller ownership, shared traversal limits, fork
inheritance, image replacement, and reclamation without reference cycles.

After successfully loading the main ELF and preparing its stack, the loader publishes
the still-open main file, never the dynamic interpreter. Publication completes before
guest execution begins and before the loader closes its temporary descriptor. A
publication failure aborts loading; only the explicit `NotSupported` response enables
the old readlink-only compatibility path, with a debug diagnostic. Successful
publication clears that fallback so readlink reaches the real procfs node. Fork
copies the fallback when needed; otherwise the child uses its broker-inherited image.

Loading then publishes the command name. The broker keeps the rest of a process's
published state across exec, so only a process starting in a new runner (the first
program, or a `vfork` child's exec) publishes its working directory, limits, umask, and
credentials too. The published working directory and umask are the thread-group
leader's, so a thread without the leader's filesystem state (created without
`CLONE_FS`) that execs makes its own state the leader's and republishes both, and a
child forked from such a thread, or from any thread but the leader, republishes them and
its name once it starts. That publication, and the name's, is best-effort: by then the old image is gone, so a failure, such as a working directory
the new process cannot reach, is logged and leaves procfs stale rather than ending the
process.

The [guest fixture](../litebox_runner_linux_userland/tests/procfs.c) verifies static
and dynamic main-image identity, mounted `self` lookup, enumeration, fork, exec,
readlink/lstat/stat/open, read-only rejection, independent reopens after rename and
unlink, failed-exec preservation, exec in a working directory the child cannot see, and
re-exec through the retained object using
`cargo nextest run -p litebox_runner_linux_userland --test run -E
'test(procfs_tracks_fork_and_exec_process_identity)'`, after `cargo build`. Writable files, devices, and directory magic links remain subsequent
work; no pathname-reopen fallback is used for `exe`.

### Working-directory links

Until the walk can start from directory objects, the shim's working directory is an
absolute path, so `cwd` is a path-based link rather than a magic link. Publication
accepts a directory, which may be open path-only, and records the path the broker
resolved when it was opened (`PublishedObject::Directory`); the consumer's key decides
which kind it accepts, rejecting the other with `IsDirectory` or `NotDirectory`.
Following `cwd` re-walks that path with the accessing caller's permissions, so it goes
stale if the directory is renamed, exactly as the shim's own working directory does.

The shim publishes before `chdir` or `fchdir` takes effect, holding its filesystem
context so concurrent changes publish in order, and fails the call if publication fails
for any reason other than `NotSupported`. It publishes only while the broker accepted
its executable (that is, while procfs is served), and only from the thread-group
leader's filesystem state: threads created without `CLONE_FS` and `vfork` children have
their own copies, and a `vfork` child acts through its parent's broker association.
A process starting in a new runner publishes its inherited working directory; children
inherit their parent's through the broker's process-creation hook, and exec keeps it,
except that a fork or exec from a thread with its own filesystem state republishes it
(see [Retained executable objects](#retained-executable-objects)).
`chdir` through a descriptor link changes to the descriptor's directory, as `fchdir`
does. The guest fixture covers `chdir`, `fchdir`, `chdir` through `/dev/fd`, a `vfork`
child's `chdir`, fork inheritance, `exec`, and paths through the link.

### Generated files

`limits` is the first generated file. Its source is the shim, which formats the table
exactly as Linux does from the values `getrlimit` reports and publishes the bytes with
the generic `FileRequest::PublishData { data, key }`, when a process starts in a new
runner and after each `setrlimit` or `prlimit64` that changes a limit. A per-process lock serializes formatting
and publishing so the last text published reflects every change; a change that took
effect is still reported as failed if publishing it fails. As with `cwd`, only processes
whose broker accepted their executable publish, and `vfork` children never do. Children
inherit their parent's text through the process-creation hook. The consumer bounds the
text to 4 KiB.

Each open description reads one snapshot of the published text, taken by its first read
and retaken whenever a read does not continue at the previous read's ending offset.
Contiguous reads, including repeated EOF reads, never splice versions; rewinding and
noncontiguous `pread` refresh the text, as on Linux. Cloned handles share snapshot and
expected-offset state, while independent opens and reopens start fresh. Like Linux,
the file is mode 0444 with size zero, and opening it for
writing fails with `EACCES` rather than `EROFS`. As for a Linux seq_file, the text has no
size to seek from or to bound a seek: the generic `SeekBehavior::UnsizedPosition` accepts
any position from the start or the current one and refuses `SEEK_END` with `EINVAL`. Unit tests
compare the formatted layout with the host's own `/proc/self/limits`, and the guest
fixture compares every row with `getrlimit` before and after `setrlimit`, in a forked
child, and after `exec`; its check also passes natively.

`status` mixes sources, so it is generated at read time from fields of each. The shim
publishes `Name` (escaped as Linux escapes it), `Umask`, and its credentials (real and
effective UID and GID, as a fixed 16-byte record from which procfs formats the `Uid`,
`Gid`, and `Groups` lines and takes the owner of the process's files) under separate keys,
each by whichever task changes it: the thread-group
leader on `prctl(PR_SET_NAME)`, any task sharing the leader's filesystem state on
`umask`, and, for all three, a process starting in a new runner, with exec republishing
`Name` (and fork and exec republishing as for `cwd`). The consumer validates each field's shape and
size and shows `status` only once all three exist. The process-creation hook now receives
the `BrokerProcess`, which procfs holds weakly to read `PPid` (`process_info`) and
`Threads` (`thread_count`) at generation time, so reparenting and thread changes need no
publication; `Pid` and `Tgid` come from the authenticated caller, and `TracerPid` is 0
because LiteBox does not support tracing. `State` is omitted rather than reported as
running: a descriptor passed to another process could read it while this one sleeps.
`Ngid`, `FDSize`, namespace IDs, memory, signal, capability, and CPU fields are omitted
too. The guest fixture compares every emitted field with the corresponding system call
across renames, a worker thread's rename, `umask`, a `vfork` child's `umask`, thread
creation and exit, fork, and `exec`; its checks also pass natively.

### Descriptor links

The broker does not know a process's descriptors, so `/proc/<pid>/fd` hands them back to
the caller. Each process directory has an `fd` directory, mode 0500, owned by the process's
published effective UID/GID (or its configured initial owner before publication).
As Linux's `proc_fd_permission` does, the backend lets a process use its own `fd`
directory whatever its mode, and otherwise permits root and enforces owner-only
read/search access; `O_PATH` can retain the directory without read permission. A process
sees only its own descriptors either way. Looking
up a well-formed descriptor number in it as a final component fails with the generic
`PathError::CallerObject(n)` (`FileError::CallerObject(n)` on the wire) for every
operation, and listing it fails with `CallerObjects`. The resolver turns a hand-back that
more components follow, including through a symlink, into `ENOTDIR`, so a remainder is
never dropped; walking into a directory descriptor is not supported yet. Malformed names
(signs, leading zeros, values beyond `i32`) do not exist.

The shim resolves a hand-back against its own descriptor table, where a number that is
not open names nothing (`ENOENT`):

* `readlink` names the file's path, or the kind of other descriptors (`pipe:[0]`, ...).
* `lstat` describes the link: owned by the process, size 64, with the descriptor's read
  and write access in its owner bits, as Linux reports it.
* Following status queries (`stat`, and `statx` or `newfstatat` without
  `AT_SYMLINK_NOFOLLOW`) and `access` reach the descriptor's object.
* `open` opens the object anew rather than duplicating the descriptor, so a file gets an
  offset and status flags of its own. Generic `FileRequest::Reopen` asks the resolver to
  authorize the requested access against current object metadata, then calls
  `Backend::reopen_file` on the retained handle; the new reference needs and inherits the
  source reference's broker rights, and its response (`FileResponse::Reopen`) has the shape
  of an open's. It never resolves the old pathname:
  rename, unlink, replacement, and even replacing the old name with a link back to its
  own descriptor cannot redirect the reopen. Requested access is not limited by the
  source descriptor's access mode, subject to current permissions and backend support; as
  on Linux, a writable reopen on a read-only filesystem fails with `EROFS` before
  permissions are checked.
  Pipes likewise get an independent open description and flags, including `O_NONBLOCK`;
  either direction or `O_RDWR` can be requested regardless of the source end. Sockets
  fail with `ENXIO`, as on Linux. So do anonymous inodes such as eventfds for root, and,
  as on Linux, with `EACCES` for anyone else, whom their root-owned mode refuses first.
  `O_NOFOLLOW` fails with `ELOOP`; `O_PATH | O_NOFOLLOW` is unsupported. `O_DIRECTORY`
  on a descriptor that is not a file fails with `ENOTDIR`.
* `chdir` changes to a directory descriptor's directory, as `fchdir` does.
* `utimensat` on a descriptor that is not a file succeeds without effect, and `execve`
  of one fails with `EACCES`, as Linux's `may_open` refuses executing a FIFO or socket.
* Creating, removing, or renaming a name below a descriptor link fails with `ENOTDIR`.
* `getdents64` lists `.`, `..`, and the open descriptors, using each descriptor's number
  plus two as its position, so opening and closing descriptors never moves another across
  the position.
* Operations the shim does not resolve, such as `chmod` through a descriptor link, fail
  with `EOPNOTSUPP` rather than acting on the wrong object.

Object reopening is implemented by in-memory and tar filesystems, procfs generated files,
devices, and `LocalFs`; as on Linux, only an `O_PATH` reopen may name a symbolic link
(others fail with `ELOOP`), and a reopened terminal device starts a new open of it, so a
`ptmx` manager reopens as a new pair and `/dev/tty` binds the reopener's controlling
terminal; composer, read-only, and overlay backends delegate to the retained
object's backend or layer. Generated files receive fresh snapshot state. Read-only backends
still reject writable opens, and an overlay reopen depends on the retained layer's support
rather than reopening a name to perform copy-up. Backends without an implementation fail
explicitly with `ENXIO`; there is no pathname fallback. On Linux, `LocalFs` reopens its
retained host descriptor, including after rename or unlink. A missing retained descriptor
fails with `ENXIO`; on non-Linux hosts, expanding access beyond that host descriptor's
original rights is also unsupported (`ENXIO`).

When it mounts procfs, the userland broker also gives its `/dev` the links Linux
conventionally has into it, which the Linux shim lists (`procfs::dev_links`): just `fd`,
to `/proc/self/fd`. The devices backend serves configured links generically and refuses
names that would shadow a device; without procfs, `/dev` has none. `stdin`, `stdout`,
and `stderr` remain the broker's own devices rather than links to descriptors 0 to 2. Bash
process substitution, which reads a pipe as `/dev/fd/<n>`, works through this path.

Other processes' descriptors are not visible until cross-process views exist. The guest
fixture covers files, `/dev/fd/N`, `/proc/<pid>/fd/N`, a symlink to a descriptor link, a
file renamed to a link to its own descriptor and successfully reopened for its original
contents, `chdir`, read-only links, independent pipe flags and nonblocking `EAGAIN`,
opposite-direction and read/write pipe reopens, sockets, eventfds, rejected flags, the
listing across calls and seeks, partial `getdents64` buffer faults, and closed and malformed
names; its checks also pass natively.

## Lookup contract: objects, not rewritten path strings

There must be one authoritative walk for a filesystem operation. It receives:

* The accessing guest process/thread and its relevant credentials.
* A root and starting directory object (cwd or dirfd), not just their display paths.
* Unnormalized path components, including trailing-slash requirements.
* Operation flags: following the final link, `O_PATH`, `O_NOFOLLOW`, and supported
  `openat2` resolution restrictions.

Each component can resolve to a directory, ordinary link, object-backed link, or
non-directory object. A mount transition changes providers, not the caller identity.
The same walk must handle broker files that link into procfs and procfs links that
lead back into broker files. Enforce one symlink traversal budget across providers.
Relative targets are interpreted at the containing directory; process `..` only after
the preceding component is resolved.

The current broker path API cannot express this entire contract. Before implementation,
prototype either resumable walking with typed provider transitions or an equivalent
broker-mediated walk. Do not duplicate two independent path resolvers and translate
between them with absolute strings.

All relevant operations must use this machinery: open, metadata and access queries,
readlink, directory traversal, cwd changes, descriptor-relative operations, and mutation
rejection. A symlink path outside `/proc` must not bypass ProcFs policy.

## Nodes, caller context, and identity

Use typed nodes rather than parsing a path on every read. A conceptual node set is:

```text
Root
SelfLink
ThreadSelfLink
ProcessDirectory(process identity)
TaskDirectory(process identity)
ThreadDirectory(process identity, thread identity)
FdDirectory(process identity, descriptor-table view)
FdLink(process identity, fd number)
ExeLink(process identity)
CwdLink(process identity)
GeneratedFile(process identity, file kind)
```

PID/TID numbers are lookup names, not retained identities. Use lifecycle-bound,
generation-aware references so a held node cannot silently attach to a reused number.
The broker's internal process key is useful precedent, not automatically a wire-visible
capability. Define reference ownership and cleanup before exposing new identity tokens.

`self` and `thread-self` are evaluated for the accessing task during traversal.
After lookup/open, a handle remains bound to the selected target. Passing a handle to
another process must not reinterpret it as that recipient's `self`.

For `fd/N`, define separate linearization points for directory lookup, readlink, and
following/opening the link. Retain the selected object when following it; do not check
the number, drop the lock, and later reopen whatever descriptor now occupies the slot.
A retained process identity must never retarget after exit, but retaining metadata must
not keep an exited process alive or prevent it from being reaped.

## Links and open descriptions

Ordinary links such as `self` expose a text target for further walking.
`exe`, `cwd`, and `fd/N` require object-backed ("magic") links:

* `readlink` returns a display name; it is not the authority for opening the target.
* `lstat` describes the link; following `stat` describes the selected target.
* Opening follows the object with the requested flags and fresh access checks.
* `O_PATH | O_NOFOLLOW` can retain the link itself when Linux permits it.
* Unsupported magic-link resolution restrictions fail explicitly.

Reopening `fd/N` is not generally `dup(N)`: regular files may need a new open
description with an independent offset and access mode, sockets may not be reopenable,
and pipes/devices have their own rules. A reference to an open object is not by itself
permission to reopen it with broader access.

An executable reference must survive pathname replacement and unlink. Retain the main
ELF object, not `argv[0]` or the dynamic interpreter; shebang execution identifies the
loaded interpreter. Retaining a file alone does not solve name tracking: the display name
and ` (deleted)` suffix come from resolver-managed rename and unlink tracking, which
out-of-band host namespace changes bypass.

Avoid adding ProcFs as a new unrelated descriptor subsystem. Prefer extending the
existing file open description with a broker-backed or virtual backing, using shared
code for flags, offsets, readiness, and directory entries.

That representation is insufficient by itself: duplicated descriptors must share open
description state, including offsets, across processes. Native fork copies of ordinary
memory do not provide that sharing. Proc handles need an explicit inheritance strategy
for every supported fork/exec path. A handle to the parent's proc node inherited by a
child must continue to refer to the parent, including after child exec.

## Generated files and directory iteration

Do not treat all proc files as ordinary immutable strings. Specify behavior per file:
source, visibility, snapshot point, seek rules, partial reads, and target-exit behavior.

A practical first implementation can use bounded snapshots for selected text files,
with a documented compatibility difference from Linux sequence-file behavior.
Multiple reads at increasing offsets must not splice unrelated snapshots. Define
whether rewind refreshes content and test that rule.

Directory positions index a per-open-description listing snapshot held by the broker,
taken when a read starts at position zero (open or rewind) and sorted by name. Entries
never move across the position while the directory changes; entries added or removed
after the snapshot appear only after a rewind, which POSIX permits. Each `d_off` is the
position following its entry, and `lseek(SEEK_SET)` accepts it; `SEEK_END` fails with
`EINVAL`. An entry can vanish between enumeration and lookup; returning it once does
not promise it still exists. A snapshot is bounded by the directory's size, replaced
on rewind, and released on close.

Sources must be guest state:

| Entry | Source and caveat |
|---|---|
| `limits` | The values `getrlimit` reports: the broker's `CPU` and `NPROC` limits and the shim's others. The shim formats and publishes the text whenever a limit changes. |
| `status` | The broker's process tree and thread count at read time; the shim's name, umask, and credentials as published when they change. `State`, memory, and signal fields are omitted until they have real sources. |
| `maps` | Guest memory manager; omit runner/libOS mappings. Preserve interval ordering. |
| `cmdline`, `environ` | Guest memory ranges and Linux lifetime rules. Saved startup vectors alone do not reflect later mutation. |
| `fd`, `fdinfo` | Guest descriptors and open descriptions, never host descriptor numbers. |
| `cpuinfo`, `meminfo` | Guest-visible capabilities/resources, not unrestricted host passthrough. Defer until accounting is defined. |

Bound output size and allocations. Resource exhaustion, interrupted reads, truncated
snapshots, and unavailable state need explicit outcomes, not fabricated empty success.
Unsupported writes, mapping, truncation, ioctls, and metadata mutation must return
operation-appropriate errors. Do not label every proc node read-only without checking
the Linux operation being emulated.

## Authorization, state publication, and concurrency

Mode bits alone do not implement procfs authorization. Cross-process reads and magic
links need per-entry Linux access rules, potentially including effective versus real
credentials and dumpability. `environ` is sensitive and should not precede these rules.
The current credential model must be audited for gaps before claiming cross-process
compatibility. Handle transfer must not accidentally bypass required checks.

For self introspection, read the current shim's state directly. Cross-process views
need explicit publication/query ownership because state lives in separate runners:

* Identify the target independently of reusable PID names.
* Authenticate the provider's registration to the corresponding broker process.
* Bound requests, replies, outstanding work, and retained handles.
* Make cancellation, provider death, process exit, exec replacement, and stalled
  providers explicit; distinguish these from an empty file.
* Do not require a guest thread to service introspection requests: it may be stopped,
  blocked, or inspecting itself.
* Prevent provider queries from recursively depending on the same filesystem request.

Copy needed state under short-lived locks, then format or perform broker operations
after releasing those locks. Never hold process, descriptor, or memory-manager locks
across remote calls. Specify a per-operation consistency point; do not promise an
atomic snapshot of all process fields.

## Challenge review and resulting decisions

| Challenge to the initial proposal | Decision |
|---|---|
| "Mount a shim provider at `/proc`." How does a broker symlink reach it? | A unified, component-wise walk is a prerequisite; prefix dispatch is rejected. |
| "Implement it as another broker backend." Where does caller context come from? | Extend explicit lookup context or provide equivalent provider-aware traversal; no ambient global current-task variable. |
| "Return the file path for `exe` or `fd/N`." What if the name changes? | Separate link display from object authority. Retain object identity and track name compatibility separately. |
| "Share an `Arc` to process state." What happens after fork and exec? | Require transferable references and shared open-description state, not runner-local pointers. |
| "Snapshot everything at open." Is that Linux behavior? | Snapshot policy is per entry and explicitly documented; native comparisons determine compatibility. |
| "Query the other runner." What if it is stopped or dead? | No dependence on guest execution; lifecycle, cancellation, bounded service, and dead-provider behavior are design gates. |
| "Use saved credentials and mode bits." Is access actually authorized? | Cross-process exposure waits for per-entry access rules and a credential/dumpability audit. |
| "Treat missing information as empty." Can callers distinguish failure? | Reject fabricated success and define errors for unavailable or unsupported state. |

These challenges narrow the first delivery. General procfs architecture does not imply
that all Linux proc entries can ship in one change.

## Staged implementation and acceptance gates

1. **Namespace prototype:** prove a broker symlink into `/proc`, a proc magic-link
   transition back to a broker object, `dirfd` traversal, `link/..`, trailing slashes,
   and a shared traversal budget. Resolve the ownership of walking state before
   selecting a transport API.
2. **Self nodes:** root, `self`, `thread-self`, process/task directories, `exe`, `cwd`,
   and `fd`, with open/readlink/stat/lstat/getdents behavior. Preserve existing
   special-case behavior until equivalent nodes are tested, then remove the checks.
   If handle inheritance is not yet possible, explicitly reject unsupported transfers
   rather than silently rebinding them.
3. **Selected generated files:** add `status`, `limits`, and `maps` after defining each
   field, resource bounds, offsets, and snapshot behavior. Add `cmdline`/`environ`
   only with their memory-lifetime and permission semantics.
4. **Cross-process views:** implement lifecycle-bound targeting, authorization, remote
   state access, and cross-runner handle inheritance. Advertise the supported subset.
5. **Additional controls/statistics:** only when the corresponding underlying
   operations and guest accounting exist.

Use native Linux differential tests for observable semantics, plus deterministic
tests for implementation races. Required cases include:

* Readlink buffer boundaries; malformed paths; link versus target metadata.
* Independent reopen offsets versus shared dup/fork offsets.
* `O_PATH`, `O_NOFOLLOW`, access modes, and unsupported `openat2` restrictions.
* Fork, vfork/exec, native/copy-based startup, and transferred proc handles.
* Descriptor close/reuse and executable rename/unlink/replacement during operations.
* Process/thread exit and number reuse, including a held directory handle.
* Directory mutation between small `getdents64` reads and after rewind.
* Partial text reads, seek/rewind, allocation limits, and oversized output.
* Symlinks crossing mounts in both directions, including directory targets.
* Cross-process access denial, provider death, stalled queries, and cancellation.
* No host PID, fd, memory layout, environment, or unrelated filesystem leakage.

## Implementation decisions

These answer the questions left open by the staged plan. Items marked *native check*
still need a differential run against Linux before they are relied on.

1. **Open-description state lives in the broker.** The broker already owns file
   offsets and status flags, and fork duplicates broker references into the child, so
   procfs handles survive runner exit and share offsets across dup/fork without new
   transport. Directory positions follow the same rule: the broker keeps a listing
   snapshot per open description (see
   [Generated files and directory iteration](#generated-files-and-directory-iteration)),
   which also lets a positioned directory descriptor transfer to a fresh fork runner.
   Retained records are reclaimed by the existing scheme: handles keep the per-process
   record, the registration guard marks it dead on exit, and `FileTarget` holds its
   backend weakly.
2. **The authoritative walk carries objects, not absolute strings** (deferred: this is a
   general resolver change across every shim, so procfs uses absolute paths meanwhile). The resolver
   will track "current directory object + remaining components" and gain a directory
   link target alongside `LinkTarget::File`, reusing `walking_dir_at` to resume from a
   held handle. The same change provides `dirfd`-relative walks, correct `link/..`, and
   a cwd held as a directory handle instead of a string. `..` from a directory reached
   through a magic link asks the backend for its parent and fails explicitly when a
   backend cannot answer. Only `O_NOFOLLOW` and `O_PATH` are supported resolution
   restrictions; `openat2` restrictions are rejected until `openat2` exists.
3. **`fd/N` hands the walk back to the caller** (implemented; see
   [Descriptor links](#descriptor-links)). Descriptor numbers are Linux state
   that the broker does not track. For the caller's own `fd/N`, procfs returns a
   continuation naming that descriptor, and the caller's shim resumes the walk from
   its own handle. This costs nothing for processes that never use `/proc` and is not
   string rewriting: it carries a descriptor number and continues from a held object.
   Other processes' `fd/` fails explicitly until cross-process views, which will need
   shim-published descriptor state. Reopening follows Linux: a fresh open of the same
   object with a fresh permission check and an independent offset, not bounded by the
   original descriptor's access mode; sockets fail with `ENXIO`, anonymous inodes with
   `EACCES` (`ENXIO` for root), and pipes/FIFOs reopen with independent flags and the
   requested direction. Generic `FileRequest::Reopen` and `Backend::reopen_file` provide
   retained-object reopening, including writable opens where permissions and the
   selected backend allow them, without resolving an old pathname.
4. **Fields are emitted only from real sources** (see the table above). Only the
   caller's own entries are exposed; `fd` additionally checks the acting credentials
   against its owner and mode. Cross-process views need a same-credentials and
   dumpability check; whether the shim tracks dumpability is not yet audited.
   Shim-sourced state that changes rarely (`exe`, `cwd`, `limits`) is pushed by the
   shim whenever it changes, so that no read depends on a runner servicing a request;
   frequently changing fields need another source.
5. **Accepted compatibility differences:**
   * Directory listings refresh only on rewind, as described above.
   * Already-open nodes of an exited process report `ENOENT`, and reads of an exited
     process's generated files `EIO`; Linux is believed to report `ESRCH` (*native check*).
   * Rename and directory removal in procfs remain unsupported (`EROFS`).

Suggested order: directory snapshots (done), path-based `cwd` (done), `limits` (done),
`status` (done), `fd/N` hand-back (done), retained-object reopening for descriptor and `exe`
links (done), then `maps` and the object-based walk with directory magic links (a general resolver
change, deferred).
