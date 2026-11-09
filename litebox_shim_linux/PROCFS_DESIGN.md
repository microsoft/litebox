# Guest procfs design

Status: design proposal, not an implementation or a claim of Linux compatibility.

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

* [File syscall handling](src/syscalls/file.rs) special-cases
  `readlink("/proc/self/exe")`, `readlink("/proc/self/fd/N")`, and following metadata
  queries for descriptor paths. These are not filesystem nodes.
* [Process state](src/syscalls/process.rs) stores an executable pathname; fork startup
  copies it. This does not retain the executable's identity after rename or unlink.
* The shim's file open description wraps a broker-backed file. Directory enumeration
  currently sorts entries and uses an index as its offset; a changed listing can move
  entries across that offset.
* [Client file operations](../litebox/src/fs/file.rs) send normalized paths to the
  broker. Lexical normalization already loses some Linux symlink semantics, including
  `link/..` and trailing-slash requirements.
* The broker [resolver](../litebox_broker_core/src/fs/resolver.rs) expands symlinks as
  strings and can rewalk their targets. The
  [backend interface](../litebox_broker_core/src/fs/backend.rs) has no explicit
  accessing-process or accessing-thread context.
* Native fork, copy-based fork, vfork-to-exec, and descriptor inheritance span runners.
  An `Arc` to shim state is not a transferable open file description.

Consequently, neither a plain broker `Backend` implementation nor a shim
`starts_with("/proc/")` check is sufficient.

## Ownership and placement

Split implementation into three layers:

1. **Guest-neutral namespace and handle machinery:** component-wise walking,
   mount transitions, ordinary and object-backed links, open descriptions, and
   transferable references. Reuse existing resolver/backend abstractions where they
   fit; extend them only for demonstrated gaps.
2. **Linux ProcFs provider:** nodes, process/thread interpretation, generated content,
   access checks, and conversion of failures to Linux errors.
3. **State sources:** local shim state for self introspection; broker-owned generic
   object identity and lifecycle; eventually bounded queries to other Linux runners.

ProcFs lives logically in the Linux shim even if a generic broker-mediated provider
mechanism is needed to serve its handles across processes. The broker must not gain
Linux text formatting, Linux PID rules, or a request named "read proc maps".

The exact transport for a remote provider is not decided here. Do not introduce a
general callback/RPC framework merely to support the initial local nodes.

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
loaded interpreter. Display-name updates and the ` (deleted)` suffix require additional
namespace tracking. Retaining a file alone does not solve name tracking; document this
as a separate compatibility milestone.

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

Directory cookies must not be indices into a freshly sorted mutable list. Choose and
document stable keyed cookies or a bounded per-open listing snapshot. An entry can
vanish between enumeration and lookup; returning it once does not promise it still
exists. Define rewind behavior and bound retained listings.

Sources must be guest state:

| Entry | Source and caveat |
|---|---|
| `status`, `limits` | Shim process/thread state; fields need individually defined semantics. |
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

## Open decisions before implementation

1. Where will the authoritative provider-aware walk run, and which minimal generic
   interfaces let it cross the existing broker boundary?
2. Which generic reference/reopen operations can preserve object identity without
   broadening access to broker-owned files?
3. Which proc open descriptions must outlive a runner, and where is their shared state
   hosted? How are reference cycles and abandoned providers reclaimed?
4. Which Linux fields and authorization rules can current guest state actually support?
5. What compatibility differences are acceptable for initial snapshots, directory
   cookies, executable display names, and already-open files after target exit?

Answer these with small executable prototypes and native comparisons before committing
to a general remote-filesystem framework.
