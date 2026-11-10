# Guest procfs design

Status: opt-in procfs backend with authenticated caller context, automatic broker
process lifetimes, and loader-published read-only executable object links. This is
not a claim of general Linux compatibility.

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
  unsupported. With procfs enabled, readlink/stat/open use real nodes. Descriptor
  readlinks and following metadata for `fd/N` still use shim special cases.
* [Process state](src/syscalls/process.rs) stores an executable pathname only for that
  compatibility fallback. Published executable identity and fork inheritance are
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
caller-aware. Direct legacy resolver/backend calls have no associated process;
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
filesystem owner. It returns a non-cloneable `ProcessRegistration` guard. The live
registration count is bounded by the namespace's configured limit; duplicate keys
or PIDs and exhausted capacity return explicit errors, never replacement or eviction.
PIDs are the broker's PID-namespace-relative IDs. Every process sharing one file
service must therefore share one PID namespace, as the userland brokers do today;
a file service shared across PID namespaces would see colliding PIDs and needs
`FileCaller` to carry the namespace before procfs can scope its listings to it.
Drop the guard on exit or runner failure, but retain it across exec. Manual
registration remains available for other startup integrations. For automatic
registration, configure `with_process_lifecycle(owner)` before mounting the provider.
The generic backend `process_created(caller, parent)` hook returns an opaque
resource retained by the broker process across exec and released on exit, startup
failure, or final cleanup. Composition rolls back earlier resources if another
provider fails. Callbacks run outside process-state locks; resource destructors must
not call back into broker process state.

The userland broker mounts this provider at `/proc` when built with
`--features linux_procfs` and invoked with `--linux-procfs`. Neither build-time nor
runtime opt-in alone changes the default namespace. Requesting the flag without the
feature reports an explicit startup error. The initial owner is UID/GID 1000, matching
the default Linux runner; children inherit the creator's owner and executable
capability. Credential changes and other initial identities are not yet published.
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
* A process directory is read-only. It contains `exe` only after a trusted state
  source publishes a readable regular file with `ProcState::set_executable`.
  Unsupported names such as `thread-self` and `fd` are not fabricated.

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
these targets are explicitly rejected in this first slice.

`O_PATH | O_NOFOLLOW` retains the proc link inode, whereas following `O_PATH` retains
the executable object. A regular-file target cannot accept a suffix or a trailing
slash. The physical-path-string resolver rejects object targets rather than turning
their display names back into authority. Readlink currently returns the saved open
path, which can become stale; live naming and the Linux ` (deleted)` suffix remain
unimplemented.

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

The [guest fixture](../litebox_runner_linux_userland/tests/procfs.c) verifies static
and dynamic main-image identity, mounted `self` lookup, enumeration, fork, exec,
readlink/lstat/stat/open, read-only rejection, independent reopens after rename and
unlink, failed-exec preservation, and re-exec through the retained object using
`cargo nextest run -p litebox_runner_linux_userland --features procfs --test run -E
'test(procfs_tracks_fork_and_exec_process_identity)'`, after building the broker with
`linux_procfs`. Writable files, devices, directory magic links, `cwd`, and `fd/N`
object authority remain subsequent work; no pathname-reopen fallback is used.

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
| `limits` | Broker-owned resource limits; the broker can generate it without querying the shim. |
| `status` | Broker for Pid/PPid/Tgid/thread count; shim for credentials. Omit `Vm*` and `State` until they have real sources. |
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
2. **The authoritative walk carries objects, not absolute strings.** The resolver
   will track "current directory object + remaining components" and gain a directory
   link target alongside `LinkTarget::File`, reusing `walking_dir_at` to resume from a
   held handle. The same change provides `dirfd`-relative walks, correct `link/..`, and
   a cwd held as a directory handle instead of a string. `..` from a directory reached
   through a magic link asks the backend for its parent and fails explicitly when a
   backend cannot answer. Only `O_NOFOLLOW` and `O_PATH` are supported resolution
   restrictions; `openat2` restrictions are rejected until `openat2` exists.
3. **`fd/N` hands the walk back to the caller.** Descriptor numbers are Linux state
   that the broker does not track. For the caller's own `fd/N`, procfs returns a
   continuation naming that descriptor, and the caller's shim resumes the walk from
   its own handle. This costs nothing for processes that never use `/proc` and is not
   string rewriting: it carries a descriptor number and continues from a held object.
   Other processes' `fd/` fails explicitly until cross-process views, which will need
   shim-published descriptor state. Reopening follows Linux: a fresh open of the same
   object with a fresh permission check and an independent offset, not bounded by the
   original descriptor's access mode; sockets fail with `ENXIO` and pipes/FIFOs reopen
   (*native check*). This needs a backend operation that reopens a held object with
   given flags and credentials, which also enables writable targets.
4. **Fields are emitted only from real sources** (see the table above). While only the
   caller's own entries are exposed, Linux always permits access, so no new
   authorization is required yet. Cross-process views need a same-credentials and
   dumpability check; whether the shim tracks dumpability is not yet audited.
   Shim-sourced self files are generated by the caller's shim when it opens them and
   handed to the broker, which stores the text with the open description.
5. **Accepted compatibility differences:**
   * Generated text is a per-open-description snapshot, regenerated whenever a read
     starts at offset zero, so `pread(..., 0)` polling sees fresh content and reads at
     increasing offsets never splice snapshots.
   * Directory listings refresh only on rewind, as described above.
   * `exe` displays the path recorded when the image was opened; there is no rename
     tracking and no ` (deleted)` suffix.
   * Already-open nodes of an exited process report `ENOENT`; Linux is believed to
     report `ESRCH` for some operations (*native check*).

Suggested order: directory snapshots (done), the object-based walk with `cwd` and
directory magic links, `fd/N` handback and removal of the shim's `/proc/self` special
cases, then `limits`, `status`, and `maps`.
