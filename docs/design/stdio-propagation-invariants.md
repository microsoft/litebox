# Stdio Propagation Invariants in Litebox

> **Status:** Reference document for "do not break this." Document
> assembled during Phase 0 of the cross-worker fd transport workstream
> after observing that stdio fd handling has been the most regression-
> heavy surface in the codebase.

Stdio fds (0, 1, 2) carry deeply-embedded special-casing throughout the
shim, runner, and platform layers. **Any change touching fork-restore,
exec, or fd inheritance must preserve every invariant in this document.**
A single deviation regressed 169 fork tests in wave-1's first PTY attempt
(`commit 1ebe223c`, reverted).

## What stdio is in the codebase

Three independent concepts that show up at different layers:

1. **Guest fds 0, 1, 2** in the per-process descriptor table. The guest
   sees these as the conventional stdin/stdout/stderr.
2. **`HostStdioSourceFd` metadata** on a `DescriptorObjectId` — records
   that this descriptor was originally one of the host's stdio
   descriptors (so dup2 alias detection works).
3. **`FdKind::StdioFd`** — a classification used by `snapshot_fd_table`
   that promotes a descriptor to "stdio" only when **both** (a) it sits
   at slot 0/1/2 *and* (b) its `object_id` matches one of the original
   host stdio object IDs.

The third concept is what gates fork acceptance. The classifier prefers
`FdKind::StdioFd` over the raw subsystem class (FilesystemFd, Pipe,
UnixSocket) when the slot is stdio AND the object matches.

## Code references

- `shim_linux/syscalls/process.rs:7008-7026` — classifier promoting fd
  to `FdKind::StdioFd`.
- `shim_linux/syscalls/process.rs:5786-5827` — wave-3 fs-parent-open
  bridge explicitly excludes `host_stdio_source_fd.is_some()`.
- `shim_linux/syscalls/process.rs:5235-5244` — UnixSocket bridge stdio-
  slot direction heuristic (fd 0 Read, fd 1/2 Write, fd 3+ ReadWrite).
- `shim_linux/lib.rs::FdReplacement.direct` — when `direct=true`, the
  replacement is a pipe end produced by `spawn_result.direct_pipes` for
  worker stdio under `use_direct_stdio` — the parent slot must be
  CONSUMED so a `ExternalFd` can be installed. When `direct=false`, the
  parent's existing virtual pipe must STAY at the slot for the bridge
  thread.
- `runner_linux_userland/lib.rs::perform_ipc_handshake` — wave-3 fix
  removed a debug `eprintln!` that was leaking onto guest stderr/PTY.
- Mux pipe bridging (`docs/design/mux-mesh-pipe-bridging.md`): stdio
  framing for the mesh worker hierarchy.

## The invariants

### I-1. Stdio fds at slots 0/1/2 must be classified as `FdKind::StdioFd` when they are aliases of the original host stdio.

Concretely: if the slot is 0/1/2 AND the descriptor's `object_id` matches
the host's recorded stdio OIDs, classification is `StdioFd`, not
`FilesystemFd` or `Pipe` even if the underlying subsystem would say
otherwise.

**Why it matters:** the bridges in `commit_delayed_fork` route stdio
classes via mux/direct-stdio (the well-trodden path) instead of through
the per-subsystem bridges (newer, narrower paths). If a stdio fd ends up
classified as FilesystemFd, the wave-3 fs-parent-open bridge would catch
it, set up a writable-fs bridge, and break stdio routing.

### I-2. Bridges added for non-stdio purposes must explicitly skip stdio entries.

The wave-3 FilesystemFd bridge guards on:
```rust
if entry.metadata.host_stdio_source_fd.is_some() { continue; }
```

Any new bridge (UnixSocket SCM_RIGHTS extension, listen-fd inheritance,
etc.) **must apply the same guard**. Stdio is owned by the mux/direct-
stdio path; new bridges do not get to second-guess it.

### I-3. Worker spawn (posix_spawn) installs stdio via `dup2` to fds 0/1/2 in the child.

`spawn_worker_host_for_exec` sets up file actions that route bridge fds
to fd 0, 1, 2 in the child via `dup2`. Bridge fds **are** in range 100+
(`PARENT_BRIDGE_FD_MIN`); after dup2 they are at 0/1/2 in the child.

**Why it matters:** an fd allocated below 100 (i.e. in the guest-bridge
target range 3–99) might collide with `dup2` targets. New fd allocation
must use `WORKER_BRIDGE_FD_MIN` or `INFRA_FD_MIN` for the bridge fds
themselves.

### I-4. The "direct" stdio fast-path consumes the parent's slot.

`FdReplacement.direct = true` (the wave-1 Bug B `fe76db98` invariant):
the parent's virtual pipe slot is REPLACED by a `ExternalFd` for the
direct path. The bridge thread does not own the slot.

`FdReplacement.direct = false`: the parent's virtual pipe STAYS; the
bridge thread reads/writes through it. The fast-path consume-and-install
must check `repl.direct == true` before consuming.

**Why it matters:** consuming the parent's pipe out from under an active
`output_bridge` causes tokio reads on stderr to block forever. This is
literally the shape of Bug B and its prior reverted fix `d9a1b1d7`.

### I-5. Stderr in the runner/shim is for guest use; diagnostic output goes to `/tmp/rst-diag.log`.

`debug_log_print` writes to a diag file. **Never write diagnostic output
to stdout or stderr from the runner or shim.** VS Code captures these
streams; debug noise breaks integration tests (the wave-3 IPC handshake
leak `49ab3759` and the wave-5 PTY tioc leak demonstrate this is an
ongoing trap).

When debugging, use `debug_log_print` and inspect `/tmp/rst-diag.log` on
the host.

### I-6. CLOEXEC semantics must be honored at exec boundaries.

Wave-4 `5ae3fcfb` (`fix: remote exec — honor CLOEXEC handoff fds`) fixed
the remote-exec path that was bridging CLOEXEC fds across exec, breaking
parent-side `posix_spawn` synchronization (parent never saw EOF on its
sync pipe → appeared as orphan execve in audit logs).

Concretely: when bridging fds at exec time, **skip fds whose `FD_CLOEXEC`
is set in the parent's table**. They are intentionally CLOEXEC, must not
survive exec.

For listen-fd inheritance work (FKLC.inherit, Phase 4 of the plan), this
is the trickiest interaction: `fork_with_inherited_listen_ports` clears
CLOEXEC explicitly to make the listen fd survive exec, but only for the
specified ports. The token-registration code must not blanket-clear
CLOEXEC for other fds.

### I-7. `host_stdio_source_fd` mapping must survive across fork+restore.

When a fork-restored child runs in a new worker process, its stdio
descriptors must still report `host_stdio_source_fd` matching the
ORIGINAL host stdio OIDs (not the new worker's host stdio OIDs).

**Why it matters:** classification depends on this match. If the new
worker's host stdio OIDs differ (which they will, since it's a different
host process), and the metadata isn't preserved, restored children
classify their stdio as FilesystemFd/Pipe and hit non-stdio bridges
inappropriately.

The wave-1 v1 PTY attempt's regression was tied to this surface: it
modified mux/stdio plumbing in ways that disrupted the host_stdio_source_fd
tracking under fork-restore.

### I-8. Mux pipe pair IDs must be unique across the worker hierarchy.

Mesh workers may forward stdio to grandchildren. Pair IDs are how the
mux dispatcher routes streams to the right pipe end. Reusing a pair ID
in a nested worker breaks routing.

The `mux-mesh-pipe-bridging.md` doc has the full rules. New bridges
introduced for fd transport must coordinate stream IDs through the same
allocator the existing mux uses.

### I-9. PTY mux fds get explicit ioctl emulation; plain pipes don't.

Wave-5 `01b22880` (PTY symptom-A) added TIOCGPGRP/TIOCSPGRP/TIOCSCTTY/
WINSZ ioctl handling for `MuxPtySlaveFd`. The wave-5 followup `68ccc5b1`
(`pty-winsz-fix`) gates WINSZ specifically on `MuxPtySlaveFd` so plain
pipes correctly return ENOTTY.

Pattern: **when handling a stdio-class ioctl, check the fd's actual type
first**. Don't unconditionally spoof.

## Regression-gate test set

Any change touching fork-restore, exec, or fd inheritance must run these
as gates. They cover the surfaces that broke in the historical incidents.

```sh
# Stdio routing and worker fork
cargo test -- --exact litebox::CP.nested_fork.bash.nonpie-glibc.dpg1
cargo test -- --exact litebox::CP.nested_fork.sh.nonpie-glibc.dpg1
cargo test -- --exact litebox::SS.backtick_pipe.bash.dpg1_dpg1
cargo test -- --exact litebox::BRS.exe_stdin.bash.bash_heredoc_pipe.nonpie-glibc.dpg1

# Socket pair / unix socket cross-worker
cargo test -- --exact litebox::US6.socketpair_read.pie-glibc.dpg1_dpg1
cargo test -- --exact litebox::US6.socketpair_write.nonpie-glibc.dpg1_dpg1

# Filesystem fd bridge (wave-3)
cargo test -- --exact litebox::FS.parent-open-fork-read.tmp.pie-glibc
cargo test -- --exact litebox::FS.bg-open-read.tmp.pie-glibc

# Pipe EOF (M-series, the canary tests Bug B was found with)
cargo test -- --exact litebox::P1.pipe_eof_fork.pie-glibc.dpg1
cargo test -- --exact litebox::M1.dpg1_dpg1.echo
cargo test -- --exact litebox::M2.dpg1_dpg1.fork_exec

# Concurrent fork + rwlock
cargo test -- --exact litebox::CF.rwlock_2.non-pie-static-musl.dpg1   # flake-class; pass needed in isolation
```

If any of the above fails on a branch that didn't fail on the parent
branch, **revert the offending commit** and try a narrower fix. This is
the wave-loop's regression-halt protocol and the explicit user
direction for the Phase 5 strict no-regression policy.

## Anti-patterns observed in prior incidents

- **`eprintln!` in worker code paths** — leaks to guest streams. Use
  `debug_log_print`. (wave-3 `49ab3759`.)
- **Modifying `signal/mod.rs` for fork-restore-related fixes** —
  recurring regression source. The wave-5 PTY fix successfully avoided
  this; the wave-1 v1 PTY fix did not.
- **Unconditional ioctl emulation on stdio fds** — broke plain-pipe
  fd 0/1/2 in the wave-5 PTY first attempt. Always type-check the fd.
- **Bridging CLOEXEC fds across exec** — breaks parent posix_spawn EOF
  synchronization. Wave-4 `5ae3fcfb`.
- **Per-fd OS pipe bridges for stdio** — see `mux-mesh-pipe-bridging.md`.
  Stdio uses the mux mesh, not per-fd bridges.
