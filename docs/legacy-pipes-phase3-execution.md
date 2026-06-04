# Legacy-pipes Phase 3 — execution brief

**Branch**: `wportnoy/legacy-pipes-phase-3` (this worktree at
`/home/wportnoy/src/litebox-phase3`)
**Base**: `wportnoy/vscode-server-in-litebox` at `0f86ae82`
**Plan**: `~/.copilot/session-state/e1aa42d0-0c8d-4b94-989c-ebd5b1f748b5/plan.md`
**Predecessor brief**: `~/.copilot/session-state/802afcd2-d50f-46cb-b868-c8a52edae7f0/files/legacy-pipes-migration.md`

This file is the **execution-time** addendum: it pins down decisions
made during reconnaissance and lists exact file/line targets so a
fresh session can land each deliverable without re-discovering the
surface.

## What was confirmed during reconnaissance (vs. what the brief said)

- **Legacy site count: 2 production callers** — correct, exactly:
  - `litebox_shim_linux/src/syscalls/process.rs:3469`  (parent mux)
  - `litebox_runner_linux_userland/src/lib.rs:2235`    (worker mux)
  - `litebox_shim_linux/src/syscalls/epoll.rs:2047` is a `#[test]`,
    not a production caller; deleted with `litebox::pipes` in Phase 5.
  - `litebox_shim_linux/src/syscalls/file.rs:6180` is
    `BrokerPipeProvider::create_pipe` (2-arg, modern) — not legacy.

- **No separate `litebox_broker_core` / `litebox_broker_protocol`
  crates exist on this branch.** All broker code lives in
  `litebox_broker`. The wire protocol is one enum (`Opcode`) at
  `litebox_common_linux/src/cwfd/fd_token_protocol.rs:123`, 5,317
  lines total. Agent memories referring to those crates are from a
  different branch and do not apply here.

- **`StateObjectEnum`** at
  `litebox_broker/src/cwfd/state_registry.rs:207` is the broker's
  closed enum of held state. Adding a new variant requires updates
  in **every** exhaustive match — `kind`, `subsystem_tag`,
  `subscribe`, `unsubscribe`, `current_events`,
  `try_flush_subscriptions`, plus the resolver pattern matches in
  `state_service.rs` (every `resolve_*` helper). No catch-alls are
  permitted (workspace clippy lint
  `wildcard_enum_match_arm = "deny"`).

- **`SubsystemTag`** at
  `litebox_common_linux/src/cwfd/fd_transfer_frame.rs:155+`
  serializes as a u8 over the wire. Currently allocated: 1 Eventfd,
  2 TcpSocket, 3 Pidfd, 4 UnixSocket, 5 Signalfd, 6 Timerfd, 7
  Inotify, 8 Process, 9 Pipe, 10 Pty, 11 InetListener, 12 InetDgram,
  13 InetRaw, 14 PipeRead, 15 PipeWrite. **Next free: 16.**

- **Opcode allocation in PIPE range (0x50)**: 0x50 CreatePipe / 0x51
  ReadPipe / 0x52 WritePipe used; 0xD0 / 0xD1 / 0xD2 response. **Next
  free: 0x53 / 0xD3**.

- **`TcpConnState` is the precedent** for "broker state object that
  wraps a host fd." See `litebox_broker/src/cwfd/tcp_conn_state.rs`
  for the shape: host fd wrapped in `OwnedFd`, epoll-driven
  readiness, read/write via host syscalls, subscribe/unsubscribe.
  `attach_host_fd` should model `HostFdAttached` on this, not on
  in-memory `PipeReadEnd`/`PipeWriteEnd`.

## D2 — B1 `attach_host_fd` execution recipe

**Goal**: SCM_RIGHTS-receive a host fd into the broker; expose it
as a broker handle the shim can install via `BrokerPipeFd`.

### Files to touch (in order of natural dependency)

1. **`litebox_common_linux/src/cwfd/fd_transfer_frame.rs`** —
   `SubsystemTag::HostFd = 16` (add variant + to_u8/from_u8 arms;
   ~5 lines).

2. **`litebox_common_linux/src/cwfd/fd_token_protocol.rs`** —
   - Add `Opcode::AttachHostFd = 0x53` (line ~150) + corresponding
     `Opcode::AttachHostFdResponse = 0xD3` (line ~254).
   - `response_for` arm at line ~448.
   - `CARRIES_PID` match at line ~534 (omit unless attach needs
     per-pid tracking; default omit per existing pipe ops).
   - `from_u8` arm at line ~638 (request) + ~717 (response).
   - Request body: `(direction: u8, _reserved: [u8; 7])` — 8 bytes,
     8-byte-aligned. Direction values: `0 = Read`, `1 = Write`,
     `2 = ReadWrite` (full duplex, for sockets). The host fd itself
     rides in the SCM_RIGHTS cmsg.
   - Response body: `(handle_id: u64)` — 8 bytes.
   - Add `build_attach_host_fd_request(direction: u8)`,
     `parse_attach_host_fd_body`,
     `build_attach_host_fd_response_ok(handle_id: u64)`,
     `parse_attach_host_fd_response_body`. Round-trip unit test
     following the `write_pipe_round_trip_body_max_boundary` pattern
     at line ~5125.

3. **`litebox_broker/src/cwfd/host_fd_state.rs`** (new file) —
   `HostFdState` struct wrapping `OwnedFd`. Methods: `read`, `write`,
   `subscribe`, `unsubscribe`, `current_events`,
   `try_flush_subscriptions`, `subsystem_tag()` returning
   `SubsystemTag::HostFd`. Pattern from `tcp_conn_state.rs` — copy
   the epoll-driven readiness skeleton and adapt to the host fd's
   syscall surface (this is a generic read/write fd, no
   socket-specific ops).

   Direction enforcement: store the `direction` from the attach
   request; `read` returns `EBADF` if direction == `Write`-only,
   `write` returns `EBADF` if direction == `Read`-only.

   Stdio preservation policy: if the wrapped fd is 0/1/2, `Drop`-time
   skip `close()`. Match in `Drop` impl: only call `OwnedFd::drop()`
   (which calls close) if `as_raw_fd() >= 3`; otherwise
   `let _ = self.fd.into_raw_fd()` to forget without closing.

4. **`litebox_broker/src/cwfd/mod.rs`** — `pub mod host_fd_state;`

5. **`litebox_broker/src/cwfd/state_registry.rs`** — 6 enum-dispatch
   match updates:
   - `StateObjectEnum::HostFdAttached(Arc<HostFdState>)` variant
     (line ~221).
   - `StateKind::HostFdAttached` variant (the `StateKind` enum above
     `StateObjectEnum`, look ~line 200).
   - Match arms in `kind`, `subsystem_tag`, `subscribe`,
     `unsubscribe`, `current_events`, `try_flush_subscriptions`.

6. **`litebox_broker/src/cwfd/state_service.rs`** —
   - `Opcode::AttachHostFd => handle_attach_host_fd(registry, request, in_fds)`
     in dispatch (line ~295 area).
   - `fn handle_attach_host_fd(registry, request, in_fds) -> HandlerResult`:
     - Validate `in_fds.len() == 1` (else `protocol_err`).
     - Parse direction from request body.
     - Build `HostFdState` from the received `OwnedFd`.
     - `registry.register(...)` → returns `StateHandle`.
     - Return `build_attach_host_fd_response_ok(handle.id())`.
   - `resolve_host_fd(registry, handle_id) -> Result<Arc<HostFdState>, StatusCode>`
     helper (modeled on `resolve_pipe_read`). Extends every existing
     resolver helper's `StateObjectEnum` match by one arm
     (`HostFdAttached(_) => Err(StatusCode::SubsystemMismatch)`).
     This is the single largest mechanical change in this slice —
     count: ~15+ resolver helpers each gain one arm.
   - `read_pipe`/`write_pipe` handlers gain a `HostFdAttached`
     resolution: extend `resolve_pipe_read` to *also* accept a
     `HostFdAttached` (call its `read`/`write` directly). Cleanest
     way is a new resolver `resolve_pipe_or_host_fd_read` that
     returns either, and have the handler match on it. Decision
     deferred until first attempt; the alternative is a separate
     `ReadHostFd`/`WriteHostFd` opcode pair.

7. **`litebox_common_linux/src/cwfd/fd_token_client.rs`** —
   `pub fn attach_host_fd(&self, host_fd: BorrowedFd<'_>, direction: u8) -> Result<u64, ClientError>`.
   Sends request frame + SCM_RIGHTS cmsg containing the host fd.
   Parses response into handle_id. Model on existing
   `pass_fd_with_sendmsg` patterns in this file.

8. **`litebox_common_linux/src/cwfd/broker_pipe_provider.rs`** —
   Add `fn attach_host_fd(&self, host_fd: BorrowedFd<'_>, direction: BrokerPipeEnd) -> Result<HandleId, BrokerPipeError>`
   to the `BrokerPipeProvider` trait. Default impl returns
   `Err(BrokerPipeError::Unsupported)` so other impls aren't forced
   to support it immediately.

9. **`litebox_runner_linux_userland/src/broker_pipe_provider.rs`** —
   `RunnerBrokerPipeProvider::attach_host_fd` impl: forwards to
   `self.client.attach_host_fd(host_fd, direction as u8)`.

10. **Unit tests** in `litebox_broker/src/cwfd/host_fd_state.rs`
    (in-file `#[cfg(test)] mod tests`) and in `fd_token_socket.rs`
    (line ~2027 pattern):
    - `host_fd_state_read_write`: pipe pair via `pipe2()`, attach
      one end via `HostFdState::new(fd, Read)`, write to the other
      end (host syscall), verify `read` returns expected bytes.
    - `host_fd_state_stdio_preservation`: attach fd 0, drop state,
      verify fd 0 still open (via `fcntl(F_GETFD)` returning 0, not
      `EBADF`).
    - `host_fd_state_close_on_drop_for_non_stdio`: attach fd ≥ 3,
      drop, verify fd is closed.
    - `host_fd_state_direction_enforcement`: attach Read-only, assert
      `write` returns `EBADF`.
    - `attach_host_fd_e2e`: full RPC via test client — attach, write
      through, read through, release. Pattern from
      `fd_token_socket.rs:2027`.
    - `attach_host_fd_protocol_error_no_fd`: send AttachHostFd with 0
      fds in cmsg, expect protocol error response.

### Validation gates for D2

```bash
cd /home/wportnoy/src/litebox-phase3
cargo fmt
cargo build -p litebox_common_linux -p litebox_broker -p litebox_runner_linux_userland
cargo clippy -p litebox_common_linux -p litebox_broker -p litebox_runner_linux_userland \
  --all-targets --all-features -- -D warnings
cargo test -p litebox_common_linux fd_token_protocol::tests
cargo test -p litebox_broker host_fd
cargo test -p litebox_broker cwfd::fd_token_socket::tests::attach_host_fd
```

### Commit

```
feat(broker): add attach_host_fd op for SCM_RIGHTS host-fd ingestion

Adds the broker B1 primitive that the legacy-pipes phase-3 migration
needs: a worker can SCM_RIGHTS-pass a host fd to the broker, which
takes ownership and exposes it as a BrokerPipe-shaped state handle.
Subsequent commits wire this into the parent-side mux-stream eager
install path, retiring --pipe-bridge.

* New SubsystemTag::HostFd (wire u8 = 16).
* New Opcode::AttachHostFd / AttachHostFdResponse (0x53 / 0xD3).
* New HostFdState wrapping OwnedFd, with stdio-preservation policy
  on drop (fds 0/1/2 are not closed).
* Direction enforcement: Read / Write / ReadWrite.
* Unit tests cover round-trip, stdio preservation, direction
  enforcement, protocol error on missing cmsg.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```

## D3 — B2 `clone_fs_fid` execution recipe

**Goal**: extend the FS install path so a worker installs a guest fd
referencing an *existing* 9P fid owned by the parent (POSIX
inherited-fd shared-offset semantics), instead of reopen-by-path.

### Approach decision

Two choices for the wire surface:

**(a)** New opcode `CloneFsFid = 0x54` / response `0xD4`:
broker-internal 9P `Twalk` of the parent's fid with zero name
components → new fid id; broker returns the new fid id; worker
installs an `FS` fd referencing it.

**(b)** Extend the existing `--broker-fd-bridge` brokerfile install
path (`litebox_shim_linux/src/syscalls/file.rs:2800`) with a fid-id
mode that bypasses `fs.open(path)` and directly registers a 9P fid
id the broker has already cloned.

**Recommended: (a) + extend (b)'s install path to consume the new
fid id.** Cleaner separation: protocol op for the broker side,
install-path extension for the shim side.

### Files to touch

1. **`litebox_common_linux/src/cwfd/fd_token_protocol.rs`** —
   `Opcode::CloneFsFid = 0x54` / `CloneFsFidResponse = 0xD4` (or in
   the 9P/process range if a more appropriate base exists; check
   `opcode_ranges` mod ~line 316). Request body: `(parent_fid: u32,
   _reserved: u32)` — 8 bytes. Response body: `(child_fid: u32,
   _reserved: u32)` — 8 bytes.

2. **`litebox_broker/src/nine_p/server.rs`** — expose a function
   `clone_fid(parent_fid: u32) -> Result<u32, NinePError>` that
   performs `Twalk` with zero name components on the parent fid,
   returns the newly-allocated child fid. May already exist as part
   of internal `Twalk` handling; if so, factor out.

3. **`litebox_broker/src/cwfd/state_service.rs`** —
   `fn handle_clone_fs_fid(...)` that calls into the 9P server's
   `clone_fid` and returns the response. Note: this op does NOT
   register anything in `BrokerStateRegistry` — 9P fids are managed
   by the 9P server's own table.

4. **`litebox_common_linux/src/cwfd/fd_token_client.rs`** —
   `pub fn clone_fs_fid(&self, parent_fid: u32) -> Result<u32, ClientError>`.

5. **`litebox_shim_linux/src/syscalls/file.rs:2800`** — extend
   `install_brokerfile_bridge_fd` (or add a sibling
   `install_brokerfile_fid_bridge_fd`) that takes a `fid_id: u32`
   instead of a `path: &str`. Registers an `FS` fd in the descriptor
   table whose backing is the given 9P fid (rather than re-opening
   by path).

6. **CLI** in `litebox_runner_linux_userland/src/lib.rs` —
   `--broker-fd-bridge` parser gains a new kind: `fs_fid:<fid_id>`
   alongside the existing `brokerfile:<path>`.

7. **Unit tests** in `litebox_broker/src/nine_p/server.rs`:
   - `clone_fid_zero_walk_shares_offset`: open file, write 100b at
     offset 0; clone fid; write 100b on clone fid; total file size
     200b, contents in order. (Shared offset.)
   - `clone_fid_independent_refcount`: clunk parent fid, clone still
     usable; clunk clone fid last, server frees state.
   - `clone_fid_unlinked_survival`: open file, clone fid, unlink the
     path, write via clone fid; succeeds (POSIX unlinked-fd
     semantics inherited from the host kernel).

   In `fd_token_socket.rs`:
   - `clone_fs_fid_e2e`: open via 9P client; call `clone_fs_fid`
     RPC; write via cloned fid; verify on host.

### Validation gates for D3

```bash
cargo build -p litebox_broker -p litebox_shim_linux -p litebox_runner_linux_userland
cargo clippy -p litebox_broker -p litebox_shim_linux -p litebox_runner_linux_userland \
  --all-targets --all-features -- -D warnings
cargo test -p litebox_broker nine_p::server::tests::clone_fid
cargo test -p litebox_broker cwfd::fd_token_socket::tests::clone_fs_fid
```

## D4 — Test scaffolding (harness invariants + handler skeletons)

See plan.md §Test scaffolding. All new tests live in
`litebox_test_harness/src/coordinator/`. Per `CLAUDE.md`:

- Native gold standard: every new test must pass native (0 FAIL).
- All test logic is in handlers (no new `Command::*` variants, no
  bash unless testing bash).
- Fan across `BinaryType::ALL` via the relevant matrix arrays.
- No XFAIL anywhere (enforced by `tests/no_expected_fail.rs`).

Tests added in D4 may fail under litebox until D5/D6/D7 land — that's
the fix-first signal. Land D4 in a single commit, even with litebox
failures, then D5/D6/D7 collapse those failures.

## D5–D10 — see plan.md

Plan.md captures D5 (parent rewrite), D6 (worker rewrite + CLI
cleanup), D7 (shim plumbing cleanup), D8 (refcount audit), D9
(validation sweep), D10 (rubber-duck + merge prep) in adequate detail.
The dependency graph is intact in the session SQL store.

## Branch / merge discipline

- Work on `wportnoy/legacy-pipes-phase-3`; **do not push to origin**.
- Pre-push hook enabled in this worktree:
  `git config --local core.hooksPath .githooks` (already done).
- Merging to `wportnoy/vscode-server-in-litebox` is **`--no-ff`
  only**, from the amalgamation worktree
  (`/home/wportnoy/src/litebox-ci` — currently at the amalgamation
  tip `0f86ae82`), and **requires explicit user approval** before the
  merge.

## House rules

- `cargo fmt` → `cargo build` → `cargo clippy --all-targets
  --all-features -- -D warnings` → targeted `cargo test` (NOT `cargo
  nextest` for the harness; see `litebox_test_harness/CLAUDE.md`).
- Safety comments on every `unsafe`.
- `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`
  trailer on every commit.
