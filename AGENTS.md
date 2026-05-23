# Agent Instructions

This repository is a Rust-based, security-focused sandboxing library OS. General
contribution guidelines live in `CONTRIBUTING.md` and the per-crate docs.

## Debugging VS Code server / Node.js / sshd failures

For **any** issue surfaced by running VS Code remote server, Node.js, or sshd
inside Litebox, read **`litebox_test_harness/CLAUDE.md`** before doing
anything else, and follow its "Investigating a failure" section.

In short:

1. Identify the suspect platform capability (e.g., `epoll+pidfd`, `pty+TIOCSPGRP`,
   fork+CLOEXEC inheritance, `io_uring` probe, `/proc/self/*`).
2. Find or add a **self-contained** test in `litebox_test_harness` that
   exercises just that capability.
3. Run it on the WSL2 native baseline (must pass) and under Litebox
   (should reproduce the failure).
4. Only then look at the syscall audit log or attach gdbserver — and only
   to inform the next minimal test, never as the fix target.

**Audit-log-driven or gdb-driven debugging without a failing minimal test
in the harness is not permitted.** Manually re-running the full
Docker → sshd → VS Code server → Litebox stack to verify a hypothesis is
also not a substitute for a harness test.

**Do not create new probe scripts in `litebox_tool_executor/scripts/`.**
That directory is bring-up and tooling only — see
`litebox_tool_executor/scripts/README.md`. New `test-*.sh`,
`check-*.sh`, `debug-*.sh`, or `verify-*.sh` scripts there will be
deleted on sight; reproduce in `litebox_test_harness` instead.

## Per-session isolation

Coding agent sessions run in separate git worktrees and branches. When a
session also brings up the Docker container, it must use a unique
container name, ssh port, and its own target directory so parallel
sessions do not invalidate each other's incremental builds or collide on
host resources.

## Branch and merge discipline

`wportnoy/vscode-server-in-litebox` is the **amalgamation branch** —
the integration of multiple work streams. Its history should be a
series of merge commits (one per work stream landed), not a linear
chain of work-stream commits. Each merge commit records *which*
work stream landed *when*, which is the property we lose if work
gets fast-forwarded onto the amalgamation.

Each agent session works on `wportnoy/<work-stream>` (e.g.,
`wportnoy/litebox-platform-fixes`, `wportnoy/typed-handles`).
Work-stream branches stay linear and accumulate per-session
commits. They don't have to be pushed to `origin` — they're visible
across worktrees of the same clone, so the amalgamation worktree
can merge from a local work-stream by name.

### Landing a work stream

The worktree containing `wportnoy/vscode-server-in-litebox`
(typically the main `litebox` clone) is the only place that lands
work onto the amalgamation. The pattern, for a work-stream `W`:

```sh
# From a local W (no origin push needed):
cd <main-worktree>           # already on vscode-server-in-litebox
git merge --no-ff W
git push origin wportnoy/vscode-server-in-litebox

# From a pushed origin/W:
cd <main-worktree>
git fetch origin
git merge --no-ff origin/W
git push origin wportnoy/vscode-server-in-litebox
```

`--no-ff` is **mandatory**. The merge commit it creates is the
durable record of which work stream landed.

### Things not to do

| Wrong | Why |
|---|---|
| `git push origin W:wportnoy/vscode-server-in-litebox` | Fast-forwards origin to W's tip. Bypasses any `--no-ff` merge commit you made locally. Succeeds silently. |
| `git rebase origin/wportnoy/vscode-server-in-litebox` (on W, then push) | Linearises history. Same bypass-merge effect as the shortcut push. |
| `git push origin wportnoy/vscode-server-in-litebox` when local HEAD is a single-parent commit (i.e., you forgot to wrap in `merge --no-ff`) | Pushes a flat extension. `.githooks/pre-push` (below) blocks this. |
| Push `wportnoy/vscode-server-in-litebox` from a session whose work isn't yet merged | Risk of clobbering another session's local merge structure. Always pull first or land via the amalgamation worktree. |

### If you need newer code from the amalgamation in your work stream

Don't rebase. Merge the amalgamation **into** your work stream
with `--no-ff`:

```sh
cd <your-work-stream-worktree>
git fetch origin
git merge --no-ff origin/wportnoy/vscode-server-in-litebox
```

This keeps the work-stream history linear-from-its-own-perspective
while still incorporating the amalgamation's state. When the
amalgamation worktree later lands the work stream, the resulting
merge commit will collapse cleanly.

### Local-only enforcement (`.githooks/pre-push`)

The repo ships a pre-push hook that rejects pushes setting
`wportnoy/vscode-server-in-litebox` to a single-parent commit.
Enable it once per clone:

```sh
git config --local core.hooksPath .githooks
```

The hook is a guardrail, not a guarantee — it doesn't run on the
server side, and any session can disable it. Server-side
enforcement (GitHub branch protection requiring `--no-ff` merges)
would be the only true block.

### Build

With the repo on ext4, use cargo s default target/ directory.
No --target-dir needed.

```bash
cargo build
cargo test -p litebox_test_harness --test integration

# Non-PIE variant
cargo rustc -p litebox_test_harness --bin litebox_test_harness --target-dir target/nonpie -- -C link-args=-no-pie
```

### Running tests

Integration test invocation patterns, tuning knobs (`LITEBOX_TEST_JOBS`
etc.), per-test timing telemetry, the `LITEBOX_HARNESS_PAUSE`
soft-breakpoint pattern for debugging a specific failing test, manual
`docker run` invocations, and audit-log analysis with
`litebox_audit_query` all live in
**[`litebox_test_harness/CLAUDE.md`](litebox_test_harness/CLAUDE.md)**
(the "Integration test" section under "Enforcement").

Why there and not here: the litebox integration test harness has a
custom shape (uses `cargo test` deliberately rather than `cargo
nextest`; spawns one `docker run` per Trial; reads several
`LITEBOX_*` env knobs) and its guidance is most useful when read
alongside the harness source.

### Docker images

```bash
docker build --target litebox-test   -t litebox-test   -f litebox_tool_executor/rootfs/Dockerfile .
docker build --target litebox-vscode -t litebox-vscode -f litebox_tool_executor/rootfs/Dockerfile .
```

### Logging

Never write diagnostic output to stdout or stderr from the runner or shim —
these are reserved for guest use (VS Code captures them). Use
`debug_log_print` which writes to `/tmp/rst-diag.log`.

## Host fd range conventions

Worker processes use three disjoint fd ranges to prevent collisions
between bridge fds and infrastructure fds during `posix_spawn`.
**All new fd allocation in `litebox_platform_linux_userland` must
respect these ranges.** Use the named constants — never hardcode
fd minimums.

| Range   | Owner                 | Constant               |
|---------|-----------------------|------------------------|
| 0–2     | stdio                 | —                      |
| 3–99    | guest bridge targets  | (posix_spawn dup2)     |
| 100–199 | parent bridge fds     | `PARENT_BRIDGE_FD_MIN` |
| 200–499 | child bridge host fds | `WORKER_BRIDGE_FD_MIN` |
| 500+    | infrastructure fds    | `INFRA_FD_MIN`         |

Constants are defined in `litebox_platform_linux_userland/src/lib.rs`.
See the module-level doc comment for details.

## Code standards

See the per-crate `CLAUDE.md` / `README.md` files and the repository-wide
custom instructions (cargo fmt → build → clippy → nextest, minimal
`unsafe`, `no_std` where feasible, justify new dependencies).
