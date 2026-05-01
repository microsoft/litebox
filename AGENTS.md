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

### Build target directory convention

This project must be built on ext4 (not NTFS) for performance. Each git
worktree **must** have its own target directory under `~/litebox-out/`:

```bash
WORKTREE=$(basename $(git rev-parse --show-toplevel))
cargo build --target-dir ~/litebox-out/$WORKTREE

# Non-PIE variant for test harness
cargo rustc -p litebox_test_harness --target-dir ~/litebox-out/$WORKTREE/nonpie -- -C link-args=-no-pie
```

**Never use `--target-dir ~/litebox-out` directly** — multiple worktrees
sharing the same target dir causes stale binary contamination (one
session's build overwrites another's binaries).

### Running tests

Always use the `litebox-test` Docker image. See `litebox_test_harness/CLAUDE.md`
for test authoring rules.

```bash
WORKTREE=$(basename $(git rev-parse --show-toplevel))

# Native (gold standard — real kernel):
docker run --rm --cap-add SYS_PTRACE \
  -v ~/litebox-out/$WORKTREE/debug:/opt/litebox:ro \
  -v ~/litebox-out/$WORKTREE/nonpie/debug:/opt/nonpie:ro \
  litebox-test /opt/litebox/litebox_test_harness spawn-tree

# Litebox sandbox (tests the shim):
docker run --rm --cap-add SYS_PTRACE -e LITEBOX_NO_AUDIT=1 \
  -v ~/litebox-out/$WORKTREE/debug:/opt/litebox:ro \
  -v ~/litebox-out/$WORKTREE/nonpie/debug:/opt/nonpie:ro \
  litebox-test /opt/litebox/litebox_tool_executor \
    --rootfs / --record-baseline \
    -- /opt/litebox/litebox_test_harness spawn-tree
```

Running `litebox_test_harness` directly (without `litebox_tool_executor`)
tests the **native kernel**, NOT litebox's shim. The coordinator prints
`[coord] runtime:` at startup to identify the environment.

### Docker images

```bash
docker build --target litebox-test   -t litebox-test   -f litebox_tool_executor/rootfs/Dockerfile .
docker build --target litebox-vscode -t litebox-vscode -f litebox_tool_executor/rootfs/Dockerfile .
```

### Logging

Never write diagnostic output to stdout or stderr from the runner or shim —
these are reserved for guest use (VS Code captures them). Use
`debug_log_print` which writes to `/tmp/rst-diag.log`.

### Analyzing audit logs

For quick checks, `grep` on the JSONL file is fine (e.g., `grep '"err"' audit.jsonl`).

For deeper analysis — finding needle-in-the-haystack errors, measuring syscall
latency distributions, or tracing cross-thread interactions — use
`litebox_audit_query` to import the log into SQLite. This pre-joins enter/exit
events and lets you run ad-hoc SQL queries (950× faster than grep for indexed
lookups on large logs).

```bash
# Import and query in one step
litebox_audit_query sql --file /path/to/audit.jsonl \
  "SELECT syscall, result_err, COUNT(*) AS cnt FROM syscalls WHERE result_err IS NOT NULL GROUP BY syscall, result_err ORDER BY cnt DESC"

# See the full schema and example queries
litebox_audit_query schema
```

Key columns: `syscall`, `args` (JSON), `duration_ns`, `result_ok`, `result_err`
(negated errno), `worker` (host PID), `pid`/`tid` (guest). See `schema` output
for the complete reference and 10+ ready-to-use queries.

## Code standards

See the per-crate `CLAUDE.md` / `README.md` files and the repository-wide
custom instructions (cargo fmt → build → clippy → nextest, minimal
`unsafe`, `no_std` where feasible, justify new dependencies).
