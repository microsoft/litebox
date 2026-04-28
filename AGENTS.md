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

## Per-session isolation

Coding agent sessions run in separate git worktrees and branches. When a
session also brings up the Docker container, it must use a unique
container name, ssh port, and ideally its own `CARGO_TARGET_DIR` so
parallel sessions do not invalidate each other's incremental builds or
collide on host resources.

## Code standards

See the per-crate `CLAUDE.md` / `README.md` files and the repository-wide
custom instructions (cargo fmt → build → clippy → nextest, minimal
`unsafe`, `no_std` where feasible, justify new dependencies).
