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

Use the integration test harness via `cargo test`:

```bash
# Full suite (both native and litebox passes):
cargo test -p litebox_test_harness --test integration

# Single test (one trial per pass):
cargo test -p litebox_test_harness --test integration -- 'litebox::PN.B.eof' --exact

# Tune concurrency (default: clamp(num_cpus / 1.5, 2, 10) — e.g., 10 on a 16-core host):
LITEBOX_TEST_JOBS=8 cargo test -p litebox_test_harness --test integration

# Only native or only litebox:
cargo test -p litebox_test_harness --test integration -- 'native::'
cargo test -p litebox_test_harness --test integration -- 'litebox::'
```

Each Trial spawns its own `docker run` (`litebox-test` image), gets a
fresh `litebox_tool_executor` + broker + runner + agent matrix, and
writes per-Trial logs to
`target/test-logs/<pass>-<sanitized_id>.{stdout,stderr}.log`.

#### Why `cargo test` and not `cargo nextest`

The repo otherwise uses `cargo nextest` (see `.config/nextest.toml`
and the CI workflow). This integration test is the deliberate
exception:

- nextest spawns a **fresh test-binary process per test** (its
  isolation model).
- Our `setup()` in `tests/integration.rs` (build the 5 binary
  variants + ensure the docker image) is amortized via `OnceLock`
  to once per cargo-test invocation.
- With nextest's process-per-test, every one of ~5500 tests would
  re-enter `setup()` and re-invoke `cargo build`. Even a no-op
  cargo build costs ~1 s; that's ~90 minutes of pure overhead.
- There's a workable migration (nextest's `[scripts.setup-X]`
  with a flock to serialize the build), but that's significant
  infrastructure for a marginal benefit — what we'd gain from
  nextest (per-test JUnit timing, per-test timeout overrides,
  test-group concurrency, retries) we already do in-tree via
  the per-test timing JSONL (below), the `LITEBOX_TEST_JOBS`
  semaphore, and harness-side `.timeout(N)`.

Don't run multiple `cargo test` invocations against the same target
dir simultaneously — the build cache will thrash.

#### Tuning knobs

| Env var                   | Default                       | Effect                                                          |
|---------------------------|-------------------------------|-----------------------------------------------------------------|
| `LITEBOX_TEST_JOBS`       | `clamp(num_cpus / 1.5, 2, 10)`| Max concurrent `docker run` invocations (the real test parallelism cap). |
| `LITEBOX_DRAIN_BACKLOG`   | `4 * LITEBOX_TEST_JOBS`       | Max in-flight post-result drain threads.                        |
| `LITEBOX_TEST_MEMORY`     | `8g`                          | Per-container `--memory` and `--memory-swap` (safety bound — OOM-kill on excess; no swap thrash). |
| `LITEBOX_TEST_PIDS`       | `8192`                        | Per-container `--pids-limit` (safety bound).                    |
| `LITEBOX_TEST_CPUS`       | (unset → no CPU cap)          | Per-container `--cpus` (opt-in only — capping CPU often regresses fork-heavy tests). |
| `LITEBOX_DRAIN_TIMEOUT_SECS` | `30`                       | Watchdog timeout on the post-result drain phase.                |
| `LITEBOX_KEEP_CONTAINER`  | (unset)                       | If set, omit `--rm` so containers persist for `docker ps` inspection. |

The litebox-pass outer timeout (`timeout --signal=KILL <N>`) is
per-test, derived from the harness's `.timeout(N)` setting + 15 s
grace, so failing fast-tests fail in (their budget) + 15 s rather
than the previous blanket 120 s.

#### Per-test timing telemetry

Each run produces `target/test-logs/per-test-timing.jsonl` with one
or two JSONL lines per test:

```json
{"test":"PB.c2p.pie-glibc.dpg1","pass":"native","t_acquire_ms":12,
 "t_docker_start_ms":810,"t_useful_ms":340,"verdict":"pass","jobs":10}
{"test":"PB.c2p.pie-glibc.dpg1","pass":"native","t_drain_ms":4500}
```

`litebox_test_harness/scripts/analyze-test-timing.py` summarizes a
single run or diffs two runs (e.g., before/after a perf change).

To run a docker invocation by hand for debugging:

```bash
# Native (gold standard — real kernel):
docker run --rm --cap-add SYS_PTRACE \
  -v $(pwd)/target/debug:/opt/litebox:ro \
  -v $(pwd)/target/nonpie/debug:/opt/nonpie:ro \
  litebox-test /opt/litebox/litebox_test_harness spawn-tree --filter=PN.B.eof

# Litebox sandbox (tests the shim):
docker run --rm --cap-add SYS_PTRACE -e LITEBOX_NO_AUDIT=1 \
  -v $(pwd)/target/debug:/opt/litebox:ro \
  -v $(pwd)/target/nonpie/debug:/opt/nonpie:ro \
  litebox-test /opt/litebox/litebox_tool_executor \
    --rootfs / --record-baseline \
    -- /opt/litebox/litebox_test_harness spawn-tree --filter=PN.B.eof
```

Running `litebox_test_harness` directly (without `litebox_tool_executor`)
tests the **native kernel**, NOT litebox's shim. The coordinator prints
`[coord] runtime:` at startup to identify the environment.

Useful integration-test env vars (all read by `tests/integration.rs`):

- `LITEBOX_TEST_JOBS=N` — concurrent docker runs (default 5).
- `LITEBOX_DRAIN_BACKLOG=N` — concurrent draining containers (default 20).
- `LITEBOX_FORCE_FULL_MATRIX=1` — opt out of the lazy non-PIE
  spawn heuristic; always spawn the full agent matrix.
- `LITEBOX_KEEP_CONTAINER=1` — drop `--rm`; containers survive
  for `docker logs <name>` inspection.
- `LITEBOX_NO_AUDIT=1` — disable audit logging in the runner.

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
