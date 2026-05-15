# Diagnostic playbook — fix-agent reference

This is the operating manual for a **fix subagent** working a single
cluster of related test failures. Use it together with the rules in
`CLAUDE.md` ("Investigating a failure" and "Multi-wave platform-fix
workflow") and the per-session worktree conventions in `AGENTS.md`.

You are a fix agent. You inherit a worktree, a list of failing
TEST_IDs that share a likely root, and (if available) a
`dominant_errno` from the parent triage step. Your job: drive those
tests from FAIL to pass under litebox without breaking native.

This playbook is the **only** ramp-up doc you need. Everything below
is concrete commands you should copy.

---

## Conventions you must follow

- **Fix-first workflow.** Reproduce a failing test before changing
  any code; never patch from intuition.
- New `unsafe` requires a safety comment.
- Per-crate gate before commit:
  `cargo fmt && cargo clippy --all-targets --all-features -p <crate>
   && cargo nextest run -p <crate>`.
- One fix per commit. Commit message:
  `fix: <subsystem> — <one-line summary>`.
  Include trailer: `Co-authored-by: Copilot
   <223556219+Copilot@users.noreply.github.com>`.
- **Never run the full litebox suite from inside this agent.** The
  parent owns that gate. Use single-test runs for everything.
- Stay in your assigned worktree. Do not touch `litebox_test_harness/`
  unless the failure is *clearly* harness-side and the parent
  confirms.

---

## Single-test cargo invocation (primary iteration tool)

```
cd <your-worktree>
cargo build && \
cargo rustc -p litebox_test_harness --bin litebox_test_harness \
    --target-dir target/nonpie -- -C link-args=-no-pie

cargo test -p litebox_test_harness --test integration -- \
    --nocapture litebox::<TEST_ID>
```

What you should see:
- libtest-mimic-style trial output, one line per matched TEST_ID.
- A `FAIL` with `<TEST_ID>: <detail>` ⇒ confirmed reproduction.
- A `pass` ⇒ already fixed (rebase took it; move to next FAIL).

Run the same TEST_ID under native (`native::<TEST_ID>`) to confirm
the native baseline still passes — it should.

---

## Capturing an audit log for a single TEST_ID

The default `cargo test` litebox path runs under
`litebox_tool_executor` *without* `--audit-log`, so the log lands at
`/tmp/litebox-vscode-server-logs/` **inside the disposable
container** and is destroyed by `docker run --rm`.

To capture the log on the host, run the docker command directly with
`--audit-log` bind-mounted to a host path. This is the equivalent of
what `cargo test -- litebox::<TEST_ID>` does:

```
WS=$(pwd)
mkdir -p /tmp/audit-out

docker run --rm --cap-add SYS_PTRACE \
  -v "$WS/target/debug:/opt/litebox:ro" \
  -v "$WS/target/nonpie/debug:/opt/nonpie:ro" \
  -v /tmp/audit-out:/audit-out \
  litebox-test \
    timeout --signal=KILL 1200 \
    /opt/litebox/litebox_tool_executor \
      --rootfs / --record-baseline \
      --audit-log /audit-out \
      -- \
    /opt/litebox/litebox_test_harness spawn-tree \
      --filter=<TEST_ID>
```

The audit log appears as
`/tmp/audit-out/audit-<timestamp>.jsonl`.

`spawn-tree --filter=<TEST_ID>` accepts a single TEST_ID (e.g.
`UA.write.A`) or a suite/group prefix.

---

## `litebox_audit_query` quickstart

The tool imports JSONL audit logs into SQLite (joining enter/exit
events into one row per syscall) and ships a built-in schema +
canned queries. **Always read the tool's own schema output before
writing custom SQL** — there are 10+ ready-made queries you can
copy.

```
# Full schema, column reference, error codes, and 10+ canned queries.
litebox_audit_query schema

# One-shot: import + query.
litebox_audit_query sql --file /tmp/audit-out/audit-<ts>.jsonl \
    "SELECT syscall, result_err, COUNT(*) AS cnt
     FROM syscalls WHERE result_err IS NOT NULL
     GROUP BY syscall, result_err ORDER BY cnt DESC LIMIT 10"

# Persistent DB for repeated queries (faster).
litebox_audit_query import /tmp/audit-out/audit-<ts>.jsonl
litebox_audit_query sql --db /tmp/audit-out/audit-<ts>.jsonl.db \
    "<query>"
```

### Schema cheatsheet

One row per syscall, keyed `(seq, worker)`. Useful columns:

| Column | Meaning |
|--------|---------|
| `seq` | Monotonic per-worker sequence |
| `worker` | Host PID of the runner process |
| `pid`, `tid` | Guest virtual PID / TID |
| `syscall` | Name (`openat`, `read`, `connect`, `other`, …) |
| `args` | JSON array of entry arguments |
| `enter_ts` / `exit_ts` / `duration_ns` | Monotonic ns; `exit_ts` NULL ⇒ orphan |
| `result_ok` | `{"ok": N}` on success |
| `result_err` | Negated errno on failure |
| `pending_ns` | Orphans only; large value ⇒ likely hung |

Common errno values you'll see (negated):
`-2 ENOENT`, `-11 EAGAIN`, `-13 EACCES`, `-22 EINVAL`,
`-25 ENOTTY`, `-38 ENOSYS`, `-4 EINTR`.

### Worked example (use this as a template)

A test fails with `UA.write.AA` showing "no echo" detail.

1. Capture audit log via the docker invocation above with
   `--filter=UA.write.AA`.
2. Find dominant error:
   ```
   litebox_audit_query sql --file /tmp/audit-out/audit-*.jsonl \
       "SELECT syscall, result_err, COUNT(*) AS cnt
        FROM syscalls WHERE result_err IS NOT NULL
        GROUP BY syscall, result_err ORDER BY cnt DESC LIMIT 10"
   ```
   Suppose this returns `connect | -111 | 5`. ECONNREFUSED on
   `connect` ⇒ the listener never bound, or the proxy didn't accept.
3. Pull the worker timeline around those `connect` calls to confirm
   the surrounding state machine:
   ```
   litebox_audit_query sql --file /tmp/audit-out/audit-*.jsonl \
       "SELECT seq, worker, pid, syscall, args, result_ok,
               result_err, duration_ns/1000 AS us
        FROM syscalls
        WHERE syscall IN ('socket','bind','listen','accept','connect')
        ORDER BY enter_ts LIMIT 50"
   ```
4. Map back to product source — usually
   `litebox_broker/src/network/` or
   `litebox_platform_linux_userland/src/syscall/` — and fix.

---

## gdbserver via `--debug`

When the audit log alone is insufficient (e.g., need to inspect
in-memory state), wrap the runner under gdbserver. The `--debug`
flag lives on `litebox_tool_executor`.

```
docker run --rm -it --cap-add SYS_PTRACE \
  -p 9999:9999 \
  -v "$WS/target/debug:/opt/litebox:ro" \
  -v "$WS/target/nonpie/debug:/opt/nonpie:ro" \
  litebox-test \
    /opt/litebox/litebox_tool_executor \
      --rootfs / --record-baseline \
      --debug 9999 \
      -- \
    /opt/litebox/litebox_test_harness spawn-tree \
      --filter=<TEST_ID>
```

In another terminal:

```
# Interactive (humans):
bash dev_tools/gdb-connect.sh --port 9999

# Non-interactive transcript (coding agents):
bash dev_tools/gdb-connect-batch.sh --port 9999 --commands probe.gdb \
  [--timeout 120]
```

### Multi-inferior model — read this first

Litebox runs as ≥4 cooperating processes (executor, broker, runner,
per-guest worker). Under gdbserver each is a separate GDB *inferior*.
The connect scripts pre-configure `set detach-on-fork off`, so all
of them remain attached. Use:

  - `info inferiors` — list them.
  - `inferior N` — switch.
  - `thread apply all bt` — backtrace every thread in current inferior.

**A breakpoint that stops one inferior will block the others.** The
broker/runner protocol is synchronous over pipes; sitting at a
breakpoint in one process makes the rest of the system deadlock as
soon as protocol traffic backs up. Two practical implications:

1. Prefer **short-lived breakpoints**: use
   `commands ... silent ... <gather info> ... continue end`
   so the inferior never sits paused.
2. For "stop and look around" use cases, prefer **pause points**
   (see next section) rather than gdb breakpoints — the pause
   freezes only the matching process, and its siblings keep running.

### Pause points (`LITEBOX_HARNESS_PAUSE`)

For many debugging scenarios, gdb breakpoints inside litebox are
fragile (multi-inferior deadlocks, fragile conditionals, attach
races, monomorphized-symbol misses). The test harness supports
**pause points** as a more reliable alternative.

Set `LITEBOX_HARNESS_PAUSE=<tag>[=<filter>][,<tag>[=<filter>]]...`
to make the harness `raise(SIGSTOP)` itself at a stable site, emit
a `[litebox-pause] tag=... pid=N ...` marker on stderr, and wait for
`SIGCONT`. Attach gdb at the paused point (data structures are
quiescent), or run `gcore <pid>` / poke `/proc/<pid>/*` and resume
with `kill -CONT <pid>`.

Available harness tags (extend the framework with shim/broker tags
as concrete debugging needs arise — see
`litebox_test_harness::pause_points`):

| Tag                       | Fires when…                                     | Typical filter |
|---------------------------|-------------------------------------------------|----------------|
| `harness:test-start`      | Just before running a test                      | test ID        |
| `harness:test-end-pass`   | Test passed; before teardown                    | test ID        |
| `harness:test-end-fail`   | Test failed or timed out; before teardown       | test ID        |

Examples:

```
# Pause before a single failing test runs (gives time to attach gdb):
LITEBOX_HARNESS_PAUSE='harness:test-start=PB.c2p.nonpie-glibc.dpg2' \
  cargo test ... --test integration -- 'litebox::PB.c2p.nonpie-glibc.dpg2' --exact

# Pause whenever any test fails:
LITEBOX_HARNESS_PAUSE='harness:test-end-fail' cargo test ...

# Multiple pause points in one run:
LITEBOX_HARNESS_PAUSE='harness:test-start=PB.x,harness:test-end-fail' cargo test ...
```

The marker prefix `[litebox-pause]` is grep-able and is distinct
from the harness's JSON protocol output.

### Failure-shape → breakpoint cookbook

For each failure shape, the suspect site to inspect (gdb breakpoint
or pause point as noted). Symbols verified against current sources;
adjust file paths if the runner refactors.

| Failure shape                                       | Suspect site                                                       | gdb or pause?     |
|-----------------------------------------------------|--------------------------------------------------------------------|-------------------|
| Single TEST_ID I want to debug from the start       | (set `LITEBOX_HARNESS_PAUSE=harness:test-start=<id>`)              | pause             |
| Any test fails — want post-mortem state             | (set `LITEBOX_HARNESS_PAUSE=harness:test-end-fail`)                | pause             |
| Guest fork returns wrong PID / clone misbehavior    | `litebox_shim_linux::syscalls::process::do_clone`                  | gdb               |
| Guest exec silently fails                           | `litebox_shim_linux::syscalls::process` (search `execve`)          | gdb               |
| Fd inheritance across exec broken                   | `litebox_shim_linux::syscalls::fd::cloexec_filter` / `FdTable`     | gdb               |
| Signal lost between guest threads                   | `litebox_shim_linux::syscalls::signal` (search `do_kill` / `queue`)| gdb               |
| epoll wakes up with 0 events                        | `litebox_shim_linux::syscalls::epoll` (search `epoll_wait`)        | gdb               |
| 9P op times out / returns wrong errno               | `litebox_broker::nine_p::fcall::handle`                            | gdb               |
| TCP connect fails with surprising errno             | `litebox_broker::net_proxy::PortRouter`                            | gdb               |
| Cross-worker fd transfer fails                      | `litebox_common_linux::cwfd` (state object trait impls)            | gdb               |
| /proc/self/* read returns wrong content             | `litebox_shim_linux::syscalls::proc` (search `proc_self`)          | gdb               |
| Stdio inheritance across worker-exec wrong          | `litebox_platform_linux_userland::posix_spawn` (PARENT_BRIDGE_FD)  | gdb               |
| `posix_spawn` of a non-PIE binary fails             | `litebox_runner_linux_userland::worker_exec`                       | gdb               |
| Pipe EAGAIN unexpected in non-blocking mode         | `litebox_shim_linux::syscalls::pipe`                               | gdb               |
| io_uring probe fails                                | `litebox_shim_linux::syscalls::io_uring`                           | gdb               |
| Signalfd / pidfd ops not routed cross-worker        | `litebox_broker::cwfd::*` (signalfd_state, pidfd_state)            | gdb               |
| Audit log shows weird errno; want to step it        | `litebox_runner_linux_userland::audit` (Sysno-level)               | gdb               |

When in doubt, run `litebox_audit_query schema` first — many bugs
narrow to a `(syscall, errno)` pair that points at one of the
above.

### Example session

`dev_tools/gdb-example-session.md` walks an end-to-end example
using `LITEBOX_HARNESS_PAUSE` + `gdb-connect-batch.sh` to drive a
single test from failure observation to root cause in a single
shell round-trip. Imitate that template for new debugging sessions.

### Coding-agent ergonomics

Coding agents typically struggle with **interactive** gdb sessions:
the multi-inferior protocol-deadlock model breaks single-process
assumptions, and step-through inside async Rust tokio futures rarely
produces useful state. The two tools above (`gdb-connect-batch.sh`
and `LITEBOX_HARNESS_PAUSE`) are specifically designed for
non-interactive use. Prefer them over driving a live `(gdb)` prompt.

---

## Crate ownership map

Use this to localize the fix. When in doubt, audit log args narrow
it further.

| Failure shape | Likely crate |
|---------------|--------------|
| Wrong errno on a single syscall, missing struct field, wrong flag handling | `litebox_runner_linux_userland`, `litebox_platform_linux_userland` |
| Fork/exec, fd inheritance, vfork, pipe bridging | `litebox_runner_linux_userland`, `litebox_platform_linux_userland` |
| TCP/UDP, smoltcp, port routing, accept/connect, RST | `litebox_broker` (smoltcp lives here), `litebox/` (top-level) |
| 9P / FS path canonicalization / RootDir locking | `litebox_broker/src/nine_p/`, `litebox_broker/src/fs/` |
| Syscall instruction patching, ELF rewriting | `litebox_syscall_rewriter`, `litebox_shim_linux`, `litebox_rtld_audit` |
| Audit log shape, missing fields | `litebox_util_log`, `litebox_runner_linux_userland` |
| Tool launcher, --debug, --audit-log routing | `litebox_tool_executor` |

Test layer (do not modify unless explicitly told to):
`litebox_test_harness/`.

---

## Per-fix iteration loop (recap)

1. Reproduce: `cargo test -- litebox::<TEST_ID>` (must FAIL).
   Confirm `cargo test -- native::<TEST_ID>` passes.
2. Read source: the test body in
   `litebox_test_harness/src/coordinator/<file>.rs` and the suspect
   product code from the ownership map.
3. Capture audit log for that single TEST_ID. Run the canned
   "Error distribution by syscall" query first.
4. If still unclear, attach gdbserver via `--debug`.
5. Fix product code. Add safety comments for any new `unsafe`.
6. Verify: rerun the same TEST_ID under both native and litebox.
   Both must pass.
7. Per-crate gate: `cargo fmt`, `cargo clippy --all-targets
   --all-features -p <crate>`, `cargo nextest run -p <crate>`.
8. Commit. One fix per commit. Move to the next TEST_ID in your set.

---

## What to do if you get stuck

- If a single TEST_ID seems to require harness changes: stop, ask
  the parent to hand the harness half off.
- If two FAILs in your set turn out to depend on each other: fix
  the lower-layer one first. If neither is "lower", fix the
  smaller-fan-out one and re-run the other; it may evaporate.
- If the audit log shows `pending_ns` orphans (`exit_ts IS NULL`):
  a syscall hung. Pull the orphan list and check args against the
  product code path.
- If you can't form a hypothesis after audit-log inspection, attach
  gdbserver. Don't keep re-reading source past 30 minutes without
  data.

---

## Out of scope for fix agents

- `litebox_test_harness/` changes.
- The VS Code suite (currently disabled, commit `7ee19f86`).
- Performance regressions — file as follow-ups, do not fix here.
