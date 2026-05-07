# Testing Rules for litebox_test_harness

These rules are mandatory when adding, modifying, or reviewing tests,
**and when investigating any failure observed in VS Code server, Node.js,
or sshd running inside Litebox**.

## Investigating a failure

This section applies whenever a failure is observed in the integration
stack (VS Code remote server, Node.js, sshd, or any other guest workload),
regardless of whether you intend to "just debug" or to add a test.

Before reading any syscall audit log, attaching gdbserver, or re-running
the full Docker stack to test a hypothesis:

1. **Name the suspect capability.** Examples: `epoll` + `pidfd`,
   `pty` + `TIOCSPGRP`, fork + CLOEXEC inheritance, `io_uring` probe,
   `/proc/self/*` reads, `clone3` flags, `eventfd` semantics.
2. **Find or add a self-contained test** in this harness that exercises
   only that capability. Prefer protocol commands over bash; follow all
   rules in "Writing Tests" below.
3. **Run native first.** It must pass on the WSL2 chroot baseline. If it
   fails native, the test is wrong, not Litebox.
4. **Run under Litebox.** If it reproduces, you now have a minimal,
   deterministic repro. Fix the product code per the fix-first workflow
   (rule 12).
5. **Only now** consult the syscall audit log or attach gdbserver, and
   only to inform the *next* minimal test. The audit log is never the
   fix target; a failing harness test is.

**Forbidden shortcuts:**

- Reverse-engineering a fix from a syscall audit log without a failing
  harness test.
- Re-running the full Docker → sshd → VS Code server → Litebox stack to
  validate a hypothesis. The harness exists so you don't have to.
- "I'll just attach gdb and poke around" before steps 1–3.

If the failing capability genuinely cannot be expressed in the harness
(e.g., requires fd inheritance not yet supported by the protocol — see
"fd Inheritance Pattern" below), say so explicitly, and the first fix is
to extend the harness/protocol so it can.

### Per-session worktree

Coding-agent sessions run in separate git worktrees so parallel sessions
don't invalidate each other's incremental builds or kill each other's
containers. When investigating an integration-stack failure, build and
run from the worktree, not the canonical checkout. See `AGENTS.md`
"Per-session isolation" for details.

## Multi-wave platform-fix workflow

When the test harness is reporting tens or hundreds of failures (e.g., after a
large product change, a refactor, or first standing up a new subsystem), use
this workflow rather than fixing tests one at a time in series. It scales the
single-failure fix-first workflow to bulk cleanup without sacrificing rigor.

This is the methodology that drove the suite from 522/968 → 998/1002 = 99.6 %
in one multi-session arc. It is not a substitute for the rules in
"Investigating a failure" above — it composes them.

### Mental model

A typical large FAIL list is mostly **cascade**: one product bug surfaces as
dozens or hundreds of distinct test failures because many tests share a code
path. The job is to identify and fix **roots**, not to triage cascades
individually. After a root is fixed, the cascade collapses and a new layer of
roots becomes visible. Repeat until the delta is empty or stable.

In the 522→998 arc, the single Bug B fix (shim worker-stdio routing) was
downstream of 442/446 of the then-remaining failures. Treating those as 442
independent bugs would have wasted the session. Treating them as one root with
a shared symptom found and fixed it once.

### The wave loop

Each wave has four phases:

1. **Triage.** Cluster the current FAIL list by likely shared root.
   - Capture a fresh full-suite log (`wave-<N>.log`) — this is also the
     regression gate from the previous wave.
   - For each FAIL, capture syscall/errno signature with `litebox_audit_query`
     (see "playbook" below). Group by `(dominant_syscall, dominant_errno,
     subsystem)` — most cascades fall out naturally.
   - Reduce each cluster to one or two **representative tests** that should
     reproduce the root with minimal noise.
   - Write the cluster table: cluster name, representative tests, hypothesized
     root, suspect crate (use the ownership map below).

2. **Fan-out.** Dispatch one fix subagent per cluster, in parallel.
   - Each subagent gets its own git worktree on its own branch (see
     `AGENTS.md` "Per-session isolation"). This prevents sessions from
     invalidating each other's incremental builds or stepping on each other's
     containers.
   - Each subagent works narrowly: its assigned cluster's representative
     tests only. **It must not run the full suite** — that's the parent's
     gate, expensive, and not its job.
   - Each subagent follows the fix-first workflow rigorously (rule 12 above):
     reproduce the failing minimal test, fix product code, watch test pass,
     verify no regressions in the cluster's representative tests.
   - One fix per commit: `fix: <subsystem> — <one-line summary>`.

3. **Merge.** Rebase or `--no-ff` merge each subagent's branch onto the
   integration branch. **Never force-push** the integration branch — use the
   pre-push hook in `.githooks/pre-push` if the repo provides one.
   `--no-ff` preserves wave structure in history; force-push obliterates it
   and breaks parallel sessions' working trees.

4. **Re-discover.** Run the full suite again as the next wave's
   `wave-<N+1>.log`. This serves three purposes simultaneously:
   - Regression gate for the wave just merged.
   - Cascade-collapse measurement: did fixing root R in cluster C
     also pass tests in clusters D, E, F? Often yes — those clusters are
     dropped from the next wave.
   - New-root discovery: what becomes visible now that the previous layer is
     fixed? Triage that as wave N+1.

Stop when the delta from one wave to the next is empty or stable, or when
remaining FAILs are documented as out-of-scope (e.g., "VS Code integration
suite — disabled in commit X" or "performance regression, filed as
follow-up").

### Triage heuristics that work in practice

- **Group by errno before grouping by test name.** `EAGAIN` on `read` from
  pipes vs `ECONNREFUSED` on `connect` are different roots even if the test
  IDs look related. Pull `result_err` distributions per cluster.
- **Group by suspect subsystem second.** `litebox_runner_linux_userland`
  fork/exec failures look very different from `litebox_broker/network`
  TCP RST issues even if the test names rhyme.
- **A "fix" that isn't gated by a failing minimal test is not a fix.** It's a
  guess. Twice in the 522→998 arc, hypotheses about "the broker rewriting the
  large ELF" and "the rwlock test stresses node" turned out to be wrong on
  inspection — both were caught by the parent in review because no minimal
  failing test had been produced.
- **Don't trust test docstrings about cause.** A test's comment describing
  what it's "supposed to" stress can be wrong (the test may have been written
  before the relevant product code, or the bottleneck may have shifted). When
  the audit log disagrees with the docstring, the audit log wins. (Worked
  example below.)

### Worked example: the ~16-test parallelism flake cluster

After the wave loop reached 998/1002, the residual ~16 failures were
**performance flakes under parallelism=8**, not correctness bugs. Tests like
`CF.rwlock_multi_6.A` passed in isolation in ~38 s but exceeded the harness's
20 s per-test exec deadline when 7 sibling containers saturated host CPU.

Initial hypotheses (ELF rewriting, 9P bind-mount routing, open-write-lock
contention) were all wrong. The actual cost, found via audit log:

```sh
litebox_audit_query sql --file <log> \
  "SELECT syscall, COUNT(*), SUM(duration_ns)/1e6 AS ms FROM syscalls
   GROUP BY syscall ORDER BY ms DESC LIMIT 10"
```

revealed `clone` taking 1.6 s × 6 calls = 9.6 s of fork-restore overhead per
trial, vs. ~25 ms of actual child syscall work per fork. The test's own
docstring (claiming it stressed the 9P open-write-lock path) was factually
wrong — opens were 1 ms each.

Lessons from this side-investigation:

- Always confirm the bottleneck via audit-log measurement, even when the
  test code claims to know.
- "Investigation-only" with no fix is a valid wave outcome when the fix
  surface is architectural (here: fork-restore in
  `litebox_platform_linux_userland`) and out of scope. Document it,
  don't paper over it.

### Anti-patterns

- **Fixing tests one at a time in series.** Doesn't scale, blocks parallelism,
  and misses cascade structure.
- **Running the full suite repeatedly during fix-time.** It's a gate, not an
  iteration tool. Use single-test runs (see playbook) for inner loop.
- **One subagent owning multiple unrelated clusters.** Defeats the parallelism;
  if it gets stuck on one cluster, the others stall.
- **Cross-cluster fixes in a single commit.** Hides the fix→test mapping.
  One fix per commit, period.
- **Force-pushing integration branches "to clean up history".** Other
  sessions are based on those commits. Use `--no-ff` merges.

### Pre-flight before starting a wave loop

- [ ] Per-session worktree set up (see `AGENTS.md`).
- [ ] Pre-push hook enabled if the repo provides one.
- [ ] Baseline `wave-0.log` captured: full suite run on the target branch.
- [ ] FAIL list extracted and bucketed by `(syscall, errno, subsystem)`.
- [ ] Out-of-scope FAILs explicitly listed (e.g., disabled suites) so they
      don't get re-triaged each wave.

## Test Categories

**Self-contained tests** depend only on bash and the test harness binaries.
These are preferred. They run everywhere: WSL2 chroot, litebox, CI.

**Integration tests** require external binaries like Node.js or VS Code.
These are acceptable but always secondary — add a self-contained test
for the underlying platform capability first.

## WSL2 Gold Standard

The native baseline is the gold standard. Every test must pass there —
**0 FAIL** on native.

- `tests/integration.rs` runs the native baseline inside the
  `litebox-test` Docker image (`docker run --rm --cap-add SYS_PTRACE
  -v target/debug:/opt/litebox:ro … litebox-test
  /opt/litebox/litebox_test_harness spawn-tree …`).
- The same image is reused for the litebox pass, with
  `litebox_tool_executor --rootfs / --record-baseline --` prepended.
- Any native failure is a **test bug**, not a litebox bug.
- The Docker image is built on demand by `ensure_docker_image()` from
  `litebox_tool_executor/rootfs/Dockerfile` — no manual setup.

There is no expected-failure mechanism in this harness. Outcomes are
strictly `pass` or `FAIL`. A litebox test that does not work fails for
real, every run, until the product code is fixed. Do not add any
form of "expected fail" allowlist, dynamic skip, or static xfail set —
they are not supported and existed only as dead code in earlier
iterations.

## Principles

### Writing Tests

1. **Self-contained over integration** — prefer tests that need only
   bash + test harness. Before adding a node/VS Code-dependent test,
   add an equivalent self-contained test for the underlying capability.

2. **Minimal test cases use protocol commands, not bash** — use FsRead,
   FsWrite, NetListen, Exec with self_exe subcommands. Bash is only
   justified when testing bash-specific fork behavior.

3. **No silent failures** — missing dependencies must cause loud FAIL
   with a clear error message, never a silent skip.

4. **Matrix coverage** — test all configurations via cross-product loops.
   When adding a capability test, cover all relevant axes:
   - In-process (same agent)
   - Parent → child (agent forks child)
   - Child → parent (reverse direction)
   - Sibling → sibling (if applicable)
   - At depth 2+ (nested workers)

5. **No timer delays** — never use sleep/retry loops to mask product bugs.
   Use protocol-level signals for synchronization.

6. **Self-contained rootfs** — `cargo test -p litebox_test_harness
   --test integration` must pass without manual rootfs setup. Add new
   guest binaries / files to `litebox_tool_executor/rootfs/Dockerfile`
   so they're baked into the `litebox-test` image.

7. **No python3 or other interpreters** — all test logic is in Rust.
   If a test needs a server/client pattern, add a subcommand to the
   test binary (main.rs) rather than invoking an interpreter.

8. **Reason every failing test, never paper over it** — every test
   must have a clear pass/FAIL semantic and a clear reproduction.
   When a test fails, fix the product code; do not add an "expected
   fail" mechanism, do not introduce a skip path, and do not record
   `pass` with a "skipped" detail string.

### Fixing Bugs

9. **Fix failing minimal tests before investigating further** — a failing
   minimal test is the highest-priority signal. It identifies a concrete
   product bug with a clear reproduction. Do not defer it.

10. **Never remove or paper over failing tests for convenience** —
    failing tests must not be deleted, commented out, converted to a
    "skip" path, or hidden behind a dynamic gate just because they are
    inconvenient. The product code must be fixed.

11. **Cover all configurations before changing product code** — before
    fixing a bug, write minimal tests covering all relevant configurations
    (e.g., init→child, child→grandchild). This ensures the fix works for
    all cases, not just the one initially observed.

12. **Fix-first workflow:**
    1. Write the test that demonstrates the desired behavior
    2. Watch it fail (confirming the bug exists)
    3. Fix the product code
    4. Watch the test pass (confirming the fix is correct)
    5. Verify no regressions (all other tests still pass)

    Never fix product code without a failing test first.

## Debugging Strategy

When a test fails and the root cause is unclear:

13. **Isolate layers with bypass tests** — write a test that bypasses
    intermediate layers (e.g., the agent protocol) to determine WHICH
    layer has the bug. For example, `stress-exec` runs fork+exec
    directly, proving litebox's fork/exec works and the bug is elsewhere.

14. **Vary one axis at a time** — write focused tests that change only
    one variable:
    - Fresh agent vs used agent (isolates accumulated state)
    - Same agent vs sibling agent (isolates parent-level corruption)
    - PIE-only vs non-PIE-only vs mixed (isolates exec path)
    - 1 exec vs 30 execs (isolates resource leaks)

    Each test should have a clear hypothesis: "if this passes but that
    fails, the bug is in X."

15. **Check accumulating data structures** — grep for `.push()` without
    corresponding `.remove()`, `.retain()`, or `.clear()`. Accumulating
    lists of IDs/handles are a common source of stale-entry bugs,
    especially when IDs can be reused.

16. **Check handle identity mechanisms** — verify how handles/IDs are
    generated. Monotonic counters are safe. Pointer addresses
    (`Arc::as_ptr()`) are vulnerable to reuse after free. Recycling
    pools require caller validation.

17. **Check cleanup ordering** — verify that resources used by background
    threads are not cleaned up before those threads finish. Look for
    `detach`/`move to background` patterns that skip `join()`.

## What NOT to Do

- Do NOT introduce any "expected fail" mechanism — no `xfail` /
  `XPASS` outcomes, no allowlists of known-failing tests, no dynamic
  skip paths. Outcomes are `pass` or `FAIL`, period.
- Do NOT skip tests by recording `pass` with "skipped" detail — that hides failures
- Do NOT use `child.kill().await` in litebox (hangs; use `start_kill()`)
- Do NOT let Exec timeouts desync the agent — use subprocess isolation
- Do NOT add python3, ruby, or other interpreter dependencies
- Do NOT remove failing tests for convenience
- Do NOT batch coordinator output to be flushed only at end-of-main() —
  the spawn-tree process can be SIGKILL'd during `teardown_tree` under
  litebox, dropping anything not already on the pipe. Emit progress
  records (JSON / log lines) incrementally and flush. See
  `TestRunner::record` for the pattern: one `println!` +
  `stdout().flush()` per result, alongside the existing `eprintln!`.

## Enforcement

### Integration test

Always run with **`cargo test`**, not `cargo nextest`:

```sh
cargo test -p litebox_test_harness --test integration
# Subset (one Trial per pass per test ID):
cargo test -p litebox_test_harness --test integration -- native::NL1
cargo test -p litebox_test_harness --test integration -- 'litebox::PN.B.eof'
# Multiple test ID prefixes (comma-separated also works):
cargo test -p litebox_test_harness --test integration -- 'native::NL'
```

The harness uses `libtest_mimic` (custom `harness = false`) and registers
two trials per test ID: `native::<id>` and `litebox::<id>`. Each trial
spawns its own `docker run` with `--filter=<test_id>` so every test
gets a fresh `litebox_tool_executor` + broker + runner + agent
matrix. Tests cannot contaminate each other.

**Concurrency knobs (env vars, std-only semaphores):**

| Variable | Default | Effect |
|----------|---:|--------|
| `LITEBOX_TEST_JOBS` | 5 | Max concurrent `docker run` invocations in their result-bearing phase. |
| `LITEBOX_DRAIN_BACKLOG` | 20 | Max post-result containers draining concurrently. Back-pressures the test loop if drain falls behind. |
| `LITEBOX_FORCE_FULL_MATRIX` | unset | When set, always spawn the non-PIE subtree even if the filter doesn't reference NP/NPC/D3/D4/D5. |
| `LITEBOX_KEEP_CONTAINER` | unset | Don't pass `--rm`; containers stay around for `docker logs`. Each is `--name`d as `litebox-<pass>-<id>-<pid>-<ns>`. |

**Per-Trial logs**: each trial's docker stdout/stderr is written
to `target/test-logs/<pass>-<sanitized_id>.{stdout,stderr}.log`
(stderr via `Stdio::from(File::create(...))`, stdout tee'd as we
parse for the JSON result line). On Trial failure, the `Err`
message includes both log paths.

**Lazy agent matrix**: the harness spawn_tree only spawns the
non-PIE subtree (NP, NPC, D3, D4, D5) when at least one filtered
test ID contains those agent names as a dot-separated component.
~97 % of tests are PIE-only and skip the 30 s
`spawn_nonpie_subtree` setup. End-of-run validation
(`validate_lazy_matrix` in `coordinator/mod.rs`) records a
synthetic `__lazy_matrix.validation` FAIL if any agent contacted
via `TestRunner::send` was not actually spawned, so a
heuristic miss is loudly visible.

**Why not `cargo nextest`?** Each Trial in nextest is its own
process; `setup()`'s `OnceLock` caching of build/image checks
becomes per-process (no help) and there's no cross-process
build lock yet. `cargo test` keeps everything in one libtest
process where the OnceLock works.

The integration test verifies:
- Native baseline: every `native::<id>` trial passes (0 FAIL).
- Litebox: every `litebox::<id>` trial passes. There is no
  expected-failure escape hatch; any test that fails on litebox but
  passes on native is a real product bug and must be fixed in the
  shim, not annotated away.

There are no "expected counts" constants and no allowlist of tolerated
litebox failures. Each trial is asserted individually: pass or fail.

### Code review checklist
When adding tests, verify:
- [ ] Uses protocol commands, not bash (unless testing bash behavior)
- [ ] No new interpreter dependencies
- [ ] Tests all relevant axes (parent↔child, sibling, depth 2+)
- [ ] Added to `litebox_tool_executor/rootfs/Dockerfile` if a new
      guest binary/file is required
- [ ] No "expected fail" / skip / dynamic gate dressed up as a pass
- [ ] VS Code concern has a corresponding minimal self-contained test
- [ ] Passes on native baseline (WSL2 gold standard)

## fd Inheritance Pattern

The VS Code CLI hands a listen socket to a child process via fork+exec:

```
parent: bind()+listen() → clear CLOEXEC → fork()+exec(child) → close(fd)
child:  accept() on inherited fd → echo data
```

This pattern is tested by the `tcp-fork-listen-accept` subcommand in
main.rs (used by the FKLC.cross_connect test). It cannot currently be
expressed via the agent protocol because the child needs to accept on a
raw fd number rather than re-binding.

The `Fork` protocol command has an `inherit_listen_ports` field designed
for this but not yet implemented. See the design notes in protocol.rs
for implementation guidance.
