# Testing Rules for litebox_test_harness

These rules are mandatory when adding, modifying, or reviewing tests,
**and when investigating any failure observed in VS Code server, Node.js,
sshd, or GitHub Copilot CLI running inside Litebox**.

## Investigating a failure

This section applies whenever a failure is observed in the integration
stack (VS Code remote server, Node.js, sshd, GitHub Copilot CLI, or any
other guest workload), regardless of whether you intend to "just debug"
or to add a test.

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
"Per-session isolation" for the general worktree / target-dir / port
discipline.

**Docker image tags are auto-isolated per worktree.** The harness
resolves `litebox-test` / `litebox-agent-cli` through
`tests/common/image_tag.rs`, which appends `:wt-<sha256(worktree)[..8]>`
so two concurrent worktrees never `docker build` over each other's
image. The path used for hashing comes from `git rev-parse
--show-toplevel`; the resulting tag is memoized per process. Zero
per-session configuration required — running `cargo test` from
`/home/me/src/litebox-foo` automatically tags
`litebox-test:wt-abcd1234` and the dashboard supervisor in
`/home/me/src/litebox-ci` automatically tags `litebox-test:wt-7b0ab919`
without either knowing about the other.

Escape hatches:

| Env var                  | Effect |
|--------------------------|--------|
| `LITEBOX_IMAGE_TAG=<tag>`     | Force a single shared tag (e.g. CI bake jobs). Bypasses suffixing entirely. |
| `LITEBOX_WORKTREE_PATH=<path>` | Override the path hashed for the suffix. Useful when running outside a worktree, or to deliberately collapse two paths to one tag. |

All litebox-derived images carry `LABEL litebox=1` (set on the
`litebox-base` stage in `litebox_tool_executor/rootfs/Dockerfile`),
so scoped cleanup is:

```sh
docker image prune --filter label=litebox=1 --filter until=72h
```

This is the recommended periodic prune; it removes images from
retired worktrees without touching unrelated images on the same
Docker daemon. The `--target` argument to `docker build` always
uses the bare stage name (`litebox-test`, `litebox-agent-cli`) —
that's a Dockerfile-internal handle, not a tag.

**Opportunistic dashboard coverage for agent worktrees.** When the
`dashboard.py auto` supervisor is running, it scans `git worktree
list` each cycle and identifies any worktree that is NOT a
`tracked_refs.ci_worktree` as an "agent worktree." If such a
worktree has been idle for at least `LITEBOX_AGENT_IDLE_SECS`
(default 300s = 5min — no source-file mtime change AND no live
lease entry from that worktree), the supervisor spawns a short
`cargo test --fill=<LITEBOX_AGENT_FILL_BUDGET>s` cycle (default
180s) at that worktree's HEAD. To guarantee isolation from the
agent's own `target/` and `docker build`, the supervisor never
runs cargo inside the agent's worktree itself — instead it
maintains per-branch shadow worktrees at
`<state-dir>/shadows/<branch>/` (one per agent branch, branch name
encoded with `%2f` for `/`)
(shared canonical git object DB, separate working tree +
separate `target/` + separate per-worktree docker image tag) and
`git checkout --detach`s the agent's HEAD into it before each
cycle. Opportunistic runs land in `runs` with
`worktree_path=<state-dir>/shadows/<branch>` and the agent's
branch in
`runs.branch` — so they're trivially distinguishable from agent's
own runs by the literal shadow path (same self-evidence trick
the tracked-ref CI worktrees use). Aggregation still works: the
state key is `(commit_sha, dirty_hash, state_wt)` and `state_wt`
is NULL for clean rows regardless of worktree, so shadow + agent
clean runs at the same sha collapse to the same state and
combine cleanly. Results appear in the dashboard's new "Agent
worktrees" section, which compares the worktree's HEAD against
the tracked-ref baseline whose HEAD shares the most recent
merge-base (= the upstream this branch forked from). Two
columns per pass: Δ vs merge-base (the agent's own regressions)
and Δ vs baseline HEAD (drift vs current upstream). Set
`LITEBOX_AGENT_SIDECAR=1` to also write a focused
`<worktree>/.dashboard/regressions.md` after each successful
cycle for direct agent consumption. Disable entirely with
`--agent-coverage-disable` on the supervisor invocation.

When a coding session fans out to subagent worktrees, the
supervisor only drives the *tip set*: worktrees whose HEAD is
not already contained in some other worktree's HEAD as an
ancestor. So if subagent branches have been merged back into a
session branch, the supervisor drives the session branch and
skips the subagent worktrees (their content is already in the
session HEAD). If subagents have fresh work that hasn't been
merged yet, the subagents are tips and the (now-stale) session
worktree is skipped. Solo sessions and fully-independent
worktrees are always tips — no behavior change. Detection is
automatic with no env knob (intentional — knobs leak into agent
shell contexts). The render section marks tips with `→` and
subsumed rows with `~`. Per-branch shadows persist across
cycles so each branch keeps its own incremental `target/`; stale
shadows whose branch no longer exists in the canonical clone are
GC'd at the start of each scheduling cycle. When multiple tips
are eligible in the same supervisor tick, the orchestrator drives
up to `--max-parallel-agent-cargos N` (default `4`) in parallel —
each in its own per-branch shadow, CPU throttled automatically by
the harness lease table (`max(1, LITEBOX_GLOBAL_JOBS /
live_lease_count)`, so no cargo is ever starved). The tracked-ref
loop applies the same model via `--max-parallel-tracked-refs N`
(default `4`), since each tracked ref already has its own
`ci_worktree`.

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

The fix-subagent role — concrete single-test invocation, audit-log capture
command, gdbserver setup, and a crate ownership map (failure shape → likely
crate) — is documented separately in
[`FIX_AGENT_PLAYBOOK.md`](./FIX_AGENT_PLAYBOOK.md).

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
     (see [`FIX_AGENT_PLAYBOOK.md`](./FIX_AGENT_PLAYBOOK.md)). Group by
     `(dominant_syscall, dominant_errno, subsystem)` — most cascades fall out
     naturally.
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
  iteration tool. Use single-test runs (see
  [`FIX_AGENT_PLAYBOOK.md`](./FIX_AGENT_PLAYBOOK.md)) for inner loop.
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

## Agent Taxonomy

Tests run against an explicit tree of *agents* — the coordinator and
its descendants — set up by `coordinator/mod.rs::spawn_tree` from the
declarative spec list in `coordinator/agents.rs::default_tree()`.
Each agent is a separate `litebox_test_harness` process; tests
address them by handle (`AgentHandle`) and route commands through
the coordinator.

### Path-encoded names

Agent names embed both structural position and binary type at every
hop, using a 3-letter binary tag per segment:

```
{d|s} {p|n} {g|m}
 │     │     │
 │     │     └── Glibc / Musl libc
 │     └──────── Pie / Non-pie ELF
 └────────────── Dynamically linked / Statically linked
```

Singleton siblings of a given binary type drop the ordinal — so
`Dpg1Dng` is "the (sole) non-PIE-glibc child of `Dpg1`", whereas
`Dpg1Dpg1` and `Dpg1Dpg2` are two PIE-glibc children of `Dpg1`.

Reading a name reconstructs the entire path including binary types
at each hop. `Dpg1_Dng_Spm` = "PIE-glibc → non-PIE-glibc →
static-PIE-musl", which is exactly the VS Code "sshd → bash → cli"
transition.

### Canonical tree (15 structural agents + 6 vscode_shape agents)

The default tree is laid out to satisfy three orthogonal coverage
axes: (1) **fork-parent binary type** — every leg of the
`BinaryType` axis as a long-lived parent; (2) **VS-Code-shape
transitions** — the hot fork transitions seen in the real VS Code
Server strace; (3) **harness-side routing / sibling pairs** —
multi-hop forwarding and cross-subtree network tests.

| Agent | Position | Binary | What it covers |
|---|---|---|---|
| `Init` | Coordinator | — | The harness process itself. |
| `Dpg1` | Depth-1 root | PieGlibc | Default top-level agent — the canonical PIE-glibc fork parent. Most tests run on or fork from here. |
| `Dpg2` | Depth-1 sibling | PieGlibc | Sibling subtree for cross-subtree routing/network tests (e.g., `Dpg1` listens, `Dpg2` connects across worker boundaries). |
| `Dpg3` | Depth-1 disposable | PieGlibc | Subtree-kill (`SK.subtree.*`) target: tests `SIGKILL`s this entire subtree to verify reaping/cleanup. Marked `IsolationKind::DisposableSubtree` so the validator doesn't flag the disappearance. |
| `Dpg1Dpg1` | Depth-2 / `Dpg1` | PieGlibc | PIE-glibc depth-2. Exercises Forward-chain routing one hop deep and basic depth-2 fork inheritance. |
| `Dpg1Dpg2` | Depth-2 / `Dpg1` | PieGlibc | PIE-glibc depth-2 sibling — pairs with `Dpg1Dpg1` for sibling-at-depth-2 network/fd-passing tests. |
| `Dpg1Dpg1Dpg1` | Depth-3 / `Dpg1Dpg1` | PieGlibc | PIE-glibc depth-3. Mostly justified by harness-side routing (Forward chain through 3 hops); shim-side it adds nothing the audit didn't show was redundant. |
| `Dpg1Dpg1Dpg2` | Depth-3 / `Dpg1Dpg1` | PieGlibc | Sibling-at-depth-3 — pairs with `Dpg1Dpg1Dpg1` for cross-subtree-at-depth-3 routing tests. |
| `Dpg1Dng` | Depth-2 / `Dpg1` | NonPieGlibc | **Non-PIE-glibc as fork parent.** Spawned via `SpawnRemote`; exercises worker-host setup and the non-PIE syscall instrumentation regime. The agent matrix arrays (EXEC_AGENTS, NPIPE_AGENTS, etc.) all include this slot. |
| `Dpg1DngDpg` | Depth-3 / `Dpg1Dng` | PieGlibc | **PIE child of NonPie parent** — spawn-time tests the worker-host *teardown* / PIE re-establishment after a non-PIE intermediate. As a forking parent it's just PIE-glibc again, but the spawn pathway to set it up is unique. |
| `Dpg1DngDng` | Depth-3 / `Dpg1Dng` | NonPieGlibc | **bash → bash recursion** (the most common VS Code transition). Tests whether a second non-PIE fork from a non-PIE parent reuses or respawns the worker host. |
| `Dpg1DngSpm` | Depth-3 / `Dpg1Dng` | StaticPieMusl | **bash → cli** transition. Exercises `Command::Fork{binary=static-pie-musl}` from a non-PIE-glibc parent — the spawn pathway no other slot covers. |
| `Dpg1Spg` | Depth-2 / `Dpg1` | StaticPieGlibc | **Static-PIE-glibc as fork parent.** Even though static-PIE-glibc still loads `ld.so` for nss/dlopen, the parent-side syscall instrumentation differs from ordinary PIE-glibc and from static-PIE-musl. |
| `Dpg1Spm` | Depth-2 / `Dpg1` | StaticPieMusl | **Static-PIE-musl as fork parent** — the same binary form as VS Code's `cli` (`cli-alpine-x64`). Truly static, no `PT_INTERP`. Without this slot, only `VS.shape.smoke` exercised StaticPieMusl as a parent. |
| `Dpg1SpmDng` | Depth-3 / `Dpg1Spm` | NonPieGlibc | **cli → node** — the VS Code signature transition. Static-PIE-musl parent spawning a standard non-PIE-glibc Node.js child. Every fd Node.js needs (sockets, pipes, pty endpoints) flows through this exact transition in real VS Code Server use. |
| `Dpg1Snm` | Depth-2 / `Dpg1` | NonPieStaticMusl | **Non-PIE-static-musl as fork parent.** Combines fixed-load address constraint of non-PIE with the no-ld.so / variant-I-TLS regime of musl-static. Not exercised by any other slot. |
| `Dpg2Dpg` | Depth-2 / `Dpg2` | PieGlibc | Singleton PIE child of `Dpg2`, used by sibling-subtree tests that need a depth-2 endpoint under `Dpg2`. |
| `Dpg3Dpg` | Depth-2 / `Dpg3` | PieGlibc | Disposable subtree depth-2 — used by `SK.subtree.deep` to test reaping a deeper subtree. Inherits `DisposableSubtree` isolation from `Dpg3`. |

### VS Code-shape canary (`coordinator/vscode_shape.rs`)

Six **semantically named** agents that mirror the actual VS Code
Server process tree from the docker-vscode-native strace, in their
real positions and with their real binary types:

```
sshd_pty (PieGlibc, depth 1)
  └── login_bash (NonPieGlibc, depth 2)
        └── piped_sh (NonPieGlibc, depth 3, stdin = pipe)
              └── launcher_bash (NonPieGlibc, depth 4, sets up redirect)
                    └── cli (StaticPieMusl, depth 5)
                          └── node (NonPieGlibc, depth 6)
```

Used for tests like `BR.cli_startup_mimic.*` and `VS.shape.smoke`
that *are* the VS Code-shape scenario; everywhere else, prefer the
structural `Dpg*` taxonomy.

**Note on `node`:** the embedded Node.js binary in the VS Code
Server distribution
(`/root/.vscode-server/cli/servers/Stable-<commit>/server/node`) is
the standard linux-x64 build: `ET_EXEC`, dynamically linked,
`INTERP=/lib64/ld-linux-x86-64.so.2`. Confirmed via `readelf` plus
strace evidence (`access("/etc/ld.so.preload")` immediately after
`execve` returns). Even though Microsoft ships `cli-alpine-x64`
(static-musl) for the CLI entry point, the bundled Node is glibc.
Hence `node` is `NonPieGlibc`, not `StaticPieMusl`.

### Why no `NP` / `NPC` / `D3` / `D4` / `D5` / `A` / `B` / `AA`?

Earlier names like `NP`/`NPC`/`D3`/`D4`/`D5` predated the
`BinaryType` axis and conflated structural position with binary
type. Earlier still, `A`/`B`/`AA`/`AB` were structural-only but
needed to be paired with a separate binary-type field that wasn't
visible in the name. The path-encoded scheme replaces both: the
binary type is in the name (`Dpg1` = "Dynamic-Pie-Glibc, position
1") and reading a deep name reconstructs the whole transition
chain.

The depth-4/5 agents (`Dpg1_Dpg1_Dpg1_Dng` and
`Dpg1_Dpg1_Dpg1_Dng_Dpg`, formerly `D4`/`D5`) were **dropped**
after the worker-host audit confirmed grandparent independence in
the shim — no shim code path depends on what happened more than
one fork ago. Tests that previously used D4/D5 were migrated to the
depth-2/3 equivalents (`Dpg1Dng`/`Dpg1DngDpg`).

### Spec-driven `spawn_tree`

Each test family declares its required agents as a list of
`AgentSpec` records:

```rust
struct AgentSpec {
    name: AgentName,            // path-encoded label
    parent: Option<AgentName>,  // None for direct children of Init
    binary: AgentBinary,        // explicit per agent (Pie / NonPie / Static…)
    isolation: IsolationKind,   // Standard | DisposableSubtree
}
```

The coordinator walks the specs in topological order (parent before
child) and spawns each via `Command::Spawn` (PIE-glibc, the default),
`Command::SpawnRemote` (non-PIE-glibc), or `Command::Fork` with an
explicit binary label for the static-PIE / musl variants.

### Adding a new agent slot

Resist adding new slots without justification. Every slot fans out
across every test in `EXEC_AGENTS` / `NPIPE_AGENTS` / EP / US6 / P1
/ etc., so the cost is significant. Justify a new slot by either:
- **A real fork transition the tree doesn't already exercise** (was
  the case for `Dpg1DngDng`, `Dpg1DngSpm`, `Dpg1SpmDng` from the VS
  Code trace — and `Dpg1Spg`/`Dpg1Spm`/`Dpg1Snm` for static-leg fork
  parents).
- **A specific shim code path that branches on parent binary type
  and isn't covered.** Cite `litebox_shim_linux/src/...` lines.

If the slot is just "a deeper version of something we have", the
worker-host audit (below) almost certainly says no — re-read it
first.

### Adding a new test

1. Pick a structural agent that matches your test's process-tree
   shape. Don't reach for new agent names — use the existing
   structural taxonomy unless you have a justification per the
   prior section.
2. Pick the `BinaryType` axis: either a single fixed leg, or
   `BinaryType::ALL` if the test is binary-type-relevant. See the
   "Binary-Type Axis" section below.
3. Embed both in your test ID:
   `<family>.<scenario>.<binary-type>.<agent>` is the canonical
   ordering. The binary-type segment may be omitted only when the
   test does not exec a binary at all.

### Matrix arrays (where to fan out a new test)

For binary-type-sensitive tests, register against one of these
arrays so the test automatically fans out across the relevant
fork-parent slots:

| Array | Module | Slots | Use for |
|---|---|---|---|
| `EXEC_AGENTS` | `matrix.rs` | 11 | exec-style tests (EXITD, BR.exec_*, FWE, M, BS, …) — fans across PIE-glibc depth-1/2/3, non-PIE-glibc, static-leg parents, and the VS-Code-shape transition slots. |
| `NPIPE_AGENTS` | `pipe_bridge.rs` | 10 | pipe-bridge churn tests (npipe family). |
| EP agent loop | `epoll_pidfd.rs::register_epoll_socket_tests` | 11 | epoll/socket tests (EP.direct.*, EP.tokio.*) — has a per-agent port table to keep concurrent runs from colliding. |
| US6 / P1 fan-out | `special_cases.rs` | 11 | UDS socketpair (US6) and pipe-EOF-fork (P1) families. |
| `RAND_AGENTS` | `getrandom_tests.rs` | 4 | getrandom contract — covers glibc + musl libc-bootstrap differences. |
| `INO_AGENTS` | `inotify.rs` | 5 | inotify file-watcher tests. |
| `SCM_PAIRS` | `scm_rights.rs` | 7 | SCM_RIGHTS fd-passing — including cross-binary pairs (cli→node, bash→bash, bash→cli). |
| `SOCKOPT_AGENTS` | `sockopt.rs` | 6 | setsockopt/getsockopt tests — one slot per BinaryType leg. |

## Worker-Host / Fork-Restore State Transitions (audit, 2026-05-07)

A code-dive audit of `litebox_shim_linux/src/syscalls/process.rs` (and
related fork-restore / worker-host paths in
`litebox_platform_linux_userland`) answered the question: **does the
second consecutive fork in a chain depend on what the first fork did?**

**Verdict: independent. Depth-2 covers all transitions.**

No code path was found that consults grandparent ancestry or prior
fork-chain history when doing the next fork/exec handoff. Each
transition snapshots/restores the current task state only. The second
fork in a chain is driven by the immediate parent's live state, not by
what the first fork did.

| Lifecycle event | Trigger | State accumulated | Grandparent-dependent? |
|---|---|---|---|
| Worker-host spawn | True-fork (`process.rs:6444-6492`) and delayed-fork exec when `needs_remote` (`process.rs:9218-9276`) | New host PID in `fork_child_host_pids`, control-plane ownership, background waiter | **No** |
| Worker-host teardown | Child host exit (`process.rs:6288-6344`); exec path waits synchronously (`process.rs:8981-9015`) | Removes mappings, unregisters from control plane, reports to process registry | **No** |
| fd-bridge inheritance | Delayed-fork exec collects child pipes/sockets, builds `parent_*_replacements` (`process.rs:8698-8970`) | `vfork_info.fd_replacements`; direct stdio installed as `ExternalFd` | **No** |
| pidfd registration | `pidfd_open` for local targets only (`process.rs:1732-1775`); rejects remote-running | Plain fd in local table | **No** |
| Signal-mask propagation | True-fork snapshots blocked mask, handlers, altstack (`process.rs:6727-6740`); exec resets via `reset_for_exec()` (`process.rs:9362-9369`) | Snapshot of current task only | **No** |
| execveat / fork-restore handoff | Routed via `exec_on_remote_host` if `needs_remote` (`process.rs:9142-9165`) | Bridges + `reset_for_exec()` clears thread-local state | **No** |
| clone3 vfork | Same vfork parking / delayed-fork machinery as clone (`process.rs:1777-1885`) | Same `ForkContext` recording | **No** |

**Implication for the test matrix:** the canonical coverage pattern is
**depth-2 with `BinaryType::ALL` fan-out**. There is no need for a
hand-curated Tier-2 of depth-3 chains exercising "interacting"
transition pairs — none were found.

Depth-3+ chains that exist in the historical agent tree (`AAAA`/`AAAAA`
in the legacy taxonomy, `Dpg1Dpg1Dpg1Dng` / `Dpg1Dpg1Dpg1DngDpg` in
the path-encoded taxonomy) do not exercise distinct shim code paths
beyond the shallower equivalents (`Dpg1Dng` / `Dpg1DngDpg`) and have
been removed.

## Handler Model

The harness uses a **registered-handler dispatch model**. The wire
protocol (`litebox_test_harness/src/protocol.rs`) is intentionally
tiny — at HEAD it carries only:

- **Process lifecycle (framework-only)**: `Spawn`, `SpawnRemote`,
  `Fork`, `Forward`, `Exec`, `ExecReady`, `Exit`.
- **The dispatch envelope**: `Command::Run { handler, args }` +
  `Response::Result { ok, data, error }` (and
  `Response::Checkpoint { tag }` / `Command::Resume { tag }` for
  multi-agent rendezvous).

Everything else — fs I/O, sockets, eventfds, pty, signals, getrandom,
clone3, io_uring, … — is a handler. There is **no** `Command::FsRead`,
no `Command::NetListen`, no `Command::EventfdOpen`. If you find one
referenced anywhere, it's a bug (the variant was retired).

### Test code uses handlers — full stop

**The only agent-dispatch primitives that test code (every file in
`coordinator/` except `mod.rs`, `run_context.rs`, `registry.rs`,
`agents.rs`) may use are:**

- `RunContext::send_named_typed(&handle, &TOKEN, args)` — typed
  one-round-trip handler call.
- `RunContext::rendezvous_pair(...)` — multi-agent rendezvous with
  per-side handlers and `ctx.checkpoint(tag)`.
- `Registry::single_agent_handler_test(...)` — convenience wrapper
  for the single-agent multi-step pattern.

`RunContext::send` and `Runner::send` (the untyped raw wire-dispatch
methods) are marked **framework-only** in their doc comments. Calling
them from a coordinator/<family>.rs file other than the four
framework files listed above is a layering violation and a sign the
test should be a handler.

The `Command` enum and the `agent_loop` match in `agent.rs` are
**closed** to test additions:

> When you would otherwise be tempted to add a `Command::PtyTiocgpgrp`,
> a `Command::Clone3 { kind: ... }`, a `Command::IoUringSetup`, or a
> new `agent_loop` match arm — write a handler.

### Authoring a handler

In `coordinator/<family>.rs`:

```rust
use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

#[derive(serde::Serialize, serde::Deserialize)]
struct MyArgs { /* fields */ }

#[derive(serde::Serialize, serde::Deserialize)]
struct MyOut { /* fields */ }

const MY: HandlerToken<MyArgs, MyOut> = HandlerToken::new("family.my");

async fn handle_my(args: MyArgs, ctx: &mut HandlerCtx<'_>) -> Result<MyOut, HandlerError> {
    // Run on the agent. Do raw libc / std::fs / std::process / crate::os::* here.
    // For multi-agent rendezvous: ctx.checkpoint("tag").await blocks the
    // handler until the coordinator sends Command::Resume { tag }.
    Ok(MyOut { /* … */ })
}

pub(crate) fn register_my(reg: &mut Registry<'_>) {
    register_handler!(MY, handle_my);
    reg.test("suite", "group", "MY.case_id")
        .timeout(60)
        .build(|cx| {
            let h = cx.require(AgentName::Dpg1);
            Box::new(move |run| Box::pin(async move {
                let out = run.send_named_typed(&h, &MY, MyArgs { /* … */ }).await;
                // assert on `out`, return super::TestOutcome
            }))
        });
}
```

### Multi-agent rendezvous

Use `RunContext::rendezvous_pair` (or the lower-level `run_multi`)
when two agents must coordinate via a shared resource (fd, file,
socket). Each side runs its own handler; checkpoints synchronize them.
See `coordinator/inotify.rs` and `coordinator/scm_rights.rs`.

**Same-pipe rendezvous gotcha**: two handlers running on agents that
share a single bidirectional pipe to the coordinator cannot make
progress concurrently — stage them sequentially. Handlers on agents
with independent pipes (the common case) can run concurrently.

### Single-agent multi-step tests

Use `Registry::single_agent_handler_test` (see `coordinator/sockopt.rs`
or `coordinator/iouring_discovery.rs`) — one helper covers
register-token + drive-test for the "agent runs a handler, coordinator
asserts on the result" pattern.

### `crate::os::*` wrappers

When a handler needs idiomatic Rust over a libc-shaped primitive,
prefer reusing or extending `crate::os::*`:

| Module | Wraps |
|---|---|
| `os::socket` | TCP sockets (bind/listen/connect/send/recv/shutdown). |
| `os::unix_socket` | Unix domain sockets incl. `sendmsg`/`recvmsg` + SCM_RIGHTS. |
| `os::inotify`, `os::eventfd`, `os::epoll`, `os::pty` | The obvious primitives. |

### Shared bash / exec handlers

For tests that just need to "run a child process on this agent and
check stdout/exit_code", reuse the shared tokens in
`coordinator/common.rs`:

- `common::BASH` — `bash -c "<cmd>"`, returns `{stdout, stderr,
  exit_code, timed_out}`. Use when the test is a bash one-liner.
- `common::EXEC_BIN` — arbitrary `argv[0..]` with optional
  `timeout_ms` / `stdin` / `env`, same output struct. Use for
  invoking specific binaries (test self-exe with subcommand, node,
  etc.).

Both run via `tokio::process::Command` inside the handler. **Prefer
these** over inventing per-family bash-runner handlers.

### When you genuinely need a new wire primitive

The Command enum is "closed to test variants", not "closed forever".
New primitives are acceptable only when:

1. They are genuinely a process-lifecycle / agent-tree primitive
   (think `Spawn`, `Fork`, `Forward`) — i.e., the framework itself
   needs it, not one test family.
2. It cannot be expressed by composing existing primitives + a
   handler.
3. You add the corresponding agent-side execution in `agent_loop`
   and an idiomatic `crate::os::*` wrapper where appropriate, plus
   doc-comments on `RunContext::send` / `Runner::send` if it widens
   the framework-only surface.

If a handler would suffice, write the handler.

### Two surfaces for test-side code: handler + (rarely) argv subcommand

**Handler is the default for test logic.** Most tests now use the
`run.run_leaf(&leaf, &TOKEN, args)` pattern to spawn an ephemeral
leaf agent of a chosen binary type (`SpawnKind::Fork{binary=bt, …}`)
and invoke a registered handler on it. The handler body lives in
`coordinator/<family>.rs` alongside the test that drives it, and the
fork+exec round-trip across binary types is exercised by
`Command::Fork{binary}` exactly as it was when the leaf was an argv
subcommand.

**Argv subcommands are an escape hatch** for the small set of leaf
programs that cannot be handlers because the test specifically needs
*fresh-process* semantics that an agent cannot model:

- PTY tests: the child's stdin must BE a PTY slave (set up by the
  parent via `openpty` + `dup2` before `execve`); an agent's stdin
  is its protocol pipe.
- Stdio-inheritance tests: the test verifies bytes flow through
  `fork+exec` stdio in a specific way (e.g., capture-pipe, the
  M1-M4/BS1-BS3 minimal canaries); the agent owns those pipes.
- Long-running probes (`wait-forever`): would jam an agent loop.
- Bash-child invocations: a leaf invoked by `bash -c "{exe} subcmd"`
  inside a `common::BASH` pipeline runs as a non-protocol child by
  definition; the parent of that exec is bash, not an agent.

These leaves live in `mod leaf_subcmd` blocks inside the family file,
each with a doc-comment naming **why** this leaf cannot be a handler.
They are registered via `register_leaf_subcommand!("name", fn)` from
the family's `register_*(reg)` function and dispatched at process
entry by `coordinator::leaf_subcommand::dispatch`. `main.rs` is
purely a router: 3 dispatcher arms (`spawn-tree`, `agent`,
`agent-listen`) + a one-line registry lookup + a catch-all error.

#### Topical layout (post-Wave-9)

Tests are organized by *subject*, not by historical bug-fix arc.
Each `coordinator/<topic>.rs` hosts one or more related test-prefix
families:

| Topic file                              | Hosted test prefixes                          |
|-----------------------------------------|-----------------------------------------------|
| `concurrent_fork.rs`                    | `CF.*`, `CC.*`                                |
| `epoll_pidfd.rs`                        | `EPI.*`, `EP.*`, `POLL.*`                     |
| `fork_matrix.rs`                        | `X*`, `BSF`, `PIF`, `SXF`, `BASH.*`, `FWE.*`, `SK.*` |
| `pipe_bridge.rs`                        | `PB.*`, `PN.*`, `PID.*`, `NPIPE.*`, `BPIPE.*` |
| `tcp_state.rs`                          | `TCS.*`, `THC.*`, `TLB.*`, `XCONN.*`, `FKLC.*` |
| `vscode_shape.rs`                       | `VS.*`, `CSM.*`                               |
| `sockopt.rs`                            | `SOCKOPT.*`, `GSN.*`                          |
| `shell.rs` *(new)*                      | `SP.*`, `SC.*`, `TR.*`, `FR.*`, `BR.*`, `BRS.*` |
| `special_cases/exit.rs`                 | exit semantics, `EXITD.*`                     |
| `special_cases/fs.rs`                   | filesystem misc, `CWF.*`                      |
| `special_cases/proc.rs` *(new)*         | `/proc` reads, `PROC.*`, `KP.*`, `KPX.*`, `proc-probe` / `check-ppid` leaf subcmds |
| `common.rs`                             | shared handlers, `CANARY_AGENTS`, `DetailOut`, `fork_binary_label`, minimal_canary (M*/BS*) |

#### Authoring a new test

1. Pick the family that owns the behaviour (existing
   `coordinator/<family>.rs`).
2. Default to a handler: `register_handler!(TOKEN, fn)`; drive it
   via `run.send_named_typed(handle, &TOKEN, args)` (single agent),
   `run.rendezvous_pair(...)` (multi-agent), or
   `run.run_leaf(&leaf, &TOKEN, args)` (ephemeral leaf agent of a
   chosen binary type).
3. Only if the test specifically requires fresh-process semantics
   from the categories above, write an argv leaf instead. Use
   `register_leaf_subcommand!("name", fn)` and add a doc-comment
   explaining why.



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

2. **Test-specific behavior lives in handlers, not in new `Command::*`
   variants.** The `Command` enum (`litebox_test_harness/src/protocol.rs`)
   is **closed to test-specific additions**. It carries only generic
   wire primitives (process lifecycle, fs I/O, socket I/O, fd-passing,
   the `Run { handler, args }` dispatch envelope) — everything
   test-specific is a registered handler.

   For a new test:
   - Define a typed `HandlerToken<Args, Out>` in your family file
     (`coordinator/<family>.rs`).
   - Implement the handler as a plain `async fn(args, ctx) -> Result<Out, _>`.
   - Register it with `register_handler!(TOKEN, fn)`.
   - Drive the test with `run.send_named_typed(handle, &TOKEN, args)` or
     (for multi-agent rendezvous) `run.rendezvous_pair`.

   See `coordinator/inotify.rs` / `eventfd.rs` / `tcp_state.rs` /
   `clone3_matrix.rs` for reference patterns. Bash is justified only when
   testing bash-specific fork behavior (the `concurrent_fork.rs::BASH`
   handler is the standard runner for those cases). If you find yourself
   reaching for a new `Command::Foo` variant or a new `agent_loop` match
   arm, write a handler instead.

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

## Binary-Type Axis

litebox's syscall shim and worker-migration logic dispatch differently
based on the *kind* of ELF binary being `execve`'d. The harness models
this as a five-leg `BinaryType` axis (`litebox_test_harness::BinaryType`):

| Variant | ELF type | Linker | Libc | PIE? | Build flags |
|---|---|---|---|---|---|
| `PieGlibc` | `ET_DYN` | dynamic | glibc | yes | (default `cargo build`) |
| `NonPieGlibc` | `ET_EXEC` | dynamic | glibc | no | `-C link-args=-no-pie` |
| `StaticPieGlibc` | `ET_DYN` | static-ish (still uses ld.so for nss) | glibc | yes | `RUSTFLAGS="-C target-feature=+crt-static" --target x86_64-unknown-linux-gnu` |
| `StaticPieMusl` | `ET_DYN` | truly static (no ld.so) | musl | yes | `RUSTFLAGS="-C target-feature=+crt-static" --target x86_64-unknown-linux-musl` |
| `NonPieStaticMusl` | `ET_EXEC` | truly static, fixed-addr | musl | no | `RUSTFLAGS="-C link-args=-no-pie -C target-feature=+crt-static -C relocation-model=static" --target x86_64-unknown-linux-musl` |

`StaticPieMusl` matches the actual VS Code Server CLI distribution
(`cli-alpine-x64`).

### Iterating the axis in tests

Use `BinaryType::ALL` to fan out a test over every leg, and resolve
the actual binary path via `crate::binary_path(bt, &self_exe)`:

```rust
for &bt in crate::BinaryType::ALL {
    let label = bt.label();   // "pie-glibc" | "nonpie-glibc" | …
    let bin = crate::binary_path(bt, &self_exe);
    // … run the test with `bin` …
}
```

`label()` returns a stable kebab-case string suitable for embedding in
test IDs (e.g. `EXITD.256.static-pie-musl.A`).

### Strict-mode invariant: every leg must be present

`binary_path()` and the per-leg accessors (`nonpie_binary()`,
`static_pie_glibc_binary()`, `static_pie_musl_binary()`,
`non_pie_static_musl_binary()`) **panic** when the requested binary
isn't present at the expected docker mount or as a sibling of the
current exe. The panic message includes the exact build command
needed to produce the missing binary.

There is no skip semantics. Tests that require a binary type whose
build was skipped will fail loudly — by design. The integration test
runner (`tests/integration.rs::ensure_binaries_built`) builds all five
binaries unconditionally and asserts each exists at the end of
`setup()`.

The musl legs require `rustup target add x86_64-unknown-linux-musl`.
The integration runner's `ensure_rust_target` helper checks for it
and fails fast with the install command if missing.

### Backwards-compat for existing test IDs

Test families that already had a narrower binary axis (EXITD, FWE, M,
BS, NPIPE, FR.bg_exe) keep their original IDs as aliases for whichever
leg the legacy code used. New legs append the kebab-case binary label
as an additional ID segment. Examples:

- `EXITD.256.pie.A` and `EXITD.256.nonpie.A` (legacy 4-segment) are
  preserved; new IDs use the BinaryType label
  (`EXITD.256.static-pie-musl.A`).
- `FWE.pie_from_init`, `FWE.nonpie_from_init` are preserved; new legs
  are `FWE.static-pie-musl_from_init` etc.
- `FR.bg_exe.<agent>` is preserved (= PieGlibc); new legs add a binary
  segment (`FR.bg_exe.static-pie-musl.<agent>`).
- `NPIPE.*` IDs are preserved unchanged (= NonPieGlibc); the new
  `BPIPE.<leg>.*` IDs cover the four other legs.

### Adding the axis to a new family

Pattern:

1. Identify whether the test exercises an external binary path (via
   `{exe}` substitution, `Command::new()`, `posix_spawn`, etc.). If
   not, the axis isn't applicable.
2. Wrap the test loop with `for &bt in crate::BinaryType::ALL`.
3. Resolve the path with `crate::binary_path(bt, &self_exe)`.
4. Embed `bt.label()` in the test ID for unique IDs across legs.
5. If preserving legacy IDs, alias one leg (typically `PieGlibc` or
   `NonPieGlibc`) to the original 3-segment ID and append `.<label>`
   for the others.

## What NOT to Do

- Do NOT introduce any "expected fail" mechanism — no `xfail` /
  `XPASS` outcomes, no allowlists of known-failing tests, no dynamic
  skip paths. Outcomes are `pass` or `FAIL`, period. **Enforced by
  `tests/no_expected_fail.rs`**: a build-time scan of
  `litebox_test_harness/src/` and `tests/` that fails the suite if
  any forbidden token (`expected_fail`, `XFAIL`, `XPASS`,
  `known_fail`) appears outside the enforcement file itself.
  This catches a subagent or human who reintroduces the mechanism
  before the change can be merged.
- Do NOT edit this `CLAUDE.md` to relax or contradict the
  "no expected fail" rule. If a subagent claims to have added a
  "known failures" section, that's a regression — revert it.
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

# Multiple disjoint filters in one invocation (OR'd, like stock libtest).
# Prefer this over a bash for-loop: one process means one amortized
# setup() and a single LITEBOX_TEST_JOBS pool spanning all prefixes,
# so the tail of one filter overlaps with the head of the next.
cargo test -p litebox_test_harness --test integration -- \
  'litebox::PB' 'litebox::PXEOF' 'litebox::EPIPE' 'litebox::PXP'
```

Don't run multiple `cargo test` invocations against the same target
dir simultaneously — the build cache will thrash.

The harness uses `libtest_mimic` (custom `harness = false`) and registers
two trials per test ID: `native::<id>` and `litebox::<id>`. Each trial
spawns its own `docker run` with `--filter=<test_id>` so every test
gets a fresh `litebox_tool_executor` + broker + runner + agent
matrix. Tests cannot contaminate each other.

#### Why not `cargo nextest`

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

#### Tuning knobs

| Env var                      | Default                       | Effect                                                          |
|------------------------------|-------------------------------|-----------------------------------------------------------------|
| `LITEBOX_TEST_JOBS`          | `min(LITEBOX_GLOBAL_JOBS, 20)`| Per-process upper bound on concurrent `docker run` invocations. **Do not set this to an arbitrary number** (e.g. `1`, `4`, `$(nproc)`). The default is derived from the host-wide budget clamped at `20` (the dockerd-serialization safety ceiling), and the lease coordinator (`tests/common/lease.rs`) further divides that budget fairly across all live `cargo test` runners on the box. Agents that set `LITEBOX_TEST_JOBS=4` are self-throttling below their fair share; agents that set `LITEBOX_TEST_JOBS=$(nproc)` are no-ops (the lease still clamps them). The harness prints a `[integration] advisory: …` line at startup whenever an explicit `LITEBOX_TEST_JOBS` differs from the lease share. Only set this for single-runner stress tests when no other harnesses are live on the host. |
| `LITEBOX_GLOBAL_JOBS`        | `(num_cpus * 2) / 3`          | Host-wide budget the lease coordinator divides across live harnesses. **This is the canonical knob** — `LITEBOX_TEST_JOBS`'s default is derived from it. Override only if you've measured docker-daemon contention on this specific host. |
| `LITEBOX_DRAIN_BACKLOG`      | `4 * LITEBOX_TEST_JOBS`       | Max in-flight post-result drain threads.                        |
| `LITEBOX_TEST_MEMORY`        | `8g`                          | Per-container `--memory` and `--memory-swap` (safety bound — OOM-kill on excess; no swap thrash). |
| `LITEBOX_TEST_PIDS`          | `8192`                        | Per-container `--pids-limit` (safety bound).                    |
| `LITEBOX_TEST_CPUS`          | (unset → no CPU cap)          | Per-container `--cpus` (opt-in only — capping CPU often regresses fork-heavy tests). |
| `LITEBOX_DRAIN_TIMEOUT_SECS` | `30`                          | Watchdog timeout on the post-result drain phase.                |
| `LITEBOX_FORCE_FULL_MATRIX`  | unset                         | When set, always spawn the non-PIE subtree even if the filter doesn't reference NP/NPC/D3/D4/D5. |
| `LITEBOX_KEEP_CONTAINER`     | unset                         | Don't pass `--rm`; containers stay around for `docker logs`. Each is `--name`d as `litebox-<pass>-<id>-<pid>-<ns>`. |
| `LITEBOX_NO_AUDIT`           | unset                         | Disable audit logging in the runner.                            |

The litebox-pass outer timeout (`timeout --signal=KILL <N>`) is
per-test, derived from the harness's `.timeout(N)` setting + 15 s
grace, so failing fast-tests fail in (their budget) + 15 s rather
than the previous blanket 120 s.

**Per-Trial logs**: each trial's docker stdout/stderr is written
to `target/test-logs/<pass>-<sanitized_id>.{stdout,stderr}.log`
(stderr via `Stdio::from(File::create(...))`, stdout tee'd as we
parse for the JSON result line). On Trial failure, the `Err`
message includes both log paths.

#### Per-test timing telemetry

Per-test results land in
**`<main-worktree>/.dashboard/results.sqlite`** — the central
dashboard store, populated **directly** by the integration test
binary on every `cargo test --test integration` run.

The store is on by default. The path is resolved via
`dirname(git rev-parse --git-common-dir)`, so any linked worktree
writes to the main worktree's store. Override with
`LITEBOX_DASHBOARD_DIR=<abs path>`; opt out with
`LITEBOX_DASHBOARD_DIR=""`. See
[`scripts/README.md`](scripts/README.md) for the (deliberately
minimal) schema, `dashboard.py` subcommands, and agent recipes.

**Selective re-run via `--fill[=N]`**: the runner picks up to N
trials prioritized by a two-class selector at the current `commit_sha`:

- **Class 1 (uncovered):** no result yet at this sha. Round-robin by
  suite, never-seen first then stalest by `latest_results.finished_ts_ms`.
- **Class 2 (failed-at-sha, retry-capped):** freshest verdict at this
  sha is fail/timeout/error and `attempts < LITEBOX_FILL_FAIL_RETRIES`
  (default `3`). Stalest-first within sha. Beyond the cap, the test is
  considered confirmed-failing and is skipped until the sha changes.

Passing-at-sha trials are skipped (a clean-sha pass is assumed stable
until the sha moves). Default N is 300 (sized to amortize `setup()`).
Used by `dashboard.py auto` to autonomously fill coverage of tracked
refs. See [`scripts/README.md`](scripts/README.md) for the full driver
contract and tuning knobs.

```sh
# run only the missing-at-HEAD trials, default batch size 300
cargo test -p litebox_test_harness --test integration -- --fill
# explicit batch size
cargo test -p litebox_test_harness --test integration -- --fill=50
```

`litebox_test_harness/scripts/analyze-test-timing.py` summarizes a
single run or diffs two runs (e.g., before/after a perf change),
querying `run_results` directly.

The file also keeps the backward-compatible `t_docker_start_ms`
field and splits it using stable stderr markers of the form
`[TIMING] <name>=<CLOCK_MONOTONIC ns>`:
`container_pid1_started_ns`, `litebox_shim_ready_ns`, and
`harness_first_output_ns`. The split fields are `t_docker_spawn_ms`,
`t_litebox_init_ms`, and `t_harness_load_ms`. Native trials have
no litebox shim, so the parser treats `litebox_shim_ready_ns` as
equal to `container_pid1_started_ns` and reports
`t_litebox_init_ms=0`. Docker containers share the host kernel
clock, so the host-side markers are comparable to the wrapper's
`docker_run_invoke_ns`; this assumes the normal single-kernel
Docker/WSL2 model. In litebox trials, the guest harness's own
`clock_gettime` is virtualized, so the wrapper uses host
`CLOCK_MONOTONIC` at stderr marker arrival for the
`harness_first_output_ns` boundary.

#### Debugging a specific failing test

The harness supports `LITEBOX_HARNESS_PAUSE` "soft breakpoints" — at
the matching site the process `raise(SIGSTOP)`s itself and waits for
`SIGCONT`. This is more reliable than gdb breakpoints under litebox's
multi-process protocol (which can deadlock when one inferior stops).
Pair with `litebox_tool_executor --debug PORT` (gdbserver) and
`dev_tools/gdb-connect-batch.sh` for a non-interactive, transcript-
based debugging round-trip. See `FIX_AGENT_PLAYBOOK.md` "gdbserver
via `--debug`" and `dev_tools/gdb-example-session.md` for the full
pattern.

```bash
# Pause the harness before a single failing test runs:
LITEBOX_HARNESS_PAUSE='harness:test-start=PB.c2p.nonpie-glibc.dpg2' \
  cargo test -p litebox_test_harness --test integration \
  -- 'litebox::PB.c2p.nonpie-glibc.dpg2' --exact
```

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

#### Keeping the container for post-mortem

Set **`LITEBOX_KEEP_CONTAINER=1`** to suppress all framework-side
`docker rm`s so the container stays around after the trial finishes,
fails, or times out — for `docker exec`, log scraping, or
`litebox_tool_executor`-side audit-log inspection. Honored in all
four cleanup paths: the foreground reap, the detached
`tear_down_detached`, the SIGTERM/INT signal handler, and the
`spawn_drain` watchdog. Containers spawn without `--rm`; you remove
them manually when done (`docker rm -f $(docker ps -aq --filter
name=litebox-)`).

#### Analyzing audit logs

For quick checks, `grep` on the JSONL file is fine (e.g., `grep '"err"' audit.jsonl`).

For deeper analysis — finding needle-in-the-haystack errors,
measuring syscall latency distributions, or tracing cross-thread
interactions — use `litebox_audit_query` to import the log into
SQLite. This pre-joins enter/exit events and lets you run ad-hoc
SQL queries (950× faster than grep for indexed lookups on large
logs).

```bash
# Import and query in one step
litebox_audit_query sql --file /path/to/audit.jsonl \
  "SELECT syscall, result_err, COUNT(*) AS cnt FROM syscalls WHERE result_err IS NOT NULL GROUP BY syscall, result_err ORDER BY cnt DESC"

# See the full schema and example queries
litebox_audit_query schema
```

Key columns: `syscall`, `args` (JSON), `duration_ns`, `result_ok`,
`result_err` (negated errno), `worker` (host PID), `pid`/`tid`
(guest). See `schema` output for the complete reference and 10+
ready-to-use queries.

**Lazy agent matrix**: the harness spawn_tree only spawns the
non-PIE subtree (NP, NPC, D3, D4, D5) when at least one filtered
test ID contains those agent names as a dot-separated component.
~97 % of tests are PIE-only and skip the 30 s
`spawn_nonpie_subtree` setup. End-of-run validation
(`validate_lazy_matrix` in `coordinator/mod.rs`) records a
synthetic `__lazy_matrix.validation` FAIL if any agent contacted
via `TestRunner::send` was not actually spawned, so a
heuristic miss is loudly visible.

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

### Dashboard schema coordination

`.dashboard/results.sqlite` is shared across **all** worktrees of the
clone (path resolved via `git rev-parse --git-common-dir`). The Rust
producer (`tests/common/dashboard_store.rs`) and the Python consumer
(`scripts/dashboard.py`) both pin a `SCHEMA_VERSION` constant and
**panic on mismatch**. Any session running `cargo test --test
integration` with an out-of-date binary will abort until rebuilt.

**Do not bump `SCHEMA_VERSION` without explicit coordination across
active sessions.** Bumps are warranted only for breaking changes
(column removed, type changed, column added without a default).
Additive schema with defaults, new indexes, and renderer-only
changes do **not** require a bump — see the `harness_leases` table
in `scripts/README.md` for the canonical "additive, no bump"
precedent.

## fd Inheritance Pattern

The VS Code CLI hands a listen socket to a child process via fork+exec:

```
parent: bind()+listen() → clear CLOEXEC → fork()+exec(child) → close(fd)
child:  accept() on inherited fd → echo data
```

This pattern is expressed through the agent protocol with
`Fork { inherit_listen_ports: [...] }`: the parent duplicates requested
listen sockets into the documented child fd slots and the child imports
them into its listener registry before serving commands. Add new tests
against that protocol path rather than reintroducing standalone helper
subcommands.

## Copilot CLI integration scenarios

A separate suite of integration trials exercises **GitHub Copilot CLI
running inside a litebox sandbox over SSH**, in both non-interactive
(`copilot -p`) and interactive TUI modes. Used by sessions doing
TDD-style validation of shim improvements that affect agent CLI
workflows.

**Trial namespace:** `copilot::pminus.<scenario>` (non-interactive)
and `copilot::tui.<scenario>` (interactive). Each registers as
`native::<full_id>` and `litebox::<full_id>`. 6 scenarios × 2 modes
× 2 passes = 24 trials.

**Invocation:**

```bash
# Single scenario:
cargo test -p litebox_test_harness --test integration -- \
  'native::copilot::pminus.simple_math' --exact

# All non-interactive (`-p`) scenarios, both passes:
cargo test -p litebox_test_harness --test integration -- \
  'copilot::pminus'

# Full Copilot suite (defaults to LITEBOX_COPILOT_JOBS=1 — serial,
# safest for API quota / model-output stability):
cargo test -p litebox_test_harness --test integration -- \
  'copilot::'

# Full Copilot suite without an explicit positional filter (now the
# default — copilot trials register unconditionally):
cargo test -p litebox_test_harness --test integration

# One-shot validation: trade GitHub API quota for wall time by
# raising the cap. ~4 is a reasonable starting point; cargo's own
# `--test-threads` still bounds the worker pool.
LITEBOX_COPILOT_JOBS=4 \
  cargo test -p litebox_test_harness --test integration -- \
  'copilot::'
```

**Token requirement (graceful per-trial fail):** the trials need a
GitHub Copilot API token. Discovery order:
`COPILOT_GITHUB_TOKEN` → `GH_TOKEN` → `gh auth token`. If none
resolve, each copilot trial fails individually with a remediation
message (and incurs no docker-build / fixture-creation cost — the
token check is the first thing `run_scenario` does). Tokens never
appear in any host-visible argv (passed into the container via a
0600 bind-mounted env file that the remote shell sources before
exec'ing copilot).

**Concurrency cap:** `LITEBOX_COPILOT_JOBS` (default `1`),
independent of `LITEBOX_TEST_JOBS`. The serial default protects
shared CI / autonomous-driver runs from GitHub API throttling and
reduces model-output flakiness — but **do not copy
`LITEBOX_COPILOT_JOBS=1` into one-shot validation runs**. For a
single agent session that just wants the suite to finish quickly,
raise the cap (e.g. `LITEBOX_COPILOT_JOBS=4`) and burn parallel
API quota; nothing in-tree forces serialization. The autonomous
driver and shared dashboard supervisor leave the default alone on
purpose.

**Registration is unconditional** — copilot trials are always part
of the trial set so the dashboard universe stays consistent and
the autonomous `--fill` selector picks them up like any other
`<pass>::<id>` trial. Token-less environments see 24 graceful
per-trial failures (6 scenarios × 2 modes × 2 passes) instead of
silently-missing universe entries. The previous
`LITEBOX_INCLUDE_COPILOT=1` env-var gate was removed.

**Native is the gold standard.** Every scenario must pass under
the native baseline; any native failure is a test bug, not a shim
bug.

**Today's litebox state on `wportnoy/vscode-server-in-litebox` HEAD**:
all 6 litebox-pass `pminus` scenarios fail (empty responses from
the Copilot CLI subprocess). This is broader than the historical
bash-output-read-hang and currently looks like a Copilot-CLI /
Node-under-litebox runtime issue. The trials are the diagnostic:
when the shim regression is fixed, individual scenarios will
start passing and the suite will show progress one scenario at a
time.

**Driver internals.** The host side reuses the existing PTY
primitive (`litebox_test_harness::os::pty::Pty`) — `Pty::open()`
+ `fork_exec(ssh_argv, ctrl_tty=true)` — exactly the pattern used
by `coordinator/pty.rs` tests. SSH connects to the dropbear
running inside the container (litebox pass) or directly under
docker (native pass). The remote command is shell-quoted and runs
through `sh -c`, which sources the token env file before exec'ing
copilot.

**Scenarios** (same workloads in both modes):

| Scenario      | Prompt strategy                                                                 |
|---------------|---------------------------------------------------------------------------------|
| `simple_math` | "What is 2+2? Reply with just the number." (answer check)                        |
| `simple_bash` | "Run `echo <canary>` and tell me what it printed." (canary-in-output check)      |
| `read_file`   | "Run `cat /workspace/canary.txt` and tell me the contents." (canary in fixture)  |
| `pipeline_wc` | "Run `wc -c /workspace/{a,b}.txt` and tell me which is bigger."                  |
| `find_head`   | "Run `find /workspace -name '*.txt' \| head -5` and list what you find."         |
| `build`       | "Run `CARGO_TARGET_DIR=/tmp/c cargo build -p litebox_timing` ..."                |

Per-trial transcripts land at
`target/test-logs/copilot-<pass>-<mode>-<scenario>.{raw,stripped,prompt}`
for forensics.

**Files involved:**
- `litebox_tool_executor/rootfs/Dockerfile` — `litebox-agent-cli` stage.
- `litebox_test_harness/tests/integration.rs` — `mod copilot` and
  conditional registration in `main()`.

**Out of scope (deferred):** sandbox policy / allow / deny
coverage. The agent-sandbox-demo branch
(`experiments/agent-sandbox-demo/`) retains the interactive
hand-driven demo with policy enforcement; this suite is the
automated companion for repeatable validation.

## VS Code Server integration scenarios

A parallel suite of integration trials exercises **VS Code
Remote Server running inside a litebox sandbox over SSH**, in
the production-shaped configuration: dropbear-in-container,
host-side driven over SSH-via-PTY. These trials are the
end-to-end validation layer that `docs/product-goal-map.md`
identifies as Goal B's remaining gap after every capability
node already flipped to ✅.

**Trial namespace:** `vscode::<scenario>`. Each registers as
`native::vscode::<scenario>` and `litebox::vscode::<scenario>`.
5 scenarios × 2 passes = 10 trials.

| Scenario              | What it exercises                                                                                            |
|-----------------------|--------------------------------------------------------------------------------------------------------------|
| `bootstrap`           | The **exact** VS Code Remote-SSH bootstrap payload — `vscode-bootstrap-captured.sh` patched at runtime with the image's CLI commit hash, piped through `ssh sh -s`. Validates `: start` / `: end` / `listeningOn==` / `Found existing installation` markers. |
| `server_listen`       | Invokes `code command-shell --on-host=127.0.0.1 --on-port=0 --parent-process-id 1` directly (no bootstrap-script wrapping). Polls its log for `Listening on N.N.N.N:PORT`, emits `VSL_PORT=` marker. Narrower diagnostic surface than `bootstrap` — points at the CLI startup path itself. |
| `connect_loopback`    | Same SSH session as `server_listen`, plus a TCP 3-way handshake to the captured port via bash's `/dev/tcp/127.0.0.1/$PORT`. Validates loopback TCP delivery inside the sandbox. |
| `connect_cross_ssh`   | Two independent SSH sessions: session A starts the CLI and emits the captured port; session B (separate dropbear → bash worker tree) does the connect. Mirrors the VS Code Remote-SSH SOCKS-proxy pattern; under litebox exercises broker cross-worker loopback TCP. |
| `extension_host_steady` | Replays the captured bootstrap, starts the production `code-server --start-server --socket-path=/tmp/code-*.sock` invocation, opens a Remote-SSH-shaped WebSocket to the Unix socket from a fresh SSH session, and asserts the connection stays alive for 60 s. |

**No token required** — VS Code's `--connection-token` is
locally-generated and never validated externally. (Unlike
`mod copilot`, which calls the GitHub Copilot API and gates
each trial on `gh auth token` / `COPILOT_GITHUB_TOKEN`.)

**Invocation:**

```bash
# Single scenario:
cargo test -p litebox_test_harness --test integration -- \
  'native::vscode::bootstrap' --exact

# All native vscode scenarios:
cargo test -p litebox_test_harness --test integration -- 'native::vscode::'

# Full VS Code suite (defaults to LITEBOX_VSCODE_JOBS=1 — serial,
# safest for shared / autonomous-driver runs):
cargo test -p litebox_test_harness --test integration -- 'vscode::'

# Same suite, parallelized:
LITEBOX_VSCODE_JOBS=4 \
  cargo test -p litebox_test_harness --test integration -- 'vscode::'
```

**Image-stage selection (`LITEBOX_VSCODE_IMAGE_STAGE`):**

| Value (default = unset) | Stage used                  | When to use |
|-------------------------|-----------------------------|-------------|
| unset / anything else   | `litebox-vscode`            | Default — runtime ELF rewriting; no extra build prerequisite. |
| `prewrite`              | `litebox-vscode-prewrite`   | Pre-rewritten `node`, `dropbear`, `bash`; saves ~10.5 s per litebox-pass trial. Requires `litebox_syscall_rewriter`, which `setup()` already builds (`integration.rs:1961`); `ensure_vscode_image` copies it into the build context for the `COPY` instruction in the Dockerfile. |

The two stages share all surrounding code — flip via env var
once the suite is stable. `ensure_vscode_image` is idempotent
(inspect-then-build), so token-free / one-shot validation runs
incur zero rebuild cost.

**Concurrency cap:** `LITEBOX_VSCODE_JOBS` (default `1`),
independent of both `LITEBOX_TEST_JOBS` and
`LITEBOX_COPILOT_JOBS`. Serial default protects shared runs
from dockerd contention; cross-SSH scenarios additionally
benefit from serial because session-A's CLI continues running
between sessions and would otherwise compete with concurrent
trial-containers' CLIs for fork-restore slots under litebox.

**Native is the gold standard.** Every trial passes on native;
any litebox-pass failure is a real shim regression. As of the
work-stream landing commit:

| Trial                             | native | litebox       |
|-----------------------------------|--------|---------------|
| `vscode::bootstrap`               | ok     | FAIL (CLI doesn't reach `Listening on` line; bootstrap markers `: start` / `: end` / `listeningOn==` never appear). |
| `vscode::server_listen`           | ok     | FAIL (same root: `VSL_CLI_PID` printed, then 60 s poll runs out without ever seeing `Listening on`). |
| `vscode::connect_loopback`        | ok     | FAIL (inherits server_listen — never gets to the connect step). |
| `vscode::connect_cross_ssh`       | ok     | FAIL (session A inherits server_listen — never gets to session B). |

All four litebox-pass failures share the same root: the
`code-${VSCODE_COMMIT}` static-PIE-musl binary launches under
litebox but never reaches its `Listening on N.N.N.N:PORT`
stage within 60 s. The fix-first workflow (rule 12) applies —
the next work stream identifies the suspect capability with a
self-contained test in the harness, watches it fail under
litebox, and fixes the product code.

**Per-trial transcripts:** `target/test-logs/vscode-<pass>-<scenario>.raw.log`,
plus `.session-{a,b}.log` for `connect_cross_ssh`.

**Driver internals.** Reuses every host-side helper that
`mod copilot` already factored out:
`copilot::ssh_argv_base` / `wait_for_sshd` / `shell_quote` /
`read_with_deadline` / `wait_pid` / `strip_ansi`. The local
helpers added in `mod vscode` are: `build_vscode_spec` (per-pass
container spec), `ensure_vscode_image` (image-stage-aware
docker build), `VsCodePermit` (the concurrency cap),
`build_server_listen_remote_cmd` / `build_connect_loopback_remote_cmd` /
`build_cross_ssh_session_a_cmd` / `build_cross_ssh_session_b_cmd`
(the in-container shell programs), and `parse_vsl_port` /
`extract_first_hex40` (host-side parsers, end-to-end
contracted by their respective native trials).

**Files involved:**
- `litebox_tool_executor/rootfs/Dockerfile` —
  `litebox-vscode` / `litebox-vscode-prewrite` /
  `litebox-vscode-native` stages.
- `litebox_tool_executor/scripts/vscode/vscode-bootstrap-captured.sh`
  — the exact payload VS Code Remote-SSH pipes through `sh`;
  `vscode::bootstrap` `include_str!`s it and patches two
  lines at runtime. `vscode::extension_host_steady` reuses it
  to install/prime the CLI before starting `code-server`.
- `litebox_test_harness/tests/integration.rs` — `mod vscode`
  and unconditional registration in `main()`.

**Out of scope (deferred):**
- Full desktop VS Code → Remote-SSH session under load.
  Needs a desktop driver (Playwright-on-Electron); not
  appropriate for `cargo test`.
- Speaking the VS Code tunnel-mode protocol on the captured
  TCP port. The trials assert "TCP 3-way handshake completes"
  which is sufficient to validate the listener + broker TCP
  loopback; speaking the protocol would couple to a moving
  upstream binary format.

