# `litebox_test_harness/scripts/`

Tools for inspecting and driving the litebox integration-test
dashboard.

## `dashboard.py` — render + autonomous fill driver

The dashboard's central store is
`<main-worktree>/.dashboard/results.sqlite`, written **directly** by
the integration test binary on every `cargo test --test integration`
invocation. This script is a pure consumer + small autonomous
driver — it never writes results.

### State directory

Default: `<main-worktree>/.dashboard/` (resolved via `dirname(git
rev-parse --git-common-dir)`, so any linked worktree resolves to the
same store). Gitignored.

Override:

- `--state-dir PATH` (CLI flag, highest precedence)
- `LITEBOX_DASHBOARD_DIR=PATH` env var (honored by both this script
  **and** the Rust producer — set it consistently)
- `LITEBOX_DASHBOARD_DIR=""` (empty) — explicit producer opt-out

### Other producer env vars

- `LITEBOX_KEEP_CONTAINER=1` — suppress all framework-side
  `docker rm` so containers survive for post-mortem `docker exec`.
  Honored in foreground reap, detached tear-down, signal handler,
  and the `spawn_drain` watchdog (the cleanup-contract paths above).
- `LITEBOX_FILL_FAIL_RETRIES=N` (default `3`) — class-2 retry cap
  for the `--fill` selector. After N attempts at the same clean sha
  with no pass, the test is considered confirmed-failing and stops
  being scheduled until the sha changes. Set to `1` to disable
  retry-confirmation entirely; raise to absorb flakier suites.
- `LITEBOX_GLOBAL_JOBS=N` (default `nproc`) — see "Cross-session
  concurrency coordination" below.

### Subcommands

```
dashboard.py render                          # write summary.md once
dashboard.py status [--format text|md|sql]   # terminal-friendly summary
dashboard.py track <ref> <ci_worktree>       # register a tracked ref
dashboard.py untrack <ref>                   # remove a tracked ref
dashboard.py refs                            # list tracked refs
dashboard.py auto [--interval SECS]          # autonomous fill driver
dashboard.py stop                            # stop auto + reap descendants
```

### Auto-driver lifecycle & cleanup contract

The `auto` supervisor and the Rust test harness cooperate to
guarantee no leaked processes or containers on any exit path
(SIGTERM, cycle timeout, `dashboard.py stop`, even SIGKILL of cargo).
Each layer cleans up what it started:

| Layer | Owns | Cleanup mechanism |
|---|---|---|
| `dashboard.py auto` supervisor | `cargo` + every descendant in its PGID | Launches cargo via `start_new_session=True` → new PGID. On cycle timeout, SIGTERM, or `stop`: `killpg(SIGTERM)` → grace → `killpg(SIGKILL)` → `docker rm -f` containers matching `*-{harness_pid}-*` |
| Harness (test binary) | in-flight `docker run` children + their named containers | Global `(pid → container_name)` registry; top-level SIGTERM/SIGINT handler iterates it, parallel `docker rm -f`, then `exit(130)` |
| Each `docker run` child | the container (via `--rm`) | `PR_SET_PDEATHSIG=SIGTERM` set in `pre_exec` — self-terminates if harness dies abruptly |
| Harness ↔ cargo bridge | parent-death notification | `PR_SET_PDEATHSIG=SIGTERM` on harness self: cargo SIGKILL → kernel SIGTERMs harness → handler fires |

**Container naming.** Every container is named
`litebox-{pass}-{test_id}-{harness_pid}-{counter}` where
`{counter}` is a process-static monotonic `AtomicU64`. The
`{harness_pid}` salt uniquely identifies all containers from one
harness invocation (so the supervisor's cleanup-by-name sweep
finds them); the `{counter}` guarantees uniqueness across
concurrent dispatches within the same wall-second (the old
`subsec_nanos()` suffix could collide at high jobs).

**Pidfile.** `<state_dir>/auto.pidfile` is JSON: `{supervisor_pid,
cargo_pid, cargo_pgid, harness_pid}`. Written when the supervisor
starts, updated when each cycle's harness pid is discovered, removed
on exit. `dashboard.py stop` reads it.

**Why not just `setsid` everywhere.** Process groups don't compose
hierarchically — they're a flat label. If both the supervisor and
the harness `setsid`'d into their own sessions, neither could reach
the other via `killpg`. So only the supervisor creates a new
session; the harness stays in cargo's PGID and handles its own
children via the registry + PDEATHSIG bridge.

**Supervisor crash-resilience.** The per-ref drive loop wraps
`_drive_ref` in `try/except` with a traceback to stderr, so a
recoverable per-ref failure (network blip, transient sqlite lock)
does not kill the supervisor. The `/proc` walk in
`_pids_in_pgid` catches `FileNotFoundError`, `ProcessLookupError`,
`PermissionError`, and `OSError` to tolerate the unavoidable race
between `Path("/proc").iterdir()` and `read_text("/proc/<pid>/stat")`
when a process exits mid-iteration. The `cleanup::install_signal_handler`
in the harness calls `dashboard_store::finalize()` before
`exit(130)`, so even SIGKILL'd cycles (e.g., the outer
`cycle_budget_secs * 2 + 600` timeout) still stamp
`runs.pass_count` / `fail_count` correctly.

### Per-trial container lifecycle: `framework::run_trial`

Inside the harness, every test family routes its container
lifecycle through a single entry point —
`framework::run_trial(pass, test_id, suite, group, ContainerSpec,
drive)` (see `tests/common/framework.rs`). It owns:

- dispatch-gate acquire (lease-aware: `LITEBOX_GLOBAL_JOBS / N`)
- canonical container name allocation
- `PR_SET_PDEATHSIG=SIGTERM` via `pre_exec` on the docker-run child
- cleanup-registry register/deregister (keyed by container name
  so detached and foreground containers coexist cleanly)
- spawn-drain handoff (foreground) or explicit `docker rm -f`
  (detached) after the trial's driver returns
- result recording via the same `emit_timing_main` path used by
  the standard tests

Per-family variation is **only** the `ContainerSpec` (image,
container command, docker args, foreground-or-detached, timeout)
and the `drive` closure (how to obtain a verdict from the running
container). Adding a new test family (e.g. VS Code) is a new
image stage in the Dockerfile + a new module that builds its
`ContainerSpec` + writes a drive closure + calls
`framework::run_trial` — no new cleanup or throttling code.

Current callers — **all three test families** in the harness now
go through `framework::run_trial`. No bespoke container lifecycle
code remains:

- `run_pass_group` (standard coordinator tests) — image
  `litebox-test`, foreground, drive closure parses JSON line on
  stdout and scrapes timing markers from stderr.
- `dropbear_bash::run_scenario` — image `litebox-agent-cli`,
  detached, drive closure SSHes to the published port and checks
  bash output. Host-side SSH driving preserved so the test
  exercises the same docker-bridge → litebox-inbound-TCP path a
  real user hits.
- `copilot_cli::run_scenario` — image `litebox-agent-cli`,
  detached, drive closure runs the Copilot CLI through SSH (pminus
  or tui mode) and checks the response canary. `CopilotPermit`
  (Copilot-API rate-limiter) sits above `framework::run_trial`.

### Sqlite schema (minimal — facts + one config table)

| Object | Role |
|---|---|
| `runs` | One row per `cargo test --test integration` invocation. `commit_sha`, `dirty_hash` (NULL ⇔ clean), `cargo_argv`, `universe_size`, pass/fail counts. |
| `run_results` | Immutable per-trial timing + verdict. Primary key `(run_id, test_id, mode)`. `mode` is the trial **pass** — `'native'` or `'litebox'` — *not* a pass/fail flag; the outcome is `verdict` (`'pass'` / `'fail'` / `'no_result'`). |
| `tracked_refs` | Config: `(ref, ci_worktree)` pairs the autonomous driver tracks. |
| `latest_results` | **VIEW** over `run_results` returning the freshest row per `(test_id, mode)`. No UPSERT path in the producer — pure SQL. |
| `meta` | One key/value row: `schema_version`. |
| `harness_leases` | Cross-session concurrency coordination — one row per live `cargo test --test integration` invocation (`pid`, `heartbeat_at_ms`). Additive (no SCHEMA_VERSION bump). |

There is no `universe`, `worktree_coverage`, `ci_cycles`, or
`latest_results`-as-table. The runner enumerates the universe
in-process; coverage is computed at query time from `run_results
JOIN runs ON commit_sha = ? WHERE dirty_hash IS NULL`.

**Query gotchas** (the two that trip up ad-hoc consumers):

- `run_results.mode` is the trial pass (`'native'` / `'litebox'`),
  **not** pass/fail. The outcome is `verdict`
  (`'pass'` / `'fail'` / `'no_result'`, all lower-case). So
  "did it pass?" is `verdict = 'pass'`, and "which pass?" is
  `mode = 'litebox'`. (Historically `mode` was named `pass`, which
  collided with the verdict; renamed in schema v4.)
- `runs.commit_sha` is the **full 40-char** SHA. A short-SHA
  equality match silently returns nothing — use
  `commit_sha LIKE 'abc1234%'` or `substr(commit_sha, 1, 12)`.

Schema-version compatibility: bumped on breaking changes. On
mismatch the Rust producer panics with a remediation pointer;
the user is consulted before any bump (stopping every coding-agent
session is a coordination cost).

### Cross-session concurrency coordination

Multiple `cargo test --test integration` invocations can run
concurrently on the same host (auto-driver, ad-hoc sessions,
subagents). The `harness_leases` table makes them self-coordinate
so total in-flight `docker run` children stay ≤ `GLOBAL_CAP`
(default = `nproc`, override via `LITEBOX_GLOBAL_JOBS`).

**Mechanism.** Each harness inserts `(pid, heartbeat_at_ms)` on
startup, heartbeats every 10s, deletes on exit. The dispatch gate
inside the harness reads the live lease count (atomic, refreshed
every ~10s) and uses `my_cap_now = max(1, min(intrinsic_jobs,
GLOBAL_CAP / live_lease_count))`. When peers come or go the cap
floats on the next dispatch.

**Why no SCHEMA_VERSION bump.** The `harness_leases` table is
purely additive — old harness binaries don't read or write it, so
they're not affected by its presence (they fall back to today's
uncoordinated dispatch). New harnesses use it to cooperate. Once
the new code lands on the amalgamation branch, sessions
opt-in organically on their next rebuild.

**Inspect live leases.**

```
sqlite3 .dashboard/results.sqlite \
  "SELECT pid, (strftime('%s','now')*1000 - heartbeat_at_ms)/1000 AS age_s
     FROM harness_leases ORDER BY age_s"
```

(Rows with `age_s > 30` are stale and get pruned by the next live
harness that connects.) The renderer also includes a one-line
summary at the top of `summary.md`.

**Failure modes.** Any error in the lease layer (sqlite locked,
table missing, etc.) is logged and silently absorbed; the harness
falls back to its uncoordinated default. The lease layer must
never block a test run — this is asserted by
`tests/dashboard_store.rs::harness_leases_table_round_trip_and_prune`.

### How the autonomous driver works

`dashboard.py auto` loops over the rows in `tracked_refs`. For each
ref, in round-robin order:

1. `git -C <ci_worktree> fetch --quiet`
2. `git -C <ci_worktree> rev-parse <ref>` → sha
3. `git -C <ci_worktree> checkout --detach --quiet <sha>`
4. `cargo test -p litebox_test_harness --test integration -- --fill[=N]`

The integration runner's `--fill` flag (in
`tests/integration.rs::dashboard_store::select_fill_batch`) picks
up to N trials using a two-class selector at the current
`commit_sha`:

- **Class 1 — uncovered:** no result yet at this sha. Within the
  band, never-seen test IDs first, then stalest by
  `latest_results.finished_ts_ms`. Round-robin by suite so no single
  family monopolizes a batch.
- **Class 2 — failed-at-sha, retry-capped:** freshest verdict at this
  sha is fail/timeout/error and `attempts < LITEBOX_FILL_FAIL_RETRIES`
  (default `3`). Stalest-first. Beyond the cap, treated as a
  confirmed regression and skipped until the sha changes.
- **Passing-at-sha** is skipped (clean-sha pass is assumed stable
  until the sha moves; drift detection would be a future class 3).

Empirically this keeps batches productive on both freshness and
regression-confirmation: most multi-attempt observations resolve
within the cap (the flake clears, or the regression confirms), so
class 2 doesn't dominate.

Producer writes results synchronously via `rusqlite`, so coverage
advances atomically.

After each full round-trip, the driver re-renders `summary.md`,
sleeps `--interval` seconds, and repeats.

### Opportunistic coverage of agent worktrees

After each tracked-ref pass, the supervisor also discovers any
worktree visible via `git worktree list` in the canonical clone
that is NOT a `tracked_refs.ci_worktree` — these are "agent
worktrees" (typically per-session work branches). For each
eligible worktree, it can spawn one short `--fill` cycle per
loop iteration. Discovery + scheduling is automatic; no marker
file, no per-worktree configuration.

**Isolation.** The supervisor never runs cargo inside the agent's
worktree. Doing so would race the agent's own `target/` and
`docker build` if the agent kicked off a cargo invocation in the
brief gap between idle-gate checks. Instead it maintains a
**per-branch shadow worktree** at `<state-dir>/shadows/<branch>/`
— a `git worktree add --detach` off the canonical clone (so it
shares `.git/objects` but has its own working tree + its own
`target/` + its own per-worktree-path docker image tag). Branch
names with `/` are encoded as `%2f` so the directory layout stays
flat. Per cycle:

1. `git -C <shadow> checkout --detach -f --quiet <agent_HEAD>`
2. `cargo test ...` from `<shadow>`.

Opportunistic runs land in `runs` with
`worktree_path=<state-dir>/shadows/<branch>` and
`branch=<agent_branch>` (via `LITEBOX_DASHBOARD_REF`). This makes
them trivially distinguishable in result-groups by the literal
shadow path — same self-evidence trick the tracked-ref CI
worktrees rely on. Aggregation across shadow + agent runs at the
same HEAD still works correctly: the state key is `(commit_sha,
dirty_hash, state_wt)` and `state_wt` is NULL for clean rows
regardless of worktree, so two clean runs at the same sha (one
from agent's own worktree, one from the shadow) collapse to the
same state and their `state_test_pass` rows combine.

Each branch's shadow persists across cycles — incremental cargo
`target/` artifacts are reused, so only the *first* opportunistic
cycle for a given branch pays a full cold-build cost. Subsequent
cycles on the same branch are incremental even if other branches
were tested in between (the earlier single-shadow design paid a
2–3 min recompile on every branch flip; per-branch shadows
eliminate that). Tradeoff: ~10–15 GB disk under `target/` per
branch. Mitigated by GC.

**GC.** At the start of each opportunistic scheduling cycle, the
supervisor reaps any shadow under `<state-dir>/shadows/` whose
decoded branch name no longer exists in the canonical clone's
local refs (`git for-each-ref refs/heads/`). Branches deleted by
the user (e.g. after merging back) immediately free their
shadow's `target/`. The legacy single-shadow path
(`<state-dir>/shadow/`) is also reaped on first GC for migration.

The shadow's Docker image is its own per-worktree tag (`litebox-
test:wt-<sha256(shadow_path)[..8]>`, per the per-session image
tag scheme), so each per-branch shadow has a distinct docker
image and the shadow's `docker build` never overwrites the
agent's image either.

**Idle gate.** A worktree is eligible only when:

- No source-ish file (`*.rs`, `*.toml`, `*.py`, `Dockerfile`) has
  been touched in the last `LITEBOX_AGENT_IDLE_SECS` (default
  `300` = 5min); AND
- No live `harness_leases` row's `/proc/<pid>/cwd` is inside the
  worktree path.

This avoids competing with the agent's own active edit/build/test
work.

**Scheduling.** Round-robin across eligible candidates, biased
toward never-tested or stalest HEADs, restricted to the *tip set*
(see below). The supervisor records the last-picked worktree in
`meta.agent_coverage_last_picked` to ensure no single worktree
starves the others over long runs. The opportunistic `cargo test`
registers with `harness_leases` the same way any other invocation
does, so the existing cross-session concurrency lease
(`LITEBOX_GLOBAL_JOBS / N`) fairly shares CPU between this cycle
and any tracked-ref cycle that's in flight.

**Tip-set targeting.** When a coding session fans out to subagent
worktrees, the agent worktree list contains multiple branches
related by ancestry. The supervisor drives only the **tip set** —
worktrees whose HEAD is not contained in some other worktree's
HEAD as an ancestor. This generalizes both fan-out shapes
uniformly:

- **Subagents merge back into the session branch** (session's
  HEAD is a merge commit containing subagent HEADs as ancestors):
  subagent worktrees are dropped, the session branch is the tip.
- **Subagents branch off the session and add new commits**
  (session HEAD is ancestor of subagent HEADs): the session
  worktree is dropped, subagents are tips.
- **Solo / independent worktrees**: every worktree is a tip — no
  behavior change.
- **Disjoint sessions**: one tip per cluster; both driven.

Detection is automatic, recomputed every supervisor cycle, and
has no configuration knob (intentional — a knob would leak into
agent shell contexts the same way `LITEBOX_TEST_JOBS=1` did).
If detection is wrong in some real workflow, the rule itself
gets fixed. The render section ("Agent worktrees") shows every
agent worktree but marks tips with `→` and subsumed worktrees
with `~`, so it's visually clear which rows the supervisor is
actually scheduling.

**Budget.** Each opportunistic cycle is `--fill=<budget>s` with
`budget = LITEBOX_AGENT_FILL_BUDGET` (default `180`), kept small
so the round-robin is responsive across many worktrees.

**Parallelism.** When multiple tip worktrees are eligible in the
same supervisor tick, the orchestrator spawns up to
`--max-parallel-agent-cargos N` cargo cycles concurrently (default
`4`). Each cycle runs in its own per-branch shadow
(`<state-dir>/shadows/<branch>/`), so they don't collide on
`target/` or per-worktree docker image tags. CPU is throttled
automatically by the harness lease table: each cargo registers in
`harness_leases` and computes its job count as
`max(1, LITEBOX_GLOBAL_JOBS / live_lease_count)`. No cargo is
ever starved — every harness gets at least 1 job — so raising
`N` is safe; the practical ceiling is cold-build I/O and docker
daemon load, not CPU. Set `--max-parallel-agent-cargos=1` to
disable parallelism.

The supervisor's tracked-ref loop applies the same model:
`--max-parallel-tracked-refs N` (default `4`) drives up to N
tracked refs concurrently per cycle. Each ref already has its
own `ci_worktree`, so parallel drives don't collide on `target/`
or docker container names (the harness pid salt keeps containers
namespaced per cargo). Set to `1` to fall back to sequential
driving.

**Surfacing.** Results land in the existing `runs` /
`run_results` tables under the worktree's own `(commit_sha,
dirty_hash, worktree_path)`, so they feed every per-state query
in the store. The "Agent worktrees" section in `summary.md` is
rendered **directly from the `regression_class` view** (the same
classifier as `dashboard.py regressions <branch>`) — one
materialization of the view drives every row. Per worktree it
reports, per pass (native / litebox):

- **Regressions** — hard / soft counts with the classifier's
  `hi/md/lo` confidence, and `N inh` when some are *inherited*
  (the baseline ref's current tip fails the same test, so the
  branch isn't the cause).
- **Fixed** — tests that failed at the baseline and now pass
  (the branch repaired them).
- **Coverage** — `covered / universe` of the comparable test
  universe, with the `not run` gap called out so a partial cycle
  can't read as clean.

A `<details>` block per worktree lists the regressed test_ids
(hard before soft, high-confidence first, inherited tagged).
The "baseline" for each agent worktree is picked dynamically: the
tracked_ref whose HEAD shares the most recent merge-base with the
agent worktree's HEAD (= the upstream they most recently forked
from). With one tracked_ref this is trivially that ref. The
section is omitted entirely when no agent worktrees are
discovered.

**Optional sidecar.** Set `LITEBOX_AGENT_SIDECAR=1` (or pass
`--agent-sidecar` to `dashboard.py auto`) to also write
`<worktree>/.dashboard/regressions.md` after each successful
agent cycle, listing the regressed test_ids per pass. Convenient
for an agent to `cat` directly without scrolling `summary.md`.

**Disable.** Pass `--agent-coverage-disable` to the supervisor
to skip opportunistic coverage entirely (supervisor only drives
tracked refs).

| Env var | Default | Effect |
|---|---|---|
| `LITEBOX_AGENT_IDLE_SECS` | `300` | Minimum seconds since last source-file mtime AND no live lease for a worktree to be eligible. |
| `LITEBOX_AGENT_FILL_BUDGET` | `180` | `--fill=Ns` budget for each opportunistic cycle. |
| `LITEBOX_AGENT_SIDECAR` | unset | When set (any value), write `<worktree>/.dashboard/regressions.md` after each successful cycle. |
| `LITEBOX_DASHBOARD_CANONICAL` | state-dir parent | Override the canonical clone path for `git worktree list` / merge-base queries (renderer-side; the supervisor accepts `--canonical-worktree` instead). |

### Bootstrap a tracked ref

```sh
# track auto-creates the worktree (git worktree add --detach) when
# the path doesn't exist. One step, one command.
dashboard.py track origin/wportnoy/vscode-server-in-litebox ~/src/litebox-ci

# Then start the autonomous driver (foreground or systemd-user unit).
dashboard.py auto --interval 60
```

### Remove a tracked ref

```sh
# Default: removes the sqlite row AND runs `git worktree remove`.
dashboard.py untrack origin/wportnoy/vscode-server-in-litebox

# Keep the worktree on disk (e.g. you want to reuse it later):
dashboard.py untrack origin/wportnoy/vscode-server-in-litebox --keep-worktree

# Force-remove a dirty worktree:
dashboard.py untrack origin/wportnoy/vscode-server-in-litebox --force
```

### Render shape

`summary.md` is top-weighted on the two tables consumers read:

- **Tracked refs** — per (pass, tracked ref): **Coverage**
  (`covered / universe (%)` of `(test_id, pass)` pairs with a
  clean-state result at the ref's current HEAD) and **Pass rate**
  (`N pass / N FAIL` of the covered set).
- **Agent worktrees** — per agent worktree: the `regression_class`
  classification (hard/soft with confidence, fixed, inherited) and
  coverage vs the merge-base baseline (see the regression-classifier
  section above).

Plus a meta header, a velocity pulse, and a **Current FAILs** section
(collapsed in a `<details>`) — the absolute "red right now" list of
failing `(test_id, pass)` at the 5 most recent states, which the
*relative* classifier can't provide. Its `<summary>` shows the failing
count at a glance.

The former **Result groups** (per-`(commit_sha, dirty_hash)`
stacked-state breakdown), **By suite × group**, and **Recent runs**
sections were retired from the always-on render to keep it focused on
what's read. Nothing is lost: that data is unchanged in sqlite and
reachable on demand — `dashboard.py regressions <branch>` for
per-branch triage, `dashboard.py status` for a snapshot, or a direct
SQL query against `run_results` / `regression_class`.

**Live-branch filter.** Current FAILs and the per-branch sections hide
rows whose only branch attribution is a branch that no longer exists in
the canonical clone (`git for-each-ref refs/heads/` union
`tracked_refs.ref`). This keeps the report focused on in-flight work —
data is never deleted from sqlite, just not rendered. Tracked-ref-tagged
rows always survive (tracked refs are live by definition). The Agent
worktrees and Tracked refs sections are already live-only (driven by
`git worktree list` and the explicit `tracked_refs` table).

### Consuming the dashboard from a coding-agent session

Every UI input is also on disk:

```sh
cat <main-worktree>/.dashboard/summary.md

sqlite3 <main-worktree>/.dashboard/results.sqlite <<'SQL'
.headers on
SELECT lr.test_id, lr.mode, lr.verdict,
       r.commit_sha, r.dirty_hash, r.worktree_path
  FROM latest_results lr
  JOIN runs r ON r.run_id = lr.run_id
 WHERE lr.mode = 'litebox' AND lr.verdict = 'fail'
 ORDER BY lr.finished_ts_ms DESC;
SQL

sqlite3 <main-worktree>/.dashboard/results.sqlite \
  "SELECT value FROM meta WHERE key='schema_version'"
```

### Standardized regression classification (`regression_class` view)

Instead of hand-rolling "is this test regressing on my branch?"
queries, read the **`regression_class`** view — a pure-SQL,
flaky-aware, confidence-tiered classifier. It's consumable from plain
`sqlite3` (no Python), and every consumer gets the identical verdict.

```sh
# CLI:
sqlite3 <main-worktree>/.dashboard/results.sqlite \
  "SELECT test_id, classification, confidence FROM regression_class
    WHERE branch='wportnoy/my-branch' AND mode='litebox'
      AND classification='hard_regression'"

# or the wrapper (refreshes caches first, then prints grouped):
dashboard.py regressions wportnoy/my-branch
dashboard.py regressions <sha-prefix> --format sql
```

Each failing `(test_id, mode)` on a branch is classified by comparing
its state at the branch HEAD against its `merge-base` baseline, plus
the test's recent flakiness **on the upstream lineage** (tracked-ref CI
runs only — so a genuine branch regression isn't mistaken for a flake):

| `classification` | Meaning |
|---|---|
| `hard_regression` | Stable pass upstream → **fails** on branch. **Really bad.** |
| `soft_regression` | Fails on branch, but was already flaky upstream / at baseline. Discount. |
| `new_fail` | Fails on branch, no definitive baseline pass to compare. |
| `preexisting_fail` | Failed at baseline too — not a regression. |
| `fixed` | Failed at the merge-base baseline, now **passes** on the branch — the branch repaired it. |
| `flaky_pass` | Passes on branch but flaked (retry-recovered) at the sha. |
| `no_result` | Branch produced only `no_result` (infra non-outcome, ~1% background) — **not** a regression. |
| `not_run` | In the comparable universe (has a baseline verdict) but **not yet run at the branch sha** — an explicit coverage gap, *not* a pass. |
| `ok` | Pass, no regression. |

The view drives off the **comparable universe** (every test with a
definitive verdict at the merge-base baseline, plus everything covered
at the branch) via a LEFT JOIN, so a test that simply hasn't run on the
branch surfaces as `not_run` instead of vanishing. This is the guard
against a *partial* run reading as "clean": `dashboard.py regressions`
prints a coverage line per pass — e.g. `litebox: hard_regression/high=80
… [covered 1543/5677, 4134 not_run]` — so a thin sample is obviously
provisional, never silently mistaken for green.

Classification keys off the **freshest *definitive* verdict** (most
recent `pass`/`fail`, ignoring `no_result`): a `no_result` never reads
as a failure (it's infra noise, and `dashboard.py regressions` reports
it separately), and a real `fail` is never masked by a later
`no_result` hiccup. A regression requires a definitive `pass` at the
merge-base baseline *and* a definitive `fail` on the branch.

`confidence` is `high` / `medium` / `low` (or `n/a`): `high` needs the
branch to fail the **full retry budget** (`LITEBOX_FILL_FAIL_RETRIES`,
default 3, all definitive fails) *and* the upstream to be
well-observed-stable — so a 2-of-3 (which a timing/load-sensitive test
can hit under the shadow's build load while upstream passes it) stays
`medium`, not high. `low` flags thin evidence — the explicit "not enough
data to judge yet" signal.

A regression is **inherited** when the `tip_verdict` column (the same
test's freshest definitive verdict at the baseline ref's *current* HEAD,
`tip_sha`) is also `fail`: the upstream tip is already broken, so the
branch isn't the cause. `dashboard.py regressions` reports the inherited
count per pass and tags each inherited test; the "Agent worktrees"
render section shows it as `N inh`. This separates a branch-introduced
break (tip passes) from one merely inherited from an already-broken
upstream.

Almost everything is a live derivation:
`test_flake_stats` (the upstream recent-flake tally) is itself a view,
kept cheap by an index on
`runs(worktree_path)`. The *only* materialized table is `branch_baseline`
— the git `merge-base(branch_HEAD, tracked_tip)` map plus the tracked
ref's current `tip_sha`, which SQLite has no way to compute — refreshed
each cycle by the `dashboard.py auto` supervisor (and at render time).
`(hard + soft)` reconciles exactly with the old binary
regression count; it just splits it by severity.

## `analyze-test-timing.py` — per-test timing summaries

Reads `run_results` from
`<main-worktree>/.dashboard/results.sqlite` (or any sqlite path
passed on the command line).

```sh
./analyze-test-timing.py                         # latest run, default store
./analyze-test-timing.py path/results.sqlite     # latest run in that store
./analyze-test-timing.py path/results.sqlite 42  # run_id 42
./analyze-test-timing.py runA.sqlite runB.sqlite # diff two runs
```
