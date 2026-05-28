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
`litebox-{pass}-{test_id}-{harness_pid}-{nanos}`. The `{harness_pid}`
salt uniquely identifies all containers from one harness invocation,
which is how the supervisor escalates to cleanup-by-name without
a shared registry.

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

### Sqlite schema (minimal — facts + one config table)

| Object | Role |
|---|---|
| `runs` | One row per `cargo test --test integration` invocation. `commit_sha`, `dirty_hash` (NULL ⇔ clean), `cargo_argv`, `universe_size`, pass/fail counts. |
| `run_results` | Immutable per-trial timing + verdict. Primary key `(run_id, test_id, pass)`. |
| `tracked_refs` | Config: `(ref, ci_worktree)` pairs the autonomous driver tracks. |
| `latest_results` | **VIEW** over `run_results` returning the freshest row per `(test_id, pass)`. No UPSERT path in the producer — pure SQL. |
| `meta` | One key/value row: `schema_version`. |

There is no `universe`, `worktree_coverage`, `ci_cycles`, or
`latest_results`-as-table. The runner enumerates the universe
in-process; coverage is computed at query time from `run_results
JOIN runs ON commit_sha = ? WHERE dirty_hash IS NULL`.

Schema-version compatibility: bumped on breaking changes. On
mismatch the Rust producer recreates the store from scratch (the
`.dashboard/` directory is local-only and gitignored).

### How the autonomous driver works

`dashboard.py auto` loops over the rows in `tracked_refs`. For each
ref, in round-robin order:

1. `git -C <ci_worktree> fetch --quiet`
2. `git -C <ci_worktree> rev-parse <ref>` → sha
3. `git -C <ci_worktree> checkout --detach --quiet <sha>`
4. `cargo test -p litebox_test_harness --test integration -- --fill[=N]`

The integration runner's `--fill` flag (in
`tests/integration.rs::dashboard_store::select_fill_batch`) picks
up to N trials that have no clean-state result at the current
`commit_sha`. Producer writes results synchronously via `rusqlite`,
so coverage advances atomically.

After each full round-trip, the driver re-renders `summary.md`,
sleeps `--interval` seconds, and repeats.

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

`summary.md` shows two **orthogonal** dimensions per (pass, tracked
ref):

- **Coverage** — `covered / universe (%)` of `(test_id, pass)`
  pairs with a clean-state result at the ref's current HEAD.
- **Pass rate** — `N pass / N FAIL` of the covered set.

Plus a **Result groups** table partitioned by
`(commit_sha, dirty_hash)` — each unique test-state stands alone, so
a pass on branch A can't mask a FAIL on branch B. Tracked refs are
italic-tagged in the table; ad-hoc agent-worktree runs appear as
their own rows.

Plus a current-FAILs list and recent-runs log.

### Consuming the dashboard from a coding-agent session

Every UI input is also on disk:

```sh
cat <main-worktree>/.dashboard/summary.md

sqlite3 <main-worktree>/.dashboard/results.sqlite <<'SQL'
.headers on
SELECT lr.test_id, lr.pass, lr.verdict,
       r.commit_sha, r.dirty_hash, r.worktree_path
  FROM latest_results lr
  JOIN runs r ON r.run_id = lr.run_id
 WHERE lr.pass = 'litebox' AND lr.verdict = 'FAIL'
 ORDER BY lr.finished_ts_ms DESC;
SQL

sqlite3 <main-worktree>/.dashboard/results.sqlite \
  "SELECT value FROM meta WHERE key='schema_version'"
```

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
