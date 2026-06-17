#!/usr/bin/env python3
"""
dashboard.py — render and drive the litebox integration-test
dashboard from `<main-worktree>/.dashboard/results.sqlite`.

Subcommands (stdlib only — no third-party deps):

    dashboard.py render                          # write summary.md once
    dashboard.py status [--format text|md|sql]   # terminal-friendly
    dashboard.py track <ref> <ci_worktree>       # register a tracked ref
    dashboard.py untrack <ref>                   # remove a tracked ref
    dashboard.py refs                            # list tracked refs
    dashboard.py auto [--interval SECS]          # autonomous fill driver
    dashboard.py drain [--wait]                  # graceful shutdown (SIGUSR1; current cycle finishes)
    dashboard.py stop                            # hard stop: reap cargo + harness + containers

The autonomous `auto` driver iterates round-robin over the rows in
the `tracked_refs` table. For each ref it does:

    git -C <ci_worktree> fetch --quiet origin
    git -C <ci_worktree> checkout --detach --quiet <ref>
    cargo test -p litebox_test_harness --test integration -- --fill

…then re-renders `summary.md`, sleeps `--interval`, and repeats.
The integration runner's `--fill` flag handles all the "what's
missing" selection — this script never touches `run_results`.

Bootstrap a tracked ref:

    git worktree add --detach /path/to/litebox-ci origin/<branch>
    dashboard.py track origin/<branch> /path/to/litebox-ci

──────────────────────────────────────────────────────────────────
Data model — two tables, two aggregation rules
──────────────────────────────────────────────────────────────────

The store has two primary tables (see
`tests/common/dashboard_store.rs` for canonical DDL):

  * `runs`        — one row per **cargo invocation**. Carries
                    attribution metadata: commit_sha, branch,
                    worktree_path, dirty_hash, plus rollup
                    counts (pass_count/fail_count) written
                    when the cargo process completes.
  * `run_results` — one row per **trial outcome**
                    `(run_id, test_id, mode)`. Streamed
                    continuously as each trial finishes,
                    carrying its verdict + per-stage timings.
                    THIS is the primary signal everything
                    aggregates over.

`mode` (native | litebox) is a separate column from `test_id`;
the aggregation unit throughout the renderer is `(test_id, mode)`.

**Every renderer aggregates the same way:** scope `run_results`
by `(commit_sha, dirty_hash)` via a JOIN to `runs`, then take
the freshest verdict per `(test_id, mode)` within that state.
That's "state-scoped freshest" — class-2 retries (a test that
failed then recovered at the same sha) are counted as one pass,
not pass+fail.

The `latest_results` VIEW (globally-freshest per (test_id, mode)
across all shas) is defined in the schema but **no longer used**
by this renderer — it could contaminate today's view with stale
verdicts from old commits. Left defined for now; removable in a
future schema bump.

`runs.pass_count` / `fail_count` (per-cargo-invocation rollups)
are NOT a source of truth for any verdict count — they were
the source of the misleading `0→3941` sparkline artefact when
a partial cycle wrote `pass_count=0`. The only places `runs`
is used for *summary* (not attribution) are:

  * `_render_recent_runs` — "what cycles ran where" (legit
    time-ordered table).
  * `_render_velocity` — "N runs in 24h" (loose time pulse).

Every other renderer uses per-state freshest semantics.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Iterable, Optional

SCHEMA_VERSION_EXPECTED = 4
DEFAULT_FILL_BATCH = 300

# Reap timing knobs.
_PGID_SIGTERM_GRACE_SECS = 10
_SUPERVISOR_SIGTERM_GRACE_SECS = 30


# ─── State directory resolution ──────────────────────────────────────


def resolve_state_dir(arg: Optional[str]) -> Path:
    """Return the absolute path to the dashboard state directory.

    Precedence: --state-dir argument > $LITEBOX_DASHBOARD_DIR (when
    non-empty) > `<main-worktree>/.dashboard/`. Mirrors the Rust
    producer's `dashboard_store::resolve_state_dir`.
    """
    if arg:
        return Path(arg).expanduser().resolve()
    env = os.environ.get("LITEBOX_DASHBOARD_DIR")
    if env:
        return Path(env).expanduser().resolve()
    out = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        check=True, capture_output=True, text=True,
    )
    return Path(out.stdout.strip()).parent / ".dashboard"


def open_db(state_dir: Path, *, bootstrap: bool = False,
            with_state_views: bool = True) -> sqlite3.Connection:
    """Open the dashboard sqlite store.

    `bootstrap=True` initializes an empty store + schema if the file
    doesn't exist yet — used by `track` so the user can register a
    tracked ref before the producer has ever run. Other subcommands
    pass `bootstrap=False` (the default) and exit with a helpful
    message instead of silently creating an empty store.

    `with_state_views=False` skips materializing the render-only
    `state_test_pass` TEMP TABLE (an expensive window over all of
    `run_results`). Callers that only need `regression_class` / the
    cache tables / raw `run_results` (e.g. `regressions`, the
    supervisor's per-cycle ref read + classification refresh) pass it
    to avoid a multi-second cost they'd never use.
    """
    db_path = state_dir / "results.sqlite"
    if not db_path.exists():
        if not bootstrap:
            sys.exit(
                f"dashboard: sqlite store not found at {db_path}\n"
                "  Run `cargo test -p litebox_test_harness --test integration` "
                "once to create it,\n"
                "  or `dashboard.py track …` (auto-creates the store)."
            )
        state_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.row_factory = sqlite3.Row
    if bootstrap:
        _ensure_schema(conn)
    check_schema(conn)
    if with_state_views:
        _ensure_views(conn)
    _ensure_classification_schema(conn)
    _ensure_classification_schema(conn)
    return conn


def _ensure_views(conn: sqlite3.Connection) -> None:
    """Define the renderer-side SQL views/tables that encode
    **The Key**.

    These are pure derivations of `runs` + `run_results` — no
    schema change, no producer coordination needed. Defining
    them once per connection ensures every aggregator inherits
    the same state key and freshness semantics, so no individual
    query can drift.

    Two objects:

      * ``state_rows`` (VIEW) — `runs ⋈ run_results` flattened,
        exposing ``state_wt`` (the CASE expression that makes
        worktree part of the state identity only when the row is
        dirty). All aggregations key off
        ``(commit_sha, dirty_hash, state_wt)``.

      * ``state_test_pass`` (TEMP TABLE) — per-(state, test_id,
        pass) summary: ``freshest_verdict`` (latest verdict at
        this state), ``ever_failed`` (any non-pass row at this
        state), ``newest_ms``. ``cov = pass + fail`` and
        ``flaky ⊆ pass`` both follow trivially from
        selecting/grouping this. Materialized as a TEMP TABLE
        rather than a VIEW because the underlying window
        function is expensive (~230k rows × O(states)) and
        every aggregator selects it many times per render —
        materializing once is the difference between a sub-
        second render and a 5+ min render. Per-connection
        scope means each render call gets a fresh snapshot.
    """
    conn.executescript(
        """
        CREATE VIEW IF NOT EXISTS state_rows AS
        SELECT
            r.run_id,
            r.commit_sha,
            r.dirty_hash,
            r.worktree_path,
            r.branch,
            CASE WHEN r.dirty_hash IS NULL
                 THEN NULL ELSE r.worktree_path END AS state_wt,
            rr.test_id,
            rr.mode,
            rr.suite,
            rr."group",
            rr.verdict,
            rr.finished_ts_ms
          FROM run_results rr
          JOIN runs r ON r.run_id = rr.run_id;

        DROP TABLE IF EXISTS temp.state_test_pass;
        CREATE TEMP TABLE state_test_pass AS
        WITH ranked AS (
            SELECT
                commit_sha, dirty_hash, state_wt,
                test_id, mode, suite, "group",
                verdict, finished_ts_ms,
                ROW_NUMBER() OVER (
                    PARTITION BY commit_sha, dirty_hash, state_wt,
                                 test_id, mode
                    ORDER BY finished_ts_ms DESC
                ) AS rn
              FROM state_rows
        )
        SELECT
            commit_sha, dirty_hash, state_wt,
            test_id, mode,
            MAX(suite)   AS suite,
            MAX("group") AS "group",
            MAX(CASE WHEN rn = 1 THEN verdict END) AS freshest_verdict,
            MAX(CASE WHEN verdict != 'pass' THEN 1 ELSE 0 END) AS ever_failed,
            MAX(finished_ts_ms) AS newest_ms
          FROM ranked
         GROUP BY commit_sha, dirty_hash, state_wt, test_id, mode;

        CREATE INDEX IF NOT EXISTS idx_state_test_pass_state
            ON state_test_pass(commit_sha, dirty_hash, state_wt, mode);
        """
    )


# ─── Regression classification (CLI-consumable, pure-SQL) ────────────
#
# Sessions repeatedly re-derive "is this test regressing on my branch?"
# with ad-hoc queries. This standardizes it as a VIEW so every consumer
# — `sqlite3 results.sqlite`, the Python renderer, any session — gets
# the identical, flaky-aware, confidence-tiered verdict with no Python
# and no drift.
#
# The classification *logic* lives entirely in SQL (the `regression_class`
# view's CASE), and so does every *derivable* input — including
# `test_flake_stats` (the recent upstream pass/fail tally for the
# "was it flaky beforehand?" softening), which is a VIEW. The view's
# aggregate is kept cheap by an index on `runs(worktree_path)` (SQLite
# can't index a view itself — views aren't materialized — so the index
# goes on the base table the view filters by).
#
# Exactly ONE input genuinely can't live in SQL and is materialized:
#   * `branch_baseline` — git `merge-base(branch_HEAD, tracked_tip)`,
#     which SQLite has no way to compute (no git ancestry). The
#     supervisor refreshes it each cycle. It is the only derived-state
#     table; everything else is a pure live derivation.
#
# Additive (a table + views + an index, created via IF NOT EXISTS / a
# meta-keyed definition version) — no SCHEMA_VERSION bump, no producer
# change, no data migration.

_CLASSIFICATION_SCHEMA_VERSION = 4

# "Recently flaky" lookback for the soft-regression discount.
_RECENT_FLAKE_WINDOW_MS = 7 * 24 * 3600 * 1000

_CLASSIFICATION_DDL = f"""
-- (regression_class + test_flake_stats are dropped by actual type in
-- Python before this runs — DROP TABLE/VIEW can't be mixed safely here.)

-- Recent pass/fail tally per (mode, test_id) over clean **upstream**
-- runs (the tracked-ref CI worktrees only). Restricting to upstream is
-- essential: it measures whether a test was flaky on the gold-standard
-- lineage *beforehand*, not whether it merely failed on some in-flight
-- branch — otherwise a genuine branch regression (pass upstream, fail
-- on branch) would look "flaky" and be wrongly softened. `no_result`
-- (an infra non-outcome, ~1% background rate) is NOT counted as a fail,
-- so it never inflates the flake signal. A pure live derivation; kept
-- cheap by `idx_runs_worktree`.
CREATE VIEW test_flake_stats AS
SELECT rr.mode, rr.test_id,
       COUNT(*) AS n_recent,
       SUM(CASE WHEN rr.verdict = 'pass' THEN 1 ELSE 0 END) AS n_pass,
       SUM(CASE WHEN rr.verdict = 'fail' THEN 1 ELSE 0 END) AS n_fail,
       CASE WHEN SUM(CASE WHEN rr.verdict = 'pass' THEN 1 ELSE 0 END) > 0
             AND SUM(CASE WHEN rr.verdict = 'fail' THEN 1 ELSE 0 END) > 0
            THEN 1 ELSE 0 END AS recent_flaky
  FROM run_results rr
  JOIN runs r ON r.run_id = rr.run_id
 WHERE r.dirty_hash IS NULL
   AND rr.finished_ts_ms >
       (CAST(strftime('%s','now') AS INTEGER) * 1000 - {_RECENT_FLAKE_WINDOW_MS})
   AND r.worktree_path IN (SELECT ci_worktree FROM tracked_refs)
 GROUP BY rr.mode, rr.test_id;

-- Per-(branch, test, mode) regression classification. Keys off the
-- freshest *definitive* verdict (most recent pass/fail, IGNORING
-- `no_result`): a test whose only branch result is an infra `no_result`
-- is classified `no_result`, never a regression; and a real `fail`
-- isn't masked by a later `no_result` hiccup. A regression requires a
-- definitive `pass` at the merge-base baseline and a definitive `fail`
-- on the branch.
CREATE VIEW regression_class AS
WITH relevant(sha) AS (
    SELECT branch_sha   FROM branch_baseline
    UNION
    SELECT baseline_sha FROM branch_baseline
),
ranked AS (
    -- Definitive verdicts (pass/fail) sorted ahead of no_result, then
    -- newest-first, so rn_def=1 is the freshest *definitive* verdict
    -- (or a no_result row iff the test produced nothing but no_result).
    SELECT r.commit_sha AS sha, rr.mode, rr.test_id, rr.verdict,
           ROW_NUMBER() OVER (
               PARTITION BY r.commit_sha, rr.mode, rr.test_id
               ORDER BY CASE WHEN rr.verdict IN ('pass','fail')
                             THEN 0 ELSE 1 END,
                        rr.finished_ts_ms DESC) AS rn_def
      FROM run_results rr
      JOIN runs r ON r.run_id = rr.run_id
     WHERE r.dirty_hash IS NULL
       AND r.commit_sha IN (SELECT sha FROM relevant)
),
sha_state AS MATERIALIZED (
    SELECT sha, mode, test_id,
           COUNT(*) AS n,
           SUM(CASE WHEN verdict = 'pass' THEN 1 ELSE 0 END) AS n_pass,
           SUM(CASE WHEN verdict = 'fail' THEN 1 ELSE 0 END) AS n_fail,
           SUM(CASE WHEN verdict NOT IN ('pass','fail')
                    THEN 1 ELSE 0 END) AS n_other,
           CASE WHEN SUM(CASE WHEN verdict='pass' THEN 1 ELSE 0 END) > 0
                 AND SUM(CASE WHEN verdict='fail' THEN 1 ELSE 0 END) > 0
                THEN 1 ELSE 0 END AS flaky_atsha,
           MAX(CASE WHEN rn_def = 1 AND verdict IN ('pass','fail')
                    THEN verdict END) AS freshest_def
      FROM ranked
     GROUP BY sha, mode, test_id
),
universe AS (
    -- Every (branch, mode, test_id) worth a verdict: covered at the
    -- branch sha OR at its baseline. Driving from this UNION (rather
    -- than an inner join on the branch sha) is what lets a test that
    -- exists in the comparable universe but simply hasn't run at the
    -- branch yet surface as `not_run` instead of vanishing — so a
    -- thin/partial run can't be mistaken for "clean". UNION of two
    -- equality joins (deduped) is cheaper than one OR-join.
    SELECT bb.branch, bb.ref, bb.branch_sha, bb.baseline_sha,
           s.mode, s.test_id
      FROM branch_baseline bb
      JOIN sha_state s ON s.sha = bb.branch_sha
    UNION
    SELECT bb.branch, bb.ref, bb.branch_sha, bb.baseline_sha,
           s.mode, s.test_id
      FROM branch_baseline bb
      JOIN sha_state s ON s.sha = bb.baseline_sha
)
SELECT
    u.branch, u.ref, u.branch_sha, u.baseline_sha,
    u.mode, u.test_id,
    b.freshest_def AS baseline_verdict,
    b.n            AS baseline_n,
    b.flaky_atsha  AS baseline_atsha_flaky,
    a.freshest_def AS branch_verdict,
    a.n            AS branch_n,
    a.n_fail       AS branch_n_fail,
    a.n_other      AS branch_n_noresult,
    a.flaky_atsha  AS branch_atsha_flaky,
    COALESCE(f.recent_flaky, 0) AS recent_flaky,
    COALESCE(f.n_pass, 0)       AS recent_pass,
    COALESCE(f.n_fail, 0)       AS recent_fail,
    CASE
      WHEN a.n IS NULL                                   THEN 'not_run'
      WHEN a.freshest_def = 'pass' AND a.flaky_atsha = 0 THEN 'ok'
      WHEN a.freshest_def = 'pass' AND a.flaky_atsha = 1 THEN 'flaky_pass'
      WHEN a.freshest_def IS NULL                        THEN 'no_result'
      WHEN b.freshest_def IS NULL                        THEN 'new_fail'
      WHEN b.freshest_def = 'fail'                       THEN 'preexisting_fail'
      WHEN COALESCE(f.recent_flaky, 0) = 1
        OR b.flaky_atsha = 1                             THEN 'soft_regression'
      ELSE 'hard_regression'
    END AS classification,
    CASE
      WHEN a.n IS NULL                                       THEN 'n/a'
      WHEN a.freshest_def = 'pass' OR a.freshest_def IS NULL THEN 'n/a'
      WHEN b.freshest_def IS NULL                            THEN 'low'
      WHEN b.freshest_def = 'fail'                           THEN 'n/a'
      WHEN COALESCE(f.recent_flaky, 0) = 1
        OR b.flaky_atsha = 1                                 THEN 'low'
      WHEN a.n_fail >= 2 AND a.n_pass = 0
       AND COALESCE(f.n_pass, 0) >= 3                        THEN 'high'
      WHEN COALESCE(f.n_pass, 0) >= 1                        THEN 'medium'
      ELSE 'low'
    END AS confidence
  FROM universe u
  LEFT JOIN sha_state a
         ON a.sha = u.branch_sha AND a.mode = u.mode AND a.test_id = u.test_id
  LEFT JOIN sha_state b
         ON b.sha = u.baseline_sha AND b.mode = u.mode AND b.test_id = u.test_id
  LEFT JOIN test_flake_stats f
         ON f.mode = u.mode AND f.test_id = u.test_id;
"""


def _ensure_classification_schema(conn: sqlite3.Connection) -> None:
    """Create the regression-classification schema: the one materialized
    table SQL can't derive (`branch_baseline`, git merge-bases), the
    index that keeps the `test_flake_stats` view cheap, and the
    `test_flake_stats` / `regression_class` VIEWs.

    Idempotent. The views are (re)defined only when their meta-keyed
    definition version changes, so steady-state connections do no schema
    writes (no churn / schema-cookie bumps). The version bump also
    retires the v1 materialized `test_flake_stats` table in place — a
    derived cache, so dropping it loses no data and needs no
    SCHEMA_VERSION bump."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS branch_baseline (
            branch_sha     TEXT NOT NULL PRIMARY KEY,
            baseline_sha   TEXT NOT NULL,
            ref            TEXT,
            branch         TEXT,
            computed_at_ms INTEGER NOT NULL
        );
        -- Lets the test_flake_stats view seek the upstream (tracked-ref
        -- CI worktree) runs instead of scanning all of `runs`.
        CREATE INDEX IF NOT EXISTS idx_runs_worktree
            ON runs(worktree_path);
        """
    )
    row = conn.execute(
        "SELECT value FROM meta WHERE key = 'classification_schema_version'"
    ).fetchone()
    if row is not None and int(row[0]) == _CLASSIFICATION_SCHEMA_VERSION:
        return
    # Drop dependent objects by their ACTUAL type before recreating.
    # `test_flake_stats` may be a v1 materialized TABLE or a v2+ VIEW;
    # `DROP TABLE/VIEW IF EXISTS` raises on a type mismatch (IF EXISTS
    # only suppresses "doesn't exist"), so detect the type first.
    conn.execute("DROP VIEW IF EXISTS regression_class")
    tfs = conn.execute(
        "SELECT type FROM sqlite_master WHERE name = 'test_flake_stats'"
    ).fetchone()
    if tfs is not None and tfs[0] in ("table", "view"):
        conn.execute(f'DROP {tfs[0].upper()} IF EXISTS test_flake_stats')
    conn.executescript(_CLASSIFICATION_DDL)
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) "
        "VALUES('classification_schema_version', ?)",
        (str(_CLASSIFICATION_SCHEMA_VERSION),),
    )


def _refresh_branch_baseline(conn: sqlite3.Connection, canonical: Path) -> int:
    """Recompute `branch_baseline` for every live branch (agent
    worktrees + tracked refs): map each branch HEAD to its
    `merge-base` with the most-recent tracked upstream. Returns the
    number of rows written. Best-effort; git failures skip a row."""
    now = now_ms()
    candidates: list[tuple[str, str]] = []
    for wt in _list_worktrees(canonical):
        if wt.get("branch") and wt.get("head"):
            candidates.append((wt["head"], wt["branch"]))
    for r in conn.execute("SELECT ref FROM tracked_refs"):
        ref = r["ref"]
        rh = (_resolve_ref_head(canonical, ref)
              or _resolve_ref_head(canonical, f"origin/{ref}"))
        if rh:
            candidates.append((rh, ref))
    rows: list[tuple] = []
    seen: set[str] = set()
    for head, label in candidates:
        if head in seen:
            continue
        seen.add(head)
        base = _pick_baseline_ref(conn, canonical, head)
        if base is None:
            continue
        rows.append((head, base["merge_base"], base["ref"], label, now))
    conn.execute("DELETE FROM branch_baseline")
    conn.executemany(
        "INSERT OR REPLACE INTO branch_baseline"
        "(branch_sha, baseline_sha, ref, branch, computed_at_ms) "
        "VALUES (?,?,?,?,?)",
        rows,
    )
    return len(rows)


def _refresh_classification_inputs(conn: sqlite3.Connection,
                                   canonical: Path) -> None:
    """Refresh the one materialized classification input,
    `branch_baseline` (git merge-bases). Called once per supervisor
    cycle. `test_flake_stats` is a live view and needs no refresh.
    Best-effort — never aborts the cycle."""
    try:
        _refresh_branch_baseline(conn, canonical)
    except sqlite3.Error as e:
        print(f"[auto] classification refresh failed: {e}", file=sys.stderr)



def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Apply the canonical DDL if the store is empty. Read from the
    shared producer file so there's only one DDL source. Idempotent.
    """
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
    ).fetchone()
    if row is not None:
        return
    rs = (
        Path(__file__).resolve().parent.parent
        / "tests" / "common" / "dashboard_store.rs"
    ).read_text()
    start = rs.index("CREATE TABLE runs")
    end = rs.index('"#;', start)
    ddl = rs[start:end]
    conn.executescript(ddl)
    conn.execute(
        "INSERT INTO meta(key, value) VALUES('schema_version', ?)",
        (str(SCHEMA_VERSION_EXPECTED),),
    )


def check_schema(conn: sqlite3.Connection) -> None:
    row = conn.execute(
        "SELECT value FROM meta WHERE key='schema_version'"
    ).fetchone()
    if not row:
        sys.exit("dashboard: meta.schema_version missing — sqlite store not initialized")
    actual = int(row[0])
    if actual != SCHEMA_VERSION_EXPECTED:
        sys.exit(
            f"dashboard: schema_version {actual} != expected "
            f"{SCHEMA_VERSION_EXPECTED}.\n"
            "  Producer and consumer are out of sync; update one of them. "
            "Run a fresh integration test to recreate the store.\n"
            "  If this store predates a column rename, migrate it in "
            "place with `dashboard.py migrate` (lossless)."
        )


def _schema_version(conn: sqlite3.Connection) -> Optional[int]:
    row = conn.execute(
        "SELECT value FROM meta WHERE key='schema_version'"
    ).fetchone()
    if not row:
        return None
    try:
        return int(row[0])
    except (TypeError, ValueError):
        return None


# Canonical v4 `latest_results` view text, kept identical to the
# fresh DDL in `tests/common/dashboard_store.rs` so a migrated store
# and a freshly-created one are schema-identical.
_LATEST_RESULTS_VIEW_V4 = """
CREATE VIEW latest_results AS
SELECT rr.test_id, rr.mode, rr.verdict, rr.finished_ts_ms,
       rr.suite, rr."group", rr.run_id
  FROM run_results rr
  JOIN (
      SELECT test_id, mode, MAX(finished_ts_ms) AS max_ts
        FROM run_results
       GROUP BY test_id, mode
  ) latest
    ON latest.test_id = rr.test_id
   AND latest.mode   = rr.mode
   AND latest.max_ts = rr.finished_ts_ms;
"""


def migrate_v3_to_v4(conn: sqlite3.Connection) -> bool:
    """In-place, lossless v3 → v4 migration. Returns True if it
    migrated, False if the store was already at v4 (idempotent no-op).

    v4 renames `run_results.pass` → `mode` (it holds the trial pass
    name `native`/`litebox`, which collided with the `verdict`
    pass/fail outcome) and lower-cases the stored verdict token
    `FAIL` → `fail` (the producer now emits lower-case end to end).
    Both are pure renames/rewrites — every row is preserved.

    SQLite's schema-aware `ALTER TABLE … RENAME COLUMN` propagates
    the rename to the primary key and both indexes automatically
    (index *names* are unchanged, matching the fresh DDL). The
    `latest_results` view is dropped and recreated from the canonical
    v4 text so a migrated store is identical to a fresh one.
    """
    ver = _schema_version(conn)
    if ver == SCHEMA_VERSION_EXPECTED:
        return False
    if ver != 3:
        raise SystemExit(
            f"dashboard: cannot migrate schema_version {ver} → "
            f"{SCHEMA_VERSION_EXPECTED}; expected a v3 store."
        )
    cols = {r[1] for r in conn.execute("PRAGMA table_info(run_results)")}
    conn.execute("BEGIN")
    try:
        if "pass" in cols and "mode" not in cols:
            # Drop every persisted object that references the old
            # column before the rename. `latest_results` is recreated
            # below from canonical v4 text; `state_rows` /
            # `state_test_pass` are regenerated per-connection by
            # `_ensure_views` (older code persisted `state_test_pass`
            # as a view — that stale copy must go too). Drop by actual
            # type so a view-vs-table mismatch can't wedge the rename.
            for obj in ("latest_results", "state_test_pass", "state_rows"):
                row = conn.execute(
                    "SELECT type FROM sqlite_master WHERE name = ?", (obj,)
                ).fetchone()
                if row and row[0] in ("view", "table"):
                    conn.execute(f'DROP {row[0].upper()} IF EXISTS "{obj}"')
            conn.execute('ALTER TABLE run_results RENAME COLUMN "pass" TO mode')
            conn.execute(_LATEST_RESULTS_VIEW_V4)
        conn.execute("UPDATE run_results SET verdict='fail' WHERE verdict='FAIL'")
        conn.execute(
            "UPDATE meta SET value=? WHERE key='schema_version'",
            (str(SCHEMA_VERSION_EXPECTED),),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return True


# ─── Time helpers ────────────────────────────────────────────────────


def now_ms() -> int:
    return int(time.time() * 1000)


def fmt_age_ms(delta_ms: int) -> str:
    if delta_ms < 0:
        return "future"
    secs = delta_ms // 1000
    if secs < 60:
        return f"{secs}s"
    mins = secs // 60
    if mins < 60:
        return f"{mins}m"
    hours = mins // 60
    if hours < 48:
        return f"{hours}h"
    days = hours // 24
    return f"{days}d"


def short_sha(sha: Optional[str]) -> str:
    return (sha or "?")[:8]


def _branch_display(branch: Optional[str]) -> str:
    """Normalize stale `runs.branch="HEAD"` sentinel values for
    display. Pre-fix producer wrote the literal string "HEAD" for
    any detached-HEAD worktree (most CI runs), so already-recorded
    rows have `branch="HEAD"`. Render those as `<detached>` so the
    table doesn't pretend "HEAD" is a real branch name.
    """
    if branch is None or branch == "":
        return "—"
    if branch == "HEAD":
        return "<detached>"
    return branch


# ─── Trend helpers ───────────────────────────────────────────────────


def _state_filter(
    commit_sha: str,
    dirty_hash: Optional[str],
    worktree_path: Optional[str],
) -> tuple[str, tuple]:
    """Return ``(where_clause, params)`` selecting exactly one
    state's rows from the view tables. The view tables expose
    ``commit_sha`` / ``dirty_hash`` / ``state_wt`` — ``state_wt``
    is the key-bearing column (NULL when the row is clean,
    otherwise the worktree path).

    Centralizes the clean-vs-dirty NULL handling so individual
    aggregators can't drift apart (e.g. one using ``state_wt = ?``
    where another uses ``state_wt IS NULL``).
    """
    if dirty_hash is None:
        return (
            "commit_sha = ? AND dirty_hash IS NULL AND state_wt IS NULL",
            (commit_sha,),
        )
    return (
        "commit_sha = ? AND dirty_hash = ? AND state_wt = ?",
        (commit_sha, dirty_hash, worktree_path),
    )


def state_verdicts(
    conn: sqlite3.Connection, commit_sha: str, dirty_hash: Optional[str],
    worktree_path: Optional[str] = None,
) -> dict[tuple[str, str], str]:
    """Return `{(test_id, pass): freshest_verdict}` at this state.

    The state key shape (clean vs dirty) is encoded in the
    `state_test_pass` view's grouping; this just filters that
    view via `_state_filter`. No window functions or in-Python
    tallying — all the freshest-per-(state, test_id, pass) work
    is done once in the view.
    """
    where, params = _state_filter(commit_sha, dirty_hash, worktree_path)
    rows = conn.execute(
        f"SELECT test_id, mode, freshest_verdict "
        f"  FROM state_test_pass WHERE {where}",
        params,
    )
    return {(r["test_id"], r["mode"]): r["freshest_verdict"] for r in rows}


def state_delta(
    prev: dict[tuple[str, str], str],
    this: dict[tuple[str, str], str],
) -> tuple[set, set, set]:
    """Compare two states, return (regressions, fixes, newly_covered)
    as sets of (test_id, pass) tuples.

    * regressions = passed in prev → not-pass in this
    * fixes      = not-pass in prev → passed in this
    * newly      = absent in prev → present in this (any verdict)
    """
    regressions = {k for k in this if k in prev and prev[k] == "pass" and this[k] != "pass"}
    fixes      = {k for k in this if k in prev and prev[k] != "pass" and this[k] == "pass"}
    newly      = {k for k in this if k not in prev}
    return regressions, fixes, newly


_SPARK_CHARS = "▁▂▃▄▅▆▇█"


def sparkline(values: list[int]) -> str:
    """Render a list of ints as a unicode-block sparkline."""
    if not values:
        return ""
    lo = min(values)
    hi = max(values)
    if hi == lo:
        return _SPARK_CHARS[-1] * len(values)
    out = []
    for v in values:
        idx = int((v - lo) / (hi - lo) * (len(_SPARK_CHARS) - 1))
        out.append(_SPARK_CHARS[idx])
    return "".join(out)


# ─── Render ──────────────────────────────────────────────────────────


def render(conn: sqlite3.Connection, state_dir: Path) -> str:
    """Build the `summary.md` text from sqlite. Two orthogonal
    dimensions per (pass, ref):

      * Coverage  — # of (test_id, pass) with a clean run at ref-tip
                    / runs.universe_size, expressed as covered/total.
      * Pass rate — of the covered set, how many pass vs FAIL.

    Plus a global "latest result per (test_id, pass)" view, current
    FAILs grouped by worktree, and recent runs.
    """
    parts: list[str] = ["# litebox integration-test dashboard\n"]
    canonical_render = _canonical_worktree_for_render(state_dir)
    live_branches = _live_branches(conn, canonical_render)
    parts.append(_render_meta(conn, state_dir))
    parts.append(_render_leases(conn))
    parts.append(_render_velocity(conn))
    parts.append(_render_tracked_refs(conn))
    parts.append(_render_agent_worktrees(conn, state_dir))
    parts.append(_render_result_groups(conn, live_branches))
    parts.append(_render_suite_group_breakdown(conn))
    parts.append(_render_current_fails(conn))
    parts.append(_render_recent_runs(conn, live_branches))
    parts.append(_render_footer(conn, state_dir))
    return "\n".join(p for p in parts if p)


def _render_leases(conn: sqlite3.Connection) -> str:
    """One-line summary of live cross-session harness leases.

    Sourced from `harness_leases`, the additive coordination table.
    Old harnesses that predate the table never INSERT into it and
    are invisible here — that's expected (they're uncoordinated).
    """
    try:
        rows = conn.execute(
            "SELECT pid, heartbeat_at_ms FROM harness_leases"
        ).fetchall()
    except sqlite3.OperationalError:
        # Table doesn't exist (older DB, no new-harness has connected
        # yet to apply ENSURE_LEASES_DDL). Silently skip.
        return ""
    now = now_ms()
    stale_ms = 30_000
    live = [r for r in rows if (now - r["heartbeat_at_ms"]) < stale_ms]
    if not live:
        return ""
    n = len(live)
    # Mirror the harness's dynamic_dispatch_cap rule:
    #   my_cap_now = max(1, GLOBAL_CAP / live)
    # We can't know each harness's intrinsic cap or GLOBAL_CAP from
    # the dashboard side without more metadata. Show just N and the
    # per-cap rule.
    return (
        f"_{n} live harness lease(s)._ Per-harness dispatch cap = "
        f"`max(1, LITEBOX_GLOBAL_JOBS / {n})` (default global = `nproc`)."
        "\n"
    )


def _render_velocity(conn: sqlite3.Connection) -> str:
    """One-line throughput pulse: runs / newly-covered tests /
    verdict flips in the last 24h. Surfaces "are we making progress
    in real time" without having to scan history.
    """
    now = now_ms()
    cutoff = now - 24 * 3600 * 1000
    n_runs = conn.execute(
        "SELECT COUNT(*) FROM runs WHERE started_ts_ms > ?", (cutoff,)
    ).fetchone()[0] or 0

    # Newly covered = (test_id, pass) whose FIRST EVER finished_ts_ms
    # falls in the 24h window. Honest "tests we'd never seen before."
    newly_covered = conn.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT test_id, mode, MIN(finished_ts_ms) AS first_ts
              FROM run_results
             GROUP BY test_id, mode
        ) WHERE first_ts > ?
        """,
        (cutoff,),
    ).fetchone()[0] or 0

    # Verdict flips = (test_id, pass) that have BOTH a pass AND a
    # non-pass row inside the 24h window. Picks up flakes + real
    # regressions/fixes that landed today.
    flips = conn.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT test_id, mode
              FROM run_results
             WHERE finished_ts_ms > ?
             GROUP BY test_id, mode
            HAVING SUM(CASE WHEN verdict = 'pass' THEN 1 ELSE 0 END) > 0
               AND SUM(CASE WHEN verdict <> 'pass' THEN 1 ELSE 0 END) > 0
        )
        """,
        (cutoff,),
    ).fetchone()[0] or 0

    return (
        "## Velocity (last 24h)\n\n"
        f"_{n_runs} runs · +{newly_covered} newly covered "
        f"(test_id, pass) pairs · {flips} verdict flips_\n"
    )


def _render_meta(conn: sqlite3.Connection, state_dir: Path) -> str:
    n_runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] or 0
    n_results = conn.execute("SELECT COUNT(*) FROM run_results").fetchone()[0] or 0
    universe = conn.execute(
        "SELECT universe_size FROM runs WHERE universe_size IS NOT NULL"
        " ORDER BY run_id DESC LIMIT 1"
    ).fetchone()
    universe_str = (
        f"{universe[0]} trials registered"
        if universe is not None
        else "universe size unknown"
    )
    return (
        f"_State dir_: `{state_dir}` · "
        f"_{n_runs} runs_ · _{n_results} result rows_ · _{universe_str}_\n"
    )


def _render_tracked_refs(conn: sqlite3.Connection) -> str:
    """Per-ref coverage + pass/fail headline. Two orthogonal numbers."""
    refs = conn.execute(
        "SELECT ref, ci_worktree FROM tracked_refs ORDER BY ref"
    ).fetchall()
    if not refs:
        return (
            "## Tracked refs\n\n"
            "_No refs tracked yet. Register one with_ "
            "`dashboard.py track <ref> <ci_worktree>` _to start "
            "autonomous backfill._\n"
        )
    universe = conn.execute(
        "SELECT universe_size FROM runs WHERE universe_size IS NOT NULL"
        " ORDER BY run_id DESC LIMIT 1"
    ).fetchone()
    universe_n = (universe[0] if universe else 0) or 0
    # Per-pass universe: distinct test_ids ever observed per pass.
    # See _render_result_groups for rationale (universe_size from runs
    # is the grand total across passes — using it as per-pass total
    # makes coverage look ~50% even at full per-pass coverage).
    per_pass_universe: dict[str, int] = {
        r["mode"]: r["n"]
        for r in conn.execute(
            'SELECT mode, COUNT(DISTINCT test_id) AS n '
            'FROM run_results GROUP BY mode'
        )
    }

    lines = ["## Tracked refs\n",
             "| Ref | Worktree | Pass | HEAD | Coverage trend "
             "| native known | native cov | native pass | native fail | native flaky "
             "| litebox known | litebox cov | litebox pass | litebox fail | litebox flaky |",
             "|---|---|---|---|---"
             "|---:|---:|---:|---:|---:"
             "|---:|---:|---:|---:|---:|"]
    for r in refs:
        ref = r["ref"]
        ci_wt = r["ci_worktree"]
        head_sha = _git_head(ci_wt)
        if head_sha is None:
            lines.append(
                f"| `{ref}` | `{ci_wt}` | — | _missing_ | — "
                f"| — | — | — | — | — | — | — | — | — | — |"
            )
            continue
        cells: list[str] = []
        for pass_name in ("native", "litebox"):
            covered, n_pass, n_fail = _coverage_pass_fail(
                conn, head_sha, pass_name
            )
            total = per_pass_universe.get(pass_name) or (universe_n // 2 if universe_n else 0)
            dirty_extra = _dirty_only_coverage(
                conn, head_sha, pass_name, ci_wt
            )
            flaky = _flaky_count(conn, head_sha, pass_name)
            cov_cell = (
                f"{covered} (+{dirty_extra} dirty)"
                if dirty_extra else str(covered)
            )
            cells.extend([
                str(total) if total else "?",
                cov_cell,
                str(n_pass),
                str(n_fail),
                str(flaky),
            ])
        last_run_age = _last_run_age_for_ci_worktree(conn, ci_wt)
        spark = _coverage_sparkline_for_worktree(conn, ci_wt)
        lines.append(
            f"| `{ref}` | `{Path(ci_wt).name}` | {last_run_age} | "
            f"`{short_sha(head_sha)}` | `{spark}` | "
            + " | ".join(cells) + " |"
        )
    lines.append("")
    lines.append(
        "_`known` = distinct `test_id`s ever observed for that pass "
        "across all shas (so `native known` ≠ `litebox known` reflects "
        "pass-only tests, e.g. litebox-only `copilot::tui.*`). "
        "`cov` = test_ids with a verdict at **this** sha (clean only). "
        "`pass`/`fail` = **freshest** verdict per test_id — so a test "
        "that failed and then passed on retry counts as `pass`, not "
        "`fail`. `cov = pass + fail` always holds. "
        "`flaky` ⊆ `pass` = test_ids whose freshest is pass but had "
        "at least one fail row at this sha (retry-recovered). High "
        "`flaky` is a smell even if `fail` is 0. "
        "`+N dirty` next to `cov` = test_ids with sha-matching rows "
        "from this tracked ref's own worktree with uncommitted "
        "changes (almost always 0 for a checkout-only `ci_worktree`; "
        "non-zero would mean someone edited files in the tracked "
        "worktree itself — a clean re-run there would add them to "
        "`cov`). Dirty work from sibling worktrees on the same sha "
        "is **not** counted here — that bookkeeping belongs to those "
        "worktrees, not to the tracked ref. "
        "`known − cov − dirty` = tests in the historical universe "
        "this sha hasn't run cleanly in this worktree (e.g. "
        "extra-cost classes off by default, copilot trials in "
        "token-less envs, or tests so far only seen in other "
        "worktrees' dirty work)._"
    )
    return "\n".join(lines) + "\n"


def _coverage_sparkline_for_worktree(
    conn: sqlite3.Connection, ci_worktree: str, n: int = 10,
) -> str:
    """Per-tracked-ref coverage trend: pass-counts at successive
    clean `(commit_sha)` cycles observed from this CI worktree,
    derived from `run_results` (per-trial signal) rather than
    `runs.pass_count` (per-cargo-invocation summary that can
    bake in a 0 from a half-finished cycle).

    A "cycle" here is a distinct `commit_sha` produced by this
    worktree, clean state only. For each such sha we count
    distinct test_ids whose freshest verdict (within that sha,
    this worktree, clean) is `pass`. Last `n` cycles
    chronological.
    """
    sha_rows = conn.execute(
        """
        SELECT r.commit_sha, MAX(rr.finished_ts_ms) AS newest_ms
          FROM run_results rr
          JOIN runs r ON r.run_id = rr.run_id
         WHERE r.worktree_path = ? AND r.dirty_hash IS NULL
         GROUP BY r.commit_sha
         ORDER BY newest_ms DESC
         LIMIT ?
        """,
        (ci_worktree, n),
    ).fetchall()
    if not sha_rows:
        return ""
    shas = [r["commit_sha"] for r in reversed(sha_rows)]  # chronological
    values: list[int] = []
    for sha in shas:
        n_pass = conn.execute(
            """
            WITH freshest AS (
                SELECT rr.test_id, rr.mode, rr.verdict,
                       ROW_NUMBER() OVER (
                           PARTITION BY rr.test_id, rr.mode
                           ORDER BY rr.finished_ts_ms DESC
                       ) AS rn
                  FROM run_results rr
                  JOIN runs r ON r.run_id = rr.run_id
                 WHERE r.commit_sha = ?
                   AND r.worktree_path = ?
                   AND r.dirty_hash IS NULL
            )
            SELECT COUNT(*) FROM freshest
             WHERE rn = 1 AND verdict = 'pass'
            """,
            (sha, ci_worktree),
        ).fetchone()[0] or 0
        values.append(n_pass)
    return f"{sparkline(values)}  {values[0]}→{values[-1]}"


def _git_head(worktree: str) -> Optional[str]:
    if not Path(worktree).is_dir():
        return None
    try:
        return subprocess.run(
            ["git", "-C", worktree, "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        return None


def _remote_for_ref(worktree: str, ref: str) -> Optional[str]:
    """Return the remote name if `ref`'s first segment matches one of
    the worktree's configured remotes, else None.

    Used so the auto driver only runs `git fetch` for refs that
    genuinely live on a remote (e.g. `origin/wportnoy/foo`) — local
    branch refs (`wportnoy/foo`) skip the fetch entirely.
    """
    if "/" not in ref:
        return None
    candidate = ref.split("/", 1)[0]
    try:
        out = subprocess.run(
            ["git", "-C", worktree, "remote"],
            check=True, capture_output=True, text=True,
        ).stdout
    except subprocess.CalledProcessError:
        return None
    if candidate in out.split():
        return candidate
    return None


# ─── Agent worktree coverage ─────────────────────────────────────────
#
# "Agent worktrees" = any worktree visible to the canonical clone via
# `git worktree list` that is NOT registered as a `tracked_refs.ci_worktree`.
# These are typically per-session work branches owned by coding agents.
# The supervisor opportunistically runs short `--fill` cycles against
# them when they're idle, so the dashboard can surface regressions vs
# the tracked-ref baseline the agent forked from. No branch-name
# hardcoding — tracked_refs is the source of truth for "already
# permanently covered;" everything else is agent work.


def _canonical_worktree(args: argparse.Namespace, state_dir: Path) -> Path:
    """Resolve the canonical clone root used for `git worktree list`
    and merge-base queries. Precedence: --canonical-worktree arg >
    state_dir.parent."""
    val = getattr(args, "canonical_worktree", None) if args is not None else None
    if val:
        return Path(val).resolve()
    return state_dir.parent.resolve()


def _list_worktrees(canonical: Path) -> list[dict]:
    """Parse `git worktree list --porcelain` into a list of
    `{path, head, branch}` dicts. `branch` is None for detached HEAD."""
    try:
        out = subprocess.run(
            ["git", "-C", str(canonical), "worktree", "list", "--porcelain"],
            check=True, capture_output=True, text=True, timeout=15,
        ).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError):
        return []
    worktrees: list[dict] = []
    cur: dict = {}
    for line in out.splitlines():
        if line.startswith("worktree "):
            if cur:
                worktrees.append(cur)
            cur = {"path": line[len("worktree "):].strip(),
                   "head": None, "branch": None}
        elif line.startswith("HEAD "):
            cur["head"] = line[len("HEAD "):].strip()
        elif line.startswith("branch "):
            ref = line[len("branch "):].strip()
            if ref.startswith("refs/heads/"):
                ref = ref[len("refs/heads/"):]
            cur["branch"] = ref
        elif line == "detached":
            cur["branch"] = None
    if cur:
        worktrees.append(cur)
    return worktrees


def _tracked_ci_worktree_paths(conn: sqlite3.Connection) -> set[str]:
    """Resolved-absolute set of `tracked_refs.ci_worktree` paths."""
    out: set[str] = set()
    for r in conn.execute("SELECT ci_worktree FROM tracked_refs"):
        try:
            out.add(str(Path(r["ci_worktree"]).resolve()))
        except (OSError, ValueError):
            out.add(r["ci_worktree"])
    return out


def _live_branches(conn: sqlite3.Connection, canonical: Path) -> set[str]:
    """Branches that exist *right now*, used to filter dead-branch
    rows out of render sections (data stays in sqlite). Union of:

      * Local heads in the canonical clone (`git for-each-ref
        refs/heads/`). This covers every worktree's checked-out
        branch plus any unchecked local branches.
      * `tracked_refs.ref` entries (with any leading `origin/`
        stripped, since `runs.branch` records the bare branch
        name even when the tracked ref is `origin/<name>`).

    Returns an empty set on git failure (caller treats empty set
    as "don't filter" — safer than dropping every row).
    """
    out: set[str] = set()
    try:
        r = subprocess.run(
            ["git", "-C", str(canonical), "for-each-ref",
             "--format=%(refname:short)", "refs/heads/"],
            check=False, capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                line = line.strip()
                if line:
                    out.add(line)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    for row in conn.execute("SELECT ref FROM tracked_refs"):
        ref = row["ref"] or ""
        if not ref:
            continue
        out.add(ref)
        # Tracked refs are sometimes recorded as `origin/<branch>`
        # but `runs.branch` records the bare `<branch>`. Normalize.
        if "/" in ref and ref.startswith(("origin/", "upstream/")):
            out.add(ref.split("/", 1)[1])
    return out


_AGENT_SRC_GLOBS = ("**/*.rs", "**/*.toml", "**/Dockerfile", "**/*.py")
_AGENT_SRC_SKIP_DIRS = {"target", ".git", "node_modules", ".dashboard"}


def _worktree_max_source_mtime(path: Path) -> Optional[float]:
    """Best-effort: walk `path` skipping `target/`, `.git/`, return max
    mtime over source-ish files. Bounded by an internal file-count cap
    so a huge tree doesn't stall the supervisor."""
    if not path.is_dir():
        return None
    max_mt = 0.0
    seen = 0
    CAP = 5000
    try:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in _AGENT_SRC_SKIP_DIRS
                       and not d.startswith(".")]
            for f in files:
                if not (f.endswith(".rs") or f.endswith(".toml")
                        or f.endswith(".py") or f == "Dockerfile"):
                    continue
                try:
                    mt = os.stat(os.path.join(root, f)).st_mtime
                except OSError:
                    continue
                if mt > max_mt:
                    max_mt = mt
                seen += 1
                if seen >= CAP:
                    return max_mt if max_mt > 0 else None
    except OSError:
        pass
    return max_mt if max_mt > 0 else None


def _lease_pids_in_worktree(conn: sqlite3.Connection,
                            worktree: str) -> list[int]:
    """Return live-heartbeat lease PIDs whose /proc/<pid>/cwd is
    under `worktree`. Used so the supervisor doesn't race an agent's
    own in-flight `cargo test` from the same worktree."""
    try:
        rows = conn.execute(
            "SELECT pid, heartbeat_at_ms FROM harness_leases"
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    now = now_ms()
    stale = 30_000
    wt_resolved = str(Path(worktree).resolve())
    out: list[int] = []
    for r in rows:
        if (now - r["heartbeat_at_ms"]) >= stale:
            continue
        try:
            cwd = os.readlink(f"/proc/{r['pid']}/cwd")
        except OSError:
            continue
        if cwd == wt_resolved or cwd.startswith(wt_resolved + "/"):
            out.append(r["pid"])
    return out


def _discover_agent_worktrees(
    conn: sqlite3.Connection, canonical: Path,
) -> list[dict]:
    """Return list of agent-worktree dicts (subset of `_list_worktrees`)
    excluding tracked-ref CI worktrees, detached / missing HEADs, and
    worktrees that haven't diverged from a tracked ref yet (their HEAD
    is an ancestor of a tracked-ref HEAD — see
    `_drop_covered_by_tracked`)."""
    tracked = _tracked_ci_worktree_paths(conn)
    out: list[dict] = []
    for wt in _list_worktrees(canonical):
        if not wt.get("branch") or not wt.get("head"):
            continue
        path = wt.get("path") or ""
        if not path:
            continue
        try:
            resolved = str(Path(path).resolve())
        except (OSError, ValueError):
            resolved = path
        if resolved in tracked:
            continue
        # Skip canonical clone itself if it's checked out to the
        # amalgamation (or any tracked_ref branch). It's covered by
        # the tracked_ref drive already. (Kept as a name-based check
        # in addition to the ancestry filter below, since a canonical
        # checkout can sit *ahead* of a tracked `origin/<ref>`.)
        if resolved == str(canonical) and _branch_is_tracked(
            conn, wt["branch"]
        ):
            continue
        if not Path(path).is_dir():
            continue
        out.append({**wt, "path": resolved})
    # Drop worktrees whose HEAD is already contained in a tracked ref:
    # driving a shadow at the merge-base only re-tests the upstream
    # baseline under the agent's branch and splits its history.
    tracked_heads = _tracked_ref_heads(conn, canonical)
    return _drop_covered_by_tracked(
        out, tracked_heads, lambda a, b: _is_ancestor(canonical, a, b),
    )


def _branch_is_tracked(conn: sqlite3.Connection, branch: str) -> bool:
    """True if `branch` (or `origin/<branch>`) appears in tracked_refs.ref."""
    rows = conn.execute("SELECT ref FROM tracked_refs").fetchall()
    refs = {r["ref"] for r in rows}
    if branch in refs:
        return True
    # tracked refs often look like `origin/wportnoy/foo`; allow match
    # on the trailing branch path.
    for ref in refs:
        if ref.split("/", 1)[-1] == branch or ref.endswith("/" + branch):
            return True
    return False


def _agent_worktree_is_idle(wt: dict, idle_secs: int,
                            conn: sqlite3.Connection) -> tuple[bool, str]:
    """Returns (idle, reason). idle=True means safe to schedule
    opportunistic coverage."""
    pids = _lease_pids_in_worktree(conn, wt["path"])
    if pids:
        return (False, f"lease pid {pids[0]} live in worktree")
    mt = _worktree_max_source_mtime(Path(wt["path"]))
    if mt is None:
        # No source files found — treat as idle (unusual but harmless).
        return (True, "no source files seen")
    age = time.time() - mt
    if age < idle_secs:
        return (False, f"source touched {int(age)}s ago (< {idle_secs}s)")
    return (True, f"idle {int(age)}s")


def _is_ancestor(canonical: Path, ancestor: str, descendant: str) -> bool:
    """True iff commit `ancestor` is an ancestor of commit `descendant`
    in `canonical`'s object graph (i.e., `descendant` already contains
    all of `ancestor`'s history). Reflexive: a commit is its own
    ancestor."""
    if not ancestor or not descendant:
        return False
    if ancestor == descendant:
        return True
    try:
        r = subprocess.run(
            ["git", "-C", str(canonical), "merge-base",
             "--is-ancestor", ancestor, descendant],
            check=False, capture_output=True, text=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return r.returncode == 0


def _compute_tip_set(
    worktrees: list[dict],
    is_ancestor: Callable[[str, str], bool],
) -> list[dict]:
    """Return the subset of `worktrees` that are *tips* — i.e. no
    other worktree's HEAD has them as an ancestor.

    Pure-functional with an injected ancestor predicate so it can be
    unit-tested with a fake graph. Order-preserving over the input
    list.

    Cases this handles uniformly:
      * Solo worktree: trivially a tip (no others to subsume it).
      * Fan-out from session (session HEAD is ancestor of subagent
        HEADs): session is dropped, subagents are tips.
      * Merge-back into session (subagent HEADs are ancestors of
        session HEAD): subagents are dropped, session is the tip.
      * Independent worktrees: all are tips.
      * Disjoint clusters: one tip per cluster.

    Worktrees missing a `head` key are skipped entirely.
    """
    out: list[dict] = []
    for wt in worktrees:
        head = wt.get("head")
        if not head:
            continue
        subsumed = False
        for other in worktrees:
            if other is wt:
                continue
            other_head = other.get("head")
            if not other_head or other_head == head:
                continue
            if is_ancestor(head, other_head):
                # Some other worktree's HEAD contains this one's
                # entire history — testing the other subsumes us.
                subsumed = True
                break
        if not subsumed:
            out.append(wt)
    return out


def _drop_covered_by_tracked(
    worktrees: list[dict],
    tracked_ref_heads: list[str],
    is_ancestor: Callable[[str, str], bool],
) -> list[dict]:
    """Drop agent worktrees whose committed HEAD is already an
    ancestor of a tracked ref's HEAD.

    Such a worktree has no commits of its own beyond the upstream it
    forked from — its HEAD *is* the merge-base. A clean shadow
    checkout there reproduces the tracked-ref baseline (already
    covered by the tracked-ref drive), not the agent's work, and would
    record that coverage under the agent's branch at the merge-base
    sha — splitting the branch's apparent history across the
    merge-base and (once it commits) its real tip. The agent's own
    in-worktree runs cover its uncommitted work; the worktree
    reappears as a coverage target the moment it has a divergent
    commit.

    Pure-functional with an injected `is_ancestor` predicate so it can
    be unit-tested with a fake graph (mirrors `_compute_tip_set`).
    Order-preserving. Empty `tracked_ref_heads` (or unresolved heads)
    is fail-open: nothing is dropped.
    """
    if not tracked_ref_heads:
        return list(worktrees)
    out: list[dict] = []
    for wt in worktrees:
        head = wt.get("head")
        if head and any(is_ancestor(head, rh) for rh in tracked_ref_heads):
            continue
        out.append(wt)
    return out


def _agent_tip_worktrees(
    conn: sqlite3.Connection, canonical: Path,
) -> tuple[list[dict], list[dict]]:
    """Convenience wrapper: discover agent worktrees and partition
    into (tips, non_tips) using the canonical clone's object graph.
    """
    candidates = _discover_agent_worktrees(conn, canonical)
    if len(candidates) <= 1:
        # Trivial: either zero or a single solo worktree.
        return (candidates, [])
    tips = _compute_tip_set(
        candidates,
        lambda a, b: _is_ancestor(canonical, a, b),
    )
    tip_paths = {t["path"] for t in tips}
    non_tips = [w for w in candidates if w["path"] not in tip_paths]
    return (tips, non_tips)


def _merge_base(canonical: Path, a: str, b: str) -> Optional[str]:
    try:
        r = subprocess.run(
            ["git", "-C", str(canonical), "merge-base", a, b],
            check=False, capture_output=True, text=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if r.returncode != 0:
        return None
    sha = r.stdout.strip()
    return sha or None


def _commit_ts(canonical: Path, sha: str) -> Optional[int]:
    try:
        r = subprocess.run(
            ["git", "-C", str(canonical), "log", "-1", "--format=%ct", sha],
            check=False, capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    s = r.stdout.strip()
    return int(s) if s.isdigit() else None


def _resolve_ref_head(canonical: Path, ref: str) -> Optional[str]:
    try:
        r = subprocess.run(
            ["git", "-C", str(canonical), "rev-parse", ref],
            check=False, capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if r.returncode != 0:
        return None
    s = r.stdout.strip()
    return s if len(s) >= 7 else None


def _tracked_ref_heads(conn: sqlite3.Connection, canonical: Path) -> list[str]:
    """Resolved HEAD SHAs of all tracked refs (local name first, then
    `origin/<ref>`). Skips refs that don't resolve. Used by
    `_discover_agent_worktrees` to suppress opportunistic coverage of
    agent worktrees that haven't diverged from a tracked ref yet."""
    heads: list[str] = []
    for r in conn.execute("SELECT ref FROM tracked_refs"):
        ref = r["ref"]
        rh = (_resolve_ref_head(canonical, ref)
              or _resolve_ref_head(canonical, f"origin/{ref}"))
        if rh:
            heads.append(rh)
    return heads


def _pick_baseline_ref(
    conn: sqlite3.Connection, canonical: Path, agent_head: str,
) -> Optional[dict]:
    """Pick the tracked_ref whose HEAD shares the most recent
    merge-base with `agent_head` (= the upstream the agent forked
    from most recently). Returns `{ref, ci_worktree, ref_head,
    merge_base, mb_ts}` or None.

    With a single tracked_ref this trivially returns that ref.
    """
    refs = conn.execute(
        "SELECT ref, ci_worktree FROM tracked_refs"
    ).fetchall()
    if not refs:
        return None
    best: Optional[dict] = None
    best_ts = -1
    for r in refs:
        ref = r["ref"]
        # Resolve ref's tip in the canonical clone. Local-name first,
        # then origin/<ref> fallback.
        ref_head = (_resolve_ref_head(canonical, ref)
                    or _resolve_ref_head(canonical, f"origin/{ref}"))
        if not ref_head:
            continue
        mb = _merge_base(canonical, agent_head, ref_head)
        if not mb:
            continue
        ts = _commit_ts(canonical, mb) or 0
        if ts > best_ts:
            best_ts = ts
            best = {"ref": ref, "ci_worktree": r["ci_worktree"],
                    "ref_head": ref_head, "merge_base": mb, "mb_ts": ts}
    return best


def _regression_counts(
    conn: sqlite3.Connection,
    baseline_sha: str, agent_sha: str,
) -> dict[str, dict[str, int]]:
    """Compare state-scoped freshest verdicts at `baseline_sha` (clean)
    vs `agent_sha` (clean). Returns
    `{pass: {regressions, improvements, common}}`.

    "Regression" = passed at baseline, failed at agent_sha.
    "Improvement" = failed at baseline, passed at agent_sha.
    "Common" = (test_id, pass) with verdicts at both states.
    Uses the state_test_pass TEMP TABLE (clean filter via
    `state_wt IS NULL AND dirty_hash IS NULL`).
    """
    out: dict[str, dict[str, int]] = {}
    for pass_name in ("native", "litebox"):
        b = {
            r["test_id"]: r["freshest_verdict"]
            for r in conn.execute(
                "SELECT test_id, freshest_verdict FROM state_test_pass "
                " WHERE commit_sha = ? AND state_wt IS NULL AND mode = ?",
                (baseline_sha, pass_name),
            )
        }
        a = {
            r["test_id"]: r["freshest_verdict"]
            for r in conn.execute(
                "SELECT test_id, freshest_verdict FROM state_test_pass "
                " WHERE commit_sha = ? AND state_wt IS NULL AND mode = ?",
                (agent_sha, pass_name),
            )
        }
        regressions = sum(
            1 for tid, va in a.items()
            if tid in b and b[tid] == "pass" and va != "pass"
        )
        improvements = sum(
            1 for tid, va in a.items()
            if tid in b and b[tid] != "pass" and va == "pass"
        )
        common = sum(1 for tid in a if tid in b)
        out[pass_name] = {
            "regressions": regressions,
            "improvements": improvements,
            "common": common,
            "agent_cov": len(a),
            "baseline_cov": len(b),
        }
    return out


def _regression_test_ids(
    conn: sqlite3.Connection,
    baseline_sha: str, agent_sha: str, pass_name: str,
    limit: int = 20,
) -> list[str]:
    """Return up to `limit` test_ids that regressed (pass at baseline,
    fail at agent_sha) for the given pass."""
    b = {
        r["test_id"]: r["freshest_verdict"]
        for r in conn.execute(
            "SELECT test_id, freshest_verdict FROM state_test_pass "
            " WHERE commit_sha = ? AND state_wt IS NULL AND mode = ?",
            (baseline_sha, pass_name),
        )
    }
    out: list[str] = []
    for r in conn.execute(
        "SELECT test_id FROM state_test_pass "
        " WHERE commit_sha = ? AND state_wt IS NULL AND mode = ? "
        "   AND freshest_verdict <> 'pass' "
        " ORDER BY test_id",
        (agent_sha, pass_name),
    ):
        tid = r["test_id"]
        if b.get(tid) == "pass":
            out.append(tid)
            if len(out) >= limit:
                break
    return out


def _last_run_age_at_sha(conn: sqlite3.Connection, sha: str,
                        worktree_path: Optional[str] = None) -> Optional[int]:
    """Newest run_results.finished_ts_ms for clean rows at this sha.

    If `worktree_path` is given, restrict to that worktree (legacy
    callers). If None (preferred for agent-coverage), aggregate over
    every clean worktree at the sha — so opportunistic supervisor
    cycles in `<state-dir>/shadows/<branch>/` correctly count toward
    "this HEAD has been tested recently" even though their
    `runs.worktree_path` is the shadow path, not the agent's path.
    """
    if worktree_path is None:
        row = conn.execute(
            "SELECT MAX(rr.finished_ts_ms)"
            "  FROM run_results rr JOIN runs r ON r.run_id = rr.run_id"
            " WHERE r.commit_sha = ? AND r.dirty_hash IS NULL",
            (sha,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT MAX(rr.finished_ts_ms)"
            "  FROM run_results rr JOIN runs r ON r.run_id = rr.run_id"
            " WHERE r.commit_sha = ? AND r.dirty_hash IS NULL"
            "   AND r.worktree_path = ?",
            (sha, worktree_path),
        ).fetchone()
    if not row or row[0] is None:
        return None
    return int(row[0])


def _pick_opportunistic_worktree(
    conn: sqlite3.Connection,
    candidates: list[dict],
) -> Optional[dict]:
    """Round-robin selection over idle candidates, biased toward
    worktrees whose current HEAD has the stalest (or absent) coverage.

    Strategy: per candidate compute `coverage_age_ms` (None if no
    coverage yet at HEAD). Sort so None comes first (never tested),
    then oldest first. Apply round-robin tiebreak via the
    `meta` key `agent_coverage_last_picked` to ensure no single
    worktree starves the others over long runs.
    """
    if not candidates:
        return None
    last_picked_row = conn.execute(
        "SELECT value FROM meta WHERE key = 'agent_coverage_last_picked'"
    ).fetchone()
    last_picked = last_picked_row[0] if last_picked_row else None

    def keyed(c: dict) -> tuple:
        age = _last_run_age_at_sha(conn, c["head"])
        never_tested = age is None
        ms_since = (now_ms() - age) if age is not None else 10**18
        same_as_last = c["path"] == last_picked
        # Tuple: never-tested first (False < True), then deprioritize
        # the most-recently-picked, then oldest coverage first.
        return (not never_tested, same_as_last, -ms_since)

    candidates_sorted = sorted(candidates, key=keyed)
    return candidates_sorted[0]


def _pick_opportunistic_worktrees_topn(
    conn: sqlite3.Connection,
    candidates: list[dict],
    n: int,
) -> list[dict]:
    """Top-N variant of `_pick_opportunistic_worktree`. Uses the same
    sort key — never-tested first, then deprioritize last-picked, then
    oldest-coverage first — and returns the leading `n` entries (or
    fewer if the candidate list is shorter). Used by the parallel
    agent-coverage orchestrator to schedule multiple cargo cycles per
    supervisor tick. With `n == 1` this is equivalent to
    `_pick_opportunistic_worktree`.
    """
    if not candidates or n <= 0:
        return []
    last_picked_row = conn.execute(
        "SELECT value FROM meta WHERE key = 'agent_coverage_last_picked'"
    ).fetchone()
    last_picked = last_picked_row[0] if last_picked_row else None

    def keyed(c: dict) -> tuple:
        age = _last_run_age_at_sha(conn, c["head"])
        never_tested = age is None
        ms_since = (now_ms() - age) if age is not None else 10**18
        same_as_last = c["path"] == last_picked
        return (not never_tested, same_as_last, -ms_since)

    candidates_sorted = sorted(candidates, key=keyed)
    return candidates_sorted[:n]


def _record_picked(conn: sqlite3.Connection, path: str) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES('agent_coverage_last_picked', ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (path,),
    )
    conn.commit()


def _coverage_pass_fail(
    conn: sqlite3.Connection, commit_sha: str, pass_name: str,
) -> tuple[int, int, int]:
    """Return (covered, n_pass, n_fail) for the **clean** state at
    this sha, for one pass. Clean only because the Tracked refs
    table is the only caller and it reports the tracked ref's
    official position.

    Reads from the `state_test_pass` view, so `cov = pass + fail`
    is inherited from the view's per-(state, test_id, pass)
    aggregation (no double-counting on retries).
    """
    row = conn.execute(
        """
        SELECT COUNT(*) AS covered,
               SUM(CASE WHEN freshest_verdict = 'pass' THEN 1 ELSE 0 END) AS n_pass,
               SUM(CASE WHEN freshest_verdict <> 'pass' THEN 1 ELSE 0 END) AS n_fail
          FROM state_test_pass
         WHERE commit_sha = ? AND state_wt IS NULL AND mode = ?
        """,
        (commit_sha, pass_name),
    ).fetchone()
    if not row:
        return (0, 0, 0)
    return (row["covered"] or 0, row["n_pass"] or 0, row["n_fail"] or 0)


def _dirty_only_coverage(
    conn: sqlite3.Connection, commit_sha: str, pass_name: str,
    worktree_path: str,
) -> int:
    """Return the count of test_ids that have a `dirty_hash IS NOT
    NULL` row at this sha **in this worktree** but NO `dirty_hash IS
    NULL` row at the same (sha, worktree). These represent
    evidence-from-dirty-sessions-here that the clean `cov` column
    intentionally hides.

    A non-zero return is a signal that running the suite clean
    (e.g. via the supervisor's `--fill`) would likely add these to
    `cov` immediately. Surfaces "we have evidence at this sha, but
    only from sessions with uncommitted changes" — so the user can
    tell apart "untested" gaps from "tested-dirty" gaps.

    Scoped to `worktree_path` so a sibling worktree sitting on the
    same commit_sha with WIP doesn't get attributed to this tracked
    ref — same false-attribution shape the tracked-ref tag in
    result-groups guards against.
    """
    row = conn.execute(
        """
        WITH dirty_ids AS (
            SELECT DISTINCT rr.test_id
              FROM run_results rr
              JOIN runs r ON r.run_id = rr.run_id
             WHERE r.commit_sha = ? AND r.dirty_hash IS NOT NULL
               AND r.worktree_path = ?
               AND rr.mode = ?
        ),
        clean_ids AS (
            SELECT DISTINCT rr.test_id
              FROM run_results rr
              JOIN runs r ON r.run_id = rr.run_id
             WHERE r.commit_sha = ? AND r.dirty_hash IS NULL
               AND r.worktree_path = ?
               AND rr.mode = ?
        )
        SELECT COUNT(*) FROM dirty_ids
         WHERE test_id NOT IN (SELECT test_id FROM clean_ids)
        """,
        (commit_sha, worktree_path, pass_name,
         commit_sha, worktree_path, pass_name),
    ).fetchone()
    return (row[0] if row else 0) or 0


def _flaky_test_ids(
    conn: sqlite3.Connection,
    commit_sha: str,
    dirty_hash: Optional[str],
    worktree_path: Optional[str],
    pass_name: str,
) -> set[str]:
    """Return the **set** of test_ids at this state whose freshest
    verdict is pass but had at least one non-pass row at the same
    state — class-2 flakes that retry-recovered.

    Reads from the `state_test_pass` view: the freshest-vs-
    ever-failed bookkeeping is already done there, so this is one
    indexed select. `flaky ⊆ pass` and `cov = pass + fail` are
    both inherited from the view's per-(state, test_id, pass)
    grouping.
    """
    where, params = _state_filter(commit_sha, dirty_hash, worktree_path)
    rows = conn.execute(
        f"SELECT test_id FROM state_test_pass "
        f" WHERE {where} AND mode = ? "
        f"   AND freshest_verdict = 'pass' AND ever_failed = 1",
        (*params, pass_name),
    )
    return {r["test_id"] for r in rows}


def _flaky_count(
    conn: sqlite3.Connection, commit_sha: str, pass_name: str,
) -> int:
    """Clean-state flaky count for the Tracked refs table."""
    row = conn.execute(
        "SELECT COUNT(*) FROM state_test_pass "
        " WHERE commit_sha = ? AND state_wt IS NULL AND mode = ? "
        "   AND freshest_verdict = 'pass' AND ever_failed = 1",
        (commit_sha, pass_name),
    ).fetchone()
    return (row[0] if row else 0) or 0


def _last_run_age_for_ci_worktree(conn: sqlite3.Connection, wt: str) -> str:
    # Read from run_results, not runs, so the displayed "age" reflects
    # the most recent individual test completion — not the most recent
    # cargo-invocation completion. The supervisor doesn't write a
    # `runs` row until the whole cargo cycle ends (which can be 10+
    # min), so anchoring the headline on `runs` makes the dashboard
    # look idle while tests are actively streaming results in. The
    # user's intuition is "Pass = how recently did anything happen
    # here," and that's a `run_results` question.
    row = conn.execute(
        "SELECT MAX(rr.finished_ts_ms)"
        "  FROM run_results rr"
        "  JOIN runs r ON r.run_id = rr.run_id"
        " WHERE r.worktree_path = ?",
        (wt,),
    ).fetchone()
    if not row or row[0] is None:
        return "—"
    return f"{fmt_age_ms(now_ms() - int(row[0]))} ago"


def _render_result_groups(conn: sqlite3.Connection,
                          live_branches: Optional[set[str]] = None) -> str:
    """One row per `(commit_sha, dirty_hash)` partition that has any
    results. Per-pass cov/pass/fail use the freshest verdict per
    (test_id, pass) within the state (so `cov = pass + fail` always
    holds even when the same test ran twice with different outcomes).

    Adds a `Δ vs prior` column showing
    `+P passing · −R regressions · +N newly covered` against the
    state directly older than this row.

    Sorted newest-first so the current state is on top.
    """
    # Discover all states + their newest_ms and contributing
    # branches. Grouping key:
    #   clean: (commit_sha,)            — collapse all worktrees
    #   dirty: (commit_sha, dirty_hash, worktree_path)
    # The CASE expression makes worktree_path part of the key only
    # when the row is dirty, so clean rows from multiple worktrees
    # still collapse to one state (a clean tree at a sha IS the
    # same artifact) but dirty work in worktree A vs worktree B is
    # kept distinct even if their tracked diffs happen to collide.
    state_rows = conn.execute(
        """
        SELECT commit_sha, dirty_hash, state_wt,
               MAX(finished_ts_ms) AS newest_ms,
               GROUP_CONCAT(DISTINCT worktree_path) AS worktrees,
               GROUP_CONCAT(DISTINCT branch)        AS branches
          FROM state_rows
         GROUP BY commit_sha, dirty_hash, state_wt
        """
    ).fetchall()
    if not state_rows:
        return ""

    # Build the per-state verdicts dict once per state key.
    # Use freshest-per-(test_id, pass)-within-state semantics so
    # counts and delta computations agree.
    states: dict[tuple[str, Optional[str], Optional[str]], dict] = {}
    for r in state_rows:
        key = (r["commit_sha"], r["dirty_hash"], r["state_wt"])
        verdicts = state_verdicts(
            conn, r["commit_sha"], r["dirty_hash"], r["state_wt"]
        )
        states[key] = {
            "newest_ms": r["newest_ms"] or 0,
            "worktree_path": r["state_wt"],
            "worktrees": set(
                w for w in (r["worktrees"] or "").split(",") if w
            ),
            "branches": set(
                b for b in (r["branches"] or "").split(",") if b
            ),
            "verdicts": verdicts,
        }

    # Tracked-ref overlay: a row gets tagged with the tracked ref's
    # label only when the row's worktree matches the tracked ref's
    # `ci_worktree` AND the row is clean. Otherwise a different
    # worktree (e.g. an agent session) that happens to be checked
    # out at the same commit_sha as a tracked ref would inherit the
    # ref's tag and falsely implicate it in unrelated dirty work.
    tracked_by_sha: dict[str, tuple[str, str]] = {}  # sha → (ref, ci_worktree)
    for r in conn.execute("SELECT ref, ci_worktree FROM tracked_refs"):
        head = _git_head(r["ci_worktree"])
        if head:
            tracked_by_sha[head] = (r["ref"], r["ci_worktree"])

    universe = conn.execute(
        "SELECT universe_size FROM runs WHERE universe_size IS NOT NULL"
        " ORDER BY run_id DESC LIMIT 1"
    ).fetchone()
    universe_n = (universe[0] if universe else 0) or 0

    # Per-pass universe: count of distinct test_ids ever observed
    # per pass. The harness's `universe_size` is the grand total
    # across both passes (native + litebox + host::fwd) and using it
    # as the "native total" / "litebox total" column makes coverage
    # look like ~50% even at full per-pass coverage. Per-pass totals
    # are stable observables: distinct test_ids per pass.
    per_pass_universe: dict[str, int] = {
        r["mode"]: r["n"]
        for r in conn.execute(
            'SELECT mode, COUNT(DISTINCT test_id) AS n '
            'FROM run_results GROUP BY mode'
        )
    }

    now = now_ms()
    lines = ["## Result groups (per commit × dirty-state)\n",
             "| Tracked ref | Sha | Dirty | Branch(es) | Worktree(s) | Path(s) "
             "| native known | native cov | native pass | native fail | native flaky "
             "| litebox known | litebox cov | litebox pass | litebox fail | litebox flaky "
             "| Newest | Δ vs prior |",
             "|---|---|---|---|---|---"
             "|---:|---:|---:|---:|---:"
             "|---:|---:|---:|---:|---:|---|---|"]

    # Sort newest-first; for each row, the "prior" state is the
    # next entry in the list (one older in time).
    ordered: list[tuple[tuple[str, Optional[str], Optional[str]], dict]] = sorted(
        states.items(), key=lambda kv: kv[1]["newest_ms"], reverse=True
    )

    # Filter noise: hide dirty partitions with very few covered tests.
    # These come from ad-hoc `cargo test --test integration -- <filter>`
    # invocations in dev worktrees and otherwise dominate the table.
    # Clean partitions are always shown. Override with
    # LITEBOX_DASHBOARD_DIRTY_MIN_COV=N (set to 0 to disable filtering).
    dirty_min_cov = int(os.environ.get("LITEBOX_DASHBOARD_DIRTY_MIN_COV", "10"))
    hidden = 0
    hidden_dead_branch = 0
    visible: list[tuple[tuple[str, Optional[str], Optional[str]], dict]] = []
    for entry in ordered:
        (sha, dirty_hash, _wt), g = entry
        if dirty_hash and dirty_min_cov > 0:
            max_cov = max(
                _counts_from_verdicts(g["verdicts"], p)[0]
                for p in ("native", "litebox")
            )
            if max_cov < dirty_min_cov:
                hidden += 1
                continue
        # Live-branch filter: a row survives if any of its recorded
        # branches still exists in the canonical clone OR the row's
        # sha matches a tracked_ref HEAD (tracked refs are live by
        # definition — keeps the tracked-ref tag visible even if the
        # branch label happened to drift). Empty live_branches means
        # "filter disabled" (test/fallback path).
        if live_branches:
            has_live = bool(g["branches"] & live_branches)
            is_tracked = sha in tracked_by_sha and dirty_hash is None
            if not has_live and not is_tracked:
                hidden_dead_branch += 1
                continue
        visible.append(entry)

    for i, ((sha, dirty_hash, state_wt), g) in enumerate(visible):
        # Tag only when this row's worktree IS the tracked ref's
        # ci_worktree AND the row is clean. Bare sha-match would
        # falsely attribute another worktree's (dirty) work to the
        # tracked ref just because both are sitting on the same
        # commit.
        tag = ""
        if sha in tracked_by_sha and dirty_hash is None:
            ref_name, ci_wt = tracked_by_sha[sha]
            if ci_wt in g["worktrees"]:
                tag = f"_{ref_name}_"
        dirty = "⚠" if dirty_hash else ""
        wt_short = ", ".join(
            sorted(os.path.basename(w) for w in g["worktrees"])
        )
        wt_paths = ", ".join(f"`{w}`" for w in sorted(g["worktrees"]))
        branches = ", ".join(f"`{_branch_display(b)}`" for b in sorted(g["branches"])) or "—"
        cells: list[str] = []
        for pass_name in ("native", "litebox"):
            cov, n_pass, n_fail = _counts_from_verdicts(g["verdicts"], pass_name)
            # Per-pass universe; fall back to halved grand total if
            # the table is empty (very fresh DB).
            total = per_pass_universe.get(pass_name) or (universe_n // 2 if universe_n else 0)
            flaky = len(_flaky_test_ids(
                conn, sha, dirty_hash, state_wt, pass_name
            ))
            cells.extend([
                str(total) if total else "?",
                str(cov),
                str(n_pass),
                str(n_fail),
                str(flaky),
            ])
        age = fmt_age_ms(now - g["newest_ms"]) if g["newest_ms"] else "—"
        # Δ vs the immediately-older state in the sort order.
        if i + 1 < len(visible):
            prior = visible[i + 1][1]["verdicts"]
            regressions, fixes, newly = state_delta(prior, g["verdicts"])
            delta = (
                f"+{len(fixes)} fixed · −{len(regressions)} regressed · "
                f"+{len(newly)} new"
            )
        else:
            delta = "_(oldest)_"
        lines.append(
            f"| {tag} | `{short_sha(sha)}` | {dirty} | "
            f"{branches} | `{wt_short}` | {wt_paths} | "
            + " | ".join(cells) + f" | {age} | {delta} |"
        )
    if hidden:
        lines.append(
            f"\n_{hidden} dirty partition(s) hidden "
            f"(cov < {dirty_min_cov}); set "
            f"`LITEBOX_DASHBOARD_DIRTY_MIN_COV=0` to show all._"
        )
    if hidden_dead_branch:
        lines.append(
            f"\n_{hidden_dead_branch} state(s) hidden whose only "
            f"recorded branches no longer exist in the canonical "
            f"clone (rows are kept in sqlite — re-create the branch "
            f"or query `runs` directly to inspect)._"
        )
    return "\n".join(lines) + "\n"


def _counts_from_verdicts(
    verdicts: dict[tuple[str, str], str], pass_name: str,
) -> tuple[int, int, int]:
    """Reduce a state's verdicts dict to `(cov, pass, fail)` for the
    given pass. cov = number of (test_id) covered for that pass;
    cov = pass + fail (invariant, since one verdict per (test_id, pass)).
    """
    pass_subset = {k: v for k, v in verdicts.items() if k[1] == pass_name}
    cov = len(pass_subset)
    n_pass = sum(1 for v in pass_subset.values() if v == "pass")
    n_fail = cov - n_pass
    return cov, n_pass, n_fail


def _render_suite_group_breakdown(conn: sqlite3.Connection) -> str:
    """Aggregate cov / total / pass / fail per (pass, suite, group).

    Total = observed universe per (suite, group) — distinct test_ids
    seen in any pass; the producer doesn't carry a per-suite universe
    count, so this denominator stabilizes as more tests run.

    Reads from `latest_results` (freshest per (test_id, pass)) — so a
    single regression flipping a row from pass→FAIL moves the numbers
    immediately, no per-commit filtering.

    Schema v3+: suite/group are NOT NULL on `run_results`. The
    producer reads them straight from the in-process registry, so we
    no longer need cross-row fallback or prefix-map inference here.
    """
def _top_n_states(
    conn: sqlite3.Connection, n: int = 5,
) -> list[dict]:
    """Return the top-N states (newest first), with their newest_ms
    + contributing branches/worktrees. State key shape:

      * clean: `(commit_sha,)`            — collapse all worktrees
      * dirty: `(commit_sha, dirty_hash, worktree_path)`

    Honors `LITEBOX_DASHBOARD_DIRTY_MIN_COV` so trivial ad-hoc dev
    partitions don't crowd out real states.

    Each returned dict has: commit_sha, dirty_hash (None for
    clean), worktree_path (None for clean; the state-defining
    worktree when dirty), newest_ms, branches (set), worktrees
    (set — same single value when dirty, possibly multiple when
    clean).
    """
    raw = conn.execute(
        """
        SELECT commit_sha, dirty_hash, state_wt,
               MAX(finished_ts_ms) AS newest_ms,
               GROUP_CONCAT(DISTINCT worktree_path) AS worktrees,
               GROUP_CONCAT(DISTINCT branch)        AS branches
          FROM state_rows
         GROUP BY commit_sha, dirty_hash, state_wt
         ORDER BY newest_ms DESC
        """
    ).fetchall()
    dirty_min_cov = int(
        os.environ.get("LITEBOX_DASHBOARD_DIRTY_MIN_COV", "10")
    )
    out: list[dict] = []
    for r in raw:
        sha = r["commit_sha"]
        dirty_hash = r["dirty_hash"]
        state_wt = r["state_wt"]
        if dirty_hash and dirty_min_cov > 0:
            verdicts = state_verdicts(conn, sha, dirty_hash, state_wt)
            max_cov = max(
                _counts_from_verdicts(verdicts, p)[0]
                for p in ("native", "litebox")
            )
            if max_cov < dirty_min_cov:
                continue
        out.append({
            "commit_sha": sha,
            "dirty_hash": dirty_hash,
            "worktree_path": state_wt,
            "newest_ms": r["newest_ms"] or 0,
            "branches": set(
                b for b in (r["branches"] or "").split(",") if b
            ),
            "worktrees": set(
                w for w in (r["worktrees"] or "").split(",") if w
            ),
        })
        if len(out) >= n:
            break
    return out


def _format_state_header(state: dict, now: int) -> str:
    """`### sha=... · branch=... · worktree=... (path) · clean|dirty=... · (newest <age> ago)`"""
    sha = short_sha(state["commit_sha"])
    branches = (
        ",".join(_branch_display(b) for b in sorted(state["branches"]))
        if state["branches"] else "—"
    )
    wts = sorted(state["worktrees"])
    wt_basenames = ",".join(os.path.basename(w) for w in wts) if wts else "—"
    wt_paths = ",".join(wts) if wts else "—"
    if state["dirty_hash"]:
        kind = f"dirty={state['dirty_hash'][:8]}"
    else:
        kind = "clean"
    age = (
        fmt_age_ms(now - state["newest_ms"])
        if state["newest_ms"] else "—"
    )
    return (
        f"### sha=`{sha}` · branch=`{branches}` · "
        f"worktree=`{wt_basenames}` (`{wt_paths}`) · "
        f"{kind} · (newest {age} ago)"
    )


def _render_suite_group_breakdown(conn: sqlite3.Connection) -> str:
    """Per-(suite, group) coverage broken out for the **5 most
    recent (commit_sha, dirty_hash) states**, each as its own
    sub-table.

    State-scoped (filtered by sha+dirty THEN freshest per
    (test_id, pass)) so verdicts from old shas can't contaminate
    the current view. The headline state may have partial
    coverage during a long cycle — that's the honest answer;
    older complete states sit below for context.

    Total = observed universe per (suite, group) across ALL
    history — a stable denominator so a half-finished cycle
    doesn't make the totals shrink. The producer doesn't carry
    a per-suite universe count.

    Schema v3+: suite/group are NOT NULL on `run_results`.
    """
    from collections import defaultdict

    # Per-(suite,group) universe is global (across all states)
    # so denominators are stable across the stacked sub-tables.
    bucket_universe: dict[tuple[str, str], set] = defaultdict(set)
    for r in conn.execute(
        'SELECT DISTINCT test_id, suite, "group" FROM run_results'
    ):
        bucket_universe[(r["suite"], r["group"])].add(r["test_id"])
    if not bucket_universe:
        return ""

    states = _top_n_states(conn, n=5)
    if not states:
        return ""

    now = now_ms()
    out_lines = ["## By suite × group (per state, 5 most recent)\n",
                 "_Total = distinct test_ids ever observed per (suite, "
                 "group). Cov/pass/fail = freshest verdict per "
                 "(test_id, pass) within this state._\n"]
    for state in states:
        out_lines.append(_format_state_header(state, now))
        # One SQL aggregation per state — GROUP BY (suite, group, mode).
        # The state filter and the cov/pass/fail/flaky arithmetic all
        # come from state_test_pass; no in-Python tallying.
        where, params = _state_filter(
            state["commit_sha"], state["dirty_hash"],
            state["worktree_path"],
        )
        bucket_rows = list(conn.execute(
            f"""
            SELECT suite, "group", mode,
                   COUNT(*) AS cov,
                   SUM(CASE WHEN freshest_verdict = 'pass'
                            THEN 1 ELSE 0 END) AS n_pass,
                   SUM(CASE WHEN freshest_verdict <> 'pass'
                            THEN 1 ELSE 0 END) AS n_fail,
                   SUM(CASE WHEN freshest_verdict = 'pass' AND ever_failed = 1
                            THEN 1 ELSE 0 END) AS n_flaky
              FROM state_test_pass
             WHERE {where}
             GROUP BY suite, "group", mode
            """,
            params,
        ))
        if not bucket_rows:
            out_lines.append("\n_No coverage at this state yet._\n")
            continue

        buckets: dict[tuple[str, str], dict] = {}
        for r in bucket_rows:
            b = buckets.setdefault(
                (r["suite"], r["group"]),
                {"native": (0, 0, 0, 0), "litebox": (0, 0, 0, 0)},
            )
            b[r["mode"]] = (r["cov"], r["n_pass"], r["n_fail"], r["n_flaky"])

        out_lines.append(
            "\n| Suite | Group "
            "| native total | native cov | native pass | native fail | native flaky "
            "| litebox total | litebox cov | litebox pass | litebox fail | litebox flaky |"
        )
        out_lines.append(
            "|---|---"
            "|---:|---:|---:|---:|---:"
            "|---:|---:|---:|---:|---:|"
        )
        for (suite, group), b in sorted(buckets.items()):
            total = len(bucket_universe.get((suite, group), set()))
            cells: list[str] = []
            for pass_name in ("native", "litebox"):
                cov, p, f, fl = b[pass_name]
                cells.extend([str(total), str(cov), str(p), str(f), str(fl)])
            out_lines.append(
                f"| {suite} | {group} | " + " | ".join(cells) + " |"
            )
        out_lines.append("")
    return "\n".join(out_lines) + "\n"


def _render_current_fails(conn: sqlite3.Connection) -> str:
    """FAILs at the 5 most recent `(commit_sha, dirty_hash)`
    states, each as its own sub-table. Cross-state recurrence
    `[k/N]` annotates how many of the 5 visible states this
    test failed in — separates durable fails from transient
    ones.

    Per-state freshest-verdict-per-(test_id, pass) semantics so
    a retry that passed at the same sha gets counted as a pass,
    not a fail. A test with mixed last-10 verdicts (both ✓ and
    ✗ globally) is marked `_(flaky)_`.
    """
    states = _top_n_states(conn, n=5)
    if not states:
        return "## Current FAILs\n\n_No states._\n"

    # Per-state failing (test_id, pass) sets, for cross-state
    # recurrence annotation.
    fail_sets: list[set[tuple[str, str]]] = []
    per_state_verdicts: list[dict] = []
    for s in states:
        v = state_verdicts(
            conn, s["commit_sha"], s["dirty_hash"], s["worktree_path"]
        )
        per_state_verdicts.append(v)
        fail_sets.append(
            {k for k, verdict in v.items() if verdict != "pass"}
        )

    if all(not fs for fs in fail_sets):
        return (
            "## Current FAILs\n\n"
            "_No FAILs in any of the 5 most recent states._\n"
        )

    # test_id → (suite, group), pulled once.
    suite_for: dict[str, tuple[str, str]] = {}
    for r in conn.execute(
        'SELECT DISTINCT test_id, suite, "group" FROM run_results'
    ):
        suite_for[r["test_id"]] = (r["suite"], r["group"])

    # test_id → finished_ts_ms per state for age column. Pull
    # once via a scoped query for each state.
    now = now_ms()
    lines = ["## Current FAILs (per state, 5 most recent)\n",
             "_Cross-state recurrence `[k/N]` = failed in k of "
             "the N visible states. `_(flaky)_` = global last-10 "
             "history has both ✓ and ✗._\n"]
    n_states = len(states)
    for idx, state in enumerate(states):
        lines.append(_format_state_header(state, now))
        fails = fail_sets[idx]
        if not fails:
            lines.append("\n_No FAILs at this state._\n")
            continue
        # Per-test ts at this state for the Age column.
        ts_for: dict[tuple[str, str], int] = {}
        if state["dirty_hash"] is None:
            ts_rows = conn.execute(
                "SELECT rr.test_id, rr.mode, MAX(rr.finished_ts_ms) AS ts "
                "  FROM run_results rr "
                "  JOIN runs r ON r.run_id = rr.run_id "
                " WHERE r.commit_sha = ? AND r.dirty_hash IS NULL "
                " GROUP BY rr.test_id, rr.mode",
                (state["commit_sha"],),
            ).fetchall()
        else:
            # Match state_verdicts' state-scope semantics: a dirty
            # state is (sha, dirty_hash, worktree_path), so the Age
            # column must read only from that worktree's dirty rows.
            ts_rows = conn.execute(
                "SELECT rr.test_id, rr.mode, MAX(rr.finished_ts_ms) AS ts "
                "  FROM run_results rr "
                "  JOIN runs r ON r.run_id = rr.run_id "
                " WHERE r.commit_sha = ? AND r.dirty_hash = ? "
                "   AND r.worktree_path = ? "
                " GROUP BY rr.test_id, rr.mode",
                (state["commit_sha"], state["dirty_hash"],
                 state["worktree_path"]),
            ).fetchall()
        for r in ts_rows:
            ts_for[(r["test_id"], r["mode"])] = r["ts"] or 0

        lines.append(
            "\n| Pass | Suite | Group | Test | Verdict | Recurrence "
            "| Last 10 | Age |"
        )
        lines.append("|---|---|---|---|---|---:|---|---|")
        for (test_id, pass_name) in sorted(
            fails, key=lambda k: (k[1], suite_for.get(k[0], ("?", "?")), k[0])
        ):
            sg = suite_for.get(test_id, ("?", "?"))
            verdict = per_state_verdicts[idx][(test_id, pass_name)]
            recur = sum(
                1 for fs in fail_sets
                if (test_id, pass_name) in fs
            )
            history = _verdict_history(conn, test_id, pass_name, n=10)
            flaky = ("✓" in history) and ("✗" in history)
            flaky_marker = " _(flaky)_" if flaky else ""
            ts = ts_for.get((test_id, pass_name), 0)
            age = fmt_age_ms(now - ts) if ts else "—"
            lines.append(
                f"| `{pass_name}` | {sg[0]} | {sg[1]} | "
                f"`{test_id}`{flaky_marker} | `{verdict}` | "
                f"[{recur}/{n_states}] | `{history}` | {age} |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def _verdict_history(
    conn: sqlite3.Connection, test_id: str, pass_name: str, n: int = 10,
) -> str:
    """Most-recent → least-recent (left → right reversed) verdict
    history for a single (test_id, pass). One char per run:
    ✓ = pass, ✗ = FAIL, · = other/no_result. Distinguishes a fresh
    regression (`✓✓✓✗`) from a flake (`✓✗✓✗`) at a glance.
    """
    rows = conn.execute(
        "SELECT verdict FROM run_results"
        " WHERE test_id = ? AND mode = ?"
        " ORDER BY finished_ts_ms DESC LIMIT ?",
        (test_id, pass_name, n),
    ).fetchall()
    # rows[0] is the most recent; reverse so newest is on the right.
    chars: list[str] = []
    for r in reversed(rows):
        v = r["verdict"]
        if v == "pass":
            chars.append("✓")
        elif v == "fail":
            chars.append("✗")
        else:
            chars.append("·")
    return "".join(chars) or "—"


def _render_agent_worktrees(conn: sqlite3.Connection,
                            state_dir: Path) -> str:
    """Per-agent-worktree coverage + regression delta vs the best-fit
    tracked-ref baseline. Auto-discovered from `git worktree list` in
    the canonical clone (any worktree that isn't a tracked-ref CI
    worktree and has a branch checked out).

    Two regression metrics per worktree:
      * Δ vs merge-base(HEAD, baseline_ref_HEAD) — agent's own
        regressions since they forked.
      * Δ vs baseline_ref_HEAD — absolute drift vs current upstream.
    """
    canonical = _canonical_worktree_for_render(state_dir)
    tips, non_tips = _agent_tip_worktrees(conn, canonical)
    candidates = tips + non_tips
    if not candidates:
        # Section omitted entirely when there are no agent worktrees
        # — keeps summary.md uncluttered for single-session use.
        return ""
    tip_paths = {t["path"] for t in tips}
    lines = [
        "## Agent worktrees\n",
        "_Opportunistic coverage for live worktrees. Each row's "
        "regression columns compare the worktree's HEAD against the "
        "tracked-ref baseline whose HEAD shares the most recent "
        "merge-base — i.e., the upstream this branch forked from._\n",
        "_Marker: `→` = tip (the supervisor opportunistically tests "
        "this worktree). `~` = subsumed (another worktree's HEAD "
        "already contains this one's history; testing the tip covers "
        "it too)._\n",
        "| | Worktree | Branch | HEAD | Baseline ref | "
        "Δ vs merge-base (native) | Δ vs merge-base (litebox) | "
        "Δ vs baseline HEAD (native) | Δ vs baseline HEAD (litebox) | "
        "Cov (native) | Cov (litebox) | Last tested |",
        "|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    details: list[str] = []
    for wt in candidates:
        agent_head = wt["head"]
        path = wt["path"]
        marker = "→" if path in tip_paths else "~"
        branch = _branch_display(wt.get("branch"))
        baseline = _pick_baseline_ref(conn, canonical, agent_head)
        if baseline is None:
            lines.append(
                f"| {marker} | `{Path(path).name}` | {branch} | "
                f"`{short_sha(agent_head)}` | _no baseline_ | — | — | — | — | "
                f"— | — | — |"
            )
            continue
        mb = baseline["merge_base"]
        ref_head = baseline["ref_head"]
        # Δ vs merge-base
        delta_mb = _regression_counts(conn, mb, agent_head)
        # Δ vs baseline HEAD
        delta_bh = _regression_counts(conn, ref_head, agent_head)
        last_age = _last_run_age_at_sha(conn, agent_head)
        last_age_str = (
            f"{fmt_age_ms(now_ms() - last_age)} ago"
            if last_age is not None else "_never_"
        )
        def cell(d: dict, p: str) -> str:
            r = d[p]["regressions"]
            i = d[p]["improvements"]
            if r == 0 and i == 0:
                if d[p]["common"] == 0:
                    return "—"
                return "0"
            parts = [f"**{r}**"] if r else []
            if i:
                parts.append(f"_+{i}_")
            return " ".join(parts) or "0"
        lines.append(
            f"| {marker} | `{Path(path).name}` | {branch} | "
            f"`{short_sha(agent_head)}` | "
            f"`{baseline['ref']}` @ `{short_sha(ref_head)}` | "
            f"{cell(delta_mb, 'native')} | {cell(delta_mb, 'litebox')} | "
            f"{cell(delta_bh, 'native')} | {cell(delta_bh, 'litebox')} | "
            f"{delta_mb['native']['agent_cov']} | "
            f"{delta_mb['litebox']['agent_cov']} | "
            f"{last_age_str} |"
        )
        # Per-worktree regression detail block (only if non-zero).
        if last_age is not None:
            blocks: list[str] = []
            for label, base_sha in (
                (f"merge-base `{short_sha(mb)}`", mb),
                (f"baseline HEAD `{short_sha(ref_head)}`", ref_head),
            ):
                for pass_name in ("native", "litebox"):
                    ids = _regression_test_ids(conn, base_sha, agent_head,
                                               pass_name, limit=20)
                    if not ids:
                        continue
                    blocks.append(
                        f"  - vs {label} ({pass_name}, {len(ids)} shown):\n    "
                        + ", ".join(f"`{tid}`" for tid in ids)
                    )
            if blocks:
                details.append(
                    f"\n<details><summary>"
                    f"Regressed test_ids — `{Path(path).name}` "
                    f"@ `{short_sha(agent_head)}`</summary>\n\n"
                    + "\n".join(blocks)
                    + "\n\n</details>"
                )
    lines.append("")
    lines.append(
        "_Bold = regressions (pass → fail). Italic `+N` = improvements "
        "(fail → pass). `—` = no overlapping coverage with that "
        "baseline yet (run more cycles). Worktrees are auto-discovered "
        "from `git worktree list`; tracked-ref CI worktrees are "
        "excluded. The supervisor opportunistically tests only the "
        "tip-set (marker `→`) — when subagents fan out from a session "
        "branch, only the worktrees whose HEAD isn't already contained "
        "in another worktree's HEAD are tested directly. Idle gate: "
        "source files untouched for `LITEBOX_AGENT_IDLE_SECS` (default "
        "300s) AND no live lease from the worktree._"
    )
    out = "\n".join(lines) + "\n"
    if details:
        out += "\n" + "\n".join(details) + "\n"
    return out


def _canonical_worktree_for_render(state_dir: Path) -> Path:
    """Render-time resolution (no argparse Namespace here): use the
    `LITEBOX_DASHBOARD_CANONICAL` env override else state_dir.parent."""
    env = os.environ.get("LITEBOX_DASHBOARD_CANONICAL")
    if env:
        return Path(env).resolve()
    return state_dir.parent.resolve()


def _render_recent_runs(conn: sqlite3.Connection,
                        live_branches: Optional[set[str]] = None) -> str:
    # Pull a generous window then post-filter — a recent run from a
    # since-deleted branch is hidden from the report (data stays in
    # sqlite). Without filtering we'd just take the top 10.
    over_fetch = 50 if live_branches else 10
    rows = conn.execute(
        """
        SELECT run_id, started_ts_ms, finished_ts_ms, hostname,
               worktree_path, branch, commit_sha, dirty_hash,
               pass_count, fail_count, universe_size
          FROM runs
         ORDER BY started_ts_ms DESC
         LIMIT ?
        """,
        (over_fetch,),
    ).fetchall()
    if not rows:
        return ""
    if live_branches:
        filtered = [
            r for r in rows
            if (r["branch"] or "") in live_branches
            or not r["branch"]  # detached HEAD / no branch recorded
        ]
        hidden_n = len(rows) - len(filtered)
        rows = filtered[:10]
    else:
        hidden_n = 0
        rows = rows[:10]
    if not rows:
        return ""
    lines = ["## Recent runs\n",
             "| # | Started | Worktree | Path | Branch | Sha | Dirty | Pass | FAIL | Universe |",
             "|---|---|---|---|---|---|---:|---:|---:|---:|"]
    now = now_ms()
    for r in rows:
        dirty = "⚠" if r["dirty_hash"] else ""
        wt_path = r["worktree_path"] or "?"
        wt_short = os.path.basename(wt_path)
        branch = _branch_display(r["branch"])
        age = fmt_age_ms(now - (r["started_ts_ms"] or now))
        lines.append(
            f"| {r['run_id']} | {age} ago | `{wt_short}` | `{wt_path}` | "
            f"`{branch}` | `{short_sha(r['commit_sha'])}` | {dirty} | "
            f"{r['pass_count'] or 0} | {r['fail_count'] or 0} | "
            f"{r['universe_size'] or '?'} |"
        )
    if hidden_n:
        lines.append(
            f"\n_{hidden_n} recent run(s) hidden whose branch no "
            f"longer exists in the canonical clone._"
        )
    return "\n".join(lines) + "\n"


def _render_footer(conn: sqlite3.Connection, state_dir: Path) -> str:
    now_str = _dt.datetime.now().isoformat(timespec="seconds")
    return (
        "---\n"
        f"_Rendered {now_str}_ · "
        f"_schema_version {SCHEMA_VERSION_EXPECTED}_ · "
        f"_state dir `{state_dir}`_\n"
    )


def write_summary(conn: sqlite3.Connection, state_dir: Path) -> Path:
    text = render(conn, state_dir)
    out = state_dir / "summary.md"
    tmp = out.with_suffix(".md.tmp")
    tmp.write_text(text)
    tmp.replace(out)
    return out


# ─── Subcommands ─────────────────────────────────────────────────────


def cmd_regressions(args: argparse.Namespace) -> int:
    """Standardized regression classification for a branch, read from
    the `regression_class` view. Buckets each failing (test, mode) as
    hard_regression (clean upstream → fail), soft_regression (was flaky
    upstream), new_fail (no baseline), preexisting_fail, or flaky_pass,
    each with a confidence tier — so sessions don't hand-roll triage
    queries."""
    state_dir = resolve_state_dir(args.state_dir)
    conn = open_db(state_dir, with_state_views=False)
    if not args.no_refresh:
        try:
            _refresh_classification_inputs(
                conn, _canonical_worktree(args, state_dir))
        except Exception as e:
            print(f"warning: classification refresh failed: "
                  f"{type(e).__name__}: {e}", file=sys.stderr)
    sel = args.branch
    row = conn.execute(
        "SELECT branch, branch_sha, baseline_sha FROM branch_baseline "
        " WHERE branch = ? OR branch_sha = ? OR branch_sha LIKE ? "
        " LIMIT 1",
        (sel, sel, sel + "%"),
    ).fetchone()
    if row is None:
        print(f"no branch_baseline entry for '{sel}'. Known branches:",
              file=sys.stderr)
        for r in conn.execute(
            "SELECT branch, substr(branch_sha,1,10) s FROM branch_baseline "
            "ORDER BY branch"
        ):
            print(f"  {r['branch']}  {r['s']}", file=sys.stderr)
        conn.close()
        return 1
    branch_sha = row["branch_sha"]
    # `regression_class` is expensive to evaluate (it classifies the whole
    # comparable universe). Materialize this branch's slice once so the
    # summary / coverage / per-bucket queries below don't each re-run it.
    conn.execute("DROP TABLE IF EXISTS temp._rc")
    conn.execute(
        "CREATE TEMP TABLE _rc AS "
        "SELECT mode, test_id, classification, confidence "
        "  FROM regression_class WHERE branch_sha = ?",
        (branch_sha,),
    )
    if args.format == "sql":
        for r in conn.execute(
            "SELECT mode, test_id, classification, confidence "
            "  FROM _rc "
            "   WHERE classification NOT IN "
            "       ('ok','flaky_pass','no_result','not_run') "
            " ORDER BY mode, classification, confidence DESC, test_id",
        ):
            print(f"{r['mode']}\t{r['classification']}\t{r['confidence']}"
                  f"\t{r['test_id']}")
        conn.close()
        return 0
    print(f"# Regressions — {row['branch']} @ {short_sha(branch_sha)} "
          f"(baseline {short_sha(row['baseline_sha'])})\n")
    for mode in ("native", "litebox"):
        counts = conn.execute(
            "SELECT classification, confidence, COUNT(*) n "
            "  FROM _rc WHERE mode = ? "
            "   AND classification NOT IN "
            "       ('ok','flaky_pass','no_result','not_run') "
            " GROUP BY classification, confidence "
            " ORDER BY classification, confidence",
            (mode,),
        ).fetchall()
        summary = "  ".join(
            f"{c['classification']}/{c['confidence']}={c['n']}" for c in counts
        ) or "clean"
        # Coverage of the comparable universe: how much of it has actually
        # run at the branch sha. A high `not_run` means the verdict is
        # provisional — a partial run must not read as "clean".
        cov = conn.execute(
            "SELECT "
            "  SUM(CASE WHEN classification = 'not_run' THEN 0 ELSE 1 END) covered,"
            "  COUNT(*) total,"
            "  SUM(CASE WHEN classification = 'no_result' THEN 1 ELSE 0 END) nr "
            "  FROM _rc WHERE mode = ?",
            (mode,),
        ).fetchone()
        covered, total, n_nr = cov["covered"] or 0, cov["total"] or 0, cov["nr"] or 0
        not_run = total - covered
        cov_str = f"covered {covered}/{total}"
        if not_run:
            cov_str += f", {not_run} not_run"
        if n_nr:
            cov_str += f", {n_nr} no_result infra"
        print(f"_{mode}_: {summary}   [{cov_str}]")
    print()
    # List the actionable buckets, hardest first.
    for mode in ("native", "litebox"):
        for cls in ("hard_regression", "new_fail", "soft_regression"):
            ids = conn.execute(
                "SELECT test_id, confidence FROM _rc "
                " WHERE mode = ? AND classification = ? "
                " ORDER BY CASE confidence WHEN 'high' THEN 0 "
                "          WHEN 'medium' THEN 1 ELSE 2 END, test_id",
                (mode, cls),
            ).fetchall()
            if not ids:
                continue
            print(f"## {cls} ({mode}) — {len(ids)}")
            for r in ids[: args.limit]:
                print(f"- `{r['test_id']}`  [{r['confidence']}]")
            if len(ids) > args.limit:
                print(f"  … and {len(ids) - args.limit} more "
                      f"(use --limit or --format sql)")
            print()
    conn.close()
    return 0


def cmd_migrate(args: argparse.Namespace) -> int:
    """Lossless in-place schema migration (v3 → v4). Opens the store
    raw (bypassing the strict version check, which would reject a v3
    store) and applies `migrate_v3_to_v4`. Idempotent."""
    state_dir = resolve_state_dir(args.state_dir)
    db_path = state_dir / "results.sqlite"
    if not db_path.exists():
        sys.exit(f"dashboard: sqlite store not found at {db_path}")
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.row_factory = sqlite3.Row
    try:
        before = _schema_version(conn)
        n_fail = 0
        if before == 3:
            n_fail = conn.execute(
                "SELECT COUNT(*) FROM run_results WHERE verdict='FAIL'"
            ).fetchone()[0]
        migrated = migrate_v3_to_v4(conn)
    finally:
        conn.close()
    if migrated:
        print(
            f"dashboard: migrated schema_version {before} → "
            f"{SCHEMA_VERSION_EXPECTED} (run_results.pass → mode; "
            f"normalized {n_fail} 'FAIL' verdicts → 'fail')"
        )
    else:
        print(
            f"dashboard: already at schema_version "
            f"{SCHEMA_VERSION_EXPECTED}; nothing to do"
        )
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    state_dir = resolve_state_dir(args.state_dir)
    conn = open_db(state_dir)
    out = write_summary(conn, state_dir)
    if not args.quiet:
        print(f"wrote {out}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    state_dir = resolve_state_dir(args.state_dir)
    conn = open_db(state_dir)
    if args.format == "md":
        sys.stdout.write(render(conn, state_dir))
        return 0
    if args.format == "sql":
        for row in conn.execute(
            "SELECT mode, verdict, COUNT(*) AS n FROM latest_results"
            " GROUP BY mode, verdict ORDER BY mode, verdict"
        ):
            print(f"{row['mode']}\t{row['verdict']}\t{row['n']}")
        return 0
    for row in conn.execute(
        "SELECT mode,"
        "  SUM(CASE WHEN verdict='pass' THEN 1 ELSE 0 END) AS n_pass,"
        "  SUM(CASE WHEN verdict='fail' THEN 1 ELSE 0 END) AS n_fail,"
        "  COUNT(*) AS n_total"
        "  FROM latest_results GROUP BY mode ORDER BY mode"
    ):
        print(
            f"{row['mode']:>8}: {row['n_pass'] or 0:5d} pass  "
            f"{row['n_fail'] or 0:4d} fail  ({row['n_total'] or 0} total)"
        )
    return 0


def cmd_track(args: argparse.Namespace) -> int:
    state_dir = resolve_state_dir(args.state_dir)
    conn = open_db(state_dir, bootstrap=True)
    wt = Path(args.ci_worktree).expanduser().resolve()
    main_wt = state_dir.parent
    # Resolve the ref eagerly so we fail loudly on typos. Run from the
    # main worktree (state_dir.parent by construction).
    try:
        subprocess.run(
            ["git", "-C", str(main_wt), "rev-parse", args.ref],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        sys.exit(f"dashboard: cannot resolve ref `{args.ref}`: {e.stderr.strip()}")
    # Create the worktree if it doesn't exist. Detached HEAD so the
    # autonomous driver's `git checkout --detach <sha>` per cycle has
    # nothing to clobber.
    if not wt.exists():
        try:
            subprocess.run(
                ["git", "-C", str(main_wt), "worktree", "add",
                 "--detach", str(wt), args.ref],
                check=True, capture_output=True, text=True,
            )
            print(f"created worktree: {wt} @ {args.ref}")
        except subprocess.CalledProcessError as e:
            sys.exit(
                f"dashboard: `git worktree add` failed for {wt}:\n"
                f"  {e.stderr.strip()}"
            )
    conn.execute(
        "INSERT INTO tracked_refs(ref, ci_worktree) VALUES (?, ?)"
        " ON CONFLICT(ref) DO UPDATE SET ci_worktree = excluded.ci_worktree",
        (args.ref, str(wt)),
    )
    print(f"tracked: {args.ref} → {wt}")
    return 0


def cmd_untrack(args: argparse.Namespace) -> int:
    state_dir = resolve_state_dir(args.state_dir)
    conn = open_db(state_dir)
    row = conn.execute(
        "SELECT ci_worktree FROM tracked_refs WHERE ref = ?", (args.ref,)
    ).fetchone()
    if not row:
        sys.exit(f"dashboard: ref `{args.ref}` was not tracked")
    wt = row["ci_worktree"]
    cur = conn.execute("DELETE FROM tracked_refs WHERE ref = ?", (args.ref,))
    assert cur.rowcount == 1
    print(f"untracked: {args.ref}")
    # Best-effort `git worktree remove`. Refuses to remove a dirty
    # worktree without --force; we surface that loudly so the user
    # can decide. The sqlite row is already gone, so re-running with
    # --keep-worktree is unnecessary.
    if args.keep_worktree:
        print(f"keeping worktree on disk: {wt}")
        return 0
    main_wt = state_dir.parent
    remove_cmd = ["git", "-C", str(main_wt), "worktree", "remove"]
    if args.force:
        remove_cmd.append("--force")
    remove_cmd.append(wt)
    try:
        subprocess.run(remove_cmd, check=True, capture_output=True, text=True)
        print(f"removed worktree: {wt}")
    except subprocess.CalledProcessError as e:
        # Most common reason: worktree is dirty (uncommitted changes).
        # User decides whether to rerun with --force or clean manually.
        print(
            f"warning: could not remove worktree {wt}: {e.stderr.strip()}\n"
            f"  Rerun with `--force` to remove anyway, or clean it up "
            f"manually with: git -C {main_wt} worktree remove --force {wt}",
            file=sys.stderr,
        )
    return 0


def cmd_refs(args: argparse.Namespace) -> int:
    state_dir = resolve_state_dir(args.state_dir)
    conn = open_db(state_dir)
    rows = conn.execute(
        "SELECT ref, ci_worktree FROM tracked_refs ORDER BY ref"
    ).fetchall()
    if not rows:
        print("(no tracked refs)")
        return 0
    for r in rows:
        head = _git_head(r["ci_worktree"]) or "missing"
        print(f"{r['ref']:50s} {r['ci_worktree']}  HEAD={short_sha(head)}")
    return 0


def cmd_auto(args: argparse.Namespace) -> int:
    """Autonomous driver: for each tracked ref, fetch + checkout +
    cargo test -- --fill, then render. Sleep. Repeat.

    Lifecycle and cleanup (see plan.md and `cleanup` module in the
    harness):

      * Each cycle launches cargo in a fresh process group (via
        `start_new_session=True`) so the supervisor can `killpg` the
        whole cargo + harness + docker-run subtree on any exit path.
      * State is written to `<state_dir>/auto.pidfile` (JSON) so
        `dashboard.py stop` can find and reap us out-of-band.
      * SIGTERM/SIGINT to the supervisor itself triggers an orderly
        reap of any in-flight cargo PGID (today's bare-Python default
        would only kill Python, leaking cargo + harness).
      * On each cycle completion an assertion scans /proc for stragglers
        in the cargo PGID and escalates if any are still alive.
    """
    state_dir = resolve_state_dir(args.state_dir)
    pidfile = state_dir / "auto.pidfile"
    _supervisor_state = _new_supervisor_state()

    def _signal_handler(signum, _frame):
        sig_name = signal.Signals(signum).name
        if not args.quiet:
            print(f"[auto] received {sig_name}; reaping in-flight cargo(s)",
                  file=sys.stderr)
        _reap_all_children(_supervisor_state, quiet=args.quiet)
        try:
            pidfile.unlink()
        except FileNotFoundError:
            pass
        # Exit with 128+signum convention.
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # Soft-close: SIGUSR1 sets a flag that the auto-loop checks at
    # cycle boundaries. The current cargo cycle runs to completion
    # (so no in-flight trials are killed mid-execution), then the
    # supervisor exits cleanly. Use `dashboard.py drain` from
    # another shell to send it without remembering the PID.
    drain_requested = threading.Event()

    def _drain_handler(_signum, _frame):
        if not args.quiet:
            print("[auto] SIGUSR1 received — will exit after current cycle",
                  file=sys.stderr)
        drain_requested.set()

    signal.signal(signal.SIGUSR1, _drain_handler)

    _write_pidfile_from_state(pidfile, os.getpid(), _supervisor_state)

    # Initial render before the first cycle starts. Re-renders the
    # summary with whatever's already in the store, so a freshly
    # (re)started supervisor — e.g., after a renderer bug fix or a
    # WSL restart — reflects the latest schema/code immediately
    # instead of showing the stale summary.md (or no summary at
    # all) for one full cycle (which can be 10+ min on a cold build).
    try:
        conn = open_db(state_dir)
        write_summary(conn, state_dir)
        conn.close()
    except Exception as e:
        print(f"[auto] initial render failed: {type(e).__name__}: {e}",
              file=sys.stderr)

    # Background freshness thread. Long cargo cycles (copilot trials
    # plus cold rebuilds easily hit 20-30 min) used to leave
    # summary.md untouched until the cycle finished, so the displayed
    # HEAD sha could lag the actual `litebox-ci` worktree HEAD by
    # tens of minutes — confusing because the renderer always
    # exact-matches `commit_sha` (so the numbers stayed truthful for
    # the *displayed* sha while the displayed sha was itself stale).
    # The thread re-renders against the live DB every
    # FRESHNESS_INTERVAL_SECS regardless of cycle phase. Rendering
    # is ~50 ms against the current store, so this is essentially
    # free compared to a cargo cycle.
    FRESHNESS_INTERVAL_SECS = 30
    freshness_stop = threading.Event()

    def _freshness_loop() -> None:
        while not freshness_stop.wait(FRESHNESS_INTERVAL_SECS):
            try:
                conn = open_db(state_dir)
                write_summary(conn, state_dir)
                conn.close()
            except Exception as e:
                # Non-fatal — the next tick will retry. Keep the
                # supervisor alive even if the renderer transiently
                # fails (e.g., schema migration in flight).
                print(
                    f"[auto] freshness render failed: "
                    f"{type(e).__name__}: {e}",
                    file=sys.stderr,
                )

    freshness_thread = threading.Thread(
        target=_freshness_loop,
        name="dashboard-freshness",
        daemon=True,
    )
    freshness_thread.start()

    try:
        while True:
            conn = open_db(state_dir, with_state_views=False)
            # Refresh the regression-classification caches (branch→
            # merge-base map + recent-flake tally) once per cycle so
            # `regression_class` stays current for any consumer.
            try:
                _refresh_classification_inputs(
                    conn, _canonical_worktree(args, state_dir))
            except Exception as e:
                print(f"[auto] classification refresh crashed: "
                      f"{type(e).__name__}: {e}", file=sys.stderr)
            refs = conn.execute(
                "SELECT ref, ci_worktree FROM tracked_refs ORDER BY ref"
            ).fetchall()
            conn.close()
            if not refs:
                if not args.quiet:
                    print("[auto] no tracked refs — sleeping; "
                          "register one with `dashboard.py track`.",
                          file=sys.stderr)
            for r in refs:
                wt = r["ci_worktree"]
                if not Path(wt).is_dir():
                    print(f"[auto] {r['ref']}: worktree {wt} missing, "
                          f"skipping", file=sys.stderr)
            ref_jobs: list[tuple[str, str]] = [
                (r["ref"], r["ci_worktree"]) for r in refs
                if Path(r["ci_worktree"]).is_dir()
            ]
            max_parallel_refs = max(
                1, int(getattr(args, "max_parallel_tracked_refs", 1) or 1),
            )
            # Wrap each ref's drive in try/except so a single ref's
            # failure (or an unexpected exception in _drive_ref's
            # recovery paths) doesn't take down the whole supervisor.
            # Parallelism here is safe because each tracked-ref has
            # its own ci_worktree (and thus its own target/, its own
            # per-pid docker container names via harness pid salt);
            # CPU is throttled by the harness lease table the same
            # way as agent-coverage parallelism.
            def _drive_one_ref(ref: str, wt: str) -> bool:
                try:
                    return _drive_ref(
                        ref, wt, args,
                        pidfile=pidfile,
                        supervisor_state=_supervisor_state,
                    )
                except Exception as e:
                    print(f"[auto] {ref}: _drive_ref crashed: "
                          f"{type(e).__name__}: {e}", file=sys.stderr)
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                    return False

            results: dict[str, bool] = {}
            if max_parallel_refs <= 1 or len(ref_jobs) <= 1:
                for ref, wt in ref_jobs:
                    results[ref] = _drive_one_ref(ref, wt)
                    if not args.quiet:
                        ok = results[ref]
                        print(f"[auto] {ref} @ {wt}: "
                              f"{'ok' if ok else 'failed'}")
            else:
                # Run in fixed-size batches so the supervisor doesn't
                # spawn more cargos than the operator asked for. The
                # leases throttle CPU per cargo, but spawning 20
                # parallel cold builds at once still thrashes I/O +
                # docker daemon — batch size caps the burst.
                if not args.quiet:
                    print(f"[auto] tracked refs: driving "
                          f"{len(ref_jobs)} ref(s), up to "
                          f"{max_parallel_refs} in parallel",
                          file=sys.stderr)
                for i in range(0, len(ref_jobs), max_parallel_refs):
                    batch = ref_jobs[i:i + max_parallel_refs]
                    threads = []
                    out_slot: dict[str, bool] = {}

                    def _runner(ref=None, wt=None):
                        out_slot[ref] = _drive_one_ref(ref, wt)

                    for ref, wt in batch:
                        t = threading.Thread(
                            target=_runner, kwargs={"ref": ref, "wt": wt},
                            name=f"tracked-ref:{ref}", daemon=False,
                        )
                        t.start()
                        threads.append(t)
                    for t in threads:
                        t.join()
                    results.update(out_slot)
                    if not args.quiet:
                        for ref, wt in batch:
                            ok = out_slot.get(ref, False)
                            print(f"[auto] {ref} @ {wt}: "
                                  f"{'ok' if ok else 'failed'}")
            # Opportunistic agent-worktree coverage: pick one idle
            # agent worktree per cycle (if any) and run a short fill.
            # Lease coordinator already shares concurrency fairly with
            # any in-flight tracked-ref cycle.
            if not getattr(args, "agent_coverage_disable", False):
                try:
                    _maybe_drive_agent_worktree(
                        args, pidfile=pidfile,
                        supervisor_state=_supervisor_state,
                    )
                except Exception as e:
                    print(f"[auto] agent-coverage drive crashed: "
                          f"{type(e).__name__}: {e}", file=sys.stderr)
                    import traceback
                    traceback.print_exc(file=sys.stderr)
            # The background freshness thread (started above the loop)
            # handles continuous summary.md updates every
            # FRESHNESS_INTERVAL_SECS regardless of cycle phase, so we
            # don't need to render here or chunk the sleep into
            # render-spaced intervals. Just sleep until the next cycle.
            if args.once:
                return 0
            if drain_requested.is_set():
                if not args.quiet:
                    print("[auto] drain requested — exiting cleanly",
                          file=sys.stderr)
                return 0
            time.sleep(args.interval)
    finally:
        freshness_stop.set()
        try:
            pidfile.unlink()
        except FileNotFoundError:
            pass


def _drive_ref(
    ref: str,
    ci_worktree: str,
    args: argparse.Namespace,
    *,
    pidfile: Optional[Path] = None,
    supervisor_state: Optional[dict] = None,
) -> bool:
    """Fetch + checkout + cargo test -- --fill for one tracked ref.
    Returns True if cargo exit was clean.

    Launches cargo in its own process group (PGID = cargo PID) so the
    supervisor can `killpg` the whole subtree on timeout / SIGTERM /
    `dashboard.py stop`. On any exit (success, timeout, error) the
    PGID is swept once more to catch any stragglers, and zombie
    containers tagged with the harness PID are `docker rm -f`'d.
    """
    env = os.environ.copy()
    # Always write into the same dashboard store the auto loop is
    # reading from, regardless of the CI worktree's main-worktree.
    env["LITEBOX_DASHBOARD_DIR"] = str(resolve_state_dir(args.state_dir))
    # 1. fetch — but only if the ref's prefix is a known remote.
    # Local branches (e.g. `wportnoy/vscode-server-in-litebox`) skip
    # the fetch; their tip moves whenever the canonical worktree
    # commits or merges, and is read straight from local refs.
    remote = _remote_for_ref(ci_worktree, ref)
    if remote:
        try:
            subprocess.run(
                ["git", "-C", ci_worktree, "fetch", "--quiet", remote],
                check=False, timeout=120,
            )
        except subprocess.TimeoutExpired:
            return False
    # 2. resolve + checkout the ref's sha (detached)
    try:
        sha = subprocess.run(
            ["git", "-C", ci_worktree, "rev-parse", ref],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        return False
    try:
        subprocess.run(
            ["git", "-C", ci_worktree, "checkout", "--detach", "--quiet", sha],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError:
        return False
    # 3. cargo test -- --fill — time-budget mode by default.
    cargo_args = [
        "cargo", "test", "-p", "litebox_test_harness",
        "--test", "integration", "--",
    ]
    if args.batch_size:
        cargo_args.append(f"--fill={args.batch_size}")
    else:
        cargo_args.append(f"--fill={args.cycle_budget_secs}s")
    # Communicate the tracked ref to the producer so it can record
    # something more informative than "HEAD" (the detached-state
    # sentinel) in `runs.branch`. See dashboard_store::insert_run_row.
    env["LITEBOX_DASHBOARD_REF"] = ref

    # Outer wall-time budget: cycle budget + generous grace for
    # cargo's own startup, drain, etc.
    deadline = time.monotonic() + (args.cycle_budget_secs * 2 + 600)
    proc = subprocess.Popen(
        cargo_args, cwd=ci_worktree, env=env,
        # New session + process group; PGID = cargo PID.
        start_new_session=True,
    )
    cargo_pgid = proc.pid  # equals PGID after start_new_session
    # Register + initial pidfile write happen inside try/finally so a
    # failure between register and the polling loop (e.g. a transient
    # pidfile-write error) still triggers `_unregister_child` and
    # doesn't leak the registry slot.
    child_id: Optional[int] = None
    harness_pid: Optional[int] = None
    poll_until = time.monotonic() + 30
    rc: Optional[int] = None
    try:
        if supervisor_state is not None:
            child_id = _register_child(
                supervisor_state, kind="tracked-ref",
                worktree_path=ci_worktree,
            )
            _update_child(supervisor_state, child_id, cargo_pgid=cargo_pgid)
            if pidfile is not None:
                _write_pidfile_from_state(
                    pidfile, os.getpid(), supervisor_state,
                )
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            if harness_pid is None and time.monotonic() < poll_until:
                harness_pid = _find_harness_pid(proc.pid)
                if harness_pid is not None and child_id is not None:
                    _update_child(supervisor_state, child_id,
                                  harness_pid=harness_pid)
                    if pidfile is not None:
                        _write_pidfile_from_state(
                            pidfile, os.getpid(), supervisor_state,
                        )
            if time.monotonic() > deadline:
                print(f"[auto] cycle exceeded deadline; reaping PGID {cargo_pgid}",
                      file=sys.stderr)
                _reap_pgid_and_containers(cargo_pgid, harness_pid,
                                          quiet=args.quiet)
                return False
            time.sleep(0.5)
    finally:
        # End-of-cycle assert: nothing should remain in cargo's PGID.
        # If it does, this is a leak — escalate cleanup.
        if cargo_pgid is not None:
            stragglers = _pids_in_pgid(cargo_pgid)
            if stragglers:
                print(f"[auto] WARN: {len(stragglers)} stragglers in PGID "
                      f"{cargo_pgid} after cycle: {stragglers[:5]}…",
                      file=sys.stderr)
                _reap_pgid_and_containers(cargo_pgid, harness_pid,
                                          quiet=args.quiet)
        if child_id is not None and supervisor_state is not None:
            _unregister_child(supervisor_state, child_id)
            if pidfile is not None:
                _write_pidfile_from_state(
                    pidfile, os.getpid(), supervisor_state,
                )

    return rc == 0


def _shadow_worktree_path(state_dir: Path) -> Path:
    """Legacy single-shadow path (deprecated; kept for migration GC).
    New code uses `_per_branch_shadow_path(state_dir, branch)`."""
    return state_dir / "shadow"


def _shadows_root(state_dir: Path) -> Path:
    """Parent directory holding per-branch shadow worktrees. Each
    immediate child is one shadow keyed by a filesystem-safe encoding
    of the branch name."""
    return state_dir / "shadows"


def _per_branch_shadow_path(state_dir: Path, branch: str) -> Path:
    """Per-branch shadow worktree path. Eliminates the cargo
    incremental-recompile cost that the previous single shared
    shadow paid on every branch flip. Tradeoff: ~10-15 GB disk
    per branch under `target/`; GC reaps stale shadows whose
    branch no longer exists in the canonical clone.

    Branches containing `/` (most do, e.g. `wportnoy/foo`) become
    nested directories under `shadows/`. We deliberately do NOT
    URL-encode `/` as `%2f`: `rust-lld` URL-decodes `%XX`
    sequences in its `-o` output path and then fails ENOENT
    because the decoded path doesn't exist. Nested directories
    sidestep the issue entirely. Empty branch is rejected
    upstream (detached worktrees are filtered out of the
    candidate set earlier).
    """
    return _shadows_root(state_dir) / branch


def _branch_from_shadow_path(state_dir: Path, shadow: Path) -> Optional[str]:
    """Inverse of `_per_branch_shadow_path`: recover the branch
    name from a shadow path under `shadows/`. Returns None if
    the path isn't under the shadows root (e.g., a leftover
    `%XX`-encoded directory from an older layout that GC should
    reap unconditionally)."""
    root = _shadows_root(state_dir)
    try:
        rel = shadow.relative_to(root)
    except ValueError:
        return None
    parts = rel.parts
    if not parts:
        return None
    return "/".join(parts)


def _gc_shadow_worktrees(canonical: Path, state_dir: Path,
                         live_branches: set[str]) -> int:
    """Remove per-branch shadow worktrees whose branch no longer
    exists in the canonical clone, plus the legacy single-shadow
    path (`<state-dir>/shadow`) and any legacy `%XX`-encoded
    flat-layout directories under `shadows/`. Returns count
    removed.

    Best-effort: failures don't abort the supervisor. Live-branches
    set must be non-empty (an empty set would reap every shadow,
    likely indicating git failure; safer to skip GC in that case).
    """
    if not live_branches:
        return 0
    removed = 0
    # 1) Legacy single-shadow path. It's a real git worktree; use
    # `git worktree remove --force` so the canonical's worktree
    # list stays consistent. Best-effort.
    legacy = _shadow_worktree_path(state_dir)
    if legacy.exists():
        try:
            subprocess.run(
                ["git", "-C", str(canonical), "worktree", "remove",
                 "--force", str(legacy)],
                check=False, capture_output=True, text=True, timeout=60,
            )
            if not legacy.exists():
                removed += 1
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    # 2) Per-branch shadows under <state-dir>/shadows/. Enumerate
    # via `git worktree list --porcelain` (authoritative — handles
    # the nested-dir layout and ignores stray non-worktree dirs)
    # then map each path back to a branch via the inverse of
    # `_per_branch_shadow_path`. Any worktree under `shadows/`
    # whose decoded branch isn't live gets reaped. Legacy `%XX`
    # flat-layout shadows decode to a non-existent branch (e.g.
    # `wportnoy%2ffoo` is not in `live_branches`, which only
    # contains real branch names like `wportnoy/foo`), so they
    # are reaped unconditionally — exactly what we want.
    root = _shadows_root(state_dir)
    if root.is_dir():
        shadow_paths = _list_shadow_worktree_paths(canonical, root)
        for shadow in shadow_paths:
            branch = _branch_from_shadow_path(state_dir, shadow)
            if branch is not None and branch in live_branches:
                continue
            try:
                subprocess.run(
                    ["git", "-C", str(canonical), "worktree", "remove",
                     "--force", str(shadow)],
                    check=False, capture_output=True, text=True, timeout=60,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            if not shadow.exists():
                removed += 1
        # Best-effort: prune now-empty parent dirs under `shadows/`
        # so the directory tree doesn't accumulate stale skeleton
        # dirs (e.g. `shadows/wportnoy/` after every `wportnoy/*`
        # shadow has been reaped). Only removes empty dirs; never
        # touches anything with live contents.
        _prune_empty_dirs(root)
    if removed:
        # `git worktree remove` already updates the admin DB but
        # `prune` mops up any half-removed entries from prior runs.
        try:
            subprocess.run(
                ["git", "-C", str(canonical), "worktree", "prune"],
                check=False, capture_output=True, text=True, timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return removed


def _list_shadow_worktree_paths(canonical: Path,
                                shadows_root: Path) -> list[Path]:
    """Enumerate paths of all git worktrees rooted under
    `shadows_root` via `git worktree list --porcelain`. Returns
    [] on any git failure. Resolves both sides before comparing
    so that symlink quirks (rare but possible on WSL2) don't
    cause false negatives."""
    try:
        r = subprocess.run(
            ["git", "-C", str(canonical), "worktree", "list", "--porcelain"],
            check=False, capture_output=True, text=True, timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    if r.returncode != 0:
        return []
    try:
        root_resolved = shadows_root.resolve()
    except OSError:
        root_resolved = shadows_root
    out: list[Path] = []
    for line in r.stdout.splitlines():
        if not line.startswith("worktree "):
            continue
        path = Path(line[len("worktree "):])
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        try:
            resolved.relative_to(root_resolved)
        except ValueError:
            continue
        out.append(path)
    return out


def _prune_empty_dirs(root: Path) -> None:
    """Remove empty subdirectories of `root` (post-order). Never
    removes `root` itself. Best-effort; ignores all errors."""
    if not root.is_dir():
        return
    for child in sorted(root.iterdir(), reverse=True):
        if not child.is_dir():
            continue
        _prune_empty_dirs(child)
        try:
            child.rmdir()
        except OSError:
            pass


def _ensure_shadow_worktree(canonical: Path, state_dir: Path,
                            agent_branch: str,
                            agent_head: str) -> Optional[Path]:
    """Ensure `<state-dir>/shadows/<branch>/` exists as a `git worktree`
    sharing `canonical`'s object DB, checked out to `agent_head`.

    Per-branch shadows eliminate the cargo incremental-recompile cost
    that the previous single shared shadow paid on every branch flip:
    each branch keeps its own `target/` across cycles, so only the
    *first* opportunistic cycle for a branch pays a cold build, and
    subsequent cycles on the same branch are incremental even if
    other branches were tested in between.

    Returns the shadow path on success, None on failure (shadow
    cannot be set up — caller should skip the cycle rather than
    fall back to in-place execution, which would race the agent's
    `target/` and `docker build`).
    """
    if not agent_branch:
        # Detached HEADs shouldn't reach here (filtered upstream),
        # but defensively: no per-branch shadow is well-defined.
        return None
    shadow = _per_branch_shadow_path(state_dir, agent_branch)
    if not shadow.exists():
        shadow.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                ["git", "-C", str(canonical), "worktree", "add",
                 "--detach", str(shadow), agent_head],
                check=True, capture_output=True, text=True, timeout=60,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"[auto] agent-coverage: shadow setup failed "
                  f"({agent_branch}): {e}", file=sys.stderr)
            return None
        return shadow
    # Existing shadow for this branch — switch to agent_head. Use
    # `git checkout --detach -f` to overwrite anything (the shadow
    # is owned by the supervisor; no one else should be writing
    # to it).
    try:
        subprocess.run(
            ["git", "-C", str(shadow), "checkout", "--detach", "-f",
             "--quiet", agent_head],
            check=True, capture_output=True, text=True, timeout=60,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"[auto] agent-coverage: shadow checkout {agent_head} "
              f"failed ({agent_branch}): {e}", file=sys.stderr)
        return None
    return shadow


def _maybe_drive_agent_worktree(
    args: argparse.Namespace,
    *,
    pidfile: Optional[Path] = None,
    supervisor_state: Optional[dict] = None,
) -> None:
    """One-cycle wrapper: discover agent worktrees, pick an idle one,
    drive a short `--fill` from it. Best-effort — failures don't
    abort the supervisor's main loop.
    """
    state_dir = resolve_state_dir(args.state_dir)
    canonical = _canonical_worktree(args, state_dir)
    conn = open_db(state_dir)
    try:
        # GC stale shadows once per cycle, before scheduling. Cheap
        # (a few seconds at most) and keeps disk usage bounded as
        # branches come and go.
        live_branches = _live_branches(conn, canonical)
        if live_branches:
            n_gc = _gc_shadow_worktrees(canonical, state_dir, live_branches)
            if n_gc and not args.quiet:
                print(f"[auto] agent-coverage: gc'd {n_gc} stale shadow(s)",
                      file=sys.stderr)
        tips, non_tips = _agent_tip_worktrees(conn, canonical)
        if not tips:
            return
        if not args.quiet and non_tips:
            subsumed = ", ".join(
                f"{Path(w['path']).name}" for w in non_tips[:4]
            )
            print(f"[auto] agent-coverage: tip-set has "
                  f"{len(tips)} of {len(tips) + len(non_tips)} "
                  f"worktrees (subsumed: {subsumed})", file=sys.stderr)
        idle_secs = int(os.environ.get("LITEBOX_AGENT_IDLE_SECS")
                        or getattr(args, "agent_idle_secs", 300) or 300)
        eligible: list[dict] = []
        skipped: list[tuple[str, str]] = []
        for wt in tips:
            ok, reason = _agent_worktree_is_idle(wt, idle_secs, conn)
            if ok:
                eligible.append(wt)
            else:
                skipped.append((wt["path"], reason))
        if not eligible:
            if not args.quiet:
                summary = "; ".join(
                    f"{Path(p).name}: {r}" for p, r in skipped[:3]
                )
                print(f"[auto] agent-coverage: 0 idle of "
                      f"{len(tips)} tips ({summary})", file=sys.stderr)
            return
        pick_n = max(1, int(getattr(args, "max_parallel_agent_cargos", 1) or 1))
        picks = _pick_opportunistic_worktrees_topn(conn, eligible, pick_n)
        if not picks:
            return
        # Record the LAST pick (preserves the round-robin signal: that
        # one will be deprioritized next cycle).
        _record_picked(conn, picks[-1]["path"])
    finally:
        conn.close()
    if not args.quiet:
        names = ", ".join(
            f"{Path(p['path']).name}@{short_sha(p['head'])}" for p in picks
        )
        print(f"[auto] agent-coverage: driving {len(picks)} worktree(s) "
              f"in parallel: {names}", file=sys.stderr)
    if len(picks) == 1:
        # Hot path: no thread overhead when parallelism is disabled.
        _drive_agent_worktree(
            picks[0], args, pidfile=pidfile,
            supervisor_state=supervisor_state,
        )
        return
    threads: list[threading.Thread] = []
    for pick in picks:
        t = threading.Thread(
            target=_drive_agent_worktree,
            args=(pick, args),
            kwargs={"pidfile": pidfile, "supervisor_state": supervisor_state},
            name=f"agent-cov:{Path(pick['path']).name}",
            daemon=False,
        )
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


def _drive_agent_worktree(
    wt: dict,
    args: argparse.Namespace,
    *,
    pidfile: Optional[Path] = None,
    supervisor_state: Optional[dict] = None,
) -> bool:
    """Run a short `--fill` cycle from an agent worktree at its
    current HEAD. Unlike `_drive_ref`, this does NOT checkout —
    the agent's worktree is alive and we don't touch its working
    tree state. Whatever HEAD is recorded there at spawn time is
    what gets tested.

    Smaller wall-time budget than tracked-ref drives so round-robin
    across multiple agent worktrees stays responsive.
    """
    env = os.environ.copy()
    state_dir = resolve_state_dir(args.state_dir)
    canonical = _canonical_worktree(args, state_dir)
    shadow = _ensure_shadow_worktree(
        canonical, state_dir, wt.get("branch") or "", wt["head"],
    )
    if shadow is None:
        return False
    env["LITEBOX_DASHBOARD_DIR"] = str(state_dir)
    env["LITEBOX_DASHBOARD_REF"] = wt.get("branch") or "<detached>"
    # We deliberately do NOT override LITEBOX_DASHBOARD_WORKTREE_PATH
    # here — let runs.worktree_path record the shadow path. This makes
    # opportunistic runs trivially distinguishable in result-groups
    # (same trick the tracked-ref CI worktrees use), and the new
    # "Agent worktrees" section's aggregations are sha-scoped over
    # clean states anyway, so shadow + agent runs at the same HEAD
    # combine correctly without further coordination.
    fill_budget = int(os.environ.get("LITEBOX_AGENT_FILL_BUDGET")
                      or getattr(args, "agent_fill_budget", 180) or 180)
    cargo_args = [
        "cargo", "test", "-p", "litebox_test_harness",
        "--test", "integration", "--",
        f"--fill={fill_budget}s",
    ]
    deadline = time.monotonic() + (fill_budget * 2 + 600)
    proc = subprocess.Popen(
        cargo_args, cwd=str(shadow), env=env,
        start_new_session=True,
    )
    cargo_pgid = proc.pid
    # Register + initial pidfile write happen inside try/finally so a
    # failure between register and the polling loop still triggers
    # `_unregister_child` and doesn't leak the registry slot. See
    # also `_drive_ref` for the same pattern + history.
    child_id: Optional[int] = None
    harness_pid: Optional[int] = None
    poll_until = time.monotonic() + 30
    rc: Optional[int] = None
    try:
        if supervisor_state is not None:
            child_id = _register_child(
                supervisor_state, kind="agent-coverage",
                worktree_path=str(shadow),
            )
            _update_child(supervisor_state, child_id, cargo_pgid=cargo_pgid)
            if pidfile is not None:
                _write_pidfile_from_state(
                    pidfile, os.getpid(), supervisor_state,
                )
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            if harness_pid is None and time.monotonic() < poll_until:
                harness_pid = _find_harness_pid(proc.pid)
                if harness_pid is not None and child_id is not None:
                    _update_child(supervisor_state, child_id,
                                  harness_pid=harness_pid)
                    if pidfile is not None:
                        _write_pidfile_from_state(
                            pidfile, os.getpid(), supervisor_state,
                        )
            if time.monotonic() > deadline:
                print(f"[auto] agent-coverage cycle exceeded deadline; "
                      f"reaping PGID {cargo_pgid}", file=sys.stderr)
                _reap_pgid_and_containers(cargo_pgid, harness_pid,
                                          quiet=args.quiet)
                return False
            time.sleep(0.5)
    finally:
        if cargo_pgid is not None:
            stragglers = _pids_in_pgid(cargo_pgid)
            if stragglers:
                _reap_pgid_and_containers(cargo_pgid, harness_pid,
                                          quiet=args.quiet)
        if child_id is not None and supervisor_state is not None:
            _unregister_child(supervisor_state, child_id)
            if pidfile is not None:
                _write_pidfile_from_state(
                    pidfile, os.getpid(), supervisor_state,
                )
    # Optional sidecar after a successful cycle.
    if rc == 0 and (os.environ.get("LITEBOX_AGENT_SIDECAR")
                    or getattr(args, "agent_sidecar", False)):
        try:
            _write_agent_sidecar(wt, args)
        except Exception as e:
            print(f"[auto] agent-coverage sidecar failed: "
                  f"{type(e).__name__}: {e}", file=sys.stderr)
    return rc == 0


def _write_agent_sidecar(wt: dict, args: argparse.Namespace) -> None:
    """Write a focused `regressions.md` into the agent worktree so
    they can `cat` it without scrolling the full summary.md."""
    state_dir = resolve_state_dir(args.state_dir)
    canonical = _canonical_worktree(args, state_dir)
    conn = open_db(state_dir)
    try:
        agent_head = wt["head"]
        baseline = _pick_baseline_ref(conn, canonical, agent_head)
        if baseline is None:
            return
        out_dir = Path(wt["path"]) / ".dashboard"
        out_dir.mkdir(exist_ok=True)
        out = out_dir / "regressions.md"
        lines = [
            f"# Regressions vs `{baseline['ref']}`",
            "",
            f"_Worktree HEAD_: `{agent_head}` (branch "
            f"`{wt.get('branch') or '<detached>'}`)",
            f"_Baseline_: `{baseline['ref']}` @ "
            f"`{baseline['ref_head']}`",
            f"_Merge-base_: `{baseline['merge_base']}`",
            "",
        ]
        for label, base_sha in (
            ("merge-base", baseline["merge_base"]),
            ("baseline HEAD", baseline["ref_head"]),
        ):
            for pass_name in ("native", "litebox"):
                ids = _regression_test_ids(conn, base_sha, agent_head,
                                           pass_name, limit=50)
                if not ids:
                    continue
                lines.append(f"## vs {label} ({pass_name}) — {len(ids)}")
                lines.append("")
                for tid in ids:
                    lines.append(f"- `{tid}`")
                lines.append("")
        out.write_text("\n".join(lines))
    finally:
        conn.close()


# ─── Process-group + pidfile helpers ─────────────────────────────────


def _write_pidfile(path: Path, **fields) -> None:
    """Atomically (best-effort) write pidfile JSON.

    The tmp path is salted with `(pid, thread_id, monotonic_ns)` so
    concurrent writers don't share a tmp filename and race on the
    `replace()` — a previous shared `.tmp` suffix produced
    `FileNotFoundError` (one thread renamed the tmp away while
    another was about to rename the same path), which then bubbled
    out of `_write_pidfile_from_state` between `_register_child`
    and the `try`/`finally` in `_drive_*`, leaking the just-
    registered child slot. See dashboard.py git history (~2026-06).
    """
    tmp = path.with_suffix(
        f"{path.suffix}.{os.getpid()}.{threading.get_ident()}."
        f"{time.monotonic_ns()}.tmp"
    )
    tmp.write_text(json.dumps(fields))
    tmp.replace(path)


# ──────────────────────────────────────────────────────────────────
# Children registry — supervisor_state["children"] is the canonical
# in-memory record of every in-flight cargo invocation the supervisor
# has spawned. The pidfile (`auto.pidfile`) mirrors this to disk so
# `dashboard.py stop` can reap out-of-band. Multiple children can be
# alive concurrently when `--max-parallel-agent-cargos > 1`; one
# tracked-ref drive can also coexist with N agent drives in flight.
#
# All registry mutations go through these helpers and hold
# `supervisor_state["lock"]` so the signal handler can safely
# snapshot the registry from another thread without racing.
# ──────────────────────────────────────────────────────────────────


def _new_supervisor_state() -> dict:
    """Construct the supervisor's mutable shared state. Owned by the
    main loop; mutated from worker threads + the signal handler.
    Always created via this helper so the lock + counter invariants
    are uniform."""
    return {
        "children": {},        # child_id -> {"cargo_pgid", "harness_pid", "worktree_path", "kind"}
        "next_child_id": 1,
        "lock": threading.Lock(),
    }


def _register_child(state: dict, *, kind: str,
                    worktree_path: Optional[str]) -> int:
    """Reserve a child_id and record an empty slot. `kind` is
    'tracked-ref' or 'agent-coverage'; `worktree_path` is the cargo
    invocation's cwd (the shadow path for agent coverage, the
    ci_worktree for tracked refs).

    Returns the new child_id. Caller fills in cargo_pgid + harness_pid
    via `_update_child` once the subprocess is spawned.
    """
    with state["lock"]:
        cid = state["next_child_id"]
        state["next_child_id"] = cid + 1
        state["children"][cid] = {
            "cargo_pgid": None,
            "harness_pid": None,
            "worktree_path": worktree_path,
            "kind": kind,
        }
    return cid


def _update_child(state: dict, child_id: int, **fields) -> None:
    """Update fields on an existing child slot. Silently ignores
    unknown child_ids (the slot may have been removed already)."""
    with state["lock"]:
        slot = state["children"].get(child_id)
        if slot is None:
            return
        slot.update(fields)


def _unregister_child(state: dict, child_id: int) -> None:
    with state["lock"]:
        state["children"].pop(child_id, None)


def _snapshot_children(state: dict) -> list[dict]:
    """Stable copy of the children dict's values. Used by the
    signal handler and pidfile writer so they can iterate without
    holding the lock through I/O."""
    with state["lock"]:
        return [dict(slot) for slot in state["children"].values()]


def _write_pidfile_from_state(pidfile: Path, supervisor_pid: int,
                              state: dict) -> None:
    """Mirror the current children registry to disk. Replaces the
    pidfile atomically. Called whenever the registry changes so
    `dashboard.py stop` always sees the latest in-flight PGIDs."""
    children = _snapshot_children(state)
    _write_pidfile(
        pidfile,
        supervisor_pid=supervisor_pid,
        children=children,
    )


def _reap_all_children(state: dict, *, quiet: bool) -> None:
    """Reap every in-flight cargo PGID recorded in the registry.
    Best-effort; failures don't abort. Called from the SIGTERM/SIGINT
    handler and the cycle-exit safety net."""
    for slot in _snapshot_children(state):
        pgid = slot.get("cargo_pgid")
        if pgid is None:
            continue
        _reap_pgid_and_containers(
            pgid, slot.get("harness_pid"), quiet=quiet,
        )


def _read_pidfile(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _find_harness_pid(cargo_pid: int) -> Optional[int]:
    """Scan /proc for the integration test binary spawned by cargo.

    Cargo's test binary is `target/{profile}/deps/integration-<hash>`;
    walk cargo_pid's task children and look for an executable name
    starting with `integration-`.
    """
    children_path = Path(f"/proc/{cargo_pid}/task/{cargo_pid}/children")
    try:
        children = children_path.read_text().split()
    except FileNotFoundError:
        return None
    for cpid_s in children:
        try:
            cpid = int(cpid_s)
        except ValueError:
            continue
        try:
            comm = Path(f"/proc/{cpid}/comm").read_text().strip()
        except FileNotFoundError:
            continue
        if comm.startswith("integration-"):
            return cpid
        # cargo may have an intermediate wrapper; recurse one level.
        sub = _find_harness_pid(cpid)
        if sub is not None:
            return sub
    return None


def _pids_in_pgid(pgid: int) -> list[int]:
    """Return all live PIDs whose PGID matches `pgid`."""
    out: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        # Race window: the proc directory listing can include a PID
        # whose entire /proc/<pid>/ tree disappears before we read
        # stat. Both FileNotFoundError and ProcessLookupError
        # (errno=ESRCH from open) are valid "process exited" signals;
        # PermissionError can also surface for processes the current
        # user can't inspect — treat all three as "skip, not in PGID".
        try:
            stat = (entry / "stat").read_text()
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            continue
        # /proc/<pid>/stat fields: pid, (comm), state, ppid, pgrp, ...
        # comm can contain spaces and parens, so split on the last ')'.
        try:
            after = stat.rsplit(")", 1)[1]
            fields = after.split()
            this_pgid = int(fields[2])  # field 5 overall; index 2 after comm
        except (IndexError, ValueError):
            continue
        if this_pgid == pgid:
            out.append(pid)
    return out


def _reap_pgid_and_containers(
    cargo_pgid: Optional[int],
    harness_pid: Optional[int],
    *,
    quiet: bool = False,
) -> None:
    """SIGTERM → grace → SIGKILL the cargo process group, then sweep
    any zombie containers tagged with `harness_pid`."""
    if cargo_pgid is not None and _pids_in_pgid(cargo_pgid):
        try:
            os.killpg(cargo_pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + _PGID_SIGTERM_GRACE_SECS
        while time.monotonic() < deadline:
            if not _pids_in_pgid(cargo_pgid):
                break
            time.sleep(0.5)
        if _pids_in_pgid(cargo_pgid):
            if not quiet:
                print(f"[reap] PGID {cargo_pgid} did not honor SIGTERM; "
                      "escalating to SIGKILL", file=sys.stderr)
            try:
                os.killpg(cargo_pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    # Sweep containers by harness-pid salt. The harness's own signal
    # handler does this too, but we re-run here as belt-and-suspenders
    # in case the harness was SIGKILL'd before it could clean up.
    if harness_pid is not None:
        _sweep_containers(harness_pid, quiet=quiet)


def _sweep_containers(harness_pid: int, *, quiet: bool = False) -> None:
    """`docker rm -f` any container whose name embeds `harness_pid`.

    Container names are
    `litebox-{pass}-{test_id}-{harness_pid}-{counter}` for BOTH
    passes — native trials and litebox trials both run inside
    docker. The `litebox-` prefix is just brand; the `{pass}`
    segment is what differs (`native` vs `litebox`). See
    `tests/common/framework_core::container_name`. We filter by
    the `-{harness_pid}-` salt so the sweep covers every
    container this harness spawned, regardless of pass. `docker
    ps -aq --filter name=...` uses substring matching, which is
    why the salt is bracketed by dashes for specificity.
    """
    try:
        out = subprocess.run(
            ["docker", "ps", "-aq", "--filter",
             f"name=-{harness_pid}-"],
            capture_output=True, text=True, timeout=60,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return
    cids = [c for c in out.stdout.split() if c]
    if not cids:
        return
    if not quiet:
        print(f"[reap] removing {len(cids)} container(s) for "
              f"harness pid {harness_pid}", file=sys.stderr)
    # Batched rm to avoid argv overflow + bounded parallelism via the
    # daemon itself.
    for i in range(0, len(cids), 50):
        try:
            subprocess.run(
                ["docker", "rm", "-f", *cids[i:i + 50]],
                capture_output=True, timeout=120,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return


# ─── stop subcommand ─────────────────────────────────────────────────


def cmd_drain(args: argparse.Namespace) -> int:
    """Ask a running `dashboard.py auto` supervisor to exit cleanly
    after its current cycle. Sends SIGUSR1, then optionally polls
    for the supervisor to exit.

    Use this instead of `stop` when you want to deploy a new
    version of the script without killing in-flight trials. Trials
    that have already streamed verdicts to `run_results` are
    persisted; trials still executing when stop is sent would be
    lost.
    """
    state_dir = resolve_state_dir(args.state_dir)
    pidfile = state_dir / "auto.pidfile"
    state = _read_pidfile(pidfile)
    if state is None:
        print(f"[drain] no pidfile at {pidfile}; nothing to drain",
              file=sys.stderr)
        return 0
    sup = state.get("supervisor_pid")
    if not sup:
        print("[drain] pidfile has no supervisor_pid", file=sys.stderr)
        return 1
    try:
        os.kill(sup, signal.SIGUSR1)
    except ProcessLookupError:
        print(f"[drain] supervisor {sup} already gone", file=sys.stderr)
        return 0
    if not args.quiet:
        print(f"[drain] SIGUSR1 → supervisor pid {sup}; will exit "
              f"after current cycle completes", file=sys.stderr)
    if not args.wait:
        return 0
    # Poll until supervisor exits. Cycle budget can be 10-30 min;
    # don't bound the wait — the user explicitly asked for --wait.
    if not args.quiet:
        print("[drain] waiting for supervisor to exit "
              "(Ctrl-C to detach)…", file=sys.stderr)
    try:
        while True:
            try:
                os.kill(sup, 0)
            except ProcessLookupError:
                break
            time.sleep(2)
    except KeyboardInterrupt:
        print("[drain] detached; supervisor will still exit at "
              "cycle boundary", file=sys.stderr)
        return 0
    if not args.quiet:
        print("[drain] supervisor exited cleanly", file=sys.stderr)
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    """Stop a running `dashboard.py auto` supervisor and reap all its
    descendants + containers.

    Reads `<state_dir>/auto.pidfile`, SIGTERMs the supervisor (which
    triggers its own in-process cleanup handler), waits up to
    {_SUPERVISOR_SIGTERM_GRACE_SECS}s, then escalates to a direct
    PGID reap + container sweep if the supervisor didn't honor it.
    """
    state_dir = resolve_state_dir(args.state_dir)
    pidfile = state_dir / "auto.pidfile"
    state = _read_pidfile(pidfile)
    if state is None:
        print(f"[stop] no pidfile at {pidfile}; nothing to stop",
              file=sys.stderr)
        return 0
    sup = state.get("supervisor_pid")
    children = state.get("children") or []
    if sup:
        try:
            os.kill(sup, signal.SIGTERM)
            if not args.quiet:
                print(f"[stop] SIGTERM → supervisor pid {sup}",
                      file=sys.stderr)
        except ProcessLookupError:
            if not args.quiet:
                print(f"[stop] supervisor {sup} already gone",
                      file=sys.stderr)
            sup = None
    if sup:
        deadline = time.monotonic() + _SUPERVISOR_SIGTERM_GRACE_SECS
        while time.monotonic() < deadline:
            try:
                os.kill(sup, 0)
            except ProcessLookupError:
                break
            time.sleep(0.5)
        else:
            print(f"[stop] supervisor {sup} did not exit in "
                  f"{_SUPERVISOR_SIGTERM_GRACE_SECS}s; escalating",
                  file=sys.stderr)
            try:
                os.kill(sup, signal.SIGKILL)
            except ProcessLookupError:
                pass
    # Belt-and-suspenders: even if the supervisor handler ran, sweep
    # every child PGID + harness in case it missed anything (e.g. it
    # was SIGKILL'd above before completing).
    for slot in children:
        _reap_pgid_and_containers(
            slot.get("cargo_pgid"), slot.get("harness_pid"),
            quiet=args.quiet,
        )
    try:
        pidfile.unlink()
    except FileNotFoundError:
        pass
    if not args.quiet:
        print("[stop] done", file=sys.stderr)
    return 0


# ─── argparse ────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dashboard.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--state-dir", help="override dashboard state directory")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_render = sub.add_parser("render", help="write summary.md once")
    p_render.add_argument("--quiet", "-q", action="store_true")
    p_render.set_defaults(func=cmd_render)

    p_status = sub.add_parser("status", help="terminal-friendly summary")
    p_status.add_argument("--format", choices=("text", "md", "sql"), default="text")
    p_status.set_defaults(func=cmd_status)

    p_migrate = sub.add_parser(
        "migrate",
        help="lossless in-place schema migration (v3 → v4: rename "
             "run_results.pass → mode, lower-case 'FAIL' verdicts). "
             "Idempotent; back up results.sqlite first.",
    )
    p_migrate.set_defaults(func=cmd_migrate)

    p_regr = sub.add_parser(
        "regressions",
        help="classify a branch's failing tests as hard/soft "
             "regression, new_fail, etc. with a confidence tier "
             "(reads the regression_class view).",
    )
    p_regr.add_argument("branch",
                        help="branch name or commit sha (prefix ok)")
    p_regr.add_argument("--format", choices=("text", "sql"), default="text")
    p_regr.add_argument("--limit", type=int, default=30,
                        help="max test_ids listed per bucket (text mode)")
    p_regr.add_argument("--no-refresh", action="store_true",
                        help="skip recomputing branch_baseline "
                             "(git merge-bases) before reading the view")
    p_regr.add_argument("--canonical-worktree", default=None,
                        help="canonical clone root for git queries "
                             "(default: state-dir's parent)")
    p_regr.set_defaults(func=cmd_regressions)

    p_track = sub.add_parser(
        "track",
        help="register a tracked ref (creates the CI worktree if missing)",
    )
    p_track.add_argument("ref", help="e.g. origin/wportnoy/vscode-server-in-litebox")
    p_track.add_argument(
        "ci_worktree",
        help="absolute path for the CI worktree (created on demand "
             "via `git worktree add --detach`)",
    )
    p_track.set_defaults(func=cmd_track)

    p_untrack = sub.add_parser(
        "untrack",
        help="remove a tracked ref (also removes the CI worktree by default)",
    )
    p_untrack.add_argument("ref")
    p_untrack.add_argument(
        "--keep-worktree", action="store_true",
        help="don't run `git worktree remove`",
    )
    p_untrack.add_argument(
        "--force", action="store_true",
        help="pass --force to `git worktree remove` (removes dirty worktrees)",
    )
    p_untrack.set_defaults(func=cmd_untrack)

    p_refs = sub.add_parser("refs", help="list tracked refs")
    p_refs.set_defaults(func=cmd_refs)

    p_auto = sub.add_parser("auto", help="autonomous fill driver")
    p_auto.add_argument(
        "--interval", type=int, default=10,
        help="sleep between full passes (default 10s — was 60s "
             "historically; container teardown happens in the "
             "background so back-to-back cycles are fine)",
    )
    p_auto.add_argument(
        "--cycle-budget-secs", type=int, default=600,
        help="per-ref cycle wall-time budget passed to "
             "`--fill=<budget>s` (default 600s = 10min). The Rust "
             "selector packs as many trials as fit.",
    )
    p_auto.add_argument(
        "--batch-size", type=int, default=None,
        help="override: hard count of trials per cycle. Mutually "
             "exclusive with the time-budget mode; sets "
             "`--fill=N` instead. Default None (use --cycle-budget-secs).",
    )
    p_auto.add_argument("--once", action="store_true",
                        help="run one pass and exit")
    p_auto.add_argument(
        "--canonical-worktree", default=None,
        help="canonical clone root for `git worktree list` / "
             "merge-base queries (default: state-dir's parent).",
    )
    p_auto.add_argument(
        "--agent-idle-secs", type=int, default=300,
        help="seconds a worktree must have no source-file mtime "
             "change AND no live lease before opportunistic "
             "coverage will spawn a cycle there (default 300s = "
             "5min). Env override: LITEBOX_AGENT_IDLE_SECS.",
    )
    p_auto.add_argument(
        "--agent-fill-budget", type=int, default=180,
        help="`--fill=Ns` budget for opportunistic agent-worktree "
             "cycles (default 180s). Env override: "
             "LITEBOX_AGENT_FILL_BUDGET.",
    )
    p_auto.add_argument(
        "--agent-sidecar", action="store_true",
        help="after a successful agent-worktree cycle, write a "
             "focused `<worktree>/.dashboard/regressions.md` so the "
             "agent can `cat` it without scrolling summary.md. Env "
             "override: LITEBOX_AGENT_SIDECAR.",
    )
    p_auto.add_argument(
        "--max-parallel-agent-cargos", type=int, default=4,
        metavar="N",
        help="maximum number of agent-coverage cargo cycles to spawn "
             "in parallel per supervisor tick (default 4). Each "
             "cycle runs in its own per-branch shadow worktree, so "
             "they don't collide on `target/` or docker image tags; "
             "CPU is throttled automatically by the harness lease "
             "table (LITEBOX_GLOBAL_JOBS / live_lease_count), so no "
             "one cargo starves at higher N — each still gets at "
             "least 1 job. Set to 1 to disable parallelism.",
    )
    p_auto.add_argument(
        "--max-parallel-tracked-refs", type=int, default=4,
        metavar="N",
        help="maximum number of tracked-ref cargo cycles to drive "
             "in parallel per supervisor tick (default 4). Each "
             "ref has its own ci_worktree, so parallel drives don't "
             "collide on `target/` or docker container names; same "
             "lease-throttled CPU sharing as agent-coverage. Set to "
             "1 to disable parallelism.",
    )
    p_auto.add_argument(
        "--agent-coverage-disable", action="store_true",
        help="disable opportunistic agent-worktree coverage "
             "entirely; supervisor only drives tracked refs.",
    )
    p_auto.add_argument("--quiet", "-q", action="store_true")
    p_auto.set_defaults(func=cmd_auto)

    p_stop = sub.add_parser(
        "stop",
        help="stop a running `dashboard.py auto` supervisor and reap "
             "all its descendants (cargo, harness, in-flight docker "
             "containers).",
    )
    p_stop.add_argument("--quiet", "-q", action="store_true")
    p_stop.set_defaults(func=cmd_stop)

    p_drain = sub.add_parser(
        "drain",
        help="ask a running `dashboard.py auto` supervisor to exit "
             "cleanly after its current cargo cycle (SIGUSR1). "
             "Use this instead of `stop` when redeploying so that "
             "in-flight trials are not killed.",
    )
    p_drain.add_argument("--wait", action="store_true",
                         help="block until the supervisor exits")
    p_drain.add_argument("--quiet", "-q", action="store_true")
    p_drain.set_defaults(func=cmd_drain)

    return p


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
