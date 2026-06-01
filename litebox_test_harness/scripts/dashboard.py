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
    dashboard.py stop                            # stop the auto driver + reap descendants

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
import time
from pathlib import Path
from typing import Iterable, Optional

SCHEMA_VERSION_EXPECTED = 3
DEFAULT_FILL_BATCH = 300

# Container-name salt prefix the harness uses
# (see tests/integration.rs build of container_name: "litebox-{pass}-{tid}-{harness_pid}-{nanos}").
# We sweep by `litebox-*-{harness_pid}-*` on cleanup escalation.
CONTAINER_NAME_PREFIX = "litebox-"

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


def open_db(state_dir: Path, *, bootstrap: bool = False) -> sqlite3.Connection:
    """Open the dashboard sqlite store.

    `bootstrap=True` initializes an empty store + schema if the file
    doesn't exist yet — used by `track` so the user can register a
    tracked ref before the producer has ever run. Other subcommands
    pass `bootstrap=False` (the default) and exit with a helpful
    message instead of silently creating an empty store.
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
    return conn


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
            "Run a fresh integration test to recreate the store."
        )


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


# ─── Trend helpers ───────────────────────────────────────────────────


def state_verdicts(
    conn: sqlite3.Connection, commit_sha: str, dirty_hash: Optional[str],
) -> dict[tuple[str, str], str]:
    """Return `{(test_id, pass): verdict}` for the freshest verdict
    per (test_id, pass) at this `(commit_sha, dirty_hash)` state.

    Handles dirty_hash NULL semantics correctly (`IS NULL` vs `= ?`)
    so a clean-state lookup doesn't accidentally include dirty runs.

    Used by Result groups + Commit-delta rendering. Computing the
    freshest verdict per (test_id, pass) within a state means counts
    are always consistent (`cov = pass + fail`, no double-count when
    the same test ran twice at the same sha with different outcomes).
    """
    if dirty_hash is None:
        sql = (
            "SELECT rr.test_id, rr.pass, rr.verdict, rr.finished_ts_ms "
            "  FROM run_results rr "
            "  JOIN runs r ON r.run_id = rr.run_id "
            " WHERE r.commit_sha = ? AND r.dirty_hash IS NULL"
        )
        params = (commit_sha,)
    else:
        sql = (
            "SELECT rr.test_id, rr.pass, rr.verdict, rr.finished_ts_ms "
            "  FROM run_results rr "
            "  JOIN runs r ON r.run_id = rr.run_id "
            " WHERE r.commit_sha = ? AND r.dirty_hash = ?"
        )
        params = (commit_sha, dirty_hash)
    freshest: dict[tuple[str, str], tuple[str, int]] = {}
    for r in conn.execute(sql, params):
        key = (r["test_id"], r["pass"])
        if key not in freshest or r["finished_ts_ms"] > freshest[key][1]:
            freshest[key] = (r["verdict"], r["finished_ts_ms"])
    return {k: v[0] for k, v in freshest.items()}


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
    parts.append(_render_meta(conn, state_dir))
    parts.append(_render_leases(conn))
    parts.append(_render_velocity(conn))
    parts.append(_render_tracked_refs(conn))
    parts.append(_render_result_groups(conn))
    parts.append(_render_suite_group_breakdown(conn))
    parts.append(_render_current_fails(conn))
    parts.append(_render_recent_runs(conn))
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
            SELECT test_id, pass, MIN(finished_ts_ms) AS first_ts
              FROM run_results
             GROUP BY test_id, pass
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
            SELECT test_id, pass
              FROM run_results
             WHERE finished_ts_ms > ?
             GROUP BY test_id, pass
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
        r["pass"]: r["n"]
        for r in conn.execute(
            'SELECT pass, COUNT(DISTINCT test_id) AS n '
            'FROM run_results GROUP BY pass'
        )
    }

    lines = ["## Tracked refs\n",
             "| Ref | Worktree | Pass | HEAD | Coverage trend "
             "| native total | native cov | native pass | native fail "
             "| litebox total | litebox cov | litebox pass | litebox fail |",
             "|---|---|---|---|---"
             "|---:|---:|---:|---:"
             "|---:|---:|---:|---:|"]
    for r in refs:
        ref = r["ref"]
        ci_wt = r["ci_worktree"]
        head_sha = _git_head(ci_wt)
        if head_sha is None:
            lines.append(
                f"| `{ref}` | `{ci_wt}` | — | _missing_ | — "
                f"| — | — | — | — | — | — | — | — |"
            )
            continue
        cells: list[str] = []
        for pass_name in ("native", "litebox"):
            covered, n_pass, n_fail = _coverage_pass_fail(
                conn, head_sha, pass_name
            )
            total = per_pass_universe.get(pass_name) or (universe_n // 2 if universe_n else 0)
            cells.extend([
                str(total) if total else "?",
                str(covered),
                str(n_pass),
                str(n_fail),
            ])
        last_run_age = _last_run_age_for_ci_worktree(conn, ci_wt)
        spark = _coverage_sparkline_for_worktree(conn, ci_wt)
        lines.append(
            f"| `{ref}` | `{Path(ci_wt).name}` | {last_run_age} | "
            f"`{short_sha(head_sha)}` | `{spark}` | "
            + " | ".join(cells) + " |"
        )
    return "\n".join(lines) + "\n"


def _coverage_sparkline_for_worktree(
    conn: sqlite3.Connection, ci_worktree: str, n: int = 10,
) -> str:
    """Per-tracked-ref coverage trend: last `n` clean runs from this
    CI worktree, plotted as a unicode sparkline of pass_count. Tells
    you "are we going up, flat, or falling" without needing a chart.
    """
    rows = conn.execute(
        "SELECT pass_count FROM runs"
        " WHERE worktree_path = ? AND dirty_hash IS NULL"
        "   AND pass_count IS NOT NULL"
        " ORDER BY started_ts_ms DESC LIMIT ?",
        (ci_worktree, n),
    ).fetchall()
    values = [r[0] for r in reversed(rows)]  # chronological for display
    if not values:
        return ""
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


def _coverage_pass_fail(
    conn: sqlite3.Connection, commit_sha: str, pass_name: str,
) -> tuple[int, int, int]:
    """Return (covered_count, n_pass, n_fail) for a (commit_sha, pass).
    Only counts clean-state runs (dirty_hash IS NULL). Uses the
    **freshest** verdict per test_id at this sha (matches
    latest_results semantics) so the class-2 retry case — a test that
    failed then recovered at the same sha — is counted as one pass,
    not as pass+fail. Anything whose freshest verdict isn't 'pass'
    (FAIL, timeout, error, etc.) counts as a fail, so the invariant
    `covered = pass + fail` always holds.
    """
    row = conn.execute(
        """
        WITH freshest AS (
            SELECT rr.test_id, rr.verdict,
                   ROW_NUMBER() OVER (
                       PARTITION BY rr.test_id
                       ORDER BY rr.finished_ts_ms DESC
                   ) AS rn
              FROM run_results rr
              JOIN runs r ON r.run_id = rr.run_id
             WHERE r.commit_sha = ? AND r.dirty_hash IS NULL
               AND rr.pass = ?
        )
        SELECT COUNT(*) AS covered,
               SUM(CASE WHEN verdict = 'pass' THEN 1 ELSE 0 END) AS n_pass,
               SUM(CASE WHEN verdict <> 'pass' THEN 1 ELSE 0 END) AS n_fail
          FROM freshest
         WHERE rn = 1
        """,
        (commit_sha, pass_name),
    ).fetchone()
    if not row:
        return (0, 0, 0)
    return (row["covered"] or 0, row["n_pass"] or 0, row["n_fail"] or 0)


def _last_run_age_for_ci_worktree(conn: sqlite3.Connection, wt: str) -> str:
    row = conn.execute(
        "SELECT MAX(finished_ts_ms) FROM runs WHERE worktree_path = ?",
        (wt,),
    ).fetchone()
    if not row or row[0] is None:
        return "—"
    return f"{fmt_age_ms(now_ms() - int(row[0]))} ago"


def _render_result_groups(conn: sqlite3.Connection) -> str:
    """One row per `(commit_sha, dirty_hash)` partition that has any
    results. Per-pass cov/pass/fail use the freshest verdict per
    (test_id, pass) within the state (so `cov = pass + fail` always
    holds even when the same test ran twice with different outcomes).

    Adds a `Δ vs prior` column showing
    `+P passing · −R regressions · +N newly covered` against the
    state directly older than this row.

    Sorted newest-first so the current state is on top.
    """
    # Discover all (commit_sha, dirty_hash) states + their newest_ms
    # and contributing worktrees.
    state_rows = conn.execute(
        """
        SELECT r.commit_sha, r.dirty_hash,
               MAX(rr.finished_ts_ms) AS newest_ms,
               GROUP_CONCAT(DISTINCT r.worktree_path) AS worktrees
          FROM run_results rr
          JOIN runs r ON r.run_id = rr.run_id
         GROUP BY r.commit_sha, r.dirty_hash
        """
    ).fetchall()
    if not state_rows:
        return ""

    # Build the per-state verdicts dict once per (sha, dirty_hash).
    # Use freshest-per-(test_id, pass)-within-state semantics so
    # counts and delta computations agree.
    states: dict[tuple[str, Optional[str]], dict] = {}
    for r in state_rows:
        key = (r["commit_sha"], r["dirty_hash"])
        verdicts = state_verdicts(conn, r["commit_sha"], r["dirty_hash"])
        states[key] = {
            "newest_ms": r["newest_ms"] or 0,
            "worktrees": set(
                w for w in (r["worktrees"] or "").split(",") if w
            ),
            "verdicts": verdicts,
        }

    # Tracked-ref overlay so the table can mark which partitions are
    # produced by the autonomous driver vs ad-hoc / agent runs.
    tracked: dict[str, str] = {}  # commit_sha → ref label
    for r in conn.execute("SELECT ref, ci_worktree FROM tracked_refs"):
        head = _git_head(r["ci_worktree"])
        if head:
            tracked[head] = r["ref"]

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
        r["pass"]: r["n"]
        for r in conn.execute(
            'SELECT pass, COUNT(DISTINCT test_id) AS n '
            'FROM run_results GROUP BY pass'
        )
    }

    now = now_ms()
    lines = ["## Result groups (per commit × dirty-state)\n",
             "| Tracked ref | Sha | Dirty | Worktree(s) "
             "| native total | native cov | native pass | native fail "
             "| litebox total | litebox cov | litebox pass | litebox fail "
             "| Newest | Δ vs prior |",
             "|---|---|---|---"
             "|---:|---:|---:|---:"
             "|---:|---:|---:|---:|---|---|"]

    # Sort newest-first; for each row, the "prior" state is the
    # next entry in the list (one older in time).
    ordered: list[tuple[tuple[str, Optional[str]], dict]] = sorted(
        states.items(), key=lambda kv: kv[1]["newest_ms"], reverse=True
    )
    for i, ((sha, dirty_hash), g) in enumerate(ordered):
        tag = f"_{tracked[sha]}_" if sha in tracked else ""
        dirty = "⚠" if dirty_hash else ""
        wt_short = ", ".join(
            sorted(os.path.basename(w) for w in g["worktrees"])
        )
        cells: list[str] = []
        for pass_name in ("native", "litebox"):
            cov, n_pass, n_fail = _counts_from_verdicts(g["verdicts"], pass_name)
            # Per-pass universe; fall back to halved grand total if
            # the table is empty (very fresh DB).
            total = per_pass_universe.get(pass_name) or (universe_n // 2 if universe_n else 0)
            cells.extend([
                str(total) if total else "?",
                str(cov),
                str(n_pass),
                str(n_fail),
            ])
        age = fmt_age_ms(now - g["newest_ms"]) if g["newest_ms"] else "—"
        # Δ vs the immediately-older state in the sort order.
        if i + 1 < len(ordered):
            prior = ordered[i + 1][1]["verdicts"]
            regressions, fixes, newly = state_delta(prior, g["verdicts"])
            delta = (
                f"+{len(fixes)} fixed · −{len(regressions)} regressed · "
                f"+{len(newly)} new"
            )
        else:
            delta = "_(oldest)_"
        lines.append(
            f"| {tag} | `{short_sha(sha)}` | {dirty} | `{wt_short}` | "
            + " | ".join(cells) + f" | {age} | {delta} |"
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
    from collections import defaultdict
    per_bucket_pass: dict[tuple[str, str, str], dict[str, int]] = defaultdict(
        lambda: {"covered": 0, "pass": 0, "fail": 0}
    )
    per_bucket_ids: dict[tuple[str, str], set] = defaultdict(set)
    for r in conn.execute(
        'SELECT test_id, pass, verdict, suite, "group" FROM latest_results'
    ):
        suite = r["suite"]
        group = r["group"]
        key = (suite, group, r["pass"])
        per_bucket_pass[key]["covered"] += 1
        if r["verdict"] == "pass":
            per_bucket_pass[key]["pass"] += 1
        else:
            per_bucket_pass[key]["fail"] += 1
        per_bucket_ids[(suite, group)].add(r["test_id"])
    if not per_bucket_pass:
        return ""

    totals = {k: len(v) for k, v in per_bucket_ids.items()}
    buckets: dict[tuple[str, str], dict] = {}
    for (suite, group, pass_name), counts in per_bucket_pass.items():
        b = buckets.setdefault(
            (suite, group),
            {"native": (0, 0, 0), "litebox": (0, 0, 0)},
        )
        b[pass_name] = (counts["covered"], counts["pass"], counts["fail"])

    lines = ["## By suite × group (observed universe)\n",
             "| Suite | Group "
             "| native total | native cov | native pass | native fail "
             "| litebox total | litebox cov | litebox pass | litebox fail |",
             "|---|---"
             "|---:|---:|---:|---:"
             "|---:|---:|---:|---:|"]
    for (suite, group), b in sorted(buckets.items()):
        total = totals.get((suite, group), 0)
        cells: list[str] = []
        for pass_name in ("native", "litebox"):
            cov, p, f = b[pass_name]
            cells.extend([str(total), str(cov), str(p), str(f)])
        lines.append(f"| {suite} | {group} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def _render_current_fails(conn: sqlite3.Connection) -> str:
    """Tests currently FAILING at any active worktree's current head.

    "Current head" is:
      * Tracked refs: `git rev-parse <ref>` (canonical, authoritative).
      * Non-tracked worktrees: the commit_sha of that worktree's
        most-recent run in the last 24 h (best inference — we
        can't read non-tracked worktrees' git state).

    Filters out **stale-old-sha** fails (worktree has produced
    newer runs at a different sha — the old fail isn't actionable
    because the worktree has moved on) while keeping
    **actively-failing-on-someone's-branch** fails.

    Tracked-ref fails are clearly the canonical CI signal; the
    non-tracked rows are tagged `_(non-tracked)_` so they're
    visually distinguishable. Both are useful: tracked tells you
    "is canonical CI green?", non-tracked tells you "what is
    another active session currently hitting?".

    A test with mixed last-10 history (both ✓ and ✗) is tagged
    `_(flaky)_` so flakes are distinguishable from fresh
    regressions at a glance.
    """
    # Tracked refs: authoritative via on-disk git.
    tracked: dict[str, str] = {}  # worktree_path → ref label
    tracked_shas: dict[str, str] = {}  # worktree_path → current sha
    for r in conn.execute("SELECT ref, ci_worktree FROM tracked_refs"):
        sha = _git_head(r["ci_worktree"])
        if sha:
            tracked[r["ci_worktree"]] = r["ref"]
            tracked_shas[r["ci_worktree"]] = sha

    # Non-tracked worktrees: infer current sha from most recent run.
    # Limit to last 24 h so abandoned worktrees fall off.
    now = now_ms()
    cutoff = now - 24 * 3600 * 1000
    worktree_shas: dict[str, str] = dict(tracked_shas)
    for r in conn.execute(
        "SELECT worktree_path, commit_sha FROM runs WHERE started_ts_ms > ? "
        "AND (worktree_path, started_ts_ms) IN "
        "  (SELECT worktree_path, MAX(started_ts_ms) FROM runs "
        "    WHERE started_ts_ms > ? GROUP BY worktree_path)",
        (cutoff, cutoff),
    ):
        wt = r["worktree_path"]
        if wt and wt not in worktree_shas and r["commit_sha"]:
            worktree_shas[wt] = r["commit_sha"]

    if not worktree_shas:
        return "## Current FAILs\n\n_None._\n"

    # For each (worktree, current_sha) pair, find tests whose
    # freshest verdict at that (clean) state is non-pass.
    # Dedupe per (test_id, pass, worktree) so the same test
    # failing on multiple worktrees shows once per worktree.
    out_rows: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for wt, sha in worktree_shas.items():
        for r in conn.execute(
            """
            SELECT rr.test_id, rr.pass, rr.verdict, rr.suite, rr."group",
                   rr.finished_ts_ms, r.commit_sha, r.dirty_hash, r.worktree_path
              FROM run_results rr
              JOIN runs r ON r.run_id = rr.run_id
             WHERE r.commit_sha = ?
               AND r.worktree_path = ?
               AND r.dirty_hash IS NULL
               AND (rr.test_id, rr.pass, rr.finished_ts_ms) IN (
                    SELECT rr2.test_id, rr2.pass, MAX(rr2.finished_ts_ms)
                      FROM run_results rr2
                      JOIN runs r2 ON r2.run_id = rr2.run_id
                     WHERE r2.commit_sha = ?
                       AND r2.worktree_path = ?
                       AND r2.dirty_hash IS NULL
                     GROUP BY rr2.test_id, rr2.pass
                   )
               AND rr.verdict <> 'pass'
            """,
            (sha, wt, sha, wt),
        ):
            key = (r["test_id"], r["pass"], wt)
            if key in seen:
                continue
            seen.add(key)
            out_rows.append(dict(r))

    if not out_rows:
        return "## Current FAILs\n\n_None at any active worktree's current head._\n"
    out_rows.sort(
        key=lambda r: (r["pass"], r["suite"], r["group"], r["test_id"], r["worktree_path"])
    )

    n_tracked = len(tracked_shas)
    n_other = len(worktree_shas) - n_tracked
    intro = (
        f"_Freshest verdict at each worktree's current head (clean). "
        f"{n_tracked} tracked + {n_other} non-tracked worktree(s) "
        f"active in last 24 h. Stale fails from older shas "
        f"(worktree has moved on) are excluded._\n"
    )
    lines = ["## Current FAILs\n",
             intro,
             "| Pass | Suite | Group | Test | Worktree | Sha | Dirty "
             "| Last 10 | Age |",
             "|---|---|---|---|---|---|---:|---|---|"]
    for r in out_rows:
        dirty = "⚠" if r["dirty_hash"] else ""
        wt_short = os.path.basename(r["worktree_path"] or "?")
        tracked_marker = "" if r["worktree_path"] in tracked else " _(non-tracked)_"
        history = _verdict_history(conn, r["test_id"], r["pass"], n=10)
        flaky = ("✓" in history) and ("✗" in history)
        flaky_marker = " _(flaky)_" if flaky else ""
        lines.append(
            f"| `{r['pass']}` | {r['suite']} | {r['group']} | "
            f"`{r['test_id']}`{flaky_marker} | "
            f"`{wt_short}`{tracked_marker} | "
            f"`{short_sha(r['commit_sha'])}` | {dirty} | "
            f"`{history}` | {fmt_age_ms(now - r['finished_ts_ms'])} |"
        )
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
        " WHERE test_id = ? AND pass = ?"
        " ORDER BY finished_ts_ms DESC LIMIT ?",
        (test_id, pass_name, n),
    ).fetchall()
    # rows[0] is the most recent; reverse so newest is on the right.
    chars: list[str] = []
    for r in reversed(rows):
        v = r["verdict"]
        if v == "pass":
            chars.append("✓")
        elif v == "FAIL":
            chars.append("✗")
        else:
            chars.append("·")
    return "".join(chars) or "—"


def _render_recent_runs(conn: sqlite3.Connection) -> str:
    rows = conn.execute(
        """
        SELECT run_id, started_ts_ms, finished_ts_ms, hostname,
               worktree_path, commit_sha, dirty_hash,
               pass_count, fail_count, universe_size
          FROM runs
         ORDER BY started_ts_ms DESC
         LIMIT 10
        """
    ).fetchall()
    if not rows:
        return ""
    lines = ["## Recent runs\n",
             "| # | Started | Worktree | Sha | Dirty | Pass | FAIL | Universe |",
             "|---|---|---|---|---:|---:|---:|---:|"]
    now = now_ms()
    for r in rows:
        dirty = "⚠" if r["dirty_hash"] else ""
        wt_short = os.path.basename(r["worktree_path"] or "?")
        age = fmt_age_ms(now - (r["started_ts_ms"] or now))
        lines.append(
            f"| {r['run_id']} | {age} ago | `{wt_short}` | "
            f"`{short_sha(r['commit_sha'])}` | {dirty} | "
            f"{r['pass_count'] or 0} | {r['fail_count'] or 0} | "
            f"{r['universe_size'] or '?'} |"
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
            "SELECT pass, verdict, COUNT(*) AS n FROM latest_results"
            " GROUP BY pass, verdict ORDER BY pass, verdict"
        ):
            print(f"{row['pass']}\t{row['verdict']}\t{row['n']}")
        return 0
    for row in conn.execute(
        "SELECT pass,"
        "  SUM(CASE WHEN verdict='pass' THEN 1 ELSE 0 END) AS n_pass,"
        "  SUM(CASE WHEN verdict='FAIL' THEN 1 ELSE 0 END) AS n_fail,"
        "  COUNT(*) AS n_total"
        "  FROM latest_results GROUP BY pass ORDER BY pass"
    ):
        print(
            f"{row['pass']:>8}: {row['n_pass'] or 0:5d} pass  "
            f"{row['n_fail'] or 0:4d} FAIL  ({row['n_total'] or 0} total)"
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
    _supervisor_state: dict = {"cargo_pgid": None, "harness_pid": None}

    def _signal_handler(signum, _frame):
        sig_name = signal.Signals(signum).name
        if not args.quiet:
            print(f"[auto] received {sig_name}; reaping in-flight cargo",
                  file=sys.stderr)
        _reap_pgid_and_containers(
            _supervisor_state.get("cargo_pgid"),
            _supervisor_state.get("harness_pid"),
            quiet=args.quiet,
        )
        try:
            pidfile.unlink()
        except FileNotFoundError:
            pass
        # Exit with 128+signum convention.
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    _write_pidfile(pidfile, supervisor_pid=os.getpid())

    try:
        while True:
            conn = open_db(state_dir)
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
                ref = r["ref"]
                wt = r["ci_worktree"]
                if not Path(wt).is_dir():
                    print(f"[auto] {ref}: worktree {wt} missing, skipping",
                          file=sys.stderr)
                    continue
                # Wrap each ref's drive in try/except so a single
                # ref's failure (or an unexpected exception in
                # _drive_ref's recovery paths) doesn't take down
                # the whole supervisor. The auto-loop's value is in
                # being long-running; one bad cycle shouldn't
                # require manual restart.
                try:
                    ok = _drive_ref(
                        ref, wt, args,
                        pidfile=pidfile,
                        supervisor_state=_supervisor_state,
                    )
                except Exception as e:
                    print(f"[auto] {ref}: _drive_ref crashed: "
                          f"{type(e).__name__}: {e}", file=sys.stderr)
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                    ok = False
                if not args.quiet:
                    print(f"[auto] {ref} @ {wt}: {'ok' if ok else 'failed'}")
            # Re-render after every full pass — and again every ~10s
            # during the sleep window so ad-hoc session runs from other
            # worktrees show up in summary.md within seconds of finishing,
            # not at the end of the next cycle.
            conn = open_db(state_dir)
            write_summary(conn, state_dir)
            conn.close()
            if args.once:
                return 0
            slept = 0
            render_every = 10
            while slept < args.interval:
                time.sleep(min(render_every, args.interval - slept))
                slept += render_every
                conn = open_db(state_dir)
                write_summary(conn, state_dir)
                conn.close()
    finally:
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
    if args.jobs:
        env["LITEBOX_TEST_JOBS"] = str(args.jobs)

    # Outer wall-time budget: cycle budget + generous grace for
    # cargo's own startup, drain, etc.
    deadline = time.monotonic() + (args.cycle_budget_secs * 2 + 600)
    proc = subprocess.Popen(
        cargo_args, cwd=ci_worktree, env=env,
        # New session + process group; PGID = cargo PID.
        start_new_session=True,
    )
    cargo_pgid = proc.pid  # equals PGID after start_new_session
    if supervisor_state is not None:
        supervisor_state["cargo_pgid"] = cargo_pgid
    if pidfile is not None:
        _write_pidfile(
            pidfile,
            supervisor_pid=os.getpid(),
            cargo_pid=proc.pid,
            cargo_pgid=cargo_pgid,
        )

    # Discover the harness (test binary) PID as it appears under
    # cargo. Best-effort; used as container-name salt for sweeps.
    harness_pid: Optional[int] = None
    poll_until = time.monotonic() + 30
    rc: Optional[int] = None
    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            if harness_pid is None and time.monotonic() < poll_until:
                harness_pid = _find_harness_pid(proc.pid)
                if harness_pid is not None and supervisor_state is not None:
                    supervisor_state["harness_pid"] = harness_pid
                    if pidfile is not None:
                        _write_pidfile(
                            pidfile,
                            supervisor_pid=os.getpid(),
                            cargo_pid=proc.pid,
                            cargo_pgid=cargo_pgid,
                            harness_pid=harness_pid,
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
        if supervisor_state is not None:
            supervisor_state["cargo_pgid"] = None
            supervisor_state["harness_pid"] = None
        if pidfile is not None:
            _write_pidfile(pidfile, supervisor_pid=os.getpid())

    return rc == 0


# ─── Process-group + pidfile helpers ─────────────────────────────────


def _write_pidfile(path: Path, **fields) -> None:
    """Atomically (best-effort) write pidfile JSON."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(fields))
    tmp.replace(path)


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

    Container names are `litebox-{pass}-{test_id}-{harness_pid}-{nanos}`
    (see tests/integration.rs build_docker_cmd), so we filter by the
    middle salt. We use `docker ps -aq --filter` rather than a glob
    because docker's name filter is a substring match.
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
    cargo_pgid = state.get("cargo_pgid")
    harness_pid = state.get("harness_pid")
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
    # the PGID and containers in case it missed anything (e.g. it was
    # SIGKILL'd above before completing).
    _reap_pgid_and_containers(cargo_pgid, harness_pid, quiet=args.quiet)
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
    p_auto.add_argument(
        "--jobs", type=int, default=None,
        help="set LITEBOX_TEST_JOBS for cargo (default: use whatever "
             "the harness derives from num_cpus).",
    )
    p_auto.add_argument("--once", action="store_true",
                        help="run one pass and exit")
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

    return p


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
