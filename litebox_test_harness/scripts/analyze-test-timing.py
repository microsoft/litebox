#!/usr/bin/env python3
"""
Analyze per-test timing data from the central dashboard sqlite store
populated by litebox_test_harness's integration test binary
(``<main-worktree>/.dashboard/results.sqlite`` by default; override
with ``LITEBOX_DASHBOARD_DIR``).

Usage:
  ./analyze-test-timing.py                        # latest run in default store
  ./analyze-test-timing.py path/to/results.sqlite # latest run in that store
  ./analyze-test-timing.py path/to/results.sqlite RUN_ID   # specific run
  ./analyze-test-timing.py runA.sqlite runB.sqlite         # diff two runs

Rows are loaded by joining ``run_results`` to ``runs``; the rest of
the script doesn't care where the data came from.
"""
import os
import sqlite3
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


def _resolve_default_sqlite() -> Path:
    """Mirror dashboard.py's default state-dir resolution."""
    env = os.environ.get("LITEBOX_DASHBOARD_DIR")
    if env:
        return Path(env) / "results.sqlite"
    out = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        check=True, capture_output=True, text=True,
    )
    return Path(out.stdout.strip()).parent / ".dashboard" / "results.sqlite"


_TIMING_COLS = [
    "t_acquire_ms", "t_docker_start_ms", "t_docker_spawn_ms",
    "t_litebox_init_ms", "t_harness_load_ms", "t_harness_args_ms",
    "t_harness_dispatch_ms", "t_useful_ms", "t_drain_ms",
]


def _load_sqlite(path: Path, run_id: int | None = None) -> list[dict]:
    """Query ``run_results`` from sqlite, latest run if ``run_id`` is
    None. Returns row dicts keyed by ``test``, ``mode``, ``verdict``,
    each ``t_*_ms`` field, and ``jobs``.
    """
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    if run_id is None:
        row = conn.execute("SELECT MAX(run_id) FROM runs").fetchone()
        if row and row[0] is not None:
            run_id = int(row[0])
        else:
            return []
    cols = ", ".join(_TIMING_COLS)
    sql_rows = conn.execute(
        f"SELECT test_id AS test, mode, verdict, {cols},"
        f" (SELECT jobs FROM runs WHERE run_id = ?) AS jobs"
        f" FROM run_results WHERE run_id = ?",
        (run_id, run_id),
    ).fetchall()
    return [{k: r[k] for k in r.keys() if r[k] is not None} for r in sql_rows]


def load(path):
    """Compatibility shim — accepts either a Path or string."""
    return _load_sqlite(Path(path))


def fmt_ms(x):
    if x >= 1000:
        return f"{x / 1000:.1f}s"
    return f"{x}ms"


def percentile(xs, p):
    if not xs:
        return 0
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def summary(rows, label):
    print(f"\n=== {label} ({len(rows)} tests) ===")
    if not rows:
        return
    verdicts = defaultdict(int)
    for r in rows:
        verdicts[r["verdict"]] += 1
    print(f"verdicts: {dict(verdicts)}")
    jobs_cap = rows[0].get("jobs", "?")
    print(f"jobs cap: {jobs_cap}")

    phases = [
        "t_acquire_ms", "t_docker_start_ms", "t_docker_spawn_ms",
        "t_litebox_init_ms", "t_harness_load_ms", "t_useful_ms", "t_drain_ms",
        # Phase A sub-phases (t_litebox_init_ms breakdown). Some are
        # absent in native pass (no shim) or when a marker didn't fire.
        "t_tool_executor_args_ms", "t_tool_executor_audit_ms",
        "t_broker_spawn_ms", "t_broker_bind_ms",
        "t_runner_spawn_call_ms", "t_runner_fork_ms",
        "t_runner_broker_conn_ms", "t_runner_rootfs_ms",
        "t_runner_program_load_ms", "t_runner_shim_handoff_ms",
        # t_harness_load_ms breakdown.
        "t_guest_runtime_init_ms", "t_harness_args_ms", "t_harness_dispatch_ms",
    ]
    print(f"\n{'phase':<22} {'p50':>10} {'p90':>10} {'p99':>10} {'max':>10} {'sum':>10}")
    for ph in phases:
        xs = [r[ph] for r in rows if ph in r]
        if not xs:
            continue
        print(f"{ph:<22} {fmt_ms(percentile(xs, 50)):>10} "
              f"{fmt_ms(percentile(xs, 90)):>10} {fmt_ms(percentile(xs, 99)):>10} "
              f"{fmt_ms(max(xs)):>10} {fmt_ms(sum(xs)):>10}")

    def total(r):
        return r.get("t_acquire_ms", 0) + r.get("t_docker_start_ms", 0) \
            + r.get("t_useful_ms", 0) + r.get("t_drain_ms", 0)

    rows_by_total = sorted(rows, key=total, reverse=True)
    print("\nslowest 20 (total wall):")
    print(f"  {'test':<55} {'total':>8} {'acq':>6} {'start':>6} "
          f"{'spawn':>6} {'init':>6} {'load':>6} {'useful':>7} {'drain':>7} verdict")
    for r in rows_by_total[:20]:
        t = total(r)
        print(f"  {r['test'][:55]:<55} {fmt_ms(t):>8} "
              f"{fmt_ms(r.get('t_acquire_ms', 0)):>6} "
              f"{fmt_ms(r.get('t_docker_start_ms', 0)):>6} "
              f"{fmt_ms(r.get('t_docker_spawn_ms', 0)):>6} "
              f"{fmt_ms(r.get('t_litebox_init_ms', 0)):>6} "
              f"{fmt_ms(r.get('t_harness_load_ms', 0)):>6} "
              f"{fmt_ms(r.get('t_useful_ms', 0)):>7} "
              f"{fmt_ms(r.get('t_drain_ms', 0)):>7} "
              f"{r['verdict']}")

    by_pass = defaultdict(list)
    for r in rows:
        by_pass[r["mode"]].append(r)
    for p, pr in by_pass.items():
        useful_sum = sum(r.get("t_useful_ms", 0) for r in pr)
        wall_sum = sum(total(r) for r in pr)
        print(f"\npass {p}: {len(pr)} tests, sum useful={fmt_ms(useful_sum)}, "
              f"sum wall={fmt_ms(wall_sum)}")
        try:
            n_jobs = int(jobs_cap)
            print(f"  ideal floor (sum useful / jobs={n_jobs}): "
                  f"{fmt_ms(useful_sum / max(1, n_jobs))}")
        except (TypeError, ValueError):
            pass


def diff(a, b):
    a_by_test = {(r["test"], r["mode"]): r for r in a}
    b_by_test = {(r["test"], r["mode"]): r for r in b}
    print(f"\n=== diff: A({len(a)}) vs B({len(b)}) ===")
    print(f"only-in-A: {len(set(a_by_test) - set(b_by_test))}")
    print(f"only-in-B: {len(set(b_by_test) - set(a_by_test))}")
    common = set(a_by_test) & set(b_by_test)
    print(f"common: {len(common)}")
    if not common:
        return

    deltas = []
    for k in common:
        ra, rb = a_by_test[k], b_by_test[k]

        def total(r):
            return sum(r.get(p, 0) for p in ("t_acquire_ms", "t_docker_start_ms",
                                              "t_useful_ms", "t_drain_ms"))

        deltas.append((k, total(rb) - total(ra), total(ra), total(rb), ra["verdict"], rb["verdict"]))

    deltas.sort(key=lambda x: x[1])
    print("\nTop 20 improvements (B faster):")
    for (test, pass_), delta, ta, tb, va, vb in deltas[:20]:
        marker = "" if va == vb else f"  [{va}->{vb}]"
        print(f"  {pass_}::{test[:48]:<48} {fmt_ms(ta):>8} -> {fmt_ms(tb):>8} "
              f"({delta:+d} ms){marker}")
    print("\nTop 20 regressions (B slower):")
    for (test, pass_), delta, ta, tb, va, vb in deltas[-20:][::-1]:
        marker = "" if va == vb else f"  [{va}->{vb}]"
        print(f"  {pass_}::{test[:48]:<48} {fmt_ms(ta):>8} -> {fmt_ms(tb):>8} "
              f"({delta:+d} ms){marker}")
    total_a = sum(d[2] for d in deltas)
    total_b = sum(d[3] for d in deltas)
    print(f"\ncommon-tests total wall: A={fmt_ms(total_a)} B={fmt_ms(total_b)} "
          f"({(total_b - total_a) / max(1, total_a) * 100:+.1f}%)")


def main():
    if len(sys.argv) == 1:
        # No args: query the default sqlite store, latest run.
        default = _resolve_default_sqlite()
        if not default.exists():
            print(__doc__, file=sys.stderr)
            print(f"\nNo default sqlite store at {default}", file=sys.stderr)
            sys.exit(2)
        summary(load(default), str(default))
        return
    if len(sys.argv) == 2:
        summary(load(sys.argv[1]), sys.argv[1])
    elif len(sys.argv) == 3 and sys.argv[2].isdigit():
        # `analyze.py path/results.sqlite 42` — specific run_id.
        rows = _load_sqlite(Path(sys.argv[1]), run_id=int(sys.argv[2]))
        summary(rows, f"{sys.argv[1]}@run_id={sys.argv[2]}")
    elif len(sys.argv) == 3:
        a = load(sys.argv[1])
        b = load(sys.argv[2])
        summary(a, sys.argv[1])
        summary(b, sys.argv[2])
        diff(a, b)
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
