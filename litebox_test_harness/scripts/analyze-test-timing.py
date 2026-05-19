#!/usr/bin/env python3
"""
Analyze per-test timing JSONL produced by litebox_test_harness integration tests.

Usage:
  ./analyze-test-timing.py target/test-logs/per-test-timing.jsonl
  ./analyze-test-timing.py run-A.jsonl run-B.jsonl   # diff two runs

Each input line is one JSON object with the schema emitted by tests/integration.rs:
  {"test":..., "pass":..., "t_acquire_ms":..., "t_docker_start_ms":...,
   "t_docker_spawn_ms":..., "t_litebox_init_ms":..., "t_harness_load_ms":...,
   "t_useful_ms":..., "t_drain_ms":..., "verdict":..., "jobs":...}
"""
import json
import sys
from collections import defaultdict


def load(path):
    """Load a JSONL file, merging main + drain lines by (test, pass)."""
    rows = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"warn: bad line in {path}: {e}", file=sys.stderr)
                continue
            k = (obj.get("test"), obj.get("pass"))
            if k not in rows:
                rows[k] = {}
            rows[k].update(obj)
    return list(rows.values())


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
        by_pass[r["pass"]].append(r)
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
    a_by_test = {(r["test"], r["pass"]): r for r in a}
    b_by_test = {(r["test"], r["pass"]): r for r in b}
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
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    if len(sys.argv) == 2:
        summary(load(sys.argv[1]), sys.argv[1])
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
