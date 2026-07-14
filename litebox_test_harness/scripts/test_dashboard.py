"""Unit tests for dashboard.py.

Run with:
  python3 litebox_test_harness/scripts/test_dashboard.py

Stdlib only — no third-party deps.
"""

from __future__ import annotations

import os
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
TEST_TMP_DIR = SCRIPTS_DIR.parents[1] / "target" / "dashboard-py-tests"
TEST_TMP_DIR.mkdir(parents=True, exist_ok=True)
tempfile.tempdir = str(TEST_TMP_DIR)
sys.path.insert(0, str(SCRIPTS_DIR))
import dashboard  # type: ignore


def _ddl_from_shared_module() -> str:
    """Extract the canonical DDL string from the shared producer
    module at `tests/common/dashboard_store.rs`. Same source the
    Rust producer + Rust test both use, so the Python test exercises
    identical schema.

    TODO: once both Rust and Python load the DDL from a single
    `dashboard_schema.sql`, drop this scrape.
    """
    rs = (
        SCRIPTS_DIR.parent / "tests" / "common" / "dashboard_store.rs"
    ).read_text()
    start = rs.index("CREATE TABLE runs")
    end = rs.index('"#;', start)
    return rs[start:end]


SCHEMA_DDL = _ddl_from_shared_module()


def _init_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_DDL)
    conn.execute("INSERT INTO meta(key, value) VALUES('schema_version','4')")
    return conn


def _add_run(conn, *, worktree="/wt", commit="sha1", dirty_hash=None,
             started_ts_ms=1000) -> int:
    conn.execute(
        "INSERT INTO runs(started_ts_ms, hostname, worktree_path, commit_sha,"
        " branch, dirty_hash) VALUES (?,?,?,?,?,?)",
        (started_ts_ms, "host", worktree, commit, "main", dirty_hash),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def _add_result(conn, *, run_id, test_id, pass_, verdict, ts_ms,
                suite="vscode", group="pidfd"):
    conn.execute(
        "INSERT INTO run_results(run_id, test_id, mode, verdict,"
        " finished_ts_ms, suite, \"group\","
        " t_acquire_ms, t_docker_start_ms, t_useful_ms)"
        " VALUES (?,?,?,?,?,?,?, 0, 0, 100)",
        (run_id, test_id, pass_, verdict, ts_ms, suite, group),
    )


class LatestResultsViewTests(unittest.TestCase):
    """The latest_results VIEW replaces the prior UPSERT-maintained
    table. Verify it returns the freshest row per (test_id, mode).
    """

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dash-lr-")
        self.db = Path(self.tmp) / "results.sqlite"
        self.conn = _init_db(self.db)

    def tearDown(self) -> None:
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_view_returns_newest_row(self):
        r1 = _add_run(self.conn, started_ts_ms=1000)
        r2 = _add_run(self.conn, started_ts_ms=2000)
        _add_result(self.conn, run_id=r1, test_id="A", pass_="native",
                    verdict="fail", ts_ms=1500)
        _add_result(self.conn, run_id=r2, test_id="A", pass_="native",
                    verdict="pass", ts_ms=2500)
        row = self.conn.execute(
            "SELECT verdict, finished_ts_ms FROM latest_results"
            " WHERE test_id='A' AND mode='native'"
        ).fetchone()
        self.assertEqual(row["verdict"], "pass")
        self.assertEqual(row["finished_ts_ms"], 2500)

    def test_view_one_row_per_pass(self):
        r = _add_run(self.conn)
        _add_result(self.conn, run_id=r, test_id="A", pass_="native",
                    verdict="pass", ts_ms=1000)
        _add_result(self.conn, run_id=r, test_id="A", pass_="litebox",
                    verdict="fail", ts_ms=1000)
        rows = self.conn.execute(
            "SELECT mode, verdict FROM latest_results WHERE test_id='A'"
            " ORDER BY mode"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["mode"], "litebox")
        self.assertEqual(rows[0]["verdict"], "fail")
        self.assertEqual(rows[1]["mode"], "native")
        self.assertEqual(rows[1]["verdict"], "pass")


class CoverageFiltersDirtyTests(unittest.TestCase):
    """A dirty run (dirty_hash IS NOT NULL) must not inflate the
    clean-commit coverage number.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dash-cov-")
        self.db = Path(self.tmp) / "results.sqlite"
        self.conn = _init_db(self.db)

    def tearDown(self) -> None:
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dirty_run_excluded_from_coverage(self):
        # Clean run records A.
        clean = _add_run(self.conn, commit="abc", dirty_hash=None,
                         started_ts_ms=1000)
        _add_result(self.conn, run_id=clean, test_id="A", pass_="native",
                    verdict="pass", ts_ms=1500)
        # Dirty run records B (against the same commit).
        dirty = _add_run(self.conn, commit="abc",
                         dirty_hash="deadbeef", started_ts_ms=2000)
        _add_result(self.conn, run_id=dirty, test_id="B", pass_="native",
                    verdict="pass", ts_ms=2500)
        # Materialize the per-connection state views (open_db does this
        # in production) so state_test_pass reflects the rows above.
        dashboard._ensure_views(self.conn)
        # _coverage_pass_fail filters dirty; only A counts.
        covered, n_pass, n_fail = dashboard._coverage_pass_fail(
            self.conn, "abc", "native"
        )
        self.assertEqual(covered, 1)
        self.assertEqual(n_pass, 1)
        self.assertEqual(n_fail, 0)


class ValidateCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dash-val-")
        self.state_dir = Path(self.tmp)
        self.db = self.state_dir / "results.sqlite"
        self.conn = _init_db(self.db)

    def tearDown(self) -> None:
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_validate(self, *argv):
        import contextlib
        import io
        args = dashboard.build_parser().parse_args(
            ["validate", "RL.case", "--sha", "fixsha", "--mode", "litebox",
             "--state-dir", str(self.state_dir), *argv]
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = dashboard.cmd_validate(args)
        return status, out.getvalue()

    def _add_trials(self, *, commit, n_pass=0, n_fail=0, n_no_result=0,
                    test_id="RL.case"):
        ts = 1000
        for verdict, count in (("pass", n_pass), ("fail", n_fail),
                               ("no_result", n_no_result)):
            for _ in range(count):
                run = _add_run(self.conn, commit=commit, started_ts_ms=ts)
                _add_result(self.conn, run_id=run, test_id=test_id,
                            pass_="litebox", verdict=verdict, ts_ms=ts + 1)
                ts += 10

    def test_runs_needed(self):
        self.assertEqual(dashboard._runs_needed(0.05, 0.95), 59)
        self.assertEqual(dashboard._runs_needed(0.01, 0.95), 299)
        self.assertEqual(dashboard._runs_needed(0.5, 0.95), 5)

    def test_not_run_is_loud_and_nonzero(self):
        self._add_trials(commit="othersha", n_pass=1)
        status, out = self._run_validate()
        self.assertNotEqual(status, 0)
        self.assertIn("NOT VALIDATED", out)
        self.assertIn("NOT_RUN", out)
        self.assertNotIn("VALIDATED (", out)
        self.assertNotIn("passing", out.lower())

    def test_still_failing_if_any_fail(self):
        self._add_trials(commit="fixsha", n_pass=2, n_fail=1)
        status, out = self._run_validate()
        self.assertNotEqual(status, 0)
        self.assertIn("STILL FAILING", out)
        self.assertIn("1 fails / 3 clean runs", out)

    def test_insufficient_clean_passes(self):
        self._add_trials(commit="fixsha", n_pass=10)
        status, out = self._run_validate("--assume-flake-rate", "0.05")
        self.assertNotEqual(status, 0)
        self.assertIn("INSUFFICIENT", out)
        self.assertIn("10 clean of 59 needed", out)
        self.assertIn("need 49 more", out)

    def test_validated_with_enough_clean_passes(self):
        self._add_trials(commit="fixsha", n_pass=60)
        status, out = self._run_validate("--assume-flake-rate", "0.05")
        self.assertEqual(status, 0)
        self.assertIn("VALIDATED", out)
        self.assertIn("60 clean, 0 fail", out)

    def test_vs_baseline_prints_contrast(self):
        self._add_trials(commit="basesha", n_pass=3, n_fail=1)
        self._add_trials(commit="fixsha", n_pass=12)
        status, out = self._run_validate("--vs-baseline", "basesha")
        self.assertEqual(status, 0)
        self.assertIn("baseline was 25.0% (1/4)", out)
        self.assertIn("VALIDATED", out)


class TrackedRefsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dash-tr-")
        self.db = Path(self.tmp) / "results.sqlite"
        self.conn = _init_db(self.db)

    def tearDown(self) -> None:
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_tracked_refs_round_trip(self):
        self.conn.execute(
            "INSERT INTO tracked_refs(ref, ci_worktree) VALUES (?, ?)",
            ("origin/main", "/tmp/ci-main"),
        )
        rows = self.conn.execute(
            "SELECT ref, ci_worktree FROM tracked_refs"
        ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ref"], "origin/main")
        self.assertEqual(rows[0]["ci_worktree"], "/tmp/ci-main")


class TipSetTests(unittest.TestCase):
    """Tip-set rule: drop any worktree whose HEAD is an ancestor of
    another worktree's HEAD. Uses a fake ancestor predicate over a
    small DAG so the test is hermetic (no git)."""

    @staticmethod
    def _ancestor_pred(graph):
        """graph: {child_sha: {ancestor_shas...}} (reflexive ancestor
        relationship is implied by tip-set's `head == other_head`
        short-circuit). Returns a predicate is_ancestor(a, b) = True
        iff `a` is in `b`'s ancestor set."""
        def pred(a: str, b: str) -> bool:
            return a in graph.get(b, set())
        return pred

    @staticmethod
    def _wts(*shas):
        return [{"path": f"/wt/{s}", "head": s, "branch": s} for s in shas]

    def test_solo_worktree_is_tip(self):
        wts = self._wts("A")
        out = dashboard._compute_tip_set(
            wts, self._ancestor_pred({}))
        self.assertEqual([w["head"] for w in out], ["A"])

    def test_all_independent_all_tips(self):
        wts = self._wts("A", "B", "C")
        out = dashboard._compute_tip_set(
            wts, self._ancestor_pred({}))
        self.assertEqual([w["head"] for w in out], ["A", "B", "C"])

    def test_fanout_from_session_subagents_are_tips(self):
        # SESSION is ancestor of S1, S2 (subagents branched off and
        # added commits): drop SESSION, keep S1 + S2.
        graph = {"S1": {"SESSION"}, "S2": {"SESSION"}}
        wts = self._wts("SESSION", "S1", "S2")
        out = dashboard._compute_tip_set(
            wts, self._ancestor_pred(graph))
        self.assertEqual([w["head"] for w in out], ["S1", "S2"])

    def test_mergeback_into_session_session_is_tip(self):
        # SESSION's HEAD is a merge containing S1 + S2 as ancestors:
        # drop S1 + S2, keep SESSION.
        graph = {"SESSION": {"S1", "S2"}}
        wts = self._wts("SESSION", "S1", "S2")
        out = dashboard._compute_tip_set(
            wts, self._ancestor_pred(graph))
        self.assertEqual([w["head"] for w in out], ["SESSION"])

    def test_disjoint_clusters_one_tip_per_cluster(self):
        # Cluster 1: SESSION-A is mergeback parent of A1.
        # Cluster 2: SESSION-B and B1 unrelated to cluster 1.
        graph = {"SESSION-A": {"A1"}}
        wts = self._wts("SESSION-A", "A1", "SESSION-B", "B1")
        out = dashboard._compute_tip_set(
            wts, self._ancestor_pred(graph))
        self.assertEqual(
            sorted(w["head"] for w in out),
            ["B1", "SESSION-A", "SESSION-B"],
        )

    def test_worktree_missing_head_skipped(self):
        wts = self._wts("A", "B")
        wts.insert(1, {"path": "/wt/no-head", "branch": "weird"})
        out = dashboard._compute_tip_set(
            wts, self._ancestor_pred({}))
        self.assertEqual([w["head"] for w in out], ["A", "B"])

    def test_chain_only_youngest_is_tip(self):
        # A <- B <- C linear: only C survives.
        graph = {"B": {"A"}, "C": {"A", "B"}}
        wts = self._wts("A", "B", "C")
        out = dashboard._compute_tip_set(
            wts, self._ancestor_pred(graph))
        self.assertEqual([w["head"] for w in out], ["C"])

    def test_preserves_input_order(self):
        # Two unrelated tips presented out of alphabetical order.
        wts = self._wts("Z", "A")
        out = dashboard._compute_tip_set(
            wts, self._ancestor_pred({}))
        self.assertEqual([w["head"] for w in out], ["Z", "A"])


class CoveredByTrackedTests(unittest.TestCase):
    """`_drop_covered_by_tracked`: drop agent worktrees whose HEAD is
    an ancestor of a tracked ref's HEAD (no divergent commits → it's
    the merge-base, already covered by the tracked-ref drive). Uses a
    fake reflexive ancestor predicate so the test is hermetic."""

    @staticmethod
    def _ancestor_pred(graph):
        """graph: {descendant_sha: {ancestor_shas...}}. Reflexive, like
        the real `_is_ancestor`."""
        def pred(a: str, b: str) -> bool:
            return a == b or a in graph.get(b, set())
        return pred

    @staticmethod
    def _wts(*shas):
        return [{"path": f"/wt/{s}", "head": s, "branch": s} for s in shas]

    def test_drops_worktree_at_merge_base(self):
        # Agent worktree HEAD MB is an ancestor of tracked tip TIP
        # (the mt-fork-repro pre-commit case): drop it.
        graph = {"TIP": {"MB"}}
        out = dashboard._drop_covered_by_tracked(
            self._wts("MB"), ["TIP"], self._ancestor_pred(graph))
        self.assertEqual(out, [])

    def test_keeps_divergent_worktree(self):
        # Agent HEAD has its own commit (not an ancestor of the tracked
        # tip): keep it.
        out = dashboard._drop_covered_by_tracked(
            self._wts("AGENT_TIP"), ["BASE"], self._ancestor_pred({}))
        self.assertEqual([w["head"] for w in out], ["AGENT_TIP"])

    def test_drops_reflexive_equal_to_tracked_head(self):
        # Fresh worktree sitting exactly at the tracked tip.
        out = dashboard._drop_covered_by_tracked(
            self._wts("TIP"), ["TIP"], self._ancestor_pred({}))
        self.assertEqual(out, [])

    def test_empty_tracked_heads_is_fail_open(self):
        wts = self._wts("A", "B")
        out = dashboard._drop_covered_by_tracked(
            wts, [], self._ancestor_pred({"X": {"A"}}))
        self.assertEqual([w["head"] for w in out], ["A", "B"])

    def test_drops_if_ancestor_of_any_tracked_ref(self):
        graph = {"TIP2": {"MB"}}
        out = dashboard._drop_covered_by_tracked(
            self._wts("MB"), ["TIP1", "TIP2"], self._ancestor_pred(graph))
        self.assertEqual(out, [])

    def test_mixed_keeps_divergent_drops_mergebase(self):
        # MB at merge-base (dropped), DIV with own commit (kept).
        graph = {"TIP": {"MB"}}
        wts = self._wts("MB", "DIV")
        out = dashboard._drop_covered_by_tracked(
            wts, ["TIP"], self._ancestor_pred(graph))
        self.assertEqual([w["head"] for w in out], ["DIV"])

    def test_missing_head_kept(self):
        wts = [{"path": "/wt/x", "branch": "weird"}]
        out = dashboard._drop_covered_by_tracked(
            wts, ["TIP"], self._ancestor_pred({}))
        self.assertEqual(out, wts)

    def test_preserves_input_order(self):
        graph = {"TIP": {"MB"}}
        wts = self._wts("Z", "MB", "A")
        out = dashboard._drop_covered_by_tracked(
            wts, ["TIP"], self._ancestor_pred(graph))
        self.assertEqual([w["head"] for w in out], ["Z", "A"])


class ShadowPathTests(unittest.TestCase):
    """Per-branch shadow path encoding + GC selection rules.
    Hermetic: only exercises pure-functional path helpers and the
    branch-decoding step of GC (the actual git invocations are
    integration-tested by the live supervisor)."""

    def test_per_branch_path_simple_branch(self):
        sd = Path("/tmp/sd-test")
        p = dashboard._per_branch_shadow_path(sd, "main")
        self.assertEqual(p, dashboard._shadows_root(sd) / "main")

    def test_per_branch_path_nested_for_slash(self):
        # Branches with `/` MUST become nested directories — NOT
        # URL-encoded as `%2f`. rust-lld URL-decodes `%XX`
        # sequences in its `-o` output path and fails ENOENT
        # against the decoded (nonexistent) path.
        sd = Path("/tmp/sd-test")
        p = dashboard._per_branch_shadow_path(sd, "wportnoy/foo-bar")
        self.assertEqual(p, dashboard._shadows_root(sd) / "wportnoy" / "foo-bar")
        # No `%` escaping anywhere in the resulting path.
        self.assertNotIn("%", str(p))

    def test_branch_from_shadow_path_roundtrip(self):
        sd = Path("/tmp/sd-test")
        for branch in ("main", "wportnoy/foo", "a/b/c"):
            p = dashboard._per_branch_shadow_path(sd, branch)
            self.assertEqual(
                dashboard._branch_from_shadow_path(sd, p), branch,
            )

    def test_branch_from_shadow_path_outside_shadows_returns_none(self):
        sd = Path("/tmp/sd-test")
        self.assertIsNone(
            dashboard._branch_from_shadow_path(sd, Path("/elsewhere/foo")),
        )

    def test_legacy_path_distinct_from_per_branch_root(self):
        sd = Path("/tmp/sd-test")
        legacy = dashboard._shadow_worktree_path(sd)
        root = dashboard._shadows_root(sd)
        # Singular vs plural — they must not collide on the
        # filesystem (so the legacy-shadow GC path can't clobber
        # the per-branch tree).
        self.assertNotEqual(legacy, root)
        self.assertEqual(legacy.name, "shadow")
        self.assertEqual(root.name, "shadows")


class ChildrenRegistryTests(unittest.TestCase):
    """Round-trip tests for the supervisor children registry that
    backs parallel agent-coverage driving. The registry is the source
    of truth for which cargo PGIDs are in flight; the pidfile mirrors
    it and the signal handler reaps over it."""

    def test_register_update_snapshot_unregister(self):
        s = dashboard._new_supervisor_state()
        self.assertEqual(dashboard._snapshot_children(s), [])
        c1 = dashboard._register_child(s, kind="agent-coverage",
                                       worktree_path="/x")
        c2 = dashboard._register_child(s, kind="tracked-ref",
                                       worktree_path="/y")
        self.assertNotEqual(c1, c2)
        dashboard._update_child(s, c1, cargo_pgid=100, harness_pid=200)
        dashboard._update_child(s, c2, cargo_pgid=300)
        snap = sorted(dashboard._snapshot_children(s),
                      key=lambda d: d["cargo_pgid"])
        self.assertEqual(snap[0]["cargo_pgid"], 100)
        self.assertEqual(snap[0]["harness_pid"], 200)
        self.assertEqual(snap[1]["cargo_pgid"], 300)
        self.assertIsNone(snap[1]["harness_pid"])
        dashboard._unregister_child(s, c1)
        snap = dashboard._snapshot_children(s)
        self.assertEqual(len(snap), 1)
        self.assertEqual(snap[0]["cargo_pgid"], 300)
        # Unknown child id is a no-op.
        dashboard._update_child(s, 9999, cargo_pgid=42)
        dashboard._unregister_child(s, 9999)

    def test_pidfile_round_trip_from_state(self):
        import tempfile
        s = dashboard._new_supervisor_state()
        c = dashboard._register_child(s, kind="agent-coverage",
                                      worktree_path="/x")
        dashboard._update_child(s, c, cargo_pgid=111, harness_pid=222)
        with tempfile.TemporaryDirectory() as td:
            pf = Path(td) / "auto.pidfile"
            dashboard._write_pidfile_from_state(pf, 9001, s)
            data = json.loads(pf.read_text())
        self.assertEqual(data["supervisor_pid"], 9001)
        self.assertEqual(len(data["children"]), 1)
        self.assertEqual(data["children"][0]["cargo_pgid"], 111)
        self.assertEqual(data["children"][0]["harness_pid"], 222)
        self.assertEqual(data["children"][0]["kind"], "agent-coverage")
        self.assertEqual(data["children"][0]["worktree_path"], "/x")


class PidfileConcurrentWriteTests(unittest.TestCase):
    """Regression: concurrent `_write_pidfile_from_state` calls used
    to share a single `auto.pidfile.tmp` path and race on `replace()`,
    raising `FileNotFoundError` (one thread renamed the tmp while
    another was about to). The exception then bubbled up between
    `_register_child` and the `try`/`finally` in `_drive_*`, leaking
    the just-registered child slot — observed as 1207 stale entries
    in a long-running supervisor's pidfile."""

    def test_concurrent_writers_do_not_raise(self):
        import tempfile
        import threading
        s = dashboard._new_supervisor_state()
        # Pre-populate the registry so each write has content.
        for i in range(8):
            cid = dashboard._register_child(
                s, kind="agent-coverage", worktree_path=f"/w{i}",
            )
            dashboard._update_child(s, cid, cargo_pgid=1000 + i)
        with tempfile.TemporaryDirectory() as td:
            pf = Path(td) / "auto.pidfile"
            errors: list[BaseException] = []

            def writer():
                try:
                    for _ in range(50):
                        dashboard._write_pidfile_from_state(pf, 1, s)
                except BaseException as e:
                    errors.append(e)

            threads = [threading.Thread(target=writer) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(errors, [],
                             f"concurrent writers raised: {errors[:3]}")
            # Final file must be valid JSON with the expected shape.
            data = json.loads(pf.read_text())
            self.assertEqual(len(data["children"]), 8)
            # No leftover .tmp files in the directory (per-thread tmp
            # suffixes get renamed away cleanly).
            leftovers = [p for p in Path(td).iterdir() if ".tmp" in p.name]
            self.assertEqual(leftovers, [],
                             f"leftover tmp files: {leftovers}")


class WatchdogTests(unittest.TestCase):
    """Supervisor liveness classification + watchdog relaunch gating.

    The pure helpers (`_cmdline_is_supervisor`, `_supervisor_health`)
    are tested with an injected process predicate / synthetic cmdlines
    so they're hermetic. The `cmd_watchdog` gating + relaunch wiring
    use a temp state dir with `subprocess.Popen` stubbed — no real
    process is ever spawned."""

    # ---- _cmdline_is_supervisor (NUL-separated /proc/<pid>/cmdline) ----
    def test_cmdline_auto_supervisor_is_recognised(self):
        cl = "python3\x00/x/dashboard.py\x00auto\x00--interval\x0060\x00"
        self.assertTrue(dashboard._cmdline_is_supervisor(cl))

    def test_cmdline_stop_is_not_supervisor(self):
        cl = "python3\x00/x/dashboard.py\x00stop\x00"
        self.assertFalse(dashboard._cmdline_is_supervisor(cl))

    def test_cmdline_unrelated_process_is_not_supervisor(self):
        cl = "python3\x00-m\x00unittest\x00"
        self.assertFalse(dashboard._cmdline_is_supervisor(cl))

    def test_cmdline_dashboard_without_auto_token_is_not_supervisor(self):
        # dashboard.py present but the subcommand is 'status', not 'auto'
        # — must not be mistaken for the supervisor after PID reuse.
        cl = "python3\x00/x/dashboard.py\x00status\x00"
        self.assertFalse(dashboard._cmdline_is_supervisor(cl))

    # ---- _supervisor_health (pure; injected pid→process predicate) ----
    @staticmethod
    def _pf(pid, heartbeat_ms):
        return {"supervisor_pid": pid, "heartbeat_ms": heartbeat_ms}

    def test_health_no_pidfile_is_down(self):
        status, age = dashboard._supervisor_health(None, 1_000_000)
        self.assertEqual(status, "down")
        self.assertEqual(age, -1)

    def test_health_live_fresh_is_up(self):
        now = 10_000_000
        status, age = dashboard._supervisor_health(
            self._pf(123, now - 5_000), now, is_supervisor=lambda p: True)
        self.assertEqual(status, "up")
        self.assertEqual(age, 5_000)

    def test_health_live_stale_is_hung(self):
        now = 10_000_000
        pf = self._pf(123, now - (dashboard._HEARTBEAT_STALE_MS + 1))
        status, _ = dashboard._supervisor_health(
            pf, now, is_supervisor=lambda p: True)
        self.assertEqual(status, "hung")

    def test_health_dead_pid_is_down_even_with_fresh_heartbeat(self):
        # Fresh heartbeat but the pid is gone / reused → down (guards
        # against reading a stale pidfile of a since-dead supervisor).
        now = 10_000_000
        status, _ = dashboard._supervisor_health(
            self._pf(123, now - 5_000), now, is_supervisor=lambda p: False)
        self.assertEqual(status, "down")

    def test_health_live_without_heartbeat_field_is_up(self):
        # Pre-watchdog pidfile (no heartbeat_ms) but a live supervisor
        # pid → 'up', not 'hung'. Must not cry wolf during a version
        # transition; age is -1 (unknown).
        now = 10_000_000
        status, age = dashboard._supervisor_health(
            {"supervisor_pid": 123}, now, is_supervisor=lambda p: True)
        self.assertEqual(status, "up")
        self.assertEqual(age, -1)

    def test_fmt_hb_age(self):
        self.assertEqual(dashboard._fmt_hb_age(5_000), "heartbeat 5s ago")
        self.assertEqual(dashboard._fmt_hb_age(0), "heartbeat 0s ago")
        self.assertEqual(dashboard._fmt_hb_age(-1),
                         "no heartbeat (pre-watchdog supervisor)")

    def test_health_stale_boundary(self):
        now = 10_000_000
        thr = dashboard._HEARTBEAT_STALE_MS
        alive = lambda p: True  # noqa: E731
        self.assertEqual(dashboard._supervisor_health(
            self._pf(1, now - (thr - 1)), now, is_supervisor=alive)[0], "up")
        self.assertEqual(dashboard._supervisor_health(
            self._pf(1, now - thr), now, is_supervisor=alive)[0], "hung")

    # ---- cmd_watchdog gating + relaunch (Popen stubbed) ----
    def test_watchdog_noop_when_not_enabled(self):
        import argparse
        with tempfile.TemporaryDirectory() as td:
            # No auto.enabled sentinel → supervisor was intentionally
            # `stop`ped → watchdog must NOT relaunch it.
            args = argparse.Namespace(state_dir=td, quiet=True)
            calls: list = []
            orig = dashboard.subprocess.Popen
            dashboard.subprocess.Popen = lambda *a, **k: calls.append((a, k))
            try:
                rc = dashboard.cmd_watchdog(args)
            finally:
                dashboard.subprocess.Popen = orig
            self.assertEqual(rc, 0)
            self.assertEqual(calls, [], "must not relaunch when stopped")

    def test_watchdog_relaunches_when_enabled_and_down(self):
        import argparse
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)
            # Enabled (supposed to be running) + no pidfile → 'down' →
            # relaunch using the recorded argv/cwd.
            (state / "auto.enabled").write_text(json.dumps({
                "argv": ["/x/dashboard.py", "auto", "--interval", "60"],
                "cwd": "/some/cwd",
            }))
            args = argparse.Namespace(state_dir=str(state), quiet=True)
            calls: list = []

            class FakePopen:
                def __init__(self, cmd, **kw):
                    calls.append((cmd, kw))

            orig = dashboard.subprocess.Popen
            dashboard.subprocess.Popen = FakePopen
            try:
                rc = dashboard.cmd_watchdog(args)
            finally:
                dashboard.subprocess.Popen = orig
            self.assertEqual(rc, 0)
            self.assertEqual(len(calls), 1)
            cmd, kw = calls[0]
            # [python, <this dashboard.py>, "auto", "--interval", "60"]
            self.assertEqual(cmd[0], sys.executable)
            self.assertTrue(cmd[1].endswith("dashboard.py"))
            self.assertEqual(cmd[2:], ["auto", "--interval", "60"])
            self.assertEqual(kw.get("cwd"), "/some/cwd")
            self.assertTrue(kw.get("start_new_session"))


class PickTopNTests(unittest.TestCase):
    """The parallel orchestrator picks the top-N worktrees by the
    same scoring tuple the single-pick selector uses. These tests
    don't try to recompute scoring (covered elsewhere) — they just
    confirm the top-N variant respects N and is consistent with the
    single-pick variant when N==1."""

    def _conn(self):
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)"
        )
        # The picker reads run_results joined with runs to age coverage;
        # with no rows everything is "never tested" and order falls back
        # to round-robin / input order.
        conn.execute(
            "CREATE TABLE runs (run_id INT, commit_sha TEXT, "
            "dirty_hash TEXT, worktree_path TEXT)"
        )
        conn.execute(
            "CREATE TABLE run_results (run_id INT, finished_ts_ms INT)"
        )
        return conn

    def test_topn_returns_at_most_n(self):
        conn = self._conn()
        cands = [{"path": f"/w{i}", "head": f"{i:040x}", "branch": "b"}
                 for i in range(5)]
        picks = dashboard._pick_opportunistic_worktrees_topn(conn, cands, 3)
        self.assertEqual(len(picks), 3)

    def test_topn_handles_n_larger_than_candidates(self):
        conn = self._conn()
        cands = [{"path": "/w0", "head": "a" * 40, "branch": "b"}]
        picks = dashboard._pick_opportunistic_worktrees_topn(conn, cands, 5)
        self.assertEqual(len(picks), 1)

    def test_topn_zero_returns_empty(self):
        conn = self._conn()
        cands = [{"path": "/w0", "head": "a" * 40, "branch": "b"}]
        self.assertEqual(
            dashboard._pick_opportunistic_worktrees_topn(conn, cands, 0), [],
        )

    def test_topn_with_n1_agrees_with_single_pick(self):
        conn = self._conn()
        cands = [{"path": f"/w{i}", "head": f"{i:040x}", "branch": "b"}
                 for i in range(3)]
        single = dashboard._pick_opportunistic_worktree(conn, cands)
        topn = dashboard._pick_opportunistic_worktrees_topn(conn, cands, 1)
        self.assertEqual(len(topn), 1)
        self.assertEqual(topn[0]["path"], single["path"])


_V3_DDL = """
CREATE TABLE runs (
    run_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    started_ts_ms  INTEGER NOT NULL,
    hostname       TEXT    NOT NULL,
    worktree_path  TEXT    NOT NULL,
    commit_sha     TEXT    NOT NULL,
    branch         TEXT,
    dirty_hash     TEXT
);
CREATE TABLE run_results (
    run_id            INTEGER NOT NULL REFERENCES runs(run_id),
    test_id           TEXT    NOT NULL,
    pass              TEXT    NOT NULL,
    verdict           TEXT    NOT NULL,
    finished_ts_ms    INTEGER NOT NULL,
    suite             TEXT    NOT NULL,
    "group"           TEXT    NOT NULL,
    t_acquire_ms      INTEGER NOT NULL,
    t_docker_start_ms INTEGER NOT NULL,
    t_useful_ms       INTEGER NOT NULL,
    PRIMARY KEY (run_id, test_id, pass)
);
CREATE INDEX run_results_test_pass_ts
    ON run_results(test_id, pass, finished_ts_ms DESC);
CREATE INDEX run_results_pass_verdict_ts
    ON run_results(pass, verdict, finished_ts_ms DESC);
CREATE VIEW latest_results AS
SELECT rr.test_id, rr.pass, rr.verdict, rr.finished_ts_ms,
       rr.suite, rr."group", rr.run_id
  FROM run_results rr
  JOIN (SELECT test_id, pass, MAX(finished_ts_ms) AS max_ts
          FROM run_results GROUP BY test_id, pass) latest
    ON latest.test_id = rr.test_id AND latest.pass = rr.pass
   AND latest.max_ts = rr.finished_ts_ms;
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO meta(key, value) VALUES('schema_version','3');
"""


class MigrationV3ToV4Tests(unittest.TestCase):
    """The lossless in-place v3 → v4 migration: rename
    `run_results.pass` → `mode`, lower-case `FAIL` → `fail`, bump the
    schema version. Every row must survive."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dash-mig-")
        self.db = Path(self.tmp) / "results.sqlite"
        self.conn = sqlite3.connect(str(self.db), isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_V3_DDL)
        self.conn.execute(
            "INSERT INTO runs(started_ts_ms, hostname, worktree_path,"
            " commit_sha, branch, dirty_hash)"
            " VALUES (1000,'h','/wt','sha1','main',NULL)"
        )
        rid = self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        for tid, p, v in [("A", "native", "FAIL"),
                          ("A", "litebox", "pass"),
                          ("B", "native", "pass")]:
            self.conn.execute(
                "INSERT INTO run_results(run_id, test_id, pass, verdict,"
                " finished_ts_ms, suite, \"group\","
                " t_acquire_ms, t_docker_start_ms, t_useful_ms)"
                " VALUES (?,?,?,?,1500,'s','g',0,0,100)",
                (rid, tid, p, v),
            )

    def tearDown(self) -> None:
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_migrate_renames_column_and_normalizes_verdict(self):
        before = self.conn.execute(
            "SELECT COUNT(*) FROM run_results"
        ).fetchone()[0]
        self.assertTrue(dashboard.migrate_v3_to_v4(self.conn))
        self.assertEqual(
            dashboard._schema_version(self.conn),
            dashboard.SCHEMA_VERSION_EXPECTED,
        )
        cols = {r[1] for r in self.conn.execute(
            "PRAGMA table_info(run_results)")}
        self.assertIn("mode", cols)
        self.assertNotIn("pass", cols)
        # No row lost.
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM run_results").fetchone()[0],
            before,
        )
        # Verdict normalized in place.
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM run_results WHERE verdict='FAIL'"
        ).fetchone()[0], 0)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM run_results WHERE verdict='fail'"
        ).fetchone()[0], 1)
        # Mode values intact.
        self.assertEqual(
            {r["mode"] for r in self.conn.execute(
                "SELECT DISTINCT mode FROM run_results")},
            {"native", "litebox"},
        )
        # latest_results view now exposes `mode`.
        row = self.conn.execute(
            "SELECT mode, verdict FROM latest_results"
            " WHERE test_id='A' AND mode='native'"
        ).fetchone()
        self.assertEqual(row["verdict"], "fail")
        # Indexes kept their names (so migrated == fresh schema).
        idx = {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master"
            " WHERE type='index' AND tbl_name='run_results'")}
        self.assertIn("run_results_test_pass_ts", idx)
        self.assertIn("run_results_pass_verdict_ts", idx)

    def test_migrate_is_idempotent(self):
        self.assertTrue(dashboard.migrate_v3_to_v4(self.conn))
        self.assertFalse(dashboard.migrate_v3_to_v4(self.conn))
        self.assertEqual(
            dashboard._schema_version(self.conn),
            dashboard.SCHEMA_VERSION_EXPECTED,
        )


class ClassificationSchemaUpgradeTests(unittest.TestCase):
    """Data-safety of the classification-schema version bump: upgrading
    an older DB must be additive (add `branch_baseline.tip_sha`, recreate
    the views) and must NEVER touch the producer `schema_version` or drop
    any `run_results` / `branch_baseline` data."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dash-clsup-")
        self.conn = _init_db(Path(self.tmp) / "results.sqlite")

    def tearDown(self) -> None:
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_tip_sha_added_without_losing_rows(self):
        # Simulate an older classification schema: branch_baseline WITHOUT
        # tip_sha, an old version meta, and a pre-existing cache row.
        self.conn.executescript(
            """
            CREATE TABLE branch_baseline (
                branch_sha     TEXT NOT NULL PRIMARY KEY,
                baseline_sha   TEXT NOT NULL,
                ref            TEXT,
                branch         TEXT,
                computed_at_ms INTEGER NOT NULL
            );
            """
        )
        self.conn.execute(
            "INSERT INTO branch_baseline"
            "(branch_sha, baseline_sha, ref, branch, computed_at_ms)"
            " VALUES('B','BASE','up','wt/x',123)"
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value)"
            " VALUES('classification_schema_version','5')"
        )
        # A producer row that must be untouched by a classifier upgrade.
        rid = _add_run(self.conn, commit="B")
        _add_result(self.conn, run_id=rid, test_id="T", pass_="litebox",
                    verdict="pass", ts_ms=1000)

        dashboard._ensure_classification_schema(self.conn)

        cols = {r[1] for r in self.conn.execute(
            "PRAGMA table_info(branch_baseline)")}
        self.assertIn("tip_sha", cols)  # additive column present
        # Pre-existing cache row preserved (tip_sha defaults NULL).
        row = self.conn.execute(
            "SELECT baseline_sha, tip_sha FROM branch_baseline"
            " WHERE branch_sha='B'").fetchone()
        self.assertEqual(row["baseline_sha"], "BASE")
        self.assertIsNone(row["tip_sha"])
        # Version bumped; producer schema_version untouched.
        self.assertEqual(
            self.conn.execute(
                "SELECT value FROM meta WHERE key='classification_schema_version'"
            ).fetchone()[0],
            str(dashboard._CLASSIFICATION_SCHEMA_VERSION),
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()[0],
            "4",
        )
        # Producer data intact; the view is live.
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM run_results").fetchone()[0],
            1,
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT type FROM sqlite_master WHERE name='regression_class'"
            ).fetchone()[0],
            "view",
        )

    def test_idempotent_when_already_current(self):
        dashboard._ensure_classification_schema(self.conn)
        # Second call is a no-op (no raise, version stable).
        dashboard._ensure_classification_schema(self.conn)
        self.assertEqual(
            self.conn.execute(
                "SELECT value FROM meta WHERE key='classification_schema_version'"
            ).fetchone()[0],
            str(dashboard._CLASSIFICATION_SCHEMA_VERSION),
        )


class RegressionClassTests(unittest.TestCase):
    """The `regression_class` view: flaky-aware, confidence-tiered
    classification, computed purely in SQL over run_results + the
    supervisor-refreshed branch_baseline + the test_flake_stats view.
    Hermetic — branch_baseline is inserted directly (no git)."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dash-regr-")
        self.db = Path(self.tmp) / "results.sqlite"
        self.conn = _init_db(self.db)
        dashboard._ensure_classification_schema(self.conn)
        # Upstream lineage lives in the tracked-ref CI worktree.
        self.conn.execute(
            "INSERT INTO tracked_refs(ref, ci_worktree) VALUES('up','/ci')"
        )
        self.now = dashboard.now_ms()

    def tearDown(self) -> None:
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _upstream(self, commit, test_id, verdict, *, dt=0):
        # A clean run on the tracked-ref CI worktree (/ci).
        rid = _add_run(self.conn, worktree="/ci", commit=commit,
                       dirty_hash=None, started_ts_ms=self.now - dt)
        _add_result(self.conn, run_id=rid, test_id=test_id, pass_="litebox",
                    verdict=verdict, ts_ms=self.now - dt)

    def _branch(self, commit, test_id, verdict, *, dt=0):
        rid = _add_run(self.conn, worktree="/wt", commit=commit,
                       dirty_hash=None, started_ts_ms=self.now - dt)
        _add_result(self.conn, run_id=rid, test_id=test_id, pass_="litebox",
                    verdict=verdict, ts_ms=self.now - dt)

    def _classify_rows(self, tip_sha=None):
        self.conn.execute(
            "INSERT OR REPLACE INTO branch_baseline"
            "(branch_sha, baseline_sha, ref, branch, tip_sha, computed_at_ms) "
            "VALUES('BRANCH','BASE','up','wt/x',?,?)",
            (tip_sha, self.now),
        )
        # test_flake_stats is a live view now — no refresh needed.
        return {
            r["test_id"]: r
            for r in self.conn.execute(
                "SELECT * FROM regression_class WHERE mode='litebox'"
            )
        }

    def _classify(self, tip_sha=None):
        return {
            tid: (r["classification"], r["confidence"])
            for tid, r in self._classify_rows(tip_sha).items()
        }

    def test_hard_regression_high_confidence(self):
        # Rock-solid upstream (3 passes), passed at baseline, fails the
        # full retry budget (3×) on the branch → hard_regression, high.
        for i in range(3):
            self._upstream("UP", "T", "pass", dt=i * 1000)
        self._upstream("BASE", "T", "pass")
        self._branch("BRANCH", "T", "fail", dt=15)
        self._branch("BRANCH", "T", "fail", dt=10)
        self._branch("BRANCH", "T", "fail", dt=5)
        self.assertEqual(self._classify()["T"], ("hard_regression", "high"))

    def test_hard_regression_medium_when_two_fails(self):
        # Only 2 definitive fails (retry budget not exhausted) — could be
        # a load flake under the shadow's build pressure → medium, not
        # high, even with rock-solid upstream.
        for i in range(3):
            self._upstream("UP", "T", "pass", dt=i * 1000)
        self._upstream("BASE", "T", "pass")
        self._branch("BRANCH", "T", "fail", dt=10)
        self._branch("BRANCH", "T", "fail", dt=5)
        self.assertEqual(self._classify()["T"], ("hard_regression", "medium"))

    def test_hard_regression_medium_when_single_branch_run(self):
        self._upstream("BASE", "T", "pass")
        self._branch("BRANCH", "T", "fail")
        self.assertEqual(self._classify()["T"], ("hard_regression", "medium"))

    def test_soft_regression_when_upstream_flaky(self):
        # Upstream flipped pass/fail recently → discount the branch fail.
        self._upstream("UP", "T", "pass", dt=2000)
        self._upstream("UP", "T", "fail", dt=1000)
        self._upstream("BASE", "T", "pass")
        self._branch("BRANCH", "T", "fail")
        self.assertEqual(self._classify()["T"][0], "soft_regression")

    def test_soft_regression_when_baseline_sha_flaky(self):
        # Baseline sha itself was flaky (fail then pass) → soft.
        self._upstream("BASE", "T", "fail", dt=2000)
        self._upstream("BASE", "T", "pass", dt=1000)
        self._branch("BRANCH", "T", "fail")
        self.assertEqual(self._classify()["T"][0], "soft_regression")

    def test_preexisting_fail(self):
        self._upstream("BASE", "T", "fail")
        self._branch("BRANCH", "T", "fail")
        self.assertEqual(self._classify()["T"], ("preexisting_fail", "n/a"))

    def test_new_fail_when_no_baseline(self):
        # Only branch coverage, no baseline row.
        self._branch("BRANCH", "T", "fail")
        self.assertEqual(self._classify()["T"], ("new_fail", "low"))

    def test_ok_and_flaky_pass(self):
        self._upstream("BASE", "T_ok", "pass")
        self._branch("BRANCH", "T_ok", "pass")
        self._upstream("BASE", "T_fp", "pass")
        self._branch("BRANCH", "T_fp", "fail", dt=10)
        self._branch("BRANCH", "T_fp", "pass", dt=5)  # recovered on retry
        res = self._classify()
        self.assertEqual(res["T_ok"], ("ok", "n/a"))
        self.assertEqual(res["T_fp"], ("flaky_pass", "n/a"))

    def test_branch_fail_not_softened_by_branch_side_pass(self):
        # A genuine regression: upstream stable pass, fails on branch.
        # The branch's own fail must NOT count as upstream flakiness
        # (regression-as-flake bug guard).
        self._upstream("BASE", "T", "pass")
        self._upstream("UP", "T", "pass", dt=1000)
        self._branch("BRANCH", "T", "fail")
        cls, _ = self._classify()["T"]
        self.assertEqual(cls, "hard_regression")

    def test_no_result_is_not_a_regression(self):
        # Branch's only result is an infra no_result (~1% background),
        # baseline passed. Must be 'no_result', NOT hard_regression.
        self._upstream("BASE", "T", "pass")
        self._branch("BRANCH", "T", "no_result")
        self.assertEqual(self._classify()["T"], ("no_result", "n/a"))

    def test_no_result_does_not_mask_a_real_fail(self):
        # Branch failed, then a later no_result hiccup. Freshest
        # *definitive* verdict is the fail → still a hard_regression.
        self._upstream("BASE", "T", "pass")
        self._upstream("UP", "T", "pass", dt=2000)
        self._branch("BRANCH", "T", "fail", dt=10)
        self._branch("BRANCH", "T", "no_result", dt=5)  # later infra blip
        self.assertEqual(self._classify()["T"][0], "hard_regression")

    def test_baseline_only_no_result_is_new_fail(self):
        # No definitive baseline pass (baseline only produced no_result)
        # → can't confirm a regression → new_fail, not hard_regression.
        self._upstream("BASE", "T", "no_result")
        self._branch("BRANCH", "T", "fail")
        self.assertEqual(self._classify()["T"], ("new_fail", "low"))

    def test_upstream_no_result_does_not_flag_flaky(self):
        # Upstream pass + upstream no_result must NOT read as flaky
        # (no_result is not a fail). A branch fail is hard, not soft.
        self._upstream("BASE", "T", "pass")
        self._upstream("UP", "T", "no_result", dt=1000)
        self._branch("BRANCH", "T", "fail")
        self.assertEqual(self._classify()["T"][0], "hard_regression")

    def test_not_run_surfaces_coverage_gap(self):
        # Passed at baseline but never run at the branch sha → 'not_run'
        # (explicit coverage gap), NOT silently absent and NOT 'ok'.
        self._upstream("BASE", "T", "pass")
        # (no branch run for T)
        self.assertEqual(self._classify()["T"], ("not_run", "n/a"))

    def test_not_run_distinct_from_no_result(self):
        # not_run = no branch row at all; no_result = ran but only infra
        # non-outcomes. They must not be conflated.
        self._upstream("BASE", "GAP", "pass")        # not run on branch
        self._upstream("BASE", "NR", "pass")
        self._branch("BRANCH", "NR", "no_result")    # ran, infra-only
        res = self._classify()
        self.assertEqual(res["GAP"][0], "not_run")
        self.assertEqual(res["NR"][0], "no_result")

    def test_fixed_when_baseline_failed_and_branch_passes(self):
        # Inverse of a regression: failed at the merge-base baseline,
        # now passes on the branch → 'fixed' (the branch repaired a
        # previously-broken test). Confidence is n/a (a pass isn't a
        # regression to grade).
        self._upstream("BASE", "T", "fail")
        self._branch("BRANCH", "T", "pass")
        self.assertEqual(self._classify()["T"], ("fixed", "n/a"))

    def test_fixed_distinct_from_ok(self):
        # ok = passed at baseline AND branch; fixed = failed at baseline,
        # passes at branch. They must not be conflated.
        self._upstream("BASE", "OKT", "pass")
        self._branch("BRANCH", "OKT", "pass")
        self._upstream("BASE", "FIXT", "fail")
        self._branch("BRANCH", "FIXT", "pass")
        res = self._classify()
        self.assertEqual(res["OKT"][0], "ok")
        self.assertEqual(res["FIXT"][0], "fixed")

    def test_tip_verdict_pass_marks_branch_introduced(self):
        # Branch-introduced regression: baseline passed, branch fails the
        # full retry budget, and the baseline ref's CURRENT tip still
        # passes → the branch broke it. tip_verdict='pass' lets the render
        # label it branch-introduced (not inherited).
        for i in range(3):
            self._upstream("UP", "T", "pass", dt=i * 1000)
        self._upstream("BASE", "T", "pass")
        self._upstream("TIP", "T", "pass")
        self._branch("BRANCH", "T", "fail", dt=15)
        self._branch("BRANCH", "T", "fail", dt=10)
        self._branch("BRANCH", "T", "fail", dt=5)
        row = self._classify_rows(tip_sha="TIP")["T"]
        self.assertEqual(row["classification"], "hard_regression")
        self.assertEqual(row["confidence"], "high")
        self.assertEqual(row["tip_verdict"], "pass")

    def test_tip_verdict_fail_marks_inherited(self):
        # Inherited regression: the baseline ref's CURRENT tip ALSO fails
        # T — the branch merely inherits an already-broken upstream. The
        # tip fail also (correctly) makes upstream observably flaky in the
        # window → soft_regression; but tip_verdict='fail' is the precise
        # "broken on the tip right now" signal the render uses to mark it
        # inherited rather than blaming the branch.
        self._upstream("BASE", "T", "pass")
        self._upstream("TIP", "T", "fail")
        self._branch("BRANCH", "T", "fail")
        row = self._classify_rows(tip_sha="TIP")["T"]
        self.assertEqual(row["tip_verdict"], "fail")
        self.assertEqual(row["classification"], "soft_regression")

    def test_tip_verdict_null_when_tip_not_covered(self):
        # No runs at the tip sha → tip_verdict is NULL; the regression is
        # surfaced as-is with no inherited/branch-introduced distinction.
        self._upstream("BASE", "T", "pass")
        self._branch("BRANCH", "T", "fail")
        row = self._classify_rows(tip_sha="TIP")["T"]  # TIP has no runs
        self.assertIsNone(row["tip_verdict"])
        self.assertEqual(row["classification"], "hard_regression")

    # ── flake-aware classification (preexisting_flake + hard-demotion) ──

    def test_preexisting_flake_when_no_baseline_but_upstream_flaky(self):
        # Branch fails, NO definitive baseline verdict, but the test flaps
        # pass/fail on the upstream lineage → it's a pre-existing flake the
        # thin merge-base just didn't cover, NOT a failure the branch
        # introduced. Must be `preexisting_flake`, not `new_fail`.
        self._upstream("UP", "T", "pass", dt=2000)
        self._upstream("UP", "T", "fail", dt=1000)   # upstream flaps
        # (no BASE run → baseline arm is NULL)
        self._branch("BRANCH", "T", "fail")
        self.assertEqual(self._classify()["T"], ("preexisting_flake", "n/a"))

    def test_preexisting_flake_via_upstream_fail_without_pass(self):
        # No baseline, branch fails, upstream has only a fail (no pass) →
        # 100% upstream fail-rate is `heavily_flaky`, so it's a
        # pre-existing flake, not `new_fail`.
        self._upstream("UP", "T", "fail", dt=1000)
        self._branch("BRANCH", "T", "fail")
        self.assertEqual(self._classify()["T"][0], "preexisting_flake")

    def test_new_fail_stays_new_fail_when_upstream_solid(self):
        # No baseline, branch fails, but upstream is SOLID (a pass, no
        # fails) → genuinely unexplained → still `new_fail`, NOT
        # `preexisting_flake`. This is the line that keeps `new_fail`
        # meaningful (worth a look) vs the flake bucket (benign).
        self._upstream("UP", "T", "pass", dt=1000)
        self._branch("BRANCH", "T", "fail")
        self.assertEqual(self._classify()["T"], ("new_fail", "low"))

    def test_low_rate_flake_single_branch_fail_is_soft(self):
        # The original false-positive shape (CF.pipe4): occasionally-flaky
        # upstream (LOW rate, below the heavy-flake threshold) + a SINGLE
        # (thin) branch fail → soft, not a false hard. The thin branch
        # evidence didn't reproduce, so we discount.
        for i in range(20):
            self._upstream("UP", "T", "pass", dt=i * 1000)
        self._upstream("UP", "T", "fail", dt=100000)   # ~5% upstream rate
        self._upstream("BASE", "T", "pass")
        self._branch("BRANCH", "T", "fail")            # single (thin) fail
        row = self._classify_rows()["T"]
        self.assertEqual(row["upstream_heavily_flaky"], 0)  # below the rate
        self.assertEqual(row["classification"], "soft_regression")

    def test_reproducible_branch_fail_low_rate_flake_stays_hard(self):
        # The false-NEGATIVE fix (SCM.pass_eventfd_poll_wake): near-solid
        # upstream (one old flake → ~5%, below threshold), baseline pass,
        # branch fails the FULL retry budget → a real regression,
        # hard/high — NOT discounted to soft just because upstream flaked
        # once weeks ago.
        for i in range(20):
            self._upstream("UP", "T", "pass", dt=i * 1000)
        self._upstream("UP", "T", "fail", dt=100000)   # ~5% upstream rate
        self._upstream("BASE", "T", "pass")
        for i in range(3):
            self._branch("BRANCH", "T", "fail", dt=i * 10)   # full budget
        self.assertEqual(self._classify()["T"], ("hard_regression", "high"))

    def test_heavily_flaky_reproduced_is_soft_medium(self):
        # dropbear_bash shape: chronically-flaky upstream (fail-rate above
        # the threshold), baseline pass, branch fails the full budget →
        # `soft` (genuinely unreliable test) but `medium`: the branch DID
        # reproduce it, so it's flagged for a re-run, not dismissed.
        for i in range(10):
            self._upstream("UP", "T", "pass", dt=i * 1000)
        for i in range(5):
            self._upstream("UP", "T", "fail", dt=(i + 20) * 1000)   # ~33%
        self._upstream("BASE", "T", "pass")
        for i in range(3):
            self._branch("BRANCH", "T", "fail", dt=i * 10)
        self.assertEqual(self._classify()["T"], ("soft_regression", "medium"))

    def test_heavily_flaky_single_fail_is_soft_low(self):
        # Same chronically-flaky test, single branch fail → soft/low (no
        # reproduction; most likely just another flake).
        for i in range(10):
            self._upstream("UP", "T", "pass", dt=i * 1000)
        for i in range(5):
            self._upstream("UP", "T", "fail", dt=(i + 20) * 1000)
        self._upstream("BASE", "T", "pass")
        self._branch("BRANCH", "T", "fail")
        self.assertEqual(self._classify()["T"], ("soft_regression", "low"))

    def test_no_baseline_reproducible_low_rate_is_new_fail(self):
        # No baseline, near-solid upstream (low rate), branch reproduces
        # the fail full-budget → `new_fail` (unexplained, worth a look),
        # NOT `preexisting_flake` (which would wrongly mark it benign).
        for i in range(20):
            self._upstream("UP", "T", "pass", dt=i * 1000)
        self._upstream("UP", "T", "fail", dt=100000)   # ~5%
        for i in range(3):
            self._branch("BRANCH", "T", "fail", dt=i * 10)
        self.assertEqual(self._classify()["T"][0], "new_fail")

    def test_solid_upstream_single_fail_stays_hard(self):
        # Guard the other side: a genuinely rock-solid-upstream test (passes,
        # ZERO upstream fails) that fails once on the branch is still a
        # `hard_regression` (medium) — only upstream *instability* demotes.
        for i in range(3):
            self._upstream("UP", "T", "pass", dt=i * 1000)
        self._upstream("BASE", "T", "pass")
        self._branch("BRANCH", "T", "fail")
        self.assertEqual(self._classify()["T"], ("hard_regression", "medium"))


class FlakyLeaderboardTests(unittest.TestCase):
    """The flaky leaderboard is SQL-first: the helper returns rows from
    one aggregate query, and Python only formats them."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dash-flaky-")
        self.db = Path(self.tmp) / "results.sqlite"
        self.conn = _init_db(self.db)
        self.now = dashboard.now_ms()

    def tearDown(self) -> None:
        self.conn.close()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _result(self, test_id, mode, verdict, *, worktree="/ci",
                suite="vscode", group="pidfd", dt=0):
        rid = _add_run(self.conn, worktree=worktree,
                       started_ts_ms=self.now - dt)
        _add_result(self.conn, run_id=rid, test_id=test_id, pass_=mode,
                    verdict=verdict, ts_ms=self.now - dt,
                    suite=suite, group=group)

    def _rows(self, **kwargs):
        defaults = {
            "mode": "litebox",
            "pattern": None,
            "suite": None,
            "group": None,
            "min_rate": 0.0,
            "limit": 40,
        }
        defaults.update(kwargs)
        return dashboard._flaky_rows(self.conn, **defaults)

    def test_genuinely_flaky_ranked_with_correct_rate(self):
        self._result("T_flaky", "litebox", "pass", dt=3)
        self._result("T_flaky", "litebox", "fail", dt=2)
        self._result("T_solid", "litebox", "pass", dt=1)
        rows = self._rows()
        self.assertEqual(rows[0]["test_id"], "T_flaky")
        self.assertEqual(rows[0]["n_pass"], 1)
        self.assertEqual(rows[0]["n_fail"], 1)
        self.assertAlmostEqual(rows[0]["fail_rate"], 0.5)

    def test_load_sensitive_flag(self):
        self._result("T_load", "litebox", "pass", worktree="/ci", dt=2)
        self._result("T_load", "litebox", "fail",
                     worktree="/repo/.dashboard/shadows/T_load", dt=1)
        row = self._rows()[0]
        self.assertEqual(row["test_id"], "T_load")
        self.assertEqual(row["load_sensitive"], 1)
        self.assertAlmostEqual(row["shadow_rate"], 1.0)
        self.assertAlmostEqual(row["dedicated_rate"], 0.0)

    def test_substrate_bug_flag(self):
        self._result("T_substrate", "native", "pass", dt=4)
        self._result("T_substrate", "native", "pass", dt=3)
        self._result("T_substrate", "litebox", "pass", dt=2)
        self._result("T_substrate", "litebox", "fail", dt=1)
        row = self._rows()[0]
        self.assertEqual(row["test_id"], "T_substrate")
        self.assertEqual(row["substrate_bug"], 1)

    def test_min_rate_filters(self):
        self._result("T_low", "litebox", "pass", dt=4)
        self._result("T_low", "litebox", "fail", dt=3)
        self._result("T_low", "litebox", "pass", dt=2)
        self._result("T_high", "litebox", "fail", dt=1)
        rows = self._rows(min_rate=0.6)
        self.assertEqual([r["test_id"] for r in rows], ["T_high"])

    def test_pattern_filters(self):
        self._result("alpha_match", "litebox", "fail", dt=2)
        self._result("beta_other", "litebox", "fail", dt=1)
        rows = self._rows(pattern="match")
        self.assertEqual([r["test_id"] for r in rows], ["alpha_match"])

    def test_no_result_rows_do_not_inflate_rate(self):
        self._result("T_noresult", "litebox", "pass", dt=3)
        self._result("T_noresult", "litebox", "fail", dt=2)
        self._result("T_noresult", "litebox", "no_result", dt=1)
        row = self._rows()[0]
        self.assertEqual(row["n_pass"], 1)
        self.assertEqual(row["n_fail"], 1)
        self.assertAlmostEqual(row["fail_rate"], 0.5)


class StressHelperTests(unittest.TestCase):
    """Pure helpers behind `dashboard.py stress` + its SQL summary."""

    def test_distribute_even_and_remainder(self):
        self.assertEqual(dashboard._stress_distribute(20, 4), [5, 5, 5, 5])
        self.assertEqual(dashboard._stress_distribute(20, 3), [7, 7, 6])
        self.assertEqual(dashboard._stress_distribute(5, 1), [5])
        self.assertEqual(dashboard._stress_distribute(0, 3), [0, 0, 0])
        self.assertEqual(dashboard._stress_distribute(2, 5), [1, 1, 0, 0, 0])

    def test_cargo_argv_is_positional_filter_not_fill(self):
        argv = dashboard._stress_cargo_argv(["RL.subscriber", "F.fork"])
        self.assertEqual(argv[:6], ["cargo", "test", "-p",
                                    "litebox_test_harness", "--test",
                                    "integration"])
        self.assertEqual(argv[6], "--")
        self.assertEqual(argv[7:], ["RL.subscriber", "F.fork"])
        # Must NOT use --fill (that would skip already-covered tests
        # instead of re-running them for fresh samples).
        self.assertNotIn("--fill", " ".join(argv))

    def test_target_summary_groups_and_windows(self):
        tmp = tempfile.mkdtemp(prefix="dash-stress-")
        try:
            conn = _init_db(Path(tmp) / "results.sqlite")
            # 2 pass + 1 fail + 1 no_result at sha S, plus a pre-window
            # pass that must be excluded, plus a different sha / dirty row.
            for v, dt in [("pass", 0), ("pass", 10), ("fail", 20),
                          ("no_result", 30)]:
                rid = _add_run(conn, worktree="/s", commit="S",
                               dirty_hash=None, started_ts_ms=1000)
                _add_result(conn, run_id=rid, test_id="RL.sub", pass_="litebox",
                            verdict=v, ts_ms=1000 + dt)
            pre = _add_run(conn, worktree="/s", commit="S", dirty_hash=None,
                           started_ts_ms=1)
            _add_result(conn, run_id=pre, test_id="RL.sub", pass_="litebox",
                        verdict="pass", ts_ms=1)          # before window
            oth = _add_run(conn, worktree="/s", commit="OTHER",
                           dirty_hash=None, started_ts_ms=1000)
            _add_result(conn, run_id=oth, test_id="RL.sub", pass_="litebox",
                        verdict="fail", ts_ms=1005)       # different sha
            rows = dashboard._stress_target_summary(
                conn, "S", ["RL.sub"], "litebox", since_ts_ms=1000)
            self.assertEqual(len(rows), 1)
            r = rows[0]
            self.assertEqual((r["n_pass"], r["n_fail"], r["n_other"]),
                             (2, 1, 1))
            # Pattern that matches nothing → no rows.
            self.assertEqual(
                dashboard._stress_target_summary(
                    conn, "S", ["NOPE"], "litebox", 1000), [])
            conn.close()
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class ThroughputRenderTests(unittest.TestCase):
    """`_render_throughput` computes cycle-completion, per-trial overhead,
    and per-tip velocity entirely in SQL. Hermetic temp DB with rows
    positioned relative to `now_ms()` so the relative windows apply."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = _init_db(Path(self.tmp.name) / "results.sqlite")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _run(self, *, finished_ts_ms, started_ts_ms, branch="b"):
        self.conn.execute(
            "INSERT INTO runs(started_ts_ms, finished_ts_ms, hostname,"
            " worktree_path, commit_sha, branch) VALUES (?,?,?,?,?,?)",
            (started_ts_ms, finished_ts_ms, "h", "/wt", "sha", branch))
        return self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def _res(self, rid, tid, mode, ts, *, spawn=1, init=1, useful=1):
        self.conn.execute(
            'INSERT INTO run_results(run_id,test_id,mode,verdict,'
            'finished_ts_ms,suite,"group",t_acquire_ms,t_docker_start_ms,'
            't_docker_spawn_ms,t_litebox_init_ms,t_useful_ms)'
            ' VALUES (?,?,?,?,?,?,?,0,0,?,?,?)',
            (rid, tid, mode, "pass", ts, "s", "g", spawn, init, useful))

    def test_empty_store_returns_blank(self):
        self.assertEqual(dashboard._render_throughput(self.conn), "")

    def test_cycle_completion_counts(self):
        now = dashboard.now_ms()
        # completed: finalized run
        a = self._run(finished_ts_ms=now, started_ts_ms=now - 60_000)
        self._res(a, "t1", "litebox", now - 60_000)
        # reaped: not finalized, last result older than the 5-min settle
        b = self._run(finished_ts_ms=None, started_ts_ms=now - 600_000)
        self._res(b, "t2", "litebox", now - 600_000)
        # in-flight: not finalized, recent result
        c = self._run(finished_ts_ms=None, started_ts_ms=now - 60_000)
        self._res(c, "t3", "litebox", now - 60_000)
        out = dashboard._render_throughput(self.conn)
        self.assertIn("1 completed · 1 reaped", out)
        self.assertIn("1 in-flight", out)
        self.assertIn("(50% reaped)", out)  # 1 reaped of (1+1)

    def test_overhead_percent(self):
        now = dashboard.now_ms()
        a = self._run(finished_ts_ms=now, started_ts_ms=now - 60_000)
        # spawn 20s + init 1s vs useful 2s ⇒ overhead 21/23 = 91%
        self._res(a, "t1", "litebox", now - 60_000,
                  spawn=20_000, init=1_000, useful=2_000)
        out = dashboard._render_throughput(self.conn)
        self.assertIn("| litebox |", out)
        self.assertIn("**91%**", out)

    def test_velocity_per_tip(self):
        now = dashboard.now_ms()
        a = self._run(finished_ts_ms=now, started_ts_ms=now - 60_000,
                      branch="mybranch")
        for i in range(6):  # 6 litebox results in 6h ⇒ 1.0/hr, 0 native
            self._res(a, f"t{i}", "litebox", now - 60_000)
        out = dashboard._render_throughput(self.conn)
        self.assertIn("`mybranch` | 0.0 | 1.0 |", out)


class ReconcileRunnersTests(unittest.TestCase):
    """Pure per-tip runner reconciliation: (desired, running) ->
    (to_start, to_drain). This is the whole scheduling policy."""

    def test_new_tip_starts(self):
        s, d = dashboard._reconcile_runners({"a": "sha1"}, {})
        self.assertEqual((s, d), ([("a", "sha1")], []))

    def test_alive_at_right_sha_left_alone(self):
        s, d = dashboard._reconcile_runners(
            {"a": "sha1"}, {"a": {"sha": "sha1", "alive": True, "done": False}})
        self.assertEqual((s, d), ([], []))

    def test_done_at_right_sha_left_alone(self):
        s, d = dashboard._reconcile_runners(
            {"a": "sha1"}, {"a": {"sha": "sha1", "alive": False, "done": True}})
        self.assertEqual((s, d), ([], []))

    def test_sha_moved_drains_and_restarts(self):
        s, d = dashboard._reconcile_runners(
            {"a": "sha2"}, {"a": {"sha": "sha1", "alive": True, "done": False}})
        self.assertEqual((s, d), ([("a", "sha2")], ["a"]))

    def test_exited_at_right_sha_left_alone(self):
        # A clean/parked exit at the desired sha with no retry budget is
        # terminal — the tip re-runs only when its sha moves.
        s, d = dashboard._reconcile_runners(
            {"a": "sha1"}, {"a": {"sha": "sha1", "alive": False, "done": False}})
        self.assertEqual((s, d), ([], []))

    def test_crashed_with_retry_budget_restarts(self):
        # A crashed runner still within its retry budget is drained and
        # respawned at the SAME sha (transient build race self-heals on a
        # clean retry) — no sha move required.
        s, d = dashboard._reconcile_runners(
            {"a": "sha1"},
            {"a": {"sha": "sha1", "alive": False, "done": True,
                   "retry": True}})
        self.assertEqual((s, d), ([("a", "sha1")], ["a"]))

    def test_crashed_budget_spent_parked(self):
        # Once the retry budget is spent (retry=False), a crashed runner is
        # parked terminal — no respawn loop on a genuinely un-buildable tip.
        s, d = dashboard._reconcile_runners(
            {"a": "sha1"},
            {"a": {"sha": "sha1", "alive": False, "done": True,
                   "retry": False}})
        self.assertEqual((s, d), ([], []))

    def test_tip_gone_drains(self):
        s, d = dashboard._reconcile_runners(
            {}, {"a": {"sha": "sha1", "alive": True, "done": False}})
        self.assertEqual((s, d), ([], ["a"]))

    def test_mixed(self):
        desired = {"keep": "s1", "moved": "s2new", "new": "s3"}
        running = {
            "keep": {"sha": "s1", "alive": True, "done": False},
            "moved": {"sha": "s2old", "alive": True, "done": False},
            "gone": {"sha": "s9", "alive": False, "done": True},
        }
        s, d = dashboard._reconcile_runners(desired, running)
        self.assertEqual(sorted(s), [("moved", "s2new"), ("new", "s3")])
        self.assertEqual(sorted(d), ["gone", "moved"])


class WatchdogStuckPlanTests(unittest.TestCase):
    """Pure decision for an UP supervisor. Restart is reserved for infra
    (BUILD_FAILING), cooldown-guarded; a parked tip is SURFACED (logged once
    per tip+sha), never restarted — so the durable 3-min timer can't churn
    the whole supervisor for one agent tip."""

    NOW = 1_000_000_000_000

    def test_healthy_no_restart(self):
        p = dashboard._wd_stuck_plan(0, [], {}, self.NOW)
        self.assertFalse(p["restart"])
        self.assertEqual(p["log"], [])

    def test_build_failing_restarts_and_fixes_docker(self):
        p = dashboard._wd_stuck_plan(
            dashboard._WD_INFRA_FAIL_ALARM + 1, [], {}, self.NOW)
        self.assertTrue(p["restart"])
        self.assertTrue(p["fix_docker"])
        self.assertIn("BUILD_FAILING", p["reason"])

    def test_build_failing_respects_cooldown(self):
        st = {"last_remediation_ms": self.NOW - 1}  # remediated a moment ago
        p = dashboard._wd_stuck_plan(
            dashboard._WD_INFRA_FAIL_ALARM + 5, [], st, self.NOW)
        self.assertFalse(p["restart"])
        self.assertIn("cooldown", p["reason"])

    def test_parked_tip_is_logged_not_restarted(self):
        # A parked tip is surfaced; it never triggers a supervisor restart.
        p = dashboard._wd_stuck_plan(0, [("wportnoy/x", "sha1")], {}, self.NOW)
        self.assertFalse(p["restart"])
        self.assertEqual(p["log"], [("wportnoy/x", "sha1")])

    def test_parked_tip_logged_once_per_sha(self):
        # Already surfaced at this sha → not logged again (no log spam).
        st = {"logged_parks": {"wportnoy/x": "sha1"}}
        p = dashboard._wd_stuck_plan(0, [("wportnoy/x", "sha1")], st, self.NOW)
        self.assertFalse(p["restart"])
        self.assertEqual(p["log"], [])

    def test_parked_at_new_sha_is_surfaced_again(self):
        st = {"logged_parks": {"wportnoy/x": "OLDsha"}}
        p = dashboard._wd_stuck_plan(0, [("wportnoy/x", "sha2")], st, self.NOW)
        self.assertEqual(p["log"], [("wportnoy/x", "sha2")])

    def test_build_failing_restarts_even_with_parked(self):
        # Infra BUILD_FAILING still restarts; the parked tip is also logged.
        p = dashboard._wd_stuck_plan(
            dashboard._WD_INFRA_FAIL_ALARM + 1,
            [("wportnoy/x", "sha1")], {}, self.NOW)
        self.assertTrue(p["restart"])
        self.assertTrue(p["fix_docker"])
        self.assertIn("BUILD_FAILING", p["reason"])
        self.assertEqual(p["log"], [("wportnoy/x", "sha1")])


class FmtRcRegressionsTests(unittest.TestCase):
    """The Agent-worktrees regression cell must be coverage-aware: a run
    with zero regressions only reads as `clean` when the WHOLE universe
    ran; a thin run reads as `partial` so a passing subset can't be
    mistaken for a validated branch."""

    def _s(self, **kw):
        s = dict(dashboard._RC_EMPTY)
        s.update(kw)
        return s

    def test_clean_only_at_full_coverage(self):
        self.assertEqual(
            dashboard._fmt_rc_regressions(self._s(covered=10, not_run=0)),
            "clean",
        )

    def test_partial_when_coverage_incomplete(self):
        # Zero regressions but 5 tests never ran → NOT clean.
        self.assertEqual(
            dashboard._fmt_rc_regressions(self._s(covered=10, not_run=5)),
            "partial",
        )

    def test_dash_when_nothing_covered(self):
        self.assertEqual(
            dashboard._fmt_rc_regressions(self._s(covered=0, not_run=100)),
            "—",
        )

    def test_regressions_take_precedence_over_partial(self):
        # A real break is reported regardless of coverage — never masked
        # as `partial`/`clean`.
        out = dashboard._fmt_rc_regressions(
            self._s(covered=10, not_run=5, hard=2, hard_high=1)
        )
        self.assertIn("hard", out)
        self.assertNotIn("partial", out)
        self.assertNotIn("clean", out)


if __name__ == "__main__":
    unittest.main()
