"""Unit tests for dashboard.py.

Run with:
  python3 litebox_test_harness/scripts/test_dashboard.py

Stdlib only — no third-party deps.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
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
    conn.execute("INSERT INTO meta(key, value) VALUES('schema_version','3')")
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
        "INSERT INTO run_results(run_id, test_id, pass, verdict,"
        " finished_ts_ms, suite, \"group\","
        " t_acquire_ms, t_docker_start_ms, t_useful_ms)"
        " VALUES (?,?,?,?,?,?,?, 0, 0, 100)",
        (run_id, test_id, pass_, verdict, ts_ms, suite, group),
    )


class LatestResultsViewTests(unittest.TestCase):
    """The latest_results VIEW replaces the prior UPSERT-maintained
    table. Verify it returns the freshest row per (test_id, pass).
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
                    verdict="FAIL", ts_ms=1500)
        _add_result(self.conn, run_id=r2, test_id="A", pass_="native",
                    verdict="pass", ts_ms=2500)
        row = self.conn.execute(
            "SELECT verdict, finished_ts_ms FROM latest_results"
            " WHERE test_id='A' AND pass='native'"
        ).fetchone()
        self.assertEqual(row["verdict"], "pass")
        self.assertEqual(row["finished_ts_ms"], 2500)

    def test_view_one_row_per_pass(self):
        r = _add_run(self.conn)
        _add_result(self.conn, run_id=r, test_id="A", pass_="native",
                    verdict="pass", ts_ms=1000)
        _add_result(self.conn, run_id=r, test_id="A", pass_="litebox",
                    verdict="FAIL", ts_ms=1000)
        rows = self.conn.execute(
            "SELECT pass, verdict FROM latest_results WHERE test_id='A'"
            " ORDER BY pass"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["pass"], "litebox")
        self.assertEqual(rows[0]["verdict"], "FAIL")
        self.assertEqual(rows[1]["pass"], "native")
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
        # _coverage_pass_fail filters dirty; only A counts.
        covered, n_pass, n_fail = dashboard._coverage_pass_fail(
            self.conn, "abc", "native"
        )
        self.assertEqual(covered, 1)
        self.assertEqual(n_pass, 1)
        self.assertEqual(n_fail, 0)


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


class ShadowPathTests(unittest.TestCase):
    """Per-branch shadow path encoding + GC selection rules.
    Hermetic: only exercises pure-functional path helpers and the
    branch-decoding step of GC (the actual git invocations are
    integration-tested by the live supervisor)."""

    def test_branch_to_dirname_round_trip_simple(self):
        self.assertEqual(
            dashboard._branch_to_shadow_dirname("main"), "main")

    def test_branch_to_dirname_round_trip_slash(self):
        self.assertEqual(
            dashboard._branch_to_shadow_dirname("wportnoy/foo-bar"),
            "wportnoy%2ffoo-bar",
        )
        # And decoding (used by GC) reverses it cleanly.
        self.assertEqual(
            "wportnoy%2ffoo-bar".replace("%2f", "/"),
            "wportnoy/foo-bar",
        )

    def test_per_branch_path_is_under_shadows_root(self):
        sd = Path("/tmp/sd-test")
        p = dashboard._per_branch_shadow_path(sd, "wportnoy/x")
        self.assertEqual(p.parent, dashboard._shadows_root(sd))
        self.assertEqual(p.name, "wportnoy%2fx")

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


if __name__ == "__main__":
    unittest.main()
