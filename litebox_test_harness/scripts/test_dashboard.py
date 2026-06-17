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

    def _classify(self):
        self.conn.execute(
            "INSERT OR REPLACE INTO branch_baseline"
            "(branch_sha, baseline_sha, ref, branch, computed_at_ms) "
            "VALUES('BRANCH','BASE','up','wt/x',?)",
            (self.now,),
        )
        # test_flake_stats is a live view now — no refresh needed.
        return {
            r["test_id"]: (r["classification"], r["confidence"])
            for r in self.conn.execute(
                "SELECT test_id, classification, confidence "
                "FROM regression_class WHERE mode='litebox'"
            )
        }

    def test_hard_regression_high_confidence(self):
        # Rock-solid upstream (3 passes), passed at baseline, fails
        # twice on branch → hard_regression, high confidence.
        for i in range(3):
            self._upstream("UP", "T", "pass", dt=i * 1000)
        self._upstream("BASE", "T", "pass")
        self._branch("BRANCH", "T", "fail", dt=10)
        self._branch("BRANCH", "T", "fail", dt=5)
        self.assertEqual(self._classify()["T"], ("hard_regression", "high"))

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


if __name__ == "__main__":
    unittest.main()
