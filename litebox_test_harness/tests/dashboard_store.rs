// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Smoke tests for the dashboard sqlite store schema.
//!
//! The actual `dashboard_store` module — schema DDL, producer-side
//! `init` / `record_result` / `finalize` / `select_fill_batch` —
//! lives in `tests/common/dashboard_store.rs` and is shared with
//! `tests/integration.rs` via `#[path]`. This file just exercises
//! the schema by applying the canonical DDL to a temp database and
//! asserting basic invariants. No docker, no integration runner.

use std::path::PathBuf;
use std::process::Command;

use rusqlite::{Connection, params};

// Pull in the shared producer module so we can use its canonical
// `SCHEMA_DDL` without duplicating it. Most of the module is unused
// from this test binary (we only touch SCHEMA_DDL), so silence the
// resulting dead-code warnings.
#[allow(dead_code)]
#[path = "common/dashboard_store.rs"]
mod dashboard_store;

fn integration_bin() -> PathBuf {
    // The integration test binary is built into target/{profile}/deps.
    // Find the most recent one matching the expected name pattern.
    let dir = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("integration-") {
                continue;
            }
            if name.ends_with(".d") {
                continue;
            }
            if let Ok(meta) = entry.metadata()
                && let Ok(mtime) = meta.modified()
            {
                if newest.as_ref().map_or(true, |(t, _)| mtime > *t) {
                    newest = Some((mtime, entry.path()));
                }
            }
        }
    }
    newest
        .map(|(_, p)| p)
        .expect("integration test binary not found in deps/")
}

#[test]
fn dashboard_store_list_mode_skips_init() {
    let tmp = tempdir_marker("list");
    let bin = integration_bin();
    let out = Command::new(&bin)
        .env("LITEBOX_DASHBOARD_DIR", &tmp)
        .args(["--list"])
        .output()
        .expect("spawn integration --list");
    assert!(out.status.success(), "integration --list failed: {out:?}");
    // --list must NOT create the dashboard sqlite (init is gated on
    // actual trial execution).
    assert!(
        !PathBuf::from(&tmp).join("results.sqlite").exists(),
        "--list should not initialize the dashboard sqlite"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dashboard_schema_initializes_and_view_returns_latest() {
    let tmp = tempdir_marker("schema");
    std::fs::create_dir_all(&tmp).unwrap();
    let db = PathBuf::from(&tmp).join("results.sqlite");
    let conn = Connection::open(&db).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "busy_timeout", 5000).unwrap();
    // Apply the canonical DDL — shared with the producer.
    conn.execute_batch(dashboard_store::SCHEMA_DDL).unwrap();
    conn.execute(
        "INSERT INTO meta(key,value) VALUES('schema_version', ?1)",
        params![dashboard_store::SCHEMA_VERSION],
    )
    .unwrap();

    // Insert two runs at different times; both record results for the
    // same (test_id, pass). The VIEW should always return the newer.
    conn.execute(
        "INSERT INTO runs(started_ts_ms, hostname, worktree_path, commit_sha, branch)
         VALUES (1000, 'host', '/wt', 'abc1234', 'main')",
        [],
    )
    .unwrap();
    let r1 = conn.last_insert_rowid();

    conn.execute(
        "INSERT INTO runs(started_ts_ms, hostname, worktree_path, commit_sha, branch)
         VALUES (2000, 'host', '/wt', 'abc1234', 'main')",
        [],
    )
    .unwrap();
    let r2 = conn.last_insert_rowid();

    let insert_result = |run_id: i64, verdict: &str, ts: i64| {
        conn.execute(
            "INSERT INTO run_results(run_id, test_id, mode, verdict, finished_ts_ms,
                                     suite, \"group\",
                                     t_acquire_ms, t_docker_start_ms, t_useful_ms)
             VALUES (?1, 'X.id', 'native', ?2, ?3, 'fork', 'fork_matrix', 0, 0, 100)",
            params![run_id, verdict, ts],
        )
        .unwrap()
    };
    insert_result(r1, "FAIL", 1500);
    insert_result(r2, "pass", 2500);

    // VIEW returns the freshest row.
    let (verdict, ts): (String, i64) = conn
        .query_row(
            "SELECT verdict, finished_ts_ms FROM latest_results
              WHERE test_id='X.id' AND mode='native'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(verdict, "pass");
    assert_eq!(ts, 2500);

    // dirty_hash IS NOT NULL is the "dirty" predicate now.
    conn.execute(
        "INSERT INTO runs(started_ts_ms, hostname, worktree_path, commit_sha, branch, dirty_hash)
         VALUES (3000, 'host', '/wt', 'abc1234', 'main', 'deadbeef')",
        [],
    )
    .unwrap();
    let n_dirty: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM runs WHERE dirty_hash IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n_dirty, 1);

    // tracked_refs is config; round-trip a row.
    conn.execute(
        "INSERT INTO tracked_refs(ref, ci_worktree) VALUES (?, ?)",
        params!["origin/main", "/tmp/ci-main"],
    )
    .unwrap();
    let wt: String = conn
        .query_row(
            "SELECT ci_worktree FROM tracked_refs WHERE ref='origin/main'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(wt, "/tmp/ci-main");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn harness_leases_table_round_trip_and_prune() {
    // Validates the additive `harness_leases` table + the
    // count-and-prune behavior the `lease` module relies on. We
    // don't drive the lease module's static state from here (its
    // `OnceLock<Registered>` is process-singleton); we exercise the
    // SQL directly against a fresh DB.
    let tmp = tempdir_marker("leases");
    std::fs::create_dir_all(&tmp).unwrap();
    let db = PathBuf::from(&tmp).join("results.sqlite");
    let conn = Connection::open(&db).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "busy_timeout", 5000).unwrap();
    conn.execute_batch(dashboard_store::SCHEMA_DDL).unwrap();
    // ENSURE_LEASES_DDL is idempotent (CREATE TABLE IF NOT EXISTS) —
    // verify re-applying it on a DB that already has the table is
    // a no-op, since that's what the producer does on every
    // connection.
    conn.execute_batch(dashboard_store::ENSURE_LEASES_DDL)
        .unwrap();

    let now = dashboard_store::now_ms();
    let stale_ms: i64 = 30_000;

    conn.execute(
        "INSERT INTO harness_leases(pid, heartbeat_at_ms) VALUES (?1, ?2)",
        params![1111_i64, now],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO harness_leases(pid, heartbeat_at_ms) VALUES (?1, ?2)",
        params![2222_i64, now],
    )
    .unwrap();

    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM harness_leases WHERE heartbeat_at_ms >= ?1",
            params![now - stale_ms],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(live, 2, "both leases should be live");

    // Fudge one heartbeat into the past, then prune-by-cutoff.
    conn.execute(
        "UPDATE harness_leases SET heartbeat_at_ms = ?1 WHERE pid = ?2",
        params![now - (stale_ms + 5_000), 1111_i64],
    )
    .unwrap();
    let deleted = conn
        .execute(
            "DELETE FROM harness_leases WHERE heartbeat_at_ms < ?1",
            params![now - stale_ms],
        )
        .unwrap();
    assert_eq!(deleted, 1, "stale lease should be pruned");

    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM harness_leases WHERE heartbeat_at_ms >= ?1",
            params![now - stale_ms],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(live, 1, "remaining lease should still be live");

    // INSERT OR REPLACE on (pid) — pid 2222 re-registers; should
    // collapse to one row, not duplicate.
    conn.execute(
        "INSERT OR REPLACE INTO harness_leases(pid, heartbeat_at_ms)
         VALUES (?1, ?2)",
        params![2222_i64, now + 1],
    )
    .unwrap();
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM harness_leases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(total, 1, "pid is PK — INSERT OR REPLACE keeps one row");

    let _ = std::fs::remove_dir_all(&tmp);
}

// ── framework_core: pure-helper unit tests ──────────────────────────
//
// Tests the deterministic, no-side-effect building blocks that
// framework.rs delegates to. Catches regressions in container
// naming + docker-args layout (e.g. the keep_containers bug that
// shipped because no test asserted "--rm" placement).

#[allow(dead_code)]
#[path = "common/framework_core.rs"]
mod framework_core;

#[test]
fn container_name_is_unique_in_tight_loop() {
    let names: std::collections::HashSet<String> = (0..10_000)
        .map(|_| framework_core::container_name("native", "FOO.bar"))
        .collect();
    assert_eq!(
        names.len(),
        10_000,
        "10k tight-loop calls should produce 10k distinct names \
         (no within-harness collision via the monotonic counter)"
    );
}

#[test]
fn container_name_matches_canonical_pattern() {
    let n = framework_core::container_name("litebox", "INHERIT.pipe.dpg1_dpg1");
    // Regex: litebox-<pass>-<sanitized_tid>-<harness_pid>-<counter>
    let parts: Vec<&str> = n.rsplitn(3, '-').collect();
    // Right-split: [counter, harness_pid, prefix...]
    assert_eq!(
        parts.len(),
        3,
        "name should have at least 3 dash-segments: {n}"
    );
    let counter: u64 = parts[0].parse().expect("counter should parse as u64");
    let harness_pid: u32 = parts[1].parse().expect("harness_pid should parse as u32");
    assert!(counter >= 1, "counter starts at 1");
    assert_eq!(harness_pid, std::process::id());
    let prefix = parts[2];
    assert!(
        prefix.starts_with("litebox-litebox-"),
        "prefix should start with litebox-{{pass}}-: {prefix}"
    );
    // test_id sanitization: dots and underscores become dashes.
    assert!(
        prefix.contains("INHERIT-pipe-dpg1-dpg1"),
        "tid should be sanitized: {prefix}"
    );
}

#[test]
fn container_name_sweep_regex_matches() {
    // The dashboard's cleanup sweep uses docker's name filter
    // `name=-{harness_pid}-` (substring match). Verify our names
    // contain that pattern.
    let pid = std::process::id();
    let n = framework_core::container_name("native", "X.y");
    assert!(
        n.contains(&format!("-{pid}-")),
        "name {n} must contain -{pid}- for sweep"
    );
}

#[test]
fn build_docker_run_args_foreground_with_rm() {
    let spec = framework_core::ContainerSpec {
        image: "litebox-test".into(),
        docker_args: vec!["-v".into(), "/host:/c:ro".into()],
        command: vec!["echo".into(), "hi".into()],
        detached: false,
        timeout_secs: None,
    };
    let args = framework_core::build_docker_run_args(&spec, "litebox-foo", /*keep*/ false);
    assert_eq!(
        args,
        vec![
            "run",
            "--rm",
            "--name",
            "litebox-foo",
            "-v",
            "/host:/c:ro",
            "litebox-test",
            "echo",
            "hi",
        ],
        "foreground spec without keep_containers: run --rm --name … args image command"
    );
}

#[test]
fn build_docker_run_args_detached() {
    let spec = framework_core::ContainerSpec {
        image: "litebox-agent-cli".into(),
        docker_args: vec!["-p".into(), "127.0.0.1:0:22".into()],
        command: vec!["/usr/sbin/dropbear".into(), "-F".into()],
        detached: true,
        timeout_secs: None,
    };
    let args = framework_core::build_docker_run_args(&spec, "litebox-dbear", /*keep*/ false);
    assert_eq!(
        args[..3],
        ["run", "-d", "--rm"],
        "detached: run -d --rm first"
    );
    assert!(args.contains(&"-p".to_string()));
}

#[test]
fn build_docker_run_args_keep_containers_omits_rm() {
    let spec = framework_core::ContainerSpec {
        image: "img".into(),
        docker_args: vec![],
        command: vec![],
        detached: false,
        timeout_secs: None,
    };
    let args = framework_core::build_docker_run_args(&spec, "n", /*keep*/ true);
    assert!(
        !args.contains(&"--rm".to_string()),
        "keep_containers=true should omit --rm: {args:?}"
    );
    assert!(args.contains(&"--name".to_string()));
}

#[test]
fn build_docker_run_args_timeout_wraps_command() {
    let spec = framework_core::ContainerSpec {
        image: "img".into(),
        docker_args: vec![],
        command: vec!["/inner".into(), "--flag".into()],
        detached: false,
        timeout_secs: Some(75),
    };
    let args = framework_core::build_docker_run_args(&spec, "n", false);
    // Find the image position, then assert timeout wraps after it.
    let img_idx = args.iter().position(|a| a == "img").unwrap();
    assert_eq!(
        &args[img_idx..img_idx + 4],
        &["img", "timeout", "--signal=KILL", "75"]
    );
    assert_eq!(&args[img_idx + 4..], &["/inner", "--flag"]);
}

#[test]
fn build_docker_run_args_no_timeout_no_wrap() {
    let spec = framework_core::ContainerSpec {
        image: "img".into(),
        docker_args: vec![],
        command: vec!["/inner".into()],
        detached: false,
        timeout_secs: None,
    };
    let args = framework_core::build_docker_run_args(&spec, "n", false);
    assert!(
        !args.contains(&"timeout".to_string()),
        "timeout_secs=None should not emit timeout: {args:?}"
    );
}

// ── select_fill_batch: class-based selector unit tests ──────────────
//
// Validates the two-class strategy (class 1: uncovered;
// class 2: failed-with-retries-left) against a synthetic database.
// Verifies the just-shipped behavior + would catch regressions
// (e.g. retries cap removed, class 2 always re-runs, passing-at-
// sha incorrectly re-selected).

fn mk_trial(name: &str) -> dashboard_store::FillCandidate {
    // Fill candidates carry a suite; tests that don't exercise suite
    // bucketing just use "fork".
    dashboard_store::FillCandidate {
        name: name.to_string(),
        suite: "fork",
    }
}

/// Set up a fresh dashboard sqlite at `tmp` with the canonical
/// SCHEMA_DDL applied and ONE `runs` row at the given commit_sha
/// (clean). Returns (db_path, run_id). Caller opens its own
/// Connection to pass to `select_fill_batch_inner`. For multiple
/// attempts at the same sha, call `insert_run_at` to get more
/// run_ids (each insert_result needs a unique run_id per
/// (test_id, pass) due to the table's PK).
fn setup_fill_db(tmp: &str, commit_sha: &str) -> (PathBuf, i64) {
    std::fs::create_dir_all(tmp).unwrap();
    let db = PathBuf::from(tmp).join("results.sqlite");
    let conn = Connection::open(&db).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "busy_timeout", 5000).unwrap();
    conn.execute_batch(dashboard_store::SCHEMA_DDL).unwrap();
    conn.execute(
        "INSERT INTO meta(key,value) VALUES('schema_version', ?1)",
        params![dashboard_store::SCHEMA_VERSION],
    )
    .unwrap();
    let run_id = insert_run_at(&conn, commit_sha, 1000);
    (db, run_id)
}

fn insert_run_at(conn: &Connection, commit_sha: &str, started_ts_ms: i64) -> i64 {
    conn.execute(
        "INSERT INTO runs(started_ts_ms, hostname, worktree_path, commit_sha, branch)
         VALUES (?1, 'host', '/wt', ?2, 'main')",
        params![started_ts_ms, commit_sha],
    )
    .unwrap();
    conn.last_insert_rowid()
}

fn insert_result(
    conn: &Connection,
    run_id: i64,
    test_id: &str,
    pass: &str,
    verdict: &str,
    finished_ts_ms: i64,
) {
    conn.execute(
        "INSERT INTO run_results(run_id, test_id, mode, verdict, finished_ts_ms,
                                 suite, \"group\",
                                 t_acquire_ms, t_docker_start_ms, t_useful_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, 'fork', 'fork_matrix', 0, 0, 100)",
        params![run_id, test_id, pass, verdict, finished_ts_ms],
    )
    .unwrap();
}

#[test]
fn select_fill_batch_class1_picks_uncovered() {
    let tmp = tempdir_marker("fillc1");
    let (db, run_id) = setup_fill_db(&tmp, "abc1234");
    let conn = Connection::open(&db).unwrap();

    let trials = vec![
        mk_trial("native::FOO.bar"),
        mk_trial("litebox::FOO.bar"),
        mk_trial("native::BAR.qux"),
    ];
    let picked = dashboard_store::select_fill_batch_inner(
        &conn,
        run_id,
        &trials,
        dashboard_store::FillCap::Count(10),
    );
    assert_eq!(
        picked.len(),
        3,
        "all uncovered trials should be picked: {picked:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn select_fill_batch_is_suite_agnostic() {
    // The selector no longer inspects the name shape — every provided
    // candidate is fillable (the vscode/copilot/dropbear suites run their
    // own closures now, not run_pass_group). Guards against a regression
    // where a name-prefix filter silently drops whole suites (which is
    // what made --fill-drain's old router panic / plateau).
    let tmp = tempdir_marker("fillsubns");
    let (db, run_id) = setup_fill_db(&tmp, "abc1234");
    let conn = Connection::open(&db).unwrap();

    let names = [
        "native::FOO.bar",
        "litebox::FOO.bar",
        "native::vscode::extension_host_spawn",
        "litebox::vscode::bootstrap",
        "native::copilot::tui.simple_math",
        "native::dropbear_bash.red_gate",
    ];
    let trials: Vec<_> = names.iter().map(|n| mk_trial(n)).collect();
    let picked = dashboard_store::select_fill_batch_inner(
        &conn,
        run_id,
        &trials,
        dashboard_store::FillCap::Count(100),
    );
    for n in names {
        assert!(
            picked.contains(&n.to_string()),
            "every never-run candidate should be picked (suite-agnostic): \
             {n} missing from {picked:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn select_fill_batch_skips_passing_at_current_sha() {
    let tmp = tempdir_marker("fillpass");
    let (db, run_id) = setup_fill_db(&tmp, "abc1234");
    let conn = Connection::open(&db).unwrap();
    insert_result(&conn, run_id, "FOO.bar", "native", "pass", 5000);

    let trials = vec![mk_trial("native::FOO.bar"), mk_trial("litebox::FOO.bar")];
    let picked = dashboard_store::select_fill_batch_inner(
        &conn,
        run_id,
        &trials,
        dashboard_store::FillCap::Count(10),
    );
    assert!(
        !picked.contains(&"native::FOO.bar".to_string()),
        "passing-at-sha should be skipped: {picked:?}"
    );
    assert!(
        picked.contains(&"litebox::FOO.bar".to_string()),
        "uncovered should be picked: {picked:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn select_fill_batch_class2_retries_failed_under_cap() {
    let tmp = tempdir_marker("fillretry");
    let (db, run_id) = setup_fill_db(&tmp, "abc1234");
    let conn = Connection::open(&db).unwrap();
    // Two attempts at the same sha → two separate run rows.
    insert_result(&conn, run_id, "FOO.bar", "native", "FAIL", 5000);
    let run2 = insert_run_at(&conn, "abc1234", 2000);
    insert_result(&conn, run2, "FOO.bar", "native", "FAIL", 6000);

    let trials = vec![mk_trial("native::FOO.bar")];
    let picked = dashboard_store::select_fill_batch_inner(
        &conn,
        run_id,
        &trials,
        dashboard_store::FillCap::Count(10),
    );
    assert!(
        picked.contains(&"native::FOO.bar".to_string()),
        "failed-at-sha with retries left should be picked: {picked:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn select_fill_batch_class2_caps_retries() {
    let tmp = tempdir_marker("fillcap");
    let (db, run_id) = setup_fill_db(&tmp, "abc1234");
    let conn = Connection::open(&db).unwrap();
    // Three attempts at same sha (== default cap).
    insert_result(&conn, run_id, "FOO.bar", "native", "FAIL", 5000);
    let run2 = insert_run_at(&conn, "abc1234", 2000);
    insert_result(&conn, run2, "FOO.bar", "native", "FAIL", 6000);
    let run3 = insert_run_at(&conn, "abc1234", 3000);
    insert_result(&conn, run3, "FOO.bar", "native", "FAIL", 7000);

    let trials = vec![mk_trial("native::FOO.bar")];
    let picked = dashboard_store::select_fill_batch_inner(
        &conn,
        run_id,
        &trials,
        dashboard_store::FillCap::Count(10),
    );
    assert!(
        !picked.contains(&"native::FOO.bar".to_string()),
        "attempts == cap should NOT be re-selected: {picked:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn select_fill_batch_class1_before_class2() {
    let tmp = tempdir_marker("fillorder");
    let (db, run_id) = setup_fill_db(&tmp, "abc1234");
    let conn = Connection::open(&db).unwrap();
    insert_result(&conn, run_id, "FOO.bar", "native", "FAIL", 5000);

    let trials = vec![mk_trial("native::FOO.bar"), mk_trial("native::BAR.qux")];
    let picked = dashboard_store::select_fill_batch_inner(
        &conn,
        run_id,
        &trials,
        dashboard_store::FillCap::Count(1),
    );
    assert_eq!(
        picked,
        vec!["native::BAR.qux".to_string()],
        "class 1 (uncovered) should drain before class 2 (failed): {picked:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn select_fill_batch_respects_retries_env() {
    let tmp = tempdir_marker("fillenvcap");
    let (db, run_id) = setup_fill_db(&tmp, "abc1234");
    let conn = Connection::open(&db).unwrap();
    insert_result(&conn, run_id, "FOO.bar", "native", "FAIL", 5000);
    let run2 = insert_run_at(&conn, "abc1234", 2000);
    insert_result(&conn, run2, "FOO.bar", "native", "FAIL", 6000);

    // LITEBOX_FILL_FAIL_RETRIES is a process-global env; each
    // env-sensitive test must set + restore. Tests that don't
    // touch this env see the default (3).
    unsafe { std::env::set_var("LITEBOX_FILL_FAIL_RETRIES", "2") };
    let trials = vec![mk_trial("native::FOO.bar")];
    let picked = dashboard_store::select_fill_batch_inner(
        &conn,
        run_id,
        &trials,
        dashboard_store::FillCap::Count(10),
    );
    unsafe { std::env::remove_var("LITEBOX_FILL_FAIL_RETRIES") };

    assert!(
        !picked.contains(&"native::FOO.bar".to_string()),
        "LITEBOX_FILL_FAIL_RETRIES=2 with 2 attempts → no re-select: {picked:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

fn tempdir_marker(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "litebox-dashboard-test-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir.to_string_lossy().into_owned()
}
