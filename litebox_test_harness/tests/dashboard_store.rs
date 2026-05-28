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
            "INSERT INTO run_results(run_id, test_id, pass, verdict, finished_ts_ms,
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
              WHERE test_id='X.id' AND pass='native'",
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

fn tempdir_marker(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "litebox-dashboard-test-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir.to_string_lossy().into_owned()
}
