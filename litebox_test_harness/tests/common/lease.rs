// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Cross-session concurrency coordination via the shared dashboard
//! sqlite.
//!
//! Every `cargo test --test integration` invocation passes through
//! the harness binary, so the harness is a universal coordination
//! point: each invocation registers a tiny lease (just its `pid` and
//! a heartbeat), and reads the count of live peers to size its own
//! dispatch cap as `GLOBAL_CAP / live_lease_count`.
//!
//! Design choices ("simple and elegant"):
//!
//!   * Minimal table: `(pid, heartbeat_at_ms)`. No `is_bot`, no
//!     `worktree`, no per-harness jobs claim. The cap is derived
//!     dynamically from peer count, not negotiated.
//!   * Continuous rebalancing. `live_lease_count` is cached in a
//!     static `AtomicUsize` refreshed by the heartbeat thread every
//!     ~5 s. The dispatch gate reads the atomic on each acquire, so
//!     when peers come or go our cap floats automatically.
//!   * Additive table → no `SCHEMA_VERSION` bump. Old harnesses
//!     ignore the table (uncoordinated fallback = today's
//!     behavior); new harnesses cooperate.
//!   * Loud-fail forbidden. Every error path here logs and falls
//!     through with sane defaults. The lease layer must never block
//!     the test run.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use rusqlite::{Connection, params};

// `dashboard_store` is `#[path]`-included by the same test binary
// that includes this module (see `tests/integration.rs`), so it
// lives at `crate::dashboard_store` for us.
use crate::dashboard_store;

const HEARTBEAT_INTERVAL_SECS: u64 = 10;
const STALE_THRESHOLD_MS: i64 = 30_000;

static LIVE_LEASES: AtomicUsize = AtomicUsize::new(1);
static REGISTERED: OnceLock<Registered> = OnceLock::new();

struct Registered {
    db_path: PathBuf,
    pid: i64,
}

fn open_conn(db_path: &PathBuf) -> Option<Connection> {
    let conn = Connection::open(db_path).ok()?;
    conn.pragma_update(None, "journal_mode", "WAL").ok()?;
    conn.pragma_update(None, "busy_timeout", 5000).ok()?;
    Some(conn)
}

fn refresh_live_count(conn: &Connection) -> usize {
    let cutoff = dashboard_store::now_ms() - STALE_THRESHOLD_MS;
    // Prune stale rows opportunistically. Best-effort.
    let _ = conn.execute(
        "DELETE FROM harness_leases WHERE heartbeat_at_ms < ?1",
        params![cutoff],
    );
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM harness_leases WHERE heartbeat_at_ms >= ?1",
            params![cutoff],
            |r| r.get(0),
        )
        .unwrap_or(0);
    // Floor at 1 — we're always at least counting ourselves once
    // registered. Treats the startup race (other harnesses have
    // registered but we haven't yet) as "I'm the only one" which is
    // safe-on-the-optimistic-side; new peers will be picked up at
    // the next refresh.
    let n = usize::try_from(n.max(1)).unwrap_or(1);
    LIVE_LEASES.store(n, Ordering::Relaxed);
    n
}

/// Number of live peer harnesses, as last refreshed by the
/// heartbeat thread (every `HEARTBEAT_INTERVAL_SECS`). Defaults to
/// 1 before any refresh has happened.
pub fn live_lease_count() -> usize {
    LIVE_LEASES.load(Ordering::Relaxed).max(1)
}

/// Register the current process as a live harness. Spawns a
/// background heartbeat thread held alive for the lifetime of the
/// process. Idempotent — second call is a no-op.
///
/// Any error in registration is logged and silently absorbed; the
/// caller proceeds with uncoordinated defaults (today's behavior).
pub fn register() {
    if REGISTERED.get().is_some() {
        return;
    }
    if dashboard_store::opted_out() {
        return;
    }
    let dir = dashboard_store::resolve_state_dir();
    let db_path = dir.join("results.sqlite");
    if !db_path.exists() {
        // No dashboard store yet; the producer's `init()` is what
        // creates it. If it hasn't run, we silently skip — no harm.
        return;
    }
    let Some(conn) = open_conn(&db_path) else {
        eprintln!("[lease] open_conn failed; proceeding uncoordinated");
        return;
    };
    let pid = i64::from(std::process::id());
    let now = dashboard_store::now_ms();
    if let Err(e) = conn.execute(
        "INSERT OR REPLACE INTO harness_leases(pid, heartbeat_at_ms) VALUES (?1, ?2)",
        params![pid, now],
    ) {
        eprintln!("[lease] INSERT failed: {e}; proceeding uncoordinated");
        return;
    }
    refresh_live_count(&conn);
    let reg = Registered {
        db_path: db_path.clone(),
        pid,
    };
    if REGISTERED.set(reg).is_err() {
        return; // raced; the other call will spawn the heartbeat.
    }
    thread::Builder::new()
        .name("lease-heartbeat".into())
        .spawn(move || heartbeat_loop(db_path, pid))
        .unwrap_or_else(|e| {
            eprintln!("[lease] heartbeat thread spawn failed: {e}");
            // Return a dummy handle by re-spawning a noop.
            thread::spawn(|| {})
        });
}

fn heartbeat_loop(db_path: PathBuf, pid: i64) {
    let interval = Duration::from_secs(HEARTBEAT_INTERVAL_SECS);
    loop {
        thread::sleep(interval);
        let Some(conn) = open_conn(&db_path) else {
            continue;
        };
        let now = dashboard_store::now_ms();
        let _ = conn.execute(
            "UPDATE harness_leases SET heartbeat_at_ms = ?1 WHERE pid = ?2",
            params![now, pid],
        );
        refresh_live_count(&conn);
    }
}

/// Delete our lease row. Called from cleanup paths (signal handler
/// + normal exit). Best-effort; errors logged and ignored.
pub fn deregister() {
    let Some(reg) = REGISTERED.get() else {
        return;
    };
    let Some(conn) = open_conn(&reg.db_path) else {
        return;
    };
    let _ = conn.execute(
        "DELETE FROM harness_leases WHERE pid = ?1",
        params![reg.pid],
    );
}
