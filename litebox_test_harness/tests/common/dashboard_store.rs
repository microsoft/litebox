//! Producer-side direct writes to the central dashboard sqlite store
//! consumed by `litebox_test_harness/scripts/dashboard.py`.
//!
//! On-disk path: `<main-worktree>/.dashboard/results.sqlite` by
//! default, resolved as `dirname(git rev-parse --git-common-dir)`.
//! Override via `LITEBOX_DASHBOARD_DIR` (absolute path). Set
//! `LITEBOX_DASHBOARD_DIR=""` (empty) to opt out explicitly.
//!
//! On by default. Loud-fail on misconfigured / unwritable paths —
//! no silent fallback. The empty-string opt-out is the only quiet
//! skip.
//!
//! Single shared `Mutex<rusqlite::Connection>` across libtest worker
//! threads, WAL + busy_timeout=5000. The producer just INSERTs into
//! `run_results`; `latest_results` is a sqlite VIEW maintained by
//! the schema itself, not an UPSERT path.
//!
//! Included via `#[path]` from both `tests/integration.rs` (the
//! producer call sites) and `tests/dashboard_store.rs` (the schema
//! smoke tests). Lives under `tests/common/` so cargo's
//! tests/*.rs auto-discovery doesn't try to compile it as its own
//! test binary — see `Cargo.toml`.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

/// Producer/consumer schema version. **DO NOT BUMP WITHOUT USER
/// CONFIRMATION.** A bump is a hard sync point across every coding
/// agent session running against the shared sqlite store — until
/// each session rebuilds their `litebox_test_harness` integration
/// binary, their `cargo test --test integration` runs will panic
/// in `init_schema` below. Coordination cost is real.
///
/// Acceptable reasons to bump (after asking):
///   * The on-disk shape genuinely changed (column added with no
///     default, column removed, type changed, table/view renamed).
/// Things that DON'T need a bump:
///   * Renderer-only changes in `scripts/dashboard.py`.
///   * Adding a new column with a usable default (NULL or sentinel).
///   * Adding indexes (the producer's `init_schema` doesn't notice).
///
/// When you do bump (with user approval), land the bump on the
/// amalgamation branch promptly so other sessions pick it up on
/// their next cargo run rather than panicking on an older meta.
pub const SCHEMA_VERSION: i64 = 4;

pub struct Ctx {
    pub run_id: i64,
    pub conn: Mutex<Connection>,
}

// None  -> uninitialized
// Some(None) -> opted out (LITEBOX_DASHBOARD_DIR="")
// Some(Some(_)) -> active context
#[allow(clippy::option_option)]
static CTX: OnceLock<Option<Ctx>> = OnceLock::new();

pub fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    )
    .unwrap_or(0)
}

pub fn opted_out() -> bool {
    matches!(std::env::var("LITEBOX_DASHBOARD_DIR"), Ok(s) if s.is_empty())
}

pub fn resolve_state_dir() -> PathBuf {
    if let Ok(env) = std::env::var("LITEBOX_DASHBOARD_DIR")
        && !env.is_empty()
    {
        return PathBuf::from(env);
    }
    // dirname(git rev-parse --git-common-dir) — same path from any
    // linked worktree.
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .output()
        .unwrap_or_else(|e| panic!("dashboard: git rev-parse failed: {e}"));
    if !out.status.success() {
        panic!(
            "dashboard: git rev-parse --git-common-dir failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let common = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let common_path = PathBuf::from(common);
    let main_wt = common_path.parent().unwrap_or_else(|| {
        panic!(
            "dashboard: cannot derive main worktree from git common dir: {}",
            common_path.display()
        )
    });
    main_wt.join(".dashboard")
}

fn git_capture(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Initialize the central store. Call once at the start of a
/// trial-executing test run (skip for `--list` mode).
///
/// Returns `Some(ctx)` when the dashboard is active, `None` when
/// the user opted out via `LITEBOX_DASHBOARD_DIR=""`. Panics on
/// any other filesystem / sqlite failure.
pub fn init() -> Option<&'static Ctx> {
    let stored = CTX.get_or_init(|| {
        if opted_out() {
            return None;
        }
        let dir = resolve_state_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| {
            panic!(
                "dashboard: cannot create state dir {}: {e}\n\
                 Set LITEBOX_DASHBOARD_DIR=\"\" to opt out explicitly.",
                dir.display()
            )
        });
        let db_path = dir.join("results.sqlite");
        let conn = Connection::open(&db_path)
            .unwrap_or_else(|e| panic!("dashboard: cannot open {}: {e}", db_path.display()));
        conn.pragma_update(None, "journal_mode", "WAL")
            .expect("dashboard: PRAGMA journal_mode=WAL");
        conn.pragma_update(None, "busy_timeout", 5000)
            .expect("dashboard: PRAGMA busy_timeout");
        init_schema(&conn);
        // Apply the additive leases-table DDL on every connection
        // (not just fresh DBs). Old harnesses don't touch this table
        // so we don't bump SCHEMA_VERSION when introducing it — the
        // IF NOT EXISTS handles the upgrade in place.
        conn.execute_batch(ENSURE_LEASES_DDL)
            .expect("dashboard: ensure harness_leases table");
        let run_id = insert_run_row(&conn);
        Some(Ctx {
            run_id,
            conn: Mutex::new(conn),
        })
    });
    stored.as_ref()
}

pub fn ctx() -> Option<&'static Ctx> {
    CTX.get().and_then(|o| o.as_ref())
}

/// Initialize the schema. Fresh DB (no `meta` table) → create
/// schema + stamp version. Existing DB at the same version → no-op.
///
/// **Loud-panic on schema_version mismatch.** No automatic wipe, no
/// silent skip — both are subtle data-loss bugs across coordinating
/// coding-agent sessions:
///
/// * Auto-wipe thrashes data on every alternation between sessions
///   built against different schema versions.
/// * Silent-skip leaves writes invisibly going into the void; the
///   session "works" but contributes nothing.
///
/// The remediation is **rebuild** so binary and store agree. Schema
/// bumps are coordinated by merging through the amalgamation; the
/// next time each session's cargo runs, it picks up the new schema
/// automatically.
fn init_schema(conn: &Connection) {
    let meta_exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !meta_exists {
        conn.execute_batch(SCHEMA_DDL)
            .expect("dashboard: schema init on fresh db");
        conn.execute(
            "INSERT INTO meta(key,value) VALUES('schema_version', ?1)",
            params![SCHEMA_VERSION],
        )
        .expect("dashboard: write schema_version");
        return;
    }
    let existing: i64 = conn
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if existing == SCHEMA_VERSION {
        return;
    }
    let direction = if existing > SCHEMA_VERSION {
        "this binary is OUT OF DATE — somebody else's session has \
         already bumped the schema. Pulling/merging in their \
         schema-bumping commit + rebuilding catches you up."
    } else {
        "this binary is NEWER — your session has a schema-bumping \
         commit that hasn't propagated to other sessions yet. \
         Landing it on wportnoy/vscode-server-in-litebox is what \
         lets the other sessions catch up, but that's a merge to the \
         amalgamation branch — don't do it without user sign-off."
    };
    panic!(
        "dashboard: schema_version mismatch — \
         store has {existing}, this binary expects {SCHEMA_VERSION}.\n\
         \n\
         {direction}\n\
         \n\
         Either way: this is a cross-session coordination problem; \
         consult with the user about how to proceed."
    );
}

/// The canonical dashboard schema. Three tables (`runs`,
/// `run_results`, `tracked_refs`), one view (`latest_results`),
/// one trivial key/value table (`meta` — only `schema_version`).
/// Producer writes facts; everything derived is a query.
///
/// NOT NULL discipline:
/// - `runs.commit_sha` / `worktree_path` / `hostname` /
///   `started_ts_ms` are always known at INSERT time → NOT NULL.
/// - `runs.finished_ts_ms` / `pass_count` / `fail_count` /
///   `universe_size` are set at end-of-main `finalize()`. NULL
///   means the run was interrupted before finishing.
/// - `runs.branch` is NULL on detached HEAD; `dirty_hash` is
///   NULL ⇔ clean (that's the predicate).
/// - `runs.jobs` reflects `LITEBOX_TEST_JOBS`; NULL when env
///   var unset.
/// - `run_results.suite` / `group` come from the in-process
///   registry (every test_id in `run_pass_group` is known) →
///   NOT NULL.
/// - `run_results.t_acquire_ms` / `t_docker_start_ms` /
///   `t_useful_ms` are always set by the producer → NOT NULL.
/// - Other `t_*_ms` come from optional `litebox_timing` markers
///   (some absent on native pass, some absent on early exit)
///   → nullable.
///
/// Exposed publicly so `tests/dashboard_store.rs` can apply the
/// same DDL when exercising the schema, and so `dashboard.py`
/// can be kept consistent against a single source of truth.
pub const SCHEMA_DDL: &str = r#"
    CREATE TABLE runs (
        run_id           INTEGER PRIMARY KEY AUTOINCREMENT,
        started_ts_ms    INTEGER NOT NULL,
        finished_ts_ms   INTEGER,
        hostname         TEXT    NOT NULL,
        worktree_path    TEXT    NOT NULL,
        commit_sha       TEXT    NOT NULL,
        branch           TEXT,
        -- dirty bit dropped: dirty_hash IS NOT NULL ⇔ tracked diff present
        dirty_hash       TEXT,
        jobs             INTEGER,
        cargo_argv       TEXT,
        universe_size    INTEGER,
        pass_count       INTEGER,
        fail_count       INTEGER
    );
    CREATE INDEX runs_commit ON runs(commit_sha);

    CREATE TABLE run_results (
        run_id                INTEGER NOT NULL REFERENCES runs(run_id),
        test_id               TEXT    NOT NULL,
        mode                  TEXT    NOT NULL,
        verdict               TEXT    NOT NULL,
        finished_ts_ms        INTEGER NOT NULL,
        suite                 TEXT    NOT NULL,
        "group"               TEXT    NOT NULL,
        t_acquire_ms          INTEGER NOT NULL,
        t_docker_start_ms     INTEGER NOT NULL,
        t_docker_spawn_ms     INTEGER,
        t_litebox_init_ms     INTEGER,
        t_harness_load_ms     INTEGER,
        t_harness_args_ms     INTEGER,
        t_harness_dispatch_ms INTEGER,
        t_useful_ms           INTEGER NOT NULL,
        t_drain_ms            INTEGER,
        PRIMARY KEY (run_id, test_id, mode)
    );
    CREATE INDEX run_results_test_pass_ts
        ON run_results(test_id, mode, finished_ts_ms DESC);
    CREATE INDEX run_results_pass_verdict_ts
        ON run_results(mode, verdict, finished_ts_ms DESC);

    -- Config: one row per tracked ref → dedicated CI worktree.
    CREATE TABLE tracked_refs (
        ref         TEXT PRIMARY KEY,
        ci_worktree TEXT NOT NULL
    );

    -- "Freshest result per (test_id, mode)" — computed at query
    -- time. Producer just INSERTs into run_results; no UPSERT
    -- bookkeeping.
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

    CREATE TABLE meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    -- Cross-session concurrency coordination. Each `cargo test
    -- --test integration` invocation inserts one row at startup and
    -- heartbeats it; deletes it on exit. Other live harnesses read
    -- the count to derive their dynamic dispatch cap (GLOBAL_CAP / N).
    -- See `tests/common/lease.rs` for the protocol.
    --
    -- The same `CREATE TABLE IF NOT EXISTS` is also kept in
    -- `ENSURE_LEASES_DDL` (separate const) so existing DBs created
    -- before this table existed get it added on first new-harness
    -- connection. Adding the table is purely additive — old harnesses
    -- don't read or write it — so no SCHEMA_VERSION bump is required.
    CREATE TABLE harness_leases (
        pid             INTEGER PRIMARY KEY,
        heartbeat_at_ms INTEGER NOT NULL
    );
"#;

/// Idempotent DDL to add the `harness_leases` table to a database
/// that was created by an older harness (predating the table). New
/// harnesses apply this on every connection. No SCHEMA_VERSION bump
/// is needed because old harnesses simply never read or write the
/// table (they fall back to uncoordinated dispatch).
pub const ENSURE_LEASES_DDL: &str = r#"
    CREATE TABLE IF NOT EXISTS harness_leases (
        pid             INTEGER PRIMARY KEY,
        heartbeat_at_ms INTEGER NOT NULL
    );
"#;

fn insert_run_row(conn: &Connection) -> i64 {
    let started_ts_ms = now_ms();
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let commit_sha = git_capture(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    // `git rev-parse --abbrev-ref HEAD` returns the literal string
    // "HEAD" when the worktree is in a detached-HEAD state. That's
    // a sentinel, not a real branch — recording it as the branch
    // name is misleading (it dominates the histogram and renders
    // as `branch=HEAD` in the dashboard).
    //
    // Prefer in order:
    //   1. `LITEBOX_DASHBOARD_REF` — set by `dashboard.py auto` to
    //      the tracked ref it just checked out. Most informative
    //      when the supervisor drove the run.
    //   2. The output of `--abbrev-ref` if it isn't the "HEAD"
    //      sentinel (i.e., the worktree is on a real branch).
    //   3. None — better to omit than to lie. The renderer can
    //      display "—" for missing branch.
    let branch = std::env::var("LITEBOX_DASHBOARD_REF")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| git_capture(&["rev-parse", "--abbrev-ref", "HEAD"]).filter(|s| s != "HEAD"));
    let worktree_path =
        git_capture(&["rev-parse", "--show-toplevel"]).unwrap_or_else(|| "unknown".to_string());
    let dirty_status = git_capture(&["status", "--porcelain"]).unwrap_or_default();
    let dirty_hash = if dirty_status.is_empty() {
        None
    } else {
        // sha256(git diff HEAD) — tracked changes only. Documented
        // as a coarse identifier, not an equality oracle (does not
        // cover untracked).
        git_capture(&["diff", "HEAD"]).map(|diff| {
            let mut h = Sha256::new();
            h.update(diff.as_bytes());
            format!("{:x}", h.finalize())
        })
    };
    let jobs: Option<i64> = std::env::var("LITEBOX_TEST_JOBS")
        .ok()
        .and_then(|s| s.parse().ok());
    let cargo_argv = serde_json::to_string(&std::env::args().collect::<Vec<_>>()).ok();

    conn.execute(
        "INSERT INTO runs (started_ts_ms, hostname, worktree_path, commit_sha, branch,
             dirty_hash, jobs, cargo_argv)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            started_ts_ms,
            hostname,
            worktree_path,
            commit_sha,
            branch,
            dirty_hash,
            jobs,
            cargo_argv,
        ],
    )
    .expect("dashboard: INSERT runs");
    i64::try_from(conn.last_insert_rowid()).unwrap_or(0)
}

/// Update `runs.universe_size` for the current run. Called after
/// trial enumeration so the renderer can show
/// "N covered of M known".
pub fn record_universe_size(n: i64) {
    let Some(ctx) = ctx() else {
        return;
    };
    let conn = ctx.conn.lock().expect("dashboard: conn lock");
    let _ = conn.execute(
        "UPDATE runs SET universe_size = ?1 WHERE run_id = ?2",
        params![n, ctx.run_id],
    );
}

/// Per-test timings. The three required fields (acquire / docker
/// start / useful) match the producer's call site, which always
/// has them. The rest come from optional `litebox_timing` markers
/// and may legitimately be absent on certain paths (e.g. native
/// pass has no shim_init marker).
#[derive(Clone, Copy)]
pub struct Timings {
    pub t_acquire_ms: u128,
    pub t_docker_start_ms: u128,
    pub t_useful_ms: u128,
    pub t_docker_spawn_ms: Option<u128>,
    pub t_litebox_init_ms: Option<u128>,
    pub t_harness_load_ms: Option<u128>,
    pub t_harness_args_ms: Option<u128>,
    pub t_harness_dispatch_ms: Option<u128>,
}

fn to_i64_opt(x: Option<u128>) -> Option<i64> {
    x.and_then(|v| i64::try_from(v).ok())
}

fn to_i64(x: u128) -> i64 {
    i64::try_from(x).unwrap_or(0)
}

/// Record a finished test result. INSERTs into the immutable
/// `run_results` table; the producer-side `latest_results` is a
/// VIEW so there's no separate UPSERT path. No-op when the
/// dashboard is disabled.
pub fn record_result(
    test_id: &str,
    pass: &str,
    verdict: &str,
    suite: &str,
    group: &str,
    timings: Timings,
) {
    let Some(ctx) = ctx() else {
        return;
    };
    let finished_ts_ms = now_ms();
    let conn = ctx.conn.lock().expect("dashboard: conn lock");
    let res = conn.execute(
        "INSERT INTO run_results (
            run_id, test_id, mode, verdict, finished_ts_ms, suite, \"group\",
            t_acquire_ms, t_docker_start_ms, t_docker_spawn_ms,
            t_litebox_init_ms, t_harness_load_ms, t_harness_args_ms,
            t_harness_dispatch_ms, t_useful_ms
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
         ON CONFLICT(run_id, test_id, mode) DO UPDATE SET
            verdict        = excluded.verdict,
            finished_ts_ms = excluded.finished_ts_ms,
            t_useful_ms    = excluded.t_useful_ms",
        params![
            ctx.run_id,
            test_id,
            pass,
            verdict,
            finished_ts_ms,
            suite,
            group,
            to_i64(timings.t_acquire_ms),
            to_i64(timings.t_docker_start_ms),
            to_i64_opt(timings.t_docker_spawn_ms),
            to_i64_opt(timings.t_litebox_init_ms),
            to_i64_opt(timings.t_harness_load_ms),
            to_i64_opt(timings.t_harness_args_ms),
            to_i64_opt(timings.t_harness_dispatch_ms),
            to_i64(timings.t_useful_ms),
        ],
    );
    if let Err(e) = res {
        eprintln!("dashboard: run_results insert failed for {test_id}/{pass}: {e}");
    }
    // No latest_results UPSERT — it's a VIEW now.
}

/// Update `t_drain_ms` on the existing `run_results` row.
pub fn record_drain(test_id: &str, pass: &str, t_drain_ms: u128) {
    let Some(ctx) = ctx() else {
        return;
    };
    let drain = i64::try_from(t_drain_ms).unwrap_or(0);
    let conn = ctx.conn.lock().expect("dashboard: conn lock");
    let res = conn.execute(
        "UPDATE run_results SET t_drain_ms = ?1
          WHERE run_id = ?2 AND test_id = ?3 AND mode = ?4",
        params![drain, ctx.run_id, test_id, pass],
    );
    if let Err(e) = res {
        eprintln!("dashboard: run_results drain update failed for {test_id}/{pass}: {e}");
    }
}

/// Finalize the `runs` row at end-of-main. Best-effort.
pub fn finalize() {
    let Some(ctx) = ctx() else {
        return;
    };
    let now = now_ms();
    let conn = ctx.conn.lock().expect("dashboard: conn lock");
    let counts: Result<(i64, i64), rusqlite::Error> = conn.query_row(
        "SELECT
           COALESCE(SUM(CASE WHEN verdict='pass' THEN 1 ELSE 0 END), 0),
           COALESCE(SUM(CASE WHEN verdict='fail' THEN 1 ELSE 0 END), 0)
         FROM run_results WHERE run_id = ?1",
        params![ctx.run_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    );
    let (pass_count, fail_count) = counts.unwrap_or((0, 0));
    let _ = conn.execute(
        "UPDATE runs SET finished_ts_ms=?1, pass_count=?2, fail_count=?3
          WHERE run_id=?4",
        params![now, pass_count, fail_count, ctx.run_id],
    );
}

/// How `select_fill_batch` decides where to stop.
///
/// `Count(N)` — pick up to N trials (hard cap).
///
/// `BudgetSecs { secs, jobs }` — keep adding trials until the
/// estimated wall time (sum of t_useful_ms / jobs) reaches `secs`.
/// Per-trial cost is read from the most recent `latest_results`
/// row; trials with no prior cost use `DEFAULT_TEST_COST_MS`.
pub enum FillCap {
    Count(usize),
    BudgetSecs { secs: u64, jobs: u64 },
}

/// Per-test wall-time estimate used by `BudgetSecs` when we have no
/// historical t_useful_ms for a trial. 5s is a reasonable median
/// for litebox docker-run + setup overhead on top of a small test.
const DEFAULT_TEST_COST_MS: u64 = 5_000;

/// Maximum number of attempts per (test_id, pass) at the current
/// clean sha before we stop re-running it. A persistently-failing
/// test gets confirmed after this many tries (likely a real
/// regression, not a flake); further re-runs would just churn.
///
/// Override via `LITEBOX_FILL_FAIL_RETRIES`.
const DEFAULT_FAIL_RETRIES: i64 = 3;

fn fail_retries_cap() -> i64 {
    std::env::var("LITEBOX_FILL_FAIL_RETRIES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_FAIL_RETRIES)
}

/// Select trial *names* (e.g. `native::PIDF.spawn_and_open`) for
/// the autonomous fill, capped by `cap`.
///
/// Selection bands, drained in order:
///
///   * **Class 1 — uncovered at current sha** (no `run_results`
///     row at the current clean `commit_sha`). The historical
///     default behavior: get basic coverage at the current state.
///     Within the band: never-seen-anywhere first, then
///     stalest-by-latest_results.finished_ts_ms. Round-robin by
///     suite so a slow family can't starve fast ones.
///   * **Class 2 — re-confirm fails at current sha**: trials
///     whose freshest verdict at the current clean sha is
///     non-pass AND fewer than `LITEBOX_FILL_FAIL_RETRIES`
///     (default 3) attempts have been recorded at this sha.
///     Ordered stalest-first within the sha (longest-ago last
///     attempt). After the cap is exhausted for a test, it's
///     considered confirmed-failing and stops being re-selected
///     (until the sha changes).
///
/// Trials that are covered + passing at the current sha are NOT
/// re-selected — the assumption is "pass at clean sha is stable
/// unless a new sha arrives." Drift detection (re-running passing
/// tests to catch silent rot) is a future class-3 expansion.
///
/// Every provided candidate is in scope — the caller
/// (`build_harness_trials`) already decides the fillable set (the whole
/// matrix + the vscode/copilot/dropbear suites). The selector only picks
/// *which* names to run next; it never inspects the name shape.
pub fn select_fill_batch(candidates: &[FillCandidate], cap: FillCap) -> Vec<String> {
    let count_cap = match cap {
        FillCap::Count(n) => n,
        FillCap::BudgetSecs { .. } => usize::MAX, // budget-bound below
    };
    if count_cap == 0 {
        return Vec::new();
    }
    let Some(ctx) = ctx() else {
        // Dashboard disabled — return in-order, capped by count.
        return candidates
            .iter()
            .take(count_cap)
            .map(|c| c.name.clone())
            .collect();
    };
    let conn = ctx.conn.lock().expect("dashboard: conn lock");
    select_fill_batch_inner(&conn, ctx.run_id, candidates, cap)
}

/// A fill-selection candidate: the identity a selector needs — the full
/// trial name and its suite (for round-robin fairness). Carrying the
/// suite explicitly is what lets the selector avoid ever guessing it from
/// the name. The runnable closure lives on the caller's `HarnessTrial`.
pub struct FillCandidate {
    pub name: String,
    pub suite: &'static str,
}

/// Test-friendly variant: takes the connection + run_id explicitly
/// instead of going through the process-singleton `ctx()`. The
/// real `select_fill_batch` is a thin wrapper around this; tests
/// bypass `ctx()` and call this directly with their own DB.
pub fn select_fill_batch_inner(
    conn: &Connection,
    run_id: i64,
    candidates: &[FillCandidate],
    cap: FillCap,
) -> Vec<String> {
    let count_cap = match cap {
        FillCap::Count(n) => n,
        FillCap::BudgetSecs { .. } => usize::MAX,
    };
    if count_cap == 0 {
        return Vec::new();
    }

    // The producer's own runs row records `commit_sha`; reuse it
    // so this works even when `git` is not on PATH at fill time.
    let commit_sha: String = conn
        .query_row(
            "SELECT commit_sha FROM runs WHERE run_id = ?1",
            params![run_id],
            |r| r.get(0),
        )
        .unwrap_or_default();

    // Per-(pass, test_id) at the current clean sha:
    //   attempts        — how many rows we have at this sha
    //   freshest_verdict — verdict of the most recent attempt
    //   freshest_ts     — finished_ts_ms of that attempt
    //                     (used as the "stalest-first" key in class 2)
    let mut at_sha: std::collections::HashMap<String, (i64, String, i64)> =
        std::collections::HashMap::new();
    if !commit_sha.is_empty() {
        let mut stmt = conn
            .prepare(
                "SELECT rr.mode, rr.test_id, rr.verdict, rr.finished_ts_ms
                   FROM run_results rr
                   JOIN runs r ON r.run_id = rr.run_id
                  WHERE r.commit_sha = ?1
                    AND r.dirty_hash IS NULL
                  ORDER BY rr.finished_ts_ms DESC",
            )
            .expect("dashboard: prepare at-sha query");
        let rows = stmt
            .query_map(params![commit_sha], |r| {
                let pass: String = r.get(0)?;
                let id: String = r.get(1)?;
                let verdict: String = r.get(2)?;
                let ts: i64 = r.get(3)?;
                Ok((format!("{pass}::{id}"), verdict, ts))
            })
            .expect("dashboard: at-sha query");
        for row in rows.flatten() {
            // Iteration is newest-first; the first row per name
            // captures the freshest verdict + ts. Subsequent rows
            // just bump the attempt counter.
            let e = at_sha
                .entry(row.0)
                .or_insert_with(|| (0, row.1.clone(), row.2));
            e.0 += 1;
        }
    }

    // Pull per-(pass, id) staleness AND per-test wall-time cost so
    // we can prioritize within the candidate set and (for the
    // BudgetSecs cap) estimate accumulated cost.
    let mut stalest: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    // Suite comes straight off the candidates — no DB round-trip and no
    // name-prefix guessing (the retired `infer_suite_from_name` table).
    let suites: std::collections::HashMap<String, String> = candidates
        .iter()
        .map(|c| (c.name.clone(), c.suite.to_string()))
        .collect();
    let mut costs: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT lr.mode, lr.test_id, lr.finished_ts_ms,
                        rr.t_useful_ms
                   FROM latest_results lr
                   JOIN run_results rr ON rr.run_id = lr.run_id
                                       AND rr.test_id = lr.test_id
                                       AND rr.mode    = lr.mode",
            )
            .expect("dashboard: prepare latest query");
        let rows = stmt
            .query_map([], |r| {
                let pass: String = r.get(0)?;
                let id: String = r.get(1)?;
                let ts: i64 = r.get(2)?;
                let cost: i64 = r.get(3)?;
                Ok((format!("{pass}::{id}"), ts, cost))
            })
            .expect("dashboard: latest query");
        for row in rows.flatten() {
            stalest.insert(row.0.clone(), row.1);
            costs.insert(row.0, row.2);
        }
    }

    // Class 1 (uncovered at current sha) and class 2 (covered but
    // freshest verdict is non-pass at current sha, with retries
    // remaining). Already-passing trials at current sha are
    // dropped from the candidate set.
    let retries_cap = fail_retries_cap();
    let mut class1_never_run: Vec<String> = Vec::new();
    let mut class1_seen_before: Vec<(String, i64)> = Vec::new();
    let mut class2: Vec<(String, i64)> = Vec::new();
    for c in candidates {
        let name = c.name.clone();
        match at_sha.get(&name) {
            None => match stalest.get(&name) {
                None => class1_never_run.push(name),
                Some(ts) => class1_seen_before.push((name, *ts)),
            },
            Some((attempts, verdict, freshest_ts)) => {
                if verdict == "pass" {
                    // Already passing at current sha — skip.
                    continue;
                }
                if *attempts >= retries_cap {
                    // Confirmed failing at current sha — stop
                    // re-running. Future sha will re-include.
                    continue;
                }
                class2.push((name, *freshest_ts));
            }
        }
    }
    class1_seen_before.sort_by_key(|(_, ts)| *ts);
    class2.sort_by_key(|(_, ts)| *ts);

    // Suite-aware round-robin within each band so a slow family
    // can't permanently starve fast ones. Class 1 drains first.
    let mut ordered: Vec<String> = round_robin_by_suite(&class1_never_run, &suites);
    let class1_stale: Vec<String> = class1_seen_before.into_iter().map(|(n, _)| n).collect();
    ordered.extend(round_robin_by_suite(&class1_stale, &suites));
    let class2_names: Vec<String> = class2.into_iter().map(|(n, _)| n).collect();
    ordered.extend(round_robin_by_suite(&class2_names, &suites));

    // Apply the cap.
    match cap {
        FillCap::Count(n) => {
            ordered.truncate(n);
        }
        FillCap::BudgetSecs { secs, jobs } => {
            let budget_ms = secs.saturating_mul(1000);
            let jobs = jobs.max(1);
            let mut accumulated_ms: u64 = 0;
            let mut keep_n = 0usize;
            for name in &ordered {
                let cost_ms = costs
                    .get(name)
                    .copied()
                    .map(|c| u64::try_from(c).unwrap_or(DEFAULT_TEST_COST_MS))
                    .unwrap_or(DEFAULT_TEST_COST_MS);
                // Wall-time contribution under parallelism `jobs`.
                accumulated_ms += cost_ms / jobs;
                keep_n += 1;
                if accumulated_ms >= budget_ms {
                    break;
                }
            }
            ordered.truncate(keep_n);
        }
    }
    ordered
}

fn round_robin_by_suite(
    names: &[String],
    suites: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let mut buckets: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for n in names {
        // Every candidate carries its suite, so the map is complete;
        // "other" is only a defensive default.
        let suite = suites
            .get(n)
            .cloned()
            .unwrap_or_else(|| "other".to_string());
        buckets.entry(suite).or_default().push(n.clone());
    }
    let mut out: Vec<String> = Vec::with_capacity(names.len());
    loop {
        let mut progressed = false;
        for (_, v) in buckets.iter_mut() {
            if let Some(first) = v.pop() {
                out.push(first);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    // `pop` returns from the end, so we built suite-stable
    // reverse-alphabetic order; reverse to get stable forward.
    out.reverse();
    out
}
