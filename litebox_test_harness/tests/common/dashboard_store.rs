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

pub const SCHEMA_VERSION: i64 = 3;

pub struct Ctx {
    pub run_id: i64,
    pub conn: Mutex<Connection>,
}

// None  -> uninitialized
// Some(None) -> opted out (LITEBOX_DASHBOARD_DIR="")
// Some(Some(_)) -> active context
#[allow(clippy::option_option)]
static CTX: OnceLock<Option<Ctx>> = OnceLock::new();

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    )
    .unwrap_or(0)
}

fn opted_out() -> bool {
    matches!(std::env::var("LITEBOX_DASHBOARD_DIR"), Ok(s) if s.is_empty())
}

fn resolve_state_dir() -> PathBuf {
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
/// **Loud-fail on schema_version mismatch.** No automatic wipe and
/// no silent skip — both are subtle data-loss bugs across
/// coordinating coding-agent sessions:
///
/// * Auto-wipe thrashes data on every alternation between sessions
///   built against different schema versions.
/// * Silent-skip leaves writes invisibly going into the void; the
///   session "works" but contributes nothing.
///
/// The remediation has to be explicit, so panic. The message names
/// the three valid actions: rebuild (other session catches up),
/// wipe (lose history but start fresh), or opt out
/// (`LITEBOX_DASHBOARD_DIR=""`).
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
    panic!(
        "dashboard: schema_version {existing} in the store does NOT \
         match this binary's {SCHEMA_VERSION}. No automatic recreate \
         — that would stomp on data from other coding-agent sessions \
         running against the shared store. Pick one:\n\
         \n\
         (1) Rebuild the other session's harness so it catches up to \
             schema_version {SCHEMA_VERSION} (recommended for bumps \
             being rolled out across sessions).\n\
         (2) `rm -rf <dashboard state dir>` (typically \
             <main-worktree>/.dashboard/) to start fresh (loses all \
             accumulated history).\n\
         (3) Set `LITEBOX_DASHBOARD_DIR=\"\"` in this binary's env to \
             opt out of dashboard writes entirely.\n\
         \n\
         Note: option (2) only helps if every other session that will \
         run cargo test against the same store is at the matching \
         schema_version, otherwise the next session to run will hit \
         the same mismatch."
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
        pass                  TEXT    NOT NULL,
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
        PRIMARY KEY (run_id, test_id, pass)
    );
    CREATE INDEX run_results_test_pass_ts
        ON run_results(test_id, pass, finished_ts_ms DESC);
    CREATE INDEX run_results_pass_verdict_ts
        ON run_results(pass, verdict, finished_ts_ms DESC);

    -- Config: one row per tracked ref → dedicated CI worktree.
    CREATE TABLE tracked_refs (
        ref         TEXT PRIMARY KEY,
        ci_worktree TEXT NOT NULL
    );

    -- "Freshest result per (test_id, pass)" — computed at query
    -- time. Producer just INSERTs into run_results; no UPSERT
    -- bookkeeping.
    CREATE VIEW latest_results AS
    SELECT rr.test_id, rr.pass, rr.verdict, rr.finished_ts_ms,
           rr.suite, rr."group", rr.run_id
      FROM run_results rr
      JOIN (
          SELECT test_id, pass, MAX(finished_ts_ms) AS max_ts
            FROM run_results
           GROUP BY test_id, pass
      ) latest
        ON latest.test_id = rr.test_id
       AND latest.pass   = rr.pass
       AND latest.max_ts = rr.finished_ts_ms;

    CREATE TABLE meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
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
    let commit_sha =
        git_capture(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let branch = git_capture(&["rev-parse", "--abbrev-ref", "HEAD"]);
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
            run_id, test_id, pass, verdict, finished_ts_ms, suite, \"group\",
            t_acquire_ms, t_docker_start_ms, t_docker_spawn_ms,
            t_litebox_init_ms, t_harness_load_ms, t_harness_args_ms,
            t_harness_dispatch_ms, t_useful_ms
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
         ON CONFLICT(run_id, test_id, pass) DO UPDATE SET
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
          WHERE run_id = ?2 AND test_id = ?3 AND pass = ?4",
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
           COALESCE(SUM(CASE WHEN verdict='FAIL' THEN 1 ELSE 0 END), 0)
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

/// Select trial *names* (e.g. `native::PIDF.spawn_and_open`) that
/// have no clean-state result at the current `commit_sha`,
/// capped by `cap`.
///
/// Priority order within the candidate set:
/// 1. Never seen anywhere (`latest_results` has no row).
/// 2. Stalest by `latest_results.finished_ts_ms` ascending.
/// 3. The rest, sorted alphabetically.
///
/// Within each band the candidates are interleaved by `suite`
/// (round-robin) so a slow family can't permanently starve fast
/// ones. Trial names that don't follow `<pass>::<id>` are
/// ignored (host::fwd, dropbear_bash trials, etc. — those are
/// out of scope for the autonomous fill).
pub fn select_fill_batch(trials: &[libtest_mimic::Trial], cap: FillCap) -> Vec<String> {
    let count_cap = match cap {
        FillCap::Count(n) => n,
        FillCap::BudgetSecs { .. } => usize::MAX, // budget-bound below
    };
    if count_cap == 0 {
        return Vec::new();
    }
    let Some(ctx) = ctx() else {
        // Dashboard disabled — return alphabetically, capped by count.
        return trials
            .iter()
            .take(count_cap)
            .map(|t| t.name().to_string())
            .collect();
    };
    let conn = ctx.conn.lock().expect("dashboard: conn lock");

    // The producer's own runs row records `commit_sha`; reuse it
    // so this works even when `git` is not on PATH at fill time.
    let commit_sha: String = conn
        .query_row(
            "SELECT commit_sha FROM runs WHERE run_id = ?1",
            params![ctx.run_id],
            |r| r.get(0),
        )
        .unwrap_or_default();

    let mut covered: std::collections::HashSet<String> = std::collections::HashSet::new();
    if !commit_sha.is_empty() {
        let mut stmt = conn
            .prepare(
                "SELECT rr.pass, rr.test_id
                   FROM run_results rr
                   JOIN runs r ON r.run_id = rr.run_id
                  WHERE r.commit_sha = ?1
                    AND r.dirty_hash IS NULL",
            )
            .expect("dashboard: prepare covered query");
        let rows = stmt
            .query_map(params![commit_sha], |r| {
                let pass: String = r.get(0)?;
                let id: String = r.get(1)?;
                Ok(format!("{pass}::{id}"))
            })
            .expect("dashboard: covered query");
        for row in rows.flatten() {
            covered.insert(row);
        }
    }

    // Pull per-(pass, id) staleness AND per-test wall-time cost so
    // we can prioritize within the candidate set and (for the
    // BudgetSecs cap) estimate accumulated cost.
    let mut stalest: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    let mut suites: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut costs: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT lr.pass, lr.test_id, lr.finished_ts_ms, lr.suite,
                        rr.t_useful_ms
                   FROM latest_results lr
                   JOIN run_results rr ON rr.run_id = lr.run_id
                                       AND rr.test_id = lr.test_id
                                       AND rr.pass    = lr.pass",
            )
            .expect("dashboard: prepare latest query");
        let rows = stmt
            .query_map([], |r| {
                let pass: String = r.get(0)?;
                let id: String = r.get(1)?;
                let ts: i64 = r.get(2)?;
                let suite: Option<String> = r.get(3)?;
                let cost: i64 = r.get(4)?;
                Ok((format!("{pass}::{id}"), ts, suite, cost))
            })
            .expect("dashboard: latest query");
        for row in rows.flatten() {
            stalest.insert(row.0.clone(), row.1);
            if let Some(s) = row.2 {
                suites.insert(row.0.clone(), s);
            }
            costs.insert(row.0, row.3);
        }
    }
    drop(conn);

    // Candidate set: trials that are <pass>::<id> shaped and not
    // already covered at current sha.
    let mut never_run: Vec<String> = Vec::new();
    let mut seen_before: Vec<(String, i64)> = Vec::new();
    for t in trials {
        let name = t.name().to_string();
        // Out-of-scope trial shapes (host::, dropbear_bash, copilot::)
        // are excluded — autonomous fill only drives the canonical
        // <pass>::<id> matrix.
        if !(name.starts_with("native::") || name.starts_with("litebox::")) {
            continue;
        }
        if covered.contains(&name) {
            continue;
        }
        match stalest.get(&name) {
            None => never_run.push(name),
            Some(ts) => seen_before.push((name, *ts)),
        }
    }
    seen_before.sort_by_key(|(_, ts)| *ts);

    // Suite-aware round-robin within each band.
    let mut ordered: Vec<String> = round_robin_by_suite(&never_run, &suites);
    let stalest_names: Vec<String> = seen_before.into_iter().map(|(n, _)| n).collect();
    ordered.extend(round_robin_by_suite(&stalest_names, &suites));

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
        let suite = suites
            .get(n)
            .cloned()
            .unwrap_or_else(|| infer_suite_from_name(n));
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

fn infer_suite_from_name(name: &str) -> String {
    // For never-run trials, latest_results has no row, so we
    // don't know the suite. Fall back to a coarse bucket based on
    // the test_id prefix (matches the `reg.test(suite, ...)` calls
    // in coordinator/*).
    let id = name
        .splitn(2, "::")
        .nth(1)
        .unwrap_or(name)
        .split('.')
        .next()
        .unwrap_or("");
    match id {
        "PIDF" | "PIDFI" | "PIFH" | "EV" | "PTY" | "SFD" => "vscode",
        "X" | "BSF" | "PIF" | "SXF" | "BASH" | "FWE" | "SK" => "fork",
        "PB" | "PN" | "PID" | "NPIPE" | "BPIPE" | "EPIPE" | "PXEOF" | "CWF" | "US6" | "P1" => {
            "xworker"
        }
        "EP" | "POLL" | "EPI" | "PROC" | "KP" | "KPX" => "matrix",
        "TCS" | "THC" | "TLB" | "XCONN" | "FKLC" | "PR" | "FT" => "stress",
        "SP" | "SC" | "TR" | "FR" | "BR" | "BRS" => "shell",
        "VS" | "CSM" => "vscode",
        "SOCKOPT" | "GSN" => "sockopt",
        _ => "other",
    }
    .to_string()
}

