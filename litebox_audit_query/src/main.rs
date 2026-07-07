// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! CLI tool for importing and querying litebox audit logs.
//!
//! Imports JSONL audit logs into a SQLite database, joining enter/exit
//! events by `(seq, worker)` into a single `syscalls` table. The coding
//! agent can then run ad-hoc SQL queries against the structured data.
//!
//! # Usage
//!
//! ```sh
//! # Import a JSONL audit log into SQLite
//! litebox_audit_query import audit.jsonl
//!
//! # Run a SQL query
//! litebox_audit_query sql --db audit.db "SELECT syscall, COUNT(*) FROM syscalls GROUP BY syscall"
//!
//! # Auto-import + query in one step
//! litebox_audit_query sql --file audit.jsonl "SELECT * FROM syscalls WHERE result_err IS NOT NULL"
//!
//! # Print schema and example queries
//! litebox_audit_query schema
//! ```

use clap::{Parser, Subcommand};
use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

mod tree;
mod watch;

#[derive(Parser)]
#[command(name = "litebox_audit_query")]
#[command(about = "Import and query litebox audit logs via SQLite")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Import a JSONL audit log into a SQLite database.
    Import {
        /// Path to the JSONL audit log file.
        file: PathBuf,
        /// Output database path (default: <file>.db).
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Run a SQL query against an imported audit database.
    Sql {
        /// SQL query to execute.
        query: String,
        /// Path to the SQLite database.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Path to a JSONL file to auto-import if the database is missing or stale.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Output format.
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },
    /// Print the database schema and example queries.
    Schema,
    /// Live-tail an audit log (JSONL), pretty-printing events with color.
    ///
    /// The cross-platform replacement for the legacy PowerShell audit viewers.
    Watch {
        /// Path to a JSONL audit log file, or a directory (the most recent
        /// `*.jsonl` file within it is used).
        path: PathBuf,
        /// Render a live-updating "frontier" tree (allowed vs denied
        /// filesystem paths and network endpoints) instead of a line log.
        #[arg(long)]
        tree: bool,
        /// Print existing content and exit instead of following the file.
        #[arg(long)]
        no_follow: bool,
        /// Show only broker policy events (tcp/udp/fs/dns/policy), hiding the
        /// per-syscall stream.
        #[arg(long)]
        policy_only: bool,
        /// Only show syscall events whose name contains this substring.
        #[arg(long)]
        filter: Option<String>,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Table,
    Csv,
    Json,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Import { file, db } => {
            let db_path = db.unwrap_or_else(|| default_db_path(&file));
            match import(&file, &db_path) {
                Ok(stats) => {
                    eprintln!(
                        "Imported {} events ({} enter, {} exit, {} orphaned) into {}",
                        stats.total_lines,
                        stats.enter_count,
                        stats.exit_count,
                        stats.orphan_count,
                        db_path.display()
                    );
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Sql {
            query,
            db,
            file,
            format,
        } => {
            let db_path = match (&db, &file) {
                (Some(db), _) => db.clone(),
                (None, Some(f)) => {
                    let db_path = default_db_path(f);
                    if should_reimport(f, &db_path) {
                        eprintln!("Auto-importing {} ...", f.display());
                        if let Err(e) = import(f, &db_path) {
                            eprintln!("Import error: {e}");
                            std::process::exit(1);
                        }
                    }
                    db_path
                }
                (None, None) => {
                    eprintln!("Error: provide --db or --file");
                    std::process::exit(1);
                }
            };
            if let Err(e) = run_sql(&db_path, &query, &format) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::Schema => print_schema(),
        Commands::Watch {
            path,
            tree,
            no_follow,
            policy_only,
            filter,
        } => {
            if let Err(e) = watch::run(&path, !no_follow, tree, policy_only, filter.as_deref()) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn default_db_path(jsonl_path: &Path) -> PathBuf {
    jsonl_path.with_extension("db")
}

fn should_reimport(jsonl_path: &Path, db_path: &Path) -> bool {
    if !db_path.exists() {
        return true;
    }
    // Reimport if the JSONL is newer than the database.
    let jsonl_modified = std::fs::metadata(jsonl_path)
        .and_then(|m| m.modified())
        .ok();
    let db_modified = std::fs::metadata(db_path).and_then(|m| m.modified()).ok();
    match (jsonl_modified, db_modified) {
        (Some(j), Some(d)) => j > d,
        _ => true,
    }
}

// ─── Schema ──────────────────────────────────────────────────────────

const CREATE_TABLE: &str = "\
CREATE TABLE syscalls (
    seq         INTEGER NOT NULL,
    worker      INTEGER NOT NULL,
    host_tid    INTEGER NOT NULL,
    pid         INTEGER NOT NULL,
    tid         INTEGER NOT NULL,
    syscall     TEXT NOT NULL,
    args        TEXT NOT NULL,
    enter_ts    INTEGER NOT NULL,
    exit_ts     INTEGER,
    duration_ns INTEGER,
    result_ok   INTEGER,
    result_err  INTEGER,
    pending_ns  INTEGER,
    PRIMARY KEY (seq, worker)
)";

const CREATE_INDEXES: &str = "\
CREATE INDEX idx_syscall ON syscalls(syscall);
CREATE INDEX idx_errors ON syscalls(result_err) WHERE result_err IS NOT NULL;
CREATE INDEX idx_worker_seq ON syscalls(worker, seq)";

// ─── Import ──────────────────────────────────────────────────────────

struct ImportStats {
    total_lines: usize,
    enter_count: usize,
    exit_count: usize,
    orphan_count: usize,
}

/// Parsed entry event, held until its matching exit arrives.
struct PendingEntry {
    seq: i64,
    worker: i64,
    host_tid: i64,
    pid: i64,
    tid: i64,
    syscall: String,
    args: String,
    enter_ts: i64,
}

/// Batch size for periodic commits during import. Keeps the WAL file
/// bounded and provides progress feedback on large logs.
const IMPORT_BATCH_SIZE: usize = 100_000;

fn import(jsonl_path: &Path, db_path: &Path) -> Result<ImportStats, String> {
    let file = std::fs::File::open(jsonl_path)
        .map_err(|e| format!("open {}: {e}", jsonl_path.display()))?;
    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let reader = BufReader::with_capacity(256 * 1024, file);

    // Remove stale database to start fresh.
    if db_path.exists() {
        std::fs::remove_file(db_path).map_err(|e| format!("remove {}: {e}", db_path.display()))?;
    }

    let conn =
        Connection::open(db_path).map_err(|e| format!("open db {}: {e}", db_path.display()))?;

    // Performance: WAL mode + relaxed sync for bulk import.
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=OFF; PRAGMA cache_size=-65536")
        .map_err(|e| format!("set pragmas: {e}"))?;

    // Create schema without indexes — add them after bulk insert.
    conn.execute_batch(CREATE_TABLE)
        .map_err(|e| format!("create table: {e}"))?;

    // Pending enter events keyed by (seq, worker).
    let mut pending: HashMap<(i64, i64), PendingEntry> = HashMap::new();
    let mut stats = ImportStats {
        total_lines: 0,
        enter_count: 0,
        exit_count: 0,
        orphan_count: 0,
    };

    let start_time = std::time::Instant::now();
    let mut rows_inserted: usize = 0;
    let mut bytes_read: u64 = 0;

    conn.execute_batch("BEGIN")
        .map_err(|e| format!("begin: {e}"))?;

    let insert_sql = "INSERT INTO syscalls \
         (seq, worker, host_tid, pid, tid, syscall, args, enter_ts, exit_ts, duration_ns, result_ok, result_err) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

    {
        let mut insert_stmt = conn
            .prepare(insert_sql)
            .map_err(|e| format!("prepare insert: {e}"))?;

        for line_result in reader.lines() {
            let line = line_result.map_err(|e| format!("read line: {e}"))?;
            bytes_read += line.len() as u64 + 1; // +1 for newline
            let trimmed = line.trim();

            // Skip blank lines, comments, and non-JSON header lines.
            if trimmed.is_empty() || !trimmed.starts_with('{') {
                continue;
            }

            let v: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue, // skip malformed lines
            };

            stats.total_lines += 1;

            let phase = v["phase"].as_str().unwrap_or("");
            let seq = v["seq"].as_i64().unwrap_or(0);
            let worker = v["worker"].as_i64().unwrap_or(0);
            let host_tid = v["host_tid"].as_i64().unwrap_or(0);
            let pid = v["pid"].as_i64().unwrap_or(0);
            let tid = v["tid"].as_i64().unwrap_or(0);
            let ts = v["ts"].as_i64().unwrap_or(0);
            let syscall = v["syscall"].as_str().unwrap_or("unknown").to_string();

            match phase {
                "enter" => {
                    stats.enter_count += 1;
                    let args = v["args"].to_string();
                    pending.insert(
                        (seq, worker),
                        PendingEntry {
                            seq,
                            worker,
                            host_tid,
                            pid,
                            tid,
                            syscall,
                            args,
                            enter_ts: ts,
                        },
                    );
                }
                "exit" => {
                    stats.exit_count += 1;
                    let (result_ok, result_err) = parse_result(&v["result"]);

                    if let Some(entry) = pending.remove(&(seq, worker)) {
                        // Matched enter+exit → full row.
                        let duration = ts - entry.enter_ts;
                        insert_stmt
                            .execute(params![
                                entry.seq,
                                entry.worker,
                                entry.host_tid,
                                entry.pid,
                                entry.tid,
                                entry.syscall,
                                entry.args,
                                entry.enter_ts,
                                ts,
                                duration,
                                result_ok,
                                result_err,
                            ])
                            .map_err(|e| format!("insert matched: {e}"))?;
                        rows_inserted += 1;
                    } else {
                        stats.orphan_count += 1;
                    }
                }
                _ => {}
            }

            // Periodic commit + progress report.
            if rows_inserted > 0 && rows_inserted % IMPORT_BATCH_SIZE == 0 {
                // Drop the borrow on `conn` held by `insert_stmt` by
                // finishing the batch inside the prepared statement's scope
                // would require restructuring. Instead, just report progress
                // — the single transaction is fine for performance since we
                // set WAL + synchronous=OFF.
                let elapsed = start_time.elapsed().as_secs_f64();
                let rate = rows_inserted as f64 / elapsed;
                let pct = if file_size > 0 {
                    format!(" {:.0}%", bytes_read as f64 / file_size as f64 * 100.0)
                } else {
                    String::new()
                };
                eprintln!("  {rows_inserted:>12} rows ({elapsed:.0}s, {rate:.0}/s{pct})");
            }
        }
    }

    // Insert orphaned enter events (syscall never returned).
    {
        let mut insert_orphan = conn
            .prepare(
                "INSERT INTO syscalls \
                 (seq, worker, host_tid, pid, tid, syscall, args, enter_ts, exit_ts, duration_ns, result_ok, result_err) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, NULL, NULL)",
            )
            .map_err(|e| format!("prepare orphan: {e}"))?;

        for entry in pending.values() {
            stats.orphan_count += 1;
            insert_orphan
                .execute(params![
                    entry.seq,
                    entry.worker,
                    entry.host_tid,
                    entry.pid,
                    entry.tid,
                    entry.syscall,
                    entry.args,
                    entry.enter_ts,
                ])
                .map_err(|e| format!("insert orphan: {e}"))?;
            rows_inserted += 1;
        }
    }

    conn.execute_batch("COMMIT")
        .map_err(|e| format!("commit: {e}"))?;

    // Build indexes after bulk insert (much faster than maintaining
    // them during insert).
    eprintln!("  building indexes...");
    conn.execute_batch(CREATE_INDEXES)
        .map_err(|e| format!("create indexes: {e}"))?;

    // Restore normal durability for subsequent queries.
    conn.execute_batch("PRAGMA synchronous=NORMAL")
        .map_err(|e| format!("restore sync: {e}"))?;

    // Fill pending_ns for orphan rows: how long the syscall had been
    // in-flight when logging stopped. Lets agents distinguish genuinely
    // hung syscalls (large pending_ns) from shutdown-interrupted ones
    // (small pending_ns near the end of the log).
    if stats.orphan_count > 0 {
        conn.execute(
            "UPDATE syscalls SET pending_ns = \
             (SELECT MAX(COALESCE(exit_ts, enter_ts)) FROM syscalls) - enter_ts \
             WHERE exit_ts IS NULL",
            [],
        )
        .map_err(|e| format!("fill pending_ns: {e}"))?;
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    eprintln!(
        "  done: {rows_inserted} rows in {elapsed:.1}s ({:.0}/s)",
        rows_inserted as f64 / elapsed
    );

    Ok(stats)
}

fn parse_result(v: &serde_json::Value) -> (Option<i64>, Option<i64>) {
    if let Some(ok) = v.get("ok").and_then(|v| v.as_i64()) {
        (Some(ok), None)
    } else if let Some(err) = v.get("err").and_then(|v| v.as_i64()) {
        (None, Some(err))
    } else {
        (None, None)
    }
}

// ─── SQL ─────────────────────────────────────────────────────────────

fn run_sql(db_path: &Path, query: &str, format: &OutputFormat) -> Result<(), String> {
    let conn =
        Connection::open(db_path).map_err(|e| format!("open db {}: {e}", db_path.display()))?;
    let mut stmt = conn.prepare(query).map_err(|e| format!("prepare: {e}"))?;

    let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let col_count = col_names.len();

    let rows: Vec<Vec<String>> = stmt
        .query_map([], |row| {
            let mut vals = Vec::with_capacity(col_count);
            for i in 0..col_count {
                let val: rusqlite::Result<String> = row.get::<_, String>(i).or_else(|_| {
                    row.get::<_, i64>(i)
                        .map(|v| v.to_string())
                        .or_else(|_| row.get::<_, f64>(i).map(|v| v.to_string()))
                        .or_else(|_| Ok("NULL".to_string()))
                });
                vals.push(val.unwrap_or_else(|_| "NULL".to_string()));
            }
            Ok(vals)
        })
        .map_err(|e| format!("query: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("fetch: {e}"))?;

    match format {
        OutputFormat::Table => print_table(&col_names, &rows),
        OutputFormat::Csv => print_csv(&col_names, &rows),
        OutputFormat::Json => print_json(&col_names, &rows),
    }

    Ok(())
}

fn print_table(cols: &[String], rows: &[Vec<String>]) {
    if cols.is_empty() {
        return;
    }

    // Calculate column widths.
    let mut widths: Vec<usize> = cols.iter().map(|c| c.len()).collect();
    for row in rows {
        for (i, val) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(val.len());
            }
        }
    }

    // Header.
    let header: Vec<String> = cols
        .iter()
        .zip(&widths)
        .map(|(c, w)| format!("{c:<w$}"))
        .collect();
    println!("{}", header.join(" | "));
    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", sep.join("-+-"));

    // Rows.
    for row in rows {
        let formatted: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(v, w)| format!("{v:<w$}"))
            .collect();
        println!("{}", formatted.join(" | "));
    }

    eprintln!("\n({} rows)", rows.len());
}

fn print_csv(cols: &[String], rows: &[Vec<String>]) {
    println!("{}", cols.join(","));
    for row in rows {
        println!("{}", row.join(","));
    }
}

fn print_json(cols: &[String], rows: &[Vec<String>]) {
    for row in rows {
        let obj: serde_json::Map<String, serde_json::Value> = cols
            .iter()
            .zip(row)
            .map(|(k, v)| {
                let val = if v == "NULL" {
                    serde_json::Value::Null
                } else if let Ok(n) = v.parse::<i64>() {
                    serde_json::Value::Number(n.into())
                } else {
                    serde_json::Value::String(v.clone())
                };
                (k.clone(), val)
            })
            .collect();
        println!("{}", serde_json::to_string(&obj).unwrap_or_default());
    }
}

// ─── Schema ──────────────────────────────────────────────────────────

fn print_schema() {
    println!(
        r#"=== litebox_audit_query schema ===

{CREATE_TABLE};

{CREATE_INDEXES};

Column reference:
  seq         - Monotonic sequence number (unique per worker)          NOT NULL
  worker      - Host OS PID of the runner process                      NOT NULL
  host_tid    - Host OS TID that emitted the audit event                NOT NULL
  pid         - Guest virtual PID                                      NOT NULL
  tid         - Guest virtual TID (important for Node.js worker threads) NOT NULL
  syscall     - Canonical snake_case Linux syscall name (e.g. "openat",      NOT NULL
                "read", "connect", "eventfd2", "pidfd_open", "rt_sigprocmask").
                "unknown" is used only if a new SyscallRequest variant is
                added in the shim without updating syscall_canonical_name.
  args        - JSON array of arguments from the entry event           NOT NULL
  enter_ts    - Monotonic nanoseconds at syscall entry                  NOT NULL
  exit_ts     - Monotonic nanoseconds at syscall exit (NULL if never returned)
  duration_ns - exit_ts - enter_ts (NULL if never returned)
  result_ok   - Value from {{"ok": N}} on success (NULL on error or no exit)
  result_err  - Value from {{"err": N}} = negated errno on failure (NULL on success)
  pending_ns  - For orphans only: log_end_ts - enter_ts (NULL for completed syscalls)
                Small = interrupted by shutdown. Large = potentially hung/deadlocked.

Error codes: result_err is the negated errno, e.g.:
  -2  = ENOENT (No such file or directory)
  -13 = EACCES (Permission denied)
  -38 = ENOSYS (Function not implemented)
  -11 = EAGAIN (Resource temporarily unavailable)
  -4  = EINTR  (Interrupted system call)
  -22 = EINVAL (Invalid argument)
  -25 = ENOTTY (Inappropriate ioctl for device)

=== Example queries ===

-- Top 20 slowest syscalls
SELECT syscall, seq, worker, host_tid, pid, tid, duration_ns/1000 AS duration_us, args
FROM syscalls ORDER BY duration_ns DESC LIMIT 20;

-- Error distribution by syscall
SELECT syscall, result_err, COUNT(*) AS cnt
FROM syscalls WHERE result_err IS NOT NULL
GROUP BY syscall, result_err ORDER BY cnt DESC;

-- Incomplete syscalls: pending_ns distinguishes hung from shutdown-interrupted.
-- Large pending_ns (seconds+) = potentially hung. Small = interrupted by shutdown.
SELECT syscall, args, worker, host_tid, pid, tid, pending_ns/1000000 AS pending_ms
FROM syscalls WHERE exit_ts IS NULL ORDER BY pending_ns DESC;

-- Per-syscall timing summary (count, min, avg, max in microseconds)
SELECT syscall,
       COUNT(*) AS cnt,
       MIN(duration_ns)/1000 AS min_us,
       AVG(duration_ns)/1000 AS avg_us,
       MAX(duration_ns)/1000 AS max_us
FROM syscalls WHERE duration_ns IS NOT NULL
GROUP BY syscall ORDER BY max_us DESC;

-- All errors for a specific worker
SELECT seq, syscall, args, result_err, duration_ns/1000 AS us
FROM syscalls WHERE worker = 42 AND result_err IS NOT NULL
ORDER BY seq;

-- Timeline of a specific process
SELECT seq, syscall, result_ok, result_err, duration_ns/1000 AS us
FROM syscalls WHERE worker = 42 AND pid = 9
ORDER BY enter_ts;

-- File operations that failed
SELECT seq, worker, host_tid, pid, syscall, args, result_err
FROM syscalls
WHERE syscall IN ('openat', 'read', 'write', 'close', 'unlinkat', 'mkdir')
  AND result_err IS NOT NULL
ORDER BY enter_ts;

-- Network syscalls
SELECT seq, worker, host_tid, pid, syscall, args, result_ok, result_err, duration_ns/1000 AS us
FROM syscalls
WHERE syscall IN ('socket', 'connect', 'bind', 'listen', 'accept')
ORDER BY enter_ts;

-- ENOSYS errors (unimplemented syscalls)
SELECT syscall, args, COUNT(*) AS cnt
FROM syscalls WHERE result_err = -38
GROUP BY syscall, args ORDER BY cnt DESC;

-- Concurrent syscalls across threads (same pid, different tid)
SELECT a.syscall AS syscall_a, a.tid AS tid_a,
       b.syscall AS syscall_b, b.tid AS tid_b,
       a.enter_ts, a.exit_ts
FROM syscalls a
JOIN syscalls b ON a.worker = b.worker AND a.pid = b.pid
  AND a.tid < b.tid
  AND a.enter_ts < b.exit_ts AND b.enter_ts < a.exit_ts
ORDER BY a.enter_ts LIMIT 50;
"#
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sample_jsonl() -> String {
        r#"# Header comment
{"phase":"enter","ts":100000,"seq":0,"pid":9,"tid":9,"worker":42,"host_tid":4201,"syscall":"openat","args":[{"fd":-100},{"path":"/etc/passwd"},{"int":0},{"int":0}]}
{"phase":"exit","ts":100500,"seq":0,"pid":9,"tid":9,"worker":42,"host_tid":4201,"syscall":"openat","result":{"ok":3}}
{"phase":"enter","ts":101000,"seq":1,"pid":9,"tid":9,"worker":42,"host_tid":4201,"syscall":"read","args":[{"fd":3},{"int":4096}]}
{"phase":"exit","ts":101200,"seq":1,"pid":9,"tid":9,"worker":42,"host_tid":4201,"syscall":"read","result":{"ok":256}}
{"phase":"enter","ts":102000,"seq":2,"pid":9,"tid":9,"worker":42,"host_tid":4202,"syscall":"connect","args":[{"fd":5},{"addr":"10.0.0.1:443"}]}
{"phase":"exit","ts":102100,"seq":2,"pid":9,"tid":9,"worker":42,"host_tid":4202,"syscall":"connect","result":{"err":-13}}
{"phase":"enter","ts":103000,"seq":3,"pid":9,"tid":9,"worker":42,"host_tid":4201,"syscall":"futex","args":[{"int":0}]}
"#
        .to_string()
    }

    #[test]
    fn import_and_query_basic() {
        let dir = std::env::temp_dir().join("litebox_audit_test");
        let _ = std::fs::create_dir_all(&dir);
        let jsonl_path = dir.join("test.jsonl");
        let db_path = dir.join("test.db");

        // Write sample data.
        let mut f = std::fs::File::create(&jsonl_path).unwrap();
        f.write_all(sample_jsonl().as_bytes()).unwrap();
        drop(f);

        // Clean up any old db.
        let _ = std::fs::remove_file(&db_path);

        // Import.
        let stats = import(&jsonl_path, &db_path).unwrap();
        assert_eq!(stats.enter_count, 4);
        assert_eq!(stats.exit_count, 3);
        assert_eq!(stats.orphan_count, 1); // futex enter with no exit

        // Query: total rows.
        let conn = Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM syscalls", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 4); // 3 matched + 1 orphan

        // Query: duration of openat.
        let duration: i64 = conn
            .query_row(
                "SELECT duration_ns FROM syscalls WHERE syscall = 'openat'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(duration, 500); // 100500 - 100000

        // Query: error result.
        let err: i64 = conn
            .query_row(
                "SELECT result_err FROM syscalls WHERE syscall = 'connect'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(err, -13);

        // Query: orphan (no exit).
        let orphan_exit: Option<i64> = conn
            .query_row(
                "SELECT exit_ts FROM syscalls WHERE syscall = 'futex'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(orphan_exit.is_none());

        // Query: pending_ns for orphan — futex entered at 103000,
        // last event exit_ts is 102100, so pending = 102100 - 103000 would
        // be negative. But log_end_ts = MAX(COALESCE(exit_ts,enter_ts)) = 103000
        // (the futex enter itself), so pending = 103000 - 103000 = 0.
        let pending: Option<i64> = conn
            .query_row(
                "SELECT pending_ns FROM syscalls WHERE syscall = 'futex'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, Some(0)); // entered at the very end of the log

        // Completed syscalls should have NULL pending_ns.
        let completed_pending: Option<i64> = conn
            .query_row(
                "SELECT pending_ns FROM syscalls WHERE syscall = 'openat'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(completed_pending.is_none());

        // Clean up.
        let _ = std::fs::remove_file(&jsonl_path);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn import_real_audit_log() {
        // Try to import the real audit log if available.
        let real_log = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("code-audit.jsonl");
        if !real_log.exists() {
            eprintln!("Skipping real audit log test (file not found)");
            return;
        }

        let dir = std::env::temp_dir().join("litebox_audit_real_test");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("real.db");
        let _ = std::fs::remove_file(&db_path);

        let stats = import(&real_log, &db_path).unwrap();
        assert!(stats.total_lines > 0, "should have imported some events");
        eprintln!(
            "Real log: {} events, {} enter, {} exit, {} orphans",
            stats.total_lines, stats.enter_count, stats.exit_count, stats.orphan_count
        );

        let conn = Connection::open(&db_path).unwrap();

        // Verify we can run the example queries without error.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM syscalls", [], |row| row.get(0))
            .unwrap();
        assert!(count > 0);

        // Error query.
        let _err_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM syscalls WHERE result_err IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();

        // Cleanup.
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
    }
}
