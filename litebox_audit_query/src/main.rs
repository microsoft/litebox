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
    pid         INTEGER NOT NULL,
    tid         INTEGER NOT NULL,
    syscall     TEXT NOT NULL,
    args        TEXT NOT NULL,
    enter_ts    INTEGER NOT NULL,
    exit_ts     INTEGER,
    duration_ns INTEGER,
    result_ok   INTEGER,
    result_err  INTEGER,
    PRIMARY KEY (seq, worker)
)";

const CREATE_INDEXES: &str = "\
CREATE INDEX idx_syscall ON syscalls(syscall);
CREATE INDEX idx_errors ON syscalls(result_err) WHERE result_err IS NOT NULL;
CREATE INDEX idx_worker_seq ON syscalls(worker, seq)";

fn create_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(CREATE_TABLE)?;
    conn.execute_batch(CREATE_INDEXES)?;
    Ok(())
}

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
    pid: i64,
    tid: i64,
    syscall: String,
    args: String,
    enter_ts: i64,
}

fn import(jsonl_path: &Path, db_path: &Path) -> Result<ImportStats, String> {
    let file = std::fs::File::open(jsonl_path)
        .map_err(|e| format!("open {}: {e}", jsonl_path.display()))?;
    let reader = BufReader::new(file);

    // Remove stale database to start fresh.
    if db_path.exists() {
        std::fs::remove_file(db_path).map_err(|e| format!("remove {}: {e}", db_path.display()))?;
    }

    let conn =
        Connection::open(db_path).map_err(|e| format!("open db {}: {e}", db_path.display()))?;
    create_schema(&conn).map_err(|e| format!("create schema: {e}"))?;

    // Pending enter events keyed by (seq, worker).
    let mut pending: HashMap<(i64, i64), PendingEntry> = HashMap::new();
    let mut stats = ImportStats {
        total_lines: 0,
        enter_count: 0,
        exit_count: 0,
        orphan_count: 0,
    };

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| format!("begin: {e}"))?;

    {
        let mut insert_stmt = tx
            .prepare(
                "INSERT INTO syscalls \
                 (seq, worker, pid, tid, syscall, args, enter_ts, exit_ts, duration_ns, result_ok, result_err) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )
            .map_err(|e| format!("prepare insert: {e}"))?;

        for line_result in reader.lines() {
            let line = line_result.map_err(|e| format!("read line: {e}"))?;
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
                    } else {
                        // Exit without matching enter — unexpected. Count
                        // and skip rather than manufacturing fake data.
                        eprintln!(
                            "warning: exit event seq={seq} worker={worker} has no matching enter, skipping"
                        );
                        stats.orphan_count += 1;
                    }
                }
                _ => {
                    // No "phase" field — unexpected format. Skip.
                    eprintln!("warning: event with unknown phase {:?}, skipping", phase);
                }
            }
        }
    }

    // Insert orphaned enter events (syscall never returned).
    {
        let mut insert_orphan = tx
            .prepare(
                "INSERT INTO syscalls \
                 (seq, worker, pid, tid, syscall, args, enter_ts, exit_ts, duration_ns, result_ok, result_err) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL, NULL, NULL)",
            )
            .map_err(|e| format!("prepare orphan: {e}"))?;

        for entry in pending.values() {
            stats.orphan_count += 1;
            insert_orphan
                .execute(params![
                    entry.seq,
                    entry.worker,
                    entry.pid,
                    entry.tid,
                    entry.syscall,
                    entry.args,
                    entry.enter_ts,
                ])
                .map_err(|e| format!("insert orphan: {e}"))?;
        }
    }

    tx.commit().map_err(|e| format!("commit: {e}"))?;
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
  pid         - Guest virtual PID                                      NOT NULL
  tid         - Guest virtual TID (important for Node.js worker threads) NOT NULL
  syscall     - Syscall name: "openat", "read", "connect", "other"    NOT NULL
  args        - JSON array of arguments from the entry event           NOT NULL
  enter_ts    - Monotonic nanoseconds at syscall entry                  NOT NULL
  exit_ts     - Monotonic nanoseconds at syscall exit (NULL if never returned)
  duration_ns - exit_ts - enter_ts (NULL if never returned)
  result_ok   - Value from {{"ok": N}} on success (NULL on error or no exit)
  result_err  - Value from {{"err": N}} = negated errno on failure (NULL on success)

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
SELECT syscall, seq, worker, pid, tid, duration_ns/1000 AS duration_us, args
FROM syscalls ORDER BY duration_ns DESC LIMIT 20;

-- Error distribution by syscall
SELECT syscall, result_err, COUNT(*) AS cnt
FROM syscalls WHERE result_err IS NOT NULL
GROUP BY syscall, result_err ORDER BY cnt DESC;

-- Syscalls that never returned (hung / killed)
SELECT seq, worker, pid, tid, syscall, args, enter_ts
FROM syscalls WHERE exit_ts IS NULL;

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
SELECT seq, worker, pid, syscall, args, result_err
FROM syscalls
WHERE syscall IN ('openat', 'read', 'write', 'close', 'unlinkat', 'mkdir')
  AND result_err IS NOT NULL
ORDER BY enter_ts;

-- Network syscalls
SELECT seq, worker, pid, syscall, args, result_ok, result_err, duration_ns/1000 AS us
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
{"phase":"enter","ts":100000,"seq":0,"pid":9,"tid":9,"worker":42,"syscall":"openat","args":[{"fd":-100},{"path":"/etc/passwd"},{"int":0},{"int":0}]}
{"phase":"exit","ts":100500,"seq":0,"pid":9,"tid":9,"worker":42,"syscall":"openat","result":{"ok":3}}
{"phase":"enter","ts":101000,"seq":1,"pid":9,"tid":9,"worker":42,"syscall":"read","args":[{"fd":3},{"int":4096}]}
{"phase":"exit","ts":101200,"seq":1,"pid":9,"tid":9,"worker":42,"syscall":"read","result":{"ok":256}}
{"phase":"enter","ts":102000,"seq":2,"pid":9,"tid":9,"worker":42,"syscall":"connect","args":[{"fd":5},{"addr":"10.0.0.1:443"}]}
{"phase":"exit","ts":102100,"seq":2,"pid":9,"tid":9,"worker":42,"syscall":"connect","result":{"err":-13}}
{"phase":"enter","ts":103000,"seq":3,"pid":9,"tid":9,"worker":42,"syscall":"futex","args":[{"int":0}]}
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
