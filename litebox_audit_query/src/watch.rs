// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Live "watch" view of a litebox audit log.
//!
//! Tails a JSONL audit log and pretty-prints each event with color, the
//! cross-platform replacement for the legacy PowerShell `Tail-AuditLog.ps1` /
//! `View-AuditLog.ps1` viewers. Broker policy decisions (`tcp_allowed`,
//! `tcp_denied`, `udp_denied`, `fs_denied`, `dns_resolved`, `policy_loaded`)
//! are rendered prominently; per-syscall enter/exit events are merged into a
//! single line and can be suppressed entirely with `--policy-only`.

use std::collections::HashMap;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

// ── ANSI color codes ─────────────────────────────────────────────────
const RESET: &str = "\x1b[0m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[90m";
const BOLD_RED: &str = "\x1b[1;31m";
const BOLD_GREEN: &str = "\x1b[1;32m";
const BOLD_CYAN: &str = "\x1b[1;36m";

/// Poll interval when following a log with no new data.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Entry point for the `watch` subcommand.
pub fn run(
    path: &Path,
    follow: bool,
    tree: bool,
    policy_only: bool,
    filter: Option<&str>,
) -> Result<(), String> {
    let log_path = resolve_log_path(path)?;
    let color = io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let mut file =
        std::fs::File::open(&log_path).map_err(|e| format!("open {}: {e}", log_path.display()))?;

    if tree {
        return run_tree(file, follow, color);
    }

    // Plain streaming mode: tail the log, pretty-printing each event.
    let mut renderer = Renderer {
        color,
        policy_only,
        filter: filter.map(str::to_string),
        pending: HashMap::new(),
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if color {
        let _ = writeln!(out, "{DIM}watching {}{RESET}", log_path.display());
    } else {
        let _ = writeln!(out, "watching {}", log_path.display());
    }

    let mut carry: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 65536];
    loop {
        let n = file
            .read(&mut chunk)
            .map_err(|e| format!("read {}: {e}", log_path.display()))?;
        if n > 0 {
            carry.extend_from_slice(&chunk[..n]);
            while let Some(pos) = carry.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = carry.drain(..=pos).collect();
                let text = String::from_utf8_lossy(&line);
                renderer.render_line(text.trim_end(), &mut out);
            }
            out.flush().map_err(|e| format!("flush: {e}"))?;
        } else if follow {
            thread::sleep(POLL_INTERVAL);
        } else {
            break;
        }
    }
    Ok(())
}

/// Tree mode: an interactive TUI on a terminal (with `--follow`), or a one-shot
/// static render for piped / `--no-follow` output.
fn run_tree(mut file: std::fs::File, follow: bool, color: bool) -> Result<(), String> {
    let mut frontier = crate::tree::Frontier::new(color);
    if color && follow {
        return crate::tui::run(frontier, file).map_err(|e| format!("tui: {e}"));
    }
    // Non-interactive: fold the whole file and render the tree once.
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("read: {e}"))?;
    for line in content.lines() {
        let trimmed = line.trim();
        // Cheap pre-filter: only broker policy events carry an `"event":` key;
        // the syscall-trace lines (the vast majority of the file) don't, so skip
        // them without paying for a full JSON parse — the tree only consumes
        // policy events (fs_*/tcp_*/dns_*).
        if trimmed.starts_with('{')
            && trimmed.contains("\"event\":")
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed)
        {
            frontier.ingest(&v);
        }
    }
    print!("{}", frontier.render());
    let _ = io::stdout().flush();
    Ok(())
}

/// Resolve `path` to a concrete JSONL file. If `path` is a directory, the
/// most recently modified `*.jsonl` file within it is chosen.
fn resolve_log_path(path: &Path) -> Result<PathBuf, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
    if meta.is_file() {
        return Ok(path.to_path_buf());
    }
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(path).map_err(|e| format!("read_dir {}: {e}", path.display()))? {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .map_err(|e| format!("stat {}: {e}", p.display()))?;
        if newest.as_ref().is_none_or(|(t, _)| mtime > *t) {
            newest = Some((mtime, p));
        }
    }
    newest
        .map(|(_, p)| p)
        .ok_or_else(|| format!("no *.jsonl files in {}", path.display()))
}

struct Renderer {
    color: bool,
    policy_only: bool,
    filter: Option<String>,
    /// Pending syscall-enter events keyed by (seq, worker), merged with their
    /// matching exit into a single output line.
    pending: HashMap<(i64, i64), (String, String)>,
}

impl Renderer {
    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("{code}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    fn render_line(&mut self, line: &str, out: &mut impl Write) {
        if line.is_empty() {
            return;
        }
        // Header/comment lines the tool_executor writes start with '#'.
        if let Some(rest) = line.strip_prefix('#') {
            let _ = writeln!(out, "{}", self.paint(DIM, rest.trim_start()));
            return;
        }
        if !line.starts_with('{') {
            return;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            return;
        };
        if v.get("event").and_then(|e| e.as_str()).is_some() {
            self.render_broker_event(&v, out);
        } else if !self.policy_only {
            self.render_syscall(&v, out);
        }
    }

    fn render_broker_event(&self, v: &serde_json::Value, out: &mut impl Write) {
        let event = v["event"].as_str().unwrap_or("");
        let hostname = v["hostname"].as_str();
        let ip = v["ip"].as_str().unwrap_or("?");
        let port = v["port"].as_i64().unwrap_or(0);
        let target = match hostname {
            Some(h) => format!("{h} ({ip})"),
            None => ip.to_string(),
        };
        let line = match event {
            "policy_loaded" => {
                let deny_all = v["network_deny_all"].as_bool().unwrap_or(false);
                let mode = if deny_all {
                    "deny-all + allowlist"
                } else {
                    "allow-all"
                };
                self.paint(
                    BOLD_CYAN,
                    &format!("=== sandbox policy loaded ({mode}) ==="),
                )
            }
            "dns_resolved" => {
                let ips: Vec<String> = v["ips"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                self.paint(
                    CYAN,
                    &format!(
                        "DNS {} -> {}",
                        v["hostname"].as_str().unwrap_or("?"),
                        ips.join(", ")
                    ),
                )
            }
            "tcp_allowed" => self.paint(GREEN, &format!("+ TCP {target}:{port}")),
            "tcp_denied" => self.paint(BOLD_RED, &format!("X BLOCKED TCP {target}:{port}")),
            "udp_denied" => self.paint(BOLD_RED, &format!("X BLOCKED UDP {target}:{port}")),
            "fs_denied" => self.paint(
                RED,
                &format!(
                    "X FS DENIED {}: {}",
                    v["action"].as_str().unwrap_or("?"),
                    v["path"].as_str().unwrap_or("?")
                ),
            ),
            "fs_allowed" => self.paint(
                DIM,
                &format!(
                    "+ FS {}: {}",
                    v["action"].as_str().unwrap_or("?"),
                    v["path"].as_str().unwrap_or("?")
                ),
            ),
            other => self.paint(DIM, &format!("[broker] {other}")),
        };
        let _ = writeln!(out, "{line}");
    }

    fn render_syscall(&mut self, v: &serde_json::Value, out: &mut impl Write) {
        let phase = v["phase"].as_str().unwrap_or("");
        let seq = v["seq"].as_i64().unwrap_or(0);
        let worker = v["worker"].as_i64().unwrap_or(0);
        let name = v["syscall"].as_str().unwrap_or("unknown").to_string();
        match phase {
            "enter" => {
                let args = format_args(&v["args"]);
                self.pending.insert((seq, worker), (name, args));
            }
            "exit" => {
                let (name, args) = self
                    .pending
                    .remove(&(seq, worker))
                    .unwrap_or_else(|| (name, String::new()));
                if let Some(f) = &self.filter
                    && !name.contains(f.as_str())
                {
                    return;
                }
                let result = &v["result"];
                let (result_str, is_err) = if let Some(ok) = result.get("ok") {
                    (format!("= {ok}"), false)
                } else if let Some(err) = result.get("err") {
                    (format!("ERR {err}"), true)
                } else {
                    (String::new(), false)
                };
                let colored_name = self.paint(syscall_color(&name), &name);
                let result_out = if is_err {
                    self.paint(RED, &result_str)
                } else {
                    self.paint(DIM, &result_str)
                };
                let _ = writeln!(out, "{colored_name}({args}) {result_out}");
            }
            _ => {}
        }
    }
}

/// Format a syscall's `args` JSON array into a compact `fd=3, "/x", ...` string.
fn format_args(args: &serde_json::Value) -> String {
    let Some(arr) = args.as_array() else {
        return String::new();
    };
    let mut parts: Vec<String> = Vec::new();
    for arg in arr {
        if let Some(fd) = arg.get("fd").and_then(serde_json::Value::as_i64) {
            parts.push(format!("fd={fd}"));
        }
        if let Some(p) = arg.get("path").and_then(|x| x.as_str()) {
            parts.push(format!("\"{p}\""));
        }
        if let Some(a) = arg.get("addr").and_then(|x| x.as_str()) {
            parts.push(a.to_string());
        }
        if let Some(i) = arg.get("int").and_then(serde_json::Value::as_i64) {
            parts.push(i.to_string());
        }
        if let Some(fl) = arg.get("flags").and_then(|x| x.as_str()) {
            parts.push(fl.to_string());
        }
    }
    parts.join(", ")
}

/// Category color for a syscall name, mirroring the legacy PowerShell viewer.
fn syscall_color(name: &str) -> &'static str {
    match name {
        "socket" | "connect" | "bind" | "listen" | "accept" => RED,
        "execve" | "execveat" | "unlinkat" => YELLOW,
        "openat" | "open" => CYAN,
        "clone" | "clone3" | "fork" | "vfork" => BOLD_GREEN,
        _ => DIM,
    }
}
