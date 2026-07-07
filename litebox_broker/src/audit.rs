// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Structured audit event logging for the broker.
//!
//! Writes JSONL lines to a shared audit file for policy decisions and network
//! events. These events interleave with the shim's syscall audit events in the
//! same file, providing a unified trace of sandbox activity.

use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Upper bound on the number of distinct `fs_allowed` `(action, path)` pairs
/// remembered for de-duplication. Once reached, further first-touch allows are
/// not emitted, bounding both memory and audit-log volume while still capturing
/// the frontier of authorized paths.
const FS_ALLOWED_DEDUP_CAP: usize = 65_536;

/// Handle for writing structured audit events to a JSONL file.
///
/// Thread-safe (uses an internal mutex). Clone to share across threads.
#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<Mutex<std::fs::File>>,
    /// De-duplication set for `fs_allowed`: the shim opens the same paths
    /// repeatedly, so only the first authorized access to each `(action, path)`
    /// is emitted. Shared across clones so the whole broker de-dups together.
    seen_allowed: Arc<Mutex<HashSet<String>>>,
}

impl AuditLog {
    /// Open an audit log file in append mode.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(file)),
            seen_allowed: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// Write a raw JSONL line.
    ///
    /// The line and its trailing newline are coalesced into a single
    /// `write_all` so the whole record hits the file in one `write(2)`. The
    /// audit file is opened `O_APPEND` and is shared with the runner's shim
    /// audit (which likewise writes each line atomically), so a single
    /// append-write per line is what keeps the two writers' JSONL from
    /// interleaving mid-record. (`writeln!` emitted the body and the `\n` as
    /// separate writes, leaving a window for a runner line to splice in and
    /// corrupt both records.)
    fn write_line(&self, line: &str) {
        if let Ok(mut f) = self.inner.lock() {
            let mut buf = String::with_capacity(line.len() + 1);
            buf.push_str(line);
            buf.push('\n');
            let _ = f.write_all(buf.as_bytes());
        }
    }

    /// Log that a DNS query was resolved.
    pub fn dns_resolved(&self, hostname: &str, ips: &[IpAddr]) {
        let ips_json: Vec<String> = ips.iter().map(|ip| format!("\"{ip}\"")).collect();
        self.write_line(&format!(
            r#"{{"event":"dns_resolved","hostname":"{hostname}","ips":[{}]}}"#,
            ips_json.join(",")
        ));
    }

    /// Log that a TCP connection was allowed by policy.
    pub fn tcp_allowed(&self, hostname: Option<&str>, ip: IpAddr, port: u16) {
        let host = hostname
            .map(|h| format!(r#","hostname":"{h}""#))
            .unwrap_or_default();
        self.write_line(&format!(
            r#"{{"event":"tcp_allowed","ip":"{ip}","port":{port}{host}}}"#
        ));
    }

    /// Log that a TCP connection was denied by policy.
    pub fn tcp_denied(&self, hostname: Option<&str>, ip: IpAddr, port: u16) {
        let host = hostname
            .map(|h| format!(r#","hostname":"{h}""#))
            .unwrap_or_default();
        self.write_line(&format!(
            r#"{{"event":"tcp_denied","ip":"{ip}","port":{port}{host}}}"#
        ));
    }

    /// Log that a UDP datagram was denied by policy.
    pub fn udp_denied(&self, hostname: Option<&str>, ip: IpAddr, port: u16) {
        let host = hostname
            .map(|h| format!(r#","hostname":"{h}""#))
            .unwrap_or_default();
        self.write_line(&format!(
            r#"{{"event":"udp_denied","ip":"{ip}","port":{port}{host}}}"#
        ));
    }

    /// Log that the sandbox policy was loaded.
    pub fn policy_loaded(&self, path: &str, policy: &crate::sandbox_policy::SandboxPolicy) {
        let net_rules: Vec<String> = policy
            .network
            .allow_connect
            .iter()
            .map(|r| format!("\"{r}\""))
            .collect();
        let deny_all = policy.network.deny_all;
        self.write_line(&format!(
            r#"{{"event":"policy_loaded","path":"{path}","network_deny_all":{deny_all},"network_allow":[{}]}}"#,
            net_rules.join(",")
        ));
    }
    /// Log that a filesystem operation was denied by policy.
    pub fn fs_denied(&self, path: &str, action: &str) {
        self.write_line(&format!(
            r#"{{"event":"fs_denied","path":"{path}","action":"{action}"}}"#
        ));
    }

    /// Log the first authorized access to a path, forming the "allowed"
    /// frontier for the tree visualizer. De-duplicated per `(action, path)`
    /// (bounded by [`FS_ALLOWED_DEDUP_CAP`]) since the shim re-opens paths
    /// constantly.
    pub fn fs_allowed(&self, path: &str, action: &str) {
        let key = format!("{action}:{path}");
        {
            let mut seen = match self.seen_allowed.lock() {
                Ok(seen) => seen,
                Err(_) => return,
            };
            if seen.contains(&key) || seen.len() >= FS_ALLOWED_DEDUP_CAP {
                return;
            }
            seen.insert(key);
        }
        self.write_line(&format!(
            r#"{{"event":"fs_allowed","path":"{path}","action":"{action}"}}"#
        ));
    }
}

// Use `Option<AuditLog>` and call methods only when `Some`.
