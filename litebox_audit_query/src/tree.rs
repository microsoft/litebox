// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! "Frontier" tree model for the audit-log watcher.
//!
//! Aggregates the stream of broker policy decisions into two live trees — one
//! for filesystem paths, one for network endpoints — coloured by whether each
//! subtree contains allowed access, denied access, or both. The policy itself
//! is effectively constant; what grows is the *frontier* of what the sandboxed
//! agent has actually reached, which this compact hierarchy makes visible.
//!
//! - Filesystem paths split on `/`.
//! - Network endpoints split on **reversed** DNS labels (so `api.github.com`
//!   and `codeload.github.com` share a `com › github` subtree), with the port
//!   as a `:PORT` leaf. Bare IPs are single-label nodes.

use std::collections::BTreeMap;

const RESET: &str = "\x1b[0m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[90m";
const BOLD: &str = "\x1b[1m";

/// One node of a frontier tree. `allowed`/`denied` are aggregated over the
/// whole subtree rooted here (set on every node along an inserted path), so an
/// internal node is green only if everything under it was allowed, red only if
/// everything was denied, and yellow when the subtree mixes both.
#[derive(Default)]
struct Node {
    children: BTreeMap<String, Node>,
    allowed: bool,
    denied: bool,
    terminal: bool,
}

impl Node {
    fn insert(&mut self, labels: &[String], allowed: bool) {
        if allowed {
            self.allowed = true;
        } else {
            self.denied = true;
        }
        match labels.split_first() {
            None => self.terminal = true,
            Some((head, rest)) => self
                .children
                .entry(head.clone())
                .or_default()
                .insert(rest, allowed),
        }
    }
}

/// The two frontier trees plus running tallies.
pub struct Frontier {
    fs: Node,
    net: Node,
    fs_allowed: u64,
    fs_denied: u64,
    net_allowed: u64,
    net_denied: u64,
    color: bool,
}

impl Frontier {
    pub fn new(color: bool) -> Self {
        Self {
            fs: Node::default(),
            net: Node::default(),
            fs_allowed: 0,
            fs_denied: 0,
            net_allowed: 0,
            net_denied: 0,
            color,
        }
    }

    /// Fold one audit event (a broker policy decision) into the model.
    /// Returns `true` if the model changed and a redraw is warranted.
    pub fn ingest(&mut self, v: &serde_json::Value) -> bool {
        let Some(event) = v.get("event").and_then(serde_json::Value::as_str) else {
            return false;
        };
        match event {
            "fs_allowed" | "fs_denied" => {
                let allowed = event == "fs_allowed";
                let Some(path) = v["path"].as_str() else {
                    return false;
                };
                let labels: Vec<String> = path
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                self.fs.insert(&labels, allowed);
                if allowed {
                    self.fs_allowed += 1;
                } else {
                    self.fs_denied += 1;
                }
                true
            }
            "tcp_allowed" | "tcp_denied" | "udp_denied" => {
                let allowed = event == "tcp_allowed";
                let host = v["hostname"]
                    .as_str()
                    .or_else(|| v["ip"].as_str())
                    .unwrap_or("?");
                let port = v["port"].as_i64().unwrap_or(0);
                let mut labels: Vec<String> = host.split('.').rev().map(str::to_string).collect();
                labels.push(format!(":{port}"));
                self.net.insert(&labels, allowed);
                if allowed {
                    self.net_allowed += 1;
                } else {
                    self.net_denied += 1;
                }
                true
            }
            _ => false,
        }
    }

    fn color(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("{code}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    /// Render both trees plus a header into a full-screen string (caller clears
    /// the screen first).
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.color(BOLD, "LiteBox sandbox frontier"));
        out.push('\n');
        out.push_str("  legend: ");
        out.push_str(&self.color(GREEN, "allowed"));
        out.push_str("  ");
        out.push_str(&self.color(RED, "denied"));
        out.push_str("  ");
        out.push_str(&self.color(YELLOW, "mixed"));
        out.push_str(&self.color(DIM, "   (denied = agent was blocked)"));
        out.push('\n');
        out.push('\n');

        out.push_str(&self.color(
            BOLD,
            &format!(
                "Network  (+{} allowed, {} blocked)\n",
                self.net_allowed, self.net_denied
            ),
        ));
        self.render_children(&self.net, "", &mut out);
        out.push('\n');

        out.push_str(&self.color(
            BOLD,
            &format!(
                "Filesystem  (+{} allowed, {} blocked)\n",
                self.fs_allowed, self.fs_denied
            ),
        ));
        self.render_children(&self.fs, "", &mut out);
        out
    }

    fn render_children(&self, node: &Node, prefix: &str, out: &mut String) {
        let n = node.children.len();
        for (i, (label, child)) in node.children.iter().enumerate() {
            let last = i + 1 == n;
            let branch = if last { "└── " } else { "├── " };
            let code = status_color(child.allowed, child.denied);
            out.push_str(prefix);
            out.push_str(&self.color(DIM, branch));
            out.push_str(&self.color(code, label));
            out.push('\n');
            let child_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
            self.render_children(child, &child_prefix, out);
        }
    }
}

fn status_color(allowed: bool, denied: bool) -> &'static str {
    match (allowed, denied) {
        (true, true) => YELLOW,
        (false, true) => RED,
        (true, false) => GREEN,
        (false, false) => DIM,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(json: &str) -> serde_json::Value {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn network_reversed_domain_aggregation() {
        let mut f = Frontier::new(false);
        assert!(f.ingest(&ev(
            r#"{"event":"tcp_allowed","hostname":"api.github.com","ip":"1.1.1.1","port":443}"#
        )));
        assert!(f.ingest(&ev(
            r#"{"event":"tcp_denied","hostname":"evil.example.com","ip":"9.9.9.9","port":443}"#
        )));
        let rendered = f.render();
        assert!(rendered.contains("github"), "{rendered}");
        assert!(rendered.contains("example"), "{rendered}");
        assert!(rendered.contains(":443"), "{rendered}");
        assert_eq!(f.net_allowed, 1);
        assert_eq!(f.net_denied, 1);
    }

    #[test]
    fn mixed_subtree_marks_ancestor() {
        let mut f = Frontier::new(false);
        // Same parent dir, one allowed child, one denied child → parent mixed.
        f.ingest(&ev(
            r#"{"event":"fs_allowed","path":"/root/ok.txt","action":"read"}"#,
        ));
        f.ingest(&ev(
            r#"{"event":"fs_denied","path":"/root/.ssh/id_rsa","action":"open"}"#,
        ));
        // The `root` node aggregates both.
        assert!(f.fs.children["root"].allowed);
        assert!(f.fs.children["root"].denied);
        assert_eq!(status_color(true, true), YELLOW);
    }

    #[test]
    fn non_policy_event_ignored() {
        let mut f = Frontier::new(false);
        assert!(!f.ingest(&ev(r#"{"phase":"enter","syscall":"openat"}"#)));
        assert!(!f.ingest(&ev(
            r#"{"event":"dns_resolved","hostname":"x.com","ips":[]}"#
        )));
    }
}
