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

pub(crate) const RESET: &str = "\x1b[0m";
pub(crate) const RED: &str = "\x1b[31m";
pub(crate) const GREEN: &str = "\x1b[32m";
pub(crate) const YELLOW: &str = "\x1b[33m";
pub(crate) const DIM: &str = "\x1b[90m";
pub(crate) const BOLD: &str = "\x1b[1m";

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
    /// Interactive-TUI expand state (ignored by the static `render`).
    expanded: bool,
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

    /// Count of (allowed, denied) terminal leaves in this subtree.
    fn leaf_counts(&self) -> (u32, u32) {
        let mut a = u32::from(self.terminal && self.allowed);
        let mut d = u32::from(self.terminal && self.denied);
        for child in self.children.values() {
            let (ca, cd) = child.leaf_counts();
            a += ca;
            d += cd;
        }
        (a, d)
    }

    fn child_mut(&mut self, labels: &[String]) -> Option<&mut Node> {
        let mut cur = self;
        for label in labels {
            cur = cur.children.get_mut(label)?;
        }
        Some(cur)
    }
}

/// One rendered line of the interactive tree, produced by
/// [`Frontier::visible_rows`]. `path[0]` is the section (`"net"` / `"fs"`).
pub struct Row {
    pub depth: usize,
    pub label: String,
    pub allowed: bool,
    pub denied: bool,
    pub expandable: bool,
    pub expanded: bool,
    pub allow_count: u32,
    pub deny_count: u32,
    pub is_section: bool,
    pub path: Vec<String>,
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
    /// Interactive-TUI section expand state (the two top-level headers).
    net_expanded: bool,
    fs_expanded: bool,
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
            net_expanded: true,
            fs_expanded: true,
        }
    }

    /// Flatten the tree into the currently-visible rows, honouring per-node
    /// expand state. Used by the interactive TUI.
    pub fn visible_rows(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        for (key, root, expanded, title) in [
            ("net", &self.net, self.net_expanded, "Network"),
            ("fs", &self.fs, self.fs_expanded, "Filesystem"),
        ] {
            let (a, d) = root.leaf_counts();
            rows.push(Row {
                depth: 0,
                label: title.to_string(),
                allowed: a > 0,
                denied: d > 0,
                expandable: !root.children.is_empty(),
                expanded,
                allow_count: a,
                deny_count: d,
                is_section: true,
                path: vec![key.to_string()],
            });
            if expanded {
                collect_rows(root, &[key.to_string()], 1, &mut rows);
            }
        }
        rows
    }

    /// Toggle the expand state of the node at `path` (`path[0]` selects the
    /// section). No-op for an unknown path.
    pub fn toggle(&mut self, path: &[String]) {
        self.set_expanded_impl(path, None);
    }

    /// Force the expand state of the node at `path`.
    pub fn set_expanded(&mut self, path: &[String], value: bool) {
        self.set_expanded_impl(path, Some(value));
    }

    fn set_expanded_impl(&mut self, path: &[String], value: Option<bool>) {
        let Some((section, rest)) = path.split_first() else {
            return;
        };
        let (root, section_flag) = match section.as_str() {
            "net" => (&mut self.net, &mut self.net_expanded),
            "fs" => (&mut self.fs, &mut self.fs_expanded),
            _ => return,
        };
        if rest.is_empty() {
            *section_flag = value.unwrap_or(!*section_flag);
        } else if let Some(node) = root.child_mut(rest) {
            node.expanded = value.unwrap_or(!node.expanded);
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

pub(crate) fn status_color(allowed: bool, denied: bool) -> &'static str {
    match (allowed, denied) {
        (true, true) => YELLOW,
        (false, true) => RED,
        (true, false) => GREEN,
        (false, false) => DIM,
    }
}

/// Walk `node`'s children (descending only into expanded ones), appending a
/// [`Row`] per visible node. `prefix` is the section-rooted path so far.
fn collect_rows(node: &Node, prefix: &[String], depth: usize, rows: &mut Vec<Row>) {
    for (label, child) in &node.children {
        let mut path = prefix.to_vec();
        path.push(label.clone());
        let (a, d) = child.leaf_counts();
        let expandable = !child.children.is_empty();
        rows.push(Row {
            depth,
            label: label.clone(),
            allowed: child.allowed,
            denied: child.denied,
            expandable,
            expanded: child.expanded,
            allow_count: a,
            deny_count: d,
            is_section: false,
            path: path.clone(),
        });
        if expandable && child.expanded {
            collect_rows(child, &path, depth + 1, rows);
        }
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
