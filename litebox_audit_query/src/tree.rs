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

use std::collections::{BTreeMap, BTreeSet};

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
    /// How many times *this exact path* (not a descendant) was itself
    /// allowed/denied — an attempt tally, not a boolean — and with which action
    /// verbs. Distinct from `allowed`/`denied`, which aggregate over the whole
    /// subtree for colouring. The tally lets the tree surface both a decision
    /// made *on an internal node's own path* (e.g. a denied `mkdir /root` on a
    /// `root` node that also has allowed children) as a `(self)` row, and *how
    /// often* a resource was hit, so a repeatedly blocked endpoint shows its
    /// true volume rather than a flat 1.
    self_allow_hits: u64,
    self_deny_hits: u64,
    allow_actions: BTreeSet<String>,
    deny_actions: BTreeSet<String>,
    /// Interactive-TUI expand state (ignored by the static `render`).
    expanded: bool,
}

impl Node {
    fn insert(&mut self, labels: &[String], allowed: bool, action: &str) {
        if allowed {
            self.allowed = true;
        } else {
            self.denied = true;
        }
        match labels.split_first() {
            None => {
                self.terminal = true;
                if allowed {
                    self.self_allow_hits += 1;
                    if !action.is_empty() {
                        self.allow_actions.insert(action.to_string());
                    }
                } else {
                    self.self_deny_hits += 1;
                    if !action.is_empty() {
                        self.deny_actions.insert(action.to_string());
                    }
                }
            }
            Some((head, rest)) => self
                .children
                .entry(head.clone())
                .or_default()
                .insert(rest, allowed, action),
        }
    }

    /// Count of (allowed, denied) leaves in this subtree, counting a node's own
    /// path decision — not the aggregate flags — so a node that was itself
    /// denied but has allowed descendants contributes exactly one denial (its
    /// own), never a phantom allow.
    fn leaf_counts(&self) -> (u32, u32) {
        let mut a = u32::from(self.self_allow_hits > 0);
        let mut d = u32::from(self.self_deny_hits > 0);
        for child in self.children.values() {
            let (ca, cd) = child.leaf_counts();
            a += ca;
            d += cd;
        }
        (a, d)
    }

    /// Count of (allowed, denied) *attempts* — audit events — in this subtree,
    /// summing each node's own tally. Where [`Node::leaf_counts`] answers "how
    /// many distinct paths", this answers "how many times", so a resource the
    /// agent bounced off repeatedly surfaces its true attempt volume.
    fn hit_counts(&self) -> (u64, u64) {
        let mut a = self.self_allow_hits;
        let mut d = self.self_deny_hits;
        for child in self.children.values() {
            let (ca, cd) = child.hit_counts();
            a += ca;
            d += cd;
        }
        (a, d)
    }

    /// One-line summary of the verbs applied to *this exact path*, e.g.
    /// `read ✓  mkdir ✗`. Empty when the path was only ever an interior node.
    fn self_action_summary(&self) -> String {
        let mut parts = Vec::new();
        for a in &self.allow_actions {
            parts.push(format!("{a} \u{2713}"));
        }
        for a in &self.deny_actions {
            parts.push(format!("{a} \u{2717}"));
        }
        parts.join("  ")
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
    /// Total allow/deny *attempts* (audit events) aggregated over this
    /// subtree — the sister of `allow_count`/`deny_count`, which count distinct
    /// paths. Lets the view show `×N` when a resource was hit more than once.
    pub allow_hits: u64,
    pub deny_hits: u64,
    pub is_section: bool,
    /// A synthetic row for a node's *own* path decision (see `collect_rows`).
    pub is_self: bool,
    /// Verb summary for a terminal/self row, e.g. `read ✓  mkdir ✗`.
    pub action: String,
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
            let (ah, dh) = root.hit_counts();
            rows.push(Row {
                depth: 0,
                label: title.to_string(),
                allowed: a > 0,
                denied: d > 0,
                expandable: !root.children.is_empty(),
                expanded,
                allow_count: a,
                deny_count: d,
                allow_hits: ah,
                deny_hits: dh,
                is_section: true,
                is_self: false,
                action: String::new(),
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
                let action = v["action"].as_str().unwrap_or("");
                self.fs.insert(&labels, allowed, action);
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
                let mut labels: Vec<String> = if host.parse::<std::net::IpAddr>().is_ok() {
                    // A bare IP is a single node: its octets/groups are not a
                    // domain hierarchy, so reversing `169.254.169.254` into
                    // `254 › 169 › 254 › 169` would be nonsense.
                    vec![host.to_string()]
                } else {
                    // Reverse DNS labels so `api.github.com` and
                    // `codeload.github.com` share a `com › github` subtree.
                    host.split('.').rev().map(str::to_string).collect()
                };
                labels.push(format!(":{port}"));
                self.net.insert(&labels, allowed, "connect");
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
        out.push_str(&self.color(
            DIM,
            "   (denied = agent was blocked; N\u{2713}/N\u{2717} = paths, \u{00d7}N = attempts)",
        ));
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
            let (ap, dp) = child.leaf_counts();
            let (ah, dh) = child.hit_counts();
            let counts = format_counts(ap, dp, ah, dh);
            if !counts.is_empty() {
                out.push(' ');
                out.push_str(&self.color(DIM, &counts));
            }
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

/// Format the `(paths … attempts)` count shown next to a tree node:
/// `(<ap>✓ <dp>✗)`, with a `×<hits>` suffix on either side only when that side
/// was hit more often than it has distinct paths — so a resource the agent
/// retried (a repeatedly blocked address, a hot allowed file) surfaces its
/// attempt volume while single-hit leaves stay uncluttered. Empty when nothing
/// was recorded at or under the node. Shared by the interactive TUI and the
/// static tree so both read identically.
pub(crate) fn format_counts(
    allow_paths: u32,
    deny_paths: u32,
    allow_hits: u64,
    deny_hits: u64,
) -> String {
    if allow_paths == 0 && deny_paths == 0 {
        return String::new();
    }
    let allow = if allow_hits > u64::from(allow_paths) {
        format!("{allow_paths}\u{2713}\u{00d7}{allow_hits}")
    } else {
        format!("{allow_paths}\u{2713}")
    };
    let deny = if deny_hits > u64::from(deny_paths) {
        format!("{deny_paths}\u{2717}\u{00d7}{deny_hits}")
    } else {
        format!("{deny_paths}\u{2717}")
    };
    format!("({allow} {deny})")
}

/// Walk `node`'s children (descending only into expanded ones), appending a
/// [`Row`] per visible node. `prefix` is the section-rooted path so far.
fn collect_rows(node: &Node, prefix: &[String], depth: usize, rows: &mut Vec<Row>) {
    for (label, child) in &node.children {
        let mut path = prefix.to_vec();
        path.push(label.clone());
        let (a, d) = child.leaf_counts();
        let (ah, dh) = child.hit_counts();
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
            allow_hits: ah,
            deny_hits: dh,
            is_section: false,
            is_self: false,
            // Leaves show their own verbs inline; interior nodes defer to a
            // `(self)` row (below) so the header stays uncluttered.
            action: if expandable {
                String::new()
            } else {
                child.self_action_summary()
            },
            path: path.clone(),
        });
        if expandable && child.expanded {
            // If this interior node's *own* path was acted on (e.g. `mkdir
            // /root` denied while its children were allowed), surface that
            // decision as a `(self)` row so its aggregate count reconciles
            // when you drill in — otherwise the ✗ looks orphaned.
            if child.self_allow_hits > 0 || child.self_deny_hits > 0 {
                let mut self_path = path.clone();
                self_path.push("\u{0}(self)".to_string());
                rows.push(Row {
                    depth: depth + 1,
                    label: "(self)".to_string(),
                    allowed: child.self_allow_hits > 0,
                    denied: child.self_deny_hits > 0,
                    expandable: false,
                    expanded: false,
                    allow_count: u32::from(child.self_allow_hits > 0),
                    deny_count: u32::from(child.self_deny_hits > 0),
                    allow_hits: child.self_allow_hits,
                    deny_hits: child.self_deny_hits,
                    is_section: false,
                    is_self: true,
                    action: child.self_action_summary(),
                    path: self_path,
                });
            }
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
    fn self_decision_surfaces_as_row_with_actions() {
        let mut f = Frontier::new(false);
        // `/root` itself: read allowed + mkdir denied; plus an allowed child.
        f.ingest(&ev(
            r#"{"event":"fs_allowed","path":"/root","action":"read"}"#,
        ));
        f.ingest(&ev(
            r#"{"event":"fs_denied","path":"/root","action":"mkdir"}"#,
        ));
        f.ingest(&ev(
            r#"{"event":"fs_allowed","path":"/root/.bashrc","action":"read"}"#,
        ));
        f.set_expanded(&["fs".to_string(), "root".to_string()], true);
        let rows = f.visible_rows();

        // Count reconciles: own read + child .bashrc = 2 allowed; own mkdir = 1
        // denied — no phantom allow from the terminal-with-allowed-descendants.
        let root = rows.iter().find(|r| r.label == "root").expect("root row");
        assert_eq!((root.allow_count, root.deny_count), (2, 1));

        // The denial on `/root` itself surfaces as a `(self)` row carrying both
        // verbs, so the ✗ is no longer orphaned when you drill in.
        let self_row = rows.iter().find(|r| r.is_self).expect("(self) row");
        assert!(self_row.allowed && self_row.denied);
        assert!(self_row.action.contains("read") && self_row.action.contains("mkdir"));

        // A pure denied leaf shows its verb inline.
        f.ingest(&ev(
            r#"{"event":"fs_denied","path":"/etc/shadow","action":"open"}"#,
        ));
        f.set_expanded(&["fs".to_string(), "etc".to_string()], true);
        let rows = f.visible_rows();
        let shadow = rows
            .iter()
            .find(|r| r.label == "shadow")
            .expect("shadow row");
        assert_eq!((shadow.allow_count, shadow.deny_count), (0, 1));
        assert!(shadow.action.contains("open"));
    }

    #[test]
    fn bare_ip_is_single_node_not_reversed() {
        let mut f = Frontier::new(false);
        f.ingest(&ev(
            r#"{"event":"tcp_denied","ip":"169.254.169.254","port":80}"#,
        ));
        let rows = f.visible_rows();
        // The IP is one node under Network, not four reversed octets.
        assert!(rows.iter().any(|r| r.label == "169.254.169.254"));
        assert!(!rows.iter().any(|r| r.label == "254"));
    }

    #[test]
    fn non_policy_event_ignored() {
        let mut f = Frontier::new(false);
        assert!(!f.ingest(&ev(r#"{"phase":"enter","syscall":"openat"}"#)));
        assert!(!f.ingest(&ev(
            r#"{"event":"dns_resolved","hostname":"x.com","ips":[]}"#
        )));
    }

    #[test]
    fn repeat_attempts_counted_and_aggregated() {
        let mut f = Frontier::new(false);
        // Same blocked endpoint hit three times, plus a different blocked host.
        for _ in 0..3 {
            f.ingest(&ev(
                r#"{"event":"tcp_denied","ip":"169.254.169.254","port":80}"#,
            ));
        }
        f.ingest(&ev(
            r#"{"event":"tcp_denied","hostname":"evil.example.com","ip":"9.9.9.9","port":443}"#,
        ));
        // Distinct denied paths under Network = 2 (the IP leaf + evil.…:443),
        // but the *attempt* total is 4 (3 on the IP, 1 on the host).
        assert_eq!(f.net.leaf_counts(), (0, 2));
        assert_eq!(f.net.hit_counts(), (0, 4));
        // The IP's own leaf carries all three of its attempts, not a flat 1.
        let ip = &f.net.children["169.254.169.254"].children[":80"];
        assert_eq!(ip.self_deny_hits, 3);
    }

    #[test]
    fn format_counts_shows_attempts_only_when_repeated() {
        // Single hit: attempts == paths, so no ×N suffix.
        assert_eq!(format_counts(0, 1, 0, 1), "(0\u{2713} 1\u{2717})");
        // Repeated denial: ×N appears on the deny side, making it pop.
        assert_eq!(
            format_counts(0, 1, 0, 47),
            "(0\u{2713} 1\u{2717}\u{00d7}47)"
        );
        // Repeated allow: ×N on the allow side.
        assert_eq!(
            format_counts(2, 0, 12, 0),
            "(2\u{2713}\u{00d7}12 0\u{2717})"
        );
        // Nothing recorded here: empty string.
        assert_eq!(format_counts(0, 0, 0, 0), "");
    }

    #[test]
    fn rows_carry_attempt_counts() {
        let mut f = Frontier::new(false);
        for _ in 0..5 {
            f.ingest(&ev(
                r#"{"event":"fs_denied","path":"/etc/shadow","action":"open"}"#,
            ));
        }
        f.set_expanded(&["fs".to_string(), "etc".to_string()], true);
        let rows = f.visible_rows();
        // The leaf shows one distinct denied path but five attempts.
        let shadow = rows
            .iter()
            .find(|r| r.label == "shadow")
            .expect("shadow row");
        assert_eq!((shadow.allow_count, shadow.deny_count), (0, 1));
        assert_eq!((shadow.allow_hits, shadow.deny_hits), (0, 5));
        // The Filesystem section aggregates the same five attempts.
        let section = rows
            .iter()
            .find(|r| r.label == "Filesystem")
            .expect("fs section");
        assert_eq!(section.deny_hits, 5);
    }
}
