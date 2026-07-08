// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unified sandbox policy for the broker.
//!
//! Combines filesystem and network access rules into a single JSON-loadable
//! policy that the broker enforces on behalf of sandboxed guests.
//!
//! # Policy file format
//!
//! ```json
//! {
//!     "filesystem": {
//!         "allow_read": ["/workspace/**", "/usr/**"],
//!         "allow_write": ["/tmp/**", "/workspace/**"],
//!         "deny": ["**/.ssh/**", "**/passwd"]
//!     },
//!     "network": {
//!         "deny_all": true,
//!         "allow_connect": ["api.github.com:443", "*.npmjs.org:443"]
//!     }
//! }
//! ```
//!
//! # Network policy semantics
//!
//! When `deny_all` is `false` (default), all connections are allowed.
//! When `deny_all` is `true`, only connections matching an `allow_connect`
//! entry are permitted. Entries are `"host:port"` patterns where `host` can
//! be a literal hostname, a wildcard pattern (e.g., `*.example.com`), or an
//! IP address. The port may be `*` to match any port.
//!
//! Hostname matching relies on the broker intercepting DNS queries from the
//! guest and building an IP → hostname reverse map.

use std::net::IpAddr;
use std::path::Path;

use serde::Deserialize;

/// A complete sandbox policy covering filesystem and network access.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SandboxPolicy {
    /// Filesystem access rules.
    #[serde(default)]
    pub filesystem: FsPolicy,
    /// Network access rules.
    #[serde(default)]
    pub network: NetworkPolicy,
}

/// Filesystem access policy using glob-style path patterns.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FsPolicy {
    /// Glob patterns of paths the guest may read.
    /// An empty list means all reads are allowed.
    #[serde(default)]
    pub allow_read: Vec<String>,
    /// Glob patterns of paths the guest may write.
    /// An empty list means all writes are allowed.
    #[serde(default)]
    pub allow_write: Vec<String>,
    /// Glob patterns of paths that are always denied (overrides allow lists).
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Network access policy with hostname-aware rules.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NetworkPolicy {
    /// If true, all outbound connections are denied by default.
    #[serde(default)]
    pub deny_all: bool,
    /// Allowed connect targets as `"host:port"` patterns.
    ///
    /// Only checked when `deny_all` is true. The host portion can be:
    /// - A literal hostname: `api.github.com`
    /// - A wildcard pattern: `*.npmjs.org`
    /// - An IP address: `93.184.216.34`
    /// - A wildcard: `*`
    ///
    /// The port can be a number or `*` for any port.
    #[serde(default)]
    pub allow_connect: Vec<String>,
}

/// Outcome of a policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl SandboxPolicy {
    /// Load a sandbox policy from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Load a sandbox policy from a JSON file.
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let data = std::fs::read_to_string(path)?;
        Ok(Self::from_json(&data)?)
    }

    /// Check whether a filesystem operation at `path` with the given `write`
    /// flag is allowed.
    pub fn check_file_access(&self, path: &str, write: bool) -> Decision {
        let normalized = normalize_path(path);
        let path = normalized.as_str();
        // Deny list always wins.
        if self.filesystem.deny.iter().any(|p| glob_match(p, path)) {
            return Decision::Deny;
        }
        if write {
            if !self.filesystem.allow_write.is_empty()
                && !self
                    .filesystem
                    .allow_write
                    .iter()
                    .any(|p| glob_match(p, path))
            {
                return Decision::Deny;
            }
        } else if !self.filesystem.allow_read.is_empty()
            && !self
                .filesystem
                .allow_read
                .iter()
                .any(|p| glob_match(p, path))
        {
            return Decision::Deny;
        }
        Decision::Allow
    }

    /// Check whether a network connection to the given destination is allowed.
    ///
    /// `hostname` is the DNS name that resolved to `ip`, if known. When the
    /// guest connects to an IP that was returned by a prior DNS query
    /// intercepted by the broker, the hostname is available for policy matching.
    pub fn check_connect(&self, ip: IpAddr, port: u16, hostname: Option<&str>) -> Decision {
        // Loopback is intra-sandbox, not egress: the network policy governs
        // reachability of *external* hosts, so 127.0.0.0/8 and ::1 are always
        // permitted. VS Code Remote-SSH depends on this — its SOCKS dynamic
        // port-forward makes the in-sandbox sshd `connect()` to the server's
        // `127.0.0.1:<ephemeral-port>`, which would otherwise be denied under
        // `deny_all`. Loopback isolation, if ever needed, is the deployment's
        // job (network namespace), not this egress policy's.
        if ip.is_loopback() {
            return Decision::Allow;
        }
        if !self.network.deny_all {
            return Decision::Allow;
        }
        for pattern in &self.network.allow_connect {
            if connect_pattern_matches(pattern, ip, port, hostname) {
                return Decision::Allow;
            }
        }
        Decision::Deny
    }
}

/// Check whether a `"host:port"` pattern matches a connection.
fn connect_pattern_matches(pattern: &str, ip: IpAddr, port: u16, hostname: Option<&str>) -> bool {
    // Split pattern into host and port parts.
    let (host_pat, port_pat) = match pattern.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => (pattern, "*"),
    };

    // Check port.
    if port_pat != "*" {
        match port_pat.parse::<u16>() {
            Ok(p) if p == port => {}
            _ => return false,
        }
    }

    // Check host — try hostname first, then IP.
    if let Some(name) = hostname
        && glob_match(host_pat, name)
    {
        return true;
    }

    // Also try matching against the IP address string.
    let ip_str = ip.to_string();
    glob_match(host_pat, &ip_str)
}

// ---------------------------------------------------------------------------
// Path normalization (adapted from litebox_shim_linux/src/policy.rs)
// ---------------------------------------------------------------------------

/// Normalize a filesystem path for policy matching.
///
/// Resolves `.` and `..` components and ensures the path is absolute.
fn normalize_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() || path == "." {
        return String::from("/");
    }

    let absolute = if path.starts_with('/') {
        String::from(path)
    } else {
        let mut s = String::from("/");
        s.push_str(path);
        s
    };

    let mut parts: Vec<&str> = Vec::new();
    for component in absolute.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }

    if parts.is_empty() {
        String::from("/")
    } else {
        let mut result = String::new();
        for part in &parts {
            result.push('/');
            result.push_str(part);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Glob matching (adapted from litebox_shim_linux/src/policy.rs)
// ---------------------------------------------------------------------------

/// Simple glob matching supporting `*`, `**`, and `?`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match_inner(&pat, &txt)
}

fn glob_match_inner(pat: &[char], txt: &[char]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < txt.len() {
        if pi < pat.len() && pat[pi] == '*' {
            if pi + 1 < pat.len() && pat[pi + 1] == '*' {
                let rest = &pat[pi + 2..];
                let rest = if rest.first() == Some(&'/') {
                    &rest[1..]
                } else {
                    rest
                };
                for start in ti..=txt.len() {
                    if glob_match_inner(rest, &txt[start..]) {
                        return true;
                    }
                }
                return false;
            }
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if pi < pat.len() && (pat[pi] == '?' || pat[pi] == txt[ti]) {
            pi += 1;
            ti += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Test helper: build an `IpAddr` from V4 octets.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn load_from_json() {
        let json = r#"{
            "filesystem": {
                "allow_read": ["/workspace/**"],
                "allow_write": ["/tmp/**"],
                "deny": ["**/.ssh/**"]
            },
            "network": {
                "deny_all": true,
                "allow_connect": ["api.github.com:443"]
            }
        }"#;
        let policy = SandboxPolicy::from_json(json).unwrap();
        assert!(policy.network.deny_all);
        assert_eq!(policy.network.allow_connect.len(), 1);
        assert_eq!(policy.filesystem.allow_read.len(), 1);
    }

    #[test]
    fn empty_json_gives_defaults() {
        let policy = SandboxPolicy::from_json("{}").unwrap();
        assert!(!policy.network.deny_all);
        assert!(policy.network.allow_connect.is_empty());
        assert!(policy.filesystem.allow_read.is_empty());
    }

    #[test]
    fn fs_deny_overrides_allow() {
        let policy = SandboxPolicy::from_json(
            r#"{
                "filesystem": {
                    "allow_read": ["/workspace/**"],
                    "allow_write": ["/workspace/**"],
                    "deny": ["**/.git/**"]
                }
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.check_file_access("/workspace/src/main.rs", false),
            Decision::Allow
        );
        assert_eq!(
            policy.check_file_access("/workspace/.git/config", false),
            Decision::Deny
        );
        assert_eq!(
            policy.check_file_access("/etc/passwd", false),
            Decision::Deny
        );
    }

    #[test]
    fn network_deny_all_with_hostname_allowlist() {
        let policy = SandboxPolicy::from_json(
            r#"{
                "network": {
                    "deny_all": true,
                    "allow_connect": ["api.github.com:443", "*.npmjs.org:443"]
                }
            }"#,
        )
        .unwrap();
        // Allowed by exact hostname match.
        assert_eq!(
            policy.check_connect(ip(140, 82, 121, 6), 443, Some("api.github.com"),),
            Decision::Allow
        );
        // Allowed by wildcard hostname match.
        assert_eq!(
            policy.check_connect(ip(104, 16, 20, 35), 443, Some("registry.npmjs.org"),),
            Decision::Allow
        );
        // Denied — wrong hostname.
        assert_eq!(
            policy.check_connect(ip(93, 184, 216, 34), 443, Some("evil.com"),),
            Decision::Deny
        );
        // Denied — no hostname, IP doesn't match pattern.
        assert_eq!(
            policy.check_connect(ip(1, 2, 3, 4), 443, None),
            Decision::Deny
        );
    }

    #[test]
    fn network_allow_by_ip_pattern() {
        let policy = SandboxPolicy::from_json(
            r#"{
                "network": {
                    "deny_all": true,
                    "allow_connect": ["10.0.0.*:*"]
                }
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.check_connect(ip(10, 0, 0, 1), 5640, None),
            Decision::Allow
        );
        assert_eq!(
            policy.check_connect(ip(10, 0, 1, 1), 80, None),
            Decision::Deny
        );
    }

    #[test]
    fn network_wildcard_port() {
        let policy = SandboxPolicy::from_json(
            r#"{
                "network": {
                    "deny_all": true,
                    "allow_connect": ["example.com:*"]
                }
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.check_connect(ip(93, 184, 216, 34), 80, Some("example.com"),),
            Decision::Allow
        );
        assert_eq!(
            policy.check_connect(ip(93, 184, 216, 34), 443, Some("example.com"),),
            Decision::Allow
        );
    }

    #[test]
    fn network_not_deny_all_allows_everything() {
        let policy = SandboxPolicy::from_json(r#"{ "network": { "deny_all": false } }"#).unwrap();
        assert_eq!(
            policy.check_connect(ip(1, 2, 3, 4), 80, Some("evil.com")),
            Decision::Allow
        );
    }

    #[test]
    fn normalize_dotdot() {
        assert_eq!(normalize_path("/usr/bin/../lib"), "/usr/lib");
        assert_eq!(normalize_path("/a/b/c/../../d"), "/a/d");
        assert_eq!(normalize_path("/.."), "/");
    }

    #[test]
    fn normalize_relative() {
        assert_eq!(normalize_path("bin/busybox"), "/bin/busybox");
        assert_eq!(normalize_path("."), "/");
    }
}
