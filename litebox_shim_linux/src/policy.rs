// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Sandbox policy enforcement for restricting guest syscall behavior.
//!
//! When the `policy` feature is enabled, the shim checks filesystem paths,
//! network addresses, and executable names against a declarative policy before
//! allowing the operation to proceed. Violations are blocked with `EACCES` and
//! (if `audit_log` is also enabled) emitted as audit events.
//!
//! Policies are `no_std`-compatible and use simple glob-style matching.

use alloc::string::String;
use alloc::vec::Vec;

/// A complete sandbox policy controlling what the guest may do.
#[derive(Debug, Clone, Default)]
pub struct SandboxPolicy {
    /// Filesystem access policy.
    pub filesystem: FsPolicy,
    /// Network access policy.
    pub network: NetworkPolicy,
    /// Process execution policy.
    pub process: ProcessPolicy,
}

/// Controls which filesystem paths can be read or written.
#[derive(Debug, Clone, Default)]
pub struct FsPolicy {
    /// Glob patterns of paths the guest may read.
    /// An empty list means all reads are allowed.
    pub allow_read: Vec<String>,
    /// Glob patterns of paths the guest may write.
    /// An empty list means all writes are allowed.
    pub allow_write: Vec<String>,
    /// Glob patterns of paths that are always denied (overrides allow lists).
    pub deny: Vec<String>,
}

/// Controls which network operations are permitted.
#[derive(Debug, Clone, Default)]
pub struct NetworkPolicy {
    /// If true, all network connect/bind operations are denied by default.
    pub deny_all: bool,
    /// Allowed connect targets as `"host:port"` or `"*:port"` patterns.
    /// Only checked when `deny_all` is true.
    pub allow_connect: Vec<String>,
}

/// Controls which programs the guest may execute.
#[derive(Debug, Clone, Default)]
pub struct ProcessPolicy {
    /// Glob patterns of paths the guest may exec.
    /// An empty list means all execs are allowed.
    pub allow_exec: Vec<String>,
}

/// Result of a policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The operation is allowed.
    Allow,
    /// The operation is denied by policy.
    Deny,
}

impl SandboxPolicy {
    /// Check whether opening a file at `path` with the given `write` flag is allowed.
    pub fn check_file_access(&self, path: &str, write: bool) -> PolicyDecision {
        // Deny list always wins.
        if self.filesystem.deny.iter().any(|p| glob_match(p, path)) {
            return PolicyDecision::Deny;
        }
        if write {
            if !self.filesystem.allow_write.is_empty()
                && !self
                    .filesystem
                    .allow_write
                    .iter()
                    .any(|p| glob_match(p, path))
            {
                return PolicyDecision::Deny;
            }
        } else if !self.filesystem.allow_read.is_empty()
            && !self
                .filesystem
                .allow_read
                .iter()
                .any(|p| glob_match(p, path))
        {
            return PolicyDecision::Deny;
        }
        PolicyDecision::Allow
    }

    /// Check whether a network connect to the given address string is allowed.
    pub fn check_connect(&self, addr: &str) -> PolicyDecision {
        if !self.network.deny_all {
            return PolicyDecision::Allow;
        }
        if self
            .network
            .allow_connect
            .iter()
            .any(|p| glob_match(p, addr))
        {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny
        }
    }

    /// Check whether executing a program at `path` is allowed.
    pub fn check_exec(&self, path: &str) -> PolicyDecision {
        if self.process.allow_exec.is_empty() {
            return PolicyDecision::Allow;
        }
        if self.process.allow_exec.iter().any(|p| glob_match(p, path)) {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny
        }
    }
}

/// Simple glob matching supporting:
/// - `*` matches any sequence of characters (within a path segment or across)
/// - `**` matches any sequence including `/`
/// - `?` matches any single character
/// - Everything else is a literal match.
///
/// This is intentionally simple and does not support character classes.
#[allow(clippy::similar_names)] // pat/txt are intentionally named
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match_inner(&pat, &txt)
}

#[allow(clippy::similar_names)] // pi/ti/star_pi/star_ti are conventional
fn glob_match_inner(pat: &[char], txt: &[char]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < txt.len() {
        if pi < pat.len() && pat[pi] == '*' {
            // Check for "**" (matches across path separators).
            if pi + 1 < pat.len() && pat[pi + 1] == '*' {
                // "**" — try matching the rest of the pattern against every suffix.
                let rest = &pat[pi + 2..];
                // Skip optional '/' after "**"
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
            // Single "*" — remember position for backtracking.
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if pi < pat.len() && (pat[pi] == '?' || pat[pi] == txt[ti]) {
            pi += 1;
            ti += 1;
        } else if star_pi != usize::MAX {
            // Backtrack: let '*' consume one more character.
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    // Consume trailing '*'s in pattern.
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Global policy storage. Set once before the shim starts executing guest code.
static POLICY: once_cell::race::OnceBox<SandboxPolicy> = once_cell::race::OnceBox::new();

/// Install a sandbox policy. Must be called before guest execution begins.
/// Can only be called once; subsequent calls are ignored.
pub fn set_policy(policy: SandboxPolicy) {
    let _ = POLICY.set(alloc::boxed::Box::new(policy));
}

/// Get the active policy, if one has been set.
pub fn get_policy() -> Option<&'static SandboxPolicy> {
    POLICY.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate alloc;

    #[test]
    fn glob_literal_match() {
        assert!(glob_match("/etc/passwd", "/etc/passwd"));
        assert!(!glob_match("/etc/passwd", "/etc/shadow"));
    }

    #[test]
    fn glob_star_match() {
        assert!(glob_match("/workspace/*", "/workspace/main.rs"));
        assert!(glob_match("/workspace/*", "/workspace/Cargo.toml"));
        assert!(!glob_match("/workspace/*", "/etc/passwd"));
    }

    #[test]
    fn glob_double_star_match() {
        assert!(glob_match("/workspace/**", "/workspace/src/main.rs"));
        assert!(glob_match(
            "/workspace/**",
            "/workspace/deep/nested/file.rs"
        ));
        assert!(glob_match("**/.ssh/**", "/home/user/.ssh/id_rsa"));
        assert!(!glob_match("/workspace/**", "/etc/passwd"));
    }

    #[test]
    fn glob_question_mark() {
        assert!(glob_match("/tmp/?.txt", "/tmp/a.txt"));
        assert!(!glob_match("/tmp/?.txt", "/tmp/ab.txt"));
    }

    #[test]
    fn policy_file_access_deny_overrides_allow() {
        let policy = SandboxPolicy {
            filesystem: FsPolicy {
                allow_read: alloc::vec!["/workspace/**".into()],
                allow_write: alloc::vec!["/workspace/**".into()],
                deny: alloc::vec!["**/.git/**".into()],
            },
            ..Default::default()
        };
        assert_eq!(
            policy.check_file_access("/workspace/src/main.rs", false),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.check_file_access("/workspace/.git/config", false),
            PolicyDecision::Deny
        );
        assert_eq!(
            policy.check_file_access("/etc/passwd", false),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn policy_network_deny_all_with_allowlist() {
        let policy = SandboxPolicy {
            network: NetworkPolicy {
                deny_all: true,
                allow_connect: alloc::vec!["api.github.com:443".into()],
            },
            ..Default::default()
        };
        assert_eq!(
            policy.check_connect("api.github.com:443"),
            PolicyDecision::Allow
        );
        assert_eq!(policy.check_connect("evil.com:443"), PolicyDecision::Deny);
    }

    #[test]
    fn policy_exec_allowlist() {
        let policy = SandboxPolicy {
            process: ProcessPolicy {
                allow_exec: alloc::vec!["/usr/bin/*".into(), "/bin/*".into()],
            },
            ..Default::default()
        };
        assert_eq!(policy.check_exec("/usr/bin/python3"), PolicyDecision::Allow);
        assert_eq!(policy.check_exec("/tmp/malware"), PolicyDecision::Deny);
    }

    #[test]
    fn policy_empty_allows_everything() {
        let policy = SandboxPolicy::default();
        assert_eq!(
            policy.check_file_access("/anything", true),
            PolicyDecision::Allow
        );
        assert_eq!(policy.check_connect("anywhere:80"), PolicyDecision::Allow);
        assert_eq!(policy.check_exec("/anything"), PolicyDecision::Allow);
    }
}
