// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `LITEBOX_HARNESS_PAUSE` "soft breakpoint" facility.
//!
//! Set the env var `LITEBOX_HARNESS_PAUSE` to one or more pause-point
//! specs (comma-separated). At each matching site the current process
//! prints `[litebox-pause] tag=... filter=... pid=N waiting for SIGCONT`
//! on stderr and `raise(SIGSTOP)`s itself. Resume with
//! `kill -CONT <pid>`.
//!
//! Spec syntax: `tag[=filter]`, where `tag` is one of the well-known
//! pause-point names (e.g., `harness:test-start`, `harness:test-end-fail`)
//! and `filter` is a free-form string compared verbatim against the
//! filter argument passed at the call site (typically a test ID). If
//! `=filter` is omitted, the tag matches with any filter.
//!
//! Examples:
//!
//! ```text
//! LITEBOX_HARNESS_PAUSE='harness:test-start=PB.c2p.nonpie-glibc.dpg2'
//! LITEBOX_HARNESS_PAUSE='harness:test-end-fail'
//! LITEBOX_HARNESS_PAUSE='harness:test-start=PB.a,harness:test-end-fail'
//! ```
//!
//! Why pause points instead of gdb breakpoints:
//!  * Pause only the matching process; siblings keep running and the
//!    broker/runner protocol doesn't deadlock.
//!  * Filter is plain code, not a fragile gdb conditional breakpoint.
//!  * Source-code site, not a symbol-resolution problem under
//!    monomorphization.
//!  * No attach race — gdb can attach *after* the pause is in effect.
//!
//! Cost when the env var is unset: one `OnceLock` load + an empty-vec
//! comparison.
//!
//! See `dev_tools/gdb-example-session.md` and `FIX_AGENT_PLAYBOOK.md`
//! "Pause points" section for end-to-end usage patterns.

use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PauseSpec {
    tag: String,
    /// `None` means "match this tag regardless of filter".
    filter: Option<String>,
}

impl PauseSpec {
    fn matches(&self, tag: &str, filter: &str) -> bool {
        if self.tag != tag {
            return false;
        }
        match &self.filter {
            None => true,
            Some(f) => f == filter,
        }
    }
}

fn parse_specs(raw: &str) -> Vec<PauseSpec> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| match s.split_once('=') {
            Some((t, f)) => PauseSpec {
                tag: t.trim().to_string(),
                filter: Some(f.trim().to_string()),
            },
            None => PauseSpec {
                tag: s.to_string(),
                filter: None,
            },
        })
        .collect()
}

fn specs() -> &'static [PauseSpec] {
    static SPECS: OnceLock<Vec<PauseSpec>> = OnceLock::new();
    SPECS.get_or_init(|| {
        std::env::var("LITEBOX_HARNESS_PAUSE")
            .ok()
            .map(|s| parse_specs(&s))
            .unwrap_or_default()
    })
}

/// True if any active spec matches `(tag, filter)`. Cheap to call
/// from a hot path when the env var is unset (returns immediately on
/// an empty slice).
#[inline]
pub fn should_pause(tag: &str, filter: &str) -> bool {
    let s = specs();
    if s.is_empty() {
        return false;
    }
    s.iter().any(|spec| spec.matches(tag, filter))
}

/// If any active spec matches, print a `[litebox-pause]` marker on
/// stderr and `raise(SIGSTOP)` self. Returns once SIGCONT is delivered.
///
/// Call this at well-known sites (test start, end-pass, end-fail,
/// etc.). When the env var is unset this is a fast no-op (single
/// load + empty-vec test).
pub fn pause_if_match(tag: &str, filter: &str) {
    if !should_pause(tag, filter) {
        return;
    }
    let pid = std::process::id();
    // Distinct prefix so the marker can't be confused with the
    // harness's protocol JSON output.
    eprintln!(
        "[litebox-pause] tag={tag} filter={filter} pid={pid} waiting for SIGCONT \
         (resume with: kill -CONT {pid})"
    );
    // SAFETY: SIGSTOP is a valid signal; raise(2) is async-signal-safe
    // and only stops the current thread group.
    let _ = unsafe { libc::raise(libc::SIGSTOP) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty() {
        assert_eq!(parse_specs(""), Vec::<PauseSpec>::new());
    }

    #[test]
    fn parse_single_tag() {
        let s = parse_specs("harness:test-start");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].tag, "harness:test-start");
        assert_eq!(s[0].filter, None);
    }

    #[test]
    fn parse_tag_with_filter() {
        let s = parse_specs("harness:test-start=PB.c2p.dpg1");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].tag, "harness:test-start");
        assert_eq!(s[0].filter, Some("PB.c2p.dpg1".to_string()));
    }

    #[test]
    fn parse_multiple_comma_separated() {
        let s = parse_specs("harness:test-end-fail,harness:test-start=PB");
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].tag, "harness:test-end-fail");
        assert_eq!(s[0].filter, None);
        assert_eq!(s[1].tag, "harness:test-start");
        assert_eq!(s[1].filter, Some("PB".to_string()));
    }

    #[test]
    fn matches_tag_only() {
        let spec = PauseSpec {
            tag: "harness:test-start".to_string(),
            filter: None,
        };
        assert!(spec.matches("harness:test-start", "anything"));
        assert!(spec.matches("harness:test-start", ""));
        assert!(!spec.matches("harness:test-end", "anything"));
    }

    #[test]
    fn matches_tag_and_filter() {
        let spec = PauseSpec {
            tag: "harness:test-start".to_string(),
            filter: Some("PB.c2p".to_string()),
        };
        assert!(spec.matches("harness:test-start", "PB.c2p"));
        assert!(!spec.matches("harness:test-start", "PB.sp"));
        assert!(!spec.matches("harness:test-end", "PB.c2p"));
    }
}
