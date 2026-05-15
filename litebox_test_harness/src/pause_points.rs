// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `LITEBOX_HARNESS_PAUSE` "soft breakpoint" facility.
//!
//! Set the env var `LITEBOX_HARNESS_PAUSE` to one or more pause-point
//! specs (comma-separated). At each matching site the current process
//! prints `[litebox-pause] tag=... filter=... pid=N waiting for SIGCONT`
//! on stderr and waits for SIGCONT. Resume with `kill -CONT <pid>`.
//!
//! Implementation note: we install a no-op SIGCONT handler and call
//! `pause(2)`. We do **not** use `raise(SIGSTOP)` because the harness
//! is typically pid 1 inside its docker container, and Linux silently
//! ignores SIGSTOP on pid 1 (kernel init protection).
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
/// stderr and wait for SIGCONT.
///
/// We install a no-op SIGCONT handler and then `pause()`. We do
/// **not** use `raise(SIGSTOP)` because the harness is typically
/// pid 1 inside its docker container, and Linux silently ignores
/// SIGSTOP on pid 1 (kernel init protection). The pause/signal-handler
/// pattern works regardless of pid.
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
    install_sigcont_handler();
    // SAFETY: pause(2) blocks until any non-ignored signal is
    // delivered; with our SIGCONT handler installed this returns
    // when the user resumes. No memory or thread invariants involved.
    let _ = unsafe { libc::pause() };
}

/// Install a no-op SIGCONT handler on first call so that subsequent
/// `pause()` calls wake up when SIGCONT arrives instead of dying or
/// being ignored. Idempotent.
fn install_sigcont_handler() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        extern "C" fn noop_handler(_signum: libc::c_int) {}
        // SAFETY: sigaction with a SIG_DFL-shaped no-op handler is
        // well-defined. We zero-init the struct to set sa_flags=0,
        // empty mask, and sa_sigaction=handler. We accept the loss
        // of any prior SIGCONT handler (the only realistic prior
        // is SIG_DFL, since pid-1 init implicitly inherits IGN for
        // SIGCONT but we want a real handler).
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = noop_handler as *const () as usize;
            let _ = libc::sigaction(libc::SIGCONT, &sa, std::ptr::null_mut());
        }
    });
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
