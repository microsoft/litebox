// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Argv-dispatch registry for the small set of leaf programs that
//! cannot be handlers.
//!
//! **Handlers are the default** — see `RunContext::run_leaf` for the
//! preferred path. A leaf program lives here only when the test
//! specifically needs fresh-argv-dispatched `main()` semantics that
//! an agent cannot provide:
//!
//! - **PTY tests**: the child's stdin must BE a PTY slave; an agent's
//!   stdin is the protocol pipe.
//! - **Stdio-inheritance tests**: the test verifies bytes flow
//!   through fork+exec stdio in a specific way; the agent owns those
//!   pipes.
//! - **Infinite-block probes** (e.g., `wait-forever`): would jam an
//!   agent's loop.
//! - **Bash-child invocations**: leaves spawned by a `bash -c` line
//!   inside a `common::BASH` handler are non-protocol children by
//!   definition.
//!
//! Each entry in this registry should have a doc-comment in its
//! family file explaining **why** it needs argv dispatch — that's
//! the deliberate escape-hatch marker.
//!
//! ## Usage
//!
//! In a family file (e.g., `coordinator/pty.rs`):
//!
//! ```ignore
//! /// Reads SIGWINCH, prints `RESIZE rows= cols=`, exits.
//! /// Lives as a leaf subcommand because the child's stdin must
//! /// be a PTY slave (set up by the parent via TIOCSWINSZ + dup2).
//! fn subcmd_pty_resize(_args: &[String]) -> i32 {
//!     // body
//!     0
//! }
//!
//! pub(crate) fn register_pty(reg: &mut Registry<'_>) {
//!     register_leaf_subcommand!("pty-resize", subcmd_pty_resize);
//!     // existing handler / test registrations …
//! }
//! ```
//!
//! `main.rs` calls [`dispatch`] very early in `main()` to route any
//! registered subcommand; if no match, dispatch falls through to the
//! existing argv `match`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Signature of a leaf subcommand: receives the full argv vector
/// (including `argv[0] = self_exe` and `argv[1] = "<name>"`), returns
/// the process exit code.
#[allow(dead_code)] // populated by family register_* fns as B-phases land
pub(crate) type SubcommandFn = fn(args: &[String]) -> i32;

#[allow(dead_code)]
fn table() -> &'static Mutex<HashMap<&'static str, SubcommandFn>> {
    static T: OnceLock<Mutex<HashMap<&'static str, SubcommandFn>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a leaf subcommand under `name`. Re-registration of the
/// same `(name, fn)` pair is idempotent; re-registration with a
/// different `fn` is a developer error and panics in debug.
#[allow(dead_code)] // called by family register_* fns as B-phases land
pub(crate) fn register(name: &'static str, f: SubcommandFn) {
    let mut t = table().lock().expect("leaf subcommand table");
    match t.insert(name, f) {
        None => {}
        Some(prev) if std::ptr::fn_addr_eq(prev, f) => {}
        Some(_) => {
            debug_assert!(
                false,
                "leaf subcommand {name:?} re-registered with a different function"
            );
        }
    }
}

/// Look up `argv[1]` in the registry; if found, invoke the
/// subcommand and return `Some(exit_code)`. Returns `None` if no
/// subcommand is registered under that name (caller falls through
/// to the legacy `main.rs` `match`).
#[allow(dead_code)] // called from main.rs at process entry
#[must_use]
pub fn dispatch(args: &[String]) -> Option<i32> {
    let cmd = args.get(1)?;
    let f = {
        let t = table().lock().expect("leaf subcommand table");
        *t.get(cmd.as_str())?
    };
    Some(f(args))
}

/// Register a leaf subcommand. Use this in a family's
/// `register_*(reg)` function for leaves that cannot be handlers.
/// See the module doc-comment for the criteria.
#[macro_export]
macro_rules! register_leaf_subcommand {
    ($name:literal, $fn:expr) => {
        $crate::coordinator::leaf_subcommand::register($name, $fn);
    };
}
