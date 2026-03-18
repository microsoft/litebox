// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Policy engine abstraction for the file broker.
//!
//! Provides a [`Policy`] trait that the broker consults on every file system
//! operation.  The default [`AllowAllPolicy`] permits everything — swap it out
//! for an Oso-backed implementation when the policy engine is integrated.

use std::path::Path;

/// The kind of file system operation being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Open,
    Read,
    Write,
    Stat,
    Chmod,
    Mkdir,
    Rmdir,
    Unlink,
    ReadDir,
    Truncate,
    Seek,
    Close,
}

/// Outcome of a policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// Policy engine consulted by the broker before performing host FS operations.
pub trait Policy: Send + Sync {
    /// Decide whether `action` is permitted on `path`.
    ///
    /// `path` is always relative to the broker's root directory.  An `None`
    /// path indicates an FD-only operation where no path context is available.
    fn check(&self, action: Action, path: Option<&Path>) -> Decision;

    /// Load or replace the policy rules from `text`.
    ///
    /// Returns an error message on failure.
    fn load_rules(&self, text: &str) -> Result<(), String>;
}

/// A policy that allows only read-only operations.
///
/// Write, Chmod, Mkdir, Rmdir, Unlink, and Truncate are denied.
/// Open, Read, Stat, ReadDir, Seek, and Close are permitted.
#[derive(Debug, Default)]
pub struct ReadOnlyPolicy;

impl Policy for ReadOnlyPolicy {
    fn check(&self, action: Action, _path: Option<&Path>) -> Decision {
        match action {
            Action::Open
            | Action::Read
            | Action::Stat
            | Action::ReadDir
            | Action::Seek
            | Action::Close => Decision::Allow,
            Action::Write
            | Action::Chmod
            | Action::Mkdir
            | Action::Rmdir
            | Action::Unlink
            | Action::Truncate => Decision::Deny,
        }
    }

    fn load_rules(&self, _text: &str) -> Result<(), String> {
        Err("ReadOnlyPolicy does not support dynamic rules".into())
    }
}

/// A policy that allows every operation unconditionally.
///
/// This is a development-time stub.  Replace with an Oso-backed policy for
/// production use.
#[derive(Debug, Default)]
pub struct AllowAllPolicy;

impl Policy for AllowAllPolicy {
    fn check(&self, _action: Action, _path: Option<&Path>) -> Decision {
        Decision::Allow
    }

    fn load_rules(&self, _text: &str) -> Result<(), String> {
        Ok(())
    }
}

/// A policy that is read-only everywhere except for explicitly listed writable
/// paths (and their children).
///
/// Write, Chmod, Mkdir, Rmdir, Unlink, and Truncate are permitted only when
/// the operation's path falls under one of the configured writable prefixes.
/// Everything else follows [`ReadOnlyPolicy`] semantics.
#[derive(Debug)]
pub struct ReadOnlyWithWritablePaths {
    writable_prefixes: Vec<std::path::PathBuf>,
}

impl ReadOnlyWithWritablePaths {
    /// Create a new policy with the given writable directory prefixes.
    ///
    /// Each prefix should be an absolute path.  A file operation is considered
    /// writable when its canonicalized path starts with any of these prefixes.
    pub fn new(writable_prefixes: Vec<std::path::PathBuf>) -> Self {
        Self { writable_prefixes }
    }

    fn path_is_writable(&self, path: Option<&Path>) -> bool {
        let Some(p) = path else { return false };
        self.writable_prefixes
            .iter()
            .any(|prefix| p.starts_with(prefix))
    }
}

impl Policy for ReadOnlyWithWritablePaths {
    fn check(&self, action: Action, path: Option<&Path>) -> Decision {
        match action {
            // Always allow read-side operations
            Action::Open
            | Action::Read
            | Action::Stat
            | Action::ReadDir
            | Action::Seek
            | Action::Close => Decision::Allow,
            // Write-side operations require the path to be under a writable prefix
            Action::Write
            | Action::Chmod
            | Action::Mkdir
            | Action::Rmdir
            | Action::Unlink
            | Action::Truncate => {
                if self.path_is_writable(path) {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
        }
    }

    fn load_rules(&self, _text: &str) -> Result<(), String> {
        Err("ReadOnlyWithWritablePaths does not support dynamic rules".into())
    }
}
