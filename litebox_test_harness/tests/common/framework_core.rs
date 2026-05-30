// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Pure helpers extracted from `framework.rs` so they can be
//! unit-tested independently of the integration test binary's
//! crate-private modules (`cleanup`, `SubPhaseMs`, etc.).
//!
//! This module:
//!   * has NO dependencies on crate-private items;
//!   * is included via `#[path]` from both the integration test
//!     binary (`tests/integration.rs` → `framework.rs` → here) and
//!     from `tests/dashboard_store.rs` for direct unit testing;
//!   * exposes the deterministic, side-effect-free building blocks
//!     `container_name` and `build_docker_run_args`.

use std::sync::atomic::{AtomicU64, Ordering};

/// Per-test-family container description. Plus how to invoke the
/// container — `detached=true` for `docker run -d`, false for
/// foreground (the docker-run process stays alive until the
/// container exits).
pub struct ContainerSpec {
    pub image: String,
    /// Extra `docker run` arguments between `--name X` and the
    /// image — e.g. `-v`, `-e`, `--cap-add`, `-p`,
    /// `--security-opt`.
    pub docker_args: Vec<String>,
    /// The container command (after the image, what to run inside).
    pub command: Vec<String>,
    pub detached: bool,
    /// If `Some(secs)`, wrap `command` with `timeout(1)` for a
    /// hard per-trial cap. Set to `None` to let the inner command
    /// manage its own timeout.
    pub timeout_secs: Option<u64>,
}

static NAME_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Build the canonical container name. Uniqueness rules:
///
///   * `harness_pid` salts across concurrent coding-agent sessions
///     on the same host (each integration test binary has a
///     distinct PID at any moment).
///   * `counter` is a process-static `AtomicU64` so two concurrent
///     dispatches within the same harness can never collide (the
///     old `subsec_nanos()` suffix could collide if two threads
///     called `SystemTime::now()` at the same nanosecond).
///   * `test_id` is sanitized to alphanumeric or `-` so docker
///     accepts it as a name (docker name regex is `[a-zA-Z0-9][a-zA-Z0-9_.-]*`).
pub fn container_name(pass: &str, test_id: &str) -> String {
    let safe_tid: String = test_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let counter = NAME_COUNTER.fetch_add(1, Ordering::Relaxed);
    let harness_pid = std::process::id();
    format!("litebox-{pass}-{safe_tid}-{harness_pid}-{counter}")
}

/// Build the full `docker run` argument vector (everything that
/// goes after `docker`) from a `ContainerSpec` + the
/// framework-allocated container name + the `keep_containers` env
/// flag. Returns the args as a `Vec<String>` so callers (real
/// spawn AND tests) can inspect it.
///
/// Layout:
///   `["run", ("-d"?), ("--rm"?), "--name", <name>, <docker_args>...,
///     <image>, ("timeout", "--signal=KILL", <secs>?), <command>...]`
///
/// `keep_containers=true` omits `--rm` so the container survives
/// in `docker ps -a` for post-mortem inspection.
pub fn build_docker_run_args(
    spec: &ContainerSpec,
    name: &str,
    keep_containers: bool,
) -> Vec<String> {
    let mut v: Vec<String> = Vec::with_capacity(8 + spec.docker_args.len() + spec.command.len());
    v.push("run".into());
    if spec.detached {
        v.push("-d".into());
    }
    if !keep_containers {
        v.push("--rm".into());
    }
    v.push("--name".into());
    v.push(name.to_string());
    v.extend(spec.docker_args.iter().cloned());
    v.push(spec.image.clone());
    if let Some(secs) = spec.timeout_secs {
        v.push("timeout".into());
        v.push("--signal=KILL".into());
        v.push(secs.to_string());
    }
    v.extend(spec.command.iter().cloned());
    v
}
