// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `framework::run_trial` — single entry point for every test
//! family's container lifecycle.
//!
//! ## Why
//!
//! Different test families (standard coordinator tests, dropbear
//! SSH tests, eventually VS Code) all need the same scaffolding
//! around each test run: acquire the cross-session dispatch gate,
//! allocate a canonical container name, apply `PR_SET_PDEATHSIG`,
//! register with the cleanup module so SIGTERM reaps in-flight
//! containers, hand off the docker-run child to `spawn_drain` (or
//! tear it down explicitly for detached containers), and record the
//! result to the dashboard. Before this module existed, each
//! family open-coded its own version of those steps and dropbear
//! omitted most of them — leading to leaked containers on harness
//! shutdown.
//!
//! ## Surface
//!
//! Per-family variation is ONLY:
//!   - `ContainerSpec` (image + container command + docker args
//!     + foreground-or-detached + timeout)
//!   - a `drive` closure that receives the running container and
//!     returns a `DriveResult` (verdict + timings).
//!
//! Everything else lives here. Adding a new test family is a new
//! `ContainerSpec` + a new drive closure + a new trial registration
//! in `main()` — no new cleanup or throttling code.
//!
//! ## Container-name uniqueness
//!
//! Names are `litebox-{pass}-{tid}-{harness_pid}-{counter}` where:
//!   - `harness_pid` salts across concurrent coding-agent sessions
//!     on the same host (each session's `integration-*` binary has
//!     a distinct PID at any moment),
//!   - `counter` is a process-static `AtomicU64` so two concurrent
//!     dispatches within the same harness can never collide (the
//!     old `subsec_nanos()` suffix could collide if two threads
//!     called `SystemTime::now()` at the same nanosecond within the
//!     same wall-second).

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

// `cleanup` is a sibling-module inside `tests/integration.rs`.
// Access via `crate::` because this file is `#[path]`-included by
// the integration test binary.
use crate::cleanup;

// Pure helpers (no crate-private deps) live in framework_core so
// they can be unit-tested from tests/dashboard_store.rs.
#[path = "framework_core.rs"]
mod core;

use core::build_docker_run_args;
pub use core::{ContainerSpec, container_name};

/// What a `drive` closure receives once the container is running.
pub struct DispatchedContainer {
    pub name: String,
    /// `Some` for foreground containers (stdout/stderr piped);
    /// `None` for detached (the docker-run process already exited).
    pub child: Option<Child>,
    /// container_port → host_port. Populated for detached containers
    /// whose spec asked for port publishing; empty otherwise.
    pub published_ports: HashMap<u16, u16>,
}

/// What a `drive` closure returns.
pub struct DriveResult {
    /// `"pass"` | `"fail"` | `"no_result"` | `"other"`.
    pub verdict: &'static str,
    /// On non-`pass`: human-readable detail for the test failure
    /// message.
    pub detail: Option<String>,
    /// Time the container took to become useful (container start +
    /// any in-container warmup before the drive closure could
    /// productively interact).
    pub t_docker_start_ms: u128,
    /// Wall time the drive closure spent on actual test work,
    /// after the container was useful.
    pub t_useful_ms: u128,
    /// Standard tests' in-container sub-phase breakdown. For
    /// families that don't have it, leave at `Default::default()`.
    pub sub_phases: crate::SubPhaseMs,
    pub t_docker_spawn_ms: Option<u128>,
    pub t_litebox_init_ms: Option<u128>,
    pub t_harness_load_ms: Option<u128>,
}

/// Apply `PR_SET_PDEATHSIG=SIGTERM` to a docker-run child via
/// `pre_exec`. Harmless for detached containers (the docker-run
/// host process exits quickly after spawning, so PDEATHSIG never
/// fires) and beneficial for foreground containers.
fn apply_pdeathsig(cmd: &mut Command) {
    // SAFETY: `pre_exec` runs post-fork(2) pre-execve(2) in a
    // single-threaded context; `prctl(2)` is async-signal-safe
    // (see signal-safety(7)). The flag is process-private and has
    // no global side effects beyond this child.
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
            Ok(())
        });
    }
}

/// Build the full `docker run` command from a `ContainerSpec` +
/// the framework-allocated container name. Delegates argument
/// layout to `build_docker_run_args` (pure, testable) and adds
/// the side-effectful `pre_exec(PDEATHSIG)` hook.
fn build_command(spec: &ContainerSpec, name: &str) -> Command {
    let keep_containers = std::env::var("LITEBOX_KEEP_CONTAINER").is_ok();
    let args = build_docker_run_args(spec, name, keep_containers);
    let mut cmd = crate::docker_command();
    cmd.args(&args);
    apply_pdeathsig(&mut cmd);
    cmd
}

/// Query `docker port <name>` and parse out published host ports.
/// Returns an empty map if the container publishes no ports.
fn query_published_ports(name: &str) -> HashMap<u16, u16> {
    let out = crate::docker_command().args(["port", name]).output().ok();
    let mut ports = HashMap::new();
    let Some(out) = out else { return ports };
    if !out.status.success() {
        return ports;
    }
    // `docker port` lines look like:
    //   22/tcp -> 0.0.0.0:32774
    //   22/tcp -> [::]:32774
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        let Some((container_part, host_part)) = line.split_once(" -> ") else {
            continue;
        };
        let container_port: u16 = container_part
            .trim()
            .split_once('/')
            .map(|(p, _)| p)
            .unwrap_or("")
            .parse()
            .unwrap_or(0);
        if container_port == 0 {
            continue;
        }
        let host_port: u16 = host_part
            .rsplit_once(':')
            .map(|(_, p)| p)
            .unwrap_or("")
            .parse()
            .unwrap_or(0);
        if host_port == 0 {
            continue;
        }
        // Only the first mapping per container port — there may be
        // both IPv4 and IPv6 lines for the same mapping; same port.
        ports.entry(container_port).or_insert(host_port);
    }
    ports
}

/// Force-remove a container by name and deregister from cleanup.
/// Idempotent. Caller invokes this for detached containers after
/// `drive` returns, regardless of verdict.
///
/// Respects `LITEBOX_KEEP_CONTAINER`: if set, we deregister from
/// the cleanup module's tracking (so SIGTERM-time reap doesn't
/// later remove it either) but skip the `docker rm -f`. The
/// container remains in `docker ps -a` for post-mortem inspection.
fn tear_down_detached(name: &str) {
    if std::env::var("LITEBOX_KEEP_CONTAINER").is_err() {
        let mut cmd = Command::new("timeout");
        crate::set_native_docker_host_if_unset(&mut cmd);
        let _ = cmd
            .args(["10", "docker", "rm", "-f", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    cleanup::deregister_docker_child(name);
}

/// Drop guard so the cleanup registry entry is removed even if
/// `drive` panics. Belt-and-suspenders with the signal-handler
/// `reap_all` path.
struct RegistryGuard {
    name: String,
    /// Set to false after explicit teardown so Drop doesn't
    /// double-deregister.
    armed: bool,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        if self.armed {
            cleanup::deregister_docker_child(&self.name);
        }
    }
}

/// One entry point per test family. Steps:
///
///   1. Acquire `active_jobs()` permit (the lease-aware dispatch
///      gate). Held until trial completion.
///   2. Allocate canonical container name.
///   3. Build the `docker run` command from `spec`, with
///      `--name`, `--rm`, `pre_exec(PDEATHSIG)`, and detached or
///      foreground.
///   4. Spawn. Register with the cleanup module so SIGTERM reaps
///      it. Install a Drop guard so panic in `drive` still
///      deregisters.
///   5. For detached: wait for `docker run -d` to return; query
///      published ports.
///   6. Call `drive(container)`.
///   7. After `drive` returns: for foreground hand the child to
///      `crate::spawn_drain`; for detached `docker rm -f` the
///      container.
///   8. Record via `crate::emit_timing_main`.
///   9. Return Ok(()) if verdict == "pass", else Err(detail).
pub fn run_trial<F>(
    pass: &'static str,
    test_id: &str,
    suite: &'static str,
    group: &'static str,
    spec: ContainerSpec,
    drive: F,
) -> Result<(), libtest_mimic::Failed>
where
    F: FnOnce(&mut DispatchedContainer) -> DriveResult,
{
    let t_start = std::time::Instant::now();
    let _permit = crate::active_jobs().acquire();
    let t_acquired = std::time::Instant::now();
    let t_acquire_ms = t_acquired.duration_since(t_start).as_millis();

    let name = container_name(pass, test_id);
    let mut cmd = build_command(&spec, &name);
    if spec.detached {
        // For detached spawn: pipe stderr so we can capture the
        // docker daemon's error message on failure (e.g. "image
        // not found", "port already allocated"). Stdout for `-d`
        // is just the container ID; pipe + drain so the pipe
        // buffer doesn't fill.
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
    } else {
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
    }

    let t_spawn = std::time::Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("docker spawn failed for {name}: {e}"))?;
    let pid = child.id();
    cleanup::register_docker_child(pid, &name, /* pid_alive */ !spec.detached);
    let mut guard = RegistryGuard {
        name: name.clone(),
        armed: true,
    };

    let dispatched = if spec.detached {
        // Wait for the docker-run process to return (it exits as
        // soon as the container starts), collecting its stdout/stderr.
        // `wait_with_output` consumes the Child so we can capture
        // both streams + status in one go.
        let out = child.wait_with_output();
        let failed = out.as_ref().map(|o| !o.status.success()).unwrap_or(true);
        if failed {
            // docker run -d failed; tear down (just in case the
            // container partially started) and bail with the
            // captured stderr so the user can see what docker said.
            // Respect LITEBOX_KEEP_CONTAINER even on the bail path:
            // a partially-failed spawn might leave debug breadcrumbs.
            if std::env::var("LITEBOX_KEEP_CONTAINER").is_err() {
                let _ = crate::docker_command()
                    .args(["rm", "-f", &name])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            guard.armed = false;
            cleanup::deregister_docker_child(&name);
            let detail = match out {
                Ok(o) => format!(
                    "docker run -d failed for {name} (exit {}): {}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr).trim(),
                ),
                Err(e) => format!("docker run -d wait failed for {name}: {e}"),
            };
            return Err(detail.into());
        }
        // The detached docker-run host PID is now invalid; mark the
        // cleanup entry so reap_all skips the kill step.
        cleanup::register_docker_child(pid, &name, /* pid_alive */ false);
        let ports = query_published_ports(&name);
        DispatchedContainer {
            name: name.clone(),
            child: None,
            published_ports: ports,
        }
    } else {
        DispatchedContainer {
            name: name.clone(),
            child: Some(child),
            published_ports: HashMap::new(),
        }
    };

    // Drive — family-specific work.
    let mut dispatched = dispatched;
    let result = drive(&mut dispatched);
    // The drive closure may have taken `child` for spawn_drain
    // hand-off; if it didn't and the container is foreground, we
    // need to hand off ourselves.
    let final_child = dispatched.child.take();

    // Tear down or hand off.
    let _t_drain_start = std::time::Instant::now();
    if spec.detached {
        tear_down_detached(&name);
        guard.armed = false;
    } else if let Some(child) = final_child {
        // crate::spawn_drain owns deregistration on drain completion.
        crate::spawn_drain(
            child,
            name.clone(),
            test_id.to_string(),
            pass,
            _t_drain_start,
        );
        guard.armed = false;
    } else {
        // Foreground spec but drive returned without leaving a
        // child — must have already wait()ed it. Deregister.
        cleanup::deregister_docker_child(&name);
        guard.armed = false;
    }
    drop(guard);

    // Record. Single source of truth — every family calls
    // emit_timing_main via this path.
    crate::emit_timing_main(
        test_id,
        pass,
        suite,
        group,
        t_acquire_ms,
        result.t_docker_start_ms,
        result.t_docker_spawn_ms,
        result.t_litebox_init_ms,
        result.t_harness_load_ms,
        &result.sub_phases,
        result.t_useful_ms,
        result.verdict,
        crate::current_jobs_cap(),
    );
    let _ = t_spawn;

    if result.verdict == "pass" {
        Ok(())
    } else {
        Err(result
            .detail
            .unwrap_or_else(|| format!("{pass}::{test_id}: verdict={}", result.verdict))
            .into())
    }
}

#[allow(dead_code)]
const _: Duration = Duration::from_secs(0);
