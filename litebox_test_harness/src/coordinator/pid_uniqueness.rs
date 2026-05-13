// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PID uniqueness + preservation across the multi-worker fork tree.
//!
//! Each test variant builds a tree of 7 processes:
//!
//! ```text
//! root (handler in dpg1)
//!   ├── child B
//!   │     ├── grandchild B1
//!   │     └── grandchild B2
//!   └── child C
//!         ├── grandchild C1
//!         └── grandchild C2
//! ```
//!
//! Variants differ only in the per-node binary type, picking transitions
//! that exercise the cross-binary-type spawn path (`exec_on_remote_host`).
//!
//! ## Data captured
//!
//! Every process emits two line types to stdout:
//!
//! 1. Its own existence:
//!    ```text
//!    P role=<R> pid=<getpid()> parent_pid=<getppid()> bt=<bt>
//!    ```
//!
//! 2. Per child it spawns, immediately after `Command::spawn`:
//!    ```text
//!    SPAWN role=<child-R> child_assigned_pid=<child.id()> bt=<child-bt>
//!    ```
//!
//! Interior nodes capture each child's stdout via
//! `child.wait_with_output()` and forward it. The root (handler) returns
//! the combined output via the typed response; the coordinator parses it.
//!
//! ## Assertions
//!
//! - **Count**: exactly 7 `P` lines (one per process).
//! - **Uniqueness**: all 7 `P pid=` values are distinct.
//! - **Preservation**: for every role with both a `SPAWN` and a `P` entry,
//!   `spawn.child_assigned_pid == p.pid` (validates `--guest-pid` carries
//!   the parent-allocated pid into the new worker's init Task).
//! - **Parent linkage**: each `P` line's `parent_pid` matches the
//!   parent role's `P pid` (validates `getppid()` returns the expected
//!   value across migration).
//!
//! ## Why the EV.fork_inherit "wait_with_output" hang doesn't bite here
//!
//! The hang documented in checkpoint 010 was caused by the *child binary*
//! blocking forever on a read of an inherited eventfd. Here every binary
//! does write-then-spawn-then-wait-then-exit; no blocking reads, no
//! infinite loops. Each level of the tree completes naturally, so the
//! stdout pipes close bottom-up and `wait_with_output` returns at each
//! level.

use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

// ─── Tree spec ──────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ChildSpec {
    /// Filesystem path of the binary to spawn for this child.
    binary: String,
    /// Stable bt label included in this child's emitted lines.
    bt: String,
    /// Test-tree role tag (e.g. `B`, `B1`, `C2`). Used by the validation
    /// to match SPAWN and P lines per process.
    role: String,
    /// Children this process should spawn in turn.
    recurse: Vec<ChildSpec>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PidTreeArgs {
    /// The two top-level children (B and C) the root spawns.
    children: Vec<ChildSpec>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PidTreeOut {
    /// Combined stdout from the entire tree (P lines + SPAWN lines, in
    /// stream order).
    combined_stdout: String,
}

const PID_TREE: HandlerToken<PidTreeArgs, PidTreeOut> =
    HandlerToken::new("pid_uniqueness.tree");

// ─── Handler (runs as the root in dpg1) ────────────────────────────

async fn handle_pid_tree(
    args: PidTreeArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PidTreeOut, HandlerError> {
    let mut out = String::new();
    let my_pid = std::process::id();
    // SAFETY: getppid() has no preconditions and is async-signal-safe.
    let my_ppid = unsafe { libc::getppid() };
    use core::fmt::Write as _;
    let _ = writeln!(
        out,
        "P role=root pid={} parent_pid={} bt=pie-glibc",
        my_pid, my_ppid
    );

    for spec in &args.children {
        spawn_and_collect(&mut out, spec)
            .map_err(|e| HandlerError(format!("spawn role={}: {e}", spec.role)))?;
    }

    Ok(PidTreeOut {
        combined_stdout: out,
    })
}

/// Spawn `spec` as a child, emit a SPAWN line for it, wait for it, and
/// append its stdout to `out`. Shared by the handler and the leaf
/// subcommand.
fn spawn_and_collect(out: &mut String, spec: &ChildSpec) -> Result<(), String> {
    use core::fmt::Write as _;
    let nested = serde_json::to_string(&spec.recurse)
        .map_err(|e| format!("encode recurse: {e}"))?;
    let mut cmd = Command::new(&spec.binary);
    cmd.args([
        "pid-uniq-tree",
        &format!("ROLE={}", spec.role),
        &format!("BT={}", spec.bt),
        &format!("SPECS={nested}"),
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    let child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", spec.binary))?;
    let child_pid = child.id();
    let _ = writeln!(
        out,
        "SPAWN role={} child_assigned_pid={} bt={}",
        spec.role, child_pid, spec.bt
    );
    let output = child
        .wait_with_output()
        .map_err(|e| format!("wait role={}: {e}", spec.role))?;
    out.push_str(&String::from_utf8_lossy(&output.stdout));
    Ok(())
}

// ─── Test registration ──────────────────────────────────────────────

struct TreeVariant {
    /// Test ID suffix: full ID is `PIDUNIQ.{name}`.
    name: &'static str,
    /// Returns the two top-level ChildSpecs (B and C subtrees) given the
    /// path to the running test harness binary.
    build: fn(&str) -> Vec<ChildSpec>,
}

const VARIANTS: &[TreeVariant] = &[
    TreeVariant {
        name: "same_bt.pie-glibc",
        build: build_same_bt_pie_glibc,
    },
    TreeVariant {
        name: "cross_bt_nonpie",
        build: build_cross_bt_nonpie,
    },
    TreeVariant {
        name: "cross_bt_diverse",
        build: build_cross_bt_diverse,
    },
];

fn build_same_bt_pie_glibc(self_exe: &str) -> Vec<ChildSpec> {
    let bin = crate::binary_path(crate::BinaryType::PieGlibc, self_exe);
    let bt = crate::BinaryType::PieGlibc.label().to_string();
    spec_uniform_two_level(&bin, &bt)
}

fn build_cross_bt_nonpie(self_exe: &str) -> Vec<ChildSpec> {
    let bin = crate::binary_path(crate::BinaryType::NonPieGlibc, self_exe);
    let bt = crate::BinaryType::NonPieGlibc.label().to_string();
    spec_uniform_two_level(&bin, &bt)
}

fn build_cross_bt_diverse(self_exe: &str) -> Vec<ChildSpec> {
    let pie = crate::binary_path(crate::BinaryType::PieGlibc, self_exe);
    let pie_bt = crate::BinaryType::PieGlibc.label().to_string();
    let nonpie = crate::binary_path(crate::BinaryType::NonPieGlibc, self_exe);
    let nonpie_bt = crate::BinaryType::NonPieGlibc.label().to_string();
    let spm = crate::binary_path(crate::BinaryType::StaticPieMusl, self_exe);
    let spm_bt = crate::BinaryType::StaticPieMusl.label().to_string();
    let snm = crate::binary_path(crate::BinaryType::NonPieStaticMusl, self_exe);
    let snm_bt = crate::BinaryType::NonPieStaticMusl.label().to_string();

    // B subtree: B=nonpie, B1=static-pie-musl, B2=nonpie (same as B).
    let b = ChildSpec {
        binary: nonpie.clone(),
        bt: nonpie_bt.clone(),
        role: "B".to_string(),
        recurse: vec![
            ChildSpec {
                binary: spm,
                bt: spm_bt,
                role: "B1".to_string(),
                recurse: vec![],
            },
            ChildSpec {
                binary: nonpie,
                bt: nonpie_bt,
                role: "B2".to_string(),
                recurse: vec![],
            },
        ],
    };
    // C subtree: C=non-pie-static-musl, C1=pie-glibc, C2=non-pie-static-musl.
    let c = ChildSpec {
        binary: snm.clone(),
        bt: snm_bt.clone(),
        role: "C".to_string(),
        recurse: vec![
            ChildSpec {
                binary: pie,
                bt: pie_bt,
                role: "C1".to_string(),
                recurse: vec![],
            },
            ChildSpec {
                binary: snm,
                bt: snm_bt,
                role: "C2".to_string(),
                recurse: vec![],
            },
        ],
    };
    vec![b, c]
}

/// Build a uniform two-level tree where every node uses the same
/// binary+bt: root → {B, C} → {B1, B2, C1, C2}.
fn spec_uniform_two_level(bin: &str, bt: &str) -> Vec<ChildSpec> {
    let mk_leaf = |role: &str| ChildSpec {
        binary: bin.to_string(),
        bt: bt.to_string(),
        role: role.to_string(),
        recurse: vec![],
    };
    let b = ChildSpec {
        binary: bin.to_string(),
        bt: bt.to_string(),
        role: "B".to_string(),
        recurse: vec![mk_leaf("B1"), mk_leaf("B2")],
    };
    let c = ChildSpec {
        binary: bin.to_string(),
        bt: bt.to_string(),
        role: "C".to_string(),
        recurse: vec![mk_leaf("C1"), mk_leaf("C2")],
    };
    vec![b, c]
}

pub(crate) fn register_pid_uniqueness_tests(reg: &mut Registry<'_>) {
    register_handler!(PID_TREE, handle_pid_tree);
    crate::register_leaf_subcommand!("pid-uniq-tree", |args: &[String]| -> i32 {
        leaf_subcmd::run(args)
    });

    for variant in VARIANTS {
        let name = variant.name;
        let build = variant.build;
        let id = format!("PIDUNIQ.{name}");
        reg.test("matrix", "pid_uniqueness", id)
            .timeout(60)
            .build(move |cx| {
                let agent = cx.require(AgentName::Dpg1);
                Box::new(move |run| {
                    Box::pin(async move {
                        let self_exe = run.self_exe().to_string();
                        let children = build(&self_exe);
                        let result = run
                            .send_named_typed(&agent, &PID_TREE, PidTreeArgs { children })
                            .await;
                        match result {
                            Ok(out) => validate(&out.combined_stdout, name),
                            Err(e) => TestOutcome::new(
                                "Dpg1",
                                false,
                                format!("handler error: {e}"),
                            ),
                        }
                    })
                })
            });
    }
}

// ─── Validation ─────────────────────────────────────────────────────

/// Expected total process count: root + 2 children + 4 grandchildren.
const EXPECTED_COUNT: usize = 7;

#[derive(Debug)]
#[allow(dead_code)] // bt is captured for forensic stdout dumps but not asserted.
struct ProcessLine {
    role: String,
    pid: u32,
    parent_pid: i32,
    bt: String,
}

#[derive(Debug)]
#[allow(dead_code)] // bt is captured for forensic stdout dumps but not asserted.
struct SpawnLine {
    role: String,
    child_assigned_pid: u32,
    bt: String,
}

fn validate(combined: &str, variant_name: &str) -> TestOutcome {
    let mut processes: Vec<ProcessLine> = Vec::new();
    let mut spawns: Vec<SpawnLine> = Vec::new();

    for line in combined.lines() {
        if let Some(rest) = line.strip_prefix("P ") {
            if let Some(p) = parse_p(rest) {
                processes.push(p);
            }
        } else if let Some(rest) = line.strip_prefix("SPAWN ") {
            if let Some(s) = parse_spawn(rest) {
                spawns.push(s);
            }
        }
    }

    // 1. Count check.
    if processes.len() != EXPECTED_COUNT {
        return TestOutcome::new(
            "Dpg1",
            false,
            format!(
                "{variant_name}: expected {} P lines, got {}\n---stdout---\n{}",
                EXPECTED_COUNT,
                processes.len(),
                combined
            ),
        );
    }

    // 2. Uniqueness check.
    let pids: Vec<u32> = processes.iter().map(|p| p.pid).collect();
    let mut by_pid: std::collections::HashMap<u32, Vec<&str>> = std::collections::HashMap::new();
    for p in &processes {
        by_pid.entry(p.pid).or_default().push(&p.role);
    }
    let duplicates: Vec<(u32, Vec<&str>)> = by_pid
        .iter()
        .filter(|(_, roles)| roles.len() > 1)
        .map(|(pid, roles)| (*pid, roles.clone()))
        .collect();
    if !duplicates.is_empty() {
        let mut msg = format!(
            "{variant_name}: pid collisions across {} processes (expected all distinct):\n",
            processes.len()
        );
        for (pid, roles) in &duplicates {
            msg.push_str(&format!("  pid={pid} used by roles {:?}\n", roles));
        }
        msg.push_str(&format!(
            "all pids: {:?}\n---stdout---\n{}",
            pids, combined
        ));
        return TestOutcome::new("Dpg1", false, msg);
    }

    // 3. Preservation check.
    let p_by_role: std::collections::HashMap<&str, &ProcessLine> = processes
        .iter()
        .map(|p| (p.role.as_str(), p))
        .collect();
    let mut pres_failures: Vec<String> = Vec::new();
    for s in &spawns {
        match p_by_role.get(s.role.as_str()) {
            None => pres_failures.push(format!(
                "role={}: SPAWN found but no matching P line",
                s.role
            )),
            Some(p) if p.pid != s.child_assigned_pid => pres_failures.push(format!(
                "role={}: parent saw child_assigned_pid={}, child reported pid={}",
                s.role, s.child_assigned_pid, p.pid
            )),
            _ => {}
        }
    }
    if !pres_failures.is_empty() {
        return TestOutcome::new(
            "Dpg1",
            false,
            format!(
                "{variant_name}: pid preservation failures:\n  {}\n---stdout---\n{}",
                pres_failures.join("\n  "),
                combined
            ),
        );
    }

    // 4. Parent linkage check.
    // Build role → expected parent role from the tree shape (root → B,C →
    // B1,B2 / C1,C2).
    let parent_of: std::collections::HashMap<&str, &str> = [
        ("B", "root"),
        ("C", "root"),
        ("B1", "B"),
        ("B2", "B"),
        ("C1", "C"),
        ("C2", "C"),
    ]
    .into_iter()
    .collect();
    let mut link_failures: Vec<String> = Vec::new();
    for p in &processes {
        if p.role == "root" {
            continue;
        }
        let parent_role = parent_of.get(p.role.as_str()).copied().unwrap_or("?");
        let parent_pid_expected = p_by_role.get(parent_role).map(|pp| pp.pid as i32);
        match parent_pid_expected {
            Some(expected) if expected != p.parent_pid => link_failures.push(format!(
                "role={}: parent_role={} expected_parent_pid={}, got parent_pid={}",
                p.role, parent_role, expected, p.parent_pid
            )),
            None => link_failures.push(format!(
                "role={}: parent_role={} not found in P lines",
                p.role, parent_role
            )),
            _ => {}
        }
    }
    if !link_failures.is_empty() {
        return TestOutcome::new(
            "Dpg1",
            false,
            format!(
                "{variant_name}: parent linkage failures:\n  {}\n---stdout---\n{}",
                link_failures.join("\n  "),
                combined
            ),
        );
    }

    TestOutcome::new(
        "Dpg1",
        true,
        format!(
            "{variant_name}: {} processes, all pids unique, preservation OK, parent linkage OK\npids: {:?}",
            processes.len(),
            pids
        ),
    )
}

fn parse_p(rest: &str) -> Option<ProcessLine> {
    let mut role: Option<&str> = None;
    let mut pid: Option<u32> = None;
    let mut parent_pid: Option<i32> = None;
    let mut bt: Option<&str> = None;
    for tok in rest.split_ascii_whitespace() {
        if let Some(v) = tok.strip_prefix("role=") {
            role = Some(v);
        } else if let Some(v) = tok.strip_prefix("pid=") {
            pid = v.parse().ok();
        } else if let Some(v) = tok.strip_prefix("parent_pid=") {
            parent_pid = v.parse().ok();
        } else if let Some(v) = tok.strip_prefix("bt=") {
            bt = Some(v);
        }
    }
    Some(ProcessLine {
        role: role?.to_string(),
        pid: pid?,
        parent_pid: parent_pid?,
        bt: bt?.to_string(),
    })
}

fn parse_spawn(rest: &str) -> Option<SpawnLine> {
    let mut role: Option<&str> = None;
    let mut child_assigned_pid: Option<u32> = None;
    let mut bt: Option<&str> = None;
    for tok in rest.split_ascii_whitespace() {
        if let Some(v) = tok.strip_prefix("role=") {
            role = Some(v);
        } else if let Some(v) = tok.strip_prefix("child_assigned_pid=") {
            child_assigned_pid = v.parse().ok();
        } else if let Some(v) = tok.strip_prefix("bt=") {
            bt = Some(v);
        }
    }
    Some(SpawnLine {
        role: role?.to_string(),
        child_assigned_pid: child_assigned_pid?,
        bt: bt?.to_string(),
    })
}

// ─── Leaf subcommand: `pid-uniq-tree ROLE=R BT=B SPECS=<json>` ─────

mod leaf_subcmd {
    use super::{ChildSpec, spawn_and_collect};
    use std::io::Write as _;

    pub(super) fn run(args: &[String]) -> i32 {
        let role = match kv(args, "ROLE=") {
            Some(v) => v,
            None => {
                eprintln!("pid-uniq-tree: missing ROLE= arg");
                return 2;
            }
        };
        let bt = match kv(args, "BT=") {
            Some(v) => v,
            None => {
                eprintln!("pid-uniq-tree: missing BT= arg");
                return 2;
            }
        };
        let specs_json = match kv(args, "SPECS=") {
            Some(v) => v,
            None => {
                eprintln!("pid-uniq-tree: missing SPECS= arg");
                return 2;
            }
        };
        let specs: Vec<ChildSpec> = match serde_json::from_str(&specs_json) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("pid-uniq-tree: bad SPECS json: {e}");
                return 2;
            }
        };

        let my_pid = std::process::id();
        // SAFETY: getppid() has no preconditions and is async-signal-safe.
        let my_ppid = unsafe { libc::getppid() };

        let mut out = String::new();
        use core::fmt::Write as _;
        let _ = writeln!(
            out,
            "P role={role} pid={my_pid} parent_pid={my_ppid} bt={bt}"
        );

        for spec in &specs {
            if let Err(e) = spawn_and_collect(&mut out, spec) {
                eprintln!("pid-uniq-tree role={role}: spawn failed: {e}");
                // Still write what we have so far so the coordinator sees
                // a partial tree (it'll trip the count check).
                break;
            }
        }

        // Single write to stdout. Use write_all to avoid println's
        // per-line locking overhead.
        let _ = std::io::stdout().write_all(out.as_bytes());
        0
    }

    fn kv(args: &[String], prefix: &str) -> Option<String> {
        args.iter()
            .find_map(|a| a.strip_prefix(prefix).map(|s| s.to_string()))
    }
}
