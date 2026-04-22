// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform fix validation tests — matrix-loop tests that prove specific bug
//! fixes are needed by exercising the exact behavior each fix corrected.
//!
//! Each test category targets a commit in the wportnoy/vscode-server-in-litebox
//! branch and must pass on both native WSL2 (gold standard) and litebox.

use super::{TestRunner, exec};
use crate::protocol::{Command, Response};

const AGENTS: &[&str] = &["A", "AA", "B"];
const DEPTH_AGENTS: &[&str] = &["A", "AA"];

// ═══════════════════════════════════════════════════════════════════
// POLL: epoll/ppoll IN events (fix 0fb258e2)
// ═══════════════════════════════════════════════════════════════════

/// Verify that poll() returns POLLIN for a pipe with data available.
/// Without fix 0fb258e2, file descriptors only reported OUT events,
/// causing shells to hang when polling stdin for readability.
pub(crate) async fn poll_ready_tests(r: &mut TestRunner) {
    eprintln!("[platform] === Poll Ready ({} agents) ===", AGENTS.len());

    for &agent in AGENTS {
        let test_id = format!("POLL.pipe.{agent}");
        let resp = r.send(agent, Command::PollReady { timeout_ms: 2000 }).await;
        let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "POLLIN");
        r.record(&test_id, agent, pass, &format!("{resp:?}"));
    }
}

// ═══════════════════════════════════════════════════════════════════
// GSN: getsockname port after bind (fix 336dc79e)
// ═══════════════════════════════════════════════════════════════════

const FAMILIES: &[&str] = &["ipv4", "ipv6"];

/// Verify that getsockname returns a nonzero port after bind(ANY, 0).
/// Without fix 336dc79e, smoltcp returned None for the local endpoint
/// of bound-but-not-connected sockets, yielding port 0.
pub(crate) async fn bind_getsockname_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Bind+Getsockname ({} families × {} agents) ===",
        FAMILIES.len(),
        DEPTH_AGENTS.len()
    );

    for &family in FAMILIES {
        for &agent in DEPTH_AGENTS {
            let test_id = format!("GSN.{family}.{agent}");
            let resp = r
                .send(
                    agent,
                    Command::BindGetsockname {
                        family: family.to_string(),
                    },
                )
                .await;
            let pass = match &resp {
                Response::Ok { data: Some(d) } => {
                    // Parse "port=NNNN" and verify > 0.
                    d.strip_prefix("port=")
                        .and_then(|s| s.parse::<u16>().ok())
                        .map_or(false, |p| p > 0)
                }
                _ => false,
            };
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// PID: monotonic pipe pair_id (fix c2d0abdc)
// ═══════════════════════════════════════════════════════════════════

/// Verify that pipe pair IDs are unique even after create+drop+recreate.
/// Without fix c2d0abdc, Arc::as_ptr() was used for pair_id, and the
/// allocator could reuse addresses after free, causing ID collisions
/// in mux_pipe_pair_ids.
pub(crate) async fn pipe_pair_id_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Pipe Pair ID Unique ({} agents) ===",
        AGENTS.len()
    );

    for &agent in AGENTS {
        let test_id = format!("PID.{agent}");
        let resp = r
            .send(agent, Command::PipePairIdUnique { count: 100 })
            .await;
        let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "unique");
        r.record(&test_id, agent, pass, &format!("{resp:?}"));
    }
}

// ═══════════════════════════════════════════════════════════════════
// EXITD: bridge thread join before exit (fix 2def3ac6)
// ═══════════════════════════════════════════════════════════════════

const EXIT_SIZES: &[usize] = &[256, 4096, 65536];
const EXIT_BINARIES: &[&str] = &["pie", "nonpie"];

/// Verify that large writes complete fully before process exit.
/// Without fix 2def3ac6, bridge threads were not joined before
/// exit_group, causing data truncation on large stdout writes.
pub(crate) async fn exit_data_integrity_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Exit Data Integrity ({} sizes × {} binaries × {} agents) ===",
        EXIT_SIZES.len(),
        EXIT_BINARIES.len(),
        DEPTH_AGENTS.len()
    );

    let self_exe = r.self_exe.clone();
    let nonpie = crate::find_nonpie_binary();

    for &size in EXIT_SIZES {
        for &binary in EXIT_BINARIES {
            let bin_path = match binary {
                "pie" => self_exe.clone(),
                "nonpie" => match &nonpie {
                    Some(p) => p.clone(),
                    None => {
                        for &agent in DEPTH_AGENTS {
                            let test_id = format!("EXITD.{size}.{binary}.{agent}");
                            r.record(&test_id, agent, true, "skipped (nonpie binary not found)");
                        }
                        continue;
                    }
                },
                _ => unreachable!(),
            };

            for &agent in DEPTH_AGENTS {
                let test_id = format!("EXITD.{size}.{binary}.{agent}");
                let resp = r
                    .send(
                        agent,
                        exec(vec![
                            bin_path.clone(),
                            "write-then-exit".into(),
                            size.to_string(),
                        ]),
                    )
                    .await;
                let pass = match &resp {
                    Response::ExecResult {
                        exit_code: 0,
                        stdout,
                        ..
                    } => stdout.len() == size,
                    _ => false,
                };
                let detail = match &resp {
                    Response::ExecResult { stdout, .. } => {
                        format!("got {} bytes, expected {size}", stdout.len())
                    }
                    _ => format!("{resp:?}"),
                };
                r.record(&test_id, agent, pass, &detail);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// NPIPE: non-PIE pipe chain integrity (fix febc3e41)
// ═══════════════════════════════════════════════════════════════════

const NPIPE_REPS: &[usize] = &[1, 5, 10];

/// Verify that repeated non-PIE execs produce clean pipe output.
/// Without the proper pipe chain handling, data from one exec could
/// leak into subsequent execs via stale mux_pipe_pair_ids entries.
///
/// Tests two patterns:
/// - Sequential non-PIE: N consecutive non-PIE execs on same agent
/// - Interleaved: alternating PIE and non-PIE execs on same agent
pub(crate) async fn nonpie_pipe_chain_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();
    let nonpie = match crate::find_nonpie_binary() {
        Some(p) => p,
        None => {
            eprintln!("[platform] === Non-PIE Pipe Chain (SKIPPED — no nonpie binary) ===");
            // Record skips for all planned test IDs.
            for &reps in NPIPE_REPS {
                for pattern in &["seq", "interleaved"] {
                    for &agent in DEPTH_AGENTS {
                        let test_id = format!("NPIPE.{pattern}.x{reps}.{agent}");
                        r.record(&test_id, agent, true, "skipped (nonpie binary not found)");
                    }
                }
            }
            return;
        }
    };

    eprintln!(
        "[platform] === Non-PIE Pipe Chain ({} reps × 2 patterns × {} agents) ===",
        NPIPE_REPS.len(),
        DEPTH_AGENTS.len()
    );

    for &reps in NPIPE_REPS {
        for &agent in DEPTH_AGENTS {
            // Sequential non-PIE pattern.
            {
                let test_id = format!("NPIPE.seq.x{reps}.{agent}");
                let mut all_clean = true;
                let mut detail = String::new();
                for i in 0..reps {
                    let tag = format!("seq_{agent}_{i}");
                    let resp = r
                        .send(
                            agent,
                            exec(vec![nonpie.clone(), "write-known".into(), tag.clone()]),
                        )
                        .await;
                    let expected = format!("PIPEDATA:{tag}");
                    let ok = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.trim() == expected);
                    if !ok {
                        all_clean = false;
                        detail = format!("iter {i}: expected '{expected}', got {resp:?}");
                        break;
                    }
                }
                if all_clean {
                    detail = format!("{reps} sequential non-PIE execs all clean");
                }
                r.record(&test_id, agent, all_clean, &detail);
            }

            // Interleaved PIE + non-PIE pattern.
            {
                let test_id = format!("NPIPE.interleaved.x{reps}.{agent}");
                let mut all_clean = true;
                let mut detail = String::new();
                for i in 0..reps {
                    // Non-PIE exec.
                    let np_tag = format!("np_{agent}_{i}");
                    let resp = r
                        .send(
                            agent,
                            exec(vec![nonpie.clone(), "write-known".into(), np_tag.clone()]),
                        )
                        .await;
                    let expected = format!("PIPEDATA:{np_tag}");
                    let ok = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.trim() == expected);
                    if !ok {
                        all_clean = false;
                        detail = format!("iter {i} nonpie: expected '{expected}', got {resp:?}");
                        break;
                    }

                    // PIE exec — must not see contamination from prior non-PIE.
                    let resp = r
                        .send(agent, exec(vec![self_exe.clone(), "echo-test".into()]))
                        .await;
                    let ok = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. }
                        if stdout.trim() == "ECHO_TEST_OK");
                    if !ok {
                        all_clean = false;
                        detail = format!("iter {i} pie: expected 'ECHO_TEST_OK', got {resp:?}");
                        break;
                    }
                }
                if all_clean {
                    detail = format!("{reps} interleaved PIE+nonPIE execs all clean");
                }
                r.record(&test_id, agent, all_clean, &detail);
            }
        }
    }
}

/// Run all platform fix validation tests.
pub(crate) async fn run(r: &mut TestRunner) {
    poll_ready_tests(r).await;
    bind_getsockname_tests(r).await;
    pipe_pair_id_tests(r).await;
    exit_data_integrity_tests(r).await;
    nonpie_pipe_chain_tests(r).await;
    stdin_pipe_subst_tests(r).await;
}

// ═══════════════════════════════════════════════════════════════════
// STDIN-PIPE-SUBST: $() inside scripts piped via stdin
// (fix for VS Code Remote-SSH install script failure)
// ═══════════════════════════════════════════════════════════════════

/// When a shell script is piped via stdin (as VS Code Remote-SSH does),
/// $() command substitution with pipelines must return correct output.
///
/// The issue: vfork children share the kernel pipe file description
/// for stdin. Pipeline children (head, grep, sed) may consume stdin
/// data, causing the parent shell to lose its script position.
///
/// Tests cover:
///   SP.simple      — $(echo hello) via stdin pipe
///   SP.pipeline    — $(echo hello | cat) via stdin pipe
///   SP.file_read   — $(cat /etc/passwd) via stdin pipe
///   SP.file_pipe   — $(cat /etc/passwd | head -1) via stdin pipe [THE BUG]
///   SP.multi_subst — multiple $() in sequence via stdin pipe
///   SP.os_detect   — $(uname -m) + $(uname -s) via stdin pipe [VS Code pattern]
pub(crate) async fn stdin_pipe_subst_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Stdin-Pipe Subst ({} agents) ===",
        AGENTS.len()
    );

    struct SubstTest {
        name: &'static str,
        /// Script to pipe via stdin to /bin/sh
        script: &'static str,
        /// Expected stdout (exact match after trim)
        expected: &'static str,
        /// Known failure — vfork stdin pipe offset issue
        xfail: bool,
    }

    let tests = &[
        SubstTest {
            name: "simple",
            script: "X=$(echo hello)\necho R=$X\n",
            expected: "R=hello",
            xfail: false,
        },
        SubstTest {
            name: "pipeline",
            script: "X=$(echo hello | cat)\necho R=$X\n",
            expected: "R=hello",
            xfail: false,
        },
        SubstTest {
            name: "file_read",
            script: "X=$(head -1 /etc/passwd)\necho R=${X%%:*}\n",
            expected: "R=root",
            xfail: false,
        },
        SubstTest {
            name: "file_pipe",
            script: "X=$(cat /etc/passwd | head -1)\necho R=${X%%:*}\n",
            expected: "R=root",
            // Known bug: vfork children share kernel pipe file description
            // for stdin. Pipeline children (head) consume stdin data,
            // causing $() to return empty.
            xfail: true,
        },
        SubstTest {
            name: "multi_subst",
            script: "A=$(echo first)\nB=$(echo second)\necho R=$A.$B\n",
            expected: "R=first.second",
            xfail: false,
        },
        SubstTest {
            name: "os_detect",
            script: "ARCH=$(uname -m)\nPLATFORM=$(uname -s)\necho R=$ARCH.$PLATFORM\n",
            expected: "R=x86_64.Linux",
            xfail: false,
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("SP.{}.{}", test.name, agent);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["/bin/sh".into()],
                        timeout_secs: Some(15),
                        stdin: Some(test.script.into()),
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if stdout.trim() == test.expected
            );
            if test.xfail {
                r.record_xfail(
                    &test_id,
                    agent,
                    pass,
                    "vfork stdin pipe offset shared",
                    &format!("{resp:?}"),
                );
            } else {
                r.record(&test_id, agent, pass, &format!("{resp:?}"));
            }
        }
    }
}
