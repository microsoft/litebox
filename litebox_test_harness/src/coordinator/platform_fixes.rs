// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform fix validation tests — matrix-loop tests that prove specific bug
//! fixes are needed by exercising the exact behavior each fix corrected.
//!
//! Each test category targets a commit in the wportnoy/vscode-server-in-litebox
//! branch and must pass on both native WSL2 (gold standard) and litebox.

use super::{TestRunner, exec};
use crate::protocol::{Command, Response};
use tokio::time::Duration;

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
    cross_worker_file_tests(r).await;
    subst_capture_tests(r).await;
    concurrent_fork_tests(r).await;
    touch_redirect_tests(r).await;
    vscode_install_pattern_tests(r).await;
    pid_visibility_tests(r).await;
    file_redirect_tests(r).await;
    loopback_tcp_tests(r).await;
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
    }

    let tests = &[
        SubstTest {
            name: "simple",
            script: "X=$(echo hello)\necho R=$X\n",
            expected: "R=hello",
        },
        SubstTest {
            name: "pipeline",
            script: "X=$(echo hello | cat)\necho R=$X\n",
            expected: "R=hello",
        },
        SubstTest {
            name: "file_read",
            script: "X=$(head -1 /etc/passwd)\necho R=${X%%:*}\n",
            expected: "R=root",
        },
        // Known litebox bug: vfork children share kernel pipe file
        // description for stdin. Pipeline children (head) consume
        // stdin data, causing $() to return empty.
        // Passes on WSL2, fails on litebox (counted in EXPECTED_FAIL_COUNT).
        SubstTest {
            name: "file_pipe",
            script: "X=$(cat /etc/passwd | head -1)\necho R=${X%%:*}\n",
            expected: "R=root",
        },
        SubstTest {
            name: "multi_subst",
            script: "A=$(echo first)\nB=$(echo second)\necho R=$A.$B\n",
            expected: "R=first.second",
        },
        SubstTest {
            name: "os_detect",
            script: "ARCH=$(uname -m)\nPLATFORM=$(uname -s)\necho R=$ARCH.$PLATFORM\n",
            expected: "R=x86_64.Linux",
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
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// CWF: Cross-worker file coherence
// (9P broker concurrent read-while-write across worker sessions)
// ═══════════════════════════════════════════════════════════════════

/// When a fork+exec'd child writes to a file and the parent reads it,
/// the data must be visible — even if the child is still alive (the
/// VS Code CLI pattern).
///
/// The bug: after delayed-fork migration, the child writes to the file
/// through the worker's 9P session.  The parent opens the same path
/// through its own 9P session.  `stat` sees the correct size, but
/// `read` returns EIO when the child's session still has the file open.
///
/// Tests:
///   CWF.seq          — child writes, exits, parent reads (sequential)
///   CWF.concurrent   — child writes, stays alive, parent reads (concurrent)
///   CWF.redirect     — bash `cmd > file &` pattern (VS Code CLI pattern)
pub(crate) async fn cross_worker_file_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Cross-Worker File ({} agents) ===",
        AGENTS.len()
    );

    let self_exe = r.self_exe.clone();

    for &agent in AGENTS {
        // CWF.seq: child writes, exits, then parent reads.
        {
            let test_id = format!("CWF.seq.{agent}");
            let path = format!("/shared/cwf-seq-{agent}.txt");
            // Write via fork+exec (child writes + exits).
            let resp = r
                .send(
                    agent,
                    exec(vec![
                        "bash".into(),
                        "-c".into(),
                        format!("{} cross-worker-file write-and-exit {}", self_exe, path),
                    ]),
                )
                .await;
            let wrote = matches!(&resp, Response::ExecResult { exit_code: 0, .. });
            if !wrote {
                r.record(&test_id, agent, false, &format!("write failed: {resp:?}"));
                continue;
            }
            // Read from same agent.
            let resp = r.send(agent, Command::FsRead { path: path.clone() }).await;
            let pass = matches!(
                &resp,
                Response::Ok { data: Some(d) } if d.starts_with("line0")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }

        // CWF.concurrent: child writes, closes fd, stays alive, parent reads.
        // The child drops the file handle before sleeping — tests that the
        // parent can read after the child's 9P session releases the file.
        {
            let test_id = format!("CWF.concurrent.{agent}");
            let path = format!("/shared/cwf-conc-{agent}.txt");
            // Start child in background (it writes, closes fd, then sleeps).
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec![
                            self_exe.clone(),
                            "cross-worker-file".into(),
                            "write-and-sleep".into(),
                            path.clone(),
                        ],
                        timeout_secs: None,
                        stdin: None,
                        background: true,
                    },
                )
                .await;
            let bg_pid = match &resp {
                Response::Background { pid } => Some(*pid),
                _ => None,
            };
            if bg_pid.is_none() {
                r.record(
                    &test_id,
                    agent,
                    false,
                    &format!("bg spawn failed: {resp:?}"),
                );
                continue;
            }
            // Wait for child to write.
            tokio::time::sleep(Duration::from_secs(3)).await;
            // Read file while child is alive.
            let resp = r.send(agent, Command::FsRead { path: path.clone() }).await;
            let pass = matches!(
                &resp,
                Response::Ok { data: Some(d) } if d.starts_with("line0")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
            // Clean up.
            if let Some(pid) = bg_pid {
                let _ = r.send(agent, Command::Kill { pid }).await;
            }
        }

        // CWF.hold: child writes, keeps fd OPEN, parent reads.
        // This is the VS Code CLI pattern — the CLI keeps its log file
        // open while the parent polls it for "Listening on <port>".
        {
            let test_id = format!("CWF.hold.{agent}");
            let path = format!("/shared/cwf-hold-{agent}.txt");
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec![
                            self_exe.clone(),
                            "cross-worker-file".into(),
                            "write-and-hold".into(),
                            path.clone(),
                        ],
                        timeout_secs: None,
                        stdin: None,
                        background: true,
                    },
                )
                .await;
            let bg_pid = match &resp {
                Response::Background { pid } => Some(*pid),
                _ => None,
            };
            if bg_pid.is_none() {
                r.record(
                    &test_id,
                    agent,
                    false,
                    &format!("bg spawn failed: {resp:?}"),
                );
                continue;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            let resp = r.send(agent, Command::FsRead { path: path.clone() }).await;
            let pass = matches!(
                &resp,
                Response::Ok { data: Some(d) } if d.starts_with("line0")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
            if let Some(pid) = bg_pid {
                let _ = r.send(agent, Command::Kill { pid }).await;
            }
        }

        // CWF.self_open: child opens file itself (no inherited fd).
        // Control test — child writes to the path directly, no redirect.
        {
            let test_id = format!("CWF.self_open.{agent}");
            let path = format!("/shared/cwf-self-{agent}.txt");
            let script = format!(
                concat!(
                    "rm -f {path}; ",
                    "{exe} cross-worker-file write-and-hold {path} &\n",
                    "BGPID=$!\nsleep 3\ncat {path}\n",
                    "kill $BGPID 2>/dev/null\n",
                ),
                path = path,
                exe = self_exe,
            );
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(15),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if stdout.starts_with("line0")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }

        // CWF.redirect_stdout: bash `cmd > file &` — child writes to stdout
        // which bash redirects to a file.  Parent reads the file.
        // This is the EXACT VS Code CLI pattern.
        {
            let test_id = format!("CWF.redirect_stdout.{agent}");
            let path = format!("/shared/cwf-rstdout-{agent}.txt");
            let script = format!(
                concat!(
                    "rm -f {path}; ",
                    "{exe} cross-worker-file write-stdout ",
                    "> {path} 2>&1 &\n",
                    "BGPID=$!\nsleep 3\ncat {path}\n",
                    "kill $BGPID 2>/dev/null\n",
                ),
                path = path,
                exe = self_exe,
            );
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(15),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if stdout.contains("line0")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }

        // CWF.redirect_exit: same as redirect_stdout but child exits quickly.
        // Tests if data becomes visible after the worker child exits.
        {
            let test_id = format!("CWF.redirect_exit.{agent}");
            let path = format!("/shared/cwf-rexit-{agent}.txt");
            let script = format!(
                concat!(
                    "rm -f {path}; ",
                    "{exe} echo-test ",
                    "> {path} 2>&1\n",
                    "cat {path}\n",
                ),
                path = path,
                exe = self_exe,
            );
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(15),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if stdout.contains("ECHO_TEST_OK")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }

        // CWF.builtin_redirect: shell builtin redirected to file.
        // No exec, no delayed fork — data should always be visible.
        {
            let test_id = format!("CWF.builtin_redirect.{agent}");
            let path = format!("/shared/cwf-builtin-{agent}.txt");
            let script = format!(
                concat!(
                    "rm -f {path}; ",
                    "echo builtin-data > {path}\n",
                    "cat {path}\n",
                ),
                path = path,
            );
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(10),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if stdout.contains("builtin-data")
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SC: $() command substitution capture — various commands
// (readlink -f failure blocks VS Code Server startup)
// ═══════════════════════════════════════════════════════════════════

/// Tests that $() command substitution correctly captures output from
/// various commands.  The VS Code Server startup script uses:
///   ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
/// If readlink -f returns empty in $(), ROOT="" and the server can't
/// find its own node binary.
///
/// Tests cover progressively more complex capture patterns:
///   SC.echo       — $(echo hello)                   [baseline]
///   SC.cat        — $(cat /etc/hostname)             [file read]
///   SC.readlink   — $(readlink -f /usr/bin/bash)     [THE BUG]
///   SC.dirname    — $(dirname /usr/bin/bash)         [path manipulation]
///   SC.nested     — $(dirname $(readlink -f ...))    [nested subst]
///   SC.vscode     — full VS Code ROOT= pattern       [end-to-end]
///   SC.which      — $(which bash)                    [path search]
///   SC.uname      — $(uname -m)                     [system info]
pub(crate) async fn subst_capture_tests(r: &mut TestRunner) {
    eprintln!("[platform] === Subst Capture ({} agents) ===", AGENTS.len());

    struct Test {
        name: &'static str,
        script: &'static str,
        check: fn(&str) -> bool,
    }

    let tests: &[Test] = &[
        Test {
            name: "echo",
            script: "X=$(echo hello); echo $X",
            check: |s| s.trim() == "hello",
        },
        Test {
            name: "cat",
            script: "X=$(cat /etc/hostname); echo $X",
            check: |s| !s.trim().is_empty(),
        },
        Test {
            name: "readlink",
            script: "X=$(readlink -f /usr/bin/bash); echo $X",
            check: |s| s.trim().contains("bash"),
        },
        Test {
            name: "dirname",
            script: "X=$(dirname /usr/bin/bash); echo $X",
            check: |s| s.trim() == "/usr/bin",
        },
        Test {
            name: "nested",
            script: "X=$(dirname $(readlink -f /usr/bin/bash)); echo $X",
            check: |s| !s.trim().is_empty() && s.trim() != "/",
        },
        Test {
            name: "vscode_root",
            // Use the test harness binary itself — a deeply nested path
            // that exists in any rootfs with /opt/litebox mounted.
            script: concat!(
                "SCRIPT=$(which bash); ",
                "ROOT=$(dirname $(dirname $(readlink -f $SCRIPT))); ",
                "echo $ROOT",
            ),
            // /usr/bin/bash → readlink → /usr/bin/bash → dirname² → /usr
            check: |s| !s.trim().is_empty() && s.trim() != "/" && s.trim() != "",
        },
        Test {
            name: "which",
            script: "X=$(which bash); echo $X",
            check: |s| s.trim().contains("bash"),
        },
        Test {
            name: "uname",
            script: "X=$(uname -m); echo $X",
            check: |s| s.trim() == "x86_64",
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("SC.{}.{}", test.name, agent);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), test.script.into()],
                        timeout_secs: Some(10),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if (test.check)(stdout)
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// CC: Concurrent fork/exec/pipe tests
// (stress test delayed-fork, CoW, pipe bridging under concurrency)
// ═══════════════════════════════════════════════════════════════════

/// Tests that fork/exec/pipe operations work correctly when multiple
/// agents perform them simultaneously.  Each test starts the same
/// operation on ALL agents via background exec (each writing results
/// to a unique file), waits, then reads and verifies results.
///
/// This catches races in:
///   - delayed-fork worker spawning under concurrent forks
///   - CoW page snapshot/restore with simultaneous vfork children
///   - pipe ring buffer position tracking across multiple processes
///   - 9P file coherence with concurrent writers
///
/// Tests:
///   CC.echo         — concurrent $(echo hello) on all agents
///   CC.fork_exec    — concurrent fork+exec of test harness
///   CC.pipe_capture — concurrent $(echo | cat) pipeline capture
///   CC.file_write   — concurrent writes, then cross-read
pub(crate) async fn concurrent_fork_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Concurrent Fork ({} agents) ===",
        AGENTS.len()
    );

    let self_exe = r.self_exe.clone();

    struct ConcTest {
        name: &'static str,
        /// Shell script template. {path} is replaced with the result file path.
        script_template: &'static str,
        /// Check function for the result file content.
        check: fn(&str) -> bool,
    }

    let tests: &[ConcTest] = &[
        ConcTest {
            name: "echo",
            script_template: "echo $(echo hello) > {path}",
            check: |s| s.trim() == "hello",
        },
        ConcTest {
            name: "fork_exec",
            script_template: "{exe} echo-test > {path} 2>&1",
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        ConcTest {
            name: "pipe_capture",
            script_template: "echo $(echo data | cat) > {path}",
            check: |s| s.trim() == "data",
        },
        ConcTest {
            name: "file_write",
            script_template: "echo agent-wrote-{agent} > {path}",
            check: |s| s.contains("agent-wrote-"),
        },
    ];

    for test in tests {
        let test_base = format!("CC.{}", test.name);

        // Phase 1: Start all agents concurrently via background exec.
        let mut bg_pids: Vec<(&str, Option<u32>, String)> = Vec::new();
        for &agent in AGENTS {
            let path = format!("/shared/cc-{}-{}.txt", test.name, agent);
            let script = test
                .script_template
                .replace("{path}", &path)
                .replace("{exe}", &self_exe)
                .replace("{agent}", agent);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: None,
                        stdin: None,
                        background: true,
                    },
                )
                .await;
            let pid = match &resp {
                Response::Background { pid } => Some(*pid),
                Response::ExecResult { .. } => None,
                _ => None,
            };
            bg_pids.push((agent, pid, path));
        }

        // Phase 2: Wait for all to complete.
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Phase 3: Read result files and verify.
        for (agent, pid, path) in &bg_pids {
            let test_id = format!("{test_base}.{agent}");
            let resp = r.send(*agent, Command::FsRead { path: path.clone() }).await;
            let pass = matches!(
                &resp,
                Response::Ok { data: Some(d) } if (test.check)(d)
            );
            r.record(&test_id, *agent, pass, &format!("{resp:?}"));

            if let Some(pid) = pid {
                let _ = r.send(*agent, Command::Kill { pid: *pid }).await;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// TR: Touch + redirect file coherence
// (9P cache stale inode after touch + fork+exec redirect)
// ═══════════════════════════════════════════════════════════════════

/// When a file is pre-created with `touch`, then a fork+exec'd binary
/// writes to it via shell redirect (`cmd > file &`), the parent's
/// `cat` of the file must see the child's output.
///
/// The VS Code install script does:
///   touch "$LOG"; chmod 600 "$LOG"
///   CLI > "$LOG" 2>&1 < /dev/null &
///   cat "$LOG"   ← must see CLI output
///
/// Tests:
///   TR.no_touch      — no pre-creation, redirect creates file (control)
///   TR.touch          — touch before redirect
///   TR.touch_chmod    — touch + chmod before redirect (VS Code pattern)
///   TR.echo_touch     — echo > file before redirect (pre-create with data)
///   TR.builtin_touch  — touch + builtin redirect (no fork+exec)
pub(crate) async fn touch_redirect_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === Touch+Redirect ({} agents) ===",
        AGENTS.len()
    );

    let self_exe = r.self_exe.clone();

    struct TRTest {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }

    let tests: &[TRTest] = &[
        TRTest {
            name: "no_touch",
            script_template: concat!(
                "rm -f {path}; ",
                "{exe} echo-test > {path} 2>&1 &\n",
                "BGPID=$!\nsleep 2\ncat {path}\n",
                "kill $BGPID 2>/dev/null\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        TRTest {
            name: "touch",
            script_template: concat!(
                "rm -f {path}; touch {path}; ",
                "{exe} echo-test > {path} 2>&1 &\n",
                "BGPID=$!\nsleep 2\ncat {path}\n",
                "kill $BGPID 2>/dev/null\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        TRTest {
            name: "touch_chmod",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "{exe} echo-test > {path} 2>&1 &\n",
                "BGPID=$!\nsleep 2\ncat {path}\n",
                "kill $BGPID 2>/dev/null\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        TRTest {
            name: "echo_touch",
            script_template: concat!(
                "rm -f {path}; echo init > {path}; ",
                "{exe} echo-test > {path} 2>&1 &\n",
                "BGPID=$!\nsleep 2\ncat {path}\n",
                "kill $BGPID 2>/dev/null\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        TRTest {
            name: "builtin_touch",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "echo builtin-data > {path} &\n",
                "wait\ncat {path}\n",
            ),
            check: |s| s.contains("builtin-data"),
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("TR.{}.{}", test.name, agent);
            let path = format!("/shared/tr-{}-{}.txt", test.name, agent);
            let script = test
                .script_template
                .replace("{path}", &path)
                .replace("{exe}", &self_exe);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(10),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if (test.check)(stdout)
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// VS: VS Code install script patterns
// (tests for the exact sequence used by Remote-SSH to start the server)
// ═══════════════════════════════════════════════════════════════════

/// Exercises the VS Code Remote-SSH install script pattern:
///   touch LOG; chmod 600 LOG; BINARY > LOG 2>&1 < /dev/null &
///   PID=$!; sleep N; cat LOG; kill -0 $PID
///
/// Tests:
///   VS.log_readable     — cat of log file returns data (not EIO)
///   VS.pid_visible       — kill -0 $! succeeds (background process visible)
///   VS.log_in_subdir     — same pattern but in a pre-existing subdirectory
///   VS.poll_log          — polling loop finds output (simulates install script)
pub(crate) async fn vscode_install_pattern_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === VS Code Install Pattern ({} agents) ===",
        AGENTS.len()
    );

    let self_exe = r.self_exe.clone();

    struct VSTest {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }

    let tests: &[VSTest] = &[
        // Basic: touch+redirect+cat — the core pattern
        VSTest {
            name: "log_readable",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "{exe} echo-test > {path} 2>&1 < /dev/null &\n",
                "sleep 2\ncat {path}\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        // kill -0 $! — background process must remain visible
        VSTest {
            name: "pid_visible",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "{exe} slow-echo > {path} 2>&1 < /dev/null &\n",
                "PID=$!\nsleep 1\n",
                "kill -0 $PID 2>/dev/null && echo PID_ALIVE || echo PID_DEAD\n",
                "wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("PID_ALIVE"),
        },
        // Same pattern but in a subdirectory (like /root/.vscode-server/)
        VSTest {
            name: "log_in_subdir",
            script_template: concat!(
                "mkdir -p /tmp/vs-test-dir; rm -f {path}; ",
                "touch {path}; chmod 600 {path}; ",
                "{exe} echo-test > {path} 2>&1 < /dev/null &\n",
                "sleep 2\ncat {path}\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        // Polling loop: check log repeatedly (simulates install script)
        VSTest {
            name: "poll_log",
            script_template: concat!(
                "rm -f {path}; touch {path}; chmod 600 {path}; ",
                "{exe} echo-test > {path} 2>&1 < /dev/null &\n",
                "for i in 1 2 3 4 5; do\n",
                "  if cat {path} 2>/dev/null | grep -q ECHO_TEST_OK; then\n",
                "    echo POLL_FOUND; break\n",
                "  fi\n",
                "  sleep 1\n",
                "done\n",
            ),
            check: |s| s.contains("POLL_FOUND"),
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("VS.{}.{}", test.name, agent);
            let path = if test.name == "log_in_subdir" {
                format!("/tmp/vs-test-dir/vs-{}-{}.log", test.name, agent)
            } else {
                format!("/shared/vs-{}-{}.log", test.name, agent)
            };
            let script = test
                .script_template
                .replace("{path}", &path)
                .replace("{exe}", &self_exe);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(15),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if (test.check)(stdout)
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// KP: PID and /proc visibility across delayed-fork migration
// ═══════════════════════════════════════════════════════════════════

/// After fork+exec, the child is migrated to a new worker via delayed fork.
/// These tests cover the full visibility matrix:
///
/// **Observation direction:**
///   parent → child:  kill -0, /proc/<child>/cmdline
///   child  → parent: kill -0, /proc/<ppid>, /proc/<ppid>/cmdline, getppid()
///   self:            /proc/self, /proc/self/cmdline, /proc/self/stat, /proc/<own_pid>
///
/// **Conditions:**
///   immediate vs delayed (1s), single fork vs many prior forks
///
/// Tests:
///   KP.kill0_bg           — parent kill -0 $! immediate
///   KP.kill0_many         — parent kill -0 after many prior forks
///   KP.proc_child         — parent /proc/<child_pid>/cmdline readable
///   KP.proc_self          — /proc/self + /proc/<own_pid> from migrated child
///   KP.ppid_proc          — child /proc/<ppid> visible
///   KP.ppid_kill0         — child kill -0 ppid
///   KP.ppid_cmdline       — child /proc/<ppid>/cmdline readable
///   KP.getppid_correct    — child getppid() returns parent's PID
///   KP.parent_monitor     — child stays alive while monitoring parent via /proc
pub(crate) async fn pid_visibility_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === PID Visibility ({} agents) ===",
        AGENTS.len()
    );

    let self_exe = r.self_exe.clone();

    struct KPTest {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }

    let tests: &[KPTest] = &[
        // --- Parent → child direction ---
        // Basic: parent kill -0 $! after background fork+exec
        KPTest {
            name: "kill0_bg",
            script_template: concat!(
                "{exe} slow-echo > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_OK || echo KILL0_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("KILL0_OK"),
        },
        // Parent kill -0 after many prior forks (higher PID, install-script-like)
        KPTest {
            name: "kill0_many",
            script_template: concat!(
                "A=$(cat /etc/os-release | head -1)\n",
                "B=$(uname -m)\n",
                "C=$(ls /tmp | head -1)\n",
                "D=$(echo x | cat)\n",
                "{exe} slow-echo > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_OK || echo KILL0_FAIL\n",
                "sleep 1\n",
                "kill -0 $PID 2>/dev/null && echo KILL0_1s_OK || echo KILL0_1s_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("KILL0_OK") && s.contains("KILL0_1s_OK"),
        },
        // Parent reads /proc/<child>/cmdline of a migrated child
        KPTest {
            name: "proc_child",
            script_template: concat!(
                "{exe} slow-echo > /dev/null 2>&1 &\n",
                "PID=$!\n",
                "sleep 1\n",
                "test -d /proc/$PID && echo PROC_DIR_OK || echo PROC_DIR_FAIL\n",
                "cat /proc/$PID/cmdline 2>/dev/null | tr '\\0' ' ' | ",
                "grep -q litebox_test_harness && echo CMDLINE_OK || echo CMDLINE_FAIL\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("PROC_DIR_OK") && s.contains("CMDLINE_OK"),
        },
        // --- Self visibility ---
        // /proc/self and /proc/<own_pid> from a migrated child
        KPTest {
            name: "proc_self",
            script_template: concat!(
                "{exe} proc-probe > /tmp/proc-self.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/proc-self.txt\n",
            ),
            check: |s| {
                s.contains("self=true")
                    && s.contains("self_cmdline=true")
                    && s.contains("own_proc=true")
                    && s.contains("own_cmdline=true")
            },
        },
        // --- Child → parent direction ---
        // Child sees parent in /proc/<ppid>
        KPTest {
            name: "ppid_proc",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-proc.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-proc.txt\n",
            ),
            check: |s| s.contains("ppid_proc=true"),
        },
        // Child can kill -0 parent
        KPTest {
            name: "ppid_kill0",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-k0.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-k0.txt\n",
            ),
            check: |s| s.contains("ppid_kill0=true"),
        },
        // Child can read /proc/<ppid>/cmdline (sysinfo reads this)
        KPTest {
            name: "ppid_cmdline",
            script_template: concat!(
                "{exe} proc-probe > /tmp/ppid-cl.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-cl.txt\n",
            ),
            check: |s| s.contains("ppid_cmdline=true"),
        },
        // Child getppid() returns the parent's actual PID
        KPTest {
            name: "getppid_correct",
            script_template: concat!(
                "echo $$\n",
                "{exe} check-ppid > /tmp/ppid-val.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/ppid-val.txt\n",
            ),
            check: |s| {
                // First line is parent's $$, check-ppid reports ppid=N
                let lines: Vec<&str> = s.lines().collect();
                if lines.len() < 2 {
                    return false;
                }
                let parent_pid = lines[0].trim();
                // The ppid line may be prefixed with [harness] line
                lines
                    .iter()
                    .any(|l| l.contains(&format!("ppid={parent_pid}")))
            },
        },
        // --- Combined: parent-monitor pattern ---
        // Child can see parent via both /proc and kill -0
        KPTest {
            name: "parent_monitor",
            script_template: concat!(
                "{exe} proc-probe > /tmp/pmon.txt 2>&1 &\n",
                "wait $!\n",
                "cat /tmp/pmon.txt\n",
            ),
            check: |s| s.contains("ppid_proc=true") && s.contains("ppid_kill0=true"),
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("KP.{}.{}", test.name, agent);
            let script = test.script_template.replace("{exe}", &self_exe);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(15),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if (test.check)(stdout)
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// FR: File-Redirect — stdout of background process → file via redirect
// (discovered during cross-worker TCP debugging: nc prints to stdout
// but the redirected file stays empty)
// ═══════════════════════════════════════════════════════════════════

/// When a background command's stdout is redirected to a file
/// (`cmd > file &`), the child process's fd 1 is connected through
/// the mux bridge to the parent, which holds the file fd.
/// Data written by the child must be visible when the parent (or a
/// sibling) reads the file.
///
/// Tests cover:
///   FR.bg_echo       — echo in background: `echo DATA > file &; wait; cat file`
///   FR.bg_printf      — printf (no trailing newline): `printf DATA > file &; wait; cat file`
///   FR.bg_exe         — exec'd process writes to stdout → file
///   FR.bg_cat_pipe    — piped: `echo DATA | cat > file &; wait; cat file`
///   FR.fg_redirect    — control: foreground redirect should always work
pub(crate) async fn file_redirect_tests(r: &mut TestRunner) {
    eprintln!(
        "[platform] === File Redirect ({} agents) ===",
        AGENTS.len()
    );

    let self_exe = r.self_exe.clone();

    struct FRTest {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }

    let tests: &[FRTest] = &[
        // Control: foreground redirect (no background, no mux bridge)
        FRTest {
            name: "fg_redirect",
            script_template: concat!(
                "echo FR_FG > {path}\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("FR_FG"),
        },
        // Background builtin (echo) writes to redirected stdout
        FRTest {
            name: "bg_echo",
            script_template: concat!(
                "echo FR_BGECHO > {path} &\n",
                "wait\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("FR_BGECHO"),
        },
        // Background exec'd process writes to redirected stdout.
        // The child goes through delayed fork → different worker.
        // Its stdout is connected through the mux bridge.
        FRTest {
            name: "bg_exe",
            script_template: concat!(
                "{exe} echo-test > {path} &\n",
                "wait\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("ECHO_TEST_OK"),
        },
        // Background pipeline writes to redirected file
        FRTest {
            name: "bg_cat_pipe",
            script_template: concat!(
                "echo FR_PIPE | cat > {path} &\n",
                "wait\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("FR_PIPE"),
        },
        // Background process with append redirect (>>)
        FRTest {
            name: "bg_append",
            script_template: concat!(
                "echo LINE1 > {path}\n",
                "echo LINE2 >> {path} &\n",
                "wait\n",
                "cat {path}\n",
            ),
            check: |s| s.contains("LINE1") && s.contains("LINE2"),
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("FR.{}.{}", test.name, agent);
            let path = format!("/shared/fr-{}-{}.txt", test.name, agent);
            let script = test
                .script_template
                .replace("{path}", &path)
                .replace("{exe}", &self_exe);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(10),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if (test.check)(stdout)
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// LB: Loopback TCP across delayed-fork workers
// (VS Code exec server uses SOCKS proxy → TCP loopback to CLI port)
// ═══════════════════════════════════════════════════════════════════

/// A background process (different worker after delayed fork) listens on
/// a TCP port. The parent (original worker) connects to it. This is the
/// exact pattern VS Code uses: the CLI listens on a port, and the SOCKS
/// proxy (through dropbear in the same sandbox) connects to it.
///
/// Tests cover the address matrix:
///   LB.localhost    — connect via 127.0.0.1
///   LB.guest_ip     — connect via 10.0.0.2 (guest's own IP)
///   LB.any          — listen 0.0.0.0, connect 127.0.0.1
///   LB.same_worker  — listen and connect in same worker (control)
pub(crate) async fn loopback_tcp_tests(r: &mut TestRunner) {
    eprintln!("[platform] === Loopback TCP (3 agents) ===");

    let self_exe = r.self_exe.clone();

    struct LBTest {
        name: &'static str,
        script_template: &'static str,
        check: fn(&str) -> bool,
    }

    let tests: &[LBTest] = &[
        // Control: same-worker TCP (no delayed fork, should always work)
        LBTest {
            name: "same_worker",
            script_template: concat!(
                "{exe} tcp-echo 19876 &\n",
                "sleep 1\n",
                "REPLY=$(echo LB_SAME | nc -q1 127.0.0.1 19876 2>/dev/null)\n",
                "echo REPLY=$REPLY\n",
                "wait\n",
            ),
            check: |s| s.contains("REPLY=LB_SAME"),
        },
        // Cross-worker: bg process (different worker) listens, parent connects via 127.0.0.1
        LBTest {
            name: "localhost",
            script_template: concat!(
                "{exe} tcp-echo 19877 > /dev/null 2>&1 &\n",
                "PID=$!\nsleep 2\n",
                "REPLY=$(echo LB_LOCAL | nc -q1 127.0.0.1 19877 2>/dev/null)\n",
                "echo REPLY=$REPLY\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("REPLY=LB_LOCAL"),
        },
        // Cross-worker: listen on 0.0.0.0, connect via 127.0.0.1
        // (exact VS Code pattern: CLI listens 0.0.0.0, SOCKS connects 127.0.0.1)
        LBTest {
            name: "any_to_local",
            script_template: concat!(
                "{exe} tcp-echo 19879 > /dev/null 2>&1 &\n",
                "PID=$!\nsleep 2\n",
                "REPLY=$(echo LB_ANY | nc -q1 127.0.0.1 19879 2>/dev/null)\n",
                "echo REPLY=$REPLY\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("REPLY=LB_ANY"),
        },
        // Cross-worker: server does CPU work after listen() before accept()
        // (Node.js pattern: listen succeeds, module loading delays accept)
        LBTest {
            name: "busy_after_listen",
            script_template: concat!(
                "{exe} tcp-listen-busy 19880 3 > /dev/null 2>&1 &\n",
                "PID=$!\nsleep 1\n",
                "REPLY=$(echo LB_BUSY | nc -q5 -w10 127.0.0.1 19880 2>/dev/null)\n",
                "echo REPLY=$REPLY\n",
                "kill $PID 2>/dev/null; wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("REPLY=LB_BUSY"),
        },
        // Cross-worker: fast-close client (data + immediate FIN).
        // Exercises CloseWait promotion — when data+FIN arrive in rapid
        // succession, the broker's smoltcp socket can skip Established and
        // land directly in CloseWait within one iface.poll() call.
        // promote_established must accept CloseWait sockets to relay the data.
        LBTest {
            name: "fast_close",
            script_template: concat!(
                "{exe} tcp-recv-all 19881 &\n",
                "PID=$!\nsleep 2\n",
                // -q0: close immediately after stdin EOF (fastest possible FIN)
                "echo LB_FAST | nc -q0 127.0.0.1 19881 2>/dev/null\n",
                "sleep 2\n",
                // tcp-recv-all prints RECV=... to stdout, captured via wait
                "wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("RECV=LB_FAST"),
        },
        // Cross-worker: verify half-close FIN propagation.
        // Server uses tcp-recv-all which calls read_to_end() — it only
        // exits when it sees EOF on the socket. EOF requires the client's
        // FIN to propagate through the TCP pair via shutdown(Write).
        // Without half-close propagation, tcp-recv-all hangs forever.
        LBTest {
            name: "halfclose_eof",
            script_template: concat!(
                "{exe} tcp-recv-all 19882 &\n",
                "PID=$!\nsleep 2\n",
                // -w2: wait 2s after stdin EOF before closing
                // (data and FIN arrive in separate iterations)
                "echo LB_HALF | nc -w2 127.0.0.1 19882 2>/dev/null\n",
                "sleep 3\n",
                "wait $PID 2>/dev/null\n",
            ),
            check: |s| s.contains("RECV=LB_HALF"),
        },
    ];

    for &agent in AGENTS {
        for test in tests {
            let test_id = format!("LB.{}.{}", test.name, agent);
            let script = test.script_template.replace("{exe}", &self_exe);
            let resp = r
                .send(
                    agent,
                    Command::Exec {
                        args: vec!["bash".into(), "-c".into(), script],
                        timeout_secs: Some(15),
                        stdin: None,
                        background: false,
                    },
                )
                .await;
            let pass = matches!(
                &resp,
                Response::ExecResult { stdout, .. }
                    if (test.check)(stdout)
            );
            r.record(&test_id, agent, pass, &format!("{resp:?}"));
        }
    }
}
