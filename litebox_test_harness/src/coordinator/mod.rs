// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test coordinator. Runs as the init process, drives all test
//! operations through pipes to child agents.

pub(crate) mod file_tcp;
pub(crate) mod fork_matrix;
pub(crate) mod matrix;
pub(crate) mod platform_fixes;
pub(crate) mod port_router;
pub(crate) mod special_cases;
pub(crate) mod tcp_stress;
pub(crate) mod vscode;

use crate::protocol::{Command, Response};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::Duration;

/// Detect whether we're running inside litebox or on native Linux.
///
/// Returns a human-readable string like:
///   "litebox sandbox (rewritten syscalls, smoltcp network)"
///   "native Docker (litebox-test container, real kernel syscalls)"
///   "native non-Docker — use litebox-test Docker image for reproducible results"
fn detect_runtime_environment() -> String {
    // Check 1: Look for litebox's syscall rewriting artifacts in /proc/self/maps.
    // The rewriter patches syscall instructions and maps a trampoline page.
    let has_trampoline = std::fs::read_to_string("/proc/self/maps")
        .map(|maps| maps.contains("litebox_rtld_audit") || maps.contains("[trampoline]"))
        .unwrap_or(false);

    // Check 2: litebox's synthetic /proc/self/stat reports the runner's
    // host process name (e.g., "litebox_broker" or "litebox_runner")
    // instead of the guest binary's actual name. If we're the test harness
    // but /proc/self/stat says we're litebox_broker, we're in the sandbox.
    let proc_stat_litebox = std::fs::read_to_string("/proc/self/stat")
        .map(|s| s.contains("(litebox_broker)") || s.contains("(litebox_runner"))
        .unwrap_or(false);

    // Check 3: litebox sets specific environment variables for the guest.
    let has_litebox_env = std::env::var("LITEBOX_RUNNER").is_ok();

    // Check 4: Check if PID 1 is the litebox init (not systemd/init).
    let pid1_is_litebox = std::fs::read_to_string("/proc/1/cmdline")
        .map(|cmd| cmd.contains("litebox") || cmd.contains("dropbear"))
        .unwrap_or(false);

    // Check 5: Network — litebox uses 10.0.0.x virtual network.
    let has_virtual_net = std::fs::read_to_string("/proc/net/fib_trie")
        .map(|t| t.contains("10.0.0.2"))
        .unwrap_or(false);

    // Check 6: Are we inside a Docker container?
    let in_docker = std::path::Path::new("/.dockerenv").exists();

    if has_trampoline || has_litebox_env || proc_stat_litebox {
        format!(
            "litebox sandbox (trampoline={has_trampoline} env={has_litebox_env} \
             proc_stat={proc_stat_litebox} vnet={has_virtual_net} pid1_litebox={pid1_is_litebox})"
        )
    } else if pid1_is_litebox && in_docker {
        // Running inside litebox's Docker container but NOT through the runner.
        format!(
            "WARNING: litebox Docker container but NOT sandboxed! \
             Tests use native kernel, not litebox shim. \
             To test litebox, run through litebox_tool_executor: \
             litebox_tool_executor --rootfs / --record-baseline -- litebox_test_harness spawn-tree"
        )
    } else if in_docker {
        // Inside a Docker container (e.g., litebox-test) — native gold standard.
        "native Docker (litebox-test container — gold standard, real kernel syscalls)".to_string()
    } else {
        // Bare metal or WSL2 — warn to use the Docker image for reproducibility.
        "WARNING: running outside Docker — use the litebox-test Docker image \
         for reproducible results: \
         docker run --rm litebox-test /opt/litebox/litebox_test_harness spawn-tree"
            .to_string()
    }
}

/// Create an Exec command with default 10s timeout.
pub(crate) fn exec(args: Vec<String>) -> Command {
    Command::Exec {
        args,
        timeout_secs: None,
        stdin: None,
        background: false,
    }
}

/// Create an Exec command with a custom timeout.
pub(crate) fn exec_timeout(args: Vec<String>, secs: u64) -> Command {
    Command::Exec {
        args,
        timeout_secs: Some(secs),
        stdin: None,
        background: false,
    }
}

struct Child {
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    #[allow(dead_code)]
    process: tokio::process::Child,
}

/// Expected outcome of a test.
#[derive(Debug, Clone)]
pub(crate) enum Expectation {
    /// Test is expected to pass.
    Pass,
    /// Test is expected to fail (known limitation). Contains reason.
    #[allow(dead_code)]
    Fail(String),
}

/// Result of a single test.
#[derive(Debug, Clone)]
pub struct TestResult {
    pub id: String,
    pub agent: String,
    pub actual_pass: bool,
    pub expected: Expectation,
    pub detail: String,
}

impl TestResult {
    /// Effective outcome: pass, fail, xfail, or xpass.
    pub fn outcome(&self) -> &'static str {
        match (&self.expected, self.actual_pass) {
            (Expectation::Pass, true) => "pass",
            (Expectation::Pass, false) => "FAIL",
            (Expectation::Fail(_), false) => "xfail",
            (Expectation::Fail(_), true) => "XPASS",
        }
    }
}

pub(crate) struct TestRunner {
    children: std::collections::HashMap<String, Child>,
    results: Vec<TestResult>,
    pub(crate) self_exe: String,
}

impl TestRunner {
    /// Record a test expected to pass.
    fn record(&mut self, test: &str, agent: &str, pass: bool, detail: &str) {
        self.record_expected(test, agent, pass, Expectation::Pass, detail);
    }

    /// Record a test with an expected failure (known limitation).
    fn record_xfail(&mut self, test: &str, agent: &str, pass: bool, reason: &str, detail: &str) {
        self.record_expected(
            test,
            agent,
            pass,
            Expectation::Fail(reason.to_string()),
            detail,
        );
    }

    fn record_expected(
        &mut self,
        test: &str,
        agent: &str,
        pass: bool,
        expected: Expectation,
        detail: &str,
    ) {
        let result = TestResult {
            id: test.to_string(),
            agent: agent.to_string(),
            actual_pass: pass,
            expected,
            detail: detail.to_string(),
        };
        let outcome = result.outcome();
        eprintln!("  {outcome}: {test} [{agent}] {detail}");
        self.results.push(result);
    }

    async fn send(&mut self, target: &str, cmd: Command) -> Response {
        if target == "init" {
            return self.exec_local(&cmd).await;
        }
        // Route through the tree: "A" → direct child,
        // "AA" → forward through A, "AAA" → forward through A → AA.
        let (direct, rest) = route(target);
        let child = match self.children.get_mut(direct) {
            Some(c) => c,
            None => {
                return Response::Error {
                    error: format!("no child {direct}"),
                };
            }
        };
        let actual_cmd = wrap_forwards(rest, cmd);
        send_cmd(child, &actual_cmd).await
    }

    async fn exec_local(&self, cmd: &Command) -> Response {
        match cmd {
            Command::FsRead { path } => match tokio::fs::read_to_string(path).await {
                Ok(data) => Response::Ok { data: Some(data) },
                Err(_) => Response::NotFound,
            },
            Command::FsWrite { path, data } => {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                match tokio::fs::write(path, data).await {
                    Ok(()) => Response::Ok { data: None },
                    Err(e) => Response::Error {
                        error: format!("{e}"),
                    },
                }
            }
            Command::FsDelete { path } => match tokio::fs::remove_file(path).await {
                Ok(()) => Response::Ok { data: None },
                Err(e) => Response::Error {
                    error: format!("{e}"),
                },
            },
            Command::FsSymlink { target, link } => {
                #[cfg(unix)]
                match tokio::fs::symlink(target, link).await {
                    Ok(()) => Response::Ok { data: None },
                    Err(e) => Response::Error {
                        error: format!("symlink: {e}"),
                    },
                }
                #[cfg(not(unix))]
                Response::Error {
                    error: "symlink not supported on this platform".to_string(),
                }
            }
            Command::FsReadlink { path } => match tokio::fs::read_link(path).await {
                Ok(target) => Response::Ok {
                    data: Some(target.to_string_lossy().into_owned()),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Response::NotFound,
                Err(e) => Response::Error {
                    error: format!("readlink: {e}"),
                },
            },
            Command::FsStat { path } => match tokio::fs::symlink_metadata(path).await {
                Ok(meta) => {
                    let kind = if meta.is_symlink() {
                        "symlink"
                    } else if meta.is_dir() {
                        "dir"
                    } else {
                        "file"
                    };
                    Response::Ok {
                        data: Some(kind.to_string()),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Response::NotFound,
                Err(e) => Response::Error {
                    error: format!("stat: {e}"),
                },
            },
            Command::NetConnect { addr, data } => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                {
                    Ok(Ok(mut stream)) => {
                        let _ = stream.write_all(data.as_bytes()).await;
                        let _ = stream.flush().await;
                        let mut buf = [0u8; 4096];
                        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                            .await
                        {
                            Ok(Ok(n)) if n > 0 => Response::Connected {
                                echo: String::from_utf8_lossy(&buf[..n]).to_string(),
                            },
                            _ => Response::ConnectFailed {
                                error: "no echo".to_string(),
                            },
                        }
                    }
                    Ok(Err(e)) => Response::ConnectFailed {
                        error: format!("{e}"),
                    },
                    Err(_) => Response::ConnectFailed {
                        error: "timeout".to_string(),
                    },
                }
            }
            _ => Response::Error {
                error: "not implemented locally".to_string(),
            },
        }
    }
}

/// Run tests, optionally filtering to a specific suite.
pub fn run_filtered(self_exe: &str, filter: Option<&str>) -> Vec<TestResult> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run_tests(self_exe, filter))
}

async fn run_tests(self_exe: &str, filter: Option<&str>) -> Vec<TestResult> {
    // Detect runtime environment: litebox sandbox vs native Linux.
    // This is critical for interpreting test results — tests running on
    // native Linux validate the gold-standard kernel behavior, while
    // tests running inside litebox validate the sandbox's emulation.
    let runtime_env = detect_runtime_environment();
    eprintln!("[coord] runtime: {runtime_env}");

    // The non-PIE binary (/litebox-test-harness-nonpie) is pre-built via:
    //   cargo rustc -p litebox_test_harness --target-dir target/nonpie -- -C link-args=-no-pie
    // It must be copied to the rootfs before running tests.

    let mut runner = TestRunner {
        children: std::collections::HashMap::new(),
        results: Vec::new(),
        self_exe: self_exe.to_string(),
    };

    // Spawn direct children A and B.
    eprintln!("[coord] spawning children");
    for id in &["A", "B"] {
        match spawn_child(self_exe).await {
            Ok(child) => {
                runner.children.insert(id.to_string(), child);
                // Tell child to spawn its own children.
                let sub = match *id {
                    "A" => vec!["AA".to_string(), "AB".to_string()],
                    _ => vec![],
                };
                if !sub.is_empty() {
                    let r = send_cmd(
                        runner.children.get_mut(*id).unwrap(),
                        &Command::Spawn { children: sub },
                    )
                    .await;
                    eprintln!("[coord] {id} spawn children: {r:?}");
                }
            }
            Err(e) => eprintln!("[coord] spawn {id} failed: {e}"),
        }
    }

    // Tell A's child AA to spawn AAA, AAB.
    let r = runner
        .send(
            "AA",
            Command::Spawn {
                children: vec!["AAA".to_string(), "AAB".to_string()],
            },
        )
        .await;
    eprintln!("[coord] AA spawn children: {r:?}");

    // Spawn non-PIE subtree: NP (non-PIE) under A, NPC (PIE) under NP.
    // This exercises fork-restore from within a worker-exec host — the
    // exact pattern when VS Code's non-PIE node binary forks children.
    // Conditional on the non-PIE binary being available.
    let has_nonpie = crate::find_nonpie_binary().is_some();
    if has_nonpie {
        eprintln!("[coord] spawning non-PIE subtree (NP → NPC)");
        let r = runner
            .send(
                "A",
                Command::SpawnRemote {
                    children: vec!["NP".to_string()],
                },
            )
            .await;
        eprintln!("[coord] SpawnRemote NP: {r:?}");

        if matches!(&r, Response::Ok { .. }) {
            // NP (non-PIE, in worker-exec host) spawns PIE child NPC.
            let r = runner
                .send(
                    "A",
                    Command::Forward {
                        target: "NP".to_string(),
                        inner: Box::new(Command::Spawn {
                            children: vec!["NPC".to_string()],
                        }),
                    },
                )
                .await;
            eprintln!("[coord] NP spawn NPC: {r:?}");
        }

        // Deep mixed chain: AA → D3 (PIE) → D4 (non-PIE) → D5 (PIE)
        // Mirrors the VS Code Remote-SSH process tree at depths 3-5:
        //
        //   A  (PIE, depth 1)  ≈ dropbear sshd
        //   AA (PIE, depth 2)  ≈ bash (bootstrap script)
        //   D3 (PIE, depth 3)  ≈ VS Code CLI
        //   D4 (non-PIE, depth 4) ≈ node (VS Code Server) — worker-exec
        //   D5 (PIE, depth 5)  ≈ node (extension host) — fork-restore from worker-exec
        eprintln!("[coord] building deep mixed chain (D3 → D4 → D5)");
        let r = runner
            .send(
                "AA",
                Command::Spawn {
                    children: vec!["D3".to_string()],
                },
            )
            .await;
        eprintln!("[coord] AA spawn D3: {r:?}");

        if matches!(&r, Response::Ok { .. }) {
            let r = runner
                .send(
                    "AA",
                    Command::Forward {
                        target: "D3".to_string(),
                        inner: Box::new(Command::SpawnRemote {
                            children: vec!["D4".to_string()],
                        }),
                    },
                )
                .await;
            eprintln!("[coord] D3 SpawnRemote D4: {r:?}");

            if matches!(&r, Response::Ok { .. }) {
                let r = runner
                    .send(
                        "AA",
                        Command::Forward {
                            target: "D3".to_string(),
                            inner: Box::new(Command::Forward {
                                target: "D4".to_string(),
                                inner: Box::new(Command::Spawn {
                                    children: vec!["D5".to_string()],
                                }),
                            }),
                        },
                    )
                    .await;
                eprintln!("[coord] D4 spawn D5: {r:?}");
            }
        }
    } else {
        eprintln!("[coord] non-PIE binary not found, skipping mixed tree");
    }

    let should_run = |suite: &str| filter.is_none() || filter == Some(suite);

    // =================================================================
    // MATRIX: Capability x topology cross-product tests
    // FS CRUD, TCP, Unix sockets, exec, env, network addresses,
    // symlinks, netlink, IPv6, terminal ioctl, filesystem I/O,
    // syscall capabilities (poll, getsockname, epoll, pipe, proc, TCP).
    // =================================================================
    if should_run("matrix") {
        eprintln!("[coord] === Matrix Tests ===");
        matrix::run_matrix_tests(&mut runner).await;
        special_cases::netlink_tests(&mut runner).await;
        special_cases::net_ipv6_tests(&mut runner).await;
        special_cases::terminal_ioctl_tests(&mut runner).await;
        special_cases::fs_io_tests(&mut runner).await;
        platform_fixes::poll_ready_tests(&mut runner).await;
        platform_fixes::bind_getsockname_tests(&mut runner).await;
        platform_fixes::pipe_pair_id_tests(&mut runner).await;
        platform_fixes::pipe_nonblock_tests(&mut runner).await;
        platform_fixes::epoll_socket_tests(&mut runner).await;
        platform_fixes::loopback_tcp_tests(&mut runner).await;
        platform_fixes::proc_filesystem_tests(&mut runner).await;
    }

    // =================================================================
    // FORK: Fork/exec patterns, delayed fork, PIE/non-PIE, pipes
    // =================================================================
    if should_run("fork") {
        eprintln!("[coord] === Fork Tests ===");
        fork_matrix::run_fork_matrix_tests(&mut runner).await;
        platform_fixes::exit_data_integrity_tests(&mut runner).await;
        platform_fixes::nonpie_pipe_chain_tests(&mut runner).await;
        platform_fixes::bash_fork_exec_tests(&mut runner).await;
        platform_fixes::concurrent_fork_tests(&mut runner).await;
        platform_fixes::pid_visibility_tests(&mut runner).await;
        special_cases::capture_pipe_tests(&mut runner).await;
        special_cases::node_exit_tests(&mut runner).await;
    }

    // =================================================================
    // SHELL: Bash-specific redirect, touch, stdin-pipe patterns
    // =================================================================
    if should_run("shell") {
        eprintln!("[coord] === Shell Tests ===");
        platform_fixes::stdin_pipe_subst_tests(&mut runner).await;
        platform_fixes::subst_capture_tests(&mut runner).await;
        platform_fixes::touch_redirect_tests(&mut runner).await;
        platform_fixes::file_redirect_tests(&mut runner).await;
        special_cases::stdin_script_tests(&mut runner).await;
    }

    // =================================================================
    // XWORKER: Cross-worker FS, TCP, Unix sockets, port routing
    // =================================================================
    if should_run("xworker") {
        eprintln!("[coord] === Cross-Worker Tests ===");
        platform_fixes::cross_worker_first_connect_tests(&mut runner).await;
        platform_fixes::cross_worker_self_connect_tests(&mut runner).await;
        platform_fixes::cross_worker_file_tests(&mut runner).await;
        platform_fixes::fork_listen_close_tests(&mut runner).await;
        special_cases::unix_socket_tests(&mut runner).await;
        special_cases::cross_worker_tests(&mut runner).await;
    }

    // =================================================================
    // VSCODE: VS Code Server patterns (needs litebox-vscode image)
    // =================================================================
    if should_run("vscode") {
        eprintln!("[coord] === VS Code Tests ===");
        vscode::vscode_repro_tests(&mut runner).await;
        vscode::vscode_bootstrap_replay(&mut runner).await;
        platform_fixes::vscode_install_pattern_tests(&mut runner).await;
    }

    // =================================================================
    // STRESS: TCP stress, port router, file+TCP combined (slow)
    // =================================================================
    if should_run("stress") {
        eprintln!("[coord] === Stress Tests ===");
        tcp_stress::run(&mut runner).await;
        file_tcp::run(&mut runner).await;
        port_router::run(&mut runner).await;
    }

    // =================================================================
    // CONTAMINATION: State accumulation tests (MUST run last)
    // =================================================================
    if should_run("contamination") {
        eprintln!("[coord] === Contamination Sequence Tests ===");
        {
            let canary_cmd = crate::protocol::Command::Exec {
                args: vec![runner.self_exe.clone(), "echo-test".into()],
                timeout_secs: None,
                stdin: None,
                background: false,
            };
            let resp = runner.send("A", canary_cmd).await;
            let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout == "ECHO_TEST_OK");
            runner.record("X_canary.pre_sequence", "A", pass, &format!("{resp:?}"));
        }
        special_cases::contamination_sequence_tests(&mut runner).await;
    }

    // Shutdown all children.
    for (id, mut child) in runner.children.drain() {
        let _ = send_cmd(&mut child, &Command::Exit).await;
        let _ = child.process.wait().await;
        eprintln!("[coord] {id} exited");
    }

    runner.results
}

/// Route a target agent name to (direct_child, remaining_path).
/// "A" → ("A", None), "AA" → ("A", Some("AA")), "NP" → ("A", Some("NP"))
fn route(target: &str) -> (&str, Option<&str>) {
    match target {
        "A" | "B" => (target, None),
        // Agents under A: AA*, AB, NP, NPC, D3, D4, D5
        "NP" | "NPC" | "D3" | "D4" | "D5" => ("A", Some(target)),
        s if s.starts_with('A') => ("A", Some(s)),
        _ => (target, None),
    }
}

/// Wrap a command in Forward layers for routing through the tree.
fn wrap_forwards(remaining: Option<&str>, cmd: Command) -> Command {
    match remaining {
        None => cmd,
        Some(target) => {
            // "AA" or "AB" → forward directly (children of A)
            if target == "AA" || target == "AB" {
                Command::Forward {
                    target: target.to_string(),
                    inner: Box::new(cmd),
                }
            } else if target.starts_with("AA") && target != "AA" {
                // "AAA", "AAB" → forward to AA, then forward to target
                Command::Forward {
                    target: "AA".to_string(),
                    inner: Box::new(Command::Forward {
                        target: target.to_string(),
                        inner: Box::new(cmd),
                    }),
                }
            } else if target == "NP" {
                // NP is a direct child of A (via SpawnRemote)
                Command::Forward {
                    target: "NP".to_string(),
                    inner: Box::new(cmd),
                }
            } else if target == "NPC" {
                // NPC is a child of NP → forward through NP
                Command::Forward {
                    target: "NP".to_string(),
                    inner: Box::new(Command::Forward {
                        target: "NPC".to_string(),
                        inner: Box::new(cmd),
                    }),
                }
            } else if target == "D3" {
                // D3 is a child of AA
                Command::Forward {
                    target: "AA".to_string(),
                    inner: Box::new(Command::Forward {
                        target: "D3".to_string(),
                        inner: Box::new(cmd),
                    }),
                }
            } else if target == "D4" {
                // D4 is a child of D3 (under AA)
                Command::Forward {
                    target: "AA".to_string(),
                    inner: Box::new(Command::Forward {
                        target: "D3".to_string(),
                        inner: Box::new(Command::Forward {
                            target: "D4".to_string(),
                            inner: Box::new(cmd),
                        }),
                    }),
                }
            } else if target == "D5" {
                // D5 is a child of D4 (under D3 under AA)
                Command::Forward {
                    target: "AA".to_string(),
                    inner: Box::new(Command::Forward {
                        target: "D3".to_string(),
                        inner: Box::new(Command::Forward {
                            target: "D4".to_string(),
                            inner: Box::new(Command::Forward {
                                target: "D5".to_string(),
                                inner: Box::new(cmd),
                            }),
                        }),
                    }),
                }
            } else {
                Command::Forward {
                    target: target.to_string(),
                    inner: Box::new(cmd),
                }
            }
        }
    }
}

async fn spawn_child(self_exe: &str) -> Result<Child, String> {
    let mut child = tokio::process::Command::new(self_exe)
        .arg("agent")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("{e}"))?;

    let stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;

    Ok(Child {
        stdin,
        stdout: BufReader::new(stdout),
        process: child,
    })
}

async fn send_cmd(child: &mut Child, cmd: &Command) -> Response {
    // Use a longer response timeout for Exec commands with custom timeouts.
    // Dig through Forward wrappers to find the inner command's timeout.
    let inner_timeout = {
        let mut c = cmd;
        loop {
            match c {
                Command::Forward { inner, .. } => c = inner,
                Command::Exec {
                    timeout_secs: Some(t),
                    ..
                } => break Some(*t),
                _ => break None,
            }
        }
    };
    let response_timeout = match inner_timeout {
        Some(t) => Duration::from_secs(t + 5),
        None => Duration::from_secs(15),
    };

    let json = serde_json::to_string(cmd).unwrap();
    if child
        .stdin
        .write_all(format!("{json}\n").as_bytes())
        .await
        .is_err()
    {
        return Response::Error {
            error: "write failed".to_string(),
        };
    }
    let _ = child.stdin.flush().await;

    let mut line = String::new();
    match tokio::time::timeout(response_timeout, child.stdout.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => match serde_json::from_str(line.trim()) {
            Ok(resp) => resp,
            Err(e) => Response::Error {
                error: format!("parse: {e}: {line}"),
            },
        },
        Ok(Ok(_)) => Response::Error {
            error: "EOF".into(),
        },
        Ok(Err(e)) => Response::Error {
            error: format!("read: {e}"),
        },
        Err(_) => Response::Error {
            error: "timeout".into(),
        },
    }
}



