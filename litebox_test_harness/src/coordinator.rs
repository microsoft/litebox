// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test coordinator. Runs as the init process, drives all test
//! operations through pipes to child agents.

use crate::agent;
use crate::protocol::{Command, Response};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::Duration;

/// Create an Exec command with default 10s timeout.
fn exec(args: Vec<String>) -> Command {
    Command::Exec {
        args,
        timeout_secs: None,
    }
}

/// Create an Exec command with a custom timeout.
fn exec_timeout(args: Vec<String>, secs: u64) -> Command {
    Command::Exec {
        args,
        timeout_secs: Some(secs),
    }
}

struct Child {
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    #[allow(dead_code)]
    process: tokio::process::Child,
}

struct TestRunner {
    children: std::collections::HashMap<String, Child>,
    results: Vec<(String, String, bool, String)>, // (test, agent, pass, detail)
    self_exe: String,
}

impl TestRunner {
    fn record(&mut self, test: &str, agent: &str, pass: bool, detail: &str) {
        let status = if pass { "pass" } else { "fail" };
        // Use eprintln for test results since stdout is used for pipe protocol.
        eprintln!(
            "  {status}: {test} [{agent}] {detail}"
        );
        self.results.push((
            test.to_string(),
            agent.to_string(),
            pass,
            detail.to_string(),
        ));
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
                }
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

/// Run all tests as the coordinator.
pub fn run_all(self_exe: &str) -> Vec<(String, String, bool, String)> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run_tests(self_exe))
}

async fn run_tests(self_exe: &str) -> Vec<(String, String, bool, String)> {
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

    // === Filesystem Tests ===
    eprintln!("[coord] === Filesystem Tests ===");
    fs_tests(&mut runner).await;

    // === Network Tests ===
    eprintln!("[coord] === Network Tests ===");
    net_tests(&mut runner).await;

    // === Fork/Exec Tests ===
    eprintln!("[coord] === Fork/Exec Tests ===");
    exec_tests(&mut runner).await;

    // === Environment Tests ===
    eprintln!("[coord] === Environment Tests ===");
    env_tests(&mut runner).await;

    // === VS Code Reproduction Tests ===
    eprintln!("[coord] === VS Code Reproduction Tests ===");
    vscode_repro_tests(&mut runner).await;

    // Shutdown all children.
    for (id, mut child) in runner.children.drain() {
        let _ = send_cmd(&mut child, &Command::Exit).await;
        let _ = child.process.wait().await;
        eprintln!("[coord] {id} exited");
    }

    runner.results
}

async fn fs_tests(r: &mut TestRunner) {
    // F1: Parent→child CRUD (init writes, A reads)
    let resp = r.send("A", Command::FsRead { path: "/shared/f1.txt".into() }).await;
    r.record("F1.absent", "A", matches!(resp, Response::NotFound), &format!("{resp:?}"));
    r.send("init", Command::FsWrite { path: "/shared/f1.txt".into(), data: "hello".into() }).await;
    let resp = r.send("A", Command::FsRead { path: "/shared/f1.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "hello");
    r.record("F1.created", "A", pass, &format!("{resp:?}"));
    r.send("init", Command::FsWrite { path: "/shared/f1.txt".into(), data: "updated".into() }).await;
    let resp = r.send("A", Command::FsRead { path: "/shared/f1.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "updated");
    r.record("F1.updated", "A", pass, &format!("{resp:?}"));
    r.send("init", Command::FsDelete { path: "/shared/f1.txt".into() }).await;
    let resp = r.send("A", Command::FsRead { path: "/shared/f1.txt".into() }).await;
    r.record("F1.deleted", "A", matches!(resp, Response::NotFound), &format!("{resp:?}"));

    // F2: Child→parent (A writes, init reads)
    r.send("A", Command::FsWrite { path: "/shared/f2.txt".into(), data: "from_child".into() }).await;
    let resp = r.send("init", Command::FsRead { path: "/shared/f2.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_child");
    r.record("F2", "init", pass, &format!("{resp:?}"));
    // A updates, init reads update
    r.send("A", Command::FsWrite { path: "/shared/f2.txt".into(), data: "child_update".into() }).await;
    let resp = r.send("init", Command::FsRead { path: "/shared/f2.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "child_update");
    r.record("F2.update", "init", pass, &format!("{resp:?}"));
    // A deletes, init reads absent
    r.send("A", Command::FsDelete { path: "/shared/f2.txt".into() }).await;
    let resp = r.send("init", Command::FsRead { path: "/shared/f2.txt".into() }).await;
    r.record("F2.deleted", "init", matches!(resp, Response::NotFound), &format!("{resp:?}"));

    // F3: Sibling visibility (A writes, B reads)
    r.send("A", Command::FsWrite { path: "/shared/f3.txt".into(), data: "from_A".into() }).await;
    let resp = r.send("B", Command::FsRead { path: "/shared/f3.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_A");
    r.record("F3.A→B", "B", pass, &format!("{resp:?}"));
    // Reverse: B writes, A reads
    r.send("B", Command::FsWrite { path: "/shared/f3b.txt".into(), data: "from_B".into() }).await;
    let resp = r.send("A", Command::FsRead { path: "/shared/f3b.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_B");
    r.record("F3.B→A", "A", pass, &format!("{resp:?}"));

    // F4: Grandchild (AA writes, init reads)
    r.send("AA", Command::FsWrite { path: "/shared/f4.txt".into(), data: "from_AA".into() }).await;
    let resp = r.send("init", Command::FsRead { path: "/shared/f4.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_AA");
    r.record("F4.AA→init", "init", pass, &format!("{resp:?}"));
    // Cousin: AA writes, B reads
    let resp = r.send("B", Command::FsRead { path: "/shared/f4.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_AA");
    r.record("F4.AA→B", "B", pass, &format!("{resp:?}"));
    // Deep: AAA writes, init reads
    r.send("AAA", Command::FsWrite { path: "/shared/f4c.txt".into(), data: "from_AAA".into() }).await;
    let resp = r.send("init", Command::FsRead { path: "/shared/f4c.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_AAA");
    r.record("F4.AAA→init", "init", pass, &format!("{resp:?}"));

    // F5: /tmp isolation (A writes /tmp, AA reads — should be absent if isolated)
    r.send("A", Command::FsWrite { path: "/tmp/f5.txt".into(), data: "temp".into() }).await;
    let resp = r.send("AA", Command::FsRead { path: "/tmp/f5.txt".into() }).await;
    // Document actual behavior (shared or isolated).
    let is_isolated = matches!(resp, Response::NotFound);
    r.record("F5.parent→child", "AA", true, &format!("tmp_isolated={is_isolated}: {resp:?}"));
    // Sibling /tmp: A writes, B reads
    let resp = r.send("B", Command::FsRead { path: "/tmp/f5.txt".into() }).await;
    let is_isolated = matches!(resp, Response::NotFound);
    r.record("F5.sibling", "B", true, &format!("tmp_isolated={is_isolated}: {resp:?}"));

    // F6: Host pre-written file
    let resp = r.send("init", Command::FsRead { path: "/shared/host_wrote.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_host");
    r.record("F6.host→init", "init", pass, &format!("{resp:?}"));
    let resp = r.send("A", Command::FsRead { path: "/shared/host_wrote.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_host");
    r.record("F6.host→A", "A", pass, &format!("{resp:?}"));
    // Agent writes for host to read after exit
    r.send("init", Command::FsWrite { path: "/shared/for_host.txt".into(), data: "from_agent".into() }).await;
}

async fn net_tests(r: &mut TestRunner) {
    // N1: Parent→child (init → A)
    let resp = r.send("A", Command::NetListen { port: 9001 }).await;
    let pass = matches!(resp, Response::Listening { .. });
    r.record("N1.listen", "A", pass, &format!("{resp:?}"));

    let resp = r.send("init", Command::NetConnect { addr: "127.0.0.1:9001".into(), data: "N1".into() }).await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N1");
    r.record("N1.init→A", "init", pass, &format!("{resp:?}"));

    // N2: A → B (sibling)
    let resp = r.send("B", Command::NetListen { port: 9002 }).await;
    let pass = matches!(resp, Response::Listening { .. });
    r.record("N2.listen", "B", pass, &format!("{resp:?}"));

    let resp = r.send("A", Command::NetConnect { addr: "127.0.0.1:9002".into(), data: "N2".into() }).await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N2");
    r.record("N2.A→B", "A", pass, &format!("{resp:?}"));

    // N3: B → A (reverse sibling)
    let resp = r.send("B", Command::NetConnect { addr: "127.0.0.1:9001".into(), data: "N3".into() }).await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N3");
    r.record("N3.B→A", "B", pass, &format!("{resp:?}"));

    // N4: Grandchild → grandparent (AAA → A)
    let resp = r.send("AAA", Command::NetConnect { addr: "127.0.0.1:9001".into(), data: "N4".into() }).await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N4");
    r.record("N4.AAA→A", "AAA", pass, &format!("{resp:?}"));

    // Done with A:9001
    let resp = r.send("A", Command::NetUnlisten { port: 9001 }).await;
    r.record("N1.unlisten", "A", matches!(resp, Response::Ok { .. }), &format!("{resp:?}"));

    // N5: Cross-subtree (B → AAA)
    let resp = r.send("AAA", Command::NetListen { port: 9005 }).await;
    let pass = matches!(resp, Response::Listening { .. });
    r.record("N5.listen", "AAA", pass, &format!("{resp:?}"));

    let resp = r.send("B", Command::NetConnect { addr: "127.0.0.1:9005".into(), data: "N5".into() }).await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N5");
    r.record("N5.B→AAA", "B", pass, &format!("{resp:?}"));

    let resp = r.send("AAA", Command::NetUnlisten { port: 9005 }).await;
    r.record("N5.unlisten", "AAA", matches!(resp, Response::Ok { .. }), &format!("{resp:?}"));

    // N6: Sibling at depth 2 (AA → AB)
    let resp = r.send("AB", Command::NetListen { port: 9004 }).await;
    let pass = matches!(resp, Response::Listening { .. });
    r.record("N6.listen", "AB", pass, &format!("{resp:?}"));

    let resp = r.send("AA", Command::NetConnect { addr: "127.0.0.1:9004".into(), data: "N6".into() }).await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N6");
    r.record("N6.AA→AB", "AA", pass, &format!("{resp:?}"));

    let resp = r.send("AB", Command::NetUnlisten { port: 9004 }).await;
    r.record("N6.unlisten", "AB", matches!(resp, Response::Ok { .. }), &format!("{resp:?}"));

    // N7: Sibling at depth 3 (AAA → AAB)
    let resp = r.send("AAB", Command::NetListen { port: 9006 }).await;
    let pass = matches!(resp, Response::Listening { .. });
    r.record("N7.listen", "AAB", pass, &format!("{resp:?}"));

    let resp = r.send("AAA", Command::NetConnect { addr: "127.0.0.1:9006".into(), data: "N7".into() }).await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N7");
    r.record("N7.AAA→AAB", "AAA", pass, &format!("{resp:?}"));

    let resp = r.send("AAB", Command::NetUnlisten { port: 9006 }).await;
    r.record("N7.unlisten", "AAB", matches!(resp, Response::Ok { .. }), &format!("{resp:?}"));

    // N8: Uncle (AB → B)
    let resp = r.send("AB", Command::NetConnect { addr: "127.0.0.1:9002".into(), data: "N8".into() }).await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "N8");
    r.record("N8.AB→B", "AB", pass, &format!("{resp:?}"));

    // Done with B:9002
    let resp = r.send("B", Command::NetUnlisten { port: 9002 }).await;
    r.record("N8.unlisten", "B", matches!(resp, Response::Ok { .. }), &format!("{resp:?}"));
}

async fn exec_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    // X1: fork+exec from first-level worker
    let resp = r.send("A", exec(vec![self_exe.clone(), "echo-test".into()])).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X1.A", "A", pass, &format!("{resp:?}"));

    // X2: fork+exec from second-level worker
    let resp = r.send("AA", exec(vec![self_exe.clone(), "echo-test".into()])).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X2.AA", "AA", pass, &format!("{resp:?}"));

    // X3: fork+exec from third-level worker
    let resp = r.send("AAA", exec(vec![self_exe.clone(), "echo-test".into()])).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X3.AAA", "AAA", pass, &format!("{resp:?}"));

    // X4: exit code propagation
    let resp = r.send("A", exec(vec![self_exe.clone(), "exit-with".into(), "42".into()])).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 42, .. });
    r.record("X4.exit_code", "A", pass, &format!("{resp:?}"));

    // X5: exit code from deep worker
    let resp = r.send("AAA", exec(vec![self_exe.clone(), "exit-with".into(), "7".into()])).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 7, .. });
    r.record("X5.deep_exit", "AAA", pass, &format!("{resp:?}"));

    // ── Delayed-fork limitation reproduction tests ──
    // Each test runs a shell command via bash -c to exercise specific
    // fork patterns that stress litebox's delayed-fork (vfork) architecture.
    // Tests that deadlock will timeout after 10s and return ExecTimeout.

    let bash = |cmd: &str| -> Vec<String> {
        vec!["bash".into(), "-c".into(), cmd.into()]
    };

    // X6: Baseline — simple bash echo (fork+exec, no pipes)
    // Expected: pass — same as X1 but through bash.
    let resp = r.send("A", exec(bash("echo hello_from_bash"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("hello_from_bash"));
    r.record("X6.bash_echo", "A", pass, &format!("{resp:?}"));

    // X7: Command substitution — $(echo inner)
    // This forks a subshell to run `echo inner`, captures its stdout.
    // The subshell does fork+exec of echo, then the parent reads the result.
    let resp = r.send("A", exec(bash("echo $(echo inner_value)"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("inner_value"));
    r.record("X7.cmd_substitution", "A", pass, &format!("{resp:?}"));

    // X8: Pipe inside command substitution — $(echo hello | cat)
    // Known delayed-fork stress test: subshell forks twice (echo + cat),
    // cat calls read() which is non-pre-exec, triggering delayed fork.
    // Pipe data from echo must be bridged to the new worker for cat.
    let resp = r.send("A", exec(bash("echo $(echo pipe_data | cat)"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("pipe_data"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X8.pipe_in_subshell", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X9: Process substitution — cat <(echo hello)
    // Uses /dev/fd/N (procfs symlink to anonymous pipe). Fails because
    // /dev/fd and /proc/self/fd are not mounted in the litebox rootfs.
    // This is a FILESYSTEM gap (missing devfs/procfs), not a fork issue.
    // Expected: fail with "No such file or directory" on /dev/fd/N.
    let resp = r.send("A", exec(bash("cat <(echo proc_sub_data)"))).await;
    let is_devfd_error = matches!(&resp, Response::ExecResult { exit_code: 1, stderr, .. } if stderr.contains("/dev/fd"));
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("proc_sub_data"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    // Record as xfail: expected to fail due to missing /dev/fd.
    let result = pass || is_devfd_error;
    r.record("X9.process_substitution", "A", result, &format!("xfail_devfd={is_devfd_error} timeout={timeout} {resp:?}"));

    // X10: Simple two-stage pipe — echo | cat
    // Shell forks twice (one for echo, one for cat), connects via pipe.
    // Each fork is serialized due to vfork semantics.
    let resp = r.send("A", exec(bash("echo pipe_two_stage | cat"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("pipe_two_stage"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X10.simple_pipe", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X11: Three-stage pipe — echo | cat | cat
    // Three children, two pipes. Tests chained pipe bridging across
    // multiple delayed-fork migrations.
    let resp = r.send("A", exec(bash("echo three_stage | cat | cat"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("three_stage"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X11.three_stage_pipe", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X12: Background process with wait — sleep 0 & wait; echo done
    // fork() for `sleep 0` with & makes parent continue. But vfork blocks
    // the parent until the child does exec or exits. Tests whether
    // backgrounding works at all.
    let resp = r.send("A", exec(bash("sleep 0 & wait; echo bg_done"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("bg_done"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X12.background_wait", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X13: Multiple background processes — echo a & echo b & wait
    // Two concurrent forks. With vfork semantics, these run serially.
    // Tests whether the outputs from both appear.
    let resp = r.send("A", exec(bash("echo bg_a & echo bg_b & wait"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("bg_a") && stdout.contains("bg_b"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X13.multi_background", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X14: Subshell exit code — (exit 42); echo $?
    // Subshell fork with immediate exit. Tests whether exit code
    // propagates back through the vfork/delayed-fork path.
    let resp = r.send("A", exec(bash("(exit 42); echo $?"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("42"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X14.subshell_exit_code", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X15: Sequential commands without pipes (baseline)
    // Multiple fork+exec operations chained with &&. No pipes between them,
    // just sequential execution. Validates basic multi-command shell scripts.
    let resp = r.send("A", exec(bash("echo seq_a && echo seq_b && echo seq_c"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("seq_a") && stdout.contains("seq_c"));
    r.record("X15.sequential_cmds", "A", pass, &format!("{resp:?}"));

    // ── More aggressive delayed-fork stress tests ──

    // X16: Deeply nested command substitution
    // Each $(…) creates a subshell fork. Three levels of nesting means
    // three sequential fork+exec+capture cycles.
    let resp = r.send("A", exec(bash("echo $(echo $(echo deep_nested))"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("deep_nested"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X16.nested_subshell", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X17: Here-document — uses an internal pipe to feed stdin
    // bash creates a pipe for the heredoc content, forks the command,
    // and the child reads from the pipe.
    let resp = r.send("A", exec(bash("cat <<'EOF'\nheredoc_line\nEOF"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("heredoc_line"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X17.heredoc", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X18: Here-string — simpler variant of heredoc
    let resp = r.send("A", exec(bash("cat <<< 'herestring_data'"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("herestring_data"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X18.herestring", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X19: Pipe with grep — common real-world pattern
    // Tests pipe bridging with a program (grep) that does buffered reads.
    let resp = r.send("A", exec(bash("echo -e 'alpha\\nbeta\\ngamma' | grep beta"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("beta"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X19.pipe_grep", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X20: Command substitution with pipe and wc — VS Code install pattern
    // `$(curl ... | sh)` like patterns use command substitution + pipe.
    let resp = r.send("A", exec(bash("echo $(echo 'line1\\nline2\\nline3' | wc -l)"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.trim() != "");
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X20.subshell_pipe_wc", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X21: Backtick substitution (older syntax) — equivalent to $() but
    // tests different bash code path.
    let resp = r.send("A", exec(bash("echo `echo backtick_val`"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("backtick_val"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X21.backtick_subst", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X22: Pipe to while-read loop — common shell pattern that does
    // fork + pipe + read in a loop. The read is non-pre-exec.
    let resp = r.send("A", exec(bash("echo -e 'a\\nb\\nc' | while read line; do echo \"got_$line\"; done"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("got_a") && stdout.contains("got_c"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X22.pipe_while_read", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // X23: Pipe from second-level worker — same as X10 but from AA.
    // Tests whether pipe bridging works differently at deeper nesting.
    let resp = r.send("AA", exec(bash("echo deeper_pipe | cat"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("deeper_pipe"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X23.deep_pipe", "AA", pass, &format!("timeout={timeout} {resp:?}"));

    // X24: Pipe in subshell from deep worker — X8 from AAA.
    let resp = r.send("AAA", exec(bash("echo $(echo deep_sub | cat)"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("deep_sub"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X24.deep_subshell_pipe", "AAA", pass, &format!("timeout={timeout} {resp:?}"));

    // X25: xargs — forks multiple child processes from piped input.
    let resp = r.send("A", exec(bash("echo -e 'p\\nq\\nr' | xargs -I{} echo xargs_{}"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("xargs_p") && stdout.contains("xargs_r"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("X25.xargs", "A", pass, &format!("timeout={timeout} {resp:?}"));
}

async fn env_tests(r: &mut TestRunner) {
    // E1: HOME env var
    let resp = r.send("A", Command::EnvGet { var: "HOME".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
    r.record("E1.A", "A", pass, &format!("{resp:?}"));

    // E2: PATH env var
    let resp = r.send("A", Command::EnvGet { var: "PATH".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
    r.record("E2.A", "A", pass, &format!("{resp:?}"));

    // E3: CWD
    let resp = r.send("A", Command::CwdGet).await;
    let pass = matches!(&resp, Response::Ok { data: Some(_) });
    r.record("E3.A", "A", pass, &format!("{resp:?}"));

    // E4: Env var from deep worker
    let resp = r.send("AAA", Command::EnvGet { var: "HOME".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
    r.record("E4.AAA", "AAA", pass, &format!("{resp:?}"));

    // E5: CWD from sibling
    let resp = r.send("B", Command::CwdGet).await;
    let pass = matches!(&resp, Response::Ok { data: Some(_) });
    r.record("E5.B", "B", pass, &format!("{resp:?}"));
}

/// VS Code Server reproduction tests — isolate known connection failure modes.
async fn vscode_repro_tests(r: &mut TestRunner) {
    let bash = |cmd: &str| -> Vec<String> {
        vec!["bash".into(), "-c".into(), cmd.into()]
    };

    // T1: Unix domain socket lifecycle in /tmp
    // Reproduces Issue 1: code-server uses --socket-path=/tmp/code-UUID.
    // Tests whether AF_UNIX bind/listen/connect/accept/send/recv works.
    let resp = r.send("A", Command::UnixSocketTest { path: "/tmp/test-t1.sock".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d.contains("unix_socket_ok"));
    r.record("T1.unix_socket", "A", pass, &format!("{resp:?}"));

    // T1b: Unix socket from deeper worker (AA)
    let resp = r.send("AA", Command::UnixSocketTest { path: "/tmp/test-t1b.sock".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d.contains("unix_socket_ok"));
    r.record("T1b.unix_socket_deep", "AA", pass, &format!("{resp:?}"));

    // T2: Port reuse after unlisten
    // Reproduces Issue 2: empty listeningOn when port 9100 is still held.
    // Worker A listens on 9100, unlistens, then worker B tries to listen.
    let resp = r.send("A", Command::NetListen { port: 9100 }).await;
    let listen_ok = matches!(&resp, Response::Listening { port: 9100 });
    r.record("T2.listen_A", "A", listen_ok, &format!("{resp:?}"));

    let resp = r.send("A", Command::NetUnlisten { port: 9100 }).await;
    r.record("T2.unlisten_A", "A", matches!(&resp, Response::Ok { .. }), &format!("{resp:?}"));

    // Small delay for port cleanup.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let resp = r.send("B", Command::NetListen { port: 9100 }).await;
    let pass = matches!(&resp, Response::Listening { port: 9100 });
    r.record("T2.reuse_B", "B", pass, &format!("{resp:?}"));

    // Clean up.
    if pass {
        let _ = r.send("B", Command::NetUnlisten { port: 9100 }).await;
    }

    // T3: /tmp file creation from forked bash
    // Reproduces Issue 3: /tmp/.vscode-bootstrap-N.sh: Permission denied.
    let resp = r.send("A", exec(bash("echo tmp_write_test > /tmp/t3-test.sh && cat /tmp/t3-test.sh && rm /tmp/t3-test.sh"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("tmp_write_test"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("T3.tmp_write", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // T3b: /tmp write from deeper worker
    let resp = r.send("AA", exec(bash("echo deep_tmp > /tmp/t3b-test.sh && cat /tmp/t3b-test.sh && rm /tmp/t3b-test.sh"))).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 0, stdout, .. } if stdout.contains("deep_tmp"));
    r.record("T3b.tmp_write_deep", "AA", pass, &format!("{resp:?}"));

    // T4: Node.js code-server startup
    // Reproduces Issue 1: code-server process dies after ~75s.
    // Try to run code-server with --socket-path; if binary exists it should
    // start (timeout = running = good). If binary not found, skip.
    // Note: Uses bash builtin `kill` for timeout since `timeout` cmd may not be in rootfs.
    let code_server = "/root/.vscode-server/cli/servers/Stable-ae130017f8afe532557dbb8539a6ef3bdaec6389/server/bin/code-server";
    let resp = r.send("A", exec_timeout(vec![
        "bash".into(), "-c".into(),
        format!("if [ -x {code_server} ]; then {code_server} --connection-token=test --accept-server-license-terms --start-server --socket-path=/tmp/t4-test.sock 2>&1 & PID=$!; sleep 3; kill $PID 2>/dev/null; wait $PID 2>/dev/null; echo exit=$?; else echo SKIP_NOT_FOUND; fi"),
    ], 30)).await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP_NOT_FOUND"));
    let started = matches!(&resp, Response::ExecResult { stdout, .. } if !stdout.contains("SKIP_NOT_FOUND"))
        || matches!(&resp, Response::ExecTimeout { .. });
    if skipped {
        r.record("T4.code_server", "A", true, "skipped (binary not found)");
    } else {
        // Any output (even crash) is informative — record it.
        r.record("T4.code_server", "A", started, &format!("{resp:?}"));
    }
    // Clean up socket.
    let _ = r.send("A", exec(bash("rm -f /tmp/t4-test.sock"))).await;

    // T5: Unix socket bidirectional data flow (cross-process)
    // Mimics CLI↔code-server: one process listens on a Unix socket,
    // another connects and sends data. Verifies echo round-trip.
    // Uses Rust subcommands (unix-echo-server/client) instead of python3.
    // bash orchestrates server background + client foreground.
    let self_exe = r.self_exe.clone();
    let resp = r.send("A", exec_timeout(bash(
        &format!("rm -f /tmp/t5.sock; \
         {self_exe} unix-echo-server /tmp/t5.sock & \
         SERVER_PID=$!; \
         sleep 1; \
         RESULT=$({self_exe} unix-echo-client /tmp/t5.sock UNIX_ECHO_TEST 2>&1); \
         echo \"t5_result=$RESULT\"; \
         kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null; \
         rm -f /tmp/t5.sock")
    ), 30)).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("t5_result=UNIX_ECHO_TEST"));
    let timeout = matches!(&resp, Response::ExecTimeout { .. });
    r.record("T5.unix_relay", "A", pass, &format!("timeout={timeout} {resp:?}"));

    // T6: code-server stderr capture — does it create the Unix socket?
    // Run code-server, wait briefly, check if /tmp/t6-test.sock exists.
    // If the socket file exists, code-server started successfully.
    let resp = r.send("A", exec_timeout(bash(
        &format!("if [ -x {code_server} ]; then \
            {code_server} --connection-token=test --accept-server-license-terms \
            --start-server --socket-path=/tmp/t6-test.sock >/dev/null 2>&1 & \
            PID=$!; sleep 3; \
            if [ -S /tmp/t6-test.sock ]; then echo SOCKET_CREATED; else echo SOCKET_MISSING; fi; \
            kill $PID 2>/dev/null; wait $PID 2>/dev/null; \
         else echo SKIP_NOT_FOUND; fi")
    ), 30)).await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP_NOT_FOUND"));
    if skipped {
        r.record("T6.code_server_socket", "A", true, "skipped (binary not found)");
    } else {
        let socket_created = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SOCKET_CREATED"));
        r.record("T6.code_server_socket", "A", socket_created, &format!("{resp:?}"));
    }
    let _ = r.send("A", exec(bash("rm -f /tmp/t6-test.sock"))).await;

    // T7: code-server stays alive with auto-shutdown (no client)
    // Run with --enable-remote-auto-shutdown and no client connecting.
    // After 5s, check if still running. It should be (75s timeout).
    let resp = r.send("A", exec_timeout(bash(
        &format!("if [ -x {code_server} ]; then \
            {code_server} --connection-token=test --accept-server-license-terms \
            --start-server --enable-remote-auto-shutdown \
            --socket-path=/tmp/t7-test.sock >/dev/null 2>&1 & \
            PID=$!; sleep 5; \
            if kill -0 $PID 2>/dev/null; then echo STILL_RUNNING; else echo EXITED_EARLY; fi; \
            kill $PID 2>/dev/null; wait $PID 2>/dev/null; \
         else echo SKIP_NOT_FOUND; fi")
    ), 30)).await;
    let skipped = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("SKIP_NOT_FOUND"));
    if skipped {
        r.record("T7.auto_shutdown", "A", true, "skipped (binary not found)");
    } else {
        let still_running = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("STILL_RUNNING"));
        r.record("T7.auto_shutdown", "A", still_running, &format!("{resp:?}"));
    }
    let _ = r.send("A", exec(bash("rm -f /tmp/t7-test.sock"))).await;
}

/// Route a targetlike "AAA" to (direct_child, remaining_path).
/// "A" → ("A", None), "AA" → ("A", Some("AA")), "AAA" → ("A", Some("AAA"))
fn route(target: &str) -> (&str, Option<&str>) {
    match target {
        "A" | "B" => (target, None),
        s if s.starts_with("A") => ("A", Some(s)),
        _ => (target, None),
    }
}

/// Wrap a command in Forward layers for routing through the tree.
fn wrap_forwards(remaining: Option<&str>, cmd: Command) -> Command {
    match remaining {
        None => cmd,
        Some(target) => {
            // "AA" → forward to AA, "AAA" → forward to AA which forwards to AAA
            if target == "AA" || target == "AB" {
                Command::Forward {
                    target: target.to_string(),
                    inner: Box::new(cmd),
                }
            } else if target.starts_with("AA") {
                // "AAA" or "AAB" → forward to AA, then forward to target
                Command::Forward {
                    target: "AA".to_string(),
                    inner: Box::new(Command::Forward {
                        target: target.to_string(),
                        inner: Box::new(cmd),
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
        Ok(Ok(_)) => Response::Error { error: "EOF".into() },
        Ok(Err(e)) => Response::Error {
            error: format!("read: {e}"),
        },
        Err(_) => Response::Error {
            error: "timeout".into(),
        },
    }
}
