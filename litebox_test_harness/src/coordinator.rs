// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test coordinator. Runs as the init process, drives all test
//! operations through pipes to child agents.

use crate::agent;
use crate::protocol::{Command, Response};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::Duration;

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
    let resp = r.send("A", Command::Exec { args: vec![self_exe.clone(), "echo-test".into()] }).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X1.A", "A", pass, &format!("{resp:?}"));

    // X2: fork+exec from second-level worker
    let resp = r.send("AA", Command::Exec { args: vec![self_exe.clone(), "echo-test".into()] }).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X2.AA", "AA", pass, &format!("{resp:?}"));

    // X3: fork+exec from third-level worker
    let resp = r.send("AAA", Command::Exec { args: vec![self_exe.clone(), "echo-test".into()] }).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X3.AAA", "AAA", pass, &format!("{resp:?}"));

    // X4: exit code propagation
    let resp = r.send("A", Command::Exec { args: vec![self_exe.clone(), "exit-with".into(), "42".into()] }).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 42, .. });
    r.record("X4.exit_code", "A", pass, &format!("{resp:?}"));

    // X5: exit code from deep worker
    let resp = r.send("AAA", Command::Exec { args: vec![self_exe.clone(), "exit-with".into(), "7".into()] }).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 7, .. });
    r.record("X5.deep_exit", "AAA", pass, &format!("{resp:?}"));
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
    match tokio::time::timeout(Duration::from_secs(15), child.stdout.read_line(&mut line)).await {
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
