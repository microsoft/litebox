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
    // F1: Parent-child CRUD
    // Phase 1: check absent
    let resp = r.send("A", Command::FsRead { path: "/shared/f1.txt".into() }).await;
    r.record("F1.absent", "A", matches!(resp, Response::NotFound), &format!("{resp:?}"));

    // Phase 2: init writes, child reads
    r.send("init", Command::FsWrite { path: "/shared/f1.txt".into(), data: "hello".into() }).await;
    let resp = r.send("A", Command::FsRead { path: "/shared/f1.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "hello");
    r.record("F1.created", "A", pass, &format!("{resp:?}"));

    // Phase 3: init updates, child reads
    r.send("init", Command::FsWrite { path: "/shared/f1.txt".into(), data: "updated".into() }).await;
    let resp = r.send("A", Command::FsRead { path: "/shared/f1.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "updated");
    r.record("F1.updated", "A", pass, &format!("{resp:?}"));

    // Phase 4: init deletes, child reads
    r.send("init", Command::FsDelete { path: "/shared/f1.txt".into() }).await;
    let resp = r.send("A", Command::FsRead { path: "/shared/f1.txt".into() }).await;
    r.record("F1.deleted", "A", matches!(resp, Response::NotFound), &format!("{resp:?}"));

    // F2: Child-parent
    r.send("A", Command::FsWrite { path: "/shared/f2.txt".into(), data: "from_child".into() }).await;
    let resp = r.send("init", Command::FsRead { path: "/shared/f2.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_child");
    r.record("F2", "init", pass, &format!("{resp:?}"));

    // F3: Sibling visibility
    r.send("A", Command::FsWrite { path: "/shared/f3.txt".into(), data: "from_A".into() }).await;
    let resp = r.send("B", Command::FsRead { path: "/shared/f3.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_A");
    r.record("F3", "B", pass, &format!("{resp:?}"));

    // F4: Grandchild visibility
    r.send("AA", Command::FsWrite { path: "/shared/f4.txt".into(), data: "from_AA".into() }).await;
    let resp = r.send("init", Command::FsRead { path: "/shared/f4.txt".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if d == "from_AA");
    r.record("F4", "init", pass, &format!("{resp:?}"));

    // F5: /tmp isolation
    r.send("A", Command::FsWrite { path: "/tmp/f5.txt".into(), data: "temp".into() }).await;
    let resp = r.send("AA", Command::FsRead { path: "/tmp/f5.txt".into() }).await;
    r.record("F5", "AA", matches!(resp, Response::NotFound), &format!("expect not_found: {resp:?}"));
}

async fn net_tests(r: &mut TestRunner) {
    // N1: Parent-child — A listens, init connects
    let resp = r.send("A", Command::NetListen { port: 9001 }).await;
    r.record("N1.listen", "A", matches!(resp, Response::Listening { .. }), &format!("{resp:?}"));

    let resp = r.send("init", Command::NetConnect { addr: "127.0.0.1:9001".into(), data: "PING".into() }).await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "PING");
    r.record("N1", "init→A", pass, &format!("{resp:?}"));

    // N2: Child-parent — init listens (via echo server), A connects
    // Init needs a listener — start one via net_listen on the local agent.
    // Actually init doesn't have an agent loop. Use a direct local listener.
    // For now, skip N2 from init's perspective (needs refactor).

    // N3: Sibling — B listens, A connects
    let resp = r.send("B", Command::NetListen { port: 9002 }).await;
    r.record("N3.listen", "B", matches!(resp, Response::Listening { .. }), &format!("{resp:?}"));

    let resp = r.send("A", Command::NetConnect { addr: "127.0.0.1:9002".into(), data: "SIBLING".into() }).await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "SIBLING");
    r.record("N3", "A→B", pass, &format!("{resp:?}"));

    // N4: Grandchild-grandparent — AAA connects to A's listener
    let resp = r.send("AAA", Command::NetConnect { addr: "127.0.0.1:9001".into(), data: "DEEP".into() }).await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "DEEP");
    r.record("N4", "AAA→A", pass, &format!("{resp:?}"));

    // N5: Deep nesting — AAA listens, B connects
    let resp = r.send("AAA", Command::NetListen { port: 9005 }).await;
    r.record("N5.listen", "AAA", matches!(resp, Response::Listening { .. }), &format!("{resp:?}"));

    let resp = r.send("B", Command::NetConnect { addr: "127.0.0.1:9005".into(), data: "CROSS".into() }).await;
    let pass = matches!(&resp, Response::Connected { echo } if echo == "CROSS");
    r.record("N5", "B→AAA", pass, &format!("{resp:?}"));

    // Cleanup
    r.send("A", Command::NetUnlisten { port: 9001 }).await;
    r.send("B", Command::NetUnlisten { port: 9002 }).await;
    r.send("AAA", Command::NetUnlisten { port: 9005 }).await;
}

async fn exec_tests(r: &mut TestRunner) {
    let self_exe = r.self_exe.clone();

    // X1: fork+exec from init
    let resp = r.send("A", Command::Exec { args: vec![self_exe.clone(), "echo-test".into()] }).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X1", "A", pass, &format!("{resp:?}"));

    // X2: fork+exec from worker (nested)
    let resp = r.send("AA", Command::Exec { args: vec![self_exe.clone(), "echo-test".into()] }).await;
    let pass = matches!(&resp, Response::ExecResult { stdout, .. } if stdout.contains("ECHO_TEST_OK"));
    r.record("X2", "AA", pass, &format!("{resp:?}"));

    // X3: exit code propagation
    let resp = r.send("A", Command::Exec { args: vec![self_exe.clone(), "exit-with".into(), "42".into()] }).await;
    let pass = matches!(&resp, Response::ExecResult { exit_code: 42, .. });
    r.record("X3", "A", pass, &format!("{resp:?}"));
}

async fn env_tests(r: &mut TestRunner) {
    // E1: Environment variable
    let resp = r.send("A", Command::EnvGet { var: "HOME".into() }).await;
    let pass = matches!(&resp, Response::Ok { data: Some(d) } if !d.is_empty() && d != "NOT_SET");
    r.record("E1", "A", pass, &format!("{resp:?}"));

    // E2: Current working directory
    let resp = r.send("A", Command::CwdGet).await;
    let pass = matches!(&resp, Response::Ok { data: Some(_) });
    r.record("E2", "A", pass, &format!("{resp:?}"));
}

/// Route a target like "AAA" to (direct_child, remaining_path).
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
