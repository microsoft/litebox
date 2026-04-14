// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Agent: spawn process tree, coordinate via stdin/stdout pipes.
//!
//! Each parent spawns children with piped stdin/stdout. After writing
//! test files, the parent sends the run command to each child's stdin.
//! Children run tests (with echo server for network tests) and write
//! JSON result lines to stdout. Parents read and aggregate results.

use crate::protocol::{AgentReady, Command, Outcome, TestResult};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;

fn tree_children(id: &str) -> &'static [&'static str] {
    match id {
        "init" => &["A", "B"],
        "A" => &["AA", "AB"],
        "AA" => &["AAA", "AAB"],
        _ => &[],
    }
}

pub fn agent_port(id: &str) -> u16 {
    match id {
        "init" => 9000,
        "A" => 9001,
        "B" => 9002,
        "AA" => 9003,
        "AB" => 9004,
        "AAA" => 9005,
        "AAB" => 9006,
        _ => 9099,
    }
}

const ALL_AGENTS: &[&str] = &["A", "B", "AA", "AB", "AAA", "AAB"];

pub fn run_coordinator(self_exe: &str) -> Vec<TestResult> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run_node(self_exe, "init", None))
}

pub fn run_agent(self_exe: &str, id: &str) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        let mut stdin = BufReader::new(tokio::io::stdin());
        let results = run_node(self_exe, id, Some(&mut stdin)).await;
        for r in &results {
            println!("{}", serde_json::to_string(r).unwrap());
        }
        println!("{{\"done\":true}}");
        // Keep echo server alive until parent closes our stdin.
        // Use a blocking thread so tokio can drive the echo server.
        let (eof_tx, eof_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1];
            let _ = std::io::Read::read(&mut std::io::stdin(), &mut buf);
            let _ = eof_tx.send(());
        });
        let _ = tokio::time::timeout(Duration::from_secs(60), eof_rx).await;
    });
}

/// Core logic for any node in the tree (init or agent).
/// Reads the run command from `parent_stdin` (None for init).
/// Returns all results (own + children's).
async fn run_node(
    self_exe: &str,
    id: &str,
    mut parent_stdin: Option<&mut BufReader<tokio::io::Stdin>>,
) -> Vec<TestResult> {
    eprintln!("[{id}] starting");

    // Bind echo server port.
    let port = agent_port(id);
    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap_or_else(|e| panic!("[{id}] bind {port}: {e}"));
    eprintln!("[{id}] bound port {port}");

    // Start echo server.
    let echo_task = tokio::spawn(echo_server(listener));

    // Spawn children with piped stdin/stdout.
    let children_ids = tree_children(id);
    let mut children: Vec<(&str, tokio::process::Child)> = Vec::new();
    for &child_id in children_ids {
        match tokio::process::Command::new(self_exe)
            .arg("agent")
            .arg("--id")
            .arg(child_id)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
        {
            Ok(child) => {
                eprintln!("[{id}] spawned {child_id}");
                children.push((child_id, child));
            }
            Err(e) => eprintln!("[{id}] spawn {child_id} failed: {e}"),
        }
    }

    // If we have a parent, read the run command from stdin.
    // If we're init, build the command ourselves.
    let has_parent = parent_stdin.is_some();
    let peers: Vec<AgentReady> = if let Some(reader) = parent_stdin.as_mut() {
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut line)).await {
            Ok(Ok(n)) if n > 0 => {
                if let Ok(Command::RunTests { peers }) = serde_json::from_str(line.trim()) {
                    peers
                } else {
                    eprintln!("[{id}] bad command from parent: {line}");
                    Vec::new()
                }
            }
            _ => {
                eprintln!("[{id}] no command from parent");
                Vec::new()
            }
        }
    } else {
        // Init builds the peer list from known ports.
        ALL_AGENTS
            .iter()
            .map(|&aid| AgentReady {
                id: aid.to_string(),
                pid: 0,
                port: agent_port(aid),
            })
            .chain(std::iter::once(AgentReady {
                id: "init".to_string(),
                pid: std::process::id(),
                port: agent_port("init"),
            }))
            .collect()
    };

    // Write parent-to-child test files BEFORE signaling children.
    let _ = tokio::fs::create_dir_all("/shared").await;
    for &child_id in children_ids {
        let path = format!("/shared/{id}_for_{child_id}.txt");
        let _ = tokio::fs::write(&path, format!("FROM_PARENT_{id}")).await;
    }

    // Two-phase protocol:
    // Phase A: Send peers to children, wait for all to report ready.
    let cmd = Command::RunTests {
        peers: peers.clone(),
    };
    let cmd_json = serde_json::to_string(&cmd).unwrap();
    let mut child_stdins: Vec<tokio::process::ChildStdin> = Vec::new();
    let mut child_stdouts: Vec<(&str, BufReader<tokio::process::ChildStdout>)> = Vec::new();

    for (child_id, child) in &mut children {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(format!("{cmd_json}\n").as_bytes()).await;
            let _ = stdin.flush().await;
            child_stdins.push(stdin);
        }
        if let Some(stdout) = child.stdout.take() {
            child_stdouts.push((child_id, BufReader::new(stdout)));
        }
    }

    // Wait for each child to write {"ready":true}, then verify
    // the child is reachable through the network. This ensures the
    // LBPL port registration has propagated through the broker before
    // we signal our own parent that we're ready.
    for (child_id, reader) in &mut child_stdouts {
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_secs(15), reader.read_line(&mut line)).await {
            Ok(Ok(n)) if n > 0 && line.contains("\"ready\":true") => {
                eprintln!("[{id}] {child_id} signaled ready, verifying reachable...");
            }
            _ => {
                eprintln!("[{id}] {child_id} not ready (timeout or error)");
                continue;
            }
        }
        // Verify network path works before propagating readiness up.
        let port = agent_port(child_id);
        let addr = format!("127.0.0.1:{port}");
        let mut verified = false;
        for _attempt in 0..50 {
            match tokio::time::timeout(
                Duration::from_millis(500),
                async {
                    let mut stream = TcpStream::connect(&addr).await?;
                    stream.write_all(b"VERIFY").await?;
                    stream.flush().await?;
                    let mut buf = [0u8; 6];
                    stream.read_exact(&mut buf).await?;
                    Ok::<_, std::io::Error>(())
                },
            )
            .await
            {
                Ok(Ok(())) => {
                    verified = true;
                    break;
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        if verified {
            eprintln!("[{id}] {child_id} verified reachable");
        } else {
            eprintln!("[{id}] WARNING: {child_id} not reachable");
        }
    }

    // Phase B: Tell children to go.
    for stdin in &mut child_stdins {
        let _ = stdin.write_all(b"{\"cmd\":\"go\"}\n").await;
        let _ = stdin.flush().await;
    }

    // If we have a parent, signal ready and wait for go.
    // Use a blocking thread for stdin so the tokio runtime can
    // continue driving the echo server while we wait.
    if has_parent {
        println!("{{\"ready\":true}}");
        let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line);
            let _ = go_tx.send(());
        });
        let _ = tokio::time::timeout(Duration::from_secs(30), go_rx).await;
    }

    // Run our own tests.
    eprintln!("[{id}] running tests");
    let peer_map: std::collections::HashMap<&str, &AgentReady> =
        peers.iter().map(|p| (p.id.as_str(), p)).collect();
    let mut results = Vec::new();
    results.extend(crate::fs_tests::run(id, &peer_map).await);
    results.extend(crate::net_tests::run(id, &peer_map).await);
    results.extend(crate::fork_tests::run(id).await);
    results.extend(crate::env_tests::run(id).await);

    // Collect children's results from their stdout.
    for (child_id, reader) in &mut child_stdouts {
        match tokio::time::timeout(Duration::from_secs(60), async {
            let mut child_results = Vec::new();
            let mut line = String::new();
            while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                let trimmed = line.trim();
                if trimmed.contains("\"done\":true") {
                    break;
                }
                if let Ok(result) = serde_json::from_str::<TestResult>(trimmed) {
                    child_results.push(result);
                }
                line.clear();
            }
            child_results
        })
        .await
        {
            Ok(child_results) => {
                eprintln!("[{id}] collected {} results from {child_id}", child_results.len());
                results.extend(child_results);
            }
            Err(_) => {
                eprintln!("[{id}] timeout reading {child_id}");
                results.push(TestResult {
                    test: "CHILD_TIMEOUT".to_string(),
                    agent: child_id.to_string(),
                    result: Outcome::Fail,
                    detail: "parent timed out reading results".to_string(),
                });
            }
        }
    }

    // Drop child stdins to signal children to exit.
    drop(child_stdins);

    echo_task.abort();
    eprintln!("[{id}] done ({} total results)", results.len());
    results
}

async fn echo_server(listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
            Err(_) => break,
        }
    }
}
