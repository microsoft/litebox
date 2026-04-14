// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Agent logic: spawn the process tree, coordinate tests, report results.
//!
//! Uses tokio's single-threaded runtime for concurrent TCP echo serving
//! and test coordination without worker threads.

use crate::protocol::{AgentReady, Command, Outcome, TestResult};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};

/// Tree layout: maps parent → children.
fn tree_children(id: &str) -> &'static [&'static str] {
    match id {
        "init" => &["A", "B"],
        "A" => &["AA", "AB"],
        "AA" => &["AAA", "AAB"],
        _ => &[],
    }
}

/// Port assignment: each agent listens on a unique port.
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

/// Run as the init/coordinator process.
pub fn run_coordinator(self_exe: &str) -> Vec<TestResult> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(coordinator_main(self_exe))
}

/// Run as an agent node in the tree.
pub fn run_agent(self_exe: &str, id: &str, coord_port: u16) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(agent_main(self_exe, id, coord_port));
}

async fn coordinator_main(self_exe: &str) -> Vec<TestResult> {
    let mut results = Vec::new();

    // Phase 1: Init-only tests.
    eprintln!("[coord] Phase 1: init-only tests");
    results.extend(run_agent_tests("init", &[]));

    // Phase 2: Spawn tree + collect registrations.
    eprintln!("[coord] Phase 2: spawning process tree");
    let coord_port = agent_port("init");
    let listener = TcpListener::bind(format!("0.0.0.0:{coord_port}"))
        .await
        .expect("coordinator bind");

    for &child_id in tree_children("init") {
        spawn_child(self_exe, child_id, coord_port);
    }

    // Collect registrations with timeout.
    let expected = 6;
    let mut peers: Vec<AgentReady> = Vec::new();

    let _ = timeout(Duration::from_secs(20), async {
        while peers.len() < expected {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                if let Ok(ready) = serde_json::from_str::<AgentReady>(line.trim()) {
                    eprintln!("[coord] agent {} registered on port {}", ready.id, ready.port);
                    peers.push(ready);
                }
            }
        }
    })
    .await;

    eprintln!("[coord] {} of {} agents registered", peers.len(), expected);

    if peers.is_empty() {
        results.push(TestResult {
            test: "TREE_REGISTER".to_string(),
            agent: "init".to_string(),
            result: Outcome::Xfail,
            detail: "no workers registered".to_string(),
        });
        print_results(&results);
        return results;
    }

    // Phase 3: Broadcast "run tests".
    eprintln!("[coord] Phase 3: cross-process tests ({} agents)", peers.len());
    let cmd = Command::RunTests {
        peers: peers.clone(),
    };
    let cmd_json = serde_json::to_string(&cmd).unwrap();
    for peer in &peers {
        if let Ok(mut stream) =
            TcpStream::connect(format!("127.0.0.1:{}", peer.port)).await
        {
            let _ = stream.write_all(format!("{cmd_json}\n").as_bytes()).await;
        }
    }

    // Collect results with timeout.
    let _ = timeout(Duration::from_secs(30), async {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                if let Ok(result) = serde_json::from_str::<TestResult>(line.trim()) {
                    results.push(result);
                }
                line.clear();
            }
        }
    })
    .await;

    // Broadcast shutdown.
    let shutdown = serde_json::to_string(&Command::Shutdown).unwrap();
    for peer in &peers {
        if let Ok(mut stream) =
            TcpStream::connect(format!("127.0.0.1:{}", peer.port)).await
        {
            let _ = stream.write_all(format!("{shutdown}\n").as_bytes()).await;
        }
    }

    print_results(&results);
    results
}

async fn agent_main(self_exe: &str, id: &str, coord_port: u16) {
    eprintln!("[agent-{id}] starting, coord_port={coord_port}");

    // Write alive marker.
    let _ = std::fs::create_dir_all("/shared");
    let _ = std::fs::write(
        format!("/shared/agent-{id}-alive.txt"),
        format!("ALIVE_{id}"),
    );

    let port = agent_port(id);
    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap_or_else(|e| panic!("agent {id}: bind {port}: {e}"));
    eprintln!("[agent-{id}] bound port {port}");

    // Spawn children.
    for &child_id in tree_children(id) {
        spawn_child(self_exe, child_id, coord_port);
    }

    // Register with coordinator.
    eprintln!("[agent-{id}] registering with coordinator...");
    match timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("127.0.0.1:{coord_port}")),
    )
    .await
    {
        Ok(Ok(mut stream)) => {
            let ready = AgentReady {
                id: id.to_string(),
                pid: std::process::id(),
                port,
            };
            let msg = serde_json::to_string(&ready).unwrap();
            let _ = stream.write_all(format!("{msg}\n").as_bytes()).await;
            let _ = stream.flush().await;
            eprintln!("[agent-{id}] registered");
        }
        Ok(Err(e)) => {
            eprintln!("[agent-{id}] FATAL: connect failed: {e}");
            return;
        }
        Err(_) => {
            eprintln!("[agent-{id}] FATAL: connect timeout");
            return;
        }
    }

    // Wait for "run tests" command on our listener.
    // Concurrently handle echo traffic on accepted connections.
    let peers = match timeout(Duration::from_secs(30), async {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                if let Ok(Command::RunTests { peers }) =
                    serde_json::from_str(line.trim())
                {
                    return peers;
                }
            }
        }
    })
    .await
    {
        Ok(peers) => peers,
        Err(_) => {
            eprintln!("[agent-{id}] timeout waiting for run command");
            return;
        }
    };

    // Run tests.
    let test_results = run_agent_tests(id, &peers);

    // Report results to coordinator.
    if let Ok(mut stream) =
        TcpStream::connect(format!("127.0.0.1:{coord_port}")).await
    {
        for r in &test_results {
            let line = serde_json::to_string(r).unwrap();
            let _ = stream.write_all(format!("{line}\n").as_bytes()).await;
        }
        let _ = stream.flush().await;
    }

    // Wait for shutdown.
    let _ = timeout(Duration::from_secs(60), async {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                if serde_json::from_str::<Command>(line.trim())
                    .is_ok_and(|c| matches!(c, Command::Shutdown))
                {
                    return;
                }
            }
        }
    })
    .await;
}

fn spawn_child(self_exe: &str, child_id: &str, coord_port: u16) {
    let result = std::process::Command::new(self_exe)
        .arg("agent")
        .arg("--id")
        .arg(child_id)
        .arg("--coord-port")
        .arg(coord_port.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn();
    match result {
        Ok(child) => {
            eprintln!("[{child_id}] spawned (pid {:?})", child.id());
            std::mem::forget(child);
        }
        Err(e) => {
            eprintln!("[{child_id}] spawn failed: {e}");
        }
    }
}

fn run_agent_tests(id: &str, peers: &[AgentReady]) -> Vec<TestResult> {
    let mut results = Vec::new();
    let peer_map: HashMap<&str, &AgentReady> =
        peers.iter().map(|p| (p.id.as_str(), p)).collect();
    results.extend(crate::fs_tests::run(id, &peer_map));
    results.extend(crate::net_tests::run(id, &peer_map));
    results.extend(crate::fork_tests::run(id));
    results.extend(crate::env_tests::run(id));
    results
}

fn print_results(results: &[TestResult]) {
    for r in results {
        println!("{}", serde_json::to_string(r).unwrap());
    }
}
