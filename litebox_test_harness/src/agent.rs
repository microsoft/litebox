// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Agent logic: spawn the process tree, coordinate tests, report results.
//!
//! The agent binary runs inside the litebox sandbox. Depending on the
//! subcommand it either:
//! - `spawn-tree`: creates the full process tree and coordinates tests
//! - `agent --id=X`: runs as a leaf/branch node, executes tests, reports

use crate::protocol::{AgentReady, Command, Outcome, TestResult};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process;

/// Tree layout: maps parent → children.
/// init spawns A,B; A spawns AA,AB; AA spawns AAA,AAB.
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

/// Run as the init/coordinator process. First runs init-only tests,
/// then attempts to spawn the tree for cross-process tests.
pub fn run_coordinator(self_exe: &str) -> Vec<TestResult> {
    let mut results = Vec::new();

    // Phase 1: Init-only tests (no fork required).
    eprintln!("[coord] Phase 1: init-only tests");
    results.extend(run_agent_tests("init", &[]));

    // Phase 2: Attempt to spawn child processes.
    eprintln!("[coord] Phase 2: spawning process tree");
    let coord_port = agent_port("init");
    let listener = match TcpListener::bind(format!("0.0.0.0:{coord_port}")) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[coord] can't bind coordinator port {coord_port}: {e}");
            results.push(TestResult {
                test: "TREE".to_string(),
                agent: "init".to_string(),
                result: Outcome::Fail,
                detail: format!("coordinator bind failed: {e}"),
            });
            return results;
        }
    };

    // Spawn direct children (A, B).
    let children = tree_children("init");
    let mut spawn_ok = true;
    for &child_id in children {
        if !spawn_child(self_exe, child_id, coord_port) {
            spawn_ok = false;
        }
    }

    if !spawn_ok {
        results.push(TestResult {
            test: "TREE_SPAWN".to_string(),
            agent: "init".to_string(),
            result: Outcome::Fail,
            detail: "failed to spawn children".to_string(),
        });
    }

    // Wait for agents with a timeout.
    let expected_agents = 6;
    let mut peers: Vec<AgentReady> = Vec::new();

    // Poll for connections with short sleeps between attempts.
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking failed");
    let registration_deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(15);

    while peers.len() < expected_agents
        && std::time::Instant::now() < registration_deadline
    {
        match listener.accept() {
            Ok((stream, _)) => {
                // Read exactly one line per connection.
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                    .ok();
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) > 0 {
                    if let Ok(ready) = serde_json::from_str::<AgentReady>(line.trim()) {
                        eprintln!("[coord] agent {} registered on port {}", ready.id, ready.port);
                        peers.push(ready);
                        continue; // immediately try next accept
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("[coord] accept error: {e}");
                break;
            }
        }
    }

    eprintln!(
        "[coord] {} of {} agents registered",
        peers.len(),
        expected_agents
    );

    if peers.is_empty() {
        results.push(TestResult {
            test: "TREE_REGISTER".to_string(),
            agent: "init".to_string(),
            result: Outcome::Xfail,
            detail: "no workers registered — fork+exec'd binaries fail in worker processes (known litebox limitation)".to_string(),
        });
        // Print summary to stdout.
        for r in &results {
            println!("{}", serde_json::to_string(r).unwrap());
        }
        return results;
    }

    // Phase 3: Cross-process tests (if we have agents).
    eprintln!("[coord] Phase 3: cross-process tests");
    let cmd = Command::RunTests {
        peers: peers.clone(),
    };
    let cmd_json = serde_json::to_string(&cmd).unwrap();
    for peer in &peers {
        if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{}", peer.port)) {
            let _ = writeln!(stream, "{cmd_json}");
        }
    }

    // Collect results from agents.
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking failed");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .ok();
                let reader = BufReader::new(&stream);
                // Read all available lines (agent sends multiple results
                // then closes the connection).
                for line in reader.lines() {
                    let line = match line {
                        Ok(l) => l,
                        Err(_) => break,
                    };
                    if let Ok(result) = serde_json::from_str::<TestResult>(&line) {
                        results.push(result);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }

    // Broadcast shutdown.
    let shutdown = serde_json::to_string(&Command::Shutdown).unwrap();
    for peer in &peers {
        if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{}", peer.port)) {
            let _ = writeln!(stream, "{shutdown}");
        }
    }

    // Print results to stdout.
    for r in &results {
        println!("{}", serde_json::to_string(r).unwrap());
    }

    results
}

/// Run as an agent node in the tree.
pub fn run_agent(self_exe: &str, id: &str, coord_port: u16) {
    eprintln!("[agent-{id}] starting, coord_port={coord_port}");

    // Write a marker to prove this agent executed.
    let _ = std::fs::create_dir_all("/shared");
    let _ = std::fs::write(
        format!("/shared/agent-{id}-alive.txt"),
        format!("ALIVE_{id}"),
    );

    let port = agent_port(id);

    // Listen on our assigned port.
    eprintln!("[agent-{id}] binding port {port}...");
    let listener = match TcpListener::bind(format!("0.0.0.0:{port}")) {
        Ok(l) => {
            eprintln!("[agent-{id}] bound port {port}");
            l
        }
        Err(e) => {
            eprintln!("[agent-{id}] FATAL: bind port {port}: {e}");
            return;
        }
    };

    // Spawn our children (if any).
    let children = tree_children(id);
    for &child_id in children {
        spawn_child(self_exe, child_id, coord_port);
    }

    // Register with coordinator.
    eprintln!("[agent-{id}] connecting to coordinator at 127.0.0.1:{coord_port}...");
    match TcpStream::connect_timeout(
        &format!("127.0.0.1:{coord_port}").parse().unwrap(),
        std::time::Duration::from_secs(5),
    ) {
        Ok(mut stream) => {
            let ready = AgentReady {
                id: id.to_string(),
                pid: process::id(),
                port,
            };
            let msg = serde_json::to_string(&ready).unwrap();
            eprintln!("[agent-{id}] sending registration: {msg}");
            let _ = writeln!(stream, "{msg}");
            let _ = stream.flush();
            drop(stream);
            eprintln!("[agent-{id}] registered with coordinator");
        }
        Err(e) => {
            eprintln!("[agent-{id}] FATAL: can't reach coordinator at 127.0.0.1:{coord_port}: {e}");
            return;
        }
    }

    // Wait for "run tests" command.
    let peers = wait_for_run_command(&listener);

    // Run tests.
    let results = run_agent_tests(id, &peers);

    // Report results to coordinator.
    if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{coord_port}")) {
        for r in &results {
            let _ = writeln!(stream, "{}", serde_json::to_string(r).unwrap());
        }
    }

    // Wait for shutdown.
    wait_for_shutdown(&listener);
}

fn spawn_child(self_exe: &str, child_id: &str, coord_port: u16) -> bool {
    let result = process::Command::new(self_exe)
        .arg("agent")
        .arg("--id")
        .arg(child_id)
        .arg("--coord-port")
        .arg(coord_port.to_string())
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::inherit())
        .stderr(process::Stdio::inherit())
        .spawn();
    match result {
        Ok(child) => {
            eprintln!("[{child_id}] spawned (pid {:?})", child.id());
            // Don't drop the child handle — keep it alive so the worker
            // process isn't orphaned.
            std::mem::forget(child);
            true
        }
        Err(e) => {
            eprintln!("[{child_id}] spawn failed: {e}");
            false
        }
    }
}

fn wait_for_run_command(listener: &TcpListener) -> Vec<AgentReady> {
    listener.set_nonblocking(false).ok();
    if let Ok((stream, _)) = listener.accept() {
        let reader = BufReader::new(&stream);
        for line in reader.lines().map_while(Result::ok) {
            if let Ok(Command::RunTests { peers }) = serde_json::from_str(&line) {
                return peers;
            }
        }
    }
    Vec::new()
}

fn wait_for_shutdown(listener: &TcpListener) {
    listener.set_nonblocking(false).ok();
    let _ = listener.accept(); // blocks until coordinator connects
}

/// Execute the test suite for this agent.
fn run_agent_tests(id: &str, peers: &[AgentReady]) -> Vec<TestResult> {
    let mut results = Vec::new();
    let peer_map: HashMap<&str, &AgentReady> =
        peers.iter().map(|p| (p.id.as_str(), p)).collect();

    // Filesystem tests
    results.extend(crate::fs_tests::run(id, &peer_map));

    // Network tests
    results.extend(crate::net_tests::run(id, &peer_map));

    // Fork tests
    results.extend(crate::fork_tests::run(id));

    // Environment tests
    results.extend(crate::env_tests::run(id));

    results
}
