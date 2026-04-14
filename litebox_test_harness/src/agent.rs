// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Agent logic: spawn the process tree, coordinate tests, report results.
//!
//! Coordination uses 9P filesystem files (not TCP) to avoid the
//! close-before-flush issue in cross-worker TCP bridges.
//! TCP is used only for the network connectivity tests themselves.

use crate::protocol::{AgentReady, Command, Outcome, TestResult};
use std::collections::HashMap;
use tokio::time::Duration;

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

const ALL_AGENTS: &[&str] = &["A", "B", "AA", "AB", "AAA", "AAB"];

/// Run as the init/coordinator process.
pub fn run_coordinator(self_exe: &str) -> Vec<TestResult> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(coordinator_main(self_exe))
}

/// Run as an agent node in the tree.
pub fn run_agent(self_exe: &str, id: &str) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(agent_main(self_exe, id));
}

async fn coordinator_main(self_exe: &str) -> Vec<TestResult> {
    let mut results = Vec::new();
    let _ = std::fs::create_dir_all("/shared");

    // Phase 1: Init-only tests.
    eprintln!("[coord] Phase 1: init-only tests");
    results.extend(run_agent_tests("init", &[]));

    // Phase 2: Spawn tree, wait for agents via filesystem.
    eprintln!("[coord] Phase 2: spawning process tree");
    for &child_id in tree_children("init") {
        spawn_child(self_exe, child_id);
    }

    // Poll for ready markers from all agents.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut ready_agents: Vec<AgentReady> = Vec::new();

    while ready_agents.len() < ALL_AGENTS.len()
        && tokio::time::Instant::now() < deadline
    {
        for &agent_id in ALL_AGENTS {
            if ready_agents.iter().any(|r| r.id == agent_id) {
                continue;
            }
            let path = format!("/shared/agent-{agent_id}-ready.json");
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(ready) = serde_json::from_str::<AgentReady>(&content) {
                    eprintln!("[coord] agent {} ready on port {}", ready.id, ready.port);
                    ready_agents.push(ready);
                }
            }
        }
        if ready_agents.len() < ALL_AGENTS.len() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    eprintln!(
        "[coord] {} of {} agents ready",
        ready_agents.len(),
        ALL_AGENTS.len()
    );

    if ready_agents.is_empty() {
        results.push(TestResult {
            test: "TREE".to_string(),
            agent: "init".to_string(),
            result: Outcome::Xfail,
            detail: "no agents registered".to_string(),
        });
        print_results(&results);
        return results;
    }

    // Phase 3: Signal agents to run tests.
    eprintln!("[coord] Phase 3: running cross-process tests");
    let cmd = Command::RunTests {
        peers: ready_agents.clone(),
    };
    let _ = std::fs::write(
        "/shared/run-tests.json",
        serde_json::to_string(&cmd).unwrap(),
    );

    // Wait for agent results.
    let result_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut collected: std::collections::HashSet<String> = std::collections::HashSet::new();

    while collected.len() < ready_agents.len()
        && tokio::time::Instant::now() < result_deadline
    {
        for agent in &ready_agents {
            if collected.contains(&agent.id) {
                continue;
            }
            let path = format!("/shared/agent-{}-results.jsonl", agent.id);
            if let Ok(content) = std::fs::read_to_string(&path) {
                for line in content.lines() {
                    if let Ok(result) = serde_json::from_str::<TestResult>(line) {
                        results.push(result);
                    }
                }
                collected.insert(agent.id.clone());
                eprintln!("[coord] collected results from {}", agent.id);
            }
        }
        if collected.len() < ready_agents.len() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    // Signal shutdown.
    let _ = std::fs::write("/shared/shutdown", "1");

    print_results(&results);
    results
}

async fn agent_main(self_exe: &str, id: &str) {
    eprintln!("[agent-{id}] starting");
    let _ = std::fs::create_dir_all("/shared");

    // Bind our test port.
    let port = agent_port(id);
    let _listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap_or_else(|e| panic!("agent {id}: bind {port}: {e}"));
    eprintln!("[agent-{id}] bound port {port}");

    // Spawn children.
    for &child_id in tree_children(id) {
        spawn_child(self_exe, child_id);
    }

    // Write ready marker.
    let ready = AgentReady {
        id: id.to_string(),
        pid: std::process::id(),
        port,
    };
    let _ = std::fs::write(
        format!("/shared/agent-{id}-ready.json"),
        serde_json::to_string(&ready).unwrap(),
    );
    eprintln!("[agent-{id}] ready");

    // Wait for run-tests signal.
    let peers = loop {
        if let Ok(content) = std::fs::read_to_string("/shared/run-tests.json") {
            if let Ok(Command::RunTests { peers }) = serde_json::from_str(&content) {
                break peers;
            }
        }
        if std::fs::metadata("/shared/shutdown").is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    // Run tests.
    eprintln!("[agent-{id}] running tests");
    let test_results = run_agent_tests(id, &peers);

    // Write results to file.
    let mut output = String::new();
    for r in &test_results {
        output.push_str(&serde_json::to_string(r).unwrap());
        output.push('\n');
    }
    let _ = std::fs::write(
        format!("/shared/agent-{id}-results.jsonl"),
        &output,
    );
    eprintln!("[agent-{id}] done ({} tests)", test_results.len());

    // Wait for shutdown.
    loop {
        if std::fs::metadata("/shared/shutdown").is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn spawn_child(self_exe: &str, child_id: &str) {
    match std::process::Command::new(self_exe)
        .arg("agent")
        .arg("--id")
        .arg(child_id)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
    {
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
