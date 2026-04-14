// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Agent: spawn process tree, coordinate via 9P files, run tests.
//! Echo server runs concurrently with test execution on each agent.

use crate::protocol::{AgentReady, Command, Outcome, TestResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
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
        .block_on(coordinator_main(self_exe))
}

pub fn run_agent(self_exe: &str, id: &str) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(agent_main(self_exe, id));
}

async fn coordinator_main(self_exe: &str) -> Vec<TestResult> {
    let mut results = Vec::new();
    let _ = tokio::fs::create_dir_all("/shared").await;

    // Start echo server on init's port so children can test N2/N4 → init.
    let init_port = agent_port("init");
    let init_listener = TcpListener::bind(format!("0.0.0.0:{init_port}"))
        .await
        .expect("init echo bind");
    let echo_task = tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = init_listener.accept().await {
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
        }
    });

    // Phase 1: Init-only tests.
    eprintln!("[coord] Phase 1: init-only tests");
    results.extend(run_agent_tests("init", &[]).await);

    // Phase 2: Spawn tree, wait for ready markers on 9P.
    eprintln!("[coord] Phase 2: spawning process tree");
    for &child_id in tree_children("init") {
        spawn_child(self_exe, child_id);
    }

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
            if let Ok(content) = tokio::fs::read_to_string(&path).await {
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

    eprintln!("[coord] {} of {} agents ready", ready_agents.len(), ALL_AGENTS.len());

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

    // Phase 3: Signal tests.
    eprintln!("[coord] Phase 3: cross-process tests");
    let cmd = Command::RunTests { peers: ready_agents.clone() };
    let _ = tokio::fs::write("/shared/run-tests.json", serde_json::to_string(&cmd).unwrap()).await;

    // Wait for results.
    let result_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut collected: std::collections::HashSet<String> = std::collections::HashSet::new();

    while collected.len() < ready_agents.len()
        && tokio::time::Instant::now() < result_deadline
    {
        for agent in &ready_agents {
            if collected.contains(&agent.id) {
                continue;
            }
            let path = format!("/shared/agent-{}-results.jsonl", agent.id);
            if let Ok(content) = tokio::fs::read_to_string(&path).await {
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

    let _ = tokio::fs::write("/shared/shutdown", "1").await;
    echo_task.abort();
    print_results(&results);
    results
}

async fn agent_main(self_exe: &str, id: &str) {
    eprintln!("[agent-{id}] starting");
    let _ = tokio::fs::create_dir_all("/shared").await;

    // Bind port and start echo server.
    let port = agent_port(id);
    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap_or_else(|e| panic!("agent {id}: bind {port}: {e}"));
    eprintln!("[agent-{id}] bound port {port}");

    // Echo server runs concurrently.
    let echo_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let echo_done_clone = echo_done.clone();
    let echo_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    if let Ok((mut stream, _)) = result {
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
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if echo_done_clone.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }
    });

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
    let _ = tokio::fs::write(
        format!("/shared/agent-{id}-ready.json"),
        serde_json::to_string(&ready).unwrap(),
    ).await;
    eprintln!("[agent-{id}] ready");

    // Wait for run signal.
    let peers = loop {
        if let Ok(content) = tokio::fs::read_to_string("/shared/run-tests.json").await {
            if let Ok(Command::RunTests { peers }) = serde_json::from_str(&content) {
                break peers;
            }
        }
        if tokio::fs::metadata("/shared/shutdown").await.is_ok() {
            echo_done.store(true, std::sync::atomic::Ordering::Relaxed);
            echo_task.abort();
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    // Run tests (async — echo server continues accepting).
    eprintln!("[agent-{id}] running tests");
    let test_results = run_agent_tests(id, &peers).await;

    // Write results.
    let mut output = String::new();
    for r in &test_results {
        output.push_str(&serde_json::to_string(r).unwrap());
        output.push('\n');
    }
    let _ = tokio::fs::write(format!("/shared/agent-{id}-results.jsonl"), &output).await;
    eprintln!("[agent-{id}] done ({} tests)", test_results.len());

    // Wait for shutdown.
    loop {
        if tokio::fs::metadata("/shared/shutdown").await.is_ok() {
            echo_done.store(true, std::sync::atomic::Ordering::Relaxed);
            echo_task.abort();
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
        Err(e) => eprintln!("[{child_id}] spawn failed: {e}"),
    }
}

async fn run_agent_tests(id: &str, peers: &[AgentReady]) -> Vec<TestResult> {
    let peer_map: std::collections::HashMap<&str, &AgentReady> =
        peers.iter().map(|p| (p.id.as_str(), p)).collect();
    let mut results = Vec::new();
    results.extend(crate::fs_tests::run(id, &peer_map).await);
    results.extend(crate::net_tests::run(id, &peer_map).await);
    results.extend(crate::fork_tests::run(id).await);
    results.extend(crate::env_tests::run(id).await);
    results
}

fn print_results(results: &[TestResult]) {
    for r in results {
        println!("{}", serde_json::to_string(r).unwrap());
    }
}
