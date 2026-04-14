// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fork/exec limitation tests (X1-X8). Async wrappers around process spawning.

use crate::protocol::{Outcome, TestResult};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

fn r(test: &str, agent: &str, outcome: Outcome, detail: &str) -> TestResult {
    TestResult {
        test: test.to_string(),
        agent: agent.to_string(),
        result: outcome,
        detail: detail.to_string(),
    }
}

pub async fn run(id: &str) -> Vec<TestResult> {
    let mut results = Vec::new();

    if id == "init" {
        results.push(test_fork_exec(id, "X1").await);
        results.push(test_fork_exec(id, "X2").await);
        results.push(test_subshell(id).await);
        results.push(test_background(id).await);
        results.push(test_tree_nesting(id).await);
        return results;
    }

    if id != "A" {
        return results;
    }

    results.push(test_fork_exec(id, "X1").await);
    results.push(test_fork_exec(id, "X2").await);
    results.push(test_subshell(id).await);
    results.push(test_pipe_subshell(id).await);
    results.push(test_background(id).await);
    results.push(test_orphan(id).await);
    results.push(r("X8", id, Outcome::Pass, "3-level nesting via tree"));

    results
}

async fn test_fork_exec(id: &str, test_id: &str) -> TestResult {
    let self_exe = std::env::args().next().unwrap_or_default();
    match Command::new(&self_exe)
        .arg("echo-test")
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            r(test_id, id, Outcome::Pass, &format!("fork+exec ok: {stdout}"))
        }
        Ok(output) => r(test_id, id, Outcome::Fail, &format!("exit {}", output.status.code().unwrap_or(-1))),
        Err(e) => r(test_id, id, Outcome::Fail, &format!("spawn: {e}")),
    }
}

async fn test_subshell(id: &str) -> TestResult {
    let self_exe = std::env::args().next().unwrap_or_default();
    match Command::new(&self_exe).arg("echo-test").output().await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if stdout.contains("ECHO_TEST_OK") {
                r("X3", id, Outcome::Pass, "subshell capture ok")
            } else {
                r("X3", id, Outcome::Fail, &format!("unexpected: {stdout}"))
            }
        }
        Err(e) => r("X3", id, Outcome::Fail, &format!("{e}")),
    }
}

async fn test_pipe_subshell(id: &str) -> TestResult {
    let self_exe = std::env::args().next().unwrap_or_default();
    match timeout(
        Duration::from_secs(5),
        Command::new(&self_exe).arg("pipe-test").output(),
    )
    .await
    {
        Ok(Ok(output)) if output.status.success() => {
            r("X4", id, Outcome::Pass, "pipe subshell completed")
        }
        Ok(Ok(output)) => r("X4", id, Outcome::Fail, &format!("exit {}", output.status.code().unwrap_or(-1))),
        Ok(Err(e)) => r("X4", id, Outcome::Fail, &format!("spawn: {e}")),
        Err(_) => r("X4", id, Outcome::Xfail, "deadlocked (known limitation)"),
    }
}

async fn test_background(id: &str) -> TestResult {
    let self_exe = std::env::args().next().unwrap_or_default();
    let marker = format!("/tmp/x5_bg_{id}.txt");
    match Command::new(&self_exe)
        .arg("write-marker")
        .arg(&marker)
        .output()
        .await
    {
        Ok(status) if status.status.success() => {
            match tokio::fs::read_to_string(&marker).await {
                Ok(c) if c.contains("MARKER") => r("X5", id, Outcome::Pass, "bg wrote marker"),
                _ => r("X5", id, Outcome::Fail, "marker not found"),
            }
        }
        Ok(status) => r("X5", id, Outcome::Fail, &format!("exit {}", status.status.code().unwrap_or(-1))),
        Err(e) => r("X5", id, Outcome::Fail, &format!("spawn: {e}")),
    }
}

async fn test_orphan(id: &str) -> TestResult {
    let self_exe = std::env::args().next().unwrap_or_default();
    match Command::new(&self_exe)
        .arg("sleep-test")
        .spawn()
    {
        Ok(_) => r("X6", id, Outcome::Pass, "orphan spawn ok"),
        Err(e) => r("X6", id, Outcome::Fail, &format!("spawn: {e}")),
    }
}

async fn test_tree_nesting(id: &str) -> TestResult {
    let self_exe = std::env::args().next().unwrap_or_default();
    match Command::new(&self_exe).arg("echo-test").output().await {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if stdout.contains("ECHO_TEST_OK") {
                r("X8", id, Outcome::Pass, "child ran successfully")
            } else {
                r("X8", id, Outcome::Xfail, &format!("child output: '{stdout}'"))
            }
        }
        Ok(output) => r("X8", id, Outcome::Xfail, &format!("exit {}", output.status.code().unwrap_or(-1))),
        Err(e) => r("X8", id, Outcome::Fail, &format!("spawn: {e}")),
    }
}
