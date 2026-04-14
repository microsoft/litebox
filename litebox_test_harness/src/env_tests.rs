// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process environment tests (E1-E6). All async.

use crate::protocol::{Outcome, TestResult};
use tokio::process::Command;

fn r(test: &str, agent: &str, outcome: Outcome, detail: &str) -> TestResult {
    TestResult {
        test: test.to_string(),
        agent: agent.to_string(),
        result: outcome,
        detail: detail.to_string(),
    }
}

pub async fn run(id: &str) -> Vec<TestResult> {
    if id != "A" {
        return Vec::new();
    }

    let self_exe = std::env::args().next().unwrap_or_default();
    let mut results = Vec::new();

    // E1: Environment variable inheritance.
    match Command::new(&self_exe)
        .arg("env-check")
        .arg("TEST_VAR_E1")
        .env("TEST_VAR_E1", "INHERITED_VALUE")
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if stdout.contains("INHERITED_VALUE") {
                results.push(r("E1", id, Outcome::Pass, "env var inherited"));
            } else {
                results.push(r("E1", id, Outcome::Fail, &format!("got '{stdout}'")));
            }
        }
        Err(e) => results.push(r("E1", id, Outcome::Fail, &format!("{e}"))),
    }

    // E2: Working directory inheritance.
    match Command::new(&self_exe)
        .arg("cwd-check")
        .current_dir("/tmp")
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if stdout.contains("/tmp") {
                results.push(r("E2", id, Outcome::Pass, &format!("cwd={stdout}")));
            } else {
                results.push(r("E2", id, Outcome::Fail, &format!("got {stdout}")));
            }
        }
        Err(e) => results.push(r("E2", id, Outcome::Fail, &format!("{e}"))),
    }

    // E3: Pipe fd inheritance.
    match Command::new(&self_exe)
        .arg("pipe-echo")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(ref mut stdin) = child.stdin {
                use tokio::io::AsyncWriteExt;
                let _ = stdin.write_all(b"FD_TEST_DATA").await;
                drop(child.stdin.take());
            }
            match child.wait_with_output().await {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if stdout.contains("FD_TEST_DATA") {
                        results.push(r("E3", id, Outcome::Pass, "pipe fd ok"));
                    } else {
                        results.push(r("E3", id, Outcome::Fail, &format!("got '{stdout}'")));
                    }
                }
                Err(e) => results.push(r("E3", id, Outcome::Fail, &format!("wait: {e}"))),
            }
        }
        Err(e) => results.push(r("E3", id, Outcome::Fail, &format!("spawn: {e}"))),
    }

    // E4: Separate stdout/stderr.
    match Command::new(&self_exe)
        .arg("stderr-test")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stdout.contains("STDOUT_OK") && stderr.contains("STDERR_OK") {
                results.push(r("E4", id, Outcome::Pass, "stdio separation ok"));
            } else {
                results.push(r("E4", id, Outcome::Fail, &format!("out='{stdout}' err='{stderr}'")));
            }
        }
        Err(e) => results.push(r("E4", id, Outcome::Fail, &format!("{e}"))),
    }

    // E5: Exit code propagation.
    match Command::new(&self_exe)
        .arg("exit-with")
        .arg("42")
        .output()
        .await
    {
        Ok(output) => {
            let code = output.status.code().unwrap_or(-1);
            if code == 42 {
                results.push(r("E5", id, Outcome::Pass, "exit code 42 propagated"));
            } else {
                results.push(r("E5", id, Outcome::Fail, &format!("got {code}")));
            }
        }
        Err(e) => results.push(r("E5", id, Outcome::Fail, &format!("{e}"))),
    }

    results
}
