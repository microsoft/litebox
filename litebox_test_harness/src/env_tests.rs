// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process environment tests (E1-E6).

use crate::protocol::{Outcome, TestResult};
use std::process;

fn result(test: &str, agent: &str, outcome: Outcome, detail: &str) -> TestResult {
    TestResult {
        test: test.to_string(),
        agent: agent.to_string(),
        result: outcome,
        detail: detail.to_string(),
    }
}

/// Run environment tests. Only agent A runs these.
pub fn run(id: &str) -> Vec<TestResult> {
    if id != "A" {
        return Vec::new();
    }

    let mut results = Vec::new();
    let self_exe = std::env::args().next().unwrap_or_default();

    // E1: Environment variables inherited by fork+exec'd children.
    results.push(test_e1_env_inheritance(id, &self_exe));

    // E2: Working directory inherited by children.
    results.push(test_e2_cwd_inheritance(id, &self_exe));

    // E3: File descriptors inherited across fork+exec (pipe bridging).
    results.push(test_e3_fd_inheritance(id, &self_exe));

    // E4: stdin/stdout/stderr correct in child workers.
    results.push(test_e4_stdio(id, &self_exe));

    // E5: Exit code propagation from child → parent.
    results.push(test_e5_exit_code(id, &self_exe));

    results
}

fn test_e1_env_inheritance(id: &str, self_exe: &str) -> TestResult {
    match process::Command::new(self_exe)
        .arg("env-check")
        .arg("TEST_VAR_E1")
        .env("TEST_VAR_E1", "INHERITED_VALUE")
        .stdout(process::Stdio::piped())
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if stdout.contains("INHERITED_VALUE") {
                result("E1", id, Outcome::Pass, "env var inherited")
            } else {
                result(
                    "E1",
                    id,
                    Outcome::Fail,
                    &format!("env var not found: got '{stdout}'"),
                )
            }
        }
        Err(e) => result("E1", id, Outcome::Fail, &format!("{e}")),
    }
}

fn test_e2_cwd_inheritance(id: &str, self_exe: &str) -> TestResult {
    match process::Command::new(self_exe)
        .arg("cwd-check")
        .current_dir("/tmp")
        .stdout(process::Stdio::piped())
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if stdout.contains("/tmp") {
                result("E2", id, Outcome::Pass, &format!("cwd={stdout}"))
            } else {
                result(
                    "E2",
                    id,
                    Outcome::Fail,
                    &format!("expected /tmp, got {stdout}"),
                )
            }
        }
        Err(e) => result("E2", id, Outcome::Fail, &format!("{e}")),
    }
}

fn test_e3_fd_inheritance(id: &str, self_exe: &str) -> TestResult {
    // Test that piped stdin/stdout work correctly.
    use std::io::Write;
    match process::Command::new(self_exe)
        .arg("pipe-echo")
        .stdin(process::Stdio::piped())
        .stdout(process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(b"FD_TEST_DATA");
                drop(child.stdin.take());
            }
            match child.wait_with_output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if stdout.contains("FD_TEST_DATA") {
                        result("E3", id, Outcome::Pass, "pipe fd inheritance ok")
                    } else {
                        result(
                            "E3",
                            id,
                            Outcome::Fail,
                            &format!("got '{stdout}' instead of FD_TEST_DATA"),
                        )
                    }
                }
                Err(e) => result("E3", id, Outcome::Fail, &format!("wait: {e}")),
            }
        }
        Err(e) => result("E3", id, Outcome::Fail, &format!("spawn: {e}")),
    }
}

fn test_e4_stdio(id: &str, self_exe: &str) -> TestResult {
    // Test that stderr is separate from stdout.
    match process::Command::new(self_exe)
        .arg("stderr-test")
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stdout.contains("STDOUT_OK") && stderr.contains("STDERR_OK") {
                result("E4", id, Outcome::Pass, "stdio separation ok")
            } else {
                result(
                    "E4",
                    id,
                    Outcome::Fail,
                    &format!("stdout='{stdout}' stderr='{stderr}'"),
                )
            }
        }
        Err(e) => result("E4", id, Outcome::Fail, &format!("{e}")),
    }
}

fn test_e5_exit_code(id: &str, self_exe: &str) -> TestResult {
    // Test that child exit code is propagated correctly.
    match process::Command::new(self_exe)
        .arg("exit-with")
        .arg("42")
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .output()
    {
        Ok(output) => {
            let code = output.status.code().unwrap_or(-1);
            if code == 42 {
                result("E5", id, Outcome::Pass, "exit code 42 propagated")
            } else {
                result(
                    "E5",
                    id,
                    Outcome::Fail,
                    &format!("expected 42, got {code}"),
                )
            }
        }
        Err(e) => result("E5", id, Outcome::Fail, &format!("{e}")),
    }
}
