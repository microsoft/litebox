// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Regression tests for error handling in the runner (see #650).
//!
//! These tests verify that the runner produces clear error messages instead
//! of panicking when given invalid inputs.

use std::process::Command;

/// Get the path to the litebox_runner_linux_userland binary.
fn runner_binary() -> String {
    std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_litebox_runner_linux_userland").to_string())
}

/// Regression test for #650: running with a nonexistent program path should
/// produce a clear, contextual error message instead of panicking.
#[test]
fn test_nonexistent_program_returns_error_not_panic() {
    let output = Command::new(runner_binary())
        .arg("/nonexistent/path/to/program")
        .output()
        .expect("Failed to execute runner binary");

    // The process should fail (non-zero exit code)
    assert!(
        !output.status.success(),
        "Expected runner to fail for nonexistent program, but it succeeded"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);

    // It should NOT contain a panic message
    assert!(
        !stderr.contains("panicked at"),
        "Runner panicked instead of returning an error.\nStderr: {stderr}"
    );

    // It SHOULD contain a contextual error message about the path
    assert!(
        stderr.contains("Could not resolve absolute path")
            || stderr.contains("Could not read metadata"),
        "Expected a contextual error message about path resolution or metadata, \
         but got:\nStderr: {stderr}"
    );
}
