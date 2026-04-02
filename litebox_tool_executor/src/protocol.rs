// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! JSON protocol types for communicating with the tool executor.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A request to execute a command inside the LiteBox sandbox.
#[derive(Debug, Deserialize)]
pub struct ToolRequest {
    /// The command and its arguments (e.g., `["/bin/ls", "-la", "/workspace"]`).
    pub command: Vec<String>,
    /// Environment variables to pass to the program (`KEY=VALUE` pairs).
    #[serde(default)]
    pub env: Vec<String>,
    /// Files to inject into the sandbox filesystem before execution.
    /// Keys are absolute paths inside the sandbox, values are file contents.
    #[serde(default)]
    pub files: HashMap<String, Vec<u8>>,
    /// Maximum wall-clock time in seconds before the execution is killed.
    pub timeout_secs: Option<u32>,
}

/// The result of a sandboxed tool execution.
#[derive(Debug, Serialize)]
pub struct ToolResult {
    /// Guest stdout output.
    pub stdout: String,
    /// Guest stderr output (non-audit lines only).
    pub stderr: String,
    /// Guest process exit code.
    pub exit_code: i32,
    /// Structured audit events captured during execution.
    pub audit_log: Vec<String>,
    /// Whether the execution was terminated due to timeout.
    pub timed_out: bool,
}
