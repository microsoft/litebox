// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test result protocol for communication between sandbox agents and the host.

use serde::{Deserialize, Serialize};

/// Result of a single test executed by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// Test identifier (e.g., "F1", "N3", "X4").
    pub test: String,
    /// Agent that ran the test (e.g., "A", "AA", "AAA").
    pub agent: String,
    /// Outcome.
    pub result: Outcome,
    /// Human-readable detail.
    #[serde(default)]
    pub detail: String,
}

/// Test outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Test passed as expected.
    Pass,
    /// Test failed unexpectedly.
    Fail,
    /// Expected failure (documents a known limitation).
    Xfail,
    /// Test skipped (not applicable for this agent position).
    Skip,
}

/// Registration message sent by each agent to the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentReady {
    /// Agent identifier.
    pub id: String,
    /// Guest PID.
    pub pid: u32,
    /// TCP port this agent is listening on for test traffic.
    pub port: u16,
}

/// Command sent by coordinator to agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum Command {
    /// All agents are registered; start running tests.
    #[serde(rename = "run")]
    RunTests {
        /// Map of agent id → port for cross-agent connectivity tests.
        peers: Vec<AgentReady>,
    },
    /// Shut down gracefully.
    #[serde(rename = "shutdown")]
    Shutdown,
}

/// Lines written to the result pipe by agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum AgentMessage {
    Ready(AgentReady),
    Result(TestResult),
}
