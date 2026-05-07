// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! getrandom(2) contract tests for VS Code startup coverage.

use std::future::Future;
use std::pin::Pin;

use crate::protocol::{Command, Response};

use super::TestOutcome;
use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;

const EAGAIN: i32 = libc::EAGAIN;

pub(crate) const RAND_AGENTS: &[AgentName] = &[AgentName::Dpg1, AgentName::Dpg1Dpg1];

const RAND_SCENARIOS: &[RandScenario] = &[
    RandScenario {
        name: "size_exact",
        run: run_size_exact,
    },
    RandScenario {
        name: "novelty",
        run: run_novelty,
    },
    RandScenario {
        name: "nonblock_when_short",
        run: run_nonblock_when_short,
    },
];

struct RandScenario {
    name: &'static str,
    run: for<'a, 'r> fn(&'a mut RunContext<'r>, &'a AgentHandle) -> RandFuture<'a>,
}

type RandFuture<'a> = Pin<Box<dyn Future<Output = Result<String, String>> + 'a>>;

pub(crate) fn register_getrandom_tests(reg: &mut Registry<'_>) {
    for &agent in RAND_AGENTS {
        for def in RAND_SCENARIOS {
            let agent_s = agent.to_string();
            let name = def.name;
            let run_scenario = def.run;
            reg.test("vscode", "getrandom", format!("RAND.{name}.{agent}"))
                .timeout(30)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        Box::pin(async move { outcome(&a, run_scenario(run, &handle).await) })
                    })
                });
        }
    }
}

fn outcome(agent: &str, result: Result<String, String>) -> TestOutcome {
    match result {
        Ok(detail) => TestOutcome::new(agent, true, detail),
        Err(detail) => TestOutcome::new(agent, false, detail),
    }
}

fn run_size_exact<'a>(run: &'a mut RunContext<'_>, agent: &'a AgentHandle) -> RandFuture<'a> {
    Box::pin(async move {
        let resp = getrandom(run, agent, 32, "").await;
        match resp {
            Response::RandomBytes { hex, errno: None } if hex.len() == 64 => {
                Ok(format!("hex_len={}", hex.len()))
            }
            other => Err(format!(
                "expected 32-byte success as 64 hex chars, got {other:?}"
            )),
        }
    })
}

fn run_novelty<'a>(run: &'a mut RunContext<'_>, agent: &'a AgentHandle) -> RandFuture<'a> {
    Box::pin(async move {
        let first = getrandom(run, agent, 32, "").await;
        let second = getrandom(run, agent, 32, "").await;
        match (first, second) {
            (
                Response::RandomBytes {
                    hex: first_hex,
                    errno: None,
                },
                Response::RandomBytes {
                    hex: second_hex,
                    errno: None,
                },
            ) if first_hex.len() == 64 && second_hex.len() == 64 && first_hex != second_hex => {
                Ok("two 32-byte samples differed".to_string())
            }
            (first, second) => Err(format!(
                "expected two distinct 32-byte successes, got first={first:?}; second={second:?}"
            )),
        }
    })
}

fn run_nonblock_when_short<'a>(
    run: &'a mut RunContext<'_>,
    agent: &'a AgentHandle,
) -> RandFuture<'a> {
    Box::pin(async move {
        let resp = getrandom(run, agent, 4096, "nonblock").await;
        // With GRND_NONBLOCK, Linux may either return the full request
        // when entropy is available or fail with EAGAIN without bytes.
        // Both outcomes are legitimate; a short success is not.
        match resp {
            Response::RandomBytes { hex, errno: None } if hex.len() == 8192 => {
                Ok(format!("nonblock_success_hex_len={}", hex.len()))
            }
            Response::RandomBytes {
                hex,
                errno: Some(EAGAIN),
            } if hex.is_empty() => Ok("nonblock_eagain".to_string()),
            other => Err(format!(
                "expected full 4096-byte success or EAGAIN with no bytes, got {other:?}"
            )),
        }
    })
}

async fn getrandom(run: &mut RunContext<'_>, agent: &AgentHandle, n: u32, flags: &str) -> Response {
    run.send(
        agent,
        Command::Getrandom {
            n,
            flags: flags.to_string(),
        },
    )
    .await
}
