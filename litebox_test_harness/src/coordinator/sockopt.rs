// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! SOCKOPT tests for per-option socket option behavior used by VS Code.

use crate::protocol::{Command, Response, SockOpt, SockOptValue};

use super::TestOutcome;
use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;

// Long-lived agents the sockopt tests run in. setsockopt /
// getsockopt syscall numbers are constant, but the shim's
// parameter rewriting (and any libc wrappers around them) differ
// per parent binary type, so we fan out across one slot per
// BinaryType leg.
const SOCKOPT_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,     // PIE-glibc
    AgentName::Dpg1Dpg1, // PIE-glibc depth-2
    AgentName::Dpg1Dng,  // non-PIE-glibc
    AgentName::Dpg1Spg,  // static-PIE-glibc (still uses ld.so for nss)
    AgentName::Dpg1Spm,  // static-PIE-musl — cli form, no ld.so
    AgentName::Dpg1Snm,  // non-PIE-static-musl
];
const SOCKOPT_SCENARIOS: &[ScenarioDef] = &[
    ScenarioDef {
        name: "reuseaddr_double_listen",
        run: run_reuseaddr_double_listen,
    },
    ScenarioDef {
        name: "reuseport_two_listeners",
        run: run_reuseport_two_listeners,
    },
    ScenarioDef {
        name: "keepalive_roundtrip",
        run: run_keepalive_roundtrip,
    },
];

struct ScenarioDef {
    name: &'static str,
    run: for<'a, 'r> fn(&'a mut RunContext<'r>, AgentHandle, &'static str) -> ScenarioFuture<'a>,
}

type ScenarioFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = TestOutcome> + 'a>>;

pub(crate) fn register_sockopt_tests(reg: &mut Registry<'_>) {
    for &agent in SOCKOPT_AGENTS {
        for def in SOCKOPT_SCENARIOS {
            let id = format!("SOCKOPT.{}.{}", def.name, agent);
            reg.test("vscode_gap", "sockopt", id)
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    let agent_label = agent.name();
                    Box::new(move |run| (def.run)(run, handle, agent_label))
                });
        }
    }
}

fn run_reuseaddr_double_listen<'a>(
    run: &'a mut RunContext<'_>,
    handle: AgentHandle,
    agent_label: &'static str,
) -> ScenarioFuture<'a> {
    Box::pin(async move {
        let first = listen(run, &handle, 0, vec![]).await;
        let port = match first {
            Ok(port) => port,
            Err(e) => return TestOutcome::new(agent_label, false, format!("initial listen: {e}")),
        };
        let plain_second = listen(run, &handle, port, vec![]).await;
        if plain_second.is_ok() {
            let _ = run.send(&handle, Command::NetUnlisten { port }).await;
            return TestOutcome::new(
                agent_label,
                false,
                format!("second listen on active port {port} succeeded without SO_REUSEADDR"),
            );
        }
        let _ = connect_echo(run, &handle, port, "sockopt_reuseaddr_plain").await;
        let _ = run.send(&handle, Command::NetUnlisten { port }).await;

        let reuse_options = vec![(SockOpt::ReuseAddr, SockOptValue::Bool(true))];
        let reuse_first = listen(run, &handle, 0, reuse_options.clone()).await;
        let reuse_port = match reuse_first {
            Ok(port) => port,
            Err(e) => {
                return TestOutcome::new(agent_label, false, format!("reuseaddr listen: {e}"));
            }
        };
        let _ = connect_echo(run, &handle, reuse_port, "sockopt_reuseaddr_enabled").await;
        let _ = run
            .send(&handle, Command::NetUnlisten { port: reuse_port })
            .await;
        match listen(run, &handle, reuse_port, reuse_options).await {
            Ok(_) => {
                let _ = run
                    .send(&handle, Command::NetUnlisten { port: reuse_port })
                    .await;
                TestOutcome::new(
                    agent_label,
                    true,
                    format!(
                        "plain_second={} reuseaddr_relisten=ok",
                        plain_second.is_ok()
                    ),
                )
            }
            Err(e) => TestOutcome::new(
                agent_label,
                false,
                format!("reuseaddr re-listen on {reuse_port} failed: {e}"),
            ),
        }
    })
}

fn run_reuseport_two_listeners<'a>(
    run: &'a mut RunContext<'_>,
    handle: AgentHandle,
    agent_label: &'static str,
) -> ScenarioFuture<'a> {
    Box::pin(async move {
        let options = vec![(SockOpt::ReusePort, SockOptValue::Bool(true))];
        let port = match listen(run, &handle, 0, options.clone()).await {
            Ok(port) => port,
            Err(e) => return TestOutcome::new(agent_label, false, format!("first listen: {e}")),
        };
        if let Err(e) = listen(run, &handle, port, options).await {
            let _ = run.send(&handle, Command::NetUnlisten { port }).await;
            return TestOutcome::new(agent_label, false, format!("second reuseport listen: {e}"));
        }

        for i in 0..8 {
            let payload = format!("sockopt_reuseport_{i}");
            if let Err(e) = connect_echo(run, &handle, port, &payload).await {
                let _ = run.send(&handle, Command::NetUnlisten { port }).await;
                return TestOutcome::new(agent_label, false, format!("connect {i}: {e}"));
            }
        }

        let stats = run.send(&handle, Command::NetListenerStats { port }).await;
        let (pass, detail) = match stats {
            Response::ListenerStats { counts } => {
                let pass = counts.len() == 2 && counts.iter().all(|count| *count > 0);
                (pass, format!("accept_counts={counts:?}"))
            }
            other => (false, format!("stats failed: {other:?}")),
        };
        let _ = run.send(&handle, Command::NetUnlisten { port }).await;
        TestOutcome::new(agent_label, pass, detail)
    })
}

fn run_keepalive_roundtrip<'a>(
    run: &'a mut RunContext<'_>,
    handle: AgentHandle,
    agent_label: &'static str,
) -> ScenarioFuture<'a> {
    Box::pin(async move {
        let port = match listen(run, &handle, 0, vec![]).await {
            Ok(port) => port,
            Err(e) => return TestOutcome::new(agent_label, false, format!("listen: {e}")),
        };
        let conn = match open(run, &handle, port).await {
            Ok(conn) => conn,
            Err(e) => {
                let _ = run.send(&handle, Command::NetUnlisten { port }).await;
                return TestOutcome::new(agent_label, false, format!("open: {e}"));
            }
        };
        let set_resp = run
            .send(
                &handle,
                Command::NetSetSockOpt {
                    conn,
                    option: SockOpt::KeepAlive,
                    value: SockOptValue::Bool(true),
                },
            )
            .await;
        if !matches!(set_resp, Response::Ok { data: None }) {
            let _ = run.send(&handle, Command::NetClose { conn }).await;
            let _ = run.send(&handle, Command::NetUnlisten { port }).await;
            return TestOutcome::new(agent_label, false, format!("set keepalive: {set_resp:?}"));
        }
        let get_resp = run
            .send(
                &handle,
                Command::NetGetSockOpt {
                    conn,
                    option: SockOpt::KeepAlive,
                },
            )
            .await;
        let pass = matches!(
            get_resp,
            Response::SockOptResult {
                value: SockOptValue::Bool(true)
            }
        );
        let _ = run.send(&handle, Command::NetClose { conn }).await;
        let _ = run.send(&handle, Command::NetUnlisten { port }).await;
        TestOutcome::new(agent_label, pass, format!("get_keepalive={get_resp:?}"))
    })
}

async fn listen(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    port: u16,
    pre_bind_options: Vec<(SockOpt, SockOptValue)>,
) -> Result<u16, String> {
    let resp = run
        .send(
            handle,
            Command::NetListen {
                port,
                pre_bind_options,
            },
        )
        .await;
    super::expect_listening_port(&resp, port).map_err(|e| format!("{e}; resp={resp:?}"))
}

async fn open(run: &mut RunContext<'_>, handle: &AgentHandle, port: u16) -> Result<u64, String> {
    let resp = run
        .send(
            handle,
            Command::NetOpen {
                addr: format!("127.0.0.1:{port}"),
            },
        )
        .await;
    match resp {
        Response::Opened { conn } => Ok(conn),
        other => Err(format!("expected Opened, got {other:?}")),
    }
}

async fn connect_echo(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    port: u16,
    payload: &str,
) -> Result<(), String> {
    let resp = run
        .send(
            handle,
            Command::NetConnect {
                addr: format!("127.0.0.1:{port}"),
                data: payload.to_string(),
            },
        )
        .await;
    match resp {
        Response::Connected { echo } if echo == payload => Ok(()),
        other => Err(format!("expected echo {payload:?}, got {other:?}")),
    }
}
