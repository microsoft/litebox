// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PTY protocol tests for VS Code terminal blockers.

use crate::protocol::{Command, Response};

use super::TestOutcome;
use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;

const PTY_AGENTS: &[AgentName] = &[
    AgentName::A,
    AgentName::AA,
    AgentName::AAA,
    AgentName::B,
    // AB exercises the reverse child branch under A alongside AA/AAA: the PTY
    // registry lives in the child while routing returns through its parent.
    AgentName::AB,
];

struct ScenarioDef {
    name: &'static str,
    build: fn(AgentHandle, String) -> PtyRun,
}

type PtyRun = Box<
    dyn for<'r> FnOnce(
            &'r mut RunContext<'_>,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = TestOutcome> + 'r>>
        + Send,
>;

const PTY_SCENARIOS: &[ScenarioDef] = &[
    ScenarioDef {
        name: "exec_echo",
        build: build_exec_echo,
    },
    ScenarioDef {
        name: "tiocgpgrp",
        build: build_tiocgpgrp,
    },
    ScenarioDef {
        name: "tiocspgrp",
        build: build_tiocspgrp,
    },
    ScenarioDef {
        name: "tiocsctty",
        build: build_tiocsctty,
    },
    ScenarioDef {
        name: "resize",
        build: build_resize,
    },
    ScenarioDef {
        name: "exec_shell_session",
        build: build_exec_shell_session,
    },
];

pub(crate) fn register_pty_tests(reg: &mut Registry<'_>) {
    for &agent in PTY_AGENTS {
        for def in PTY_SCENARIOS {
            let agent_s = agent.to_string();
            let name = def.name;
            let build = def.build;
            reg.test("vscode", "pty", format!("PTY.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    build(handle, agent_s.clone())
                });
        }
    }
}

fn build_exec_echo(handle: AgentHandle, agent: String) -> PtyRun {
    Box::new(move |run| {
        Box::pin(async move {
            let result = run_pty_child(
                run,
                &handle,
                vec!["/bin/echo".into(), "hello".into()],
                true,
                None,
                "hello\r\n",
            )
            .await;
            outcome(&agent, result)
        })
    })
}

fn build_tiocgpgrp(handle: AgentHandle, agent: String) -> PtyRun {
    Box::new(move |run| {
        Box::pin(async move {
            let self_exe = run.self_exe().to_string();
            let (master, _slave_path) = expect_pty_open(run, &handle).await?;
            let pid = expect_background(
                run.send(
                    &handle,
                    Command::PtyExec {
                        master,
                        args: vec![self_exe, "pty-tiocgpgrp".into()],
                        ctrl_tty: true,
                    },
                )
                .await,
            )?;
            expect_wait_ok(run, &handle, pid).await?;
            let data = expect_received(
                run.send(
                    &handle,
                    Command::PtyRead {
                        master,
                        n_bytes: None,
                    },
                )
                .await,
            )?;
            expect_closed(run, &handle, master).await?;
            let expected = format!("TIOCGPGRP pgrp={pid}\r\n");
            exact(&data, &expected)
        })
        .map_outcome(agent)
    })
}

fn build_tiocspgrp(handle: AgentHandle, agent: String) -> PtyRun {
    Box::new(move |run| {
        Box::pin(async move {
            let self_exe = run.self_exe().to_string();
            let (master, _slave_path) = expect_pty_open(run, &handle).await?;
            let pid = expect_background(
                run.send(
                    &handle,
                    Command::PtyExec {
                        master,
                        args: vec![self_exe, "pty-tiocspgrp".into()],
                        ctrl_tty: true,
                    },
                )
                .await,
            )?;
            expect_wait_ok(run, &handle, pid).await?;
            let data = expect_received(
                run.send(
                    &handle,
                    Command::PtyRead {
                        master,
                        n_bytes: None,
                    },
                )
                .await,
            )?;
            expect_closed(run, &handle, master).await?;
            let expected = format!("TIOCSPGRP pgrp={pid} got={pid}\r\n");
            exact(&data, &expected)
        })
        .map_outcome(agent)
    })
}

fn build_tiocsctty(handle: AgentHandle, agent: String) -> PtyRun {
    Box::new(move |run| {
        Box::pin(async move {
            let self_exe = run.self_exe().to_string();
            run_pty_child(
                run,
                &handle,
                vec![self_exe, "pty-tiocsctty".into()],
                true,
                None,
                "TTY_OK\r\n",
            )
            .await
        })
        .map_outcome(agent)
    })
}

fn build_resize(handle: AgentHandle, agent: String) -> PtyRun {
    Box::new(move |run| {
        Box::pin(async move {
            let self_exe = run.self_exe().to_string();
            let (master, _slave_path) = expect_pty_open(run, &handle).await?;
            let pid = expect_background(
                run.send(
                    &handle,
                    Command::PtyExec {
                        master,
                        args: vec![self_exe, "pty-resize".into()],
                        ctrl_tty: true,
                    },
                )
                .await,
            )?;
            let ready = expect_received(
                run.send(
                    &handle,
                    Command::PtyRead {
                        master,
                        n_bytes: Some(7),
                    },
                )
                .await,
            )?;
            exact(&ready, "READY\r\n")?;
            expect_ok(
                run.send(
                    &handle,
                    Command::PtyResize {
                        master,
                        rows: 41,
                        cols: 132,
                    },
                )
                .await,
            )?;
            expect_wait_ok(run, &handle, pid).await?;
            let data = expect_received(
                run.send(
                    &handle,
                    Command::PtyRead {
                        master,
                        n_bytes: None,
                    },
                )
                .await,
            )?;
            expect_closed(run, &handle, master).await?;
            exact(&data, "RESIZE rows=41 cols=132\r\n")
        })
        .map_outcome(agent)
    })
}

fn build_exec_shell_session(handle: AgentHandle, agent: String) -> PtyRun {
    Box::new(move |run| {
        Box::pin(async move {
            let (master, _slave_path) = expect_pty_open(run, &handle).await?;
            let pid = expect_background(
                run.send(
                    &handle,
                    Command::PtyExec {
                        master,
                        args: vec![
                            "bash".into(),
                            "-c".into(),
                            "stty -echo; echo READY; read x; echo got=$x".into(),
                        ],
                        ctrl_tty: true,
                    },
                )
                .await,
            )?;
            let ready = expect_received(
                run.send(
                    &handle,
                    Command::PtyRead {
                        master,
                        n_bytes: Some(7),
                    },
                )
                .await,
            )?;
            exact(&ready, "READY\r\n")?;
            expect_sent(
                run.send(
                    &handle,
                    Command::PtyWrite {
                        master,
                        data: "value\n".to_string(),
                    },
                )
                .await,
            )?;
            expect_wait_ok(run, &handle, pid).await?;
            let data = expect_received(
                run.send(
                    &handle,
                    Command::PtyRead {
                        master,
                        n_bytes: None,
                    },
                )
                .await,
            )?;
            expect_closed(run, &handle, master).await?;
            exact(&data, "got=value\r\n")
        })
        .map_outcome(agent)
    })
}

async fn run_pty_child(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    args: Vec<String>,
    ctrl_tty: bool,
    input: Option<&str>,
    expected: &str,
) -> Result<String, String> {
    let (master, _slave_path) = expect_pty_open(run, handle).await?;
    let pid = expect_background(
        run.send(
            handle,
            Command::PtyExec {
                master,
                args,
                ctrl_tty,
            },
        )
        .await,
    )?;
    if let Some(data) = input {
        expect_sent(
            run.send(
                handle,
                Command::PtyWrite {
                    master,
                    data: data.to_string(),
                },
            )
            .await,
        )?;
    }
    expect_wait_ok(run, handle, pid).await?;
    let data = expect_received(
        run.send(
            handle,
            Command::PtyRead {
                master,
                n_bytes: None,
            },
        )
        .await,
    )?;
    expect_closed(run, handle, master).await?;
    exact(&data, expected)
}

async fn expect_pty_open(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
) -> Result<(u64, String), String> {
    match run.send(handle, Command::PtyOpen {}).await {
        Response::PtyHandle { master, slave_path } if master != 0 && !slave_path.is_empty() => {
            Ok((master, slave_path))
        }
        other => Err(format!("expected PtyHandle, got {other:?}")),
    }
}

fn expect_background(resp: Response) -> Result<u32, String> {
    match resp {
        Response::Background { pid } if pid != 0 => Ok(pid),
        other => Err(format!("expected Background, got {other:?}")),
    }
}

async fn expect_wait_ok(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    pid: u32,
) -> Result<(), String> {
    match run
        .send(
            handle,
            Command::WaitBackground {
                pid,
                timeout_secs: Some(10),
            },
        )
        .await
    {
        Response::ExecResult { exit_code: 0, .. } => Ok(()),
        other => Err(format!("expected successful WaitBackground, got {other:?}")),
    }
}

fn expect_received(resp: Response) -> Result<String, String> {
    match resp {
        Response::Received { data } => Ok(data),
        other => Err(format!("expected Received, got {other:?}")),
    }
}

fn expect_sent(resp: Response) -> Result<(), String> {
    match resp {
        Response::Sent => Ok(()),
        other => Err(format!("expected Sent, got {other:?}")),
    }
}

fn expect_ok(resp: Response) -> Result<(), String> {
    match resp {
        Response::Ok { data: None } => Ok(()),
        other => Err(format!("expected Ok(None), got {other:?}")),
    }
}

async fn expect_closed(
    run: &mut RunContext<'_>,
    handle: &AgentHandle,
    master: u64,
) -> Result<(), String> {
    match run.send(handle, Command::PtyClose { master }).await {
        Response::Closed => Ok(()),
        other => Err(format!("expected Closed, got {other:?}")),
    }
}

fn exact(actual: &str, expected: &str) -> Result<String, String> {
    if actual == expected {
        Ok(format!("exact {expected:?}"))
    } else {
        Err(format!("expected {expected:?}, got {actual:?}"))
    }
}

fn outcome(agent: &str, result: Result<String, String>) -> TestOutcome {
    match result {
        Ok(detail) => TestOutcome::new(agent, true, detail),
        Err(detail) => TestOutcome::new(agent, false, detail),
    }
}

trait OutcomeFutureExt<'r> {
    fn map_outcome(
        self,
        agent: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = TestOutcome> + 'r>>;
}

impl<'r, F> OutcomeFutureExt<'r> for std::pin::Pin<Box<F>>
where
    F: std::future::Future<Output = Result<String, String>> + 'r,
{
    fn map_outcome(
        self,
        agent: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = TestOutcome> + 'r>> {
        Box::pin(async move { outcome(&agent, self.await) })
    }
}
