// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Eventfd semantics tests for VS Code/Node platform compatibility.

use crate::protocol::{Command, Response};

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;
use super::run_context::RunContext;

pub(crate) const EV_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,
    AgentName::Dpg1Dpg1,
    AgentName::Dpg2,
    AgentName::Dpg2Dpg,
];

struct EventfdScenario {
    name: &'static str,
    run: Option<
        for<'a, 'r> fn(&'a mut RunContext<'r>, &'a super::agents::AgentHandle) -> EventfdFuture<'a>,
    >,
}

type EventfdFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + 'a>>;

const EV_SCENARIOS: &[EventfdScenario] = &[
    EventfdScenario {
        name: "counter",
        run: Some(run_counter),
    },
    EventfdScenario {
        name: "semaphore",
        run: Some(run_semaphore),
    },
    EventfdScenario {
        name: "cross_agent_wakeup",
        run: None,
    },
    EventfdScenario {
        name: "epollet",
        run: Some(run_epollet),
    },
];

pub(crate) fn register_eventfd_tests(reg: &mut Registry<'_>) {
    for &agent in EV_AGENTS {
        for def in EV_SCENARIOS {
            let Some(run_scenario) = def.run else {
                continue;
            };
            let agent_s = agent.to_string();
            let name = def.name;
            reg.test("vscode", "eventfd", format!("EV.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        Box::pin(async move {
                            let result = run_scenario(run, &handle).await;
                            outcome(&a, result)
                        })
                    })
                });
        }
    }

    // Cross-agent sharing is restricted to paired subtrees. Layer 1 models
    // sharing as a registry authorization plus a logical read forwarded through
    // the creator agent; it intentionally does not implement SCM_RIGHTS fd
    // passing (layer 2). We register A↔B and AA↔BB only, not same-agent cases.
    for &(creator, reader) in &[
        (AgentName::Dpg1, AgentName::Dpg2),
        (AgentName::Dpg2, AgentName::Dpg1),
        (AgentName::Dpg1Dpg1, AgentName::Dpg2Dpg),
        (AgentName::Dpg2Dpg, AgentName::Dpg1Dpg1),
    ] {
        let id = format!("EV.cross_agent_wakeup.{creator}_to_{reader}");
        let label = format!("{creator}->{reader}");
        reg.test("vscode", "eventfd", id)
            .timeout(60)
            .build(move |cx| {
                let creator_handle = cx.require(creator);
                let reader_handle = cx.require(reader);
                Box::new(move |run| {
                    let label = label.clone();
                    Box::pin(async move {
                        let result =
                            run_cross_agent(run, &creator_handle, &reader_handle, reader).await;
                        outcome(&label, result)
                    })
                })
            });
    }
}

fn outcome(agent: &str, result: Result<String, String>) -> TestOutcome {
    match result {
        Ok(detail) => TestOutcome::new(agent, true, detail),
        Err(detail) => TestOutcome::new(agent, false, detail),
    }
}

fn run_counter<'a>(
    run: &'a mut RunContext<'_>,
    agent: &'a super::agents::AgentHandle,
) -> EventfdFuture<'a> {
    Box::pin(async move {
        let id = eventfd_open(run, agent, 0, "nonblock").await?;
        expect_sent(
            run.send(agent, Command::EventfdWrite { id, value: 3 })
                .await,
            "write 3",
        )?;
        expect_sent(
            run.send(agent, Command::EventfdWrite { id, value: 5 })
                .await,
            "write 5",
        )?;
        expect_eventfd_value(
            run.send(agent, Command::EventfdRead { id }).await,
            8,
            "read accumulated counter",
        )?;
        expect_eagain(
            run.send(agent, Command::EventfdRead { id }).await,
            "read empty nonblock",
        )?;
        expect_closed(run.send(agent, Command::EventfdClose { id }).await, "close")?;
        Ok(format!("counter id={id} value=8 eagain=ok"))
    })
}

fn run_semaphore<'a>(
    run: &'a mut RunContext<'_>,
    agent: &'a super::agents::AgentHandle,
) -> EventfdFuture<'a> {
    Box::pin(async move {
        let id = eventfd_open(run, agent, 5, "semaphore|nonblock").await?;
        for index in 0..5 {
            expect_eventfd_value(
                run.send(agent, Command::EventfdRead { id }).await,
                1,
                &format!("semaphore read {index}"),
            )?;
        }
        expect_eagain(
            run.send(agent, Command::EventfdRead { id }).await,
            "semaphore empty",
        )?;
        expect_closed(run.send(agent, Command::EventfdClose { id }).await, "close")?;
        Ok(format!("semaphore id={id} five_reads=1 eagain=ok"))
    })
}

fn run_epollet<'a>(
    run: &'a mut RunContext<'_>,
    agent: &'a super::agents::AgentHandle,
) -> EventfdFuture<'a> {
    Box::pin(async move {
        let id = eventfd_open(run, agent, 0, "nonblock|cloexec").await?;
        expect_sent(
            run.send(agent, Command::EventfdWrite { id, value: 3 })
                .await,
            "write 3",
        )?;
        expect_sent(
            run.send(agent, Command::EventfdWrite { id, value: 5 })
                .await,
            "write 5",
        )?;
        let detail = expect_ok_data(
            run.send(agent, Command::EventfdEpollEt { id }).await,
            "epollet",
        )?;
        if !detail.contains("first=1")
            || !detail.contains("second=0")
            || !detail.contains("value=8")
        {
            return Err(format!("epollet detail mismatch: {detail}"));
        }
        expect_closed(run.send(agent, Command::EventfdClose { id }).await, "close")?;
        Ok(format!("epollet id={id} {detail}"))
    })
}

async fn run_cross_agent(
    run: &mut RunContext<'_>,
    creator: &super::agents::AgentHandle,
    reader: &super::agents::AgentHandle,
    reader_name: AgentName,
) -> Result<String, String> {
    let reader_pid = run.send(reader, Command::GetPid).await;
    if !matches!(reader_pid, Response::Ok { data: Some(_) }) {
        return Err(format!("reader readiness failed: {reader_pid:?}"));
    }
    let id = eventfd_open(run, creator, 7, "nonblock").await?;
    let share = run
        .send(
            creator,
            Command::EventfdShare {
                id,
                target: reader_name.name().to_string(),
            },
        )
        .await;
    let share_detail = expect_ok_data(share, "share")?;
    expect_eventfd_value(
        run.send(
            creator,
            Command::EventfdReadShared {
                id,
                reader: reader_name.name().to_string(),
            },
        )
        .await,
        7,
        "reader logical read forwarded through creator",
    )?;
    expect_closed(
        run.send(creator, Command::EventfdClose { id }).await,
        "close",
    )?;
    Ok(format!(
        "cross_agent id={id} reader={} forward_via_creator=ok {share_detail}",
        reader_name.name()
    ))
}

async fn eventfd_open(
    run: &mut RunContext<'_>,
    agent: &super::agents::AgentHandle,
    initval: u64,
    flags: &str,
) -> Result<u64, String> {
    match run
        .send(
            agent,
            Command::EventfdOpen {
                initval,
                flags: flags.to_string(),
            },
        )
        .await
    {
        Response::EventfdHandle { id } => Ok(id),
        other => Err(format!("eventfd_open({initval}, {flags:?}) got {other:?}")),
    }
}

fn expect_sent(resp: Response, label: &str) -> Result<(), String> {
    match resp {
        Response::Sent => Ok(()),
        other => Err(format!("{label}: expected Sent, got {other:?}")),
    }
}

fn expect_closed(resp: Response, label: &str) -> Result<(), String> {
    match resp {
        Response::Closed => Ok(()),
        other => Err(format!("{label}: expected Closed, got {other:?}")),
    }
}

fn expect_ok_data(resp: Response, label: &str) -> Result<String, String> {
    match resp {
        Response::Ok { data: Some(data) } => Ok(data),
        other => Err(format!("{label}: expected Ok data, got {other:?}")),
    }
}

fn expect_eventfd_value(resp: Response, expected: u64, label: &str) -> Result<(), String> {
    match resp {
        Response::EventfdValue { value } if value == expected => Ok(()),
        Response::EventfdValue { value } => Err(format!(
            "{label}: expected EventfdValue {expected}, got {value}"
        )),
        other => Err(format!("{label}: expected EventfdValue, got {other:?}")),
    }
}

fn expect_eagain(resp: Response, label: &str) -> Result<(), String> {
    match resp {
        Response::Error { error } if error.contains("EAGAIN") => Ok(()),
        other => Err(format!("{label}: expected Error/EAGAIN, got {other:?}")),
    }
}
