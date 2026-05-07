// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! io_uring discovery tests for VS Code startup blockers.
//!
//! This branch does not include W2's richer `EpollOpen`/`EpollWait`
//! surface, so the epoll fallback scenario uses the intentionally tiny
//! `Command::EpollOpen` primitive: create an epoll fd, close it immediately,
//! and report only success/failure. That is enough to prove an io_uring probe
//! does not poison the subsequent epoll fallback path.

use crate::protocol::{Command, Response};

use super::agents::AgentName;
use super::registry::Registry;

const ENOSYS: i32 = libc::ENOSYS;
const EOPNOTSUPP: i32 = libc::EOPNOTSUPP;

pub(crate) const IOR_AGENTS: &[AgentName] =
    &[AgentName::Dpg1, AgentName::Dpg1Dpg1, AgentName::Dpg2];

const IOR_SCENARIOS: &[IorScenario] = &[
    IorScenario {
        name: "setup_returns_documented_outcome",
        kind: IorScenarioKind::SetupReturnsDocumentedOutcome,
    },
    IorScenario {
        name: "epoll_works_after_iouring_refusal",
        kind: IorScenarioKind::EpollWorksAfterIouringRefusal,
    },
    IorScenario {
        name: "repeated_setup_consistent",
        kind: IorScenarioKind::RepeatedSetupConsistent,
    },
];

#[derive(Clone, Copy)]
enum IorScenarioKind {
    SetupReturnsDocumentedOutcome,
    EpollWorksAfterIouringRefusal,
    RepeatedSetupConsistent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IoUringOutcome {
    ring_fd: i32,
    errno: Option<i32>,
}

struct IorScenario {
    name: &'static str,
    kind: IorScenarioKind,
}

fn outcome_from_response(resp: &Response) -> Option<IoUringOutcome> {
    match resp {
        Response::IoUringResult { ring_fd, errno } => Some(IoUringOutcome {
            ring_fd: *ring_fd,
            errno: *errno,
        }),
        _ => None,
    }
}

fn is_documented_outcome(outcome: IoUringOutcome) -> bool {
    matches!(
        outcome,
        IoUringOutcome {
            ring_fd: 1,
            errno: None,
        } | IoUringOutcome {
            ring_fd: -1,
            errno: Some(ENOSYS),
        } | IoUringOutcome {
            ring_fd: -1,
            errno: Some(EOPNOTSUPP),
        }
    )
}

pub(crate) fn register_iouring_discovery_tests(reg: &mut Registry<'_>) {
    for &agent in IOR_AGENTS {
        for def in IOR_SCENARIOS {
            let agent_s = agent.to_string();
            let name = def.name;
            let kind = def.kind;
            reg.test("vscode", "iouring", format!("IOR.{name}.{agent}"))
                .timeout(30)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        Box::pin(async move {
                            let (pass, detail) = match kind {
                                IorScenarioKind::SetupReturnsDocumentedOutcome => {
                                    let resp = run
                                        .send(&handle, Command::IoUringSetup { entries: 8 })
                                        .await;
                                    let pass = outcome_from_response(&resp)
                                        .is_some_and(is_documented_outcome);
                                    (pass, format!("{resp:?}"))
                                }
                                IorScenarioKind::EpollWorksAfterIouringRefusal => {
                                    let ior_resp = run
                                        .send(&handle, Command::IoUringSetup { entries: 8 })
                                        .await;
                                    let ior_ok = outcome_from_response(&ior_resp)
                                        .is_some_and(is_documented_outcome);
                                    let epoll_resp = run.send(&handle, Command::EpollOpen).await;
                                    let epoll_ok = matches!(
                                        epoll_resp,
                                        Response::EpollOpenResult {
                                            epoll_fd: 1,
                                            errno: None,
                                        }
                                    );
                                    (
                                        ior_ok && epoll_ok,
                                        format!("io_uring={ior_resp:?}; epoll={epoll_resp:?}"),
                                    )
                                }
                                IorScenarioKind::RepeatedSetupConsistent => {
                                    let first = run
                                        .send(&handle, Command::IoUringSetup { entries: 8 })
                                        .await;
                                    let second = run
                                        .send(&handle, Command::IoUringSetup { entries: 8 })
                                        .await;
                                    let third = run
                                        .send(&handle, Command::IoUringSetup { entries: 8 })
                                        .await;
                                    let outcomes = [
                                        outcome_from_response(&first),
                                        outcome_from_response(&second),
                                        outcome_from_response(&third),
                                    ];
                                    let pass = outcomes[0].is_some_and(is_documented_outcome)
                                        && outcomes[0] == outcomes[1]
                                        && outcomes[1] == outcomes[2];
                                    (
                                        pass,
                                        format!(
                                            "first={first:?}; second={second:?}; third={third:?}"
                                        ),
                                    )
                                }
                            };
                            super::TestOutcome::new(&a, pass, detail)
                        })
                    })
                });
        }
    }
}
