// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! clone3 flag-combination matrix tests.

use crate::protocol::{Clone3Kind, Command, Response};

use super::agents::AgentName;
use super::registry::Registry;

const CL3_AGENTS: &[AgentName] = &[AgentName::A, AgentName::AA, AgentName::B, AgentName::BB];

struct Clone3Def {
    name: &'static str,
    kind: fn() -> Clone3Kind,
    expect: fn(&Response) -> Result<(), String>,
}

const CL3_KINDS: &[Clone3Def] = &[
    Clone3Def {
        name: "thread",
        kind: || Clone3Kind::Thread,
        expect: expect_success_without_pidfd,
    },
    Clone3Def {
        name: "process",
        kind: || Clone3Kind::Process,
        expect: expect_success_without_pidfd,
    },
    Clone3Def {
        name: "with_pidfd",
        kind: || Clone3Kind::WithPidfd,
        expect: expect_success_with_pidfd,
    },
    Clone3Def {
        name: "with_set_tid",
        kind: || Clone3Kind::WithSetTid { tid: 99_999 },
        expect: expect_set_tid_outcome,
    },
    Clone3Def {
        name: "with_cgroup",
        kind: || Clone3Kind::WithCgroup { cgroup_fd: 0 },
        expect: expect_cgroup_outcome,
    },
];

pub(crate) fn register_clone3_matrix(reg: &mut Registry<'_>) {
    for &agent in CL3_AGENTS {
        for def in CL3_KINDS {
            let agent_s = agent.to_string();
            let name = def.name;
            let kind = def.kind;
            let expect = def.expect;
            reg.test("vscode", "clone3", format!("CL3.{name}.{agent}"))
                .timeout(60)
                .build(move |cx| {
                    let handle = cx.require(agent);
                    Box::new(move |run| {
                        let a = agent_s.clone();
                        Box::pin(async move {
                            let resp = run.send(&handle, Command::Clone3 { kind: kind() }).await;
                            match expect(&resp) {
                                Ok(()) => super::TestOutcome::new(&a, true, format!("{resp:?}")),
                                Err(error) => super::TestOutcome::new(
                                    &a,
                                    false,
                                    format!("{error}; response={resp:?}"),
                                ),
                            }
                        })
                    })
                });
        }
    }
}

fn expect_success_without_pidfd(resp: &Response) -> Result<(), String> {
    match resp {
        Response::CloneResult {
            pid,
            pidfd: None,
            ok: true,
            error: None,
        } if *pid > 0 => Ok(()),
        Response::CloneResult {
            ok: false,
            error: Some(error),
            ..
        } if documented_error(error, &["ENOSYS"]) => Ok(()),
        other => Err(format!(
            "expected clone3 success or documented native ENOSYS/seccomp result without pidfd, got {other:?}"
        )),
    }
}

fn expect_success_with_pidfd(resp: &Response) -> Result<(), String> {
    match resp {
        Response::CloneResult {
            pid,
            pidfd: Some(pidfd),
            ok: true,
            error: None,
        } if *pid > 0 && *pidfd >= 0 => Ok(()),
        Response::CloneResult {
            ok: false,
            error: Some(error),
            ..
        } if documented_error(error, &["ENOSYS"]) => Ok(()),
        other => Err(format!(
            "expected clone3 success or documented native ENOSYS/seccomp result with pidfd, got {other:?}"
        )),
    }
}

fn expect_set_tid_outcome(resp: &Response) -> Result<(), String> {
    match resp {
        Response::CloneResult {
            pid,
            ok: true,
            error: None,
            ..
        } if *pid > 0 => Ok(()),
        Response::CloneResult {
            ok: false,
            error: Some(error),
            ..
        } if documented_error(error, &["ENOSYS", "EPERM"]) => Ok(()),
        other => Err(format!(
            "expected set_tid success or documented ENOSYS/EPERM failure, got {other:?}"
        )),
    }
}

fn expect_cgroup_outcome(resp: &Response) -> Result<(), String> {
    match resp {
        Response::CloneResult {
            pid,
            ok: true,
            error: None,
            ..
        } if *pid > 0 => Ok(()),
        Response::CloneResult {
            ok: false,
            error: Some(error),
            ..
        } if error.starts_with("cgroup_fd_unavailable:")
            || documented_error(
                error,
                &[
                    "EACCES",
                    "EBADF",
                    "EINVAL",
                    "ENOENT",
                    "ENOSYS",
                    "EOPNOTSUPP",
                    "EPERM",
                    "EROFS",
                ],
            ) =>
        {
            Ok(())
        }
        other => Err(format!(
            "expected cgroup success or documented cgroup-fd/permission error, got {other:?}"
        )),
    }
}

fn documented_error(error: &str, names: &[&str]) -> bool {
    names
        .iter()
        .any(|name| error == *name || error.contains(name))
}
