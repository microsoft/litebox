// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Inotify file watcher semantics tests for VS Code workspace watching.

use crate::protocol::{Command, InotifyEvent, Response};

use super::TestOutcome;
use super::agents::{AgentHandle, AgentName};
use super::registry::Registry;
use super::run_context::RunContext;

pub(crate) const INO_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,     // PIE-glibc baseline
    AgentName::Dpg1Dpg1, // PIE-glibc depth-2
    AgentName::Dpg2,     // PIE-glibc sibling subtree
    AgentName::Dpg2Dpg,  // PIE-glibc, sibling depth-2
    AgentName::Dpg1Dng,  // non-PIE-glibc — different fd-bridge / inotify_init1 path
];

#[derive(Clone, Copy)]
enum ScenarioKind {
    CreateFile,
    ModifyFile,
    DeleteFile,
    MoveWithin,
    MultiWatch,
}

struct InotifyScenario {
    name: &'static str,
    kind: ScenarioKind,
}

const INO_SCENARIOS: &[InotifyScenario] = &[
    InotifyScenario {
        name: "create_file",
        kind: ScenarioKind::CreateFile,
    },
    InotifyScenario {
        name: "modify_file",
        kind: ScenarioKind::ModifyFile,
    },
    InotifyScenario {
        name: "delete_file",
        kind: ScenarioKind::DeleteFile,
    },
    InotifyScenario {
        name: "move_within",
        kind: ScenarioKind::MoveWithin,
    },
    InotifyScenario {
        name: "multi_watch",
        kind: ScenarioKind::MultiWatch,
    },
];

pub(crate) fn register_inotify_tests(reg: &mut Registry<'_>) {
    for &agent in INO_AGENTS {
        for def in INO_SCENARIOS {
            let scenario = def.kind;
            let agent_label = agent.to_string();
            reg.test("vscode_gap", "inotify", format!("INO.{}.{agent}", def.name))
                .timeout(60)
                .build(move |cx| {
                    let watcher = cx.require(agent);
                    let actor_agent = if matches!(scenario, ScenarioKind::MultiWatch) {
                        // multi_watch verifies one fd routing two watch descriptors;
                        // a cross-agent variant would duplicate the other scenarios'
                        // file visibility check without adding watch-descriptor signal.
                        agent
                    } else {
                        peer_for(agent)
                    };
                    let actor = if actor_agent == agent {
                        watcher.clone()
                    } else {
                        cx.require(actor_agent)
                    };
                    Box::new(move |run| {
                        let label = agent_label.clone();
                        Box::pin(async move {
                            let result =
                                run_scenario(run, &watcher, &actor, scenario, &label).await;
                            match result {
                                Ok(detail) => TestOutcome::new(&label, true, detail),
                                Err(detail) => TestOutcome::new(&label, false, detail),
                            }
                        })
                    })
                });
        }
    }
}

fn peer_for(agent: AgentName) -> AgentName {
    if matches!(agent, AgentName::Dpg1 | AgentName::Dpg1Dpg1) {
        AgentName::Dpg2
    } else {
        AgentName::Dpg1
    }
}

async fn run_scenario(
    run: &mut RunContext<'_>,
    watcher: &AgentHandle,
    actor: &AgentHandle,
    scenario: ScenarioKind,
    label: &str,
) -> Result<String, String> {
    match scenario {
        ScenarioKind::CreateFile => run_create_file(run, watcher, actor, label).await,
        ScenarioKind::ModifyFile => run_modify_file(run, watcher, actor, label).await,
        ScenarioKind::DeleteFile => run_delete_file(run, watcher, actor, label).await,
        ScenarioKind::MoveWithin => run_move_within(run, watcher, actor, label).await,
        ScenarioKind::MultiWatch => run_multi_watch(run, watcher, label).await,
    }
}

async fn run_create_file(
    run: &mut RunContext<'_>,
    watcher: &AgentHandle,
    actor: &AgentHandle,
    label: &str,
) -> Result<String, String> {
    let dir = test_dir("create", label);
    ensure_dir(run, actor, &dir).await?;
    let id = inotify_open(run, watcher).await?;
    let wd = inotify_add_watch(run, watcher, id, &dir, "create|modify|delete").await?;
    fs_write(run, actor, &format!("{dir}/newfile.txt"), "created").await?;
    let events = inotify_read(run, watcher, id, 16).await?;
    let _ = inotify_close(run, watcher, id).await;
    if events.iter().any(|event| {
        event.wd == wd
            && has_mask(event, "IN_CREATE")
            && event.name.as_deref() == Some("newfile.txt")
    }) {
        Ok(format!("wd={wd} events={events:?}"))
    } else {
        Err(format!(
            "missing IN_CREATE for newfile.txt wd={wd} events={events:?}"
        ))
    }
}

async fn run_modify_file(
    run: &mut RunContext<'_>,
    watcher: &AgentHandle,
    actor: &AgentHandle,
    label: &str,
) -> Result<String, String> {
    let dir = test_dir("modify", label);
    ensure_dir(run, actor, &dir).await?;
    let file = format!("{dir}/existing.txt");
    fs_write(run, actor, &file, "before").await?;
    let id = inotify_open(run, watcher).await?;
    let wd = inotify_add_watch(run, watcher, id, &dir, "modify").await?;
    fs_write(run, actor, &file, "after").await?;
    let events = inotify_read(run, watcher, id, 16).await?;
    let _ = inotify_close(run, watcher, id).await;
    if events
        .iter()
        .any(|event| event.wd == wd && has_mask(event, "IN_MODIFY"))
    {
        Ok(format!("wd={wd} events={events:?}"))
    } else {
        Err(format!("missing IN_MODIFY wd={wd} events={events:?}"))
    }
}

async fn run_delete_file(
    run: &mut RunContext<'_>,
    watcher: &AgentHandle,
    actor: &AgentHandle,
    label: &str,
) -> Result<String, String> {
    let dir = test_dir("delete", label);
    ensure_dir(run, actor, &dir).await?;
    let file = format!("{dir}/remove-me.txt");
    fs_write(run, actor, &file, "delete me").await?;
    let id = inotify_open(run, watcher).await?;
    let wd = inotify_add_watch(run, watcher, id, &dir, "delete").await?;
    fs_delete(run, actor, &file).await?;
    let events = inotify_read(run, watcher, id, 16).await?;
    let _ = inotify_close(run, watcher, id).await;
    if events.iter().any(|event| {
        event.wd == wd
            && has_mask(event, "IN_DELETE")
            && event.name.as_deref() == Some("remove-me.txt")
    }) {
        Ok(format!("wd={wd} events={events:?}"))
    } else {
        Err(format!(
            "missing IN_DELETE for remove-me.txt wd={wd} events={events:?}"
        ))
    }
}

async fn run_move_within(
    run: &mut RunContext<'_>,
    watcher: &AgentHandle,
    actor: &AgentHandle,
    label: &str,
) -> Result<String, String> {
    let dir = test_dir("move", label);
    ensure_dir(run, actor, &dir).await?;
    let old = format!("{dir}/old-name.txt");
    let new = format!("{dir}/new-name.txt");
    fs_write(run, actor, &old, "move me").await?;
    let id = inotify_open(run, watcher).await?;
    let wd = inotify_add_watch(run, watcher, id, &dir, "moved_from|moved_to").await?;
    exec_mv(run, actor, &old, &new).await?;
    let events = inotify_read(run, watcher, id, 16).await?;
    let _ = inotify_close(run, watcher, id).await;
    let from = events.iter().find(|event| {
        event.wd == wd
            && has_mask(event, "IN_MOVED_FROM")
            && event.cookie != 0
            && event.name.as_deref() == Some("old-name.txt")
    });
    let to = events.iter().find(|event| {
        event.wd == wd
            && has_mask(event, "IN_MOVED_TO")
            && event.cookie != 0
            && event.name.as_deref() == Some("new-name.txt")
    });
    match (from, to) {
        (Some(from), Some(to)) if from.cookie == to.cookie => {
            Ok(format!("wd={wd} cookie={} events={events:?}", from.cookie))
        }
        _ => Err(format!(
            "missing paired IN_MOVED_FROM/IN_MOVED_TO wd={wd} events={events:?}"
        )),
    }
}

async fn run_multi_watch(
    run: &mut RunContext<'_>,
    watcher: &AgentHandle,
    label: &str,
) -> Result<String, String> {
    let root = test_dir("multi", label);
    let left = format!("{root}/left");
    let right = format!("{root}/right");
    ensure_dir(run, watcher, &left).await?;
    ensure_dir(run, watcher, &right).await?;
    let left_file = format!("{left}/left.txt");
    let right_file = format!("{right}/right.txt");
    fs_write(run, watcher, &left_file, "before-left").await?;
    fs_write(run, watcher, &right_file, "before-right").await?;
    let id = inotify_open(run, watcher).await?;
    let left_wd = inotify_add_watch(run, watcher, id, &left, "modify").await?;
    let right_wd = inotify_add_watch(run, watcher, id, &right, "modify").await?;
    fs_write(run, watcher, &left_file, "after-left").await?;
    fs_write(run, watcher, &right_file, "after-right").await?;
    let events = inotify_read(run, watcher, id, 32).await?;
    let _ = inotify_close(run, watcher, id).await;
    let saw_left = events
        .iter()
        .any(|event| event.wd == left_wd && has_mask(event, "IN_MODIFY"));
    let saw_right = events
        .iter()
        .any(|event| event.wd == right_wd && has_mask(event, "IN_MODIFY"));
    if saw_left && saw_right && left_wd != right_wd {
        Ok(format!(
            "left_wd={left_wd} right_wd={right_wd} events={events:?}"
        ))
    } else {
        Err(format!(
            "multi_watch routing mismatch left_wd={left_wd} right_wd={right_wd} events={events:?}"
        ))
    }
}

fn test_dir(scenario: &str, label: &str) -> String {
    format!("/root/litebox-inotify-{scenario}-{label}")
}

async fn ensure_dir(
    run: &mut RunContext<'_>,
    actor: &AgentHandle,
    dir: &str,
) -> Result<(), String> {
    let seed = format!("{dir}/.seed");
    fs_write(run, actor, &seed, "seed").await?;
    fs_delete(run, actor, &seed).await
}

async fn fs_write(
    run: &mut RunContext<'_>,
    actor: &AgentHandle,
    path: &str,
    data: &str,
) -> Result<(), String> {
    match run
        .send(
            actor,
            Command::FsWrite {
                path: path.to_string(),
                data: data.to_string(),
            },
        )
        .await
    {
        Response::Ok { .. } => Ok(()),
        other => Err(format!("fs_write({path:?}) got {other:?}")),
    }
}

async fn fs_delete(
    run: &mut RunContext<'_>,
    actor: &AgentHandle,
    path: &str,
) -> Result<(), String> {
    match run
        .send(
            actor,
            Command::FsDelete {
                path: path.to_string(),
            },
        )
        .await
    {
        Response::Ok { .. } => Ok(()),
        other => Err(format!("fs_delete({path:?}) got {other:?}")),
    }
}

async fn exec_mv(
    run: &mut RunContext<'_>,
    actor: &AgentHandle,
    old: &str,
    new: &str,
) -> Result<(), String> {
    match run
        .send(
            actor,
            super::exec(vec!["mv".to_string(), old.to_string(), new.to_string()]),
        )
        .await
    {
        Response::ExecResult { exit_code: 0, .. } => Ok(()),
        other => Err(format!("mv {old:?} {new:?} got {other:?}")),
    }
}

async fn inotify_open(run: &mut RunContext<'_>, watcher: &AgentHandle) -> Result<u64, String> {
    match run.send(watcher, Command::InotifyOpen {}).await {
        Response::InotifyHandle { id } => Ok(id),
        other => Err(format!("inotify_open got {other:?}")),
    }
}

async fn inotify_add_watch(
    run: &mut RunContext<'_>,
    watcher: &AgentHandle,
    id: u64,
    path: &str,
    mask: &str,
) -> Result<i32, String> {
    match run
        .send(
            watcher,
            Command::InotifyAddWatch {
                id,
                path: path.to_string(),
                mask: mask.to_string(),
            },
        )
        .await
    {
        Response::WatchDescriptor { wd } => Ok(wd),
        other => Err(format!(
            "inotify_add_watch({path:?}, {mask:?}) got {other:?}"
        )),
    }
}

async fn inotify_read(
    run: &mut RunContext<'_>,
    watcher: &AgentHandle,
    id: u64,
    max_events: u32,
) -> Result<Vec<InotifyEvent>, String> {
    match run
        .send(watcher, Command::InotifyRead { id, max_events })
        .await
    {
        Response::InotifyEvents { events } => Ok(events),
        other => Err(format!("inotify_read({id}) got {other:?}")),
    }
}

async fn inotify_close(
    run: &mut RunContext<'_>,
    watcher: &AgentHandle,
    id: u64,
) -> Result<(), String> {
    match run.send(watcher, Command::InotifyClose { id }).await {
        Response::Closed => Ok(()),
        other => Err(format!("inotify_close({id}) got {other:?}")),
    }
}

fn has_mask(event: &InotifyEvent, needle: &str) -> bool {
    event.mask.split('|').any(|part| part == needle)
}
