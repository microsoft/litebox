// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Inotify file watcher semantics tests for VS Code workspace
//! watching, migrated to the handler-refactor protocol.
//!
//! Each scenario (`create_file` / `modify_file` / `delete_file` /
//! `move_within`) splits into one watcher handler and one actor
//! handler that rendezvous on the `armed` checkpoint. The
//! `multi_watch` scenario is single-agent (one watcher exercising
//! two watch descriptors on one inotify fd) and uses `send_named`.
//!
//! Handler bodies hold the `Inotify` fd and watch descriptors as
//! local stack variables — no `AgentState` access.
//! `crate::os::inotify` provides the libc wrapper.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::handlers::{HandlerCtx, HandlerError};
use crate::os::inotify::{Event, Inotify};
use crate::register_handler;

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

pub(crate) const INO_AGENTS: &[AgentName] = &[
    AgentName::Dpg1,     // PIE-glibc baseline
    AgentName::Dpg1Dpg1, // PIE-glibc depth-2
    AgentName::Dpg2,     // PIE-glibc sibling subtree
    AgentName::Dpg2Dpg,  // PIE-glibc sibling depth-2
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

const SCENARIOS: &[(&str, ScenarioKind)] = &[
    ("create_file", ScenarioKind::CreateFile),
    ("modify_file", ScenarioKind::ModifyFile),
    ("delete_file", ScenarioKind::DeleteFile),
    ("move_within", ScenarioKind::MoveWithin),
    ("multi_watch", ScenarioKind::MultiWatch),
];

// ─── Watcher handler args/return ────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct WatchArgs {
    dir: String,
    /// File the actor will create/modify/delete. Watcher uses it for
    /// preflight (e.g. modify/delete need the file to exist before
    /// arming).
    target_path: String,
    /// Bytes to write during preflight when the scenario needs the
    /// file to exist before arming (`modify`/`delete`/`move_within`).
    /// Empty string means "no preflight write".
    preflight_contents: String,
    /// inotify mask the watcher arms.
    mask_bits: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct WatchOut {
    wd: i32,
    events: Vec<Event>,
}

// ─── Actor handler args/return ──────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct ActorCreate {
    dir: String,
    path: String,
    contents: String,
}

#[derive(Serialize, Deserialize)]
struct ActorModify {
    path: String,
    new_contents: String,
}

#[derive(Serialize, Deserialize)]
struct ActorDelete {
    path: String,
}

#[derive(Serialize, Deserialize)]
struct ActorMove {
    old_path: String,
    new_path: String,
}

// ─── Watcher handlers ───────────────────────────────────────────────

async fn handle_watch(args: WatchArgs, ctx: &mut HandlerCtx<'_>) -> Result<Value, HandlerError> {
    tokio::fs::create_dir_all(&args.dir).await?;
    if !args.preflight_contents.is_empty() {
        tokio::fs::write(&args.target_path, args.preflight_contents.as_bytes()).await?;
    }
    let ino = Inotify::new()?;
    let wd = ino.add_watch(&args.dir, args.mask_bits)?;
    ctx.checkpoint("armed").await?;
    let events = ino.drain(Duration::from_secs(2))?;
    Ok(serde_json::to_value(WatchOut { wd, events })?)
}

// ─── Actor handlers ─────────────────────────────────────────────────

async fn handle_actor_create(
    args: ActorCreate,
    ctx: &mut HandlerCtx<'_>,
) -> Result<Value, HandlerError> {
    tokio::fs::create_dir_all(&args.dir).await?;
    ctx.checkpoint("armed").await?;
    tokio::fs::write(&args.path, args.contents.as_bytes()).await?;
    Ok(Value::Null)
}

async fn handle_actor_modify(
    args: ActorModify,
    ctx: &mut HandlerCtx<'_>,
) -> Result<Value, HandlerError> {
    ctx.checkpoint("armed").await?;
    tokio::fs::write(&args.path, args.new_contents.as_bytes()).await?;
    Ok(Value::Null)
}

async fn handle_actor_delete(
    args: ActorDelete,
    ctx: &mut HandlerCtx<'_>,
) -> Result<Value, HandlerError> {
    ctx.checkpoint("armed").await?;
    tokio::fs::remove_file(&args.path).await?;
    Ok(Value::Null)
}

async fn handle_actor_move(
    args: ActorMove,
    ctx: &mut HandlerCtx<'_>,
) -> Result<Value, HandlerError> {
    ctx.checkpoint("armed").await?;
    tokio::fs::rename(&args.old_path, &args.new_path).await?;
    Ok(Value::Null)
}

// ─── Single-agent multi_watch handler ───────────────────────────────

#[derive(Serialize, Deserialize)]
struct MultiArgs {
    root: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct MultiOut {
    left_wd: i32,
    right_wd: i32,
    events: Vec<Event>,
}

async fn handle_multi_watch(
    args: MultiArgs,
    _ctx: &mut HandlerCtx<'_>,
) -> Result<Value, HandlerError> {
    let left = format!("{}/left", args.root);
    let right = format!("{}/right", args.root);
    tokio::fs::create_dir_all(&left).await?;
    tokio::fs::create_dir_all(&right).await?;
    let left_file = format!("{left}/left.txt");
    let right_file = format!("{right}/right.txt");
    tokio::fs::write(&left_file, "before-left").await?;
    tokio::fs::write(&right_file, "before-right").await?;
    let ino = Inotify::new()?;
    let left_wd = ino.add_watch(&left, libc::IN_MODIFY)?;
    let right_wd = ino.add_watch(&right, libc::IN_MODIFY)?;
    tokio::fs::write(&left_file, "after-left").await?;
    tokio::fs::write(&right_file, "after-right").await?;
    let events = ino.drain(Duration::from_secs(2))?;
    Ok(serde_json::to_value(MultiOut {
        left_wd,
        right_wd,
        events,
    })?)
}

// ─── Registration ───────────────────────────────────────────────────

pub(crate) fn register_inotify_tests(reg: &mut Registry<'_>) {
    // Register handlers once at startup (idempotent if called
    // multiple times since lookup is string-keyed).
    register_handler!("inotify.watch", handle_watch);
    register_handler!("inotify.actor.create", handle_actor_create);
    register_handler!("inotify.actor.modify", handle_actor_modify);
    register_handler!("inotify.actor.delete", handle_actor_delete);
    register_handler!("inotify.actor.move", handle_actor_move);
    register_handler!("inotify.multi_watch", handle_multi_watch);

    for &agent in INO_AGENTS {
        for &(name, kind) in SCENARIOS {
            let label = agent.to_string();
            let test_id = format!("INO.{name}.{agent}");
            reg.test("vscode_gap", "inotify", test_id)
                .timeout(60)
                .build(move |cx| {
                    let watcher = cx.require(agent);
                    let actor_agent = if matches!(kind, ScenarioKind::MultiWatch) {
                        agent
                    } else {
                        peer_for(agent)
                    };
                    let actor = if actor_agent == agent {
                        watcher.clone()
                    } else {
                        cx.require(actor_agent)
                    };
                    let label = label.clone();
                    Box::new(move |run| {
                        Box::pin(async move {
                            let result = drive_scenario(run, &watcher, &actor, kind, &label).await;
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
    // Pick an actor that doesn't share a direct top-level pipe with
    // the watcher. multi-agent rendezvous requires the two pipes to
    // be independent: while the watcher is paused at `checkpoint`,
    // the coord can't multiplex more commands onto the same parent
    // pipe to talk to a different in-flight handler.
    match agent {
        AgentName::Dpg1 | AgentName::Dpg1Dpg1 | AgentName::Dpg1Dng => AgentName::Dpg2,
        _ => AgentName::Dpg1,
    }
}

fn test_dir(scenario: &str, label: &str) -> String {
    format!("/root/litebox-inotify-{scenario}-{label}")
}

async fn drive_scenario(
    run: &mut super::run_context::RunContext<'_>,
    watcher: &super::agents::AgentHandle,
    actor: &super::agents::AgentHandle,
    kind: ScenarioKind,
    label: &str,
) -> Result<String, String> {
    match kind {
        ScenarioKind::CreateFile => drive_create(run, watcher, actor, label).await,
        ScenarioKind::ModifyFile => drive_modify(run, watcher, actor, label).await,
        ScenarioKind::DeleteFile => drive_delete(run, watcher, actor, label).await,
        ScenarioKind::MoveWithin => drive_move(run, watcher, actor, label).await,
        ScenarioKind::MultiWatch => drive_multi(run, watcher, label).await,
    }
}

/// Common rendezvous machinery for inotify cross-agent tests.
/// Both watcher and actor run their handlers and rendezvous on
/// `"armed"`; this helper returns the watcher's `WatchOut`.
async fn run_watch_actor(
    run: &mut super::run_context::RunContext<'_>,
    watcher: &super::agents::AgentHandle,
    actor: &super::agents::AgentHandle,
    actor_handler: &str,
    watch_args: Value,
    actor_args: Value,
) -> Result<WatchOut, String> {
    use crate::protocol::Response;

    // Kick off both handlers; each will arrive at the "armed"
    // checkpoint and emit Response::Checkpoint.
    run.run_write(watcher, "inotify.watch", watch_args).await?;
    match run.run_read(watcher).await {
        Response::Checkpoint { tag } if tag == "armed" => {}
        other => {
            return Err(format!(
                "watcher: expected Checkpoint(armed), got {other:?}"
            ));
        }
    }
    run.run_write(actor, actor_handler, actor_args).await?;
    match run.run_read(actor).await {
        Response::Checkpoint { tag } if tag == "armed" => {}
        other => return Err(format!("actor: expected Checkpoint(armed), got {other:?}")),
    }

    // Both arrived. Release both — the writes don't block; the actor
    // will do its filesystem operation, the watcher will drain events.
    run.run_resume(watcher, "armed").await?;
    run.run_resume(actor, "armed").await?;

    // Read both results. Order matters for the inotify case: the
    // actor's Result comes back quickly (just writes a file); the
    // watcher's takes up to 2s for the drain. Read watcher first so
    // the timeout-based drain has time to see the actor's event.
    let watcher_resp = run.run_read(watcher).await;
    let actor_resp = run.run_read(actor).await;

    let actor_ok = matches!(&actor_resp, Response::Result { ok: true, .. });
    if !actor_ok {
        return Err(format!("actor failed: {actor_resp:?}"));
    }
    match watcher_resp {
        Response::Result { ok: true, data, .. } => {
            serde_json::from_value::<WatchOut>(data).map_err(|e| format!("watcher decode: {e}"))
        }
        Response::Result {
            ok: false, error, ..
        } => Err(error.unwrap_or_else(|| "watcher failed".into())),
        other => Err(format!("watcher: expected Result, got {other:?}")),
    }
}

async fn drive_create(
    run: &mut super::run_context::RunContext<'_>,
    watcher: &super::agents::AgentHandle,
    actor: &super::agents::AgentHandle,
    label: &str,
) -> Result<String, String> {
    let dir = test_dir("create", label);
    let path = format!("{dir}/newfile.txt");
    let mask = libc::IN_CREATE | libc::IN_MODIFY | libc::IN_DELETE;
    let watch_args = json!({
        "dir": &dir,
        "target_path": &path,
        "preflight_contents": "",
        "mask_bits": mask,
    });
    let actor_args = json!({ "dir": &dir, "path": &path, "contents": "created" });

    let out = run_watch_actor(
        run,
        watcher,
        actor,
        "inotify.actor.create",
        watch_args,
        actor_args,
    )
    .await?;
    if out.events.iter().any(|e| {
        e.has(libc::IN_CREATE) && e.name.as_deref() == Some("newfile.txt") && e.wd == out.wd
    }) {
        Ok(format!("wd={} events={:?}", out.wd, out.events))
    } else {
        Err(format!(
            "missing IN_CREATE for newfile.txt wd={} events={:?}",
            out.wd, out.events
        ))
    }
}

async fn drive_modify(
    run: &mut super::run_context::RunContext<'_>,
    watcher: &super::agents::AgentHandle,
    actor: &super::agents::AgentHandle,
    label: &str,
) -> Result<String, String> {
    let dir = test_dir("modify", label);
    let path = format!("{dir}/existing.txt");
    let watch_args = json!({
        "dir": &dir,
        "target_path": &path,
        "preflight_contents": "before",
        "mask_bits": libc::IN_MODIFY,
    });
    let actor_args = json!({ "path": &path, "new_contents": "after" });

    let out = run_watch_actor(
        run,
        watcher,
        actor,
        "inotify.actor.modify",
        watch_args,
        actor_args,
    )
    .await?;
    if out
        .events
        .iter()
        .any(|e| e.has(libc::IN_MODIFY) && e.wd == out.wd)
    {
        Ok(format!("wd={} events={:?}", out.wd, out.events))
    } else {
        Err(format!(
            "missing IN_MODIFY wd={} events={:?}",
            out.wd, out.events
        ))
    }
}

async fn drive_delete(
    run: &mut super::run_context::RunContext<'_>,
    watcher: &super::agents::AgentHandle,
    actor: &super::agents::AgentHandle,
    label: &str,
) -> Result<String, String> {
    let dir = test_dir("delete", label);
    let path = format!("{dir}/remove-me.txt");
    let watch_args = json!({
        "dir": &dir,
        "target_path": &path,
        "preflight_contents": "delete me",
        "mask_bits": libc::IN_DELETE,
    });
    let actor_args = json!({ "path": &path });

    let out = run_watch_actor(
        run,
        watcher,
        actor,
        "inotify.actor.delete",
        watch_args,
        actor_args,
    )
    .await?;
    if out.events.iter().any(|e| {
        e.has(libc::IN_DELETE) && e.name.as_deref() == Some("remove-me.txt") && e.wd == out.wd
    }) {
        Ok(format!("wd={} events={:?}", out.wd, out.events))
    } else {
        Err(format!(
            "missing IN_DELETE for remove-me.txt wd={} events={:?}",
            out.wd, out.events
        ))
    }
}

async fn drive_move(
    run: &mut super::run_context::RunContext<'_>,
    watcher: &super::agents::AgentHandle,
    actor: &super::agents::AgentHandle,
    label: &str,
) -> Result<String, String> {
    let dir = test_dir("move", label);
    let old = format!("{dir}/old-name.txt");
    let new = format!("{dir}/new-name.txt");
    let watch_args = json!({
        "dir": &dir,
        "target_path": &old,
        "preflight_contents": "move me",
        "mask_bits": libc::IN_MOVED_FROM | libc::IN_MOVED_TO,
    });
    let actor_args = json!({ "old_path": &old, "new_path": &new });

    let out = run_watch_actor(
        run,
        watcher,
        actor,
        "inotify.actor.move",
        watch_args,
        actor_args,
    )
    .await?;
    let from = out.events.iter().find(|e| {
        e.has(libc::IN_MOVED_FROM)
            && e.cookie != 0
            && e.name.as_deref() == Some("old-name.txt")
            && e.wd == out.wd
    });
    let to = out.events.iter().find(|e| {
        e.has(libc::IN_MOVED_TO)
            && e.cookie != 0
            && e.name.as_deref() == Some("new-name.txt")
            && e.wd == out.wd
    });
    match (from, to) {
        (Some(f), Some(t)) if f.cookie == t.cookie => Ok(format!(
            "wd={} cookie={} events={:?}",
            out.wd, f.cookie, out.events
        )),
        _ => Err(format!(
            "missing paired IN_MOVED_FROM/IN_MOVED_TO wd={} events={:?}",
            out.wd, out.events
        )),
    }
}

async fn drive_multi(
    run: &mut super::run_context::RunContext<'_>,
    watcher: &super::agents::AgentHandle,
    label: &str,
) -> Result<String, String> {
    let root = test_dir("multi", label);
    let args = json!({ "root": &root });
    let data = run
        .send_named(watcher, "inotify.multi_watch", args)
        .await
        .map_err(|e| format!("send_named: {e}"))?;
    let out: MultiOut = serde_json::from_value(data).map_err(|e| format!("decode: {e}"))?;
    let saw_left = out
        .events
        .iter()
        .any(|e| e.wd == out.left_wd && e.has(libc::IN_MODIFY));
    let saw_right = out
        .events
        .iter()
        .any(|e| e.wd == out.right_wd && e.has(libc::IN_MODIFY));
    if saw_left && saw_right && out.left_wd != out.right_wd {
        Ok(format!(
            "left_wd={} right_wd={} events={:?}",
            out.left_wd, out.right_wd, out.events
        ))
    } else {
        Err(format!(
            "routing mismatch left_wd={} right_wd={} events={:?}",
            out.left_wd, out.right_wd, out.events
        ))
    }
}
