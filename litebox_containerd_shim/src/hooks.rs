// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OCI hooks, which run on the host as runc runs them.
//!
//! Hooks may call containerd, which may call this shim, so no lock may be held while they run.

use std::fs::File;
use std::io::{self, Write as _};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::error::{Error, Result};
use crate::runner::reap;
use crate::spec::{self, ContainerPlan, Hook};

/// The container's OCI hooks, which belong to its init process, and their OCI state.
pub(crate) struct Hooks {
    pub(crate) stages: spec::Hooks,
    /// The OCI state without its status.
    state: serde_json::Value,
}

impl Hooks {
    /// The hooks of `plan` for the container `id` in `bundle`, whose init process's runner is
    /// `pid`.
    pub(crate) fn new(plan: ContainerPlan, id: &str, bundle: &str, pid: Option<u32>) -> Self {
        let mut state = serde_json::json!({
            "ociVersion": plan.oci_version,
            "id": id,
            "bundle": bundle,
            "annotations": plan.annotations,
        });
        if let Some(pid) = pid {
            state["pid"] = pid.into();
        }
        Self {
            stages: plan.hooks,
            state,
        }
    }

    /// Runs `hooks` in order with the container in `status` and their output in `log`, up to the
    /// first that fails.
    pub(crate) fn run(&self, log: &File, hooks: &[Hook], status: &str) -> Result<()> {
        let mut state = self.state.clone();
        state["status"] = status.into();
        // As runc reports it: a stopped container has no process.
        if status == "stopped"
            && let Some(state) = state.as_object_mut()
        {
            state.remove("pid");
        }
        let state = state.to_string();
        hooks.iter().try_for_each(|hook| {
            run_hook(hook, state.as_bytes(), log).map_err(|error| Error::io(&hook.name, &error))
        })
    }

    /// Runs every hook of `hooks` like [`Self::run`], only logging failures, as the OCI runtime
    /// spec requires for `poststart` and `poststop` hooks.
    pub(crate) fn run_logged(&self, log: &File, hooks: &[Hook], status: &str) {
        for hook in hooks {
            if let Err(error) = self.run(log, std::slice::from_ref(hook), status) {
                log::warn!("{error}");
            }
        }
    }
}

/// Runs `hook` with the OCI state `state` on its stdin and its output in `log`, killing it once
/// its timeout expires. Fails unless it exits successfully.
fn run_hook(hook: &Hook, state: &[u8], log: &File) -> io::Result<()> {
    let mut command = Command::new(&hook.path);
    if let Some((arg0, args)) = hook.args.split_first() {
        command.arg0(arg0).args(args);
    }
    if let Some(env) = &hook.env {
        command
            .env_clear()
            .envs(env.iter().filter_map(|entry| entry.split_once('=')));
    }
    command
        .stdin(Stdio::piped())
        .stdout(log.try_clone()?)
        .stderr(log.try_clone()?);
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().expect("the hook's stdin is piped");
    let state = state.to_vec();
    // A hook that never reads its input must not hold up the daemon past its timeout.
    let writer = std::thread::Builder::new()
        .name("litebox-hook".to_owned())
        .spawn(move || {
            let _ = stdin.write_all(&state);
        });
    if let Err(error) = writer {
        reap(&mut child, Some(Instant::now()))?;
        return Err(error);
    }
    // A timeout too long to represent is none.
    let deadline = hook
        .timeout
        .and_then(|timeout| Instant::now().checked_add(timeout));
    match reap(&mut child, deadline)? {
        (_, true) => Err(io::ErrorKind::TimedOut.into()),
        (status, false) if status.success() => Ok(()),
        (status, false) => Err(io::Error::other(status.to_string())),
    }
}
