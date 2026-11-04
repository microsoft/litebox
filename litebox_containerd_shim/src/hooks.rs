// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OCI hooks, which run on the host as runc runs them. Hooks may call containerd, which may call
//! the shim: the shim's state lock is never held while they run.

use std::fs::File;
use std::io::{Read as _, Seek as _, Write as _};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use oci_spec::runtime::{Hook, Spec};

use crate::{MAX_ERROR_DETAIL, Result, internal};

/// The container's hooks, and its OCI state without its status.
pub struct Hooks {
    hooks: oci_spec::runtime::Hooks,
    state: serde_json::Value,
}

impl Hooks {
    /// The hooks of `spec` for the container `id` in `bundle`, whose init's pid is `pid`: the
    /// broker's, whose namespaces are the daemon's (the host's), so a hook that enters them acts on
    /// the host.
    pub fn new(spec: &Spec, id: &str, bundle: &str, pid: u32) -> Self {
        let state = serde_json::json!({
            "ociVersion": spec.version(),
            "id": id,
            "pid": pid,
            "bundle": bundle,
            "annotations": spec.annotations().clone().unwrap_or_default(),
        });
        Self {
            hooks: spec.hooks().clone().unwrap_or_default(),
            state,
        }
    }

    /// Runs the `prestart` and `createRuntime` hooks, up to the first that fails. They run once
    /// the root archive is built: file binds hold the host files as they were before these hooks.
    pub fn create(&self) -> Result<()> {
        let stages = [
            ("prestart", self.hooks.prestart()),
            ("createRuntime", self.hooks.create_runtime()),
        ];
        for (stage, hooks) in stages {
            for hook in hooks.iter().flatten() {
                self.run(stage, hook, "creating").map_err(internal)?;
            }
        }
        Ok(())
    }

    /// Runs the `poststart` hooks; failures are logged only.
    pub fn poststart(&self) {
        let hooks = self.hooks.poststart();
        self.run_all("poststart", hooks.as_deref(), "running", |error| {
            log::warn!("{error}");
        });
    }

    /// Runs the `poststop` hooks, with pid 0, as runc gives a stopped container none; failures go
    /// to `report` only.
    pub fn poststop(&self, report: impl Fn(&str)) {
        let hooks = self.hooks.poststop();
        self.run_all("poststop", hooks.as_deref(), "stopped", report);
    }

    fn run_all(&self, stage: &str, hooks: Option<&[Hook]>, status: &str, report: impl Fn(&str)) {
        for hook in hooks.unwrap_or_default() {
            if let Err(error) = self.run(stage, hook, status) {
                report(&error);
            }
        }
    }

    /// Runs `hook` with the OCI state on its stdin, killing it after its timeout; fails unless it
    /// exits with 0, with its stderr; the error is escaped.
    fn run(&self, stage: &str, hook: &Hook, status: &str) -> std::result::Result<(), String> {
        let path = hook.path().display().to_string();
        let failed =
            |what: &dyn std::fmt::Display| format!("the {stage} hook {path:?} failed: {what}");
        let mut oci_state = self.state.clone();
        oci_state["status"] = status.into();
        if status == "stopped" {
            oci_state["pid"] = 0.into();
        }
        let mut command = Command::new(hook.path());
        if let Some((arg0, args)) = hook.args().as_deref().and_then(<[String]>::split_first) {
            command.arg0(arg0).args(args);
        }
        if let Some(env) = hook.env() {
            command
                .env_clear()
                .envs(env.iter().filter_map(|entry| entry.split_once('=')));
        }
        let timeout = hook
            .timeout()
            .map(|seconds| Duration::from_secs(u64::try_from(seconds).unwrap_or(0)));
        let mut stderr = File::from(
            rustix::fs::memfd_create("hook-stderr", rustix::fs::MemfdFlags::CLOEXEC)
                .map_err(|error| failed(&error))?,
        );
        let exit = (|| {
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(stderr.try_clone()?)
                .spawn()?;
            let mut stdin = child.stdin.take().expect("piped");
            std::thread::spawn(move || stdin.write_all(oci_state.to_string().as_bytes()));
            crate::wait_or_kill(&mut child, timeout)
        })()
        .map_err(|error| failed(&error))?;
        // Bounded: the error goes back to containerd in one message.
        let mut output = Vec::new();
        let _ = stderr.rewind().and_then(|()| {
            (&mut stderr)
                .take(MAX_ERROR_DETAIL as u64)
                .read_to_end(&mut output)
        });
        let output = String::from_utf8_lossy(&output);
        match exit {
            Some(exit) if exit.success() => Ok(()),
            Some(exit) => Err(failed(&format!("{exit}, stderr {output:?}"))),
            None => Err(failed(&format!("timed out, stderr {output:?}"))),
        }
    }
}
