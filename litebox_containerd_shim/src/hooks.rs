// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OCI hooks, which run on the host as runc runs them. Hooks may call containerd, which may call
//! the shim: the shim's state lock is never held while they run.

use std::fs::File;
use std::io::{self, Read as _, Seek as _, Write as _};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use oci_spec::runtime::{Hook, Spec};

use crate::{MAX_ERROR_DETAIL, Result, internal};

/// Refuses a hook whose `args[0]` is not its `path`, file name or stem (in any case): a Windows
/// hook always gets its `path` as `args[0]`, since `Command` puts the program first.
#[cfg(windows)]
pub fn check(spec: &Spec) -> Result<()> {
    let Some(hooks) = spec.hooks() else {
        return Ok(());
    };
    let stages = [
        ("prestart", hooks.prestart()),
        ("createRuntime", hooks.create_runtime()),
        ("poststart", hooks.poststart()),
        ("poststop", hooks.poststop()),
    ];
    for (stage, hooks) in stages {
        for hook in hooks.iter().flatten() {
            let path = hook.path();
            if let Some(arg0) = hook.args().as_deref().and_then(<[String]>::first)
                && ![Some(path.as_os_str()), path.file_name(), path.file_stem()]
                    .into_iter()
                    .flatten()
                    .any(|name| name.eq_ignore_ascii_case(arg0))
            {
                return Err(crate::unsupported(format!(
                    "the {stage} hook {:?} cannot have args[0] {arg0:?} on Windows",
                    path.display().to_string()
                )));
            }
        }
    }
    Ok(())
}

/// The container's hooks, and its OCI state without its status.
pub struct Hooks {
    hooks: oci_spec::runtime::Hooks,
    state: serde_json::Value,
}

impl Hooks {
    /// The hooks of `spec` for the container `id` in `bundle`, whose init's pid is `pid`: the
    /// broker's, in the container's network namespace and the daemon's (the host's) other
    /// namespaces, so a hook that enters those acts on the host.
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
            set_arg0(&mut command, arg0);
            command.args(args);
        }
        if let Some(env) = hook.env() {
            command
                .env_clear()
                .envs(env.iter().filter_map(|entry| entry.split_once('=')));
        }
        let timeout = hook
            .timeout()
            .map(|seconds| Duration::from_secs(u64::try_from(seconds).unwrap_or(0)));
        let mut stderr = scratch_file().map_err(|error| failed(&error))?;
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

#[cfg(unix)]
fn set_arg0(command: &mut Command, arg0: &str) {
    command.arg0(arg0);
}

#[cfg(windows)]
fn set_arg0(_: &mut Command, _: &str) {}

#[cfg(unix)]
fn scratch_file() -> io::Result<File> {
    let file = rustix::fs::memfd_create("hook-stderr", rustix::fs::MemfdFlags::CLOEXEC)?;
    Ok(File::from(file))
}

#[cfg(windows)]
fn scratch_file() -> io::Result<File> {
    use std::hash::{BuildHasher as _, Hasher as _, RandomState};
    use std::os::windows::fs::OpenOptionsExt as _;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_DELETE_ON_CLOSE,
    };

    let name = format!(
        "litebox-hook-stderr-{}-{:016x}",
        std::process::id(),
        RandomState::new().build_hasher().finish()
    );
    File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .attributes(FILE_ATTRIBUTE_TEMPORARY)
        .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
        .open(std::env::temp_dir().join(name))
}

#[cfg(all(test, windows))]
mod tests {
    use oci_spec::runtime::{HookBuilder, HooksBuilder, Spec};

    use super::{Hooks, check};

    #[test]
    fn a_hook_gets_its_path_as_args0() {
        let hook = |arg0: &str| {
            HookBuilder::default()
                .path(r"C:\Windows\System32\cmd.exe")
                .args(
                    [arg0, "/v:on", "/c", "echo !CMDCMDLINE!>&2& exit /b 3"]
                        .map(String::from)
                        .to_vec(),
                )
                .build()
                .unwrap()
        };
        let spec = |arg0: &str| {
            let mut spec = Spec::default();
            let hooks = HooksBuilder::default().poststop(vec![hook(arg0)]);
            spec.set_hooks(Some(hooks.build().unwrap()));
            spec
        };
        let hooks = Hooks::new(&Spec::default(), "id", "bundle", 1);
        for arg0 in [r"C:\Windows\System32\cmd.exe", "CMD.EXE", "cmd"] {
            check(&spec(arg0)).unwrap();
            let error = hooks.run("poststop", &hook(arg0), "stopped").unwrap_err();
            // The hook's command line, as stderr's `Debug`.
            assert!(
                error.contains(r#"stderr "\"C:\\Windows\\System32\\cmd.exe\" /v:on"#),
                "{arg0}: {error}"
            );
        }
        match check(&spec("sh")) {
            Err(crate::ttrpc::Error::RpcStatus(status)) => {
                assert_eq!(status.code(), crate::ttrpc::Code::UNIMPLEMENTED);
            }
            other => panic!("accepted args[0] sh: {other:?}"),
        }
    }

    #[test]
    fn a_failed_hook_reports_its_stderr() {
        let hooks = Hooks::new(&Spec::default(), "id", "bundle", 1);
        let hook = |script: &str| {
            HookBuilder::default()
                .path(r"C:\Windows\System32\cmd.exe")
                .args(["cmd", "/c", script].map(String::from).to_vec())
                .build()
                .unwrap()
        };
        assert_eq!(
            hooks.run("prestart", &hook("exit /b 0"), "creating"),
            Ok(())
        );
        let error = hooks
            .run("prestart", &hook("echo oops 1>&2 & exit /b 3"), "creating")
            .unwrap_err();
        assert!(error.contains("exit code: 3"), "{error}");
        assert!(error.contains("oops"), "{error}");
    }
}
