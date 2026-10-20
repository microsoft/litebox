// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Building, packaging for, and running guests under LiteBox's Linux userland runner.

use crate::Workspace;
use crate::exec::{parallel_map, session_command};
use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use xshell::{Shell, cmd};

pub struct LiteBox {
    broker: PathBuf,
    runner: PathBuf,
    packager: PathBuf,
    allow_fork: bool,
    pub profile: &'static str,
}

impl LiteBox {
    /// Builds the broker, runner, and packager.
    pub fn build(workspace: &Workspace, release: bool, allow_fork: bool) -> Result<Self> {
        let sh = Shell::new()?;
        sh.change_dir(&workspace.root);
        let release_flag = release.then_some("--release");
        // Cargo's messages give the executables' paths, which depend on its configuration (e.g.
        // a build target).
        let messages = cmd!(
            sh,
            "cargo build {release_flag...} --message-format=json-render-diagnostics -p litebox_broker_userland -p litebox_runner_linux_userland -p litebox_packager"
        )
        .read()?;
        let mut executables = BTreeMap::new();
        for message in messages.lines() {
            let message: serde_json::Value = serde_json::from_str(message)?;
            if let (Some(name), Some(executable)) = (
                message["target"]["name"].as_str(),
                message["executable"].as_str(),
            ) {
                executables.insert(name.to_owned(), PathBuf::from(executable));
            }
        }
        let mut executable = |name: &str| {
            executables
                .remove(name)
                .with_context(|| format!("cargo build did not report the {name} executable"))
        };
        Ok(Self {
            broker: executable("litebox-broker-userland")?,
            runner: executable("litebox_runner_linux_userland")?,
            packager: executable("litebox_packager")?,
            allow_fork,
            profile: if release { "release" } else { "debug" },
        })
    }

    /// Packages `files` into `tar` at their host paths: ELFs rewritten and, where `ldd` finds
    /// them, with their shared libraries; other files as they are. Keeps an existing `tar` made by
    /// the same packager unless its key file (`<tar>.key`) was removed, as when its files change.
    pub fn package(&self, files: &[PathBuf], tar: &Path, jobs: usize) -> Result<()> {
        // Cargo updates binaries' modification times even when it does not rebuild them, so the
        // packager is identified by its contents.
        let key = format!("{:x}\n", Sha256::digest(std::fs::read(&self.packager)?));
        let key_file = tar.with_extension("tar.key");
        if tar.exists() && std::fs::read_to_string(&key_file).is_ok_and(|old| old == key) {
            return Ok(());
        }
        eprintln!("Packaging {} files into {}...", files.len(), tar.display());
        // The packager refuses ELFs with libraries `ldd` cannot find (e.g. test data that loads
        // libraries beside it), so those are included without their libraries.
        let with_libraries: Vec<Result<bool>> =
            parallel_map(jobs, "Finding libraries", files, |file| {
                Ok(is_elf(file)? && libraries_found(file))
            });
        let mut command = Command::new(&self.packager);
        for (file, with_libraries) in files.iter().zip(with_libraries) {
            if with_libraries? {
                command.arg(file);
            } else {
                let path = file.to_str().context("non-UTF-8 path")?;
                command.arg("--include").arg(format!("{path}:{path}"));
            }
        }
        // Built beside the tar so an interrupted run does not leave a truncated one that looks
        // up to date.
        let partial = tar.with_extension("partial.tar");
        command.arg("-o").arg(&partial);
        let output = command.stdout(Stdio::null()).output()?;
        if !output.status.success() {
            bail!(
                "litebox_packager failed ({}):\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::fs::rename(&partial, tar)?;
        std::fs::write(key_file, key)?;
        Ok(())
    }

    /// The command running `argv` under LiteBox, with `tar` as its root file system and `env` as
    /// its whole environment.
    pub fn command(&self, tar: &Path, env: &[(&str, String)], argv: &[String]) -> Command {
        let mut command = session_command(&self.broker);
        if self.allow_fork {
            command.args(["--unstable", "--allow-process-duplication"]);
        }
        command
            .arg("--fs-initial-files")
            .arg(tar)
            .arg("--runner")
            .arg(&self.runner);
        for (key, value) in env {
            command.arg("--env").arg(format!("{key}={value}"));
        }
        command.args(argv);
        command
    }
}

/// The host's syscall names by number, from its C headers; empty if they cannot be read.
pub fn host_syscall_names() -> BTreeMap<u32, String> {
    let Ok(sh) = Shell::new() else {
        return BTreeMap::new();
    };
    let Ok(macros) = cmd!(sh, "cc -E -dM -")
        .stdin("#include <sys/syscall.h>\n")
        .quiet()
        .read()
    else {
        return BTreeMap::new();
    };
    macros
        .lines()
        .filter_map(|line| {
            let (name, number) = line.strip_prefix("#define __NR_")?.split_once(' ')?;
            Some((number.trim().parse().ok()?, name.to_owned()))
        })
        .collect()
}

/// Whether `ldd` finds all of `elf`'s shared libraries (true too for static ELFs, which have
/// none).
fn libraries_found(elf: &Path) -> bool {
    Command::new("ldd")
        .arg(elf)
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|output| !String::from_utf8_lossy(&output.stdout).contains("not found"))
}

fn is_elf(path: &Path) -> Result<bool> {
    let mut magic = [0; 4];
    let read = File::open(path)?.read(&mut magic)?;
    Ok(read == magic.len() && magic == *b"\x7fELF")
}

/// What the broker and runner reported about a guest's end, separately from the guest's own
/// output.
#[derive(Default)]
pub struct GuestEnd {
    /// The guest's exit code; under the runner, a guest a signal killed exits 128 + the signal.
    pub code: Option<i32>,
    /// LiteBox's own panic, as `<message> (at <location>)`.
    pub panic: Option<String>,
    /// An error the broker or runner reported, e.g. a guest that could not be loaded.
    pub error: Option<String>,
}

/// Reads a run's [`GuestEnd`] from its interleaved output, without the runner's warnings (see
/// [`strip_runner_warnings`]), and the broker's exit code.
pub fn guest_end(output: &str, broker_code: Option<i32>) -> GuestEnd {
    let mut end = GuestEnd {
        code: broker_code.filter(|&code| code == 0),
        ..GuestEnd::default()
    };
    let mut lines = output.lines().peekable();
    while let Some(line) = lines.next() {
        if let Some((_, location)) = line.split_once("panicked at ") {
            if end.panic.is_none() {
                let message = lines.peek().copied().unwrap_or_default().trim();
                let location = location.trim_end_matches(':');
                end.panic = Some(format!("{message} (at {location})"));
            }
        } else if let Some((_, status)) = line.split_once("runner exited with exit status: ") {
            end.code = status
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|code| code.parse().ok());
        } else if let Some((_, status)) = line.split_once("runner exited with ") {
            // The runner itself died, e.g. "signal: 11 (SIGSEGV)".
            let status = status.trim_end_matches(['"', ' ', '}']);
            end.error
                .get_or_insert_with(|| format!("runner exited with {status}"));
        } else if let Some(error) = line.strip_prefix("Error: ")
            && end.error.is_none()
        {
            // anyhow prints the causes of an error, indented, after a "Caused by:" line.
            let mut error = error.to_owned();
            if lines.peek().is_some_and(|next| next.trim().is_empty()) {
                lines.next();
            }
            if lines.peek() == Some(&"Caused by:") {
                lines.next();
                if let Some(cause) = lines.next() {
                    error = format!("{error}: {}", cause.trim());
                }
            }
            end.error = Some(error);
        }
    }
    end
}

/// How debug runners report a host syscall that their seccomp filter blocked.
const BLOCKED_SYSCALL: &str = "WARNING: disallowed syscall invoked: ";
/// How debug runners report a host `openat` that their seccomp filter blocked: this, the path,
/// then [`BLOCKED_OPENAT_END`].
const BLOCKED_OPENAT: &str = "INFO: openat with ";
const BLOCKED_OPENAT_END: &str = " is not allowed";

/// Removes debug runners' warnings about host syscalls their seccomp filter blocked from
/// `output`, returning the rest and the syscalls' numbers (but for `openat`'s). The warnings come
/// from a signal handler, so they can land in the middle of other lines.
pub fn strip_runner_warnings(output: &str) -> (String, Vec<u32>) {
    let mut stripped = String::with_capacity(output.len());
    let mut numbers = Vec::new();
    let mut rest = output;
    loop {
        let syscall = rest.find(BLOCKED_SYSCALL);
        let openat = rest.find(BLOCKED_OPENAT);
        let after = if let Some(start) = syscall
            && openat.is_none_or(|openat| start < openat)
        {
            stripped.push_str(&rest[..start]);
            let after = &rest[start + BLOCKED_SYSCALL.len()..];
            let digits = after.bytes().take_while(u8::is_ascii_digit).count();
            if let Ok(number) = after[..digits].parse()
                && !numbers.contains(&number)
            {
                numbers.push(number);
            }
            &after[digits..]
        } else if let Some(start) = openat
            && let Some(end) = rest[start..].find(BLOCKED_OPENAT_END)
        {
            stripped.push_str(&rest[..start]);
            &rest[start + end + BLOCKED_OPENAT_END.len()..]
        } else {
            break;
        };
        rest = after.strip_prefix('\n').unwrap_or(after);
    }
    stripped.push_str(rest);
    numbers.sort_unstable();
    (stripped, numbers)
}
