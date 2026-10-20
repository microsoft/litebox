// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Running test commands: logged, time-limited, and many at once.

use anyhow::{Context as _, Result};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{IsTerminal as _, Write as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// How a command ended.
pub struct Outcome {
    /// The exit code, if it exited.
    pub code: Option<i32>,
    /// The terminating signal, if a signal killed it.
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub duration: Duration,
    /// Its standard output and error, interleaved.
    pub output: String,
}

/// A command running `program` in a session of its own, for [`run_logged`].
pub fn session_command(program: impl AsRef<OsStr>) -> Command {
    // As the spawned process does not lead a process group, setsid makes it a session leader
    // without forking, so its PID is the session ID.
    let mut command = Command::new("setsid");
    command.arg(program);
    command
}

/// Runs `command`, made by [`session_command`], with no input and its output in `log`, killing
/// it, and every process it started, after `timeout`.
pub fn run_logged(mut command: Command, log: &Path, timeout: Duration) -> Result<Outcome> {
    let file = File::create(log).with_context(|| format!("creating {}", log.display()))?;
    command
        .stdin(Stdio::null())
        .stdout(file.try_clone()?)
        .stderr(file);
    let start = Instant::now();
    let mut child = command
        .spawn()
        .with_context(|| format!("spawning {command:?}"))?;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            kill_session(child.id());
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let duration = start.elapsed();
    // Kill what it left behind, e.g. a runner whose broker died, or the test's own children
    // (which LTP moves into process groups of their own).
    kill_session(child.id());
    let output = String::from_utf8_lossy(&std::fs::read(log)?).into_owned();
    Ok(Outcome {
        code: status.code(),
        signal: status.signal(),
        timed_out,
        duration,
        output,
    })
}

/// While alive, prints `message` if the user interrupts the scanner (e.g. with Ctrl-C), which
/// does not reach the commands [`run_logged`] runs, as they are in sessions of their own.
pub struct InterruptHint(Child);

impl InterruptHint {
    pub fn new(message: &str) -> Result<Self> {
        // Without a dependency the scanner cannot handle signals itself, but a shell in its
        // process group gets the terminal's SIGINT too.
        let watcher = Command::new("sh")
            .args([
                "-c",
                r#"trap 'printf "\n%s\n" "$1" >&2; exit 130' INT
                   while kill -0 "$2" 2>/dev/null; do sleep 1; done"#,
                "sh",
                message,
                &std::process::id().to_string(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .context("spawning sh")?;
        Ok(Self(watcher))
    }
}

impl Drop for InterruptHint {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn kill_session(session: u32) {
    // Killing a process can let its parent, not yet killed, start another.
    for _ in 0..10 {
        let members = session_members(session);
        if members.is_empty() {
            return;
        }
        let _ = Command::new("kill")
            .arg("-KILL")
            .args(members.iter().map(u32::to_string))
            .stderr(Stdio::null())
            .status();
        // Let parents caught mid-fork finish, so the next pass sees their children.
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The live (not zombie) processes in `session`.
fn session_members(session: u32) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| {
            let pid: u32 = entry.ok()?.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // "<pid> (<comm>) <state> <ppid> <pgrp> <session> ...", where comm may hold anything.
            let mut fields = stat.get(stat.rfind(')')? + 1..)?.split_whitespace();
            let state = fields.next()?;
            let in_session = fields.nth(2)?.parse::<u32>().ok()? == session;
            (in_session && state != "Z").then_some(pid)
        })
        .collect()
}

/// Applies `f` to every item on `jobs` threads, reporting progress on standard error, and returns
/// the results in order.
pub fn parallel_map<T: Sync, R: Send>(
    jobs: usize,
    label: &str,
    items: &[T],
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let results = Mutex::new((0..items.len()).map(|_| None).collect::<Vec<_>>());
    let interactive = std::io::stderr().is_terminal();
    std::thread::scope(|scope| {
        for _ in 0..jobs.max(1) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(index) else { break };
                    let result = f(item);
                    results.lock().unwrap()[index] = Some(result);
                    let done = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if interactive {
                        eprint!("\r{label}: {done}/{}", items.len());
                        let _ = std::io::stderr().flush();
                    } else if done.is_multiple_of(100) || done == items.len() {
                        eprintln!("{label}: {done}/{}", items.len());
                    }
                }
            });
        }
    });
    if interactive {
        eprintln!();
    }
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .map(Option::unwrap)
        .collect()
}
