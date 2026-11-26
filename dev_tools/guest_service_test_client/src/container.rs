// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs `programs.json` entries in the guest service's container, and checks how each run ended.

use std::fs::File;
use std::io::Write as _;
use std::sync::{Condvar, Mutex, PoisonError};
use std::thread;

use anyhow::{Context as _, Result, bail, ensure};
use litebox_guest_service_protocol::guest_service::{
    CloseStdinRequest, CreateContainerRequest, ExecProcessRequest, Process, ReadStreamRequest,
    ReleaseProcessRequest, SignalProcessRequest, StartContainerRequest, TtyWinResizeRequest,
    WaitProcessRequest, WriteStreamRequest,
};
use litebox_guest_service_protocol::guest_service_ttrpc::GuestServiceClient;
use ttrpc::context;

use crate::programs::{Entry, ExitStatus, Run, TERMINAL_COLUMNS, TERMINAL_ROWS};

/// The container's ID: the client runs one.
const CONTAINER: &str = "test";
/// The container's init process's exec ID.
const INIT: &str = "";
/// The most bytes one read asks for: the most the guest service returns.
const READ_LEN: u32 = 64 * 1024;
/// The signal that ends the container's init.
const SIGKILL: u32 = 9;

/// A guest service's container, which runs entries.
pub struct Container {
    service: GuestServiceClient,
    /// Where every run's output also goes, as it comes.
    output: Option<Mutex<File>>,
    /// The `console_stdin` runs' input.
    input: Vec<u8>,
}

/// Finds a line `ready` (as a terminal ends it too: `ready\r`) in output that comes in pieces.
#[derive(Default)]
struct ReadyLine {
    /// The current line so far, up to a `ready\r`'s length: a longer one is not it.
    line: Vec<u8>,
    seen: bool,
}

impl ReadyLine {
    /// Whether the output so far, `data` included, has the line.
    fn feed(&mut self, data: &[u8]) -> bool {
        for &byte in data {
            if self.seen {
                break;
            }
            if byte == b'\n' {
                self.seen = matches!(self.line.as_slice(), b"ready" | b"ready\r");
                self.line.clear();
            } else if self.line.len() <= b"ready\r".len() {
                self.line.push(byte);
            }
        }
        self.seen
    }
}

/// A run's progress: whether its standard output showed `ready`, whether it ended, and its
/// standard output so far.
#[derive(Default)]
struct Progress {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    ready: bool,
    ended: bool,
    stdout: Vec<u8>,
}

impl Progress {
    fn update(&self, update: impl FnOnce(&mut State)) {
        update(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner));
        self.changed.notify_all();
    }

    /// Waits until the run is ready or ended; true if ready.
    fn wait_ready(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let state = self
            .changed
            .wait_while(state, |state| !state.ready && !state.ended)
            .unwrap_or_else(PoisonError::into_inner);
        state.ready
    }

    /// Waits until the standard output has `text` at or after offset `from`, and returns the
    /// offset after it, or `None` if the run ended first.
    fn wait_output(&self, text: &[u8], from: usize) -> Option<usize> {
        let find = |state: &State| {
            state.stdout[from..]
                .windows(text.len())
                .position(|window| window == text)
                .map(|at| from + at + text.len())
        };
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let state = self
            .changed
            .wait_while(state, |state| find(state).is_none() && !state.ended)
            .unwrap_or_else(PoisonError::into_inner);
        find(&state)
    }
}

/// How a run ended.
struct Outcome {
    exit_status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Container {
    /// Creates and starts the container on `service`, with `init` as its init process, which
    /// runs until [`Self::end`] kills it.
    pub fn start(
        service: GuestServiceClient,
        init: &str,
        output: Option<File>,
        input: Vec<u8>,
    ) -> Result<Self> {
        let process = Process {
            args: vec![init.to_owned()],
            cwd: "/".to_owned(),
            ..Default::default()
        };
        let create = CreateContainerRequest {
            container_id: CONTAINER.to_owned(),
            process: Some(process).into(),
            ..Default::default()
        };
        service
            .create_container(context::Context::default(), &create)
            .context("CreateContainer")?;
        let start = StartContainerRequest {
            container_id: CONTAINER.to_owned(),
            ..Default::default()
        };
        service
            .start_container(context::Context::default(), &start)
            .context("StartContainer")?;
        let close = CloseStdinRequest {
            container_id: CONTAINER.to_owned(),
            exec_id: INIT.to_owned(),
            ..Default::default()
        };
        service
            .close_stdin(context::Context::default(), &close)
            .context("CloseStdin of the container's init")?;
        Ok(Self {
            service,
            output: output.map(Mutex::new),
            input,
        })
    }

    /// Kills the container's init, which ends the container, and checks that it was running.
    pub fn end(self) -> Result<()> {
        let signal = SignalProcessRequest {
            container_id: CONTAINER.to_owned(),
            exec_id: INIT.to_owned(),
            signal: SIGKILL,
            ..Default::default()
        };
        self.service
            .signal_process(context::Context::default(), &signal)
            .context("SignalProcess of the container's init")?;
        let exit_status = self.wait(INIT)?;
        ensure!(
            exit_status == ExitStatus::Signaled { signal: SIGKILL },
            "the container's init {exit_status} before it was killed"
        );
        self.release(INIT)
    }

    /// Runs `entry`, whose first run is run `first`, checks how its runs ended, and returns the
    /// failed ones, as `run INDEX (LABEL)`.
    pub fn run_entry(&self, first: usize, entry: &Entry) -> Vec<String> {
        let runs = entry.runs();
        let outcomes: Vec<Result<Outcome>> = thread::scope(|scope| {
            let started: Vec<_> = (first..)
                .zip(runs)
                .map(|(index, run)| scope.spawn(move || self.run(index, run)))
                .collect();
            started
                .into_iter()
                .map(|run| {
                    run.join()
                        .unwrap_or_else(|_| bail!("the run's thread panicked"))
                })
                .collect()
        });
        let mut failures = Vec::new();
        for ((index, run), outcome) in (first..).zip(runs).zip(outcomes) {
            let run_label = format!("run {index} ({})", run.label());
            match outcome.and_then(|outcome| check(run, &outcome)) {
                Ok(()) => println!("PASS  {run_label}"),
                Err(error) => {
                    println!("FAIL  {run_label}: {error:#}");
                    failures.push(run_label);
                }
            }
        }
        failures
    }

    /// Runs `run`, number `index`, in an exec process of its own.
    fn run(&self, index: usize, run: &Run) -> Result<Outcome> {
        let exec_id = format!("run-{index}");
        let process = Process {
            args: run.argv.clone(),
            env: run.envp.clone(),
            cwd: "/".to_owned(),
            terminal: run.terminal,
            rows: if run.terminal { TERMINAL_ROWS } else { 0 },
            columns: if run.terminal { TERMINAL_COLUMNS } else { 0 },
            ..Default::default()
        };
        let exec = ExecProcessRequest {
            container_id: CONTAINER.to_owned(),
            exec_id: exec_id.clone(),
            process: Some(process).into(),
            ..Default::default()
        };
        self.service
            .exec_process(context::Context::default(), &exec)
            .context("ExecProcess")?;
        let progress = Progress::default();
        thread::scope(|scope| {
            let stdout = scope.spawn(|| self.read(&exec_id, Stream::Stdout, &progress));
            let stderr = scope.spawn(|| self.read(&exec_id, Stream::Stderr, &progress));
            let stdin = scope.spawn(|| self.feed(&exec_id, run, &progress));
            let exit_status = self.wait(&exec_id);
            progress.update(|state| state.ended = true);
            let joined = |reader: thread::ScopedJoinHandle<'_, Result<Vec<u8>>>| {
                reader
                    .join()
                    .unwrap_or_else(|_| bail!("the reader's thread panicked"))
            };
            let outcome = exit_status.and_then(|exit_status| {
                Ok(Outcome {
                    exit_status,
                    stdout: joined(stdout).context("ReadStdout")?,
                    stderr: joined(stderr).context("ReadStderr")?,
                })
            });
            // Releasing the process closes its streams, which ends the stdin thread's writes; so
            // join it after.
            let released = self.release(&exec_id);
            let _ = stdin.join();
            released.and(outcome)
        })
    }

    /// Gives the run its standard input (see the `programs.json` format): failures to write are
    /// not the run's, which need not read it all.
    fn feed(&self, exec_id: &str, run: &Run, progress: &Progress) {
        if !run.script.is_empty() {
            self.play(exec_id, run, progress);
            return;
        }
        let input = if run.console_stdin {
            if !progress.wait_ready() {
                return;
            }
            &self.input
        } else {
            run.stdin.as_bytes()
        };
        if !input.is_empty() {
            let write = WriteStreamRequest {
                container_id: CONTAINER.to_owned(),
                exec_id: exec_id.to_owned(),
                data: input.to_vec(),
                ..Default::default()
            };
            let _ = self
                .service
                .write_stdin(context::Context::default(), &write);
        }
        if !run.console_stdin && !run.terminal {
            let close = CloseStdinRequest {
                container_id: CONTAINER.to_owned(),
                exec_id: exec_id.to_owned(),
                ..Default::default()
            };
            let _ = self
                .service
                .close_stdin(context::Context::default(), &close);
        }
    }

    /// Plays `run`'s `script` (see the `programs.json` format), until it ends or the run does; a
    /// terminal's input stays open.
    fn play(&self, exec_id: &str, run: &Run, progress: &Progress) {
        let mut from = 0;
        for step in &run.script {
            if !step.wait.is_empty() {
                let Some(after) = progress.wait_output(step.wait.as_bytes(), from) else {
                    return;
                };
                from = after;
            }
            if let Some([row, column]) = step.resize {
                let resize = TtyWinResizeRequest {
                    container_id: CONTAINER.to_owned(),
                    exec_id: exec_id.to_owned(),
                    row,
                    column,
                    ..Default::default()
                };
                let _ = self
                    .service
                    .tty_win_resize(context::Context::default(), &resize);
            }
            if !step.send.is_empty() {
                let write = WriteStreamRequest {
                    container_id: CONTAINER.to_owned(),
                    exec_id: exec_id.to_owned(),
                    data: step.send.as_bytes().to_vec(),
                    ..Default::default()
                };
                let _ = self
                    .service
                    .write_stdin(context::Context::default(), &write);
            }
        }
    }

    /// Reads `stream` until its end, copying it to the output; standard output also updates
    /// `progress`.
    fn read(&self, exec_id: &str, stream: Stream, progress: &Progress) -> Result<Vec<u8>> {
        let mut recorded = Vec::new();
        let mut ready = ReadyLine::default();
        let request = ReadStreamRequest {
            container_id: CONTAINER.to_owned(),
            exec_id: exec_id.to_owned(),
            len: READ_LEN,
            ..Default::default()
        };
        loop {
            let response = match stream {
                Stream::Stdout => self
                    .service
                    .read_stdout(context::Context::default(), &request)?,
                Stream::Stderr => self
                    .service
                    .read_stderr(context::Context::default(), &request)?,
            };
            if response.data.is_empty() {
                return Ok(recorded);
            }
            if let Some(output) = &self.output {
                let mut output = output.lock().unwrap_or_else(PoisonError::into_inner);
                output.write_all(&response.data)?;
                output.flush()?;
            }
            recorded.extend_from_slice(&response.data);
            if matches!(stream, Stream::Stdout) {
                let ready_now = ready.feed(&response.data);
                progress.update(|state| {
                    state.ready |= ready_now;
                    state.stdout.extend_from_slice(&response.data);
                });
            }
        }
    }

    /// The exit status of the process `exec_id`, once it exited.
    fn wait(&self, exec_id: &str) -> Result<ExitStatus> {
        let wait = WaitProcessRequest {
            container_id: CONTAINER.to_owned(),
            exec_id: exec_id.to_owned(),
            ..Default::default()
        };
        let response = self
            .service
            .wait_process(context::Context::default(), &wait)
            .context("WaitProcess")?;
        Ok(ExitStatus::reported(response.status, response.signal))
    }

    fn release(&self, exec_id: &str) -> Result<()> {
        let release = ReleaseProcessRequest {
            container_id: CONTAINER.to_owned(),
            exec_id: exec_id.to_owned(),
            ..Default::default()
        };
        self.service
            .release_process(context::Context::default(), &release)
            .context("ReleaseProcess")?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

/// Checks how `run` ended.
fn check(run: &Run, outcome: &Outcome) -> Result<()> {
    let expected = run.expected_exit_status();
    ensure!(
        outcome.exit_status == expected,
        "{}, expected {expected}",
        outcome.exit_status
    );
    for (what, expected, actual) in [
        ("stdout", &run.expect_stdout, &outcome.stdout),
        ("stderr", &run.expect_stderr, &outcome.stderr),
    ] {
        let Some(expected) = expected else {
            continue;
        };
        ensure!(
            expected.as_bytes() == actual.as_slice(),
            "{what} was {:?}, expected {expected:?}",
            String::from_utf8_lossy(actual)
        );
    }
    for expected in &run.expect_stdout_contains {
        ensure!(
            outcome
                .stdout
                .windows(expected.len())
                .any(|window| window == expected.as_bytes()),
            "stdout was {:?}, without {expected:?}",
            String::from_utf8_lossy(&outcome.stdout)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ReadyLine;

    #[test]
    fn a_ready_line_is_found_across_pieces() {
        let mut ready = ReadyLine::default();
        assert!(!ready.feed(b"not ready\nrea"));
        assert!(!ready.feed(b"dy"));
        assert!(ready.feed(b"\nmore"));
        assert!(ready.feed(b""));
        let mut terminal = ReadyLine::default();
        assert!(terminal.feed(b"ready\r\n"));
        for output in [&b"ready"[..], b"already\n", b"ready!\n", b"readyready\n"] {
            assert!(!ReadyLine::default().feed(output), "{output:?}");
        }
    }
}
