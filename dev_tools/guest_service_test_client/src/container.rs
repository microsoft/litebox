// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs `programs.json` entries in the guest service's container, and checks how each run ended.

use std::fs::File;
use std::io::Write as _;
use std::sync::{Condvar, Mutex, PoisonError};
use std::thread;

use anyhow::{Context as _, Result, bail, ensure};
use litebox_guest_service_protocol::guest_service::{
    CloseStdinRequest, CreateContainerRequest, Empty, ExecProcessRequest, Process,
    ReadStreamRequest, ReleaseProcessRequest, SignalProcessRequest, WaitProcessRequest,
    WriteStreamRequest,
};
use litebox_guest_service_protocol::guest_service_ttrpc::GuestServiceClient;
use ttrpc::context;

use crate::programs::{Entry, ExitStatus, RECORD_SIZE, Run, TERMINAL_COLUMNS, TERMINAL_ROWS};

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

/// Whether a run's standard output showed `ready`, or the run ended.
#[derive(Default)]
struct Progress {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Progress {
    fn update(&self, update: impl FnOnce(&mut (bool, bool))) {
        update(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner));
        self.changed.notify_all();
    }

    /// Waits until the run is ready or ended; true if ready.
    fn wait_ready(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let state = self
            .changed
            .wait_while(state, |(ready, ended)| !*ready && !*ended)
            .unwrap_or_else(PoisonError::into_inner);
        state.0
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
            process: Some(process).into(),
            ..Default::default()
        };
        service
            .create_container(context::Context::default(), &create)
            .context("CreateContainer")?;
        service
            .start_container(context::Context::default(), &Empty::new())
            .context("StartContainer")?;
        let close = CloseStdinRequest {
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

    /// Runs `entry`, whose first run is run `first`, and checks how its runs ended.
    pub fn run_entry(&self, first: usize, entry: &Entry) -> Result<()> {
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
            let path = &run.argv[0];
            match outcome.and_then(|outcome| check(run, &outcome)) {
                Ok(()) => println!("PASS  run {index} ({path})"),
                Err(error) => {
                    println!("FAIL  run {index} ({path}): {error:#}");
                    failures.push(index);
                }
            }
        }
        ensure!(failures.is_empty(), "runs {failures:?} failed");
        Ok(())
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
            progress.update(|(_, ended)| *ended = true);
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
                exec_id: exec_id.to_owned(),
                ..Default::default()
            };
            let _ = self
                .service
                .close_stdin(context::Context::default(), &close);
        }
    }

    /// Reads `stream` until its end, copying it to the output; standard output also updates
    /// `progress`.
    fn read(&self, exec_id: &str, stream: Stream, progress: &Progress) -> Result<Vec<u8>> {
        let mut recorded = Vec::new();
        let mut ready = ReadyLine::default();
        let request = ReadStreamRequest {
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
            if matches!(stream, Stream::Stdout) && ready.feed(&response.data) {
                progress.update(|(ready, _)| *ready = true);
            }
        }
    }

    /// The exit status of the process `exec_id`, once it exited.
    fn wait(&self, exec_id: &str) -> Result<ExitStatus> {
        let wait = WaitProcessRequest {
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
    if let Some(expected) = run.expect_stdout_records {
        check_records(&outcome.stdout, expected)?;
    }
    Ok(())
}

/// Checks that `stdout` is `writers` writers' `records` records each (see
/// `expect_stdout_records` in the [`programs`](crate::programs) docs).
fn check_records(stdout: &[u8], [writers, records]: [usize; 2]) -> Result<()> {
    let mut next = vec![0; writers];
    for (at, record) in stdout.chunks(RECORD_SIZE).enumerate() {
        let writer = (0..writers).find(|&writer| {
            let expected = format!("w{writer} {}", next[writer]);
            record == format!("{expected:<width$}\n", width = RECORD_SIZE - 1).as_bytes()
        });
        let Some(writer) = writer else {
            bail!(
                "stdout's record {at} was {:?}, no writer's next",
                String::from_utf8_lossy(record)
            );
        };
        next[writer] += 1;
    }
    ensure!(
        next.iter().all(|&written| written == records),
        "stdout had {next:?} records per writer, expected {records}"
    );
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
