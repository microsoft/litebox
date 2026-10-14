// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test client for standalone programs: runs those of the payload's
//! `programs.json` in order, and checks how each ends. `programs.json` is an
//! array of runs:
//! - `argv`: `argv[0]` is the program's absolute path (e.g., in
//!   `rootfs.tar`).
//! - `envp`: `KEY=VALUE` strings (default none).
//! - `stdin`: the run's standard input, after which it ends (default: none,
//!   as `/dev/null`).
//! - `console_stdin`: default false; if true (without `stdin`), the run's
//!   standard input is the console's: what the host sends, when it sends it.
//!   It never ends, as a device cannot tell where input ends.
//! - `expect_exit_code` (default 0), or `expect_signal` for a signal death.
//! - `expect_stdout`, `expect_stderr`: the exact output, if given; output
//!   beyond what is recorded fails the check.
//! - `min_reflected_syscalls`: default 0; guest syscalls the runner did not
//!   take directly, so the kernel reflected them.
//!
//! Output also goes to the console, as it would without this client.

use crate::service::Service;
use crate::service::program::Programs;
use alloc::collections::VecDeque;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec::Vec;
use litebox_broker_core::stdio::StdioOutputStream;
use litebox_broker_vm_kernel::stdio::Console;
use litebox_common_vm_abi::program::{ExitStatus, Program};
use serde::Deserialize;
use spin::Mutex;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    argv: Vec<String>,
    #[serde(default)]
    envp: Vec<String>,
    #[serde(default)]
    stdin: String,
    #[serde(default)]
    console_stdin: bool,
    expect_exit_code: Option<u32>,
    expect_signal: Option<u32>,
    expect_stdout: Option<String>,
    expect_stderr: Option<String>,
    #[serde(default)]
    min_reflected_syscalls: u64,
}

/// Keeps at most this much of each stream per run; the console gets all.
const MAX_RECORDED: usize = 64 * 1024;

/// What a stream wrote, up to [`MAX_RECORDED`] bytes.
#[derive(Default)]
struct Recorded {
    bytes: Vec<u8>,
    /// The stream wrote more than `bytes`.
    truncated: bool,
}

/// A run's standard input.
enum Input {
    /// What is left of it, then its end.
    Given(VecDeque<u8>),
    /// The device's.
    Console,
}

/// The runs' [`Console`]: serves each run's standard input, and records what
/// each output stream wrote to `device`.
pub struct Stdio {
    device: &'static dyn Console,
    /// The current run's.
    input: Mutex<Input>,
    /// Standard output, then standard error.
    recorded: Mutex<[Recorded; 2]>,
}

impl Stdio {
    pub fn new(device: &'static dyn Console) -> Self {
        Self {
            device,
            input: Mutex::new(Input::Given(VecDeque::new())),
            recorded: Mutex::new(Default::default()),
        }
    }

    /// Standard output and standard error since the last call.
    fn take(&self) -> [Recorded; 2] {
        core::mem::take(&mut *self.recorded.lock())
    }
}

impl Console for Stdio {
    fn read(&self, output: &mut [u8]) -> Option<usize> {
        let mut input = self.input.lock();
        let input = match &mut *input {
            Input::Given(input) => input,
            Input::Console => return self.device.read(output),
        };
        if input.is_empty() {
            return None;
        }
        let len = output.len().min(input.len());
        for (byte, input) in output.iter_mut().zip(input.drain(..len)) {
            *byte = input;
        }
        Some(len)
    }

    /// Given input, or its end, never waits.
    fn has_input(&self) -> bool {
        match *self.input.lock() {
            Input::Given(_) => true,
            Input::Console => self.device.has_input(),
        }
    }

    /// Records what the device took.
    fn write(&self, stream: StdioOutputStream, input: &[u8]) -> usize {
        let written = self.device.write(stream, input);
        let index = match stream {
            StdioOutputStream::Stdout => 0,
            StdioOutputStream::Stderr => 1,
        };
        let recorded = &mut self.recorded.lock()[index];
        let room = MAX_RECORDED.saturating_sub(recorded.bytes.len());
        let kept = written.min(room);
        recorded.bytes.extend_from_slice(&input[..kept]);
        recorded.truncated |= kept < written;
        written
    }
}

/// # Panics
///
/// On a malformed `programs.json`, or any unexpected end of a run.
pub fn run(json: &[u8], service: &mut Programs, stdio: &Stdio) {
    let runs: Vec<Run> = serde_json::from_slice(json).expect("malformed programs.json");
    assert!(!runs.is_empty(), "programs.json has no runs");
    let strings = |strings: Vec<String>| {
        strings
            .into_iter()
            .map(|string| CString::new(string).expect("programs.json strings have no NUL"))
            .collect::<Vec<_>>()
    };
    for (index, run) in runs.into_iter().enumerate() {
        let path = run.argv.first().expect("a run has an argv").clone();
        litebox_util_log::info!(index:% = index, path:% = path; "running");
        let expected = match (run.expect_exit_code, run.expect_signal) {
            (code, None) => ExitStatus::Exited {
                code: code.unwrap_or(0),
            },
            (None, Some(signal)) => ExitStatus::Signaled { signal },
            (Some(_), Some(_)) => {
                panic!("run {index}: `expect_exit_code` and `expect_signal` exclude each other")
            }
        };
        assert!(
            !run.console_stdin || run.stdin.is_empty(),
            "run {index}: `stdin` and `console_stdin` exclude each other"
        );
        stdio.take();
        *stdio.input.lock() = if run.console_stdin {
            Input::Console
        } else {
            Input::Given(run.stdin.into_bytes().into())
        };
        let reply = service.call(Program {
            path: path.clone(),
            argv: strings(run.argv),
            envp: strings(run.envp),
        });
        let [stdout, stderr] = stdio.take();
        let status = reply
            .status
            .unwrap_or_else(|error| panic!("run {index} ({path}) did not run: {error:?}"));
        assert_eq!(status, expected, "run {index} ({path}): exit status");
        for (what, expected, actual) in [
            ("stdout", run.expect_stdout, stdout),
            ("stderr", run.expect_stderr, stderr),
        ] {
            if let Some(expected) = expected {
                assert!(
                    !actual.truncated,
                    "run {index} ({path}): {what} exceeded the {MAX_RECORDED} bytes recorded, \
                     so it cannot be checked exactly"
                );
                assert!(
                    expected.as_bytes() == actual.bytes,
                    "run {index} ({path}): {what} was {:?}, expected {expected:?}",
                    String::from_utf8_lossy(&actual.bytes)
                );
            }
        }
        assert!(
            reply.reflected_syscalls >= run.min_reflected_syscalls,
            "run {index} ({path}): {} reflected syscalls, expected at least {}",
            reply.reflected_syscalls,
            run.min_reflected_syscalls
        );
        litebox_util_log::info!(
            index:% = index,
            status:? = status,
            reflected_syscalls:% = reply.reflected_syscalls;
            "run passed"
        );
    }
}
