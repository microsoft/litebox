// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test client for [`Linux`]: runs the payload's `linux.json` in order and
//! checks how each program ends. `linux.json` is an array of steps: a run, or
//! an array of runs to run concurrently. A run:
//! - `argv`: `argv[0]` is the program's absolute path in `rootfs.tar`.
//! - `envp`: default empty.
//! - `time_limit_ms`: kills the process this long after it first runs.
//! - `expect_exit_code`: default 0; `expect_signal` instead for a signal
//!   death, `expect_killed` for the kernel's reason to kill the process, or
//!   `expect_runner_failure: true` for the runner's own failure.
//! - `expect_stdout`, `expect_stderr`: exact output, if given; alone only, as
//!   concurrent runs share the streams.
//! - `min_reflected_syscalls`: default 0; syscalls the shim did not patch, so
//!   the kernel reflected them.
//! - `min_preemptions`: default 0; times the timer took the CPU from the
//!   process.

use crate::payload::Payload;
use crate::service::Service;
use crate::service::linux::{Failure, Linux, Outcome, Program, Request};
use alloc::string::String;
use alloc::vec::Vec;
use litebox_broker_protocol::process::ProcessExitStatus;
use litebox_common_linux::vm_userland::RUNNER_FAILURE;
use litebox_shim_vm_kernel::Dead;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(untagged)]
enum Step {
    Alone(Run),
    Concurrent(Vec<Run>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    argv: Vec<String>,
    #[serde(default)]
    envp: Vec<String>,
    time_limit_ms: Option<u64>,
    expect_exit_code: Option<u32>,
    expect_signal: Option<u32>,
    expect_killed: Option<String>,
    #[serde(default)]
    expect_runner_failure: bool,
    expect_stdout: Option<String>,
    expect_stderr: Option<String>,
    #[serde(default)]
    min_reflected_syscalls: u64,
    #[serde(default)]
    min_preemptions: u64,
}

/// How a run should end.
#[derive(Debug, PartialEq, Eq)]
enum Ending {
    Status(ProcessExitStatus),
    Killed(String),
    RunnerFailed,
}

impl Run {
    fn expected(&self, what: &str) -> Ending {
        match (
            self.expect_exit_code,
            self.expect_signal,
            &self.expect_killed,
            self.expect_runner_failure,
        ) {
            (code, None, None, false) => Ending::Status(ProcessExitStatus::Exited {
                code: code.unwrap_or(0),
            }),
            (None, Some(signal), None, false) => {
                Ending::Status(ProcessExitStatus::Signaled { signal })
            }
            (None, None, Some(reason), false) => Ending::Killed(reason.clone()),
            (None, None, None, true) => Ending::RunnerFailed,
            _ => panic!(
                "{what}: `expect_exit_code`, `expect_signal`, `expect_killed`, and \
                 `expect_runner_failure` exclude each other"
            ),
        }
    }
}

/// # Panics
///
/// On any failure, including an unexpected end of a program.
pub fn run(payload: &Payload, service: &mut Linux) {
    let json = payload
        .file("linux.json")
        .expect("payload has no linux.json");
    let steps: Vec<Step> = serde_json::from_slice(json).expect("malformed linux.json");
    assert!(!steps.is_empty(), "linux.json has no steps");
    for (index, step) in steps.into_iter().enumerate() {
        let (runs, alone) = match step {
            Step::Alone(run) => (alloc::vec![run], true),
            Step::Concurrent(runs) => (runs, false),
        };
        let names: Vec<String> = runs
            .iter()
            .enumerate()
            .map(|(i, run)| {
                let program = run.argv.first().map_or("", String::as_str);
                if alone {
                    alloc::format!("step {index} ({program})")
                } else {
                    alloc::format!("step {index}, run {i} ({program})")
                }
            })
            .collect();
        for (run, name) in runs.iter().zip(&names) {
            assert!(
                alone || (run.expect_stdout.is_none() && run.expect_stderr.is_none()),
                "{name}: concurrent runs share the standard streams"
            );
            litebox_util_log::info!(name:% = name; "running");
        }
        let reply = service.call(Request {
            programs: runs
                .iter()
                .map(|run| Program {
                    argv: run.argv.clone(),
                    envp: run.envp.clone(),
                    time_limit: run.time_limit_ms.map(core::time::Duration::from_millis),
                })
                .collect(),
        });
        for ((run, name), outcome) in runs.iter().zip(&names).zip(&reply.outcomes) {
            check(run, name, outcome);
        }
        if alone {
            let check_stream = |what, expected: &Option<String>, actual: &[u8]| {
                if let Some(expected) = expected {
                    assert!(
                        expected.as_bytes() == actual,
                        "{}: {what} was {:?}, expected {expected:?}",
                        names[0],
                        String::from_utf8_lossy(actual)
                    );
                }
            };
            check_stream("stdout", &runs[0].expect_stdout, &reply.stdout);
            check_stream("stderr", &runs[0].expect_stderr, &reply.stderr);
        }
    }
}

fn check(run: &Run, name: &str, outcome: &Outcome) {
    let ending = match &outcome.status {
        Ok(status) => Ending::Status(*status),
        Err(Failure::Runner(Dead::Killed(reason))) => Ending::Killed((*reason).into()),
        Err(Failure::Runner(Dead::Exited(RUNNER_FAILURE))) => Ending::RunnerFailed,
        Err(failure) => panic!("{name}: {failure}"),
    };
    assert_eq!(ending, run.expected(name), "{name}: ending");
    assert!(
        outcome.reflected_syscalls >= run.min_reflected_syscalls,
        "{name}: {} reflected syscalls, expected at least {}",
        outcome.reflected_syscalls,
        run.min_reflected_syscalls
    );
    assert!(
        outcome.preemptions >= run.min_preemptions,
        "{name}: {} preemptions, expected at least {}",
        outcome.preemptions,
        run.min_preemptions
    );
    litebox_util_log::info!(
        name:% = name,
        ending:? = ending,
        reflected_syscalls:% = outcome.reflected_syscalls,
        preemptions:% = outcome.preemptions;
        "run passed"
    );
}
