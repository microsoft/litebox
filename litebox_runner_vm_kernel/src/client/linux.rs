// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test client for [`Linux`]: runs the programs of the payload's `linux.json`
//! in order and checks how each ends. `linux.json` is an array of runs:
//! - `argv`: `argv[0]` is the program's absolute path in `rootfs.tar`.
//! - `envp`: default empty.
//! - `expect_exit_code`: default 0; `expect_signal` instead for a signal
//!   death.
//! - `expect_stdout`, `expect_stderr`: exact output, if given.
//! - `min_reflected_syscalls`: default 0; syscalls the shim did not patch, so
//!   the kernel reflected them.

use crate::payload::Payload;
use crate::service::Service;
use crate::service::linux::{Linux, Request};
use alloc::string::String;
use alloc::vec::Vec;
use litebox_broker_protocol::process::ProcessExitStatus;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    argv: Vec<String>,
    #[serde(default)]
    envp: Vec<String>,
    expect_exit_code: Option<u32>,
    expect_signal: Option<u32>,
    expect_stdout: Option<String>,
    expect_stderr: Option<String>,
    #[serde(default)]
    min_reflected_syscalls: u64,
}

/// # Panics
///
/// On any failure, including an unexpected end of a program.
pub fn run(payload: &Payload, service: &mut Linux) {
    let json = payload
        .file("linux.json")
        .expect("payload has no linux.json");
    let runs: Vec<Run> = serde_json::from_slice(json).expect("malformed linux.json");
    assert!(!runs.is_empty(), "linux.json has no runs");
    for (index, run) in runs.into_iter().enumerate() {
        let program = run.argv.first().cloned().unwrap_or_default();
        litebox_util_log::info!(index:% = index, program:% = program; "running");
        let reply = service.call(Request {
            argv: run.argv,
            envp: run.envp,
        });
        let status = reply
            .status
            .unwrap_or_else(|failure| panic!("run {index} ({program}): {failure}"));
        let expected = match (run.expect_exit_code, run.expect_signal) {
            (None, Some(signal)) => ProcessExitStatus::Signaled { signal },
            (code, None) => ProcessExitStatus::Exited {
                code: code.unwrap_or(0),
            },
            (Some(_), Some(_)) => {
                panic!("run {index}: `expect_exit_code` and `expect_signal` exclude each other")
            }
        };
        assert_eq!(status, expected, "run {index} ({program}): status");
        let check = |what, expected: Option<String>, actual: &[u8]| {
            if let Some(expected) = expected {
                assert!(
                    expected.as_bytes() == actual,
                    "run {index} ({program}): {what} was {:?}, expected {expected:?}",
                    String::from_utf8_lossy(actual)
                );
            }
        };
        check("stdout", run.expect_stdout, &reply.stdout);
        check("stderr", run.expect_stderr, &reply.stderr);
        assert!(
            reply.reflected_syscalls >= run.min_reflected_syscalls,
            "run {index} ({program}): {} reflected syscalls, expected at least {}",
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
