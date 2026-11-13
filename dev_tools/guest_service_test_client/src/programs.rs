// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `programs.json`: the runs of a test, in order, and how each must end. It is an array of
//! entries: a run, or a `{ "concurrent": [...] }` group of runs started together. A run:
//! - `argv`: `argv[0]` is the program's absolute path in the sandbox's root file system.
//! - `envp`: `KEY=VALUE` strings (default none).
//! - `stdin`: the run's standard input, after which it ends (default: none, so it ends at once).
//! - `console_stdin`: default false; if true (without `stdin`), the run's standard input is the
//!   test's input (the client's `--input`), sent once the run's standard output shows a line
//!   `ready`; it does not end while the run runs.
//! - `terminal`: default false; if true, the run's standard streams are a terminal of
//!   [`TERMINAL_ROWS`] by [`TERMINAL_COLUMNS`], its controlling terminal: its standard error is
//!   in `expect_stdout`, with the terminal's output processing (e.g., `\n` as `\r\n`), and
//!   `expect_stderr` is empty. Its input does not end while it runs: an end would hang the
//!   terminal up.
//! - `expect_exit_code` (default 0), or `expect_signal` for a signal death.
//! - `expect_stdout`, `expect_stderr`: the exact output, if given.
//! - `expect_stdout_records`: `[writers, records]`, if given: standard output is records of
//!   [`RECORD_SIZE`] bytes, each `w<writer> <seq>` padded with spaces and ended by a newline, and
//!   nothing else: each writer's (numbered from 0) `records` records (numbered from 0), whole and
//!   in order; writers' records may interleave.
//! - `min_reflected_syscalls`: default 0; guest syscalls that the VM kernel reflected to the
//!   runner, as the runner did not take them directly.
//! - `replay`: default false; in debug builds of the VM kernel, every process gives up on its
//!   claim at its first kernel entry of each kind, as if another CPU held it, and each must then
//!   be handled once, by its replay (see `litebox_shim_vm_kernel::ProcessConfig::give_up_once`):
//!   so the program must also make a syscall that the kernel reflects, raise an exception, and
//!   take an interrupt (e.g., a timer's). Release builds ignore it.
//!
//! Only the VM kernel can check the last two, from its log: this client only lists the entries
//! that have them ([`Entry::counts`]), for the test harness to run each in a boot of its own.
//!
//! In a group, runs take no `stdin`, `expect_stdout`, `expect_stderr`, or `expect_stdout_records`,
//! and at most one takes `console_stdin`.

use anyhow::{Result, bail, ensure};
use serde::Deserialize;

/// The size of a `terminal` run's terminal.
pub const TERMINAL_ROWS: u32 = 24;
pub const TERMINAL_COLUMNS: u32 = 80;

/// See `expect_stdout_records` in the [module](self) docs.
pub const RECORD_SIZE: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Entry {
    Run(Run),
    Concurrent(Concurrent),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Concurrent {
    concurrent: Vec<Run>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub argv: Vec<String>,
    #[serde(default)]
    pub envp: Vec<String>,
    #[serde(default)]
    pub stdin: String,
    #[serde(default)]
    pub console_stdin: bool,
    #[serde(default)]
    pub terminal: bool,
    expect_exit_code: Option<u32>,
    expect_signal: Option<u32>,
    pub expect_stdout: Option<String>,
    pub expect_stderr: Option<String>,
    pub expect_stdout_records: Option<[usize; 2]>,
    #[serde(default)]
    min_reflected_syscalls: u64,
    #[serde(default)]
    replay: bool,
}

/// What the VM kernel checks of an entry's processes (see the [module](self) docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// The most of its runs' `min_reflected_syscalls`.
    pub min_reflected_syscalls: u64,
    /// Whether a run has `replay`.
    pub replay: bool,
}

/// How a process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// With an exit code.
    Exited { code: u32 },
    /// By a signal.
    Signaled { signal: u32 },
}

impl ExitStatus {
    /// As `WaitProcess` reports it: by `signal`, unless 0; otherwise, with `status`.
    pub fn reported(status: i32, signal: i32) -> Self {
        if signal == 0 {
            Self::Exited {
                code: status.cast_unsigned(),
            }
        } else {
            Self::Signaled {
                signal: signal.cast_unsigned(),
            }
        }
    }
}

impl core::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Exited { code } => write!(f, "exited with {code}"),
            Self::Signaled { signal } => write!(f, "killed by signal {signal}"),
        }
    }
}

impl Run {
    /// How the run must end.
    pub fn expected_exit_status(&self) -> ExitStatus {
        match (self.expect_exit_code, self.expect_signal) {
            (code, None) => ExitStatus::Exited {
                code: code.unwrap_or(0),
            },
            (None, Some(signal)) => ExitStatus::Signaled { signal },
            (Some(_), Some(_)) => unreachable!("`parse` rejects runs with both"),
        }
    }

    fn check(&self, index: usize) -> Result<()> {
        ensure!(!self.argv.is_empty(), "run {index}: no argv");
        ensure!(
            self.expect_exit_code.is_none() || self.expect_signal.is_none(),
            "run {index}: `expect_exit_code` and `expect_signal` exclude each other"
        );
        ensure!(
            !self.console_stdin || self.stdin.is_empty(),
            "run {index}: `stdin` and `console_stdin` exclude each other"
        );
        ensure!(
            !self.terminal || self.stdin.is_empty(),
            "run {index}: a terminal's input is `console_stdin`'s: its end would hang it up"
        );
        Ok(())
    }
}

impl Entry {
    /// Its runs, in order.
    pub fn runs(&self) -> &[Run] {
        match self {
            Self::Run(run) => core::slice::from_ref(run),
            Self::Concurrent(Concurrent { concurrent }) => concurrent,
        }
    }

    /// What the VM kernel checks of its processes, if anything.
    pub fn counts(&self) -> Option<Counts> {
        let runs = self.runs();
        let counts = Counts {
            min_reflected_syscalls: runs
                .iter()
                .map(|run| run.min_reflected_syscalls)
                .max()
                .unwrap_or(0),
            replay: runs.iter().any(|run| run.replay),
        };
        (counts.min_reflected_syscalls > 0 || counts.replay).then_some(counts)
    }
}

/// The entries of `json`, a `programs.json`, checked.
pub fn parse(json: &[u8]) -> Result<Vec<Entry>> {
    let entries: Vec<Entry> = serde_json::from_slice(json)?;
    ensure!(!entries.is_empty(), "no runs");
    let mut index = 0;
    for entry in &entries {
        if let Entry::Concurrent(Concurrent { concurrent }) = entry {
            ensure!(!concurrent.is_empty(), "runs {index}..: an empty group");
            if concurrent.iter().any(|run| {
                !run.stdin.is_empty()
                    || run.expect_stdout.is_some()
                    || run.expect_stderr.is_some()
                    || run.expect_stdout_records.is_some()
            }) || concurrent.iter().filter(|run| run.console_stdin).count() > 1
            {
                bail!(
                    "runs {index}..: concurrent runs take no `stdin`, `expect_stdout`, \
                     `expect_stderr`, or `expect_stdout_records`, and at most one `console_stdin`"
                );
            }
        }
        for run in entry.runs() {
            run.check(index)?;
            index += 1;
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::{Counts, Entry, parse};

    #[test]
    fn malformed_runs_are_rejected() {
        for json in [
            &br"[]"[..],
            br#"[{ "argv": [] }]"#,
            br#"[{ "argv": ["/a"], "unknown": 1 }]"#,
            br#"[{ "argv": ["/a"], "expect_exit_code": 1, "expect_signal": 9 }]"#,
            br#"[{ "argv": ["/a"], "stdin": "x", "console_stdin": true }]"#,
            br#"[{ "argv": ["/a"], "stdin": "x", "terminal": true }]"#,
            br#"[{ "concurrent": [{ "argv": ["/a"], "expect_stdout": "" }] }]"#,
            br#"[{ "concurrent": [{ "argv": ["/a"], "expect_stdout_records": [1, 1] }] }]"#,
            br#"[{ "concurrent": [
                { "argv": ["/a"], "console_stdin": true },
                { "argv": ["/b"], "console_stdin": true }
            ] }]"#,
        ] {
            assert!(parse(json).is_err(), "{}", String::from_utf8_lossy(json));
        }
    }

    #[test]
    fn entries_with_kernel_checks_list_their_counts() {
        let entries = parse(
            br#"[
                { "argv": ["/a"] },
                { "argv": ["/b"], "min_reflected_syscalls": 3 },
                { "concurrent": [
                    { "argv": ["/c"], "min_reflected_syscalls": 1, "replay": true },
                    { "argv": ["/d"], "min_reflected_syscalls": 4 }
                ] }
            ]"#,
        )
        .unwrap();
        let counts: Vec<Option<Counts>> = entries.iter().map(Entry::counts).collect();
        assert_eq!(
            counts,
            [
                None,
                Some(Counts {
                    min_reflected_syscalls: 3,
                    replay: false
                }),
                Some(Counts {
                    min_reflected_syscalls: 4,
                    replay: true
                }),
            ]
        );
    }
}
