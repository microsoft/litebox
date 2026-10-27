// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test client for standalone programs: runs those of the payload's
//! `programs.json` in order, and checks how each ends. `programs.json` is an
//! array of runs, or of `{ "concurrent": [...] }` groups of runs started
//! together. A run:
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
//! - `expect_stdout_records`: `[writers, records]`, if given: standard output
//!   is records of 256 bytes, each `w<writer> <seq>` padded with spaces and
//!   ended by a newline, and nothing else: each writer's (numbered from 0)
//!   `records` records (numbered from 0), whole and in order; writers' records
//!   may interleave.
//! - `min_reflected_syscalls`: default 0; guest syscalls the runner did not
//!   take directly, so the kernel reflected them.
//! - `replay`: default false; in debug builds, the run's process gives up on
//!   its claim at its first kernel entry of each kind, as if another CPU held
//!   it, and each must then be handled once, by its replay (see
//!   `litebox_shim_vm_kernel::ProcessConfig::give_up_once`): so the program
//!   must also make a syscall that the kernel reflects, raise an exception,
//!   and take an interrupt (e.g., a timer's). In a group, every run's process
//!   does if one has it. Release builds ignore it.
//! - `expect_killed`: default false; the kernel killed the run's process,
//!   instead of an exit status.
//!
//! Debug hooks, for tests of broker threads (flags default to false); release
//! builds skip a run with any. In a group, those but the process hooks apply
//! to every run:
//! - `gate`: `read`, `handshake`, `adopt`, or `transmitted`: the broker's gate
//!   holds the next broker thread to reach that point.
//! - `hold_starts`: the kernel starts no launched process until a step
//!   releases them.
//! - `fail_adoption`, `slow_serves`: process hooks (see
//!   `litebox_shim_vm_kernel::Hooks`).
//! - `stack_failure`: `root`, `spawn`, `after_association`, or `clone`: a
//!   broker stack the run's process does not get: its own, whose spawn fails,
//!   and is made again; or as `litebox_shim_vm_kernel::StackFailure` says.
//! - `broker_slice_us`: broker threads' slices last at most that many
//!   microseconds, with no grace.
//! - `hold_retake`: `handshake`, `futex`, `preempted_futex`, or
//!   `preempted_futex_ran`: the next handoff of that case is held.
//! - `post_as_finished`: the next broker thread to finish bound has its inbox
//!   posted to then. It and `hold_retake` must have acted by the end of the
//!   run's group.
//! - `lose_share_response`: the next share request loses its response, and
//!   times out. Without it, no share request may time out in the group.
//! - `keep_reaped`: the processes reaped from then on are dropped only past
//!   the broker's shutdown: so no later run may check what they left behind.
//! - `script`: steps (see [`Step`]) taken in turn from the run's process's
//!   start, between the scheduler's steps. The run fails if its group ends
//!   first.
//!
//! In a group, runs share standard input and output, so they take no
//! `stdin`, `expect_stdout`, `expect_stderr`, or `expect_stdout_records`, and
//! at most one takes `console_stdin`.
//!
//! Debug builds also check that each entry's processes, once they all ended,
//! left nothing behind in the kernel (see [`Programs::check_released`]).
//!
//! Output also goes to the console, as it would without this client.

use crate::devices::Devices;
#[cfg(debug_assertions)]
use crate::service::program::RunHooks;
use crate::service::program::{Programs, Reply};
use alloc::collections::VecDeque;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec::Vec;
use litebox_broker_core::stdio::StdioOutputStream;
#[cfg(debug_assertions)]
use litebox_broker_vm_kernel::gate::Point;
use litebox_broker_vm_kernel::stdio::Console;
use litebox_common_vm_abi::program::{ExitStatus, Program};
use litebox_platform_vm_kernel::preempt::KernelMutex;
use litebox_shim_vm_kernel::Dead;
#[cfg(debug_assertions)]
use litebox_shim_vm_kernel::Process;
use litebox_shim_vm_kernel::program::RunError;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(untagged)]
enum Entry {
    Run(Run),
    Concurrent(Concurrent),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Concurrent {
    concurrent: Vec<Run>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent flags of programs.json's runs"
)]
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
    expect_stdout_records: Option<[usize; 2]>,
    #[serde(default)]
    min_reflected_syscalls: u64,
    #[serde(default)]
    #[cfg_attr(
        not(debug_assertions),
        expect(dead_code, reason = "release builds ignore it")
    )]
    replay: bool,
    #[serde(default)]
    expect_killed: bool,
    gate: Option<GatePoint>,
    #[serde(default)]
    hold_starts: bool,
    #[serde(default)]
    fail_adoption: bool,
    #[serde(default)]
    slow_serves: bool,
    stack_failure: Option<StackFailure>,
    broker_slice_us: Option<u64>,
    hold_retake: Option<RetakeCase>,
    #[serde(default)]
    post_as_finished: bool,
    #[serde(default)]
    lose_share_response: bool,
    #[serde(default)]
    keep_reaped: bool,
    #[serde(default)]
    script: Vec<Step>,
}

impl Run {
    /// Whether it uses debug hooks, which release builds lack.
    fn has_hooks(&self) -> bool {
        self.gate.is_some()
            || self.hold_starts
            || self.fail_adoption
            || self.slow_serves
            || self.stack_failure.is_some()
            || self.broker_slice_us.is_some()
            || self.hold_retake.is_some()
            || self.post_as_finished
            || self.lose_share_response
            || self.keep_reaped
            || !self.script.is_empty()
    }
}

/// Where the broker's gate holds a broker thread.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GatePoint {
    Read,
    Handshake,
    Adopt,
    Transmitted,
}

/// A broker stack that a run's process does not get.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StackFailure {
    Root,
    Spawn,
    AfterAssociation,
    Clone,
}

/// A handoff that a run's `hold_retake` holds.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RetakeCase {
    Handshake,
    Futex,
    PreemptedFutex,
    PreemptedFutexRan,
}

/// A step of a run's `script`: a condition to wait for, or an action.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    /// The broker's gate holds a broker thread.
    Held,
    /// A broker thread sleeps for a lock.
    LockSleeper,
    /// The gate releases the broker thread it holds.
    Release,
    /// The broker thread the gate releases next moves to another CPU.
    Migrate,
    /// Kills the run's process.
    Kill,
    /// The kernel holds the start of a launched process.
    StartHeld,
    /// The kernel starts the launched processes again.
    ReleaseStarts,
}

/// Keeps at most this much of each stream per run; the console gets all.
const MAX_RECORDED: usize = 1024 * 1024;

/// See `expect_stdout_records` in the [module](self) docs.
const RECORD_SIZE: usize = 256;

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
/// each output stream wrote to `device`. Its locks are kernel-grade, as the
/// devices' are (see [`Devices`]).
pub struct Stdio {
    device: &'static Devices,
    /// The current run's.
    input: KernelMutex<Input>,
    /// Standard output, then standard error.
    recorded: KernelMutex<[Recorded; 2]>,
}

impl Stdio {
    pub fn new(device: &'static Devices) -> Self {
        Self {
            device,
            input: KernelMutex::new(Input::Given(VecDeque::new())),
            recorded: KernelMutex::new(Default::default()),
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

    fn can_write(&self) -> bool {
        self.device.can_write()
    }

    fn interrupts(&self) -> bool {
        self.device.interrupts()
    }
}

/// # Panics
///
/// On a malformed `programs.json`, or any unexpected end of a run.
pub fn run(json: &[u8], service: &mut Programs, stdio: &Stdio) {
    let entries: Vec<Entry> = serde_json::from_slice(json).expect("malformed programs.json");
    assert!(!entries.is_empty(), "programs.json has no runs");
    let mut index = 0;
    let last = entries.len() - 1;
    for (at, entry) in entries.into_iter().enumerate() {
        let runs = match &entry {
            Entry::Run(run) => core::slice::from_ref(run),
            Entry::Concurrent(Concurrent { concurrent }) => concurrent.as_slice(),
        };
        assert!(
            at == last || !runs.iter().any(|run| run.keep_reaped),
            "runs {index}..: `keep_reaped` is for the last entry only"
        );
        match entry {
            Entry::Run(run) if !cfg!(debug_assertions) && run.has_hooks() => {
                litebox_util_log::info!(index:% = index; "skipped: debug hooks");
                index += 1;
            }
            Entry::Run(run) => {
                run_group(index, alloc::vec![run], service, stdio);
                index += 1;
            }
            Entry::Concurrent(Concurrent { concurrent }) => {
                assert!(
                    concurrent.iter().all(|run| run.stdin.is_empty()
                        && run.expect_stdout.is_none()
                        && run.expect_stderr.is_none()
                        && run.expect_stdout_records.is_none())
                        && concurrent.iter().filter(|run| run.console_stdin).count() <= 1,
                    "runs {index}..: concurrent runs share standard streams, so they take no \
                     `stdin`, `expect_stdout`, `expect_stderr`, or `expect_stdout_records`, and \
                     at most one `console_stdin`"
                );
                let len = concurrent.len();
                if !cfg!(debug_assertions) && concurrent.iter().any(Run::has_hooks) {
                    litebox_util_log::info!(index:% = index; "skipped: debug hooks");
                } else {
                    run_group(index, concurrent, service, stdio);
                }
                index += len;
            }
        }
    }
}

/// Runs `runs`, numbered from `first`, at once, and checks each.
fn run_group(first: usize, runs: Vec<Run>, service: &mut Programs, stdio: &Stdio) {
    let strings = |strings: &[String]| {
        strings
            .iter()
            .map(|string| CString::new(string.as_str()).expect("programs.json strings have no NUL"))
            .collect::<Vec<_>>()
    };
    let programs: Vec<Program> = (first..)
        .zip(&runs)
        .map(|(index, run)| {
            let path = run.argv.first().expect("a run has an argv").clone();
            litebox_util_log::info!(index:% = index, path:% = path; "running");
            Program {
                path,
                argv: strings(&run.argv),
                envp: strings(&run.envp),
            }
        })
        .collect();
    for (index, run) in (first..).zip(&runs) {
        assert!(
            !run.console_stdin || run.stdin.is_empty(),
            "run {index}: `stdin` and `console_stdin` exclude each other"
        );
    }
    stdio.take();
    // Only a lone run has input.
    *stdio.input.lock() = if runs.iter().any(|run| run.console_stdin) {
        Input::Console
    } else {
        Input::Given(runs.iter().flat_map(|run| run.stdin.bytes()).collect())
    };
    #[cfg(debug_assertions)]
    if runs.iter().any(|run| run.replay) {
        service.give_up_once();
    }
    #[cfg(debug_assertions)]
    let mut scripts = set_hooks(&runs, service, stdio.device);
    #[cfg(debug_assertions)]
    let share_timeouts = stdio.device.share_timeouts();
    let replies = service.run_concurrently(
        &programs,
        #[cfg(debug_assertions)]
        |index, process| scripts[index].advance(process, stdio.device),
    );
    #[cfg(debug_assertions)]
    {
        clear_hooks(first, &runs, service, stdio.device);
        let lost = runs.iter().any(|run| run.lose_share_response);
        assert_eq!(
            stdio.device.share_timeouts() - share_timeouts,
            u64::from(lost),
            "runs {first}..: share requests that timed out"
        );
        for ((index, run), script) in (first..).zip(&runs).zip(&scripts) {
            assert!(
                script.next == run.script.len(),
                "run {index}: its group ended before its script's step {:?}",
                run.script[script.next]
            );
        }
    }
    let output = stdio.take();
    // Kept processes keep their address spaces.
    let kept = runs.iter().any(|run| run.keep_reaped);
    for ((index, run), reply) in (first..).zip(runs).zip(replies) {
        check(index, run, reply, &output);
    }
    if cfg!(debug_assertions) && !kept {
        service.check_released();
    }
}

/// Sets the debug hooks `runs` ask for, for their group: their scripts.
#[cfg(debug_assertions)]
fn set_hooks(runs: &[Run], service: &mut Programs, devices: &'static Devices) -> Vec<Script> {
    use core::sync::atomic::Ordering;
    use litebox_shim_vm_kernel::sched::RetakeHold;
    service.set_hooks(
        runs.iter()
            .map(|run| {
                use litebox_shim_vm_kernel::StackFailure as Failure;
                let stack_failure = run.stack_failure.and_then(|failure| match failure {
                    StackFailure::Root => None,
                    StackFailure::Spawn => Some(Failure::Spawn),
                    StackFailure::AfterAssociation => Some(Failure::AfterAssociation),
                    StackFailure::Clone => Some(Failure::Clone),
                });
                RunHooks {
                    process: litebox_shim_vm_kernel::Hooks {
                        fail_adoption: run.fail_adoption,
                        slow_serves: run.slow_serves,
                        stack_failure,
                    },
                    fail_spawn: matches!(run.stack_failure, Some(StackFailure::Root)),
                }
            })
            .collect(),
    );
    if runs.iter().any(|run| run.hold_starts) {
        service.hold_starts();
    }
    let hooks = service.scheduler().hooks();
    if let Some(point) = runs.iter().find_map(|run| run.gate) {
        devices.gate().arm(match point {
            GatePoint::Read => Point::Read,
            GatePoint::Handshake => Point::Handshake,
            GatePoint::Adopt => Point::Adopt,
            GatePoint::Transmitted => Point::Transmitted,
        });
    }
    hooks.held_start.store(false, Ordering::SeqCst);
    if let Some(slice) = runs.iter().find_map(|run| run.broker_slice_us) {
        hooks
            .broker_slice
            .store(slice.saturating_mul(1000).max(1), Ordering::SeqCst);
    }
    if runs.iter().any(|run| run.keep_reaped) {
        hooks.keep_reaped();
    }
    let hooked = |hook: fn(&Run) -> bool| runs.iter().any(hook);
    hooks.hold_retake(
        runs.iter()
            .find_map(|run| run.hold_retake)
            .map(|case| match case {
                RetakeCase::Handshake => RetakeHold::Handshake,
                RetakeCase::Futex => RetakeHold::Futex,
                RetakeCase::PreemptedFutex => RetakeHold::PreemptedFutex,
                RetakeCase::PreemptedFutexRan => RetakeHold::PreemptedFutexRan,
            }),
    );
    hooks.retaken.store(false, Ordering::SeqCst);
    hooks
        .post_as_finished
        .store(hooked(|run| run.post_as_finished), Ordering::SeqCst);
    if hooked(|run| run.lose_share_response) {
        devices.lose_share_response();
    }
    hooks
        .poll
        .store(hooked(|run| !run.script.is_empty()), Ordering::SeqCst);
    runs.iter()
        .map(|run| Script {
            steps: run.script.clone(),
            next: 0,
            service: service.scheduler().clone(),
        })
        .collect()
}

/// Checks that the scheduler hooks `runs` (from `first` on) set acted, then
/// clears what [`set_hooks`] set but the processes reaped kept.
#[cfg(debug_assertions)]
fn clear_hooks(first: usize, runs: &[Run], service: &Programs, devices: &'static Devices) {
    use core::sync::atomic::Ordering;
    let hooks = service.scheduler().hooks();
    assert!(
        !runs.iter().any(|run| run.hold_retake.is_some()) || hooks.retaken.load(Ordering::SeqCst),
        "runs {first}..: no handoff of the case was held"
    );
    assert!(
        !hooks.post_as_finished.swap(false, Ordering::SeqCst),
        "runs {first}..: no broker thread finished"
    );
    devices.gate().release();
    hooks.hold_starts.store(false, Ordering::SeqCst);
    hooks.broker_slice.store(0, Ordering::SeqCst);
    hooks.hold_retake(None);
    hooks.poll.store(false, Ordering::SeqCst);
}

/// A run's [`Run::script`], as its group runs.
#[cfg(debug_assertions)]
struct Script {
    steps: Vec<Step>,
    next: usize,
    service: litebox_shim_vm_kernel::sched::Scheduler,
}

#[cfg(debug_assertions)]
impl Script {
    /// Takes the steps it can, on `process`, the run's, and `devices`, until
    /// one waits: whether it took them all.
    fn advance(&mut self, process: &mut Process, devices: &'static Devices) -> bool {
        use core::sync::atomic::Ordering;
        let gate = devices.gate();
        let hooks = self.service.hooks();
        while let Some(&step) = self.steps.get(self.next) {
            let ready = match step {
                Step::Held => gate.holds(),
                Step::LockSleeper => litebox_platform_vm_kernel::lock_sleepers() != 0,
                Step::Release => {
                    gate.release();
                    true
                }
                Step::Migrate => {
                    gate.migrate();
                    true
                }
                Step::Kill => {
                    process.kill("killed by its test's script");
                    true
                }
                Step::StartHeld => hooks.held_start.load(Ordering::SeqCst),
                Step::ReleaseStarts => {
                    hooks.hold_starts.store(false, Ordering::SeqCst);
                    true
                }
            };
            if !ready {
                return false;
            }
            self.next += 1;
        }
        true
    }
}

/// Checks how run `index` ended; `output` is what its group wrote.
fn check(index: usize, run: Run, reply: Reply, output: &[Recorded; 2]) {
    let path = &run.argv[0];
    if run.expect_killed {
        assert!(
            matches!(reply.status, Err(RunError::Dead(Dead::Killed(_)))),
            "run {index} ({path}): {:?}, expected the kernel to kill it",
            reply.status
        );
        litebox_util_log::info!(index:% = index, status:? = reply.status; "run passed");
        return;
    }
    let expected = match (run.expect_exit_code, run.expect_signal) {
        (code, None) => ExitStatus::Exited {
            code: code.unwrap_or(0),
        },
        (None, Some(signal)) => ExitStatus::Signaled { signal },
        (Some(_), Some(_)) => {
            panic!("run {index}: `expect_exit_code` and `expect_signal` exclude each other")
        }
    };
    let status = reply
        .status
        .unwrap_or_else(|error| panic!("run {index} ({path}) did not run: {error:?}"));
    assert_eq!(status, expected, "run {index} ({path}): exit status");
    for (what, expected, actual) in [
        ("stdout", run.expect_stdout, &output[0]),
        ("stderr", run.expect_stderr, &output[1]),
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
    if let Some(expected) = run.expect_stdout_records {
        check_records(index, path, &output[0], expected);
    }
    assert!(
        reply.reflected_syscalls >= run.min_reflected_syscalls,
        "run {index} ({path}): {} reflected syscalls, expected at least {}",
        reply.reflected_syscalls,
        run.min_reflected_syscalls
    );
    #[cfg(debug_assertions)]
    if run.replay {
        assert_eq!(
            reply.replay_counts, [1; 5],
            "run {index} ({path}): how many times its first kernel call, reflected syscall, page \
             fault, other exception, and interrupt, which gave up on its claim, were handled"
        );
    }
    litebox_util_log::info!(
        index:% = index,
        status:? = status,
        reflected_syscalls:% = reply.reflected_syscalls;
        "run passed"
    );
}

/// Checks that `stdout` is `writers` writers' `records` records each (see
/// `expect_stdout_records` in the [module](self) docs).
fn check_records(index: usize, path: &str, stdout: &Recorded, [writers, records]: [usize; 2]) {
    assert!(
        !stdout.truncated,
        "run {index} ({path}): stdout exceeded the {MAX_RECORDED} bytes recorded, so its \
         records cannot be checked"
    );
    let mut next = alloc::vec![0; writers];
    for (at, record) in stdout.bytes.chunks(RECORD_SIZE).enumerate() {
        let Some(writer) = (0..writers).find(|&writer| {
            let expected = alloc::format!("w{writer} {}", next[writer]);
            record == alloc::format!("{expected:<width$}\n", width = RECORD_SIZE - 1).as_bytes()
        }) else {
            panic!(
                "run {index} ({path}): stdout's record {at} was {:?}, no writer's next",
                String::from_utf8_lossy(record)
            );
        };
        next[writer] += 1;
    }
    assert!(
        next.iter().all(|&written| written == records),
        "run {index} ({path}): stdout had {next:?} records per writer, expected {records}"
    );
}
