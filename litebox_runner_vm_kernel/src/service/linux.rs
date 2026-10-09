// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux programs, each run to its end in a fresh
//! `litebox_runner_linux_on_vm_userland` process, as
//! `litebox_common_linux::vm_userland` describes; a [`Request`]'s programs run
//! concurrently, time-sliced ([`litebox_shim_vm_kernel::scheduler`]). From the
//! payload: `runner.elf`, and `rootfs.tar`, the broker's read-only file system
//! at `/`. `/dev` has the standard streams, which all processes share: stdin
//! is empty, and stdout and stderr go to the console and to the [`Reply`].
//!
//! Each process has one thread, and no timers or signals. A wait with a
//! timeout (e.g., `nanosleep`) blocks; one without (e.g., `pause`) is a
//! deadlock, as nothing could end it, and the runner fails. No wall clock either: a program
//! that reads the real-time clock (`time`, `gettimeofday`,
//! `clock_gettime(CLOCK_REALTIME)`, or a futex wait on it) kills its runner.
//! Monotonic clocks work (the TSC).

use super::Service;
use crate::payload::Payload;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use litebox_broker_core::ObjectRights;
use litebox_broker_core::fs::composer::Composer;
use litebox_broker_core::fs::devices::Devices;
use litebox_broker_core::fs::resolver::Resolver;
use litebox_broker_core::fs::tar_ro::TarRo;
use litebox_broker_core::stdio::{
    StdioOutputStream, StdioProvider, StdioProviderError, StdioStream,
};
use litebox_broker_protocol::process::ProcessExitStatus;
use litebox_broker_vm_kernel::Broker;
use litebox_broker_vm_kernel::providers::HardwareRandom;
use litebox_common_linux::vm_userland::{ARGV_IMAGE, ENVP_IMAGE, encode_strings, exit_status};
use litebox_common_vm_abi::IDENTITY_LEN;
use litebox_platform_vm_kernel::VmKernel;
use litebox_shim_vm_kernel::{Dead, Process, ProcessConfig};
use spin::Mutex;

/// Programs to run concurrently.
pub struct Request {
    pub programs: Vec<Program>,
}

pub struct Program {
    /// `argv[0]` is the program's absolute path in `rootfs.tar`.
    pub argv: Vec<String>,
    pub envp: Vec<String>,
    /// Killed this long after it first runs.
    pub time_limit: Option<core::time::Duration>,
}

pub struct Reply {
    /// By program, in the [`Request`]'s order.
    pub outcomes: Vec<Outcome>,
    /// All the programs' output, interleaved.
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub struct Outcome {
    /// `Err` with the cause if the runner failed, rather than the program.
    pub status: Result<ProcessExitStatus, Failure>,
    /// Syscalls the shim did not patch, which the kernel reflected to it.
    pub reflected_syscalls: u64,
    /// Times the timer took the CPU from the process.
    pub preemptions: u64,
}

#[derive(Debug)]
pub enum Failure {
    Spawn(litebox_shim_vm_kernel::SpawnError),
    /// The runner's own failure, or an exit code it never reports.
    Runner(Dead),
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Spawn(error) => write!(f, "spawning the runner: {error}"),
            Self::Runner(Dead::Exited(code)) => {
                write!(f, "the runner failed (exit code {code:#x})")
            }
            Self::Runner(Dead::Killed(reason)) => write!(f, "the runner was killed: {reason}"),
        }
    }
}

pub struct Linux {
    platform: &'static VmKernel,
    tsc_khz: u64,
    runner: &'static [u8],
    broker: Broker,
    stdio: Arc<ConsoleStdio>,
}

impl Linux {
    /// # Panics
    ///
    /// On a missing or malformed payload file.
    pub fn new(platform: &'static VmKernel, tsc_khz: u64, payload: &Payload) -> Self {
        let file = |name| {
            payload
                .file(name)
                .unwrap_or_else(|| panic!("payload has no {name}"))
        };
        let (runner, rootfs) = (file("runner.elf"), file("rootfs.tar"));
        let stdio = Arc::new(ConsoleStdio::default());
        let devices_stdio: Arc<dyn StdioProvider> = stdio.clone();
        let fs = Composer::builder()
            .mount("/", |allocator| {
                TarRo::new(alloc::borrow::Cow::Borrowed(rootfs), allocator)
            })
            .mount("/dev", |allocator| {
                Devices::new(allocator, devices_stdio, Arc::new(HardwareRandom::new()))
            })
            .build()
            .unwrap_or_else(|error| panic!("file system: {error}"));
        let broker = Broker::with_file_service(
            Arc::new(Resolver::<VmKernel, _>::new(fs)),
            ObjectRights::all(),
        );
        Self {
            platform,
            tsc_khz,
            runner,
            broker,
            stdio,
        }
    }

    fn spawn(&self, program: &Program) -> Result<Process, Failure> {
        let strings = |strings: &[String]| {
            encode_strings(strings.iter().map(String::as_str)).expect("no NULs in arguments")
        };
        let mut images = [&[][..]; 2];
        let (argv, envp) = (strings(&program.argv), strings(&program.envp));
        images[ARGV_IMAGE] = &argv;
        images[ENVP_IMAGE] = &envp;
        let mut process = Process::spawn(
            self.platform,
            &self.broker,
            &ProcessConfig {
                runner: self.runner,
                images: &images,
                identity: [0; IDENTITY_LEN],
                tsc_khz: self.tsc_khz,
            },
        )
        .map_err(Failure::Spawn)?;
        if let Some(limit) = program.time_limit {
            process.set_time_limit(limit);
        }
        Ok(process)
    }

    fn run(&self, request: &Request) -> Vec<Outcome> {
        let mut spawned: Vec<Result<Process, Failure>> = request
            .programs
            .iter()
            .map(|program| self.spawn(program))
            .collect();
        let mut running: Vec<&mut Process> =
            spawned.iter_mut().filter_map(|p| p.as_mut().ok()).collect();
        litebox_shim_vm_kernel::scheduler::run(self.platform, &mut running);
        spawned
            .into_iter()
            .map(|process| {
                let mut process = match process {
                    Ok(process) => process,
                    Err(failure) => {
                        return Outcome {
                            status: Err(failure),
                            reflected_syscalls: 0,
                            preemptions: 0,
                        };
                    }
                };
                let status = match process.finish() {
                    Dead::Exited(code) => {
                        exit_status(code).ok_or(Failure::Runner(Dead::Exited(code)))
                    }
                    dead @ Dead::Killed(_) => Err(Failure::Runner(dead)),
                };
                Outcome {
                    status,
                    reflected_syscalls: process.reflected_syscalls(),
                    preemptions: process.preemptions(),
                }
            })
            .collect()
    }
}

impl Service for Linux {
    type Request = Request;
    type Reply = Reply;

    fn call(&mut self, request: Request) -> Reply {
        self.stdio.reset();
        let outcomes = self.run(&request);
        let (stdout, stderr) = self.stdio.reset();
        Reply {
            outcomes,
            stdout,
            stderr,
        }
    }
}

/// Keeps at most this much of each stream for the [`Reply`]; the console gets
/// everything.
const MAX_CAPTURE: usize = 64 * 1024;

/// A console line holds at most this much of a stream; a longer line is split.
const MAX_LINE: usize = 1024;

/// Standard streams for runner processes: stdin at end-of-file; stdout and
/// stderr captured, and to the console.
///
/// The console gets only whole lines, each printed at once with its stream's
/// prefix, and escaped ([`Untrusted`]). So a program's output can neither
/// continue a kernel line nor start one without the prefix, whatever it
/// interleaves with.
#[derive(Default)]
struct ConsoleStdio {
    state: Mutex<[Stream; 2]>,
}

#[derive(Default)]
struct Stream {
    captured: Vec<u8>,
    /// The current line, not yet printed.
    line: Vec<u8>,
}

impl Stream {
    fn prefix(index: usize) -> &'static str {
        if index == STDOUT {
            "[guest] "
        } else {
            "[guest stderr] "
        }
    }

    /// Prints the current line, if any.
    fn flush(&mut self, prefix: &str) {
        if !self.line.is_empty() {
            let line = Untrusted(&String::from_utf8_lossy(&self.line));
            litebox_hal::console::print(format_args!("{prefix}{line}\n"));
            self.line.clear();
        }
    }
}

const STDOUT: usize = 0;
const STDERR: usize = 1;

impl ConsoleStdio {
    /// The captured output so far, which it forgets; prints any partial
    /// lines.
    fn reset(&self) -> (Vec<u8>, Vec<u8>) {
        let mut streams = self.state.lock();
        for (index, stream) in streams.iter_mut().enumerate() {
            stream.flush(Stream::prefix(index));
        }
        let [stdout, stderr] = &mut *streams;
        (
            core::mem::take(&mut stdout.captured),
            core::mem::take(&mut stderr.captured),
        )
    }
}

impl StdioProvider for ConsoleStdio {
    fn read(&self, _output: &mut [u8]) -> Result<usize, StdioProviderError> {
        Ok(0)
    }

    fn write(&self, stream: StdioOutputStream, input: &[u8]) -> Result<usize, StdioProviderError> {
        let index = match stream {
            StdioOutputStream::Stdout => STDOUT,
            StdioOutputStream::Stderr => STDERR,
        };
        let mut streams = self.state.lock();
        let stream = &mut streams[index];
        let room = MAX_CAPTURE.saturating_sub(stream.captured.len());
        stream
            .captured
            .extend_from_slice(&input[..input.len().min(room)]);
        for &byte in input {
            if byte == b'\n' {
                if stream.line.is_empty() {
                    // Keep empty lines visible.
                    stream.line.push(b' ');
                }
                stream.flush(Stream::prefix(index));
            } else {
                stream.line.push(byte);
                if stream.line.len() >= MAX_LINE {
                    stream.flush(Stream::prefix(index));
                }
            }
        }
        Ok(input.len())
    }

    fn is_terminal(&self, _stream: StdioStream) -> bool {
        false
    }
}

/// Escapes control characters so a program cannot forge or garble console
/// lines.
struct Untrusted<'a>(&'a str);

impl core::fmt::Display for Untrusted<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Write as _;
        for c in self.0.chars() {
            if c.is_control() {
                write!(f, "{}", c.escape_default())?;
            } else {
                f.write_char(c)?;
            }
        }
        Ok(())
    }
}
