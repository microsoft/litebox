// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `guest_service_test_client`: runs Linux test programs on LiteBox's stacked runners (the VM
//! kernel, `litebox_runner_vm_kernel`), whose programs the host cannot start directly, through
//! the guest service, the VM's init; the userland backend needs no such client, as its runner runs
//! programs directly. It reaches the guest service through a hybrid vsock bridge (e.g.,
//! vhost-device-vsock's `uds-path`), as the containerd shim does: a Unix socket where
//! `CONNECT <port>\n`, answered with `OK <host port>\n`, connects to the guest's vsock port. It
//! exits with 0 if the test passed, 1 otherwise.
//!
//! A test is a `programs.json` (see [`programs`]). The client creates and starts one container,
//! whose init is `--init` (a program that waits until killed), runs the entries in order, each run
//! an exec process, the runs of a group at once, then kills the container's init. It prints a line
//! per run. With `--counted`, it only lists the entries with checks that only the VM kernel makes
//! (see [`programs`]), a line `INDEX MIN_REFLECTED_SYSCALLS REPLAY` each (`REPLAY` 0 or 1), for
//! the test harness to run each alone (`--only`) in a boot of its own, and the others together
//! (`--skip-counted`).

#![cfg(target_os = "linux")]

mod container;
pub mod programs;

use std::fs::OpenOptions;
use std::io::{self, BufRead as _, BufReader, Write as _};
use std::os::fd::IntoRawFd as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use clap::Parser;
use litebox_guest_service_protocol::GUEST_SERVICE_PORT;
use litebox_guest_service_protocol::guest_service_ttrpc::GuestServiceClient;

use container::Container;
use programs::Entry;

/// Between attempts to reach the guest service, which may not listen yet.
const CONNECT_RETRY: Duration = Duration::from_millis(100);
/// How long the bridge may take to answer `CONNECT`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
struct Cli {
    /// The test: a `programs.json`.
    test: PathBuf,
    /// The hybrid vsock bridge's Unix socket.
    #[arg(long, required_unless_present = "counted")]
    bridge: Option<PathBuf>,
    /// The container's init: a program that waits until killed.
    #[arg(long, default_value = "/container_init")]
    init: String,
    /// The `console_stdin` runs' input.
    #[arg(long)]
    input: Option<PathBuf>,
    /// A file to append every run's output to, as it comes.
    #[arg(long)]
    output: Option<PathBuf>,
    /// How long the guest service may take to listen, in seconds.
    #[arg(long, default_value_t = 120)]
    connect_timeout: u64,
    /// Runs only entry INDEX (counted from 0).
    #[arg(long, value_name = "INDEX", conflicts_with = "skip_counted")]
    only: Option<usize>,
    /// Skips the entries that `--counted` lists.
    #[arg(long)]
    skip_counted: bool,
    /// Lists the entries with checks that only the VM kernel makes, and exits.
    #[arg(long, conflicts_with_all = ["only", "skip_counted"])]
    counted: bool,
}

/// Runs the command line's test, and exits with its result.
pub fn main() -> ! {
    match run(&Cli::parse()) {
        Ok(()) => std::process::exit(0),
        Err(error) => {
            println!("FAIL: {error:#}");
            std::process::exit(1);
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    let json =
        std::fs::read(&cli.test).with_context(|| format!("cannot read {}", cli.test.display()))?;
    let entries = programs::parse(&json).with_context(|| cli.test.display().to_string())?;
    if cli.counted {
        for (index, counts) in entries.iter().enumerate() {
            if let Some(counts) = counts.counts() {
                println!(
                    "{index} {} {}",
                    counts.min_reflected_syscalls,
                    u8::from(counts.replay)
                );
            }
        }
        return Ok(());
    }
    // The run numbers of each entry's first run.
    let firsts = entries.iter().scan(0, |next, entry| {
        let first = *next;
        *next += entry.runs().len();
        Some(first)
    });
    let selected: Vec<(usize, &Entry)> = firsts
        .zip(&entries)
        .enumerate()
        .filter(|(index, (_, entry))| match cli.only {
            Some(only) => *index == only,
            None => !cli.skip_counted || entry.counts().is_none(),
        })
        .map(|(_, selected)| selected)
        .collect();
    if let Some(only) = cli.only {
        ensure!(only < entries.len(), "no entry {only}");
    }
    let input = match &cli.input {
        Some(path) => {
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?
        }
        None => Vec::new(),
    };
    let output = match &cli.output {
        Some(path) => Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("cannot open {}", path.display()))?,
        ),
        None => None,
    };
    let service = connect(cli)?;
    let container = Container::start(service, &cli.init, output, input)?;
    let mut result = Ok(());
    for (first, entry) in selected {
        result = container.run_entry(first, entry);
        if result.is_err() {
            break;
        }
    }
    container.end().context("ending the container")?;
    result
}

/// Connects to the guest service through `cli`'s bridge, retrying until it listens, for up to
/// `cli`'s connect timeout.
fn connect(cli: &Cli) -> Result<GuestServiceClient> {
    let bridge = cli.bridge.as_deref().expect("clap requires it");
    let timeout = Duration::from_secs(cli.connect_timeout);
    let deadline = Instant::now() + timeout;
    loop {
        match connect_once(bridge) {
            Ok(stream) => {
                let client = ttrpc::Client::new(stream.into_raw_fd())
                    .context("cannot serve the connection")?;
                return Ok(GuestServiceClient::new(client));
            }
            Err(error) if Instant::now() > deadline => {
                bail!(
                    "the guest service did not listen within {timeout:?} at {}: {error}",
                    bridge.display()
                );
            }
            // E.g., the bridge does not exist yet, or closes the connection, as nothing
            // listens yet.
            Err(_) => std::thread::sleep(CONNECT_RETRY),
        }
    }
}

fn connect_once(bridge: &Path) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(bridge)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.write_all(format!("CONNECT {GUEST_SERVICE_PORT}\n").as_bytes())?;
    // A byte at a time: what follows the line is the guest service's.
    let mut answer = Vec::new();
    BufReader::with_capacity(1, &stream).read_until(b'\n', &mut answer)?;
    if !answer.starts_with(b"OK ") || !answer.ends_with(b"\n") {
        return Err(io::Error::other(format!("the bridge answered {answer:?}")));
    }
    stream.set_read_timeout(None)?;
    Ok(stream)
}
