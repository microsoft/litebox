// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Regression-test deployment: a fresh broker subprocess and runner subprocess
//! per fixture. The parent collects the runner's *actual* status and diagnostics
//! rather than the broker CLI's status (which summarizes nonzero guest exits).
//! No guest or runner code executes in the broker/test-parent process.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use litebox_broker_core::fs::composer::Composer;
use litebox_broker_core::fs::in_mem::{InMem, InitialNode};
use litebox_broker_core::fs::overlay::Overlay;
use litebox_broker_core::fs::resolver::Resolver;
use litebox_broker_core::fs::tar_ro::TarRo;
use litebox_broker_core::{ObjectRights, PolicyEngine};
use litebox_broker_platform_macos_userland::MacosSyncPrimitivesProvider as Platform;
use litebox_broker_protocol::fs::{FileMode, FileUser};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_macos_userland::shared_memory::MacosSharedMemory;
use litebox_broker_transport_macos_userland::unix_socket::{
    UnixStreamHostSetupChannel, validate_peer_process,
};
use litebox_broker_userland::builder::BrokerCoreBuilder;

const TIMEOUT: Duration = Duration::from_secs(30);
const SOCKET_ENV: &str = "LITEBOX_MACOS_TEST_BROKER_SOCKET";
const ARCHIVE_ENV: &str = "LITEBOX_MACOS_TEST_BROKER_ARCHIVE";
const READY: &str = "LITEBOX_MACOS_TEST_BROKER_READY\n";

/// Package the fixture tree; only the broker opens this host archive.
pub fn archive(root: &Path, archive: &Path) {
    let output = Command::new("tar")
        .env("COPYFILE_DISABLE", "1")
        .args(["--format=ustar", "-cf"])
        .arg(archive)
        .arg("-C")
        .arg(root)
        .arg(".")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "tar: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn run(archive: &Path, program: &str, extra: &[&str]) -> Output {
    // Short, private socket paths also work with Darwin's sockaddr_un limit.
    let directory = tempfile::Builder::new()
        .prefix("lb-mac-test-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .unwrap();
    let socket = directory.path().join("broker.sock");
    let mut broker = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "common::broker_process",
                "--nocapture",
                "--quiet",
            ])
            .env(SOCKET_ENV, &socket)
            .env(ARCHIVE_ENV, archive)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let broker_errors = collect(broker.0.stderr.take().unwrap());
    let broker_stdout = broker.0.stdout.take().unwrap();
    let (ready, started) = mpsc::sync_channel(1);
    let broker_output = thread::spawn(move || {
        let mut stdout = BufReader::new(broker_stdout);
        // Discard only the child libtest preamble, before the broker is ready.
        loop {
            let mut line = String::new();
            if stdout.read_line(&mut line).unwrap() == 0 {
                return Vec::new();
            }
            if line.ends_with(READY) {
                break;
            }
        }
        ready.send(()).unwrap();
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    if started.recv_timeout(TIMEOUT).is_err() {
        let _ = broker.0.kill();
        let _ = broker.0.wait();
        panic!(
            "broker setup failed: {}",
            String::from_utf8_lossy(&broker_errors.join().unwrap())
        );
    }

    let runner_path = std::env::var_os("NEXTEST_BIN_EXE_litebox_runner_linux_on_macos_userland")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_litebox_runner_linux_on_macos_userland").into());
    let mut runner = ChildGuard(
        Command::new(runner_path)
            .args(["--unstable", "--broker-control-channel"])
            .arg(&socket)
            .args(extra)
            .arg(program)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    // The trusted test parent tells the broker which runner PID to authenticate.
    // Close this pipe after the bootstrap line; broker-owned guest stdin is EOF.
    writeln!(broker.0.stdin.take().unwrap(), "{}", runner.0.id()).unwrap();
    let runner_output = collect(runner.0.stdout.take().unwrap());
    let runner_errors = collect(runner.0.stderr.take().unwrap());
    let status = wait(&mut runner.0, "runner");
    let broker_status = wait(&mut broker.0, "broker");
    let errors = broker_errors.join().unwrap();
    assert!(
        broker_status.success(),
        "broker failed: {}",
        String::from_utf8_lossy(&errors)
    );
    assert!(
        errors.is_empty(),
        "unexpected broker diagnostics: {}",
        String::from_utf8_lossy(&errors)
    );
    let mut stdout = broker_output.join().unwrap();
    stdout.extend(runner_output.join().unwrap());
    Output {
        status,
        stdout,
        stderr: runner_errors.join().unwrap(),
    }
}

fn collect(mut stream: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        bytes
    })
}

fn wait(child: &mut Child, name: &str) -> std::process::ExitStatus {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {name}");
        thread::sleep(Duration::from_millis(10));
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Entry point selected by the parent when this integration-test executable is
/// re-executed as a broker. A normal test invocation has no bootstrap variables.
#[test]
fn broker_process() -> Result<(), Box<dyn std::error::Error>> {
    let Some(socket) = std::env::var_os(SOCKET_ENV) else {
        return Ok(());
    };
    let archive = std::env::var_os(ARCHIVE_ENV).ok_or("missing broker archive")?;
    let data = std::fs::read(archive)?;
    let writable = InMem::<Platform>::new_initialized(vec![(
        "/tmp".to_owned(),
        InitialNode::Directory {
            mode: FileMode::RWXU | FileMode::RWXG | FileMode::RWXO,
            owner: FileUser::ROOT,
        },
    )]);
    let backend = Composer::builder()
        .mount_nestable("/", |allocators| {
            Overlay::<Platform>::new(
                writable,
                TarRo::new(data.into(), allocators.next()),
                allocators.next(),
            )
        })
        .mount("/dev", litebox_broker_core::fs::devices::Devices::new)
        .build()
        .map_err(|_| "failed to construct test filesystem")?;
    let fs = Arc::new(Resolver::<Platform, _>::new(backend));
    let broker = BrokerCoreBuilder::new(PolicyEngine::with_host_guaranteed_rights(
        ObjectRights::all(),
    ))
    .with_file_service(fs)
    .build()?;
    let listener = UnixListener::bind(socket)?;
    listener.set_nonblocking(true)?;
    print!("{READY}");
    std::io::stdout().flush()?;
    let mut pid = String::new();
    std::io::stdin().read_line(&mut pid)?;
    let pid = pid.trim().parse()?;
    let deadline = Instant::now() + TIMEOUT;
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "runner never connected");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    };
    stream.set_nonblocking(false)?; // Darwin accept inherits listener flags.
    validate_peer_process(&stream, pid)?;
    let setup = UnixStreamHostSetupChannel::from_host_guaranteed(stream, deadline);
    litebox_broker_userland::runtime::serve_association(
        &broker,
        setup,
        || MacosSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        MacosSharedMemory::create_control_ring,
        |channel, buffers, control| {
            channel.send_shared_memory(buffers, Some(deadline))?;
            channel.send_shared_memory(control, Some(deadline))
        },
        UnixStreamHostSetupChannel::into_active,
    )?;
    // Avoid appending the libtest summary to the captured guest stdout.
    std::process::exit(0);
}
