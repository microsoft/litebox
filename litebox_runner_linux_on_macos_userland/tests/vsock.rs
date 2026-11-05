// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The broker's hybrid vsock bridge (`--vsock-uds`) between a guest's `AF_VSOCK` sockets and
//! host Unix sockets.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;
#[path = "../../litebox_runner_linux_on_windows_userland/tests/vsock_hybrid_host/mod.rs"]
mod vsock_hybrid_host;

use std::io::BufRead as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Runs `vsock_hybrid`, whose AF_VSOCK sockets reach host Unix sockets through the broker's
/// hybrid vsock bridge, against [`vsock_hybrid_host`], its host end.
///
/// Built at test time from `litebox_runner_vm_kernel/tests/linux/vsock_hybrid.rs`.
#[test]
fn test_vsock_hybrid_with_macos_broker() {
    const TIMEOUT: Duration = Duration::from_secs(120);
    // How long the guest has to end after its host end failed, and the broker's output to close
    // after the broker ended.
    const GRACE: Duration = Duration::from_secs(5);

    let runner = common::runner_binary();
    let broker = common::broker_binary(&runner);
    let fixture = tempfile::Builder::new()
        .prefix("litebox-vsock-")
        .tempdir()
        .unwrap();
    let archive = guest_archive(fixture.path());
    // Its own directory, writable only by this user, as the bridge requires; short, as macOS
    // limits Unix socket paths, the bridge's `PATH_<port>` included, to 103 bytes.
    let sockets = tempfile::Builder::new().prefix("lbv-").tempdir().unwrap();
    let vsock_uds = sockets.path().canonicalize().unwrap().join("vsock");
    // Before the guest can connect.
    let (listener, refuser) = vsock_hybrid_host::host_sockets(&vsock_uds);
    let mut child = Command::new(broker)
        .arg("--vsock-uds")
        .arg(&vsock_uds)
        .arg("--fs-initial-files")
        .arg(&archive)
        .arg("--runner")
        .arg(&runner)
        .args(["--", "/bin/vsock_hybrid"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to run litebox-broker-userland");
    let stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let (line_sender, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in stdout.lines().map_while(Result::ok) {
            let _ = line_sender.send(line);
        }
    });

    let deadline = Instant::now() + TIMEOUT;
    let mut output = String::new();
    loop {
        let Ok(line) = lines.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        else {
            let status = wait_or_kill(&mut child, Instant::now() + GRACE);
            panic!(
                "the guest never printed `ready`; the broker ended with {status}; output:\n{output}"
            );
        };
        output.push_str(&line);
        output.push('\n');
        if line == "ready" {
            break;
        }
    }
    let host_path = vsock_uds.clone();
    let host = std::thread::spawn(move || vsock_hybrid_host::run(&host_path, listener));
    // In time, as each of the host end's steps times out.
    let host_result = host.join();
    // A host end that failed may leave the guest waiting for it.
    let status = wait_or_kill(
        &mut child,
        if host_result.is_ok() {
            deadline
        } else {
            Instant::now() + GRACE
        },
    );
    while let Ok(line) = lines.recv_timeout(GRACE) {
        output.push_str(&line);
        output.push('\n');
    }
    // The guest's output shows whether the guest failed first.
    assert!(
        host_result.is_ok(),
        "the host end failed; the broker ended with {status}; output:\n{output}"
    );
    assert!(
        status.success(),
        "litebox-broker-userland failed: {status}; output:\n{output}"
    );
    assert_eq!(output, "ready\nvsock-hybrid ok\n");
    // The broker removed PATH as it stopped the bridge.
    assert!(!std::fs::exists(&vsock_uds).unwrap());
    drop(refuser);
}

/// Packs the guest of [`test_vsock_hybrid_with_macos_broker`], built from its source, with
/// `tests/test-bins`' dynamic loader and glibc into `directory`.
///
/// The guest is a PIE, as the macOS loader takes only `ET_DYN` programs, and names the dynamic
/// loader as its interpreter, which applies its relocations; it uses nothing from glibc.
fn guest_archive(directory: &Path) -> PathBuf {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../litebox_runner_vm_kernel/tests/linux/vsock_hybrid.rs");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/test-bins");
    let root = directory.join("root");
    for directory in ["bin", "lib/aarch64-linux-gnu"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = Command::new(rustc)
        .args([
            "--edition=2024",
            "--target",
            "aarch64-unknown-none",
            "-C",
            "opt-level=2",
            "-C",
            "relocation-model=pie",
            "-C",
            "link-arg=-pie",
            "-C",
            "link-arg=--dynamic-linker=/lib/ld-linux-aarch64.so.1",
            "-o",
        ])
        .arg(root.join("bin/vsock_hybrid"))
        .arg(&source)
        .output()
        .expect("failed to run rustc");
    assert!(
        output.status.success(),
        "failed to build {} (is the target installed? `rustup target add aarch64-unknown-none`):\n{}",
        source.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    for (source, destination) in [
        ("ld-linux-aarch64.so.1", "lib/ld-linux-aarch64.so.1"),
        ("libc.so.6", "lib/aarch64-linux-gnu/libc.so.6"),
    ] {
        std::fs::copy(fixtures.join(source), root.join(destination)).unwrap();
    }
    let archive = directory.join("root.tar");
    let tar = Command::new("tar")
        .env("COPYFILE_DISABLE", "1")
        .args(["--format=ustar", "-cf"])
        .arg(&archive)
        .arg("-C")
        .arg(&root)
        .args(["bin", "lib"])
        .output()
        .unwrap();
    assert!(
        tar.status.success(),
        "{}",
        String::from_utf8_lossy(&tar.stderr)
    );
    archive
}

/// Waits for `child` to exit, killing it at `deadline`.
fn wait_or_kill(child: &mut Child, deadline: Instant) -> ExitStatus {
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    child.wait().unwrap()
}
