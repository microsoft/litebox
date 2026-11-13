// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Builds the programs that the shim's tests run, with the cargo that runs the tests.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Backend;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned()
}

fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| workspace_root().join("target"), PathBuf::from)
}

/// Builds and copies the programs of `backend` into this test's private directory.
// Builds are serialized, and tests run copies because Cargo may replace even unchanged
// executables.
pub(crate) fn build_programs(backend: Backend, destination: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let target = target_dir().join("shim-test-programs");
    std::fs::create_dir_all(&target).unwrap();
    let lock = std::fs::File::create(target.join(".lock")).unwrap();
    lock.lock().unwrap();
    let guest_service = build_static_guest_service();
    let (program, runner) = match backend {
        Backend::Userland => build_broker_and_runner(&target),
        Backend::Vm => build_vm_kernel_and_runner(&target),
    };
    std::fs::create_dir_all(destination).unwrap();
    let [guest_service, program, runner] = [guest_service, program, runner].map(|source| {
        let copy = destination.join(source.file_name().unwrap());
        std::fs::copy(source, &copy).unwrap();
        copy
    });
    (guest_service, program, runner)
}

/// The flags of a build: the caller's, with these added; or none, so that the configuration's apply.
enum RustFlags<'a> {
    Added(&'a [&'a str]),
    Configured,
}

/// Runs `cargo build` with `args` in the directory `dir` of the workspace, into `target_dir`, with
/// `rustflags`.
fn cargo_build(dir: &str, args: &[&str], target_dir: &Path, rustflags: RustFlags<'_>) {
    let mut command = Command::new(env!("CARGO"));
    command
        .arg("build")
        .args(args)
        .arg("--target-dir")
        .arg(target_dir)
        .current_dir(workspace_root().join(dir));
    let rustflags = match rustflags {
        RustFlags::Added(rustflags) => rustflags,
        RustFlags::Configured => {
            // Either would replace the configuration's.
            command
                .env_remove("RUSTFLAGS")
                .env_remove("CARGO_ENCODED_RUSTFLAGS");
            &[]
        }
    };
    if !rustflags.is_empty() {
        // Cargo ignores `RUSTFLAGS` once `CARGO_ENCODED_RUSTFLAGS` is set, even empty.
        let (name, separator) = match std::env::var_os("CARGO_ENCODED_RUSTFLAGS") {
            Some(_) => ("CARGO_ENCODED_RUSTFLAGS", "\x1f"),
            None => ("RUSTFLAGS", " "),
        };
        let mut flags = std::env::var(name).unwrap_or_default();
        for flag in rustflags {
            if !flags.is_empty() {
                flags.push_str(separator);
            }
            flags.push_str(flag);
        }
        command.env(name, flags);
    }
    let output = command.output().expect("cannot run cargo");
    assert!(
        output.status.success(),
        "cargo build {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Builds the guest service static for the host's glibc target, in a target directory of its own
/// so that its flags keep the workspace's build cache, and returns its path.
fn build_static_guest_service() -> PathBuf {
    let target = format!("{}-unknown-linux-gnu", std::env::consts::ARCH);
    let dir = target_dir().join("static-guest-service");
    let args = ["-p", "litebox_guest_service", "--target", &target];
    let rustflags = RustFlags::Added(&["-C", "target-feature=+crt-static"]);
    cargo_build("", &args, &dir, rustflags);
    dir.join(&target).join("debug/litebox-guest-service")
}

/// Builds the broker and LiteBox's Linux runner, and returns their paths.
fn build_broker_and_runner(target: &Path) -> (PathBuf, PathBuf) {
    let args = [
        "-p",
        "litebox_broker_userland",
        "-p",
        "litebox_runner_linux_userland",
    ];
    cargo_build("", &args, target, RustFlags::Added(&[]));
    let debug = target.join("debug");
    (
        debug.join("litebox-broker-userland"),
        debug.join("litebox_runner_linux_userland"),
    )
}

/// Builds the VM kernel and the VM's Linux runner, as `dev_tools/run_linux_on_vm_userland.sh`
/// does; returns their paths.
fn build_vm_kernel_and_runner(target: &Path) -> (PathBuf, PathBuf) {
    const TARGET: &str = "x86_64-unknown-none";
    let args = ["--target", TARGET];
    cargo_build(
        "litebox_runner_vm_kernel",
        &args,
        target,
        RustFlags::Added(&[]),
    );
    let runner_dir = target.join("vm_userland");
    let runner = "litebox_runner_linux_on_vm_userland";
    cargo_build(runner, &args, &runner_dir, RustFlags::Configured);
    (
        target.join(TARGET).join("debug/litebox_runner_vm_kernel"),
        runner_dir.join(TARGET).join("debug").join(runner),
    )
}
