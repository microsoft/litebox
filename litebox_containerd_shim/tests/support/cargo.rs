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
        #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
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
    #[cfg(windows)]
    let RustFlags::Added(rustflags) = rustflags;
    #[cfg(target_os = "linux")]
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

/// A separate target directory isolates the static-link flags. On Windows, musl with `rust-lld`
/// avoids a Linux link toolchain.
fn build_static_guest_service() -> PathBuf {
    #[cfg(target_os = "linux")]
    let (libc, rustflags) = ("gnu", ["-C", "target-feature=+crt-static"].as_slice());
    #[cfg(windows)]
    let (libc, rustflags) = (
        "musl",
        [
            "-C",
            "linker=rust-lld",
            "-C",
            "linker-flavor=ld.lld",
            "-C",
            "target-feature=+crt-static",
        ]
        .as_slice(),
    );
    let target = format!("{}-unknown-linux-{libc}", std::env::consts::ARCH);
    let dir = target_dir().join("static-guest-service");
    let args = ["-p", "litebox_guest_service", "--target", &target];
    cargo_build("", &args, &dir, RustFlags::Added(rustflags));
    dir.join(&target).join("debug/litebox-guest-service")
}

fn build_broker_and_runner(target: &Path) -> (PathBuf, PathBuf) {
    #[cfg(target_os = "linux")]
    let runner = "litebox_runner_linux_userland";
    #[cfg(windows)]
    let runner = "litebox_runner_linux_on_windows_userland";
    cargo_build(
        "",
        &["-p", "litebox_broker_userland", "-p", runner],
        target,
        RustFlags::Added(&[]),
    );
    let executable = |name: &str| {
        let suffix = std::env::consts::EXE_SUFFIX;
        target.join("debug").join(format!("{name}{suffix}"))
    };
    (executable("litebox-broker-userland"), executable(runner))
}

/// Builds the VM kernel and the VM's Linux runner, as `dev_tools/run_linux_on_vm_userland.sh`
/// does; returns their paths.
#[cfg(target_os = "linux")]
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
