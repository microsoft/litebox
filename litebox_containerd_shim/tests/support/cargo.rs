// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Builds the programs that the shim's tests run, with the cargo that runs the tests.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned()
}

pub(crate) fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| workspace_root().join("target"), PathBuf::from)
}

/// Runs `cargo build` with `args` into `target_dir`, with `rustflags` added to the caller's.
pub(crate) fn cargo_build(args: &[&str], target_dir: &Path, rustflags: &[&str]) {
    let mut command = Command::new(env!("CARGO"));
    command
        .arg("build")
        .args(args)
        .arg("--target-dir")
        .arg(target_dir)
        .current_dir(workspace_root());
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
pub(crate) fn build_static_guest_service() -> PathBuf {
    let target = format!("{}-unknown-linux-gnu", std::env::consts::ARCH);
    let dir = target_dir().join("static-guest-service");
    let args = ["-p", "litebox_guest_service", "--target", &target];
    cargo_build(&args, &dir, &["-C", "target-feature=+crt-static"]);
    dir.join(&target).join("debug/litebox-guest-service")
}
