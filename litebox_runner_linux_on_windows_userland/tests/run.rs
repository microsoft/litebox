// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

fn checked_output(command: &mut Command) -> String {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("Failed to run {command:?}: {error}"));
    assert!(
        output.status.success(),
        "{command:?} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).unwrap()
}

fn brokered_runner_command(initial_files: &Path) -> Command {
    let runner = std::env::var_os("NEXTEST_BIN_EXE_litebox_runner_linux_on_windows_userland")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_litebox_runner_linux_on_windows_userland").into());
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args([
            "build",
            "-p",
            "litebox_broker_userland",
            "--bin",
            "litebox-broker-userland",
        ])
        .status()
        .expect("failed to build litebox-broker-userland");
    assert!(status.success(), "failed to build litebox-broker-userland");

    let broker = PathBuf::from(&runner).with_file_name("litebox-broker-userland.exe");
    assert!(
        broker.is_file(),
        "broker executable not found at {}",
        broker.display()
    );
    let mut command = Command::new(broker);
    command
        .arg("--fs-initial-files")
        .arg(initial_files)
        .arg("--runner")
        .arg(runner);
    command
}

fn packaged_rootfs(test_directory: &str, image: &str, cache_hit_variable: &str) -> PathBuf {
    let test_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test_directory);
    std::fs::create_dir_all(&test_dir).unwrap();
    let tar_path = test_dir.join("rootfs.tar");
    if std::env::var_os(cache_hit_variable).is_some_and(|value| value == "true") {
        assert!(
            tar_path.is_file(),
            "CI reported a rootfs cache hit via {cache_hit_variable}, but {} is missing",
            tar_path.display(),
        );
        println!("Using cached rootfs: {}", tar_path.display());
    } else {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        checked_output(
            Command::new(cargo)
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .args([
                    "run",
                    "-p",
                    "litebox_packager",
                    "--",
                    "--oci-image",
                    image,
                    "--target-arch",
                    "x86-64",
                    "--target-host",
                    "windows",
                    "--output",
                ])
                .arg(&tar_path),
        );
    }
    tar_path
}

#[test]
fn test_runner_with_python() {
    let tar_path = packaged_rootfs(
        "windows_python_rewriter",
        // python:3.12-slim-bookworm, pinned for reproducible guest files.
        "docker.io/library/python@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258",
        "LITEBOX_PYTHON_ROOTFS_CACHE_HIT",
    );
    let output = checked_output(
        brokered_runner_command(&tar_path)
            .args([
                "--env",
                "LD_LIBRARY_PATH=/usr/local/lib:/lib64:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/lib",
                "--env",
                "LD_ORIGIN_PATH=/usr/local/bin",
                "--env",
                "PYTHONHOME=/usr/local",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--env",
                "HOME=/",
            ])
            .args([
                "/usr/local/bin/python3",
                "-c",
                "import math; print('Hello, World from litebox!'); assert math.sqrt(81) == 9",
            ]),
    );
    print!("{output}");
    assert!(
        output
            .lines()
            .any(|line| line.trim() == "Hello, World from litebox!"),
        "Unexpected Python output:\n{output}",
    );
}

#[test]
fn test_node_with_rewriter() {
    let tar_path = packaged_rootfs(
        "windows_node_rewriter",
        // node:22-bookworm-slim, pinned for reproducible guest files.
        "docker.io/library/node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392",
        "LITEBOX_NODE_ROOTFS_CACHE_HIT",
    );
    let output = checked_output(
        brokered_runner_command(&tar_path)
            .args([
                "--env",
                "LD_LIBRARY_PATH=/lib64:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/lib",
                "--env",
                "LD_ORIGIN_PATH=/usr/local/bin",
                "--env",
                "HOME=/",
            ])
            .args([
                "/usr/local/bin/node",
                "-e",
                "require('node:assert').strictEqual(process.arch, 'x64'); const fs = require('node:fs'); const content = 'Hello World!'; console.log(content);",
            ]),
    );
    print!("{output}");
    assert!(
        output.lines().any(|line| line.trim() == "Hello World!"),
        "Unexpected Node output:\n{output}",
    );
}
