// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::{
    collections::BTreeSet,
    io::Read,
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

fn stage_and_rewrite(rootfs: &Path, wsl_root: &Path, mut pending: BTreeSet<String>) {
    let mut elf_paths = BTreeSet::new();
    while let Some(guest_path) = pending.pop_first() {
        if !elf_paths.insert(guest_path.clone()) {
            continue;
        }
        let relative_path = guest_path.trim_start_matches('/');
        let resolved_path =
            checked_output(Command::new("wsl.exe").args(["--exec", "readlink", "-f", &guest_path]));
        let source = wsl_root.join(resolved_path.trim().trim_start_matches('/'));
        assert!(source.is_file(), "Missing ELF source: {}", source.display());
        let destination = rootfs.join(relative_path);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::copy(source, destination).unwrap();
        let dependencies =
            checked_output(Command::new("wsl.exe").args(["--exec", "ldd", &guest_path]));
        for line in dependencies.lines() {
            assert!(
                !line.contains("not found"),
                "Missing dependency for {guest_path}: {line}",
            );
            let dependency = line.split_once("=>").map_or(line, |(_, path)| path);
            if let Some(path) = dependency
                .split_whitespace()
                .next()
                .filter(|path| path.starts_with('/'))
            {
                pending.insert(path.to_owned());
            }
        }
    }

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    for guest_path in elf_paths {
        let source = rootfs.join(guest_path.trim_start_matches('/'));
        let rewritten = source.with_extension("hooked");
        checked_output(
            Command::new(&cargo)
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .args(["run", "-p", "litebox_syscall_rewriter", "--"])
                .arg(&source)
                .arg("-o")
                .arg(&rewritten),
        );
        std::fs::remove_file(&source).unwrap();
        std::fs::rename(rewritten, source).unwrap();
    }
}

fn stage_path(source: &Path, destination: &Path) {
    if source.is_dir() {
        std::fs::create_dir_all(destination).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            if matches!(
                entry.file_name().to_str(),
                Some("__pycache__" | "site-packages" | "dist-packages")
            ) {
                continue;
            }
            stage_path(&entry.path(), &destination.join(entry.file_name()));
        }
    } else if source.is_file() {
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::copy(source, destination).unwrap();
    }
}

fn find_elf_files(rootfs: &Path, directory: &Path, elf_paths: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            find_elf_files(rootfs, &path, elf_paths);
        } else {
            let mut magic = [0; 4];
            if std::fs::File::open(&path)
                .unwrap()
                .read_exact(&mut magic)
                .is_ok()
                && magic == *b"\x7fELF"
            {
                elf_paths.insert(format!(
                    "/{}",
                    path.strip_prefix(rootfs)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace('\\', "/")
                ));
            }
        }
    }
}

#[test]
#[ignore = "Requires WSL with x86-64 Linux python3 and ldd"]
fn test_runner_with_python() {
    let test_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("windows_python_rewriter");
    std::fs::create_dir_all(&test_dir).unwrap();
    let rootfs = test_dir.join("rootfs");
    if rootfs.exists() {
        std::fs::remove_dir_all(&rootfs).unwrap();
    }
    let configuration = checked_output(Command::new("wsl.exe").args([
        "--exec",
        "python3",
        "-c",
        "import platform, sys; assert platform.machine() == 'x86_64'; print(sys.executable); print(sys.prefix); print(*sys.path, sep=chr(10))",
    ]));
    let mut configuration = configuration.lines();
    let python_path = configuration
        .next()
        .expect("Missing Python executable path");
    let python_home = configuration.next().expect("Missing Python home");
    let search_paths = configuration
        .filter(|path| {
            path.starts_with('/')
                && (*path == python_home
                    || path
                        .strip_prefix(python_home)
                        .is_some_and(|tail| tail.starts_with('/')))
                && !path
                    .split('/')
                    .any(|part| matches!(part, "site-packages" | "dist-packages"))
        })
        .collect::<Vec<_>>();
    let python_search_path = search_paths.join(":");
    let python_guest_dir = python_path.rsplit_once('/').unwrap().0;
    let wsl_root = checked_output(Command::new("wsl.exe").args(["--exec", "wslpath", "-w", "/"]));
    let wsl_root = PathBuf::from(wsl_root.trim());
    std::fs::create_dir_all(&rootfs).unwrap();
    for guest_path in search_paths {
        let relative_path = guest_path.trim_start_matches('/');
        stage_path(&wsl_root.join(relative_path), &rootfs.join(relative_path));
    }

    let mut pending = BTreeSet::from([python_path.to_owned()]);
    find_elf_files(&rootfs, &rootfs, &mut pending);
    stage_and_rewrite(&rootfs, &wsl_root, pending);

    let tar_path = test_dir.join("rootfs.tar");
    checked_output(
        Command::new("tar")
            .arg("-cf")
            .arg(&tar_path)
            .arg("-C")
            .arg(&rootfs)
            .arg("."),
    );
    let binary_path = std::env::var_os("NEXTEST_BIN_EXE_litebox_runner_linux_on_windows_userland")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_litebox_runner_linux_on_windows_userland").into());
    let output = checked_output(
        Command::new(binary_path)
            .args([
                "--unstable",
                "--env",
                "LD_LIBRARY_PATH=/lib64:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/lib",
                "--env",
                &format!("LD_ORIGIN_PATH={python_guest_dir}"),
                "--env",
                &format!("PYTHONHOME={python_home}"),
                "--env",
                &format!("PYTHONPATH={python_search_path}"),
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--env",
                "HOME=/",
                "--initial-files",
            ])
            .arg(tar_path)
            .args([
                python_path,
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
#[ignore = "Requires WSL with bash, which, x86-64 Linux Node.js, ldd, and readlink"]
fn test_node_with_rewriter() {
    let node =
        checked_output(Command::new("wsl.exe").args(["--exec", "bash", "-ic", "which node"]));
    let configuration = checked_output(Command::new("wsl.exe").args([
        "--exec",
        node.trim(),
        "-p",
        "require('node:assert').strictEqual(process.arch, 'x64'); process.execPath",
    ]));
    let node_path = configuration.trim();
    let test_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("windows_node_rewriter");
    let rootfs = test_dir.join("rootfs");
    if rootfs.exists() {
        std::fs::remove_dir_all(&rootfs).unwrap();
    }
    std::fs::create_dir_all(rootfs.join("out")).unwrap();
    let wsl_root = checked_output(Command::new("wsl.exe").args(["--exec", "wslpath", "-w", "/"]));
    stage_and_rewrite(
        &rootfs,
        &PathBuf::from(wsl_root.trim()),
        BTreeSet::from([node_path.to_owned()]),
    );
    std::fs::write(
        rootfs.join("out/hello_world.js"),
        "const fs = require('node:fs');\nconst content = 'Hello World!';\nconsole.log(content);\n",
    )
    .unwrap();
    let tar_path = test_dir.join("rootfs.tar");
    checked_output(
        Command::new("tar")
            .arg("-cf")
            .arg(&tar_path)
            .arg("-C")
            .arg(&rootfs)
            .arg("."),
    );
    let binary_path = std::env::var_os("NEXTEST_BIN_EXE_litebox_runner_linux_on_windows_userland")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_litebox_runner_linux_on_windows_userland").into());
    let output = checked_output(
        Command::new(binary_path)
            .args([
                "--unstable",
                "--env",
                "LD_LIBRARY_PATH=/lib64:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/lib",
                "--env",
                &format!("LD_ORIGIN_PATH={}", node_path.rsplit_once('/').unwrap().0),
                "--env",
                "HOME=/",
                "--initial-files",
            ])
            .arg(tar_path)
            .args([node_path, "/out/hello_world.js"]),
    );
    print!("{output}");
    assert!(
        output.lines().any(|line| line.trim() == "Hello World!"),
        "Unexpected Node output:\n{output}",
    );
}
