// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Native `fork` of AArch64 Linux programs through the userland broker.
//!
//! The fixtures in `tests/test-bins/` are glibc PIEs built from
//! `litebox_runner_linux_userland/tests/<name>.c` (or `tests/<name>.c` here) with
//! `zig cc -target aarch64-linux-gnu.2.36 -O2 -fno-sanitize=all -fPIE -pie -s -o <name> <name>.c`.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod common;

use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Packs `program` from `tests/test-bins` with the dynamic loader and glibc into `directory`.
fn guest_archive(directory: &Path, program: &str) -> PathBuf {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/test-bins");
    let root = directory.join("root");
    for (source, destination) in [
        (program, format!("bin/{program}")),
        ("ld-linux-aarch64.so.1", "lib/ld-linux-aarch64.so.1".into()),
        ("libc.so.6", "lib/aarch64-linux-gnu/libc.so.6".into()),
    ] {
        let path = root.join(destination);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::copy(fixtures.join(source), &path).unwrap();
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

/// Returns a broker command that runs `program` with `arguments` and may duplicate processes.
fn broker_command(archive: &Path, program: &str, arguments: &[&str]) -> Command {
    let runner = common::runner_binary();
    let mut command = Command::new(common::broker_binary(&runner));
    command
        .args([
            "--unstable",
            "--allow-process-duplication",
            "--fs-initial-files",
        ])
        .arg(archive)
        .arg("--runner")
        .arg(&runner)
        .args(["--", "--env", "LD_LIBRARY_PATH=/lib/aarch64-linux-gnu"])
        .arg(format!("/bin/{program}"))
        .args(arguments)
        .env_remove("LITEBOX_DISABLE_NATIVE_FORK");
    command
}

/// Runs `program` and returns its standard output, which must report success.
fn run_fixture(program: &str, arguments: &[&str]) -> String {
    let directory = tempfile::tempdir().unwrap();
    let archive = guest_archive(directory.path(), program);
    let Output {
        status,
        stdout,
        stderr,
    } = broker_command(&archive, program, arguments)
        .output()
        .unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    assert!(
        status.success(),
        "{program}: {status}\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    stdout
}

fn output_line<'a>(output: &'a str, prefix: &str) -> &'a str {
    output
        .lines()
        .find(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("missing {prefix:?} in {output:?}"))
}

fn numeric_field(line: &str, name: &str) -> i32 {
    line.split_whitespace()
        .find_map(|field| field.strip_prefix(name)?.parse().ok())
        .unwrap_or_else(|| panic!("missing {name} in {line:?}"))
}

/// Runs `fork_parent`, whose children resume from snapshots of their parents' memory.
///
/// Built with `-D'__builtin___clear_cache(begin,end)=((void)(begin),(void)(end))'` added: the
/// cache maintenance it replaces reads `CTR_EL0`, which macOS traps, and the platform invalidates
/// the instruction cache itself when it grants execute permission.
#[test]
fn fork_child_resumes_from_parent_snapshot() {
    let output = run_fixture("fork_parent", &[]);

    let parent = output_line(&output, "parent ");
    assert_eq!(numeric_field(parent, "global="), 2);
    assert_eq!(numeric_field(parent, "intact="), 1);
    assert_eq!(numeric_field(parent, "usr1="), 0);
    assert_eq!(numeric_field(parent, "sigchld="), 1);
    assert_eq!(numeric_field(parent, "echild="), 1);
    assert_eq!(numeric_field(parent, "alarm="), 1);
    let fork = output_line(&output, "fork ");
    let child = numeric_field(fork, "child=");
    assert_ne!(child, numeric_field(parent, "pid="));
    assert_eq!(numeric_field(fork, "waited="), child);
    assert_eq!(numeric_field(fork, "exited="), 1);
    // The child and its own forked child passed every check.
    assert_eq!(numeric_field(fork, "code="), 7);
    let pipe = output_line(&output, "pipe ");
    assert_eq!(numeric_field(pipe, "pid="), child);
    assert_eq!(numeric_field(pipe, "failures="), 0);
    assert_eq!(
        numeric_field(output_line(&output, "child-stdout "), "pid="),
        child
    );
    let raw_fork = output_line(&output, "raw-fork ");
    assert_eq!(
        numeric_field(raw_fork, "waited="),
        numeric_field(raw_fork, "child=")
    );
    assert_eq!(numeric_field(raw_fork, "exited="), 1);
    assert_eq!(numeric_field(raw_fork, "code="), 9);
}

/// Runs `fork_threads_parent`, which forks while sibling threads run guest code, block, and
/// sleep, and forks from several threads at once.
#[test]
fn fork_pauses_sibling_threads() {
    let output = run_fixture("fork_threads_parent", &[]);

    let line = output_line(&output, "threads-fork ");
    assert_eq!(numeric_field(line, "code="), 7);
    assert_eq!(numeric_field(line, "failures="), 0);
    assert_eq!(numeric_field(line, "read="), 1);
    assert_eq!(numeric_field(line, "slept="), 1);
}

/// Runs `fork_shared_futex_parent`, whose forked children share `MAP_SHARED | MAP_ANONYMOUS`
/// memory and the futexes, mutexes, and semaphores in it with the parent.
#[test]
fn forked_children_share_futexes_in_shared_memory() {
    let output = run_fixture("fork_shared_futex_parent", &[]);

    assert!(
        output.lines().any(|line| line
            == "shared-futex memory=1 wake=1 timeout=1 interrupted=1 private=1 mutex=1 \
                semaphore=1 bitset=1 misaligned=1 count=1 inaccessible=1 private-memory=1 \
                clear-tid=1"),
        "{output:?}"
    );
}

/// Runs `fork_interrupt_parent`, whose forked child spins in guest code until its parent's signal
/// interrupts it.
#[test]
fn fork_child_can_be_interrupted_in_guest_code() {
    let output = run_fixture("fork_interrupt_parent", &[]);

    assert!(
        output
            .lines()
            .any(|line| line == "forked child interrupted"),
        "{output:?}"
    );
}

/// Runs a `fork_chain_parent` chain in which each generation forks the next and waits for it.
#[test]
fn deep_fork_chains_complete() {
    const DEPTH: u32 = 32;
    let output = run_fixture("fork_chain_parent", &["fork", &DEPTH.to_string()]);

    let expected = format!("fork-chain depth={DEPTH} code=42");
    assert!(output.lines().any(|line| line == expected), "{output:?}");
}

/// Returns the host processes descended from `process_id`.
fn descendants(process_id: u32) -> Vec<u32> {
    let mut found = Vec::new();
    let mut pending = vec![process_id];
    while let Some(parent) = pending.pop() {
        let children = Command::new("pgrep")
            .arg("-P")
            .arg(parent.to_string())
            .output()
            .unwrap();
        for child in String::from_utf8(children.stdout)
            .unwrap()
            .lines()
            .map(|line| line.parse::<u32>().unwrap())
        {
            found.push(child);
            pending.push(child);
        }
    }
    found
}

fn is_running(process_id: u32) -> bool {
    Command::new("kill")
        .args(["-0", &process_id.to_string()])
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// Kills the broker while `fork_spin`'s parent and native fork child spin without system calls,
/// and checks that both runners exit instead of outliving their broker. The parent spins on a
/// sibling thread after its initial thread exited, so its guest is not finished.
///
/// Built from `tests/fork_spin.c`.
#[test]
fn runners_exit_when_their_broker_dies() {
    let directory = tempfile::tempdir().unwrap();
    let archive = guest_archive(directory.path(), "fork_spin");
    let mut broker = broker_command(&archive, "fork_spin", &[])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(broker.stdout.take().unwrap());
    let mut spinning = Vec::new();
    while spinning.len() < 2 {
        let mut line = String::new();
        if stdout.read_line(&mut line).unwrap() == 0 {
            let _ = broker.kill();
            panic!("the broker ended before both processes spun: {spinning:?}");
        }
        spinning.push(line);
    }
    let runners = descendants(broker.id());
    broker.kill().unwrap();
    broker.wait().unwrap();
    assert_eq!(runners.len(), 2, "expected two runners, got {runners:?}");

    let deadline = Instant::now() + Duration::from_secs(10);
    while runners.iter().any(|&runner| is_running(runner)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let survivors: Vec<_> = runners
        .into_iter()
        .filter(|&runner| is_running(runner))
        .collect();
    for &survivor in &survivors {
        let _ = Command::new("kill")
            .args(["-9", &survivor.to_string()])
            .status();
    }
    assert!(
        survivors.is_empty(),
        "runners {survivors:?} outlived their broker"
    );
}
