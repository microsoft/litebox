// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// End-to-end runs of the Mach-O programs in this directory, shared by every
// Darwin runner: each runner's `tests/run.rs` defines `RUNNER` (the path of its
// binary) and `include!`s this file.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const GREETING: &str = "a file read from the tar archive\n";

/// Pack the test binary `name` as `/bin/<name>` (plus `/greeting.txt`) into a
/// tar archive, then run it under the runner with `args`.
fn run(name: &str, args: &[&str]) -> Output {
    let bins = Path::new(env!("CARGO_MANIFEST_DIR")).join("../litebox_shim_darwin/test-bins");
    let tar_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("darwin-{name}.tar"));
    {
        let program = std::fs::read(bins.join(format!("{name}.macho"))).unwrap();
        let mut archive = tar::Builder::new(std::fs::File::create(&tar_path).unwrap());
        for (path, mode, data) in [
            (format!("bin/{name}"), 0o755, program.as_slice()),
            ("greeting.txt".to_owned(), 0o644, GREETING.as_bytes()),
        ] {
            let mut header = tar::Header::new_ustar();
            header.set_size(data.len() as u64);
            header.set_mode(mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            archive.append_data(&mut header, path, data).unwrap();
        }
        archive.finish().unwrap();
    }
    Command::new(RUNNER)
        .arg("--initial-files")
        .arg(&tar_path)
        .arg(format!("/bin/{name}"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).unwrap()
}

#[track_caller]
fn assert_exit(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        stdout(output),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn hello_writes_to_stdout_and_returns_from_main() {
    let output = run("hello", &[]);
    assert_exit(&output, 0);
    assert_eq!(stdout(&output), "Hello from a Mach-O guest\n");
}

#[test]
fn exit_status_reaches_the_host() {
    assert_exit(&run("exit_code", &[]), 42);
}

#[test]
fn failed_syscall_sets_carry_and_returns_errno() {
    // ENOENT is 2 on Darwin, as on Linux.
    assert_exit(&run("errno", &[]), 2);
}

#[test]
fn unknown_syscall_is_enosys() {
    // ENOSYS is 78 on Darwin (38 on Linux).
    assert_exit(&run("enosys", &[]), 78);
}

#[test]
fn reads_a_file_from_the_archive() {
    let output = run("cat", &[]);
    assert_exit(&output, 0);
    assert_eq!(stdout(&output), GREETING);
}

#[test]
fn main_receives_argv() {
    let output = run("args", &["first", "second argument"]);
    assert_exit(&output, 0);
    assert_eq!(stdout(&output), "first\nsecond argument\n");
}

#[test]
fn anonymous_mmap_round_trips() {
    let output = run("mmap", &[]);
    assert_exit(&output, 0);
    assert_eq!(stdout(&output), "written through an mmap page\n");
}
